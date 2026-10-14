"""Uninstalled journal-bound History matching and original settlement evidence.

Only MATCHED_OBSERVATION when an actual counted global unit, original durable
preimage, both original enrollment nonces, exact permanent fence and ALL sent
business/audit rows agree. No send/clear/reset/high-water mutation. Remote read
objects remain necessary inputs, not authenticated source/admission authority;
The owned-read bridge establishes actual fixed-read provenance. Separate
APPLIED evidence requires original committed C6 and complete remote proof;
neither observer grants a send, FIFO, quota or high-water mutation permit.
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


@dataclass(frozen=True)
class AppliedEvidenceObservation:
    """Historical remote effects only; never a fresh send or quota permit."""
    state: str
    generation_id: str
    sequence: int
    unit_id: str
    applied_operation_ids: tuple


@contextmanager
def _hold_applied_generation(writer_token,generation,unit):
    """Pin original C6 files and published XLSX through the whole handoff.

    Keep this separate from current-cycle qualification: historical completion
    must not recompile a newer qualified set or reinterpret a frozen retry.
    Original receipt evidence is necessary here, not online send eligibility.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as io
    from monitor.issue_tracker_send_unit import _read_original_generation_identity
    generations=folder=None; held=[]; owned_objects={}
    try:
        owner=local._owner(writer_token)
        if (type(generation) is not local.Generation or type(generation.sequence) is not int
                or generation.sequence<1): raise RemoteHistoryHold()
        original=_read_original_generation_identity(generation.generation_id,writer_token)
        action=local._json(unit.action_preimage)
        if (original[:3]!=(generation.generation_id,action['identity']['publish_id'],action['manifest_id'])
                or action['identity']['generation_id']!=generation.generation_id
                or generation.manifest_id!=action['manifest_id']): raise RemoteHistoryHold()
        generations=local._directory(owner.root_fd,'generations')
        opened=os.fstat(generations); owned_objects[generations]=(opened.st_dev,opened.st_ino)
        folder=local._generation_fd(owner,generation)
        opened=os.fstat(folder); owned_objects[folder]=(opened.st_dev,opened.st_ino)
        dir_identity=io._identity(os.fstat(folder))
        ancestors_identity=io._identity(os.fstat(generations))
        expected={'STATE','MANIFEST','INTENT','RECEIPT'}
        if set(os.listdir(folder))!=expected: raise RemoteHistoryHold()
        snapshots={}
        receipt_raw=local._read(folder,'RECEIPT')[0]
        receipt=local._json(receipt_raw)
        if receipt.get('published')!=local._published_name(generation.generation_id,'xlsx'):
            raise RemoteHistoryHold()
        for parent,name,limit,private in (
                *((folder,name,1024*1024,True) for name in sorted(expected)),
                (owner.publication_fd,receipt['published'],local._MAX_XLSX,False)):
            fd=os.open(name,local._flags()|os.O_NONBLOCK,dir_fd=parent)
            opened=os.fstat(fd); owned_objects[fd]=(opened.st_dev,opened.st_ino)
            held.append((parent,name,fd,None,None))
            info=local._check(fd,directory=False,private=private)
            io._named(parent,name,fd,directory=False)
            identity=io._identity(info)
            raw=os.pread(fd,limit+1,0)
            if not raw or len(raw)!=info.st_size or len(raw)>limit: raise RemoteHistoryHold()
            held[-1]=(parent,name,fd,identity,raw)
            snapshots[name]={'identity':list(identity),'sha256':hashlib.sha256(raw).hexdigest()}
        # Reuse the cold reader's semantic facts only for these exact originals.
        # Its identity uses dev/ino/SIZE, not io._identity's dev/ino/MODE prefix.
        # Neither a same-byte file nor a substituted ancestor can be adopted in
        # the cold-read -> held-capture gap. No qualification is cached here.
        originals={name:(identity,raw) for parent,name,_fd,identity,raw in held if parent==folder}
        ordered=('STATE','RECEIPT','MANIFEST','INTENT')
        if (tuple(identity[:2] for identity in (ancestors_identity,dir_identity))!=original[3]
                or tuple((originals[name][0][0],originals[name][0][1],originals[name][0][6])
                         for name in ordered)!=original[4:8]
                or tuple(hashlib.sha256(originals[name][1]).hexdigest() for name in ordered)!=original[8:12]
                or originals['RECEIPT'][1]!=receipt_raw):
            raise RemoteHistoryHold()
        intent=local._json(originals['INTENT'][1])['prepared']
        published_identity,published_raw=next((identity,raw) for parent,_name,_fd,identity,raw in held
                                             if parent==owner.publication_fd)
        published_witness=(published_identity[0],published_identity[1],published_identity[6],
                           hashlib.sha256(published_raw).hexdigest())
        if (published_witness!=(receipt['published_dev'],receipt['published_ino'],
                                receipt['published_size'],receipt['published_sha256'])
                or published_witness!=(intent['dev'],intent['ino'],intent['size'],intent['sha256'])
                or published_witness[3]!=original[1]):
            raise RemoteHistoryHold()
        def verify_originals():
            if local._owner(writer_token) is not owner: raise RemoteHistoryHold()
            io._named(owner.root_fd,'generations',generations,directory=True)
            io._named(generations,generation.generation_id,folder,directory=True)
            if (io._identity(os.fstat(generations))!=ancestors_identity
                    or io._identity(os.fstat(folder))!=dir_identity
                    or set(os.listdir(folder))!=expected): raise RemoteHistoryHold()
            for parent,name,fd,identity,raw in held:
                # Same complete original check, without three pre-read fstats
                # of one held file. Two FRESH samples enclose its actual read;
                # neither phase nor the original recovery barriers is omitted.
                before=local._check(fd,directory=False)
                named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                if (before.st_mode & 0o777!=0o600 or io._identity(before)!=identity
                        or io._identity(named)!=identity or os.pread(fd,len(raw)+1,0)!=raw
                        or io._identity(os.fstat(fd))!=identity):
                    raise RemoteHistoryHold()
        def verify():
            verify_originals()
            # The cold recovery reader performed these actual directory
            # barriers on every replay. Keep both and recheck the entire held
            # graph afterwards, including replacements during either fsync.
            try:
                os.fsync(owner.publication_fd)
                os.fsync(folder)
            except OSError as exc:
                raise RemoteHistoryHold() from exc
            verify_originals()
        verify()
        state=local._json(next(raw for _parent,name,_fd,_id,raw in held if name=='STATE'))
        manifest=local._json(next(raw for _parent,name,_fd,_id,raw in held if name=='MANIFEST'))
        from monitor.issue_tracker_manifest import _validated_operations, _runtime_operation
        from monitor.issue_tracker_send_unit import _FAMILY
        operations=_validated_operations(manifest['operations'],'original APPLIED manifest',validator=_runtime_operation)
        selected=[operation for operation in operations if operation['activity_key'][0]==_FAMILY[action['identity']['sheet']]]
        if (state['sequence']!=generation.sequence
                or [op['operation_id'] for op in selected]!=[pair[0] for pair in action['outcomes']]):
            raise RemoteHistoryHold()
        keyed={op['operation_id']:op['activity_key'] for op in selected}
        if any(keyed[row['operation_id']]!=row['activity_key'] for row in action['business']):
            raise RemoteHistoryHold()
        for _parent,_name,fd,_identity,_raw in held: os.fsync(fd)
        os.fsync(folder); os.fsync(generations); os.fsync(owner.publication_fd); verify()
        facts={'generation_id':generation.generation_id,'sequence':generation.sequence,
               'manifest_id':generation.manifest_id,'published_sha256':original[1],
               'generation_directory_identity':list(dir_identity),'files':snapshots}
        yield owner,verify,facts,tuple(row['operation_id'] for row in action['business'])
        verify()
    finally:
        failed=False
        for _parent,_name,fd,_identity,_raw in reversed(held):
            try:
                current=os.fstat(fd)
                if (current.st_dev,current.st_ino)==owned_objects.get(fd): os.close(fd)
                else: failed=True
            except OSError: failed=True
        for fd in (folder,generations):
            if fd is not None:
                try:
                    current=os.fstat(fd)
                    if (current.st_dev,current.st_ino)==owned_objects.get(fd): os.close(fd)
                    else: failed=True
                except OSError: failed=True
        if failed: raise RemoteHistoryHold()


@contextmanager
def _hold_applied_records(parent,names,body,*,states=('APPLIED-STARTED','APPLIED')):
    """Never adopt a substituted same-byte marker or partially written pair."""
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as io
    held=[]; owned_objects={}
    try:
        for name in names:
            fd=os.open(name,local._flags()|os.O_NONBLOCK,dir_fd=parent)
            held.append((name,fd,None,None))
            opened=os.fstat(fd); owned_objects[fd]=(opened.st_dev,opened.st_ino)
            info=local._check(fd,directory=False)
            io._named(parent,name,fd,directory=False)
            identity=io._identity(info)
            raw=os.pread(fd,local._MAX_MANIFEST+1,0)
            if not raw or len(raw)!=info.st_size or len(raw)>local._MAX_MANIFEST: raise RemoteHistoryHold()
            held[-1]=(name,fd,identity,raw)
        # Both files bind both originally prepared inodes. Neither a cold
        # same-byte replacement nor the presence of an unpaired marker is a
        # settlement witness. These identities are not caller supplied.
        pair={name:list(identity[:2]) for name,_fd,identity,_raw in held}
        if len(states)!=2 or len(held)!=2: raise RemoteHistoryHold()
        for (_name,_fd,_identity,raw),state in zip(held,states):
            if raw!=local._canonical({**body,'record_identities':pair,'state':state}):
                raise RemoteHistoryHold()
        def verify():
            for name,fd,identity,raw in held:
                io._named(parent,name,fd,directory=False)
                if io._identity(os.fstat(fd))!=identity or os.pread(fd,len(raw)+1,0)!=raw:
                    raise RemoteHistoryHold()
        verify()
        for _name,fd,_identity,_raw in held: os.fsync(fd)
        os.fsync(parent); verify()
        yield verify
        verify()
    finally:
        failed=False
        for _name,fd,_identity,_raw in reversed(held):
            try:
                current=os.fstat(fd)
                if (current.st_dev,current.st_ino)!=owned_objects.get(fd):
                    failed=True
                else:
                    os.close(fd)
            except OSError: failed=True
        if failed: raise RemoteHistoryHold()


@contextmanager
def _write_applied_pair(parent,names,body,verify_inputs,*,states=('APPLIED-STARTED','APPLIED')):
    """Retain BOTH prepared file descriptors through all commits and return.

    A STARTED file commits first and binds the already prepared marker inode.
    Interruptions retain all partial/pending evidence; no deletion, overwrite,
    replacement adoption or completion of a partial pair is performed.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as io
    held=[]; owned_objects={}
    try:
        for name in names:
            temp='.pending-'+local.uuid.uuid4().hex
            fd=os.open(temp,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            held.append([name,temp,fd,None,None])
            opened=os.fstat(fd); owned_objects[fd]=(opened.st_dev,opened.st_ino)
            local._check(fd,directory=False)
            io._named(parent,temp,fd,directory=False)
        pair={name:list(io._identity(os.fstat(fd))[:2]) for name,_temp,fd,_id,_raw in held}
        if len(states)!=2 or len(held)!=2: raise RemoteHistoryHold()
        for item,state in zip(held,states):
            raw=local._canonical({**body,'record_identities':pair,'state':state})
            if len(raw)>local._MAX_MANIFEST: raise RemoteHistoryHold()
            view=memoryview(raw)
            while view:
                count=os.write(item[2],view)
                if count<=0: raise RemoteHistoryHold()
                view=view[count:]
            os.fsync(item[2]); item[3]=io._identity(os.fstat(item[2])); item[4]=raw
        def verify():
            verify_inputs()
            for _name,current,fd,identity,raw in held:
                io._named(parent,current,fd,directory=False)
                if io._identity(os.fstat(fd))!=identity or os.pread(fd,len(raw)+1,0)!=raw:
                    raise RemoteHistoryHold()
        verify()
        for item in held:
            verify()
            name,temp,fd,identity,raw=item
            local._rename_new(parent,temp,name)
            # Only our own retained inode may acquire its final name. Rename
            # may update ctime; every other original field and bytes survives.
            io._named(parent,name,fd,directory=False)
            after=io._identity(os.fstat(fd))
            if after[:-1]!=identity[:-1] or os.pread(fd,len(raw)+1,0)!=raw:
                raise RemoteHistoryHold()
            item[1]=name; item[3]=after
            os.fsync(parent); verify()
        yield verify
        verify()
    finally:
        failed=False
        for _name,_current,fd,_identity,_raw in reversed(held):
            try:
                current=os.fstat(fd)
                if (current.st_dev,current.st_ino)!=owned_objects.get(fd):
                    failed=True
                else:
                    os.close(fd)
            except OSError: failed=True
        if failed: raise RemoteHistoryHold()


def _owned_applied_evidence(writer_token,owner_token,binding,unit,generation,*,record):
    from monitor import issue_tracker_local_commit as local
    failed=False
    try:
        with ExitStack() as scope:
            owner,verify_local,facts,sent=scope.enter_context(_hold_applied_generation(writer_token,generation,unit))
            verify_proof=scope.enter_context(_hold_completion_originals(owner_token,binding,unit))
            completion=inspect_completion_evidence(owner_token,binding,unit)
            _sheet_owner,_parent,_name,base=global_journal._inputs(owner_token,binding,unit)
            if not sent or completion.state!='COMPLETE-PRESENT-NOT-APPLIED': raise RemoteHistoryHold()
            def verify():
                verify_local(); verify_proof()
                if inspect_completion_evidence(owner_token,binding,unit)!=completion: raise RemoteHistoryHold()
            verify()
            body={'schema_version':1,'unit_id':unit.unit_id,'binding':base,'local_generation':facts,
                  'completion_header_sha256':completion.header_sha256,'attempt_count':completion.attempt_count,
                  'wire_sha256':unit.wire_sha256,'action_digest':unit.action_digest,
                  'outcome_mapping_sha256':unit.outcome_mapping_sha256,'applied_operation_ids':list(sent)}
            started='REMOTE-APPLIED-STARTED-'+unit.unit_id
            applied='REMOTE-APPLIED-'+unit.unit_id
            names=set(os.listdir(owner.root_fd))
            if record and started not in names and applied not in names:
                # Failed pre-rename evidence is never silently discarded.
                if any(name.startswith('.pending-') for name in names): raise RemoteHistoryHold()
                scope.enter_context(_write_applied_pair(owner.root_fd,(started,applied),body,verify))
            verify_pair=scope.enter_context(_hold_applied_records(owner.root_fd,(started,applied),body))
            verify(); verify_pair()
            result=AppliedEvidenceObservation('APPLIED',generation.generation_id,generation.sequence,unit.unit_id,sent)
        # All held input/record close and final rechecks completed before return.
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def record_owned_applied_evidence(writer_token,owner_token,binding,unit,*,generation):
    """Record complete original C6/remote effects; no resend or FIFO permit.

    This separate journal never mutates UNKNOWN/count/WIRE, C6 originals,
    permanent fences, settings outbox or per-key high-water. Those consumers
    must independently bind the durable original record before integration.
    A duplicate complete pair is only cold-safe read-only replay.
    """
    return _owned_applied_evidence(writer_token,owner_token,binding,unit,generation,record=True)


def inspect_owned_applied_evidence(writer_token,owner_token,binding,unit,*,generation):
    """Cold re-establishment of original file/directory barriers, never repair."""
    return _owned_applied_evidence(writer_token,owner_token,binding,unit,generation,record=False)


@contextmanager
def _hold_original_applied_key_watermark_inputs(writer_token,owner_token,binding,unit,generation):
    """Retain original C6, COMPLETE and APPLIED throughout key-watermark IO.

    No current qualified-set compilation, journal reset or global NEW release.
    A returned APPLIED dataclass cannot substitute for these actual originals.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as io
    with ExitStack() as scope:
        owner,verify_local,facts,sent=scope.enter_context(_hold_applied_generation(writer_token,generation,unit))
        verify_complete=scope.enter_context(_hold_completion_originals(owner_token,binding,unit))
        completion=inspect_completion_evidence(owner_token,binding,unit)
        _sheet_owner,_parent,_name,base=global_journal._inputs(owner_token,binding,unit)
        if not sent or completion.state!='COMPLETE-PRESENT-NOT-APPLIED': raise RemoteHistoryHold()
        applied_body={'schema_version':1,'unit_id':unit.unit_id,'binding':base,'local_generation':facts,
            'completion_header_sha256':completion.header_sha256,'attempt_count':completion.attempt_count,
            'wire_sha256':unit.wire_sha256,'action_digest':unit.action_digest,
            'outcome_mapping_sha256':unit.outcome_mapping_sha256,'applied_operation_ids':list(sent)}
        names=('REMOTE-APPLIED-STARTED-'+unit.unit_id,'REMOTE-APPLIED-'+unit.unit_id)
        verify_applied=scope.enter_context(_hold_applied_records(owner.root_fd,names,applied_body))
        def verify():
            verify_local(); verify_complete(); verify_applied()
            if inspect_completion_evidence(owner_token,binding,unit)!=completion: raise RemoteHistoryHold()
        verify()
        references={}
        for name in names:
            raw,info=local._read(owner.root_fd,name,local._MAX_MANIFEST)
            references[name]={'identity':list(io._identity(info)),'sha256':hashlib.sha256(raw).hexdigest()}
        action=local._json(unit.action_preimage)
        keys=tuple((tuple(row['activity_key']),generation.sequence) for row in action['business'])
        if not keys or len({key for key,_sequence in keys})!=len(keys): raise RemoteHistoryHold()
        body={'schema_version':1,'unit_id':unit.unit_id,'binding':base,'local_generation':facts,
            'project_identity':list(io._identity(os.fstat(owner.project_fd))[:2]),
            'applied_originals':references,'key_watermarks':[[list(key),sequence] for key,sequence in keys]}
        verify()
        yield owner,verify,body,keys
        verify()


@contextmanager
def _hold_settled_catalog_key_watermarks(writer_token,owner_token,binding,unit,generation):
    failed=False
    try:
        with _hold_settled_catalog_key_watermark_originals(writer_token,owner_token,binding,unit,generation) as values:
            yield values
    except Exception:
        failed=True
    if failed:
        raise RemoteHistoryHold()


@contextmanager
def _hold_settled_catalog_key_watermark_originals(writer_token,owner_token,binding,unit,generation):
    """Fixed original settlement while a catalog creator appends its own names.

    Fully replay actual COMPLETE before any write, with all C6/matched inputs/
    COMPLETE/APPLIED/key originals already held. Subsequent checks use those
    same bytes/inodes, not a cold inventory reader that mistakes the creator's
    unindexed NV witness for a foreign unit. The caller separately pins ALL
    catalog originals and its exact append. No path/flag/verifier override,
    count clearing, freshness or send authority is accepted or returned.
    The old key writer's semantic replay contract is unchanged.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as io
    with ExitStack() as scope:
        owner,verify_local,facts,sent=scope.enter_context(_hold_applied_generation(writer_token,generation,unit))
        verify_matched,_originals=scope.enter_context(_hold_match_originals(owner_token,binding,unit))
        verify_complete=scope.enter_context(_hold_completion_originals(owner_token,binding,unit))
        completion=inspect_completion_evidence(owner_token,binding,unit)
        _sheet_owner,_parent,_name,base=global_journal._inputs(owner_token,binding,unit)
        if not sent or completion.state!='COMPLETE-PRESENT-NOT-APPLIED': raise RemoteHistoryHold()
        applied_body={'schema_version':1,'unit_id':unit.unit_id,'binding':base,'local_generation':facts,
            'completion_header_sha256':completion.header_sha256,'attempt_count':completion.attempt_count,
            'wire_sha256':unit.wire_sha256,'action_digest':unit.action_digest,
            'outcome_mapping_sha256':unit.outcome_mapping_sha256,'applied_operation_ids':list(sent)}
        names=('REMOTE-APPLIED-STARTED-'+unit.unit_id,'REMOTE-APPLIED-'+unit.unit_id)
        verify_applied=scope.enter_context(_hold_applied_records(owner.root_fd,names,applied_body))
        references={}
        for name in names:
            raw,info=local._read(owner.root_fd,name,local._MAX_MANIFEST)
            references[name]={'identity':list(io._identity(info)),'sha256':hashlib.sha256(raw).hexdigest()}
        action=local._json(unit.action_preimage)
        keys=tuple((tuple(row['activity_key']),generation.sequence) for row in action['business'])
        if not keys or len({key for key,_sequence in keys})!=len(keys): raise RemoteHistoryHold()
        body={'schema_version':1,'unit_id':unit.unit_id,'binding':base,'local_generation':facts,
            'project_identity':list(io._identity(os.fstat(owner.project_fd))[:2]),
            'applied_originals':references,'key_watermarks':[[list(key),sequence] for key,sequence in keys]}
        verify_keys=scope.enter_context(_hold_applied_records(owner.root_fd,
            ('REMOTE-KEY-HIGH-WATER-STARTED-'+unit.unit_id,'REMOTE-KEY-HIGH-WATER-'+unit.unit_id),
            body,states=('KEY-HIGH-WATER-STARTED','KEY-HIGH-WATER')))
        def verify():
            verify_local(); verify_matched(); verify_complete(); verify_applied(); verify_keys()
            verify_local(); verify_matched(); verify_complete()
        verify()
        yield owner,verify,body,keys
        verify()


def _owned_applied_key_watermarks(writer_token,owner_token,binding,unit,generation,*,record):
    """Immutable per-original-unit evidence; never a spreadsheet admission permit."""
    failed=False
    try:
        with ExitStack() as scope:
            owner,verify_inputs,body,keys=scope.enter_context(
                _hold_original_applied_key_watermark_inputs(writer_token,owner_token,binding,unit,generation))
            names=('REMOTE-KEY-HIGH-WATER-STARTED-'+unit.unit_id,'REMOTE-KEY-HIGH-WATER-'+unit.unit_id)
            states=('KEY-HIGH-WATER-STARTED','KEY-HIGH-WATER')
            present=set(os.listdir(owner.root_fd))
            if record and not any(name in present for name in names):
                # Never silently discard a failed original pending image.
                if any(name.startswith('.pending-') for name in present): raise RemoteHistoryHold()
                scope.enter_context(_write_applied_pair(owner.root_fd,names,body,verify_inputs,states=states))
            verify_records=scope.enter_context(_hold_applied_records(owner.root_fd,names,body,states=states))
            verify_inputs(); verify_records()
            result=keys
        # All final input/record checks and owned closes dominate return.
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def record_owned_applied_key_watermarks(writer_token,owner_token,binding,unit,*,generation):
    """Durably record only ACTUALLY SENT keys from the original APPLIED unit.

    NOOP is excluded. Original UNKNOWN/count/WIRE and reservations are retained.
    This per-unit record is necessary input to a future complete FIFO/high-water
    consumer; it does not prove global maximum or authorize a successor/NEW unit.
    """
    return _owned_applied_key_watermarks(writer_token,owner_token,binding,unit,generation,record=True)


def inspect_owned_applied_key_watermarks(writer_token,owner_token,binding,unit,*,generation):
    """Cold original-only observation; absent/partial records are never repaired."""
    return _owned_applied_key_watermarks(writer_token,owner_token,binding,unit,generation,record=False)


def reconcile_owned_project_unit(writer_token, owner_token, binding, unit,
                                 authentication, *, generation):
    """Fixed four-read settlement; retained contexts finish before return."""
    with _hold_reconciled_owned_project_unit(writer_token, owner_token, binding,
            unit, authentication, generation=generation) as result:
        pass
    return result


@contextmanager
def _hold_reconciled_owned_project_unit(writer_token, owner_token, binding, unit,
                                       authentication, *, generation, _catalog=None):
    """Fixed project-authenticated four-read reconciliation of ONE original.

    The online cycle consumer may call this for an already counted UNKNOWN,
    independently of a new local C6. The original committed generation,
    count, immutable wire, History and nonces stay held across the reads and
    COMPLETE/APPLIED/key handoff. No caller response, plan, URL or MATCHED
    label is accepted. A visible fence alone never installs completion.

    This never sends business mutations, increments/resets an attempt, creates
    NEW, admits a retry, releases G1 reservations or cleans settings outboxes.
    Globally complete metadata capacity is NOT needed to read historical
    evidence and is NOT inferred from these four responses. Partial original
    completion stores are refused, never adopted, repaired or overwritten.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor.issue_tracker_history_read_launcher import (
        OwnedProjectSheetsReadUnit, require_current_owned_project_read,
    )
    from monitor.issue_tracker_token_launcher import require_current_owned_project_token
    from monitor.issue_tracker_online_target import inspect_project_online_target

    failed = False
    try:
        project = local._owner(writer_token)
        with _hold_applied_generation(writer_token, generation, unit) as (actual, verify_c6, _facts, _sent):
            if actual is not project:
                raise RemoteHistoryHold()
            with _hold_match_originals(owner_token, binding, unit) as (verify_originals, _images):
                before_count = global_journal.inspect_global_unit(owner_token, binding, unit)
                if not 1 <= before_count.attempt_count <= 6:
                    raise RemoteHistoryHold()
                require_current_owned_project_token(owner_token, binding, authentication)
                inspect_project_online_target(writer_token, binding)
                responses = {}
                retained = ExitStack()
                retained_checks = []
                def verify_live():
                    if _catalog is not None:
                        _catalog.verify()
                    verify_c6(); verify_originals()
                    for check in retained_checks:
                        check()
                    if local._owner(writer_token) is not project:
                        raise RemoteHistoryHold()
                    if global_journal.inspect_global_unit(owner_token, binding, unit) != before_count:
                        raise RemoteHistoryHold()
                    require_current_owned_project_token(owner_token, binding, authentication)
                    inspect_project_online_target(writer_token, binding)
                    for key, kind, _file in _COMPLETION_READS:
                        if key in responses:
                            require_current_owned_project_read(writer_token, owner_token, binding,
                                responses[key], authentication, read_kind=kind)
                    verify_c6(); verify_originals()
                    for check in retained_checks:
                        check()
                verify_live()
                _sheet, parent, name, _base = global_journal._inputs(owner_token, binding, unit)
                prefix = name[:-len('.journal')]
                with retained:
                    if any(prefix + suffix in os.listdir(parent)
                           for suffix in ('.completion', '.completion-started')):
                        # Existing/partial stores go through the strict original
                        # reader. Failure must never fall back to recreation.
                        inspect_completion_evidence(owner_token, binding, unit)
                        matched = True
                    else:
                        for key, kind, _file in _COMPLETION_READS:
                            verify_live()
                            responses[key] = OwnedProjectSheetsReadUnit(writer_token, owner_token,
                                binding, authentication, read_kind=kind).read_once()
                            verify_live()
                        result = observe_owned_remote_history_unit(writer_token, owner_token,
                            binding, unit, **responses)
                        verify_live()
                        matched = result.state == 'MATCHED_OBSERVATION'
                        if matched:
                            _completion, verify_created = retained.enter_context(
                                _hold_created_completion_evidence(writer_token, owner_token,
                                    binding, unit, _reconciliation=_catalog, **responses))
                            retained_checks.append(verify_created)
                            if _catalog is not None:
                                _catalog.created(unit, verify_created)
                            verify_live()
                    if matched:
                        retained_checks.append(retained.enter_context(
                            _hold_completion_originals(owner_token, binding, unit)))
                        # Recheck the creator's saved identities AFTER capture
                        # and BEFORE APPLIED. Capture cannot adopt a replacement.
                        verify_live()
                        result = record_owned_applied_evidence(writer_token, owner_token,
                            binding, unit, generation=generation)
                        original_owner, verify_applied, key_body, _keys = retained.enter_context(
                            _hold_original_applied_key_watermark_inputs(writer_token,
                                owner_token, binding, unit, generation))
                        if original_owner is not project:
                            raise RemoteHistoryHold()
                        retained_checks.append(verify_applied)
                        verify_live()
                        record_owned_applied_key_watermarks(writer_token, owner_token,
                            binding, unit, generation=generation)
                        retained_checks.append(retained.enter_context(_hold_applied_records(
                            project.root_fd, ('REMOTE-KEY-HIGH-WATER-STARTED-'+unit.unit_id,
                                'REMOTE-KEY-HIGH-WATER-'+unit.unit_id), key_body,
                            states=('KEY-HIGH-WATER-STARTED', 'KEY-HIGH-WATER'))))
                    verify_live()
                    yield result
                    verify_live()
    except Exception:
        failed = True
    if failed:
        raise RemoteHistoryHold()


class _CatalogReconciliationOriginals:
    """Private actual-creator handoff, not caller namespace exemptions."""
    def __init__(self, writer, token, binding, held, owner, project, rows, check_c6, store=None):
        self.writer, self.token, self.binding = writer, token, binding
        self.held, self.owner, self.project = held, owner, project
        self.rows, self.check_c6 = rows, check_c6
        self.additions = frozenset()
        self.store = store

    def verify_cycles(self):
        if self.store is not None:
            from monitor import issue_tracker_cycle_source as cycles
            from monitor.issue_tracker_online_target import _require_held_current_project_online_target
            _require_held_current_project_online_target(self.writer, self.binding)
            active = cycles._HELD_CYCLE_REPLAY.get()
            if active is None or active[0] is not self.store:
                raise RemoteHistoryHold()
            if not cycles.read_completed_cycle_evidence(self.store):
                raise RemoteHistoryHold()
            _require_held_current_project_online_target(self.writer, self.binding)

    def verify_sources_during_creation(self, unit):
        """Actual creator's two exclusive names; all old originals stay held.

        Names derive from an actual current-project C6 row and fixed journal
        inputs, never a caller namespace allowance. The creator owns/checks its
        new partial files until overlapping capture in created().
        """
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_attempt_journal as journal
        self.verify_cycles()
        if (local._owner(self.writer) is not self.project
                or ownership._validated_owner(self.token, self.binding) is not self.owner):
            raise RemoteHistoryHold()
        actual_identity = journal._identity(os.fstat(self.project.project_fd))[:2]
        if not any(row.unit == unit and row.project_identity == actual_identity for row in self.rows):
            raise RemoteHistoryHold()
        owner, parent, name, _base = global_journal._inputs(self.token, self.binding, unit)
        if owner is not self.owner or parent != self.held.namespace[0]:
            raise RemoteHistoryHold()
        prefix = name[:-len('.journal')]
        future = frozenset((prefix+'.completion-started', prefix+'.completion'))
        present = future & frozenset(os.listdir(parent))
        self.check_c6()
        self.held.verify(parent_additions=self.additions | present)
        self.check_c6()
        self.verify_cycles()

    def verify(self):
        from monitor import issue_tracker_local_commit as local
        self.verify_cycles()
        if (local._owner(self.writer) is not self.project
                or ownership._validated_owner(self.token, self.binding) is not self.owner):
            raise RemoteHistoryHold()
        self.held.verify(parent_additions=self.additions)
        self.check_c6()
        self.held.verify(parent_additions=self.additions)
        self.verify_cycles()

    def created(self, unit, verify_created):
        # Called only AFTER the fixed real creator yields its held originals,
        # while its context remains live. Public entry points accept neither
        # this object nor names, verifiers, additions or a completion label.
        from monitor import issue_tracker_attempt_journal as journal
        project_identity = journal._identity(os.fstat(self.project.project_fd))[:2]
        if not any(row.unit == unit and row.project_identity == project_identity for row in self.rows):
            raise RemoteHistoryHold()
        owner, parent, name, _base = global_journal._inputs(self.token, self.binding, unit)
        if owner is not self.owner or parent != self.held.namespace[0]:
            raise RemoteHistoryHold()
        prefix = name[:-len('.journal')]
        additions = frozenset((prefix+'.completion-started', prefix+'.completion'))
        if additions & (self.held.namespace[2] | self.additions):
            raise RemoteHistoryHold()
        verify_created()
        # Overlap the actual creator with new retained FD/raw/full-stat
        # originals BEFORE it may close. Recheck its saved identities AFTER
        # capture so same-byte substitution cannot become the new original.
        self.held.file(parent, prefix+'.completion-started', 16384)
        folder = self.held.directory(parent, prefix+'.completion')
        wanted = {'HEADER', 'COMPLETE', *(file for _key, _kind, file in _COMPLETION_READS)}
        if set(os.listdir(folder)) != wanted:
            raise RemoteHistoryHold()
        for file in sorted(wanted):
            self.held.file(folder, file, 65536 if file == 'HEADER' else
                (16384 if file == 'COMPLETE' else 2*1024*1024))
        verify_created()
        self.additions |= additions
        self.verify()


def reconcile_pending_project_units(writer_token, owner_token, binding, authentication=None):
    """Select this project's counted units from ALL actual catalog/C6 originals.

    No caller unit, generation, plan, path or response is accepted. Shared
    catalog/origins/families and ALL real project C6 stay pinned through the
    fixed four-read driver and its exclusive completion creator. Existing
    public readers remain strict. Count zero is not permission to authenticate,
    create NEW or send. Without an explicit original authentication, the fixed
    owned OAuth unit runs once, only after selecting a counted current-project
    row with ALL originals held. No caller factory or auth result is adopted.
    Original attempts and UNKNOWN are never reset.
    """
    return _reconcile_pending_project_units(writer_token, owner_token, binding, authentication)


def _reconcile_pending_project_units(writer_token, owner_token, binding, authentication=None, *, _store=None):
    # Keep the ordinary read-only result diagnostic-only.
    result, _authentication = _reconcile_pending_project_units_with_authentication(
        writer_token, owner_token, binding, authentication, _store=_store)
    return result


def _reconcile_pending_project_units_and_project_auth(writer_token, owner_token, binding, *, _store=None):
    """Return actual lazy OAuth only after ALL reconciliation finalizers.

    No caller credential/factory or old read verifier is accepted. The exact
    process-local issued authentication remains bound to the original live
    owners/current target. Later use requires ordinary issuer checks and NEW
    actual reads; this is not a snapshot, G1 or send capability.
    No current counted unit returns ((), None), without authenticating.
    """
    failed = False
    try:
        result, authentication = _reconcile_pending_project_units_with_authentication(
            writer_token, owner_token, binding, _store=_store)
        if authentication is not None:
            from monitor.issue_tracker_token_launcher import require_current_owned_project_token
            from monitor.issue_tracker_online_target import inspect_project_online_target
            require_current_owned_project_token(owner_token, binding, authentication)
            inspect_project_online_target(writer_token, binding)
            require_current_owned_project_token(owner_token, binding, authentication)
    except Exception:
        failed = True
    if failed:
        raise RemoteHistoryHold() from None
    return result, authentication


@contextmanager
def _hold_current_project_last_original_owners(writer_token, owner_token, binding):
    """Keep newly acquired original foreign owners past strict C6 readers.

    ALL original origins locate the last unit, never the last current-project
    subset. No old verifier escapes, and the returned row is only a locator.
    Existing live owners are borrowed, not transferred to this cleanup scope.
    The fixed consumer independently overlaps fresh actual write-aware images
    while its strict core is live; this scope grants no COUNT or send authority.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_attempt_journal as journal
    from monitor import issue_tracker_unit_catalog as catalog
    owner_tail=ExitStack();primary=cleanup_problem=None
    try:
        project=local._owner(writer_token)
        owner=ownership._validated_owner(owner_token,binding)
        def current():
            if (local._owner(writer_token) is not project
                    or ownership._validated_owner(owner_token,binding) is not owner):
                raise RemoteHistoryHold()
        with catalog.hold_pending_project_origins(owner_token,binding) as (origins,verify_origins):
            with catalog._hold_project_c6_from_origins(owner_token,binding,origins,
                    _owner_tail=owner_tail) as (rows,verify_c6):
                if (not rows or tuple(row.unit for row in rows)!=tuple(origin.unit for origin in origins)
                        or rows[-1].project_identity!=journal._identity(os.fstat(project.project_fd))[:2]):
                    raise RemoteHistoryHold()
                last=rows[-1]
                current();verify_origins();verify_c6()
        # Both semantic scopes have completed. Never invoke their verifiers
        # here or return them as evidence of the next input/count scope.
        current();yield last;current()
    except BaseException as error:
        primary=error
    finally:
        try:owner_tail.close()
        except BaseException as error:
            cleanup_problem=error
            if primary is None or (isinstance(primary,Exception) and not isinstance(error,Exception)):
                primary=error
    if primary is not None:
        if isinstance(primary,Exception):raise RemoteHistoryHold() from None
        if cleanup_problem is not None and cleanup_problem is not primary:raise primary from cleanup_problem
        raise primary


@contextmanager
def _hold_native_current_cycle_compiler_inputs(prepared,writer_token,owner_token,binding,*,
                                             _store,http_root):
    """Fixed current C5/C6 originals for one genuine native compiler scope.

    Derive K, W1, qualification and latest-cycle receipts from actual held
    inputs, not caller snapshots or an old generation. No acquisition of a
    second sheet owner, network read, catalog append, COUNT or send authority.
    The observed compiler and actual native registration remain separate.
    """
    from pathlib import Path
    from monitor import issue_tracker_local_commit as local,issue_tracker_nv_reservation as native
    from monitor import issue_tracker_settings_audit_allocation as allocation
    from monitor import issue_tracker_stage_l_consumer as source,issue_tracker_receipt_snapshot as receipts
    from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
    from monitor.issue_tracker_state_owner import current_k,_settings_original_scope
    from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
    try:
        record=native._verify_catalog_preparation(prepared)
        project=local._owner(writer_token);owner=ownership._validated_owner(owner_token,binding)
        root=Path(http_root)
        if (record['token'] is not owner_token or record['binding']!=binding
                or root.resolve(strict=True)!=root or not root.is_absolute()
                or Path(_store.project_identity)!=project.project or _store.scope!='prod'
                or type(prepared) is native._CatalogNonallocatingPreparation
                   and record['nonallocating_writer'] is not writer_token):raise RemoteHistoryHold()
        whitelist_path=root/'monitor/Issue_Tracker_Template_v1.xlsx'
        def preparation_tail():
            if (native._verify_catalog_preparation(prepared) is not record
                    or local._owner(writer_token) is not project
                    or ownership._validated_owner(owner_token,binding) is not owner):raise RemoteHistoryHold()
        with _settings_original_scope() as scope:
            scope.callback(preparation_tail)
            prior=tuple(row for row in record['prior_delivery_events']
                if row['writer'] is writer_token and row['owner'] is project and row['raw'] is not None)
            verify_cycle=scope.enter_context(_hold_current_completed_cycle_replay(_store))
            verify_history=scope.enter_context(receipts._hold_history_originals(writer_token))
            verify_inputs=scope.enter_context(source._hold_original_replay_inputs(_store,project.project,whitelist_path))
            # LIFO: revoke/finish actual K settings first, while every current
            # cycle/C6/source raw verifier is still live. Their real finalizers
            # must reject a receipt rebound during the last settings close;
            # no qualification or K capability is reused after K revocation.
            if prior:
                scope.enter_context(allocation._hold_native_catalog_k_read(prepared,writer_token,owner_token,binding))
            def originals():
                preparation_tail();verify_cycle();verify_history();verify_inputs();preparation_tail()
            originals()
            settings=current_k(writer_token);whitelist=read_whitelist_workbook(whitelist_path)
            qualified=source.qualify_prod_stage_l(_store,http_root=root,settings=settings,
                whitelist_snapshot=whitelist,whitelist_path=whitelist_path,writer_token=writer_token)
            observed=receipts.read_current_cycle_local_receipts(writer_token,_store,
                expected_template_sha256=whitelist.workbook_sha256,settings=settings,
                whitelist_sha256=whitelist.whitelist.sha256,qualified_source=qualified)
            if (not observed.generation_ids or observed.published!=len(observed.generation_ids)
                    or qualified.cycle_ids[-1]!=observed.cycle_id):raise RemoteHistoryHold()
            originals()
            yield settings,whitelist,qualified,observed
            originals()
            if (current_k(writer_token)!=settings or read_whitelist_workbook(whitelist_path)!=whitelist
                    or source.qualify_prod_stage_l(_store,http_root=root,settings=settings,
                        whitelist_snapshot=whitelist,whitelist_path=whitelist_path,writer_token=writer_token)!=qualified
                    or receipts.read_current_cycle_local_receipts(writer_token,_store,
                        expected_template_sha256=whitelist.workbook_sha256,settings=settings,
                        whitelist_sha256=whitelist.whitelist.sha256,qualified_source=qualified)!=observed):
                raise RemoteHistoryHold()
            originals()
    except Exception:
        raise RemoteHistoryHold() from None


@contextmanager
def _hold_current_cycle_native_receipt_locators(writer_token,*,_store,http_root):
    """Retain current C5/C6/K originals across native preparation discovery.

    Plain generation/publish locators are NOT retained eligibility or a closed
    verifier. A future preparation must independently replay current C5/C6/K
    and every original source while live; these labels cannot create or adopt
    an enrollment, reservation, compiled unit, COUNT or send permission.
    """
    from pathlib import Path
    from monitor import issue_tracker_local_commit as local
    try:
        project=local._owner(writer_token);root=Path(http_root)
        if (not root.is_absolute() or root.resolve(strict=True)!=root
                or Path(_store.project_identity)!=project.project or _store.scope!='prod'):raise RemoteHistoryHold()
        # Reject foreign/unissued writers before importing source readers.
        # No partially imported source/K provider escapes a refused entry.
        from monitor import issue_tracker_stage_l_consumer as source
        from monitor import issue_tracker_receipt_snapshot as receipts,issue_tracker_send_unit as compiler
        from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
        from monitor.issue_tracker_state_owner import current_k,_settings_original_scope
        from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
        whitelist_path=root/'monitor/Issue_Tracker_Template_v1.xlsx'
        def owner_tail():
            if local._owner(writer_token) is not project:raise RemoteHistoryHold()
        with _settings_original_scope() as scope:
            scope.callback(owner_tail)
            cycle=scope.enter_context(_hold_current_completed_cycle_replay(_store))
            history=scope.enter_context(receipts._hold_history_originals(writer_token))
            inputs=scope.enter_context(source._hold_original_replay_inputs(_store,project.project,whitelist_path))
            def originals():owner_tail();cycle();history();inputs();owner_tail()
            def snapshot():
                originals();settings=current_k(writer_token);whitelist=read_whitelist_workbook(whitelist_path)
                qualified=source.qualify_prod_stage_l(_store,http_root=root,settings=settings,
                    whitelist_snapshot=whitelist,whitelist_path=whitelist_path,writer_token=writer_token)
                observed=receipts.read_current_cycle_local_receipts(writer_token,_store,
                    expected_template_sha256=whitelist.workbook_sha256,settings=settings,
                    whitelist_sha256=whitelist.whitelist.sha256,qualified_source=qualified)
                if (not observed.generation_ids or observed.published!=len(observed.generation_ids)
                        or qualified.cycle_ids[-1]!=observed.cycle_id):raise RemoteHistoryHold()
                actual=tuple(compiler._original_receipt_identity(qualified,_store,generation,writer_token,
                    settings,whitelist,whitelist.workbook_sha256) for generation in observed.generation_ids)
                if len({item[0] for item in actual})!=len(actual):raise RemoteHistoryHold()
                originals();return settings,whitelist,qualified,observed,actual
            first=snapshot()
            originals();yield tuple(item[:2] for item in first[-1]);originals()
            if snapshot()!=first:raise RemoteHistoryHold()
            originals()
        owner_tail()
    except Exception:raise RemoteHistoryHold() from None


def _read_current_cycle_native_receipt_locators(writer_token,*,_store,http_root):
    """Plain labels only, after full closure; never a retained permission."""
    with _hold_current_cycle_native_receipt_locators(writer_token,_store=_store,http_root=http_root) as labels:
        result=labels
    return result


@contextmanager
def _hold_current_cycle_native_creation_locators(writer_token,owner_token,binding,*,_store,http_root):
    """Current creator discovery after genuine audit archival, never adoption.

    Ordinary/no-delivery discovery retains the existing strict locator. Old
    delivery claims require actual dual-owner ALL proof and immutable K/C5/C6
    source holders. The initial read issuer is retired before new native
    writes; only plain labels and its genuine original handoff reach prep.
    """
    from pathlib import Path
    from monitor import issue_tracker_local_commit as local,issue_tracker_settings_audit_allocation as allocation
    try:
        project=local._owner(writer_token);ownership._validated_owner(owner_token,binding);root=Path(http_root)
        if (not root.is_absolute() or root.resolve(strict=True)!=root
                or Path(_store.project_identity)!=project.project or _store.scope!='prod'):raise RemoteHistoryHold()
        claims={name for name in os.listdir(project.root_fd)
            if name in (allocation._DELIVERY_FOLDER,allocation._DELIVERY_STARTED)
            or name.startswith(allocation._DELIVERY_FOLDER+'-') or name.startswith(allocation._DELIVERY_STARTED+'-')}
        if not claims:
            with _hold_current_cycle_native_receipt_locators(writer_token,_store=_store,http_root=root) as labels:
                yield labels,None
            return
        from monitor import issue_tracker_stage_l_consumer as source,issue_tracker_receipt_snapshot as receipts
        from monitor import issue_tracker_send_unit as compiler
        from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
        from monitor.issue_tracker_state_owner import current_k,_settings_original_scope
        from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
        path=root/'monitor/Issue_Tracker_Template_v1.xlsx'
        # Outer prior scope's actual raw tail finishes AFTER source/settings
        # cleanup. Initial ALL semantics never span the native append.
        with allocation._hold_owned_native_prior_source_read(writer_token,owner_token,binding) as bridge:
            with _settings_original_scope() as scope:
                cycle=scope.enter_context(_hold_current_completed_cycle_replay(_store))
                history=scope.enter_context(receipts._hold_history_originals(writer_token))
                inputs=scope.enter_context(source._hold_original_replay_inputs(_store,project.project,path))
                def originals():
                    if local._owner(writer_token) is not project:raise RemoteHistoryHold()
                    cycle();history();inputs();ownership._validated_owner(owner_token,binding)
                originals();settings=current_k(writer_token);whitelist=read_whitelist_workbook(path)
                qualified=source.qualify_prod_stage_l(_store,http_root=root,settings=settings,
                    whitelist_snapshot=whitelist,whitelist_path=path,writer_token=writer_token)
                observed=receipts.read_current_cycle_local_receipts(writer_token,_store,
                    expected_template_sha256=whitelist.workbook_sha256,settings=settings,
                    whitelist_sha256=whitelist.whitelist.sha256,qualified_source=qualified)
                if (not observed.generation_ids or observed.published!=len(observed.generation_ids)
                        or qualified.cycle_ids[-1]!=observed.cycle_id):raise RemoteHistoryHold()
                actual=tuple(compiler._original_receipt_identity(qualified,_store,g,writer_token,
                    settings,whitelist,whitelist.workbook_sha256) for g in observed.generation_ids)
                if len({row[0] for row in actual})!=len(actual):raise RemoteHistoryHold()
                # Move this same-call response-independent freeze before the
                # FIRST bounded identity read. Only plain intent bytes and
                # receipt relations cross the existing genuine raw handoff;
                # no qualified set, K/nonce issuer or skip permission does.
                from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
                metadata={'project_id':str(_store.project_identity),'schema_version':1,
                    'producer_version':'stage-l-runtime-v1','template_contract_version':'local-xlsx-v1',
                    'template_sha256':whitelist.workbook_sha256}
                manifest,manifest_id=freeze_prod_stage_l_manifest(qualified,_store,http_root=root,
                    settings=settings,whitelist_snapshot=whitelist,whitelist_path=path,metadata=metadata,
                    expected_template_sha256=whitelist.workbook_sha256,writer_token=writer_token)
                packet=allocation._owned_prior_source_packet(bridge,owner_token,binding)
                if (packet['retired'] or packet['received'] or 'native_pre_read_manifest' in packet
                        or 'native_pre_read_manifest_issued' in packet):raise RemoteHistoryHold()
                intent=(manifest,manifest_id,tuple(row[:3] for row in actual))
                packet['native_pre_read_manifest']=intent
                packet['native_pre_read_manifest_issued']=intent
                originals();yield tuple(row[:2] for row in actual),bridge;originals()
                packet=allocation._owned_prior_source_packet(bridge,owner_token,binding)
                if (packet.get('native_pre_read_manifest') is not intent
                        or packet.get('native_pre_read_manifest_issued') is not intent):raise RemoteHistoryHold()
                # Raw source holders finalize normally here. The actual prep
                # independently replayed C5/C6/K while LIVE; no stale K scope
                # or closed semantic verifier is invoked at this boundary.
    except Exception:raise RemoteHistoryHold() from None


def _prepare_current_cycle_native_switch_unit(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Fixed current Switch preparation; no caller source or send permission."""
    return _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,
        _store=_store,http_root=http_root,_sheet='ETH&IB Switch')


def _prepare_current_cycle_native_switch_originals(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Same-call genuine NEW Switch creation plus original zero-count prereads.

    No existing unit, locator, callback, old verifier or repair selector enters.
    Native creator/locator finalizers finish before the independent NEW writes;
    original issued responses keep their existing deadlines throughout.
    This creates local originals only, never COUNT, CLAIM or a network write.
    """
    return _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,
        _store=_store,http_root=http_root,_sheet='ETH&IB Switch',_new_originals=True)


def _prepare_current_cycle_native_eth_cabling_unit(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Fixed ETH preparation; original columns select genuine NV when needed."""
    return _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,
        _store=_store,http_root=http_root,_sheet='ETH Cabling')


def _prepare_current_cycle_native_eth_cabling_originals(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Fixed same-call ETH NEW originals, including genuine NV inserts."""
    return _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,
        _store=_store,http_root=http_root,_sheet='ETH Cabling',_new_originals=True)


def _prepare_current_cycle_native_ib_cabling_unit(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Fixed IB preparation; original columns select genuine NV when needed."""
    return _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,
        _store=_store,http_root=http_root,_sheet='IB Cabling')


def _prepare_current_cycle_native_ib_cabling_originals(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Fixed same-call IB NEW originals, including genuine NV inserts."""
    return _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,
        _store=_store,http_root=http_root,_sheet='IB Cabling',_new_originals=True)


def _current_cycle_native_new_pending(writer_token,owner_token,binding):
    """Necessary ALL-original settlement observation, never NEW/send authority.

    Counted UNKNOWN stays pending. Zero-count historical units leave pending
    only through the actual FIFO reader's three original UNSENT records.
    All semantic readers finish before any creator runs; no closed verifier
    is handed off and fresh native preparation still independently qualifies.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_retained_inventory as inventory
    try:
        project=local._owner(writer_token);owner=ownership._validated_owner(owner_token,binding)
        # Reuse the original reconciliation's exact first-use contract: all
        # three local enrollment originals, not a lock/name subset. Missing
        # enrollment refuses before current source selection or lazy OAuth.
        if _observe_original_first_catalog_absence(writer_token,owner_token,binding):return False
        with inventory._hold_all_project_mixed_settlements(owner_token,binding) as (rows,verify_mixed):
            verify_mixed()
            if any(row.attempt_count and not row.settled for row in rows):pending=True
            else:
                with inventory._hold_all_project_fifo_frontier(owner_token,binding) as (fifo,verify_fifo):
                    verify_mixed();verify_fifo();verify_mixed()
                    ids=tuple(row.unit.unit_id for row in rows)
                    counted=tuple(row.unit.unit_id for row in rows if row.attempt_count and row.settled)
                    zero={row.unit.unit_id for row in rows if row.attempt_count==0}
                    parts=(fifo.applied,fifo.superseded,fifo.frontier,tuple(item[0] for item in fifo.blocked))
                    flattened=tuple(item for part in parts for item in part)
                    if (fifo.projects!=tuple((row.unit.unit_id,row.project_identity) for row in rows)
                            or fifo.applied!=counted or not set(fifo.superseded)<=zero
                            or len(ids)!=len(set(ids)) or len(flattened)!=len(set(flattened))
                            or set(flattened)!=set(ids)):raise RemoteHistoryHold()
                    pending=bool(fifo.frontier or fifo.blocked)
                    verify_fifo();verify_mixed();verify_fifo()
            verify_mixed()
        if local._owner(writer_token) is not project or ownership._validated_owner(owner_token,binding) is not owner:
            raise RemoteHistoryHold()
        return pending
    except Exception:raise RemoteHistoryHold() from None


def _prepare_next_current_cycle_native_originals(writer_token,owner_token,binding,authentication,*,_store,http_root):
    """Fixed current Switch/ETH/IB loop; first WIRE stops, actual NO_SEND advances.

    Pending ALL originals only block NEW; they do not grant FIRST/R2 selection.
    Skipped families are actual same-call NO_SEND, never supplied/cold labels.
    The returned authentication is still independently validated by every
    consumer, not GO. No COUNT, CLAIM, mutation or bootstrap occurs here.
    """
    from monitor import issue_tracker_local_commit as local
    try:
        project=local._owner(writer_token);owner=ownership._validated_owner(owner_token,binding)
        if _current_cycle_native_new_pending(writer_token,owner_token,binding):
            return ('EXISTING_PENDING',None,authentication)
        skipped=();original_stamp=None;original_families=None
        for _index in range(3):
            state,unit_id,selected,families,authentication,stamp=_prepare_current_cycle_native_unit(
                writer_token,owner_token,binding,authentication,_store=_store,http_root=http_root,
                _sheet='AUTO',_new_originals=True,_skipped_sheets=skipped,
                _same_cycle=None if original_stamp is None else (original_stamp,original_families))
            if (local._owner(writer_token) is not project
                    or ownership._validated_owner(owner_token,binding) is not owner
                    or selected in skipped or selected not in families
                    or original_stamp is not None and (stamp!=original_stamp or families!=original_families)):
                raise RemoteHistoryHold()
            if state=='WIRE_REGISTERED':return (state,unit_id,authentication)
            if state!='NO_SEND':raise RemoteHistoryHold()
            original_stamp=stamp;original_families=families;skipped=(*skipped,selected)
            if set(skipped)==set(families):return ('NO_SEND',None,authentication)
        raise RemoteHistoryHold()
    except Exception:raise RemoteHistoryHold() from None


@contextmanager
def _hold_native_preparation_source_reads():
    """Borrow actual original FDs only, not K/source/READ observations."""
    from tools import ufm_collection_pipeline as pipeline
    try:
        source=pipeline._HELD_SOURCE_READS.get()
        directories=pipeline._HELD_DIRECTORY_READS.get()
        with ExitStack() as scope:
            if source is None and directories is None:
                scope.enter_context(pipeline._hold_reusable_directory_reads())
                scope.enter_context(pipeline._hold_reusable_source_reads())
                source=pipeline._HELD_SOURCE_READS.get()
                directories=pipeline._HELD_DIRECTORY_READS.get()
            if (type(source) is not pipeline._OriginalSourceReads
                    or type(directories) is not pipeline._OriginalDirectoryReads
                    or source.directories is not directories):raise RemoteHistoryHold()
            def current():
                if (pipeline._HELD_SOURCE_READS.get() is not source
                        or pipeline._HELD_DIRECTORY_READS.get() is not directories):raise RemoteHistoryHold()
                source.require_live();source.verify();source.require_live()
            current();yield;current()
        # Only this scope's original issuers close here. Borrowed holders
        # remain with the actual enclosing NEW owner, never reset/reissued.
    except Exception:raise RemoteHistoryHold() from None


def _prepare_current_cycle_native_unit(writer_token,owner_token,binding,authentication,*,
                                      _store,http_root,_sheet,_new_originals=False,_skipped_sheets=(),_same_cycle=None):
    """Fixed NEW source-FD owner; original read tail follows all FD cleanup."""
    options=dict(_store=_store,http_root=http_root,_sheet=_sheet,
        _new_originals=_new_originals,_skipped_sheets=_skipped_sheets,_same_cycle=_same_cycle)
    if _new_originals is not True:
        return _prepare_current_cycle_native_unit_unscoped(writer_token,owner_token,binding,authentication,
            **options,_source_tail=None)
    from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
    from monitor.issue_tracker_token_launcher import require_current_owned_project_token
    from tools import ufm_collection_pipeline as pipeline
    try:
        original_tail=[]
        # NEW owns the actual issuers. A pre-existing pair is not borrowed:
        # nested issuance still refuses, rather than returning before its
        # caller's eventual source/directory cleanup.
        with ExitStack() as original_scope:
            original_scope.enter_context(pipeline._hold_reusable_directory_reads())
            original_scope.enter_context(pipeline._hold_reusable_source_reads())
            result=_prepare_current_cycle_native_unit_unscoped(writer_token,owner_token,binding,authentication,
                **options,_source_tail=original_tail)
        if len(original_tail)!=1:raise RemoteHistoryHold()
        actual_authentication,actual_images=original_tail[0]
        require_current_owned_project_token(owner_token,binding,actual_authentication)
        for kind,title,row,response in actual_images:
            require_current_owned_project_read(writer_token,owner_token,binding,response,actual_authentication,
                read_kind=kind,sheet=title,row=row)
        require_current_owned_project_token(owner_token,binding,actual_authentication)
        return result
    except Exception:raise RemoteHistoryHold() from None


def _prepare_current_cycle_native_unit_unscoped(writer_token,owner_token,binding,authentication,*,
                                      _store,http_root,_sheet,_new_originals=False,_skipped_sheets=(),_same_cycle=None,
                                      _source_tail=None):
    """Fixed native preparation and local pending registration, never a send.

    Derive latest current C6 inside live source holders, not caller generation
    or unit. Existing local enrollment is mandatory, never bootstrap/adoption.
    A local pending entry or NO_SEND observation is not G1, COUNT, send or a
    proof about final outer-owner cleanup. No compiler object escapes closure.
    """
    from pathlib import Path
    from monitor import issue_tracker_local_commit as local
    try:
        project=local._owner(writer_token);sheet_owner=ownership._validated_owner(owner_token,binding)
        root=Path(http_root)
        automatic=_sheet=='AUTO'
        fixed=('ETH&IB Switch','ETH Cabling','IB Cabling')
        if (_sheet not in (*fixed,'AUTO') or automatic and not _new_originals
                or type(_skipped_sheets) is not tuple or len(set(_skipped_sheets))!=len(_skipped_sheets)
                or any(title not in fixed for title in _skipped_sheets)
                or not automatic and (_skipped_sheets or _same_cycle is not None)
                or type(_new_originals) is not bool
                or not root.is_absolute() or root.resolve(strict=True)!=root
                or Path(_store.project_identity)!=project.project or _store.scope!='prod'):raise RemoteHistoryHold()
        from monitor import issue_tracker_nv_reservation as native,issue_tracker_unit_catalog as catalog
        from monitor.issue_tracker_history_read_launcher import OwnedProjectSheetsReadUnit,require_current_owned_project_read
        from monitor.issue_tracker_token_launcher import require_current_owned_project_token
        new_images=None;new_unit=None;new_packet=None
        with _hold_current_cycle_native_creation_locators(writer_token,owner_token,binding,
                _store=_store,http_root=root) as (labels,prior_bridge):
            # Derive necessary Cabling keys from current protected C5 before
            # issuing bounded reads. The held locator context and fixed
            # compiler independently revalidate this source; no caller keys.
            keys=()
            if automatic:
                from monitor import issue_tracker_stage_l_consumer as source
                from monitor.issue_tracker_state_owner import current_k
                from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
                whitelist_path=root/'monitor/Issue_Tracker_Template_v1.xlsx'
                qualified=source.qualify_prod_stage_l(_store,http_root=root,settings=current_k(writer_token),
                    whitelist_snapshot=read_whitelist_workbook(whitelist_path),whitelist_path=whitelist_path,
                    writer_token=writer_token)
                family_by_sheet={'ETH&IB Switch':'switch','ETH Cabling':'eth_cabling','IB Cabling':'ib_cabling'}
                present={item.activity_key[0] for item in qualified.candidates}
                families=tuple(title for title in fixed if family_by_sheet[title] in present)
                remaining=tuple(title for title in families if title not in _skipped_sheets)
                if (not remaining or not set(_skipped_sheets)<=set(families)
                        or _same_cycle is not None and (labels,families)!=_same_cycle):raise RemoteHistoryHold()
                _sheet=remaining[0]
            if _sheet!='ETH&IB Switch':
                from monitor import issue_tracker_stage_l_consumer as source
                from monitor.issue_tracker_state_owner import current_k
                from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
                whitelist_path=root/'monitor/Issue_Tracker_Template_v1.xlsx'
                qualified=source.qualify_prod_stage_l(_store,http_root=root,settings=current_k(writer_token),
                    whitelist_snapshot=read_whitelist_workbook(whitelist_path),whitelist_path=whitelist_path,
                    writer_token=writer_token)
                family={'ETH Cabling':'eth_cabling','IB Cabling':'ib_cabling'}[_sheet]
                keys=tuple(item.activity_key for item in qualified.candidates if item.activity_key[0]==family)
                if not keys or len(set(keys))!=len(keys):raise RemoteHistoryHold()
            if automatic and authentication is None:
                from monitor.issue_tracker_token_launcher import OwnedProjectTokenRefreshUnit
                authentication=OwnedProjectTokenRefreshUnit(owner_token,binding).refresh_once()
            require_current_owned_project_token(owner_token,binding,authentication)
            observed=OwnedProjectSheetsReadUnit(writer_token,owner_token,binding,authentication,
                read_kind='template_identity').read_once()
            plan,_project,_digest=require_current_owned_project_read(writer_token,owner_token,binding,observed,
                authentication,read_kind='template_identity')
            identity=decode.decode_template_identity(plan,observed)
            selection_reads=[]
            def verify_initial_identity():
                require_current_owned_project_token(owner_token,binding,authentication)
                current=require_current_owned_project_read(writer_token,owner_token,binding,observed,
                    authentication,read_kind='template_identity')
                if current!=(plan,_project,_digest) or decode.decode_template_identity(current[0],observed)!=identity:
                    raise RemoteHistoryHold()
                require_current_owned_project_token(owner_token,binding,authentication)
                if require_current_owned_project_read(writer_token,owner_token,binding,observed,
                        authentication,read_kind='template_identity')!=current:raise RemoteHistoryHold()
                for title,response,original in selection_reads:
                    if require_current_owned_project_read(writer_token,owner_token,binding,response,
                            authentication,read_kind='activity',sheet=title)!=original:raise RemoteHistoryHold()
                require_current_owned_project_token(owner_token,binding,authentication)
                for title,response,original in selection_reads:
                    if require_current_owned_project_read(writer_token,owner_token,binding,response,
                            authentication,read_kind='activity',sheet=title)!=original:raise RemoteHistoryHold()
            verify_initial_identity()
            generation,publish=labels[-1]
            missing=()
            def read_activity(title):
                verify_initial_identity()
                response=OwnedProjectSheetsReadUnit(writer_token,owner_token,binding,authentication,
                    read_kind='activity',sheet=title).read_once()
                original=require_current_owned_project_read(writer_token,owner_token,binding,response,
                    authentication,read_kind='activity',sheet=title)
                selection_reads.append((title,response,original));verify_initial_identity()
                return original[0],response
            if keys:
                target_plan,target_response=read_activity(_sheet)
                sid=dict(identity.sheet_ids)[_sheet]
                missing=tuple(key for key in keys if not decode.discover_activity_sheet(target_plan,target_response,
                    sheet_id=sid,activity_key=key).active_rows)
            if missing:
                other='IB Cabling' if _sheet=='ETH Cabling' else 'ETH Cabling'
                other_plan,other_response=read_activity(other)
                eth,ib=((target_plan,target_response),(other_plan,other_response)) if _sheet=='ETH Cabling' else (
                    (other_plan,other_response),(target_plan,target_response))
                preparation=native.hold_catalog_nv_preparation(owner_token,binding,identity,*eth,*ib,
                    generation_id=generation,publish_id=publish,sheet=_sheet,requested_keys=missing,
                    _source_prior_bridge=prior_bridge)
            else:preparation=native.hold_catalog_nonallocating_preparation(writer_token,owner_token,binding,identity,
                generation_id=generation,publish_id=publish,sheet=_sheet,_source_prior_bridge=prior_bridge)
            verify_initial_identity()
            with preparation as prepared:
                receiver=(_hold_native_current_cycle_observed_switch_unit if _sheet=='ETH&IB Switch'
                    else _hold_native_current_cycle_observed_nv_cabling_unit if missing
                    else _hold_native_current_cycle_observed_cabling_unit)
                with receiver(prepared,writer_token,owner_token,binding,
                        authentication,_store=_store,http_root=root) as unit:
                    if unit.outcome=='WIRE-CANDIDATE':
                        catalog.register_pending_c6_unit(writer_token,owner_token,binding,unit,
                            **({'_nv_preparation':prepared} if missing else {'_unit_preparation':prepared}))
                        if _new_originals:
                            record=native._verify_catalog_preparation(prepared)
                            tail=record['nv_project_read_tail' if missing else 'project_read_tail'];packet=tail.packet
                            if (packet is not tail._issued_packet or packet[:3]!=(writer_token,owner_token,binding)
                                    or packet[3] is not project or packet[4] is not sheet_owner
                                    or packet[5] is not authentication or packet[7] is not unit):raise RemoteHistoryHold()
                            new_packet=record['native_current_original_prereads']
                            if (new_packet is not record['native_current_original_prereads_issued']
                                    or type(new_packet) is not tuple or len(new_packet)!=4
                                    or new_packet[0] is not unit or new_packet[1] is not authentication
                                    or new_packet[2] is not packet[6]):raise RemoteHistoryHold()
                            new_images=packet[6];new_unit=unit
                        result=('WIRE_REGISTERED',unit.unit_id)
                    elif unit.outcome=='NO_SEND':result=('NO_SEND',unit.unit_id)
                    else:raise RemoteHistoryHold()
                    if _source_tail is not None:
                        # The actual receiver is still LIVE. Preserve only
                        # its once-issued response references, never a closed
                        # preparation/K verifier or caller-supplied tail.
                        original_record=(record if unit.outcome=='WIRE-CANDIDATE'
                            else native._verify_catalog_preparation(prepared))
                        original_packet=original_record['native_current_original_prereads']
                        if (original_packet is not original_record['native_current_original_prereads_issued']
                                or type(original_packet) is not tuple or len(original_packet)!=4
                                or original_packet[0] is not unit or original_packet[1] is not authentication
                                or type(original_packet[2]) is not tuple or not original_packet[2]):raise RemoteHistoryHold()
                        initial=(('template_identity',None,None,observed),)
                        selections=tuple(('activity',title,None,response) for title,response,_plan in selection_reads)
                        _source_tail.append((authentication,(*initial,*selections,*original_packet[2])))
            verify_initial_identity()
        # Check the original initial read after every source-holder finalizer.
        # These external owners are still live; no closed source/K verifier is
        # revived and no fresh read or deadline can replace the original.
        verify_initial_identity()
        if new_unit is not None:
            # The entire native locator/bridge has closed successfully. Its
            # strict namespace allowances are unchanged: these NEW families
            # are never written inside a closed/revived preparation scope.
            from monitor import issue_tracker_history_preread_journal as preread
            from monitor import issue_tracker_metadata_reservation as reservation
            def original_reads():
                if (local._owner(writer_token) is not project
                        or ownership._validated_owner(owner_token,binding) is not sheet_owner
                        or record.get('native_current_original_prereads') is not new_packet
                        or record.get('native_current_original_prereads_issued') is not new_packet
                        or new_packet[0] is not new_unit or new_packet[1] is not authentication
                        or new_packet[2] is not new_images):raise RemoteHistoryHold()
                verify_initial_identity()
                for kind,title,row,response in new_images:
                    require_current_owned_project_read(writer_token,owner_token,binding,response,
                        authentication,read_kind=kind,sheet=title,row=row)
                require_current_owned_project_token(owner_token,binding,authentication)
            original_reads()
            business=new_packet[3]
            if (type(business) is not tuple or len(business)!=len(new_unit.outcomes)
                    or tuple(reading['operation_id'] for reading in business)!=tuple(item[0] for item in new_unit.outcomes)
                    or any(type(reading) is not dict or set(reading)!=
                        {'operation_id','discovery_response','occupancy_response','row_response'} for reading in business)
                    or any(response is not None and not any(response is image[3] for image in new_images)
                        for reading in business for name,response in reading.items() if name.endswith('_response'))
                    or new_images[0][:3]!=('template_identity',None,None)
                    or new_images[1][:3]!=('metadata',None,None)
                    or new_images[-1][:3]!=('history_tail',None,None)):raise RemoteHistoryHold()
            body=local._json(new_unit.action_preimage);generation_id=body['identity']['generation_id']
            generation=local.Generation(generation_id,int(local._GEN.fullmatch(generation_id).group(1)),
                body['manifest_id'],writer_token)
            with _hold_applied_generation(writer_token,generation,new_unit) as (actual,verify_c6,_facts,_operations):
                if actual is not project:raise RemoteHistoryHold()
                def current():original_reads();verify_c6();original_reads()
                current();global_journal.prepare_global_unit(owner_token,binding,new_unit);current()
                preread.prepare_owned_project_history_preread(writer_token,owner_token,binding,authentication,new_unit,
                    identity_response=new_images[0][3],history_response=new_images[-1][3]);current()
                preread.prepare_owned_project_business_preread(writer_token,owner_token,binding,authentication,
                    generation,new_unit,identity_response=new_images[0][3],business_reads=business);current()
                reservation.prepare_owned_project_metadata_reservation(writer_token,owner_token,binding,authentication,
                    new_unit,identity_response=new_images[0][3],metadata_response=new_images[1][3]);current()
            original_reads()
        return (*result,_sheet,families,authentication,labels) if automatic else result
    except Exception:raise RemoteHistoryHold() from None


@contextmanager
def _hold_native_current_cycle_observed_switch_unit(prepared,writer_token,owner_token,binding,authentication,*,
                                                    _store,http_root):
    """Fixed Switch-only reception; no caller source, plan or row coordinates."""
    with _hold_native_current_cycle_observed_nonallocating_unit(prepared,writer_token,owner_token,binding,
            authentication,_store=_store,http_root=http_root,_sheets=('ETH&IB Switch',)) as unit:
        yield unit


@contextmanager
def _hold_native_current_cycle_observed_cabling_unit(prepared,writer_token,owner_token,binding,authentication,*,
                                                     _store,http_root):
    """Derive the unique current ETH/IB target; missing/Closed keys stay HOLD.

    No caller family or allocator fallback. This read-only nonallocating
    receiver handles existing active rows only, never creates an NV store.
    """
    with _hold_native_current_cycle_observed_nonallocating_unit(prepared,writer_token,owner_token,binding,
            authentication,_store=_store,http_root=http_root,_sheets=('ETH Cabling','IB Cabling')) as unit:
        yield unit


def _verify_native_issued_nv_columns(prepared,writer_token,owner_token,binding,authentication,eth_response,ib_response):
    """Necessary retained-column equality; no allocation/read/NEW authority."""
    from monitor import issue_tracker_nv_reservation as native
    from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
    from monitor.issue_tracker_token_launcher import require_current_owned_project_token
    try:
        record=native._verify_catalog_preparation(prepared)
        if (type(prepared) is not native._CatalogNvPreparation or record['token'] is not owner_token
                or record['binding']!=binding):raise RemoteHistoryHold()
        original=prepared.observation
        require_current_owned_project_token(owner_token,binding,authentication)
        for sheet,completion in (('ETH Cabling',eth_response),('IB Cabling',ib_response)):
            require_current_owned_project_read(writer_token,owner_token,binding,completion,authentication,
                read_kind='activity',sheet=sheet)
        if tuple(hashlib.sha256(item.data).hexdigest() for item in (eth_response,ib_response))!=(
                original.eth_source_sha256,original.ib_source_sha256):raise RemoteHistoryHold()
        if (native._verify_catalog_preparation(prepared) is not record or prepared.observation is not original
                or record['token'] is not owner_token or record['binding']!=binding):raise RemoteHistoryHold()
        require_current_owned_project_token(owner_token,binding,authentication)
    except Exception:raise RemoteHistoryHold() from None


@contextmanager
def _hold_native_current_cycle_observed_nv_cabling_unit(prepared,writer_token,owner_token,binding,authentication,*,
                                                        _store,http_root):
    """Fixed current Cabling insertion receiver under genuine retained NV IDs.

    The other original Cabling column is issued and checked too. No caller
    family, key, plan, reservation or fallback from nonallocating reception.
    This compiler edge is not G1, COUNT, send or preparation-tail completion.
    """
    with _hold_native_current_cycle_observed_nonallocating_unit(prepared,writer_token,owner_token,binding,
            authentication,_store=_store,http_root=http_root,_sheets=('ETH Cabling','IB Cabling'),
            _native_nv=True) as unit:
        yield unit


def _native_pre_read_manifest_intent(record,original,qualified,metadata):
    """Pure exact intent comparison, NOT current source or owner authority.

    The fixed receiver has independently acquired its actual preparation and
    requalified source. These bytes only select reads; original compiler start
    and end fresh freezes remain mandatory before any WIRE registration.
    """
    from monitor.issue_tracker_manifest import _runtime_recorded_at,_runtime_skip,_canonical_array
    from monitor import issue_tracker_local_commit as local
    try:
        packet=record['native_pre_read_manifest']
        if (packet is not record['native_pre_read_manifest_issued'] or type(packet) is not tuple
                or len(packet)!=3 or type(packet[0]) is not bytes or not 1<=len(packet[0])<=1024*1024
                or type(packet[1]) is not str or hashlib.sha256(packet[0]).hexdigest()!=packet[1]
                or type(packet[2]) is not tuple or type(original) is not tuple or len(original)!=3
                or sum(row==original for row in packet[2])!=1 or original[2]!=packet[1]):
            raise RemoteHistoryHold()
        source={'cycle_ids':list(qualified.cycle_ids),'k':qualified.k,'mode':qualified.mode,
            'scope':qualified.scope,'project_key':qualified.project_key,
            'source_authority_sha256':qualified.source_authority_sha256,
            'observations_sha256':qualified.observations_sha256,
            'whitelist_sha256':qualified.whitelist_sha256,'k_event_sha256':qualified.k_event_sha256,
            'completion_sha256':list(qualified.completion_sha256),
            'recorded_at_utc':_runtime_recorded_at(qualified.recorded_at_utc),
            'whitelist_skips':[_runtime_skip(item) for item in qualified.whitelist_skips]}
        operations=_canonical_array(qualified.operations_json,'runtime operations')
        if (metadata['template_sha256']!=qualified.template_sha256
                or packet[0]!=local._canonical({**metadata,'operations':operations,'qualified_source':source})):
            raise RemoteHistoryHold()
        return packet[:2]
    except Exception:raise RemoteHistoryHold() from None


@contextmanager
def _hold_native_current_cycle_observed_nonallocating_unit(prepared,writer_token,owner_token,binding,authentication,*,
                                                           _store,http_root,_sheets,_native_nv=False):
    """Acquire fixed issued images under current C5/C6 and preparation originals.

    No caller plans, rows, generation, qualified source, metadata inventory or
    compiler callback. This constructs a candidate, never COUNT/send or G1 GO;
    registration remains an independent operation inside this live scope.
    """
    from pathlib import Path
    from monitor import issue_tracker_nv_reservation as native,issue_tracker_send_unit as compiler
    from monitor import issue_tracker_metadata_capacity as capacity
    from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
    from monitor.issue_tracker_history_read_launcher import OwnedProjectSheetsReadUnit,require_current_owned_project_read
    from monitor.issue_tracker_token_launcher import require_current_owned_project_token
    from monitor.issue_tracker_state_owner import _settings_original_scope
    try:
        record=native._verify_catalog_preparation(prepared)
        if (_sheets not in (('ETH&IB Switch',),('ETH Cabling','IB Cabling'))
                or type(_native_nv) is not bool or _native_nv and _sheets!=('ETH Cabling','IB Cabling')
                or type(prepared) is not (native._CatalogNvPreparation if _native_nv else native._CatalogNonallocatingPreparation)
                or record['token'] is not owner_token or record['binding']!=binding
                or not _native_nv and record['nonallocating_writer'] is not writer_token):raise RemoteHistoryHold()
        prepared_unit_id=prepared.observation.unit_id if _native_nv else prepared.unit_id
        acquired=[]
        def verify_reads():
            require_current_owned_project_token(owner_token,binding,authentication)
            for kind,sheet,row,response in acquired:
                require_current_owned_project_read(writer_token,owner_token,binding,response,authentication,
                    read_kind=kind,sheet=sheet,row=row)
        def read(kind,*,sheet=None,row=None):
            verify_reads()
            response=OwnedProjectSheetsReadUnit(writer_token,owner_token,binding,authentication,
                read_kind=kind,sheet=sheet,row=row).read_once()
            acquired.append((kind,sheet,row,response));verify_reads()
            plan,_project,_digest=require_current_owned_project_read(writer_token,owner_token,binding,
                response,authentication,read_kind=kind,sheet=sheet,row=row)
            return plan,response
        # The issued-read/authentication tail outlives the actual K and raw
        # source finalizers. It does not reuse K or requalify closed inputs.
        with _settings_original_scope() as read_scope:
            read_scope.callback(verify_reads)
            from monitor import issue_tracker_settings_audit_allocation as allocation
            migrated=allocation._native_received_prior_source_manifest(prepared,writer_token,owner_token,binding)
            def intent_tail():
                if allocation._native_received_prior_source_manifest(
                        prepared,writer_token,owner_token,binding) is not migrated:raise RemoteHistoryHold()
            # LIFO: compiler K/C6/source, then source borrower close, then
            # pure intent reception, then the unchanged original read tail.
            # This data does not replace the upcoming fresh qualification.
            read_scope.callback(intent_tail)
            # Retain only actual directory/file descriptors, not digests or
            # qualification results. Every compiler boundary still replays
            # its original checks and hashes current bytes. Their revoke and
            # conditional cleanup finish BEFORE the unchanged issued-read tail.
            read_scope.enter_context(_hold_native_preparation_source_reads())
            with _hold_native_current_cycle_compiler_inputs(prepared,writer_token,owner_token,binding,
                    _store=_store,http_root=http_root) as (settings,whitelist,qualified,receipts):
                # Finish response-independent local derivation BEFORE issuing
                # the bounded reads. Their original deadline includes launch
                # time and is never refreshed to pay for local source replay.
                metadata={'project_id':str(_store.project_identity),'schema_version':1,
                    'producer_version':'stage-l-runtime-v1','template_contract_version':'local-xlsx-v1',
                    'template_sha256':whitelist.workbook_sha256}
                context=dict(http_root=Path(http_root),settings=settings,whitelist_snapshot=whitelist,
                    whitelist_path=Path(http_root)/'monitor/Issue_Tracker_Template_v1.xlsx',metadata=metadata,
                    expected_template_sha256=whitelist.workbook_sha256,writer_token=writer_token)
                if migrated is None:
                    # Standalone/no-bridge keeps its original freeze order.
                    manifest,manifest_id=freeze_prod_stage_l_manifest(qualified,_store,**context)
                originals=tuple(compiler._original_receipt_identity(qualified,_store,generation,writer_token,
                    settings,whitelist,whitelist.workbook_sha256) for generation in receipts.generation_ids)
                selected=tuple((original,sheet) for original in originals for sheet in _sheets
                    if native._nonallocating_identity(owner_token,binding,record['identity'],
                        original[0],original[1],sheet)[0]==prepared_unit_id)
                if len(selected)!=1:raise RemoteHistoryHold()
                original,sheet=selected[0]
                if migrated is not None:
                    manifest,manifest_id=_native_pre_read_manifest_intent(record,original[:3],qualified,metadata)
                if original[2]!=manifest_id:raise RemoteHistoryHold()
                family=compiler._FAMILY[sheet]
                operations=tuple(item for item in json.loads(manifest)['operations'] if item['activity_key'][0]==family)
                if not operations:raise RemoteHistoryHold()
                identity_plan,identity_response=read('template_identity')
                identity=decode.decode_template_identity(identity_plan,identity_response)
                if identity!=record['identity']:raise RemoteHistoryHold()
                metadata_plan,metadata_response=read('metadata')
                budget=capacity.observe_metadata_capacity(metadata_plan,metadata_response,identity,reservations=())
                if budget.outcome!='VISIBLE_ONLY_UNPROVED':raise RemoteHistoryHold()
                document=json.loads(metadata_response.data.decode('utf8'),object_pairs_hook=capacity._pairs,
                    parse_constant=capacity._nonfinite)
                occupied=tuple(item['developerMetadata']['metadataId']
                    for item in document.get('matchedDeveloperMetadata',[]))
                sid=dict(identity.sheet_ids)[sheet]
                discovery_plan,discovery_response=read('activity',sheet=sheet)
                if _native_nv:
                    other_sheet='IB Cabling' if sheet=='ETH Cabling' else 'ETH Cabling'
                    _other_plan,other_response=read('activity',sheet=other_sheet)
                    columns=(discovery_response,other_response) if sheet=='ETH Cabling' else (other_response,discovery_response)
                    _verify_native_issued_nv_columns(prepared,writer_token,owner_token,binding,authentication,*columns)
                occupancy_plan,occupancy_response=read('insertion',sheet=sheet)
                occupancy,row_count,_digest=decode._insertion_sheet_image(occupancy_plan,occupancy_response,
                    sheet_id=sid,title=sheet,target=binding.spreadsheet_id)
                cells={(index,column):value for index,column,value in occupancy};reserved=[];business=[]
                columns=('B','C','F','J','K','L','M','N','O','P','Q','R','S','T','U')
                for operation in operations:
                    key=tuple(operation['activity_key'])
                    discovery=decode.discover_activity_sheet(discovery_plan,discovery_response,sheet_id=sid,activity_key=key)
                    if discovery.active_rows:
                        if len(discovery.active_rows)!=1:raise RemoteHistoryHold()
                        index=discovery.active_rows[0][0]
                    else:
                        # A genuine nonallocating Cabling scope cannot invent
                        # missing IDs or reinterpret Closed as a free row.
                        if sheet!='ETH&IB Switch' and not _native_nv:raise RemoteHistoryHold()
                        if _native_nv:index=None
                        else:
                            index=next((index for index in range(2,row_count) if index not in reserved
                                and all(cells[(index,column)]==() for column in columns)),None)
                            if index is None:raise RemoteHistoryHold()
                    if index is not None and index in reserved:raise RemoteHistoryHold()
                    row_plan,row_response=(read('row',sheet=sheet,row=index+1) if index is not None else (None,None))
                    business.append({'operation_id':operation['operation_id'],'discovery_plan':discovery_plan,
                        'discovery_response':discovery_response,'occupancy_plan':occupancy_plan,
                        'occupancy_response':occupancy_response,'row_plan':row_plan,'row_response':row_response})
                    if index is not None:reserved.append(index)
                history_plan,history_response=read('history_tail')
                freeze=(compiler.freeze_observed_receipted_switch_unit if sheet=='ETH&IB Switch'
                    else compiler.freeze_observed_receipted_cabling_unit)
                family_options={} if sheet=='ETH&IB Switch' else {'sheet':sheet}
                unit=freeze(qualified,_store,**context,**family_options,
                    local_generation_id=original[0],business_reads=tuple(business),history_plan=history_plan,
                    history_response=history_response,spreadsheet_token=owner_token,binding=binding,identity=identity,
                    occupied_metadata_ids=occupied,**({'_nv_preparation':prepared} if _native_nv else {'_unit_preparation':prepared}))
                original_images=tuple(acquired)
                if _native_nv:
                    # Existing actual reservation comparison remains WIRE-only;
                    # an NV preparation never gains NO_SEND cancellation.
                    if native._catalog_nv_compiled_observation(prepared,owner_token,binding,unit)!=prepared.observation:
                        raise RemoteHistoryHold()
                    native._bind_nv_project_read_tail(prepared,writer_token,owner_token,binding,
                        authentication,original_images,unit)
                else:native._bind_nonallocating_project_read_tail(prepared,writer_token,owner_token,binding,
                    authentication,original_images,unit)
                # Same lexical producer, not a supplied locator/plan/guard.
                # Preserve each actual operation's raw response references,
                # including None-row NV inserts and the separate other column.
                if any(name in record for name in ('native_current_original_prereads',
                        'native_current_original_prereads_issued')):raise RemoteHistoryHold()
                creation=(unit,authentication,original_images,
                    tuple({name:reading[name] for name in ('operation_id','discovery_response',
                        'occupancy_response','row_response')} for reading in business))
                record['native_current_original_prereads']=creation
                record['native_current_original_prereads_issued']=creation
                verify_reads();yield unit;verify_reads()
    except Exception:
        raise RemoteHistoryHold() from None


def _acquire_current_project_template_reads(writer_token, owner_token, binding, authentication):
    """One fixed acquisition; four original observations, never a snapshot grant.

    The launcher owns the unchanged acquisition deadline, complete cleanup and
    final original checks. Keep each consumer read gate after issuance. This
    boundary accepts no read shape, provider, qualification or cached result.
    """
    from monitor.issue_tracker_history_read_launcher import (
        OwnedProjectTemplateReadCohort, require_current_owned_project_read)
    kinds=('template_identity','template_headers','whitelist','metadata')
    observed=OwnedProjectTemplateReadCohort(writer_token,owner_token,binding,authentication).read_once()
    if type(observed) is not tuple or len(observed)!=4:
        raise RemoteHistoryHold()
    responses=dict(zip(kinds,observed))
    for kind,response in responses.items():
        require_current_owned_project_read(writer_token,owner_token,binding,response,
            authentication,read_kind=kind)
    return responses


def _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses):
    """Fresh fixed originals at one boundary; no retained aggregate authority.

    Share only the existing group's source reads within this non-yield check.
    Every original response, registration and deadline is checked on entry and
    after the final auth/target read. Separate graph IO/cleanup boundaries must
    call again; this neither caches a PASS nor renews an observation.
    """
    from monitor.issue_tracker_history_read_launcher import _require_current_owned_project_read_group
    kinds=('template_identity','template_headers','whitelist','metadata')
    if type(responses) is not dict or set(responses)!=set(kinds):raise RemoteHistoryHold()
    captured=tuple(responses[kind] for kind in kinds)
    _require_current_owned_project_read_group(writer_token,owner_token,binding,authentication,
        tuple((kind,None,None,response) for kind,response in zip(kinds,captured)))
    if set(responses)!=set(kinds) or any(responses[kind] is not response
            for kind,response in zip(kinds,captured)):raise RemoteHistoryHold()


@contextmanager
def _hold_current_project_online_inputs(writer_token, owner_token, binding, authentication, *,
                                        _store, http_root):
    """Acquire fixed current source and actual reads while strict scopes LIVE.

    The previous reconciliation's authentication may be reused only while its
    actual owners remain live. ALL catalog/C6/family originals are acquired
    anew before observing the current source or issuing reads. No caller unit,
    qualified set, read plan, quota list or historical completeness is adopted.
    The fixed internal consumer may overlap genuine business images before
    these strict scopes close. No selected unit, callback, factory or permission
    is supplied by the caller. This scope does not count, claim or send.
    """
    from pathlib import Path
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_attempt_journal as journal
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_retained_inventory as inventory
    from monitor import issue_tracker_stage_l_consumer as source
    from monitor import issue_tracker_receipt_snapshot as receipts
    from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
    from monitor.issue_tracker_state_owner import current_k
    from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
    from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
    from monitor.issue_tracker_token_launcher import (
        OwnedProjectTokenRefreshUnit, require_current_owned_project_token)
    from monitor.issue_tracker_metadata_reservation import _hold_owned_project_mixed_metadata_capacity
    from monitor.issue_tracker_history_preread_journal import _hold_owned_original_business_history_inputs
    from monitor.issue_tracker_online_target import inspect_project_online_target

    failed = False; interruption = [None]
    try:
        project = local._owner(writer_token)
        ownership._validated_owner(owner_token, binding)
        root = Path(http_root)
        if (not root.is_absolute() or root.resolve(strict=True) != root
                or Path(_store.project_identity) != project.project):
            raise RemoteHistoryHold()
        whitelist_path = root / 'monitor/Issue_Tracker_Template_v1.xlsx'
        business_guards = []; prepared = []
        @contextmanager
        def remember_interruption():
            try: yield
            except BaseException as error:
                interruption[0] = error
                raise
        with ExitStack() as business_tail_scope, ExitStack() as native_k_scope, \
                ExitStack() as business_scope, ExitStack() as scope, remember_interruption():
            from monitor import issue_tracker_settings_audit_allocation as allocation
            claims={name for name in os.listdir(project.root_fd)
                if name in (allocation._DELIVERY_FOLDER,allocation._DELIVERY_STARTED)
                or name.startswith(allocation._DELIVERY_FOLDER+'-')
                or name.startswith(allocation._DELIVERY_STARTED+'-')}
            if claims:
                # The exact actual owners already dominate this input reader.
                # Prove ALL completed delivery originals before reading K;
                # do not reacquire a sheet lock, create a preparation or use a
                # closed creator bridge. Its actual catalog loan must remain
                # LIVE until every business semantic borrower has closed;
                # overlapping original business raw tails outlive this issuer.
                native_k_scope.enter_context(allocation._hold_owned_native_completed_source_k(
                    writer_token,owner_token,binding))
            rows, verify_c6 = scope.enter_context(catalog.hold_pending_project_c6_units(owner_token, binding))
            retained, verify_inventory = scope.enter_context(
                inventory._hold_catalog_retained_inventory(owner_token, binding))
            settlements, verify_settlements = scope.enter_context(
                inventory._hold_all_project_mixed_settlements(owner_token, binding))
            if (tuple(row.unit for row in rows) != tuple(row.unit for row in retained)
                    or tuple(row.unit for row in rows) != tuple(row.unit for row in settlements)
                    or any(row.project_identity != settlement.project_identity
                        or observation.attempt_count != settlement.attempt_count
                        for row, observation, settlement in zip(rows, retained, settlements))):
                raise RemoteHistoryHold()
            current_identity = journal._identity(os.fstat(project.project_fd))[:2]
            selected = tuple((row, observation) for row, observation, settlement in zip(rows, retained, settlements)
                if row.project_identity == current_identity and observation.attempt_count < 6
                and not settlement.settled)
            if not selected:
                raise RemoteHistoryHold()
            verify_cycle = scope.enter_context(_hold_current_completed_cycle_replay(_store))
            verify_history = scope.enter_context(receipts._hold_history_originals(writer_token))
            verify_inputs = scope.enter_context(source._hold_original_replay_inputs(
                _store, project.project, whitelist_path))

            def originals():
                local._owner(writer_token); ownership._validated_owner(owner_token, binding)
                verify_c6(); verify_inventory(); verify_settlements()
                verify_cycle(); verify_history(); verify_inputs()
                inspect_project_online_target(writer_token, binding)

            def qualify():
                originals()
                settings = current_k(writer_token)
                whitelist = read_whitelist_workbook(whitelist_path)
                qualified = source.qualify_prod_stage_l(_store, http_root=root, settings=settings,
                    whitelist_snapshot=whitelist, whitelist_path=whitelist_path, writer_token=writer_token)
                originals()
                return settings, whitelist, qualified

            settings, whitelist, qualified = qualify()
            source_inputs = []; current_source_scopes = []
            for row, observation in selected:
                action = local._json(row.unit.action_preimage)
                generation_id = action['identity']['generation_id']
                _template, original_source = receipts._manifest_source(project, generation_id)
                actual = qualified
                if tuple(original_source['cycle_ids']) != qualified.cycle_ids:
                    if not observation.attempt_count:
                        raise RemoteHistoryHold()
                    actual = source.replay_original_receipted_prod_source(_store, http_root=root,
                        settings=settings, whitelist_snapshot=whitelist, whitelist_path=whitelist_path,
                        expected_template_sha256=whitelist.workbook_sha256,
                        local_generation_id=generation_id, writer_token=writer_token)
                # Only the identity-independent FIRST local prefix precedes
                # actual online reads. Identity/receipt gates precede business
                # binding; the full current-source suffix follows ALL fresh IO.
                global_journal._prepare_first_original_source_prefix(row,observation,
                    qualified_source=actual,store=_store,writer_token=writer_token,settings=settings,
                    whitelist_snapshot=whitelist,expected_template_sha256=whitelist.workbook_sha256,
                    http_root=root,whitelist_path=whitelist_path,_shared_retry=bool(observation.attempt_count))
                unit_scope = scope.enter_context(ExitStack())
                observe_source = unit_scope.enter_context(
                    global_journal._hold_receipted_original_source_inputs(owner_token, binding, row.unit,
                        qualified_source=actual, store=_store, writer_token=writer_token, settings=settings,
                        whitelist_snapshot=whitelist, expected_template_sha256=whitelist.workbook_sha256,
                        http_root=root, whitelist_path=whitelist_path, _shared_retry=bool(observation.attempt_count)))
                bind_business = business_scope.enter_context(
                    _hold_owned_original_business_history_inputs(writer_token, owner_token, binding, row.unit))
                source_inputs.append((row, actual, unit_scope, observe_source, bind_business))
            # These original source/business scopes captured no COUNT join at
            # entry. Pre-acquire only the exact FIRST row's read-only Count
            # graph now; old strict K/ALL borrowers close in their same order,
            # and no ATTEMPT or CLAIM is created before all genuine fresh IO.
            global_journal._prefetch_first_original_count_graph()
            if authentication is None:
                authentication = OwnedProjectTokenRefreshUnit(owner_token, binding).refresh_once()
            originals(); require_current_owned_project_token(owner_token, binding, authentication)
            originals()
            responses = _acquire_current_project_template_reads(writer_token,owner_token,binding,authentication)
            for kind in ('template_identity', 'template_headers', 'whitelist', 'metadata'):
                originals()
                # Each use still checks the complete original source graph
                # around its actual once-issued observation. Cohort acquisition
                # itself publishes nothing until all four requests and final
                # original auth/target/owner/cleanup checks have completed.
                require_current_owned_project_read(writer_token,owner_token,binding,responses[kind],
                    authentication,read_kind=kind)
                originals()
            identity_plan, _project, _digest = require_current_owned_project_read(
                writer_token, owner_token, binding, responses['template_identity'], authentication,
                read_kind='template_identity')
            identity = decode.decode_template_identity(identity_plan, responses['template_identity'])
            with _hold_owned_project_mixed_metadata_capacity(writer_token, owner_token, binding,
                    authentication, identity_response=responses['template_identity'],
                    metadata_response=responses['metadata']) as (budget, verify_capacity):
                for row, actual, unit_scope, observe_source, bind_business in source_inputs:
                    observe_owned_unit_read_gates(writer_token, owner_token, binding, row.unit,
                        whitelist_snapshot=whitelist.whitelist, identity_response=responses['template_identity'],
                        headers_response=responses['template_headers'], whitelist_response=responses['whitelist'],
                        metadata_response=responses['metadata'])
                    observe_source(identity)
                    _business, verify_business = business_scope.enter_context(
                        bind_business(authentication, identity_response=responses['template_identity']))
                    business_guards.append(verify_business)
                    prepared.append((row, actual, verify_business))
                    if claims:
                        # Capture genuine LIVE original FDs before yield or
                        # ANY finalizer, including exceptional exit. After the
                        # strict business reader closes this real overlap uses
                        # only original issued reads and its own held raw graph,
                        # never a stale catalog verifier or a K/count grant.
                        business_tail_scope.enter_context(verify_business._hold_original_images())
                    originals(); verify_capacity()
                    if actual is qualified:
                        # Retain EVERY actual current-source scope until ALL
                        # fresh business/continuity/capacity IO is complete.
                        # Its original second qualification then occupies the
                        # last source-replay boundary, not an early snapshot.
                        current_source_scopes.append(unit_scope)
                    else:
                        unit_scope.close()
                if current_source_scopes:
                    originals()
                    if (current_k(writer_token), read_whitelist_workbook(whitelist_path)) != (settings, whitelist):
                        raise RemoteHistoryHold()
                    for unit_scope in current_source_scopes:
                        # This executes the REAL original source() again,
                        # including all four K graphs and full receipt/cycle/
                        # target/owner tails. No closed verifier, cached
                        # qualification result or caller provider is adopted.
                        unit_scope.close()
                    originals()
                elif qualify() != (settings, whitelist, qualified):
                    # An older source cannot stand in for the current source.
                    raise RemoteHistoryHold()
                _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses)
                originals(); verify_capacity()
                if budget.outcome != 'VISIBLE_ONLY_UNPROVED':
                    raise RemoteHistoryHold()
            originals()
            yield settings, whitelist, responses, tuple(prepared), authentication
            # The separate business holders dominate even the LAST old source/
            # C6/inventory finalizer. Their own originals remain live here.
            scope.close()
            for verify_business in business_guards: verify_business()
            business_scope.close()
            native_k_scope.close()
            business_tail_scope.close()
        # No FD/inventory verifier is reused after closure. Check every actual
        # unit's original issued reads after ALL business holders have exited.
        for verify_business in business_guards: verify_business._verify_issued_only()
        _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses)
        require_current_owned_project_token(owner_token, binding, authentication)
        inspect_project_online_target(writer_token, binding)
    except BaseException as error:
        primary = interruption[0]
        if primary is not None and not isinstance(primary, Exception):
            if error is not primary: raise primary from error
            raise
        if not isinstance(error, Exception): raise
        # Public traceback/message stay typed and suppress original context;
        # retain the actual fault internally for bounded evidence diagnosis.
        raise RemoteHistoryHold() from None


def _prepare_current_project_online_observation(writer_token, owner_token, binding, authentication, *,
                                                _store, http_root):
    """Unchanged read-only diagnostic after ALL original finalizers.

    Never acquire the new image graph here or turn visible accounting into
    admission. The fixed acquisition scope preserves the original close order
    and actual issued business/read/authentication checks exactly.
    """
    with _hold_current_project_online_inputs(writer_token, owner_token, binding, authentication,
            _store=_store, http_root=http_root):
        pass
    return 'VISIBLE_ONLY_UNPROVED'


@contextmanager
def _hold_current_project_online_original_inputs(writer_token, owner_token, binding, authentication, *,
                                                 _store, http_root):
    """Fixed live input graph, never a returned closed permit or GO.

    Original cycle/config/W1 and actual issued images outlive strict ALL
    catalog/count/quota readers. No closed verifier or path reacquisition is
    used for business images. Dedicated-from-creation / one historical Cloud
    project is a confirmed deployment precondition, not API evidence. Retain
    actual same-project quota images separately; this input edge still cannot
    count, claim, launch or report GO. Only the actual selected row and held
    original images are yielded; a future fixed driver must independently
    enforce G1/FIFO and actual FIRST/R2 admission inside this scope.
    """
    from pathlib import Path
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_stage_l_consumer as source
    from monitor.issue_tracker_cycle_source import _hold_current_completed_cycle_replay
    from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
    from monitor.issue_tracker_token_launcher import require_current_owned_project_token
    from monitor.issue_tracker_online_target import inspect_project_online_target
    from monitor.issue_tracker_metadata_reservation import (
        MetadataReservationHold, _hold_owned_project_dedicated_quota_images)
    try:
        project = local._owner(writer_token)
        ownership._validated_owner(owner_token, binding)
        root = Path(http_root)
        if (not root.is_absolute() or root.resolve(strict=True) != root
                or Path(_store.project_identity) != project.project):
            raise RemoteHistoryHold()
        with _hold_current_project_last_original_owners(writer_token,owner_token,binding) as last, \
                _hold_current_completed_cycle_replay(_store) as verify_cycle, \
                source._hold_original_replay_inputs(_store, project.project,
                    root/'monitor/Issue_Tracker_Template_v1.xlsx') as verify_inputs, \
                global_journal._hold_first_original_source_prefix(writer_token,owner_token,binding,last), \
                ExitStack() as all_images, \
                ExitStack() as quota_images, ExitStack() as images:
            verify_quota = None; budget = None
            with _hold_current_project_online_inputs(writer_token, owner_token, binding, authentication,
                    _store=_store, http_root=root) as prepared:
                _settings, _whitelist, responses, originals, authentication = prepared
                selected=tuple(row for row,_actual_source,_guard in originals
                    if row.unit==last.unit and row.project_identity==last.project_identity
                    and row.c6_facts==last.c6_facts)
                if len(selected)!=1:
                    raise RemoteHistoryHold()
                # Use the actual prepared unit object, not the independently
                # parsed primer locator or a reconstructed FrozenUnit. Only
                # the genuine ALL-last graph can protect the following tail.
                verify_all=all_images.enter_context(
                    global_journal._hold_selected_last_catalog_write_originals(
                        writer_token,owner_token,binding,selected[0].unit))
                verify_all()
                global_journal._bind_first_original_source_prefix(selected[0])
                try:
                    budget, verify_quota = quota_images.enter_context(
                        _hold_owned_project_dedicated_quota_images(writer_token, owner_token, binding, authentication,
                            identity_response=responses['template_identity'], metadata_response=responses['metadata']))
                except MetadataReservationHold:
                    # Legacy quotas have no historical project origin. Retain
                    # their existing read-only observation, never infer/repair
                    # provenance or grant permission from today's credentials.
                    verify_quota = None
                else:
                    if not budget.inventory_complete or budget.outcome not in (
                            'DEDICATED_PROJECT_CAPACITY', 'STOP_CAPACITY'):
                        raise RemoteHistoryHold()
                    verify_quota()
                graphs = []
                for row, actual_source, guard in originals:
                    packet, verify = images.enter_context(guard._hold_original_images())
                    if packet[0] is not responses['template_identity']:
                        raise RemoteHistoryHold()
                    graphs.append((row, actual_source, guard, packet, verify))
                verify_cycle(); verify_inputs(); verify_all()
            # ALL strict count/catalog/quota/business scopes have completed.
            # Only genuinely overlapped images and actual issued reads survive.
            verify_cycle(); verify_inputs(); verify_all()
            if verify_quota is not None:
                verify_quota()
            for _row, _actual_source, _guard, _packet, verify in graphs:
                verify()
            _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses)
            require_current_owned_project_token(owner_token, binding, authentication)
            inspect_project_online_target(writer_token, binding)
            selected_graph=tuple(graph for graph in graphs if graph[0] is selected[0])
            if len(selected_graph)!=1:
                raise RemoteHistoryHold()
            # Actual original owners/images dominate the entire consumer,
            # including its last cleanup. Do not return a closed guard as
            # evidence, adopt a caller selector or infer GO from visible quota.
            yield _settings,_whitelist,responses,selected_graph[0],authentication,budget
            verify_cycle(); verify_inputs(); verify_all()
            if verify_quota is not None:
                verify_quota()
            for _row,_actual_source,_guard,_packet,verify in graphs:
                verify()
            _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses)
            require_current_owned_project_token(owner_token,binding,authentication)
            inspect_project_online_target(writer_token,binding)
            # Finish actual image cleanup before the unchanged input-only
            # wrapper's typed refusal, or before the fixed driver's return.
            images.close()
            _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses)
            verify_cycle(); verify_inputs(); verify_all()
            if verify_quota is not None:
                verify_quota()
        _verify_current_project_template_reads(writer_token,owner_token,binding,authentication,responses)
        require_current_owned_project_token(owner_token, binding, authentication)
        inspect_project_online_target(writer_token, binding)
    except Exception:
        raise RemoteHistoryHold() from None


def _consume_current_project_online_original_inputs(writer_token, owner_token, binding, authentication, *,
                                                     _store, http_root):
    """Unchanged input-only entry: actual live graph, then HOLD without COUNT."""
    with _hold_current_project_online_original_inputs(writer_token,owner_token,binding,authentication,
            _store=_store,http_root=http_root):
        pass
    raise RemoteHistoryHold() from None


def _observe_original_first_catalog_absence(writer_token, owner_token, binding):
    """Strict original enrollment plus no catalog is a read-only observation.

    It is not enrollment provisioning, remote nonce proof, a NEW permit or
    permission to replace missing catalog/journal evidence. Existing families
    still go through the unchanged complete original reconciliation reader.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_enrollment_journal as enrollment
    from monitor import issue_tracker_local_commit as local
    from monitor.issue_tracker_sheets_read_decode import _TEMPLATE_SHEETS
    held = None; failed = False; absent = False
    try:
        project = local._owner(writer_token)
        owner = ownership._validated_owner(owner_token, binding)
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        names = {name for name in os.listdir(parent) if name.startswith(stem+'.')}
        if not names - {stem+'.lock', stem+'.enrollment'}:
            if names != {stem+'.lock', stem+'.enrollment'}:
                raise RemoteHistoryHold()
            held = catalog._originals(owner_token, binding)
            held.namespace = (parent, stem+'.', names)
            folder = held.directory(parent, stem+'.enrollment')
            if set(os.listdir(folder)) != {'HEADER', 'NONCES', 'INITIALIZED'}:
                raise RemoteHistoryHold()
            originals = {name: held.file(folder, name, 16384)[0]
                for name in ('HEADER', 'NONCES', 'INITIALIZED')}
            header = local._json(originals['HEADER'],
                {'schema_version', 'spreadsheet_id', 'sheet_ids', 'nonces_sha256'})
            rows = header['sheet_ids']
            if (type(header['schema_version']) is not int or header['schema_version'] != 1
                    or header['spreadsheet_id'] != binding.spreadsheet_id or type(rows) is not list
                    or len(rows) != len(_TEMPLATE_SHEETS)
                    or any(type(row) is not list or len(row) != 2
                        or row[0] != title or type(row[1]) is not int or not 0 <= row[1] <= 2147483647
                        for title, row in zip(_TEMPLATE_SHEETS, rows))
                    or len({row[1] for row in rows}) != len(rows)):
                raise RemoteHistoryHold()
            base = {key: header[key] for key in ('schema_version', 'spreadsheet_id', 'sheet_ids')}
            # The semantic reader uses the same actual pinned directory; no
            # typed remote identity is fabricated from this local header.
            held.verify()
            enrollment._inspect(parent, folder, stem+'.enrollment', base)
            held.verify()
            absent = True
        if (local._owner(writer_token) is not project
                or ownership._validated_owner(owner_token, binding) is not owner):
            raise RemoteHistoryHold()
        if held is not None:
            held.verify()
    except Exception:
        failed = True
    finally:
        if held is not None:
            try: held.close()
            except Exception: failed = True
    if failed: raise RemoteHistoryHold() from None
    return absent


def _reconcile_pending_project_units_with_authentication(writer_token, owner_token, binding, authentication=None, *, _store=None):
    """Private fixed worker composition, never a caller cycle/verifier permit."""
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_retained_inventory as inventory
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_attempt_journal as journal
    if _observe_original_first_catalog_absence(writer_token, owner_token, binding):
        return (), authentication
    failed = False; inputs = ExitStack(); proofs = ExitStack(); held = None
    try:
        project = local._owner(writer_token)
        owner = ownership._validated_owner(owner_token, binding)
        held = catalog._originals(owner_token, binding)
        _folder, units, _previous = catalog._inspect(owner_token, binding, held)
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        names = {name for name in os.listdir(parent) if name.startswith(stem+'.')}
        allowed = {stem+'.lock', stem+'.enrollment', stem+'.units', stem+'.units-started',
            *(stem+'.units-position-%020d' % position for position in range(1, len(units)+1))}
        allowed.update(stem+'.unit-'+unit.unit_id+'.'+family
            for unit in units for family in inventory._CATALOG_FAMILIES if family != 'enrollment')
        if names - allowed:
            raise RemoteHistoryHold()
        captured = {name for actual, name, *_rest in held.files if actual == parent}
        captured.update(name for actual, name, *_rest in held.directories if actual == parent)
        # Capture every original family BEFORE semantic readers or recovery
        # barriers. Their temporary scopes never substitute these actual FDs.
        for name in sorted(names-captured-{stem+'.lock'}):
            if name.endswith('-started'):
                held.file(parent, name, 16384)
            else:
                folder = held.directory(parent, name); family = name.rsplit('.', 1)[-1]
                entries = tuple(os.listdir(folder))
                if family == 'nv':
                    from monitor import issue_tracker_nv_reservation as nv
                    if frozenset(entries) != nv._CATALOG_NAMES:
                        raise RemoteHistoryHold()
                else:
                    inventory._family_entries(family, entries)
                for entry in sorted(entries):
                    limit = max(inventory._limit(family, entry), nv._LIMIT) if family == 'nv' else inventory._limit(family, entry)
                    held.file(folder, entry, limit)
        held.verify()
        with inventory._hold_catalog_retained_inventory(owner_token, binding) as (observations, verify_inventory):
            if units != tuple(row.unit for row in observations):
                raise RemoteHistoryHold()
            verify_inventory(); held.verify()
        with catalog.hold_pending_project_origins(owner_token, binding) as (origins, verify_origins):
            if units != tuple(row.unit for row in origins):
                raise RemoteHistoryHold()
            rows, check_c6 = inputs.enter_context(catalog._hold_project_c6_from_origins(owner_token, binding, origins))
            verify_origins(); held.verify(); check_c6()
        replay = _CatalogReconciliationOriginals(writer_token, owner_token, binding,
            held, owner, project, rows, check_c6, _store)
        replay.verify()
        current_identity = journal._identity(os.fstat(project.project_fd))[:2]
        results = []
        for row, observation in zip(rows, observations):
            if row.unit != observation.unit:
                raise RemoteHistoryHold()
            if row.project_identity != current_identity or not observation.attempt_count:
                continue
            if authentication is None:
                from monitor.issue_tracker_token_launcher import OwnedProjectTokenRefreshUnit
                replay.verify()
                authentication = OwnedProjectTokenRefreshUnit(owner_token, binding).refresh_once()
                replay.verify()
            facts = local._json(row.c6_facts)
            generation = local.Generation(facts['generation_id'], facts['sequence'], facts['manifest_id'], writer_token)
            results.append(proofs.enter_context(_hold_reconciled_owned_project_unit(
                writer_token, owner_token, binding, row.unit, authentication,
                generation=generation, _catalog=replay)))
            replay.verify()
        replay.verify()
        # Creator finalizers run with ALL C6 live. The overlapping retained
        # completion originals above then survive their close and ALL C6's
        # finalizers; no closed verifier or freshly adopted image is used.
        proofs.close(); replay.verify(); inputs.close()
        held.verify(parent_additions=replay.additions)
    except Exception:
        failed = True
    finally:
        try: inputs.close()
        except Exception: failed = True
        try: proofs.close()
        except Exception: failed = True
        if held is not None: held.close()
    if failed:
        raise RemoteHistoryHold()
    return tuple(results), authentication


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
            # GLOBAL/History belong to immutable unit namespaces. Enrollment
            # nonces belong to the ONE shared spreadsheet owner, not its unit;
            # derive the original fixed root name from the genuine owner only.
            # Never create/adopt a per-unit nonce copy or accept caller paths.
            name=owner.lock_name[:-5]+suffix if suffix=='.enrollment' else prefix+suffix
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
        # No fence and the exact original tail is still an unresolved attempt,
        # not proof of a conflicting partial application or of no transport.
        # This narrow observation does not clear COUNT/UNKNOWN or grant R2;
        # the governed retry independently requires all original continuity.
        unchanged_without_fence = (not fence_present and not foreign_fence
            and post.row_count == original.row_count
            and post.last_data_row_index == old_tail and post.cells == original.cells)
        conflict = (foreign_fence or post.row_count < original.row_count or old != still
                    or not unchanged_without_fence and
                    (actual != expected or post.last_data_row_index != old_tail + len(expected)))
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
    fd=None; owned_object=None
    try:
        owner,parent,name,_base=global_journal._inputs(owner_token,binding,unit)
        name=name[:-len('.journal')]+'.completion-started'
        fd=os.open(name,local._flags()|os.O_NONBLOCK,dir_fd=parent)
        opened=os.fstat(fd); owned_object=(opened.st_dev,opened.st_ino)
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
        # Full stat/name/raw equality governs proof; cleanup owns the original
        # object only. Byte/ctime drift does not transfer ownership, but a
        # recycled integer naming a foreign dev/inode must not be closed.
        # This does not claim portable same-inode open-description identity.
        if fd is not None:
            try: current=os.fstat(fd)
            except OSError: current=None
            if current is not None and (current.st_dev,current.st_ino)==owned_object:
                os.close(fd)


def record_owned_completion_evidence(writer_token,owner_token,binding,unit,*,
                                     identity_response,headers_response,metadata_response,history_response):
    """Persist the original proof set; this API alone grants no settlement."""
    with _hold_created_completion_evidence(writer_token,owner_token,binding,unit,
            identity_response=identity_response,headers_response=headers_response,
            metadata_response=metadata_response,history_response=history_response) as (result, verify):
        verify()
    return result


@contextmanager
def _hold_created_completion_evidence(writer_token,owner_token,binding,unit,*,
                                     identity_response,headers_response,metadata_response,history_response,
                                     _reconciliation=None):
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
                if _reconciliation is not None:
                    if type(_reconciliation) is not _CatalogReconciliationOriginals:
                        raise RemoteHistoryHold()
                    _reconciliation.verify_sources_during_creation(unit)
                if local._owner(writer_token) is not project: raise RemoteHistoryHold()
                if ownership._validated_owner(owner_token,binding) is not owner: raise RemoteHistoryHold()
                for key,kind,_file in _COMPLETION_READS:
                    require_current_owned_read(writer_token,owner_token,binding,responses[key],read_kind=kind)
                verify()
                if start_verify is not None: start_verify()
                if _reconciliation is not None:
                    _reconciliation.verify_sources_during_creation(unit)
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
                live()
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
            live()
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
            def verify_created():
                live(); journal._named(parent,name,folder,directory=True)
                if journal._identity(os.fstat(folder))!=directory_identity or set(os.listdir(folder))!=set(originals_saved):
                    raise RemoteHistoryHold()
                for file,saved in originals_saved.items():
                    if (journal._read(folder,file,2*1024*1024),list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False))))!=saved:
                        raise RemoteHistoryHold()
                live(); journal._named(parent,name,folder,directory=True)
                if journal._identity(os.fstat(folder))!=directory_identity: raise RemoteHistoryHold()
            verify_created()
            yield result,verify_created
            verify_created()
    except Exception: failed=True
    finally:
        try: scope.close()
        except Exception: failed=True
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise RemoteHistoryHold()


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
        from monitor.issue_tracker_history_read_launcher import _require_current_owned_read_group
        from monitor.issue_tracker_online_whitelist_read import compare_online_whitelist_read
        responses=(('template_identity',identity_response),('template_headers',headers_response),
                   ('whitelist',whitelist_response),('metadata',metadata_response))
        read_group=tuple((kind,None,None,response) for kind,response in responses)
        plans=_require_current_owned_read_group(writer_token,owner_token,binding,read_group)
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
        _require_current_owned_read_group(writer_token,owner_token,binding,read_group)
        result=OwnedUnitReadGateObservation(identity,whitelist.rules_sha256,pair.journal_sha256,capacity.outcome)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result
