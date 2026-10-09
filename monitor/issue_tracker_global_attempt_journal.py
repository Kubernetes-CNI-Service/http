"""Uninstalled conservative spreadsheet-wide immutable attempt evidence.

One retained unit blocks ALL new units in this spreadsheet, across projects.
The sole unit's action, binding and wire are immutable; at most six durable
UNKNOWN intents survive cold processes. No completion, reset, reclamation or
network here. A typed/coherent unit is not authenticated job/admission authority,
nor does an intent alone bound real sends: fixed launcher, single consumption,
fresh checks, reservations, FIFO and COMPLETE still need integration.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import os
import threading
import weakref

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_send_intent as compiled

_LIVE_WIRE_CLAIMS = weakref.WeakKeyDictionary()
_WIRE_CLAIM_GUARD = threading.Lock()


class GlobalAttemptHold(ValueError):
    def __init__(self): super().__init__('req7_global_attempt_unproved')


@dataclass(frozen=True)
class GlobalIntentObservation:
    attempt_count: int
    wire_sha256: str
    action_digest: str
    outcome: str


@dataclass(frozen=True,eq=False)
class CountedOriginalWireObservation:
    """Borrowed CLOEXEC read-only FD, NOT fresh admission or a send permit."""
    attempt_count: int
    wire_sha256: str
    fd: int = field(repr=False)
    action_fd: int = field(repr=False)


def _require_original_wire_launch(writer_token,token,binding,unit,image,*,consume):
    """Original active object only; a coherent/copyable FD tuple is not issued.

    Consume before Popen, including startup/final validation failure. Durable
    CLAIM already forbids cold reuse. This adds no fresh cadence/quota authority.
    """
    failed = False
    try:
        if type(image) is not CountedOriginalWireObservation: raise GlobalAttemptHold()
        with _WIRE_CLAIM_GUARD:
            issued = _LIVE_WIRE_CLAIMS.get(image)
            if issued is None: raise GlobalAttemptHold()
            writer,owner,target,original,wire,action,count,verify,used = issued
            if (writer is not writer_token or owner is not token or target != binding or original is not unit
                    or type(image.fd) is not int or image.fd != wire
                    or type(image.action_fd) is not int or image.action_fd != action
                    or type(image.attempt_count) is not int or image.attempt_count != count
                    or image.wire_sha256 != unit.wire_sha256
                    or (consume and used) or (not consume and not used)): raise GlobalAttemptHold()
            if consume: _LIVE_WIRE_CLAIMS[image] = issued[:-1]+(True,)
        verify()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()


def _inspect_wire_claims(claims, original, unit, header):
    if (journal._read(claims,'HEADER',16384) != local._canonical(header)
            or journal._read(claims,'INITIALIZED',16384) != _initialization(header)):
        raise GlobalAttemptHold()
    names = set(os.listdir(claims)); count = len(names)-2
    if not 0 <= count <= 6 or names != {'HEADER','INITIALIZED',*(f'CLAIM-{i}' for i in range(1,count+1))}:
        raise GlobalAttemptHold()
    previous = hashlib.sha256(local._canonical(header)).hexdigest()
    for index in range(1,count+1):
        raw = journal._read(claims,f'CLAIM-{index}',16384)
        expected = {'schema_version':1,'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,
            'attempt_count':index,'original_intent_sha256':hashlib.sha256(journal._read(original,f'ATTEMPT-{index}',16384)).hexdigest(),
            'previous_sha256':previous,'outcome':'CONSUMED_UNKNOWN_NOT_SEND_PROOF'}
        if raw != local._canonical(expected): raise GlobalAttemptHold()
        previous = hashlib.sha256(raw).hexdigest()
    return count,previous


@contextmanager
def _hold_counted_original_wire(writer_token,token,binding,unit):
    """Consume this original count once BEFORE eventual child launch.

    Private necessary handoff only: no Popen/socket/permission or counter reset.
    Both actual owners remain held. Immutable dispatch records survive cold
    owners, never backfill a missing/partial prefix, and cannot prove a send.
    Borrow the original read-only WIRE FD only inside this context; do not
    close/modify it. A caller/post-check failure retains consumed UNKNOWN.
    Real fresh admission, shared cadence and quota must dominate any launcher.
    """
    original = claims = wire = action = image = None; wire_identity = action_identity = None; failed = False
    prefix_originals = []
    try:
        project = local._owner(writer_token)
        owner,parent,name,base = _inputs(token,binding,unit)
        _require_no_completion(parent,name)
        original = local._directory(parent,name)
        journal._named(parent,name,original,directory=True)
        # The count is witnessed by the immutable ORIGINAL prefix, not merely
        # coherent bytes reopened after interpreting it. Pin every image and
        # the namespace BEFORE the first semantic count read, not only CLAIM.
        original_identity = journal._identity(os.fstat(original))
        names = set(os.listdir(original)); count = len(names)-4
        if (not 1 <= count <= 6 or names != {'ACTION-PREIMAGE','WIRE','HEADER','INITIALIZED',
                *(f'ATTEMPT-{i}' for i in range(1,count+1))}): raise GlobalAttemptHold()
        for entry in ('HEADER','INITIALIZED',*(f'ATTEMPT-{i}' for i in range(1,count+1))):
            fd = os.open(entry,local._flags()|os.O_NONBLOCK,dir_fd=original)
            prefix_originals.append((entry,fd,None))
            identity = journal._identity(os.fstat(fd))
            prefix_originals[-1] = (entry,fd,identity)
            journal._named(original,entry,fd,directory=False)
            raw = os.pread(fd,16385,0)
            if (len(raw) > 16384 or len(raw) != identity[6]
                    or raw != journal._read(original,entry,16384)
                    or journal._identity(os.fstat(fd)) != identity): raise GlobalAttemptHold()
        if journal._identity(os.fstat(original)) != original_identity: raise GlobalAttemptHold()
        wire = os.open('WIRE',local._flags()|os.O_NONBLOCK,dir_fd=original)
        journal._named(original,'WIRE',wire,directory=False)
        wire_identity = journal._identity(os.fstat(wire))
        if os.pread(wire,1024*1024+1,0) != unit.wire_bytes: raise GlobalAttemptHold()
        action = os.open('ACTION-PREIMAGE',local._flags()|os.O_NONBLOCK,dir_fd=original)
        journal._named(original,'ACTION-PREIMAGE',action,directory=False)
        action_identity = journal._identity(os.fstat(action))
        if os.pread(action,1024*1024+1,0) != unit.action_preimage: raise GlobalAttemptHold()
        if _inspect(original,unit,base)[0] != count: raise GlobalAttemptHold()
        for entry,fd,identity in prefix_originals:
            journal._named(original,entry,fd,directory=False)
            if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
        if (journal._identity(os.fstat(original)) != original_identity
                or journal._identity(os.fstat(wire)) != wire_identity
                or journal._identity(os.fstat(action)) != action_identity): raise GlobalAttemptHold()
        header = {'schema_version':1,'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,
            'action_digest':unit.action_digest,'journal_header_sha256':hashlib.sha256(local._canonical(base)).hexdigest(),
            'wire_identity':wire_identity,'action_identity':action_identity}
        claim_name = owner.lock_name[:-5]+'.dispatch'
        if claim_name not in os.listdir(parent):
            if count != 1: raise GlobalAttemptHold()
            claims = _create_folder(parent,claim_name)
            local._write_new(claims,'HEADER',local._canonical(header))
            # Never mark initialized before every prior image barrier succeeds.
            local._write_new(claims,'INITIALIZED',_initialization(header))
        else: claims = local._directory(parent,claim_name)
        journal._named(parent,claim_name,claims,directory=True)
        used,previous = _inspect_wire_claims(claims,original,unit,header)
        if used != count-1: raise GlobalAttemptHold()
        _sync_initialization(parent,claims,header)
        if local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner:
            raise GlobalAttemptHold()
        journal._named(original,'WIRE',wire,directory=False)
        journal._named(original,'ACTION-PREIMAGE',action,directory=False)
        if (journal._identity(os.fstat(wire)) != wire_identity
                or journal._identity(os.fstat(action)) != action_identity): raise GlobalAttemptHold()
        local._write_new(claims,f'CLAIM-{count}',local._canonical({'schema_version':1,
            'unit_id':unit.unit_id,'wire_sha256':unit.wire_sha256,'attempt_count':count,
            'original_intent_sha256':hashlib.sha256(journal._read(original,f'ATTEMPT-{count}',16384)).hexdigest(),
            'previous_sha256':previous,'outcome':'CONSUMED_UNKNOWN_NOT_SEND_PROOF'}))
        if _inspect_wire_claims(claims,original,unit,header)[0] != count: raise GlobalAttemptHold()
        claims_identity = journal._identity(os.fstat(claims))
        names = tuple(sorted(os.listdir(claims)))
        identities = tuple(journal._identity(os.stat(item,dir_fd=claims,follow_symlinks=False)) for item in names)
        if _inspect(original,unit,base)[0] != count: raise GlobalAttemptHold()
        journal._named(parent,name,original,directory=True)
        journal._named(parent,claim_name,claims,directory=True)
        if (local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner
                or journal._identity(os.fstat(wire)) != wire_identity
                or journal._identity(os.fstat(action)) != action_identity): raise GlobalAttemptHold()
        def verify():
            _require_no_completion(parent,name)
            if (journal._identity(os.fstat(original)) != original_identity
                    or journal._identity(os.fstat(claims)) != claims_identity): raise GlobalAttemptHold()
            for entry,fd,identity in prefix_originals:
                journal._named(original,entry,fd,directory=False)
                if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
            if (_inspect(original,unit,base)[0] != count
                or _inspect_wire_claims(claims,original,unit,header)[0] != count
                or tuple(sorted(os.listdir(claims))) != names
                or tuple(journal._identity(os.stat(item,dir_fd=claims,follow_symlinks=False)) for item in names) != identities
                or os.pread(wire,1024*1024+1,0) != unit.wire_bytes
                or journal._identity(os.fstat(wire)) != wire_identity
                or os.pread(action,1024*1024+1,0) != unit.action_preimage
                or journal._identity(os.fstat(action)) != action_identity
                or local._owner(writer_token) is not project or ownership._validated_owner(token,binding) is not owner):
                raise GlobalAttemptHold()
            journal._named(original,'WIRE',wire,directory=False)
            journal._named(original,'ACTION-PREIMAGE',action,directory=False)
            journal._named(parent,name,original,directory=True)
            journal._named(parent,claim_name,claims,directory=True)
            # Semantic replays above reopen the journal. A held prefix must
            # still be the original AFTER those reads, including an in-place
            # byte/mtime restoration during the last pre-Popen verification.
            for entry,fd,identity in prefix_originals:
                journal._named(original,entry,fd,directory=False)
                if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
            if (journal._identity(os.fstat(original)) != original_identity
                    or journal._identity(os.fstat(claims)) != claims_identity): raise GlobalAttemptHold()
        verify()
        image = CountedOriginalWireObservation(count,unit.wire_sha256,wire,action)
        with _WIRE_CLAIM_GUARD:
            _LIVE_WIRE_CLAIMS[image] = (writer_token,token,binding,unit,wire,action,count,verify,False)
        yield image
        verify()
    except Exception: failed = True
    finally:
        if image is not None:
            with _WIRE_CLAIM_GUARD: _LIVE_WIRE_CLAIMS.pop(image,None)
        for held,identity in ((wire,wire_identity),(action,action_identity),
                              *((fd,identity) for _entry,fd,identity in prefix_originals)):
            if held is None: continue
            try:
                # Never close a foreign FD that replaced a violated borrow.
                # Full metadata drift is still HOLD above, but it does not
                # transfer ownership of this descriptor to a different inode.
                # Close our original even after chmod/write; never a reused FD.
                if identity is None or journal._identity(os.fstat(held))[:2] == identity[:2]: os.close(held)
                else: failed = True
            except OSError: failed = True
        for handle in (claims,original):
            if handle is not None:
                try: os.close(handle)
                except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def _inputs(token, binding, unit):
    owner = ownership._validated_owner(token, binding)
    header = compiled._projection(unit)
    identity = json.loads(unit.action_preimage.decode('utf-8'))['identity']
    if identity['spreadsheet_id'] != binding.spreadsheet_id: raise GlobalAttemptHold()
    header.update(spreadsheet_id=binding.spreadsheet_id, allowlist_sha256=binding.allowlist_sha256,
                  policy_sha256=binding.policy_sha256)
    return owner, owner.directories[-1][0], owner.lock_name[:-5] + '.journal', header


def _require_no_completion(parent,journal_name,*,marker_only=False):
    """Conservative no-resend boundary, not proof of remote settlement.

    An in-progress/partial proof store blocks WIRE claims. Raw diagnostic
    intent counting is not transport; it additionally refuses any COMPLETE
    marker, even malformed. Neither absence nor presence grants admission,
    APPLIED, cleanup, capacity reclamation or a replacement generation.
    """
    key=journal_name[:-len('.journal')]
    name=key+'.completion'; names=os.listdir(parent)
    # The sibling survives a lost/displaced proof directory. Even malformed
    # bytes are only a conservative STOP, never settlement/admission evidence.
    if key+'.completion-started' in names and (not marker_only or name not in names):
        raise GlobalAttemptHold()
    if name not in names: return
    if not marker_only: raise GlobalAttemptHold()
    folder=local._directory(parent,name)
    try:
        journal._named(parent,name,folder,directory=True)
        identity=journal._identity(os.fstat(folder))
        if 'COMPLETE' in os.listdir(folder): raise GlobalAttemptHold()
        journal._named(parent,name,folder,directory=True)
        if journal._identity(os.fstat(folder))!=identity: raise GlobalAttemptHold()
    finally: os.close(folder)


def _create_folder(parent, name):
    # Partial creation is retained HOLD, but no owned descriptor may leak when
    # a directory fsync or interruption happens before returning the handle.
    os.mkdir(name, 0o700, dir_fd=parent); os.fsync(parent)
    fd = local._directory(parent, name)
    try: os.fsync(fd)
    except BaseException:
        os.close(fd); raise
    return fd


def _inspect(folder, unit, header):
    if (journal._read(folder, 'ACTION-PREIMAGE', 1024 * 1024) != unit.action_preimage
            or journal._read(folder, 'WIRE', 1024 * 1024) != unit.wire_bytes
            or journal._read(folder, 'HEADER', 16384) != local._canonical(header)
            or journal._read(folder, 'INITIALIZED', 16384) != _initialization(header)):
        raise GlobalAttemptHold()
    names = set(os.listdir(folder)); count = len(names) - 4
    if not 0 <= count <= 6 or names != {'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED', *(f'ATTEMPT-{i}' for i in range(1, count + 1))}:
        raise GlobalAttemptHold()
    previous = hashlib.sha256(local._canonical(header)).hexdigest()
    for index in range(1, count + 1):
        raw = journal._read(folder, f'ATTEMPT-{index}', 16384)
        expected = {**header, 'attempt_count': index, 'previous_sha256': previous, 'outcome': 'UNKNOWN'}
        if raw != local._canonical(expected): raise GlobalAttemptHold()
        previous = hashlib.sha256(raw).hexdigest()
    return count, previous


def _initialization(header):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                            'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})


def _sync_initialization(parent, folder, header):
    """Confirm genuine post-image-barrier marker under ownership, never create it.

    A present marker means this writer previously completed ALL eight image
    barriers before it was written. Synchronize its held file and directories
    before an intent; pathname existence alone, or a fully shaped HEADER whose
    final fsync failed, must not stand in for those preceding barriers.
    """
    fd = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(fd, directory=False)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
        raw = os.read(fd, 16385)
        if len(raw) != info.st_size or raw != _initialization(header): raise GlobalAttemptHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally: os.close(fd)


@contextmanager
def _write_global_start(parent, name, raw):
    """Create the permanent STOP name before any byte or durability barrier.

    Partial/empty witnesses stay retained on failure. They are never positive
    evidence, repaired, replaced or removed by this initializer.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
        raise GlobalAttemptHold()
    local._flags()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        local._check(fd, directory=False)
        journal._named(parent, name, fd, directory=False)
        remaining = memoryview(raw)
        while remaining:
            written = os.write(fd, remaining)
            if not 0 < written <= len(remaining): raise GlobalAttemptHold()
            remaining = remaining[written:]
        identity = journal._identity(os.fstat(fd))
        def verify():
            journal._named(parent, name, fd, directory=False)
            if journal._identity(os.fstat(fd)) != identity: raise GlobalAttemptHold()
        os.fsync(fd)
        verify()
        os.fsync(parent)
        verify()
        yield verify
        verify()
    finally:
        os.close(fd)


def prepare_global_unit(token, binding, unit):
    """New coherent images only; never adopt a partial/existing global store."""
    folder = None; failed = False
    try:
        owner, parent, name, header = _inputs(token, binding, unit)
        _require_no_completion(parent,name)
        # A retained store is a conservative barrier even before ATTEMPT-1.
        # New generations/sheets/projects cannot bypass it by another key.
        started=name[:-len('.journal')]+'.journal-started'
        names=set(os.listdir(parent))
        if name in names or started in names: raise GlobalAttemptHold()
        # A separate retained STOP precedes the whole unit namespace. Losing
        # the journal must never turn UNKNOWN or an exhausted count into a
        # fresh first use. Even empty/malformed/partial STARTED blocks creation;
        # it is not completion, inventory, high-water or a send permission.
        with _write_global_start(parent,started,local._canonical({
            'schema_version':1,'state':'GLOBAL-UNIT-STARTED','unit_id':unit.unit_id,
            'header_sha256':hashlib.sha256(local._canonical(header)).hexdigest()})) as verify_start:
            ownership._validated_owner(token,binding)
            verify_start()
            folder = _create_folder(parent, name)
            local._write_new(folder, 'ACTION-PREIMAGE', unit.action_preimage)
            local._write_new(folder, 'WIRE', unit.wire_bytes)
            local._write_new(folder, 'HEADER', local._canonical(header))
            journal._named(parent, name, folder, directory=True)
            ownership._validated_owner(token, binding)
            # Never create this marker until ALL eight required image barriers
            # succeeded. A failed final HEADER directory fsync otherwise leaves
            # coherent-looking bytes which must not be adopted by a later owner.
            local._write_new(folder, 'INITIALIZED', _initialization(header))
            journal._named(parent, name, folder, directory=True)
            ownership._validated_owner(token, binding)
            count, _previous = _inspect(folder, unit, header)
            if count: raise GlobalAttemptHold()
            verify_start()
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def _observe(token, binding, unit, append):
    folder = None; failed = False
    try:
        owner, parent, name, header = _inputs(token, binding, unit)
        folder = local._directory(parent, name)
        journal._named(parent, name, folder, directory=True)
        count, previous = _inspect(folder, unit, header)
        if append:
            _require_no_completion(parent,name,marker_only=True)
            if count == 6: raise GlobalAttemptHold()
            _sync_initialization(parent, folder, header)
            ownership._validated_owner(token, binding)
            journal._named(parent, name, folder, directory=True)
            count += 1
            local._write_new(folder, f'ATTEMPT-{count}', local._canonical(
                {**header, 'attempt_count': count, 'previous_sha256': previous, 'outcome': 'UNKNOWN'}))
            _require_no_completion(parent,name,marker_only=True)
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        verified, _previous = _inspect(folder, unit, header)
        if verified != count: raise GlobalAttemptHold()
        result = GlobalIntentObservation(count, unit.wire_sha256, unit.action_digest,
                                         'UNKNOWN' if count else 'UNATTEMPTED_OBSERVATION')
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def inspect_global_unit(token, binding, unit):
    """Read-only global barrier/count observation; never COMPLETE or a permit."""
    # Existing readers must not bypass the original history scope simply by
    # supplying a coherent current/cached unit. This compares images only;
    # original C6, freshness and all send gates remain separate obligations.
    with _hold_original_global_unit(token, binding) as (original, seen, verify):
        compiled._projection(unit)
        if unit != original: raise GlobalAttemptHold()
        verify()
    return seen


@contextmanager
def _hold_original_global_unit(token, binding):
    """Read the retained single-unit namespace without a caller's unit image.

    Keep every original descriptor before interpreting ACTION/WIRE and through
    the consumer. This does not certify a complete multi-unit inventory, C6,
    current qualification, APPLIED, FIFO, quota or a send capability. Absent or
    partial evidence is HOLD, never an empty inventory or a first-use permit.
    """
    folder = None; folder_object = None; held = []; owned_objects = {}; failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        parent = owner.directories[-1][0]
        name = owner.lock_name[:-5] + '.journal'
        started = owner.lock_name[:-5] + '.journal-started'
        parent_identity = journal._identity(os.fstat(parent))
        folder = local._directory(parent, name)
        opened = os.fstat(folder); folder_object = (opened.st_dev, opened.st_ino)
        journal._named(parent, name, folder, directory=True)
        folder_identity = journal._identity(os.fstat(folder))
        names = frozenset(os.listdir(folder)); count = len(names) - 4
        if (not 0 <= count <= 6 or names != {'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED',
                *(f'ATTEMPT-{i}' for i in range(1, count + 1))}):
            raise GlobalAttemptHold()
        images = {}
        for directory, entry, limit in (
                (parent, started, 16384),
                *((folder, entry, 1024 * 1024 if entry in ('ACTION-PREIMAGE', 'WIRE') else 16384)
                  for entry in sorted(names))):
            fd = os.open(entry, local._flags(), dir_fd=directory)
            held.append((directory, entry, fd, None, None))
            opened = os.fstat(fd); owned_objects[fd] = (opened.st_dev, opened.st_ino)
            info = local._check(fd, directory=False)
            journal._named(directory, entry, fd, directory=False)
            identity = journal._identity(info)
            raw = os.pread(fd, limit + 1, 0)
            if (not raw or len(raw) != info.st_size or len(raw) > limit
                    or journal._identity(os.fstat(fd)) != identity):
                raise GlobalAttemptHold()
            held[-1] = (directory, entry, fd, identity, raw)
            images[entry] = raw
        def verify():
            if ownership._validated_owner(token, binding) is not owner:
                raise GlobalAttemptHold()
            journal._named(parent, name, folder, directory=True)
            if (journal._identity(os.fstat(parent)) != parent_identity
                    or journal._identity(os.fstat(folder)) != folder_identity
                    or frozenset(os.listdir(folder)) != names):
                raise GlobalAttemptHold()
            for directory, entry, fd, identity, raw in held:
                journal._named(directory, entry, fd, directory=False)
                if (journal._identity(os.fstat(fd)) != identity
                        or os.pread(fd, len(raw) + 1, 0) != raw):
                    raise GlobalAttemptHold()
        verify()
        from monitor.issue_tracker_send_unit import _original_unit
        unit = _original_unit(images['ACTION-PREIMAGE'], images['WIRE'])
        verify()
        _owner, _parent, _name, header = _inputs(token, binding, unit)
        if (_owner is not owner or _parent != parent or _name != name
                or images[started] != local._canonical({
                    'schema_version': 1, 'state': 'GLOBAL-UNIT-STARTED', 'unit_id': unit.unit_id,
                    'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})
                or _inspect(folder, unit, header)[0] != count):
            raise GlobalAttemptHold()
        for _directory, _entry, fd, _identity, _raw in held:
            os.fsync(fd)
        os.fsync(folder); os.fsync(parent); verify()
        seen = GlobalIntentObservation(count, unit.wire_sha256, unit.action_digest,
                                       'UNKNOWN' if count else 'UNATTEMPTED_OBSERVATION')
        yield unit, seen, verify
        verify()
    except Exception:
        failed = True
    finally:
        for _directory, _entry, fd, _identity, _raw in reversed(held):
            try:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == owned_objects.get(fd):
                    os.close(fd)
                else:
                    failed = True
            except OSError: failed = True
        if folder is not None:
            try:
                current = os.fstat(folder)
                if (current.st_dev, current.st_ino) == folder_object:
                    os.close(folder)
                else:
                    failed = True
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def inspect_original_global_unit(token, binding):
    """Original historical bytes/count only; no reconstruction from a new cycle."""
    with _hold_original_global_unit(token, binding) as (unit, seen, verify):
        verify()
    return unit, seen


def record_global_attempt_intent(token, binding, unit):
    """Persist count BEFORE any eventual send, still not a transport capability."""
    return _observe(token, binding, unit, True)


def _reserved_images(token, binding, identity, unit):
    """Reopen actual original stores, not caller-supplied counts or snapshots."""
    from monitor.issue_tracker_enrollment_journal import require_unit_enrollment, inspect_enrollment_journal
    from monitor.issue_tracker_history_preread_journal import require_history_append_capacity
    from monitor.issue_tracker_metadata_reservation import inspect_metadata_reservation
    from monitor.issue_tracker_nv_reservation import require_unit_nv_reservation

    _inputs(token, binding, unit)
    require_unit_enrollment(token, binding, identity, unit)
    original = inspect_enrollment_journal(token, binding, identity)
    history = require_history_append_capacity(token, binding, unit)
    quota = inspect_metadata_reservation(token, binding, identity, unit)
    action = json.loads(unit.action_preimage)
    nv = None
    if action['identity']['sheet'] in ('ETH Cabling', 'IB Cabling') and any(
            item['action'] == 'insert' for item in action['business']):
        nv = require_unit_nv_reservation(token, binding, identity, unit)
    ownership._validated_owner(token, binding)
    return original, history, quota, nv


@contextmanager
def _hold_reserved_quota_originals(token,binding,identity,unit):
    """Retain the actual quota directory/four image FDs across durable count.

    Content equality after reopening is not original-namespace continuity.
    This does not create a quota, reclaim UNKNOWN or establish G1 inventory.
    """
    from monitor import issue_tracker_metadata_reservation as quota
    folder=None
    try:
        parent,name,_base,_state,_sheet,_fence=quota._inputs(token,binding,identity,unit)
        folder=local._directory(parent,name)
        with quota._hold_quota_originals(parent,name,folder) as verify:
            yield verify
    finally:
        if folder is not None: os.close(folder)


def record_reserved_attempt_intent(token, binding, identity, unit):
    """Count only after the exact original reservation chain, then recheck it.

    This necessary local gate is NOT a send permit or fresh admission. It does
    not launch a worker, bound actual wire attempts, discharge hidden PROJECT
    quota, prove row continuity/FIFO, settle UNKNOWN or grant COMPLETE. The
    primitive record_global_attempt_intent remains evidence-only and cannot
    authorize transport. A failed post-count barrier leaves counted UNKNOWN;
    never decrement, repair, replace a reservation or treat the count as send.
    """
    failed = False
    try:
        with _hold_reserved_quota_originals(token,binding,identity,unit) as verify_quota:
            before = inspect_global_unit(token, binding, unit)
            if before.attempt_count == 6: raise GlobalAttemptHold()
            images = _reserved_images(token, binding, identity, unit)
            verify_quota()
            result = _observe(token, binding, unit, True)
            verify_quota()
            if (_reserved_images(token, binding, identity, unit) != images
                    or result.attempt_count != before.attempt_count + 1
                    or inspect_global_unit(token, binding, unit) != result):
                raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_original_business_reserved_attempt_intent(token, binding, identity, unit):
    """Bind ALL original business images to the necessary reservation count.

    This is still evidence, NOT fresh admission, a launcher capability, FIFO
    settlement or COMPLETE. Never recreate a missing original. A post-count
    failure retains UNKNOWN; quota's hidden PROJECT limitation is unchanged.
    """
    from monitor.issue_tracker_history_preread_journal import inspect_business_preread

    def originals():
        reservations = _reserved_images(token, binding, identity, unit)
        business = inspect_business_preread(token, binding, identity, unit)
        ownership._validated_owner(token, binding)
        return reservations, business

    failed = False
    try:
        with _hold_reserved_quota_originals(token,binding,identity,unit) as verify_quota:
            before = inspect_global_unit(token, binding, unit)
            if before.attempt_count == 6: raise GlobalAttemptHold()
            images = originals()
            verify_quota()
            result = _observe(token, binding, unit, True)
            verify_quota()
            if (originals() != images or result.attempt_count != before.attempt_count + 1
                    or inspect_global_unit(token, binding, unit) != result):
                raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def _receipted_original_facts(
    token, binding, identity, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
    _shared_retry=False,
):
    """Read-only actual original C5/C6 facts, never admission or recompilation."""
    from monitor.issue_tracker_send_unit import _original_receipt_identity, _read_original_generation_identity
    from monitor.issue_tracker_history_preread_journal import inspect_business_preread, inspect_business_source_projection
    from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l, replay_original_receipted_prod_source
    from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
    from monitor.issue_tracker_local_workbook_commit import _source_rows
    from monitor.issue_tracker_online_target import inspect_project_online_target
    from monitor.issue_tracker_settings_audit_allocation import inspect_settings_audit_allocation

    _inputs(token, binding, unit)
    inspect_project_online_target(writer_token, binding)
    action = json.loads(unit.action_preimage)
    audits = (inspect_settings_audit_allocation(writer_token, token, binding, unit)
              if action['audits'] else b'')
    target = action['identity']
    cycles = read_completed_cycle_evidence(store)
    if not cycles or not qualified_source.cycle_ids: raise GlobalAttemptHold()
    older = qualified_source.cycle_ids[-1] != cycles[-1].cycle_id
    if older and _shared_retry is not True: raise GlobalAttemptHold()
    arguments = dict(http_root=http_root, settings=settings,
        whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
        writer_token=writer_token)
    def source():
        if older:
            return replay_original_receipted_prod_source(store, **arguments,
                expected_template_sha256=expected_template_sha256,
                local_generation_id=target['generation_id'])
        return qualify_prod_stage_l(store, **arguments)
    def receipt_identity():
        if older:
            return _read_original_generation_identity(target['generation_id'], writer_token)
        return _original_receipt_identity(qualified_source, store, target['generation_id'],
            writer_token, settings, whitelist_snapshot, expected_template_sha256)
    # A caller's old qualified object does not establish provenance. Replay
    # the actual admitted original before observing its raw C6 identity.
    actual_source = source()
    if actual_source != qualified_source: raise GlobalAttemptHold()
    receipt = receipt_identity()
    if receipt[:3] != (target['generation_id'], target['publish_id'], action['manifest_id']):
        raise GlobalAttemptHold()
    reservations = _reserved_images(token, binding, identity, unit)
    business = inspect_business_preread(token, binding, identity, unit)
    cabling_rows, switch_rows = _source_rows(actual_source)
    if inspect_business_source_projection(token, binding, identity, unit, (*cabling_rows, *switch_rows)) != business:
        raise GlobalAttemptHold()
    if source() != actual_source or read_completed_cycle_evidence(store) != cycles:
        raise GlobalAttemptHold()
    if receipt_identity() != receipt:
        raise GlobalAttemptHold()
    inspect_project_online_target(writer_token, binding)
    ownership._validated_owner(token, binding)
    return receipt, actual_source, reservations, business, audits


@contextmanager
def _hold_receipted_audit_originals(writer_token, token, binding, unit):
    """Keep original C25 identities, not two separately reopened snapshots."""
    _inputs(token,binding,unit)
    if json.loads(unit.action_preimage)['audits']:
        from monitor.issue_tracker_settings_audit_allocation import _hold_counted_audit_originals
        with _hold_counted_audit_originals(writer_token,token,binding,unit) as verify:
            yield verify
    else:
        yield lambda: None


def record_receipted_original_attempt_intent(
    token, binding, identity, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
):
    """Original protected C5/C6, business/reservations/audits around count.

    Both actual owners stay held. No inferred receipt, source recompilation of
    UNKNOWN, repair, count reset or rollback; post-count drift retains UNKNOWN.
    Still no older-cycle R2, cadence, transport, COMPLETE or FIFO authority.
    """
    from monitor.issue_tracker_receipt_snapshot import _hold_history_originals
    def originals():
        return _receipted_original_facts(token,binding,identity,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
            whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
            http_root=http_root,whitelist_path=whitelist_path)

    failed = False
    try:
        with _hold_receipted_audit_originals(writer_token,token,binding,unit) as verify_audits, \
                _hold_history_originals(writer_token) as verify_receipts, \
                _hold_reserved_quota_originals(token,binding,identity,unit) as verify_quota:
            before = inspect_global_unit(token, binding, unit)
            if before.attempt_count == 6: raise GlobalAttemptHold()
            images = originals()
            verify_audits(); verify_receipts(); verify_quota()
            result = _observe(token, binding, unit, True)
            verify_audits(); verify_receipts(); verify_quota()
            if (originals() != images or result.attempt_count != before.attempt_count + 1
                    or inspect_global_unit(token, binding, unit) != result):
                raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_shared_retry_continuous_owned_attempt_intent(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
    boot_id,monotonic_ns,
):
    """Original admitted C6 R2 count shares the automatic/manual limiter; not GO.

    Actual issued reads and original C5/C6/reservations dominate the durable
    opportunity INTENT. Counter executes once inside it, then pairs with the
    exact original ATTEMPT before all fresh facts are checked again. Failure
    never rolls back count, deletes an orphan or clears UNKNOWN. Hidden G1,
    fixed launcher/FIFO/COMPLETE still must dominate GO.
    """
    with _hold_shared_retry_counted_sources(
        token,binding,unit,writer_token=writer_token,identity_response=identity_response,
        history_response=history_response,business_reads=business_reads,qualified_source=qualified_source,
        store=store,settings=settings,whitelist_snapshot=whitelist_snapshot,
        expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
        headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response,
        boot_id=boot_id,monotonic_ns=monotonic_ns,
    ) as (result,_verify_sources):
        return result


@contextmanager
def _hold_shared_retry_counted_sources(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
    boot_id,monotonic_ns,
):
    """Original R2 opportunity/count owners, retained across optional fixed launch.

    The legitimate paired COUNT changes the admission namespace. Pin its new
    complete original prefix only AFTER the real opportunity closes; all
    worker/config/W1/audit/quota owners remain held across that transition.
    This grants neither GO nor completion and never accepts a caller verifier.
    """
    from monitor.issue_tracker_admission import _hold_shared_retry_opportunity
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates
    from monitor.issue_tracker_local_workbook_commit import _latest_receipted_prod_xlsx
    from monitor.issue_tracker_stage_l_consumer import _hold_original_replay_inputs
    from monitor.issue_tracker_receipt_snapshot import _hold_history_originals
    from monitor.issue_tracker_send_unit import _read_original_generation_identity
    from monitor.issue_tracker_cycle_source import _hold_completed_cycle_replay
    from tools.ufm_collection_pipeline import _hold_reusable_directory_reads
    from pathlib import Path
    def facts():
        continuity=observe_owned_business_continuity(writer_token,token,binding,unit,
            identity_response=identity_response,history_response=history_response,business_reads=business_reads)
        gates=observe_owned_unit_read_gates(writer_token,token,binding,unit,
            whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
            headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)
        originals=_receipted_original_facts(token,binding,gates.identity,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
            whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
            http_root=http_root,whitelist_path=whitelist_path,_shared_retry=True)
        if (observe_owned_business_continuity(writer_token,token,binding,unit,
                identity_response=identity_response,history_response=history_response,business_reads=business_reads)!=continuity
                or observe_owned_unit_read_gates(writer_token,token,binding,unit,
                    whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
                    headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)!=gates):
            raise GlobalAttemptHold()
        return continuity,gates,originals
    failed=False
    try:
        with _hold_reusable_directory_reads(), \
                _hold_original_replay_inputs(store,Path(store.project_identity),whitelist_path) as verify_inputs, \
                _hold_completed_cycle_replay(store) as verify_cycles, \
                _hold_receipted_audit_originals(writer_token,token,binding,unit) as verify_audits:
            before=inspect_global_unit(token,binding,unit)
            if not 1<=before.attempt_count<6: raise GlobalAttemptHold()
            original=facts()
            with _hold_reserved_quota_originals(token,binding,original[1].identity,unit) as verify_quota:
                image=_latest_receipted_prod_xlsx(writer_token,expected_template_sha256)
                with _hold_shared_retry_opportunity(writer_token,token,binding,unit,store,image,
                                                     boot_id=boot_id,monotonic_ns=monotonic_ns):
                    # The opportunity INTENT is already durable. Pin its exact
                    # namespace now; close before the legitimate paired COUNT.
                    # Semantic admission replay must not adopt an orphan here.
                    with _hold_history_originals(writer_token) as verify_receipts:
                        def verify_originals():
                            verify_inputs(); verify_cycles(); verify_receipts(); verify_audits(); verify_quota()
                            if _read_original_generation_identity(original[2][0][0],writer_token) != original[2][0]:
                                raise GlobalAttemptHold()
                        verify_originals()
                        result=_observe(token,binding,unit,True)
                        # Post-count drift preserves UNKNOWN and an unpaired
                        # opportunity, never repairs or rolls back the counter.
                        verify_originals()
                with _hold_history_originals(writer_token) as verify_paired_receipts:
                    def verify_originals():
                        verify_inputs(); verify_cycles(); verify_paired_receipts(); verify_audits(); verify_quota()
                    def verify_sources():
                        verify_originals()
                        if (facts()!=original or inspect_global_unit(token,binding,unit)!=result):
                            raise GlobalAttemptHold()
                        verify_originals()
                    if result.attempt_count!=before.attempt_count+1: raise GlobalAttemptHold()
                    verify_sources()
                    yield result,verify_sources
                    verify_originals()
    except Exception: failed=True
    if failed: raise GlobalAttemptHold()


@contextmanager
def _hold_shared_retry_owned_attempt_wire(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
    boot_id,monotonic_ns,
):
    """One original admitted identical R2 count through fixed launch, not GO.

    Fresh ALL-business/History/W1 reads and held original C6 sources dominate
    the shared cadence opportunity and one durable count. They remain current
    at consume/pre-Popen/post-send/exit; UNKNOWN and every consumed count/claim
    survive failure. First-count/exhausted units cannot enter this retry lane.
    """
    failed=False
    try:
        local._owner(writer_token)
        if not 1<=inspect_global_unit(token,binding,unit).attempt_count<6: raise GlobalAttemptHold()
        with _hold_shared_retry_counted_sources(
            token,binding,unit,writer_token=writer_token,identity_response=identity_response,
            history_response=history_response,business_reads=business_reads,qualified_source=qualified_source,
            store=store,settings=settings,whitelist_snapshot=whitelist_snapshot,
            expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
            headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response,
            boot_id=boot_id,monotonic_ns=monotonic_ns,
        ) as (result,verify_sources):
            with _hold_counted_original_wire(writer_token,token,binding,unit) as image:
                if image.attempt_count!=result.attempt_count: raise GlobalAttemptHold()
                with _WIRE_CLAIM_GUARD:
                    issued=_LIVE_WIRE_CLAIMS.get(image)
                    if issued is None: raise GlobalAttemptHold()
                    verify_wire=issued[-2]
                    def verify():
                        verify_wire(); verify_sources(); verify_wire()
                    _LIVE_WIRE_CLAIMS[image]=issued[:-2]+(verify,issued[-1])
                verify_wire()
                yield image
                verify()
    except Exception: failed=True
    if failed: raise GlobalAttemptHold()


def record_owned_receipted_attempt_intent(
    token, binding, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
    identity_response, headers_response, whitelist_response, metadata_response,
):
    """Issued live read gates around the original C5/C6 durable count, NOT GO.

    No caller template identity/plan/freshness flag is accepted. W1 equality,
    strict template headers, both original enrollment nonces and absence of an
    existing unit fence must survive the original protected count. Read expiry
    or post-count policy drift retains UNKNOWN, never rolls back a count. This
    observation still does not prove hidden PROJECT quota, fresh business/History
    rows, older-cycle R2, shared cadence or any actual mutation/COMPLETE permit.
    """
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates

    def gates():
        return observe_owned_unit_read_gates(
            writer_token, token, binding, unit, whitelist_snapshot=whitelist_snapshot.whitelist,
            identity_response=identity_response, headers_response=headers_response,
            whitelist_response=whitelist_response, metadata_response=metadata_response)

    failed = False
    try:
        original_gates = gates()
        result = record_receipted_original_attempt_intent(
            token, binding, original_gates.identity, unit, qualified_source=qualified_source,
            store=store, writer_token=writer_token, settings=settings,
            whitelist_snapshot=whitelist_snapshot, expected_template_sha256=expected_template_sha256,
            http_root=http_root, whitelist_path=whitelist_path)
        if gates() != original_gates or inspect_global_unit(token,binding,unit) != result:
            raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


@contextmanager
def _hold_continuous_owned_attempt_wire(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
):
    """First original C6 count through fixed launch; necessary, NOT GO.

    The original source/receipt/audit/quota descriptors and actual issued read
    deadlines remain held through every live wire check, including pre-Popen.
    No caller verifier/permission flag is accepted. Existing UNKNOWN requires
    the separate shared retry cadence; this scope cannot bypass it. Neither
    visible quota nor a consumed claim proves G1, FIFO or COMPLETE.
    """
    from pathlib import Path
    from monitor.issue_tracker_stage_l_consumer import _hold_original_replay_inputs
    from monitor.issue_tracker_receipt_snapshot import _hold_history_originals
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates
    from monitor.issue_tracker_cycle_source import _hold_completed_cycle_replay
    from tools.ufm_collection_pipeline import _hold_reusable_directory_reads
    failed=False
    try:
        local._owner(writer_token)
        if inspect_global_unit(token,binding,unit).attempt_count != 0: raise GlobalAttemptHold()
        def facts():
            continuity=observe_owned_business_continuity(writer_token,token,binding,unit,
                identity_response=identity_response,history_response=history_response,business_reads=business_reads)
            gates=observe_owned_unit_read_gates(writer_token,token,binding,unit,
                whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
                headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)
            originals=_receipted_original_facts(token,binding,gates.identity,unit,
                qualified_source=qualified_source,store=store,writer_token=writer_token,settings=settings,
                whitelist_snapshot=whitelist_snapshot,expected_template_sha256=expected_template_sha256,
                http_root=http_root,whitelist_path=whitelist_path)
            if (observe_owned_business_continuity(writer_token,token,binding,unit,
                    identity_response=identity_response,history_response=history_response,business_reads=business_reads)!=continuity
                    or observe_owned_unit_read_gates(writer_token,token,binding,unit,
                        whitelist_snapshot=whitelist_snapshot.whitelist,identity_response=identity_response,
                        headers_response=headers_response,whitelist_response=whitelist_response,metadata_response=metadata_response)!=gates):
                raise GlobalAttemptHold()
            return continuity,gates,originals
        with _hold_reusable_directory_reads(), \
                _hold_original_replay_inputs(store,Path(store.project_identity),whitelist_path) as verify_inputs, \
                _hold_completed_cycle_replay(store) as verify_cycles, \
                _hold_history_originals(writer_token) as verify_receipts, \
                _hold_receipted_audit_originals(writer_token,token,binding,unit) as verify_audits:
            original=facts()
            with _hold_reserved_quota_originals(token,binding,original[1].identity,unit) as verify_quota:
                def verify_originals():
                    verify_inputs(); verify_cycles(); verify_receipts(); verify_audits(); verify_quota()
                def verify_sources():
                    verify_originals()
                    if facts()!=original: raise GlobalAttemptHold()
                    verify_originals()
                # facts() has just replayed the actual native source and both
                # issued-read gates. Count once under those original owners;
                # nesting the separate count primitive would replay the same
                # unchanged chain again and consume the original read budget.
                verify_originals()
                result=_observe(token,binding,unit,True)
                if (result.attempt_count!=1 or
                        inspect_global_unit(token,binding,unit)!=result): raise GlobalAttemptHold()
                verify_sources()
                with _hold_counted_original_wire(writer_token,token,binding,unit) as image:
                    with _WIRE_CLAIM_GUARD:
                        issued=_LIVE_WIRE_CLAIMS.get(image)
                        if issued is None: raise GlobalAttemptHold()
                        verify_wire=issued[-2]
                        def verify():
                            verify_wire(); verify_sources(); verify_wire()
                        _LIVE_WIRE_CLAIMS[image]=issued[:-2]+(verify,issued[-1])
                    # The post-count full replay above remains current only
                    # while every original stays held. Actual consumption,
                    # last pre-Popen, post-send and scope exit still replay
                    # full sources and check issued deadlines independently.
                    verify_wire(); verify_originals(); verify_wire()
                    yield image
                    verify()
    except Exception: failed=True
    if failed: raise GlobalAttemptHold()


def record_continuous_owned_attempt_intent(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
):
    """Actual ALL business/History reads around original C6 count, not GO.

    Never recompile an UNKNOWN unit, ignore NOOP, reset a count, settle a fence
    or accept a caller freshness flag. Post-count expiry/drift keeps UNKNOWN.
    Shared cadence, actual one-use mutation and hidden PROJECT quota remain
    separate requirements, so this necessary counter yields no send capability.
    """
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    def continuity():
        return observe_owned_business_continuity(writer_token,token,binding,unit,
            identity_response=identity_response,history_response=history_response,business_reads=business_reads)
    failed = False
    try:
        original = continuity()
        result = record_owned_receipted_attempt_intent(token,binding,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,
            settings=settings,whitelist_snapshot=whitelist_snapshot,
            expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
            identity_response=identity_response,headers_response=headers_response,
            whitelist_response=whitelist_response,metadata_response=metadata_response)
        if continuity() != original or inspect_global_unit(token,binding,unit) != result: raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result
