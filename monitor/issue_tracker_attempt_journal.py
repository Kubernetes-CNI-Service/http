"""Uninstalled conservative attempt evidence under the existing local owner.

No API here sends, issues a mutation capability, permits retry, unlocks, clears
UNKNOWN or proves COMPLETE. Immutable bytes are opaque journal inputs, not a
validated Sheets batch. This prototype uses the existing project-wide C-6
owner; production spreadsheet-wide ownership across projects, inherited lock,
fresh admission, durable reservations and the governed launcher still require
integration. It conservatively stops ALL new units until independent COMPLETE
reconciliation exists; it has no cleanup/reset operation or expiry takeover.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import uuid

from monitor import issue_tracker_local_commit as local

_UNIT=re.compile(r"[0-9a-f]{64}\Z")
_ROOT="remote-attempts"


class AttemptJournalHold(ValueError):
    def __init__(self): super().__init__("req7_attempt_journal_unproved")


@dataclass(frozen=True)
class AttemptIntentObservation:
    attempt_count: int
    wire_sha256: str
    outcome: str


def _inputs(unit_id,wire):
    if (type(unit_id) is not str or _UNIT.fullmatch(unit_id) is None
            or type(wire) is not bytes or not 1<=len(wire)<=1024*1024):
        raise AttemptJournalHold()
    return hashlib.sha256(wire).hexdigest()


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _named(parent,name,held,*,directory):
    current=os.fstat(held); named=os.stat(name,dir_fd=parent,follow_symlinks=False)
    local._check(held,directory=directory)
    if (current.st_mode & 0o777 != (0o700 if directory else 0o600)
            or _identity(current)!=_identity(named)):
        raise AttemptJournalHold()


def _read(parent,name,limit):
    raw,before=local._read(parent,name,limit)
    after=os.stat(name,dir_fd=parent,follow_symlinks=False)
    if (before.st_mode & 0o777 != 0o600 or _identity(before)!=_identity(after)):
        raise AttemptJournalHold()
    return raw


def _write_read_image(parent, name, raw):
    """Fixed private original read-image names, distinct from 1 MiB wire.

    Retain the whole bounded 2 MiB read response through no-follow exclusive
    creation and atomic NOREPLACE with file+directory barriers. Never alter
    manifest/wire limits, truncate input, overwrite, adopt or repair a partial
    store. Callers hold and validate their own private owner/directory FDs.
    """
    if (type(name) is not str or name not in ('HISTORY-RAW', 'ETH-RAW', 'IB-RAW', 'METADATA-RAW')
            or type(raw) is not bytes or not 1 <= len(raw) <= 2 * 1024 * 1024):
        raise AttemptJournalHold()
    pending = '.pending-' + uuid.uuid4().hex
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise AttemptJournalHold()
            view = view[count:]
        os.fsync(fd)
    finally: os.close(fd)
    local._rename_new(parent, pending, name)
    os.fsync(parent)


def _open(token,unit_id):
    owner=local._owner(token)
    root=local._directory(owner.root_fd,_ROOT)
    unit=None
    try:
        if set(os.listdir(root))!={unit_id}: raise AttemptJournalHold()
        unit=local._directory(root,unit_id)
        _named(owner.root_fd,_ROOT,root,directory=True)
        _named(root,unit_id,unit,directory=True)
        return owner,root,unit
    except BaseException:
        if unit is not None: os.close(unit)
        os.close(root)
        raise


def _inspect(unit,unit_id,wire,digest):
    if _read(unit,"WIRE",1024*1024)!=wire: raise AttemptJournalHold()
    expected_header={"schema_version":1,"unit_id":unit_id,"wire_sha256":digest}
    if _read(unit,"HEADER",4096)!=local._canonical(expected_header): raise AttemptJournalHold()
    names=set(os.listdir(unit)); count=len(names)-2
    if not 0<=count<=6 or names!={"WIRE","HEADER",*(f"ATTEMPT-{i}" for i in range(1,count+1))}:
        raise AttemptJournalHold()
    previous=hashlib.sha256(local._canonical(expected_header)).hexdigest()
    for index in range(1,count+1):
        raw=_read(unit,f"ATTEMPT-{index}",4096)
        expected={**expected_header,"attempt_count":index,"previous_sha256":previous,"outcome":"UNKNOWN"}
        if raw!=local._canonical(expected): raise AttemptJournalHold()
        previous=hashlib.sha256(raw).hexdigest()
    return count,previous


def prepare_unit(token,unit_id,wire):
    """Install NEW immutable evidence only; partial creation is HOLD, not repair."""
    root=unit=None; failed=False
    try:
        digest=_inputs(unit_id,wire); owner=local._owner(token)
        # No adoption of an unexplained empty/preexisting store or a new target.
        if _ROOT in os.listdir(owner.root_fd): raise AttemptJournalHold()
        root=local._mkdir(owner.root_fd,_ROOT)
        unit=local._mkdir(root,unit_id)
        local._write_new(unit,"WIRE",wire)
        local._write_new(unit,"HEADER",local._canonical({"schema_version":1,"unit_id":unit_id,"wire_sha256":digest}))
        local._owner(token); _named(owner.root_fd,_ROOT,root,directory=True); _named(root,unit_id,unit,directory=True)
        _inspect(unit,unit_id,wire,digest)
    except Exception:
        failed=True
    finally:
        for fd in (unit,root):
            if fd is not None:
                try: os.close(fd)
                except OSError: failed=True
    if failed: raise AttemptJournalHold()


def _observe(token,unit_id,wire,*,append):
    root=unit=None; failed=False
    try:
        digest=_inputs(unit_id,wire); owner,root,unit=_open(token,unit_id)
        count,previous=_inspect(unit,unit_id,wire,digest)
        if append:
            if count==6: raise AttemptJournalHold()
            count+=1
            raw=local._canonical({"schema_version":1,"unit_id":unit_id,"wire_sha256":digest,
                                  "attempt_count":count,"previous_sha256":previous,"outcome":"UNKNOWN"})
            # Atomic NOREPLACE record + file fsync + directory fsync, BEFORE
            # returning. Any barrier failure preserves evidence and gives HOLD.
            local._write_new(unit,f"ATTEMPT-{count}",raw)
        local._owner(token); _named(owner.root_fd,_ROOT,root,directory=True); _named(root,unit_id,unit,directory=True)
        verified,_previous=_inspect(unit,unit_id,wire,digest)
        if verified!=count: raise AttemptJournalHold()
        result=AttemptIntentObservation(count,digest,"UNKNOWN" if count else "UNATTEMPTED_OBSERVATION")
    except Exception:
        failed=True
    finally:
        for fd in (unit,root):
            if fd is not None:
                try: os.close(fd)
                except OSError: failed=True
    if failed: raise AttemptJournalHold()
    return result


def inspect_unit(token,unit_id,wire):
    """Read-only chain observation; no missing record manufactured or repaired."""
    return _observe(token,unit_id,wire,append=False)


def record_attempt_intent(token,unit_id,wire):
    """Count an immutable intent conservatively, never a send capability.

Successful authentication/final fresh checks must dominate the eventual call.
Until a fixed launcher consumes each durable intent at most once, six intent
records alone do NOT bound actual attempts. No transport consumes this object.
"""
    return _observe(token,unit_id,wire,append=True)
