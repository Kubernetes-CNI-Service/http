"""Spreadsheet-wide original nonce evidence with explicit manual initialization.

Generate once under the actual global owner, persist before remote markers,
never adopt/reset a partial store or trust a caller's replacement nonce. Four
business/History sheet nonces remain SHEET-anchored and DOCUMENT-visible when
observed remotely. Typed identity and matching metadata are necessary evidence,
NOT format/source authority, live admission, COMPLETE or a mutation capability.
The manual CLI delegates fresh-only creation; importing this library or running
an ordinary worker never initializes, repairs, adopts or provisions state.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import secrets

if __name__ == "__main__" and not __package__:
    # Run as a file (python3 monitor/issue_tracker_enrollment_journal.py --help) rather than with -m:
    # the repository root must be importable for the `monitor` package below.
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal

_TITLES=("ETH&IB Switch","ETH Cabling","IB Cabling","Update_History")
_KEY="http-ztp-enrollment-v1"


class EnrollmentHold(ValueError):
    def __init__(self): super().__init__("req7_enrollment_unproved")


@dataclass(frozen=True)
class JournaledEnrollments:
    nonces: tuple = field(repr=False)
    journal_sha256: str


@dataclass(frozen=True)
class ObservedEnrollmentPair:
    target_nonce_valid: bool
    history_nonce_valid: bool
    journal_sha256: str
    metadata_sha256: str


def _inputs(token,binding,identity):
    from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity, _TEMPLATE_SHEETS
    owner=ownership._validated_owner(token,binding)
    if (type(identity) is not ObservedTemplateIdentity or identity.spreadsheet_id!=binding.spreadsheet_id
            or type(identity.sheet_ids) is not tuple or len(identity.sheet_ids)!=14
            or type(identity.source_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}",identity.source_sha256) is None):
        raise EnrollmentHold()
    mapping={}; ids=set()
    for item in identity.sheet_ids:
        if (type(item) is not tuple or len(item)!=2 or type(item[0]) is not str or item[0] not in _TEMPLATE_SHEETS
                or item[0] in mapping or type(item[1]) is not int or not 0<=item[1]<=2147483647 or item[1] in ids):
            raise EnrollmentHold()
        mapping[item[0]]=item[1]; ids.add(item[1])
    if set(mapping)!=set(_TEMPLATE_SHEETS): raise EnrollmentHold()
    header={"schema_version":1,"spreadsheet_id":binding.spreadsheet_id,
            "sheet_ids":[[title,mapping[title]] for title in _TEMPLATE_SHEETS]}
    return owner,owner.directories[-1][0],owner.lock_name[:-5]+".enrollment",header


def _nonce_rows(rows,header):
    mapping=dict(header["sheet_ids"])
    if type(rows) is not list or len(rows)!=4: raise EnrollmentHold()
    values=[]
    for title,item in zip(_TITLES,rows):
        if (type(item) is not list or len(item)!=3 or type(item[0]) is not str or type(item[1]) is not int
                or item[:2]!=[title,mapping[title]]
                or type(item[2]) is not str or re.fullmatch(r"[0-9a-f]{64}",item[2]) is None):
            raise EnrollmentHold()
        values.append(item[2])
    if len(set(values))!=4: raise EnrollmentHold()
    return tuple(tuple(item) for item in rows)


def _marker(header_bytes):
    return local._canonical({"schema_version":1,"state":"INITIALIZED",
                             "header_sha256":hashlib.sha256(header_bytes).hexdigest()})


def _inspect(parent,folder,name,header):
    if set(os.listdir(folder))!={"NONCES","HEADER","INITIALIZED"}: raise EnrollmentHold()
    raw=journal._read(folder,"NONCES",16384)
    rows=json.loads(raw.decode("utf-8"))
    # Only arrays/scalars are accepted; canonical equality also rejects all
    # whitespace/type changes and cannot turn an object into trusted rows.
    nonces=_nonce_rows(rows,header)
    if local._canonical(rows)!=raw: raise EnrollmentHold()
    expected=local._canonical({**header,"nonces_sha256":hashlib.sha256(raw).hexdigest()})
    if journal._read(folder,"HEADER",16384)!=expected: raise EnrollmentHold()
    wanted=_marker(expected)
    if journal._read(folder,"INITIALIZED",4096)!=wanted: raise EnrollmentHold()
    # Marker is generated ONLY after six image barriers. Confirm its held
    # bytes/durability before observing authority; never manufacture it here.
    fd=os.open("INITIALIZED",local._flags(),dir_fd=folder)
    try:
        info=local._check(fd,directory=False); journal._named(folder,"INITIALIZED",fd,directory=False)
        data=os.read(fd,4097)
        if data!=wanted or len(data)!=info.st_size: raise EnrollmentHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder,"INITIALIZED",fd,directory=False)
    finally: os.close(fd)
    journal._named(parent,name,folder,directory=True)
    return JournaledEnrollments(nonces,hashlib.sha256(expected).hexdigest())


def prepare_enrollment_journal(token,binding,identity):
    folder=None; failed=False
    try:
        owner,parent,name,header=_inputs(token,binding,identity)
        if name in os.listdir(parent): raise EnrollmentHold()
        rows=[[title,dict(header["sheet_ids"])[title],secrets.token_hex(32)] for title in _TITLES]
        _nonce_rows(rows,header); raw=local._canonical(rows)
        expected=local._canonical({**header,"nonces_sha256":hashlib.sha256(raw).hexdigest()})
        os.mkdir(name,0o700,dir_fd=parent); os.fsync(parent)
        folder=local._directory(parent,name); os.fsync(folder)
        local._write_new(folder,"NONCES",raw); local._write_new(folder,"HEADER",expected)
        journal._named(parent,name,folder,directory=True); ownership._validated_owner(token,binding)
        # All six folder/image barriers precede genuine initialization.
        local._write_new(folder,"INITIALIZED",_marker(expected))
        result=_inspect(parent,folder,name,header); ownership._validated_owner(token,binding)
    except Exception: failed=True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise EnrollmentHold()
    return result


def _require_project_initialization_completion(project):
    """Reopen the fixed original owners; DATA/return values never authorize a report.

    This read-only completion gate is not a publisher and grants no business
    sending authority. Any required owner/FD verification or cleanup failure
    propagates to the fixed refusal diagnostic.
    """
    from monitor import issue_tracker_online_target as targets
    from monitor.issue_tracker_enrollment_initialize import _hold_initialization_completion
    with local.try_writer_owner(project, project / '99-output-monitor') as writer:
        with targets._hold_current_project_online_target(writer) as binding:
            with ownership.spreadsheet_owner(binding) as owner:
                with _hold_initialization_completion(writer, owner, binding) as verify:
                    verify()


def _manual_main():
    import argparse
    import sys
    from pathlib import Path
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description=(
        'Explicit manual enrollment of new, conflict-free state only; no repair or adoption. '
        'Ordinary workers never initialize. Automatic sending remains disabled.'))
    parser.add_argument('--initialize-project', required=True, metavar='ABS_PROJECT',
                        help='initialize a confirmed new project target once')
    arguments = parser.parse_args()
    project = Path(arguments.initialize_project)
    if not project.is_absolute():
        parser.error('--initialize-project requires an absolute project path')
    failed = False
    try:
        from monitor.issue_tracker_enrollment_initialize import initialize_current_project
        initialize_current_project(project)
        _require_project_initialization_completion(project)
    except Exception:
        failed = True
    if failed:
        sys.stderr.write('enrollment initialization refused; evidence retained\n')
        return 3
    sys.stdout.write('enrollment initialized; automatic sending remains disabled\n')
    return 0


def inspect_enrollment_journal(token,binding,identity):
    folder=None; failed=False
    try:
        owner,parent,name,header=_inputs(token,binding,identity)
        folder=local._directory(parent,name); journal._named(parent,name,folder,directory=True)
        result=_inspect(parent,folder,name,header); ownership._validated_owner(token,binding)
    except Exception: failed=True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise EnrollmentHold()
    return result


def require_unit_enrollment(token,binding,identity,unit):
    """Bind both original nonces to a coherent composer, not send permission."""
    failed=False
    try:
        from monitor.issue_tracker_send_intent import _projection
        _projection(unit)
        observed=inspect_enrollment_journal(token,binding,identity)
        rows={title:(sid,nonce) for title,sid,nonce in observed.nonces}
        action=json.loads(unit.action_preimage); target=action["identity"]
        if (target["spreadsheet_id"]!=binding.spreadsheet_id or target["sheet"] not in _TITLES[:3]
                or rows[target["sheet"]]!=(target["sheet_id"],action["target_nonce"])
                or rows["Update_History"]!=(action["history_sheet_id"],action["history_nonce"])):
            raise EnrollmentHold()
    except Exception: failed=True
    if failed: raise EnrollmentHold()


def observe_enrollment_pair(token,binding,identity,plan,response,*,sheet):
    """Exact visible pair only; marker presence alone never proves COMPLETE."""
    failed=False
    try:
        from monitor.issue_tracker_metadata_capacity import _validate_plan
        if (type(sheet) is not str or sheet not in _TITLES[:3] or _validate_plan(plan)!=binding.spreadsheet_id
                or type(response.status) is not int or response.status!=200 or response.complete is not True
                or type(response.data) is not bytes or not 1<=len(response.data)<=2*1024*1024):
            raise EnrollmentHold()
        result=_observe_enrollment_image(token,binding,identity,response.data,sheet=sheet)
    except Exception: failed=True
    if failed: raise EnrollmentHold()
    return result


def _observe_enrollment_image(token,binding,identity,raw,*,sheet):
    """Pure retained-image nonce matching, NOT HTTP/auth/freshness proof.

    The live caller above validates the actual request and complete response.
    A cold COMPLETE reader must separately bind its original RAW bytes and
    fixed request digest; no artificial bearer token or HTTP plan is needed
    to recheck the same metadata semantics against the actual local journal.
    """
    failed=False
    try:
        from monitor.issue_tracker_metadata_capacity import _entry,_pairs,_nonfinite
        if (type(sheet) is not str or sheet not in _TITLES[:3]
                or type(raw) is not bytes or not 1<=len(raw)<=2*1024*1024): raise EnrollmentHold()
        observed=inspect_enrollment_journal(token,binding,identity)
        expected={sid:nonce for title,sid,nonce in observed.nonces}; title_ids=dict(identity.sheet_ids)
        document=json.loads(raw.decode("utf-8","strict"),object_pairs_hook=_pairs,parse_constant=_nonfinite)
        if type(document) is not dict or not set(document)<={"matchedDeveloperMetadata"}: raise EnrollmentHold()
        entries=document.get("matchedDeveloperMetadata",[])
        if type(entries) is not list or len(entries)>30000: raise EnrollmentHold()
        ids=set(); found=set()
        for entry in entries:
            if type(entry) is not dict or set(entry)!={"developerMetadata"}: raise EnrollmentHold()
            mid,pool,size,image=_entry(entry["developerMetadata"],set(title_ids.values()))
            if mid in ids: raise EnrollmentHold()
            ids.add(mid)
            key,value,visibility,kind,sid,coordinate=image
            if key==_KEY:
                if (kind!="SHEET" or visibility!="DOCUMENT" or sid not in expected
                        or value!=expected[sid] or sid in found): raise EnrollmentHold()
                found.add(sid)
        if not {title_ids[sheet],title_ids["Update_History"]}<=found: raise EnrollmentHold()
        ownership._validated_owner(token,binding)
        result=ObservedEnrollmentPair(True,True,observed.journal_sha256,hashlib.sha256(raw).hexdigest())
    except Exception: failed=True
    if failed: raise EnrollmentHold()
    return result


if __name__ == '__main__':
    raise SystemExit(_manual_main())
