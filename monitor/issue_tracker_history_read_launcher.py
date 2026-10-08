"""Uninstalled fixed Sheets reads, not reconciliation or send authority.

An actual ACTIVE project owner and spreadsheet owner dominate this one-use
launch. Current fixed-file target policy/allowlist are reopened before and after
the read. Both borrowed locks pass to the isolated child. Token/request input is
private bounded stdin under the original 30-second budget, never argv/env.
Only enumerated fixed bounded read shapes are available: no URL, ranges, program,
credential path, PID, timeout, mutation, refresh, replay or activation override.
Correlated complete HTTP bytes are an observation, not typed History matches,
enrollment continuity, COMPLETE/APPLIED, a retry permit or deployment proof.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
import weakref
from time import monotonic as _monotonic
from monitor.issue_tracker_attempt_supervision import supervise_owned_attempt, AttemptHold, _BUDGETS

_SOURCE_ROOT = Path(__file__).resolve().parents[1]
_NONCE = re.compile(r'[0-9a-f]{64}\Z')
_LIMIT = 2*1024*1024
_READS = weakref.WeakKeyDictionary()
_READ_GUARD = threading.Lock()
_PROJECT_READS = weakref.WeakKeyDictionary()
_PROJECT_READ_GUARD = threading.Lock()
_CHILD_PROGRAM = '''import sys
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor.issue_tracker_history_read_launcher import _history_child
raise SystemExit(_history_child(sys.argv[2]))
'''


class HistoryReadLauncherHold(ValueError):
    def __init__(self, termination_confirmed=False):
        super().__init__('req7_owned_history_read_denied')
        self.termination_confirmed = termination_confirmed


@dataclass(frozen=True, eq=False)
class SupervisedSheetsReadCompletion:
    data: bytes = field(repr=False)
    request_path_sha256: str
    status: int = 200
    complete: bool = True
    termination_confirmed: bool = True


def require_current_owned_read(writer_token,owner_token,binding,completion,*,read_kind,sheet=None,row=None):
    """Original process-local issued observation only, NOT a mutation permit.

    Equality, caller-built dataclasses/digests or standalone protocol decoding
    do not establish a read. Recheck exact actual owner acquisitions, immutable
    response/shape, original bounded observation deadline and fresh target files.
    No persisted authority, refresh, send, CAS, remote continuity or COMPLETE.
    """
    failed=False
    try:
        if type(completion) is not SupervisedSheetsReadCompletion: raise HistoryReadLauncherHold()
        with _READ_GUARD: issued=_READS.get(completion)
        if issued is None: raise HistoryReadLauncherHold()
        writer,owner,original_binding,project,sheet_fd,kind,original_sheet,original_row,plan,data,deadline=issued
        if (writer_token is not writer or owner_token is not owner or binding != original_binding
                or read_kind != kind or sheet != original_sheet or row != original_row
                or type(read_kind) is not str or type(sheet) is not type(original_sheet)
                or type(row) is not type(original_row)
                or type(completion.data) is not bytes or completion.data != data
                or type(completion.status) is not int or completion.status != 200
                or completion.complete is not True or completion.termination_confirmed is not True
                or completion.request_path_sha256 != hashlib.sha256(plan.path.encode('ascii')).hexdigest()
                or _monotonic() >= deadline): raise HistoryReadLauncherHold()
        from monitor.issue_tracker_local_commit import _owner
        from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
        from monitor.issue_tracker_online_target import inspect_project_online_target
        if _owner(writer_token) is not project or owner_lock_fd(owner_token,binding) != sheet_fd:
            raise HistoryReadLauncherHold()
        inspect_project_online_target(writer_token,binding)
        if _monotonic() >= deadline: raise HistoryReadLauncherHold()
        result=plan
    except Exception: failed=True
    if failed: raise HistoryReadLauncherHold()
    return result


def require_current_owned_project_read(writer_token,owner_token,binding,completion,authentication,*,
                                       read_kind,sheet=None,row=None):
    """Original project-auth acquisition and actual fixed read, not G1 GO.

    Same-valued tokens, decoded objects, other successful auth acquisitions and
    standalone legacy reads cannot provide this provenance. Both original
    owners, current target/fixed credentials, token expiry, exact read shape
    and original read deadline still have to hold. No dedicated-table claim,
    historical visibility proof, reservation authority or send is supplied.
    """
    failed=False
    try:
        if type(completion) is not SupervisedSheetsReadCompletion: raise HistoryReadLauncherHold()
        with _PROJECT_READ_GUARD: original=_PROJECT_READS.get(completion)
        if authentication is not original or original is None: raise HistoryReadLauncherHold()
        from monitor.issue_tracker_token_launcher import require_current_owned_project_token
        project,digest=require_current_owned_project_token(owner_token,binding,original)
        plan=require_current_owned_read(writer_token,owner_token,binding,completion,
            read_kind=read_kind,sheet=sheet,row=row)
        if plan.headers[1]!=('Authorization','Bearer '+original.token.value): raise HistoryReadLauncherHold()
        if require_current_owned_project_token(owner_token,binding,original)!=(project,digest):
            raise HistoryReadLauncherHold()
        # Fixed-source revalidation must not carry the original read past its
        # deadline or survive project policy/owner revocation in that interval.
        require_current_owned_read(writer_token,owner_token,binding,completion,
            read_kind=read_kind,sheet=sheet,row=row)
        result=plan,project,digest
    except Exception: failed=True
    if failed: raise HistoryReadLauncherHold()
    return result


def _canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')


def _decode_completion(raw, nonce, path_digest):
    failed = False
    try:
        if (type(raw) is not bytes or not 1 <= len(raw) <= _LIMIT
                or type(nonce) is not str or _NONCE.fullmatch(nonce) is None
                or type(path_digest) is not str or _NONCE.fullmatch(path_digest) is None):
            raise HistoryReadLauncherHold(True)
        boundary=raw.find(b'\n',0,1024)
        if boundary < 0: raise HistoryReadLauncherHold(True)
        header,body=raw[:boundary+1],raw[boundary+1:]
        value=json.loads(header.decode('ascii'))
        if (type(value) is not dict or set(value) != {'schema_version','nonce','request_path_sha256','status','body_sha256','body_bytes'}
                or _canonical(value) != header or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['nonce'] != nonce or value['request_path_sha256'] != path_digest
                or type(value['status']) is not int or value['status'] != 200
                or type(value['body_bytes']) is not int or not body or value['body_bytes'] != len(body)
                or value['body_sha256'] != hashlib.sha256(body).hexdigest()):
            raise HistoryReadLauncherHold(True)
        result=SupervisedSheetsReadCompletion(body,path_digest)
    except Exception: failed=True
    if failed: raise HistoryReadLauncherHold(True)
    return result


def _prepare(binding,token,kind,sheet,row):
    from monitor import issue_tracker_sheets_read_plan as plans
    fixed={'history_tail':plans.prepare_history_tail_read,'whitelist':plans.prepare_online_whitelist_read,
           'template_identity':plans.prepare_template_identity_read,'template_headers':plans.prepare_template_header_read}
    if type(kind) is not str: raise HistoryReadLauncherHold()
    if kind in fixed:
        if sheet is not None or row is not None: raise HistoryReadLauncherHold()
        return fixed[kind](binding,token)
    if kind in ('activity','insertion'):
        if row is not None: raise HistoryReadLauncherHold()
        function=plans.prepare_activity_sheet_read if kind=='activity' else plans.prepare_insertion_sheet_read
        return function(binding,token,sheet=sheet)
    if kind=='row':
        return plans.prepare_sheets_read(binding,token,mode='row_rectangle',sheet=sheet,first_row=row)
    if kind=='metadata':
        if sheet is not None or row is not None: raise HistoryReadLauncherHold()
        from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
        return prepare_metadata_capacity_read(binding,token)
    raise HistoryReadLauncherHold()


def _parse_request(raw,nonce):
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
    if (type(raw) is not bytes or not 1 <= len(raw) <= 32768
            or type(nonce) is not str or _NONCE.fullmatch(nonce) is None): raise HistoryReadLauncherHold()
    value=json.loads(raw.decode('ascii'))
    if (type(value) is not dict or set(value) != {'schema_version','nonce','spreadsheet_id','policy_sha256',
                                                'allowlist_sha256','token','expires_at','read_kind','sheet','row'}
            or _canonical(value) != raw or type(value['schema_version']) is not int or value['schema_version'] != 2
            or value['nonce'] != nonce): raise HistoryReadLauncherHold()
    binding=OnlineTargetBinding(value['spreadsheet_id'],value['allowlist_sha256'],value['policy_sha256'])
    token=AuthenticatedToken(value['token'],value['expires_at'])
    return binding,token,_prepare(binding,token,value['read_kind'],value['sheet'],value['row'])


def _native_read(binding,token,kind,sheet,row):
    # Reconstruct only the validated fixed planner shape inside the child.
    from monitor import issue_tracker_tls_inputs as tls
    fixed={'history_tail':tls.NativeHistoryTailReadUnit,'whitelist':tls.NativeOnlineWhitelistReadUnit,
           'template_identity':tls.NativeTemplateIdentityReadUnit,'template_headers':tls.NativeTemplateHeaderReadUnit}
    if kind in fixed: return fixed[kind](binding,token).send_once()
    if kind=='activity': return tls.NativeActivitySheetReadUnit(binding,token,sheet=sheet).send_once()
    if kind=='insertion': return tls.NativeInsertionSheetReadUnit(binding,token,sheet=sheet).send_once()
    if kind=='row': return tls.NativeSheetsReadUnit(binding,token,mode='row_rectangle',sheet=sheet,first_row=row).send_once()
    if kind=='metadata':
        from monitor.issue_tracker_metadata_capacity import NativeMetadataCapacityReadUnit
        return NativeMetadataCapacityReadUnit(binding,token).send_once()
    raise HistoryReadLauncherHold()


def _history_child(nonce):
    """Internal entry: root guard, private input, one fixed native read, no retry."""
    failed=False
    try:
        if type(nonce) is not str or _NONCE.fullmatch(nonce) is None or os.geteuid() != 0:
            raise HistoryReadLauncherHold()
        raw=bytearray()
        while True:
            chunk=os.read(0,min(4096,32769-len(raw)))
            if not chunk: break
            raw.extend(chunk)
            if len(raw)>32768: raise HistoryReadLauncherHold()
        binding,token,prepared=_parse_request(bytes(raw),nonce)
        value=json.loads(bytes(raw).decode('ascii'))
        response=_native_read(binding,token,value['read_kind'],value['sheet'],value['row'])
        if (type(response.status) is not int or response.status != 200 or response.complete is not True
                or type(response.data) is not bytes or not response.data): raise HistoryReadLauncherHold()
        path_digest=hashlib.sha256(prepared.path.encode('ascii')).hexdigest()
        header=_canonical({'schema_version':1,'nonce':nonce,'request_path_sha256':path_digest,'status':200,
                           'body_sha256':hashlib.sha256(response.data).hexdigest(),'body_bytes':len(response.data)})
        output=header+response.data
        # Composite private response retains the existing supervisor cap. Near
        # the body limit, refuse rather than increase it or truncate the body.
        _decode_completion(output,nonce,path_digest)
        cursor=0
        while cursor<len(output):
            written=os.write(1,output[cursor:cursor+65536])
            if written<=0: raise HistoryReadLauncherHold()
            cursor+=written
    except Exception: failed=True
    return 1 if failed else 0


class OwnedSheetsReadUnit:
    """One observed response under actual dual owners; no COMPLETE authority."""
    def __init__(self,writer_token,owner_token,binding,token,*,read_kind,sheet=None,row=None):
        failed=False
        try:
            from monitor.issue_tracker_local_commit import _owner
            from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
            _owner(writer_token); owner_lock_fd(owner_token,binding); _prepare(binding,token,read_kind,sheet,row)
        except Exception: failed=True
        if failed: raise HistoryReadLauncherHold()
        self._writer=writer_token; self._owner=owner_token; self._binding=binding; self._token=token
        self._kind=read_kind; self._sheet=sheet; self._row=row
        self._guard=threading.Lock(); self._used=False

    def read_once(self):
        return self._read_once()

    def _read_once(self,*,project_auth=None):
        with self._guard:
            used=self._used; self._used=True
        if used: raise HistoryReadLauncherHold()
        started=time.monotonic(); failed=False; confirmed=False; process=None
        try:
            if project_auth is not None:
                from monitor.issue_tracker_token_launcher import require_current_owned_project_token
                require_current_owned_project_token(self._owner,self._binding,project_auth)
                if self._token is not project_auth.token: raise HistoryReadLauncherHold()
            from monitor.issue_tracker_local_commit import _owner
            from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
            from monitor.issue_tracker_online_target import inspect_project_online_target
            project=_owner(self._writer); sheet_fd=owner_lock_fd(self._owner,self._binding)
            inspect_project_online_target(self._writer,self._binding)
            nonce=secrets.token_hex(32)
            raw=_canonical({'schema_version':2,'nonce':nonce,'spreadsheet_id':self._binding.spreadsheet_id,
                            'policy_sha256':self._binding.policy_sha256,'allowlist_sha256':self._binding.allowlist_sha256,
                            'token':self._token.value,'expires_at':self._token.expires_at,
                            'read_kind':self._kind,'sheet':self._sheet,'row':self._row})
            _binding,_token,prepared=_parse_request(raw,nonce)
            path_digest=hashlib.sha256(prepared.path.encode('ascii')).hexdigest()
            executable=str(Path(sys.executable).resolve(strict=True))
            if _monotonic() >= started+_BUDGETS['read']: raise HistoryReadLauncherHold()
            # Final actual owner observations precede this one child launch.
            if _owner(self._writer) is not project or owner_lock_fd(self._owner,self._binding) != sheet_fd:
                raise HistoryReadLauncherHold()
            process=subprocess.Popen([executable,'-I','-B','-c',_CHILD_PROGRAM,str(_SOURCE_ROOT),nonce],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                start_new_session=True,close_fds=True,pass_fds=(project.lock_fd,sheet_fd),
                cwd=str(_SOURCE_ROOT),env={'LC_ALL':'C'})
            completion=supervise_owned_attempt(process,started_monotonic=started,kind='read',request_bytes=raw)
            confirmed=completion.termination_confirmed
            inspect_project_online_target(self._writer,self._binding)
            if _owner(self._writer) is not project or owner_lock_fd(self._owner,self._binding) != sheet_fd:
                raise HistoryReadLauncherHold(True)
            result=_decode_completion(completion.data,nonce,path_digest)
            if project_auth is not None:
                require_current_owned_project_token(self._owner,self._binding,project_auth)
                inspect_project_online_target(self._writer,self._binding)
                if _owner(self._writer) is not project or owner_lock_fd(self._owner,self._binding)!=sheet_fd:
                    raise HistoryReadLauncherHold(True)
            if _monotonic() >= started+_BUDGETS['read']: raise HistoryReadLauncherHold(True)
            # Private identity registry, not dataclass equality or caller hashes.
            # Only this actual successful supervised/fresh-owner launch issues
            # a bounded process-local read observation. Decoding alone does not.
            with _READ_GUARD:
                _READS[result]=(self._writer,self._owner,self._binding,project,sheet_fd,
                    self._kind,self._sheet,self._row,prepared,result.data,started+_BUDGETS['read'])
            if project_auth is not None:
                with _PROJECT_READ_GUARD: _PROJECT_READS[result]=project_auth
        except Exception as error:
            failed=True
            if isinstance(error,AttemptHold): confirmed=error.termination_confirmed
        finally:
            if process is not None:
                for stream in (process.stdin,process.stdout,process.stderr):
                    if stream is not None:
                        try: stream.close()
                        except OSError: failed=True
        if failed: raise HistoryReadLauncherHold(confirmed)
        return result


class OwnedProjectSheetsReadUnit(OwnedSheetsReadUnit):
    """Fixed read shapes with original owned auth provenance; never a permit."""
    def __init__(self,writer_token,owner_token,binding,authentication,*,read_kind,sheet=None,row=None):
        failed=False
        try:
            from monitor.issue_tracker_token_launcher import require_current_owned_project_token
            require_current_owned_project_token(owner_token,binding,authentication)
            super().__init__(writer_token,owner_token,binding,authentication.token,
                             read_kind=read_kind,sheet=sheet,row=row)
        except Exception: failed=True
        if failed: raise HistoryReadLauncherHold()
        self._authentication=authentication

    def read_once(self):
        return self._read_once(project_auth=self._authentication)


class OwnedHistoryTailReadUnit(OwnedSheetsReadUnit):
    """Convenience entry without a caller-selected shape, still read-only."""
    def __init__(self,writer_token,owner_token,binding,token):
        super().__init__(writer_token,owner_token,binding,token,read_kind='history_tail')
