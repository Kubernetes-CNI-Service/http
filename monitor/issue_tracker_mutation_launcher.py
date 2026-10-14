"""Uninstalled fixed original-count native launcher, NOT fresh send admission.

Only actual active dual owners plus one issued original CLAIM object may reach
this private entry. No program/URL/body/CA/budget/lock/PID override, CLI, refresh,
replay, COMPLETE or count reset. A production worker must additionally dominate
it with original protected sources, live continuity, shared C23 cadence and G1
capacity. This necessary transport layer does not replace those gates or Stage O.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from time import monotonic as _monotonic

from monitor.issue_tracker_attempt_supervision import supervise_owned_attempt, AttemptHold, _BUDGETS

_SOURCE_ROOT = Path(__file__).resolve().parents[1]
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_CHILD_PROGRAM = '''import sys
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor.issue_tracker_mutation_launcher import _mutation_child
raise SystemExit(_mutation_child(sys.argv[2],int(sys.argv[3]),int(sys.argv[4])))
'''


class MutationLauncherHold(ValueError):
    def __init__(self,termination_confirmed=False):
        super().__init__('req7_counted_mutation_denied')
        self.termination_confirmed = termination_confirmed


@dataclass(frozen=True)
class CountedMutationCompletion:
    attempt_count: int
    status: int
    wire_sha256: str
    response_sha256: object
    outcome: str
    termination_confirmed: bool = True


def _canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')


def _digest(value):
    if type(value) is not str or _SHA.fullmatch(value) is None: raise MutationLauncherHold()
    return value


def _decode_completion(raw,nonce,count,wire_sha256):
    failed = False
    try:
        _digest(nonce); _digest(wire_sha256)
        if (type(raw) is not bytes or not 1 <= len(raw) <= 4096
                or type(count) is not int or not 1 <= count <= 6): raise MutationLauncherHold(True)
        value = json.loads(raw.decode('ascii'))
        if (type(value) is not dict or _canonical(value) != raw
                or set(value) != {'schema_version','nonce','attempt_count','wire_sha256','status','response_sha256','outcome'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or type(value['attempt_count']) is not int or value['attempt_count'] != count
                or value['nonce'] != nonce or value['wire_sha256'] != wire_sha256
                or type(value['status']) is not int or not 200 <= value['status'] <= 599
                or type(value['outcome']) is not str or value['outcome'] not in ('UNKNOWN','DEFINITE_REJECTION')
                or (value['outcome']=='DEFINITE_REJECTION' and
                    (value['status'] not in (400,403,404) or value['response_sha256'] is None))): raise MutationLauncherHold(True)
        if value['response_sha256'] is not None: _digest(value['response_sha256'])
        result = CountedMutationCompletion(count,value['status'],wire_sha256,value['response_sha256'],value['outcome'])
    except Exception: failed = True
    if failed: raise MutationLauncherHold(True)
    return result


def _parse_private(raw,nonce):
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
    from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read
    if type(raw) is not bytes or not 1 <= len(raw) <= 32768: raise MutationLauncherHold()
    value = json.loads(raw.decode('ascii'))
    if (type(value) is not dict or _canonical(value) != raw or set(value) !=
            {'schema_version','nonce','spreadsheet_id','policy_sha256','allowlist_sha256','token','expires_at',
             'unit_id','wire_sha256','action_digest','attempt_count'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['nonce'] != nonce or type(value['attempt_count']) is not int
            or not 1 <= value['attempt_count'] <= 6): raise MutationLauncherHold()
    for field in ('unit_id','wire_sha256','action_digest'): _digest(value[field])
    binding = OnlineTargetBinding(value['spreadsheet_id'],value['allowlist_sha256'],value['policy_sha256'])
    token = AuthenticatedToken(value['token'],value['expires_at'])
    prepare_template_identity_read(binding,token)
    return value,binding,token


def _mutation_child(nonce,action_fd,wire_fd):
    """Fixed private child: original held images, native one-shot, no retry."""
    failed = False
    try:
        _digest(nonce)
        if (os.geteuid() != 0 or any(type(fd) is not int or fd < 3 for fd in (action_fd,wire_fd))
                or action_fd == wire_fd): raise MutationLauncherHold()
        raw = bytearray()
        while True:
            chunk = os.read(0,min(4096,32769-len(raw)))
            if not chunk: break
            raw.extend(chunk)
            if len(raw) > 32768: raise MutationLauncherHold()
        value,binding,token = _parse_private(bytes(raw),nonce)
        from monitor.issue_tracker_tls_inputs import NativeOriginalSheetsMutationUnit
        native = NativeOriginalSheetsMutationUnit(binding,token,action_fd,wire_fd)
        original = native._prepared.unit
        if (original.unit_id != value['unit_id'] or original.action_digest != value['action_digest']
                or original.wire_sha256 != value['wire_sha256']): raise MutationLauncherHold()
        observed = native.send_once()
        output = _canonical({'schema_version':1,'nonce':nonce,'attempt_count':value['attempt_count'],
            'wire_sha256':observed.wire_sha256,'status':observed.status,
            'response_sha256':observed.response_sha256,'outcome':observed.outcome})
        _decode_completion(output,nonce,value['attempt_count'],value['wire_sha256'])
        cursor = 0
        while cursor < len(output):
            written = os.write(1,output[cursor:])
            if written <= 0: raise MutationLauncherHold()
            cursor += written
    except Exception: failed = True
    return 1 if failed else 0


def _send_counted_original_once(writer_token,owner_token,binding,token,unit,image):
    """Necessary original-count transport only; never install as admission.

    Consume the actually issued live CLAIM once before Popen. The same original
    60-second total deadline covers start, bounded private input, DNS/TLS/body,
    termination and post-checks. Both owners remain caller-owned; child inherits
    both locks and original ACTION/WIRE. UNKNOWN is never cleared here.
    """
    started = time.monotonic(); failed = False; confirmed = False; process = None
    try:
        from monitor import issue_tracker_global_attempt_journal as global_journal
        from monitor.issue_tracker_local_commit import _owner
        from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
        from monitor.issue_tracker_online_target import inspect_project_online_target
        from monitor.issue_tracker_send_unit import prepare_mutation_request
        project = _owner(writer_token); sheet_fd = owner_lock_fd(owner_token,binding)
        inspect_project_online_target(writer_token,binding); prepare_mutation_request(binding,token,unit)
        global_journal._consume_original_wire_launch_attempt(writer_token,owner_token,binding,unit,image)
        nonce = secrets.token_hex(32)
        raw = _canonical({'schema_version':1,'nonce':nonce,'spreadsheet_id':binding.spreadsheet_id,
            'policy_sha256':binding.policy_sha256,'allowlist_sha256':binding.allowlist_sha256,
            'token':token.value,'expires_at':token.expires_at,'unit_id':unit.unit_id,
            'wire_sha256':unit.wire_sha256,'action_digest':unit.action_digest,'attempt_count':image.attempt_count})
        _parse_private(raw,nonce)
        executable = str(Path(sys.executable).resolve(strict=True))
        if _monotonic() >= started+_BUDGETS['mutation']: raise MutationLauncherHold()
        if _owner(writer_token) is not project or owner_lock_fd(owner_token,binding) != sheet_fd: raise MutationLauncherHold()
        inspect_project_online_target(writer_token,binding)
        global_journal._require_original_wire_launch(writer_token,owner_token,binding,unit,image,consume=False)
        prepare_mutation_request(binding,token,unit)
        if _monotonic() >= started+_BUDGETS['mutation']: raise MutationLauncherHold()
        process = subprocess.Popen([executable,'-I','-B','-c',_CHILD_PROGRAM,str(_SOURCE_ROOT),nonce,str(image.action_fd),str(image.fd)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True,
            pass_fds=(project.lock_fd,sheet_fd,image.action_fd,image.fd),cwd=str(_SOURCE_ROOT),env={'LC_ALL':'C'})
        completion = supervise_owned_attempt(process,started_monotonic=started,kind='mutation',request_bytes=raw)
        confirmed = completion.termination_confirmed
        inspect_project_online_target(writer_token,binding)
        global_journal._require_original_wire_launch(writer_token,owner_token,binding,unit,image,consume=False)
        result = _decode_completion(completion.data,nonce,image.attempt_count,unit.wire_sha256)
        if _monotonic() >= started+_BUDGETS['mutation']: raise MutationLauncherHold(True)
    except Exception as error:
        failed = True
        if isinstance(error,AttemptHold): confirmed = error.termination_confirmed
    finally:
        if process is not None:
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:
                    try: stream.close()
                    except OSError: failed = True
    if failed: raise MutationLauncherHold(confirmed)
    return result
