"""Uninstalled fixed auth-only child launcher, never a mutation/send permit.

Only the fixed root credential reader, public governed SDK and one native OAuth
unit run in the child. No URL, program, credential path, request, PID or timeout
override is accepted. The held spreadsheet lock is inherited, never unlocked
here. Start-up belongs to the existing 30-second total supervision budget.
An uncertain child is HOLD, not retry authority; this unit is consumed even on
failure. A token proves no target/config/W1/cadence/COMPLETE or permission to
mutate. Production CPython/dependency/CA/root identity remains REAL_ENV NOT RUN.
"""
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
from time import monotonic as _monotonic
import warnings
import weakref
from monitor.issue_tracker_attempt_supervision import supervise_owned_attempt, AttemptHold, _BUDGETS

_SOURCE_ROOT = Path(__file__).resolve().parents[1]
_CHILD_PROGRAM = '''import sys
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor.issue_tracker_token_launcher import _token_child
raise SystemExit(_token_child(sys.argv[2]))
'''
_PROJECT_CHILD_PROGRAM = _CHILD_PROGRAM.replace('_token_child', '_project_token_child')
_PROJECT_TOKENS = weakref.WeakKeyDictionary()
_PROJECT_GUARD = threading.Lock()
_NONCE = re.compile(r'[0-9a-f]{64}\Z')
_TOKEN = re.compile(r'[A-Za-z0-9._~+/\-]+=*\Z')
_EOL_TEXT = ('You are using a Python version %s past its end of life. Google will update '
             'google-auth with critical bug fixes on a best-effort basis, but not with any '
             'other fixes or features. Please upgrade your Python version, and then update google-auth.')
_EOL_IMAGES = {_EOL_TEXT % version for version in ('3.9', '3.10')}


class TokenLauncherHold(ValueError):
    def __init__(self, termination_confirmed=False):
        super().__init__('req7_owned_token_refresh_denied')
        self.termination_confirmed = termination_confirmed


@dataclass(frozen=True)
class TokenRefreshCompletion:
    token: object = field(repr=False)
    runtime_warnings: tuple
    termination_confirmed: bool = True


@dataclass(frozen=True,eq=False)
class ProjectTokenRefreshCompletion:
    """Issued auth-source observation, not G1 inventory or send authority."""
    token: object = field(repr=False)
    cloud_project_id: str = field(repr=False)
    credential_sha256: str
    runtime_warnings: tuple
    termination_confirmed: bool = True


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode('ascii')


def _decode_completion(raw, nonce):
    failed = False
    try:
        if (type(nonce) is not str or _NONCE.fullmatch(nonce) is None
                or type(raw) is not bytes or not 1 <= len(raw) <= 32768):
            raise TokenLauncherHold(True)
        value = json.loads(raw.decode('ascii'))
        if (type(value) is not dict or set(value) != {'schema_version','nonce','token','expires_at','runtime_warnings'}
                or _canonical(value) != raw or type(value['schema_version']) is not int
                or value['schema_version'] != 1 or value['nonce'] != nonce
                or type(value['token']) is not str or not 1 <= len(value['token']) <= 8192
                or _TOKEN.fullmatch(value['token']) is None
                or type(value['expires_at']) not in (int, float)
                or not -sys.float_info.max <= value['expires_at'] <= sys.float_info.max
                or not math.isfinite(value['expires_at']) or value['expires_at'] <= time.time()
                or type(value['runtime_warnings']) is not list
                or value['runtime_warnings'] not in ([], ['GOOGLE_AUTH_PYTHON_EOL'])):
            raise TokenLauncherHold(True)
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        result = TokenRefreshCompletion(AuthenticatedToken(value['token'], value['expires_at']),
                                        tuple(value['runtime_warnings']))
    except Exception: failed = True
    if failed: raise TokenLauncherHold(True)
    return result


def _decode_project_completion(raw,nonce):
    """Decode only; construction/decoding does not issue a live observation."""
    failed=False
    try:
        if type(raw) is not bytes or not 1<=len(raw)<=32768: raise TokenLauncherHold(True)
        value=json.loads(raw.decode('ascii'))
        if (type(value) is not dict or _canonical(value)!=raw or set(value)!=
                {'schema_version','nonce','token','expires_at','runtime_warnings','cloud_project_id','credential_sha256'}
                or type(value['schema_version']) is not int or value['schema_version']!=2
                or type(value['cloud_project_id']) is not str
                or re.fullmatch(r'[a-z][a-z0-9-]{4,28}[a-z0-9]',value['cloud_project_id']) is None
                or type(value['credential_sha256']) is not str or _NONCE.fullmatch(value['credential_sha256']) is None):
            raise TokenLauncherHold(True)
        legacy={key:item for key,item in value.items() if key not in ('cloud_project_id','credential_sha256')}
        legacy['schema_version']=1
        decoded=_decode_completion(_canonical(legacy),nonce)
        result=ProjectTokenRefreshCompletion(decoded.token,value['cloud_project_id'],value['credential_sha256'],
                                            decoded.runtime_warnings,decoded.termination_confirmed)
    except Exception: failed=True
    if failed: raise TokenLauncherHold(True)
    return result


def require_current_owned_project_token(owner_token,binding,value):
    """Exact issued object/current original owner, expiry and fixed source.

    No hashes/typed copies can acquire this process-local observation. Source
    bytes and project must still match the fixed credential file; no refresh,
    reread of another path, send permission or metadata completeness is issued.
    """
    failed=False
    try:
        if type(value) is not ProjectTokenRefreshCompletion: raise TokenLauncherHold()
        with _PROJECT_GUARD: issued=_PROJECT_TOKENS.get(value)
        if issued is None: raise TokenLauncherHold()
        pid,original_token,target,owner,token,token_image,project,digest,warnings_image=issued
        if (pid!=os.getpid() or owner_token is not original_token or binding!=target
                or value.token is not token or (value.token.value,value.token.expires_at)!=token_image
                or value.cloud_project_id!=project or value.credential_sha256!=digest
                or value.runtime_warnings!=warnings_image or value.termination_confirmed is not True
                or time.time()>=token_image[1]): raise TokenLauncherHold()
        from monitor.issue_tracker_spreadsheet_owner import _validated_owner
        from monitor.issue_tracker_sdk_authentication import _fixed_cloud_project_inputs
        if _validated_owner(owner_token,binding) is not owner: raise TokenLauncherHold()
        _parsed,current_project,current_digest=_fixed_cloud_project_inputs()
        if (current_project!=project or current_digest!=digest
                or _validated_owner(owner_token,binding) is not owner or time.time()>=token_image[1]):
            raise TokenLauncherHold()
        result=project,digest
    except Exception: failed=True
    if failed: raise TokenLauncherHold()
    return result


def _token_child(nonce):
    """Fixed internal child entry. Failure emits no secret diagnostics or token."""
    return _emit_token_child(nonce,project_scope=False)


def _project_token_child(nonce):
    """Separate fixed G1 source protocol, no caller unit or scope override."""
    return _emit_token_child(nonce,project_scope=True)


def _emit_token_child(nonce,*,project_scope):
    failed = False
    try:
        if type(nonce) is not str or _NONCE.fullmatch(nonce) is None or os.geteuid() != 0:
            raise TokenLauncherHold()
        # Retain the known public runtime EOL warning as an explicit bounded
        # diagnostic tag; the parent re-emits its fixed nonsecret text. Never
        # relay arbitrary warning/exception strings into the private protocol.
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter('always')
            if project_scope:
                from monitor.issue_tracker_sdk_authentication import _refresh_fixed_cloud_project
                token,project,digest=_refresh_fixed_cloud_project()
            else:
                from monitor.issue_tracker_sdk_authentication import refresh_fixed_service_account
                from monitor.issue_tracker_tls_inputs import NativeTokenHttpsUnit
                token = refresh_fixed_service_account(NativeTokenHttpsUnit())
        if (len(recorded) > 2 or any(item.category is not FutureWarning or str(item.message) not in _EOL_IMAGES
                                     for item in recorded)):
            raise TokenLauncherHold()
        image={'schema_version': 1, 'nonce': nonce, 'token': token.value,
                          'expires_at': token.expires_at,
                          'runtime_warnings': ['GOOGLE_AUTH_PYTHON_EOL'] if recorded else []}
        if project_scope: image.update(schema_version=2,cloud_project_id=project,credential_sha256=digest)
        raw=_canonical(image)
        (_decode_project_completion if project_scope else _decode_completion)(raw,nonce)
        # Private pipe only; no token in argv/env/files/logs or exception text.
        offset = 0
        while offset < len(raw):
            written = os.write(1, raw[offset:])
            if written <= 0: raise TokenLauncherHold()
            offset += written
    except Exception: failed = True
    return 1 if failed else 0


class OwnedTokenRefreshUnit:
    """One fixed supervised refresh under an existing actual spreadsheet owner.

    Neither construction nor refresh opens/closes the borrowed lock. The caller
    must HOLD/escalate on unconfirmed termination and must never infer a token
    from partial output, a failed child or an uncorrelated response.
    """
    def __init__(self, owner_token, binding):
        failed = False
        try:
            from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
            owner_lock_fd(owner_token, binding)
        except Exception: failed = True
        if failed: raise TokenLauncherHold()
        self._owner_token = owner_token; self._binding = binding
        self._used = False; self._guard = threading.Lock()

    def refresh_once(self):
        return self._refresh_once(project_scope=False)

    def _refresh_once(self,*,project_scope):
        with self._guard:
            consumed = self._used; self._used = True
        if consumed: raise TokenLauncherHold()
        # The clock precedes identity checks, nonce allocation AND Popen.
        started = time.monotonic(); failed = False; confirmed = False; process = None
        try:
            from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
            fd = owner_lock_fd(self._owner_token, self._binding)
            executable = str(Path(sys.executable).resolve(strict=True))
            nonce = secrets.token_hex(32)
            if _monotonic() >= started + _BUDGETS['token']: raise TokenLauncherHold()
            process = subprocess.Popen(
                [executable, '-I', '-B', '-c', _PROJECT_CHILD_PROGRAM if project_scope else _CHILD_PROGRAM, str(_SOURCE_ROOT), nonce],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, close_fds=True, pass_fds=(fd,),
                cwd=str(_SOURCE_ROOT), env={'LC_ALL': 'C'},
            )
            completion = supervise_owned_attempt(process, started_monotonic=started, kind='token')
            confirmed = completion.termination_confirmed
            owner_lock_fd(self._owner_token, self._binding)
            result = (_decode_project_completion if project_scope else _decode_completion)(completion.data, nonce)
            if result.runtime_warnings:
                version = '%d.%d' % sys.version_info[:2]
                if _EOL_TEXT % version not in _EOL_IMAGES: raise TokenLauncherHold(True)
                warnings.warn(_EOL_TEXT % version, FutureWarning)
            if project_scope:
                from monitor.issue_tracker_spreadsheet_owner import _validated_owner
                owner=_validated_owner(self._owner_token,self._binding)
                if not confirmed or _monotonic()>=started+_BUDGETS['token']: raise TokenLauncherHold(confirmed)
                with _PROJECT_GUARD:
                    _PROJECT_TOKENS[result]=(os.getpid(),self._owner_token,self._binding,owner,result.token,
                        (result.token.value,result.token.expires_at),result.cloud_project_id,
                        result.credential_sha256,result.runtime_warnings)
        except Exception as error:
            failed = True
            if isinstance(error, AttemptHold): confirmed = error.termination_confirmed
        finally:
            # Supervision may refuse before entering its pipe cleanup scope
            # when a leader/session is unproved. Close only our private pipes,
            # NEVER the borrowed lock or an unproved numeric process group.
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try: stream.close()
                        except OSError: failed = True
        if failed: raise TokenLauncherHold(confirmed)
        return result


class OwnedProjectTokenRefreshUnit(OwnedTokenRefreshUnit):
    """Uninstalled G1 fixed-project auth; same one-use 30-second supervision."""
    def refresh_once(self):
        return self._refresh_once(project_scope=True)
