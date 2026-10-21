"""NOT RUN. Actual private-input contexts, fixed owned cold-child containment."""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

import test_cases
from test_cases import test_req7_spreadsheet_owner as existing_io

ROOT=Path(test_cases.__file__).resolve().parents[1]
TARGET='synthetic_spreadsheet_id_0001'
CRE=b'{"type":"service_account","private_key":"FIXED-PRIVATE-INPUT-NOT-A-REAL-KEY","client_email":"synthetic@example.invalid","token_uri":"https://oauth2.googleapis.com/token"}\n'
ALLOWLIST=b'["synthetic_spreadsheet_id_0001"]\n'
GLOBAL=b'{"schema_version":2,"common":{"mgmt":{"issue-tracker":{"status":"enabled","spreadsheet_id":"synthetic_spreadsheet_id_0001","publish_every_cycles":1}}}}\n'
CHILD_METHODS=('_exercise_credential_body_ni_then_close_ni', '_exercise_target_body_ni_then_close_ni')
CHILD_PROGRAM=(
 "import sys,unittest\n"
 "sys.path.insert(0,sys.argv[1])\n"
 "from test_cases.test_req7_private_input_ni_cleanup import PrivateInputNICleanupTests\n"
 "from test_cases.private_input_ni_fixture import CHILD_METHODS\n"
 "name=sys.argv[2]\n"
 "if name not in CHILD_METHODS: raise SystemExit(64)\n"
 "r=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([PrivateInputNICleanupTests(name)]))\n"
 "print('PRIVATE_INPUT_NI_CHILD_END='+name+';success='+str(r.wasSuccessful()),flush=True)\n"
 "raise SystemExit(0 if r.wasSuccessful() else 1)\n")

def capture(call):
    try:return call(),None
    except BaseException as error:return None,error

def errors():
    body=KeyboardInterrupt('fixed original private-input body NI')
    body_cause=RuntimeError('fixed original private-input body cause')
    body.__cause__=body_cause;body.__suppress_context__=True
    close=GeneratorExit('fixed distinct private-input close NI')
    close_cause=RuntimeError('fixed distinct private-input close cause')
    close.__cause__=close_cause;close.__suppress_context__=True
    return body,body_cause,close,close_cause

def new_root():
    root=Path(tempfile.mkdtemp(prefix='req7-private-input-ni-owned-',dir='/private/tmp')).resolve(strict=True)
    root.chmod(0o700)
    print('PRIVATE_INPUT_NI_OWNED_ROOT='+str(root),flush=True)
    fixed=root/'var/lib/http-ztp-container/service-account'
    fixed.mkdir(parents=True,mode=0o700);fixed.chmod(0o700)
    for name,raw in (('cre.json',CRE),('issue-tracker-spreadsheet-whitelist.json',ALLOWLIST)):
        path=fixed/name;path.write_bytes(raw);path.chmod(0o600)
    return root

class KnownCloseIO:
    """Transparent module-local IO, only known original closes may be faulted."""
    def __init__(self,base,revoked,*,record_opens=True):
        self.base=base;self.revoked_check=revoked;self.record_opens=record_opens
        self.opened=[];self.slots=();self.calls=[];self.ebadf=[];self.revoked=[]
        self.fault_fd=None;self.fault_error=None;self.faults=0
    def __getattr__(self,name):return getattr(self.base,name)
    def open(self,*args,**kwargs):
        fd=self.base.open(*args,**kwargs)
        if self.record_opens:self.opened.append(fd)
        return fd
    def arm(self,descriptors,*,fault_fd=None,fault_error=None):
        if self.slots:raise AssertionError('fixture never refreshes known original slots')
        descriptors=tuple(descriptors)
        if len(descriptors)!=len(set(descriptors)):raise AssertionError('fixture duplicate original slots')
        self.slots=tuple((fd,os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in descriptors)
        self.fault_fd=fault_fd;self.fault_error=fault_error
    def close(self,fd):
        matches=[slot for slot in self.slots if slot[0]==fd]
        if not matches:return self.base.close(fd)
        if fd in self.calls:raise AssertionError('fixture saw duplicate close; no numeric retry')
        before=os.fstat(fd)
        if (before.st_dev,before.st_ino)!=matches[0][1:]:raise AssertionError('fixture refuses replaced original FD')
        self.calls.append(fd);self.revoked.append(self.revoked_check())
        self.base.close(fd)  # Genuine native close happens BEFORE injected NI.
        try:os.fstat(fd)
        except OSError as error:
            if error.errno!=errno.EBADF:raise
            self.ebadf.append(error.errno)
        else:raise AssertionError('actual close did not close original descriptor')
        if fd==self.fault_fd:
            self.faults+=1
            raise self.fault_error
    def snapshot(self):
        remaining=[]
        # Only the exact known slots, never /dev/fd, /proc, PID or descriptor scan.
        for fd,dev,ino in self.slots:
            try:actual=os.fstat(fd)
            except OSError as error:
                if error.errno!=errno.EBADF:raise
            else:remaining.append({'same_original':(actual.st_dev,actual.st_ino)==(dev,ino)})
        return dict(slots=len(self.slots),calls=len(self.calls),ebadf=list(self.ebadf),
          revoked=list(self.revoked),faults=self.faults,remaining=remaining,
          each_known_slot_once=len(self.calls)==len(set(self.calls)))

class TargetCloseRoute:
    """Route only observed target slots through their original close observer."""
    def __init__(self,local_io,target_io):
        self.local_io=local_io;self.target_io=target_io
    def __getattr__(self,name):return getattr(self.local_io,name)
    def close(self,fd):
        local_slot=any(slot[0]==fd for slot in self.local_io.slots)
        target_slot=any(slot[0]==fd for slot in self.target_io.slots)
        if target_slot and not local_slot:
            # That observer checks its saved actual dev/ino BEFORE native close;
            # this is the same close, not a second close, rescue or fake count.
            return self.target_io.close(fd)
        return self.local_io.close(fd)

def credential_case(*,fault):
    from monitor import issue_tracker_credential_shape as private
    root=new_root();body,cause,close,close_cause=errors()
    ready=False;view=None;observed=None
    def operation():
        nonlocal ready,view,observed
        with existing_io.scoped_fixture(root,private):
            view=KnownCloseIO(private.os,lambda:True)
            with mock.patch.object(private,'os',view):
                with private._hold_private_file('cre.json') as (raw,verify):
                    view.arm(view.opened,fault_fd=view.opened[-1] if fault else None,
                      fault_error=close if fault else None)
                    verify();parsed=private.parse_service_account_info(raw)
                    observed=(raw,dict(parsed.mapping))
                    ready=True
                    if fault:raise body
    _unused,error=capture(operation)
    return dict(root=root,error=error,body=body,cause=cause,close=close,close_cause=close_cause,
      ready=ready,observed=observed,private=view.snapshot() if view else None,
      shared_os_unchanged=private.os is os)

def target_case(*,fault):
    from monitor import issue_tracker_online_target as target
    from monitor import issue_tracker_credential_shape as private
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_state_owner as state
    root=new_root();project=root/'project';project.mkdir(mode=0o755);project.chmod(0o755)
    publication=project/'99-output-monitor';publication.mkdir(mode=0o755);publication.chmod(0o755)
    config=project/'01-global.yaml';config.write_bytes(GLOBAL);config.chmod(0o644)
    state.initialize_tracker_state(project,publication,initialized_at='2026-09-25T00:00:00Z',acquisition_id='acquisition-0')
    body,cause,close,close_cause=errors()
    ready=False;bound=None;token=None;observed_k=None
    private_io=target_io=local_io=None;seen=[];profile_errors=[]
    inner=target._hold_current_project_online_target.__wrapped__
    previous=sys.getprofile()
    def profile(frame,event,arg):
        if previous is not None:previous(frame,event,arg)
        if (event=='return' and frame.f_code is inner.__code__
                and frame.f_globals is target.__dict__ and frame.f_locals.get('key') is not None):
            if not seen:
                try:
                    fd=frame.f_locals['fd'];descriptors=(fd,*frame.f_locals['project_fds'])
                    target_io.arm(descriptors,fault_fd=fd if fault else None,
                      fault_error=close if fault else None)
                    seen.append(True)
                except BaseException as error:profile_errors.append(type(error).__name__)
    def operation():
        nonlocal ready,bound,token,observed_k,private_io,target_io,local_io
        with existing_io.scoped_fixture(root,private),existing_io.scoped_fixture(root,target):
            private_io=KnownCloseIO(private.os,lambda:target._HELD_CURRENT_TARGET.get() is None)
            target_io=KnownCloseIO(target.os,lambda:target._HELD_CURRENT_TARGET.get() is None)
            with ExitStack() as patches:
                patches.enter_context(mock.patch.object(private,'os',private_io))
                patches.enter_context(mock.patch.object(target,'os',target_io))
                with state.tracker_writer(project,publication) as token:
                    owner=local._owner(token);k=state.current_k(token);observed_k=(k.revision,k.k)
                    local_io=KnownCloseIO(local.os,lambda:token not in local._ACTIVE,record_opens=False)
                    local_io.arm((owner.project_fd,owner.root_fd,owner.publication_fd,owner.lock_fd))
                    patches.enter_context(mock.patch.object(local,'os',TargetCloseRoute(local_io,target_io)))
                    sys.setprofile(profile)
                    try:
                        with target._hold_current_project_online_target(token) as bound:
                            private_io.arm(private_io.opened)
                            target._require_held_current_project_online_target(token,bound)
                            local._owner(token)
                            ready=True
                            if fault:raise body
                    finally:sys.setprofile(previous)
    _unused,error=capture(operation)
    _unused,revoked_error=capture(lambda:target._require_held_current_project_online_target(token,bound))
    return dict(root=root,error=error,body=body,cause=cause,close=close,close_cause=close_cause,
      ready=ready,binding=bound,observed_k=observed_k,profile_seen=len(seen),profile_errors=profile_errors,
      target=target_io.snapshot() if target_io else None,private=private_io.snapshot() if private_io else None,
      local=local_io.snapshot() if local_io else None,target_expected_slots=1+len(project.parts),
      target_revoked=target._HELD_CURRENT_TARGET.get() is None,
      local_revoked=token not in local._ACTIVE,revoked_error=revoked_error,hold=target.OnlineTargetHold,
      shared_os_unchanged=target.os is private.os is local.os is os,
      config_unchanged=config.read_bytes()==GLOBAL)

def diagnostic(label,outcome):
    print('PRIVATE_INPUT_NI_FACTS='+json.dumps(dict(label=label,ready=outcome['ready'],
      original_body_ni=outcome['error'] is outcome['body'],
      original_body_cause=outcome['error'] is not None and outcome['error'].__cause__ is outcome['cause'],
      error_type=type(outcome['error']).__name__ if outcome['error'] is not None else None,
      private=outcome.get('private'),target=outcome.get('target'),local=outcome.get('local'),
      target_revoked=outcome.get('target_revoked'),local_revoked=outcome.get('local_revoked'),
      profile_seen=outcome.get('profile_seen'),profile_errors=outcome.get('profile_errors')),
      sort_keys=True),flush=True)

def run_owned(case,name):
    if name not in CHILD_METHODS:raise AssertionError('unknown private-input child selector')
    process=subprocess.Popen((sys.executable,'-B','-c',CHILD_PROGRAM,str(ROOT),name),
      cwd=str(ROOT),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      start_new_session=True,close_fds=True,env={'LC_ALL':'C','HOME':os.path.expanduser('~')})
    try:
        try:output,errors=process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            if process.poll() is None:process.kill()
            process.communicate(timeout=5)
            case.fail('OWNED_PRIVATE_INPUT_FIXTURE_TIMEOUT_UNKNOWN')
        case.assertLessEqual(len(output)+len(errors),131072)
        print(output.decode('utf-8','replace'),end='',flush=True)
        if process.returncode!=0:print(errors.decode('utf-8','replace'),end='',flush=True)
        case.assertEqual(0,process.returncode,'OWNED_PRIVATE_INPUT_NI_ASSERTIONS_FAILED')
        case.assertEqual(1,output.count(('PRIVATE_INPUT_NI_CHILD_END='+name+';success=True\n').encode()))
    finally:
        for stream in (process.stdout,process.stderr):stream.close()
