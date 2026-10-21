"""NOT RUN. Narrow no-body-exception contexts; V2 observers remain unchanged."""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

from test_cases import private_input_ni_fixture as original

ROOT=original.ROOT
PAIRS=(('credential','ni'),('credential','eio'),('target','ni'),('target','eio'))
SECRET='FIXED_PRIVATE_CLOSE_REGRESSION_SECRET'
CHILD_PROGRAM=(
 "import sys,unittest\n"
 "sys.path.insert(0,sys.argv[1])\n"
 "from test_cases.test_req7_private_input_close_regression import PrivateInputCloseRegressionTests\n"
 "from test_cases.private_input_close_regression_fixture import PAIRS\n"
 "pair=(sys.argv[2],sys.argv[3])\n"
 "if pair not in PAIRS: raise SystemExit(64)\n"
 "case=PrivateInputCloseRegressionTests()\n"
 "r=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([unittest.FunctionTestCase(lambda:case._exercise(*pair))]))\n"
 "print('PRIVATE_INPUT_CLOSE_CHILD_END='+':'.join(pair)+';success='+str(r.wasSuccessful()),flush=True)\n"
 "raise SystemExit(0 if r.wasSuccessful() else 1)\n")

def close_error(kind):
    if kind=='ni':error=GeneratorExit('fixed original close-only NI')
    elif kind=='eio':error=OSError(errno.EIO,SECRET)
    else:raise AssertionError('unknown close fault')
    cause=RuntimeError('fixed original close-only cause')
    error.__cause__=cause;error.__suppress_context__=True
    return error,cause

def credential_case(kind):
    from monitor import issue_tracker_credential_shape as private
    root=original.new_root();error,cause=close_error(kind)
    view=None;body_completed=False;observed=None
    def operation():
        nonlocal view,body_completed,observed
        with original.existing_io.scoped_fixture(root,private):
            view=original.KnownCloseIO(private.os,lambda:True)
            with mock.patch.object(private,'os',view):
                with private._hold_private_file('cre.json') as (raw,verify):
                    view.arm(view.opened,fault_fd=view.opened[-1],fault_error=error)
                    verify();observed=(raw,dict(private.parse_service_account_info(raw).mapping))
                    body_completed=True  # NO body raise: only actual close may fault.
    _unused,outgoing=original.capture(operation)
    return dict(root=root,error=outgoing,close_error=error,close_cause=cause,
      body_completed=body_completed,observed=observed,private=view.snapshot() if view else None,
      shared_os_unchanged=private.os is os,hold=private.CredentialFileHold)

def target_case(kind):
    from monitor import issue_tracker_online_target as target
    from monitor import issue_tracker_credential_shape as private
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_state_owner as state
    root=original.new_root();project=root/'project';project.mkdir(mode=0o755);project.chmod(0o755)
    publication=project/'99-output-monitor';publication.mkdir(mode=0o755);publication.chmod(0o755)
    config=project/'01-global.yaml';config.write_bytes(original.GLOBAL);config.chmod(0o644)
    state.initialize_tracker_state(project,publication,initialized_at='2026-09-25T00:00:00Z',acquisition_id='acquisition-0')
    error,cause=close_error(kind)
    body_completed=False;bound=None;token=None;observed_k=None
    private_io=target_io=local_io=None;seen=[];profile_errors=[]
    inner=target._hold_current_project_online_target.__wrapped__;previous=sys.getprofile()
    def profile(frame,event,arg):
        if previous is not None:previous(frame,event,arg)
        if (event=='return' and frame.f_code is inner.__code__
                and frame.f_globals is target.__dict__ and frame.f_locals.get('key') is not None and not seen):
            try:
                fd=frame.f_locals['fd']
                target_io.arm((fd,*frame.f_locals['project_fds']),fault_fd=fd,fault_error=error)
                seen.append(True)
            except BaseException as problem:profile_errors.append(type(problem).__name__)
    def operation():
        nonlocal body_completed,bound,token,observed_k,private_io,target_io,local_io
        with original.existing_io.scoped_fixture(root,private),original.existing_io.scoped_fixture(root,target):
            private_io=original.KnownCloseIO(private.os,lambda:target._HELD_CURRENT_TARGET.get() is None)
            target_io=original.KnownCloseIO(target.os,lambda:target._HELD_CURRENT_TARGET.get() is None)
            with ExitStack() as patches:
                patches.enter_context(mock.patch.object(private,'os',private_io))
                patches.enter_context(mock.patch.object(target,'os',target_io))
                with state.tracker_writer(project,publication) as token:
                    owner=local._owner(token);k=state.current_k(token);observed_k=(k.revision,k.k)
                    local_io=original.KnownCloseIO(local.os,lambda:token not in local._ACTIVE,record_opens=False)
                    local_io.arm((owner.project_fd,owner.root_fd,owner.publication_fd,owner.lock_fd))
                    patches.enter_context(mock.patch.object(local,'os',original.TargetCloseRoute(local_io,target_io)))
                    sys.setprofile(profile)
                    try:
                        with target._hold_current_project_online_target(token) as bound:
                            private_io.arm(private_io.opened)
                            target._require_held_current_project_online_target(token,bound)
                            local._owner(token)
                            body_completed=True  # NO body raise or hidden error sentinel.
                    finally:sys.setprofile(previous)
    _unused,outgoing=original.capture(operation)
    _unused,revoked_error=original.capture(lambda:target._require_held_current_project_online_target(token,bound))
    return dict(root=root,error=outgoing,close_error=error,close_cause=cause,
      body_completed=body_completed,binding=bound,observed_k=observed_k,
      profile_seen=len(seen),profile_errors=profile_errors,
      private=private_io.snapshot() if private_io else None,target=target_io.snapshot() if target_io else None,
      local=local_io.snapshot() if local_io else None,target_expected_slots=1+len(project.parts),
      target_revoked=target._HELD_CURRENT_TARGET.get() is None,local_revoked=token not in local._ACTIVE,
      revoked_error=revoked_error,hold=target.OnlineTargetHold,
      shared_os_unchanged=private.os is target.os is local.os is os,
      config_unchanged=config.read_bytes()==original.GLOBAL)

def diagnostic(holder,kind,outcome):
    print('PRIVATE_INPUT_CLOSE_FACTS='+json.dumps(dict(holder=holder,kind=kind,
      body_completed=outcome['body_completed'],error_type=type(outcome['error']).__name__ if outcome['error'] is not None else None,
      original_close_error=outcome['error'] is outcome['close_error'],
      original_close_cause=outcome['error'] is not None and outcome['error'].__cause__ is outcome['close_cause'],
      private=outcome.get('private'),target=outcome.get('target'),local=outcome.get('local'),
      target_revoked=outcome.get('target_revoked'),local_revoked=outcome.get('local_revoked')),
      sort_keys=True),flush=True)

def run_owned(case,holder,kind):
    if (holder,kind) not in PAIRS:raise AssertionError('unknown close regression child')
    process=subprocess.Popen((sys.executable,'-B','-c',CHILD_PROGRAM,str(ROOT),holder,kind),
      cwd=str(ROOT),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      start_new_session=True,close_fds=True,env={'LC_ALL':'C','HOME':os.path.expanduser('~')})
    try:
        try:output,errors=process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            if process.poll() is None:process.kill()
            process.communicate(timeout=5)
            case.fail('OWNED_PRIVATE_INPUT_CLOSE_TIMEOUT_UNKNOWN')
        case.assertLessEqual(len(output)+len(errors),131072)
        print(output.decode('utf-8','replace'),end='',flush=True)
        if process.returncode!=0:print(errors.decode('utf-8','replace'),end='',flush=True)
        case.assertEqual(0,process.returncode,'OWNED_PRIVATE_INPUT_CLOSE_ASSERTIONS_FAILED')
        marker=('PRIVATE_INPUT_CLOSE_CHILD_END='+holder+':'+kind+';success=True\n').encode()
        case.assertEqual(1,output.count(marker))
    finally:
        for stream in (process.stdout,process.stderr):stream.close()
