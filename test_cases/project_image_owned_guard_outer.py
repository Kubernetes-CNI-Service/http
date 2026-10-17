"""Finite PROJECT-IMAGE test seam; fake-direct tested, no real-child proof.

Only delegate waits are deadline-clamped. Selector/kill/OS calls and uncertain
cleanup are not a universal wall-clock bound or permission to execute a guard.
"""
import contextlib
import hashlib
import inspect
import json
import posixpath
import signal
import socket
import sys
import threading
import types
import _thread
import os
import stat
import subprocess
import time

class GuardOuterHold(RuntimeError):
    pass

FACTS = []
HELD = []
_RUNTIME_INTERPRETER = sys.executable  # Original runtime, not caller argv or a later sys alias.


def _exact_launch(argv, env, archive_fd, archive_key):
    python = _RUNTIME_INTERPRETER
    if (type(python) is not str or not posixpath.isabs(python)
            or posixpath.normpath(python) != python or '\0' in python):
        raise GuardOuterHold('original runtime interpreter identity required')
    bootstrap_sha = 'cd1802da572565c837228ca21a294584d073369d2e4eacf34579f1c0509db120'
    guard_sha = '46af60b5b4ed3c3df6e3ad0f0a0b1fee5c8af60ceea8c6e60e08de5580481256'
    if (len(argv) != 18 or any(type(s) is not str for s in argv)
            or argv[:5] != [python, '-I', '-S', '-B', '-c']
            or hashlib.sha256(argv[5].encode()).hexdigest() != bootstrap_sha
            or set(env) != {'PATH','TMPDIR','PYTHONDONTWRITEBYTECODE','HTTP_TEST_GUARD_BINDING'}
            or any(type(v) is not str for v in env.values())):
        raise GuardOuterHold('exact isolated child activation required')
    try:
        binding = json.loads(env['HTTP_TEST_GUARD_BINDING'])
    except Exception:
        raise GuardOuterHold('fixed child binding required')
    fields = {'parent','root','directory','bootstrap_sha256','guard_sha256',
              'archive_key','domain_argv','phase'}
    if (type(binding) is not dict or set(binding) != fields
            or env['HTTP_TEST_GUARD_BINDING'] != json.dumps(binding, sort_keys=True)
            or binding['phase'] not in ('OBSERVE_DEFAULTS','OWNED_PARAMETERS')
            or binding['bootstrap_sha256'] != bootstrap_sha or binding['guard_sha256'] != guard_sha
            or binding['archive_key'] != [str(n) for n in archive_key]
            or binding['domain_argv'] != argv[6:]):
        raise GuardOuterHold('unreceived child binding or borrowed archive')
    parent, root, cwd = (binding[n] for n in ('parent','root','directory'))
    if (any(type(p) is not str or not p.startswith('/') or '\0' in p
            or posixpath.normpath(p) != p for p in (parent,root,cwd))
            or root != parent + '/live' or posixpath.dirname(cwd) != parent
            or not posixpath.basename(cwd).startswith('owned-native-guard.')
            or posixpath.basename(cwd) == 'owned-native-guard.'):
        raise GuardOuterHold('exact owned child path declarations required')
    domain = argv[6:]
    if (domain[:8] != ['--lock', root+'/.deployment.lock', '--root', root,
                       '--runtime','native','--archive-fd',str(archive_fd)]
            or domain[8] != '--archive-sha256'
            or domain[10] != '--source-manifest-sha256'
            or any(len(value) != 64 or any(c not in '0123456789abcdef' for c in value)
                   for value in (domain[9],domain[11]))
            or env['PATH'] != cwd+'/bin' or env['TMPDIR'] != cwd+'/tmp'
            or env['PYTHONDONTWRITEBYTECODE'] != '1'):
        raise GuardOuterHold('original absolute domain or exact environment changed')
    return tuple(argv), dict(env), cwd

def run_project_image_guard(original_guard, argv, *, env, archive_fd, timeout=5):
    if type(archive_fd) is not int or type(argv) is not list or type(env) is not dict:
        raise GuardOuterHold('fixed guard capability required')
    if type(timeout) not in (int, float) or timeout != 5:
        raise GuardOuterHold('fixed five-second guard API required')
    if getattr(subprocess, '_active', None) != []:
        raise GuardOuterHold('foreign pending Popen objects')
    clock = time.monotonic
    deadline = clock() + 20.0
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    key = lambda value: tuple(getattr(value, name) for name in fields)
    physical = lambda value: (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode),
                              value.st_uid, value.st_gid)
    archive_before = os.fstat(archive_fd)
    if not stat.S_ISREG(archive_before.st_mode) or archive_before.st_nlink != 1:
        raise GuardOuterHold('borrowed archive is not one original regular file')
    archive_key = key(archive_before)
    launch_argv, launch_env, launch_cwd = _exact_launch(argv, env, archive_fd, archive_key)
    P = subprocess.Popen
    original_init, original_wait, original_kill = P.__init__, P.wait, P.kill
    original_poll, original_close = P._internal_poll, os.close
    row = dict(object=None, pid=None, streams=[], unknown=[], waits=[], signals=[],
               cleanup_errors=[], assisted=[], restored=False, local_ok=False)
    HELD.append(row)  # Strong reference retained even when identity is UNKNOWN.
    patches = []; primary = result = None; errors = []
    def choose(body, cleanup):
        if body is not None and not isinstance(body, Exception): return body
        return next((e for e in cleanup if not isinstance(e, Exception)),
                    body if body is not None else (cleanup[0] if cleanup else None))
    def patch(obj, name, value):
        own = name in vars(obj); before = inspect.getattr_static(obj, name)
        patches.append((obj, name, own, before)); setattr(obj, name, value)
    def owned(process):
        if process is not row['object']:
            raise GuardOuterHold('foreign Popen object')
        if (row['unknown'] or type(row['pid']) is not int or row['pid'] <= 0
                or getattr(process, 'pid', None) != row['pid']
                or getattr(process, '_child_created', None) is not True):
            row['unknown'].append('owned child identity UNKNOWN')
            raise GuardOuterHold('owned child identity UNKNOWN')
    def init(process, *args, **kwargs):
        if (row['object'] is not None or type(process) is not P or len(args) != 1
                or tuple(args[0]) != launch_argv or kwargs.get('env') != launch_env
                or kwargs.get('pass_fds') != (archive_fd,)
                or kwargs.get('stdin') != subprocess.DEVNULL
                or kwargs.get('stdout') != subprocess.PIPE or kwargs.get('stderr') != subprocess.PIPE
                or kwargs.get('shell') is not False or kwargs.get('bufsize') != 0
                or set(kwargs) - {'env','pass_fds','stdin','stdout','stderr','shell','bufsize'}):
            raise GuardOuterHold('unadmitted guard child construction')
        if key(os.fstat(archive_fd)) != archive_key:
            raise GuardOuterHold('borrowed archive changed before construction')
        row['object'] = process; body = None; observations = []
        # Only child cwd changes: parent cwd and original absolute domain argv remain intact.
        try: original_init(process, *args, **kwargs, cwd=launch_cwd)
        except BaseException as error: body = error
        try:
            row['pid'] = process.pid
            owned(process)
            for role in ('stdout', 'stderr'):
                stream = getattr(process, role); fd = stream.fileno()
                if fd == archive_fd: raise GuardOuterHold('archive adopted as owned pipe')
                row['streams'].append(dict(object=stream, fd=fd, key=physical(os.fstat(fd)), role=role))
        except BaseException as error:
            row['unknown'].append('post-init metadata UNKNOWN'); observations.append(error)
        selected = choose(body, observations)
        if selected is not None: raise selected
    def wait(process, timeout=None):
        owned(process)
        remaining = max(0.0, deadline - clock())
        if timeout is not None and (type(timeout) not in (int, float) or not 0 <= timeout < float('inf')):
            raise GuardOuterHold('unknown wait limit')
        limit = remaining if timeout is None else min(timeout, remaining)
        if remaining <= 0 and process.returncode is None:
            raise GuardOuterHold('wait deadline exhausted; completion UNKNOWN')
        row['waits'].append(limit)
        try: return original_wait(process, timeout=limit)
        except subprocess.TimeoutExpired: raise
        except BaseException:
            row['unknown'].append('interrupted wait outcome UNKNOWN'); raise
    def kill(process):
        owned(process)
        if process.returncode is not None: return None
        row['signals'].append(row['pid'])
        try: return original_kill(process)
        except BaseException:
            row['unknown'].append('signal outcome UNKNOWN'); raise
    def poll(process, *args, **kwargs):
        owned(process)
        if args or kwargs: raise GuardOuterHold('unknown poll arguments')
        try: return original_poll(process)
        except BaseException:
            row['unknown'].append('poll outcome UNKNOWN'); raise
    def close(fd):
        if fd == archive_fd: raise GuardOuterHold('borrowed archive must not be closed')
        return original_close(fd)  # Existing installed FS authority, never a new FD adoption.
    try:
        for obj, name, value in ((P,'__init__',init),(P,'wait',wait),(P,'kill',kill),
                                  (P,'_internal_poll',poll),(os,'close',close)):
            patch(obj, name, value)
        result = original_guard(argv, env=env, archive_fd=archive_fd,
                                timeout=min(timeout, max(0.0, deadline-clock())))
    except BaseException as error: primary = error
    finally:
        process = row['object']
        if process is not None:
            try:
                owned(process)
                if process.returncode is None:
                    row['assisted'].append('owned child cleanup')
                    try: kill(process)
                    except BaseException as error: errors.append(error)
                    try: wait(process, timeout=max(0.0, deadline-clock()))
                    except BaseException as error: errors.append(error)
            except BaseException as error: errors.append(error)
        for item in row['streams']:
            try:
                stream = item['object']
                if stream.closed: continue  # No probe of an already closed/reused numeric slot.
                if stream.fileno() != item['fd'] or physical(os.fstat(item['fd'])) != item['key']:
                    raise GuardOuterHold('original pipe identity UNKNOWN')
                row['assisted'].append(item['role']); stream.close()
            except BaseException as error: errors.append(error)
        try:
            if key(os.fstat(archive_fd)) != archive_key:
                raise GuardOuterHold('borrowed archive changed')
        except BaseException as error: errors.append(error)
        for obj, name, own, before in reversed(patches):
            try:
                if own: setattr(obj, name, before)
                else: delattr(obj, name)
            except BaseException as error: errors.append(error)
        try:
            row['restored'] = all(inspect.getattr_static(o,n) is v and (n in vars(o))==own
                                  for o,n,own,v in patches)
            row['local_ok'] = (primary is None and not errors and row['restored']
                and not row['unknown'] and not row['assisted'] and process is not None
                and process.returncode is not None and all(s['object'].closed for s in row['streams'])
                and clock() < deadline)
        except BaseException as error: errors.append(error)
        row['cleanup_errors'] = [type(e).__name__ for e in errors]
        FACTS.append({k:row[k] for k in ('pid','unknown','waits','signals','assisted','cleanup_errors','restored','local_ok')})
    selected = choose(primary, errors)
    if selected is not None:
        try:
            selected.project_image_guard_cleanup_errors = tuple(errors)
        except BaseException as attachment:
            selected = choose(selected, [attachment])
        raise selected  # Preserve the selected original object/cause, never raise-from.
    if not row['local_ok']:
        raise GuardOuterHold('guard completion/cleanup not proved')
    return result  # Exact original result, not a fabricated CompletedProcess.

SOURCE_FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')

PARENT_FACTS = []

@contextlib.contextmanager
def parent_launch_boundary(filesystem):
    """One original helper→guard→Popen; Python API gate, not a C sandbox."""
    P = subprocess.Popen
    methods = ('__init__','_execute_child','wait','kill',
               '_internal_poll','_try_wait','send_signal','terminate')
    real = {n:inspect.getattr_static(P,n) for n in methods}
    outer_init = [co for co in run_project_image_guard.__code__.co_consts
                  if isinstance(co,types.CodeType) and co.co_name=='init']
    if len(outer_init)!=1:raise GuardOuterHold('one original outer init required')
    state=dict(active=True,phase='DEFAULT',helper=None,used=False,child=None,
               created=0,initialized=0,executed=0,audits=0,signalling=False,
               waiting=False,attempts=[],audit_registered=False,reaped=[],wait_errors=[])
    primary=None;errors=[];snapshots=[]
    def choose(body,tail):
        if body is not None and not isinstance(body,Exception):return body
        return next((e for e in tail if not isinstance(e,Exception)),
                    body if body is not None else (tail[0] if tail else None))
    def refuse(label):
        state['attempts'].append(label);raise GuardOuterHold(label)
    def denied(*a,**k):refuse('DEFAULT capability denied')
    def owned(process):
        if (process is not state['child'] or len(HELD)!=state.get('held_index',-1)+1):
            refuse('unowned process object')
        row=HELD[state['held_index']]
        if (row['object'] is not process or row['unknown'] or type(row['pid']) is not int
                or row['pid']<=0 or getattr(process,'pid',None)!=row['pid']
                or getattr(process,'_child_created',None) is not True):
            refuse('owned process identity UNKNOWN')
        return row['pid']
    def arguments(args,kw,cwd):
        names={'stdin','stdout','stderr','shell','bufsize','env','pass_fds'}
        if cwd:names.add('cwd')
        if (len(args)!=1 or type(args[0]) is not list or tuple(args[0])!=state['argv']
                or set(kw)!=names or kw['env']!=state['env']
                or kw['pass_fds']!=(state['archive_fd'],) or kw['stdin']!=subprocess.DEVNULL
                or kw['stdout']!=subprocess.PIPE or kw['stderr']!=subprocess.PIPE
                or kw['shell'] is not False or kw['bufsize']!=0
                or (cwd and kw['cwd']!=state['cwd'])
                or tuple(getattr(os.fstat(state['archive_fd']),n) for n in SOURCE_FIELDS)!=state['archive_key']):
            refuse('unbound constructor arguments')
    def init(process,*args,**kw):
        frame=sys._getframe(1)
        if (type(process) is not P or state['phase']!='ARM' or state['child'] is not None
                or state['created'] or state['initialized']
                or frame.f_code is not outer_init[0]
                or frame.f_locals.get('process') is not process
                or frame.f_back is None or frame.f_back.f_code is not state['guard'].__code__):
            refuse('foreign or repeated original constructor delegate')
        # Do not touch P.__new__: restoring its descriptor does not restore
        # CP39's allocator slot behavior. Retain exact self before native init.
        state['child']=process;state['created']=1
        arguments(args,kw,True);state['initialized']=1
        return real['__init__'](process,*args,**kw)
    def execute(process,*args,**kw):
        frame=sys._getframe(1)
        if (process is not state['child'] or state['executed']
                or frame.f_code is not real['__init__'].__code__
                or frame.f_locals.get('self') is not process):
            refuse('foreign original execute chain')
        state['executed']=1
        return real['_execute_child'](process,*args,**kw)
    def send(process,sig):
        frame=sys._getframe(1)
        if frame.f_code is not real['kill'].__code__ or sig!=signal.SIGKILL:
            refuse('unbound signal method')
        owned(process)
        return real['send_signal'](process,sig)
    def kill(pid,sig):
        frame=sys._getframe(1)
        if (frame.f_code is not real['send_signal'].__code__
                or frame.f_locals.get('self') is not state['child']
                or pid!=owned(state['child']) or sig!=signal.SIGKILL):
            refuse('unbound PID signal')
        state['signalling']=True
        try:return baseline[(id(os),'kill')][3](pid,sig)
        finally:state['signalling']=False
    def waitpid(pid,flags):
        frame=sys._getframe(1)
        origin=('_try_wait' if frame.f_code is real['_try_wait'].__code__ else
                '_internal_poll' if frame.f_code is real['_internal_poll'].__code__ else None)
        if (origin is None or frame.f_locals.get('self') is not state['child']
                or pid!=owned(state['child']) or flags not in (0,os.WNOHANG)):
            refuse('unbound PID wait')
        state['waiting']=True
        try:
            value=baseline[(id(os),'waitpid')][3](pid,flags)
        except BaseException as error:
            state['wait_errors'].append(type(error).__name__);raise
        finally:state['waiting']=False
        if (type(value) is not tuple or len(value)!=2
                or any(type(n) is not int for n in value) or value[0] not in (0,pid)):
            refuse('original waitpid result UNKNOWN')
        if value[0]==pid:
            if state['reaped']:refuse('repeated original waitpid receipt')
            state['reaped'].append(dict(origin=origin,pid=value[0],status=value[1]))
        return value
    def original_poll(process,*args,**kw):
        owned(process)
        if args or kw:refuse('unknown original poll arguments')
        # CP39's captured default otherwise bypasses patched os.waitpid.
        return real['_internal_poll'](process,_waitpid=waitpid)
    def audit(event,args):
        if not state['active']:return  # hook remains registered but inactive
        if event=='subprocess.Popen':
            frame=sys._getframe(1)
            if (state['phase']!='ARM' or state['audits'] or state['executed']!=1
                    or frame.f_code is not real['_execute_child'].__code__
                    or frame.f_locals.get('self') is not state['child']
                    or len(args)!=4 or args[0]!=state['argv'][0]
                    or tuple(args[1])!=state['argv'] or args[2]!=state['cwd']
                    or args[3]!=state['env']):
                refuse('unbound Popen audit')
            state['audits']=1;return
        if event=='os.kill' and state['signalling'] and args==(owned(state['child']),signal.SIGKILL):
            return
        if event=='os.waitpid' and state['waiting']:return
        if event.startswith(('socket.','os.exec')) or event in (
                'os.system','os.fork','os.forkpty','os.posix_spawn','os.posix_spawnp',
                'os.kill','os.killpg','os.waitpid','_thread.start_new_thread'):
            refuse('DEFAULT audit denied')
    required=((P,methods),(subprocess,('run','call','check_call','check_output')),
        (os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','kill','killpg','waitpid')),
        (socket,('socket','socketpair')),(threading.Thread,('__init__','start')),
        (threading.Timer,('__init__','start')),(_thread,('start_new_thread',)),
        (signal,('signal','alarm','setitimer')))
    optional=((os,('execl','execle','execlp','execlpe','execvp','execvpe',
                  'spawnl','spawnle','spawnlp','spawnlpe','spawnv','spawnve','spawnvp','spawnvpe',
                  'wait','wait3','wait4','waitid','_exit')),
        (threading,('_start_new_thread',)),(_thread,('start_new','interrupt_main','exit')),
        (signal,('raise_signal','pthread_kill','sigwait','sigwaitinfo','sigtimedwait','pause')))
    presence=[]
    for mandatory,groups in ((True,required),(False,optional)):
        for obj,names in groups:
            for name in names:
                present=hasattr(obj,name);presence.append((obj,name,present))
                if mandatory and not present:raise GuardOuterHold('required capability missing:'+name)
                if present and not any(o is obj and n==name for o,n,_,_ in snapshots):
                    snapshots.append((obj,name,name in vars(obj),inspect.getattr_static(obj,name)))
    baseline={(id(o),n):(o,n,own,value) for o,n,own,value in snapshots}
    def restore(rows):
        for obj,name,own,value in reversed(rows):
            try:
                if own:setattr(obj,name,value)
                else:delattr(obj,name)
            except BaseException as error:errors.append(error)
    def bind_helper(code):
        if state['helper'] is not None or state['used'] or type(code) is not types.CodeType:
            refuse('helper binding is not single-use original code')
        state['helper']=code
    def admit(original_guard,argv,*,env,archive_fd,timeout=5):
        frame=sys._getframe(1)
        if (state['used'] or state['attempts'] or frame.f_code is not state['helper']
                or frame.f_locals.get('original_guard') is not original_guard
                or frame.f_locals.get('activated') is not argv
                or frame.f_locals.get('environment') is not env
                or frame.f_locals.get('archive_fd')!=archive_fd or timeout!=5):
            refuse('unbound or repeated helper ARM')
        archive=os.fstat(archive_fd)
        if not stat.S_ISREG(archive.st_mode) or archive.st_nlink!=1:
            refuse('borrowed archive original type')
        archive_key=tuple(getattr(archive,n) for n in SOURCE_FIELDS)
        launch,environment,cwd=_exact_launch(argv,env,archive_fd,archive_key)
        directory=filesystem._fd(frame.f_locals.get('directory_fd'))
        snapshot=filesystem._fd(archive_fd,named=False)
        if (not directory['directory'] or directory['path']!=cwd or snapshot['directory']
                or not filesystem._inside(snapshot['path'])):
            refuse('held directory/archive authority missing')
        state.update(used=True,phase='ARM',argv=launch,env=environment,cwd=cwd,
                     archive_fd=archive_fd,archive_key=archive_key,guard=original_guard,held_index=len(HELD))
        temporary=[];body=None;result=None
        changes=((P,'__init__',init),(P,'_execute_child',execute),
            (P,'wait',real['wait']),(P,'kill',real['kill']),
            (P,'_internal_poll',original_poll),(P,'_try_wait',real['_try_wait']),
            (P,'send_signal',send),(os,'kill',kill),(os,'waitpid',waitpid))
        try:
            for obj,name,value in changes:
                temporary.append((obj,name,name in vars(obj),inspect.getattr_static(obj,name)))
                setattr(obj,name,value)
            result=run_project_image_guard(original_guard,argv,env=env,archive_fd=archive_fd,timeout=timeout)
            if any(state[n]!=1 for n in ('created','initialized','executed','audits')):
                refuse('one original child/audit not proved')
            if len(state['reaped'])!=1 or state['wait_errors']:
                refuse('kernel waitpid receipt missing or UNKNOWN')
        except BaseException as error:body=error
        finally:
            restore(temporary);state['phase']='DEFAULT'
        selected=choose(body,errors)
        if selected is not None:raise selected
        return result
    admit.bind_helper=bind_helper
    try:
        sys.addaudithook(audit);state['audit_registered']=True
        for obj,name,_,_ in snapshots:setattr(obj,name,denied)
        yield admit
        if not state['used'] or state['attempts']:raise GuardOuterHold('one clean ARM not proved')
    except BaseException as error:primary=error
    finally:
        state['active']=False
        restore(snapshots)
        try:
            restored=all(hasattr(o,n)==present for o,n,present in presence) and all(
                (n in vars(o))==own and inspect.getattr_static(o,n) is value for o,n,own,value in snapshots)
            if not restored:errors.append(GuardOuterHold('parent bindings not restored'))
            PARENT_FACTS.append(dict(used=state['used'],created=state['created'],
                initialized=state['initialized'],executed=state['executed'],audits=state['audits'],
                attempts=list(state['attempts']),reaped=list(state['reaped']),
                wait_errors=list(state['wait_errors']),audit_registered=state['audit_registered'],
                audit_active=state['active'],restored=restored,
                presence=[(n,present) for _,n,present in presence],
                cleanup_errors=[type(e).__name__ for e in errors],
                local_ok=(primary is None and not errors and restored and state['used']
                    and not state['attempts'] and len(state['reaped'])==1 and not state['wait_errors']
                    and all(state[n]==1 for n in ('created','initialized','executed','audits'))),
                actual_C_background_proof=False))
        except BaseException as error:errors.append(error)
    selected=choose(primary,errors)
    if selected is not None:raise selected

class HeldGuardInputs:
    """Borrow two original fixture FDs without adopting, writing or closing them.

    This is the portable two-input adapter for parent_launch_boundary, not a
    filesystem sandbox. Archive provenance is the original installer's staged
    snapshot pathname; the helper must obtain it from that original context.
    """
    def __init__(self, *, parent, directory, directory_fd, archive, archive_fd):
        parent, directory, archive = (os.fspath(p) for p in (parent, directory, archive))
        if any(type(p) is not str or not posixpath.isabs(p)
               or posixpath.normpath(p) != p or '\0' in p
               or os.path.realpath(p) != p for p in (parent, directory, archive)):
            raise GuardOuterHold('canonical original input paths required')
        if (posixpath.dirname(directory) != parent
                or not posixpath.basename(directory).startswith('owned-native-guard.')
                or posixpath.basename(directory) == 'owned-native-guard.'
                or archive == parent or not archive.startswith(parent + '/')):
            raise GuardOuterHold('original input namespace differs')
        if (type(directory_fd) is not int or type(archive_fd) is not int
                or directory_fd < 0 or archive_fd < 0 or directory_fd == archive_fd):
            raise GuardOuterHold('two distinct original borrowed descriptors required')
        self.parent = parent
        parent_stat = os.lstat(parent)
        if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.geteuid()
                or stat.S_IMODE(parent_stat.st_mode) != 0o700):
            raise GuardOuterHold('owned private original parent required')
        self.parent_key = self._parent_key(parent_stat)
        self.records = {}
        for fd, path, directory_role in ((directory_fd, directory, True), (archive_fd, archive, False)):
            named = os.lstat(path)
            held = os.fstat(fd)
            key = self._key(named)
            if self._key(held) != key:
                raise GuardOuterHold('named input is not the held original')
            valid_type = stat.S_ISDIR(held.st_mode) if directory_role else stat.S_ISREG(held.st_mode)
            if (not valid_type or held.st_uid != os.geteuid()
                    or stat.S_IMODE(held.st_mode) != (0o700 if directory_role else 0o600)
                    or not directory_role and held.st_nlink != 1):
                raise GuardOuterHold('original borrowed input role or metadata differs')
            self.records[fd] = dict(path=path, directory=directory_role, key=key)
        for fd in self.records:
            self._fd(fd)

    @staticmethod
    def _key(value):
        return tuple(getattr(value, name) for name in SOURCE_FIELDS)

    @staticmethod
    def _parent_key(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)

    def _fd(self, fd, *, mutation=False, named=True):
        if type(fd) is not int or fd not in self.records or mutation:
            raise GuardOuterHold('unknown or mutable borrowed input authority')
        record = self.records[fd]
        try:
            if (self._parent_key(os.lstat(self.parent)) != self.parent_key
                    or os.path.realpath(self.parent) != self.parent
                    or os.path.realpath(record['path']) != record['path']
                    or self._key(os.fstat(fd)) != record['key']
                    or self._key(os.lstat(record['path'])) != record['key']):
                raise GuardOuterHold('borrowed input original changed')
        except OSError as error:
            raise GuardOuterHold('borrowed input original unavailable') from error
        # named=False never weakens snapshot original checks in this adapter.
        return dict(directory=record['directory'], path=record['path'])

    def _inside(self, path):
        return type(path) is str and (path == self.parent or path.startswith(self.parent + '/'))

def borrowed_snapshot_path(manager, original_snapshot, archive_fd, parent):
    """Receive the actual original installer's live staged-snapshot yield.

    No pathname is reconstructed and no borrowed FD is closed or adopted.
    The original context remains responsible for post-yield verification and
    its cleanup. This function gives no independent write permission.
    """
    wrapped = getattr(original_snapshot, '__wrapped__', None)
    if (type(manager) is not contextlib._GeneratorContextManager
            or type(wrapped) is not types.FunctionType
            or type(archive_fd) is not int or archive_fd < 0):
        raise GuardOuterHold('original staged snapshot context required')
    generator = manager.gen
    frame = generator.gi_frame if type(generator) is types.GeneratorType else None
    if (frame is None or generator.gi_running
            or frame.f_code is not wrapped.__code__ or frame.f_globals is not wrapped.__globals__
            or type(frame.f_locals.get('output')) is not int
            or frame.f_locals['output'] != archive_fd):
        raise GuardOuterHold('original active snapshot yield differs')
    destination = frame.f_locals.get('destination')
    try:
        path, parent = os.fspath(destination), os.fspath(parent)
    except TypeError as error:
        raise GuardOuterHold('original snapshot destination missing') from error
    if (type(path) is not str or type(parent) is not str
            or not posixpath.isabs(path) or not posixpath.isabs(parent)
            or posixpath.normpath(path) != path or posixpath.normpath(parent) != parent
            or '\0' in path or '\0' in parent or not path.startswith(parent + '/')
            or os.path.realpath(path) != path or os.path.realpath(parent) != parent):
        raise GuardOuterHold('original snapshot escaped private fixture parent')
    first, held, last = os.lstat(path), os.fstat(archive_fd), os.lstat(path)
    if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
            or held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) != 0o600
            or HeldGuardInputs._key(first) != HeldGuardInputs._key(held)
            or HeldGuardInputs._key(last) != HeldGuardInputs._key(held)):
        raise GuardOuterHold('original snapshot path and borrowed descriptor differ')
    return path
