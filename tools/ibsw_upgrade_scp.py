"""SCP source/receiver library; main operational entry remains HTTP-only.

Nonempty execution payloads are refused until live package ownership, reliable
request/content evidence and SCP-only manager ACK are integrated and verified.
Public receiver fields are DATA, not an upgrade permission. No keys/services
are installed or changed. Existing signed identity/canary/postchecks still apply.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import stat


ERRORS = {
    'SCP_SOURCE_REQUIRED': 'SCP requires a management-server SSH address, username and independently trusted source host key.',
    'SCP_CONTENT_BINDING_REQUIRED': 'SCP execution is unavailable until original package ownership and content binding are implemented; no execution payload was produced.',
    'SCP_SOURCE_ARGUMENTS': 'Invalid SCP source address, username, port or bounded credential; no transfer started.',
    'SCP_SOURCE_TRUST': 'SCP source needs an exact trusted entry (literal or hashed) in --scp-known-hosts; verify its fingerprint independently. No TOFU or disabled host-key checks.',
    'SCP_SOURCE_CHANGED': 'The original SCP trust source changed during this run; stop the batch and inspect the source.',
    'SCP_SOURCE_PREFLIGHT_FAILED': 'The switch could not verify SSH access to the SCP source. Check source routing, SSH port, host fingerprint and source credentials. No installer was dispatched for this request.',
    'SCP_SECRET_CHANNEL_FAILED': 'The SCP credential-only SSH stdin channel did not complete; the original request is retained and is not replayed.',
}


class ScpHold(ValueError):
    def __init__(self, reason_code):
        self.reason_code = reason_code if reason_code in ERRORS else 'SCP_SOURCE_ARGUMENTS'
        super().__init__(ERRORS[self.reason_code])


def _read_trust(path):
    fd = None
    try:
        path = Path(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        item = os.fstat(fd)
        if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_mode & 0o022
                or not 0 < item.st_size <= 1024*1024):
            raise ScpHold('SCP_SOURCE_TRUST')
        value = os.read(fd, item.st_size+1)
        after = os.fstat(fd)
        named = os.lstat(path)
        def facts(row):
            return (row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_ctime_ns,row.st_mode)
        if len(value)!=item.st_size or facts(item)!=facts(after) or facts(item)!=facts(named):
            raise ScpHold('SCP_SOURCE_TRUST')
        return value, (*facts(item),hashlib.sha256(value).hexdigest())
    except ScpHold:
        raise
    except (OSError,ValueError,TypeError):
        raise ScpHold('SCP_SOURCE_TRUST') from None
    finally:
        if fd is not None: os.close(fd)


@dataclass(frozen=True)
class ScpSource:
    host: str
    user: str
    port: int
    known_hosts_path: Path
    host_keys: bytes
    password: str = field(repr=False)
    _identity: tuple = field(repr=False)

    def verify(self):
        try:
            _value, identity = _read_trust(self.known_hosts_path)
            if identity != self._identity: raise ScpHold('SCP_SOURCE_CHANGED')
        except ScpHold:
            raise ScpHold('SCP_SOURCE_CHANGED') from None

    def public_document(self):
        keys=[]
        for line in self.host_keys.splitlines():
            wire=base64.b64decode(line.split()[2],validate=True)
            keys.append('SHA256:'+base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b'=').decode())
        return dict(method='scp',direction='IB_SWITCH_PULLS_FROM_MANAGEMENT_SERVER',
                    host=self.host,user=self.user,port=self.port,host_key_fingerprints=keys,
                    credentials_persisted=False)


def source_from_known_hosts(host,user,port,path,password):
    try:
        host=str(ipaddress.IPv4Address(host))
        if (not isinstance(user,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9._-]{0,63}',user)
                or type(port) is not int or not 1<=port<=65535 or type(password) is not str
                or len(password.encode())>4096 or any(ord(c)<32 or ord(c)==127 for c in password)):
            raise ValueError()
    except (ValueError,TypeError,ipaddress.AddressValueError):
        raise ScpHold('SCP_SOURCE_ARGUMENTS') from None
    value,identity=_read_trust(path)
    from ibsw_upgrade_driver import _known_host_endpoint_matches
    from ssh_key_preparation import public_key_identity_bytes
    endpoint=host if port==22 else '['+host+']:'+str(port)
    endpoints={endpoint,'['+host+']:22'} if port==22 else {endpoint}
    found=set()
    try:
        for line in value.splitlines():
            if not line.strip() or line.lstrip().startswith(b'#'): continue
            fields=line.split()
            if fields[0].startswith(b'@'):
                if len(fields)>1 and _known_host_endpoint_matches(fields[1],endpoints): raise ValueError()
                continue
            if not _known_host_endpoint_matches(fields[0],endpoints): continue
            if len(fields)<3: raise ValueError()
            public_key_identity_bytes(fields[1]+b' '+fields[2]+b'\n')
            found.add(endpoint.encode()+b' '+fields[1]+b' '+fields[2]+b'\n')
        if not found: raise ValueError()
    except (ValueError,UnicodeError):
        raise ScpHold('SCP_SOURCE_TRUST') from None
    return ScpSource(host,user,port,Path(path),b''.join(sorted(found)),password,identity)


def launch_payload(source,packages=()):
    if type(source) is not ScpSource: raise ScpHold('SCP_SOURCE_REQUIRED')
    verify_source_shared(source)
    # Only an empty package selection may form the existing probe context.
    # No public DATA dictionary or path/size tuple supplies live package ownership.
    for _package in packages:
        raise ScpHold('SCP_CONTENT_BINDING_REQUIRED')
    paths={}
    payload=(json.dumps(dict(host=source.host,user=source.user,port=source.port,
        host_keys=source.host_keys.decode('ascii'),password=source.password,
        paths=paths,timeout_seconds=600),separators=(',',':'))+'\n').encode()
    if len(payload)>65536: raise ScpHold('SCP_SOURCE_ARGUMENTS')
    return payload


# Executed on the switch, using only its standard Python and OpenSSH programs.
# PTY output is never reflected: a remote password prompt/banner can contain a
# secret or terminal control bytes. Only fixed/numeric diagnostics are emitted.
_REMOTE_HELPER = r'''import errno,hashlib,json,os,pty,re,select,shlex,signal,stat,sys,tempfile,time,termios
SSH = '/usr/bin/ssh'
SCP = '/usr/bin/scp'
def fail(code):
    print('IBSW_SCP_ERROR='+code,flush=True)
    raise SystemExit(77)
raw=os.environ.pop('IBSW_SCP_AUTH',None)
if raw is None: raw=sys.stdin.buffer.read(65537).decode('utf-8')
if len(raw.encode())>65536: fail('CONTEXT_INVALID')
try:
    cfg=json.loads(raw)
    password=cfg['password']; host=cfg['host']; user=cfg['user']; port=cfg['port']
    if (not isinstance(password,str) or any(ord(c)<32 or ord(c)==127 for c in password)
        or len(password.encode())>4096 or not re.fullmatch(r'[0-9.]{7,15}',host)
        or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9._-]{0,63}',user)
        or type(port) is not int or not 1<=port<=65535): raise ValueError()
except Exception: fail('CONTEXT_INVALID')
def run(command,timeout):
    pid,fd=pty.fork()
    if pid==0:
        attrs=termios.tcgetattr(0); attrs[3]&=~termios.ECHO; termios.tcsetattr(0,termios.TCSANOW,attrs)
        os.execve(command[0],command,dict(os.environ))
    deadline=time.monotonic()+timeout; sent=False; pending=b''; status=None; failure=None
    try:
        while True:
            if time.monotonic()>=deadline: failure=124; break
            ready,_,_=select.select([fd],[],[],min(0.1,max(0,deadline-time.monotonic())))
            if ready:
                try: data=os.read(fd,65536)
                except OSError as error:
                    if error.errno!=errno.EIO: raise
                    data=b''
                if not data:
                    # EOF alone is not process exit. Keep the same deadline
                    # even if a broken client closes its TTY before exiting.
                    found,status_value=os.waitpid(pid,os.WNOHANG)
                    if found: status=status_value; break
                    time.sleep(.02)
                    continue
                pending=(pending+data)[-4096:]
                if re.search(br'(?i)password:\s*$',pending):
                    if sent or not password: failure=77; break
                    os.write(fd,password.encode()+b'\n'); sent=True; pending=b''
            found,status_value=os.waitpid(pid,os.WNOHANG)
            if found: status=status_value; break
        if failure is not None:
            try: os.killpg(pid,signal.SIGTERM)
            except ProcessLookupError: pass
            until=time.monotonic()+1
            while time.monotonic()<until:
                found,status_value=os.waitpid(pid,os.WNOHANG)
                if found: status=status_value; break
                time.sleep(.02)
            if status is None:
                try: os.killpg(pid,signal.SIGKILL)
                except ProcessLookupError: pass
        if status is None: _,status=os.waitpid(pid,0)
        if failure is not None: return failure
        return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128+os.WTERMSIG(status)
    finally:
        os.close(fd)
        if status is None:
            try: os.killpg(pid,signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(pid,0)
            except ChildProcessError: pass
mode=sys.argv[1]
if mode not in ('probe','fetch'): fail('CONTEXT_INVALID')
if mode=='fetch':
    # Receiver validation only. Public envelope is DATA, not authority.
    try:
        binding=cfg['content_binding']
        if (type(binding) is not dict or type(binding.get('version')) is not int
                or binding['version']!=1 or not re.fullmatch(r'[0-9a-f]{64}',binding['binding_sha256'])
                or type(binding['packages']) is not dict or type(cfg['paths']) is not dict
                or not cfg['paths'] or set(binding['packages'])!=set(cfg['paths'])): raise ValueError()
        for name,expected in binding['packages'].items():
            if (type(expected) is not dict or type(expected.get('size')) is not int
                    or expected['size']<=0 or type(cfg['paths'][name]) is not int
                    or expected['size']!=cfg['paths'][name]
                    or not re.fullmatch(r'[0-9a-f]{64}',expected['sha256'])): raise ValueError()
    except (KeyError,ValueError,TypeError): fail('CONTENT_CONTEXT_INVALID')
with tempfile.TemporaryDirectory(prefix='.ibsw-scp-') as directory:
    trust=directory+'/known_hosts'
    with open(trust,'x',encoding='ascii') as handle: handle.write(cfg['host_keys'])
    os.chmod(trust,0o600)
    options=['-F','/dev/null','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+trust,
        '-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no','-o','IdentitiesOnly=yes',
        '-o','ConnectTimeout=5','-o','NumberOfPasswordPrompts=1',
        '-o','ConnectionAttempts=1','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2']
    options+=['-o','BatchMode=yes'] if not password else ['-o','PreferredAuthentications=publickey,password']
    if mode=='probe':
        code=run([SSH,*options,'-p',str(port),user+'@'+host,'/bin/true'],min(20,float(cfg['timeout_seconds'])))
        print('IBSW_SCP_SOURCE_VERIFIED' if code==0 else 'IBSW_SCP_ERROR=SOURCE_AUTH_OR_CONNECT_FAILED',flush=True)
        raise SystemExit(code)
    path,destination=sys.argv[2:]
    if (path not in cfg['paths'] or not path.startswith('/') or '\x00' in path
            or not os.path.isabs(destination)): fail('PACKAGE_CONTEXT_INVALID')
    before=None
    try:
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.close(fd)
    except FileExistsError: pass
    item=os.lstat(destination)
    if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_mode&0o077:
        fail('DESTINATION_UNSAFE')
    before=(item.st_dev,item.st_ino)
    started=int(time.time()); clock=time.monotonic()
    code=run([SCP,'-O','-q',*options,'-P',str(port),user+'@'+host+':'+shlex.quote(path),destination],float(cfg['timeout_seconds']))
    item=os.lstat(destination)
    if (not stat.S_ISREG(item.st_mode) or (item.st_dev,item.st_ino)!=before
            or item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_mode&0o077): code=65
    size=item.st_size
    if code==0 and size!=cfg['paths'][path]: code=66
    content_error=None
    if code==0:
        fd=None
        try:
            fd=os.open(destination,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            initial=os.fstat(fd)
            def facts(row):
                return (row.st_dev,row.st_ino,row.st_mode,row.st_nlink,row.st_uid,
                        row.st_size,row.st_mtime_ns,row.st_ctime_ns)
            if facts(initial)!=facts(item): raise ValueError()
            digest=hashlib.sha256(); count=0
            while True:
                if time.monotonic()-clock>=float(cfg['timeout_seconds']): raise ValueError()
                data=os.read(fd,min(1024*1024,max(1,size-count+1)))
                if not data: break
                count+=len(data)
                if count>size: raise ValueError()
                digest.update(data)
            if (count!=size or facts(initial)!=facts(os.fstat(fd))
                    or facts(initial)!=facts(os.lstat(destination))): raise ValueError()
            if digest.hexdigest()!=binding['packages'][path]['sha256']:
                content_error='CONTENT_MISMATCH'; code=67
        except (OSError,ValueError,TypeError):
            content_error='CONTENT_ORIGINAL_CHANGED'; code=68
        finally:
            if fd is not None: os.close(fd)
        if code==0:
            import base64
            reference=base64.urlsafe_b64encode(path.encode()).rstrip(b'=').decode()
            print('IBSW_SCP_CONTENT_VERIFIED=1|%s|%s|%d|%s'%(binding['binding_sha256'],reference,size,digest.hexdigest()),flush=True)
    elapsed=max(0.000001,time.monotonic()-clock); finished=int(time.time())
    print('IBSW_SCP_DOWNLOAD_RESULT=1|%d|%d|%d|0|%d|%.6f|%.6f'%(started,finished,code,size,elapsed,size/elapsed),flush=True)
    if content_error: print('IBSW_SCP_ERROR='+content_error,flush=True)
    if code: print('IBSW_SCP_ERROR=TRANSFER_FAILED',flush=True)
    raise SystemExit(code)
'''


def remote_helper_bytes():
    return _REMOTE_HELPER.encode()


def _python_command(code,*args):
    expression='import base64;exec(base64.b64decode('+repr(base64.b64encode(code).decode())+'))'
    return '/usr/bin/python3 -c '+shlex.quote(expression)+''.join(' '+shlex.quote(arg) for arg in args)


def probe_command():
    return _python_command(remote_helper_bytes(),'probe')


_LAUNCHER = r'''import json,os,stat,subprocess,sys
remote=sys.argv[1]; directory=os.path.dirname(remote)
raw=sys.stdin.buffer.read(65537)
if len(raw)>65536: raise SystemExit(65)
context=json.loads(raw)
env=dict(os.environ,IBSW_SCP_AUTH=json.dumps(context,separators=(',',':')))
runner=directory+'/runner.sh'
metadata=os.lstat(runner)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.geteuid() or metadata.st_mode&0o022: raise SystemExit(65)
handles=[]
try:
    for name in ('execution.stdout','execution.stderr'):
        fd=os.open(directory+'/'+name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
        handles.append(fd); item=os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or item.st_nlink!=1 or item.st_mode&0o077: raise SystemExit(65)
    with open(os.devnull,'rb') as stdin:
        subprocess.Popen(['/bin/bash',runner],stdin=stdin,stdout=handles[0],stderr=handles[1],
                         env=env,start_new_session=True,close_fds=True)
    print('IBSW_LAUNCH_REQUESTED',flush=True)
finally:
    for fd in handles: os.close(fd)
'''


def launch_command(remote):
    if (not isinstance(remote,str) or not remote.startswith('/') or posixpath.normpath(remote)!=remote
            or posixpath.basename(remote)!='step.sh' or any(ord(c)<32 or ord(c)==127 for c in remote)):
        raise ScpHold('SCP_SOURCE_ARGUMENTS')
    return _python_command(_LAUNCHER.encode(),remote)


def preflight_source(leaf,transport,deadline,source):
    # No readiness/auth/network action through an incomplete manager bridge.
    # The public source/receiver library alone cannot attest live originals.
    raise ScpHold('SCP_CONTENT_BINDING_REQUIRED')


def verify_source_shared(source):
    try:
        source.verify()
    except ScpHold as error:
        if error.reason_code=='SCP_SOURCE_CHANGED':
            from ibsw_upgrade_contract import SharedUpgradeHold
            raise SharedUpgradeHold('SCP_SOURCE_CHANGED: original source trust changed; no further dispatch') from error
        raise


# Local source library only. Not connected to native dispatch or ACK.
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import threading
import time


class ContentHold(ValueError):
    pass


def _identity(item):
    return (item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
            item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)


def _directory_identity(item):
    return (item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid)


def _object_key(item):
    return (item.st_dev,item.st_ino,stat.S_IFMT(item.st_mode))


class _PackageContentOwner:
    def __init__(self,root,paths,*,deadline,max_fds):
        self._lock=threading.RLock()
        self._closed=False;self._poisoned=False
        self._fds=[];self._directories={};self._files={}
        self.cleanup_issues=[]
        try:
            if (type(max_fds) is not int or max_fds<1 or isinstance(deadline,bool)
                    or not isinstance(deadline,(int,float)) or not math.isfinite(deadline)):
                raise ContentHold('finite internal acquisition bounds required')
            self._deadline=deadline
            self._time_left()
            self.root=Path(root)
            if not self.root.is_absolute() or '..' in self.root.parts:
                raise ContentHold('absolute non-traversing original root required')
            if type(paths) not in (list,tuple) or not paths:
                raise ContentHold('explicit nonempty needed package selection required')
            selected=tuple(sorted({Path(p) for p in paths}))
            directories={Path('/')}
            for path in selected:
                if not path.is_absolute() or '..' in path.parts:
                    raise ContentHold('absolute non-traversing package required')
                path.relative_to(self.root)
                if path==self.root:
                    raise ContentHold('package must be below original root')
                directories.update(path.parents)
            if len(directories)+len(selected)>max_fds:
                raise ContentHold('entire original file/directory FD budget exceeded')
            flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
            for path in sorted(directories,key=lambda p:(len(p.parts),str(p))):
                self._time_left()
                parent=None if path==Path('/') else self._directories[path.parent][0]
                name='/' if parent is None else path.name
                fd,item=self._open_original(name,flags|os.O_DIRECTORY,parent)
                if not stat.S_ISDIR(item.st_mode):
                    raise ContentHold('original directory required')
                self._directories[path]=(fd,parent,name,_directory_identity(item))
            for path in selected:
                self._time_left()
                parent=self._directories[path.parent][0]
                fd,item=self._open_original(path.name,flags,parent)
                if (not stat.S_ISREG(item.st_mode) or item.st_nlink!=1
                        or item.st_mode & 0o022 or item.st_size<=0):
                    raise ContentHold('nonempty nonshared non-writable regular package required')
                original=_identity(item)
                self._files[path]=(fd,parent,path.name,original,None)
                digest=hashlib.sha256();size=0
                while True:
                    self._time_left();self.verify()
                    chunk=os.read(fd,1024*1024)
                    self._time_left()
                    if not chunk:break
                    size+=len(chunk)
                    if size>item.st_size:
                        raise ContentHold('original package grew during digest')
                    digest.update(chunk)
                if size!=item.st_size:
                    raise ContentHold('original package truncated during digest')
                self._files[path]=(fd,parent,path.name,original,digest.hexdigest())
                self.verify()
            self._time_left();self.verify()
        except BaseException as original:
            self._poisoned=True
            try:self.close()
            except BaseException as cleanup:
                # Retain the original operator object AND its existing cause.
                # Cleanup facts remain on the holder; never relabel NI.
                if not isinstance(original,Exception):raise original
                raise cleanup from original
            if isinstance(original,ContentHold) or not isinstance(original,Exception):raise
            if isinstance(original,OSError) and original.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOSPC):raise
            raise ContentHold('original package acquisition failed') from original

    def _time_left(self):
        if time.monotonic()>=self._deadline:
            raise ContentHold('original package acquisition deadline exceeded')

    def _open_original(self,name,flags,parent):
        # Capture the original named object before open. Register that identity
        # immediately on receiving the numeric slot, before the first fstat;
        # cleanup never adopts an unproved replacement as the original.
        named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        fd=os.open(name,flags,dir_fd=parent)
        self._fds.append((fd,_object_key(named)))
        item=os.fstat(fd)
        identity=_directory_identity if flags & os.O_DIRECTORY else _identity
        if identity(item)!=identity(named):
            raise ContentHold('opened object differs from original named source')
        return fd,item

    def verify(self):
        with self._lock:
            if self._closed or self._poisoned:
                raise ContentHold('original package group unavailable; no baseline refresh')
            try:
                for fd,parent,name,original in self._directories.values():
                    if (_directory_identity(os.fstat(fd))!=original
                            or _directory_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=original):
                        raise ContentHold('original directory/name changed')
                for fd,parent,name,original,_digest in self._files.values():
                    if (_identity(os.fstat(fd))!=original
                            or _identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=original):
                        raise ContentHold('original package/name changed')
            except BaseException as error:
                self._poisoned=True
                if not isinstance(error,Exception) or isinstance(error,ContentHold):raise
                if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOSPC):raise
                raise ContentHold('original package group changed') from error

    def bind(self,request,dispatch):
        with self._lock:
            self.verify()
            if any(type(b) is not bytes or not b or len(b)>4*1024*1024 for b in (request,dispatch)):
                self._poisoned=True
                raise ContentHold('bounded request/dispatch DATA required')
            packages={str(path):dict(size=row[3][6],sha256=row[4]) for path,row in self._files.items()}
            document=dict(version=1,request_sha256=hashlib.sha256(request).hexdigest(),
                dispatch_sha256=hashlib.sha256(dispatch).hexdigest(),packages=packages)
            raw=json.dumps(document,sort_keys=True,separators=(',',':')).encode('ascii')
            binding=hashlib.sha256(raw).hexdigest()
            self.verify()
            return dict(content_binding=dict(version=1,binding_sha256=binding,packages=packages),
                        record=dict(document,binding_sha256=binding))

    def close(self):
        with self._lock:
            if self._closed:
                # No retry of potentially reused numeric slots. A previous
                # uncertain close cannot become clean by a second call.
                if self.cleanup_issues:self._raise_cleanup_issues()
                return
            self._closed=True
            failures=[]
            for fd,key in reversed(self._fds):
                try:
                    if _object_key(os.fstat(fd))!=key:
                        raise ContentHold('borrowed descriptor cannot be closed as original')
                    os.close(fd)
                except BaseException as error:failures.append(error)
            self.cleanup_issues.extend(failures)
            if failures:
                self._poisoned=True
                self._raise_cleanup_issues()

    def _raise_cleanup_issues(self):
        critical=next((e for e in self.cleanup_issues if not isinstance(e,Exception)),None)
        if critical is not None:raise critical
        raise ContentHold('critical original descriptor cleanup uncertain') from self.cleanup_issues[0]

    def __enter__(self):
        try:
            self.verify();return self
        except BaseException as primary:
            self._poisoned=True
            try:self.close()
            except BaseException as cleanup:
                if not isinstance(primary,Exception):raise primary
                if not isinstance(cleanup,Exception):raise
                # Keep primary source failure; cleanup remains separately
                # recorded, permanently invalidating this owner.
                raise primary
            raise

    def __exit__(self,kind,error,traceback):
        try:self.close()
        except BaseException as cleanup:
            if error is not None and not isinstance(error,Exception):raise error
            raise


def package_content_owner(root,paths,*,deadline,max_fds):
    return _PackageContentOwner(root,paths,deadline=deadline,max_fds=max_fds)


def _probe_source_channel(leaf,transport,deadline,source):
    """Fixed stdin-only source probe fact, never native preflight permission.

    This private protocol seam does not attest original native parent authority.
    The public preflight and nonempty execution payload remain HOLD. Raw wire
    buffers and the secret are never returned or attached to diagnostics.
    """
    from ibsw_upgrade_observer import _owned_phase, _remaining
    if type(source) is not ScpSource or type(deadline) not in (int,float) or not math.isfinite(deadline):
        raise ScpHold('SCP_SECRET_CHANNEL_FAILED')
    channel = None
    failure = None
    finished = False
    output,error = bytearray(),bytearray()
    status,complete = None,False
    close_lock = threading.Lock()
    close_attempted = False
    close_error = None

    def remember(caught):
        nonlocal failure
        if failure is None or (isinstance(failure,Exception) and not isinstance(caught,Exception)):
            failure = caught

    class OwnedChannel:
        def close(self):
            nonlocal close_attempted,close_error
            # The supervisor and synchronous tail share one actual object
            # close attempt; an unknown close is never retried by this helper.
            with close_lock:
                if close_attempted:
                    if close_error is not None:
                        raise close_error
                    return
                close_attempted = True
            try:
                channel.close()
            except BaseException as caught:
                close_error = caught
                raise

    owner = OwnedChannel()

    def finish():
        nonlocal finished
        if finished:
            return
        finished = True
        if channel is not None:
            try:
                owner.close()
            except BaseException as caught:
                remember(caught)
        for verify in (leaf.verify,lambda: verify_source_shared(source)):
            try:
                verify()
            except BaseException as caught:
                remember(caught)

    try:
        _remaining(deadline)
        leaf.verify()
        verify_source_shared(source)
        payload = json.loads(launch_payload(source,()))
        payload['timeout_seconds'] = min(20.0,_remaining(deadline))
        payload = (json.dumps(payload,separators=(',',':'))+'\n').encode()
        # The old receiver supports an environment compatibility context.
        # This fixed probe alone must instead consume the current stdin.
        body = b"import os\nos.environ.pop('IBSW_SCP_AUTH',None)\n"+remote_helper_bytes()
        command = _python_command(body,'probe')
        channel = transport.open_session(timeout=_remaining(deadline))
        channel.settimeout(_remaining(deadline))
        with _owned_phase((owner,),deadline):
            try:
                leaf.verify()
                verify_source_shared(source)
                channel.exec_command(command)
                position = 0
                while position < len(payload):
                    leaf.verify_io_identity()
                    verify_source_shared(source)
                    channel.settimeout(_remaining(deadline))
                    count = channel.send(payload[position:])
                    if type(count) is not int or not 0 < count <= len(payload)-position:
                        raise ScpHold('SCP_SECRET_CHANNEL_FAILED')
                    position += count
                channel.settimeout(_remaining(deadline))
                channel.shutdown_write()
                while True:
                    leaf.verify_io_identity()
                    _remaining(deadline)
                    for ready,receive,target in ((channel.recv_ready,channel.recv,output),
                            (channel.recv_stderr_ready,channel.recv_stderr,error)):
                        if ready():
                            channel.settimeout(_remaining(deadline))
                            part = receive(65536)
                            if type(part) is not bytes:
                                raise ScpHold('SCP_SECRET_CHANNEL_FAILED')
                            target.extend(part)
                            if len(output)+len(error)>65536:
                                raise ScpHold('SCP_SECRET_CHANNEL_FAILED')
                    if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():
                        if channel.exit_status_ready():
                            status = channel.recv_exit_status()
                        complete = channel.eof_received is True and type(status) is int and status == 0
                        break
                    if not transport.is_active():
                        break
                    time.sleep(min(.005,_remaining(deadline)))
            except BaseException as caught:
                remember(caught)
            finally:
                finish()
            try:
                _remaining(deadline)
            except BaseException as caught:
                remember(caught)
    except BaseException as caught:
        remember(caught)
    finally:
        finish()
    if failure is not None and not isinstance(failure,Exception):
        raise failure
    # A changed original shared source must retain batch-stop classification,
    # rather than becoming an ordinary per-device wire failure.
    from ibsw_upgrade_contract import SharedUpgradeHold
    if isinstance(failure,SharedUpgradeHold):
        raise failure
    if (failure is not None or time.monotonic()>=deadline or not complete
            or bytes(output)!=b'IBSW_SCP_SOURCE_VERIFIED\n' or error):
        raise ScpHold('SCP_SECRET_CHANNEL_FAILED') from None
    return None


# Protocol-only fixed launcher. This is not used by the native backend and is
# deliberately distinct from the old environment-context _LAUNCHER.
_STDIN_LAUNCHER = r'''import base64,hashlib,ipaddress,json,os,posixpath,re,select,stat,subprocess,sys,time

def fail():
    raise ValueError('fixed stdin launch refused')

def key(info):
    return info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)

def facts(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,
            info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def directory_facts(info):
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid

def pairs(values):
    result={}
    for name,value in values:
        if name in result: fail()
        result[name]=value
    return result

def constant(value): fail()

def integer(value):
    if len(value)>20: fail()
    return int(value)

def hex_value(value,length):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None

def source_path(value):
    return (type(value) is str and value.startswith('/') and value!='/'
        and len(value)<=4096 and posixpath.normpath(value)==value
        and not any(ord(char)<32 or ord(char)==127 for char in value))

def frame(deadline):
    raw=bytearray()
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0: fail()
        ready,_,_=select.select([0],[],[],remaining)
        if not ready: fail()
        part=os.read(0,65537-len(raw))
        if not part: break
        raw.extend(part)
        if len(raw)>65536: fail()
    if not raw or raw[-1:]!=b'\n' or raw.count(b'\n')!=1: fail()
    value=json.loads(raw.decode('ascii'),object_pairs_hook=pairs,parse_constant=constant,parse_int=integer)
    expected={'host','user','port','host_keys','password','paths','timeout_seconds','content_binding'}
    if type(value) is not dict or set(value)!=expected: fail()
    host,user,port=value['host'],value['user'],value['port']
    if (type(host) is not str or str(ipaddress.IPv4Address(host))!=host
        or type(user) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9._-]{0,63}',user) is None
        or type(port) is not int or not 1<=port<=65535): fail()
    secret=value['password'];pins=value['host_keys']
    if (type(secret) is not str or len(secret.encode())>4096
        or any(ord(char)<32 or ord(char)==127 for char in secret)
        or type(pins) is not str or not pins or len(pins)>65536
        or not pins.endswith('\n') or '\r' in pins or '\x00' in pins): fail()
    endpoint=host if port==22 else '['+host+']:'+str(port)
    for line in pins.encode('ascii').splitlines():
        fields=line.split()
        if len(fields)!=3 or fields[0]!=endpoint.encode('ascii'): fail()
        if re.fullmatch(br'[A-Za-z0-9@._+-]{1,128}',fields[1]) is None: fail()
        if not base64.b64decode(fields[2],validate=True): fail()
    paths=value['paths'];binding=value['content_binding']
    fields={'version','binding_sha256','request_id','request_sha256','companion_sha256','packages'}
    if (type(paths) is not dict or not paths or type(binding) is not dict or set(binding)!=fields
        or type(binding['version']) is not int or binding['version']!=1
        or not hex_value(binding['request_id'],32)
        or any(not hex_value(binding[name],64) for name in ('binding_sha256','request_sha256','companion_sha256'))
        or type(binding['packages']) is not dict or set(binding['packages'])!=set(paths)): fail()
    for path,size in paths.items():
        item=binding['packages'][path]
        if (not source_path(path) or type(size) is not int or not 0<size<2**63
            or type(item) is not dict or set(item)!={'size','sha256'}
            or type(item['size']) is not int or item['size']!=size
            or not hex_value(item['sha256'],64)): fail()
    return bytes(raw),value

def launch():
    deadline=time.monotonic()+10
    rows=[];edges=[];named_files=[]
    child=None;stdin_attempted=False;primary=None;cleanup=[]
    def remaining():
        value=deadline-time.monotonic()
        if value<=0: fail()
        return value
    def remember(error):
        nonlocal primary
        if primary is None or isinstance(primary,Exception) and not isinstance(error,Exception): primary=error
    def opened(name,flags,parent=None):
        named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        descriptor=os.open(name,flags,dir_fd=parent)
        row=[descriptor,key(named),False]
        rows.append(row) # Register from original named preimage before first fstat.
        compare=directory_facts if stat.S_ISDIR(named.st_mode) else facts
        if compare(os.fstat(descriptor))!=compare(named): fail()
        return descriptor,named,row
    def close_row(row):
        if row[2]: return
        row[2]=True # Never retry a close whose result is uncertain.
        if key(os.fstat(row[0]))!=row[1]: fail()
        os.close(row[0])
    def regular(info):
        return (stat.S_ISREG(info.st_mode) and info.st_nlink==1
                and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600)
    def read_source(parent,name,expected):
        fd,named,row=opened(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,parent)
        if not regular(named) or not 0<named.st_size<=4*1024*1024: fail()
        data=bytearray();offset=0
        while offset<named.st_size:
            remaining();part=os.pread(fd,min(65536,named.st_size-offset),offset)
            if not part: fail()
            data.extend(part);offset+=len(part)
        if os.pread(fd,1,offset) or hashlib.sha256(data).hexdigest()!=expected: fail()
        if facts(os.fstat(fd))!=facts(named) or facts(os.stat(name,dir_fd=parent,follow_symlinks=False))!=facts(named): fail()
        named_files.append((parent,name,fd,facts(named)))
        return bytes(data),row
    try:
        if len(sys.argv)!=4: fail()
        remote,runner_sha,step_sha=sys.argv[1:]
        if (not source_path(remote) or posixpath.basename(remote)!='step.sh'
            or not hex_value(runner_sha,64) or not hex_value(step_sha,64)): fail()
        raw,context=frame(deadline)
        directory=posixpath.dirname(remote)
        components=directory.split('/')[1:]
        if not components or len(components)>64 or any(not part for part in components): fail()
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC
        parent,root_info,_=opened('/',flags)
        root_fd=parent
        for part in components:
            following,named,_=opened(part,flags,parent)
            if not stat.S_ISDIR(named.st_mode): fail()
            edges.append((parent,part,following,directory_facts(named)))
            parent=following
        info=os.fstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: fail()
        runner,runner_row=read_source(parent,'runner.sh',runner_sha)
        step,step_row=read_source(parent,'step.sh',step_sha)
        component=re.findall(br'^IBSW_COMPONENT=(os|bios|cpld)$',step,re.M)
        method=re.findall(br'^IBSW_METHOD=([^\n]*)$',step,re.M)
        if len(component)!=1 or method!=[b'scp']: fail()
        budget=600 if component[0]==b'os' else 300
        if type(context['timeout_seconds']) is not int or context['timeout_seconds']!=budget: fail()
        output=[]
        for name in ('execution.stdout','execution.stderr'):
            fd,named,row=opened(name,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,parent)
            if not regular(named): fail()
            output.append(row)
        for ancestor,name,fd,original in edges:
            if directory_facts(os.fstat(fd))!=original or directory_facts(os.stat(name,dir_fd=ancestor,follow_symlinks=False))!=original: fail()
        if directory_facts(os.fstat(root_fd))!=directory_facts(root_info): fail()
        for ancestor,name,fd,original in named_files:
            if facts(os.fstat(fd))!=original or facts(os.stat(name,dir_fd=ancestor,follow_symlinks=False))!=original: fail()
        # All original source/directory FDs must close before actual Popen.
        for row in reversed(rows):
            if all(row is not value for value in output): close_row(row)
        remaining()
        child=subprocess.Popen(['/bin/bash','-p',directory+'/runner.sh'],stdin=subprocess.PIPE,
            stdout=output[0][0],stderr=output[1][0],close_fds=True,start_new_session=True,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':directory},cwd=directory)
        descriptor=child.stdin.fileno();os.set_blocking(descriptor,False)
        position=0
        while position<len(raw):
            _,ready,_=select.select([],[descriptor],[],remaining())
            if not ready: fail()
            try: count=os.write(descriptor,raw[position:])
            except BlockingIOError: continue
            if count<=0: fail()
            position+=count
        stdin_attempted=True
        child.stdin.close() # EOF and critical close, not environment delivery.
        for row in reversed(output): close_row(row)
        remaining()
    except BaseException as error:
        remember(error)
    finally:
        if child is not None and child.stdin is not None and not stdin_attempted:
            stdin_attempted=True
            try: child.stdin.close()
            except BaseException as error: cleanup.append(error);remember(error)
        for row in reversed(rows):
            if not row[2]:
                try: close_row(row)
                except BaseException as error: cleanup.append(error);remember(error)
    if primary is not None: raise primary
    if cleanup: fail()
    # Asynchronous delivery fact ONLY; no child success or native authority.
    print('IBSW_LAUNCH_REQUESTED',flush=True)

try: launch()
except Exception:
    print('IBSW_SCP_ERROR=STDIN_LAUNCH_REFUSED',flush=True)
    raise SystemExit(65) from None
'''


def _stdin_launch_command(remote, runner_sha256, step_sha256):
    """Pure fixed protocol DATA; no parent/request/dispatch or SCP permission."""
    if (type(remote) is not str or not remote.startswith('/')
            or posixpath.normpath(remote) != remote or posixpath.basename(remote) != 'step.sh'
            or len(remote) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in remote)
            or any(type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None
                   for value in (runner_sha256, step_sha256))):
        raise ScpHold('SCP_SOURCE_ARGUMENTS')
    return _python_command(_STDIN_LAUNCHER.encode(), remote, runner_sha256, step_sha256)
