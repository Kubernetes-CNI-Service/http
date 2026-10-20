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
