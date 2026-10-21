"""UNRUN stdlib-only finite IO carrier pieces; no production imports/grants.

These do not yet assemble the 453-line invoke carrier or register tests.
Canonical isolation prepares a fixed private lowered image BEFORE cold imports.
"""
import errno
import hashlib
import os
from pathlib import Path
import select
import shlex
import stat
import subprocess
from types import SimpleNamespace


def lower_fixed_io_images(provider_bytes, template_bytes, ssh, scp, nv):
    """Pure test-image transform, before import/hash; exact inverse asserted.

    Returns bytes and diagnostic hashes, not filesystem writes or authority.
    The root driver must create a new coherent image, never change root R.
    """
    transformed = provider_bytes
    replacements = []
    for label, name in (('SSH', ssh), ('SCP', scp)):
        p = Path(name)
        if not p.is_absolute() or p.resolve() != p:
            raise AssertionError('exact private executable path required')
        old = (label + " = '/usr/bin/" + label.lower() + "'").encode()
        new = (label + ' = ' + repr(str(p))).encode()
        if transformed.count(old) != 1 or transformed.count(new) != 0:
            raise AssertionError('unique original executable literal required')
        transformed = transformed.replace(old, new, 1)
        replacements.append((old, new))
    marker = b'# IBSW_BODY_CPLD\n'
    if template_bytes.count(marker) != 1:
        raise AssertionError('one complete original CPLD section required')
    prefix, body = template_bytes.split(marker, 1)
    if body.count(b'\nnv ') != 4:
        raise AssertionError('four independently reviewed CPLD NV sites required')
    p = Path(nv)
    if not p.is_absolute() or p.resolve() != p:
        raise AssertionError('exact private NV executable required')
    token = ('\n' + shlex.quote(str(p)) + ' ').encode()
    if token in body:
        raise AssertionError('lowered executable unexpectedly preexists')
    lowered_body = body.replace(b'\nnv ', token)
    restored = transformed
    for old, new in reversed(replacements):
        if restored.count(new) != 1:
            raise AssertionError('nonunique executable inverse')
        restored = restored.replace(new, old, 1)
    lowered_template = prefix + marker + lowered_body
    if restored != provider_bytes or lowered_body.replace(token, b'\nnv ') != body:
        raise AssertionError('IO lowering failed full byte inverse')
    return transformed, lowered_template, {
        'provider_before': hashlib.sha256(provider_bytes).hexdigest(),
        'provider_after': hashlib.sha256(transformed).hexdigest(),
        'template_before': hashlib.sha256(template_bytes).hexdigest(),
        'template_after': hashlib.sha256(lowered_template).hexdigest(),
        'replacement_counts': (1, 1, 4), 'inverse_full_bytes_equal': True,
    }


_OWNED_SUPERVISOR = r'''
import json,os,subprocess,sys
record=sys.argv[1]; expression=sys.argv[2]; arguments=sys.argv[3:]
constructor=subprocess.Popen.__init__; children=[]; launch=0; unknown=False
def observe(frame,event,value):
    if event=='return' and frame.f_code is constructor.__code__ and frame.f_globals is constructor.__globals__:
        child=frame.f_locals.get('self')
        if type(child) is subprocess.Popen and type(getattr(child,'pid',None)) is int:
            if all(child is not item for item in children):children.append(child)
sys.argv=['-c',*arguments]
try:
    sys.setprofile(observe)
    exec(compile(expression,'<fixed-bridge-command>','exec'),{'__name__':'__main__'})
except SystemExit as error:
    launch=error.code if type(error.code) is int else 0 if error.code is None else 2
except BaseException:
    launch=2
finally:
    sys.setprofile(None)
codes=[]; stdin_closed=[]
for child in children:
    try: codes.append(child.wait(timeout=15))
    except subprocess.TimeoutExpired:
        child.kill();child.wait(timeout=5);unknown=True;codes.append(child.returncode)
    stdin_closed.append(child.stdin is None or child.stdin.closed)
# Out-of-band PUBLIC test observation only. Never contaminate the production
# fixed marker stdout or the required empty stderr, nor write credential data.
fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as handle:
    json.dump(dict(launch=launch,codes=codes,stdin_closed=stdin_closed,unknown=unknown),handle)
raise SystemExit(2 if unknown else launch)
'''


class PhysicalSwitchSFTP:
    """Physical owned switch subtree; existing synthetic SSH-home IO elsewhere.

    No relocation: the exact remote absolute path is opened by both SFTP and
    Bash. Actual metadata is never given a synthetic uid or rewritten size.
    """
    def __init__(self, switch_root, home_double):
        self.root = Path(switch_root)
        info = self.root.lstat()
        if (not self.root.is_absolute() or self.root.resolve() != self.root
                or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise AssertionError('exact original private switch directory required')
        self.original_root = info.st_dev, info.st_ino
        parent_info = self.root.parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700):
            raise AssertionError('own physical test parent required')
        self.original_parent = parent_info.st_dev, parent_info.st_ino
        self.home = home_double
        self.handles = []
        self.closed_calls = 0

    @property
    def files(self): return self.home.files
    @property
    def modes(self): return self.home.modes

    def actual(self, name):
        p = Path(name)
        if not p.is_absolute() or str(p) != name or '..' in p.parts:
            raise AssertionError('normalized absolute remote path required')
        if p == self.root or self.root in p.parents:
            original = self.root.lstat()
            if (original.st_dev, original.st_ino) != self.original_root:
                raise AssertionError('fixture switch root identity drift')
            # Reject a symlink anywhere in an existing ancestor. No resolver
            # fallback or adoption to a different physical remote root.
            for parent in p.parents:
                if parent == self.root.parent:
                    break
                if parent.exists() and stat.S_ISLNK(parent.lstat().st_mode):
                    raise AssertionError('fixture remote ancestor symlink')
            return p
        if name not in ('/home', '/home/admin', '/home/admin/.ssh',
                        '/home/admin/.ssh/authorized_keys'):
            raise AssertionError('unapproved remote SFTP path: ' + name)
        return None

    def lstat(self, name):
        if name in ('/', '/private', '/private/tmp'):
            # Explicit target-ancestor IO double. The real host /private/tmp
            # is 1777, NOT a claimed trusted target ancestor. Production upload
            # checks remain unchanged; launcher uses actual host identities.
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0,
                                   st_gid=0, st_size=0, st_mtime=1)
        if name == str(self.root.parent):
            value = self.root.parent.lstat()
            if (value.st_dev, value.st_ino) != self.original_parent:
                raise AssertionError('owned physical parent identity drift')
            return value
        p = self.actual(name)
        if p is not None:
            return p.lstat()
        value = self.home.lstat(name)
        # This is the explicit synthetic SSH-home IO view, never metadata for
        # physical switch files. Match the fixture account's actual UID query.
        return SimpleNamespace(st_mode=value.st_mode, st_uid=os.geteuid(),
            st_gid=os.getegid(), st_size=value.st_size, st_mtime=value.st_mtime)

    stat = lstat

    def mkdir(self, name, mode):
        p = self.actual(name)
        return self.home.mkdir(name, mode) if p is None else p.mkdir(mode=mode)

    def chmod(self, name, mode):
        p = self.actual(name)
        if p is None:
            return self.home.chmod(name, mode)
        if stat.S_ISLNK(p.lstat().st_mode):
            raise AssertionError('no fixture chmod symlink')
        os.chmod(p, mode, follow_symlinks=False)

    def open(self, name, mode):
        p = self.actual(name)
        if p is None:
            original = self.home.open(name, mode)
            class HomeHandle:
                # Synthetic home dictionary IO only; the physical branch below
                # always returns the actual fstat result without UID rewriting.
                def __getattr__(self, selected): return getattr(original, selected)
                def stat(self):
                    value = original.stat()
                    return SimpleNamespace(st_mode=value.st_mode, st_uid=os.geteuid(),
                        st_gid=os.getegid(), st_size=value.st_size, st_mtime=value.st_mtime)
                def __enter__(self): return self
                def __exit__(self, *args): original.close()
            return HomeHandle()
        if mode in ('wx', 'xw', 'xb', 'x', 'wxb', 'w+x'):
            flags, binary = os.O_RDWR | os.O_CREAT | os.O_EXCL, 'w+b'
        elif mode in ('rb', 'r'):
            flags, binary = os.O_RDONLY, 'rb'
        else:
            raise AssertionError('unapproved physical SFTP open mode: ' + mode)
        fd = os.open(p, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
        stream = os.fdopen(fd, binary)

        class Handle:
            def read(self, *args): return stream.read(*args)
            def write(self, *args): return stream.write(*args)
            def seek(self, *args): return stream.seek(*args)
            def flush(self): return stream.flush()
            def stat(self):
                stream.flush()
                return os.fstat(stream.fileno())
            def close(self): return stream.close()
            @property
            def closed(self): return stream.closed
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        handle = Handle()
        self.handles.append(handle)
        return handle

    def rename(self, old, new):
        a, b = self.actual(old), self.actual(new)
        if a is None or b is None:
            if a is not None or b is not None:
                raise AssertionError('cross-view rename forbidden')
            return self.home.rename(old, new)
        if b.exists() or b.is_symlink():
            raise FileExistsError(errno.EEXIST, 'fixture non-overwrite rename', new)
        # The directory belongs solely to this test, which has no concurrent
        # writers. This is an SFTP IO double, not a production atomic primitive.
        os.rename(a, b)

    def close(self):
        self.closed_calls += 1
        if any(not value.closed for value in self.handles):
            raise AssertionError('SFTP closed before its actual known handles')

    def get_channel(self):
        return SimpleNamespace(settimeout=lambda seconds: None)


class ActualFixedPythonChannel:
    """Execute exact fixed producer command in a retained test-owned child.

    The fixed test supervisor observes original Popen objects, writes only
    public exit facts to a test-owned EXCL side record and leaves wire markers
    unchanged. No command replacement occurs after production source binding.
    """
    def __init__(self, root, record):
        self.root, self.record = Path(root), Path(record)
        if self.record.parent != self.root or self.record.exists():
            raise AssertionError('fresh public observation record in own root required')
        self.process = None
        self.send_calls = self.close_calls = 0
        self.out_eof = self.err_eof = False
        self.collected = [bytearray(), bytearray()]
        self.actual_returncode = None
        self.unknown = False
        self.command = None

    def settimeout(self, seconds):
        if type(seconds) not in (int, float) or seconds <= 0:
            raise AssertionError('positive original channel budget required')

    def exec_command(self, command):
        words = shlex.split(command)
        # Independent mandatory test IO safety gate, not production authority.
        from test_cases.native_cpld_safe_image import require_safe_command
        require_safe_command(Path(__file__).resolve().parents[1], words)
        if (self.process is not None or words[:2] != ['/usr/bin/python3', '-c']
                or len(words) not in (4, 6)
                or len(words) == 4 and words[-1] != 'probe'):
            raise AssertionError('fixed source probe or fixed stdin launcher only')
        self.command = command
        # The real driver producer joint chooses this exact command; this IO
        # seam does not manufacture a request, dispatch result or approval.
        self.process = subprocess.Popen([words[0], '-B', '-c', _OWNED_SUPERVISOR,
            str(self.record), words[2], *words[3:]], cwd=self.root,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root),
                 'TMPDIR': str(self.root), 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True)

    def send(self, value):
        self.send_calls += 1
        count = min(7, len(value))
        self.process.stdin.write(value[:count]); self.process.stdin.flush()
        return count

    def sendall(self, value):
        raise AssertionError('bounded partial send required')

    def shutdown_write(self): self.process.stdin.close()
    def recv_ready(self):
        return not self.out_eof and bool(select.select([self.process.stdout], [], [], 0)[0])
    def recv_stderr_ready(self):
        return not self.err_eof and bool(select.select([self.process.stderr], [], [], 0)[0])
    def recv(self, size):
        value = os.read(self.process.stdout.fileno(), size)
        self.collected[0].extend(value)
        if not value: self.out_eof = True
        return value
    def recv_stderr(self, size):
        value = os.read(self.process.stderr.fileno(), size)
        self.collected[1].extend(value)
        if not value: self.err_eof = True
        return value
    def exit_status_ready(self): return self.process is not None and self.process.poll() is not None
    def recv_exit_status(self):
        self.actual_returncode = self.process.wait(timeout=25)
        return self.actual_returncode
    @property
    def eof_received(self): return self.out_eof and self.err_eof
    @property
    def closed(self): return self.close_calls > 0 or (self.exit_status_ready() and self.eof_received)
    def close(self):
        self.close_calls += 1
        if self.process is None: return
        if not self.process.stdin.closed: self.process.stdin.close()
        try:
            self.actual_returncode = self.process.wait(timeout=25)
        except subprocess.TimeoutExpired:
            self.unknown = True
            # Only this retained original handle, never a PID scan. Unknown
            # descendants retain evidence; this never represents clean success.
            self.process.kill(); self.process.wait(timeout=5)
            raise AssertionError('owned diagnostic child timeout UNKNOWN')
        finally:
            for stream in (self.process.stdout, self.process.stderr):
                if not stream.closed: stream.close()

