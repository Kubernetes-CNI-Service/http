"""NOTRUN pure independent private executable literals; no network/client call."""
import base64
import hashlib
import struct


SECRET = 'NATIVE-CPLD-BRIDGE-SYNTHETIC-ONLY-71c4'
PACKAGE = 'nvos-amd64-25.03.1010.bin'
BURN = 'FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
REFRESH = 'FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'


def executable_sources():
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes((17,)) * 32
    pin = b'[198.51.100.44]:2222 ssh-ed25519 ' + base64.b64encode(wire) + b'\n'
    shared = '''#!/usr/bin/python3
import hashlib,json,os,stat,sys,time
from pathlib import Path
a=sys.argv[1:]
fixed=a[2:] if a[:2]==['-O','-q'] else a
if fixed[:2]!=['-F','/dev/null']:raise SystemExit(90)
for option in ('StrictHostKeyChecking=yes','GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no','IdentitiesOnly=yes','ConnectionAttempts=1','NumberOfPasswordPrompts=1'):
    if option not in fixed:raise SystemExit(91)
pins=[value.split('=',1)[1] for value in fixed if value.startswith('UserKnownHostsFile=')]
if len(pins)!=1:raise SystemExit(92)
p=Path(pins[0]); s=p.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit(94)
if p.read_bytes()!=PIN_LITERAL:raise SystemExit(95)
sys.stdout.write('Password: ');sys.stdout.flush()
secret=sys.stdin.readline().rstrip('\\n')
if hashlib.sha256(secret.encode()).hexdigest()!=SECRET_SHA_LITERAL:raise SystemExit(96)
if 'IBSW_SCP_AUTH' in os.environ or any(secret in value for value in a+list(os.environ.values())):raise SystemExit(97)
'''.replace('PIN_LITERAL', repr(pin)).replace('SECRET_SHA_LITERAL', repr(hashlib.sha256(SECRET.encode()).hexdigest()))
    ssh = shared + '''
if a[-4:]!=['-p','2222','source_test@198.51.100.44','/bin/true']:raise SystemExit(98)
print(secret) # Actual PTY echo challenge; original helper must not reflect it.
'''
    scp = shared + '''
if a[:4]!=['-O','-q','-F','/dev/null'] or '-P' not in a or a[a.index('-P')+1]!='2222':raise SystemExit(98)
source=a[-2]
if not source.startswith('source_test@198.51.100.44:'):raise SystemExit(99)
remote=Path(os.environ['TMPDIR'])
if not remote.name.startswith('.ibsw-') or remote.is_symlink():raise SystemExit(101)
path=Path(source.split(':',1)[1]); root=remote.parent.parent
if path.name==PACKAGE_LITERAL:
    expected=root/'packages'/'image'/PACKAGE_LITERAL
elif path.name in CPLD_LITERAL:
    expected=root/'packages'/'firmware'/path.name
else:raise SystemExit(100)
if path!=expected:raise SystemExit(100)
with (remote/'scp.os.trace').open('a') as handle:
    handle.write(json.dumps(dict(source=source,time_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)))+'\\n')
Path(a[-1]).write_bytes(b'SYNTHETIC-NOT-FIRMWARE')
print(secret)
'''.replace('PACKAGE_LITERAL', repr(PACKAGE)).replace('CPLD_LITERAL', repr((BURN, REFRESH)))
    nv = '''#!/usr/bin/python3
import json,os,sys,time
from pathlib import Path
if any('NATIVE-CPLD-BRIDGE-SYNTHETIC-ONLY-' in value for value in sys.argv+list(os.environ.values())):raise SystemExit(94)
remote=Path(os.environ['TMPDIR'])
if not remote.name.startswith('.ibsw-') or remote.is_symlink():raise SystemExit(101)
with (remote/'nv.os.trace').open('a') as handle:
    handle.write(json.dumps(dict(argv=sys.argv[1:],time_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)))+'\\n')
raise SystemExit(93)
'''
    return {'private-ssh': ssh.encode(), 'private-scp': scp.encode(), 'private-nv': nv.encode()}
