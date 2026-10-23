"""UNRUN pure test-source builder; root writes these before coherent imports.

Independent literal source/bytes/options. It reads no package or project file.
Return values are executable fixture bytes, never a production command grant.
"""
import base64
import hashlib
from pathlib import Path
import struct

# The private nv stub embeds only CARRIER_PREFIX, never the whole unit
# credential.
CARRIER_PREFIX = 'NATIVE-CPLD-BRIDGE-SYNTHETIC-ONLY-'
SECRET = CARRIER_PREFIX + '71c4'
BURN = 'FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
REFRESH = 'FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'


def executable_sources():
    wire = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes((17,))*32
    pin = b'[198.51.100.44]:2222 ssh-ed25519 ' + base64.b64encode(wire) + b'\n'
    shared = '''#!/usr/bin/python3
import hashlib,json,os,stat,sys
from pathlib import Path
a=sys.argv[1:]
if a[:2]!=['-F','/dev/null']:raise SystemExit(90)
for option in ('StrictHostKeyChecking=yes','GlobalKnownHostsFile=/dev/null','UpdateHostKeys=no','IdentitiesOnly=yes','ConnectionAttempts=1','NumberOfPasswordPrompts=1'):
    if option not in a:raise SystemExit(91)
pins=[value.split('=',1)[1] for value in a if value.startswith('UserKnownHostsFile=')]
if len(pins)!=1:raise SystemExit(92)
p=Path(pins[0]); s=p.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit(94)
if p.read_bytes()!=PIN:raise SystemExit(95)
sys.stdout.write('Password: ');sys.stdout.flush()
secret=sys.stdin.readline().rstrip('\\n')
if hashlib.sha256(secret.encode()).hexdigest()!=SECRET_SHA:raise SystemExit(96)
if 'IBSW_SCP_AUTH' in os.environ or any(secret in value for value in a+list(os.environ.values())):raise SystemExit(97)
'''.replace('PIN', repr(pin)).replace('SECRET_SHA', repr(hashlib.sha256(SECRET.encode()).hexdigest()))
    ssh = shared + '''
if a[-4:]!=['-p','2222','source_test@198.51.100.44','/bin/true']:raise SystemExit(98)
print(secret) # Actual PTY echo challenge; fixed helper must never reflect it.
'''
    scp = shared.replace("if a[:2]!=['-F','/dev/null']:",
        "if a[:4]!=['-O','-q','-F','/dev/null']:") + '''
if '-O' not in a or '-P' not in a or a[a.index('-P')+1]!='2222':raise SystemExit(98)
source=a[-2]
if not source.startswith('source_test@198.51.100.44:'):raise SystemExit(99)
path=source.split(':',1)[1]
if Path(path).name not in NAMES or '/packages/firmware/' not in path:raise SystemExit(100)
remote=Path(os.environ['TMPDIR'])
if not remote.name.startswith('.ibsw-') or remote.is_symlink():raise SystemExit(101)
with (remote/'scp.bridge.trace').open('a') as handle:handle.write(json.dumps(source)+'\\n')
Path(a[-1]).write_bytes(b'SYNTHETIC-NOT-FIRMWARE')
print(secret)
'''.replace('NAMES', repr((BURN, REFRESH)))
    nv = '''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
if any(CARRIER_TEXT in value for value in sys.argv+list(os.environ.values())):raise SystemExit(94)
remote=Path(os.environ['TMPDIR'])
if not remote.name.startswith('.ibsw-') or remote.is_symlink():raise SystemExit(101)
with (remote/'nv.bridge.trace').open('a') as handle:handle.write(json.dumps(sys.argv[1:])+'\\n')
raise SystemExit(93)
'''.replace('CARRIER_TEXT', repr(CARRIER_PREFIX))
    return {'private-ssh': ssh.encode(), 'private-scp': scp.encode(), 'private-nv': nv.encode()}
