"""SOURCE ONLY BIOS2 executable IO lowering + original retained channel."""
import hashlib
import shlex
import subprocess
from pathlib import Path
from test_cases.native_cpld_physical_io import (
    PhysicalSwitchSFTP, ActualFixedPythonChannel as _Channel, _OWNED_SUPERVISOR)

def _sections(template):
    marks = [b'# IBSW_BODY_' + x + b'\n' for x in (b'OS', b'BIOS', b'CPLD')]
    if any(template.count(x) != 1 for x in marks):
        raise AssertionError('exact original three sections required')
    common, rest = template.split(marks[0], 1)
    os_body, rest = rest.split(marks[1], 1)
    bios_body, cpld_body = rest.split(marks[2], 1)
    return common, os_body, bios_body, cpld_body

def lower_fixed_io_images(provider, template, ssh, scp, nv):
    lowered = provider
    pairs = []
    for name, path in (('SSH', ssh), ('SCP', scp)):
        p = Path(path)
        if not p.is_absolute() or p.resolve() != p:
            raise AssertionError('literal own executable path required')
        old = (name + " = '/usr/bin/" + name.lower() + "'").encode()
        new = (name + ' = ' + repr(str(p))).encode()
        if lowered.count(old) != 1 or new in lowered:
            raise AssertionError('unique fixed source executable literal required')
        lowered = lowered.replace(old, new, 1); pairs.append((old, new))
    p = Path(nv)
    if not p.is_absolute() or p.resolve() != p:
        raise AssertionError('literal own NV path required')
    common, os_body, bios_body, cpld_body = _sections(template)
    token = ('\n' + shlex.quote(str(p)) + ' ').encode()
    if bios_body.count(b'\nnv ') != 2 or token in template:
        raise AssertionError('exact two BIOS NV sites required')
    body = bios_body.replace(b'\nnv ', token)
    result = (common + b'# IBSW_BODY_OS\n' + os_body + b'# IBSW_BODY_BIOS\n' +
              body + b'# IBSW_BODY_CPLD\n' + cpld_body)
    restored = lowered
    for old, new in reversed(pairs):
        if restored.count(new) != 1:
            raise AssertionError('unique source executable inverse required')
        restored = restored.replace(new, old, 1)
    if restored != provider or body.replace(token, b'\nnv ') != bios_body:
        raise AssertionError('full IO inverse differs')
    return lowered, result, dict(provider_before=hashlib.sha256(provider).hexdigest(),
        provider_after=hashlib.sha256(lowered).hexdigest(),
        template_before=hashlib.sha256(template).hexdigest(),
        template_after=hashlib.sha256(result).hexdigest(),
        replacement_counts=(1, 1, 2), inverse_full_bytes_equal=True)

class ActualFixedPythonChannel(_Channel):
    def exec_command(self, command):
        from test_cases.native_bios_safe_image import require_safe_command
        words = shlex.split(command)
        require_safe_command(Path(__file__).resolve().parents[1], words, self.root)
        if (self.process is not None or words[:2] != ['/usr/bin/python3', '-c']
                or len(words) not in (4, 6)):
            raise AssertionError('only original fixed probe/BIOS launcher')
        self.command = command
        self.process = subprocess.Popen([words[0], '-B', '-c', _OWNED_SUPERVISOR,
            str(self.record), words[2], *words[3:]], cwd=self.root,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root),
                 'TMPDIR': str(self.root), 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True)

