"""Genuine rendered SCP scripts must HOLD on EOF, not fall back.

One whole / three component subcases. Current renderer absence is a capability
FAIL before shell execution, NOT evidence of an exploitable execution path.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_cases import test_ibsw3_scp_stage_scope as BASE

contract = BASE.RUNTIME.contract
component = BASE.RUNTIME.component

GLOBAL = """schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.254
      port: 8088
      http_root: /var/www/html
switches:
- ib:
    version: '25.03.1010'
    upgrade:
      packages:
        os:
          files:
          - file: nvos-amd64-25.02.8008.bin
          - file: nvos-amd64-25.03.1010.bin
        bios:
          file: 0ACQF.cab
          version: '0ACQF_06.01.009'
        cpld:
          burn:
            file: FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
          refresh:
            file: FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
"""


class EmptyScpWireShellBoundaryTests(unittest.TestCase):
    def test_scp_os_bios_cpld_with_eof_wire_refuse_before_transport_or_nv(self):
        node = contract.InventoryDevice('ew-spine01.example', '192.0.2.1',
                                        '02:00:00:00:00:01')
        for selected, index in (('os', 1), ('bios', 0), ('cpld', 0)):
            with self.subTest(component=selected), tempfile.TemporaryDirectory(
                    prefix='ibsw-scp-empty-wire-') as raw:
                root = Path(raw).resolve()
                switch = root / 'switch'
                switch.mkdir(mode=0o700)
                binaries = root / 'bin'
                binaries.mkdir(mode=0o700)
                home = root / 'home'
                home.mkdir(mode=0o700)
                calls = root / 'forbidden-calls'
                calls.write_bytes(b'')
                for command in ('nv', 'ssh', 'scp', 'curl'):
                    stub = binaries / command
                    stub.write_text('#!/bin/sh\nprintf "%s\\n" "' + command
                                    + '" >> "$IBSW_TEST_FORBIDDEN_CALLS"\nexit 97\n')
                    stub.chmod(0o700)
                policy = contract.normalize_upgrade(contract.load_global_text(GLOBAL),
                    selected=(selected,), method='scp',
                    package_dir=str(root / 'no-source-packages'))
                rendered, unsupported = None, None
                try:
                    rendered = component.render_declared_step(policy, node,
                        component=selected, package_index=index,
                        run_id='eof-scp-' + selected, method='scp',
                        switch_dir=str(switch))
                except ValueError as error:
                    unsupported = error
                self.assertIsNone(unsupported,
                    'MISSING_FIXED_SCP_RENDERER_CAPABILITY_SHELL_NOT_REACHED')
                self.assertIn('\nIBSW_METHOD=scp\n', rendered.script)
                self.assertEqual('UNKNOWN', rendered.activation_state)
                script = root / 'step.sh'
                script.write_text(rendered.script)
                environment = {
                    'PATH': str(binaries) + ':/usr/bin:/bin',
                    'HOME': str(home), 'TMPDIR': str(root), 'LC_ALL': 'C',
                    'PYTHONDONTWRITEBYTECODE': '1',
                    'IBSW_TEST_FORBIDDEN_CALLS': str(calls),
                }
                # No inherited credential/BASH_ENV/PYTHONPATH; the real script
                # receives EOF, never a valid source/context/secret envelope.
                result = subprocess.run(
                    ['/bin/bash', '--noprofile', '--norc', '-p', str(script)],
                    cwd=str(root), env=environment, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
                self.assertEqual(64, result.returncode, result.stderr)
                self.assertEqual(b'', calls.read_bytes(),
                    'EOF wire must not invoke nv/ssh/scp/curl or fall back')
                self.assertIn(b'IBSW_EXECUTION_RC=64 IBSW_ACTIVATION_STATE=UNKNOWN',
                              result.stdout)
                for forbidden in (
                    b'IBSW_STAGE=PACKAGE_READY', b'IBSW_STAGE=WAIT_DOWNLOAD_RECORD',
                    b'IBSW_STAGE=IMAGE_FETCH', b'IBSW_STAGE=BIOS_FETCH',
                    b'IBSW_STAGE=INSTALL_REQUESTED', b'IBSW_STAGE=CPLD_BURN',
                    b'IBSW_STAGE=CPLD_REFRESH', b'IBSW_COMPONENT_STAGE=BURN_REQUESTED',
                    b'IBSW_COMPONENT_STAGE=REFRESH_REQUESTED',
                ):
                    self.assertNotIn(forbidden, result.stdout)
                self.assertEqual([], list(switch.iterdir()),
                    'no package, ACK, or content result is fabricated on EOF')
                self.assertFalse((root / 'no-source-packages').exists())
