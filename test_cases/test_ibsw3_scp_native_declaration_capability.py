"""Declaration capability preconditions, NOT a native-SCP/zero-ACK behavior proof.

Only declarations and actual private request originals are prepared. The current
CLI remains HTTP-only. No transport/source grant or component dispatch is faked.
"""
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_scp_stage_scope as BASE

driver = BASE.driver
component = BASE.RUNTIME.component
contract = BASE.RUNTIME.contract

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
"""


class NativeScpDeclarationCapabilityTests(unittest.TestCase):
    def test_real_contract_to_renderer_supports_an_explicit_scp_declaration(self):
        policy = contract.normalize_upgrade(contract.load_global_text(GLOBAL),
            selected=('os',), method='scp')
        node = contract.InventoryDevice('ew-spine01.example', '192.0.2.1',
                                        '02:00:00:00:00:01')
        rendered, unsupported = None, None
        try:
            rendered = component.render_declared_step(policy, node, component='os',
                package_index=1, run_id='scp-capability', method='scp',
                switch_dir='/home/admin')
        except ValueError as error:
            # Record unsupported capability as a literal FAIL, not import ERROR
            # or a claimed reproduced native-manager exploit.
            unsupported = error
        self.assertIsNone(unsupported,
            'MISSING_FIXED_SCP_DECLARATION_CAPABILITY_NOT_A_ZERO_ACK_VULNERABILITY')
        self.assertEqual('25.03.1010', rendered.target_version)
        self.assertEqual('UNKNOWN', rendered.activation_state)
        self.assertIn('\nIBSW_METHOD=scp\n', rendered.script)
        self.assertNotIn('http://', rendered.script)
        self.assertNotIn('https://', rendered.script)

    @contextlib.contextmanager
    def prepared_request(self, method):
        # The three callers below use only literal method values. This fixture
        # does not open actual package paths; package selection remains a plan.
        if method not in ('scp', 'http'):
            raise AssertionError('fixed capability fixture methods only')
        manual = BASE.manual.ManualTests()
        with tempfile.TemporaryDirectory(prefix='ibsw-scp-declaration-') as raw:
            root = Path(raw).resolve()
            project, home, known, logs = manual.fixture(root)
            arguments = list(manual.arguments(project))
            self.assertEqual(1, arguments.count('--method'))
            self.assertEqual('local', arguments[arguments.index('--method') + 1])
            arguments[arguments.index('--method') + 1] = method
            arguments = tuple(arguments)
            result = dict(unsupported=None, script=None, request=None,
                          dispatch_present=False, ack_present=False)
            with manual.no_deployment_or_filesystem_locks(), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('no native child')), \
                 patch.object(socket, 'create_connection', side_effect=AssertionError('no network')):
                prepared = driver.prepare_manual_run(BASE.app.__file__, str(project), arguments)
                run = Path(prepared['run_directory'])
                with driver.open_manual_run(BASE.app.__file__, str(project), arguments,
                                            prepared['run_directory']) as scope:
                    result['parsed_method'] = scope.parsed.method
                    try:
                        scope.prepare_requested_step(BASE.HOST, 'os', 1)
                    except ValueError as error:
                        result['unsupported'] = error
                    if result['unsupported'] is None:
                        scope.request_prepared_step(BASE.HOST, 'os', 1)
                    scope.verify()
                # Original scope/input owners are closed; tree still exists.
                result['plan'] = json.loads((run / 'plan.json').read_bytes())
                stage = run / BASE.HOST / 'os-0001'
                if result['unsupported'] is None:
                    result['script'] = (stage / 'step.sh').read_bytes()
                    result['request'] = json.loads((stage / 'request.json').read_bytes())
                result['dispatch_present'] = (stage / 'component-dispatch.json').exists()
                result['ack_present'] = (stage / 'download-ack').exists()
            yield result

    def test_real_scp_plan_scope_prepares_original_request_without_dispatch(self):
        with self.prepared_request('scp') as result:
            self.assertEqual('scp', result['parsed_method'])
            self.assertEqual('scp', result['plan']['method'])
            self.assertEqual('NOT_EXECUTED', result['plan']['execution_state'])
            self.assertIsNone(result['unsupported'],
                'MISSING_FIXED_SCP_REQUEST_GRAPH_CAPABILITY_MANAGER_NOT_REACHED')
            self.assertIn(b'\nIBSW_METHOD=scp\n', result['script'])
            self.assertEqual('REQUESTED', result['request']['state'])
            self.assertEqual('UNKNOWN', result['request']['activation_state'])
            self.assertEqual('NOT_EXECUTED', result['request']['execution_state'])
            self.assertRegex(result['request']['request_id'], r'^[0-9a-f]{32}$')
            self.assertFalse(result['dispatch_present'])
            self.assertFalse(result['ack_present'])

    def test_real_http_plan_scope_keeps_its_original_request_control(self):
        with self.prepared_request('http') as result:
            self.assertIsNone(result['unsupported'])
            self.assertEqual('http', result['parsed_method'])
            self.assertEqual('http', result['plan']['method'])
            self.assertEqual('NOT_EXECUTED', result['plan']['execution_state'])
            self.assertIn(b'\nIBSW_METHOD=http\n', result['script'])
            self.assertEqual('REQUESTED', result['request']['state'])
            self.assertEqual('UNKNOWN', result['request']['activation_state'])
            self.assertEqual('NOT_EXECUTED', result['request']['execution_state'])
            self.assertRegex(result['request']['request_id'], r'^[0-9a-f]{32}$')
            self.assertFalse(result['dispatch_present'])
            self.assertFalse(result['ack_present'])
