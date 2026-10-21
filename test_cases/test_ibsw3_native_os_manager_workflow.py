"""SOURCE ONLY canonical OS3 composition, not the historical private two-target test.

Original negative2 and single-target positive bodies are unchanged. The fixed
cold-image decorator owns each complete whole; no controller clears UNKNOWN.
No actual switch/SSH test and no main CLI authority is implied by this source.
"""
import base64
import hashlib
import json
from pathlib import Path
import unittest

from test_cases.native_os_test_isolation import isolated_whole
from test_cases import scp_native_os_manager_fixture as FLOW
from test_cases.native_os_safe_image import validate_image

HOST = 'ew-spine01.example'
PACKAGE = 'nvos-amd64-25.03.1010.bin'
PAYLOAD = b'SYNTHETIC-NOT-FIRMWARE'
ORIGINALS = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh',
             'runner-binding.json', 'scp-source-request.json')


class NativeOsManagerWorkflowTests(unittest.TestCase):
    def require_dispatch(self, result):
        self.assertIsNone(result.carrier_error)
        self.assertTrue(result.preflights, 'actual original source preflight must return first')
        self.assertTrue(result.dispatches,
            'MISSING_NATIVE_SCP_OS_BACKEND after actual source preflight; ACK/fault stages NOT_REACHED')

    @isolated_whole
    def test_single_target_v2_ack_record_precedes_private_fetch_without_releasing_unknown_slot(self):
        image = Path(FLOW.__file__).resolve().parents[1]
        validate_image(image)  # Fail closed BEFORE actual CLI if not safely lowered.
        result = FLOW.exercise(self, two=False, fault=None)
        self.assertIsNone(result.carrier_error)
        self.assertIsNone(result.invoke_error)
        self.assertEqual(2, len(result.factories))
        self.assertEqual(1, len(result.freezes))
        self.assertEqual(1, len(result.preflights))
        self.assertEqual([22], result.selected_nonempty_reads)
        self.assertEqual([], result.unselected_reads)
        self.assertEqual([], result.after_freeze_reads)
        self.assertEqual(1, len(result.dispatches))
        leaf, dispatch = result.dispatches[0]
        self.assertEqual(HOST, leaf.node.hostname)
        self.assertEqual(('os', 1, 'os-0001', 'DISPATCHED_UNKNOWN'),
                         (dispatch.component, dispatch.package_index, dispatch.stage, dispatch.state))
        # Observe every original context return. Revalidation is allowed; it is
        # not another request or a reason to drop observations from the fixture.
        self.assertTrue(result.contexts)
        child, original_leaf, parent, stage, held, raw = result.contexts[0]
        self.assertIs(leaf, original_leaf)
        self.assertEqual(set(ORIGINALS), set(held))
        for current_child, current_leaf, current_parent, current_stage, current_held, current_raw in result.contexts:
            self.assertIs(child, current_child)
            self.assertIs(leaf, current_leaf)
            self.assertIs(parent, current_parent)
            self.assertEqual(stage, current_stage)
            self.assertTrue(current_raw == raw, 'same private context bytes; never print credential frame')
            self.assertEqual(set(ORIGINALS), set(current_held))
            for name in ORIGINALS:
                self.assertIs(held[name], current_held[name])
                self.assertIs(child.files[(str(stage), name)], held[name])
        self.assertIs(child._native_parent, parent)
        self.assertIs(child._package_source_owner, parent._package_source_owner)
        self.assertEqual('os', json.loads(held['step-binding.json'].payload)['component'])
        dispatch_raw = (stage / 'component-dispatch.json').read_bytes()
        saved_dispatch = json.loads(dispatch_raw)
        self.assertEqual('SCP_STDIN_OWNED_RUNNER_V2', saved_dispatch['launch_kind'])
        self.assertEqual(hashlib.sha256(held['scp-source-request.json'].payload).hexdigest(),
                         saved_dispatch['scp_companion_sha256'])
        bound = [values for actual_leaf, actual_dispatch, values in result.bound
                 if actual_leaf is leaf and actual_dispatch is dispatch]
        self.assertTrue(bound, 'actual original bound consumer must return')
        self.assertTrue(all(values[0] is child for values in bound))
        self.assertEqual([93], [value['child_exit_code'] for value in result.manager_results
                              if value.get('child_exit_code') is not None])
        self.assertEqual(1, len(result.records))
        self.assertEqual(1, len(result.acks))
        self.assertEqual(1, len(result.nv_calls))
        ack, record = result.acks[0], result.records[0]
        self.assertEqual(HOST, ack['host'])
        self.assertEqual(HOST, record['host'])
        content, line = ack['content'], ack['line']
        self.assertTrue(content.startswith(b'IBSW_SCP_CONTENT_VERIFIED=1|'))
        self.assertTrue(line.startswith(b'IBSW_SCP_DOWNLOAD_RESULT=1|'))
        self.assertNotIn(b'\n', content)
        self.assertNotIn(b'\n', line)
        self.assertEqual(b'IBSW_SCP_DOWNLOAD_ACK_V2|' + child.run_id.encode('ascii') + b'|'
            + hashlib.sha256(content).hexdigest().encode('ascii') + b'|' + line + b'\n', ack['bytes'])
        saved = json.loads(record['path'].read_bytes())
        self.assertEqual(2, saved['schema_version'])
        self.assertEqual('SCP_DOWNLOAD_MEASUREMENT_DATA_ONLY', saved['state'])
        self.assertEqual('os', saved['binding']['component'])
        self.assertEqual(hashlib.sha256(dispatch_raw).hexdigest(), saved['dispatch_sha256'])
        self.assertEqual(hashlib.sha256(held['request.json'].payload).hexdigest(), saved['request_sha256'])
        self.assertEqual(hashlib.sha256(held['scp-source-request.json'].payload).hexdigest(),
                         saved['companion_sha256'])
        self.assertEqual(content + b'\n' + line + b'\n',
                         base64.b64decode(saved['raw_lines_base64'], validate=True))
        order = result.events_for(HOST)
        self.assertLess(order['file_sync'], order['directory_sync'])
        self.assertLess(order['directory_sync'], order['writer_finish'])
        self.assertLess(order['writer_finish'], order['record_return'])
        self.assertLess(order['record_return'], ack['order'])
        self.assertLess(ack['order'], result.nv_order_for(HOST))
        self.assertEqual(['action', 'fetch', 'system', 'image',
                          'file://' + str(result.switch / PACKAGE)], result.nv_calls[0]['argv'])
        code, report, error, calls, installs = result.result
        self.assertNotEqual(0, code)
        self.assertEqual([], installs)
        self.assertEqual([dict(hostname=HOST, state='UNKNOWN')], report['targets'])
        self.assertEqual([HOST], report['unresolved_in_flight'])
        self.assertEqual(dict(upgrade_workers=1, verification_workers=1, in_flight_limit=1),
                         report['scheduler'])
        self.assertEqual(1, report['ready_ib_count'])
        self.assertEqual(1, len(report['component_results']))
        self.assertIn('INSTALLER_EXIT_NONZERO_BEFORE_REBOOT', report['component_results'][0]['reason'])
        self.assertFalse(any(command.startswith(('nv config patch ', 'nv config apply', 'nv config save'))
                             for host, command in calls))
        self.assertTrue(result.owner_receipts)
        self.assertTrue(all(not receipt['unknown'] and receipt['all_original_streams_closed']
                            for receipt in result.owner_receipts))
        self.assertFalse(result.cancelled)
        self.assertEqual([], result.secret_leaks)
        validate_image(image)

    @isolated_whole
    def test_native_scp_os_missing_or_wrong_content_keeps_manager_ack_absent(self):
        for fault in ('missing_content', 'wrong_content'):
            with self.subTest(fault=fault):
                result = FLOW.exercise(self, two=False, fault=fault)
                self.require_dispatch(result)
                self.assertEqual(1, len(result.dispatches), 'single selected target, not batch-stop policy')
                self.assertTrue(result.fault_fired)
                self.assertTrue(result.fault_same_inode)
                self.assertTrue(result.success_line_preserved)
                self.assertEqual([], result.acks)
                self.assertEqual([], result.nv_calls)
                self.assertEqual([], result.invocation_installs)
                self.assertTrue(result.invoke_error is None or isinstance(result.invoke_error, FLOW.SharedUpgradeHold))
                if result.result is not None:
                    self.assertNotEqual(0, result.result[0])
                else:
                    self.assertIsInstance(result.invoke_error, FLOW.SharedUpgradeHold)
                self.assertTrue(result.cancelled, 'explicit test owner cancellation, not natural300s wait')
                self.assertEqual([], result.dispatches_after_fault)
                for child, leaf, parent, stage, held, raw in result.contexts:
                    self.assertTrue((stage / 'request.json').is_file())
                    self.assertTrue((stage / 'scp-source-request.json').is_file())
                self.assertEqual([], result.secret_leaks)

    @isolated_whole
    def test_native_scp_os_critical_measurement_commit_failure_withholds_ack(self):
        for fault in ('record_file_sync', 'record_directory_sync', 'record_writer_close'):
            with self.subTest(fault=fault):
                # Single target makes zeroACK global assertion exact. Actual
                # Shared/batch stop is observed, not a new target-failure policy.
                result = FLOW.exercise(self, two=False, fault=fault)
                self.require_dispatch(result)
                self.assertTrue(result.fault_fired)
                self.assertTrue(result.record_shared_errors, 'actual original record SharedUpgradeHold')
                self.assertTrue(result.shared_stop)
                self.assertEqual(1, len(result.dispatches))
                self.assertEqual([], result.dispatches_after_fault)
                self.assertEqual([], result.acks)
                self.assertEqual([], result.nv_calls)
                self.assertEqual([], result.invocation_installs)
                self.assertTrue(result.invoke_error is None or isinstance(result.invoke_error, FLOW.SharedUpgradeHold))
                if result.result is not None:
                    self.assertNotEqual(0, result.result[0])
                else:
                    self.assertIsInstance(result.invoke_error, FLOW.SharedUpgradeHold)
                self.assertTrue(result.cancelled)
                self.assertEqual(1, result.fault_attempts, 'no critical IO retry or record refresh')
                if fault == 'record_writer_close':
                    self.assertTrue(result.real_close_ebadf)
                self.assertTrue(all((stage / 'request.json').is_file()
                    and (stage / 'scp-source-request.json').is_file()
                    for child, leaf, parent, stage, held, raw in result.contexts))
                self.assertEqual([], result.secret_leaks)

