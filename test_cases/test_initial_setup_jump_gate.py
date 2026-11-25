"""WP-2 independent contracts, guide r494 :517-587/K1-K5/D34-O10-O12.

Expected classes, eight slots and two 240-second cooldowns are specification
constants, not calculated from product output. All device IO below is a named
model. Real scheduler/record/attention paths execute; clocks never really wait.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_eth_jump_transport_contract as transport
from test_cases.native_cpld_physical_io import owned_test_root

READBACK = ('nv set system hostname EXAMPLE-IB01\n'
            'nv set interface eth0 ipv4 address 203.0.113.2/24\n'
            'nv set interface eth0 ipv4 gateway 203.0.113.1\n'
            'nv set interface eth0-1 link state up\n'
            'nv set interface eth0-1 type eth\n'
            'nv set system config auto-save state enabled\n'
            'nv set system ztp config-save enabled\n')


class Clock:
    def __init__(self, test, app):
        self.test, self.app, self.now, self.waits = test, app, 0.0, []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.test.assertIsNone(self.app._TASK_DEADLINE, 'cooldown is outside the task deadline')
        self.waits.append(seconds)
        self.now += seconds


class JumpGateTests(unittest.TestCase):
    def setUp(self):
        owned_root = owned_test_root()
        self.app = transport.load_module('wp2_jump_gate', transport.INITIAL_SETUP)
        self.temp = tempfile.TemporaryDirectory(prefix='wp2-direct-', dir=owned_root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.jump = self.app.Device('EXAMPLE-JUMP01', 'eth_jump', '192.0.2.10', '192.0.2.10', '', '', '', '')
        self.ib = self.app.Device('EXAMPLE-IB01', 'ib', '203.0.113.2', '203.0.113.2/24',
                                  '203.0.113.1', '', '', '')
        self.target = self.app.Target(self.ib, self.jump, 'swp1', 'eth0')
        self.neighbor = self.app.Neighbor('fe80::17', 'vlan1', '02:00:00:00:00:17')
        self.task = self.app.PreparedIBTask(self.target, self.neighbor, '', False)
        self.args = SimpleNamespace(apply=True, yes=True, force=False, verbose=False,
                                    eth_user='cumulus', ib_user='admin', connect_timeout=2,
                                    execution_mode='management', max_workers=16, task_timeout=30,
                                    report=self.root / 'report.log')

    def failure(self):
        return self.app.SshFailure(self.app.SshFailureKind.JUMP_UNREACHABLE,
                                   'outer', '192.0.2.10', 'EXAMPLE-JUMP01')

    def gate(self):
        self.assertTrue(hasattr(self.app, 'JumpGate'), 'guide :522 requires the coordinator JumpGate')
        return self.app.JumpGate()

    def test_outer_network_failures_are_jump_unreachable(self):
        messages = [
            'ssh: connect to host 192.0.2.10 port 22: ' + reason
            for reason in ('Connection timed out', 'Connection refused', 'No route to host', 'Network is unreachable')
        ] + ['Connection timed out during banner exchange',
             'kex_exchange_identification: Connection closed by remote host',
             'Connection closed by 192.0.2.10 port 22', 'Connection reset by 192.0.2.10',
             'Control socket connect(/PUBLIC/socket): Connection refused',
             'mux_client_request_session: session request failed']
        for text in messages:
            with self.subTest(message=text):
                error = self.app.classify_ssh_failure(text, outer_address='192.0.2.10', inner_address=None)
                self.assertIsInstance(error, self.app.SshFailure)
                self.assertEqual(('OOB_JUMP_UNREACHABLE', 'outer', '192.0.2.10'),
                                 (error.kind.value, error.hop, error.address))
        for unrelated in ('192.0.2.100', '192.0.2.101', '203.0.113.2'):
            with self.subTest(unrelated=unrelated):
                error = self.app.classify_ssh_failure(
                    'ssh: connect to host ' + unrelated + ' port 22: Connection refused',
                    outer_address='192.0.2.10', inner_address='fe80::17')
                self.assertTrue(error is None or error.hop != 'outer', 'match address tokens, not substrings')

    def test_inner_and_direct_failures_are_not_jump_unreachable(self):
        for address in ('fe80::17', '203.0.113.2'):
            text = 'ssh: connect to host ' + address + ' port 22: Connection refused'
            with self.subTest(address=address):
                error = self.app.classify_ssh_failure(text, outer_address='192.0.2.10', inner_address=address)
                self.assertTrue(error is None or error.hop == 'inner')
                direct = self.app.classify_ssh_failure(text, outer_address=None, inner_address=address)
                self.assertIsInstance(direct, self.app.SshFailure)
                self.assertEqual(('DIRECT_SSH_NETWORK', 'direct', address),
                                 (direct.kind.value, direct.hop, direct.address))

    def execute_stage_failure(self, stage):
        app, failure = self.app, self.failure()
        # O5 still runs in this device-local stage test. Only its explicit
        # link-local read receives the MAC for the independent CSV fixture.
        checked_task = replace(self.task, target=replace(
            self.target, ib=replace(self.ib, eth0_mac="02:00:00:00:00:17")))
        setter = ["nv", "set", "interface", "eth0", "link", "state", "up"]

        def stage_command(_target, _neighbor, _eth_user, _eth_pass, _ib_user, _current, _timeout, command, **_kwargs):
            if command == ["ip", "addr", "show", "eth0"]:
                return app.SessionResult(
                    "2: eth0: <UP> mtu 1500 state UP\n"
                    "    link/ether 02:00:00:00:00:17 brd ff:ff:ff:ff:ff:ff\n", 0)
            if stage == "day0" and command == setter:
                raise failure
            return app.SessionResult(READBACK, 0)

        models = {
            'inspect_ib_device': (app.SessionResult(READBACK, 0), 'PUBLIC-IB-Current-71!', True),
            'run_initial_stage': (READBACK, True), 'base_stage_needed': True,
            '_management_network_commands': [setter],
            '_require_empty_pending': None,
            # U3 (v3.1.6 D1c): the write stages' pending read now enters here; empty diff.
            '_settle_owned_pending': None,
            'verify_state': None, '_verify_management_network_state': None,
            'verify_ipv4_login': None, 'run_service_stage': (True, True),
            'run_key_stage': True, 'run_management_direct_checks': [],
        }
        point = {'authentication': 'inspect_ib_device', 'initial': 'run_initial_stage',
                 'day0': None, 'ipv4_readiness': 'verify_ipv4_login',
                 'services': 'run_service_stage', 'public_keys': 'run_key_stage'}[stage]
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "_stage_ib_command", side_effect=stage_command))
            for name, value in models.items():
                stack.enter_context(mock.patch.object(app, name,
                    side_effect=failure if name == point else None, return_value=value))
            stack.enter_context(mock.patch.object(app, 'log'))
            return app.execute_ib_task(checked_task, self.args, None, 'PUBLIC-Initial-72!', None, [], None, True)

    def test_every_stage_jump_timeout_has_one_category(self):
        for stage in ('authentication', 'initial', 'day0', 'ipv4_readiness', 'services', 'public_keys'):
            with self.subTest(stage=stage):
                record = self.execute_stage_failure(stage)
                self.assertEqual('OOB_JUMP_UNREACHABLE', record.get('failure_kind'))
                self.assertEqual('FAILED_OOB_JUMP_UNREACHABLE', self.app.record_category(record))
                attention = self.app.initial_setup_attention({'example-ib01': record}, [])
                self.assertEqual(['FAILED_OOB_JUMP_UNREACHABLE'], [item['category'] for item in attention])
        # The real Initial helper performs the specific nv show system ztp read.
        with mock.patch.object(self.app, '_stage_ib_command', side_effect=self.failure()) as command:
            with self.assertRaises(self.app.SshFailure):
                self.app.run_initial_stage(self.target, self.neighbor, 'cumulus', '', 'admin', 2,
                                           READBACK, local=False, apply=False, authorized=True,
                                           ib_password='PUBLIC-Current-73!')
        self.assertEqual(['nv', 'show', 'system', 'ztp'], command.call_args.args[7])

    def test_jump_authentication_is_its_own_category(self):
        record = {'hostname': 'EXAMPLE-IB01', 'outcome': 'FAILED',
                  'failure_kind': 'OOB_JUMP_AUTHENTICATION', 'failed_stage': 'authentication'}
        self.assertEqual('FAILED_OOB_JUMP_AUTHENTICATION', self.app.record_category(record))
        self.assertEqual('FAILED_OOB_JUMP_AUTHENTICATION',
                         self.app.initial_setup_attention({'example-ib01': record}, [])[0]['category'])

    def test_record_category_and_attention_read_the_same_table(self):
        self.assertTrue(hasattr(self.app, 'FAILURE_KIND_CATEGORY'), 'guide :520 requires one ordered table')
        # r508 WP5 items7/8 + K4: append the approved readonly pending row;
        # preserve the original four rows/order and exact equality, never subset.
        # I-037 rule 7 adds a separate initial-direct status, distinct from
        # the legacy final Stage 5 direct SSH network-probe status.
        expected = ('DIRECT_SSH_NETWORK', 'DIRECT_LOGIN_NETWORK', 'OOB_JUMP_UNREACHABLE',
                    'OOB_JUMP_AUTHENTICATION', 'TARGET_HOST_KEY_CHANGED',
                    'HOST_KEY_REFRESH_PENDING')
        self.assertEqual(expected, tuple(self.app.FAILURE_KIND_CATEGORY))
        table = dict(self.app.FAILURE_KIND_CATEGORY, FUTURE_DECLARED_KIND='FAILED_FUTURE_DECLARED_KIND')
        record = {'hostname': 'EXAMPLE-IB01', 'outcome': 'FAILED', 'failure_kind': 'FUTURE_DECLARED_KIND'}
        with mock.patch.object(self.app, 'FAILURE_KIND_CATEGORY', table):
            self.assertEqual('FAILED_FUTURE_DECLARED_KIND', self.app.record_category(record))
            with mock.patch.object(self.app, 'record_category', return_value='WRONG_LEGACY_CATEGORY'):
                self.assertEqual('FAILED_FUTURE_DECLARED_KIND',
                                 self.app.initial_setup_attention({'example-ib01': record}, [])[0]['category'])

    def test_per_jump_in_flight_cap_and_no_jump_tasks(self):
        gate = self.gate()
        self.assertEqual([True] * 8 + [False], [gate.claim_jump_slot('example-jump01', 0) for _ in range(9)])
        self.assertTrue(all(gate.claim_jump_slot(None, 0) for _ in range(20)))
        self.assertFalse(gate.jump_slot_available('example-jump01', 0))
        self.assertEqual('done', gate.report_jump_outcome('example-jump01', None, writes_attempted=False, now=0))
        self.assertTrue(gate.jump_slot_available('example-jump01', 0))
        self.assertEqual('fail', gate.report_jump_outcome(None, self.failure(), writes_attempted=False, now=0))

    def test_cooling_requeues_unwritten_and_never_replays_writes(self):
        gate, failure = self.gate(), self.failure()
        for _ in range(2):
            self.assertTrue(gate.claim_jump_slot('example-jump01', 0))
            self.assertEqual('requeue', gate.report_jump_outcome('example-jump01', failure,
                             writes_attempted=False, now=0))
        self.assertFalse(gate.jump_slot_available('example-jump01', 239))
        self.assertEqual(['example-jump01'], gate.jump_probes_due(240))
        gate.report_jump_probe('example-jump01', failure, now=240)
        self.assertEqual(['example-jump01'], gate.jump_probes_due(480))
        gate.report_jump_probe('example-jump01', failure, now=480)
        self.assertTrue(gate.jump_exhausted('example-jump01'))
        self.assertEqual('fail', gate.report_jump_outcome('example-jump01', failure, writes_attempted=False, now=480))
        other = self.gate()
        self.assertTrue(other.claim_jump_slot('example-jump02', 0))
        self.assertEqual('fail', other.report_jump_outcome('example-jump02', failure, writes_attempted=True, now=0))
        # A completed master with an earlier failed candidate is one success, not a failure report.
        other.report_jump_outcome('example-jump03', failure, writes_attempted=False, now=0)
        other.report_jump_outcome('example-jump03', None, writes_attempted=False, now=0)
        other.report_jump_outcome('example-jump03', failure, writes_attempted=False, now=0)
        self.assertTrue(other.jump_slot_available('example-jump03', 0))

    def run_requeued_scheduler(self, *, managed):
        app = self.app
        clock = Clock(self, app)
        attempts, receipts, finalizations = [], [], []
        cycle = SimpleNamespace(complete=lambda *args: receipts.append(clock.now) or True,
                                fail_unfinished=lambda target: finalizations.append(clock.now)) if managed else None
        sessions = SimpleNamespace(records={'example-jump01': {'address': '192.0.2.10'}},
                                   ensure_jump_master=mock.Mock(), probe_jump_master=mock.Mock())
        def execute(*args):
            attempts.append((clock.now, app._TASK_DEADLINE))
            if len(attempts) < 3:
                return {'hostname': 'EXAMPLE-IB01', 'outcome': 'FAILED', 'failure_kind': 'OOB_JUMP_UNREACHABLE',
                        'reason': 'PUBLIC jump unavailable', 'direct_rows': [], 'batch_error': ''}
            return {'hostname': 'EXAMPLE-IB01', 'outcome': 'ALREADY_CONFIGURED', 'direct_rows': [], 'batch_error': ''}
        with mock.patch.object(app.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(app.time, 'sleep', side_effect=clock.sleep), \
                mock.patch.object(app, 'execute_ib_task', side_effect=execute), \
                mock.patch.object(app, '_JUMP_SESSIONS', sessions), \
                mock.patch.object(app, 'log'):
            result = app.run_prepared_tasks([self.task], self.args, None, 'PUBLIC-Initial-72!', None, [], None,
                                           method_cycle=cycle)
        return result, clock, attempts, receipts, finalizations

    def test_cooling_does_not_consume_task_timeout(self):
        result, clock, attempts, _, _ = self.run_requeued_scheduler(managed=False)
        self.assertEqual(3, len(attempts))
        self.assertEqual([240], clock.waits)
        self.assertEqual([(0, 30), (0, 30), (240, 270)], attempts)
        self.assertEqual('ALREADY_CONFIGURED', result['records']['example-ib01']['outcome'])

    def test_snapshot_phase_cools_once_after_a_full_pass(self):
        self.assertTrue(hasattr(self.app, 'collect_jump_snapshot_passes'), 'guide :530 full snapshot passes')
        devices = [self.app.replace(self.jump, hostname='EXAMPLE-JUMP0' + str(i), login_ip='192.0.2.' + str(9+i))
                   for i in (1, 2, 3)]
        clock, events, tried = Clock(self, self.app), [], set()
        def collect(device):
            events.append(device.hostname)
            if device.hostname in ('EXAMPLE-JUMP01', 'EXAMPLE-JUMP02') and device.hostname not in tried:
                tried.add(device.hostname)
                raise self.app.SshFailure(self.app.SshFailureKind.JUMP_UNREACHABLE, 'outer',
                                          device.login_ip, device.hostname)
        with mock.patch.object(self.app.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(self.app.time, 'sleep', side_effect=clock.sleep), \
                mock.patch.object(self.app, '_JUMP_SESSIONS', SimpleNamespace(ensure_jump_master=mock.Mock(), probe_jump_master=mock.Mock())):
            failures = self.app.collect_jump_snapshot_passes(devices, collect)
        self.assertEqual(['EXAMPLE-JUMP01', 'EXAMPLE-JUMP02', 'EXAMPLE-JUMP03', 'EXAMPLE-JUMP01', 'EXAMPLE-JUMP02'], events)
        self.assertEqual([240], clock.waits)
        self.assertEqual({}, failures)

    def test_single_slot_requeue_completes_method_cycle_once(self):
        result, clock, attempts, receipts, finalizations = self.run_requeued_scheduler(managed=True)
        self.assertEqual(3, len(attempts))
        self.assertEqual([240], receipts)
        self.assertEqual([240], finalizations)
        self.assertEqual('', result['fatal'])

    def test_record_has_stable_jump_fields(self):
        app = self.app
        sessions = SimpleNamespace(records={'example-jump01': {'address': '192.0.2.11'}})
        with mock.patch.object(app, 'execute_ib_task', return_value={'outcome': 'ALREADY_CONFIGURED'}), \
                mock.patch.object(app, '_JUMP_SESSIONS', sessions), mock.patch.object(app, 'log'):
            result = app.run_prepared_tasks([self.task], self.args, None, '', None, [], None)
        record = result['records']['example-ib01']
        self.assertEqual('CHECKED_EXISTING_CONFIGURATION', record.get('category'))
        self.assertIn('failure_kind', record)
        self.assertFalse(record['writes_attempted'])
        self.assertEqual({'hostname': 'EXAMPLE-JUMP01', 'login_ip': '192.0.2.11', 'type': 'eth_jump',
                          'interface': 'vlan1', 'vrf': 'default', 'access_vlan': None,
                          'selection_reason': 'LEAF_LOCAL_PATH'}, record['jump'])

    def test_actual_inline_write_failure_is_not_replayed(self):
        app, calls = self.app, []
        def execute(*args):
            calls.append('attempt')
            app._ACTIVE_COORDINATOR.writes_attempted = True
            return {'outcome': 'FAILED', 'failure_kind': 'OOB_JUMP_UNREACHABLE',
                    'reason': 'PUBLIC network failure after a write permit'}
        with mock.patch.object(app, 'execute_ib_task', side_effect=execute), \
                mock.patch.object(app, 'log'), \
                mock.patch.object(app.time, 'sleep', side_effect=AssertionError('written task must not cool/replay')):
            result = app.run_prepared_tasks([self.task], self.args, None, '', None, [], None)
        record = result['records']['example-ib01']
        self.assertEqual(['attempt'], calls)
        self.assertEqual('FAILED_OOB_JUMP_UNREACHABLE', record['category'])
        self.assertTrue(record['writes_attempted'])
        self.assertIn('result unverified', record['reason'])
        self.assertIn('no automatic replay', record['reason'])

    def test_actual_inline_exhaustion_finishes_remaining_without_dispatch(self):
        app, clock, attempts = self.app, Clock(self, self.app), []
        other = app.replace(self.task, target=app.replace(self.target,
                            ib=app.replace(self.ib, hostname='EXAMPLE-IB02')))
        def execute(task, *args):
            attempts.append(task.target.ib.hostname)
            self.assertLessEqual(len(attempts), 2, 'exhausted tasks must not be dispatched again')
            return {'outcome': 'FAILED', 'failure_kind': 'OOB_JUMP_UNREACHABLE'}
        sessions = SimpleNamespace(records={}, probe_jump_master=mock.Mock(side_effect=self.failure()))
        with mock.patch.object(app.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(app.time, 'sleep', side_effect=clock.sleep), \
                mock.patch.object(app, 'execute_ib_task', side_effect=execute), \
                mock.patch.object(app, '_JUMP_SESSIONS', sessions), mock.patch.object(app, 'log'):
            result = app.run_prepared_tasks([self.task, other], self.args, None, '', None, [], None)
        self.assertEqual(['EXAMPLE-IB01', 'EXAMPLE-IB02'], attempts)
        self.assertEqual([240, 240], clock.waits)
        self.assertEqual(2, sessions.probe_jump_master.call_count)
        self.assertEqual(['FAILED_OOB_JUMP_UNREACHABLE'] * 2,
                         [result['records'][name]['category'] for name in ('example-ib01', 'example-ib02')])

    def test_all_candidates_failure_cools_without_counting_candidate_success(self):
        gate, failure = self.gate(), self.failure()
        failure.candidates_exhausted = True
        gate.claim_jump_slot('example-jump01', 0)
        self.assertEqual('requeue', gate.report_jump_outcome('example-jump01', failure,
                         writes_attempted=False, now=0))
        self.assertEqual([], gate.jump_probes_due(239))
        self.assertEqual(['example-jump01'], gate.jump_probes_due(240))
        gate.report_jump_probe('example-jump01', None, now=240)
        gate.claim_jump_slot('example-jump01', 240)
        self.assertEqual('requeue', gate.report_jump_outcome('example-jump01', self.failure(),
                         writes_attempted=False, now=240))
        self.assertTrue(gate.jump_slot_available('example-jump01', 240))

    def test_no_jump_task_uses_real_inline_queue_and_null_record(self):
        app = self.app
        direct = app.replace(self.task, target=app.replace(self.target, ethernet=None))
        with mock.patch.object(app, 'execute_ib_task', return_value={'outcome': 'ALREADY_CONFIGURED'}) as execute, \
                mock.patch.object(app, 'log'):
            result = app.run_prepared_tasks([direct], self.args, None, '', None, [], None)
        self.assertEqual(1, execute.call_count)
        record = result['records']['example-ib01']
        self.assertIsNone(record['jump'])
        self.assertIsNone(record['oob'])
        self.assertIsNone(record['failure_kind'])

    def test_snapshot_authentication_is_not_network_and_is_not_retried(self):
        app = self.app
        failure = app.SshFailure(app.SshFailureKind.JUMP_AUTHENTICATION,
                                 'outer', '192.0.2.11', 'EXAMPLE-JUMP01')
        outcomes, records = {}, {}
        sessions = SimpleNamespace(records={'example-jump01': {'address': '192.0.2.11'}},
                                   probe_jump_master=mock.Mock())
        with mock.patch.object(app, '_JUMP_SESSIONS', sessions), \
                mock.patch.object(app.time, 'sleep', side_effect=AssertionError('auth is not a cooldown')):
            failures = app.collect_jump_snapshot_passes([self.jump], mock.Mock(side_effect=failure))
            with mock.patch.object(app, 'log'):
                ready = app.prepare_ready_ib_tasks([self.target], self.args, {}, {}, {}, {},
                                                  failures, outcomes, records)
        self.assertEqual([], ready)
        sessions.probe_jump_master.assert_not_called()
        record = records['example-ib01']
        self.assertEqual('FAILED', record['outcome'])
        self.assertEqual('OOB_JUMP_AUTHENTICATION', record['failure_kind'])
        self.assertEqual('FAILED_OOB_JUMP_AUTHENTICATION', record['category'])
        self.assertEqual('FAILED_OOB_JUMP_AUTHENTICATION',
                         app.initial_setup_attention(records, [])[0]['category'])
        self.assertEqual(('192.0.2.11', 'eth_jump', False),
                         (record['jump']['login_ip'], record['jump']['type'], record['writes_attempted']))

    def test_snapshot_control_flow_and_program_errors_propagate(self):
        app = self.app
        for kind in (app.ProjectInputChanged, app.BatchStopped, KeyboardInterrupt, SystemExit, ValueError):
            with self.subTest(error=kind.__name__):
                error = kind('PUBLIC stop')
                with self.assertRaises(kind) as caught:
                    app.collect_jump_snapshot_passes([self.jump], mock.Mock(side_effect=error))
                self.assertIs(error, caught.exception)

    def test_snapshot_authority_precedes_recovery_probe(self):
        app, clock, calls = self.app, Clock(self, self.app), []
        authority = SimpleNamespace(assert_unchanged=mock.Mock())
        stopped = app.ProjectInputChanged('PUBLIC input changed while cooling')
        def collect(device):
            calls.append(device.hostname)
            authority.assert_unchanged.side_effect = stopped
            raise self.failure()
        sessions = SimpleNamespace(probe_jump_master=mock.Mock())
        with mock.patch.object(app.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(app.time, 'sleep', side_effect=clock.sleep), \
                mock.patch.object(app, '_JUMP_SESSIONS', sessions):
            with self.assertRaises(app.ProjectInputChanged) as caught:
                app.collect_jump_snapshot_passes([self.jump], collect, authority=authority)
        self.assertIs(stopped, caught.exception)
        self.assertEqual(['EXAMPLE-JUMP01'], calls)
        self.assertEqual([240], clock.waits)
        sessions.probe_jump_master.assert_not_called()

    def test_real_fork_dispatch_never_admits_ninth_same_jump_task(self):
        # 129 tasks independently imply nine global workers by the existing N/16 rule.
        # Real child processes only run this named model; no transport/process IO is inherited.
        app, context = self.app, self.app.multiprocessing.get_context('fork')
        active, peak, hits = context.Value('i', 0), context.Value('i', 0), context.Array('i', 129)
        lock, first_wave, ninth_admitted = context.Lock(), context.Event(), context.Event()
        tasks = [app.replace(self.task, target=app.replace(self.target,
                    ib=app.replace(self.ib, hostname=f'EXAMPLE-IB{number:03d}')))
                 for number in range(129)]
        def execute(task, *args):
            index = int(task.target.ib.hostname[-3:])
            with lock:
                hits[index] += 1
                active.value += 1
                peak.value = max(peak.value, active.value)
                if active.value == 8:
                    first_wave.set()
                if active.value > 8:
                    ninth_admitted.set()
            try:
                if index < 8:
                    if not first_wave.wait(3):
                        raise AssertionError('eight independent workers should fill the permitted slots')
                    # A bounded synchronization window, not a product cooldown or fake timeout.
                    ninth_admitted.wait(0.15)
                return {'outcome': 'ALREADY_CONFIGURED'}
            finally:
                with lock:
                    active.value -= 1
        with mock.patch.object(app, 'execute_ib_task', side_effect=execute), \
                mock.patch.object(app, 'interactive_run', side_effect=AssertionError('real SSH is forbidden')), \
                mock.patch.object(app, 'log'):
            result = app.run_prepared_tasks(tasks, self.args, None, '', None, [], None)
        self.assertEqual(9, result['workers'])
        self.assertEqual(8, peak.value)
        self.assertEqual([1] * 129, list(hits))
        self.assertEqual(['ALREADY_CONFIGURED'] * 129, list(result['outcomes'].values()))

    def test_expired_cooldown_waits_for_active_task_without_master_exit(self):
        gate = self.gate()
        for _ in range(3):
            self.assertTrue(gate.claim_jump_slot('example-jump01', 0))
        for _ in range(2):
            gate.report_jump_outcome('example-jump01', self.failure(), writes_attempted=False, now=0)
        sessions = SimpleNamespace(probe_jump_master=mock.Mock(), ensure_jump_master=mock.Mock(),
                                   close_jump_masters=mock.Mock())
        coordinator = SimpleNamespace(assert_unchanged=mock.Mock())
        with mock.patch.object(self.app, '_JUMP_SESSIONS', sessions), \
                mock.patch.object(self.app.time, 'monotonic', return_value=240):
            self.app.recover_jump_cooldowns(gate, {'example-jump01': self.jump}, coordinator)
            sessions.probe_jump_master.assert_not_called()
            sessions.ensure_jump_master.assert_not_called()
            sessions.close_jump_masters.assert_not_called()
            gate.report_jump_outcome('example-jump01', None, writes_attempted=True, now=240)
            self.app.recover_jump_cooldowns(gate, {'example-jump01': self.jump}, coordinator)
            sessions.probe_jump_master.assert_called_once_with(self.jump)
        sessions.close_jump_masters.assert_not_called()

    def test_live_socket_probe_rejects_hostname_and_keeps_failed_identity_closed(self):
        from test_cases import test_initial_setup_jump_sessions as fixtures
        case = fixtures.JumpSessionTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.establish()
        case.configure(hostname={'192.0.2.10': 'WRONG-JUMP'})
        self.assertTrue(hasattr(case.sessions, 'probe_jump_master'), 'cooldown needs a real hostname probe, not check only')
        with self.assertRaises(case.app.SshFailure) as caught:
            case.sessions.probe_jump_master(case.jump)
        self.assertEqual('OOB_IDENTITY_CONFLICT', caught.exception.kind.value)
        record = case.sessions.records['example-jump01']
        self.assertFalse(record['ready'])
        self.assertIs(caught.exception, record['error'])
        with mock.patch.object(case.app, '_JUMP_SESSIONS', case.sessions), \
                mock.patch.object(case.sessions, 'jump_master_alive', return_value=True) as alive, \
                mock.patch.object(case.app, 'interactive_run', side_effect=AssertionError('refused identity dispatch')) as execute:
            with self.assertRaises(case.app.SshFailure) as subsequent:
                case.app.run_on_ethernet(case.jump, 'cumulus', '', ['hostname'], 2)
        self.assertIs(caught.exception, subsequent.exception)
        alive.assert_not_called()
        execute.assert_not_called()

    def test_real_phase_worker_reply_preserves_control_exception_identity(self):
        app = self.app
        for status, kind in (('project-changed', app.ProjectInputChanged), ('stopped', app.BatchStopped)):
            with self.subTest(status=status):
                original, captured = app.worker_request, []
                connection = SimpleNamespace(send=mock.Mock(), recv=mock.Mock(return_value=(status, 'PUBLIC stop')))
                sessions = SimpleNamespace(jump_control_path=mock.Mock(return_value=str(self.root / 'PUBLIC-control')),
                                           jump_master_alive=mock.Mock(return_value=False))
                def observed_request(*args):
                    try:
                        return original(*args)
                    except kind as error:
                        captured.append(error)
                        raise
                with mock.patch.object(app, '_WORKER_CONNECTION', connection), \
                        mock.patch.object(app, '_JUMP_SESSIONS', sessions), \
                        mock.patch.object(app, 'worker_request', side_effect=observed_request), \
                        mock.patch.object(app, 'interactive_run', side_effect=AssertionError('no dispatch after control stop')) as execute:
                    with self.assertRaises(kind) as caught:
                        app._execute_ib_phase(self.target, self.neighbor, 'cumulus', '', 'admin',
                            'PUBLIC-Current-72!', 2, ['nv', 'config', 'show', '-o', 'commands'],
                            _phase_operation='auth-probe-readonly')
                self.assertEqual(1, len(captured))
                self.assertIs(captured[0], caught.exception)
                connection.send.assert_called_once_with(('request', ('jump-master', 'example-jump01')))
                execute.assert_not_called()

    def test_live_socket_network_probe_commits_recovered_ready_state(self):
        from test_cases import test_initial_setup_jump_sessions as fixtures
        case = fixtures.JumpSessionTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        verified = []
        case.establish(verify_identity=lambda jump, address: verified.append((jump.hostname, address)))
        record = case.sessions.records['example-jump01']
        failure = case.app.SshFailure(case.app.SshFailureKind.JUMP_UNREACHABLE,
                                      'outer', '192.0.2.10', 'EXAMPLE-JUMP01')
        actual_control = case.sessions._control_jump_master
        with mock.patch.object(case.sessions, '_control_jump_master',
                               side_effect=lambda record, op: False if op == 'exit' else actual_control(record, op)):
            case.sessions._reject_jump_master(record, failure)
        self.assertFalse(record['ready'])
        self.assertIs(failure, record['error'])
        self.assertTrue(case.sessions.jump_master_alive(case.jump), 'old public fake socket deliberately survived exit')
        case.sessions.probe_jump_master(case.jump)
        self.assertEqual([('EXAMPLE-JUMP01', '192.0.2.10')] * 2, verified)
        self.assertTrue(record['ready'], 'only complete hostname and callback verification may recover state')
        self.assertIsNone(record['error'])
        self.assertEqual(record['path'], case.sessions.jump_control_path(case.jump))
        with mock.patch.object(case.app, '_JUMP_SESSIONS', case.sessions):
            self.assertEqual('EXAMPLE-JUMP01', case.app.run_on_ethernet(case.jump, 'cumulus', '', ['hostname'], 2).strip())


if __name__ == '__main__':
    unittest.main()
