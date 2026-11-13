"""WP-1 / I-013 direct contracts: fake SSH only; guide r494 :417–507/K2/K9.

All expectations below come from the approved guide, not command construction.
The sole tempfile redirection independently checks the production dir=/tmp
request, while real paths stay inside the runner's explicit owned test root.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager, ExitStack
import csv
import errno
import inspect
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases import test_eth_jump_transport_contract as transport
from test_cases.native_cpld_physical_io import owned_test_root


FAKE_SSH = r'''import json, os, sys
from pathlib import Path
a = sys.argv[1:]
cfg = json.loads(Path(os.environ['WP1_CONFIG']).read_text())
state_path = Path(os.environ['WP1_STATE'])
state = json.loads(state_path.read_text()) if state_path.exists() else {}
with Path(os.environ['WP1_CALLS']).open('a') as h:
    h.write(json.dumps(a) + '\n')
cp = next((x.split('=', 1)[1] for x in a if x.startswith('ControlPath=')), '')
if '-O' in a:
    op = a[a.index('-O') + 1]
    if op == 'check':
        raise SystemExit(0 if cp in state and Path(cp).exists() else 255)
    state.pop(cp, None)
    Path(cp).unlink(missing_ok=True)
    state_path.write_text(json.dumps(state))
    raise SystemExit(0)
if '-M' in a:
    endpoint = next(x for x in reversed(a) if '@' in x)
    addr = endpoint.split('@', 1)[1]
    if addr in cfg.get('network', []):
        print('ssh: connect to host ' + addr + ' port 22: Connection timed out', file=sys.stderr)
        raise SystemExit(255)
    if addr in cfg.get('hostkey', []):
        print('REMOTE HOST IDENTIFICATION HAS CHANGED!', file=sys.stderr)
        raise SystemExit(255)
    if addr in cfg.get('key_denied', []) or addr in cfg.get('auth', []):
        if 'BatchMode=yes' in a:
            print('Permission denied (publickey).', file=sys.stderr)
            raise SystemExit(255)
        print(endpoint + "'s password: ", end='', flush=True)
        password = input()
        if addr in cfg.get('auth', []) or password != 'fixture-password':
            print('Permission denied (password).', file=sys.stderr)
            raise SystemExit(255)
    state[cp] = addr
    state_path.write_text(json.dumps(state))
    Path(cp).touch()
    raise SystemExit(0)
addr = state.get(cp)
if not addr:
    print('Control socket connect: fixture socket unavailable', file=sys.stderr)
    raise SystemExit(255)
print(cfg.get('hostname', {}).get(addr, 'EXAMPLE-JUMP01') if 'hostname' in a[-1] else 'fixture-output')
'''


class JumpSessionTests(unittest.TestCase):
    def setUp(self):
        owned_root = owned_test_root()
        self.tmp = tempfile.TemporaryDirectory(prefix='wp1-', dir=owned_root)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        original_cwd = os.open('.', os.O_RDONLY | os.O_DIRECTORY)

        def restore_cwd():
            try:
                os.fchdir(original_cwd)
            finally:
                os.close(original_cwd)

        self.addCleanup(restore_cwd)
        os.chdir(owned_root)
        self.app = transport.load_module('wp1_jump_sessions', transport.INITIAL_SETUP)
        self.jump = self.app.Device('EXAMPLE-JUMP01', 'eth_jump', '192.0.2.10',
                                   '192.0.2.10', '', '', '', '')
        self.config = self.root / 'config.json'
        self.config.write_text('{}')
        self.calls_path = self.root / 'calls.jsonl'
        self.state_path = self.root / 'state.json'
        ssh = self.root / 'ssh'
        ssh.write_text('#!' + sys.executable + '\n' + FAKE_SSH)
        ssh.chmod(0o700)
        (self.root / 'home').mkdir()
        self.environment = mock.patch.dict(os.environ, {
            'PATH': str(self.root) + os.pathsep + os.environ.get('PATH', ''),
            'HOME': str(self.root / 'home'), 'WP1_CONFIG': str(self.config),
            'WP1_STATE': str(self.state_path), 'WP1_CALLS': str(self.calls_path),
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        real_mkdtemp = tempfile.mkdtemp

        def control_directory(*args, **kwargs):
            self.assertEqual((), args)
            self.assertEqual('isj-', kwargs['prefix'])
            self.assertEqual('/tmp', kwargs['dir'], 'guide :437 production directory contract')
            absolute = Path(real_mkdtemp(prefix='isj-', dir=owned_root))
            relative = absolute.relative_to(owned_root)
            self.assertEqual(owned_root, absolute.parent)
            self.assertEqual(absolute, relative.resolve())
            return str(relative)

        self.redirect = mock.patch.object(self.app.tempfile, 'mkdtemp', side_effect=control_directory)
        self.redirect.start()
        self.addCleanup(self.redirect.stop)
        real_interactive, real_run = self.app.interactive_run, self.app.subprocess.run

        def closed_interactive(command, *args, **kwargs):
            self.assertEqual('ssh', command[0], 'tests never launch an absolute real SSH client')
            self.assertEqual(str(ssh), shutil.which(command[0]))
            return real_interactive(command, *args, **kwargs)

        def closed_run(command, *args, **kwargs):
            self.assertEqual('ssh', command[0], 'tests never launch an absolute real SSH client')
            self.assertEqual(str(ssh), shutil.which(command[0]))
            return real_run(command, *args, **kwargs)

        self.closed_pty = mock.patch.object(self.app, 'interactive_run', side_effect=closed_interactive)
        self.closed_control = mock.patch.object(self.app.subprocess, 'run', side_effect=closed_run)
        self.closed_pty.start()
        self.closed_control.start()
        self.addCleanup(self.closed_pty.stop)
        self.addCleanup(self.closed_control.stop)
        self.sessions = None
        self.addCleanup(self.close_sessions)

    def close_sessions(self):
        if self.sessions is not None:
            self.sessions.close_jump_masters()

    def configure(self, **values):
        self.config.write_text(json.dumps(values))

    def make_sessions(self, *, local=False):
        self.assertTrue(hasattr(self.app, 'JumpSessions'), 'guide :428 requires JumpSessions')
        self.sessions = self.app.JumpSessions(
            local_keys={self.app.normalize_name(self.jump.hostname)} if local else set(), timeout=2)
        return self.sessions

    def calls(self):
        return [json.loads(x) for x in self.calls_path.read_text().splitlines()] if self.calls_path.exists() else []

    def establish(self, **kwargs):
        sessions = self.sessions or self.make_sessions()
        return sessions.open_jump_master(self.jump, 'cumulus',
                                         self.app.ethernet_responder('fixture-password'), **kwargs)

    def test_control_path_none_keeps_argv_byte_identical(self):
        # Guide :435 and current T14 typed fixed-PATH carrier.
        self.assertIn('control_path', inspect.signature(self.app.outer_ssh_command).parameters)
        command = ['nv', 'show', 'interface']
        old = self.app.outer_ssh_command(self.jump, 'cumulus', command, 2)
        self.assertEqual(old, self.app.outer_ssh_command(self.jump, 'cumulus', command, 2, control_path=None))
        local = ['sh', '-c', 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec nv show interface']
        self.assertEqual(local, self.app.outer_ssh_command(self.jump, 'cumulus', command, 2,
                                                         local=True, control_path='/unused'))
        self.assertEqual(['nv', 'show', 'interface'], command)

    def test_one_master_per_jump_for_snapshot_and_tasks(self):
        self.establish()
        path = self.sessions.jump_control_path(self.jump)
        with mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions):
            self.assertEqual('EXAMPLE-JUMP01', self.app.run_on_ethernet(
                self.jump, 'cumulus', '', ['hostname'], 2).strip())
            self.app.run_on_ethernet(self.jump, 'cumulus', '', ['nv', 'show', 'interface'], 2)
            self.app.run_on_ethernet(self.jump, 'cumulus', '', ['bridge', 'fdb', 'show'], 2)
        self.assertEqual(1, sum('-M' in a for a in self.calls()))
        commands = [a for a in self.calls() if '-M' not in a and '-O' not in a]
        self.assertTrue(commands)
        self.assertTrue(all('ControlPath=' + path in a for a in commands))

    def test_inner_hop_never_multiplexes(self):
        self.establish()
        ib = self.app.Device('EXAMPLE-IB01', 'ib', '203.0.113.2', '203.0.113.2/24', '', '', '', '')
        target = self.app.Target(ib, self.jump, 'swp7', 'eth0')
        neighbor = self.app.Neighbor('fe80::1', 'swp7', '02:11:22:33:44:55')
        with mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions):
            argv = self.app.nested_ssh_command(target, neighbor, 'cumulus', 'admin', 2, ['true'])
        self.assertIn('ControlPath=' + self.sessions.jump_control_path(self.jump), argv)
        self.assertIn('ControlMaster=no', argv[-1])
        self.assertIn('ControlPath=none', argv[-1])

    def test_strict_ipv4_probe_keeps_inner_unmultiplexed_with_real_project_policy(self):
        self.establish()
        ib = self.app.Device('EXAMPLE-IB01', 'ib', '203.0.113.2', '203.0.113.2/24', '', '', '', '')
        target = self.app.Target(ib, self.jump, 'swp7', 'eth0')
        global_path = self.root / '01-global.yaml'
        public_hash = '$' + '6$PUBLICsalt$' + 'A' * 86
        global_path.write_text('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                               '      aaa:\n        user:\n          admin:\n'
                               '            pass' + 'word: ' + public_hash + '\n')
        password = '-'.join(('PUBLIC', 'Target', '71!'))
        # Model only the native hash backend; real policy type/identity/shape checks execute.
        with mock.patch.object(self.app, 'verify_password_hash',
                               side_effect=lambda value, setting: value == password and setting == public_hash), \
                mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions), \
                mock.patch.object(self.app.time, 'sleep'), \
                mock.patch.object(self.app, 'outer_ssh_command', wraps=self.app.outer_ssh_command) as outer, \
                mock.patch.object(self.app, 'interactive_run', return_value=self.app.SessionResult('', 0)) as execute:
            policy = self.app.ProjectPasswordPolicy(global_path, 'admin', target_password=password, interactive=False)
            self.app.verify_ipv4_login(target, 'default', 'cumulus', '', 'admin', 2,
                                      _ib_current_password='PUBLIC-Current-72!', _password_policy=policy)
        outer.assert_called_once()
        inner = outer.call_args.args[2]
        self.assertIsInstance(inner, list)
        self.assertIn('ControlMaster=no', inner, 'guide :436 applies to strict IPv4 inner SSH too')
        self.assertIn('ControlPath=none', inner)
        self.assertEqual('admin@203.0.113.2', inner[-2])
        self.assertEqual('true', inner[-1])
        self.assertEqual(self.sessions.jump_control_path(self.jump), outer.call_args.kwargs['control_path'])
        execute.assert_called_once()

    def test_strict_ipv4_rechecks_master_after_every_wait_and_rebuilds_before_retry(self):
        self.establish()
        path = Path(self.sessions.jump_control_path(self.jump))
        ib = self.app.Device('EXAMPLE-IB01', 'ib', '203.0.113.2', '203.0.113.2/24', '', '', '', '')
        target = self.app.Target(ib, self.jump, 'swp7', 'eth0')
        global_path = self.root / '01-global.yaml'
        public_hash = '$' + '6$PUBLICsalt$' + 'A' * 86
        global_path.write_text('schema_version: 2\nswitches:\n- ib:\n    system:\n'
                               '      aaa:\n        user:\n          admin:\n'
                               '            pass' + 'word: ' + public_hash + '\n')
        password = '-'.join(('PUBLIC', 'Target', '71!'))
        coordinator = self.app.RuntimeCoordinator.__new__(self.app.RuntimeCoordinator)
        coordinator.stopped, coordinator.current_target = False, target
        coordinator.metrics = {}  # Existing metric state required by real strict dispatch.
        actual_control = self.app.subprocess.run
        actual_interactive = self.app.interactive_run
        events, preceding, probes = [], [], []
        waits = []

        def clock(seconds):
            waits.append(seconds)
            events.append(('sleep', len(waits)))
            if len(waits) == 2:
                path.unlink()  # The socket expires during the second readiness wait.

        def control(command, *args, **kwargs):
            result = actual_control(command, *args, **kwargs)
            if '-O' in command and command[command.index('-O') + 1] == 'check':
                events.append(('check', result.returncode == 0))
            return result

        def execute(command, *args, **kwargs):
            if 'ip vrf exec default ssh' not in command[-1] or 'admin@203.0.113.2' not in command[-1]:
                return actual_interactive(command, *args, **kwargs)
            preceding.append(events[-1])
            probes.append(list(command))
            events.append(('probe', len(probes)))
            if len(probes) < 3:
                return self.app.SessionResult('ssh: connect to host 203.0.113.2 port 22: Connection refused', 255)
            return self.app.SessionResult('', 0)

        with mock.patch.object(self.app, 'verify_password_hash',
                               side_effect=lambda value, setting: value == password and setting == public_hash), \
                mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions), \
                mock.patch.object(self.app, '_ACTIVE_COORDINATOR', coordinator), \
                mock.patch.object(coordinator, 'request', wraps=coordinator.request) as request, \
                mock.patch.object(self.app.subprocess, 'run', side_effect=control), \
                mock.patch.object(self.app, 'interactive_run', side_effect=execute), \
                mock.patch.object(self.app.time, 'sleep', side_effect=clock):
            policy = self.app.ProjectPasswordPolicy(global_path, 'admin', target_password=password, interactive=False)
            self.app.verify_ipv4_login(target, 'default', 'cumulus', '', 'admin', 2,
                                      _ib_current_password='PUBLIC-Current-72!', _password_policy=policy)
        self.assertEqual([15, 10, 10], waits, 'r506 WP-3 changes only the IPv4 readiness schedule')
        self.assertEqual(3, len(probes))
        self.assertEqual([('check', True)] * 3, preceding,
                         'each strict PTY dispatch needs a live check after its own sleep')
        self.assertEqual(1, sum(call.args[0] == 'jump-master' for call in request.call_args_list))
        self.assertEqual(2, sum('-M' in command for command in self.calls()))
        self.assertTrue(all('ControlPath=' + str(path) in command for command in probes))

    def test_candidates_switch_only_on_outer_network_failure(self):
        self.configure(network=['192.0.2.10'])
        observed = []
        selected = self.establish(candidates=('192.0.2.10', '192.0.2.11'),
                                  verify_identity=lambda jump, address: observed.append((jump, address, len(self.calls()))))
        self.assertEqual('192.0.2.11', selected)
        self.assertEqual([(self.jump, '192.0.2.11')], [(j, a) for j, a, _ in observed])
        self.assertEqual(2, sum('-M' in a for a in self.calls()))
        self.assertEqual(1, len(json.loads(self.state_path.read_text())))
        self.assertIn('hostname', self.calls()[observed[0][2] - 1][-1])

    def test_final_authentication_and_hostkey_never_switch_candidates(self):
        for problem in ('auth', 'hostkey'):
            with self.subTest(problem=problem):
                self.close_sessions()
                self.sessions = None
                self.calls_path.unlink(missing_ok=True)
                self.configure(**{problem: ['192.0.2.10']})
                sessions = self.make_sessions()
                with self.assertRaises(self.app.SshFailure) as caught:
                    self.establish(candidates=('192.0.2.10', '192.0.2.11'))
                self.assertIsInstance(caught.exception, self.app.SetupError)
                self.assertEqual(('outer', '192.0.2.10', self.jump.hostname),
                                 (caught.exception.hop, caught.exception.address, caught.exception.jump))
                self.assertFalse(any('192.0.2.11' in ' '.join(a) for a in self.calls()))

    def test_identity_mismatch_does_not_switch_candidates(self):
        self.configure(hostname={'192.0.2.10': 'WRONG-JUMP'})
        self.make_sessions()
        with self.assertRaises(self.app.SshFailure):
            self.establish(candidates=('192.0.2.10', '192.0.2.11'))
        self.assertFalse(any('192.0.2.11' in ' '.join(a) for a in self.calls()))

    def test_identity_callback_follows_hostname_and_cannot_switch_candidates(self):
        self.make_sessions()

        def refused(jump, address):
            self.assertIs(self.jump, jump)
            self.assertEqual('192.0.2.10', address)
            ordinary = [a for a in self.calls() if '-M' not in a and '-O' not in a]
            self.assertEqual(1, len(ordinary))
            self.assertIn('hostname', ordinary[0][-1])
            raise self.app.SetupError('fixture identity mismatch')

        with self.assertRaises(self.app.SshFailure):
            self.establish(candidates=('192.0.2.10', '192.0.2.11'), verify_identity=refused)
        self.assertFalse(any('192.0.2.11' in ' '.join(a) for a in self.calls()))

    def assert_identity_failure_survives_exit_error(self, cleanup_error, *, callback=False,
                                                   interruption=False):
        self.close_sessions()
        self.sessions = None
        self.calls_path.unlink(missing_ok=True)
        self.configure(**({} if callback else {'hostname': {'192.0.2.10': 'WRONG-JUMP'}}))
        sessions = self.make_sessions()
        actual_verify = sessions._verify_jump_master_identity
        actual_control = self.app.subprocess.run
        original_failures = []
        cleanup_calls = []

        def verify(record):
            try:
                return actual_verify(record)
            except self.app.SshFailure as failure:
                original_failures.append(failure)
                raise

        def control(command, *args, **kwargs):
            if '-O' in command and command[command.index('-O') + 1] == 'exit':
                cleanup_calls.append(tuple(command))
                raise cleanup_error
            return actual_control(command, *args, **kwargs)

        def refuse(jump, address):
            self.assertIs(self.jump, jump)
            self.assertEqual('192.0.2.10', address)
            raise self.app.SetupError('fixture callback identity rejection')

        expected = type(cleanup_error) if interruption else self.app.SshFailure
        with mock.patch.object(sessions, '_verify_jump_master_identity', side_effect=verify), \
                mock.patch.object(self.app.subprocess, 'run', side_effect=control), \
                self.assertRaises(expected) as caught:
            self.establish(candidates=('192.0.2.10', '192.0.2.11'),
                           verify_identity=refuse if callback else None)
        self.assertEqual(1, len(original_failures))
        self.assertEqual(1, len(cleanup_calls))
        original = original_failures[0]
        self.assertEqual(('OOB_IDENTITY_CONFLICT', 'outer', '192.0.2.10', 'EXAMPLE-JUMP01'),
                         (original.kind.value, original.hop, original.address, original.jump))
        if interruption:
            self.assertIs(cleanup_error, caught.exception)
        else:
            self.assertIs(original, caught.exception, 'cleanup must not replace identity failure')
        record = sessions.records['example-jump01']
        self.assertFalse(record['ready'], 'failure state must be committed before attempting cleanup')
        self.assertIs(original, record['error'])
        self.assertFalse(any('192.0.2.11' in ' '.join(a) for a in self.calls()))
        with mock.patch.object(self.app, '_JUMP_SESSIONS', sessions), \
                mock.patch.object(sessions, 'jump_master_alive', return_value=True) as alive, \
                mock.patch.object(self.app, 'interactive_run', side_effect=AssertionError('unverified master dispatch')) as dispatch:
            for operation in (
                    lambda: self.app.collect_ethernet_interfaces(self.jump, 'cumulus', '', 2),
                    lambda: self.app.run_on_ethernet(self.jump, 'cumulus', '', ['hostname'], 2)):
                with self.assertRaises(self.app.SshFailure) as subsequent:
                    operation()
                self.assertIs(original, subsequent.exception)
        alive.assert_not_called()
        dispatch.assert_not_called()

    def test_identity_failure_stays_closed_when_master_exit_times_out(self):
        for callback in (False, True):
            with self.subTest(callback=callback):
                self.assert_identity_failure_survives_exit_error(
                    self.app.subprocess.TimeoutExpired(['ssh', '-O', 'exit'], 2), callback=callback)

    def test_identity_failure_stays_closed_when_master_exit_has_oserror(self):
        for callback in (False, True):
            with self.subTest(callback=callback):
                self.assert_identity_failure_survives_exit_error(OSError('fixture exit unavailable'), callback=callback)

    def test_identity_cleanup_preserves_baseexception_interruptions_and_failed_state(self):
        for error in (KeyboardInterrupt(), SystemExit(73)):
            with self.subTest(interruption=type(error).__name__):
                self.assert_identity_failure_survives_exit_error(error, interruption=True)

    def test_master_failures_are_typed_and_do_not_relabel_inner_network_as_outer(self):
        self.make_sessions()
        network = self.app.classify_ssh_failure(
            'ssh: connect to host 192.0.2.10 port 22: Connection refused',
            outer_address='192.0.2.10', inner_address='fe80::1')
        self.assertEqual(('OOB_JUMP_UNREACHABLE', 'outer', '192.0.2.10'),
                         (network.kind.value, network.hop, network.address))
        inner = self.app.classify_ssh_failure(
            'ssh: connect to host fe80::1 port 22: Connection refused',
            outer_address='192.0.2.10', inner_address='fe80::1')
        self.assertTrue(inner is None or inner.hop != 'outer')
        kinds = []
        for output in ('Permission denied (password).', 'REMOTE HOST IDENTIFICATION HAS CHANGED!'):
            failure = self.app.classify_ssh_failure(output, outer_address='192.0.2.10', inner_address=None)
            self.assertIsInstance(failure, self.app.SshFailure)
            self.assertIsInstance(failure, self.app.SetupError)
            self.assertNotEqual(network.kind, failure.kind)
            kinds.append(failure.kind)
        self.assertNotEqual(kinds[0], kinds[1])

    def test_control_dir_is_short_private_and_removed(self):
        self.establish()
        path = Path(self.sessions.jump_control_path(self.jump))
        self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
        self.assertLessEqual(len(os.fsencode(str(path))) + 17, 104)
        self.sessions.close_jump_masters()
        self.assertFalse(path.parent.exists())
        self.assertTrue(any('-O' in a and 'exit' in a for a in self.calls()))

    def test_control_directory_creation_failure_is_raiseable_typed_local_failure(self):
        self.make_sessions()
        with mock.patch.object(self.app.tempfile, 'mkdtemp', side_effect=OSError('fixture unavailable')), \
                self.assertRaises(self.app.SshFailure) as caught:
            self.establish()
        self.assertIsInstance(caught.exception, self.app.SetupError)
        self.assertEqual(('LOCAL_COMMAND_ERROR', 'outer', '192.0.2.10', 'EXAMPLE-JUMP01'),
                         (caught.exception.kind.value, caught.exception.hop,
                          caught.exception.address, caught.exception.jump))
        self.assertEqual([], self.calls())

    def test_failed_master_exit_is_reported_after_directory_cleanup(self):
        self.establish()
        directory = Path(self.sessions.jump_control_path(self.jump)).parent
        with mock.patch.object(self.sessions, '_control_jump_master', return_value=False), \
                self.assertRaises(self.app.SshFailure) as caught:
            self.sessions.close_jump_masters()
        self.assertEqual(('outer', '192.0.2.10', 'EXAMPLE-JUMP01'),
                         (caught.exception.hop, caught.exception.address, caught.exception.jump))
        self.assertFalse(directory.exists())

    def test_old_main_fixture_adapter_keeps_probe_expectations_and_has_no_external_effects(self):
        from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory
        factory = legacy_jump_sessions_factory(self.app)
        sessions = factory(local_keys=set(), timeout=7)
        with mock.patch.object(self.app, 'probe_ethernet_key', return_value='password') as probe, \
                mock.patch.object(self.app, 'interactive_run', side_effect=AssertionError('fixture SSH')), \
                mock.patch.object(self.app.tempfile, 'mkdtemp', side_effect=AssertionError('fixture directory')):
            self.assertEqual('password', sessions.probe_jump_key(self.jump, 'cumulus'))
            self.assertEqual('192.0.2.10', sessions.open_jump_master(self.jump, 'cumulus', None))
            self.assertIsNone(sessions.jump_control_path(self.jump))
            sessions.close_jump_masters()
        probe.assert_called_once_with(self.jump, 'cumulus', 7)

    def test_master_uses_selected_address_on_rebuild(self):
        self.configure(network=['192.0.2.10'])
        self.establish(candidates=('192.0.2.10', '192.0.2.11'))
        path = Path(self.sessions.jump_control_path(self.jump))
        path.unlink()
        before = len(self.calls())
        self.sessions.ensure_jump_master(self.jump)
        masters = [a for a in self.calls()[before:] if '-M' in a]
        self.assertEqual(1, len(masters))
        self.assertIn('cumulus@192.0.2.11', masters[0])

    def test_key_jump_logs_in_once_password_jump_prompts_once(self):
        sessions = self.make_sessions()
        self.configure(key_denied=['192.0.2.10'])
        target = type('Task', (), {'ethernet': self.jump})()
        with mock.patch.object(self.app.sys.stdin, 'isatty', return_value=True), \
                mock.patch('builtins.input', return_value='yes') as shared, \
                mock.patch.object(self.app.getpass, 'getpass', return_value='fixture-password') as password:
            values = self.app.prompt_ethernet_passwords([target], None, set(),
                eth_user='cumulus', timeout=2, jump_sessions=sessions)
        shared.assert_called_once()
        password.assert_called_once()
        self.assertEqual('fixture-password', values[self.app.normalize_name(self.jump.hostname)])
        self.assertEqual(2, sum('-M' in a for a in self.calls()))

    def test_fd_mode_never_prompts_and_key_success_is_one_login(self):
        sessions = self.make_sessions()
        target = type('Task', (), {'ethernet': self.jump})()
        with mock.patch('builtins.input', side_effect=AssertionError('fd mode prompt')), \
                mock.patch.object(self.app.getpass, 'getpass', side_effect=AssertionError('fd mode prompt')):
            self.app.prompt_ethernet_passwords([target], None, set(), eth_user='cumulus', timeout=2,
                                             password_for=lambda _: 'fixture-password', jump_sessions=sessions)
        self.assertEqual(1, sum('-M' in a for a in self.calls()))

    def test_local_leaf_builds_no_master(self):
        sessions = self.make_sessions(local=True)
        self.assertIsNone(sessions.open_jump_master(self.jump, 'cumulus', None))
        self.assertIsNone(sessions.jump_control_path(self.jump))
        self.assertEqual([], self.calls())

    def test_control_ops_only_through_closed_builder(self):
        self.make_sessions()
        with self.assertRaises(self.app.SetupError):
            self.app.jump_master_control_argv('forward', '/fixture', self.jump)
        with mock.patch.object(self.app, 'jump_master_control_argv', wraps=self.app.jump_master_control_argv) as builder:
            self.establish()
            self.sessions.close_jump_masters()
        self.assertIn('check', [x.args[0] for x in builder.call_args_list])
        self.assertIn('exit', [x.args[0] for x in builder.call_args_list])

    def test_missing_socket_requests_rebuild_not_silent_fallback(self):
        self.establish()
        path = Path(self.sessions.jump_control_path(self.jump))
        path.unlink()
        coordinator = self.app.RuntimeCoordinator.__new__(self.app.RuntimeCoordinator)
        coordinator.stopped = False  # Existing cancellation boundary, not a new product fallback.
        coordinator.current_target = type('Target', (), {'ethernet': self.jump})()
        with mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions), \
                mock.patch.object(self.app, '_ACTIVE_COORDINATOR', coordinator), \
                mock.patch.object(coordinator, 'request', wraps=coordinator.request) as request:
            self.app.run_on_ethernet(self.jump, 'cumulus', '', ['hostname'], 2)
        self.assertEqual(1, sum(c.args[0] == 'jump-master' for c in request.call_args_list))
        self.assertEqual(2, sum('-M' in a for a in self.calls()))

    def test_main_lifetime_cleans_on_exception_without_swallowing_interrupt(self):
        sessions = self.make_sessions()
        self.establish()
        directory = Path(sessions.jump_control_path(self.jump)).parent
        with mock.patch.object(sessions, '_control_jump_master', side_effect=self.app.SshFailure(
                self.app.SshFailureKind.JUMP_UNREACHABLE, 'outer', '192.0.2.10', self.jump.hostname)), \
                self.assertRaises(KeyboardInterrupt):
            with self.app._jump_session_lifetime():
                self.app._JUMP_SESSIONS = sessions
                raise KeyboardInterrupt()
        self.assertFalse(directory.exists())
        self.assertIsNone(self.app._JUMP_SESSIONS)

    def test_master_failure_fields_survive_inline_and_real_fork_ipc(self):
        sessions = self.make_sessions()
        failure = self.app.SshFailure(self.app.SshFailureKind.JUMP_UNREACHABLE,
                                      'outer', '192.0.2.11', self.jump.hostname)
        coordinator = self.app.RuntimeCoordinator.__new__(self.app.RuntimeCoordinator)
        target = type('Target', (), {'ethernet': self.jump})()
        with mock.patch.object(self.app, '_JUMP_SESSIONS', sessions), \
                mock.patch.object(sessions, 'ensure_jump_master', side_effect=failure):
            reply = coordinator.request('jump-master', self.app.normalize_name(self.jump.hostname), target)
            with self.assertRaises(self.app.SshFailure) as caught:
                self.app._unwrap_jump_master_reply(reply)
            self.assertEqual(('outer', '192.0.2.11', self.jump.hostname),
                             (caught.exception.hop, caught.exception.address, caught.exception.jump))
            context = multiprocessing.get_context('fork')
            parent, child = context.Pipe()

            def child_request():
                parent.close()
                self.app._WORKER_CONNECTION = child
                try:
                    self.app.worker_request('jump-master', self.app.normalize_name(self.jump.hostname))
                except self.app.SshFailure as error:
                    child.send(('observed', (error.kind.value, error.hop, error.address, error.jump,
                                             isinstance(error, self.app.SetupError))))
                finally:
                    child.close()

            process = context.Process(target=child_request)
            process.start()
            child.close()
            try:
                self.assertTrue(parent.poll(5))
                message = parent.recv()
                self.assertEqual(('request', ('jump-master', self.app.normalize_name(self.jump.hostname))), message)
                parent.send(('ok', coordinator.request(*message[1], target)))
                self.assertTrue(parent.poll(5))
                self.assertEqual(('observed', ('OOB_JUMP_UNREACHABLE', 'outer', '192.0.2.11',
                                               self.jump.hostname, True)), parent.recv())
            finally:
                parent.close()
                process.join(5)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
            self.assertEqual(0, process.exitcode)

    def test_real_fork_missing_socket_rebuilds_once_in_coordinator(self):
        self.establish()
        path = Path(self.sessions.jump_control_path(self.jump))
        path.unlink()
        coordinator = self.app.RuntimeCoordinator.__new__(self.app.RuntimeCoordinator)
        target = type('Target', (), {'ethernet': self.jump})()
        context = multiprocessing.get_context('fork')
        parent, child = context.Pipe()

        def child_command():
            parent.close()
            self.app._WORKER_CONNECTION = child
            self.app._JUMP_SESSIONS = self.sessions
            try:
                output = self.app.run_on_ethernet(self.jump, 'cumulus', '', ['hostname'], 2)
                child.send(('observed', output.strip()))
            finally:
                child.close()

        process = context.Process(target=child_command)
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(5))
            request = parent.recv()
            self.assertEqual(('request', ('jump-master', 'example-jump01')), request)
            with mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions), \
                    mock.patch.object(self.sessions, 'ensure_jump_master',
                                      wraps=self.sessions.ensure_jump_master) as rebuild:
                parent.send(('ok', coordinator.request(*request[1], target)))
                rebuild.assert_called_once_with(self.jump)
            self.assertTrue(parent.poll(5))
            self.assertEqual(('observed', 'EXAMPLE-JUMP01'), parent.recv())
        finally:
            parent.close()
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
        self.assertEqual(0, process.exitcode)
        self.assertEqual(2, sum('-M' in a for a in self.calls()))
        ordinary = [a for a in self.calls() if '-M' not in a and '-O' not in a]
        self.assertTrue(all('ControlPath=' + str(path) in a for a in ordinary))

    def test_main_factory_precedes_prompt_and_snapshot_and_has_lifetime(self):
        # This static main assertion does not replace WP-2's real main workflow.
        tree = ast.parse(transport.INITIAL_SETUP.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        lifetime = [node.func.id for node in main.decorator_list
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertIn('_jump_session_lifetime', lifetime)
        calls = [(node.func.id, node.lineno, node) for node in ast.walk(main)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        factory = [(line, node) for name, line, node in calls if name == '_new_jump_sessions']
        prompts = [(line, node) for name, line, node in calls if name == 'prompt_ethernet_passwords']
        snapshots = [line for name, line, node in calls if name == 'collect_ethernet_interfaces']
        self.assertEqual(1, len(factory))
        self.assertEqual(2, len(prompts), 'initial Leaf and late Spine prompt paths both use the factory')
        self.assertTrue(snapshots)
        self.assertLess(factory[0][0], min(line for line, node in prompts))
        self.assertLess(min(line for line, node in prompts), min(snapshots))
        for line, node in prompts:
            value = next((kw.value for kw in node.keywords if kw.arg == 'jump_sessions'), None)
            self.assertIsInstance(value, ast.Name)
            self.assertEqual('_JUMP_SESSIONS', value.id)

    def test_real_setup_csv_reader_handoff_reuses_one_master(self):
        # Two real scripts: setup's standalone CSV validator -> initial reader -> transport.
        # It calls neither setup.main/load/main nor any deployment or service helper.
        from test_cases.module_loader import load_script
        setup = load_script('wp1_setup_reader', transport.INITIAL_SETUP.parents[3] / 'DAY0-Prepare/01-a-setup.py')
        header = ('hostname', 'type', 'template', 'eth0_ip', 'netmask', 'eth0_gw', 'eth0_mac',
                  'eth1_ip', 'netmask', 'eth1_gw', 'eth1_mac', 'lo_ip', 'vrf_default',
                  'vlan_id', 'svi_ip', 'netmask', 'vrr_ip', 'vrr_mac', 'vlan_ports',
                  'bgp_asn', 'bgp_ports', 'bond_ports', 'bond_type', 'bond_mac', 'peerlink_ports',
                  'vrl', 'evpn_vrf', 'evpn_l3vni', 'evpn_l3vlan', 'dhcp_relay', 'evpn_l2vni',
                  'evpn_l2vlan', 'svi_ip', 'netmask', 'vrr_ip', 'vrr_mac', 'vlan_ports')
        ib, jump = [''] * 37, [''] * 37
        ib[:7] = ['EXAMPLE-IB01', 'ib', 'NA', '198.51.100.2', '24', '198.51.100.1', '02:00:00:00:00:02']
        jump[:4] = ['EXAMPLE-JUMP01', 'eth_jump', '', '192.0.2.10']
        inventory = self.root / '02-devices_config.csv'
        with inventory.open('w', newline='') as stream:
            csv.writer(stream).writerows((header, ib, jump))
        self.assertEqual(([], []), setup._validate_eth_csv(str(inventory)))
        devices, jumps = self.app.load_devices(inventory)
        self.assertEqual({'example-ib01'}, set(devices))
        self.assertEqual({'example-jump01'}, set(jumps))
        self.jump = jumps['example-jump01']
        self.assertEqual('192.0.2.10', self.jump.login_ip)
        self.establish()
        with mock.patch.object(self.app, '_JUMP_SESSIONS', self.sessions):
            self.app.run_on_ethernet(self.jump, 'cumulus', '', ['nv', 'show', 'interface'], 2)
            self.app.run_on_ethernet(self.jump, 'cumulus', '', ['bridge', 'fdb', 'show'], 2)
        self.assertEqual(1, sum('-M' in a for a in self.calls()))
        commands = [a for a in self.calls() if '-M' not in a and '-O' not in a]
        self.assertEqual(3, len(commands), 'hostname first, followed by the two qualified commands')
        self.assertTrue(all('ControlPath=' + self.sessions.jump_control_path(self.jump) in a for a in commands))


class JumpFixtureOwnedRootTests(unittest.TestCase):
    """r530 sixth carrier: independent roots, real paths and launch-before safety."""

    def roots(self):
        from test_cases.native_cpld_physical_io import owned_test_root
        temporary = tempfile.TemporaryDirectory(prefix='jump roots ', dir=owned_test_root())
        self.addCleanup(temporary.cleanup)
        pool = Path(temporary.name)
        roots = (pool / 'space root', pool / ('long-' + 'r' * 120))
        for root in roots:
            root.mkdir(mode=0o700)
        return roots

    @contextmanager
    def guarded_case(self, case_type, declared, state, *, stop_at_factory=False, fault=None):
        """Reject any old root or real SSH before creation, even in the RED tree."""
        case = case_type()
        owner = sys.modules[case_type.__module__]
        old_parent = getattr(owner, 'SHORT_ROOT', None)
        real_is_dir, real_factory = Path.is_dir, tempfile.mkdtemp
        real_open, real_close, real_fchdir = os.open, os.close, os.fchdir
        real_write, real_popen = Path.write_text, subprocess.Popen
        backup = real_open('.', os.O_RDONLY | os.O_DIRECTORY)
        prior = os.fstat(backup)
        state.update(parents=[], cwd_fds=[], restored=[], control_dirs=[])

        def is_dir(path):
            # Only the obsolete literal's existence is modeled, to reach its
            # actual factory. No old directory is created or otherwise used.
            return True if old_parent is not None and path == old_parent else real_is_dir(path)

        def factory(*args, **kwargs):
            parent = kwargs.get('dir', args[2] if len(args) > 2 else None)
            state['parents'].append(parent)
            self.assertIsNotNone(declared, 'factory requires an independent runner root')
            self.assertEqual(declared, Path(parent) if parent is not None else None,
                             'fixture factory must consume the declared runner root')
            if stop_at_factory:
                raise OwnedJumpFactoryReached()
            return real_factory(*args, **kwargs)

        def opened(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            item = os.fstat(descriptor)
            if path == '.' and stat.S_ISDIR(item.st_mode) and (
                    item.st_dev, item.st_ino) == (prior.st_dev, prior.st_ino):
                state['cwd_fds'].append(descriptor)
            return descriptor

        def restored(descriptor):
            if descriptor in state['cwd_fds']:
                state['restored'].append((descriptor, [p.exists() for p in state['control_dirs']]))
                state['calls_after_master_close'] = case.calls() if hasattr(case, 'calls_path') else []
            return real_fchdir(descriptor)

        def written(path, *args, **kwargs):
            if fault is not None and path.name == 'config.json':
                raise fault
            return real_write(path, *args, **kwargs)

        def child(command, *args, **kwargs):
            self.assertIsInstance(command, list)
            self.assertTrue(command and command[0] == 'ssh', 'no absolute or non-fixture SSH child')
            self.assertEqual(str(case.root / 'ssh'), shutil.which(command[0]),
                             'only this case-owned fake SSH may launch')
            return real_popen(command, *args, **kwargs)

        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ,
                    {} if declared is None else {'HTTP_TEST_OWNED_ROOT': str(declared)}))
                if declared is None:
                    os.environ.pop('HTTP_TEST_OWNED_ROOT', None)
                stack.enter_context(mock.patch.object(Path, 'is_dir', autospec=True, side_effect=is_dir))
                stack.enter_context(mock.patch.object(tempfile, 'mkdtemp', side_effect=factory))
                stack.enter_context(mock.patch.object(os, 'open', side_effect=opened))
                stack.enter_context(mock.patch.object(os, 'fchdir', side_effect=restored))
                stack.enter_context(mock.patch.object(Path, 'write_text', autospec=True, side_effect=written))
                stack.enter_context(mock.patch.object(subprocess, 'Popen', side_effect=child))
                try:
                    case.setUp()
                    # PTY launches use pty.fork/execvp, not Popen. Guard the
                    # actual outer entry independently of the fixture's gates.
                    if hasattr(case, 'sessions'):
                        real_interactive = case.app.interactive_run

                        def interactive(command, *args, **kwargs):
                            self.assertIsInstance(command, list)
                            self.assertTrue(command and command[0] == 'ssh',
                                            'no absolute or non-fixture PTY SSH child')
                            self.assertEqual(str(case.root / 'ssh'), shutil.which(command[0]),
                                             'only this case-owned fake SSH may enter PTY')
                            return real_interactive(command, *args, **kwargs)

                        stack.enter_context(mock.patch.object(case.app, 'interactive_run',
                                                             side_effect=interactive))
                    yield case
                finally:
                    try:
                        self.assertTrue(case.doCleanups(), 'nested fixture cleanup must not hide an error')
                    finally:
                        deleted_cwd = False
                        try:
                            try:
                                state['after_cwd'] = Path.cwd()
                            except FileNotFoundError:
                                state['after_cwd'], deleted_cwd = None, True
                            state['closed'] = []
                            for descriptor in state['cwd_fds']:
                                try:
                                    os.fstat(descriptor)
                                except OSError as error:
                                    state['closed'].append(error.errno == errno.EBADF)
                                else:
                                    state['closed'].append(False)
                        finally:
                            # Even a failed observer or a deleted-cwd mutation
                            # cannot skip restoration of this test owner's FD.
                            real_fchdir(backup)
                        self.assertFalse(deleted_cwd, 'fixture deleted cwd without restoring its held original')
        finally:
            real_close(backup)

    def test_both_setup_factories_consume_each_independent_root_before_creation(self):
        from test_cases import test_initial_setup_jump_gate as gate
        for root in self.roots():
            for case_type in (JumpSessionTests, gate.JumpGateTests):
                with self.subTest(root=root.name, fixture=case_type.__name__):
                    state = {}
                    with self.assertRaises(OwnedJumpFactoryReached):
                        with self.guarded_case(case_type, root, state, stop_at_factory=True):
                            self.fail('factory hard stop did not execute')
                    self.assertEqual([root], state['parents'])

    def test_third_workflow_consumes_each_declared_root_before_real_world_factory(self):
        from test_cases.module_loader import load_script
        master_fixture = sys.modules[JumpSessionTests.__module__]
        legacy_metadata = Path('/Users/joeyyang/Desktop/http-v314-wp1-tmp-20261112-231739')
        source = Path(__file__).with_name('test_initial_setup_jump_unreachable_workflow.py')
        self.assertNotIn('SHORT_ROOT', vars(master_fixture))
        for index, root in enumerate(self.roots()):
            with self.subTest(root=root.name):
                name, workflow, parents = 'rv100_third_factory_' + str(index), None, []
                self.assertNotIn(name, sys.modules)

                def before_real_factory(*args, **kwargs):
                    parent = kwargs.get('dir', args[2] if len(args) > 2 else None)
                    parents.append(parent)
                    self.assertEqual(root, Path(parent) if parent is not None else None,
                                     'workflow must consume the independently declared runner root')
                    raise OwnedJumpFactoryReached()

                try:
                    with mock.patch.object(subprocess, 'Popen',
                            side_effect=AssertionError('root observer must never start a child')) as child, \
                            mock.patch('pty.fork',
                            side_effect=AssertionError('root observer must never enter PTY')) as fork:
                        # Metadata-only compatibility for the old alias import.
                        # Never inspect/create the old root or leave the alias.
                        with mock.patch.object(master_fixture, 'SHORT_ROOT', legacy_metadata, create=True):
                            workflow = load_script(name, source)
                        self.assertNotIn('SHORT_ROOT', vars(master_fixture))
                        with mock.patch.dict(os.environ, {'HTTP_TEST_OWNED_ROOT': str(root)}), \
                                mock.patch.object(workflow.tempfile, 'TemporaryDirectory',
                                                  side_effect=before_real_factory), \
                                mock.patch.object(workflow.PublicWorld, '__init__',
                                    side_effect=AssertionError('root observer must not enter MAIN world')) as world:
                            try:
                                with self.assertRaises(OwnedJumpFactoryReached):
                                    workflow.JumpUnreachableWorkflowTests().run_world(blocked_until=0)
                            finally:
                                world.assert_not_called()
                                child.assert_not_called()
                                fork.assert_not_called()
                        self.assertEqual([root], parents)
                finally:
                    if workflow is not None and sys.modules.get(name) is workflow:
                        sys.modules.pop(name)
                    self.assertNotIn('SHORT_ROOT', vars(master_fixture))

    def test_independent_launch_guards_reject_absolute_and_wrong_path_before_pty_or_popen(self):
        root = self.roots()[0]
        real_popen_class = subprocess.Popen
        with self.guarded_case(JumpSessionTests, root, {}) as case:
            # A last-resort pure hardstop is before the real PTY fork, not an
            # incorrect assumption that Popen intercepts pty.fork/execvp.
            with mock.patch.object(case.app.pty, 'fork',
                    side_effect=AssertionError('last-resort PTY hardstop reached')) as fork:
                with self.assertRaisesRegex(AssertionError, 'no absolute or non-fixture PTY SSH child'):
                    case.app.interactive_run(['/usr/bin/ssh', 'PUBLIC'], lambda unused: None, 1)
                with mock.patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}):
                    with self.assertRaisesRegex(AssertionError, 'only this case-owned fake SSH may enter PTY'):
                        case.app.interactive_run(['ssh', 'PUBLIC'], lambda unused: None, 1)
                fork.assert_not_called()
            with mock.patch.object(real_popen_class, '__init__',
                    side_effect=AssertionError('last-resort Popen hardstop reached')) as constructor:
                with self.assertRaisesRegex(AssertionError, 'no absolute or non-fixture SSH child'):
                    subprocess.Popen(['/usr/bin/ssh', 'PUBLIC'])
                with mock.patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}):
                    with self.assertRaisesRegex(AssertionError, 'only this case-owned fake SSH may launch'):
                        subprocess.Popen(['ssh', 'PUBLIC'])
                constructor.assert_not_called()

    def test_space_and_long_owned_roots_complete_real_fake_master_and_cleanup(self):
        prior = Path.cwd()
        for root in self.roots():
            with self.subTest(root=root.name):
                state = {}
                with self.guarded_case(JumpSessionTests, root, state) as case:
                    try:
                        case.establish()
                    except case.app.SshFailure as error:
                        self.fail('long-root normal fake master must succeed: ' + error.kind.value)
                    control = Path(case.sessions.jump_control_path(case.jump))
                    absolute = control.resolve()
                    state['control_dirs'].append(absolute.parent)
                    self.assertFalse(control.is_absolute())
                    self.assertEqual(root, absolute.parent.parent)
                    self.assertGreater(len(os.fsencode(str(absolute))) + 17, 104)
                    self.assertLessEqual(len(os.fsencode(str(control))) + 17, 104)
                    self.assertEqual(0o700, stat.S_IMODE(absolute.parent.stat().st_mode))
                    self.assertEqual(root, Path.cwd())
                    with mock.patch.object(case.app, '_JUMP_SESSIONS', case.sessions):
                        self.assertEqual('EXAMPLE-JUMP01', case.app.run_on_ethernet(
                            case.jump, 'cumulus', '', ['hostname'], 2).strip())
                        control.unlink()
                        case.sessions.ensure_jump_master(case.jump)
                        self.assertEqual('EXAMPLE-JUMP01', case.app.run_on_ethernet(
                            case.jump, 'cumulus', '', ['hostname'], 2).strip())
                    self.assertEqual(2, sum('-M' in command for command in case.calls()))
                    self.assertEqual(str(control), case.sessions.jump_control_path(case.jump))
                self.assertEqual(prior, state['after_cwd'])
                self.assertTrue(state['cwd_fds'], 'fixture must hold the original cwd descriptor')
                self.assertEqual([(state['cwd_fds'][0], [False])], state['restored'])
                self.assertTrue(all(state['closed']))
                self.assertFalse(absolute.parent.exists())
                self.assertTrue(any('-O' in command and 'exit' in command
                                    for command in state['calls_after_master_close']))

    @contextmanager
    def observed_third_world(self, declared, state, *, fault=None, active_fault=False):
        from test_cases.module_loader import load_script
        source = Path(__file__).with_name('test_initial_setup_jump_unreachable_workflow.py')
        name, workflow = 'rv100_observed_third', None
        self.assertNotIn(name, sys.modules)
        raw_factory, raw_popen = tempfile.mkdtemp, subprocess.Popen
        raw_open, raw_fchdir, raw_close = os.open, os.fchdir, os.close
        backup = raw_open('.', os.O_RDONLY | os.O_DIRECTORY)
        identity = os.fstat(backup)
        state.update(world_dirs=[], control_dirs=[], cwd_fds=[], restored=[], fake_calls=[])

        def directory(*args, **kwargs):
            parent = kwargs.get('dir', args[2] if len(args) > 2 else None)
            parent = Path(parent) if parent is not None else None
            self.assertTrue(parent == declared or (parent is not None and any(
                parent.resolve().is_relative_to(world) for world in state['world_dirs'])),
                'every real fixture directory must stay in the independent owned root')
            result = Path(raw_factory(*args, **kwargs))
            prefix = kwargs.get('prefix', args[1] if len(args) > 1 else '')
            if prefix == 'wp2-workflow-':
                state['world_dirs'].append(result)
            elif prefix == 'isj-':
                self.assertEqual(declared, result.parent)
                state['control_dirs'].append(result)
            return str(result)

        def opened(path, flags, *args, **kwargs):
            descriptor = raw_open(path, flags, *args, **kwargs)
            metadata = os.fstat(descriptor)
            if path == '.' and (metadata.st_dev, metadata.st_ino) == (identity.st_dev, identity.st_ino):
                state['cwd_fds'].append(descriptor)
            return descriptor

        def restored(descriptor):
            if descriptor in state['cwd_fds']:
                state['restored'].append((descriptor, [path.exists() for path in state['control_dirs']]))
            return raw_fchdir(descriptor)

        def child(command, *args, **kwargs):
            self.assertIsInstance(command, list)
            self.assertTrue(command and command[0] == 'ssh', 'only modeled SSH children may run')
            self.assertTrue(state['world_dirs'], 'no child before this case world exists')
            self.assertEqual(str(state['world_dirs'][0] / 'ssh'), shutil.which(command[0]),
                             'only this world-owned fake SSH may execute')
            state['fake_calls'].append(list(command))
            return raw_popen(command, *args, **kwargs)

        try:
            workflow = load_script(name, source)
            self.assertNotIn('SHORT_ROOT', vars(workflow))
            actual_load = workflow.load_script

            def loaded(module_name, path):
                module = actual_load(module_name, path)
                if path == workflow.INITIAL and active_fault:
                    prompt = module.prompt_ethernet_passwords

                    def interrupted(*args, **kwargs):
                        prompt(*args, **kwargs)
                        raise fault

                    module.prompt_ethernet_passwords = interrupted
                return module

            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ, {'HTTP_TEST_OWNED_ROOT': str(declared)}))
                stack.enter_context(mock.patch.object(tempfile, 'mkdtemp', side_effect=directory))
                stack.enter_context(mock.patch.object(subprocess, 'Popen', side_effect=child))
                stack.enter_context(mock.patch('pty.fork',
                    side_effect=AssertionError('third workflow must not enter real PTY')))
                stack.enter_context(mock.patch.object(os, 'open', side_effect=opened))
                stack.enter_context(mock.patch.object(os, 'fchdir', side_effect=restored))
                stack.enter_context(mock.patch.object(workflow, 'load_script', side_effect=loaded))
                if fault is not None and not active_fault:
                    stack.enter_context(mock.patch.object(workflow.PublicWorld, '__init__', side_effect=fault))
                try:
                    yield workflow.JumpUnreachableWorkflowTests()
                finally:
                    try:
                        state['after_cwd'] = Path.cwd()
                    except FileNotFoundError:
                        state['after_cwd'] = None
                    state['closed'] = []
                    for descriptor in state['cwd_fds']:
                        try:
                            os.fstat(descriptor)
                        except OSError as error:
                            state['closed'].append(error.errno == errno.EBADF)
                        else:
                            state['closed'].append(False)
        finally:
            try:
                raw_fchdir(backup)
            finally:
                raw_close(backup)
                if workflow is not None and sys.modules.get(name) is workflow:
                    sys.modules.pop(name)

    def test_third_cold_import_has_no_alias_root_factory_or_child(self):
        from test_cases.module_loader import load_script
        source = Path(__file__).with_name('test_initial_setup_jump_unreachable_workflow.py')
        name, workflow = 'rv100_cold_third', None
        self.assertNotIn(name, sys.modules)
        self.assertNotIn('SHORT_ROOT', vars(sys.modules[JumpSessionTests.__module__]))
        try:
            with mock.patch.dict(os.environ), \
                    mock.patch.object(tempfile, 'mkdtemp', side_effect=AssertionError('no factory on cold import')) as factory, \
                    mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no cold import child')) as child, \
                    mock.patch('pty.fork', side_effect=AssertionError('no cold import PTY')) as fork:
                os.environ.pop('HTTP_TEST_OWNED_ROOT', None)
                workflow = load_script(name, source)
                self.assertNotIn('SHORT_ROOT', vars(workflow))
                factory.assert_not_called()
                child.assert_not_called()
                fork.assert_not_called()
        finally:
            if workflow is not None and sys.modules.get(name) is workflow:
                sys.modules.pop(name)

    def test_third_missing_link_mode_and_noncanonical_roots_refuse_before_factory(self):
        from test_cases.module_loader import load_script
        root = self.roots()[0]
        alias, wrong_mode = root.parent / 'third-alias', root.parent / 'third-wrong-mode'
        alias.symlink_to(root, target_is_directory=True)
        wrong_mode.mkdir(mode=0o755)
        wrong_mode.chmod(0o755)
        ordinary = root.parent / 'third-file'
        ordinary.write_text('PUBLIC fixture\n')
        choices = (None, root / 'missing', alias, wrong_mode, ordinary, root / '..' / root.name)
        for index, declared in enumerate(choices):
            with self.subTest(root=str(declared)):
                name, workflow = 'rv100_bad_third_' + str(index), None
                self.assertNotIn(name, sys.modules)
                try:
                    workflow = load_script(name, Path(__file__).with_name(
                        'test_initial_setup_jump_unreachable_workflow.py'))
                    with mock.patch.dict(os.environ), \
                            mock.patch.object(workflow.tempfile, 'TemporaryDirectory',
                                side_effect=AssertionError('unqualified root reached actual factory')) as factory, \
                            mock.patch.object(subprocess, 'Popen',
                                side_effect=AssertionError('unqualified root reached child')) as child, \
                            mock.patch('pty.fork',
                                side_effect=AssertionError('unqualified root reached PTY')) as fork:
                        if declared is None:
                            os.environ.pop('HTTP_TEST_OWNED_ROOT', None)
                        else:
                            os.environ['HTTP_TEST_OWNED_ROOT'] = str(declared)
                        with self.assertRaisesRegex(AssertionError, 'explicit owned test root refused'):
                            workflow.JumpUnreachableWorkflowTests().run_world(blocked_until=0)
                        factory.assert_not_called()
                        child.assert_not_called()
                        fork.assert_not_called()
                finally:
                    if workflow is not None and sys.modules.get(name) is workflow:
                        sys.modules.pop(name)

    def test_third_normal_main_uses_two_roots_and_closes_before_cwd_restore(self):
        prior = Path.cwd()
        for root in self.roots():
            with self.subTest(root=root.name):
                state = {}
                with self.observed_third_world(root, state) as workflow:
                    code, summary, text, waits, opened = workflow.run_world(blocked_until=180)
                    self.assertEqual(0, code)
                    self.assertEqual([240], waits)
                    self.assertEqual(2, opened.count('198.51.100.10'))
                    self.assertEqual(1, opened.count('198.51.100.11'))
                    self.assertEqual(prior, Path.cwd())
                self.assertEqual(prior, state['after_cwd'])
                self.assertTrue(state['cwd_fds'])
                self.assertEqual([(state['cwd_fds'][0], [False] * len(state['control_dirs']))], state['restored'])
                self.assertTrue(all(state['closed']))
                self.assertTrue(state['control_dirs'])
                self.assertTrue(all(not path.exists() for path in state['control_dirs'] + state['world_dirs']))
                self.assertTrue(any('-O' in command and 'exit' in command for command in state['fake_calls']))

    def test_third_setup_and_active_master_errors_keep_identity_and_restore_cwd(self):
        prior = Path.cwd()
        for root, active in zip(self.roots(), (False, True)):
            with self.subTest(root=root.name, active=active):
                error = OwnedJumpControlInterruption('PUBLIC control') if active else OSError(errno.EIO, 'PUBLIC setup')
                state = {}
                with self.assertRaises(type(error)) as caught:
                    with self.observed_third_world(root, state, fault=error, active_fault=active) as workflow:
                        workflow.run_world(blocked_until=180)
                self.assertIs(error, caught.exception)
                self.assertEqual(prior, state['after_cwd'])
                self.assertTrue(state['cwd_fds'])
                self.assertEqual([(state['cwd_fds'][0], [False] * len(state['control_dirs']))], state['restored'])
                self.assertTrue(all(state['closed']))
                self.assertTrue(all(not path.exists() for path in state['control_dirs'] + state['world_dirs']))
                if active:
                    self.assertTrue(state['control_dirs'])
                    self.assertTrue(any('-O' in command and 'exit' in command for command in state['fake_calls']))
                else:
                    self.assertEqual([], state['fake_calls'])

    def test_real_absolute_oversize_still_refuses_before_ssh_and_cleans_exact_directory(self):
        root = self.roots()[1]
        real_factory = tempfile.mkdtemp
        state = {}
        with self.guarded_case(JumpSessionTests, root, state) as case:
            directory = Path(real_factory(prefix='absolute-isj-', dir=root))
            self.assertGreater(len(os.fsencode(str(directory / '0'))) + 17, 104)
            case.make_sessions()
            with mock.patch.object(case.app.tempfile, 'mkdtemp', return_value=str(directory)), \
                    self.assertRaises(case.app.SshFailure) as caught:
                case.establish()
            self.assertEqual(('LOCAL_COMMAND_ERROR', 'outer', '192.0.2.10', 'EXAMPLE-JUMP01'),
                (caught.exception.kind.value, caught.exception.hop,
                 caught.exception.address, caught.exception.jump))
            self.assertEqual([], case.calls())
            self.assertEqual(directory, case.sessions.directory)
        self.assertFalse(directory.exists())

    def test_setup_error_restores_and_closes_held_cwd_before_next_case(self):
        root, state, prior = self.roots()[0], {}, Path.cwd()
        error = OSError(errno.EIO, 'PUBLIC config write failed after owned cwd selection')
        with self.assertRaises(OSError) as caught:
            with self.guarded_case(JumpSessionTests, root, state, fault=error):
                self.fail('config write fault was not reached')
        self.assertIs(error, caught.exception)
        self.assertEqual(prior, state['after_cwd'])
        self.assertTrue(state['cwd_fds'])
        self.assertEqual([(state['cwd_fds'][0], [])], state['restored'])
        self.assertTrue(all(state['closed']))

    def test_missing_link_wrong_mode_and_noncanonical_roots_refuse_before_any_factory(self):
        from test_cases import test_initial_setup_jump_gate as gate
        root = self.roots()[0]
        alias = root.parent / 'alias'
        alias.symlink_to(root)
        wrong_mode = root.parent / 'wrong-mode'
        wrong_mode.mkdir(mode=0o755)
        wrong_mode.chmod(0o755)
        choices = (None, root / 'missing', alias, wrong_mode, root / '..' / root.name)
        for declared in choices:
            for case_type in (JumpSessionTests, gate.JumpGateTests):
                with self.subTest(root=str(declared), fixture=case_type.__name__):
                    state = {}
                    with self.assertRaisesRegex(AssertionError, 'explicit owned test root refused'):
                        with self.guarded_case(case_type, declared, state):
                            self.fail('unqualified root was accepted')
                    self.assertEqual([], state['parents'])


class OwnedJumpFactoryReached(RuntimeError):
    """Independent hard stop after checking root, before any factory operation."""


class OwnedJumpControlInterruption(BaseException):
    """Synthetic control interruption, never a product exception replacement."""


if __name__ == '__main__':
    unittest.main()
