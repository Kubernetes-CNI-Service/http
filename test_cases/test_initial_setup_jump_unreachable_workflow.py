"""WP-2 real C2 reader -> real P1 cache -> real MAIN, fake owned SSH/clock.

Guide :581-593, matching the approved comma-interface workflow's actual C2
load_global/P1 chain. Native password matching is explicitly a PUBLIC model;
real policy/input admission, snapshots, queue, stages, reports and exit execute.
No real SSH, load/setup CLI, installation, service, native image or KAT input.
"""
from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_initial_setup_credentials_fd_workflow as existing
from test_cases import test_initial_setup_jump_sessions as master_fixture
from test_cases.module_loader import load_script
from test_cases.native_cpld_physical_io import owned_test_root

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / 'infiniband/bringup/xdr-initial-setup/initial-setup.py'
C2 = ROOT / 'ztp/config/cumulus/template/90-c2-generate_configs.py'
PUBLIC_CURRENT = '-'.join(('PUBLIC', 'wp2', 'current', '71!'))
PUBLIC_HASH = '$' + '6$PUBLICsalt$' + 'A' * 86
PUBLIC_BANNER = 'PUBLIC-RAW-BANNER-MUST-NOT-APPEAR'
GLOBAL = ('schema_version: 2\ncommon:\n  switch:\n    system:\n'
          '      dns:\n        server:\n        - 192.0.2.53\n'
          '      ntp:\n        server:\n        - 192.0.2.123\n'
          '      date-time:\n        timezone: Etc/UTC\n'
          'switches:\n- ib:\n    system:\n      aaa:\n        user:\n          admin:\n'
          '            pass' + 'word: ' + PUBLIC_HASH + '\n')


class PublicWorld(existing._World):
    """Borrow terminal protocol only; device readback literals are independent."""
    def transport(self, command, responder, timeout, **kwargs):
        self.argvs.append(list(command))
        text = ' '.join(command)
        auth = re.search(r'__HTTP_IB_AUTH_([0-9a-f]{32})_(auth-probe-readonly|password-change|post-change-read)__=BEGIN', text)
        if auth is not None:
            return self.phase_session(command, responder, text, *auth.groups())
        frame = re.search(r'__HTTP_IB_BEGIN_([a-f0-9]+)__', text)
        if frame is None:
            raise AssertionError('PUBLIC check-only IB transport requires the original command frame')
        peer = re.search(r'admin@\[?([a-f0-9:.]+)', text).group(1)
        device = self.by_link_local.get(peer) or self.by_ip.get(peer)
        if device is None:
            raise AssertionError('unknown PUBLIC inner peer')
        if responder('admin@' + peer + "'s password: ") != PUBLIC_CURRENT:
            raise AssertionError('selected IB credential changed roles')
        payload = self.ib_payload(device, text)
        nonce = frame.group(1)
        return self.app.SessionResult('__HTTP_IB_BEGIN_' + nonce + '__\n' + payload
                                      + '__HTTP_IB_END_' + nonce + '__=0\n', 0)

    def ethernet_output(self, jump, command):
        if command == ['ip', 'neighbor']:
            index = 0 if jump == 'EXAMPLE-JUMP01' else 1
            suffix = ('10', '12')[index]
            return 'fe80::ff:fe00:' + suffix + ' dev vlan1000 lladdr 02:00:00:00:00:' + suffix + ' REACHABLE\n'
        return super().ethernet_output(jump, command)

    def ib_payload(self, device, text):
        if re.search(r'\bnv (?:set|unset)\b|\bnv config (?:apply|save)\b', text):
            self.writes.append(text)
            raise AssertionError('read-only workflow must not write an IB')
        if 'nv show system ztp' in text:
            return 'service disabled\nstatus aborted\nconfig-save enabled enabled\n'
        if 'nv config diff' in text or ('true' in text and 'nv ' not in text):
            return ''
        if 'nv config show' in text:
            return ('nv set system config auto-save state enabled\n'
                    'nv set system ztp config-save enabled\n'
                    'nv set interface eth0 ipv4 address ' + device.login_ip + '/24\n'
                    'nv set interface eth0-1 ipv4 gateway 192.0.2.1\n'
                    'nv set interface eth0-1 link state up\n'
                    'nv set interface eth0-1 type eth\n'
                    'nv set system hostname ' + device.hostname + '\n'
                    'nv set system dns server 192.0.2.53\n'
                    'nv set system ntp server 192.0.2.123 state enabled\n'
                    'nv set system date-time timezone Etc/UTC\n')
        raise AssertionError('unexpected PUBLIC IB command')

    def phase_session(self, command, responder, text, nonce, operation):
        # The already-authenticated outer master never emits a second password prompt.
        peer = re.search(r'admin@\[?(fe80::[0-9a-f:]+)', text).group(1)
        device = self.by_link_local[peer]
        session = existing._PhaseSession(self.app, responder)
        end = '__HTTP_IB_AUTH_' + nonce + '_' + operation + '__=EXIT:'
        session.feed('\n__HTTP_IB_AUTH_' + nonce + '_' + operation + '__=BEGIN\n')
        if session.feed('admin@' + peer + "'s password: ") != PUBLIC_CURRENT:
            raise AssertionError('selected IB credential changed roles')
        payload = self.ib_payload(device, 'nv config show')
        session.feed('\n__HTTP_IB_BEGIN_' + nonce + '__\n' + payload + '__HTTP_IB_END_' + nonce + '__=0\n' + end + '0\n')
        return session.result(0)


class JumpUnreachableWorkflowTests(unittest.TestCase):
    def run_world(self, *, blocked_until):
        owned_root = owned_test_root()
        app = load_script('wp2_real_main', INITIAL)
        with tempfile.TemporaryDirectory(prefix='wp2-workflow-', dir=owned_root) as folder, ExitStack() as stack:
            root = Path(folder)
            original_cwd = os.open('.', os.O_RDONLY | os.O_DIRECTORY)

            def restore_cwd():
                try:
                    os.fchdir(original_cwd)
                finally:
                    os.close(original_cwd)

            stack.callback(restore_cwd)
            os.chdir(owned_root)
            home = root / 'home'
            home.mkdir()
            world = PublicWorld(self, app, root, jump_passwords={'EXAMPLE-JUMP01': '', 'EXAMPLE-JUMP02': ''},
                                ib_password=PUBLIC_CURRENT, configured=True, global_text=GLOBAL)
            world.by_link_local = {'fe80::ff:fe00:10': world.devices[existing.IBS[0][0]],
                                   'fe80::ff:fe00:12': world.devices[existing.IBS[1][0]]}
            clock_path, blocked_path = root / 'clock', root / 'blocked'
            clock_path.write_text('0')
            calls, successes = root / 'ssh-calls.jsonl', root / 'master-success.jsonl'
            config, state = root / 'config.json', root / 'state.json'
            commands = [['hostname'], ['nv', 'show', 'interface'], ['ip', '-d', 'link', 'show'],
                        ['bridge', 'fdb', 'show'], ['ip', 'neighbor'], ['ip', '-j', 'address', 'show'],
                        ['ifquery', 'vlan1000']]
            outputs = {address: {shlex.join(command): world.ethernet_output(host, command) for command in commands}
                       for host, address in existing.JUMPS}
            config.write_text(json.dumps({'outputs': outputs, 'hostname': dict((ip, host) for host, ip in existing.JUMPS)}))
            program = master_fixture.FAKE_SSH
            program = program.replace('import json, os, sys', 'import json, os, sys, shlex')
            program = program.replace("if '-O' in a:\n", """blocked = Path(os.environ['WP2_BLOCKED']).exists() and float(Path(os.environ['WP2_CLOCK']).read_text()) < float(os.environ['WP2_UNTIL'])
if '-O' in a:
    if blocked and state.get(cp) == '198.51.100.10' and a[a.index('-O') + 1] == 'check':
        raise SystemExit(255)
""")
            program = program.replace("    addr = endpoint.split('@', 1)[1]\n", """    addr = endpoint.split('@', 1)[1]
    if blocked and addr == '198.51.100.10':
        print('ssh: connect to host 198.51.100.10 port 22: Connection timed out', file=sys.stderr)
        raise SystemExit(255)
""")
            program = program.replace('    state[cp] = addr\n', "    with Path(os.environ['WP2_SUCCESSES']).open('a') as h: h.write(addr + '\\n')\n    state[cp] = addr\n")
            anchor = "print(cfg.get('hostname', {}).get(addr, 'EXAMPLE-JUMP01') if 'hostname' in a[-1] else 'fixture-output')"
            self.assertEqual(1, program.count(anchor), 'owned fixture program anchor, never a product patch')
            program = program.replace(anchor, "remote = shlex.split(a[-1])[2].split('; exec ', 1)[1]\nprint(cfg['outputs'][addr][shlex.join(shlex.split(remote))], end='')")
            fake_ssh = root / 'ssh'
            fake_ssh.write_text('#!' + sys.executable + '\n' + program)
            fake_ssh.chmod(0o700)
            now, waits, sessions = [0.0], [], []
            def sleep(seconds):
                self.assertIsNone(app._TASK_DEADLINE, 'coordinator cooldown is not an IB task deadline')
                waits.append(seconds)
                now[0] += seconds
                clock_path.write_text(str(now[0]))
            actual_mkdtemp, actual_run = tempfile.mkdtemp, app.subprocess.run
            def owned_directory(*args, **kwargs):
                if kwargs.get('prefix') == 'isj-':
                    self.assertEqual('/tmp', kwargs['dir'])
                    absolute = Path(actual_mkdtemp(prefix='isj-', dir=owned_root))
                    relative = absolute.relative_to(owned_root)
                    self.assertEqual(owned_root, absolute.parent)
                    self.assertEqual(absolute, relative.resolve())
                    return str(relative)
                self.assertTrue(Path(kwargs['dir']).resolve().is_relative_to(root))
                return actual_mkdtemp(*args, **kwargs)
            def run(command, *args, **kwargs):
                self.assertEqual('ssh', command[0], 'no arbitrary subprocess in real MAIN workflow')
                self.assertEqual(str(fake_ssh), shutil.which('ssh'))
                return actual_run(command, *args, **kwargs)
            def transport(command, responder, timeout, **kwargs):
                text = ' '.join(command)
                inner = bool(re.search(r'admin@\[?(?:fe80:|192\.0\.2\.)', text))
                if inner:
                    if 'cumulus@198.51.100.10' in text:
                        if not blocked_path.exists():
                            # Public network-loss fixture: the old outer socket
                            # disappears while the first IB session is blocked.
                            for socket, address in json.loads(state.read_text()).items():
                                if address == '198.51.100.10':
                                    self.assertEqual(owned_root, Path(socket).resolve().parent.parent)
                                    Path(socket).unlink(missing_ok=True)
                        blocked_path.touch(exist_ok=True)
                        if now[0] < blocked_until:
                            return app.SessionResult('ssh: connect to host 198.51.100.10 port 22: Connection timed out\n'
                                                     + PUBLIC_BANNER + '\n', 255)
                    return world.transport(command, responder, timeout, **kwargs)
                completed = run(command, text=True, capture_output=True, timeout=timeout, check=False)
                return app.SessionResult(completed.stdout + completed.stderr, completed.returncode)
            actual_factory = app._new_jump_sessions
            def factory(**kwargs):
                session = actual_factory(**kwargs)
                sessions.append(session)
                return session
            env = {'HOME': str(home), 'PATH': str(root) + os.pathsep + os.environ.get('PATH', ''),
                   'WP1_CONFIG': str(config), 'WP1_STATE': str(state), 'WP1_CALLS': str(calls),
                   'WP2_CLOCK': str(clock_path), 'WP2_BLOCKED': str(blocked_path),
                   'WP2_UNTIL': str(blocked_until), 'WP2_SUCCESSES': str(successes)}
            stack.enter_context(mock.patch.dict(os.environ, env))
            stack.enter_context(mock.patch.object(Path, 'home', return_value=home))
            stack.enter_context(mock.patch.object(app.tempfile, 'mkdtemp', side_effect=owned_directory))
            stack.enter_context(mock.patch.object(app.subprocess, 'run', side_effect=run))
            stack.enter_context(mock.patch.object(app, 'interactive_run', side_effect=transport))
            application_clock = SimpleNamespace(**{**vars(app.time), 'monotonic': lambda: now[0], 'sleep': sleep})
            stack.enter_context(mock.patch.object(app, 'time', application_clock))
            stack.enter_context(mock.patch.object(existing, 'time', application_clock))
            stack.enter_context(mock.patch.object(app, '_new_jump_sessions', side_effect=factory))
            stack.enter_context(mock.patch.object(app, 'verify_password_hash',
                                                 side_effect=lambda value, setting: value == PUBLIC_CURRENT and setting == PUBLIC_HASH))
            stack.enter_context(mock.patch('builtins.input', side_effect=AssertionError('fd mode prompt')))
            stack.enter_context(mock.patch.object(app.getpass, 'getpass', side_effect=AssertionError('fd mode prompt')))
            stdout, stderr = io.StringIO(), io.StringIO()
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))

            def close_owned_sessions(exc_type, primary, traceback):
                for session in sessions:
                    if session.directory is not None:
                        try:
                            session.close_jump_masters()
                        except BaseException as cleanup:
                            # Match the original product lifetime's priority;
                            # never replace its primary with ordinary cleanup.
                            if primary is None or (isinstance(primary, Exception)
                                                   and not isinstance(cleanup, Exception)):
                                raise
                return False

            stack.push(close_owned_sessions)
            with mock.patch.object(sys, 'argv', [str(C2), '--branch=ib']):
                c2 = load_script('wp2_actual_c2', C2)
            with mock.patch.object(c2, '_GLOBAL_FILE', str(root / '01-global.yaml')):
                selected = c2.load_global('ib')
            self.assertEqual(['192.0.2.53'], selected['system']['dns']['server'])
            self.assertEqual(['192.0.2.123'], selected['system']['ntp']['server'])
            self.assertEqual('Etc/UTC', selected['system']['date-time']['timezone'])
            with mock.patch.object(sys, 'argv', world.argv('--generate-json')):
                self.assertEqual(0, app.main())
            if app.REPORT_HANDLE is not None:
                app.REPORT_HANDLE.close()
                app.REPORT_HANDLE = None
            self.assertEqual(5, json.loads((root / 'targets.json').read_text())['version'])
            reader, writer = os.pipe()
            os.write(writer, json.dumps({'jump_passwords': {}, 'nvos_initial_password': PUBLIC_CURRENT,
                                         'ib_target_password': PUBLIC_CURRENT}).encode())
            os.close(writer)
            reader_stat = os.fstat(reader)
            reader_identity = (reader_stat.st_dev, reader_stat.st_ino)
            try:
                with mock.patch.object(sys, 'argv', world.argv('--credentials-fd', str(reader))):
                    code = app.main()
            finally:
                try:
                    current = os.fstat(reader)
                    if (current.st_dev, current.st_ino) == reader_identity:
                        os.close(reader)
                except OSError:
                    pass
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
                    app.REPORT_HANDLE = None
            summary = world.summary()
            healthy = summary['records'][existing.IBS[1][0].casefold()]
            self.assertEqual('ALREADY_CONFIGURED', healthy['outcome'],
                             'independent healthy-jump control must qualify before the blocked-jump oracle')
            outputs_text = stdout.getvalue() + stderr.getvalue() + world.outputs()
            opened = successes.read_text().splitlines() if successes.exists() else []
            self.assertFalse(world.writes)
            self.assertEqual(1, len(sessions), '--generate-json has no session factory; online MAIN creates one')
            self.assertTrue(all(session.directory is None for session in sessions))
            return code, summary, outputs_text, waits, opened

    def test_application_clock_does_not_capture_external_time_consumers(self):
        # The real subprocess module retains this same stdlib module, not
        # the subject's app.time reference. Its waits must stay on real time.
        import time as external_time
        original_sleep, original_monotonic = external_time.sleep, external_time.monotonic
        original_load = load_script
        observed, subject = [], {}

        def load_with_clock_observation(name, path):
            if Path(path) == C2:
                observed.append('clock installed before real C2')
                self.assertIs(original_sleep, external_time.sleep)
                self.assertIs(original_monotonic, external_time.monotonic)
                self.assertIsNot(external_time, subject['app'].time)
                self.assertEqual(0.0, subject['app'].time.monotonic())
                external_time.sleep(0)
                self.assertEqual(0.0, subject['app'].time.monotonic())
            loaded = original_load(name, path)
            if Path(path) == INITIAL:
                subject['app'] = loaded
            return loaded

        with mock.patch.object(sys.modules[__name__], 'load_script',
                               side_effect=load_with_clock_observation):
            code, summary, text, waits, opened = self.run_world(blocked_until=180)
        self.assertEqual(['clock installed before real C2'], observed)
        self.assertEqual(0, code)
        self.assertEqual([240], waits)
        self.assertEqual(2, opened.count('198.51.100.10'))
        self.assertEqual(1, opened.count('198.51.100.11'))
        self.assertNotIn(PUBLIC_BANNER, text)

    def test_blocked_jump_recovers_or_is_named(self):
        code, summary, text, waits, opened = self.run_world(blocked_until=180)
        diagnostic = {name: {key: record.get(key) for key in ('outcome', 'category', 'failed_stage', 'script_error', 'reason')}
                      for name, record in summary['records'].items()}
        safe_diagnostic = json.dumps(diagnostic).replace(PUBLIC_CURRENT, '[redacted]').replace(PUBLIC_HASH, '[redacted]')
        self.assertEqual(0, code, 'the temporarily blocked jump should recover after one cooldown: ' + safe_diagnostic)
        self.assertEqual([240], waits)
        self.assertEqual(2, opened.count('198.51.100.10'))
        self.assertEqual(1, opened.count('198.51.100.11'))
        for record in summary['records'].values():
            self.assertEqual('ALREADY_CONFIGURED', record['outcome'])
            self.assertFalse(record['writes_attempted'])
        self.assertNotIn(PUBLIC_BANNER, text)

    def test_summary_has_no_raw_banner_and_exit_is_incomplete(self):
        code, summary, text, waits, opened = self.run_world(blocked_until=9999)
        self.assertEqual(2, code)
        self.assertEqual([240, 240], waits)
        first, second = (summary['records'][host.casefold()] for host, *_ in existing.IBS)
        self.assertEqual('FAILED_OOB_JUMP_UNREACHABLE', first['category'])
        self.assertEqual('OOB_JUMP_UNREACHABLE', first['failure_kind'])
        self.assertEqual('EXAMPLE-JUMP01', first['jump']['hostname'])
        self.assertEqual('198.51.100.10', first['jump']['login_ip'])
        self.assertEqual('eth_jump', first['jump']['type'])
        self.assertFalse(first['writes_attempted'])
        self.assertEqual('ALREADY_CONFIGURED', second['outcome'])
        self.assertIn('network', text.lower())
        self.assertNotIn(PUBLIC_BANNER, text)


if __name__ == '__main__':
    unittest.main()
