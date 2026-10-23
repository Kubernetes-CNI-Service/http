"""Direct operator-usability contracts for the IB upgrade entry; no device IO.

Three owner-requested behaviours of infiniband/bringup/xdr-upgrade/upgrade.py:

* a fixed, audited SSH-runtime venv (owner ruling 2026-10-23:
  ~/.venvs/http/ibsw-upgrade, then the compatible ~/.venv-upgrade) is selected
  once before any guard, prompt or secret, so ``python3 upgrade.py`` works
  without manual activation;
* the process raises only its own open-file soft limit toward
  min(hard limit, estimated need) before the startup FD budget is evaluated;
* after the default interactive inspection, an explicit ``yes`` can continue
  into the real upgrade of exactly the READY/UPGRADE_REQUIRED devices.

Expected values come from these requirements and the documented pipeline
reservations, never from the implementation under test.
"""
import ast
import contextlib
import io
import os
from pathlib import Path
import pwd
import resource
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import unittest as _unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _support

_runtime = _support(_unittest.TestCase())
app = _runtime.app
import ibsw_upgrade_pipeline as pipeline  # noqa: E402  fixed tools path bound by support()
import ibsw_upgrade_observer as observer  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'infiniband/bringup/xdr-upgrade/upgrade.py'
ENTRY_DIRECTORY = ENTRY.parent
REQUIREMENTS = ENTRY_DIRECTORY / 'requirements.txt'
MARKER = 'IBSW_UPGRADE_VENV_REEXEC'
# requirements.txt pins (owner-approved SSH runtime); PyYAML is present but unpinned.
PINS = (('paramiko', '5.0.0'), ('bcrypt', '5.0.0'), ('cryptography', '50.0.1'),
        ('invoke', '2.2.1'), ('PyNaCl', '1.6.2'), ('cffi', '2.0.0'),
        ('pycparser', '2.23'), ('typing-extensions', '4.16.0'))
UNPINNED = ('PyYAML',)


def make_venv(root, *, versions=None, python_version='3.12'):
    """Synthetic venv layout with dist-info metadata only; nothing is installed."""
    versions = dict(PINS, PyYAML='6.0.2') if versions is None else versions
    root.mkdir(parents=True)
    site = root / 'lib' / ('python' + python_version) / 'site-packages'
    (root / 'bin').mkdir()
    site.mkdir(parents=True)
    (root / 'pyvenv.cfg').write_text('home = /usr/bin\ninclude-system-site-packages = false\n')
    python = root / 'bin' / 'python3'
    python.write_text('#!/bin/sh\nexit 97\n')
    python.chmod(0o755)
    for name, version in versions.items():
        info = site / (name.replace('-', '_') + '-' + version + '.dist-info')
        info.mkdir()
        (info / 'METADATA').write_text(
            'Metadata-Version: 2.1\nName: ' + name + '\nVersion: ' + version + '\n')
    for directory in (root, root / 'bin', root / 'lib', site.parent, site):
        directory.chmod(0o755)
    return root


class _Exec(BaseException):
    """Stops the test at the exec boundary; BaseException so callers cannot swallow it."""

    def __init__(self, path, argv, env):
        super().__init__(path)
        self.path, self.argv, self.env = path, list(argv), dict(env)


def recording_exec(path, argv, env):
    raise _Exec(path, argv, env)


def missing_runtime(name):
    # A system interpreter: cryptography from the distribution, paramiko absent.
    if name == 'cryptography':
        return '46.0.5'
    raise app.metadata.PackageNotFoundError(name)


class RuntimeRequirementsTests(unittest.TestCase):
    def test_requirements_file_pins_match_the_observer_runtime_pins(self):
        lines = [line.strip() for line in REQUIREMENTS.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        pinned = tuple(tuple(line.split('==')) for line in lines if '==' in line)
        unpinned = tuple(line for line in lines if '==' not in line)
        self.assertEqual(PINS, pinned)
        self.assertEqual(UNPINNED, unpinned)
        self.assertEqual(PINS, tuple(observer.SSH_RUNTIME_PINS))


class RuntimeVenvSwitchTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='ibsw-venv-switch-')
        self.root = Path(self.folder.name).resolve()
        self.addCleanup(self.folder.cleanup)

    def switch(self, args, *, candidates, version=missing_runtime, flags=None):
        err = io.StringIO()
        environment = {key: value for key, value in os.environ.items() if key != MARKER}
        with patch.dict(os.environ, environment, clear=True), \
             patch.object(app.metadata, 'version', side_effect=version), \
             patch.object(app, '_runtime_venv_candidates', return_value=tuple(candidates)), \
             patch.object(app, '_read_password', side_effect=AssertionError('no prompt before switch')), \
             patch.object(os, 'execve', side_effect=recording_exec), \
             patch.object(sys, 'argv', ['upgrade.py', *args]), \
             contextlib.ExitStack() as stack, contextlib.redirect_stderr(err):
            if flags is not None:
                stack.enter_context(patch.object(app.sys, 'flags', flags))
            try:
                status = app._reexec_in_runtime_venv(tuple(args))
            except _Exec as executed:
                return executed, err.getvalue(), dict(os.environ)
        return status, err.getvalue(), None

    def test_candidates_are_the_owner_fixed_home_paths_in_order(self):
        # Owner ruling 2026-10-23: ~/.venvs/http/ibsw-upgrade first, the existing
        # ~/.venv-upgrade as compatible second, expanded with os.path.expanduser;
        # the script-directory .venv is no longer a candidate.
        home = self.root / 'operator-home'
        with patch.dict(os.environ, {'HOME': str(home)}):
            candidates = tuple(app._runtime_venv_candidates())
        self.assertEqual((home / '.venvs' / 'http' / 'ibsw-upgrade', home / '.venv-upgrade'), candidates)
        self.assertNotIn(ENTRY_DIRECTORY / '.venv', candidates)
        self.assertEqual(MARKER, app._RUNTIME_VENV_MARKER)

    def test_satisfied_interpreter_never_switches(self):
        venv = make_venv(self.root / 'good')
        versions = dict(PINS, PyYAML='6.0.2')

        def present(name):
            return versions[name]
        status, err, _env = self.switch(('--upgrade', '--yes'), candidates=(venv,), version=present)
        self.assertNotIsInstance(status, _Exec)
        self.assertEqual('', err)

    def test_unmet_runtime_switches_once_with_unchanged_arguments_and_marker_only(self):
        first, second = make_venv(self.root / 'first'), make_venv(self.root / 'second')
        args = ('--upgrade', '--yes', '--devices', 'ib-spine0[1-2]*', '--method', 'http')
        executed, err, _env = self.switch(args, candidates=(first, second))
        self.assertIsInstance(executed, _Exec)
        python = str(first / 'bin' / 'python3')
        self.assertEqual(python, executed.path)
        options = ['-B'] if sys.flags.dont_write_bytecode else []
        self.assertEqual([python, *options, 'upgrade.py', *args], executed.argv)
        expected = {key: value for key, value in os.environ.items() if key != MARKER}
        expected[MARKER] = '1'
        self.assertEqual(expected, executed.env)
        self.assertIn('[RUNTIME]', err)
        self.assertIn(str(first), err)
        self.assertIn('paramiko', err)

    def test_isolation_and_site_flags_are_not_forwarded_to_the_venv(self):
        venv = make_venv(self.root / 'venv')
        flags = SimpleNamespace(dont_write_bytecode=0, isolated=1, no_site=1,
                                ignore_environment=1, no_user_site=1, safe_path=True)
        executed, _err, _env = self.switch(('--inspect-only',), candidates=(venv,), flags=flags)
        self.assertEqual([str(venv / 'bin' / 'python3'), 'upgrade.py', '--inspect-only'], executed.argv)

    def test_marker_prevents_a_second_switch_and_is_removed_from_this_process(self):
        venv = make_venv(self.root / 'venv')
        with patch.dict(os.environ, {MARKER: '1'}), \
             patch.object(app.metadata, 'version', side_effect=missing_runtime), \
             patch.object(app, '_runtime_venv_candidates', return_value=(venv,)), \
             patch.object(os, 'execve', side_effect=AssertionError('second switch')), \
             patch.object(sys, 'argv', ['upgrade.py', '--upgrade', '--yes']), \
             contextlib.redirect_stderr(io.StringIO()):
            app._reexec_in_runtime_venv(('--upgrade', '--yes'))
            self.assertNotIn(MARKER, os.environ)

    def test_help_version_scripts_diagnostics_and_invalid_arguments_never_switch(self):
        venv = make_venv(self.root / 'venv')
        for args in (('--help',), ('-h',), ('--version',), ('--upgrade', '--help'),
                     ('--scripts-only',), ('--diagnose-inputs',), ('--no-such-option',)):
            with self.subTest(args=args):
                status, err, _env = self.switch(args, candidates=(venv,))
                self.assertNotIsInstance(status, _Exec)
                self.assertEqual('', err)

    def test_audit_skips_unsafe_or_wrong_candidates_in_fixed_order(self):
        good = make_venv(self.root / 'good')
        cases = {}
        cases['other-writable'] = make_venv(self.root / 'other-writable')
        cases['other-writable'].chmod(0o757)
        cases['wrong-pin'] = make_venv(self.root / 'wrong-pin',
                                       versions=dict(PINS, cryptography='46.0.5', PyYAML='6.0.2'))
        cases['missing-yaml'] = make_venv(self.root / 'missing-yaml', versions=dict(PINS))
        cases['no-pyvenv'] = make_venv(self.root / 'no-pyvenv')
        (cases['no-pyvenv'] / 'pyvenv.cfg').unlink()
        cases['not-executable'] = make_venv(self.root / 'not-executable')
        (cases['not-executable'] / 'bin' / 'python3').chmod(0o644)
        cases['symlinked-root'] = self.root / 'symlinked-root'
        cases['symlinked-root'].symlink_to(make_venv(self.root / 'link-target'))
        cases['absent'] = self.root / 'absent'
        for label, bad in cases.items():
            with self.subTest(candidate=label):
                python, reason = app._audited_runtime_venv(bad)
                self.assertIsNone(python)
                self.assertTrue(reason)
                executed, _err, _env = self.switch(('--upgrade', '--yes'), candidates=(bad, good))
                self.assertIsInstance(executed, _Exec)
                self.assertEqual(str(good / 'bin' / 'python3'), executed.path)
        status, _err, _env = self.switch(('--upgrade', '--yes'),
                                         candidates=(cases['wrong-pin'], cases['absent']))
        self.assertNotIsInstance(status, _Exec)

    def test_group_writable_venv_is_accepted_only_for_a_private_user_group(self):
        venv = make_venv(self.root / 'group-writable')
        venv.chmod(0o775)
        account = pwd.getpwuid(os.geteuid())
        private = SimpleNamespace(gr_name=account.pw_name, gr_mem=[], gr_gid=account.pw_gid)
        shared = SimpleNamespace(gr_name='synthetic-shared', gr_mem=['someone-else'], gr_gid=account.pw_gid)
        info = os.stat(venv)
        if info.st_gid != account.pw_gid:
            self.skipTest('temporary directory group is not the primary group of this account')
        with patch('grp.getgrgid', return_value=private):
            self.assertIsNotNone(app._audited_runtime_venv(venv)[0])
        with patch('grp.getgrgid', return_value=shared):
            self.assertIsNone(app._audited_runtime_venv(venv)[0])

    def test_no_candidate_hold_names_exact_create_commands_without_installing(self):
        first, second = self.root / 'first', self.root / 'second'
        with patch.object(app.metadata, 'version', return_value='0.0'), \
             patch.object(app, '_runtime_venv_candidates', return_value=(first, second)), \
             patch.object(subprocess, 'run', side_effect=AssertionError('nothing is installed')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('nothing is installed')), \
             self.assertRaises(app._InspectionHold) as raised:
            app._check_runtime()
        message = str(raised.exception)
        # Original diagnostic is preserved verbatim.
        self.assertIn('paramiko expected=5.0.0 installed=0.0', message)
        self.assertIn('nothing was installed automatically', message)
        # Both fixed candidates are named; the owner-designated first one is the creation target.
        self.assertIn(str(second), message)
        self.assertIn('python3 -m venv ' + str(first), message)
        self.assertIn(str(first / 'bin' / 'python') + ' -m pip install -r '
                      + str(ENTRY_DIRECTORY / 'requirements.txt'), message)

    def test_parent_directories_inside_home_are_audited(self):
        home = self.root / 'operator-home'
        venv = make_venv(home / '.venvs' / 'http' / 'ibsw-upgrade')
        for directory in (home, home / '.venvs', home / '.venvs' / 'http'):
            directory.chmod(0o755)
        with patch.dict(os.environ, {'HOME': str(home)}):
            self.assertIsNotNone(app._audited_runtime_venv(venv)[0])
            (home / '.venvs').chmod(0o757)
            python, reason = app._audited_runtime_venv(venv)
            self.assertIsNone(python)
            self.assertIn('writable by others', reason)

    def test_switch_precedes_the_guard_and_every_prompt_in_the_script_entry(self):
        tree = ast.parse(ENTRY.read_text())
        blocks = [node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "__name__ == '__main__'"]
        self.assertEqual(1, len(blocks))
        calls = [name for _line, _column, name in sorted(
            (node.lineno, node.col_offset, ast.unparse(node.func))
            for node in ast.walk(blocks[0]) if isinstance(node, ast.Call))]
        self.assertIn('_reexec_in_runtime_venv', calls)
        self.assertIn('_guarded_main', calls)
        self.assertLess(calls.index('_reexec_in_runtime_venv'), calls.index('_guarded_main'))
        # main() itself never switches interpreters: tests and the guard call it in-process.
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        self.assertNotIn('_reexec_in_runtime_venv',
                         [ast.unparse(n.func) for n in ast.walk(main) if isinstance(n, ast.Call)])


class _Limits:
    """In-memory RLIMIT_NOFILE; the real test-process limit is never changed."""

    def __init__(self, soft, hard, *, refuse=False):
        self.soft, self.hard, self.refuse, self.calls = soft, hard, refuse, []

    def getrlimit(self, which):
        assert which == resource.RLIMIT_NOFILE
        return self.soft, self.hard

    def setrlimit(self, which, limits):
        assert which == resource.RLIMIT_NOFILE
        self.calls.append(tuple(limits))
        if self.refuse:
            raise ValueError('synthetic refusal')
        self.soft, self.hard = limits

    @contextlib.contextmanager
    def active(self):
        with patch.object(resource, 'getrlimit', self.getrlimit), \
             patch.object(resource, 'setrlimit', self.setrlimit):
            yield


class DescriptorSoftLimitTests(unittest.TestCase):
    def raise_limit(self, limits, required):
        err = io.StringIO()
        with limits.active(), contextlib.redirect_stderr(err):
            record = app._raise_descriptor_soft_limit(required)
        return record, err.getvalue()

    def test_raises_only_the_soft_value_toward_the_need_and_keeps_hard(self):
        limits = _Limits(1024, 524288)
        record, err = self.raise_limit(limits, 18000)
        self.assertEqual([(18000, 524288)], limits.calls)
        self.assertEqual((1024, 18000, 524288, 18000),
                         (record['soft_before'], record['soft_after'], record['hard'], record['required']))
        self.assertIn('1024 -> 18000', err)
        self.assertIn('shell', err)

    def test_hard_limit_caps_the_target_and_is_reported(self):
        limits = _Limits(1024, 4096)
        record, err = self.raise_limit(limits, 18000)
        self.assertEqual([(4096, 4096)], limits.calls)
        self.assertEqual(4096, record['soft_after'])
        self.assertIn('1024 -> 4096', err)
        self.assertIn('hard', err.lower())
        self.assertIn('18000', err)

    def test_sufficient_or_unlimited_soft_limit_is_left_unchanged_silently(self):
        for soft in (18000, 65536, resource.RLIM_INFINITY):
            with self.subTest(soft=soft):
                limits = _Limits(soft, resource.RLIM_INFINITY)
                record, err = self.raise_limit(limits, 18000)
                self.assertEqual([], limits.calls)
                self.assertEqual('', err)
                self.assertEqual(record['soft_before'], record['soft_after'])

    def test_unlimited_hard_limit_uses_the_estimated_need(self):
        limits = _Limits(256, resource.RLIM_INFINITY)
        record, _err = self.raise_limit(limits, 5000)
        self.assertEqual([(5000, resource.RLIM_INFINITY)], limits.calls)
        self.assertEqual(5000, record['soft_after'])

    def test_refused_change_keeps_the_original_limit_and_continues(self):
        limits = _Limits(1024, 524288, refuse=True)
        record, err = self.raise_limit(limits, 18000)
        self.assertEqual(1024, record['soft_after'])
        self.assertEqual((1024, 524288), (limits.soft, limits.hard))
        self.assertIn('1024', err)

    def test_estimate_admits_full_startup_and_upgrade_concurrency_under_pipeline_rules(self):
        # The pipeline's own admission functions are the oracle: with retained
        # startup evidence of up to 16 descriptors per device, half the target
        # must still admit every startup worker and every upgrade worker.
        for candidates, workers, hops in ((192, 32, 1), (192, 32, 3), (2, 1, 1), (40, 20, 2)):
            with self.subTest(candidates=candidates, workers=workers, hops=hops):
                with patch.object(pipeline, '_open_descriptor_count', return_value=40):
                    inspect = app._descriptor_soft_target(candidates, workers, upgrade=False, os_hops=hops)
                    upgrade = app._descriptor_soft_target(candidates, workers, upgrade=True, os_hops=hops)
                occupied = 40 + 16 * candidates
                self.assertEqual(workers, pipeline.preflight_slots(
                    soft=inspect, occupied=occupied, pending=0, requested=workers))
                upgrade_workers = min(32, (candidates + 1) // 2)
                self.assertEqual(upgrade_workers, pipeline._descriptor_budget(
                    soft=upgrade, occupied=occupied, requested=upgrade_workers, os_hops=hops)['in_flight_limit'])
                self.assertGreaterEqual(upgrade, inspect)
        with patch.object(pipeline, '_open_descriptor_count', return_value=40):
            field = app._descriptor_soft_target(192, 32, upgrade=True, os_hops=1)
            small = app._descriptor_soft_target(2, 1, upgrade=True, os_hops=1)
        self.assertGreater(field, 1024, 'the 192-device field case needs more than the default soft limit')
        self.assertLessEqual(field, 65536)
        self.assertLessEqual(small, 2048, 'small batches must not ask for a large limit')


def summary_fixture():
    rows = []

    def plan(host, os_action='AT_TARGET_NO_FLASH', bios='AT_TARGET_NO_FLASH', cpld='AT_TARGET_NO_FLASH'):
        for component, action in (('os', os_action), ('bios', bios), ('cpld', cpld)):
            rows.append(dict(hostname=host, component=component, current='c', target='t', action=action))
    plan('ib-a.example.test', cpld='UPGRADE_REQUIRED')
    plan('ib-b.example.test')
    plan('ib-c.example.test', cpld='UPGRADE_REQUIRED')
    plan('ib-d.example.test', bios='REVIEW_REQUIRED', cpld='UPGRADE_REQUIRED')
    plan('ib-e.example.test', os_action='UPGRADE_REQUIRED')
    health = []
    for number, host in enumerate(('ib-a.example.test', 'ib-b.example.test', 'ib-c.example.test',
                                   'ib-d.example.test', 'ib-e.example.test'), 1):
        health.append(dict(observation_id='h%d' % number, hostname=host, phase='STARTUP',
                           observed_state='FAIL' if host == 'ib-c.example.test' else 'PASS'))
    return dict(state='READONLY_INSPECTION_DATA', mode='INSPECT_ONLY', result='INCOMPLETE',
                run_directory='/synthetic/run-inspect', selected_components=['os', 'bios', 'cpld'],
                targets=[dict(hostname=h) for h in ('ib-a.example.test', 'ib-b.example.test', 'ib-c.example.test',
                                                    'ib-d.example.test', 'ib-e.example.test')],
                skipped_devices=[dict(hostname='ib-z.example.test', state='SKIPPED_UNREACHABLE',
                                      reasons=['SSH_CONNECT_FAILED'])],
                version_plan=rows, health_checks=health,
                component_precheck_issues=[dict(hostname='ib-d.example.test', component='bios',
                                                reason_code='BIOS_VERSION_UNPARSED')])


class UpgradeOfferTests(unittest.TestCase):
    def parsed(self, *args):
        with patch.object(Path, 'home', return_value=Path('/synthetic/home')):
            return app._parse_cli(args)

    def test_plan_offers_only_ready_upgrade_required_devices_with_passing_health(self):
        plan = app._upgrade_handoff_plan(summary_fixture())
        self.assertEqual(('ib-a.example.test', 'ib-e.example.test'), tuple(plan['devices']))
        self.assertEqual({'cpld': ('ib-a.example.test',), 'os': ('ib-e.example.test',)},
                         {k: tuple(v) for k, v in plan['components'].items() if v})
        self.assertEqual(('ib-c.example.test',), tuple(plan['excluded']['health_not_pass']))
        self.assertEqual(('ib-d.example.test',), tuple(plan['excluded']['review_required']))
        self.assertEqual('/synthetic/run-inspect', plan['inspection_run_directory'])

    def offer(self, argv, *, terminal=True, answer=None, summary=None, json_flag=False):
        parsed = self.parsed(*argv, *(('--json',) if json_flag else ()))
        err = io.StringIO()
        reads = []

        def confirm(timeout):
            reads.append(timeout)
            return answer
        with patch.object(app, '_upgrade_handoff_terminal', return_value=terminal), \
             patch.object(app, '_read_upgrade_confirmation', side_effect=confirm), \
             contextlib.redirect_stderr(err):
            handoff = app._offer_upgrade_handoff(tuple(argv), parsed, summary or summary_fixture())
        return handoff, err.getvalue(), reads

    def test_no_offer_outside_the_default_interactive_inspection(self):
        for label, argv, kwargs in (
                ('explicit-inspect', ('--inspect-only',), {}),
                ('dry-run', ('--dry-run',), {}),
                ('verify-only', ('--verify-only',), {}),
                ('json', (), dict(json_flag=True)),
                ('not-a-terminal', (), dict(terminal=False))):
            with self.subTest(case=label):
                handoff, err, reads = self.offer(argv, answer='yes', **kwargs)
                self.assertIsNone(handoff)
                self.assertEqual('', err)
                self.assertEqual([], reads)
        nothing = summary_fixture()
        for row in nothing['version_plan']:
            row['action'] = 'AT_TARGET_NO_FLASH'
        handoff, err, reads = self.offer((), answer='yes', summary=nothing)
        self.assertIsNone(handoff)
        self.assertEqual('', err)
        self.assertEqual([], reads)

    def test_only_an_exact_yes_confirms(self):
        for answer in ('no', 'y', 'YES', 'yes please', '', None):
            with self.subTest(answer=answer):
                handoff, err, reads = self.offer((), answer=answer)
                self.assertIsNone(handoff)
                self.assertEqual([app._UPGRADE_CONFIRMATION_SECONDS], reads)
        handoff, err, reads = self.offer((), answer='yes')
        self.assertEqual(('ib-a.example.test', 'ib-e.example.test'), tuple(handoff['devices']))
        self.assertEqual(300, app._UPGRADE_CONFIRMATION_SECONDS)

    def test_prompt_names_devices_exclusions_and_the_fresh_upgrade_preflight(self):
        _handoff, err, _reads = self.offer((), answer='no')
        for host in ('ib-a.example.test', 'ib-e.example.test'):
            self.assertIn(host, err)
        self.assertNotIn('ib-b.example.test', err)
        self.assertIn('2 device(s)', err)
        self.assertIn('ib-c.example.test', err)
        self.assertIn('ib-d.example.test', err)
        self.assertIn('yes', err)
        self.assertIn('password', err.lower())
        self.assertIn('preflight', err.lower())

    def test_confirmation_reader_discards_typeahead_and_defaults_to_no(self):
        events = []

        class Input:
            def __init__(self, line):
                self.line = line

            def isatty(self):
                return True

            def fileno(self):
                return 0

            def readline(self, limit=-1):
                events.append('read')
                return self.line
        for line, readable, expected in (('yes\n', True, 'yes'), (' no \n', True, 'no'),
                                         ('', True, None), ('yes\n', False, None)):
            with self.subTest(line=line, readable=readable):
                events.clear()
                stream = Input(line)
                with patch.object(sys, 'stdin', stream), \
                     patch.object(app.termios, 'tcflush', side_effect=lambda *a: events.append('flush')), \
                     patch.object(app.select, 'select',
                                  side_effect=lambda r, w, x, t: (events.append(('wait', t)) or
                                                                   ((r, [], []) if readable else ([], [], [])))), \
                     contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(expected, app._read_upgrade_confirmation(7))
                self.assertEqual('flush', events[0], 'typeahead must be discarded before waiting')
                self.assertIn(('wait', 7), events)

    def test_terminal_requires_stdin_stdout_and_stderr_ttys(self):
        def stream(tty):
            return SimpleNamespace(isatty=lambda: tty)
        for flags in ((True, True, True), (False, True, True), (True, False, True), (True, True, False)):
            with self.subTest(flags=flags), \
                 patch.object(sys, 'stdin', stream(flags[0])), \
                 patch.object(sys, 'stdout', stream(flags[1])), \
                 patch.object(sys, 'stderr', stream(flags[2])):
                self.assertIs(all(flags), app._upgrade_handoff_terminal())

    def test_upgrade_arguments_add_only_explicit_upgrade_confirmation(self):
        self.assertEqual(('--project', '/p', '--cpld-only', '--method', 'http', '--upgrade', '--yes'),
                         app._upgrade_handoff_argv(('--project', '/p', '--cpld-only', '--method', 'http')))
        self.assertEqual(('-y', '--method', 'scp', '--upgrade'),
                         app._upgrade_handoff_argv(('-y', '--method', 'scp')))
        parsed = self.parsed(*app._upgrade_handoff_argv(('--devices', 'ib-*', '--method', 'http')))
        self.assertTrue(parsed.upgrade)
        self.assertFalse(parsed.inspect_only)
        self.assertNotIn('--password', app._upgrade_handoff_argv(('--method', 'http')))

    def test_selection_is_restricted_to_confirmed_devices_and_drift_refuses(self):
        node = lambda name: SimpleNamespace(hostname=name)  # noqa: E731
        devices = (node('ib-a.example.test'), node('ib-b.example.test'), node('ib-e.example.test'))
        blocked = (SimpleNamespace(hostname='ib-x.example.test', csv_row=9, reasons=('MAC',)),)
        handoff = dict(devices=('ib-e.example.test', 'ib-a.example.test'))
        kept, kept_blocked = app._restrict_to_handoff(devices, blocked, handoff)
        self.assertEqual(['ib-a.example.test', 'ib-e.example.test'], [n.hostname for n in kept])
        self.assertEqual((), tuple(kept_blocked))
        with self.assertRaises(app._InspectionHold) as raised:
            app._restrict_to_handoff(devices[:2], blocked, handoff)
        self.assertIn('INSPECTION_HANDOFF', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
