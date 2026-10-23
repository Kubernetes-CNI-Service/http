"""Real entry workflows for the IB upgrade usability changes; device IO simulated.

* Default interactive inspection -> explicit ``yes`` -> one switch password ->
  real upgrade of only the confirmed READY/UPGRADE_REQUIRED devices, through the
  real entry, driver, observer, executor and pipeline with the fixed fake SSH
  of the three-component workflow. Declining, explicit read-only modes and
  non-interactive runs keep the inspection-only result.
* An open-file soft limit too small for startup (previously
  FD_BUDGET_INSUFFICIENT) is raised in-process through a simulated rlimit and
  the upgrade completes; an insufficient hard limit keeps the original refusal.
* A real interpreter without the SSH runtime execs the owner-designated
  ~/.venvs/http/ibsw-upgrade once, before the host runtime guard, with
  unchanged arguments; a bundle-local .venv is ignored.

No real SSH, network, switch, venv creation or package installation is used.
"""
import contextlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_cases import test_ibsw225_three_component_workflow as workflow
from test_cases.test_ibsw225_flat_tools_layout import MEMBERS as FLAT_MEMBERS

ROOT = Path(__file__).resolve().parents[1]
HOST, PEER = 'ew-spine01.example', 'ew-spine02.example'
FAIL_HEALTH = workflow.manual.HEALTH.replace(b'OK', b'FAIL')
MARKER = 'IBSW_UPGRADE_VENV_REEXEC'


def _fixture(name):
    return workflow.ThreeComponentWorkflowTests(name)


class InspectionUpgradeOfferWorkflowTests(unittest.TestCase):
    def offer_run(self, root, *, answer, password_prompts, terminal=True, entry_args=(),
                  after_confirm=None, **options):
        app = workflow.app
        summaries, offers = [], []

        def emit(summary, *, force=False):
            summaries.append(json.loads(json.dumps(summary)))
            return False

        def confirm(timeout):
            offers.append(timeout)
            if after_confirm is not None:
                after_confirm(root)
            return answer
        with patch.object(app, '_upgrade_handoff_terminal', return_value=terminal), \
             patch.object(app, '_read_upgrade_confirmation', side_effect=confirm), \
             patch.object(app, '_emit_report_json', side_effect=emit):
            code, _report, err, calls, installs = _fixture(
                'test_inspection_is_strictly_read_only_for_all_components').invoke(
                root, entry_args=entry_args, password_prompt_attempts=password_prompts, **options)
        return code, err, calls, installs, summaries, offers

    def assert_saved(self, summary):
        saved = Path(summary['run_directory']) / 'run-report.json'
        self.assertEqual(summary, json.loads(saved.read_text()))

    def test_yes_upgrades_only_confirmed_devices_after_one_password_in_a_new_run(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            code, err, calls, installs, summaries, offers = self.offer_run(
                root, answer='yes', password_prompts=1, two=True,
                health_payloads={(PEER, 'startup'): FAIL_HEALTH})
            self.assertEqual(0, code, err)
            self.assertEqual([300], offers)
            self.assertEqual(['INSPECT_ONLY', 'UPGRADE'], [s['mode'] for s in summaries])
            inspection, upgrade = summaries
            self.assertEqual({HOST, PEER}, {t['hostname'] for t in inspection['targets']})
            self.assertEqual('NOT_EXECUTED', inspection['execution_state'])
            self.assertEqual([HOST], [t['hostname'] for t in upgrade['targets']])
            self.assertEqual([(HOST, 'os'), (HOST, 'bios'), (HOST, 'cpld')], [(n, c) for n, c, _v in installs])
            handoff = upgrade['inspection_handoff']
            self.assertEqual(inspection['run_directory'], handoff['inspection_run_directory'])
            self.assertEqual([HOST], handoff['devices'])
            self.assertEqual([PEER], handoff['excluded']['health_not_pass'])
            self.assertNotEqual(inspection['run_directory'], upgrade['run_directory'])
            for summary in summaries:
                self.assert_saved(summary)
            # The excluded peer saw only the read-only inspection session; the
            # confirmed device repeated identity in the upgrade's own preflight.
            identity = workflow.observer._IDENTITY_COMMAND
            self.assertEqual(1, sum(1 for n, c in calls if n == PEER and c == identity))
            self.assertGreaterEqual(sum(1 for n, c in calls if n == HOST and c == identity), 2)
            self.assertFalse(any(n == PEER and not (c == identity or c.startswith('nv show '))
                                 for n, c in calls))
            self.assertLess(err.index('[UPGRADE OFFER]'), err.index('[AUTH]'))

    def test_declined_offer_keeps_the_inspection_only_result(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            code, err, _calls, installs, summaries, offers = self.offer_run(
                root, answer='no', password_prompts=0, two=True)
            self.assertEqual(0, code, err)
            self.assertEqual([300], offers)
            self.assertEqual(['INSPECT_ONLY'], [s['mode'] for s in summaries])
            self.assertEqual([], installs)
            self.assertIn('[UPGRADE OFFER]', err)
            self.assertNotIn('[AUTH]', err)
            self.assert_saved(summaries[0])

    def test_non_interactive_default_inspection_is_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            app = workflow.app
            with patch.object(app, '_read_upgrade_confirmation',
                              side_effect=AssertionError('no prompt without a terminal')):
                code, report, err, _calls, installs = _fixture(
                    'test_inspection_is_strictly_read_only_for_all_components').invoke(
                    root, entry_args=(), password_prompt_attempts=0, two=True)
            self.assertEqual(0, code, err)
            self.assertEqual('INSPECT_ONLY', report['mode'])
            self.assertEqual('NOT_EXECUTED', report['execution_state'])
            self.assertNotIn('inspection_handoff', report)
            self.assertEqual([], installs)
            self.assertNotIn('[UPGRADE OFFER]', err)

    def test_explicit_read_only_mode_never_offers_an_upgrade(self):
        for mode in ('--inspect-only', '--dry-run'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder).resolve()
                code, err, _calls, installs, summaries, offers = self.offer_run(
                    root, answer='yes', password_prompts=0, two=True, entry_args=(mode,))
                self.assertEqual(0, code, err)
                self.assertEqual([], offers)
                self.assertEqual(['INSPECT_ONLY'], [s['mode'] for s in summaries])
                self.assertEqual([], installs)

    def test_nothing_to_upgrade_produces_no_offer(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            code, err, _calls, installs, summaries, offers = self.offer_run(
                root, answer='yes', password_prompts=0, two=True, old_os=False, firmware_at_target=True)
            self.assertEqual(0, code, err)
            self.assertEqual([], offers)
            self.assertEqual([], installs)
            self.assertNotIn('[UPGRADE OFFER]', err)

    def test_input_drift_after_confirmation_refuses_before_password_or_installation(self):
        def drop_confirmed_host(root):
            csv_path = root / 'project' / '02-devices_config.csv'
            lines = csv_path.read_text().splitlines(keepends=True)
            kept = [line for line in lines if not line.startswith(HOST + ',')]
            self.assertEqual(len(lines) - 1, len(kept))
            csv_path.write_text(''.join(kept))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            code, err, _calls, installs, summaries, offers = self.offer_run(
                root, answer='yes', password_prompts=0, two=True, after_confirm=drop_confirmed_host)
            self.assertEqual(2, code, err)
            self.assertIn('INSPECTION_HANDOFF', err)
            self.assertEqual([], installs)
            self.assertEqual(['INSPECT_ONLY'], [s['mode'] for s in summaries])


class _Limits:
    """In-memory RLIMIT_NOFILE shared by the entry and pipeline; real limit untouched."""

    def __init__(self, soft, hard):
        self.soft, self.hard, self.calls = soft, hard, []

    def getrlimit(self, which):
        assert which == resource.RLIMIT_NOFILE
        return self.soft, self.hard

    def setrlimit(self, which, limits):
        assert which == resource.RLIMIT_NOFILE
        self.calls.append(tuple(limits))
        self.soft, self.hard = limits

    @contextlib.contextmanager
    def active(self):
        with patch.object(resource, 'getrlimit', self.getrlimit), \
             patch.object(resource, 'setrlimit', self.setrlimit):
            yield


class DescriptorSoftLimitWorkflowTests(unittest.TestCase):
    def upgrade(self, root, limits):
        with limits.active():
            return _fixture('test_all_three_native_components_have_verified_status_and_complete_evidence').invoke(root)

    def test_small_soft_limit_is_raised_in_process_and_the_upgrade_completes(self):
        limits = _Limits(128, resource.RLIM_INFINITY)
        with tempfile.TemporaryDirectory() as folder:
            code, report, err, _calls, installs = self.upgrade(Path(folder).resolve(), limits)
            self.assertEqual(0, code, err)
            self.assertNotIn('FD_BUDGET_INSUFFICIENT', err)
            self.assertEqual(3, len(installs))
            self.assertEqual(1, len(limits.calls))
            raised, hard = limits.calls[0]
            self.assertEqual(resource.RLIM_INFINITY, hard)
            self.assertGreater(raised, 128)
            record = report['readiness_scheduler']['soft_limit']
            self.assertEqual((128, raised), (record['soft_before'], record['soft_after']))
            self.assertEqual(raised // 2, report['readiness_scheduler']['descriptor_budget'])
            self.assertIn('128 -> %d' % raised, err)

    def test_insufficient_hard_limit_keeps_the_original_refusal(self):
        limits = _Limits(128, 128)
        with tempfile.TemporaryDirectory() as folder:
            code, _report, err, _calls, installs = self.upgrade(Path(folder).resolve(), limits)
            self.assertEqual(2, code, err)
            self.assertIn('FD_BUDGET_INSUFFICIENT', err)
            self.assertIn('[FD]', err)
            self.assertIn('hard', err.lower())
            self.assertEqual([], limits.calls)
            self.assertEqual([], installs)


LAUNCHER = '''import importlib, json, os, pathlib, runpy, sys
bundle = pathlib.Path(sys.argv[1]).resolve()
lock = pathlib.Path(sys.argv[2])
with open(os.path.join(os.environ["IBSW_TEST_RECORD"], "entry-env.json"), "w") as handle:
    json.dump(dict(os.environ), handle)  # exactly what the entry inherits
sys.path.insert(0, str(bundle))
guard = importlib.import_module("ib_bringup_runtime_guard")
if pathlib.Path(guard.__file__).resolve() != bundle / "ib_bringup_runtime_guard.py":
    raise AssertionError("only the copied flat guard may be used")
guard._RUNTIME_GUARD_PATH = lock  # never the host-wide guard inode
sys.argv = [str(bundle / "upgrade.py"), *sys.argv[3:]]
runpy.run_path(str(bundle / "upgrade.py"), run_name="__main__")
'''
RECORDER = '''#!/bin/sh
printf '%s\\n' "$@" > "$IBSW_TEST_RECORD/argv"
/usr/bin/env > "$IBSW_TEST_RECORD/env"
exit 0
'''
DECOY = '''#!/bin/sh
: > "$IBSW_TEST_RECORD/bundle-local-venv-used"
exit 96
'''
VERSIONS = (('paramiko', '5.0.0'), ('bcrypt', '5.0.0'), ('cryptography', '50.0.1'),
            ('invoke', '2.2.1'), ('PyNaCl', '1.6.2'), ('cffi', '2.0.0'),
            ('pycparser', '2.23'), ('typing-extensions', '4.16.0'), ('PyYAML', '6.0.2'))


class RuntimeVenvSwitchWorkflowTests(unittest.TestCase):
    def venv(self, venv, interpreter):
        site = venv / 'lib' / 'python3.12' / 'site-packages'
        (venv / 'bin').mkdir(parents=True)
        site.mkdir(parents=True)
        (venv / 'pyvenv.cfg').write_text('home = /usr/bin\n')
        python = venv / 'bin' / 'python3'
        python.write_text(interpreter)
        python.chmod(0o755)
        for name, version in VERSIONS:
            info = site / (name.replace('-', '_') + '-' + version + '.dist-info')
            info.mkdir()
            (info / 'METADATA').write_text('Metadata-Version: 2.1\nName: %s\nVersion: %s\n' % (name, version))
        for directory in (venv, venv / 'bin', venv / 'lib', site.parent, site):
            directory.chmod(0o755)
        return venv

    def bundle(self, root):
        bundle = root / 'ibsw-bundle'
        bundle.mkdir()
        for relative in FLAT_MEMBERS:
            (bundle / Path(relative).name).write_bytes((ROOT / relative).read_bytes())
        bundle.chmod(0o755)
        # A fully valid bundle-local .venv is no longer a candidate (owner ruling).
        self.venv(bundle / '.venv', DECOY)
        return bundle

    def test_interpreter_without_ssh_runtime_execs_the_home_venv_once_before_the_guard(self):
        with tempfile.TemporaryDirectory(prefix='ibsw-venv-workflow-') as folder:
            root = Path(folder).resolve()
            bundle = self.bundle(root)
            home = root / 'home'
            venv = self.venv(home / '.venvs' / 'http' / 'ibsw-upgrade', RECORDER)
            for directory in (home, home / '.venvs', home / '.venvs' / 'http'):
                directory.chmod(0o755)
            record = root / 'record'
            record.mkdir()
            lock = root / 'private-runtime.lock'
            environment = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'LC_ALL': 'C',
                           'IBSW_TEST_RECORD': str(record), 'IBSW_TEST_CANARY': 'unchanged-value'}
            args = ['--inspect-only', '--devices', 'ib-spine0[1-2]*']
            # -S hides every site-packages: this interpreter lacks paramiko and PyYAML.
            result = subprocess.run([sys.executable, '-B', '-S', '-c', LAUNCHER, str(bundle), str(lock), *args],
                                    cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('[RUNTIME]', result.stderr)
            self.assertIn(str(venv), result.stderr)
            self.assertFalse((record / 'bundle-local-venv-used').exists())
            self.assertFalse(lock.exists(), 'the switch must precede the runtime guard')
            argv = (record / 'argv').read_text().splitlines()
            self.assertEqual(['-B', str(bundle / 'upgrade.py'), *args], argv)
            recorded = dict(line.split('=', 1) for line in (record / 'env').read_text().splitlines() if '=' in line)
            inherited = json.loads((record / 'entry-env.json').read_text())
            self.assertNotIn(MARKER, inherited)
            self.assertEqual('1', recorded.get(MARKER))
            shell_owned = {'PWD', 'SHLVL', '_', 'OLDPWD'}  # set by /bin/sh itself
            for key, value in environment.items():
                self.assertEqual(value, recorded.get(key), key)
            for key, value in inherited.items():
                if key not in shell_owned:
                    self.assertEqual(value, recorded.get(key), key)
            self.assertLessEqual(set(recorded) - set(inherited), {MARKER} | shell_owned)


if __name__ == '__main__':
    unittest.main()
