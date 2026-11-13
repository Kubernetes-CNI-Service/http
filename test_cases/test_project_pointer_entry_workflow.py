"""Q067/r539: real default-pointer bootstrap before identity and runtime selection.

Each child disables site and rejects yaml. All repository/project bytes are synthetic
or copied public source in an explicitly owned test root; execution stops before the
runtime candidate audit, operator exec, instance guard, or device/input workflow.
"""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY_RELATIVE = 'infiniband/bringup/xdr-upgrade/upgrade2.py'

DRIVER = '''import contextlib,importlib.util,io,json,os,sys,types
from pathlib import Path
entry,project,mode=sys.argv[1:]
events=[]
observed={'events':events,'exception':None,'code':None,'stderr':''}
class NoYaml:
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0]=='yaml':
            raise ModuleNotFoundError('PyYAML intentionally unavailable',name=fullname)
sys.meta_path.insert(0,NoYaml())
def safe_boundary(event,args):
    if event in ('subprocess.Popen','socket.connect','socket.bind','os.exec','os.system'):
        raise AssertionError('unexpected external effect: '+event)
    if event=='open' and str(args[0]) in ('.finished-source.json','.finished-commit.json'):
        events.append('control:'+str(args[0]))
sys.addaudithook(safe_boundary)
spec=importlib.util.spec_from_file_location('owned_pointer_entry',entry)
app=importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
import operator_identity
original_resolve=operator_identity.resolve_operator
original_needs=operator_identity.needs_reexec
def resolve(selected):
    events.append('identity')
    answer=original_resolve(selected)
    if answer.action!='self':
        raise AssertionError('owned fixture must resolve to current account')
    return answer
def needs(answer):
    events.append('needs-reexec')
    return original_needs(answer)
def reject_exec(*args,**kwargs):
    raise AssertionError('unexpected real operator exec')
operator_identity.resolve_operator=resolve
operator_identity.needs_reexec=needs
operator_identity.exec_as_operator=reject_exec
class ReachedRuntime(BaseException):
    pass
def runtime(argv):
    events.append('venv')
    observed['argv']=list(argv)
    raise ReachedRuntime()
app._reexec_in_runtime_venv=runtime
class ForbiddenGuard(BaseException):
    pass
guard=types.ModuleType('ib_bringup_runtime_guard')
@contextlib.contextmanager
def guard_boundary():
    events.append('forbidden-guard')
    raise ForbiddenGuard()
    yield
guard._runtime_instance_guard=guard_boundary
sys.modules['ib_bringup_runtime_guard']=guard
sys.argv=[entry]+(['--project',project] if mode=='explicit' else [])
errors=io.StringIO()
try:
    with contextlib.redirect_stderr(errors):
        observed['code']=app.main()
except ReachedRuntime:
    observed['code']='runtime-boundary'
except ForbiddenGuard:
    observed['code']='forbidden-guard-boundary'
except ImportError as error:
    observed['exception']={'type':type(error).__name__,'name':error.name}
observed['stderr']=errors.getvalue()
print(json.dumps(observed,sort_keys=True))
'''


def owned_test_root():
    """Validate the runner's explicit roots before any factory or test write."""
    own = Path(os.environ['HTTP_TEST_OWNED_ROOT'])
    temporary = Path(os.environ['TMPDIR'])
    if (not own.is_absolute() or own != own.resolve() or temporary != own
            or not own.is_dir() or own.is_symlink()
            or own.stat().st_uid != os.getuid() or own.stat().st_mode & 0o777 != 0o700):
        raise AssertionError('explicit same owned mode-0700 test roots required')
    return own


class ProjectPointerEntryWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pointer-entry-', dir=owned_test_root())
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.tree = self.work / 'repository'
        self.entry = self.tree / ENTRY_RELATIVE
        self.entry.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / ENTRY_RELATIVE, self.entry)
        tools = self.tree / 'tools'
        tools.mkdir()
        # The RED baseline has no NEW yet. Copy it normally once production adds
        # it; never fill the missing dependency with an algorithm or source stub.
        names = ['operator_identity.py', 'fleet_ssh.py', 'ssh_key_preparation.py',
                 'project_contract.py']
        if (ROOT / 'tools/project_pointer.py').is_file():
            names.append('project_pointer.py')
        for name in names:
            shutil.copyfile(ROOT / 'tools' / name, tools / name)
        day0 = self.tree / 'DAY0-Prepare'
        day0.mkdir()
        self.project = day0 / 'example-project'
        self.project.mkdir()
        self.pointer = day0 / 'activate-project'
        self.pointer.symlink_to('example-project')
        self.home = self.work / 'home'
        self.home.mkdir()
        self.driver = self.work / 'driver.py'
        self.driver.write_text(DRIVER, encoding='utf-8')

    def child(self, mode='default'):
        environment = {name: os.environ[name] for name in ('TMPDIR', 'HTTP_TEST_OWNED_ROOT')}
        environment.update(HOME=str(self.home), PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='en_US.UTF-8')
        done = subprocess.run(
            [sys.executable, '-S', '-B', str(self.driver), str(self.entry), str(self.project), mode],
            cwd=self.work, env=environment, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn('Traceback', done.stderr)
        return json.loads(done.stdout)

    def test_ordinary_default_project_reaches_identity_then_runtime_without_yaml(self):
        result = self.child()
        self.assertIsNone(result['exception'], result['exception'])
        self.assertEqual(result['events'], ['identity', 'needs-reexec', 'venv'])
        self.assertEqual(result['code'], 'runtime-boundary')
        self.assertEqual(result['argv'], [])

    def test_committed_restore_is_read_completely_before_identity_and_runtime(self):
        receipt = {'schema_version': 1, 'state': 'PREPARED', 'source_record': '/synthetic/source',
                   'project': 'example-project', 'record_id': 'example-record',
                   'content_sha256': 'a' * 64, 'include_history': False}
        payload = json.dumps(receipt, sort_keys=True).encode('ascii')
        (self.project / '.finished-source.json').write_bytes(payload)
        info = self.project.stat()
        marker = {'schema_version': 1, 'state': 'COMMITTED',
                  'receipt_sha256': hashlib.sha256(payload).hexdigest(),
                  'target_project': 'example-project', 'target_dev': info.st_dev, 'target_ino': info.st_ino}
        (self.project / '.finished-commit.json').write_text(json.dumps(marker), encoding='ascii')
        result = self.child()
        self.assertIsNone(result['exception'], result['exception'])
        self.assertEqual(result['events'], ['control:.finished-source.json',
                                          'control:.finished-commit.json',
                                          'identity', 'needs-reexec', 'venv'])
        self.assertEqual(result['code'], 'runtime-boundary')

    def test_sync_incomplete_rejects_before_identity_runtime_and_guard(self):
        (self.tree / '.sync-code-in-progress').mkdir()
        result = self.child()
        self.assertIsNone(result['exception'], result['exception'])
        self.assertEqual(result['events'], [])
        self.assertEqual(result['code'], 2)
        self.assertIn('ERROR: DAY0-Prepare/activate-project -> example-project: project sync is incomplete:',
                      result['stderr'])

    def test_ineligible_restore_rejects_before_identity_runtime_and_guard(self):
        (self.project / '.finished-commit.ready').write_text('{}', encoding='ascii')
        result = self.child()
        self.assertIsNone(result['exception'], result['exception'])
        self.assertEqual(result['events'], [])
        self.assertEqual(result['code'], 2)
        self.assertIn('ERROR: DAY0-Prepare/activate-project -> example-project: restored project has no completed commit:',
                      result['stderr'])

    def test_explicit_project_preserves_original_identity_runtime_path(self):
        result = self.child('explicit')
        self.assertIsNone(result['exception'], result['exception'])
        self.assertEqual(result['events'], ['identity', 'needs-reexec', 'venv'])
        self.assertEqual(result['code'], 'runtime-boundary')
        self.assertEqual(result['argv'], ['--project', str(self.project)])

    def test_main_then_runtime_keeps_real_legacy_pointer_recheck(self):
        # Real main/NEW/OI then real run/_run/PC, IB adapter and engine. Only
        # runtime selection and guard acquisition stop at explicit test seams;
        # existing OwnedWorkflow hard-refuses all real transport/subprocesses.
        from test_cases.ibsw_upgrade_runtime_fixture import OwnedWorkflow
        import operator_identity
        import project_contract
        import project_pointer
        import ib_bringup_runtime_guard as guard
        fixture = OwnedWorkflow(self)
        events = []
        original_light = project_pointer.active_project_dir
        original_legacy = project_contract.active_project_dir
        original_identity = operator_identity.resolve_operator
        original_needs = operator_identity.needs_reexec
        original_run = fixture.entry.run
        def light(repository):
            events.append('light-pointer')
            return original_light(repository)
        def legacy(repository):
            events.append('legacy-pointer')
            return original_legacy(repository)
        def identity(project):
            events.append('identity')
            return original_identity(project)
        def needs(resolution):
            events.append('needs-reexec')
            return original_needs(resolution)
        def runtime(argv):
            events.append('venv')
            return 'NOT_NEEDED'
        @contextlib.contextmanager
        def owned_guard():
            events.append('guard-enter')
            try:
                yield
            finally:
                events.append('guard-exit')
        def run():
            events.append('run')
            with mock.patch.object(fixture.entry, 'run', original_run):
                return fixture.run(['--plan'])
        with mock.patch.object(project_pointer, 'active_project_dir', light), \
                mock.patch.object(project_contract, 'active_project_dir', legacy), \
                mock.patch.object(operator_identity, 'resolve_operator', identity), \
                mock.patch.object(operator_identity, 'needs_reexec', needs), \
                mock.patch.object(operator_identity, 'exec_as_operator', side_effect=AssertionError('unexpected operator exec')), \
                mock.patch.object(fixture.entry, '_reexec_in_runtime_venv', runtime), \
                mock.patch.object(guard, '_runtime_instance_guard', owned_guard), \
                mock.patch.object(fixture.entry, 'run', run), \
                mock.patch.object(sys, 'argv', [str(fixture.entry.ENTRY)]), \
                contextlib.redirect_stderr(io.StringIO()):
            code = fixture.entry.main()
        self.assertEqual(code, 3)
        self.assertEqual(events, ['light-pointer', 'identity', 'needs-reexec', 'venv',
                                  'guard-enter', 'run', 'legacy-pointer', 'guard-exit'])
        self.assertEqual([row['hostname'] for row in fixture.reports()[0]['devices']],
                         ['example-ib01', 'example-ib02'])
        self.assertTrue(all(row['reason'] == 'PLAN_ONLY' for row in fixture.reports()[0]['devices']))
