"""r539/Q067 independent stdlib pointer, restore, FD and legacy-hook contracts."""
from __future__ import annotations

import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from types import ModuleType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


class _ProjectPointerFixture(unittest.TestCase):
    def setUp(self):
        own = Path(os.environ['HTTP_TEST_OWNED_ROOT'])
        if (own != Path(os.environ['TMPDIR']) or not own.is_absolute()
                or own.resolve() != own or own.is_symlink() or not own.is_dir()
                or own.stat().st_uid != os.getuid() or own.stat().st_mode & 0o777 != 0o700):
            raise AssertionError('explicit same canonical owned mode-0700 test roots required')
        self.tmp = tempfile.TemporaryDirectory(prefix='pointer-contract-', dir=own)
        self.addCleanup(self.tmp.cleanup)
        self.tree = Path(self.tmp.name)
        self.day0 = self.tree / 'DAY0-Prepare'
        self.day0.mkdir()
        self.project = self.day0 / 'example-project'
        self.project.mkdir()
        self.pointer = self.day0 / 'activate-project'
        self.light = importlib.import_module('project_pointer')
        self.assertEqual(Path(self.light.__file__).resolve(), ROOT / 'tools/project_pointer.py')

    def legacy(self):
        module = importlib.import_module('project_contract')
        self.assertEqual(Path(module.__file__).resolve(), ROOT / 'tools/project_contract.py')
        return module

    def controls(self, receipt_update=None, marker_update=None):
        receipt = {'schema_version': 1, 'state': 'PREPARED', 'source_record': '/synthetic/source',
                   'project': 'source-project', 'record_id': 'example-record',
                   'content_sha256': 'a' * 64, 'include_history': False}
        receipt.update(receipt_update or {})
        payload = json.dumps(receipt, sort_keys=True).encode('ascii')
        (self.project / '.finished-source.json').write_bytes(payload)
        info = self.project.stat()
        marker = {'schema_version': 1, 'state': 'COMMITTED',
                  'receipt_sha256': hashlib.sha256(payload).hexdigest(),
                  'target_project': 'example-project', 'target_dev': info.st_dev, 'target_ino': info.st_ino}
        marker.update(marker_update or {})
        (self.project / '.finished-commit.json').write_bytes(json.dumps(marker).encode('ascii'))

    @staticmethod
    def changed(info, **values):
        fields = {name: getattr(info, name) for name in (
            'st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')}
        fields.update(values)
        return SimpleNamespace(**fields)

    def directory_fd(self):
        descriptor = os.open(self.project, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        self.addCleanup(os.close, descriptor)
        return descriptor


class ProjectPointerContractTests(_ProjectPointerFixture):
    def test_no_pointer_and_plain_eligible_project_remain_supported(self):
        self.assertIsNone(self.light.active_project_dir(self.tree))
        self.assertIsNone(self.light.require_project_eligible(self.project))
        self.pointer.symlink_to('example-project')
        self.assertEqual(self.light.active_project_dir(self.tree), self.project.resolve())

    def test_pointer_regular_file_is_not_absence(self):
        self.pointer.write_text('example-project')
        with self.assertRaises(self.light.ActiveProjectPointerError) as caught:
            self.light.active_project_dir(self.tree)
        self.assertEqual(str(caught.exception), 'DAY0-Prepare/activate-project is not a link: ' + str(self.pointer))

    def test_pointer_plain_name_and_exclusion_messages_are_literal(self):
        for name in ('../example-project', 'nested/project', '.hidden', 'template',
                     'activate-project', 'tests', 'test_cases', 'dumps'):
            with self.subTest(name=name):
                self.pointer.symlink_to(name)
                try:
                    with self.assertRaises(self.light.ActiveProjectPointerError) as caught:
                        self.light.active_project_dir(self.tree)
                    self.assertEqual(str(caught.exception),
                                     'DAY0-Prepare/activate-project -> ' + name
                                     + ' is not a project name (one plain name; not '
                                     + 'activate-project, dumps, template, test_cases, tests; no leading \'.\')')
                finally:
                    self.pointer.unlink()

    def test_pointer_missing_target_preserves_no_cause(self):
        self.pointer.symlink_to('missing-project')
        with self.assertRaises(self.light.ActiveProjectPointerError) as caught:
            self.light.active_project_dir(self.tree)
        self.assertEqual(str(caught.exception), 'DAY0-Prepare/activate-project -> missing-project: '
                         'DAY0-Prepare/missing-project does not exist')
        self.assertIsNone(caught.exception.__cause__)

    def test_pointer_file_or_link_target_is_not_real_directory(self):
        (self.day0 / 'file-project').write_text('synthetic')
        (self.day0 / 'linked-project').symlink_to('example-project')
        for name in ('file-project', 'linked-project'):
            with self.subTest(name=name):
                self.pointer.symlink_to(name)
                try:
                    with self.assertRaises(self.light.ActiveProjectPointerError) as caught:
                        self.light.active_project_dir(self.tree)
                    self.assertEqual(str(caught.exception), 'DAY0-Prepare/activate-project -> ' + name
                                     + ': DAY0-Prepare/' + name + ' is not a real directory')
                finally:
                    self.pointer.unlink()

    def test_light_and_legacy_pointer_use_current_eligibility_callable(self):
        self.pointer.symlink_to('example-project')
        for module in (self.light, self.legacy()):
            with self.subTest(module=module.__name__):
                for message in ('first synthetic refusal', 'second synthetic refusal'):
                    reason = ValueError(message)
                    with mock.patch.object(module, 'require_project_eligible', side_effect=reason) as hook:
                        with self.assertRaises(module.ActiveProjectPointerError) as caught:
                            module.active_project_dir(self.tree)
                    hook.assert_called_once_with(self.project)
                    self.assertIs(caught.exception.__cause__, reason)
                    self.assertEqual(str(caught.exception),
                                     'DAY0-Prepare/activate-project -> example-project: ' + message)

    def test_light_and_legacy_eligible_use_current_reader_callable(self):
        for module in (self.light, self.legacy()):
            with self.subTest(module=module.__name__):
                with mock.patch.object(module, '_read_rehydrate_control', return_value=None) as hook:
                    self.assertIsNone(module.require_project_eligible(self.project))
                self.assertEqual([(item.args[1], item.args[2]) for item in hook.call_args_list],
                                 [('.finished-source.json', 65536), ('.finished-commit.ready', 4096),
                                  ('.finished-commit.json', 4096)])
                self.assertEqual(len({item.args[0] for item in hook.call_args_list}), 1)
                reason = ValueError('new current reader refusal')
                with mock.patch.object(module, '_read_rehydrate_control', side_effect=reason):
                    with self.assertRaises(ValueError) as caught:
                        module.require_project_eligible(self.project)
                self.assertIs(caught.exception, reason)

    def test_legacy_exports_same_actual_exception_and_constants(self):
        legacy = self.legacy()
        self.assertIs(legacy.ActiveProjectPointerError, legacy._project_pointer.ActiveProjectPointerError)
        self.assertEqual(legacy.ACTIVE_PROJECT_POINTER, 'DAY0-Prepare/activate-project')
        self.assertEqual(legacy.ACTIVE_PROJECT_EXCLUDED_NAMES,
                         frozenset({'template', 'activate-project', 'tests', 'test_cases', 'dumps'}))
        self.assertEqual((legacy.REHYDRATE_RECEIPT_NAME, legacy.REHYDRATE_READY_NAME,
                          legacy.REHYDRATE_COMMIT_NAME),
                         ('.finished-source.json', '.finished-commit.ready', '.finished-commit.json'))

    def test_any_sync_marker_shape_rejects_before_project_controls(self):
        marker = self.tree / '.sync-code-in-progress'
        for kind in ('file', 'directory', 'dangling-link'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    marker.write_bytes(b'')
                elif kind == 'directory':
                    marker.mkdir()
                else:
                    marker.symlink_to('missing')
                try:
                    with mock.patch.object(self.light, '_read_rehydrate_control') as reader:
                        with self.assertRaises(ValueError) as caught:
                            self.light.require_project_eligible(self.project)
                        reader.assert_not_called()
                    self.assertEqual(str(caught.exception), 'project sync is incomplete: ' + str(marker))
                finally:
                    marker.rmdir() if kind == 'directory' else marker.unlink()

    def test_full_restore_allows_only_completed_exact_marker(self):
        self.controls()
        self.assertIsNone(self.light.require_project_eligible(self.project))
        ready = self.project / '.finished-commit.ready'
        ready.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'restored project has no completed commit:'):
            self.light.require_project_eligible(self.project)
        ready.unlink()
        (self.project / '.finished-commit.json').unlink()
        with self.assertRaisesRegex(ValueError, 'restored project has no completed commit:'):
            self.light.require_project_eligible(self.project)

    def test_receipt_exact_schema_and_strict_literal_types(self):
        bad = ({'schema_version': True}, {'schema_version': 2}, {'state': 'COMMITTED'},
               {'source_record': 'relative'}, {'source_record': 1}, {'project': ''},
               {'record_id': ''}, {'content_sha256': 'A' * 64}, {'content_sha256': 'a' * 63},
               {'include_history': 0}, {'extra': 'not-allowed'})
        for update in bad:
            with self.subTest(update=update):
                self.controls(receipt_update=update)
                with self.assertRaises(ValueError) as caught:
                    self.light.require_project_eligible(self.project)
                self.assertEqual(str(caught.exception), 'restored project has an invalid receipt: ' + str(self.project))

    def test_marker_exact_schema_hash_project_inode_and_strict_types(self):
        info = self.project.stat()
        bad = ({'schema_version': True}, {'schema_version': 2}, {'state': 'PREPARED'},
               {'receipt_sha256': '0' * 64}, {'target_project': 'other-project'},
               {'target_dev': str(info.st_dev)}, {'target_ino': str(info.st_ino)},
               {'target_dev': True}, {'target_ino': True},
               {'target_dev': info.st_dev + 1}, {'target_ino': info.st_ino + 1},
               {'extra': 'not-allowed'})
        for update in bad:
            with self.subTest(update=update):
                self.controls(marker_update=update)
                with self.assertRaises(ValueError) as caught:
                    self.light.require_project_eligible(self.project)
                self.assertEqual(str(caught.exception), 'restored project has a mismatched commit marker: ' + str(self.project))

    def test_restore_non_ascii_and_bad_json_preserve_caused_fixed_error(self):
        for name in ('.finished-source.json', '.finished-commit.json'):
            for payload in (b'{broken', b'\xff'):
                with self.subTest(name=name, payload=payload):
                    self.controls()
                    (self.project / name).write_bytes(payload)
                    with self.assertRaises(ValueError) as caught:
                        self.light.require_project_eligible(self.project)
                    self.assertEqual(str(caught.exception),
                                     'restored project has malformed commit controls: ' + str(self.project))
                    self.assertIsInstance(caught.exception.__cause__, (UnicodeError, json.JSONDecodeError))

    def test_control_reader_exact_bytes_and_missing_control(self):
        descriptor = self.directory_fd()
        self.assertIsNone(self.light._read_rehydrate_control(descriptor, '.finished-source.json', 65536))
        (self.project / '.finished-source.json').write_bytes(b'first\nsecond\n')
        self.assertEqual(self.light._read_rehydrate_control(descriptor, '.finished-source.json', 65536),
                         b'first\nsecond\n')

    def test_control_reader_refuses_zero_large_link_and_multiple_links(self):
        descriptor = self.directory_fd()
        target = self.project / 'control'
        for kind in ('zero', 'large', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                companion = self.project / 'companion'
                if kind == 'zero':
                    target.write_bytes(b'')
                elif kind == 'large':
                    target.write_bytes(b'x' * 4097)
                elif kind == 'symlink':
                    target.symlink_to('missing')
                else:
                    companion.write_bytes(b'{}')
                    os.link(companion, target)
                try:
                    with self.assertRaises(ValueError) as caught:
                        self.light._read_rehydrate_control(descriptor, 'control', 4096)
                    self.assertEqual(str(caught.exception), 'restore control has an unsafe shape: control')
                finally:
                    target.unlink()
                    if companion.exists():
                        companion.unlink()

    def test_control_reader_open_failure_preserves_cause_and_no_owned_close(self):
        descriptor = self.directory_fd()
        (self.project / 'control').write_bytes(b'{}')
        reason = PermissionError(errno.EACCES, 'synthetic open denied')
        with mock.patch.object(self.light.os, 'open', side_effect=reason), \
                mock.patch.object(self.light.os, 'close') as close:
            with self.assertRaises(ValueError) as caught:
                self.light._read_rehydrate_control(descriptor, 'control', 4096)
            close.assert_not_called()
        self.assertEqual(str(caught.exception), 'restore control cannot be opened: control')
        self.assertIs(caught.exception.__cause__, reason)

    def test_control_reader_short_read_closes_exact_owned_descriptor(self):
        descriptor = self.directory_fd()
        (self.project / 'control').write_bytes(b'{}')
        actual_open, actual_close = os.open, os.close
        retained = []
        def open_control(*args, **kwargs):
            owned = actual_open(*args, **kwargs)
            retained.append(owned)
            return owned
        try:
            with mock.patch.object(self.light.os, 'open', side_effect=open_control) as opened, \
                    mock.patch.object(self.light.os, 'close', wraps=actual_close) as close, \
                    mock.patch.object(self.light.os, 'read', return_value=b''):
                with self.assertRaisesRegex(ValueError, '^restore control changed while reading: control$'):
                    self.light._read_rehydrate_control(descriptor, 'control', 4096)
                self.assertEqual(len(retained), 1)
                self.assertTrue(close.called, 'reader must close its owned FD even after short read')
                close.assert_called_once_with(retained[0])
                self.assertNotEqual(retained[0], descriptor)
                self.assertEqual(opened.call_args.kwargs['dir_fd'], descriptor)
            with self.assertRaises(OSError) as caught:
                os.fstat(retained[0])
            self.assertEqual(caught.exception.errno, errno.EBADF)
        finally:
            # A deliberate drop-close control must neither raise AttributeError
            # in the observer nor leak the exact descriptor created by this test.
            for owned in retained:
                try:
                    actual_close(owned)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise

    def test_control_reader_replaced_opened_inode_closes_and_refuses(self):
        descriptor = self.directory_fd()
        path = self.project / 'control'
        path.write_bytes(b'{}')
        actual_close = os.close
        info = path.stat()
        with mock.patch.object(self.light.os, 'fstat', return_value=self.changed(info, st_ino=info.st_ino + 1)), \
                mock.patch.object(self.light.os, 'close', wraps=actual_close) as close:
            with self.assertRaisesRegex(ValueError, '^restore control was replaced: control$'):
                self.light._read_rehydrate_control(descriptor, 'control', 4096)
            self.assertEqual(close.call_count, 1)

    def test_control_reader_named_rebind_and_disappearance_close_and_refuse(self):
        descriptor = self.directory_fd()
        path = self.project / 'control'
        path.write_bytes(b'{}')
        info = path.stat()
        actual_close = os.close
        reason = FileNotFoundError(errno.ENOENT, 'synthetic late disappearance')
        for after, message in ((self.changed(info, st_ino=info.st_ino + 1),
                                'restore control changed while reading: control'),
                               (reason, 'restore control disappeared: control')):
            with self.subTest(message=message), \
                    mock.patch.object(self.light.os, 'stat', side_effect=[info, after]), \
                    mock.patch.object(self.light.os, 'close', wraps=actual_close) as close:
                with self.assertRaises(ValueError) as caught:
                    self.light._read_rehydrate_control(descriptor, 'control', 4096)
                self.assertEqual(str(caught.exception), message)
                self.assertEqual(close.call_count, 1)
                if after is reason:
                    self.assertIs(caught.exception.__cause__, reason)

    def test_project_final_inode_recheck_rejects_and_closes(self):
        self.controls()
        actual_fstat = os.fstat
        seen_directory = []
        def fstat(descriptor):
            info = actual_fstat(descriptor)
            if stat.S_ISDIR(info.st_mode):
                seen_directory.append(descriptor)
                if len(seen_directory) == 2:
                    return self.changed(info, st_ino=info.st_ino + 1)
            return info
        with mock.patch.object(self.light.os, 'fstat', side_effect=fstat):
            with self.assertRaises(ValueError) as caught:
                self.light.require_project_eligible(self.project)
        self.assertEqual(str(caught.exception), 'project was replaced during commit check: ' + str(self.project))
        self.assertEqual(len(seen_directory), 2)
        with self.assertRaises(OSError) as closed:
            os.fstat(seen_directory[0])
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_cold_bare_and_tools_import_are_stdlib_only_and_bind_real_copy(self):
        tree = self.tree / 'cold-repository'
        tools = tree / 'tools'
        tools.mkdir(parents=True)
        shutil.copyfile(ROOT / 'tools/project_pointer.py', tools / 'project_pointer.py')
        (tools / '__init__.py').write_text('', encoding='utf-8')
        driver = self.tree / 'cold-driver.py'
        driver.write_text('''import importlib,json,sys
from pathlib import Path
tree,mode=sys.argv[1:]
class NoHeavy:
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] in ('yaml','project_contract'):
            raise ModuleNotFoundError('heavy dependency forbidden',name=fullname)
sys.meta_path.insert(0,NoHeavy())
def deny(event,args):
    if event in ('subprocess.Popen','socket.connect','socket.bind','os.exec','os.system'):
        raise AssertionError('unexpected external effect')
sys.addaudithook(deny)
sys.path.insert(0,str(Path(tree)/'tools') if mode=='bare' else tree)
name='project_pointer' if mode=='bare' else 'tools.project_pointer'
module=importlib.import_module(name)
print(json.dumps({'file':module.__file__,'pointer':module.ACTIVE_PROJECT_POINTER,
                  'absent':module.active_project_dir(tree),'exception_module':module.ActiveProjectPointerError.__module__}))
''', encoding='utf-8')
        home = self.tree / 'cold-home'
        home.mkdir()
        environment = {name: os.environ[name] for name in ('TMPDIR', 'HTTP_TEST_OWNED_ROOT')}
        environment.update(HOME=str(home), PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='en_US.UTF-8')
        for mode, module in (('bare', 'project_pointer'), ('package', 'tools.project_pointer')):
            with self.subTest(mode=mode):
                done = subprocess.run([sys.executable, '-S', '-B', str(driver), str(tree), mode],
                                      cwd=tree, env=environment, stdin=subprocess.DEVNULL,
                                      capture_output=True, text=True, timeout=15)
                self.assertEqual(done.returncode, 0, done.stderr)
                result = json.loads(done.stdout)
                self.assertEqual(Path(result['file']).resolve(), tools / 'project_pointer.py')
                self.assertEqual(result['pointer'], 'DAY0-Prepare/activate-project')
                self.assertIsNone(result['absent'])
                self.assertEqual(result['exception_module'], module)

    def test_cold_legacy_bare_and_tools_export_their_same_local_exception(self):
        import yaml
        # The legacy module still needs its existing optional runtime. A private
        # HOME must not hide a user-site dependency; only its site is carried,
        # never the original repository/tools path or a fake yaml module.
        yaml_site = str(Path(yaml.__file__).resolve().parent.parent)
        tree = self.tree / 'legacy-cold-repository'
        tools = tree / 'tools'
        tools.mkdir(parents=True)
        for name in ('project_pointer.py', 'project_contract.py'):
            shutil.copyfile(ROOT / 'tools' / name, tools / name)
        (tools / '__init__.py').write_text('', encoding='utf-8')
        day0 = tree / 'DAY0-Prepare'
        day0.mkdir()
        (day0 / 'activate-project').write_text('not a pointer', encoding='ascii')
        driver = self.tree / 'legacy-cold-driver.py'
        driver.write_text('''import importlib,json,sys
from pathlib import Path
tree,mode,runtime_site=sys.argv[1:]
def deny(event,args):
    if event in ('subprocess.Popen','socket.connect','socket.bind','os.exec','os.system'):
        raise AssertionError('unexpected external effect')
sys.addaudithook(deny)
sys.path.insert(0,runtime_site)
sys.path.insert(0,str(Path(tree)/'tools') if mode=='bare' else tree)
name='project_contract' if mode=='bare' else 'tools.project_contract'
module=importlib.import_module(name)
try:
    module.active_project_dir(tree)
except module.ActiveProjectPointerError as error:
    print(json.dumps({'caught':type(error) is module._project_pointer.ActiveProjectPointerError,
                      'file':module._project_pointer.__file__,'text':str(error)}))
else:
    raise AssertionError('bad pointer was accepted')
''', encoding='utf-8')
        home = self.tree / 'legacy-cold-home'
        home.mkdir()
        environment = {name: os.environ[name] for name in ('TMPDIR', 'HTTP_TEST_OWNED_ROOT')}
        environment.update(HOME=str(home), PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='en_US.UTF-8')
        for mode in ('bare', 'package'):
            with self.subTest(mode=mode):
                done = subprocess.run([sys.executable, '-B', str(driver), str(tree), mode, yaml_site], cwd=tree,
                                      env=environment, stdin=subprocess.DEVNULL,
                                      capture_output=True, text=True, timeout=15)
                self.assertEqual(done.returncode, 0, done.stderr)
                result = json.loads(done.stdout)
                self.assertTrue(result['caught'])
                self.assertEqual(Path(result['file']).resolve(), tools / 'project_pointer.py')
                self.assertEqual(result['text'], 'DAY0-Prepare/activate-project is not a link: '
                                 + str(day0 / 'activate-project'))


class ProjectPointerSourceCarrierTests(_ProjectPointerFixture):
    def setUp(self):
        super().setUp()
        # Source-vector/roster/data checks only: a future accidental carrier
        # invocation cannot launch even an owned native/stub child here.
        for name in ('subprocess.Popen', 'os.system', 'os.execve', 'socket.create_connection'):
            patcher = mock.patch(name, side_effect=AssertionError('data-only carrier must not execute ' + name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_native_os_and_bios_inverse_accept_current_project_contract_data(self):
        from test_cases import native_os_safe_image as os_image
        from test_cases import native_bios_safe_image as bios_image
        files = {path: (ROOT / path).read_bytes() for path in os_image.PRODUCTION_PINS}
        files['tools/project_pointer.py'] = (ROOT / 'tools/project_pointer.py').read_bytes()
        for name, verify in (('OS', os_image._native_os_reviewed_source_bytes),
                             ('BIOS', bios_image._verified_source_vector)):
            with self.subTest(source=name):
                problem = None
                try:
                    old = verify(files)
                except AssertionError as error:
                    problem = str(error)
                self.assertIsNone(problem, 'current extraction must validate through the unchanged old pin: ' + str(problem))
                self.assertEqual(hashlib.sha256(old['tools/project_contract.py']).hexdigest(),
                                 '100c0b0f19b70d46ac89b1be2f82411f894421062c49b7926e7d2efb35b3cefd')

    def test_native_current_copy_cohorts_carry_exactly_one_pointer_dependency(self):
        from test_cases import native_cpld_safe_image as cpld
        from test_cases import native_bios_safe_image as bios
        from test_cases import native_os_safe_image as os_image
        for name, observed, core_count, current_count in (
                ('CPLD', cpld.COPY_FILES, 48, 49), ('BIOS', bios.COPY_FILES, 56, 57),
                ('OS', os_image.COPY_FILES, 55, 56)):
            with self.subTest(source=name):
                self.assertIn('tools/project_pointer.py', observed)
                self.assertEqual(observed.count('tools/project_pointer.py'), 1)
                self.assertEqual(len(observed), current_count)
                self.assertEqual(len([name for name in observed if name != 'tools/project_pointer.py']), core_count)

    def test_canonical_bootstrap_refuses_foreign_pointer_before_any_import(self):
        from test_cases.ibsw225_fixture_support import runtime_source_support as helper
        foreign = ModuleType('project_pointer')
        foreign.__file__ = str(ROOT / 'tools/project_pointer.py')
        attempts = []
        def unexpected(name, *args, **kwargs):
            attempts.append(name)
            raise RuntimeError('independent unexpected import before new-source refusal')
        caught = None
        with mock.patch.dict(sys.modules, {'project_pointer': foreign}), \
                mock.patch.object(helper.importlib, 'import_module', side_effect=unexpected):
            try:
                helper.support(self)
            except BaseException as error:
                caught = error
            self.assertIs(sys.modules['project_pointer'], foreign)
        self.assertIs(type(caught), AssertionError, 'new dependency must join original fixed-source preflight')
        self.assertEqual(attempts, [])

    def test_real_legacy_bundle_carries_complete_current_pointer_dependency(self):
        from test_cases.ibsw225_fixture_support import legacy_shell_workflow as legacy
        own = self.tree / 'legacy-bundle'
        own.mkdir()
        case = legacy.LegacyShellCompatibilityWorkflowTests()
        flat = case.bundle(own)
        case.require_complete(flat)
        self.assertTrue((flat / 'project_pointer.py').is_file(), 'real bundle must carry the new current dependency')
        self.assertFalse((flat / 'project_pointer.py').is_symlink())
        self.assertEqual((flat / 'project_pointer.py').read_bytes(), (ROOT / 'tools/project_pointer.py').read_bytes())

    def test_flat_members_include_exactly_one_current_pointer_dependency(self):
        from test_cases import test_ibsw225_flat_tools_layout as flat
        self.assertIn('tools/project_pointer.py', flat.MEMBERS)
        self.assertEqual(flat.MEMBERS.count('tools/project_pointer.py'), 1)

    def test_current_pointer_dependency_missing_wrong_or_wrong_type_refuses_data(self):
        from test_cases import native_os_safe_image as os_image
        from test_cases import native_bios_safe_image as bios
        from test_cases import native_cpld_safe_image as cpld
        files = {path: (ROOT / path).read_bytes() for path in os_image.PRODUCTION_PINS}
        for label, payload in (('missing', None), ('wrong-bytes', b'unreviewed pointer source\n'),
                               ('wrong-type', 'not bytes')):
            variant = dict(files)
            if payload is not None:
                variant['tools/project_pointer.py'] = payload
            for name, verify in (('OS', os_image._native_os_reviewed_source_bytes),
                                 ('BIOS', bios._verified_source_vector),
                                 ('CPLD', cpld._verify_project_pointer_source)):
                with self.subTest(source=name, payload=label), self.assertRaises(AssertionError):
                    verify(variant)


class ProjectPointerHistoricalDataTests(_ProjectPointerFixture):
    # These reviewed literal hunk coordinates come from the independently
    # verified 100c -> b841 diff, not from the subject's inverse region table.
    REGIONS = ((4282, 7461, 4282, 1146), (72022, 2562, 65707, 723))

    def extraction_source(self):
        # Complete accepted .4 bytes: D7 must not repin the old B DATA oracle.
        environment = {name: os.environ[name] for name in ('TMPDIR', 'HTTP_TEST_OWNED_ROOT')}
        environment.update(HOME=str(self.tree), PATH='/usr/bin:/bin:/usr/sbin:/sbin', GIT_OPTIONAL_LOCKS='0')
        raw = subprocess.check_output(
            ['/usr/bin/git', '--no-optional-locks', '-C', str(ROOT), 'show',
             '7b1b18a5f87076c032007d1da3273bccc04f3f99:tools/project_contract.py'],
            cwd=self.tree, env=environment, stdin=subprocess.DEVNULL, timeout=15,
        )
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'b8410d455c55c9664bb3cb873dd9ff690e03cbfbc0f771e1dc76cf7c9b3ef89d')
        return raw

    def old_source(self):
        environment = {name: os.environ[name] for name in ('TMPDIR', 'HTTP_TEST_OWNED_ROOT')}
        environment.update(HOME=str(self.tree), PATH='/usr/bin:/bin:/usr/sbin:/sbin', GIT_OPTIONAL_LOCKS='0')
        raw = subprocess.check_output(
            ['/usr/bin/git', '--no-optional-locks', '-C', str(ROOT), 'show',
             '50ad1700c5e5675a06c413aa699c7c0e72803289:tools/project_contract.py'],
            cwd=self.tree, env=environment, stdin=subprocess.DEVNULL, timeout=15,
        )
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '100c0b0f19b70d46ac89b1be2f82411f894421062c49b7926e7d2efb35b3cefd')
        return raw

    def test_whole_old_project_data_needs_no_new_execution_dependency(self):
        old = self.old_source()
        from test_cases import native_os_safe_image as os_image
        from test_cases import native_bios_safe_image as bios
        files = {path: (ROOT / path).read_bytes() for path in os_image.PRODUCTION_PINS}
        files['tools/project_contract.py'] = old
        self.assertNotIn('tools/project_pointer.py', files)
        with mock.patch('subprocess.Popen', side_effect=AssertionError('historical DATA must not execute')):
            self.assertTrue(os_image._restore_project_pointer_layer(old) == old, 'old DATA bytes must remain unchanged')
            for name, verify in (('OS', os_image._native_os_reviewed_source_bytes),
                                 ('BIOS', bios._verified_source_vector)):
                with self.subTest(source=name):
                    self.assertTrue(verify(files)['tools/project_contract.py'] == old,
                                    'old19 validation cannot invent a new execution dependency')

    def test_exact_inverse_restores_independent_old_bytes_and_refuses_all_unreviewed_layers(self):
        old = self.old_source()
        from test_cases import native_os_safe_image as os_image
        current = self.extraction_source()
        self.assertEqual(hashlib.sha256(current).hexdigest(),
                         'b8410d455c55c9664bb3cb873dd9ff690e03cbfbc0f771e1dc76cf7c9b3ef89d')
        bad = {'outside-prefix': b'# UNREVIEWED\n' + current,
               'outside-suffix': current + b'# UNREVIEWED\n',
               'outside-middle': current[:32] + bytes([current[32] ^ 1]) + current[33:]}
        for ordinal, (old_at, old_len, new_at, new_len) in enumerate(self.REGIONS, 1):
            prior, reviewed = old[old_at:old_at + old_len], current[new_at:new_at + new_len]
            bad['missing-' + str(ordinal)] = current[:new_at] + current[new_at + new_len:]
            bad['duplicate-' + str(ordinal)] = current + reviewed
            bad['half-old-' + str(ordinal)] = current[:new_at] + prior + current[new_at + new_len:]
            bad['truncated-' + str(ordinal)] = current[:new_at + new_len - 1] + current[new_at + new_len:]
        first, second = self.REGIONS
        a, alen, b, blen = first[2], first[3], second[2], second[3]
        bad['reordered'] = (current[:a] + current[b:b + blen] + current[a + alen:b]
                            + current[a:a + alen] + current[b + blen:])
        with mock.patch('subprocess.Popen', side_effect=AssertionError('inverse DATA must not execute')):
            self.assertTrue(os_image._restore_project_pointer_layer(current) == old,
                            'complete inverse must equal independent historical Git bytes')
            for label, payload in bad.items():
                with self.subTest(layer=label), self.assertRaises(AssertionError):
                    os_image._restore_project_pointer_layer(payload)


class InitialSetupLatestYamlDataLayerTests(_ProjectPointerFixture):
    # Independent D67-O10 B bytes, inserted in fixed complete .4 Git data.
    OFFSET = 55588
    ANCHOR = b'    # Publisher-owned pointers to the latest complete release (R-016 \xc2\xa73.4).\n'
    ROW = (b'    SetupLinkSpec("infiniband/bringup/xdr-initial-setup/latest_yaml", "ztp/config/nvos/latest_yaml", "dir",\n'
           b'                  "optional", writer="setup", base="repository"),\n')

    def sources(self):
        baseline = ProjectPointerHistoricalDataTests.extraction_source(self)
        old = ProjectPointerHistoricalDataTests.old_source(self)
        self.assertEqual(174, len(self.ROW))
        self.assertEqual(1, baseline.count(self.ANCHOR))
        self.assertEqual(self.ANCHOR, baseline[self.OFFSET:self.OFFSET + len(self.ANCHOR)])
        expected = baseline[:self.OFFSET] + self.ROW + baseline[self.OFFSET:]
        self.assertEqual(hashlib.sha256(expected).hexdigest(),
                         'e3225c8152b38855d59f4e15033ff3f16395565030b6075cab13221ceacf32a7')
        return baseline, old, expected

    def strict_layer(self):
        from test_cases import native_os_safe_image as os_image
        layer = getattr(os_image, '_restore_initial_setup_latest_yaml_layer', None)
        self.assertTrue(callable(layer), 'D7 requires one strict outer DATA seam, not a repinned B layer')
        return os_image, layer

    def test_exact_d7_outer_layer_restores_b_then_original_old_data(self):
        baseline, old, expected = self.sources()
        os_image, layer = self.strict_layer()
        self.assertEqual(expected, (ROOT / 'tools/project_contract.py').read_bytes())
        with mock.patch('subprocess.Popen', side_effect=AssertionError('inverse DATA must not execute')):
            self.assertEqual(baseline, layer(expected))
            self.assertEqual(old, os_image._restore_project_pointer_layer(expected))
            self.assertEqual(old, os_image._restore_project_pointer_layer(baseline))
            self.assertEqual(old, os_image._restore_project_pointer_layer(old))

    def test_strict_d7_outer_layer_refuses_missing_and_unreviewed_data(self):
        baseline, old, expected = self.sources()
        _os_image, layer = self.strict_layer()
        at, size = self.OFFSET, len(self.ROW)
        first, second = self.ROW.splitlines(keepends=True)
        bad = {
            'missing': baseline, 'old-history': old,
            'duplicate': expected[:at] + self.ROW + expected[at:],
            'half-field': expected[:at] + self.ROW.replace(b'"optional"', b'"publisher"', 1) + expected[at + size:],
            'truncated': expected[:at + size - 1] + expected[at + size:],
            'reordered': expected[:at] + second + first + expected[at + size:],
            'outside-prefix': b'# UNREVIEWED\n' + expected,
            'outside-suffix': expected + b'# UNREVIEWED\n',
            'outside-middle': expected[:32] + bytes([expected[32] ^ 1]) + expected[33:],
            'wrong-type': expected.decode('utf-8'), 'none': None,
        }
        with mock.patch('subprocess.Popen', side_effect=AssertionError('inverse DATA must not execute')):
            for label, payload in bad.items():
                with self.subTest(layer=label), self.assertRaises(AssertionError):
                    layer(payload)

    def test_d7_whole_current_vectors_still_require_exact_pointer_dependency(self):
        _baseline, old, expected = self.sources()
        os_image, _layer = self.strict_layer()
        from test_cases import native_bios_safe_image as bios_image
        files = {path: (ROOT / path).read_bytes() for path in os_image.PRODUCTION_PINS}
        files['tools/project_contract.py'] = expected
        pointer = (ROOT / 'tools/project_pointer.py').read_bytes()
        self.assertEqual('aa2c3ad58d383327d32e61376de1cdb32dc7456fdc339650634c209f87ee9419',
                         hashlib.sha256(pointer).hexdigest())
        files['tools/project_pointer.py'] = pointer
        with mock.patch('subprocess.Popen', side_effect=AssertionError('current-vector DATA must not execute')):
            for name, verify in (('OS', os_image._native_os_reviewed_source_bytes),
                                 ('BIOS', bios_image._verified_source_vector)):
                with self.subTest(source=name, vector='whole-current'):
                    self.assertEqual(old, verify(files)['tools/project_contract.py'])
                for label, payload in (('missing', None), ('wrong', b'UNREVIEWED NEW\n'), ('type', 'not bytes')):
                    bad = dict(files)
                    if payload is None:
                        del bad['tools/project_pointer.py']
                    else:
                        bad['tools/project_pointer.py'] = payload
                    with self.subTest(source=name, vector=label), self.assertRaises(AssertionError):
                        verify(bad)
