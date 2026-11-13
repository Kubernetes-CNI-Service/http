"""UNRUN: one direct whole, four fixed cold-child IO safety negatives.

These are test-carrier safety checks, not native dispatch or device evidence.
No production provider, verifier, graph, request or manager is substituted.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_cases as TEST_PACKAGE
from test_cases import native_cpld_safe_image as SAFE

CASES = ('missing-metadata', 'invalid-metadata', 'stub-drift', 'arbitrary-expression')
RETAINED_IMAGES = []
END = 'IBSW_SAFE_IMAGE_DIRECT_END='
CHILD = r'''
import importlib.util,json,sys
from pathlib import Path
image,source,case=sys.argv[1:]
sys.path.insert(0,image)
spec=importlib.util.spec_from_file_location('_native_cpld_safe_image_negative_source',source)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.exercise_negative(Path(image),case)
print(module.END+json.dumps(dict(case=case,image=image,popen_calls=0),sort_keys=True),flush=True)
'''


def exercise_negative(image, case):
    """Executed only in an owned cold interpreter whose canonical root=image."""
    from test_cases import native_cpld_physical_io as IO
    check = unittest.TestCase()
    check.assertIn(case, CASES)
    check.assertEqual(image, Path(TEST_PACKAGE.__file__).resolve().parents[1])
    check.assertEqual(image/'test_cases/native_cpld_physical_io.py', Path(IO.__file__).resolve())
    check.assertEqual(image/'test_cases/native_cpld_safe_image.py', Path(SAFE.__file__).resolve())
    # Prove that the freshly prepared lower/stub metadata is valid BEFORE fault.
    SAFE.validate_image(image)
    metadata = image / 'native-cpld-safe-image.json'
    original_metadata = metadata.read_bytes()
    original_inode = metadata.stat().st_ino
    bad_stub = image/'tools/native-cpld-io/private-scp'
    original_stub = bad_stub.read_bytes()
    command = '/usr/bin/python3 -c ' + shlex.quote('raise SystemExit(0)') + ' probe'

    if case == 'missing-metadata':
        metadata.unlink()  # Exclusively test-owned image; retained, not repaired.
    elif case == 'invalid-metadata':
        metadata.write_bytes(b'{invalid-json\n')
    elif case == 'stub-drift':
        # Same inode/size, executable still present: existence is not enough.
        changed_stub = b'!' + original_stub[1:]
        bad_stub.write_bytes(changed_stub)
        check.assertEqual(len(original_stub), bad_stub.stat().st_size)

    channel = IO.ActualFixedPythonChannel(image, image/'never-created-channel.json')
    with patch.object(IO.subprocess, 'Popen', side_effect=AssertionError('FORBIDDEN_ACTUAL_EXEC')) as attempted:
        if case == 'missing-metadata':
            with check.assertRaises(FileNotFoundError):
                channel.exec_command(command)
            check.assertFalse(metadata.exists())
        elif case == 'invalid-metadata':
            # select_image must NOT silently regenerate an invalid prepared tree.
            with patch.object(SAFE, 'prepare_image', wraps=SAFE.prepare_image) as repairs:
                with check.assertRaises(json.JSONDecodeError):
                    SAFE.select_image(image)
                repairs.assert_not_called()
            with check.assertRaises(json.JSONDecodeError):
                channel.exec_command(command)
            check.assertEqual(b'{invalid-json\n', metadata.read_bytes())
            check.assertEqual(original_inode, metadata.stat().st_ino)
        elif case == 'stub-drift':
            with check.assertRaisesRegex(AssertionError, '^independent literal private executable mismatch$'):
                channel.exec_command(command)
            check.assertEqual(changed_stub, bad_stub.read_bytes())
            check.assertEqual(original_metadata, metadata.read_bytes())
        else:
            with check.assertRaisesRegex(AssertionError, '^only exact lowered fixed producer expressions may execute$'):
                channel.exec_command(command)
            check.assertEqual(original_metadata, metadata.read_bytes())
            check.assertEqual(original_stub, bad_stub.read_bytes())
        attempted.assert_not_called()
    check.assertIsNone(channel.process)
    check.assertIsNone(channel.command)
    check.assertFalse((image/'never-created-channel.json').exists())


class NativeCpldSafeImageDirectTests(unittest.TestCase):
    def test_metadata_stub_and_expression_fail_before_any_actual_channel_popen(self):
        source_root = Path(TEST_PACKAGE.__file__).resolve().parents[1]
        # Canonical input here must be the UNLOWERED root U, not a mutable legacy
        # image. prepare_image itself enforces the exact original source hashes.
        for case in CASES:
            with self.subTest(case=case):
                image = SAFE.prepare_image(source_root)
                RETAINED_IMAGES.append(str(image))
                environment = dict(PATH='/usr/bin:/bin', LC_ALL='C',
                    PYTHONDONTWRITEBYTECODE='1', TMPDIR=os.environ['HTTP_TEST_OWNED_ROOT'],
                    HTTP_TEST_OWNED_ROOT=os.environ['HTTP_TEST_OWNED_ROOT'])
                command = (sys.executable, '-B', '-c', CHILD, str(image),
                           str(Path(__file__).resolve()), case)
                timed_out = False
                with subprocess.Popen(command, cwd=image, env=environment,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, close_fds=True) as owned:
                    try:
                        output, _ = owned.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        # Only this retained original child; never a PID scan.
                        owned.kill()
                        output, _ = owned.communicate()
                    status = owned.returncode
                text = output.decode('utf-8', errors='replace')
                sys.stdout.write(text)
                self.assertFalse(timed_out, 'test-owned diagnostic child timeout: UNKNOWN')
                self.assertEqual(0, status)
                lines = text.splitlines()
                endings = [line[len(END):] for line in lines if line.startswith(END)]
                self.assertEqual(1, len(endings))
                self.assertTrue(lines and lines[-1].startswith(END))
                self.assertEqual(dict(case=case, image=str(image), popen_calls=0), json.loads(endings[0]))
        print('IBSW_SAFE_IMAGE_RETAINED=' + json.dumps(RETAINED_IMAGES), flush=True)


class ExplicitOwnedRootContractTests(unittest.TestCase):
    """Runner-owned roots, not image metadata or ambient tempfile defaults."""
    def setUp(self):
        self.outer = Path(os.environ['HTTP_TEST_OWNED_ROOT'])
        self.assertEqual(self.outer, self.outer.resolve())
        self.assertEqual(0o700, self.outer.stat().st_mode & 0o777)
        self.source = Path(__file__).resolve().parents[1]

    def root(self, prefix='owned root with spaces '):
        root = Path(tempfile.mkdtemp(prefix=prefix, dir=self.outer))
        root.chmod(0o700)
        return root

    def test_invalid_explicit_roots_refuse_before_creation_without_system_fallback(self):
        real = self.root()
        bad_mode = self.root('wrong-mode-')
        bad_mode.chmod(0o755)
        link = self.outer / ('root-link-' + real.name.replace(' ', '-'))
        link.symlink_to(real, target_is_directory=True)
        for value in (None, 'relative-root', str(bad_mode), str(link), str(real / '..' / real.name)):
            with self.subTest(value=value):
                environment = dict(os.environ)
                if value is None:
                    environment.pop('HTTP_TEST_OWNED_ROOT', None)
                else:
                    environment['HTTP_TEST_OWNED_ROOT'] = value
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(SAFE.tempfile, 'mkdtemp', side_effect=AssertionError('FORBIDDEN_CREATE')) as made, \
                        patch.object(subprocess, 'Popen', side_effect=AssertionError('FORBIDDEN_POPEN')) as launched:
                    with self.assertRaisesRegex((RuntimeError, AssertionError), 'owned.*root|root.*refused'):
                        SAFE.prepare_image(self.source)
                    made.assert_not_called()
                    launched.assert_not_called()

    def test_three_image_families_use_independently_supplied_space_and_long_roots(self):
        from test_cases import native_bios_safe_image as bios
        from test_cases import native_os_safe_image as os_image
        original = tempfile.mkdtemp
        for prefix in ('second root with spaces ', 'long-root-' + 'x' * 110):
            root = self.root(prefix)
            def checked_creation(*args, **kwargs):
                self.assertEqual(root, Path(kwargs['dir']), 'explicit runner root must select every creation')
                return original(*args, **kwargs)
            with self.subTest(root=str(root)), patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)), \
                    patch.object(tempfile, 'mkdtemp', side_effect=checked_creation):
                for gate in (SAFE, bios, os_image):
                    image = gate.prepare_image(self.source)
                    self.assertEqual(root, image.parent)
                    gate.validate_image(image)
                    RETAINED_IMAGES.append(str(image))
                    other = self.root_without_tempfile(original)
                    with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(other)):
                        with self.assertRaisesRegex((AssertionError, RuntimeError), 'root|image'):
                            gate.validate_image(image)

    def root_without_tempfile(self, original):
        root = Path(original(prefix='different-owned-root-', dir=self.outer))
        root.chmod(0o700)
        return root

    def test_synthetic_ancestor_view_is_only_the_declared_root_chain(self):
        from test_cases.native_cpld_physical_io import PhysicalSwitchSFTP
        root = self.root()
        flow = root / 'flow'
        flow.mkdir(mode=0o700)
        switch = flow / 'switch'
        switch.mkdir(mode=0o700)
        with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)):
            sftp = PhysicalSwitchSFTP(switch, SimpleNamespace())
            for ancestor in (root, *root.parents):
                value = sftp.lstat(str(ancestor))
                self.assertEqual(0, value.st_uid)
                self.assertEqual(0o755, value.st_mode & 0o777)
            self.assertEqual(flow.lstat().st_ino, sftp.lstat(str(flow)).st_ino)
            self.assertEqual(switch.lstat().st_ino, sftp.lstat(str(switch)).st_ino)
            with self.assertRaises(AssertionError):
                sftp.lstat(str(root.parent / 'unapproved-sibling'))

    def test_cold_whitelists_explicitly_propagate_the_same_root(self):
        from test_cases import native_bios_isolation, native_os_test_isolation
        from test_cases import scp_native_cpld_bridge_isolation
        root = self.root()
        for isolated, gate_name in ((native_bios_isolation, 'native_bios_safe_image'),
                (native_os_test_isolation, 'native_os_safe_image'),
                (scp_native_cpld_bridge_isolation, 'native_cpld_safe_image')):
            selector = next(iter(isolated.ROSTER))
            def method(_case):
                raise AssertionError('PARENT_MUST_NOT_EXECUTE_WORKFLOW')
            method.__module__, method.__qualname__ = selector.rsplit('.', 1)
            def observe(_command, **kwargs):
                self.assertEqual(str(root), kwargs['env'].get('HTTP_TEST_OWNED_ROOT'))
                self.assertEqual(str(root), kwargs['env'].get('TMPDIR'))
                raise RuntimeError('OBSERVED_COLD_ENV')
            gate = __import__('test_cases.' + gate_name, fromlist=['select_image'])
            with self.subTest(module=isolated.__name__), patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)), \
                    patch.object(gate, 'select_image', return_value=root), \
                    patch.object(isolated.subprocess, 'Popen', side_effect=observe):
                with self.assertRaisesRegex(RuntimeError, '^OBSERVED_COLD_ENV$'):
                    isolated.isolated_whole(method)(self)

    def test_cold_image_validation_rejects_lost_root_inheritance(self):
        original = tempfile.mkdtemp
        root = self.root()
        def checked_creation(*args, **kwargs):
            self.assertEqual(root, Path(kwargs['dir']))
            return original(*args, **kwargs)
        with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)), \
                patch.object(tempfile, 'mkdtemp', side_effect=checked_creation):
            image = SAFE.prepare_image(self.source)
        environment = dict(os.environ)
        environment.pop('HTTP_TEST_OWNED_ROOT', None)
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(subprocess, 'Popen', side_effect=AssertionError('FORBIDDEN_POPEN')) as launched:
            with self.assertRaisesRegex((RuntimeError, AssertionError), 'owned.*root|root.*refused'):
                SAFE.validate_image(image)
            launched.assert_not_called()

    def test_os_coordinator_env_retains_root_without_changing_runner_env_contract(self):
        from test_cases import native_os_dual_channel as channel
        root = self.root()
        flow = root / 'native-os-bridge-owned-test'
        flow.mkdir(mode=0o700)
        switch = flow / 'switch'
        switch.mkdir(mode=0o700)
        facts = {name: list(channel._facts(path.lstat())) for name, path in (('root', flow), ('switch', switch))}
        with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)):
            self.assertEqual(str(root), channel._environment(flow).get('HTTP_TEST_OWNED_ROOT'))
            channel._root_check(flow, facts)
            other = self.root('wrong-root-')
            with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(other)):
                with self.assertRaisesRegex(RuntimeError, 'root.*refused'):
                    channel._root_check(flow, facts)

    def test_simfleet_real_bash_uses_explicit_owned_tmp(self):
        from test_cases.ibsw_v2_switch_sim import LocalSession
        root = self.root()
        switch = SimpleNamespace(tick=lambda: False, take_fault=lambda _command: None,
            sysroot=root, bin=root, state=root, login_password='PUBLIC-SYNTHETIC-ONLY',
            home=root, hostname='synthetic-switch')
        fleet = SimpleNamespace(http_root=root, contexts=[], commands=[])
        command = '/usr/bin/python3 -c ' + shlex.quote(
            'import tempfile; print(tempfile.gettempdir())')
        with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)):
            result = LocalSession(switch, fleet, 'public-model').run(command)
        self.assertEqual(0, result.rc)
        self.assertEqual(str(root), result.stdout.decode().strip())

    def test_runtime_venv_cold_fixture_keeps_owned_tmp(self):
        from test_cases import test_ibsw_upgrade_usability_workflow as workflow
        root = self.root()
        def observe(_command, **kwargs):
            self.assertEqual(str(root), kwargs['env'].get('TMPDIR'))
            raise RuntimeError('OBSERVED_VENV_ENV')
        method = workflow.RuntimeVenvSwitchWorkflowTests(
            'test_interpreter_without_ssh_runtime_execs_the_home_venv_once_before_the_guard')
        with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)), \
                patch.object(workflow.subprocess, 'run', side_effect=observe):
            with self.assertRaisesRegex(RuntimeError, '^OBSERVED_VENV_ENV$'):
                method.test_interpreter_without_ssh_runtime_execs_the_home_venv_once_before_the_guard()

    def test_standalone_v2_check_carrier_keeps_explicit_tmp_before_bash(self):
        from test_cases import test_ibsw_v2_device_scripts as scripts
        root = self.root()
        case = scripts.CheckScriptTest()
        case.bin, case.sysroot = root, root
        def observe(_command, **kwargs):
            self.assertEqual(str(root), kwargs['env'].get('TMPDIR'))
            raise RuntimeError('OBSERVED_STANDALONE_CHECK_ENV')
        with patch.dict(os.environ, HTTP_TEST_OWNED_ROOT=str(root)), \
                patch.object(scripts.subprocess, 'run', side_effect=observe):
            with self.assertRaisesRegex(RuntimeError, '^OBSERVED_STANDALONE_CHECK_ENV$'):
                case.run_check('precheck')

    def test_wrong_uid_root_refuses_before_any_creation(self):
        from test_cases import native_cpld_physical_io as io
        wrong_uid = os.geteuid() + 1
        with patch.object(io.os, 'geteuid', return_value=wrong_uid), \
                patch.object(tempfile, 'mkdtemp', side_effect=AssertionError('FORBIDDEN_CREATE')) as made, \
                patch.object(subprocess, 'Popen', side_effect=AssertionError('FORBIDDEN_POPEN')) as launched:
            with self.assertRaisesRegex(AssertionError, 'owned.*root.*refused'):
                SAFE.prepare_image(self.source)
            made.assert_not_called()
            launched.assert_not_called()

    def test_actual_cold_interpreter_refuses_missing_root_before_workflow(self):
        image = SAFE.prepare_image(self.source)
        environment = dict(PATH='/usr/bin:/bin', LC_ALL='C',
            TMPDIR=str(self.outer), PYTHONDONTWRITEBYTECODE='1')
        # No production import or invocation; only the already hash-admitted
        # local image's stdlib-only validator runs in this retained cold child.
        program = ('import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
            'from test_cases.native_cpld_safe_image import validate_image; '
            'validate_image(Path(sys.argv[1])); print("FORBIDDEN_VALIDATION_SUCCESS")')
        outcome = subprocess.run([sys.executable, '-B', '-c', program, str(image)],
            cwd=image, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertNotEqual(0, outcome.returncode)
        self.assertEqual(b'', outcome.stdout)
        self.assertIn(b'explicit owned test root refused', outcome.stderr)
