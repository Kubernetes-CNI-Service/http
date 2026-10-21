"""UNRUN: one direct whole, four fixed cold-child IO safety negatives.

These are test-carrier safety checks, not native dispatch or device evidence.
No production provider, verifier, graph, request or manager is substituted.
"""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
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
                    PYTHONDONTWRITEBYTECODE='1', TMPDIR='/private/tmp')
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
