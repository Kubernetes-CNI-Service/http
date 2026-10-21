"""Test-only, fixed-roster one-whole child isolation; no production authority."""
import functools
import importlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest

ROSTER = (
    'test_cases.test_ibsw3_native_cpld_bridge.NativeCpldBridgeWorkflowTests.test_native_cpld_dispatch_retains_originals_and_manager_reads_real_exit_93',
    'test_cases.test_ibsw3_native_cpld_bridge.NativeCpldBridgeWorkflowTests.test_companion_drift_after_context_prevents_secret_send_and_dispatch',
)
_ACTIVE_CHILD_SELECTOR = None
_END = 'IBSW_SCP_ISOLATED_END='
_CHILD_PROGRAM = (
    'import sys; sys.path.insert(0, sys.argv[1]); '
    'from test_cases.scp_native_cpld_bridge_isolation import _child_main; '
    'raise SystemExit(_child_main(sys.argv[2], sys.argv[3]))'
)


def isolated_whole(function):
    selector = function.__module__ + '.' + function.__qualname__
    if selector not in ROSTER:
        raise RuntimeError('unlisted isolated test')

    @functools.wraps(function)
    def invoke(self):
        if _ACTIVE_CHILD_SELECTOR == selector:
            return function(self)
        if _ACTIVE_CHILD_SELECTOR is not None:
            raise RuntimeError('nested isolated test refused')
        from test_cases.native_cpld_safe_image import select_image
        source = Path(__file__).resolve().parents[1]
        root = select_image(source)
        print('IBSW_SCP_COLD_IMAGE=' + str(root), flush=True)
        nonce = secrets.token_hex(16)
        environment = {
            'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
            'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': tempfile.gettempdir(),
        }
        command = (sys.executable, '-B', '-c', _CHILD_PROGRAM,
                   str(root), selector, nonce)
        timed_out = False
        with subprocess.Popen(command, cwd=str(root), env=environment,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, close_fds=True) as child:
            try:
                output, _ = child.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Only this retained, directly-created child handle is managed.
                child.kill()
                output, _ = child.communicate()
            returncode = child.returncode
        text = output.decode('utf-8', errors='replace')
        sys.stdout.write(text)
        self.assertFalse(timed_out, 'owned child diagnostic budget expired: UNKNOWN')
        lines = text.splitlines()
        ends = [line[len(_END):] for line in lines if line.startswith(_END)]
        self.assertEqual(1, len(ends), 'one complete child END required')
        self.assertTrue(lines and lines[-1].startswith(_END), 'END must be final')
        expected = dict(nonce=nonce, selector=selector, ran=1, failures=0,
                        errors=0, skipped=0, exit=0)
        self.assertEqual(expected, json.loads(ends[0]))
        self.assertEqual(0, returncode)
    return invoke


def _child_main(selector, nonce):
    global _ACTIVE_CHILD_SELECTOR
    if (selector not in ROSTER or len(nonce) != 32
            or any(char not in '0123456789abcdef' for char in nonce)
            or _ACTIVE_CHILD_SELECTOR is not None):
        raise RuntimeError('invalid isolated child request')
    from test_cases.native_cpld_safe_image import validate_image
    validate_image(Path(__file__).resolve().parents[1])
    _ACTIVE_CHILD_SELECTOR = selector
    module_name, class_name, method_name = selector.rsplit('.', 2)
    # Normal canonical imports only: no sys.modules/provider substitution.
    module = importlib.import_module(module_name)
    case = getattr(module, class_name)(method_name)
    suite = unittest.TestSuite((case,))
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stdout).run(suite)
    retained = getattr(module, 'RETAINED_TREES', None)
    if retained is None:
        retained = module.BASE.RETAINED_TREES
    print('IBSW_SCP_RETAINED_TREES=' + json.dumps(retained), flush=True)
    code = 0 if (result.wasSuccessful() and result.testsRun == 1
                 and not result.skipped) else 1
    print(_END + json.dumps(dict(nonce=nonce, selector=selector,
          ran=result.testsRun, failures=len(result.failures),
          errors=len(result.errors), skipped=len(result.skipped), exit=code),
          sort_keys=True), flush=True)
    return code


