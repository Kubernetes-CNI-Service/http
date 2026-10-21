"""NOTRUN fixed three-whole cold isolation; timeout is UNKNOWN, never PASS."""
import functools
import importlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import unittest

ROSTER = tuple('test_cases.test_ibsw3_native_os_manager_workflow.NativeOsManagerWorkflowTests.' + name
               for name in (
    'test_single_target_v2_ack_record_precedes_private_fetch_without_releasing_unknown_slot',
    'test_native_scp_os_missing_or_wrong_content_keeps_manager_ack_absent',
    'test_native_scp_os_critical_measurement_commit_failure_withholds_ack'))
_ACTIVE_CHILD_SELECTOR = None
_END = 'IBSW_NATIVE_OS_ISOLATED_END='
_CHILD = (
    'import sys; sys.path.insert(0,sys.argv[1]); '
    'from test_cases.native_os_test_isolation import _child_main; '
    'raise SystemExit(_child_main(sys.argv[2],sys.argv[3]))')


def isolated_whole(function):
    selector = function.__module__ + '.' + function.__qualname__
    if selector not in ROSTER:
        raise RuntimeError('unlisted native OS isolated whole')

    @functools.wraps(function)
    def invoke(self):
        if _ACTIVE_CHILD_SELECTOR == selector:
            return function(self)
        if _ACTIVE_CHILD_SELECTOR is not None:
            raise RuntimeError('nested native OS whole refused')
        from test_cases.native_os_safe_image import select_image
        image = select_image(Path(__file__).resolve().parents[1])
        print('IBSW_NATIVE_OS_COLD_IMAGE=' + str(image), flush=True)
        nonce = secrets.token_hex(16)
        environment = dict(PATH='/usr/bin:/bin', LC_ALL='C',
            PYTHONDONTWRITEBYTECODE='1', TMPDIR=tempfile.gettempdir())
        command = (sys.executable, '-B', '-c', _CHILD, str(image), selector, nonce)
        timed_out = False
        # Parent owns this exact Popen only. It never scans descendants/PIDs or
        # closes numeric slots. Inner original runner owners have their own60s
        # diagnostic cleanup; unknown descendants remain UNKNOWN/retained.
        with subprocess.Popen(command, cwd=image, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, close_fds=True) as child:
            try:
                raw, _ = child.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True
                child.kill()
                raw, _ = child.communicate(timeout=5)
            code = child.returncode
        text = raw.decode('utf-8', errors='replace')
        sys.stdout.write(text)
        self.assertFalse(timed_out, 'owned whole deadline UNKNOWN; retained trees are not clean proof')
        lines = text.splitlines()
        ends = [line[len(_END):] for line in lines if line.startswith(_END)]
        self.assertEqual(1, len(ends))
        self.assertTrue(lines and lines[-1].startswith(_END))
        self.assertEqual(dict(nonce=nonce, selector=selector, ran=1, failures=0,
                             errors=0, skipped=0, exit=0), json.loads(ends[0]))
        self.assertEqual(0, code)
    return invoke


def _child_main(selector, nonce):
    global _ACTIVE_CHILD_SELECTOR
    if (selector not in ROSTER or type(nonce) is not str or len(nonce) != 32
            or any(value not in '0123456789abcdef' for value in nonce)
            or _ACTIVE_CHILD_SELECTOR is not None):
        raise RuntimeError('invalid exact native OS whole request')
    from test_cases.native_os_safe_image import validate_image
    validate_image(Path(__file__).resolve().parents[1])
    before = tuple(threading.enumerate())
    _ACTIVE_CHILD_SELECTOR = selector
    module_name, class_name, method_name = selector.rsplit('.', 2)
    module = importlib.import_module(module_name)
    case = getattr(module, class_name)(method_name)
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stdout).run(unittest.TestSuite((case,)))
    after = tuple(threading.enumerate())
    added = [thread.name for thread in after if thread not in before and thread.is_alive()]
    from test_cases import native_os_dual_channel as owners
    print('IBSW_NATIVE_OS_RETAINED_TREES=' + json.dumps(module.FLOW.RETAINED_TREES), flush=True)
    print('IBSW_NATIVE_OS_UNKNOWN_OWNERS=' + str(len(owners.UNKNOWN_SESSIONS)), flush=True)
    print('IBSW_NATIVE_OS_ADDED_ALIVE=' + json.dumps(added), flush=True)
    code = 0 if (result.wasSuccessful() and result.testsRun == 1 and not result.skipped
                 and not added and not owners.UNKNOWN_SESSIONS) else 1
    print(_END + json.dumps(dict(nonce=nonce, selector=selector, ran=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        exit=code), sort_keys=True), flush=True)
    return code
