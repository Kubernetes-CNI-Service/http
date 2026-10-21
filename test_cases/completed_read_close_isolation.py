"""Proposed fixed-one-whole cold isolation; test-only, NOT RUN."""
import importlib
import importlib.machinery
import os
import json
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import unittest

_SELECTOR = ('test_cases.test_completed_collection_source_read_close.'
    'CompletedSourceReadLeaseCloseTests.'
    'test_owned_child_actual_lock_close_then_eio_preserves_body_interrupt_and_cause')
_UNKNOWN_CHILDREN = []
_END = 'COMPLETED_READ_CLOSE_CHILD_END='
_PROGRAM = '''
import os,stat,sys
root=os.path.abspath(sys.argv[1])
if 'test_cases' in sys.modules:
    raise RuntimeError('close child source package was preloaded')
for relative in ('test_cases/__init__.py','test_cases/completed_read_close_isolation.py'):
    info=os.lstat(os.path.join(root,relative))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise RuntimeError('close child canonical bootstrap is missing or linked')
sys.path.insert(0,root)
from test_cases.completed_read_close_isolation import _child_main
raise SystemExit(_child_main(sys.argv[2],sys.argv[3]))
'''


def run_close_whole(self):
    selector = _SELECTOR
    root = Path(__file__).resolve().parents[1]
    nonce = secrets.token_hex(16)
    command = (sys.executable, '-B', '-c', _PROGRAM,
               str(root), selector, nonce)
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    # Preserve actual normal dependency configuration, not an isolation bypass.
    # PYTHONPATH/code fallbacks are NOT forwarded.
    for name in ('HOME', 'PYTHONUSERBASE', 'PYTHONNOUSERSITE'):
        if name in os.environ:
            environment[name] = os.environ[name]
    child = subprocess.Popen(command, cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, close_fds=True)
    timed_out = False
    output = b''
    primary = None
    cleanup_errors = []
    kill_requested = False
    try:
        try:
            output, _ = child.communicate(timeout=30)
        except subprocess.TimeoutExpired as error:
            timed_out = True
            output = error.output or b''
            kill_requested = True
            child.kill()  # Only the retained original Popen, no PID search.
            output, _ = child.communicate(timeout=5)
    except BaseException as error:
        primary = error
        # Preserve an original interrupt/cause. Retain uncertain ownership
        # rather than turn missing terminal evidence into cleanup success.
        if child.poll() is None:
            try:
                if not kill_requested:
                    kill_requested = True
                    child.kill()
                    child.communicate(timeout=5)
                else:
                    _UNKNOWN_CHILDREN.append(child)
            except BaseException as cleanup:
                cleanup_errors.append(cleanup)
                _UNKNOWN_CHILDREN.append(child)
    finally:
        if child.poll() is not None:
            for stream in (child.stdout, child.stderr, child.stdin):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as error:
                        cleanup_errors.append(error)
    for error in cleanup_errors:
        if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
            primary = error
    if primary is not None:
        raise primary
    rendered = output.decode('utf-8', errors='replace')
    sys.stdout.write(rendered)
    self.assertFalse(timed_out, 'owned close child timeout: UNKNOWN, not PASS')
    lines = rendered.splitlines()
    ends = [line[len(_END):] for line in lines if line.startswith(_END)]
    self.assertEqual(1, len(ends), 'complete unique child END required')
    self.assertTrue(lines and lines[-1].startswith(_END), 'child END must be final')
    self.assertEqual(dict(nonce=nonce, selector=selector, ran=1,
        failures=0, errors=0, skipped=0, exit=0), json.loads(ends[0]))
    self.assertEqual(0, child.returncode)


def _install_fixed_source_root():
    """Finite TEST source imports cannot fall back to another image/main."""
    root = Path(__file__).resolve().parents[1]
    prefixes = frozenset(('test_cases', 'monitor', 'tools', 'ztp', 'infra'))
    aliases = {'switch_collection_gate': root / 'monitor',
               'project_contract': root / 'tools'}
    def within(value):
        resolved = Path(value).resolve(strict=True)
        return resolved == root or root in resolved.parents
    for name in ('test_cases', 'test_cases.completed_read_close_isolation'):
        module = sys.modules.get(name)
        if module is None or not within(module.__file__):
            raise RuntimeError('close child canonical bootstrap differs')
    class FixedSource:
        def find_spec(self, fullname, path=None, target=None):
            top = fullname.partition('.')[0]
            if fullname in aliases:
                search = (str(aliases[fullname]),)
            elif top in prefixes:
                search = (str(root),) if path is None else tuple(path)
                if not search or not all(within(item) for item in search):
                    raise ImportError('foreign close child source namespace')
            else:
                return None  # Keep genuine stdlib/site dependency resolution.
            spec = importlib.machinery.PathFinder.find_spec(fullname, search)
            if spec is None:
                raise ImportError('missing canonical close child source')
            if spec.origin is not None and not within(spec.origin):
                raise ImportError('foreign close child source origin')
            locations = spec.submodule_search_locations
            if locations is not None and not all(within(item) for item in locations):
                raise ImportError('foreign close child package namespace')
            return spec
    sys.meta_path.insert(0, FixedSource())


def _child_main(selector, nonce):
    if (selector != _SELECTOR or type(nonce) is not str
            or len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce)
            or threading.enumerate() != [threading.current_thread()]):
        raise RuntimeError('invalid owned close child request')
    _install_fixed_source_root()
    module_name, class_name, method_name = selector.rsplit('.', 2)
    module = importlib.import_module(module_name)
    case = getattr(module, class_name)('_exercise_owned_child_actual_lock_close_then_eio_preserves_body_interrupt_and_cause')
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
        unittest.TestSuite((case,)))
    code = 0 if (result.wasSuccessful() and result.testsRun == 1
                 and not result.skipped
                 and threading.enumerate() == [threading.current_thread()]) else 1
    print(_END + json.dumps(dict(nonce=nonce, selector=selector, ran=result.testsRun,
        failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), exit=code), sort_keys=True), flush=True)
    return code
