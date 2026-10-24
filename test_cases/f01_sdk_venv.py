"""F01 SDK identity tests run on the venv-ibsw-upgrade interpreter when the runner is not a venv.

tools/f01_ssh_dependency_identity.py (used unchanged by tools/ufm_bootstrap_auth_adapter.py) proves the
Paramiko SDK only inside an isolated venv: sys.prefix != sys.base_prefix, include-system-site-packages =
false, and the lock's exact distributions installed there with their RECORD. The formal full proof runs
on /usr/bin/python3 (CLT 3.9, owner decision 2026-10-24), which is never such a venv, so that check
refuses there. A test that needs the identity is decorated with @sdk_identity_test:

* inside a venv it runs in-process, exactly as before;
* otherwise the same test id (assertions unchanged) runs in a child of the table's venv-ibsw-upgrade
  interpreter (~/.venvs/http/ibsw-upgrade/bin/python), which must first prove the production identity,
  and the child must report exactly that one test run with no failure, error or skip.

A missing venv, a venv without the identity, or any other child outcome FAILS the test with the install
command `python3 infra/deps.py install --target venv-ibsw-upgrade`. Nothing is ever skipped.
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "infra/dependencies.json"
TARGET = "venv-ibsw-upgrade"
INSTALL_COMMAND = "python3 infra/deps.py install --target venv-ibsw-upgrade"
INSTALL_HINT = (f"create it as the user who runs the full proof, from the repository root "
                f"(on macOS with /usr/bin/python3): {INSTALL_COMMAND}")
CHILD_ENV = "HTTP_F01_SDK_VENV_CHILD"
PROBE_PREFIX = "F01-SDK-VENV-PROBE "
RESULT_PREFIX = "F01-SDK-VENV-CHILD-RESULT "
PROBE_TIMEOUT = 300
CHILD_TIMEOUT = 1800
OUTPUT_TAIL = 12000
COUNTS = ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")

# Child programs, run as `<venv python> -I -B -c <program> <repository root> [test id]`: -I ignores PYTHON*
# variables, the user site and the working directory, so the repository root is put on sys.path explicitly.
PROBE = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tools import ufm_bootstrap_auth_adapter as auth\n"
    "identity = auth._factory_sdk_identity()\n"
    "print(" + repr(PROBE_PREFIX) + " + json.dumps({'prefix': sys.prefix, 'executable': sys.executable,"
    " 'lock_sha256': identity['environment']['lock_sha256']}))\n"
)
CHILD = (
    "import json, sys, unittest\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[2])\n"
    "result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)\n"
    "sys.stdout.flush()\n"
    "print(" + repr(RESULT_PREFIX) + " + json.dumps({'run': result.testsRun, 'failures': len(result.failures),"
    " 'errors': len(result.errors), 'skipped': len(result.skipped),"
    " 'expected_failures': len(result.expectedFailures),"
    " 'unexpected_successes': len(result.unexpectedSuccesses), 'prefix': sys.prefix}))\n"
    "sys.exit(0 if result.wasSuccessful() else 1)\n"
)

_PROBED: dict = {}


def venv_path() -> Path:
    """The table's venv-ibsw-upgrade directory of the current user (as infra/deps.py expands it)."""
    table = json.loads(TABLE.read_text(encoding="ascii"))
    return Path(os.path.expanduser(table["targets"][TARGET]["path"]))


def current_interpreter_is_venv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def tagged(output: str, prefix: str):
    """The JSON object of the last line starting with prefix, or None."""
    for line in reversed(output.splitlines()):
        if line.startswith(prefix):
            try:
                value = json.loads(line[len(prefix):])
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _same_directory(left: object, right: Path) -> bool:
    return isinstance(left, str) and os.path.realpath(left) == os.path.realpath(str(right))


def _run(command: list, timeout: int, env: dict = None) -> tuple:
    """(returncode or None, combined output) of one child; a timeout or OSError is returncode None."""
    try:
        completed = subprocess.run(command, cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        output = exc.output or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        return None, f"{output}\n[timed out after {timeout} s]"
    except OSError as exc:
        return None, f"[cannot run {command[0]}: {exc.__class__.__name__}: {exc}]"
    return completed.returncode, completed.stdout


def probe_problem(python: Path, venv: Path):
    """None when the venv proves the production F01 SDK identity, else why not (cached per interpreter)."""
    key = str(python)
    if key not in _PROBED:
        returncode, output = _run([str(python), "-I", "-B", "-c", PROBE, str(ROOT)], PROBE_TIMEOUT)
        value = tagged(output, PROBE_PREFIX)
        if returncode != 0 or value is None:
            _PROBED[key] = f"identity probe exit {returncode}: {output.strip()[-2000:]}"
        elif not _same_directory(value.get("prefix"), venv):
            _PROBED[key] = f"identity probe ran in {value.get('prefix')!r}, not {venv}"
        else:
            _PROBED[key] = None
    return _PROBED[key]


def run_in_sdk_venv(test) -> None:
    """Run test.id() in the venv child; return only when it passed there, else fail `test` (never skip)."""
    test_id = test.id()
    venv = venv_path()
    python = venv / "bin" / "python"
    if os.environ.get(CHILD_ENV) == "1":
        test.fail(f"{test_id}: the F01 SDK child interpreter {sys.executable} is not a venv; {INSTALL_HINT}")
    if not ((venv / "pyvenv.cfg").is_file() and os.access(str(python), os.X_OK)):
        test.fail(f"{test_id} needs the F01 SDK identity, which only an isolated venv proves, and this "
                  f"interpreter ({sys.executable}) is not one; {venv} is missing: {INSTALL_HINT}")
    problem = probe_problem(python, venv)
    if problem is not None:
        test.fail(f"{test_id}: {venv} does not prove the F01 SDK identity; recreate it (rm -rf {venv}, then "
                  f"{INSTALL_COMMAND}).\n{problem}")
    env = dict(os.environ)
    env[CHILD_ENV] = "1"
    returncode, output = _run([str(python), "-I", "-B", "-c", CHILD, str(ROOT), test_id], CHILD_TIMEOUT, env)
    summary = tagged(output, RESULT_PREFIX)
    passed = (returncode == 0 and summary is not None and summary.get("run") == 1
              and all(summary.get(name) == 0 for name in COUNTS)
              and _same_directory(summary.get("prefix"), venv))
    if not passed:
        test.fail(f"{test_id} did not pass in the F01 SDK venv child {python} (exit {returncode}, result "
                  f"{summary}); its assertions are the ones shown below. An SDK identity failure means the "
                  f"venv must be recreated: {INSTALL_COMMAND}\n--- child output (tail) ---\n"
                  f"{output[-OUTPUT_TAIL:]}")


def sdk_identity_test(method):
    """Decorator for a test method that needs the production F01 SDK identity (see the module doc)."""
    @functools.wraps(method)
    def routed(self, *args, **kwargs):
        if current_interpreter_is_venv():
            return method(self, *args, **kwargs)
        run_in_sdk_venv(self)
        return None
    routed.f01_sdk_venv_routed = True
    return routed
