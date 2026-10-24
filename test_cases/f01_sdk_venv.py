"""F01 SDK identity tests run on the venv-ibsw-upgrade interpreter when the runner is not that venv.

tools/f01_ssh_dependency_identity.py (used unchanged by tools/ufm_bootstrap_auth_adapter.py) proves the
Paramiko SDK only inside an isolated venv: sys.prefix != sys.base_prefix, include-system-site-packages =
false, and the lock's exact distributions installed there with their RECORD. The formal full proof runs
on /usr/bin/python3 (CLT 3.9, owner decision 2026-10-24), which is never such a venv, so that check
refuses there. A test that needs the identity is decorated with @sdk_identity_test:

* when this interpreter is the table's venv-ibsw-upgrade (~/.venvs/http/ibsw-upgrade) it runs in-process;
* otherwise the same test id (assertions unchanged) runs in a child of that venv's interpreter, which must
  first prove the production identity and must be the proof interpreter in a venv: the child's
  base_prefix (realpath), sys.version_info[:3], sys.implementation.cache_tag and platform.machine() equal
  this interpreter's, so the four tests run on the Python the full proof records. The child must report
  exactly that one test run with no failure, error or skip.

A missing or broken venv, a venv without the identity or of another base interpreter, or any other child
outcome FAILS the test with the install command `python3 infra/deps.py install --target venv-ibsw-upgrade`.
Nothing is ever skipped. Children run in their own session; a timeout kills the whole process group.
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "infra/dependencies.json"
TARGET = "venv-ibsw-upgrade"
INSTALL_COMMAND = "python3 infra/deps.py install --target venv-ibsw-upgrade"
INSTALL_HINT = (f"create it as the user who runs the full proof, from the repository root, with the proof "
                f"interpreter (on macOS /usr/bin/python3): {INSTALL_COMMAND}")
CHILD_ENV = "HTTP_F01_SDK_VENV_CHILD"
PROBE_PREFIX = "F01-SDK-VENV-PROBE "
RESULT_PREFIX = "F01-SDK-VENV-CHILD-RESULT "
PROBE_TIMEOUT = 300
CHILD_TIMEOUT = 1800
KILL_GRACE = 30
OUTPUT_TAIL = 12000
COUNTS = ("failures", "errors", "skipped", "expected_failures", "unexpected_successes")
IDENTITY_KEYS = ("base_prefix", "version", "cache_tag", "machine")

# The interpreter identity both child programs report next to their own result.
_IDENTITY = ("{'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'version': list(sys.version_info[:3]),"
             " 'cache_tag': sys.implementation.cache_tag, 'machine': platform.machine()}")
# Child programs, run as `<venv python> -I -B -c <program> <repository root> [test id]`: -I ignores PYTHON*
# variables, the user site and the working directory, so the repository root is put on sys.path explicitly.
# The tagged result line goes to stdout on a line of its own (after a newline, so output a test leaves
# without one cannot be glued to it); unittest progress goes to stderr.
PROBE = (
    "import json, platform, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tools import ufm_bootstrap_auth_adapter as auth\n"
    "identity = auth._factory_sdk_identity()\n"
    "value = " + _IDENTITY + "\n"
    "value['lock_sha256'] = identity['environment']['lock_sha256']\n"
    "sys.stdout.write('\\n' + " + repr(PROBE_PREFIX) + " + json.dumps(value) + '\\n')\n"
    "sys.stdout.flush()\n"
)
CHILD = (
    "import json, platform, sys, unittest\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[2])\n"
    "result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)\n"
    "value = " + _IDENTITY + "\n"
    "value.update(run=result.testsRun, failures=len(result.failures), errors=len(result.errors),"
    " skipped=len(result.skipped), expected_failures=len(result.expectedFailures),"
    " unexpected_successes=len(result.unexpectedSuccesses))\n"
    "sys.stdout.write('\\n' + " + repr(RESULT_PREFIX) + " + json.dumps(value) + '\\n')\n"
    "sys.stdout.flush()\n"
    "sys.exit(0 if result.wasSuccessful() else 1)\n"
)

_PROBED: dict = {}


def venv_path() -> Path:
    """The table's venv-ibsw-upgrade directory of the current user (as infra/deps.py expands it)."""
    table = json.loads(TABLE.read_text(encoding="ascii"))
    return Path(os.path.expanduser(table["targets"][TARGET]["path"]))


def runs_in_target_venv() -> bool:
    """True only when this interpreter is the table's venv itself (any other venv also uses the child)."""
    return os.path.realpath(sys.prefix) == os.path.realpath(str(venv_path()))


def interpreter_identity() -> dict:
    """The parts of this (proof) interpreter's identity a child must share."""
    return {"base_prefix": os.path.realpath(sys.base_prefix), "version": list(sys.version_info[:3]),
            "cache_tag": sys.implementation.cache_tag, "machine": platform.machine()}


def identity_problem(value, venv: Path):
    """None when a child reported that it ran in `venv` on the proof interpreter, else what differs."""
    if not isinstance(value, dict):
        return "no interpreter identity was reported"
    problems = []
    if not _same_directory(value.get("prefix"), venv):
        problems.append(f"prefix {value.get('prefix')!r} is not {venv}")
    reported = dict(value)
    if isinstance(reported.get("base_prefix"), str):
        reported["base_prefix"] = os.path.realpath(reported["base_prefix"])
    for key, expected in interpreter_identity().items():
        if reported.get(key) != expected:
            problems.append(f"{key} {reported.get(key)!r} differs from the proof interpreter's {expected!r}")
    return "; ".join(problems) or None


def tagged(output: str, prefix: str):
    """The JSON object of the last line that starts with prefix, or None (never a partial match)."""
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


def _kill_group(process) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except OSError:
            pass


def _run(command: list, timeout: int, env: dict = None) -> tuple:
    """(returncode or None, stdout, stderr) of one child in its own session; on timeout the group is killed.

    Output is decoded as UTF-8 with replacement, so undecodable bytes cannot turn a FAIL into an ERROR.
    """
    try:
        process = subprocess.Popen(command, cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
                                   errors="replace", start_new_session=True)
    except OSError as exc:
        return None, "", f"[cannot run {command[0]}: {exc.__class__.__name__}: {exc}]"
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(process)
        try:
            stdout, stderr = process.communicate(timeout=KILL_GRACE)
        except subprocess.TimeoutExpired:
            # A descendant that left the group still holds the pipes; give up on its output.
            for stream in (process.stdout, process.stderr):
                stream.close()
            process.wait()
            stdout, stderr = "", ""
        return None, stdout or "", f"{stderr or ''}\n[timed out after {timeout} s; process group {process.pid} killed]"
    except BaseException:
        _kill_group(process)
        process.wait()
        raise
    return process.returncode, stdout, stderr


def _tails(stdout: str, stderr: str) -> str:
    return (f"--- child stdout (tail) ---\n{stdout[-OUTPUT_TAIL:]}\n"
            f"--- child stderr (tail) ---\n{stderr[-OUTPUT_TAIL:]}")


def probe_problem(python: Path, venv: Path):
    """None when the venv proves the production F01 SDK identity on the proof interpreter, else why not.

    Cached per interpreter path for this process.
    """
    key = str(python)
    if key not in _PROBED:
        returncode, stdout, stderr = _run([str(python), "-I", "-B", "-c", PROBE, str(ROOT)], PROBE_TIMEOUT)
        value = tagged(stdout, PROBE_PREFIX)
        if returncode != 0 or value is None:
            _PROBED[key] = f"identity probe exit {returncode}:\n{_tails(stdout, stderr)}"
        else:
            problem = identity_problem(value, venv)
            _PROBED[key] = None if problem is None else f"its interpreter is not the proof interpreter: {problem}"
    return _PROBED[key]


def _venv_problem(venv: Path, python: Path):
    """None when venv/bin/python can run, else what is wrong with the venv directory."""
    if not venv.exists() and not venv.is_symlink():
        return f"{venv} is missing"
    if not (venv / "pyvenv.cfg").is_file():
        return f"{venv} exists but is not a venv (no pyvenv.cfg); move it away"
    if os.path.islink(python) and not python.exists():
        return (f"{python} is a broken symlink to {os.readlink(python)} (its base interpreter is gone); "
                f"remove the venv (rm -rf {venv})")
    if not os.access(str(python), os.X_OK):
        return f"{python} is missing or not executable; remove the venv (rm -rf {venv})"
    return None


def run_in_sdk_venv(test) -> None:
    """Run test.id() in the venv child; return only when it passed there, else fail `test` (never skip)."""
    test_id = test.id()
    venv = venv_path()
    python = venv / "bin" / "python"
    if os.environ.get(CHILD_ENV) == "1":
        test.fail(f"{test_id}: the F01 SDK child interpreter {sys.executable} (prefix {sys.prefix}) is not "
                  f"{venv}; {INSTALL_HINT}")
    problem = _venv_problem(venv, python)
    if problem is not None:
        test.fail(f"{test_id} needs the F01 SDK identity, which only the isolated {TARGET} venv proves, and "
                  f"this interpreter ({sys.executable}) is not that venv. {problem}. {INSTALL_HINT}")
    problem = probe_problem(python, venv)
    if problem is not None:
        test.fail(f"{test_id}: {venv} does not prove the F01 SDK identity on the proof interpreter "
                  f"{sys.executable}; recreate it: rm -rf {venv}, then {INSTALL_COMMAND} (with that "
                  f"interpreter).\n{problem}")
    env = dict(os.environ)
    env[CHILD_ENV] = "1"
    returncode, stdout, stderr = _run([str(python), "-I", "-B", "-c", CHILD, str(ROOT), test_id],
                                      CHILD_TIMEOUT, env)
    summary = tagged(stdout, RESULT_PREFIX)
    mismatch = identity_problem(summary, venv)
    passed = (returncode == 0 and summary is not None and summary.get("run") == 1
              and all(summary.get(name) == 0 for name in COUNTS) and mismatch is None)
    if not passed:
        test.fail(f"{test_id} did not pass in the F01 SDK venv child {python} (exit {returncode}, result "
                  f"{summary}, interpreter {mismatch or 'ok'}); its assertions are the ones shown below. An SDK "
                  f"identity failure means the venv must be recreated: {INSTALL_COMMAND}\n{_tails(stdout, stderr)}")


def sdk_identity_test(method):
    """Decorator for a test method that needs the production F01 SDK identity (see the module doc)."""
    @functools.wraps(method)
    def routed(self, *args, **kwargs):
        if runs_in_target_venv():
            return method(self, *args, **kwargs)
        run_in_sdk_venv(self)
        return None
    routed.f01_sdk_venv_routed = True
    return routed
