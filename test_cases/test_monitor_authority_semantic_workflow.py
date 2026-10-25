#!/usr/bin/env python3
"""Direct and cross-component contracts for Monitor cache authority semantics."""

from __future__ import annotations

from contextlib import ExitStack
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from contextlib import contextmanager
import ast
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "tools/control-auth.py"
CGI_PATH = ROOT / "monitor/ztp-monitor-control.cgi"


def load_python(name: str, path: Path):
    if path.suffix == ".cgi":
        loader = SourceFileLoader(name, os.fspath(path))
        spec = importlib.util.spec_from_loader(name, loader)
    else:
        spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONTROL_AUTH = load_python("monitor_authority_r4_helper", HELPER_PATH)
MONITOR_CGI = load_python("monitor_authority_r4_cgi", CGI_PATH)
HELPER_SHA256 = hashlib.sha256(HELPER_PATH.read_bytes()).hexdigest()
INFRA_SETUP_PATH = ROOT / "infra/infra-setup.py"
INFRA_SETUP = load_python("monitor_authority_r4_infra_setup", INFRA_SETUP_PATH)
NATIVE_RECOVERY_COMMAND = "sudo ./infra/infra-setup.py --recover-monitor-authority --apply"


def canonical(payload: dict[str, object]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def breaker_payload(failure_count: int = 1) -> bytes:
    return canonical({
        "schema_version": 1,
        "contaminant_dev": 7,
        "contaminant_ino": 11,
        "failure_count": failure_count,
    })


def cache_payload(value: bool, digest: str = HELPER_SHA256) -> bytes:
    return canonical({
        "schema_version": 1,
        "factory_records_active": value,
        "helper_sha256": digest,
    })


def leaf_snapshot(path: Path) -> tuple[object, ...]:
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
        path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None,
    )


def shell_function(path: Path, name: str) -> str:
    """Return one top-level shell function for an executable runner harness."""
    source = path.read_text(encoding="utf-8")
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}\n", source,
    )
    if match is None:
        raise AssertionError(f"missing shell function {name} in {path}")
    return match.group(0)


def decision_capture_shell(path: Path, *, portable: bool = True) -> str:
    source = (
        shell_function(path, "terminate_monitor_authority_capture_holders")
        + shell_function(path, "capture_monitor_authority_decision")
    )
    if portable and sys.platform == "darwin":
        return (
            source.replace("exec /usr/bin/timeout", "timeout")
            .replace("/usr/bin/timeout", "timeout")
            + test_timeout_shell()
        )
    return source


def darwin_capture_holder_cleanup_shell() -> str:
    if sys.platform != "darwin":
        return ""
    return r'''
terminate_monitor_authority_capture_holders() {
  local holder_file=$1 stdout_pipe=$2 stderr_pipe=$3
  local stdout_reader=$4 stderr_reader=$5 report_file=$6
  local pass holder_pid pass_file="${report_file}.pass"
  for pass in 1 2 3 4; do
    rm -f -- "$pass_file"
    /usr/sbin/lsof -t -- "$holder_file" 2>/dev/null |
      while IFS= read -r holder_pid; do
        case "$holder_pid" in
          ''|*[!0-9]*) continue ;;
        esac
        if [[ "$holder_pid" != "$stdout_reader" && \
              "$holder_pid" != "$stderr_reader" ]]; then
          : >"$report_file"
          : >"$pass_file"
          kill -KILL "$holder_pid" 2>/dev/null || true
        fi
      done || true
    [[ -e "$pass_file" ]] || break
  done
  rm -f -- "$pass_file"
  [[ ! -e "$report_file" ]]
}
'''


def test_timeout_shell() -> str:
    body = r'''
timeout() {
  local timeout_seconds ready_file
  [[ "$1" == --signal=KILL ]] || return 125
  timeout_seconds=$2
  shift 2
  ready_file=${HTTP_ZTP_TEST_TIMEOUT_READY_FILE:-}
  if declare -F "$1" >/dev/null; then
    export -f "$1"
    set -- /bin/bash -c '"$@"' http-test-timeout "$@"
  fi
  /usr/bin/python3 -c \
    'import os,signal,subprocess,sys,time
ready=sys.argv[2]
budget_deadline=time.monotonic()+float(sys.argv[1])
command=subprocess.Popen(sys.argv[3:],close_fds=False)
expired=False
try:
    deadline=time.monotonic()+2.0
    deadline=min(deadline,budget_deadline)
    while ready and not os.path.exists(ready) and command.poll() is None and time.monotonic()<deadline:
        time.sleep(0.005)
    if ready and not os.path.exists(ready) and command.poll() is None:
        expired=True
    else:
        try:
            command.wait(timeout=max(0.0,budget_deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            expired=True
finally:
    if command.poll() is None:
        command.kill()
    command_rc=command.wait()
if expired or command_rc == -signal.SIGKILL:
    raise SystemExit(124)
raise SystemExit(command_rc if command_rc >= 0 else 128-command_rc)' \
    "$timeout_seconds" "$ready_file" "$@" <&0 >&1 2>&2
}
'''
    # A portable timeout fixture must bind the current proof interpreter, not
    # macOS's /usr/bin/python3 developer-tools dispatch shim. Keep the original
    # readiness barrier within the requested timeout, with kill/reap intact.
    return body.replace("/usr/bin/python3 -c", shlex.quote(os.path.realpath(sys.executable)) + " -B -c")


def timeout_with_owned_pid_receipt(pid_file: Path) -> str:
    """Publish the supervisor's original Popen PID inside its kill/reap scope."""
    portable_timeout = test_timeout_shell()
    checkpoint = "try:\n    deadline=time.monotonic()+2.0"
    if portable_timeout.count(checkpoint) != 1:
        raise AssertionError("portable supervisor receipt boundary changed")
    # Hex literals cannot escape the shell's single-quoted Python program.
    parent = str(pid_file.parent).encode("utf-8").hex()
    destination = str(pid_file).encode("utf-8").hex()
    receipt = "\n".join((
        "try:",
        "    import tempfile",
        f'    receipt_fd,receipt_stage=tempfile.mkstemp(dir=bytes.fromhex("{parent}").decode("utf-8"),prefix=".readiness-pid-")',
        "    try:",
        '        with os.fdopen(receipt_fd,"wb") as receipt_stream:',
        '            receipt_stream.write(str(command.pid).encode("ascii"))',
        "            receipt_stream.flush();os.fsync(receipt_stream.fileno())",
        f'        os.replace(receipt_stage,bytes.fromhex("{destination}").decode("utf-8"))',
        "    finally:",
        "        if os.path.exists(receipt_stage):os.unlink(receipt_stage)",
        "    deadline=time.monotonic()+2.0",
    ))
    return portable_timeout.replace(checkpoint, receipt)


def darwin_python_holder_terminator(holder_path: str, identities: set) -> bool:
    """Test-only macOS stand-in for infra-setup.py's /proc holder scan (lsof on the holder file)."""
    del identities
    clean = True
    for _attempt in range(4):
        listed = subprocess.run(
            ["/usr/sbin/lsof", "-t", "--", holder_path], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        holders = [int(value) for value in listed.stdout.split()
                   if value.isdigit() and int(value) != os.getpid()]
        if not holders:
            break
        clean = False
        for holder in holders:
            try:
                os.kill(holder, signal.SIGKILL)
            except ProcessLookupError:
                pass
    return clean


@contextmanager
def python_capture_holder_scan():
    """Use the production /proc scan on Linux and the lsof stand-in where /proc is absent."""
    if os.path.isdir("/proc/self/fd"):
        yield
        return
    with mock.patch.object(INFRA_SETUP, "terminate_descriptor_holders", darwin_python_holder_terminator):
        yield


def python_native_setup(root: Path, *argv: str):
    """A real InfraSetup whose host paths live under `root` (authorized unattended by default)."""
    options = INFRA_SETUP.parse_arguments(["--recover-monitor-authority", *(argv or ("--apply", "--yes"))])
    with mock.patch.object(INFRA_SETUP, "HOST_ROOT", root):
        return INFRA_SETUP.InfraSetup(options)


def failed_capture_holder_cleanup_shell() -> str:
    return r'''
terminate_monitor_authority_capture_holders() {
  : >"$6"
  return 1
}
'''


def private_python_fixture_command(path: Path) -> str:
    """Run an owned fake producer with the proof's native interpreter."""
    return shlex.quote(os.path.realpath(sys.executable)) + " -B " + shlex.quote(os.fspath(path))


def run_shell(
    body: str, *, timeout_seconds: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > 15.0
    ):
        raise ValueError("shell harness timeout is outside the fixed local bound")
    process = subprocess.Popen(
        ["/bin/bash"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=ROOT, text=True, start_new_session=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    try:
        stdout, stderr = process.communicate(
            input=body, timeout=float(timeout_seconds),
        )
    except subprocess.TimeoutExpired as timeout_error:
        # A descendant can retain captured pipes after the shell was reaped.
        # Its old PID is no longer authority to signal a process group. The
        # caller separately owns and cleans its recorded detached fake PIDs.
        if process.poll() is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            process.wait(timeout=2.0)
            raise timeout_error
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            process.wait(timeout=2.0)
        raise timeout_error
    except BaseException as interruption:
        # All post-construction failures must finish owned cleanup. Preserve
        # the existing TimeoutExpired branch and its separate stale-PID rule.
        first_cleanup_interrupt = None
        cleanup_failures = None
        capture_complete = False
        try:
            cleanup_failures = []
            capture_complete = True
        except BaseException:
            # Python could not allocate the diagnostic collection. Continue
            # cleanup, but never publish an empty tuple as captured evidence.
            pass

        def record_failure(phase, error):
            nonlocal capture_complete, first_cleanup_interrupt
            # Priority cannot depend on successful diagnostic allocation.
            if not isinstance(error, Exception) and first_cleanup_interrupt is None:
                first_cleanup_interrupt = error
            try:
                cleanup_failures.append((phase, error))
            except BaseException:
                capture_complete = False

        try:
            interruption._run_shell_cleanup_failures = None
        except BaseException:
            capture_complete = False
        try:
            running = process.poll() is None
        except BaseException as error:
            record_failure("poll", error)
            running = False  # an unknown leader is not group authority
        if running:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except BaseException as error:
                record_failure("group", error)
        try:
            process.communicate(timeout=2.0)
        except BaseException as error:
            record_failure("communicate", error)
            try:
                process.kill()
            except BaseException as error:
                record_failure("objectkill", error)
        for phase, stream in (
            ("stdin", process.stdin), ("stdout", process.stdout),
            ("stderr", process.stderr),
        ):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    record_failure(phase, error)
        try:
            process.wait(timeout=2.0)
        except BaseException as error:
            record_failure("wait", error)
        try:
            interruption._run_shell_cleanup_failures = (
                tuple(cleanup_failures) if capture_complete else None
            )
        except BaseException:
            # None/missing is NOT_CAPTURED, never evidence of no failures.
            # If Python also refuses this clearing assignment, diagnostic
            # metadata is unavailable/untrustworthy; the primary still wins.
            try:
                interruption._run_shell_cleanup_failures = None
            except BaseException:
                pass
        if isinstance(interruption, Exception) and first_cleanup_interrupt is not None:
            raise first_cleanup_interrupt
        raise
    return subprocess.CompletedProcess(
        process.args, process.returncode, stdout=stdout, stderr=stderr,
    )


def cleanup_recorded_test_processes(pid_file: Path) -> None:
    """Kill every fixed-fixture PID and prove disappearance by two seconds."""

    try:
        raw = pid_file.read_bytes()
    except FileNotFoundError:
        return
    finally:
        pid_file.unlink(missing_ok=True)
    if not raw or len(raw) > 256:
        raise AssertionError("test holder PID evidence is invalid")
    try:
        process_ids = tuple(int(value) for value in raw.decode("ascii").split())
    except (UnicodeDecodeError, ValueError) as exc:
        raise AssertionError("test holder PID evidence is invalid") from exc
    if (
        not process_ids
        or len(process_ids) > 8
        or len(set(process_ids)) != len(process_ids)
        or any(process_id <= 1 or process_id == os.getpid() for process_id in process_ids)
    ):
        raise AssertionError("test holder PID set is invalid")
    for process_id in process_ids:
        try:
            os.kill(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 2.0
    remaining = process_ids
    while remaining and time.monotonic() < deadline:
        alive = []
        for process_id in remaining:
            try:
                waited, _status = os.waitpid(process_id, os.WNOHANG)
            except ChildProcessError:
                waited = 0
            if waited == process_id:
                continue
            try:
                os.kill(process_id, 0)
            except ProcessLookupError:
                continue
            alive.append(process_id)
        remaining = tuple(alive)
        if remaining:
            time.sleep(0.01)
    if remaining:
        raise AssertionError(f"test holder PIDs survived cleanup: {remaining!r}")


BAD_PAYLOADS = {
    "breaker-truncated": ("breaker", b'{"schema_version":1'),
    "breaker-extra": ("breaker", canonical({
        "schema_version": 1, "contaminant_dev": 7, "contaminant_ino": 11,
        "failure_count": 1, "extra": False,
    })),
    "breaker-future-schema": ("breaker", canonical({
        "schema_version": 2, "contaminant_dev": 7, "contaminant_ino": 11,
        "failure_count": 1,
    })),
    "breaker-zero": ("breaker", breaker_payload(0)),
    "breaker-four": ("breaker", breaker_payload(4)),
    "cache-zero-length": ("cache", b""),
    "cache-truncated": ("cache", b'{"schema_version":1'),
    "cache-extra": ("cache", canonical({
        "schema_version": 1, "factory_records_active": True,
        "helper_sha256": HELPER_SHA256, "extra": False,
    })),
    "cache-future-schema": ("cache", canonical({
        "schema_version": 2, "factory_records_active": True,
        "helper_sha256": HELPER_SHA256,
    })),
    "cache-wrong-helper": ("cache", cache_payload(True, "0" * 64)),
}


def _split_source_lines(source: str) -> list[str]:
    """Match AST's CRLF/CR/LF line numbering; form feed is not a newline."""
    lines = []
    start = index = 0
    while index < len(source):
        character = source[index]
        if character == "\r":
            index += 1
            if index < len(source) and source[index] == "\n":
                index += 1
        elif character == "\n":
            index += 1
        else:
            index += 1
            continue
        lines.append(source[start:index])
        start = index
    if start < len(source):
        lines.append(source[start:])
    return lines


class _SourceSegments:
    """Source-local, lazy line split with AST UTF-8 byte-column slicing."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._lines: list[str] | None = None

    def get(self, node: ast.AST) -> str | None:
        try:
            if node.end_lineno is None or node.end_col_offset is None:
                return None
            lineno = node.lineno - 1
            end_lineno = node.end_lineno - 1
            col_offset = node.col_offset
            end_col_offset = node.end_col_offset
        except AttributeError:
            return None

        if self._lines is None:
            self._lines = _split_source_lines(self._source)
        lines = self._lines
        if end_lineno == lineno:
            return lines[lineno].encode()[col_offset:end_col_offset].decode()
        first = lines[lineno].encode()[col_offset:].decode()
        last = lines[end_lineno].encode()[:end_col_offset].decode()
        middle = lines[lineno + 1:end_lineno]
        middle.insert(0, first)
        middle.append(last)
        return "".join(middle)


def _class_scope_monitor_authority_findings(
    path: Path, source: str,
) -> tuple[list[str], set[str]]:
    """Preserve the class/method/setUp scan's findings and order."""
    violations = []
    method_fixtures = set()
    segments = _SourceSegments(source)
    tree = ast.parse(source, filename=os.fspath(path))
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        class_decorators = " ".join(
            segments.get(item) or ""
            for item in node.decorator_list
        )
        if "monitor_authority" in class_decorators:
            violations.append(f"{path.name}:{node.name}:class-decorator")
        for child in node.body:
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = {
                segments.get(item) or ""
                for item in child.decorator_list
            }
            if "with_valid_monitor_authority_fixture" in decorators:
                method_fixtures.add(child.name)
                if (
                    path.name != "test_ztp_container_runtime.py"
                    or node.name != "ContainerTransactionContractTests"
                    or child.name.startswith("test_monitor_authority")
                ):
                    violations.append(
                        f"{path.name}:{node.name}.{child.name}:fixture-scope"
                    )
            if child.name in {"setUp", "setUpClass"}:
                segment = segments.get(child) or ""
                if (
                    "require_monitor_authority" in segment
                    or "with_valid_monitor_authority_fixture" in segment
                ):
                    violations.append(
                        f"{path.name}:{node.name}.{child.name}"
                    )
    return violations, method_fixtures


class MonitorAuthoritySemanticWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.sandbox = Path(self.temporary.name)
        self.uid = os.geteuid()
        self.gid = os.getegid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_test_harness_shells_have_local_deadlines_and_group_cleanup(self) -> None:
        process = mock.MagicMock()
        process.args = ["/bin/bash"]
        process.pid = 4242
        process.returncode = -signal.SIGKILL
        # This case represents a still-live timed-out session; the separate
        # reaped-session case must never signal its stale identifier.
        process.poll.return_value = None
        process.communicate.side_effect = (
            subprocess.TimeoutExpired(process.args, 15.0),
            ("", ""),
        )
        process.__enter__.return_value = process
        with mock.patch.object(
            subprocess, "Popen", return_value=process,
        ) as popen, mock.patch.object(os, "killpg") as killpg:
            with self.assertRaises(subprocess.TimeoutExpired):
                run_shell("while :; do :; done\n", timeout_seconds=0.25)

        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(
            0.25, process.communicate.call_args_list[0].kwargs["timeout"],
        )
        killpg.assert_called_once_with(4242, signal.SIGKILL)
        self.assertEqual(
            2.0, process.communicate.call_args_list[1].kwargs["timeout"],
        )

        source = Path(__file__).read_text(encoding="utf-8")
        exact_cli = re.search(
            r"exact_cli\s*=\s*subprocess\.run\((.*?)\n\s*\)", source, re.S,
        )
        self.assertIsNotNone(exact_cli)
        self.assertRegex(exact_cli.group(1), r"\btimeout\s*=\s*10\b")

    def test_shell_communicate_interrupt_preserves_object_and_cleanup_bound(self) -> None:
        """Independent direct: interrupt, cleanup, then the SAME exception."""
        cause = ValueError("owned interruption cause")
        interruption = KeyboardInterrupt("owned interruption")
        interruption.__cause__ = cause
        process = mock.MagicMock()
        process.args = ["/bin/bash"]
        process.pid = 4242
        process.returncode = -signal.SIGKILL
        process.poll.return_value = None
        process.communicate.side_effect = (interruption, ("", ""))

        with mock.patch.object(
            subprocess, "Popen", return_value=process,
        ) as popen, mock.patch.object(os, "killpg") as killpg, \
                mock.patch.object(os, "getpgid", return_value=4242):
            with self.assertRaises(KeyboardInterrupt) as caught:
                run_shell("exit 91\n", timeout_seconds=0.25)

        self.assertIs(interruption, caught.exception)
        self.assertIs(cause, caught.exception.__cause__)
        self.assertEqual((), getattr(caught.exception, "_run_shell_cleanup_failures", None))
        popen.assert_called_once()
        self.assertEqual(["/bin/bash"], popen.call_args.args[0])
        self.assertIs(True, popen.call_args.kwargs["start_new_session"])
        self.assertEqual(2, process.communicate.call_count)
        self.assertEqual(
            {"input": "exit 91\n", "timeout": 0.25},
            process.communicate.call_args_list[0].kwargs,
        )
        self.assertEqual(
            {"timeout": 2.0}, process.communicate.call_args_list[1].kwargs,
        )
        killpg.assert_called_once_with(4242, signal.SIGKILL)

    def test_actual_owned_bash_communicate_interrupt_closes_before_return(self) -> None:
        """Actual helper -> one Bash; no input/body reaches the child."""
        cause = ValueError("owned Bash interruption cause")
        interruption = KeyboardInterrupt("owned Bash interruption")
        interruption.__cause__ = cause
        real_popen = subprocess.Popen
        real_getpgid = os.getpgid
        real_killpg = os.killpg
        owned = []
        calls = []
        cleanup_errors = []
        # Cleanup facts are not cleared/ignored to turn an unexpected fixture
        # failure into the intended behavioral RED. unittest reports them even
        # if a behavioral assertion below already failed.
        self.addCleanup(self.assertEqual, [], cleanup_errors)
        clean_environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": os.fspath(self.sandbox),
            "LANG": "C",
            "LC_ALL": "C",
        }

        def create_actual_owned_bash(*args, **kwargs):
            self.assertEqual((["/bin/bash"],), args)
            self.assertEqual(ROOT, kwargs["cwd"])
            self.assertIs(True, kwargs["start_new_session"])
            self.assertEqual(
                {**clean_environment, "PYTHONDONTWRITEBYTECODE": "1"},
                kwargs["env"],
            )
            for name in ("stdin", "stdout", "stderr"):
                self.assertEqual(subprocess.PIPE, kwargs[name])
            process = real_popen(*args, **kwargs)  # one real construction
            # Scope is explicitly POST-construction. A constructor that raises
            # before returning remains a separate unresolved startup case.
            original_communicate = process.communicate
            original_wait = process.wait
            streams = (process.stdin, process.stdout, process.stderr)
            owned.append((process, process.pid, original_communicate,
                          original_wait, streams))

            def interrupt_before_first_input(*call_args, **call_kwargs):
                calls.append((call_args, dict(call_kwargs)))
                if len(calls) == 1:
                    # Do not delegate or write stdin. Clean ENV excludes
                    # BASH_ENV/ENV; noninteractive Bash has no script to run.
                    raise interruption
                self.assertNotIn("input", call_kwargs)
                return original_communicate(*call_args, **call_kwargs)

            process.communicate = interrupt_before_first_input
            return process  # SAME actual Popen, not a substituted result

        try:
            with mock.patch.dict(os.environ, clean_environment, clear=True), \
                    mock.patch.object(subprocess, "Popen", side_effect=create_actual_owned_bash) as constructor:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    run_shell("exit 91\n", timeout_seconds=0.25)
            self.assertIs(interruption, caught.exception)
            self.assertIs(cause, caught.exception.__cause__)
            self.assertEqual((), getattr(caught.exception, "_run_shell_cleanup_failures", None))
            constructor.assert_called_once()
            self.assertEqual(1, len(owned))
            process, pid, original_communicate, original_wait, streams = owned[0]
            self.assertEqual(pid, process.pid)
            self.assertEqual(
                ((), {"input": "exit 91\n", "timeout": 0.25}), calls[0],
            )
            # This assertion is BEFORE this test's fallback. On the old helper
            # it is a genuine FAIL: the real child is still waiting for stdin.
            self.assertIsNotNone(process.poll())
            self.assertEqual(-signal.SIGKILL, process.returncode)
            self.assertEqual(2, len(calls))
            self.assertEqual(((), {"timeout": 2.0}), calls[1])
            self.assertTrue(all(stream.closed for stream in streams))
        finally:
            primary = sys.exc_info()[1]
            cleanup_interrupt = None
            for process, pid, original_communicate, original_wait, streams in owned:
                try:
                    if process.pid != pid or not getattr(process, "_child_created", False):
                        raise AssertionError("UNKNOWN original Popen ownership")
                    # No stale PID/group receipt is reused. Only this same
                    # original, unreaped leader with a fresh matching PGID may
                    # be signalled. No external PID scan and no descendants.
                    if process.poll() is None:
                        if real_getpgid(pid) != pid:
                            raise AssertionError("UNKNOWN original live process group")
                        real_killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # still attempt object-owned communicate/wait below
                except BaseException as error:
                    cleanup_errors.append(("owned-signal", type(error).__name__))
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
                try:
                    stdout, stderr = original_communicate(timeout=2.0)
                    if stdout != "" or stderr != "":
                        raise AssertionError("unexpected child output; no body may run")
                except BaseException as error:
                    cleanup_errors.append(("owned-communicate", type(error).__name__))
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
                for stream in streams:
                    try:
                        stream.close()  # captured original stream objects only
                    except BaseException as error:
                        cleanup_errors.append(("owned-stream-close", type(error).__name__))
                        if not isinstance(error, Exception) and cleanup_interrupt is None:
                            cleanup_interrupt = error
                try:
                    original_wait(timeout=2.0)
                except BaseException as error:
                    cleanup_errors.append(("owned-wait", type(error).__name__))
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
            # All cleanup attempts happen first. Original non-Exception wins;
            # a new cleanup NI wins only over an ordinary/no primary. Ordinary
            # cleanup errors remain independently reported by addCleanup.
            if cleanup_interrupt is not None and (
                primary is None or isinstance(primary, Exception)
            ):
                raise cleanup_interrupt

    def test_shell_interrupt_cleanup_errors_do_not_skip_owned_tail_or_replace_primary(self) -> None:
        cause = ValueError("primary owned interruption cause")
        interruption = KeyboardInterrupt("primary owned interruption")
        interruption.__cause__ = cause
        group_error = OSError("owned group kill")
        communicate_error = OSError("owned cleanup communicate")
        objectkill_error = OSError("owned object kill")
        stdin_error = OSError("owned stdin close")
        stdout_error = SystemExit("secondary cleanup interruption")
        wait_error = OSError("owned wait")
        events = []
        process = mock.MagicMock()
        process.args = ["/bin/bash"]
        process.pid = 4242
        process.poll.return_value = None

        def fail(label, error):
            def operation(*args, **kwargs):
                events.append(label)
                raise error
            return operation

        communication_count = 0

        def communicate(*args, **kwargs):
            nonlocal communication_count
            communication_count += 1
            events.append("communicate-primary" if communication_count == 1 else "communicate-cleanup")
            if communication_count == 1:
                raise interruption
            raise communicate_error

        process.communicate.side_effect = communicate
        process.kill.side_effect = fail("object-kill", objectkill_error)
        process.stdin.close.side_effect = fail("stdin-close", stdin_error)
        process.stdout.close.side_effect = fail("stdout-close", stdout_error)
        process.stderr.close.side_effect = lambda: events.append("stderr-close")
        process.wait.side_effect = fail("wait", wait_error)
        caught = None
        with mock.patch.object(subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(os, "killpg", side_effect=fail("group-kill", group_error)) as killpg, \
                mock.patch.object(os, "getpgid", return_value=4242):
            try:
                run_shell("exit 91\n", timeout_seconds=0.25)
            except BaseException as error:
                caught = error

        self.assertIs(interruption, caught)
        self.assertIs(cause, caught.__cause__)
        recorded = getattr(caught, "_run_shell_cleanup_failures", None)
        self.assertIs(tuple, type(recorded))
        expected = (
            ("group", group_error),
            ("communicate", communicate_error),
            ("objectkill", objectkill_error),
            ("stdin", stdin_error),
            ("stdout", stdout_error),
            ("wait", wait_error),
        )
        self.assertEqual(6, len(recorded))
        for actual_item, expected_item in zip(recorded, expected):
            self.assertIs(tuple, type(actual_item))
            self.assertEqual(2, len(actual_item))
            self.assertEqual(expected_item[0], actual_item[0])
            self.assertIs(expected_item[1], actual_item[1])
        popen.assert_called_once()
        killpg.assert_called_once_with(4242, signal.SIGKILL)
        self.assertEqual(
            [
                "communicate-primary", "group-kill", "communicate-cleanup",
                "object-kill", "stdin-close", "stdout-close", "stderr-close", "wait",
            ],
            events,
        )
        self.assertEqual(2, process.communicate.call_count)
        self.assertEqual(
            {"input": "exit 91\n", "timeout": 0.25},
            process.communicate.call_args_list[0].kwargs,
        )
        self.assertEqual({"timeout": 2.0}, process.communicate.call_args_list[1].kwargs)
        process.kill.assert_called_once_with()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=2.0)

    def test_shell_ordinary_error_cleanup_preserves_primary_or_first_cleanup_ni(self) -> None:
        for mode in ("clean", "cleanup-ni"):
            with self.subTest(mode=mode):
                primary_cause = ValueError("owned ordinary cause")
                primary = OSError(5, "owned primary communicate")
                primary.__cause__ = primary_cause
                cleanup_cause = ValueError("owned cleanup interruption cause")
                cleanup_ni = KeyboardInterrupt("first cleanup interruption")
                cleanup_ni.__cause__ = cleanup_cause
                group_error = OSError("owned group kill")
                objectkill_error = OSError("owned object kill")
                stdin_error = OSError("owned stdin close")
                stdout_error = SystemExit("later cleanup interruption")
                wait_error = OSError("owned wait")
                process = mock.MagicMock()
                process.args = ["/bin/bash"]
                process.pid = 4242
                process.poll.return_value = None
                process.communicate.side_effect = (
                    primary, ("", "") if mode == "clean" else cleanup_ni,
                )
                if mode == "cleanup-ni":
                    process.kill.side_effect = objectkill_error
                    process.stdin.close.side_effect = stdin_error
                    process.stdout.close.side_effect = stdout_error
                    process.wait.side_effect = wait_error
                caught = None
                with mock.patch.object(subprocess, "Popen", return_value=process) as constructor, \
                        mock.patch.object(os, "killpg", side_effect=None if mode == "clean" else group_error) as killpg, \
                        mock.patch.object(os, "getpgid", return_value=4242):
                    try:
                        run_shell("exit 91\n", timeout_seconds=0.25)
                    except BaseException as error:
                        caught = error
                constructor.assert_called_once()
                self.assertIs(primary_cause, primary.__cause__)
                if mode == "clean":
                    self.assertIs(primary, caught)
                    expected = ()
                    process.kill.assert_not_called()
                else:
                    self.assertIs(cleanup_ni, caught)
                    self.assertIs(cleanup_cause, caught.__cause__)
                    self.assertIs(primary, caught.__context__)
                    expected = (
                        ("group", group_error),
                        ("communicate", cleanup_ni),
                        ("objectkill", objectkill_error),
                        ("stdin", stdin_error),
                        ("stdout", stdout_error),
                        ("wait", wait_error),
                    )
                    process.kill.assert_called_once_with()
                recorded = getattr(primary, "_run_shell_cleanup_failures", None)
                self.assertIs(tuple, type(recorded))
                self.assertEqual(len(expected), len(recorded))
                for actual_item, expected_item in zip(recorded, expected):
                    self.assertIs(tuple, type(actual_item))
                    self.assertEqual(2, len(actual_item))
                    self.assertEqual(expected_item[0], actual_item[0])
                    self.assertIs(expected_item[1], actual_item[1])
                killpg.assert_called_once_with(4242, signal.SIGKILL)
                self.assertEqual(2, process.communicate.call_count)
                self.assertEqual(
                    {"input": "exit 91\n", "timeout": 0.25},
                    process.communicate.call_args_list[0].kwargs,
                )
                self.assertEqual({"timeout": 2.0}, process.communicate.call_args_list[1].kwargs)
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close.assert_called_once_with()
                process.wait.assert_called_once_with(timeout=2.0)

    def test_actual_owned_bash_ordinary_communicate_error_closes_before_return(self) -> None:
        """Actual helper/Bash, ordinary failure before any input reaches it."""
        cause = ValueError("owned ordinary Bash cause")
        primary = OSError(5, "owned Bash communicate")
        primary.__cause__ = cause
        real_popen = subprocess.Popen
        real_getpgid = os.getpgid
        real_killpg = os.killpg
        owned = []
        calls = []
        cleanup_errors = []
        self.addCleanup(self.assertEqual, [], cleanup_errors)
        clean_environment = {
            "PATH": "/usr/bin:/bin", "HOME": os.fspath(self.sandbox),
            "LANG": "C", "LC_ALL": "C",
        }

        def create_actual_owned_bash(*args, **kwargs):
            self.assertEqual((["/bin/bash"],), args)
            self.assertEqual(ROOT, kwargs["cwd"])
            self.assertIs(True, kwargs["start_new_session"])
            self.assertEqual(
                {**clean_environment, "PYTHONDONTWRITEBYTECODE": "1"}, kwargs["env"],
            )
            for name in ("stdin", "stdout", "stderr"):
                self.assertEqual(subprocess.PIPE, kwargs[name])
            process = real_popen(*args, **kwargs)
            original_communicate = process.communicate
            original_wait = process.wait
            streams = (process.stdin, process.stdout, process.stderr)
            owned.append((process, process.pid, original_communicate, original_wait, streams))

            def fail_before_first_input(*call_args, **call_kwargs):
                calls.append((call_args, dict(call_kwargs)))
                if len(calls) == 1:
                    raise primary  # no delegate and no stdin write
                self.assertNotIn("input", call_kwargs)
                return original_communicate(*call_args, **call_kwargs)

            process.communicate = fail_before_first_input
            return process  # SAME real Popen; construction must have succeeded

        try:
            with mock.patch.dict(os.environ, clean_environment, clear=True), \
                    mock.patch.object(subprocess, "Popen", side_effect=create_actual_owned_bash) as constructor:
                with self.assertRaises(OSError) as caught:
                    run_shell("exit 91\n", timeout_seconds=0.25)
            self.assertIs(primary, caught.exception)
            self.assertIs(cause, caught.exception.__cause__)
            constructor.assert_called_once()
            self.assertEqual(1, len(owned))
            process, pid, original_communicate, original_wait, streams = owned[0]
            self.assertEqual(pid, process.pid)
            self.assertEqual(((), {"input": "exit 91\n", "timeout": 0.25}), calls[0])
            # BEFORE test fallback: current NI-only helper genuinely fails here.
            self.assertIsNotNone(process.poll())
            self.assertEqual(-signal.SIGKILL, process.returncode)
            self.assertEqual((), getattr(primary, "_run_shell_cleanup_failures", None))
            self.assertEqual(2, len(calls))
            self.assertEqual(((), {"timeout": 2.0}), calls[1])
            self.assertTrue(all(stream.closed for stream in streams))
        finally:
            pending = sys.exc_info()[1]
            cleanup_interrupt = None
            for process, pid, original_communicate, original_wait, streams in owned:
                try:
                    if process.pid != pid or not getattr(process, "_child_created", False):
                        raise AssertionError("UNKNOWN original Popen ownership")
                    if process.poll() is None:
                        if real_getpgid(pid) != pid:
                            raise AssertionError("UNKNOWN original live process group")
                        real_killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    cleanup_errors.append(("owned-signal", type(error).__name__))
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
                try:
                    stdout, stderr = original_communicate(timeout=2.0)
                    if stdout != "" or stderr != "":
                        raise AssertionError("unexpected output; no body may run")
                except BaseException as error:
                    cleanup_errors.append(("owned-communicate", type(error).__name__))
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
                for stream in streams:
                    try:
                        stream.close()
                    except BaseException as error:
                        cleanup_errors.append(("owned-stream-close", type(error).__name__))
                        if not isinstance(error, Exception) and cleanup_interrupt is None:
                            cleanup_interrupt = error
                try:
                    original_wait(timeout=2.0)
                except BaseException as error:
                    cleanup_errors.append(("owned-wait", type(error).__name__))
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
            if cleanup_interrupt is not None and (
                pending is None or isinstance(pending, Exception)
            ):
                raise cleanup_interrupt

    def test_specialized_capture_harnesses_cannot_bypass_group_cleanup(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        direct_bash_runs = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if not (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
                and node.func.attr == "run"
                and node.args
                and isinstance(node.args[0], (ast.List, ast.Tuple))
                and node.args[0].elts
                and isinstance(node.args[0].elts[0], ast.Constant)
                and node.args[0].elts[0].value == "/bin/bash"
            ):
                continue
            if any(keyword.arg == "input" for keyword in node.keywords):
                direct_bash_runs.append(node.lineno)
        self.assertEqual([], direct_bash_runs)

    def test_recorded_test_holders_are_killed_and_reaped_by_a_local_deadline(
        self,
    ) -> None:
        pid_file = self.sandbox / "setsid-holder.pid"
        holder = subprocess.Popen(
            ["/bin/sleep", "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pid_file.write_text(str(holder.pid), encoding="ascii")
        try:
            cleanup_recorded_test_processes(pid_file)
            with self.assertRaises(ProcessLookupError):
                os.kill(holder.pid, 0)
            self.assertFalse(pid_file.exists())
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=2)

    def test_deadline_group_pid_evidence_is_atomically_published_before_timeout(
        self,
    ) -> None:
        source = Path(__file__).read_text(encoding="utf-8")
        match = re.search(
            r"def test_shell_decision_capture_deadline_kills_and_reaps_process_group"
            r"\(.*?(?=\n    def |\Z)",
            source,
            re.S,
        )
        self.assertIsNotNone(match)
        method = match.group(0)
        for required in (
            "os.open(",
            "os.fsync(",
            "os.replace(",
            "self.assertTrue(process_file.exists()",
            "self.assertEqual(2, len(process_ids))",
            "self.assertEqual(2, len(set(process_ids)))",
            "run_shell(harness, timeout_seconds=15)",
            "self.assertLess(elapsed, 12.0)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, method)

    def authority(self, label: str = "case") -> tuple[Path, Path, dict[str, object]]:
        boundary = self.sandbox / label
        parent = boundary / "var" / "lib"
        parent.mkdir(parents=True)
        boundary.chmod(0o700)
        (boundary / "var").chmod(0o755)
        parent.chmod(0o755)
        authority = parent / "http-ztp-monitor-auth"
        options = {
            "authority_boundary": boundary,
            "required_root_uid": self.uid,
            "required_root_gid": self.gid,
            "required_web_uid": self.uid,
            "required_web_gid": self.gid,
            "expected_helper_sha256": HELPER_SHA256,
        }
        bootstrap = dict(options)
        bootstrap.pop("expected_helper_sha256")
        CONTROL_AUTH.provision_monitor_authority(authority, **bootstrap)
        return boundary, authority, options

    @staticmethod
    def paths(authority: Path) -> tuple[Path, Path, Path]:
        lock = authority / "status.lock"
        cache_dir = authority / "monitor-auth"
        return lock, cache_dir, cache_dir / "factory-status.json"

    def install_payload(self, authority: Path, target: str, payload: bytes) -> Path:
        lock, _cache_dir, cache = self.paths(authority)
        selected = lock if target == "breaker" else cache
        selected.write_bytes(payload)
        selected.chmod(0o660 if target == "breaker" else 0o600)
        return selected

    def cgi_status(self, authority: Path, refresher=mock.DEFAULT):
        if refresher is mock.DEFAULT:
            refresher = mock.Mock(return_value=True)
        result = MONITOR_CGI._cached_control_auth_status(
            cache_root=authority,
            authority_boundary=authority.parents[2],
            cache_parent_uid=self.uid,
            cache_parent_gid=self.gid,
            cache_euid=self.uid,
            cache_egid=self.gid,
            expected_helper_sha256=HELPER_SHA256,
            refresher=refresher,
            semantic_api=CONTROL_AUTH,
        )
        return result, refresher

    def test_shared_helper_api_owns_the_exact_breaker_and_cache_grammar(self) -> None:
        required = (
            "MONITOR_AUTHORITY_BREAKER_SCHEMA",
            "MONITOR_AUTHORITY_CACHE_SCHEMA",
            "MONITOR_AUTHORITY_BREAKER_THRESHOLD",
            "parse_monitor_authority_breaker",
            "parse_monitor_authority_cache",
        )
        for name in required:
            with self.subTest(name=name):
                self.assertTrue(hasattr(CONTROL_AUTH, name), name)
        self.assertTrue(callable(MONITOR_CGI._load_control_auth_semantic_api))
        self.assertEqual(
            {"contaminant_dev": 7, "contaminant_ino": 11,
             "failure_count": 1, "schema_version": 1},
            CONTROL_AUTH.parse_monitor_authority_breaker(breaker_payload(1)),
        )
        self.assertTrue(
            CONTROL_AUTH.parse_monitor_authority_cache(
                cache_payload(True), expected_helper_sha256=HELPER_SHA256,
            )
        )

    def test_valid_empty_n1_n2_n3_and_cache_states_preserve_bytes_and_inodes(self) -> None:
        breaker_states = (b"", breaker_payload(1), breaker_payload(2), breaker_payload(3))
        cache_states = (None, cache_payload(True), cache_payload(False))
        for breaker in breaker_states:
            for cache_bytes in cache_states:
                label = f"valid-{len(breaker)}-{cache_bytes is not None}-{time.monotonic_ns()}"
                with self.subTest(breaker=breaker, cache=cache_bytes):
                    _boundary, authority, options = self.authority(label)
                    lock, _cache_dir, cache = self.paths(authority)
                    lock.write_bytes(breaker)
                    if cache_bytes is not None:
                        cache.write_bytes(cache_bytes)
                        cache.chmod(0o600)
                        old_ns = time.time_ns() - 10 * 60 * 1_000_000_000
                        os.utime(cache, ns=(old_ns, old_ns))
                    before_lock = (lock.read_bytes(), lock.stat().st_dev, lock.stat().st_ino)
                    before_cache = None if not cache.exists() else (
                        cache.read_bytes(), cache.stat().st_dev, cache.stat().st_ino,
                    )
                    before_metadata = {
                        path: leaf_snapshot(path)
                        for path in (authority, lock, lock.parent / "monitor-auth")
                    }
                    if cache.exists():
                        before_metadata[cache] = leaf_snapshot(cache)
                    CONTROL_AUTH.provision_monitor_authority(authority, **options)
                    CONTROL_AUTH.attest_monitor_authority(authority, **options)
                    self.assertEqual(
                        before_lock,
                        (lock.read_bytes(), lock.stat().st_dev, lock.stat().st_ino),
                    )
                    self.assertEqual(
                        before_cache,
                        None if not cache.exists() else (
                            cache.read_bytes(), cache.stat().st_dev, cache.stat().st_ino,
                        ),
                    )
                    self.assertEqual(
                        before_metadata,
                        {path: leaf_snapshot(path) for path in before_metadata},
                    )

    def test_routine_provision_never_repairs_existing_invalid_metadata(self) -> None:
        mutations = (
            ("root-mode", "root", 0o700),
            ("lock-mode", "lock", 0o600),
            ("cache-mode", "cache-dir", 0o755),
        )
        for index, (label, selected, mode) in enumerate(mutations):
            with self.subTest(case=label):
                _boundary, authority, options = self.authority(f"metadata-{index}")
                lock, cache_dir, _cache = self.paths(authority)
                target = {
                    "root": authority,
                    "lock": lock,
                    "cache-dir": cache_dir,
                }[selected]
                target.chmod(mode)
                before = {
                    path: leaf_snapshot(path)
                    for path in (authority, lock, cache_dir)
                }
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.provision_monitor_authority(authority, **options)
                self.assertEqual(
                    before,
                    {path: leaf_snapshot(path) for path in before},
                    "routine provision modified an existing unsafe object",
                )

    def test_all_ten_metadata_perfect_bad_payloads_fail_provision_attest_and_cgi(self) -> None:
        self.assertEqual(10, len(BAD_PAYLOADS))
        for index, (label, (target, payload)) in enumerate(BAD_PAYLOADS.items()):
            with self.subTest(case=label):
                _boundary, authority, options = self.authority(f"bad-{index}")
                selected = self.install_payload(authority, target, payload)
                before = (selected.read_bytes(), selected.stat().st_dev, selected.stat().st_ino)
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.provision_monitor_authority(authority, **options)
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.attest_monitor_authority(authority, **options)
                self.assertEqual(
                    before,
                    (selected.read_bytes(), selected.stat().st_dev, selected.stat().st_ino),
                )
                refresher = mock.Mock(
                    side_effect=AssertionError("semantic-invalid CGI spawned helper")
                )
                with self.assertRaises(MONITOR_CGI.ControlAuthStatusError) as raised:
                    self.cgi_status(authority, refresher)
                self.assertEqual("cache-authority", raised.exception.category)
                refresher.assert_not_called()

    def test_noncanonical_payload_and_every_crash_candidate_fail_read_only(self) -> None:
        _boundary, authority, options = self.authority("noncanonical")
        lock, cache_dir, _cache = self.paths(authority)
        noncanonical = (
            b'{"schema_version": 1, "contaminant_dev": 7, '
            b'"contaminant_ino": 11, "failure_count": 1}\n'
        )
        lock.write_bytes(noncanonical)
        with self.assertRaises(CONTROL_AUTH.ControlAuthError):
            CONTROL_AUTH.attest_monitor_authority(authority, **options)
        lock.write_bytes(breaker_payload(3))
        candidate = cache_dir / (".factory-status." + "a" * 32 + ".tmp")
        candidate.write_bytes(cache_payload(True))
        candidate.chmod(0o600)
        with self.assertRaises(CONTROL_AUTH.ControlAuthError):
            CONTROL_AUTH.attest_monitor_authority(authority, **options)

    def test_explicit_recovery_repairs_only_invalid_content_and_is_retryable(self) -> None:
        _boundary, authority, options = self.authority("recover")
        lock, cache_dir, cache = self.paths(authority)
        lock.write_bytes(b'{"schema_version":1')
        cache.write_bytes(b"")
        cache.chmod(0o600)
        stale = cache_dir / (".factory-status." + "b" * 32 + ".tmp")
        stale.write_bytes(b"incomplete")
        stale.chmod(0o600)
        errors = io.StringIO()
        with redirect_stderr(errors):
            CONTROL_AUTH.recover_monitor_authority(authority, **options)
        self.assertEqual(b"", lock.read_bytes())
        self.assertFalse(cache.exists())
        self.assertEqual([], list(cache_dir.iterdir()))
        CONTROL_AUTH.attest_monitor_authority(authority, **options)
        self.assertEqual(
            CONTROL_AUTH.MONITOR_AUTHORITY_RECOVERY_WARNING + "\n",
            errors.getvalue(),
        )

        for checkpoint in CONTROL_AUTH.MONITOR_AUTHORITY_RECOVERY_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint):
                lock.write_bytes(b'{"schema_version":1')
                cache.write_bytes(b"")
                cache.chmod(0o600)

                def fail_here(name):
                    if name == checkpoint:
                        raise OSError("injected recovery interruption")

                with mock.patch.object(
                    CONTROL_AUTH, "_monitor_recovery_checkpoint", side_effect=fail_here,
                ), self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.recover_monitor_authority(authority, **options)
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.attest_monitor_authority(authority, **options)
                CONTROL_AUTH.recover_monitor_authority(authority, **options)
                CONTROL_AUTH.attest_monitor_authority(authority, **options)

    def test_post_commit_fault_is_success_or_leaves_non_attestable_marker(self) -> None:
        _boundary, authority, options = self.authority("post-commit-double-fault")
        lock, _cache_dir, cache = self.paths(authority)
        lock.write_bytes(b'{"schema_version":1')
        cache.write_bytes(b"")
        cache.chmod(0o600)
        real_create = CONTROL_AUTH._create_monitor_recovery_marker
        creates = 0

        def create_once(*args, **kwargs):
            nonlocal creates
            creates += 1
            if creates > 1:
                raise OSError("injected re-marker failure")
            return real_create(*args, **kwargs)

        def fail_after_marker_remove(name):
            if name == "marker-remove":
                raise OSError("injected post-commit failure")

        failed = False
        with mock.patch.object(
            CONTROL_AUTH, "_create_monitor_recovery_marker", side_effect=create_once,
        ), mock.patch.object(
            CONTROL_AUTH, "_monitor_recovery_checkpoint",
            side_effect=fail_after_marker_remove,
        ), redirect_stderr(io.StringIO()):
            try:
                CONTROL_AUTH.recover_monitor_authority(authority, **options)
            except CONTROL_AUTH.ControlAuthError:
                failed = True
        if failed:
            with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                CONTROL_AUTH.attest_monitor_authority(authority, **options)
        else:
            CONTROL_AUTH.attest_monitor_authority(authority, **options)

    def test_recovery_marker_shared_grammar_has_two_exact_canonical_phases(self) -> None:
        phases = (
            "recovery-in-progress",
            "recovery-committed-cleanup-pending",
        )
        for phase in phases:
            with self.subTest(phase=phase):
                data = CONTROL_AUTH.build_monitor_authority_recovery_marker(phase)
                self.assertEqual(
                    {"phase": phase, "schema_version": 1},
                    CONTROL_AUTH.parse_monitor_authority_recovery_marker(data),
                )
                self.assertEqual(
                    data,
                    canonical({"phase": phase, "schema_version": 1}),
                )
        for invalid in (
            b"", b'{"phase":"recovery-in-progress","schema_version":1}',
            canonical({"phase": "unknown", "schema_version": 1}),
            canonical({
                "extra": False, "phase": "recovery-in-progress",
                "schema_version": 1,
            }),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                CONTROL_AUTH.ControlAuthError,
            ):
                CONTROL_AUTH.parse_monitor_authority_recovery_marker(invalid)

    def test_post_commit_marker_cleanup_four_by_two_matrix(self) -> None:
        original_unlink = os.unlink
        expected = {
            ("fail-before", "succeed"): ("marker-retained", False, True),
            ("fail-before", "fail"): ("marker-retained", False, True),
            ("succeed", "succeed"): ("complete", True, False),
            ("succeed", "fail"): (
                "marker-removal-durability-unknown", True, False,
            ),
            ("unlink-then-raise", "succeed"): ("complete", True, False),
            ("unlink-then-raise", "fail"): (
                "marker-removal-durability-unknown", True, False,
            ),
            ("wrong-slot", "succeed"): (
                "marker-authority-uncertain", False, True,
            ),
            ("wrong-slot", "fail"): (
                "marker-authority-uncertain", False, True,
            ),
        }
        self.assertEqual(8, len(expected))
        for index, ((unlink_mode, fsync_mode), outcome) in enumerate(expected.items()):
            cleanup, restart_allowed, marker_present = outcome
            with self.subTest(unlink=unlink_mode, fsync=fsync_mode):
                _boundary, authority, options = self.authority(f"matrix-{index}")
                lock, cache_dir, cache = self.paths(authority)
                lock.write_bytes(b'{"schema_version":1')
                cache.write_bytes(b"")
                cache.chmod(0o600)
                marker_creations = 0
                real_create = CONTROL_AUTH._create_monitor_recovery_marker

                def count_create(*args, **kwargs):
                    nonlocal marker_creations
                    marker_creations += 1
                    return real_create(*args, **kwargs)

                def unlink_marker(directory_descriptor, name):
                    if unlink_mode == "fail-before":
                        raise OSError("injected fail-before unlink")
                    original_unlink(name, dir_fd=directory_descriptor)
                    if unlink_mode == "unlink-then-raise":
                        raise OSError("injected unlink-then-raise")
                    if unlink_mode == "wrong-slot":
                        replacement = os.open(
                            name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=directory_descriptor,
                        )
                        os.write(replacement, b"wrong-slot\n")
                        os.close(replacement)
                        raise OSError("injected wrong canonical slot")

                def fsync_parent(directory_descriptor):
                    if fsync_mode == "fail":
                        raise OSError("injected marker-parent fsync failure")
                    os.fsync(directory_descriptor)

                warnings = io.StringIO()
                with mock.patch.object(
                    CONTROL_AUTH, "_create_monitor_recovery_marker",
                    side_effect=count_create,
                ), mock.patch.object(
                    CONTROL_AUTH, "_monitor_marker_unlink",
                    side_effect=unlink_marker,
                ), mock.patch.object(
                    CONTROL_AUTH, "_monitor_marker_parent_fsync",
                    side_effect=fsync_parent,
                ), redirect_stderr(warnings):
                    result = CONTROL_AUTH.recover_monitor_authority(
                        authority, **options,
                    )
                self.assertEqual(
                    {
                        "cleanup": cleanup,
                        "recovery_committed": True,
                        "restart_allowed": restart_allowed,
                    },
                    result,
                )
                self.assertEqual(1, marker_creations, "speculative re-marker write")
                self.assertEqual(b"", lock.read_bytes())
                self.assertFalse(cache.exists())
                candidates = list(cache_dir.iterdir())
                self.assertEqual(marker_present, bool(candidates))
                if cleanup == "marker-retained":
                    self.assertEqual(1, len(candidates))
                    self.assertEqual(
                        "recovery-committed-cleanup-pending",
                        CONTROL_AUTH.parse_monitor_authority_recovery_marker(
                            candidates[0].read_bytes(),
                        )["phase"],
                    )
                if cleanup == "marker-removal-durability-unknown":
                    self.assertIn("stale", warnings.getvalue().casefold())
                    self.assertNotIn(cache_payload(True).decode().strip(), warnings.getvalue())

    def test_every_marker_phase_transition_fault_remains_routine_blocking(
        self,
    ) -> None:
        checkpoints = (
            "marker-committed-truncate",
            "marker-committed-write",
            "marker-committed-fsync",
            "marker-committed-rebind",
            "marker-committed-directory-fsync",
            "marker-committed-attest",
        )
        self.assertTrue(
            set(checkpoints).issubset(
                set(CONTROL_AUTH.MONITOR_AUTHORITY_RECOVERY_CHECKPOINTS)
            )
        )
        for index, checkpoint in enumerate(checkpoints):
            with self.subTest(checkpoint=checkpoint):
                _boundary, authority, options = self.authority(
                    f"phase-fault-{index}"
                )
                lock, _cache_dir, cache = self.paths(authority)
                lock.write_bytes(b'{"schema_version":1')
                cache.write_bytes(b"")
                cache.chmod(0o600)

                def fail_here(name):
                    if name == checkpoint:
                        raise OSError("injected marker phase interruption")

                with mock.patch.object(
                    CONTROL_AUTH, "_monitor_recovery_checkpoint",
                    side_effect=fail_here,
                ), redirect_stderr(io.StringIO()), self.assertRaises(
                    CONTROL_AUTH.ControlAuthError,
                ):
                    CONTROL_AUTH.recover_monitor_authority(authority, **options)
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.attest_monitor_authority(authority, **options)

    def test_resurrected_completed_marker_has_distinct_machine_classification(
        self,
    ) -> None:
        _boundary, authority, options = self.authority("resurrected")
        lock, cache_dir, cache = self.paths(authority)
        lock.write_bytes(b'{"schema_version":1')
        cache.write_bytes(b"")
        cache.chmod(0o600)
        captured: dict[str, object] = {}
        original_unlink = os.unlink

        def unlink_then_capture(directory_descriptor, name):
            captured["name"] = name
            captured["data"] = (cache_dir / name).read_bytes()
            original_unlink(name, dir_fd=directory_descriptor)

        with mock.patch.object(
            CONTROL_AUTH, "_monitor_marker_unlink", side_effect=unlink_then_capture,
        ), mock.patch.object(
            CONTROL_AUTH, "_monitor_marker_parent_fsync",
            side_effect=OSError("injected cleanup durability failure"),
        ), redirect_stderr(io.StringIO()):
            result = CONTROL_AUTH.recover_monitor_authority(authority, **options)
        self.assertEqual(
            {
                "cleanup": "marker-removal-durability-unknown",
                "recovery_committed": True,
                "restart_allowed": True,
            },
            result,
        )
        resurrected = cache_dir / str(captured["name"])
        resurrected.write_bytes(captured["data"])
        resurrected.chmod(0o600)
        with self.assertRaises(CONTROL_AUTH.MonitorAuthorityMarkerError) as raised:
            CONTROL_AUTH.attest_monitor_authority(authority, **options)
        self.assertEqual(
            "recovery-committed-cleanup-pending", raised.exception.classification,
        )
        refresher = mock.Mock(side_effect=AssertionError("resurrection spawned helper"))
        with self.assertRaises(MONITOR_CGI.ControlAuthStatusError) as cgi_error:
            self.cgi_status(authority, refresher)
        self.assertEqual(
            "recovery-committed-cleanup-pending", cgi_error.exception.category,
        )
        refresher.assert_not_called()
        with redirect_stderr(io.StringIO()):
            retried = CONTROL_AUTH.recover_monitor_authority(authority, **options)
        self.assertTrue(retried["restart_allowed"])
        self.assertEqual("complete", retried["cleanup"])
        CONTROL_AUTH.attest_monitor_authority(authority, **options)

    def test_docker_read_only_adapter_reports_both_marker_phases_exactly(self) -> None:
        activate = load_python(
            "monitor_authority_r4_activate", ROOT / "infra/docker/activate.py",
        )
        expected = {
            "recovery-in-progress": (
                "not been committed",
                "sudo ./infra/docker/deploy.sh recover-monitor-authority",
            ),
            "recovery-committed-cleanup-pending": (
                "COMPLETED",
                "sudo ./infra/docker/deploy.sh recover-monitor-authority",
            ),
        }
        for classification, fragments in expected.items():
            with self.subTest(classification=classification):
                runner = mock.Mock(return_value=SimpleNamespace(
                    returncode=4,
                    stdout=(json.dumps(
                        {"classification": classification, "valid": False},
                        sort_keys=True, separators=(",", ":"),
                    ) + "\n"),
                    stderr="bounded helper diagnostic\n",
                ))
                with self.assertRaises(
                    activate.MonitorAuthorityError,
                ) as raised:
                    activate.require_monitor_authority(runner=runner)
                self.assertEqual(classification, raised.exception.classification)
                for fragment in fragments:
                    self.assertIn(fragment, str(raised.exception))
                if classification == "recovery-committed-cleanup-pending":
                    self.assertIn(
                        "repaired authority itself is not in question",
                        str(raised.exception),
                    )

        malformed = mock.Mock(return_value=SimpleNamespace(
            returncode=4,
            stdout=(
                '{"classification":"recovery-committed-cleanup-pending",'
                '"valid":false,"extra":false}\n'
            ),
            stderr="bounded\n",
        ))
        with self.assertRaises(activate.ActivationError) as raised:
            activate.require_monitor_authority(runner=malformed)
        self.assertNotIsInstance(raised.exception, activate.MonitorAuthorityError)

    def test_real_docker_entrypoint_activate_health_and_hostctl_share_semantics(
        self,
    ) -> None:
        _boundary, authority, options = self.authority("docker-real-callers")
        _lock, cache_dir, _cache = self.paths(authority)
        marker = cache_dir / (".factory-status." + "d" * 32 + ".tmp")
        marker.write_bytes(CONTROL_AUTH.build_monitor_authority_recovery_marker(
            "recovery-committed-cleanup-pending"
        ))
        marker.chmod(0o600)

        timeline: list[str] = []

        def semantic_runner(_command, **_kwargs):
            timeline.append("monitor-authority")
            try:
                CONTROL_AUTH.attest_monitor_authority(authority, **options)
            except CONTROL_AUTH.MonitorAuthorityMarkerError as exc:
                return SimpleNamespace(
                    returncode=4,
                    stdout=(json.dumps(
                        {"classification": exc.classification, "valid": False},
                        sort_keys=True, separators=(",", ":"),
                    ) + "\n"),
                    stderr="bounded helper diagnostic\n",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        entrypoint = load_python(
            "monitor_authority_r4_entrypoint", ROOT / "infra/docker/entrypoint.py",
        )
        settings = SimpleNamespace(http_root=self.sandbox)

        @contextmanager
        def held(*_args, **_kwargs):
            yield 17

        after_authority = mock.Mock(side_effect=AssertionError(
            "entrypoint continued after completed marker"
        ))
        with mock.patch.object(
            entrypoint.activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            entrypoint.hostlock, "safe_lock", side_effect=held,
        ), mock.patch.object(
            entrypoint.activate, "validate_python_runtime",
            side_effect=lambda: timeline.append("runtime-gate"),
        ), mock.patch.object(
            entrypoint.activate, "verify_control_auth_image_copies",
        ), mock.patch.object(
            entrypoint.activate.subprocess, "run", side_effect=semantic_runner,
        ), mock.patch.object(
            entrypoint.activate, "require_control_auth", after_authority,
        ):
            self.assertEqual(2, entrypoint.main([]))
        self.assertEqual(["runtime-gate", "monitor-authority"], timeline)
        after_authority.assert_not_called()

        activate = entrypoint.activate
        timeline.clear()
        with mock.patch.object(
            activate.subprocess, "run", side_effect=semantic_runner,
        ), mock.patch.object(
            activate, "observe_runtime", side_effect=AssertionError(
                "service observed runtime after completed marker"
            ),
        ), self.assertRaises(activate.MonitorAuthorityError):
            activate.exec_managed_service("apache2", settings)
        self.assertEqual(["monitor-authority"], timeline)

        healthcheck = load_python(
            "monitor_authority_r4_health", ROOT / "infra/docker/healthcheck.py",
        )
        timeline.clear()
        with mock.patch.object(
            healthcheck.activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            healthcheck.activate, "validate_python_runtime",
            side_effect=lambda: timeline.append("runtime-gate"),
        ), mock.patch.object(
            healthcheck.activate.subprocess, "run", side_effect=semantic_runner,
        ), mock.patch.object(
            healthcheck.activate, "validate_image_source_contract",
            side_effect=AssertionError("health continued after completed marker"),
        ), self.assertRaises(healthcheck.activate.MonitorAuthorityError):
            healthcheck.check_runtime()
        self.assertEqual(["runtime-gate", "monitor-authority"], timeline)

        hostctl = load_python(
            "monitor_authority_r4_hostctl", ROOT / "infra/docker/hostctl.py",
        )
        stops: list[str] = []
        with mock.patch.object(
            hostctl.activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            hostctl.activate.subprocess, "run", side_effect=semantic_runner,
        ), mock.patch.object(
            hostctl.activate, "require_control_auth", return_value={"valid": True},
        ), mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, lambda _root: held(), None),
        ), mock.patch.object(
            hostctl, "stop_managed_services", side_effect=lambda: stops.append("stop"),
        ), mock.patch.object(hostctl, "write_resume_status"):
            self.assertEqual(2, hostctl.main(["resume"]))
        self.assertEqual(["stop"], stops)

        for operation in (
            hostctl.transactional_load,
            hostctl.transactional_reload_network,
        ):
            stops.clear()
            clears: list[str] = []
            with self.subTest(operation=operation.__name__), mock.patch.object(
                hostctl.activate.subprocess, "run", side_effect=semantic_runner,
            ), mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(
                    hostctl.hostlock.HostLockError,
                    lambda _root: held(),
                    lambda _fd: {},
                ),
            ), mock.patch.object(
                hostctl.activate, "clear_activation",
                side_effect=lambda _settings: clears.append("clear"),
            ), mock.patch.object(
                hostctl, "stop_managed_services",
                side_effect=lambda: stops.append("stop"),
            ), self.assertRaises(hostctl.activate.MonitorAuthorityError):
                operation(settings)
            self.assertEqual(["clear"], clears)
            self.assertEqual(["stop"], stops)

        quarantines: list[str] = []
        with mock.patch.object(
            hostctl.activate.subprocess, "run", side_effect=semantic_runner,
        ), mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(
                hostctl.hostlock.HostLockError, lambda _root: held(), None,
            ),
        ), mock.patch.object(
            hostctl, "clear_guardian_fault_best_effort", return_value=None,
        ), mock.patch.object(
            hostctl, "quarantine_inactive_locked",
            side_effect=lambda _settings, reason: quarantines.append(reason),
        ):
            state = hostctl.guardian_step(
                settings, hostctl.GUARDIAN_INITIAL_STATE,
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        self.assertEqual(1, len(quarantines))
        self.assertIn("recovery-committed-cleanup-pending", quarantines[0])

    def test_real_entrypoint_semantics_block_ten_bad_payloads_and_enable_cgi(
        self,
    ) -> None:
        entrypoint = load_python(
            "monitor_authority_r4_entrypoint_payloads",
            ROOT / "infra/docker/entrypoint.py",
        )

        @contextmanager
        def held(*_args, **_kwargs):
            yield 17

        def runner_for(authority, options, timeline):
            def semantic_runner(_command, **_kwargs):
                timeline.append("monitor-authority")
                try:
                    CONTROL_AUTH.attest_monitor_authority(authority, **options)
                except CONTROL_AUTH.MonitorAuthorityMarkerError as exc:
                    return SimpleNamespace(
                        returncode=4,
                        stdout=(json.dumps(
                            {"classification": exc.classification, "valid": False},
                            sort_keys=True, separators=(",", ":"),
                        ) + "\n"),
                        stderr="bounded helper diagnostic\n",
                    )
                except CONTROL_AUTH.ControlAuthError:
                    return SimpleNamespace(returncode=1, stdout="", stderr="invalid\n")
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return semantic_runner

        settings = SimpleNamespace(http_root=self.sandbox)
        for index, (label, (target, payload)) in enumerate(BAD_PAYLOADS.items()):
            with self.subTest(label=label):
                _boundary, authority, options = self.authority(f"service-bad-{index}")
                self.install_payload(authority, target, payload)
                timeline: list[str] = []
                after_semantic = mock.Mock(side_effect=AssertionError(
                    "entrypoint continued after semantic-invalid authority"
                ))
                with mock.patch.object(
                    entrypoint.activate.Settings, "from_environment",
                    return_value=settings,
                ), mock.patch.object(
                    entrypoint.hostlock, "safe_lock", side_effect=held,
                ), mock.patch.object(
                    entrypoint.activate, "validate_python_runtime",
                    side_effect=lambda: timeline.append("runtime-gate"),
                ), mock.patch.object(
                    entrypoint.activate, "verify_control_auth_image_copies",
                ), mock.patch.object(
                    entrypoint.activate.subprocess, "run",
                    side_effect=runner_for(authority, options, timeline),
                ), mock.patch.object(
                    entrypoint.activate, "require_control_auth", after_semantic,
                ), mock.patch.object(
                    entrypoint.activate, "validate_image_source_contract",
                    after_semantic,
                ), mock.patch.object(
                    entrypoint.activate, "ensure_runtime_directories",
                    after_semantic,
                ), mock.patch.object(
                    entrypoint.os, "execv", after_semantic,
                ), redirect_stderr(io.StringIO()):
                    self.assertEqual(2, entrypoint.main([]))
                self.assertEqual(["runtime-gate", "monitor-authority"], timeline)
                after_semantic.assert_not_called()

        _boundary, authority, options = self.authority("service-valid")
        events: list[str] = []
        with mock.patch.object(
            entrypoint.activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            entrypoint.hostlock, "safe_lock", side_effect=held,
        ), mock.patch.object(
            entrypoint.activate, "validate_python_runtime",
            side_effect=lambda: events.append("runtime-gate"),
        ), mock.patch.object(
            entrypoint.activate, "verify_control_auth_image_copies",
        ), mock.patch.object(
            entrypoint.activate.subprocess, "run",
            side_effect=runner_for(authority, options, events),
        ), mock.patch.object(
            entrypoint.activate, "require_control_auth",
            side_effect=lambda **_kwargs: events.append("control-auth"),
        ), mock.patch.object(
            entrypoint.activate, "validate_image_source_contract",
            side_effect=lambda *_args, **_kwargs: events.append("image-source"),
        ), mock.patch.object(
            entrypoint.activate, "restore_mutable_image_sources",
        ), mock.patch.object(
            entrypoint.activate, "ensure_runtime_directories",
            side_effect=lambda *_args, **_kwargs: events.append("runtime-init"),
        ), mock.patch.object(
            entrypoint.activate, "ensure_docker_deployment_owner",
        ), mock.patch.object(
            entrypoint.activate, "clear_precommit_activation",
        ), mock.patch.object(
            entrypoint.activate, "clear_stale_worker_pid_files",
        ), mock.patch.object(
            entrypoint, "initialize_resume_status",
        ), mock.patch.object(
            entrypoint.os, "execv", side_effect=lambda *_args: events.append("exec"),
        ):
            self.assertEqual(0, entrypoint.main([]))
        self.assertEqual(
            [
                "runtime-gate", "monitor-authority", "control-auth",
                "image-source", "image-source", "runtime-init", "exec",
            ],
            events,
        )
        self.assertTrue(self.cgi_status(authority)[0])

    def test_native_load_read_only_adapter_uses_backend_specific_recovery_command(
        self,
    ) -> None:
        loader = load_python(
            "monitor_authority_r4_load", ROOT / "DAY0-Prepare/11-load.py",
        )
        payload = b"same-helper\n"
        for backend, command in (
            ("systemd", NATIVE_RECOVERY_COMMAND),
            ("supervisor", "sudo ./infra/docker/deploy.sh recover-monitor-authority"),
        ):
            with self.subTest(backend=backend), mock.patch.object(
                loader, "_verified_control_auth_payload", return_value=payload,
            ), mock.patch.object(
                loader, "_run_subprocess", return_value=SimpleNamespace(
                    returncode=4,
                    stdout=(
                        '{"classification":"recovery-committed-cleanup-pending",'
                        '"valid":false}\n'
                    ),
                    stderr="bounded helper diagnostic\n",
                ),
            ):
                with self.assertRaises(loader.LoadError) as raised:
                    loader.verify_monitor_authority(
                        runtime_backend=SimpleNamespace(name=backend),
                    )
                self.assertIn("COMPLETED", str(raised.exception))
                self.assertIn(
                    "repaired authority itself is not in question",
                    str(raised.exception),
                )
                self.assertIn(command, str(raised.exception))

    def test_shared_semantic_api_builds_every_cgi_persisted_payload(self) -> None:
        for name in (
            "build_monitor_authority_breaker", "build_monitor_authority_cache",
        ):
            with self.subTest(api=name):
                self.assertTrue(callable(getattr(CONTROL_AUTH, name, None)))

        _boundary, authority, options = self.authority("shared-serializer")
        with mock.patch.object(
            MONITOR_CGI, "_cache_payload",
            return_value=cache_payload(True)[:-2] + b',"extra":false}\n',
            create=True,
        ):
            self.assertTrue(self.cgi_status(authority, mock.Mock(return_value=True))[0])
        CONTROL_AUTH.attest_monitor_authority(authority, **options)

        lock, _cache_dir, _cache = self.paths(authority)
        descriptor = os.open(lock, os.O_RDWR)
        try:
            with mock.patch.object(
                MONITOR_CGI, "_cache_breaker_payload", return_value=b"invalid\n",
                create=True,
            ):
                MONITOR_CGI._write_cache_breaker(
                    descriptor,
                    {
                        "schema_version": 1,
                        "contaminant_dev": 7,
                        "contaminant_ino": 11,
                        "failure_count": 3,
                    },
                    required_uid=self.uid,
                    required_gid=self.gid,
                    semantic_api=CONTROL_AUTH,
                )
        finally:
            os.close(descriptor)
        self.assertEqual(
            3,
            CONTROL_AUTH.parse_monitor_authority_breaker(lock.read_bytes())[
                "failure_count"
            ],
        )

    def test_lifecycle_success_implies_the_same_real_cgi_request_succeeds(self) -> None:
        _boundary, authority, options = self.authority("positive-workflow")
        CONTROL_AUTH.attest_monitor_authority(authority, **options)
        self.assertTrue(self.cgi_status(authority)[0])

        environment = {
            "REQUEST_METHOD": "GET",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/ztp-monitor",
        }
        response = mock.Mock()
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            MONITOR_CGI, "control_auth_status",
            side_effect=lambda: self.cgi_status(authority)[0],
        ), mock.patch.object(
            MONITOR_CGI, "process_state", return_value=(False, None),
        ), mock.patch.object(MONITOR_CGI, "respond", response):
            MONITOR_CGI.main()
        response.assert_called_once()
        self.assertNotEqual(
            "503 Service Unavailable",
            response.call_args.kwargs.get("status", "200 OK")
            if response.call_args.kwargs else (
                response.call_args.args[1]
                if len(response.call_args.args) > 1 else "200 OK"
            ),
        )

    def test_docker_exact_listener_authority_reaches_all_three_real_cgis(
        self,
    ) -> None:
        activate = load_python(
            "monitor_origin_c01_docker", ROOT / "infra/docker/activate.py",
        )
        endpoints = (
            load_python(
                "monitor_origin_c01_manual",
                ROOT / "monitor/manual-ztp-control.cgi",
            ),
            load_python(
                "monitor_origin_c01_switch",
                ROOT / "monitor/switch-collection-control.cgi",
            ),
            load_python(
                "monitor_origin_c01_ztp",
                ROOT / "monitor/ztp-monitor-control.cgi",
            ),
        )
        expected_addresses = ("192.0.2.40", "198.51.100.20")
        listener_config = activate.render_apache_listener_config(expected_addresses)
        self.assertEqual(
            [f"Listen {address}:80" for address in expected_addresses],
            [line for line in listener_config.splitlines() if line.startswith("Listen ")],
        )
        self.assertEqual(
            [f"<VirtualHost {address}:80>" for address in expected_addresses],
            [
                line for line in listener_config.splitlines()
                if line.startswith("<VirtualHost ")
            ],
        )
        for forbidden in (
            "Listen 80", "Listen 0.0.0.0:80", "Listen [::]:80",
            "<VirtualHost *:80>", "<VirtualHost *:443>", ":443>",
        ):
            self.assertNotIn(forbidden, listener_config)
        for invalid_address in (
            "0.0.0.0", "224.0.0.1", "255.255.255.255",
        ):
            with self.subTest(invalid_address=invalid_address):
                with self.assertRaises(activate.ActivationError):
                    activate.render_apache_listener_config((invalid_address,))

        for endpoint in endpoints:
            for address in expected_addresses:
                valid = {
                    "SERVER_ADDR": address,
                    "SERVER_PORT": "80",
                    "REQUEST_SCHEME": "http",
                    "HTTPS": "off",
                    "HTTP_HOST": f"{address}:80",
                    "HTTP_ORIGIN": f"http://{address}",
                    "HTTP_SEC_FETCH_SITE": "same-origin",
                }
                with self.subTest(endpoint=endpoint.__name__, address=address), \
                        mock.patch.dict(os.environ, valid, clear=True):
                    self.assertEqual((True, ""), endpoint.post_control_guard())
                with self.subTest(
                    endpoint=endpoint.__name__, address=address,
                    case="SERVER_ADDR is not the selected listener",
                ), mock.patch.dict(
                    os.environ, {**valid, "SERVER_ADDR": "203.0.113.9"}, clear=True,
                ):
                    self.assertFalse(endpoint.post_control_guard()[0])

    def test_native_real_service_ips_render_one_exact_nonwildcard_listener_file(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_render", ROOT / "DAY0-Prepare/11-load.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            subnet = Path(temporary) / "02-dhcp-subnet_config.csv"
            subnet.write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "air,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
                "192.0.2.1,192.0.2.40,oob,no\n"
                "prod,198.51.100.0,255.255.255.0,198.51.100.100,"
                "198.51.100.120,198.51.100.1,198.51.100.20,oobofoob,yes\n",
                encoding="utf-8",
            )
            derived = loader.derive_service_ips_from_subnet(subnet, "/ztp")
            boot_ips = loader.derive_boot_ips_from_subnet(subnet, "/ztp")
        settings = loader.GlobalSettings(
            dhcp_enabled=True,
            dhcp_package="isc-dhcp-server",
            http_enabled=True,
            http_package="apache2",
            http_root=ROOT,
            ztp_enabled=True,
            ztp_prefix="/ztp",
            ztp_ips=derived,
            versions={},
            boot_ips=boot_ips,
        )
        self.assertEqual(
            ("192.0.2.40", "198.51.100.20"), settings.service_ips,
        )
        self.assertEqual(
            Path("/etc/apache2/conf-enabled/http-ztp-listeners.conf"),
            getattr(loader, "NATIVE_APACHE_LISTENER_CONF", None),
        )
        renderer = getattr(loader, "render_native_apache_listener_config", None)
        self.assertTrue(callable(renderer), "11-load lacks the Native listener renderer")
        rendered = renderer(settings.service_ips)
        expected = (
            "# Generated by DAY0-Prepare/11-load.py; do not edit.\n"
            "# Exact service-IP listeners only; wildcard binds are forbidden.\n"
            "Listen 192.0.2.40:80\n"
            "Listen 198.51.100.20:80\n"
            "\n"
            "<VirtualHost 192.0.2.40:80>\n"
            "    ServerName 192.0.2.40\n"
            "    DocumentRoot /var/www/html\n"
            "    ErrorLog /var/log/apache2/error.log\n"
            "    CustomLog /var/log/apache2/access.log combined\n"
            "</VirtualHost>\n"
            "\n"
            "<VirtualHost 198.51.100.20:80>\n"
            "    ServerName 198.51.100.20\n"
            "    DocumentRoot /var/www/html\n"
            "    ErrorLog /var/log/apache2/error.log\n"
            "    CustomLog /var/log/apache2/access.log combined\n"
            "</VirtualHost>\n"
        )
        self.assertEqual(expected, rendered)
        for invalid_address in (
            "0.0.0.0", "224.0.0.1", "255.255.255.255",
        ):
            with self.subTest(invalid_address=invalid_address):
                with self.assertRaises(loader.LoadError):
                    renderer((invalid_address,))

    def test_native_listener_publication_is_atomic_and_rolls_back_configtest(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_publish", ROOT / "DAY0-Prepare/11-load.py",
        )
        publisher = getattr(loader, "publish_native_apache_listener_config", None)
        self.assertTrue(callable(publisher), "11-load lacks atomic listener publication")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subnet = root / "02-dhcp-subnet_config.csv"
            subnet.write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "air,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
                "192.0.2.1,192.0.2.40,oob,no\n",
                encoding="utf-8",
            )
            derived = loader.derive_service_ips_from_subnet(subnet, "/ztp")
            settings = loader.GlobalSettings(
                dhcp_enabled=True,
                dhcp_package="isc-dhcp-server",
                http_enabled=True,
                http_package="apache2",
                http_root=ROOT,
                ztp_enabled=True,
                ztp_prefix="/ztp",
                ztp_ips=derived,
                versions={},
            )
            self.assertEqual(("192.0.2.40",), settings.service_ips)
            destination = root / "http-ztp-listeners.conf"
            original = b"Listen 192.0.2.9:80\n"
            replacement = (
                b"# Generated by DAY0-Prepare/11-load.py; do not edit.\n"
                b"# Exact service-IP listeners only; wildcard binds are forbidden.\n"
                b"Listen 192.0.2.40:80\n\n"
                b"<VirtualHost 192.0.2.40:80>\n"
                b"    ServerName 192.0.2.40\n"
                b"    DocumentRoot /var/www/html\n"
                b"    ErrorLog /var/log/apache2/error.log\n"
                b"    CustomLog /var/log/apache2/access.log combined\n"
                b"</VirtualHost>\n"
            )
            destination.write_bytes(original)
            destination.chmod(0o644)
            commands = []
            replacements = []
            real_replace = loader.os.replace

            def configtest(command):
                commands.append(tuple(command))
                self.assertEqual(replacement, destination.read_bytes())
                raise loader.LoadError("injected apache configtest failure")

            def observed_replace(source, target):
                replacements.append((Path(source), Path(target)))
                return real_replace(source, target)

            with mock.patch.object(loader.os, "replace", side_effect=observed_replace):
                with self.assertRaisesRegex(
                    loader.LoadError, "injected apache configtest failure",
                ):
                    publisher(
                        settings.service_ips, destination=destination,
                        command_runner=configtest,
                    )
            self.assertEqual(original, destination.read_bytes())
            self.assertEqual(0o644, stat.S_IMODE(destination.stat().st_mode))
            self.assertEqual(
                [tuple(loader.sudo_command("apache2ctl", "configtest"))], commands,
            )
            self.assertGreaterEqual(len(replacements), 2)
            self.assertTrue(all(target == destination for _source, target in replacements))
            self.assertEqual([], list(root.glob(".http-ztp-listeners.conf.*")))

            commands.clear()
            replacements.clear()

            def successful_configtest(command):
                commands.append(tuple(command))
                self.assertEqual(replacement, destination.read_bytes())

            with mock.patch.object(loader.os, "replace", side_effect=observed_replace):
                publisher(
                    settings.service_ips, destination=destination,
                    command_runner=successful_configtest,
                )
            self.assertEqual(replacement, destination.read_bytes())
            self.assertEqual(0o644, stat.S_IMODE(destination.stat().st_mode))
            self.assertEqual(
                [tuple(loader.sudo_command("apache2ctl", "configtest"))], commands,
            )
            self.assertGreaterEqual(len(replacements), 1)
            self.assertTrue(all(target == destination for _source, target in replacements))
            self.assertEqual([], list(root.glob(".http-ztp-listeners.conf.*")))

        main_tree = ast.parse(
            (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8"),
        )
        main = next(
            node for node in main_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "main"
        )
        publish_calls = []
        preflight_calls = []
        for node in ast.walk(main):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "publish_native_apache_listener_config":
                publish_calls.append(node)
            elif node.func.id == "preflight_services":
                preflight_calls.append(node)
        self.assertEqual(1, len(publish_calls))
        self.assertTrue(preflight_calls)
        self.assertLess(publish_calls[0].lineno, min(call.lineno for call in preflight_calls))
        self.assertEqual(1, len(publish_calls[0].args))
        self.assertEqual(
            "inputs.settings.http_listener_ips",
            ast.unparse(publish_calls[0].args[0]),
        )

    def test_native_listener_late_directory_fsync_failure_restores_prior_state(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_late_fsync",
            ROOT / "DAY0-Prepare/11-load.py",
        )
        publisher = loader.publish_native_apache_listener_config
        original = b"Listen 192.0.2.9:80\n"
        for prior_exists in (True, False):
            with self.subTest(prior_exists=prior_exists), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                destination = root / "http-ztp-listeners.conf"
                prior_metadata = None
                if prior_exists:
                    destination.write_bytes(original)
                    destination.chmod(0o640)
                    prior_metadata = destination.stat()
                directory_fsyncs = []
                configtests = []

                def successful_configtest(command):
                    configtests.append(tuple(command))

                def fail_after_successful_configtest(path):
                    directory_fsyncs.append(Path(path))
                    if len(directory_fsyncs) == 2:
                        self.assertEqual(
                            [tuple(loader.sudo_command("apache2ctl", "configtest"))],
                            configtests,
                            "late fsync injection preceded successful configtest",
                        )
                        self.assertEqual(
                            [], list(root.glob(f".{destination.name}.*.rollback")),
                            "late fsync was injected before rollback-name cleanup",
                        )
                        raise OSError("injected late directory fsync failure")

                with mock.patch.object(
                    loader, "_fsync_parent_directory",
                    side_effect=fail_after_successful_configtest,
                ):
                    with self.assertRaisesRegex(
                        OSError, "injected late directory fsync failure",
                    ):
                        publisher(
                            ("192.0.2.40",), destination=destination,
                            command_runner=successful_configtest,
                        )

                self.assertGreaterEqual(len(directory_fsyncs), 2)
                self.assertTrue(all(path == root for path in directory_fsyncs))
                if prior_exists:
                    self.assertEqual(original, destination.read_bytes())
                    restored = destination.stat()
                    self.assertEqual(0o640, stat.S_IMODE(restored.st_mode))
                    self.assertEqual(1, restored.st_nlink)
                    self.assertEqual(
                        (
                            prior_metadata.st_dev, prior_metadata.st_ino,
                            prior_metadata.st_uid, prior_metadata.st_gid,
                        ),
                        (
                            restored.st_dev, restored.st_ino,
                            restored.st_uid, restored.st_gid,
                        ),
                    )
                else:
                    self.assertFalse(os.path.lexists(destination))
                self.assertEqual(
                    [], list(root.glob(f".{destination.name}.*")),
                    "late durability failure left a candidate or rollback name",
                )

    def test_native_listener_candidate_metadata_is_durable_before_publication(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_metadata_fsync",
            ROOT / "DAY0-Prepare/11-load.py",
        )
        real_fchmod = loader.os.fchmod
        real_fchown = getattr(loader.os, "fchown", None)
        real_fsync = loader.os.fsync
        real_replace = loader.os.replace
        events = []

        def observed_fchmod(descriptor, mode):
            events.append("metadata")
            return real_fchmod(descriptor, mode)

        def observed_fchown(descriptor, uid, gid):
            events.append("metadata")
            return real_fchown(descriptor, uid, gid)

        def observed_fsync(descriptor):
            kind = "data-fsync" if stat.S_ISREG(os.fstat(descriptor).st_mode) \
                else "directory-fsync"
            events.append(kind)
            return real_fsync(descriptor)

        def observed_replace(source, target):
            events.append("publish")
            return real_replace(source, target)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "http-ztp-listeners.conf"
            destination.write_bytes(b"Listen 192.0.2.9:80\n")
            patches = [
                mock.patch.object(loader.os, "fchmod", side_effect=observed_fchmod),
                mock.patch.object(loader.os, "fsync", side_effect=observed_fsync),
                mock.patch.object(loader.os, "replace", side_effect=observed_replace),
            ]
            if real_fchown is not None:
                patches.append(mock.patch.object(
                    loader.os, "fchown", side_effect=observed_fchown,
                ))
            with ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                loader.publish_native_apache_listener_config(
                    ("192.0.2.40",), destination=destination,
                    command_runner=lambda _command: None,
                )

        metadata_indexes = [
            index for index, event in enumerate(events) if event == "metadata"
        ]
        data_fsync_indexes = [
            index for index, event in enumerate(events) if event == "data-fsync"
        ]
        self.assertTrue(metadata_indexes, events)
        self.assertTrue(data_fsync_indexes, events)
        publish_index = events.index("publish")
        self.assertLess(max(metadata_indexes), max(data_fsync_indexes), events)
        self.assertLess(max(data_fsync_indexes), publish_index, events)

    def test_native_listener_success_durably_removes_recovery_authority(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_cleanup_durable",
            ROOT / "DAY0-Prepare/11-load.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "http-ztp-listeners.conf"
            destination.write_bytes(b"Listen 192.0.2.9:80\n")
            directory_fsyncs = []
            recovery_presence = []

            def observe_directory_fsync(path):
                directory_fsyncs.append(Path(path))
                recovery_presence.append(bool(list(
                    root.glob(f".{destination.name}.*.recovery")
                )))

            with mock.patch.object(
                loader, "_fsync_parent_directory",
                side_effect=observe_directory_fsync,
            ):
                loader.publish_native_apache_listener_config(
                    ("192.0.2.40",), destination=destination,
                    command_runner=lambda _command: None,
                )

            self.assertEqual([root, root, root], directory_fsyncs)
            self.assertEqual([False, True, False], recovery_presence)
            self.assertEqual([], list(root.glob(f".{destination.name}.*")))

    def test_native_listener_cleanup_fsync_failure_reports_committed_state(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_cleanup_fsync_failure",
            ROOT / "DAY0-Prepare/11-load.py",
        )
        replacement = (
            b"# Generated by DAY0-Prepare/11-load.py; do not edit.\n"
            b"# Exact service-IP listeners only; wildcard binds are forbidden.\n"
            b"Listen 192.0.2.40:80\n\n"
            b"<VirtualHost 192.0.2.40:80>\n"
            b"    ServerName 192.0.2.40\n"
            b"    DocumentRoot /var/www/html\n"
            b"    ErrorLog /var/log/apache2/error.log\n"
            b"    CustomLog /var/log/apache2/access.log combined\n"
            b"</VirtualHost>\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "http-ztp-listeners.conf"
            destination.write_bytes(b"Listen 192.0.2.9:80\n")
            prior_inode = destination.stat().st_ino
            directory_fsyncs = []
            configtests = []

            def fail_cleanup_fsync(path):
                directory_fsyncs.append(Path(path))
                if len(directory_fsyncs) == 3:
                    self.assertEqual(
                        [], list(root.glob(f".{destination.name}.*")),
                        "cleanup fsync was injected before recovery unlink",
                    )
                    raise OSError("injected cleanup directory fsync failure")

            def successful_configtest(command):
                configtests.append(tuple(command))

            with mock.patch.object(
                loader, "_fsync_parent_directory", side_effect=fail_cleanup_fsync,
            ):
                with self.assertRaisesRegex(
                    loader.LoadError,
                    "新配置已提交.*cleanup durability unknown",
                ):
                    loader.publish_native_apache_listener_config(
                        ("192.0.2.40",), destination=destination,
                        command_runner=successful_configtest,
                    )

            self.assertEqual([root, root, root], directory_fsyncs)
            self.assertEqual(
                [tuple(loader.sudo_command("apache2ctl", "configtest"))],
                configtests,
            )
            self.assertEqual(replacement, destination.read_bytes())
            self.assertNotEqual(prior_inode, destination.stat().st_ino)
            self.assertEqual(1, destination.stat().st_nlink)
            self.assertEqual([], list(root.glob(f".{destination.name}.*")))

    def test_native_listener_preexisting_rollback_or_recovery_fails_closed(
        self,
    ) -> None:
        loader = load_python(
            "monitor_origin_c01_native_stale_recovery",
            ROOT / "DAY0-Prepare/11-load.py",
        )
        cases = [
            ("single rollback regular", (("a" * 32, "rollback", "regular"),)),
            ("single recovery regular", (("b" * 32, "recovery", "regular"),)),
            ("multiple same family", (
                ("c" * 32, "rollback", "regular"),
                ("d" * 32, "rollback", "regular"),
            )),
            ("mixed families", (
                ("e" * 32, "rollback", "regular"),
                ("f" * 32, "recovery", "regular"),
            )),
            ("unknown tokens", (
                ("operator-rollback", "rollback", "regular"),
                ("operator-recovery", "recovery", "regular"),
            )),
            ("symlink", (("1" * 32, "rollback", "symlink"),)),
            ("directory", (("2" * 32, "recovery", "directory"),)),
        ]
        if hasattr(os, "mkfifo"):
            cases.append(("fifo", (("3" * 32, "rollback", "fifo"),)))
        for label, recovery_specs in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                destination = root / "http-ztp-listeners.conf"
                destination.write_bytes(b"Listen 192.0.2.9:80\n")
                target = root / "operator-evidence"
                target.write_bytes(b"do not modify\n")
                recoveries = []
                for token, family, kind in recovery_specs:
                    recovery = root / f".{destination.name}.{token}.{family}"
                    if kind == "symlink":
                        recovery.symlink_to(target.name)
                    elif kind == "directory":
                        recovery.mkdir()
                    elif kind == "fifo":
                        os.mkfifo(recovery)
                    else:
                        recovery.write_bytes(f"stale {token}\n".encode("ascii"))
                    recoveries.append(recovery)

                watched = [destination, target, *recoveries]

                def snapshot(path):
                    metadata = path.lstat()
                    if stat.S_ISLNK(metadata.st_mode):
                        content = os.readlink(path)
                    elif stat.S_ISREG(metadata.st_mode):
                        content = path.read_bytes()
                    else:
                        content = None
                    return (
                        metadata.st_dev, metadata.st_ino, metadata.st_mode,
                        metadata.st_nlink, metadata.st_uid, metadata.st_gid,
                        metadata.st_size, metadata.st_mtime_ns, content,
                    )

                before = {path: snapshot(path) for path in watched}
                expected_names = sorted(path.name for path in recoveries)
                with mock.patch.object(
                    loader.tempfile, "mkstemp",
                    side_effect=AssertionError("candidate created before stale gate"),
                ):
                    with self.assertRaises(loader.LoadError) as raised:
                        loader.publish_native_apache_listener_config(
                            ("192.0.2.40",), destination=destination,
                            command_runner=lambda _command: (_ for _ in ()).throw(
                                AssertionError("configtest reached before stale gate")
                            ),
                        )

                expected_message = (
                    "Apache listener 存在滞留 rollback/recovery authority；"
                    "请停止 Apache 并人工处理后重试："
                    + ", ".join(expected_names)
                )
                self.assertEqual(expected_message, str(raised.exception))
                self.assertEqual(before, {path: snapshot(path) for path in watched})
                self.assertEqual(
                    expected_names,
                    sorted(
                        path.name
                        for suffix in ("rollback", "recovery")
                        for path in root.glob(f".{destination.name}.*.{suffix}")
                    ),
                )

    def test_native_setup_removes_default_wildcard_http_and_https_listeners(
        self,
    ) -> None:
        setup = (ROOT / "infra/infra-setup.sh").read_text(encoding="utf-8")
        teardown = (ROOT / "infra/infra-teardown.sh").read_text(encoding="utf-8")
        self.assertNotIn("<VirtualHost *:443>", setup)
        self.assertNotRegex(setup, r"(?m)^\s*Listen\s+(?:80|443|\*:80|\*:443)\s*$")
        self.assertIn("track_managed_file /etc/apache2/ports.conf", setup)
        self.assertRegex(setup, r"\ba2dissite\b[^\n]*\b000-default\b")
        self.assertIn("http-ztp-listeners.conf", setup)
        configure_at = setup.index('info "Configuring apache2..."')
        setup_gate = setup.index("apache2ctl configtest", configure_at)
        self.assertLess(setup.index("a2dissite", configure_at), setup_gate)
        self.assertLess(setup.index("/etc/apache2/ports.conf", configure_at), setup_gate)
        for managed in (
            "/etc/apache2/ports.conf",
            "/etc/apache2/sites-enabled/000-default.conf",
            "/etc/apache2/conf-enabled/http-ztp-listeners.conf",
        ):
            with self.subTest(teardown_managed=managed):
                self.assertIn(managed, teardown)

    def test_python_setup_removes_default_wildcard_http_and_https_listeners(
        self,
    ) -> None:
        setup = INFRA_SETUP_PATH.read_text(encoding="utf-8")
        teardown = (ROOT / "infra/infra-teardown.sh").read_text(encoding="utf-8")
        self.assertNotIn("<VirtualHost *:443>", setup)
        self.assertNotRegex(setup, r"(?m)^\s*Listen\s+(?:80|443|\*:80|\*:443)\s*$")
        self.assertNotRegex(INFRA_SETUP.APACHE_PORTS_CONTENT, r"(?m)^\s*Listen\b")
        self.assertIn("self.track_managed_file(APACHE_PORTS_CONF)", setup)
        self.assertRegex(setup, r"\ba2dissite\b[^\n]*\b000-default\b")
        self.assertEqual(
            "/etc/apache2/conf-enabled/http-ztp-listeners.conf", INFRA_SETUP.APACHE_LISTENER_CONF,
        )
        configure_at = setup.index('self.info("Configuring apache2...")')
        setup_gate = setup.index('"apache2ctl", "configtest"', configure_at)
        self.assertLess(setup.index("a2dissite", configure_at), setup_gate)
        self.assertLess(setup.index("APACHE_PORTS_CONF", configure_at), setup_gate)
        self.assertLess(setup.index("os.unlink(listener)", configure_at), setup_gate)
        for managed in (
            "/etc/apache2/ports.conf",
            "/etc/apache2/sites-enabled/000-default.conf",
            "/etc/apache2/conf-enabled/http-ztp-listeners.conf",
        ):
            with self.subTest(teardown_managed=managed):
                self.assertIn(managed, teardown)

    def test_real_environment_registers_exact_listener_proof_as_not_run(
        self,
    ) -> None:
        registry = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        heading = (
            "## TC-REAL-MONITOR-ORIGIN-001 — exact service-IP Origin authority"
        )
        self.assertIn(heading, registry)
        section = registry.split(heading, 1)[1].split("\n## ", 1)[0]
        for required in (
            "Native/systemd",
            "Docker/Supervisor",
            "apache2ctl -S",
            "ss -ltnp",
            "SERVER_ADDR",
            "SERVER_PORT",
            "REQUEST_SCHEME",
            "HTTP_HOST",
            "HTTP_ORIGIN",
            "0.0.0.0",
            "[::]",
            ":443",
            "Status: OPEN / NOT RUN",
            "自动化 fixture 不得冒充真实 Apache/端口证据",
        ):
            with self.subTest(required=required):
                self.assertIn(required, section)

    def test_docker_host_recovery_is_one_stop_then_repair_transaction(self) -> None:
        hostlock = load_python("monitor_authority_r4_hostlock", ROOT / "infra/docker/hostlock.py")
        events: list[str] = []

        @contextmanager
        def held(_path, _wait):
            events.append("outer-lock-enter")
            try:
                yield 17
            finally:
                events.append("outer-lock-exit")

        class AuthorityModule:
            _CONTROL_AUTH_SOURCE_SHA256 = HELPER_SHA256

            @staticmethod
            def validate_auth_file(*_args, **_kwargs):
                events.append("credential-validate")

            @staticmethod
            def status_auth_file(*_args, **_kwargs):
                events.append("credential-status")
                return {"valid": True, "factory_records_active": False}

            @staticmethod
            def recover_monitor_authority(*_args, **_kwargs):
                events.append("authority-recover")
                return {
                    "cleanup": "complete",
                    "recovery_committed": True,
                    "restart_allowed": True,
                }

            @staticmethod
            def attest_monitor_authority(*_args, **_kwargs):
                events.append("authority-attest")

            @staticmethod
            def monitor_authority_recovery_decision(payload, diagnostics):
                return CONTROL_AUTH.monitor_authority_recovery_decision(
                    payload, diagnostics,
                )

        with mock.patch.object(hostlock, "safe_lock", side_effect=held), mock.patch.object(
            hostlock, "_stop_remove_owned_container_locked",
            side_effect=lambda **_kwargs: events.append("stop-remove"),
        ), mock.patch.object(
            hostlock, "clear_activation_marker",
            side_effect=lambda _path: events.append("clear-activation"),
        ), mock.patch.object(
            hostlock, "_load_control_auth",
            side_effect=lambda: events.append("helper-load") or AuthorityModule,
        ):
            result = hostlock.recover_monitor_authority_transaction(
                lock_path=self.sandbox / ".deployment.lock",
                runner=mock.Mock(return_value=SimpleNamespace(returncode=0)),
            )
        self.assertEqual(
            {
                "cleanup": "complete",
                "recovery_committed": True,
                "restart_allowed": True,
            },
            result,
        )
        self.assertEqual(
            ["outer-lock-enter", "stop-remove", "clear-activation", "helper-load",
             "credential-validate", "credential-status", "authority-recover",
             "authority-attest", "outer-lock-exit"],
            events,
        )
        events.clear()
        with mock.patch.object(hostlock, "safe_lock", side_effect=held), mock.patch.object(
            hostlock, "_stop_remove_owned_container_locked",
            side_effect=lambda **_kwargs: events.append("stop-remove"),
        ), mock.patch.object(
            hostlock, "clear_activation_marker",
            side_effect=lambda _path: events.append("clear-activation"),
        ), mock.patch.object(
            hostlock, "_load_control_auth", return_value=AuthorityModule,
        ):
            decision = hostlock.recover_monitor_authority_transaction(
                lock_path=self.sandbox / ".deployment.lock",
                runner=mock.Mock(return_value=SimpleNamespace(returncode=0)),
                decision=True,
            )
        self.assertEqual(
            "restart-allowed:complete;reset-invalid-cache=false", decision,
        )
        self.assertEqual(1, events.count("authority-recover"))
        self.assertEqual(1, events.count("authority-attest"))
        parser = hostlock.parser()
        option_strings = {
            option for action in parser._actions for option in action.option_strings
        }
        self.assertIn("--recover-monitor-authority", option_strings)
        self.assertIn("--recover-monitor-authority-decision", option_strings)

    def test_native_recovery_executes_stop_attest_start_and_never_repairs_a_live_writer(
        self,
    ) -> None:
        setup = ROOT / "infra/infra-setup.sh"
        recovery = (
            shell_function(setup, "monitor_authority_result_directory")
            + decision_capture_shell(setup)
            + shell_function(setup, "run_native_monitor_authority_routine")
            + shell_function(setup, "recover_monitor_authority_action")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source-helper"
            installed = root / "installed-helper"
            event_log = root / "events"
            helper_script = (
                "#!/bin/bash\n"
                "printf 'helper:%s\\n' \"$1\" >> \"$EVENT_LOG\"\n"
                "if [[ \"${HELPER_FAILURE:-}\" == \"$1\" ]]; then exit 1; fi\n"
                "case \"$1\" in\n"
                "  monitor-authority-recover-decision)\n"
                "    printf '%s' \"${RECOVERY_DECISION:-restart-allowed:complete;reset-invalid-cache=false}\"\n"
                "    exit \"${DECISION_RC:-0}\" ;;\n"
                "  monitor-authority-attest-decision|monitor-authority-provision-decision)\n"
                "    printf '%s' attest-valid ;;\n"
                "esac\n"
            )
            source.write_text(helper_script, encoding="utf-8")
            installed.write_text(helper_script, encoding="utf-8")
            source.chmod(0o755)
            installed.chmod(0o755)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()

            harness = recovery + f'''
exec 3>/dev/null
control_auth_source={shlex.quote(os.fspath(source))}
control_auth_helper={shlex.quote(os.fspath(installed))}
control_auth_source_sha256={digest}
EVENT_LOG={shlex.quote(os.fspath(event_log))}
export EVENT_LOG HELPER_FAILURE RECOVERY_DECISION DECISION_RC
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(os.fspath(root))}; }}
systemd_is_operational() {{ [[ "${{SYSTEMD_OK:-1}}" == 1 ]]; }}
stat() {{ printf '1\\n'; }}
sha256sum() {{ printf '%s  %s\\n' {digest} "$1"; }}
systemctl() {{
  printf 'systemctl:%s\\n' "$*" >> "$EVENT_LOG"
  case "$1" in
    show)
      if [[ -e "$EVENT_LOG.started" ]]; then
        printf '%s\\n' "${{AFTER_START_STATE:-active}}"
      elif [[ -e "$EVENT_LOG.stopped" ]]; then
        printf '%s\\n' "${{AFTER_STOP_STATE:-inactive}}"
      else
        printf '%s\\n' "${{INITIAL_STATE:-active}}"
      fi
      ;;
    stop) : > "$EVENT_LOG.stopped"; return "${{STOP_RC:-0}}" ;;
    start) : > "$EVENT_LOG.started"; return "${{START_RC:-0}}" ;;
    *) return 90 ;;
  esac
}}
recover_monitor_authority_action
'''

            negative_cases = (
                ("no-systemd", {"SYSTEMD_OK": "0"}),
                ("stop-failed", {"STOP_RC": "1"}),
                ("still-active", {"AFTER_STOP_STATE": "active"}),
            )
            for label, variables in negative_cases:
                with self.subTest(case=label), mock.patch.dict(
                    os.environ, variables, clear=False,
                ):
                    event_log.unlink(missing_ok=True)
                    Path(os.fspath(event_log) + ".stopped").unlink(missing_ok=True)
                    Path(os.fspath(event_log) + ".started").unlink(missing_ok=True)
                    result = run_shell(harness)
                    self.assertNotEqual(0, result.returncode)
                    events = event_log.read_text(encoding="utf-8").splitlines() \
                        if event_log.exists() else []
                    self.assertFalse(
                        any(event.startswith("helper:") for event in events),
                        events,
                    )

            event_log.unlink(missing_ok=True)
            Path(os.fspath(event_log) + ".stopped").unlink(missing_ok=True)
            Path(os.fspath(event_log) + ".started").unlink(missing_ok=True)
            result = run_shell(harness)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                [
                    "systemctl:show --property=ActiveState --value apache2",
                    "systemctl:stop apache2",
                    "systemctl:show --property=ActiveState --value apache2",
                    "helper:validate",
                    "helper:monitor-authority-recover-decision",
                    "helper:monitor-authority-attest-decision",
                    "systemctl:start apache2",
                    "systemctl:show --property=ActiveState --value apache2",
                ],
                event_log.read_text(encoding="utf-8").splitlines(),
            )

            blocked_results = (
                ("restart-blocked:marker-retained;reset-invalid-cache=false", "0"),
                ("restart-blocked:marker-authority-uncertain;reset-invalid-cache=true", "0"),
                ("restart-allowed", "0"),
                ("restart-allowed:complete;reset-invalid-cache=false", "7"),
            )
            for recovery_decision, decision_rc in blocked_results:
                with self.subTest(recovery_decision=recovery_decision), mock.patch.dict(
                    os.environ,
                    {"RECOVERY_DECISION": recovery_decision, "DECISION_RC": decision_rc},
                    clear=False,
                ):
                    event_log.unlink(missing_ok=True)
                    Path(os.fspath(event_log) + ".stopped").unlink(missing_ok=True)
                    Path(os.fspath(event_log) + ".started").unlink(missing_ok=True)
                    result = run_shell(harness)
                    self.assertNotEqual(0, result.returncode)
                    events = event_log.read_text(encoding="utf-8").splitlines()
                    self.assertIn("helper:monitor-authority-recover-decision", events)
                    self.assertNotIn("helper:monitor-authority-attest-decision", events)
                    self.assertNotIn("systemctl:start apache2", events)

        exact_cli = subprocess.run(
            ["/bin/bash", os.fspath(setup), "--recover-monitor-authority", "--client"],
            cwd=ROOT, text=True, capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(2, exact_cli.returncode)
        self.assertIn("--recover-monitor-authority must be the only option", exact_cli.stderr)

    def test_python_native_recovery_executes_stop_attest_start_and_never_repairs_a_live_writer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source-helper"
            installed = root / INFRA_SETUP.CONTROL_AUTH_HELPER.lstrip("/")
            installed.parent.mkdir(parents=True)
            (root / "run").mkdir()
            event_log = root / "events"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            helper_script = (
                "#!/bin/bash\n"
                "printf 'helper:%s\\n' \"$1\" >> \"$EVENT_LOG\"\n"
                "if [[ \"${HELPER_FAILURE:-}\" == \"$1\" ]]; then exit 1; fi\n"
                "case \"$1\" in\n"
                "  monitor-authority-recover-decision)\n"
                "    printf '%s' \"${RECOVERY_DECISION:-restart-allowed:complete;reset-invalid-cache=false}\"\n"
                "    exit \"${DECISION_RC:-0}\" ;;\n"
                "  monitor-authority-attest-decision|monitor-authority-provision-decision)\n"
                "    printf '%s' attest-valid ;;\n"
                "esac\n"
            )
            source.write_text(helper_script, encoding="utf-8")
            installed.write_text(helper_script, encoding="utf-8")
            source.chmod(0o755)
            installed.chmod(0o755)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            systemctl = fake_bin / "systemctl"
            systemctl.write_text(
                "#!/bin/bash\n"
                "printf 'systemctl:%s\\n' \"$*\" >> \"$EVENT_LOG\"\n"
                "case \"$1\" in\n"
                "  show)\n"
                "    if [[ -e \"$EVENT_LOG.started\" ]]; then printf '%s\\n' \"${AFTER_START_STATE:-active}\"\n"
                "    elif [[ -e \"$EVENT_LOG.stopped\" ]]; then printf '%s\\n' \"${AFTER_STOP_STATE:-inactive}\"\n"
                "    else printf '%s\\n' \"${INITIAL_STATE:-active}\"; fi ;;\n"
                "  stop) : > \"$EVENT_LOG.stopped\"; exit \"${STOP_RC:-0}\" ;;\n"
                "  start) : > \"$EVENT_LOG.started\"; exit \"${START_RC:-0}\" ;;\n"
                "  *) exit 90 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            systemctl.chmod(0o755)

            def recover(variables, *argv):
                for suffix in ("", ".stopped", ".started"):
                    Path(os.fspath(event_log) + suffix).unlink(missing_ok=True)
                systemd_dir = root / "run/systemd/system"
                if variables.get("SYSTEMD_OK", "1") == "1":
                    systemd_dir.mkdir(parents=True, exist_ok=True)
                elif systemd_dir.exists():
                    systemd_dir.rmdir()
                environment = {
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
                    "EVENT_LOG": os.fspath(event_log),
                    **variables,
                }
                setup = python_native_setup(root, *argv)
                setup.control_auth_source = source
                stderr = io.StringIO()
                with mock.patch.dict(os.environ, environment, clear=False), \
                        mock.patch.object(INFRA_SETUP, "HOST_ROOT", root), \
                        mock.patch.object(INFRA_SETUP, "CONTROL_AUTH_SOURCE_SHA256", digest), \
                        redirect_stderr(stderr):
                    code = setup.recover_monitor_authority()
                events = event_log.read_text(encoding="utf-8").splitlines() \
                    if event_log.exists() else []
                return code == 0, events, stderr.getvalue(), code

            for label, variables in (
                ("no-systemd", {"SYSTEMD_OK": "0"}),
                ("stop-failed", {"STOP_RC": "1"}),
                ("still-active", {"AFTER_STOP_STATE": "active"}),
            ):
                with self.subTest(case=label):
                    accepted, events, _stderr, _code = recover(variables)
                    self.assertFalse(accepted)
                    self.assertFalse(
                        any(event.startswith("helper:") for event in events), events,
                    )

            accepted, events, stderr, _code = recover({})
            self.assertTrue(accepted, stderr)
            self.assertEqual(
                [
                    "systemctl:show --property=ActiveState --value apache2",
                    "systemctl:stop apache2",
                    "systemctl:show --property=ActiveState --value apache2",
                    "helper:validate",
                    "helper:monitor-authority-recover-decision",
                    "helper:monitor-authority-attest-decision",
                    "systemctl:start apache2",
                    "systemctl:show --property=ActiveState --value apache2",
                ],
                events,
            )
            self.assertEqual(
                "[WARN] Apache stopped for explicit Monitor cache authority recovery.\n"
                "[OK] explicit Monitor cache authority recovery completed.\n",
                stderr,
            )

            # Without --apply the recovery only verifies its prerequisites read-only and asks for --apply.
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                accepted, events, stderr, code = recover({}, "--recover-monitor-authority")
            self.assertEqual((False, 3), (accepted, code))  # 3: check mode found a pending change
            self.assertEqual(["systemctl:show --property=ActiveState --value apache2", "helper:validate"], events)
            self.assertIn("WOULD APPLY: stop apache2 (ActiveState=active)", stdout.getvalue())
            self.assertFalse(Path(os.fspath(event_log) + ".stopped").exists())

            for recovery_decision, decision_rc in (
                ("restart-blocked:marker-retained;reset-invalid-cache=false", "0"),
                ("restart-blocked:marker-authority-uncertain;reset-invalid-cache=true", "0"),
                ("restart-allowed", "0"),
                ("restart-allowed:complete;reset-invalid-cache=false", "7"),
            ):
                with self.subTest(recovery_decision=recovery_decision):
                    accepted, events, _stderr, _code = recover(
                        {"RECOVERY_DECISION": recovery_decision, "DECISION_RC": decision_rc},
                    )
                    self.assertFalse(accepted)
                    self.assertIn("helper:monitor-authority-recover-decision", events)
                    self.assertNotIn("helper:monitor-authority-attest-decision", events)
                    self.assertNotIn("systemctl:start apache2", events)

        exact_cli = subprocess.run(
            [sys.executable, "-B", os.fspath(INFRA_SETUP_PATH), "--recover-monitor-authority", "--client"],
            cwd=ROOT, text=True, capture_output=True, check=False, timeout=10,
        )
        self.assertEqual(2, exact_cli.returncode)
        self.assertIn("--recover-monitor-authority must be the only option", exact_cli.stderr)

    def test_native_teardown_executes_read_only_attestation_before_preservation(
        self,
    ) -> None:
        teardown = ROOT / "infra/infra-teardown.sh"
        preserve = (
            shell_function(teardown, "monitor_authority_result_directory")
            + decision_capture_shell(teardown)
            + shell_function(teardown, "preserve_apache_control_boundary")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            boundary = root / "boundary.conf"
            helper = root / "control-auth"
            events = root / "events"
            boundary.write_text("boundary\n", encoding="utf-8")
            helper.write_text(
                "#!/bin/bash\n"
                "printf 'helper:%s\\n' \"$1\" >> \"$EVENT_LOG\"\n"
                "if [[ \"$1\" == monitor-authority-attest-decision ]]; then\n"
                "  if [[ \"${FAIL_ATTEST:-}\" == \"$1\" ]]; then exit 1; fi\n"
                "  printf '%s' \"${MARKER_PHASE:-attest-valid}\"\n"
                "  exit 0\n"
                "fi\n"
                "[[ \"${FAIL_ATTEST:-}\" != \"$1\" ]]\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            boundary_digest = hashlib.sha256(boundary.read_bytes()).hexdigest()
            helper_digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            harness = preserve + f'''
exec 3>/dev/null
apache_public_boundary_conf={shlex.quote(os.fspath(boundary))}
apache_public_boundary_sha256={boundary_digest}
control_auth_helper={shlex.quote(os.fspath(helper))}
control_auth_helper_sha256={helper_digest}
control_auth_file=/does/not/matter
apache_boundary_snapshot=already-held
EVENT_LOG={shlex.quote(os.fspath(events))}
export EVENT_LOG FAIL_ATTEST MARKER_PHASE
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(os.fspath(root))}; }}
protected_monitor_content_present() {{ return 0; }}
stat() {{ printf '1\\n'; }}
sha256sum() {{
  if [[ "$1" == "$apache_public_boundary_conf" ]]; then
    printf '%s  %s\\n' "$apache_public_boundary_sha256" "$1"
  else
    printf '%s  %s\\n' "$control_auth_helper_sha256" "$1"
  fi
}}
stop_apache_for_auth_failure() {{ printf 'service:stop\\n' >> "$EVENT_LOG"; }}
error() {{ printf 'error:%s\\n' "$*" >> "$EVENT_LOG"; }}
success() {{ printf 'success:%s\\n' "$*" >> "$EVENT_LOG"; }}
preserve_apache_control_boundary
'''
            result = run_shell(harness)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                [
                    "helper:monitor-authority-attest-decision",
                    "helper:validate",
                    "success:Preserving authenticated Apache boundary V2 and persistent Monitor credentials.",
                ],
                events.read_text(encoding="utf-8").splitlines(),
            )
            events.unlink()
            with mock.patch.dict(
                os.environ,
                {"FAIL_ATTEST": "monitor-authority-attest-decision"},
                clear=False,
            ):
                result = run_shell(harness)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual(
                [
                    "helper:monitor-authority-attest-decision",
                    "service:stop",
                    "error:Persistent Monitor cache authority is invalid; Apache remains stopped.",
                ],
                events.read_text(encoding="utf-8").splitlines(),
            )
            self.assertNotIn(
                "monitor-authority-recover",
                events.read_text(encoding="utf-8"),
            )

            for phase, phrase in (
                ("recovery-in-progress", "not been committed"),
                ("recovery-committed-cleanup-pending", "COMPLETED"),
            ):
                with self.subTest(phase=phase), mock.patch.dict(
                    os.environ,
                    {"MARKER_PHASE": phase, "FAIL_ATTEST": ""},
                    clear=False,
                ):
                    events.unlink(missing_ok=True)
                    result = run_shell(harness)
                    self.assertNotEqual(0, result.returncode)
                    log = events.read_text(encoding="utf-8")
                    self.assertIn("service:stop", log)
                    self.assertIn(phrase, log)
                    self.assertIn(NATIVE_RECOVERY_COMMAND, log)

    def test_native_setup_routine_adapter_never_repairs_marker_state(self) -> None:
        setup = ROOT / "infra/infra-setup.sh"
        adapter = (
            shell_function(setup, "monitor_authority_result_directory")
            + decision_capture_shell(setup)
            + shell_function(setup, "run_native_monitor_authority_routine")
        )
        for operation in ("monitor-authority-provision", "monitor-authority-attest"):
            for phase, phrase in (
                ("recovery-in-progress", "not been committed"),
                ("recovery-committed-cleanup-pending", "COMPLETED"),
            ):
                with self.subTest(operation=operation, phase=phase):
                    with tempfile.TemporaryDirectory() as temporary:
                        result = run_shell(adapter + f'''
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
control_auth_helper=control_auth_helper
control_auth_helper() {{ printf '%s' {shlex.quote(phase)}; return 0; }}
run_native_monitor_authority_routine {shlex.quote(operation)}
''')
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn(phrase, result.stderr)
                    self.assertIn(
                        "sudo ./infra/infra-setup.sh --recover-monitor-authority",
                        result.stderr,
                    )

    def test_python_setup_routine_adapter_never_repairs_marker_state(self) -> None:
        for operation in ("monitor-authority-provision", "monitor-authority-attest"):
            for phase, phrase in (
                ("recovery-in-progress", "not been committed"),
                ("recovery-committed-cleanup-pending", "COMPLETED"),
            ):
                with self.subTest(operation=operation, phase=phase), \
                        tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "run").mkdir()
                    helper = root / INFRA_SETUP.CONTROL_AUTH_HELPER.lstrip("/")
                    helper.parent.mkdir(parents=True)
                    calls = root / "calls"
                    helper.write_text(
                        "#!/bin/bash\n"
                        f"printf '%s\\n' \"$1\" >> {shlex.quote(os.fspath(calls))}\n"
                        f"printf '%s' {shlex.quote(phase)}\n",
                        encoding="utf-8",
                    )
                    helper.chmod(0o755)
                    setup = python_native_setup(root)
                    stderr = io.StringIO()
                    with mock.patch.object(INFRA_SETUP, "HOST_ROOT", root), redirect_stderr(stderr):
                        self.assertFalse(setup.run_native_monitor_authority_routine(operation))
                    self.assertIn(phrase, stderr.getvalue())
                    self.assertIn(NATIVE_RECOVERY_COMMAND, stderr.getvalue())
                    # The routine adapter only asks for a decision; it never repairs.
                    self.assertEqual([f"{operation}-decision"],
                                     calls.read_text(encoding="utf-8").splitlines())

    def test_docker_deploy_executes_recovery_and_doctor_is_attest_only(self) -> None:
        deploy = ROOT / "infra/docker/deploy.sh"
        recovery = (
            shell_function(deploy, "monitor_authority_result_directory")
            + decision_capture_shell(deploy)
            + shell_function(deploy, "recover_monitor_authority_action")
        )
        doctor = shell_function(deploy, "doctor")
        with tempfile.TemporaryDirectory() as temporary:
            result = run_shell(recovery + f'''
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
script_dir=/fixed/docker
lock_wait=600
python3() {{ printf '%s' 'restart-allowed:complete;reset-invalid-cache=false'; }}
say() {{ printf '%s\\n' "$*"; }}
fail() {{ printf '[ERROR] %s\\n' "$*" >&2; return 91; }}
recover_monitor_authority_action
''')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("container remains stopped", result.stdout)
        self.assertIn("sudo ./infra/docker/deploy.sh deploy", result.stdout)

        matrix = (
            ("restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false", 0, True),
            ("restart-blocked:marker-retained;reset-invalid-cache=true", 0, False),
            ("restart-blocked:marker-authority-uncertain;reset-invalid-cache=false", 0, False),
            ("restart-allowed", 0, False),
            ("restart-allowed:complete;reset-invalid-cache=false", 7, False),
        )
        for decision, helper_rc, expect_success in matrix:
            with self.subTest(decision=decision), tempfile.TemporaryDirectory() as temporary:
                result = run_shell(recovery + f'''
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
script_dir=/fixed/docker
lock_wait=600
python3() {{ printf '%s' {shlex.quote(decision)}; return {helper_rc}; }}
say() {{ printf '%s\\n' "$*"; }}
fail() {{ printf '[ERROR] %s\\n' "$*" >&2; return 91; }}
recover_monitor_authority_action
''')
                self.assertEqual(expect_success, result.returncode == 0)
                if expect_success:
                    self.assertIn(
                        "sudo ./infra/docker/deploy.sh deploy", result.stdout,
                    )
                else:
                    self.assertNotIn(
                        "sudo ./infra/docker/deploy.sh deploy", result.stdout,
                    )

        result = run_shell(doctor + r'''
events=()
host_preflight() { events+=(preflight); }
load_runtime_env() { events+=(env); }
prepare_bind_mounts() { events+=(binds); }
prepare_control_auth() { events+=(auth); }
prepare_monitor_authority() { events+=(PROVISION-BUG); }
attest_monitor_authority() { events+=(attest); }
owned_container_id() { return 0; }
assert_service_ports_free() { events+=(ports); }
say() { :; }
doctor
printf '%s\n' "${events[*]}"
''')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "preflight env auth attest ports", result.stdout.splitlines()[-1],
        )
        self.assertNotIn("PROVISION-BUG", result.stdout)

    def test_shell_decision_capture_is_binary_exact_and_bounded(self) -> None:
        scripts = (
            ROOT / "infra/infra-setup.sh",
            ROOT / "infra/infra-teardown.sh",
            ROOT / "infra/docker/deploy.sh",
        )
        token = "restart-allowed:complete;reset-invalid-cache=false"
        cases = (
            ("exact", f"printf '%s' {shlex.quote(token)}", 0, True),
            ("extra-lf", f"printf '%s\\n' {shlex.quote(token)}", 0, False),
            ("extra-blank", f"printf '%s\\n\\n' {shlex.quote(token)}", 0, False),
            ("truncated", "printf '%s' restart-allowed", 0, False),
            ("nul", f"printf '%s\\0' {shlex.quote(token)}", 0, False),
            ("wrong-rc", f"printf '%s' {shlex.quote(token)}", 7, False),
            ("stderr", f"printf '%s' {shlex.quote(token)}; printf noise >&2", 0, False),
            (
                "oversize-stdout",
                "i=0; while [[ $i -lt 5000 ]]; do printf x; i=$((i+1)); done",
                0,
                False,
            ),
            (
                "oversize-stderr",
                f"printf '%s' {shlex.quote(token)}; "
                "i=0; while [[ $i -lt 5000 ]]; do printf x >&2; i=$((i+1)); done",
                0,
                False,
            ),
        )
        for script in scripts:
            capture = decision_capture_shell(script)
            production_capture = decision_capture_shell(script, portable=False)
            self.assertNotIn("declare -F", production_capture)
            self.assertNotIn("command_is_function", production_capture)
            for label, producer, producer_rc, expected in cases:
                with self.subTest(script=script.name, case=label), tempfile.TemporaryDirectory() as temporary:
                    producer_path = Path(temporary) / f"producer-{label}.sh"
                    producer_path.write_text(
                        "#!/bin/bash\n" + producer + f"\nexit {producer_rc}\n",
                        encoding="utf-8",
                    )
                    producer_path.chmod(0o755)
                    result = run_shell(capture + f'''
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
if capture_monitor_authority_decision {shlex.quote(os.fspath(producer_path))}; then
  printf 'accepted:%s\\n' "$monitor_authority_decision"
  exit 0
fi
exit 9
''')
                    self.assertEqual(expected, result.returncode == 0)
                    if expected:
                        self.assertEqual(f"accepted:{token}\n", result.stdout)

    def test_shell_decision_capture_rejects_and_cleans_detached_fifo_holders(
        self,
    ) -> None:
        scripts = (
            ROOT / "infra/infra-setup.sh",
            ROOT / "infra/infra-teardown.sh",
            ROOT / "infra/docker/deploy.sh",
        )
        token = "restart-allowed:complete;reset-invalid-cache=false"
        for script in scripts:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as temporary:
                result_root = Path(temporary)
                helper = result_root / "detached-holder.py"
                holder_pid_file = result_root / "holder.pid"
                helper.write_text(
                    "#!/usr/bin/python3\n"
                    "import os\n"
                    "from pathlib import Path\n"
                    "import signal\n"
                    "import sys\n"
                    "import time\n"
                    f"os.write(1, {token.encode()!r})\n"
                    "ready_read, ready_write = os.pipe()\n"
                    "first = os.fork()\n"
                    "if first:\n"
                    "    os.close(ready_write)\n"
                    "    os.read(ready_read, 1)\n"
                    "    os._exit(0)\n"
                    "os.close(ready_read)\n"
                    "os.setsid()\n"
                    "second = os.fork()\n"
                    "if second:\n"
                    "    os._exit(0)\n"
                    "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')\n"
                    "os.write(ready_write, b'1')\n"
                    "os.close(ready_write)\n"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    "if sys.platform == 'darwin':\n"
                    "    while True:\n"
                    "        time.sleep(0.02)\n"
                    "        os.write(1, b'x')\n"
                    "while True:\n"
                    "    time.sleep(60)\n",
                    encoding="utf-8",
                )
                helper.chmod(0o755)
                capture = (
                    decision_capture_shell(script)
                    + darwin_capture_holder_cleanup_shell()
                )
                harness = capture + f'''
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
if capture_monitor_authority_decision \
    {private_python_fixture_command(helper)} {shlex.quote(os.fspath(holder_pid_file))}; then
  capture_state=accepted
  capture_rc=0
else
  capture_rc=$?
  capture_state=rejected
fi
holder_state=gone
if [[ -s {shlex.quote(os.fspath(holder_pid_file))} ]]; then
  read -r holder_pid < {shlex.quote(os.fspath(holder_pid_file))}
  attempts=0
  while kill -0 "$holder_pid" 2>/dev/null && [[ $attempts -lt 50 ]]; do
    /bin/sleep 0.02
    attempts=$((attempts + 1))
  done
  if kill -0 "$holder_pid" 2>/dev/null; then holder_state=alive; fi
fi
printf 'capture=%s rc=%s token=<%s> holder=%s\\n' \
  "$capture_state" "$capture_rc" "$monitor_authority_decision" "$holder_state"
'''
                try:
                    result = run_shell(harness, timeout_seconds=4)
                finally:
                    cleanup_recorded_test_processes(holder_pid_file)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(
                    "capture=rejected rc=1 token=<> holder=gone\n", result.stdout,
                )
                self.assertEqual("", result.stderr)
                self.assertEqual(
                    [], list(result_root.glob("http-ztp-monitor-decision.*")),
                )

    def test_shell_decision_capture_deadline_kills_and_reaps_process_group(
        self,
    ) -> None:
        scripts = (
            ROOT / "infra/infra-setup.sh",
            ROOT / "infra/infra-teardown.sh",
            ROOT / "infra/docker/deploy.sh",
        )
        for script in scripts:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as temporary:
                result_root = Path(temporary)
                helper = result_root / "stalled-group.py"
                process_file = result_root / "processes"
                helper.write_text(
                    "#!/usr/bin/python3\n"
                    "import os\n"
                    "from pathlib import Path\n"
                    "import signal\n"
                    "import sys\n"
                    "import time\n"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    "child = os.fork()\n"
                    "if child:\n"
                    "    target = Path(sys.argv[1])\n"
                    "    temporary = target.with_name(\n"
                    "        f'.{target.name}.{os.getpid()}.tmp'\n"
                    "    )\n"
                    "    payload = f'{os.getpid()} {child}'.encode('ascii')\n"
                    "    descriptor = os.open(\n"
                    "        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,\n"
                    "        0o600,\n"
                    "    )\n"
                    "    try:\n"
                    "        remaining = memoryview(payload)\n"
                    "        while remaining:\n"
                    "            written = os.write(descriptor, remaining)\n"
                    "            if written <= 0:\n"
                    "                raise OSError('short PID evidence write')\n"
                    "            remaining = remaining[written:]\n"
                    "        os.fsync(descriptor)\n"
                    "    finally:\n"
                    "        os.close(descriptor)\n"
                    "    os.replace(temporary, target)\n"
                    "    parent_descriptor = os.open(\n"
                    "        target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC\n"
                    "    )\n"
                    "    try:\n"
                    "        os.fsync(parent_descriptor)\n"
                    "    finally:\n"
                    "        os.close(parent_descriptor)\n"
                    "while True:\n"
                    "    time.sleep(60)\n",
                    encoding="utf-8",
                )
                helper.chmod(0o755)
                capture = decision_capture_shell(script, portable=False)
                self.assertEqual(
                    3, capture.count("/usr/bin/timeout --signal=KILL 11"),
                )
                capture = capture.replace("exec /usr/bin/timeout", "timeout")
                capture = capture.replace("/usr/bin/timeout", "timeout")
                capture = capture.replace(
                    "timeout --signal=KILL 11", "timeout --signal=KILL 0.75",
                )
                capture += darwin_capture_holder_cleanup_shell() + test_timeout_shell()
                harness = capture + f'''
export HTTP_ZTP_TEST_TIMEOUT_READY_FILE={shlex.quote(os.fspath(process_file))}
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
if capture_monitor_authority_decision \
    {shlex.quote(os.fspath(helper))} {shlex.quote(os.fspath(process_file))}; then
  capture_state=accepted
  capture_rc=0
else
  capture_rc=$?
  capture_state=rejected
fi
printf 'capture=%s rc=%s token=<%s>\\n' \
  "$capture_state" "$capture_rc" "$monitor_authority_decision"
'''
                started = time.monotonic()
                process_ids: tuple[int, ...] = ()
                try:
                    result = run_shell(harness, timeout_seconds=15)
                    elapsed = time.monotonic() - started
                    self.assertTrue(process_file.exists())
                    process_ids = tuple(
                        int(value) for value in
                        process_file.read_text(encoding="ascii").split()
                    )
                    self.assertEqual(2, len(process_ids))
                    self.assertEqual(2, len(set(process_ids)))
                    deadline = time.monotonic() + 2
                    while process_ids and time.monotonic() < deadline:
                        alive = []
                        for process_id in process_ids:
                            try:
                                os.kill(process_id, 0)
                            except ProcessLookupError:
                                continue
                            alive.append(process_id)
                        if not alive:
                            break
                        time.sleep(0.02)
                    else:
                        alive = list(process_ids)
                finally:
                    cleanup_recorded_test_processes(process_file)
                self.assertGreaterEqual(elapsed, 0.65)
                self.assertLess(elapsed, 12.0)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("capture=rejected rc=1 token=<>\n", result.stdout)
                self.assertEqual("", result.stderr)
                self.assertEqual([], alive)
                self.assertEqual(
                    [], list(result_root.glob("http-ztp-monitor-decision.*")),
                )

    def test_shell_capture_reader_deadline_survives_holder_kill_failure(
        self,
    ) -> None:
        scripts = (
            ROOT / "infra/infra-setup.sh",
            ROOT / "infra/infra-teardown.sh",
            ROOT / "infra/docker/deploy.sh",
        )
        token = "restart-allowed:complete;reset-invalid-cache=false"
        for script in scripts:
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as temporary:
                result_root = Path(temporary)
                helper = result_root / "unkillable-holder.py"
                holder_pid_file = result_root / "holder.pid"
                helper.write_text(
                    "#!/usr/bin/python3\n"
                    "import os\n"
                    "from pathlib import Path\n"
                    "import signal\n"
                    "import sys\n"
                    "import time\n"
                    f"os.write(1, {token.encode()!r})\n"
                    "ready_read, ready_write = os.pipe()\n"
                    "first = os.fork()\n"
                    "if first:\n"
                    "    os.close(ready_write)\n"
                    "    os.read(ready_read, 1)\n"
                    "    os._exit(0)\n"
                    "os.close(ready_read)\n"
                    "os.setsid()\n"
                    "second = os.fork()\n"
                    "if second:\n"
                    "    os._exit(0)\n"
                    "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')\n"
                    "os.write(ready_write, b'1')\n"
                    "os.close(ready_write)\n"
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    "while True:\n"
                    "    time.sleep(60)\n",
                    encoding="utf-8",
                )
                helper.chmod(0o755)
                capture = (
                    decision_capture_shell(script, portable=False)
                    + failed_capture_holder_cleanup_shell()
                )
                self.assertEqual(
                    3, capture.count("/usr/bin/timeout --signal=KILL 11"),
                )
                capture = capture.replace("exec /usr/bin/timeout", "timeout")
                capture = capture.replace("/usr/bin/timeout", "timeout")
                capture = capture.replace(
                    "timeout --signal=KILL 11 \\\n    head -c 4097",
                    "timeout --signal=KILL 0.75 \\\n    head -c 4097",
                )
                capture += test_timeout_shell()
                harness = capture + f'''
export HTTP_ZTP_TEST_TIMEOUT_READY_FILE={shlex.quote(os.fspath(holder_pid_file))}
monitor_authority_result_directory() {{ printf '%s\\n' {shlex.quote(temporary)}; }}
if capture_monitor_authority_decision \
    {private_python_fixture_command(helper)} {shlex.quote(os.fspath(holder_pid_file))}; then
  capture_state=accepted
  capture_rc=0
else
  capture_rc=$?
  capture_state=rejected
fi
printf 'capture=%s rc=%s token=<%s>\\n' \
  "$capture_state" "$capture_rc" "$monitor_authority_decision"
'''
                started = time.monotonic()
                holder_pid = None
                try:
                    result = run_shell(harness, timeout_seconds=3)
                    elapsed = time.monotonic() - started
                    self.assertTrue(
                        holder_pid_file.exists(),
                        f"stdout={result.stdout!r} stderr={result.stderr!r}",
                    )
                    holder_pid = int(holder_pid_file.read_text(encoding="ascii"))
                    os.kill(holder_pid, 0)
                finally:
                    cleanup_recorded_test_processes(holder_pid_file)
                self.assertGreaterEqual(elapsed, 0.20)
                self.assertLess(elapsed, 2.0)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("capture=rejected rc=1 token=<>\n", result.stdout)
                self.assertEqual("", result.stderr)
                self.assertEqual(
                    [], list(result_root.glob("http-ztp-monitor-decision.*")),
                )

    def test_portable_timeout_readiness_cannot_extend_the_requested_reader_deadline(self) -> None:
        # A never-ready producer must consume the requested timeout, not a
        # separate two-second readiness allowance followed by another timer.
        # Owned child, no detached holder or foreign PID; retain the original
        # FIFO case's .75 reader / 2 total / 3 outer bounds unchanged.
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'never-ready'
            command = (shlex.quote(os.path.realpath(sys.executable))
                       + " -B -c 'import time; time.sleep(10)'")
            harness = test_timeout_shell() + f'''
export HTTP_ZTP_TEST_TIMEOUT_READY_FILE={shlex.quote(os.fspath(ready))}
timeout --signal=KILL 0.75 {command}
printf 'timeout=%s\\n' "$?"
'''
            started = time.monotonic()
            result = run_shell(harness, timeout_seconds=3)
            elapsed = time.monotonic() - started
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('timeout=124\n', result.stdout)
            self.assertEqual('', result.stderr)
            self.assertFalse(ready.exists())
            self.assertGreaterEqual(elapsed, 0.70)
            self.assertLess(elapsed, 1.5, 'readiness must be inside the .75-second timeout')

    def test_portable_timeout_binds_current_native_python_without_system_launcher_dispatch(self) -> None:
        interpreter = shlex.quote(os.path.realpath(sys.executable))
        body = test_timeout_shell()
        self.assertIn(interpreter + " -B -c", body)
        self.assertNotIn("/usr/bin/python3 -c", body)
        self.assertIn("deadline=time.monotonic()+2.0", body)
        self.assertIn("command.kill()", body)
        self.assertIn("command_rc=command.wait()", body)

    def test_private_python_fixture_command_ignores_ambient_shebang_dispatch(self) -> None:
        helper = self.sandbox / "poisoned-shebang-fixture.py"
        helper.write_text("#!/missing/fixture-interpreter\nprint('private-body')\n", encoding="utf-8")
        helper.chmod(0o700)
        command = private_python_fixture_command(helper)
        self.assertEqual(shlex.quote(os.path.realpath(sys.executable)) + " -B " + shlex.quote(str(helper)), command)
        result = run_shell(command + "\n", timeout_seconds=3)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("private-body\n", result.stdout)

    def test_shell_timeout_never_signals_an_already_reaped_session_identifier(self) -> None:
        process = mock.Mock()
        process.pid = 987654321
        process.poll.return_value = 0
        process.communicate.side_effect = subprocess.TimeoutExpired(["/bin/bash"], 3)
        with mock.patch.object(subprocess, "Popen", return_value=process), \
                mock.patch.object(os, "killpg", side_effect=PermissionError("stale session")) as kill_group:
            with self.assertRaises(subprocess.TimeoutExpired):
                run_shell(":\n", timeout_seconds=3)
        kill_group.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_called_once_with(timeout=2.0)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close.assert_called_once()

    def test_portable_timeout_missing_readiness_kills_and_reaps_command(self) -> None:
        """A failed readiness barrier must not abandon a live command."""
        pid_file = self.sandbox / "readiness-command.pid"
        absent_ready = self.sandbox / "never-ready"
        command = "import time; time.sleep(60)"
        # The supervisor owns Popen's original PID. Publish its receipt
        # atomically inside the existing kill/reap finally, not in a child
        # which the unchanged 0.1-second deadline can interrupt mid-write.
        # Publication does not signal readiness or restart the timeout budget.
        harness = timeout_with_owned_pid_receipt(pid_file) + f'''
export HTTP_ZTP_TEST_TIMEOUT_READY_FILE={shlex.quote(str(absent_ready))}
if timeout --signal=KILL 0.1 {shlex.quote(os.path.realpath(sys.executable))} -B -c {shlex.quote(command)}; then
  timeout_rc=0
else
  timeout_rc=$?
fi
printf 'timeout rc=%s\\n' "$timeout_rc"
'''
        command_reaped = False
        try:
            result = run_shell(harness, timeout_seconds=3)
            self.assertTrue(pid_file.exists(), result.stderr)
            command_pid = int(pid_file.read_text(encoding="ascii"))
            self.assertFalse(absent_ready.exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(command_pid, 0)
            command_reaped = True
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("timeout rc=124\n", result.stdout)
            self.assertEqual("", result.stderr)
        finally:
            if command_reaped:
                pid_file.unlink(missing_ok=True)
            else:
                cleanup_recorded_test_processes(pid_file)

    def test_timeout_receipt_cleanup_never_signals_a_verified_reaped_pid(self) -> None:
        # Both actual supervisors already wait/reap their own Popen child.
        # A bare historical PID must not be signalled after disappearance.
        with mock.patch.object(sys.modules[__name__], "cleanup_recorded_test_processes",
                               side_effect=AssertionError("verified reaped PID must not be signalled")) as cleanup:
            self.test_portable_timeout_missing_readiness_kills_and_reaps_command()
            self.test_portable_timeout_supervisor_fault_reaps_started_command()
        cleanup.assert_not_called()

    def test_portable_timeout_supervisor_fault_reaps_started_command(self) -> None:
        """Even a timer/supervisor fault cannot orphan its private command."""
        pid_file = self.sandbox / "supervisor-fault-command.pid"
        command = "import time; time.sleep(60)"
        timeout = timeout_with_owned_pid_receipt(pid_file)
        checkpoint = "deadline=time.monotonic()+2.0"
        self.assertEqual(1, timeout.count(checkpoint))
        timeout = re.sub(
            r"(?m)^([ ]*)" + re.escape(checkpoint) + r"$",
            lambda match: (
                match[1] + "while not os.path.exists(ready):\n"
                + match[1] + "    time.sleep(0.005)\n"
                + match[1] + "raise SystemExit(125)"
            ),
            timeout,
        )
        harness = timeout + f'''
export HTTP_ZTP_TEST_TIMEOUT_READY_FILE={shlex.quote(str(pid_file))}
if timeout --signal=KILL 0.1 {shlex.quote(os.path.realpath(sys.executable))} -B -c {shlex.quote(command)}; then
  timeout_rc=0
else
  timeout_rc=$?
fi
printf 'timeout rc=%s\\n' "$timeout_rc"
'''
        command_reaped = False
        try:
            result = run_shell(harness, timeout_seconds=3)
            self.assertTrue(pid_file.exists(), result.stderr)
            command_pid = int(pid_file.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(command_pid, 0)
            command_reaped = True
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("timeout rc=125\n", result.stdout)
            self.assertEqual("", result.stderr)
        finally:
            if command_reaped:
                pid_file.unlink(missing_ok=True)
            else:
                cleanup_recorded_test_processes(pid_file)

    def test_portable_timeout_preserves_shell_function_io_and_status(self) -> None:
        """Real shell adapters keep their argument, pipe, diagnostic and status contract."""
        harness = test_timeout_shell() + r'''
fixture_command() {
  local input
  IFS= read -r input
  printf 'function=%s input=%s\n' "$1" "$input"
  printf 'function diagnostic\n' >&2
  return 7
}
if timeout --signal=KILL 1 fixture_command argument <<<'pipe input'; then
  timeout_rc=0
else
  timeout_rc=$?
fi
printf 'timeout rc=%s\n' "$timeout_rc"
'''
        result = run_shell(harness, timeout_seconds=3)
        self.assertEqual(0, result.returncode)
        self.assertEqual(
            "function=argument input=pipe input\ntimeout rc=7\n", result.stdout,
        )
        self.assertEqual("function diagnostic\n", result.stderr)

    def test_python_setup_decision_capture_is_binary_exact_and_bounded(self) -> None:
        token = "restart-allowed:complete;reset-invalid-cache=false"
        cases = (
            ("exact", f"printf '%s' {shlex.quote(token)}", 0, True),
            ("extra-lf", f"printf '%s\\n' {shlex.quote(token)}", 0, False),
            ("extra-blank", f"printf '%s\\n\\n' {shlex.quote(token)}", 0, False),
            ("truncated", "printf '%s' restart-allowed", 0, False),
            ("nul", f"printf '%s\\0' {shlex.quote(token)}", 0, False),
            ("wrong-rc", f"printf '%s' {shlex.quote(token)}", 7, False),
            ("stderr", f"printf '%s' {shlex.quote(token)}; printf noise >&2", 0, False),
            ("oversize-stdout", "i=0; while [[ $i -lt 5000 ]]; do printf x; i=$((i+1)); done", 0, False),
            (
                "oversize-stderr",
                f"printf '%s' {shlex.quote(token)}; "
                "i=0; while [[ $i -lt 5000 ]]; do printf x >&2; i=$((i+1)); done",
                0,
                False,
            ),
            ("unknown-token", "printf '%s' attest-valid-but-longer", 0, False),
        )
        self.assertEqual(4097, INFRA_SETUP.MONITOR_DECISION_LIMIT)
        self.assertEqual(11.0, INFRA_SETUP.MONITOR_DECISION_TIMEOUT)
        self.assertEqual(
            set(CONTROL_AUTH.MONITOR_AUTHORITY_DECISION_TOKENS),
            set(INFRA_SETUP.MONITOR_DECISION_TOKENS),
        )
        for label, producer, producer_rc, expected in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                producer_path = Path(temporary) / f"producer-{label}.sh"
                producer_path.write_text(
                    "#!/bin/bash\n" + producer + f"\nexit {producer_rc}\n", encoding="utf-8",
                )
                producer_path.chmod(0o755)
                decision = INFRA_SETUP.capture_decision(producer_path, "decision", Path(temporary))
                self.assertEqual(token if expected else "", decision)
                self.assertEqual([], list(Path(temporary).glob("http-ztp-monitor-decision.*")))

    def test_python_setup_decision_capture_rejects_and_cleans_detached_holders(self) -> None:
        token = "restart-allowed:complete;reset-invalid-cache=false"
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary)
            helper = result_root / "detached-holder.py"
            holder_pid_file = result_root / "holder.pid"
            helper.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "from pathlib import Path\n"
                "import signal\n"
                "import sys\n"
                "import time\n"
                f"os.write(1, {token.encode()!r})\n"
                "ready_read, ready_write = os.pipe()\n"
                "first = os.fork()\n"
                "if first:\n"
                "    os.close(ready_write)\n"
                "    os.read(ready_read, 1)\n"
                "    os._exit(0)\n"
                "os.close(ready_read)\n"
                "os.setsid()\n"
                "second = os.fork()\n"
                "if second:\n"
                "    os._exit(0)\n"
                "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')\n"
                "os.write(ready_write, b'1')\n"
                "os.close(ready_write)\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "while True:\n"
                "    time.sleep(60)\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            started = time.monotonic()
            try:
                with python_capture_holder_scan():
                    decision = INFRA_SETUP.capture_decision(helper, os.fspath(holder_pid_file), result_root)
                elapsed = time.monotonic() - started
                holder_pid = int(holder_pid_file.read_text(encoding="ascii"))
                deadline = time.monotonic() + 1.0
                holder_alive = True
                while holder_alive and time.monotonic() < deadline:
                    try:
                        os.kill(holder_pid, 0)
                        time.sleep(0.02)
                    except ProcessLookupError:
                        holder_alive = False
            finally:
                cleanup_recorded_test_processes(holder_pid_file)
            self.assertEqual("", decision)
            self.assertFalse(holder_alive, "the escaped holder must be killed")
            self.assertLess(elapsed, 5.0)
            self.assertEqual([], list(result_root.glob("http-ztp-monitor-decision.*")))

    def test_python_setup_decision_deadline_kills_and_reaps_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary)
            helper = result_root / "stalled-group.py"
            process_file = result_root / "processes"
            helper.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "from pathlib import Path\n"
                "import signal\n"
                "import sys\n"
                "import time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "child = os.fork()\n"
                "if child:\n"
                "    target = Path(sys.argv[1])\n"
                "    temporary = target.with_name(f'.{target.name}.tmp')\n"
                "    temporary.write_text(f'{os.getpid()} {child}', encoding='ascii')\n"
                "    os.replace(temporary, target)\n"
                "while True:\n"
                "    time.sleep(60)\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            started = time.monotonic()
            alive = []
            try:
                with mock.patch.object(INFRA_SETUP, "MONITOR_DECISION_TIMEOUT", 1.5):
                    decision = INFRA_SETUP.capture_decision(helper, os.fspath(process_file), result_root)
                elapsed = time.monotonic() - started
                self.assertTrue(process_file.exists())
                process_ids = tuple(int(value) for value in process_file.read_text(encoding="ascii").split())
                self.assertEqual(2, len(set(process_ids)))
                deadline = time.monotonic() + 2
                alive = list(process_ids)
                while alive and time.monotonic() < deadline:
                    still = []
                    for process_id in alive:
                        try:
                            os.kill(process_id, 0)
                        except ProcessLookupError:
                            continue
                        still.append(process_id)
                    alive = still
                    if alive:
                        time.sleep(0.02)
            finally:
                cleanup_recorded_test_processes(process_file)
            self.assertEqual("", decision)
            self.assertGreaterEqual(elapsed, 1.4)
            self.assertLess(elapsed, 12.0)
            self.assertEqual([], alive)
            self.assertEqual([], list(result_root.glob("http-ztp-monitor-decision.*")))

    def test_python_setup_reader_deadline_survives_holder_kill_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_root = Path(temporary)
            helper = result_root / "unkillable-holder.py"
            holder_pid_file = result_root / "holder.pid"
            helper.write_text(
                f"#!{sys.executable}\n"
                "import os\n"
                "from pathlib import Path\n"
                "import signal\n"
                "import sys\n"
                "import time\n"
                "os.write(1, b'restart-allowed:complete;reset-invalid-cache=false')\n"
                "ready_read, ready_write = os.pipe()\n"
                "if os.fork():\n"
                "    os.close(ready_write)\n"
                "    os.read(ready_read, 1)\n"
                "    os._exit(0)\n"
                "os.setsid()\n"
                "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')\n"
                "os.write(ready_write, b'1')\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "while True:\n"
                "    time.sleep(60)\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            failed_kills = []

            def failed_holder_kill(holder_path, identities):
                failed_kills.append(holder_path)
                return False

            started = time.monotonic()
            try:
                with mock.patch.object(INFRA_SETUP, "MONITOR_DECISION_TIMEOUT", 0.75), \
                        mock.patch.object(INFRA_SETUP, "terminate_descriptor_holders", failed_holder_kill):
                    decision = INFRA_SETUP.capture_decision(helper, os.fspath(holder_pid_file), result_root)
                elapsed = time.monotonic() - started
                os.kill(int(holder_pid_file.read_text(encoding="ascii")), 0)
            finally:
                cleanup_recorded_test_processes(holder_pid_file)
            self.assertEqual("", decision)
            self.assertTrue(failed_kills)
            self.assertGreaterEqual(elapsed, 0.20)
            self.assertLess(elapsed, 2.0)
            self.assertEqual([], list(result_root.glob("http-ztp-monitor-decision.*")))

    def test_python_setup_capture_bounds_bytes_and_isolates_the_helper(self) -> None:
        source = inspect.getsource(INFRA_SETUP.capture_decision)
        for required in (
            "start_new_session=True", "pass_fds=(holder_fd,)", "MONITOR_DECISION_LIMIT",
            "kill_process_group(process.pid)", "terminate_descriptor_holders(holder_path, identities)",
            "reader.drain(deadline)", 'prefix="http-ztp-monitor-decision."',
        ):
            self.assertIn(required, source)
        self.assertIn('glob.glob("/proc/[0-9]*/fd/[0-9]*")', inspect.getsource(INFRA_SETUP.terminate_descriptor_holders))
        self.assertNotIn("shell=True", source)

    def test_shared_helper_alone_maps_structured_recovery_decisions(self) -> None:
        warning = CONTROL_AUTH.MONITOR_AUTHORITY_RECOVERY_WARNING + "\n"
        cleanup_warning = (
            CONTROL_AUTH.MONITOR_AUTHORITY_CLEANUP_DURABILITY_WARNING + "\n"
        )
        cases = tuple(
            (
                cleanup,
                restart_allowed,
                (warning if reset else "") + (
                    cleanup_warning
                    if cleanup == "marker-removal-durability-unknown" else ""
                ),
                f"restart-{'allowed' if restart_allowed else 'blocked'}:{cleanup};"
                f"reset-invalid-cache={'true' if reset else 'false'}",
            )
            for cleanup, restart_allowed in (
                ("complete", True),
                ("marker-removal-durability-unknown", True),
                ("marker-retained", False),
                ("marker-authority-uncertain", False),
            )
            for reset in (False, True)
        )
        for cleanup, restart_allowed, diagnostics, token in cases:
            with self.subTest(cleanup=cleanup, diagnostics=diagnostics):
                self.assertEqual(token, CONTROL_AUTH.monitor_authority_recovery_decision(
                    {
                        "cleanup": cleanup,
                        "recovery_committed": True,
                        "restart_allowed": restart_allowed,
                    },
                    diagnostics,
                ))
        for payload, diagnostics in (
            ({"cleanup": "complete", "restart_allowed": True}, ""),
            ({
                "cleanup": "complete", "recovery_committed": True,
                "restart_allowed": False,
            }, ""),
            ({
                "cleanup": "complete", "recovery_committed": True,
                "restart_allowed": True,
            }, "unexpected\n"),
            ({
                "cleanup": "complete", "recovery_committed": True,
                "restart_allowed": True,
            }, warning + warning),
            ({
                "cleanup": "marker-removal-durability-unknown",
                "recovery_committed": True, "restart_allowed": True,
            }, cleanup_warning + warning),
        ):
            with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                CONTROL_AUTH.monitor_authority_recovery_decision(payload, diagnostics)

    def test_decision_token_enum_is_complete_and_warning_provenance_is_lossless(self) -> None:
        outcomes = (
            ("complete", "allowed"),
            ("marker-removal-durability-unknown", "allowed"),
            ("marker-retained", "blocked"),
            ("marker-authority-uncertain", "blocked"),
        )
        expected = {
            "attest-valid", "recovery-in-progress",
            "recovery-committed-cleanup-pending",
        } | {
            f"restart-{restart}:{cleanup};reset-invalid-cache={reset}"
            for cleanup, restart in outcomes
            for reset in ("true", "false")
        }
        self.assertEqual(expected, set(CONTROL_AUTH.MONITOR_AUTHORITY_DECISION_TOKENS))

    def test_shell_capture_bounds_bytes_while_reading_and_has_a_fixed_deadline(self) -> None:
        paths = (
            ROOT / "infra/infra-setup.sh",
            ROOT / "infra/infra-teardown.sh",
            ROOT / "infra/docker/deploy.sh",
        )
        sources = []
        for path in paths:
            source = decision_capture_shell(path, portable=False)
            sources.append(source)
            with self.subTest(path=path):
                self.assertIn("head -c 4097", source)
                self.assertEqual(
                    3, source.count("/usr/bin/timeout --signal=KILL 11"),
                )
                self.assertIn("command -v /usr/bin/timeout", source)
                self.assertIn("mkfifo", source)
                self.assertIn("/proc/[0-9]*/fd/[0-9]*", source)
                self.assertIn('kill -KILL -- "-$command_pid"', source)
                self.assertIn('"$descriptor" -ef "$stdout_pipe"', source)
                self.assertIn('"$descriptor" -ef "$stderr_pipe"', source)
                self.assertNotIn("/bin/sleep", source)
                self.assertNotIn("/usr/bin/setsid", source)
                self.assertNotIn("/usr/sbin/lsof", source)
                self.assertNotIn("$(", source)
                self.assertNotRegex(
                    source,
                    r'if \"\$@\" >\"\$stdout_file\" 2>\"\$stderr_file\"',
                )
        self.assertEqual(1, len(set(sources)))

    def test_native_and_docker_publish_the_exact_reset_warning_once(self) -> None:
        warning = CONTROL_AUTH.MONITOR_AUTHORITY_RECOVERY_WARNING
        setup = (ROOT / "infra/infra-setup.sh").read_text(encoding="utf-8")
        deploy = (ROOT / "infra/docker/deploy.sh").read_text(encoding="utf-8")
        teardown = (ROOT / "infra/infra-teardown.sh").read_text(encoding="utf-8")
        self.assertEqual(1, setup.count(warning))
        self.assertEqual(1, deploy.count(warning))
        self.assertNotIn(warning, teardown)
        self.assertIn("reset-invalid-cache=true", setup)
        self.assertIn("reset-invalid-cache=true", deploy)
        self.assertRegex(
            setup,
            r'printf .*MONITOR_AUTHORITY_RECOVERY_WARNING.*>&2.*\n.*printf .*MONITOR_AUTHORITY_RECOVERY_WARNING.*>&3',
        )
        self.assertRegex(
            deploy,
            r'printf .*MONITOR_AUTHORITY_RECOVERY_WARNING.*>&2',
        )

    def test_python_setup_publishes_the_exact_reset_warning_once(self) -> None:
        warning = CONTROL_AUTH.MONITOR_AUTHORITY_RECOVERY_WARNING
        setup = INFRA_SETUP_PATH.read_text(encoding="utf-8")
        self.assertEqual(1, setup.count(warning))
        self.assertEqual(warning, INFRA_SETUP.MONITOR_AUTHORITY_RECOVERY_WARNING)
        self.assertIn("reset-invalid-cache=true", setup)
        # Published once, to the operator (stderr) and the setup log alike.
        self.assertEqual(1, setup.count("self.both_streams(MONITOR_AUTHORITY_RECOVERY_WARNING)"))
        self.assertIn("print(text, file=sys.stderr", inspect.getsource(INFRA_SETUP.InfraSetup.both_streams))
        self.assertIn("self.to_log(text)", inspect.getsource(INFRA_SETUP.InfraSetup.both_streams))

    def test_cgi_has_no_second_serializer_or_semantic_constant_owner(self) -> None:
        source = CGI_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        functions = {
            node.name for node in tree.body if isinstance(node, ast.FunctionDef)
        }
        self.assertNotIn("_cache_payload", functions)
        self.assertNotIn("_cache_breaker_payload", functions)
        assignments = {
            target.id
            for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (
                node.targets if isinstance(node, ast.Assign) else (node.target,)
            )
            if isinstance(target, ast.Name)
        }
        for duplicate in (
            "CONTROL_AUTH_CACHE_BREAKER_SCHEMA",
            "CONTROL_AUTH_CACHE_SCHEMA",
            "CONTROL_AUTH_CACHE_BREAKER_THRESHOLD",
        ):
            self.assertNotIn(duplicate, assignments)

    def test_all_operator_surfaces_state_the_same_n3_denial_runbook(self) -> None:
        authorities = (
            ROOT / "test_cases/REAL_ENVIRONMENT.md",
            ROOT / "docs/operations/README.md",
            ROOT / "infra/docker/README.md",
        )
        required = (
            "N=3 is not proof of an attacker",
            "same-identity breaker N=1→2→3",
            "automatic repair loops are forbidden",
            NATIVE_RECOVERY_COMMAND,
            "sudo ./infra/docker/deploy.sh recover-monitor-authority",
            "never manually unlink/chmod/rewrite",
            "exactly one fixed warning",
            "re-wedging remains possible",
        )
        for authority in authorities:
            with self.subTest(authority=authority):
                metadata = authority.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(0o644, stat.S_IMODE(metadata.st_mode))
                content = authority.read_text(encoding="utf-8")
                for fragment in required:
                    self.assertIn(fragment, content)

    def test_manifest_has_one_real_lifecycle_to_cgi_authority_workflow(self) -> None:
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        workflow = next(
            item for item in manifest["workflows"]
            if item["id"] == "monitor_authority_lifecycle_to_cgi"
        )
        required_members = {
            "tools/control-auth.py", "monitor/ztp-monitor-control.cgi",
            "infra/infra-setup.py", "infra/infra-setup.sh", "infra/ubuntu24_host.py",
            "infra/infra-teardown.sh",
            "infra/docker/deploy.sh", "infra/docker/hostlock.py",
            "infra/docker/entrypoint.py", "infra/docker/activate.py",
            "infra/docker/hostctl.py",
        }
        self.assertTrue(required_members.issubset(set(workflow["members"])))
        self.assertIn(
            "test_cases.test_monitor_authority_semantic_workflow", workflow["tests"],
        )
        governed_paths = {
            ".github/workflows/monitor-authority-root.yml",
            "test_cases/monitor_authority_root_warden.py",
            "test_cases/monitor_authority_source_guard.py",
            "test_cases/run_monitor_authority_entrypoints.sh",
            "test_cases/REAL_ENVIRONMENT.md",
        }
        matching_rules = [
            rule for rule in manifest["path_rules"]
            if set(rule["paths"]) == governed_paths
        ]
        self.assertEqual(1, len(matching_rules))
        self.assertTrue({
            "test_cases.test_monitor_authority_entrypoints",
            "test_cases.test_monitor_authority_semantic_workflow",
            "test_cases.test_monitor_authority_source_guard",
        } <= set(matching_rules[0]["tests"]))
        all_paths = {
            path
            for rule in manifest["path_rules"]
            for path in rule["paths"]
        }
        self.assertIn("docs/operations/README.md", all_paths)
        self.assertIn("infra/docker/README.md", all_paths)

    def test_no_test_class_scope_patch_can_neutralize_monitor_authority(self) -> None:
        expected_method_fixtures = {
            "test_each_container_lifecycle_fails_before_work_when_control_auth_is_invalid",
            "test_fresh_markerless_guardian_accepts_real_stopped_pid_results",
            "test_fresh_markerless_resume_accepts_real_stopped_pid_results",
            "test_guardian_fault_unlink_failure_remains_unhealthy_and_quarantines_across_rounds",
            "test_guardian_final_bounded_recheck_holds_lock_and_quarantines",
            "test_guardian_first_fault_unlink_failure_does_not_block_markerless_stop",
            "test_guardian_health_runs_outside_short_lock_then_rechecks_generation",
            "test_guardian_marker_change_and_healthy_probe_clear_failure_count",
            "test_guardian_markerless_cleanup_retries_across_rounds_and_persists_quarantine",
            "test_guardian_quarantine_clears_before_ordered_stop_and_never_self_stops",
            "test_guardian_second_fault_unlink_failure_does_not_block_markerless_stop",
            "test_guardian_threshold_rechecks_under_same_lock_and_recovery_does_not_mutate",
            "test_guardian_treats_inactive_stopped_runtime_as_safe_under_lock",
            "test_http_only_load_precommit_and_commit_converge_exact_apache_set",
            "test_load_observes_then_quiesces_before_mutation_and_rolls_back_failure",
            "test_load_validates_receipt_only_after_trusted_lock_and_before_observe",
            "test_load_withdraws_start_authority_before_stop_and_publishes_candidate_late",
            "test_no_start_load_initializes_controls_before_worker_convergence",
            "test_reload_network_failure_withdraws_authority_and_stops_services",
            "test_reload_network_noop_keeps_runtime_untouched",
            "test_reload_network_rebinds_services_without_generation",
            "test_reload_network_rejects_stale_authority_before_mutation",
            "test_reload_network_requires_committed_current_authority",
            "test_resume_health_failure_rolls_back_started_services",
            "test_resume_rejects_unsafe_rebuild_marker_and_stops_every_service",
            "test_service_ip_move_replans_and_restarts_dhcp_in_one_load_transaction",
            "test_successful_load_clears_rebuild_marker_only_after_final_health",
        }
        violations = []
        actual_method_fixtures = set()
        for path in sorted((ROOT / "test_cases").glob("test_*.py")):
            source = path.read_text(encoding="utf-8")
            found, fixtures = _class_scope_monitor_authority_findings(path, source)
            violations.extend(found)
            actual_method_fixtures.update(fixtures)
        self.assertEqual([], violations)
        self.assertEqual(expected_method_fixtures, actual_method_fixtures)


class ClassScopeSegmentLiteralContractTests(unittest.TestCase):
    """Independent source/AST expectations before U1-SEG implementation."""

    def test_segments_preserve_newlines_utf8_bytes_formfeed_and_missing_locations(self):
        segment_type = globals().get("_SourceSegments")
        self.assertTrue(callable(segment_type), "U1-SEG helper not implemented")
        splitter = globals().get("_split_source_lines")
        self.assertTrue(callable(splitter), "U1-SEG splitter not implemented")
        cases = (
            ("LF", "value = f(\n x,\n)\n", "f(\n x,\n)"),
            ("CRLF", "value = f(\r\n x,\r\n)\r\n", "f(\r\n x,\r\n)"),
            ("CR", "value = f(\r x,\r)\r", "f(\r x,\r)"),
            ("UTF8", "é = f(42)\n", "f(42)"),
            ("FF", "value = 1\f+ 2\n", "1\f+ 2"),
        )
        original_get_source_segment = ast.get_source_segment
        for label, source, expected in cases:
            with self.subTest(source_shape=label):
                tree = ast.parse(source)
                node = tree.body[0].value
                with mock.patch.object(
                    sys.modules[__name__], "_split_source_lines", wraps=splitter,
                ) as split:
                    segments = segment_type(source)
                    self.assertEqual(0, split.call_count)
                    self.assertEqual(expected, segments.get(node))
                    self.assertEqual(expected, segments.get(node))
                    self.assertEqual(1, split.call_count)
                self.assertEqual(expected, ast.get_source_segment(source, node))
        self.assertIs(ast.get_source_segment, original_get_source_segment)
        with mock.patch.object(
            sys.modules[__name__], "_split_source_lines", wraps=splitter,
        ) as split:
            self.assertIsNone(segment_type("x = 1\n").get(ast.Constant(value=1)))
            self.assertEqual(0, split.call_count)

    def test_findings_keep_class_method_setup_rules_and_order_across_line_endings(self):
        findings = globals().get("_class_scope_monitor_authority_findings")
        self.assertTrue(callable(findings), "U1-SEG findings helper not implemented")
        source = (
            "@monitor_authority(\n"
            "    enabled=True,\n"
            ")\n"
            "class Alpha:\n"
            "    @tag(\n"
            "        'multi-line',\n"
            "    )\n"
            "    @with_valid_monitor_authority_fixture\n"
            "    def test_scoped(self):\n"
            "        pass\n"
            "    def setUp(self):\n"
            "        require_monitor_authority(\n"
            "            self,\n"
            "        )\n"
        )
        expected = [
            "synthetic.py:Alpha:class-decorator",
            "synthetic.py:Alpha.test_scoped:fixture-scope",
            "synthetic.py:Alpha.setUp",
        ]
        for line_ending in ("\n", "\r\n", "\r"):
            with self.subTest(line_ending=repr(line_ending)):
                violations, fixture_names = findings(
                    Path("synthetic.py"), source.replace("\n", line_ending),
                )
                self.assertEqual(expected, violations)
                self.assertEqual({"test_scoped"}, fixture_names)


if __name__ == "__main__":
    unittest.main()
