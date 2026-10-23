"""Real fixed-sibling backup adapter and private-FD workflow.

Only the outer test admission accepts ordinary runner -B and the two fixed
local runtimes below. Inner -I -B, UID501, full literal env and all process,
FD, state, time and cleanup expectations remain independent and unchanged.
"""
from contextlib import ExitStack
import ast
import types
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
# These are independent admitted original identities, not subject output.
_RUNTIME_ORIGINALS = (
    {
        "version": (3, 9, 6),
        "executable": "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9",
        "runtime_sha256": "5c5950c62eee5fd227a67e4bdfcde81c9add59799bba0949635f3d5ba9661c26",
        "subprocess_relative": "lib/python3.9/subprocess.py",
        "subprocess_sha256": "d2f73c7128a3931f74411b46352146ba85322a8dc8f12a721d4801dc43d9766e",
    },
    {
        "version": (3, 12, 14),
        "executable": "/Users/joeyyang/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3.12",
        "runtime_sha256": "7a314947596fc484d4ec36ffc28e843b78d6d749c68736f8b5c24e7333f418eb",
        "subprocess_relative": "lib/python3.12/subprocess.py",
        "subprocess_sha256": "85d29b2bf0249f5436838298c9a60ee93508b1102e9ac43b001f8a7e7ae8f375",
    },
)
_RUNTIME_MATCHES = [row for row in _RUNTIME_ORIGINALS
    if row["executable"] == os.path.realpath(sys.executable)
    and row["version"] == tuple(sys.version_info[:3])]
if len(_RUNTIME_MATCHES) != 1:
    raise ValueError("unsupported fixed local backup FD fixture runtime")
_RUNTIME_ORIGINAL = _RUNTIME_MATCHES[0]
RUNTIME = Path(_RUNTIME_ORIGINAL["executable"])
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ztp/backup/yaml-collect.py"
PARENT_SOURCE = SOURCE.parent / "_bounded_process.py"
LAUNCHER_SOURCE = SOURCE.parent / "_bounded_process_launcher.py"
FIXTURE = HERE / "fixtures/bounded_inner_fd_fixture.py"
PINS = {
    # 2026-10-23: re-pinned after the owner-approved server_mgmt/server_ufm device types (2026-10-19..22)
    # added _NON_SWITCH_TYPES to load_devices_csv (+4/-1 lines; was 066db88e… at 7c44779). The bounded
    # process helpers below are unchanged.
    SOURCE: "2f8185ae5f7fdfdbce299b554caab57a39d2b77330924c78975bb5c1fcebb86e",
    PARENT_SOURCE: "3ec254c596423a0fc93ef895f6226c62584672ec37a878c068524b30f30d221e",
    LAUNCHER_SOURCE: "2ef142cf049d1496d8d5321015529592576d6a724c4b9c6b5b50c5c551a8c1fa",
    FIXTURE: "bac0c68a18a313b60297c720d64d416a5d405c80c089b411b8a8fc6dbc1b64b9",
    RUNTIME: _RUNTIME_ORIGINAL["runtime_sha256"],
    RUNTIME.parent.parent / _RUNTIME_ORIGINAL["subprocess_relative"]: _RUNTIME_ORIGINAL["subprocess_sha256"],
}
FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
          "st_size", "st_mtime_ns", "st_ctime_ns")
# The driver keeps this module alive through its final receipt. These are real
# strong object references, not traceback locals or PID-file capabilities.
OWNED_RESOURCE_RECORDS = []
def rescue_owned_original(record):
    """Test-only finally; never counted as candidate/product cleanup proof."""
    process = record["processes"][0] if record["processes"] else None
    if process is not None and not record["kernel_reaped"]:
        reservation = record["reservations"][0] if len(record["reservations"]) == 1 else None
        confirmed = (type(reservation) is record["reservation_class"]
                     and reservation.process is process and reservation.pid == record["original_pid"]
                     and not reservation.lost and not reservation.reaped)
        if (not record["init_returned"] or type(process) is not record["popen_class"]
                or process.pid != record["original_pid"] or process.returncode is not None
                or record["wait_ownership_lost"] or not confirmed):
            record["resource_state"] = "UNKNOWN"
            record["errors"].append(("unadmitted_or_lost_original", AssertionError("UNKNOWN original ownership")))
        else:
            # Exact strong original successfully initialized session leader.
            # Never poll, rediscover getpgid, read a PID file, or retry a signal
            # whose syscall may already have happened.
            if not record["actual_signal_attempted"]:
                record["actual_signal_attempted"] = True
                record["rescue_actions"].append("OWNED_GROUP_SIGNAL_ATTEMPT")
                try:
                    record["real_killpg"](record["original_pid"], signal.SIGKILL)
                except BaseException as error:
                    record["errors"].append(("rescue_group", error))
            deadline = time.monotonic() + 1.0  # Extra fixture rescue, not product budget.
            while not record["kernel_reaped"]:
                try:
                    pid, status = record["real_waitpid"](record["original_pid"], os.WNOHANG)
                    if pid == record["original_pid"]:
                        record["kernel_reaped"] = True
                        process.returncode = os.waitstatus_to_exitcode(status)
                        record["rescue_actions"].append("OWNED_RAW_WAIT_RETURN")
                        break
                    if pid != 0:
                        raise AssertionError("UNKNOWN unexpected owned raw wait result")
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired("fixture original anchor rescue", 1.0)
                    time.sleep(0.005)
                except BaseException as error:
                    if isinstance(error, ChildProcessError):
                        record["wait_ownership_lost"] = True
                    record["errors"].append(("rescue_wait", error))
                    break
    # Each held source gets an independent attempt. Unknown/reused slots are
    # retained, not blindly closed. Stream.close also updates the Python owner.
    for row in record["streams"] + record["pipes"]:
        try:
            try:
                actual = os.fstat(row["fd"])
            except OSError as error:
                if error.errno == errno.EBADF:
                    continue
                raise
            key = [actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_gid]
            if key != row["identity"]:
                raise AssertionError("UNKNOWN reused owned FD; not closed")
            record["rescue_actions"].append("OWNED_CLOSE_ATTEMPT:" + row["role"])
            if "stream" in row:
                if row["stream"].closed or row["stream"].fileno() != row["fd"]:
                    raise AssertionError("UNKNOWN stream object/slot mismatch")
                row["stream"].close()
            else:
                os.close(row["fd"])
            try:
                os.fstat(row["fd"])
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                raise AssertionError("UNKNOWN close not confirmed")
        except BaseException as error:
            record["errors"].append(("rescue_fd:" + row["role"], error))
    if process is None:
        record["anchor_clean"] = True  # No original constructor was entered.
    else:
        record["anchor_clean"] = record["init_returned"] and record["kernel_reaped"]
    if not record["anchor_clean"] or record["errors"]:
        record["resource_state"] = "UNKNOWN"
    elif record["rescue_actions"]:
        record["resource_state"] = "RESCUED_TEST_ONLY"
    else:
        record["resource_state"] = "PRODUCT_CLEAN"


def original(path):
    a = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        b = os.fstat(fd)
        assert stat.S_ISREG(b.st_mode) and b.st_nlink == 1
        parts = []
        while True:
            part = os.read(fd, 131072)
            if not part:
                break
            parts.append(part)
        c = os.fstat(fd)
    finally:
        os.close(fd)
    d = path.lstat()
    rows = [[str(getattr(s, k)) for k in FIELDS] for s in (a, b, c, d)]
    assert rows == [rows[0]] * 4
    return {"stat9": rows[0], "sha256": hashlib.sha256(b"".join(parts)).hexdigest()}


class BoundedCanonicalPrivateFDWorkflowTests(unittest.TestCase):
    def test_real_staged_adapter_preserves_rc17_and_has_no_private_pipe_alias(self):
        # Explicit source-contract FAIL before staging; never an ImportError.
        for path in (PARENT_SOURCE, LAUNCHER_SOURCE):
            self.assertTrue(path.is_file(), "FEATURE_CONTRACT_API_ABSENT: fixed canonical sibling")
        case = "canonical_python4"
        self.assertEqual(OWNED_RESOURCE_RECORDS, [])
        self.assertEqual(threading.active_count(), 1)
        self.assertEqual(subprocess._active, [])
        self.assertEqual(os.getuid(), 501)
        self.assertEqual(sys.platform, "darwin")
        self.assertEqual(sys.version_info[:3], _RUNTIME_ORIGINAL["version"])
        self.assertEqual(Path(os.path.realpath(sys.executable)), RUNTIME)
        # Outer -I was the historical controller premise, not an inner contract.
        self.assertTrue(sys.dont_write_bytecode)
        self.assertIs(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
        before = {str(p): original(p) for p in PINS}
        for p, digest in PINS.items():
            self.assertEqual(before[str(p)]["sha256"], digest)
        caches = tuple(Path(importlib.util.cache_from_source(str(p)))
                       for p in (PARENT_SOURCE, LAUNCHER_SOURCE, FIXTURE))
        for cache in caches:
            with self.assertRaises(FileNotFoundError):
                cache.lstat()
        # macOS may spell TMPDIR as /var while fixed source loading resolves
        # it to /private/var. Capture the canonical original before staging;
        # keep all subsequent path and inode assertions exact.
        root = Path(tempfile.mkdtemp(prefix="http-h-canonical-private-fd-")).resolve()
        root_identity = (root.lstat().st_dev, root.lstat().st_ino, os.getuid())
        stage = root / "backup"
        try:
            stage.mkdir(mode=0o700)
            for path in (SOURCE, PARENT_SOURCE, LAUNCHER_SOURCE, FIXTURE):
                target = stage / ("bounded_inner_fd_fixture.py" if path == FIXTURE else path.name)
                target.write_bytes(path.read_bytes())
                target.chmod(0o600)
                self.assertEqual(target.read_bytes(), path.read_bytes())
            tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
            names = {"_read_bounded_source", "_verify_bounded_sources", "_load_bounded_process", "_run_bounded_process"}
            nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
            self.assertEqual(sorted(node.name for node in nodes), sorted(names))
            literal_map = {"_bounded_process.py": "3ec254c596423a0fc93ef895f6226c62584672ec37a878c068524b30f30d221e",
                           "_bounded_process_launcher.py": "2ef142cf049d1496d8d5321015529592576d6a724c4b9c6b5b50c5c551a8c1fa"}
            maps = [node.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "_BOUNDED_SOURCE_SHA256" for t in node.targets)]
            self.assertEqual(len(maps), 1)
            self.assertEqual(ast.literal_eval(maps[0]), literal_map)
            ns = {"__file__": str(stage / "yaml-collect.py"), "Path": Path, "os": os,
                  "stat": stat, "hashlib": hashlib, "types": types, "sys": sys,
                  "subprocess": subprocess, "_BOUNDED_SOURCE_SHA256": literal_map,
                  "MAX_SSH_OUTPUT_BYTES": 65536}
            unit = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)] + nodes,
                              type_ignores=[])
            def no_start_during_load(*args, **kwargs):
                raise AssertionError("fixed source loading cannot start a command")
            # Actual selected production functions, not a copied adapter.
            with mock.patch.object(subprocess.Popen, "__init__", no_start_during_load):
                exec(compile(ast.fix_missing_locations(unit), str(SOURCE), "exec"), ns)
                parent = ns["_load_bounded_process"]()
            self.assertEqual(Path(parent.__file__), stage / "_bounded_process.py")
            self.assertEqual(parent.LAUNCHER, stage / "_bounded_process_launcher.py")
            ns["_BOUNDED_PROCESS"] = parent
            stage_before = {str(path): original(path) for path in stage.iterdir()}
        except BaseException as initial_error:
            # No process constructor was allowed during this original loading.
            # This is owned source-only cleanup, never PID cleanup authority.
            try:
                shutil.rmtree(root)
            except BaseException as cleanup_error:
                OWNED_RESOURCE_RECORDS.append({
                    "phase": "SOURCE_LOAD_FAILED_NO_CONSTRUCTOR", "root": root,
                    "root_identity": root_identity, "processes": [],
                    "resource_state": "UNKNOWN", "errors": [
                        ("source_load", initial_error), ("source_root_cleanup", cleanup_error)]})
                if isinstance(initial_error, Exception) and not isinstance(cleanup_error, Exception):
                    raise
            raise
        pipe_originals = []
        events = []
        reservations = []
        process_objects = []
        parent_stream_slots = []
        primary = None
        cleanup = []
        restored = {}
        result = None
        real_pipe, real_killpg, real_waitpid = os.pipe, os.killpg, os.waitpid
        real_init = subprocess.Popen.__init__
        real_signal, real_wait = parent.signal_original_group, parent.wait_original_anchor
        real_backend = parent.run_bounded_anchored
        observations = []
        retained = {"case": case, "root": root, "root_identity": root_identity, "processes": process_objects,
                    "reservations": reservations, "pipes": pipe_originals, "streams": [],
                    "popen_class": subprocess.Popen, "reservation_class": parent.Reservation,
                    "phase": "BEFORE_CONSTRUCTOR",
                    "init_returned": False, "original_pid": None,
                    "actual_signal_attempted": False, "kernel_reaped": False,
                    "wait_ownership_lost": False, "rescue_actions": [], "errors": [],
                    "resource_state": "PENDING", "real_killpg": real_killpg,
                    "real_waitpid": real_waitpid, "anchor_clean": False}
        OWNED_RESOURCE_RECORDS.append(retained)
        bindings = [(os, "pipe"), (os, "killpg"), (os, "waitpid"),
                    (subprocess.Popen, "__init__"), (parent, "signal_original_group"),
                    (parent, "wait_original_anchor"), (socket, "socket"),
                    (socket, "create_connection"), (threading.Thread, "__init__"),
                    (threading.Thread, "start"), (subprocess, "run"),
                    (parent, "run_bounded_anchored")]
        bindings = [(obj, name, getattr(obj, name)) for obj, name in bindings]

        def deny(*_a, **_k):
            events.append({"kind": "FORBIDDEN_CAPABILITY"})
            raise AssertionError("unapproved real capability")

        def pipe():
            own_call = sys._getframe(1).f_code is real_backend.__code__
            if own_call:
                self.assertLess(len(pipe_originals), 4)
            ends = real_pipe()
            if own_call:
                roles = ("request_read", "request_write") if not pipe_originals else ("status_read", "status_write")
                new_rows = [{"role": role, "fd": fd, "identity": None} for role, fd in zip(roles, ends)]
                pipe_originals.extend(new_rows)  # Capture BOTH before first fstat.
                for row in new_rows:
                    metadata = os.fstat(row["fd"])
                    self.assertTrue(stat.S_ISFIFO(metadata.st_mode))
                    row["identity"] = [metadata.st_dev, metadata.st_ino, metadata.st_mode,
                                       metadata.st_uid, metadata.st_gid]
                if len(pipe_originals) == 4:
                    payload = json.dumps(pipe_originals, sort_keys=True, separators=(",", ":")).encode("ascii")
                    fd = os.open(root / "protocol-originals.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        self.assertEqual(os.write(fd, payload), len(payload))
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            return ends

        def init(process, argv, **kwargs):
            self.assertIs(sys._getframe(1).f_code, real_backend.__code__)
            self.assertEqual(len(process_objects), 0)
            self.assertEqual(argv[:4], [sys.executable, "-I", "-B", str(stage / "_bounded_process_launcher.py")])
            self.assertEqual(len(argv), 8)
            self.assertEqual(tuple(map(int, argv[4:6])), (pipe_originals[0]["fd"], pipe_originals[3]["fd"]))
            self.assertEqual(kwargs, {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE, "text": False, "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                "start_new_session": True, "close_fds": True,
                "pass_fds": (pipe_originals[0]["fd"], pipe_originals[3]["fd"])})
            process_objects.append(process)  # Strong original object, not PID-file authority.
            retained["phase"] = "CONSTRUCTOR_ENTERED_STRONG_OBJECT"
            try:
                answer = real_init(process, argv, **kwargs)
            except BaseException:
                retained["phase"] = "CONSTRUCTOR_RAISED_UNADMITTED"
                raise
            retained["init_returned"] = True
            retained["original_pid"] = process.pid
            retained["phase"] = "CONSTRUCTOR_DELEGATE_RETURNED"
            for role in ("stdout", "stderr"):
                stream = getattr(process, role)
                row = {"role": role, "fd": stream.fileno(), "identity": None}
                parent_stream_slots.append(row)
                retained["streams"].append(dict(row, stream=stream))
            for row, held in zip(parent_stream_slots, retained["streams"]):
                metadata = os.fstat(row["fd"])
                row["identity"] = [metadata.st_dev, metadata.st_ino, metadata.st_mode,
                                   metadata.st_uid, metadata.st_gid]
                held["identity"] = row["identity"]
            return answer

        def signal_group(reservation):
            reservations.append(reservation)
            retained["phase"] = "ORIGINAL_RESERVATION_SIGNAL_BOUNDARY"
            self.assertIs(reservation.process, process_objects[0])
            self.assertIsNone(reservation.process.returncode)
            self.assertFalse(reservation.wait_started)
            self.assertFalse(reservation.reaped)
            events.append({"kind": "SIGNAL_BOUNDARY", "unreaped": True})
            return real_signal(reservation)

        def killpg(pid, value):
            self.assertIs(sys._getframe(1).f_code, real_signal.__code__)
            reservation = reservations[-1]
            self.assertEqual(pid, reservation.pid)
            self.assertIs(reservation.process, process_objects[0])
            self.assertTrue(reservation.signal_attempted)
            self.assertFalse(reservation.wait_started)
            self.assertIsNone(reservation.process.returncode)
            self.assertEqual(value, signal.SIGKILL)
            retained["actual_signal_attempted"] = True  # Interrupted syscall never retried.
            answer = real_killpg(pid, value)
            events.append({"kind": "GROUP_SIGNAL_RETURN"})
            return answer

        def wait(reservation, timeout=1):
            self.assertEqual(timeout, 1)
            self.assertIs(reservation, reservations[-1])
            self.assertEqual(events[-1]["kind"], "GROUP_SIGNAL_RETURN")
            events.append({"kind": "WAIT_BOUNDARY", "timeout": timeout})
            return real_wait(reservation, timeout=timeout)

        def waitpid(pid, options):
            self.assertIs(sys._getframe(1).f_code, real_wait.__code__)
            self.assertEqual(pid, reservations[-1].pid)
            self.assertEqual(options, os.WNOHANG)
            try:
                answer = real_waitpid(pid, options)
            except ChildProcessError:
                retained["wait_ownership_lost"] = True
                raise
            if answer[0]:
                self.assertEqual(answer[0], retained["original_pid"])
                retained["kernel_reaped"] = True
                events.append({"kind": "ORIGINAL_ANCHOR_REAP", "raw_status": answer[1]})
            return answer

        def observed_backend(argv, timeout, env=None, stdin_text=None):
            observed = real_backend(argv, timeout, env=env, stdin_text=stdin_text)
            observations.append(observed)
            return observed

        try:
            self.assertEqual(stat.S_IMODE(root.lstat().st_mode), 0o700)
            with ExitStack() as stack:
                replacements = (pipe, killpg, waitpid, init, signal_group, wait,
                                deny, deny, deny, deny, deny, observed_backend)
                for (obj, name, _old), replacement in zip(bindings, replacements):
                    stack.enter_context(mock.patch.object(obj, name, replacement))
                started = time.monotonic()
                argv = [str(RUNTIME), "-I", "-B", str(stage / "bounded_inner_fd_fixture.py"), str(root), "normal17"]
                answer = ns["_run_bounded_process"](argv, 1.0,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "ANCHOR_LOCAL_LITERAL": "owned-normal17",
                         "__CF_USER_TEXT_ENCODING": "0x1F5:0:0"})
                self.assertEqual(len(observations), 1)
                result = observations[0]
                self.assertIs(type(answer), subprocess.CompletedProcess)
                self.assertIs(answer.args, argv)
                self.assertEqual((answer.returncode, answer.stdout, answer.stderr),
                                 (17, result.stdout.decode("utf-8", errors="ignore"),
                                  "OWNED-NORMAL17-STDERR\n"))
                self.assertLess(time.monotonic() - started, 1.5)
                print("CANONICAL_FD_RESULT " + json.dumps({"case": case, "returncode": result.returncode,
                    "command_status": result.command_status, "anchor_returncode": result.anchor_returncode,
                    "stop_reason": result.stop_reason, "stdout_length": len(result.stdout),
                    "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                    "stderr_length": len(result.stderr), "stderr_hex": result.stderr[:65536].hex(),
                    "python_fd_stdout_hex": result.stdout[:65536].hex()}), flush=True)
                self.assertEqual(result.returncode, 17)
                self.assertEqual(result.command_status["wait_status"], 17 << 8)
                self.assertEqual(result.command_status["returncode"], 17)
                self.assertNotEqual(result.command_status["command_pid"], reservations[0].pid)
                self.assertEqual(result.anchor_returncode, -signal.SIGKILL)
                self.assertIsNone(result.stop_reason)
                self.assertEqual(result.stderr, b"OWNED-NORMAL17-STDERR\n")
                body = json.loads(result.stdout.decode("ascii"))
                self.assertEqual(body["kind"], "OWNED_NORMAL17")
                self.assertEqual(body["argv_tail"], ["normal17"])
                self.assertIs(body["complete_literal_env_match"], True)
                self.assertEqual(body["protocol_slots"], [{"role": name, "state": "EBADF"} for name in
                    ("request_read", "request_write", "status_read", "status_write")])
                self.assertIs(body["no_original_pipe_alias"], True)
                enumerated = body["self_fd_enumeration"]
                self.assertTrue(3 <= len(enumerated) <= 128)
                self.assertTrue({0, 1, 2} <= {row["fd"] for row in enumerated})
                self.assertEqual(len({row["fd"] for row in enumerated}), len(enumerated))
                original_keys = {(row["identity"][0], row["identity"][1], stat.S_IFMT(row["identity"][2])) for row in pipe_originals}
                self.assertTrue(all(row["stable"] is True and tuple(row["key"]) not in original_keys for row in enumerated))
                self.assertEqual(body["protocol_evidence_sha256"], hashlib.sha256((root / "protocol-originals.json").read_bytes()).hexdigest())
                self.assertEqual(result.protocol_fd_counts, (4, 4, 4, 0))
                for row in pipe_originals + parent_stream_slots:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(row["fd"])
                    self.assertEqual(closed.exception.errno, errno.EBADF)
                for _phase, state, _fd in result.protocol_fd_events:
                    self.assertIn(state, ("CLOSE_ATTEMPT", "CLOSE_RETURN"))
                self.assertEqual([e["kind"] for e in events], ["SIGNAL_BOUNDARY", "GROUP_SIGNAL_RETURN", "WAIT_BOUNDARY", "ORIGINAL_ANCHOR_REAP"])
                self.assertTrue(reservations[0].reaped)
                for stream in (process_objects[0].stdout, process_objects[0].stderr):
                    self.assertTrue(stream.closed)
        except BaseException as error:
            primary = error
        finally:
            retained["primary"] = primary
            # Global retained owns the actual objects through driver tail.
            # Independent conditional fixture rescue is not product evidence.
            for obj, name, old in bindings:
                restored[name + ":" + str(id(obj))] = getattr(obj, name) is old
            try:
                rescue_owned_original(retained)
            except BaseException as error:
                retained["resource_state"] = "UNKNOWN"
                retained["errors"].append(("rescue_unfinished", error))
            cleanup.extend(error for _phase, error in retained["errors"])
            try:
                self.assertEqual({str(path): original(path) for path in stage.iterdir()}, stage_before)
            except BaseException as error:
                cleanup.append(error)
            safe = retained["anchor_clean"] and not retained["errors"]
            try:
                metadata = root.lstat()
                if safe and (metadata.st_dev, metadata.st_ino, metadata.st_uid) == root_identity:
                    shutil.rmtree(root)
                else:
                    raise AssertionError("UNKNOWN resource state; original root preserved, no PID adoption")
            except BaseException as error:
                cleanup.append(error)
            try:
                self.assertTrue(all(restored.values()))
                self.assertEqual(retained["resource_state"], "PRODUCT_CLEAN")
                self.assertEqual(retained["rescue_actions"], [])
                self.assertEqual({str(p): original(p) for p in PINS}, before)
                for cache in caches:
                    with self.assertRaises(FileNotFoundError):
                        cache.lstat()
                with self.assertRaises(FileNotFoundError):
                    root.lstat()
            except BaseException as error:
                cleanup.append(error)
            try:
                print("OWNED_WORKFLOW_FACTS " + json.dumps({"case": case, "events": events,
                    "owned_root": str(root), "owned_root_devino_uid": root_identity,
                    "outer_objects_captured_pre_init": len(process_objects),
                    "original_reservations_seen": len(reservations), "protocol_originals": pipe_originals,
                    "parent_stream_originals": parent_stream_slots,
                    "restored": restored, "root_removed": not root.exists(),
                    "constructor_phase": retained["phase"], "init_delegate_returned": retained["init_returned"],
                    "resource_state": retained["resource_state"], "rescue_actions": retained["rescue_actions"],
                    "cleanup_types": [type(e).__name__ for e in cleanup],
                    "cleanup_authority_policy": "ORIGINAL_OBJECT_ONLY_NOT_UNIVERSAL_PROOF"}), flush=True)
            except BaseException as error:
                cleanup.append(error)
                retained["errors"].append(("workflow_facts", error))
        chosen = (primary if primary is not None and not isinstance(primary, Exception)
                  else next((e for e in cleanup if not isinstance(e, Exception)), None)
                  or primary or (cleanup[0] if cleanup else None))
        if chosen is not None:
            raise chosen


if __name__ == "__main__":
    unittest.main(verbosity=2)
