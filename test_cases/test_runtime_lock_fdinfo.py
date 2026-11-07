"""Current-OFD Linux authority; private fdinfo model is not Native Linux proof."""
import ast
from contextlib import ExitStack
import fcntl
import errno
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_load_release_transaction as TX


LOAD = TX.LOAD
EX = fcntl.LOCK_EX | fcntl.LOCK_NB
SH = fcntl.LOCK_SH | fcntl.LOCK_NB
FIXED = b"pos:\t0\nflags:\t0100002\nmnt_id:\t31\nino:\t135941\nlock:\t1: FLOCK  ADVISORY  WRITE 548819 fc:01:135941 0 EOF\n"


def modeled_fdinfo(metadata, lock="WRITE"):
    prefix = f"pos:\t0\nflags:\t0100002\nmnt_id:\t31\nino:\t{metadata.st_ino}\n"
    if lock is not None:
        prefix += (f"lock:\t1: FLOCK ADVISORY {lock} 548819 "
                   f"{os.major(metadata.st_dev):02x}:{os.minor(metadata.st_dev):02x}:{metadata.st_ino} 0 EOF\n")
    return prefix.encode("ascii")


class RuntimeLockFDInfoTests(unittest.TestCase):
    def test_fixed_kernel_schema_matches_device_and_inode_without_current_pid_requirement(self):
        # Kernel Linux device 252:1 is 64513; Darwin's makedev encoding is
        # different. Only this fixed schema example models Linux geometry.
        metadata = SimpleNamespace(st_dev=64513, st_ino=135941)
        with mock.patch.object(LOAD.os, "major", return_value=252), mock.patch.object(LOAD.os, "minor", return_value=1):
            self.assertIsNone(LOAD._require_runtime_fdinfo_exclusive(FIXED, metadata))
            self.assertIsNone(LOAD._require_runtime_fdinfo_exclusive(FIXED.replace(b"548819", b"1"), metadata))

    def test_invalid_schema_and_nonexclusive_rows_never_grant_authority(self):
        metadata = SimpleNamespace(st_dev=64513, st_ino=135941)
        cases = [b"", FIXED[:40], FIXED[:-1], FIXED.replace(b"WRITE", b"READ"),
            FIXED.replace(b"FLOCK", b"POSIX"), FIXED.replace(b"ADVISORY", b"MANDATORY"),
            FIXED.replace(b"fc:01", b"fc:02"), FIXED.replace(b"fc:01", b"fd:01"),
            FIXED.replace(b"fc:01:135941", b"fc:01:135942"),
            FIXED.replace(b"0 EOF", b"1 EOF"), FIXED.replace(b"0 EOF", b"0 99"),
            FIXED.replace(b"1: FLOCK", b"x: FLOCK"), FIXED.replace(b"548819", b"creator"),
            FIXED.replace(b"fc:01", b"fc:+1"), FIXED.replace(b"lock:", b"lock :"),
            FIXED + b"lock:\t2: FLOCK ADVISORY WRITE 1 fc:01:135941 0 EOF\n",
            FIXED + b"lock:\tunknown\n", FIXED + b"unknown-field:\tvalue\n",
            FIXED + b"pos:\t0\n", FIXED + b"\0\n", FIXED + b"\xff\n"]
        for payload in cases:
            with self.subTest(payload=payload), mock.patch.object(LOAD.os, "major", return_value=252), \
                    mock.patch.object(LOAD.os, "minor", return_value=1):
                with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                    LOAD._require_runtime_fdinfo_exclusive(payload, metadata)

    def private_lock(self, root, lock=EX):
        path = root / ".deployment.lock"
        path.write_bytes(b"independent original lock\n")
        descriptor = os.open(path, os.O_RDWR)
        if lock is not None: fcntl.flock(descriptor, lock)
        self.addCleanup(os.close, descriptor)
        query = root / "private-fdinfo-model"
        query.mkdir()
        (query / str(descriptor)).write_bytes(modeled_fdinfo(os.fstat(descriptor),
            "WRITE" if lock == EX else "READ" if lock == SH else None))
        return path, descriptor, query

    def bind_linux_model(self, stack, path, query):
        stack.enter_context(mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path))
        stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
        stack.enter_context(mock.patch.object(LOAD, "_RUNTIME_LOCK_FDINFO_ROOT", query, create=True))

    def test_real_exclusive_and_dup_fds_are_checked_readonly_without_flock_calls(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path, descriptor, query = self.private_lock(Path(directory).resolve())
            self.bind_linux_model(stack, path, query)
            duplicate = os.dup(descriptor)
            self.addCleanup(os.close, duplicate)
            (query / str(duplicate)).write_bytes(modeled_fdinfo(os.fstat(duplicate)))
            with mock.patch.object(LOAD.fcntl, "flock", side_effect=AssertionError("guard mutates/probes lock")) as flock:
                LOAD._require_runtime_lock_guard(descriptor)
                LOAD._require_runtime_lock_guard(duplicate)
                flock.assert_not_called()
            witness = os.open(path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(witness, SH)
            finally:
                os.close(witness)

    def test_shared_and_unlocked_fds_are_rejected_without_upgrading(self):
        for lock in (SH, None):
            with self.subTest(lock=lock), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                path, descriptor, query = self.private_lock(Path(directory).resolve(), lock)
                self.bind_linux_model(stack, path, query)
                with mock.patch.object(LOAD.fcntl, "flock", side_effect=AssertionError("guard silently acquires EX")) as flock:
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                        LOAD._require_runtime_lock_guard(descriptor)
                    flock.assert_not_called()
                witness = os.open(path, os.O_RDWR)
                try: fcntl.flock(witness, SH)
                finally: os.close(witness)

    def test_proc_missing_truncated_or_oversize_read_is_failclosed_and_keeps_original_ex(self):
        for payload in (None, b"pos:\t0", b"x" * (65536 + 1)):
            with self.subTest(payload_size=None if payload is None else len(payload)), \
                    tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                path, descriptor, query = self.private_lock(Path(directory).resolve())
                row = query / str(descriptor)
                if payload is None: row.unlink()
                else: row.write_bytes(payload)
                self.bind_linux_model(stack, path, query)
                with mock.patch.object(LOAD.fcntl, "flock", side_effect=AssertionError("guard probes lock")):
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                        LOAD._require_runtime_lock_guard(descriptor)
                witness = os.open(path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError): fcntl.flock(witness, SH)
                finally: os.close(witness)

    def test_bounded_reader_completes_short_reads_without_closing_callers_fd(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path, descriptor, query = self.private_lock(Path(directory).resolve())
            self.bind_linux_model(stack, path, query)
            original_read = os.read
            with mock.patch.object(LOAD.os, "read", side_effect=lambda fd, size: original_read(fd, min(size, 7))):
                self.assertEqual(modeled_fdinfo(os.fstat(descriptor)), LOAD._read_runtime_lock_fdinfo(descriptor))
            self.assertEqual(path.stat().st_ino, os.fstat(descriptor).st_ino)

    def test_reader_io_failure_closes_only_its_query_fd_and_symlink_is_refused(self):
        for failure in ("read-eio", "query-symlink"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                path, descriptor, query = self.private_lock(Path(directory).resolve())
                self.bind_linux_model(stack, path, query)
                closed, original_close = [], os.close
                if failure == "query-symlink":
                    row = query / str(descriptor)
                    row.rename(query / "retained-row")
                    row.symlink_to("retained-row")
                def close(fd):
                    closed.append(fd)
                    return original_close(fd)
                with ExitStack() as observe:
                    observe.enter_context(mock.patch.object(LOAD.os, "close", side_effect=close))
                    if failure == "read-eio":
                        observe.enter_context(mock.patch.object(LOAD.os, "read", side_effect=OSError(errno.EIO, "private fdinfo fault")))
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock fdinfo unavailable"):
                        LOAD._require_runtime_lock_guard(descriptor)
                self.assertNotIn(descriptor, closed)
                self.assertEqual(1 if failure == "read-eio" else 0, len(closed))
                for fd in closed:
                    with self.assertRaises(OSError): os.fstat(fd)
                self.assertEqual(path.stat().st_ino, os.fstat(descriptor).st_ino)
                witness = os.open(path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError): fcntl.flock(witness, SH)
                finally: os.close(witness)

    def test_closed_wrong_inode_and_invalid_fd_are_zero_fdinfo_read(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path, descriptor, query = self.private_lock(Path(directory).resolve())
            self.bind_linux_model(stack, path, query)
            wrong = os.open(Path(directory) / "different-inode", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            closed = os.dup(descriptor)
            os.close(closed)
            try:
                with mock.patch.object(LOAD, "_read_runtime_lock_fdinfo", side_effect=AssertionError("query before FD/path identity")) as read:
                    for fd in (closed, wrong, None, True, 2, -1, "4"):
                        with self.subTest(fd=fd), self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                            LOAD._require_runtime_lock_guard(fd)
                    read.assert_not_called()
            finally: os.close(wrong)

    def test_actual_exec_inherits_original_ex_without_relocking_or_unlocking_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            path, descriptor, query = self.private_lock(Path(directory).resolve())
            script = "\n".join((
                "import fcntl, os, runpy, sys", "from pathlib import Path",
                "namespace=runpy.run_path(sys.argv[1])",
                "guard=namespace['_require_runtime_lock_guard']", "g=guard.__globals__",
                "g['runtime_os']=lambda:'Linux'", "g['DEPLOYMENT_LOCK']=Path(sys.argv[2])",
                "g['_RUNTIME_LOCK_FDINFO_ROOT']=Path(sys.argv[3])",
                "def forbidden(*args): raise AssertionError('child guard probes/relocks inherited FD')",
                "fcntl.flock=forbidden", "guard(int(sys.argv[4]))", "print('CHECKED_CURRENT_FD',flush=True)",
            ))
            result = subprocess.run([sys.executable, "-B", "-c", script, str(TX.ROOT / "DAY0-Prepare/11-load.py"),
                str(path), str(query), str(descriptor)], pass_fds=(descriptor,), cwd=Path(directory),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual("CHECKED_CURRENT_FD\n", result.stdout)
            witness = os.open(path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(witness, SH)
            finally: os.close(witness)

    def test_late_path_rebinding_and_same_inode_fd_reuse_are_rejected(self):
        for change in ("path", "fd"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root = Path(directory).resolve()
                path, descriptor, query = self.private_lock(root)
                self.bind_linux_model(stack, path, query)
                real_read = LOAD._read_runtime_lock_fdinfo
                changed = []
                def read(fd):
                    payload = real_read(fd)
                    if not changed:
                        changed.append(change)
                        if change == "path":
                            path.rename(root / "held-old-lock")
                            path.write_bytes(b"independent original lock\n")
                        else:
                            os.close(descriptor)
                            replacement = os.open(path, os.O_RDWR)
                            self.assertEqual(descriptor, replacement)
                            (query / str(descriptor)).write_bytes(modeled_fdinfo(os.fstat(descriptor), None))
                    return payload
                with mock.patch.object(LOAD, "_read_runtime_lock_fdinfo", side_effect=read), \
                        mock.patch.object(LOAD.fcntl, "flock", side_effect=AssertionError("guard probes lock")):
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                        LOAD._require_runtime_lock_guard(descriptor)
                self.assertEqual([change], changed)
                if change == "fd":
                    witness = os.open(path, os.O_RDWR)
                    try: fcntl.flock(witness, SH)
                    finally: os.close(witness)

    def test_foreign_process_release_cannot_turn_unlocked_caller_into_ex_owner(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            path, descriptor, query = self.private_lock(Path(directory).resolve(), None)
            self.bind_linux_model(stack, path, query)
            child = subprocess.Popen([sys.executable, "-I", "-B", "-c", "\n".join((
                "import fcntl, os, sys", "fd=os.open(sys.argv[1],os.O_RDWR)",
                "fcntl.flock(fd,fcntl.LOCK_EX)", "print('HELD',flush=True)",
                "assert sys.stdin.readline().strip()=='RELEASE'", "fcntl.flock(fd,fcntl.LOCK_UN)",
                "print('RELEASED',flush=True)", "assert sys.stdin.readline().strip()=='FINISH'")), str(path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            def receive(expected):
                self.assertTrue(select.select([child.stdout], [], [], 10)[0])
                self.assertEqual(expected + "\n", child.stdout.readline())
            observed = []
            def read(fd):
                self.assertEqual(descriptor, fd)
                observed.append("caller has no lock")
                child.stdin.write("RELEASE\n"); child.stdin.flush()
                receive("RELEASED")
                return modeled_fdinfo(os.fstat(fd), None)
            try:
                receive("HELD")
                with mock.patch.object(LOAD, "_read_runtime_lock_fdinfo", side_effect=read, create=True), \
                        mock.patch.object(LOAD.fcntl, "flock", side_effect=AssertionError("guard probes/acquires EX")):
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                        LOAD._require_runtime_lock_guard(descriptor)
                self.assertEqual(["caller has no lock"], observed)
                witness = os.open(path, os.O_RDWR)
                try: fcntl.flock(witness, SH)
                finally: os.close(witness)
            finally:
                if child.poll() is None:
                    if not observed:
                        child.stdin.write("RELEASE\n"); child.stdin.flush()
                        receive("RELEASED")
                    child.stdin.write("FINISH\n"); child.stdin.flush()
                try: child.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill(); child.communicate()


class RuntimeLockFDInfoWorkflowTests(unittest.TestCase):
    def test_original_rendezvous_and_late_name_injections_on_linux_read_boundary(self):
        cases = (("test_runtime_lock_guard_foreign_owner_release_between_probes_is_not_authority", None),
                 ("test_runtime_lock_guard_late_probe_name_rebind_retains_both_owners", "WRITE"))
        for method, declared_lock in cases:
            with self.subTest(method=method):
                fixture = TX.ReleaseTransactionTests(method)
                fixture.setUp()
                observed = []
                def read(fd):
                    if observed: self.assertEqual(observed[0], fd)
                    observed.append(fd)
                    return modeled_fdinfo(os.fstat(fd), declared_lock)
                try:
                    with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                            mock.patch.object(LOAD, "_read_runtime_lock_fdinfo", side_effect=read):
                        getattr(fixture, method)()
                    self.assertEqual(1, len(observed), "the real new injection boundary must execute")
                finally:
                    fixture.tearDown()
                    fixture.doCleanups()


from test_cases import linux_runtime_lock_model as MODEL_PORT


def _enter_context(testcase, manager):
    """TestCase.enterContext for the formal CLT CPython 3.9 interpreter.

    Same steps as CPython 3.11's unittest.case._enter_context: look the special
    methods up on the type, enter now, and register exit as a LIFO cleanup.
    """
    manager_type = type(manager)
    try:
        enter = manager_type.__enter__
        exit_ = manager_type.__exit__
    except AttributeError:
        raise TypeError(
            f"'{manager_type.__module__}.{manager_type.__qualname__}' object does "
            "not support the context manager protocol"
        ) from None
    result = enter(manager)
    testcase.addCleanup(exit_, manager, None, None, None)
    return result


class DarwinFixtureLinuxFDInfoPortTests(unittest.TestCase):
    """Only Linux-manager fixtures on Darwin receive the declared model."""

    def private_real_lock(self, mode=EX):
        directory = _enter_context(self, tempfile.TemporaryDirectory(prefix="declared-fdinfo-"))
        path = Path(directory).resolve() / ".deployment.lock"
        path.write_bytes(b"independent real native lock")
        descriptor = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, descriptor)
        if mode is not None:
            fcntl.flock(descriptor, mode)
        _enter_context(self, mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path))
        _enter_context(self, mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
        return path, descriptor

    def test_real_exclusive_fd_passes_both_original_guard_and_declared_port(self):
        path, descriptor = self.private_real_lock()
        original_reader = LOAD._read_runtime_lock_fdinfo
        original_guard = LOAD._require_runtime_lock_guard
        with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD):
            self.assertIs(original_guard, LOAD._require_runtime_lock_guard)
            LOAD._require_runtime_lock_guard(descriptor)
        self.assertIs(original_reader, LOAD._read_runtime_lock_fdinfo)
        witness = os.open(path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(witness, SH)
        finally:
            os.close(witness)

    def test_darwin_port_runs_native_guard_before_modeling_current_identity(self):
        path, descriptor = self.private_real_lock()
        native = LOAD._require_runtime_lock_guard
        with mock.patch.object(LOAD, "_require_runtime_lock_guard", wraps=native) as guard:
            with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD):
                payload = LOAD._read_runtime_lock_fdinfo(descriptor)
                if sys.platform == "darwin":
                    guard.assert_called_once_with(descriptor)
                else:
                    guard.assert_not_called()
                LOAD._require_runtime_fdinfo_exclusive(payload, os.fstat(descriptor))
        self.assertEqual(path.lstat().st_ino, os.fstat(descriptor).st_ino)

    def test_duplicate_original_fd_is_valid_without_replacing_the_lock_inode(self):
        path, descriptor = self.private_real_lock()
        duplicate = os.dup(descriptor)
        self.addCleanup(os.close, duplicate)
        before = path.lstat().st_ino
        with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD):
            LOAD._require_runtime_lock_guard(duplicate)
        self.assertEqual(before, path.lstat().st_ino)
        self.assertEqual(before, os.fstat(descriptor).st_ino)

    def test_shared_and_unlocked_descriptors_remain_rejected(self):
        for mode in (SH, None):
            with self.subTest(mode=mode), ExitStack() as stack:
                directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="nonexclusive-fdinfo-"))
                path = Path(directory).resolve() / ".deployment.lock"
                path.write_bytes(b"independent nonexclusive")
                descriptor = os.open(path, os.O_RDWR)
                try:
                    if mode is not None:
                        fcntl.flock(descriptor, mode)
                    stack.enter_context(mock.patch.object(LOAD, "DEPLOYMENT_LOCK", path))
                    stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
                    stack.enter_context(MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD))
                    with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                        LOAD._require_runtime_lock_guard(descriptor)
                    witness = os.open(path, os.O_RDWR)
                    try:
                        fcntl.flock(witness, SH)
                    finally:
                        os.close(witness)
                finally:
                    os.close(descriptor)

    def test_foreign_open_description_cannot_borrow_original_exclusive_lock(self):
        path, owner = self.private_real_lock()
        foreign = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, foreign)
        with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD):
            with self.assertRaisesRegex(LOAD.LoadError, "deployment lock"):
                LOAD._require_runtime_lock_guard(foreign)
            LOAD._require_runtime_lock_guard(owner)

    def test_original_fd_path_rebinding_check_is_not_replaced(self):
        path, descriptor = self.private_real_lock()
        retained = path.with_name("original-held-lock")
        path.rename(retained)
        path.write_bytes(b"independent foreign path")
        before = retained.lstat().st_ino
        with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD):
            with self.assertRaisesRegex(LOAD.LoadError, "deployment lock identity"):
                LOAD._require_runtime_lock_guard(descriptor)
        self.assertEqual(before, os.fstat(descriptor).st_ino)
        self.assertEqual(before, retained.lstat().st_ino)

    def test_exception_restores_query_port_and_runtime_os(self):
        path, descriptor = self.private_real_lock()
        reader, runtime = LOAD._read_runtime_lock_fdinfo, LOAD.runtime_os
        with self.assertRaisesRegex(RuntimeError, "independent fixture body failure"):
            with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(LOAD):
                LOAD._require_runtime_lock_guard(descriptor)
                raise RuntimeError("independent fixture body failure")
        self.assertIs(reader, LOAD._read_runtime_lock_fdinfo)
        self.assertIs(runtime, LOAD.runtime_os)

    def test_linux_host_branch_keeps_real_query_and_never_enters_darwin_guard(self):
        reader, guard = object(), mock.Mock()
        api = SimpleNamespace(_read_runtime_lock_fdinfo=reader, _require_runtime_lock_guard=guard)
        with mock.patch.object(sys, "platform", "linux"):
            with MODEL_PORT.declared_linux_fdinfo_for_darwin_fixture(api):
                self.assertIs(reader, api._read_runtime_lock_fdinfo)
        self.assertIs(reader, api._read_runtime_lock_fdinfo)
        guard.assert_not_called()


# A child program that replaces the LOAD module's runtime_os with a constant
# "Linux" models a Linux manager.  On actual Darwin the production Linux branch
# of _require_runtime_lock_guard then reads /proc/self/fdinfo, which does not
# exist, and HOLDs before the behaviour under test.  197839a declared one port
# for exactly this case (linux_runtime_lock_model.declared_linux_fdinfo_for_darwin_fixture);
# every LOAD entry point that such a child calls must run inside it, or the child
# must install its own declared _read_runtime_lock_fdinfo model first.
LOAD_ENTRY_POINTS = ("main", "recover_setup_switch_journal")
DECLARED_PORT = "declared_linux_fdinfo_for_darwin_fixture"


def _assigns_linux_runtime_os(statement, module_name):
    for node in ast.walk(statement):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (isinstance(target, ast.Attribute) and target.attr == "runtime_os"
                    and isinstance(target.value, ast.Name) and target.value.id == module_name
                    and isinstance(node.value, ast.Lambda)
                    and isinstance(node.value.body, ast.Constant)
                    and node.value.body.value == "Linux"):
                return True
    return False


def _assigns_declared_reader(statement, module_name):
    return any(
        isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Attribute) and target.attr == "_read_runtime_lock_fdinfo"
            and isinstance(target.value, ast.Name) and target.value.id == module_name
            for target in node.targets)
        for node in ast.walk(statement))


def _is_declared_port(expression, module_name):
    if not isinstance(expression, ast.Call) or len(expression.args) != 1:
        return False
    func = expression.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    argument = expression.args[0]
    return (name == DECLARED_PORT and isinstance(argument, ast.Name)
            and argument.id == module_name)


def unported_linux_load_entries(program):
    """(line, entry) of LOAD entry calls that model Linux without the declared port.

    A call ``X.main(...)``/``X.recover_setup_switch_journal(...)`` models Linux when a
    statement ``X.runtime_os = lambda...: "Linux"`` precedes it in the same or an
    enclosing block (anywhere inside that earlier statement; a nested def inherits
    its enclosing blocks, conservatively).  It is ported when an
    enclosing ``with`` enters ``declared_linux_fdinfo_for_darwin_fixture(X)``, when an
    earlier statement of the same or an enclosing block enters it through
    ``<stack>.enter_context``, or when such an earlier statement assigns
    ``X._read_runtime_lock_fdinfo``.  Syntax only.
    """
    parents = {}
    for parent in ast.walk(program):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    findings = []
    for call in ast.walk(program):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr in LOAD_ENTRY_POINTS
                and isinstance(call.func.value, ast.Name)):
            continue
        module_name = call.func.value.id
        linux = ported = False
        child = call
        while child in parents:
            parent = parents[child]
            if isinstance(parent, (ast.With, ast.AsyncWith)) and child in parent.body:
                ported = ported or any(_is_declared_port(item.context_expr, module_name)
                                       for item in parent.items)
            for _field, value in ast.iter_fields(parent):
                if isinstance(value, list) and child in value:
                    for earlier in value[:value.index(child)]:
                        if not isinstance(earlier, ast.stmt):
                            continue
                        linux = linux or _assigns_linux_runtime_os(earlier, module_name)
                        ported = ported or _assigns_declared_reader(earlier, module_name)
                        ported = ported or any(
                            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "enter_context" and len(node.args) == 1
                            and _is_declared_port(node.args[0], module_name)
                            for node in ([earlier.value] if isinstance(earlier, ast.Expr) else []))
            child = parent
        if linux and not ported:
            findings.append((call.lineno, call.func.attr))
    return findings


def unported_linux_child_programs(paths):
    """file:line:entry for every unported Linux-modelling LOAD call in child program literals."""
    findings = []
    for path in paths:
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if "runtime_os" not in text:
            continue
        for node in ast.walk(ast.parse(text, filename=str(path))):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and "runtime_os" in node.value):
                continue
            try:
                program = ast.parse(node.value)
            except SyntaxError:
                continue
            findings.extend(f"{path.name}:{node.lineno + line - 1}:{entry}"
                            for line, entry in unported_linux_load_entries(program))
    return sorted(findings)


class LinuxModelChildProgramPortTests(unittest.TestCase):
    """Child programs that model Linux on Darwin must use the declared fdinfo port."""

    def test_scanner_flags_only_unported_linux_entries(self):
        # Joined at run time from separate one-line literals, so this control is
        # not itself a whole child-program literal for the repository scan below.
        program = "".join((
            "import sys\n",
            "load = object()\n",
            "load.runtime_os = lambda: 'Linux'\n",
            "load.main([])\n",                                                   # 4 flagged
            "with declared_linux_fdinfo_for_darwin_fixture(load):\n",
            "    load.main([])\n",
            "with port.declared_linux_fdinfo_for_darwin_fixture(load):\n",
            "    load.recover_setup_switch_journal(path)\n",
            "with port.declared_linux_fdinfo_for_darwin_fixture(other):\n",
            "    load.recover_setup_switch_journal(path)\n",                       # 10 flagged
            "if sys.argv[1] == 'linux':\n",
            "    other.runtime_os = lambda: 'Linux'\n",
            "else:\n",
            "    other.main([])\n",                                               # 14 native
            "other.main([])\n",                                                   # 15 flagged
            "def later():\n",
            "    load.main([])\n",                                                # 17 flagged
            "native = object()\n",
            "native.runtime_os = lambda: 'Darwin'\n",
            "native.main([])\n",
            "modelled = object()\n",
            "modelled.runtime_os = lambda: 'Linux'\n",
            "modelled._read_runtime_lock_fdinfo = lambda fd: b''\n",
            "modelled.main([])\n",
            "stacked = object()\n",
            "stacked.runtime_os = lambda: 'Linux'\n",
            "stack.enter_context(declared_linux_fdinfo_for_darwin_fixture(stacked))\n",
            "stacked.recover_setup_switch_journal(path)\n",
        ))
        self.assertEqual(
            [(4, "main"), (10, "recover_setup_switch_journal"), (15, "main"), (17, "main")],
            sorted(unported_linux_load_entries(ast.parse(program))),
        )
        with tempfile.TemporaryDirectory(prefix="linux-model-child-") as directory:
            path = Path(directory) / "synthetic_case.py"
            path.write_text("PROGRAM = '''" + program + "'''\n", encoding="utf-8")
            # The literal and its first program line both start on file line 1.
            self.assertEqual(
                ["synthetic_case.py:10:recover_setup_switch_journal",
                 "synthetic_case.py:15:main", "synthetic_case.py:17:main",
                 "synthetic_case.py:4:main"],
                unported_linux_child_programs([path]),
            )

    def test_test_child_programs_that_model_linux_use_the_declared_port(self):
        cases = Path(__file__).resolve().parent
        self.assertEqual([], unported_linux_child_programs(sorted(cases.glob("*.py"))))
