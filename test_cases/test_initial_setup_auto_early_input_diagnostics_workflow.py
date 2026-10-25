"""Independent fixed-PUBLIC early input diagnostic workflows.

Five finite cases. Real guards/reads/pause/locks delegate; only reached external
fault outcomes are modeled. No old H1/early test or production API is replaced.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager, redirect_stdout, redirect_stderr
from functools import wraps
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cases import test_req10c_auto_contract as h1
from test_cases import test_initial_setup_auto_early_common_pause_workflow as early
from test_cases.module_loader import load_script

basis = early.basis
alias_identity = early.alias_identity
target_values = early.target_values
hold = early.hold
import stat

CREDENTIALS = ("auto.env credential input could not be safely validated; private "
               "permissions/mode, a qualified owner, and no symbolic links are required; "
               "device state is UNKNOWN")
COVERAGE = ("--auto requires one P2P management link for every CSV IB switch; "
            "fix CSV/P2P before starting a watch; device state is UNKNOWN")
GENERIC = "IB phase project authority failed; device state is UNKNOWN"
PAUSE = "auto watch pause could not be confirmed; operator HOLD; credentials preserved"
POISONS = ("PUBLIC-RAW-PROBE-auto.env-CSV/P2P", "/PUBLIC-PATH-PROBE/credential",
           "PUBLIC-CREDENTIAL-PROBE-not-a-secret")


@contextmanager
def _rejected_credential_seed(app, seed):
    real = app.read_auto_credentials
    seen = {"rejects": 0, "seeded": 0}

    @wraps(real)
    def read(path):
        try:
            return real(path)
        except app.SetupError:
            seen["rejects"] += 1
        # No successful core read is fabricated, and original except is over.
        seen["seeded"] += 1
        raise seed

    with mock.patch.object(app, "read_auto_credentials", new=read):
        yield seen


def _diagnostic_owned_scheduler(test, app, base, credentials=None, *, guard_kind,
                        expected_target=None, error_seed=None, expected_program=None):
    """Only H1: real early guard/pause, owned external scheduler and state."""
    from contextlib import ExitStack, contextmanager
    from functools import wraps
    import shlex
    import shutil
    import stat
    import subprocess

    @contextmanager
    def scope(base=base):
        def hold():
            error = RuntimeError("FIXTURE HOLD: H1 owned scheduler prerequisite unavailable")
            try:
                raise error from None
            except RuntimeError:
                error.__cause__ = error.__context__ = None
                raise

        if guard_kind not in ("world-mode", "symlink", "unlinked"):
            hold()
        if not all(getattr(os, key, 0) for key in ("O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY")):
            hold()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")

        def nine(info):
            return tuple(getattr(info, name) for name in fields)

        def snapshot(path):
            before = nine(path.lstat())
            if stat.S_ISLNK(before[2]):
                raw = os.readlink(path)
                if before != nine(path.lstat()):
                    hold()
                return before, raw
            if not stat.S_ISREG(before[2]) or before[5] != 1 or before[6] > 1048576:
                hold()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                if nine(os.fstat(fd)) != before:
                    hold()
                readings = []
                for _ in range(2):
                    os.lseek(fd, 0, os.SEEK_SET)
                    parts, total = [], 0
                    while True:
                        part = os.read(fd, min(65536, 1048577 - total))
                        if not part:
                            break
                        total += len(part)
                        if total > 1048576:
                            hold()
                        parts.append(part)
                    if nine(os.fstat(fd)) != before or nine(path.lstat()) != before:
                        hold()
                    readings.append(b"".join(parts))
                if readings[0] != readings[1] or len(readings[0]) != before[6]:
                    hold()
                return before, readings[0]
            finally:
                os.close(fd)

        def directory(path):
            path.mkdir(mode=0o700)
            path.chmod(0o700)  # This exact freshly created owned directory only.
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
                hold()

        def stage(path, raw, mode):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
            try:
                os.fchmod(fd, mode)
                offset = 0
                while offset < len(raw):
                    amount = os.write(fd, raw[offset:])
                    if type(amount) is not int or not 0 < amount <= len(raw) - offset:
                        hold()
                    offset += amount
                os.fsync(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.geteuid() or info.st_mode & 0o777 != mode
                        or info.st_size != len(raw)):
                    hold()
                sealed = nine(info)
            finally:
                os.close(fd)
            if snapshot(path) != (sealed, raw):
                hold()
            return sealed

        base = Path(base)
        tool = (base / "h1-owned-tool").resolve()
        directory(tool)
        state = tool / "xdr-initial-setup-logs"
        directory(state)
        bin_dir = tool / "bin"
        directory(bin_dir)
        original_source = snapshot(Path(app.__file__))
        script = tool / "initial-setup.py"
        stage(script, original_source[1], 0o600)  # Public source, identity route only; never executed.
        marker = state / "auto-watch.state"
        stage(marker, b"http-v3-req10c-auto-v1\n", 0o600)
        lock = state / "auto-crontab.lock"
        stage(lock, b"", 0o600)
        credential_path = (state / "auto.env" if credentials is None
                           else Path(os.path.abspath(credentials)))
        protected = {marker: snapshot(marker), script: snapshot(script), lock: snapshot(lock)}
        if guard_kind == "unlinked":
            if credentials is not None or os.path.lexists(credential_path):
                hold()
            if type(expected_target) is not app.Target:
                hold()
        else:
            protected[credential_path] = snapshot(credential_path)
            info = protected[credential_path][0]
            if guard_kind == "world-mode":
                if not stat.S_ISREG(info[2]) or info[3] != os.geteuid() or info[2] & 0o777 != 0o644:
                    hold()
            else:
                target_path = base / "real.env"
                if (not stat.S_ISLNK(info[2])
                        or protected[credential_path][1] != str(target_path)):
                    hold()
                protected[target_path] = snapshot(target_path)
                target_info = protected[target_path][0]
                if (not stat.S_ISREG(target_info[2]) or target_info[3] != os.geteuid()
                        or target_info[2] & 0o777 != 0o600):
                    hold()

        foreign = "17 * * * * /usr/bin/true # PUBLIC-H1-FOREIGN\n"
        own = ("*/10 * * * * cd " + shlex.quote(str(tool)) + " && "
               + shlex.join(["python3", str(script), "--auto", "--apply", "--yes",
                             "--credentials-file", str(credential_path)])
               + " # http-v3-req10c-auto\n")
        initial = foreign + own
        database = tool / "cron.db"
        stage(database, initial.encode("utf-8"), 0o600)
        fake = bin_dir / "crontab"
        program = (
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "p = pathlib.Path(os.environ['REQ10C_H1_CRON_DB'])\n"
            "if sys.argv[1:] == ['-l']:\n"
            "    sys.stdout.write(p.read_text(encoding='utf-8'))\n"
            "elif sys.argv[1:] == ['-']:\n"
            "    p.write_text(sys.stdin.read(), encoding='utf-8')\n"
            "else:\n"
            "    sys.exit(2)\n"
        )
        stage(fake, program.encode("ascii"), 0o700)
        fake_before = snapshot(fake)
        directory_seals = {path: nine(path.lstat()) for path in (tool, state, bin_dir)}
        real_run = subprocess.run
        real_pause = app._pause_auto_watch
        real_reader = app.read_auto_credentials
        real_coverage = app.require_auto_full_target_coverage
        seen = {"events": [], "scheduler": [], "writes": 0,
                "main_error": None, "seeded": 0}

        @wraps(real_run)
        def run(argv, *args, **kwargs):
            if type(argv) is not list or argv not in (["crontab", "-l"], ["crontab", "-"]):
                raise AssertionError("PUBLIC H1 unexpected external command; blocked before dispatch")
            if shutil.which("crontab") != str(fake) or snapshot(fake) != fake_before:
                hold()
            kind = "L" if argv == ["crontab", "-l"] else "W"
            seen["events"].append(kind + "_BEGIN")
            expected = initial if seen["writes"] == 0 else foreign
            payload_ok = kind != "W" or kwargs.get("input") == foreign
            result = real_run(argv, *args, **kwargs)
            seen["events"].append(kind + "_RETURN")
            seen["scheduler"].append(
                type(result.returncode) is int and result.returncode == 0
                and payload_ok and (kind != "L" or result.stdout == expected)
            )
            if kind == "W":
                seen["writes"] += 1
            return result

        @wraps(real_pause)
        def pause(actual_tool, actual_credentials):
            if actual_tool != tool or actual_credentials != credential_path:
                raise AssertionError("PUBLIC H1 pause attempted a foreign tool/state role")
            seen["events"].append("PAUSE_ENTRY")
            result = real_pause(actual_tool, actual_credentials)
            seen["events"].append("PAUSE_RETURN")
            return result

        @wraps(real_reader)
        def reader(path):
            if path != credential_path:
                raise AssertionError("PUBLIC H1 credential guard attempted a foreign input")
            seen["events"].append("TARGET_GUARD_ENTRY")
            try:
                return real_reader(path)
            except app.SetupError:
                seen["events"].append("TARGET_GUARD_REJECT")
            # Outside the real rejection except: seed context is not fabricated.
            seen["seeded"] += 1
            if not isinstance(error_seed, BaseException):
                hold()
            raise error_seed

        @wraps(real_coverage)
        def coverage(count, targets):
            cached = app.load_target_cache.return_value
            if (type(count) is not int or count != 2 or type(targets) is not list
                    or len(targets) != 1 or targets[0] is not expected_target
                    or type(cached) is not tuple or len(cached) != 2 or targets is not cached[1]):
                raise AssertionError("PUBLIC H1 coverage guard did not receive original actual fixture")
            seen["events"].append("TARGET_GUARD_ENTRY")
            try:
                return real_coverage(count, targets)
            except app.SetupError:
                seen["events"].append("TARGET_GUARD_REJECT")
            # Outside the real rejection except: seed context is not fabricated.
            seen["seeded"] += 1
            if not isinstance(error_seed, BaseException):
                hold()
            raise error_seed

        def forbidden_discovery(*args, **kwargs):
            raise AssertionError("PUBLIC H1 credential guard must precede input discovery")

        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {
                "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                "REQ10C_H1_CRON_DB": str(database), "PYTHONDONTWRITEBYTECODE": "1",
            }))
            stack.enter_context(mock.patch.object(app, "__file__", str(script)))
            stack.enter_context(mock.patch.object(subprocess, "run", new=run))
            stack.enter_context(mock.patch.object(app, "_pause_auto_watch", new=pause))
            if guard_kind == "unlinked":
                stack.enter_context(mock.patch.object(app, "require_auto_full_target_coverage", new=coverage))
                stack.enter_context(mock.patch.object(app.socket, "gethostname", return_value="PUBLIC-H1-MANAGEMENT"))
                stack.enter_context(mock.patch.object(app.socket, "getfqdn", return_value="PUBLIC-H1-MANAGEMENT.example.test"))
            else:
                stack.enter_context(mock.patch.object(app, "read_auto_credentials", new=reader))
                stack.enter_context(mock.patch.object(app, "discover_input_file", side_effect=forbidden_discovery))
            yield seen

        if expected_program is None:
            test.assertTrue(type(seen["main_error"]) is app.SetupError,
                            "actual known main error was not captured; details suppressed")
        else:
            test.assertTrue(seen["main_error"] is expected_program,
                            "actual program primary object was not preserved")
        seen["events"].append("MAIN_ERROR")
        test.assertEqual([
            "TARGET_GUARD_ENTRY", "TARGET_GUARD_REJECT", "PAUSE_ENTRY",
            "L_BEGIN", "L_RETURN", "L_BEGIN", "L_RETURN", "W_BEGIN", "W_RETURN",
            "L_BEGIN", "L_RETURN", "L_BEGIN", "L_RETURN", "PAUSE_RETURN", "MAIN_ERROR",
        ], seen["events"], "actual H1 guard/pause/scheduler order was not reached")
        test.assertTrue(len(seen["scheduler"]) == 5 and all(seen["scheduler"])
                        and seen["writes"] == 1,
                        "actual owned scheduler results or replacement input differ")
        test.assertTrue(database.read_bytes() == foreign.encode("utf-8"),
                        "pause did not preserve the independent foreign cron bytes")
        test.assertTrue(all(snapshot(path) == value for path, value in protected.items()),
                        "H1 pause changed protected input/marker/lock/source identity or bytes")
        test.assertTrue(snapshot(fake) == fake_before
                        and all(nine(path.lstat()) == value for path, value in directory_seals.items()),
                        "H1 owned fixture identities changed outside the authorized DB write")
        if guard_kind == "unlinked":
            test.assertTrue(not os.path.lexists(credential_path),
                            "unlinked pre-authority guard must preserve absent default auto.env")

    return scope()



@contextmanager
def _diagnostic_scenario(f, *, body=None, pause_fault=None, program=None, pause_program=None,
                         known_error=None):
    """No core success mocked; finite own-input/owned-cron fault boundaries."""
    app = f["app"]
    real_open, real_read, real_close, real_stat = os.open, os.read, os.close, os.fstat
    real_path_read, real_path_write = Path.read_text, Path.write_text
    watched = {str(f["cron"]): "cron", str(f["credentials"]): "env",
               str(f["marker"]): "marker",
               str(f["credentials"].parent / "auto-crontab.lock"): "lock"}
    real_load, real_pause = app.load_target_cache, app._pause_auto_watch
    real_ctor = app.ProjectPasswordPolicy.__init__
    initial_global = basis.bound_file(f["global_path"])
    initial_alias = alias_identity(f)
    global_identity = initial_global[0][:2]
    active = {}
    observed = dict(datafault=0, readfault=0, prefix=False, closed_input=0,
                    fixture_drain=[], ctor=0, ctor_depth=0, loads=0,
                    actual_tuple=None, actual_targets=None, payload_diff=False,
                    authority=False, publication=None, alias_absent=False,
                    pause_entries=0, pause_returns=0, pause_errors=[],
                    pause_reads=0, pause_writes=0, pause_commits=0,
                    pause_injected=0, postcommit=None, locks=0,
                    env_entries=0, actor=[], timeline=[], marker_entries=0,
                    pause_active=False, path_reads={key: 0 for key in watched.values()},
                    path_writes={key: 0 for key in watched.values()},
                    path_opens={key: 0 for key in watched.values()})
    def restriction_ready():
        return observed["datafault"] == 1 or observed["readfault"] == 1
    def entry(label, real):
        @wraps(real)
        def call(*args, **kwargs):
            # M0 data perturbation is not itself a SOURCE recognized throw.
            # Shared readonly OOB prefix is allowed until actual pause entry.
            observed["actor"].append((label, restriction_ready(),
                                      observed["pause_entries"] > 0))
            return real(*args, **kwargs)
        return call
    @wraps(real_ctor)
    def constructor(instance, *args, **kwargs):
        observed["ctor"] += 1
        observed["ctor_depth"] += 1
        try:
            return real_ctor(instance, *args, **kwargs)
        finally:
            observed["ctor_depth"] -= 1
    def path_access(path, table):
        if isinstance(path, (str, bytes, os.PathLike)):
            key = watched.get(os.fsdecode(path))
            if key is not None:
                observed[table][key] += 1
    def path_read(path, *args, **kwargs):
        path_access(path, "path_reads")
        return real_path_read(path, *args, **kwargs)
    def path_write(path, *args, **kwargs):
        path_access(path, "path_writes")
        return real_path_write(path, *args, **kwargs)
    def opening(name, flags, mode=0o777, *, dir_fd=None):
        path_access(name, "path_opens")
        fd = real_open(name, flags, mode, dir_fd=dir_fd)
        if observed["ctor_depth"] and flags & os.O_ACCMODE == os.O_RDONLY:
            info = real_stat(fd)
            if (info.st_dev, info.st_ino) == global_identity:
                active[fd] = global_identity
        return fd
    def own(fd):
        ident = active.get(fd)
        if ident is None:
            return False
        try:
            info = real_stat(fd)
        except OSError:
            return False
        return (info.st_dev, info.st_ino) == ident
    def reading(fd, size):
        ours = own(fd)
        part = real_read(fd, size)
        if (ours and part and body in ("ctor-known", "ctor-program")
                and observed["readfault"] == 0):
            observed["prefix"] = True
            observed["readfault"] += 1
            observed["timeline"].append("constructor-real-read-fault")
            if body == "ctor-program":
                raise program
            if known_error is not None:
                raise known_error
            raise OSError(errno.EACCES, "PUBLIC owned global read fault")
        return part
    def closing(fd):
        ours = own(fd)
        result = real_close(fd)
        if ours:
            active.pop(fd, None)
            observed["closed_input"] += 1
        return result
    @wraps(real_load)
    def loader(*args, **kwargs):
        observed["loads"] += 1
        admitted = real_load(*args, **kwargs)
        if body not in ("cache", "alias") or observed["datafault"]:
            return admitted
        if (type(admitted) is not tuple or len(admitted) != 2 or admitted[0] != 1
                or type(admitted[0]) is not int or type(admitted[1]) is not list
                or len(admitted[1]) != 1):
            hold()
        original = json.loads(basis.bound_file(f["cache"])[1])
        targets = target_values(admitted[1])
        if (original.get("targets") != targets or targets[0]["ib_port_alias"] != "eth0"
                or original.get("global") != str(f["global_path"].resolve(strict=True))
                or original["global"] is None or alias_identity(f) != initial_alias):
            hold()
        published = json.loads(json.dumps(original))
        if body == "cache":
            published["targets"][0]["ib_port_alias"] = "mgmt"
        raw = (json.dumps(published, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        sidecar = f["cache"].with_name(f["cache"].name + ".sha256")
        f["cache"].write_bytes(raw)
        sidecar.write_text(hashlib.sha256(raw).hexdigest() + "  " + f["cache"].name + "\n",
                           encoding="ascii")
        if body == "alias":
            if alias_identity(f) != initial_alias or basis.bound_file(f["global_path"]) != initial_global:
                hold()
            (f["tool"] / "01-global.yaml").unlink()
            observed["alias_absent"] = not os.path.lexists(f["tool"] / "01-global.yaml")
            if not observed["alias_absent"]:
                hold()
        if app._valid_cache_authority(published, f["csv"], f["p2p"],
                                      f["tool"] / "01-global.yaml") is not True:
            hold()
        observed["publication"] = (basis.bound_file(f["cache"]), basis.bound_file(sidecar))
        if (sidecar.read_text(encoding="ascii").split()
                != [hashlib.sha256(raw).hexdigest(), f["cache"].name]
                or observed["publication"][1][0][7] < observed["publication"][0][0][7]):
            hold()
        observed["actual_tuple"], observed["actual_targets"] = admitted, targets
        observed["payload_diff"] = target_values(admitted[1]) != published["targets"]
        observed["authority"] = True
        observed["datafault"] += 1
        observed["timeline"].append("admitted-data-fault")
        return admitted  # SAME genuine tuple and Targets, never reconstructed.
    @wraps(real_pause)
    def pause(*args, **kwargs):
        observed["pause_entries"] += 1
        observed["pause_active"] = True
        observed["timeline"].append("pause-entry")
        delegate = app.subprocess.run  # original invoke's real owned adapter
        def boundary(command, *values, **options):
            result = delegate(command, *values, **options)
            if command == ["crontab", "-l"]:
                observed["pause_reads"] += 1
                if observed["pause_reads"] == 1 and pause_fault in ("read-known", "read-program"):
                    observed["pause_injected"] += 1
                    if pause_fault == "read-program":
                        raise pause_program
                    raise OSError(errno.EACCES, "PUBLIC pause listing read fault")
            elif command == ["crontab", "-"]:
                observed["pause_writes"] += 1
                observed["pause_commits"] += 1
                if pause_fault == "committed-timeout":
                    observed["postcommit"] = basis.bound_file(f["cron"])
                    observed["pause_injected"] += 1
                    raise subprocess.TimeoutExpired(["crontab", "-"], 10)
            return result
        try:
            with mock.patch.object(app.subprocess, "run", new=boundary):
                result = real_pause(*args, **kwargs)
            observed["pause_returns"] += 1
            observed["timeline"].append("pause-return")
            return result
        except BaseException as error:
            observed["pause_errors"].append(error)
            raise
        finally:
            observed["pause_active"] = False
    real_lock = app._auto_crontab_lock
    @wraps(real_lock)
    def lock(*args, **kwargs):
        observed["locks"] += 1
        return real_lock(*args, **kwargs)
    real_env, real_marker = app.read_auto_credentials, app._auto_marker
    @wraps(real_env)
    def env(*args, **kwargs):
        observed["env_entries"] += 1
        return real_env(*args, **kwargs)
    @wraps(real_marker)
    def marker(*args, **kwargs):
        observed["marker_entries"] += 1
        return real_marker(*args, **kwargs)
    try:
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(Path, "read_text", new=path_read))
            stack.enter_context(mock.patch.object(Path, "write_text", new=path_write))
            for name, replacement in (("open", opening), ("read", reading), ("close", closing)):
                stack.enter_context(mock.patch.object(app.os, name, new=replacement))
            stack.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "__init__", new=constructor))
            stack.enter_context(mock.patch.object(app, "load_target_cache", new=loader))
            stack.enter_context(mock.patch.object(app, "_pause_auto_watch", new=pause))
            stack.enter_context(mock.patch.object(app, "_auto_crontab_lock", new=lock))
            stack.enter_context(mock.patch.object(app, "read_auto_credentials", new=env))
            stack.enter_context(mock.patch.object(app, "_auto_marker", new=marker))
            for name, label in (
                ("_authenticate_ib_read", "IB-selector"), ("run_on_ib", "IB"),
                ("_run_authorized_ib_command", "IB-write"), ("verify_ipv4_login", "IPv4"),
                ("verify_password_hash", "native"), ("confirm_first_device_change", "consent"),
                ("run_on_ethernet", "OOB-read"), ("install_oob_management_key", "OOB-write"),
                ("_write_auto_credentials", "writer"), ("_install_auto_watch", "install"),
                ("_remove_auto_watch", "complete-remove"), ("_save_auto_terminal", "terminal-save"),
            ):
                stack.enter_context(mock.patch.object(app, name, new=entry(label, getattr(app, name))))
            password = (app.ProjectPasswordPolicy.password)
            stack.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "password",
                                                  new=entry("target-fetch", password)))
            yield observed
    finally:
        for fd, ident in tuple(active.items()):
            try:
                info = real_stat(fd)
            except OSError as error:
                if error.errno == errno.EBADF:
                    hold()
                raise
            if (info.st_dev, info.st_ino) != ident:
                hold()
            real_close(fd)
            observed["fixture_drain"].append(fd)
            active.pop(fd, None)



class H1EarlyInputDiagnosticWorkflowTests(unittest.TestCase):
    # Explicit unbound receiver closure; never inherit another TestCase.
    fixture = early.EarlyAutoCommonPauseWorkflowTests.fixture
    events = early.EarlyAutoCommonPauseWorkflowTests.events
    p1 = early.EarlyAutoCommonPauseWorkflowTests.p1
    write_credentials = early.EarlyAutoCommonPauseWorkflowTests.write_credentials
    invoke = early.EarlyAutoCommonPauseWorkflowTests.invoke
    prepare = early.EarlyAutoCommonPauseWorkflowTests.prepare
    preserved = early.EarlyAutoCommonPauseWorkflowTests.preserved
    reached = early.EarlyAutoCommonPauseWorkflowTests.reached
    stopped = early.EarlyAutoCommonPauseWorkflowTests.stopped

    @classmethod
    def setUpClass(cls):
        raw = basis.bound_file(h1.INITIAL)[1]
        names = {node.name for node in ast.parse(raw).body
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        if not {"main", "read_auto_credentials", "require_auto_full_target_coverage",
                "_pause_auto_watch", "ProjectPasswordPolicy"} <= names:
            early.hold()
        early.EarlyAutoCommonPauseWorkflowTests.setUpClass.__func__(cls)

    def _app(self, base):
        return load_script("h1_diagnostic_" + base.name.replace("-", "_"), h1.INITIAL)

    def _safe_error(self, error, expected, *, facts=None):
        self.assertTrue(type(error) is self._actual_error_type
                        and error.args == (expected,)
                        and error.__cause__ is None and error.__context__ is None,
                        "fixed known error/type/empty chains differ; values suppressed")
        fields = vars(error)
        self.assertTrue(set(fields) <= {"cleanup_uncertain", "io_errno"},
                        "known diagnostic copied an unapproved attribute")
        self.assertTrue("cleanup_uncertain" not in fields
                        or fields["cleanup_uncertain"] is True,
                        "cleanup fact is not exact True")
        self.assertTrue("io_errno" not in fields or
                        type(fields["io_errno"]) is int and 1 <= fields["io_errno"] <= 255,
                        "IO fact is not a bounded builtin integer")
        if facts == "valid":
            self.assertTrue(fields.get("cleanup_uncertain") is True
                            and type(fields.get("io_errno")) is int
                            and fields.get("io_errno") == 13,
                            "existing bounded safety facts were lost")
        elif facts == "absent":
            self.assertTrue(not fields, "invalid or irrelevant metadata was copied")

    def _privacy(self, result, seed=None, *, program=False):
        text = result["stdout"] + result["stderr"]
        self.assertTrue(all(value not in text for value in POISONS),
                        "diagnostic streams exposed a PUBLIC sensitive-lookalike probe")
        if not program:
            error = result["error"]
            values = list(error.args) + list(vars(error).keys()) + list(vars(error).values())
            # Only closed booleans escape; never render an arbitrary exception.
            self.assertTrue(all(type(value) is not str or
                                all(probe not in value for probe in POISONS)
                                for value in values),
                            "known diagnostic retained an arbitrary probe")
        if seed is not None:
            self.assertTrue(result["error"] is not seed or program,
                            "known input error was returned instead of a fresh safe domain")

    def _low(self, app, base, seed, *, guard_kind, credentials=None,
             target=None, program=False):
        streams = (io.StringIO(), io.StringIO())
        actors = []
        if guard_kind == "unlinked":
            csv, p2p = base / "ib.csv", base / "p2p.dot"
            csv.write_bytes(b"PUBLIC original coverage CSV\n")
            p2p.write_bytes(b"PUBLIC original coverage P2P\n")
            argv = ["initial-setup.py", "--auto", "--ib-csv", str(csv),
                    "--p2p", str(p2p), "--target-cache", str(base / "target.json"),
                    "--report", str(base / "report.log"),
                    "--snapshot-dir", str(base / "snapshots")]
        else:
            argv = ["initial-setup.py", "--auto", "--credentials-file", str(credentials)]

        def forbid(label):
            def blocked(*args, **kwargs):
                actors.append(label)
                raise AssertionError("PUBLIC unexpected business entry after input refusal")
            return blocked

        with _diagnostic_owned_scheduler(
                self, app, base, credentials, guard_kind=guard_kind,
                expected_target=target, error_seed=seed,
                expected_program=seed if program else None) as seen:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(sys, "argv", argv))
                stack.enter_context(mock.patch.object(sys.stdin, "isatty",
                                                      return_value=guard_kind == "unlinked"))
                if guard_kind == "unlinked":
                    stack.enter_context(mock.patch.object(app, "load_target_cache",
                                                          return_value=(2, [target])))
                for name in ("_authenticate_ib_read", "run_on_ib", "run_on_ethernet",
                             "_run_authorized_ib_command", "verify_ipv4_login",
                             "verify_password_hash", "confirm_first_device_change",
                             "install_oob_management_key", "_write_auto_credentials",
                             "_install_auto_watch", "_remove_auto_watch", "_save_auto_terminal"):
                    stack.enter_context(mock.patch.object(app, name, new=forbid(name)))
                stack.enter_context(redirect_stdout(streams[0]))
                stack.enter_context(redirect_stderr(streams[1]))
                try:
                    app.main()
                except BaseException as error:
                    seen["main_error"] = error
                finally:
                    if app.REPORT_HANDLE is not None:
                        app.REPORT_HANDLE.close()
                        app.REPORT_HANDLE = None
        self.assertTrue(not actors, "input refusal dispatched a business actor")
        self.assertTrue(seen["seeded"] == 1,
                        "seed was not substituted after exactly one real guard rejection")
        return dict(error=seen["main_error"], stdout=streams[0].getvalue(),
                    stderr=streams[1].getvalue())

    def test_credential_known_poison_and_active_context_keep_fixed_private_policy(self):
        with tempfile.TemporaryDirectory(prefix="h1-diag-credential-") as folder:
            base = Path(folder)
            app = self._app(base)
            self._actual_error_type = app.SetupError
            credentials = base / "auto.env"
            credentials.write_bytes(b"NVOS_INITIAL_PASSWORD=PUBLIC-IN\nZTP_ETH_PASSWORD=PUBLIC-OO\n")
            credentials.chmod(0o644)
            renders = []

            class NoRenderKnown(app.SetupError):
                def __str__(self):
                    renders.append(True)
                    raise AssertionError("PUBLIC known exception was rendered")

            seed = NoRenderKnown(POISONS[0])
            seed.phase, seed.path, seed.credential = "target-coverage", POISONS[1], POISONS[2]
            seed.cleanup_uncertain, seed.errno = True, 13
            try:
                raise RuntimeError("PUBLIC active caller context")
            except RuntimeError:
                result = self._low(app, base, seed, guard_kind="world-mode",
                                   credentials=credentials)
            self._safe_error(result["error"], CREDENTIALS, facts="valid")
            self.assertTrue(not renders, "known diagnostic rendered the original error")
            self._privacy(result, seed)

    def test_actual_coverage_rejection_cannot_be_spoofed_as_credential_origin(self):
        with tempfile.TemporaryDirectory(prefix="h1-diag-coverage-") as folder:
            base = Path(folder)
            app = self._app(base)
            self._actual_error_type = app.SetupError
            ib = app.Device("EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                            "203.0.113.1", "", "", "")
            eth = app.Device("EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
                             "192.0.2.1", "", "", "")
            target = app.Target(ib, eth, "swp7", "eth0")
            seed = app.SetupError(POISONS[0])
            seed.phase, seed.path = "credentials-input", POISONS[1]
            seed.cleanup_uncertain, seed.errno, seed.io_errno = 1, True, 0
            result = self._low(app, base, seed, guard_kind="unlinked", target=target)
            self._safe_error(result["error"], COVERAGE, facts="absent")
            self._privacy(result, seed)

    def test_unrelated_actual_constructor_read_fault_with_input_tags_stays_generic(self):
        with tempfile.TemporaryDirectory(prefix="h1-diag-unrelated-") as folder:
            f = self.prepare(folder)
            self._actual_error_type = f["app"].SetupError
            seed = OSError(errno.EACCES, POISONS[0], POISONS[1])
            seed.phase, seed.code, seed.credential = "credentials-input", "target-coverage", POISONS[2]
            with _diagnostic_scenario(f, body="ctor-known", known_error=seed) as seen:
                result = self.invoke(f, "--auto", "--credentials-file",
                                     str(f["credentials"]), cron_round=True)
            self.reached(f, seen, "ctor-known")
            self.assertTrue(seen["env_entries"] == 1 and seen["pause_entries"] == 1
                            and seen["pause_returns"] == 1 and not seen["pause_errors"]
                            and seen["pause_reads"] == 4 and seen["pause_writes"] == 1
                            and seen["pause_commits"] == 1 and f["cron"].read_text() == early.FOREIGN,
                            "unrelated actual read/pause frontier did not complete")
            self._safe_error(result["error"], GENERIC)
            self._privacy(result, seed)
            self.stopped(seen, "ctor-known")
            self.preserved(f, seen)

    def test_input_specific_diagnostic_never_overrides_actual_precommit_pause_failure(self):
        with tempfile.TemporaryDirectory(prefix="h1-diag-pause-") as folder:
            f = self.prepare(folder)
            app = f["app"]
            self._actual_error_type = app.SetupError
            f["credentials"].chmod(0o644)
            f["env_before"] = basis.bound_file(f["credentials"])
            seed = app.SetupError(POISONS[0])
            with _rejected_credential_seed(app, seed) as edge:
                with _diagnostic_scenario(f, pause_fault="read-known") as seen:
                    result = self.invoke(f, "--auto", "--credentials-file",
                                         str(f["credentials"]), cron_round=True)
            self.assertTrue(edge["rejects"] == edge["seeded"] == 1
                            and seen["env_entries"] == 1,
                            "actual credential rejection did not precede modeled seed")
            self.assertTrue(seen["pause_entries"] == seen["locks"] == 1
                            and seen["pause_returns"] == 0 and len(seen["pause_errors"]) == 1
                            and seen["pause_reads"] == seen["pause_injected"] == 1
                            and seen["pause_writes"] == seen["pause_commits"] == 0
                            and basis.bound_file(f["cron"]) == f["cron_before"],
                            "actual first listing/precommit pause-failure edge not reached")
            self._safe_error(result["error"], PAUSE, facts="absent")
            self._privacy(result, seed)
            self.assertTrue(not seen["actor"] and not result["hashes"] and not result["prompts"],
                            "early input or pause failure acquired a business role")
            self.preserved(f, seen)

    def test_program_error_at_actual_input_boundary_keeps_original_object(self):
        with tempfile.TemporaryDirectory(prefix="h1-diag-program-") as folder:
            base = Path(folder)
            app = self._app(base)
            credentials = base / "auto.env"
            credentials.write_bytes(b"NVOS_INITIAL_PASSWORD=PUBLIC-IN\nZTP_ETH_PASSWORD=PUBLIC-OO\n")
            credentials.chmod(0o644)
            seed = RuntimeError("PUBLIC program says auto.env CSV/P2P " + POISONS[0])
            seed.phase, seed.path = "credentials-input", POISONS[1]
            original_args, original_attrs = seed.args, dict(vars(seed))
            result = self._low(app, base, seed, guard_kind="world-mode",
                               credentials=credentials, program=True)
            self.assertTrue(result["error"] is seed and seed.args == original_args
                            and vars(seed) == original_attrs
                            and seed.__cause__ is None and seed.__context__ is None,
                            "input callsite normalized or changed the program primary")
            self._privacy(result, program=True)


if __name__ == "__main__":
    unittest.main()
