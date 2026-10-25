"""Independent early eligible AUTO common-pause workflows; O draft, NOT RUN.

Actual CLI/C2/P1/loader/global/policy/pause/lock/crontab operations delegate.
Only owned external input/read/process faults are modeled. Original base5/129
and its invoke are immutable; this module uses a separately reviewed copy.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager, redirect_stdout, redirect_stderr
from functools import wraps
import errno
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import shlex
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_cases import test_initial_setup_target_credentials_workflow as basis

PUBLIC_INITIAL, PUBLIC_OOB = basis.PUBLIC_INITIAL, basis.PUBLIC_OOB
_OwnedTTY = basis._OwnedTTY
bound_file = basis.bound_file
FOREIGN = "3 4 * * * /PUBLIC/foreign-job # preserve-foreign\n"
PAUSE_ARGS = ("auto watch pause could not be confirmed; operator HOLD; credentials preserved",)
DEVICE_FIELDS = ("hostname", "dev_type", "login_ip", "eth0_prefix",
                 "eth0_gateway", "eth0_mac", "eth1_prefix", "eth1_gateway")


class _PrerequisiteHold(RuntimeError):
    pass


def hold():
    error = _PrerequisiteHold("FIXTURE HOLD: early AUTO fault boundary unavailable")
    try:
        raise error from None
    except _PrerequisiteHold:
        error.__cause__ = None
        error.__context__ = None
        raise


def job(f):
    """Independent complete PUBLIC canonical grammar, not a SUT output."""
    q = shlex.quote
    state = f["credentials"].parent
    return (
        "*/10 * * * * cd " + q(str(f["tool"]))
        + " && flock -w 0 " + q(str(state / "auto.lock"))
        + " " + q(str(Path(sys.executable).resolve())) + " " + q(str(f["source"]))
        + " --auto --apply --yes --credentials-file " + q(str(f["credentials"]))
        + " --execution-mode management --ib-csv " + q(str(f["csv"]))
        + " --p2p " + q(str(f["p2p"])) + " --target-cache " + q(str(f["cache"]))
        + " --report " + q(str(f["root"] / "out/report.log"))
        + " --snapshot-dir " + q(str(f["root"] / "out/snapshots"))
        + " >> " + q(str(state / "auto-cron.log"))
        + " 2>&1 # http-v3-req10c-auto\n"
    )


def target_values(targets):
    return [dict(ib={key: getattr(item.ib, key) for key in DEVICE_FIELDS},
                 ethernet={key: getattr(item.ethernet, key) for key in DEVICE_FIELDS},
                 ethernet_port=item.ethernet_port, ib_port_alias=item.ib_port_alias)
            for item in targets]


def alias_identity(f):
    alias = f["tool"] / "01-global.yaml"
    try:
        root, info = f["root"].lstat(), alias.lstat()
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid()
                or stat.S_IMODE(root.st_mode) & 0o077
                or alias.parent != f["tool"] or alias.name != "01-global.yaml"
                or not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or os.readlink(alias) != str(f["global_path"])
                or alias.resolve(strict=True) != f["global_path"].resolve(strict=True)):
            hold()
        return basis.nine(info), os.readlink(alias)
    except (OSError, ValueError):
        hold()


@contextmanager
def scenario(f, *, body=None, pause_fault=None, program=None, pause_program=None):
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


class EarlyAutoCommonPauseWorkflowTests(unittest.TestCase):
    fixture = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.fixture
    events = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.events
    p1 = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.p1
    write_credentials = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.write_credentials

    @classmethod
    def setUpClass(cls):
        _identity, raw = basis.bound_file(basis.INITIAL)
        if not any(isinstance(node, ast.FunctionDef) and node.name == "_pause_auto_watch"
                   for node in ast.parse(raw).body):
            raise RuntimeError("NOT_READY: preserve-env common pause API absent")
        basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.setUpClass.__func__(cls)

    def invoke(self, f, *options, cron_round=False, uncertain=False, execution_mode="management"):
        app, errors = f["app"], f["boundary_errors"]
        real_run, real_execve = subprocess.run, os.execve
        real_fork, real_killpg, real_kill = app.pty.fork, os.killpg, os.kill
        real_waitpid, real_clock = os.waitpid, time.monotonic
        child_slots = []
        actual_cleanup = []
        prompt_roles = []
        hash_checks = []
        stdout, stderr = io.StringIO(), io.StringIO()
        rc, domain = None, None
        argv = [str(f["source"]), "--ib-csv", str(f["csv"]), "--p2p", str(f["p2p"]),
                "--target-cache", str(f["cache"]), "--report", str(f["root"] / "out/report.log"),
                "--snapshot-dir", str(f["root"] / "out/snapshots"), "--connect-timeout", "2",
                "--execution-mode", execution_mode, *options]
        def fail(stage, exc):
            errors.append({"stage": stage, "exception_type": type(exc).__name__})
        def run(command, *args, **kwargs):
            try:
                if command == ["crontab", "-l"]:
                    self.assertFalse(args)
                    self.assertTrue(kwargs.get("capture_output") is True and kwargs.get("text") is True)
                    return subprocess.CompletedProcess(command, 0, f["cron"].read_text(), "")
                if command == ["crontab", "-"]:
                    self.assertFalse(args)
                    self.assertTrue(type(kwargs.get("input")) is str)
                    f["cron"].write_text(kwargs["input"], encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                worker = [sys.executable, "-I", "-S", "-B", str(f["source"].resolve()),
                          "--_verify-password"]
                if command == worker:
                    self.assertFalse(args)
                    self.assertTrue(kwargs.get("timeout") == 8 and kwargs.get("check") is False)
                    self.assertTrue(kwargs.get("env") == {
                        "PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"})
                    payload = json.loads(kwargs["input"])
                    hash_checks.append({"target": hmac.compare_digest(payload["password"], self.kat["PASSWORD"]),
                                        "IB": hmac.compare_digest(payload["hash"], self.kat["YESCRYPT"]),
                                        "supplied_bad": hmac.compare_digest(payload["password"], "PUBLIC-Wrong-Target-81!")})
                    return real_run(command, **kwargs)
                validator = shutil.which("ssh-keygen")
                if command == [validator, "-l", "-E", "sha256", "-f", "/dev/stdin"]:
                    self.assertFalse(args)
                    self.assertTrue(kwargs.get("timeout") == 10 and kwargs.get("check") is False)
                    return real_run(command, **kwargs)
                raise AssertionError("unexpected external subprocess boundary")
            except BaseException as exc:
                fail("subprocess.run", exc)
                raise
        def execvp(executable, command):
            try:
                self.assertEqual("ssh", executable)
                self.assertTrue(type(command) is list and command and command[0] == "ssh")
                real_execve(sys.executable, [sys.executable, "-I", "-S", "-B",
                             str(f["stub"]), str(f["config"]), *command[1:]], {
                    "PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"})
            except BaseException as exc:
                # This branch is in the owned PTY child. Parent RAM lists are
                # not shared; use the same PUBLIC receipt, never secret repr.
                raw = (json.dumps({"kind": "adapter-error", "stage": "execvp",
                                   "exception_type": type(exc).__name__}) + "\n").encode()
                fd = os.open(f["root"] / "transport-events.jsonl", os.O_WRONLY|os.O_APPEND|os.O_CREAT, 0o600)
                try:
                    os.write(fd, raw)
                finally:
                    os.close(fd)
                os._exit(86)
        def getpass(label):
            try:
                if cron_round:
                    raise AssertionError("cron must never prompt")
                if label.startswith("Ethernet password for EXAMPLE-JUMP01 "):
                    prompt_roles.append("OOB")
                    return PUBLIC_OOB
                if label in ("IB target password (admin): ", "Confirm IB target password: "):
                    prompt_roles.append("TARGET")
                    return self.kat["PASSWORD"]
                raise AssertionError("unknown interactive credential source")
            except BaseException as exc:
                fail("getpass", exc)
                raise
        def fork():
            pair = real_fork()
            if pair[0] > 0:
                child_slots.append({"pid": pair[0], "master": pair[1]})
            return pair
        def ready(pid):
            return uncertain and (f["root"] / "uncertain-ready").is_file() and any(
                slot["pid"] == pid for slot in child_slots)
        def killpg(pid, sig):
            if ready(pid):
                raise PermissionError(1, "PUBLIC modeled owned group signal refusal")
            return real_killpg(pid, sig)
        def kill(pid, sig):
            if ready(pid):
                raise PermissionError(1, "PUBLIC modeled owned signal refusal")
            return real_kill(pid, sig)
        def clock():
            return real_clock() + (1000 if uncertain and (f["root"] / "uncertain-ready").is_file() else 0)
        original_interactive = app.interactive_run
        def interactive(*args, **kwargs):
            try:
                return original_interactive(*args, **kwargs)
            except BaseException as exc:
                actual_cleanup.append(getattr(exc, "cleanup_uncertain", None) is True)
                raise
        clean_env = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                     "PYTHONDONTWRITEBYTECODE": "1",
                     "NVOS_INITIAL_PASSWORD": json.loads(f["config"].read_text())["initial"]}
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ, clean_env, clear=True))
                stack.enter_context(mock.patch.object(sys, "argv", argv))
                stack.enter_context(mock.patch.object(sys, "stdin", _OwnedTTY()))
                stack.enter_context(mock.patch.object(Path, "home", return_value=f["root"]))
                stack.enter_context(mock.patch.object(app.getpass, "getpass", new=getpass))
                stack.enter_context(mock.patch.object(app.subprocess, "run", new=run))
                stack.enter_context(mock.patch.object(app.os, "execvp", new=execvp))
                stack.enter_context(mock.patch.object(app.pty, "fork", new=fork))
                stack.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
                if uncertain:
                    stack.enter_context(mock.patch.object(app.os, "killpg", new=killpg))
                    stack.enter_context(mock.patch.object(app.os, "kill", new=kill))
                    stack.enter_context(mock.patch.object(app.time, "monotonic", new=clock))
                stack.enter_context(redirect_stdout(stdout))
                stack.enter_context(redirect_stderr(stderr))
                try:
                    rc = app.main()
                except BaseException as exc:
                    domain = exc
        finally:
            if app.REPORT_HANDLE is not None:
                app.REPORT_HANDLE.close()
                app.REPORT_HANDLE = None
            # Exceptional fixture custody is separate from SUT reap evidence.
            # Restore patches above first; exact known PID only, no scans.
            for slot in child_slots:
                try:
                    observed, _status = real_waitpid(slot["pid"], os.WNOHANG)
                except ChildProcessError:
                    continue
                if observed == 0:
                    try:
                        real_killpg(slot["pid"], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    real_waitpid(slot["pid"], 0)
                    actual_cleanup.append("FIXTURE_DRAIN_NOT_SUT")
        events = self.events(f)
        self.assertEqual([], errors, "external adapter failures must never become product PASS")
        self.assertEqual([], [e for e in events if e["kind"] == "adapter-error"],
                         "child-side adapter failure is fixture HOLD, not behavior rejection")
        def event_strings(value):
            if type(value) is str:
                yield value
            elif type(value) is dict:
                for key, member in value.items():
                    yield from event_strings(key)
                    yield from event_strings(member)
            elif type(value) is list:
                for member in value:
                    yield from event_strings(member)
        self.assertTrue(all(secret not in text for text in event_strings(events)
                            for secret in (self.kat["PASSWORD"], PUBLIC_INITIAL, PUBLIC_OOB,
                                           self.kat["SHA512"], self.kat["YESCRYPT"])),
                        "owned event records must not contain credential/KAT values")
        observation = dict(rc=rc, error=domain, prompts=prompt_roles, hashes=hash_checks,
                           cleanup=actual_cleanup, events=events, stdout=stdout.getvalue(),
                           stderr=stderr.getvalue())
        # Avoid leaking cleartext through assertEqual diagnostics.
        self.assertTrue(all(secret not in observation["stdout"] + observation["stderr"]
                            for secret in (self.kat["PASSWORD"], PUBLIC_INITIAL, PUBLIC_OOB,
                                           self.kat["SHA512"], self.kat["YESCRYPT"])),
                        "parent diagnostic streams must not contain credential/KAT values")
        f["observations"].append(observation)
        self.assertEqual(f["control_before"], bound_file(f["control"]))
        return observation


    def prepare(self, folder):
        f = self.fixture(Path(folder).resolve(), expiry=False, configured=True)
        text = f["csv"].read_text(encoding="ascii")
        old = "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n"
        if text.count(old) != 1:
            hold()
        f["csv"].write_text(text.replace(old, "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"),
                            encoding="ascii")
        self.p1(f)
        payload = json.loads(basis.bound_file(f["cache"])[1])
        self.assertTrue(payload["targets"][0]["ethernet"]["dev_type"] == "eth"
                        and payload["targets"][0]["ib_port_alias"] == "eth0"
                        and payload["global"] == str(f["global_path"].resolve(strict=True)),
                        "genuine C2/P1 did not admit the independent eligible fixture")
        self.write_credentials(f, self.kat["PASSWORD"])
        reads, writes = [], []
        def cron(command, *args, **kwargs):
            if command == ["crontab", "-l"]:
                reads.append(1)
                return subprocess.CompletedProcess(command, 0, f["cron"].read_text(), "")
            if command == ["crontab", "-"]:
                writes.append(1)
                f["cron"].write_text(kwargs["input"], encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError("PUBLIC prewatch adapter unknown command")
        with mock.patch.object(f["app"].subprocess, "run", new=cron):
            f["app"]._install_auto_watch(
                f["tool"], f["credentials"], f["csv"], f["p2p"], f["cache"],
                f["root"] / "out/report.log", f["root"] / "out/snapshots", force=False)
        self.assertTrue(len(reads) == 2 and len(writes) == 1
                        and f["cron"].read_text() == FOREIGN + job(f),
                        "real producer did not create the independent complete canonical job")
        f["protected"] = tuple(f[key] for key in
                               ("global_path", "csv", "p2p", "source", "control", "auth")) + (
            f["root"] / "infiniband/publickey/laptop.pub",
            f["root"] / "infiniband/publickey/mgmt-server.pub",
        )
        f["protected_before"] = [basis.bound_file(path) for path in f["protected"]]
        f["env_before"], f["marker_before"] = (basis.bound_file(f["credentials"]),
                                               basis.bound_file(f["marker"]))
        f["cron_before"] = basis.bound_file(f["cron"])
        f["lock"] = f["credentials"].parent / "auto-crontab.lock"
        f["lock_before"] = basis.bound_file(f["lock"])
        return f

    def preserved(self, f, seen):
        self.assertTrue(basis.bound_file(f["credentials"]) == f["env_before"]
                        and basis.bound_file(f["marker"]) == f["marker_before"],
                        "common pause rewrote or deleted supplied env or marker")
        self.assertTrue([basis.bound_file(path) for path in f["protected"]]
                        == f["protected_before"],
                        "early failure changed protected inputs/keys/control identity")
        self.assertTrue(basis.bound_file(f["lock"])[0][:2] == f["lock_before"][0][:2],
                        "pause deleted or replaced the persistent project lock")
        if seen["publication"] is not None:
            sidecar = f["cache"].with_name(f["cache"].name + ".sha256")
            self.assertTrue(seen["publication"] ==
                            (basis.bound_file(f["cache"]), basis.bound_file(sidecar)),
                            "SUT rewrote the deliberately qualified data publication")
        if seen["alias_absent"]:
            self.assertTrue(not os.path.lexists(f["tool"] / "01-global.yaml"),
                            "SUT recreated a disappeared admitted alias")
        self.assertTrue(not seen["fixture_drain"],
                        "fixture drain is not SUT global-input FD cleanup")

    def reached(self, f, seen, body):
        if body in ("cache", "alias"):
            if (seen["datafault"] != 1 or not seen["authority"]
                    or seen["actual_tuple"] is None):
                hold()
            self.assertTrue(target_values(seen["actual_tuple"][1]) == seen["actual_targets"],
                            "transparent loader changed its genuine returned Target objects")
            self.assertTrue(seen["payload_diff"] is (body == "cache")
                            and seen["alias_absent"] is (body == "alias"),
                            "actual admitted data fault differs from the independent single change")
        else:
            if seen["readfault"] != 1 or not seen["prefix"]:
                hold()
            self.assertTrue(seen["ctor"] > 0 and seen["closed_input"] == 1,
                            "actual constructor/input prefix did not close its real FD once")

    def stopped(self, seen, body):
        forbidden = []
        for label, disturbed, paused in seen["actor"]:
            if paused or (disturbed and (body.startswith("ctor") or label != "OOB-read")):
                forbidden.append(label)
        self.assertTrue(not forbidden,
                        "eligible refusal/pause allowed a later forbidden business actor")
        self.assertTrue(seen["marker_entries"] == 0,
                        "eligible failure changed or recreated the watch marker")

    def known(self, f, result, exact_pause=False):
        error = result["error"]
        self.assertTrue(error is not None or result["rc"] != 0,
                        "qualified known failure became normal success")
        if exact_pause:
            self.assertTrue(type(error) is f["app"].SetupError,
                            "unconfirmed pause lost its exact safe domain type")
            self.assertTrue(error.args == PAUSE_ARGS and error.__cause__ is None
                            and error.__context__ is None,
                            "known common pause did not preserve fixed safe error/empty chains")
        elif error is not None:
            self.assertTrue(type(error) is f["app"].SetupError
                            and error.__cause__ is None and error.__context__ is None,
                            "known early refusal retained an unsafe error type or chain")

    def test_basic_auto_cli_refusal_never_touches_existing_watch_state(self):
        for label, options, mode in (
                ("plan", ("--auto", "--plan"), "management"),
                ("ethernet", ("--auto",), "ethernet")):
            with self.subTest(cli=label), tempfile.TemporaryDirectory(
                    prefix="auto-early-cli-") as folder:
                f = self.prepare(folder)
                with scenario(f) as seen:
                    result = self.invoke(f, *options, "--credentials-file",
                                         str(f["credentials"]), cron_round=True,
                                         execution_mode=mode)
                self.known(f, result)
                self.assertTrue(seen["pause_entries"] == seen["locks"]
                                == seen["env_entries"] == seen["marker_entries"] == 0
                                and not any(seen["path_reads"].values())
                                and not any(seen["path_writes"].values())
                                and not any(seen["path_opens"].values()),
                                "invalid basic AUTO CLI entered state or pause")
                self.assertTrue(not seen["actor"] and not result["hashes"]
                                and not result["prompts"],
                                "basic CLI refusal acquired roles or dispatched a business actor")
                self.assertTrue(basis.bound_file(f["cron"]) == f["cron_before"],
                                "invalid CLI changed a preexisting real owned watch")
                self.preserved(f, seen)

    def test_real_eligible_early_known_faults_really_pause_and_preserve_roles(self):
        for body in ("cache", "alias", "ctor-known"):
            with self.subTest(body=body), tempfile.TemporaryDirectory(
                    prefix="auto-early-known-") as folder:
                f = self.prepare(folder)
                with scenario(f, body=body) as seen:
                    result = self.invoke(f, "--auto", "--credentials-file",
                                         str(f["credentials"]), cron_round=True)
                self.reached(f, seen, body)
                self.known(f, result)
                self.assertTrue(seen["pause_entries"] == seen["pause_returns"] == 1
                                and not seen["pause_errors"],
                                "known eligible failure did not actually complete one real pause")
                self.assertTrue(seen["pause_reads"] == 4
                                and seen["pause_writes"] == seen["pause_commits"] == 1
                                and seen["pause_injected"] == 0
                                and f["cron"].read_text() == FOREIGN,
                                "pause did not actually remove own job and qualify foreign-only readback")
                self.stopped(seen, body)
                self.preserved(f, seen)

    def test_real_common_pause_error_priority_and_committed_failure_are_not_rollback(self):
        for label, body, pause_fault in (
                ("body-program", "ctor-program", "read-known"),
                ("pause-program", "cache", "read-program"),
                ("both-known-committed", "cache", "committed-timeout")):
            with self.subTest(priority=label), tempfile.TemporaryDirectory(
                    prefix="auto-early-priority-") as folder:
                f = self.prepare(folder)
                body_program = RuntimeError("PUBLIC body program primary")
                pause_program = AssertionError("PUBLIC pause program primary")
                with scenario(f, body=body, pause_fault=pause_fault,
                              program=body_program, pause_program=pause_program) as seen:
                    result = self.invoke(f, "--auto", "--credentials-file",
                                         str(f["credentials"]), cron_round=True)
                self.reached(f, seen, body)
                self.assertTrue(seen["pause_entries"] == 1 and seen["pause_returns"] == 0
                                and len(seen["pause_errors"]) == 1
                                and seen["pause_injected"] == 1,
                                "actual common pause failure edge was not reached exactly once")
                if label == "both-known-committed":
                    self.known(f, result, exact_pause=True)
                    self.assertTrue(seen["pause_reads"] == 2
                                    and seen["pause_writes"] == seen["pause_commits"] == 1
                                    and seen["postcommit"] == basis.bound_file(f["cron"])
                                    and f["cron"].read_text() == FOREIGN,
                                    "uncertain committed pause was rolled back/retried or falsely qualified")
                else:
                    expected = body_program if label == "body-program" else pause_program
                    expected_args = (("PUBLIC body program primary",) if label == "body-program"
                                     else ("PUBLIC pause program primary",))
                    self.assertTrue(result["error"] is expected and expected.args == expected_args
                                    and expected.__cause__ is None and expected.__context__ is None,
                                    "body/pause program primary identity or original chains were changed")
                    self.assertTrue(seen["pause_reads"] == 1
                                    and seen["pause_writes"] == seen["pause_commits"] == 0
                                    and basis.bound_file(f["cron"]) == f["cron_before"],
                                    "prewrite pause fault changed or retried the original listing")
                self.stopped(seen, body)
                self.preserved(f, seen)


if __name__ == "__main__":
    unittest.main()
