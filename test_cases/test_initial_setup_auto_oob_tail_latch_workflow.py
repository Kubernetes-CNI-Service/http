"""Eligible eth AUTO tail/latch workflows; independent O tests-first, NOT RUN.

Real C2/CSV/P1/cache/MAIN/policy/native/PTY/frame/KEY/OOB shell execute only
on future Root issuance. SSH/crontab/owned signal denials are external MODELS.
No old TestCase inheritance or edits; no native SSH/device/cross-run UNKNOWN.
"""
from __future__ import annotations
import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from functools import wraps
import hashlib
import hmac
import inspect
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_cases import test_initial_setup_target_credentials_workflow as basis

PUBLIC_INITIAL, PUBLIC_OOB = basis.PUBLIC_INITIAL, basis.PUBLIC_OOB
FOREIGN_CRON = "3 4 * * * /PUBLIC/foreign-job # preserve-foreign\n"
PUBLIC_BAD_TARGET = "PUBLIC-Wrong-Target-81!"
GLOBAL_SUFFIX = b"# PUBLIC changed after authenticated read, before next mutation\n"
bound_file, _OwnedTTY = basis.bound_file, basis._OwnedTTY
READ = ["nv", "config", "show", "-o", "commands"]
CANONICAL_RECEIPTS = ("IBSW_PUBLIC_KEYS_UPDATED", "IBSW_PUBLIC_KEYS_UNCHANGED")

OOB_KEY_PROGRAM = r'''
def oob_key_program(command):
    if (len(command) != 5 or command[:2] != ["sh", "-c"] or command[3] != "--"
            or hashlib.sha256(command[2].encode()).hexdigest() != C["key_script_sha256"]):
        raise ValueError("unqualified direct OOB key carrier")
    if base64.b64decode(command[4], validate=True) != C["oob_management_line"].encode("ascii"):
        raise ValueError("unqualified direct OOB PUBLIC key input")
    home = root / "oob-remote-home"
    env = dict(PATH=os.defpath, HOME=str(home), LC_ALL="C", LANG="C")
    completed = subprocess.run(command, capture_output=True, text=True,
                               timeout=5, check=False, env=env)
    allowed = ("IBSW_PUBLIC_KEYS_UPDATED\n", "IBSW_PUBLIC_KEYS_UNCHANGED\n")
    record("oob-key-shell", actual_rc=completed.returncode,
           receipt=completed.stdout[:-1] if completed.stdout in allowed else "NONCANONICAL",
           own_home=env["HOME"] == str(home))
    emit(completed.stdout)
    return completed.returncode
'''
OOB_BRANCH = '''    if len(logical) == 5 and logical[:2] == ["sh", "-c"] and logical[3] == "--":
        return oob_key_program(logical)
'''
OWN_HOME_CHECK = '''if os.environ.get("HOME") != str(root / "ssh-process-home"):
    raise ValueError("owned SSH HOME qualification unavailable")
'''


class _W2FixtureHold(RuntimeError):
    pass


def _hold():
    raise _W2FixtureHold("FIXTURE HOLD: W2 external capability or actual UNKNOWN boundary unavailable") from None


def _peer_program():
    source = basis.SSH_PROGRAM
    anchors = ("root = config_path.parent\n", "def run():\n",
               "    nested, phase_nonce, operation = unphase(logical)\n")
    if any(source.count(anchor) != 1 for anchor in anchors):
        _hold()
    source = source.replace(anchors[0], anchors[0] + OWN_HOME_CHECK, 1)
    source = source.replace(anchors[1], OOB_KEY_PROGRAM + "\n" + anchors[1], 1)
    return source.replace(anchors[2], OOB_BRANCH + anchors[2], 1)


def _fingerprint(line):
    wire = base64.b64decode(line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b"=").decode("ascii")


def _witness(case):
    return dict(case=case, phase="setup", timeline=[], cutoff=None, afterfault=[],
                devices=[], built=[], cached=[], selected=[], native=[], fetch=[],
                ib=[], key_before=[], tail=[], pause=[], pause_depth=0, pause_reads=[], pause_writes=[],
                signal_denials=[], product_depth=0, children=[], waits=[], uncertain=[])


def _unknown_callsite_descriptor(app, function, source):
    """Fixture capability only, based on the reviewed unchanged helper AST."""
    if not inspect.isfunction(function) or not callable(getattr(sys, "_getframe", None)):
        _hold()
    code = function.__code__
    if (function.__globals__ is not app.__dict__
            or code.co_name != "interactive_run" or code.co_filename != str(source)
            or code.co_argcount != 3 or code.co_kwonlyargcount != 1
            or code.co_varnames[:4] != ("command", "responder", "timeout", "display")
            or type(code.co_firstlineno) is not int or code.co_firstlineno <= 0):
        _hold()
    return code, {code.co_firstlineno + 67: "POLL",
                  code.co_firstlineno + 133: "CLEANUP"}


class EligibleOOBTailLatchWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.setUpClass.__func__(cls)
        probe = basis.load_script("w2_actual_pause_readiness", basis.INITIAL)
        value = getattr(probe, "_pause_auto_watch", None)
        if not callable(value) or list(inspect.signature(value).parameters) != ["tool", "credentials"]:
            _hold()
        ib_runner = getattr(probe, "run_on_ib", None)
        if (not callable(ib_runner)
                or not {"ib_default_password", "ib_command"}.issubset(
                    inspect.signature(ib_runner).parameters)):
            _hold()
        if any(hmac.compare_digest(cls.kat["PASSWORD"], value)
               for value in (PUBLIC_INITIAL, PUBLIC_OOB)):
            _hold()

    fixture = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.fixture
    events = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.events
    p1 = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.p1
    write_credentials = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.write_credentials

    def _mark_fault(self, f, kind):
        w = f["w2"]
        if w["phase"] == "main" and w["cutoff"] is None:
            w["cutoff"] = kind
            w["timeline"].append("fault-" + kind)

    def _global_fault(self, f):
        w = f["w2"]
        if w["phase"] == "main" and w["case"] == "global-changed":
            now = bound_file(f["global_path"])
            if now[1] == f["global_before"][1] + GLOBAL_SUFFIX:
                self._mark_fault(f, "global-changed")
                if "postfault_global" not in f:
                    f["postfault_global"] = now
            elif now != f["global_before"]:
                _hold()

    def _entry(self, f, name):
        w = f["w2"]
        self._global_fault(f)
        w["timeline"].append(name)
        if w["phase"] == "main" and w["cutoff"] is not None:
            w["afterfault"].append(name)

    def invoke(self, f, *options, cron_round=False, uncertain=False):
        """Transparent real-core observers, plus closed external HOME routing."""
        app, w = f["app"], f["w2"]
        real_fork, real_wait = app.pty.fork, os.waitpid
        real_kill, real_execve = os.kill, os.execve
        real_interactive = app.interactive_run
        unknown_diag = None
        unknown_code = unknown_sites = None
        if uncertain and w["phase"] == "main":
            unknown_code, unknown_sites = _unknown_callsite_descriptor(
                app, real_interactive, f["source"])
            unknown_diag = dict(active=set(), born=0, overflow=False, unexpected=False,
                                errors=0, nonproduct=0, nonproduct_reaped=0,
                                POLL=dict(attempts=0, zero=0, live=0, reaped=0),
                                CLEANUP=dict(attempts=0, zero=0, live=0, reaped=0),
                                OTHER=dict(attempts=0, zero=0, live=0, reaped=0))
        def unknown_count(table, field):
            if table[field] < 65535:
                table[field] += 1
            else:
                unknown_diag["overflow"] = True
        def emit_unknown_diag(qualified):
            def bounded(number):
                if number > 65535:
                    unknown_diag["overflow"] = True
                    return 65535
                return number
            counts = dict(owned_pty_born=unknown_diag["born"],
                          nonproduct_other_attempts=unknown_diag["nonproduct"],
                          nonproduct_reaped=unknown_diag["nonproduct_reaped"],
                          real_wait_errors=unknown_diag["errors"],
                          model_group_denials=bounded(w["signal_denials"].count("group-denied-MODEL")),
                          model_pid_denials=bounded(w["signal_denials"].count("pid-denied-MODEL")),
                          uncertain_errors=bounded(len(w["uncertain"])),
                          legacy_aggregate_product_zero_live=bounded(sum(
                              row["product"] and row["nohang"] and row["zero"] and row["live"]
                              for row in w["waits"])))
            for role in ("POLL", "CLEANUP", "OTHER"):
                for field in ("attempts", "zero", "live", "reaped"):
                    counts["product_" + role.lower() + "_" + field] = unknown_diag[role][field]
            public = dict(version="W2_UNKNOWN_PUBLIC_DIAG_V2", READY="UNOBSERVED",
                          callsite_qualified=not unknown_diag["unexpected"],
                          unexpected_product_caller=unknown_diag["unexpected"],
                          counter_overflow=unknown_diag["overflow"],
                          overall_current_qualified=qualified,
                          signal_pair_exact=w["signal_denials"] == ["group-denied-MODEL", "pid-denied-MODEL"],
                          uncertain_exact=w["uncertain"] == [True],
                          aggregate_original_one=sum(
                              row["product"] and row["nohang"] and row["zero"] and row["live"]
                              for row in w["waits"]) == 1,
                          fixture_reap_seen=any(not row["product"] and row["reaped"]
                                                for row in w["waits"]),
                          fixture_drain_marker_seen="FIXTURE_DRAIN_NOT_SUT" in result["cleanup"],
                          counts=counts)
            sys.stderr.write("W2_UNKNOWN_PUBLIC_DIAG_V2=" + json.dumps(
                public, sort_keys=True, separators=(",", ":")) + "\n")
            sys.stderr.flush()
        real_ib, real_select = app.run_on_ib, app._authenticate_ib_read
        real_value, real_native = app._ib_project_value, app.verify_password_hash
        real_password = app.ProjectPasswordPolicy.password
        real_pause, real_read_cron, real_write_cron = app._pause_auto_watch, app._read_auto_crontab, app._write_auto_crontab
        real_devices, real_build, real_cache = app.load_devices, app.build_targets, app.load_target_cache
        def devices(*args, **kw):
            result = real_devices(*args, **kw)
            w["devices"].append(result)
            return result
        def build(*args, **kw):
            result = real_build(*args, **kw)
            w["built"].append(result)
            return result
        def cache(*args, **kw):
            result = real_cache(*args, **kw)
            w["cached"].append(result)
            return result
        def ib(*args, **kw):
            self._entry(f, "ib-entry")
            values = inspect.signature(real_ib).bind(*args, **kw)
            values.apply_defaults()
            current = values.arguments["ib_default_password"]
            command = values.arguments["ib_command"]
            if type(command) is list and command[:2] == ["sh", "-c"]:
                w["key_before"].append(any(row["IB"] and row["target"] and row["matched"]
                                           for row in w["native"]))
            w["ib"].append(dict(initial=hmac.compare_digest(current, PUBLIC_INITIAL),
                                target=hmac.compare_digest(current, self.kat["PASSWORD"]),
                                oob=hmac.compare_digest(current, PUBLIC_OOB)))
            try:
                return real_ib(*args, **kw)
            finally:
                self._global_fault(f)
        def select(*args, **kw):
            self._entry(f, "selector-entry")
            result = real_select(*args, **kw)
            w["selected"].append(dict(initial=hmac.compare_digest(result.current_password, PUBLIC_INITIAL),
                                      target=hmac.compare_digest(result.current_password, self.kat["PASSWORD"])))
            w["timeline"].append("selector-return")
            return result
        def native(password, setting):
            self._entry(f, "native-entry")
            result = real_native(password, setting)
            fact = dict(IB=hmac.compare_digest(setting, self.kat["YESCRYPT"]),
                        target=hmac.compare_digest(password, self.kat["PASSWORD"]),
                        bad=hmac.compare_digest(password, PUBLIC_BAD_TARGET),
                        matched=result is True)
            w["native"].append(fact)
            if w["case"] == "bad-target" and fact["IB"] and fact["bad"] and result is False:
                self._mark_fault(f, "bad-target")
            return result
        def password(policy):
            self._entry(f, "target-fetch")
            w["fetch"].append("actual-policy-fetch")
            try:
                return real_password(policy)
            except app.SetupError:
                if w["case"] == "missing-target":
                    self._mark_fault(f, "missing-target")
                raise
        def value(*args, **kw):
            try:
                return real_value(*args, **kw)
            except app.SetupError:
                if w["case"] == "missing-target" and kw.get("fetch") is True:
                    self._mark_fault(f, "missing-target")
                self._global_fault(f)
                raise
        def actor(name, original):
            @wraps(original)
            def observed(*args, **kw):
                self._entry(f, name)
                if name == "oob-tail-entry":
                    w["tail"].append("actual-helper-entry")
                return original(*args, **kw)
            return observed
        def read_cron():
            result = real_read_cron()
            if w["pause_depth"]:
                w["pause_reads"].append(dict(afterwrite=bool(w["pause_writes"]),
                                             retained=result == FOREIGN_CRON))
            return result
        def write_cron(contents):
            result = real_write_cron(contents)
            if w["pause_depth"]:
                w["pause_writes"].append(contents == FOREIGN_CRON)
                w["timeline"].append("pause-cron-write-return")
            return result
        def pause(*args, **kw):
            w["timeline"].append("pause-entry")
            w["pause"].append("entry")
            w["pause_depth"] += 1
            try:
                result = real_pause(*args, **kw)
            finally:
                w["pause_depth"] -= 1
            w["pause"].append("returned")
            w["timeline"].append("pause-return")
            return result
        def fork():
            result = real_fork()
            if result[0] > 0:
                w["children"].append(result[0])
                if unknown_diag is not None:
                    unknown_count(unknown_diag, "born")
                    if len(unknown_diag["active"]) < 65535:
                        unknown_diag["active"].add(result[0])
                    else:
                        unknown_diag["overflow"] = True
            return result
        def wait(pid, flags):
            diagnostic_owned = (unknown_diag is not None
                                and pid in unknown_diag["active"])
            diagnostic_product = diagnostic_owned and w["product_depth"] > 0
            diagnostic_role = "OTHER"
            if diagnostic_product:
                caller = None
                try:
                    caller = sys._getframe(1)
                    if caller.f_code is unknown_code:
                        diagnostic_role = unknown_sites.get(caller.f_lineno, "OTHER")
                except Exception:
                    # Observer capability only; never inject into product cleanup.
                    unknown_diag["unexpected"] = True
                finally:
                    del caller
                if diagnostic_role == "OTHER":
                    unknown_diag["unexpected"] = True
                unknown_count(unknown_diag[diagnostic_role], "attempts")
            elif diagnostic_owned:
                unknown_count(unknown_diag, "nonproduct")
            try:
                result = real_wait(pid, flags)
            except BaseException:
                if diagnostic_owned:
                    unknown_count(unknown_diag, "errors")
                raise
            if pid in w["children"]:
                live = False
                if w["product_depth"] and flags == os.WNOHANG and result[0] == 0:
                    try:
                        real_kill(pid, 0)
                        live = True
                    except OSError:
                        pass
                w["waits"].append(dict(product=w["product_depth"] > 0,
                                       nohang=flags == os.WNOHANG,
                                       zero=result[0] == 0, reaped=result[0] == pid, live=live))
                if diagnostic_owned:
                    if diagnostic_product:
                        row = unknown_diag[diagnostic_role]
                        if result[0] == 0:
                            unknown_count(row, "zero")
                            if live:
                                unknown_count(row, "live")
                        elif result[0] == pid:
                            unknown_count(row, "reaped")
                    elif result[0] == pid:
                        unknown_count(unknown_diag, "nonproduct_reaped")
                    if result[0] == pid:
                        unknown_diag["active"].discard(pid)
            return result
        def interactive(*args, **kw):
            w["product_depth"] += 1
            try:
                return real_interactive(*args, **kw)
            except BaseException as error:
                if getattr(error, "cleanup_uncertain", None) is True:
                    w["uncertain"].append(True)
                    self._mark_fault(f, "uncertain")
                raise
            finally:
                w["product_depth"] -= 1
        def execve(executable, argv, env):
            # Captured by copied backend before it installs its execvp seam.
            if (executable != sys.executable or argv[:4] != [sys.executable, "-I", "-S", "-B"]
                    or argv[4:6] != [str(f["stub"]), str(f["config"])]):
                _hold()
            routed = dict(env)
            routed["HOME"] = str(f["ssh_home"])
            return real_execve(executable, argv, routed)
        with ExitStack() as stack:
            for name, wrapped in (("load_devices", devices), ("build_targets", build),
                                  ("load_target_cache", cache), ("run_on_ib", ib),
                                  ("_authenticate_ib_read", select), ("_ib_project_value", value),
                                  ("verify_password_hash", native), ("_pause_auto_watch", pause),
                                  ("_read_auto_crontab", read_cron), ("_write_auto_crontab", write_cron),
                                  ("interactive_run", interactive)):
                original = getattr(app, name)
                stack.enter_context(mock.patch.object(app, name, new=wraps(original)(wrapped)))
            stack.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "password", new=wraps(real_password)(password)))
            for name, label in (("_execute_ib_phase", "phase-entry"),
                                ("_run_authorized_ib_command", "authorized-helper-entry"),
                                ("install_oob_management_key", "oob-tail-entry"),
                                ("_write_auto_credentials", "credentials-writer-entry"),
                                ("_install_auto_watch", "watch-install-entry"),
                                ("_remove_auto_watch", "completion-entry"),
                                ("_save_auto_terminal", "terminal-write-entry")):
                original = getattr(app, name)
                stack.enter_context(mock.patch.object(app, name, new=actor(label, original)))
            stack.enter_context(mock.patch.object(app.pty, "fork", new=fork))
            stack.enter_context(mock.patch.object(app.os, "waitpid", new=wait))
            stack.enter_context(mock.patch.object(app.os, "execve", new=execve))
            result = self._invoke_backend(f, *options, cron_round=cron_round, uncertain=uncertain)
        self._global_fault(f)
        if uncertain and w["phase"] == "main":
            ready = f["root"] / "uncertain-ready"
            qualified = (ready.is_file() and bound_file(ready)[1] == b"READY\n"
                         and w["signal_denials"] == ["group-denied-MODEL", "pid-denied-MODEL"]
                         and w["uncertain"] == [True]
                         and unknown_diag["CLEANUP"] == {
                             "attempts": 1, "zero": 1, "live": 1, "reaped": 0}
                         and unknown_diag["OTHER"]["attempts"] == 0
                         and unknown_diag["errors"] == 0
                         and any(not row["product"] and row["reaped"] for row in w["waits"])
                         and "FIXTURE_DRAIN_NOT_SUT" in result["cleanup"])
            emit_unknown_diag(qualified)
            if unknown_diag["unexpected"] or unknown_diag["overflow"]:
                _hold()
            if not qualified:
                _hold()
        return result

    def _safe_invoke(self, f, *options, **kw):
        result = unexpected = None
        try:
            result = self.invoke(f, *options, **kw)
        except _W2FixtureHold:
            raise
        except BaseException as error:
            unexpected = error
        self.assertTrue(unexpected is None,
                        "qualified MAIN raised unexpected program/adapter error; details suppressed")
        return result

    def _invoke_backend(self, f, *options, cron_round=False, uncertain=False):
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
                "--execution-mode", "management", *options]
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
                f["w2"]["signal_denials"].append("group-denied-MODEL")
                raise PermissionError(1, "PUBLIC modeled owned group signal refusal")
            return real_killpg(pid, sig)
        def kill(pid, sig):
            if ready(pid):
                f["w2"]["signal_denials"].append("pid-denied-MODEL")
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
                except app.SetupError as exc:
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


    def _prepare(self, folder, case, *, watch=True):
        scenario = {"global-changed": "change-global-after-read",
                    "uncertain": "uncertain"}.get(case, "normal")
        # Canonicalize only the already-owned fresh temporary root; macOS
        # /var aliases must not make the preinstalled job a different tool.
        f = self.fixture(str(Path(folder).resolve(strict=True)),
                         scenario=scenario, expiry=False, configured=True)
        f["w2"] = _witness(case)
        csv_text = f["csv"].read_text(encoding="ascii")
        old = "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n"
        if csv_text.count(old) != 1:
            _hold()
        f["csv"].write_text(csv_text.replace(old, "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"), encoding="ascii")
        state = json.loads(f["state"].read_text())
        state["credential"] = "initial"
        f["state"].write_text(json.dumps(state), encoding="ascii")
        f["state"].chmod(0o600)
        f["ssh_home"] = f["root"] / "ssh-process-home"
        f["ssh_home"].mkdir(mode=0o700)
        oob_home = f["root"] / "oob-remote-home"
        oob_home.mkdir(mode=0o700)
        (oob_home / ".ssh").mkdir(mode=0o700)
        f["oob_auth"] = oob_home / ".ssh/authorized_keys"
        f["oob_old"] = "# PUBLIC independent OOB original\n" + basis.public_key(23, "oob-foreign-original")
        f["oob_auth"].write_text(f["oob_old"], encoding="ascii")
        f["oob_auth"].chmod(0o600)
        f["oob_control"] = oob_home / "foreign-control"
        f["oob_control"].write_bytes(b"PUBLIC OOB foreign control\n")
        f["oob_control"].chmod(0o600)
        f["oob_control_before"] = bound_file(f["oob_control"])
        config = json.loads(f["config"].read_text())
        config["oob_management_line"] = f["management"]
        f["config"].write_text(json.dumps(config), encoding="utf-8")
        f["config"].chmod(0o600)
        f["stub"].write_text(_peer_program(), encoding="utf-8")
        f["stub"].chmod(0o600)
        cache = self.p1(f)
        w = f["w2"]
        self.assertTrue(w["devices"] and w["built"]
                        and not w["ib"] and not w["native"],
                        "real CSV/P1 generation did not reach the intended nonremote producer")
        produced_device = w["devices"][-1][1]["example-jump01"]
        produced_target = w["built"][-1][0]
        self.assertTrue(type(produced_device) is f["app"].Device
                        and produced_device.dev_type == "eth"
                        and produced_device.hostname == "EXAMPLE-JUMP01"
                        and produced_device.login_ip == "192.0.2.10"
                        and produced_target.ethernet is produced_device,
                        "eth eligibility was not produced from actual CSV/build_targets")
        self.assertTrue(cache["targets"][0]["ethernet"]["dev_type"] == "eth"
                        and cache["targets"][0]["ethernet"]["login_ip"] == "192.0.2.10"
                        and cache["targets"][0]["ib"]["hostname"] == "EXAMPLE-IB01"
                        and cache["targets"][0]["ethernet_port"] == "swp7"
                        and cache["targets"][0]["ib_port_alias"] == "eth0",
                        "real P1 cache does not preserve independent eligibility inputs")
        result = f["app"].load_target_cache(
            f["cache"], f["csv"], f["p2p"], public_key_tool=f["tool"],
            validate_public_keys_with_ssh_keygen=True)
        self.assertTrue(type(result) is tuple and result[0] == 1
                        and result[1][0].ethernet.dev_type == "eth"
                        and result[1][0].ethernet.hostname == "EXAMPLE-JUMP01",
                        "actual cache reader did not admit the eligible eth device")
        f["actual_target"] = result[1][0]
        entries = [entry for entry in cache["public_keys"] if entry["name"] == "mgmt-server.pub"]
        self.assertTrue(len(entries) == 1 and set(entries[0]) == {"name", "line", "fingerprint"}
                        and entries[0]["line"] == f["management"].strip()
                        and entries[0]["fingerprint"] == _fingerprint(f["management"]),
                        "actual P1 management PUBLIC entry differs from independent wire input")
        f["entry"] = entries[0]
        self.write_credentials(f, None if case == "missing-target" else
                               PUBLIC_BAD_TARGET if case == "bad-target" else self.kat["PASSWORD"])
        f["global_before"] = bound_file(f["global_path"])
        if watch:
            self._pre_watch(f)
        f["setup_witness"] = w
        f["w2"] = _witness(case)
        f["w2"]["phase"] = "main"
        return f

    def _pre_watch(self, f):
        app = f["app"]
        real_run = subprocess.run
        commits = []
        def run(command, *args, **kw):
            if command == ["crontab", "-l"]:
                return subprocess.CompletedProcess(command, 0, f["cron"].read_text(), "")
            if command == ["crontab", "-"]:
                if args or type(kw.get("input")) is not str:
                    _hold()
                commits.append("actual-producer-commit")
                f["cron"].write_text(kw["input"], encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            return real_run(command, *args, **kw)
        with mock.patch.object(app.subprocess, "run", new=run):
            app._install_auto_watch(
                f["tool"], f["credentials"], f["csv"], f["p2p"], f["cache"],
                f["root"] / "out/report.log", f["root"] / "out/snapshots", force=False)
        listing = f["cron"].read_text()
        rows = listing.splitlines()
        expected = [
            "*/10", "*", "*", "*", "*", "cd", str(f["tool"]), "&&",
            "flock", "-w", "0", str(f["credentials"].parent / "auto.lock"),
            str(Path(sys.executable).resolve()), str(f["source"]),
            "--auto", "--apply", "--yes", "--credentials-file", str(f["credentials"]),
            "--execution-mode", "management", "--ib-csv", str(f["csv"]),
            "--p2p", str(f["p2p"]), "--target-cache", str(f["cache"]),
            "--report", str(f["root"] / "out/report.log"),
            "--snapshot-dir", str(f["root"] / "out/snapshots"),
            ">>", str(f["credentials"].parent / "auto-cron.log"),
            "2>&1", "#", "http-v3-req10c-auto",
        ]
        self.assertTrue(commits == ["actual-producer-commit"]
                        and len(rows) == 2 and rows[0] + "\n" == FOREIGN_CRON
                        and shlex.split(rows[1]) == expected,
                        "actual pre-watch producer does not match independent complete job")
        self.assertTrue(bound_file(f["marker"])[1] == b"http-v3-req10c-auto-v1\n",
                        "real watch ownership marker was not produced")
        f["watch_before"] = listing
        f["lock"] = f["credentials"].parent / "auto-crontab.lock"
        f["lock_before"] = bound_file(f["lock"])
        self.assertTrue(stat.S_IMODE(f["lock_before"][0][2]) == 0o600,
                        "actual retained watch lock is not private")
        f["protected_before"] = tuple(bound_file(f[name]) for name in
                                      ("credentials", "marker", "control", "auth", "oob_auth", "oob_control"))
        alias = f["tool"] / "01-global.yaml"
        f["alias_before"] = basis.nine(alias.lstat()), os.readlink(alias)

    def _oob_effect(self, f, events):
        receipts = [event for event in events if event["kind"] == "oob-key-shell"]
        self.assertTrue(len(receipts) == 1 and receipts[0]["actual_rc"] == 0
                        and receipts[0]["receipt"] in CANONICAL_RECEIPTS
                        and receipts[0]["own_home"] is True,
                        "actual OOB shell rc/canonical receipt/own HOME was not witnessed")
        info, raw = bound_file(f["oob_auth"])
        self.assertTrue(raw == (f["oob_old"] + f["management"]).encode("ascii")
                        and f["laptop"].encode("ascii") not in raw
                        and stat.S_IMODE(info[2]) == 0o600
                        and bound_file(f["oob_control"]) == f["oob_control_before"],
                        "actual OOB key effect changed foreign data or installed the wrong PUBLIC key")

    def _direct_oob(self, f):
        """Existing real helper qualification, not a fake MAIN success."""
        app = f["app"]
        carrier = app.key_install_command([f["entry"]])
        config = json.loads(f["config"].read_text())
        if (type(carrier) is not list or len(carrier) != 5 or carrier[:2] != ["sh", "-c"]
                or carrier[3] != "--"
                or hashlib.sha256(carrier[2].encode()).hexdigest() != config["key_script_sha256"]
                or base64.b64decode(carrier[4], validate=True) != f["management"].encode("ascii")):
            _hold()
        real_execve, real_fork, real_wait, real_killpg = os.execve, app.pty.fork, os.waitpid, os.killpg
        real_run = subprocess.run
        children, product_reaps, fixture_drains = [], [], []
        def fork():
            result = real_fork()
            if result[0] > 0:
                children.append(result[0])
            return result
        def wait(pid, flags):
            result = real_wait(pid, flags)
            if pid in children and result[0] == pid:
                product_reaps.append("actual-owned-reap")
            return result
        def execvp(executable, argv):
            if executable != "ssh" or type(argv) is not list or argv[0] != "ssh":
                os._exit(86)
            real_execve(sys.executable, [sys.executable, "-I", "-S", "-B",
                                        str(f["stub"]), str(f["config"]), *argv[1:]],
                        dict(PATH=os.defpath, LC_ALL="C", LANG="C",
                             PYTHONDONTWRITEBYTECODE="1", HOME=str(f["ssh_home"])))
        def run(command, *args, **kw):
            validator = shutil.which("ssh-keygen")
            if command != [validator, "-l", "-E", "sha256", "-f", "/dev/stdin"]:
                _hold()
            return real_run(command, *args, **kw)
        output, errors = io.StringIO(), io.StringIO()
        error = None
        try:
            with mock.patch.dict(os.environ, {
                     "PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                     "PYTHONDONTWRITEBYTECODE": "1", "HOME": str(f["root"])}, clear=True), \
                 mock.patch.object(app.pty, "fork", new=fork), \
                 mock.patch.object(app.os, "waitpid", new=wait), \
                 mock.patch.object(app.os, "execvp", new=execvp), \
                 mock.patch.object(app.subprocess, "run", new=run), \
                 mock.patch.object(Path, "home", return_value=f["root"]), \
                 redirect_stdout(output), redirect_stderr(errors):
                try:
                    app.install_oob_management_key(
                        f["actual_target"].ethernet, "cumulus", PUBLIC_OOB, f["entry"], 2)
                except BaseException as caught:
                    error = caught
        finally:
            for pid in children:
                try:
                    got, unused = real_wait(pid, os.WNOHANG)
                except ChildProcessError:
                    continue
                if got == 0:
                    try:
                        real_killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    real_wait(pid, 0)
                    fixture_drains.append("FIXTURE_DRAIN_NOT_SUT")
        self.assertTrue(error is None and product_reaps == ["actual-owned-reap"]
                        and not fixture_drains,
                        "existing OOB helper/typed carrier/real shell qualification failed")
        events = self.events(f)
        self.assertTrue(not any(event["kind"] == "adapter-error" for event in events),
                        "owned OOB adapter failed before its genuine shell")
        self._oob_effect(f, events)
        self.assertTrue(all(secret not in output.getvalue() + errors.getvalue()
                            for secret in (PUBLIC_INITIAL, PUBLIC_OOB, self.kat["PASSWORD"],
                                           self.kat["YESCRYPT"])),
                        "direct helper projected credential data")

    def _main(self, f, *, uncertain=False):
        return self._safe_invoke(f, "--auto", "--apply", "--yes",
                                 "--credentials-file", str(f["credentials"]),
                                 cron_round=True, uncertain=uncertain)

    def _assert_pause(self, f, result):
        w = f["w2"]
        self.assertTrue(result["error"] is not None or result["rc"] != 0,
                        "nonretryable admission/UNKNOWN was reported as completion")
        self.assertTrue(w["cutoff"] == w["case"] and not w["afterfault"],
                        "actual fault was not reached or later IB/tail/persistence actor ran")
        self.assertTrue(w["pause"] == ["entry", "returned"]
                        and w["pause_writes"] == [True]
                        and sum(row["afterwrite"] and row["retained"] for row in w["pause_reads"]) >= 2,
                        "marker is not pause: real single cron commit and two post-reads required")
        self.assertTrue(f["cron"].read_text() == FOREIGN_CRON,
                        "qualified complete own job remains scheduled or foreign listing changed")
        after = tuple(bound_file(f[name]) for name in
                      ("credentials", "marker", "control", "auth", "oob_auth", "oob_control"))
        self.assertTrue(after == f["protected_before"]
                        and bound_file(f["lock"])[0][:2] == f["lock_before"][0][:2],
                        "failed round changed retained credentials/marker/keys/control or lock inode")
        alias = f["tool"] / "01-global.yaml"
        self.assertTrue((basis.nine(alias.lstat()), os.readlink(alias)) == f["alias_before"]
                        and not f["terminal"].exists() and not w["tail"],
                        "failed round changed project alias or used tail/completion")
        self.assertTrue(not any(event["kind"] in
                                {"mutation", "apply-y", "save", "pam-target", "key-shell", "oob-key-shell"}
                                for event in result["events"]),
                        "negative round performed a device/key write")
        self.assertTrue(result["prompts"] == [],
                        "cron missing/bad/changed/UNKNOWN path attempted an interactive prompt")

    def test_00_existing_oob_helper_runs_exact_carrier_and_real_shell(self):
        with tempfile.TemporaryDirectory(prefix="w2-oob-qualification-") as folder:
            f = self._prepare(folder, "ready", watch=False)
            self._direct_oob(f)

    def test_01_ready_eth_real_main_current_and_both_key_consumers(self):
        with tempfile.TemporaryDirectory(prefix="w2-ready-") as folder:
            f = self._prepare(folder, "ready")
            result = self._main(f)
            w = f["w2"]
            self.assertTrue(result["error"] is None and result["rc"] == 0,
                            "qualified eligible ready AUTO round did not complete")
            self.assertTrue(w["cached"] and any(value is not None
                                              and value[1][0].ethernet.dev_type == "eth"
                                              for value in w["cached"])
                            and w["selected"] and all(row["initial"] and not row["target"]
                                                      for row in w["selected"]),
                            "actual final cache/selector did not retain eligible eth and selected INITIAL")
            self.assertTrue(w["native"] and any(row["target"] and row["IB"] and row["matched"]
                                                for row in w["native"])
                            and w["key_before"] and all(w["key_before"])
                            and w["ib"] and all(row["initial"] and not row["target"] and not row["oob"]
                                               for row in w["ib"]),
                            "write-capable KEY lacked native TARGET authority or reused TARGET/OOB as CURRENT")
            events = result["events"]
            self.assertTrue(all(event["initial"] and not event["target"] and not event["oob"]
                                for event in events if event["kind"] == "inner-answer")
                            and not any(event["kind"] in {"mutation", "apply-y", "save", "pam-target"}
                                        for event in events),
                            "ready case changed credentials/config instead of keeping actual CURRENT")
            self.assertTrue(any(event["kind"] == "key-shell" and event["actual_rc"] == 0
                                and event["receipt"] in CANONICAL_RECEIPTS for event in events)
                            and w["tail"] == ["actual-helper-entry"],
                            "real IB KEY and eligible OOB helper did not both execute")
            self._oob_effect(f, events)
            ib_auth = bound_file(f["auth"])[1]
            self.assertTrue(ib_auth == (f["old_key"] + f["laptop"] + f["management"]).encode("ascii"),
                            "actual IB generated shell did not preserve both independent PUBLIC keys")
            self.assertTrue(not f["credentials"].exists() and not f["marker"].exists()
                            and f["cron"].read_text() == FOREIGN_CRON and result["prompts"] == []
                            and bound_file(f["control"]) == f["control_before"],
                            "successful own completion/foreign preservation differs from contract")

    def test_02_missing_bad_changed_and_true_unknown_latch_and_real_pause(self):
        for case in ("missing-target", "bad-target", "global-changed", "uncertain"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="w2-latch-") as folder:
                f = self._prepare(folder, case)
                result = self._main(f, uncertain=case == "uncertain")
                w = f["w2"]
                if case == "missing-target":
                    self.assertTrue(w["fetch"] or w["cutoff"] == "missing-target",
                                    "missing target did not reach real write-capable admission")
                elif case == "bad-target":
                    self.assertTrue(any(row["bad"] and row["IB"] and not row["matched"]
                                        for row in w["native"]),
                                    "bad independent target did not reach real IB native mismatch")
                elif case == "global-changed":
                    self.assertTrue(any(event["kind"] == "global-changed-after-read"
                                        for event in result["events"])
                                    and "postfault_global" in f
                                    and bound_file(f["global_path"]) == f["postfault_global"],
                                    "actual authenticated-read global change/freshness cutoff not qualified")
                else:
                    self.assertTrue(w["signal_denials"] == ["group-denied-MODEL", "pid-denied-MODEL"]
                                    and w["uncertain"] == [True]
                                    and any(row["product"] and row["nohang"] and row["zero"] and row["live"]
                                            for row in w["waits"])
                                    and "FIXTURE_DRAIN_NOT_SUT" in result["cleanup"],
                                    "true primitive UNKNOWN/real live WNOHANG0 was not distinguished from fixture drain")
                self._assert_pause(f, result)


if __name__ == "__main__":
    unittest.main()
