"""Private AUTO-watch pause tests-first contract; O-only immutable draft, NOT RUN.

The pause API is absent until reviewed source exists. AST NOT_READY is a
prerequisite HOLD, never a fabricated TypeError behavior RED.
No host crontab or listed shell job is executed. The crontab process is the
owned external MODEL; actual lock/list/write/pause/install/unsetup delegate.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack, contextmanager
import errno
import fcntl
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
UNSETUP = ROOT / "DAY0-Prepare/02-unsetup.py"
FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
          "st_size", "st_mtime_ns", "st_ctime_ns")
SAFE_ARGS = ("auto watch pause could not be confirmed; operator HOLD; credentials preserved",)
FOREIGN_BEFORE = (
    "MAILTO=PUBLIC-operator@example.test\n"
    "3 4 * * * /PUBLIC/foreign-before # retain-order\n\n"
)
FOREIGN_AFTER = (
    "7 6 * * * /PUBLIC/foreign-after # retain-bytes\n"
    "# PUBLIC final comment without final LF"
)
FOREIGN = FOREIGN_BEFORE + FOREIGN_AFTER
MARKER_BYTES = b"http-v3-req10c-auto-v1\n"
ENV_BYTES = (
    b"NVOS_INITIAL_PASSWORD=PUBLIC-INITIAL-Only-17!\n"
    b"NVOS_TARGET_PASSWORD=PUBLIC-TARGET-Only-81!\n"
    b"ZTP_ETH_PASSWORD_EXAMPLE_JUMP01=PUBLIC-OOB-Only-91!\n"
)


def fixture_hold():
    error = RuntimeError("FIXTURE HOLD: owned pause API, lock or adapter prerequisite unavailable")
    try:
        raise error from None
    except RuntimeError:
        error.__cause__ = None
        error.__context__ = None
        raise


def nine(info):
    return tuple(getattr(info, name) for name in FIELDS)


def bound_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = nine(os.fstat(fd))
        if not stat.S_ISREG(first[2]) or first[5] != 1 or first[6] > 1048576:
            fixture_hold()
        if nine(path.lstat()) != first:
            fixture_hold()
        copies = []
        for _ in range(2):
            os.lseek(fd, 0, 0)
            chunks, total = [], 0
            while total <= first[6]:
                part = os.read(fd, min(65536, first[6] + 1 - total))
                if not part:
                    break
                chunks.append(part)
                total += len(part)
            raw = b"".join(chunks)
            if len(raw) != first[6] or os.read(fd, 1):
                fixture_hold()
            if nine(os.fstat(fd)) != first or nine(path.lstat()) != first:
                fixture_hold()
            copies.append(raw)
        if copies[0] != copies[1]:
            fixture_hold()
        return first, copies[0]
    finally:
        os.close(fd)


def optional_file(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return bound_file(path)


def canonical_job(f, python="/usr/bin/python3"):
    """Independent PUBLIC job grammar, not the production renderer."""
    q = shlex.quote
    return (
        "*/10 * * * * cd " + q(str(f["tool"]))
        + " && flock -w 0 " + q(str(f["state"] / "auto.lock"))
        + " " + q(python) + " " + q(str(f["tool"] / "initial-setup.py"))
        + " --auto --apply --yes --credentials-file " + q(str(f["credentials"]))
        + " --execution-mode management --ib-csv " + q(str(f["csv"]))
        + " --p2p " + q(str(f["p2p"]))
        + " --target-cache " + q(str(f["cache"]))
        + " --report " + q(str(f["report"]))
        + " --snapshot-dir " + q(str(f["snapshots"]))
        + " >> " + q(str(f["state"] / "auto-cron.log"))
        + " 2>&1 # http-v3-req10c-auto\n"
    )


def legacy_plain_job(f):
    q = shlex.quote
    return (
        "*/10 * * * * cd " + q(str(f["tool"]))
        + " && /usr/bin/python3 initial-setup.py --auto --apply --yes"
        + " --credentials-file " + q(str(f["credentials"])) + "\n"
    )


def legacy_locked_job(f):
    q = shlex.quote
    return (
        "*/10 * * * * cd " + q(str(f["tool"]))
        + " && flock -w 0 " + q(str(f["state"] / "auto.lock"))
        + " /usr/bin/python3 " + q(str(f["tool"] / "initial-setup.py"))
        + " --auto --credentials-file " + q(str(f["credentials"]))
        + " # http-v3-req10c-auto\n"
    )


class AutoWatchPauseDirectAndWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _info, raw = bound_file(INITIAL)
        tree = ast.parse(raw, filename=str(INITIAL))
        definitions = [item for item in tree.body
                       if isinstance(item, ast.FunctionDef) and item.name == "_pause_auto_watch"]
        if len(definitions) != 1:
            fixture_hold()
        args = definitions[0].args
        if (args.posonlyargs or [arg.arg for arg in args.args] != ["tool", "credentials"]
                or args.vararg is not None or args.kwarg is not None
                or args.kwonlyargs or args.defaults):
            fixture_hold()
        if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW")):
            fixture_hold()
        cls.app = load_script("pause_actual_initial", INITIAL)
        cls.unsetup = load_script("pause_actual_unsetup", UNSETUP)
        if getattr(cls.unsetup, "_DRY_RUN", None) is not False:
            fixture_hold()
        if not callable(getattr(cls.unsetup, "_cleanup_req10c_auto_watch", None)):
            fixture_hold()

    def fixture(self, folder, *, env=True, marker=True):
        root = Path(folder)
        tool = root / "infiniband/bringup/xdr-initial-setup"
        state = tool / "xdr-initial-setup-logs"
        state.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        credentials = state / "auto.env"
        watch_marker = state / "auto-watch.state"
        if env:
            credentials.write_bytes(ENV_BYTES)
            credentials.chmod(0o600)
        if marker:
            watch_marker.write_bytes(MARKER_BYTES)
            watch_marker.chmod(0o600)
        control = root / "foreign-control"
        control.write_bytes(b"PUBLIC immutable foreign control\n")
        control.chmod(0o600)
        cron = root / "owned-crontab.db"
        cron.write_text(FOREIGN, encoding="utf-8")
        cron.chmod(0o600)
        inputs = {}
        for key, name in (("csv", "ib.csv"), ("p2p", "p2p.dot"),
                          ("cache", "targets.json"), ("report", "report.log")):
            path = root / name
            path.write_bytes(b"PUBLIC scheduler argument only\n")
            inputs[key] = path
        inputs["snapshots"] = root / "snapshots"
        return dict(root=root, tool=tool, state=state, credentials=credentials,
                    marker=watch_marker, cron=cron, control=control,
                    lock=state / "auto-crontab.lock", **inputs)

    def snapshot(self, f):
        return {name: optional_file(f[name])
                for name in ("credentials", "marker", "control", "cron")}

    def assert_leaves_preserved(self, f, before, *, cron):
        for name in ("credentials", "marker", "control"):
            self.assertTrue(optional_file(f[name]) == before[name],
                            "pause must preserve secret/marker/foreign leaf identity and bytes")
        if cron:
            self.assertTrue(bound_file(f["cron"]) == before["cron"],
                            "refusal or absence must not rewrite crontab")

    def assert_safe_hold(self, caught):
        self.assertTrue(type(caught) is self.app.SetupError,
                        "known pause failure must be the fixed safe domain")
        self.assertTrue(caught.args == SAFE_ARGS,
                        "known pause failure must have only the independent fixed message")
        self.assertTrue(caught.__cause__ is None and caught.__context__ is None,
                        "known pause failure must not retain a private exception chain")

    def adapter(self, f, *, fault=None, seed=None):
        observed = dict(reads=0, writes=0, committed=0, adapter_errors=[],
                        release_entries=0, release_failures=0, actual_release=False)

        def run(command, *args, **kwargs):
            if command == ["crontab", "-l"]:
                if (args or kwargs != {"capture_output": True, "text": True,
                                       "timeout": 10, "check": False}):
                    observed["adapter_errors"].append("read-shape")
                    raise AssertionError("PUBLIC owned adapter shape")
                observed["reads"] += 1
                if fault in ("read-program", "read-known") and observed["reads"] == 1:
                    raise seed
                if fault == "post-read-error" and observed["committed"] and observed["reads"] == 3:
                    raise OSError(errno.EACCES, "PUBLIC post-write listing refusal")
                if fault == "post-read-mismatch" and observed["committed"] and observed["reads"] == 3:
                    f["cron"].write_text(FOREIGN + "\n# PUBLIC concurrent foreign addition\n",
                                         encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, f["cron"].read_text(encoding="utf-8"), "")
            if command == ["crontab", "-"]:
                required = {"input", "capture_output", "text", "timeout", "check"}
                if (args or set(kwargs) != required or type(kwargs["input"]) is not str
                        or kwargs["capture_output"] is not True or kwargs["text"] is not True
                        or kwargs["timeout"] != 10 or kwargs["check"] is not False):
                    observed["adapter_errors"].append("write-shape")
                    raise AssertionError("PUBLIC owned adapter shape")
                observed["writes"] += 1
                if fault == "write-program":
                    raise seed
                f["cron"].write_text(kwargs["input"], encoding="utf-8")
                observed["committed"] += 1
                if fault == "committed-timeout":
                    raise subprocess.TimeoutExpired(["PUBLIC-crontab"], 10,
                                                    output="PUBLIC ambiguous outcome")
                return subprocess.CompletedProcess(command, 0, "", "")
            observed["adapter_errors"].append("unexpected-boundary")
            raise AssertionError("PUBLIC only owned crontab boundary is permitted")

        return run, observed

    def pause(self, f, *, fault=None, seed=None, release_seed=None):
        run, observed = self.adapter(f, fault=fault, seed=seed)
        original_lock = self.app._auto_crontab_lock

        @contextmanager
        def actual_release_then_fault(tool):
            observed["release_entries"] += 1
            try:
                with original_lock(tool):
                    yield
            finally:
                # This probe is after the real original context exit. It does
                # not replace/unlock a product FD or synthesize a successful exit.
                fd = os.open(f["lock"], os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    info = os.fstat(fd)
                    named = f["lock"].lstat()
                    if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                            or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                        fixture_hold()
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    observed["actual_release"] = True
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
                observed["release_failures"] += 1
                raise release_seed

        result = object()
        caught = None
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.app.subprocess, "run", new=run))
            if release_seed is not None:
                stack.enter_context(mock.patch.object(self.app, "_auto_crontab_lock",
                                                       new=actual_release_then_fault))
            try:
                result = self.app._pause_auto_watch(f["tool"], f["credentials"])
            except BaseException as error:
                caught = error
        if observed["adapter_errors"]:
            fixture_hold()
        return result, caught, observed

    def test_absent_canonical_and_two_supported_legacy_shapes(self):
        # Four of the original twelve supplied-cron states.
        for kind in ("absent", "canonical", "legacy-plain", "legacy-locked"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="pause-normal-") as folder:
                f = self.fixture(folder, env=kind != "legacy-plain", marker=kind != "absent")
                jobs = {"absent": "", "canonical": canonical_job(f),
                        "legacy-plain": legacy_plain_job(f), "legacy-locked": legacy_locked_job(f)}
                f["cron"].write_text(FOREIGN_BEFORE + jobs[kind] + FOREIGN_AFTER, encoding="utf-8")
                before = self.snapshot(f)
                result, caught, observed = self.pause(f)
                self.assertTrue(caught is None, "qualified pause unexpectedly rejected")
                self.assertTrue(result is None, "qualified pause returns only None")
                self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN,
                                "foreign bytes/order/no-final-LF must be retained exactly")
                self.assert_leaves_preserved(f, before, cron=kind == "absent")
                self.assertEqual(2 if kind == "absent" else 4, observed["reads"])
                self.assertEqual(0 if kind == "absent" else 1, observed["writes"])
                self.assertEqual(0 if kind == "absent" else 1, observed["committed"])
                lock = bound_file(f["lock"])[0]
                self.assertTrue(stat.S_IMODE(lock[2]) == 0o600 and lock[5] == 1,
                                "persistent project lock must be safely retained")

    def test_ambiguous_malformed_and_valid_plus_unknown_hold_whole_table(self):
        # Three of the original twelve states. Candidate is not ownership.
        for kind in ("foreign-comment-hit", "malformed-nul", "valid-plus-unknown-tail"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="pause-refusal-") as folder:
                f = self.fixture(folder)
                comment = (
                    "1 * * * * /PUBLIC/foreign-command # http-v3-req10c-auto "
                    + str(f["tool"] / "initial-setup.py") + "\n"
                )
                tail = canonical_job(f).replace(
                    " 2>&1 # http-v3-req10c-auto\n",
                    " 2>&1 && /PUBLIC/second-command # http-v3-req10c-auto\n",
                )
                if kind == "foreign-comment-hit":
                    listing = FOREIGN_BEFORE + comment + FOREIGN_AFTER
                    self.assertTrue(self.app._own_auto_cron_line(comment, f["tool"], f["credentials"]),
                                    "fixture must actually hit the old substring candidate")
                elif kind == "malformed-nul":
                    listing = FOREIGN_BEFORE + "\x00PUBLIC malformed listing\n" + FOREIGN_AFTER
                else:
                    listing = FOREIGN_BEFORE + canonical_job(f) + tail + FOREIGN_AFTER
                    self.assertTrue(self.app._own_auto_cron_line(tail, f["tool"], f["credentials"]),
                                    "unknown tail must not evade candidate qualification")
                f["cron"].write_text(listing, encoding="utf-8")
                before = self.snapshot(f)
                _result, caught, observed = self.pause(f)
                self.assert_safe_hold(caught)
                self.assertEqual(2, observed["reads"])
                self.assertEqual(0, observed["writes"])
                self.assertEqual(0, observed["committed"])
                self.assert_leaves_preserved(f, before, cron=True)

    def test_ambiguous_write_and_post_write_failures_never_retry_or_claim_rollback(self):
        # Three of the original twelve states. Real owned writes commit first.
        for fault in ("committed-timeout", "post-read-error", "post-read-mismatch"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="pause-outcome-") as folder:
                f = self.fixture(folder)
                f["cron"].write_text(FOREIGN_BEFORE + canonical_job(f) + FOREIGN_AFTER,
                                     encoding="utf-8")
                before = self.snapshot(f)
                _result, caught, observed = self.pause(f, fault=fault)
                self.assert_safe_hold(caught)
                self.assertEqual(1, observed["writes"])
                self.assertEqual(1, observed["committed"])
                self.assertEqual({"committed-timeout": 2, "post-read-error": 3,
                                  "post-read-mismatch": 4}[fault], observed["reads"])
                self.assert_leaves_preserved(f, before, cron=False)
                expected = (FOREIGN + "\n# PUBLIC concurrent foreign addition\n"
                            if fault == "post-read-mismatch" else FOREIGN)
                self.assertTrue(f["cron"].read_text(encoding="utf-8") == expected,
                                "actual committed bytes remain; failure must not cause a rewrite")

    def test_program_identity_release_priority_and_missing_state(self):
        # Two original program states plus three independent priority combinations
        # and one actual known-entry missing-state case: six fresh states here.
        cases = ("body-runtime", "body-assertion", "program-plus-known-release",
                 "known-plus-known-release", "release-program-only", "missing-state")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix="pause-primary-") as folder:
                f = self.fixture(folder)
                if case in ("body-assertion",):
                    f["cron"].write_text(FOREIGN_BEFORE + canonical_job(f) + FOREIGN_AFTER,
                                         encoding="utf-8")
                before = self.snapshot(f)
                body = None
                release = None
                fault = None
                if case in ("body-runtime", "program-plus-known-release"):
                    body = RuntimeError("PUBLIC body program identity")
                    fault = "read-program"
                elif case == "body-assertion":
                    body = AssertionError("PUBLIC body assertion identity")
                    fault = "write-program"
                elif case == "known-plus-known-release":
                    body = self.app.SetupError("PUBLIC body known identity")
                    fault = "read-known"
                if case in ("program-plus-known-release", "known-plus-known-release"):
                    release = OSError(errno.EIO, "PUBLIC release known identity")
                elif case == "release-program-only":
                    release = RuntimeError("PUBLIC release program identity")
                if case == "missing-state":
                    # Remove only these exact owned fixture leaves, then its
                    # empty private directory. This is not a SUT cleanup step.
                    f["credentials"].unlink()
                    f["marker"].unlink()
                    f["state"].rmdir()
                    before = self.snapshot(f)
                _result, caught, observed = self.pause(f, fault=fault, seed=body,
                                                       release_seed=release)
                if case in ("known-plus-known-release", "missing-state"):
                    self.assert_safe_hold(caught)
                else:
                    expected_error = release if case == "release-program-only" else body
                    self.assertTrue(caught is expected_error,
                                    "program primary must propagate as the original object")
                if release is not None:
                    self.assertEqual(1, observed["release_entries"])
                    self.assertEqual(1, observed["release_failures"])
                    self.assertTrue(observed["actual_release"],
                                    "release fault must follow the real original lock exit")
                self.assertEqual(1 if case == "body-assertion" else 0, observed["writes"])
                self.assertEqual(0, observed["committed"])
                self.assertEqual({"body-runtime": 1, "body-assertion": 2,
                                  "program-plus-known-release": 1,
                                  "known-plus-known-release": 1,
                                  "release-program-only": 2,
                                  "missing-state": 0}[case], observed["reads"])
                self.assert_leaves_preserved(f, before, cron=True)
                if case == "missing-state":
                    self.assertFalse(f["state"].exists(),
                                     "pause must not mkdir to manufacture a lock prerequisite")

    def test_real_install_pause_and_real_unsetup_preserve_foreign_lifecycle(self):
        # W1: two actual production scripts. Only the external crontab process
        # is modeled; no scheduler or queued command is executed.
        with tempfile.TemporaryDirectory(prefix="pause-real-workflow-") as folder:
            f = self.fixture(folder, marker=False)
            run, observed = self.adapter(f)
            with mock.patch.object(self.app.subprocess, "run", new=run):
                self.app._install_auto_watch(
                    f["tool"], f["credentials"], f["csv"], f["p2p"],
                    f["cache"], f["report"], f["snapshots"], force=False,
                )
            if observed["adapter_errors"]:
                fixture_hold()
            expected_job = canonical_job(f, python=str(Path(sys.executable).resolve()))
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN + "\n" + expected_job,
                            "real producer must match independent complete canonical job")
            self.assertTrue(f["marker"].read_bytes() == MARKER_BYTES,
                            "actual producer must create original canonical ownership marker")
            self.assertEqual(2, observed["reads"])
            self.assertEqual(1, observed["writes"])
            before = self.snapshot(f)
            lock_before = bound_file(f["lock"])[0]
            result, caught, paused = self.pause(f)
            self.assertTrue(caught is None, "actual generated watch must qualify for pause")
            self.assertTrue(result is None)
            self.assertEqual(4, paused["reads"])
            self.assertEqual(1, paused["writes"])
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN + "\n",
                            "pause retains the producer's existing foreign prefix exactly")
            self.assert_leaves_preserved(f, before, cron=False)
            lock_after = bound_file(f["lock"])[0]
            self.assertTrue(lock_after[:2] == lock_before[:2],
                            "pause must retain the original lock inode")
            cleanup_run, cleanup = self.adapter(f)
            with mock.patch.object(self.unsetup, "HTTP_BASE", str(f["root"])), \
                    mock.patch.object(self.unsetup.subprocess, "run", new=cleanup_run):
                self.unsetup._cleanup_req10c_auto_watch()
            if cleanup["adapter_errors"]:
                fixture_hold()
            self.assertFalse(f["credentials"].exists())
            self.assertFalse(f["marker"].exists())
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN + "\n")
            self.assertEqual(0, cleanup["writes"])
            self.assertTrue(bound_file(f["control"]) == before["control"],
                            "real unsetup must preserve the foreign control leaf")
            self.assertTrue(bound_file(f["lock"])[0][:2] == lock_before[:2],
                            "real unsetup must not delete the retained project lock")

    def test_real_canonical_quoted_paths_pause_and_unsetup(self):
        # Additive W1 quote case: this is the documented actual canonical
        # renderer, not a permissive arbitrary-quote or shell-expression input.
        with tempfile.TemporaryDirectory(prefix="pause-real-quoted-") as outer:
            folder = Path(outer) / "PUBLIC project 'alpha'"
            f = self.fixture(folder, marker=False)
            self.assertTrue(" " in str(f["tool"]) and "'" in str(f["credentials"]),
                            "owned input must actually exercise both path quoting boundaries")
            run, observed = self.adapter(f)
            with mock.patch.object(self.app.subprocess, "run", new=run):
                self.app._install_auto_watch(
                    f["tool"], f["credentials"], f["csv"], f["p2p"],
                    f["cache"], f["report"], f["snapshots"], force=False,
                )
            if observed["adapter_errors"]:
                fixture_hold()
            expected_job = canonical_job(f, python=str(Path(sys.executable).resolve()))
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN + "\n" + expected_job,
                            "real quoted producer must match independent complete canonical job")
            self.assertTrue(f["marker"].read_bytes() == MARKER_BYTES)
            self.assertEqual(2, observed["reads"])
            self.assertEqual(1, observed["writes"])
            before = self.snapshot(f)
            lock_before = bound_file(f["lock"])[0]
            result, caught, paused = self.pause(f)
            self.assertTrue(caught is None,
                            "documented canonical quoting cannot be treated as an absent own watch")
            self.assertTrue(result is None)
            self.assertEqual(4, paused["reads"])
            self.assertEqual(1, paused["writes"])
            self.assertEqual(1, paused["committed"])
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN + "\n",
                            "normal pause return must follow removal of the real quoted own job")
            self.assert_leaves_preserved(f, before, cron=False)
            self.assertTrue(bound_file(f["lock"])[0][:2] == lock_before[:2])
            cleanup_run, cleanup = self.adapter(f)
            with mock.patch.object(self.unsetup, "HTTP_BASE", str(f["root"])), \
                    mock.patch.object(self.unsetup.subprocess, "run", new=cleanup_run):
                self.unsetup._cleanup_req10c_auto_watch()
            if cleanup["adapter_errors"]:
                fixture_hold()
            self.assertFalse(f["credentials"].exists())
            self.assertFalse(f["marker"].exists())
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == FOREIGN + "\n")
            self.assertEqual(0, cleanup["writes"])
            self.assertTrue(bound_file(f["control"]) == before["control"])
            self.assertTrue(bound_file(f["lock"])[0][:2] == lock_before[:2])

    def test_unicode_non_lf_separators_hold_entire_physical_cron_line(self):
        # These are not cron LF boundaries. A canonical-looking suffix may
        # not license deletion of the independent foreign scheduled command.
        for label, separator in (
                ("NEL", "\u0085"),
                ("LINE-SEPARATOR", "\u2028"),
                ("PARAGRAPH-SEPARATOR", "\u2029")):
            with self.subTest(separator=label), \
                    tempfile.TemporaryDirectory(prefix="pause-non-lf-") as folder:
                f = self.fixture(folder)
                physical_foreign = (
                    "11 12 * * * /PUBLIC/foreign-command " + separator + canonical_job(f)
                )
                self.assertTrue(
                    physical_foreign.endswith("\n") and physical_foreign.count("\n") == 1,
                    "fixture must contain one complete physical LF cron line",
                )
                f["cron"].write_text(
                    FOREIGN_BEFORE + physical_foreign + FOREIGN_AFTER, encoding="utf-8",
                )
                before = self.snapshot(f)
                _result, caught, observed = self.pause(f)
                self.assert_safe_hold(caught)
                self.assertEqual(0, observed["writes"])
                self.assertEqual(0, observed["committed"])
                self.assert_leaves_preserved(f, before, cron=True)



if __name__ == "__main__":
    unittest.main()
