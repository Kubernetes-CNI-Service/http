"""I15 canonical fixture v3 draft; not executed or approved for W adoption.

The six original test methods and independent literal oracles are unchanged.
Default None creates one retained own0700 parent only after the real class setup
four workers settle. Explicit Root parent+birth6 must qualify before any worker.
Native stdlib cleanup remains original; UNKNOWN blocks this I15 class births,
not all other unittest suites. No new family/deadline/FD-retirement guarantee.
Original KAT contract/C2/P1/main/PTY bodies are not replaced. Canonical full and
finite single-scene issuance have distinct lifecycle/worker groupings.
"""
from __future__ import annotations

import builtins
from contextlib import ExitStack, contextmanager
from functools import wraps
from importlib.machinery import ModuleSpec
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from types import FunctionType, ModuleType
import unittest
from unittest import mock
import tempfile

from test_cases.module_loader import load_script, _ExactSourceLoader

ROOT = Path(__file__).resolve().parents[1]
INITIAL_SOURCE = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
WORKFLOW_ROOT_PARENT = None
WORKFLOW_ROOT_PARENT_BIRTH6 = None
RETAINED_ROOTS = []
EXPLANATION = "Legacy Summary counters: 原阶段计数，非目标终态"
SAFE_ARGS = ("invalid target outcome facts",)
READ = ["nv", "config", "show", "-o", "commands"]
NETWORK_SETTERS = (
    ("nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"),
    ("nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"),
    ("nv", "set", "interface", "eth0-1", "link", "state", "up"),
    ("nv", "set", "interface", "eth0-1", "type", "eth"),
    ("nv", "set", "system", "hostname", "EXAMPLE-IB01"),
)
EXPECTED = {
    "S0": "Target outcomes (authoritative):\n  targets=3 COMPLETED=0 CHECKED_ONLY=0 SKIPPED_NO_WORK=0 BLOCKED_PREREQUISITE=3 FAILED_AFTER_ATTEMPT=0 NOT_ATTEMPTED_AFTER_STOP=0\n  OOB snapshots: total=1 COLLECTED=0 FAILED=1\n  Network: written=0 readback_verified=0; IPv4: failed=0; would_change=0\n  EXAMPLE-IB01 via EXAMPLE-JUMP01: BLOCKED_PREREQUISITE Network.written=NOT_REACHED Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=NOT_REACHED\n  EXAMPLE-IB02 via EXAMPLE-JUMP01: BLOCKED_PREREQUISITE Network.written=NOT_REACHED Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=NOT_REACHED\n  EXAMPLE-IB03 via EXAMPLE-JUMP01: BLOCKED_PREREQUISITE Network.written=NOT_REACHED Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=NOT_REACHED",
    "S1": "Target outcomes (authoritative):\n  targets=1 COMPLETED=0 CHECKED_ONLY=1 SKIPPED_NO_WORK=0 BLOCKED_PREREQUISITE=0 FAILED_AFTER_ATTEMPT=0 NOT_ATTEMPTED_AFTER_STOP=0\n  OOB snapshots: total=1 COLLECTED=1 FAILED=0\n  Network: written=0 readback_verified=0; IPv4: failed=0; would_change=1\n  EXAMPLE-IB01 via EXAMPLE-JUMP01: CHECKED_ONLY Network.written=NO Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=YES",
    "S2": "Target outcomes (authoritative):\n  targets=1 COMPLETED=0 CHECKED_ONLY=0 SKIPPED_NO_WORK=1 BLOCKED_PREREQUISITE=0 FAILED_AFTER_ATTEMPT=0 NOT_ATTEMPTED_AFTER_STOP=0\n  OOB snapshots: total=1 COLLECTED=1 FAILED=0\n  Network: written=0 readback_verified=0; IPv4: failed=0; would_change=0\n  EXAMPLE-IB01 via EXAMPLE-JUMP01: SKIPPED_NO_WORK Network.written=NO Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=NO",
    "S3": "Target outcomes (authoritative):\n  targets=2 COMPLETED=0 CHECKED_ONLY=0 SKIPPED_NO_WORK=0 BLOCKED_PREREQUISITE=0 FAILED_AFTER_ATTEMPT=1 NOT_ATTEMPTED_AFTER_STOP=1\n  OOB snapshots: total=1 COLLECTED=1 FAILED=0\n  Network: written=1 readback_verified=1; IPv4: failed=1; would_change=1\n  EXAMPLE-IB01 via EXAMPLE-JUMP01: FAILED_AFTER_ATTEMPT Network.written=YES Network.readback_verified=YES IPv4.failed=YES would_change=YES\n  EXAMPLE-IB02 via EXAMPLE-JUMP01: NOT_ATTEMPTED_AFTER_STOP Network.written=NOT_REACHED Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=NOT_REACHED",
    "COMPLETED": "Target outcomes (authoritative):\n  targets=2 COMPLETED=1 CHECKED_ONLY=0 SKIPPED_NO_WORK=1 BLOCKED_PREREQUISITE=0 FAILED_AFTER_ATTEMPT=0 NOT_ATTEMPTED_AFTER_STOP=0\n  OOB snapshots: total=1 COLLECTED=1 FAILED=0\n  Network: written=1 readback_verified=1; IPv4: failed=0; would_change=1\n  ExAmPlE-IB02 via ExAmPlE-JUMP01: COMPLETED Network.written=YES Network.readback_verified=YES IPv4.failed=NO would_change=YES\n  EXAMPLE-IB01 via EXAMPLE-JUMP01: SKIPPED_NO_WORK Network.written=NO Network.readback_verified=NOT_REACHED IPv4.failed=NOT_REACHED would_change=NO",
}
TARGET_ROWS = {
    "S0": (("EXAMPLE-IB01", "EXAMPLE-JUMP01", "BLOCKED_PREREQUISITE", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED"), ("EXAMPLE-IB02", "EXAMPLE-JUMP01", "BLOCKED_PREREQUISITE", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED"), ("EXAMPLE-IB03", "EXAMPLE-JUMP01", "BLOCKED_PREREQUISITE", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED")),
    "S1": (("EXAMPLE-IB01", "EXAMPLE-JUMP01", "CHECKED_ONLY", "NO", "NOT_REACHED", "NOT_REACHED", "YES"),),
    "S2": (("EXAMPLE-IB01", "EXAMPLE-JUMP01", "SKIPPED_NO_WORK", "NO", "NOT_REACHED", "NOT_REACHED", "NO"),),
    "S3": (("EXAMPLE-IB01", "EXAMPLE-JUMP01", "FAILED_AFTER_ATTEMPT", "YES", "YES", "YES", "YES"), ("EXAMPLE-IB02", "EXAMPLE-JUMP01", "NOT_ATTEMPTED_AFTER_STOP", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED", "NOT_REACHED")),
    "COMPLETED": (("ExAmPlE-IB02", "ExAmPlE-JUMP01", "COMPLETED", "YES", "YES", "NO", "YES"), ("EXAMPLE-IB01", "EXAMPLE-JUMP01", "SKIPPED_NO_WORK", "NO", "NOT_REACHED", "NOT_REACHED", "NO")),
}



SUMMARY_PEER_BASE_SHA256 = "a6cee346fc36929849a68bb98f18f4859b2ea1ca064d5a7e88262f8551f47af9"
SUMMARY_PEER_TRANSFORMS = (
    ("OOB two ports", "          (\"nv\",\"show\",\"interface\"): \"Interface Admin Oper\\nswp7 up up\\n\",\n", "          (\"nv\",\"show\",\"interface\"): \"Interface Admin Oper\\nswp7 up up\\nswp8 up up\\n\",\n"),
    ("OOB two link ports and one vlan", "          (\"ip\",\"-d\",\"link\",\"show\"): \"7: swp7: <BROADCAST,UP> mtu 1500 state UP\\n    link/ether 02:00:00:00:00:07\\n8: vlan1: <UP> mtu 1500 state UP\\n    vlan protocol 802.1Q id 1\\n\",\n", "          (\"ip\",\"-d\",\"link\",\"show\"): \"7: swp7: <BROADCAST,UP> mtu 1500 state UP\\n    link/ether 02:00:00:00:00:07\\n8: swp8: <BROADCAST,UP> mtu 1500 state UP\\n    link/ether 02:00:00:00:00:08\\n9: vlan1: <UP> mtu 1500 state UP\\n    vlan protocol 802.1Q id 1\\n\",\n"),
    ("OOB two FDB literals", "          (\"bridge\",\"fdb\",\"show\"): \"02:00:00:00:00:17 dev swp7 vlan 1 dynamic\\n\",\n", "          (\"bridge\",\"fdb\",\"show\"): \"02:00:00:00:00:17 dev swp7 vlan 1 dynamic\\n02:00:00:00:00:18 dev swp8 vlan 1 dynamic\\n\",\n"),
    ("OOB two ND literals", "          (\"ip\",\"neighbor\"): \"fe80::17 dev vlan1 lladdr 02:00:00:00:00:17 REACHABLE\\n\",\n", "          (\"ip\",\"neighbor\"): \"fe80::17 dev vlan1 lladdr 02:00:00:00:00:17 REACHABLE\\nfe80::18 dev vlan1 lladdr 02:00:00:00:00:18 REACHABLE\\n\",\n"),
    ("closed four endpoints to independent literal state basenames", "    if destination not in (\"admin@fe80::17\", \"admin@203.0.113.2\"):\n        raise ValueError(\"inner endpoint\")\n", "    if destination in (\"admin@fe80::17\", \"admin@203.0.113.2\"):\n        summary_target, summary_state = \"IB01\", \"summary-device-01.json\"\n    elif destination in (\"admin@fe80::18\", \"admin@203.0.113.3\"):\n        summary_target, summary_state = \"IB02\", \"summary-device-02.json\"\n    else:\n        raise ValueError(\"inner endpoint\")\n    selected_state_path = root / summary_state\n    record(\"summary-target-entry\", target=summary_target)\n"),
    ("actual selected state read and closed identity", "        S = json.loads(state_path.read_text())\n", "        S = json.loads(selected_state_path.read_text())\n        if S.get(\"summary_target\") != summary_target:\n            raise ValueError(\"summary state identity\")\n"),
    ("existing PAM persistence local selected state", "            state_path.write_text(json.dumps(S))\n", "            selected_state_path.write_text(json.dumps(S))\n"),
    ("ordinary business exact IPv4 destination fact and selected state persistence", "        body, rc = business(command,S)\n        state_path.write_text(json.dumps(S))\n", "        S[\"summary_ipv4\"] = destination == \"admin@203.0.113.2\"\n        body, rc = business(command,S)\n        selected_state_path.write_text(json.dumps(S))\n"),
    ("finite peer state/show/business wrapper before original run", "def run():\n", "_summary_base_show_state = show_state\n_summary_base_business = business\ndef show_state(S):\n    body = _summary_base_show_state(S)\n    if S[\"summary_target\"] == \"IB02\":\n        body = body.replace(\n            \"nv set system hostname EXAMPLE-IB01\\n\",\n            \"nv set system hostname EXAMPLE-IB02\\n\")\n        body = body.replace(\n            \"nv set interface eth0 ipv4 address 203.0.113.2/24\\n\",\n            \"nv set interface eth0 ipv4 address 203.0.113.3/24\\n\")\n    return body\ndef business(command, S):\n    if (S[\"summary_target\"] == \"IB01\" and S.get(\"summary_ipv4\") is True\n            and command == [\"true\"] and S.get(\"summary_network_saved\") is True):\n        record(\"summary-ipv4-fault\", target=\"IB01\")\n        return \"PUBLIC IPv4 verification could not complete\\n\", 255\n    before_network = S[\"network\"]\n    body, rc = _summary_base_business(command, S)\n    if (S[\"summary_target\"] == \"IB01\"\n            and command == [\"nv\", \"config\", \"apply\", \"-y\"]\n            and rc == 0 and before_network is False and S[\"network\"] is True):\n        S[\"summary_network_applied\"] = True\n        record(\"summary-network-applied\", target=\"IB01\", actual_rc=rc)\n    if (S[\"summary_target\"] == \"IB01\"\n            and command == [\"nv\", \"config\", \"save\"]\n            and rc == 0 and S.get(\"summary_network_applied\") is True):\n        S[\"summary_network_saved\"] = True\n        record(\"summary-network-saved\", target=\"IB01\", actual_rc=rc)\n    return body, rc\n\ndef run():\n"),
)


def _summary_two_target_peer(caller):
    # Fixture qualification only: exact original generated peer, no SUT oracle.
    original = caller.peer_program()
    if (type(original) is not str or
            hashlib.sha256(original.encode("utf-8")).hexdigest()
            != SUMMARY_PEER_BASE_SHA256):
        raise RuntimeError("NOT_READY: original PUBLIC summary peer changed")
    program = original
    for label, old, new in SUMMARY_PEER_TRANSFORMS:
        if program.count(old) != 1:
            raise RuntimeError("NOT_READY: unique PUBLIC summary peer anchor absent")
        program = program.replace(old, new, 1)
    restored = program
    for label, old, new in reversed(SUMMARY_PEER_TRANSFORMS):
        if restored.count(new) != 1:
            raise RuntimeError("NOT_READY: unique PUBLIC summary peer inverse absent")
        restored = restored.replace(new, old, 1)
    if restored != original:
        raise RuntimeError("NOT_READY: PUBLIC summary peer whole inverse differs")
    return program


@contextmanager
def _pure_boundary(attempts):
    def refuse(*args, **kwargs):
        attempts.append("PUBLIC pure reporter attempted external effect")
        raise AssertionError("PUBLIC reporter must be pure")
    with ExitStack() as stack:
        for owner, names in (
                (builtins, ("open", "print", "input")),
                (os, ("open", "read", "write", "stat", "lstat", "readlink",
                      "system", "fork", "forkpty", "posix_spawn", "posix_spawnp",
                      "kill", "killpg", "waitpid")),
                (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
                (socket, ("socket", "create_connection"))):
            for name in names:
                if hasattr(owner, name):
                    stack.enter_context(mock.patch.object(owner, name, new=refuse))
        yield


class _CanonicalI15FixtureReadiness:
    """Finite fixture readiness, not a global runner or process-family proof.

    No cleanup is added. Unittest can continue other TestCases/modules after an
    error; this state only blocks later births in this I15 workflow class.
    Original KAT/worker/Caller/Base operations remain the actual implementations.
    """
    HOLD = "FIXTURE HOLD: I15 fixture readiness/custody unknown; evidence retained"

    def __init__(self, base):
        self.base = base
        self.owner_pid = os.getpid()
        self.unknown = False
        self.secondary_errors = []
        self.native = []
        self.pending_native = None
        self.setup_complete = False
        self.parent = None
        self.parent_birth6 = None
        self.parent_fd = None
        self.parent_fd_birth5 = None
        self.parent_nlink = None
        self.children = {}
        self.parent_birth_pending = False
        self.fixtures = []
        self.results = []
        self.interactive_depth = 0
        self.pty = []
        self.current_fixture = None

    def hold(self):
        self.unknown = True
        raise RuntimeError(self.HOLD)

    def gate(self):
        if self.unknown:
            raise RuntimeError(self.HOLD)

    @staticmethod
    def nine(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def close_directory_once(self, fd, birth5, primary=None):
        # Caller consumes its slot before this one attempt. A stale integer
        # receives no close, retry, reopen or post-consumption query.
        try:
            current = os.fstat(fd)
            if birth5 is None or self.nine(current)[:5] != birth5:
                self.hold()
        except BaseException as error:
            self.unknown = True
            self.secondary_errors.append(error)
            if primary is None:
                raise
            return
        try:
            os.close(fd)
        except BaseException as error:
            self.unknown = True
            self.secondary_errors.append(error)
            if primary is None:
                raise

    def close_parent_once(self):
        fd, self.parent_fd = self.parent_fd, None
        if fd is not None:
            self.close_directory_once(fd, self.parent_fd_birth5)

    def bind_parent(self, parent, expected_birth6=None):
        self.gate()
        if parent is None:
            if (not self.setup_complete or len(self.native) != 4
                    or expected_birth6 is not None):
                self.hold()
            self.parent_birth_pending = True
            try:
                parent = Path(tempfile.mkdtemp(prefix="http-i15-summary-parent-"))
            except BaseException:
                self.unknown = True
                raise
            finally:
                self.parent_birth_pending = False
        elif (type(expected_birth6) is not tuple or len(expected_birth6) != 6
              or any(type(value) is not int or value < 0
                     for value in expected_birth6)):
            self.hold()
        if type(parent) is not type(Path()) or not parent.is_absolute():
            self.hold()
        before = parent.lstat()
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o700
                or (expected_birth6 is not None
                    and self.nine(before)[:6] != expected_birth6)):
            self.hold()
        self.parent = parent  # retain actual path even on later failure
        self.parent_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        actual = os.fstat(self.parent_fd)
        self.parent_fd_birth5 = self.nine(actual)[:5]
        if self.nine(actual) != self.nine(before) or list(os.listdir(self.parent_fd)):
            self.hold()
        self.parent_birth6 = self.nine(actual)[:6]
        self.parent_nlink = actual.st_nlink
        self.check_parent()
        return parent

    def child_identity(self, name):
        before = os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o700):
            self.hold()
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                     | os.O_CLOEXEC, dir_fd=self.parent_fd)
        birth5 = None
        primary = None
        try:
            actual = os.fstat(fd)
            birth5 = self.nine(actual)[:5]
            after = os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False)
            if not (self.nine(before) == self.nine(actual) == self.nine(after)
                    == self.nine(os.fstat(fd))):
                self.hold()
            return birth5
        except BaseException as error:
            primary = error
            self.unknown = True
            raise
        finally:
            owned, fd = fd, None
            self.close_directory_once(owned, birth5, primary)

    def check_parent(self, new_child=None):
        try:
            return self._check_parent(new_child)
        except BaseException:
            self.unknown = True
            raise

    def _check_parent(self, new_child):
        self.gate()
        if self.parent_fd is None or self.parent_birth6 is None:
            self.hold()
        before = os.fstat(self.parent_fd)
        named = self.parent.lstat()
        if (self.nine(before) != self.nine(named)
                or self.nine(before)[:5] != self.parent_birth6[:5]):
            self.hold()
        expected = dict(self.children)
        new_name = None
        if new_child is not None:
            if (type(new_child) is not type(Path())
                    or new_child.parent != self.parent
                    or new_child.name in expected):
                self.hold()
            new_name = new_child.name
            expected[new_name] = None
        names = sorted(os.listdir(self.parent_fd))
        if names != sorted(expected):
            self.hold()
        observed = {}
        for name in names:
            identity = self.child_identity(name)
            if name != new_name and identity != expected[name]:
                self.hold()
            observed[name] = identity
        after = os.fstat(self.parent_fd)
        if (self.nine(before) != self.nine(after)
                or self.nine(after) != self.nine(self.parent.lstat())
                or sorted(os.listdir(self.parent_fd)) != names):
            self.hold()
        if new_name is None:
            if after.st_nlink != self.parent_nlink:
                self.hold()
        else:
            # Only one original mkdtemp's returned, registered child can advance
            # parent nlink. No OS-specific +1 assumption. Child nlink/times may
            # change through legitimate internal fixture work; their stable
            # dev/ino/mode/uid/gid never change or silently refresh.
            self.children[new_name] = observed[new_name]
            self.parent_nlink = after.st_nlink
        return self.parent

    @contextmanager
    def private_umask(self):
        self.gate()
        try:
            old = os.umask(0o077)
        except BaseException:
            self.unknown = True
            raise
        primary = None
        try:
            yield
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                os.umask(old)
            except BaseException as error:
                self.unknown = True
                self.secondary_errors.append(error)
                if primary is None:
                    raise

    @contextmanager
    def native_scope(self, source, phase, app=None):
        self.gate()
        if self.pending_native is not None or phase not in ("setup", "p1", "main"):
            self.hold()
        scope_start = len(self.native)
        source_before = self.base.bound_file(source)
        if (type(source) is not type(Path()) or not source.is_absolute()
                or source.is_symlink()
                or source_before[1] != self.base.bound_file(INITIAL_SOURCE)[1]):
            self.hold()
        real_run, real_popen = subprocess.run, subprocess.Popen
        real_kill, real_killpg, real_close = os.kill, os.killpg, os.close
        real_pty_fork = None if app is None else app.pty.fork
        real_interactive = None if app is None else app.interactive_run
        patchers = []
        primary = None

        def install(owner, name, replacement):
            patcher = mock.patch.object(owner, name, new=replacement)
            patcher.start()
            patchers.append(patcher)

        def popen(*args, **kwargs):
            self.gate()
            if self.pending_native is None:
                self.hold()
            slot = {"object": None, "returned": False, "settled": False,
                    "phase": phase}
            self.native.append(slot)
            try:
                process = real_popen(*args, **kwargs)
            except BaseException:
                self.unknown = True
                raise
            # Hand the identical actual object to original run/CM immediately.
            # No proxy, frame reflection or diagnostic call before handoff.
            slot["object"], slot["returned"] = process, True
            return process

        def run(argv, *args, **kwargs):
            try:
                self.gate()
                self.sync_pty()
                if (phase == "p1" or self.interactive_depth
                        or self.pending_native is not None
                        or not all(slot["settled"] for slot in self.native)
                        or not all(slot["reaped"] and slot["closed"]
                                   for slot in self.pty)):
                    self.hold()
                limit = 4 if phase == "setup" else 10
                if len(self.native) - scope_start >= limit:
                    self.hold()
                if (type(argv) is not list or argv != [
                        sys.executable, "-I", "-S", "-B", str(source.resolve()),
                        "--_verify-password"] or args
                        or set(kwargs) != {"input", "text", "capture_output",
                                           "timeout", "check", "env"}
                        or type(kwargs["input"]) is not str
                        or kwargs["text"] is not True
                        or kwargs["capture_output"] is not True
                        or kwargs["timeout"] != 8 or kwargs["check"] is not False
                        or kwargs["env"] != {
                            "PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                            "PYTHONDONTWRITEBYTECODE": "1"}):
                    self.hold()
                before = len(self.native)
                self.pending_native = phase
                try:
                    result = real_run(argv, **kwargs)
                except BaseException:
                    self.unknown = True
                    raise
                finally:
                    self.pending_native = None
                if len(self.native) != before + 1:
                    self.hold()
                slot = self.native[-1]
                process = slot["object"]
                settled = (
                    slot["returned"] and type(process.returncode) is int
                    and process.returncode == result.returncode
                    and all(getattr(process, name) is not None
                            and getattr(process, name).closed is True
                            for name in ("stdin", "stdout", "stderr")))
                slot["settled"] = settled
                if not settled or result.returncode != 0:
                    self.hold()
                if self.base.bound_file(source) != source_before:
                    self.hold()
                return result
            except BaseException:
                self.unknown = True
                raise

        def fork(*args, **kwargs):
            if os.getpid() == self.owner_pid:
                self.gate()
                self.sync_pty()
                if (phase != "main" or self.pending_native is not None
                        or not all(slot["settled"] for slot in self.native)
                        or not all(slot["reaped"] and slot["closed"]
                                   for slot in self.pty)):
                    self.hold()
            try:
                pair = real_pty_fork(*args, **kwargs)
            except BaseException:
                self.unknown = True
                raise
            if pair[0] == 0:
                return pair
            slot = {"pid": pair[0], "fd": pair[1], "fixture": self.current_fixture,
                    "birth": None, "consumed": False, "closed": False,
                    "reaped": False}
            self.pty.append(slot)
            try:
                info = os.fstat(pair[1])  # active actual birth only
                if not stat.S_ISCHR(info.st_mode):
                    self.hold()
                slot["birth"] = (self.nine(info)[:7], info.st_rdev)
            except BaseException as error:
                self.unknown = True
                self.secondary_errors.append(error)
            # Never replace the actual pair with a proxy or deny original
            # current-child cleanup after the real fork has already returned.
            return pair

        def close(fd):
            if os.getpid() != self.owner_pid or self.pending_native is not None:
                return real_close(fd)
            active = [slot for slot in self.pty
                      if slot["fd"] == fd and not slot["consumed"]]
            if not active:
                return real_close(fd)
            if len(active) != 1:
                self.unknown = True
                return real_close(fd)
            slot = active[0]
            same = False
            try:
                info = os.fstat(fd)  # before original consuming close only
                same = slot["birth"] == (self.nine(info)[:7], info.st_rdev)
            except BaseException as error:
                self.unknown = True
                self.secondary_errors.append(error)
            slot["consumed"] = True
            if not same:
                self.unknown = True
            try:
                answer = real_close(fd)  # original operation, once, unchanged
            except BaseException:
                self.unknown = True
                raise
            slot["closed"] = same
            return answer

        def signal_call(function, pid, sig):
            if os.getpid() == self.owner_pid and self.pending_native is None:
                # Observe an original exceptional/fixture cleanup request;
                # never suppress it, add another signal or invent ownership.
                self.unknown = True
            return function(pid, sig)

        def interactive(*args, **kwargs):
            self.gate()
            self.interactive_depth += 1
            try:
                return real_interactive(*args, **kwargs)
            except BaseException as error:
                if (getattr(error, "cleanup_uncertain", None) is True
                        or not isinstance(error, app.SetupError)):
                    self.unknown = True
                raise
            finally:
                self.interactive_depth -= 1

        try:
            install(subprocess, "run", run)
            install(subprocess, "Popen", popen)
            # No waitpid hook is installed. Caller retains its actual product
            # reap observer. Native signal/close paths are transparent stdlib
            # delegates; PTY close observation never queries retired FDs.
            install(os, "kill", lambda pid, sig: signal_call(real_kill, pid, sig))
            install(os, "killpg", lambda pid, sig: signal_call(real_killpg, pid, sig))
            if app is not None:
                install(app.pty, "fork", fork)
                install(os, "close", close)
                install(app, "interactive_run", interactive)
            yield
        except BaseException as error:
            primary = error
            self.unknown = True
            raise
        finally:
            first_restore = None
            # Only these standard mock.patch operations, not arbitrary
            # suppressing context managers. Every entered original restore is
            # attempted once in LIFO order even after an earlier restore error.
            for patcher in reversed(patchers):
                try:
                    patcher.stop()
                except BaseException as error:
                    self.unknown = True
                    self.secondary_errors.append(error)
                    if first_restore is None:
                        first_restore = error
            if primary is None and first_restore is not None:
                raise first_restore

    def sync_pty(self):
        for slot in self.pty:
            if slot["reaped"]:
                continue
            witness = slot["fixture"]["caller"]
            if any(pid == slot["pid"] for pid, status in witness["reaps"]):
                slot["reaped"] = True
            if any(pid == slot["pid"] for pid, status in witness["fixture_reaps"]):
                self.unknown = True
        self.gate()

    def fixture_returned(self, actual):
        self.gate()
        self.fixtures.append(actual)
        if (actual["source"].is_symlink()
                or self.base.bound_file(actual["source"])[1]
                != self.base.bound_file(INITIAL_SOURCE)[1]):
            self.hold()
        for key in ("global_path", "config"):
            info = actual[key].lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                self.hold()

    def invoke_returned(self, fixture, actual):
        self.results.append(actual)  # exact original object retained, not changed
        self.sync_pty()
        witness = fixture["caller"]
        if (actual["cleanup"] or fixture["boundary_errors"]
                or witness["fixture_reaps"]
                or any(event["kind"] == "adapter-error"
                       for event in actual["events"])
                or sorted(witness["slots"])
                   != sorted(pid for pid, status in witness["reaps"])):
            self.unknown = True
        self.gate()

    def after_method(self):
        self.gate()
        self.sync_pty()
        self.check_parent()
        if (self.pending_native is not None or self.interactive_depth
                or not all(slot["settled"] for slot in self.native)
                or not all(slot["reaped"] and slot["closed"]
                           for slot in self.pty)):
            self.hold()


class TargetOutcomeSummaryDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = INITIAL_SOURCE
        if (type(path) is not type(Path()) or not path.is_absolute()
                or path.is_symlink() or not path.is_file()):
            raise RuntimeError("NOT_READY: complete Initial source missing")
        name = "_i15_summary_actual_complete_initial"
        if name in sys.modules:
            raise RuntimeError("NOT_READY: summary source namespace occupied")
        cls.app = load_script(name, path)
        cls.owned_name = name
        spec = getattr(cls.app, "__spec__", None)
        if not (
                type(cls.app) is ModuleType and type(spec) is ModuleSpec
                and type(spec.loader) is _ExactSourceLoader
                and spec.origin == str(path) and spec.loader.path == str(path)
                and cls.app.__file__ == str(path)
                and cls.app.__loader__ is spec.loader):
            raise RuntimeError("NOT_READY: actual Initial origin differs")

    @classmethod
    def tearDownClass(cls):
        if sys.modules.get(cls.owned_name) is cls.app:
            del sys.modules[cls.owned_name]

    def renderer(self):
        function = getattr(self.app, "_render_target_outcome_summary", None)
        self.assertIs(type(function), FunctionType,
                      "new private reporting contract is not implemented")
        self.assertTrue(function.__globals__ is vars(self.app)
                        and function.__code__.co_filename == str(INITIAL_SOURCE))
        return function

    def observe(self, function, targets, ethernet):
        value = error = None
        attempts = []
        with _pure_boundary(attempts):
            try:
                value = function(target_results=targets, ethernet_results=ethernet)
            except BaseException as caught:
                error = caught
        self.assertEqual([], attempts)
        return value, error

    def test_four_independent_reports_and_pure_completed_positive(self):
        function = self.renderer()
        for scene in ("S0", "S1", "S2", "S3", "COMPLETED"):
            with self.subTest(scene=scene):
                ethernet = (("EXAMPLE-JUMP01",
                             "FAILED" if scene == "S0" else "COLLECTED"),)
                value, error = self.observe(function, TARGET_ROWS[scene], ethernet)
                self.assertIsNone(error, "valid independent reporting facts rejected")
                self.assertIs(type(value), str)
                self.assertEqual(EXPECTED[scene], value)

    def test_duplicate_identity_or_unknown_closed_fact_is_exact_safe_even_in_ambient_error(self):
        function = self.renderer()
        good = ("EXAMPLE-IB01", "EXAMPLE-JUMP01", "COMPLETED", "YES", "YES", "NO", "YES")
        same_identity_other_OOB = ("example-ib01", "EXAMPLE-JUMP02", *good[2:])
        changed_bucket = (good[0], good[1], "NOT_A_KNOWN_OUTCOME", *good[3:])
        changed_fact = (*good[:3], "NOT_A_KNOWN_FACT", *good[4:])
        cases = (
            ((good, same_identity_other_OOB),
             (("EXAMPLE-JUMP01", "COLLECTED"), ("EXAMPLE-JUMP02", "COLLECTED"))),
            ((good,), (("EXAMPLE-JUMP01", "COLLECTED"),
                       ("example-jump01", "COLLECTED"))),
            ((changed_bucket,), (("EXAMPLE-JUMP01", "COLLECTED"),)),
            ((changed_fact,), (("EXAMPLE-JUMP01", "COLLECTED"),)),
        )
        for number, (targets, ethernet) in enumerate(cases):
            with self.subTest(case=number):
                try:
                    raise ValueError("PUBLIC unrelated ambient reporting error")
                except ValueError:
                    value, error = self.observe(function, targets, ethernet)
                self.assertIsNone(value)
                self.assertIs(type(error), self.app.SetupError)
                self.assertEqual(SAFE_ARGS, error.args)
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)
                self.assertEqual({}, vars(error))


class TargetOutcomeSummaryMainWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global WORKFLOW_ROOT_PARENT, WORKFLOW_ROOT_PARENT_BIRTH6
        # Re-entry never resets an earlier UNKNOWN, even after normal completion.
        if "_canonical_i15" in cls.__dict__:
            raise RuntimeError(_CanonicalI15FixtureReadiness.HOLD)
        from test_cases import test_initial_setup_main_caller_precommit as caller
        if caller.base.INITIAL != INITIAL_SOURCE:
            raise RuntimeError("NOT_READY: direct and workflow Initial sources differ")
        cls.caller = caller
        cls.base = caller.base
        state = _CanonicalI15FixtureReadiness(cls.base)
        cls._canonical_i15 = state
        cls.addClassCleanup(state.close_parent_once)
        parent = WORKFLOW_ROOT_PARENT
        try:
            if parent is not None:
                # Fixed external identity is supplied only by Root. Invalid
                # path/alias/owner/mode/identity fails BEFORE setup workers.
                state.bind_parent(parent, WORKFLOW_ROOT_PARENT_BIRTH6)
            elif WORKFLOW_ROOT_PARENT_BIRTH6 is not None:
                state.hold()
            # Unittest invokes this descriptor once. It is not called manually
            # per method; canonical four workflows share this one setup4.
            with state.native_scope(INITIAL_SOURCE, "setup"):
                caller.MainCallerPrecommitDraftTests.setUpClass.__func__(cls)
            if len(state.native) != 4 or not all(s["settled"] for s in state.native):
                state.hold()
            state.setup_complete = True
            if parent is None:
                parent = state.bind_parent(None)
            else:
                state.check_parent()
            WORKFLOW_ROOT_PARENT = parent
            WORKFLOW_ROOT_PARENT_BIRTH6 = state.parent_birth6
        except BaseException:
            state.unknown = True
            raise

    def setUp(self):
        try:
            self._canonical_i15.gate()
            self._canonical_i15.check_parent()
        except BaseException:
            self._canonical_i15.unknown = True
            raise

    def tearDown(self):
        # ERROR/HOLD is recorded in addition to, never substituted for, any
        # original business failure. Other unittest classes can still continue.
        self._canonical_i15.after_method()

    def fixed_hold(self):
        return self.caller.MainCallerPrecommitDraftTests.fixed_hold(self)

    def fixture(self, folder, **kwargs):
        state = self._canonical_i15
        state.gate()
        state.check_parent()
        try:
            actual = self.caller.MainCallerPrecommitDraftTests.fixture(
                self, folder, **kwargs)
            state.fixture_returned(actual)
            return actual
        except BaseException:
            state.unknown = True
            raise

    def events(self, f):
        return self.caller.MainCallerPrecommitDraftTests.events(self, f)

    def invoke(self, f, *options, **kwargs):
        state = self._canonical_i15
        state.gate()
        if (not any(f is item for item in state.fixtures) or kwargs
                or options not in ((), ("--generate-json",), ("--apply", "--yes"))):
            state.hold()
        phase = "p1" if options == ("--generate-json",) else "main"
        state.current_fixture = f
        try:
            with state.native_scope(f["source"], phase, app=f["app"]):
                actual = self.caller.MainCallerPrecommitDraftTests.invoke(
                    self, f, *options, **kwargs)
                state.invoke_returned(f, actual)
            return actual
        except BaseException:
            state.unknown = True
            raise

    def p1(self, f):
        return self.caller.MainCallerPrecommitDraftTests.p1(self, f)

    @contextmanager
    def root(self):
        # All roots remain retained. No new process/recursive/second cleanup.
        state = self._canonical_i15
        state.gate()
        parent = state.check_parent()
        info = parent.lstat()
        self.assertTrue(stat.S_ISDIR(info.st_mode) and not parent.is_symlink()
                        and info.st_uid == os.getuid()
                        and stat.S_IMODE(info.st_mode) == 0o700)
        with state.private_umask():
            try:
                path = Path(tempfile.mkdtemp(prefix="i15-summary-public-", dir=parent))
                RETAINED_ROOTS.append(str(path))
                owned = path.lstat()
                self.assertTrue(stat.S_ISDIR(owned.st_mode)
                                and owned.st_uid == os.getuid()
                                and stat.S_IMODE(owned.st_mode) == 0o700)
                # Only a returned original child birth may advance nlink.
                state.check_parent(new_child=path)
            except BaseException:
                state.unknown = True
                raise
            yield path

    def no_keys_before_real_p1(self, f):
        # Existing _public_key_profile skips blank project-preparation files.
        # Own PUBLIC fixture only, BEFORE P1. Never alter a produced cache.
        directory = f["root"] / "infiniband/publickey"
        for name in ("laptop.pub", "mgmt-server.pub"):
            path = directory / name
            self.assertTrue(path.is_file() and not path.is_symlink())
            path.write_text("", encoding="ascii")
        self.p1(f)
        cache = json.loads(f["cache"].read_text(encoding="utf-8"))
        self.assertEqual([], cache["public_keys"])
        return cache

    def protect(self, f):
        names = ("source", "global_path", "csv", "p2p", "auth", "control", "cron", "cache")
        captured = {name: self.base.bound_file(f[name]) for name in names}
        checksum = f["cache"].with_name(f["cache"].name + ".sha256")
        captured["cache_checksum"] = self.base.bound_file(checksum)
        return captured

    def require_preserved(self, f, before):
        for name, identity in before.items():
            path = (f["cache"].with_name(f["cache"].name + ".sha256")
                    if name == "cache_checksum" else f[name])
            self.assertTrue(self.base.bound_file(path) == identity,
                            "protected PUBLIC input/foreign bytes changed; values suppressed")
        self.assertFalse(any(path.exists() for path in
                             (f["credentials"], f["marker"], f["terminal"])))

    def require_product_custody(self, f, result):
        w = f["caller"]
        self.assertTrue(bool(w["slots"]) and len(w["slots"]) == len(set(w["slots"])))
        self.assertEqual(sorted(w["slots"]), sorted(pid for pid, status in w["reaps"]))
        self.assertEqual([], w["fixture_reaps"])
        self.assertEqual([], result["cleanup"])
        self.assertEqual([], f["boundary_errors"])

    def require_report(self, result, scene, legacy):
        lines = result["stdout"].splitlines()
        self.assertEqual(1, lines.count(EXPLANATION))
        self.assertEqual(1, lines.count(legacy))
        self.assertIn(EXPECTED[scene] + "\n", result["stdout"])
        self.assertEqual(1, result["stdout"].count(EXPECTED[scene] + "\n"))

    def test_S0_one_real_OOB_failure_blocks_three_unattempted_IB_targets(self):
        with self.root() as folder:
            f = self.fixture(folder, case="summary-oob-failed", scenario="outer-denied",
                             network=True, services=True, credential="initial")
            f["csv"].write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:17,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:18,,,\n"
                "EXAMPLE-IB03,ib,203.0.113.4,24,203.0.113.1,02:00:00:00:00:19,,,\n"
                "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n", encoding="ascii")
            f["p2p"].write_text(
                '"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n'
                '"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n'
                '"EXAMPLE-IB03":"eth0" -- "EXAMPLE-JUMP01":"9";\n', encoding="ascii")
            cache = self.no_keys_before_real_p1(f)
            self.assertEqual(3, cache["ib_candidate_count"])
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02", "EXAMPLE-IB03"],
                             [row["ib"]["hostname"] for row in cache["targets"]])
            self.assertEqual(["EXAMPLE-JUMP01"] * 3,
                             [row["ethernet"]["hostname"] for row in cache["targets"]])
            before, start = self.protect(f), len(self.events(f))
            result = self.invoke(f, "--apply", "--yes")
            fresh = self.events(f)[start:]
            self.assertIsNone(result["error"], "qualified OOB refusal must reach original summary")
            self.assertEqual(1, result["rc"])
            self.assertEqual(1, sum(e["kind"] == "non-auth-refusal"
                                  and e.get("reason") == "outer-denied" for e in fresh))
            self.assertEqual(1, sum(e["kind"] == "outer-answer" for e in fresh))
            self.assertFalse(any(e["kind"] in ("inner-answer", "nested-dispatch", "mutation",
                                               "apply-y", "save", "key-shell", "ipv4-read",
                                               "pam-target") for e in fresh))
            self.assertTrue(not f["caller"]["selector"] and not f["caller"]["native"]
                            and not f["caller"]["fetch"] and not f["caller"]["helper"])
            self.require_product_custody(f, result)
            self.require_preserved(f, before)
            self.require_report(result, "S0",
                "Summary: targets=3 configured=0 skipped=0 failed=3 day0-skipped=0 services-skipped=0")

    def test_S1_actual_checkonly_missing_plan_never_counts_an_update(self):
        with self.root() as folder:
            f = self.fixture(folder, case="readonly-initial",
                             network=False, services=True, credential="initial")
            self.no_keys_before_real_p1(f)
            before, start = self.protect(f), len(self.events(f))
            plans = []
            original = f["app"]._management_network_commands
            @wraps(original)
            def constructor(device, current):
                value = original(device, current)
                plans.append(tuple(tuple(command) for command in value))
                return value
            with mock.patch.object(f["app"], "_management_network_commands", new=constructor):
                result = self.invoke(f)
            fresh, w = self.events(f)[start:], f["caller"]
            self.assertIsNone(result["error"], "real check-only prefix did not complete")
            self.assertEqual(0, result["rc"])
            self.assertEqual([NETWORK_SETTERS], plans)
            self.assertEqual(["selector-return", "diff-entry", "diff-return"], w["timeline"])
            self.assertTrue(len(w["selector"]) == 1 and w["selector"][0]["initial"]
                            and not w["selector"][0]["required"])
            self.assertTrue(len(w["returned_diff"]) == 1
                            and w["returned_diff"][0]["empty"]
                            and w["returned_diff"][0]["rc"] == 0
                            and w["returned_diff"][0]["initial"]
                            and not w["returned_diff"][0]["pam"])
            self.assertEqual([], w["fetch"])
            self.assertEqual([], w["native"])
            self.assertEqual([], w["helper"])
            self.assertFalse(any(e["kind"] in ("mutation", "apply-y", "save", "key-shell",
                                               "ipv4-read", "pam-target") for e in fresh))
            self.require_product_custody(f, result)
            self.require_preserved(f, before)
            self.require_report(result, "S1",
                "Summary: targets=1 configured=0 skipped=0 failed=0 day0-skipped=0 services-skipped=0")

    def test_S2_real_completed_checks_with_no_work_are_not_unattempted(self):
        with self.root() as folder:
            f = self.fixture(folder, case="summary-noop",
                             network=True, services=True, credential="initial")
            self.no_keys_before_real_p1(f)
            before, start = self.protect(f), len(self.events(f))
            result = self.invoke(f, "--apply", "--yes")
            fresh, w = self.events(f)[start:], f["caller"]
            self.assertIsNone(result["error"], "actual qualified no-work path failed")
            self.assertEqual(0, result["rc"])
            self.assertTrue(len(w["selector"]) == 1 and w["selector"][0]["initial"]
                            and not w["selector"][0]["required"])
            self.assertEqual(["selector-return"], w["timeline"])
            self.assertEqual([], w["consent"])
            self.assertEqual([], w["helper"])
            self.assertEqual([], w["fetch"])
            self.assertEqual([], w["native"])
            self.assertFalse(any(e["kind"] in ("mutation", "apply-y", "save", "key-shell",
                                               "ipv4-read", "pam-target") for e in fresh))
            self.require_product_custody(f, result)
            self.require_preserved(f, before)
            self.require_report(result, "S2",
                "Summary: targets=1 configured=0 skipped=1 failed=0 day0-skipped=1 services-skipped=1")

    def test_S3_real_saved_verified_Network_then_IPv4_failure_stops_second_target(self):
        with self.root() as folder:
            f = self.fixture(folder, case="summary-two-target-stop",
                             network=False, services=True, credential="initial")
            f["csv"].write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:17,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,02:00:00:00:00:18,,,\n"
                "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n", encoding="ascii")
            f["p2p"].write_text(
                '"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n'
                '"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n', encoding="ascii")
            first = json.loads(f["state"].read_text(encoding="ascii"))
            first.update(summary_target="IB01", network=False,
                         summary_network_applied=False, summary_network_saved=False)
            second = dict(first, summary_target="IB02", network=True)
            state01, state02 = (folder / "summary-device-01.json",
                                folder / "summary-device-02.json")
            state01.write_text(json.dumps(first), encoding="ascii")
            state02.write_text(json.dumps(second), encoding="ascii")
            state01.chmod(0o600)
            state02.chmod(0o600)
            f["stub"].write_text(_summary_two_target_peer(self.caller), encoding="utf-8")
            f["stub"].chmod(0o600)
            cache = self.no_keys_before_real_p1(f)
            self.assertEqual(2, cache["ib_candidate_count"])
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"],
                             [row["ib"]["hostname"] for row in cache["targets"]])
            self.assertEqual(["swp7", "swp8"],
                             [row["ethernet_port"] for row in cache["targets"]])
            self.assertEqual(["203.0.113.2", "203.0.113.3"],
                             [row["ib"]["login_ip"] for row in cache["targets"]])
            before, start = self.protect(f), len(self.events(f))
            second_before = self.base.bound_file(state02)
            alias = f["tool"] / "01-global.yaml"
            alias_before = (self.base.nine(alias.lstat()), os.readlink(alias))
            app = f["app"]
            original_interface = app.interface_status_line
            original_select = app._authenticate_ib_read
            original_helper = app._run_authorized_ib_command
            original_verify = app._verify_management_network_state
            original_ipv4 = app.verify_ipv4_login
            evaluation, selector_entries, prefix, statuses, verified, ipv4_errors = (
                [], [], [], [], [], [])
            required_rows = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
                "nv set interface eth0-1 link state up",
                "nv set interface eth0-1 type eth",
                "nv set system hostname EXAMPLE-IB01",
                "nv set system config auto-save state enabled",
                "nv set system ztp config-save enabled",
                "nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.ubuntu.com",
                "nv set system ntp server time.ib.example.test",
                "nv set system date-time timezone Asia/Taipei",
            )
            @wraps(original_interface)
            def interface(table, port):
                evaluation.append("IB01" if port == "swp7" else
                                  "IB02" if port == "swp8" else "OTHER")
                return original_interface(table, port)
            @wraps(original_select)
            def select(*args, **kwargs):
                target = inspect.signature(original_select).bind(*args, **kwargs).arguments["target"]
                selector_entries.append("IB01" if target.ib.hostname == "EXAMPLE-IB01"
                                        else "IB02" if target.ib.hostname == "EXAMPLE-IB02"
                                        else "OTHER")
                return original_select(*args, **kwargs)
            @wraps(original_helper)
            def helper(*args, **kwargs):
                command = inspect.signature(original_helper).bind(*args, **kwargs).arguments["ib_command"]
                value = original_helper(*args, **kwargs)
                if command in (["nv", "config", "apply", "-y"],
                               ["nv", "config", "save"], READ):
                    tag = ("apply-return" if command == ["nv", "config", "apply", "-y"]
                           else "save-return" if command == ["nv", "config", "save"]
                           else "readback-return")
                    prefix.append(tag)
                    statuses.append(type(value) is app.SessionResult
                                    and type(value.exit_code) is int
                                    and value.exit_code == 0)
                return value
            @wraps(original_verify)
            def verify(device, current):
                value = original_verify(device, current)
                prefix.append("verify-return")
                verified.append(device.hostname == "EXAMPLE-IB01"
                                and all(row in current.splitlines() for row in required_rows))
                return value
            @wraps(original_ipv4)
            def ipv4(*args, **kwargs):
                prefix.append("ipv4-entry")
                try:
                    return original_ipv4(*args, **kwargs)
                except BaseException as error:
                    ipv4_errors.append(type(error) is app.SetupError)
                    prefix.append("ipv4-error")
                    raise
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(app, "interface_status_line", new=interface))
                stack.enter_context(mock.patch.object(app, "_authenticate_ib_read", new=select))
                stack.enter_context(mock.patch.object(app, "_run_authorized_ib_command", new=helper))
                stack.enter_context(mock.patch.object(app, "_verify_management_network_state", new=verify))
                stack.enter_context(mock.patch.object(app, "verify_ipv4_login", new=ipv4))
                result = self.invoke(f, "--apply", "--yes")
            fresh, w = self.events(f)[start:], f["caller"]
            self.assertIsNone(result["error"], "real Network/IPv4 STOP did not return through main")
            self.assertEqual(1, result["rc"])
            self.assertEqual(["IB01"], evaluation)
            self.assertEqual(["IB01"], selector_entries)
            self.assertEqual(["apply-return", "save-return", "readback-return",
                              "verify-return", "ipv4-entry", "ipv4-error"], prefix)
            self.assertEqual([True, True, True], statuses)
            self.assertEqual([True], verified)
            self.assertEqual([True], ipv4_errors)
            self.assertEqual([*NETWORK_SETTERS, ("nv", "config", "apply", "-y"),
                              ("nv", "config", "save"), tuple(READ)], w["helper"])
            self.assertTrue(len(w["gate"]) == 8 and all(w["gate"]))
            self.assertTrue(len(w["selector"]) == 1 and w["selector"][0]["initial"]
                            and not w["selector"][0]["required"])
            self.assertEqual(list(NETWORK_SETTERS),
                             [tuple(e["command"]) for e in fresh if e["kind"] == "mutation"])
            applied = [i for i, e in enumerate(fresh) if e["kind"] == "summary-network-applied"]
            saved = [i for i, e in enumerate(fresh) if e["kind"] == "summary-network-saved"]
            faults = [i for i, e in enumerate(fresh) if e["kind"] == "summary-ipv4-fault"]
            self.assertTrue(len(applied) == len(saved) == len(faults) == 1
                            and applied[0] < saved[0] < faults[0])
            reads = [i for i, e in enumerate(fresh) if e["kind"] == "caller-show"
                     and saved[0] < i < faults[0]]
            self.assertEqual(1, len(reads))
            entries = [e["target"] for e in fresh if e["kind"] == "summary-target-entry"]
            self.assertTrue(bool(entries) and all(label == "IB01" for label in entries))
            self.assertFalse(any(e["kind"] in ("key-shell", "pam-target", "pam-start",
                                               "inner-rejected", "rejected-business")
                                 for e in fresh))
            self.assertTrue(all(e.get("initial") is True and e.get("target") is False
                                and e.get("oob") is False
                                for e in fresh if e["kind"] == "inner-answer"))
            self.assertNotIn("\n[EXAMPLE-IB02] via ", result["stdout"])
            self.assertIn("STOP: IPv4 verification did not complete; no subsequent IB device will be configured.",
                          result["stdout"])
            after = json.loads(state01.read_text(encoding="ascii"))
            self.assertTrue(after["network"] is True and after["initial"] is True
                            and after["services"] is True and after["pending"] == []
                            and after["summary_network_applied"] is True
                            and after["summary_network_saved"] is True)
            self.assertTrue(self.base.bound_file(state02) == second_before,
                            "unattempted PUBLIC second device state changed")
            self.assertTrue((self.base.nine(alias.lstat()), os.readlink(alias)) == alias_before,
                            "protected PUBLIC global alias changed")
            self.require_product_custody(f, result)
            self.require_preserved(f, before)
            self.require_report(result, "S3",
                "Summary: targets=2 configured=0 skipped=0 failed=1 day0-skipped=0 services-skipped=1")
