"""Bare expiry is not a current-password challenge; independent tests-first.
No old protocol/peer/driver edits or inheritance. Deadline exhaustion is MODEL;
all private phase, input, actual PTY/read/signal/reap and real policy are genuine.
"""
from __future__ import annotations
from contextlib import ExitStack, contextmanager
from functools import wraps
import errno
import json
import os
from pathlib import Path
import re
import signal
import stat
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_ib_phase_protocol as basis

APP = basis.APP
BARE = "\nYour password has expired.\n"
DELAYED = "bare-expiry-delayed"
COALESCED = "bare-expiry-coalesced-255"
BRANCH = r'''
    if case in ("bare-expiry-delayed", "bare-expiry-coalesced-255"):
        if op != "auth-probe-readonly":
            raise ValueError("bare fixture requires sole readonly operation")
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        if case == "bare-expiry-delayed":
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            event("bare-expiry", mode="delayed")
            emit("\nYour password has expired.\n")
            # Existing fixture wait only. Parent arms the already-reviewed
            # deadline MODEL after the real bare-prefix read, not before it.
            select.select([], [], [], 10)
            event("bare-peer-natural-timeout")
            return 255
        event("bare-expiry", mode="coalesced")
        emit("\nYour password has expired.\n" + end(255))
        event("bare-coalesced-exit", declared=255)
        return 255
'''


class _BareFixtureHold(RuntimeError):
    pass


def hold():
    error = _BareFixtureHold("FIXTURE HOLD: independent bare-expiry prefix/custody boundary unavailable")
    try:
        raise error from None
    except _BareFixtureHold:
        error.__cause__ = None
        error.__context__ = None
        raise


def peer_program():
    anchor = '    if case=="readonly-expiry":\n'
    source = basis.PEER_PROGRAM
    if source.count(anchor) != 1:
        hold()
    return source.replace(anchor, BRANCH + anchor, 1)


@contextmanager
def observe(f, mode):
    """External, active-owned-boundary observations; never fake a core result."""
    real_fork, real_read, real_write = APP.pty.fork, os.read, os.write
    real_close, real_fstat, real_wait = os.close, os.fstat, os.waitpid
    real_killpg, real_kill = os.killpg, os.kill
    real_interactive = APP.interactive_run
    real_value, real_native = APP._ib_project_value, APP.verify_password_hash
    real_password = APP.ProjectPasswordPolicy.password
    active, children, progress = {}, set(), {}
    seen = dict(errors=[], depth=0, prefix="", nonce=None, current_inputs=0,
                bare_read=False, prefix_after_current=False, coalesced_read=False,
                forbidden_pam_text=False, after_bare_input=False,
                deadline_armed=False, fetch=0, password=0, native=0, prompt=0,
                signals=[], product_reaps=[], fixture_reaps=[])
    def error(stage):
        if stage not in seen["errors"]:
            seen["errors"].append(stage)
    def owned(fd):
        identity = active.get(fd)
        if identity is None:
            return False
        try:
            info = real_fstat(fd)
        except OSError:
            error("owned-fstat")
            return False
        if basis.nine(info)[:6] != identity:
            error("owned-identity")
            return False
        return True
    def fork():
        result = real_fork()
        if result[0] > 0:
            try:
                active[result[1]] = basis.nine(real_fstat(result[1]))[:6]
                children.add(result[0])
            except OSError:
                error("fork-identity")
        return result
    def arm_deadline():
        if seen["deadline_armed"]:
            return
        descriptor = None
        try:
            descriptor = os.open(f["root"] / "ready",
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
            payload = b"PUBLIC-BARE-READ-DEADLINE-MODEL\n"
            offset = 0
            while offset < len(payload):
                amount = real_write(descriptor, payload[offset:])
                if type(amount) is not int or not 0 < amount <= len(payload) - offset:
                    error("deadline-control-write")
                    return
                offset += amount
            seen["deadline_armed"] = True
        except OSError:
            error("deadline-control")
        finally:
            if descriptor is not None:
                real_close(descriptor)
    def read(fd, amount):
        ours = owned(fd)
        raw = real_read(fd, amount)
        if not ours or not raw:
            return raw
        text = raw.decode("utf-8", "replace").replace("\r", "")
        seen["prefix"] += text
        if len(seen["prefix"]) > 4 * 1024 * 1024:
            error("prefix-bound")
            seen["prefix"] = seen["prefix"][-4096:]
        prefix = seen["prefix"]
        if re.search(r"(?im)^\s*(?:\(current\) UNIX password:|New password:|Retype new password:)", prefix):
            seen["forbidden_pam_text"] = True
        start = re.search(r"(?m)^__HTTP_IB_AUTH_([0-9a-f]{32})_auth-probe-readonly__=BEGIN\n", prefix)
        if start is not None:
            seen["nonce"] = start.group(1)
        if BARE in prefix:
            seen["bare_read"] = True
            seen["prefix_after_current"] |= seen["current_inputs"] == 1
        if seen["nonce"] is not None:
            end = "__HTTP_IB_AUTH_" + seen["nonce"] + "_auth-probe-readonly__=EXIT:255\n"
            if BARE in text and end in text:
                seen["coalesced_read"] = True
        if (mode == DELAYED and seen["bare_read"] and seen["prefix_after_current"]
                and not seen["deadline_armed"]):
            arm_deadline()
        return raw
    def write(fd, data):
        ours = owned(fd)
        amount = real_write(fd, data)
        if ours and type(amount) is int and amount > 0:
            part = bytes(data)[:amount]
            if seen["bare_read"] and part not in (b"\x03", b"\x03\n"):
                seen["after_bare_input"] = True
            pending = progress.get(fd, b"") + part
            wanted = f["initial"].encode("utf-8") + b"\n"
            if pending == wanted:
                seen["current_inputs"] += 1
                progress[fd] = b""
            elif wanted.startswith(pending):
                progress[fd] = pending
            else:
                progress[fd] = b""
        return amount
    def close(fd):
        ours = owned(fd)
        if ours:
            active.pop(fd, None)
            progress.pop(fd, None)
        return real_close(fd)
    def wait(pid, flags):
        ours = pid in children
        result = real_wait(pid, flags)
        if ours and result[0] == pid:
            destination = "product_reaps" if seen["depth"] else "fixture_reaps"
            seen[destination].append(os.waitstatus_to_exitcode(result[1]))
            children.discard(pid)
        return result
    def signal_call(original):
        def call(pid, sig):
            product = pid in children and seen["depth"] > 0
            result = original(pid, sig)
            if product and sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
                seen["signals"].append(sig)
            return result
        return call
    @wraps(real_interactive)
    def interactive(*args, **kwargs):
        seen["depth"] += 1
        try:
            return real_interactive(*args, **kwargs)
        finally:
            seen["depth"] -= 1
    @wraps(real_value)
    def value(*args, **kwargs):
        if kwargs.get("fetch") is True:
            seen["fetch"] += 1
        return real_value(*args, **kwargs)
    @wraps(real_password)
    def password(policy):
        seen["password"] += 1
        return real_password(policy)
    @wraps(real_native)
    def native(*args, **kwargs):
        seen["native"] += 1
        return real_native(*args, **kwargs)
    def forbidden_prompt(*args, **kwargs):
        seen["prompt"] += 1
        raise AssertionError("PUBLIC readonly bare expiry cannot prompt for a target")
    with ExitStack() as stack:
        for name, replacement in (("read", read), ("write", write), ("close", close),
                                  ("waitpid", wait), ("killpg", signal_call(real_killpg)),
                                  ("kill", signal_call(real_kill))):
            stack.enter_context(mock.patch.object(APP.os, name, new=replacement))
        stack.enter_context(mock.patch.object(APP.pty, "fork", new=fork))
        stack.enter_context(mock.patch.object(APP, "interactive_run", new=interactive))
        stack.enter_context(mock.patch.object(APP, "_ib_project_value", new=value))
        stack.enter_context(mock.patch.object(APP, "verify_password_hash", new=native))
        stack.enter_context(mock.patch.object(APP.ProjectPasswordPolicy, "password", new=password))
        stack.enter_context(mock.patch.object(APP.getpass, "getpass", new=forbidden_prompt))
        yield seen
    seen["active_remaining"] = bool(active)


class BareExpiryReadonlyTests(unittest.TestCase):
    fixture = basis.IndependentIBPhaseProtocolDraftTests.fixture
    peer_events = basis.IndependentIBPhaseProtocolDraftTests.peer_events
    assert_custody = basis.IndependentIBPhaseProtocolDraftTests.assert_custody

    @classmethod
    def setUpClass(cls):
        if APP is not basis.APP:
            hold()
        basis.IndependentIBPhaseProtocolDraftTests.setUpClass.__func__(cls)

    def prepare(self, folder, mode):
        f = self.fixture(folder, mode)
        f["peer"].write_text(peer_program(), encoding="utf-8")
        f["peer"].chmod(0o600)
        f["global_before"] = basis.snapshot(f["global_path"])
        return f

    def run_case(self, f, mode):
        with observe(f, mode) as seen:
            policy = APP.ProjectPasswordPolicy(
                f["global_path"], "admin", target_password=self.kat["PASSWORD"], interactive=False)
            out = basis.IndependentIBPhaseProtocolDraftTests.drive(
                self, f, selector=True, policy=policy, timeout=mode == DELAYED)
        if (seen["errors"] or not seen["bare_read"] or not seen["prefix_after_current"]
                or seen["nonce"] is None
                or (mode == DELAYED and not seen["deadline_armed"])
                or (mode == COALESCED and not seen["coalesced_read"])):
            hold()
        self.assertTrue(not seen["forbidden_pam_text"],
                        "independent peer accidentally supplied a real PAM challenge")
        requests = [event for event in out["peer"] if event["kind"] == "request"]
        self.assertTrue(len(requests) == 1 and seen["current_inputs"] == 1
                        and requests[0]["operation"] == "auth-probe-readonly"
                        and requests[0]["nonce"] == seen["nonce"],
                        "bare expiry cannot create another credential operation")
        self.assertTrue(seen["fetch"] == seen["password"] == seen["native"] == seen["prompt"] == 0,
                        "bare expiry cannot acquire or verify a target")
        self.assertTrue(out["result"] is None,
                        "bare expiry cannot return password-change-required authority")
        self.assertTrue(type(out["error"]) is APP.SetupError
                        and not isinstance(out["error"], APP.IBAuthenticationError),
                        "bare expiry must be safe non-auth HOLD; details suppressed")
        self.assertTrue(not seen["after_bare_input"]
                        and not any(event["kind"] in ("pam-current", "pam-new", "pam-confirm")
                                    for event in out["peer"]),
                        "no current/new/retype or PAM input is authorized by a banner")
        self.assert_custody(out)
        self.assertTrue(not seen["fixture_reaps"] and not seen["active_remaining"]
                        and seen["product_reaps"] == out["reaps"],
                        "fixture custody cannot replace the actual product reap")
        self.assertTrue(basis.snapshot(f["global_path"]) == f["global_before"],
                        "bare expiry changed the real project authority input")
        return out, seen

    def test_bare_expiry_delayed_exit_uses_existing_deadline_without_pam_authority(self):
        with tempfile.TemporaryDirectory(prefix="ib-bare-expiry-deadline-") as folder:
            f = self.prepare(folder, DELAYED)
            out, seen = self.run_case(f, DELAYED)
            self.assertTrue(not any(event["kind"] == "bare-peer-natural-timeout"
                                    for event in out["peer"]),
                            "peer natural timeout is not product cancellation")
            if (len(out["reaps"]) != 1
                    or not any(out["reaps"][0] == -sig for sig in seen["signals"])):
                hold()
            self.assertTrue(len(out["reaps"]) == 1
                            and any(out["reaps"][0] == -sig for sig in seen["signals"]),
                            "delayed live peer needs actual product signal and reap")

    def test_bare_expiry_coalesced_exit255_is_nonauth_not_a_current_challenge(self):
        with tempfile.TemporaryDirectory(prefix="ib-bare-expiry-exit-") as folder:
            f = self.prepare(folder, COALESCED)
            out, seen = self.run_case(f, COALESCED)
            if out["reaps"] != [255] or seen["signals"]:
                # A legitimate safe cancellation is not a product failure;
                # this particular natural-EXIT255 fixture was not qualified.
                hold()
            self.assertTrue(out["reaps"] == [255] and not seen["signals"]
                            and any(event["kind"] == "bare-coalesced-exit"
                                    and event["declared"] == 255 for event in out["peer"]),
                            "coalesced real exit255 is natural reap, not cancel proof")


if __name__ == "__main__":
    unittest.main()
