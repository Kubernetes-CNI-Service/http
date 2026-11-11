"""Direct: OOB credentials are key-first then one shared hidden password; IB target password policy.

What: `prompt_ethernet_passwords` tries the OOB public key first and asks for a password only for
the switches whose key login was rejected, offering one shared password ([Y/n], default yes) and
refusing to prompt without a terminal; the IB target-password policy rejects unusable or
unsupported project hash settings before any backend call and refuses a typed target that does not
match the project or whose two hidden confirmations differ, without touching the project global.

Expectation sources (not derived from the implementation):
- R-011 I13 (需求文档.md:1223; the guide :843 cites its earlier place 待确认问题.md :156-157; TEST
  tracker :1742): OOB public key first, a password only for rejected switches, one shared password
  confirmed with [Y/n].  I13 is v15-implemented behaviour, adopted as this release's expectation
  source under the owner's 11-06 ruling to take v15 as the base (开发计划.md:314; guide O13 :266);
  this is not an owner confirmation of I13.
- R-011 I14 (需求文档.md:1224; TEST tracker :1818), confirmed by the owner on 11-03: the IB
  initial-password prompt waits at most 5 s and Enter or timeout means admin.  No v15 delivered
  test exercises it, so none was ported; WP-11 (tracker mapping, guide :1124) added the direct
  acceptance as three test_r011_i14_* tests below, on a real pseudo-terminal.
  Guide table 6-1 row 5 (:748) and P3: a public-key OOB login leaves the Ethernet password empty.
- v15 CURRENT-CONTRACT.md:48-50: OOB tries the key first and asks only on failure, shared password
  by default; the IB target password is typed twice, hidden, checked against the same project's
  global hash, and is not the OOB password.
- v15 delivered tests `initial-setup-test-cases/test_desktop_initial_setup.py::OobTests` (:253-279)
  and the parts of `::PasswordTests` (:41-92) that DEV does not already pin (file sha256 bound by
  HANDOFF-SHA256SUMS:27).  Guide table 7-1 row 1 (:815): DEV's tests are stricter and are not
  moved; only the gaps come here (census in the WP-7 report).

Fixture rewrites (public audit, guide :835): synthetic switch names, documentation IPv4 ranges,
passwords assembled at run time, and a synthetic SHA-512-shaped project setting assembled at run
time.  The hash backend is replaced by a model that only compares the typed value with the run-time
target; the real backend and its KAT stay pinned by test_initial_setup_target_password_policy.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
# v3.1.3 WP-11 (R-011 tracker mapping) additions below.
import os
import termios
from contextlib import redirect_stderr

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_oob_credentials", INITIAL)


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


# A syntactically valid SHA-512 crypt setting; synthetic, never a real project hash.
SYNTHETIC_SETTING = "$" + "6$PUBLICsalt$" + "A" * 86


def project_global(setting: str = SYNTHETIC_SETTING) -> str:
    return ('schema_version: 2\ncommon:\n  switch:\n    system:\n'
            '      config:\n        auto-save:\n          state: enabled\n'
            'switches:\n- ib:\n    system:\n      aaa:\n        user:\n'
            '          admin:\n            password: "' + setting + '"\n')


def target(jump: str = "example-oob-leaf01", address: str = "198.51.100.10", port: str = "swp1"):
    ib = app.Device("example-ib001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device(jump, "eth_jump", address, "", "", "", "", "")
    return app.Target(ib, eth, port, "eth0")


class OobCredentialTests(unittest.TestCase):
    # -- I13: OOB key first, then one shared hidden password ------------------------------------

    # v15 OobTests.test_all_key_success_no_password_prompts (test_desktop_initial_setup.py:254)
    def test_all_key_success_no_password_prompts(self):
        with patch.object(app, "probe_ethernet_key", return_value="key"), \
             patch.object(app.getpass, "getpass") as prompt, patch("builtins.input") as choose, \
             redirect_stdout(io.StringIO()):
            result = app.prompt_ethernet_passwords([target()], None, set(), eth_user="cumulus", timeout=5)
        # Table 6-1 row 5 P3 (guide :748): a key login leaves the Ethernet password empty.
        self.assertEqual(result, {"example-oob-leaf01": ""})
        prompt.assert_not_called()
        choose.assert_not_called()

    # v15 OobTests.test_key_reject_shared_password_once (test_desktop_initial_setup.py:260)
    def test_key_reject_shared_password_once(self):
        shared = secret("oob")
        second = target("example-oob-leaf02", "198.51.100.11", "swp2")
        with patch.object(app, "probe_ethernet_key", return_value="password"), \
             patch.object(app.sys.stdin, "isatty", return_value=True), \
             patch.object(app.getpass, "getpass", return_value=shared) as prompt, \
             patch("builtins.input", return_value=""), redirect_stdout(io.StringIO()):
            result = app.prompt_ethernet_passwords([target(), second], None, set(),
                                                   eth_user="cumulus", timeout=5)
        self.assertEqual(set(result.values()), {shared})
        self.assertEqual(prompt.call_count, 1)

    # v15 OobTests.test_password_required_without_tty_fails_before_prompting
    # (test_desktop_initial_setup.py:272)
    def test_password_required_without_tty_fails_before_prompting(self):
        with patch.object(app, "probe_ethernet_key", return_value="password"), \
             patch.object(app.sys.stdin, "isatty", return_value=False), \
             patch.object(app.getpass, "getpass") as prompt, patch("builtins.input") as choose, \
             redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(app.SetupError, "run interactively"):
                app.prompt_ethernet_passwords([target()], None, set(), eth_user="cumulus", timeout=5)
        prompt.assert_not_called()
        choose.assert_not_called()

    # -- IB target password policy: the PasswordTests gaps (guide :815) -------------------------

    # v15 PasswordTests.test_invalid_or_expensive_hash_rejected (test_desktop_initial_setup.py:47).
    # DEV pins only a non-crypt string through the policy
    # (test_initial_setup_target_password_policy ...test_ambiguous_or_unsupported_global_is_rejected_
    # before_hash_or_prompt); the locked, empty and unsupported-cost settings are pinned here.
    def test_invalid_or_expensive_hash_rejected(self):
        backend = patch.object(app.subprocess, "run",
                               side_effect=AssertionError("an invalid setting must not reach the backend"))
        with backend as run:
            for value in ("*", "", "plaintext", "$y$huge$salt$hash", "$6$rounds=999999999$salt$hash"):
                with self.subTest(value=value):
                    with self.assertRaises(app.SetupError):
                        app.verify_password_hash(secret("target"), value)
        run.assert_not_called()

    # v15 PasswordTests.test_policy_two_inputs_and_mismatch_do_not_write
    # (test_desktop_initial_setup.py:64).  The two-input success half is pinned by DEV
    # (...IndependentTargetCredentialPolicyDraftTests.test_interactive_target_matches_project_and_
    # changed_global_invalidates_cached_secret, real KAT); both halves run here against a modeled
    # backend that matches only the run-time target.
    def test_policy_two_inputs_and_mismatch_do_not_write(self):
        expected = secret("target")

        def modeled(password, setting):
            self.assertEqual(setting, SYNTHETIC_SETTING)
            return password == expected

        with tempfile.TemporaryDirectory() as temp, patch.object(app, "verify_password_hash", side_effect=modeled), \
                redirect_stdout(io.StringIO()):
            path = Path(temp) / "01-global.yaml"
            path.write_text(project_global(), encoding="utf-8")
            before = path.read_bytes()
            policy = app.ProjectPasswordPolicy(path, "admin")
            with patch.object(app.getpass, "getpass", side_effect=[expected, expected]):
                self.assertEqual(policy.password(), expected)
            self.assertEqual(path.read_bytes(), before)
            policy = app.ProjectPasswordPolicy(path, "admin")
            wrong = secret("wrong")
            with patch.object(app.getpass, "getpass", side_effect=[wrong, wrong]):
                with self.assertRaises(app.SetupError):
                    policy.password()
            self.assertEqual(path.read_bytes(), before)

    # v15 PasswordTests.test_policy_conflicting_confirmations (test_desktop_initial_setup.py:77)
    def test_policy_conflicting_confirmations(self):
        expected = secret("target")
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(app, "verify_password_hash",
                             side_effect=lambda password, setting: password == expected), \
                redirect_stdout(io.StringIO()):
            path = Path(temp) / "01-global.yaml"
            path.write_text(project_global(), encoding="utf-8")
            policy = app.ProjectPasswordPolicy(path, "admin")
            with patch.object(app.getpass, "getpass", side_effect=[expected, secret("other")]):
                with self.assertRaises(app.SetupError):
                    policy.password()

    # -- v3.1.3 WP-11: R-011 TEST-tracker acceptance gaps (guide :1124, :1126) -----------------------
    # Expectations come from the TEST tracker (参考/TEST问题跟踪/user-test-issue-tracker.md) at the
    # cited lines; the v15 lines (参考/initial-setup-v15/initial-setup-20261019-v15_oob-spine.py) only
    # show that the behaviour already exists there (guide :1124 "实现不改（v15 已有）").

    # I13 (tracker :1775-1776): only an explicit authentication rejection leads to a password; an
    # unreachable or timed-out switch, a host-key conflict or a wrong identity never does.
    # v15 probe_ethernet_key :459-480 (password only at :477-479; refusals :470, :475, :480).
    def test_r011_i13_key_probe_falls_back_to_a_password_only_on_an_explicit_rejection(self):
        switch = target().ethernet

        def completed(code, stdout="", stderr=""):
            return app.subprocess.CompletedProcess(["ssh"], code, stdout, stderr)

        rejected = "cumulus@198.51.100.10: Permission denied (publickey,password).\n"
        for expected, reply in (("key", completed(0, "example-oob-leaf01\n")),
                                ("password", completed(255, stderr=rejected))):
            with self.subTest(expected=expected), \
                    patch.object(app.subprocess, "run", return_value=reply) as run:
                self.assertEqual(app.probe_ethernet_key(switch, "cumulus", 5), expected)
            argv = run.call_args.args[0]
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("PreferredAuthentications=publickey", argv)
        refusals = {
            "timed-out": completed(255, stderr="ssh: connect to host 198.51.100.10 port 22: Connection timed out\n"),
            "no-route": completed(255, stderr="ssh: connect to host 198.51.100.10 port 22: No route to host\n"),
            "host-key": completed(255, stderr="Host key verification failed.\n"),
            "changed-key-and-rejection": completed(
                255, stderr="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n" + rejected),
            "other-identity": completed(0, "example-oob-leaf99\n"),
            "local-timeout": app.subprocess.TimeoutExpired(["ssh"], 5),
        }
        for label, reply in refusals.items():
            with self.subTest(refusal=label), patch.object(app.subprocess, "run", side_effect=[reply]):
                with self.assertRaises(app.SetupError):
                    app.probe_ethernet_key(switch, "cumulus", 5)

    # I13 (tracker :1775-1781, :1805-1807): a key login and an unreachable switch are never asked;
    # the switches whose key was rejected share one hidden input after one [Y/n] question, and on
    # "n" each is asked by hostname and login IP and keeps its own value; the value is not printed.
    # v15 prompt_ethernet_passwords :3181-3218 (unreachable :3194-3197, question :3207, per-switch
    # prompt :3213-3214).
    def test_r011_i13_only_rejected_switches_are_asked_and_declining_asks_each_by_name_and_address(self):
        switches = [target("example-oob-leaf01", "198.51.100.11", "swp1"),
                     target("example-oob-leaf02", "198.51.100.12", "swp2"),
                     target("example-oob-leaf03", "198.51.100.13", "swp3"),
                     target("example-oob-leaf04", "198.51.100.14", "swp4")]

        def probe(device, user, timeout):
            if device.hostname == "example-oob-leaf01":
                return "key"
            if device.hostname == "example-oob-leaf04":
                raise app.SetupError("OOB key probe failed (network/host-key/identity): example-oob-leaf04")
            return "password"

        shared = secret("shared")
        with patch.object(app, "probe_ethernet_key", side_effect=probe), \
                patch.object(app.sys.stdin, "isatty", return_value=True), \
                patch.object(app.getpass, "getpass", return_value=shared) as hidden, \
                patch("builtins.input", return_value="") as choose, redirect_stdout(io.StringIO()) as out:
            result = app.prompt_ethernet_passwords(switches, None, set(), eth_user="cumulus", timeout=5)
        self.assertEqual(result, {"example-oob-leaf01": "", "example-oob-leaf02": shared,
                                  "example-oob-leaf03": shared, "example-oob-leaf04": ""})
        self.assertEqual(choose.call_count, 1)
        self.assertEqual(hidden.call_count, 1)
        self.assertNotIn(shared, out.getvalue())

        typed = {"example-oob-leaf02": secret("leaf02"), "example-oob-leaf03": secret("leaf03")}
        asked = []

        def per_switch(text):
            asked.append(text)
            return next((value for name, value in typed.items() if name in text), secret("unexpected"))

        with patch.object(app, "probe_ethernet_key", side_effect=probe), \
                patch.object(app.sys.stdin, "isatty", return_value=True), \
                patch.object(app.getpass, "getpass", side_effect=per_switch), \
                patch("builtins.input", return_value="n") as choose, redirect_stdout(io.StringIO()) as out:
            result = app.prompt_ethernet_passwords(switches, None, set(), eth_user="cumulus", timeout=5)
        self.assertEqual(result, {"example-oob-leaf01": "", **typed, "example-oob-leaf04": ""})
        self.assertEqual(choose.call_count, 1)
        self.assertEqual(len(asked), 2)
        self.assertIn("example-oob-leaf02", asked[0])
        self.assertIn("198.51.100.12", asked[0])
        self.assertIn("example-oob-leaf03", asked[1])
        self.assertIn("198.51.100.13", asked[1])
        self.assertFalse(any(value in out.getvalue() for value in typed.values()))

    # I13 (tracker :1808): an invalid [Y/n] answer, an empty password, end of input and Ctrl-C are
    # refused, never turned into a default or empty password.  v15 :3209 (invalid answer), :3215-3216
    # (empty value); v15 converts neither EOFError nor KeyboardInterrupt here (:3207-3216), so either
    # that exception or a SetupError is accepted.
    def test_r011_i13_invalid_answer_empty_password_end_of_input_and_cancel_never_default(self):
        switches = [target("example-oob-leaf02", "198.51.100.12", "swp2"),
                    target("example-oob-leaf03", "198.51.100.13", "swp3")]
        cases = (
            ("invalid-answer", ["maybe"], [], app.SetupError, 0),
            ("shared-empty", [""], [""], app.SetupError, 1),
            ("per-switch-empty", ["n"], [secret("leaf02"), ""], app.SetupError, 2),
            ("end-of-input", [EOFError()], [], (EOFError, app.SetupError), 0),
            ("cancel", [""], [KeyboardInterrupt()], (KeyboardInterrupt, app.SetupError), 1),
        )
        for label, answers, values, refusal, hidden_calls in cases:
            with self.subTest(case=label), \
                    patch.object(app, "probe_ethernet_key", return_value="password"), \
                    patch.object(app.sys.stdin, "isatty", return_value=True), \
                    patch.object(app.getpass, "getpass", side_effect=values) as hidden, \
                    patch("builtins.input", side_effect=answers), redirect_stdout(io.StringIO()):
                with self.assertRaises(refusal):
                    app.prompt_ethernet_passwords(switches, None, set(), eth_user="cumulus", timeout=5)
                self.assertEqual(hidden.call_count, hidden_calls)

    # I13 (tracker :1775 "对需密码目标去重"): several IB targets behind one OOB (host names compared
    # case-insensitively) give one key probe and, on "n", one hidden prompt for that OOB.
    # v15 prompt_ethernet_passwords :3186 (one entry per OOB), :3189-3218.
    def test_r011_i13_targets_behind_one_oob_give_one_probe_and_one_prompt(self):
        def behind(ib_name, ib_address, jump, address, port):
            ib = app.Device(ib_name, "ib", ib_address, ib_address + "/24", "192.0.2.1",
                            "02:00:00:00:00:10", "", "")
            return app.Target(ib, app.Device(jump, "eth_jump", address, "", "", "", "", ""), port, "eth0")

        targets = [behind("example-ib001", "192.0.2.11", "example-oob-leaf02", "198.51.100.12", "swp1"),
                   behind("example-ib002", "192.0.2.12", "EXAMPLE-OOB-LEAF02", "198.51.100.12", "swp2"),
                   behind("example-ib003", "192.0.2.13", "example-oob-leaf03", "198.51.100.13", "swp1")]
        typed = {"leaf02": secret("leaf02"), "leaf03": secret("leaf03")}
        asked = []

        def per_switch(text):
            asked.append(text)
            return next((value for name, value in typed.items() if name in text.lower()), secret("unexpected"))

        with patch.object(app, "probe_ethernet_key", return_value="password") as probe, \
                patch.object(app.sys.stdin, "isatty", return_value=True), \
                patch.object(app.getpass, "getpass", side_effect=per_switch), \
                patch("builtins.input", return_value="n") as choose, redirect_stdout(io.StringIO()):
            result = app.prompt_ethernet_passwords(targets, None, set(), eth_user="cumulus", timeout=5)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(choose.call_count, 1)
        self.assertEqual(len(asked), 2)
        self.assertEqual(result, {"example-oob-leaf02": typed["leaf02"], "example-oob-leaf03": typed["leaf03"]})

    # I14 on a real pseudo-terminal: what the operator types reaches the terminal only from inside
    # the prompt's wait (after the echo was turned off), as a person typing at the prompt would.
    INITIAL_ENV = "WP11_UNSET_INITIAL_IB_PASSWORD"

    def initial_prompt_on_pty(self, typing=b"", *, interrupt=False, environment=None):
        master, slave = os.openpty()
        original = termios.tcgetattr(slave)
        if typing == "EOF":
            eof = original[6][termios.VEOF]
            typing = eof if isinstance(eof, bytes) else bytes([eof])
        waits, outcome = [], {}
        real_select = app.select.select

        def operator(read, write, error, timeout):
            waits.append(timeout)
            if interrupt:
                raise KeyboardInterrupt
            if typing:
                os.write(master, typing)
            return real_select(read, write, error, 0.2)

        terminal = io.open(slave, "r", encoding="utf-8", closefd=False)
        try:
            with patch.dict(os.environ, environment or {}, clear=True), \
                    patch.object(app.sys, "stdin", terminal), \
                    patch.object(app.select, "select", side_effect=operator), \
                    redirect_stderr(io.StringIO()) as prompt:
                try:
                    outcome["value"] = app.resolve_initial_ib_password(self.INITIAL_ENV, interactive=True)
                except app.SetupError as exc:
                    outcome["error"] = str(exc)
            restored = termios.tcgetattr(slave) == original
            os.set_blocking(master, False)
            echoed = b""
            try:
                while True:
                    chunk = os.read(master, 4096)
                    if not chunk:
                        break
                    echoed += chunk
            except (BlockingIOError, OSError):
                pass
            # Whatever is still queued on the terminal would reach the next prompt's read.
            os.write(master, b"\n")
            leftover = os.read(slave, 4096)
        finally:
            terminal.close()
            os.close(master)
            os.close(slave)
        return outcome, waits, prompt.getvalue(), restored, echoed, leftover

    # I14 (tracker :1835-1839, :1849, :1862): an explicit credential is used without a prompt; one
    # hidden prompt names admin and the 5 s; a typed non-empty line is used exactly as typed (spaces
    # kept, only the line end removed) and is not echoed; Enter means admin; the terminal is
    # restored.  v15 resolve_initial_ib_password :731-746 (prompt and 5 s at :746),
    # _hidden_password_timeout :402-429 (echo off :408-409, value :422-423, restore :427).
    def test_r011_i14_initial_ib_prompt_keeps_a_typed_line_and_enter_means_admin(self):
        explicit = secret("initial-explicit")
        outcome, waits, prompt, restored, _, _ = self.initial_prompt_on_pty(
            environment={self.INITIAL_ENV: explicit})
        self.assertEqual(outcome, {"value": explicit})
        self.assertEqual((waits, prompt), ([], ""))
        self.assertTrue(restored)

        typed = "  " + secret("initial-typed") + " "
        outcome, waits, prompt, restored, echoed, leftover = self.initial_prompt_on_pty(
            (typed + "\n").encode())
        self.assertEqual(outcome, {"value": typed})
        self.assertEqual(waits, [5])
        self.assertIn("admin", prompt)
        self.assertIn("5 seconds", prompt)
        self.assertNotIn(secret("initial-typed").encode(), echoed)
        self.assertTrue(restored)
        self.assertEqual(leftover, b"\n")

        outcome, waits, _, restored, _, leftover = self.initial_prompt_on_pty(b"\n")
        self.assertEqual(outcome, {"value": "admin"})
        self.assertEqual(waits, [5])
        self.assertTrue(restored)
        self.assertEqual(leftover, b"\n")

    # I14 (tracker :1840-1841, :1853-1854, :1864-1865): no complete line within the one 5 s deadline
    # means admin; typing without Enter neither extends the deadline (one wait of 5) nor is used,
    # and the partial input is discarded so it cannot reach the next prompt.  v15 :415-418 (one
    # select with the full deadline, then flush and admin).
    def test_r011_i14_initial_ib_prompt_times_out_once_to_admin_and_discards_partial_input(self):
        partial = secret("initial-partial")
        outcome, waits, _, restored, echoed, leftover = self.initial_prompt_on_pty(partial.encode())
        self.assertEqual(outcome, {"value": "admin"})
        self.assertEqual(waits, [5])
        self.assertEqual(leftover, b"\n")
        self.assertNotIn(partial.encode(), echoed)
        self.assertTrue(restored)

    # I14 (tracker :1851-1852, :1866): end of input and Ctrl-C stop with an error instead of the
    # default, and the terminal is restored; without a terminal there is no prompt at all.
    # v15 :405-406 (no terminal), :420-421 (end of input), :424-425 (Ctrl-C), :426-429 (restore).
    def test_r011_i14_initial_ib_prompt_end_of_input_cancel_and_no_terminal_never_mean_admin(self):
        outcome, waits, _, restored, _, leftover = self.initial_prompt_on_pty("EOF")
        self.assertEqual(list(outcome), ["error"])
        self.assertIn("input ended", outcome["error"])
        self.assertEqual(waits, [5])
        self.assertTrue(restored)
        self.assertEqual(leftover, b"\n")

        outcome, waits, _, restored, _, _ = self.initial_prompt_on_pty(interrupt=True)
        self.assertEqual(list(outcome), ["error"])
        self.assertIn("cancelled", outcome["error"])
        self.assertTrue(restored)

        with patch.dict(os.environ, {}, clear=True), patch.object(app.sys, "stdin", io.StringIO()), \
                patch.object(app.select, "select", side_effect=AssertionError("no prompt without a terminal")), \
                redirect_stderr(io.StringIO()) as prompt:
            with self.assertRaisesRegex(app.SetupError, "needs a terminal"):
                app.resolve_initial_ib_password(self.INITIAL_ENV, interactive=True)
        self.assertEqual(prompt.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
