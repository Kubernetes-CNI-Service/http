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
  test exercises it, so no I14 test is ported here (the tracker mapping is WP-11, guide :1124).
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


if __name__ == "__main__":
    unittest.main()
