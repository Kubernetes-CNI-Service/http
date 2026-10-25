"""Independent monotonic AUTO policy fact; no permission or error-schema change.

O-only test draft. Native crypto and policy/helper operations genuinely delegate.
Missing private field is NOT_READY, never a missing-ABI behavior RED.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from functools import wraps
import hmac
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases import test_initial_setup_target_credentials_workflow as basis

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
FACT = "_auto_authority_failed"
PROJECT_ARGS = ("IB phase project authority failed; device state is UNKNOWN",)
PUBLIC_WRONG = "Incorrect123!"
PUBLIC_CHANGE = "# PUBLIC changed after real policy birth\n"


def captured(call):
    output, diagnostic = io.StringIO(), io.StringIO()
    value = error = None
    with redirect_stdout(output), redirect_stderr(diagnostic):
        try:
            value = call()
        except BaseException as caught:
            error = caught
    return value, error, output.getvalue(), diagnostic.getvalue()


def fixture_hold():
    # This function is called outside any caught private exception handler.
    error = RuntimeError("FIXTURE HOLD: genuine policy/native prerequisite unavailable")
    try:
        raise error from None
    except RuntimeError:
        error.__cause__ = None
        error.__context__ = None
        raise


@contextmanager
def native_observer(app, kat):
    """Counts and fixed boolean roles only; underlying native result is real."""
    real = app.verify_password_hash
    seen = {"calls": [], "prompts": 0}
    @wraps(real)
    def native(password, setting):
        seen["calls"].append({
            "target": type(password) is str and hmac.compare_digest(password, kat["PASSWORD"]),
            "wrong": type(password) is str and hmac.compare_digest(password, PUBLIC_WRONG),
            "IB": type(setting) is str and hmac.compare_digest(setting, kat["YESCRYPT"]),
        })
        return real(password, setting)
    def prompt(*args, **kwargs):
        seen["prompts"] += 1
        raise AssertionError("PUBLIC supplied noninteractive policy must not prompt")
    with mock.patch.object(app, "verify_password_hash", new=native), \
            mock.patch.object(app.getpass, "getpass", new=prompt):
        yield seen


class AutoPolicyAuthorityFactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only detect absence of the private constructor contract. Literal
        # presence is not taken as proof of its behavior or a false default.
        _identity, raw = basis.bound_file(SOURCE)
        tree = ast.parse(raw)
        policy_class = next((node for node in tree.body
                             if isinstance(node, ast.ClassDef)
                             and node.name == "ProjectPasswordPolicy"), None)
        constructor = (next((node for node in policy_class.body
                             if isinstance(node, ast.FunctionDef) and node.name == "__init__"), None)
                       if policy_class is not None else None)
        available = constructor is not None and any(
            (isinstance(node, ast.Attribute) and node.attr == FACT)
            or (isinstance(node, ast.Constant) and node.value == FACT)
            for node in ast.walk(constructor)
        )
        if not available:
            raise RuntimeError("NOT_READY: AUTO policy restriction fact constructor ABI absent")
        cls.kat = basis.required_external_kat()
        probe = load_script("auto_policy_fact_prerequisite", SOURCE)
        for algorithm in ("SHA512", "YESCRYPT"):
            good = captured(lambda: probe.verify_password_hash(cls.kat["PASSWORD"], cls.kat[algorithm]))
            bad = captured(lambda: probe.verify_password_hash(PUBLIC_WRONG, cls.kat[algorithm]))
            if not (good[1] is None and good[0] is True and bad[1] is None and bad[0] is False):
                fixture_hold()

    def fixture(self, folder):
        root = Path(folder)
        global_path = root / "01-global.yaml"
        global_path.write_text(basis.global_text(self.kat), encoding="utf-8")
        global_path.chmod(0o600)
        app = load_script("auto_policy_fact_" + root.name.replace("-", "_"), SOURCE)
        return app, global_path

    def born(self, app, global_path, *, wrong=False):
        result = captured(lambda: app.ProjectPasswordPolicy(
            global_path, "admin",
            target_password=PUBLIC_WRONG if wrong else self.kat["PASSWORD"],
            interactive=False,
        ))
        self.private(result)
        self.assertTrue(
            result[1] is None and type(result[0]) is app.ProjectPasswordPolicy,
            "genuine policy constructor failed on qualified valid input; details suppressed",
        )
        if result[1] is not None or type(result[0]) is not app.ProjectPasswordPolicy:
            fixture_hold()
        return result[0]

    def private(self, result):
        self.assertTrue(
            all(secret not in result[2] + result[3] for secret in
                (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"], PUBLIC_WRONG)),
            "policy/native diagnostics exposed credential data; details suppressed",
        )

    def fact(self, policy, expected):
        self.assertTrue(getattr(policy, FACT, None) is expected,
                        "policy restriction fact is not the exact expected monotonic boolean")

    def safe_project_error(self, app, result):
        error = result[1]
        self.assertTrue(type(error) is app.SetupError,
                        "real project authority did not return its existing safe domain error")
        self.assertTrue(
            error.args == PROJECT_ARGS and error.__dict__ == {}
            and error.__cause__ is None and error.__context__ is None,
            "policy fact changed existing project error shape or retained a private chain",
        )
        self.private(result)

    def test_valid_helper_and_false_candidate_match_do_not_mark_authority_failed(self):
        for operation in ("valid-helper", "false-match"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(
                    prefix="auto-policy-normal-") as folder:
                app, global_path = self.fixture(folder)
                before = basis.bound_file(global_path)
                with native_observer(app, self.kat) as seen:
                    policy = self.born(app, global_path)
                    self.fact(policy, False)
                    boundary = len(seen["calls"])
                    if operation == "valid-helper":
                        result = captured(lambda: app._ib_project_value(
                            policy, user="admin", fetch=True))
                        self.assertTrue(
                            result[1] is None and type(result[0]) is str
                            and hmac.compare_digest(result[0], self.kat["PASSWORD"]),
                            "actual correct-account helper did not return the native verified target",
                        )
                    else:
                        result = captured(lambda: policy.matches(PUBLIC_WRONG))
                        self.assertTrue(result[1] is None and result[0] is False,
                                        "actual independent wrong candidate must genuinely mismatch")
                    self.private(result)
                    expected_role = "target" if operation == "valid-helper" else "wrong"
                    self.assertTrue(any(item[expected_role] and item["IB"]
                                        for item in seen["calls"][boundary:]),
                                    "actual operation did not reach the real project IB native verifier")
                    self.fact(policy, False)
                    self.assertTrue(seen["prompts"] == 0,
                                    "supplied policy unexpectedly acquired an interactive value")
                self.assertTrue(basis.bound_file(global_path) == before,
                                "policy observation changed its genuine project input")

    def test_wrong_account_marks_fact_without_changing_error_or_disabling_real_helper(self):
        with tempfile.TemporaryDirectory(prefix="auto-policy-account-") as folder:
            app, global_path = self.fixture(folder)
            before = basis.bound_file(global_path)
            with native_observer(app, self.kat) as seen:
                policy = self.born(app, global_path)
                self.fact(policy, False)
                boundary = len(seen["calls"])
                with mock.patch.object(policy, "password", wraps=policy.password) as fetch:
                    rejected = captured(lambda: app._ib_project_value(
                        policy, user="other", fetch=True))
                    self.safe_project_error(app, rejected)
                    self.fact(policy, True)
                    self.assertTrue(fetch.call_count == 0 and len(seen["calls"]) == boundary
                                    and seen["prompts"] == 0,
                                    "account rejection fetched or verified a target before refusing")
                    accepted = captured(lambda: app._ib_project_value(
                        policy, user="admin", fetch=True))
                    self.assertTrue(
                        accepted[1] is None and type(accepted[0]) is str
                        and hmac.compare_digest(accepted[0], self.kat["PASSWORD"]),
                        "restriction fact incorrectly replaced the existing helper permission contract",
                    )
                    self.assertTrue(fetch.call_count > 0
                                    and any(item["target"] and item["IB"]
                                            for item in seen["calls"][boundary:]),
                                    "correct-account followup did not genuinely fetch and verify the target")
                    self.private(accepted)
                    self.fact(policy, True)
                    self.assertTrue(seen["prompts"] == 0,
                                    "restriction observation triggered an interactive retry")
            self.assertTrue(basis.bound_file(global_path) == before,
                            "account restriction changed project data")

    def test_actual_stale_global_and_native_target_mismatch_mark_authority_failed(self):
        for case in ("stale-global", "wrong-target"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                    prefix="auto-policy-rejection-") as folder:
                app, global_path = self.fixture(folder)
                with native_observer(app, self.kat) as seen:
                    policy = self.born(app, global_path, wrong=case == "wrong-target")
                    self.fact(policy, False)
                    if case == "stale-global":
                        with global_path.open("a", encoding="utf-8") as stream:
                            stream.write(PUBLIC_CHANGE)
                    before_call = basis.bound_file(global_path)
                    boundary = len(seen["calls"])
                    result = captured(lambda: app._ib_project_value(
                        policy, user="admin", fetch=True))
                    self.safe_project_error(app, result)
                    self.fact(policy, True)
                    if case == "stale-global":
                        self.assertTrue(len(seen["calls"]) == boundary,
                                        "stale actual binding reached native target acquisition")
                    else:
                        self.assertTrue(any(item["wrong"] and item["IB"]
                                            for item in seen["calls"][boundary:]),
                                        "actual bad supplied target did not reach the genuine IB verifier")
                    self.assertTrue(seen["prompts"] == 0,
                                    "known supplied-authority refusal prompted or guessed another value")
                self.assertTrue(basis.bound_file(global_path) == before_call,
                                "authority rejection rewrote or rolled back the actual project input")


if __name__ == "__main__":
    unittest.main()
