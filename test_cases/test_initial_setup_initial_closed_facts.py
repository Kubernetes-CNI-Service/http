"""Independent Initial closed-fact contracts, additive tests first.

PUBLIC literal supplied-state cases; actual project policy/native verification
with a finite external ordinary-transport MODEL. Not MAIN or native SSH proof.
"""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_management_stage_roles as BASE

APP = BASE.APP
INITIAL_AUTO = ("nv", "set", "system", "config", "auto-save", "state", "enabled")
INITIAL_ZTP = ("nv", "set", "system", "ztp", "config-save", "enabled")
APPLY = ("nv", "config", "apply", "-y")
SAVE = ("nv", "config", "save")
READ = ("nv", "config", "show", "-o", "commands")
BASE_BODY = "nv set system hostname nvos\nnv set service lldp state enabled\n"
AUTO_ON = "nv set system config auto-save state enabled\n"
AUTO_OFF = "nv set system config auto-save state disabled\n"
ZTP_ON = "nv set system ztp config-save enabled\n"
ZTP_OFF = "nv set system ztp config-save disabled\n"
BOTH_ON = AUTO_ON + ZTP_ON
PUBLIC_CURRENT = "PUBLIC-INITIAL-Only-17!"
PUBLIC_OOB = "PUBLIC-OOB-Only-91!"


class InitialClosedFactContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(callable(getattr(APP, name, None)) for name in (
                "run_initial_stage", "_run_authorized_ib_command")):
            raise RuntimeError("FIXTURE HOLD: existing Initial interfaces are unavailable")
        captured = io.StringIO()
        fault = None
        kat = None
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            try:
                kat = BASE.required_external_kat()
            except BaseException as error:
                fault = error
        if (fault is not None or type(kat) is not dict or
                not all(type(kat.get(key)) is str and kat[key] for key in
                        ("PASSWORD", "SHA512", "YESCRYPT"))):
            raise RuntimeError("FIXTURE HOLD: qualified external input unavailable") from None
        if any(kat[key] in captured.getvalue() for key in ("PASSWORD", "SHA512", "YESCRYPT")):
            raise RuntimeError("FIXTURE HOLD: external-input reader diagnostic is unsafe") from None
        cls.kat = kat

    def _capture(self, action):
        return BASE.PresentGlobalManagementStageRoleDraftTests._eg_capture(self, action)

    def _no_private_output(self, output):
        self.assertTrue(all(self.kat[key] not in output for key in
                            ("PASSWORD", "SHA512", "YESCRYPT")),
                        "qualified input appeared in diagnostic; values suppressed")

    def _fixture(self, folder):
        result, caught, output = self._capture(
            lambda: BASE.PresentGlobalManagementStageRoleDraftTests.fixture(self, folder))
        self._no_private_output(output)
        if caught is not None:
            raise RuntimeError("FIXTURE HOLD: owned Initial fixture birth failed") from None
        return result

    def _snapshot(self, path):
        result, caught, output = self._capture(
            lambda: BASE.PresentGlobalManagementStageRoleDraftTests._eg_global_snapshot(self, path))
        self._no_private_output(output)
        if caught is not None:
            raise RuntimeError("FIXTURE HOLD: owned authority snapshot failed") from None
        return result

    def _stage(self, policy, target, neighbor, current, *, authorized):
        return APP.run_initial_stage(
            target, neighbor, "cumulus", PUBLIC_OOB, "admin", 2, current,
            local=False, apply=True, authorized=authorized,
            _ib_current_password=PUBLIC_CURRENT, _password_policy=policy)

    def _safe_closed_failure(self, caught, outcome):
        self.assertTrue(type(caught) is APP.SetupError,
                        "closed Initial facts must produce a safe domain refusal")
        self.assertTrue(caught.args == ("Initial stage failed; device state is UNKNOWN",),
                        "Initial refusal message differs from independent safe contract")
        self.assertTrue(caught.__cause__ is None and caught.__context__ is None,
                        "closed-fact refusal retained an exception chain")
        self.assertTrue(not caught.__dict__,
                        "pure closed-fact refusal acquired unexpected failure facts")
        self.assertTrue(outcome is None, "unqualified Initial facts returned an outcome")

    def _real_authority_action(self, policy, target, neighbor, current, returned_body, *,
                               authorized):
        verify, transport, native, calls, errors = (
            BASE.PresentGlobalManagementStageRoleDraftTests.observers(
                self, target, neighbor, returned_body))
        real_helper = APP._run_authorized_ib_command
        active = []
        helper_commands = []
        per_call_native = []
        delivered = []
        read_delivered = []
        allowed = (INITIAL_AUTO, INITIAL_ZTP, APPLY, SAVE, READ)

        def helper(*args, **kwargs):
            if len(args) != 8 or type(args[7]) is not list:
                errors.append("PUBLIC helper shape")
                raise AssertionError("PUBLIC unexpected Initial helper boundary")
            command = tuple(args[7])
            if command not in allowed:
                errors.append("PUBLIC helper command")
                raise AssertionError("PUBLIC unexpected Initial helper command")
            helper_commands.append(command)
            active.append((command, len(native)))
            try:
                result = real_helper(*args, **kwargs)
                delivered.append(type(result) is APP.SessionResult and
                                 type(result.exit_code) is int and result.exit_code == 0)
                if command == READ:
                    read_delivered.append(type(result) is APP.SessionResult and
                                          result.output == returned_body)
                return result
            finally:
                active.pop()

        def dispatch(*args, **kwargs):
            result = transport(*args, **kwargs)
            per_call_native.append(bool(active) and
                                   active[-1][0] == tuple(args[7]) and
                                   len(native) > active[-1][1])
            return result

        with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
             mock.patch.object(APP, "run_on_ib", side_effect=dispatch), \
             mock.patch.object(APP, "_run_authorized_ib_command", side_effect=helper), \
             mock.patch.object(APP.getpass, "getpass",
                               side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts, \
             mock.patch("builtins.input", return_value="yes") as consent:
            outcome, caught, output = self._capture(
                lambda: self._stage(policy, target, neighbor, current, authorized=authorized))
        return {
            "outcome": outcome, "caught": caught, "output": output,
            "native": native, "calls": calls, "errors": errors,
            "helpers": helper_commands, "per_call_native": per_call_native,
            "delivered": delivered, "read_delivered": read_delivered,
            "active": active, "prompt_count": prompts.call_count,
            "consent_count": consent.call_count,
        }

    def _assert_reached_prefix(self, observed, expected, *, consent_count):
        # All entries are closed PUBLIC commands or safe booleans/counts.
        self.assertEqual([], observed["errors"])
        self.assertEqual(expected, observed["helpers"])
        self.assertEqual(expected, [row["command"] for row in observed["calls"]])
        self.assertEqual([True] * len(expected), observed["per_call_native"],
                         "native permission must precede dispatch in this same real helper")
        self.assertEqual([True] * len(expected), observed["delivered"],
                         "every modeled transport must return through the real helper")
        self.assertEqual([True], observed["read_delivered"],
                         "the actual READ helper must return its supplied body before grammar checks")
        self.assertEqual([], observed["active"])
        self.assertTrue(bool(observed["native"]) and all(
            row["target"] and row["selected_ib_setting"] and row["result"]
            for row in observed["native"]),
            "actual native checks must qualify the same-account IB authority")
        self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and
                            not row["inner_oob"] for row in observed["calls"]),
                        "Initial changed the independent outer/current roles")
        self.assertEqual(consent_count, observed["consent_count"])
        self.assertEqual(0, observed["prompt_count"])
        self._no_private_output(observed["output"])

    def test_single_disabled_fact_requires_actual_consent_and_missing_only_transaction(self):
        cases = (
            ("auto-disabled", BASE_BODY + AUTO_OFF + ZTP_ON, INITIAL_AUTO),
            ("ztp-disabled", BASE_BODY + AUTO_ON + ZTP_OFF, INITIAL_ZTP),
        )
        for label, current, setter in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(
                    prefix="initial-closed-positive-") as folder:
                path, policy, target, neighbor = self._fixture(folder)
                before = self._snapshot(path)
                observed = self._real_authority_action(
                    policy, target, neighbor, current, BASE_BODY + BOTH_ON,
                    authorized=False)
                self._assert_reached_prefix(
                    observed, [setter, APPLY, SAVE, READ], consent_count=1)
                self.assertTrue(observed["caught"] is None,
                                "qualified single disabled value was refused")
                self.assertTrue(type(observed["outcome"]) is tuple and
                                observed["outcome"] == (True, False),
                                "authorized Initial transaction returned unexpected flags")
                self.assertTrue(before == self._snapshot(path),
                                "Initial changed the authority full identity or bytes")

    def test_bad_initial_facts_refuse_before_target_native_dispatch_or_consent(self):
        cases = (
            ("unknown-auto", BASE_BODY + ZTP_ON +
             "nv set system config auto-save state PUBLIC_UNKNOWN\n"),
            ("unknown-ztp", BASE_BODY + AUTO_ON +
             "nv set system ztp config-save PUBLIC_UNKNOWN\n"),
            ("auto-enabled-disabled", BASE_BODY + AUTO_ON + AUTO_OFF + ZTP_ON),
            ("ztp-disabled-enabled", BASE_BODY + AUTO_ON + ZTP_OFF + ZTP_ON),
            ("auto-extra-after-complete", BASE_BODY + BOTH_ON +
             "nv set system config auto-save state enabled EXTRA\n"),
            ("ztp-extra-after-complete", BASE_BODY + BOTH_ON +
             "nv set system ztp config-save enabled EXTRA\n"),
            ("auto-truncated-after-complete", BASE_BODY + BOTH_ON +
             "nv set system config auto-save state\n"),
            ("ztp-truncated-after-complete", BASE_BODY + BOTH_ON +
             "nv set system ztp config-save\n"),
        )
        for label, current in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(
                    prefix="initial-closed-preflight-") as folder:
                counts = {"target": 0, "native": 0, "transport": 0, "consent": 0, "getpass": 0}

                def forbidden(kind):
                    def reject(*args, **kwargs):
                        counts[kind] += 1
                        raise AssertionError("PUBLIC premature Initial external boundary")
                    return reject

                with mock.patch.object(APP.ProjectPasswordPolicy, "password",
                                       side_effect=forbidden("target")), \
                     mock.patch.object(APP, "verify_password_hash",
                                       side_effect=forbidden("native")), \
                     mock.patch.object(APP, "run_on_ib", side_effect=forbidden("transport")), \
                     mock.patch("builtins.input", side_effect=forbidden("consent")), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=forbidden("getpass")):
                    # Policy birth is actual and also inside the external tripwires.
                    path, policy, target, neighbor = self._fixture(folder)
                    before = self._snapshot(path)
                    outcome, caught, output = self._capture(
                        lambda: self._stage(policy, target, neighbor, current, authorized=True))
                self.assertEqual(
                    {"target": 0, "native": 0, "transport": 0, "consent": 0, "getpass": 0},
                    counts, "unqualified facts crossed an external boundary")
                self._no_private_output(output)
                self.assertTrue(before == self._snapshot(path),
                                "preflight refusal changed authority full identity or bytes")
                self._safe_closed_failure(caught, outcome)

    def test_bad_closed_actual_readback_refuses_after_real_helper_prefix(self):
        cases = (
            ("unknown-after-complete", BASE_BODY + BOTH_ON +
             "nv set system config auto-save state PUBLIC_UNKNOWN\n"),
            ("contradiction-after-complete", BASE_BODY + BOTH_ON + ZTP_OFF),
            ("extra-after-complete", BASE_BODY + BOTH_ON +
             "nv set system config auto-save state enabled EXTRA\n"),
            ("truncated-after-complete", BASE_BODY + BOTH_ON +
             "nv set system ztp config-save\n"),
        )
        for label, returned_body in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(
                    prefix="initial-closed-readback-") as folder:
                path, policy, target, neighbor = self._fixture(folder)
                before = self._snapshot(path)
                observed = self._real_authority_action(
                    policy, target, neighbor, BASE_BODY + AUTO_OFF + ZTP_ON,
                    returned_body, authorized=True)
                # Inspect genuine successful helper prefix before the domain outcome.
                self._assert_reached_prefix(
                    observed, [INITIAL_AUTO, APPLY, SAVE, READ], consent_count=0)
                self.assertTrue(before == self._snapshot(path),
                                "readback refusal changed authority full identity or bytes")
                self._safe_closed_failure(observed["caught"], observed["outcome"])


if __name__ == "__main__":
    unittest.main()
