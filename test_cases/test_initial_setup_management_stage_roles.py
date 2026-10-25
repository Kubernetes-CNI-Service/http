"""Present-global management role/Initial contracts: tests-first draft, NOT RUN.

Proposed managed ABI is deliberately not implemented in source-v4. Missing ABI
is prerequisite HOLD, not behavior RED. These are direct boundary tests:
actual project policy/native verification, external ordinary transport MODEL.
They do not establish that the supplied current credential authenticated;
the independent owned-PTY selector/phase suite covers that provenance.
"""
from __future__ import annotations
import hmac
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from test_cases.module_loader import load_script
from test_cases.test_initial_setup_target_password_policy import required_external_kat

ROOT = Path(__file__).resolve().parents[1]
APP = load_script("management_stage_role_contract", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")
PUBLIC_INITIAL = "PUBLIC-INITIAL-Only-17!"
PUBLIC_OOB = "PUBLIC-OOB-Only-91!"
INITIAL_AUTO = ("nv", "set", "system", "config", "auto-save", "state", "enabled")
INITIAL_ZTP = ("nv", "set", "system", "ztp", "config-save", "enabled")
APPLY = ("nv", "config", "apply", "-y")
SAVE = ("nv", "config", "save")
READ = ("nv", "config", "show", "-o", "commands")
CURRENT_BASE = "nv set system hostname nvos\nnv set service lldp state enabled\n"
BOTH_INITIAL = ("nv set system config auto-save state enabled\n"
                "nv set system ztp config-save enabled\n")
ACK = "PUBLIC-MUTATION-ACK\n"


class PresentGlobalManagementStageRoleDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # ABI review must precede any runtime; never call this a current RED.
        if not all(callable(getattr(APP, name, None)) for name in
                   ("_run_authorized_ib_command", "run_initial_stage")):
            raise RuntimeError("FIXTURE HOLD: proposed management role/Initial ABI not implemented")
        cls.kat = required_external_kat()

    def fixture(self, folder):
        root = Path(folder)
        path = root / "01-global.yaml"
        # Independent account and common/IB override; never copied from SUT.
        path.write_text(
            "schema_version: 2\ncommon:\n  switch:\n    system:\n"
            "      aaa:\n        user:\n          admin:\n            password: " +
            repr(self.kat["SHA512"]) + "\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
            "          admin:\n            password: "
                + repr(self.kat["YESCRYPT"])
                + "\n",
            encoding="utf-8")
        path.chmod(0o600)
        policy = APP.ProjectPasswordPolicy(path, "admin",
            target_password=self.kat["PASSWORD"], interactive=False)
        ib = APP.Device("EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                        "203.0.113.1", "02:00:00:00:00:17", "", "")
        eth = APP.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "", "", "", "", "")
        target = APP.Target(ib, eth, "swp7", "eth0")
        neighbor = APP.Neighbor("fe80::17", "vlan1", "02:00:00:00:00:17", "default")
        return path, policy, target, neighbor

    def observers(self, target, neighbor, returned_body):
        # Transparent real native worker delegate: never a fake match or hash.
        original_verify = APP.verify_password_hash
        native = []
        calls = []
        adapter_errors = []
        def verify(password, setting):
            result = original_verify(password, setting)
            native.append({"target": hmac.compare_digest(password, self.kat["PASSWORD"]),
                           "selected_ib_setting": setting == self.kat["YESCRYPT"],
                           "result": result is True})
            return result
        def transport(*args, **kwargs):
            # Only a bounded ordinary remote transport is modeled. No policy,
            # stage, parser, command constructor or authorization is patched.
            if (len(args) != 8 or args[0] is not target or args[1] is not neighbor or
                    args[2] != "cumulus" or args[4] != "admin" or args[6] != 2 or
                    type(args[7]) is not list or kwargs.get("local") is not False or
                    kwargs.get("allow_password_change") is not False or
                    kwargs.get("_phase_operation") is not None or
                    kwargs.get("ib_new_password") is not None):
                adapter_errors.append("ordinary-transport-boundary")
                raise AssertionError("PUBLIC adapter rejected an unexpected ordinary transport")
            command = tuple(args[7])
            if command not in (INITIAL_AUTO, INITIAL_ZTP, APPLY, SAVE, READ):
                adapter_errors.append("ordinary-command")
                raise AssertionError("PUBLIC adapter rejected an unexpected command")
            calls.append({"command": command,
                          "outer_oob": hmac.compare_digest(args[3], PUBLIC_OOB),
                          "inner_initial": hmac.compare_digest(args[5], PUBLIC_INITIAL),
                          "inner_target": hmac.compare_digest(args[5], self.kat["PASSWORD"]),
                          "inner_oob": hmac.compare_digest(args[5], PUBLIC_OOB)})
            return APP.SessionResult(returned_body if command == READ else ACK, 0)
        return verify, transport, native, calls, adapter_errors

    def test_present_global_write_authority_is_distinct_from_selected_current_and_oob(self):
        for selected in ("initial", "target"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory(prefix="main-role-positive-") as folder:
                path, policy, target, neighbor = self.fixture(folder)
                current = PUBLIC_INITIAL if selected == "initial" else self.kat["PASSWORD"]
                self.assertTrue(len({PUBLIC_INITIAL, PUBLIC_OOB, self.kat["PASSWORD"]}) == 3,
                                "three fixture roles must be distinct; values suppressed")
                before = path.read_bytes()
                verify, transport, native, calls, errors = self.observers(target, neighbor, CURRENT_BASE)
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=transport), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts:
                    result = APP._run_authorized_ib_command(
                        target, neighbor, "cumulus", PUBLIC_OOB, "admin", current, 2,
                        list(INITIAL_AUTO), local=False, _password_policy=policy)
                self.assertEqual([], errors)
                self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                                "actual native verification must use exact-account IB setting; values suppressed")
                self.assertEqual([INITIAL_AUTO], [row["command"] for row in calls])
                self.assertTrue(all(row["outer_oob"] and not row["inner_oob"] for row in calls))
                self.assertTrue(all(row["inner_initial"] == (selected == "initial") and
                                    row["inner_target"] == (selected == "target") for row in calls),
                                "project target permission must not replace the authenticated current role")
                self.assertTrue(result.output == ACK and result.exit_code == 0)
                self.assertTrue(before == path.read_bytes(), "project bytes changed; hash material suppressed")
                prompts.assert_not_called()
        with tempfile.TemporaryDirectory(prefix="main-role-account-") as folder:
            _, policy, target, neighbor = self.fixture(folder)
            # Wrong account must be refused before native or ordinary transport.
            verify, transport, native, calls, errors = self.observers(target, neighbor, CURRENT_BASE)
            with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                 mock.patch.object(APP, "run_on_ib", side_effect=transport):
                with self.assertRaises(APP.SetupError):
                    APP._run_authorized_ib_command(
                        target, neighbor, "cumulus", PUBLIC_OOB, "operator", PUBLIC_INITIAL, 2,
                        list(INITIAL_AUTO), local=False, _password_policy=policy)
            self.assertEqual([], errors)
            self.assertEqual([], native)
            self.assertEqual([], calls)
        with tempfile.TemporaryDirectory(prefix="main-role-fresh-") as folder:
            path, policy, target, neighbor = self.fixture(folder)
            verify, transport, native, calls, errors = self.observers(target, neighbor, CURRENT_BASE)
            with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                 mock.patch.object(APP, "run_on_ib", side_effect=transport):
                APP._run_authorized_ib_command(
                    target, neighbor, "cumulus", PUBLIC_OOB, "admin", PUBLIC_INITIAL, 2,
                    list(INITIAL_AUTO), local=False, _password_policy=policy)
                self.assertTrue(bool(native) and len(calls) == 1,
                                "first actual native-authorized dispatch must be reached")
                native_count = len(native)
                path.write_text(path.read_text(encoding="utf-8") + "# PUBLIC changed before second mutation\n",
                                encoding="utf-8")
                with self.assertRaises(APP.SetupError):
                    APP._run_authorized_ib_command(
                        target, neighbor, "cumulus", PUBLIC_OOB, "admin", PUBLIC_INITIAL, 2,
                        list(INITIAL_ZTP), local=False, _password_policy=policy)
            self.assertEqual([], errors)
            self.assertEqual([INITIAL_AUTO], [row["command"] for row in calls])
            self.assertEqual(native_count, len(native), "changed project must not invoke native backend again")

    def test_initial_two_literals_commit_only_missing_values_and_skip_when_present(self):
        cases = (
            ("present", CURRENT_BASE + BOTH_INITIAL, (), True),
            ("missing-auto", CURRENT_BASE + "nv set system ztp config-save enabled\n", (INITIAL_AUTO,), False),
            ("missing-ztp", CURRENT_BASE + "nv set system config auto-save state enabled\n", (INITIAL_ZTP,), False),
            ("missing-both", CURRENT_BASE, (INITIAL_AUTO, INITIAL_ZTP), False),
        )
        for label, current, setters, skipped in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="main-initial-direct-") as folder:
                _, policy, target, neighbor = self.fixture(folder)
                verify, transport, native, calls, errors = self.observers(target, neighbor, CURRENT_BASE + BOTH_INITIAL)
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=transport), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts:
                    outcome = APP.run_initial_stage(
                        target, neighbor, "cumulus", PUBLIC_OOB, "admin", 2, current,
                        local=False, apply=True, authorized=True,
                        _ib_current_password=PUBLIC_INITIAL, _password_policy=policy)
                self.assertEqual([], errors)
                self.assertEqual((True, skipped), outcome)
                # This independent tuple is never generated by desired_commands.
                expected = list(setters) + ([APPLY, SAVE, READ] if setters else [])
                self.assertEqual(expected, [row["command"] for row in calls])
                self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and not row["inner_oob"] for row in calls))
                if setters:
                    self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                                    "each write stage needs actual verified project authority")
                    self.assertEqual(1, sum(row["command"] == APPLY for row in calls))
                    self.assertEqual(1, sum(row["command"] == SAVE for row in calls))
                else:
                    self.assertEqual([], native, "satisfied Initial must not acquire an irrelevant target")
                    self.assertEqual([], calls, "satisfied Initial must not read again, set, apply or save")
                prompts.assert_not_called()


    def test_unknown_initial_current_refuses_before_any_write_or_target_acquisition(self):
        for label, current in (("empty", ""), ("unverifiable", "PUBLIC configuration unavailable\n")):
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="main-initial-unknown-") as folder:
                _, policy, target, neighbor = self.fixture(folder)
                verify, transport, native, calls, errors = self.observers(target, neighbor, CURRENT_BASE + BOTH_INITIAL)
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=transport), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unknown state cannot request target")) as prompts, \
                     mock.patch("builtins.input", side_effect=AssertionError("PUBLIC unknown state cannot request mutation consent")) as consent:
                    with self.assertRaises(APP.SetupError):
                        APP.run_initial_stage(
                            target, neighbor, "cumulus", PUBLIC_OOB, "admin", 2, current,
                            local=False, apply=True, authorized=True,
                            _ib_current_password=PUBLIC_INITIAL, _password_policy=policy)
                self.assertEqual([], errors)
                self.assertEqual([], calls, "unknown current must not set, apply, save or read by guessing state")
                self.assertEqual([], native, "unknown current must not acquire a target write permission")
                prompts.assert_not_called()
                consent.assert_not_called()

    def test_initial_failed_actual_readback_refuses_after_the_full_reached_transaction(self):
        # Independent literal returned bodies, not parser/desired-command output.
        cases = (
            ("missing-ztp", CURRENT_BASE + "nv set system config auto-save state enabled\n"),
            ("unverifiable", "PUBLIC configuration unavailable\n"),
            ("empty", ""),
        )
        for label, returned_body in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="main-initial-readback-") as folder:
                _, policy, target, neighbor = self.fixture(folder)
                verify, transport, native, calls, errors = self.observers(target, neighbor, returned_body)
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=transport), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC explicit target needs no prompt")) as prompts:
                    with self.assertRaises(APP.SetupError):
                        APP.run_initial_stage(
                            target, neighbor, "cumulus", PUBLIC_OOB, "admin", 2, CURRENT_BASE,
                            local=False, apply=True, authorized=True,
                            _ib_current_password=PUBLIC_INITIAL, _password_policy=policy)
                self.assertEqual([], errors)
                self.assertEqual([INITIAL_AUTO, INITIAL_ZTP, APPLY, SAVE, READ],
                                 [row["command"] for row in calls],
                                 "failure must follow the reached setters/commit/save/actual modeled readback")
                self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                                "readback negative needs reached real project/native qualification")
                self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and not row["inner_oob"] for row in calls))
                prompts.assert_not_called()

    def test_initial_check_only_and_actual_confirmation_refusal_never_dispatch(self):
        for label, apply, authorized, expected, consent_count in (
            ("check-only", False, True, (True, False), 0),
            ("refused", True, False, (False, True), 1),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="main-initial-not-authorized-") as folder:
                _, policy, target, neighbor = self.fixture(folder)
                verify, transport, native, calls, errors = self.observers(target, neighbor, CURRENT_BASE + BOTH_INITIAL)
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=transport), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC no-write case cannot request target")) as prompts, \
                     mock.patch("builtins.input", return_value="no") as consent:
                    # Real confirm_first_device_change executes; only the human
                    # terminal input is MODEL. Core authorization is not patched.
                    outcome = APP.run_initial_stage(
                        target, neighbor, "cumulus", PUBLIC_OOB, "admin", 2, CURRENT_BASE,
                        local=False, apply=apply, authorized=authorized,
                        _ib_current_password=PUBLIC_INITIAL, _password_policy=policy)
                self.assertEqual([], errors)
                self.assertEqual(expected, outcome)
                self.assertEqual([], calls, "no mutation or follow-up read after check-only/refused consent")
                self.assertEqual([], native, "no target permission acquisition for an unapproved change")
                self.assertEqual(consent_count, consent.call_count)
                prompts.assert_not_called()

    def _eg_capture(self, action):
        import contextlib
        import io
        output = io.StringIO()
        result = None
        caught = None
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                result = action()
            except BaseException as error:
                caught = error
        return result, caught, output.getvalue()

    def _eg_fixture(self, folder):
        result, caught, output = self._eg_capture(lambda: self.fixture(folder))
        self.assertTrue(caught is None,
                        "PUBLIC fixture birth failed; exception material suppressed")
        self.assertTrue(all(value not in output for value in
                            (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"])),
                        "fixture diagnostic exposed qualified input; values suppressed")
        return result

    def _eg_entry(self, entry, policy, target, neighbor):
        if entry == "helper":
            return APP._run_authorized_ib_command(
                target, neighbor, "cumulus", PUBLIC_OOB, "admin", PUBLIC_INITIAL, 2,
                list(INITIAL_AUTO), local=False, _password_policy=policy)
        if entry == "stage":
            return APP.run_initial_stage(
                target, neighbor, "cumulus", PUBLIC_OOB, "admin", 2, CURRENT_BASE,
                local=False, apply=True, authorized=True,
                _ib_current_password=PUBLIC_INITIAL, _password_policy=policy)
        raise AssertionError("PUBLIC unknown E/G entry")

    def _eg_global_snapshot(self, path):
        # Owned PUBLIC fixture only; crypt settings stay in RAM, never messages.
        import os
        import stat
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def identity(value):
            return tuple(getattr(value, name) for name in fields)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            first = identity(os.fstat(fd))
            if (not stat.S_ISREG(first[2]) or first[5] != 1 or
                    first[6] > 8192 or identity(path.lstat()) != first):
                raise RuntimeError("PUBLIC global snapshot prerequisite HOLD")
            bodies = []
            for unused in range(2):
                os.lseek(fd, 0, os.SEEK_SET)
                body = b""
                while True:
                    chunk = os.read(fd, min(4096, 8193 - len(body)))
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > 8192:
                        raise RuntimeError("PUBLIC global snapshot size HOLD")
                if (len(body) != first[6] or identity(os.fstat(fd)) != first or
                        identity(path.lstat()) != first):
                    raise RuntimeError("PUBLIC global snapshot changed HOLD")
                bodies.append(body)
            if bodies[0] != bodies[1]:
                raise RuntimeError("PUBLIC global snapshot second EOF HOLD")
            return first, bodies[0]
        finally:
            os.close(fd)

    def test_known_error_chokes_preserve_only_literal_safe_facts(self):
        import contextlib
        # Independent public contract. Exact True is not truthiness; only
        # builtin int errno 1..255 survives. This finite table is not Cartesian.
        cases = (
            ("helper-os13", "helper", "os", 13, True, None, True, 13),
            ("stage-os13", "stage", "os", 13, True, None, True, 13),
            ("helper-setup255", "helper", "setup", None, False, 255, False, 255),
            ("stage-setup1", "stage", "setup", None, True, 1, True, 1),
            ("helper-boolfacts", "helper", "setup", None, 1, True, False, None),
            ("stage-invalidfacts", "stage", "os", 256, 1, 0, False, None),
        )
        for label, entry, kind, number, raw_uncertain, raw_io, expected_uncertain, expected_errno in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory(prefix="main-known-error-") as folder:
                path, policy, target, neighbor = self._eg_fixture(folder)
                before = self._eg_global_snapshot(path)
                verify, transport, native, calls, errors = self.observers(
                    target, neighbor, CURRENT_BASE + BOTH_INITIAL)
                seed = "PUBLIC-KNOWN-FAULT-SEED"
                fault = OSError(number, seed) if kind == "os" else APP.SetupError(seed)
                fault.cleanup_uncertain = raw_uncertain
                if raw_io is not None:
                    fault.io_errno = raw_io
                fault.__cause__ = RuntimeError("PUBLIC-FAULT-CAUSE")
                fault.__context__ = RuntimeError("PUBLIC-FAULT-CONTEXT")
                original_args = fault.args
                reached = []
                delegated = []
                real_helper = APP._run_authorized_ib_command
                def dispatch(*args, **kwargs):
                    result = transport(*args, **kwargs)
                    if entry == "helper":
                        reached.append("after-validated-transport")
                        raise fault
                    return result
                def after_helper(*args, **kwargs):
                    # MODEL the dependency return boundary only AFTER this
                    # real helper succeeded. Do not let the inner choke mask
                    # the Initial outer choke's original OSError/fact branch.
                    result = real_helper(*args, **kwargs)
                    delegated.append(type(result) is APP.SessionResult and
                                     result.output == ACK and result.exit_code == 0)
                    reached.append("after-real-helper-return")
                    raise fault
                wrapper = (mock.patch.object(APP, "_run_authorized_ib_command", side_effect=after_helper)
                           if entry == "stage" else contextlib.nullcontext())
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=dispatch), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts, \
                     wrapper:
                    result, caught, output = self._eg_capture(
                        lambda: self._eg_entry(entry, policy, target, neighbor))
                expected_args = (("management IB operation failed; device state is UNKNOWN",)
                                 if entry == "helper" else
                                 ("Initial stage failed; device state is UNKNOWN",))
                self.assertTrue(type(caught) is APP.SetupError and caught is not fault,
                                "known error must become a fresh fixed safe domain error")
                self.assertTrue(caught.args == expected_args,
                                "known error args differ from the independent literal contract")
                self.assertTrue(caught.__cause__ is None and caught.__context__ is None,
                                "known error retained a diagnostic chain")
                expected_keys = set()
                if expected_uncertain:
                    expected_keys.add("cleanup_uncertain")
                if expected_errno is not None:
                    expected_keys.add("io_errno")
                self.assertTrue(set(caught.__dict__) == expected_keys,
                                "known error copied facts outside the closed safe set")
                self.assertTrue((getattr(caught, "cleanup_uncertain", None) is True) == expected_uncertain,
                                "uncertainty fact must use exact True")
                self.assertTrue((not hasattr(caught, "io_errno") if expected_errno is None else
                                 type(caught.io_errno) is int and caught.io_errno == expected_errno),
                                "errno fact must be an independently expected bounded builtin int")
                self.assertTrue(fault.args == original_args,
                                "normalization must not modify the original fault")
                self.assertTrue(result is None, "failed operation unexpectedly returned success")
                self.assertEqual([], errors)
                self.assertEqual([INITIAL_AUTO], [row["command"] for row in calls])
                self.assertEqual(["after-validated-transport" if entry == "helper" else
                                  "after-real-helper-return"], reached)
                self.assertEqual([True] if entry == "stage" else [], delegated)
                self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                                "known fault must follow actual project/native qualification")
                self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and not row["inner_oob"] for row in calls),
                                "fault path changed independent credential roles")
                self.assertTrue(before == self._eg_global_snapshot(path),
                                "known fault changed the project full identity or bytes")
                self.assertTrue(all(value not in output for value in
                                    (seed, self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"])),
                                "known fault diagnostic exposed input; values suppressed")
                prompts.assert_not_called()

    def test_program_errors_cross_both_real_layers_without_business_conversion(self):
        for entry in ("helper", "stage"):
            for error_type in (RuntimeError, AssertionError):
                with self.subTest(entry=entry, kind=error_type.__name__), \
                     tempfile.TemporaryDirectory(prefix="main-program-error-") as folder:
                    path, policy, target, neighbor = self._eg_fixture(folder)
                    before = self._eg_global_snapshot(path)
                    verify, transport, native, calls, errors = self.observers(
                        target, neighbor, CURRENT_BASE + BOTH_INITIAL)
                    fault = error_type("PUBLIC-PROGRAM-FAULT-SEED")
                    reached = []
                    def dispatch(*args, **kwargs):
                        transport(*args, **kwargs)
                        reached.append("after-validated-transport")
                        raise fault
                    with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                         mock.patch.object(APP, "run_on_ib", side_effect=dispatch), \
                         mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts:
                        result, caught, output = self._eg_capture(
                            lambda: self._eg_entry(entry, policy, target, neighbor))
                    self.assertTrue(caught is fault and type(caught) is error_type,
                                    "program errors must retain original identity, not become business HOLD")
                    self.assertTrue(caught.args == ("PUBLIC-PROGRAM-FAULT-SEED",),
                                    "program error args unexpectedly changed")
                    self.assertTrue(result is None, "program error returned a success value")
                    self.assertEqual(["after-validated-transport"], reached)
                    self.assertEqual([], errors)
                    self.assertEqual([INITIAL_AUTO], [row["command"] for row in calls])
                    self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                                    "program fault must follow actual project/native qualification")
                    self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and not row["inner_oob"] for row in calls))
                    self.assertTrue(before == self._eg_global_snapshot(path),
                                    "program error changed the project full identity or bytes")
                    self.assertTrue(all(value not in output for value in
                                        (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"])),
                                    "program error diagnostic exposed qualified input; values suppressed")
                    prompts.assert_not_called()

    def test_every_initial_action_and_actual_readback_has_fresh_native_authority(self):
        with tempfile.TemporaryDirectory(prefix="main-initial-every-gate-") as folder:
            path, policy, target, neighbor = self._eg_fixture(folder)
            before = self._eg_global_snapshot(path)
            verify, transport, native, calls, errors = self.observers(
                target, neighbor, CURRENT_BASE + BOTH_INITIAL)
            real_helper = APP._run_authorized_ib_command
            active = []
            helper_commands = []
            gate_witnesses = []
            delegated = []
            def helper(*args, **kwargs):
                command = tuple(args[7])
                helper_commands.append(command)
                active.append((command, len(native)))
                try:
                    result = real_helper(*args, **kwargs)
                    delegated.append(type(result) is APP.SessionResult and result.exit_code == 0)
                    return result
                finally:
                    active.pop()
            def dispatch(*args, **kwargs):
                result = transport(*args, **kwargs)
                gate_witnesses.append(bool(active) and active[-1][0] == tuple(args[7])
                                      and len(native) > active[-1][1])
                return result
            with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                 mock.patch.object(APP, "run_on_ib", side_effect=dispatch), \
                 mock.patch.object(APP, "_run_authorized_ib_command", side_effect=helper), \
                 mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts:
                outcome, caught, output = self._eg_capture(
                    lambda: self._eg_entry("stage", policy, target, neighbor))
            expected = [INITIAL_AUTO, INITIAL_ZTP, APPLY, SAVE, READ]
            self.assertTrue(caught is None,
                            "Initial positive failed; exception material suppressed")
            self.assertEqual((True, False), outcome)
            self.assertEqual([], errors)
            self.assertEqual(expected, helper_commands)
            self.assertEqual(expected, [row["command"] for row in calls])
            self.assertEqual([True, True, True, True, True], gate_witnesses,
                             "each actual transport must follow native verification in its own real helper call")
            self.assertEqual([True, True, True, True, True], delegated)
            self.assertEqual([], active)
            self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                            "all reached native checks must verify the selected project IB setting")
            self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and not row["inner_oob"] for row in calls),
                            "Initial must keep selected current distinct from OOB and target permission")
            self.assertTrue(before == self._eg_global_snapshot(path),
                            "successful Initial changed project authority")
            self.assertTrue(all(value not in output for value in
                                (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"])),
                            "Initial diagnostic exposed qualified input; values suppressed")
            prompts.assert_not_called()

    def test_global_change_after_each_real_initial_action_blocks_the_next_action(self):
        expected = [INITIAL_AUTO, INITIAL_ZTP, APPLY, SAVE, READ]
        for cutpoint in (INITIAL_AUTO, INITIAL_ZTP, APPLY, SAVE):
            with self.subTest(command=cutpoint), tempfile.TemporaryDirectory(prefix="main-initial-cut-") as folder:
                path, policy, target, neighbor = self._eg_fixture(folder)
                verify, transport, native, calls, errors = self.observers(
                    target, neighbor, CURRENT_BASE + BOTH_INITIAL)
                real_helper = APP._run_authorized_ib_command
                delegated = []
                perturbations = []
                def helper(*args, **kwargs):
                    result = real_helper(*args, **kwargs)
                    command = tuple(args[7])
                    delegated.append((command, type(result) is APP.SessionResult and result.exit_code == 0))
                    if command == cutpoint and not perturbations:
                        # Explicit MODEL mutation of this owned authority file
                        # AFTER the real helper's successful post-result guard.
                        path.write_bytes(path.read_bytes() + b"# PUBLIC authority changed between Initial actions\n")
                        perturbations.append((len(native), self._eg_global_snapshot(path)))
                    return result
                with mock.patch.object(APP, "verify_password_hash", side_effect=verify), \
                     mock.patch.object(APP, "run_on_ib", side_effect=transport), \
                     mock.patch.object(APP, "_run_authorized_ib_command", side_effect=helper), \
                     mock.patch.object(APP.getpass, "getpass", side_effect=AssertionError("PUBLIC unexpected target prompt")) as prompts:
                    outcome, caught, output = self._eg_capture(
                        lambda: self._eg_entry("stage", policy, target, neighbor))
                prefix = expected[:expected.index(cutpoint) + 1]
                self.assertEqual(1, len(perturbations), "the independent post-helper change was not reached")
                self.assertTrue(type(caught) is APP.SetupError,
                                "changed project must fail closed before the next action; error material suppressed")
                self.assertTrue(outcome is None, "changed authority returned stage success")
                self.assertEqual([], errors)
                self.assertEqual(prefix, [row["command"] for row in calls],
                                 "no next mutation or readback may cross changed authority")
                self.assertEqual([(command, True) for command in prefix], delegated,
                                 "the already-reached real helper prefix must remain witnessed, not rolled back")
                self.assertEqual(perturbations[0][0], len(native),
                                 "changed authority must refuse before another native backend call")
                self.assertTrue(perturbations[0][1] == self._eg_global_snapshot(path),
                                "refusal changed the perturbed authority full identity or bytes")
                self.assertTrue(bool(native) and all(row["target"] and row["selected_ib_setting"] and row["result"] for row in native),
                                "pre-change prefix must have actual native project permission")
                self.assertTrue(all(row["outer_oob"] and row["inner_initial"] and not row["inner_oob"] for row in calls))
                self.assertTrue(all(value not in output for value in
                                    (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"])),
                                "changed-project diagnostic exposed qualified input; values suppressed")
                prompts.assert_not_called()


if __name__ == "__main__":
    unittest.main()
