"""Explicit Services/KEY/IPv4 context contracts; tests-first NOT READY.

Real canonical policy/native/helper/builder/consumer code; ordinary transport,
IPv4 interactive endpoint and key-possession endpoint are external MODELS.
No MAIN/auto/offline grant, native SSH/PTY custody or device proof is implied.
"""
from __future__ import annotations

import ast
import base64
from contextlib import ExitStack, contextmanager, redirect_stdout, redirect_stderr
import hashlib
import hmac
import io
import os
from pathlib import Path
import shlex
import struct
import stat
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_management_stage_roles as roles

APP = roles.APP
PUBLIC_INITIAL = "PUBLIC-INITIAL-Only-17!"
PUBLIC_OOB = "PUBLIC-OOB-Only-91!"
DNS = ("nv", "set", "system", "dns", "server", "192.0.2.53")
NTP = ("nv", "set", "system", "ntp", "server", "192.0.2.123")
TZ = ("nv", "set", "system", "date-time", "timezone", "UTC")
APPLY = ("nv", "config", "apply", "-y")
SAVE = ("nv", "config", "save")
READ = ("nv", "config", "show", "-o", "commands")
SERVICE_ORDER = [DNS, NTP, TZ, APPLY, SAVE, READ]
BASE = "nv set system hostname nvos\nnv set service lldp state enabled\n"
SERVICE_BODY = (BASE + "nv set system dns server 192.0.2.53\n"
                "nv set system ntp server 192.0.2.123\n"
                "nv set system date-time timezone UTC\n")
UPDATED = "IBSW_PUBLIC_KEYS_UPDATED\n"
UNCHANGED = "IBSW_PUBLIC_KEYS_UNCHANGED\n"
EXTRA = "IBSW_PUBLIC_KEYS_UPDATED\nPUBLIC-T1-EXTRA\n"
SAFE_ARGS = ("management IB operation failed; device state is UNKNOWN",)
SAFE_PATH = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "



def canonical_source_tree(path):
    # Qualification-only bounded source read, not a policy or execution hook.
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
              "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    def nine(value):
        return tuple(getattr(value, field) for field in fields)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = nine(os.fstat(fd))
        if (not stat.S_ISREG(first[2]) or first[5] != 1 or first[6] > 1048576
                or nine(path.lstat()) != first):
            raise RuntimeError("FIXTURE HOLD: canonical source custody invalid")
        copies = []
        for unused in range(2):
            os.lseek(fd, 0, os.SEEK_SET)
            body = b""
            while True:
                part = os.read(fd, min(65536, 1048577 - len(body)))
                if not part:
                    break
                body += part
                if len(body) > 1048576:
                    raise RuntimeError("FIXTURE HOLD: canonical source exceeds bound")
            if (len(body) != first[6] or nine(os.fstat(fd)) != first
                    or nine(path.lstat()) != first):
                raise RuntimeError("FIXTURE HOLD: canonical source changed")
            copies.append(body)
        if copies[0] != copies[1]:
            raise RuntimeError("FIXTURE HOLD: canonical source EOF disagreement")
        return ast.parse(copies[0], filename=str(path))
    finally:
        os.close(fd)

class ExplicitConsumerContextDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Do not issue missing-kwargs TypeError as a behavioral RED.
        path = Path(APP.__file__)
        tree = canonical_source_tree(path)
        for name in ("run_service_stage", "run_key_stage", "verify_ipv4_login"):
            nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == name]
            if len(nodes) != 1 or not callable(getattr(APP, name, None)):
                raise RuntimeError("FIXTURE HOLD: explicit consumer API absent")
            args = nodes[0].args
            defaults = {item.arg: value for item, value in zip(args.kwonlyargs, args.kw_defaults)}
            if not all(key in defaults and isinstance(defaults[key], ast.Constant)
                       and defaults[key].value is None
                       for key in ("_ib_current_password", "_password_policy")):
                raise RuntimeError("FIXTURE HOLD: explicit consumer kwargs not ready")
        cls.kat = roles.required_external_kat()
        ready = False
        try:
            ready = all(APP.verify_password_hash(cls.kat["PASSWORD"], cls.kat[name]) is True
                        and APP.verify_password_hash("Incorrect123!", cls.kat[name]) is False
                        for name in ("SHA512", "YESCRYPT"))
        except BaseException:
            # Qualification failure is fixed fixture HOLD, outside except;
            # never let a private backend diagnostic enter unittest repr.
            pass
        if not ready:
            raise RuntimeError("FIXTURE HOLD: genuine original password KAT unavailable")

    def capture(self, action):
        output = io.StringIO()
        value = caught = None
        normal = False
        with redirect_stdout(output), redirect_stderr(output):
            try:
                value = action()
                normal = True
            except BaseException as error:
                caught = error
        return dict(value=value, error=caught, normal=normal, output=output.getvalue())

    def fixture(self, folder, *, block_birth=False):
        attempts = []
        def forbidden(*args, **kwargs):
            attempts.append("PUBLIC unexpected acquisition at policy birth")
            raise AssertionError("PUBLIC policy birth acquired a target")
        with ExitStack() as stack:
            if block_birth:
                for owner, name in ((APP, "verify_password_hash"),
                                    (APP.ProjectPasswordPolicy, "password"),
                                    (APP.getpass, "getpass")):
                    stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
            birth = self.capture(lambda: roles.PresentGlobalManagementStageRoleDraftTests.fixture(self, folder))
        if not birth["normal"] or birth["error"] is not None:
            # Prerequisite classification only; do not expose the captured
            # private exception through a unittest assertion or error chain.
            qualification = RuntimeError("FIXTURE HOLD: explicit consumer fixture birth unavailable")
            try:
                raise qualification from None
            finally:
                qualification.__cause__ = None
                qualification.__context__ = None
        self.assertTrue(birth["normal"] and birth["error"] is None,
                        "fixture birth failed; diagnostic material suppressed")
        self.assertEqual([], attempts)
        self.private_output(birth["output"])
        path, policy, target, neighbor = birth["value"]
        def field(value):
            return struct.pack(">I", len(value)) + value
        wire = field(b"ssh-ed25519") + field(bytes([31]) * 32)
        line = "ssh-ed25519 " + base64.b64encode(wire).decode("ascii") + " PUBLIC-T1-management"
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
        entry = dict(name="mgmt-server.pub", line=line, fingerprint=fingerprint)
        private = Path(folder) / "PUBLIC-private-placeholder"
        private.write_bytes(b"PUBLIC placeholder; possession endpoint is external MODEL\n")
        private.chmod(0o600)
        return dict(path=path, policy=policy, target=target, neighbor=neighbor,
                    services={"dns": ["192.0.2.53"], "ntp": ["192.0.2.123"], "timezone": "UTC"},
                    keys=[entry], private=private, line=line)

    def private_output(self, output):
        self.assertTrue(all(secret not in output for secret in
                            (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"],
                             PUBLIC_INITIAL, PUBLIC_OOB)),
                        "diagnostics exposed credentials or qualified input; values suppressed")

    def snapshot(self, path):
        return roles.PresentGlobalManagementStageRoleDraftTests._eg_global_snapshot(self, path)

    def invoke(self, kind, f, current, policy, *, apply=True, authorized=True,
               service_body=BASE, keys=None, user="admin"):
        context = dict(_ib_current_password=current, _password_policy=policy)
        if kind == "service":
            return APP.run_service_stage(
                f["target"], f["neighbor"], "cumulus", PUBLIC_OOB, user, 2,
                f["services"], service_body, local=False, apply=apply,
                authorized=authorized, **context)
        if kind == "key":
            return APP.run_key_stage(
                f["target"], f["neighbor"], "cumulus", PUBLIC_OOB, user, 2,
                f["keys"] if keys is None else keys, local=False, apply=apply,
                authorized=authorized, management_private_key=f["private"], **context)
        if kind == "ipv4":
            return APP.verify_ipv4_login(
                f["target"], "default", "cumulus", PUBLIC_OOB, user, 2,
                local=False, **context)
        raise AssertionError("PUBLIC unknown consumer fixture")

    @contextmanager
    def boundaries(self, f, kind, selected, *, receipt=UPDATED, legacy=False,
                   block=False, fault=None, change_transport=False, change_helper=None,
                   consent="no"):
        real_verify = APP.verify_password_hash
        real_helper = APP._run_authorized_ib_command
        real_password = APP.ProjectPasswordPolicy.password
        observation = dict(native=[], fetch=[], calls=[], roles=[], helper=[], success=[],
                           helper_errors=[], active=[], gate=[], possession=[], prompts=[],
                           consent=[], errors=[], fault=[], mutation=[])
        def label(command):
            if type(command) is not list:
                raise AssertionError("PUBLIC transport argv is not a list")
            vector = tuple(command)
            if vector in SERVICE_ORDER:
                return vector
            if (len(command) == 5 and command[:2] == ["sh", "-c"]
                    and command[3] == "--" and type(command[2]) is str):
                try:
                    public = base64.b64decode(command[4], validate=True)
                except (ValueError, TypeError):
                    raise AssertionError("PUBLIC installer payload is malformed") from None
                if public == (f["line"] + "\n").encode("ascii"):
                    return "KEY"
            raise AssertionError("PUBLIC command outside the closed transport model")
        def mutate():
            if observation["mutation"]:
                raise AssertionError("PUBLIC mutation must occur exactly once")
            path = f["path"]
            path.write_bytes(path.read_bytes() + b"# PUBLIC between consumer actions\n")
            observation["mutation"].append((len(observation["native"]), self.snapshot(path)))
        def verify(password, setting):
            if block:
                observation["errors"].append("forbidden-native")
                raise AssertionError("PUBLIC target verifier must not be reached")
            result = real_verify(password, setting)
            observation["native"].append(dict(
                target=hmac.compare_digest(password, self.kat["PASSWORD"]),
                IB=hmac.compare_digest(setting, self.kat["YESCRYPT"]), result=result is True))
            return result
        def password(policy):
            if block or legacy:
                observation["errors"].append("forbidden-fetch")
                raise AssertionError("PUBLIC target fetch must not be reached")
            observation["fetch"].append("actual-policy-password")
            return real_password(policy)
        def helper(*args, **kwargs):
            item = label(args[7])
            observation["helper"].append(item)
            observation["active"].append((item, len(observation["native"])))
            try:
                result = real_helper(*args, **kwargs)
                observation["success"].append(item)
            except BaseException as error:
                observation["helper_errors"].append(error)
                raise
            finally:
                observation["active"].pop()
            if item == change_helper:
                mutate()
            return result
        def dispatch(*args, **kwargs):
            if block:
                observation["errors"].append("forbidden-dispatch")
                raise AssertionError("PUBLIC dispatch must not be reached")
            if (len(args) != 8 or args[0] is not f["target"] or args[1] is not f["neighbor"]
                    or args[2] != "cumulus" or args[4] != "admin" or args[6] != 2
                    or kwargs.get("local") is not False
                    or kwargs.get("allow_password_change", False) is not False
                    or kwargs.get("ib_new_password") is not None
                    or kwargs.get("_phase_operation") is not None):
                observation["errors"].append("ordinary-boundary")
                raise AssertionError("PUBLIC unexpected ordinary boundary")
            item = label(args[7])
            observation["calls"].append(item)
            observation["roles"].append(
                hmac.compare_digest(args[3], PUBLIC_OOB) and
                hmac.compare_digest(args[5], PUBLIC_OOB if legacy else selected))
            active = observation["active"]
            observation["gate"].append(
                not legacy and bool(active) and active[-1][0] == item and
                len(observation["native"]) > active[-1][1])
            if fault is not None:
                observation["fault"].append("actual-ordinary-boundary")
                raise fault
            if change_transport:
                mutate()
            return APP.SessionResult(receipt if item == "KEY" else
                                     (SERVICE_BODY if item == READ else "PUBLIC-ACK\n"), 0)
        def interactive(command, responder, timeout):
            if block or kind != "ipv4":
                observation["errors"].append("forbidden-interactive")
                raise AssertionError("PUBLIC unexpected interactive boundary")
            try:
                carrier = shlex.split(command[-1])
                if (command[0] != "ssh" or command[-2] != "cumulus@192.0.2.10"
                        or len(carrier) != 3 or carrier[:2] != ["sh", "-c"]
                        or not carrier[2].startswith(SAFE_PATH) or timeout != 45):
                    raise ValueError("PUBLIC IPv4 outer carrier")
                nested = shlex.split(carrier[2][len(SAFE_PATH):])
                expected = ["ip", "vrf", "exec", "default", "ssh",
                            "-o", "ConnectTimeout=2", "-o", "StrictHostKeyChecking=accept-new",
                            "-o", "LogLevel=ERROR", "admin@203.0.113.2", "true"]
                if nested != expected or responder.allow_password_change is not False:
                    raise ValueError("PUBLIC IPv4 inner carrier")
                if legacy:
                    role_ok = (hmac.compare_digest(responder.ethernet_password, PUBLIC_OOB)
                               and hmac.compare_digest(responder.ib_default_password, PUBLIC_OOB))
                else:
                    outer = responder("cumulus@192.0.2.10's password: ")
                    inner = responder("admin@203.0.113.2's password: ")
                    role_ok = (type(outer) is str and hmac.compare_digest(outer, PUBLIC_OOB)
                               and type(inner) is str and hmac.compare_digest(inner, selected))
                observation["calls"].append("IPV4")
                observation["roles"].append(role_ok)
                observation["gate"].append(not legacy and bool(observation["native"]))
                if fault is not None:
                    observation["fault"].append("actual-ipv4-boundary")
                    raise fault
                if change_transport:
                    mutate()
                return APP.SessionResult("", 0)
            except (ValueError, IndexError, TypeError):
                observation["errors"].append("ipv4-carrier")
                raise AssertionError("PUBLIC IPv4 adapter rejected the carrier") from None
        def possession(*args, **kwargs):
            observation["possession"].append("actual-possession-opportunity")
        def getpass(*args, **kwargs):
            observation["prompts"].append("unexpected")
            raise AssertionError("PUBLIC unexpected target prompt")
        def terminal(prompt):
            observation["consent"].append("actual-confirm-input")
            return consent
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(APP, "verify_password_hash", side_effect=verify))
            stack.enter_context(mock.patch.object(APP.ProjectPasswordPolicy, "password", new=password))
            stack.enter_context(mock.patch.object(APP, "_run_authorized_ib_command", new=helper))
            stack.enter_context(mock.patch.object(APP, "run_on_ib", side_effect=dispatch))
            stack.enter_context(mock.patch.object(APP, "interactive_run", side_effect=interactive))
            stack.enter_context(mock.patch.object(APP, "verify_management_key_possession", side_effect=possession))
            stack.enter_context(mock.patch.object(APP.getpass, "getpass", side_effect=getpass))
            stack.enter_context(mock.patch("builtins.input", side_effect=terminal))
            yield observation

    def common(self, outcome, observation):
        self.assertEqual([], observation["errors"])
        self.assertEqual([], observation["prompts"])
        self.assertEqual([], observation["active"])
        self.assertTrue(all(observation["roles"]), "outer/current credential roles changed; values suppressed")
        self.private_output(outcome["output"])

    def reached_native(self, observation):
        self.assertTrue(bool(observation["native"]) and all(
            row["target"] and row["IB"] and row["result"] for row in observation["native"]),
            "actual native verifier must use the correct project IB target/setting")
        self.assertTrue(bool(observation["gate"]) and all(observation["gate"]),
                        "each dispatch must have actual fresh project native authority")

    def test_explicit_selected_current_roles_and_key_receipt_consumer(self):
        cases = [(kind, role, UPDATED if role == "initial" else UNCHANGED)
                 for kind in ("service", "key", "ipv4")
                 for role in ("initial", "target")]
        cases.append(("key-extra", "initial", EXTRA))
        for label, role, receipt in cases:
            kind = "key" if label == "key-extra" else label
            with self.subTest(kind=label, current=role), tempfile.TemporaryDirectory(prefix="t1-role-") as folder:
                f = self.fixture(folder)
                selected = PUBLIC_INITIAL if role == "initial" else self.kat["PASSWORD"]
                before = self.snapshot(f["path"])
                self.assertTrue(len({PUBLIC_INITIAL, PUBLIC_OOB, self.kat["PASSWORD"]}) == 3,
                                "three roles must differ; values suppressed")
                with self.boundaries(f, kind, selected, receipt=receipt) as observation:
                    outcome = self.capture(lambda: self.invoke(kind, f, selected, f["policy"]))
                self.common(outcome, observation)
                self.reached_native(observation)
                expected = SERVICE_ORDER if kind == "service" else ["KEY" if kind == "key" else "IPV4"]
                self.assertEqual(expected, observation["calls"])
                self.assertEqual([] if kind == "ipv4" else expected, observation["helper"])
                self.assertEqual([] if kind == "ipv4" else expected, observation["success"])
                self.assertEqual([], observation["consent"])
                self.assertTrue(before == self.snapshot(f["path"]), "authority identity/bytes changed")
                if label == "key-extra":
                    self.assertTrue(type(outcome["error"]) is APP.SetupError and not outcome["normal"],
                                    "successful real helper with extra line must reach consumer refusal")
                    self.assertTrue(not observation["helper_errors"],
                                    "receipt fault must not be an earlier helper denial; diagnostic material suppressed")
                    self.assertEqual([], observation["possession"])
                    self.assertTrue("已验证" not in outcome["output"] and "已写入" not in outcome["output"],
                                    "rejected receipt cannot produce key success")
                else:
                    self.assertTrue(outcome["normal"] and outcome["error"] is None,
                                    "qualified explicit role path did not return normally")
                    expected_result = (True, False) if kind == "service" else (True if kind == "key" else None)
                    self.assertTrue(outcome["value"] == expected_result,
                                    "consumer returned an unexpected public result")
                    self.assertEqual(["actual-possession-opportunity"] if kind == "key" else [],
                                     observation["possession"])

    def test_noop_checkonly_refusal_and_empty_key_do_not_acquire_target(self):
        cases = (
            ("service", "satisfied", True, True, SERVICE_BODY, None, (True, True), 0),
            ("service", "check-only", False, True, BASE, None, (True, False), 0),
            ("service", "refused", True, False, BASE, None, (False, True), 1),
            ("key", "empty", True, True, BASE, [], True, 0),
            ("key", "check-only", False, True, BASE, None, True, 0),
            ("key", "refused", True, False, BASE, None, False, 1),
        )
        for kind, label, apply, authorized, body, keys, expected, consent_count in cases:
            with self.subTest(kind=kind, case=label), tempfile.TemporaryDirectory(prefix="t1-nowrite-") as folder:
                f = self.fixture(folder, block_birth=True)
                before = self.snapshot(f["path"])
                with self.boundaries(f, kind, PUBLIC_INITIAL, block=True) as observation:
                    outcome = self.capture(lambda: self.invoke(
                        kind, f, PUBLIC_INITIAL, f["policy"], apply=apply,
                        authorized=authorized, service_body=body, keys=keys))
                self.common(outcome, observation)
                self.assertTrue(outcome["normal"] and outcome["error"] is None,
                                "no-write path unexpectedly failed")
                self.assertTrue(outcome["value"] == expected, "no-write public return changed")
                for name in ("native", "fetch", "calls", "helper", "possession"):
                    self.assertEqual([], observation[name], "no-write path acquired target or dispatched")
                self.assertEqual(consent_count, len(observation["consent"]))
                self.assertTrue(before == self.snapshot(f["path"]), "no-write path changed authority")

    def test_mixed_or_invalid_context_cannot_use_the_legacy_fallback(self):
        cases = [(kind, mode) for kind in ("service", "key", "ipv4")
                 for mode in ("current-only", "policy-only")]
        cases += [("ipv4", "wrong-account"), ("ipv4", "non-string-current")]
        for kind, mode in cases:
            with self.subTest(kind=kind, case=mode), tempfile.TemporaryDirectory(prefix="t1-context-") as folder:
                f = self.fixture(folder, block_birth=True)
                current, policy, user = PUBLIC_INITIAL, f["policy"], "admin"
                if mode == "current-only":
                    policy = None
                elif mode == "policy-only":
                    current = None
                elif mode == "wrong-account":
                    user = "otheradmin"
                elif mode == "non-string-current":
                    current = 123
                before = self.snapshot(f["path"])
                with self.boundaries(f, kind, PUBLIC_INITIAL, block=True) as observation:
                    outcome = self.capture(lambda: self.invoke(kind, f, current, policy, user=user))
                self.common(outcome, observation)
                self.assertTrue(type(outcome["error"]) is APP.SetupError and not outcome["normal"],
                                "invalid context must safely HOLD before any fallback")
                self.assertTrue(outcome["error"].__cause__ is None and outcome["error"].__context__ is None,
                                "context denial retained an error chain")
                for name in ("native", "fetch", "calls", "possession", "consent"):
                    self.assertEqual([], observation[name], "invalid context reached a forbidden boundary")
                self.assertTrue(before == self.snapshot(f["path"]), "context denial changed authority")

    def test_changed_global_after_reached_prefix_stops_writes_or_readback(self):
        cases = (
            ("service", "after-dns", DNS, False, [DNS]),
            ("service", "after-save", SAVE, False, [DNS, NTP, TZ, APPLY, SAVE]),
            ("key", "installer-return", None, True, ["KEY"]),
            ("ipv4", "interactive-return", None, True, ["IPV4"]),
        )
        for kind, label, helper_cut, transport_cut, expected in cases:
            with self.subTest(kind=kind, case=label), tempfile.TemporaryDirectory(prefix="t1-change-") as folder:
                f = self.fixture(folder)
                with self.boundaries(f, kind, PUBLIC_INITIAL, change_helper=helper_cut,
                                     change_transport=transport_cut) as observation:
                    outcome = self.capture(lambda: self.invoke(kind, f, PUBLIC_INITIAL, f["policy"]))
                self.common(outcome, observation)
                self.assertEqual(1, len(observation["mutation"]), "actual PUBLIC perturbation not reached")
                self.assertTrue(type(outcome["error"]) is APP.SetupError and not outcome["normal"],
                                "changed project must prevent a success return")
                self.assertEqual(expected, observation["calls"], "next write/readback crossed changed authority")
                self.reached_native(observation)
                self.assertEqual(observation["mutation"][0][0], len(observation["native"]),
                                 "changed binding must stop before another native operation")
                self.assertTrue(observation["mutation"][0][1] == self.snapshot(f["path"]),
                                "refusal changed perturbed global full identity/bytes")
                if kind == "service":
                    self.assertEqual(expected, observation["success"],
                                     "already-reached real helper prefix may not be hidden or rolled back")
                    self.assertTrue("Services SUCCESS:" not in outcome["output"])
                else:
                    self.assertEqual([], observation["possession"])
                    self.assertTrue("已验证" not in outcome["output"] and "已写入" not in outcome["output"])

    def test_known_error_sanitization_and_program_error_identity_are_distinct(self):
        cases = (
            ("service", "known", None), ("key", "known", None), ("ipv4", "known", None),
            ("service", "program", RuntimeError), ("key", "program", AssertionError),
            ("ipv4", "program", RuntimeError),
        )
        for kind, mode, error_type in cases:
            with self.subTest(kind=kind, error=mode), tempfile.TemporaryDirectory(prefix="t1-error-") as folder:
                f = self.fixture(folder)
                before = self.snapshot(f["path"])
                fault = OSError(13, "PUBLIC-T1-IO-FAULT") if mode == "known" else error_type("PUBLIC-T1-PROGRAM-FAULT")
                if mode == "known":
                    fault.cleanup_uncertain = True
                    fault.__cause__ = RuntimeError("PUBLIC-T1-CAUSE")
                    fault.__context__ = RuntimeError("PUBLIC-T1-CONTEXT")
                original_args = fault.args
                with self.boundaries(f, kind, PUBLIC_INITIAL, fault=fault) as observation:
                    outcome = self.capture(lambda: self.invoke(kind, f, PUBLIC_INITIAL, f["policy"]))
                self.common(outcome, observation)
                self.reached_native(observation)
                self.assertEqual(["IPV4" if kind == "ipv4" else "KEY" if kind == "key" else DNS],
                                 observation["calls"], "fault must follow the first real dispatch")
                self.assertEqual(["actual-ipv4-boundary" if kind == "ipv4" else "actual-ordinary-boundary"],
                                 observation["fault"])
                self.assertTrue(not outcome["normal"], "fault returned normal success")
                self.assertEqual([], observation["possession"])
                self.assertTrue(fault.args == original_args, "normalization changed the original fault")
                if mode == "known":
                    caught = outcome["error"]
                    self.assertTrue(type(caught) is APP.SetupError and caught is not fault,
                                    "known IO must become the fixed safe domain error")
                    self.assertTrue(caught.args == SAFE_ARGS and caught.__cause__ is None and caught.__context__ is None,
                                    "safe error literal/chain contract violated")
                    self.assertTrue(getattr(caught, "cleanup_uncertain", None) is True and
                                    type(getattr(caught, "io_errno", None)) is int and caught.io_errno == 13 and
                                    set(caught.__dict__) == {"cleanup_uncertain", "io_errno"},
                                    "only independently approved safe facts may survive")
                    if kind != "ipv4":
                        self.assertTrue(len(observation["helper_errors"]) == 1 and
                                        caught is observation["helper_errors"][0],
                                        "consumer must propagate its real helper's safe error")
                    self.assertTrue("PUBLIC-T1-IO-FAULT" not in outcome["output"])
                else:
                    self.assertTrue(outcome["error"] is fault,
                                    "program error must retain original identity, not business HOLD")
                self.assertTrue(before == self.snapshot(f["path"]), "fault changed authority")
                self.assertTrue("Services SUCCESS:" not in outcome["output"] and
                                "已验证" not in outcome["output"] and "已写入" not in outcome["output"])

    def test_both_none_uses_actual_legacy_delegation_without_new_policy(self):
        for kind in ("service", "key", "ipv4"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="t1-legacy-") as folder:
                f = self.fixture(folder, block_birth=True)
                before = self.snapshot(f["path"])
                with self.boundaries(f, kind, PUBLIC_OOB, legacy=True) as observation:
                    outcome = self.capture(lambda: self.invoke(kind, f, None, None))
                self.common(outcome, observation)
                self.assertTrue(outcome["normal"] and outcome["error"] is None,
                                "actual legacy delegation changed")
                expected = SERVICE_ORDER if kind == "service" else ["KEY" if kind == "key" else "IPV4"]
                self.assertEqual(expected, observation["calls"])
                self.assertEqual([], observation["helper"], "legacy branch unexpectedly used new helper")
                self.assertEqual([], observation["native"])
                self.assertEqual([], observation["fetch"])
                self.assertEqual([], observation["consent"])
                self.assertEqual(["actual-possession-opportunity"] if kind == "key" else [],
                                 observation["possession"])
                self.assertTrue(before == self.snapshot(f["path"]), "legacy path changed authority")
                # This direct MODEL checks original delegation only. Independent
                # old-None source specialization and old suites remain required.

    def test_explicit_apply_and_authorized_require_exact_boolean_values(self):
        cases = (
            ("service", "apply-string", "yes", True),
            ("service", "authorized-int", True, 1),
            ("key", "apply-string", "yes", True),
            ("key", "authorized-int", True, 1),
        )
        for kind, label, apply, authorized in cases:
            with self.subTest(kind=kind, flag=label), tempfile.TemporaryDirectory(prefix="t1-flags-") as folder:
                f = self.fixture(folder, block_birth=True)
                before = self.snapshot(f["path"])
                with self.boundaries(f, kind, PUBLIC_INITIAL, block=True) as observation:
                    outcome = self.capture(lambda: self.invoke(
                        kind, f, PUBLIC_INITIAL, f["policy"],
                        apply=apply, authorized=authorized))
                self.common(outcome, observation)
                caught = outcome["error"]
                self.assertTrue(type(caught) is APP.SetupError and not outcome["normal"],
                                "non-boolean explicit authorization must safely HOLD")
                self.assertTrue(caught.args == SAFE_ARGS and caught.__cause__ is None
                                and caught.__context__ is None,
                                "explicit authorization denial literal/chain contract violated")
                for name in ("fetch", "native", "calls", "possession", "consent"):
                    self.assertEqual([], observation[name],
                                     "invalid explicit flags reached acquisition or dispatch")
                self.assertTrue(before == self.snapshot(f["path"]),
                                "invalid explicit flags changed authority identity/bytes")


if __name__ == "__main__":
    unittest.main()
