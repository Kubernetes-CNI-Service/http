"""Independent present-global manual MAIN caller contracts; O tests-first.

Real canonical C2/P1/MAIN/selector/stages/PTY/frame/parser/shell. Only the
owned remote host and consent terminal are MODELS. No missing-global/offline,
AUTO/local grant, target atomic lock, runtime or full-proof claim.
"""
from __future__ import annotations
import ast
from contextlib import ExitStack
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_target_credentials_workflow as base

APP_NAMES = ("run_initial_stage", "_management_network_commands",
             "_verify_management_network_state", "_authenticate_ib_read")
READ = ["nv", "config", "show", "-o", "commands"]
DIFF = ["nv", "config", "diff", "-o", "commands"]
AUTO = ["nv", "set", "system", "config", "auto-save", "state", "enabled"]
ZTP = ["nv", "set", "system", "ztp", "config-save", "enabled"]
ADDRESS = ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"]
APPLY = ["nv", "config", "apply", "-y"]
SAVE = ["nv", "config", "save"]
SERVICE = [
 ["nv","set","system","dns","server","203.0.113.53"],
 ["nv","set","system","ntp","server","ntp.ubuntu.com"],
 ["nv","set","system","ntp","server","time.ib.example.test"],
 ["nv","set","system","date-time","timezone","Asia/Taipei"],
]
PUBLIC_BASE = "nv set system hostname nvos\nnv set service lldp state enabled\n"
PUBLIC_READY = (
 "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
 "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
 "nv set interface eth0-1 link state up\n"
 "nv set interface eth0-1 type eth\n"
 "nv set system hostname EXAMPLE-IB01\n")
PUBLIC_INITIAL_ROWS = (
 "nv set system config auto-save state enabled\n"
 "nv set system ztp config-save enabled\n")
PUBLIC_SERVICES = (
 "nv set system dns server 203.0.113.53\n"
 "nv set system ntp server ntp.ubuntu.com\n"
 "nv set system ntp server time.ib.example.test\n"
 "nv set system date-time timezone Asia/Taipei\n")

# Append an independently specified remote-host behavior layer to the inherited
# actual SSH executable. It is not a product hook and never opens a network.
PEER_EXTENSION = r'''
_base_business = business
_base_show_state = show_state
def readonly_expiry_cancel():
    import signal
    received = []
    def cancelled(number, frame):
        received.append(number)
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, cancelled)
    signal.signal(signal.SIGTERM, cancelled)
    try:
        # Handlers are installed BEFORE the notice is observable. Product
        # cancellation may be SIGTERM, not a literal Ctrl-C PTY write.
        emit("\nYour password has expired.\n(current) UNIX password: ")
        record("caller-expiry-ready", operation="auth-probe-readonly")
        select.select([], [], [], 2)
    except KeyboardInterrupt:
        if not received:
            raise
        record("caller-expiry-cancel", operation="auth-probe-readonly",
               sigint=received[-1] == signal.SIGINT,
               sigterm=received[-1] == signal.SIGTERM)
        return 130 if received[-1] == signal.SIGINT else 143
    record("adapter-error", stage="caller-expiry-cancel-timeout",
           exception_type="FixtureTimeout")
    return 86
def show_state(S):
    lines = _base_show_state(S).splitlines()
    lines = [line for line in lines if not line.startswith(
        ("nv set system config auto-save state ", "nv set system ztp config-save "))]
    for key, prefix in (
        ("autosave", "nv set system config auto-save state "),
        ("ztp", "nv set system ztp config-save "),
    ):
        value = S["initial_facts"][key]
        if value != "absent":
            lines.append(prefix + value)
    if C.get("caller_case") == "preflight-bad":
        lines = [line for line in lines if line != "nv set interface eth0-1 ipv4 gateway 203.0.113.1"]
        lines.append("nv set interface eth0-1 ipv4 gateway 203.0.113.254")
    # The conflict appears in the post-Initial readback; the v15 skeleton recomputes the later
    # stages from that one readback (06 D1a-L; v15 :4199-4204), so it is the first such read.
    if C.get("caller_case") == "refresh-conflict" and S.get("post_initial_reads", 0) >= 1:
        lines = [line for line in lines if not line.startswith("nv set interface eth0-1 ipv4 gateway ")]
        lines.append("nv set interface eth0-1 ipv4 gateway 203.0.113.254")
    return "\n".join(lines) + "\n"
def business(command, S):
    if command == ["nv", "config", "show", "-o", "commands"]:
        if S.get("initial_transaction_done"):
            S["post_initial_reads"] = S.get("post_initial_reads", 0) + 1
        body = show_state(S)
        record("caller-show", after_initial=S.get("post_initial_reads", 0),
               conflict=C.get("caller_case") == "refresh-conflict" and S.get("post_initial_reads", 0) >= 1)
        return body, 0
    if command == ["nv", "config", "diff", "-o", "commands"]:
        S["caller_probes"] = S.get("caller_probes", 0) + 1
        mode = C.get("caller_case")
        if mode == "pending-first":
            S["pending"] = [["nv","set","interface","eth0","ipv4","address","203.0.113.2/24"]]
            code = 0
        elif mode == "pending-later" and S["caller_probes"] == 2:
            S["pending"] = [["nv","set","interface","eth0","ipv4","address","203.0.113.2/24"]]
            code = 1
        else:
            code = 1 if S["pending"] else 0
        record("caller-diff", nonempty=bool(S["pending"]), actual_rc=code,
               attempt=S["caller_probes"])
        return ("\n".join(shlex.join(x) for x in S["pending"]) + "\n" if S["pending"] else ""), code
    if command == ["nv", "config", "apply", "-y"]:
        pending = S["pending"]
        expected = []
        if S["initial_facts"]["autosave"] != "enabled":
            expected.append(["nv","set","system","config","auto-save","state","enabled"])
        if S["initial_facts"]["ztp"] != "enabled":
            expected.append(["nv","set","system","ztp","config-save","enabled"])
        # The modeled NVOS also commits the v15 Initial transaction, which sets both values
        # even when one is already enabled (P3c map 2.3 :118, D32d :284; R3, 04 Q-039).
        if expected and pending in (expected, INITIAL):
            S["initial_facts"] = {"autosave":"enabled","ztp":"enabled"}
            S["initial"] = True
            S["initial_transaction_done"] = True
            S["post_initial_reads"] = 0
            S["pending"] = []
            record("apply-y")
            return "", 0
    return _base_business(command, S)
'''
# The insertion is before run(), not after the module's real SystemExit.
def peer_program():
    marker = "def run():\n"
    if base.SSH_PROGRAM.count(marker) != 1:
        raise RuntimeError("FIXTURE HOLD: inherited owned SSH boundary changed")
    program = base.SSH_PROGRAM.replace(marker, PEER_EXTENSION + "\n" + marker, 1)
    expiry = '        if not S["changed"] and C["expiry"]:\n'
    if program.count(expiry) != 1:
        raise RuntimeError("FIXTURE HOLD: inherited expiry boundary changed")
    program = program.replace(expiry,
        '        if (C.get("caller_case") == "readonly-expiry" and phase_nonce\n'
        '                and operation == "auth-probe-readonly"):\n'
        '            return readonly_expiry_cancel()\n' + expiry, 1)
    refusal = '        emit("\\n"+errors[C["scenario"]]);record("non-auth-refusal",reason=C["scenario"],operation=operation)\n'
    if program.count(refusal) != 1:
        raise RuntimeError("FIXTURE HOLD: inherited refusal boundary changed")
    return program.replace(refusal,
        '        record("non-auth-refusal",reason=C["scenario"],operation=operation);emit("\\n"+errors[C["scenario"]])\n', 1)


class MainCallerPrecommitDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No subject calls here beyond the inherited real KAT/C2 qualification.
        # Root must bind the current source/fixture closure before issuance.
        base.InitialTargetCredentialsMainAutoWorkflowDraftTests.setUpClass.__func__(cls)
        source = base.bound_file(base.INITIAL)[1]
        tree = ast.parse(source, filename=str(base.INITIAL))
        defs = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        if any(name not in defs for name in APP_NAMES):
            raise RuntimeError("FIXTURE HOLD: caller dependency API absent")
        for name in ("run_service_stage", "run_key_stage", "verify_ipv4_login"):
            if name not in defs:
                raise RuntimeError("FIXTURE HOLD: consumer API absent")
            args = defs[name].args
            defaults = dict(zip((arg.arg for arg in args.kwonlyargs), args.kw_defaults))
            if not all(key in defaults and isinstance(defaults[key], ast.Constant)
                       and defaults[key].value is None
                       for key in ("_ib_current_password", "_password_policy")):
                raise RuntimeError("FIXTURE HOLD: explicit consumer context NOT_READY")

    def fixed_hold(self):
        error = RuntimeError("FIXTURE HOLD: MAIN caller prerequisite unavailable")
        try:
            raise error from None
        finally:
            error.__cause__ = None
            error.__context__ = None

    def fixture(self, folder, *, case, facts=("enabled", "enabled"),
                network=True, services=True, credential="initial", scenario="normal"):
        born = None
        f = None
        try:
            f = base.InitialTargetCredentialsMainAutoWorkflowDraftTests.fixture(
                self, folder, scenario=scenario, expiry=False, configured=True)
        except BaseException as error:
            born = error
        if born is not None:
            self.fixed_hold()
        f["stub"].write_text(peer_program(), encoding="utf-8")
        f["stub"].chmod(0o600)
        state = json.loads(f["state"].read_text())
        state.update(initial=facts == ("enabled", "enabled"), network=network,
                     services=services, credential=credential, changed=True,
                     pending=[], initial_facts=dict(zip(("autosave", "ztp"), facts)))
        f["state"].write_text(json.dumps(state), encoding="ascii")
        config = json.loads(f["config"].read_text())
        config["caller_case"] = case
        if case == "readonly-expiry":
            config["expiry"] = True
            state["changed"] = False
            f["state"].write_text(json.dumps(state), encoding="ascii")
        f["config"].write_text(json.dumps(config), encoding="utf-8")
        f["config"].chmod(0o600)
        f["caller"] = dict(consent=[], stage=[], classifier=[], returned_diff=[], diff_entry=[], timeline=[],
                           selector=[], network_constructor=[], helper=[], helper_reads=[], calls=[], native=[], fetch=[], gate=[],
                           slots=[], reaps=[], fixture_reaps=[], product_depth=0)
        return f

    # Unbound original safe boundary/fixture helpers only. No imported TestCase
    # inheritance/discovery and no original test or assertion is rewritten.
    def events(self, f):
        events = base.InitialTargetCredentialsMainAutoWorkflowDraftTests.events(self, f)
        if (json.loads(f["config"].read_text()).get("caller_case") == "readonly-expiry"
                and any(event.get("kind") == "adapter-error"
                        and event.get("stage") == "caller-expiry-cancel-timeout"
                        for event in events)):
            # New-case premise classification before the unchanged inherited
            # adapter assertions. Never label missing normal cancellation PASS.
            self.fixed_hold()
        return events
    assert_no_new_writes = base.InitialTargetCredentialsMainAutoWorkflowDraftTests.assert_no_new_writes

    def invoke(self, f, *options, **kwargs):
        app, witness = f["app"], f["caller"]
        real_initial = app.run_initial_stage
        real_classify = app._validate_owned_pending
        real_ib = app.run_on_ib
        real_helper = app._run_authorized_ib_command
        real_select = app._authenticate_ib_read
        real_confirm = app.confirm_first_device_change
        real_network = app._management_network_commands
        real_verify = app.verify_password_hash
        real_password = app.ProjectPasswordPolicy.password
        real_fork, real_waitpid = app.pty.fork, os.waitpid
        real_interactive = app.interactive_run
        def fork():
            pair = real_fork()
            if pair[0] > 0:
                witness["slots"].append(pair[0])
            return pair
        def waitpid(pid, flags):
            pair = real_waitpid(pid, flags)
            if pid in witness["slots"] and pair[0] == pid:
                key = "reaps" if witness["product_depth"] else "fixture_reaps"
                witness[key].append((pid, os.waitstatus_to_exitcode(pair[1])))
            return pair
        def interactive(*args, **kw):
            witness["product_depth"] += 1
            try:
                return real_interactive(*args, **kw)
            finally:
                witness["product_depth"] -= 1
        def initial(*args, **kw):
            result = real_initial(*args, **kw)
            witness["stage"].append(result)
            return result
        def classify(device, output):
            result = real_classify(device, output)
            witness["classifier"].append(dict(count=result,
                owned_address=output == "nv set interface eth0 ipv4 address 203.0.113.2/24\n"))
            return result
        def ib(*args, **kw):
            bound = inspect.signature(real_ib).bind(*args, **kw).arguments
            command = bound["ib_command"]
            if command[:2] == ["nv", "set"]:
                witness["timeline"].append("setter-entry")
            if command == DIFF:
                witness["timeline"].append("diff-entry")
                witness["diff_entry"].append(dict(
                    initial=hmac.compare_digest(bound["ib_default_password"], base.PUBLIC_INITIAL),
                    target=hmac.compare_digest(bound["ib_default_password"], self.kat["PASSWORD"]),
                    native=len(witness["native"]), fetch=len(witness["fetch"])))
            result = real_ib(*args, **kw)
            if command == DIFF:
                witness["timeline"].append("diff-return")
                witness["returned_diff"].append(dict(
                    rc=result.exit_code, empty=result.output == "",
                    owned_address=result.output == "nv set interface eth0 ipv4 address 203.0.113.2/24\n",
                    initial=hmac.compare_digest(bound["ib_default_password"], base.PUBLIC_INITIAL),
                    target=hmac.compare_digest(bound["ib_default_password"], self.kat["PASSWORD"]),
                    phase=kw.get("_phase_operation"), pam=kw.get("allow_password_change", False),
                    new_password=kw.get("ib_new_password") is not None,
                    native=len(witness["native"]), fetch=len(witness["fetch"])))
            witness["calls"].append(tuple(command) if command[:2] != ["sh","-c"] else ("KEY-SHELL",))
            return result
        def helper(*args, **kw):
            command = inspect.signature(real_helper).bind(*args, **kw).arguments["ib_command"]
            before = len(witness["native"])
            result = real_helper(*args, **kw)
            witness["helper"].append(tuple(command) if command[:2] != ["sh","-c"] else ("KEY-SHELL",))
            witness["gate"].append(len(witness["native"]) > before)
            if command == READ:
                witness["helper_reads"].append(dict(
                    initial_pair=all(row in result.output.splitlines() for row in PUBLIC_INITIAL_ROWS.splitlines()),
                    conflict="nv set interface eth0-1 ipv4 gateway 203.0.113.254" in result.output.splitlines()))
            return result
        def select(*args, **kw):
            result = real_select(*args, **kw)
            witness["timeline"].append("selector-return")
            witness["selector"].append(dict(
                initial=hmac.compare_digest(result.current_password, base.PUBLIC_INITIAL),
                target=hmac.compare_digest(result.current_password, self.kat["PASSWORD"]),
                required=result.read_result.password_change_required is True,
                native=len(witness["native"]), fetch=len(witness["fetch"]),
                bad_gateway=("nv set interface eth0-1 ipv4 gateway 203.0.113.254" in result.read_result.output.splitlines()
                             and "nv set interface eth0-1 ipv4 gateway 203.0.113.1" not in result.read_result.output.splitlines())))
            return result
        def confirm(*args, **kw):
            result = real_confirm(*args, **kw)
            if result is True:
                witness["timeline"].append("consent-granted")
            return result
        def network(device, current):
            rows = current.splitlines()
            fact = dict(bad_gateway="nv set interface eth0-1 ipv4 gateway 203.0.113.254" in rows
                        and "nv set interface eth0-1 ipv4 gateway 203.0.113.1" not in rows,
                        domain_rejected=False, returned=False)
            witness["network_constructor"].append(fact)
            try:
                result = real_network(device, current)
            except BaseException as error:
                fact["domain_rejected"] = type(error) is app.SetupError
                raise
            fact["returned"] = True
            return result
        def verify(password, setting):
            result = real_verify(password, setting)
            witness["native"].append(dict(target=hmac.compare_digest(password, self.kat["PASSWORD"]),
                                           IB=hmac.compare_digest(setting, self.kat["YESCRYPT"]),
                                           matched=result is True))
            return result
        def password(policy):
            witness["fetch"].append("actual-policy-fetch")
            return real_password(policy)
        def answer(prompt):
            # Only actual product consent reaches this terminal model. Input
            # text itself is not logged; an unknown prompt is fixture HOLD.
            if not prompt.startswith("Authorize this change and subsequent eligible IB devices?"):
                self.fixed_hold()
            witness["consent"].append("actual-consent")
            return "no" if f["case"] == "decline" else "yes"
        f["case"] = json.loads(f["config"].read_text())["caller_case"]
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app, "run_initial_stage", new=initial))
            stack.enter_context(mock.patch.object(app, "_validate_owned_pending", new=classify))
            stack.enter_context(mock.patch.object(app, "run_on_ib", new=ib))
            stack.enter_context(mock.patch.object(app, "_run_authorized_ib_command", new=helper))
            stack.enter_context(mock.patch.object(app, "_authenticate_ib_read", new=select))
            stack.enter_context(mock.patch.object(app, "confirm_first_device_change", new=confirm))
            stack.enter_context(mock.patch.object(app, "_management_network_commands", new=network))
            stack.enter_context(mock.patch.object(app, "verify_password_hash", new=verify))
            stack.enter_context(mock.patch.object(app.ProjectPasswordPolicy, "password", new=password))
            stack.enter_context(mock.patch.object(app.pty, "fork", new=fork))
            stack.enter_context(mock.patch.object(app.os, "waitpid", new=waitpid))
            stack.enter_context(mock.patch.object(app, "interactive_run", new=interactive))
            stack.enter_context(mock.patch("builtins.input", new=answer))
            return base.InitialTargetCredentialsMainAutoWorkflowDraftTests.invoke(
                self, f, *options, **kwargs)

    def p1(self, f):
        failure = None
        selected = None
        try:
            with mock.patch.object(self.c2, "_GLOBAL_FILE", str(f["global_path"])):
                selected = self.c2.load_global("ib")
        except BaseException as error:
            failure = error
        if failure is not None:
            self.fixed_hold()
        system = selected["system"]
        self.assertEqual(["203.0.113.53"], system["dns"]["server"])
        self.assertEqual(["ntp.ubuntu.com", "time.ib.example.test"], system["ntp"]["server"])
        self.assertEqual("Asia/Taipei", system["date-time"]["timezone"])
        self.assertTrue(hmac.compare_digest(system["aaa"]["user"]["admin"]["password"], self.kat["YESCRYPT"]),
                        "real C2 selected project authority mismatch; values suppressed")
        result = self.invoke(f, "--generate-json")
        if result["error"] is not None or result["rc"] != 0:
            self.fixed_hold()
        cache = json.loads(f["cache"].read_text())
        # Table 6-1 row 6 (guide :749): v15 CURRENT-CONTRACT.md:20 "cache version 5".
        self.assertEqual(5, cache["version"])
        self.assertTrue(self.kat["PASSWORD"] not in f["cache"].read_text(),
                        "P1 cache exposed target; value suppressed")
        f["caller"] = dict(consent=[], stage=[], classifier=[], returned_diff=[], diff_entry=[], timeline=[],
                           selector=[], network_constructor=[], helper=[], helper_reads=[], calls=[], native=[], fetch=[], gate=[],
                           slots=[], reaps=[], fixture_reaps=[], product_depth=0)

    def run_case(self, folder, **scene):
        check = scene["case"] in ("readonly-initial", "readonly-target", "readonly-expiry", "readonly-network")
        if not check:
            # Owner Q-035 (a), guide :438 (v15 inspect_ib_device; P3c map 4.5 P1): an --apply run
            # needs the device's current password to equal the project target, so the modeled
            # device of an --apply scene already uses the target (fixture, not an expectation).
            scene.setdefault("credential", "target")
        f = self.fixture(folder, **scene)
        self.p1(f)
        before = len(self.events(f))
        result = self.invoke(f, *([] if check else ["--apply"]))
        fresh = self.events(f)[before:]
        # The inherited invoke already checks secret-free output/events; this
        # additional result check never reprs private error objects.
        self.assertTrue(all(secret not in result["stdout"] + result["stderr"] for secret in
                            (self.kat["PASSWORD"], self.kat["SHA512"], self.kat["YESCRYPT"],
                             base.PUBLIC_INITIAL, base.PUBLIC_OOB)),
                        "MAIN diagnostic privacy failed; values suppressed")
        self.assertEqual([], f["boundary_errors"], "external boundary prerequisite failure")
        return f, result, fresh

    def writes(self, events):
        return [event for event in events if event["kind"] in
                ("mutation", "apply-y", "save", "key-shell", "ipv4-read", "pam-target")]

    def diffs(self, events):
        return [event for event in events if event["kind"] == "caller-diff"]

    def assert_success(self, result):
        self.assertTrue(result["error"] is None and result["rc"] == 0,
                        "qualified real MAIN did not complete; private error suppressed")

    def assert_hold(self, result):
        self.assertTrue(result["error"] is not None or result["rc"] != 0,
                        "unsafe caller branch returned normal success")

    def assert_no_later(self, events):
        self.assertTrue(not any(event["kind"] in ("key-shell", "ipv4-read") for event in events))
        self.assertTrue(not any(event.get("command") in SERVICE for event in events))

    def test_actual_initial_prestate_and_single_consent(self):
        scenes = (
            dict(case="present-noop", facts=("enabled","enabled"), network=True, services=False),
            dict(case="decline", facts=("absent","absent"), network=False, services=False),
            dict(case="disabled-accept", facts=("disabled","enabled"), network=True, services=True),
        )
        for scene in scenes:
            with self.subTest(case=scene["case"]), tempfile.TemporaryDirectory(prefix="caller-flags-") as folder:
                f, result, events = self.run_case(folder, **scene)
                w = f["caller"]
                self.assertEqual(["actual-consent"], w["consent"])
                if scene["case"] == "decline":
                    self.assertEqual([], self.writes(events))
                    self.assertEqual([], self.diffs(events))
                    # Owner Q-035 (a) item 4 (04 Q-035; P3c map D32d :284): with --apply the
                    # current IB password must equal the project target, so the target is fetched
                    # and natively verified at authentication, before the declined consent.
                    self.assertTrue(bool(w["fetch"]) and bool(w["native"])
                                    and all(row["IB"] and row["target"] for row in w["native"]))
                    # Owner Q-035 (a) item 1: the strict Initial stage reads ZTP through the
                    # authorized helper before asking; nothing else reaches the helper.
                    self.assertEqual([("nv", "show", "system", "ztp")], w["helper"])
                    self.assertFalse(any(event["kind"] == "caller-show" and event["after_initial"] for event in events))
                else:
                    self.assert_success(result)
                    self.assertTrue(bool(w["native"]) and all(row["IB"] for row in w["native"]))
                    self.assertTrue(bool(w["gate"]) and all(w["gate"]))
                    if scene["case"] == "present-noop":
                        # P3c map D32d :284 (E10, 04 Q-039; 06 D1a-B): the v15 stage skeleton asks
                        # for consent at the first write stage, after its empty-pending probe (T15).
                        self.assertEqual(["selector-return", "diff-entry", "diff-return", "consent-granted"]
                                         + ["setter-entry"] * 4, w["timeline"],
                                         "actual consent and probe return must precede Services setters")
                        self.assertTrue(not any(event.get("command") in (AUTO,ZTP) for event in events))
                        self.assertTrue(not any(event["kind"] == "caller-show" and event["after_initial"] for event in events))
                        self.assertTrue(any(event.get("command") in SERVICE for event in events))
                        self.assertEqual(1, len(self.diffs(events)))
                    else:
                        mutations = [event["command"] for event in events if event["kind"] == "mutation"]
                        # P3c map 2.3 :118, D32d :284 (R3, 04 Q-039; 06 D1a-B): the v15 Initial
                        # transaction writes both settings (D1a2 report 4.3 R3).
                        self.assertEqual([AUTO, ZTP], mutations)
                        self.assertEqual(1, sum(event["kind"] == "apply-y" for event in events))
                        self.assertEqual(1, sum(event["kind"] == "save" for event in events))
                        # 06 D1a-L (guide :487; v15 :4199-4204): Initial returns its one readback
                        # and the later stages are recomputed from it, so there is one
                        # post-Initial read and run_initial_stage returns (readback, authorized).
                        self.assertEqual([1], [event["after_initial"] for event in events
                                              if event["kind"] == "caller-show" and event["after_initial"]])
                        self.assertTrue(any(type(body) is str and authorized is True
                                            and all(row in body.splitlines()
                                                    for row in PUBLIC_INITIAL_ROWS.splitlines())
                                            for body, authorized in w["stage"]))
                        self.assertEqual([dict(initial_pair=True, conflict=False)],
                                         w["helper_reads"], "the real authorized readback must return")
                        self.assertEqual(1, len(self.diffs(events)))

    def test_pending_owner_classification_is_not_commit_authority(self):
        scenes = (
            dict(case="pending-first", facts=("absent","absent"), network=False, services=True),
            dict(case="pending-later", facts=("absent","absent"), network=False, services=True),
            dict(case="KEY-only", facts=("enabled","enabled"), network=True, services=True),
        )
        for scene in scenes:
            with self.subTest(case=scene["case"]), tempfile.TemporaryDirectory(prefix="caller-pending-") as folder:
                f, result, events = self.run_case(folder, **scene)
                w = f["caller"]
                if scene["case"] == "KEY-only":
                    self.assert_success(result)
                    self.assertEqual([], self.diffs(events))
                    # Owner Q-035 (a) item 3 (04 Q-035; P3c map D32d :284): every --apply verifies
                    # the IPv4 login after Network, so a KEY-only run reads IPv4 once and still
                    # writes nothing but the keys.
                    self.assertEqual([], [e for e in events if e["kind"] in ("mutation","apply-y","save")])
                    self.assertEqual(1, sum(e["kind"] == "ipv4-read" for e in events))
                    self.assertEqual(1, sum(e["kind"] == "key-shell" for e in events))
                else:
                    self.assert_hold(result)
                    expected = 0 if scene["case"] == "pending-first" else 1
                    self.assertTrue(any(row["count"] == 1 and row["owned_address"] for row in w["classifier"]),
                                    "real owner classifier must actually accept owned pending")
                    self.assertTrue(any(row["rc"] == expected and row["owned_address"] for row in w["returned_diff"]),
                                    "real run_on_ib must return the correct owned frame/status before caller HOLD")
                    self.assertEqual(1 if expected == 0 else 2, len(self.diffs(events)))
                    self.assertEqual(0 if expected == 0 else 1,
                                     sum(e["kind"] == "apply-y" for e in events))
                    self.assert_no_later(events)
                    state = json.loads(f["state"].read_text())
                    self.assertEqual([ADDRESS], state["pending"], "no clear/adopt/commit of existing pending")
                    self.assertEqual([], [e for e in events if e.get("command") not in (AUTO,ZTP)
                                         and e["kind"] == "mutation"])
                    if expected == 0:
                        # Owner Q-035 (a) item 4: with --apply the current password must equal
                        # the project target, so the target is fetched and natively verified at
                        # authentication, before the pending refusal.
                        self.assertTrue(bool(w["fetch"]) and bool(w["native"])
                                        and all(row["IB"] and row["target"] for row in w["native"]))

    def test_actual_preflight_and_changed_only_refresh(self):
        scenes = (
            dict(case="preflight-bad", facts=("absent","absent"), network=True, services=True),
            dict(case="refresh-good", facts=("absent","absent"), network=True, services=True),
            dict(case="refresh-conflict", facts=("absent","absent"), network=True, services=True),
        )
        for scene in scenes:
            with self.subTest(case=scene["case"]), tempfile.TemporaryDirectory(prefix="caller-refresh-") as folder:
                f, result, events = self.run_case(folder, **scene)
                w = f["caller"]
                if scene["case"] == "preflight-bad":
                    self.assert_hold(result)
                    # Owner Q-035 (a) item 4: the --apply scene's device already uses the project
                    # target, so the successful selector returns the target, not INITIAL.
                    self.assertTrue(len(w["selector"]) == 1 and w["selector"][0]["target"]
                                    and not w["selector"][0]["required"] and w["selector"][0]["bad_gateway"],
                                    "actual successful selector must return independently wrong gateway body")
                    # Owner Q-035 (a) item 2 (04 Q-035; v15 CURRENT-CONTRACT.md:54): a partial or
                    # conflicting Network is refused before any write, so the Network setter
                    # constructor is never entered and the report names the conflict.
                    self.assertEqual([], w["network_constructor"],
                                     "conflicting Network is refused before the setter constructor")
                    self.assertTrue("conflict" in result["stdout"],
                                    "the refusal must name the Network conflict")
                    self.assertEqual([], self.writes(events))
                    self.assertEqual([], w["helper"])
                    # Owner Q-035 (a) item 4: the target is fetched and natively verified at
                    # authentication, before the refusal.
                    self.assertTrue(bool(w["fetch"]) and bool(w["native"])
                                    and all(row["IB"] and row["target"] for row in w["native"]))
                else:
                    mutations = [e["command"] for e in events if e["kind"] == "mutation"]
                    self.assertEqual([AUTO,ZTP], mutations)
                    self.assertEqual(1, sum(e["kind"] == "apply-y" for e in events))
                    self.assertEqual(1, sum(e["kind"] == "save" for e in events))
                    # 06 D1a-L (guide :487; v15 :4199-4204): Initial returns its one readback,
                    # run_initial_stage returns (readback, authorized) and the later stages are
                    # recomputed from that readback; there is no second refresh read.
                    self.assertEqual([1], [e["after_initial"] for e in events
                                          if e["kind"] == "caller-show" and e["after_initial"]])
                    self.assertTrue(any(type(body) is str and authorized is True
                                        and all(row in body.splitlines()
                                                for row in PUBLIC_INITIAL_ROWS.splitlines())
                                        for body, authorized in w["stage"]))
                    self.assertEqual([dict(initial_pair=True, conflict=scene["case"] == "refresh-conflict")],
                                     w["helper_reads"], "actual helper return must precede caller qualification")
                    self.assertEqual(1, len(self.diffs(events)))
                    if scene["case"] == "refresh-good":
                        self.assert_success(result)
                        # Owner Q-035 (a) item 3: every --apply verifies the IPv4 login once.
                        self.assertEqual(1, sum(e["kind"] == "ipv4-read" for e in events))
                    else:
                        self.assert_hold(result)
                        self.assertTrue(any(e["kind"] == "caller-show" and e["conflict"] for e in events))
                        self.assert_no_later(events)

    def test_apply_with_initial_login_is_refused_before_consent_and_helper(self):
        # 06 WP6-a8 (WP-6 review A wa-4): the --apply scene whose device still logs in with the
        # initial password.  Owner Q-035 (a) item 4 (guide :438; P3c map 4.5 P1 :356): with --apply
        # the current IB password must equal the project target, so this device is stopped (b-5)
        # before the first-change consent and before the authorized helper; a failed device makes
        # the run INCOMPLETE, exit 2 (table 6-1 row 11, guide :754).
        with tempfile.TemporaryDirectory(prefix="caller-initial-apply-") as folder:
            f, result, events = self.run_case(folder, case="initial-apply", facts=("absent", "absent"),
                                              network=False, services=True, credential="initial")
            w = f["caller"]
            self.assertEqual([], w["consent"], "b-5 refuses before the first-change consent")
            self.assertEqual([], w["helper"], "b-5 refuses before the authorized helper")
            self.assertEqual([], self.writes(events))
            self.assertTrue(len(w["selector"]) == 1 and w["selector"][0]["initial"]
                            and not w["selector"][0]["required"],
                            "the read-only authentication selected the initial password")
            self.assertTrue(any(row["IB"] and not row["target"] and not row["matched"] for row in w["native"]),
                            "the initial password is checked against the project target and does not match")
            self.assertTrue(result["error"] is None and result["rc"] == 2,
                            "a device stopped by b-5 makes the run INCOMPLETE (2)")
            self.assertIn("current IB password does not match project global", result["stdout"])

    def test_checkonly_lazy_selected_current_and_actual_diff_report(self):
        scenes = (
            dict(case="readonly-initial", credential="initial"),
            dict(case="readonly-target", credential="target"),
            dict(case="readonly-expiry", credential="initial"),
            dict(case="readonly-network", credential="initial", scenario="network"),
        )
        for scene in scenes:
            with self.subTest(case=scene["case"]), tempfile.TemporaryDirectory(prefix="caller-readonly-") as folder:
                f, result, events = self.run_case(folder, **scene)
                w = f["caller"]
                self.assertEqual([], self.writes(events))
                self.assertEqual([], w["consent"])
                self.assertEqual([], w["helper"], "read-only report must not acquire authorized-write helper")
                inner = [e for e in events if e["kind"] == "inner-answer"]
                total = (3 if scene["case"] == "readonly-target" else
                         2 if scene["case"] == "readonly-initial" else 1)
                self.assertEqual(total, len(inner))
                if scene["case"] in ("readonly-initial","readonly-target"):
                    # Table 6-1 row 11 (guide :754; v15 CURRENT-CONTRACT.md:67): a check-only run that
                    # finds work left (here the public keys to install) ends INCOMPLETE, exit 2.
                    self.assertTrue(result["error"] is None and result["rc"] == 2,
                                    "check-only with remaining work must end INCOMPLETE (2)")
                    # P3c map D32d :284 (E8, 04 Q-039; 06 D1a-B; v15 CURRENT-CONTRACT.md:59): the
                    # v15 check-only reads no pending diff; its one ordinary read after selection
                    # is the ZTP state (Q-035 item 1), counted apart from auth-probe sessions, and it
                    # uses the selected credential.
                    self.assertEqual(0, len(self.diffs(events)))
                    auth = [e for e in inner if e["operation"] == "auth-probe-readonly"]
                    self.assertEqual(2 if scene["case"] == "readonly-target" else 1, len(auth))
                    self.assertEqual([], w["returned_diff"])
                    self.assertEqual([], w["diff_entry"])
                    self.assertEqual(["selector-return"], w["timeline"])
                    expected_role = "target" if scene["case"] == "readonly-target" else "initial"
                    self.assertTrue(len(w["selector"]) == 1 and not w["selector"][0]["required"]
                                    and w["selector"][0][expected_role],
                                    "one actual nonrequired selector result must establish selected CURRENT")
                    reads = [e for e in inner if e["operation"] is None]
                    self.assertTrue(len(reads) == 1 and reads[0]["command"] == ["nv", "show", "system", "ztp"]
                                    and reads[0]["phase"] is False and reads[0][expected_role],
                                    "the ZTP read must use actual selected current, not a desired role")
                    self.assertTrue(w["selector"][0]["native"] == len(w["native"])
                                    and w["selector"][0]["fetch"] == len(w["fetch"]),
                                    "the selected return to the report cannot acquire additional authority")
                    if scene["case"] == "readonly-initial":
                        self.assertEqual([], w["fetch"])
                        self.assertEqual([], w["native"])
                    else:
                        self.assertTrue(bool(w["fetch"]) and bool(w["native"]))
                        self.assertTrue(all(row["IB"] and row["target"] for row in w["native"]))
                else:
                    if scene["case"] == "readonly-expiry":
                        self.assertTrue(len(w["selector"]) == 1 and w["selector"][0]["required"],
                                        "real readonly expiry observation must reach caller")
                        self.assertTrue(any(e["kind"] == "caller-expiry-cancel"
                                            and e["operation"] == "auth-probe-readonly"
                                            and (e["sigint"] or e["sigterm"]) for e in events),
                                        "owned peer must witness actual normal product cancellation")
                        self.assertTrue(bool(w["slots"]) and len(w["slots"]) == len(set(w["slots"]))
                                        and sorted(w["slots"]) == sorted(pid for pid, status in w["reaps"])
                                        and not w["fixture_reaps"] and not any(result["cleanup"]),
                                        "expiry observation requires actual product reap, not fixture drain/uncertainty")
                    else:
                        self.assert_hold(result)
                        self.assertTrue(any(e["kind"] == "non-auth-refusal" and e["reason"] == "network"
                                            and e["operation"] == "auth-probe-readonly" for e in events),
                                        "actual peer network refusal must be reached after authenticated phase")
                        self.assertTrue(len(inner) == 1 and inner[0]["phase"] is True
                                        and inner[0]["operation"] == "auth-probe-readonly"
                                        and inner[0]["initial"] is True and inner[0]["oob"] is False,
                                        "network case must use actual phase-bound INITIAL, not earlier wrong-role rejection")
                    self.assertEqual([], self.diffs(events))
                    self.assertEqual([], w["fetch"])
                    self.assertEqual([], w["native"])
                self.assertFalse(f["credentials"].exists() or f["marker"].exists()
                                 or f["terminal"].exists(),
                                 "check-only may not persist credentials/watch/terminal state")

    def test_admitted_targets_and_declared_project_survive_second_payload_read(self):
        import stat
        from functools import wraps
        # Table 6-1 row 6 (guide :749): a v15 cache-version-5 target record also carries
        # login_interface (v15 CURRENT-CONTRACT.md:20; RUNBOOK.md:22 eth0 entry).
        device_fields = ("hostname", "dev_type", "login_ip", "eth0_prefix",
                         "eth0_gateway", "eth0_mac", "eth1_prefix", "eth1_gateway",
                         "login_interface")
        cases = ("MATCH", "TARGET-MISMATCH", "ALIAS-DISAPPEARS")
        for case in cases:
            with self.subTest(admission=case), tempfile.TemporaryDirectory(prefix="caller-admission-") as folder:
                f = self.fixture(folder, case="readonly-initial")
                self.p1(f)
                app = f["app"]
                alias = f["tool"] / "01-global.yaml"
                checksum = f["cache"].with_name(f["cache"].name + ".sha256")

                def held_regular(path):
                    fd = None
                    failure = False
                    value = None
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        first = base.nine(os.fstat(fd))
                        if (not stat.S_ISREG(first[2]) or first[5] != 1
                                or first[3] != os.getuid() or first[6] > 1048576
                                or base.nine(path.lstat()) != first):
                            failure = True
                        else:
                            copies = []
                            for unused in range(2):
                                os.lseek(fd, 0, os.SEEK_SET)
                                raw = b""
                                while True:
                                    chunk = os.read(fd, min(65536, 1048577 - len(raw)))
                                    if not chunk:
                                        break
                                    raw += chunk
                                    if len(raw) > 1048576:
                                        failure = True
                                        break
                                if (len(raw) != first[6] or base.nine(os.fstat(fd)) != first
                                        or base.nine(path.lstat()) != first):
                                    failure = True
                                copies.append(raw)
                            if len(copies) != 2 or copies[0] != copies[1]:
                                failure = True
                            if not failure:
                                value = (first, copies[0], hashlib.sha256(copies[0]).hexdigest())
                    except (OSError, ValueError):
                        failure = True
                    finally:
                        if fd is not None:
                            try:
                                os.close(fd)
                            except OSError:
                                failure = True
                    if failure or value is None:
                        self.fixed_hold()
                    return value

                def owned_alias():
                    error = None
                    value = None
                    try:
                        root_info = f["root"].lstat()
                        tool_info = f["tool"].lstat()
                        project_info = f["global_path"].parent.lstat()
                        info = alias.lstat()
                        target = os.readlink(alias)
                        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid()
                                or stat.S_IMODE(root_info.st_mode) & 0o077
                                or not stat.S_ISDIR(tool_info.st_mode) or tool_info.st_uid != os.getuid()
                                or not stat.S_ISDIR(project_info.st_mode) or project_info.st_uid != os.getuid()
                                or alias.parent != f["tool"] or alias.name != "01-global.yaml"
                                or not stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid()
                                or info.st_nlink != 1 or target != str(f["global_path"])
                                or alias.resolve(strict=True) != f["global_path"].resolve(strict=True)
                                or base.nine(alias.lstat()) != base.nine(info)):
                            error = True
                        else:
                            value = (base.nine(info), target)
                    except (OSError, ValueError):
                        error = True
                    if error or value is None:
                        self.fixed_hold()
                    return value

                original_alias = owned_alias()
                protected_paths = (f["global_path"], f["csv"], f["p2p"], f["source"],
                                   f["control"], f["auth"],
                                   f["root"] / "infiniband/publickey/laptop.pub",
                                   f["root"] / "infiniband/publickey/mgmt-server.pub")
                protected = [held_regular(path) for path in protected_paths]
                observed = dict(loads=0, successful_loads=0, callback=0,
                                actual_return=None, target_before=None, target_match=None,
                                authority=None, publication=None, alias_absent=False,
                                changed_paths=None, entries=[], premise_failed=False)
                real_load = app.load_target_cache
                real_authority = app._valid_cache_authority

                def target_values(targets):
                    return [dict(ib={key: getattr(item.ib, key) for key in device_fields},
                                 ethernet={key: getattr(item.ethernet, key) for key in device_fields},
                                 ethernet_port=item.ethernet_port,
                                 ib_port_alias=item.ib_port_alias) for item in targets]

                def differences(left, right, path=()):
                    if type(left) is not type(right):
                        return [path]
                    if type(left) is dict:
                        if set(left) != set(right):
                            return [path]
                        return [item for key in left for item in differences(left[key], right[key], path + (key,))]
                    if type(left) is list:
                        if len(left) != len(right):
                            return [path]
                        return [item for pos, (a, b) in enumerate(zip(left, right))
                                for item in differences(a, b, path + (pos,))]
                    return [] if left == right else [path]

                @wraps(real_load)
                def load(*args, **kwargs):
                    observed["loads"] += 1
                    admitted = real_load(*args, **kwargs)
                    if (observed["loads"] != 1 or type(admitted) is not tuple
                            or len(admitted) != 2 or type(admitted[0]) is not int
                            or admitted[0] != 1 or type(admitted[1]) is not list
                            or len(admitted[1]) != 1):
                        observed["premise_failed"] = True
                        self.fixed_hold()
                    observed["successful_loads"] += 1
                    observed["actual_return"] = admitted
                    original = json.loads(held_regular(f["cache"])[1].decode("utf-8"))
                    actual_targets = target_values(admitted[1])
                    if (original.get("ib_candidate_count") != 1
                            or original.get("targets") != actual_targets
                            or actual_targets[0]["ib_port_alias"] != "eth0"
                            or original.get("global") != str(f["global_path"].resolve(strict=True))
                            or original["global"] is None
                            or owned_alias() != original_alias):
                        observed["premise_failed"] = True
                        self.fixed_hold()
                    observed["target_before"] = actual_targets
                    published = json.loads(json.dumps(original))
                    if case == "TARGET-MISMATCH":
                        published["targets"][0]["ib_port_alias"] = "mgmt"
                    delta = differences(original, published)
                    expected_delta = [("targets", 0, "ib_port_alias")] if case == "TARGET-MISMATCH" else []
                    if delta != expected_delta:
                        observed["premise_failed"] = True
                        self.fixed_hold()
                    observed["changed_paths"] = delta
                    body = (json.dumps(published, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                    # Independent data-publication protocol, never a governance
                    # ledger update. Both branches refresh valid checksum.
                    f["cache"].write_bytes(body)
                    checksum.write_text(hashlib.sha256(body).hexdigest() + "  " + f["cache"].name + "\n",
                                        encoding="ascii")
                    if case == "ALIAS-DISAPPEARS":
                        if (owned_alias() != original_alias
                                or held_regular(f["global_path"]) != protected[0]):
                            observed["premise_failed"] = True
                            self.fixed_hold()
                        # Exact verified owned symlink only; never its target.
                        alias.unlink()
                        observed["alias_absent"] = not os.path.lexists(alias)
                        if not observed["alias_absent"]:
                            observed["premise_failed"] = True
                            self.fixed_hold()
                    observed["target_match"] = target_values(admitted[1]) == published["targets"]
                    observed["authority"] = real_authority(published, f["csv"], f["p2p"], alias)
                    if observed["authority"] is not True:
                        observed["premise_failed"] = True
                        self.fixed_hold()
                    observed["publication"] = (held_regular(f["cache"]), held_regular(checksum))
                    published_fields = observed["publication"][1][1].decode("ascii").split()
                    if (published_fields != [hashlib.sha256(observed["publication"][0][1]).hexdigest(),
                                             f["cache"].name]
                            or observed["publication"][0][0][7] > observed["publication"][1][0][7]):
                        observed["premise_failed"] = True
                        self.fixed_hold()
                    observed["callback"] += 1
                    return admitted

                # Entry witnesses count attempted calls before delegate success.
                # An early unrelated error cannot masquerade as zero activity.
                def observer(label, real):
                    @wraps(real)
                    def call(*args, **kwargs):
                        observed["entries"].append(label)
                        return real(*args, **kwargs)
                    return call

                before_events = len(self.events(f))
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(app, "load_target_cache", new=load))
                    for name, label in (
                        ("_authenticate_ib_read", "selector"),
                        ("_execute_ib_phase", "phase"),
                        ("run_on_ib", "IB"),
                        ("_run_authorized_ib_command", "authorized"),
                        ("verify_ipv4_login", "IPv4"),
                        ("verify_password_hash", "native"),
                        ("confirm_first_device_change", "confirm"),
                    ):
                        stack.enter_context(mock.patch.object(
                            app, name, new=observer(label, getattr(app, name))))
                    real_password = app.ProjectPasswordPolicy.password
                    stack.enter_context(mock.patch.object(
                        app.ProjectPasswordPolicy, "password",
                        new=observer("target-fetch", real_password)))
                    result = self.invoke(f)
                events = self.events(f)[before_events:]
                self.assertTrue(not observed["premise_failed"] and observed["loads"] == 1
                                and observed["successful_loads"] == 1 and observed["callback"] == 1,
                                "real admitted cache publication premise did not complete")
                self.assertTrue(observed["actual_return"] is not None
                                and target_values(observed["actual_return"][1]) == observed["target_before"],
                                "original real returned Targets must not be reconstructed or mutated")
                self.assertTrue(observed["authority"] is True,
                                "unrelated input authority rejection cannot prove correlation")
                self.assertTrue(observed["publication"] ==
                                (held_regular(f["cache"]), held_regular(checksum)),
                                "SUT changed deliberately published cache or its data sidecar")
                self.assertTrue(protected == [held_regular(path) for path in protected_paths],
                                "admission check changed protected input/global/keys/foreign identity")
                self.assertEqual([("targets", 0, "ib_port_alias")] if case == "TARGET-MISMATCH" else [],
                                 observed["changed_paths"])
                if case == "ALIAS-DISAPPEARS":
                    self.assertTrue(observed["alias_absent"] and not os.path.lexists(alias),
                                    "declared owned alias absence must persist; real target stays protected")
                else:
                    self.assertTrue(owned_alias() == original_alias, "declared alias identity changed")
                self.assertEqual([], self.writes(events), "check-only admission may not perform business writes")
                self.assertFalse(f["credentials"].exists() or f["marker"].exists() or f["terminal"].exists())
                if case == "MATCH":
                    # Behavior failure is a real assertion RED, not a fixture HOLD.
                    # Table 6-1 row 11 (guide :754; v15 CURRENT-CONTRACT.md:67): the admitted
                    # check-only run still has public keys to install, so it ends INCOMPLETE (2).
                    self.assertTrue(result["error"] is None and result["rc"] == 2,
                                    "admitted check-only with remaining work must end INCOMPLETE (2)")
                    self.assertTrue(observed["target_match"] is True)
                    self.assertEqual(1, observed["entries"].count("selector"))
                    # P3c map D32d :284 (E8, 04 Q-039; 06 D1a-B; v15 CURRENT-CONTRACT.md:59):
                    # the v15 check-only reads no pending diff.
                    self.assertEqual(0, len(self.diffs(events)))
                    self.assertEqual(["selector-return"], f["caller"]["timeline"])
                    self.assertTrue(len(f["caller"]["selector"]) == 1
                                    and f["caller"]["selector"][0]["initial"]
                                    and not f["caller"]["selector"][0]["required"])
                    self.assertEqual([], f["caller"]["returned_diff"])
                    self.assertFalse(any(label in ("native", "target-fetch", "confirm",
                                                   "authorized", "IPv4") for label in observed["entries"]))
                else:
                    self.assert_hold(result)
                    self.assertEqual([], observed["entries"],
                                     "admission mismatch must stop before any IB/target/native/consent entry")
                    self.assertFalse(any(event["kind"] in
                                         ("inner-answer", "nested-dispatch", "inner-rejected",
                                          "pam-start", "pam-target", "key-shell", "ipv4-read")
                                         for event in events),
                                     "shared OOB readonly may occur, but no IB actor may precede HOLD")
                    self.assertEqual([], self.diffs(events))
                    self.assertEqual([], result["hashes"])
                    self.assertFalse("TARGET" in result["prompts"])
                    self.assertTrue(observed["target_match"] is (case != "TARGET-MISMATCH"),
                                    "fault must be the declared independent target or alias mismatch")


if __name__ == "__main__":
    unittest.main()
