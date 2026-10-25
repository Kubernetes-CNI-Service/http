"""Independent PUBLIC Network diagnostics: pure gates and actual MAIN workflow.

Owned SSH/NVUE state is a MODEL. Actual C2/P1, selector, policy/native backend,
PTY/frame, authorized commands and readback verification are real delegates.
No raw private error, desired-from-subject expectation, or production bypass.
"""
from __future__ import annotations

from contextlib import ExitStack
from functools import wraps
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_main_caller_precommit as caller

base = caller.base
READ = ["nv", "config", "show", "-o", "commands"]
APPLY = ["nv", "config", "apply", "-y"]
SAVE = ["nv", "config", "save"]
INITIAL_ROWS = (
    "nv set system config auto-save state enabled",
    "nv set system ztp config-save enabled",
)
SERVICE_ROWS = (
    "nv set system dns server 203.0.113.53",
    "nv set system ntp server ntp.ubuntu.com",
    "nv set system ntp server time.ib.example.test",
    "nv set system date-time timezone Asia/Taipei",
)
RESERVED_ROWS = (
    "nv set interface eth0-1 link state up",
    "nv set interface eth0-1 type eth",
)
COMPLETE_ROWS = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24",
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
    *RESERVED_ROWS,
    "nv set system hostname EXAMPLE-IB01",
    *INITIAL_ROWS,
    *SERVICE_ROWS,
)
BAD_READ_ROWS = (
    "nv set system hostname nvos",
    *INITIAL_ROWS,
    *RESERVED_ROWS,
    *SERVICE_ROWS,
)
NETWORK_SETTERS = (
    ("nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"),
    ("nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"),
    ("nv", "set", "interface", "eth0-1", "link", "state", "up"),
    ("nv", "set", "interface", "eth0-1", "type", "eth"),
    ("nv", "set", "system", "hostname", "EXAMPLE-IB01"),
)
GENERIC = "management Network setter plan is not qualified"
READBACK = "management Network post-configuration verification failed; device state is UNKNOWN"
FIELD_ERRORS = {
    "hostname": "management Network hostname conflict; device state is UNKNOWN",
    "eth0 gateway": "management Network eth0 gateway conflict; device state is UNKNOWN",
    "eth1 gateway": "management Network eth1 gateway conflict; device state is UNKNOWN",
}


def body(rows):
    return "\n".join(rows) + "\n"


def conflicting_rows(field):
    if field == "hostname":
        return tuple("nv set system hostname OTHER-IB01"
                     if row == "nv set system hostname EXAMPLE-IB01" else row
                     for row in COMPLETE_ROWS)
    if field == "eth0 gateway":
        return tuple("nv set interface eth0-1 ipv4 gateway 198.51.100.1"
                     if row == "nv set interface eth0-1 ipv4 gateway 203.0.113.1" else row
                     for row in COMPLETE_ROWS)
    if field == "eth1 gateway":
        return (
            "nv set interface eth0 ipv4 address 203.0.113.2/24",
            "nv set interface eth1 ipv4 address 198.51.100.2/24",
            "nv set interface eth0 ipv4 gateway 203.0.113.1",
            "nv set interface eth1 ipv4 gateway 198.51.100.254",
            *RESERVED_ROWS, "nv set system hostname EXAMPLE-IB01",
            *INITIAL_ROWS, *SERVICE_ROWS,
        )
    raise RuntimeError("FIXTURE HOLD: unknown PUBLIC conflict selector")


# Added only to the owned external peer's RAM program before its unique run().
# The original business delegate actually accepts setters/applies/saves first.
DIAGNOSTIC_PEER = r'''
_diagnostic_original_business = business
_diagnostic_original_show = show_state
def show_state(S):
    selected = C.get("diagnostic_case")
    if selected in ("hostname", "eth0 gateway"):
        return "\n".join(C["diagnostic_rows"]) + "\n"
    return _diagnostic_original_show(S)
def business(command, S):
    selected = C.get("diagnostic_case")
    if (selected == "readback" and command == ["nv","config","show","-o","commands"]
            and S.get("diagnostic_saved_network") is True):
        record("diagnostic-bad-read")
        return "\n".join(C["diagnostic_rows"]) + "\n", 0
    before_network = S["network"]
    result = _diagnostic_original_business(command, S)
    if (selected == "readback" and command == ["nv","config","apply","-y"]
            and before_network is False and S["network"] is True
            and type(result[1]) is int and result[1] == 0):
        S["diagnostic_applied_network"] = True
        record("diagnostic-network-applied")
    if (selected == "readback" and command == ["nv","config","save"]
            and S.get("diagnostic_applied_network") is True
            and type(result[1]) is int and result[1] == 0):
        S["diagnostic_saved_network"] = True
        record("diagnostic-network-saved")
    return result
'''


class NetworkDiagnosticDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = base.load_script("network_diagnostic_actual_source", base.INITIAL)
        for name in ("_management_network_commands", "_verify_management_network_state",
                     "parse_nvue_state", "verify_state", "force_day0_needed"):
            if not callable(getattr(cls.app, name, None)):
                raise RuntimeError("FIXTURE HOLD: existing Network direct dependency absent")

    def device(self, dual=False):
        return self.app.Device(
            hostname="EXAMPLE-IB01", dev_type="ib", login_ip="203.0.113.2",
            eth0_prefix="203.0.113.2/24", eth0_gateway="203.0.113.1",
            eth0_mac="02:00:00:00:00:17",
            eth1_prefix="198.51.100.2/24" if dual else "",
            eth1_gateway="198.51.100.1" if dual else "",
        )

    def pure(self, function, *args):
        attempted, result, error = [], None, None
        def forbidden(label):
            def call(*unused, **ignored):
                attempted.append(label)
                raise RuntimeError("PUBLIC forbidden side effect in pure Network gate")
            return call
        with ExitStack() as stack:
            for owner, name, label in (
                (self.app, "run_on_ib", "IB"),
                (self.app, "_run_authorized_ib_command", "authorized"),
                (self.app, "verify_password_hash", "native"),
                (self.app.subprocess, "run", "subprocess"),
                (self.app.os, "open", "os.open"),
                (Path, "read_text", "read_text"),
                (Path, "read_bytes", "read_bytes"),
                (Path, "write_text", "write_text"),
                (Path, "write_bytes", "write_bytes"),
            ):
                stack.enter_context(mock.patch.object(owner, name, new=forbidden(label)))
            stack.enter_context(mock.patch("builtins.open", new=forbidden("open")))
            try:
                result = function(*args)
            except BaseException as caught:
                error = caught
        self.assertEqual([], attempted, "pure Network gate attempted an external effect")
        return result, error

    def safe_error(self, error, message):
        self.assertTrue(type(error) is self.app.SetupError,
                        "actual pure gate must reject with exact SetupError")
        self.assertTrue(error.args == (message,),
                        "Network diagnostic must be the fixed PUBLIC literal only")
        self.assertTrue(error.__cause__ is None and error.__context__ is None
                        and error.__dict__ == {},
                        "Network diagnostic retained private chains or extra attributes")
        self.assertTrue(not any(value in str(error)
                                for value in ("OTHER-IB01", "EXAMPLE-IB01",
                                              "198.51.100.1", "198.51.100.254",
                                              "203.0.113.2/24", "PUBLIC-RAW-MARKER")),
                        "Network diagnostic echoed raw actual or desired values")

    def test_real_hostname_and_required_gateway_conflicts_use_fixed_public_fields(self):
        for field in ("hostname", "eth0 gateway", "eth1 gateway"):
            with self.subTest(field=field):
                result, error = self.pure(
                    self.app._management_network_commands,
                    self.device(dual=field == "eth1 gateway"), body(conflicting_rows(field)))
                self.safe_error(error, FIELD_ERRORS[field])
                self.assertTrue(result is None, "conflict produced business setters")

    def test_unknown_grammar_and_membership_controls_preserve_existing_force_semantics(self):
        malformed = (
            "",
            body((*conflicting_rows("hostname"),
                  "nv set interface eth0 link state up PUBLIC-RAW-MARKER")),
            body((*COMPLETE_ROWS, "nv set interface eth0-2 link state up")),
        )
        for supplied in malformed:
            with self.subTest(case="generic", ordinal=malformed.index(supplied)):
                result, error = self.pure(
                    self.app._management_network_commands, self.device(), supplied)
                self.safe_error(error, GENERIC)
                self.assertTrue(result is None, "unqualified body became missing setters")
        with self.subTest(case="target-plus-extra-gateway"):
            result, error = self.pure(
                self.app._management_network_commands, self.device(),
                body((*COMPLETE_ROWS,
                      "nv set interface eth0 ipv4 gateway 203.0.113.254")))
            self.assertTrue(error is None and result == [],
                            "expected gateway membership plus extra gateway is not a conflict")
        with self.subTest(case="missing-address-keeps-existing-address"):
            supplied = body(tuple("nv set interface eth0 ipv4 address 203.0.113.200/24"
                                  if row == "nv set interface eth0 ipv4 address 203.0.113.2/24"
                                  else row for row in COMPLETE_ROWS))
            state = self.app.parse_nvue_state(supplied)
            needed, error = self.pure(self.app.force_day0_needed, self.device(), state)
            self.assertTrue(error is None and needed is True
                            and state.eth0_addresses == ("203.0.113.200/24",),
                            "old force fillmissing may not delete or conflict on an extra address")
            result, error = self.pure(
                self.app._management_network_commands, self.device(), supplied)
            self.assertTrue(error is None and result ==
                            [["nv", "set", "interface", "eth0", "ipv4", "address",
                              "203.0.113.2/24"]],
                            "fillmissing must add only requested address, never remove the old one")

    def test_actual_readback_verifier_reports_fixed_failure_without_raw_details(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                states, verified = [], []
                real_parse, real_verify = self.app.parse_nvue_state, self.app.verify_state
                @wraps(real_parse)
                def parse(supplied):
                    result = real_parse(supplied)
                    states.append(result)
                    return result
                @wraps(real_verify)
                def verify(device, state):
                    verified.append(state)
                    return real_verify(device, state)
                with mock.patch.object(self.app, "parse_nvue_state", new=parse), \
                        mock.patch.object(self.app, "verify_state", new=verify):
                    result, error = self.pure(
                        self.app._verify_management_network_state, self.device(),
                        body(COMPLETE_ROWS if complete else BAD_READ_ROWS))
                self.assertTrue(len(verified) == 1
                                and any(verified[0] is state for state in states),
                                "actual parser state must reach the real readback verifier")
                if complete:
                    self.assertTrue(error is None and result is verified[0],
                                    "qualified readback must return actual verified parser state")
                else:
                    self.safe_error(error, READBACK)
                    self.assertTrue(result is None, "failed actual readback returned business state")


class NetworkDiagnosticWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        caller.MainCallerPrecommitDraftTests.setUpClass.__func__(cls)

    fixed_hold = caller.MainCallerPrecommitDraftTests.fixed_hold
    fixture = caller.MainCallerPrecommitDraftTests.fixture
    events = caller.MainCallerPrecommitDraftTests.events
    invoke = caller.MainCallerPrecommitDraftTests.invoke
    p1 = caller.MainCallerPrecommitDraftTests.p1
    assert_success = caller.MainCallerPrecommitDraftTests.assert_success

    def diagnostic_fixture(self, folder, selected):
        f = self.fixture(folder, case="diagnostic-" + selected,
                         network=selected != "readback", services=True,
                         credential="initial")
        program = f["stub"].read_text(encoding="utf-8")
        marker = "def run():\n"
        if program.count(marker) != 1:
            self.fixed_hold()
        program = program.replace(marker, DIAGNOSTIC_PEER + "\n" + marker, 1)
        f["stub"].write_text(program, encoding="utf-8")
        f["stub"].chmod(0o600)
        config = json.loads(f["config"].read_text())
        config["diagnostic_case"] = selected
        config["diagnostic_rows"] = list(BAD_READ_ROWS if selected == "readback"
                                         else conflicting_rows(selected))
        f["config"].write_text(json.dumps(config), encoding="utf-8")
        f["config"].chmod(0o600)
        self.p1(f)
        return f

    def execute(self, f, *options):
        app = f["app"]
        state = dict(order=[], commands=[], helper_reads=[], constructors=[],
                     verifies=[], following=[], unexpected=None)
        real_ib = app.run_on_ib
        real_helper = app._run_authorized_ib_command
        real_constructor = app._management_network_commands
        real_verify = app._verify_management_network_state
        @wraps(real_ib)
        def ib(*args, **kwargs):
            command = inspect.signature(real_ib).bind(*args, **kwargs).arguments["ib_command"]
            state["commands"].append(tuple(command)
                                     if command[:2] != ["sh", "-c"] else ("KEY-SHELL",))
            return real_ib(*args, **kwargs)
        @wraps(real_helper)
        def helper(*args, **kwargs):
            command = inspect.signature(real_helper).bind(*args, **kwargs).arguments["ib_command"]
            result = real_helper(*args, **kwargs)
            if command == READ:
                state["order"].append("authorized-read-return")
                state["helper_reads"].append(
                    dict(bad=result.output == body(BAD_READ_ROWS),
                         status0=type(result.exit_code) is int and result.exit_code == 0))
            return result
        @wraps(real_constructor)
        def constructor(device, supplied):
            entry = dict(host=supplied == body(conflicting_rows("hostname")),
                         gateway=supplied == body(conflicting_rows("eth0 gateway")),
                         error=None)
            state["constructors"].append(entry)
            try:
                return real_constructor(device, supplied)
            except BaseException as caught:
                entry["error"] = caught
                raise
        @wraps(real_verify)
        def verify(device, supplied):
            state["order"].append("actual-verify-entry")
            entry = dict(bad=supplied == body(BAD_READ_ROWS), error=None)
            state["verifies"].append(entry)
            try:
                return real_verify(device, supplied)
            except BaseException as caught:
                entry["error"] = caught
                raise
        def following(name, function):
            @wraps(function)
            def call(*args, **kwargs):
                state["following"].append(name)
                return function(*args, **kwargs)
            return call
        with ExitStack() as stack:
            for name, function in (
                ("run_on_ib", ib), ("_run_authorized_ib_command", helper),
                ("_management_network_commands", constructor),
                ("_verify_management_network_state", verify),
            ):
                stack.enter_context(mock.patch.object(app, name, new=function))
            for name in ("run_service_stage", "run_key_stage", "verify_ipv4_login"):
                stack.enter_context(mock.patch.object(
                    app, name, new=following(name, getattr(app, name))))
            result = None
            try:
                result = self.invoke(f, *options)
            except BaseException as caught:
                state["unexpected"] = caught
        self.assertTrue(state["unexpected"] is None,
                        "qualified diagnostic workflow had an unexpected program/fixture failure")
        self.assertTrue(type(result) is dict, "real MAIN observation is unavailable")
        return result, state

    def assert_fixed_error(self, app, error, message):
        self.assertTrue(type(error) is app.SetupError and error.args == (message,),
                        "actual core rejection did not retain fixed PUBLIC error contract")
        self.assertTrue(error.__cause__ is None and error.__context__ is None
                        and error.__dict__ == {},
                        "actual core rejection retained private error chains or attributes")

    def assert_no_private_report(self, result):
        self.assertTrue(not any(value in result["stdout"] + result["stderr"]
                                for value in (self.kat["PASSWORD"], self.kat["SHA512"],
                                              self.kat["YESCRYPT"], base.PUBLIC_INITIAL,
                                              base.PUBLIC_OOB)),
                        "diagnostic workflow leaked private credential facts")

    def test_real_main_bad_network_readback_reports_fixed_failure_and_stops(self):
        with tempfile.TemporaryDirectory(prefix="network-diagnostic-readback-") as folder:
            f = self.diagnostic_fixture(folder, "readback")
            auth_before = base.bound_file(f["auth"])
            before = len(self.events(f))
            result, observed = self.execute(f, "--apply", "--yes")
            fresh = self.events(f)[before:]
            self.assertTrue(result["rc"] != 0 or result["error"] is not None,
                            "failed Network readback returned success")
            self.assertTrue(len(f["caller"]["selector"]) == 1
                            and f["caller"]["selector"][0]["initial"] is True
                            and f["caller"]["selector"][0]["required"] is False,
                            "actual INITIAL selector must precede Network writes")
            transactions = [command for command in observed["commands"]
                            if command[:2] == ("nv", "set") or
                            command in (tuple(APPLY), tuple(SAVE))]
            self.assertEqual([*NETWORK_SETTERS, tuple(APPLY), tuple(SAVE)], transactions,
                             "bad readback must follow the real Network transaction")
            markers = [event["kind"] for event in fresh if event["kind"].startswith("diagnostic-")]
            self.assertEqual(["diagnostic-network-applied", "diagnostic-network-saved",
                              "diagnostic-bad-read"], markers,
                             "actual false-to-true commit/save must precede model bad READ")
            self.assertTrue(observed["order"] ==
                            ["authorized-read-return", "actual-verify-entry"]
                            and observed["helper_reads"] == [dict(bad=True, status0=True)]
                            and len(observed["verifies"]) == 1
                            and observed["verifies"][0]["bad"] is True,
                            "real authorized READ returned bad body before actual verification")
            self.assert_fixed_error(f["app"], observed["verifies"][0]["error"], READBACK)
            self.assertTrue("post-configuration verification failed" in result["stdout"]
                            and READBACK in result["stdout"],
                            "original report diagnostic compatibility is required")
            self.assertEqual([], observed["following"],
                             "bad Network READ must stop Services/KEY/IPv4 consumer entry")
            self.assertTrue(not any(event["kind"] in ("key-shell", "ipv4-read", "pam-target")
                                    for event in fresh)
                            and base.bound_file(f["auth"]) == auth_before,
                            "failed readback must not acquire later key/IPv4 effects")
            self.assertTrue(not any(path.exists() for path in
                                    (f["credentials"], f["marker"], f["terminal"])),
                            "manual diagnostic failure may not persist automatic credentials")
            self.assert_no_private_report(result)

    def test_real_main_force_conflicts_report_fixed_field_before_consent_or_write(self):
        for field in ("hostname", "eth0 gateway"):
            with self.subTest(field=field), \
                    tempfile.TemporaryDirectory(prefix="network-diagnostic-conflict-") as folder:
                f = self.diagnostic_fixture(folder, field)
                auth_before = base.bound_file(f["auth"])
                before = len(self.events(f))
                result, observed = self.execute(f, "--force", "--apply", "--yes")
                fresh = self.events(f)[before:]
                self.assertTrue(result["rc"] != 0 or result["error"] is not None,
                                "actual preflight conflict returned success")
                self.assertTrue(len(f["caller"]["selector"]) == 1
                                and f["caller"]["selector"][0]["initial"] is True
                                and f["caller"]["selector"][0]["required"] is False,
                                "conflict must reach after actual INITIAL authentication")
                self.assertTrue(len(observed["constructors"]) == 1
                                and observed["constructors"][0][
                                    "host" if field == "hostname" else "gateway"] is True,
                                "real constructor did not receive the one conflicting actual field")
                self.assert_fixed_error(
                    f["app"], observed["constructors"][0]["error"], FIELD_ERRORS[field])
                report = result["stdout"].lower()
                self.assertTrue("conflict" in report and field in report
                                and "unknown" in report,
                                "fixed PUBLIC field conflict must preserve original report contract")
                diagnostic = "\n".join(line for line in report.splitlines()
                                       if "management network" in line)
                self.assertTrue(not any(raw in diagnostic for raw in
                                        ("other-ib01", "198.51.100.1", "203.0.113.2/24")),
                                "conflict diagnostic echoed raw actual/desired data")
                self.assertTrue(not any(command[:2] == ("nv", "set") or
                                        command in (tuple(APPLY), tuple(SAVE))
                                        for command in observed["commands"]),
                                "preflight conflict may not issue setters/apply/save")
                self.assertTrue(not f["caller"]["fetch"] and not f["caller"]["native"]
                                and not f["caller"]["helper"] and
                                "consent-granted" not in f["caller"]["timeline"],
                                "preflight conflict acquired Target/native/consent/write authority")
                self.assertEqual([], observed["following"],
                                 "preflight conflict may not enter later consumers")
                self.assertTrue(not any(event["kind"] in
                                        ("mutation", "apply-y", "save", "key-shell",
                                         "ipv4-read", "pam-target") for event in fresh)
                                and base.bound_file(f["auth"]) == auth_before,
                                "preflight conflict changed external business state")
                self.assertTrue(not any(path.exists() for path in
                                        (f["credentials"], f["marker"], f["terminal"])),
                                "preflight conflict persisted automatic state")
                self.assert_no_private_report(result)


if __name__ == "__main__":
    unittest.main()
