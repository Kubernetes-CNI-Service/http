"""First interactive link-down retry admission; one independent workflow, NOT RUN.

Real C2/P1/MAIN, interface parsers, project policy/native, OOB generated shell,
selected writer/reader and watch producer delegate. SSH/crontab are owned
external MODELS; the watch-entry reader is an explicit additional test-side read.
"""
from __future__ import annotations

from contextlib import ExitStack
from functools import wraps
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_target_credentials_workflow as basis
from test_cases import test_initial_setup_auto_oob_tail_latch_workflow as w2

PUBLIC_INITIAL, PUBLIC_OOB = basis.PUBLIC_INITIAL, basis.PUBLIC_OOB
FOREIGN = "3 4 * * * /PUBLIC/foreign-job # preserve-foreign\n"
PEER_SHA256 = "217dadcd5e205abed245d2e2100445aad833ba4d0b263d5b9ab51f098606debb"
UP_TABLE = '"Interface Admin Oper\\nswp7 up up\\n"'
DOWN_TABLE = '"Interface Admin Oper\\nswp7 up down\\n"'


class _LinkFixtureHold(RuntimeError):
    pass


def hold():
    error = _LinkFixtureHold("FIXTURE HOLD: first-interactive linkdown external prerequisite unavailable")
    try:
        raise error from None
    except _LinkFixtureHold:
        error.__cause__ = None
        error.__context__ = None
        raise


def down_peer():
    peer = w2._peer_program()
    if hashlib.sha256(peer.encode()).hexdigest() != PEER_SHA256 or peer.count(UP_TABLE) != 1:
        hold()
    return peer.replace(UP_TABLE, DOWN_TABLE, 1)


def expected_job(f):
    """Independent canonical renderer using only supplied PUBLIC paths."""
    q = shlex.quote
    state = f["credentials"].parent
    return (
        "*/10 * * * * cd " + q(str(f["tool"]))
        + " && flock -w 0 " + q(str(state / "auto.lock"))
        + " " + q(str(Path(sys.executable).resolve())) + " " + q(str(f["source"]))
        + " --auto --apply --yes --credentials-file " + q(str(f["credentials"]))
        + " --execution-mode management --ib-csv " + q(str(f["csv"]))
        + " --p2p " + q(str(f["p2p"])) + " --target-cache " + q(str(f["cache"]))
        + " --report " + q(str(f["root"] / "out/report.log"))
        + " --snapshot-dir " + q(str(f["root"] / "out/snapshots"))
        + " >> " + q(str(state / "auto-cron.log"))
        + " 2>&1 # http-v3-req10c-auto\n"
    )


class FirstInteractiveLinkdownRetryWorkflowTests(unittest.TestCase):
    # Non-inheriting real helper delegation. No old test methods are aliased.
    fixture = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.fixture
    p1 = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.p1
    events = basis.InitialTargetCredentialsMainAutoWorkflowDraftTests.events
    invoke = w2.EligibleOOBTailLatchWorkflowTests.invoke
    _invoke_backend = w2.EligibleOOBTailLatchWorkflowTests._invoke_backend
    _entry = w2.EligibleOOBTailLatchWorkflowTests._entry
    _global_fault = w2.EligibleOOBTailLatchWorkflowTests._global_fault
    _mark_fault = w2.EligibleOOBTailLatchWorkflowTests._mark_fault
    _oob_effect = w2.EligibleOOBTailLatchWorkflowTests._oob_effect

    @classmethod
    def setUpClass(cls):
        w2.EligibleOOBTailLatchWorkflowTests.setUpClass.__func__(cls)
        probe = basis.load_script("linkdown_existing_abi_readiness", basis.INITIAL)
        requirements = {
            "_write_auto_credentials": {"_password_policy", "_ib_user"},
            "_ib_project_value": {"policy", "user", "fetch"},
            "interface_status_line": {"interface_table", "interface"},
            "interface_oper_status": {"status_line", "interface"},
            "install_oob_management_key": {"ethernet", "user", "password", "entry", "timeout"},
            "_install_auto_watch": {"tool", "credentials", "ib_csv", "p2p", "cache",
                                    "report", "snapshots", "force"},
            "read_auto_credentials": {"path"},
        }
        for name, names in requirements.items():
            value = getattr(probe, name, None)
            if not callable(value) or not names.issubset(inspect.signature(value).parameters):
                hold()
        if any(hmac.compare_digest(cls.kat["PASSWORD"], value)
               for value in (PUBLIC_INITIAL, PUBLIC_OOB)) or PUBLIC_INITIAL == PUBLIC_OOB:
            hold()

    def prepare(self, folder):
        f = self.fixture(str(Path(folder).resolve(strict=True)),
                         scenario="normal", expiry=False, configured=True)
        f["w2"] = w2._witness("linkdown")
        old = "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n"
        raw = f["csv"].read_text(encoding="ascii")
        if raw.count(old) != 1:
            hold()
        f["csv"].write_text(raw.replace(old, "EXAMPLE-JUMP01,eth,192.0.2.10,,,,,,\n"),
                            encoding="ascii")
        state = json.loads(f["state"].read_text())
        state["credential"] = "initial"
        f["state"].write_text(json.dumps(state), encoding="ascii")
        f["state"].chmod(0o600)
        f["ssh_home"] = f["root"] / "ssh-process-home"
        f["ssh_home"].mkdir(mode=0o700)
        oob_home = f["root"] / "oob-remote-home"
        oob_home.mkdir(mode=0o700)
        (oob_home / ".ssh").mkdir(mode=0o700)
        f["oob_auth"] = oob_home / ".ssh/authorized_keys"
        f["oob_old"] = "# PUBLIC independent OOB original\n" + basis.public_key(23, "oob-foreign-original")
        f["oob_auth"].write_text(f["oob_old"], encoding="ascii")
        f["oob_auth"].chmod(0o600)
        f["oob_control"] = oob_home / "foreign-control"
        f["oob_control"].write_bytes(b"PUBLIC OOB foreign control\n")
        f["oob_control"].chmod(0o600)
        f["oob_control_before"] = basis.bound_file(f["oob_control"])
        config = json.loads(f["config"].read_text())
        config["oob_management_line"] = f["management"]
        f["config"].write_text(json.dumps(config), encoding="utf-8")
        f["config"].chmod(0o600)
        f["stub"].write_text(down_peer(), encoding="utf-8")
        f["stub"].chmod(0o600)
        cache = self.p1(f)
        produced = f["w2"]
        self.assertTrue(produced["devices"] and produced["built"]
                        and not produced["ib"] and not produced["native"],
                        "real CSV/P1 did not reach the nonremote producer prefix")
        device = produced["devices"][-1][1]["example-jump01"]
        target = produced["built"][-1][0]
        self.assertTrue(type(device) is f["app"].Device and device.dev_type == "eth"
                        and device.hostname == "EXAMPLE-JUMP01" and device.login_ip == "192.0.2.10"
                        and target.ethernet is device,
                        "actual CSV/build_targets did not produce eligible OOB transport")
        self.assertTrue(cache["targets"][0]["ethernet"]["dev_type"] == "eth"
                        and cache["targets"][0]["ethernet_port"] == "swp7"
                        and cache["targets"][0]["ib_port_alias"] == "eth0"
                        and cache["targets"][0]["ib"]["hostname"] == "EXAMPLE-IB01",
                        "actual P1 did not preserve independent target literals")
        admitted = f["app"].load_target_cache(
            f["cache"], f["csv"], f["p2p"], public_key_tool=f["tool"],
            validate_public_keys_with_ssh_keygen=True)
        self.assertTrue(type(admitted) is tuple and type(admitted[0]) is int
                        and admitted[0] == 1 and admitted[1][0].ethernet.dev_type == "eth",
                        "real cache reader did not admit the eligible target")
        entries = [entry for entry in cache["public_keys"] if entry["name"] == "mgmt-server.pub"]
        self.assertTrue(len(entries) == 1
                        and entries[0]["line"] == f["management"].strip()
                        and entries[0]["fingerprint"] == w2._fingerprint(f["management"]),
                        "actual P1 management key differs from independent PUBLIC wire")
        self.assertTrue(not any(os.path.lexists(f[name]) for name in
                                ("credentials", "marker", "terminal"))
                        and f["cron"].read_bytes() == FOREIGN.encode("ascii"),
                        "first-interactive fixture already has env/watch/terminal state")
        # No write_credentials, pre-watch producer, deletion or restoration.
        f["protected"] = tuple(f[name] for name in
                               ("source", "csv", "p2p", "global_path", "control", "auth",
                                "oob_control", "state", "config", "stub", "cache")) + (
            f["cache"].with_name(f["cache"].name + ".sha256"),
            f["root"] / "infiniband/publickey/laptop.pub",
            f["root"] / "infiniband/publickey/mgmt-server.pub",
        )
        f["protected_before"] = [basis.bound_file(path) for path in f["protected"]]
        alias = f["tool"] / "01-global.yaml"
        f["alias_before"] = basis.nine(alias.lstat()), os.readlink(alias)
        f["w2"] = w2._witness("linkdown")
        f["w2"]["phase"] = "main"
        return f

    def test_first_interactive_linkdown_qualifies_target_before_real_oob_writer_and_watch(self):
        with tempfile.TemporaryDirectory(prefix="auto-first-linkdown-") as folder:
            f = self.prepare(folder)
            app = f["app"]
            trace = dict(timeline=[], status=[], oper=[], native=[], admission=[],
                         tails=[], writer=[], reader=[], watches=0, writer_active=False)
            real_line, real_oper = app.interface_status_line, app.interface_oper_status
            real_native, real_value = app.verify_password_hash, app._ib_project_value
            real_tail, real_writer = app.install_oob_management_key, app._write_auto_credentials
            real_reader, real_watch = app.read_auto_credentials, app._install_auto_watch
            @wraps(real_line)
            def line(interface_table, interface):
                result = real_line(interface_table, interface)
                if interface == "swp7":
                    trace["status"].append(
                        result == "swp7 up down"
                        and "Interface Admin Oper" in interface_table.replace("\r", "").splitlines()
                        and "swp7 up down" in interface_table.replace("\r", "").splitlines())
                return result
            @wraps(real_oper)
            def oper(status_line, interface):
                result = real_oper(status_line, interface)
                if interface == "swp7":
                    trace["oper"].append(status_line == "swp7 up down" and result == "down")
                    trace["timeline"].append("interface-down-return")
                return result
            @wraps(real_native)
            def native(password, setting):
                result = real_native(password, setting)
                trace["native"].append(dict(
                    qualified=result is True
                    and hmac.compare_digest(password, self.kat["PASSWORD"])
                    and hmac.compare_digest(setting, self.kat["YESCRYPT"]),
                    before_tail=not trace["tails"], before_writer=not trace["writer"],
                    during_writer=trace["writer_active"]))
                return result
            @wraps(real_value)
            def value(*args, **kwargs):
                bound = inspect.signature(real_value).bind(*args, **kwargs)
                bound.apply_defaults()
                result = real_value(*args, **kwargs)
                if bound.arguments["fetch"] is True:
                    policy = bound.arguments["policy"]
                    trace["admission"].append(
                        type(policy) is app.ProjectPasswordPolicy and policy.user == "admin"
                        and policy.path.resolve() == f["global_path"].resolve()
                        and bound.arguments["user"] == "admin"
                        and type(result) is str
                        and hmac.compare_digest(result, self.kat["PASSWORD"]))
                    trace["timeline"].append("retry-admission-return")
                return result
            @wraps(real_tail)
            def tail(*args, **kwargs):
                bound = inspect.signature(real_tail).bind(*args, **kwargs)
                trace["tails"].append(
                    bound.arguments["ethernet"].dev_type == "eth"
                    and bound.arguments["ethernet"].hostname == "EXAMPLE-JUMP01"
                    and bound.arguments["entry"]["name"] == "mgmt-server.pub"
                    and bound.arguments["entry"]["line"] == f["management"].strip()
                    and hmac.compare_digest(bound.arguments["password"], PUBLIC_OOB))
                trace["timeline"].append("oob-tail-entry")
                result = real_tail(*args, **kwargs)
                trace["timeline"].append("oob-tail-return")
                return result
            @wraps(real_writer)
            def writer(*args, **kwargs):
                bound = inspect.signature(real_writer).bind(*args, **kwargs)
                bound.apply_defaults()
                policy = bound.arguments["_password_policy"]
                trace["writer"].append(
                    type(policy) is app.ProjectPasswordPolicy
                    and policy.user == "admin" and bound.arguments["_ib_user"] == "admin"
                    and policy.path.resolve() == f["global_path"].resolve())
                trace["timeline"].append("writer-entry")
                trace["writer_active"] = True
                try:
                    result = real_writer(*args, **kwargs)
                finally:
                    trace["writer_active"] = False
                trace["timeline"].append("writer-return")
                return result
            @wraps(real_watch)
            def watch(*args, **kwargs):
                trace["watches"] += 1
                trace["timeline"].append("watch-wrapper-entry")
                bound = inspect.signature(real_watch).bind(*args, **kwargs)
                self.assertTrue(bound.arguments["credentials"] == f["credentials"],
                                "watch did not select the actual newly written default env")
                before = basis.bound_file(f["credentials"])
                # This is explicitly one additional TEST-SIDE actual data read.
                values = real_reader(f["credentials"])
                after = basis.bound_file(f["credentials"])
                trace["reader"].append(
                    before == after and stat.S_IMODE(before[0][2]) == 0o600
                    and set(values) == {"NVOS_INITIAL_PASSWORD", "NVOS_TARGET_PASSWORD",
                                        "ZTP_ETH_PASSWORD_EXAMPLE_JUMP01"}
                    and hmac.compare_digest(values["NVOS_INITIAL_PASSWORD"], PUBLIC_INITIAL)
                    and hmac.compare_digest(values["NVOS_TARGET_PASSWORD"], self.kat["PASSWORD"])
                    and hmac.compare_digest(values["ZTP_ETH_PASSWORD_EXAMPLE_JUMP01"], PUBLIC_OOB))
                trace["env_at_watch"] = before
                trace["timeline"].append("reader-qualified-at-watch-entry")
                trace["timeline"].append("watch-delegate-entry")
                result = real_watch(*args, **kwargs)
                trace["timeline"].append("watch-return")
                return result
            result = unexpected = None
            with ExitStack() as stack:
                for name, observer in (
                    ("interface_status_line", line), ("interface_oper_status", oper),
                    ("verify_password_hash", native), ("_ib_project_value", value),
                    ("install_oob_management_key", tail), ("_write_auto_credentials", writer),
                    ("_install_auto_watch", watch),
                ):
                    stack.enter_context(mock.patch.object(app, name, new=observer))
                try:
                    result = self.invoke(f, "--auto", cron_round=False)
                except (_LinkFixtureHold, w2._W2FixtureHold):
                    raise
                except BaseException as caught:
                    unexpected = caught
            if f["boundary_errors"] or any(event["kind"] == "adapter-error" for event in self.events(f)):
                hold()
            self.assertTrue(unexpected is None,
                            "qualified first-interactive MAIN raised unexpected error; details suppressed")
            self.assertTrue(result["error"] is None and result["rc"] == 0,
                            "qualified nonterminal first-interactive MAIN did not install safe retry")
            self.assertTrue(trace["status"] and all(trace["status"])
                            and trace["oper"] and all(trace["oper"])
                            and any(event["kind"] == "ethernet-read"
                                    and event["command"] == ["nv", "show", "interface"]
                                    for event in result["events"]),
                            "actual PUBLIC table and real interface parser did not reach down")
            self.assertTrue(not f["w2"]["selected"] and not f["w2"]["ib"]
                            and not any(label in f["w2"]["timeline"] for label in
                                        ("selector-entry", "phase-entry", "authorized-helper-entry"))
                            and not any(event["kind"] in
                                        {"inner-answer", "nested-dispatch", "mutation", "apply-y",
                                         "save", "pam-target", "key-shell", "ipv4-read"}
                                        for event in result["events"]),
                            "down link dispatched IB selector/session/configuration or inner key/PAM")
            self.assertTrue(trace["admission"] and all(trace["admission"])
                            and any(row["qualified"] and row["before_tail"] and row["before_writer"]
                                    for row in trace["native"]),
                            "real project/native TARGET admission did not precede OOB/write capability")
            self.assertTrue(trace["tails"] == [True] and trace["writer"] == [True]
                            and trace["watches"] == 1 and trace["reader"] == [True]
                            and any(row["qualified"] and row["during_writer"] for row in trace["native"]),
                            "actual eligible OOB/selected writer/reader/watch role chain was not unique and valid")
            timeline = trace["timeline"]
            required = ["interface-down-return", "retry-admission-return", "oob-tail-entry",
                        "oob-tail-return", "writer-entry", "writer-return", "watch-wrapper-entry",
                        "reader-qualified-at-watch-entry", "watch-delegate-entry", "watch-return"]
            self.assertTrue(all(label in timeline for label in required)
                            and [timeline.index(label) for label in required]
                            == sorted(timeline.index(label) for label in required),
                            "genuine down/admission/OOB/publication/test-reader/watch order changed")
            self.assertTrue(result["prompts"].count("OOB") == 1
                            and result["prompts"].count("TARGET") == 2
                            and len(result["prompts"]) == 3,
                            "first-interactive source roles did not prompt one OOB and one target pair")
            self._oob_effect(f, result["events"])
            self.assertTrue(all(event["oob"] and not event["initial"] and not event["target"]
                                for event in result["events"] if event["kind"] == "outer-answer"),
                            "actual outer OOB authentication used an IB role")
            self.assertTrue(basis.bound_file(f["credentials"]) == trace["env_at_watch"]
                            and basis.bound_file(f["marker"])[1] == b"http-v3-req10c-auto-v1\n"
                            and not os.path.lexists(f["terminal"])
                            and f["cron"].read_text() == FOREIGN + expected_job(f),
                            "actual writer/watch state or independent complete job differs")
            self.assertTrue(not f["w2"]["pause"]
                            and not any(label in f["w2"]["timeline"] for label in
                                        ("completion-entry", "terminal-write-entry"))
                            and "FIXTURE_DRAIN_NOT_SUT" not in result["cleanup"]
                            and f["w2"]["children"]
                            and sum(row["product"] and row["reaped"] for row in f["w2"]["waits"])
                            == len(f["w2"]["children"]),
                            "nonterminal positive used pause/completion or exceptional fixture drain")
            self.assertTrue([basis.bound_file(path) for path in f["protected"]]
                            == f["protected_before"],
                            "first retry changed IB/source/project/foreign inputs beyond allowed effects")
            alias = f["tool"] / "01-global.yaml"
            self.assertTrue((basis.nine(alias.lstat()), os.readlink(alias)) == f["alias_before"],
                            "first retry changed the admitted project alias")


if __name__ == "__main__":
    unittest.main()
