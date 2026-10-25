"""Private per-call cache admission output contract; tests-first, not run.

Real C2/P1/loader and public-key validators. No loader result/profile mocks,
network, new cache codec, or grant to AUTO/local/missing-global consumers.
"""
from __future__ import annotations
import ast
import base64
import builtins
import copy
from contextlib import ExitStack
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_target_credentials_workflow as base

OMITTED = object()
DEVICE_FIELDS = ("hostname", "dev_type", "login_ip", "eth0_prefix",
                 "eth0_gateway", "eth0_mac", "eth1_prefix", "eth1_gateway")
SAFE_ARGS = ("invalid private cache admission output",)


def exact_value(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(
            exact_value(actual[key], expected[key]) for key in expected)
    if type(expected) is list:
        return len(actual) == len(expected) and all(
            exact_value(left, right) for left, right in zip(actual, expected))
    return actual == expected


class CacheAdmissionOutputDirectTests(unittest.TestCase):
    # Plain function descriptors: real non-inherited unbound base delegation.
    invoke = base.InitialTargetCredentialsMainAutoWorkflowDraftTests.invoke
    events = base.InitialTargetCredentialsMainAutoWorkflowDraftTests.events

    @staticmethod
    def prerequisite_hold():
        error = RuntimeError("FIXTURE HOLD: cache admission prerequisite unavailable")
        try:
            raise error from None
        finally:
            error.__cause__ = None
            error.__context__ = None

    @classmethod
    def setUpClass(cls):
        # No missing-keyword TypeError may be issued as a behavior RED.
        failure = None
        ready = False
        try:
            raw = base.bound_file(base.INITIAL)[1]
            tree = ast.parse(raw, filename=str(base.INITIAL))
            loader = next(node for node in tree.body
                          if isinstance(node, ast.FunctionDef)
                          and node.name == "load_target_cache")
            for argument, default in zip(loader.args.kwonlyargs,
                                         loader.args.kw_defaults):
                if argument.arg == "_admission_out":
                    ready = isinstance(default, ast.Constant) and default.value is None
        except (OSError, ValueError, StopIteration):
            failure = True
        if failure or not ready:
            error = RuntimeError("NOT_READY: private cache admission output API absent")
            try:
                raise error from None
            finally:
                error.__cause__ = None
                error.__context__ = None
        born = None
        try:
            # Original external KAT positive/negative pairs and actual C2 import.
            base.InitialTargetCredentialsMainAutoWorkflowDraftTests.setUpClass.__func__(cls)
        except BaseException as error:
            born = error
        if born is not None:
            cls.prerequisite_hold()

    def prepare(self, folder):
        born = None
        f = None
        try:
            f = base.InitialTargetCredentialsMainAutoWorkflowDraftTests.fixture(
                self, folder, expiry=False, configured=True)
            base.InitialTargetCredentialsMainAutoWorkflowDraftTests.p1(self, f)
        except BaseException as error:
            born = error
        if born is not None or f is None:
            self.prerequisite_hold()
        return f

    def expected_profile(self, f):
        keys = []
        # Fixture literals, never SUT's fingerprint/profile/desired-command output.
        for name, line in (("laptop.pub", f["laptop"]),
                           ("mgmt-server.pub", f["management"])):
            public_line = line.rstrip("\n")
            wire = base64.b64decode(public_line.split()[1], validate=True)
            fingerprint = "SHA256:" + base64.b64encode(
                hashlib.sha256(wire).digest()).decode("ascii").rstrip("=")
            keys.append(dict(name=name, line=public_line, fingerprint=fingerprint))
        return dict(services={"dns": ["203.0.113.53"],
                              "ntp": ["ntp.ubuntu.com", "time.ib.example.test"],
                              "timezone": "Asia/Taipei"},
                    public_keys=keys)

    def protected(self, f):
        paths = (f["cache"], f["cache"].with_name(f["cache"].name + ".sha256"),
                 f["csv"], f["p2p"], f["global_path"], f["source"],
                 f["auth"], f["control"],
                 f["root"] / "infiniband/publickey/laptop.pub",
                 f["root"] / "infiniband/publickey/mgmt-server.pub")
        return [base.bound_file(path) for path in paths]

    def corrupt_owned_checksum_input(self, f):
        cache = f["cache"]
        sidecar = cache.with_name(cache.name + ".sha256")
        original_cache = base.bound_file(cache)
        original_sidecar = base.bound_file(sidecar)
        fields = original_sidecar[1].decode("ascii").split()
        self.assertTrue(len(fields) == 2 and fields[1] == cache.name
                        and fields[0] == hashlib.sha256(original_cache[1]).hexdigest(),
                        "CHECKSUM prerequisite needs the real original matching data sidecar")
        # Retain the OLD digest. Rewriting its identical DATA bytes after the
        # cache corruption admits the earlier timestamp gate, not the new hash.
        cache.write_bytes(original_cache[1] + b" ")
        sidecar.write_bytes(original_sidecar[1])
        current_cache = base.bound_file(cache)
        current_sidecar = base.bound_file(sidecar)
        self.assertTrue(current_cache[1] == original_cache[1] + b" "
                        and current_sidecar[1] == original_sidecar[1]
                        and current_sidecar[0][7] >= current_cache[0][7]
                        and fields[0] != hashlib.sha256(current_cache[1]).hexdigest(),
                        "CHECKSUM must reach stale-hash rejection, not an earlier mtime gate")

    def call_loader(self, f, *, out=OMITTED, forbid_copy=False, observe_payload=False):
        app = f["app"]
        validator = shutil.which("ssh-keygen")
        if validator is None:
            self.prerequisite_hold()
        calls = dict(validators=0, password_native=0, profile_copy=0, unexpected=0)
        payloads = []
        domains = []
        real_run = subprocess.run
        real_validate = app._validate_cache_profile

        def run(command, *args, **kwargs):
            expected = [validator, "-l", "-E", "sha256", "-f", "/dev/stdin"]
            if (type(command) is not list or command != expected or args
                    or set(kwargs) != {"input", "capture_output", "text", "timeout", "check"}
                    or kwargs.get("timeout") != 10 or kwargs.get("check") is not False
                    or kwargs.get("capture_output") is not True
                    or kwargs.get("text") is not True
                    or type(kwargs.get("input")) is not str
                    or kwargs["input"] not in (f["laptop"], f["management"])):
                calls["unexpected"] += 1
                raise RuntimeError("PUBLIC unexpected cache validator boundary")
            calls["validators"] += 1
            return real_run(command, **kwargs)

        def crypto(*args, **kwargs):
            calls["password_native"] += 1
            raise RuntimeError("PUBLIC cache loader must not verify a password")

        def copying(*args, **kwargs):
            calls["profile_copy"] += 1
            raise RuntimeError("PUBLIC default cache load may not copy a profile")

        @wraps(real_validate)
        def validate(payload):
            try:
                result = real_validate(payload)
            except app.SetupError as error:
                domains.append(error)
                raise
            payloads.append(payload)
            return result

        result = None
        caught = None
        kwargs = dict(public_key_tool=f["tool"],
                      validate_public_keys_with_ssh_keygen=True,
                      allow_baked_missing_global=False)
        if out is not OMITTED:
            kwargs["_admission_out"] = out
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(app.subprocess, "run", new=run))
            stack.enter_context(mock.patch.object(app, "verify_password_hash", new=crypto))
            if forbid_copy:
                # Dynamic representatives plus separate source None-specialization
                # review; these do not prove absence of arbitrary hand-written copies.
                stack.enter_context(mock.patch.object(app.json, "dumps", new=copying))
                stack.enter_context(mock.patch.object(copy, "deepcopy", new=copying))
            if observe_payload:
                stack.enter_context(mock.patch.object(app, "_validate_cache_profile",
                                                      new=validate))
            try:
                result = app.load_target_cache(f["cache"], f["csv"], f["p2p"], **kwargs)
            except BaseException as error:
                caught = error
        return dict(result=result, error=caught, calls=calls, payloads=payloads,
                    domains=domains)

    def assert_real_target(self, f, result):
        app = f["app"]
        self.assertTrue(type(result) is tuple and len(result) == 2
                        and type(result[0]) is int and result[0] == 1
                        and type(result[1]) is list and len(result[1]) == 1,
                        "real cache load must retain the original two-item result")
        target = result[1][0]
        self.assertTrue(type(target) is app.Target and type(target.ib) is app.Device
                        and type(target.ethernet) is app.Device,
                        "actual loader Target/Device objects are required")
        self.assertTrue(tuple(getattr(target.ib, key) for key in DEVICE_FIELDS) ==
                        ("EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                         "203.0.113.1", "02:00:00:00:00:17", "", "")
                        and tuple(getattr(target.ethernet, key) for key in DEVICE_FIELDS) ==
                        ("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "192.0.2.10",
                         "", "", "", "")
                        and target.ethernet_port == "swp7" and target.ib_port_alias == "eth0",
                        "independent CSV/P2P literal Target fields changed")

    def assert_successful_call(self, f, observation):
        self.assertTrue(observation["error"] is None,
                        "qualified loader failed; private exception suppressed")
        self.assertEqual(dict(validators=2, password_native=0, profile_copy=0, unexpected=0),
                         observation["calls"])
        self.assert_real_target(f, observation["result"])

    def test_default_omitted_and_explicit_none_preserve_legacy_success_and_rejection(self):
        for mode in ("OMITTED", "NONE"):
            with self.subTest(default=mode), tempfile.TemporaryDirectory(prefix="cache-admission-default-") as folder:
                f = self.prepare(folder)
                before = self.protected(f)
                options = {} if mode == "OMITTED" else {"out": None}
                observation = self.call_loader(f, forbid_copy=True, **options)
                self.assert_successful_call(f, observation)
                self.assertTrue(self.protected(f) == before,
                                "legacy successful read changed owned inputs")
                # Owned cache input corruption only; no output-write/capacity fault.
                self.corrupt_owned_checksum_input(f)
                after_perturbation = self.protected(f)
                rejected = self.call_loader(f, forbid_copy=True, **options)
                self.assertTrue(rejected["error"] is None and rejected["result"] is None,
                                "legacy checksum rejection must remain None, not new API failure")
                self.assertEqual(dict(validators=0, password_native=0, profile_copy=0, unexpected=0),
                                 rejected["calls"])
                self.assertTrue(self.protected(f) == after_perturbation,
                                "legacy miss may not rewrite the perturbed input")

    def test_opt_in_publishes_same_result_and_complete_detached_ordered_profile(self):
        with tempfile.TemporaryDirectory(prefix="cache-admission-detached-") as folder:
            f = self.prepare(folder)
            before = self.protected(f)
            expected = self.expected_profile(f)
            first_out, second_out = {}, {}
            first = self.call_loader(f, out=first_out, observe_payload=True)
            second = self.call_loader(f, out=second_out, observe_payload=True)
            for output, observed in ((first_out, first), (second_out, second)):
                self.assert_successful_call(f, observed)
                self.assertTrue(type(output) is dict and set(output) == {"accepted"}
                                and type(output["accepted"]) is dict
                                and set(output["accepted"]) == {"result", "profile"},
                                "successful output must publish exactly the complete accepted record")
                accepted = output["accepted"]
                self.assertTrue(accepted["result"] is observed["result"],
                                "record must bind the same actual two-item return object")
                self.assertTrue(exact_value(accepted["profile"], expected),
                                "complete ordered profile must match independent PUBLIC literals")
                self.assertTrue(len(observed["payloads"]) == 1,
                                "real accepted profile validator must complete once")
                payload = observed["payloads"][0]
                profile = accepted["profile"]
                self.assertTrue(profile is not payload
                                and profile["services"] is not payload["services"]
                                and profile["services"]["dns"] is not payload["services"]["dns"]
                                and profile["services"]["ntp"] is not payload["services"]["ntp"]
                                and profile["public_keys"] is not payload["public_keys"]
                                and all(a is not b for a, b in
                                        zip(profile["public_keys"], payload["public_keys"])),
                                "published nested containers may not alias real admitted payload")
            self.assertTrue(first_out["accepted"] is not second_out["accepted"]
                            and first_out["accepted"]["profile"] is not second_out["accepted"]["profile"],
                            "independent output dictionaries must not share published records")
            first["payloads"][0]["services"]["dns"][0] = "198.51.100.54"
            first["payloads"][0]["public_keys"][0]["line"] = "PUBLIC changed validator input"
            self.assertTrue(exact_value(first_out["accepted"]["profile"], expected)
                            and exact_value(second_out["accepted"]["profile"], expected),
                            "later mutation of admitted input containers changed detached facts")
            first_out["accepted"]["profile"]["services"]["ntp"].reverse()
            first_out["accepted"]["profile"]["public_keys"][0]["name"] = "PUBLIC changed output"
            self.assertTrue(exact_value(second_out["accepted"]["profile"], expected),
                            "one call's output mutation contaminated another call")
            self.assertTrue(self.protected(f) == before,
                            "profile handoff or RAM observer mutation changed owned files")

    def test_opt_in_real_miss_and_existing_domain_failure_leave_fresh_output_empty(self):
        for case in ("MISSING", "CHECKSUM", "PROFILE-DOMAIN"):
            with self.subTest(miss=case), tempfile.TemporaryDirectory(prefix="cache-admission-miss-") as folder:
                f = self.prepare(folder)
                previous_output = {}
                previous = self.call_loader(f, out=previous_output)
                self.assert_successful_call(f, previous)
                expected = self.expected_profile(f)
                self.assertTrue(type(previous_output) is dict
                                and set(previous_output) == {"accepted"}
                                and type(previous_output["accepted"]) is dict
                                and set(previous_output["accepted"]) == {"result", "profile"}
                                and previous_output["accepted"]["result"] is previous["result"]
                                and exact_value(previous_output["accepted"]["profile"], expected),
                                "same module needs a genuine earlier accepted record, not a mocked stale seed")
                original_cache = base.bound_file(f["cache"])
                if case == "MISSING":
                    # Only this exact freshly created own cache leaf is removed.
                    if f["cache"].parent != f["root"] / "out" or f["cache"].is_symlink():
                        self.prerequisite_hold()
                    f["cache"].unlink()
                elif case == "CHECKSUM":
                    self.corrupt_owned_checksum_input(f)
                else:
                    payload = json.loads(original_cache[1].decode("utf-8"))
                    payload["services"]["dns"] = []
                    raw = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                    f["cache"].write_bytes(raw)
                    f["cache"].with_name(f["cache"].name + ".sha256").write_text(
                        hashlib.sha256(raw).hexdigest() + "  " + f["cache"].name + "\n",
                        encoding="ascii")
                sidecar_before = base.bound_file(f["cache"].with_name(f["cache"].name + ".sha256"))
                cache_before = None if case == "MISSING" else base.bound_file(f["cache"])
                output = {}
                observed = self.call_loader(f, out=output, observe_payload=case == "PROFILE-DOMAIN")
                if case == "PROFILE-DOMAIN":
                    self.assertTrue(len(observed["domains"]) == 1
                                    and type(observed["error"]) is f["app"].SetupError
                                    and observed["error"] is observed["domains"][0]
                                    and observed["result"] is None,
                                    "existing real profile domain failure must propagate unchanged")
                else:
                    self.assertTrue(observed["error"] is None and observed["result"] is None,
                                    "real ordinary miss must retain None result")
                self.assertTrue(type(output) is dict and not output,
                                "failed admission may not publish a stale or partial accepted record")
                self.assertTrue(previous_output["accepted"]["result"] is previous["result"]
                                and exact_value(previous_output["accepted"]["profile"], expected),
                                "later failed load changed an independent earlier record")
                self.assertEqual(dict(validators=0, password_native=0, profile_copy=0, unexpected=0),
                                 observed["calls"])
                self.assertTrue(base.bound_file(f["cache"].with_name(f["cache"].name + ".sha256"))
                                == sidecar_before, "miss modified data sidecar")
                self.assertTrue(not os.path.lexists(f["cache"]) if case == "MISSING"
                                else base.bound_file(f["cache"]) == cache_before,
                                "miss unexpectedly recreated or rewrote cache")

    def test_invalid_output_is_safe_domain_before_any_io_or_native_activity(self):
        class DictSubclass(dict):
            pass
        for case in ("FALSE", "LIST", "DICT-SUBCLASS", "NONEMPTY"):
            with self.subTest(output=case), tempfile.TemporaryDirectory(prefix="cache-admission-invalid-") as folder:
                f = self.prepare(folder)
                app = f["app"]
                before = self.protected(f)
                output = (False if case == "FALSE" else [] if case == "LIST"
                          else DictSubclass() if case == "DICT-SUBCLASS"
                          else {"PUBLIC": "retained"})
                attempts = []
                def forbidden(*args, **kwargs):
                    attempts.append("PUBLIC forbidden IO/native")
                    raise RuntimeError("PUBLIC invalid output reached IO/native")
                caught = None
                returned = None
                with ExitStack() as stack:
                    for owner, name in ((Path, "stat"), (Path, "lstat"),
                                        (Path, "read_bytes"), (Path, "read_text"),
                                        (Path, "open"), (builtins, "open"), (os, "open"),
                                        (app.subprocess, "run"), (app, "verify_password_hash")):
                        stack.enter_context(mock.patch.object(owner, name, new=forbidden))
                    try:
                        returned = app.load_target_cache(
                            f["cache"], f["csv"], f["p2p"], public_key_tool=f["tool"],
                            validate_public_keys_with_ssh_keygen=True,
                            allow_baked_missing_global=False, _admission_out=output)
                    except BaseException as error:
                        caught = error
                self.assertTrue(type(caught) is app.SetupError,
                                "invalid output must raise the exact fixed domain type")
                self.assertTrue(caught.args == SAFE_ARGS and caught.__cause__ is None
                                and caught.__context__ is None,
                                "invalid output diagnostic must be fixed and chain-free")
                self.assertTrue(returned is None and attempts == [],
                                "invalid output may not read files or run native/process boundaries")
                self.assertTrue(output == {"PUBLIC": "retained"} if case == "NONEMPTY"
                                else not output, "invalid output was cleared or partially published")
                self.assertTrue(self.protected(f) == before,
                                "invalid output changed owned inputs")


if __name__ == "__main__":
    unittest.main()
