"""Independent black-box MAIN service/key profile custody workflows.

Real C2, P1/cache, MAIN, policy, native password backend, selector, PTY/frame
and parser execute only when the normal test runner issues these tests. The
borrowed owned remote host and terminal are MODELS, not native SSH proof.
No private-out ABI, snapshot-only acceptance, AUTO/local/missing-global grant.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack
from functools import wraps
import hashlib
import hmac
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_main_caller_precommit as caller

base = caller.base
PROJECT_ERROR = "IB phase project authority failed; device state is UNKNOWN"
PUBLIC_SERVICES = {
    "dns": ["203.0.113.53"],
    "ntp": ["ntp.ubuntu.com", "time.ib.example.test"],
    "timezone": "Asia/Taipei",
}
DNS_REPLACEMENT = "198.51.100.77"
DEVICE_FIELDS = (
    "hostname", "dev_type", "login_ip", "eth0_prefix", "eth0_gateway",
    "eth0_mac", "eth1_prefix", "eth1_gateway",
)
ENTRY_NAMES = (
    "_authenticate_ib_read", "_execute_ib_phase", "run_on_ib",
    "_run_authorized_ib_command", "verify_ipv4_login",
    "verify_password_hash", "confirm_first_device_change",
)
PUBLICATION_LIMIT = 1048576


def _nine(value):
    return tuple(str(part) for part in (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    ))


def _held_regular(path):
    """Owned regular input custody; returned private bytes stay in RAM."""
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid() or before.st_size > PUBLICATION_LIMIT):
        raise RuntimeError("FIXTURE HOLD: owned regular custody unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        if _nine(os.fstat(fd)) != _nine(before):
            raise RuntimeError("FIXTURE HOLD: owned regular identity changed")
        def read():
            chunks, total = [], 0
            while True:
                block = os.read(fd, min(65536, PUBLICATION_LIMIT + 1 - total))
                if not block:
                    break
                total += len(block)
                if total > PUBLICATION_LIMIT:
                    raise RuntimeError("FIXTURE HOLD: owned regular input exceeds cap")
                chunks.append(block)
            if os.read(fd, 1) != b"":
                raise RuntimeError("FIXTURE HOLD: owned regular EOF unavailable")
            return b"".join(chunks)
        body = read()
        os.lseek(fd, 0, os.SEEK_SET)
        if read() != body or not (
                _nine(before) == _nine(os.fstat(fd)) == _nine(path.lstat())):
            raise RuntimeError("FIXTURE HOLD: owned regular read changed")
        return _nine(before), body, hashlib.sha256(body).hexdigest()
    finally:
        os.close(fd)


def _held_alias(path, root):
    before = path.lstat()
    if (not stat.S_ISLNK(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1):
        raise RuntimeError("FIXTURE HOLD: owned declared alias unavailable")
    link = os.readlink(path)
    target = path.resolve(strict=True)
    if not target.is_relative_to(root.resolve(strict=True)):
        raise RuntimeError("FIXTURE HOLD: declared alias escaped owned fixture")
    if _nine(path.lstat()) != _nine(before) or os.readlink(path) != link:
        raise RuntimeError("FIXTURE HOLD: declared alias changed")
    return _nine(before), link, str(target)


def _fingerprint(line):
    # Independent OpenSSH-wire checksum, never the product implementation.
    wire = base64.b64decode(line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b"=").decode("ascii")


def _replacement_key():
    # One independently fixed PUBLIC Ed25519 wire value, no private key.
    wire = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"\x25" * 32
    line = ("ssh-ed25519 " + base64.b64encode(wire).decode("ascii")
            + " PUBLIC-profile-custody-substitution")
    return {"name": "laptop.pub", "line": line, "fingerprint": _fingerprint(line)}


def _target_values(targets):
    return [{
        "ib": {name: getattr(target.ib, name) for name in DEVICE_FIELDS},
        "ethernet": {name: getattr(target.ethernet, name) for name in DEVICE_FIELDS},
        "ethernet_port": target.ethernet_port,
        "ib_port_alias": target.ib_port_alias,
    } for target in targets]


def _differences(left, right, path=()):
    if type(left) is not type(right):
        return [path]
    if type(left) is dict:
        if set(left) != set(right):
            return [path]
        return [part for name in sorted(left)
                for part in _differences(left[name], right[name], path + (name,))]
    if type(left) is list:
        if len(left) != len(right):
            return [path]
        return [part for index, (a, b) in enumerate(zip(left, right))
                for part in _differences(a, b, path + (index,))]
    return [] if left == right else [path]


class MainProfileCustodyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No future custody/private-out API is a fixture prerequisite.
        caller.MainCallerPrecommitDraftTests.setUpClass.__func__(cls)
        cls.replacement = _replacement_key()
        validator = shutil.which("ssh-keygen")
        if validator is None:
            raise RuntimeError("FIXTURE HOLD: real PUBLIC key validator absent")
        failed, probe = False, None
        try:
            probe = subprocess.run(
                [validator, "-l", "-E", "sha256", "-f", "/dev/stdin"],
                input=cls.replacement["line"] + "\n",
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            failed = True
        if (failed or probe is None or probe.returncode != 0
                or len(probe.stdout.splitlines()) != 1
                or cls.replacement["fingerprint"] not in probe.stdout.split()):
            raise RuntimeError("FIXTURE HOLD: independent PUBLIC key not qualified") from None

    # Unbound helpers only; no TestCase inheritance or imported class alias.
    fixed_hold = caller.MainCallerPrecommitDraftTests.fixed_hold
    fixture = caller.MainCallerPrecommitDraftTests.fixture
    events = caller.MainCallerPrecommitDraftTests.events
    invoke = caller.MainCallerPrecommitDraftTests.invoke
    assert_success = caller.MainCallerPrecommitDraftTests.assert_success
    assert_no_new_writes = caller.MainCallerPrecommitDraftTests.assert_no_new_writes

    def _safe_invoke(self, f, *options):
        unexpected, result = None, None
        try:
            result = self.invoke(f, *options)
        except BaseException as error:
            unexpected = error
        # Assertions are outside the exception handler: never print its private
        # args/chain. Unknown program errors are test failure, not safe HOLD.
        self.assertTrue(unexpected is None,
                        "qualified MAIN raised an unexpected program error; details suppressed")
        self.assertTrue(type(result) is dict,
                        "qualified MAIN observer did not return its actual result")
        return result

    @staticmethod
    def _new_witness():
        return dict(consent=[], stage=[], classifier=[], returned_diff=[], diff_entry=[], timeline=[],
                    selector=[], network_constructor=[], helper=[], helper_reads=[], calls=[],
                    native=[], fetch=[], gate=[], slots=[], reaps=[], fixture_reaps=[], product_depth=0)

    def _prepare(self, folder):
        f = self.fixture(folder, case="readonly-initial", credential="initial")
        selected_error, selected = None, None
        try:
            with mock.patch.object(self.c2, "_GLOBAL_FILE", str(f["global_path"])):
                selected = self.c2.load_global("ib")
        except BaseException as error:
            selected_error = error
        self.assertTrue(selected_error is None and type(selected) is dict,
                        "real C2 fixture selection failed; details suppressed")
        self.assertTrue(selected["system"]["dns"]["server"] == ["203.0.113.53"]
                        and selected["system"]["ntp"]["server"] ==
                        ["ntp.ubuntu.com", "time.ib.example.test"]
                        and selected["system"]["date-time"]["timezone"] == "Asia/Taipei",
                        "real C2 did not preserve independent PUBLIC service literals")
        self.assertTrue(hmac.compare_digest(
                            selected["system"]["aaa"]["user"]["admin"]["password"],
                            self.kat["YESCRYPT"]),
                        "real C2 did not select the qualified IB authority; values suppressed")
        p1 = self._safe_invoke(f, "--generate-json")
        self.assert_success(p1)
        self.assertTrue(not p1["hashes"] and "TARGET" not in p1["prompts"],
                        "P1 fixture acquired a target credential")
        f["caller"] = self._new_witness()
        return f

    def _protected(self, f):
        regular = (
            f["source"], f["global_path"], f["csv"], f["p2p"],
            f["root"] / "infra/infra-neutral.conf",
            f["tool"] / "infra-neutral.conf",
            f["root"] / "infiniband/publickey/laptop.pub",
            f["root"] / "infiniband/publickey/mgmt-server.pub",
            f["stub"], f["config"], f["auth"], f["control"], f["cron"],
        )
        links = (f["tool"] / "01-global.yaml", f["tool"] / "publickey")
        return tuple(_held_regular(path) for path in regular), tuple(
            _held_alias(path, f["root"]) for path in links)

    def _delete_owned_cache_pair(self, f):
        cache = f["cache"]
        checksum = cache.with_name(cache.name + ".sha256")
        root = f["root"].resolve(strict=True)
        self.assertTrue(cache.name == "targets.json"
                        and cache.parent.resolve(strict=True) == root / "out",
                        "cache deletion target is not the exact owned fixture data")
        parent = _nine(cache.parent.lstat())[:5]
        first, second = _held_regular(cache), _held_regular(checksum)
        self.assertTrue(_nine(cache.parent.lstat())[:5] == parent,
                        "owned data parent identity changed before deletion")
        self.assertTrue(_nine(cache.lstat()) == first[0]
                        and _nine(checksum.lstat()) == second[0],
                        "owned data identity changed before deletion")
        # Only the requalified two fixture DATA leaves, never a receipt/WAL.
        cache.unlink()
        checksum.unlink()
        self.assertTrue(not os.path.lexists(cache) and not os.path.lexists(checksum),
                        "genuine cache miss was not established")

    def _publish(self, f, observed, case, actual_targets, actual_count):
        cache = f["cache"]
        checksum = cache.with_name(cache.name + ".sha256")
        original = json.loads(_held_regular(cache)[1].decode("utf-8"))
        expected_keys = [
            {"name": name, "line": line.strip(), "fingerprint": _fingerprint(line)}
            for name, line in (("laptop.pub", f["laptop"]),
                               ("mgmt-server.pub", f["management"]))
        ]
        self.assertTrue(original["services"] == PUBLIC_SERVICES
                        and original["public_keys"] == expected_keys,
                        "real first profile differs from independent fixture inputs")
        self.assertTrue(type(actual_count) is int and actual_count == 1
                        and original["ib_candidate_count"] == 1
                        and original["targets"] == _target_values(actual_targets)
                        and len(actual_targets) == 1
                        and original["targets"][0]["ib_port_alias"] == "eth0",
                        "first actual target/count premise is not qualified")
        self.assertTrue(original["global"] == str(f["global_path"].resolve(strict=True))
                        and original["global"] is not None,
                        "first actual present-global premise is not qualified")
        published = json.loads(json.dumps(original))
        paths = []
        if case == "LEGAL_DNS_SUBSTITUTION":
            published["services"]["dns"][0] = DNS_REPLACEMENT
            paths = [("services", "dns", 0)]
        elif case == "PUBLIC_KEY_SUBSTITUTION":
            self.assertTrue(expected_keys[0]["line"] != self.replacement["line"],
                            "independent replacement key is not distinct")
            published["public_keys"][0] = dict(self.replacement)
            paths = [("public_keys", 0, "fingerprint"), ("public_keys", 0, "line")]
        self.assertTrue(_differences(original, published) == paths,
                        "controlled publication changed unrelated semantic fields")
        self.assertTrue(all(original[name] == published[name] for name in
                            ("targets", "ib_candidate_count", "global", "cache_authority",
                             "ib_csv", "p2p", "version", "generated_at")),
                        "controlled publication changed input/target authority")
        raw = (json.dumps(published, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        checksum.write_text(hashlib.sha256(raw).hexdigest() + "  " + cache.name + "\n",
                            encoding="ascii")
        observed["publication"] = (_held_regular(cache), _held_regular(checksum))
        fields = observed["publication"][1][1].decode("ascii").split()
        self.assertTrue(fields == [hashlib.sha256(raw).hexdigest(), cache.name]
                        and observed["publication"][0][1] == raw
                        and int(observed["publication"][0][0][7]) <=
                        int(observed["publication"][1][0][7]),
                        "controlled data sidecar/mtime qualification failed")
        # Declared extra pure qualification, not a fake validator return.
        observed["authority"] = f["app"]._valid_cache_authority(
            published, f["csv"], f["p2p"], f["tool"] / "01-global.yaml")
        self.assertTrue(observed["authority"] is True,
                        "controlled publication lost actual input authority")
        observed["profile_changed"] = (
            (published["services"], published["public_keys"]) !=
            (original["services"], original["public_keys"]))
        observed["published"] += 1

    def _one_case(self, branch, case):
        with tempfile.TemporaryDirectory(prefix="main-profile-custody-") as folder:
            f = self._prepare(folder)
            app = f["app"]
            protected = self._protected(f)
            if branch == "GENUINE_GENERATE":
                self._delete_owned_cache_pair(f)
                self.assertTrue(self._protected(f) == protected,
                                "cache-miss setup changed protected real inputs")
            before = self.events(f)
            entries = {name: 0 for name in ENTRY_NAMES}
            entries["policy.password"] = 0
            observed = dict(loads=0, saves=0, actual_miss=0, actual_success=0,
                            published=0, publication=None, authority=None,
                            profile_changed=None,
                            actual_result=None, target_reference=None,
                            target_snapshot=None, producer_profile=False)
            real_load, real_save = app.load_target_cache, app.save_target_cache

            def require(value):
                # Independent fixture is already qualified. A real loader or
                # writer regression here is behavior failure, never fixture HOLD.
                self.assertTrue(value,
                                "qualified actual cache path did not match its independent setup")

            @wraps(real_load)
            def load(*args, **kwargs):
                observed["loads"] += 1
                result = real_load(*args, **kwargs)
                require(observed["loads"] == 1)
                if branch == "GENUINE_GENERATE":
                    require(result is None)
                    observed["actual_miss"] += 1
                else:
                    require(type(result) is tuple and len(result) == 2
                            and type(result[0]) is int and type(result[1]) is list)
                    observed["actual_success"] += 1
                    observed["actual_result"] = result
                    observed["target_reference"] = result[1]
                    observed["target_snapshot"] = _target_values(result[1])
                    self._publish(f, observed, case, result[1], result[0])
                # The real actual result object, including genuine None.
                return result

            @wraps(real_save)
            def save(*args, **kwargs):
                observed["saves"] += 1
                bound = inspect.signature(real_save).bind(*args, **kwargs).arguments
                require(branch == "GENUINE_GENERATE" and observed["saves"] == 1
                        and observed["actual_miss"] == 1)
                producer_profile = json.loads(json.dumps({
                    "services": bound["services"], "public_keys": bound["public_keys"],
                }))
                result = real_save(*args, **kwargs)
                generated = json.loads(_held_regular(f["cache"])[1].decode("utf-8"))
                observed["producer_profile"] = (
                    producer_profile == {"services": generated["services"],
                                         "public_keys": generated["public_keys"]})
                require(observed["producer_profile"])
                observed["target_reference"] = bound["targets"]
                observed["target_snapshot"] = _target_values(bound["targets"])
                self._publish(f, observed, case, bound["targets"], bound["ib_candidate_count"])
                return result

            def observer(name, function):
                @wraps(function)
                def call(*args, **kwargs):
                    entries[name] += 1
                    return function(*args, **kwargs)
                return call

            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(app, "load_target_cache", new=load))
                stack.enter_context(mock.patch.object(app, "save_target_cache", new=save))
                for name in ENTRY_NAMES:
                    stack.enter_context(mock.patch.object(
                        app, name, new=observer(name, getattr(app, name))))
                stack.enter_context(mock.patch.object(
                    app.ProjectPasswordPolicy, "password",
                    new=observer("policy.password", app.ProjectPasswordPolicy.password)))
                result = self._safe_invoke(f)

            # All private byte comparisons use safe boolean diagnostics.
            self.assertTrue(self._protected(f) == protected,
                            "MAIN changed a protected input/foreign control")
            self.assertTrue(observed["publication"] is not None
                            and (_held_regular(f["cache"]),
                                 _held_regular(f["cache"].with_name(f["cache"].name + ".sha256"))) ==
                            observed["publication"],
                            "MAIN changed controlled cache/data sidecar after publication")
            self.assertTrue(observed["loads"] == 1 and observed["published"] == 1
                            and observed["authority"] is True,
                            "actual cache handoff/publication witness missing")
            self.assertTrue(type(observed["target_reference"]) is list
                            and _target_values(observed["target_reference"]) ==
                            observed["target_snapshot"],
                            "actual admitted/produced Target objects were changed")
            self.assertTrue(branch != "REUSE" or
                            (type(observed["actual_result"]) is tuple
                             and observed["actual_result"][1] is observed["target_reference"]),
                            "original actual loader result reference was not retained")
            self.assertTrue((branch == "REUSE" and observed["actual_success"] == 1
                             and observed["actual_miss"] == 0 and observed["saves"] == 0)
                            or (branch == "GENUINE_GENERATE" and observed["actual_miss"] == 1
                                and observed["actual_success"] == 0 and observed["saves"] == 1
                                and observed["producer_profile"] is True),
                            "actual reuse/miss/producer path was not reached")
            fresh = self.events(f)[len(before):]
            self.assertTrue(not any(event["kind"] in
                            ("mutation", "apply-y", "save", "key-shell", "ipv4-read", "pam-target")
                            for event in fresh),
                            "check-only profile custody performed a business write")
            self.assertTrue(not any(path.exists() for path in
                            (f["credentials"], f["marker"], f["terminal"])),
                            "check-only profile custody persisted credentials/watch/terminal state")
            self.assertTrue(not result["hashes"] and "TARGET" not in result["prompts"],
                            "profile custody acquired native/Target permission")
            if case == "MATCH":
                self.assertTrue(observed["profile_changed"] is False,
                                "matching control changed the profile")
                self.assert_success(result)
                self.assertTrue(len(f["caller"]["selector"]) == 1
                                and f["caller"]["selector"][0]["initial"] is True
                                and f["caller"]["selector"][0]["target"] is False,
                                "matching control did not select actual INITIAL current")
                self.assertTrue(f["caller"]["timeline"] ==
                                ["selector-return", "diff-entry", "diff-return"],
                                "matching control did not perform one actual readonly report")
                self.assertTrue(len(f["caller"]["returned_diff"]) == 1
                                and f["caller"]["returned_diff"][0]["rc"] == 0
                                and f["caller"]["returned_diff"][0]["empty"] is True
                                and f["caller"]["returned_diff"][0]["initial"] is True,
                                "matching control readonly report was not qualified")
            else:
                self.assertTrue(observed["profile_changed"] is True,
                                "negative control did not substitute a legal profile")
                error = result["error"]
                self.assertTrue(type(error) is app.SetupError
                                and error.args == (PROJECT_ERROR,)
                                and error.__cause__ is None and error.__context__ is None,
                                "profile mismatch did not yield the fixed chain-free project error")
                self.assertTrue(all(value == 0 for value in entries.values()),
                                "profile mismatch reached an IB/native/Target/consent entry")
                self.assertTrue(not any(event["kind"] in
                                ("nested-dispatch", "inner-answer", "inner-rejected",
                                 "pam-start", "pam-readonly-refusal", "non-auth-refusal",
                                 "caller-show", "caller-diff")
                                for event in fresh),
                                "profile mismatch reached an actual inner transport boundary")
                self.assertTrue(not f["caller"]["selector"] and not f["caller"]["calls"]
                                and not f["caller"]["fetch"] and not f["caller"]["native"]
                                and not f["caller"]["consent"],
                                "profile mismatch acquired actual business capability")
            self.assertTrue(not any(secret in result["stdout"] + result["stderr"]
                                    for secret in (self.kat["PASSWORD"], self.kat["SHA512"],
                                                   self.kat["YESCRYPT"],
                                                   base.PUBLIC_INITIAL, base.PUBLIC_OOB)),
                            "profile-custody diagnostics leaked private values")

    def test_reused_profile_is_not_replaced_by_second_payload(self):
        for case in ("MATCH", "LEGAL_DNS_SUBSTITUTION", "PUBLIC_KEY_SUBSTITUTION"):
            with self.subTest(case=case):
                self._one_case("REUSE", case)

    def test_genuinely_generated_profile_is_not_replaced_by_second_payload(self):
        for case in ("MATCH", "LEGAL_DNS_SUBSTITUTION", "PUBLIC_KEY_SUBSTITUTION"):
            with self.subTest(case=case):
                self._one_case("GENUINE_GENERATE", case)


if __name__ == "__main__":
    unittest.main()
