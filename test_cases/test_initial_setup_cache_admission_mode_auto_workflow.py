"""Manual mode-auto uses each actual cache admission, not a stale first one.

Only the normal runner may execute these two owned C2/P1/MAIN workflows.
Hostname facts and own cache publication/invalidation are explicit MODELS.
Loader, local selection, producers, save, selector, PTY and DIFF stay real.
"""
from __future__ import annotations
from test_cases.private_public_fixture_input import require_fixture_value as _private_fixture_value

import ast
from contextlib import ExitStack
from functools import wraps
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases import test_initial_setup_main_caller_precommit as caller
from test_cases import test_initial_setup_main_profile_custody as custody

base = caller.base
DIFF = ["nv", "config", "diff", "-o", "commands"]
PUBLIC_HOST = "PUBLIC-MANAGEMENT"
PUBLIC_FQDN = "PUBLIC-MANAGEMENT.invalid"
KEY_LITERALS = (
    ("laptop.pub",
     _private_fixture_value("cache_admission_key_0"),
     "SHA256:SQfC+vTbLURn9cTkVxIS8fGQ3FKNAJWeB0o139+gV4M"),
    ("mgmt-server.pub",
     _private_fixture_value("cache_admission_key_1"),
     "SHA256:d1XG1idLGWKZW03ZMN9Xy/UxG8gtz+7myOGwwkmitNo"),
)
# Table 6-1 row 6 (guide :749): a v15 cache-version-5 target record carries login_interface
# (v15 CURRENT-CONTRACT.md:20); both rows log in through their CSV eth0 address (RUNBOOK.md:22).
TARGET_LITERAL = [{
    "ib": {
        "hostname": "EXAMPLE-IB01", "dev_type": "ib",
        "login_ip": "203.0.113.2", "eth0_prefix": "203.0.113.2/24",
        "eth0_gateway": "203.0.113.1", "eth0_mac": "02:00:00:00:00:17",
        "eth1_prefix": "", "eth1_gateway": "", "login_interface": "eth0",
    },
    "ethernet": {
        "hostname": "EXAMPLE-JUMP01", "dev_type": "eth_jump",
        "login_ip": "192.0.2.10", "eth0_prefix": "192.0.2.10",
        "eth0_gateway": "", "eth0_mac": "", "eth1_prefix": "", "eth1_gateway": "",
        "login_interface": "eth0",
    },
    "ethernet_port": "swp7", "ib_port_alias": "eth0",
}]


def _profile(dns):
    # Independent complete PUBLIC input literals; never product profile output.
    return {
        "services": {
            "dns": [dns],
            "ntp": ["ntp.ubuntu.com", "time.ib.example.test"],
            "timezone": "Asia/Taipei",
        },
        "public_keys": [
            {"name": name, "line": line, "fingerprint": fingerprint}
            for name, line, fingerprint in KEY_LITERALS
        ],
    }


class CacheAdmissionModeAutoWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if custody.base is not base:
            raise RuntimeError("FIXTURE HOLD: canonical helper receiver differs") from None
        tree = ast.parse(base.bound_file(base.INITIAL)[1], filename=str(base.INITIAL))
        loader = next((node for node in tree.body
                       if isinstance(node, ast.FunctionDef)
                       and node.name == "load_target_cache"), None)
        defaults = ({} if loader is None else
                    dict(zip((arg.arg for arg in loader.args.kwonlyargs),
                             loader.args.kw_defaults)))
        value = defaults.get("_admission_out")
        if not isinstance(value, ast.Constant) or value.value is not None:
            raise RuntimeError("FIXTURE HOLD: private cache admission ABI NOT_READY") from None
        caller.MainCallerPrecommitDraftTests.setUpClass.__func__(cls)

    # Explicit unbound helper receiver closure, never TestCase inheritance.
    fixed_hold = caller.MainCallerPrecommitDraftTests.fixed_hold
    fixture = caller.MainCallerPrecommitDraftTests.fixture
    events = caller.MainCallerPrecommitDraftTests.events
    invoke = caller.MainCallerPrecommitDraftTests.invoke
    assert_success = caller.MainCallerPrecommitDraftTests.assert_success
    _safe_invoke = custody.MainProfileCustodyWorkflowTests._safe_invoke
    _prepare = custody.MainProfileCustodyWorkflowTests._prepare
    _protected = custody.MainProfileCustodyWorkflowTests._protected

    @staticmethod
    def _new_witness():
        witness = custody.MainProfileCustodyWorkflowTests._new_witness()
        witness.update(helper_all=[], helper_metadata=[], metadata_gate=[])
        return witness

    def _check_profile(self, value, dns):
        self.assertTrue(
            type(value) is dict and set(value) == {"services", "public_keys"}
            and type(value["services"]) is dict
            and set(value["services"]) == {"dns", "ntp", "timezone"}
            and type(value["services"]["dns"]) is list
            and type(value["services"]["ntp"]) is list
            and all(type(item) is str for item in value["services"]["dns"])
            and all(type(item) is str for item in value["services"]["ntp"])
            and type(value["services"]["timezone"]) is str
            and type(value["public_keys"]) is list
            and all(type(entry) is dict
                    and set(entry) == {"name", "line", "fingerprint"}
                    and all(type(part) is str for part in entry.values())
                    for entry in value["public_keys"]),
            "actual complete profile has an unqualified type/shape")
        self.assertTrue(value == _profile(dns),
                        "actual complete profile differs from independent PUBLIC literals")

    def _cache_pair(self, f):
        cache = f["cache"]
        checksum = cache.with_name(cache.name + ".sha256")
        self.assertTrue(cache.name == "targets.json"
                        and cache.parent.resolve(strict=True) ==
                        f["root"].resolve(strict=True) / "out",
                        "cache leaves are not the exact owned data pair")
        return cache, checksum

    def _write_existing(self, path, before, raw):
        # Only an already-qualified own data leaf: no truncate before FD match.
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            self.assertTrue(custody._nine(os.fstat(fd)) == before[0],
                            "owned publication FD differs from qualified leaf")
            os.ftruncate(fd, 0)
            position = 0
            while position < len(raw):
                count = os.write(fd, raw[position:])
                self.assertTrue(count > 0, "owned publication write made no progress")
                position += count
            os.fsync(fd)
            finished = custody._nine(os.fstat(fd))
            self.assertTrue(finished[:6] == before[0][:6]
                            and int(finished[6]) == len(raw),
                            "owned publication changed leaf identity or size")
        finally:
            os.close(fd)
        result = custody._held_regular(path)
        self.assertTrue(result[0] == finished and result[1] == raw,
                        "owned publication readback differs from real FD write")
        return result

    def _publish_dns(self, f, previous, wanted):
        cache, checksum = self._cache_pair(f)
        pair = custody._held_regular(cache), custody._held_regular(checksum)
        parent = custody._nine(cache.parent.lstat())[:5]
        payload = json.loads(pair[0][1].decode("utf-8"))
        self._check_profile(
            {"services": payload["services"], "public_keys": payload["public_keys"]},
            previous)
        self.assertTrue(type(payload["ib_candidate_count"]) is int
                        and payload["ib_candidate_count"] == 1
                        and payload["targets"] == TARGET_LITERAL
                        and payload["global"] == str(f["global_path"].resolve(strict=True)),
                        "owned publication lost independent target/global premise")
        replacement = json.loads(json.dumps(payload))
        replacement["services"]["dns"][0] = wanted
        self.assertTrue(custody._differences(payload, replacement)
                        == [("services", "dns", 0)],
                        "controlled publication changed unrelated fields")
        raw = (json.dumps(replacement, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        side = (hashlib.sha256(raw).hexdigest() + "  " + cache.name + "\n").encode("ascii")
        written = (self._write_existing(cache, pair[0], raw),
                   self._write_existing(checksum, pair[1], side))
        self.assertTrue(custody._nine(cache.parent.lstat())[:5] == parent
                        and int(written[0][0][7]) <= int(written[1][0][7])
                        and written[1][1].decode("ascii").split()
                        == [hashlib.sha256(written[0][1]).hexdigest(), cache.name],
                        "owned publication parent/sidecar timing or checksum differs")
        self._check_profile(
            {"services": replacement["services"], "public_keys": replacement["public_keys"]},
            wanted)
        return written

    def _remove_sidecar(self, f, expected_pair):
        cache, checksum = self._cache_pair(f)
        parent = custody._nine(cache.parent.lstat())[:5]
        self.assertTrue((custody._held_regular(cache), custody._held_regular(checksum))
                        == expected_pair,
                        "own sidecar invalidation premise changed")
        self.assertTrue(custody._nine(checksum.lstat()) == expected_pair[1][0],
                        "own sidecar name rebound before unlink")
        checksum.unlink()
        self.assertTrue(not os.path.lexists(checksum)
                        and custody._held_regular(cache) == expected_pair[0]
                        and custody._nine(cache.parent.lstat())[:5] == parent,
                        "actual own sidecar miss was not isolated")

    def _exercise(self, second_miss):
        with tempfile.TemporaryDirectory(prefix="cache-admission-mode-auto-") as folder:
            f = self._prepare(folder)
            custody.MainProfileCustodyWorkflowTests._model_readonly_key_peer(self, f)
            app = f["app"]
            protected = self._protected(f)
            # Actual P1 produced B. A is only a lawful owned cache publication.
            pair_a = self._publish_dns(f, "203.0.113.53", "203.0.113.54")
            self.assertTrue(self._protected(f) == protected,
                            "first cache setup changed a protected real input")
            before = self.events(f)
            observed = dict(timeline=[], loads=[], local=[], parsed=[], early_devices=[], late_devices=[], late_links=[],
                            saves=0, second_none=False, devices=None, links=None,
                            produced=None, producer_services=None, producer_keys=None,
                            before_save=None, final_pair=None, errors=[], diff=None,
                            role_result=None, role_local=None, selection_entry=[], key_receipts=[], records=[])
            real_parse, real_load = app.parse_args, app.load_target_cache
            real_local, real_save = app.local_ethernet_keys, app.save_target_cache
            real_devices, real_p2p, real_build = app.load_devices, app.parse_p2p, app.build_targets
            real_services, real_keys = app._service_profile, app._public_key_profile
            real_select, real_ib = app._authenticate_ib_read, app.run_on_ib
            real_execute = app.execute_ib_task

            def require(value):
                self.assertTrue(value,
                                "qualified actual mode-auto branch did not reach its independent premise")

            def guarded(name, implementation, original):
                @wraps(original)
                def call(*args, **kwargs):
                    try:
                        return implementation(*args, **kwargs)
                    except BaseException as error:
                        observed["errors"].append((name, type(error).__name__))
                        raise
                return call

            def parse(*args, **kwargs):
                value = real_parse(*args, **kwargs)
                observed["parsed"].append(value)
                # v3.1.3 guide table 4-2: --auto and --credentials-file are deleted (O3), so
                # "no watch, no credential file" is now their absence from the parsed options.
                require(value.execution_mode == "auto" and "auto" not in vars(value)
                        and value.apply is False and value.yes is False
                        and "credentials_file" not in vars(value)
                        and value.local_ethernet_hostname == "")
                observed["timeline"].append("parse-return")
                return value

            def load(*args, **kwargs):
                bound = inspect.signature(real_load).bind(*args, **kwargs).arguments
                if "_admission_out" not in bound:
                    # v6 preflight establishes physical role; it is not a profile admission.
                    require(set(bound) == {"cache_path", "ib_csv", "p2p"}
                            and observed["role_result"] is None and not observed["loads"]
                            and bound["cache_path"] == f["cache"].resolve(strict=True)
                            and bound["ib_csv"] == f["csv"].resolve(strict=True)
                            and bound["p2p"] == f["p2p"].resolve(strict=True)
                            and json.loads(pair_a[0][1])["version"] == 6)
                    observed["timeline"].append("role-load-entry")
                    result = real_load(*args, **kwargs)
                    require(type(result) is tuple and len(result) == 2
                            and type(result[0]) is int and result[0] == 1
                            and type(result[1]) is list
                            and custody._target_values(result[1]) == TARGET_LITERAL)
                    observed["role_result"] = result
                    observed["timeline"].append("role-load-return-v6")
                    return result
                out = bound.get("_admission_out")
                number = len(observed["loads"]) + 1
                require(type(observed["role_local"]) is set and not observed["role_local"]
                        and len(observed["early_devices"]) == 1 and observed["early_devices"][0]["returned"]
                        and number in (1, 2) and type(out) is dict and not out
                        and bound["cache_path"] == f["cache"].resolve(strict=True)
                        and bound["ib_csv"] == f["csv"].resolve(strict=True)
                        and bound["p2p"] == f["p2p"].resolve(strict=True)
                        and bound["public_key_tool"] == f["tool"].resolve(strict=True)
                        and bound["validate_public_keys_with_ssh_keygen"] is (number == 2)
                        and bound["allow_baked_missing_global"] is (number == 1))
                if number == 2:
                    require(out is not observed["loads"][0]["out"])
                record = dict(out=out, result=None, returned=False)
                observed["loads"].append(record)
                observed["timeline"].append("first-load-entry" if number == 1
                                            else "second-load-entry")
                result = real_load(*args, **kwargs)
                record["result"], record["returned"] = result, True
                if number == 2 and second_miss:
                    require(result is None and out == {})
                    observed["second_none"] = True
                    observed["timeline"].append("second-load-return-None-empty-out")
                    return result
                require(type(result) is tuple and len(result) == 2
                        and type(result[0]) is int and result[0] == 1
                        and type(result[1]) is list
                        and custody._target_values(result[1]) == TARGET_LITERAL
                        and set(out) == {"accepted"}
                        and type(out["accepted"]) is dict
                        and set(out["accepted"]) == {"result", "profile"}
                        and out["accepted"]["result"] is result)
                self._check_profile(out["accepted"]["profile"],
                                    "203.0.113.54" if number == 1 else "203.0.113.53")
                observed["timeline"].append("first-load-return-A" if number == 1
                                            else "second-load-return-B")
                if number == 1:
                    if second_miss:
                        self._remove_sidecar(f, pair_a)
                        observed["timeline"].append("own-sidecar-unlink")
                    else:
                        observed["final_pair"] = self._publish_dns(
                            f, "203.0.113.54", "203.0.113.53")
                        observed["timeline"].append("publish-B")
                else:
                    require(result is not observed["loads"][0]["result"]
                            and result[1] is not observed["loads"][0]["result"][1])
                return result

            def local(*args, **kwargs):
                bound = inspect.signature(real_local).bind(*args, **kwargs).arguments
                if observed["role_local"] is None:
                    role = observed["role_result"]
                    require(role is not None and not observed["loads"]
                            and bound["mode"] == "auto" and bound["override"] == ""
                            and bound["targets"] is role[1]
                            and custody._target_values(bound["targets"]) == TARGET_LITERAL)
                    result = real_local(*args, **kwargs)
                    require(type(result) is set and not result)
                    observed["role_local"] = result
                    observed["timeline"].append("role-local-return-empty")
                    return result
                number = len(observed["local"]) + 1
                require(number in (1, 2) and bound["mode"] == "auto" and bound["override"] == "")
                expected = (observed["loads"][0]["result"][1] if number == 1 else
                            observed["produced"] if second_miss else
                            observed["loads"][1]["result"][1])
                require(bound["targets"] is expected
                        and custody._target_values(bound["targets"]) == TARGET_LITERAL)
                result = real_local(*args, **kwargs)
                require(type(result) is set and not result)
                observed["local"].append(dict(targets=bound["targets"], result=result))
                observed["timeline"].append("local-for-cache-return-empty" if number == 1
                                            else "late-local-return-empty")
                return result

            def devices(*args, **kwargs):
                if observed["role_local"] is not None and not observed["loads"]:
                    bound = inspect.signature(real_devices).bind(*args, **kwargs).arguments
                    self.assertTrue(
                        set(bound) == {"path"} and bound["path"] == f["csv"].resolve(strict=True)
                        and not observed["role_local"] and not observed["early_devices"]
                        and observed["devices"] is None and not observed["late_devices"]
                        and observed["timeline"][-1] == "role-local-return-empty",
                        "managerial device selection must read the pinned CSV once before either profile admission")
                    record = dict(path=bound["path"], result=None, returned=False)
                    observed["early_devices"].append(record)
                    observed["timeline"].append("early-selection-csv-entry")
                    result = real_devices(*args, **kwargs)
                    require(type(result) is tuple and len(result) == 2
                            and all(type(group) is dict for group in result)
                            and [{name: getattr(device, name) for name in custody.DEVICE_FIELDS}
                                 for device in result[0].values()] == [TARGET_LITERAL[0]["ib"]]
                            and [{name: getattr(device, name) for name in custody.DEVICE_FIELDS}
                                 for device in result[1].values()] == [TARGET_LITERAL[0]["ethernet"]])
                    record.update(result=result, returned=True)
                    observed["timeline"].append("early-selection-csv-return")
                    return result
                if len(observed["local"]) == 2:
                    # After the cache path is settled, v15 main re-reads the same CSV once for the
                    # transit inventory it routes Jumps with (v15 main :5681
                    # `_, transit_inventory = load_devices(ib_csv_path)`); it is not the cache
                    # producer.  Only that one read is let through; every read is recorded (06
                    # WP6-06), and a further one is answered from it without reading the CSV, so the
                    # run finishes and the count check below names it.
                    record = dict(result=None, returned=False)
                    observed["late_devices"].append(record)
                    if len(observed["late_devices"]) > 1:
                        record["result"] = observed["late_devices"][0]["result"]
                        return record["result"]
                    record["result"], record["returned"] = real_devices(*args, **kwargs), True
                    observed["timeline"].append("late-transit-devices-return")
                    return record["result"]
                require(second_miss and observed["second_none"] and observed["devices"] is None)
                result = real_devices(*args, **kwargs)
                require(type(result) is tuple and len(result) == 2)
                observed["devices"] = result
                observed["timeline"].append("producer-devices-return")
                return result

            def p2p(*args, **kwargs):
                if len(observed["local"]) == 2:
                    # D1b MAIN reads live cascade links after the pinned transit CSV.
                    # This is a separate real parse, never a cache producer or its memoized result.
                    bound = inspect.signature(real_p2p).bind(*args, **kwargs).arguments
                    self.assertTrue(
                        set(bound) == {"path"}
                        and bound["path"] == f["p2p"].resolve(strict=True)
                        and len(observed["late_devices"]) == 1
                        and observed["late_devices"][0]["returned"]
                        and not observed["late_links"]
                        and not f["caller"]["selector"]
                        and observed["timeline"][-1] == "late-transit-devices-return",
                        "late routing P2P must parse the same pinned path once after transit CSV and before selection")
                    record = dict(path=bound["path"], result=None, returned=False)
                    observed["late_links"].append(record)
                    observed["timeline"].append("late-routing-p2p-entry")
                    result = real_p2p(*args, **kwargs)
                    require(type(result) is list and all(type(link) is app.Link for link in result))
                    record.update(result=result, returned=True)
                    observed["timeline"].append("late-routing-p2p-return")
                    return result
                require(second_miss and observed["devices"] is not None and observed["links"] is None)
                result = real_p2p(*args, **kwargs)
                observed["links"] = result
                observed["timeline"].append("producer-p2p-return")
                return result

            def build(*args, **kwargs):
                bound = inspect.signature(real_build).bind(*args, **kwargs).arguments
                require(second_miss and bound["links"] is observed["links"]
                        and bound["ib_devices"] is observed["devices"][0]
                        and bound["eth_devices"] is observed["devices"][1])
                result = real_build(*args, **kwargs)
                require(type(result) is list and custody._target_values(result) == TARGET_LITERAL
                        and result is not observed["loads"][0]["result"][1])
                observed["produced"] = result
                observed["timeline"].append("producer-targets-return")
                return result

            def services(*args, **kwargs):
                require(second_miss and observed["produced"] is not None
                        and observed["producer_services"] is None)
                result = real_services(*args, **kwargs)
                require(result == _profile("203.0.113.53")["services"])
                observed["producer_services"] = result
                observed["timeline"].append("producer-services-return-B")
                return result

            def keys(*args, **kwargs):
                result = real_keys(*args, **kwargs)
                if observed["second_none"]:
                    require(second_miss and observed["producer_services"] is not None
                            and observed["producer_keys"] is None)
                    require(result == _profile("203.0.113.53")["public_keys"])
                    observed["producer_keys"] = result
                    observed["timeline"].append("producer-keys-return")
                return result

            def save(*args, **kwargs):
                bound = inspect.signature(real_save).bind(*args, **kwargs).arguments
                require(second_miss and observed["second_none"] and observed["saves"] == 0
                        and bound["targets"] is observed["produced"]
                        and bound["cache_path"] == f["cache"].resolve(strict=True)
                        and bound["ib_csv"] == f["csv"].resolve(strict=True)
                        and bound["p2p"] == f["p2p"].resolve(strict=True)
                        and bound["global_file"] == f["tool"].resolve(strict=True) / "01-global.yaml"
                        and type(bound["ib_candidate_count"]) is int
                        and bound["ib_candidate_count"] == 1
                        and bound["services"] is observed["producer_services"]
                        and bound["public_keys"] is observed["producer_keys"])
                before_save = {"services": bound["services"], "public_keys": bound["public_keys"]}
                self._check_profile(before_save, "203.0.113.53")
                observed["before_save"] = json.loads(json.dumps(before_save))
                observed["saves"] += 1
                observed["timeline"].append("save-entry-B")
                result = real_save(*args, **kwargs)
                require(result is None)
                observed["timeline"].append("save-normal-return")
                cache, checksum = self._cache_pair(f)
                observed["final_pair"] = custody._held_regular(cache), custody._held_regular(checksum)
                payload = json.loads(observed["final_pair"][0][1].decode("utf-8"))
                self._check_profile(
                    {"services": payload["services"], "public_keys": payload["public_keys"]},
                    "203.0.113.53")
                require(observed["before_save"]
                        == {"services": payload["services"], "public_keys": payload["public_keys"]}
                        and payload["targets"] == TARGET_LITERAL)
                return result

            def select(*args, **kwargs):
                observed["selection_entry"].append(
                    (len(f["caller"]["native"]), len(f["caller"]["fetch"])))
                result = real_select(*args, **kwargs)
                observed["timeline"].append("selector-return")
                return result

            def ib(*args, **kwargs):
                bound = inspect.signature(real_ib).bind(*args, **kwargs).arguments
                is_diff = bound["ib_command"] == DIFF
                if is_diff:
                    observed["timeline"].append("diff-entry")
                result = real_ib(*args, **kwargs)
                if bound["ib_command"][:2] == ["sh", "-c"]:
                    self.assertTrue(type(result) is app.SessionResult
                                    and type(result.exit_code) is int and result.exit_code == 34
                                    and result.output == "" and not observed["key_receipts"],
                                    "the sole sealed readonly key check must return exact empty rc34")
                    observed["key_receipts"].append(result.exit_code)
                if is_diff:
                    require(observed["diff"] is None)
                    observed["diff"] = result
                    observed["timeline"].append("diff-return")
                return result

            def execute(*args, **kwargs):
                record = real_execute(*args, **kwargs)
                observed["records"].append(record)
                return record

            with ExitStack() as stack:
                for name, implementation, original in (
                    ("parse_args", parse, real_parse),
                    ("load_target_cache", load, real_load),
                    ("local_ethernet_keys", local, real_local),
                    ("load_devices", devices, real_devices), ("parse_p2p", p2p, real_p2p),
                    ("build_targets", build, real_build), ("_service_profile", services, real_services),
                    ("_public_key_profile", keys, real_keys), ("save_target_cache", save, real_save),
                    ("_authenticate_ib_read", select, real_select), ("run_on_ib", ib, real_ib),
                    ("execute_ib_task", execute, real_execute),
                ):
                    stack.enter_context(mock.patch.object(
                        app, name, new=guarded(name, implementation, original)))
                # Explicit external identity MODEL, not a fake local-core result.
                stack.enter_context(mock.patch.object(app.socket, "gethostname", return_value=PUBLIC_HOST))
                stack.enter_context(mock.patch.object(app.socket, "getfqdn", return_value=PUBLIC_FQDN))
                result = self._safe_invoke(f, "--execution-mode", "auto")

            self.assertTrue(len(observed["early_devices"]) == 1
                            and observed["early_devices"][0]["returned"]
                            and observed["early_devices"][0]["path"] == f["csv"].resolve(strict=True)
                            and observed["early_devices"][0]["result"] is not observed["devices"],
                            "the one real managerial selection read must remain separate from any producer")
            # v15 main :5681: after the cache is settled the CSV is re-read exactly once (06 WP6-06).
            self.assertEqual(1, len(observed["late_devices"]),
                             "main re-reads the CSV exactly once after the cache is settled")
            self.assertTrue(observed["late_devices"][0]["returned"], "the one re-read returned")
            self.assertIsNot(observed["early_devices"][0]["result"], observed["late_devices"][0]["result"],
                             "early selection must not substitute the later transit CSV read")
            self.assertEqual(1, len(observed["late_links"]),
                             "late routing parses the same pinned P2P exactly once, independently of cache production")
            self.assertTrue(observed["late_links"][0]["returned"]
                            and observed["late_links"][0]["path"] == f["p2p"].resolve(strict=True)
                            and observed["late_links"][0]["result"] is not observed["links"],
                            "late routing must use its real parse result, not the producer's memoized links")
            self.assertTrue(observed["errors"] == [],
                            "observer fault must not become product rejection or PASS")
            # Table 6-1 row 11 (guide :754; v15 CURRENT-CONTRACT.md:67): the readonly run still
            # has public keys to install, so it ends INCOMPLETE (2).
            self.assertTrue(result["error"] is None and result["rc"] == 2,
                            "readonly mode-auto with remaining work must end INCOMPLETE (2)")
            self.assertTrue(len(observed["parsed"]) == 1
                            and len(observed["loads"]) == 2 and len(observed["local"]) == 2
                            and all(item["returned"] for item in observed["loads"]),
                            "two real loader/local paths did not complete")
            first, second = observed["loads"]
            self.assertTrue(observed["role_result"] is not first["result"]
                            and observed["role_result"] is not second["result"]
                            and type(observed["role_local"]) is set and not observed["role_local"],
                            "the real v6 role probe is separate from either profile admission")
            self.assertTrue(first["out"] is not second["out"]
                            and first["out"]["accepted"]["result"] is first["result"],
                            "first receiver/result identity changed after second attempt")
            self._check_profile(first["out"]["accepted"]["profile"], "203.0.113.54")
            self.assertTrue(custody._target_values(first["result"][1]) == TARGET_LITERAL
                            and all(custody._target_values(item["targets"]) == TARGET_LITERAL
                                    for item in observed["local"]),
                            "actual first/final producer or loader Targets changed after use")
            self.assertTrue(self._protected(f) == protected,
                            "mode-auto changed a protected real input or foreign control")
            cache, checksum = self._cache_pair(f)
            self.assertTrue(observed["final_pair"] is not None
                            and (custody._held_regular(cache), custody._held_regular(checksum))
                            == observed["final_pair"],
                            "late MAIN read changed the complete final publication")
            final_payload = json.loads(observed["final_pair"][0][1].decode("utf-8"))
            self._check_profile(
                {"services": final_payload["services"], "public_keys": final_payload["public_keys"]},
                "203.0.113.53")
            side = observed["final_pair"][1][1].decode("ascii").split()
            self.assertTrue(side == [hashlib.sha256(observed["final_pair"][0][1]).hexdigest(), cache.name]
                            and int(observed["final_pair"][0][0][7])
                            <= int(observed["final_pair"][1][0][7]),
                            "final actual cache/sidecar qualification is not coherent")
            prefix = ["parse-return", "role-load-entry", "role-load-return-v6",
                      "role-local-return-empty", "early-selection-csv-entry", "early-selection-csv-return",
                      "first-load-entry", "first-load-return-A"]
            # P3c map D32d :284 (E8, 04 Q-039; 06 D1a-B; v15 CURRENT-CONTRACT.md:59): the v15
            # check-only report reads no pending diff after the selection.
            suffix = ["late-local-return-empty", "late-transit-devices-return",
                      "late-routing-p2p-entry", "late-routing-p2p-return", "selector-return"]
            if second_miss:
                self.assertTrue(second["result"] is None and second["out"] == {}
                                and observed["saves"] == 1 and observed["before_save"] is not None
                                and observed["local"][1]["targets"] is observed["produced"],
                                "second real miss did not discard first and use producer/save")
                self._check_profile(observed["before_save"], "203.0.113.53")
                middle = [
                    "own-sidecar-unlink", "local-for-cache-return-empty", "second-load-entry",
                    "second-load-return-None-empty-out", "producer-devices-return",
                    "producer-p2p-return", "producer-targets-return",
                    "producer-services-return-B", "producer-keys-return",
                    "save-entry-B", "save-normal-return",
                ]
            else:
                self.assertTrue(second["out"]["accepted"]["result"] is second["result"]
                                and observed["saves"] == 0 and observed["produced"] is None
                                and observed["local"][1]["targets"] is second["result"][1],
                                "second actual successful admission was not the final source")
                self._check_profile(second["out"]["accepted"]["profile"], "203.0.113.53")
                middle = ["publish-B", "local-for-cache-return-empty",
                          "second-load-entry", "second-load-return-B"]
            self.assertTrue(observed["timeline"] == prefix + middle + suffix,
                            "actual loader/local/producer/selector/DIFF order differs")
            self.assertTrue(len(f["caller"]["selector"]) == 1
                            and f["caller"]["selector"][0]["initial"] is True
                            and f["caller"]["selector"][0]["target"] is False
                            and f["caller"]["timeline"] == ["selector-return"],
                            "MATCH did not reach actual INITIAL readonly selection")
            # P3c map D32d :284 (E8, 04 Q-039; v15 CURRENT-CONTRACT.md:59): no pending-diff read in check-only.
            self.assertTrue(observed["diff"] is None,
                            "the readonly report read a pending diff")
            # I039 qualifies startup, selection and O5; D6 separately qualifies the readonly key check.
            # permission never replaces the independently selected INITIAL login.
            self.assertTrue(result["prompts"] == ["TARGET", "TARGET", "OOB"]
                            and result["hashes"] ==
                            [{"target": True, "IB": True, "supplied_bad": False}] * 4
                            and f["caller"]["native"] ==
                            [{"target": True, "IB": True, "matched": True}] * 4
                            and f["caller"]["fetch"] == ["actual-policy-fetch"] * 4
                            and not f["caller"]["consent"],
                            "readonly mode-auto must perform the original three qualifications plus one readonly key qualification and no consent")
            self.assertTrue(observed["selection_entry"] == [(1, 1)]
                            and f["caller"]["selector"][0]["native"] == 2
                            and f["caller"]["selector"][0]["fetch"] == 2,
                            "startup qualification must precede selection, which performs only the second qualification")
            metadata = [row for row in f["caller"]["helper_all"] if row["metadata"]]
            self.assertTrue(len(metadata) == 1
                            and metadata[0]["command"] == ("ip", "addr", "show", "eth0")
                            and metadata[0]["metadata"] is True and metadata[0]["returned"] is True
                            and metadata[0]["current_initial"] is True
                            and metadata[0]["current_target"] is False
                            and metadata[0]["current_oob"] is False and metadata[0]["outer_oob"] is True
                            and (metadata[0]["native_before"], metadata[0]["fetch_before"],
                                 metadata[0]["native_after"], metadata[0]["fetch_after"]) == (2, 2, 3, 3)
                            and f["caller"]["helper_metadata"] == [("ip", "addr", "show", "eth0")]
                            and f["caller"]["metadata_gate"] == [True],
                            "one real O5 read must preserve INITIAL/OOB roles and perform only the third qualification")
            fresh = self.events(f)[len(before):]
            self.assertEqual(1, sum(event["kind"] == "identity-addr-read" for event in fresh),
                             "one owned peer identity read must witness the real O5 helper")
            key_checks = [row for row in f["caller"]["helper_all"] if row["command"] == ("KEY-SHELL",)]
            self.assertTrue(len(f["caller"]["helper_all"]) == 2 and len(key_checks) == 1
                            and key_checks[0]["metadata"] is False and key_checks[0]["returned"] is True
                            and (key_checks[0]["native_before"], key_checks[0]["fetch_before"],
                                 key_checks[0]["native_after"], key_checks[0]["fetch_after"]) == (3, 3, 4, 4)
                            and f["caller"]["helper"] == [("KEY-SHELL",)] and f["caller"]["gate"] == [True]
                            and observed["key_receipts"] == [34],
                            "only one authenticated readonly key check may add qualification four after O5")
            self.assertEqual([34], [event.get("rc") for event in fresh if event["kind"] == "readonly-key-check"])
            key_answers = [event for event in fresh
                           if event["kind"] == "inner-answer" and event.get("command") == ["KEY-SHELL"]]
            self.assertTrue(len(key_answers) == 1 and key_answers[0]["phase"] is False
                            and key_answers[0]["initial"] is True and key_answers[0]["target"] is False
                            and key_answers[0]["oob"] is False,
                            "the ordinary readonly key frame must keep the selected INITIAL credential")
            self.assertTrue(len(observed["records"]) == 1
                            and observed["records"][0]["outcome"] == "CHECK_ONLY"
                            and observed["records"][0]["stage_status"]["public_keys"] == "PLANNED_NOT_APPLIED"
                            and observed["records"][0]["needs_change"] is True
                            and observed["records"][0]["verified_complete"] is False
                            and observed["records"][0]["writes_attempted"] is False
                            and observed["records"][0]["backup"] is None,
                            "real completion must retain the missing-key plan without verified success or backup")
            self.assertTrue(not any(event["kind"] in
                            ("mutation", "apply-y", "save", "key-shell", "ipv4-read", "pam-target", "config-backup")
                            or event["kind"].startswith("pam-")
                            for event in fresh),
                            "readonly mode-auto performed a business write")
            self.assertTrue(not any(path.exists() for path in
                            (f["credentials"], f["marker"], f["terminal"])),
                            "manual mode-auto persisted AUTO state")
            self.assertTrue(all(secret not in result["stdout"] + result["stderr"]
                                for secret in (self.kat["PASSWORD"], self.kat["SHA512"],
                                               self.kat["YESCRYPT"], base.PUBLIC_INITIAL,
                                               base.PUBLIC_OOB)),
                            "mode-auto diagnostics leaked private values")

    def test_manual_mode_auto_uses_second_successful_admission(self):
        self._exercise(False)

    def test_manual_mode_auto_discards_first_on_second_real_miss(self):
        self._exercise(True)


if __name__ == "__main__":
    unittest.main()
