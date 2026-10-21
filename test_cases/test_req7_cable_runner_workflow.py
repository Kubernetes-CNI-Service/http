"""Independent new Cable identity in actual runner proof consumers.

SOURCE ONLY until root executes. No test suite is selected or executed here;
full-suite attestation functions operate on explicit synthetic snapshots and
only a private temporary ledger. Metadata observation is not Linux wheel
execution, SDK import, native authorization, Docker or worker integration.
"""

from contextlib import contextmanager
import builtins
import copy
import hashlib
from importlib import metadata
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_change_aware_test_runner as original
from test_cases import test_req7_cable_dependency as cable
from test_cases import test_req7_dependency_contract as legacy


RUNNER = original.RUNNER
NEW_KEY = "req7_cable_dependencies"
OLD_KEY = "req7_dependencies"
TOP_LOCK = "requirements-container-top-level.lock"
SDK_TOPLEVEL = frozenset(("google", "google_auth_httplib2", "httplib2",
    "requests", "urllib3", "cryptography", "cffi", "certifi",
    "charset_normalizer", "idna", "proto", "pyasn1", "pyasn1_modules",
    "pyparsing", "uritemplate"))

# No repository/user-site path insertion, fake loader or SDK import. Only
# controlled metadata identities are used in this isolated import-path probe.
COLD_RUNNER = r'''
import builtins,importlib.util,importlib.metadata as metadata,json,pathlib,sys
from types import SimpleNamespace
script,pair_root,yaml_init,pins_json,top_json,blocked_json=sys.argv[1:]
script=pathlib.Path(script);pair_root=pathlib.Path(pair_root)
source_root=script.resolve().parents[1]
assert all(pathlib.Path(p or '.').resolve()!=source_root for p in sys.path)
assert 'tools' not in sys.modules and 'tools.req7_cable_dependency_contract' not in sys.modules
spec=importlib.util.spec_from_file_location('yaml',yaml_init,
    submodule_search_locations=[str(pathlib.Path(yaml_init).parent)])
yaml=importlib.util.module_from_spec(spec);sys.modules['yaml']=yaml;spec.loader.exec_module(yaml)
spec=importlib.util.spec_from_file_location('cold_cable_runner',script)
runner=importlib.util.module_from_spec(spec);sys.modules[spec.name]=runner;spec.loader.exec_module(runner)
assert all(pathlib.Path(p or '.').resolve()!=source_root for p in sys.path)
before=tuple(sys.path)
versions=dict(json.loads(pins_json));versions['typing_extensions']='4.16.0'
top=dict(json.loads(top_json));blocked=set(json.loads(blocked_json));attempts=[]
metadata.distribution=lambda name:SimpleNamespace(version=versions[name])
metadata.version=lambda name:top[name]
runner.ROOT=pair_root;runner.CONTAINER_TOPLEVEL_LOCK=pair_root/'requirements-container-top-level.lock'
original_import=builtins.__import__
def guarded(name,*args,**kwargs):
    if name.split('.',1)[0] in blocked:
        attempts.append(name);raise AssertionError('SDK import forbidden')
    return original_import(name,*args,**kwargs)
builtins.__import__=guarded
try:
    identity=runner.req7_cable_dependency_environment(pair_root)
    environment=runner.full_suite_environment()
finally:
    builtins.__import__=original_import
assert attempts==[]
assert len(sys.path)==len(before) and all(a is b for a,b in zip(sys.path,before))
assert all(pathlib.Path(p or '.').resolve()!=source_root for p in sys.path)
print(json.dumps({'identity':identity,'environment':environment},sort_keys=True))
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def expected_identity(policy_bytes, lock_bytes, pins):
    conditional = (("typing_extensions", "4.16.0"),) if sys.version_info[:2] < (3, 11) else ()
    return {"policy_sha256": sha(policy_bytes), "lock_sha256": sha(lock_bytes),
            "versions": [name + "==" + version for name, version in pins + conditional],
            "linux_artifacts_executed": False}


def require_api(case):
    case.assertTrue(callable(getattr(RUNNER, "req7_cable_dependency_environment", None)),
                    "separate runner Cable dependency observation required")
    case.assertTrue(callable(getattr(RUNNER, "_verify_req7_cable_environment_snapshot", None)),
                    "Cable pair must bind the actual full attestation snapshot")


@contextmanager
def no_sdk_imports():
    original_import = builtins.__import__
    attempted = []
    def guarded(name, *args, **kwargs):
        if name.split(".", 1)[0] in SDK_TOPLEVEL:
            attempted.append(name)
            raise AssertionError("SDK import forbidden in runner identity gate")
        return original_import(name, *args, **kwargs)
    with mock.patch.object(builtins, "__import__", side_effect=guarded):
        yield attempted


@contextmanager
def fixture():
    """Independently authored public pairs; real runner + real held-FD loader."""
    with tempfile.TemporaryDirectory(prefix="cable-runner-identity-") as directory:
        root = Path(directory).resolve(strict=True)
        data = {
            cable.POLICY_PATH: cable.policy_bytes(), cable.LOCK_PATH: cable.lock_bytes(),
            legacy.POLICY_PATH: legacy.policy_bytes(), legacy.LOCK_PATH: legacy.lock_bytes(),
            TOP_LOCK: original.CONTAINER_TOPLEVEL_LOCK.read_bytes(),
        }
        for name, raw in data.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        support = {name: sha(raw) for name, raw in data.items()}
        snapshot = RUNNER.Snapshot(manifest_sha256="a" * 64, scripts={}, tests={}, support=support)
        with mock.patch.object(RUNNER, "ROOT", root), \
                mock.patch.object(RUNNER, "CONTAINER_TOPLEVEL_LOCK", root / TOP_LOCK):
            yield root, snapshot


class CableRunnerIdentityTests(unittest.TestCase):
    def test_separate_current_metadata_identity_is_literal_and_refuses_drift(self):
        require_api(self)
        expected_new = expected_identity(cable.policy_bytes(), cable.lock_bytes(), cable.PINS)
        expected_old = expected_identity(legacy.policy_bytes(), legacy.lock_bytes(), legacy.PINS)
        self.assertNotEqual(expected_new["policy_sha256"], expected_old["policy_sha256"])
        with fixture() as (root, _snapshot), no_sdk_imports() as attempts:
            self.assertEqual(RUNNER.req7_cable_dependency_environment(root), expected_new)
            self.assertEqual(RUNNER.req7_dependency_environment(root), expected_old)
            environment = RUNNER.full_suite_environment()
            self.assertEqual(environment[NEW_KEY], expected_new)
            self.assertEqual(environment[OLD_KEY], expected_old)
            real_distribution = metadata.distribution
            for fault in ("missing", "version"):
                seen = []
                def changed(name):
                    if name == "google-api-core":
                        seen.append(name)
                        if fault == "missing":
                            raise metadata.PackageNotFoundError(name)
                        return SimpleNamespace(version="0.0.0")
                    return real_distribution(name)
                with self.subTest(fault=fault), mock.patch.object(metadata, "distribution", side_effect=changed):
                    self.assertEqual(RUNNER.req7_dependency_environment(root), expected_old)
                    with self.assertRaises(RUNNER.ImpactError):
                        RUNNER.req7_cable_dependency_environment(root)
                    with self.assertRaises(RUNNER.ImpactError):
                        RUNNER.full_suite_environment()
                self.assertEqual(seen, ["google-api-core", "google-api-core"])
            for relative in (cable.POLICY_PATH, cable.LOCK_PATH):
                path = root / relative
                before = path.read_bytes()
                path.write_bytes(before + b"\n")
                with self.subTest(pair_drift=relative), self.assertRaises(RUNNER.ImpactError):
                    RUNNER.req7_cable_dependency_environment(root)
                self.assertEqual(RUNNER.req7_dependency_environment(root), expected_old)
                path.write_bytes(before)
            self.assertEqual(attempts, [])
            cold_cwd = root / "cold-nonrepository-cwd"
            cold_cwd.mkdir()
            yaml_spec = importlib.util.find_spec("yaml")
            self.assertIsNotNone(yaml_spec)
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            # These five independent literals preserve the original TOPLEVEL
            # identity contract. The cold probe is not installed-package proof.
            top = (("Jinja2", "3.1.6"), ("PyYAML", "6.0.3"), ("pandas", "2.3.3"),
                   ("openpyxl", "3.1.5"), ("XlsxWriter", "3.2.9"))
            result = subprocess.run([sys.executable, "-I", "-B", "-c", COLD_RUNNER,
                str(Path(RUNNER.__file__).resolve()), str(root), yaml_spec.origin,
                json.dumps(cable.PINS), json.dumps(top), json.dumps(sorted(SDK_TOPLEVEL))],
                cwd=cold_cwd, env=environment, stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            cold = json.loads(result.stdout)
            self.assertEqual(cold["identity"], expected_new)
            self.assertEqual(cold["environment"][NEW_KEY], expected_new)
            self.assertEqual(cold["environment"][OLD_KEY], expected_old)

    def test_full_attestation_requires_both_cable_snapshot_hashes_and_new_environment_key(self):
        require_api(self)
        expected_new = expected_identity(cable.policy_bytes(), cable.lock_bytes(), cable.PINS)
        expected_old = expected_identity(legacy.policy_bytes(), legacy.lock_bytes(), legacy.PINS)
        with fixture() as (root, snapshot), no_sdk_imports() as attempts:
            environment = RUNNER.full_suite_environment()
            self.assertEqual(environment[NEW_KEY], expected_new)
            self.assertEqual(environment[OLD_KEY], expected_old)
            proof = RUNNER.full_suite_attestation(snapshot, environment=environment)
            self.assertEqual(proof["environment"], environment)
            self.assertEqual(proof["scenario_coverage"], {
                "root-entrypoint-workflow": "NOT COVERED (requires Linux EUID 0 private namespace)"})
            self.assertTrue(RUNNER.full_suite_attestation_is_current(snapshot, proof))
            for relative in (cable.POLICY_PATH, cable.LOCK_PATH):
                for mutation in ("missing", "mixed", "old_pair_hash"):
                    changed = dict(snapshot.support)
                    if mutation == "missing":
                        changed.pop(relative)
                    elif mutation == "mixed":
                        changed[relative] = "0" * 64
                    else:
                        changed[relative] = expected_old["policy_sha256" if relative == cable.POLICY_PATH else "lock_sha256"]
                    bad = RUNNER.Snapshot(manifest_sha256=snapshot.manifest_sha256,
                        scripts={}, tests={}, support=changed)
                    with self.subTest(snapshot=relative, mutation=mutation), self.assertRaises(RUNNER.ImpactError):
                        RUNNER.full_suite_attestation(bad, environment=environment)
            for mutation in ("missing", "renamed_key", "none", "old_identity", "mixed_identity"):
                changed = copy.deepcopy(environment)
                if mutation == "missing":
                    changed.pop(NEW_KEY)
                elif mutation == "renamed_key":
                    changed["req7_cable_dependencies_other"] = changed.pop(NEW_KEY)
                elif mutation == "none":
                    changed[NEW_KEY] = None
                elif mutation == "old_identity":
                    changed[NEW_KEY] = copy.deepcopy(expected_old)
                else:
                    changed[NEW_KEY]["lock_sha256"] = expected_old["lock_sha256"]
                self.assertEqual(changed[OLD_KEY], expected_old)
                with self.subTest(environment=mutation), self.assertRaises(RUNNER.ImpactError):
                    RUNNER.full_suite_attestation(snapshot, environment=changed)
            old_proof = copy.deepcopy(proof)
            old_proof["environment"].pop(NEW_KEY)
            self.assertFalse(RUNNER.full_suite_attestation_is_current(snapshot, old_proof))
            missing_support = dict(snapshot.support)
            missing_support.pop(cable.POLICY_PATH)
            missing_support.pop(cable.LOCK_PATH)
            old_snapshot = RUNNER.Snapshot(manifest_sha256=snapshot.manifest_sha256,
                scripts={}, tests={}, support=missing_support)
            self.assertFalse(RUNNER.full_suite_attestation_is_current(old_snapshot, old_proof))
            partial = root / "private-partial-approvals.json"
            partial.write_text(json.dumps({"full_suite_attestation": old_proof}) + "\n")
            RUNNER.atomic_write_approvals(partial, snapshot, full_suite=False)
            partial_payload = json.loads(partial.read_bytes())
            self.assertNotIn("full_suite_attestation", partial_payload)
            self.assertFalse(RUNNER.full_suite_attestation_is_current(
                snapshot, partial_payload.get("full_suite_attestation")))
            self.assertEqual(attempts, [])

    def test_cable_environment_drift_before_or_during_approval_preserves_prior_bytes(self):
        require_api(self)
        expected_new = expected_identity(cable.policy_bytes(), cable.lock_bytes(), cable.PINS)
        expected_old = expected_identity(legacy.policy_bytes(), legacy.lock_bytes(), legacy.PINS)
        prior = b'{"prior":"must-preserve"}\n'
        for fault_read in (1, 2):
            with self.subTest(metadata_fault_read=fault_read), fixture() as (root, snapshot), no_sdk_imports() as attempts:
                environment = RUNNER.full_suite_environment()
                self.assertEqual(environment[NEW_KEY], expected_new)
                self.assertEqual(environment[OLD_KEY], expected_old)
                approvals = root / "private-approvals.json"
                approvals.write_bytes(prior)
                real_distribution = metadata.distribution
                observations = []
                def changed(name):
                    if name == "google-api-core":
                        temporary = sorted(root.glob(".private-approvals.json.*"))
                        observations.append([path.read_bytes() for path in temporary])
                        if len(observations) == fault_read:
                            return SimpleNamespace(version="0.0.0")
                    return real_distribution(name)
                with mock.patch.object(metadata, "distribution", side_effect=changed):
                    self.assertEqual(RUNNER.req7_dependency_environment(root), expected_old)
                    with self.assertRaises(RUNNER.ImpactError):
                        RUNNER.atomic_write_approvals(approvals, snapshot, full_suite=True,
                            full_suite_environment_value=environment)
                self.assertEqual(len(observations), fault_read)
                self.assertEqual(observations[0], [])
                if fault_read == 2:
                    self.assertEqual(len(observations[1]), 1)
                    pending = json.loads(observations[1][0])
                    self.assertEqual(pending["full_suite_attestation"]["environment"][NEW_KEY], expected_new)
                    self.assertEqual(pending["full_suite_attestation"]["environment"][OLD_KEY], expected_old)
                self.assertEqual(approvals.read_bytes(), prior)
                self.assertEqual(list(root.glob(".private-approvals.json.*")), [])
                self.assertEqual(attempts, [])
        with fixture() as (root, snapshot), no_sdk_imports() as attempts:
            environment = RUNNER.full_suite_environment()
            self.assertEqual(environment[NEW_KEY], expected_new)
            self.assertEqual(environment[OLD_KEY], expected_old)
            approvals = root / "private-preflight-approvals.json"
            before = (json.dumps({"schema_version": 1,
                "impact_manifest_sha256": "a" * 64, "scripts": {}, "tests": {},
                "support": dict(snapshot.support)}, sort_keys=True) + "\n").encode()
            approvals.write_bytes(before)
            args = RUNNER.parser().parse_args(["--all", "--approvals", str(approvals)])
            for relative in (cable.POLICY_PATH, cable.LOCK_PATH):
                incomplete = dict(snapshot.support)
                incomplete.pop(relative)
                bad = RUNNER.Snapshot(manifest_sha256=snapshot.manifest_sha256,
                    scripts={}, tests={}, support=incomplete)
                # Only controller inputs are synthetic. Actual full environment,
                # new loader and old FD reader remain real. No suite may run.
                with self.subTest(preflight_missing=relative), \
                        mock.patch.object(RUNNER, "load_and_validate_manifest", return_value={"baseline_tests": []}), \
                        mock.patch.object(RUNNER, "make_snapshot", return_value=bad), \
                        mock.patch.object(RUNNER, "run_selection", side_effect=AssertionError("MUST NOT execute a suite")) as selected:
                    with self.assertRaises(RUNNER.ImpactError):
                        RUNNER._one_cycle(args)
                    selected.assert_not_called()
                self.assertEqual(approvals.read_bytes(), before)
            self.assertEqual(attempts, [])
