"""Actual activation/runner consumers of REQ7 policy; no Docker or SDK import."""

from contextlib import ExitStack
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_req7_dependency_contract import (
    ROOT, PINS, POLICY_PATH, LOCK_PATH, policy_bytes, lock_bytes,
)
from test_cases.test_ztp_container_runtime import load_script
from test_cases.test_change_aware_test_runner import RUNNER


class Req7DependencyWorkflowTests(unittest.TestCase):
    def test_activation_checks_linux_arch_versions_and_origins_before_sdk_import(self):
        activate = load_script("activate.py")
        self.assertTrue(hasattr(activate, "validate_req7_python_runtime"), "REQ7 activation dependency gate missing")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / POLICY_PATH).parent.mkdir(parents=True)
            (root / POLICY_PATH).write_bytes(policy_bytes()); (root / LOCK_PATH).write_bytes(lock_bytes())
            venv = root / "venv"; python = venv / "bin/python"; python.parent.mkdir(parents=True); python.touch()
            files = {}
            for name, _ in PINS:
                leaf = venv / "lib/python3.12/site-packages" / (name.replace("-", "_") + ".py")
                leaf.parent.mkdir(parents=True, exist_ok=True); leaf.write_text("VALUE = 1\n")
                files[name] = leaf
            def distribution(name):
                return SimpleNamespace(version=dict(PINS)[name], files=[files[name].relative_to(venv)],
                                       locate_file=lambda path: venv / path)
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(activate, "DEFAULT_IMAGE_SOURCE_TREE", root))
                stack.enter_context(mock.patch.object(activate, "CONTAINER_VENV", venv))
                stack.enter_context(mock.patch.object(activate, "CONTAINER_VENV_PYTHON", python))
                stack.enter_context(mock.patch.object(activate.sys, "executable", str(python)))
                stack.enter_context(mock.patch.object(activate.sys, "version_info", (3, 12, 9)))
                stack.enter_context(mock.patch.object(activate.sys, "platform", "linux"))
                stack.enter_context(mock.patch("platform.python_implementation", return_value="CPython"))
                stack.enter_context(mock.patch("platform.machine", return_value="aarch64"))
                stack.enter_context(mock.patch("importlib.metadata.distribution", side_effect=distribution))
                imports = stack.enter_context(mock.patch("importlib.import_module", side_effect=AssertionError("SDK import before gate")))
                result = activate.validate_req7_python_runtime()
                self.assertEqual([f"{n}=={v}" for n, v in PINS], result["versions"])
                self.assertEqual("aarch64", result["architecture"])
                imports.assert_not_called()
                with mock.patch("platform.machine", return_value="ppc64le"), self.assertRaises(activate.ActivationError):
                    activate.validate_req7_python_runtime()
                with mock.patch.object(activate.sys, "version_info", (3, 11, 9)), self.assertRaises(activate.ActivationError):
                    activate.validate_req7_python_runtime()
                foreign = root / "outside.py"; foreign.write_text("VALUE = 1\n"); files["google-auth"] = foreign
                with self.assertRaises(activate.ActivationError): activate.validate_req7_python_runtime()

    def test_runner_full_identity_binds_policy_lock_and_exact_local_dependency_versions(self):
        environment = RUNNER.full_suite_environment()
        self.assertIn("req7_dependencies", environment, "full proof does not bind REQ7 dependency identity")
        expected_pins = PINS + ((("typing_extensions", "4.16.0"),) if sys.version_info[:2] < (3, 11) else ())
        self.assertEqual({"policy_sha256": hashlib.sha256(policy_bytes()).hexdigest(),
                          "lock_sha256": hashlib.sha256(lock_bytes()).hexdigest(),
                          "versions": [f"{n}=={v}" for n, v in expected_pins],
                          "linux_artifacts_executed": False}, environment["req7_dependencies"])
        real = importlib.metadata.distribution
        def drifted(name):
            if name == "google-auth": return SimpleNamespace(version="2.51.0")
            return real(name)
        with mock.patch("importlib.metadata.distribution", side_effect=drifted), self.assertRaises(RUNNER.ImpactError):
            RUNNER.full_suite_environment()

    def test_image_and_manifest_bind_the_exact_additive_policy_lock_and_helper(self):
        activate = load_script("activate.py")
        for path in (POLICY_PATH, LOCK_PATH, "tools/req7_dependency_contract.py"):
            self.assertIn(path, activate.image_source_paths(ROOT))
            self.assertIn(path, activate.IMAGE_COUPLED_SOURCE_PATHS)
        manifest = RUNNER.load_and_validate_manifest(ROOT, ROOT / "test_cases/script_test_manifest.json")
        snapshot = RUNNER.make_snapshot(ROOT, ROOT / "test_cases/script_test_manifest.json", manifest)
        for path in (POLICY_PATH, LOCK_PATH): self.assertIn(path, snapshot.support)
        dockerfile = (ROOT / "infra/docker/Dockerfile").read_text()
        installation = "--only-binary=:all: --no-deps --require-hashes -r /opt/http-ztp/source-tree/" + LOCK_PATH
        self.assertIn(installation, dockerfile)
        self.assertLess(dockerfile.index(installation), dockerfile.index("verify-req7-python-runtime"))
        self.assertEqual(1, dockerfile.count(installation))

    def test_dependency_snapshot_mutation_cannot_inherit_previous_full_proof(self):
        self.assertTrue(hasattr(RUNNER, "req7_dependency_environment"), "runner lacks REQ7 dependency binding")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / POLICY_PATH).parent.mkdir(parents=True)
            (root / POLICY_PATH).write_bytes(policy_bytes()); (root / LOCK_PATH).write_bytes(lock_bytes())
            identity = RUNNER.req7_dependency_environment(root)
            self.assertEqual(hashlib.sha256(lock_bytes()).hexdigest(), identity["lock_sha256"])
            (root / LOCK_PATH).write_bytes(lock_bytes() + b"requests==2.0\n")
            with self.assertRaises(RUNNER.ImpactError): RUNNER.req7_dependency_environment(root)

    def test_full_attestation_rejects_missing_or_mixed_dependency_snapshot_hashes(self):
        environment = RUNNER.full_suite_environment()
        support = {"requirements-container-top-level.lock": environment["container_toplevel_lock_sha256"],
                   POLICY_PATH: hashlib.sha256(policy_bytes()).hexdigest(),
                   LOCK_PATH: hashlib.sha256(lock_bytes()).hexdigest()}
        valid = RUNNER.Snapshot(manifest_sha256="a" * 64, scripts={}, tests={}, support=support)
        self.assertEqual(environment, RUNNER.full_suite_attestation(valid, environment=environment)["environment"])
        for path in (POLICY_PATH, LOCK_PATH):
            for missing in (False, True):
                changed = dict(support)
                if missing: changed.pop(path)
                else: changed[path] = "0" * 64
                snapshot = RUNNER.Snapshot(manifest_sha256="a" * 64, scripts={}, tests={}, support=changed)
                with self.subTest(path=path, missing=missing), self.assertRaises(RUNNER.ImpactError):
                    RUNNER.full_suite_attestation(snapshot, environment=environment)

    def test_full_approval_refuses_mixed_dependency_hashes_without_ledger_mutation(self):
        environment = RUNNER.full_suite_environment()
        support = {"requirements-container-top-level.lock": environment["container_toplevel_lock_sha256"],
                   POLICY_PATH: hashlib.sha256(policy_bytes()).hexdigest(), LOCK_PATH: "0" * 64}
        snapshot = RUNNER.Snapshot(manifest_sha256="a" * 64, scripts={}, tests={}, support=support)
        with tempfile.TemporaryDirectory() as temp:
            ledger = Path(temp) / "approved.json"; ledger.write_bytes(b'{"prior":"preserve"}\n')
            with self.assertRaises(RUNNER.ImpactError):
                RUNNER.atomic_write_approvals(ledger, snapshot, full_suite=True,
                                             full_suite_environment_value=environment)
            self.assertEqual(b'{"prior":"preserve"}\n', ledger.read_bytes())


if __name__ == "__main__": unittest.main()
