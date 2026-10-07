"""Independent REQ7 C-14 dependency policy, artifacts and fail-closed reads.

Public wheel hashes are pinned from PyPI and independently downloaded/hashed;
this suite never imports google-auth, installs packages or builds a container.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PINS = (("google-auth", "2.50.0"), ("pyasn1-modules", "0.4.2"),
        ("pyasn1", "0.6.4"), ("cryptography", "50.0.1"),
        ("cffi", "2.0.0"), ("pycparser", "2.23"))
WHEELS = (
    ("google-auth", "any", "google_auth-2.50.0-py3-none-any.whl", "04382175e28b94f49694977f0a792688b59a668def1499e9d8de996dc9ce5b15"),
    ("pyasn1-modules", "any", "pyasn1_modules-0.4.2-py3-none-any.whl", "29253a9207ce32b64c3ac6600edc75368f98473906e8fd1043bd6b5b1de2c14a"),
    ("pyasn1", "any", "pyasn1-0.6.4-py3-none-any.whl", "deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b"),
    ("cryptography", "aarch64", "cryptography-50.0.1-cp39-abi3-manylinux_2_28_aarch64.whl", "4c4188f7c0cf655be5c06342b817ed0f9595b69ffa2b12026e5353eed29dea88"),
    ("cryptography", "x86_64", "cryptography-50.0.1-cp39-abi3-manylinux_2_28_x86_64.whl", "407fe2b6db00939c05c0e945e9914238f2f0a430974839429dafc82b1ee6bee5"),
    ("cffi", "aarch64", "cffi-2.0.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", "b21e08af67b8a103c71a250401c78d5e0893beff75e28c53c98f4de42f774062"),
    ("cffi", "x86_64", "cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba"),
    ("pycparser", "any", "pycparser-2.23-py3-none-any.whl", "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934"),
)
POLICY_PATH = "infra/docker/req7-dependency-policy.json"
LOCK_PATH = "infra/docker/requirements-req7-online.txt"


def policy():
    return {"schema_version": 1, "contract": "REQ7-C14-T6-A",
            "python": "CPython-3.12", "platform": "linux",
            "architectures": ["aarch64", "x86_64"], "extras": [],
            "distributions": [{"name": n, "version": v} for n, v in PINS],
            "artifacts": [{"name": n, "architecture": a, "filename": f, "sha256": h}
                          for n, a, f, h in WHEELS],
            "development_conditional": {"name": "typing_extensions", "version": "4.16.0",
                                        "marker": "python_full_version < '3.11'"},
            "forbidden_transports": ["google-api-python-client", "httplib2", "requests", "AuthorizedSession"]}


def policy_bytes(value=None):
    return (json.dumps(policy() if value is None else value, sort_keys=True,
                       ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode()


def lock_bytes():
    lines = ["# REQ7 C-14: CPython 3.12 Linux aarch64/x86_64; wheels only; no extras; pip --no-deps --require-hashes."]
    for name, version in PINS:
        wheels = [w for w in WHEELS if w[0] == name]
        for _, _, filename, digest in wheels:
            lines.append(f"# wheel: {filename} sha256:{digest}")
        lines.append(name + "==" + version + " \\")
        for i, digest in enumerate(sorted(w[3] for w in wheels)):
            lines.append("    --hash=sha256:" + digest + (" \\" if i < len(wheels) - 1 else ""))
    return ("\n".join(lines) + "\n").encode()


def load():
    path = ROOT / "tools/req7_dependency_contract.py"
    if not path.is_file(): raise AssertionError("REQ7 dependency validator is missing")
    spec = importlib.util.spec_from_file_location("req7_dependency_direct", path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Req7DependencyDirectTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / POLICY_PATH).parent.mkdir(parents=True)
        (self.root / POLICY_PATH).write_bytes(policy_bytes())
        (self.root / LOCK_PATH).write_bytes(lock_bytes())

    def test_shipped_policy_and_lock_match_independent_official_artifacts(self):
        self.assertEqual(policy_bytes(), (ROOT / POLICY_PATH).read_bytes())
        self.assertEqual(lock_bytes(), (ROOT / LOCK_PATH).read_bytes())
        result = self.module.load_dependency_contract(ROOT)
        self.assertEqual(PINS, result.distributions)
        self.assertEqual(WHEELS, result.artifacts)
        self.assertEqual(hashlib.sha256(policy_bytes()).hexdigest(), result.policy_sha256)
        self.assertEqual(hashlib.sha256(lock_bytes()).hexdigest(), result.lock_sha256)
        with self.assertRaises(AttributeError): result.lock_sha256 = "0" * 64

    def test_every_linux_architecture_has_exact_six_package_closure(self):
        contract = self.module.load_dependency_contract(self.root)
        for arch in ("aarch64", "x86_64"):
            expected = tuple((n, f, h) for n, a, f, h in WHEELS if a in ("any", arch))
            self.assertEqual(expected, self.module.architecture_artifacts(contract, arch))
            self.assertEqual(6, len(expected))
        for bad in ("arm64", "amd64", "ppc64le", "", True):
            with self.subTest(bad=bad), self.assertRaises(self.module.DependencyContractError):
                self.module.architecture_artifacts(contract, bad)

    def test_unknown_duplicate_noncanonical_policy_and_new_dependencies_refuse(self):
        variants = []
        for field, value in (("schema_version", True), ("python", "CPython-3.11"),
                             ("platform", "darwin"), ("extras", ["requests"]),
                             ("architectures", ["x86_64"]), ("unknown", 1)):
            altered = policy(); altered[field] = value; variants.append(policy_bytes(altered))
        altered = policy(); altered["distributions"].append({"name": "requests", "version": "2.0"})
        variants.append(policy_bytes(altered))
        variants.extend((policy_bytes().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'),
                         json.dumps(policy()).encode(), policy_bytes() + b"\n", b"\xff"))
        for raw in variants:
            with self.subTest(raw=raw[:35]), self.assertRaises(self.module.DependencyContractError):
                (self.root / POLICY_PATH).write_bytes(raw)
                self.module.load_dependency_contract(self.root)

    def test_foreign_wheel_duplicate_digest_missing_arch_and_version_drift_refuse(self):
        for field, value in (("filename", "cryptography-50.0.1.tar.gz"),
                             ("filename", "cryptography-50.0.1-cp39-abi3-win_amd64.whl"),
                             ("architecture", "arm64"), ("sha256", "A" * 64),
                             ("unknown", True)):
            altered = policy(); altered["artifacts"][3][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(self.module.DependencyContractError):
                (self.root / POLICY_PATH).write_bytes(policy_bytes(altered))
                self.module.load_dependency_contract(self.root)
        missing = policy(); missing["artifacts"].pop()
        duplicate = policy(); duplicate["artifacts"][4] = copy.deepcopy(duplicate["artifacts"][3])
        repeated_digest = policy(); repeated_digest["artifacts"][4]["sha256"] = repeated_digest["artifacts"][3]["sha256"]
        for altered in (missing, duplicate, repeated_digest):
            with self.assertRaises(self.module.DependencyContractError):
                (self.root / POLICY_PATH).write_bytes(policy_bytes(altered))
                self.module.load_dependency_contract(self.root)
        altered = policy(); altered["distributions"][0]["version"] = "2.51.0"
        with self.assertRaises(self.module.DependencyContractError):
            (self.root / POLICY_PATH).write_bytes(policy_bytes(altered))
            self.module.load_dependency_contract(self.root)

    def test_install_lock_is_exact_no_sdist_index_override_extras_or_unpinned_dependency(self):
        for extra in (b"requests\n", b"--index-url https://invalid.example\n", b"--trusted-host invalid.example\n"):
            with self.subTest(extra=extra), self.assertRaises(self.module.DependencyContractError):
                (self.root / LOCK_PATH).write_bytes(lock_bytes() + extra)
                self.module.load_dependency_contract(self.root)
        for raw in (lock_bytes().replace(b"google-auth==", b"google-auth[requests]=="),
                    lock_bytes().replace(b"04382175", b"00000000"), b""):
            with self.assertRaises(self.module.DependencyContractError):
                (self.root / LOCK_PATH).write_bytes(raw)
                self.module.load_dependency_contract(self.root)

    def test_symlink_hardlink_directory_and_unbounded_policy_refuse(self):
        path = self.root / POLICY_PATH; saved = path.read_bytes()
        path.unlink(); other = self.root / "outside.json"; other.write_bytes(saved)
        path.symlink_to(other)
        with self.assertRaises(self.module.DependencyContractError): self.module.load_dependency_contract(self.root)
        path.unlink(); os.link(other, path)
        with self.assertRaises(self.module.DependencyContractError): self.module.load_dependency_contract(self.root)
        path.unlink(); path.mkdir()
        with self.assertRaises(self.module.DependencyContractError): self.module.load_dependency_contract(self.root)
        path.rmdir(); path.write_bytes(b"x" * 65537)
        with self.assertRaises(self.module.DependencyContractError): self.module.load_dependency_contract(self.root)

    def test_metadata_identity_is_exact_conditional_and_never_imports_sdk(self):
        contract = self.module.load_dependency_contract(self.root)
        versions = dict(PINS, typing_extensions="4.16.0")
        for py, expected in (((3, 12), PINS), ((3, 9), PINS + (("typing_extensions", "4.16.0"),))):
            getter = mock.Mock(side_effect=lambda name: versions[name])
            with mock.patch("importlib.import_module", side_effect=AssertionError("SDK import forbidden")):
                actual = self.module.installed_dependency_identity(contract, python_version=py, version_getter=getter)
            self.assertEqual(expected, actual.versions)
            self.assertEqual([mock.call(n) for n, _ in expected], getter.call_args_list)
            self.assertFalse(hasattr(actual, "permit"))
            self.assertFalse(hasattr(actual, "token"))

    def test_policy_rebinding_during_lock_read_never_produces_a_mixed_contract(self):
        original_read = self.module.os.read
        for same_bytes in (True, False):
            (self.root / POLICY_PATH).write_bytes(policy_bytes())
            mutated = False
            def interleaved(descriptor, size):
                nonlocal mutated
                data = original_read(descriptor, size)
                if data == lock_bytes() and not mutated:
                    replacement = self.root / "replacement.json"
                    replacement.write_bytes(policy_bytes() if same_bytes else b"{}\n")
                    replacement.replace(self.root / POLICY_PATH)
                    mutated = True
                return data
            with self.subTest(same_bytes=same_bytes), mock.patch.object(
                self.module.os, "read", side_effect=interleaved,
            ), self.assertRaises(self.module.DependencyContractError):
                self.module.load_dependency_contract(self.root)
            self.assertTrue(mutated)

    def test_missing_or_drifted_dependency_never_counts_as_verified_identity(self):
        contract = self.module.load_dependency_contract(self.root)
        for name, _ in PINS:
            getter = lambda n, changed=name: "0.0.0" if n == changed else dict(PINS)[n]
            with self.subTest(name=name), self.assertRaises(self.module.DependencyContractError):
                self.module.installed_dependency_identity(contract, python_version=(3, 12), version_getter=getter)
        for py in ((3, 8), (2, 7), (True, 12), "3.12"):
            with self.subTest(py=py), self.assertRaises(self.module.DependencyContractError):
                self.module.installed_dependency_identity(contract, python_version=py, version_getter=dict(PINS).__getitem__)


if __name__ == "__main__": unittest.main()
