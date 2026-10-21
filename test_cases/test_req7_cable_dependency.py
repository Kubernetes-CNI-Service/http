"""Independent public Cable SDK dependency contract; SOURCE-only until root runs.

The 22 literal wheel records come from the separately reviewed official-PyPI
selection, not the implementation. Only synthetic public policy/lock fixtures
are loaded; no install, SDK import, credential, container or network operation.
Private qualification needs this test's repository root plus the original
tools.req7_dependency_contract available through ordinary canonical imports.
"""

from contextlib import contextmanager
from importlib import metadata
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = "infra/docker/req7-cable-dependency-policy.json"
LOCK_PATH = "infra/docker/requirements-req7-cable-sync.txt"
LOCK_HEADER = "# REQ7 Cable sync SDK v1: CPython 3.12 Linux aarch64/x86_64; wheels only; no extras; pip --no-deps --require-hashes."
PINS = (
    ("certifi", "2026.7.22"), ("cffi", "2.0.0"),
    ("charset-normalizer", "3.5.1"), ("cryptography", "50.0.1"),
    ("google-api-core", "2.30.3"), ("google-api-python-client", "2.198.0"),
    ("google-auth-httplib2", "0.3.1"), ("google-auth", "2.50.0"),
    ("googleapis-common-protos", "1.75.0"), ("httplib2", "0.32.0"),
    ("idna", "3.19"), ("proto-plus", "1.27.2"), ("protobuf", "6.33.6"),
    ("pyasn1-modules", "0.4.2"), ("pyasn1", "0.6.4"),
    ("pycparser", "2.23"), ("pyparsing", "3.3.2"),
    ("requests", "2.32.5"), ("uritemplate", "4.2.0"), ("urllib3", "2.6.3"),
)
WHEELS = (
    ("certifi", "any", "certifi-2026.7.22-py3-none-any.whl", "62f22742b58a1a33014a2b6b706588a8d7e2a88ae7bd1a6ebe8c992928483775"),
    ("cffi", "aarch64", "cffi-2.0.0-cp312-cp312-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", "b21e08af67b8a103c71a250401c78d5e0893beff75e28c53c98f4de42f774062"),
    ("cffi", "x86_64", "cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl", "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba"),
    ("charset-normalizer", "any", "charset_normalizer-3.5.1-py3-none-any.whl", "6df0ec430f9a831772c23ca5a224cba36517a58a84bb32c32bb59a9fa67c47f6"),
    ("cryptography", "aarch64", "cryptography-50.0.1-cp39-abi3-manylinux_2_28_aarch64.whl", "4c4188f7c0cf655be5c06342b817ed0f9595b69ffa2b12026e5353eed29dea88"),
    ("cryptography", "x86_64", "cryptography-50.0.1-cp39-abi3-manylinux_2_28_x86_64.whl", "407fe2b6db00939c05c0e945e9914238f2f0a430974839429dafc82b1ee6bee5"),
    ("google-api-core", "any", "google_api_core-2.30.3-py3-none-any.whl", "a85761ba72c444dad5d611c2220633480b2b6be2521eca69cca2dbb3ffd6bfe8"),
    ("google-api-python-client", "any", "google_api_python_client-2.198.0-py3-none-any.whl", "fabac935474e817da5e662ff61bf7139439d6f92b32d332a7318a2d45931e03e"),
    ("google-auth-httplib2", "any", "google_auth_httplib2-0.3.1-py3-none-any.whl", "682356a90ef4ba3d06548c37e9112eea6fc00395a11b0303a644c1a86abc275c"),
    ("google-auth", "any", "google_auth-2.50.0-py3-none-any.whl", "04382175e28b94f49694977f0a792688b59a668def1499e9d8de996dc9ce5b15"),
    ("googleapis-common-protos", "any", "googleapis_common_protos-1.75.0-py3-none-any.whl", "961ed60399c457ceb0ee8f285a84c870aabc9c6a832b9d37bb281b5bebde43ed"),
    ("httplib2", "any", "httplib2-0.32.0-py3-none-any.whl", "dc6705cacdf3fb0a2aba7629fa33c90fd93e30035db0c157325826be177e4816"),
    ("idna", "any", "idna-3.19-py3-none-any.whl", "815e7be7a7806d54abb586dc943addc79e8b2ee16915059658cbeff4b1b43bf4"),
    ("proto-plus", "any", "proto_plus-1.27.2-py3-none-any.whl", "6432f75893d3b9e70b9c412f1d2f03f65b11fb164b793d14ae2ca01821d22718"),
    ("protobuf", "any", "protobuf-6.33.6-py3-none-any.whl", "77179e006c476e69bf8e8ce866640091ec42e1beb80b213c3900006ecfba6901"),
    ("pyasn1-modules", "any", "pyasn1_modules-0.4.2-py3-none-any.whl", "29253a9207ce32b64c3ac6600edc75368f98473906e8fd1043bd6b5b1de2c14a"),
    ("pyasn1", "any", "pyasn1-0.6.4-py3-none-any.whl", "deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b"),
    ("pycparser", "any", "pycparser-2.23-py3-none-any.whl", "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934"),
    ("pyparsing", "any", "pyparsing-3.3.2-py3-none-any.whl", "850ba148bd908d7e2411587e247a1e4f0327839c40e2e5e6d05a007ecc69911d"),
    ("requests", "any", "requests-2.32.5-py3-none-any.whl", "2462f94637a34fd532264295e186976db0f5d453d1cdd31473c85a6a161affb6"),
    ("uritemplate", "any", "uritemplate-4.2.0-py3-none-any.whl", "962201ba1c4edcab02e60f9a0d3821e82dfc5d2d6662a21abd533879bdb8a686"),
    ("urllib3", "any", "urllib3-2.6.3-py3-none-any.whl", "bf272323e553dfb2e87d9bfd225ca7b0f467b919d7bbd355436d3fd37cb0acd4"),
)


def policy():
    return {"schema_version": 1, "contract": "REQ7-CABLE-SDK-V1",
            "python": "CPython-3.12", "platform": "linux",
            "architectures": ["aarch64", "x86_64"], "extras": [],
            "distributions": [{"name": n, "version": v} for n, v in PINS],
            "artifacts": [{"name": n, "architecture": a, "filename": f, "sha256": h}
                          for n, a, f, h in WHEELS],
            "development_conditional": {"name": "typing_extensions", "version": "4.16.0",
                                        "marker": "python_full_version < '3.11'"},
            "transport": {"sdk": "google-api-python-client", "http": "google-auth-httplib2",
                          "discovery": "static-only", "api_retries": 0,
                          "authentication_response_replays": 0}}


def policy_bytes(value=None):
    return (json.dumps(policy() if value is None else value, sort_keys=True,
                       ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def lock_bytes(artifacts=WHEELS):
    lines = [LOCK_HEADER]
    for name, version in PINS:
        wheels = [row for row in artifacts if row[0] == name]
        lines.extend(f"# wheel: {filename} sha256:{digest}"
                     for _, _, filename, digest in wheels)
        lines.append(name + "==" + version + " \\")
        hashes = sorted(row[3] for row in wheels)
        lines.extend("    --hash=sha256:" + digest + (" \\" if i < len(hashes) - 1 else "")
                     for i, digest in enumerate(hashes))
    return ("\n".join(lines) + "\n").encode("ascii")


@contextmanager
def fixture(raw=None, lock=None):
    with tempfile.TemporaryDirectory(prefix="req7-cable-dependency-") as directory:
        root = Path(directory)
        (root / POLICY_PATH).parent.mkdir(parents=True)
        (root / POLICY_PATH).write_bytes(policy_bytes() if raw is None else raw)
        (root / LOCK_PATH).write_bytes(lock_bytes() if lock is None else lock)
        yield root


def load():
    """Load only this candidate's ordinary tools file; missing API is literal FAIL."""
    path = ROOT / "tools/req7_cable_dependency_contract.py"
    if not path.is_file():
        raise AssertionError("independent Cable SDK dependency validator required")
    spec = importlib.util.spec_from_file_location("req7_cable_dependency_direct", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for name in ("CableDependencyContract", "CableDependencyIdentity", "CableDependencyContractError",
                 "load_cable_dependency_contract", "cable_architecture_artifacts",
                 "installed_cable_dependency_identity"):
        if not hasattr(module, name):
            raise AssertionError("Cable SDK dependency API required: " + name)
    return module


class CableDependencyDirectTests(unittest.TestCase):
    def module(self):
        return load()

    def test_literal_public_wheels_architectures_and_distinct_original_c14_types(self):
        module = self.module()
        from tools import req7_dependency_contract as original
        with fixture() as root:
            contract = module.load_cable_dependency_contract(root)
        self.assertIs(type(contract), module.CableDependencyContract)
        self.assertEqual(contract.distributions, PINS)
        self.assertEqual(contract.artifacts, WHEELS)
        self.assertEqual(contract.policy_sha256, hashlib.sha256(policy_bytes()).hexdigest())
        self.assertEqual(contract.lock_sha256, hashlib.sha256(lock_bytes()).hexdigest())
        self.assertFalse(isinstance(contract, original.DependencyContract))
        with self.assertRaises(AttributeError):
            contract.policy_sha256 = "0" * 64
        for arch in ("aarch64", "x86_64"):
            expected = tuple((n, f, h) for n, a, f, h in WHEELS if a in ("any", arch))
            self.assertEqual(len(expected), 20)
            self.assertEqual(module.cable_architecture_artifacts(contract, arch), expected)
        for bad in ("arm64", "amd64", "", True):
            with self.subTest(arch=bad), self.assertRaises(module.CableDependencyContractError):
                module.cable_architecture_artifacts(contract, bad)
        old_contract = original.DependencyContract("a" * 64, "b" * 64, (), ())
        old_identity = original.DependencyIdentity("a" * 64, "b" * 64, ())
        for foreign in (old_contract, old_identity):
            with self.subTest(foreign=type(foreign).__name__):
                with self.assertRaises(module.CableDependencyContractError):
                    module.cable_architecture_artifacts(foreign, "aarch64")
                with self.assertRaises(module.CableDependencyContractError):
                    module.installed_cable_dependency_identity(foreign, python_version=(3, 12),
                                                               version_getter=dict(PINS).__getitem__)

    def test_tamper_missing_symlink_wrong_pins_extras_and_old_contract_are_refused(self):
        module = self.module()
        variants = []
        for key, value in (("schema_version", True), ("contract", "REQ7-C14-T6-A"),
                           ("python", "CPython-3.11"), ("platform", "darwin"),
                           ("architectures", ["x86_64"]), ("extras", ["requests"]),
                           ("unknown", 1)):
            changed = policy(); changed[key] = value; variants.append(policy_bytes(changed))
        changed = policy(); changed["distributions"][0]["version"] = "0.0.0"
        variants.append(policy_bytes(changed))
        changed = policy(); changed["artifacts"].pop()
        variants.append(policy_bytes(changed))
        changed = policy(); changed["artifacts"][1] = copy.deepcopy(changed["artifacts"][2])
        variants.append(policy_bytes(changed))
        for key, value in (("api_retries", 1), ("authentication_response_replays", 1),
                           ("api_retries", False), ("authentication_response_replays", False),
                           ("discovery", "dynamic"), ("http", "requests")):
            changed = policy(); changed["transport"][key] = value; variants.append(policy_bytes(changed))
        variants.extend((json.dumps(policy()).encode(), policy_bytes() + b"\n", b"\xff",
                         policy_bytes().replace(b'"schema_version": 1',
                                                b'"schema_version": 1, "schema_version": 1')))
        for raw in variants:
            with self.subTest(policy=raw[:45]), fixture(raw=raw) as root:
                with self.assertRaises(module.CableDependencyContractError):
                    module.load_cable_dependency_contract(root)
        # A matching altered lock must not launder an unknown public artifact.
        bad_artifacts = list(WHEELS)
        bad_artifacts[0] = (*bad_artifacts[0][:3], "0" * 64)
        changed = policy(); changed["artifacts"][0]["sha256"] = "0" * 64
        with fixture(policy_bytes(changed), lock_bytes(tuple(bad_artifacts))) as root:
            with self.assertRaises(module.CableDependencyContractError):
                module.load_cable_dependency_contract(root)
        for raw in (lock_bytes() + b"unlocked-package\n", lock_bytes().replace(b"httplib2==", b"httplib2[extra]=="),
                    lock_bytes().replace(b"--hash=sha256:", b"--hash=md5:", 1), b""):
            with self.subTest(lock=raw[:45]), fixture(lock=raw) as root:
                with self.assertRaises(module.CableDependencyContractError):
                    module.load_cable_dependency_contract(root)
        for leaf in (POLICY_PATH, LOCK_PATH):
            with fixture() as root:
                (root / leaf).unlink()
                with self.assertRaises(module.CableDependencyContractError):
                    module.load_cable_dependency_contract(root)
            with fixture() as root:
                path = root / leaf
                saved = path.read_bytes(); path.unlink()
                outside = root / "synthetic-outside"; outside.write_bytes(saved)
                path.symlink_to(outside)
                with self.assertRaises(module.CableDependencyContractError):
                    module.load_cable_dependency_contract(root)

    def test_installed_metadata_versions_python_condition_and_missing_packages_refuse(self):
        module = self.module()
        with fixture() as root:
            contract = module.load_cable_dependency_contract(root)
        versions = dict(PINS, typing_extensions="4.16.0")
        for py, expected in (((3, 12), PINS), ((3, 9), PINS + (("typing_extensions", "4.16.0"),))):
            getter = mock.Mock(side_effect=versions.__getitem__)
            with mock.patch("importlib.import_module", side_effect=AssertionError("SDK import forbidden")):
                identity = module.installed_cable_dependency_identity(
                    contract, python_version=py, version_getter=getter)
            self.assertIs(type(identity), module.CableDependencyIdentity)
            self.assertEqual(identity.versions, expected)
            self.assertEqual(identity.policy_sha256, contract.policy_sha256)
            self.assertEqual(identity.lock_sha256, contract.lock_sha256)
            self.assertEqual(getter.call_args_list, [mock.call(name) for name, _ in expected])
            self.assertFalse(hasattr(identity, "permit"))
            self.assertFalse(hasattr(identity, "token"))
        for name, _ in PINS + (("typing_extensions", "4.16.0"),):
            for missing in (False, True):
                def getter(queried, changed=name, missing=missing):
                    if queried == changed:
                        if missing: raise metadata.PackageNotFoundError(queried)
                        return "0.0.0"
                    return versions[queried]
                py = (3, 9) if name == "typing_extensions" else (3, 12)
                with self.subTest(name=name, missing=missing), self.assertRaises(module.CableDependencyContractError):
                    module.installed_cable_dependency_identity(contract, python_version=py, version_getter=getter)
        for py in ((3, 8), (2, 7), (True, 12), "3.12", (3,)):
            with self.subTest(py=py), self.assertRaises(module.CableDependencyContractError):
                module.installed_cable_dependency_identity(contract, python_version=py,
                                                           version_getter=versions.__getitem__)


if __name__ == "__main__":
    unittest.main()
