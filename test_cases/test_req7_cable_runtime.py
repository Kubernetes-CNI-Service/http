"""Independent managed-runtime metadata/origin gate; no SDK or installation.

SOURCE only until root executes. Controlled Python/platform/metadata values
model the managed Linux venv; real fixed public pairs use the original FD
reader. Neither these metadata observations nor fixture files grant sending.
"""
from contextlib import ExitStack, contextmanager
import builtins
import hashlib
from importlib import metadata
import os
from pathlib import Path
import platform
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_ztp_container_runtime as original


ROOT = Path(__file__).resolve().parents[1]
POLICY = "infra/docker/req7-cable-dependency-policy.json"
LOCK = "infra/docker/requirements-req7-cable-sync.txt"
HELPER = "tools/req7_cable_dependency_contract.py"
TRIO = (POLICY, LOCK, HELPER)
POLICY_SHA = "70cc11c4ffb49c18989c7b48f449455079402c9d272d67b5af696b0f9c46f673"
LOCK_SHA = "44fef0c84983b81b77a32cd5e5fe1653dea097ceccecf460910f1fb59257f11b"
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
SDK_TOPLEVEL = frozenset(("google", "google_auth_httplib2", "httplib2",
    "cryptography", "cffi", "requests", "urllib3", "certifi",
    "charset_normalizer", "idna", "proto", "pyasn1", "pyasn1_modules",
    "pyparsing", "uritemplate"))


def load(case):
    # Reuse the original complete script loader, pointing only its fixture
    # source-directory seam to this coherent root; no API/registry replacement.
    with mock.patch.object(original, "DOCKER_ROOT", ROOT / "infra/docker"):
        activate = original.load_script("activate.py")
    case.assertTrue(callable(getattr(activate, "validate_req7_cable_python_runtime", None)),
                    "separate Cable managed-runtime validator required")
    return activate


@contextmanager
def no_sdk_imports():
    real = builtins.__import__
    attempted = []
    def guarded(name, *args, **kwargs):
        if name.split(".", 1)[0] in SDK_TOPLEVEL:
            attempted.append(name)
            raise AssertionError("SDK import forbidden in runtime metadata gate")
        return real(name, *args, **kwargs)
    with mock.patch.object(builtins, "__import__", side_effect=guarded):
        yield attempted


def expected(architecture):
    return {"policy_sha256": POLICY_SHA, "lock_sha256": LOCK_SHA,
            "versions": [name + "==" + version for name, version in PINS],
            "architecture": architecture}


@contextmanager
def runtime_fixture(case, activate):
    with tempfile.TemporaryDirectory(prefix="cable-runtime-") as directory:
        root = Path(directory).resolve(strict=True)
        for relative, digest in ((POLICY, POLICY_SHA), (LOCK, LOCK_SHA)):
            data = (ROOT / relative).read_bytes()
            case.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for relative in ("infra/docker/req7-dependency-policy.json",
                         "infra/docker/requirements-req7-online.txt"):
            (root / relative).write_bytes((ROOT / relative).read_bytes())
        venv = root / "venv"
        python = venv / "bin/python"
        python.parent.mkdir(parents=True)
        python.touch()
        files, versions, inventories = {}, dict(PINS), {}
        for name, _version in PINS:
            path = venv / "lib/python3.12/site-packages" / (name.replace("-", "_") + ".py")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"PRIVATE_METADATA_ORIGIN_ONLY = True\n")
            files[name] = path
            inventories[name] = [path]
        seen = []
        missing = set()
        def distribution(name):
            seen.append(name)
            if name in missing:
                raise metadata.PackageNotFoundError(name)
            return SimpleNamespace(version=versions[name], files=inventories[name],
                                   locate_file=lambda relative: relative)
        with ExitStack() as stack:
            for name, value in (("DEFAULT_IMAGE_SOURCE_TREE", root), ("CONTAINER_VENV", venv),
                                ("CONTAINER_VENV_PYTHON", python)):
                stack.enter_context(mock.patch.object(activate, name, value))
            stack.enter_context(mock.patch.object(activate.sys, "executable", str(python)))
            stack.enter_context(mock.patch.object(activate.sys, "version_info", (3, 12, 9)))
            stack.enter_context(mock.patch.object(activate.sys, "platform", "linux"))
            stack.enter_context(mock.patch.object(platform, "python_implementation", return_value="CPython"))
            stack.enter_context(mock.patch.object(platform, "machine", return_value="aarch64"))
            stack.enter_context(mock.patch.object(metadata, "distribution", side_effect=distribution))
            yield SimpleNamespace(root=root, venv=venv, python=python, files=files,
                                  versions=versions, inventories=inventories, missing=missing, seen=seen)


class CableRuntimeDirectTests(unittest.TestCase):
    def test_real_pair_and_original_fd_reader_validate_both_architectures_without_sdk(self):
        activate = load(self)
        with runtime_fixture(self, activate) as fixture, no_sdk_imports() as attempts:
            for architecture in ("aarch64", "x86_64"):
                fixture.seen.clear()
                with mock.patch.object(platform, "machine", return_value=architecture):
                    self.assertEqual(activate.validate_req7_cable_python_runtime(), expected(architecture))
                self.assertEqual(set(fixture.seen), {name for name, _ in PINS})
            self.assertEqual(attempts, [])

    def test_missing_wrong_version_empty_inventory_and_unsafe_origins_are_refused(self):
        activate = load(self)
        for fault in ("missing", "version", "empty", "outside", "symlink_outside", "hardlink", "absent_origin"):
            with self.subTest(fault=fault), runtime_fixture(self, activate) as fixture, no_sdk_imports() as attempts:
                self.assertEqual(activate.validate_req7_cable_python_runtime(), expected("aarch64"))
                name = "google-api-python-client"
                path = fixture.files[name]
                if fault == "missing":
                    fixture.missing.add(name)
                elif fault == "version":
                    fixture.versions[name] = "0.0.0"
                elif fault == "empty":
                    fixture.inventories[name] = []
                elif fault in ("outside", "symlink_outside"):
                    outside = fixture.root / "outside.py"
                    outside.write_bytes(b"PRIVATE_FOREIGN_ORIGIN = True\n")
                    if fault == "outside":
                        fixture.inventories[name] = [outside]
                    else:
                        path.unlink(); path.symlink_to(outside)
                elif fault == "hardlink":
                    os.link(path, fixture.root / "second-link.py")
                else:
                    path.unlink()
                with self.assertRaises(activate.ActivationError):
                    activate.validate_req7_cable_python_runtime()
                self.assertEqual(attempts, [])

    def test_managed_interpreter_platform_architecture_and_fixed_pair_drift_are_refused(self):
        activate = load(self)
        with runtime_fixture(self, activate) as fixture, no_sdk_imports() as attempts:
            self.assertEqual(activate.validate_req7_cable_python_runtime(), expected("aarch64"))
            variants = ((activate.sys, "executable", str(fixture.root / "foreign-python")),
                        (activate.sys, "version_info", (3, 11, 9)),
                        (activate.sys, "version_info", (3, 13, 0)),
                        (activate.sys, "platform", "darwin"),
                        (platform, "python_implementation", lambda: "PyPy"),
                        (platform, "machine", lambda: "arm64"),
                        (platform, "machine", lambda: "ppc64le"))
            for owner, name, value in variants:
                with self.subTest(field=name, value=str(value)), mock.patch.object(owner, name, value):
                    with self.assertRaises(activate.ActivationError):
                        activate.validate_req7_cable_python_runtime()
            for relative in (POLICY, LOCK):
                path = fixture.root / relative
                before = path.read_bytes()
                path.write_bytes(before + b"\n")
                with self.subTest(pair=relative), self.assertRaises(activate.ActivationError):
                    activate.validate_req7_cable_python_runtime()
                path.write_bytes(before)
            self.assertEqual(attempts, [])
