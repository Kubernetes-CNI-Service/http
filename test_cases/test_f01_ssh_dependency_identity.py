"""Independent F01 environment contract; synthetic imports, real local files.

No installed native module is imported and no SSH/socket/process is started.
GREEN here proves the boundary contract, not an actual installation or full.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.machinery
import importlib.metadata
import importlib.util
import io
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PINS = (
    ("paramiko", "5.0.0", ("paramiko",)),
    ("bcrypt", "5.0.0", ("bcrypt", "bcrypt._bcrypt")),
    ("cryptography", "50.0.1", ("cryptography", "cryptography.hazmat.bindings._rust")),
    ("invoke", "2.2.1", ("invoke",)),
    ("PyNaCl", "1.6.2", ("nacl", "nacl._sodium")),
    ("cffi", "2.0.0", ("cffi", "_cffi_backend")),
    ("pycparser", "2.23", ("pycparser",)),
    ("typing-extensions", "4.16.0", ("typing_extensions",)),
)
EXTENSIONS = {"bcrypt._bcrypt", "cryptography.hazmat.bindings._rust", "nacl._sodium", "_cffi_backend"}
LOCK = "# Independent exact eight-package fixture\n" + "".join(f"{n}=={v}\n" for n, v, _ in PINS)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class F01SshDependencyIdentityTests(unittest.TestCase):
    def setUp(self):
        source = ROOT / "tools/f01_ssh_dependency_identity.py"
        self.assertTrue(source.is_file(), "F01 eight-package environment identity boundary is absent")
        spec = importlib.util.spec_from_file_location("f01_dependency_direct", source)
        self.subject = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.subject)
        self.assertTrue(callable(getattr(self.subject, "f01_ssh_dependency_environment", None)))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.area = Path(self.temporary.name).resolve()
        self.repo = self.area / "repo"
        self.repo.mkdir()
        self.lock = self.repo / "requirements-f01-ssh.lock"
        self.lock.write_text(LOCK, encoding="ascii")
        self.lock_sha = digest(LOCK.encode("ascii"))
        self.prefix = self.area / "env"
        self.site = self.prefix / "lib/python3.9/site-packages"
        self.site.mkdir(parents=True)
        (self.prefix / "bin").mkdir()
        self.executable = str(self.prefix / "bin/python")
        (self.prefix / "pyvenv.cfg").write_text(
            "home = /synthetic/base/bin\ninclude-system-site-packages = false\nversion = 3.9.6\n", encoding="ascii")
        self.modules = {}
        self.distributions = []
        for name, version, modules in PINS:
            record = []
            for module_name in modules:
                binary = module_name in EXTENSIONS
                relative = (module_name.replace(".", "/") + importlib.machinery.EXTENSION_SUFFIXES[0]
                            if binary else module_name.replace(".", "/") + "/__init__.py")
                if module_name == "typing_extensions":
                    relative = "typing_extensions.py"
                path = self.site / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = ("independent-fixture:" + module_name + "\n").encode("ascii")
                path.write_bytes(raw)
                module = types.ModuleType(module_name)
                module.__file__ = str(path)
                loader_type = (importlib.machinery.ExtensionFileLoader if binary
                               else importlib.machinery.SourceFileLoader)
                module.__spec__ = importlib.util.spec_from_file_location(
                    module_name, path, loader=loader_type(module_name, str(path)))
                self.modules[module_name] = module
                record.append((relative, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="), str(len(raw))))
            info = self.site / (name.replace("-", "_") + "-" + version + ".dist-info")
            info.mkdir()
            metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode("ascii")
            (info / "METADATA").write_bytes(metadata)
            record.append((info.name + "/METADATA", "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(metadata).digest()).decode().rstrip("="), str(len(metadata))))
            record.append((info.name + "/RECORD", "", ""))
            stream = io.StringIO(newline="")
            csv.writer(stream).writerows(record)
            with (info / "RECORD").open("w", encoding="ascii", newline="") as output:
                output.write(stream.getvalue())
            self.distributions.append(importlib.metadata.PathDistribution(info))

    def observe(self, *, import_hook=None, metadata_hook=None, expected=None):
        def importer(name):
            if import_hook:
                import_hook(name)
            return self.modules[name]
        def distributions():
            if metadata_hook:
                return metadata_hook()
            return list(self.distributions)
        with mock.patch.object(self.subject.sys, "prefix", str(self.prefix)), \
             mock.patch.object(self.subject.sys, "base_prefix", "/synthetic/base"), \
             mock.patch.object(self.subject.sys, "executable", self.executable), \
             mock.patch.object(self.subject.metadata, "distributions", side_effect=distributions), \
             mock.patch.object(self.subject.importlib, "import_module", side_effect=importer):
            return self.subject.f01_ssh_dependency_environment(
                self.repo, expected_lock_sha256=self.lock_sha if expected is None else expected)

    def assert_hold(self, **kwargs):
        with self.assertRaises(self.subject.F01DependencyError):
            self.observe(**kwargs)

    def test_fixed_eight_versions_and_all_twelve_real_file_origins_are_bound(self):
        observed = self.observe()
        self.assertEqual(1, observed["schema_version"])
        self.assertEqual(self.lock_sha, observed["lock_sha256"])
        self.assertEqual(self.executable, observed["python_executable"])
        self.assertEqual(str(self.prefix), observed["environment_prefix"])
        self.assertEqual("/synthetic/base", observed["base_prefix"])
        self.assertEqual(
            {"paramiko": "5.0.0", "bcrypt": "5.0.0", "cryptography": "50.0.1", "invoke": "2.2.1",
             "pynacl": "1.6.2", "cffi": "2.0.0", "pycparser": "2.23", "typing-extensions": "4.16.0"},
            {d["name"]: d["version"] for d in observed["distributions"]})
        sources = {m["name"]: m for d in observed["distributions"] for m in d["modules"]}
        self.assertEqual({"paramiko", "bcrypt", "bcrypt._bcrypt", "cryptography",
                          "cryptography.hazmat.bindings._rust", "invoke", "nacl", "nacl._sodium",
                          "cffi", "_cffi_backend", "pycparser", "typing_extensions"}, set(sources))
        for name, record in sources.items():
            raw = ("independent-fixture:" + name + "\n").encode("ascii")
            self.assertEqual(digest(raw), record["sha256"])
            self.assertEqual(len(raw), record["size_bytes"])
            self.assertEqual(self.modules[name].__file__, record["origin"])

    def test_missing_package_or_duplicate_metadata_refuses_before_import(self):
        original = list(self.distributions)
        for value in (original[:-1], original + [original[0]]):
            imported = []
            self.distributions = value
            self.assert_hold(import_hook=imported.append)
            self.assertEqual([], imported)
        self.distributions = original

    def test_wrong_installed_version_refuses_before_import(self):
        info = self.distributions[0]._path / "METADATA"
        info.write_text("Metadata-Version: 2.1\nName: paramiko\nVersion: 4.0.0\n\n", encoding="ascii")
        imported = []
        self.assert_hold(import_hook=imported.append)
        self.assertEqual([], imported)

    def test_lock_drift_or_snapshot_hash_mismatch_refuses_before_import(self):
        self.assert_hold(expected="0" * 64)
        self.lock.write_text(LOCK.replace("typing-extensions==4.16.0", "typing-extensions==4.15.0"), encoding="ascii")
        self.lock_sha = digest(self.lock.read_bytes())
        imported = []
        self.assert_hold(import_hook=imported.append)
        self.assertEqual([], imported)

    def test_system_site_packages_true_is_not_an_isolated_environment(self):
        (self.prefix / "pyvenv.cfg").write_text("include-system-site-packages = true\n", encoding="ascii")
        imported = []
        self.assert_hold(import_hook=imported.append)
        self.assertEqual([], imported)

    def test_system_python_is_not_an_isolated_environment(self):
        # observe owns the actual sys boundary, so use its configured base path.
        self.prefix = Path("/synthetic/base")
        self.assert_hold()

    def test_ambient_main_module_or_native_extension_is_rejected(self):
        for name in ("paramiko", "_cffi_backend"):
            module = self.modules[name]
            original_file, original_spec = module.__file__, module.__spec__
            outside = self.area / (name + ".py")
            outside.write_text("ambient\n", encoding="ascii")
            module.__file__ = str(outside)
            module.__spec__ = importlib.util.spec_from_file_location(name, outside)
            self.assert_hold()
            module.__file__, module.__spec__ = original_file, original_spec

    def test_module_spec_must_match_loaded_file_and_record_ownership(self):
        self.modules["paramiko"].__spec__.origin = self.modules["invoke"].__file__
        self.assert_hold()
        self.modules["paramiko"].__spec__.origin = self.modules["paramiko"].__file__
        record = self.distributions[0]._path / "RECORD"
        record.write_text("paramiko-5.0.0.dist-info/RECORD,,\n", encoding="ascii")
        self.assert_hold()

    def test_same_version_metadata_and_record_from_another_environment_are_rejected(self):
        foreign = self.area / "foreign/paramiko-5.0.0.dist-info"
        foreign.mkdir(parents=True)
        for name in ("METADATA", "RECORD"):
            (foreign / name).write_bytes((self.distributions[0]._path / name).read_bytes())
        self.distributions[0] = importlib.metadata.PathDistribution(foreign)
        self.assert_hold()

    def test_source_change_during_import_is_not_a_stable_identity(self):
        def change(name):
            if name == "paramiko":
                Path(self.modules[name].__file__).write_text("changed during import\n", encoding="ascii")
        self.assert_hold(import_hook=change)

    def test_same_bytes_replacement_of_original_metadata_during_import_is_rejected(self):
        def replace(name):
            if name == "paramiko":
                path = self.distributions[0]._path / "METADATA"
                replacement = path.with_name("replacement")
                replacement.write_bytes(path.read_bytes())
                replacement.replace(path)
        self.assert_hold(import_hook=replace)

    def test_same_bytes_ancestor_rebinding_during_import_is_rejected(self):
        def replace(name):
            if name == "paramiko":
                original = self.prefix / "lib"
                held = self.prefix / "held-lib"
                original.rename(held)
                shutil.copytree(held, original)
        self.assert_hold(import_hook=replace)

    def test_later_import_cannot_rebind_previously_loaded_module_loader(self):
        def replace(name):
            if name == "typing_extensions":
                self.modules["paramiko"].__spec__.loader = importlib.machinery.SourceFileLoader(
                    "paramiko", str(self.area / "unrelated.py"))
        self.assert_hold(import_hook=replace)

    def test_distribution_set_must_still_be_unique_after_imports(self):
        calls = []
        def changed():
            calls.append(1)
            return list(self.distributions) + ([self.distributions[0]] if len(calls) > 1 else [])
        self.assert_hold(metadata_hook=changed)

    def test_module_origin_symlink_is_rejected(self):
        path = Path(self.modules["paramiko"].__file__)
        actual = path.with_name("real.py")
        path.rename(actual)
        path.symlink_to(actual)
        self.assert_hold()

    def test_changed_valid_environment_changes_identity_for_old_proof_comparison(self):
        before = self.observe()
        config = self.prefix / "pyvenv.cfg"
        config.write_text(config.read_text() + "prompt = second-environment\n", encoding="ascii")
        after = self.observe()
        self.assertNotEqual(before, after)
        self.assertNotEqual(before["pyvenv_cfg_sha256"], after["pyvenv_cfg_sha256"])


if __name__ == "__main__":
    unittest.main()
