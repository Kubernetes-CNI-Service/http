"""Independent HTTP initializer protocol gaps; real same-inode negative wrappers.

These kernel-negative workflows deliberately require the real initializer wrapper
first. Defensive main sentinels prove only rejection before any algorithm/body;
they do not claim full successful initialization, report cleanup or managed-cycle
cleanup. All kernel actors require later root review and a private-path carrier.
"""
import ast
from contextlib import contextmanager
import importlib.util
from importlib.machinery import SourceFileLoader
import inspect
import io
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
UPGRADE = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.py"
FIXED_SYSTEM_LOCK = Path("/tmp/http-ib-bringup.runtime.lock")

@contextmanager
def actual_source(name, path):
    if name in sys.modules:
        raise AssertionError("Cannot overwrite a preexisting source module")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or type(spec.loader) is not SourceFileLoader:
        raise AssertionError("Real fixed source loader is required")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        if sys.modules.get(name) is module:
            del sys.modules[name]

class HttpInitializerGuardProtocolTests(unittest.TestCase):
    def test_upgrade_sole_help_states_current_modes_without_guard_or_runtime_load(self):
        with actual_source("_ibsw_current_handoff_help", UPGRADE) as app:
            output = io.StringIO()
            with mock.patch.object(sys, "argv", [str(UPGRADE), "--help"]), \
                 mock.patch.object(app, "_runtime_instance_guard", side_effect=AssertionError("Help cannot acquire a host lock")) as guard, \
                 mock.patch.object(app, "_fixed_driver", side_effect=AssertionError("Help cannot load operational runtime")) as runtime, \
                 mock.patch.object(sys, "stdout", output):
                with self.assertRaises(SystemExit) as caught:
                    app._guarded_main()
            self.assertEqual(caught.exception.code, 0)
            help_text = " ".join(output.getvalue().split())
            for literal in ("--project", "--diagnose-inputs", "--inspect-only", "--scripts-only", "--upgrade", "--yes",
                            "--os-only", "--bios-only", "--cpld-only",
                            "HTTP is the default transfer; SCP requires explicit selection.",
                            "HTTPS is unsupported; no automatic transport fallback.",
                            "inspection never upgrades devices.", "does not recover earlier UNKNOWN runs"):
                self.assertIn(literal, help_text)
            guard.assert_not_called()
            runtime.assert_not_called()

    def initializer_capability(self, initial):
        self.assertTrue(callable(getattr(initial, "_guarded_main", None)),
            "The real HTTP initializer final standalone entry must expose its guarded wrapper")
        self.assertTrue(callable(getattr(initial, "_runtime_instance_guard", None)),
            "The self-contained initializer must own the fixed same-inode guard algorithm")
        self.assertIs(type(initial), ModuleType)
        self.assertEqual(Path(initial.__file__), INITIAL)
        self.assertEqual(Path(initial.__spec__.origin), INITIAL)
        self.assertIs(type(initial.__spec__.loader), SourceFileLoader)

    def owner(self, owner, path):
        self.assertEqual(owner._RUNTIME_GUARD_PATH, FIXED_SYSTEM_LOCK)
        function = owner._runtime_instance_guard.__wrapped__
        self.assertIs(function.__globals__, vars(owner))
        self.assertEqual(Path(function.__code__.co_filename), path)

    def signature_and_portability(self, initial):
        parameters = inspect.signature(initial.main).parameters
        self.assertEqual(tuple(parameters), ("method_cycle",))
        self.assertIs(parameters["method_cycle"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIsNone(parameters["method_cycle"].default)
        parsed = ast.parse(INITIAL.read_text())
        roots = set()
        for statement in parsed.body:
            if isinstance(statement, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in statement.names)
            elif isinstance(statement, ast.ImportFrom):
                roots.add((statement.module or "").split(".")[0])
        self.assertNotIn("tools", roots)
        self.assertFalse(any(name.startswith("ibsw") for name in roots))
        self.assertTrue(roots <= sys.stdlib_module_names,
            "Supported Leaf single-file initializer must retain standard-library-only imports")

    def test_literal_portable_initializer_entry_and_unchanged_method_cycle_signature(self):
        with actual_source("ibsw_protocol_initial_direct", INITIAL) as initial:
            self.initializer_capability(initial)
            self.owner(initial, INITIAL)
            self.signature_and_portability(initial)

    def test_real_initializer_guard_rejects_upgrade_before_algorithm_on_same_private_inode(self):
        with actual_source("ibsw_protocol_initial_first", INITIAL) as initial:
            self.initializer_capability(initial)  # Initial RED before TD/upgrade import/lock.
            self.owner(initial, INITIAL)
            with actual_source("ibsw_protocol_upgrade_second", UPGRADE) as upgrade:
                canonical = upgrade._runtime_guard_owner
                self.owner(canonical, ROOT / "tools/ib_bringup_runtime_guard.py")
                self.assertIs(upgrade._runtime_instance_guard, canonical._runtime_instance_guard)
                with tempfile.TemporaryDirectory(prefix="ibsw-initial-upgrade-busy-") as raw:
                    lock = Path(raw) / "private-runtime.lock"
                    with mock.patch.object(initial, "_RUNTIME_GUARD_PATH", lock), \
                         mock.patch.object(canonical, "_RUNTIME_GUARD_PATH", lock), \
                         mock.patch.object(upgrade, "main", side_effect=AssertionError("Upgrade body must not run while initialization owns host guard")) as body, \
                         mock.patch.object(sys, "argv", [str(UPGRADE), "--upgrade", "--os-only"]), \
                         mock.patch.object(sys, "stderr", io.StringIO()) as diagnostic:
                        with initial._runtime_instance_guard() as held:
                            before = lock.lstat()
                            self.assertEqual((os.fstat(held).st_dev, os.fstat(held).st_ino),
                                             (before.st_dev, before.st_ino))
                            self.assertEqual(upgrade._guarded_main(), 75)
                            body.assert_not_called()
                            self.assertIn("ALREADY_RUNNING", diagnostic.getvalue())
                            self.assertEqual((lock.lstat().st_dev, lock.lstat().st_ino),
                                             (before.st_dev, before.st_ino))
                        with canonical._runtime_instance_guard() as reacquired:
                            self.assertEqual((os.fstat(reacquired).st_dev, os.fstat(reacquired).st_ino),
                                             (before.st_dev, before.st_ino))
                        self.assertEqual((lock.lstat().st_dev, lock.lstat().st_ino),
                                         (before.st_dev, before.st_ino))

    def test_real_upgrade_guard_rejects_initializer_before_algorithm_on_same_private_inode(self):
        with actual_source("ibsw_protocol_initial_second", INITIAL) as initial:
            self.initializer_capability(initial)  # Initial RED before TD/upgrade import/lock.
            self.owner(initial, INITIAL)
            with actual_source("ibsw_protocol_upgrade_first", UPGRADE) as upgrade:
                canonical = upgrade._runtime_guard_owner
                self.owner(canonical, ROOT / "tools/ib_bringup_runtime_guard.py")
                self.assertIs(upgrade._runtime_instance_guard, canonical._runtime_instance_guard)
                with tempfile.TemporaryDirectory(prefix="ibsw-upgrade-initial-busy-") as raw:
                    lock = Path(raw) / "private-runtime.lock"
                    with mock.patch.object(initial, "_RUNTIME_GUARD_PATH", lock), \
                         mock.patch.object(canonical, "_RUNTIME_GUARD_PATH", lock), \
                         mock.patch.object(initial, "main", side_effect=AssertionError("Initializer body must not run while upgrade owns host guard")) as body, \
                         mock.patch.object(sys, "argv", [str(INITIAL), "--plan"]), \
                         mock.patch.object(sys, "stderr", io.StringIO()) as diagnostic:
                        with canonical._runtime_instance_guard() as held:
                            before = lock.lstat()
                            self.assertEqual((os.fstat(held).st_dev, os.fstat(held).st_ino),
                                             (before.st_dev, before.st_ino))
                            self.assertEqual(initial._guarded_main(), 75)
                            body.assert_not_called()
                            self.assertIn("ALREADY_RUNNING", diagnostic.getvalue())
                            self.assertEqual((lock.lstat().st_dev, lock.lstat().st_ino),
                                             (before.st_dev, before.st_ino))
                        with initial._runtime_instance_guard() as reacquired:
                            self.assertEqual((os.fstat(reacquired).st_dev, os.fstat(reacquired).st_ino),
                                             (before.st_dev, before.st_ino))
                        self.assertEqual((lock.lstat().st_dev, lock.lstat().st_ino),
                                         (before.st_dev, before.st_ino))
