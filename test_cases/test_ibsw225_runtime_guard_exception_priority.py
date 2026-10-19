"""Guard exception identity contract for both real source owners; private inode only."""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
OWNERS = (
    ("embedded", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"),
    ("canonical", ROOT / "tools/ib_bringup_runtime_guard.py"),
)

@contextmanager
def owner_source(label, path):
    name = "_ibsw_guard_exception_" + label
    if name in sys.modules:
        raise AssertionError("Cannot overwrite an existing module")
    spec = importlib.util.spec_from_file_location(name, path)
    owner = importlib.util.module_from_spec(spec)
    sys.modules[name] = owner
    try:
        spec.loader.exec_module(owner)
        yield owner
    finally:
        if sys.modules.get(name) is owner:
            del sys.modules[name]

class RuntimeGuardExceptionPriorityTests(unittest.TestCase):
    def exercise(self, label, path, primary, cleanup, expected):
        with owner_source(label, path) as owner:
            with tempfile.TemporaryDirectory(prefix="ibsw-guard-exception-") as raw:
                lock = Path(raw) / "private-runtime.lock"
                self.assertNotEqual(lock, Path("/tmp/http-ib-bringup.runtime.lock"))
                real_close = os.close
                close_returns = []
                closing = [False]
                def final_close(descriptor):
                    result = real_close(descriptor)
                    close_returns.append((descriptor, result))
                    if closing[0]:
                        raise cleanup
                    return result
                with mock.patch.object(owner, "_RUNTIME_GUARD_PATH", lock), mock.patch.object(owner.os, "close", final_close):
                    try:
                        with owner._runtime_instance_guard() as descriptor:
                            named = lock.lstat()
                            self.assertEqual((os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino), (named.st_dev, named.st_ino))
                            closing[0] = True
                            if primary is not None:
                                raise primary
                    except BaseException as caught:
                        self.assertIs(caught, expected)
                    else:
                        self.fail("The original primary or cleanup failure must propagate")
                self.assertEqual(close_returns, [(descriptor, None)])
                with self.assertRaises(OSError) as closed:
                    os.fstat(descriptor)
                self.assertEqual(closed.exception.errno, 9)
                self.assertEqual((lock.lstat().st_dev, lock.lstat().st_ino), (named.st_dev, named.st_ino))

    def test_pending_nonordinary_survives_ordinary_close_failure_and_keeps_cause(self):
        for label, path in OWNERS:
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(owner=label, primary=kind.__name__):
                    cause = ValueError("original cause")
                    primary = kind("original primary")
                    primary.__cause__ = cause
                    cleanup = OSError("original close failure")
                    self.exercise(label, path, primary, cleanup, primary)
                    self.assertIs(primary.__cause__, cause)

    def test_cleanup_nonordinary_wins_over_ordinary_body_error(self):
        for label, path in OWNERS:
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(owner=label, cleanup=kind.__name__):
                    cleanup = kind("original cleanup")
                    self.exercise(label, path, ValueError("original body"), cleanup, cleanup)

    def test_close_failure_without_body_error_propagates_same_object(self):
        for label, path in OWNERS:
            with self.subTest(owner=label):
                cleanup = OSError("original close failure")
                self.exercise(label, path, None, cleanup, cleanup)
