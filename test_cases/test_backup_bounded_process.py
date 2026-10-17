"""Independent direct contracts for the fixed backup process boundary.

All business functions are AST-selected, never a whole collector import.
Expected status, caps, original exceptions and source refusal are independent literals.
"""
from __future__ import annotations

import ast
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ztp/backup/yaml-collect.py"
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


class BoundedCanonicalDirectTests(unittest.TestCase):
    def definitions(self):
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
        names = ("_read_bounded_source", "_verify_bounded_sources",
                 "_load_bounded_process", "_run_bounded_process")
        selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
        self.assertEqual(sorted(n.name for n in selected), sorted(names),
                         "FEATURE_CONTRACT_API_ABSENT: fixed sibling boundary")
        module = ast.Module(body=[ast.ImportFrom(module="__future__",
            names=[ast.alias(name="annotations")], level=0)] + selected, type_ignores=[])
        return compile(ast.fix_missing_locations(module), str(SOURCE), "exec")

    def namespace(self, code, entry, source_pins=None):
        ns = {"__file__": str(entry), "Path": Path, "os": os, "stat": stat,
              "hashlib": hashlib, "importlib": __import__("importlib"),
              "types": types, "sys": sys, "subprocess": subprocess,
              "MAX_SSH_OUTPUT_BYTES": 65536,
              "_BOUNDED_SOURCE_SHA256": source_pins or {}}
        exec(code, ns)
        return ns

    def test_adapter_preserves_four_inputs_text_cap_marker_and_true_status(self):
        code = self.definitions()
        ns = self.namespace(code, SOURCE)
        argv = ["/owned/literal-command", "", "--literal"]
        env = {"LITERAL": "not-a-secret"}
        stdin = "literal input\n"
        ordinary = types.SimpleNamespace(stdout=b"A\xffB", stderr=b"E\xffF",
                                         stop_reason=None, returncode=17)
        overflow = types.SimpleNamespace(stdout=b"O" * 65536, stderr=b"E" * 65536,
                                         stop_reason="overflow", returncode=17)
        timeout = types.SimpleNamespace(stdout=b"", stderr=b"",
                                        stop_reason="timeout", returncode=17)
        marker = b"\n[output exceeded 65536-byte limit]"
        literals = ((ordinary, 17, "AB", "EF"),
                    (overflow, 125, (b"O" * (65536 - len(marker)) + marker).decode(),
                     (b"E" * (65536 - len(marker)) + marker).decode()),
                    (timeout, 124, "", "timeout after 0.1s"))
        for observed, rc, stdout, stderr in literals:
            with self.subTest(kind=observed.stop_reason):
                events = []
                def verify():
                    events.append("SOURCE_VERIFIED")
                def backend(a, t, env=None, stdin_text=None):
                    events.append("FIXED_BACKEND")
                    self.assertIs(a, argv)
                    self.assertEqual(t, 0.1)
                    self.assertIs(env, env_input)
                    self.assertIs(stdin_text, stdin)
                    return observed
                env_input = env
                ns["_verify_bounded_sources"] = verify
                ns["_BOUNDED_PROCESS"] = types.SimpleNamespace(run_bounded_anchored=backend)
                answer = ns["_run_bounded_process"](argv, 0.1, env=env, stdin_text=stdin)
                self.assertIs(type(answer), subprocess.CompletedProcess)
                self.assertIs(answer.args, argv)
                self.assertEqual((answer.returncode, answer.stdout, answer.stderr), (rc, stdout, stderr))
                self.assertLessEqual(len(answer.stdout.encode()), 65536)
                self.assertLessEqual(len(answer.stderr.encode()), 65536)
                self.assertEqual(events, ["SOURCE_VERIFIED", "FIXED_BACKEND"])
        self.assertEqual(argv, ["/owned/literal-command", "", "--literal"])
        self.assertEqual(env, {"LITERAL": "not-a-secret"})

    def test_loader_is_fixed_sibling_and_rechecks_changed_or_missing_source(self):
        code = self.definitions()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            entry = root / "yaml-collect.py"
            entry.write_bytes(b"# owned fixture origin only\n")
            parent = b"LITERAL_TAG = 'fixed-parent-source'\n"
            launcher = b"# fixed launcher source only, never executed\n"
            pins = {"_bounded_process.py": hashlib.sha256(parent).hexdigest(),
                    "_bounded_process_launcher.py": hashlib.sha256(launcher).hexdigest()}
            ns = self.namespace(code, entry, pins)
            with self.assertRaises((OSError, ValueError)):
                ns["_verify_bounded_sources"]()
            (root / "_bounded_process.py").write_bytes(parent)
            (root / "_bounded_process_launcher.py").write_bytes(launcher)
            before_names = set(sys.modules)
            loaded = ns["_load_bounded_process"]()
            self.assertEqual(loaded.LITERAL_TAG, "fixed-parent-source")
            self.assertEqual(Path(loaded.__file__), root / "_bounded_process.py")
            self.assertEqual(set(sys.modules), before_names)
            (root / "_bounded_process_launcher.py").write_bytes(b"# changed, not admitted\n")
            with self.assertRaises(ValueError):
                ns["_verify_bounded_sources"]()
            (root / "_bounded_process_launcher.py").unlink()
            with self.assertRaises((OSError, ValueError)):
                ns["_verify_bounded_sources"]()
            with self.assertRaises(ValueError):
                ns["_read_bounded_source"]("../unrelated-private-source.py")

    def test_source_hold_precedes_backend_and_original_NI_cause_survives(self):
        code = self.definitions()
        ns = self.namespace(code, SOURCE)
        calls = []
        cause = OSError("independent literal cause")
        primary = KeyboardInterrupt("independent literal primary")
        primary.__cause__ = cause
        def backend(*a, **kw):
            calls.append("BACKEND")
            raise primary
        ns["_BOUNDED_PROCESS"] = types.SimpleNamespace(run_bounded_anchored=backend)
        ns["_verify_bounded_sources"] = lambda: calls.append("VERIFY")
        with self.assertRaises(KeyboardInterrupt) as caught:
            ns["_run_bounded_process"](["/owned/command"], 0.1)
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, cause)
        self.assertEqual(calls, ["VERIFY", "BACKEND"])
        calls.clear()
        hold = ValueError("independent changed original")
        def reject():
            calls.append("VERIFY_HOLD")
            raise hold
        ns["_verify_bounded_sources"] = reject
        with self.assertRaises(ValueError) as held:
            ns["_run_bounded_process"](["/owned/command"], 0.1)
        self.assertIs(held.exception, hold)
        self.assertEqual(calls, ["VERIFY_HOLD"])


class BoundedSourceCleanupTests(unittest.TestCase):
    def reader(self, entry, source_bytes):
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'), filename=str(SOURCE))
        nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == '_read_bounded_source']
        self.assertEqual(len(nodes), 1, 'FEATURE_CONTRACT_API_ABSENT: original-source reader')
        unit = ast.Module(body=[ast.ImportFrom(module='__future__',
            names=[ast.alias(name='annotations')], level=0)] + nodes, type_ignores=[])
        ns = {'__file__': str(entry), 'Path': Path, 'os': os, 'stat': stat,
              'hashlib': hashlib, '_BOUNDED_SOURCE_SHA256': {
                  '_bounded_process.py': hashlib.sha256(source_bytes).hexdigest()}}
        exec(compile(ast.fix_missing_locations(unit), str(SOURCE), 'exec'), ns)
        return ns['_read_bounded_source']

    def lane(self, primary, closing, expected, attachment=None):
        payload = b'# independently written original, not executable fixture\n'
        real_open, real_read, real_close, real_fstat = os.open, os.read, os.close, os.fstat
        with tempfile.TemporaryDirectory(prefix='http-h-reader-close-') as directory:
            root = Path(directory).resolve()
            self.assertEqual(stat.S_IMODE(root.lstat().st_mode), 0o700)
            self.assertEqual(root.lstat().st_uid, os.getuid())
            entry = root / 'yaml-collect.py'
            entry.write_bytes(b'# origin only\n')
            source = root / '_bounded_process.py'
            source.write_bytes(payload)
            source.chmod(0o600)
            before = source.lstat()
            identity = tuple(getattr(before, key) for key in FIELDS)
            self.assertTrue(stat.S_ISREG(before.st_mode))
            self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
            self.assertEqual(before.st_nlink, 1)
            self.assertEqual(before.st_uid, os.getuid())
            reader = self.reader(entry, payload)
            opens, reads, closes, close_identities = [], [], [], []
            caught = None
            def capture_open(path, flags):
                fd = real_open(path, flags)
                opens.append((fd, str(path), flags))
                return fd
            def fail_or_read(fd, count):
                reads.append(fd)
                if primary is not None:
                    raise primary
                return real_read(fd, count)
            def close_then_fail(fd):
                closes.append(fd)
                close_identities.append(tuple(getattr(real_fstat(fd), key) for key in FIELDS))
                real_close(fd)  # Exactly the original, real physical close.
                raise closing
            try:
                with mock.patch.object(os, 'open', capture_open), \
                     mock.patch.object(os, 'read', fail_or_read), \
                     mock.patch.object(os, 'close', close_then_fail):
                    try:
                        reader('_bounded_process.py')
                    except BaseException as error:
                        caught = error
                # Post-assert all injection premises: observer assertions cannot
                # be swallowed by the primary and mistaken for a business RED.
                self.assertEqual(len(opens), 1)
                fd, opened_path, opened_flags = opens[0]
                self.assertEqual(opened_path, str(source))
                self.assertEqual(opened_flags, os.O_RDONLY | os.O_NOFOLLOW)
                self.assertGreaterEqual(len(reads), 1)
                self.assertTrue(all(item == fd for item in reads))
                self.assertEqual(closes, [fd])
                self.assertEqual(close_identities, [identity])
                with self.assertRaises(OSError) as closed:
                    real_fstat(fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
                self.assertIs(caught, expected)
                self.assertIs(caught.__cause__, expected.__cause__)
                if primary is not None and attachment is None:
                    recorded = getattr(primary, 'bounded_source_cleanup_errors', None)
                    self.assertIs(type(recorded), tuple)
                    self.assertEqual(len(recorded), 1)
                    self.assertIs(recorded[0], closing)
                if attachment is not None:
                    self.assertFalse(hasattr(primary, 'bounded_source_cleanup_errors'),
                                     'NOT_CAPTURED is not a successful empty tuple')
                self.assertEqual(source.read_bytes(), payload)
                self.assertEqual(tuple(getattr(source.lstat(), key) for key in FIELDS), identity)
            finally:
                # Conditional fixture rescue is NOT the product close. Only
                # this exact captured original inode may be closed here.
                for fd, _name, _flags in opens:
                    try:
                        current = real_fstat(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
                    else:
                        self.assertEqual(tuple(getattr(current, key) for key in FIELDS), identity)
                        real_close(fd)

    def test_original_source_close_once_obeys_six_literal_priorities(self):
        ordinary = ValueError('literal original ordinary')
        original_NI = KeyboardInterrupt('literal original NI')
        close_ordinary = OSError('literal original close ordinary')
        close_NI = SystemExit('literal original close NI')
        original_NI_cause = OSError('literal original NI cause')
        close_NI_cause = OSError('literal close NI cause')
        original_NI.__cause__ = original_NI_cause
        close_NI.__cause__ = close_NI_cause
        cases = (
            ('ordinary_ordinary', ordinary, close_ordinary, ordinary),
            ('ordinary_close_NI', ordinary, close_NI, close_NI),
            ('original_NI_ordinary', original_NI, close_ordinary, original_NI),
            ('original_NI_close_NI', original_NI, close_NI, original_NI),
            ('no_primary_ordinary', None, close_ordinary, close_ordinary),
            ('no_primary_close_NI', None, close_NI, close_NI),
        )
        for label, primary, closing, expected in cases:
            with self.subTest(literal=label):
                self.lane(primary, closing, expected)
                self.assertIs(original_NI.__cause__, original_NI_cause)
                self.assertIs(close_NI.__cause__, close_NI_cause)

    def test_diagnostic_attachment_NI_cannot_replace_original_or_earlier_close_NI(self):
        attach_NI = KeyboardInterrupt('literal later diagnostic attachment NI')
        attach_cause = OSError('literal later diagnostic cause')
        attach_NI.__cause__ = attach_cause
        class RefuseOrdinary(ValueError):
            def __setattr__(self, name, value):
                if name == 'bounded_source_cleanup_errors':
                    raise attach_NI
                return super().__setattr__(name, value)
        class RefuseNI(KeyboardInterrupt):
            def __setattr__(self, name, value):
                if name == 'bounded_source_cleanup_errors':
                    raise attach_NI
                return super().__setattr__(name, value)
        ordinary = RefuseOrdinary('literal primary ordinary')
        primary_NI = RefuseNI('literal primary NI')
        primary_cause = OSError('literal primary cause')
        primary_NI.__cause__ = primary_cause
        close_ordinary = OSError('literal first cleanup ordinary')
        close_NI = SystemExit('literal first cleanup NI')
        close_cause = OSError('literal first cleanup NI cause')
        close_NI.__cause__ = close_cause
        cases = (
            ('original_NI_remains', primary_NI, close_ordinary, primary_NI),
            ('first_close_NI_remains', ordinary, close_NI, close_NI),
            ('ordinary_yields_to_attachment_NI', ordinary, close_ordinary, attach_NI),
        )
        for label, primary, closing, expected in cases:
            with self.subTest(literal=label):
                self.lane(primary, closing, expected, attachment=attach_NI)
                self.assertIs(primary_NI.__cause__, primary_cause)
                self.assertIs(close_NI.__cause__, close_cause)
                self.assertIs(attach_NI.__cause__, attach_cause)


if __name__ == "__main__":
    unittest.main(verbosity=2)
