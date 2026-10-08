"""Independent exact-source and fresh-namespace contracts for test imports."""
import builtins
import os
from pathlib import Path
import py_compile
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


class ModuleLoaderContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="exact-source-loader-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.paths_before = sys.path[:]
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), self.paths_before))
        self.names = {}
        self.addCleanup(self.restore_modules)

    def restore_modules(self):
        for name, previous in self.names.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

    def load(self, path, suffix=""):
        name = "exact_source_" + self._testMethodName + suffix
        self.names.setdefault(name, sys.modules.get(name))
        return load_script(name, path)

    def test_identical_source_compiles_once_but_executes_in_fresh_namespaces(self):
        path = self.root / "fresh.py"
        path.write_text(
            "from dataclasses import dataclass\n"
            "VALUES = []\n"
            "@dataclass\nclass Record:\n    value: int\n"
            "def make_record(value):\n    return Record(value)\n",
            encoding="utf-8",
        )
        with mock.patch.object(builtins, "compile", wraps=builtins.compile) as compiler:
            first = self.load(path)
            first.VALUES.append("first only")
            second = self.load(path)
        calls = [call for call in compiler.call_args_list if call.args[1] == str(path)]
        self.assertEqual(1, len(calls))
        self.assertIsNot(first, second)
        self.assertEqual([], second.VALUES)
        self.assertIsNot(first.Record, second.Record)
        self.assertIs(first.Record, type(first.make_record(17)))
        self.assertIs(second.Record, type(second.make_record(23)))
        self.assertEqual(17, first.make_record(17).value)
        self.assertEqual(23, second.make_record(23).value)
        self.assertIs(first, sys.modules[first.__name__])

    def test_stale_timestamp_bytecode_cannot_override_current_source_bytes(self):
        path = self.root / "timestamp.py"
        path.write_bytes(b"VALUE = 1\n")
        original = path.stat()
        with mock.patch.object(sys, "pycache_prefix", None):
            py_compile.compile(str(path), doraise=True)
            path.write_bytes(b"VALUE = 2\n")
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
            self.assertEqual(original.st_size, path.stat().st_size)
            self.assertEqual(original.st_mtime_ns, path.stat().st_mtime_ns)
            self.assertEqual(b"VALUE = 2\n", path.read_bytes())
            self.assertEqual(2, self.load(path).VALUE)

    def test_same_size_same_mtime_change_is_not_an_in_memory_cache_hit(self):
        path = self.root / "rebound.py"
        path.write_bytes(b"VALUE = 1\n")
        original = path.stat()
        self.assertEqual(1, self.load(path).VALUE)
        path.write_bytes(b"VALUE = 2\n")
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(2, self.load(path).VALUE)

    def test_deleted_source_is_not_recovered_from_cached_code(self):
        path = self.root / "removed.py"
        path.write_text("VALUE = 7\n", encoding="utf-8")
        self.assertEqual(7, self.load(path).VALUE)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.load(path)

    def test_identical_bytes_keep_each_logical_filename_in_function_code(self):
        for basename in ("first.py", "second.py"):
            path = self.root / basename
            path.write_text("def fail():\n    raise ValueError('literal failure')\n", encoding="utf-8")
            module = self.load(path, basename)
            self.assertEqual(str(path), module.fail.__code__.co_filename)
            with self.assertRaises(ValueError) as raised:
                module.fail()
            self.assertEqual("literal failure", str(raised.exception))

    def test_invalid_new_source_restores_previous_module_and_owned_paths(self):
        path = self.root / "invalid.py"
        path.write_text("VALUE = 7\n", encoding="utf-8")
        first = self.load(path)
        before = sys.path[:]
        path.write_text("def invalid(:\n", encoding="utf-8")
        with self.assertRaises(SyntaxError):
            self.load(path)
        self.assertIs(first, sys.modules[first.__name__])
        self.assertEqual(before, sys.path)
        path.write_text("VALUE = 9\n", encoding="utf-8")
        self.assertEqual(9, self.load(path).VALUE)

    def test_cached_execution_preserves_production_declared_lazy_import_path(self):
        path = self.root / "paths.py"
        path.write_text("import sys\nsys.path.insert(0, 'literal-module-authority')\n", encoding="utf-8")
        for _ in range(2):
            before = sys.path[:]
            self.load(path)
            self.assertEqual(["literal-module-authority", *before], sys.path)

    def test_python_encoding_cookie_and_future_flags_are_preserved(self):
        path = self.root / "encoding.py"
        path.write_bytes(
            b"# coding: latin-1\nfrom __future__ import annotations\n"
            b"VALUE = '\xe9'\ndef annotated(value: Missing):\n    return value\n"
        )
        for _ in range(2):
            module = self.load(path)
            self.assertEqual("\u00e9", module.VALUE)
            self.assertEqual({"value": "Missing"}, module.annotated.__annotations__)

    def test_fresh_source_package_retains_relative_import_metadata(self):
        package = self.root / "package"
        package.mkdir()
        (package / "member.py").write_text("VALUE = 29\n", encoding="utf-8")
        path = package / "__init__.py"
        path.write_text("from .member import VALUE\n", encoding="utf-8")
        name = "exact_source_" + self._testMethodName
        self.addCleanup(lambda: sys.modules.pop(name + ".member", None))
        for _ in range(2):
            module = self.load(path)
            self.assertEqual(29, module.VALUE)
            self.assertEqual(name, module.__package__)
            self.assertEqual([str(package)], list(module.__path__))

    def test_compile_cache_is_bounded_and_eviction_keeps_fresh_values(self):
        paths = [self.root / ("entry_%d.py" % index) for index in range(9)]
        for index, path in enumerate(paths):
            path.write_text("VALUE = %d\n" % index, encoding="utf-8")
        with mock.patch.object(builtins, "compile", wraps=builtins.compile) as compiler:
            for index, path in enumerate(paths):
                self.assertEqual(index, self.load(path).VALUE)
            self.assertEqual(0, self.load(paths[0]).VALUE)
            self.assertEqual(8, self.load(paths[8]).VALUE)
        calls = [call for call in compiler.call_args_list if call.args[1] in {str(p) for p in paths}]
        self.assertEqual(10, len(calls))

    def test_large_sources_load_without_retention_in_compile_cache(self):
        path = self.root / "large.py"
        path.write_bytes(b"#" + b"x" * (2 * 1024 * 1024) + b"\nVALUE = 31\n")
        with mock.patch.object(builtins, "compile", wraps=builtins.compile) as compiler:
            for _ in range(2):
                self.assertEqual(31, self.load(path).VALUE)
        calls = [call for call in compiler.call_args_list if call.args[1] == str(path)]
        self.assertEqual(2, len(calls))


if __name__ == "__main__":
    unittest.main()
