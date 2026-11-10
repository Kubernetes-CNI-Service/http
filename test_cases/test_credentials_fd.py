"""Direct contract for tools/credentials_fd.py: one JSON credential object from an inherited fd.

Expectations come from the R-012 design §8.3 (:340-348) and §19 (:619), from problem document I-007
rules 5 and 6 (:427-428) and from the v3.1.3 guide WP-5 / O5, not from the implementation.  Every
credential value is assembled at run time; none is written in this file.
"""

from __future__ import annotations

import ast
import errno
import importlib.util
import json
import os
from pathlib import Path
import sys
import sysconfig
import threading
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import device_identity as DI  # noqa: E402

MODULE_PATH = ROOT / "tools/credentials_fd.py"


def load():
    """The module by its package name, as initial-setup's _import_tools loads it (guide O5)."""
    from tools import credentials_fd
    return credentials_fd


def secret(label: str) -> str:
    return "-".join(("PUBLIC", "fd", label, str(os.getpid()), "Zq7"))


def pipe_with(data: bytes) -> int:
    """A real pipe fed by its own thread: input larger than the kernel pipe buffer (the oversize
    case) must not block the writer before the reader runs."""
    reader, writer = os.pipe()

    def feed() -> None:
        view = memoryview(data)
        try:
            while view:
                view = view[os.write(writer, view):]
        except OSError:
            pass  # the reader stopped early (oversize) and closed its end
        finally:
            os.close(writer)

    threading.Thread(target=feed, daemon=True).start()
    return reader


def assert_closed(test: unittest.TestCase, fd: int) -> None:
    with test.assertRaises(OSError) as caught:
        os.fstat(fd)
    test.assertEqual(errno.EBADF, caught.exception.errno)


def chain_text(error: BaseException) -> str:
    """Everything an operator or a log could see of an error and its whole chain."""
    parts = ["".join(traceback.format_exception(type(error), error, error.__traceback__))]
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.extend((str(current), repr(current), repr(current.args)))
        if hasattr(current, "__dict__"):
            parts.extend(repr(value) for value in vars(current).values())
        current = current.__cause__ or current.__context__
    return "\n".join(parts)


class CredentialsFdTests(unittest.TestCase):
    def setUp(self) -> None:
        self.CF = load()

    def test_reads_one_json_object_and_closes_fd(self) -> None:
        # R-012 design :343: read one JSON object from the inherited pipe fd, then close it.
        initial = secret("initial")
        fd = pipe_with(json.dumps({"nvos_initial_password": initial}).encode("utf-8"))
        values = self.CF.read_credentials(fd, required=("nvos_initial_password",), optional=())
        self.assertEqual({"nvos_initial_password": initial}, values)
        assert_closed(self, fd)
        # A refused input closes the fd as well: nothing stays readable after the entry.
        fd = pipe_with(b"[]")
        with self.assertRaises(self.CF.CredentialsError):
            self.CF.read_credentials(fd, required=(), optional=("nvos_initial_password",))
        assert_closed(self, fd)

    def test_unknown_keys_ignored_missing_required_refused(self) -> None:
        # R-012 design :344: each script takes only the keys it knows, ignores the rest, and
        # refuses a missing required key at the entry.
        initial, other, future = secret("initial"), secret("other"), secret("future")
        payload = {"nvos_initial_password": initial, "upgrade_password": other, "future_key": future}
        fd = pipe_with(json.dumps(payload).encode("utf-8"))
        values = self.CF.read_credentials(fd, required=(), optional=("nvos_initial_password",))
        self.assertEqual({"nvos_initial_password": initial}, values)
        for required in (("ib_target_password",), ("jump_passwords",)):
            with self.subTest(required=required):
                fd = pipe_with(json.dumps(payload).encode("utf-8"))
                with self.assertRaises(self.CF.CredentialsError) as caught:
                    self.CF.read_credentials(fd, required=required, optional=("nvos_initial_password",))
                self.assertIs(self.CF.CredentialsError, type(caught.exception))
                self.assertIn(required[0], str(caught.exception))
        # An absent optional key is simply absent.
        fd = pipe_with(b"{}")
        self.assertEqual({}, self.CF.read_credentials(
            fd, required=(), optional=("nvos_initial_password", "ib_target_password", "jump_passwords")))

    def test_errors_never_echo_values(self) -> None:
        # R-012 design :346 and :619: no password in argv, environment, logs or state; an error
        # message, its repr and its exception chain are logs too.
        value = secret("never-echo")
        cases = {
            "not json": ("{" + value).encode("utf-8"),
            "not utf-8": b"\xff" + json.dumps({"ib_target_password": value}).encode("utf-8"),
            "wrong type": json.dumps({"ib_target_password": [value]}).encode("utf-8"),
            "empty host": json.dumps({"jump_passwords": {"": value}}).encode("utf-8"),
            "host value type": json.dumps({"jump_passwords": {"EXAMPLE-JUMP01": [value]}}).encode("utf-8"),
            "missing next to value": json.dumps({"nvos_initial_password": value}).encode("utf-8"),
            "not an object": json.dumps([value]).encode("utf-8"),
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                fd = pipe_with(data)
                with self.assertRaises(self.CF.CredentialsError) as caught:
                    self.CF.read_credentials(fd, required=("ib_target_password",),
                                             optional=("nvos_initial_password", "jump_passwords"))
                self.assertNotIn(value, chain_text(caught.exception))
        with self.subTest(case="ambiguous host table"):
            table = {"EXAMPLE-JUMP01": value, "example-jump01.site.example.test": secret("twin")}
            with self.assertRaises(self.CF.CredentialsError) as caught:
                self.CF.host_passwords(table, key=DI.short_key)
            text = chain_text(caught.exception)
            self.assertNotIn(value, text)
            self.assertNotIn(secret("twin"), text)

    def test_non_object_oversize_and_non_utf8_refused(self) -> None:
        # R-012 design :344 (strict out): only one UTF-8 JSON object of bounded size is accepted.
        oversize = json.dumps({"nvos_initial_password": "x" * (64 * 1024)}).encode("utf-8")
        for label, data in (
            ("array", b"[]"), ("string", b'"x"'), ("number", b"1"), ("null", b"null"),
            ("empty", b""), ("two objects", b"{} {}"),
            ("oversize", oversize), ("non-utf-8", b'{"nvos_initial_password": "\xff\xfe"}'),
        ):
            with self.subTest(case=label):
                fd = pipe_with(data)
                with self.assertRaises(self.CF.CredentialsError) as caught:
                    self.CF.read_credentials(fd, required=(), optional=("nvos_initial_password",))
                self.assertIs(self.CF.CredentialsError, type(caught.exception))
                assert_closed(self, fd)
        with self.subTest(case="unreadable fd"):
            reader, writer = os.pipe()
            os.close(writer)
            os.close(reader)
            with self.assertRaises(self.CF.CredentialsError):
                self.CF.read_credentials(reader, required=(), optional=("nvos_initial_password",))

    def test_host_table_matches_by_short_key_and_refuses_ambiguity(self) -> None:
        # Problem document I-007 rules 5 and 6 (:427-428): compare by the short name (part before
        # the first ".", casefolded); short keys must be unique, never guessed between.
        leaf, spine = secret("leaf"), secret("spine")
        fd = pipe_with(json.dumps({"jump_passwords": {
            "EW-Leaf01.site.example.test": leaf, "oob-spine01": spine}}).encode("utf-8"))
        values = self.CF.read_credentials(fd, required=("jump_passwords",), optional=())
        table = self.CF.host_passwords(values["jump_passwords"], key=DI.short_key)
        self.assertEqual(leaf, table[DI.short_key("ew-leaf01")])
        self.assertEqual(spine, table[DI.short_key("OOB-SPINE01.example.test")])
        self.assertNotIn(DI.short_key("ew-leaf02"), table)
        with self.assertRaises(self.CF.CredentialsError):
            self.CF.host_passwords({"EW-Leaf01": leaf, "ew-leaf01.site.example.test": spine},
                                   key=DI.short_key)

    def test_module_imports_no_other_tools_module(self) -> None:
        # Guide O5: only the standard library, so the module works in both the repository layout
        # and the Leaf same-directory layout; appendix A.7: a library has a module docstring and
        # neither argparse nor a __main__ block.
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))
        self.assertTrue(ast.get_docstring(tree), "library module needs a docstring")
        stdlib = {Path(sysconfig.get_paths()[name]).resolve() for name in ("stdlib", "platstdlib")}
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(0, node.level, "no relative import")
                imported.append(node.module)
        for name in imported:
            top = name.split(".")[0]
            with self.subTest(module=name):
                self.assertNotEqual("tools", top)
                self.assertNotEqual("argparse", top)
                if top == "__future__":
                    continue
                spec = importlib.util.find_spec(top)
                self.assertIsNotNone(spec)
                if spec.origin in ("built-in", "frozen"):
                    continue
                origin = Path(spec.origin).resolve()
                self.assertTrue(any(root in origin.parents for root in stdlib),
                                f"{name} is not from the standard library")
                self.assertNotIn("site-packages", origin.parts)
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "__name__":
                self.fail("a library module has no __main__ block")


if __name__ == "__main__":
    unittest.main()
