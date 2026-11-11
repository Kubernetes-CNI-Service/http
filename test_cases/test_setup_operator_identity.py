"""Direct: a standalone 01-a-setup.py run by root decides its identity like load (I-006, v3.1.3 guide section 8).

What: only a root run (sudo or a direct root login) on the systemd backend, outside load's server-delegated
child, prints operator_identity's identity line.  V via sudo on U's project, an invalid sudo invoker and a
project owner missing from passwd are refused (exit 1) before any write, --dry-run too.  Root acting for U
prepares laptop.pub in U's own child process (the parent never reads HOME's ~/.ssh) and hands what this run
created in the project to U, on success and on failure; root's own project and non-root runs are unchanged.
The hidden child entry needs the root-parent marker, a non-root process and never generates a key.

Expectation sources (not derived from the implementation): v3.1.3 guide 8.2 (:1875-1891), 8.4 (:1904-1923),
8.5 (:1925-1939) with the 8.3 defaults decided by http dev 2026-11-09 (D1S-O1..O4 all (a)); v3.1.2 guide
:223, :508-516, :528-530, :615, :623-626, :2215-2219; 问题文档 I-006 方案 (owner 2026-10-27, :290-295, :347);
the plan row 「§1 D1 I-006（01-a-setup 单独运行）」; tools/operator_identity.py's file header (:18-19, O11 ④).

Root is never real here.  Tests play root by replacing 01-a-setup's entry step with itself on injected
inputs (functools.partial: euid, environment, passwd, the project owner; guide 8.4 #1, 2.2 #5), never by
mocking os.geteuid as a whole.  operator_identity.run_as_operator and the handover function that
_load_module() returns are recorders.  The project tree is test_activate_project_contract.Sandbox (the
repository template and synthetic projects in a temporary tree, setup's globals rebased onto it); HOME is a
temporary directory (guide 2.2 #6).  Real uid switching is TC-REAL-I006-OPERATOR-LOAD-001 step 10 (NOT RUN).
"""

from __future__ import annotations

import argparse
import ast
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stderr, redirect_stdout
import functools
import importlib.abc
import io
import os
from pathlib import Path
import pwd
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_activate_project_contract as ACTIVATE
from test_cases.test_ssh_key_preparation_contract import public_line

SETUP = ACTIVATE.SETUP
CONTRACT = ACTIVATE.CONTRACT
PREPARE = SETUP._prepare_laptop_public_key      # the real function: Sandbox.patches() replaces it
import operator_identity as IDENTITY            # noqa: E402  the flat module 01-a-setup imports (tools/ on sys.path)

MARKER = IDENTITY.ROOT_PARENT_MARKER
ME = pwd.getpwuid(os.getuid())


def passwd_entry(name: str, uid: int, gid: int, home: str) -> pwd.struct_passwd:
    return pwd.struct_passwd((name, "x", uid, gid, "fixture", home, "/bin/sh"))


ROOT_ENTRY = passwd_entry("root", 0, 0, "/nonexistent/fixture-home/root")
U = passwd_entry("opuser", ME.pw_uid + 1, ME.pw_gid, "/nonexistent/fixture-home/opuser")
V = passwd_entry("vuser", ME.pw_uid + 2, ME.pw_gid, "/nonexistent/fixture-home/vuser")
NOBODY_UID = ME.pw_uid + 9    # a project owner with no passwd entry


def as_root(*, owner_uid: int, sudo=None, sudo_uid=None, euid: int = 0, backend=None):
    """Play root through 01-a-setup's own entry step on injected inputs (guide 8.4 #1)."""
    real = getattr(SETUP, "_setup_operator", None)
    if real is None:
        return nullcontext()     # before 8.4 there is no entry step to play root through
    entries = {entry.pw_uid: entry for entry in (ROOT_ENTRY, U, V)}
    names = {entry.pw_name: entry for entry in (ROOT_ENTRY, U, V)}

    def getpwuid(uid):
        if uid not in entries:
            raise KeyError(uid)
        return entries[uid]

    def getpwnam(name):
        if name not in names:
            raise KeyError(name)
        return names[name]

    def project_owner(path):
        os.stat(path)              # FileNotFoundError: a project still to be created (O11 ④)
        return SimpleNamespace(st_uid=owner_uid)

    environ = {}
    if sudo is not None:
        environ.update(SUDO_USER=sudo, SUDO_UID=str(sudo_uid))
    if backend is not None:
        environ["HTTP_ZTP_RUNTIME_BACKEND"] = backend
    return mock.patch.object(SETUP, "_setup_operator", functools.partial(
        real, euid=euid, environ=environ, getpwuid=getpwuid, getpwnam=getpwnam, stat=project_owner))


def names_under(project: Path) -> set:
    """The project's entries by relative name, links not followed: this test's own witness."""
    found = set()
    for current, directories, files in os.walk(project):
        for name in (*directories, *files):
            found.add((Path(current) / name).relative_to(project).as_posix())
    return found


class SetupOperatorEntryTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="setup-operator-")
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name).resolve()
        self.box = ACTIVATE.Sandbox(self.base)
        self.project = self.box.day0 / ACTIVATE.PROJECT
        self.home = self.base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        self.events = []

    def recorder(self, label, result=None):
        def record(*args, **kwargs):
            self.events.append((label, args, kwargs))
            return result
        return record

    @contextmanager
    def stage(self, *, real_prepare=True, child_code=0, **overrides):
        """setup bound to the Sandbox; the child start and the handover are recorders."""
        with ExitStack() as stack:
            stack.enter_context(self.box.patches(**overrides))
            if real_prepare:
                stack.enter_context(mock.patch.object(SETUP, "_prepare_laptop_public_key", PREPARE))
            stack.enter_context(mock.patch.object(SETUP, "deployment_lock", return_value=mock.MagicMock()))
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(self.home)}))
            os.environ.pop(MARKER, None)
            stack.enter_context(mock.patch.object(Path, "home", return_value=self.home))
            stack.enter_context(mock.patch.object(IDENTITY, "run_as_operator", self.recorder("child", child_code)))
            hand = self.recorder("hand")
            stack.enter_context(mock.patch.object(
                SETUP, "_load_module", lambda: SimpleNamespace(_hand_new_entries_to_operator=hand), create=True))
            yield stack

    def run_main(self, *options, project=None):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            try:
                code = SETUP.main(["--host-role=workstation", "-y", "--no-upgrade", *options,
                                   str(project or self.project)])
            except SystemExit as stop:
                code = ACTIVATE.exit_code(stop)
        return code, output.getvalue()

    def labels(self):
        return [event[0] for event in self.events]

    def test_sudo_v_on_u_project_refused_before_any_write(self):
        # O7 ② (v3.1.2 guide :223, :511); :2215, :2218 (refused at the entry, after the deployment lock,
        # before any write, --dry-run too); plan row §1 D1 I-006（01-a-setup 单独运行）「拒绝 V」.
        for options in ((), ("--dry-run",)):
            with self.subTest(options=options):
                before = ACTIVATE.snapshot(self.box.root)
                with self.stage() as stack:
                    for name in ("_initialize_project_from_template", "setup"):
                        stack.enter_context(mock.patch.object(
                            SETUP, name, side_effect=AssertionError(name + " after a refusal")))
                    stack.enter_context(as_root(owner_uid=U.pw_uid, sudo=V.pw_name, sudo_uid=V.pw_uid))
                    code, output = self.run_main(*options)
                self.assertEqual(1, code, output)
                self.assertIn("操作员：" + U.pw_name, output, "the identity line")
                error = next((line for line in output.splitlines() if "[ERROR]" in line), "")
                self.assertIn(U.pw_name, error)
                self.assertIn(V.pw_name, error)
                self.assertEqual([], self.events)
                self.assertEqual(before, ACTIVATE.snapshot(self.box.root))
                self.assertIsNone(self.box.pointer())

    def test_invalid_invoker_and_unknown_owner_refused_even_for_root_login(self):
        # v3.1.2 guide :513 (an owner missing from passwd is refused, also for a direct root login; the prompt names
        # `sudo chown <操作员>:<操作员主组> <项目>`), :514 (sudo invoker checks); :2215 last sentence.
        cases = (
            ("unknown SUDO_USER", dict(owner_uid=U.pw_uid, sudo="ghost", sudo_uid=ME.pw_uid + 7)),
            ("SUDO_UID differs", dict(owner_uid=U.pw_uid, sudo=U.pw_name, sudo_uid=V.pw_uid)),
            ("owner not in passwd, sudo", dict(owner_uid=NOBODY_UID, sudo=U.pw_name, sudo_uid=U.pw_uid)),
            ("owner not in passwd, root login", dict(owner_uid=NOBODY_UID)),
        )
        for label, inputs in cases:
            with self.subTest(case=label):
                before = ACTIVATE.snapshot(self.box.root)
                with self.stage() as stack:
                    stack.enter_context(mock.patch.object(
                        SETUP, "setup", side_effect=AssertionError("setup after a refusal")))
                    stack.enter_context(as_root(**inputs))
                    code, output = self.run_main()
                self.assertEqual(1, code, output)
                self.assertIn("[ERROR]", output)
                if inputs["owner_uid"] == NOBODY_UID:
                    self.assertIn(f"sudo chown <操作员>:<操作员主组> {self.project}", output)
                self.assertEqual([], self.events)
                self.assertEqual(before, ACTIVATE.snapshot(self.box.root))

    def test_supervisor_backend_and_server_delegated_child_skip_identity(self):
        # v3.1.2 guide :2219 (supervisor backend: no identity, no line); development plan :112 (Docker frozen);
        # principle 8 (load's server-delegated child path does not change).
        with self.stage() as stack:
            stack.enter_context(mock.patch.object(IDENTITY, "resolve_operator",
                                                  side_effect=AssertionError("identity computed")))
            transaction = stack.enter_context(mock.patch.object(SETUP, "setup"))
            stack.enter_context(as_root(owner_uid=U.pw_uid, sudo=U.pw_name, sudo_uid=U.pw_uid,
                                        backend="supervisor"))
            code, output = self.run_main()
        self.assertEqual(0, code, output)
        self.assertNotIn("操作员：", output)
        transaction.assert_called_once_with(str(self.project))
        with self.stage() as stack:
            stack.enter_context(mock.patch.object(IDENTITY, "resolve_operator",
                                                  side_effect=AssertionError("identity computed")))
            stack.enter_context(mock.patch.object(SETUP, "stop_native_ztp_monitors"))
            transaction = stack.enter_context(mock.patch.object(SETUP, "setup"))
            stack.enter_context(as_root(owner_uid=U.pw_uid, sudo=U.pw_name, sudo_uid=U.pw_uid))
            args = argparse.Namespace(project=str(self.project), create=False, p2p_file=None,
                                      host_role="management-server", _server_delegated=True)
            output = io.StringIO()
            with redirect_stdout(output):
                code = SETUP._main_locked(args)
        self.assertEqual(0, code, output.getvalue())
        self.assertNotIn("操作员：", output.getvalue())
        transaction.assert_called_once_with(str(self.project), server_delegated=True)

    def test_non_root_run_unchanged_and_never_imports_operator_identity(self):
        # Plan row §1 D1 I-006（01-a-setup 单独运行）「被 root 或 sudo 运行时」; 设计/I-006与R-005实现计划.md:96
        # (standalone setup may run as the operator); D1S-O3 (a).
        class Refuse(importlib.abc.MetaPathFinder):
            hits = []

            def find_spec(self, fullname, path=None, target=None):
                if fullname == "operator_identity":
                    self.hits.append(fullname)
                    raise ImportError("operator_identity imported by a non-root setup")
                return None

        for label, owner in (("U on U's project", ME.pw_uid), ("V runs directly", U.pw_uid)):
            with self.subTest(case=label), self.stage() as stack:
                stack.enter_context(mock.patch.dict(sys.modules))
                sys.modules.pop("operator_identity", None)
                stack.enter_context(mock.patch.object(sys, "meta_path", [Refuse(), *sys.meta_path]))
                transaction = stack.enter_context(mock.patch.object(SETUP, "setup"))
                stack.enter_context(as_root(owner_uid=owner, euid=ME.pw_uid))
                code, output = self.run_main()
                self.assertEqual(0, code, output)
                self.assertEqual([], Refuse.hits)
                self.assertNotIn("操作员：", output)
                transaction.assert_called_once_with(str(self.project))

    def test_root_own_project_keeps_home_key_and_generation(self):
        # 问题文档 :293 (item 3 only forbids generating a real user's key as root); v3.1.2 guide :645, :508-509
        # (root's project: run as root, method B).
        for label, inputs in (("root login", {}), ("U via sudo", dict(sudo=U.pw_name, sudo_uid=U.pw_uid))):
            with self.subTest(case=label):
                self.events.clear()
                with self.stage() as stack:
                    stack.enter_context(mock.patch.object(SETUP.ssh_keys, "ensure_public_key",
                                                          self.recorder("ensure", self.home / ".ssh/id_ed25519.pub")))
                    stack.enter_context(mock.patch.object(SETUP.ssh_keys, "prepare_project_public_key",
                                                          self.recorder("publish")))
                    stack.enter_context(mock.patch.object(
                        SETUP, "setup", lambda project: SETUP._prepare_laptop_public_key(project)))
                    stack.enter_context(as_root(owner_uid=0, **inputs))
                    code, output = self.run_main()
                self.assertEqual(0, code, output)
                self.assertIn("以 root 执行", output)
                self.assertEqual(["ensure", "publish"], self.labels())
                self.assertEqual(self.home / ".ssh", Path(self.events[0][1][0]))

    def test_represent_prepares_laptop_key_through_operator_child(self):
        # 问题文档 :291 (item 1: the passwd home, never root's), :293, :347 (write on the operator side as the
        # operator); plan row §1 D1 I-006（01-a-setup 单独运行）; D1S-O1 (a).
        script = os.path.realpath(SETUP.__file__)
        for label, inputs in (("U via sudo", dict(sudo=U.pw_name, sudo_uid=U.pw_uid)), ("root login", {})):
            for child_code in (0, 1):
                with self.subTest(case=label, child=child_code):
                    self.events.clear()
                    pointer = self.box.root / ACTIVATE.POINTER
                    if os.path.lexists(pointer):
                        pointer.unlink()
                    os.symlink(ACTIVATE.OTHER, pointer)      # switching away from another project
                    with self.stage(child_code=child_code) as stack:
                        for name in ("select_public_key", "ensure_public_key", "prepare_project_public_key"):
                            stack.enter_context(mock.patch.object(
                                SETUP.ssh_keys, name, side_effect=AssertionError("parent read " + name)))
                        stack.enter_context(as_root(owner_uid=U.pw_uid, **inputs))
                        code, output = self.run_main()
                    children = [event for event in self.events if event[0] == "child"]
                    self.assertEqual(1, len(children), output)
                    operator, child_script, child_args = children[0][1]
                    self.assertEqual((U.pw_name, U.pw_uid, U.pw_gid, U.pw_dir), tuple(operator))
                    self.assertEqual(script, os.path.realpath(child_script))
                    self.assertEqual(["--_prepare-laptop-key", os.path.realpath(self.project)], list(child_args))
                    if child_code:
                        self.assertEqual(1, code, output)
                        self.assertEqual(ACTIVATE.OTHER, self.box.pointer(), "no switch after the key step failed")
                    else:
                        self.assertEqual(0, code, output)
                        self.assertEqual(ACTIVATE.PROJECT, self.box.pointer())

    def test_operator_child_entry_requires_marker_and_non_root_and_never_generates(self):
        # M6 marker semantics (v3.1.2 guide :529-530): only a root parent's child; 问题文档 :293; v3.1.2 guide
        # :615 and D1S-O4 (a): no key means a hint to run ssh-keygen without sudo, nothing generated.
        block = next(node for node in ast.parse(Path(SETUP.__file__).read_text(encoding="utf-8")).body
                     if isinstance(node, ast.If) and "__main__" in ast.dump(node.test))
        entry = compile(ast.Module(body=block.body, type_ignores=[]), SETUP.__file__, "exec")
        key = public_line("ssh-ed25519", 61, "operator@laptop")
        laptop = self.project / "laptop.pub"

        def run_child(environ, euid=None):
            laptop.write_bytes(b"")
            output = io.StringIO()
            real = getattr(SETUP, "_laptop_key_child", None)
            injected = (mock.patch.object(SETUP, "_laptop_key_child", functools.partial(real, euid=euid))
                        if real is not None and euid is not None else nullcontext())
            with ExitStack() as stack:
                stack.enter_context(self.box.patches())
                stack.enter_context(mock.patch.object(SETUP, "_prepare_laptop_public_key", PREPARE))
                stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(self.home)}))
                os.environ.pop(MARKER, None)
                os.environ.update(environ)
                stack.enter_context(mock.patch.object(Path, "home", return_value=self.home))
                stack.enter_context(mock.patch.object(sys, "argv", [SETUP.__file__, "--_prepare-laptop-key",
                                                                    os.path.realpath(self.project)]))
                stack.enter_context(injected)
                stack.enter_context(redirect_stdout(output))
                stack.enter_context(redirect_stderr(output))
                try:
                    exec(entry, SETUP.__dict__)
                    code = 0
                except SystemExit as stop:
                    code = ACTIVATE.exit_code(stop)
            return code, output.getvalue()

        for label, environ, euid in (("no marker", {}, None), ("root", {MARKER: "1"}, 0)):
            with self.subTest(case=label):
                code, output = run_child(environ, euid)
                self.assertEqual(2, code, output)
                self.assertEqual(b"", laptop.read_bytes())
        (self.home / ".ssh" / "id_ed25519.pub").write_bytes(key)
        code, output = run_child({MARKER: "1"})
        self.assertEqual(0, code, output)
        self.assertEqual(key.strip(), laptop.read_bytes().strip())
        (self.home / ".ssh" / "id_ed25519.pub").unlink()
        before = sorted(path.name for path in (self.home / ".ssh").iterdir())
        code, output = run_child({MARKER: "1"})
        self.assertEqual(1, code, output)
        self.assertIn("ssh-keygen -t ed25519", output)
        self.assertEqual(before, sorted(path.name for path in (self.home / ".ssh").iterdir()))
        self.assertEqual(b"", laptop.read_bytes())

    def test_represent_hands_this_runs_entries_to_operator_on_success_and_failure(self):
        # 问题文档 :294 (item 4: what root writes into the project belongs to the real user), :295 (item 5:
        # 01-a-setup the same); v3.1.2 guide :624-626 (hand over after success or a non-zero end); 8.2 (--dry-run
        # starts no child and hands nothing over).
        with self.stage(real_prepare=False):
            code, output = self.run_main()      # a first, ordinary run brings the project to its steady state
        self.assertEqual(0, code, output)
        prepared = next(row.target for row in CONTRACT.SETUP_LINK_SPECS
                        if row.base == "project" and row.role == "prepared" and row.kind == "dir"
                        and "/" not in row.target and not (self.project / row.target / ".gitkeep").exists())
        removed = ("README.txt", "infiniband/bringup/xdr-initial-setup", prepared)
        for label, switch in (("success", None), ("switch refused", False)):
            with self.subTest(case=label):
                for name in removed:
                    path = self.project / name
                    if path.is_dir():
                        shutil.rmtree(path)
                    elif os.path.lexists(path):
                        path.unlink()
                before = names_under(self.project)
                self.events.clear()
                with self.stage() as stack:
                    if switch is not None:
                        stack.enter_context(mock.patch.object(SETUP, "_switch_active_project",
                                                              return_value=switch))
                    stack.enter_context(as_root(owner_uid=U.pw_uid, sudo=U.pw_name, sudo_uid=U.pw_uid))
                    code, output = self.run_main()
                created = names_under(self.project) - before
                self.assertEqual(0 if switch is None else 1, code, output)
                hands = [event for event in self.events if event[0] == "hand"]
                self.assertEqual(1, len(hands), output)
                project, names, identity = hands[0][1]
                self.assertEqual(os.path.realpath(self.project), os.path.realpath(project))
                self.assertEqual(sorted(created), list(names))
                self.assertTrue({"README.txt", "infiniband/bringup/xdr-initial-setup",
                                 "infiniband/bringup/xdr-initial-setup/infra-neutral.conf", prepared} <= set(names))
                self.assertFalse(set(names) & before, "entries that existed before are not handed over")
                self.assertEqual(U.pw_uid, identity.operator.uid)
        self.events.clear()
        with self.stage() as stack:
            stack.enter_context(as_root(owner_uid=U.pw_uid, sudo=U.pw_name, sudo_uid=U.pw_uid))
            code, output = self.run_main("--dry-run")
        self.assertEqual(0, code, output)
        self.assertEqual([], [event for event in self.events if event[0] in ("hand", "child")])

    def test_create_under_sudo_hands_project_dir_before_operator_child(self):
        # v3.1.2 guide :623 (O11 ④: sudo by U creating a project hands it to U first, so U's child can write in
        # it); tools/operator_identity.py header :18-19 (a new project's operator is the sudo invoker, else root).
        target = self.box.day0 / "site-new"
        real_template = SETUP._initialize_project_from_template

        def template(project):
            self.events.append(("template", (), {}))
            return real_template(project)

        with self.stage() as stack:
            stack.enter_context(mock.patch.object(SETUP, "_initialize_project_from_template", template))
            stack.enter_context(as_root(owner_uid=U.pw_uid, sudo=U.pw_name, sudo_uid=U.pw_uid))
            code, output = self.run_main("--create", project=target)
        self.assertEqual(0, code, output)
        self.assertEqual(["hand", "template", "child", "hand"], self.labels(), output)
        self.assertEqual([""], list(self.events[0][1][1]), "the project directory itself first")
        rest = list(self.events[3][1][1])
        self.assertTrue(rest and "" not in rest)
        self.assertEqual(sorted(names_under(target)), rest)
        self.events.clear()
        other = self.box.day0 / "site-root"
        with self.stage() as stack:
            stack.enter_context(mock.patch.object(SETUP.ssh_keys, "ensure_public_key",
                                                  self.recorder("ensure", self.home / ".ssh/id_ed25519.pub")))
            stack.enter_context(mock.patch.object(SETUP.ssh_keys, "prepare_project_public_key",
                                                  self.recorder("publish")))
            stack.enter_context(as_root(owner_uid=0))
            code, output = self.run_main("--create", project=other)
        self.assertEqual(0, code, output)
        self.assertTrue(other.is_dir())
        self.assertEqual(["ensure", "publish"], self.labels(), "a direct root login creates root's project")


if __name__ == "__main__":
    unittest.main()
