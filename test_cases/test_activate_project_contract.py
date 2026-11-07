"""R-016 AP-a (v3.1.1 WP-3): the activate-project pointer and the reader that resolves it.

Every expected value is written from the design, never read back from the implementation:
- R-016 详细设计 v1.1 §2: DAY0-Prepare/activate-project is valid only when it is a link whose text is one
  plain name -- not template, activate-project, nor a name starting with "." -- and DAY0-Prepare/<name> is a
  real directory judged by lstat (never a link).  §4.2 细节 (R16-19): the same check also excludes tests,
  test_cases, dumps and runs require_project_eligible.
- R-016 §5.1: project_contract.active_project_dir(http_root) -> Path | None returns the real project directory
  when valid, None without a pointer, raises an error naming the reason when the pointer is invalid; read-only,
  no lock.  详细工作指导 WP-3 「先写的测试」: seven cases -- no pointer, valid, template, a link, a multi-level
  name, a missing directory, a leading ".".
- http dev 2026-11-07: the error type is frozen for WP-4/6/9 -- ActiveProjectPointerError, a ValueError (the
  type require_project_eligible already raises).

setup's activation (01-a-setup.py), R-016 §4.2 and 详细工作指导 WP-3:
- six steps, each safe to repeat: 1 validate the target and write nothing (failure exits 2); 2 prepare the target
  project, writing only the project (failure exits 1 and does not switch); 3 reconcile the link table, errors
  only counted; 4 switch -- skip when the pointer already names the target, otherwise one confirmation when it
  names another project (-y/--yes skips it), then leftover .activate-project.*.tmp removed, a temporary link
  .activate-project.<pid>.tmp os.replace'd over the pointer and DAY0-Prepare fsynced; 5 write ztp/.setup_manifest
  (Q5: a derived record whose first line is the real project path); 6 exit 1 when errors were counted, else 0.
  Crash anywhere between steps 2 and 5, run setup again: the result is that of one clean run (往前恢复).
  No lock and no marker for the reconcile and the switch (R-016 §1 第 3 条); O6 (owner 2026-11-07): no rollback.
- Tree links of project rows go through the pointer: relpath("DAY0-Prepare/activate-project/<name>", link dir)
  (R-016 §2); so do the per-key links of the four public-key directories, refreshed after the switch (R16-13).
- Parameters: --csv-dir retired -- a parameter error, exit 2, pointing at a project link 02-devices_config.csv ->
  outside file (Q1, R-014 第 3 条); --yes is the long -y and --confirm-project-switch stays a synonym (Q4, owner
  2026-11-03 「好的」); the project parameter must be a direct real subdirectory of DAY0-Prepare and not template,
  else exit 2 (N4); --force turns validation errors into warnings and goes on preparing and switching (O13).
"""

from __future__ import annotations

import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_script("activate_project_contract_project_contract", ROOT / "tools/project_contract.py")
SETUP = load_script("activate_project_contract_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
EXAMPLE = ROOT / "examples/public-project"

PROJECT = "site-p"
OTHER = "site-q"
POINTER = "DAY0-Prepare/activate-project"
# Table rows whose text WP-3 left direct for the package owning their reader (详细工作指导 WP-9); empty since
# WP-9c (I-031) gave the AIR json its fixed name.
HANDED_ON: dict[str, str] = {}


def active_project_dir():
    if not hasattr(CONTRACT, "active_project_dir"):
        raise AssertionError("R-016 §5.1: project_contract.active_project_dir(http_root) resolves the pointer")
    return CONTRACT.active_project_dir


def pointer_error():
    if not hasattr(CONTRACT, "ActiveProjectPointerError"):
        raise AssertionError("http dev 2026-11-07: an invalid pointer raises ActiveProjectPointerError")
    return CONTRACT.ActiveProjectPointerError


def tree_state(root: Path) -> dict[str, tuple[int, int, str | None]]:
    """Every entry under root with its mode, mtime and link text: the read-only witness."""
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            info = path.lstat()
            state[str(path.relative_to(root))] = (
                info.st_mode, info.st_mtime_ns, os.readlink(path) if path.is_symlink() else None,
            )
    return state


def public_key(seed: int, comment: str) -> str:
    """A valid synthetic OpenSSH Ed25519 public line; no private key exists."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment + "\n"


_WORKBOOK: list[bytes] = []


def workbook_bytes() -> bytes:
    """One synthetic P2P workbook, made once: openpyxl stamps creation times, and runs compared byte for byte
    must hold the same bytes."""
    if not _WORKBOOK:
        import openpyxl

        stream = io.BytesIO()
        book = openpyxl.Workbook()
        book.active["A1"] = "synthetic P2P"
        book.save(stream)
        _WORKBOOK.append(stream.getvalue())
    return _WORKBOOK[0]


def snapshot(root: Path) -> dict[str, tuple[str, ...]]:
    """Every entry under root by kind: link text, or content digest with root-relative absolute paths."""
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                state[relative] = ("link", os.readlink(path))
            elif path.is_dir():
                state[relative] = ("dir",)
            else:
                payload = path.read_bytes().replace(os.fsencode(root), b"<root>")
                state[relative] = ("file", hashlib.sha256(payload).hexdigest())
    return state


class Sandbox:
    """A temporary http/ tree with the repository's DAY0-Prepare/template and two valid synthetic projects."""

    def __init__(self, base: Path):
        self.root = base / "http"
        self.day0 = self.root / "DAY0-Prepare"
        shutil.copytree(ROOT / "DAY0-Prepare/template", self.day0 / "template", symlinks=True)
        (self.root / "image").mkdir()
        (self.root / "infra").mkdir()  # a tracked repository directory: setup's infra-log root lock lives in it
        for seed, name in ((11, PROJECT), (21, OTHER)):
            self.make_project(name, seed)

    def make_project(self, name: str, seed: int) -> Path:
        project = self.day0 / name
        project.mkdir()
        document = yaml.safe_load((EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8"))
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [item for item in document["switches"] if set(item) == {"eth"}]
        document["switches"][0]["eth"]["system"]["aaa"]["user"]["cumulus"]["hashed-password"] = (
            "$6$fixture$safe-value"
        )
        (project / "01-global.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        shutil.copy2(EXAMPLE / "02-dhcp-subnet_config.csv.example", project / "02-dhcp-subnet_config.csv")
        header, eth_row = (EXAMPLE / "02-devices_config.csv.example").read_text(encoding="utf-8").splitlines()[:2]
        (project / "02-devices_config.csv").write_text(f"{header}\n{eth_row}\n", encoding="utf-8")
        (project / "laptop.pub").write_text(public_key(seed, "operator@laptop"), encoding="ascii")
        (project / "mgmt-server.pub").write_text(public_key(seed + 1, "mgmt@server"), encoding="ascii")
        (project / "Site P2P_v1.0.xlsx").write_bytes(workbook_bytes())
        return project

    def patches(self, **overrides) -> ExitStack:
        """setup's globals bound to this tree.  The module-level absolute link lists setup computed at import
        are rebased here too, so no run of any setup version can write into the repository."""
        root = self.root
        values = {
            "HERE": str(self.day0), "HTTP_BASE": str(root), "ZTP": str(root / "ztp"),
            "TEMPLATE_DIR": str(self.day0 / "template"), "IMAGE_DIR": str(root / "image"),
            "MANIFEST_FILE": str(root / "ztp/.setup_manifest"),
            "P2P_AIR_JSON_LINK": str(root / CONTRACT.P2P_AIR_PATH),
            "P2P_INPUT_LINKS": [str(root / name) for name in CONTRACT.P2P_INPUT_PATHS],
            "P2P_OUTPUT_LINKS": [str(root / name) for name in CONTRACT.P2P_OUTPUT_PATHS],
            "BRINGUP_OUTPUT_MAPPINGS": [(str(root / name), target) for name, target in CONTRACT.BRINGUP_OUTPUT_SPECS],
            "ANALYZER_INPUT_MAPPINGS": [(str(root / name), target) for name, target in CONTRACT.ANALYZER_INPUT_SPECS],
            "ANALYZER_OUTPUT_MAPPINGS": [(str(root / name), target)
                                         for name, target in CONTRACT.ANALYZER_OUTPUT_SPECS],
            "_NET_CSV_LINKS": [(str(root / name), target) for name, target in CONTRACT.NETWORK_CSV_MAPPINGS],
            "_DRY_RUN": False, "_AUTO_YES": True, "_CONFIRM_PROJECT_SWITCH": False, "_FORCE": False,
            "_STRICT": False, "_NO_UPGRADE": True, "_P2P_FILE": None, "_SWITCH_SCOPE": None,
            "_P2P_SOURCE": None, "_LINK_ERRORS": 0, "_INFRA_LOG_MIGRATION": None,
        }
        values.update(overrides)
        stack = ExitStack()
        stack.enter_context(mock.patch.multiple(
            SETUP, **{name: value for name, value in values.items() if hasattr(SETUP, name)},
        ))
        # The operator's ~/.ssh is not the subject here: every project already carries its laptop.pub.
        stack.enter_context(mock.patch.object(SETUP, "_prepare_laptop_public_key"))
        return stack

    def pointer(self) -> str | None:
        path = self.root / POINTER
        return os.readlink(path) if path.is_symlink() else None


def exit_code(stop: SystemExit) -> int:
    return 0 if stop.code is None else stop.code


class ActivationStepsTests(unittest.TestCase):
    """R-016 §4.2 through setup(): what each step may write, the exit codes, the switch and its confirmation."""

    def sandbox(self) -> Sandbox:
        temporary = tempfile.TemporaryDirectory(prefix="activate-project-")
        self.addCleanup(temporary.cleanup)
        return Sandbox(Path(temporary.name).resolve())

    def activate(self, box: Sandbox, name: str, **overrides) -> tuple[int, str]:
        """setup() for DAY0-Prepare/<name>: (exit code, printed output)."""
        output = io.StringIO()
        code = 0
        with box.patches(**overrides), redirect_stdout(output):
            try:
                SETUP.setup(str(box.day0 / name))
            except SystemExit as stop:
                code = exit_code(stop)
        return code, output.getvalue()

    def activated(self, box: Sandbox, name: str, **overrides) -> str:
        code, output = self.activate(box, name, **overrides)
        self.assertEqual(0, code, output)
        return output

    @staticmethod
    def table_texts(box: Sandbox) -> dict[str, str | None]:
        return {row.path: (os.readlink(box.root / row.path) if (box.root / row.path).is_symlink() else None)
                for row in CONTRACT.SETUP_LINK_SPECS if row.path not in HANDED_ON}

    def test_project_rows_and_key_links_go_through_the_pointer(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        self.assertEqual(PROJECT, box.pointer())
        self.assertEqual(box.day0 / PROJECT, active_project_dir()(box.root))
        checked = 0
        for row in CONTRACT.SETUP_LINK_SPECS:
            link = box.root / row.path
            # The publisher's latest_yaml is not setup's (R-016 §3.4); HANDED_ON rows are other packages'; an
            # offline tools/ analyzer absent from the tree is not recreated.
            if row.writer != "setup" or row.path in HANDED_ON or row.path.startswith("tools/"):
                continue
            with self.subTest(link=row.path):
                expected = (CONTRACT.pointer_link_target(row.path, row.target) if row.base == "project"
                            else os.path.relpath(row.target, os.path.dirname(row.path)))
                self.assertEqual(expected, os.readlink(link))
                checked += 1
        self.assertGreater(checked, 50)
        for directory in CONTRACT.PUBLICKEY_DIRECTORIES:
            for key in ("laptop.pub", "mgmt-server.pub"):
                name = directory + "/" + key
                with self.subTest(key_link=name):
                    self.assertEqual(CONTRACT.pointer_link_target(name, key), os.readlink(box.root / name))
        manifest = (box.root / "ztp/.setup_manifest").read_text(encoding="utf-8").splitlines()
        self.assertEqual("# setup manifest — proj: " + os.path.realpath(box.day0 / PROJECT), manifest[0])

    def test_the_manifest_records_every_link_of_the_table(self):
        # Q5 / review A8: the derived record comes from the link table -- every row setup made, the shared
        # section and the dynamic section (per-key links, optimize samples).
        box = self.sandbox()
        self.activated(box, PROJECT)
        recorded = set((box.root / "ztp/.setup_manifest").read_text(encoding="utf-8").splitlines()[1:])
        made = [row.path for row in CONTRACT.SETUP_LINK_SPECS if (box.root / row.path).is_symlink()]
        absent = [row.path for row in CONTRACT.SETUP_LINK_SPECS
                  if row.writer == "setup" and not row.path.startswith("tools/") and row.path not in made]
        self.assertEqual([], absent, "setup makes every setup row (offline tools/ rows aside)")
        for name in made:
            with self.subTest(row=name):
                self.assertIn(str(box.root / name), recorded)
        dynamic = [path for pattern in CONTRACT.setup_dynamic_link_patterns()
                   for path in box.root.glob(pattern) if path.is_symlink()]
        self.assertTrue(any(path.parent.name == "publickey" for path in dynamic))
        self.assertTrue(any(path.parent.name.endswith("-sample") for path in dynamic))
        for path in dynamic:
            with self.subTest(dynamic=str(path.relative_to(box.root))):
                self.assertIn(str(path), recorded)

    def test_a_user_p2p_link_spelled_with_a_dot_prefix_is_kept(self):
        # R-014 第 3 条 (WP-11): p2p.xlsx -> p2p/<workbook> is the user's own link; ./p2p/<workbook> is the same
        # path, and the selector already reads it so (review A9) -- setup keeps it and does not fail.
        box = self.sandbox()
        project = box.day0 / OTHER
        (project / "p2p").mkdir()
        (project / "Site P2P_v1.0.xlsx").rename(project / "p2p/Site P2P_v1.0.xlsx")
        (project / "p2p.xlsx").symlink_to("./p2p/Site P2P_v1.0.xlsx")
        code, output = self.activate(box, OTHER)
        self.assertEqual(0, code, output)
        self.assertEqual("./p2p/Site P2P_v1.0.xlsx", os.readlink(project / "p2p.xlsx"))
        self.assertEqual(OTHER, box.pointer())

    def test_switching_projects_changes_only_the_pointer_among_the_fixed_links(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        before = self.table_texts(box)
        self.activated(box, OTHER)
        self.assertEqual(OTHER, box.pointer())
        self.assertEqual(before, self.table_texts(box))
        self.assertEqual(box.day0 / OTHER, active_project_dir()(box.root))
        manifest = (box.root / "ztp/.setup_manifest").read_text(encoding="utf-8").splitlines()
        self.assertEqual("# setup manifest — proj: " + os.path.realpath(box.day0 / OTHER), manifest[0])

    def test_validation_failure_exits_2_and_writes_nothing(self):
        cases = {
            # --strict makes an empty key an input error (_validate_project).
            "empty key under --strict": ({"_STRICT": True},
                                         lambda project: (project / "mgmt-server.pub").write_bytes(b"")),
            "no P2P workbook": ({}, lambda project: (project / "Site P2P_v1.0.xlsx").unlink()),
        }
        for label, (overrides, spoil) in cases.items():
            with self.subTest(case=label):
                box = self.sandbox()
                self.activated(box, PROJECT)
                spoil(box.day0 / OTHER)
                before = snapshot(box.root)
                code, output = self.activate(box, OTHER, **overrides)
                self.assertEqual(2, code, output)
                self.assertEqual(before, snapshot(box.root))
                self.assertEqual(PROJECT, box.pointer())

    def test_force_turns_validation_errors_into_warnings_and_goes_on_to_switch(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        (box.day0 / OTHER / "mgmt-server.pub").write_bytes(b"")
        code, output = self.activate(box, OTHER, _STRICT=True, _FORCE=True)
        self.assertEqual(0, code, output)
        self.assertIn("--force", output)
        self.assertEqual(OTHER, box.pointer())

    def test_preparation_error_exits_1_without_switching_or_writing_outside_the_target(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        # A project directory where the template has a file: template completion reports and counts it.
        (box.day0 / OTHER / "README.txt").mkdir()
        before = {name: value for name, value in snapshot(box.root).items()
                  if not name.startswith(f"DAY0-Prepare/{OTHER}/")}
        code, output = self.activate(box, OTHER)
        self.assertEqual(1, code, output)
        self.assertEqual(PROJECT, box.pointer())
        after = {name: value for name, value in snapshot(box.root).items()
                 if not name.startswith(f"DAY0-Prepare/{OTHER}/")}
        self.assertEqual(before, after)

    def test_reconcile_error_exits_1_after_switching(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        blocked = box.root / "ethernet/eth.csv"
        blocked.unlink()
        blocked.write_text("operator file\n", encoding="utf-8")
        code, output = self.activate(box, OTHER)
        self.assertEqual(1, code, output)
        self.assertEqual(OTHER, box.pointer())
        self.assertFalse(blocked.is_symlink())
        self.assertEqual("operator file\n", blocked.read_text(encoding="utf-8"))
        self.assertIn("ethernet/eth.csv", output)

    def test_switch_replaces_a_temporary_link_over_the_pointer_and_fsyncs_day0(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        stale = box.day0 / ".activate-project.4242.tmp"
        stale.symlink_to(PROJECT)
        events = []
        real_replace, real_fsync = os.replace, os.fsync
        day0_identity = (box.day0.stat().st_dev, box.day0.stat().st_ino)

        def replace(source, destination, *args, **kwargs):
            events.append(("replace", os.fspath(source), os.fspath(destination)))
            return real_replace(source, destination, *args, **kwargs)

        def fsync(descriptor):
            info = os.fstat(descriptor)
            events.append(("fsync", (info.st_dev, info.st_ino) == day0_identity))
            return real_fsync(descriptor)

        with mock.patch.object(SETUP.os, "replace", side_effect=replace), \
                mock.patch.object(SETUP.os, "fsync", side_effect=fsync):
            self.activated(box, OTHER)
        self.assertEqual(OTHER, box.pointer())
        switch = ("replace", str(box.day0 / f".activate-project.{os.getpid()}.tmp"), str(box.root / POINTER))
        self.assertIn(switch, events)
        self.assertIn(("fsync", True), events[events.index(switch):])
        self.assertFalse(os.path.lexists(stale))
        self.assertEqual([], sorted(box.day0.glob(".activate-project.*.tmp")))

    def test_switch_is_skipped_when_the_pointer_already_names_the_target(self):
        box = self.sandbox()
        self.activated(box, PROJECT)
        self.assertEqual(PROJECT, box.pointer())
        identity = (box.root / POINTER).lstat().st_ino
        destinations = []
        real_replace = os.replace

        def replace(source, destination, *args, **kwargs):
            destinations.append(os.fspath(destination))
            return real_replace(source, destination, *args, **kwargs)

        with mock.patch.object(SETUP.os, "replace", side_effect=replace):
            self.activated(box, PROJECT, _AUTO_YES=False)
        self.assertNotIn(str(box.root / POINTER), destinations)
        self.assertEqual(identity, (box.root / POINTER).lstat().st_ino)

    def test_cross_project_switch_asks_once_and_yes_or_the_synonym_skip_the_question(self):
        cases = (
            # (label, overrides, tty, answer, switched, questions)
            ("interactive yes", {"_AUTO_YES": False}, True, "yes", True, 1),
            ("interactive y is not yes", {"_AUTO_YES": False}, True, "y", False, 1),
            ("no terminal, no flag", {"_AUTO_YES": False}, False, None, False, 0),
            ("-y/--yes", {"_AUTO_YES": True}, False, None, True, 0),
            ("--confirm-project-switch", {"_AUTO_YES": False, "_CONFIRM_PROJECT_SWITCH": True}, False, None,
             True, 0),
        )
        for label, overrides, tty, answer, switched, questions in cases:
            with self.subTest(case=label):
                box = self.sandbox()
                self.activated(box, PROJECT)
                with mock.patch.object(SETUP.sys.stdin, "isatty", return_value=tty), \
                        mock.patch("builtins.input", return_value=answer) as asked:
                    code, output = self.activate(box, OTHER, **overrides)
                self.assertEqual(questions, asked.call_count, output)
                self.assertEqual(OTHER if switched else PROJECT, box.pointer(), output)
                self.assertEqual(0 if switched else 1, code, output)

    def test_crash_between_steps_2_and_5_then_rerun_equals_one_clean_run(self):
        reference = self.sandbox()
        self.activated(reference, PROJECT)
        self.activated(reference, OTHER)
        expected = snapshot(reference.root)
        real_engine, real_symlink = SETUP._reconcile_links, os.symlink

        def engine_never_starts(links):
            raise RuntimeError("crash: before step 3")

        def engine_half_way(links):
            links = list(links)
            real_engine(links[:len(links) // 2])
            raise RuntimeError("crash: inside step 3")

        def no_temporary_pointer(source, destination, *args, **kwargs):
            if os.path.basename(os.fspath(destination)).startswith(".activate-project."):
                raise RuntimeError("crash: step 4 before the rename")
            return real_symlink(source, destination, *args, **kwargs)

        crashes = (
            ("before step 3", mock.patch.object(SETUP, "_reconcile_links", side_effect=engine_never_starts), PROJECT),
            ("inside step 3", mock.patch.object(SETUP, "_reconcile_links", side_effect=engine_half_way), PROJECT),
            ("step 4", mock.patch.object(SETUP.os, "symlink", side_effect=no_temporary_pointer), PROJECT),
            ("between steps 4 and 5", mock.patch.object(
                SETUP, "_write_manifest", side_effect=RuntimeError("crash: before step 5")), OTHER),
        )
        for label, crash, pointer in crashes:
            with self.subTest(crash=label):
                box = self.sandbox()
                self.activated(box, PROJECT)
                with crash, self.assertRaises(RuntimeError):
                    self.activate(box, OTHER)
                self.assertEqual(pointer, box.pointer())
                self.activated(box, OTHER)
                self.assertEqual(expected, snapshot(box.root))


class ActivationParameterTests(unittest.TestCase):
    """--csv-dir (Q1), -y/--yes and its synonym (Q4), the project parameter (N4), through setup's CLI."""

    def test_csv_dir_is_retired_with_a_hint_and_exit_2(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as stopped:
            SETUP._parse_args(["--csv-dir", "/tmp", PROJECT])
        self.assertEqual(2, exit_code(stopped.exception))
        self.assertIn("02-devices_config.csv", stderr.getvalue())

    def test_yes_is_the_long_y_and_confirm_project_switch_stays(self):
        for argv in (["-y", PROJECT], ["--yes", PROJECT]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                try:
                    parsed = SETUP._parse_args(argv)
                except SystemExit:
                    self.fail(f"Q4: {argv[0]} is a setup option")
                self.assertTrue(parsed.auto_yes)
        self.assertTrue(SETUP._parse_args(["--confirm-project-switch", PROJECT]).confirm_project_switch)

    def test_project_must_be_a_direct_real_subdirectory_of_day0_and_not_template(self):
        temporary = tempfile.TemporaryDirectory(prefix="activate-project-cli-")
        self.addCleanup(temporary.cleanup)
        box = Sandbox(Path(temporary.name).resolve())
        (box.day0 / PROJECT / "nested").mkdir()
        (box.day0 / ".hidden").mkdir()
        (box.day0 / "alias").symlink_to(PROJECT)
        outside = box.root.parent / "elsewhere"
        shutil.copytree(box.day0 / OTHER, outside)
        # The writers' deployment lock file (R-016 §4.2 锁) is the one entry main may create before refusing.
        def state():
            return {name: value for name, value in snapshot(box.root.parent).items()
                    if not name.endswith(".deployment.lock")}

        before = state()
        rejected = (f"{PROJECT}/nested", str(outside), "template", "alias", ".hidden")
        for argument in rejected:
            with self.subTest(project=argument), box.patches(), redirect_stdout(io.StringIO()):
                self.assertEqual(2, SETUP.main(["-y", "--host-role=workstation", "--no-upgrade", argument]))
            self.assertEqual(before, state())
        for argument in (PROJECT, f"DAY0-Prepare/{OTHER}", str(box.day0 / PROJECT)):
            with self.subTest(accepted=argument), box.patches(), redirect_stdout(io.StringIO()) as printed:
                self.assertEqual(0, SETUP.main(["-y", "--host-role=workstation", "--no-upgrade", argument]),
                                 printed.getvalue())
            self.assertEqual(os.path.basename(argument), box.pointer())


class ActiveProjectDirTests(unittest.TestCase):
    """R-016 §2, §5.1: the seven cases of 详细工作指导 WP-3, and the exclusions §4.2 adds."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "http"
        self.day0 = self.root / "DAY0-Prepare"
        for name in (PROJECT, "site-q", "template"):
            (self.day0 / name).mkdir(parents=True)
            (self.day0 / name / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")

    def point(self, text: str) -> None:
        pointer = self.day0 / "activate-project"
        if pointer.is_symlink():
            pointer.unlink()
        os.symlink(text, pointer)

    def assert_invalid(self, *reason_words: str) -> None:
        error = pointer_error()
        self.assertTrue(issubclass(error, ValueError))
        with self.assertRaises(error) as raised:
            active_project_dir()(self.root)
        for word in reason_words:
            self.assertIn(word, str(raised.exception))

    def test_no_pointer_is_none(self):
        self.assertIsNone(active_project_dir()(self.root))

    def test_no_pointer_even_without_day0_is_none(self):
        empty = self.root.parent / "empty-http"
        empty.mkdir()
        self.assertIsNone(active_project_dir()(empty))

    def test_valid_pointer_returns_the_real_project_directory(self):
        self.point(PROJECT)
        found = active_project_dir()(self.root)
        self.assertIsInstance(found, Path)
        self.assertEqual(found, Path(os.path.realpath(self.day0 / PROJECT)))
        # §5.1 「返回真实项目目录」: even when the caller names the tree through an alias.
        alias = self.root.parent / "http-alias"
        os.symlink(self.root, alias)
        self.assertEqual(active_project_dir()(str(alias)), Path(os.path.realpath(self.day0 / PROJECT)))

    def test_reading_the_pointer_changes_nothing(self):
        self.point(PROJECT)
        before = tree_state(self.root.parent)
        active_project_dir()(self.root)
        self.assertEqual(tree_state(self.root.parent), before)

    def test_pointer_to_template_is_invalid(self):
        self.point("template")
        self.assert_invalid("template")

    def test_pointer_to_a_link_is_invalid(self):
        os.symlink(PROJECT, self.day0 / "linked-project")
        self.point("linked-project")
        self.assert_invalid("linked-project")

    def test_multi_level_names_are_invalid(self):
        (self.day0 / PROJECT / "nested").mkdir()
        for text in (PROJECT + "/nested", "../DAY0-Prepare/" + PROJECT, str(self.day0 / PROJECT)):
            with self.subTest(text=text):
                self.point(text)
                self.assert_invalid(text)
                (self.day0 / "activate-project").unlink()

    def test_pointer_to_a_missing_directory_is_invalid(self):
        self.point("site-gone")
        self.assert_invalid("site-gone")

    def test_pointer_to_a_dot_name_is_invalid(self):
        for text in (".hidden", "..", "."):
            with self.subTest(text=text):
                if text == ".hidden":
                    (self.day0 / text).mkdir()
                self.point(text)
                self.assert_invalid()
                (self.day0 / "activate-project").unlink()

    def test_excluded_names_are_invalid(self):
        for text in ("activate-project", "tests", "test_cases", "dumps"):
            with self.subTest(text=text):
                if text != "activate-project":
                    (self.day0 / text).mkdir()
                self.point(text)
                self.assert_invalid(text)
                (self.day0 / "activate-project").unlink()

    def test_pointer_to_a_regular_file_is_invalid(self):
        (self.day0 / "notes.txt").write_text("x\n", encoding="utf-8")
        self.point("notes.txt")
        self.assert_invalid("notes.txt")

    def test_pointer_that_is_not_a_link_is_invalid(self):
        (self.day0 / "activate-project").mkdir()
        self.assert_invalid("activate-project")

    def test_project_that_require_project_eligible_rejects_is_invalid(self):
        # A restore receipt without its commit marker: require_project_eligible refuses the project.
        (self.day0 / PROJECT / CONTRACT.REHYDRATE_RECEIPT_NAME).write_text("{}", encoding="ascii")
        self.point(PROJECT)
        self.assert_invalid(PROJECT)

    def test_incomplete_sync_makes_the_pointer_invalid(self):
        (self.root / ".sync-code-in-progress").write_text("", encoding="ascii")
        self.point(PROJECT)
        self.assert_invalid()


# ── v3.1.1 WP-6: unsetup through the pointer (R-016 §4.4, Q7, O14) ───────────────────────────────────────
# Imports and helpers stay with this section: parallel work packages append their own classes to this file.
from contextlib import redirect_stdout  # noqa: E402
import io  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from unittest import mock  # noqa: E402

WP6_UNSETUP = load_script("activate_project_contract_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")
# O14 (owner 2026-11-07 「同意你的建议。」 via http dev): the four names older setups left behind; the fifth is
# monitor/99-output-ufm, which R-013 took out of the table (WP-8 待决 1, settled by http dev 2026-11-08: a legacy
# name handled like the four).
WP6_RETIRED_MONITOR_LINK = "monitor/99-output-ufm"
WP6_LEGACY_LINKS = (
    "ztp/config/nvos/template/99-output-ib",
    "ztp/config/nvos/template/99-output-nvl",
    "ztp/config/nvos/template/99-output-published",
    "ztp/config/cumulus/template/AIR/output-p2p",
    WP6_RETIRED_MONITOR_LINK,
)
# R-016 §3.2 (owner 2026-11-04): one link per project key in each of the four real key directories.
WP6_KEY_NAMES = ("laptop.pub", "mgmt-server.pub")
WP6_SHARED_IMAGE = "ztp/image/cumulus/cumulus-linux-fixture-amd64.bin"
WP6_SHARED_DIRECTORY = "infiniband/bringup/ufm-setup-upgrade/image"


def wp6_link_state(root: Path) -> dict[str, str]:
    """Every symlink under root with its text: what unsetup may change."""
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            if path.is_symlink():
                state[str(path.relative_to(root))] = os.readlink(path)
    return state


class WP6UnsetupTests(unittest.TestCase):
    """R-016 §4.4 unsetup with the pointer layout (v3.1.1 WP-6).

    Expected values come from the design and the owner's rulings, never from 02-unsetup.py:
    - R-016 详细设计 v1.1 §4.4 (Q1-Q7 「好的」, owner 2026-11-03): read the project with active_project_dir()
      first, then unlink DAY0-Prepare/activate-project; withdraw the configuration authorities of that project,
      not of projects inferred from link realpaths (R16-20); ``02-unsetup.py <project>`` runs only when that
      project is the active one; crontab cleanup as before; .setup_manifest deleted.
    - Q7: the table's fixed links stay; dangling, they mean "no project is active".
    - O14 (owner 2026-11-07 「同意你的建议。」 via http dev): besides the pointer and .setup_manifest, unsetup removes
      only the per-key links of the four key directories, the ztp/optimize/*-sample/* links and the four legacy
      names; the fixed links, the shared-image section included, stay.
    - 详细工作指导 WP-6: a project argument naming another project does nothing.  The exit codes follow the
      existing unsetup contract: a refusal is 1 and touches nothing (as the log-receipt and infra/logs gates);
      nothing to do is 0 (as "未找到任何由 setup 管理的软链接，无需操作").
    - infra/logs: its canonical pointer-form text is accepted only once WP-9b adapts
      project_contract.managed_infra_log_project (WP-6 dispatch); the fixture leaves it out except in the test
      that names this dependency.
    """

    PROJECT = "site-p"
    OTHER = "site-q"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "http"
        self.day0 = self.root / "DAY0-Prepare"
        self.project = self.day0 / self.PROJECT
        self.other = self.day0 / self.OTHER

    # ── fixture: the tree as setup leaves it with site-p active ──
    def build(self, *, infra_logs: bool = False) -> None:
        for project in (self.project, self.other):
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
            for name in WP6_KEY_NAMES:
                (project / name).write_text("ssh-ed25519 AAAA fixture\n", encoding="ascii")
        (self.root / "infra").mkdir()
        (self.root / "image").mkdir()
        (self.root / "image/cumulus-linux-fixture-amd64.bin").write_bytes(b"shared image\n")
        rows = [row for row in CONTRACT.SETUP_LINK_SPECS if row.base == "project"]
        for row in rows:
            if row.kind == "dir":
                (self.project / row.target).mkdir(parents=True, exist_ok=True)
        for row in rows:
            if row.kind == "file":
                (self.project / row.target).parent.mkdir(parents=True, exist_ok=True)
                (self.project / row.target).write_bytes(b"project file\n")
        # The publisher rows reach <99-output-*>/latest through their release directory rows.
        for name in ("99-output-eth/latest", "99-output-ib_nvl/latest"):
            (self.project / name).mkdir(parents=True, exist_ok=True)
        os.symlink(self.PROJECT, self.day0 / "activate-project")
        for path, text in CONTRACT.pointer_link_specs():
            if path == "infra/logs" and not infra_logs:
                continue
            self.symlink(path, text)
        for directory in CONTRACT.PUBLICKEY_DIRECTORIES:
            for name in WP6_KEY_NAMES:
                self.symlink(directory + "/" + name, CONTRACT.pointer_link_target(directory + "/" + name, name))
        (self.root / "ethernet/publickey/operator.pub").write_text("operator-owned key\n", encoding="ascii")
        sample = "ztp/optimize/" + self.PROJECT + "-sample"
        for name, target in (("01-global.yaml", "01-global.yaml"), ("comparison", "99-output-ztp")):
            self.symlink(sample + "/" + name, os.path.relpath(self.project / target, self.root / sample))
        (self.root / sample / "operator-notes.txt").write_text("operator-owned\n", encoding="utf-8")
        for path in WP6_LEGACY_LINKS:
            self.symlink(path, os.path.relpath(self.project / "99-output-ib_nvl", (self.root / path).parent))
        self.symlink(WP6_SHARED_IMAGE, os.path.relpath(self.root / "image/cumulus-linux-fixture-amd64.bin",
                                                       (self.root / WP6_SHARED_IMAGE).parent))
        self.symlink(WP6_SHARED_DIRECTORY, os.path.relpath(self.root / "image",
                                                           (self.root / WP6_SHARED_DIRECTORY).parent))
        manifest = self.root / "ztp/.setup_manifest"
        # R16-14 / Q5: the manifest body is a derived record, never a list of what to delete.
        manifest.write_text(f"# setup manifest — proj: {self.project}\n{self.root / 'monitor/01-global.yaml'}\n",
                            encoding="utf-8")

    def symlink(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(text, path)

    def fixed_paths(self, *, infra_logs: bool = False) -> list[str]:
        return [path for path, _text in CONTRACT.pointer_link_specs() if infra_logs or path != "infra/logs"]

    def unsetup(self, project: str | None = None) -> tuple[int | None, str]:
        output = io.StringIO()
        with mock.patch.multiple(
            WP6_UNSETUP, HTTP_BASE=str(self.root), HERE=str(self.day0), ZTP=str(self.root / "ztp"),
            MANIFEST_FILE=str(self.root / "ztp/.setup_manifest"), _AUTO_YES=True, _DRY_RUN=False,
        ), redirect_stdout(output):
            # The real filesystem stage: main() would also stop host services outside this fixture.
            result = WP6_UNSETUP._main_locked(SimpleNamespace(project=project))
        return result, output.getvalue()

    # ── R-016 §4.4, Q7, O14 ──
    def assert_unsetup_result(self, before: dict[str, str], *, infra_logs: bool = False) -> None:
        self.assertFalse(os.path.lexists(self.day0 / "activate-project"), "R-016 §4.4: the pointer is unlinked")
        self.assertIsNone(CONTRACT.active_project_dir(self.root), "R-016 §5.1: no project is active")
        self.assertFalse(os.path.lexists(self.root / "ztp/.setup_manifest"), "R-016 §4.4: the manifest goes")
        for path in self.fixed_paths(infra_logs=infra_logs):
            link = self.root / path
            with self.subTest(fixed=path):
                self.assertTrue(link.is_symlink(), "Q7: the fixed link stays")
                self.assertEqual(before[path], os.readlink(link), "Q7: the fixed link stays as it was")
                self.assertFalse(link.exists(), "Q7: dangling means no project is active")
        for directory in CONTRACT.PUBLICKEY_DIRECTORIES:
            for name in WP6_KEY_NAMES:
                with self.subTest(key=directory + "/" + name):
                    self.assertFalse(os.path.lexists(self.root / directory / name), "O14: per-key links go")
        self.assertEqual(b"operator-owned key\n", (self.root / "ethernet/publickey/operator.pub").read_bytes())
        sample = self.root / "ztp/optimize" / (self.PROJECT + "-sample")
        self.assertEqual(["operator-notes.txt"], sorted(item.name for item in sample.iterdir()),
                         "O14: only the sample links go")
        for path in WP6_LEGACY_LINKS:
            with self.subTest(legacy=path):
                self.assertFalse(os.path.lexists(self.root / path), "O14: the legacy names go")
        for path in (WP6_SHARED_IMAGE, WP6_SHARED_DIRECTORY):
            with self.subTest(shared=path):
                self.assertEqual(before[path], os.readlink(self.root / path), "O14: the shared section stays")
                self.assertTrue((self.root / path).exists())
        self.assertEqual(b"project file\n", (self.project / "02-devices_config.csv").read_bytes(), "data stays")

    def test_unsetup_unlinks_the_pointer_and_keeps_every_fixed_link_dangling(self):
        self.build()
        before = wp6_link_state(self.root)
        for path in self.fixed_paths():
            with self.subTest(fixture=path):
                self.assertTrue((self.root / path).exists(), "fixture: every fixed link resolves while active")
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assert_unsetup_result(before)

    def test_unsetup_naming_the_active_project_runs(self):
        self.build()
        before = wp6_link_state(self.root)
        result, output = self.unsetup(str(self.project))
        self.assertEqual(0, result, output)
        self.assert_unsetup_result(before)

    def test_unsetup_naming_another_project_changes_nothing_and_exits_1(self):
        self.build()
        before = wp6_link_state(self.root)
        manifest = (self.root / "ztp/.setup_manifest").read_bytes()
        result, output = self.unsetup(str(self.other))
        self.assertEqual(1, result, output)
        self.assertIn(self.PROJECT, output, "the message names the active project")
        self.assertIn(self.OTHER, output, "the message names the project asked for")
        self.assertIn("未做任何改动", output)
        self.assertEqual(before, wp6_link_state(self.root))
        self.assertEqual(manifest, (self.root / "ztp/.setup_manifest").read_bytes())

    def test_unsetup_withdraws_the_authorities_of_the_pointer_project_only(self):
        # R16-20: the project comes from the pointer, never from link realpaths.  A legacy link into site-q
        # used to add site-q to the withdrawal set.
        from test_cases import test_config_sync_authority as AUTHORITY_TESTS

        authority = WP6_UNSETUP.config_sync_authority
        self.build()
        os.unlink(self.root / WP6_LEGACY_LINKS[0])
        self.symlink(WP6_LEGACY_LINKS[0], os.path.relpath(self.other, (self.root / WP6_LEGACY_LINKS[0]).parent))
        roots = {}
        for project in (self.project, self.other):
            root = project / "99-output-ztp/configuration-methods"
            ticket = authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
            authority.finish_method(root, ticket, AUTHORITY_TESTS.ConfigSyncAuthorityTests.method_receipt_v2(ticket))
            roots[project.name] = root
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual("failed", authority.read_method_current(roots[self.PROJECT], "leaf1")["state"])
        self.assertEqual("success", authority.read_method_current(roots[self.OTHER], "leaf1")["state"])

    def test_without_a_pointer_unsetup_removes_only_leftovers_and_a_project_argument_does_nothing(self):
        # The state a finished unsetup leaves (Q7): fixed links dangle; the infiniband xdr-initial-setup log
        # link is one of them, and REQ10C cleanup must read that as "nothing to clean", not fail.
        self.build()
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        state = wp6_link_state(self.root)
        result, output = self.unsetup(str(self.project))
        self.assertEqual(0, result, output)
        self.assertIn("没有激活的项目", output)
        self.assertEqual(state, wp6_link_state(self.root))
        # Leftovers an interrupted run or an older setup can leave: removed; the fixed links stay.
        self.symlink(WP6_LEGACY_LINKS[1], "../../../../DAY0-Prepare/site-p/99-output-nvl")
        self.symlink("nvlink/publickey/laptop.pub", "../../DAY0-Prepare/activate-project/laptop.pub")
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual(state, wp6_link_state(self.root))
        # Q5: the manifest is the derived record of the active project and goes with the pointer; without a
        # pointer it is no project's record, and unsetup leaves it for setup to rewrite (existing contract:
        # no project named, no manifest removed).
        manifest = self.root / "ztp/.setup_manifest"
        manifest.write_text(f"# setup manifest — proj: {self.project}\n", encoding="utf-8")
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual(state, wp6_link_state(self.root))
        self.assertTrue(manifest.is_file())

    def test_invalid_pointer_changes_nothing_and_exits_1(self):
        self.build()
        os.unlink(self.day0 / "activate-project")
        os.symlink("template", self.day0 / "activate-project")
        before = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(1, result, output)
        self.assertIn("activate-project", output)
        self.assertEqual(before, wp6_link_state(self.root))
        self.assertTrue((self.root / "ztp/.setup_manifest").is_file())

    def test_retired_monitor_link_in_a_real_directory_is_reported_and_kept(self):
        # Owner rule 2026-11-03 (需求文档 R-016 设计输入, :920-925): a same-named real file is reported, not
        # replaced or deleted, and the run does not stop.  WP-8 待决 1 (http dev 2026-11-08) applies it here.
        self.build()
        retired = self.root / WP6_RETIRED_MONITOR_LINK
        os.unlink(retired)
        retired.mkdir()
        (retired / "operator.txt").write_text("operator-owned\n", encoding="utf-8")
        before = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(1, result, output)
        self.assertIn("[ERROR]", output)
        self.assertIn(WP6_RETIRED_MONITOR_LINK, output)
        self.assertEqual("operator-owned\n", (retired / "operator.txt").read_text(encoding="utf-8"))
        # Not interrupted: the rest of unsetup still ran.
        self.assertFalse(os.path.lexists(self.day0 / "activate-project"))
        for path in WP6_LEGACY_LINKS[:-1]:
            with self.subTest(legacy=path):
                self.assertFalse(os.path.lexists(self.root / path))
        for path in self.fixed_paths():
            with self.subTest(fixed=path):
                self.assertEqual(before[path], os.readlink(self.root / path))

    def test_pointer_form_infra_logs_is_kept_and_a_second_unsetup_succeeds(self):
        # Depends on WP-9b: managed_infra_log_project must accept the canonical pointer-form text, and keep
        # accepting it when the pointer is gone and the link dangles (Q7).  RED until WP-9b lands.
        self.build(infra_logs=True)
        before = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assert_unsetup_result(before, infra_logs=True)
        state = wp6_link_state(self.root)
        result, output = self.unsetup()
        self.assertEqual(0, result, output)
        self.assertEqual(state, wp6_link_state(self.root))


WP6_PACKAGE = load_script("activate_project_contract_package_common", ROOT / "tools/_package_common.py")


class WP6RetiredLinkPackagingTests(unittest.TestCase):
    """WP-8 待决 1 (http dev 2026-11-08): tar and sync leave the retired monitor/99-output-ufm link behind.

    WP-8 measured that neither packaging path excluded the dangling link any more once R-013 removed it from the
    table.  Tar filters every member through project_contract.transfer_exclude_reason and setup_managed_links;
    sync's monitor/ rsync job takes its link excludes from setup_managed_links only.
    """

    def test_transfer_exclude_reason_names_the_retired_link(self):
        self.assertIsNotNone(CONTRACT.transfer_exclude_reason(WP6_RETIRED_MONITOR_LINK))
        self.assertIsNone(CONTRACT.transfer_exclude_reason("monitor/generate-monitor-html.py"), "control")

    def test_setup_managed_links_name_a_retired_link_that_is_present(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "DAY0-Prepare").mkdir()
            manifest = root / "ztp/.setup_manifest"
            with mock.patch.multiple(WP6_PACKAGE, ROOT=root, DAY0=root / "DAY0-Prepare", MANIFEST=manifest):
                absent = WP6_PACKAGE.setup_managed_links()
                (root / "monitor").mkdir()
                os.symlink("../DAY0-Prepare/site-p/99-output-ufm", root / WP6_RETIRED_MONITOR_LINK)
                present = WP6_PACKAGE.setup_managed_links()
        self.assertNotIn(WP6_RETIRED_MONITOR_LINK, absent)
        self.assertEqual({WP6_RETIRED_MONITOR_LINK}, present - absent)


# ── v3.1.1 WP-4: --status, --check-template and the shared links (R-016 §4.5, §4.6; I-024) ──
# Expected values come from the design, never from the implementation under test:
# - R-016 §4.5: --status is read-only and lock-free and no longer reads ztp/.setup_manifest; it reports the
#   pointer (没有 / 有效 / 无效), every fixed row (正确、缺失、指向别处、真实文件冲突、目标缺失: required ones are
#   errors, optional ones are only listed), whether the active project's derived contents (§3.3) are complete;
#   exit 0 when all is well, 1 on any problem.  详细工作指导 WP-4: publisher-owned rows are not checked; shared
#   links are right when they lead under http/image (I-024); a user link input is reported as 「来自链接 → 目标」
#   (WP-11, R-014 第 3 条).
# - R-016 §4.6: --check-template changes nothing, checks template for each fixed name as if the pointer named
#   template, lists required and optional names apart, exit 0 when no required name is missing, else 1.
# - I-024 (owner 2026-11-02): setup's links and --status use one list; the UFM image link
#   infiniband/bringup/ufm-setup-upgrade/image -> ../../../image is shared, never a project escape.
# - The shared targets come from the table's shared section (_check_conflicts, which also used them, is gone:
#   D11, http dev 2026-11-08 -- a switch changes only the pointer, R-016 §1 第 2 条).
# Each row's canonical text is the table's own (pointer_link_specs / pointer_link_target, wave-3 brief), never a
# literal written here.

import contextlib
from contextlib import redirect_stderr, redirect_stdout
import functools
import io
import shutil
from unittest import mock

WP4_PROJECT = "site-p"
WP4_UFM_IMAGE = "infiniband/bringup/ufm-setup-upgrade/image"


@functools.lru_cache(maxsize=1)
def wp4_setup():
    """DAY0-Prepare/01-a-setup.py, loaded once for the WP-4 classes."""
    return load_script("activate_project_contract_wp4_setup", ROOT / "DAY0-Prepare/01-a-setup.py")


def wp4_table():
    """The link table setup itself imports (tools/project_contract.py)."""
    return wp4_setup().sys.modules["project_contract"]


def wp4_complete_tree(root: Path, name: str = WP4_PROJECT) -> Path:
    """A tree as R-016 says setup leaves it: the pointer, every non-publisher row at its canonical text, the
    project's required inputs and prepared contents (§3.3, §3.4), and one key linked in each public-key
    directory (§3.2).  Optional targets are left absent: dangling optional rows are normal (§3.4)."""
    table = wp4_table()
    day0 = root / "DAY0-Prepare"
    project = day0 / name
    project.mkdir(parents=True)
    # §3.3: the 99-output-* directories the template carries.
    for entry in sorted((ROOT / "DAY0-Prepare/template").iterdir()):
        if entry.name.startswith("99-output-") and entry.is_dir():
            (project / entry.name).mkdir()
    for row in table.SETUP_LINK_SPECS:
        if row.base != "project" or row.role not in ("required", "prepared"):
            continue
        target = project / row.target
        if row.kind == "dir":
            target.mkdir(parents=True, exist_ok=True)
        elif not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"fixture {row.target}\n", encoding="utf-8")
    (project / "laptop.pub").write_text("ssh-ed25519 fixture operator@laptop\n", encoding="ascii")
    os.symlink(name, day0 / "activate-project")
    texts = dict(table.pointer_link_specs())
    for row in table.SETUP_LINK_SPECS:
        if row.role == "publisher":
            continue
        link = root / row.path
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(texts[row.path], link)
    for directory in table.PUBLICKEY_DIRECTORIES:
        (root / directory).mkdir(parents=True, exist_ok=True)
        os.symlink(table.pointer_link_target(directory + "/laptop.pub", "laptop.pub"),
                   root / directory / "laptop.pub")
    return project


def wp4_patches(root: Path, template: Path | None = None) -> dict:
    return dict(
        HERE=str(root / "DAY0-Prepare"), HTTP_BASE=str(root), ZTP=str(root / "ztp"),
        IMAGE_DIR=str(root / "image"), MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
        TEMPLATE_DIR=str(template if template is not None else ROOT / "DAY0-Prepare/template"),
    )


def wp4_run_main(root: Path, argv, template: Path | None = None, *, forbid_manifest: bool = False):
    """main(argv) under the tree; an argparse refusal is its exit code.  No lock may be taken."""
    setup = wp4_setup()
    printed = io.StringIO()
    manifest_reader = (mock.patch.object(
        setup, "_read_bounded_regular_text",
        side_effect=AssertionError("R-016 §4.5: --status no longer reads ztp/.setup_manifest"),
    ) if forbid_manifest else contextlib.nullcontext())
    with mock.patch.multiple(setup, **wp4_patches(root, template)), mock.patch.object(
        setup, "deployment_lock", side_effect=AssertionError("R-016 §4.5/§4.6: read-only actions take no lock"),
    ), manifest_reader, redirect_stdout(printed), redirect_stderr(io.StringIO()):
        try:
            code = setup.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, printed.getvalue()


def wp4_inspect(root: Path) -> dict:
    setup = wp4_setup()
    with mock.patch.multiple(setup, **wp4_patches(root)):
        return setup.inspect_active_project()


def wp4_check_template(root: Path, template: Path) -> dict:
    setup = wp4_setup()
    with mock.patch.multiple(setup, **wp4_patches(root, template)):
        return setup.check_template()


class WP4StatusTests(unittest.TestCase):
    """R-016 §4.5 and 详细工作指导 WP-4: --status over the pointer layout."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "http"
        self.project = wp4_complete_tree(self.root)

    def status(self):
        return wp4_run_main(self.root, ["--status"])

    def assert_status(self, expected_code: int, *words: str) -> str:
        code, printed = self.status()
        self.assertEqual(expected_code, code, printed)
        for word in words:
            self.assertIn(word, printed)
        return printed

    def assert_problem(self, path: str, state: str) -> None:
        printed = self.assert_status(1, path, state)
        report = wp4_inspect(self.root)
        self.assertEqual(state, report["links"][path])
        self.assertTrue(any(path in line and state in line for line in report["problems"]), report["problems"])

    def test_complete_tree_is_right_read_only_lock_free_and_manifest_free(self):
        # A stale manifest naming another project is not an identity source any more (R-016 §4.5, Q5).
        other = self.root / "DAY0-Prepare/site-q"
        other.mkdir()
        (self.root / "ztp/.setup_manifest").write_text(
            f"# setup manifest — proj: {other}\n", encoding="utf-8")
        before = tree_state(self.root.parent)
        code, printed = wp4_run_main(self.root, ["--status"], forbid_manifest=True)
        self.assertEqual(0, code, printed)
        self.assertIn("activate-project", printed)
        self.assertIn(WP4_PROJECT, printed)
        self.assertEqual(tree_state(self.root.parent), before, "--status writes nothing")
        self.assertNotIn("site-q", printed)

        report = wp4_inspect(self.root)
        self.assertEqual(Path(os.path.realpath(self.project)), report["project"])
        self.assertEqual([], report["problems"])
        for row in wp4_table().SETUP_LINK_SPECS:
            if row.role in ("required", "prepared"):
                with self.subTest(row=row.path):
                    self.assertEqual("正确", report["links"][row.path])

    def test_no_pointer_is_reported_and_exits_1(self):
        (self.root / "DAY0-Prepare/activate-project").unlink()
        self.assert_status(1, "activate-project", "没有")
        report = wp4_inspect(self.root)
        self.assertIsNone(report["project"])
        self.assertTrue(report["problems"])

    def test_invalid_pointer_names_the_reason_and_exits_1(self):
        pointer = self.root / "DAY0-Prepare/activate-project"
        (self.root / "DAY0-Prepare/template").mkdir()
        for text in ("template", "../DAY0-Prepare/" + WP4_PROJECT, "site-gone"):
            with self.subTest(text=text):
                pointer.unlink()
                os.symlink(text, pointer)
                self.assert_status(1, "无效", text)
                self.assertIsNone(wp4_inspect(self.root)["project"])

    def test_missing_fixed_link_is_an_error(self):
        (self.root / "ztp/status").unlink()
        self.assert_problem("ztp/status", "缺失")

    def test_link_pointing_elsewhere_is_an_error_even_when_it_reaches_the_same_file(self):
        # R-016 §4.3: 「已正确」 is judged by the link text alone; the pre-migration direct text is elsewhere
        # (详细工作指导 WP-4 「风险」: before migration --status reports every such row 「指向别处」).
        path = "ztp/config/cumulus/template/02-devices_config.csv"
        link = self.root / path
        link.unlink()
        os.symlink(os.path.relpath(self.project / "02-devices_config.csv", link.parent), link)
        self.assertEqual(link.resolve(), (self.project / "02-devices_config.csv").resolve())
        self.assert_problem(path, "指向别处")

    def test_real_file_in_a_link_position_is_an_error_and_is_kept(self):
        path = "ethernet/eth.csv"
        link = self.root / path
        link.unlink()
        link.write_bytes(b"operator file\n")
        self.assert_problem(path, "真实文件冲突")
        self.assertEqual(b"operator file\n", link.read_bytes())

    def test_required_target_missing_is_an_error(self):
        (self.project / "01-global.yaml").unlink()
        self.assert_problem("ztp/config/cumulus/template/01-global.yaml", "目标缺失")

    def test_optional_rows_are_only_listed(self):
        table = wp4_table()
        optional = [row.path for row in table.SETUP_LINK_SPECS if row.role == "optional"]
        self.assertIn(table.P2P_AIR_PATH, optional)
        self.assertFalse((self.project / "99-output-p2p/p2p-air.json").exists(), "not an AIR project")
        # One optional link pointing elsewhere is listed too, never an error (R-016 §4.5).
        moved = self.root / "ethernet/monitor/04-device-aliases.csv"
        moved.unlink()
        os.symlink("../../somewhere-else.csv", moved)
        printed = self.assert_status(0, table.P2P_AIR_PATH, "ethernet/monitor/04-device-aliases.csv")
        report = wp4_inspect(self.root)
        self.assertEqual([], report["problems"])
        self.assertEqual("目标缺失", report["links"][table.P2P_AIR_PATH])
        self.assertEqual("指向别处", report["links"]["ethernet/monitor/04-device-aliases.csv"])
        self.assertTrue(any(table.P2P_AIR_PATH in line for line in report["listed"]))
        self.assertNotIn("[ERROR]", printed)

    def test_publisher_rows_are_not_checked(self):
        table = wp4_table()
        publisher = [row.path for row in table.SETUP_LINK_SPECS if row.role == "publisher"]
        self.assertTrue(publisher)
        for path in publisher:
            link = self.root / path
            link.parent.mkdir(parents=True, exist_ok=True)
            os.symlink("no-release-yet", link)
        printed = self.assert_status(0)
        for path in publisher:
            self.assertNotIn(path, printed)
            self.assertNotIn(path, wp4_inspect(self.root)["links"])

    def test_ufm_image_link_under_http_image_is_right_i024(self):
        # I-024: a project with UFM, http/image present, setup's link ../../../image: right, not an escape.
        devices = self.project / "02-devices_config.csv"
        devices.write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
            "ufm01,server_ufm,NA,198.51.100.31,24,198.51.100.1,02:00:00:00:02:31\n", encoding="utf-8")
        image = self.root / "image"
        image.mkdir()
        (image / "ufm.lic").write_bytes(b"fixture license\n")
        (image / "cumulus-linux-5.16.4-mlx-amd64.bin").write_bytes(b"fixture image\n")
        link = self.root / WP4_UFM_IMAGE
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(image, link.parent), link)
        self.assertEqual("../../../image", os.readlink(link))
        binary = self.root / "ztp/image/cumulus/cumulus-linux-5.16.4-mlx-amd64.bin"
        binary.parent.mkdir(parents=True)
        os.symlink(os.path.relpath(image / binary.name, binary.parent), binary)

        printed = self.assert_status(0, WP4_UFM_IMAGE)
        self.assertNotIn("逃逸", printed)
        report = wp4_inspect(self.root)
        self.assertEqual([], report["problems"])
        self.assertEqual("正确", report["links"][WP4_UFM_IMAGE])
        self.assertEqual("正确", report["links"]["ztp/image/cumulus/" + binary.name])

    def test_shared_link_leading_elsewhere_is_listed_not_right(self):
        link = self.root / WP4_UFM_IMAGE
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink("../../../DAY0-Prepare/" + WP4_PROJECT, link)
        self.assert_status(0, WP4_UFM_IMAGE)
        report = wp4_inspect(self.root)
        self.assertEqual("指向别处", report["links"][WP4_UFM_IMAGE])
        self.assertTrue(any(WP4_UFM_IMAGE in line for line in report["listed"]))

    def test_missing_derived_content_is_an_error(self):
        # R-016 §3.3: the 99-output-* directories are the preparation step's; one missing is a problem.
        shutil.rmtree(self.project / "99-output-dhcp")
        printed = self.assert_status(1, "99-output-dhcp")
        report = wp4_inspect(self.root)
        self.assertTrue(any("派生内容" in line and "99-output-dhcp" in line for line in report["problems"]),
                        report["problems"])
        self.assertIn("派生内容", printed)

    def test_public_key_links_follow_the_project_keys(self):
        # R-016 §3.2: each of the four real directories holds one canonical link per non-empty project key.
        table = wp4_table()
        missing = sorted(table.PUBLICKEY_DIRECTORIES)[0] + "/laptop.pub"
        (self.root / missing).unlink()
        self.assert_problem(missing, "缺失")
        os.symlink(table.pointer_link_target(missing, "laptop.pub"), self.root / missing)
        self.assert_status(0)

        stale = sorted(table.PUBLICKEY_DIRECTORIES)[-1] + "/retired.pub"
        os.symlink(table.pointer_link_target(stale, "retired.pub"), self.root / stale)
        self.assert_status(1, stale)
        operator_file = self.root / sorted(table.PUBLICKEY_DIRECTORIES)[-1] / "operator.pub"
        (self.root / stale).unlink()
        operator_file.write_text("operator-managed\n", encoding="ascii")
        self.assert_status(0)

    def test_user_link_input_is_reported_with_its_target(self):
        # WP-11 / R-014 第 3 条: a project input may be the user's link; --status names where it comes from.
        outside = self.root.parent / "Work/devices.csv"
        outside.parent.mkdir()
        outside.write_bytes((self.project / "02-devices_config.csv").read_bytes())
        devices = self.project / "02-devices_config.csv"
        devices.unlink()
        os.symlink(outside, devices)
        printed = self.assert_status(0, "02-devices_config.csv", "来自链接", str(outside.resolve()))
        self.assertTrue(any("02-devices_config.csv" in line and str(outside.resolve()) in line
                            for line in wp4_inspect(self.root)["inputs"]), printed)
        outside.unlink()
        self.assert_status(1, "02-devices_config.csv")

    def test_rows_of_a_tool_this_host_lacks_are_not_applicable(self):
        # Offline analyzers are not deployed (setup leaves their links alone where the tool is absent).
        shutil.rmtree(self.root / "tools/ibdiagnet-analyze-tool")
        self.assert_status(0)
        self.assertEqual("不适用", wp4_inspect(self.root)["links"]["tools/ibdiagnet-analyze-tool/99-output-p2p"])


class WP4CheckTemplateTests(unittest.TestCase):
    """R-016 §4.6 (B 方案) and 详细工作指导 WP-4/WP-8: --check-template against template's fixed names."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "http"
        (self.root / "DAY0-Prepare").mkdir(parents=True)

    def copy_template(self) -> Path:
        copy = self.root / "DAY0-Prepare/template"
        shutil.copytree(ROOT / "DAY0-Prepare/template", copy, symlinks=True)
        return copy

    def required_names(self) -> set[str]:
        return {row.target for row in wp4_table().SETUP_LINK_SPECS
                if row.base == "project" and row.role == "required"}

    def test_the_real_template_passes_and_nothing_changes(self):
        # R-013 acceptance (WP-8): --check-template on the repository's template returns 0.
        template = ROOT / "DAY0-Prepare/template"
        before = tree_state(template)
        code, printed = wp4_run_main(self.root, ["--check-template"], template)
        self.assertEqual(0, code, printed)
        self.assertEqual(tree_state(template), before)
        for name in self.required_names():
            self.assertIn(name, printed)
        report = wp4_check_template(self.root, template)
        self.assertEqual({name: True for name in self.required_names()}, report["required"])

    def test_a_copy_missing_one_required_name_fails(self):
        template = self.copy_template()
        (template / "02-dhcp-subnet_config.csv").unlink()
        code, printed = wp4_run_main(self.root, ["--check-template"], template)
        self.assertEqual(1, code, printed)
        self.assertIn("02-dhcp-subnet_config.csv", printed)
        self.assertFalse(wp4_check_template(self.root, template)["required"]["02-dhcp-subnet_config.csv"])

    def test_link_members_count_like_files(self):
        # WP-12 adds template/ib.csv -> 02-devices_config.csv, the template's first link: never an error.
        # (R-016 §10.2 decision E, owner 2026-11-04; v3.1.1 WP-12: the repository template now carries it.)
        template = self.copy_template()
        self.assertEqual("02-devices_config.csv", os.readlink(template / "ib.csv"))
        (template / "01-global.yaml").rename(template / "global-source.yaml")
        os.symlink("global-source.yaml", template / "01-global.yaml")
        code, printed = wp4_run_main(self.root, ["--check-template"], template)
        self.assertEqual(0, code, printed)

    def test_prepared_and_optional_names_may_be_missing_and_are_listed_apart(self):
        template = self.copy_template()
        shutil.rmtree(template / "99-output-p2p")
        code, printed = wp4_run_main(self.root, ["--check-template"], template)
        self.assertEqual(0, code, printed)
        self.assertIn("必需", printed)
        self.assertIn("可选", printed)
        report = wp4_check_template(self.root, template)
        self.assertFalse(report["prepared"]["99-output-p2p"])
        self.assertFalse(report["optional"]["99-output-p2p/p2p-air.json"])
        self.assertTrue(all(report["required"].values()))

    def test_check_template_is_a_standalone_read_only_action(self):
        for argv in (["--check-template", WP4_PROJECT], ["--check-template", "--status"],
                     ["--check-template", "-y"]):
            with self.subTest(argv=argv):
                code, _printed = wp4_run_main(self.root, argv)
                self.assertEqual(2, code)

# v3.1.1 WP-9a: imports for the classes below, kept here so WP-3's header stays as it is.
from contextlib import ExitStack  # noqa: E402
import json  # noqa: E402
from unittest import mock  # noqa: E402


class WP9aServiceReaderTests(unittest.TestCase):
    """v3.1.1 WP-9a direct cases: the readers and resident services resolve the pointer themselves.

    R-016 §5.1 (one function names the active project; resolve once per run), §5.2 (class 1: setup's
    canonical text; class 6: never the parent of a resolved project file), §6 (worker: skip a cycle
    without a pointer and keep the schedule; monitor: stop when the pointer moves), 问题文档 I-030 (the
    AIR json link is resolved first and is optional).  The pointer layout is the workflow module's
    PointerTree, built by the test itself.
    """

    def setUp(self):
        from test_cases import test_activate_project_services_workflow as services

        self.services = services
        temporary = tempfile.TemporaryDirectory(prefix="wp9a-direct-")
        self.addCleanup(temporary.cleanup)
        self.tree = services.PointerTree(Path(temporary.name))

    def invalid_pointer(self) -> None:
        (self.tree.day0 / "template").mkdir(exist_ok=True)
        self.tree.point("template")   # R-016 §2: never a project

    def test_gate_names_the_pointer_project_and_never_the_inventory_link(self):
        worker = self.services.WORKER
        # monitor/02-devices_config.csv names Q, the pointer names P: the pointer wins (R-016 §5.2).
        inventory = self.tree.root / "monitor/02-devices_config.csv"
        inventory.unlink()
        inventory.symlink_to(f"../DAY0-Prepare/{self.services.PROJECT_Q}/02-devices_config.csv")
        self.assertEqual(str(self.tree.real(self.services.PROJECT_P)),
                         worker.active_project_identity(self.tree.root))
        self.tree.unpoint()
        with self.assertRaises(worker.NoActiveProjectError) as raised:
            worker.active_project_identity(self.tree.root)
        self.assertIsInstance(raised.exception, worker.CollectionGateError)
        self.assertEqual("没有激活的项目", str(raised.exception))
        self.invalid_pointer()
        with self.assertRaisesRegex(worker.CollectionGateError, "template") as raised:
            worker.active_project_identity(self.tree.root)
        self.assertNotIsInstance(raised.exception, worker.NoActiveProjectError)

    def test_continuous_cycles_without_a_pointer_wait_one_interval_and_stay_enabled(self):
        worker = self.services.WORKER
        self.tree.unpoint()
        cases = (
            ("collection", worker.run_continuous_collection_cycle, "CONTINUOUS_STATUS_FILE",
             {"_CONTINUOUS_COLLECTION_INTERVAL_SECONDS": 600, "_CONTINUOUS_COLLECTION_NEXT_RUN": 0.0}),
            ("backup", worker.run_continuous_backup_cycle, "CONTINUOUS_BACKUP_STATUS_FILE",
             {"_CONTINUOUS_BACKUP_INTERVAL_SECONDS": 600, "_CONTINUOUS_BACKUP_NEXT_RUN": 0.0,
              "_CONTINUOUS_BACKUP_PASSWORD": "unused"}),
        )
        for lane, cycle, status_name, schedule in cases:
            with self.subTest(lane=lane), \
                    self.services.ActivateProjectServicesWorkflowTests.worker(self, self.tree, mock.Mock()) \
                    as status, mock.patch.multiple(worker, **schedule), \
                    mock.patch.object(worker, "collect_safely") as collect, \
                    mock.patch.object(worker, "run_yaml_backup_safely") as backup:
                self.assertTrue(cycle("prod", 60, 0))
                document = json.loads(getattr(worker, status_name).read_text(encoding="utf-8"))
                collect.assert_not_called()
                backup.assert_not_called()
                # R-016 §6: the cycle is skipped, the schedule is kept (not "failed", not stopped).
                self.assertEqual(("waiting", True, "没有激活的项目", 600),
                                 (document["state"], document["enabled"], document["wait_reason"],
                                  document["remaining_seconds"]))
                self.assertTrue(status.is_dir())

    def monitor_paths(self):
        root = self.tree.root
        return mock.patch.multiple(
            self.services.MONITOR, HERE=self.tree.day0,
            ACTIVE_INVENTORY=root / "ztp/config/isc-dhcp-server/02-devices_config.csv",
            ACTIVE_AIR_JSON=root / "ztp/config/isc-dhcp-server/p2p-air.json",
            ZTP_STATUS_DIR=root / "ztp/status",
        )

    def test_monitor_stops_only_when_the_pointer_moves(self):
        monitor = self.services.MONITOR
        project = self.tree.projects[self.services.PROJECT_P]
        with self.monitor_paths():
            self.assertIsNone(monitor.active_project_moved(project))
            self.tree.point(self.services.PROJECT_Q)
            self.assertIn("已指向其他项目：site-q", monitor.active_project_moved(project))
            self.tree.unpoint()
            self.assertIn("没有激活的项目", monitor.active_project_moved(project))
            self.invalid_pointer()
            self.assertIn("template", monitor.active_project_moved(project))

    def test_monitor_requires_setup_canonical_text_not_the_old_direct_link(self):
        monitor = self.services.MONITOR
        project = self.tree.projects[self.services.PROJECT_P]
        inventory = self.tree.root / "ztp/config/isc-dhcp-server/02-devices_config.csv"
        with self.monitor_paths():
            monitor.require_active_project(project)
            # R-016 §8: the old direct text resolves to the same file but is no longer setup's link.
            inventory.unlink()
            inventory.symlink_to("../../../DAY0-Prepare/site-p/02-devices_config.csv")
            with self.assertRaisesRegex(ValueError, "活动项目身份无效（active inventory）"):
                monitor.require_active_project(project)

    def test_monitor_reads_the_air_json_through_its_link_and_treats_dangling_as_absent(self):
        monitor = self.services.MONITOR
        air = self.tree.projects[self.services.PROJECT_P] / "99-output-p2p/p2p-air.json"
        with self.monitor_paths():
            link = monitor.ACTIVE_AIR_JSON
            self.assertIsNone(monitor.active_air_json(link))      # dangling: not an AIR project
            air.write_text("{}\n", encoding="utf-8")
            resolved = monitor.active_air_json(link)
            self.assertEqual(self.tree.real(self.services.PROJECT_P) / "99-output-p2p/p2p-air.json", resolved)
            self.assertFalse(resolved.is_symlink())
            link.unlink()
            self.assertIsNone(monitor.active_air_json(link))      # no link at all

    def test_project_readers_follow_the_pointer_even_without_the_monitor_global_link(self):
        services = self.services
        (self.tree.root / "monitor/01-global.yaml").unlink()   # the issue tracker's old anchor
        (self.tree.root / "ztp/status").unlink()                # manual-ztp's old anchor
        real = self.tree.real(services.PROJECT_P)
        with ExitStack() as stack:
            for module in (services.ISSUE_SYNC, services.SWITCH_STATUS, services.MANUAL_WORKER, services.MANUAL):
                stack.enter_context(mock.patch.object(module, "HTTP_ROOT", self.tree.root))
            self.assertEqual(real, services.ISSUE_SYNC.project_directory(None))
            self.assertEqual(real, services.SWITCH_STATUS.project_directory(None))
            self.assertEqual(real, services.MANUAL_WORKER.active_project())
            self.assertEqual(real, services.MANUAL.resolve_project(None))
            # an explicit project still wins where the reader takes one
            explicit = self.tree.projects[services.PROJECT_Q]
            self.assertEqual(explicit.resolve(), services.ISSUE_SYNC.project_directory(explicit))
            self.assertEqual(explicit.resolve(), services.SWITCH_STATUS.project_directory(explicit))
            self.invalid_pointer()
            with self.assertRaisesRegex(services.ISSUE_SYNC.SyncError, "template"):
                services.ISSUE_SYNC.project_directory(None)
            with self.assertRaisesRegex(services.SWITCH_STATUS.InputError, "template"):
                services.SWITCH_STATUS.project_directory(None)
            self.assertIsNone(services.MANUAL_WORKER.active_project())
            with self.assertRaisesRegex(services.MANUAL.ManualZtpError, "template"):
                services.MANUAL.resolve_project(None)


class WP9bReaderDirectTests(unittest.TestCase):
    """v3.1.1 WP-9b: load, unload and packaging name the project the pointer selects.

    Expected values come from the design, never from the implementation:
    - R-016 §5.1: a reader resolves DAY0-Prepare/activate-project once with active_project_dir -- None without
      a pointer, an error naming the reason when it is invalid -- and no longer reads the setup manifest's
      first line nor cuts a project name out of a link's text.
    - R-016 §2: a tree link to a project file is relpath("DAY0-Prepare/activate-project/<name>", its directory).
    - 详细工作指导 WP-9 class 1 and 2.3: load's same-project rollback receipt admits a public-key or DHCP
      publication only in that form; only the expected text changes, the receipt flow does not.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wp9b-readers-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "http"
        self.day0 = self.root / "DAY0-Prepare"
        for name in ("site-p", "site-q"):
            project = self.day0 / name
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
            (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
        self.pointer = self.day0 / "activate-project"
        # A stale manifest naming the other project: none of these readers may consult it (R-016 §5.1).
        manifest = self.root / "ztp/.setup_manifest"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(f"# setup manifest — proj: {self.day0 / 'site-q'}\n", encoding="utf-8")
        self.manifest = manifest

    def point(self, name):
        if os.path.lexists(self.pointer):
            self.pointer.unlink()
        if name is not None:
            self.pointer.symlink_to(name)

    def link(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(text)
        return path

    def test_packaging_resolves_the_pointer_not_the_manifest(self):
        from unittest import mock
        package = load_script("wp9b_readers_package_common", ROOT / "tools/_package_common.py")
        with mock.patch.multiple(package, ROOT=self.root, DAY0=self.day0, MANIFEST=self.manifest):
            self.point("site-p")
            self.assertEqual((self.day0 / "site-p").resolve(), package.active_project())
            self.assertEqual((self.day0 / "site-p").resolve(), package.resolve_project(None))
            self.point(None)
            self.assertIsNone(package.active_project())
            with self.assertRaisesRegex(ValueError, "activate-project"):
                package.resolve_project(None)  # two candidate projects and no pointer: ask for --project
            self.point("missing")
            with self.assertRaisesRegex(ValueError, "activate-project -> missing"):
                package.resolve_project(None)

    def test_unload_resolves_the_pointer_not_the_manifest(self):
        from unittest import mock
        unload = load_script("wp9b_readers_unload", ROOT / "DAY0-Prepare/13-unload.py")
        with mock.patch.object(unload, "HTTP_ROOT", self.root):
            self.point("site-p")
            self.assertEqual((self.day0 / "site-p").resolve(), unload.resolve_project(None))
            self.point(None)
            self.assertIsNone(unload.resolve_project(None))
            self.point("template")
            with self.assertRaisesRegex(unload.UnloadError, "activate-project -> template"):
                unload.resolve_project(None)

    def test_ibsw_managed_inputs_bind_the_pointer_project_and_hold_the_pointer(self):
        # 详细工作指导 WP-9 class 1/5 and O7: the v1 upgrade library takes the project from the pointer and the
        # link texts from the table; v1 keeps reading the project's 02 (O7 (c)).
        inputs = load_script("wp9b_readers_ibsw_inputs", ROOT / "tools/ibsw_upgrade_inputs.py")
        project = self.day0 / "site-p"
        (project / "01-global.yaml").write_text(
            "schema_version: 2\ncommon:\n  mgmt:\n    http:\n      status: enabled\n"
            "      address: 192.0.2.254\n      port: 8088\n      http_root: /var/www/html\n"
            "switches:\n- ib:\n    version: '25.03.1010'\n", encoding="utf-8")
        header = ("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,"
                  "lo_ip,bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl")
        rows = [f"ew-spine{n:02d}.example,ib,NA,192.0.2.{n},24,192.0.2.254,02:00:00:00:00:{n:02x}" + "," * 12
                for n in (1, 2)]
        (project / "02-devices_config.csv").write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
        (project / "02-dhcp-subnet_config.csv").write_text("header\n", encoding="utf-8")
        (project / "ib.csv").symlink_to("02-devices_config.csv")  # the template default (decision E)
        (project / "99-output-ztp").mkdir()
        (project / "99-output-ib_nvl/bringup/xdr-upgrade-logs").mkdir(parents=True)
        for relative, fixed in (
            ("infiniband/01-global.yaml", "01-global.yaml"), ("infiniband/ib.csv", "ib.csv"),
            ("ztp/config/cumulus/template/01-global.yaml", "01-global.yaml"),
            ("ztp/config/cumulus/template/02-devices_config.csv", "02-devices_config.csv"),
            ("ztp/config/isc-dhcp-server/02-subnet_config.csv", "02-dhcp-subnet_config.csv"),
            ("ztp/status", "99-output-ztp"),
            ("infiniband/bringup/xdr-upgrade/xdr-upgrade-logs", "99-output-ib_nvl/bringup/xdr-upgrade-logs"),
        ):
            self.link(relative, CONTRACT.pointer_link_target(relative, fixed))
        entry = self.root / "infiniband/bringup/xdr-upgrade"
        (entry / "01-global.yaml").symlink_to("../../01-global.yaml")
        (entry / "ib.csv").symlink_to("../../ib.csv")
        plan = inputs.InputPaths(project=None, csv_path=str(entry / "ib.csv"),
                                 global_path=str(entry / "01-global.yaml"),
                                 output_path=str(entry / "xdr-upgrade-logs/run-1/plan.json"))
        self.point("site-p")
        with inputs.open_managed_inputs(plan) as scope:
            self.assertEqual(["ew-spine01.example", "ew-spine02.example"],
                             [device.hostname for device in scope.inventory().devices])
            self.point("site-q")  # R-016 §5.1: one run reads one project; a switch is not adopted
            with self.assertRaises(ValueError):
                scope.verify()
        self.point(None)
        with self.assertRaisesRegex(ValueError, "no active project"):
            inputs.open_managed_inputs(plan)
        self.point("site-p")
        direct = self.root / "infiniband/01-global.yaml"
        direct.unlink()
        direct.symlink_to("../DAY0-Prepare/site-p/01-global.yaml")  # an earlier setup's direct form
        with self.assertRaisesRegex(ValueError, "managed global is not the exact"):
            inputs.open_managed_inputs(plan)

    def test_load_resolves_the_pointer_and_binds_receipt_links_through_it(self):
        from unittest import mock
        load = load_script("wp9b_readers_load", ROOT / "DAY0-Prepare/11-load.py")
        project = (self.day0 / "site-p").resolve()
        (project / "laptop.pub").write_text("ssh-ed25519 AAAAsynthetic laptop\n", encoding="ascii")
        (project / "99-output-dhcp").mkdir()
        (project / "99-output-dhcp/dhcpd.conf").write_text("# synthetic\n", encoding="ascii")
        key = self.link("ztp/config/publickey/laptop.pub", "../../../DAY0-Prepare/activate-project/laptop.pub")
        dhcp = self.link("ztp/config/isc-dhcp-server/dhcpd.conf",
                         "../../../DAY0-Prepare/activate-project/99-output-dhcp/dhcpd.conf")
        with mock.patch.multiple(load, HTTP_ROOT=self.root, ZTP_DIR=self.root / "ztp", MANIFEST=self.manifest):
            self.point("site-p")
            self.assertEqual(project, load.active_project())
            self.assertEqual(project / "laptop.pub", load._runtime_key_source(key, project, os.readlink(key)))
            self.assertEqual(project / "99-output-dhcp/dhcpd.conf",
                             load._runtime_dhcp_link_source(project, dhcp, os.readlink(dhcp)))
            self.point(None)
            self.assertIsNone(load.active_project())
            self.point("missing")
            with self.assertRaisesRegex(load.LoadError, "activate-project -> missing"):
                load.active_project()
            # The same link text names whatever the pointer selects: another project is not this one's.
            self.point("site-q")
            with self.assertRaises(load.LoadError):
                load._runtime_key_source(key, project, os.readlink(key))
            with self.assertRaises(load.LoadError):
                load._runtime_dhcp_link_source(project, dhcp, os.readlink(dhcp))
            # The direct form an earlier setup wrote is no longer setup's publication (O4 左列：R-016).
            self.point("site-p")
            with self.assertRaises(load.LoadError):
                load._runtime_key_source(key, project, os.path.relpath(project / "laptop.pub", key.parent))
            with self.assertRaises(load.LoadError):
                load._runtime_dhcp_link_source(
                    project, dhcp, os.path.relpath(project / "99-output-dhcp/dhcpd.conf", dhcp.parent))


if __name__ == "__main__":
    unittest.main()
