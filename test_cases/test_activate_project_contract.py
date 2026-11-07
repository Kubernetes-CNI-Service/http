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
# Table rows whose text WP-3 leaves direct, each handed to the package that owns its reader (详细工作指导 WP-9):
# delete an entry when that package moves the row behind the pointer.
HANDED_ON = {
    CONTRACT.P2P_AIR_PATH: "WP-9c: I-031 fixed AIR json name; _process_xlsx_files derives it until then",
}


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


if __name__ == "__main__":
    unittest.main()
