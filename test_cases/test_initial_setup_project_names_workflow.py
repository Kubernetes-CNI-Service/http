#!/usr/bin/env python3
"""v3.1.3 WP-8 workflow (O8): initial-setup reads a project by the project's own fixed names.

What: the real setup (DAY0-Prepare/01-a-setup.py, a subprocess in a copy of the git-indexed workspace made by
test_activate_project_workflow.Workspace) prepares three synthetic projects and leaves the last one active.  The
copied workspace's real initial-setup.py then runs main() in this process in management mode, either with --plan
(every input read, targets built and cached, report written, no device contacted) or as a read-only check whose
OOB Leaf snapshot is modelled as unavailable, so the run writes its snapshot directory and starts no IB task.  HOME
is a temporary directory; no external command other than `ssh-keygen -l` may run.

Expected values, written from the sources, never from the implementation:
- 详细工作指导 v3.1.3 WP-8 表 8-1 (:915-924) and :926 (O8): with --project-dir <P> the CSV is <P>/ib.csv, never
  02-devices_config.csv (v3.1.1 AP-c); the P2P <P>/p2p.xlsx; the global <P>/01-global.yaml; the public keys every
  non-empty *.pub at <P>'s root, an empty one skipped (the set 01-a-setup.py::_process_pubkeys links); the
  neutral defaults <P>/infiniband/bringup/xdr-initial-setup/infra-neutral.conf.  The bridges beside the script
  reach only the active project (:891), so no file of the active project is read.  Report, snapshots and cache
  stay under the current directory (表 8-1 last row; 参考/initial-setup-v15/CURRENT-CONTRACT.md:18).
- 表 8-1 second column: without --project-dir, CSV, P2P and the outputs follow the current directory; the
  global, the public keys and the neutral defaults follow the script's directory (DEV
  test_initial_setup_selfcontained_neutral.py :204-207, :238-241).
- :913: the report opens with one input-sources line naming the directory of CSV and P2P and the directory of
  the global, public keys and neutral defaults; when the two differ the line says so and the run goes on.
- :937 (v3.1.1 TRACKED_SETUP_BRIDGES and _process_pubkeys): on the active project, --project-dir and the
  bridges read the same global and the same keys (names and fingerprints).
- :938 (v15 :5548-5549): without a usable key the report has v15's WARNING line, no key installation is
  built, and the run is not refused.
- :926 (load_target_cache takes the public-key directory; None is the old <tool>/publickey behaviour) and the
  README's cache contract (xdr-initial-setup/README.md, initial-setup-targets.json: a valid cache is reused,
  otherwise regenerated): under --project-dir an unchanged project reuses the cache, and a newer key at the
  project root regenerates it with that key, in management mode and on an OOB Leaf in auto mode, whose reuse
  check alone guards the key directory (v3.1.3 WP-8b, review 中 2).
- 2.2 第 4 条: the fixture global carries REQ22's common.mgmt.{dhcp-server,ztp}.status.
- An OpenSSH fingerprint is "SHA256:" and the unpadded base64 of the SHA-256 of the key blob (ssh-keygen -l
  -E sha256); the expected fingerprints are computed that way here.
The three name-comparison methods of the guide's table (:940-942) are written only once O9's census is 0
(06 WP8a-2); the census counted 434 suffix-only matches (06 WP8a-A), so they are not in this module.
"""

from __future__ import annotations

import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases import test_activate_project_workflow as ACTIVATE_WORKFLOW
from test_cases.module_loader import load_script


EXAMPLE = Path(__file__).resolve().parents[1] / "examples/public-project"
TOOL_DIR = Path("infiniband/bringup/xdr-initial-setup")
NEUTRAL = TOOL_DIR / "infra-neutral.conf"        # 表 8-1: the project's neutral defaults (v3.1.2 WP-1)
OTHER = ACTIVATE_WORKFLOW.FIRST                  # set up, then left inactive
ACTIVE = ACTIVATE_WORKFLOW.SECOND                # set up last: the pointer names it
KEYLESS = "site-n"                               # keeps only the template's empty *.pub
CACHED = {"management": "site-m", "auto": "site-l"}   # one project per cache-reuse test: each adds a key
OOB_LEAF, IB_FIRST, IB_SECOND = "EXAMPLE-OOB-Leaf01", "EXAMPLE-IB-Leaf01", "EXAMPLE-IB-Leaf02"
DNS = {OTHER: "198.51.100.53", ACTIVE: "203.0.113.53", KEYLESS: "192.0.2.53",
       CACHED["management"]: "198.51.100.54", CACHED["auto"]: "198.51.100.55"}
# Besides these, the workstation setup binds the operator's own key into every project's laptop.pub
# (01-a-setup.py::_prepare_laptop_public_key), so P and the active project differ by these files.
KEYS = {
    OTHER: {"operator-p.pub": (64, "PUBLIC-other-operator"), "mgmt-server.pub": None},
    ACTIVE: {"mgmt-server.pub": (63, "PUBLIC-active-mgmt")},
    CACHED["management"]: {"mgmt-server.pub": (65, "PUBLIC-cache-mgmt")},
    CACHED["auto"]: {"mgmt-server.pub": (66, "PUBLIC-cache-mgmt")},
}
# Made distinct after setup, so a run's NTP and time zone show which neutral file it read.
SCRIPT_NEUTRAL = {"DNS": "192.0.2.54", "NTP": "time.script.example.test", "TIMEZONE": "Asia/Tokyo"}
ACTIVE_NEUTRAL = {"DNS": "203.0.113.54", "NTP": "time.active.example.test", "TIMEZONE": "Asia/Taipei"}
SNAPSHOT_FAILURE = "fixture: the OOB Leaf snapshot is not modelled"
WARNING = "WARNING: no usable *.pub keys found; no IB public key will be installed."   # v15 :5549
KEYGEN = ["ssh-keygen", "-l", "-E", "sha256", "-f", "/dev/stdin"]

_RECORDED: list[str] | None = None   # paths opened by the run being recorded
_HOOKED = False


def _record_open(event, args):
    if event == "open" and _RECORDED is not None and isinstance(args[0], (str, bytes, os.PathLike)):
        _RECORDED.append(os.fsdecode(args[0]))


def neutral_text(values: dict[str, str]) -> str:
    return "".join(f"{key}={values[key]}\n" for key in ("DNS", "NTP", "TIMEZONE"))


def neutral_values(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#"))


def fingerprint(line: str) -> str:
    digest = hashlib.sha256(base64.b64decode(line.split()[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def usable_keys(directory: Path) -> list[tuple[str, str]]:
    """表 8-1: every key line of each non-empty *.pub in directory, as (file name, fingerprint)."""
    return sorted((path.name, fingerprint(line)) for path in directory.glob("*.pub")
                  for line in path.read_text(encoding="ascii").splitlines() if line.strip())


def write_project(project: Path, name: str) -> None:
    """The inputs setup prepares: a global with an IB family, the device CSV, one P2P workbook, keys."""
    document = yaml.safe_load((EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8"))
    mgmt = document["common"]["mgmt"]
    mgmt["http"]["address"] = "192.0.2.10"
    for service in ("dhcp-server", "ztp"):
        mgmt[service]["status"] = "enabled"   # 2.2 第 4 条: REQ22's entry gate reads both
    switches = [item for item in document["switches"] if set(item) & {"eth", "ib"}]
    for item in switches:
        if "eth" in item:
            item["eth"]["system"]["aaa"]["user"]["cumulus"]["hashed-password"] = "$6$fixture$safe-value"
        else:
            system = item["ib"]["system"]
            # A well-formed SHA-512 target hash, assembled so no hash literal sits in the source (public audit).
            system["aaa"] = {"user": {"admin": {"password": "$" + "6$PUBLICsalt$" + "A" * 86}}}
            # DNS names the project; NTP and the time zone fall back to the neutral defaults.
            system["dns"] = {"server": [DNS[name]]}
            system["ntp"] = {"server": []}
            system["date-time"] = {"timezone": ""}
    document["switches"] = switches
    (project / "01-global.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    lines = (EXAMPLE / "02-devices_config.csv.example").read_text(encoding="utf-8").splitlines()
    header = lines[0]
    oob = next(line for line in lines if line.startswith(OOB_LEAF + ",eth,"))
    first = next(line for line in lines if line.startswith(IB_FIRST + ",ib,"))
    second = first
    for old, new in ((IB_FIRST, IB_SECOND), ("203.0.113.21", "203.0.113.31"), ("203.0.113.22", "203.0.113.32"),
                     ("02:00:00:00:01:21", "02:00:00:00:01:31"), ("02:00:00:00:01:22", "02:00:00:00:01:32")):
        second = second.replace(old, new)
    (project / "02-devices_config.csv").write_text("\n".join((header, oob, first, second)) + "\n",
                                                   encoding="utf-8")
    if name == OTHER:
        # v3.1.1 AP-c: the project's own ib.csv, a subset of 02 with only the first IB leaf.
        (project / "ib.csv").write_text("\n".join((header, oob, first)) + "\n", encoding="utf-8")
    import openpyxl

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.append(["Name", "Port", "Name", "Port"])
    sheet.append([IB_FIRST, "eth0", OOB_LEAF, "swp1"])
    sheet.append([IB_SECOND, "eth0", OOB_LEAF, "swp2"])
    book.save(project / "Site P2P_v1.0.xlsx")   # the one workbook setup selects for p2p.xlsx
    for key, value in KEYS.get(name, {}).items():
        (project / key).write_text("" if value is None else ACTIVATE_WORKFLOW.public_key(*value),
                                   encoding="ascii")


class _Run:
    def __init__(self, cwd: Path, code, refusal, read: set[Path], installs: int) -> None:
        self.cwd, self.code, self.refusal, self.read, self.installs = cwd, code, refusal, read, installs
        logs = cwd / "xdr-initial-setup-logs"
        reports = sorted(logs.glob("initial-setup-report*.log"))
        self.report_path = reports[0] if len(reports) == 1 else None
        self.report = self.report_path.read_text(encoding="utf-8").splitlines() if self.report_path else []
        cache = logs / "initial-setup-targets.json"
        self.cache = json.loads(cache.read_text(encoding="utf-8")) if cache.is_file() else None
        self.snapshots = logs / "initial-setup-ethernet-snapshots"

    def value(self, prefix: str):
        values = [line[len(prefix):] for line in self.report if line.startswith(prefix)]
        return values[0] if len(values) == 1 else values

    def keys(self):
        return [(entry["name"], entry["fingerprint"]) for entry in self.cache["public_keys"]]


class InitialSetupProjectNamesWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global _HOOKED
        if not _HOOKED:
            sys.addaudithook(_record_open)
            _HOOKED = True
        directory = tempfile.TemporaryDirectory(prefix="initial-setup-project-names-")
        cls.addClassCleanup(directory.cleanup)
        cls.base = Path(directory.name).resolve()
        cls.space = space = ACTIVATE_WORKFLOW.Workspace(cls.base)
        names = (KEYLESS, *CACHED.values(), OTHER, ACTIVE)   # ACTIVE last: setup leaves it active
        for name in (KEYLESS, *CACHED.values()):
            space.make_project(name)
        for name in names:
            write_project(space.project(name), name)
        for name in names:
            result = space.setup(name, "-y")
            if result.returncode != 0:
                raise RuntimeError(f"fixture: setup {name} exited {result.returncode}:\n{result.stdout}")
        if space.pointer() != ACTIVE:
            raise RuntimeError("fixture: the last setup did not leave its project active")
        # A project without a usable key: the workstation setup always fills laptop.pub, so empty it again.
        (space.project(KEYLESS) / "laptop.pub").write_text("", encoding="ascii")
        (space.http / NEUTRAL).write_text(neutral_text(SCRIPT_NEUTRAL), encoding="utf-8")
        (space.project(ACTIVE) / NEUTRAL).write_text(neutral_text(ACTIVE_NEUTRAL), encoding="utf-8")
        cls.script_dir = space.http / TOOL_DIR
        cls.app = load_script("initial_setup_project_names_workflow", cls.script_dir / "initial-setup.py")
        cls.home = cls.base / "run-home"   # the runs' HOME: empty, not the operator's
        cls.home.mkdir()

    def project(self, name: str) -> Path:
        return self.space.project(name).resolve()

    def fresh_cwd(self) -> Path:
        directory = tempfile.TemporaryDirectory(prefix="cwd-", dir=self.base)
        self.addCleanup(directory.cleanup)
        return Path(directory.name).resolve()

    def run_main(self, cwd: Path, *options: str, plan: bool = True, mode: str = "management") -> _Run:
        """main() of the copied script in this process from cwd: never a device, a prompt or the real HOME."""
        global _RECORDED
        app = self.app
        real_popen = subprocess.Popen
        installs = []

        def keygen_only(argv, *args, **kwargs):
            # The cache generator validates each key with `ssh-keygen -l` (P1); nothing else may run.
            if [Path(str(argv[0])).name, *argv[1:]] != KEYGEN:
                raise AssertionError(f"fixture: unexpected external command {argv!r}")
            return real_popen(argv, *args, **kwargs)

        def forbidden(*args, **kwargs):
            raise AssertionError("fixture: no terminal, device session or wait in this run")

        def snapshot_unavailable(*args, **kwargs):
            raise app.SetupError(SNAPSHOT_FAILURE)

        def install(*args, **kwargs):
            installs.append(args)
            return real_install(*args, **kwargs)

        real_install = app.key_install_command
        argv = [str(self.script_dir / "initial-setup.py"), "--execution-mode", mode,
                *(("--plan",) if plan else ()), *options]
        home = self.home
        code = refusal = None
        previous = os.getcwd()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(mock.patch.object(Path, "home", return_value=home))
            stack.enter_context(mock.patch.object(app.subprocess, "Popen", new=keygen_only))
            for owner, name in ((app.pty, "fork"), (app.os, "execvp"), (app, "interactive_run"),
                                (app.getpass, "getpass"), (app.time, "sleep")):
                stack.enter_context(mock.patch.object(owner, name, new=forbidden))
            stack.enter_context(mock.patch.object(app, "key_install_command", new=install))
            # Read-only check: SSH replaced at the OOB Leaf; its key login answers, its snapshot does not.
            stack.enter_context(mock.patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(mock.patch.object(app, "collect_ethernet_interfaces", new=snapshot_unavailable))
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            recorded = []
            os.chdir(cwd)
            _RECORDED = recorded
            try:
                code = app.main()
            except app.SetupError as error:
                refusal = str(error)
            finally:
                _RECORDED = None
                os.chdir(previous)
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
                    app.REPORT_HANDLE = None
        read = {Path(os.path.realpath(os.path.join(cwd, path))) for path in recorded}
        return _Run(cwd, code, refusal, read, len(installs))

    def assert_outputs_under_cwd(self, run: _Run) -> None:
        self.assertIsNotNone(run.report_path, "表 8-1: the report is under the current directory")
        self.assertEqual(run.cwd / "xdr-initial-setup-logs", run.report_path.parent)
        self.assertIsNotNone(run.cache, "表 8-1: the target cache is under the current directory")
        self.assertTrue((run.snapshots / "spine-jump-routes.json").is_file(),
                        "表 8-1: the snapshots are under the current directory")

    def test_project_dir_reads_ib_csv_not_02(self):
        other = self.project(OTHER)
        self.assertTrue((other / "ib.csv").is_file() and not (other / "ib.csv").is_symlink())
        self.assertNotEqual((other / "02-devices_config.csv").read_bytes(), (other / "ib.csv").read_bytes())
        run = self.run_main(self.fresh_cwd(), "--project-dir", str(other))
        # O8, v3.1.1 AP-c: the project's own ib.csv, never 02-devices_config.csv.
        self.assertEqual(str(other / "ib.csv"), run.value("Input CSV: "))
        self.assertIsNone(run.refusal)
        self.assertEqual(0, run.code)
        self.assertEqual(str(other / "ib.csv"), run.cache["ib_csv"])
        self.assertEqual(sha256(other / "ib.csv"), run.cache["cache_authority"]["ib_csv_sha256"])
        self.assertEqual(1, run.cache["ib_candidate_count"])
        self.assertEqual([IB_FIRST], [target["ib"]["hostname"] for target in run.cache["targets"]])
        self.assertNotIn(other / "02-devices_config.csv", run.read)

    def test_project_dir_reads_the_projects_own_files(self):
        other, active = self.project(OTHER), self.project(ACTIVE)
        self.assertNotEqual(OTHER, self.space.pointer(), "fixture: P is not the active project")
        self.assertEqual(0, (other / "mgmt-server.pub").stat().st_size, "fixture: one empty *.pub")
        # setup made P's neutral file from infra/infra-neutral.conf (v3.1.2 WP-1); the fixture left it alone.
        infra = self.space.http / "infra/infra-neutral.conf"
        self.assertEqual(infra.read_bytes(), (other / NEUTRAL).read_bytes())
        cwd = self.fresh_cwd()
        run = self.run_main(cwd, "--project-dir", str(other), plan=False)
        self.assertEqual(str(other / "ib.csv"), run.value("Input CSV: "))
        self.assertEqual(str((other / "p2p.xlsx").resolve()), run.value("Input P2P: "))
        self.assertIsNone(run.refusal)
        self.assertIn("    ERROR: " + SNAPSHOT_FAILURE, run.report, "the read-only run reached the snapshots")
        self.assertEqual(str((other / "01-global.yaml").resolve()), run.cache["global"])
        self.assertEqual(sha256(other / "01-global.yaml"), run.cache["cache_authority"]["global_sha256"])
        expected = usable_keys(other)
        self.assertEqual(["laptop.pub", "operator-p.pub"], [name for name, _ in expected], "fixture: two usable")
        self.assertEqual(expected, sorted(run.keys()), "表 8-1: the non-empty *.pub at P's root")
        neutral = neutral_values(infra)
        self.assertEqual({"dns": [DNS[OTHER]], "ntp": [neutral["NTP"]], "timezone": neutral["TIMEZONE"]},
                         run.cache["services"], "表 8-1: P's global and P's neutral defaults")
        self.assertEqual(f"CSV and P2P from {other}; global, public keys and neutral defaults from {other}",
                         run.value("Input sources: "), ":913: one directory, nothing to report")
        foreign = sorted(str(path) for path in run.read
                         if path.is_relative_to(active) or path == (self.space.http / NEUTRAL).resolve())
        self.assertEqual([], foreign, ":891: the active project's files and the script's own inputs are not read")
        self.assert_outputs_under_cwd(run)
        self.assertEqual([], sorted(str(path) for path in other.rglob("initial-setup-*")),
                         "表 8-1: no output goes into the project")

    def test_project_dir_on_active_project_matches_bridge_reads(self):
        active = self.project(ACTIVE)
        bridged = self.run_main(self.script_dir)
        direct = self.run_main(self.fresh_cwd(), "--project-dir", str(active))
        self.assertIsNone(bridged.refusal)
        self.assertIsNone(direct.refusal, "表 8-1: --project-dir reads the active project's own files too")
        self.assertEqual(0, direct.code)
        global_hash = sha256(active / "01-global.yaml")
        self.assertEqual(global_hash, bridged.cache["cache_authority"]["global_sha256"])
        self.assertEqual(global_hash, direct.cache["cache_authority"]["global_sha256"])
        expected = usable_keys(active)
        self.assertEqual(["laptop.pub", "mgmt-server.pub"], [name for name, _ in expected], "fixture: two usable")
        self.assertEqual(expected, sorted(bridged.keys()))
        self.assertEqual(sorted(bridged.keys()), sorted(direct.keys()))

    def test_project_dir_without_public_keys_warns_and_installs_none(self):
        keyless = self.project(KEYLESS)
        keys = sorted(keyless.glob("*.pub"))
        self.assertTrue(keys, "fixture: setup copied the template's *.pub placeholders")
        self.assertEqual([0] * len(keys), [path.stat().st_size for path in keys], "fixture: all empty")
        run = self.run_main(self.fresh_cwd(), "--project-dir", str(keyless))
        self.assertIsNone(run.refusal, "表 8-1 公钥 row and v15 :5548-5549: no usable key is not a refusal")
        self.assertEqual(0, run.code)
        self.assertEqual(str((keyless / "ib.csv").resolve()), run.value("Input CSV: "))
        self.assertIn(WARNING, run.report)
        self.assertEqual([], run.cache["public_keys"])
        self.assertEqual(0, run.installs, "no public-key installation is built")

    def assert_cache_follows_project_keys(self, mode: str) -> None:
        """Same cwd, --project-dir P three times: generated, reused, then regenerated after a newer root key."""
        project = self.project(CACHED[mode])
        cwd = self.fresh_cwd()
        cache = cwd / "xdr-initial-setup-logs" / "initial-setup-targets.json"
        runs = []

        def run_once() -> _Run:
            report = cwd / f"report-{len(runs) + 1}.log"   # explicit, so every run keeps its own report
            run = self.run_main(cwd, "--project-dir", str(project), "--report", str(report), mode=mode)
            self.assertIsNone(run.refusal)
            self.assertEqual(0, run.code)
            runs.append([line for line in report.read_text(encoding="utf-8").splitlines()
                         if line.startswith("Target cache: ")])
            return run

        first = run_once()
        self.assertEqual(usable_keys(project), sorted(first.keys()))
        self.assertEqual(2, len(first.keys()), "fixture: laptop.pub and mgmt-server.pub")
        run_once()
        added = project / "operator-new.pub"
        added.write_text(ACTIVATE_WORKFLOW.public_key(67, "PUBLIC-new-operator"), encoding="ascii")
        newer = cache.stat().st_mtime_ns + 1_000_000_000
        os.utime(added, ns=(newer, newer))
        third = run_once()
        self.assertEqual([[f"Target cache: generated {cache}"], [f"Target cache: reused {cache}"],
                          [f"Target cache: generated {cache}"]], runs,
                         "README cache contract with :926: reused while P is unchanged, regenerated after a newer key")
        self.assertEqual(usable_keys(project), sorted(third.keys()))
        self.assertIn("operator-new.pub", [name for name, _ in third.keys()])

    def test_project_dir_cache_is_reused_until_a_project_key_changes(self):
        self.assert_cache_follows_project_keys("management")

    def test_project_dir_cache_on_an_oob_leaf_in_auto_mode_follows_project_keys(self):
        # Auto mode on the OOB Leaf itself: its cache reuse never re-reads the keys with validation, so only
        # load_target_cache's own check of the project-root key directory notices the newer key.
        app = self.app
        with mock.patch.object(app.socket, "gethostname", return_value=OOB_LEAF), \
                mock.patch.object(app.socket, "getfqdn", return_value=OOB_LEAF):
            self.assert_cache_follows_project_keys("auto")

    def test_default_bases_without_project_dir(self):
        other, active = self.project(OTHER), self.project(ACTIVE)
        cwd = self.fresh_cwd()
        shutil.copyfile(other / "ib.csv", cwd / "ib.csv")
        shutil.copyfile(other / "p2p.xlsx", cwd / "p2p.xlsx")
        run = self.run_main(cwd, plan=False)
        self.assertIsNone(run.refusal, ":913: different directories are reported, not refused")
        self.assertEqual(str(cwd / "ib.csv"), run.value("Input CSV: "))
        self.assertEqual(str(cwd / "p2p.xlsx"), run.value("Input P2P: "))
        self.assertIn("    ERROR: " + SNAPSHOT_FAILURE, run.report, "the read-only run reached the snapshots")
        self.assert_outputs_under_cwd(run)
        # The script's directory: its bridges reach the active project; its own neutral file stays its own.
        self.assertEqual(str((active / "01-global.yaml").resolve()), run.cache["global"])
        self.assertEqual({"dns": [DNS[ACTIVE]], "ntp": [SCRIPT_NEUTRAL["NTP"]],
                          "timezone": SCRIPT_NEUTRAL["TIMEZONE"]}, run.cache["services"])
        self.assertEqual(usable_keys(active), sorted(run.keys()))
        sources = [index for index, line in enumerate(run.report) if line.startswith("Input sources: ")]
        self.assertEqual(1, len(sources), ":913: one input-sources line")
        line = run.report[sources[0]]
        self.assertIn(f"CSV and P2P from {cwd};", line)
        self.assertIn(f"global, public keys and neutral defaults from {self.script_dir}", line)
        self.assertIn("different directories", line, ":913: the difference is reported")
        cache_line = next(index for index, line in enumerate(run.report) if line.startswith("Target cache: "))
        self.assertLess(sources[0], cache_line, ":913: at the start of the report")


if __name__ == "__main__":
    unittest.main()
