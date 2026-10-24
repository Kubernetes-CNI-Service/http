#!/usr/bin/env python3
"""W1-W5: opt-in two-phase sharded full proof on a disposable fixture repository.

Each scenario builds a small Git repository with its own test modules, shard plan
and manifest, then runs the real runner: the copied CLI for the end-to-end proof
path and the imported module for in-process fault cells.  Faults are injected only
by the fixture's own test doubles (never by a runner hook).  Expectations follow
PROP-14 W1-W5 and the G5Q-RA landing form; none is derived from the runner.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "full_shard_workflow_runner", ROOT / "test_cases/run_related_tests.py",
)
RUNNER = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = RUNNER
_SPEC.loader.exec_module(RUNNER)
GIT = shutil.which("git", path=os.confstr("CS_PATH") or "/usr/bin:/bin")
# The first landing supports APFS clonefile checkouts on macOS only (design A.1).
SHARDED_PLATFORM = sys.platform == "darwin"

ALPHA = "test_cases.test_alpha"
BETA = "test_cases.test_beta"
DELTA = "test_cases.test_delta"
GAMMA = "test_cases.test_gamma"
EPSILON = "test_cases.test_epsilon"
D2_UNIT = f"{DELTA}::{DELTA}.DeltaTests.test_d2"
EXPECTED_LANES = {
    f"{ALPHA}.AlphaTests.test_a1": "w0",
    f"{ALPHA}.AlphaTests.test_a2": "w0",
    f"{DELTA}.DeltaTests.test_d1": "w0",
    f"{BETA}.BetaTests.test_b1": "w1",
    f"{BETA}.BetaTests.test_b2": "w1",
    f"{BETA}.BetaTests.test_b3": "w2",
    f"{BETA}.BetaTests.test_b4": "w2",
    f"{DELTA}.DeltaTests.test_d2": "wq",
    f"{GAMMA}.GammaTests.test_g1": "wq",
    f"{GAMMA}.GammaTests.test_g2": "wq",
}

PROBE = '''"""Fixture-only marker and mode helpers (not a test module)."""
import contextlib
import json
import os
import time


def mode():
    return os.environ.get("SHARD_FIXTURE_MODE", "")


def _append(value):
    path = os.environ.get("SHARD_FIXTURE_MARKERS")
    if path:
        line = json.dumps(value) + "\\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)


@contextlib.contextmanager
def record(case):
    started = time.time()
    yield
    _append({"id": case.id(), "cwd": os.getcwd(), "pid": os.getpid(),
             "start": started, "end": time.time()})


def note(case, data):
    _append(dict(data, note=case.id(), cwd=os.getcwd(), pid=os.getpid()))
'''

ALPHA_SOURCE = '''"""Fixture alpha: phase A, declared same lane as delta."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

from test_cases import fixture_probe as probe

SHARED = {"alpha_ran": False}


class AlphaTests(unittest.TestCase):
    def test_a1(self):
        with probe.record(self):
            SHARED["alpha_ran"] = True
            mode = probe.mode()
            if mode == "crash":
                os.kill(os.getpid(), signal.SIGKILL)
            if mode == "silent":
                os._exit(0)
            if mode == "untracked":
                Path("untracked-leftover.txt").write_text("left\\n", encoding="utf-8")
            if mode == "ignored":
                Path("ignored-out").mkdir(exist_ok=True)
                Path("ignored-out/left.txt").write_text("left\\n", encoding="utf-8")
            if mode == "ignored-source":
                Path("ignored-out").mkdir(exist_ok=True)
                Path("ignored-out/leak.py").write_text("LEAK = 1\\n", encoding="utf-8")
            if mode == "ignored-remove":
                Path("ignored-out/pre.txt").unlink()
            if mode == "tmpdir":
                Path(tempfile.gettempdir(), "left-in-lane-tmp.txt").write_text("left\\n", encoding="utf-8")
            if mode == "tracked":
                with open("README.txt", "a", encoding="utf-8") as handle:
                    handle.write("changed by a test\\n")
            if mode == "residue":
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(120)"],
                    start_new_session=True, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )

    @unittest.skipIf(probe.mode() == "skip", "fixture decorator skip")
    def test_a2(self):
        with probe.record(self):
            if probe.mode() == "fail":
                self.fail("fixture failure requested")
'''

BETA_SOURCE = '''"""Fixture beta: split into two contiguous case slices."""
import gc
from pathlib import Path
import tempfile
import unittest
import weakref

from test_cases import fixture_probe as probe

RELEASED = {}


class BetaTests(unittest.TestCase):
    # True only where TMPDIR is a lane's private directory below the fixture's lane-tmp
    # parent: a skip that the lane environment creates and the serial run would not.
    @unittest.skipIf(
        probe.mode() == "lane-skip" and Path(tempfile.gettempdir()).parent.name == "lane-tmp",
        "fixture skip that only a lane TMPDIR triggers",
    )
    def test_b1(self):
        with probe.record(self):
            pass

    def test_b2(self):
        with probe.record(self):
            pass

    def test_b3(self):
        with probe.record(self):
            if probe.mode() == "release":
                RELEASED["b3"] = weakref.ref(self)

    def test_b4(self):
        if probe.mode() == "skip":
            self.skipTest("fixture runtime skip")
        with probe.record(self):
            if probe.mode() == "release":
                gc.collect()
                reference = RELEASED.get("b3")
                alive = sorted(
                    item.id() for item in gc.get_objects()
                    if isinstance(item, unittest.TestCase)
                    and type(item).__module__.startswith("test_cases.test_")
                )
                probe.note(self, {
                    "b3_recorded": reference is not None,
                    "b3_alive": reference is not None and reference() is not None,
                    "alive": alive,
                })
'''

DELTA_SOURCE = '''"""Fixture delta: one case runs in phase A, one case is a quiet-phase unit."""
import unittest

from test_cases import fixture_probe as probe
from test_cases import test_alpha as ALPHA


class DeltaTests(unittest.TestCase):
    def test_d1(self):
        with probe.record(self):
            if probe.mode() == "order":
                self.assertTrue(ALPHA.SHARED["alpha_ran"], "delta depends on alpha in-process")

    def test_d2(self):
        with probe.record(self):
            pass
'''

GAMMA_SOURCE = '''"""Fixture gamma: a quiet-phase module."""
import unittest

from test_cases import fixture_probe as probe


class GammaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if probe.mode() == "skip":
            raise unittest.SkipTest("fixture holder skip")

    def test_g1(self):
        with probe.record(self):
            pass

    def test_g2(self):
        with probe.record(self):
            pass
'''

EPSILON_SOURCE = '''"""Fixture epsilon: a new module that no plan names."""
import unittest


class EpsilonTests(unittest.TestCase):
    def test_e1(self):
        pass
'''


MACHINE_SHARED_TEMPORARY_ROOTS = ("/tmp", "/var/tmp")


def _inside_machine_shared_temporary_root(path):
    real = os.path.realpath(path)
    for shared in MACHINE_SHARED_TEMPORARY_ROOTS:
        root = os.path.realpath(shared)
        if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
            return True
    return False


def _fixture_parent():
    """Where the disposable fixture lives.

    S0 (2026-10-24): a sharded run refuses lane roots below the machine-shared /tmp or
    /var/tmp.  The fixture keeps its default place unless the operator's TMPDIR is
    there; then (macOS only) it uses the per-user temporary directory instead, which
    the sharded mode accepts.  Under a sharded outer run TMPDIR is already outside.
    """
    if not SHARDED_PLATFORM or not _inside_machine_shared_temporary_root(tempfile.gettempdir()):
        return None
    completed = subprocess.run(
        ["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True,
    )
    return completed.stdout.strip() or None


def fixture_plan(*, delta_lane="w0", same_lane=True, runtime_skips=None, leftover_allowlist=None):
    phase_a = [
        {"lane": "w0", "units": [ALPHA] + ([DELTA] if delta_lane == "w0" else [])},
        {"lane": "w1", "units": [f"{BETA}#0/2"] + ([DELTA] if delta_lane == "w1" else [])},
        {"lane": "w2", "units": [f"{BETA}#1/2"]},
    ]
    plan = {
        "schema_version": 1,
        "description": "fixture plan for the sharded full workflow",
        "derivation": {"status": "fixture"},
        "lane_deadline_seconds": 9000,
        "phase_a": phase_a,
        "phase_b": {"lane": "wq", "units": [D2_UNIT, GAMMA]},
        "slices": {BETA: [f"{BETA}.BetaTests.test_b3"]},
        "same_lane": [[ALPHA, DELTA]] if same_lane else [],
        "phase_b_reasons": {GAMMA: "fixture quiet module", D2_UNIT: "fixture quiet case"},
    }
    if runtime_skips is not None:
        plan["runtime_skips"] = runtime_skips
    if leftover_allowlist is not None:
        plan["leftover_allowlist"] = leftover_allowlist
    return plan


class ShardFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shard-wf-", dir=_fixture_parent())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        # M1 (REVIEW-1): on BSD every directory created below inherits this group; give
        # the fixture root the user's primary gid so the runner's gid gate sees the same
        # state whatever group owns TMPDIR's parent (for example /private/tmp).
        os.chown(self.base, -1, os.getgid())
        self.root = self.base / "repository"
        self.root.mkdir()
        self.lane_tmp_parent = self.base / "lane-tmp"
        self.lane_tmp_parent.mkdir(mode=0o700)
        self.counter = 0
        self.git_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        self.addCleanup(self.reap_recorded_residue)
        self.audits = []

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))

    def git(self, *args):
        result = subprocess.run([GIT, *args], cwd=self.root, env=self.git_env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        return result.stdout

    def build(self, *, plan=None, extra_epsilon=False, pre_ignored=False):
        self.write("test_cases/__init__.py", "")
        for relative in ("tools/project_contract.py", "test_cases/run_related_tests.py",
                         "requirements-container-top-level.lock"):
            self.write(relative, (ROOT / relative).read_bytes())
        self.write("tools/sync-code.py", "ROOT_CODE_PATTERNS = ()\n"
                   "def matching_files(root, patterns): return ()\n")
        self.write("infra/docker/activate.py", "def image_source_paths(root): return ()\n")
        self.write("tools/_package_common.py", "def deployment_archive_source_paths(root): return ()\n")
        self.write("test_cases/fixture_probe.py", PROBE)
        modules = {ALPHA: ALPHA_SOURCE, BETA: BETA_SOURCE, DELTA: DELTA_SOURCE, GAMMA: GAMMA_SOURCE}
        if extra_epsilon:
            modules[EPSILON] = EPSILON_SOURCE
        for name, source in modules.items():
            self.write(name.replace(".", "/") + ".py", source)
        self.write("README.txt", "fixture\n")
        self.write(".gitignore", "ignored-out/\n__pycache__/\n")
        self.plan_bytes = (json.dumps(plan or fixture_plan(), indent=1) + "\n").encode("utf-8")
        self.write("test_cases/full_shard_plan.json", self.plan_bytes)
        scripts = {p: p for p in ("tools/project_contract.py", "tools/sync-code.py",
                                  "infra/docker/activate.py", "tools/_package_common.py")}
        support = ["test_cases/run_related_tests.py", "requirements-container-top-level.lock",
                   "test_cases/full_shard_plan.json"]
        manifest = {
            "schema_version": 1, "baseline_tests": [ALPHA], "scripts": scripts,
            "test_suites": [{"id": f"fixture-{index}", "description": name, "tests": [name]}
                            for index, name in enumerate(sorted(modules))],
            "test_rules": [{"id": "fixture-direct", "paths": list(scripts), "tests": [ALPHA]}],
            "workflows": [{"id": "fixture-workflow", "members": list(scripts), "tests": [ALPHA]}],
            "tracked_support": support,
            "path_rules": [{"paths": support, "full_suite": True}],
        }
        self.write("test_cases/script_test_manifest.json", json.dumps(manifest, indent=1))
        self.ledger = self.root / "test_cases/script_test_approved_hashes.json"
        manifest_path = self.root / "test_cases/script_test_manifest.json"
        checked = RUNNER.load_and_validate_manifest(self.root, manifest_path)
        RUNNER.atomic_write_approvals(
            self.ledger, RUNNER.make_snapshot(self.root, manifest_path, checked),
        )
        self.git("init", "--quiet")
        self.git("config", "user.name", "Shard Fixture")
        self.git("config", "user.email", "shard-fixture@example.invalid")
        self.git("config", "core.hooksPath", str(self.base / "no-hooks"))
        self.git("config", "commit.gpgsign", "false")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "independent shard fixture")
        if pre_ignored:
            # An ignored file the main checkout already holds (copied into every clone).
            self.write("ignored-out/pre.txt", "kept by the operator\n")

    def next_paths(self):
        self.counter += 1
        return (self.base / f"evidence-{self.counter}",
                self.base / f"markers-{self.counter}.jsonl")

    def run_in_process(self, mode="", *, temp_parent=None):
        evidence, markers = self.next_paths()
        environment = {"SHARD_FIXTURE_MODE": mode, "SHARD_FIXTURE_MARKERS": str(markers),
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(tempfile, "tempdir", str(temp_parent or self.lane_tmp_parent)), \
                redirect_stdout(out), redirect_stderr(err):
            code = RUNNER.run_sharded_selection(
                self.root, RUNNER.Selection(full_suite=True), False, evidence,
            )
        audit = json.loads((evidence / "audit.json").read_text(encoding="utf-8"))
        self.audits.append(audit)
        return code, evidence, self.markers(markers), audit, out.getvalue() + err.getvalue()

    def cli(self, *args, markers=None, mode=""):
        environment = dict(self.git_env)
        environment.update({"SHARD_FIXTURE_MODE": mode, "TMPDIR": str(self.lane_tmp_parent),
                            "PYTHONPYCACHEPREFIX": str(self.base / "operator-pyc")})
        if markers is not None:
            environment["SHARD_FIXTURE_MARKERS"] = str(markers)
        return subprocess.run(
            [sys.executable, "-B", "test_cases/run_related_tests.py", *args],
            cwd=self.root, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, timeout=600,
        )

    @staticmethod
    def markers(path):
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def reap_recorded_residue(self):
        for audit in self.audits:
            for item in audit.get("residue", []):
                try:
                    os.kill(int(item["pid"]), 9)
                except (ProcessLookupError, KeyError, ValueError, PermissionError):
                    pass

    def assert_platform_refusal(self):
        evidence, _markers = self.next_paths()
        with self.assertRaisesRegex(RUNNER.ImpactError, "--sharded is supported only on"):
            RUNNER.run_sharded_selection(self.root, RUNNER.Selection(full_suite=True), False, evidence)
        self.assertFalse(evidence.exists())

    def assert_failed(self, result, keyword):
        code, evidence, markers, audit, output = result
        self.assertEqual(1, code, output)
        self.assertEqual("failed", audit["status"])
        self.assertTrue(any(keyword in problem for problem in audit["problems"]), audit["problems"])
        self.assertTrue((evidence / "work").is_dir(), "failure evidence must be kept")
        return markers


class FullShardWorkflowTests(ShardFixture):
    def test_w1_each_canonical_case_runs_once_in_its_lane_and_quiet_phase_runs_alone(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, evidence, markers, audit, output = self.run_in_process()
        self.assertEqual(0, code, output)
        self.assertEqual("passed", audit["status"])
        self.assertEqual(sorted(EXPECTED_LANES), sorted(item["id"] for item in markers))
        self.assertEqual(
            EXPECTED_LANES, {item["id"]: Path(item["cwd"]).name for item in markers},
        )
        quiet = [item for item in markers if EXPECTED_LANES[item["id"]] == "wq"]
        parallel = [item for item in markers if EXPECTED_LANES[item["id"]] != "wq"]
        self.assertGreaterEqual(min(item["start"] for item in quiet), max(item["end"] for item in parallel))
        self.assertEqual(1, len({item["pid"] for item in quiet}))
        self.assertEqual(10, audit["canonical_count"])
        self.assertEqual(hashlib.sha256(self.plan_bytes).hexdigest(), audit["plan_sha256"])
        self.assertEqual("B", audit["lanes"]["wq"]["phase"])
        self.assertEqual({"A"}, {audit["lanes"][lane]["phase"] for lane in ("w0", "w1", "w2")})
        self.assertFalse((evidence / "work").exists(), "clones must be removed before approval")
        for lane in audit["lanes"].values():
            self.assertFalse(Path(lane["tmpdir"]).exists())
            self.assertFalse(Path(lane["pycache"]).exists())
            self.assertTrue(Path(lane["log"]).is_file())
        self.assertEqual([], audit["problems"])

    def test_w1_cli_sharded_proof_is_the_serial_attestation_and_passes_require_full(self):
        self.build()
        evidence, markers = self.next_paths()
        result = self.cli("--all", "--sharded", str(evidence), "-v", markers=markers)
        if not SHARDED_PLATFORM:
            self.assertEqual(2, result.returncode)
            self.assertIn("--sharded is supported only on", result.stderr)
            return
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        sharded = json.loads(self.ledger.read_text(encoding="utf-8"))
        self.assertIn("full_suite_attestation", sharded)
        self.assertNotIn("sharded", json.dumps(sharded["full_suite_attestation"]))
        check = self.cli("--check", "--require-full")
        self.assertEqual(0, check.returncode, check.stdout + check.stderr)
        serial_ledger = self.base / "serial-approvals.json"
        serial = self.cli("--approvals", str(serial_ledger), "--all", "-v")
        self.assertEqual(0, serial.returncode, serial.stdout + serial.stderr)
        self.assertEqual(
            json.loads(serial_ledger.read_text(encoding="utf-8"))["full_suite_attestation"],
            sharded["full_suite_attestation"],
        )
        audit = json.loads((evidence / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual("passed", audit["status"])
        self.assertFalse(str(evidence).startswith(str(self.root)))

    def test_w2_failing_case_blocks_the_proof_but_the_quiet_phase_still_runs(self):
        # S0 (2026-10-24): serial --all keeps running after a failing test.  A phase A
        # whose only problems are test outcomes is not an isolation problem, so the quiet
        # phase still runs alone after it; the run still fails and issues no proof.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("fail")
        markers = self.assert_failed(result, "non-success")
        audit = result[3]
        ids = {item["id"] for item in markers}
        self.assertIn(f"{ALPHA}.AlphaTests.test_a1", ids)
        self.assertNotIn(f"{ALPHA}.AlphaTests.test_a2", ids)
        quiet = [item for item in markers if EXPECTED_LANES.get(item["id"]) == "wq"]
        parallel = [item for item in markers if EXPECTED_LANES.get(item["id"]) != "wq"]
        self.assertEqual(
            sorted(test_id for test_id, lane in EXPECTED_LANES.items() if lane == "wq"),
            sorted(item["id"] for item in quiet),
        )
        self.assertGreaterEqual(min(item["start"] for item in quiet), max(item["end"] for item in parallel))
        self.assertFalse(audit["phase_b_skipped"])
        self.assertEqual([], audit["gate_problems"])
        self.assertEqual(0, audit["lanes"]["wq"]["exit"])
        self.assertEqual(
            [f"{ALPHA}.AlphaTests.test_a2"], [item["id"] for item in audit["non_success"]],
        )

    def test_w2_isolation_problem_in_phase_a_still_skips_the_quiet_phase(self):
        # A crash, a tracked-byte change or an untracked (non-ignored) leftover is an
        # isolation or equivalence problem: phase B does not run after it.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        for mode, keyword in (("crash", "no finished record"), ("tracked", "tracked"),
                              ("untracked", "untracked")):
            with self.subTest(mode=mode):
                result = self.run_in_process(mode)
                markers = self.assert_failed(result, keyword)
                audit = result[3]
                self.assertTrue(audit["phase_b_skipped"])
                self.assertTrue(
                    any(keyword in problem for problem in audit["gate_problems"]), audit["gate_problems"],
                )
                self.assertFalse({item["id"] for item in markers if EXPECTED_LANES.get(item["id"]) == "wq"})

    def test_w2_cli_failure_leaves_the_ledger_and_require_full_unchanged(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        before = self.ledger.read_bytes()
        evidence, markers = self.next_paths()
        result = self.cli("--all", "--sharded", str(evidence), markers=markers, mode="fail")
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertEqual(before, self.ledger.read_bytes())
        self.assertEqual(5, self.cli("--check", "--require-full").returncode)

    def test_w2_lane_crash_fails_closed(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        markers = self.assert_failed(self.run_in_process("crash"), "no finished record")
        self.assertFalse({i["id"] for i in markers if EXPECTED_LANES.get(i["id"]) == "wq"})

    def test_w2_lane_exit_before_finished_fails_closed(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        self.assert_failed(self.run_in_process("silent"), "no finished record")

    def test_w2_tracked_byte_change_fails_closed(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        self.assert_failed(self.run_in_process("tracked"), "tracked")

    def assert_leftover_audited_and_removed(self, result, kind, path):
        code, evidence, _markers, audit, output = result
        self.assertEqual(0, code, output)
        self.assertEqual("passed", audit["status"])
        self.assertEqual([], audit["problems"])
        self.assertEqual(
            {"paths": [path], "count": 1, "sha256": hashlib.sha256(path.encode("utf-8")).hexdigest()},
            audit["lanes"]["w0"]["leftovers"][kind],
        )
        for lane in ("w1", "w2", "wq"):
            self.assertNotIn(path, audit["lanes"][lane]["leftovers"][kind]["paths"])
        self.assertFalse((evidence / "work").exists(), "lane checkouts are removed at cleanup")
        self.assertFalse(Path(audit["lanes"]["w0"]["tmpdir"]).exists(), "lane TMPDIR is removed")

    def test_w2_reviewed_ignored_leftover_is_audited_and_removed_not_blocking(self):
        # S0 (2026-10-24): serial --all leaves ignored files in its checkout and never
        # checks them, but every later serial test can see them, while a lane's stay in
        # that lane.  An ignored leftover whose shape the plan reviewed as unobservable by
        # other tests (leftover_allowlist) is listed, counted and hashed in the audit,
        # removed with the lane at cleanup, and does not block.
        self.build(plan=fixture_plan(leftover_allowlist={
            "ignored-out/left.txt": "fixture-reviewed: no other fixture test reads it",
        }))
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("ignored")
        self.assert_leftover_audited_and_removed(result, "ignored", "ignored-out/left.txt")
        self.assertEqual(0, result[3]["lanes"]["w0"]["leftovers"]["unreviewed"]["count"])

    def test_w2_tmpdir_leftover_is_audited_and_removed_not_blocking(self):
        # A lane TMPDIR is private to the lane; serial --all leaves its TMPDIR entries
        # unchecked and no test of the suite lists or globs a temporary root (census).
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        self.assert_leftover_audited_and_removed(self.run_in_process("tmpdir"), "tmpdir", "left-in-lane-tmp.txt")

    def assert_unreviewed_ignored_change(self, result, path):
        markers = self.assert_failed(result, "leftover_allowlist")
        audit = result[3]
        self.assertTrue(
            any("leftover_allowlist" in problem and path in problem for problem in audit["problems"]),
            audit["problems"],
        )
        # It refuses the proof but is not an isolation gate: the quiet phase still runs.
        self.assertEqual([], audit["gate_problems"])
        self.assertFalse(audit["phase_b_skipped"])
        self.assertEqual(
            sorted(test_id for test_id, lane in EXPECTED_LANES.items() if lane == "wq"),
            sorted(item["id"] for item in markers if EXPECTED_LANES.get(item["id"]) == "wq"),
        )
        self.assertIn(path, audit["lanes"]["w0"]["leftovers"]["unreviewed"]["paths"])

    def test_w2_unreviewed_new_ignored_leftover_refuses_the_proof_but_not_the_quiet_phase(self):
        # S0 review A1: serial shows an ignored leftover to every later test (S0/armG: the
        # download-parent-red fixture trees' *.py are parsed by the quiesce workflow, which
        # fails serially but passed in another lane).  Without a reviewed shape the proof
        # is refused; it is not an isolation gate.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        self.assert_unreviewed_ignored_change(self.run_in_process("ignored"), "ignored-out/left.txt")

    def test_w2_unreviewed_removal_of_an_existing_ignored_file_refuses_the_proof(self):
        # Removing an ignored file the checkout already held hides it from later serial
        # tests only; other lanes still see it.  Unreviewed, it refuses the proof.
        self.build(pre_ignored=True)
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("ignored-remove")
        self.assert_unreviewed_ignored_change(result, "ignored-out/pre.txt")
        self.assertIn("ignored-out/pre.txt", result[3]["lanes"]["w0"]["leftovers"]["ignored_removed"]["paths"])

    def test_w2_ignored_file_inside_the_serial_snapshot_fails_closed(self):
        # Serial --all re-reads its source/test snapshot after the run and refuses approval
        # when it changed; an ignored *.py on a production path is part of that snapshot.
        # A lane checkout keeps that same predicate, so this ignored leftover still blocks.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("ignored-source")
        self.assert_failed(result, "snapshot")
        audit = result[3]
        self.assertTrue(
            any("snapshot" in problem and "ignored-out/leak.py" in problem for problem in audit["gate_problems"]),
            audit["gate_problems"],
        )
        self.assertTrue(audit["phase_b_skipped"])
        serial_ledger = self.base / "serial-ignored-source.json"
        serial = self.cli("--approvals", str(serial_ledger), "--all", mode="ignored-source")
        self.assertNotEqual(0, serial.returncode, serial.stdout + serial.stderr)
        self.assertFalse(serial_ledger.exists())

    def test_w2_lane_roots_inside_the_machine_shared_tmp_are_refused_before_any_lane(self):
        # S0 root cause: lane TMPDIRs below /private/tmp share an ancestor that the suite's
        # own tests write into while other lanes pin the stat of every ancestor.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        shared = Path(tempfile.mkdtemp(prefix="shard-wf-shared-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, shared, True)
        os.chown(shared, -1, os.getgid())
        code, _evidence, markers, audit, output = self.run_in_process(temp_parent=shared)
        self.assertEqual(1, code, output)
        self.assertEqual([], markers)
        self.assertTrue(
            any("machine-shared temporary directory" in problem for problem in audit["problems"]),
            audit["problems"],
        )
        self.assertEqual([], os.listdir(shared))

    def test_w1_audit_records_lane_wall_clock_and_ancestor_drift(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, _evidence, _markers, audit, output = self.run_in_process()
        self.assertEqual(0, code, output)
        self.assertEqual("http-full-shard-audit/2", audit["schema"])
        self.assertEqual([], audit["gate_problems"])
        for name in ("w0", "w1", "w2", "wq"):
            lane = audit["lanes"][name]
            with self.subTest(lane=name):
                for key in ("started_epoch", "lane_tests_started_epoch", "lane_finished_epoch",
                            "ended_epoch", "wall_seconds", "prepare_seconds", "gate_seconds"):
                    self.assertIsInstance(lane[key], (int, float), key)
                self.assertLessEqual(lane["started_epoch"], lane["lane_tests_started_epoch"])
                self.assertLessEqual(lane["lane_tests_started_epoch"], lane["lane_finished_epoch"])
                self.assertLessEqual(lane["lane_finished_epoch"], lane["ended_epoch"])
                self.assertEqual(lane["seconds"], lane["wall_seconds"])
                self.assertGreaterEqual(lane["prepare_seconds"], 0)
                self.assertGreaterEqual(lane["gate_seconds"], 0)
        for label, names in (("a", ("w0", "w1", "w2")), ("b", ("wq",))):
            self.assertLessEqual(
                audit[f"phase_{label}_started_epoch"], min(audit["lanes"][n]["started_epoch"] for n in names),
            )
            self.assertGreaterEqual(
                audit[f"phase_{label}_ended_epoch"], max(audit["lanes"][n]["ended_epoch"] for n in names),
            )
        self.assertLessEqual(audit["phase_a_ended_epoch"], audit["phase_b_started_epoch"])
        self.assertIsInstance(audit["enumeration"]["prepare_seconds"], (int, float))
        for phase in ("A", "B"):
            self.assertEqual({"temp_parent", "work"}, set(audit["chain_drift"][phase]))
            for drift in audit["chain_drift"][phase].values():
                self.assertIsInstance(drift, list)

    def test_w2_detached_residual_process_fails_closed_and_is_reaped(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("residue")
        self.assert_failed(result, "residual")
        audit = result[3]
        self.assertTrue(audit["residue"])
        deadline = time.monotonic() + 15
        alive = [int(item["pid"]) for item in audit["residue"]]
        while alive and time.monotonic() < deadline:
            still = []
            for pid in alive:
                try:
                    os.kill(pid, 0)
                    still.append(pid)
                except ProcessLookupError:
                    pass
            alive = still
            time.sleep(0.1)
        self.assertEqual([], alive)

    def test_w2_dirty_main_checkout_refuses_before_any_lane_runs(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        self.write("README.txt", "uncommitted change\n")
        code, _evidence, markers, audit, output = self.run_in_process()
        self.assertEqual(1, code, output)
        self.assertEqual([], markers)
        self.assertTrue(any("checkout" in problem for problem in audit["problems"]), audit["problems"])

    def test_d14a_new_module_without_plan_assignment_refuses_before_lanes(self):
        self.build(extra_epsilon=True)
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, _evidence, markers, audit, output = self.run_in_process()
        self.assertEqual(1, code, output)
        self.assertEqual([], markers)
        self.assertTrue(
            any(f"unassigned canonical modules: {EPSILON}" in problem for problem in audit["problems"]),
            audit["problems"],
        )

    def test_w3_hidden_cross_lane_order_dependency_is_reported_not_hidden(self):
        self.build(plan=fixture_plan(delta_lane="w1", same_lane=False))
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, _evidence, _markers, audit, output = self.run_in_process("order")
        self.assertEqual(1, code, output)
        self.assertIn(f"{DELTA}.DeltaTests.test_d1", {item["id"] for item in audit["non_success"]})

    def test_w5_declared_shared_resource_split_across_lanes_is_refused(self):
        self.build(plan=fixture_plan(delta_lane="w1", same_lane=True))
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, _evidence, markers, audit, output = self.run_in_process()
        self.assertEqual(1, code, output)
        self.assertEqual([], markers)
        self.assertTrue(any("same_lane" in problem for problem in audit["problems"]), audit["problems"])

    def test_m3_lane_releases_each_test_after_it_runs_and_keeps_no_unselected_test(self):
        # M3 (REVIEW-1): serial TestSuite.run drops each test once it has run; a lane
        # must do the same and must not keep the instances of the tests it does not run.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, _evidence, markers, _audit, output = self.run_in_process("release")
        self.assertEqual(0, code, output)
        b4 = f"{BETA}.BetaTests.test_b4"
        notes = [item for item in markers if item.get("note") == b4]
        self.assertEqual(1, len(notes), markers)
        self.assertEqual("w2", Path(notes[0]["cwd"]).name)
        self.assertTrue(notes[0]["b3_recorded"], notes[0])
        self.assertFalse(notes[0]["b3_alive"], notes[0])
        self.assertEqual([b4], notes[0]["alive"])

    def test_m2_skip_entries_are_audited_per_lane_and_bounded_by_the_plan(self):
        # M2: decorator skips are expected from the enumeration; the runtime skip and the
        # class fixture holder skip are allowed by the plan with their exact reasons.
        a2 = f"{ALPHA}.AlphaTests.test_a2"
        b4 = f"{BETA}.BetaTests.test_b4"
        holder = f"setUpClass ({GAMMA}.GammaTests)"
        self.build(plan=fixture_plan(runtime_skips={
            b4: "fixture runtime skip", holder: "fixture holder skip",
        }))
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        code, _evidence, _markers, audit, output = self.run_in_process("skip")
        self.assertEqual(0, code, output)
        self.assertEqual([], audit["problems"])
        self.assertEqual([{"id": a2, "reason": "fixture decorator skip"}], audit["decorator_skips"])
        self.assertEqual([{"id": a2, "reason": "fixture decorator skip"}], audit["lanes"]["w0"]["skips"])
        self.assertEqual([], audit["lanes"]["w1"]["skips"])
        self.assertEqual([{"id": b4, "reason": "fixture runtime skip"}], audit["lanes"]["w2"]["skips"])
        self.assertEqual([{"id": holder, "reason": "fixture holder skip"}], audit["lanes"]["wq"]["skips"])
        self.assertEqual(
            [f"{GAMMA}.GammaTests.test_g1", f"{GAMMA}.GammaTests.test_g2"],
            audit["lanes"]["wq"]["suppressed_ids"],
        )

    def test_m2_runtime_or_holder_skip_outside_the_plan_fails_closed(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("skip")
        self.assert_failed(result, "unexpected skip")
        problems = "\n".join(result[3]["problems"])
        self.assertIn(f"{BETA}.BetaTests.test_b4", problems)
        self.assertIn(f"setUpClass ({GAMMA}.GammaTests)", problems)
        self.assertNotIn(f"{ALPHA}.AlphaTests.test_a2", problems)

    def test_m2_skip_that_only_the_lane_environment_triggers_fails_closed(self):
        # M2: lanes run with a private TMPDIR; a skip that depends on it is not a skip
        # the serial run would make and must not be accepted as coverage.
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        result = self.run_in_process("lane-skip")
        self.assert_failed(result, "unexpected skip")
        self.assertTrue(
            any(f"{BETA}.BetaTests.test_b1" in problem for problem in result[3]["problems"]),
            result[3]["problems"],
        )
        self.assertEqual([], result[3]["decorator_skips"])


if __name__ == "__main__":
    unittest.main()
