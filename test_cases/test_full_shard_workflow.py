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


@contextlib.contextmanager
def record(case):
    started = time.time()
    yield
    path = os.environ.get("SHARD_FIXTURE_MARKERS")
    if path:
        line = json.dumps({"id": case.id(), "cwd": os.getcwd(), "pid": os.getpid(),
                           "start": started, "end": time.time()}) + "\\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)
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

    def test_a2(self):
        with probe.record(self):
            if probe.mode() == "fail":
                self.fail("fixture failure requested")
'''

BETA_SOURCE = '''"""Fixture beta: split into two contiguous case slices."""
import unittest

from test_cases import fixture_probe as probe


class BetaTests(unittest.TestCase):
    def test_b1(self):
        with probe.record(self):
            pass

    def test_b2(self):
        with probe.record(self):
            pass

    def test_b3(self):
        with probe.record(self):
            pass

    def test_b4(self):
        with probe.record(self):
            pass
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


def fixture_plan(*, delta_lane="w0", same_lane=True):
    phase_a = [
        {"lane": "w0", "units": [ALPHA] + ([DELTA] if delta_lane == "w0" else [])},
        {"lane": "w1", "units": [f"{BETA}#0/2"] + ([DELTA] if delta_lane == "w1" else [])},
        {"lane": "w2", "units": [f"{BETA}#1/2"]},
    ]
    return {
        "schema_version": 1,
        "description": "fixture plan for the sharded full workflow",
        "derivation": {"status": "fixture"},
        "lane_deadline_seconds": 7800,
        "phase_a": phase_a,
        "phase_b": {"lane": "wq", "units": [D2_UNIT, GAMMA]},
        "slices": {BETA: [f"{BETA}.BetaTests.test_b3"]},
        "same_lane": [[ALPHA, DELTA]] if same_lane else [],
        "phase_b_reasons": {GAMMA: "fixture quiet module", D2_UNIT: "fixture quiet case"},
    }


class ShardFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="shard-wf-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
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

    def build(self, *, plan=None, extra_epsilon=False):
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

    def next_paths(self):
        self.counter += 1
        return (self.base / f"evidence-{self.counter}",
                self.base / f"markers-{self.counter}.jsonl")

    def run_in_process(self, mode=""):
        evidence, markers = self.next_paths()
        environment = {"SHARD_FIXTURE_MODE": mode, "SHARD_FIXTURE_MARKERS": str(markers),
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(tempfile, "tempdir", str(self.lane_tmp_parent)), \
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

    def test_w2_failing_case_blocks_the_proof_and_the_quiet_phase(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        markers = self.assert_failed(self.run_in_process("fail"), "non-success")
        ids = {item["id"] for item in markers}
        self.assertIn(f"{ALPHA}.AlphaTests.test_a1", ids)
        self.assertNotIn(f"{ALPHA}.AlphaTests.test_a2", ids)
        self.assertFalse({i for i in ids if EXPECTED_LANES.get(i) == "wq"})

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

    def test_w2_untracked_ignored_and_tmpdir_leftovers_fail_closed(self):
        self.build()
        if not SHARDED_PLATFORM:
            self.assert_platform_refusal()
            return
        for mode, keyword in (("untracked", "untracked"), ("ignored", "ignored"), ("tmpdir", "TMPDIR")):
            with self.subTest(mode=mode):
                self.assert_failed(self.run_in_process(mode), keyword)

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


if __name__ == "__main__":
    unittest.main()
