"""Workflow: the root parents start the real cron.sh with the root-parent marker (v3.1.2 WP-11, M6, I-006).

The real monitor/switch-collection-worker.py (run_collection_slots) and DAY0-Prepare/12-ztp-monitor.py
(run_completion_handoff) start a staged copy of the real ethernet/monitor/cron.sh, which asks the real
tools/operator_identity.py who the operator is.  Expectations:
- v3.1.2 guide 3.1 已定 2 (owner 2026-11-07「同意你的建议。」, http dev 转述, 落地记录.md:1612): the worker and
  12-ztp-monitor set the 「由 root 父进程启动」 marker when they start cron.sh, and a cron.sh carrying it is not
  re-run as the operator, even when root's sudo variables are inherited (a `sudo 11-load.py` passes them on);
- guide WP-11 step 3: the three descriptors the worker hands over (--preheld-lock-fd, --worker-context-fd,
  --emit-target-plan-fd) do not pass through runuser on this path and still reach cron.sh;
- 问题文档 I-029 (:1319) implies that before K4 the worker's cron.sh runs as root.

The euid cron.sh sees is played by an `id -u` recorder on its pinned PATH (guide 2.2 item 6: no real uid switch);
the recorder also notes whether the marker reached cron.sh's environment.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT / "monitor"), str(ROOT / "tools")):
    if path not in sys.path:
        sys.path.insert(0, path)

from operator_identity import ROOT_PARENT_MARKER, ROOT_PARENT_MARKER_VALUE  # noqa: E402
from test_cases import test_cron_operator_identity as direct  # noqa: E402


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


WORKER = load("cron_operator_identity_workflow_worker", ROOT / "monitor/switch-collection-worker.py")
MONITOR = load("cron_operator_identity_workflow_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")


def cycle_identity(scope: str) -> dict:
    body = {
        "project_key": hashlib.sha256(b"/project-fixture").hexdigest(),
        "run_token": "12345678123442348123456789abcdef",
        "scope": scope,
        "sequence": 7,
        "source": "switch_collection",
    }
    body["cycle_id"] = hashlib.sha256(json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return body


class CronRootParentMarkerWorkflowTests(unittest.TestCase):
    def stage(self) -> Path:
        directory = tempfile.TemporaryDirectory(prefix="cron-marker-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        direct.stage_tree(root, pointer=True)
        (root / "nvlink/monitor").mkdir(parents=True)
        (root / "nvlink/monitor/cron.sh").symlink_to("../../ethernet/monitor/cron.sh")
        (root / "ethernet/monitor/eth.csv").unlink()   # only the IB lane has an inventory
        return root

    def root_parent_environment(self, root: Path):
        """A root parent whose own environment came from `sudo 11-load.py`: euid 0 and the sudo variables."""
        environment = direct.fixture_environment(root, FAKE_EUID="0", SUDO_USER=direct.ME.pw_name,
                                                 SUDO_UID=str(direct.ME.pw_uid))
        environment.pop(ROOT_PARENT_MARKER, None)
        return mock.patch.dict(os.environ, environment, clear=True)

    def run_worker(self, root: Path) -> tuple[dict, list]:
        scope_identity = cycle_identity("prod")
        cycle = root / "cycle"
        bindings = {"infiniband/prod": {
            "evidence": str(cycle / "infiniband-prod/evidence-manifest.json"),
            "envelope": str(cycle / "infiniband-prod/identity-envelope.json"),
            "input_inventory": str(cycle / "inputs/infiniband-prod.csv"),
        }}
        observed = []
        original = WORKER.run_interruptible

        def observe(command, cwd, timeout, **kwargs):
            result = original(command, cwd, timeout, **kwargs)
            observed.append({"command": command, "pass_fds": kwargs.get("pass_fds", ()), "result": result[0]})
            return result

        scripts = {area: root / area / "monitor/cron.sh" for area in ("ethernet", "infiniband", "nvlink")}
        with self.root_parent_environment(root), \
                mock.patch.object(WORKER, "SCRIPTS", scripts), \
                mock.patch.object(WORKER, "HTML_SCRIPT", root / "monitor/generate-monitor-html.py"), \
                mock.patch.object(WORKER, "run_interruptible", side_effect=observe):
            result = WORKER.run_collection_slots(scope_identity, artifact_bindings=bindings, timeout=120,
                                                 lock_wait=0)
        return result, observed

    def marker_seen(self, root: Path) -> list:
        path = root / "logs/id.log"
        return [] if not path.exists() else [line.split("\t") for line in path.read_text().splitlines()]

    def test_worker_spawned_cron_sh_carries_root_parent_marker(self):
        root = self.stage()
        _result, observed = self.run_worker(root)
        # ethernet/prod and nvlink/prod (no inventory: one direct run each), infiniband/prod (plan, then collect)
        self.assertEqual(4, len(observed))
        seen = self.marker_seen(root)
        self.assertEqual(4, len(seen), observed)
        self.assertEqual([[ROOT_PARENT_MARKER_VALUE, direct.ME.pw_name]] * 4, seen)
        # 已定 2: with the marker the inherited sudo variables do not re-run it as the operator
        self.assertEqual([], direct.records(root, "runuser.jsonl"))

    def test_ztp_monitor_completion_collection_carries_marker(self):
        root = self.stage()
        scripts = {area: root / area / "monitor/cron.sh" for area in ("ethernet", "infiniband", "nvlink")}
        with self.root_parent_environment(root), \
                mock.patch.object(MONITOR, "COLLECTOR_SCRIPTS", scripts), \
                mock.patch.object(MONITOR, "generate_monitor_html", return_value=True):
            MONITOR.run_completion_handoff({"devices": [{"type": "ib"}]}, root / "unused-html", 120)
        self.assertEqual([[ROOT_PARENT_MARKER_VALUE, direct.ME.pw_name]], self.marker_seen(root))
        self.assertEqual([], direct.records(root, "runuser.jsonl"))
        # it ran on as root for the operator: the operator's key, and cron.sh refreshed the page itself
        self.assertEqual({direct.OPERATOR_KEY}, set(direct.identity_options(root)))
        self.assertEqual([["--type", "prod"]], direct.records(root, "generator.jsonl"))

    def test_worker_inherited_fds_still_reach_cron_sh(self):
        root = self.stage()
        result, observed = self.run_worker(root)
        phases = [item for item in observed if "infiniband" in item["command"][1]]
        plan = phases[0]
        self.assertEqual(3, len(plan["pass_fds"]))
        for flag in ("--worker-context-fd", "--emit-target-plan-fd", "--preheld-lock-fd"):
            self.assertIn(flag, plan["command"])
        # the planner wrote its plan through the inherited descriptors under its preheld lock
        self.assertEqual(0, plan["result"]["returncode"], plan["result"]["stderr"])
        self.assertTrue((root / "cycle/inputs/infiniband-prod.target-plan.json").is_file(), plan["result"])
        self.assertEqual(2, len(phases), "the worker went on from the plan to the collection")
        collect = phases[1]
        self.assertEqual(2, len(collect["pass_fds"]))
        self.assertNotIn("[A4] ERROR", collect["result"]["stderr"])
        self.assertNotIn("[A4] ERROR", collect["result"]["stdout"])
        outcome = next(item for item in result["outcomes"] if item["source_slot"] == "infiniband/prod")
        self.assertNotEqual("worker_error", outcome["outcome"])
        # both IB phases went through cron.sh's identity step as root with the marker, never through runuser
        self.assertEqual([[ROOT_PARENT_MARKER_VALUE, direct.ME.pw_name]] * 4, self.marker_seen(root))
        self.assertEqual([], direct.records(root, "runuser.jsonl"))


if __name__ == "__main__":
    unittest.main()
