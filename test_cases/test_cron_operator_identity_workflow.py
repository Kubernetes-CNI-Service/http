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
- R-038 (owner「我觉得这种情况下应该自动用 sudo 命令来跑，需要密码的话就提示用户输入」, http dev 记录 :1944;
  v3.1.6 guide 8.24 workflow :2716): the operator's manual run of the real cron.sh hands the Ethernet step to sudo,
  and the real ethernet/monitor/post-collect.py then refreshes monitor.html with the real
  monitor/generate-monitor-html.py exactly once; while another process holds the generator's lock it waits and
  then finishes without a second page; when sudo is not passed the collection stays and the page is unchanged.

The euid cron.sh sees is played by an `id -u` recorder on its pinned PATH (guide 2.2 item 6: no real uid switch);
the recorder also notes whether the marker reached cron.sh's environment.  In the R-038 workflow the sudo recorder
lets the command run as the test user; the LLDP analyzer is the one stand-in on the page path (as in
test_collection_cycle_handoff_workflow): it publishes the report post-collect expects for the archive.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
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


# The LLDP analyzer stand-in: it publishes the report post-collect expects for this archive.
ANALYZER = '''import argparse, pathlib, re
parser = argparse.ArgumentParser()
for option in ("--archive", "--dot", "--output-dir"):
    parser.add_argument(option, required=True)
arguments = parser.parse_args()
stem = re.sub(r"\\.(?:tar\\.gz|tgz)$", "", pathlib.Path(arguments.archive).name)
(pathlib.Path(arguments.output_dir) / f"{stem}-ethernet-topology-validation.xlsx").write_bytes(b"fixture report\\n")
'''
PAGE_FILES = ("ethernet/monitor/post-collect.py", "monitor/generate-monitor-html.py", "monitor/dot_to_html.py",
              "ztp/dynamic_air_inventory.py", "ztp/config_sync_authority.py", "tools/device_identity.py")
PAGE_END = "=== generate-monitor-html end ==="


class CronOperatorSudoRefreshWorkflowTests(direct.CronIdentityCase):
    def stage_page(self) -> Path:
        """The staged tree with the real post-collect and page generator in place of their recorders."""
        root = self.stage()
        for relative in PAGE_FILES:
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, root / relative)
        analyzer = root / "tools/lldp-analyze-tool"
        (analyzer / "99-output-p2p").mkdir(parents=True)
        (analyzer / "analyze_lldp.py").write_text(ANALYZER, encoding="utf-8")
        (analyzer / "99-output-p2p/fixture-air.dot").write_text("digraph fixture {}\n", encoding="utf-8")
        return root

    def environment(self, root: Path, **extra: str) -> dict:
        return direct.fixture_environment(root, "ethernet", FAKE_EUID=str(direct.ME.pw_uid), **extra)

    @staticmethod
    def pages_built(root: Path) -> int:
        log = root / "monitor/generate-monitor.log"
        return log.read_text(encoding="utf-8").count(PAGE_END) if log.exists() else 0

    def assert_one_sudo_post_collect(self, root: Path, output: str) -> None:
        archives = sorted((root / "ethernet/monitor/eth-info").glob("*.tar.gz"))
        self.assertEqual(1, len(archives), output)
        self.assertEqual([["-n", "--", "python3", "-B", str(root / "ethernet/monitor/post-collect.py"),
                           "--archive", str(archives[0]), "--environment", "air"]],
                         direct.records(root, "sudo.jsonl"), output)

    def test_manual_operator_run_refreshes_the_page_once_through_sudo(self):
        root = self.stage_page()
        completed = self.run_cron(root, "--air", area="ethernet", FAKE_EUID=str(direct.ME.pw_uid),
                                  FAKE_SUDO="nopasswd")
        output = completed.stdout + completed.stderr
        self.assert_one_sudo_post_collect(root, output)
        self.assertTrue((root / "monitor/monitor.html").is_file(), output)
        self.assertEqual(1, self.pages_built(root), output)
        self.assertIn("closed loop complete", output)
        self.assertEqual(0, completed.returncode, output)

    def test_a_held_generation_lock_is_waited_for_and_the_page_built_once(self):
        root = self.stage_page()
        page = root / "monitor/monitor.html"
        reports = root / "tools/lldp-analyze-tool/99-output-p2p"
        lock = os.open(root / "monitor/.generate-monitor-html.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX)   # another process is building the page (generation_lock)
        with open(root / "logs/cron.out", "w", encoding="utf-8") as stream:
            process = subprocess.Popen(["bash", str(root / "ethernet/monitor/cron.sh"), "--air"], cwd=root,
                                       env=self.environment(root, FAKE_SUDO="nopasswd"), stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT)
        def stop():
            if process.poll() is None:
                process.kill()
                process.wait()
        self.addCleanup(stop)
        deadline = time.monotonic() + 120
        while not list(reports.glob("*-ethernet-topology-validation.xlsx")) and time.monotonic() < deadline:
            time.sleep(0.1)
        time.sleep(1.0)   # post-collect goes on to the generator, which waits for the lock
        output = (root / "logs/cron.out").read_text(encoding="utf-8")
        self.assertIsNone(process.poll(), output)
        self.assertFalse(page.exists(), output)
        fcntl.flock(lock, fcntl.LOCK_UN)
        returncode = process.wait(timeout=120)
        output = (root / "logs/cron.out").read_text(encoding="utf-8")
        self.assertEqual(0, returncode, output)
        self.assert_one_sudo_post_collect(root, output)
        self.assertTrue(page.is_file(), output)
        self.assertEqual(1, self.pages_built(root), output)

    def test_a_refused_sudo_keeps_the_collection_and_the_page(self):
        root = self.stage_page()
        page = root / "monitor/monitor.html"
        page.write_text("<html>previous page</html>\n", encoding="utf-8")
        os.utime(page, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
        completed = self.run_cron(root, "--air", area="ethernet", tty=True, FAKE_EUID=str(direct.ME.pw_uid),
                                  FAKE_SUDO="refuse")
        output = completed.stdout + completed.stderr
        self.assertEqual(1, len(list((root / "ethernet/monitor/eth-info").glob("*.tar.gz"))), output)
        self.assertEqual("<html>previous page</html>\n", page.read_text(encoding="utf-8"))
        self.assertEqual(1_700_000_000_000_000_000, page.stat().st_mtime_ns)
        self.assertEqual(0, self.pages_built(root), output)
        self.assertIn("未刷新（sudo 未通过）", output)
        self.assertEqual(0, completed.returncode, output)


if __name__ == "__main__":
    unittest.main()
