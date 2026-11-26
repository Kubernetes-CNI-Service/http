"""Workflow: the manual cron.sh automatic entry picks the only valid environment, then logs in as before (I-067).

Expectations come from 问题文档 I-067 合同 (owner Q-058: v3.1.6, manual cron only, YAML backup unchanged) and the
v3.1.6 guide 8.3 (:2052-2057) and 8.4 C5 workflow (:2071), never from cron.sh or environment_probe.py:
- run by hand without an environment, cron.sh asks the real ztp/environment_probe.py; when only the Production or
  only the AIR side of eth.csv has valid rows that environment is chosen and the choice is logged
  (「单一有效清单选择」); choosing it is not an identity check: the normal key login still compares each device's
  hostname / eth0 MAC with the inventory and a device that does not match is rejected (8.3 第 1 条);
- the worker's fixed slot (the real monitor/switch-collection-worker.py command line) and an explicit selection
  never reach this policy (8.3 第 3 条);
- the real ztp/backup/yaml-collect.py default (automatic) call keeps the old policy: a single-environment
  inventory is still refused there (8.3 第 3 条, Q-058).

A staged copy of the real cron.sh runs in a private tree (test_cron_operator_identity.stage_tree, the
test_ufm_monitor_cron_workflow precedent).  Only ssh is replaced: a fake device answers the identity part of the
command cron.sh and the probe send (hostname, eth0 MAC) from FAKE_DEVICES and changes nothing; everything else ssh
is asked to do succeeds without output, as in the staged tree's own recorder.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT / "monitor"), str(ROOT / "tools")):   # the worker's own imports
    if path not in sys.path:
        sys.path.insert(0, path)

from test_cases import test_cron_operator_identity as direct  # noqa: E402


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


WORKER = load("cron_single_environment_workflow_worker", ROOT / "monitor/switch-collection-worker.py")

# ssh: record the call; a key-preparation or probe command gets the identity of the device at that address
# (FAKE_DEVICES: address -> [hostname, eth0 MAC]); only the identity part of a key-preparation command runs,
# so nothing is written for authorized_keys.  An address that is not listed cannot be reached.
FAKE_SSH = '''#!{python}
import json, os, subprocess, sys
arguments = sys.argv[1:]
with open(os.path.join(os.environ["FAKE_LOG_DIR"], "ssh.jsonl"), "a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\\n")
remote = arguments[-1] if arguments else ""
targets = [arg for arg in arguments if "@" in arg and not arg.startswith("-")]
address = targets[-1].split("@", 1)[1] if targets else ""
if "actual_raw=" not in remote and not remote.startswith("hostname -s"):
    sys.exit(0)
answer = json.loads(os.environ["FAKE_DEVICES"]).get(address)
if answer is None:
    print(f"ssh: connect to host {{address}} port 22: Connection timed out", file=sys.stderr)
    sys.exit(255)
if remote.startswith("hostname -s"):
    print(answer[0])
    print(answer[1])
    sys.exit(0)
identity = remote.split("\\nmkdir -p ~/.ssh", 1)[0]
device = (
    'hostname() {{ printf "%s\\\\n" "$FAKE_NAME"; }}\\n'
    'cat() {{ if [ "$1" = /sys/class/net/eth0/address ]; then printf "%s\\\\n" "$FAKE_MAC"; '
    'else command cat "$@"; fi; }}\\n'
)
completed = subprocess.run(["bash", "-c", device + identity],
                           env=dict(os.environ, FAKE_NAME=answer[0], FAKE_MAC=answer[1]))
sys.exit(completed.returncode)
'''
# python3 on cron.sh's pinned PATH: note which helper ran with which arguments, then run it.
PYTHON = '''#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_LOG_DIR/python3.log"
exec {python} "$@"
'''

HEADER = "hostname,type,eth0_ip,netmask,eth0_mac\n"
# Production only: Leaf01 answers as itself; Leaf02 has no MAC in the CSV and answers with another hostname.
PROD_ONLY = HEADER + (
    "EXAMPLE-Leaf01,eth,192.0.2.11,24,02:00:00:00:00:11\n"
    "EXAMPLE-Leaf02,eth,192.0.2.12,24,\n"
)
PROD_DEVICES = {
    "192.0.2.11": ["EXAMPLE-Leaf01", "02:00:00:00:00:11"],
    "192.0.2.12": ["EXAMPLE-Other02", "02:00:00:00:00:12"],
}
# AIR only: Leaf01 answers as itself; Leaf02 answers with its hostname but another eth0 MAC.
AIR_ONLY = HEADER + (
    "AIR-EXAMPLE-Leaf01,air,192.0.2.21,24,02:00:00:00:00:21\n"
    "AIR-EXAMPLE-Leaf02,air,192.0.2.22,24,02:00:00:00:00:22\n"
)
AIR_DEVICES = {
    "192.0.2.21": ["AIR-EXAMPLE-Leaf01", "02:00:00:00:00:21"],
    "192.0.2.22": ["AIR-EXAMPLE-Leaf02", "02:00:00:00:00:99"],
}


class CronSingleEnvironmentWorkflowTests(unittest.TestCase):
    def stage(self, inventory: str) -> Path:
        directory = tempfile.TemporaryDirectory(prefix="cron-single-env-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()   # macOS /var alias: the path cron.sh sees is the resolved one
        direct.stage_tree(root, pointer=False)
        (root / "ztp").mkdir()
        for name in ("environment_probe.py", "dhcp_runtime_inventory.py", "dynamic_air_inventory.py"):
            shutil.copy2(ROOT / "ztp" / name, root / "ztp" / name)
        (root / "DAY0-Prepare" / direct.PROJECT / "02-devices_config.csv").write_text(inventory, encoding="utf-8")
        direct.write_exec(root / "bin/ssh", FAKE_SSH.format(python=sys.executable))
        direct.write_exec(root / "bin/python3", PYTHON.format(python=shlex.quote(sys.executable)))
        return root

    def run_cron(self, root: Path, devices: dict, *args: str):
        environment = direct.fixture_environment(root, area="ethernet", FAKE_DEVICES=json.dumps(devices))
        completed = subprocess.run(["bash", str(root / "ethernet/monitor/cron.sh"), *args], cwd=root,
                                   env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                   timeout=300, check=False)
        return completed, completed.stdout + completed.stderr

    @staticmethod
    def probe_runs(root: Path) -> list:
        path = root / "logs/python3.log"
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        return [line for line in lines if "environment_probe.py" in line]

    @staticmethod
    def logged_in(root: Path) -> set:
        addresses = set()
        for arguments in direct.records(root, "ssh.jsonl"):
            addresses.update(arg.split("@", 1)[1] for arg in arguments if "@" in arg and not arg.startswith("-"))
        return addresses

    def test_manual_auto_entry_selects_the_single_environment_and_still_checks_identity(self):
        # 问题文档 I-067 合同「仅cron自动入口，明确只有prod或air有效清单时选之并记日志，仍执行原登录/身份核对」;
        # guide 8.3 第 1 条 :2054; 8.4 C5 workflow :2071「prod-only/air-only 各一次，环境选择日志可见，身份不符仍拒绝」
        for label, inventory, devices, environment, good, bad, reason in (
            ("prod-only", PROD_ONLY, PROD_DEVICES, "prod", "EXAMPLE-Leaf01", "EXAMPLE-Leaf02",
             "hostname identity mismatch"),
            ("air-only", AIR_ONLY, AIR_DEVICES, "air", "AIR-EXAMPLE-Leaf01", "AIR-EXAMPLE-Leaf02",
             "management MAC identity mismatch"),
        ):
            with self.subTest(inventory=label):
                root = self.stage(inventory)
                completed, output = self.run_cron(root, devices)
                self.assertIn(f"[ENV] single valid inventory selected: {environment}", output, output)
                self.assertIn("单一有效清单选择", output)
                self.assertNotIn("environment selection failed", output)
                runs = self.probe_runs(root)
                self.assertEqual(1, len(runs), runs)
                self.assertIn("--allow-single-environment", runs[0].split())
                # the original key login still checks every device of the chosen environment
                self.assertEqual(set(devices), self.logged_in(root))
                self.assertRegex(output, rf"\[KEY\]\[OK\] +{good} ")
                self.assertIn(f"[KEY][IDENTITY-MISMATCH] {bad} ", output)
                self.assertIn(reason, output)
                self.assertNotRegex(output, rf"\[KEY\]\[OK\][^\n]*{bad}")
                archives = sorted(path.name for path in (root / "ethernet/monitor/eth-info").glob("*.tar.gz"))
                self.assertTrue(archives, output)
                self.assertTrue(all(name.endswith(f"-{environment}.tar.gz") for name in archives), archives)

    def test_worker_slots_and_explicit_choices_are_not_taken_over(self):
        # guide 8.3 第 3 条 :2056「显式 prod/air/type 选择、worker 冻结 slot 及其上下文保持原流程，不走这项自动单环境政策」
        air_slot = WORKER.commands_for_scope("air", lock_wait=0)
        prod_slot = [command for command in WORKER.commands_for_scope("prod", lock_wait=0)
                     if command[1].endswith("ethernet/monitor/cron.sh")]
        self.assertEqual(1, len(air_slot))
        self.assertEqual(1, len(prod_slot))
        for label, arguments, inventory, devices in (
            ("worker AIR slot over a Production-only inventory", air_slot[0][2:], PROD_ONLY, PROD_DEVICES),
            ("worker Production slot over an AIR-only inventory", prod_slot[0][2:], AIR_ONLY, AIR_DEVICES),
            ("explicit --type prod over an AIR-only inventory", ["--type", "prod"], AIR_ONLY, AIR_DEVICES),
        ):
            with self.subTest(case=label):
                root = self.stage(inventory)
                _completed, output = self.run_cron(root, devices, *arguments)
                self.assertEqual([], self.probe_runs(root), output)
                self.assertNotIn("single valid inventory", output)
                self.assertEqual(set(), self.logged_in(root) & set(devices),
                                 "the other environment's devices are never contacted")

    def test_yaml_backup_default_keeps_the_shared_policy(self):
        # 04 Q-058「C5仅cron/YAML不变」; guide 8.3 第 3 条 :2056「yaml-collect.py 原 auto/default 调用不传开启值，保持旧默认」
        for label, inventory in (("prod-only", PROD_ONLY), ("air-only", AIR_ONLY)):
            with self.subTest(inventory=label), tempfile.TemporaryDirectory(prefix="yaml-single-env-") as directory:
                root = Path(directory).resolve()
                (root / "ztp/backup").mkdir(parents=True)
                for name in ("environment_probe.py", "dynamic_air_inventory.py"):
                    shutil.copy2(ROOT / "ztp" / name, root / "ztp" / name)
                # yaml-collect.py loads its two fixed bounded-process siblings at import
                for name in ("yaml-collect.py", "_bounded_process.py", "_bounded_process_launcher.py"):
                    shutil.copy2(ROOT / "ztp/backup" / name, root / "ztp/backup" / name)
                (root / "ztp/backup/02-devices_config.csv").write_text(inventory, encoding="utf-8")
                (root / "logs").mkdir()
                direct.write_exec(root / "bin/ssh", FAKE_SSH.format(python=sys.executable))
                environment = dict(os.environ, PATH=f"{root / 'bin'}:/usr/bin:/bin", FAKE_LOG_DIR=str(root / "logs"),
                                   FAKE_DEVICES=json.dumps({**PROD_DEVICES, **AIR_DEVICES}),
                                   PYTHONDONTWRITEBYTECODE="1")
                completed = subprocess.run([sys.executable, "-B", str(root / "ztp/backup/yaml-collect.py")], cwd=root,
                                           env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                           timeout=120, check=False)
                output = completed.stdout + completed.stderr
                self.assertEqual(1, completed.returncode, output)
                self.assertIn("无法自动判断当前可达环境", output)
                self.assertIn("no overlapping eth0 IP to probe", output)
                self.assertEqual([], direct.records(root, "ssh.jsonl"))


if __name__ == "__main__":
    unittest.main()
