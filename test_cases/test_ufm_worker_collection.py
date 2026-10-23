"""UFM on the worker path (owner 2026-10-21, option A): the frozen target plan carries the server_ufm
rows of the infiniband slot, the worker checks them against the frozen inventory, and the real cron.sh
collects the UFMs from that plan exactly as on a manual run (infiniband/monitor/UFM-MONITOR.md)."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_cases.test_collection_cycle_handoff_workflow as handoff
import test_cases.test_ufm_monitor_cron_workflow as ufm_cron
from test_cases.test_ufm_monitor_scripts import FAKE_DOCKER, FAKES

ROOT = Path(__file__).resolve().parents[1]
MONITOR = ROOT / "monitor"
if str(MONITOR) not in sys.path:   # the worker imports switch_collection_gate by its bare name
    sys.path.insert(0, str(MONITOR))

UFM_ROW = "ufm01,server_ufm,198.51.100.30\n"
INVENTORY = b"hostname,type,eth0_ip\nleaf-ib,ib,192.0.2.11\nufm01,server_ufm,198.51.100.30\n"


def load_worker():
    spec = importlib.util.spec_from_file_location("ufm_worker_collection_target",
                                                  MONITOR / "switch-collection-worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WORKER = load_worker()


def plan(**rows):
    value = {"eth": [], "spx": [], "ib": [], "nv": [], "dynamic_identities": [], "ufm": []}
    value.update(rows)
    return value


class UfmTargetPlanProvenanceTest(unittest.TestCase):
    def matches(self, target_plan, slot="infiniband/prod", inventory=INVENTORY):
        return WORKER._collection_target_plan_matches_sources(
            {"target_plan": target_plan, "air_dynamic_rows": [], "prod_runtime_rows": []}, inventory, slot)

    def test_the_infiniband_plan_carries_exactly_the_inventory_ufms(self):
        self.assertTrue(self.matches(plan(ib=["leaf-ib|192.0.2.11"], ufm=["ufm01|198.51.100.30"])))

    def test_an_unbacked_missing_or_rewritten_ufm_target_is_rejected(self):
        for ufm in ([], ["ufm01|198.51.100.30", "rogue|198.51.100.199"], ["ufm01|198.51.100.99"],
                    ["rogue|198.51.100.30"]):
            with self.subTest(ufm=ufm):
                self.assertFalse(self.matches(plan(ib=["leaf-ib|192.0.2.11"], ufm=ufm)))

    def test_other_slots_never_carry_ufm_targets(self):
        inventory = b"hostname,type,eth0_ip\nleaf-nv,nvl,192.0.2.12\nufm01,server_ufm,198.51.100.30\n"
        self.assertTrue(self.matches(plan(nv=["leaf-nv|192.0.2.12"]), "nvlink/prod", inventory))
        self.assertFalse(self.matches(plan(nv=["leaf-nv|192.0.2.12"], ufm=["ufm01|198.51.100.30"]),
                                      "nvlink/prod", inventory))

    def test_a_five_key_plan_recorded_before_the_ufm_key_still_verifies(self):
        # Codex review 2026-10-22: a cycle frozen before 2026-10-21 keeps its five-key plan and digest;
        # checking it again must not fail. It planned no UFM, whatever the inventory lists now.
        legacy = plan(ib=["leaf-ib|192.0.2.11"])
        del legacy["ufm"]
        self.assertTrue(self.matches(legacy))
        self.assertFalse(self.matches({key: value for key, value in legacy.items() if key != "ib"}),
                         "only the ufm key may be absent")

    def test_new_plans_and_new_evidence_still_need_the_ufm_key(self):
        source = (MONITOR / "switch-collection-worker.py").read_text(encoding="utf-8")
        self.assertIn('raise ValueError("collector target plan shape is invalid")', source)
        emitter = (MONITOR / "collection_v2_emitter.py").read_text(encoding="utf-8")
        self.assertIn('"eth", "spx", "ib", "nv", "dynamic_identities", "ufm"', emitter)


class UfmWorkerCollectionWorkflowTest(unittest.TestCase):
    def test_the_worker_plan_reaches_the_ufm_phase_and_the_switch_result_still_qualifies(self):
        harness = handoff.CollectionCycleHandoffWorkflowTests("test_managed_real_collectors_emit_run_bound_v2_evidence")
        with tempfile.TemporaryDirectory() as directory:
            root = harness.make_layout(directory)
            inventory = root / "infiniband/monitor/ib.csv"
            inventory.write_text(inventory.read_text(encoding="utf-8") + UFM_ROW, encoding="utf-8")
            (root / "infiniband/monitor/ufm-info").mkdir()   # the data links setup creates
            (root / "infiniband/monitor/ufm-ibdiagnet").mkdir()
            for name in ("ufm-info.sh", "ufm-ibdiagnet.sh"):
                shutil.copy(ROOT / "infiniband/monitor" / name, root / "infiniband/monitor" / name)
            (root / "infiniband/monitor/01-global.yaml").write_text(
                'servers:\n  - ufm:\n      vip: "198.51.100.33"\n', encoding="utf-8")
            calls = root / "fixture-ssh-calls.log"
            with open(root / "fixture-bash-env.sh", "a", encoding="utf-8") as shims:
                shims.write(
                    'eval "fixture_original_ssh() $(declare -f ssh | tail -n +2)"\n'
                    f'ssh() {{ printf "%s\\n" "$*" >> "{calls}"; fixture_original_ssh "$@"; }}\n'
                    "export -f ssh fixture_original_ssh\n")
            completed, payload, traces = harness.run_workflow(root, "prod")
            ssh_calls = calls.read_text(encoding="utf-8") if calls.exists() else ""
            by_slot = {trace["source_slot"]: trace for trace in traces}
            records = [json.loads(path.read_text(encoding="utf-8"))
                       for path in (root / "infiniband/monitor/ufm-ibdiagnet").glob("*.ufm-run.json")]

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIsNotNone(payload, completed.stdout)
        frozen = by_slot["infiniband/prod"]["context"]["target_plan"]
        self.assertEqual(["ufm01|198.51.100.30"], frozen["ufm"], "the planner froze the UFM row")
        self.assertEqual(["leaf-ib|192.0.2.11"], frozen["ib"], "a UFM is never a switch target")
        for slot in ("ethernet/prod", "nvlink/prod"):
            self.assertEqual([], by_slot[slot]["context"]["target_plan"]["ufm"], slot)
        self.assertIn("root@198.51.100.30", ssh_calls, "the full collector worked on the frozen UFM target")
        result = payload["result"]
        self.assertTrue(all(item["outcome"] == "accepted" and item["child_result"]["schema_version"] == 2
                            for item in result["outcomes"]), result["outcomes"])
        ib = next(item for item in result["outcomes"] if item["source_slot"] == "infiniband/prod")
        self.assertEqual(1, ib["child_result"]["planned"], "UFMs stay out of the switch result")
        self.assertIsNotNone(result["summary"])
        self.assertTrue(result["summary"]["qualifying"])
        # Codex review 2026-10-22: the run record names the cycle the worker completed. Here the device
        # answering the VIP cannot be matched to the inventory (no eth0_mac), so the run fails closed.
        [record] = records
        self.assertEqual(record["cycle"], result["identity"])
        self.assertEqual((record["outcome"], record["report"]), ("failed", None))
        self.assertIn("管理口 MAC 不符", record["reason"])


# A stand-in for tools/ibdiagnet-analyze-tool/analyze.py, as in test_ufm_monitor_cron_workflow: the
# report, and the provenance naming the input and the CVT by sha256 that post-collect.py checks.
IB_ANALYZER = r'''import hashlib, json, os, sys
args = sys.argv[1:]
def identity(path):
    real = os.path.realpath(path)
    return {"path": os.path.abspath(path), "resolved_path": real, "kind": "file",
            "sha256": hashlib.sha256(open(real, "rb").read()).hexdigest()}
output = args[args.index("--output") + 1]
open(output, "wb").write(b"PK report")
json.dump({"schema": "ib-report-provenance-v1", "report": identity(output),
           "cvt": identity(args[args.index("--p2p") + 1]), "actual": identity(args[1])},
          open(output + ".provenance.json", "w"))
'''

# Appended to the harness's fixture-bash-env.sh: ssh/scp to a UFM node or the VIP reach the fake UFMs
# of test_ufm_monitor_cron_workflow (per-IP sandboxes running the real ufm-*.sh with fake UFM commands);
# every other address keeps the harness's generic switch shims.
UFM_SHIMS = r'''
eval "fixture_switch_ssh() $(declare -f ssh | tail -n +2)"
eval "fixture_switch_scp() $(declare -f scp | tail -n +2)"
fixture_ufm_address() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            @PATTERNS@) return 0 ;;
        esac
    done
    return 1
}
fixture_ufm() {
    local tool="$1"; shift
    FAKE_UFM_STATE="@FAKES@/state.json" FAKE_UFM_CALLS="@FAKES@/calls.jsonl" FAKE_UFM_HOSTS="@FAKES@/hosts" \
        FAKE_UFM_BIN="@FAKES@/ufm-bin" FAKE_UFM_SYSFS="@FAKES@/sys-infiniband" COPYFILE_DISABLE=1 \
        "@FAKES@/bin/${tool}" "$@"
}
ssh() { if fixture_ufm_address "$@"; then fixture_ufm ssh "$@"; else fixture_switch_ssh "$@"; fi; }
scp() { if fixture_ufm_address "$@"; then fixture_ufm scp "$@"; else fixture_switch_scp "$@"; fi; }
# The harness makes every wait free; the UFM scripts run in the background here, so each poll of
# cron.sh waits a little instead of spending its bounded number of checks at once.
sleep() { command sleep 0.2; }
export -f fixture_switch_ssh fixture_switch_scp fixture_ufm_address fixture_ufm ssh scp sleep
'''

# The harness gives each cron.sh 10 s and the whole worker run 30 s; the UFM phase adds about forty
# fake ssh/scp round trips (one python process each) and the background ufm-*.sh runs, which bring the
# infiniband cron.sh close to 10 s, so this test gives both more room (only the bootstrap's direct
# worker call is changed).
HARNESS_SLOT_CALL = "body, artifact_bindings=bindings, timeout=10, lock_wait=0,"
SLOT_TIMEOUT = 90
WORKFLOW_TIMEOUT = 600


class UfmWorkerIbdiagnetSuccessWorkflowTest(unittest.TestCase):
    """Codex review 2026-10-22: one run of the whole success chain. The real worker freezes the plan,
    the real cron.sh (infiniband entry point) runs ibdiagnet on the UFM holding the VIP, the real
    post-collect.py publishes the report and its receipt, and the UFM run record that names them
    carries the cycle the worker completed."""

    HOLDER = ufm_cron.UFMS["ufm02.example.test"][0]   # ufm02 holds the VIP

    def run_worker(self, harness, root):
        self.assertEqual(1, handoff.BOOTSTRAP.count(HARNESS_SLOT_CALL), "the harness's worker call changed")
        bootstrap = handoff.BOOTSTRAP.replace(
            HARNESS_SLOT_CALL, HARNESS_SLOT_CALL.replace("timeout=10", f"timeout={SLOT_TIMEOUT}"))
        real_run = subprocess.run

        def patient_run(*args, **kwargs):
            return real_run(*args, **dict(kwargs, timeout=WORKFLOW_TIMEOUT))

        with mock.patch.object(handoff, "BOOTSTRAP", bootstrap), \
                mock.patch.object(handoff.subprocess, "run", patient_run):
            return harness.run_workflow(root, "prod")

    def make_layout(self, harness, directory):
        root = harness.make_layout(directory)
        monitor = root / "infiniband/monitor"
        # The identity is the management MAC (eth0_mac) of the frozen inventory; the switch row has none.
        rows = ["hostname,type,eth0_ip,eth0_mac", "leaf-ib,ib,192.0.2.11,"]
        rows += [f"{name},server_ufm,{ip},{mac}" for name, (ip, mac) in ufm_cron.UFMS.items()]
        (monitor / "ib.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
        for name in ("ufm-info.sh", "ufm-ibdiagnet.sh", "post-collect.py"):
            shutil.copy(ROOT / "infiniband/monitor" / name, monitor / name)
        for name in ("ufm-info", "ufm-ibdiagnet"):   # the data links setup creates
            (monitor / name).mkdir()
        (monitor / "01-global.yaml").write_text(
            f'servers:\n  - ufm:\n      vip: "{ufm_cron.VIP}"\n', encoding="utf-8")
        # the IB closed loop: the setup output link with one CVT, and the stand-in analyzer
        reports = root / "DAY0-Prepare/site/99-output-p2p"
        reports.mkdir(parents=True)
        (reports / "site-cvt.xlsx").write_bytes(b"cvt")
        (monitor / "99-output-p2p").symlink_to(reports)
        analyzer = root / "tools/ibdiagnet-analyze-tool"
        analyzer.mkdir(parents=True)
        (analyzer / "analyze.py").write_text(IB_ANALYZER, encoding="utf-8")
        # the fake UFMs: ssh/scp, the UFM's own commands, its sysfs, and the state naming the VIP holder
        fakes = root.resolve() / "fixture-ufm"
        for name in ("bin", "ufm-bin", "hosts", "sys-infiniband/mlx5_0"):
            (fakes / name).mkdir(parents=True)
        for tool in ("ssh", "scp"):
            self.write_exec(fakes / "bin" / tool, ufm_cron.FAKE_REMOTE.replace("{python}", sys.executable))
        commands = dict(FAKES, hostname='echo "$FAKE_HOSTNAME"',
                        ip='echo "eno8303          UP             $FAKE_MAC <BROADCAST,MULTICAST,UP>"')
        for name, body in commands.items():
            self.write_exec(fakes / "ufm-bin" / name, f"#!/bin/sh\n{body}\n")
        self.write_exec(fakes / "ufm-bin/docker", FAKE_DOCKER.replace("{python}", sys.executable))
        state = {"ufms": {ip: {"hostname": name, "mac": mac} for name, (ip, mac) in ufm_cron.UFMS.items()},
                 "down": [], "vip": {ufm_cron.VIP: self.HOLDER}}
        (fakes / "state.json").write_text(json.dumps(state), encoding="utf-8")
        addresses = [ip for ip, _mac in ufm_cron.UFMS.values()] + [ufm_cron.VIP]
        patterns = "|".join(f"*@{ip}|*@{ip}:*" for ip in addresses)
        with open(root / "fixture-bash-env.sh", "a", encoding="utf-8") as shims:
            shims.write(UFM_SHIMS.replace("@PATTERNS@", patterns).replace("@FAKES@", str(fakes)))
        return root

    @staticmethod
    def write_exec(path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def identity(path):
        content = path.read_bytes()
        return {"name": path.name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}

    def test_a_worker_cycle_reaches_a_successful_ibdiagnet_report_and_the_record_names_that_cycle(self):
        harness = handoff.CollectionCycleHandoffWorkflowTests("test_managed_real_collectors_emit_run_bound_v2_evidence")
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(harness, directory)
            monitor = root / "infiniband/monitor"
            completed, payload, traces = self.run_worker(harness, root)
            by_slot = {trace["source_slot"]: trace for trace in traces}
            child = (by_slot.get("infiniband/prod") or {}).get("observed_child") or {}
            evidence = f"{completed.stderr}\n--- infiniband cron.sh ---\n{child.get('stdout')}\n{child.get('stderr')}"

            self.assertEqual(0, completed.returncode, evidence)
            self.assertIsNotNone(payload, completed.stdout)
            self.assertTrue(payload["returned"], payload)
            result = payload["result"]
            frozen = by_slot["infiniband/prod"]["context"]["target_plan"]
            self.assertEqual([f"{name}|{ip}" for name, (ip, _mac) in ufm_cron.UFMS.items()], frozen["ufm"],
                             "the worker froze the UFM rows of the inventory")
            self.assertTrue(all(item["outcome"] == "accepted" and item["child_result"]["schema_version"] == 2
                                for item in result["outcomes"]), f"{result['outcomes']}\n{evidence}")
            ib = next(item for item in result["outcomes"] if item["source_slot"] == "infiniband/prod")
            self.assertEqual(1, ib["child_result"]["planned"], "UFMs stay out of the switch result")
            self.assertIsNotNone(result["summary"])
            self.assertTrue(result["summary"]["qualifying"])

            records = [json.loads(path.read_text(encoding="utf-8"))
                       for path in (monitor / "ufm-ibdiagnet").glob("*.ufm-run.json")]
            self.assertEqual(1, len(records), evidence)
            [record] = records
            self.assertEqual(result["identity"], record["cycle"], "the record names the cycle the worker completed")
            self.assertEqual(("ok", "ok", "ibdiagnet", "ufm02"),
                             (record["outcome"], record["analysis"], record["kind"], record["node"]), evidence)
            for key, directory_name in (("input", "ufm-ibdiagnet"), ("done", "ufm-ibdiagnet"),
                                        ("report", "99-output-p2p"), ("receipt", "99-output-p2p")):
                self.assertIsInstance(record[key], dict, key)
                path = monitor / directory_name / record[key]["name"]
                self.assertTrue(path.is_file(), f"{key} named by the record does not exist: {path}")
                self.assertEqual(self.identity(path), record[key], key)
            receipt = json.loads((monitor / "99-output-p2p" / record["receipt"]["name"]).read_text(encoding="utf-8"))
            self.assertEqual((record["run_id"], record["node"], record["kind"]),
                             (receipt["run_id"], receipt["node"], receipt["kind"]))
            self.assertEqual(record["done"]["sha256"], receipt["done"]["sha256"], "the receipt names this .done")
            self.assertEqual((record["input"]["name"], record["input"]["sha256"]),
                             (receipt["input"]["name"], receipt["input"]["sha256"]), "the report is of this input")


if __name__ == "__main__":
    unittest.main()
