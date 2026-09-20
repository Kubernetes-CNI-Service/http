#!/usr/bin/env python3
"""Real-subprocess contract for one governed collection-cycle handoff.

This workflow deliberately stops at the persistence-free worker/collector seam.
Sequence allocation, immutable lifecycle records, launch records and high-water
witness behaviour have separate tests and are not assumed here.
"""

from __future__ import annotations

import hashlib
import json
import errno
import os
from pathlib import Path
import pty
import select
import signal
import shutil
import subprocess
import sys
import tempfile
import termios
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
TASK_RESULT_PREFIX = "[HTTP_ZTP_TASK_RESULT] "
RUN_TOKEN = "12345678123442348123456789abcdef"
SEQUENCE = 7
PROJECT_IDENTITY = "/project-fixture"
PROJECT_KEY = hashlib.sha256(PROJECT_IDENTITY.encode("utf-8")).hexdigest()
EXPECTED_SLOTS = {
    "air": ("ethernet/air",),
    "prod": (
        "ethernet/prod",
        "infiniband/prod",
        "nvlink/prod",
    ),
    "all": (
        "ethernet/air",
        "ethernet/prod",
        "infiniband/prod",
        "nvlink/prod",
    ),
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def expected_identity(scope: str) -> dict:
    body = {
        "project_key": PROJECT_KEY,
        "run_token": RUN_TOKEN,
        "scope": scope,
        "sequence": SEQUENCE,
        "source": "switch_collection",
    }
    return {
        **body,
        "cycle_id": hashlib.sha256(canonical_bytes(body)).hexdigest(),
    }


BOUNDARY_BASH = r'''#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

PREFIX = "[HTTP_ZTP_TASK_RESULT] "

arguments = sys.argv[1:]
if not arguments or not arguments[0].endswith("/monitor/cron.sh"):
    os.execv("/bin/bash", ["bash", *arguments])

invoked = Path(arguments[0])
root = invoked.parent.parent.parent.resolve()
control = json.loads((root / "fixture-control.json").read_text(encoding="utf-8"))
area = invoked.parent.parent.name
slot = "ethernet/air" if area == "ethernet" and "--air" in arguments else f"{area}/prod"
target = control.get("target_slot")
mutate = target is None or target == slot

context = None
child_arguments = list(arguments)
if "--worker-context-fd" in arguments:
    position = arguments.index("--worker-context-fd")
    descriptor = int(arguments[position + 1])
    chunks = []
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    raw_context = b"".join(chunks)
    context = json.loads(raw_context)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, raw_context)
    os.close(write_fd)
    os.dup2(read_fd, descriptor)
    os.close(read_fd)
    pass_fds = (descriptor,)
else:
    pass_fds = ()

ordinary = []
skip = set()
for position, value in enumerate(arguments):
    if position in skip:
        continue
    if value == "--worker-context-fd" and position + 1 < len(arguments):
        skip.add(position + 1)
        continue
    ordinary.append(value)
trace = {
    "argv": ordinary,
    "context": context,
    "context_fd_present": "--worker-context-fd" in arguments,
    "environment": dict(os.environ),
    "invoked_path": str(invoked),
    "resolved_path": str(invoked.resolve()),
    "source_slot": slot,
}
with (root / "fixture-trace.jsonl").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(trace, ensure_ascii=False, sort_keys=True) + "\n")

completed = subprocess.run(
    ["/bin/bash", *child_arguments], stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, pass_fds=pass_fds, env=os.environ.copy(), check=False,
)
stdout = completed.stdout.decode("utf-8", errors="replace")
stderr = completed.stderr.decode("utf-8", errors="replace")
returncode = completed.returncode

def mutate_marker(transform):
    global stdout
    lines = stdout.splitlines()
    indexes = [index for index, line in enumerate(lines) if line.startswith(PREFIX)]
    if len(indexes) != 1:
        return
    index = indexes[0]
    payload = json.loads(lines[index][len(PREFIX):])
    replacement = transform(payload)
    lines[index] = PREFIX + json.dumps(replacement, ensure_ascii=False, separators=(",", ":"))
    stdout = "\n".join(lines) + ("\n" if completed.stdout.endswith(b"\n") else "")

mode = control.get("mode", "success")
if mutate:
    if mode == "missing_marker":
        stdout = "\n".join(
            line for line in stdout.splitlines() if not line.startswith(PREFIX)
        ) + "\n"
    elif mode == "duplicate_marker":
        marker = next((line for line in stdout.splitlines() if line.startswith(PREFIX)), "")
        stdout += marker + "\n"
    elif mode == "malformed_marker":
        stdout += PREFIX + "{malformed-json\n"
    elif mode == "duplicate_slot":
        mutate_marker(lambda payload: {**payload, "source_slot": control["duplicate_as"]})
    elif mode == "extra_slot":
        mutate_marker(lambda payload: {**payload, "source_slot": "rogue/prod"})
    elif mode == "wrong_source_slot":
        mutate_marker(lambda payload: {**payload, "source_slot": "ethernet/air"})
    elif mode == "wrong_run_token":
        mutate_marker(lambda payload: {
            **payload, "run_token": "ffeeddccbbaa49888776655443322110",
        })
    elif mode == "wrong_sequence":
        mutate_marker(lambda payload: {**payload, "sequence": payload["sequence"] + 1})
    elif mode == "wrong_project_key":
        mutate_marker(lambda payload: {**payload, "project_key": "0" * 64})
    elif mode == "wrong_scope":
        mutate_marker(lambda payload: {**payload, "scope": "air"})
    elif mode == "wrong_cycle_id":
        mutate_marker(lambda payload: {**payload, "cycle_id": "0" * 64})
    elif mode == "bad_evidence_sha":
        mutate_marker(lambda payload: {
            **payload, "evidence": {**payload["evidence"], "sha256": "A" * 64},
        })
    elif mode == "bad_envelope_size_bool":
        mutate_marker(lambda payload: {
            **payload, "envelope": {**payload["envelope"], "size_bytes": True},
        })
    elif mode == "bad_envelope_size_zero":
        mutate_marker(lambda payload: {
            **payload, "envelope": {**payload["envelope"], "size_bytes": 0},
        })
    elif mode == "bad_inventory_sha":
        mutate_marker(lambda payload: {
            **payload, "input_inventory_sha256": "c" * 63,
        })
    elif mode == "wrong_evidence_digest":
        mutate_marker(lambda payload: {
            **payload, "evidence": {**payload["evidence"], "sha256": "d" * 64},
        })
    elif mode == "wrong_envelope_size":
        mutate_marker(lambda payload: {
            **payload,
            "envelope": {
                **payload["envelope"],
                "size_bytes": payload["envelope"]["size_bytes"] + 1,
            },
        })
    elif mode == "wrong_inventory_digest":
        mutate_marker(lambda payload: {
            **payload, "input_inventory_sha256": "e" * 64,
        })
    elif mode == "missing_evidence_file" and context:
        Path(context["artifacts"]["evidence"]).unlink(missing_ok=True)
    elif mode == "submitted_complete_empty":
        mutate_marker(lambda payload: {**payload, "complete_empty": False})
    elif mode == "schema_v1":
        mutate_marker(lambda payload: {
            "schema_version": 1, "task": "switch_collection",
            "state": "success", "planned": 0, "succeeded": 0,
            "failed_count": 0, "failed_devices": [],
        })
    elif mode == "mixed_nonempty" and slot != control.get("empty_slot"):
        mutate_marker(lambda payload: {
            **payload, "state": "success", "planned": 1, "succeeded": 1,
            "failed_count": 0, "failed_devices": [],
        })
    elif mode == "unreachable":
        def unreachable_one(payload):
            payload.update({
                "state": "failed", "planned": 1, "succeeded": 0,
                "failed_count": 1,
                "failed_devices": [{
                    "hostname": "leaf-unreachable", "operation": "collection",
                    "reason": "fixture unreachable",
                }],
            })
            return payload
        mutate_marker(unreachable_one)
        returncode = 1
    elif mode == "success_payload_rc1":
        returncode = 1
    elif mode == "failed_payload_rc0":
        def failed(payload):
            payload.update({
                "state": "failed", "planned": 1, "succeeded": 0,
                "failed_count": 1,
                "failed_devices": [{
                    "hostname": "leaf-unreachable", "operation": "collection",
                    "reason": "fixture unreachable",
                }],
            })
            return payload
        mutate_marker(failed)
        returncode = 0
    elif mode == "all_unreachable":
        def unreachable(payload):
            payload.update({
                "state": "failed", "planned": 1, "succeeded": 0,
                "failed_count": 1,
                "failed_devices": [{
                    "hostname": "leaf-unreachable", "operation": "collection",
                    "reason": "fixture unreachable",
                }],
            })
            return payload
        mutate_marker(unreachable)
        returncode = 1
    elif mode == "zero_byte_evidence" and context:
        evidence = Path(context["artifacts"]["evidence"])
        evidence.write_bytes(b"")
        def zero_evidence(payload):
            payload["evidence"] = {
                "sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0,
            }
            return payload
        mutate_marker(zero_evidence)

sys.stdout.write(stdout)
sys.stderr.write(stderr)
raise SystemExit(returncode)
'''


SHELL_SHIMS = r'''# Hermetic process-boundary shims; the copied cron.sh still runs in full.
flock() { return 0; }
ssh-keygen() { return 0; }
sleep() { return 0; }
ssh() {
    if [[ "${FIXTURE_SSH_MODE:-}" == "auth_failure" ]]; then
        printf 'Permission denied (publickey,password).\n' >&2
        return 255
    fi
    return 0
}
scp() {
    local last="${@: -1}"
    case "$last" in
        /*.info) mkdir -p "$(dirname "$last")"; printf 'fixture-info\n' > "$last" ;;
        /*.link) mkdir -p "$(dirname "$last")"; printf 'port,peer\n1,fixture\n' > "$last" ;;
    esac
    return 0
}
export -f flock ssh-keygen sleep ssh scp
'''


ANALYZER_FIXTURE = r'''#!/usr/bin/env python3
import argparse
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--archive", type=Path, required=True)
p.add_argument("--dot", type=Path, required=True)
p.add_argument("--output-dir", type=Path, required=True)
a = p.parse_args()
name = a.archive.name
for suffix in (".tar.gz", ".tgz"):
    if name.lower().endswith(suffix):
        name = name[:-len(suffix)]
        break
(a.output_dir / f"{name}-ethernet-topology-validation.xlsx").write_bytes(b"xlsx")
'''


HTML_FIXTURE = r'''#!/usr/bin/env python3
import sys
print("fixture monitor.html generation failed", file=sys.stderr)
raise SystemExit(23)
'''


HTML_SUCCESS_FIXTURE = r'''#!/usr/bin/env python3
raise SystemExit(0)
'''


BOOTSTRAP = r'''from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
scope = sys.argv[2]
mode = sys.argv[3]
target = sys.argv[4] or None
action = sys.argv[5] if len(sys.argv) > 5 else "direct"
sys.path.insert(0, str(root / "monitor"))
worker = runpy.run_path(str(root / "monitor/switch-collection-worker.py"))
required = ("run_collection_slots", "parse_collection_slot_result")
missing = [name for name in required if not callable(worker.get(name))]
if missing:
    raise AssertionError("worker must define B3 handoff API: " + ", ".join(missing))

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
slots = {
    "air": ("ethernet/air",),
    "prod": ("ethernet/prod", "infiniband/prod", "nvlink/prod"),
    "all": ("ethernet/air", "ethernet/prod", "infiniband/prod", "nvlink/prod"),
}[scope]
bindings = {}
for slot in slots:
    stem = slot.replace("/", "-")
    area = root / "fixture-artifacts" / stem
    area.mkdir(parents=True, exist_ok=True)
    inventory = area / "inventory.csv"
    inventory.write_bytes(("hostname,type\n" + slot + ",fixture\n").encode("utf-8"))
    bindings[slot] = {
        "evidence": str(area / "evidence.bin"),
        "envelope": str(area / "envelope.json"),
        "input_inventory": str(inventory),
    }
control = {"mode": mode}
if target:
    control["target_slot"] = target
if mode == "duplicate_slot":
    control["duplicate_as"] = "ethernet/prod"
if mode == "mixed_nonempty":
    control["empty_slot"] = "ethernet/prod"
(root / "fixture-control.json").write_text(
    json.dumps(control, sort_keys=True), encoding="utf-8",
)
try:
    if action in ("persisted", "sigkill"):
        coordinator = worker.get("run_collection_cycle_coordinator")
        if not callable(coordinator):
            raise AssertionError("worker must define run_collection_cycle_coordinator")
        status_dir = root / "monitor/status"
        with worker["CollectionGate"](
            "/project-fixture", scope,
            collection_keys=worker["collection_keys_for_scope"](scope),
            status_dir=status_dir,
            enforce_cooldown=False,
            lane="collection",
        ) as gate:
            if not gate.decision.allowed:
                raise AssertionError("fixture collection gate was not allowed")
            if action == "persisted":
                result = coordinator(
                    gate,
                    artifact_bindings=bindings,
                    timeout=10,
                    lock_wait=0,
                )
            else:
                store = worker["CollectionCycleStore"](gate=gate)
                start = store.allocate_start()
                context = {
                    "identity": start,
                    "artifact_bindings": bindings,
                    "timeout": 10,
                    "lock_wait": 0,
                }
                with tempfile.TemporaryFile(mode="w+b") as context_file, \
                        tempfile.TemporaryFile(mode="w+b") as result_file:
                    context_file.write(worker["_canonical_json_line"](context))
                    context_file.flush()
                    context_file.seek(0)
                    argv = [
                        sys.executable,
                        str(root / "monitor/switch-collection-worker.py"),
                        "--internal-cycle",
                        "--internal-cycle-context-fd", str(context_file.fileno()),
                        "--internal-cycle-result-fd", str(result_file.fileno()),
                    ]
                    process = subprocess.Popen(
                        argv,
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        pass_fds=(context_file.fileno(), result_file.fileno()),
                    )
                    ready = worker["_wait_for_collection_cycle_ready"](
                        process, result_file.fileno()
                    )
                    store.publish_launch(
                        start,
                        pid=process.pid,
                        boot_id=ready["boot_id"],
                        process_start_time=ready["process_start_time"],
                        argv=argv,
                        context=context,
                        credential_argv_positions=(),
                        credential_context_names=(),
                    )
                    try:
                        store.allocate_start(process_inspector=lambda _binding: "live")
                    except worker["CollectionCycleHoldError"] as exc:
                        live_hold = str(exc)
                    else:
                        raise AssertionError("live coordinator did not HOLD")
                    os.kill(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                next_start = store.allocate_start(
                    process_inspector=worker["inspect_collection_cycle_process"]
                )
                result = {
                    "live_hold": live_hold,
                    "killed_returncode": process.returncode,
                    "next_start": next_start,
                }
        project_key = hashlib.sha256(b"/project-fixture").hexdigest()
        cycle_root = (
            status_dir / "collection-cycles" / project_key / scope
            / "switch_collection"
        )
        records = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((cycle_root / "records").glob("*.json"))
        }
        persisted = {
            "witness": json.loads(
                (cycle_root / "high-water.json").read_text(encoding="utf-8")
            ),
            "records": records,
            "parent_pid": __import__("os").getpid(),
        }
    else:
        result = worker["run_collection_slots"](
            body, artifact_bindings=bindings, timeout=10, lock_wait=0,
        )
except Exception as exc:
    print("__WORKFLOW_RESULT__" + json.dumps({
        "returned": False,
        "error_type": type(exc).__name__,
        "error": str(exc),
    }, sort_keys=True))
else:
    print("__WORKFLOW_RESULT__" + json.dumps({
        "returned": True,
        "result": result,
        "persisted": persisted if action in ("persisted", "sigkill") else None,
    }, ensure_ascii=False, sort_keys=True))
'''


class CollectionCycleHandoffWorkflowTests(unittest.TestCase):
    def make_layout(self, directory: str) -> Path:
        root = Path(directory)
        tools = root / "tools"
        monitor = root / "monitor"
        ethernet = root / "ethernet/monitor"
        infiniband = root / "infiniband/monitor"
        nvlink = root / "nvlink/monitor"
        for path in (tools, monitor, ethernet, infiniband, nvlink):
            path.mkdir(parents=True)
        shutil.copy2(ROOT / "tools/project_contract.py", tools / "project_contract.py")
        shutil.copy2(
            ROOT / "monitor/switch-collection-worker.py",
            monitor / "switch-collection-worker.py",
        )
        shutil.copy2(
            ROOT / "monitor/switch_collection_gate.py",
            monitor / "switch_collection_gate.py",
        )
        for name in ("cron.sh", "post-collect.py", "sw-info.sh", "sw-link.sh"):
            shutil.copy2(ROOT / "ethernet/monitor" / name, ethernet / name)
        fixture_bin = root / "fixture-bin"
        fixture_bin.mkdir()
        (fixture_bin / "bash").write_text(BOUNDARY_BASH, encoding="utf-8")
        (fixture_bin / "bash").chmod(0o755)
        (root / "fixture-bash-env.sh").write_text(
            SHELL_SHIMS, encoding="utf-8",
        )
        analyzer_dir = root / "tools/lldp-analyze-tool"
        output_dir = analyzer_dir / "99-output-p2p"
        output_dir.mkdir(parents=True)
        (analyzer_dir / "analyze_lldp.py").write_text(
            ANALYZER_FIXTURE, encoding="utf-8",
        )
        (output_dir / "fixture-lldpq.dot").write_text(
            "digraph fixture {}\n", encoding="utf-8",
        )
        (monitor / "generate-monitor-html.py").write_text(
            HTML_SUCCESS_FIXTURE, encoding="utf-8",
        )
        (monitor / "generate-monitor-html.py").chmod(0o755)
        inventories = {
            ethernet: ("eth.csv", "leaf-eth,eth,192.0.2.10\n"),
            infiniband: ("ib.csv", "leaf-ib,ib,192.0.2.11\n"),
            nvlink: ("nvsw.csv", "leaf-nv,nvl,192.0.2.12\n"),
        }
        for area, (name, row) in inventories.items():
            (area / name).write_text(
                "hostname,type,eth0_ip\n" + row, encoding="utf-8",
            )
            (area / "mgmt-server.pub").write_text(
                "ssh-ed25519 AAAATEST workflow-fixture\n", encoding="utf-8",
            )
        for area in (infiniband, nvlink):
            (area / "cron.sh").symlink_to("../../ethernet/monitor/cron.sh")
            (area / "sw-info.sh").symlink_to("../../ethernet/monitor/sw-info.sh")
            (area / "sw-link.sh").symlink_to("../../ethernet/monitor/sw-link.sh")
        return root

    def run_workflow(
        self, root: Path, scope: str, mode: str = "success", target: str = "",
        action: str = "direct",
    ) -> tuple[subprocess.CompletedProcess[str], dict | None, list[dict]]:
        trace = root / "fixture-trace.jsonl"
        trace.unlink(missing_ok=True)
        completed = subprocess.run(
            [
                sys.executable, "-B", "-c", BOOTSTRAP,
                str(root), scope, mode, target, action,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            env={
                "BASH_ENV": str(root / "fixture-bash-env.sh"),
                "PATH": str(root / "fixture-bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        payload = None
        for line in completed.stdout.splitlines():
            if line.startswith("__WORKFLOW_RESULT__"):
                payload = json.loads(line.removeprefix("__WORKFLOW_RESULT__"))
        traces = []
        if trace.is_file():
            traces = [
                json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()
                if line
            ]
            for item in traces:
                observed = {}
                context = item.get("context")
                if isinstance(context, dict):
                    for name, raw_path in context["artifacts"].items():
                        path = Path(raw_path)
                        if path.is_file():
                            content = path.read_bytes()
                            observed[name] = {
                                "sha256": hashlib.sha256(content).hexdigest(),
                                "size_bytes": len(content),
                            }
                        else:
                            observed[name] = None
                item["observed_artifacts"] = observed
        return completed, payload, traces

    def test_dedicated_coordinator_persists_launch_and_completion_before_return(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.make_layout(td)
            completed, payload, _traces = self.run_workflow(
                root, "prod", action="persisted",
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload)
            assert payload is not None
            self.assertTrue(payload["returned"], payload)
            result = payload["result"]
            self.assertIsNone(result["summary"])
            self.assertEqual(
                ["accepted", "accepted", "accepted"],
                [item["outcome"] for item in result["outcomes"]],
            )
            persisted = payload["persisted"]
            self.assertEqual({"high_water": 1}, persisted["witness"])
            records = persisted["records"]
            self.assertEqual(3, len(records))
            start = records["00000000000000000001.start.json"]
            launch = records["00000000000000000001.launch.json"]
            completion = records["00000000000000000001.completion.json"]
            self.assertEqual("start", start["kind"])
            self.assertEqual("launch", launch["kind"])
            self.assertEqual("completion", completion["kind"])
            self.assertNotEqual(persisted["parent_pid"], launch["pid"])
            self.assertEqual("cycle_completed", completion["outcome"])
            self.assertEqual(result, completion["run_result"])

    def test_sigkill_coordinator_holds_live_then_reconciles_crash_before_next_start(self):
        with tempfile.TemporaryDirectory() as td:
            root = self.make_layout(td)
            completed, payload, traces = self.run_workflow(
                root, "prod", action="sigkill",
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload)
            assert payload is not None
            self.assertTrue(payload["returned"], payload)
            self.assertEqual("exact-token child live", payload["result"]["live_hold"])
            self.assertEqual(-signal.SIGKILL, payload["result"]["killed_returncode"])
            self.assertEqual(2, payload["result"]["next_start"]["sequence"])
            self.assertEqual([], traces)
            persisted = payload["persisted"]
            self.assertEqual({"high_water": 2}, persisted["witness"])
            records = persisted["records"]
            crashed = records["00000000000000000001.completion.json"]
            self.assertEqual("cycle_crashed", crashed["outcome"])
            self.assertIsNone(crashed["run_result"])
            self.assertIn("00000000000000000002.start.json", records)
            self.assertNotIn("00000000000000000002.launch.json", records)

    def assert_fail_closed(
        self, payload: dict | None, completed: subprocess.CompletedProcess[str],
        *, scope: str = "prod",
    ) -> None:
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIsNotNone(payload, completed.stdout)
        self.assertTrue(
            payload["returned"],
            "malformed child output must become a terminal worker result, not escape",
        )
        self.assertIsNone(payload["result"]["summary"])
        results = payload["result"].get("outcomes", [])
        self.assertEqual(
            list(EXPECTED_SLOTS[scope]),
            [item.get("source_slot") for item in results],
            "one terminal worker-owned outcome is required for every slot",
        )
        self.assertEqual(len(results), len({item["source_slot"] for item in results}))
        self.assertTrue(any(item["outcome"] != "accepted" for item in results))
        self.assertTrue(all(
            item["child_result"] is None
            for item in results if item["outcome"] != "accepted"
        ))

    @staticmethod
    def set_html_result(root: Path, *, success: bool) -> None:
        (root / "monitor/generate-monitor-html.py").write_text(
            HTML_SUCCESS_FIXTURE if success else HTML_FIXTURE,
            encoding="utf-8",
        )

    def test_prod_real_v1_handoff_is_ordered_persistable_and_nonqualifying(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            completed, payload, traces = self.run_workflow(root, "prod")

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIsNotNone(payload, completed.stdout)
        self.assertTrue(payload["returned"], payload)
        result = payload["result"]
        expected_slots = EXPECTED_SLOTS["prod"]
        self.assertEqual(list(expected_slots), [
            item["source_slot"] for item in result["outcomes"]
        ])
        identity = expected_identity("prod")
        self.assertEqual(identity, result["identity"])
        self.assertIsNone(
            result["summary"],
            "real v1 children are evidence-only and cannot qualify a cycle",
        )
        self.assertEqual(len(expected_slots), len(traces))
        for trace, slot in zip(traces, expected_slots):
            self.assertIsNone(trace["context"])
            self.assertFalse(trace["context_fd_present"])
            invoked = Path(trace["invoked_path"])
            expected_area = slot.split("/", 1)[0]
            self.assertEqual(
                Path(expected_area) / "monitor/cron.sh",
                invoked.relative_to(root.resolve()),
            )
            self.assertEqual(
                (root / "ethernet/monitor/cron.sh").resolve(),
                Path(trace["resolved_path"]),
            )
            argv_text = "\x00".join(trace["argv"])
            env_text = "\x00".join(
                f"{key}={value}" for key, value in trace["environment"].items()
            )
            for forbidden in (
                identity["run_token"], identity["project_key"], identity["cycle_id"],
            ):
                self.assertNotIn(forbidden, argv_text)
                self.assertNotIn(forbidden, env_text)
            for forbidden_name in (
                "--run-token", "--sequence", "--project-key", "--scope",
                "--cycle-id", "--worker-context-fd",
            ):
                self.assertNotIn(forbidden_name, trace["argv"])
        self.assertTrue(all(
            item["outcome"] == "accepted"
            and item["child_result"]["schema_version"] == 1
            for item in result["outcomes"]
        ))

    def test_real_ib_and_nvlink_entrypoints_reject_an_empty_selected_lane(self):
        for area, inventory_name, slot in (
            ("infiniband", "ib.csv", "infiniband/prod"),
            ("nvlink", "nvsw.csv", "nvlink/prod"),
        ):
            with self.subTest(slot=slot), tempfile.TemporaryDirectory() as directory:
                root = self.make_layout(directory)
                (root / area / "monitor" / inventory_name).write_text(
                    "hostname,type,eth0_ip\n", encoding="utf-8",
                )
                completed, payload, _traces = self.run_workflow(root, "prod")

                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertIsNotNone(payload, completed.stdout)
                assert payload is not None
                outcomes = {
                    item["source_slot"]: item
                    for item in payload["result"]["outcomes"]
                }
                self.assertNotEqual("accepted", outcomes[slot]["outcome"])
                self.assertIsNone(outcomes[slot]["child_result"])

    def test_all_scope_order_and_every_slot_echo_mutation_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            completed, payload, traces = self.run_workflow(
                root, "all", "mixed_nonempty",
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload, completed.stdout)
            self.assertTrue(payload["returned"], payload)
            self.assertEqual(
                list(EXPECTED_SLOTS["all"]),
                [item["source_slot"] for item in payload["result"]["outcomes"]],
            )
            self.assertIsNone(payload["result"]["summary"])
            by_slot = {
                item["source_slot"]: item
                for item in payload["result"]["outcomes"]
            }
            self.assertEqual("missing_marker", by_slot["ethernet/air"]["outcome"])
            self.assertTrue(all(
                by_slot[slot]["outcome"] == "accepted"
                and by_slot[slot]["child_result"]["schema_version"] == 1
                for slot in EXPECTED_SLOTS["prod"]
            ))

            mutations = (
                "missing_marker",
                "duplicate_marker",
                "malformed_marker",
                "duplicate_slot",
                "extra_slot",
                "wrong_source_slot",
                "wrong_run_token",
                "wrong_sequence",
                "wrong_project_key",
                "wrong_scope",
                "wrong_cycle_id",
                "bad_evidence_sha",
                "bad_envelope_size_bool",
                "bad_envelope_size_zero",
                "bad_inventory_sha",
                "wrong_evidence_digest",
                "wrong_envelope_size",
                "wrong_inventory_digest",
                "submitted_complete_empty",
                "success_payload_rc1",
                "failed_payload_rc0",
            )
            for mode in mutations:
                with self.subTest(mode=mode):
                    completed, payload, _ = self.run_workflow(
                        root, "prod", mode, "infiniband/prod",
                    )
                    self.assert_fail_closed(payload, completed)

    def test_v1_cannot_assert_artifacts_and_all_unreachable_stays_nonqualifying(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            completed, payload, traces = self.run_workflow(
                root, "prod", "zero_byte_evidence", "infiniband/prod",
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload, completed.stdout)
            self.assertTrue(payload["returned"], payload)
            by_slot = {
                item["source_slot"]: item
                for item in payload["result"]["outcomes"]
            }
            self.assertEqual("accepted", by_slot["infiniband/prod"]["outcome"])
            child = by_slot["infiniband/prod"]["child_result"]
            self.assertEqual(1, child["schema_version"])
            self.assertNotIn("evidence", child)
            self.assertNotIn("envelope", child)
            self.assertNotIn("input_inventory_sha256", child)
            self.assertIsNone(payload["result"]["summary"])

            completed, payload, _ = self.run_workflow(
                root, "prod", "all_unreachable",
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload, completed.stdout)
            self.assertTrue(payload["returned"], payload)
            result = payload["result"]
            self.assertIsNone(result["summary"])
            self.assertEqual(
                list(EXPECTED_SLOTS["prod"]),
                [item["source_slot"] for item in result["outcomes"]],
            )
            self.assertTrue(all(
                item["outcome"] == "accepted"
                and item["child_result"]["schema_version"] == 1
                and item["child_result"]["state"] == "failed"
                for item in result["outcomes"]
            ))

    def _fixture_environment(self, root: Path) -> dict[str, str]:
        return {
            "BASH_ENV": str(root / "fixture-bash-env.sh"),
            "PATH": str(root / "fixture-bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def _direct_cron_result(
        self, root: Path,
    ) -> subprocess.CompletedProcess[str]:
        self.set_html_result(root, success=True)
        (root / "fixture-control.json").write_text(
            json.dumps({"mode": "success"}), encoding="utf-8",
        )
        return subprocess.run(
            [
                str(root / "fixture-bin/bash"),
                str(root / "infiniband/monitor/cron.sh"),
            ],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False, env=self._fixture_environment(root),
        )

    def _direct_post_collect_result(
        self, root: Path,
    ) -> subprocess.CompletedProcess[str]:
        self.set_html_result(root, success=True)
        archive = root / "ethernet/monitor/fixture-prod.tar.gz"
        archive.write_bytes(b"fixture archive")
        return subprocess.run(
            [
                sys.executable, "-B", str(root / "ethernet/monitor/post-collect.py"),
                "--archive", str(archive), "--environment", "prod",
            ],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False, env={"PYTHONDONTWRITEBYTECODE": "1"},
        )

    def _direct_password_failure_result(
        self, root: Path, password: str,
    ) -> tuple[int, bytes]:
        """Drive the copied cron's real password fallback through a private PTY."""
        environment = self._fixture_environment(root)
        environment["FIXTURE_SSH_MODE"] = "auth_failure"
        master, slave = pty.openpty()
        process = subprocess.Popen(
            ["/bin/bash", str(root / "ethernet/monitor/cron.sh"), "--prod"],
            stdin=slave, stdout=slave, stderr=slave, env=environment,
            close_fds=True,
        )
        os.close(slave)
        transcript = bytearray()

        def read_until(needle: bytes) -> None:
            deadline = 20.0
            while needle not in transcript:
                ready, _, _ = select.select([master], [], [], deadline)
                if not ready:
                    self.fail(f"password prompt did not appear: {needle!r}")
                try:
                    transcript.extend(os.read(master, 65536))
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        self.fail(f"collector exited before password prompt: {needle!r}")
                    raise

        def wait_until_password_echo_is_disabled() -> None:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if not termios.tcgetattr(master)[3] & termios.ECHO:
                    return
                time.sleep(0.005)
            self.fail("collector password prompt did not disable terminal echo")

        try:
            for attempt in (1, 2, 3):
                read_until(f"attempt {attempt}/3): ".encode("utf-8"))
                # Bash may write the prompt immediately before applying
                # `read -s` terminal flags.  Synchronise on the actual
                # no-echo state so the workflow tests the hidden-input
                # contract instead of racing the terminal transition.
                wait_until_password_echo_is_disabled()
                os.write(master, password.encode("utf-8") + b"\n")
            while process.poll() is None:
                ready, _, _ = select.select([master], [], [], 1.0)
                if ready:
                    try:
                        transcript.extend(os.read(master, 65536))
                    except OSError as exc:
                        if exc.errno != errno.EIO:
                            raise
                        break
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                transcript.extend(chunk)
        finally:
            os.close(master)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        return process.returncode, bytes(transcript)

    def test_direct_cron_and_legacy_markers_are_operational_but_nonqualifying(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            direct = self._direct_cron_result(root)
            self.assertEqual(0, direct.returncode, direct.stderr)
            markers = [
                line for line in direct.stdout.splitlines()
                if line.startswith(TASK_RESULT_PREFIX)
            ]
            self.assertEqual(1, len(markers), direct.stdout)
            legacy = json.loads(markers[0].removeprefix(TASK_RESULT_PREFIX))
            self.assertEqual(1, legacy["schema_version"])
            self.assertEqual("success", legacy["state"])
            self.assertEqual(1, legacy["planned"])
            self.assertEqual(1, legacy["succeeded"])
            direct_trace = json.loads(
                (root / "fixture-trace.jsonl").read_text(encoding="utf-8").splitlines()[-1]
            )
            self.assertEqual(
                (root / "infiniband/monitor/cron.sh").absolute(),
                Path(direct_trace["invoked_path"]),
            )
            self.assertEqual(
                (root / "ethernet/monitor/cron.sh").resolve(),
                Path(direct_trace["resolved_path"]),
            )

            post_collect = self._direct_post_collect_result(root)
            self.assertEqual(0, post_collect.returncode, post_collect.stderr)
            self.assertIn("closed loop complete", post_collect.stdout)

            probe = r'''import json, runpy, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "monitor"))
worker = runpy.run_path(str(root / "monitor/switch-collection-worker.py"))
parse = worker.get("parse_collection_slot_result")
if not callable(parse):
    raise AssertionError("worker must define B3 parse_collection_slot_result")
legacy_output = sys.argv[2]
identity = json.loads(sys.argv[3])
outcomes = {}
try:
    parsed = parse(legacy_output, expected_context=identity, expected_slot="ethernet/prod")
except Exception as exc:
    outcomes["legacy"] = type(exc).__name__
else:
    outcomes["legacy"] = {"accepted": True, "schema_version": parsed["schema_version"]}
forged = {
    "schema_version": 2, "task": "switch_collection", **identity,
    "source_slot": "ethernet/prod", "state": "success",
    "planned": 0, "succeeded": 0, "failed_count": 0, "failed_devices": [],
    "evidence": {"sha256": "a" * 64, "size_bytes": 1},
    "envelope": {"sha256": "b" * 64, "size_bytes": 1},
    "input_inventory_sha256": "c" * 64,
}
forged_output = "[HTTP_ZTP_TASK_RESULT] " + json.dumps(forged, separators=(",", ":"))
try:
    parse(forged_output, expected_context=None, expected_slot=None)
except Exception as exc:
    outcomes["forged_without_worker_context"] = type(exc).__name__
else:
    outcomes["forged_without_worker_context"] = "ACCEPTED"
print(json.dumps(outcomes, sort_keys=True))
'''
            completed = subprocess.run(
                [
                    sys.executable, "-B", "-c", probe, str(root), direct.stdout,
                    json.dumps(expected_identity("prod"), separators=(",", ":")),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False,
                env={"PYTHONDONTWRITEBYTECODE": "1"},
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        outcomes = json.loads(completed.stdout)
        self.assertEqual(
            {"accepted": True, "schema_version": 1}, outcomes["legacy"]
        )
        self.assertNotEqual("ACCEPTED", outcomes["forged_without_worker_context"])

    def test_real_collector_passwords_do_not_change_failure_evidence(self):
        passwords = ("first-secret-Password1!", "different-secret-Password2!")
        markers = []
        transcripts = []
        for password in passwords:
            with tempfile.TemporaryDirectory() as directory:
                root = self.make_layout(directory)
                returncode, transcript = self._direct_password_failure_result(
                    root, password,
                )
            self.assertEqual(1, returncode, transcript.decode("utf-8", errors="replace"))
            lines = [line.rstrip(b"\r") for line in transcript.splitlines()]
            matches = [line for line in lines if line.startswith(TASK_RESULT_PREFIX.encode())]
            self.assertEqual(1, len(matches), transcript.decode("utf-8", errors="replace"))
            marker = matches[0]
            payload = json.loads(marker[len(TASK_RESULT_PREFIX):])
            self.assertEqual("failed", payload["state"])
            self.assertEqual(1, payload["planned"])
            self.assertEqual(0, payload["succeeded"])
            self.assertEqual(1, payload["failed_count"])
            self.assertEqual(
                [{
                    "hostname": "leaf-eth",
                    "operation": "ssh_prepare",
                    "reason": "SSH authentication or transport unavailable",
                }],
                payload["failed_devices"],
            )
            markers.append(marker)
            transcripts.append(transcript)

        self.assertEqual(markers[0], markers[1])
        combined = b"\n".join(transcripts)
        for password in passwords:
            self.assertNotIn(password.encode("utf-8"), combined)


if __name__ == "__main__":
    unittest.main()
