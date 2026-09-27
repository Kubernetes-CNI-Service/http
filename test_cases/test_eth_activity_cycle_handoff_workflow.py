"""Hermetic real ETH analyzer -> cron -> emitter -> worker cycle handoff.

SSH/SCP are shimmed; the production Python and Shell entrypoints are copied
byte-for-byte into a private fixture root.  No real crontab or device runs.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from test_cases import test_collection_cycle_handoff_workflow as handoff_workflow
from test_cases.test_collection_cycle_worker_contract import WORKER
from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_activity_source import validate_eth_cycle_binding


ROOT = Path(__file__).resolve().parents[1]


class EthActivityCycleHandoffWorkflowTests(unittest.TestCase):
    def test_real_analyzer_sidecar_is_bound_to_worker_completion(self):
        helper = handoff_workflow.CollectionCycleHandoffWorkflowTests(
            "test_managed_real_collectors_emit_run_bound_v2_evidence"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = helper.make_layout(directory)
            boundary = root / "fixture-bin/bash"
            script = boundary.read_text(encoding="utf-8")
            script = script.replace("import sys\n", "import sys\nimport tempfile\n", 1)
            fifo = ("    read_fd, write_fd = os.pipe()\n"
                    "    os.write(write_fd, raw_context)\n"
                    "    os.close(write_fd)\n"
                    "    os.dup2(read_fd, descriptor)\n"
                    "    os.close(read_fd)\n")
            self.assertIn(fifo, script)
            script = script.replace(fifo, (
                "    with tempfile.TemporaryFile() as held_context:\n"
                "        held_context.write(raw_context)\n"
                "        held_context.flush()\n"
                "        held_context.seek(0)\n"
                "        os.dup2(held_context.fileno(), descriptor)\n"
            ))
            marker = '(root / "fixture-child-stdout.txt").write_text(stdout, encoding="utf-8")'
            self.assertIn(marker, script)
            marker_err = '(root / "fixture-child-stderr.txt").write_text(stderr, encoding="utf-8")'
            self.assertIn(marker_err, script)
            script = script.replace(
                marker_err,
                marker_err + '\n(root / f"fixture-child-{Path(arguments[0]).parent.parent.name}-stderr.txt").write_text(stderr, encoding="utf-8")',
            )
            boundary.write_text(script.replace(
                marker,
                marker + '\n(root / f"fixture-child-{Path(arguments[0]).parent.parent.name}-stdout.txt").write_text(stdout, encoding="utf-8")',
            ), encoding="utf-8")
            analyzer = root / "tools/lldp-analyze-tool"
            shutil.copy2(ROOT / "tools/lldp-analyze-tool/analyze_lldp.py",
                         analyzer / "analyze_lldp.py")
            shutil.copy2(ROOT / "tools/lldp-analyze-tool/build_report.py",
                         analyzer / "build_report.py")
            shutil.copy2(ROOT / "monitor/issue_tracker_activity_source.py",
                         root / "monitor/issue_tracker_activity_source.py")
            p2p = root / "ztp/config/cumulus/template/P2P"
            p2p.mkdir(parents=True)
            project = root / "DAY0-Prepare/fixture-project"
            project.mkdir(parents=True)
            selected = project / "selected-fabric.xlsx"
            selected.write_bytes(b"literal selected P2P source bytes")
            (project / "p2p.xlsx").symlink_to(selected.name)
            (p2p / "p2p.xlsx").symlink_to(
                os.path.relpath(project / "p2p.xlsx", p2p),
            )
            (p2p / "01-inventory.log").write_bytes(b"[Eth-SW]\nleaf-*\n")
            topology_rules = root / "ztp/config/topology_rules.py"
            shutil.copy2(ROOT / "ztp/config/topology_rules.py", topology_rules)
            output = p2p / "output-p2p"
            output.mkdir()
            dot = b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n'
            (output / "selected-fabric-lldpq.dot").write_bytes(dot)
            (analyzer / "99-output-p2p/selected-fabric-lldpq.dot").write_bytes(dot)
            shutil.copy2(ROOT / "tools/lldp-analyze-tool/04-lldp-device-aliases.json",
                         analyzer / "04-lldp-device-aliases.json")

            bootstrap = handoff_workflow.BOOTSTRAP
            self.assertIn('    "sequence": 7,', bootstrap)
            with mock.patch.object(
                handoff_workflow, "BOOTSTRAP",
                bootstrap.replace('    "sequence": 7,', '    "sequence": 1,', 1),
            ):
                completed, payload, traces = helper.run_workflow(
                    root, "prod", action="persisted",
                )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload, completed.stdout)
            assert payload is not None
            self.assertTrue(payload["returned"], payload)
            self.assertEqual(
                {"start", "launch", "completion"},
                {record["kind"] for record in payload["persisted"]["records"].values()},
            )
            eth = next(item for item in payload["result"]["outcomes"]
                       if item["source_slot"] == "ethernet/prod")
            self.assertEqual("accepted", eth["outcome"],
                             "\n".join(f"{path}: {path.read_text(errors='replace')[:3000]}"
                                       for path in root.rglob("*activity*.json")))
            binding = next(item for item in traces
                           if item["context"]["source_slot"] == "ethernet/prod")
            activity = binding["context"]["activity"]
            self.assertEqual("ethernet/prod", activity["source_slot"])
            self.assertEqual(selected.read_bytes(),
                             Path(activity["topology"]["path"]).read_bytes())
            self.assertEqual(dot, Path(activity["sources"]["dot"]["path"]).read_bytes())
            sidecar_dir = Path(binding["context"]["artifacts"]["evidence"]).parent
            private_sidecar = sidecar_dir / "activity-observation.json"
            self.assertTrue(private_sidecar.is_file(),
                            (root / "fixture-child-ethernet-stdout.txt").read_text() + "\n" +
                            (root / "fixture-child-ethernet-stderr.txt").read_text())
            evidence = json.loads((sidecar_dir / "evidence-manifest.json").read_bytes())
            role = next(item for item in evidence["roles"]
                        if item["role"] == "activity_observation")
            self.assertEqual(hashlib.sha256(private_sidecar.read_bytes()).hexdigest(),
                             role["sha256"])
            self.assertEqual(payload["result"]["identity"],
                             json.loads(private_sidecar.read_bytes())["cycle_binding"]["identity"])
            with mock.patch.object(WORKER, "HTTP_ROOT", root.resolve()):
                self.assertTrue(WORKER._collection_slot_artifacts_match(
                    eth["child_result"], binding["context"]["artifacts"],
                    binding["context"],
                ))
                replay = copy.deepcopy(binding["context"])
                replay["identity"]["run_token"] = "abcdefabcdef4abc8abcdefabcdefabc"
                replay["identity"] = WORKER.build_collection_cycle_identity(
                    "/project-fixture", "prod", 1,
                    replay["identity"]["run_token"],
                )
                self.assertFalse(WORKER._collection_slot_artifacts_match(
                    eth["child_result"], binding["context"]["artifacts"], replay,
                ), "an older sidecar cannot bind to a different worker cycle")
                wrong_slot = copy.deepcopy(binding["context"])
                wrong_slot["source_slot"] = "ethernet/air"
                self.assertFalse(WORKER._collection_slot_artifacts_match(
                    eth["child_result"], binding["context"]["artifacts"], wrong_slot,
                ), "an Ethernet prod sidecar cannot bind to the air slot")
                info_role = evidence["roles"][0]
                info = root / info_role["relative_path"]
                held_info = info.read_bytes()
                info.write_bytes(b"foreign archive Y")
                try:
                    self.assertFalse(WORKER._collection_slot_artifacts_match(
                        eth["child_result"], binding["context"]["artifacts"],
                        binding["context"],
                    ), "a different archive cannot substitute for sidecar source X")
                finally:
                    info.write_bytes(held_info)
                frozen_dot = Path(activity["sources"]["dot"]["path"])
                held_dot = frozen_dot.read_bytes()
                frozen_dot.write_bytes(held_dot + b"// later plan mutation\n")
                try:
                    self.assertFalse(WORKER._collection_slot_artifacts_match(
                        eth["child_result"], binding["context"]["artifacts"],
                        binding["context"],
                    ), "post-launch plan mutation cannot pass completion")
                finally:
                    frozen_dot.write_bytes(held_dot)
            with WORKER.CollectionGate(
                "/project-fixture", "prod", status_dir=root / "monitor/status",
                enforce_cooldown=False, lane="collection",
            ) as gate:
                store = WORKER.CollectionCycleStore(gate=gate)
                cycles = read_completed_cycle_evidence(store)
                self.assertEqual(1, len(cycles))
                self.assertEqual(payload["result"]["identity"]["cycle_id"],
                                 cycles[0].cycle_id)
                forged_sidecar = root / "forged-B.activity.json"
                forged = json.loads(private_sidecar.read_bytes())
                forged["cycle_binding"]["identity"] = (
                    WORKER.build_collection_cycle_identity(
                        "/project-fixture", "prod", 2,
                        "abcdefabcdef4abc8abcdefabcdefabc",
                    )
                )
                validate_eth_cycle_binding(forged["cycle_binding"])
                forged_sidecar.write_text(json.dumps(forged), encoding="utf-8")
                self.assertEqual(cycles, read_completed_cycle_evidence(store),
                                 "a caller-authored sidecar adds no durable worker cycle")


if __name__ == "__main__":
    unittest.main()
