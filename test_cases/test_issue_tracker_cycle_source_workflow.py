"""Real v2 collector emitter → worker completion → read-only tracker handoff."""

import argparse
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1
from test_cases.test_collection_v2_emitter_contract import EMITTER
from tools.project_contract import summarize_collection_cycle_results


class IssueTrackerCycleSourceWorkflowTests(unittest.TestCase):
    def test_emitter_sidecar_worker_completion_yields_only_cycle_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = "/fixture-air-project"
            with WORKER.CollectionGate(
                project, "air", status_dir=root / "monitor/status",
                enforce_cooldown=False, lane="collection",
            ) as gate:
                self.assertTrue(gate.decision.allowed)
                store = WORKER.CollectionCycleStore(gate=gate)
                with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=TOKEN_1):
                    identity = store.allocate_start(process_inspector=lambda _binding: "dead")
                store.publish_launch(
                    identity, pid=4321, boot_id="fixture-boot", process_start_time="9000",
                    argv=["collector"], context={"scope": "air"},
                    credential_argv_positions=(), credential_context_names=(),
                )
                slot = "ethernet/air"
                leaf = (
                    root / "monitor/status/collection-cycles" / identity["project_key"]
                    / "air/switch_collection/artifacts/00000000000000000001"
                )
                sidecar = leaf / "ethernet-air"
                inventory = leaf / "inputs/ethernet-air.csv"
                inventory.parent.mkdir(parents=True)
                frozen = b"hostname,type,eth0_ip\nleaf-air,air,192.0.2.11\n"
                inventory.write_bytes(frozen)
                context = {
                    "identity": identity, "source_slot": slot,
                    "artifacts": {
                        "evidence": str(sidecar / "evidence-manifest.json"),
                        "envelope": str(sidecar / "identity-envelope.json"),
                        "input_inventory": str(inventory),
                    },
                    "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
                }
                context_path = root / "context.json"
                context_path.write_bytes(EMITTER.canonical(context))
                planned = root / "planned.txt"
                planned.write_text("leaf-air\n", encoding="utf-8")
                legacy = root / "legacy.txt"
                legacy.write_text(EMITTER.PREFIX + json.dumps({
                    "schema_version": 1, "task": "switch_collection",
                    "state": "success", "planned": 1, "succeeded": 1,
                    "failed_count": 0, "failed_devices": [],
                }) + "\n", encoding="utf-8")
                info = root / "ethernet/monitor/eth-info/20260925-0315.tar.gz"
                info.parent.mkdir(parents=True)
                info.write_bytes(b"archive")
                args = argparse.Namespace(
                    context_file=context_path, legacy_result_file=legacy,
                    planned_file=planned, info=info, link=None, csv=None,
                )
                with mock.patch.object(EMITTER, "ROOT", root):
                    child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                    EMITTER.publish(sidecar_dir, evidence, envelope)
                self.assertEqual(2, child["schema_version"])
                summary = summarize_collection_cycle_results(
                    identity, [child], html_annotation={
                        "attempted": False, "state": "not_attempted", "error_sha256": None,
                    },
                )
                empty = {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0}
                store.publish_completion(identity, {
                    "identity": identity,
                    "outcomes": [{
                        "source_slot": slot, "outcome": "accepted", "child_result": child,
                        "evidence": {"stdout": empty, "stderr": empty, "returncode": 0},
                    }],
                    "summary": summary,
                })
                handoff = read_completed_cycle_evidence(store)
                self.assertEqual(1, len(handoff))
                self.assertEqual(identity["cycle_id"], handoff[0].cycle_id)
                self.assertEqual((slot,), handoff[0].source_slots)
                self.assertTrue(handoff[0].qualifying)
                self.assertFalse(hasattr(handoff[0], "operations_json"))


if __name__ == "__main__":
    unittest.main()
