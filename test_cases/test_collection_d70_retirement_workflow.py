"""Workflow: a completed IB prod cycle carries only its base roles, and a D-70-shaped IB child is refused end
to end, even with a stale D-70 producer module importable.

Codex REQ7 retirement, batch 2 (2026-10-24). Real scripts: monitor/switch-collection-worker.py (its
CollectionGate, which is monitor/switch_collection_gate.py, its CollectionCycleStore and its slot replay
_collection_slot_artifacts_match) and monitor/collection_v2_emitter.py (build_result and publish), driven
for one completed prod cycle by test_setup_collection_link_evidence_workflow.ProdCycleFixture.

Before the retirement a worker context with ``ib_analysis`` made the emitter mint six D-70 roles (nine in
all) plus an ``ib_analysis_binding`` envelope, and the worker accepted that child once
monitor/collection_ib_producer.py vouched for it. A deployed host may still hold that retired file (a sync
without delete), so the stand-in module of test_collection_d70_retirement is made importable and vouches
for everything: the emitter must refuse the D-70 context, the worker's replay must refuse the D-70 child,
and neither may consult the stand-in. The direct counterpart is test_collection_d70_retirement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_collection_d70_retirement import (
    BASE_ROLE_NAMES, D70_BINDING_KEYS, EMITTER, d70_binding, stale_producer,
)
from test_cases.test_setup_collection_link_evidence_workflow import ProdCycleFixture

SLOT = "infiniband/prod"
LEAF = "infiniband-prod"


def canonical_digest(payload: bytes) -> dict:
    return {"sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}


class D70RetiredCycleWorkflowTest(ProdCycleFixture, unittest.TestCase):
    def completed_ib_child(self) -> tuple:
        """One completed cycle: the IB child as the completion record keeps it, its context and artifacts."""
        identity, artifacts = self._cycle()
        completion = self.store._validate_completion_record(
            WORKER._read_private_json(self.store.completion_path(identity["sequence"])), identity)
        [outcome] = [item for item in completion["run_result"]["outcomes"] if item["source_slot"] == SLOT]
        context = json.loads((self.root / f"{LEAF}-context.json").read_bytes())
        bindings = context["artifacts"]
        evidence = json.loads(Path(bindings["evidence"]).read_bytes())
        envelope = json.loads(Path(bindings["envelope"]).read_bytes())
        # The completed cycle itself: three base roles, no D-70 envelope key, and it replays (control).
        self.assertEqual(BASE_ROLE_NAMES, [role["role"] for role in evidence["roles"]])
        self.assertEqual([], sorted(key for key in envelope if key.startswith("ib_analysis")))
        with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
            self.assertTrue(WORKER._collection_slot_artifacts_match(outcome["child_result"], bindings, context),
                            "control: the real completed IB child replays")
        return outcome["child_result"], context, evidence, envelope, artifacts

    def test_the_emitter_refuses_a_d70_context_for_the_cycles_real_collector_outputs(self):
        _child, context, _evidence, _envelope, artifacts = self.completed_ib_child()
        d70_context_file = self.root / f"{LEAF}-d70-context.json"
        d70_context_file.write_bytes(EMITTER.canonical({**context, "ib_analysis": d70_binding()}))
        info = artifacts[SLOT]["info"]
        link = self.root / "infiniband/monitor/ib-link" / info.name
        args = argparse.Namespace(
            context_file=d70_context_file, legacy_result_file=self.root / f"{LEAF}-legacy.txt",
            planned_file=self.root / f"{LEAF}-planned.txt", info=info, link=link,
            csv=link.with_suffix("").with_suffix(".csv"), activity=None,
        )
        with stale_producer() as stale, mock.patch.object(EMITTER, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "worker context shape is invalid"):
                EMITTER.build_result(args)
        self.assertEqual([], stale.calls, "the stale D-70 producer was never consulted")

    def test_the_worker_replay_refuses_a_d70_shaped_child_of_the_completed_cycle(self):
        child, context, evidence, envelope, _artifacts = self.completed_ib_child()
        bindings = context["artifacts"]
        evidence_path, envelope_path = Path(bindings["evidence"]), Path(bindings["envelope"])
        frozen = Path(bindings["input_inventory"]).read_bytes()
        binding = d70_binding()
        d70_context = {**context, "ib_analysis": binding}
        # What the retired emitter wrote for such a context: six more roles and the binding in the envelope,
        # with the child's digests matching the rewritten files.
        forged_evidence = WORKER._canonical_json_line({"roles": evidence["roles"] + binding["roles"]})
        forged_envelope_body = dict(envelope)
        forged_envelope_body["evidence"] = canonical_digest(forged_evidence)
        forged_envelope_body["ib_analysis_context_sha256"] = hashlib.sha256(
            WORKER._canonical_json_line(d70_context)).hexdigest()
        forged_envelope_body["ib_analysis_binding"] = {key: binding[key] for key in D70_BINDING_KEYS}
        forged_envelope = WORKER._canonical_json_line(forged_envelope_body)
        evidence_path.write_bytes(forged_evidence)
        envelope_path.write_bytes(forged_envelope)
        forged_child = {**child, "evidence": canonical_digest(forged_evidence),
                        "envelope": canonical_digest(forged_envelope)}
        with stale_producer() as stale, mock.patch.object(WORKER, "HTTP_ROOT", self.root):
            self.assertFalse(WORKER._collection_validate_artifact_roles(
                json.loads(forged_evidence), root=self.root, child=forged_child, inventory=frozen,
                context=d70_context,
            ), "the worker's role check refuses the six D-70 roles")
            self.assertFalse(WORKER._collection_slot_artifacts_match(forged_child, bindings, d70_context),
                             "the worker's replay refuses the D-70 child")
        self.assertEqual([], stale.calls, "the stale D-70 producer was never consulted")


if __name__ == "__main__":
    unittest.main()
