"""R0 (2026-10-23): v2 collection evidence through setup's collection output links.

setup makes <network>/monitor/<output> (eth-info, spx-link, ib-info, ib-link, nvsw-info, nvsw-link,
ufm-info, ufm-ibdiagnet) links to ../../DAY0-Prepare/<project>/99-output-monitor/<network>/<output>
(tools/project_contract.py::MONITOR_RUNTIME_MAPPINGS). cron.sh hands the emitter its archives below those
links; the evidence readers refused any symlink on the way, so on a real management server every worker
slot failed v2 publication (checked 2026-10-23 with a probe of collection_v2_emitter.regular_member).
Exactly those links, pointing exactly at their project directory, may now be walked; any other link is
still refused. Evidence bytes stay bound by sha256.

The completed cycle is replayed by the worker's own slot check (codex REQ7 retirement, batch 1,
2026-10-23: the old REQ7 IB cycle reader and its switch-runtime walker were retired with the rest of the
old chain)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
from test_cases.test_collection_v2_emitter_contract import EMITTER
from tools.project_contract import setup_collection_link_hop, summarize_collection_cycle_results

OUTPUTS = {"ethernet": ("eth-info", "spx-link"), "infiniband": ("ib-info", "ib-link"),
           "nvlink": ("nvsw-info", "nvsw-link")}


def link_outputs(root: Path, project: str = "site") -> None:
    for network, outputs in OUTPUTS.items():
        for output in outputs:
            real = root / "DAY0-Prepare" / project / "99-output-monitor" / network / output
            real.mkdir(parents=True, exist_ok=True)
            link = root / network / "monitor" / output
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(f"../../DAY0-Prepare/{project}/99-output-monitor/{network}/{output}")


class SetupCollectionLinkHopTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        link_outputs(self.root)

    def test_exactly_the_setup_collection_links_are_walkable(self):
        for network, outputs in OUTPUTS.items():
            for output in outputs:
                with self.subTest(link=f"{network}/monitor/{output}"):
                    self.assertTrue(setup_collection_link_hop(self.root, self.root / network / "monitor" / output))
        ufm = self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet"
        ufm.mkdir(parents=True)
        (self.root / "infiniband/monitor/ufm-ibdiagnet").symlink_to(
            "../../DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet")
        self.assertTrue(setup_collection_link_hop(self.root, self.root / "infiniband/monitor/ufm-ibdiagnet"))

    def test_any_other_link_is_refused(self):
        monitor = self.root / "infiniband/monitor"
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        cases = {
            "absolute target": str(self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ib-info"),
            "other directory": "../../elsewhere",
            "another network's directory": "../../DAY0-Prepare/site/99-output-monitor/nvlink/nvsw-info",
            "a dot project": "../../DAY0-Prepare/./99-output-monitor/infiniband/ib-info",
        }
        for label, target in cases.items():
            with self.subTest(label=label):
                (monitor / "ib-info").unlink()
                (monitor / "ib-info").symlink_to(target)
                self.assertFalse(setup_collection_link_hop(self.root, monitor / "ib-info"))
        (monitor / "ib-info").unlink()
        (monitor / "ib-info").symlink_to("../../DAY0-Prepare/site/99-output-monitor/infiniband/ib-info")
        # a link name setup never makes, and a path that is not a link at all
        (monitor / "notes").symlink_to("../../DAY0-Prepare/site/99-output-monitor/infiniband/ib-info")
        self.assertFalse(setup_collection_link_hop(self.root, monitor / "notes"))
        self.assertFalse(setup_collection_link_hop(self.root, self.root / "DAY0-Prepare"))
        # the project directory behind the link must itself be real
        real_project = self.root / "DAY0-Prepare/site"
        real_project.rename(self.root / "DAY0-Prepare/site-real")
        real_project.symlink_to("site-real")
        self.assertFalse(setup_collection_link_hop(self.root, monitor / "ib-info"))

    def test_the_emitter_and_worker_walkers_follow_the_rule(self):
        archive = self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ib-info/20261023-0110.tar.gz"
        archive.write_bytes(b"archive")
        relative = "infiniband/monitor/ib-info/20261023-0110.tar.gz"
        with mock.patch.object(EMITTER, "ROOT", self.root):
            self.assertEqual((relative, b"archive"),
                             EMITTER.regular_member(self.root / relative, "infiniband", "ib-info", ".tar.gz"))
        self.assertEqual(self.root / relative, WORKER._collection_artifact_path(self.root, relative))
        (self.root / "infiniband/monitor/ib-info").unlink()
        (self.root / "infiniband/monitor/ib-info").symlink_to("../../elsewhere-ib-info")
        (self.root / "elsewhere-ib-info").mkdir()
        (self.root / "elsewhere-ib-info/20261023-0110.tar.gz").write_bytes(b"archive")
        with mock.patch.object(EMITTER, "ROOT", self.root), self.assertRaisesRegex(ValueError, "symlink"):
            EMITTER.regular_member(self.root / relative, "infiniband", "ib-info", ".tar.gz")
        with self.assertRaisesRegex(ValueError, "symlink"):
            WORKER._collection_artifact_path(self.root, relative)


class ProdCycleFixture:
    """One completed prod cycle through the current real worker store and emitter, without a fake IB role.

    Inlined from test_collection_ib_cycle_binding_workflow (retired with the old REQ7 chain); only the
    parameters that test used for the D-70 and legacy-plan shapes are left out."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="setup-link-cycle-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        project = self.root / "project"
        project.mkdir()
        gate = WORKER.CollectionGate(
            str(project), "prod", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        self.gate = gate.__enter__()
        self.addCleanup(lambda: gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=self.gate)

    def _cycle(self):
        token = TOKEN_1 if self.store._read_witness() is None else TOKEN_2
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=token):
            identity = self.store.allocate_start(
                process_inspector=lambda _binding: "dead",
            )
        self.store.publish_launch(
            identity, pid=4321, boot_id="fixture-boot", process_start_time="9000",
            argv=["collector"], context={"scope": "prod"},
            credential_argv_positions=(), credential_context_names=(),
        )
        area = (self.root / "monitor/status/collection-cycles"
                / identity["project_key"] / "prod/switch_collection/artifacts"
                / f"{identity['sequence']:020d}")
        outcomes = []
        artifacts = {}
        stamp = f"20260925-{315 + identity['sequence']:04d}"
        for source_slot, family, host, typ, prefix, key in (
            ("ethernet/prod", "ethernet", "leaf-a", "eth", "eth-info", "eth"),
            ("infiniband/prod", "infiniband", "leaf-ib", "ib", "ib-info", "ib"),
            ("nvlink/prod", "nvlink", "nvsw01", "nvl", "nvsw-info", "nv"),
        ):
            leaf = source_slot.replace("/", "-")
            frozen = (
                "hostname,type,eth0_ip\n"
                f"{host},{typ},192.0.2.10\n"
            ).encode()
            inventory = area / "inputs" / f"{leaf}.csv"
            inventory.parent.mkdir(parents=True, exist_ok=True)
            inventory.write_bytes(frozen)
            plan = {"eth": [], "spx": [], "ib": [], "nv": [],
                    "dynamic_identities": [], "ufm": []}
            plan[key] = [f"{host}|192.0.2.10"]
            private = area / leaf
            context = {
                "identity": identity, "source_slot": source_slot,
                "artifacts": {
                    "evidence": str(private / "evidence-manifest.json"),
                    "envelope": str(private / "identity-envelope.json"),
                    "input_inventory": str(inventory),
                },
                "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
                "target_plan": plan,
                "target_plan_sha256": hashlib.sha256(EMITTER.canonical(plan)).hexdigest(),
                "air_dynamic_rows": [], "prod_runtime_rows": [],
                "runtime_input_hashes": {},
            }
            context_path = self.root / f"{leaf}-context.json"
            context_path.write_bytes(EMITTER.canonical(context))
            planned = self.root / f"{leaf}-planned.txt"
            planned.write_text(host + "\n", encoding="utf-8")
            legacy = self.root / f"{leaf}-legacy.txt"
            legacy.write_text(EMITTER.PREFIX + json.dumps({
                "schema_version": 1, "task": "switch_collection", "state": "success",
                "planned": 1, "succeeded": 1, "failed_count": 0,
                "failed_devices": [],
            }, separators=(",", ":")) + "\n", encoding="utf-8")
            info_name = stamp + ("-prod.tar.gz" if family == "ethernet" else ".tar.gz")
            info = self.root / family / "monitor" / prefix / info_name
            info.parent.mkdir(parents=True, exist_ok=True)
            info.write_bytes(f"literal {source_slot} info".encode())
            link = csv = None
            if family != "ethernet":
                link_prefix = "ib-link" if family == "infiniband" else "nvsw-link"
                link = self.root / family / "monitor" / link_prefix / info_name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.write_bytes(b"literal link archive")
                csv = link.with_suffix("").with_suffix(".csv")
                csv.write_bytes(b"port,peer\n1,fixture\n")
            args = argparse.Namespace(
                context_file=context_path, legacy_result_file=legacy,
                planned_file=planned, info=info, link=link, csv=csv,
                activity=None,
            )
            with mock.patch.object(EMITTER, "ROOT", self.root):
                child, evidence, envelope, sidecar = EMITTER.build_result(args)
                EMITTER.publish(sidecar, evidence, envelope)
            empty = {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0}
            outcomes.append({
                "source_slot": source_slot, "outcome": "accepted",
                "child_result": child,
                "evidence": {"stdout": empty, "stderr": empty, "returncode": 0},
            })
            artifacts[source_slot] = {"info": info, "envelope": sidecar / "identity-envelope.json"}
        summary = summarize_collection_cycle_results(
            identity, [item["child_result"] for item in outcomes],
            html_annotation={
                "attempted": False, "state": "not_attempted", "error_sha256": None,
            },
        )
        self.store.publish_completion(identity, {
            "identity": identity, "outcomes": outcomes, "summary": summary,
        })
        return identity, artifacts


class SetupLinkedCollectionCycleWorkflowTest(ProdCycleFixture, unittest.TestCase):
    """The real emitter and completion store with every collection output behind its setup link."""

    def setUp(self):
        super().setUp()
        link_outputs(self.root)

    def _completed_child(self, identity: dict, slot: str) -> tuple[dict, dict]:
        """The slot's child result as the completion record keeps it, and the context the emitter was given."""
        completion = self.store._validate_completion_record(
            WORKER._read_private_json(self.store.completion_path(identity["sequence"])), identity)
        [outcome] = [item for item in completion["run_result"]["outcomes"] if item["source_slot"] == slot]
        context = json.loads((self.root / f"{slot.replace('/', '-')}-context.json").read_bytes())
        return outcome["child_result"], context

    def test_a_cycle_collected_behind_setup_links_completes_and_replays(self):
        identity, artifacts = self._cycle()
        info = artifacts["infiniband/prod"]["info"]
        self.assertTrue((self.root / "infiniband/monitor/ib-info").is_symlink())
        self.assertTrue((self.root / "DAY0-Prepare/site/99-output-monitor/infiniband/ib-info" / info.name).is_file(),
                        "the archive physically lives in the project directory")
        [cycle] = read_completed_cycle_evidence(self.store)
        self.assertTrue(cycle.qualifying)
        # The worker replays the completed cycle's recorded IB child: frozen inventory and plan, completion-bound
        # evidence and envelope, and the base role bytes read through the setup links.
        child, context = self._completed_child(identity, "infiniband/prod")
        with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
            self.assertTrue(WORKER._collection_slot_artifacts_match(child, context["artifacts"], context),
                            "the IB base roles replay through the links")


if __name__ == "__main__":
    unittest.main()
