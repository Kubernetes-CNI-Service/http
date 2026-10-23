"""Workflow (REQ7 R1, 2026-10-23): one worker cycle's UFM IB analysis is bound into that cycle's evidence.

The R1 run binding (monitor/collection_ufm_run_binding.py) stays as collection evidence: the emitter binds
the UFM run that names this worker cycle, the worker replays it from the files before accepting the IB
slot, and the completion record keeps exactly that slot. No REQ7 reader consumes it any more: the old
completed-cycle reader (collection_ib_cycle_binding.py, issue_tracker_ib_runtime.py) was retired with the
codex REQ7 chain (batch 1, 2026-10-23), and the online Issue Tracker sync reads the project's
ufm-ibdiagnet output directly.

Real scripts: the P2P->CVT converter, infiniband/monitor/post-collect.py with the real analyzer, the v2
emitter (build_result + publish), the worker's slot check and completion store, and
monitor/collection_ufm_run_binding.py. The run record is written in the format of cron.sh's UFM lane
(ufm_run_record_write, exercised end to end by test_ufm_worker_collection), naming the cycle the worker
allocated. The worker/emitter cycle scaffold follows
test_setup_collection_link_evidence_workflow.ProdCycleFixture."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import xlsxwriter

from monitor.collection_ufm_run_binding import (
    UFM_RUN_ROLE_NAMES, UfmRunBindingHold, validate_ufm_run_binding,
)
from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1
from test_cases.test_collection_v2_emitter_contract import EMITTER
from test_cases.test_ib_post_collect import ibdiagnet_archive
from tools.project_contract import summarize_collection_cycle_results

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "20261023-0110-prod-0123456789abcdef"
NODE = "ufm02"


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def make_real_cvt(root: Path, project: Path, reports: Path, test: unittest.TestCase) -> Path:
    """The project CVT from the real p2p-to-validation.py. leaf01 sw1p1 <-> server01 mlx5_0 is cabled in
    the ibdiagnet fixture (test_ib_analysis_domain.write_ibdiagnet_fixture); leaf01 sw1p2 <-> server02
    mlx5_0 is not, so the report has one Missing link."""
    p2p = project / "site-p2p.xlsx"
    book = xlsxwriter.Workbook(str(p2p))
    sheet = book.add_worksheet("CL links")
    for row, values in enumerate((("Name", "Port", "Name", "Port"),
                                  ("leaf01", "sw1p1", "server01", "mlx5_0"),
                                  ("leaf01", "sw1p2", "server02", "mlx5_0"))):
        for column, value in enumerate(values):
            sheet.write(row, column, value)
    book.close()
    (project / "p2p.xlsx").symlink_to(p2p.name)
    converter = root / "converter"
    converter.mkdir()
    for name, text in (("01-inventory.log", "[IB-SW]\n*leaf*\n\n[server]\n*server*\n"),
                       ("02-port-mapping.log", ""), ("03-splitter.log", "")):
        (converter / name).write_text(text, encoding="utf-8")
    (converter / "p2p.xlsx").symlink_to(project / "p2p.xlsx")
    cvt = reports / "site-p2p-cvt.xlsx"
    converted = subprocess.run(
        [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
         "--output", str(cvt), "--inventory", str(converter / "01-inventory.log"),
         "--port-map", str(converter / "02-port-mapping.log"),
         "--splitter", str(converter / "03-splitter.log")],
        cwd=converter, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "XLSX_TO_CSV_BASE_DIR": str(converter)},
        capture_output=True, text=True, timeout=120, check=False)
    test.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
    return cvt


class UfmReq7IbCycleWorkflowTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="req7-ufm-ib-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.project = self.root / "DAY0-Prepare/site"
        self.project.mkdir(parents=True)
        gate = WORKER.CollectionGate(str(self.project), "prod", status_dir=self.root / "monitor/status",
                                     enforce_cooldown=False, lane="collection")
        self.gate = gate.__enter__()
        self.addCleanup(lambda: gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=self.gate)

    # -- the UFM lane's outputs, made by the real converter, post-collect and analyzer -------------------
    def run_ufm_chain(self) -> dict:
        monitor = self.root / "infiniband/monitor"
        monitor.mkdir(parents=True)
        shutil.copy2(ROOT / "infiniband/monitor/post-collect.py", monitor / "post-collect.py")
        tool = self.root / "tools/ibdiagnet-analyze-tool"
        tool.mkdir(parents=True)
        (tool / "analyze.py").symlink_to(ROOT / "tools/ibdiagnet-analyze-tool/analyze.py")
        reports = self.project / "99-output-p2p"
        collected = self.project / "99-output-monitor/infiniband/ufm-ibdiagnet"
        reports.mkdir(parents=True)
        collected.mkdir(parents=True)
        (monitor / "99-output-p2p").symlink_to(reports)          # the links setup creates
        (monitor / "ufm-ibdiagnet").symlink_to(collected)
        make_real_cvt(self.root, self.project, reports, self)
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        archive = ibdiagnet_archive(collected, f"{RUN_ID}_{NODE}_ibdiagnet2.tgz")
        shutil.rmtree(collected / "snapshot")
        (collected / f"{RUN_ID}_{NODE}_ibdiagnet2.done").write_text(
            "rc=0\nreason=\nhostname=ufm02.example.test\n", encoding="utf-8")
        analysed = subprocess.run(   # as cron.sh calls it: the archive through the setup link
            [sys.executable, "-B", str(monitor / "post-collect.py"),
             "--archive", str(monitor / "ufm-ibdiagnet" / archive.name)],
            capture_output=True, text=True, timeout=300, check=False, cwd=self.root, env=environment)
        self.assertEqual(0, analysed.returncode, analysed.stdout + analysed.stderr)
        stem = f"{RUN_ID}_{NODE}-ibdiagnet-topology-validation"
        return {"collected": collected, "reports": reports, "archive": archive,
                "done": collected / f"{RUN_ID}_{NODE}_ibdiagnet2.done",
                "report": reports / f"{stem}.xlsx", "receipt": reports / f"{stem}.receipt.json",
                "cvt": reports / "site-p2p-cvt.xlsx"}

    @staticmethod
    def write_run_record(chain: dict, cycle) -> Path:
        """What cron.sh's ufm_run_record_write leaves after a successful run."""
        def identity(path: Path) -> dict:
            raw = path.read_bytes()
            return {"name": path.name, "sha256": sha(raw), "size": len(raw)}
        record = chain["collected"] / f"{RUN_ID}.ufm-run.json"
        record.write_text(json.dumps({
            "schema": "ufm-ib-run-record-v1", "cycle": cycle,
            "recorded_at": "2026-10-23T01:21:00+00:00", "outcome": "ok", "reason": "",
            "run_id": RUN_ID, "node": NODE, "kind": "ibdiagnet",
            "done": identity(chain["done"]), "input": identity(chain["archive"]), "analysis": "ok",
            "report": identity(chain["report"]), "receipt": identity(chain["receipt"]),
            "ibdiagnet_failures_in_a_row": 0,
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return record

    # -- one completed prod cycle, the IB slot carrying the run record ----------------------------------
    def complete_cycle(self, *, record_cycle="this"):
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=TOKEN_1):
            identity = self.store.allocate_start(process_inspector=lambda _binding: "dead")
        self.store.publish_launch(
            identity, pid=4321, boot_id="fixture-boot", process_start_time="9000",
            argv=["collector"], context={"scope": "prod"},
            credential_argv_positions=(), credential_context_names=(),
        )
        chain = self.run_ufm_chain()
        record = self.write_run_record(chain, identity if record_cycle == "this" else None)
        area = (self.root / "monitor/status/collection-cycles" / identity["project_key"]
                / "prod/switch_collection/artifacts" / f"{identity['sequence']:020d}")
        outcomes, ib_slot, emitter_errors = [], None, ""
        for source_slot, family, host, typ, prefix, key in (
            ("ethernet/prod", "ethernet", "leaf-a", "eth", "eth-info", "eth"),
            ("infiniband/prod", "infiniband", "leaf-ib", "ib", "ib-info", "ib"),
            ("nvlink/prod", "nvlink", "nvsw01", "nvl", "nvsw-info", "nv"),
        ):
            leaf = source_slot.replace("/", "-")
            frozen = f"hostname,type,eth0_ip\n{host},{typ},192.0.2.10\n".encode()
            inventory = area / "inputs" / f"{leaf}.csv"
            inventory.parent.mkdir(parents=True, exist_ok=True)
            inventory.write_bytes(frozen)
            plan = {"eth": [], "spx": [], "ib": [], "nv": [], "dynamic_identities": [], "ufm": []}
            plan[key] = [f"{host}|192.0.2.10"]
            private = area / leaf
            context = {
                "identity": identity, "source_slot": source_slot,
                "artifacts": {"evidence": str(private / "evidence-manifest.json"),
                              "envelope": str(private / "identity-envelope.json"),
                              "input_inventory": str(inventory)},
                "input_inventory_sha256": sha(frozen), "target_plan": plan,
                "target_plan_sha256": sha(EMITTER.canonical(plan)),
                "air_dynamic_rows": [], "prod_runtime_rows": [], "runtime_input_hashes": {},
            }
            context_path = self.root / f"{leaf}-context.json"
            context_path.write_bytes(EMITTER.canonical(context))
            planned = self.root / f"{leaf}-planned.txt"
            planned.write_text(host + "\n", encoding="utf-8")
            legacy = self.root / f"{leaf}-legacy.txt"
            legacy.write_text(EMITTER.PREFIX + json.dumps({
                "schema_version": 1, "task": "switch_collection", "state": "success",
                "planned": 1, "succeeded": 1, "failed_count": 0, "failed_devices": [],
            }, separators=(",", ":")) + "\n", encoding="utf-8")
            info_name = "20261023-0110" + ("-prod.tar.gz" if family == "ethernet" else ".tar.gz")
            info = self.root / family / "monitor" / prefix / info_name
            info.parent.mkdir(parents=True, exist_ok=True)
            info.write_bytes(f"literal {source_slot} info".encode())
            link = csv = None
            if family != "ethernet":
                link = self.root / family / "monitor" / ("ib-link" if family == "infiniband" else "nvsw-link") / info_name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.write_bytes(b"literal link archive")
                csv = link.with_suffix("").with_suffix(".csv")
                csv.write_bytes(b"port,peer\n1,fixture\n")
            args = argparse.Namespace(
                context_file=context_path, legacy_result_file=legacy, planned_file=planned,
                info=info, link=link, csv=csv, activity=None,
                ufm_run_record=(self.root / "infiniband/monitor/ufm-ibdiagnet" / record.name
                                if source_slot == "infiniband/prod" else None),
            )
            stderr = io.StringIO()
            with mock.patch.object(EMITTER, "ROOT", self.root), contextlib.redirect_stderr(stderr):
                child, evidence, envelope, sidecar = EMITTER.build_result(args)
                EMITTER.publish(sidecar, evidence, envelope)
            if source_slot == "infiniband/prod":
                ib_slot = (child, context, json.loads(evidence), json.loads(envelope))
                emitter_errors = stderr.getvalue()
                with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
                    self.assertTrue(WORKER._collection_slot_artifacts_match(
                        child, context["artifacts"], context), "the worker accepts the emitted IB slot")
            empty = {"sha256": sha(b""), "size_bytes": 0}
            outcomes.append({"source_slot": source_slot, "outcome": "accepted", "child_result": child,
                             "evidence": {"stdout": empty, "stderr": empty, "returncode": 0}})
        summary = summarize_collection_cycle_results(
            identity, [item["child_result"] for item in outcomes],
            html_annotation={"attempted": False, "state": "not_attempted", "error_sha256": None},
        )
        self.store.publish_completion(identity, {"identity": identity, "outcomes": outcomes, "summary": summary})
        return identity, chain, record, ib_slot, emitter_errors

    def completed_ib_child(self, identity: dict) -> dict:
        """The IB child result exactly as the cycle's completion record keeps it."""
        completion = self.store._validate_completion_record(
            WORKER._read_private_json(self.store.completion_path(identity["sequence"])), identity)
        [outcome] = [item for item in completion["run_result"]["outcomes"]
                     if item["source_slot"] == "infiniband/prod"]
        return outcome["child_result"]

    def test_the_cycles_ufm_report_is_bound_into_the_completed_cycle_through_the_run_record(self):
        identity, chain, record, (child, context, evidence, envelope), errors = self.complete_cycle()
        self.assertEqual("", errors)
        self.assertEqual(["info_archive", "link_archive", "link_csv", *UFM_RUN_ROLE_NAMES],
                         [role["role"] for role in evidence["roles"]])
        self.assertEqual(1, child["planned"], "the UFM run never counts as a switch")
        binding = envelope["ufm_run_binding"]
        self.assertEqual((RUN_ID, NODE, "ibdiagnet", False), (
            binding["run_id"], binding["node"], binding["kind"], binding["degraded"]))
        self.assertEqual(sha(record.read_bytes()), binding["run_record_sha256"])
        # The completed cycle keeps exactly the IB child the worker accepted, and its UFM binding replays
        # from the files alone: this run's report of this CVT, named by this record.
        self.assertEqual(child, self.completed_ib_child(identity))
        replayed = validate_ufm_run_binding(identity, binding, evidence["roles"][3:], http_root=self.root)
        self.assertEqual(evidence["roles"][3:], replayed)
        by_role = {role["role"]: role for role in replayed}
        self.assertEqual(
            f"DAY0-Prepare/site/99-output-p2p/{RUN_ID}_{NODE}-ibdiagnet-topology-validation.xlsx",
            by_role["validation_report"]["relative_path"])
        self.assertEqual(sha(chain["report"].read_bytes()), by_role["validation_report"]["sha256"])
        self.assertEqual(sha(chain["cvt"].read_bytes()), binding["expected_topology_sha256"])
        self.assertEqual(sha(chain["cvt"].read_bytes()), by_role["expected_cvt"]["sha256"])
        self.assertEqual(sha(record.read_bytes()), by_role["ufm_run_record"]["sha256"])

        [cycle] = read_completed_cycle_evidence(self.store)
        self.assertTrue(cycle.qualifying)

        # Bytes changed after completion: the replay holds instead of returning a stale source.
        chain["report"].write_bytes(chain["report"].read_bytes() + b"\0")
        with self.assertRaises(UfmRunBindingHold):
            validate_ufm_run_binding(identity, binding, evidence["roles"][3:], http_root=self.root)
        with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
            self.assertFalse(WORKER._collection_slot_artifacts_match(child, context["artifacts"], context),
                             "the worker replays the UFM files instead of trusting the envelope")

    def test_a_ufm_run_of_another_cycle_leaves_the_switch_cycle_qualifying_without_ib_analysis(self):
        identity, _chain, _record, (child, context, evidence, envelope), errors = self.complete_cycle(
            record_cycle=None)
        self.assertIn("does not name this worker cycle", errors)
        self.assertEqual(["info_archive", "link_archive", "link_csv"],
                         [role["role"] for role in evidence["roles"]])
        self.assertNotIn("ufm_run_binding", envelope)
        [cycle] = read_completed_cycle_evidence(self.store)
        self.assertTrue(cycle.qualifying, "a UFM problem never changes the switch result")
        # The completed cycle keeps the three-role IB child, and the worker replays it from the files.
        completed = self.completed_ib_child(identity)
        self.assertEqual(child, completed)
        with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
            self.assertTrue(WORKER._collection_slot_artifacts_match(completed, context["artifacts"], context),
                            "the IB base roles replay without a UFM binding")


class UfmReq7RealCronCycleTest(unittest.TestCase):
    """The whole chain once more with the real worker and the real cron.sh (codex review 2026-10-22: one
    completed worker cycle, from the fake UFM's successful ibdiagnet to the report and the same-cycle run
    record): the layout of test_ufm_worker_collection.UfmWorkerIbdiagnetSuccessWorkflowTest, but with the
    real analyzer, the real CVT, a real ibdiagnet2 snapshot on the fake UFM, the data link into the project
    and the worker's project being that project, as on a management server after setup."""

    def test_the_real_cron_cycle_binds_its_ufm_report_for_req7(self):
        import test_cases.test_collection_cycle_handoff_workflow as handoff
        import test_cases.test_ufm_worker_collection as worker_chain
        from test_cases.test_ib_analysis_domain import write_ibdiagnet_fixture

        chain = worker_chain.UfmWorkerIbdiagnetSuccessWorkflowTest(
            "test_a_worker_cycle_reaches_a_successful_ibdiagnet_report_and_the_record_names_that_cycle")
        harness = handoff.CollectionCycleHandoffWorkflowTests(
            "test_managed_real_collectors_emit_run_bound_v2_evidence")
        with tempfile.TemporaryDirectory() as directory:
            root = chain.make_layout(harness, directory).resolve()
            project = root / "DAY0-Prepare/site"
            reports = project / "99-output-p2p"
            monitor = root / "infiniband/monitor"
            collected = project / "99-output-monitor/infiniband/ufm-ibdiagnet"
            collected.mkdir(parents=True)
            (monitor / "ufm-ibdiagnet").rmdir()
            (monitor / "ufm-ibdiagnet").symlink_to(collected)
            (reports / "site-cvt.xlsx").unlink()                 # the layout's placeholder CVT
            make_real_cvt(root, project, reports, self)
            analyzer = root / "tools/ibdiagnet-analyze-tool/analyze.py"
            analyzer.unlink()
            analyzer.symlink_to(ROOT / "tools/ibdiagnet-analyze-tool/analyze.py")
            snapshot = root / "fixture-ibdiagnet2"
            snapshot.mkdir()
            write_ibdiagnet_fixture(snapshot)
            with open(root / "fixture-bash-env.sh", "a", encoding="utf-8") as shims:
                shims.write(f"export FAKE_IBDIAGNET_FIXTURE={snapshot}\n")
            bootstrap = handoff.BOOTSTRAP
            self.assertEqual((2, 3), (bootstrap.count('b"/project-fixture"'), bootstrap.count('"/project-fixture"')))
            bootstrap = bootstrap.replace('b"/project-fixture"', repr(str(project).encode())).replace(
                '"/project-fixture"', repr(str(project)))
            with mock.patch.object(handoff, "BOOTSTRAP", bootstrap):
                completed, payload, traces = chain.run_worker(harness, root)
            log = (monitor / "cronjob.log").read_text(encoding="utf-8") if (monitor / "cronjob.log").exists() else ""

            self.assertEqual(0, completed.returncode, completed.stderr + log)
            self.assertTrue(payload and payload["returned"], f"{payload}\n{log}")
            result = payload["result"]
            self.assertIsNotNone(result["summary"], f"{json.dumps(result['outcomes'], indent=1)[:4000]}\n{log}")
            self.assertTrue(result["summary"]["qualifying"], log)
            [record_path] = collected.glob("*.ufm-run.json")
            record = json.loads(record_path.read_text(encoding="utf-8"))
            self.assertEqual(result["identity"], record["cycle"])
            self.assertEqual(("ok", "ok"), (record["outcome"], record["analysis"]), log)

            ib = next(item for item in result["outcomes"] if item["source_slot"] == "infiniband/prod")
            private = (root / "monitor/status/collection-cycles" / result["identity"]["project_key"]
                       / "prod/switch_collection/artifacts" / f"{result['identity']['sequence']:020d}"
                       / "infiniband-prod")
            evidence = json.loads((private / "evidence-manifest.json").read_text(encoding="utf-8"))
            envelope = json.loads((private / "identity-envelope.json").read_text(encoding="utf-8"))
            self.assertEqual(["info_archive", "link_archive", "link_csv", *UFM_RUN_ROLE_NAMES],
                             [role["role"] for role in evidence["roles"]], log)
            self.assertEqual(sha(record_path.read_bytes()), envelope["ufm_run_binding"]["run_record_sha256"])
            # the worker accepted this slot only after its own replay of the UFM files
            self.assertEqual(("accepted", 2), (ib["outcome"], ib["child_result"]["schema_version"]))
            self.assertEqual(1, ib["child_result"]["planned"], "the UFM run never counts as a switch")
            self.assertEqual(evidence["roles"][3:], validate_ufm_run_binding(
                result["identity"], envelope["ufm_run_binding"], evidence["roles"][3:], http_root=root))
            report_role = evidence["roles"][3 + UFM_RUN_ROLE_NAMES.index("validation_report")]
            self.assertEqual(f"DAY0-Prepare/site/99-output-p2p/{record['run_id']}_{record['node']}"
                             "-ibdiagnet-topology-validation.xlsx", report_role["relative_path"])
            # The harness does not persist completion records; ProdCycle-based
            # UfmReq7IbCycleWorkflowTest carries the same evidence on into the completion record.


if __name__ == "__main__":
    unittest.main()
