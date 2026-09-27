"""Real collector/emitter completion leaves the IB report role absent."""

from __future__ import annotations

import hashlib
import json
import os
import argparse
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.collection_ib_cycle_binding import (
    IbCycleRoleHold, IbCycleRoleSource, inspect_completed_ib_cycle_roles,
)
from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import (
    IbBoundCycleReport, IbKWindow, IbReportLink, IbRuntimeHoldError,
    IbWhitelistedKWindow, read_ib_k_window, read_whitelisted_ib_k_window,
)
from monitor.issue_tracker_state_owner import (
    initialize_tracker_state, set_k, tracker_writer,
)
from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
from test_cases.test_collection_v2_emitter_contract import EMITTER
from tools.project_contract import summarize_collection_cycle_results
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx


class ProdCycleFixture:
    """Exercise the current real worker and emitter, without a fake IB role."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="req7-ib-role-")
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

    def _cycle(self, *, ib_analysis=None):
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
                    "dynamic_identities": []}
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
            if source_slot == "infiniband/prod" and ib_analysis is not None:
                context["ib_analysis"] = ib_analysis
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


class IbCycleRoleWorkflowTests(ProdCycleFixture, unittest.TestCase):

    def _tracker_state(self):
        project = self.root / "project"
        publication = project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            project, publication, initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="req7-ib-window-fixture",
        )
        return project, publication

    def test_real_k_cold_start_is_read_only_and_cannot_skip_missing_roles(self) -> None:
        project, publication = self._tracker_state()
        with tracker_writer(project, publication) as token:
            empty = read_ib_k_window(self.store, http_root=self.root, token=token)
            self.assertIsInstance(empty, IbKWindow)
            self.assertEqual(("pending", "cold_start", 0, 3),
                             (empty.status, empty.reason, empty.observed, empty.required))
            self.assertFalse(empty.qualified)
            self.assertEqual((), empty.rows)
            self._cycle()
            one = read_ib_k_window(self.store, http_root=self.root, token=token)
            self.assertEqual(("pending", "cold_start", 1, 3),
                             (one.status, one.reason, one.observed, one.required))
            set_k(token, new_k=1, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="req7-k-one",
                  expected_revision=0)
            with self.assertRaises(IbRuntimeHoldError):
                read_ib_k_window(self.store, http_root=self.root, token=token)

    def test_k_token_for_another_project_cannot_rebind_cycle(self) -> None:
        foreign = self.root / "foreign-project"
        foreign.mkdir()
        publication = foreign / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            foreign, publication, initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="req7-foreign-k",
        )
        with tracker_writer(foreign, publication) as token:
            with self.assertRaises(IbRuntimeHoldError):
                read_ib_k_window(self.store, http_root=self.root, token=token)

    def test_k_reducer_binds_two_real_completions_and_latest_actual(self) -> None:
        project, publication = self._tracker_state()
        self._cycle()
        self._cycle()
        cycles = read_completed_cycle_evidence(self.store)
        first = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        latest = IbReportLink(
            "Mis-wiring", first.expected_endpoints,
            ("server03", "mlx5_2"), "Miswired_Links", 3,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                str(cycle.sequence) * 64, "a" * 64,
                (first if cycle.sequence == 1 else latest,),
            ) for cycle in cycles
        }
        with tracker_writer(project, publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="req7-k-two",
                  expected_revision=0)
            # Only the protected report decoder is replaced here; real worker
            # completions and durable K are still read, and this mock cannot
            # be cited as protected-source or Stage-L acceptance evidence.
            with mock.patch(
                "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
                side_effect=lambda _store, *, http_root, sequence: reports[sequence],
            ):
                window = read_ib_k_window(self.store, http_root=self.root, token=token)
                self.assertEqual("history_sufficient", window.status)
                self.assertEqual((latest,), window.rows)
                self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                                 window.cycle_ids)
                self.assertFalse(window.qualified)
                reports[2] = IbBoundCycleReport(
                    cycles[1].cycle_id, 2, cycles[1].completion_sha256,
                    "2" * 64, "b" * 64, (latest,),
                )
                with self.assertRaises(IbRuntimeHoldError):
                    read_ib_k_window(self.store, http_root=self.root, token=token)

    def test_ib_k_whitelist_uses_both_expected_endpoints_and_held_workbook(self) -> None:
        project, publication = self._tracker_state()
        self._cycle()
        cycle = read_completed_cycle_evidence(self.store)[0]
        rule_book = publication / "local.xlsx"
        rule_book.write_bytes(literal_xlsx(rules=("SERVER01",)))
        row = IbReportLink(
            "Link Down", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("", ""), "Missing_Links", 2,
        )
        bound = IbBoundCycleReport(
            cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
            "a" * 64, "b" * 64, (row,),
        )
        with tracker_writer(project, publication) as token:
            set_k(token, new_k=1, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="req7-k-w1",
                  expected_revision=0)
            # Protected report decoding is the only patched seam. The real
            # workbook reader, W1 evaluator, durable K and worker cycle run.
            with mock.patch(
                "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
                return_value=bound,
            ):
                result = read_whitelisted_ib_k_window(
                    self.store, http_root=self.root, token=token,
                    workbook_path=rule_book,
                )
                self.assertIsInstance(result, IbWhitelistedKWindow)
                self.assertEqual((), result.kept_rows)
                self.assertEqual((row,), tuple(skip.row for skip in result.skips))
                self.assertEqual("server01", result.skips[0].matched_rule)
                self.assertFalse(result.qualified)
                rule_book.write_bytes(literal_xlsx(rules=("other-host",)))
                changed = read_whitelisted_ib_k_window(
                    self.store, http_root=self.root, token=token,
                    workbook_path=rule_book,
                )
                self.assertEqual((row,), changed.kept_rows)
                self.assertNotEqual(result.workbook_sha256, changed.workbook_sha256)
                rule_book.write_bytes(literal_xlsx(rules=("leaf-*",)))
                by_a = read_whitelisted_ib_k_window(
                    self.store, http_root=self.root, token=token,
                    workbook_path=rule_book,
                )
                self.assertEqual("leaf-*", by_a.skips[0].matched_rule)
                from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
                reads = 0

                def changing_workbook(path):
                    nonlocal reads
                    snapshot = read_whitelist_workbook(path)
                    reads += 1
                    if reads == 1:
                        rule_book.write_bytes(literal_xlsx(rules=("other-host",)))
                    return snapshot

                with mock.patch(
                    "monitor.issue_tracker_whitelist_workbook.read_whitelist_workbook",
                    side_effect=changing_workbook,
                ):
                    with self.assertRaises(IbRuntimeHoldError):
                        read_whitelisted_ib_k_window(
                            self.store, http_root=self.root, token=token,
                            workbook_path=rule_book,
                        )

    def test_completed_nine_roles_replay_as_read_only_ib_source(self) -> None:
        from monitor.collection_ib_producer import IB_ROLE_NAMES

        roles = []
        for name in IB_ROLE_NAMES:
            path = self.root / "DAY0-Prepare/fabric-a/99-output-ufm/runs" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            body = ("worker-owned-" + name).encode()
            path.write_bytes(body)
            roles.append({
                "role": name, "state": "present",
                "relative_path": path.relative_to(self.root).as_posix(),
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
            })
        binding = {
            "run_id": "synthetic-cycle", "node": "EXAMPLE-UFM01",
            "authority_sha256": "a" * 64,
            "expected_topology_sha256": "b" * 64,
            "attestation_sha256": "c" * 64, "roles": roles,
        }
        # The protected producer's real replay is independently tested in
        # test_collection_ib_producer_workflow; this fixture binds its return
        # through the real emitter, durable completion and IB cycle reader.
        with mock.patch(
            "monitor.collection_ib_producer.validate_ib_completion_attestation",
            return_value=roles,
        ) as replay:
            identity, _ = self._cycle(ib_analysis=binding)
            source = inspect_completed_ib_cycle_roles(
                self.store, http_root=self.root, sequence=identity["sequence"],
            )
            self.assertIsInstance(source, IbCycleRoleSource)
            self.assertEqual(identity["cycle_id"], source.cycle_id)
            self.assertEqual(("info_archive", "link_archive", "link_csv", *IB_ROLE_NAMES),
                             source.roles)
            self.assertEqual(roles[3]["relative_path"], source.report_relative_path)
            self.assertEqual(roles[3]["sha256"], source.report_sha256)
            self.assertEqual(binding["expected_topology_sha256"],
                             source.expected_topology_sha256)
            self.assertFalse(source.qualified)
            self.assertGreaterEqual(replay.call_count, 3)
            report = self.root / roles[3]["relative_path"]
            report.write_bytes(b"swapped-report")
            with self.assertRaises(IbCycleRoleHold):
                inspect_completed_ib_cycle_roles(
                    self.store, http_root=self.root, sequence=identity["sequence"],
                )

    def test_real_completed_prod_cycle_still_lacks_all_six_ib_roles(self) -> None:
        identity, _artifacts = self._cycle()
        self.assertTrue(read_completed_cycle_evidence(self.store)[0].qualifying)
        gap = inspect_completed_ib_cycle_roles(
            self.store, http_root=self.root, sequence=identity["sequence"],
        )
        self.assertEqual(identity["cycle_id"], gap.cycle_id)
        self.assertEqual(("info_archive", "link_archive", "link_csv"), gap.roles)
        self.assertEqual((
            "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
            "validation_report", "report_provenance", "ufm_completion_receipt",
        ), gap.missing_roles)
        self.assertRegex(gap.completion_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(gap.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse(gap.qualified)

    def test_hand_added_six_roles_and_same_mtime_do_not_gain_authority(self) -> None:
        identity, artifacts = self._cycle()
        evidence = artifacts["infiniband/prod"]["envelope"].with_name(
            "evidence-manifest.json"
        )
        baseline = evidence.read_bytes()
        stamp = evidence.stat().st_mtime_ns
        payload = json.loads(baseline)
        payload["roles"].extend({
            "role": name, "state": "present", "relative_path": "not-worker-owned",
            "sha256": hashlib.sha256(b"forged").hexdigest(), "size_bytes": 6,
        } for name in (
            "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
            "validation_report", "report_provenance", "ufm_completion_receipt",
        ))
        evidence.write_bytes((json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ) + "\n").encode())
        os.utime(evidence, ns=(stamp, stamp))
        with self.assertRaises(IbCycleRoleHold):
            inspect_completed_ib_cycle_roles(
                self.store, http_root=self.root, sequence=identity["sequence"],
            )

    def test_different_cycle_or_root_cannot_borrow_ib_manifest(self) -> None:
        first, _ = self._cycle()
        second, _ = self._cycle()
        with self.assertRaises(IbCycleRoleHold):
            inspect_completed_ib_cycle_roles(
                self.store, http_root=self.root,
                sequence=second["sequence"] + 1,
            )
        outside = self.root / "foreign-root"
        outside.mkdir()
        with self.assertRaises(IbCycleRoleHold):
            inspect_completed_ib_cycle_roles(
                self.store, http_root=outside, sequence=first["sequence"],
            )

    def test_drifted_base_artifact_and_missing_private_report_hold(self) -> None:
        identity, artifacts = self._cycle()
        info = artifacts["infiniband/prod"]["info"]
        before = info.read_bytes()
        stamp = info.stat().st_mtime_ns
        info.write_bytes(before + b"changed")
        os.utime(info, ns=(stamp, stamp))
        with self.assertRaises(IbCycleRoleHold):
            inspect_completed_ib_cycle_roles(
                self.store, http_root=self.root, sequence=identity["sequence"],
            )
        info.write_bytes(before)
        evidence = artifacts["infiniband/prod"]["envelope"].with_name(
            "evidence-manifest.json"
        )
        evidence.unlink()
        with self.assertRaises(IbCycleRoleHold):
            inspect_completed_ib_cycle_roles(
                self.store, http_root=self.root, sequence=identity["sequence"],
            )


if __name__ == "__main__":
    unittest.main()
