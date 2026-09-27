"""Tests-first Stage-L ETH Switch runtime-source window; never send eligibility."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_activity_source import (
    load_eth_activity_evidence, validate_worker_eth_activity_context,
    write_eth_activity_evidence,
)
from monitor.issue_tracker_k_chain import assess_k_window
from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
from test_cases.test_collection_v2_emitter_contract import EMITTER
from test_cases.test_issue_tracker_switch_info_source import _info
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
from tools.project_contract import summarize_collection_cycle_results


_DEFAULT_SNAPSHOT = object()


def _bound_archive(path: Path, hosts: tuple[str, ...], *, alarm: bool) -> None:
    stamp = path.name.removesuffix(".tar.gz")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as bundle:
        folder = tarfile.TarInfo(stamp + "/")
        folder.type = tarfile.DIRTYPE
        bundle.addfile(folder)
        for host in hosts:
            body = _info(host, fan_state="fail" if alarm else "ok")
            member = tarfile.TarInfo(stamp + "/" + host + ".info")
            member.size = len(body)
            bundle.addfile(member, io.BytesIO(body))
        meta_bytes = json.dumps({
            "schema_version": 1, "environment": "air", "collector": "cron.sh",
            "collected_at": "2026-09-25T03:15:00+08:00",
            "device_count": len(hosts),
        }, separators=(",", ":")).encode()
        member = tarfile.TarInfo(stamp + "/collection.json")
        member.size = len(meta_bytes)
        bundle.addfile(member, io.BytesIO(meta_bytes))


class RuntimeWorkerFixture:
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="req7-switch-runtime-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.project = self.root / "project"
        self.project.mkdir(mode=0o755)
        self.project.chmod(0o755)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir(mode=0o755)
        self.publication.chmod(0o755)
        initialize_tracker_state(
            self.project, self.publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="switch-runtime-first-use",
        )
        with tracker_writer(self.project, self.publication) as token:
            set_k(
                token, new_k=2, actor="operator:fixture",
                recorded_at="2026-09-25T00:01:00Z", request_id="set-k-two",
                expected_revision=0,
            )
            self.settings = current_k(token)
            self.assertEqual((1, 2), (self.settings.revision, self.settings.k))
        self.workbook = self.project / "local-template.xlsx"
        self.workbook.write_bytes(literal_xlsx())
        self.whitelist_snapshot = read_whitelist_workbook(self.workbook)
        self.assertEqual((), self.whitelist_snapshot.whitelist.rules)
        gate = WORKER.CollectionGate(
            str(self.project), "air", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        self.gate = gate.__enter__()
        self.addCleanup(lambda: gate.__exit__(None, None, None))
        self.assertTrue(self.gate.decision.allowed)
        self.store = WORKER.CollectionCycleStore(gate=self.gate)
        self.artifacts: list[tuple[Path, Path, Path]] = []
        self.activity_artifacts: list[dict] = []

    def cycle(self, *, alarm: bool = True, dynamic: bool = False,
              activity: bool = False) -> dict:
        token = TOKEN_1 if not self.artifacts else TOKEN_2
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=token):
            identity = self.store.allocate_start(process_inspector=lambda _binding: "dead")
        self.store.publish_launch(
            identity, pid=4321, boot_id="fixture-boot", process_start_time="9000",
            argv=["collector"], context={"scope": "air"},
            credential_argv_positions=(), credential_context_names=(),
        )
        sequence = identity["sequence"]
        parent = (self.root / "monitor/status/collection-cycles"
                  / identity["project_key"] / "air/switch_collection/artifacts"
                  / f"{sequence:020d}")
        sidecar = parent / "ethernet-air"
        inventory = parent / "inputs/ethernet-air.csv"
        inventory.parent.mkdir(parents=True)
        frozen = b"hostname,type,eth0_ip\nleaf-a,air,192.0.2.10\n"
        inventory.write_bytes(frozen)
        plan = {
            "eth": ["leaf-a|192.0.2.10"], "spx": [], "ib": [], "nv": [],
            "dynamic_identities": [],
        }
        dynamic_rows: list[str] = []
        names = ("leaf-a",)
        if dynamic:
            plan["eth"].append("dynamic-air|192.0.2.20")
            plan["dynamic_identities"].append(
                "dynamic-air|aa:bb:cc:dd:ee:ff|dhcp-lease"
            )
            dynamic_rows.append(
                "dynamic-air|192.0.2.20|aa:bb:cc:dd:ee:ff|template|dhcp-lease|fixture"
            )
            names = ("leaf-a", "dynamic-air")
        context = {
            "identity": identity, "source_slot": "ethernet/air",
            "artifacts": {
                "evidence": str(sidecar / "evidence-manifest.json"),
                "envelope": str(sidecar / "identity-envelope.json"),
                "input_inventory": str(inventory),
            },
            "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
            "target_plan": plan,
            "target_plan_sha256": hashlib.sha256(EMITTER.canonical(plan)).hexdigest(),
            "air_dynamic_rows": dynamic_rows,
            "prod_runtime_rows": [], "runtime_input_hashes": {},
        }
        WORKER._collection_freeze_plan_sources(
            "ethernet/air", context["artifacts"], context,
            EMITTER.canonical(plan),
        )
        if activity:
            p2p = self.root / "ztp/config/cumulus/template/P2P"
            (p2p / "output-p2p").mkdir(parents=True, exist_ok=True)
            (p2p / "p2p.xlsx").write_bytes(b"literal-static-air-topology")
            dot = b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n'
            (p2p / "output-p2p/p2p-air.dot").write_bytes(dot)
            (p2p / "01-inventory.log").write_bytes(b"[Eth-SW]\nleaf-*\n")
            aliases = (self.root / "tools/lldp-analyze-tool"
                       / "04-lldp-device-aliases.json")
            aliases.parent.mkdir(parents=True, exist_ok=True)
            aliases.write_bytes(b'{"schema_version":1,"canonical_to_aliases":{}}')
            with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
                context["activity"] = WORKER._collection_snapshot_activity_sources(
                    "ethernet/air", context["artifacts"],
                )
            self.assertEqual(dot, Path(context["activity"]["sources"]["dot"]["path"]).read_bytes())
        context_path = self.root / f"context-{sequence}.json"
        context_path.write_bytes(EMITTER.canonical(context))
        planned = self.root / f"planned-{sequence}.txt"
        planned.write_text("\n".join(names) + "\n", encoding="utf-8")
        legacy = self.root / f"legacy-{sequence}.txt"
        legacy.write_text(EMITTER.PREFIX + json.dumps({
            "schema_version": 1, "task": "switch_collection", "state": "success",
            "planned": len(names), "succeeded": len(names),
            "failed_count": 0, "failed_devices": [],
        }, separators=(",", ":")) + "\n", encoding="utf-8")
        archive = (self.root / "ethernet/monitor/eth-info"
                   / f"20260925-{315 + sequence:04d}-air.tar.gz")
        _bound_archive(archive, names, alarm=alarm)
        activity_path = None
        if activity:
            frozen = context["activity"]["sources"]
            sources = {
                role: Path(frozen[role]["path"])
                for role in ("dot", "inventory", "device_aliases")
            }
            sources["archive"] = archive
            report = (self.root / "tools/lldp-analyze-tool/99-output-p2p"
                      / (archive.name.removesuffix(".tar.gz")
                         + "-ethernet-topology-validation.xlsx"))
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_bytes(b"literal-offline-activity-report")
            activity_path = Path(context["activity"]["sidecar_path"])
            binding = validate_worker_eth_activity_context(context)
            write_eth_activity_evidence(
                activity_path, sources=sources,
                source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                               for role, path in sources.items()},
                report_path=report,
                result_records=({
                    "device_a": "leaf-a", "interface_a": "swp1",
                    "device_b": "leaf-z", "interface_b": "swp2",
                    "status": "CONFIRMED_BOTH_SIDE", "dot_line": 1,
                    "observation_a": {"remote_host": "leaf-z", "remote_port": "swp2"},
                    "observation_b": {"remote_host": "leaf-a", "remote_port": "swp1"},
                },),
                cycle_binding=binding,
            )
            self.assertEqual("CONFIRMED_BOTH_SIDE", load_eth_activity_evidence(
                activity_path, sources=sources, report_path=report,
                expected_evidence_sha256=hashlib.sha256(activity_path.read_bytes()).hexdigest(),
                expected_cycle_binding=binding,
            ).links[0].status)
        args = argparse.Namespace(
            context_file=context_path, legacy_result_file=legacy,
            planned_file=planned, info=archive, link=None, csv=None,
            activity=activity_path,
        )
        with mock.patch.object(EMITTER, "ROOT", self.root):
            child, evidence, envelope, published = EMITTER.build_result(args)
            EMITTER.publish(published, evidence, envelope)
        with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
            self.assertTrue(WORKER._collection_slot_artifacts_match(
                child, context["artifacts"], context,
            ), "real worker must validate this emitted private role")
        summary = summarize_collection_cycle_results(
            identity, [child], html_annotation={
                "attempted": False, "state": "not_attempted", "error_sha256": None,
            },
        )
        empty = {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0}
        self.store.publish_completion(identity, {
            "identity": identity,
            "outcomes": [{
                "source_slot": "ethernet/air", "outcome": "accepted",
                "child_result": child,
                "evidence": {"stdout": empty, "stderr": empty, "returncode": 0},
            }],
            "summary": summary,
        })
        self.artifacts.append((inventory, published, archive))
        if activity:
            self.activity_artifacts.append({
                "identity": identity, "context": context, "slot": published,
                "private": published / "activity-observation.json",
                "sources": sources, "report": report,
            })
        return identity

    def runtime(self, *, whitelist_snapshot=_DEFAULT_SNAPSHOT):
        # Import at call site so the real worker/emitter fixture control runs
        # independently while the new production bridge is absent (RED).
        from monitor.issue_tracker_switch_runtime import read_switch_runtime_window
        if whitelist_snapshot is _DEFAULT_SNAPSHOT:
            whitelist_snapshot = self.whitelist_snapshot
        return read_switch_runtime_window(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=whitelist_snapshot,
            whitelist_path=self.workbook,
        )

    def reissue_last_activity(self, *, private_bytes: bytes | None = None,
                              role_relative: str | None = None) -> None:
        """Keep worker record digests coherent so a negative reaches C binding."""
        artifact = self.activity_artifacts[-1]
        private = artifact["private"]
        if private_bytes is not None:
            private.write_bytes(private_bytes)
        manifest_path = artifact["slot"] / "evidence-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        role = manifest["roles"][3]
        self.assertEqual("activity_observation", role["role"])
        if role_relative is not None:
            role["relative_path"] = role_relative
        role["sha256"] = hashlib.sha256(private.read_bytes()).hexdigest()
        role["size_bytes"] = len(private.read_bytes())
        manifest_raw = EMITTER.canonical(manifest)
        manifest_path.write_bytes(manifest_raw)
        evidence_digest = {
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "size_bytes": len(manifest_raw),
        }
        envelope_path = artifact["slot"] / "identity-envelope.json"
        envelope = json.loads(envelope_path.read_bytes())
        envelope["evidence"] = evidence_digest
        envelope_raw = EMITTER.canonical(envelope)
        envelope_path.write_bytes(envelope_raw)
        completion_path = self.store.completion_path(artifact["identity"]["sequence"])
        completion = json.loads(completion_path.read_bytes())
        result = completion["run_result"]
        child = result["outcomes"][0]["child_result"]
        child["evidence"] = evidence_digest
        child["envelope"] = {
            "sha256": hashlib.sha256(envelope_raw).hexdigest(),
            "size_bytes": len(envelope_raw),
        }
        result["summary"] = summarize_collection_cycle_results(
            artifact["identity"], [child],
            html_annotation=result["summary"]["html_annotation"],
        )
        completion_path.write_bytes(EMITTER.canonical(completion))
        self.assertEqual(2, len(read_completed_cycle_evidence(self.store)))


class SwitchRuntimeDirectTests(RuntimeWorkerFixture, unittest.TestCase):
    def test_prod_fabric_identity_comes_from_frozen_inventory_not_host_guess(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, _prod_fabric_identities,
        )

        inventory = (
            b"hostname,type,eth0_ip,template\n"
            b"leaf-a,eth,192.0.2.10,tan-leaf\n"
            b"spx-a,eth_spx,192.0.2.11,tan-leaf\n"
            b"nvsw01,nvl,192.0.2.12,border-leaf\n"
        )
        self.assertEqual(
            (("leaf-a", "eth", "tan-leaf"),
             ("spx-a", "eth_spx", "tan-leaf")),
            _prod_fabric_identities(inventory, "ethernet/prod"),
        )
        self.assertEqual(
            (("nvsw01", "nvl", "border-leaf"),),
            _prod_fabric_identities(inventory, "nvlink/prod"),
        )
        with self.assertRaises(SwitchRuntimeHoldError):
            _prod_fabric_identities(
                inventory.replace(b"tan-leaf", b"tan\x00leaf", 1),
                "ethernet/prod",
            )

    def test_prod_eth_status_to_issue_source_table_matches_analyzer_sheets(self):
        from monitor.issue_tracker_activity_source import (
            EndpointObservation, EthLinkObservation,
        )
        from monitor.issue_tracker_switch_runtime import (
            ProdEthActivityKWindow, SwitchRuntimeHoldError,
            classify_prod_eth_activity_k_window,
        )

        statuses = (
            "CONFIRMED_BOTH_SIDE", "CONFIRMED_SW_SIDE", "WRONG_PEER",
            "SW_LLDP_PRESENT", "NO_LLDP", "DOWN", "MISSING_DEVICE",
            "MISSING_INTERFACE",
        )
        links = tuple(EthLinkObservation(
            f"leaf-{index}", "swp1", f"peer-{index}", "swp2",
            status, index + 1,
            EndpointObservation("actual", "swp9"),
            EndpointObservation("actual", "swp8"),
        ) for index, status in enumerate(statuses))
        window = ProdEthActivityKWindow(
            cycle_ids=("0" * 64,), completion_sha256=("1" * 64,),
            activity_sha256=("2" * 64,), persistent_links=links,
            whitelist_skips=(), k_event_sha256="3" * 64,
            whitelist_sha256="4" * 64, template_sha256="5" * 64,
        )
        rows = classify_prod_eth_activity_k_window(window)
        self.assertEqual((
            ("WRONG_PEER", "Miswired_Links", "Mis-wiring"),
            ("SW_LLDP_PRESENT", "Miswired_Links", "Mis-wiring"),
            ("NO_LLDP", "Miswired_Links", "Mis-wiring"),
            ("DOWN", "Missing_Links", "Link Down"),
            ("MISSING_DEVICE", "Missing_Links", "Link Down"),
            ("MISSING_INTERFACE", "Missing_Links", "Link Down"),
        ), tuple((row.observation.status, row.source_sheet, row.issue_type)
                  for row in rows))
        self.assertTrue(all(row.qualified is False for row in rows))
        with self.assertRaises(SwitchRuntimeHoldError):
            classify_prod_eth_activity_k_window(window.__class__(
                **{**window.__dict__, "qualified": True}
            ))
        with self.assertRaises(SwitchRuntimeHoldError):
            classify_prod_eth_activity_k_window(window.__class__(
                **{**window.__dict__, "persistent_links": links + (
                    links[2].__class__(
                        links[2].device_a, links[2].interface_a,
                        links[2].device_b, links[2].interface_b,
                        "FOREIGN", links[2].dot_line,
                        links[2].observation_a, links[2].observation_b,
                    ),
                )}
            ))

    def test_prod_eth_k_validator_rejects_copied_or_qualified_witness(self):
        from monitor.issue_tracker_switch_runtime import (
            ProdEthActivityKWindow, SwitchRuntimeHoldError,
            validate_prod_eth_activity_k_window,
        )

        copied = {"cycle_ids": ("0" * 64,)}
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_eth_activity_k_window(
                copied, None, http_root=self.root, settings=None,
                whitelist_snapshot=None, whitelist_path=self.workbook,
            )
        forged = ProdEthActivityKWindow(
            cycle_ids=(), completion_sha256=(), activity_sha256=(),
            persistent_links=(), whitelist_skips=(),
            k_event_sha256="0" * 64, whitelist_sha256="0" * 64,
            template_sha256="0" * 64, qualified=True,
        )
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_eth_activity_k_window(
                forged, None, http_root=self.root, settings=None,
                whitelist_snapshot=None, whitelist_path=self.workbook,
            )

    def test_prod_eth_activity_reader_rejects_air_cycle(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_cycle_source,
        )

        self.cycle(activity=True)
        with self.assertRaises(SwitchRuntimeHoldError):
            read_prod_eth_activity_cycle_source(
                self.store, http_root=self.root, sequence=1,
            )

    def _source_witness(self):
        from monitor.issue_tracker_switch_runtime import read_switch_runtime_source_witness
        return read_switch_runtime_source_witness(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.whitelist_snapshot,
            whitelist_path=self.workbook,
        )

    def test_prod_window_reducer_intersects_real_source_rows_without_granting_authority(self):
        from monitor.issue_tracker_switch_runtime import (
            ProdSwitchCycleSource, SwitchRuntimeHoldError,
            intersect_prod_switch_sources,
        )
        from monitor.issue_tracker_switch_info_source import (
            SwitchAbnormalValue, SwitchInfoPreview, SwitchSourceRow,
        )
        value = SwitchAbnormalValue(
            hostname="nvsw01", category="asic_temp", component_or_sensor="ASIC1",
            state="ok", current_c=75.0, maximum_c=70.0, critical_c=80.0,
        )
        first = ProdSwitchCycleSource(
            cycle_id="a" * 64, sequence=7, completion_sha256="b" * 64,
            preview=SwitchInfoPreview(
                source_slot="nvlink/prod", selected_hosts=("nvsw01",),
                archive_sha256="c" * 64,
                abnormal_keys=(("nvsw01", "asic_temp", "ASIC1"),),
                abnormal_values=(value,),
                not_applicable_by_host=(("nvsw01", ("fan", "psu")),),
            ),
            rows=(SwitchSourceRow("nvlink/prod", "nvsw01", "asic_temp",
                                  "ASIC1", "c" * 64, value),),
        )
        second = replace(first, cycle_id="d" * 64, sequence=8,
                         completion_sha256="e" * 64,
                         preview=replace(first.preview, archive_sha256="f" * 64),
                         rows=(replace(first.rows[0], archive_sha256="f" * 64),))
        window = intersect_prod_switch_sources(
            (first, second), source_slot="nvlink/prod",
        )
        self.assertEqual(("a" * 64, "d" * 64), window.cycle_ids)
        self.assertEqual((("nvsw01", "asic_temp", "ASIC1"),),
                         window.persistent_keys)
        self.assertEqual(("nvsw01",), window.selected_hosts)
        self.assertFalse(window.qualified)
        # Two independent completed cycles can legitimately collect byte-for-byte
        # identical switch data; content equality is not cycle replay.
        same_content = replace(
            second,
            preview=replace(second.preview,
                            archive_sha256=first.preview.archive_sha256),
            rows=(replace(second.rows[0],
                          archive_sha256=first.preview.archive_sha256),),
        )
        self.assertEqual(("a" * 64, "d" * 64),
                         intersect_prod_switch_sources(
                             (first, same_content),
                             source_slot="nvlink/prod",
                         ).cycle_ids)
        for altered in (
            replace(second, sequence=9),
            replace(second, cycle_id=first.cycle_id),
            replace(second, preview=replace(second.preview,
                                            selected_hosts=("nvsw02",))),
            replace(second, rows=(replace(second.rows[0], qualified=True),)),
        ):
            with self.subTest(altered=altered), self.assertRaises(SwitchRuntimeHoldError):
                intersect_prod_switch_sources(
                    (first, altered), source_slot="nvlink/prod",
                )

    def test_runtime_source_witness_binds_real_worker_emitter_eth_activity_and_az(self):
        from monitor.issue_tracker_switch_runtime import validate_switch_runtime_source_witness
        first = self.cycle(activity=True)
        second = self.cycle(activity=True)
        witness = self._source_witness()
        self.assertEqual((first["cycle_id"], second["cycle_id"]), witness.cycle_ids)
        self.assertEqual(("ethernet/air",), witness.source_slots)
        self.assertEqual(first["project_key"], witness.project_key)
        self.assertEqual(2, len(witness.completion_sha256))
        self.assertEqual(2, len(witness.info_sha256))
        self.assertEqual(2, len(witness.activity_sha256))
        self.assertEqual((("leaf-a", "fan", "PSU1/FAN1"),),
                         witness.switch_persistent_keys)
        self.assertEqual(("CONFIRMED_BOTH_SIDE", "CONFIRMED_BOTH_SIDE"),
                         tuple(cycle[0].status for cycle in witness.eth_links_by_cycle))
        self.assertEqual((("leaf-a", "swp1", "leaf-z", "swp2"),), witness.eth_endpoints)
        self.assertFalse(witness.qualified)
        self.assertEqual(witness, validate_switch_runtime_source_witness(
            witness, self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.whitelist_snapshot,
            whitelist_path=self.workbook,
        ))

    def test_runtime_source_witness_rejects_manual_claim_and_changed_source_at_freeze(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, validate_switch_runtime_source_witness,
        )
        self.cycle(activity=True)
        self.cycle(activity=True)
        witness = self._source_witness()
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_switch_runtime_source_witness(
                replace(witness, qualified=True), self.store,
                http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.whitelist_snapshot,
                whitelist_path=self.workbook,
            )
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_switch_runtime_source_witness(
                replace(witness, activity_sha256=("0" * 64,) * 2), self.store,
                http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.whitelist_snapshot,
                whitelist_path=self.workbook,
            )
        _inventory, _sidecar, archive = self.artifacts[-1]
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_switch_runtime_source_witness(
                witness, self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.whitelist_snapshot,
                whitelist_path=self.workbook,
            )

    def test_runtime_source_witness_rejects_switch_observation_change_between_reads(self):
        from monitor import issue_tracker_switch_runtime as runtime
        self.cycle(activity=True)
        self.cycle(activity=True)
        original = runtime._cycle_preview
        calls = 0

        def changing_preview(*args):
            nonlocal calls
            calls += 1
            value = original(*args)
            if calls == 4:
                return (*value[:2], set(), *value[3:])
            return value

        with mock.patch.object(runtime, "_cycle_preview", side_effect=changing_preview):
            with self.assertRaises(runtime.SwitchRuntimeHoldError):
                self._source_witness()

    def test_runtime_source_witness_rejects_missing_activity_stale_k_and_whitelist(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle(activity=True)
        self.cycle(activity=False)
        with self.assertRaises(SwitchRuntimeHoldError):
            self._source_witness()

    def test_runtime_source_witness_rejects_stale_k_and_whitelist_at_freeze(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, validate_switch_runtime_source_witness,
        )
        self.cycle(activity=True)
        self.cycle(activity=True)
        witness = self._source_witness()
        self.workbook.write_bytes(literal_xlsx(rules=("leaf-z",)))
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_switch_runtime_source_witness(
                witness, self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.whitelist_snapshot,
                whitelist_path=self.workbook,
            )
        self.workbook.write_bytes(literal_xlsx())
        with tracker_writer(self.project, self.publication) as token:
            set_k(token, new_k=3, actor="operator:fixture",
                  recorded_at="2026-09-25T00:02:00Z", request_id="set-k-three",
                  expected_revision=1)
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_switch_runtime_source_witness(
                witness, self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.whitelist_snapshot,
                whitelist_path=self.workbook,
            )

    def test_control_is_two_real_worker_emitter_completions_and_validated_k(self):
        first = self.cycle()
        second = self.cycle()
        evidence = read_completed_cycle_evidence(self.store)
        self.assertEqual((first["cycle_id"], second["cycle_id"]),
                         tuple(item.cycle_id for item in evidence))
        self.assertEqual("history_sufficient",
                         assess_k_window(evidence, self.settings).status)
        self.assertEqual(2, self.settings.k)
        for _inventory, sidecar, archive in self.artifacts:
            roles = json.loads((sidecar / "evidence-manifest.json").read_bytes())["roles"]
            self.assertEqual("info_archive", roles[0]["role"])
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                             roles[0]["sha256"])

    def test_two_static_air_cycles_have_one_persistent_fan_key_but_no_eligibility(self):
        first = self.cycle()
        second = self.cycle()
        window = self.runtime()
        self.assertEqual((first["cycle_id"], second["cycle_id"]),
                         window.cycle_ids)
        self.assertEqual({("leaf-a", "fan", "PSU1/FAN1")},
                         set(window.persistent_keys))
        self.assertFalse(window.qualified)

    def test_forged_selected_host_in_frozen_inventory_holds(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        self.cycle()
        inventory, _sidecar, _archive = self.artifacts[-1]
        inventory.write_bytes(b"hostname,type,eth0_ip\nleaf-z,air,192.0.2.10\n")
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_old_completion_replay_or_missing_private_role_holds(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        self.cycle()
        latest = self.store.completion_path(2)
        original = latest.read_bytes()
        latest.write_bytes(self.store.completion_path(1).read_bytes())
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()
        latest.write_bytes(original)
        _inventory, sidecar, _archive = self.artifacts[-1]
        (sidecar / "evidence-manifest.json").unlink()
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_byte_identical_foreign_archive_symlink_is_not_role_authority(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        self.cycle()
        _inventory, _sidecar, archive = self.artifacts[-1]
        foreign = self.root / "foreign-archive.tar.gz"
        foreign.write_bytes(archive.read_bytes())
        archive.unlink()
        archive.symlink_to(foreign)
        self.assertEqual(hashlib.sha256(foreign.read_bytes()).hexdigest(),
                         hashlib.sha256(archive.read_bytes()).hexdigest())
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_reissued_bound_sidecar_cannot_turn_static_air_link_role_present(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        second = self.cycle()
        _inventory, sidecar, _archive = self.artifacts[-1]
        manifest_path = sidecar / "evidence-manifest.json"
        envelope_path = sidecar / "identity-envelope.json"
        manifest = json.loads(manifest_path.read_bytes())
        self.assertEqual("not_applicable", manifest["roles"][1]["state"])
        manifest["roles"][1].update({
            "state": "present",
            "relative_path": "ethernet/monitor/spx-link/20260925-0317-air.tar.gz",
            "sha256": hashlib.sha256(b"forged-link").hexdigest(),
            "size_bytes": len(b"forged-link"),
        })
        manifest_raw = EMITTER.canonical(manifest)
        manifest_path.write_bytes(manifest_raw)
        manifest_digest = {
            "sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "size_bytes": len(manifest_raw),
        }
        envelope = json.loads(envelope_path.read_bytes())
        envelope["evidence"] = manifest_digest
        envelope_raw = EMITTER.canonical(envelope)
        envelope_path.write_bytes(envelope_raw)
        envelope_digest = {
            "sha256": hashlib.sha256(envelope_raw).hexdigest(),
            "size_bytes": len(envelope_raw),
        }
        completion_path = self.store.completion_path(second["sequence"])
        completion = json.loads(completion_path.read_bytes())
        run_result = completion["run_result"]
        child = run_result["outcomes"][0]["child_result"]
        child["evidence"] = manifest_digest
        child["envelope"] = envelope_digest
        annotation = run_result["summary"]["html_annotation"]
        run_result["summary"] = summarize_collection_cycle_results(
            second, [child], html_annotation=annotation,
        )
        completion_path.write_bytes(EMITTER.canonical(completion))
        self.assertEqual(2, len(read_completed_cycle_evidence(self.store)),
                         "the reissued worker chain remains independently valid")
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_one_cycle_is_cold_start_not_a_reduced_k(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_missing_or_stale_c24_snapshot_cannot_be_treated_as_empty_w1(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        self.cycle()
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime(whitelist_snapshot=None)
        self.workbook.write_bytes(literal_xlsx(rules=("leaf-z",)))
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_dynamic_target_plan_without_persisted_selected_names_holds(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle(dynamic=True)
        self.cycle(dynamic=True)
        self.assertEqual(2, len(read_completed_cycle_evidence(self.store)))
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()


if __name__ == "__main__":
    unittest.main()
