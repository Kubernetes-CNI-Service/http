"""Real C24 Whitelist and worker/emitter info roles cannot bypass runtime HOLD."""

from __future__ import annotations

from dataclasses import replace
import unittest
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor import issue_tracker_activity_source as ACTIVITY_SOURCE
from monitor.issue_tracker_activity_source import load_eth_activity_evidence
from monitor.issue_tracker_activity_source import (
    validate_worker_eth_activity_context, write_eth_activity_evidence,
)
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_collection_v2_emitter_contract import EMITTER
from test_cases.test_issue_tracker_switch_runtime import RuntimeWorkerFixture
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
from test_cases.test_issue_tracker_switch_info_source import _info, _nvl_info
from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
from tools.project_contract import summarize_collection_cycle_results


class SwitchRuntimeWorkflowTests(RuntimeWorkerFixture, unittest.TestCase):
    # The workflow also binds the real C24 reader to the worker/emitter/K seam.
    def test_real_worker_emitter_window_keeps_az_whitelist_provenance_and_freeze_guard(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_switch_runtime_source_witness,
            validate_switch_runtime_source_witness,
        )
        self.cycle(activity=True)
        self.cycle(activity=True)
        self.workbook.write_bytes(literal_xlsx(rules=("leaf-z",)))
        snapshot = read_whitelist_workbook(self.workbook)
        witness = read_switch_runtime_source_witness(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=snapshot, whitelist_path=self.workbook,
        )
        self.assertEqual(witness.eth_endpoints, witness.eth_whitelist_skips)
        self.assertEqual(((witness.eth_endpoints[0], "leaf-z"),),
                         witness.eth_whitelist_matches)
        self.assertEqual("leaf-z", witness.eth_endpoints[0][2])
        self.assertFalse(witness.qualified)
        self.assertEqual(witness, validate_switch_runtime_source_witness(
            witness, self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=snapshot, whitelist_path=self.workbook,
        ))
        report = self.activity_artifacts[-1]["report"]
        report.write_bytes(report.read_bytes() + b"late drift")
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_switch_runtime_source_witness(
                witness, self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=snapshot, whitelist_path=self.workbook,
            )

    def test_nonempty_w1_matching_switch_holds_before_any_runtime_promotion(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle()
        self.cycle()
        self.workbook.write_bytes(literal_xlsx(rules=("leaf-a",)))
        snapshot = read_whitelist_workbook(self.workbook)
        self.assertEqual(("leaf-a",), snapshot.whitelist.rules)
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime(whitelist_snapshot=snapshot)

    def test_two_real_worker_emitter_cycles_bind_fourth_h29_role_without_eligibility(self):
        first = self.cycle(activity=True)
        second = self.cycle(activity=True)
        self.assertEqual((first["cycle_id"], second["cycle_id"]),
                         tuple(item.cycle_id for item in read_completed_cycle_evidence(self.store)))
        for artifact in self.activity_artifacts:
            context = artifact["context"]
            self.assertEqual(b"literal-static-air-topology",
                             Path(context["activity"]["topology"]["path"]).read_bytes())
            self.assertEqual(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n',
                             artifact["sources"]["dot"].read_bytes())
            manifest = json.loads((artifact["slot"] / "evidence-manifest.json").read_bytes())
            self.assertEqual(["info_archive", "link_archive", "link_csv",
                              "activity_observation"],
                             [role["role"] for role in manifest["roles"]])
            fourth = manifest["roles"][3]
            private = artifact["private"]
            self.assertEqual(private.relative_to(self.root).as_posix(), fourth["relative_path"])
            self.assertEqual("present", fourth["state"])
            self.assertEqual((hashlib.sha256(private.read_bytes()).hexdigest(),
                              len(private.read_bytes())),
                             (fourth["sha256"], fourth["size_bytes"]))
            envelope = json.loads((artifact["slot"] / "identity-envelope.json").read_bytes())
            context_sha = hashlib.sha256(EMITTER.canonical(context)).hexdigest()
            self.assertEqual(context_sha, envelope["activity_context_sha256"])
            sidecar = json.loads(private.read_bytes())
            self.assertEqual(artifact["identity"], sidecar["cycle_binding"]["identity"])
            self.assertEqual(context_sha, sidecar["cycle_binding"]["context_sha256"])
            witness = load_eth_activity_evidence(
                private, sources=artifact["sources"], report_path=artifact["report"],
                expected_evidence_sha256=fourth["sha256"],
                expected_cycle_binding=sidecar["cycle_binding"],
            )
            self.assertEqual("CONFIRMED_BOTH_SIDE", witness.links[0].status)
            self.assertFalse(witness.qualified)
        window = self.runtime()
        self.assertEqual((first["cycle_id"], second["cycle_id"]), window.cycle_ids)
        self.assertEqual({("leaf-a", "fan", "PSU1/FAN1")}, set(window.persistent_keys))
        self.assertFalse(window.qualified)

    def test_reissued_foreign_fourth_role_path_never_promotes(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle(activity=True)
        self.cycle(activity=True)
        second = self.activity_artifacts[-1]
        private = second["private"]
        foreign = self.root / "foreign-activity-observation.json"
        foreign.write_bytes(private.read_bytes())
        self.reissue_last_activity(role_relative=foreign.relative_to(self.root).as_posix())
        self.assertEqual(hashlib.sha256(foreign.read_bytes()).hexdigest(),
                         hashlib.sha256(private.read_bytes()).hexdigest())
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_reissued_old_cycle_activity_identity_holds_even_with_fresh_completion(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle(activity=True)
        self.cycle(activity=True)
        first, second = self.activity_artifacts
        forged = json.loads(second["private"].read_bytes())
        forged["cycle_binding"]["identity"] = first["identity"]
        self.reissue_last_activity(private_bytes=json.dumps(
            forged, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"))
        self.assertNotEqual(second["identity"],
                            json.loads(second["private"].read_bytes())["cycle_binding"]["identity"])
        with self.assertRaises(SwitchRuntimeHoldError):
            self.runtime()

    def test_report_parent_symlink_cannot_read_outside_http_root(self):
        from monitor.issue_tracker_switch_runtime import SwitchRuntimeHoldError
        self.cycle(activity=True)
        self.cycle(activity=True)
        with tempfile.TemporaryDirectory(prefix="req7-outside-report-") as outside_name:
            outside = Path(outside_name)
            self.assertNotIn(self.root, outside.parents)
            reports = [artifact["report"] for artifact in self.activity_artifacts]
            parent = reports[0].parent
            self.assertEqual(parent, reports[1].parent)
            for report in reports:
                (outside / report.name).write_bytes(report.read_bytes())
                report.unlink()
            parent.rmdir()
            parent.symlink_to(outside, target_is_directory=True)
            self.assertEqual(b"literal-offline-activity-report", reports[1].read_bytes(),
                             "the foreign sentinel is reachable and byte-identical")
            reads = []
            original_hash = ACTIVITY_SOURCE._regular_sha256

            def watched_hash(path):
                if Path(path) in reports:
                    reads.append(str(path))
                return original_hash(path)

            with mock.patch.object(ACTIVITY_SOURCE, "_regular_sha256",
                                   side_effect=watched_hash):
                with self.assertRaises(SwitchRuntimeHoldError):
                    self.runtime()
            self.assertEqual([], reads,
                             "the outside report must be rejected before H29 reads it")


class ProdSwitchSourceWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="req7-prod-source-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.project = self.root / "project"
        self.project.mkdir()
        gate = WORKER.CollectionGate(
            str(self.project), "prod", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        self.gate = gate.__enter__()
        self.addCleanup(lambda: gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=self.gate)

    def _archive(self, area, prefix, host, body, *, sequence=1, extra=None):
        path = (self.root / area / "monitor" / prefix /
                (f"20260925-{314 + sequence:04d}-prod.tar.gz" if area == "ethernet"
                 else f"20260925-{314 + sequence:04d}.tar.gz"))
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = path.name.removesuffix(".tar.gz")
        with tarfile.open(path, "w:gz") as bundle:
            folder = tarfile.TarInfo(stamp + "/")
            folder.type = tarfile.DIRTYPE
            bundle.addfile(folder)
            for name, content in ((host, body),) + (() if extra is None else (extra,)):
                member = tarfile.TarInfo(stamp + "/" + name + ".info")
                member.size = len(content)
                bundle.addfile(member, io.BytesIO(content))
            metadata = json.dumps({
                "schema_version": 1, "environment": "prod", "collector": "cron.sh",
                "collected_at": "2026-09-25T03:15:00+08:00",
                "device_count": 1 if extra is None else 2,
            }, separators=(",", ":")).encode()
            member = tarfile.TarInfo(stamp + "/collection.json")
            member.size = len(metadata)
            bundle.addfile(member, io.BytesIO(metadata))
        return path

    def _cycle(self, *, dynamic_eth=False, activity=False, derivation=False,
               observed_peer="foreign-z", fabric_templates=None,
               ib_analysis=None):
        token = TOKEN_1 if self.store._read_witness() is None else TOKEN_2
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=token):
            identity = self.store.allocate_start(process_inspector=lambda _binding: "dead")
        self.store.publish_launch(
            identity, pid=4321, boot_id="fixture-boot", process_start_time="9000",
            argv=["collector"], context={"scope": "prod"},
            credential_argv_positions=(), credential_context_names=(),
        )
        area = (self.root / "monitor/status/collection-cycles" / identity["project_key"]
                / "prod/switch_collection/artifacts" / f"{identity['sequence']:020d}")
        outcomes = []
        artifacts = {}
        for slot, host, typ, prefix, body in (
            ("ethernet/prod", "leaf-a", "eth", "eth-info", _info("leaf-a", fan_state="fail")),
            ("infiniband/prod", "leaf-ib", "ib", "ib-info", b"literal IB info"),
            ("nvlink/prod", "nvsw01", "nvl", "nvsw-info", _nvl_info("nvsw01", asic_current="75")),
        ):
            family = slot.split("/", 1)[0]
            leaf = slot.replace("/", "-")
            inventory = area / "inputs" / (leaf + ".csv")
            inventory.parent.mkdir(parents=True, exist_ok=True)
            chosen_template = (fabric_templates or {}).get(slot)
            if chosen_template is None:
                frozen = f"hostname,type,eth0_ip\n{host},{typ},192.0.2.10\n".encode()
            else:
                frozen = (f"hostname,type,eth0_ip,template\n"
                          f"{host},{typ},192.0.2.10,{chosen_template}\n").encode()
            inventory.write_bytes(frozen)
            plan = {"eth": [], "spx": [], "ib": [], "nv": [],
                    "dynamic_identities": []}
            plan[{"ethernet": "eth", "infiniband": "ib", "nvlink": "nv"}[family]] = [
                f"{host}|192.0.2.10"
            ]
            runtime_rows = []
            runtime_hashes = {}
            extra = None
            if family == "ethernet" and dynamic_eth:
                dynamic_host = "DISCOVERED-CUMULUS-AABBCCDDEEFF"
                runtime_rows = ["aa:bb:cc:dd:ee:ff|192.0.2.20|cumulus|active"]
                runtime_hashes["journal_derived_rows"] = hashlib.sha256(
                    EMITTER.canonical(runtime_rows)
                ).hexdigest()
                plan["eth"].append(dynamic_host + "|192.0.2.20")
                plan["dynamic_identities"].append(
                    dynamic_host + "|aa:bb:cc:dd:ee:ff|dhcp-unbound-cumulus"
                )
                extra = (dynamic_host, _info(dynamic_host))
            private = area / leaf
            context = {
                "identity": identity, "source_slot": slot,
                "artifacts": {
                    "evidence": str(private / "evidence-manifest.json"),
                    "envelope": str(private / "identity-envelope.json"),
                    "input_inventory": str(inventory),
                },
                "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
                "target_plan": plan,
                "target_plan_sha256": hashlib.sha256(EMITTER.canonical(plan)).hexdigest(),
                "air_dynamic_rows": [], "prod_runtime_rows": runtime_rows,
                "runtime_input_hashes": runtime_hashes,
            }
            if family == "infiniband" and ib_analysis is not None:
                context["ib_analysis"] = ib_analysis
            frozen_sources = WORKER._collection_freeze_plan_sources(
                slot, context["artifacts"], context, EMITTER.canonical(plan),
            )
            if family == "ethernet" and activity:
                p2p = self.root / "ztp/config/cumulus/template/P2P"
                if derivation:
                    from test_cases.test_issue_tracker_topology_derivation_workflow import _real_chain
                    if not p2p.exists():
                        _real_chain(self.root)
                else:
                    (p2p / "output-p2p").mkdir(parents=True, exist_ok=True)
                    (p2p / "p2p.xlsx").write_bytes(b"literal-prod-topology-source")
                    (p2p / "output-p2p/p2p-lldpq.dot").write_bytes(
                        b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n'
                    )
                    (p2p / "01-inventory.log").write_bytes(b"[Eth-SW]\nleaf-*\n")
                    aliases = (self.root / "tools/lldp-analyze-tool"
                               / "04-lldp-device-aliases.json")
                    aliases.parent.mkdir(parents=True, exist_ok=True)
                    aliases.write_bytes(b'{"schema_version":1,"canonical_to_aliases":{}}')
                with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
                    context["activity"] = WORKER._collection_snapshot_activity_sources(
                        slot, context["artifacts"],
                    )
            context_path = self.root / f"{leaf}-{identity['sequence']}-context.json"
            context_path.write_bytes(EMITTER.canonical(context))
            planned = self.root / f"{leaf}-{identity['sequence']}-planned.txt"
            planned.write_text(host + "\n" + (
                extra[0] + "\n" if extra is not None else ""
            ), encoding="utf-8")
            legacy = self.root / f"{leaf}-{identity['sequence']}-legacy.txt"
            legacy.write_text(EMITTER.PREFIX + json.dumps({
                "schema_version": 1, "task": "switch_collection", "state": "success",
                "planned": 1 if extra is None else 2,
                "succeeded": 1 if extra is None else 2,
                "failed_count": 0,
                "failed_devices": [],
            }, separators=(",", ":")) + "\n", encoding="utf-8")
            info = self._archive(family, prefix, host, body,
                                 sequence=identity["sequence"], extra=extra)
            link = csv = None
            if family != "ethernet":
                link_prefix = {"infiniband": "ib-link", "nvlink": "nvsw-link"}[family]
                link = self.root / family / "monitor" / link_prefix / info.name
                csv = link.with_suffix("").with_suffix(".csv")
                link.parent.mkdir(parents=True, exist_ok=True)
                link.write_bytes(b"literal link archive")
                csv.write_bytes(b"port,peer\n1,fixture\n")
            args = argparse.Namespace(
                context_file=context_path, legacy_result_file=legacy,
                planned_file=planned, info=info, link=link, csv=csv,
                activity=None,
            )
            if family == "ethernet" and activity:
                frozen_activity = context["activity"]
                sources = {
                    role: Path(frozen_activity["sources"][role]["path"])
                    for role in ("dot", "inventory", "device_aliases")
                }
                sources["archive"] = info
                report = (self.root / "tools/lldp-analyze-tool/99-output-p2p"
                          / (info.name.removesuffix(".tar.gz")
                             + "-ethernet-topology-validation.xlsx"))
                report.parent.mkdir(parents=True, exist_ok=True)
                report.write_bytes(b"literal-prod-link-report")
                args.activity = Path(frozen_activity["sidecar_path"])
                write_eth_activity_evidence(
                    args.activity, sources=sources,
                    source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for role, path in sources.items()},
                    report_path=report,
                    result_records=({
                        "device_a": "leaf-a", "interface_a": "swp1",
                        "device_b": "leaf-z", "interface_b": "swp2",
                        "status": "WRONG_PEER", "dot_line": 2 if derivation else 1,
                        "observation_a": {"remote_host": observed_peer, "remote_port": "swp9"},
                        "observation_b": {"remote_host": "leaf-a", "remote_port": "swp1"},
                    },),
                    cycle_binding=validate_worker_eth_activity_context(context),
                )
            with mock.patch.object(EMITTER, "ROOT", self.root):
                child, evidence, envelope, directory = EMITTER.build_result(args)
                EMITTER.publish(directory, evidence, envelope)
            with mock.patch.object(WORKER, "HTTP_ROOT", self.root):
                self.assertTrue(WORKER._collection_slot_artifacts_match(
                    child, context["artifacts"], context,
                ))
            empty = {"sha256": hashlib.sha256(b"").hexdigest(), "size_bytes": 0}
            outcomes.append({
                "source_slot": slot, "outcome": "accepted", "child_result": child,
                "evidence": {"stdout": empty, "stderr": empty, "returncode": 0},
            })
            artifacts[slot] = {"info": info, "link": link, "csv": csv,
                               "inventory": inventory,
                               "plan": Path(frozen_sources["target_plan"]),
                               "rows": (Path(frozen_sources["runtime_derived_rows"])
                                        if "runtime_derived_rows" in frozen_sources else None),
                               "envelope": directory / "identity-envelope.json",
                               "activity": (directory / "activity-observation.json"
                                            if family == "ethernet" and activity else None)}
        children = [item["child_result"] for item in outcomes]
        summary = summarize_collection_cycle_results(
            identity, children, html_annotation={
                "attempted": False, "state": "not_attempted", "error_sha256": None,
            },
        )
        self.store.publish_completion(identity, {
            "identity": identity, "outcomes": outcomes, "summary": summary,
        })
        return identity, artifacts

    def test_real_prod_eth_fourth_role_yields_only_cycle_bound_link_source(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_cycle_source,
            validate_prod_eth_activity_cycle_source,
        )

        first, artifacts = self._cycle(activity=True)
        source = read_prod_eth_activity_cycle_source(
            self.store, http_root=self.root, sequence=first["sequence"],
        )
        self.assertEqual(first["cycle_id"], source.cycle_id)
        self.assertEqual("WRONG_PEER", source.links[0].status)
        self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"), (
            source.links[0].device_a, source.links[0].interface_a,
            source.links[0].device_b, source.links[0].interface_b,
        ))
        self.assertIsNone(source.derivation,
                          "an activity role alone cannot prove P2P derivation")
        self.assertFalse(source.qualified)
        self.assertEqual(source, validate_prod_eth_activity_cycle_source(
            source, self.store, http_root=self.root,
        ))
        private = artifacts["ethernet/prod"]["activity"]
        private.write_bytes(private.read_bytes() + b"late drift")
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_eth_activity_cycle_source(
                source, self.store, http_root=self.root,
            )

    def test_prod_eth_activity_reader_holds_when_fourth_role_is_absent(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_cycle_source,
        )
        identity, _artifacts = self._cycle()
        with self.assertRaises(SwitchRuntimeHoldError):
            read_prod_eth_activity_cycle_source(
                self.store, http_root=self.root, sequence=identity["sequence"],
            )

    def test_prod_eth_activity_reader_holds_on_frozen_dot_drift(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_cycle_source,
        )
        identity, artifacts = self._cycle(activity=True)
        source = read_prod_eth_activity_cycle_source(
            self.store, http_root=self.root, sequence=identity["sequence"],
        )
        frozen = (artifacts["ethernet/prod"]["activity"].parent.parent
                  / "inputs/ethernet-prod.dot")
        frozen.write_bytes(frozen.read_bytes() + b"late drift")
        with self.assertRaises(SwitchRuntimeHoldError):
            read_prod_eth_activity_cycle_source(
                self.store, http_root=self.root, sequence=identity["sequence"],
            )
        with self.assertRaises(SwitchRuntimeHoldError):
            from monitor.issue_tracker_switch_runtime import validate_prod_eth_activity_cycle_source
            validate_prod_eth_activity_cycle_source(
                source, self.store, http_root=self.root,
            )

    def test_real_p2p_worker_freeze_binds_prod_eth_activity_derivation(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_cycle_source,
            validate_prod_eth_activity_cycle_source,
        )
        from test_cases.test_issue_tracker_topology_derivation import EXPECTED

        identity, artifacts = self._cycle(activity=True, derivation=True)
        source = read_prod_eth_activity_cycle_source(
            self.store, http_root=self.root, sequence=identity["sequence"],
        )
        self.assertIsNotNone(source.derivation)
        self.assertEqual(EXPECTED, tuple(
            (edge.sheet, edge.row, edge.a_node, edge.a_port,
             edge.z_node, edge.z_port) for edge in source.derivation.edges
        ))
        self.assertFalse(source.qualified)
        self.assertEqual(source, validate_prod_eth_activity_cycle_source(
            source, self.store, http_root=self.root,
        ))
        sidecar = (artifacts["ethernet/prod"]["activity"].parent.parent
                   / "inputs/ethernet-prod.splitter-profiles.json")
        sidecar.write_bytes(sidecar.read_bytes() + b"late drift")
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_eth_activity_cycle_source(
                source, self.store, http_root=self.root,
            )

    def test_prod_eth_per_value_k_and_w1_are_read_only_and_bound(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_k_window,
            validate_prod_eth_activity_k_window,
        )
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )

        publication = self.project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            self.project, publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="prod-eth-activity-k-window",
        )
        with tracker_writer(self.project, publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="prod-eth-k-two",
                  expected_revision=0)
            settings = current_k(token)
        template = self.project / "local-template.xlsx"
        template.write_bytes(literal_xlsx())
        snapshot = read_whitelist_workbook(template)
        first, _ = self._cycle(activity=True, derivation=True)
        second, _ = self._cycle(activity=True, derivation=True)
        window = read_prod_eth_activity_k_window(
            self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template,
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), window.cycle_ids)
        self.assertEqual(1, len(window.persistent_links))
        self.assertEqual("WRONG_PEER", window.persistent_links[0].status)
        self.assertEqual((), window.whitelist_skips)
        self.assertFalse(window.qualified)
        self.assertEqual((), tuple(publication.iterdir()))
        self.assertEqual(window, validate_prod_eth_activity_k_window(
            window, self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template,
        ))
        template.write_bytes(literal_xlsx(rules=("leaf-z",)))
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_eth_activity_k_window(
                window, self.store, http_root=self.root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
            )
        filtered = read_prod_eth_activity_k_window(
            self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=read_whitelist_workbook(template),
            whitelist_path=template,
        )
        self.assertEqual((("leaf-a", "swp1", "leaf-z", "swp2"),),
                         filtered.whitelist_skips)
        self.assertEqual(((("leaf-a", "swp1", "leaf-z", "swp2"), "leaf-z"),),
                         filtered.whitelist_skip_matches)
        changed_snapshot = read_whitelist_workbook(template)
        self.assertEqual(filtered, validate_prod_eth_activity_k_window(
            filtered, self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=changed_snapshot, whitelist_path=template,
        ))
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_eth_activity_k_window(
                replace(filtered, whitelist_skip_matches=((
                    ("leaf-a", "swp1", "leaf-z", "swp2"), "forged-rule"),)),
                self.store, http_root=self.root, settings=settings,
                whitelist_snapshot=changed_snapshot, whitelist_path=template,
            )
        self.assertEqual((), filtered.persistent_links)
        self.assertFalse(filtered.qualified)

    def test_prod_eth_k_does_not_promote_same_endpoint_with_changed_observed_value(self):
        from monitor.issue_tracker_switch_runtime import read_prod_eth_activity_k_window
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )

        publication = self.project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            self.project, publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="prod-eth-value-k-window",
        )
        with tracker_writer(self.project, publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="prod-eth-value-two",
                  expected_revision=0)
            settings = current_k(token)
        template = self.project / "local-template.xlsx"
        template.write_bytes(literal_xlsx())
        snapshot = read_whitelist_workbook(template)
        self._cycle(activity=True, derivation=True,
                    observed_peer="foreign-z")
        self._cycle(activity=True, derivation=True,
                    observed_peer="changed-peer")
        window = read_prod_eth_activity_k_window(
            self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template,
        )
        self.assertEqual((), window.persistent_links)
        self.assertFalse(window.qualified)

    def test_two_real_prod_worker_emitter_cycles_bind_eth_nvl_k_window_without_ib_authority(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_switch_k_window,
            validate_prod_switch_k_window,
        )
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )

        publication = self.project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            self.project, publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="prod-switch-k-window",
        )
        with tracker_writer(self.project, publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="prod-k-two",
                  expected_revision=0)
            settings = current_k(token)
        template = self.project / "local-template.xlsx"
        template.write_bytes(literal_xlsx())
        snapshot = read_whitelist_workbook(template)
        first, _ = self._cycle()
        second, artifacts = self._cycle()
        self.assertEqual(2, len(read_completed_cycle_evidence(self.store)))
        eth = read_prod_switch_k_window(
            self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template,
            source_slot="ethernet/prod",
        )
        nvl = read_prod_switch_k_window(
            self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template,
            source_slot="nvlink/prod",
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), eth.cycle_ids)
        self.assertEqual((("leaf-a", "fan", "PSU1/FAN1"),),
                         eth.persistent_keys)
        self.assertEqual((("nvsw01", "asic_temp", "ASIC1"),),
                         nvl.persistent_keys)
        self.assertFalse(eth.qualified)
        self.assertFalse(nvl.qualified)
        self.assertEqual((), tuple(publication.iterdir()))
        self.assertEqual(nvl, validate_prod_switch_k_window(
            nvl, self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=snapshot, whitelist_path=template,
        ))
        template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_switch_k_window(
                eth, self.store, http_root=self.root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
            )
        changed_snapshot = read_whitelist_workbook(template)
        filtered = read_prod_switch_k_window(
            self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=changed_snapshot, whitelist_path=template,
            source_slot="ethernet/prod",
        )
        self.assertEqual(("switch:leaf-a",), filtered.whitelist_skips)
        self.assertEqual((("switch:leaf-a", "leaf-a"),),
                         filtered.whitelist_skip_matches)
        self.assertEqual(filtered, validate_prod_switch_k_window(
            filtered, self.store, http_root=self.root, settings=settings,
            whitelist_snapshot=changed_snapshot, whitelist_path=template,
        ))
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_switch_k_window(
                replace(filtered, whitelist_skip_matches=((
                    "switch:leaf-a", "forged-rule"),)),
                self.store, http_root=self.root, settings=settings,
                whitelist_snapshot=changed_snapshot, whitelist_path=template,
            )
        self.assertFalse(filtered.qualified)
        artifacts["nvlink/prod"]["info"].write_bytes(b"late drift")
        with self.assertRaises(SwitchRuntimeHoldError):
            read_prod_switch_k_window(
                self.store, http_root=self.root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
                source_slot="nvlink/prod",
            )

    def test_prod_k_readers_reuse_one_active_writer_without_nested_lock(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_eth_activity_k_window,
            read_prod_switch_k_window,
        )
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )

        publication = self.project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            self.project, publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="prod-shared-k-window",
        )
        with tracker_writer(self.project, publication) as token:
            set_k(token, new_k=1, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="shared-k-one",
                  expected_revision=0)
            settings = current_k(token)
        template = self.project / "local-template.xlsx"
        template.write_bytes(literal_xlsx())
        snapshot = read_whitelist_workbook(template)
        self._cycle(activity=True, derivation=True)
        with tracker_writer(self.project, publication) as token:
            for slot in ("ethernet/prod", "nvlink/prod"):
                window = read_prod_switch_k_window(
                    self.store, http_root=self.root, settings=settings,
                    whitelist_snapshot=snapshot, whitelist_path=template,
                    source_slot=slot, writer_token=token,
                )
                self.assertEqual(1, len(window.cycle_ids))
            eth = read_prod_eth_activity_k_window(
                self.store, http_root=self.root, settings=settings,
                whitelist_snapshot=snapshot, whitelist_path=template,
                writer_token=token,
            )
            self.assertEqual(1, len(eth.cycle_ids))
            with self.assertRaises(SwitchRuntimeHoldError):
                read_prod_switch_k_window(
                    self.store, http_root=self.root, settings=settings,
                    whitelist_snapshot=snapshot, whitelist_path=template,
                    source_slot="ethernet/prod", writer_token=object(),
                )

    def test_prod_worker_emitter_static_eth_nvl_rows_are_source_bound_but_not_qualified(self):
        from monitor.issue_tracker_switch_runtime import (
            read_prod_switch_cycle_source, validate_prod_switch_cycle_source,
        )
        identity, artifacts = self._cycle()
        eth = read_prod_switch_cycle_source(
            self.store, http_root=self.root, sequence=identity["sequence"],
            source_slot="ethernet/prod",
        )
        nvl = read_prod_switch_cycle_source(
            self.store, http_root=self.root, sequence=identity["sequence"],
            source_slot="nvlink/prod",
        )
        self.assertEqual(("leaf-a", "fan", "PSU1/FAN1"),
                         (eth.rows[0].hostname, eth.rows[0].category,
                          eth.rows[0].component_or_sensor))
        self.assertEqual(("nvsw01", ("fan", "psu")),
                         nvl.preview.not_applicable_by_host[0])
        self.assertEqual("asic_temp", nvl.rows[0].category)
        self.assertEqual((("leaf-a", "eth", ""),), eth.fabric_identities)
        self.assertEqual((("nvsw01", "nvl", ""),), nvl.fabric_identities)
        self.assertFalse(eth.qualified)
        self.assertFalse(nvl.qualified)
        self.assertEqual(nvl, validate_prod_switch_cycle_source(
            nvl, self.store, http_root=self.root,
        ))
        info = artifacts["nvlink/prod"]["info"]
        info.write_bytes(info.read_bytes() + b"late drift")
        with self.assertRaises(ValueError):
            validate_prod_switch_cycle_source(nvl, self.store, http_root=self.root)

    def test_prod_fabric_template_is_bound_to_completed_inventory_bytes(self):
        from monitor.issue_tracker_switch_runtime import (
            read_prod_switch_cycle_source, validate_prod_switch_cycle_source,
        )

        identity, artifacts = self._cycle(fabric_templates={
            "ethernet/prod": "tan-leaf", "nvlink/prod": "border-leaf",
        })
        eth = read_prod_switch_cycle_source(
            self.store, http_root=self.root, sequence=identity["sequence"],
            source_slot="ethernet/prod",
        )
        self.assertEqual((("leaf-a", "eth", "tan-leaf"),), eth.fabric_identities)
        self.assertFalse(eth.qualified)
        self.assertEqual(eth, validate_prod_switch_cycle_source(
            eth, self.store, http_root=self.root,
        ))
        inventory = artifacts["ethernet/prod"]["inventory"]
        inventory.write_bytes(inventory.read_bytes().replace(b"tan-leaf", b"oob-leaf"))
        with self.assertRaises(ValueError):
            validate_prod_switch_cycle_source(eth, self.store, http_root=self.root)

    def test_prod_dynamic_hosts_bind_frozen_plan_and_rows_then_drift_holds(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_switch_cycle_source,
            validate_prod_switch_cycle_source,
        )
        identity, artifacts = self._cycle(dynamic_eth=True)
        witness = read_prod_switch_cycle_source(
            self.store, http_root=self.root, sequence=identity["sequence"],
            source_slot="ethernet/prod",
        )
        self.assertEqual(("leaf-a", "DISCOVERED-CUMULUS-AABBCCDDEEFF"),
                         witness.preview.selected_hosts)
        self.assertFalse(witness.qualified)
        self.assertEqual(witness, validate_prod_switch_cycle_source(
            witness, self.store, http_root=self.root,
        ))
        rows = artifacts["ethernet/prod"]["rows"]
        rows.write_bytes(b"[]\n")
        with self.assertRaises(SwitchRuntimeHoldError):
            validate_prod_switch_cycle_source(witness, self.store, http_root=self.root)

    def test_prod_missing_fixed_plan_holds_before_info_preview(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_switch_cycle_source,
        )
        identity, artifacts = self._cycle()
        artifacts["nvlink/prod"]["plan"].unlink()
        with self.assertRaises(SwitchRuntimeHoldError):
            read_prod_switch_cycle_source(
                self.store, http_root=self.root, sequence=identity["sequence"],
                source_slot="nvlink/prod",
            )

    def test_prod_link_role_drift_holds_even_when_info_archive_is_unchanged(self):
        from monitor.issue_tracker_switch_runtime import (
            SwitchRuntimeHoldError, read_prod_switch_cycle_source,
        )
        identity, artifacts = self._cycle()
        csv_path = artifacts["nvlink/prod"]["csv"]
        csv_path.write_bytes(csv_path.read_bytes() + b"late drift")
        with self.assertRaises(SwitchRuntimeHoldError):
            read_prod_switch_cycle_source(
                self.store, http_root=self.root, sequence=identity["sequence"],
                source_slot="nvlink/prod",
            )


if __name__ == "__main__":
    unittest.main()
