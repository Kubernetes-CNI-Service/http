"""Real prod worker/emitter cycle cannot borrow an absent IB producer record."""

from __future__ import annotations

import json
import hashlib
import datetime as dt
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import runpy
import tempfile
import unittest
from unittest import mock

import xlsxwriter

from monitor.collection_ib_cycle_binding import inspect_completed_ib_cycle_roles
from monitor.collection_ib_producer import (
    IbProducerHold, load_ib_producer_authority, observe_ib_cvt_source,
    parse_ib_producer_authority, IbProducerAuthoritySnapshot,
    produce_worker_ib_analysis, verify_ib_completed_result,
    validate_ib_role_binding, validate_ib_completion_attestation, IB_ROLE_NAMES,
)
from test_cases.test_collection_ib_producer import _HEX, _record
from test_cases.test_collection_ib_cycle_binding_workflow import (
    ProdCycleFixture, WORKER,
)
from test_cases.test_collection_v2_emitter_contract import (
    CollectionV2EmitterContractTests, EMITTER,
)


class IbProducerAuthorityWorkflowTests(ProdCycleFixture, unittest.TestCase):

    def setUp(self) -> None:
        super().setUp()
        self.project = self.root / "project"

    def test_worker_only_mints_ib_context_after_protected_producer_success(self) -> None:
        from tools.project_contract import build_collection_cycle_identity
        with tempfile.TemporaryDirectory(prefix="ib-worker-context-") as directory:
            root = Path(directory).resolve(strict=True)
            project = root / "DAY0-Prepare/fabric-a"
            project.mkdir(parents=True)
            identity = build_collection_cycle_identity(
                str(project), "prod", 7, "12345678123442348123456789abcdef",
            )
            record = _record()
            record.update({"project_root": str(project),
                           "project_key": identity["project_key"]})
            snapshot = IbProducerAuthoritySnapshot(
                parse_ib_producer_authority(
                    record, project_key=identity["project_key"], project_root=project,
                ), "b" * 64, (1, 2, 3),
            )
            binding = {"authority_sha256": snapshot.sha256, "roles": []}
            with mock.patch.object(WORKER, "HTTP_ROOT", root), mock.patch.object(
                WORKER, "active_project_identity", return_value=str(project),
            ), mock.patch.object(
                WORKER, "_collection_ib_authority_installed", return_value=True,
            ), mock.patch(
                "monitor.collection_ib_producer.load_ib_producer_authority",
                return_value=snapshot,
            ), mock.patch(
                "monitor.collection_ib_producer.produce_worker_ib_analysis",
                return_value=binding,
            ) as producer, mock.patch(
                "monitor.collection_ib_producer.recheck_ib_producer_authority",
            ) as recheck:
                self.assertEqual(
                    (binding, snapshot),
                    WORKER._collection_prepare_ib_analysis(identity, "infiniband/prod"),
                )
                producer.assert_called_once_with(
                    identity, project_root=project, http_root=root,
                )
                recheck.assert_called_once_with(snapshot)
                self.assertEqual(
                    (None, None),
                    WORKER._collection_prepare_ib_analysis(identity, "ethernet/prod"),
                )
            with mock.patch.object(WORKER, "HTTP_ROOT", root), mock.patch.object(
                WORKER, "active_project_identity", return_value=str(project),
            ), mock.patch.object(
                WORKER, "_collection_ib_authority_installed", return_value=True,
            ), mock.patch(
                "monitor.collection_ib_producer.load_ib_producer_authority",
                side_effect=IbProducerHold("missing install"),
            ), mock.patch(
                "monitor.collection_ib_producer.produce_worker_ib_analysis",
            ) as producer:
                self.assertEqual(
                    (None, None),
                    WORKER._collection_prepare_ib_analysis(identity, "infiniband/prod"),
                )
                producer.assert_not_called()
            with mock.patch.object(WORKER, "HTTP_ROOT", root), mock.patch.object(
                WORKER, "active_project_identity", return_value=str(project),
            ), mock.patch.object(
                WORKER, "_collection_ib_authority_installed", return_value=False,
            ), mock.patch(
                "monitor.collection_ib_producer.load_ib_producer_authority",
            ) as load:
                self.assertEqual(
                    (None, None),
                    WORKER._collection_prepare_ib_analysis(identity, "infiniband/prod"),
                )
                load.assert_not_called()
            with mock.patch.object(WORKER, "HTTP_ROOT", root), mock.patch.object(
                WORKER, "active_project_identity",
                side_effect=WORKER.CollectionGateError("no setup-managed project"),
            ), mock.patch(
                "monitor.collection_ib_producer.load_ib_producer_authority",
            ) as load:
                self.assertEqual(
                    (None, None),
                    WORKER._collection_prepare_ib_analysis(identity, "infiniband/prod"),
                )
                load.assert_not_called()

    def test_real_worker_slot_routes_only_prod_ib_producer_binding_to_child(self) -> None:
        from tools.project_contract import build_collection_cycle_identity
        from test_cases.test_collection_cycle_worker_contract import legacy, marker
        with tempfile.TemporaryDirectory(prefix="ib-worker-slot-route-") as directory:
            root = Path(directory).resolve(strict=True)
            project = root / "DAY0-Prepare/fabric-a"
            project.mkdir(parents=True)
            identity = build_collection_cycle_identity(
                str(project), "prod", 7, "12345678123442348123456789abcdef",
            )
            ib = root / "infiniband/monitor"
            ib.mkdir(parents=True)
            cron = ib / "cron.sh"
            cron.write_text("#!/bin/sh\n", encoding="utf-8")
            (ib / "ib.csv").write_text(
                "hostname,type,eth0_ip\nleaf01,ib,192.0.2.11\n", encoding="utf-8",
            )
            plan = {"eth": [], "spx": [], "ib": ["leaf01|192.0.2.11"],
                    "nv": [], "dynamic_identities": []}
            binding = {"authority_sha256": "a" * 64, "roles": []}
            observed = []

            def run(argv, _cwd, _timeout, **_kwargs):
                if "--emit-target-plan-fd" in argv:
                    descriptor = int(argv[argv.index("--emit-target-plan-fd") + 1])
                    os.write(descriptor, EMITTER.canonical(plan))
                    return {"returncode": 0, "stdout": "", "stderr": ""}, False
                if "--worker-context-fd" in argv:
                    descriptor = int(argv[argv.index("--worker-context-fd") + 1])
                    size = os.fstat(descriptor).st_size
                    observed.append(json.loads(os.pread(descriptor, size, 0)))
                return {"returncode": 0, "stdout": marker(legacy()), "stderr": ""}, False

            commands = [["collector", "ethernet"], [str(cron)], ["collector", "nvlink"]]
            with mock.patch.object(WORKER, "HTTP_ROOT", root), mock.patch.object(
                WORKER, "SCRIPTS", {**WORKER.SCRIPTS, "infiniband": cron},
            ), mock.patch.object(
                WORKER, "commands_for_scope", return_value=commands,
            ), mock.patch.object(
                WORKER, "run_interruptible", side_effect=run,
            ), mock.patch.object(
                WORKER, "_collection_prepare_ib_analysis", return_value=(binding, object()),
            ) as producer, mock.patch(
                "monitor.collection_ib_producer.recheck_ib_producer_authority",
            ) as recheck:
                result = WORKER.run_collection_slots(
                    identity, artifact_bindings={}, timeout=5, lock_wait=0,
                )
            producer.assert_called_once_with(identity, "infiniband/prod")
            recheck.assert_called_once()
            self.assertEqual([binding], [row["ib_analysis"] for row in observed])
            self.assertEqual(["accepted"] * 3,
                             [row["outcome"] for row in result["outcomes"]], repr(result))

    def test_real_converter_archive_analyzer_receipt_bind_one_worker_cycle(self) -> None:
        from tools.project_contract import build_collection_cycle_identity
        from tools.ufm_collection_contract import publish_local_archive
        from tools.ufm_remote_producer import (
            RemoteCollectionObservation, VerifiedRetrievedObservation,
        )
        with tempfile.TemporaryDirectory(prefix="ib-worker-completed-") as directory:
            root = Path(directory).resolve(strict=True)
            setup = root / "ztp/config/nvos/template/P2P"
            setup.mkdir(parents=True)
            project = root / "DAY0-Prepare/fabric-a"
            project.mkdir(parents=True)
            selected = project / "fabric-blue.xlsx"
            book = xlsxwriter.Workbook(str(selected))
            sheet = book.add_worksheet("CL links")
            for col, item in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, col, item)
            for col, item in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, col, item)
            book.close()
            (project / "p2p.xlsx").symlink_to(selected.name)
            (setup / "p2p.xlsx").symlink_to(
                "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx"
            )
            inventory = setup / "01-inventory.log"
            inventory.write_text("[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8")
            port_map = setup / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            splitter = setup / "03-splitter.log"
            splitter.write_text("", encoding="utf-8")
            output = setup / "output-p2p"
            output.mkdir()
            cvt = output / "fabric-blue-cvt.xlsx"
            result = subprocess.run(
                [sys.executable, "-B", str(Path(__file__).resolve().parents[1]
                 / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
                 "--output", str(cvt), "--inventory", str(inventory),
                 "--port-map", str(port_map), "--splitter", str(splitter)],
                cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                                "XLSX_TO_CSV_BASE_DIR": str(setup)},
                capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            incoming = project / "99-output-ufm/incoming"
            incoming.mkdir(parents=True)
            record = _record()
            identity = build_collection_cycle_identity(
                str(project), "prod", 7, "12345678123442348123456789abcdef",
            )
            record.update({
                "project_key": identity["project_key"], "project_root": str(project),
                "retrieval_dir": str(incoming),
                "p2p_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
                "cvt_sha256": hashlib.sha256(cvt.read_bytes()).hexdigest(),
                "cvt_provenance_sha256": hashlib.sha256(
                    Path(f"{cvt}.provenance.json").read_bytes()
                ).hexdigest(),
            })
            snapshot = IbProducerAuthoritySnapshot(
                parse_ib_producer_authority(
                    record, project_key=identity["project_key"], project_root=project,
                ), "b" * 64, (1, 2, 3),
            )
            vendor = root / "vendor-iblinkinfo.txt"
            vendor.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            called = []
            observations = []

            def retrieved(plan, **kwargs):
                called.append((plan.run_id, kwargs["destination"]))
                archive = publish_local_archive(plan, vendor, incoming)
                sha = hashlib.sha256(archive.read_bytes()).hexdigest()
                remote = RemoteCollectionObservation(
                    "EXAMPLE-UFM01", plan.run_id, "iblinkinfo",
                    plan.ufm_remote_path, sha,
                )
                observation = VerifiedRetrievedObservation(
                    remote, archive, sha, sha, sha, "b" * 64, "b" * 64,
                )
                observations.append(observation)
                return observation

            protected = root / "synthetic-root-attestation"
            protected.mkdir(mode=0o700)
            for patcher in (
                mock.patch("monitor.collection_ib_producer._ROOT_UID", os.getuid()),
                mock.patch(
                    "monitor.collection_ib_producer._open_protected_attestation_dir",
                    side_effect=lambda _key: os.open(protected, os.O_RDONLY),
                ),
                mock.patch(
                    "monitor.collection_ib_producer.load_ib_producer_authority",
                    return_value=snapshot,
                ),
                mock.patch("monitor.collection_ib_producer.recheck_ib_producer_authority"),
            ):
                patcher.start()
                self.addCleanup(patcher.stop)
            with mock.patch(
                "monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                side_effect=retrieved,
            ):
                binding = produce_worker_ib_analysis(
                    identity, project_root=project, http_root=root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 20, tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail("fake transport should be supplied upstream"),
                )
            self.assertEqual(1, len(called))
            self.assertEqual(called[0][0], binding["run_id"])
            self.assertEqual(tuple(role["role"] for role in binding["roles"]), IB_ROLE_NAMES)
            self.assertEqual(record["cvt_sha256"], binding["expected_topology_sha256"])
            self.assertEqual(6, len(binding["roles"]))
            self.assertEqual(
                binding["roles"], validate_ib_completion_attestation(
                    identity, binding, http_root=root,
                ),
            )
            without_witness = dict(binding)
            del without_witness["attestation_sha256"]
            with self.assertRaises(IbProducerHold):
                validate_ib_completion_attestation(
                    identity, without_witness, http_root=root,
                )
            protected_record = protected / f"{identity['cycle_id']}.json"
            protected_bytes = protected_record.read_bytes()
            protected_record.write_bytes(b"{}\n")
            with self.assertRaises(IbProducerHold):
                validate_ib_completion_attestation(identity, binding, http_root=root)
            protected_record.write_bytes(protected_bytes)
            protected_record.chmod(0o644)
            with self.assertRaises(IbProducerHold):
                validate_ib_completion_attestation(identity, binding, http_root=root)
            protected_record.chmod(0o600)
            slot_dir = (
                root / "monitor/status/collection-cycles" / identity["project_key"]
                / "prod/switch_collection/artifacts/00000000000000000007/infiniband-prod"
            )
            frozen = slot_dir.parent / "inputs/infiniband-prod.csv"
            frozen.parent.mkdir(parents=True)
            frozen.write_bytes(b"hostname,type,eth0_ip\nleaf01,ib,192.0.2.11\n")
            context = {
                "identity": identity, "source_slot": "infiniband/prod",
                "artifacts": {
                    "evidence": str(slot_dir / "evidence-manifest.json"),
                    "envelope": str(slot_dir / "identity-envelope.json"),
                    "input_inventory": str(frozen),
                },
                "input_inventory_sha256": hashlib.sha256(frozen.read_bytes()).hexdigest(),
                "ib_analysis": binding,
            }
            plan = {"eth": [], "spx": [], "ib": ["leaf01|192.0.2.11"],
                    "nv": [], "dynamic_identities": []}
            context.update({
                "target_plan": plan,
                "target_plan_sha256": hashlib.sha256(EMITTER.canonical(plan)).hexdigest(),
                "air_dynamic_rows": [], "prod_runtime_rows": [],
                "runtime_input_hashes": {},
            })
            WORKER._collection_freeze_plan_sources(
                "infiniband/prod", context["artifacts"], context,
                EMITTER.canonical(plan),
            )
            context_path = root / "worker-context.json"
            context_path.write_bytes(EMITTER.canonical(context))
            planned = root / "planned.txt"
            planned.write_text("leaf01\n", encoding="utf-8")
            legacy = root / "legacy.txt"
            legacy.write_text(
                EMITTER.PREFIX + json.dumps({
                    "schema_version": 1, "task": "switch_collection",
                    "state": "success", "planned": 1, "succeeded": 1,
                    "failed_count": 0, "failed_devices": [],
                }, separators=(",", ":")) + "\n", encoding="utf-8",
            )
            base = []
            for stem, suffix in (("ib-info", ".tar.gz"),
                                 ("ib-link", ".tar.gz"), ("ib-link", ".csv")):
                path = root / "infiniband/monitor" / stem / ("20260926-0420" + suffix)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"port,peer\n1,fixture\n" if suffix == ".csv" else b"archive")
                base.append(path)
            args = argparse.Namespace(
                context_file=context_path, legacy_result_file=legacy,
                planned_file=planned, info=base[0], link=base[1], csv=base[2],
            )
            with mock.patch.object(EMITTER, "ROOT", root):
                forged_context = dict(context)
                forged_context["ib_analysis"] = without_witness
                context_path.write_bytes(EMITTER.canonical(forged_context))
                with self.assertRaises(IbProducerHold):
                    EMITTER.build_result(args)
                context_path.write_bytes(EMITTER.canonical(context))
                child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                self.assertEqual(
                    ["info_archive", "link_archive", "link_csv", *IB_ROLE_NAMES],
                    [role["role"] for role in json.loads(evidence)["roles"]],
                )
                self.assertEqual(
                    hashlib.sha256(EMITTER.canonical(context)).hexdigest(),
                    json.loads(envelope)["ib_analysis_context_sha256"],
                )
                ib_metadata = {key: binding[key] for key in (
                    "run_id", "node", "authority_sha256", "expected_topology_sha256",
                    "attestation_sha256",
                )}
                self.assertEqual(ib_metadata, json.loads(envelope)["ib_analysis_binding"])
                outside = root / "caller-selected-absolute-archive.tar.gz"
                outside.write_bytes((root / binding["roles"][0]["relative_path"]).read_bytes())
                forged_evidence = json.loads(evidence)
                forged_evidence["roles"][3]["relative_path"] = str(outside)
                forged_evidence_raw = EMITTER.canonical(forged_evidence)
                forged_envelope = json.loads(envelope)
                forged_envelope["evidence"] = EMITTER.digest(forged_evidence_raw)
                with self.assertRaises(ValueError):
                    EMITTER.publish(
                        sidecar_dir, forged_evidence_raw,
                        EMITTER.canonical(forged_envelope),
                    )
                EMITTER.publish(sidecar_dir, evidence, envelope)
            with mock.patch.object(WORKER, "HTTP_ROOT", root):
                self.assertTrue(WORKER._collection_slot_artifacts_match(
                    child, context["artifacts"], context,
                ))
                envelope_path = sidecar_dir / "identity-envelope.json"
                for variant in ("deleted", "changed", "foreign-cycle",
                                "attestation-changed"):
                    with self.subTest(envelope_variant=variant):
                        tampered = json.loads(envelope)
                        metadata = dict(tampered["ib_analysis_binding"])
                        if variant == "deleted":
                            del metadata["node"]
                        elif variant == "changed":
                            metadata["expected_topology_sha256"] = "f" * 64
                        else:
                            metadata[
                                "attestation_sha256" if variant == "attestation-changed"
                                else "run_id"
                            ] = ("f" * 64 if variant == "attestation-changed"
                                 else "20260926-0420-prod-ffffffffffffffff")
                        tampered["ib_analysis_binding"] = metadata
                        raw = EMITTER.canonical(tampered)
                        envelope_path.write_bytes(raw)
                        reissued = {**child, "envelope": EMITTER.digest(raw)}
                        self.assertFalse(WORKER._collection_slot_artifacts_match(
                            reissued, context["artifacts"], context,
                        ))
                        envelope_path.write_bytes(envelope)
            worker_context = context
            self.assertTrue(WORKER._collection_validate_artifact_roles(
                json.loads(evidence), root=root, child=child,
                inventory=frozen.read_bytes(), context=worker_context,
            ))
            final = (project / "99-output-ufm/runs" / binding["run_id"]
                     / binding["node"])
            source = observe_ib_cvt_source(snapshot.authority, http_root=root)
            for role in binding["roles"]:
                path = root / role["relative_path"]
                original = path.read_bytes()
                with self.subTest(swapped_role=role["role"]):
                    path.write_bytes(b"cross-cycle-swapped-byte")
                    with self.assertRaises(IbProducerHold):
                        verify_ib_completed_result(
                            identity, snapshot=snapshot, source=source,
                            retrieved=observations[0], final=final,
                            run_id=binding["run_id"], http_root=root,
                        )
                    with self.assertRaises(IbProducerHold):
                        validate_ib_role_binding(identity, binding, http_root=root)
                    self.assertFalse(WORKER._collection_validate_artifact_roles(
                        json.loads(evidence), root=root, child=child,
                        inventory=frozen.read_bytes(), context=worker_context,
                    ))
                    path.write_bytes(original)
            swapped_identity = build_collection_cycle_identity(
                str(project), "prod", 8, "12345678123442348123456789abcdef",
            )
            with self.assertRaises(IbProducerHold):
                verify_ib_completed_result(
                    swapped_identity, snapshot=snapshot, source=source,
                    retrieved=observations[0], final=final,
                    run_id=binding["run_id"], http_root=root,
                )

    def test_real_cgi_cannot_forward_ib_role_payload_to_worker(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        cgi = runpy.run_path(str(source_root / "monitor/switch-collection-control.cgi"))
        payload = "action=collect&ib_analysis_roles=validation_report%3Dfake.xlsx"
        environment = {
            "REQUEST_METHOD": "POST", "HTTP_X_REQUESTED_WITH": "SwitchCollectionControl",
            "CONTENT_LENGTH": str(len(payload)),
        }
        # run_path functions retain their original globals, not the returned dict.
        globals_ = cgi["main"].__globals__
        writer = mock.Mock()
        overrides = {
            "control_request_guard": lambda: (True, ""),
            "post_control_guard": lambda: (True, ""),
            "process_state": lambda: (True, 123),
            "collection_status": lambda: {"state": "idle"},
            "yaml_backup_status": lambda: {"state": "idle"},
            "continuous_collection_status": lambda: {"enabled": False},
            "continuous_backup_status": lambda: {"enabled": False},
            "request_action": lambda: "",
            "write_request": writer,
            "respond": mock.Mock(),
        }
        with mock.patch.dict(cgi["os"].environ, environment, clear=True), \
                mock.patch.dict(globals_, overrides), \
                mock.patch.object(cgi["sys"], "stdin", io.StringIO(payload)):
            cgi["main"]()
        writer.assert_called_once_with("collect")

    def test_real_converter_sidecar_is_source_only_and_stale_setup_selection_holds(self) -> None:
        source_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="ib-cvt-real-workflow-") as directory:
            root = Path(directory).resolve(strict=True)
            config = root / "ztp/config"
            setup = config / "nvos/template/P2P"
            setup.mkdir(parents=True)
            converter = setup / "p2p-to-validation.py"
            shutil.copy2(
                source_root / "ztp/config/nvos/template/P2P/p2p-to-validation.py",
                converter,
            )
            for name in ("topology_rules.py", "ib_topology_provenance.py"):
                shutil.copy2(source_root / "ztp/config" / name, config / name)
            project = root / "DAY0-Prepare/fabric-a"
            project.mkdir(parents=True)
            selected = project / "fabric-blue.xlsx"
            workbook = xlsxwriter.Workbook(str(selected))
            sheet = workbook.add_worksheet("CL links")
            for column, value in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, column, value)
            for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, column, value)
            workbook.close()
            (project / "p2p.xlsx").symlink_to(selected.name)
            (setup / "p2p.xlsx").symlink_to(
                "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx"
            )
            inventory = setup / "01-inventory.log"
            inventory.write_text("[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8")
            port_map = setup / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            splitter = setup / "03-splitter.log"
            splitter.write_text("", encoding="utf-8")
            output = setup / "output-p2p"
            output.mkdir()
            cvt = output / "fabric-blue-cvt.xlsx"
            result = subprocess.run(
                [sys.executable, "-B", str(converter), "--output", str(cvt),
                 "--inventory", str(inventory), "--port-map", str(port_map),
                 "--splitter", str(splitter)],
                cwd=setup,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                     "XLSX_TO_CSV_BASE_DIR": str(setup)},
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=60, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout)
            record = _record()
            record["project_root"] = str(project)
            record["p2p_sha256"] = hashlib.sha256(selected.read_bytes()).hexdigest()
            record["cvt_sha256"] = hashlib.sha256(cvt.read_bytes()).hexdigest()
            sidecar = Path(f"{cvt}.provenance.json")
            record["cvt_provenance_sha256"] = hashlib.sha256(sidecar.read_bytes()).hexdigest()
            authority = parse_ib_producer_authority(
                record, project_key=_HEX, project_root=project,
            )
            observed = observe_ib_cvt_source(authority, http_root=root)
            self.assertEqual(cvt, observed.cvt)
            self.assertFalse(hasattr(observed, "qualified"))
            # Same local CVT bytes cannot license a different selected project.
            (setup / "p2p.xlsx").unlink()
            (setup / "p2p.xlsx").symlink_to(
                "../../../../../DAY0-Prepare/fabric-other/p2p.xlsx"
            )
            with self.assertRaises(IbProducerHold):
                observe_ib_cvt_source(authority, http_root=root)

    def test_real_prod_completion_remains_three_role_when_authority_is_absent(self) -> None:
        identity, artifacts = self._cycle()
        before = self.store.completion_path(identity["sequence"]).read_bytes()
        with tempfile.TemporaryDirectory(prefix="ib-producer-authority-") as directory:
            with mock.patch("monitor.collection_ib_producer._AUTHORITY_DIR", Path(directory)):
                with self.assertRaises(IbProducerHold):
                    load_ib_producer_authority(
                        project_key=identity["project_key"], project_root=self.project,
                    )
        gap = inspect_completed_ib_cycle_roles(
            self.store, http_root=self.root, sequence=identity["sequence"],
        )
        self.assertEqual(("info_archive", "link_archive", "link_csv"), gap.roles)
        self.assertFalse(gap.qualified)
        self.assertEqual(before, self.store.completion_path(identity["sequence"]).read_bytes())
        self.assertTrue(artifacts["infiniband/prod"]["envelope"].is_file())

    def test_child_cannot_hand_fill_six_analysis_roles_into_worker_acceptance(self) -> None:
        identity, artifacts = self._cycle()
        outcome = self.store._validate_completion_record(
            WORKER._read_private_json(self.store.completion_path(identity["sequence"])),
            identity,
        )["run_result"]["outcomes"][1]
        child = outcome["child_result"]
        ib = artifacts["infiniband/prod"]
        evidence = json.loads(ib["envelope"].with_name("evidence-manifest.json").read_bytes())
        frozen = (ib["envelope"].parent.parent / "inputs/infiniband-prod.csv").read_bytes()
        self.assertTrue(WORKER._collection_validate_artifact_roles(
            evidence, root=self.root, child=child, inventory=frozen,
        ))
        evidence["roles"].extend({
            "role": name, "state": "present", "relative_path": "infiniband/monitor/ib-link/fake.csv",
            "sha256": "a" * 64, "size_bytes": 1,
        } for name in (
            "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
            "validation_report", "report_provenance", "ufm_completion_receipt",
        ))
        self.assertFalse(WORKER._collection_validate_artifact_roles(
            evidence, root=self.root, child=child, inventory=frozen,
        ))

    def test_child_context_cannot_supply_ib_role_paths_to_real_emitter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ib-emitter-role-injection-") as directory:
            root = Path(directory)
            args = CollectionV2EmitterContractTests().fixture(root)
            context = json.loads(args.context_file.read_bytes())
            context["ib_analysis_roles"] = {
                "validation_report": "/tmp/unrelated-topology-validation.xlsx",
            }
            args.context_file.write_bytes(EMITTER.canonical(context))
            with mock.patch.object(EMITTER, "ROOT", root), self.assertRaises(ValueError):
                EMITTER.build_result(args)
            sidecar = (root / "monitor/status/collection-cycles"
                       / context["identity"]["project_key"]
                       / "prod/switch_collection/artifacts/00000000000000000007"
                       / "infiniband-prod/evidence-manifest.json")
            self.assertFalse(sidecar.exists())


if __name__ == "__main__":
    unittest.main()
