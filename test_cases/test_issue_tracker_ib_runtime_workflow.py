"""REQ7: real CVT and validator output still cannot claim a prod cycle."""

from __future__ import annotations

import hashlib
import datetime as dt
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import xlsxwriter

from monitor.issue_tracker_ib_runtime import (
    IbRuntimeHoldError, parse_ib_validation_rows,
    read_completed_ib_cycle_report, read_ib_local_report,
    require_completed_ib_cycle,
)
from monitor.collection_ib_cycle_binding import IbCycleRoleSource
from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_collection_ib_cycle_binding_workflow import (
    ProdCycleFixture, TOKEN_1, WORKER,
)
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx


ROOT = Path(__file__).resolve().parents[1]
CONVERTER = ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"
VALIDATOR = ROOT / "tools/ibdiagnet-analyze-tool/scripts/validate_ib_topology.py"


class IbRuntimeWorkflowTests(unittest.TestCase):
    def test_real_converter_and_validator_are_not_completed_cycle_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req7-ib-local-flow-") as directory:
            stage = Path(directory)
            p2p = stage / "p2p.xlsx"
            with xlsxwriter.Workbook(str(p2p)) as book:
                links = book.add_worksheet("CL links")
                for column, value in enumerate(("Name", "Port", "Name", "Port")):
                    links.write(0, column, value)
                for column, value in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                    links.write(1, column, value)
            inventory = stage / "01-inventory.log"
            inventory.write_text("[ib]\n*leaf*\n\n[server]\n*server*\n", encoding="utf-8")
            port_map = stage / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            splitter = stage / "03-splitter.log"
            splitter.write_text("", encoding="utf-8")
            cvt = stage / "p2p-cvt.xlsx"
            actual = stage / "iblinkinfo.log"
            actual.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n', encoding="utf-8",
            )
            report = stage / "iblinkinfo-topology-validation.xlsx"
            environment = {**os.environ, "XLSX_TO_CSV_BASE_DIR": str(stage),
                           "PYTHONDONTWRITEBYTECODE": "1"}
            for script, args in ((
                CONVERTER, ("--output", cvt, "--inventory", inventory,
                            "--port-map", port_map, "--splitter", splitter),
            ), (
                VALIDATOR, ("--iblinkinfo", actual, "--p2p", cvt,
                            "--output", report),
            )):
                completed = subprocess.run(
                    [sys.executable, "-B", str(script), *(str(item) for item in args)],
                    cwd=stage, env=environment, text=True, capture_output=True,
                    timeout=60, check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.assertIsInstance(parse_ib_validation_rows(report.read_bytes()), tuple)
            witness = read_ib_local_report(report)
            self.assertEqual(hashlib.sha256(cvt.read_bytes()).hexdigest(),
                             witness.expected_topology_sha256)
            self.assertFalse(witness.qualified)
            source = IbCycleRoleSource(
                cycle_id="synthetic-cycle-1", sequence=1,
                completion_sha256="a" * 64, evidence_sha256="b" * 64,
                roles=("info_archive", "link_archive", "link_csv",
                       "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
                       "validation_report", "report_provenance", "ufm_completion_receipt"),
                report_relative_path=report.relative_to(stage).as_posix(),
                report_sha256=witness.report_sha256,
                expected_topology_sha256=witness.expected_topology_sha256,
                attestation_sha256="c" * 64,
            )
            # The real converter/validator bytes are consumed only after a
            # completed-cycle inspector supplies a source. This patched
            # inspector is a composition seam, not production authority.
            with mock.patch(
                "monitor.collection_ib_cycle_binding.inspect_completed_ib_cycle_roles",
                return_value=source,
            ):
                bound = read_completed_ib_cycle_report(
                    object(), http_root=stage, sequence=1,
                )
            self.assertEqual(source.report_sha256, bound.report_sha256)
            self.assertFalse(bound.qualified)
            with self.assertRaisesRegex(IbRuntimeHoldError, "no IB analyzer artifact role"):
                require_completed_ib_cycle(witness, {
                    "cycle_id": "fabricated", "scope": "prod", "qualifying": True,
                    "source_slots": ("ethernet/prod", "infiniband/prod", "nvlink/prod"),
                })


class ProtectedProdIbKAdapterWorkflowTests(ProdCycleFixture, unittest.TestCase):
    """Use real producer/worker/emitter/replayer modules on a private root."""

    def test_protected_nine_role_cycle_reduces_k_and_w1_then_rejects_drift(self) -> None:
        from monitor.collection_ib_producer import (
            IbProducerAuthoritySnapshot, parse_ib_producer_authority,
            produce_worker_ib_analysis,
        )
        from monitor.issue_tracker_ib_runtime import (
            IbRuntimeHoldError, read_prod_ib_k_window, validate_prod_ib_k_window,
        )
        from test_cases.test_collection_ib_producer import _record
        from tools.project_contract import build_collection_cycle_identity
        from tools.ufm_collection_contract import publish_local_archive
        from tools.ufm_remote_producer import (
            RemoteCollectionObservation, VerifiedRetrievedObservation,
        )

        project = self.root / "DAY0-Prepare/fabric-a"
        project.mkdir(parents=True)
        # The inherited fixture's unused project gate owns the same collection
        # lane lock; close it before opening this producer-shaped project.
        self.gate.__exit__(None, None, None)
        protected_gate = WORKER.CollectionGate(
            str(project), "prod", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        held_gate = protected_gate.__enter__()
        self.addCleanup(lambda: protected_gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=held_gate)
        setup = self.root / "ztp/config/nvos/template/P2P"
        setup.mkdir(parents=True)
        selected = project / "fabric-blue.xlsx"
        with xlsxwriter.Workbook(str(selected)) as book:
            sheet = book.add_worksheet("CL links")
            for col, item in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, col, item)
            for col, item in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, col, item)
        (project / "p2p.xlsx").symlink_to(selected.name)
        (setup / "p2p.xlsx").symlink_to(
            "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx")
        for name, body in (("01-inventory.log", "[ib-sw]\n*leaf*\n\n[server]\n*server*\n"),
                           ("02-port-mapping.log", ""), ("03-splitter.log", "")):
            (setup / name).write_text(body, encoding="utf-8")
        output = setup / "output-p2p"
        output.mkdir()
        cvt = output / "fabric-blue-cvt.xlsx"
        converter = ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"
        converted = subprocess.run(
            [sys.executable, "-B", str(converter), "--output", str(cvt),
             "--inventory", str(setup / "01-inventory.log"),
             "--port-map", str(setup / "02-port-mapping.log"),
             "--splitter", str(setup / "03-splitter.log")],
            cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                            "XLSX_TO_CSV_BASE_DIR": str(setup)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
        incoming = project / "99-output-ufm/incoming"
        incoming.mkdir(parents=True)
        identity = build_collection_cycle_identity(str(project), "prod", 1, TOKEN_1)
        record = _record()
        record.update({
            "project_key": identity["project_key"], "project_root": str(project),
            "retrieval_dir": str(incoming),
            "p2p_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
            "cvt_sha256": hashlib.sha256(cvt.read_bytes()).hexdigest(),
            "cvt_provenance_sha256": hashlib.sha256(
                Path(f"{cvt}.provenance.json").read_bytes()).hexdigest(),
        })
        snapshot = IbProducerAuthoritySnapshot(
            parse_ib_producer_authority(
                record, project_key=identity["project_key"], project_root=project),
            "b" * 64, (1, 2, 3),
        )
        vendor = self.root / "vendor-iblinkinfo.txt"
        vendor.write_text(
            "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
            ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
            '20 1[  ] "server02 mlx5_1"\n', encoding="utf-8",
        )
        protected = self.root / "synthetic-root-attestation"
        protected.mkdir(mode=0o700)

        def retrieved(plan, **_kwargs):
            archive = publish_local_archive(plan, vendor, incoming)
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            return VerifiedRetrievedObservation(
                RemoteCollectionObservation("EXAMPLE-UFM01", plan.run_id,
                                            "iblinkinfo", plan.ufm_remote_path, sha),
                archive, sha, sha, sha, "b" * 64, "b" * 64,
            )

        with mock.patch("monitor.collection_ib_producer._ROOT_UID", os.getuid()), \
             mock.patch("monitor.collection_ib_producer._open_protected_attestation_dir",
                        side_effect=lambda _key: os.open(protected, os.O_RDONLY)), \
             mock.patch("monitor.collection_ib_producer.load_ib_producer_authority",
                        return_value=snapshot), \
             mock.patch("monitor.collection_ib_producer.recheck_ib_producer_authority"), \
             mock.patch("monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                        side_effect=retrieved):
            binding = produce_worker_ib_analysis(
                identity, project_root=project, http_root=self.root,
                clock=lambda: dt.datetime(2026, 9, 26, 4, 20,
                                          tzinfo=dt.timezone.utc),
                runner=lambda _argv: self.fail("transport is supplied by fixture"),
            )
            self._cycle(ib_analysis=binding)
            publication = project / "99-output-monitor"
            publication.mkdir()
            initialize_tracker_state(
                project, publication, initialized_at="2026-09-25T00:00:00Z",
                acquisition_id="req7-protected-ib-k-fixture",
            )
            workbook = publication / "local.xlsx"
            workbook.write_bytes(literal_xlsx())
            with tracker_writer(project, publication) as token:
                set_k(token, new_k=1, actor="operator:fixture",
                      recorded_at="2026-09-25T00:01:00Z",
                      request_id="req7-protected-k-1", expected_revision=0)
                settings = current_k(token)
                whitelist = read_whitelist_workbook(workbook)
                args = {
                    "http_root": self.root, "settings": settings,
                    "whitelist_snapshot": whitelist,
                    "whitelist_path": workbook, "writer_token": token,
                }
                source = read_prod_ib_k_window(self.store, **args)
                self.assertFalse(source.qualified)
                self.assertEqual((identity["cycle_id"],), source.cycle_ids)
                self.assertEqual("prod", self.store.scope)
                self.assertEqual(whitelist.workbook_sha256, source.template_sha256)
                self.assertEqual("2026-09-26T04:20:00Z", source.recorded_at_utc)
                self.assertEqual(1, len(source.rows))
                self.assertEqual("Mis-wiring", source.rows[0].issue_type)
                self.assertEqual("server01", source.rows[0].expected_endpoints[2])
                self.assertEqual("server02", source.rows[0].actual_destination[0])
                self.assertEqual(source, validate_prod_ib_k_window(source, self.store, **args))
                workbook.write_bytes(literal_xlsx(rules=("leaf01",)))
                with self.assertRaises(IbRuntimeHoldError):
                    validate_prod_ib_k_window(source, self.store, **args)
                filtered = read_prod_ib_k_window(
                    self.store, **{**args, "whitelist_snapshot":
                                   read_whitelist_workbook(workbook)},
                )
                self.assertEqual((), filtered.rows)
                self.assertEqual("leaf01", filtered.whitelist_skips[0][1])
                workbook.write_bytes(literal_xlsx())
                attestation = protected / f"{identity['cycle_id']}.json"
                original = attestation.read_bytes()
                attestation.write_bytes(b"{}\n")
                with self.assertRaises(IbRuntimeHoldError):
                    read_prod_ib_k_window(self.store, **args)
                attestation.write_bytes(original)
                attestation.unlink()
                with self.assertRaises(IbRuntimeHoldError):
                    read_prod_ib_k_window(self.store, **args)
                attestation.write_bytes(original)
                set_k(token, new_k=2, actor="operator:fixture",
                      recorded_at="2026-09-25T00:02:00Z",
                      request_id="req7-protected-k-2", expected_revision=1)
                with self.assertRaises(IbRuntimeHoldError):
                    validate_prod_ib_k_window(source, self.store, **args)


if __name__ == "__main__":
    unittest.main()
