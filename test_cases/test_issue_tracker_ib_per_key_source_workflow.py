"""RED real IB producer -> protected worker/emitter -> per-key source."""

import datetime as dt
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import xlsxwriter

from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, tracker_writer,
)
from test_cases.test_issue_tracker_ib_per_key_source import KEY_A, source
from test_cases.test_collection_ib_cycle_binding_workflow import ProdCycleFixture, WORKER
from test_cases.test_collection_ib_producer import _record
from tools.project_contract import build_collection_cycle_identity
from tools.ufm_collection_contract import publish_local_archive
from tools.ufm_remote_producer import (
    RemoteCollectionObservation, VerifiedRetrievedObservation,
)


ROOT = Path(__file__).resolve().parents[1]


class IbPerKeySourceWorkflowTests(unittest.TestCase):
    setUp = ProdCycleFixture.setUp
    _cycle = ProdCycleFixture._cycle

    def _protected_cycle(self):
        from monitor.collection_ib_producer import (
            IbProducerAuthoritySnapshot, parse_ib_producer_authority,
            produce_worker_ib_analysis,
        )

        project = self.root / "DAY0-Prepare/fabric-a"
        project.mkdir(parents=True)
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
        from test_cases.test_collection_ib_cycle_binding_workflow import TOKEN_1
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

        # Keep the synthetic root-owned authority mount and loopback transport
        # available for the adapter's independent readback below as well.
        patchers = (
            mock.patch("monitor.collection_ib_producer._ROOT_UID", os.getuid()),
            mock.patch("monitor.collection_ib_producer._open_protected_attestation_dir",
                       side_effect=lambda _key: os.open(protected, os.O_RDONLY)),
            mock.patch("monitor.collection_ib_producer.load_ib_producer_authority",
                       return_value=snapshot),
            mock.patch("monitor.collection_ib_producer.recheck_ib_producer_authority"),
            mock.patch("monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                       side_effect=retrieved),
        )
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
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
            acquisition_id="req7-ib-per-key-fixture",
        )
        return project, publication, protected / f"{identity['cycle_id']}.json", identity

    def test_real_nine_role_cycle_pending_then_attestation_drift_holds(self):
        project, publication, attestation, identity = self._protected_cycle()
        SOURCE = source(self)
        with tracker_writer(project, publication) as token:
            args = {
                "http_root": self.root, "settings": current_k(token),
                "key": KEY_A, "writer_token": token,
            }
            result = SOURCE.read_prod_ib_per_key_source(self.store, **args)
            self.assertEqual((identity["cycle_id"],), result.cycle_ids)
            self.assertEqual(("pending", 1, 3),
                             (result.state, result.observed, result.required))
            self.assertFalse(result.qualified)
            attestation.write_bytes(b"{}\n")
            with self.assertRaises(SOURCE.IbPerKeySourceHold):
                SOURCE.read_prod_ib_per_key_source(self.store, **args)


if __name__ == "__main__":
    unittest.main()

