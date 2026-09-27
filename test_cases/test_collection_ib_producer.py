"""REQ7 prod IB producer authority never comes from child or CGI data."""

from __future__ import annotations

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from monitor.collection_ib_producer import (
    IbProducerHold, load_ib_producer_authority, parse_ib_producer_authority,
    observe_ib_cvt_source, recheck_ib_producer_authority, _parse_record,
    derive_ib_cycle_run_id, verify_ib_completed_result,
    produce_worker_ib_analysis,
    validate_ib_completion_attestation,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ztp/config"))
from ib_topology_provenance import sidecar_path, write_cvt_provenance


_HEX = "a" * 64


def _record() -> dict:
    return {
        "schema_version": 1,
        "project_key": _HEX,
        "project_root": "/opt/http/DAY0-Prepare/fabric-a",
        "lease_path": "/var/lib/http-ztp-container/leases/ufm.lease",
        "known_hosts_pin": _HEX,
        "jump": {
            "host": "jump.example.test", "user": "root",
            "known_hosts": "/var/lib/http-ztp-container/ssh/known_hosts",
            "identity": "/var/lib/http-ztp-container/ssh/id_ed25519",
        },
        "far": {
            "host": "192.0.2.42", "user": "root",
            "identity_evidence": "project-and-lease-bound",
            "bind_interface": None,
        },
        "install": {
            "root": "/root/ufm-agent", "python_path": "/usr/bin/python3",
            "agent_sha256": _HEX, "contract_sha256": _HEX,
            "python_sha256": _HEX,
        },
        "timeout_seconds": 60,
        "retrieval_dir": "/opt/http/DAY0-Prepare/fabric-a/99-output-ufm/incoming",
        "p2p_sha256": _HEX,
        "cvt_sha256": _HEX,
        "cvt_provenance_sha256": _HEX,
    }


class IbProducerAuthorityDirectTests(unittest.TestCase):
    def test_protected_attestation_is_exact_no_overwrite_private_data(self) -> None:
        from monitor import collection_ib_producer as producer

        with tempfile.TemporaryDirectory(prefix="ib-attestation-") as directory:
            parent = Path(directory)
            project_key = "a" * 64
            cycle_id = "b" * 64
            with mock.patch.object(producer, "_ROOT_UID", os.getuid()), mock.patch.object(
                producer, "_open_protected_attestation_dir",
                side_effect=lambda _key: os.open(parent, os.O_RDONLY),
            ):
                digest = producer._publish_protected_attestation(
                    project_key, cycle_id, {"schema_version": 1},
                )
                path = parent / f"{cycle_id}.json"
                self.assertEqual(b'{"schema_version":1}\n', path.read_bytes())
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                self.assertEqual(0o600, path.stat().st_mode & 0o777)
                with self.assertRaises(IbProducerHold):
                    producer._publish_protected_attestation(
                        project_key, cycle_id, {"schema_version": 1},
                    )
                self.assertEqual(b'{"schema_version":1}\n', path.read_bytes())
                path.chmod(0o644)
                with self.assertRaises(IbProducerHold):
                    producer._read_protected_attestation(project_key, cycle_id)

    def test_ufm_run_id_is_derived_from_the_exact_worker_cycle_identity(self) -> None:
        from test_cases.test_collection_cycle_worker_contract import IDENTITY

        when = dt.datetime(2026, 9, 26, 4, 20, tzinfo=dt.timezone.utc)
        first = derive_ib_cycle_run_id(IDENTITY, when=when)
        self.assertRegex(first, r"^20260926-0420-prod-[0-9a-f]{16}$")
        self.assertEqual(first, derive_ib_cycle_run_id(dict(IDENTITY), when=when))
        changed = dict(IDENTITY)
        changed["run_token"] = "22345678123442348123456789abcdef"
        from tools.project_contract import canonical_collection_cycle_json
        body = {key: value for key, value in changed.items() if key != "cycle_id"}
        changed["cycle_id"] = hashlib.sha256(canonical_collection_cycle_json(body)).hexdigest()
        self.assertNotEqual(first, derive_ib_cycle_run_id(changed, when=when))
        with self.assertRaises(IbProducerHold):
            derive_ib_cycle_run_id({**IDENTITY, "cycle_id": "0" * 64}, when=when)
        with self.assertRaises(IbProducerHold):
            derive_ib_cycle_run_id(IDENTITY, when=when.replace(tzinfo=None))

    def _local_cvt_fixture(self, root: Path) -> tuple[dict, Path, Path]:
        project = root / "DAY0-Prepare/fabric-a"
        project.mkdir(parents=True)
        selected = project / "fabric-blue.xlsx"
        selected.write_bytes(b"selected-p2p-bytes")
        (project / "p2p.xlsx").symlink_to(selected.name)
        setup = root / "ztp/config/nvos/template/P2P"
        setup.mkdir(parents=True)
        (setup / "p2p.xlsx").symlink_to(
            "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx"
        )
        outputs = setup / "output-p2p"
        outputs.mkdir()
        cvt = outputs / "fabric-blue-cvt.xlsx"
        cvt.write_bytes(b"standalone-cvt-fixture-not-a-completed-cycle")
        sources = {"p2p": setup / "p2p.xlsx"}
        for role in ("inventory", "port_map", "splitter", "converter", "topology_rules"):
            source = root / f"{role}.txt"
            source.write_bytes(role.encode())
            sources[role] = source
        write_cvt_provenance(cvt, sources)
        record = _record()
        record["project_root"] = str(project)
        record["p2p_sha256"] = hashlib.sha256(selected.read_bytes()).hexdigest()
        record["cvt_sha256"] = hashlib.sha256(cvt.read_bytes()).hexdigest()
        record["cvt_provenance_sha256"] = hashlib.sha256(
            sidecar_path(cvt).read_bytes()
        ).hexdigest()
        return record, selected, cvt

    def test_valid_record_is_only_parsed_not_declared_a_completed_cycle(self) -> None:
        record = parse_ib_producer_authority(
            _record(), project_key=_HEX,
            project_root=Path("/opt/http/DAY0-Prepare/fabric-a"),
        )
        self.assertEqual(_HEX, record.project_key)
        self.assertEqual(_HEX, record.cvt_sha256)
        self.assertFalse(hasattr(record, "cycle_id"))
        self.assertFalse(hasattr(record, "qualified"))

    def test_wrong_project_stale_cvt_or_callback_field_is_rejected(self) -> None:
        for patch in (
            {"project_key": "other"},
            {"project_root": "/opt/http/DAY0-Prepare/other"},
            {"cvt_sha256": ""},
            {"producer_callback": "trust-me"},
        ):
            with self.subTest(patch=patch), self.assertRaises(IbProducerHold):
                parse_ib_producer_authority(
                    {**_record(), **patch}, project_key=_HEX,
                    project_root=Path("/opt/http/DAY0-Prepare/fabric-a"),
                )

    def test_missing_or_unprotected_authority_path_holds_without_io_side_effects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ib-authority-absent-") as directory:
            root = Path(directory).resolve(strict=True)
            project = root / "project"
            project.mkdir()
            authority_dir = root / "authority"
            authority_dir.mkdir()
            with mock.patch("monitor.collection_ib_producer._AUTHORITY_DIR", authority_dir):
                with self.assertRaises(IbProducerHold):
                    load_ib_producer_authority(
                        project_key=_HEX, project_root=project,
                    )
                self.assertEqual([], list(authority_dir.iterdir()))
                (authority_dir / f"{_HEX}.json").write_text("{}\n", encoding="utf-8")
                with self.assertRaises(IbProducerHold):
                    load_ib_producer_authority(
                        project_key=_HEX, project_root=project,
                    )

    def test_noncanonical_or_duplicate_record_and_replaced_snapshot_hold(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ib-authority-snapshot-") as directory:
            project = Path(directory).resolve(strict=True)
            record = _record()
            record["project_root"] = str(project)
            canonical = (json.dumps(
                record, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
            ) + "\n").encode()
            self.assertEqual(record, _parse_record(canonical))
            for raw in (canonical[:-1], b'{"a":1,"a":2}\n'):
                with self.subTest(raw=raw), self.assertRaises(IbProducerHold):
                    _parse_record(raw)
            identity = (1, 2, 3)
            with mock.patch(
                "monitor.collection_ib_producer._read_root_owned_record",
                return_value=(canonical, identity),
            ):
                snapshot = load_ib_producer_authority(
                    project_key=_HEX, project_root=project,
                )
                recheck_ib_producer_authority(snapshot)
            changed = {**record, "cvt_sha256": "b" * 64}
            changed_raw = (json.dumps(
                changed, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
            ) + "\n").encode()
            with mock.patch(
                "monitor.collection_ib_producer._read_root_owned_record",
                return_value=(changed_raw, identity),
            ), self.assertRaises(IbProducerHold):
                recheck_ib_producer_authority(snapshot)

    def test_no_path_override_or_unscoped_project_key(self) -> None:
        with self.assertRaises(IbProducerHold):
            load_ib_producer_authority(
                project_key="../other", project_root=Path("/opt/http/DAY0-Prepare/a"),
            )
        with self.assertRaises(TypeError):
            load_ib_producer_authority(
                project_key=_HEX,
                project_root=Path("/opt/http/DAY0-Prepare/a"),
                path=Path("/tmp/attacker.json"),
            )

    def test_cvt_source_observation_only_matches_setup_selection_and_installed_digests(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ib-cvt-authority-") as directory:
            root = Path(directory).resolve(strict=True)
            record, selected, cvt = self._local_cvt_fixture(root)
            authority = parse_ib_producer_authority(
                record, project_key=_HEX, project_root=selected.parent,
            )
            observation = observe_ib_cvt_source(authority, http_root=root)
            self.assertEqual(selected, observation.selected_p2p)
            self.assertEqual(cvt, observation.cvt)
            self.assertFalse(hasattr(observation, "cycle_id"))
            self.assertFalse(hasattr(observation, "qualified"))

    def test_absent_stale_or_foreign_cvt_source_cannot_be_observed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ib-cvt-reject-") as directory:
            root = Path(directory).resolve(strict=True)
            for name in (
                "missing sidecar", "changed selected p2p", "changed cvt", "foreign project",
            ):
                with self.subTest(name=name):
                    case_root = root / name.replace(" ", "-")
                    record, selected, cvt = self._local_cvt_fixture(case_root)
                    setup_link = case_root / "ztp/config/nvos/template/P2P/p2p.xlsx"
                    mutate = {
                        "missing sidecar": lambda: sidecar_path(cvt).unlink(),
                        "changed selected p2p": lambda: selected.write_bytes(b"changed"),
                        "changed cvt": lambda: cvt.write_bytes(b"changed"),
                        "foreign project": lambda: setup_link.unlink(),
                    }[name]
                    mutate()
                    authority = parse_ib_producer_authority(
                        record, project_key=_HEX, project_root=selected.parent,
                    )
                    with self.assertRaises(IbProducerHold):
                        observe_ib_cvt_source(
                            authority, http_root=case_root,
                        )

    def test_malformed_provenance_shape_is_classified_as_hold(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ib-cvt-malformed-") as directory:
            root = Path(directory).resolve(strict=True)
            record, selected, _cvt = self._local_cvt_fixture(root)
            authority = parse_ib_producer_authority(
                record, project_key=_HEX, project_root=selected.parent,
            )
            with mock.patch(
                "monitor.collection_ib_producer.read_cvt_provenance",
                return_value={"sources": {}},
            ), self.assertRaises(IbProducerHold):
                observe_ib_cvt_source(authority, http_root=root)

    def test_manual_completion_claim_without_a_real_receipt_holds(self) -> None:
        from test_cases.test_collection_cycle_worker_contract import IDENTITY
        from monitor.collection_ib_producer import (
            IbCvtSourceObservation, IbProducerAuthoritySnapshot,
        )
        from tools.ufm_remote_producer import (
            RemoteCollectionObservation, VerifiedRetrievedObservation,
        )

        with tempfile.TemporaryDirectory(prefix="ib-completion-manual-") as directory:
            root = Path(directory).resolve(strict=True)
            project = root / "DAY0-Prepare/fabric-a"
            project.mkdir(parents=True)
            record = _record()
            record["project_key"] = IDENTITY["project_key"]
            record["project_root"] = str(project)
            record["retrieval_dir"] = str(project / "99-output-ufm/incoming")
            snapshot = IbProducerAuthoritySnapshot(
                parse_ib_producer_authority(
                    record, project_key=IDENTITY["project_key"], project_root=project,
                ), "b" * 64, (1, 2, 3),
            )
            run_id = derive_ib_cycle_run_id(
                IDENTITY, when=dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc),
            )
            final = project / "99-output-ufm/runs" / run_id / "EXAMPLE-UFM01"
            final.mkdir(parents=True)
            archive_name = f"iblinkinfo_{run_id}.tar.gz"
            (final / archive_name).write_bytes(b"manually-written")
            (final / "receipt.json").write_text(
                json.dumps({"run_id": run_id, "node": "EXAMPLE-UFM01"}), encoding="utf-8",
            )
            remote = RemoteCollectionObservation(
                "EXAMPLE-UFM01", run_id, "iblinkinfo", "/root/monitor/iblinkinfo/" + archive_name,
                hashlib.sha256(b"manually-written").hexdigest(),
            )
            retrieved = VerifiedRetrievedObservation(
                remote, project / "99-output-ufm/incoming" / archive_name,
                remote.remote_sha256,
                remote.remote_sha256, remote.remote_sha256,
                "b" * 64, "b" * 64,
            )
            source = IbCvtSourceObservation(
                project / "fabric-blue.xlsx", root / "ztp/config/nvos/template/P2P/output-p2p/fabric-blue-cvt.xlsx",
                "a" * 64, "a" * 64,
            )
            with self.assertRaises(IbProducerHold):
                verify_ib_completed_result(
                    IDENTITY, snapshot=snapshot, source=source, retrieved=retrieved,
                    final=final, run_id=run_id, http_root=root,
                )

    def test_missing_protected_install_never_dispatches_ufm_or_analyzer(self) -> None:
        from tools.project_contract import build_collection_cycle_identity
        with tempfile.TemporaryDirectory(prefix="ib-no-install-") as directory:
            root = Path(directory).resolve(strict=True)
            project = root / "DAY0-Prepare/fabric-a"
            project.mkdir(parents=True)
            identity = build_collection_cycle_identity(
                str(project), "prod", 7, "12345678123442348123456789abcdef",
            )
            with mock.patch(
                "monitor.collection_ib_producer.load_ib_producer_authority",
                side_effect=IbProducerHold("absent root record"),
            ), mock.patch(
                "monitor.collection_ib_producer.observe_and_retrieve_remote_producer"
            ) as remote, mock.patch(
                "monitor.collection_ib_producer.run_local_iblinkinfo"
            ) as analyze, self.assertRaises(IbProducerHold):
                produce_worker_ib_analysis(
                    identity, project_root=project, http_root=root,
                    clock=lambda: dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail("network before authority"),
                )
            remote.assert_not_called()
            analyze.assert_not_called()

    def test_missing_or_existing_protected_cycle_target_never_dispatches_ufm(self) -> None:
        from tools.project_contract import build_collection_cycle_identity
        from monitor.collection_ib_producer import (
            IbCvtSourceObservation, IbProducerAuthoritySnapshot,
        )

        with tempfile.TemporaryDirectory(prefix="ib-no-witness-parent-") as directory:
            root = Path(directory).resolve(strict=True)
            record, _, _ = self._local_cvt_fixture(root)
            project = root / "DAY0-Prepare/fabric-a"
            incoming = project / "99-output-ufm/incoming"
            incoming.mkdir(parents=True)
            identity = build_collection_cycle_identity(
                str(project), "prod", 7, "12345678123442348123456789abcdef",
            )
            record.update({
                "project_key": identity["project_key"],
                "retrieval_dir": str(incoming),
            })
            snapshot = IbProducerAuthoritySnapshot(
                parse_ib_producer_authority(
                    record, project_key=identity["project_key"],
                    project_root=project,
                ), "b" * 64, (1, 2, 3),
            )
            protected = root / "synthetic-attestation-parent"
            protected.mkdir()
            for case in ("missing-parent", "already-published"):
                with self.subTest(case=case):
                    existing = protected / f"{identity['cycle_id']}.json"
                    if case == "already-published":
                        existing.write_bytes(b"{}\n")
                    opener = (mock.Mock(side_effect=IbProducerHold("no protected dir"))
                              if case == "missing-parent" else
                              mock.Mock(side_effect=lambda _key: os.open(
                                  protected, os.O_RDONLY,
                              )))
                    with mock.patch(
                        "monitor.collection_ib_producer.load_ib_producer_authority",
                        return_value=snapshot,
                    ), mock.patch(
                        "monitor.collection_ib_producer._open_protected_attestation_dir",
                        opener,
                    ), mock.patch(
                        "monitor.collection_ib_producer.observe_ib_cvt_source",
                        return_value=IbCvtSourceObservation(
                            project / "fabric-blue.xlsx", root / "cvt.xlsx",
                            "a" * 64, "b" * 64,
                        ),
                    ), mock.patch(
                        "monitor.collection_ib_producer.recheck_ib_producer_authority",
                    ), mock.patch(
                        "monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                    ) as remote, mock.patch(
                        "monitor.collection_ib_producer.run_local_iblinkinfo",
                    ) as analyze, self.assertRaises(IbProducerHold):
                        produce_worker_ib_analysis(
                            identity, project_root=project, http_root=root,
                            clock=lambda: dt.datetime(
                                2026, 9, 26, tzinfo=dt.timezone.utc,
                            ),
                            runner=lambda _argv: self.fail("network before attestation"),
                        )
                    remote.assert_not_called()
                    analyze.assert_not_called()


if __name__ == "__main__":
    unittest.main()
