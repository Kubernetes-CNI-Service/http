#!/usr/bin/env python3
"""Independent direct contract for the private A4 collection-v2 publisher."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_activity_source import write_eth_activity_evidence


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "collection_v2_emitter_contract", ROOT / "monitor/collection_v2_emitter.py"
)
assert SPEC is not None and SPEC.loader is not None
EMITTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EMITTER)


def identity() -> dict:
    body = {
        "project_key": hashlib.sha256(b"/project-fixture").hexdigest(),
        "run_token": "12345678123442348123456789abcdef",
        "scope": "prod", "sequence": 7, "source": "switch_collection",
    }
    body["cycle_id"] = hashlib.sha256(json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return body


class CollectionV2EmitterContractTests(unittest.TestCase):
    def eth_activity_fixture(self, root: Path) -> tuple[argparse.Namespace, Path, Path]:
        chosen = {**identity(), "scope": "all"}
        body = {key: chosen[key] for key in (
            "project_key", "run_token", "scope", "sequence", "source"
        )}
        chosen["cycle_id"] = hashlib.sha256(json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        slot = "ethernet/prod"
        leaf = (root / "monitor/status/collection-cycles" / chosen["project_key"]
                / "all/switch_collection/artifacts/00000000000000000007")
        private = leaf / "inputs"
        private.mkdir(parents=True)
        inventory = private / "ethernet-prod.csv"
        inventory.write_bytes(b"hostname,type,eth0_ip\nleaf-a,eth,192.0.2.10\n")
        p2p = private / "ethernet-prod.p2p.xlsx"
        p2p.write_bytes(b"literal workbook authority")
        dot = private / "ethernet-prod.dot"
        dot.write_bytes(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n')
        lldp_inventory = private / "ethernet-prod.lldp-inventory.log"
        lldp_inventory.write_bytes(b"[Eth-SW]\nleaf-*\n")
        aliases = private / "ethernet-prod.aliases.json"
        aliases.write_bytes(b'{"schema_version":1,"canonical_to_aliases":{}}')
        sidecar = private / "ethernet-prod.activity.json"
        output = leaf / "ethernet-prod"
        activity_sources = {
            "dot": dot, "inventory": lldp_inventory, "device_aliases": aliases,
        }
        context = {
            "identity": chosen, "source_slot": slot,
            "artifacts": {
                "evidence": str(output / "evidence-manifest.json"),
                "envelope": str(output / "identity-envelope.json"),
                "input_inventory": str(inventory),
            },
            "input_inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest(),
            "activity": {
                "schema_version": 1,
                "source_slot": slot,
                "topology": {"path": str(p2p), "sha256": hashlib.sha256(p2p.read_bytes()).hexdigest()},
                "sources": {
                    role: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                    for role, path in activity_sources.items()
                },
                "sidecar_path": str(sidecar),
            },
        }
        context_path = root / "eth-context.json"
        context_path.write_bytes(EMITTER.canonical(context))
        archive_x = root / "ethernet/monitor/eth-info/20260925-0315-air.tar.gz"
        archive_y = archive_x.with_name("20260925-0315-prod.tar.gz")
        archive_x.parent.mkdir(parents=True)
        archive_x.write_bytes(b"literal archive X")
        archive_y.write_bytes(b"literal archive Y")
        report = (root / "tools/lldp-analyze-tool/99-output-p2p"
                  / "20260925-0315-air-ethernet-topology-validation.xlsx").resolve()
        report.parent.mkdir(parents=True)
        report.write_bytes(b"literal report")
        all_sources = {**activity_sources, "archive": archive_x}
        write_eth_activity_evidence(
            sidecar, sources=all_sources,
            source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                           for role, path in all_sources.items()},
            report_path=report,
            result_records=[{
                "device_a": "leaf-a", "interface_a": "swp1",
                "device_b": "leaf-z", "interface_b": "swp2",
                "status": "CONFIRMED_BOTH_SIDE", "dot_line": 1,
                "observation_a": {"remote_host": "leaf-z", "remote_port": "swp2"},
                "observation_b": {"remote_host": "leaf-a", "remote_port": "swp1"},
            }],
            cycle_binding={
                "identity": chosen, "source_slot": slot,
                "context_sha256": hashlib.sha256(EMITTER.canonical(context)).hexdigest(),
            },
        )
        planned = root / "eth-planned.txt"
        planned.write_text("leaf-a\n", encoding="utf-8")
        legacy = root / "eth-legacy.txt"
        legacy.write_text(EMITTER.PREFIX + json.dumps({
            "schema_version": 1, "task": "switch_collection", "state": "success",
            "planned": 1, "succeeded": 1, "failed_count": 0, "failed_devices": [],
        }, separators=(",", ":")) + "\n", encoding="utf-8")
        return argparse.Namespace(
            context_file=context_path, legacy_result_file=legacy,
            planned_file=planned, info=archive_x, link=None, csv=None,
            activity=sidecar,
        ), archive_x, archive_y

    def test_eth_activity_exact_archive_cross_binding_and_foreign_slot_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, archive_x, archive_y = self.eth_activity_fixture(root)
            with mock.patch.object(EMITTER, "ROOT", root):
                args.info = archive_y
                with self.assertRaises(ValueError):
                    EMITTER.build_result(args)
                args.info = archive_x
                child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                self.assertEqual(
                    ["info_archive", "link_archive", "link_csv", "activity_observation"],
                    [role["role"] for role in json.loads(evidence)["roles"]],
                )
                self.assertEqual(hashlib.sha256(args.activity.read_bytes()).hexdigest(),
                                 json.loads(evidence)["roles"][3]["sha256"])
                EMITTER.publish(sidecar_dir, evidence, envelope)
                self.assertEqual(args.activity.read_bytes(),
                                 (sidecar_dir / "activity-observation.json").read_bytes())
                self.assertEqual(2, child["schema_version"])

    def test_eth_activity_report_must_be_exact_archive_stem_in_canonical_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, _archive_x, _archive_y = self.eth_activity_fixture(root)
            payload = json.loads(args.activity.read_bytes())
            foreign = root / "foreign-report.xlsx"
            foreign.write_bytes(b"literal report")
            payload["report"]["path"] = str(foreign)
            args.activity.write_text(json.dumps(payload, sort_keys=True,
                                                separators=(",", ":")), encoding="utf-8")
            with mock.patch.object(EMITTER, "ROOT", root), self.assertRaises(ValueError):
                EMITTER.build_result(args)

    def fixture(self, root: Path) -> argparse.Namespace:
        chosen = identity()
        slot = "infiniband/prod"
        leaf = (root / "monitor/status/collection-cycles" / chosen["project_key"]
                / "prod/switch_collection/artifacts/00000000000000000007")
        sidecars = leaf / "infiniband-prod"
        inventory = leaf / "inputs/infiniband-prod.csv"
        inventory.parent.mkdir(parents=True)
        frozen = b"hostname,type,eth0_ip\nleaf-ib,ib,192.0.2.11\n"
        inventory.write_bytes(frozen)
        context = {
            "identity": chosen, "source_slot": slot,
            "artifacts": {
                "evidence": str(sidecars / "evidence-manifest.json"),
                "envelope": str(sidecars / "identity-envelope.json"),
                "input_inventory": str(inventory),
            },
            "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
        }
        context_path = root / "context.json"
        context_path.write_bytes(EMITTER.canonical(context))
        planned = root / "planned.txt"
        planned.write_text("leaf-ib\n", encoding="utf-8")
        legacy = root / "legacy.txt"
        legacy.write_text(
            EMITTER.PREFIX + json.dumps({
                "schema_version": 1, "task": "switch_collection",
                "state": "success", "planned": 1, "succeeded": 1,
                "failed_count": 0, "failed_devices": [],
            }, separators=(",", ":")) + "\n", encoding="utf-8",
        )
        paths = []
        for stem, suffix in (("ib-info", ".tar.gz"),
                             ("ib-link", ".tar.gz"), ("ib-link", ".csv")):
            path = root / "infiniband/monitor" / stem / ("20260925-0315" + suffix)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"port,peer\n1,fixture\n" if suffix == ".csv" else b"archive")
            paths.append(path)
        return argparse.Namespace(
            context_file=context_path, legacy_result_file=legacy,
            planned_file=planned, info=paths[0], link=paths[1], csv=paths[2],
        )

    def test_exact_members_publish_atomically_and_bind_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            with mock.patch.object(EMITTER, "ROOT", root):
                child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                self.assertFalse(sidecar_dir.exists())
                EMITTER.publish(sidecar_dir, evidence, envelope)
            self.assertEqual(2, child["schema_version"])
            self.assertEqual(identity()["cycle_id"], child["cycle_id"])
            self.assertEqual(evidence, (
                sidecar_dir / "evidence-manifest.json"
            ).read_bytes())
            self.assertEqual(envelope, (
                sidecar_dir / "identity-envelope.json"
            ).read_bytes())
            self.assertEqual(
                ["info_archive", "link_archive", "link_csv"],
                [role["role"] for role in json.loads(evidence)["roles"]],
            )

    def test_publish_rejects_rebound_status_symlink_without_foreign_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            with mock.patch.object(EMITTER, "ROOT", root):
                _child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                status = root / "monitor/status"
                foreign = root / "foreign-status"
                status.rename(foreign)
                status.symlink_to(foreign, target_is_directory=True)
                leaked = foreign / sidecar_dir.relative_to(status)

                with self.assertRaises((OSError, ValueError)):
                    EMITTER.publish(sidecar_dir, evidence, envelope)
                self.assertFalse(leaked.exists())

    def test_publish_rejects_symlink_lock_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            with mock.patch.object(EMITTER, "ROOT", root):
                _child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                foreign_lock = root / "foreign-lock"
                foreign_lock.write_bytes(b"independent lock contents")
                (sidecar_dir.parent / ".publish.lock").symlink_to(foreign_lock)

                with self.assertRaises((OSError, ValueError)):
                    EMITTER.publish(sidecar_dir, evidence, envelope)
                self.assertFalse(sidecar_dir.exists())
                self.assertEqual(b"independent lock contents", foreign_lock.read_bytes())

    def test_publish_rejects_hardlinked_lock_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            with mock.patch.object(EMITTER, "ROOT", root):
                _child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                foreign_lock = root / "foreign-lock"
                foreign_lock.write_bytes(b"independent lock contents")
                os.link(foreign_lock, sidecar_dir.parent / ".publish.lock")

                with self.assertRaises((OSError, ValueError)):
                    EMITTER.publish(sidecar_dir, evidence, envelope)
                self.assertFalse(sidecar_dir.exists())
                self.assertEqual(b"independent lock contents", foreign_lock.read_bytes())

    def test_publish_does_not_resolve_new_status_path_after_rename_rebind(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            with mock.patch.object(EMITTER, "ROOT", root):
                _child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                status = root / "monitor/status"
                original_status = root / "original-status"
                real_rename = os.rename
                rebound = False

                def rebind_before_publication(source, destination, *args, **kwargs):
                    nonlocal rebound
                    if not rebound:
                        real_rename(status, original_status)
                        status.mkdir()
                        if isinstance(source, Path):
                            relative_stage = source.relative_to(status)
                        else:
                            relative_stage = sidecar_dir.parent.relative_to(status) / source
                        spoof_stage = status / relative_stage
                        spoof_stage.mkdir(parents=True)
                        (spoof_stage / "evidence-manifest.json").write_bytes(
                            b"untrusted replacement evidence"
                        )
                        rebound = True
                    return real_rename(source, destination, *args, **kwargs)

                with mock.patch.object(EMITTER.os, "rename", side_effect=rebind_before_publication):
                    with self.assertRaisesRegex(ValueError, "ancestry changed"):
                        EMITTER.publish(sidecar_dir, evidence, envelope)
                self.assertTrue(rebound)
                self.assertFalse(
                    sidecar_dir.exists(),
                    "the newly bound status directory must receive no authority",
                )
                self.assertFalse(
                    (original_status / sidecar_dir.relative_to(status)).exists(),
                    "a failed publication must remove the detached sidecar",
                )

    def test_timestamp_mismatch_and_publish_failure_leave_no_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            wrong = args.csv.with_name("20260925-0316.csv")
            wrong.write_bytes(args.csv.read_bytes())
            args.csv = wrong
            with mock.patch.object(EMITTER, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "timestamps disagree"):
                    EMITTER.build_result(args)
                # The normal link CSV has the same timestamp as the archive.
                args.csv = root / "infiniband/monitor/ib-link/20260925-0315.csv"
                child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
                self.assertEqual(2, child["schema_version"])
                with mock.patch.object(EMITTER.os, "rename", side_effect=OSError("injected")):
                    with self.assertRaises(OSError):
                        EMITTER.publish(sidecar_dir, evidence, envelope)
            self.assertFalse(sidecar_dir.exists())
            self.assertFalse(list(sidecar_dir.parent.glob(".v2-evidence-*")))

    def test_missing_required_archive_refuses_sidecars_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            args.link.unlink()
            with mock.patch.object(EMITTER, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "missing"):
                    EMITTER.build_result(args)
            sidecars = list((root / "monitor/status").rglob(
                "evidence-manifest.json"
            ))
            self.assertEqual([], sidecars)

    def test_two_passwords_cannot_change_helper_output_or_enter_sidecars(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixture(root)
            variants = []
            with mock.patch.object(EMITTER, "ROOT", root):
                for password in ("secret-password-A", "secret-password-B"):
                    with mock.patch.dict(os.environ, {
                        "SSHPASS": password, "SSH_ASKPASS_VALUE": password,
                    }):
                        variants.append(EMITTER.build_result(args)[:3])
            self.assertEqual(variants[0], variants[1])
            for value in variants:
                for content in value[1:]:
                    self.assertNotIn(b"secret-password-A", content)
                    self.assertNotIn(b"secret-password-B", content)


if __name__ == "__main__":
    unittest.main()
