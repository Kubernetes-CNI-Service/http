#!/usr/bin/env python3
"""Local-only UFM archive handoff: fail closed before a public receipt."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
PIPELINE = load_script("ufm_collection_pipeline_direct", ROOT / "tools/ufm_collection_pipeline.py")
HTML = load_script("ufm_candidate_panel_direct", ROOT / "monitor/generate-monitor-html.py")

RUN_ID = "20260926-0315-air-0123456789abcdef"


class UfmCollectionPipelineTests(unittest.TestCase):
    def directory_read_scope(self):
        scope = getattr(PIPELINE, '_hold_reusable_directory_reads', None)
        self.assertTrue(callable(scope), 'repeated checks need an actual held-FD scope')
        return scope()

    def test_repeated_directory_reads_open_each_original_ancestor_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); leaf = root / 'a' / 'b'
            leaf.mkdir(parents=True)
            real_open = os.open; opened = []
            def opening(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if flags & os.O_DIRECTORY:
                    opened.append(descriptor)
                return descriptor
            with mock.patch.object(PIPELINE.os, 'open', side_effect=opening):
                with self.directory_read_scope():
                    for _ in range(5):
                        with PIPELINE._hold_real_dir_chain(leaf) as (fd, verify, identities):
                            self.assertEqual(leaf.stat().st_ino, os.fstat(fd).st_ino)
                            self.assertEqual(len(leaf.parts), len(identities))
                            verify()
                self.assertEqual(len(leaf.parts), len(opened))
                for descriptor in opened:
                    with self.assertRaises(OSError): os.fstat(descriptor)

    def test_sibling_directory_reads_share_only_original_ancestors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); first = root / 'a'; second = root / 'b'
            first.mkdir(); second.mkdir()
            real_open = os.open; opened = []
            def opening(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if flags & os.O_DIRECTORY: opened.append(descriptor)
                return descriptor
            with mock.patch.object(PIPELINE.os, 'open', side_effect=opening):
                with self.directory_read_scope():
                    for leaf in (first, second, first, second):
                        with PIPELINE._hold_real_dir_chain(leaf) as (fd, verify, _):
                            self.assertEqual(leaf.stat().st_ino, os.fstat(fd).st_ino); verify()
                self.assertEqual(len(root.parts) + 2, len(opened))

    def test_reused_directory_scope_rejects_same_leaf_through_replaced_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = root / 'parent'; leaf = parent / 'leaf'
            leaf.mkdir(parents=True); original = leaf.stat().st_ino
            with self.assertRaises(PIPELINE.PipelineError):
                with self.directory_read_scope():
                    with PIPELINE._hold_real_dir_chain(leaf): pass
                    moved = root / 'moved'; parent.rename(moved); parent.mkdir()
                    (moved / 'leaf').rename(leaf)
                    self.assertEqual(original, leaf.stat().st_ino)
                    with PIPELINE._hold_real_dir_chain(leaf): pass

    def test_reused_directory_scope_verifies_original_names_at_scope_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); leaf = root / 'leaf'; leaf.mkdir()
            with self.assertRaises(PIPELINE.PipelineError):
                with self.directory_read_scope():
                    with PIPELINE._hold_real_dir_chain(leaf): pass
                    leaf.rename(root / 'moved'); leaf.mkdir()

    def test_reused_directory_scope_does_not_cache_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); archive = root / 'owned.tar.gz'
            archive.write_bytes(b'independent original archive')
            with self.directory_read_scope():
                witness = PIPELINE._source_archive_witness(archive)
                old_time = archive.stat().st_mtime_ns
                archive.write_bytes(b'independent changed archive!')
                os.utime(archive, ns=(old_time, old_time))
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE._require_source_archive_witness(archive, witness)

    def test_reused_directory_scope_is_closed_after_failed_body(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); held = []
            with self.assertRaisesRegex(RuntimeError, 'independent failure'):
                with self.directory_read_scope():
                    with PIPELINE._hold_real_dir_chain(root) as (fd, _, _): held.append(fd)
                    raise RuntimeError('independent failure')
            with self.assertRaises(OSError): os.fstat(held[0])
            with self.directory_read_scope():
                with PIPELINE._hold_real_dir_chain(root) as (fd, verify, _): verify()

    def test_archive_witness_rejects_real_ancestor_replace_with_same_leaf_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / "parent"
            incoming = parent / "incoming"
            incoming.mkdir(parents=True)
            archive = incoming / "owned.tar.gz"
            archive.write_bytes(b"independent retrieved archive")
            original = PIPELINE._source_archive_witness(archive)
            parent.rename(root / "moved")
            parent.mkdir()
            (root / "moved" / "incoming").rename(incoming)
            self.assertEqual(original.parent_identity, (incoming.stat().st_dev, incoming.stat().st_ino))
            self.assertEqual(original.file_identity[1], archive.stat().st_ino)
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._require_source_archive_witness(archive, original)

    def test_archive_witness_refuses_symlink_ancestor_even_when_leaf_inode_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); real=root/'real'; incoming=real/'incoming'
            incoming.mkdir(parents=True); archive=incoming/'owned.tar.gz'
            archive.write_bytes(b'independent retrieved archive')
            witness=PIPELINE._source_archive_witness(archive)
            alias=root/'alias'; alias.symlink_to(real,target_is_directory=True)
            self.assertEqual(archive.stat().st_ino,(alias/'incoming'/archive.name).stat().st_ino)
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._source_archive_witness(alias/'incoming'/archive.name)
            PIPELINE._require_source_archive_witness(archive,witness)

    def test_archive_witness_refuses_ancestor_rebind_during_held_file_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); parent=root/'parent'; incoming=parent/'incoming'
            incoming.mkdir(parents=True); archive=incoming/'owned.tar.gz'
            archive.write_bytes(b'independent retrieved archive')
            original=archive.stat().st_ino; real_read=os.read; rebound=[]
            def reading(fd,size):
                data=real_read(fd,size)
                if data and os.fstat(fd).st_ino==original and not rebound:
                    moved=root/'moved'; parent.rename(moved)
                    parent.symlink_to(moved,target_is_directory=True); rebound.append(True)
                return data
            with mock.patch.object(PIPELINE.os,'read',side_effect=reading):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE._source_archive_witness(archive)
            self.assertEqual([True],rebound)
            self.assertEqual(original,archive.stat().st_ino)

    def test_output_root_refuses_ancestor_alias_with_same_held_project_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); parent=root/'parent'; project=parent/'project'
            project.mkdir(parents=True); held=PIPELINE._open_real_dir(project)
            try:
                self.assertTrue(PIPELINE._same_root_inode(project,held))
                moved=root/'moved'; parent.rename(moved)
                parent.symlink_to(moved,target_is_directory=True)
                self.assertEqual(os.fstat(held).st_ino,project.stat().st_ino)
                self.assertFalse(PIPELINE._same_root_inode(project,held),
                                 'same leaf is not authority through a rebound ancestor')
            finally: os.close(held)

    def test_receipt_reader_rejects_node_rebind_after_path_provenance_parse(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            node = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            node.mkdir(parents=True)
            report_name = PIPELINE._report_name(plan)
            report = node / report_name
            report.write_bytes(b"synthetic report")
            (node / plan.archive_name).write_bytes(b"synthetic archive")
            sidecar = PIPELINE.sidecar_path(report)
            sidecar.write_bytes(b'{"report":"synthetic"}\n')
            report_sha = hashlib.sha256(report.read_bytes()).hexdigest()
            receipt = {
                "schema": "ufm-collection-v1", "status": "success",
                "kind": plan.kind, "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "archive": plan.archive_name,
                "archive_sha256": hashlib.sha256(b"synthetic archive").hexdigest(),
                "report": report_name, "report_sha256": report_sha,
                "report_provenance_sha256": hashlib.sha256(sidecar.read_bytes()).hexdigest(),
            }
            (node / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            rebound: list[bool] = []

            def rebind_after_parse(_report: Path) -> dict:
                report_bytes, sidecar_bytes = report.read_bytes(), sidecar.read_bytes()
                node.rename(node.with_name("moved-node"))
                node.mkdir()
                report.write_bytes(report_bytes)
                sidecar.write_bytes(sidecar_bytes)
                rebound.append(True)
                return {"report": {"sha256": report_sha}}

            with mock.patch.object(PIPELINE, "read_report_provenance",
                                   side_effect=rebind_after_parse):
                self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertEqual([True], rebound)
            self.assertFalse((node / "receipt.json").exists())
            self.assertFalse((node / plan.archive_name).exists())

    def test_receipt_reader_rejects_sidecar_replaced_between_hash_and_provenance_parse(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            node = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            node.mkdir(parents=True)
            report_name = PIPELINE._report_name(plan)
            report = node / report_name
            report.write_bytes(b"synthetic report")
            (node / plan.archive_name).write_bytes(b"synthetic archive")
            sidecar = PIPELINE.sidecar_path(report)
            sidecar.write_bytes(b'{"report":"synthetic"}\n')
            report_sha = hashlib.sha256(report.read_bytes()).hexdigest()
            receipt = {
                "schema": "ufm-collection-v1", "status": "success",
                "kind": plan.kind, "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "archive": plan.archive_name,
                "archive_sha256": hashlib.sha256(b"synthetic archive").hexdigest(),
                "report": report_name, "report_sha256": report_sha,
                "report_provenance_sha256": hashlib.sha256(sidecar.read_bytes()).hexdigest(),
            }
            (node / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            replaced: list[bool] = []

            def replace_before_parse(_report: Path) -> dict:
                replacement = node / "replacement-sidecar"
                replacement.write_bytes(b" " + sidecar.read_bytes())
                replacement.replace(sidecar)
                replaced.append(True)
                return {"report": {"sha256": report_sha}}

            with mock.patch.object(PIPELINE, "read_report_provenance",
                                   side_effect=replace_before_parse):
                self.assertEqual([], PIPELINE.validated_receipts(project, "air"))
            self.assertEqual([True], replaced)

    def test_receipt_reader_rejects_replaced_name_and_missing_nofollow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            receipt = root / "receipt.json"
            receipt.write_bytes(b'{"status":"success"}')
            original_inode = receipt.stat().st_ino
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            real_read = os.read
            replaced: list[bool] = []

            def replace_after_read(descriptor: int, size: int) -> bytes:
                data = real_read(descriptor, size)
                if data and os.fstat(descriptor).st_ino == original_inode and not replaced:
                    replacement = root / "replacement"
                    replacement.write_bytes(b'{"status":"failed"}')
                    replacement.replace(receipt)
                    replaced.append(True)
                return data

            try:
                with mock.patch.object(PIPELINE.os, "read", side_effect=replace_after_read):
                    with self.assertRaises(PIPELINE.PipelineError):
                        PIPELINE._read_regular_at(directory_fd, "receipt.json",
                                                  max_bytes=4096)
                self.assertEqual([True], replaced)
                with mock.patch.object(PIPELINE.os, "O_NOFOLLOW", 0):
                    with self.assertRaises(PIPELINE.PipelineError):
                        PIPELINE._read_regular_at(directory_fd, "receipt.json",
                                                  max_bytes=4096)
            finally:
                os.close(directory_fd)

    def test_receipt_json_duplicate_keys_cannot_become_a_success_claim(self):
        unique = b'{"schema":"ufm-collection-v1","status":"success"}'
        self.assertEqual("success", PIPELINE._parse_receipt_json(unique)["status"])
        for ambiguous in (
            b'{"schema":"ufm-collection-v1","status":"failed","status":"success"}',
            b'{"schema":"ufm-collection-v1","archive_sha256":"old",'
            b'"archive_sha256":"new"}',
            b'{"schema":"ufm-collection-v1","nested":{"kind":"old",'
            b'"kind":"new"}}',
        ):
            with self.subTest(ambiguous=ambiguous):
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE._parse_receipt_json(ambiguous)
        with self.assertRaises(PIPELINE.PipelineError):
            PIPELINE._parse_receipt_json(b"[" * 1100 + b"0" + b"]" * 1100)

    def test_staged_archive_digest_must_match_independent_source_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory).resolve() / "staged.tar.gz"
            staged.write_bytes(b"original source archive bytes")
            expected = hashlib.sha256(b"original source archive bytes").hexdigest()
            self.assertEqual(expected, PIPELINE._require_staged_archive_digest(staged, expected))
            staged.write_bytes(b"replacement archive bytes")
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._require_staged_archive_digest(staged, expected)

    def test_source_archive_witness_rejects_byte_drift_and_same_byte_replace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "ibdiagnet2_example.tar.gz"
            archive.write_bytes(b"independent-archive-input")
            first = PIPELINE._source_archive_witness(archive)
            PIPELINE._require_source_archive_witness(archive, first)
            before = archive.stat()
            archive.write_bytes(b"independent-archive-inpuT")
            os.utime(archive, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._require_source_archive_witness(archive, first)

            second = PIPELINE._source_archive_witness(archive)
            replacement = root / "replacement"
            replacement.write_bytes(archive.read_bytes())
            replacement.replace(archive)
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._require_source_archive_witness(archive, second)

            incoming = root / "incoming"
            incoming.mkdir()
            nested = incoming / archive.name
            nested.write_bytes(archive.read_bytes())
            third = PIPELINE._source_archive_witness(nested)
            same_bytes = nested.read_bytes()
            incoming.rename(root / "moved-incoming")
            incoming.mkdir()
            (incoming / archive.name).write_bytes(same_bytes)
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._require_source_archive_witness(nested, third)

    def test_candidate_panel_refuses_unbound_preview_without_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            baseline = HTML.render_ufm_evidence_panel(project, "air")
            candidate = {
                "schema": "ufm-collection-v1", "status": "success",
                "kind": "iblinkinfo", "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "archive": f"iblinkinfo_{RUN_ID}.tar.gz",
                "archive_sha256": "0" * 64,
                "report": f"iblinkinfo_{RUN_ID}-topology-validation.xlsx",
                "report_sha256": "1" * 64,
                "report_provenance_sha256": "2" * 64,
            }
            for changed in (
                {**candidate, "archive": "iblinkinfo_other.tar.gz"},
                {**candidate, "report_sha256": "not-a-digest"},
                {**candidate, "status": "unverified"},
            ):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    HTML.render_ufm_candidate_panel(project, "air", changed)
            self.assertEqual(baseline, HTML.render_ufm_evidence_panel(project, "air"))
            self.assertFalse((project / "99-output-ufm").exists())

    def test_missing_stage_attestation_refuses_before_a_result_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            report, log, cvt = (root / "report.xlsx", root / "actual.log",
                                root / "cvt.xlsx")
            for path in (report, log, cvt):
                path.write_bytes(b"synthetic")
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE._staged_analysis_attestation(report, log, cvt)

    def test_held_result_chain_rejects_replaced_node_and_missing_nofollow(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve() / "project"
            node = project / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            node.mkdir(parents=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            root_fd = os.open(project, flags)
            run_fd = os.open(node.parent, flags)
            node_fd = os.open(node, flags)
            try:
                self.assertTrue(PIPELINE._result_chain_still_bound(
                    root_fd, plan, node.name, run_fd, node_fd))
                with mock.patch.object(PIPELINE.os, "O_NOFOLLOW", 0):
                    self.assertFalse(PIPELINE._result_chain_still_bound(
                        root_fd, plan, node.name, run_fd, node_fd))
                node.rename(project / "retained-original-node")
                node.mkdir()
                self.assertFalse(PIPELINE._result_chain_still_bound(
                    root_fd, plan, node.name, run_fd, node_fd))
            finally:
                os.close(node_fd)
                os.close(run_fd)
                os.close(root_fd)

    def test_report_sidecar_publication_never_overwrites_an_incumbent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            name = "report.xlsx.provenance.json"
            incumbent = root / name
            incumbent.write_bytes(b"operator-owned-sidecar")
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE._publish_result_sidecar_at(
                        directory_fd, name, {"schema": "synthetic-only"},
                    )
            finally:
                os.close(directory_fd)
            self.assertEqual(b"operator-owned-sidecar", incumbent.read_bytes())
            self.assertEqual([incumbent], list(root.iterdir()))

    def test_intermediate_output_symlink_cannot_import_external_receipt(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "project"
            project.mkdir()
            external = root / "external"
            node = external / "runs" / RUN_ID / "EXAMPLE-UFM01"
            node.mkdir(parents=True)
            archive = node / plan.archive_name
            report = node / f"iblinkinfo_{RUN_ID}-topology-validation.xlsx"
            archive.write_bytes(b"external-archive")
            report.write_bytes(b"external-report")
            (node / "receipt.json").write_text(json.dumps({
                "schema": "ufm-collection-v1", "status": "success", "kind": "iblinkinfo",
                "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "archive": archive.name,
                "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "report": report.name,
                "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
            }), encoding="utf-8")
            (project / "99-output-ufm").symlink_to(external, target_is_directory=True)
            self.assertEqual([], PIPELINE.validated_receipts(project, "air"))

    def test_archive_member_must_be_the_single_nonempty_regular_artifact(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"synthetic-cvt-marker")
            output = root / "project"
            output.mkdir()
            for body in (b"", b"not a gzip archive"):
                archive = root / plan.archive_name
                archive.write_bytes(body)
                with self.subTest(body=body), self.assertRaises(PIPELINE.PipelineError):
                    PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, output)
                self.assertFalse((output / "99-output-ufm").exists())

    def test_wrong_run_name_or_existing_result_never_overwrites(self):
        plan = PIPELINE.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "iblinkinfo_other.tar.gz"
            archive.write_bytes(b"synthetic")
            cvt = root / "cvt.xlsx"
            cvt.write_bytes(b"synthetic-cvt-marker")
            output = root / "project"
            output.mkdir()
            with self.assertRaises(PIPELINE.PipelineError):
                PIPELINE.run_local_iblinkinfo(plan, "EXAMPLE-UFM01", archive, cvt, output)
            self.assertFalse((output / "99-output-ufm").exists())

    def test_receipt_schema_cannot_claim_success_without_bound_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            run = root / "99-output-ufm" / "runs" / RUN_ID / "EXAMPLE-UFM01"
            run.mkdir(parents=True)
            (run / "receipt.json").write_text(json.dumps({
                "schema": "ufm-collection-v1", "status": "success",
                "kind": "iblinkinfo", "run_id": RUN_ID, "node": "EXAMPLE-UFM01",
                "report": f"iblinkinfo_{RUN_ID}-topology-validation.xlsx",
                "report_sha256": "0" * 64,
            }), encoding="utf-8")
            self.assertEqual([], PIPELINE.validated_receipts(root, "air"))



if __name__ == "__main__":
    unittest.main()
