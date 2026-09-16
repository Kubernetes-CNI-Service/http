#!/usr/bin/env python3
"""Direct contracts for reviewing and publishing V3 finished bundles."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/import-from-download.py"
SPEC = importlib.util.spec_from_file_location("finished_import_contract", SCRIPT)
assert SPEC and SPEC.loader
IMPORTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = IMPORTER
SPEC.loader.exec_module(IMPORTER)

FINISHED_ROOT_NAME = "http-ztp-finished"
FINAL_STATE = "FINISHED_BACKUP_VERIFIED_RUNTIME_STOPPED"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def tar_bytes(files: dict[str, bytes], root: str) -> bytes:
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            directory = tarfile.TarInfo(root)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o700
            directory.uid = directory.gid = 0
            directory.mtime = 0
            archive.addfile(directory)
            for name, payload in sorted(files.items()):
                info = tarfile.TarInfo(f"{root}/{name}")
                info.mode = 0o600
                info.uid = info.gid = 0
                info.mtime = 0
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


def build_finished_bundle(
    path: Path,
    *,
    project: str = "customer",
    corrupt_component: bool = False,
    delta_before_sha256: str | None = None,
    extra_base_files: dict[str, bytes] | None = None,
) -> tuple[str, dict[str, object]]:
    base_files = {
        "delete.txt": b"delete-before\n",
        "keep.txt": b"keep\n",
        "replace.txt": b"replace-before\n",
        **(extra_base_files or {}),
    }
    replacement = b"replace-after\n"
    created = b"created-after-stop\n"
    project_tar = tar_bytes(base_files, "project")
    source_tar = tar_bytes({"tools/example.py": b"print('frozen')\n"}, "source")
    delta_tar = tar_bytes({"new.txt": created, "replace.txt": replacement}, "delta")
    delta_manifest = {
        "schema_version": 1,
        "base_component": "pre-stop/project.tar.gz",
        "changes": [
            {
                "path": "delete.txt",
                "action": "delete",
                "before_sha256": sha256_bytes(base_files["delete.txt"]),
                "sha256": None,
                "size": None,
            },
            {
                "path": "new.txt",
                "action": "create",
                "before_sha256": None,
                "sha256": sha256_bytes(created),
                "size": len(created),
            },
            {
                "path": "replace.txt",
                "action": "replace",
                "before_sha256": delta_before_sha256 or sha256_bytes(base_files["replace.txt"]),
                "sha256": sha256_bytes(replacement),
                "size": len(replacement),
            },
        ],
    }
    payloads = {
        "pre-stop/project.tar.gz": project_tar,
        "pre-stop/deployment-source.tar.gz": source_tar,
        "final-delta/delta.tar.gz": delta_tar,
        "final-delta/delta-manifest.json": (
            json.dumps(delta_manifest, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode(),
        "host-state/runtime.json": b'{"runtime":"native","stopped":true}\n',
        "deployment-footprint.json": b'{"schema_version":1,"paths":[]}\n',
        "deletion-plan.json": b'{"schema_version":1,"items":[]}\n',
        "deletion-plan.md": b"# Deletion plan\n\nNo automatic deletion.\n",
    }
    stages = {
        "pre-stop/project.tar.gz": "pre-stop",
        "pre-stop/deployment-source.tar.gz": "pre-stop",
        "final-delta/delta.tar.gz": "final-delta",
        "final-delta/delta-manifest.json": "final-delta",
        "host-state/runtime.json": "host-state",
        "deployment-footprint.json": "footprint",
        "deletion-plan.json": "deletion-plan",
        "deletion-plan.md": "deletion-plan",
    }
    components = [
        {
            "path": name,
            "size": len(payload),
            "sha256": sha256_bytes(payload),
            "mode": 0o600,
            "schema_version": 1,
            "stage": stages[name],
        }
        for name, payload in sorted(payloads.items())
    ]
    transaction_id = "finish-20260910T010203Z-001"
    identity_basis = {
        "schema_version": 1,
        "project": project,
        "transaction_id": transaction_id,
        "runtime": "native",
        "state": FINAL_STATE,
        "components": components,
    }
    content_sha256 = sha256_bytes(
        json.dumps(identity_basis, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    )
    record_id = f"20260910T010203Z-{content_sha256[:12]}"
    manifest = {
        **identity_basis,
        "bundle_type": FINISHED_ROOT_NAME,
        "created_at": "2026-09-10T01:02:03Z",
        "record_id": record_id,
        "content_sha256": content_sha256,
    }
    manifest_payload = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    checksummed = {**payloads, "bundle-manifest.json": manifest_payload}
    checksum_payload = "".join(
        f"{sha256_bytes(payload)}  {name}\n"
        for name, payload in sorted(checksummed.items())
    ).encode("ascii")
    if corrupt_component:
        payloads["host-state/runtime.json"] = b'{"runtime":"docker","stopped":true}\n'
    all_files = {
        **payloads,
        "bundle-manifest.json": manifest_payload,
        "SHA256SUMS": checksum_payload,
    }
    directories = {
        FINISHED_ROOT_NAME,
        f"{FINISHED_ROOT_NAME}/pre-stop",
        f"{FINISHED_ROOT_NAME}/final-delta",
        f"{FINISHED_ROOT_NAME}/host-state",
    }
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(directories):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o700
            info.uid = info.gid = 0
            info.mtime = 0
            archive.addfile(info)
        for relative, payload in sorted(all_files.items()):
            info = tarfile.TarInfo(f"{FINISHED_ROOT_NAME}/{relative}")
            info.mode = 0o600
            info.uid = info.gid = 0
            info.mtime = 0
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return record_id, manifest


class FinishedProjectImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.day0 = self.root / "DAY0-Prepare"
        self.review_root = self.root / "package-imports"
        self.finished_root = self.root / "Finished-projects"
        self.day0.mkdir()
        self.patches = (
            mock.patch.object(IMPORTER, "ROOT", self.root),
            mock.patch.object(IMPORTER, "DAY0", self.day0),
            mock.patch.object(IMPORTER, "DEFAULT_REVIEW_ROOT", self.review_root),
            mock.patch.object(IMPORTER, "FINISHED_ROOT", self.finished_root, create=True),
        )
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def run_import(self, *arguments: str) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = IMPORTER.main(list(arguments))
        return result, output.getvalue()

    def test_help_separates_legacy_merge_from_finished_review_and_publish(self):
        guidance = IMPORTER.HELP_EPILOG
        self.assertIn("finished bundle", guidance)
        self.assertIn("默认 review-only", guidance)
        self.assertIn("--finish", guidance)
        self.assertIn("Finished-projects/<project>/<record-id>", guidance)
        self.assertIn("不得作为 load、upload 或 sync 输入", guidance)

    def test_finished_bundle_defaults_to_review_only_without_touching_day0(self):
        archive = self.root / "finished.tar.gz"
        record_id, _manifest = build_finished_bundle(archive)
        result, output = self.run_import(str(archive), "--review-root", str(self.review_root))
        self.assertEqual(0, result, output)
        self.assertIn("finished bundle", output)
        self.assertIn("review-only", output)
        self.assertFalse((self.day0 / "customer").exists())
        self.assertFalse((self.finished_root / "customer" / record_id).exists())
        report = json.loads(
            (next(self.review_root.iterdir()) / "finished-import-report.json").read_text(encoding="utf-8")
        )
        self.assertEqual("verified-review-only", report["status"])
        self.assertEqual(record_id, report["record_id"])

    def test_finish_publishes_immutable_record_and_reconstructs_final_view(self):
        archive = self.root / "finished.tar.gz"
        record_id, _manifest = build_finished_bundle(archive)
        result, output = self.run_import(
            str(archive), "--review-root", str(self.review_root), "--finish"
        )
        self.assertEqual(0, result, output)
        record = self.finished_root / "customer" / record_id
        self.assertEqual(0o555, stat.S_IMODE(record.stat().st_mode))
        self.assertEqual(b"keep\n", (record / "reconstructed-final/keep.txt").read_bytes())
        self.assertEqual(b"replace-after\n", (record / "reconstructed-final/replace.txt").read_bytes())
        self.assertEqual(b"created-after-stop\n", (record / "reconstructed-final/new.txt").read_bytes())
        self.assertFalse((record / "reconstructed-final/delete.txt").exists())
        for item in record.rglob("*"):
            self.assertFalse(item.is_symlink(), item)
            expected = 0o555 if item.is_dir() else 0o444
            self.assertEqual(expected, stat.S_IMODE(item.stat().st_mode), item)

    def test_corrupt_finished_bundle_never_downgrades_to_legacy_import(self):
        archive = self.root / "corrupt.tar.gz"
        build_finished_bundle(archive, corrupt_component=True)
        result, output = self.run_import(str(archive), "--review-root", str(self.review_root))
        self.assertEqual(1, result, output)
        self.assertIn("SHA-256", output)
        self.assertFalse(any(self.day0.iterdir()))
        self.assertFalse(self.finished_root.exists())

    def test_archive_and_delta_identity_fail_closed(self):
        archive = self.root / "finished.tar.gz"
        build_finished_bundle(archive)
        hardlink = self.root / "finished-hardlink.tar.gz"
        os.link(archive, hardlink)
        result, output = self.run_import(str(archive), "--review-root", str(self.review_root))
        self.assertEqual(1, result, output)
        self.assertIn("single-link", output)
        hardlink.unlink()
        mismatched = self.root / "mismatched.tar.gz"
        build_finished_bundle(mismatched, delta_before_sha256="0" * 64)
        result, output = self.run_import(str(mismatched), "--review-root", str(self.review_root))
        self.assertEqual(1, result, output)
        self.assertIn("pre-stop SHA-256", output)


if __name__ == "__main__":
    unittest.main()
