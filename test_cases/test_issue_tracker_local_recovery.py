"""Cold-process, observation-only recovery contract for C-6 local evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from monitor.issue_tracker_local_commit import begin_generation, commit, record_intent
from monitor.issue_tracker_state_owner import initialize_tracker_state, tracker_writer
from monitor.issue_tracker_local_recovery import inspect_recovered_generations


MANIFEST = b'{"schema_version":1}\n'
PAYLOAD = b"prepared evidence from a governed fake generation\n"


def cold_inspect(project: Path, publication: Path) -> subprocess.CompletedProcess[str]:
    """Import and call the public recovery API in a fresh interpreter."""
    script = """
import json
import sys
from monitor.issue_tracker_local_recovery import inspect_recovered_generations
rows = inspect_recovered_generations(sys.argv[1], sys.argv[2])
print(json.dumps([{
    'generation_id': row.generation_id,
    'sequence': row.sequence,
    'manifest_id': row.manifest_id,
    'status': row.status,
    'prepared_observation': row.prepared_observation,
} for row in rows], sort_keys=True))
"""
    return subprocess.run(
        [sys.executable, "-B", "-c", script, str(project), str(publication)],
        cwd=Path(__file__).resolve().parents[1],
        text=True, capture_output=True, timeout=15,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


def disk_snapshot(project: Path) -> tuple[tuple[str, int, int, bytes], ...]:
    """Bind named file content and inode without using the recovery implementation."""
    root = project / ".tracker"
    entries = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        content = path.read_bytes() if path.is_file() and not path.is_symlink() else b""
        entries.append((str(path.relative_to(root)), info.st_ino, info.st_size, content))
    return tuple(entries)


class LocalRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="tracker-cold-recovery-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve(strict=True)
        self.project = self.base / "project"
        self.project.mkdir(mode=0o755)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir(mode=0o755)
        initialize_tracker_state(
            self.project, self.publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="cold-recovery-first-use",
        )

    def test_cold_process_classifies_empty_intent_and_genuine_receipt_without_writes(self):
        with tracker_writer(self.project, self.publication) as token:
            empty = begin_generation(token, MANIFEST)
            unresolved = begin_generation(token, MANIFEST)
            record_intent(token, unresolved, PAYLOAD)
            published = begin_generation(token, MANIFEST)
            record_intent(token, published, PAYLOAD)
            commit(token, published)
        before = disk_snapshot(self.project)
        result = cold_inspect(self.project, self.publication)
        self.assertEqual(0, result.returncode, result.stderr)
        rows = json.loads(result.stdout)
        self.assertEqual(
            [(empty.generation_id, 1, "UNRESOLVED", "NO-INTENT"),
             (unresolved.generation_id, 2, "UNRESOLVED", "PREPARED-PRESENT"),
             (published.generation_id, 3, "RECEIPT-PRESENT-NOT-ELIGIBILITY", "NONE")],
            [(row["generation_id"], row["sequence"], row["status"],
              row["prepared_observation"]) for row in rows],
        )
        self.assertTrue(all("ELIGIBLE" not in row["status"] for row in rows))
        self.assertEqual(before, disk_snapshot(self.project))
        self.assertEqual(3, len(rows))

    def test_cold_process_rejects_forged_receipt_instead_of_promoting_intent(self):
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PAYLOAD)
        receipt = (self.project / ".tracker" / "generations" /
                   generation.generation_id / "RECEIPT")
        receipt.write_bytes(b'{"schema_version":1,"status":"APPLIED"}\n')
        before = disk_snapshot(self.project)
        result = cold_inspect(self.project, self.publication)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(before, disk_snapshot(self.project))
        self.assertEqual(b'{"schema_version":1,"status":"APPLIED"}\n', receipt.read_bytes())

    def test_cold_process_rejects_missing_generation_state_without_repair(self):
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PAYLOAD)
        state = (self.project / ".tracker" / "generations" /
                 generation.generation_id / "STATE")
        state.unlink()
        before = disk_snapshot(self.project)
        result = cold_inspect(self.project, self.publication)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(before, disk_snapshot(self.project))
        self.assertFalse(state.exists())

    def test_cold_process_rejects_orphan_quarantine_despite_genuine_receipt(self):
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, MANIFEST)
            record_intent(token, generation, PAYLOAD)
            commit(token, generation)
        orphan = self.project / ".tracker" / "quarantine" / "unbound-orphan.bin"
        orphan.write_bytes(b"unexplained prior evidence\n")
        before = disk_snapshot(self.project)
        result = cold_inspect(self.project, self.publication)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(before, disk_snapshot(self.project))
        self.assertEqual(b"unexplained prior evidence\n", orphan.read_bytes())

    def test_cold_process_rejects_generation_symlink_without_leaking_foreign_bytes(self):
        foreign = self.base / "foreign"
        foreign.mkdir()
        sentinel = foreign / "STATE"
        sentinel.write_bytes(b"outside secret sentinel\n")
        alias = (self.project / ".tracker" / "generations" /
                 ("gen-" + "0" * 19 + "1-" + "a" * 32))
        alias.symlink_to(foreign, target_is_directory=True)
        before = disk_snapshot(self.project)
        result = cold_inspect(self.project, self.publication)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn("outside secret sentinel", result.stderr)
        self.assertEqual(before, disk_snapshot(self.project))
        self.assertEqual(b"outside secret sentinel\n", sentinel.read_bytes())


if __name__ == "__main__":
    unittest.main()
