"""REQ6: a historical sweep and later collection share one private backup tree.

Only synthetic YAML is created under a temporary project.  The collector's SSH
boundary is replaced; both production filesystem paths run unmodified.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_production(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load production script: {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BACKUP = load_production("req6_real_backup_producer", "ztp/backup/yaml-collect.py")
SWEEP = load_production("req6_real_permission_sweep", "ztp/backup/permission-sweep.py")
OLD_YAML = b"hashed-password: synthetic-old\n"
NEW_YAML = "hashed-password: synthetic-new\n"


def device():
    return {
        "hostname": "leaf02", "fmt": "eth",
        "eth0_ip": "192.0.2.10", "eth0_pfx": "24",
        "eth0_gw": "192.0.2.1", "eth0_mac": "02:00:00:00:00:02",
        "eth1_ip": "", "eth1_pfx": "", "eth1_gw": "",
        "alternate_ssh_ips": [], "transition_ssh_ips": [],
        "dynamic_dhcp": False,
    }


def synthetic_ssh(_user, _password, _target, command, **_kwargs):
    if command.startswith("hostname"):
        return "leaf02\n", "", 0
    if command.startswith("sudo "):
        return NEW_YAML, "", 0
    return "", "", 0


class BackupPermissionConvergenceWorkflow(unittest.TestCase):
    def make_old_tree(self, base):
        root = base / "project" / "99-output-backup"
        family = root / "20260927_0001-prod-backup" / "eth"
        family.mkdir(parents=True)
        old = family / "leaf01.yaml"
        old.write_bytes(OLD_YAML)
        old.chmod(0o644)
        for directory in (root, family.parent, family):
            directory.chmod(0o755)
        return root, old

    def assert_private_tree(self, root):
        yaml_count = 0
        wide_hashed_count = 0
        for directory, _children, files in os.walk(root):
            self.assertEqual(0, stat.S_IMODE(os.lstat(directory).st_mode) & ~0o700)
            for filename in files:
                path = Path(directory) / filename
                if not filename.endswith(".yaml"):
                    continue
                yaml_count += 1
                mode = stat.S_IMODE(os.lstat(path).st_mode)
                self.assertEqual(0, mode & ~0o600)
                if mode & ~0o600 and b"hashed-password" in path.read_bytes():
                    wide_hashed_count += 1
        self.assertEqual(2, yaml_count)
        self.assertEqual(0, wide_hashed_count)

    def test_sweep_then_real_collector_does_not_reopen_historical_exposure(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, old = self.make_old_tree(base)
            old_before = old.stat()
            old_digest = hashlib.sha256(old.read_bytes()).hexdigest()
            state = base / "root-private-state"
            frozen = SWEEP.freeze_manifest(root, state, project_name="project")
            frozen_bytes = Path(frozen["manifest_path"]).read_bytes()
            self.assertEqual(hashlib.sha256(frozen_bytes).hexdigest(), frozen["sha256"])
            SWEEP.apply_manifest(
                Path(frozen["manifest_path"]), frozen["sha256"],
                state / "result.jsonl", resume=False,
            )
            self.assertEqual(old_before.st_ino, old.stat().st_ino)
            self.assertEqual(old_digest, hashlib.sha256(old.read_bytes()).hexdigest())
            self.assertEqual(0o600, stat.S_IMODE(old.stat().st_mode))
            self.assertTrue(any(
                row["path"].endswith("leaf01.yaml") and row["status"] == "completed"
                for row in (json.loads(line) for line in
                            (state / "result.jsonl").read_text().splitlines())
            ))

            name = "20260928_0001-prod-backup"
            staging, _final = BACKUP._stage_private_backup_tree(root, name)
            previous_umask = os.umask(0o022)
            try:
                with mock.patch.object(BACKUP, "_ssh", side_effect=synthetic_ssh):
                    _log, result = BACKUP.collect_device(
                        device(), staging, "synthetic-password", "", "",
                    )
            finally:
                os.umask(previous_umask)
            self.assertTrue(result["yaml_ok"])
            report = BACKUP._publish_and_retain_backup_batch(
                root, staging, name, environment="prod",
            )
            self.assertIn("publish", report["events"])
            self.assertEqual(NEW_YAML.encode(),
                             (root / name / "eth" / "leaf02.yaml").read_bytes())
            self.assertEqual(old_digest, hashlib.sha256(old.read_bytes()).hexdigest())
            self.assert_private_tree(root)

    def test_sweep_then_real_collection_deduplicates_and_prunes_without_widening(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, sentinel = self.make_old_tree(base)
            sentinel_before = sentinel.stat()
            sentinel_digest = hashlib.sha256(sentinel.read_bytes()).hexdigest()
            oldest_name = "20260927_0001-prod-backup"
            previous_names = [
                "20260927_0002-prod-backup",
                "20260927_0003-prod-backup",
                "20260927_0004-prod-backup",
            ]
            current_name = "20260928_0001-prod-backup"
            oldest_shared = root / oldest_name / "eth" / "leaf02.yaml"
            oldest_shared.write_bytes(b"version-0\n")
            oldest_shared.chmod(0o644)
            for name, payload in zip(previous_names, (
                b"version-1\n", b"version-2\n", NEW_YAML.encode(),
            )):
                family = root / name / "eth"
                family.mkdir(parents=True, mode=0o700)
                family.parent.chmod(0o700)
                family.chmod(0o700)
                leaf = family / "leaf02.yaml"
                leaf.write_bytes(payload)
                leaf.chmod(0o600)

            state = base / "root-private-state"
            frozen = SWEEP.freeze_manifest(root, state, project_name="project")
            SWEEP.apply_manifest(
                Path(frozen["manifest_path"]), frozen["sha256"],
                state / "result.jsonl", resume=False,
            )
            self.assertEqual(0o600, stat.S_IMODE(sentinel.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(oldest_shared.stat().st_mode))

            # Scope the count cap to this synthetic five-batch fixture.  The
            # production cap remains 100; this exercises the same real branch
            # without fabricating 101 backup directories or changing code.
            previous_umask = os.umask(0o022)
            try:
                staging, _final = BACKUP._stage_private_backup_tree(root, current_name)
                with mock.patch.object(BACKUP, "_ssh", side_effect=synthetic_ssh):
                    _log, result = BACKUP.collect_device(
                        device(), staging, "synthetic-password", "", "",
                    )
                self.assertTrue(result["yaml_ok"])
                with mock.patch.object(BACKUP, "BACKUP_RETENTION_CAP", 3):
                    report = BACKUP._publish_and_retain_backup_batch(
                        root, staging, current_name, environment="prod",
                    )
            finally:
                os.umask(previous_umask)

            self.assertEqual(
                ["publish", "deduplicate", "version-prune",
                 "batch-prune", "batch-prune"], report["events"],
            )
            self.assertEqual(
                [f"{previous_names[-1]}/eth/leaf02.yaml"],
                report["deduplicated"],
            )
            self.assertEqual(
                [f"{oldest_name}/eth/leaf02.yaml"],
                report["version_pruned"],
            )
            self.assertEqual(previous_names[:2], report["batch_pruned"])
            self.assertFalse(oldest_shared.exists())
            self.assertFalse((root / previous_names[0]).exists())
            self.assertFalse((root / previous_names[1]).exists())
            self.assertFalse((root / previous_names[2] / "eth" / "leaf02.yaml").exists())
            self.assertEqual(
                NEW_YAML.encode(),
                (root / current_name / "eth" / "leaf02.yaml").read_bytes(),
            )
            self.assertEqual(sentinel_before.st_ino, sentinel.stat().st_ino)
            self.assertEqual(sentinel_digest, hashlib.sha256(sentinel.read_bytes()).hexdigest())
            self.assertEqual(OLD_YAML, sentinel.read_bytes())
            self.assert_private_tree(root)

    def test_post_freeze_collector_activity_blocks_sweep_before_old_chmod(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root, old = self.make_old_tree(base)
            # This negative isolates the new collector entry from a mere root
            # mode correction: the frozen root itself is already private.
            root.chmod(0o700)
            state = base / "root-private-state"
            frozen = SWEEP.freeze_manifest(root, state, project_name="project")
            staging, _final = BACKUP._stage_private_backup_tree(
                root, "20260928_0001-prod-backup",
            )
            with mock.patch.object(BACKUP, "_ssh", side_effect=synthetic_ssh):
                _log, result = BACKUP.collect_device(
                    device(), staging, "synthetic-password", "", "",
                )
            self.assertTrue(result["yaml_ok"])
            with self.assertRaises(SWEEP.SweepError):
                SWEEP.apply_manifest(
                    Path(frozen["manifest_path"]), frozen["sha256"],
                    state / "result.jsonl", resume=False,
                )
            self.assertEqual(0o644, stat.S_IMODE(old.stat().st_mode))
            self.assertEqual(OLD_YAML, old.read_bytes())


if __name__ == "__main__":
    unittest.main()
