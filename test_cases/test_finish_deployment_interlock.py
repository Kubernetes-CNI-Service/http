#!/usr/bin/env python3
"""Workflow contract for the durable finished-project writer interlock."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import deployment_lock as locks
from tools import finished_project_state as state


TRANSACTION_ID = "finish-20260916T081150Z-0123456789abcdef"


class FinishDeploymentInterlockTests(unittest.TestCase):
    def _pending(self, root: Path, *, transaction_id: str = TRANSACTION_ID) -> Path:
        root.mkdir(mode=0o700)
        path = root / state.FINISH_PENDING_NAME
        path.write_text(json.dumps({
            "schema_version": 1,
            "transaction_id": transaction_id,
            "project": "customer",
            "runtime": "native",
            "source_manifest_sha256": None,
            "release_sha256": None,
            "created_at": "2026-09-16T08:11:50Z",
        }, sort_keys=True) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_pending_blocks_an_unrelated_writer_after_lock_before_body(self):
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name) / "http"
            finish_root = Path(name) / "finish-state"
            workspace.mkdir()
            pending = self._pending(finish_root)
            entered = False
            with mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(
                        state, "_required_owner_uid", return_value=pending.stat().st_uid,
                    ), mock.patch.object(
                        state, "_required_owner_gid", return_value=pending.stat().st_gid,
                    ):
                with self.assertRaisesRegex(
                    locks.DeploymentLockError,
                    "finish transaction.*customer.*resume",
                ):
                    with locks.deployment_lock(workspace):
                        entered = True
            self.assertFalse(entered)

    def test_only_the_exact_finish_transaction_can_reenter(self):
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name) / "http"
            finish_root = Path(name) / "finish-state"
            workspace.mkdir()
            pending = self._pending(finish_root)
            with mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(
                        state, "_required_owner_uid", return_value=pending.stat().st_uid,
                    ), mock.patch.object(
                        state, "_required_owner_gid", return_value=pending.stat().st_gid,
                    ):
                with locks.deployment_lock(
                    workspace, finish_transaction_id=TRANSACTION_ID,
                ) as descriptor:
                    self.assertIsInstance(descriptor, int)
                with self.assertRaisesRegex(
                    locks.DeploymentLockError, "different finish transaction",
                ):
                    with locks.deployment_lock(
                        workspace, finish_transaction_id="finish-other",
                    ):
                        pass

    def test_dry_run_remains_read_only_but_reports_pending(self):
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name) / "http"
            finish_root = Path(name) / "finish-state"
            workspace.mkdir()
            pending = self._pending(finish_root)
            with mock.patch.object(state, "FINISH_STATE_ROOT", finish_root), \
                    mock.patch.object(
                        state, "_required_owner_uid", return_value=pending.stat().st_uid,
                    ), mock.patch.object(
                        state, "_required_owner_gid", return_value=pending.stat().st_gid,
                    ):
                with locks.deployment_lock(workspace, dry_run=True) as descriptor:
                    self.assertIsNone(descriptor)
            self.assertFalse((workspace / ".deployment.lock").exists())


if __name__ == "__main__":
    unittest.main()
