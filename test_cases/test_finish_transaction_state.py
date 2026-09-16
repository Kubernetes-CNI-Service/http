#!/usr/bin/env python3
"""Direct contract for durable finished-project transaction state."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tools import finished_project_state as state


TRANSACTION_ID = "finish-20260916T082220Z-0123456789abcdef"


def canonical_sha256(value: object) -> str:
    payload = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def pending_payload(transaction_id: str = TRANSACTION_ID) -> dict[str, object]:
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "project": "customer",
        "runtime": "native",
        "source_manifest_sha256": None,
        "release_sha256": None,
        "created_at": "2026-09-16T08:22:20Z",
    }


class FinishTransactionStateTests(unittest.TestCase):
    def _owner_patches(self):
        return (
            mock.patch.object(state, "_required_owner_uid", return_value=os.getuid()),
            mock.patch.object(state, "_required_owner_gid", return_value=os.getgid()),
        )

    def test_pending_is_private_atomic_idempotent_and_exactly_cleared(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "finish"
            uid_patch, gid_patch = self._owner_patches()
            with uid_patch, gid_patch:
                created = state.create_finish_pending(pending_payload(), root=root)
                self.assertEqual(pending_payload(), created)
                self.assertEqual(pending_payload(), state.read_finish_pending(root))
                self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))
                self.assertEqual(
                    0o600,
                    stat.S_IMODE((root / state.FINISH_PENDING_NAME).stat().st_mode),
                )
                self.assertEqual(
                    pending_payload(),
                    state.create_finish_pending(pending_payload(), root=root),
                    "same transaction retry must be idempotent",
                )
                state.clear_finish_pending(TRANSACTION_ID, root=root)
                self.assertIsNone(state.read_finish_pending(root))

    def test_pending_never_overwrites_or_clears_another_transaction(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "finish"
            uid_patch, gid_patch = self._owner_patches()
            with uid_patch, gid_patch:
                state.create_finish_pending(pending_payload(), root=root)
                other = pending_payload("finish-other")
                with self.assertRaisesRegex(state.FinishStateError, "owns pending"):
                    state.create_finish_pending(other, root=root)
                with self.assertRaisesRegex(state.FinishStateError, "owns pending"):
                    state.clear_finish_pending("finish-other", root=root)
                self.assertEqual(pending_payload(), state.read_finish_pending(root))

    def test_transaction_receipt_advances_only_over_declared_edges(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "finish"
            uid_patch, gid_patch = self._owner_patches()
            with uid_patch, gid_patch:
                planned = state.create_transaction(
                    transaction_id=TRANSACTION_ID,
                    project="customer",
                    runtime="native",
                    created_at="2026-09-16T08:22:20Z",
                    root=root,
                )
                self.assertEqual("planned", planned["state"])
                archiving = state.advance_transaction(
                    TRANSACTION_ID, "pre_stop_archiving", root=root,
                    evidence={"plan_sha256": "a" * 64},
                )
                self.assertEqual("pre_stop_archiving", archiving["state"])
                with self.assertRaisesRegex(state.FinishStateError, "transition"):
                    state.advance_transaction(
                        TRANSACTION_ID, "runtime_stopped", root=root,
                    )
                with self.assertRaisesRegex(state.FinishStateError, "transition"):
                    state.advance_transaction(
                        TRANSACTION_ID, "planned", root=root,
                    )
                receipt = root / "transactions" / TRANSACTION_ID / "transaction.json"
                self.assertEqual(0o600, stat.S_IMODE(receipt.stat().st_mode))
                self.assertEqual(1, receipt.stat().st_nlink)
                on_disk = json.loads(receipt.read_text(encoding="utf-8"))
                self.assertEqual(archiving, on_disk)

    def test_each_committed_stage_binds_time_input_and_output_digests(self):
        created_at = "2026-09-16T08:22:20Z"
        committed_at = "2026-09-16T08:23:21Z"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "finish"
            uid_patch, gid_patch = self._owner_patches()
            with uid_patch, gid_patch:
                planned = state.create_transaction(
                    transaction_id=TRANSACTION_ID,
                    project="customer",
                    runtime="native",
                    created_at=created_at,
                    root=root,
                )
                planned_input = {
                    "created_at": created_at,
                    "project": "customer",
                    "runtime": "native",
                    "transaction_id": TRANSACTION_ID,
                }
                planned_output = {"evidence": {}, "state": "planned"}
                self.assertEqual([{
                    "state": "planned",
                    "committed_at": created_at,
                    "input_sha256": canonical_sha256(planned_input),
                    "output_sha256": canonical_sha256(planned_output),
                }], planned["history"])

                with mock.patch.object(
                    state, "_utc_now", return_value=committed_at, create=True,
                ):
                    archiving = state.advance_transaction(
                        TRANSACTION_ID, "pre_stop_archiving", root=root,
                        evidence={"plan_sha256": "a" * 64},
                    )
                archiving_output = {
                    "evidence": {"plan_sha256": "a" * 64},
                    "state": "pre_stop_archiving",
                }
                self.assertEqual({
                    "state": "pre_stop_archiving",
                    "committed_at": committed_at,
                    "input_sha256": canonical_sha256(planned_output),
                    "output_sha256": canonical_sha256(archiving_output),
                }, archiving["history"][-1])
                self.assertEqual(
                    archiving["history"][-2]["output_sha256"],
                    archiving["history"][-1]["input_sha256"],
                )

    def test_transaction_identity_rejects_symlinked_state(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "finish"
            uid_patch, gid_patch = self._owner_patches()
            with uid_patch, gid_patch:
                state.create_transaction(
                    transaction_id=TRANSACTION_ID,
                    project="customer",
                    runtime="docker",
                    created_at="2026-09-16T08:22:20Z",
                    root=root,
                )
                receipt = root / "transactions" / TRANSACTION_ID / "transaction.json"
                saved = receipt.with_name("saved.json")
                receipt.rename(saved)
                receipt.symlink_to(saved.name)
                with self.assertRaisesRegex(state.FinishStateError, "unsafe|identity"):
                    state.read_transaction(TRANSACTION_ID, root=root)


if __name__ == "__main__":
    unittest.main()
