#!/usr/bin/env python3
"""Direct contract for collection-cycle parsing and lifecycle wrappers."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MONITOR = ROOT / "monitor"
TOOLS = ROOT / "tools"
for path in (str(MONITOR), str(TOOLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from project_contract import (
    COLLECTION_CYCLE_MAX_FAILED_DEVICES,
    COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES,
)


def load_worker():
    spec = importlib.util.spec_from_file_location(
        "collection_cycle_worker_contract_target",
        MONITOR / "switch-collection-worker.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


WORKER = load_worker()
PREFIX = "[HTTP_ZTP_TASK_RESULT] "
IDENTITY = {
    "project_key": hashlib.sha256(b"/fixture-project").hexdigest(),
    "run_token": "12345678123442348123456789abcdef",
    "scope": "prod",
    "sequence": 7,
    "source": "switch_collection",
}
IDENTITY["cycle_id"] = hashlib.sha256(json.dumps(
    IDENTITY, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
).encode("utf-8")).hexdigest()


def marker(payload: dict) -> str:
    return PREFIX + json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ) + "\n"


def legacy(*, state: str = "success") -> dict:
    if state == "failed":
        return {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "failed",
            "planned": 1,
            "succeeded": 0,
            "failed_count": 1,
            "failed_devices": [{
                "hostname": "leaf01",
                "operation": "collection,ssh_prepare",
                "reason": "界" * 1024,
            }],
        }
    return {
        "schema_version": 1,
        "task": "switch_collection",
        "state": "success",
        "planned": 0,
        "succeeded": 0,
        "failed_count": 0,
        "failed_devices": [],
    }


def v2(slot: str) -> dict:
    return {
        "schema_version": 2,
        "task": "switch_collection",
        **IDENTITY,
        "source_slot": slot,
        "state": "success",
        "planned": 0,
        "succeeded": 0,
        "failed_count": 0,
        "failed_devices": [],
        "evidence": {
            "sha256": hashlib.sha256(b"evidence").hexdigest(),
            "size_bytes": len(b"evidence"),
        },
        "envelope": {
            "sha256": hashlib.sha256(b"envelope").hexdigest(),
            "size_bytes": len(b"envelope"),
        },
        "input_inventory_sha256": hashlib.sha256(b"inventory").hexdigest(),
    }


class CollectionCycleWorkerContractTests(unittest.TestCase):
    def test_backup_task_parser_rejects_zero_planned_without_rejecting_empty_collection_slot(self):
        zero = legacy()
        zero["task"] = "yaml_backup"
        with self.assertRaisesRegex(ValueError, "zero planned devices"):
            WORKER.parse_task_result(marker(zero), "yaml_backup")

        zero["task"] = "switch_collection"
        self.assertEqual(
            zero,
            WORKER.parse_task_result(marker(zero), "switch_collection"),
        )

    def test_shared_legacy_parser_consumes_only_bounds_and_preserves_backup_operations(self):
        source = (MONITOR / "switch-collection-worker.py").read_text(encoding="utf-8")
        self.assertNotIn("MAX_TASK_RESULT_DEVICES = 10000", source)
        self.assertNotIn("MAX_TASK_RESULT_TEXT_BYTES = 1024", source)
        self.assertEqual(
            COLLECTION_CYCLE_MAX_FAILED_DEVICES,
            WORKER.MAX_TASK_RESULT_DEVICES,
        )
        self.assertEqual(
            COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES,
            WORKER.MAX_TASK_RESULT_TEXT_BYTES,
        )

        for operation in ("yaml_backup", "connect"):
            payload = {
                "schema_version": 1,
                "task": "yaml_backup",
                "state": "failed",
                "planned": 1,
                "succeeded": 0,
                "failed_count": 1,
                "failed_devices": [{
                    "hostname": "leaf-backup",
                    "operation": operation,
                    "reason": "backup unavailable",
                }],
            }
            self.assertEqual(
                payload,
                WORKER.parse_task_result(marker(payload), "yaml_backup"),
            )

            collection_payload = legacy(state="failed")
            collection_payload["failed_devices"][0]["operation"] = operation
            with self.assertRaises(WORKER.CollectionSlotParseError):
                WORKER.parse_collection_slot_result(
                    marker(collection_payload),
                    expected_context=IDENTITY,
                    expected_slot="ethernet/prod",
                )

    def test_lifecycle_vocabulary_is_closed_unique_and_disjoint(self):
        child = WORKER.COLLECTION_SLOT_CHILD_STATES
        outcomes = WORKER.COLLECTION_SLOT_TERMINAL_OUTCOMES
        self.assertIsInstance(child, tuple)
        self.assertIsInstance(outcomes, tuple)
        self.assertEqual(("success", "partial", "failed"), child)
        self.assertEqual(len(child), len(set(child)))
        self.assertEqual(len(outcomes), len(set(outcomes)))
        self.assertFalse(set(child) & set(outcomes))
        self.assertEqual({
            "accepted", "cancelled", "crashed", "worker_error",
            "missing_marker", "malformed_marker", "duplicate_marker",
            "extra_marker", "returncode_conflict", "artifact_mismatch",
            "identity_mismatch",
        }, set(outcomes))

    def test_new_run_api_requires_existing_timeout_and_lock_wait_authorities(self):
        parameters = inspect.signature(WORKER.run_collection_slots).parameters
        self.assertIs(inspect.Parameter.empty, parameters["timeout"].default)
        self.assertIs(inspect.Parameter.empty, parameters["lock_wait"].default)

    def test_parser_accepts_v2_and_retains_bounded_v1_without_upgrade(self):
        slot = "ethernet/prod"
        parsed_v2 = WORKER.parse_collection_slot_result(
            marker(v2(slot)), expected_context=IDENTITY, expected_slot=slot,
        )
        self.assertEqual(v2(slot), parsed_v2)

        parsed_v1 = WORKER.parse_collection_slot_result(
            marker(legacy(state="failed")),
            expected_context=IDENTITY,
            expected_slot=slot,
        )
        self.assertEqual(1, parsed_v1["schema_version"])
        self.assertEqual("collection,ssh_prepare",
                         parsed_v1["failed_devices"][0]["operation"])
        self.assertEqual("界" * 341, parsed_v1["failed_devices"][0]["reason"])
        for forbidden in (*IDENTITY, "source_slot", "operations"):
            self.assertNotIn(forbidden, parsed_v1)

    def test_parser_reports_distinct_marker_and_identity_causes(self):
        slot = "ethernet/prod"
        bad_identity = v2(slot)
        bad_identity["run_token"] = "ffeeddccbbaa49888776655443322110"
        cases = (
            ("collector log only\n", "missing_marker"),
            (PREFIX + "{bad-json\n", "malformed_marker"),
            (marker(legacy()) * 2, "duplicate_marker"),
            (marker(legacy()) * 3, "extra_marker"),
            (marker(bad_identity), "identity_mismatch"),
        )
        for output, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(WORKER.CollectionSlotParseError) as caught:
                    WORKER.parse_collection_slot_result(
                        output,
                        expected_context=IDENTITY,
                        expected_slot=slot,
                    )
                self.assertEqual(expected, caught.exception.outcome)

    def test_run_returns_one_immutable_terminal_wrapper_per_declared_slot(self):
        commands = [["collector", slot] for slot in (
            "ethernet/prod", "infiniband/prod", "nvlink/prod",
        )]
        outputs = iter((
            ({"returncode": 0, "stdout": marker(legacy()), "stderr": ""}, False),
            ({"returncode": 1, "stdout": marker(legacy(state="failed")),
              "stderr": "unreachable"}, False),
            ({"returncode": -15, "stdout": "", "stderr": "terminated"}, False),
        ))
        with mock.patch.object(WORKER, "commands_for_scope", return_value=commands), \
                mock.patch.object(WORKER, "run_interruptible",
                                  side_effect=lambda *a, **k: next(outputs)):
            result = WORKER.run_collection_slots(
                copy.deepcopy(IDENTITY), artifact_bindings={}, timeout=10,
                lock_wait=0,
            )

        self.assertEqual(IDENTITY, result["identity"])
        self.assertEqual({"identity", "outcomes", "summary"}, set(result))
        self.assertIsNone(result["summary"])
        self.assertEqual(
            ["ethernet/prod", "infiniband/prod", "nvlink/prod"],
            [item["source_slot"] for item in result["outcomes"]],
        )
        self.assertEqual(
            ["accepted", "accepted", "crashed"],
            [item["outcome"] for item in result["outcomes"]],
        )
        self.assertTrue(all(
            set(item) == {"source_slot", "outcome", "child_result", "evidence"}
            for item in result["outcomes"]
        ))
        self.assertEqual(1, result["outcomes"][1]["child_result"]["schema_version"])
        self.assertIsNone(result["outcomes"][2]["child_result"])
        evidence = result["outcomes"][1]["evidence"]
        self.assertEqual({"stdout", "stderr", "returncode"}, set(evidence))
        self.assertEqual(
            {"sha256": hashlib.sha256(b"unreachable").hexdigest(),
             "size_bytes": len(b"unreachable")},
            evidence["stderr"],
        )

    def test_all_accepted_v1_children_still_have_no_run_summary(self):
        slots = ("ethernet/prod", "infiniband/prod", "nvlink/prod")
        commands = [["collector", slot] for slot in slots]
        outputs = iter(
            ({"returncode": 0, "stdout": marker(legacy()), "stderr": ""}, False)
            for _slot in slots
        )
        with mock.patch.object(WORKER, "commands_for_scope", return_value=commands), \
                mock.patch.object(WORKER, "run_interruptible",
                                  side_effect=lambda *a, **k: next(outputs)):
            result = WORKER.run_collection_slots(
                copy.deepcopy(IDENTITY), artifact_bindings={}, timeout=10,
                lock_wait=0,
            )

        self.assertEqual(["accepted"] * len(slots), [
            item["outcome"] for item in result["outcomes"]
        ])
        self.assertEqual([1] * len(slots), [
            item["child_result"]["schema_version"]
            for item in result["outcomes"]
        ])
        self.assertIsNone(
            result["summary"],
            "accepted legacy evidence must never become a run summary",
        )

    def test_non_success_wrapper_cannot_carry_or_be_upgraded_to_child(self):
        evidence = {
            "stdout": {"sha256": hashlib.sha256(b"").hexdigest(),
                       "size_bytes": 0},
            "stderr": {"sha256": hashlib.sha256(b"bad").hexdigest(),
                       "size_bytes": 3},
            "returncode": 2,
        }
        invalid = {
            "source_slot": "ethernet/prod",
            "outcome": "malformed_marker",
            "child_result": legacy(),
            "evidence": evidence,
        }
        with self.assertRaises(ValueError):
            WORKER.validate_collection_slot_outcome(
                invalid, expected_slot="ethernet/prod",
                expected_context=IDENTITY,
            )


if __name__ == "__main__":
    unittest.main()
