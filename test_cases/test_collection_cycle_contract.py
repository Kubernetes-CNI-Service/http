#!/usr/bin/env python3
"""Direct pure contracts for governed collection-cycle evidence.

The pure identity builder deliberately accepts a caller-supplied run token as a
test-injection seam.  B3-A5's refusal of externally supplied tokens belongs to
the worker/request boundary: CLI flags, environment variables, CGI request
fields, and child-result fields must never become token authorities.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
from pathlib import Path
import re
import sys
import unittest
from collections.abc import Mapping


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import project_contract as CONTRACT


EXPECTED_SOURCE_SLOTS = {
    "air": ("ethernet/air",),
    "prod": (
        "ethernet/prod",
        "infiniband/prod",
        "nvlink/prod",
    ),
    "all": (
        "ethernet/air",
        "ethernet/prod",
        "infiniband/prod",
        "nvlink/prod",
    ),
}
PROJECT_IDENTITY = "工程/prod\n"
PROJECT_KEY = hashlib.sha256(PROJECT_IDENTITY.encode("utf-8")).hexdigest()
RUN_TOKEN = "00112233445546778899aabbccddeeff"
OTHER_RUN_TOKEN = "ffeeddccbbaa49888776655443322110"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
HTML_ERROR_SHA = hashlib.sha256(
    b"fixture monitor.html generation failed"
).hexdigest()
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
EXPECTED_SUMMARY_KEYS = {
    "identity",
    "results",
    "qualifying",
    "qualification_reasons",
    "complete_empty",
    "slot_counts",
    "html_annotation",
}
EXPECTED_FAILED_DEVICE_OPERATIONS = (
    "collection",
    "ssh_prepare",
)
EXPECTED_MAX_FAILED_DEVICES = 10000
EXPECTED_MAX_FAILED_DEVICE_TEXT_BYTES = 1024


def canonical_bytes(value: object) -> bytes:
    """Independent oracle; expectations never come from production code."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def expected_identity(
    scope: str = "prod",
    sequence: int = 7,
    run_token: str = RUN_TOKEN,
    project_identity: str = PROJECT_IDENTITY,
) -> dict:
    project_key = hashlib.sha256(project_identity.encode("utf-8")).hexdigest()
    body = {
        "project_key": project_key,
        "run_token": run_token,
        "scope": scope,
        "sequence": sequence,
        "source": "switch_collection",
    }
    return {
        **body,
        "cycle_id": hashlib.sha256(canonical_bytes(body)).hexdigest(),
    }


def recompute_cycle_id(identity: dict) -> dict:
    body = {key: value for key, value in identity.items() if key != "cycle_id"}
    return {
        **body,
        "cycle_id": hashlib.sha256(canonical_bytes(body)).hexdigest(),
    }


def valid_result(
    slot: str,
    *,
    scope: str = "prod",
    sequence: int = 7,
    run_token: str = RUN_TOKEN,
    state: str = "success",
    planned: int = 2,
    succeeded: int = 2,
    failures: list[dict] | None = None,
) -> dict:
    failed_devices = copy.deepcopy(failures or [])
    identity = expected_identity(
        scope=scope,
        sequence=sequence,
        run_token=run_token,
    )
    return {
        "schema_version": 2,
        "task": "switch_collection",
        **identity,
        "source_slot": slot,
        "state": state,
        "planned": planned,
        "succeeded": succeeded,
        "failed_count": len(failed_devices),
        "failed_devices": failed_devices,
        "evidence": {"sha256": SHA_A, "size_bytes": 123},
        "envelope": {"sha256": SHA_B, "size_bytes": 456},
        "input_inventory_sha256": SHA_C,
    }


def legacy_result() -> dict:
    return {
        "schema_version": 1,
        "task": "switch_collection",
        "state": "success",
        "planned": 2,
        "succeeded": 2,
        "failed_count": 0,
        "failed_devices": [],
    }


def failed_device(
    hostname: str,
    *,
    operations: list[str] | tuple[str, ...] = ("collection",),
    reason: str = "unreachable",
) -> dict:
    return {
        "hostname": hostname,
        "operations": list(operations),
        "reason": reason,
    }


def legacy_failed_device(
    hostname: str,
    *,
    operation: str = "collection",
    reason: str = "unreachable",
) -> dict:
    return {
        "hostname": hostname,
        "operation": operation,
        "reason": reason,
    }


class CollectionCycleContractTests(unittest.TestCase):
    def api(self, name: str):
        self.assertTrue(
            hasattr(CONTRACT, name),
            f"tools/project_contract.py must define B3 pure API {name}",
        )
        return getattr(CONTRACT, name)

    def test_exact_ordered_source_slots_and_scope_refusal(self):
        authority = self.api("COLLECTION_CYCLE_SOURCE_SLOTS")
        resolver = self.api("collection_cycle_source_slots")

        self.assertEqual(EXPECTED_SOURCE_SLOTS, authority)
        self.assertIsInstance(authority, Mapping)
        for scope, expected in EXPECTED_SOURCE_SLOTS.items():
            self.assertIsInstance(authority[scope], tuple)
            self.assertEqual(expected, resolver(scope))
            self.assertIsInstance(resolver(scope), tuple)
        with self.assertRaises(TypeError):
            authority["air"] = ("ethernet/prod",)
        with self.assertRaises(TypeError):
            authority["new-scope"] = ("ethernet/air",)
        for invalid in ("", "AIR", "production", None, True, 1):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    resolver(invalid)

    def test_canonical_json_is_compact_sorted_utf8_and_digest_is_independent(self):
        serialize = self.api("canonical_collection_cycle_json")
        project_key = self.api("collection_cycle_project_key")

        value = {"\N{LATIN SMALL LETTER E WITH ACUTE}": "\N{CJK UNIFIED IDEOGRAPH-96EA}", "a": 1}
        expected = b'{"a":1,"\xc3\xa9":"\xe9\x9b\xaa"}'
        self.assertEqual(expected, canonical_bytes(value))
        self.assertEqual(expected, serialize(value))
        self.assertIsInstance(serialize(value), bytes)
        self.assertEqual(PROJECT_KEY, project_key(PROJECT_IDENTITY))
        self.assertNotEqual(PROJECT_KEY, project_key(PROJECT_IDENTITY.rstrip()))
        for invalid in (b"project", None, True, 1):
            with self.subTest(invalid=invalid):
                with self.assertRaises((TypeError, ValueError)):
                    project_key(invalid)

    def test_sequence_and_uuid4_hex_are_strict_and_bool_is_not_an_integer(self):
        validate_sequence = self.api("validate_collection_cycle_sequence")
        validate_token = self.api("validate_collection_cycle_run_token")

        for value in (1, 2, 2**63):
            self.assertEqual(value, validate_sequence(value))
        for invalid in (0, -1, True, False, 1.0, "1", None):
            with self.subTest(sequence=invalid):
                with self.assertRaises(ValueError):
                    validate_sequence(invalid)

        self.assertRegex(RUN_TOKEN, re.compile(r"^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$"))
        self.assertEqual(RUN_TOKEN, validate_token(RUN_TOKEN))
        for invalid in (
            RUN_TOKEN.upper(),
            RUN_TOKEN[:-1],
            "00112233445536778899aabbccddeeff",
            "00112233445546777899aabbccddeeff",
            "00112233-4455-4677-8899-aabbccddeeff",
            "g" * 32,
            None,
        ):
            with self.subTest(token=invalid):
                with self.assertRaises(ValueError):
                    validate_token(invalid)

    def test_cycle_identity_has_exact_keys_and_recomputed_cycle_id(self):
        build = self.api("build_collection_cycle_identity")
        validate = self.api("validate_collection_cycle_identity")
        validate_sequence = self.api("validate_collection_cycle_sequence")
        max_sequence = self.api("COLLECTION_CYCLE_MAX_SEQUENCE")
        expected = expected_identity()

        self.assertEqual(10**20 - 1, max_sequence)
        self.assertEqual(max_sequence, validate_sequence(max_sequence))
        with self.assertRaises(ValueError):
            validate_sequence(max_sequence + 1)
        largest_name = f"{max_sequence:020d}.start.json"
        predecessor_name = f"{max_sequence - 1:020d}.start.json"
        self.assertEqual(20, len(largest_name.removesuffix(".start.json")))
        self.assertLess(predecessor_name, largest_name)

        observed = build(PROJECT_IDENTITY, "prod", 7, RUN_TOKEN)
        self.assertEqual(expected, observed)
        self.assertEqual(
            {
                "project_key", "scope", "source", "sequence", "run_token",
                "cycle_id",
            },
            set(observed),
        )
        self.assertEqual(expected, validate(copy.deepcopy(expected)))

        for scope, sequence, token, project_identity in (
            ("air", 1, RUN_TOKEN, "/air-project"),
            ("prod", 19, OTHER_RUN_TOKEN, "/prod-project"),
            ("all", 2**31, RUN_TOKEN, "工程/all"),
        ):
            with self.subTest(
                scope=scope,
                sequence=sequence,
                project_identity=project_identity,
            ):
                variant = expected_identity(
                    scope=scope,
                    sequence=sequence,
                    run_token=token,
                    project_identity=project_identity,
                )
                self.assertEqual(
                    variant,
                    build(project_identity, scope, sequence, token),
                )
                self.assertEqual(variant, validate(copy.deepcopy(variant)))

        mutations = []
        for key in expected:
            missing = copy.deepcopy(expected)
            del missing[key]
            mutations.append(missing)
        extra = copy.deepcopy(expected)
        extra["finished_at"] = "2026-09-19T00:00:00Z"
        mutations.append(extra)
        for key, value in (
            ("project_key", "0" * 64),
            ("scope", "air"),
            ("source", "mutable_status"),
            ("sequence", 8),
            ("run_token", OTHER_RUN_TOKEN),
            ("cycle_id", "0" * 64),
        ):
            mutated = copy.deepcopy(expected)
            mutated[key] = value
            mutations.append(mutated)
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(ValueError):
                    validate(mutated)

        for key, value in (
            ("project_key", "0" * 63),
            ("scope", "production"),
            ("source", "mutable_status"),
            ("sequence", 0),
            ("run_token", RUN_TOKEN.upper()),
        ):
            mutated = copy.deepcopy(expected)
            mutated[key] = value
            mutated = recompute_cycle_id(mutated)
            with self.subTest(recomputed_invalid=key):
                with self.assertRaises(ValueError):
                    validate(mutated)

    def test_schema_v2_result_is_exact_and_run_bound(self):
        validate = self.api("validate_collection_cycle_result")
        identity = expected_identity()
        payload = valid_result("ethernet/prod")
        self.assertEqual(
            payload,
            validate(payload, expected_identity=identity,
                     expected_slot="ethernet/prod"),
        )

        required = set(payload)
        for key in required:
            missing = copy.deepcopy(payload)
            del missing[key]
            with self.subTest(missing=key):
                with self.assertRaises(ValueError):
                    validate(missing, expected_identity=identity,
                             expected_slot="ethernet/prod")
        extra = copy.deepcopy(payload)
        extra["qualified"] = True
        with self.assertRaises(ValueError):
            validate(extra, expected_identity=identity,
                     expected_slot="ethernet/prod")

        mutations = {
            "schema_version": 1,
            "task": "yaml_backup",
            "project_key": "0" * 64,
            "scope": "air",
            "source": "mutable_status",
            "sequence": 8,
            "run_token": OTHER_RUN_TOKEN,
            "source_slot": "infiniband/prod",
            "cycle_id": "0" * 64,
            "input_inventory_sha256": "0" * 63,
        }
        for key, value in mutations.items():
            mutated = copy.deepcopy(payload)
            mutated[key] = value
            with self.subTest(field=key):
                with self.assertRaises(ValueError):
                    validate(mutated, expected_identity=identity,
                             expected_slot="ethernet/prod")

        for key, value in (
            ("schema_version", 2.0),
            ("sequence", 7.0),
        ):
            mutated = copy.deepcopy(payload)
            mutated[key] = value
            with self.subTest(exact_json_type=key, value=value):
                with self.assertRaises(ValueError):
                    validate(
                        mutated,
                        expected_identity=identity,
                        expected_slot="ethernet/prod",
                    )
        sequence_one_identity = expected_identity(sequence=1)
        boolean_sequence = valid_result("ethernet/prod", sequence=1)
        boolean_sequence["sequence"] = True
        with self.assertRaises(ValueError):
            validate(
                boolean_sequence,
                expected_identity=sequence_one_identity,
                expected_slot="ethernet/prod",
            )

        for field in ("evidence", "envelope"):
            zero_byte = copy.deepcopy(payload)
            zero_byte[field] = {
                "sha256": EMPTY_SHA256,
                "size_bytes": 0,
            }
            with self.subTest(field=field, zero_bytes=True):
                self.assertEqual(
                    zero_byte,
                    validate(
                        zero_byte,
                        expected_identity=identity,
                        expected_slot="ethernet/prod",
                    ),
                )

            for invalid in (
                {"sha256": SHA_A},
                {"sha256": SHA_A, "size_bytes": True},
                {"sha256": SHA_A.upper(), "size_bytes": 1},
                {"sha256": SHA_A, "size_bytes": -1},
                {"sha256": SHA_A, "size_bytes": 0},
                {"sha256": SHA_A, "size_bytes": 1, "extra": True},
            ):
                mutated = copy.deepcopy(payload)
                mutated[field] = invalid
                with self.subTest(field=field, invalid=invalid):
                    with self.assertRaises(ValueError):
                        validate(mutated, expected_identity=identity,
                                 expected_slot="ethernet/prod")

        count_mutations = []
        for field, value in (
            ("planned", True),
            ("planned", -1),
            ("succeeded", True),
            ("succeeded", -1),
            ("failed_count", True),
            ("failed_count", -1),
            ("state", "cancelled"),
        ):
            mutated = copy.deepcopy(payload)
            mutated[field] = value
            count_mutations.append(mutated)
        mismatch = copy.deepcopy(payload)
        mismatch["failed_count"] = 1
        count_mutations.append(mismatch)
        bad_total = copy.deepcopy(payload)
        bad_total["succeeded"] = 1
        count_mutations.append(bad_total)
        success_with_failure = copy.deepcopy(payload)
        success_with_failure.update({
            "planned": 2,
            "succeeded": 1,
            "failed_count": 1,
            "failed_devices": [{
                "hostname": "leaf02",
                "operations": ["collection"],
                "reason": "unreachable",
            }],
        })
        count_mutations.append(success_with_failure)
        for mutated in count_mutations:
            with self.subTest(count_state_mutation=mutated):
                with self.assertRaises(ValueError):
                    validate(mutated, expected_identity=identity,
                             expected_slot="ethernet/prod")

    def test_failed_devices_have_bounded_exact_canonical_schema(self):
        validate = self.api("validate_collection_cycle_result")
        serialize = self.api("canonical_collection_cycle_json")
        operations = self.api("COLLECTION_CYCLE_FAILED_DEVICE_OPERATIONS")
        max_devices = self.api("COLLECTION_CYCLE_MAX_FAILED_DEVICES")
        max_text_bytes = self.api(
            "COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES"
        )
        self.assertEqual(EXPECTED_FAILED_DEVICE_OPERATIONS, operations)
        self.assertEqual(EXPECTED_MAX_FAILED_DEVICES, max_devices)
        self.assertEqual(EXPECTED_MAX_FAILED_DEVICE_TEXT_BYTES, max_text_bytes)

        identity = expected_identity()
        first = valid_result(
            "ethernet/prod",
            state="partial",
            planned=3,
            succeeded=1,
            failures=[
                failed_device(
                    "strasz",
                    operations=("ssh_prepare", "collection", "ssh_prepare"),
                    reason="timeout",
                ),
                failed_device("Straße", reason="unreachable"),
            ],
        )
        second = copy.deepcopy(first)
        second["failed_devices"].reverse()
        second["failed_devices"][0]["operations"].reverse()
        validated_first = validate(
            first,
            expected_identity=identity,
            expected_slot="ethernet/prod",
        )
        validated_second = validate(
            second,
            expected_identity=identity,
            expected_slot="ethernet/prod",
        )
        # Unicode casefold puts "strasse" before "strasz"; lower() would
        # produce the opposite order because it retains the sharp-s.
        self.assertEqual(
            ["Straße", "strasz"],
            [item["hostname"] for item in validated_first["failed_devices"]],
        )
        self.assertEqual(
            ["collection", "ssh_prepare"],
            validated_first["failed_devices"][1]["operations"],
        )
        self.assertEqual(
            serialize(validated_first),
            serialize(validated_second),
        )
        self.assertEqual(validated_first["cycle_id"], validated_second["cycle_id"])

        boundary_failures = [
            failed_device(f"leaf-{index:05d}")
            for index in range(EXPECTED_MAX_FAILED_DEVICES)
        ]
        boundary = valid_result(
            "ethernet/prod",
            state="failed",
            planned=EXPECTED_MAX_FAILED_DEVICES,
            succeeded=0,
            failures=boundary_failures,
        )
        self.assertEqual(
            EXPECTED_MAX_FAILED_DEVICES,
            len(validate(
                boundary,
                expected_identity=identity,
                expected_slot="ethernet/prod",
            )["failed_devices"]),
        )
        over_limit = copy.deepcopy(boundary)
        over_limit["failed_devices"].append(failed_device("leaf-over-limit"))
        over_limit["failed_count"] += 1
        over_limit["planned"] += 1
        with self.assertRaises(ValueError):
            validate(
                over_limit,
                expected_identity=identity,
                expected_slot="ethernet/prod",
            )

        exact_text_bound = valid_result(
            "ethernet/prod",
            state="failed",
            planned=1,
            succeeded=0,
            failures=[failed_device("h" * EXPECTED_MAX_FAILED_DEVICE_TEXT_BYTES)],
        )
        self.assertEqual(
            exact_text_bound,
            validate(
                exact_text_bound,
                expected_identity=identity,
                expected_slot="ethernet/prod",
            ),
        )

        # 341 CJK code points plus one ASCII byte is exactly 1024 UTF-8
        # bytes.  The v2 boundary is bytes, never characters.
        maximal_non_ascii_reason = "界" * 341 + "x"
        self.assertEqual(
            EXPECTED_MAX_FAILED_DEVICE_TEXT_BYTES,
            len(maximal_non_ascii_reason.encode("utf-8")),
        )
        non_ascii_boundary = valid_result(
            "ethernet/prod",
            state="failed",
            planned=1,
            succeeded=0,
            failures=[failed_device("leaf-cjk", reason=maximal_non_ascii_reason)],
        )
        self.assertEqual(
            non_ascii_boundary,
            validate(
                non_ascii_boundary,
                expected_identity=identity,
                expected_slot="ethernet/prod",
            ),
        )

        invalid_items = []
        for missing_key in ("hostname", "operations", "reason"):
            item = failed_device("leaf01")
            del item[missing_key]
            invalid_items.append(item)
        extra = failed_device("leaf01")
        extra["qualified"] = True
        invalid_items.append(extra)
        for field in ("hostname", "reason"):
            for invalid_value in (
                "",
                "contains\x00nul",
                "contains\rcarriage",
                "contains\nline",
                "é" * 513,
                7,
            ):
                item = failed_device("leaf01")
                item[field] = invalid_value
                invalid_items.append(item)
        for invalid_operations in (
            [],
            ["free_text"],
            ["collection,ssh_prepare"],
            ["collection", 7],
            "collection",
            None,
        ):
            item = failed_device("leaf01")
            item["operations"] = invalid_operations
            invalid_items.append(item)

        for item in invalid_items:
            mutated = valid_result(
                "ethernet/prod",
                state="failed",
                planned=1,
                succeeded=0,
                failures=[item],
            )
            with self.subTest(invalid_item=item), self.assertRaises(ValueError):
                validate(
                    mutated,
                    expected_identity=identity,
                    expected_slot="ethernet/prod",
                )

        duplicate = valid_result(
            "ethernet/prod",
            state="failed",
            planned=2,
            succeeded=0,
            failures=[failed_device("Host1"), failed_device("host1")],
        )
        with self.assertRaises(ValueError):
            validate(
                duplicate,
                expected_identity=identity,
                expected_slot="ethernet/prod",
            )

        # Schema-v1 is historical evidence.  Its canonical comma-joined
        # operation string is parsed, while its raw representation is retained.
        legacy = legacy_result()
        legacy.update({
            "state": "partial",
            "succeeded": 1,
            "failed_count": 1,
            "failed_devices": [legacy_failed_device(
                "leaf01", operation="collection,ssh_prepare",
                reason="界" * 1024,
            )],
        })
        summary = self.api("summarize_collection_cycle_results")(
            expected_identity(scope="air"),
            [legacy],
            html_annotation={
                "attempted": False,
                "state": "not_attempted",
                "error_sha256": None,
            },
        )
        retained = summary["results"][0]["failed_devices"][0]
        self.assertEqual("collection,ssh_prepare", retained["operation"])
        self.assertLessEqual(
            len(retained["reason"].encode("utf-8")),
            EXPECTED_MAX_FAILED_DEVICE_TEXT_BYTES,
        )
        self.assertEqual("界" * 341, retained["reason"])

        for invalid_operation in (
            "ssh_prepare,collection",
            "collection,collection",
            "collection,free_text",
            "",
        ):
            bad_legacy = copy.deepcopy(legacy)
            bad_legacy["failed_devices"][0]["operation"] = invalid_operation
            with self.subTest(legacy_operation=invalid_operation), \
                    self.assertRaises(ValueError):
                self.api("summarize_collection_cycle_results")(
                    expected_identity(scope="air"),
                    [bad_legacy],
                    html_annotation={
                        "attempted": False,
                        "state": "not_attempted",
                        "error_sha256": None,
                    },
                )

        malformed_legacy = copy.deepcopy(legacy)
        malformed_legacy["failed_devices"][0]["operations"] = ["collection"]
        with self.assertRaises(ValueError):
            self.api("summarize_collection_cycle_results")(
                expected_identity(scope="air"),
                [malformed_legacy],
                html_annotation={
                    "attempted": False,
                    "state": "not_attempted",
                    "error_sha256": None,
                },
            )

    def test_missing_duplicate_extra_and_mismatched_slots_are_rejected(self):
        summarize = self.api("summarize_collection_cycle_results")
        identity = expected_identity()
        slots = EXPECTED_SOURCE_SLOTS["prod"]
        results = [valid_result(slot) for slot in slots]

        invalid_sets = (
            results[:-1],
            results + [copy.deepcopy(results[0])],
            results + [valid_result("ethernet/air")],
        )
        for invalid in invalid_sets:
            with self.subTest(slots=[item["source_slot"] for item in invalid]):
                with self.assertRaises(ValueError):
                    summarize(identity, invalid, html_annotation={
                        "attempted": True,
                        "state": "success",
                        "error_sha256": None,
                    })

        mismatched = [copy.deepcopy(item) for item in results]
        mismatched[1]["sequence"] = 8
        with self.assertRaises(ValueError):
            summarize(identity, mismatched, html_annotation={
                "attempted": True,
                "state": "success",
                "error_sha256": None,
            })

    def test_partial_and_legacy_results_are_terminal_but_nonqualifying(self):
        summarize = self.api("summarize_collection_cycle_results")
        reason_vocabulary = self.api(
            "COLLECTION_CYCLE_QUALIFICATION_REASONS"
        )
        identity = expected_identity()
        slots = EXPECTED_SOURCE_SLOTS["prod"]

        self.assertIsInstance(reason_vocabulary, (tuple, frozenset))
        self.assertTrue(reason_vocabulary)
        self.assertEqual(len(reason_vocabulary), len(set(reason_vocabulary)))
        self.assertTrue(all(
            isinstance(reason, str) and reason
            for reason in reason_vocabulary
        ))

        partial = [valid_result(slot) for slot in slots]
        partial[1] = valid_result(
            slots[1],
            state="partial",
            planned=2,
            succeeded=1,
            failures=[{
                "hostname": "leaf02",
                "operations": ["collection"],
                "reason": "unreachable",
            }],
        )
        summary = summarize(identity, partial, html_annotation={
            "attempted": True, "state": "success", "error_sha256": None,
        })
        self.assertFalse(summary["qualifying"])
        self.assertIn("partial", summary["qualification_reasons"])
        self.assertLessEqual(
            set(summary["qualification_reasons"]),
            set(reason_vocabulary),
        )

        legacy = [valid_result(slot) for slot in slots]
        legacy[1] = legacy_result()
        summary = summarize(identity, legacy, html_annotation={
            "attempted": True, "state": "success", "error_sha256": None,
        })
        self.assertFalse(summary["qualifying"])
        self.assertIn("legacy", summary["qualification_reasons"])
        self.assertLessEqual(
            set(summary["qualification_reasons"]),
            set(reason_vocabulary),
        )
        legacy_float = [valid_result(slot) for slot in slots]
        legacy_float[1] = legacy_result()
        legacy_float[1]["schema_version"] = 1.0
        with self.assertRaises(ValueError):
            summarize(identity, legacy_float, html_annotation={
                "attempted": True, "state": "success", "error_sha256": None,
            })

        failed = [valid_result(slot) for slot in slots]
        failed[1] = valid_result(
            slots[1],
            state="failed",
            planned=1,
            succeeded=0,
            failures=[{
                "hostname": "leaf02",
                "operations": ["collection"],
                "reason": "unreachable",
            }],
        )
        summary = summarize(identity, failed, html_annotation={
            "attempted": True, "state": "success", "error_sha256": None,
        })
        self.assertFalse(summary["qualifying"])
        self.assertIn("failed", summary["qualification_reasons"])
        self.assertLessEqual(
            set(summary["qualification_reasons"]),
            set(reason_vocabulary),
        )

        failed_and_partial = [valid_result(slot) for slot in slots]
        failed_and_partial[0] = valid_result(
            slots[0],
            state="partial",
            planned=2,
            succeeded=1,
            failures=[{
                "hostname": "leaf01",
                "operations": ["collection"],
                "reason": "partial fixture",
            }],
        )
        failed_and_partial[2] = valid_result(
            slots[2],
            state="failed",
            planned=1,
            succeeded=0,
            failures=[{
                "hostname": "leaf03",
                "operations": ["collection"],
                "reason": "failed fixture",
            }],
        )
        expected_reasons = [
            reason for reason in reason_vocabulary
            if reason in {"partial", "failed"}
        ]
        for ordering in (
            failed_and_partial,
            list(reversed(failed_and_partial)),
        ):
            with self.subTest(
                reason_input_order=[item["source_slot"] for item in ordering],
            ):
                summary = summarize(identity, ordering, html_annotation={
                    "attempted": True,
                    "state": "success",
                    "error_sha256": None,
                })
                self.assertEqual(
                    expected_reasons,
                    summary["qualification_reasons"],
                )

    def test_complete_empty_and_per_slot_counts_are_explicit(self):
        summarize = self.api("summarize_collection_cycle_results")
        html = {
            "attempted": True,
            "state": "success",
            "error_sha256": None,
        }

        for scope, slots in EXPECTED_SOURCE_SLOTS.items():
            with self.subTest(scope=scope):
                identity = expected_identity(scope=scope)
                empty = [
                    valid_result(
                        slot,
                        scope=scope,
                        planned=0,
                        succeeded=0,
                    )
                    for slot in slots
                ]
                summary = summarize(identity, empty, html_annotation=html)
                self.assertEqual(EXPECTED_SUMMARY_KEYS, set(summary))
                self.assertEqual(identity, summary["identity"])
                self.assertTrue(summary["qualifying"])
                self.assertTrue(summary["complete_empty"])
                self.assertEqual(list(slots), [
                    item["source_slot"] for item in summary["results"]
                ])

        identity = expected_identity()
        slots = EXPECTED_SOURCE_SLOTS["prod"]

        empty = [
            valid_result(slot, planned=0, succeeded=0)
            for slot in slots
        ]
        summary = summarize(identity, empty, html_annotation=html)
        self.assertTrue(summary["qualifying"])
        self.assertTrue(summary["complete_empty"])
        self.assertEqual(
            {
                slot: {"planned": 0, "succeeded": 0, "failed_count": 0}
                for slot in slots
            },
            summary["slot_counts"],
        )

        nonempty = [valid_result(slot) for slot in slots]
        summary = summarize(identity, nonempty, html_annotation=html)
        self.assertTrue(summary["qualifying"])
        self.assertFalse(summary["complete_empty"])
        self.assertEqual(
            {
                slot: {"planned": 2, "succeeded": 2, "failed_count": 0}
                for slot in slots
            },
            summary["slot_counts"],
        )

        mixed = [
            valid_result(slots[0], planned=0, succeeded=0),
            valid_result(slots[1], planned=2, succeeded=2),
            valid_result(slots[2], planned=0, succeeded=0),
        ]
        summary = summarize(identity, mixed, html_annotation=html)
        self.assertTrue(summary["qualifying"])
        self.assertFalse(summary["complete_empty"])
        self.assertEqual(0, summary["slot_counts"][slots[0]]["planned"])
        self.assertEqual(2, summary["slot_counts"][slots[1]]["planned"])

        unreachable = [
            valid_result(
                slot,
                state="failed",
                planned=1,
                succeeded=0,
                failures=[{
                    "hostname": f"unreachable-{index}",
                    "operations": ["collection"],
                    "reason": "unreachable",
                }],
            )
            for index, slot in enumerate(slots, start=1)
        ]
        summary = summarize(identity, unreachable, html_annotation=html)
        self.assertFalse(summary["qualifying"])
        self.assertFalse(summary["complete_empty"])

        zero_failed = [
            valid_result(
                slot,
                state="failed",
                planned=0,
                succeeded=0,
            )
            for slot in slots
        ]
        summary = summarize(identity, zero_failed, html_annotation=html)
        self.assertFalse(summary["qualifying"])
        self.assertFalse(summary["complete_empty"])

        impossible = valid_result(slots[0], planned=0, succeeded=1)
        with self.assertRaises(ValueError):
            self.api("validate_collection_cycle_result")(
                impossible,
                expected_identity=identity,
                expected_slot=slots[0],
            )
        impossible_set = [valid_result(slot) for slot in slots]
        impossible_set[0] = impossible
        with self.assertRaises(ValueError):
            summarize(identity, impossible_set, html_annotation=html)

    def test_html_failure_is_bound_annotation_not_collection_qualification(self):
        summarize = self.api("summarize_collection_cycle_results")
        signature = inspect.signature(summarize)
        html_parameter = signature.parameters["html_annotation"]
        self.assertIs(html_parameter.default, inspect.Parameter.empty)
        self.assertIs(
            html_parameter.kind,
            inspect.Parameter.KEYWORD_ONLY,
        )
        identity = expected_identity()
        results = [
            valid_result(slot) for slot in EXPECTED_SOURCE_SLOTS["prod"]
        ]
        with self.assertRaises(TypeError):
            summarize(identity, results)
        with self.assertRaises(TypeError):
            summarize(identity, results, {
                "attempted": True,
                "state": "success",
                "error_sha256": None,
            })
        failed_html = {
            "attempted": True,
            "state": "failed",
            "error_sha256": HTML_ERROR_SHA,
        }
        failed_summary = summarize(
            identity,
            results,
            html_annotation=failed_html,
        )
        success_html = {
            "attempted": True,
            "state": "success",
            "error_sha256": None,
        }
        success_summary = summarize(
            identity,
            results,
            html_annotation=success_html,
        )
        self.assertEqual(EXPECTED_SUMMARY_KEYS, set(failed_summary))
        self.assertEqual(EXPECTED_SUMMARY_KEYS, set(success_summary))
        for field in (
            "identity",
            "results",
            "qualifying",
            "complete_empty",
            "slot_counts",
            "qualification_reasons",
        ):
            self.assertEqual(success_summary[field], failed_summary[field], field)
        self.assertTrue(failed_summary["qualifying"])
        self.assertEqual(failed_html, failed_summary["html_annotation"])
        self.assertEqual(success_html, success_summary["html_annotation"])
        self.assertNotEqual(
            success_summary["html_annotation"],
            failed_summary["html_annotation"],
        )
        for forbidden in ("time", "archive", "status", "cooldown", "html"):
            self.assertNotIn(forbidden, failed_summary["identity"])

    def test_html_annotation_cross_fields_are_bijective(self):
        summarize = self.api("summarize_collection_cycle_results")
        identity = expected_identity()
        results = [
            valid_result(slot) for slot in EXPECTED_SOURCE_SLOTS["prod"]
        ]

        not_attempted = {
            "attempted": False,
            "state": "not_attempted",
            "error_sha256": None,
        }
        summary = summarize(
            identity,
            results,
            html_annotation=not_attempted,
        )
        self.assertEqual(EXPECTED_SUMMARY_KEYS, set(summary))
        self.assertEqual(not_attempted, summary["html_annotation"])
        self.assertTrue(summary["qualifying"])

        invalid_annotations = (
            {
                "attempted": True,
                "state": "not_attempted",
                "error_sha256": None,
            },
            {
                "attempted": False,
                "state": "success",
                "error_sha256": None,
            },
            {
                "attempted": True,
                "state": "failed",
                "error_sha256": None,
            },
            {
                "attempted": True,
                "state": "success",
                "error_sha256": HTML_ERROR_SHA,
            },
            {
                "attempted": False,
                "state": "not_attempted",
                "error_sha256": HTML_ERROR_SHA,
            },
        )
        for annotation in invalid_annotations:
            with self.subTest(annotation=annotation):
                with self.assertRaises(ValueError):
                    summarize(
                        identity,
                        results,
                        html_annotation=annotation,
                    )


if __name__ == "__main__":
    unittest.main()
