"""Independent C25 immutable-K chain snapshot contract, with no writer."""

import hashlib
import json
import unittest
from dataclasses import replace

from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_k_chain import (
    KChainHoldError, assess_k_window, validate_k_chain_snapshot,
)


TOKEN_0 = "00112233445546778899aabbccddeeff"
TOKEN_1 = "ffeeddccbbaa49888776655443322110"
TIME_0 = "2026-09-25T00:00:00Z"
TIME_1 = "2026-09-25T00:10:00Z"


def line(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def fixtures(new_k=5, token_0=TOKEN_0, token_1=TOKEN_1):
    request_0 = {"new_k": 3, "actor": "system:default", "expected_revision": None,
                 "request_id": token_0}
    first = line({
        "schema_version": 1, "revision": 0, "type": "init", "old_k": None,
        "new_k": 3, "actor": "system:default", "recorded_at": TIME_0,
        "request_id": token_0, "payload_sha256": sha(line(request_0)),
        "predecessor_sha256": None,
    })
    request_1 = {"new_k": new_k, "actor": "operator:fixture", "expected_revision": 0,
                 "request_id": token_1}
    second = line({
        "schema_version": 1, "revision": 1, "type": "set_k", "old_k": 3,
        "new_k": new_k, "actor": "operator:fixture", "recorded_at": TIME_1,
        "request_id": token_1, "payload_sha256": sha(line(request_1)),
        "predecessor_sha256": sha(first),
    })
    current = line({"schema_version": 1, "revision": 1, "event_sha256": sha(second)})
    initialized = line({
        "schema_version": 1, "event0_sha256": sha(first), "initialized_at": TIME_0,
    })
    return {0: first, 1: second}, current, initialized


class IssueTrackerKChainTests(unittest.TestCase):
    def test_exact_chain_selects_highest_revision_and_unbounded_positive_k(self):
        events, current, initialized = fixtures(new_k=5000)
        state = validate_k_chain_snapshot(events, current, initialized)
        self.assertEqual(1, state.revision)
        self.assertEqual(5000, state.k)
        self.assertEqual(sha(events[1]), state.event_sha256)

    def test_safe_opaque_acquisition_id_does_not_assume_uuid4(self):
        events, current, initialized = fixtures(token_0="acquisition-2026-09-25")
        self.assertEqual(5, validate_k_chain_snapshot(events, current, initialized).k)

    def test_stale_or_missing_current_never_uses_old_k(self):
        events, current, initialized = fixtures()
        stale = line({"schema_version": 1, "revision": 0, "event_sha256": sha(events[0])})
        for pointer in (stale, None, b"{}\n"):
            with self.subTest(pointer=pointer), self.assertRaises(KChainHoldError):
                validate_k_chain_snapshot(events, pointer, initialized)

    def test_missing_initialized_or_event_zero_is_not_first_use(self):
        events, current, initialized = fixtures()
        for rows, witness in ((events, None), ({1: events[1]}, initialized), ({}, initialized)):
            with self.subTest(rows=rows, witness=witness), self.assertRaises(KChainHoldError):
                validate_k_chain_snapshot(rows, current, witness)

    def test_revision_gap_old_k_break_and_duplicate_request_id_refuse(self):
        events, current, initialized = fixtures()
        with self.assertRaises(KChainHoldError):
            validate_k_chain_snapshot({0: events[0], 2: events[1]}, current, initialized)
        for field, value in (("old_k", 4), ("request_id", TOKEN_0)):
            second = json.loads(events[1])
            second[field] = value
            altered = line(second)
            pointer = line({"schema_version": 1, "revision": 1,
                            "event_sha256": sha(altered)})
            with self.subTest(field=field), self.assertRaises(KChainHoldError):
                validate_k_chain_snapshot({0: events[0], 1: altered}, pointer, initialized)

    def test_bool_zero_k_and_event_byte_mutation_fail_closed(self):
        for invalid in (True, 0):
            events, current, initialized = fixtures(new_k=invalid)
            with self.subTest(invalid=invalid), self.assertRaises(KChainHoldError):
                validate_k_chain_snapshot(events, current, initialized)
        events, current, initialized = fixtures()
        with self.assertRaises(KChainHoldError):
            validate_k_chain_snapshot({0: events[0], 1: events[1] + b" "}, current, initialized)

    def test_window_cannot_count_duplicate_gap_or_foreign_scope_as_cycles(self):
        events, current, initialized = fixtures(new_k=2)
        settings = validate_k_chain_snapshot(events, current, initialized)
        first = CycleEvidence(
            cycle_id="cycle-1", sequence=1, project_key="project-A",
            scope="prod", source_slots=("source-A",), qualifying=True,
            summary_sha256="1" * 64, completion_sha256="2" * 64,
        )
        second = replace(first, cycle_id="cycle-2", sequence=2)
        self.assertEqual("history_sufficient", assess_k_window((first, second), settings).status)
        for altered in (
            replace(second, cycle_id=first.cycle_id),
            replace(second, sequence=3),
            replace(second, project_key="project-B"),
            replace(second, scope="air"),
            replace(second, source_slots=("source-B",)),
        ):
            with self.subTest(altered=altered), self.assertRaises(KChainHoldError):
                assess_k_window((first, altered), settings)


if __name__ == "__main__":
    unittest.main()
