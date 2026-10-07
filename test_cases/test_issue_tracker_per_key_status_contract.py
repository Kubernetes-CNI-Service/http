"""REQ7 independent per-key consecutive-window projection contracts.

Literal observations are fixtures, not source or publication authority. Real
source adapters must independently bind observations to completed cycles.
"""

import unittest
from dataclasses import replace

from monitor import issue_tracker_k_chain
from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_k_chain import KChainHoldError, validate_k_chain_snapshot
from test_cases.test_issue_tracker_k_chain import fixtures


KEY_A = ("eth", "node-a", "eth0", "link_down")
KEY_B = ("eth", "node-b", "eth0", "link_down")


def projection(testcase):
    candidate = getattr(issue_tracker_k_chain, "assess_per_key_window", None)
    testcase.assertIsNotNone(candidate, "C-25 per-key projection is not implemented")
    return candidate


def evidence():
    first = CycleEvidence(
        cycle_id="cycle-1", sequence=1, project_key="project-A",
        scope="prod", source_slots=("eth",), qualifying=True,
        summary_sha256="1" * 64, completion_sha256="2" * 64,
    )
    return first, replace(first, cycle_id="cycle-2", sequence=2)


class PerKeyStatusContractTests(unittest.TestCase):
    def setUp(self):
        events, current, initialized = fixtures(new_k=3)
        self.settings = validate_k_chain_snapshot(events, current, initialized)
        self.first, self.second = evidence()

    def test_two_keys_same_history_have_distinct_pending_numerators(self):
        assess = projection(self)
        cycles = (self.first, self.second)
        observed = {
            self.first.cycle_id: frozenset((KEY_A,)),
            self.second.cycle_id: frozenset((KEY_A, KEY_B)),
        }
        for key, expected in ((KEY_A, 2), (KEY_B, 1)):
            with self.subTest(key=key):
                result = assess(cycles, observed, self.settings, key)
                self.assertEqual(("pending", expected, 3),
                                 (result.status, result.observed, result.required))

    def test_archive_sequence_gap_cannot_be_counted_as_consecutive(self):
        assess = projection(self)
        third = replace(self.second, cycle_id="cycle-3", sequence=3)
        observed = {self.first.cycle_id: frozenset((KEY_A,)),
                    third.cycle_id: frozenset((KEY_A,))}
        with self.assertRaises(KChainHoldError):
            assess((self.first, third), observed, self.settings, KEY_A)

    def test_latest_absent_resets_progress_and_never_qualifies(self):
        assess = projection(self)
        observed = {self.first.cycle_id: frozenset((KEY_A,)),
                    self.second.cycle_id: frozenset()}
        result = assess((self.first, self.second), observed, self.settings, KEY_A)
        self.assertEqual(("pending", "latest_absent", 0, 3),
                         (result.status, result.reason, result.observed, result.required))

    def test_observation_binding_rejects_missing_and_foreign_cycle(self):
        assess = projection(self)
        cycles = (self.first, self.second)
        for observed in (
            {self.first.cycle_id: frozenset((KEY_A,))},
            {self.first.cycle_id: frozenset((KEY_A,)),
             self.second.cycle_id: frozenset((KEY_A,)),
             "foreign-cycle": frozenset((KEY_A,))},
        ):
            with self.subTest(observed=observed), self.assertRaises(KChainHoldError):
                assess(cycles, observed, self.settings, KEY_A)

    def test_nonqualifying_cycle_cannot_contribute_to_key_progress(self):
        assess = projection(self)
        for claim in (False, 1, "true"):
            second = replace(self.second, qualifying=claim)
            observed = {self.first.cycle_id: frozenset((KEY_A,)),
                        second.cycle_id: frozenset((KEY_A,))}
            with self.subTest(claim=claim), self.assertRaises(KChainHoldError):
                assess((self.first, second), observed, self.settings, KEY_A)

    def test_complete_latest_k_window_qualifies_without_old_key_presence(self):
        assess = projection(self)
        third = replace(self.second, cycle_id="cycle-3", sequence=3)
        fourth = replace(self.second, cycle_id="cycle-4", sequence=4)
        cycles = (self.first, self.second, third, fourth)
        observed = {self.first.cycle_id: frozenset(),
                    **{item.cycle_id: frozenset((KEY_A,)) for item in cycles[1:]}}
        result = assess(cycles, observed, self.settings, KEY_A)
        self.assertEqual(("qualified", "consecutive_active", 3, 3),
                         (result.status, result.reason, result.observed, result.required))

    def test_recent_gap_in_key_presence_counts_suffix_not_total_occurrences(self):
        assess = projection(self)
        third = replace(self.second, cycle_id="cycle-3", sequence=3)
        observed = {self.first.cycle_id: frozenset((KEY_A,)),
                    self.second.cycle_id: frozenset(),
                    third.cycle_id: frozenset((KEY_A,))}
        result = assess((self.first, self.second, third), observed, self.settings, KEY_A)
        self.assertEqual(("pending", "insufficient_consecutive", 1, 3),
                         (result.status, result.reason, result.observed, result.required))

    def test_zero_cycles_is_cold_start_not_an_absent_latest_observation(self):
        assess = projection(self)
        result = assess((), {}, self.settings, KEY_A)
        self.assertEqual(("pending", "cold_start", 0, 3),
                         (result.status, result.reason, result.observed, result.required))

    def test_k_one_uses_one_latest_cycle_and_large_k_has_no_semantic_ceiling(self):
        assess = projection(self)
        observed = {self.first.cycle_id: frozenset((KEY_A,))}
        for k, state in ((1, "qualified"), (1000001, "pending")):
            events, current, initialized = fixtures(new_k=k)
            settings = validate_k_chain_snapshot(events, current, initialized)
            result = assess((self.first,), observed, settings, KEY_A)
            self.assertEqual((state, 1, k),
                             (result.status, result.observed, result.required))

    def test_mixed_identity_and_duplicate_cycle_fail_closed(self):
        assess = projection(self)
        for second in (
            replace(self.second, project_key="project-B"),
            replace(self.second, scope="air"),
            replace(self.second, source_slots=("ib",)),
            replace(self.second, cycle_id=self.first.cycle_id),
        ):
            observed = {item.cycle_id: frozenset((KEY_A,))
                        for item in (self.first, second)}
            with self.subTest(second=second), self.assertRaises(KChainHoldError):
                assess((self.first, second), observed, self.settings, KEY_A)

    def test_mutable_or_malformed_observations_and_key_fail_closed(self):
        assess = projection(self)
        for key, items in (
            (KEY_A, {KEY_A}), (KEY_A, (KEY_A,)),
            (KEY_A, frozenset((('eth', 'node-a', 'eth0', ''),))),
            (KEY_A, frozenset((('eth', 'node-a', 'eth0', '\x00'),))),
            (("eth", "node-a", "eth0"), frozenset((KEY_A,))),
        ):
            with self.subTest(key=key, items=items), self.assertRaises(KChainHoldError):
                assess((self.first,), {self.first.cycle_id: items}, self.settings, key)

    def test_malformed_k_state_never_silently_uses_a_default(self):
        assess = projection(self)
        observed = {self.first.cycle_id: frozenset((KEY_A,))}
        for k in (True, 0, -1, "3", 3.0):
            with self.subTest(k=k), self.assertRaises(KChainHoldError):
                assess((self.first,), observed, replace(self.settings, k=k), KEY_A)


if __name__ == "__main__":
    unittest.main()
