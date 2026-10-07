"""RED ETH per-key source continuity, separate from publication authority."""

import unittest
from dataclasses import replace
import importlib
import importlib.util

from monitor.issue_tracker_activity_source import EndpointObservation, EthLinkObservation
from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_k_chain import KChainState
from monitor.issue_tracker_switch_runtime import ProdEthActivityCycleSource
from monitor.issue_tracker_topology_derivation import TopologyDerivationWitness


KEY = ("eth_cabling", "leaf-a", "swp1", "Mis-wiring")


def source(testcase):
    name = "monitor.issue_tracker_per_key_source"
    testcase.assertIsNotNone(importlib.util.find_spec(name),
                             "trusted ETH per-key source adapter is not implemented")
    return importlib.import_module(name)


def pair():
    first = CycleEvidence(
        "1" * 64, 1, "project-A", "prod",
        ("ethernet/prod", "infiniband/prod", "nvlink/prod"), True,
        "a" * 64, "b" * 64,
    )
    second = replace(first, cycle_id="2" * 64, sequence=2,
                     completion_sha256="c" * 64)
    link = EthLinkObservation(
        "leaf-a", "swp1", "leaf-z", "swp2", "WRONG_PEER", 1,
        EndpointObservation("foreign-z", "swp9"),
        EndpointObservation("leaf-a", "swp1"),
    )
    derivation = TopologyDerivationWitness({"topology": "d" * 64}, ())
    source1 = ProdEthActivityCycleSource(
        first.cycle_id, 1, first.completion_sha256, "e" * 64,
        (link,), derivation,
    )
    source2 = replace(source1, cycle_id=second.cycle_id, sequence=2,
                      completion_sha256=second.completion_sha256,
                      activity_sha256="f" * 64)
    return (first, second), (source1, source2), link


class EthPerKeySourceTests(unittest.TestCase):
    def setUp(self):
        self.settings = KChainState(1, 3, "9" * 64)
        self.cycles, self.sources, self.link = pair()

    def test_active_key_window_projects_latest_changed_business_value(self):
        from monitor import issue_tracker_switch_runtime as runtime
        reducer = getattr(runtime, "_persistent_eth_active_links", None)
        self.assertIsNotNone(reducer, "active-key ETH source projection is missing")
        latest = replace(self.link,
                         observation_a=EndpointObservation("changed-peer", "swp8"))
        sources = (self.sources[0], replace(self.sources[1], links=(latest,)))
        self.assertEqual((latest,), reducer(
            self.cycles, sources, KChainState(1, 2, "9" * 64)))

    def test_active_key_window_excludes_latest_inactive_and_pending_new_key(self):
        from monitor import issue_tracker_switch_runtime as runtime
        reducer = getattr(runtime, "_persistent_eth_active_links", None)
        self.assertIsNotNone(reducer, "active-key ETH source projection is missing")
        for latest in (replace(self.link, status="CONFIRMED_BOTH_SIDE"),
                       replace(self.link, status="DOWN")):
            with self.subTest(status=latest.status):
                sources = (self.sources[0], replace(self.sources[1], links=(latest,)))
                self.assertEqual((), reducer(
                    self.cycles, sources, KChainState(1, 2, "9" * 64)))

    def test_active_key_window_retains_pending_other_key_without_blocking_subset(self):
        from monitor import issue_tracker_switch_runtime as runtime
        reducer = getattr(runtime, "_persistent_eth_active_links", None)
        self.assertIsNotNone(reducer, "active-key ETH source projection is missing")
        pending = replace(self.link, interface_a="swp3")
        latest = replace(self.link,
                         observation_a=EndpointObservation("changed-peer", "swp8"))
        sources = (self.sources[0], replace(self.sources[1], links=(latest, pending)))
        self.assertEqual((latest,), reducer(
            self.cycles, sources, KChainState(1, 2, "9" * 64)))

    def test_same_key_changed_peer_or_status_still_counts_two_of_three(self):
        SOURCE = source(self)
        for altered in (
            replace(self.link, observation_a=EndpointObservation("other-z", "swp9")),
            replace(self.link, status="NO_LLDP"),
        ):
            with self.subTest(altered=altered):
                sources = (self.sources[0], replace(self.sources[1], links=(altered,)))
                status = SOURCE.reduce_eth_per_key_sources(
                    self.cycles, sources, self.settings, KEY)
                self.assertEqual(("pending", 2, 3),
                                 (status.state, status.observed, status.required))
                self.assertFalse(status.qualified)

    def test_unchanged_full_value_is_two_of_three_but_not_qualified(self):
        SOURCE = source(self)
        status = SOURCE.reduce_eth_per_key_sources(
            self.cycles, self.sources, self.settings, KEY)
        self.assertEqual(("pending", 2, 3),
                         (status.state, status.observed, status.required))
        self.assertEqual(self.cycles[1].cycle_id, status.cycle_ids[-1])
        self.assertEqual(self.sources[1].activity_sha256,
                         status.activity_sha256[-1])
        self.assertFalse(status.qualified)

    def test_missing_source_foreign_cycle_and_completion_rebind_hold(self):
        SOURCE = source(self)
        for sources in (
            self.sources[:1],
            self.sources + (self.sources[1],),
            (self.sources[0], replace(self.sources[1], cycle_id="3" * 64)),
            (self.sources[0], replace(self.sources[1], completion_sha256="4" * 64)),
        ):
            with self.subTest(sources=sources), self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.reduce_eth_per_key_sources(
                    self.cycles, sources, self.settings, KEY)

    def test_unverified_derivation_or_replayed_activity_hash_holds(self):
        SOURCE = source(self)
        for sources in (
            (self.sources[0], replace(self.sources[1], derivation=None)),
            (self.sources[0], replace(self.sources[1],
                                      activity_sha256=self.sources[0].activity_sha256)),
        ):
            with self.subTest(sources=sources), self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.reduce_eth_per_key_sources(
                    self.cycles, sources, self.settings, KEY)


    def test_different_issue_type_or_latest_confirmed_resets_this_key(self):
        SOURCE = source(self)
        for altered in (replace(self.link, status="DOWN"),
                        replace(self.link, status="CONFIRMED_BOTH_SIDE")):
            with self.subTest(status=altered.status):
                status = SOURCE.reduce_eth_per_key_sources(
                    self.cycles,
                    (self.sources[0], replace(self.sources[1], links=(altered,))),
                    self.settings, KEY)
                self.assertEqual(("pending", "latest_absent", 0, 3),
                                 (status.state, status.reason,
                                  status.observed, status.required))
                self.assertFalse(status.qualified)

    def test_changed_key_then_latest_active_counts_only_suffix(self):
        SOURCE = source(self)
        status = SOURCE.reduce_eth_per_key_sources(
            self.cycles,
            (replace(self.sources[0], links=(replace(self.link, status="DOWN"),)),
             self.sources[1]), self.settings, KEY)
        self.assertEqual(("pending", 1, 3),
                         (status.state, status.observed, status.required))

    def test_k_complete_source_window_is_not_a_publication_permit(self):
        SOURCE = source(self)
        changed = replace(self.link,
                          observation_a=EndpointObservation("new-peer", "swp8"))
        status = SOURCE.reduce_eth_per_key_sources(
            self.cycles,
            (self.sources[0], replace(self.sources[1], links=(changed,))),
            KChainState(1, 2, "9" * 64), KEY)
        self.assertEqual(("source_window_complete", 2, 2),
                         (status.state, status.observed, status.required))
        self.assertFalse(status.qualified)

    def test_invalid_k_key_or_nonqualifying_cycle_fails_closed(self):
        SOURCE = source(self)
        for k in (True, 0, -1, "3"):
            with self.subTest(k=k), self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.reduce_eth_per_key_sources(
                    self.cycles, self.sources, KChainState(1, k, "9" * 64), KEY)
        for key in (("eth_cabling", "", "swp1", "Mis-wiring"),
                    ("eth_cabling", "leaf-a", "swp1" + chr(0), "Mis-wiring"),
                    ["eth_cabling", "leaf-a", "swp1", "Mis-wiring"]):
            with self.subTest(key=key), self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.reduce_eth_per_key_sources(
                    self.cycles, self.sources, self.settings, key)
        with self.assertRaises(SOURCE.PerKeySourceHold):
            SOURCE.reduce_eth_per_key_sources(
                (self.cycles[0], replace(self.cycles[1], qualifying=1)),
                self.sources, self.settings, KEY)

    def test_duplicate_active_key_and_unknown_status_fail_closed(self):
        SOURCE = source(self)
        for links in ((self.link, self.link),
                      (replace(self.link, status="UNRECOGNIZED"),)):
            with self.subTest(links=links), self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.reduce_eth_per_key_sources(
                    self.cycles, (self.sources[0], replace(self.sources[1], links=links)),
                    self.settings, KEY)

    def test_changed_expected_topology_is_not_ordinary_pending(self):
        SOURCE = source(self)
        changed = replace(self.sources[1],
                          derivation=TopologyDerivationWitness({"topology": "8" * 64}, ()))
        with self.assertRaises(SOURCE.PerKeySourceHold):
            SOURCE.reduce_eth_per_key_sources(
                self.cycles, (self.sources[0], changed), self.settings, KEY)

    def test_same_topology_digest_cannot_hide_changed_expected_peer(self):
        SOURCE = source(self)
        changed = replace(self.sources[1],
                          links=(replace(self.link, device_b="different-plan-peer"),))
        with self.assertRaises(SOURCE.PerKeySourceHold):
            SOURCE.reduce_eth_per_key_sources(
                self.cycles, (self.sources[0], changed), self.settings, KEY)

    def test_non_topology_input_digest_does_not_reset_same_active_key(self):
        SOURCE = source(self)
        first = replace(self.sources[0], derivation=TopologyDerivationWitness(
            {"topology": "d" * 64, "inventory": "5" * 64}, ()))
        second = replace(self.sources[1], derivation=TopologyDerivationWitness(
            {"topology": "d" * 64, "inventory": "6" * 64}, ()))
        status = SOURCE.reduce_eth_per_key_sources(
            self.cycles, (first, second), self.settings, KEY)
        self.assertEqual(("pending", 2, 3),
                         (status.state, status.observed, status.required))
        self.assertFalse(status.qualified)

    def test_topology_role_missing_cannot_fall_back_to_other_digest(self):
        SOURCE = source(self)
        altered = replace(self.sources[1], derivation=TopologyDerivationWitness(
            {"release_id": "d" * 64}, ()))
        with self.assertRaises(SOURCE.PerKeySourceHold):
            SOURCE.reduce_eth_per_key_sources(
                self.cycles, (self.sources[0], altered), self.settings, KEY)

    def test_literal_backslash_text_is_not_a_nul_byte(self):
        SOURCE = source(self)
        key = ("eth_cabling", "leaf-a", "swp1\\x00", "Mis-wiring")
        self.assertNotIn(chr(0), key[2])
        status = SOURCE.reduce_eth_per_key_sources(
            self.cycles, self.sources, self.settings, key)
        self.assertEqual(("pending", "latest_absent", 0, 3),
                         (status.state, status.reason, status.observed, status.required))


if __name__ == "__main__":
    unittest.main()
