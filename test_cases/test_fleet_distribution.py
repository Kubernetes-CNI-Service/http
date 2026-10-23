"""Fleet jobs (IB upgrade v2): package distribution (owner 2026-10-23, review 15.6-15.8).

Relay below 10G: queues per OOB leaf from P2P, the first copy of a queue comes from
the ztp-server, every verified copy serves up to four switches at once, a queue is
released for upgrade only after its holders stop serving. Direct at 10G and above:
random start in the window, rotation across OOB leaves, shared server cap.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_distribution as dist  # noqa: E402
from fleet_distribution import SERVER, UNKNOWN_GROUP  # noqa: E402


def drive(scheduler, *, fail=lambda receiver, source: None):
    """Start everything possible, finish it all, repeat; return the rounds of (receiver, source)."""
    rounds = []
    while True:
        started = scheduler.assignments(now=float(len(rounds)))
        if not started:
            return rounds
        rounds.append(started)
        for receiver, source in started:
            error = fail(receiver, source)
            scheduler.finished(receiver, error is None, error=error or dist.UNCLEAR)


class OobGroupTest(unittest.TestCase):
    def test_management_links_in_p2p_group_switches_by_oob_leaf(self):
        with tempfile.TemporaryDirectory() as tmp:
            p2p = Path(tmp) / "p2p.csv"
            p2p.write_text("a-node,a-port,z-node,z-port\n"
                           "sw01,eth0,oob-leaf01,swp1\n"
                           "oob-leaf01,swp2,sw02,mgmt\n"
                           "sw03,eth0,oob-leaf02,swp1\n"
                           "sw04,eth0,oob-leaf01,swp3\n"
                           "sw04,eth0,oob-leaf02,swp9\n"
                           "sw01,ib1,spine01,1\n", encoding="utf-8")
            groups, warnings = dist.oob_groups(p2p, ["sw01", "sw02", "sw03", "sw04", "sw05"])
        self.assertEqual(groups, {"sw01": "oob-leaf01", "sw02": "oob-leaf01", "sw03": "oob-leaf02",
                                  "sw04": UNKNOWN_GROUP, "sw05": UNKNOWN_GROUP})
        self.assertTrue(any("sw04" in line and "two OOB leaves" in line for line in warnings), warnings)
        self.assertTrue(any("sw05" in line and "no management link" in line for line in warnings), warnings)
        self.assertEqual(dist.ordered_groups(groups, ["sw03", "sw01", "sw02"]),
                         {"oob-leaf02": ["sw03"], "oob-leaf01": ["sw01", "sw02"]})


class RelayTest(unittest.TestCase):
    def test_a_full_queue_of_48_needs_four_pulls_and_only_one_comes_from_the_server(self):
        hosts = [f"sw{i:02d}" for i in range(48)]
        relay = dist.RelayScheduler({"leaf1": hosts}, dist.ServerGate(cap=1))
        rounds = drive(relay)
        self.assertEqual([len(batch) for batch in rounds[:3]], [1, 4, 20])
        self.assertEqual(sum(len(batch) for batch in rounds), 48)
        self.assertEqual(len(rounds), 4, "1 -> +4 -> +20 -> +23 (owner: at most four pulls)")
        self.assertEqual([source for batch in rounds for _r, source in batch].count(SERVER), 1)
        for batch in rounds:
            sources = [source for _receiver, source in batch if source != SERVER]
            self.assertTrue(all(sources.count(source) <= 4 for source in sources), "four receivers per source")
        self.assertEqual(relay.releasable(), ["leaf1"])
        self.assertEqual(relay.release("leaf1"), hosts[:1] + [host for batch in rounds[1:] for host, _s in batch])
        self.assertTrue(relay.done())

    def test_a_new_holder_serves_at_once_without_waiting_for_its_round(self):
        hosts = [f"sw{i:02d}" for i in range(10)]
        relay = dist.RelayScheduler({"leaf1": hosts}, dist.ServerGate(cap=1))
        [(head, source)] = relay.assignments(0)
        self.assertEqual((head, source), ("sw00", SERVER))
        relay.finished(head, True)
        first = relay.assignments(1)
        self.assertEqual([source for _r, source in first], [head] * 4)
        new_holder = first[0][0]
        relay.finished(new_holder, True)                       # one finishes; the other three still copy
        second = relay.assignments(2)
        self.assertEqual(second[0], ("sw05", new_holder), "the new holder serves immediately (least loaded)")
        sources = [source for _r, source in second]
        self.assertEqual((sources.count(new_holder), sources.count(head)), (4, 1),
                         "the head's freed slot is reused; nobody serves more than four")
        self.assertEqual(relay.releasable(), [], "the queue still has receivers in flight")

    def test_server_pulls_share_one_gate_with_cap_and_gap(self):
        gate = dist.ServerGate(cap=1)
        relay = dist.RelayScheduler({"a": ["a1", "a2"], "b": ["b1"], "c": ["c1"]}, gate)
        self.assertEqual(relay.assignments(0), [("a1", SERVER)])
        relay.finished("a1", True)
        self.assertEqual(relay.assignments(1), [("a2", "a1"), ("b1", SERVER)])
        spaced = dist.RelayScheduler({"a": ["a1"], "b": ["b1"]}, dist.ServerGate(gap=0.25))
        self.assertEqual(spaced.assignments(10.0), [("a1", SERVER)])
        self.assertEqual(spaced.assignments(10.1), [])
        self.assertEqual(spaced.assignments(10.3), [("b1", SERVER)])

    def test_failures_retry_another_holder_retire_bad_sources_and_leave_the_queue(self):
        relay = dist.RelayScheduler({"leaf1": ["h1", "h2", "r1", "r2", "r3"]}, dist.ServerGate(),
                                    holders=("h1", "h2"), fanout=1, retries=2, holder_failures=2, breaker=99)
        self.assertEqual(relay.assignments(0), [("r1", "h1"), ("r2", "h2")], "pre-staged copies serve; no server pull")
        relay.finished("r1", False, error=dist.SOURCE)
        relay.finished("r2", False, error=dist.SOURCE)
        self.assertEqual(sorted(relay.assignments(1)), [("r1", "h2"), ("r2", "h1")], "a retry goes to an untried holder")
        relay.finished("r1", False, error=dist.SOURCE)
        relay.finished("r2", False, error=dist.RECEIVER)
        self.assertEqual(relay.retired, {"h2"}, "two source-side failures retire h2; a receiver-side one spares h1")
        self.assertEqual(relay.assignments(2), [("r1", "h1")], "all sources tried: the remaining one is reused")
        relay.finished("r1", False, error=dist.RECEIVER)
        self.assertEqual(relay.failed, {"r1": "DISTRIBUTION_FAILED"}, "three attempts, then FAILED")
        self.assertEqual(relay.assignments(3), [("r2", "h1")])
        relay.finished("r2", True)
        self.assertEqual(relay.assignments(4), [("r3", "h1")])
        relay.finished("r3", True)
        self.assertEqual(relay.releasable(), ["leaf1"], "a failed receiver leaves the queue instead of blocking it")
        self.assertEqual(relay.release("leaf1"), ["h1", "h2", "r2", "r3"])

    def test_a_queue_without_a_usable_holder_falls_back_to_the_server(self):
        relay = dist.RelayScheduler({"leaf1": ["h1", "r1"]}, dist.ServerGate(), holders=("h1",))
        relay.holder_lost("h1")
        self.assertEqual(relay.assignments(0), [("r1", SERVER)])

    def test_a_drained_queue_serves_no_new_transfers_and_releases_after_its_last_one(self):
        relay = dist.RelayScheduler({"leaf1": ["h1"], UNKNOWN_GROUP: ["u1", "u2"]}, dist.ServerGate(),
                                    holders=("h1",), fanout=1)
        self.assertEqual(relay.assignments(0), [("u1", "h1")], "an unknown switch borrows any holder")
        self.assertEqual(relay.releasable(), [], "h1 is still serving")
        relay.finished("u1", True)
        self.assertIn("leaf1", relay.releasable())
        relay.release("leaf1")
        self.assertEqual(relay.assignments(1), [("u2", "u1")], "the released queue's holder is not used again")

    def test_systemic_peer_failures_trip_the_breaker_and_use_the_server(self):
        relay = dist.RelayScheduler({"leaf1": ["h1", "h2", "r1", "r2", "r3"]}, dist.ServerGate(),
                                    holders=("h1", "h2"), fanout=2, retries=5, holder_failures=9, breaker=4)
        for now in range(3):
            for receiver, _source in relay.assignments(now):
                relay.finished(receiver, False, error=dist.UNCLEAR)
            if relay.peer_disabled:
                break
        self.assertTrue(relay.peer_disabled)
        self.assertTrue(all(source == SERVER for _r, source in relay.assignments(9)))

    def test_one_peer_success_rules_out_a_systemic_failure(self):
        relay = dist.RelayScheduler({"leaf1": ["h1", "h2", "r1", "r2", "r3", "r4"]}, dist.ServerGate(),
                                    holders=("h1", "h2"), fanout=4, retries=9, holder_failures=99, breaker=2)
        relay.assignments(0)
        relay.finished("r1", True)
        for receiver in ("r2", "r3", "r4"):
            relay.finished(receiver, False, error=dist.UNCLEAR)
        self.assertFalse(relay.peer_disabled)


class DirectTest(unittest.TestCase):
    def test_random_start_rotation_and_shared_cap(self):
        groups = {"leaf1": ["a1", "a2", "a3"], "leaf2": ["b1", "b2"]}
        delays = iter([0, 5, 0, 0, 9])
        gate = dist.ServerGate(cap=2)
        direct = dist.DirectScheduler(groups, gate, window=60, now=100.0, randbelow=lambda bound: next(delays))
        self.assertEqual(direct.order, ["a1", "b1", "a2", "b2", "a3"])
        self.assertEqual(direct.starts(100.0), ["a1", "a2"], "b1 waits 5 s; the cap stops at two")
        self.assertEqual(direct.starts(100.0), [])
        direct.finished("a1", True)
        self.assertEqual(direct.starts(101.0), ["b2"])
        self.assertEqual(direct.next_wake(101.0), 105.0)
        direct.finished("a2", False, reason="DOWNLOAD_FAILED")
        self.assertEqual(direct.starts(105.0), ["b1"])
        direct.finished("b1", True)
        direct.finished("b2", True)
        self.assertEqual(direct.starts(109.0), ["a3"])
        direct.finished("a3", True)
        self.assertTrue(direct.done())
        self.assertEqual((direct.staged_hosts, direct.failed), (["a1", "b1", "b2", "a3"], {"a2": "DOWNLOAD_FAILED"}))
        self.assertEqual(gate.active, 0)

    def test_window_is_capped_like_the_v1_jitter_option(self):
        seen = []
        dist.DirectScheduler({"g": ["a"]}, dist.ServerGate(), window=99999, now=0,
                             randbelow=lambda bound: seen.append(bound) or 0)
        self.assertEqual(seen, [dist.MAX_WINDOW_SECONDS])


if __name__ == "__main__":
    unittest.main()
