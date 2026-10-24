"""Fleet jobs (IB upgrade v2): reboot probing (owner 2026-10-23; review 15.4, 15.5, 15.12).

upgrading Q: first ping at once, then every 30 s; no reply = rebooting, rebooting Q after
1 minute (O1 2026-10-24, was 3); SSH check every 2 minutes. rebooting Q: ping every 15 s, TCP/22, one SSH
session for boot_id + nvued + `nv show system version`. One action per switch, stale
results ignored, limits measured from dispatch and never reset.

Readiness budget (field 2026-10-24): in the v1 CPLD log, the first SSH reach after the
reboot to NVUE ready took up to 718 s on 57 switches (7 over 600 s, none over 720 s, all
upgraded), so the readiness checks get 15 minutes; the 30-minute dwell and the 60-minute
device deadline stay (dispatch to NVUE ready was at most 1598 s).

Reboot wait (O1, 2026-10-24): after v1's WAIT_REBOOT mark the switches answered SSH after
68 s at the earliest, so rebooting Q starts 60 s after the failed ping instead of 180 s; a
switch still on the same boot goes back to upgrading Q (boot_same), so probing early is safe.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_probe as probe  # noqa: E402

BOOT_A, BOOT_B = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"


class Clock:
    """Runs the tracker the way the main loop does: ask, run every due action with a scripted result."""

    def __init__(self, tracker, results):
        self.tracker, self.results, self.now = tracker, results, 0.0
        self.trace, self.handbacks, self.handback_times = [], [], []

    def run(self, until, step=1.0):
        while self.now <= until:
            while True:                     # the main loop dispatches newly due actions at once
                actions, handbacks = self.tracker.due(self.now)
                self._keep(handbacks)
                if not actions:
                    break
                for host, action, token in actions:
                    result = self.results(host, action, self.now)
                    self.trace.append((self.now, host, action))
                    self._keep([self.tracker.report(host, token, action, result, self.now)])
            self.now += step
        return self.handbacks

    def _keep(self, handbacks):
        for handback in handbacks:
            if handback:
                self.handbacks.append(handback)
                self.handback_times.append(self.now)

    def actions(self, kind):
        return [time for time, _host, action in self.trace if action == kind]


def device(reboot_at=None, up_at=None, nvue_at=None, boot_after=BOOT_B, status=None):
    """Scripted switch: installing until reboot_at, down until up_at, nvued/CLI ready at nvue_at."""
    def results(host, action, now):
        down = reboot_at is not None and now >= reboot_at and (up_at is None or now < up_at)
        rebooted = up_at is not None and now >= up_at
        if action == probe.PING:
            return "no_reply" if down else "reply"
        if action == probe.TCP:
            return not down
        if action == probe.STATUS:
            if down:
                return {"kind": "connect_fail"}
            return status(now) if status else {"kind": "ok", "boot_id": boot_after if rebooted else BOOT_A,
                                                  "outcome": "running"}
        if action == probe.LADDER:
            if down:
                return {"kind": "connect_fail"}
            if not rebooted:
                return {"kind": "boot_same", "boot_id": BOOT_A}
            if nvue_at is not None and now < nvue_at:
                return {"kind": "nvued_down", "boot_id": boot_after}
            return {"kind": "ready", "boot_id": boot_after, "version": "25.02.0001"}
        raise AssertionError(action)
    return results


class ProbeTest(unittest.TestCase):
    def tracker(self, **timings):
        tracker = probe.ProbeTracker(probe.Timings(**timings))
        tracker.add("sw01", now=0.0, dispatched_at=0.0, boot_before=BOOT_A)
        return tracker

    def test_installing_then_rebooting_then_ready(self):
        clock = Clock(self.tracker(), device(reboot_at=95, up_at=400, nvue_at=470))
        [handback] = clock.run(600)
        self.assertEqual((handback.outcome, handback.boot_id, handback.version), (probe.READY, BOOT_B, "25.02.0001"))
        pings = clock.actions(probe.PING)
        self.assertEqual(pings[:4], [0.0, 30.0, 60.0, 90.0], "first ping at once, then every 30 s while installing")
        self.assertEqual(pings[4], 120.0)                            # 95 is down; the 120 ping finds it down
        self.assertNotIn(150.0, pings, "1-minute wait before the ladder starts")
        self.assertEqual(pings[5], 180.0, "rebooting Q starts 60 s after the failed ping")
        self.assertEqual(pings[5:8], [180.0, 195.0, 210.0], "ladder pings every 15 s")
        self.assertEqual(clock.actions(probe.STATUS), [120.0], "one SSH check fell due while in upgrading Q")
        ladders = clock.actions(probe.LADDER)
        self.assertEqual(ladders[0], 405.0, "ping 405 replies, TCP and SSH follow in the same tick")
        self.assertEqual(ladders[1:3], [435.0, 465.0], "nvued not ready: the SSH step repeats every 30 s")
        self.assertEqual(handback.reason, "READY")

    def test_first_ping_failing_means_already_rebooting(self):
        clock = Clock(self.tracker(), device(reboot_at=0, up_at=200))
        [handback] = clock.run(400)
        self.assertEqual(handback.outcome, probe.READY)
        self.assertEqual(clock.actions(probe.PING)[:2], [0.0, 60.0])

    def test_a_reboot_between_two_pings_is_caught_by_the_ssh_check(self):
        clock = Clock(self.tracker(), device(reboot_at=31, up_at=55))   # down only between pings
        [handback] = clock.run(300)
        self.assertEqual(handback.outcome, probe.READY)
        self.assertEqual(clock.actions(probe.STATUS), [120.0], "the 2-minute SSH check sees the new boot_id")
        self.assertEqual(clock.actions(probe.LADDER), [120.0], "and enters the ladder at once")

    def test_a_false_reboot_goes_back_to_upgrading_q_without_resetting_the_dwell(self):
        def pings(host, action, now):
            if action == probe.PING:
                return "no_reply" if now == 30 else "reply"      # one lost burst while still installing
            if action == probe.TCP:
                return True
            if action == probe.STATUS:
                return {"kind": "ok", "boot_id": BOOT_A, "outcome": "running"}
            return {"kind": "boot_same", "boot_id": BOOT_A}
        clock = Clock(self.tracker(), pings)
        [handback] = clock.run(2000, step=5.0)
        self.assertIn(90.0, clock.actions(probe.LADDER), "the ladder finds the same boot")
        self.assertIn(120.0, clock.actions(probe.PING), "back to upgrading Q pings")
        self.assertEqual((handback.outcome, handback.reason), (probe.UNKNOWN, "REBOOT_NOT_OBSERVED"))
        self.assertEqual(clock.handback_times, [1805.0], "30 minutes from dispatch, not from the bounce")

    def test_reboot_wait_is_one_minute_and_ladder_pings_stay_15_seconds(self):
        timings = probe.Timings()
        self.assertEqual((timings.reboot_wait, timings.ladder_ping), (60.0, 15.0))

    def test_a_switch_back_70_seconds_after_going_down_is_ready_earlier(self):
        def run(**timings):
            clock = Clock(self.tracker(**timings), device(reboot_at=20, up_at=90))
            [handback] = clock.run(600, step=5.0)
            self.assertEqual((handback.outcome, handback.boot_id), (probe.READY, BOOT_B))
            return clock.handback_times[0]
        default, three_minutes = run(), run(reboot_wait=180.0)
        self.assertEqual(default, 90.0, "the ping 60 s after the lost one finds it back; TCP and SSH follow")
        self.assertEqual(three_minutes, 210.0)
        self.assertLess(default, three_minutes)

    def test_a_lost_ping_without_a_reboot_returns_to_upgrading_q_without_a_handback(self):
        def bounce(host, action, now):
            if action == probe.PING:
                return "no_reply" if now == 30 else "reply"
            if action == probe.TCP:
                return True
            if action == probe.STATUS:
                return {"kind": "ok", "boot_id": BOOT_A, "outcome": "running"}
            return {"kind": "boot_same", "boot_id": BOOT_A}
        tracker = self.tracker()
        clock = Clock(tracker, bounce)
        self.assertEqual(clock.run(300, step=5.0), [], "no handback: the switch is still installing")
        self.assertEqual(clock.actions(probe.LADDER), [90.0], "probed 60 s after the lost ping, same boot")
        self.assertEqual(tracker.devices["sw01"].phase, probe.UPGRADING)
        self.assertIn(120.0, clock.actions(probe.PING), "upgrading Q pings again")

    def test_status_outcomes(self):
        failed = Clock(self.tracker(), device(status=lambda now: {"kind": "ok", "boot_id": BOOT_A,
                                                                   "outcome": "preinstall_failed",
                                                                   "reason": "PACKAGE_READY"}))
        [handback] = failed.run(200)
        self.assertEqual((handback.outcome, handback.reason), (probe.FAILED, "PACKAGE_READY"))

        hostkey = Clock(self.tracker(), device(status=lambda now: {"kind": "hostkey"}))
        [handback] = hostkey.run(200)
        self.assertEqual((handback.outcome, handback.reason), (probe.REVIEW, "HOST_KEY_MISMATCH"))

        late = {"kind": "ok", "boot_id": BOOT_A, "outcome": "exit_after_install"}
        warned = Clock(self.tracker(), device(reboot_at=250, up_at=500,
                                              status=lambda now: late if now < 250 else {"kind": "connect_fail"}))
        [handback] = warned.run(800)
        self.assertEqual(handback.outcome, probe.READY, "a nonzero exit after install keeps probing (review 15.2)")
        self.assertEqual(handback.warnings, ("INSTALLER_EXIT_NONZERO_AFTER_INSTALL",))

    def test_limits(self):
        never_ready = Clock(self.tracker(), device(reboot_at=10, up_at=300, nvue_at=10**9))
        [handback] = never_ready.run(2000, step=5.0)
        self.assertEqual((handback.outcome, handback.reason), (probe.UNKNOWN, "NVUE_NOT_READY"))
        self.assertEqual(never_ready.handback_times, [1205.0], "15 minutes after the first readiness check at 300")

        never_up = Clock(self.tracker(deadline=1000), device(reboot_at=10))
        [handback] = never_up.run(2000, step=5.0)
        self.assertEqual((handback.outcome, handback.reason), (probe.UNKNOWN, "DEVICE_DEADLINE_EXCEEDED"))
        self.assertEqual(never_up.handback_times, [1005.0])

    def test_default_limits_follow_the_v1_field_data(self):
        timings = probe.Timings()
        self.assertEqual((timings.ladder_budget, timings.dwell, timings.deadline), (900.0, 1800.0, 3600.0),
                         "readiness checks 15 minutes (field 2026-10-24); dwell 30 and deadline 60 minutes unchanged")

    def test_the_slowest_v1_nvue_start_is_ready_within_the_budget(self):
        # First readiness check at 300 s; NVUE ready 718 s later, the slowest of 57 switches in the v1 log.
        slowest = Clock(self.tracker(), device(reboot_at=10, up_at=300, nvue_at=300 + 718))
        [handback] = slowest.run(2000, step=5.0)
        self.assertEqual((handback.outcome, handback.reason), (probe.READY, "READY"))
        self.assertEqual(slowest.handback_times, [1020.0], "the 30-second SSH retry that follows NVUE ready")

    def test_one_action_per_switch_and_stale_results_are_ignored(self):
        tracker = self.tracker()
        actions, _ = tracker.due(0.0)
        self.assertEqual([(host, action) for host, action, _t in actions], [("sw01", probe.PING)])
        self.assertEqual(tracker.due(50.0), ([], []), "nothing new while the ping is in flight")
        token = actions[0][2]
        self.assertIsNone(tracker.report("sw01", token + 1, probe.PING, "no_reply", 1.0))
        self.assertEqual(tracker.devices["sw01"].phase, probe.UPGRADING, "a stale token changes nothing")
        tracker.report("sw01", token, probe.PING, "error", 1.0)
        self.assertEqual(tracker.devices["sw01"].phase, probe.UPGRADING, "a local ping error is not a reboot")
        self.assertEqual(tracker.snapshot(1.0)["upgrading"], 1)

    def test_a_job_without_reboot_returns_when_its_script_exits_zero(self):
        tracker = probe.ProbeTracker(probe.Timings())
        tracker.add("sw01", now=0.0, dispatched_at=0.0, boot_before=BOOT_A, expect_reboot=False)
        state = {"kind": "ok", "boot_id": BOOT_A, "outcome": "running"}
        clock = Clock(tracker, device(status=lambda now: state if now < 40 else dict(state, outcome="exit_zero")))
        [handback] = clock.run(200)
        self.assertEqual((handback.outcome, handback.reason, handback.boot_id),
                         (probe.READY, "COMPLETED_WITHOUT_REBOOT", BOOT_A))
        self.assertEqual(clock.actions(probe.STATUS), [15.0, 30.0, 45.0], "checked every 15 s, not every 2 minutes")
        self.assertEqual(clock.handback_times, [45.0])

    def test_requeue_after_verification_keeps_the_dispatch_deadline(self):
        tracker = probe.ProbeTracker(probe.Timings(deadline=500))
        tracker.requeue_rebooting("sw01", now=400.0, dispatched_at=0.0, boot_before=BOOT_A, warnings=("W",))
        clock = Clock(tracker, device(reboot_at=0))
        clock.now = 400.0
        [handback] = clock.run(700)
        self.assertEqual((handback.outcome, handback.reason, handback.warnings),
                         (probe.UNKNOWN, "DEVICE_DEADLINE_EXCEEDED", ("W",)))


if __name__ == "__main__":
    unittest.main()
