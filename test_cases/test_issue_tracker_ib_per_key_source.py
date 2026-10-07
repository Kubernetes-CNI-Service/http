"""RED IB-only per-key protected-source continuity, never a C5 permit."""

from dataclasses import replace
import importlib
import importlib.util
import unittest

from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_ib_runtime import IbBoundCycleReport, IbReportLink
from monitor.issue_tracker_k_chain import KChainState


KEY_A = ("ib_cabling", "leaf01", "sw1p1", "Mis-wiring")
KEY_B = ("ib_cabling", "leaf02", "sw2p1", "Link Down")
ROW_A = IbReportLink(
    "Mis-wiring", ("leaf01", "sw1p1", "server01", "mlx5_0"),
    ("server02", "mlx5_1"), "Miswired_Links", 2,
)
ROW_B = IbReportLink(
    "Link Down", ("leaf02", "sw2p1", "server03", "mlx5_2"),
    ("", ""), "Missing_Links", 2,
)


def source(testcase):
    name = "monitor.issue_tracker_ib_per_key_source"
    testcase.assertIsNotNone(importlib.util.find_spec(name),
                             "protected IB per-key adapter is not implemented")
    return importlib.import_module(name)


def fixture():
    first = CycleEvidence(
        "1" * 64, 1, "project-A", "prod",
        ("ethernet/prod", "infiniband/prod", "nvlink/prod"), True,
        "a" * 64, "b" * 64,
    )
    second = replace(first, cycle_id="2" * 64, sequence=2,
                     completion_sha256="c" * 64)
    reports = (
        IbBoundCycleReport(first.cycle_id, 1, first.completion_sha256,
                           "d" * 64, "f" * 64, (ROW_A,),
                           recorded_at_utc="2026-09-26T04:20:00Z"),
        IbBoundCycleReport(second.cycle_id, 2, second.completion_sha256,
                           "e" * 64, "f" * 64, (ROW_A, ROW_B),
                           recorded_at_utc="2026-09-26T04:21:00Z"),
    )
    return (first, second), reports


class IbPerKeySourceTests(unittest.TestCase):
    def setUp(self):
        self.settings = KChainState(1, 3, "9" * 64)
        self.cycles, self.reports = fixture()

    def test_same_cycles_have_a_two_of_three_b_one_of_three(self):
        SOURCE = source(self)
        a = SOURCE.reduce_ib_per_key_reports(
            self.cycles, self.reports, self.settings, KEY_A)
        b = SOURCE.reduce_ib_per_key_reports(
            self.cycles, self.reports, self.settings, KEY_B)
        self.assertEqual(("pending", 2, 3),
                         (a.state, a.observed, a.required))
        self.assertEqual(("pending", 1, 3),
                         (b.state, b.observed, b.required))
        self.assertFalse(a.qualified)
        self.assertEqual("f" * 64, a.expected_topology_sha256)

    def test_missing_or_rebound_report_holds(self):
        SOURCE = source(self)
        for reports in (
            self.reports[:1],
            (self.reports[0], replace(self.reports[1], cycle_id="3" * 64)),
            (self.reports[0], replace(self.reports[1],
                                      completion_sha256="4" * 64)),
            (self.reports[0], replace(self.reports[1], report_sha256="d" * 64)),
        ):
            with self.subTest(reports=reports), self.assertRaises(SOURCE.IbPerKeySourceHold):
                SOURCE.reduce_ib_per_key_reports(
                    self.cycles, reports, self.settings, KEY_A)

    def test_topology_or_expected_peer_drift_holds(self):
        SOURCE = source(self)
        for reports in (
            (self.reports[0], replace(self.reports[1],
                                      expected_topology_sha256="0" * 64)),
            (self.reports[0], replace(self.reports[1], rows=(
                replace(ROW_A, expected_endpoints=("leaf01", "sw1p1",
                                                   "other-server", "mlx5_0")),
                ROW_B,
            ))),
        ):
            with self.subTest(reports=reports), self.assertRaises(SOURCE.IbPerKeySourceHold):
                SOURCE.reduce_ib_per_key_reports(
                    self.cycles, reports, self.settings, KEY_A)

    def test_missing_protected_run_time_holds(self):
        SOURCE = source(self)
        with self.assertRaises(SOURCE.IbPerKeySourceHold):
            SOURCE.reduce_ib_per_key_reports(
                self.cycles,
                (self.reports[0], replace(self.reports[1], recorded_at_utc="")),
                self.settings, KEY_A,
            )

    def test_changed_actual_peer_does_not_reset_same_active_key(self):
        SOURCE = source(self)
        newer = replace(self.reports[1], rows=(
            replace(ROW_A, actual_destination=("different-server", "mlx5_4")), ROW_B))
        result = SOURCE.reduce_ib_per_key_reports(
            self.cycles, (self.reports[0], newer), self.settings, KEY_A)
        self.assertEqual(("pending", 2, 3),
                         (result.state, result.observed, result.required))
        self.assertFalse(result.qualified)

    def test_latest_absent_key_resets_to_zero(self):
        SOURCE = source(self)
        result = SOURCE.reduce_ib_per_key_reports(
            self.cycles, (self.reports[0], replace(self.reports[1], rows=(ROW_B,))),
            self.settings, KEY_A)
        self.assertEqual(("pending", "latest_absent", 0, 3),
                         (result.state, result.reason, result.observed, result.required))

    def test_invalid_k_or_non_boolean_qualifying_fails_closed(self):
        SOURCE = source(self)
        for k in (True, 0, -1, "3"):
            with self.subTest(k=k), self.assertRaises(SOURCE.IbPerKeySourceHold):
                SOURCE.reduce_ib_per_key_reports(
                    self.cycles, self.reports, KChainState(1, k, "9" * 64), KEY_A)
        with self.assertRaises(SOURCE.IbPerKeySourceHold):
            SOURCE.reduce_ib_per_key_reports(
                (self.cycles[0], replace(self.cycles[1], qualifying=1)),
                self.reports, self.settings, KEY_A)

    def test_duplicate_key_and_invalid_producer_calendar_time_fail_closed(self):
        SOURCE = source(self)
        for altered in (replace(self.reports[1], rows=(ROW_A, ROW_A)),
                        replace(self.reports[1], recorded_at_utc="2026-02-30T04:21:00Z")):
            with self.subTest(altered=altered), self.assertRaises(SOURCE.IbPerKeySourceHold):
                SOURCE.reduce_ib_per_key_reports(
                    self.cycles, (self.reports[0], altered), self.settings, KEY_A)


if __name__ == "__main__":
    unittest.main()
