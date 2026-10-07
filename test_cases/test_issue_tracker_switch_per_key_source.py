"""RED Switch-only per-key source continuity; not three-panel status."""

from dataclasses import replace
import importlib
import importlib.util
import unittest

from monitor.issue_tracker_cycle_source import CycleEvidence
from monitor.issue_tracker_k_chain import KChainState
from monitor.issue_tracker_switch_info_source import (
    SwitchAbnormalValue, SwitchInfoPreview, map_switch_source_rows,
)
from monitor.issue_tracker_switch_runtime import ProdSwitchCycleSource


KEY_A = ("switch", "leaf-a", "fan", "PSU1/FAN1")
KEY_B = ("switch", "leaf-a", "fan", "PSU2/FAN1")


def source(testcase):
    name = "monitor.issue_tracker_switch_per_key_source"
    testcase.assertIsNotNone(importlib.util.find_spec(name),
                             "protected Switch per-key adapter is not implemented")
    return importlib.import_module(name)


def fixture(*, second_has_a=True, second_has_b=True):
    first = CycleEvidence(
        "1" * 64, 1, "project-A", "prod",
        ("ethernet/prod", "infiniband/prod", "nvlink/prod"), True,
        "a" * 64, "b" * 64,
    )
    second = replace(first, cycle_id="2" * 64, sequence=2,
                     completion_sha256="c" * 64)

    def switch(cycle, archive, keys):
        keys = tuple((item[1], item[2], item[3]) for item in keys)
        preview = SwitchInfoPreview(
            "ethernet/prod", ("leaf-a",), archive, keys,
            tuple(SwitchAbnormalValue(*item, "fail") for item in keys),
        )
        return ProdSwitchCycleSource(
            cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
            preview, map_switch_source_rows(preview),
        )

    return (first, second), (
        switch(first, "d" * 64, (KEY_A,)),
        switch(second, "e" * 64,
               (KEY_A,) * second_has_a + (KEY_B,) * second_has_b),
    )


class SwitchPerKeySourceTests(unittest.TestCase):
    def setUp(self):
        self.settings = KChainState(1, 3, "9" * 64)
        self.cycles, self.sources = fixture()

    def test_same_cycles_have_a_two_of_three_b_one_of_three(self):
        SOURCE = source(self)
        a = SOURCE.reduce_switch_per_key_sources(
            self.cycles, self.sources, self.settings, KEY_A,
            source_slot="ethernet/prod")
        b = SOURCE.reduce_switch_per_key_sources(
            self.cycles, self.sources, self.settings, KEY_B,
            source_slot="ethernet/prod")
        self.assertEqual(("pending", 2, 3),
                         (a.state, a.observed, a.required))
        self.assertEqual(("pending", 1, 3),
                         (b.state, b.observed, b.required))
        self.assertFalse(a.qualified)

    def test_missing_or_rebound_cycle_and_slot_hold(self):
        SOURCE = source(self)
        for sources in (
            self.sources[:1],
            (self.sources[0], replace(self.sources[1], cycle_id="3" * 64)),
            (self.sources[0], replace(self.sources[1],
                                      completion_sha256="4" * 64)),
            (self.sources[0], replace(self.sources[1], preview=replace(
                self.sources[1].preview, source_slot="nvlink/prod"))),
        ):
            with self.subTest(sources=sources), self.assertRaises(SOURCE.SwitchPerKeySourceHold):
                SOURCE.reduce_switch_per_key_sources(
                    self.cycles, sources, self.settings, KEY_A,
                    source_slot="ethernet/prod")

    def test_selected_hosts_drift_or_archive_replay_hold(self):
        SOURCE = source(self)
        for sources in (
            (self.sources[0], replace(self.sources[1], preview=replace(
                self.sources[1].preview, selected_hosts=("other-host",)))),
            (self.sources[0], replace(self.sources[1], preview=replace(
                self.sources[1].preview,
                archive_sha256=self.sources[0].preview.archive_sha256))),
        ):
            with self.subTest(sources=sources), self.assertRaises(SOURCE.SwitchPerKeySourceHold):
                SOURCE.reduce_switch_per_key_sources(
                    self.cycles, sources, self.settings, KEY_A,
                    source_slot="ethernet/prod")

    def test_changed_measurement_keeps_key_continuity_not_old_value(self):
        SOURCE = source(self)
        key = ("switch", "leaf-a", "asic_temp", "ASIC")
        sources = []
        for original, reading in zip(self.sources, (81.0, 82.0)):
            altered = replace(original.preview,
                              abnormal_keys=(("leaf-a", "asic_temp", "ASIC"),),
                              abnormal_values=(SwitchAbnormalValue(
                                  "leaf-a", "asic_temp", "ASIC", "alarm",
                                  reading, 80.0, 90.0),))
            sources.append(replace(original, preview=altered,
                                   rows=map_switch_source_rows(altered)))
        result = SOURCE.reduce_switch_per_key_sources(
            self.cycles, tuple(sources), self.settings, key,
            source_slot="ethernet/prod")
        self.assertEqual(("pending", 2, 3),
                         (result.state, result.observed, result.required))
        self.assertFalse(result.qualified)

    def test_latest_absent_key_has_zero_continuity(self):
        SOURCE = source(self)
        cycles, sources = fixture(second_has_a=False)
        result = SOURCE.reduce_switch_per_key_sources(
            cycles, sources, self.settings, KEY_A, source_slot="ethernet/prod")
        self.assertEqual(("pending", "latest_absent", 0, 3),
                         (result.state, result.reason, result.observed, result.required))

    def test_invalid_k_and_non_boolean_qualifying_fail_closed(self):
        SOURCE = source(self)
        for k in (True, 0, -1, "3"):
            with self.subTest(k=k), self.assertRaises(SOURCE.SwitchPerKeySourceHold):
                SOURCE.reduce_switch_per_key_sources(
                    self.cycles, self.sources, KChainState(1, k, "9" * 64), KEY_A,
                    source_slot="ethernet/prod")
        with self.assertRaises(SOURCE.SwitchPerKeySourceHold):
            SOURCE.reduce_switch_per_key_sources(
                (self.cycles[0], replace(self.cycles[1], qualifying=1)),
                self.sources, self.settings, KEY_A, source_slot="ethernet/prod")

    def test_rebound_rows_and_duplicate_keys_fail_closed(self):
        SOURCE = source(self)
        preview = self.sources[1].preview
        duplicate = replace(preview,
                            abnormal_keys=preview.abnormal_keys + (preview.abnormal_keys[0],),
                            abnormal_values=preview.abnormal_values + (preview.abnormal_values[0],))
        for second in (replace(self.sources[1], rows=self.sources[0].rows),
                       replace(self.sources[1], preview=duplicate)):
            with self.subTest(second=second), self.assertRaises(SOURCE.SwitchPerKeySourceHold):
                SOURCE.reduce_switch_per_key_sources(
                    self.cycles, (self.sources[0], second), self.settings, KEY_A,
                    source_slot="ethernet/prod")


if __name__ == "__main__":
    unittest.main()
