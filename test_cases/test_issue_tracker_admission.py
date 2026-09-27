"""C-23 shared local admission transition contract, independent of C6 writer."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES


FLOOR_NS = MIN_CONTINUOUS_INTERVAL_MINUTES * 60 * 1_000_000_000
CYCLES = ("completed-1", "completed-2", "completed-3", "completed-4")


class SharedAdmissionDirectTests(unittest.TestCase):
    def _read_durable_state(self, case):
        from monitor.issue_tracker_admission import read_shared_local_admission
        from monitor.issue_tracker_local_commit import _canonical

        published = b"published workbook"
        generation_id = "gen-00000000000000000001-" + "b" * 32
        published_sha = hashlib.sha256(published).hexdigest()
        event = {
            "schema_version": 1, "lane": "manual",
            "generation_id": generation_id,
            "published_sha256": published_sha,
            "project_key": "project", "scope": "prod",
            "cycle_id": "completed-1", "cycle_completion_sha256": "a" * 64,
            "policy_sha256": "c" * 64, "publish_every_cycles": 1,
            "boot_id": "boot-A", "monotonic_ns": 1,
        }
        if case == "stored_event_drift":
            event["project_key"] = "different-project"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            if case != "missing_admissions":
                admissions = root / "admissions"
                admissions.mkdir(mode=0o700)
                number = 2 if case == "incomplete_admissions" else 1
                admission = admissions / f"admission-{number:020d}.json"
                admission.write_bytes(_canonical(event))
                admission.chmod(0o600)
            generations = root / "generations"
            generations.mkdir(mode=0o700)
            if case != "generation_mismatch":
                generation = generations / generation_id
                generation.mkdir(mode=0o700)
                receipt = generation / "RECEIPT"
                receipt.write_bytes(_canonical({
                    "generation_id": generation_id,
                    "published_sha256": published_sha,
                }))
                receipt.chmod(0o600)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, root_fd)
            cycles = (SimpleNamespace(
                qualifying=True, cycle_id="completed-1",
                completion_sha256="a" * 64,
            ),)
            if case == "duplicate_collector_cycle":
                cycles += cycles
            prior = None if case == "missing_receipt" else published
            if case == "published_drift":
                prior = b"different workbook"
            with (mock.patch("monitor.issue_tracker_admission._owner",
                             return_value=SimpleNamespace(root_fd=root_fd)),
                  mock.patch("monitor.issue_tracker_admission.read_completed_cycle_evidence",
                             return_value=cycles)):
                return read_shared_local_admission(
                    object(), SimpleNamespace(project_key="project", scope="prod"),
                    prior,
                )

    def test_only_six_durable_journal_failures_are_terminal(self):
        from monitor.issue_tracker_admission import AdmissionTerminalOrphan

        for case in (
            "missing_admissions", "incomplete_admissions", "missing_receipt",
            "generation_mismatch", "stored_event_drift", "published_drift",
        ):
            with self.subTest(case=case):
                with self.assertRaises(AdmissionTerminalOrphan):
                    self._read_durable_state(case)

    def test_collector_duplicate_and_transient_io_do_not_claim_terminal_state(self):
        from monitor.issue_tracker_admission import (
            AdmissionHold, AdmissionTerminalOrphan, read_shared_local_admission,
        )

        with self.assertRaises(AdmissionHold) as duplicate:
            self._read_durable_state("duplicate_collector_cycle")
        self.assertNotIsInstance(duplicate.exception, AdmissionTerminalOrphan)
        with (mock.patch("monitor.issue_tracker_admission._owner",
                         side_effect=OSError("transient read failure"))):
            with self.assertRaises(AdmissionHold) as transient:
                read_shared_local_admission(object(), object(), b"published")
        self.assertNotIsInstance(transient.exception, AdmissionTerminalOrphan)

    def _event(self, lane, cycle_id, monotonic_ns, *, n=2, boot="boot-A"):
        return {
            "lane": lane, "cycle_id": cycle_id,
            "publish_every_cycles": n,
            "boot_id": boot, "monotonic_ns": monotonic_ns,
        }

    def test_manual_may_anchor_same_completed_cycle_but_auto_counts_strictly_after(self):
        from monitor.issue_tracker_admission import (
            AdmissionHold, assess_shared_admission_step,
        )

        prior = self._event("automatic", "completed-2", 11)
        manual = self._event("manual", "completed-2", 11 + FLOOR_NS)
        self.assertTrue(assess_shared_admission_step(prior, manual, CYCLES))
        with self.assertRaises(AdmissionHold):
            assess_shared_admission_step(
                manual,
                self._event("automatic", "completed-3", 11 + 2 * FLOOR_NS),
                CYCLES,
            )
        self.assertTrue(assess_shared_admission_step(
            manual,
            self._event("automatic", "completed-4", 11 + 2 * FLOOR_NS),
            CYCLES,
        ))

    def test_first_event_validates_clock_lane_and_interval_before_it_can_anchor(self):
        from monitor.issue_tracker_admission import (
            AdmissionHold, assess_shared_admission_step,
        )

        valid = self._event("manual", "completed-1", 11)
        self.assertTrue(assess_shared_admission_step(None, valid, CYCLES))
        for field, invalid in (
            ("lane", "unknown"), ("publish_every_cycles", 0),
            ("boot_id", ""), ("monotonic_ns", 0),
        ):
            with self.subTest(field=field):
                with self.assertRaises(AdmissionHold):
                    assess_shared_admission_step(
                        None, {**valid, field: invalid}, CYCLES,
                    )
        with self.assertRaises(AdmissionHold):
            assess_shared_admission_step(
                None, self._event("automatic", "completed-1", 11, n=2),
                CYCLES,
            )

    def test_manual_subfloor_is_visible_anomaly_not_a_new_limiter(self):
        from monitor.issue_tracker_admission import (
            AdmissionCollectorAnomaly, assess_shared_admission_step,
        )

        prior = self._event("automatic", "completed-2", 11)
        with self.assertRaisesRegex(
            AdmissionCollectorAnomaly, "collector_interval_below_minimum",
        ):
            assess_shared_admission_step(
                prior,
                self._event("manual", "completed-2", 11 + FLOOR_NS - 1),
                CYCLES,
            )

    def test_manual_to_manual_uses_same_cycle_anchor_and_shared_floor(self):
        from monitor.issue_tracker_admission import (
            AdmissionCollectorAnomaly, assess_shared_admission_step,
        )

        first = self._event("manual", "completed-2", 11, n=3)
        second = self._event("manual", "completed-2", 11 + FLOOR_NS,
                             n=3)
        self.assertTrue(assess_shared_admission_step(first, second, CYCLES))
        with self.assertRaises(AdmissionCollectorAnomaly):
            assess_shared_admission_step(
                first, {**second, "monotonic_ns": 11 + FLOOR_NS - 1}, CYCLES,
            )

    def test_unverifiable_restart_never_uses_cross_boot_monotonic_difference(self):
        from monitor.issue_tracker_admission import (
            AdmissionHold, assess_shared_admission_step,
        )

        with self.assertRaises(AdmissionHold):
            assess_shared_admission_step(
                self._event("manual", "completed-2", 11),
                self._event("automatic", "completed-4", 11 + 2 * FLOOR_NS,
                            boot="boot-B"),
                CYCLES,
            )


if __name__ == "__main__":
    unittest.main()
