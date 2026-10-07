"""RED real prod worker/emitter -> Switch role -> per-key source view."""

import unittest

from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, tracker_writer,
)
from test_cases.test_issue_tracker_switch_per_key_source import KEY_A, source
from test_cases import test_issue_tracker_switch_runtime_workflow as runtime_cases


class SwitchPerKeySourceWorkflowTests(unittest.TestCase):
    setUp = runtime_cases.ProdSwitchSourceWorkflowTests.setUp
    _archive = runtime_cases.ProdSwitchSourceWorkflowTests._archive
    _cycle = runtime_cases.ProdSwitchSourceWorkflowTests._cycle

    def _settings(self):
        publication = self.project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            self.project, publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="switch-per-key-first-use",
        )
        return publication

    def test_real_two_cycles_bind_switch_abnormal_key_without_publication(self):
        publication = self._settings()
        first, _ = self._cycle()
        second, _ = self._cycle()
        SOURCE = source(self)
        with tracker_writer(self.project, publication) as token:
            result = SOURCE.read_prod_switch_per_key_source(
                self.store, http_root=self.root, settings=current_k(token),
                key=KEY_A, source_slot="ethernet/prod", writer_token=token,
            )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), result.cycle_ids)
        self.assertEqual(("pending", 2, 3),
                         (result.state, result.observed, result.required))
        self.assertFalse(result.qualified)

    def test_protected_archive_sha_drift_holds(self):
        publication = self._settings()
        self._cycle()
        _second, artifacts = self._cycle()
        archive = artifacts["ethernet/prod"]["info"]
        archive.write_bytes(archive.read_bytes() + b"late drift")
        SOURCE = source(self)
        with tracker_writer(self.project, publication) as token:
            with self.assertRaises(SOURCE.SwitchPerKeySourceHold):
                SOURCE.read_prod_switch_per_key_source(
                    self.store, http_root=self.root, settings=current_k(token),
                    key=KEY_A, source_slot="ethernet/prod", writer_token=token,
                )


if __name__ == "__main__":
    unittest.main()

