"""RED real prod worker/emitter -> protected cycle -> ETH per-key source."""

import unittest

from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, tracker_writer,
)
from test_cases.test_issue_tracker_per_key_source import KEY, source
from test_cases import test_issue_tracker_switch_runtime_workflow as runtime_cases


class EthPerKeySourceWorkflowTests(unittest.TestCase):
    setUp = runtime_cases.ProdSwitchSourceWorkflowTests.setUp
    _archive = runtime_cases.ProdSwitchSourceWorkflowTests._archive
    _cycle = runtime_cases.ProdSwitchSourceWorkflowTests._cycle

    def _settings(self):
        publication = self.project / "99-output-monitor"
        publication.mkdir()
        initialize_tracker_state(
            self.project, publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="per-key-source-first-use",
        )
        return publication

    def test_real_active_key_window_uses_latest_peer_and_rechecks_w1(self):
        from monitor.issue_tracker_state_owner import set_k
        from monitor.issue_tracker_switch_runtime import (
            read_prod_eth_activity_k_window, validate_prod_eth_activity_k_window,
            SwitchRuntimeHoldError,
        )
        from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx

        publication = self._settings()
        template = self.project / "local-template.xlsx"
        template.write_bytes(literal_xlsx())
        self._cycle(activity=True, derivation=True, observed_peer="foreign-z")
        self._cycle(activity=True, derivation=True, observed_peer="changed-peer")
        with tracker_writer(self.project, publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="active-key-k-two",
                  expected_revision=0)
            settings = current_k(token)
            snapshot = read_whitelist_workbook(template)
            arguments = dict(http_root=self.root, settings=settings,
                             whitelist_snapshot=snapshot, whitelist_path=template,
                             writer_token=token)
            per_value = read_prod_eth_activity_k_window(self.store, **arguments)
            self.assertEqual((), per_value.persistent_links)
            window = read_prod_eth_activity_k_window(
                self.store, normalized_active_keys=True, **arguments)
            self.assertEqual(1, len(window.persistent_links))
            self.assertEqual("changed-peer",
                             window.persistent_links[0].observation_a.remote_host)
            self.assertIs(window.normalized_active_keys, True)
            self.assertFalse(window.qualified)
            self.assertEqual(window, validate_prod_eth_activity_k_window(
                window, self.store, **arguments))
            template.write_bytes(literal_xlsx(rules=("leaf-z",)))
            with self.assertRaises(SwitchRuntimeHoldError):
                validate_prod_eth_activity_k_window(window, self.store, **arguments)
            filtered = read_prod_eth_activity_k_window(
                self.store, normalized_active_keys=True, **{
                    **arguments, "whitelist_snapshot": read_whitelist_workbook(template)})
            self.assertEqual((), filtered.persistent_links)
            self.assertEqual((("leaf-a", "swp1", "leaf-z", "swp2"),),
                             filtered.whitelist_skips)
        self.assertEqual((), tuple(publication.iterdir()))

    def test_real_two_cycles_same_key_changed_peer_is_two_of_three(self):
        publication = self._settings()
        first, _ = self._cycle(activity=True, derivation=True,
                               observed_peer="foreign-z")
        second, _ = self._cycle(activity=True, derivation=True,
                                observed_peer="changed-peer")
        SOURCE = source(self)
        with tracker_writer(self.project, publication) as token:
            settings = current_k(token)
            status = SOURCE.read_prod_eth_per_key_source(
                self.store, http_root=self.root, settings=settings,
                key=KEY, writer_token=token,
            )
        self.assertEqual((first["cycle_id"], second["cycle_id"]),
                         status.cycle_ids)
        self.assertEqual(("pending", 2, 3),
                         (status.state, status.observed, status.required))
        self.assertFalse(status.qualified)

    def test_missing_fourth_role_or_sha_drift_holds(self):
        publication = self._settings()
        self._cycle(activity=True, derivation=True)
        _second, artifacts = self._cycle(activity=True, derivation=True)
        private = artifacts["ethernet/prod"]["activity"]
        private.write_bytes(private.read_bytes() + b"late drift")
        SOURCE = source(self)
        with tracker_writer(self.project, publication) as token:
            settings = current_k(token)
            with self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.read_prod_eth_per_key_source(
                    self.store, http_root=self.root, settings=settings,
                    key=KEY, writer_token=token,
                )

    def test_missing_eth_fourth_role_is_not_an_empty_observation(self):
        publication = self._settings()
        self._cycle(activity=True, derivation=True)
        self._cycle(activity=False)
        SOURCE = source(self)
        with tracker_writer(self.project, publication) as token:
            settings = current_k(token)
            with self.assertRaises(SOURCE.PerKeySourceHold):
                SOURCE.read_prod_eth_per_key_source(
                    self.store, http_root=self.root, settings=settings,
                    key=KEY, writer_token=token,
                )


if __name__ == "__main__":
    unittest.main()
