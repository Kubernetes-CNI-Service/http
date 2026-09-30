#!/usr/bin/env python3
"""Workflow contracts joining attribution cache, admission and report selection."""

from __future__ import annotations

import csv
import datetime as dt
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_cases.test_ztp_collection_attribution import device, load_monitor, record


class CollectionAttributionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_monitor()

    def test_air_vlan_candidate_inherited_from_prod_requires_current_exact_identity(self):
        """Inventory -> AIR scope -> admission -> one identity probe, not ping."""
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "02-devices_config.csv"
            with inventory.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow([
                    "hostname", "type", "eth0_ip", "netmask", "eth0_mac",
                    "vlan_id", "svi_ip", "netmask",
                ])
                writer.writerow([
                    "prod-leaf10", "eth", "192.0.2.185", "23",
                    "02:00:00:00:00:11", "119", "192.0.2.250", "23",
                ])
                writer.writerow([
                    "AIR-lab05-leaf10", "air", "192.0.2.185", "23",
                    "02:00:00:00:00:12", "", "", "",
                ])
            full_inventory = self.monitor.read_devices(
                inventory, "all", air_json=None, dhcp_leases=None,
            )
            air = [row for row in full_inventory if row["type"] == "air"]
            self.assertEqual(1, len(air))
            self.assertEqual(
                ["192.0.2.185", "192.0.2.250"], air[0]["ssh_ips"],
            )
            self.assertEqual(
                ("eth0", "020000000012"),
                air[0]["candidate_identity"]["192.0.2.250"],
            )
            selected = self.monitor.devices_for_switch_collection(
                air, {"192.0.2.185": air[0]}, identity_devices=full_inventory,
            )
            self.assertEqual(air, selected)
            seen = []

            def probe(address, candidates):
                seen.append((address, tuple(row["hostname"] for row in candidates)))
                return {
                    "status": "success", "source": "ssh-posthoc",
                    "source_kind": "device_reported", "address": address,
                    "observation_time": "2026-09-30T12:03:08+00:00",
                    "observed_identity": {
                        "hostname": "AIR-lab05-leaf10",
                        "interface_macs": {
                            "eth0": "02:00:00:00:00:12",
                            "vlan119": "02:00:00:00:00:13",
                        },
                    },
                }

            selected, records, attempts = self.monitor.resolve_shared_address_attributions(
                air, selected, probe, identity_devices=full_inventory,
            )
            self.assertEqual(
                ["192.0.2.250"],
                [address for address, _ in seen],
            )
            self.assertTrue(all(len(candidates) == 2 for _, candidates in seen))
            self.assertEqual(air, selected)
            self.assertEqual("matched", attempts["192.0.2.250"]["status"])
            self.assertEqual("192.0.2.250", records[0]["address"])
            address_verdicts = {
                verdict["address"]: verdict
                for verdict in air[0]["collection_admission"]["addresses"]
            }
            self.assertTrue(address_verdicts["192.0.2.185"]["eligible"])
            self.assertTrue(address_verdicts["192.0.2.250"]["eligible"])
            self.assertEqual(
                "matched",
                address_verdicts["192.0.2.250"]["paths"]["posthoc_identity"]["status"],
            )
            self.assertNotIn("collection_admission", full_inventory[0])

    def test_budget_deferred_cached_bindings_survive_for_next_cycle_reverification(self):
        full = []
        scoped = []
        cached = []
        for index in range(40):
            primary = f"192.0.2.{index + 10}"
            alternate = f"198.51.100.{index + 10}"
            prod = device(f"prod-cache-{index}", f"02000005{index:04x}", primary)
            air = device(f"air-cache-{index}", f"02000006{index:04x}", primary)
            for row in (prod, air):
                row["ssh_ips"].append(alternate)
                row["candidate_identity"][alternate] = ("eth0", row["mac_plain"])
            prior = record(self.monitor, air)
            prior["address"] = alternate
            full.extend((prod, air))
            scoped.append(air)
            cached.append(prior)

        selected = self.monitor.devices_for_switch_collection(
            scoped, {}, identity_devices=full, attribution_records=cached,
        )
        self.assertEqual([], selected)
        first_calls = []

        def first_probe(address, candidates):
            first_calls.append(address)
            return {
                "status": "probe_failed", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": address,
                "observed_identity": None,
            }

        first_minute = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)
        with patch.object(self.monitor, "now_local", return_value=first_minute):
            selected, new_records, attempts = self.monitor.resolve_shared_address_attributions(
                scoped, selected, first_probe, identity_devices=full,
            )
        self.assertEqual([], selected)
        self.assertEqual([], new_records)
        self.assertEqual(32, len(first_calls))
        deferred = {
            address for address, result in attempts.items()
            if result["status"] == "probe_budget_deferred"
        }
        self.assertEqual(8, len(deferred))
        retained = self.monitor.current_collection_attributions(
            scoped, cached, new_records, attempts,
        )
        self.assertEqual(deferred, {entry["address"] for entry in retained})
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            digests = {"inventory.csv": "a" * 64}
            self.monitor.persist_collection_attribution(state, digests, retained)
            loaded = self.monitor.load_collection_attribution(state, full, digests)
        self.assertEqual(deferred, {entry["address"] for entry in loaded})

        selected = self.monitor.devices_for_switch_collection(
            scoped, {}, identity_devices=full, attribution_records=loaded,
        )
        second_calls = []

        def second_probe(address, candidates):
            second_calls.append(address)
            row = next(item for item in candidates if item["type"] == "eth" and
                       item["hostname"].startswith("air-"))
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": address,
                "observation_time": "2026-09-30T12:01:00+00:00",
                "observed_identity": {
                    "hostname": row["hostname"],
                    "interface_macs": {"eth0": row["mac_plain"]},
                },
            }

        with patch.object(
            self.monitor, "now_local", return_value=first_minute + dt.timedelta(minutes=1),
        ):
            selected, second_records, _attempts = self.monitor.resolve_shared_address_attributions(
                scoped, selected, second_probe, identity_devices=full,
            )
        self.assertEqual(deferred, set(second_calls))
        self.assertEqual(deferred, {entry["address"] for entry in second_records})
        self.assertEqual(8, len(selected))

    def test_verified_cache_still_requires_current_exact_observation(self):
        address = "192.0.2.60"
        prod = device("prod-leaf-06", "020000000051", address)
        air = device("air-leaf-06", "020000000052", address)
        stale_other = device("removed-leaf", "020000000053", "192.0.2.61")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64},
                [record(self.monitor, air), record(self.monitor, stale_other)],
            )
            reconciled = self.monitor.load_collection_attribution(
                state, [prod, air], {"inventory.csv": "b" * 64},
            )
            selected = self.monitor.devices_for_switch_collection(
                [prod, air], {}, attribution_records=reconciled,
            )
            self.assertEqual([], selected)

            def probe(candidate_address, candidates):
                return {
                    "status": "success", "source": "ssh-posthoc",
                    "source_kind": "device_reported",
                    "address": candidate_address,
                    "observation_time": "2026-09-20T08:05:00+00:00",
                    "observed_identity": {
                        "hostname": air["hostname"],
                        "interface_macs": {"eth0": air["mac_plain"]},
                    },
                }

            selected, current_records, attempts = (
                self.monitor.resolve_shared_address_attributions(
                    [prod, air], selected, probe,
                )
            )
        self.assertEqual([air], selected)
        self.assertEqual(1, len(current_records))
        self.assertEqual("matched", attempts[address]["status"])
        self.assertFalse(prod["collection_admission"]["eligible"])
        self.assertTrue(air["collection_admission"]["eligible"])
        path = air["collection_admission"]["addresses"][0]["paths"]["posthoc_identity"]
        self.assertEqual("matched", path["status"])
        self.assertEqual("device_reported", path["source_kind"])
        self.assertEqual("ssh-posthoc", path["source"])

    def test_project_symlink_switch_never_reuses_previous_project_binding(self):
        first = device("project-a-leaf", "0200000000a1", "192.0.2.101")
        second = device("project-b-leaf", "0200000000b1", "192.0.2.101")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_a = root / "project-a-output"
            project_b = root / "project-b-output"
            project_a.mkdir()
            project_b.mkdir()
            status = root / "status"
            status.symlink_to(project_a, target_is_directory=True)
            state = status / ".collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64},
                [record(self.monitor, first)],
            )
            (project_b / state.name).write_bytes(
                (project_a / state.name).read_bytes()
            )
            status.unlink()
            status.symlink_to(project_b, target_is_directory=True)
            self.assertEqual(
                [],
                self.monitor.load_collection_attribution(
                    status / state.name, [second],
                    {"inventory.csv": "b" * 64},
                ),
            )

    def test_failed_probe_is_visible_but_cannot_cross_write_another_row(self):
        address = "192.0.2.70"
        rows = [
            device("prod-leaf-07", "020000000061", address),
            device("air-leaf-07", "020000000062", address),
        ]
        selected = self.monitor.devices_for_switch_collection(rows, {})
        calls = 0

        def failed_probe(candidate_address, candidates):
            nonlocal calls
            calls += 1
            return {
                "status": "probe_failed",
                "source": "ssh-posthoc",
                "source_kind": "device_reported",
                "address": candidate_address,
                "observation_time": "2026-09-20T08:02:00+00:00",
                "observed_identity": None,
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            rows, selected, failed_probe,
        )
        self.assertEqual(1, calls)
        self.assertEqual([], selected)
        self.assertEqual([], records)
        self.assertEqual("probe_failed", attempts[address]["status"])
        for row in rows:
            verdict = row["collection_admission"]["addresses"][0]
            self.assertFalse(verdict["eligible"])
            self.assertEqual("probe_failed", verdict["paths"]["posthoc_identity"]["status"])

    def test_cache_discard_reason_is_visible_in_cycle_report_warning(self):
        status = {
            "status": "discarded",
            "reason": "over_capacity",
            "message": "归属缓存超过容量上限，已整库丢弃",
        }
        warning = self.monitor.collection_attribution_status_warning(status)
        self.assertIn("over_capacity", warning)
        self.assertIn("容量", warning)
        report = {
            "project": "example", "generated_at": "now",
            "release_id": "0123456789abcdefabcd",
            "release_generated_at": "then", "since_minutes": 60,
            "services": {}, "devices": [], "unmatched_interactions": [],
            "collection_errors": [warning],
        }
        rendered = self.monitor.render_markdown(report)
        self.assertIn("采集警告", rendered)
        self.assertIn("over_capacity", rendered)


if __name__ == "__main__":
    unittest.main()
