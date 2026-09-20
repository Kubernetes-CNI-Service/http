#!/usr/bin/env python3
"""Direct contracts for REQ-11 shared-address attribution persistence."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_monitor():
    path = ROOT / "DAY0-Prepare/12-ztp-monitor.py"
    spec = importlib.util.spec_from_file_location("ztp_collection_attribution", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def device(hostname: str, mac: str, address: str) -> dict:
    return {
        "hostname": hostname,
        "type": "eth",
        "ip": address,
        "ssh_ips": [address],
        "ssh_user": "admin",
        "mac_plain": mac,
        "identity_macs": {"eth0": mac},
        "candidate_identity": {address: ("eth0", mac)},
    }


def record(monitor, row: dict, *, source: str = "ssh-posthoc") -> dict:
    return {
        "schema_version": 1,
        "address": row["ip"],
        "source": source,
        "source_kind": "device_reported",
        "provisioning_relationship": "unknown",
        "observed_identity": {
            "hostname": row["hostname"],
            "interface_macs": {"eth0": row["mac_plain"]},
        },
        "input_row_identity": monitor.collection_row_identity(row),
        "observation_time": "2026-09-20T08:00:00+00:00",
    }


class CollectionAttributionDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_monitor()

    def test_shared_address_probe_runs_once_and_selects_exactly_one_row(self):
        address = "192.0.2.10"
        prod = device("prod-leaf-01", "020000000001", address)
        air = device("air-leaf-01", "020000000002", address)
        rows = [prod, air]
        selected = self.monitor.devices_for_switch_collection(rows, {})
        self.assertEqual([], selected)
        calls = []

        def probe(candidate_address, candidates):
            calls.append((candidate_address, tuple(row["hostname"] for row in candidates)))
            return {
                "status": "success",
                "source": "ssh-posthoc",
                "source_kind": "device_reported",
                "address": candidate_address,
                "observation_time": "2026-09-20T08:00:00+00:00",
                "observed_identity": {
                    "hostname": "air-leaf-01.example.test",
                    "interface_macs": {"eth0": "02:00:00:00:00:02"},
                },
            }

        selected, new_records, attempts = (
            self.monitor.resolve_shared_address_attributions(rows, selected, probe)
        )
        self.assertEqual([(address, ("prod-leaf-01", "air-leaf-01"))], calls)
        self.assertEqual([air], selected)
        self.assertEqual(1, len(new_records))
        self.assertEqual("air-leaf-01", new_records[0]["input_row_identity"]["hostname"])
        self.assertEqual("matched", attempts[address]["status"])
        prod_path = prod["collection_admission"]["addresses"][0]["paths"]["posthoc_identity"]
        air_path = air["collection_admission"]["addresses"][0]["paths"]["posthoc_identity"]
        self.assertEqual("conflict", prod_path["status"])
        self.assertEqual("matched", air_path["status"])
        self.assertFalse(prod["collection_admission"]["eligible"])
        self.assertTrue(air["collection_admission"]["eligible"])

    def test_ambiguous_or_conflicting_observation_never_selects_or_persists(self):
        address = "192.0.2.20"
        first = device("leaf-01", "020000000011", address)
        second = device("leaf-02", "020000000012", address)
        rows = [first, second]
        selected = self.monitor.devices_for_switch_collection(rows, {})

        def conflicting_probe(candidate_address, candidates):
            return {
                "status": "success",
                "source": "synthetic-provider-A",
                "source_kind": "third_party_provider",
                "address": candidate_address,
                "observation_time": "2026-09-20T08:01:00+00:00",
                "observed_identity": {
                    "hostname": "leaf-01",
                    "interface_macs": {"eth0": second["mac_plain"]},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            rows, selected, conflicting_probe,
        )
        self.assertEqual([], selected)
        self.assertEqual([], records)
        self.assertEqual("identity_mismatch", attempts[address]["status"])
        for row in rows:
            verdict = row["collection_admission"]["addresses"][0]
            self.assertFalse(verdict["eligible"])
            self.assertEqual(
                "identity_mismatch", verdict["paths"]["posthoc_identity"]["status"],
            )

    def test_open_source_and_third_party_kind_round_trip_without_reclassification(self):
        row = device("leaf-03", "020000000021", "192.0.2.30")
        third_party = record(self.monitor, row, source="vendor-feed:alpha/v7")
        third_party["source_kind"] = "third_party_provider"
        third_party["provisioning_relationship"] = "external"
        normalized = self.monitor.validate_collection_attribution_record(third_party)
        self.assertEqual("vendor-feed:alpha/v7", normalized["source"])
        self.assertEqual("third_party_provider", normalized["source_kind"])
        self.assertEqual("external", normalized["provisioning_relationship"])

        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64}, [third_party],
            )
            loaded = self.monitor.load_collection_attribution(
                state, [row], {"inventory.csv": "a" * 64},
            )
        self.assertEqual([normalized], loaded)

    def test_input_digest_change_reconciles_per_row_instead_of_flushing_all(self):
        first = device("leaf-04", "020000000031", "192.0.2.40")
        second = device("leaf-05", "020000000032", "192.0.2.41")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64},
                [record(self.monitor, first), record(self.monitor, second)],
            )
            retained = self.monitor.load_collection_attribution(
                state, [first], {"inventory.csv": "b" * 64},
            )
        self.assertEqual(1, len(retained))
        self.assertEqual("leaf-04", retained[0]["input_row_identity"]["hostname"])

    def test_only_newer_exact_posthoc_evidence_outranks_local_ownership(self):
        address = "192.0.2.45"
        prod = device("prod-leaf-05", "020000000035", address)
        air = device("air-leaf-05", "020000000036", address)
        cached = record(self.monitor, air)
        cached["observation_time"] = "2026-09-20T08:10:00+00:00"
        prod["dhcp_owner_observation_times"] = {
            address: "2026-09-20T08:00:00+00:00",
        }
        selected = self.monitor.devices_for_switch_collection(
            [prod, air], {address: prod}, attribution_records=[cached],
        )
        self.assertEqual([air], selected)
        self.assertEqual(
            "matched",
            air["collection_admission"]["addresses"][0]["paths"]
            ["posthoc_identity"]["status"],
        )

        prod["dhcp_owner_observation_times"][address] = (
            "2026-09-20T08:20:00+00:00"
        )
        selected = self.monitor.devices_for_switch_collection(
            [prod, air], {address: prod}, attribution_records=[cached],
        )
        self.assertEqual([prod], selected)
        for row in (prod, air):
            self.assertEqual(
                "superseded",
                row["collection_admission"]["addresses"][0]["paths"]
                ["posthoc_identity"]["status"],
            )

    def test_atomic_private_state_replaces_previous_complete_document(self):
        row = device("leaf-06", "020000000041", "192.0.2.50")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64}, [record(self.monitor, row)],
            )
            first = state.read_bytes()
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "b" * 64}, [],
            )
            second = state.read_bytes()
            self.assertNotEqual(first, second)
            self.assertEqual(0o600, state.stat().st_mode & 0o777)
            payload = json.loads(second)
            self.assertEqual([], payload["records"])
            self.assertEqual({"inventory.csv": "b" * 64}, payload["input_digests"])
            leftovers = [
                item.name for item in state.parent.iterdir()
                if item.name.startswith(".collection-attribution.json.")
                and item.name != ".collection-attribution.json.lock"
            ]
            self.assertEqual([], leftovers)

    def test_record_rejects_invalid_address_time_and_closed_enums(self):
        row = device("leaf-07", "020000000051", "192.0.2.51")
        baseline = record(self.monitor, row)
        for field, invalid in (
            ("address", "not-an-ip"),
            ("observation_time", "yesterday"),
            ("source_kind", "invented_kind"),
            ("provisioning_relationship", "maybe"),
        ):
            candidate = dict(baseline)
            candidate[field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.monitor.validate_collection_attribution_record(candidate)

    def test_input_digest_is_content_bound_and_ignores_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "inventory.csv"
            source.write_bytes(b"same bytes\n")
            first = self.monitor.collection_attribution_input_digests({
                "inventory": source,
            })
            before = source.stat().st_mtime_ns
            time.sleep(0.002)
            os.utime(source, None)
            self.assertNotEqual(before, source.stat().st_mtime_ns)
            second = self.monitor.collection_attribution_input_digests({
                "inventory": source,
            })
            self.assertEqual(first, second)
            source.write_bytes(b"different bytes\n")
            third = self.monitor.collection_attribution_input_digests({
                "inventory": source,
            })
            self.assertNotEqual(first, third)

    def test_symlink_state_is_rejected_and_old_valid_evidence_does_not_expire(self):
        row = device("leaf-08", "020000000061", "192.0.2.61")
        old = record(self.monitor, row)
        old["observation_time"] = "2001-01-01T00:00:00+00:00"
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            state = directory_path / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64}, [old],
            )
            self.assertEqual(
                [self.monitor.validate_collection_attribution_record(old)],
                self.monitor.load_collection_attribution(
                    state, [row], {"inventory.csv": "a" * 64},
                ),
            )
            link = directory_path / "linked-state.json"
            link.symlink_to(state)
            with self.assertRaises((OSError, ValueError)):
                self.monitor.load_collection_attribution(
                    link, [row], {"inventory.csv": "a" * 64},
                )

    def test_duplicate_address_and_changed_row_identity_fail_closed(self):
        first = device("leaf-09", "020000000071", "192.0.2.71")
        second = device("leaf-10", "020000000072", "192.0.2.71")
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            with self.assertRaises(ValueError):
                self.monitor.persist_collection_attribution(
                    state, {"inventory.csv": "a" * 64},
                    [record(self.monitor, first), record(self.monitor, second)],
                )
            self.monitor.persist_collection_attribution(
                state, {"inventory.csv": "a" * 64},
                [record(self.monitor, first)],
            )
            changed = device("leaf-09", "020000000073", "192.0.2.71")
            self.assertEqual(
                [],
                self.monitor.load_collection_attribution(
                    state, [changed], {"inventory.csv": "b" * 64},
                ),
            )

    def test_probe_executes_one_identity_only_remote_command(self):
        address = "192.0.2.81"
        rows = [
            device("leaf-11", "020000000081", address),
            device("leaf-12", "020000000082", address),
        ]
        calls = []
        original = self.monitor.run_command

        def fake_run(command, timeout):
            calls.append((command, timeout))
            return {
                "returncode": 0,
                "stdout": (
                    "__HOSTNAME_BEGIN__\nleaf-12\n__HOSTNAME_END__\n"
                    "__INTERFACE_MACS_BEGIN__\n"
                    "eth0=02:00:00:00:00:82\n"
                    "__INTERFACE_MACS_END__\n"
                ),
                "stderr": "",
            }

        self.monitor.run_command = fake_run
        try:
            result = self.monitor.probe_shared_address_identity(
                address, rows, 5, None, Path("/tmp/known-hosts"),
            )
        finally:
            self.monitor.run_command = original
        self.assertEqual(1, len(calls))
        self.assertEqual("success", result["status"])
        self.assertEqual("leaf-12", result["observed_identity"]["hostname"])
        self.assertEqual(
            "020000000082",
            result["observed_identity"]["interface_macs"]["eth0"],
        )


if __name__ == "__main__":
    unittest.main()
