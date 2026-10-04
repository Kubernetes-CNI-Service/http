#!/usr/bin/env python3
"""Direct contracts for REQ-11 shared-address attribution persistence."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
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

    def test_air_scope_probes_full_inventory_but_only_admits_air_identity(self):
        address = "192.0.2.110"
        primary = "192.0.2.109"
        prod = device("prod-leaf-10", "0200000000a1", primary)
        air = device("air-leaf-10", "0200000000b1", primary)
        for row in (prod, air):
            row["ssh_ips"].append(address)
            row["candidate_identity"][address] = ("eth0", row["mac_plain"])
        selected = self.monitor.devices_for_switch_collection(
            [air], {primary: air}, identity_devices=[prod, air],
        )
        self.assertEqual([air], selected)
        calls = []

        def probe(candidate_address, candidates):
            calls.append((candidate_address, tuple(row["hostname"] for row in candidates)))
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": candidate_address,
                "observation_time": "2026-09-20T08:00:00+00:00",
                "observed_identity": {
                    "hostname": "air-leaf-10.example.test",
                    "interface_macs": {"eth0": "02:00:00:00:00:b1"},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            [air], selected, probe, identity_devices=[prod, air],
        )
        self.assertEqual([(address, ("prod-leaf-10", "air-leaf-10"))], calls)
        self.assertEqual([air], selected)
        self.assertEqual(1, len(records))
        self.assertEqual("air-leaf-10", records[0]["input_row_identity"]["hostname"])
        self.assertEqual("matched", attempts[address]["status"])
        verdict = next(
            item for item in air["collection_admission"]["addresses"]
            if item["address"] == address
        )
        self.assertTrue(verdict["eligible"])
        self.assertEqual("matched", verdict["paths"]["posthoc_identity"]["status"])
        self.assertNotIn("collection_admission", prod)

    def test_air_scope_never_selects_prod_or_unverified_shared_address(self):
        address = "192.0.2.111"
        prod = device("prod-leaf-11", "0200000000a2", address)
        air = device("air-leaf-11", "0200000000b2", "192.0.2.112")
        air["ssh_ips"].append(address)
        air["candidate_identity"][address] = ("eth0", air["mac_plain"])
        cases = (
            ("prod", "prod-leaf-11", "02:00:00:00:00:a2", "out_of_scope_identity"),
            ("wrong_mac", "air-leaf-11", "02:00:00:00:00:a2", "identity_mismatch"),
            ("probe_failed", "", "", "probe_failed"),
        )
        for label, hostname, mac, expected_attempt in cases:
            with self.subTest(label=label):
                selected = self.monitor.devices_for_switch_collection(
                    [air], {}, identity_devices=[prod, air],
                )
                self.assertEqual([air], selected)

                def probe(candidate_address, candidates):
                    return {
                        "status": "probe_failed" if label == "probe_failed" else "success",
                        "source": "ssh-posthoc", "source_kind": "device_reported",
                        "address": candidate_address,
                        "observation_time": "2026-09-20T08:00:00+00:00",
                        "observed_identity": (
                            {"hostname": hostname, "interface_macs": {"eth0": mac}}
                            if hostname else None
                        ),
                    }

                selected, records, attempts = self.monitor.resolve_shared_address_attributions(
                    [air], selected, probe, identity_devices=[prod, air],
                )
                self.assertEqual([air], selected)
                self.assertEqual([], records)
                self.assertEqual(expected_attempt, attempts[address]["status"])
                self.assertTrue(air["collection_admission"]["eligible"])
                verdict = next(
                    item for item in air["collection_admission"]["addresses"]
                    if item["address"] == address
                )
                self.assertFalse(verdict["eligible"])
                self.assertNotIn("collection_admission", prod)

    def test_prod_scope_never_selects_air_identity_at_shared_address(self):
        alternate = "198.51.100.111"
        prod = device("prod-leaf-scope", "0200000000a6", "192.0.2.117")
        air = device("air-leaf-scope", "0200000000b6", alternate)
        prod["ssh_ips"].append(alternate)
        prod["candidate_identity"][alternate] = ("eth0", prod["mac_plain"])
        selected = self.monitor.devices_for_switch_collection(
            [prod], {}, identity_devices=[prod, air],
        )
        self.assertEqual([prod], selected)

        def probe(address, candidates):
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": address,
                "observation_time": "2026-09-30T12:05:00+00:00",
                "observed_identity": {
                    "hostname": air["hostname"],
                    "interface_macs": {"eth0": air["mac_plain"]},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            [prod], selected, probe, identity_devices=[prod, air],
        )
        self.assertEqual([prod], selected)
        self.assertEqual([], records)
        self.assertEqual("out_of_scope_identity", attempts[alternate]["status"])
        verdict = next(
            item for item in prod["collection_admission"]["addresses"]
            if item["address"] == alternate
        )
        self.assertFalse(verdict["eligible"])
        self.assertNotIn("collection_admission", air)

    def test_air_scope_does_not_probe_unselected_cross_environment_inventory(self):
        rows = []
        air_rows = []
        for index in range(40):
            address = f"192.0.2.{100 + index}"
            prod = device(f"prod-{index}", f"02000001{index:04x}", address)
            air = device(f"air-{index}", f"02000002{index:04x}", address)
            rows.extend((prod, air))
            air_rows.append(air)
        selected = self.monitor.devices_for_switch_collection(
            air_rows, {}, identity_devices=rows,
        )
        self.assertEqual([], selected)
        calls = []

        def probe(address, candidates):
            calls.append(address)
            raise AssertionError("unselected AIR inventory must not cause SSH probes")

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            air_rows, selected, probe, identity_devices=rows,
        )
        self.assertEqual([], calls)
        self.assertEqual([], selected)
        self.assertEqual([], records)
        self.assertEqual({}, attempts)

    def test_cached_air_vlan_binding_triggers_fresh_probe_without_current_dhcp_owner(self):
        primary = "192.0.2.115"
        vlan_address = "192.0.2.116"
        prod = device("prod-leaf-15", "0200000000a5", primary)
        air = device("air-leaf-15", "0200000000b5", primary)
        for row in (prod, air):
            row["ssh_ips"].append(vlan_address)
            row["candidate_identity"][vlan_address] = ("eth0", row["mac_plain"])
        cached = record(self.monitor, air)
        cached["address"] = vlan_address
        selected = self.monitor.devices_for_switch_collection(
            [air], {}, identity_devices=[prod, air],
            attribution_records=[cached],
        )
        self.assertEqual([], selected)  # the cache is not current admission evidence
        calls = []

        def probe(address, candidates):
            calls.append(address)
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": address,
                "observation_time": "2026-09-30T12:05:00+00:00",
                "observed_identity": {
                    "hostname": air["hostname"],
                    "interface_macs": {"eth0": air["mac_plain"]},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            [air], selected, probe, identity_devices=[prod, air],
        )
        self.assertEqual([vlan_address], calls)
        self.assertEqual([air], selected)
        self.assertEqual("matched", attempts[vlan_address]["status"])
        self.assertEqual([vlan_address], [entry["address"] for entry in records])

    def test_cross_scope_probe_budget_defers_unverified_addresses_fail_closed(self):
        full = []
        scoped = []
        for index in range(40):
            primary = f"192.0.2.{index + 10}"
            alternate = f"198.51.100.{index + 10}"
            prod = device(f"prod-budget-{index}", f"02000003{index:04x}", alternate)
            air = device(f"air-budget-{index}", f"02000004{index:04x}", primary)
            air["ssh_ips"].append(alternate)
            air["candidate_identity"][alternate] = ("eth0", air["mac_plain"])
            full.extend((prod, air))
            scoped.append(air)
        selected = self.monitor.devices_for_switch_collection(
            scoped, {}, identity_devices=full,
        )
        self.assertEqual(scoped, selected)
        calls = []

        def probe(address, candidates):
            calls.append(address)
            observed = next(row for row in candidates if row["hostname"].startswith("air-"))
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": address,
                "observation_time": "2026-09-30T12:05:00+00:00",
                "observed_identity": {
                    "hostname": observed["hostname"],
                    "interface_macs": {"eth0": observed["mac_plain"]},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            scoped, selected, probe, identity_devices=full,
        )
        self.assertEqual(32, len(calls))
        self.assertEqual(32, len(set(calls)))
        self.assertEqual(scoped, selected)
        self.assertEqual(32, len(records))
        deferred = {
            address for address, detail in attempts.items()
            if detail["status"] == "probe_budget_deferred"
        }
        self.assertEqual(8, len(deferred))
        for row in scoped:
            alternate = row["ssh_ips"][1]
            verdict = next(
                item for item in row["collection_admission"]["addresses"]
                if item["address"] == alternate
            )
            self.assertEqual(alternate not in deferred, verdict["eligible"])

    def test_admitted_eth0_does_not_suppress_shared_vlan_identity_probe(self):
        vlan_address = "192.0.2.113"
        prod = device("prod-leaf-13", "0200000000a3", vlan_address)
        air = device("air-leaf-13", "0200000000b3", "192.0.2.112")
        air["ssh_ips"].append(vlan_address)
        air["candidate_identity"][vlan_address] = ("eth0", air["mac_plain"])
        selected = self.monitor.devices_for_switch_collection(
            [air], {}, identity_devices=[prod, air],
        )
        self.assertEqual([air], selected)  # eth0 address is unique
        before = {
            verdict["address"]: verdict
            for verdict in air["collection_admission"]["addresses"]
        }
        self.assertFalse(before[vlan_address]["eligible"])
        calls = []

        def probe(address, candidates):
            calls.append(address)
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": address,
                "observation_time": "2026-09-20T08:00:00+00:00",
                "observed_identity": {
                    "hostname": air["hostname"],
                    "interface_macs": {"eth0": air["mac_plain"]},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            [air], selected, probe, identity_devices=[prod, air],
        )
        self.assertEqual([vlan_address], calls)
        self.assertEqual([air], selected)
        self.assertEqual("matched", attempts[vlan_address]["status"])
        self.assertEqual([vlan_address], [row["address"] for row in records])
        after = {
            verdict["address"]: verdict
            for verdict in air["collection_admission"]["addresses"]
        }
        self.assertTrue(after[vlan_address]["eligible"])

    def test_disabled_air_row_cannot_be_admitted_by_posthoc_probe(self):
        address = "192.0.2.114"
        prod = device("prod-leaf-14", "0200000000a4", address)
        air = device("air-leaf-14", "0200000000b4", address)
        air["ssh_collect_enabled"] = False
        selected = self.monitor.devices_for_switch_collection(
            [air], {}, identity_devices=[prod, air],
        )

        def probe(candidate_address, candidates):
            return {
                "status": "success", "source": "ssh-posthoc",
                "source_kind": "device_reported", "address": candidate_address,
                "observation_time": "2026-09-20T08:00:00+00:00",
                "observed_identity": {
                    "hostname": air["hostname"],
                    "interface_macs": {"eth0": air["mac_plain"]},
                },
            }

        selected, records, _attempts = self.monitor.resolve_shared_address_attributions(
            [air], selected, probe, identity_devices=[prod, air],
        )
        self.assertEqual([], selected)
        self.assertEqual([], records)
        self.assertFalse(air["collection_admission"]["eligible"])
        self.assertFalse(air["collection_admission"]["addresses"][0]["eligible"])

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

    def test_newer_cached_evidence_requires_current_probe_before_outranking_owner(self):
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
        self.assertEqual([], selected)
        self.assertEqual(
            "verification_required",
            air["collection_admission"]["addresses"][0]["paths"]
            ["posthoc_identity"]["status"],
        )

        calls = []

        def current_probe(candidate_address, candidates):
            calls.append(candidate_address)
            return {
                "status": "success",
                "source": "ssh-posthoc",
                "source_kind": "device_reported",
                "address": candidate_address,
                "observation_time": "2026-09-20T08:15:00+00:00",
                "observed_identity": {
                    "hostname": air["hostname"],
                    "interface_macs": {"eth0": air["mac_plain"]},
                },
            }

        selected, records, attempts = self.monitor.resolve_shared_address_attributions(
            [prod, air], selected, current_probe,
        )
        self.assertEqual([address], calls)
        self.assertEqual([air], selected)
        self.assertEqual(1, len(records))
        self.assertEqual("matched", attempts[address]["status"])

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

    def test_any_ledger_integrity_failure_discards_the_whole_cache(self):
        first = device("leaf-13", "020000000091", "192.0.2.91")
        second = device("leaf-14", "020000000092", "192.0.2.92")
        digests = {"inventory.csv": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            malformed_payloads = [
                b"{not-json\n",
                json.dumps({
                    "schema_version": 999,
                    "input_digests": digests,
                    "records": [],
                }).encode("utf-8"),
                json.dumps({
                    "schema_version": 1,
                    "input_digests": digests,
                    "records": [
                        record(self.monitor, first),
                        record(self.monitor, first),
                        record(self.monitor, second),
                    ],
                }).encode("utf-8"),
            ]
            for payload in malformed_payloads:
                with self.subTest(payload=payload[:24]):
                    state.write_bytes(payload)
                    self.assertEqual(
                        [],
                        self.monitor.load_collection_attribution(
                            state, [first, second], digests,
                        ),
                    )

    def test_cache_discard_status_distinguishes_capacity_and_integrity_reasons(self):
        row = device("leaf-status", "020000000093", "192.0.2.93")
        digests = {"inventory.csv": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            cases = (
                ("absent", None),
                ("schema_mismatch", json.dumps({
                    "schema_version": 999,
                    "input_digests": digests,
                    "records": [],
                }).encode("utf-8")),
                ("corrupt", b"{not-json\n"),
                (
                    "over_capacity",
                    b" " * (self.monitor.MAX_COLLECTION_ATTRIBUTION_BYTES + 1),
                ),
            )
            for expected_reason, payload in cases:
                with self.subTest(reason=expected_reason):
                    state.unlink(missing_ok=True)
                    if payload is not None:
                        state.write_bytes(payload)
                    status = {}
                    self.assertEqual(
                        [],
                        self.monitor.load_collection_attribution(
                            state, [row], digests, status=status,
                        ),
                    )
                    self.assertEqual("discarded", status["status"])
                    self.assertEqual(expected_reason, status["reason"])
                    self.assertIn("message", status)
            target = Path(directory) / "target.json"
            target.write_text("{}", encoding="utf-8")
            state.unlink(missing_ok=True)
            state.symlink_to(target)
            status = {}
            self.assertEqual(
                [],
                self.monitor.load_collection_attribution(
                    state, [row], digests, status=status,
                ),
            )
            self.assertEqual("unreadable", status["reason"])

    def test_cache_status_reports_row_reconciliation_on_every_load(self):
        first = device("leaf-current", "020000000094", "192.0.2.94")
        removed = device("leaf-removed", "020000000095", "192.0.2.95")
        digests = {"inventory.csv": "a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "collection-attribution.json"
            self.monitor.persist_collection_attribution(
                state, digests,
                [record(self.monitor, first), record(self.monitor, removed)],
            )
            status = {}
            self.assertEqual(
                [self.monitor.validate_collection_attribution_record(
                    record(self.monitor, first)
                )],
                self.monitor.load_collection_attribution(
                    state, [first], digests, status=status,
                ),
            )
            self.assertEqual("loaded", status["status"])
            self.assertEqual("reconciled", status["reason"])
            self.assertEqual(2, status["records_seen"])
            self.assertEqual(1, status["records_retained"])

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
            # Set an explicit distinct timestamp: filesystems with coarse or
            # virtualized clocks need not advance after a short sleep.
            changed_mtime = before + 2_000_000_000
            os.utime(source, ns=(changed_mtime, changed_mtime))
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
            self.assertEqual(
                [],
                self.monitor.load_collection_attribution(
                    link, [row], {"inventory.csv": "a" * 64},
                ),
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
