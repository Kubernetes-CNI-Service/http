#!/usr/bin/env python3
"""Workflow contracts joining attribution cache, admission and report selection."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.test_ztp_collection_attribution import device, load_monitor, record


ROOT = Path(__file__).resolve().parents[1]


def load_html():
    path = ROOT / "monitor/generate-monitor-html.py"
    spec = importlib.util.spec_from_file_location("ztp_attribution_workflow_html", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    return module


class CollectionAttributionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_monitor()
        cls.html = load_html()

    def test_reconciled_shared_address_crosses_real_report_and_html_boundary(self):
        """A fresh device identity, never an old cache row, owns collection/UI."""
        address = "192.0.2.60"
        initial_csv = (
            "hostname,type,template,eth0_ip,eth0_mac\n"
            "leaf-a,eth,leaf,192.0.2.60,02:00:00:00:00:11\n"
            "leaf-b,eth,leaf,192.0.2.60,02:00:00:00:00:12\n"
            "removed-leaf,eth,leaf,192.0.2.61,02:00:00:00:00:13\n"
        )
        current_csv = initial_csv.replace(
            "removed-leaf,eth,leaf,192.0.2.61,02:00:00:00:00:13\n", "",
        )
        cases = (
            ("current-holder", "leaf-b", "02:00:00:00:00:12", ["leaf-b"]),
            ("split-identity", "leaf-a", "02:00:00:00:00:12", []),
        )
        for label, observed_hostname, observed_mac, expected_collected in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inventory = root / "02-devices_config.csv"
                inventory.write_text(initial_csv, encoding="utf-8")
                old_rows = self.monitor.read_devices(inventory, dhcp_leases=None)
                old_by_name = {item["hostname"]: item for item in old_rows}
                old_digests = self.monitor.collection_attribution_input_digests(
                    {"devices_csv": inventory},
                )
                status_root = root / "ztp-status"
                status_root.mkdir()
                sidecar = status_root / self.monitor.COLLECTION_ATTRIBUTION_STATE_NAME
                self.monitor.persist_collection_attribution(
                    sidecar, old_digests,
                    [record(self.monitor, old_by_name["leaf-a"]),
                     record(self.monitor, old_by_name["removed-leaf"])],
                )

                inventory.write_text(current_csv, encoding="utf-8")
                rows = self.monitor.read_devices(inventory, dhcp_leases=None)
                current_digests = self.monitor.collection_attribution_input_digests(
                    {"devices_csv": inventory},
                )
                self.assertNotEqual(old_digests, current_digests)
                reconciliation = {}
                cached = self.monitor.load_collection_attribution(
                    sidecar, rows, current_digests, status=reconciliation,
                )
                self.assertEqual("reconciled", reconciliation["reason"])
                self.assertEqual(2, reconciliation["records_seen"])
                self.assertEqual(1, reconciliation["records_retained"])
                self.assertEqual("leaf-a", cached[0]["input_row_identity"]["hostname"])
                selected = self.monitor.devices_for_switch_collection(
                    rows, {}, attribution_records=cached,
                )
                self.assertEqual([], selected, "old cache cannot select a shared holder")

                commands = []

                def fake_ssh(command, timeout):
                    commands.append(tuple(command))
                    self.assertEqual(f"cumulus@{address}", command[-2])
                    self.assertTrue(command[-1].startswith("sh -c "))
                    self.assertIn("__HOSTNAME_BEGIN__", command[-1])
                    self.assertIn("__INTERFACE_MACS_BEGIN__", command[-1])
                    if "__ZTP_LOG_BEGIN__" not in command[-1]:
                        return {
                            "returncode": 0,
                            "stdout": (
                                "__HOSTNAME_BEGIN__\n" + observed_hostname
                                + "\n__HOSTNAME_END__\n"
                                "__INTERFACE_MACS_BEGIN__\neth0=" + observed_mac
                                + "\n__INTERFACE_MACS_END__\n"
                            ),
                            "stderr": "",
                        }
                    self.assertEqual(
                        ["leaf-b"],
                        [item["hostname"] for item in selected],
                        "only the exact holder may reach the full collector",
                    )
                    return {"returncode": 0, "stdout": "", "stderr": ""}

                with mock.patch.object(self.monitor, "run_command", side_effect=fake_ssh):
                    selected, new_records, attempts = (
                        self.monitor.resolve_shared_address_attributions(
                            rows, selected,
                            lambda candidate_address, candidates:
                                self.monitor.probe_shared_address_identity(
                                    candidate_address, candidates, 5, None,
                                    root / "known_hosts",
                                ),
                        )
                    )
                    collected = {
                        item["hostname"]: self.monitor.collect_switch(
                            item, 5, None, root / "known_hosts",
                        )
                        for item in selected
                    }
                self.assertEqual(expected_collected, list(collected))
                self.assertEqual(1 + len(expected_collected), len(commands))
                self.assertNotIn("__ZTP_LOG_BEGIN__", commands[0][-1])
                if expected_collected:
                    self.assertIn("__ZTP_LOG_BEGIN__", commands[1][-1])
                self.assertEqual(
                    "matched" if expected_collected else "identity_mismatch",
                    attempts[address]["status"],
                )
                self.assertEqual(expected_collected, [
                    item["input_row_identity"]["hostname"] for item in new_records
                ])
                self.monitor.persist_collection_attribution(
                    sidecar, current_digests, new_records,
                )
                persisted = self.monitor.load_collection_attribution(
                    sidecar, rows, current_digests,
                )
                self.assertEqual(expected_collected, [
                    item["input_row_identity"]["hostname"] for item in persisted
                ])

                for item in rows:
                    item["overall"] = "pending"
                    item["progress"] = {"percent": 0}
                report = {
                    "project": "synthetic-site", "scope": "prod",
                    "generated_at": "2026-09-20T08:10:00+00:00",
                    "devices": rows,
                }
                run_dir = self.monitor.write_report(report, status_root, collected)
                on_disk = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
                self.assertEqual({"leaf-a", "leaf-b"}, {
                    item["hostname"] for item in on_disk["devices"]
                })
                for hostname in ("leaf-a", "leaf-b"):
                    raw = run_dir / "raw/switches" / hostname
                    self.assertEqual(hostname in expected_collected, raw.exists())

                loaded = self.html.load_ztp_status(
                    status_root, inventory=inventory, scope="prod",
                )
                self.assertTrue(loaded["available"])
                by_name = {item["hostname"]: item for item in loaded["devices"]}
                self.assertEqual({"leaf-a", "leaf-b"}, set(by_name))
                self.assertEqual(expected_collected, [
                    item["hostname"] for item in loaded["devices"]
                    if item["collection_admission"]["eligible"]
                ])
                html = self.html.render_ztp_status_rows(loaded)
                for hostname in ("leaf-a", "leaf-b"):
                    row = html.split(f'data-hostname="{hostname}"', 1)[1].split(
                        "</tr>", 1,
                    )[0]
                    self.assertEqual(
                        hostname not in expected_collected,
                        "当前身份归属证据不足" in row,
                    )

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
