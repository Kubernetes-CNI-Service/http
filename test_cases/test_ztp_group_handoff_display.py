#!/usr/bin/env python3
"""Display and audit contracts for environment-scoped ZTP handoff."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


MONITOR = load_module(
    "ztp_group_handoff_display_monitor",
    ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
HTML = load_module(
    "ztp_group_handoff_display_html",
    ROOT / "monitor/generate-monitor-html.py",
)

EXPECTED_NINE_STAGES = (
    "dhcp", "bootstrap", "config_http", "ssh", "network", "version",
    "config_apply", "ssh_keys", "complete",
)


class CompletionDisplayParityTests(unittest.TestCase):
    def test_real_info_collector_classifies_health_without_any_ztp_completion_or_config_receipt(self):
        # Execute the complete production shell collector. Only hardware/system
        # commands are private fixtures; no device/network/service is touched.
        for kind, platform in (("eth", "SN5600"), ("ib", "Q3200"), ("nvl", "MNV72")):
            for health, badge in (("OK", "h-ok"), ("Not OK", "h-err"), ("", "h-unk")):
                with self.subTest(kind=kind, health=health), tempfile.TemporaryDirectory() as directory:
                    project = Path(directory)
                    commands, temporary = project / "bin", project / "tmp"
                    commands.mkdir()
                    temporary.mkdir()
                    hostname = commands / "hostname"
                    hostname.write_text("#!/bin/sh\nprintf 'Fixture-Switch01\\n'\n")
                    hostname.chmod(0o700)
                    nv = commands / "nv"
                    nv.write_text(
                        "#!/bin/sh\ncase \"$*\" in\n"
                        "  'show platform') printf 'system-type    %s\\n' \"$TEST_F02_PLATFORM\" ;;\n"
                        "  'show system health') if [ -n \"$TEST_F02_HEALTH\" ]; then printf 'status      %s\\n' \"$TEST_F02_HEALTH\"; fi ;;\n"
                        "  *) : ;;\nesac\n"
                    )
                    nv.chmod(0o700)
                    for name in ("timedatectl", "df", "free", "top", "uptime", "clagctl"):
                        path = commands / name
                        path.write_text("#!/bin/sh\nexit 0\n")
                        path.chmod(0o700)
                    environment = {**os.environ, "PATH": str(commands) + ":/usr/bin:/bin",
                                   "TMPDIR": str(temporary), "TEST_F02_PLATFORM": platform,
                                   "TEST_F02_HEALTH": health}
                    collected = subprocess.run(["/bin/bash", str(ROOT / "ethernet/monitor/sw-info.sh")], cwd=project,
                                               env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8)
                    self.assertEqual(0, collected.returncode, collected.stderr)
                    raw = (project / "monitor/Fixture-Switch01.info").read_text()
                    self.assertEqual(1, raw.count("# Execute Command: nv show system health"))
                    self.assertIn("# Collect complete", raw)
                    self.assertFalse((temporary / "sw-info.lock").exists())
                    self.assertEqual([], list(temporary.iterdir()), "collector must clean its own temporary/lock files")
                    info = HTML.parse_info_file("Fixture-Switch01", raw)
                    self.assertEqual(health.lower() if health else "unknown", info["health"], raw)
                    self.assertIn(f'h-badge {badge}', HTML.render_sw_list_row(info))
                    incomplete = {"hostname": "Fixture-Switch01", "type": kind, "ztp_round": 1,
                                  "config_method": "initial-setup" if kind == "ib" else "ztp",
                                  "issues": [], "stages": {name: MONITOR.stage() for name in EXPECTED_NINE_STAGES}}
                    MONITOR.finalize_device(incomplete)
                    self.assertEqual("pending", incomplete["overall"])
                    self.assertFalse(MONITOR.completion_handoff_device_complete(incomplete))
                    self.assertFalse(HTML.ztp_completed(incomplete))
                    self.assertFalse((project / "99-output-ztp").exists(), "health cannot mint a ZTP/config history")

    @staticmethod
    def complete_fixture():
        return {
            "hostname": "Leaf01", "type": "eth", "ztp_round": 1,
            "boot_id": "boot-Leaf01", "ip": "192.0.2.1",
            "mac": "00:11:22:33:44:55", "overall": "success",
            "progress": {"done": 9, "total": 9, "percent": 100},
            "issues": [],
            "stages": {
                name: {"status": "success", "detail": "independent receipt",
                       "timestamp": "2026-09-01T12:00:00+08:00",
                       "success_index": 1}
                for name in EXPECTED_NINE_STAGES
            },
        }

    def test_html_rejects_nonboolean_false_authority_vetoes(self):
        for flag in ("round_authority_invalid", "unbound_identity",
                     "identity_pending", "promotion_pending"):
            for value in (True, 0, "", None, [], {}):
                with self.subTest(flag=flag, value=value):
                    row = self.complete_fixture()
                    row[flag] = value
                    self.assertFalse(HTML.ztp_completed(row))
                    self.assertFalse(MONITOR.completion_handoff_device_complete(row))
            row = self.complete_fixture()
            row[flag] = False
            self.assertTrue(HTML.ztp_completed(row))
            self.assertTrue(MONITOR.completion_handoff_device_complete(row))

    def test_server_ufm_unknown_types_cannot_use_switch_completion_even_with_nine_successes(self):
        for kind in ("server", "ufm", "UFM", "server-ufm", "eth_jump", "future-switch", "", None):
            with self.subTest(kind=kind):
                row = self.complete_fixture()
                row["type"] = kind
                for consumer, predicate in (("machine", MONITOR.completion_handoff_device_complete), ("html", HTML.ztp_completed)):
                    with self.subTest(consumer=consumer):
                        self.assertFalse(predicate(row))
                MONITOR.finalize_device(row)
                self.assertNotEqual("success", row["overall"])
        # Independent declared supported switch families retain completion;
        # future types need reviewed inventory/executor contracts, not inference.
        for kind in ("eth", "eth_spx", "spx", "air", "ib", "nvl"):
            with self.subTest(supported=kind):
                row = self.complete_fixture()
                row["type"] = kind
                MONITOR.finalize_device(row)
                self.assertEqual("success", row["overall"])
                self.assertTrue(MONITOR.completion_handoff_device_complete(row))
                self.assertTrue(HTML.ztp_completed(row))

    def test_real_report_server_or_ufm_completion_claim_cannot_reach_machine_or_html_completion(self):
        for kind in ("server", "ufm"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                row = self.complete_fixture()
                row["type"] = kind
                report = {"project": "private-fixture", "scope": "prod", "devices": [row],
                          "generated_at": "2026-09-01T12:00:00+08:00", "since_minutes": 10,
                          "services": {}, "collection_errors": []}
                snapshot = MONITOR.write_report(report, Path(directory), {})
                saved = json.loads((snapshot / "report.json").read_text())["devices"][0]
                self.assertFalse(MONITOR.completion_handoff_device_complete(saved))
                self.assertFalse(HTML.ztp_completed(saved))
                self.assertEqual({}, MONITOR.ready_completion_handoff_reports(report))

    def test_finalized_second_round_unknown_time_cannot_publish_overall_success(self):
        invalid_times = ("", "not-a-time", "2026-09-01T12:00:00", None, True,
                         "2026-09-01T10:00:00+08:00")
        for name in EXPECTED_NINE_STAGES:
            for invalid in invalid_times:
                with self.subTest(stage=name, timestamp=invalid):
                    row = self.complete_fixture()
                    row.update(ztp_round=2, cycle_started_at="2026-09-01T11:59:00+08:00")
                    for value in row["stages"].values():
                        value["success_index"] = 2
                    row["stages"][name]["timestamp"] = invalid
                    MONITOR.finalize_device(row)
                    self.assertNotEqual("success", row["overall"], "overall must obey the same current nine-stage proof")
                    self.assertFalse(MONITOR.completion_handoff_device_complete(row))
                    self.assertFalse(HTML.ztp_completed(row))

    def test_real_report_unknown_second_round_time_remains_incomplete_then_current_evidence_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.complete_fixture()
            row.update(ztp_round=2, cycle_started_at="2026-09-01T11:59:00+08:00")
            for value in row["stages"].values():
                value["success_index"] = 2
            row["stages"]["config_apply"]["timestamp"] = ""
            MONITOR.finalize_device(row)
            report = {"project": "private-fixture", "scope": "prod", "devices": [row],
                      "generated_at": "2026-09-01T12:00:00+08:00", "since_minutes": 10,
                      "services": {}, "collection_errors": []}
            snapshot = MONITOR.write_report(report, root, {})
            saved = json.loads((snapshot / "report.json").read_text())["devices"][0]
            self.assertNotEqual("success", saved["overall"])
            self.assertFalse(HTML.ztp_completed(saved))
            self.assertEqual({}, MONITOR.ready_completion_handoff_reports({"scope": "prod", "devices": [saved]}))
            self.assertIn("CURRENT_NINE_STAGE_PROOF_INCOMPLETE", (snapshot / "devices.csv").read_text())
            self.assertIn("CURRENT_NINE_STAGE_PROOF_INCOMPLETE", (snapshot / "report.md").read_text())
            # New independent, comparable source evidence can recover this
            # derived diagnostic; the original negative snapshot is retained.
            saved["stages"]["config_apply"]["timestamp"] = "2026-09-01T12:00:00+08:00"
            MONITOR.finalize_device(saved)
            self.assertEqual("success", saved["overall"])
            self.assertTrue(MONITOR.completion_handoff_device_complete(saved))
            self.assertTrue(HTML.ztp_completed(saved))
            self.assertNotEqual("success", json.loads((snapshot / "report.json").read_text())["devices"][0]["overall"])

    def test_real_snapshot_history_veto_survives_html_and_next_monitor_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            damaged = root / "20260901_115900"
            damaged.mkdir()
            original = b'{"devices":null}\n'
            (damaged / "report.json").write_bytes(original)
            (root / "latest").symlink_to(damaged.name)
            for _ in range(2):
                row = self.complete_fixture()
                previous = MONITOR._previous_report(root)
                MONITOR.assign_ztp_rounds([row], previous)
                MONITOR.assign_stage_success_indices([row], previous)
                MONITOR.finalize_device(row)
                report = {
                    "project": "private-fixture", "scope": "prod",
                    "generated_at": "2026-09-01T12:00:00+08:00",
                    "since_minutes": 10, "services": {}, "devices": [row],
                    "collection_errors": [],
                }
                snapshot = MONITOR.write_report(report, root, {})
                persisted = json.loads((snapshot / "report.json").read_text())
                saved = persisted["devices"][0]
                self.assertIs(saved["round_authority_invalid"], True)
                self.assertFalse(HTML.ztp_completed(saved))
                self.assertEqual({}, MONITOR.ready_completion_handoff_reports(persisted))
                rendered = HTML.render_ztp_status_rows({
                    "available": True, "devices": [saved],
                })
                self.assertIn("Leaf01", rendered)
                self.assertIn("Previous cycle history", rendered)
            self.assertEqual(original, (damaged / "report.json").read_bytes())

    def test_f02_collector_health_classifies_without_ztp_completion(self):
        unavailable = {"available": False, "error": "no ZTP report"}
        self.assertIn("no ZTP report", HTML.render_ztp_status_rows(unavailable))
        self.assertFalse(MONITOR.completion_handoff_device_complete({
            "hostname": "Leaf01", "type": "eth", "ztp_round": 1,
            "overall": "pending", "progress": {"percent": 0},
        }))

        for raw_health, badge in (("OK", "h-ok"), ("Not OK", "h-err")):
            with self.subTest(raw_health=raw_health):
                info = HTML.parse_info_file(
                    "Leaf01",
                    "Switch Type: ETH (VX)\n"
                    "####################################################\n"
                    "# Execute Command: nv show system health\n"
                    "####################################################\n"
                    f"status      {raw_health}\n",
                )
                self.assertEqual(raw_health.lower(), info["health"])
                self.assertIn(f'h-badge {badge}', HTML.render_eth_card(info))
                self.assertIn(f'h-badge {badge}', HTML.render_sw_list_row(info))

    def test_html_completion_uses_same_current_nine_stage_proof_as_handoff(self):
        timestamp = "2026-09-01T12:00:00+08:00"
        boundary = "2026-09-01T11:59:00+08:00"
        current = {
            "hostname": "Leaf01", "type": "eth", "ztp_round": 2,
            "cycle_started_at": boundary, "overall": "success",
            "progress": {"done": 9, "total": 9, "percent": 100},
            "stages": {
                name: {
                    "status": "success", "detail": "fixture source receipt",
                    "timestamp": timestamp, "success_index": 2,
                }
                for name in EXPECTED_NINE_STAGES
            },
        }
        self.assertTrue(MONITOR.completion_handoff_device_complete(current))
        self.assertTrue(HTML.ztp_completed(current))

        invalid_generation = json.loads(json.dumps(current))
        invalid_generation["round_authority_invalid"] = True
        invalid_generation["overall"] = "warning"
        self.assertFalse(MONITOR.completion_handoff_device_complete(invalid_generation))
        self.assertFalse(HTML.ztp_completed(invalid_generation))

        invalid_reset = json.loads(json.dumps(current))
        invalid_reset["manual_operation"] = "reset"
        invalid_reset["reset_reboot_observed"] = "false"
        self.assertFalse(MONITOR.completion_handoff_device_complete(invalid_reset))
        self.assertFalse(HTML.ztp_completed(invalid_reset))

        boolean_stage = json.loads(json.dumps(current))
        boolean_stage["ztp_round"] = 1
        for stage in boolean_stage["stages"].values():
            stage["success_index"] = 1
        boolean_stage["stages"]["config_apply"]["success_index"] = True
        self.assertFalse(MONITOR.completion_handoff_device_complete(boolean_stage))
        self.assertFalse(HTML.ztp_completed(boolean_stage))

        skipped = json.loads(json.dumps(current))
        skipped["stages"]["complete"]["status"] = "skipped"
        skipped["overall"] = "running"
        self.assertFalse(MONITOR.completion_handoff_device_complete(skipped))
        self.assertFalse(HTML.ztp_completed(skipped))

        untimed = json.loads(json.dumps(current))
        untimed["stages"]["ssh_keys"]["timestamp"] = ""
        self.assertFalse(MONITOR.completion_handoff_device_complete(untimed))
        self.assertFalse(HTML.ztp_completed(untimed))

        preboundary = json.loads(json.dumps(current))
        preboundary["stages"]["config_apply"]["timestamp"] = (
            "2026-09-01T10:00:00+08:00"
        )
        self.assertFalse(MONITOR.completion_handoff_device_complete(preboundary))
        self.assertFalse(HTML.ztp_completed(preboundary))

        manual_skew = json.loads(json.dumps(current))
        manual_skew.update({
            "trigger_source": "manual_web", "manual_cycle_marker": boundary,
        })
        for stage_value in manual_skew["stages"].values():
            stage_value["timestamp"] = "2026-09-01T11:58:57+08:00"
        self.assertTrue(MONITOR.completion_handoff_device_complete(manual_skew))
        self.assertTrue(HTML.ztp_completed(manual_skew))

        manual_digest = json.loads(json.dumps(current))
        digest = "a" * 64
        manual_digest.update({
            "trigger_source": "manual_web", "manual_cycle_marker": boundary,
            "manual_command_started_at": boundary,
            "manual_command_finished_at": "2026-09-01T11:59:10+08:00",
            "manual_command_ztp_complete": True,
            "manual_command_ztp_log_sha256": digest,
            "ztp_log_sha256": digest, "ztp_log_current_boot": True,
            "ztp_log_stage_names": [
                "network", "version", "config_apply", "ssh_keys", "complete",
            ],
        })
        for name in manual_digest["ztp_log_stage_names"]:
            manual_digest["stages"][name]["timestamp"] = (
                "2026-09-01T11:56:00+08:00"
            )
        manual_digest["stages"]["bootstrap"]["timestamp"] = (
            "2026-09-01T11:59:04+08:00"
        )
        manual_digest["stages"]["config_http"]["timestamp"] = (
            "2026-09-01T11:59:05+08:00"
        )
        self.assertTrue(MONITOR.completion_handoff_device_complete(manual_digest))
        self.assertTrue(HTML.ztp_completed(manual_digest))
        nonboolean_boot = json.loads(json.dumps(manual_digest))
        nonboolean_boot["ztp_log_current_boot"] = "true"
        self.assertFalse(MONITOR.completion_handoff_device_complete(nonboolean_boot))
        self.assertFalse(HTML.ztp_completed(nonboolean_boot))
        bad_digest = json.loads(json.dumps(manual_digest))
        bad_digest["ztp_log_sha256"] = "0" * 64
        self.assertFalse(MONITOR.completion_handoff_device_complete(bad_digest))
        self.assertFalse(HTML.ztp_completed(bad_digest))

        for stage_name, status in (
            ("config_apply", "skipped"),
            ("config_apply", "warning"),
            ("ssh_keys", "skipped"),
            ("ssh_keys", "warning"),
        ):
            with self.subTest(stage=stage_name, status=status):
                not_applied = json.loads(json.dumps(current))
                not_applied["stages"][stage_name]["status"] = status
                self.assertFalse(
                    MONITOR.completion_handoff_device_complete(not_applied),
                )
                self.assertFalse(HTML.ztp_completed(not_applied))

        for stage_name, device_type in (("dhcp", "eth"), ("version", "ib")):
            with self.subTest(legitimate_skip=stage_name):
                allowed = json.loads(json.dumps(current))
                allowed["type"] = device_type
                allowed["stages"][stage_name]["status"] = "skipped"
                self.assertTrue(MONITOR.completion_handoff_device_complete(allowed))
                self.assertTrue(HTML.ztp_completed(allowed))

        sparse = {"ztp_round": 1, "stages": {"complete": {"status": "success"}}}
        self.assertFalse(MONITOR.completion_handoff_device_complete(sparse))
        self.assertFalse(HTML.ztp_completed(sparse))


def runtime_device(hostname: str, *, environment: str = "unknown") -> dict:
    return {
        "hostname": hostname,
        "type": "pending_nvos",
        "environment": environment,
        "platform_family": "nvos",
        "product": "QM9700",
        "serial": "",
        "unbound_identity": True,
        "managed_ztp": True,
        "dynamic_dhcp": True,
        "ip": "192.0.2.90",
        "mac": "02:00:00:00:00:90",
        "lease_state": "active",
        "ztp_round": 1,
        "stages": {},
        "overall": "warning",
        "progress": {"done": 0, "total": 9, "percent": 0},
        "issues": [],
    }


class CompletionStateAuditTests(unittest.TestCase):
    def test_unchanged_group_preserves_its_original_collected_at(self):
        first = dt.datetime(2026, 9, 1, 10, 0, tzinfo=dt.timezone.utc)
        second = dt.datetime(2026, 9, 1, 10, 5, tzinfo=dt.timezone.utc)
        initial = {
            "air-ethernet": (("AIR-Leaf01", "boot-a", "done-a"),),
            "prod-infiniband": (("IB-Leaf01", "boot-b", "done-b"),),
        }
        updated = dict(initial)
        updated["prod-infiniband"] = (("IB-Leaf01", "boot-c", "done-c"),)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            state = root / MONITOR.HANDOFF_STATE_NAME
            with mock.patch.object(MONITOR, "now_local", side_effect=[first, second]):
                MONITOR.persist_completion_handoff_signatures(state, project, initial)
                MONITOR.persist_completion_handoff_signatures(state, project, updated)

            groups = json.loads(state.read_text(encoding="utf-8"))["groups"]
            self.assertEqual(
                first.isoformat(timespec="seconds"),
                groups["air-ethernet"]["collected_at"],
            )
            self.assertEqual(
                second.isoformat(timespec="seconds"),
                groups["prod-infiniband"]["collected_at"],
            )


class AutomaticHandoffNamingTests(unittest.TestCase):
    def test_process_calls_gate_only_automatic_handoff(self):
        timestamp = "2026-09-01T12:00:00+08:00"
        report = {
            "scope": "all",
            "devices": [{
                "hostname": "AIR-Leaf01", "type": "air", "boot_id": "boot-a",
                "ztp_round": 1, "overall": "success",
                "progress": {"done": 9, "total": 9, "percent": 100},
                "stages": {
                    name: {
                        "status": "success", "detail": "fixture source receipt",
                        "timestamp": timestamp, "success_index": 1,
                    }
                    for name in EXPECTED_NINE_STAGES
                },
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            with mock.patch.object(
                MONITOR, "run_completion_handoff_with_gate", return_value=True,
            ) as handoff, mock.patch.object(
                MONITOR, "persist_completion_handoff_signatures",
            ):
                MONITOR.process_ready_completion_handoffs(
                    report, Path("unused"), 60, project,
                    root / MONITOR.HANDOFF_STATE_NAME,
                    {}, {}, {}, 5, monotonic=lambda: 100.0,
                )
        handoff.assert_called_once()

    def test_automatic_gate_explicitly_disables_time_cooldown(self):
        observed = {}

        class FakeGate:
            def __init__(self, *_args, **kwargs):
                observed.update(kwargs)
                self.decision = type("Decision", (), {"allowed": True})()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def mark_success(self):
                observed["marked"] = True

        with mock.patch.object(MONITOR, "CollectionGate", FakeGate), mock.patch.object(
            MONITOR, "run_completion_handoff", return_value=True,
        ):
            self.assertTrue(MONITOR.run_completion_handoff_with_gate(
                {"scope": "air", "devices": [{"type": "air"}]},
                Path("unused"), 60, Path("/project"), "air-ethernet",
            ))
        self.assertIs(observed["enforce_cooldown"], False)
        self.assertTrue(observed["marked"])


class EnvironmentDisplayTests(unittest.TestCase):
    def test_log_summary_has_separate_air_production_and_unknown_groups(self):
        report = {"devices": [
            {"hostname": "AIR-Leaf01", "type": "pending_eth",
             "environment": "air", "overall": "pending", "progress": {"percent": 0}},
            {"hostname": "IB-Leaf01", "type": "ib",
             "overall": "success", "progress": {"percent": 100}},
            {"hostname": "DISCOVERED", "type": "pending_eth",
             "environment": "unknown", "overall": "warning", "progress": {"percent": 0}},
        ]}
        with mock.patch.object(MONITOR, "log") as logger:
            MONITOR.print_environment_summary(report)
        messages = [str(call.args[0]) for call in logger.call_args_list]
        self.assertEqual(3, len(messages))
        self.assertTrue(any(message.startswith("[STATUS] AIR: 0/1") for message in messages))
        self.assertTrue(any(message.startswith("[STATUS] Production: 1/1") for message in messages))
        self.assertTrue(any(
            message.startswith("[STATUS] Unknown / 未归类: 0/1")
            for message in messages
        ))

    def test_explicit_unknown_renders_in_its_own_ztp_environment(self):
        device = runtime_device("DISCOVERED-NVOS-020000000090")
        self.assertEqual("unknown", HTML.ztp_environment(device))
        rows = HTML.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-09-01T10:00:00+08:00",
            "devices": [device],
        })
        self.assertIn('data-environment="unknown"', rows)
        self.assertIn("Unknown / 未归类", rows)
        self.assertIn("DISCOVERED-NVOS-020000000090", rows)

    def test_all_scope_loads_unknown_report_without_leaking_into_prod_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "devices.csv"
            inventory.write_text("hostname,type,template\n", encoding="utf-8")
            run = root / "20260901_100000"
            run.mkdir()
            (run / "report.json").write_text(json.dumps({
                "project": "sample", "scope": "all",
                "generated_at": "2026-09-01T10:00:00+08:00",
                "devices": [runtime_device("DISCOVERED-NVOS-020000000090")],
            }), encoding="utf-8")
            combined = HTML.load_ztp_status(root, inventory, scope="all")
            production = HTML.load_ztp_status(root, inventory, scope="prod")
        self.assertTrue(combined["available"])
        self.assertEqual(
            ["DISCOVERED-NVOS-020000000090"],
            [device["hostname"] for device in combined["devices"]],
        )
        self.assertEqual(
            "2026-09-01T10:00:00+08:00",
            combined["environment_updates"]["unknown"],
        )
        self.assertFalse(production["available"])

    def test_switch_status_places_explicit_unknown_outside_production(self):
        hostname = "DISCOVERED-NVOS-020000000090"
        status = {
            "available": True, "source": "fixture", "project": "sample",
            "generated_at": "2026-09-01T10:00:00+08:00",
            "environment_updates": {
                "unknown": "2026-09-01T10:00:00+08:00",
            },
            "counts": {"warning": 1},
            "devices": [runtime_device(hostname)],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            output = root / "monitor.html"
            with mock.patch.object(
                HTML, "load_ztp_status", return_value=status,
            ), mock.patch.object(
                HTML, "load_dynamic_air_inventory", return_value=[],
            ), mock.patch.multiple(
                HTML,
                ETH_INFO_DIR=empty, SPX_LINK_DIR=empty,
                IB_INFO_DIR=empty, IBL_LINK_DIR=empty,
                NV_INFO_DIR=empty, NVL_LINK_DIR=empty,
                P2P_OUTPUT_DIR=empty, OUTPUT=output,
                LOG_FILE=root / "generate-monitor.log",
            ):
                HTML.main("all")

            document = output.read_text(encoding="utf-8")
        card_panel = document.split('<div id="card-grid">', 1)[1].split(
            '<div id="list-view"', 1,
        )[0]
        production = card_panel.split(
            '<section class="card-env-group" data-environment="production">', 1,
        )[1].split(
            '<section class="card-env-group" data-environment="unknown">', 1,
        )[0]
        unknown = card_panel.split(
            '<section class="card-env-group" data-environment="unknown">', 1,
        )[1]
        self.assertNotIn(hostname, production)
        self.assertIn("Unknown / 未归类（1）", unknown)
        self.assertIn(hostname, unknown)

    def test_release_identity_flows_from_report_to_dashboard_banner(self):
        release_id = "0123456789abcdefabcd"
        release_time = "2026-09-06T12:00:00+08:00"
        report_time = "2026-09-06T12:01:00+08:00"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "devices.csv"
            inventory.write_text("hostname,type,template\n", encoding="utf-8")
            run = root / "20260906_120100"
            run.mkdir()
            device = runtime_device("AIR-EXAMPLE-Leaf01", environment="air")
            (run / "report.json").write_text(json.dumps({
                "project": "sample",
                "scope": "air",
                "release_id": release_id,
                "release_generated_at": release_time,
                "generated_at": report_time,
                "devices": [device],
            }), encoding="utf-8")

            status = HTML.load_ztp_status(root, inventory, scope="air")
            self.assertEqual(release_id, status["release_id"])
            self.assertEqual(release_time, status["release_generated_at"])

            empty = root / "empty"
            empty.mkdir()
            output = root / "monitor.html"
            with mock.patch.object(
                HTML, "load_ztp_status", return_value=status,
            ), mock.patch.object(
                HTML, "load_dynamic_air_inventory", return_value=[],
            ), mock.patch.object(
                HTML, "DISPLAY_TZ", dt.timezone(dt.timedelta(hours=8)),
            ), mock.patch.multiple(
                HTML,
                ETH_INFO_DIR=empty, SPX_LINK_DIR=empty,
                IB_INFO_DIR=empty, IBL_LINK_DIR=empty,
                NV_INFO_DIR=empty, NVL_LINK_DIR=empty,
                P2P_OUTPUT_DIR=empty, OUTPUT=output,
                LOG_FILE=root / "generate-monitor.log",
            ):
                HTML.main("air")
            document = output.read_text(encoding="utf-8")
        toolbar = document.split('<div class="ztp-toolbar">', 1)[1].split(
            "</div>", 1,
        )[0]
        self.assertIn(f"Release：<strong>{release_id}</strong>", toolbar)
        self.assertIn("2026-09-06 12:00:00 UTC+08:00", toolbar)

    def test_full_dashboard_emits_stable_sort_protocol_for_ztp_and_link_rows(self):
        class FrozenDateTime(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                value = cls(2026, 9, 8, 12, 0)
                if tz is None:
                    return value
                return value.replace(tzinfo=HTML.DISPLAY_TZ).astimezone(tz)

        status = {
            "available": True,
            "source": "fixture",
            "project": "sample",
            "generated_at": "2026-09-07T14:28:28+08:00",
            "counts": {"pending": 2},
            "devices": [
                {
                    **runtime_device("AIR-h05-oobofoob-leaf10", environment="air"),
                    "type": "air", "ip": "192.0.2.185",
                },
                {
                    **runtime_device("AIR-h05-oobofoob-leaf2", environment="air"),
                    "type": "air", "ip": "192.0.2.177",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            spx = root / "spx-link"
            spx.mkdir()
            (spx / "20260907-1428.csv").write_text(
                "Hostname,Interface,Effective-BER,Effective-Error,"
                "Carrier-Transitions,Date,Time,ECN-Marked,PFC-Receive,"
                "PFC-Send,Oper-Status,Peer,Peer-Interface\n"
                "leaf10,swp10,1E-8,0.01,10,2026-09-07,14:28:00,0,0,0,up,leaf2,swp2\n"
                "leaf2,swp2,9E-9,0.001,2,2026-09-07,14:28:00,0,0,0,up,leaf10,swp10\n",
                encoding="utf-8",
            )
            output = root / "monitor.html"
            with mock.patch.object(
                HTML, "load_ztp_status", return_value=status,
            ), mock.patch.object(
                HTML, "load_dynamic_air_inventory", return_value=[],
            ), mock.patch.object(
                HTML, "datetime", FrozenDateTime,
            ), mock.patch.multiple(
                HTML,
                ETH_INFO_DIR=empty, SPX_LINK_DIR=spx,
                IB_INFO_DIR=empty, IBL_LINK_DIR=empty,
                NV_INFO_DIR=empty, NVL_LINK_DIR=empty,
                P2P_OUTPUT_DIR=empty, OUTPUT=output,
                LOG_FILE=root / "generate-monitor.log",
            ):
                HTML.main("all")
            document = output.read_text(encoding="utf-8")

        ztp_body = document.split('<table id="ztp-tbl"', 1)[1].split(
            "</tbody>", 1,
        )[0]
        self.assertLess(
            ztp_body.index("AIR-h05-oobofoob-leaf2"),
            ztp_body.index("AIR-h05-oobofoob-leaf10"),
        )
        self.assertIn(
            'class="ztp-ip-cell" data-sort-kind="ip" '
            'data-sort-value="3221226161" data-sort-missing="false"',
            ztp_body,
        )
        self.assertIn(
            'data-sort-kind="number" data-sort-value="9E-9" '
            'data-sort-missing="false">9E-9</td>',
            document,
        )
        self.assertIn("environment.groups.sort", document)
        self.assertIn("restoreSortState();", document)


if __name__ == "__main__":
    unittest.main()
