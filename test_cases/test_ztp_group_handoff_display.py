#!/usr/bin/env python3
"""Display and audit contracts for environment-scoped ZTP handoff."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path
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
        report = {
            "scope": "all",
            "devices": [{
                "hostname": "AIR-Leaf01", "type": "air", "boot_id": "boot-a",
                "progress": {"percent": 100},
                "stages": {"complete": {"timestamp": "done-a"}},
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


if __name__ == "__main__":
    unittest.main()
