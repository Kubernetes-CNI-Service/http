#!/usr/bin/env python3
"""Contracts for type-scoped ZTP-to-Switch collection handoff."""

from __future__ import annotations

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
    "ztp_group_handoff_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
GATE = load_module(
    "ztp_group_handoff_gate", ROOT / "monitor/switch_collection_gate.py",
)
WORKER = load_module(
    "ztp_group_handoff_worker", ROOT / "monitor/switch-collection-worker.py",
)


def device(hostname: str, device_type: str, percent: int = 100, **extra):
    value = {
        "hostname": hostname,
        "type": device_type,
        "boot_id": f"boot-{hostname}",
        "progress": {"percent": percent},
        "stages": {
            "complete": {"timestamp": f"2026-09-01T12:00:00+08:00-{hostname}"},
        },
    }
    value.update(extra)
    return value


class CompletionGroupTests(unittest.TestCase):
    def test_completed_air_group_does_not_wait_for_other_types(self):
        report = {
            "scope": "all",
            "devices": [
                device("AIR-Leaf01", "air"),
                device("Leaf01", "eth", 66),
                device("IB-Leaf01", "ib", 11),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        self.assertEqual(["air-ethernet"], list(ready))
        self.assertEqual(
            ["AIR-Leaf01"],
            [item["hostname"] for item in ready["air-ethernet"]["devices"]],
        )
        self.assertEqual("all", ready["air-ethernet"]["scope"])

    def test_one_incomplete_device_waits_for_its_whole_group(self):
        report = {
            "scope": "prod",
            "devices": [
                device("Leaf01", "eth"),
                device("Leaf02", "eth_spx", 99),
                device("IB-Leaf01", "ib"),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        self.assertEqual(["prod-infiniband"], list(ready))

    def test_display_subclasses_do_not_create_extra_handoff_gates(self):
        report = {
            "scope": "prod",
            "devices": [
                device("OOB-Leaf01", "eth", 100, template="oob-leaf"),
                device("TAN-Leaf01", "eth", 50, template="tan-leaf"),
                device("Border01", "eth_spx", 100, template="border"),
                device("IB-Leaf01", "ib", 100),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        self.assertEqual(["prod-infiniband"], list(ready))
        grouped = MONITOR.completion_handoff_reports(report)
        self.assertEqual(
            ["OOB-Leaf01", "TAN-Leaf01", "Border01"],
            [row["hostname"] for row in grouped["prod-ethernet"]["devices"]],
        )

    def test_identity_flags_block_only_their_own_group(self):
        for flag in ("unbound_identity", "identity_pending", "promotion_pending"):
            with self.subTest(flag=flag):
                report = {
                    "scope": "prod",
                    "devices": [
                        device("Leaf01", "eth"),
                        device("IB-Leaf01", "ib", **{flag: True}),
                    ],
                }
                ready = MONITOR.ready_completion_handoff_reports(report)
                self.assertEqual(["prod-ethernet"], list(ready))

    def test_classifiable_pending_devices_block_only_their_group(self):
        report = {
            "scope": "all",
            "devices": [
                device("AIR-Leaf01", "air"),
                device("Pending-AIR", "pending_air", 100, environment="air"),
                device("Leaf01", "eth"),
                device("Pending-ETH", "pending_eth", 100,
                       environment="production"),
                device("IB-Leaf01", "ib"),
                device("Pending-IB", "pending_ib", 100,
                       environment="production"),
                device("NVL-Leaf01", "nvl"),
                device("Pending-NVL", "pending_nvl", 100,
                       environment="production"),
            ],
        }
        self.assertEqual({}, MONITOR.ready_completion_handoff_reports(report))

    def test_air_pending_eth_uses_environment_to_block_air_not_production(self):
        report = {
            "scope": "all",
            "devices": [
                device("AIR-Leaf01", "air"),
                device("AIR-Pending01", "pending_eth", 100, environment="air"),
                device("Leaf01", "eth"),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        self.assertEqual(["prod-ethernet"], list(ready))

    def test_unclassified_runtime_pending_does_not_block_a_known_group(self):
        report = {
            "scope": "all",
            "devices": [
                device("Leaf01", "eth"),
                device("DISCOVERED-CUMULUS", "pending_eth", 0,
                       environment="unknown", identity_pending=True),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        self.assertEqual(["prod-ethernet"], list(ready))

    def test_contradictory_pending_type_and_environment_fail_closed(self):
        rows = [
            device("Bad-AIR", "pending_air", 0, environment="production"),
            device("Bad-IB", "pending_ib", 0, environment="air"),
        ]
        self.assertEqual(
            [None, None],
            [MONITOR.completion_handoff_group(row) for row in rows],
        )
        report = {"scope": "all", "devices": [device("Leaf01", "eth"), *rows]}
        self.assertEqual(
            ["prod-ethernet"],
            list(MONITOR.ready_completion_handoff_reports(report)),
        )

    def test_all_scope_runtime_unknown_is_not_guessed_as_production(self):
        observation = {
            "mac_plain": "020000000099", "mac": "02:00:00:00:00:99",
            "platform": "cumulus", "product": None, "serial": None,
            "ip": "192.0.2.99", "last_lease_ip": "192.0.2.99",
            "last_seen": "2026-09-01T12:00:00+08:00",
            "lease_state": "active", "fingerprints": {}, "issues": [],
        }
        with mock.patch.object(MONITOR, "unknown_dhcp_devices", return_value=[observation]):
            rows = MONITOR.runtime_unknown_devices(
                Path("unused.csv"), "", scope="all", dhcp_leases=None,
            )
        self.assertEqual(1, len(rows))
        self.assertEqual("unknown", rows[0]["environment"])
        self.assertIsNone(MONITOR.completion_handoff_group(rows[0]))

    def test_unknown_and_pending_nvos_neither_block_nor_trigger_known_groups(self):
        report = {
            "scope": "all",
            "devices": [
                device("Leaf01", "eth"),
                device("Unknown01", "unknown", 0),
                device("Unknown-NVOS01", "pending_nvos", 0),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        self.assertEqual(["prod-ethernet"], list(ready))
        unknown_only = {"scope": "all", "devices": report["devices"][1:]}
        self.assertEqual({}, MONITOR.ready_completion_handoff_reports(unknown_only))

    def test_each_group_builds_only_its_own_collection_command(self):
        scripts = {
            "ethernet": Path("/collect/ethernet.sh"),
            "infiniband": Path("/collect/infiniband.sh"),
            "nvlink": Path("/collect/nvlink.sh"),
        }
        report = {
            "scope": "all",
            "devices": [
                device("AIR-Leaf01", "air"),
                device("Leaf01", "spx"),
                device("IB-Leaf01", "ib"),
                device("NVL-Leaf01", "nvl"),
            ],
        }
        ready = MONITOR.ready_completion_handoff_reports(report)
        expected = {
            "air-ethernet": [["bash", "/collect/ethernet.sh", "--air"]],
            "prod-ethernet": [["bash", "/collect/ethernet.sh", "--prod"]],
            "prod-infiniband": [["bash", "/collect/infiniband.sh"]],
            "prod-nvlink": [["bash", "/collect/nvlink.sh"]],
        }
        self.assertEqual(
            expected,
            {
                key: MONITOR.completion_collection_commands(group_report, scripts)
                for key, group_report in ready.items()
            },
        )


class CompletionStateTests(unittest.TestCase):
    def test_staggered_groups_handoff_once_as_each_type_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            state = root / MONITOR.HANDOFF_STATE_NAME
            handed_off = {}
            retries = {}
            retry_after = {}
            attempts = []

            def run(report, expected_attempts):
                nonlocal handed_off, retries, retry_after
                before = len(attempts)

                def handoff(
                    _report, _html, _timeout, _project, collection_key, **_kwargs,
                ):
                    attempts.append(collection_key)
                    return True

                with mock.patch.object(
                    MONITOR, "run_completion_handoff_with_gate",
                    side_effect=handoff,
                ):
                    handed_off, retries, retry_after = (
                        MONITOR.process_ready_completion_handoffs(
                            report, Path("unused"), 60, project, state,
                            handed_off, retries, retry_after, 5,
                            monotonic=lambda: 100.0,
                        )
                    )
                self.assertEqual(expected_attempts, attempts[before:])

            ethernet_done = device("Leaf01", "eth")
            ib_waiting = device("IB-Leaf01", "ib", 10)
            nvl_waiting = device("NVL-Leaf01", "nvl", 10)
            run(
                {"scope": "prod", "devices": [
                    ethernet_done, ib_waiting, nvl_waiting,
                ]},
                ["prod-ethernet"],
            )
            # An unchanged report is deduplicated and does not recollect.
            before = list(attempts)
            run(
                {"scope": "prod", "devices": [
                    ethernet_done, ib_waiting, nvl_waiting,
                ]},
                [],
            )
            self.assertEqual(before, attempts)
            run(
                {"scope": "prod", "devices": [
                    ethernet_done, device("IB-Leaf01", "ib"), nvl_waiting,
                ]},
                ["prod-infiniband"],
            )
            run(
                {"scope": "prod", "devices": [
                    ethernet_done, device("IB-Leaf01", "ib"),
                    device("NVL-Leaf01", "nvl"),
                ]},
                ["prod-nvlink"],
            )
            self.assertEqual(
                ["prod-ethernet", "prod-infiniband", "prod-nvlink"],
                attempts,
            )
            self.assertEqual(
                set(attempts),
                set(MONITOR.load_completion_handoff_signatures(state, project)),
            )

    def test_group_signatures_are_persisted_together_and_deduplicate_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            state = root / MONITOR.HANDOFF_STATE_NAME
            signatures = {
                "air-ethernet": (("AIR-Leaf01", "boot-a", "done-a"),),
                "prod-infiniband": (("IB-Leaf01", "boot-b", "done-b"),),
            }
            MONITOR.persist_completion_handoff_signatures(state, project, signatures)
            self.assertEqual(
                signatures,
                MONITOR.load_completion_handoff_signatures(state, project),
            )
            self.assertEqual(2, json.loads(state.read_text())["schema_version"])
            self.assertEqual(0o644, state.stat().st_mode & 0o777)

    def test_legacy_state_is_ignored_safely_and_recollected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            state = root / MONITOR.HANDOFF_STATE_NAME
            state.write_text(json.dumps({
                "schema_version": 1,
                "project": str(project.resolve()),
                "scope": "all",
                "signature": [["Leaf01", "boot-a", "done-a"]],
            }), encoding="utf-8")
            self.assertEqual(
                {}, MONITOR.load_completion_handoff_signatures(state, project),
            )

    def test_invalid_group_state_fails_safe_to_recollection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            state = root / MONITOR.HANDOFF_STATE_NAME
            state.write_text(json.dumps({
                "schema_version": 2,
                "project": str(project.resolve()),
                "groups": {"unsafe-group": {"signature": []}},
            }), encoding="utf-8")
            self.assertEqual(
                {}, MONITOR.load_completion_handoff_signatures(state, project),
            )

    def test_failed_ready_group_does_not_prevent_sibling_group_attempt(self):
        report = {
            "scope": "prod",
            "devices": [device("Leaf01", "eth"), device("IB-Leaf01", "ib")],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            attempts = []

            def handoff(group_report, _html, _timeout, _project, collection_key, **_kwargs):
                attempts.append(collection_key)
                return collection_key == "prod-infiniband"

            with mock.patch.object(
                MONITOR, "run_completion_handoff_with_gate", side_effect=handoff,
            ), mock.patch.object(MONITOR, "persist_completion_handoff_signatures"):
                handed_off, retry_signatures, _retry_after = (
                    MONITOR.process_ready_completion_handoffs(
                        report, Path("unused"), 60, project,
                        root / MONITOR.HANDOFF_STATE_NAME,
                        {}, {}, {}, 5, monotonic=lambda: 100.0,
                    )
                )
            self.assertEqual(["prod-ethernet", "prod-infiniband"], attempts)
            self.assertIn("prod-infiniband", handed_off)
            self.assertNotIn("prod-ethernet", handed_off)
            self.assertIn("prod-ethernet", retry_signatures)

    def test_group_gate_io_error_does_not_abort_ready_sibling(self):
        report = {
            "scope": "prod",
            "devices": [device("Leaf01", "eth"), device("IB-Leaf01", "ib")],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            attempts = []

            def handoff(group_report, _html, _timeout, _project, collection_key, **_kwargs):
                attempts.append(collection_key)
                if collection_key == "prod-ethernet":
                    raise PermissionError("cooldown state is not writable")
                return True

            with mock.patch.object(
                MONITOR, "run_completion_handoff_with_gate", side_effect=handoff,
            ), mock.patch.object(MONITOR, "persist_completion_handoff_signatures"):
                handed_off, retry_signatures, _retry_after = (
                    MONITOR.process_ready_completion_handoffs(
                        report, Path("unused"), 60, project,
                        root / MONITOR.HANDOFF_STATE_NAME,
                        {}, {}, {}, 5, monotonic=lambda: 100.0,
                    )
                )
            self.assertEqual(["prod-ethernet", "prod-infiniband"], attempts)
            self.assertIn("prod-infiniband", handed_off)
            self.assertIn("prod-ethernet", retry_signatures)


class CollectionGateScopeTests(unittest.TestCase):
    def test_scope_mapping_uses_exact_one_three_and_four_keys(self):
        self.assertEqual(("air-ethernet",), GATE.collection_keys_for_scope("air"))
        self.assertEqual(
            ("prod-ethernet", "prod-infiniband", "prod-nvlink"),
            GATE.collection_keys_for_scope("prod"),
        )
        self.assertEqual(
            (
                "air-ethernet", "prod-ethernet",
                "prod-infiniband", "prod-nvlink",
            ),
            GATE.collection_keys_for_scope("all"),
        )

    def test_explicit_empty_collection_keys_are_rejected(self):
        with self.assertRaises(GATE.CollectionGateError):
            GATE.CollectionGate(
                "project-a", "prod", collection_keys=(),
            )

    def test_successful_group_does_not_cool_down_sibling_group(self):
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with GATE.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status, cooldown_seconds=60, clock=lambda: clock[0],
            ) as ethernet:
                self.assertTrue(ethernet.decision.allowed)
                ethernet.mark_success()
            clock[0] += 1
            with GATE.CollectionGate(
                "project-a", "prod", collection_keys=("prod-infiniband",),
                status_dir=status, cooldown_seconds=60, clock=lambda: clock[0],
            ) as infiniband:
                self.assertTrue(infiniband.decision.allowed)

    def test_automatic_handoff_bypasses_time_cooldown_but_keeps_gate(self):
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with GATE.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status, cooldown_seconds=60, clock=lambda: clock[0],
            ) as first:
                first.mark_success()
            clock[0] += 1
            with GATE.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status, cooldown_seconds=60, clock=lambda: clock[0],
                enforce_cooldown=False,
            ) as new_ztp_round:
                self.assertTrue(new_ztp_round.decision.allowed)

    def test_manual_prod_success_covers_all_three_prod_groups(self):
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with GATE.CollectionGate(
                "project-a", "prod", status_dir=status,
                cooldown_seconds=60, clock=lambda: clock[0],
            ) as manual:
                self.assertTrue(manual.decision.allowed)
                manual.mark_success()
            clock[0] += 1
            for key in ("prod-ethernet", "prod-infiniband", "prod-nvlink"):
                with self.subTest(key=key), GATE.CollectionGate(
                    "project-a", "prod", collection_keys=(key,),
                    status_dir=status, cooldown_seconds=60, clock=lambda: clock[0],
                ) as automatic:
                    self.assertFalse(automatic.decision.allowed)
                    self.assertEqual("cooldown", automatic.decision.reason)

    def test_multi_group_request_runs_when_any_requested_group_is_fresh(self):
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with GATE.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status, cooldown_seconds=60, clock=lambda: clock[0],
            ) as automatic:
                automatic.mark_success()
            clock[0] += 1
            with GATE.CollectionGate(
                "project-a", "prod", status_dir=status,
                cooldown_seconds=60, clock=lambda: clock[0],
            ) as manual:
                self.assertTrue(manual.decision.allowed)

    def test_schema_one_gate_state_is_ignored_instead_of_blocking_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            (status / GATE.STATE_NAME).write_text(json.dumps({
                "schema_version": 1,
                "project": "project-a",
                "scope": "prod",
                "successful_epoch": 1000.0,
                "successful_at": "1970-01-01T00:16:40+00:00",
            }), encoding="utf-8")
            with GATE.CollectionGate(
                "project-a", "prod", status_dir=status,
                cooldown_seconds=60, clock=lambda: 1001.0,
            ) as gate:
                self.assertTrue(gate.decision.allowed)

    def test_unconvertible_state_epoch_is_rejected_as_gate_error(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            (status / GATE.STATE_NAME).write_text(json.dumps({
                "schema_version": 2,
                "project": "project-a",
                "successes": {
                    "prod-ethernet": {
                        "successful_epoch": 1e308,
                        "successful_at": "invalid-but-finite-epoch",
                    },
                },
            }), encoding="utf-8")
            with self.assertRaises(GATE.CollectionGateError):
                with GATE.CollectionGate(
                    "project-a", "prod",
                    collection_keys=("prod-ethernet",),
                    status_dir=status, clock=lambda: 1001.0,
                ):
                    pass

    def test_lock_open_oserror_is_wrapped_as_gate_error(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            (status / GATE.LOCK_NAME).symlink_to(status / "missing-target")
            with self.assertRaises(GATE.CollectionGateError):
                with GATE.CollectionGate(
                    "project-a", "air", status_dir=status,
                ):
                    pass

    def test_lock_wait_is_bounded_and_does_not_wait_on_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            holder = GATE.CollectionGate(
                "project-a", "air", status_dir=status,
            )
            holder.__enter__()
            clock = [0.0]

            def advance(seconds):
                clock[0] += seconds

            try:
                with GATE.CollectionGate(
                    "project-a", "air", status_dir=status,
                    lock_wait_seconds=2, monotonic=lambda: clock[0],
                    sleeper=advance, poll_seconds=1,
                ) as waiting:
                    self.assertFalse(waiting.decision.allowed)
                    self.assertEqual("busy", waiting.decision.reason)
                self.assertEqual(2.0, clock[0])
            finally:
                holder.__exit__(None, None, None)

            wall_clock = [1000.0]
            with GATE.CollectionGate(
                "project-a", "air", status_dir=status,
                clock=lambda: wall_clock[0], cooldown_seconds=60,
            ) as successful:
                successful.mark_success()
            wall_clock[0] += 1
            no_sleep = mock.Mock(side_effect=AssertionError("cooldown must not wait"))
            with GATE.CollectionGate(
                "project-a", "air", status_dir=status,
                clock=lambda: wall_clock[0], cooldown_seconds=60,
                lock_wait_seconds=600, sleeper=no_sleep,
            ) as cooling:
                self.assertFalse(cooling.decision.allowed)
                self.assertEqual("cooldown", cooling.decision.reason)
            no_sleep.assert_not_called()

    def test_lock_wait_can_acquire_after_holder_releases(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            holder = GATE.CollectionGate(
                "project-a", "prod",
                collection_keys=("prod-ethernet",), status_dir=status,
            )
            holder.__enter__()
            clock = [0.0]
            released = [False]

            def release_holder(seconds):
                clock[0] += seconds
                if not released[0]:
                    released[0] = True
                    holder.__exit__(None, None, None)

            try:
                with GATE.CollectionGate(
                    "project-a", "prod",
                    collection_keys=("prod-infiniband",), status_dir=status,
                    lock_wait_seconds=2, monotonic=lambda: clock[0],
                    sleeper=release_holder, poll_seconds=0.25,
                ) as acquired:
                    self.assertTrue(acquired.decision.allowed)
            finally:
                holder.__exit__(None, None, None)

    def test_lock_wait_cancellation_releases_contender(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with GATE.CollectionGate(
                "project-a", "air", status_dir=status,
            ):
                with self.assertRaises(GATE.CollectionGateCancelled):
                    with GATE.CollectionGate(
                        "project-a", "air", status_dir=status,
                        lock_wait_seconds=60, cancel_check=lambda: True,
                    ):
                        pass

    def test_manual_worker_passes_all_scope_keys_to_shared_gate(self):
        captured = {}

        class FakeGate:
            cooldown_seconds = 1800

            def __init__(self, project, scope, **kwargs):
                captured.update(project=project, scope=scope, **kwargs)
                self.decision = GATE.GateDecision(True, "allowed")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def mark_success(self):
                return "2026-09-01T12:00:00+08:00"

        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(WORKER, "CollectionGate", FakeGate), \
                mock.patch.object(WORKER, "active_project_identity", return_value="/project"), \
                mock.patch.object(WORKER, "commands_for_scope", return_value=[]), \
                mock.patch.object(WORKER, "write_status"), \
                mock.patch.object(WORKER.subprocess, "run", return_value=completed):
            self.assertTrue(WORKER.collect("all", 60, 37))
        self.assertEqual("all", captured["scope"])
        self.assertEqual(
            GATE.collection_keys_for_scope("all"), captured["collection_keys"],
        )
        self.assertEqual(37, captured["lock_wait_seconds"])
        self.assertTrue(callable(captured["cancel_check"]))


class SwitchCollectionWorkerTests(unittest.TestCase):
    @staticmethod
    def _write_proc_entry(
        proc_root: Path, pid: int, argv: list[str], parent: int = 1,
    ) -> None:
        entry = proc_root / str(pid)
        entry.mkdir()
        entry.joinpath("cmdline").write_bytes(
            b"\0".join(item.encode("utf-8") for item in argv) + b"\0"
        )
        entry.joinpath("stat").write_text(
            f"{pid} (fixture) S {parent} 0 0 0\n", encoding="utf-8",
        )

    def test_process_scan_matches_literal_ib_and_nvlink_symlink_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts_root = root / "scripts"
            scripts_root.mkdir()
            canonical = scripts_root / "ethernet-cron.sh"
            canonical.write_text("#!/bin/sh\n", encoding="utf-8")
            ib_alias = scripts_root / "infiniband-cron.sh"
            nvl_alias = scripts_root / "nvlink-cron.sh"
            ib_alias.symlink_to(canonical)
            nvl_alias.symlink_to(canonical)
            scripts = {
                "ethernet": canonical,
                "infiniband": ib_alias,
                "nvlink": nvl_alias,
            }
            proc_root = root / "proc"
            proc_root.mkdir()
            self._write_proc_entry(
                proc_root, 91001, ["bash", str(ib_alias)],
            )
            self._write_proc_entry(
                proc_root, 91002, ["bash", str(nvl_alias)],
            )
            self._write_proc_entry(
                proc_root, 91003, ["bash", str(canonical)],
            )
            self._write_proc_entry(
                proc_root, 91004, ["bash", "/tmp/unrelated-cron.sh"],
            )
            self._write_proc_entry(
                proc_root, 91005, ["ssh", "admin@switch"], parent=91001,
            )
            with mock.patch.object(WORKER, "SCRIPTS", scripts):
                self.assertEqual(
                    {91001, 91002, 91003, 91005},
                    WORKER.collection_process_ids(proc_root),
                )

    def test_worker_maps_gate_wait_cancellation_to_idle(self):
        class CancelledGate:
            def __init__(self, _project, _scope, **kwargs):
                self.cancel_check = kwargs["cancel_check"]

            def __enter__(self):
                self.assert_cancelled = self.cancel_check()
                raise WORKER.CollectionGateCancelled("operator stop")

            def __exit__(self, *_args):
                return None

        write_status = mock.Mock()
        with mock.patch.object(WORKER, "CollectionGate", CancelledGate), \
                mock.patch.object(WORKER, "active_project_identity", return_value="/project"), \
                mock.patch.object(WORKER, "claim_request", return_value="stop"), \
                mock.patch.object(WORKER, "stop_all_collectors", return_value=[91001]), \
                mock.patch.object(WORKER, "write_status", write_status):
            self.assertFalse(WORKER.collect("prod", 60, 10))
        states = [call.args[0] for call in write_status.call_args_list]
        self.assertEqual(["collecting", "idle"], states)
        self.assertEqual([91001], write_status.call_args.kwargs["stopped_pids"])


if __name__ == "__main__":
    unittest.main()
