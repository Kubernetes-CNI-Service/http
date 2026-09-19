#!/usr/bin/env python3
"""Direct tests-first contract for immutable collection-cycle persistence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import ExitStack


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "monitor/switch-collection-worker.py"
TOOLS_ROOT = ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

import project_contract as CONTRACT


PROJECT_IDENTITY = "/srv/http/project-alpha"
OTHER_PROJECT_IDENTITY = "/srv/http/project-beta"
PROJECT_KEY = hashlib.sha256(PROJECT_IDENTITY.encode("utf-8")).hexdigest()
OTHER_PROJECT_KEY = hashlib.sha256(OTHER_PROJECT_IDENTITY.encode("utf-8")).hexdigest()
SCOPE = "prod"
SOURCE = "switch_collection"
TOKEN_1 = "00112233445546778899aabbccddeeff"
TOKEN_2 = "ffeeddccbbaa49888776655443322110"
TOKEN_3 = "123456789abc4def8123456789abcdef"
SHA_A = "c" * 64
SHA_B = "d" * 64
SHA_C = "e" * 64
TEST_SECRET_ONE = "-".join(("first", "secret"))
TEST_SECRET_TWO = "-".join(("second", "secret"))
REDACTED_PLACEHOLDER = "".join(("<red", "acted>"))


def load_worker():
    spec = importlib.util.spec_from_file_location(
        "collection_cycle_persistence_worker", WORKER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {WORKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(spec.name)
    sys.path.insert(0, str(WORKER_PATH.parent))
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if old is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = old
    return module


WORKER = load_worker()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def snapshot_tree(path: Path) -> tuple:
    if not path.exists():
        return ()
    return tuple(
        (
            str(item.relative_to(path)),
            "dir" if item.is_dir() else "file",
            None if item.is_dir() else item.read_bytes(),
        )
        for item in sorted(path.rglob("*"))
    )


def cycle_identity(start: dict) -> dict:
    return {
        name: start[name]
        for name in (
            "project_key", "scope", "source", "sequence", "run_token",
            "cycle_id",
        )
    }


def successful_cycle_summary(start: dict) -> dict:
    identity = cycle_identity(start)
    results = []
    for slot in CONTRACT.collection_cycle_source_slots(identity["scope"]):
        results.append({
            "schema_version": 2,
            "task": "switch_collection",
            **identity,
            "source_slot": slot,
            "state": "success",
            "planned": 1,
            "succeeded": 1,
            "failed_count": 0,
            "failed_devices": [],
            "evidence": {"sha256": SHA_A, "size_bytes": 123},
            "envelope": {"sha256": SHA_B, "size_bytes": 456},
            "input_inventory_sha256": SHA_C,
        })
    return CONTRACT.summarize_collection_cycle_results(
        identity,
        results,
        html_annotation={
            "attempted": True,
            "state": "success",
            "error_sha256": None,
        },
    )


def successful_cycle_result(start: dict) -> dict:
    summary = successful_cycle_summary(start)
    empty_stream = {
        "sha256": hashlib.sha256(b"").hexdigest(),
        "size_bytes": 0,
    }
    return {
        "identity": cycle_identity(start),
        "outcomes": [
            {
                "source_slot": child["source_slot"],
                "outcome": "accepted",
                "child_result": child,
                "evidence": {
                    "stdout": dict(empty_stream),
                    "stderr": dict(empty_stream),
                    "returncode": 0,
                },
            }
            for child in summary["results"]
        ],
        "summary": summary,
    }


class CollectionCyclePersistenceTests(unittest.TestCase):
    """Pin the persistence seam before any B3 production implementation."""

    def api(self, name: str):
        self.assertTrue(
            hasattr(WORKER, name),
            f"monitor/switch-collection-worker.py must define B3 persistence API {name}",
        )
        return getattr(WORKER, name)

    def test_interim_worker_bounds_equal_pure_authority(self):
        self.assertEqual(
            CONTRACT.COLLECTION_CYCLE_MAX_FAILED_DEVICES,
            WORKER.MAX_TASK_RESULT_DEVICES,
        )
        self.assertEqual(
            CONTRACT.COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES,
            WORKER.MAX_TASK_RESULT_TEXT_BYTES,
        )

    def test_store_requires_entered_allowed_collection_gate_and_fixed_source(self):
        store_type = self.api("CollectionCycleStore")
        hold_type = self.api("CollectionCycleHoldError")
        with tempfile.TemporaryDirectory() as td:
            status_dir = Path(td) / "monitor" / "status"
            merely_constructed = WORKER.CollectionGate(
                PROJECT_IDENTITY,
                SCOPE,
                status_dir=status_dir,
                enforce_cooldown=False,
                lane="collection",
            )
            with self.assertRaises(hold_type):
                store_type(gate=merely_constructed, source=SOURCE)

            with WORKER.CollectionGate(
                PROJECT_IDENTITY,
                SCOPE,
                status_dir=status_dir,
                enforce_cooldown=False,
                collection_keys=("yaml-backup",),
                lane="backup",
            ) as backup_gate:
                self.assertTrue(backup_gate.decision.allowed)
                with self.assertRaises(hold_type):
                    store_type(gate=backup_gate, source=SOURCE)

            with WORKER.CollectionGate(
                PROJECT_IDENTITY,
                SCOPE,
                status_dir=status_dir,
                enforce_cooldown=False,
                lane="collection",
            ) as gate:
                self.assertTrue(gate.decision.allowed)
                with self.assertRaises(ValueError):
                    store_type(gate=gate, source="yaml_backup")
                released_store = store_type(gate=gate, source=SOURCE)

            with self.assertRaises(hold_type):
                released_store.allocate_start(
                    process_inspector=self.dead_inspector,
                )

    def test_busy_gate_refusal_is_byte_inert_and_next_allowed_run_gets_sequence_one(self):
        store_type = self.api("CollectionCycleStore")
        hold_type = self.api("CollectionCycleHoldError")
        with tempfile.TemporaryDirectory() as td:
            status_dir = Path(td) / "monitor/status"
            cycle_root = status_dir / "collection-cycles"
            with WORKER.CollectionGate(
                PROJECT_IDENTITY,
                SCOPE,
                status_dir=status_dir,
                enforce_cooldown=False,
                lane="collection",
            ) as holder:
                self.assertTrue(holder.decision.allowed)
                before = snapshot_tree(cycle_root)
                with WORKER.CollectionGate(
                    PROJECT_IDENTITY,
                    SCOPE,
                    status_dir=status_dir,
                    enforce_cooldown=False,
                    lane="collection",
                    lock_wait_seconds=0,
                ) as refused, mock.patch.object(
                    WORKER, "_mint_cycle_run_token",
                ) as mint:
                    self.assertFalse(refused.decision.allowed)
                    self.assertEqual("busy", refused.decision.reason)
                    with self.assertRaises(hold_type):
                        store_type(gate=refused, source=SOURCE)
                    mint.assert_not_called()
                self.assertEqual(before, snapshot_tree(cycle_root))

            with WORKER.CollectionGate(
                PROJECT_IDENTITY,
                SCOPE,
                status_dir=status_dir,
                enforce_cooldown=False,
                lane="collection",
            ) as allowed:
                store = store_type(gate=allowed, source=SOURCE)
                start = self.allocate(store, TOKEN_1, self.dead_inspector)
                self.assertEqual(1, start["sequence"])

    def test_direct_internal_cycle_mode_refuses_without_authority_or_durable_bytes(self):
        cycle_root = ROOT / "monitor/status/collection-cycles"
        before = snapshot_tree(cycle_root)
        completed = subprocess.run(
            [
                sys.executable,
                str(WORKER_PATH),
                "--internal-cycle",
                "--scope", SCOPE,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertNotEqual(0, completed.returncode)
        self.assertIn("internal_cycle_gate_required", completed.stderr)
        self.assertEqual(before, snapshot_tree(cycle_root))

    def setUp(self):
        self._stack = ExitStack()

    def tearDown(self):
        self._stack.close()

    def store(
        self,
        status_dir: Path,
        *,
        project_identity: str = PROJECT_IDENTITY,
        scope: str = SCOPE,
    ):
        cls = self.api("CollectionCycleStore")
        gate = WORKER.CollectionGate(
            project_identity,
            scope,
            status_dir=status_dir,
            enforce_cooldown=False,
            lane="collection",
        )
        entered = self._stack.enter_context(gate)
        self.assertTrue(entered.decision.allowed)
        return cls(gate=entered, source=SOURCE)

    def allocate(self, store, token: str, inspector):
        mint = self.api("_mint_cycle_run_token")
        with mock.patch.object(WORKER, "_mint_cycle_run_token", return_value=token):
            start = store.allocate_start(process_inspector=inspector)
        self.assertEqual(token, start["run_token"])
        return start

    @staticmethod
    def dead_inspector(_binding: dict) -> str:
        return "dead"

    @staticmethod
    def live_inspector(_binding: dict) -> str:
        return "live"

    @staticmethod
    def unavailable_inspector(_binding: dict) -> str:
        return "unavailable"

    def finish(self, store, start: dict, *, pid: int = 4321) -> tuple[dict, dict]:
        launch = store.publish_launch(
            start,
            pid=pid,
            boot_id="boot-identity-1",
            process_start_time="90123",
            argv=["collector", "--password", TEST_SECRET_ONE, "--scope", SCOPE],
            context={"scope": SCOPE, "password": TEST_SECRET_ONE},
            credential_argv_positions=(2,),
            credential_context_names=("password",),
        )
        completion = store.publish_completion(start, successful_cycle_result(start))
        return launch, completion

    def allocate_finished(self, store, token: str) -> tuple[dict, dict, dict]:
        start = self.allocate(store, token, self.dead_inspector)
        launch, completion = self.finish(store, start)
        return start, launch, completion

    def assert_hold(self, call, reason: str) -> None:
        error_type = self.api("CollectionCycleHoldError")
        with self.assertRaises(error_type) as raised:
            call()
        self.assertIn(reason, str(raised.exception))

    def test_final_record_publication_is_private_durable_and_no_clobber(self):
        publish = self.api("durable_publish_collection_cycle_json")
        with tempfile.TemporaryDirectory() as td:
            record_dir = Path(td) / "status" / "collection-cycles" / PROJECT_KEY
            target = record_dir / "00000000000000000001.start.json"
            events: list[tuple[str, object]] = []
            real_fsync = os.fsync
            real_link = os.link

            def fsync(fd: int):
                mode = os.fstat(fd).st_mode
                events.append(("fsync", "dir" if stat.S_ISDIR(mode) else "file"))
                return real_fsync(fd)

            def link(source, destination, *args, **kwargs):
                events.append(("link", Path(destination).name))
                return real_link(source, destination, *args, **kwargs)

            with mock.patch.object(WORKER.os, "fsync", side_effect=fsync), \
                    mock.patch.object(WORKER.os, "link", side_effect=link), \
                    mock.patch.object(
                        WORKER.os, "replace",
                        side_effect=AssertionError("os.replace is forbidden for final records"),
                    ):
                publish(target, {"kind": "start", "sequence": 1})

            self.assertEqual(0o700, stat.S_IMODE(record_dir.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
            self.assertEqual({"kind": "start", "sequence": 1}, read_json(target))
            self.assertIn(("fsync", "file"), events)
            self.assertIn(("link", target.name), events)
            self.assertEqual(("fsync", "dir"), events[-1])
            self.assertLess(events.index(("fsync", "file")), events.index(("link", target.name)))
            with self.assertRaises(FileExistsError):
                publish(target, {"kind": "start", "sequence": 999})
            self.assertEqual(1, read_json(target)["sequence"])

    def test_witness_publication_is_atomic_private_durable_and_leaves_no_temp(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            events: list[tuple[str, object]] = []
            real_fsync = os.fsync
            real_link = os.link
            real_rename = os.rename
            real_replace = os.replace

            def fsync(fd: int):
                mode = os.fstat(fd).st_mode
                events.append(("fsync", "dir" if stat.S_ISDIR(mode) else "file"))
                return real_fsync(fd)

            def publish(kind, implementation, source, destination, *args, **kwargs):
                if Path(destination) == store.witness_path:
                    events.append(("witness_publish", kind))
                return implementation(source, destination, *args, **kwargs)

            with mock.patch.object(WORKER.os, "fsync", side_effect=fsync), \
                    mock.patch.object(
                        WORKER.os, "link",
                        side_effect=lambda source, destination, *args, **kwargs:
                        publish("link", real_link, source, destination, *args, **kwargs),
                    ), \
                    mock.patch.object(
                        WORKER.os, "rename",
                        side_effect=lambda source, destination, *args, **kwargs:
                        publish("rename", real_rename, source, destination, *args, **kwargs),
                    ), \
                    mock.patch.object(
                        WORKER.os, "replace",
                        side_effect=lambda source, destination, *args, **kwargs:
                        publish("replace", real_replace, source, destination, *args, **kwargs),
                    ):
                start = self.allocate(store, TOKEN_1, self.dead_inspector)

            witness_publish = next(
                index for index, event in enumerate(events)
                if event[0] == "witness_publish"
            )
            self.assertIn(("fsync", "file"), events[:witness_publish])
            self.assertIn(("fsync", "dir"), events[witness_publish + 1:])
            self.assertEqual(0o700, stat.S_IMODE(store.status_dir.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(store.witness_path.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(store.start_path(1).stat().st_mode))
            self.assertEqual(
                {store.witness_path, store.start_path(1)},
                {path for path in store.status_dir.rglob("*") if path.is_file()},
            )
            self.assertEqual(1, start["sequence"])

    def test_first_run_is_distinct_and_witness_is_write_ahead_outside_records(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            store.status_dir.mkdir(parents=True, mode=0o700)
            self.assertFalse(store.records_dir.exists())
            self.assertFalse(store.witness_path.exists())
            self.assertIn(store.status_dir, store.witness_path.parents)
            self.assertNotIn(store.records_dir, store.witness_path.parents)

            calls: list[tuple[str, int]] = []
            write_witness = store._write_witness
            publish_start = store._publish_start

            def witness(sequence: int):
                calls.append(("witness", sequence))
                return write_witness(sequence)

            def start(identity: dict):
                calls.append(("start", identity["sequence"]))
                return publish_start(identity)

            with mock.patch.object(store, "_write_witness", side_effect=witness), \
                    mock.patch.object(store, "_publish_start", side_effect=start):
                allocated = self.allocate(store, TOKEN_1, self.dead_inspector)

            self.assertEqual(1, allocated["sequence"])
            self.assertEqual([("witness", 1), ("start", 1)], calls)
            self.assertEqual(1, read_json(store.witness_path)["high_water"])
            self.assertEqual(0o700, stat.S_IMODE(store.status_dir.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(store.witness_path.stat().st_mode))
            self.assertTrue(store.start_path(1).is_file())

    def test_project_and_scope_keys_are_isolated_for_the_fixed_source(self):
        with tempfile.TemporaryDirectory() as td:
            status_dir = Path(td) / "monitor" / "status"
            stores = []
            starts = []
            for project_identity, scope in (
                (PROJECT_IDENTITY, "prod"),
                (PROJECT_IDENTITY, "air"),
                (OTHER_PROJECT_IDENTITY, "prod"),
            ):
                local_stack = ExitStack()
                gate = local_stack.enter_context(WORKER.CollectionGate(
                    project_identity,
                    scope,
                    status_dir=status_dir,
                    enforce_cooldown=False,
                    lane="collection",
                ))
                store = self.api("CollectionCycleStore")(
                    gate=gate, source=SOURCE,
                )
                start = self.allocate(store, TOKEN_1, self.dead_inspector)
                local_stack.close()
                stores.append(store)
                starts.append(start)

            self.assertEqual([1, 1, 1], [start["sequence"] for start in starts])
            self.assertEqual(3, len({store.witness_path for store in stores}))
            self.assertEqual(3, len({store.records_dir for store in stores}))
            expected_keys = (
                (PROJECT_KEY, "prod"),
                (PROJECT_KEY, "air"),
                (OTHER_PROJECT_KEY, "prod"),
            )
            for store, start, (project_key, scope) in zip(
                stores, starts, expected_keys,
            ):
                self.assertEqual(project_key, start["project_key"])
                self.assertEqual(scope, start["scope"])
                self.assertEqual(SOURCE, start["source"])
                self.assertEqual(1, read_json(store.witness_path)["high_water"])
                self.assertTrue(store.start_path(1).is_file())

    def test_no_witness_with_preexisting_empty_records_dir_is_true_first_run(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            store.records_dir.mkdir(parents=True, mode=0o700)
            self.assertEqual([], list(store.records_dir.iterdir()))
            self.assertFalse(store.witness_path.exists())

            start = self.allocate(store, TOKEN_1, self.dead_inspector)
            self.assertEqual(1, start["sequence"])
            self.assertEqual(1, read_json(store.witness_path)["high_water"])
            self.assertTrue(store.start_path(1).is_file())

    def test_write_ahead_witness_survives_start_failure_and_blocks_reuse(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            with mock.patch.object(
                store, "_publish_start", side_effect=OSError("injected start failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected start failure"):
                    self.allocate(store, TOKEN_1, self.dead_inspector)

            self.assertEqual(1, read_json(store.witness_path)["high_water"])
            self.assertFalse(store.start_path(1).exists())
            witness_before = store.witness_path.read_bytes()
            self.assert_hold(
                lambda: self.allocate(store, TOKEN_2, self.dead_inspector),
                "witness has no matching start",
            )
            self.assertEqual(witness_before, store.witness_path.read_bytes())
            self.assertFalse(store.start_path(1).exists())

    def test_mint_then_witness_crash_leaves_bytes_unchanged_and_reuses_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            self.allocate_finished(store, TOKEN_1)
            witness_before = store.witness_path.read_bytes()
            records_before = {
                path.name: path.read_bytes()
                for path in store.records_dir.iterdir()
            }
            events = []

            def mint_token():
                events.append("mint")
                return TOKEN_2

            def crash_witness(_sequence):
                events.append("witness")
                raise OSError("mint-window crash")

            with mock.patch.object(
                WORKER, "_mint_cycle_run_token", side_effect=mint_token,
            ), mock.patch.object(
                store, "_write_witness", side_effect=crash_witness,
            ):
                with self.assertRaisesRegex(OSError, "mint-window crash"):
                    store.allocate_start(process_inspector=self.dead_inspector)

            self.assertEqual(["mint", "witness"], events)
            self.assertEqual(witness_before, store.witness_path.read_bytes())
            self.assertEqual(
                records_before,
                {
                    path.name: path.read_bytes()
                    for path in store.records_dir.iterdir()
                },
            )
            self.assertFalse(store.start_path(2).exists())

            next_start = self.allocate(store, TOKEN_3, self.dead_inspector)
            self.assertEqual(2, next_start["sequence"])
            self.assertEqual(TOKEN_3, next_start["run_token"])

    def test_clean_state_allocates_witness_plus_one_and_never_decreases(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            first, _launch, _completion = self.allocate_finished(store, TOKEN_1)
            second = self.allocate(store, TOKEN_2, self.dead_inspector)
            self.assertEqual(first["sequence"] + 1, second["sequence"])
            self.assertEqual(2, read_json(store.witness_path)["high_water"])
            for forbidden in (2, 1):
                with self.subTest(forbidden=forbidden), \
                        self.assertRaises((ValueError, OSError)):
                    store._write_witness(forbidden)
            self.assertEqual(2, read_json(store.witness_path)["high_water"])

    def test_missing_corrupt_and_below_max_witness_each_hold_without_allocation(self):
        cases = {
            "missing": None,
            "empty": b"",
            "invalid_json": b"not-json\n",
            "bool": b'{"high_water":true}\n',
            "float": b'{"high_water":1.0}\n',
            "string": b'{"high_water":"1"}\n',
            "null": b'{"high_water":null}\n',
            "zero": b'{"high_water":0}\n',
            "negative": b'{"high_water":-1}\n',
            "extra_key": b'{"high_water":1,"extra":true}\n',
            "below_record_max": b'{"high_water":1}\n',
        }
        for case, replacement in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                store = self.store(Path(td) / "monitor" / "status")
                self.allocate_finished(store, TOKEN_1)
                if case == "below_record_max":
                    self.allocate_finished(store, TOKEN_2)
                before = sorted(store.records_dir.iterdir())
                if case == "missing":
                    store.witness_path.unlink()
                    reason = "witness absent with records"
                else:
                    assert replacement is not None
                    store.witness_path.write_bytes(replacement)
                    reason = (
                        "witness below record maximum"
                        if case == "below_record_max" else "witness corrupt"
                    )
                witness_exists = store.witness_path.exists()
                witness_bytes = (
                    store.witness_path.read_bytes() if witness_exists else None
                )

                self.assert_hold(
                    lambda: self.allocate(store, TOKEN_2, self.dead_inspector),
                    reason,
                )
                self.assertEqual(before, sorted(store.records_dir.iterdir()))
                self.assertEqual(witness_exists, store.witness_path.exists())
                if witness_exists:
                    self.assertEqual(witness_bytes, store.witness_path.read_bytes())

    def test_internal_gap_highest_pair_deletion_and_older_prefix_restore_hold(self):
        token_4 = "abcdef0123454abc8def0123456789ab"
        for case in ("internal_gap", "highest_pair_deleted", "older_prefix"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                store = self.store(Path(td) / "monitor" / "status")
                self.allocate_finished(store, TOKEN_1)
                prefix = {
                    path.name: path.read_bytes()
                    for path in store.records_dir.iterdir()
                }
                self.allocate_finished(store, TOKEN_2)
                self.allocate_finished(store, TOKEN_3)

                if case == "internal_gap":
                    for path in (store.start_path(2), store.launch_path(2),
                                 store.completion_path(2)):
                        path.unlink()
                    reason = "record gap"
                elif case == "highest_pair_deleted":
                    # Delete every highest-sequence record.  The remaining
                    # prefix is complete, so only the high-water witness can
                    # prove that this is a rollback.
                    for path in (store.start_path(3), store.launch_path(3),
                                 store.completion_path(3)):
                        path.unlink()
                    reason = "record maximum below witness"
                else:
                    for path in tuple(store.records_dir.iterdir()):
                        path.unlink()
                    for name, data in prefix.items():
                        (store.records_dir / name).write_bytes(data)
                    reason = "record maximum below witness"

                before_names = sorted(path.name for path in store.records_dir.iterdir())
                self.assert_hold(
                    lambda: self.allocate(store, token_4, self.dead_inspector),
                    reason,
                )
                self.assertEqual(
                    before_names,
                    sorted(path.name for path in store.records_dir.iterdir()),
                )
                self.assertEqual(3, read_json(store.witness_path)["high_water"])

    def test_start_launch_completion_are_separate_and_launch_never_completes(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            start = self.allocate(store, TOKEN_1, self.dead_inspector)
            self.assertTrue(store.start_path(1).is_file())
            self.assertFalse(store.launch_path(1).exists())
            self.assertFalse(store.completion_path(1).exists())

            launch = store.publish_launch(
                start,
                pid=4321,
                boot_id="boot-identity-1",
                process_start_time="90123",
                argv=["collector", "--password", TEST_SECRET_ONE],
                context={"password": TEST_SECRET_ONE, "scope": SCOPE},
                credential_argv_positions=(2,),
                credential_context_names=("password",),
            )
            self.assertEqual(4321, launch["pid"])
            self.assertEqual("boot-identity-1", launch["boot_id"])
            self.assertEqual("90123", launch["process_start_time"])
            self.assertTrue(store.launch_path(1).is_file())
            self.assertFalse(store.completion_path(1).exists())
            self.assertEqual([], store.qualifying_completions())

            inspected: list[dict] = []

            def exact_token_live(binding: dict) -> str:
                inspected.append(binding)
                return "live"

            self.assert_hold(
                lambda: self.allocate(store, TOKEN_2, exact_token_live),
                "exact-token child live",
            )
            self.assertEqual(1, len(inspected))
            self.assertEqual(TOKEN_1, inspected[0]["run_token"])
            self.assertEqual(4321, inspected[0]["pid"])
            self.assertEqual("boot-identity-1", inspected[0]["boot_id"])
            self.assertEqual("90123", inspected[0]["process_start_time"])
            self.assertRegex(inspected[0]["invocation_digest"], r"^[0-9a-f]{64}$")
            self.assertEqual(launch["invocation_digest"], inspected[0]["invocation_digest"])

    def test_completion_accepts_only_full_worker_derived_validated_summary(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            first = self.allocate(store, TOKEN_1, self.dead_inspector)
            store.publish_launch(
                first,
                pid=4321,
                boot_id="boot-identity-1",
                process_start_time="90123",
                argv=["collector"],
                context={"scope": SCOPE},
                credential_argv_positions=(),
                credential_context_names=(),
            )
            forged = {
                "state": "success",
                "qualifying": True,
                "complete_empty": False,
            }
            with self.assertRaises(ValueError):
                store.publish_completion(first, forged)
            self.assertFalse(store.completion_path(1).exists())

            mismatched = successful_cycle_result(first)
            mismatched["identity"] = dict(mismatched["identity"])
            mismatched["identity"]["run_token"] = TOKEN_2
            with self.assertRaises(ValueError):
                store.publish_completion(first, mismatched)
            self.assertFalse(store.completion_path(1).exists())

            run_result = successful_cycle_result(first)
            completion = store.publish_completion(first, run_result)
            self.assertEqual("cycle_completed", completion["outcome"])
            self.assertEqual(run_result, completion["run_result"])
            self.assertEqual(cycle_identity(first), completion["identity"])
            self.assertEqual(completion, read_json(store.completion_path(1)))
            self.assertEqual(
                [run_result["summary"]], store.qualifying_completions()
            )

    def test_launch_and_completion_are_no_clobber(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            start = self.allocate(store, TOKEN_1, self.dead_inspector)
            start_before = store.start_path(1).read_bytes()
            with self.assertRaises(FileExistsError):
                store._publish_start(start)
            self.assertEqual(start_before, store.start_path(1).read_bytes())
            launch_kwargs = {
                "pid": 4321,
                "boot_id": "boot-identity-1",
                "process_start_time": "90123",
                "argv": ["collector"],
                "context": {"scope": SCOPE},
                "credential_argv_positions": (),
                "credential_context_names": (),
            }
            store.publish_launch(start, **launch_kwargs)
            launch_before = store.launch_path(1).read_bytes()
            with self.assertRaises(FileExistsError):
                store.publish_launch(start, **{**launch_kwargs, "pid": 9999})
            self.assertEqual(launch_before, store.launch_path(1).read_bytes())

            run_result = successful_cycle_result(start)
            store.publish_completion(start, run_result)
            completion_before = store.completion_path(1).read_bytes()
            with self.assertRaises(FileExistsError):
                store.publish_completion(start, run_result)
            self.assertEqual(
                completion_before,
                store.completion_path(1).read_bytes(),
            )

            witness_before = store.witness_path.read_bytes()
            records_before = {
                path.name: path.read_bytes()
                for path in store.records_dir.iterdir()
            }
            self.assert_hold(
                lambda: self.allocate(store, TOKEN_1, self.dead_inspector),
                "run_token_collision",
            )
            self.assertEqual(witness_before, store.witness_path.read_bytes())
            self.assertEqual(
                records_before,
                {
                    path.name: path.read_bytes()
                    for path in store.records_dir.iterdir()
                },
            )

    def test_orphan_tamper_and_identity_association_mismatch_each_hold_unchanged(self):
        cases = (
            "orphan_launch", "orphan_completion", "tampered_start",
            "mismatched_launch", "mismatched_completion",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                store = self.store(Path(td) / "monitor" / "status")
                start = self.allocate(store, TOKEN_1, self.dead_inspector)
                store.publish_launch(
                    start,
                    pid=4321,
                    boot_id="boot-identity-1",
                    process_start_time="90123",
                    argv=["collector"],
                    context={"scope": SCOPE},
                    credential_argv_positions=(),
                    credential_context_names=(),
                )
                if case == "orphan_launch":
                    store.start_path(1).unlink()
                elif case == "orphan_completion":
                    store.publish_completion(
                        start,
                        successful_cycle_result(start),
                    )
                    store.start_path(1).unlink()
                    store.launch_path(1).unlink()
                elif case == "tampered_start":
                    store.start_path(1).write_bytes(b'{"kind":"start"}\n')
                elif case == "mismatched_launch":
                    launch = read_json(store.launch_path(1))
                    launch["run_token"] = TOKEN_2
                    store.launch_path(1).write_text(
                        json.dumps(launch, sort_keys=True, separators=(",", ":"))
                        + "\n",
                        encoding="utf-8",
                    )
                else:
                    store.publish_completion(
                        start,
                        successful_cycle_result(start),
                    )
                    completion = read_json(store.completion_path(1))
                    completion["identity"]["run_token"] = TOKEN_2
                    store.completion_path(1).write_text(
                        json.dumps(
                            completion, sort_keys=True, separators=(",", ":"),
                        ) + "\n",
                        encoding="utf-8",
                    )

                witness_before = store.witness_path.read_bytes()
                records_before = {
                    path.name: path.read_bytes()
                    for path in store.records_dir.iterdir()
                }
                error_type = self.api("CollectionCycleHoldError")
                with self.assertRaises(error_type):
                    self.allocate(store, TOKEN_2, self.dead_inspector)
                self.assertEqual(witness_before, store.witness_path.read_bytes())
                self.assertEqual(
                    records_before,
                    {
                        path.name: path.read_bytes()
                        for path in store.records_dir.iterdir()
                    },
                )

    def test_missing_launch_live_child_and_unavailable_inspection_each_hold(self):
        scenarios = (
            (False, self.dead_inspector, "launch record missing"),
            (True, self.live_inspector, "exact-token child live"),
            (True, self.unavailable_inspector, "process inspection unavailable"),
        )
        for publish_launch, inspector, reason in scenarios:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as td:
                store = self.store(Path(td) / "monitor" / "status")
                start = self.allocate(store, TOKEN_1, self.dead_inspector)
                if publish_launch:
                    store.publish_launch(
                        start,
                        pid=4321,
                        boot_id="boot-identity-1",
                        process_start_time="90123",
                        argv=["collector"],
                        context={"scope": SCOPE},
                        credential_argv_positions=(),
                        credential_context_names=(),
                    )
                before = sorted(store.records_dir.iterdir())
                self.assert_hold(
                    lambda: self.allocate(store, TOKEN_2, inspector),
                    reason,
                )
                self.assertEqual(before, sorted(store.records_dir.iterdir()))

    def test_process_inspection_error_and_unexpected_result_hold_without_mutation(self):
        for result in ("error", "unexpected", "", None, True):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as td:
                store = self.store(Path(td) / "monitor" / "status")
                start = self.allocate(store, TOKEN_1, self.dead_inspector)
                store.publish_launch(
                    start,
                    pid=4321,
                    boot_id="boot-identity-1",
                    process_start_time="90123",
                    argv=["collector"],
                    context={"scope": SCOPE},
                    credential_argv_positions=(),
                    credential_context_names=(),
                )
                witness_before = store.witness_path.read_bytes()
                records_before = {
                    path.name: path.read_bytes()
                    for path in store.records_dir.iterdir()
                }
                error_type = self.api("CollectionCycleHoldError")
                with self.assertRaises(error_type):
                    self.allocate(
                        store, TOKEN_2,
                        lambda _binding, value=result: value,
                    )
                self.assertEqual(witness_before, store.witness_path.read_bytes())
                self.assertEqual(
                    records_before,
                    {
                        path.name: path.read_bytes()
                        for path in store.records_dir.iterdir()
                    },
                )

    def test_dead_bound_child_gets_crashed_completion_then_next_sequence(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            start = self.allocate(store, TOKEN_1, self.dead_inspector)
            store.publish_launch(
                start,
                pid=4321,
                boot_id="boot-identity-1",
                process_start_time="90123",
                argv=["collector"],
                context={"scope": SCOPE},
                credential_argv_positions=(),
                credential_context_names=(),
            )

            next_start = self.allocate(store, TOKEN_2, self.dead_inspector)
            crashed = read_json(store.completion_path(1))
            self.assertEqual("cycle_crashed", crashed["outcome"])
            self.assertIsNone(crashed["run_result"])
            self.assertEqual(2, next_start["sequence"])
            with self.assertRaises(FileExistsError):
                store.publish_completion(
                    start,
                    successful_cycle_result(start),
                )
            self.assertEqual(
                "cycle_crashed",
                read_json(store.completion_path(1))["outcome"],
            )

    def test_crash_completion_must_be_durable_before_witness_advances(self):
        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            start = self.allocate(store, TOKEN_1, self.dead_inspector)
            store.publish_launch(
                start,
                pid=4321,
                boot_id="boot-identity-1",
                process_start_time="90123",
                argv=["collector"],
                context={"scope": SCOPE},
                credential_argv_positions=(),
                credential_context_names=(),
            )
            witness_before = store.witness_path.read_bytes()
            records_before = {
                path.name: path.read_bytes()
                for path in store.records_dir.iterdir()
            }
            error_type = self.api("CollectionCycleHoldError")
            with mock.patch.object(
                store,
                "_publish_crashed_completion",
                side_effect=OSError("injected crash-completion failure"),
            ):
                with self.assertRaises((OSError, error_type)):
                    self.allocate(store, TOKEN_2, self.dead_inspector)

            self.assertEqual(witness_before, store.witness_path.read_bytes())
            self.assertEqual(1, read_json(store.witness_path)["high_water"])
            self.assertFalse(store.completion_path(1).exists())
            self.assertFalse(store.start_path(2).exists())
            self.assertEqual(
                records_before,
                {
                    path.name: path.read_bytes()
                    for path in store.records_dir.iterdir()
                },
            )

    def test_pid_boot_and_start_binding_and_credential_redaction_precede_digest(self):
        digest = self.api("redacted_collection_cycle_invocation_digest")
        argv_one = ["collector", "--password", TEST_SECRET_ONE, "--scope", SCOPE]
        argv_two = ["collector", "--password", TEST_SECRET_TWO, "--scope", SCOPE]
        context_one = {"scope": SCOPE, "password": TEST_SECRET_ONE}
        context_two = {"scope": SCOPE, "password": TEST_SECRET_TWO}
        kwargs = {
            "credential_argv_positions": (2,),
            "credential_context_names": ("password",),
        }
        observed_one = digest(argv_one, context_one, **kwargs)
        observed_two = digest(argv_two, context_two, **kwargs)
        self.assertEqual(observed_one, observed_two)
        self.assertRegex(observed_one, r"^[0-9a-f]{64}$")

        redacted = {
            "argv": [
                "collector", "--password", REDACTED_PLACEHOLDER,
                "--scope", SCOPE,
            ],
            "context": {"password": REDACTED_PLACEHOLDER, "scope": SCOPE},
        }
        expected = hashlib.sha256(
            json.dumps(
                redacted, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(expected, observed_one)

        invalid_metadata = (
            {"credential_argv_positions": (), "credential_context_names": ("password",)},
            {"credential_argv_positions": (2,), "credential_context_names": ()},
            {"credential_argv_positions": (2, 2), "credential_context_names": ("password",)},
            {"credential_argv_positions": (True,), "credential_context_names": ("password",)},
            {"credential_argv_positions": (99,), "credential_context_names": ("password",)},
            {"credential_argv_positions": (2,), "credential_context_names": ("password", "password")},
            {"credential_argv_positions": (2,), "credential_context_names": ("missing",)},
        )
        for invalid in invalid_metadata:
            with self.subTest(digest_metadata=invalid), self.assertRaises(ValueError):
                digest(argv_one, context_one, **invalid)

        with tempfile.TemporaryDirectory() as td:
            store = self.store(Path(td) / "monitor" / "status")
            start = self.allocate(store, TOKEN_1, self.dead_inspector)
            for invalid in invalid_metadata:
                with self.subTest(launch_metadata=invalid), self.assertRaises(ValueError):
                    store.publish_launch(
                        start,
                        pid=4321,
                        boot_id="boot-identity-1",
                        process_start_time="90123",
                        argv=argv_one,
                        context=context_one,
                        **invalid,
                    )
                self.assertFalse(store.launch_path(1).exists())
            launch = store.publish_launch(
                start,
                pid=4321,
                boot_id="boot-identity-1",
                process_start_time="90123",
                argv=argv_one,
                context=context_one,
                **kwargs,
            )
            self.assertEqual(expected, launch["invocation_digest"])
            durable = store.launch_path(1).read_text(encoding="utf-8")
            self.assertNotIn("first-secret", durable)
            self.assertNotIn("second-secret", durable)
            self.assertNotIn("<redacted>", durable)

    def test_production_parser_refuses_external_run_token(self):
        parser = WORKER.parser()
        with mock.patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit) as raised:
                parser.parse_args(["--scope", SCOPE, "--run-token", TOKEN_1])
        self.assertEqual(2, raised.exception.code)

    def test_completion_outcome_is_disjoint_from_child_and_slot_vocabularies(self):
        outcomes = set(self.api("COLLECTION_CYCLE_COMPLETION_OUTCOMES"))
        slot_outcomes = set(WORKER.COLLECTION_SLOT_TERMINAL_OUTCOMES)
        child_states = set(WORKER.COLLECTION_SLOT_CHILD_STATES)
        self.assertEqual({"cycle_completed", "cycle_crashed"}, outcomes)
        self.assertFalse(outcomes & slot_outcomes)
        self.assertFalse(outcomes & child_states)
        self.assertFalse(slot_outcomes & child_states)


if __name__ == "__main__":
    unittest.main()
