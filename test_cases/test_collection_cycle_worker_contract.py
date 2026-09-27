#!/usr/bin/env python3
"""Direct contract for collection-cycle parsing and lifecycle wrappers."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MONITOR = ROOT / "monitor"
TOOLS = ROOT / "tools"
for path in (str(MONITOR), str(TOOLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from project_contract import (
    COLLECTION_CYCLE_FAILED_DEVICE_OPERATIONS,
    COLLECTION_CYCLE_MAX_FAILED_DEVICES,
    COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES,
    YAML_BACKUP_FAILED_DEVICE_OPERATIONS,
)


def load_worker():
    spec = importlib.util.spec_from_file_location(
        "collection_cycle_worker_contract_target",
        MONITOR / "switch-collection-worker.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


WORKER = load_worker()
PREFIX = "[HTTP_ZTP_TASK_RESULT] "
COLLECTION_OPERATIONS = COLLECTION_CYCLE_FAILED_DEVICE_OPERATIONS
BACKUP_OPERATIONS = YAML_BACKUP_FAILED_DEVICE_OPERATIONS
IDENTITY = {
    "project_key": hashlib.sha256(b"/fixture-project").hexdigest(),
    "run_token": "12345678123442348123456789abcdef",
    "scope": "prod",
    "sequence": 7,
    "source": "switch_collection",
}
IDENTITY["cycle_id"] = hashlib.sha256(json.dumps(
    IDENTITY, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
).encode("utf-8")).hexdigest()


def marker(payload: dict) -> str:
    return PREFIX + json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ) + "\n"


def legacy(*, state: str = "success") -> dict:
    if state == "failed":
        return {
            "schema_version": 1,
            "task": "switch_collection",
            "state": "failed",
            "planned": 1,
            "succeeded": 0,
            "failed_count": 1,
            "failed_devices": [{
                "hostname": "leaf01",
                "operation": "collection,ssh_prepare",
                "reason": "界" * 1024,
            }],
        }
    return {
        "schema_version": 1,
        "task": "switch_collection",
        "state": "success",
        "planned": 0,
        "succeeded": 0,
        "failed_count": 0,
        "failed_devices": [],
    }


def v2(slot: str) -> dict:
    return {
        "schema_version": 2,
        "task": "switch_collection",
        **IDENTITY,
        "source_slot": slot,
        "state": "success",
        "planned": 0,
        "succeeded": 0,
        "failed_count": 0,
        "failed_devices": [],
        "evidence": {
            "sha256": hashlib.sha256(b"evidence").hexdigest(),
            "size_bytes": len(b"evidence"),
        },
        "envelope": {
            "sha256": hashlib.sha256(b"envelope").hexdigest(),
            "size_bytes": len(b"envelope"),
        },
        "input_inventory_sha256": hashlib.sha256(b"inventory").hexdigest(),
    }


class CollectionCycleWorkerContractTests(unittest.TestCase):
    def test_setup_managed_selected_p2p_symlink_freezes_real_stem_and_rejects_retarget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / "fixture-project"
            project.mkdir(parents=True)
            selected = project / "selected-fabric.xlsx"
            selected.write_bytes(b"independent selected workbook bytes")
            canonical = project / "p2p.xlsx"
            canonical.symlink_to(selected.name)
            p2p = root / "ztp/config/cumulus/template/P2P"
            output = p2p / "output-p2p"
            output.mkdir(parents=True)
            fixed = p2p / "p2p.xlsx"
            fixed.symlink_to(os.path.relpath(canonical, p2p))
            dot = output / "selected-fabric-lldpq.dot"
            dot.write_bytes(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n')
            (p2p / "01-inventory.log").write_bytes(b"[Eth-SW]\nleaf-*\n")
            aliases = root / "tools/lldp-analyze-tool/04-lldp-device-aliases.json"
            aliases.parent.mkdir(parents=True)
            aliases.write_bytes(b'{"schema_version":1,"canonical_to_aliases":{}}')
            with mock.patch.object(WORKER, "HTTP_ROOT", root):
                bindings = WORKER._collection_managed_bindings(IDENTITY, "ethernet/prod")
                Path(bindings["input_inventory"]).parent.mkdir(parents=True)
                activity = WORKER._collection_snapshot_activity_sources(
                    "ethernet/prod", bindings,
                )
            self.assertIsNotNone(activity, "setup-managed real-stem DOT must be selected")
            self.assertEqual(selected.read_bytes(), Path(activity["topology"]["path"]).read_bytes())
            self.assertEqual(dot.read_bytes(), Path(activity["sources"]["dot"]["path"]).read_bytes())

            # A different project/source cannot be adopted by retargeting a
            # setup-managed name during the same freeze transaction.
            foreign = root / "outside.xlsx"
            foreign.write_bytes(selected.read_bytes())
            original_freeze = WORKER._collection_freeze_activity_member
            def move_after_first(source, destination, *, maximum):
                digest = original_freeze(source, destination, maximum=maximum)
                if source.resolve(strict=True) == selected.resolve(strict=True):
                    canonical.unlink()
                    canonical.symlink_to(os.path.relpath(foreign, project))
                return digest
            with mock.patch.object(WORKER, "HTTP_ROOT", root):
                second_identity = {**IDENTITY, "sequence": IDENTITY["sequence"] + 1}
                second_bindings = WORKER._collection_managed_bindings(
                    second_identity, "ethernet/prod",
                )
                Path(second_bindings["input_inventory"]).parent.mkdir(parents=True)
                with mock.patch.object(
                    WORKER, "_collection_freeze_activity_member",
                    side_effect=move_after_first,
                ):
                    with self.assertRaises(ValueError):
                        WORKER._collection_snapshot_activity_sources(
                            "ethernet/prod", second_bindings,
                        )
                # The same foreign target must also be rejected before launch.
                with self.assertRaises(ValueError):
                    WORKER._collection_snapshot_activity_sources(
                        "ethernet/prod", second_bindings,
                    )

                canonical.unlink()
                canonical.symlink_to(selected.name)
                wrong_name = output / "p2p-lldpq.dot"
                dot.rename(wrong_name)
                with self.assertRaisesRegex(ValueError, "matching DOT is missing"):
                    WORKER._collection_snapshot_activity_sources(
                        "ethernet/prod", second_bindings,
                    )
                wrong_name.rename(dot)

                other_project = root / "DAY0-Prepare/other-project"
                other_project.mkdir()
                other_selected = other_project / selected.name
                other_selected.write_bytes(selected.read_bytes())
                other_canonical = other_project / "p2p.xlsx"
                other_canonical.symlink_to(other_selected.name)
                third_identity = {**IDENTITY, "sequence": IDENTITY["sequence"] + 2}
                third_bindings = WORKER._collection_managed_bindings(
                    third_identity, "ethernet/prod",
                )
                Path(third_bindings["input_inventory"]).parent.mkdir(parents=True)
                def move_outer(source, destination, *, maximum):
                    digest = original_freeze(source, destination, maximum=maximum)
                    if source.resolve(strict=True) == selected.resolve(strict=True):
                        fixed.unlink()
                        fixed.symlink_to(os.path.relpath(other_canonical, p2p))
                    return digest
                with mock.patch.object(
                    WORKER, "_collection_freeze_activity_member",
                    side_effect=move_outer,
                ):
                    with self.assertRaisesRegex(ValueError, "selection changed"):
                        WORKER._collection_snapshot_activity_sources(
                            "ethernet/prod", third_bindings,
                        )

                fixed.unlink()
                fixed.symlink_to(os.path.relpath(canonical, p2p))
                fourth_identity = {**IDENTITY, "sequence": IDENTITY["sequence"] + 3}
                fourth_bindings = WORKER._collection_managed_bindings(
                    fourth_identity, "ethernet/prod",
                )
                Path(fourth_bindings["input_inventory"]).parent.mkdir(parents=True)
                original_bytes = selected.read_bytes()
                def rewrite_same_length(source, destination, *, maximum):
                    digest = original_freeze(source, destination, maximum=maximum)
                    if source.resolve(strict=True) == selected.resolve(strict=True):
                        selected.write_bytes(b"X" * len(original_bytes))
                    return digest
                with mock.patch.object(
                    WORKER, "_collection_freeze_activity_member",
                    side_effect=rewrite_same_length,
                ):
                    with self.assertRaisesRegex(ValueError, "selected workbook identity changed"):
                        WORKER._collection_snapshot_activity_sources(
                            "ethernet/prod", fourth_bindings,
                        )

    def test_worker_freezes_exact_eth_plan_sources_before_collector_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            p2p = root / "ztp/config/cumulus/template/P2P"
            output = p2p / "output-p2p"
            output.mkdir(parents=True)
            workbook = p2p / "p2p.xlsx"
            workbook.write_bytes(b"literal topology plan bytes")
            dot = output / "p2p-lldpq.dot"
            dot.write_bytes(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n')
            inventory = p2p / "01-inventory.log"
            inventory.write_bytes(b"[Eth-SW]\nleaf-*\n")
            aliases = root / "tools/lldp-analyze-tool/04-lldp-device-aliases.json"
            aliases.parent.mkdir(parents=True)
            aliases.write_bytes(b'{"schema_version":1,"canonical_to_aliases":{}}')
            with mock.patch.object(WORKER, "HTTP_ROOT", root):
                bindings = WORKER._collection_managed_bindings(
                    IDENTITY, "ethernet/prod",
                )
                private = Path(bindings["input_inventory"]).parent
                private.mkdir(parents=True)
                activity = WORKER._collection_snapshot_activity_sources(
                    "ethernet/prod", bindings,
                )
            self.assertEqual("ethernet/prod", activity["source_slot"])
            self.assertEqual({"dot", "inventory", "device_aliases"},
                             set(activity["sources"]))
            for role, original in (
                ("dot", dot), ("inventory", inventory),
                ("device_aliases", aliases),
            ):
                frozen = Path(activity["sources"][role]["path"])
                self.assertEqual(original.read_bytes(), frozen.read_bytes())
                self.assertEqual(hashlib.sha256(frozen.read_bytes()).hexdigest(),
                                 activity["sources"][role]["sha256"])
            frozen_plan = Path(activity["topology"]["path"])
            self.assertEqual(workbook.read_bytes(), frozen_plan.read_bytes())
            self.assertEqual(hashlib.sha256(frozen_plan.read_bytes()).hexdigest(),
                             activity["topology"]["sha256"])

    def test_backup_task_parser_rejects_zero_planned_without_rejecting_empty_collection_slot(self):
        zero = legacy()
        zero["task"] = "yaml_backup"
        with self.assertRaisesRegex(ValueError, "zero planned devices"):
            WORKER.parse_task_result(
                marker(zero), "yaml_backup",
                permitted_operations=BACKUP_OPERATIONS,
            )

        zero["task"] = "switch_collection"
        self.assertEqual(
            zero,
            WORKER.parse_task_result(
                marker(zero), "switch_collection",
                permitted_operations=COLLECTION_OPERATIONS,
            ),
        )

    def test_shared_legacy_parser_consumes_only_bounds_and_preserves_backup_operations(self):
        source = (MONITOR / "switch-collection-worker.py").read_text(encoding="utf-8")
        self.assertNotIn("MAX_TASK_RESULT_DEVICES = 10000", source)
        self.assertNotIn("MAX_TASK_RESULT_TEXT_BYTES = 1024", source)
        self.assertEqual(
            COLLECTION_CYCLE_MAX_FAILED_DEVICES,
            WORKER.MAX_TASK_RESULT_DEVICES,
        )
        self.assertEqual(
            COLLECTION_CYCLE_MAX_FAILED_DEVICE_TEXT_BYTES,
            WORKER.MAX_TASK_RESULT_TEXT_BYTES,
        )

        for operation in ("yaml_backup", "connect"):
            payload = {
                "schema_version": 1,
                "task": "yaml_backup",
                "state": "failed",
                "planned": 1,
                "succeeded": 0,
                "failed_count": 1,
                "failed_devices": [{
                    "hostname": "leaf-backup",
                    "operation": operation,
                    "reason": "backup unavailable",
                }],
            }
            self.assertEqual(
                payload,
                WORKER.parse_task_result(
                    marker(payload), "yaml_backup",
                    permitted_operations=BACKUP_OPERATIONS,
                ),
            )

            collection_payload = legacy(state="failed")
            collection_payload["failed_devices"][0]["operation"] = operation
            with self.assertRaises(WORKER.CollectionSlotParseError):
                WORKER.parse_collection_slot_result(
                    marker(collection_payload),
                    expected_context=IDENTITY,
                    expected_slot="ethernet/prod",
                )

    def test_shared_legacy_parser_requires_explicit_closed_lane_authority(self):
        parameters = inspect.signature(WORKER.parse_task_result).parameters
        self.assertEqual(
            inspect.Parameter.KEYWORD_ONLY,
            parameters["permitted_operations"].kind,
        )
        self.assertIs(
            inspect.Parameter.empty,
            parameters["permitted_operations"].default,
        )
        self.assertEqual(("collection", "ssh_prepare"), COLLECTION_OPERATIONS)
        self.assertEqual(("connect", "yaml_backup"), BACKUP_OPERATIONS)

        collection = legacy(state="failed")
        collection["failed_devices"][0]["reason"] = "unreachable"
        backup = copy.deepcopy(collection)
        backup["task"] = "yaml_backup"
        backup["failed_devices"][0]["operation"] = "connect,yaml_backup"

        self.assertEqual(
            collection,
            WORKER.parse_task_result(
                marker(collection), "switch_collection",
                permitted_operations=COLLECTION_OPERATIONS,
            ),
        )
        self.assertEqual(
            backup,
            WORKER.parse_task_result(
                marker(backup), "yaml_backup",
                permitted_operations=BACKUP_OPERATIONS,
            ),
        )

        for payload, task, authority in (
            (collection, "switch_collection", BACKUP_OPERATIONS),
            (backup, "yaml_backup", COLLECTION_OPERATIONS),
        ):
            with self.subTest(task=task), self.assertRaisesRegex(
                ValueError, "operation"
            ):
                WORKER.parse_task_result(
                    marker(payload), task,
                    permitted_operations=authority,
                )

        for invalid_authority in (
            (),
            ("collection", "collection"),
            ("ssh_prepare", "collection"),
            ("Collection",),
            ("ssh-prepare",),
            ("",),
            ["collection"],
        ):
            with self.subTest(authority=invalid_authority), self.assertRaisesRegex(
                ValueError, "permitted_operations"
            ):
                WORKER.parse_task_result(
                    marker(collection), "switch_collection",
                    permitted_operations=invalid_authority,
                )

        for invalid_operation in (
            "collection,collection",
            "ssh_prepare,collection",
            "collection,",
            ",collection",
            "retrieve_info",
        ):
            invalid = copy.deepcopy(collection)
            invalid["failed_devices"][0]["operation"] = invalid_operation
            with self.subTest(operation=invalid_operation), self.assertRaisesRegex(
                ValueError, "operation"
            ):
                WORKER.parse_task_result(
                    marker(invalid), "switch_collection",
                    permitted_operations=COLLECTION_OPERATIONS,
                )

    def test_yaml_backup_production_caller_passes_its_lane_authority(self):
        source = (MONITOR / "switch-collection-worker.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("YAML_BACKUP_FAILED_DEVICE_OPERATIONS", source)
        self.assertIn(
            'parse_task_result(\n'
            '                result["stdout"], "yaml_backup",\n'
            '                permitted_operations=YAML_BACKUP_FAILED_DEVICE_OPERATIONS,\n'
            '            )',
            source,
        )

    def test_lifecycle_vocabulary_is_closed_unique_and_disjoint(self):
        child = WORKER.COLLECTION_SLOT_CHILD_STATES
        outcomes = WORKER.COLLECTION_SLOT_TERMINAL_OUTCOMES
        self.assertIsInstance(child, tuple)
        self.assertIsInstance(outcomes, tuple)
        self.assertEqual(("success", "partial", "failed"), child)
        self.assertEqual(len(child), len(set(child)))
        self.assertEqual(len(outcomes), len(set(outcomes)))
        self.assertFalse(set(child) & set(outcomes))
        self.assertEqual({
            "accepted", "cancelled", "crashed", "worker_error",
            "missing_marker", "malformed_marker", "duplicate_marker",
            "extra_marker", "returncode_conflict", "artifact_mismatch",
            "identity_mismatch",
        }, set(outcomes))

    def test_new_run_api_requires_existing_timeout_and_lock_wait_authorities(self):
        parameters = inspect.signature(WORKER.run_collection_slots).parameters
        self.assertIs(inspect.Parameter.empty, parameters["timeout"].default)
        self.assertIs(inspect.Parameter.empty, parameters["lock_wait"].default)

    def test_dynamic_slots_refuse_v2_when_the_frozen_resolver_is_missing(self):
        # Missing resolver bytes cannot independently prove zero dynamic
        # targets; a static-looking plan is not qualifying v2 authority.
        for slot in ("ethernet/air", "ethernet/prod"):
            with self.subTest(slot=slot), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inventory = root / "inputs/ethernet.csv"
                inventory.parent.mkdir()
                inventory.write_text("type,hostname,ip\neth,leaf-a,192.0.2.10\n",
                                     encoding="utf-8")
                lease = root / "dhcpd.leases"
                lease.write_text("", encoding="utf-8")
                log = root / "dhcp-runtime.log"
                log.write_text("", encoding="utf-8")
                air_json = root / "ztp/config/isc-dhcp-server/p2p-air.json"
                air_json.parent.mkdir(parents=True)
                air_json.write_text('{"nodes":{}}\n', encoding="utf-8")
                with mock.patch.object(WORKER, "HTTP_ROOT", root), mock.patch.dict(
                    "os.environ", {"DHCP_LEASES_FILE": str(lease),
                                   "DHCP_RUNTIME_LOG_FILE": str(log)},
                ):
                    snapshot = WORKER._collection_snapshot_runtime(
                        slot, {"input_inventory": str(inventory)}
                    )
                self.assertEqual("resolver_unavailable", snapshot["v2_unavailable"])
                self.assertEqual({}, snapshot["runtime_input_hashes"])

    def test_parser_accepts_v2_and_retains_bounded_v1_without_upgrade(self):
        slot = "ethernet/prod"
        parsed_v2 = WORKER.parse_collection_slot_result(
            marker(v2(slot)), expected_context=IDENTITY, expected_slot=slot,
        )
        self.assertEqual(v2(slot), parsed_v2)

        parsed_v1 = WORKER.parse_collection_slot_result(
            marker(legacy(state="failed")),
            expected_context=IDENTITY,
            expected_slot=slot,
        )
        self.assertEqual(1, parsed_v1["schema_version"])
        self.assertEqual("collection,ssh_prepare",
                         parsed_v1["failed_devices"][0]["operation"])
        self.assertEqual("界" * 341, parsed_v1["failed_devices"][0]["reason"])
        for forbidden in (*IDENTITY, "source_slot", "operations"):
            self.assertNotIn(forbidden, parsed_v1)

    def test_v2_evidence_digest_cannot_certify_an_invalid_manifest(self):
        """A matching hash authenticates bytes, not their artifact-role claims.

        CODEX-0274 / CLAUDE-R-0201 freeze three ordered roles and require the
        worker to validate them independently.  A child must not qualify by
        hashing a self-authored empty object and calling it evidence.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence-manifest.json"
            envelope = root / "identity-envelope.json"
            inventory = root / "inventory.csv"
            evidence.write_bytes(b"{}\n")
            envelope.write_bytes(b"{}\n")
            inventory.write_bytes(b"hostname,type,eth0_ip\nleaf01,eth,192.0.2.1\n")
            child = v2("ethernet/prod")
            for field, path in (("evidence", evidence), ("envelope", envelope)):
                content = path.read_bytes()
                child[field] = {
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }
            child["input_inventory_sha256"] = hashlib.sha256(
                inventory.read_bytes()
            ).hexdigest()
            self.assertFalse(WORKER._collection_slot_artifacts_match(
                child,
                {
                    "evidence": str(evidence),
                    "envelope": str(envelope),
                    "input_inventory": str(inventory),
                },
            ))

    def test_v2_manifest_rejects_escape_and_false_not_applicable(self):
        """A child's valid digest cannot authorize traversal or self-exemption."""
        def encoded(value: object) -> bytes:
            return json.dumps(
                value, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"

        def digest(content: bytes) -> dict[str, object]:
            return {
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }

        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            project = outer / "project"
            private = (
                project / "monitor/status/collection-cycles"
                / IDENTITY["project_key"] / "prod/switch_collection/artifacts"
                / "00000000000000000007/infiniband-prod"
            )
            private.mkdir(parents=True)
            evidence = private / "evidence-manifest.json"
            envelope = private / "identity-envelope.json"
            inventory = private.parent / "inputs/infiniband-prod.csv"
            inventory.parent.mkdir(parents=True)
            inventory.write_bytes(b"hostname,type,eth0_ip\nleaf-ib,ib,192.0.2.11\n")
            outside = outer / "outside.tar.gz"
            outside.write_bytes(b"attacker-controlled archive")
            escape = project / "infiniband/monitor/escape"
            escape.parent.mkdir(parents=True, exist_ok=True)
            escape.symlink_to(outer, target_is_directory=True)
            info = project / "infiniband/monitor/ib-info/20260925-0315.tar.gz"
            link = project / "infiniband/monitor/ib-link/20260925-0315.tar.gz"
            csv = project / "infiniband/monitor/ib-link/20260925-0315.csv"
            for path, content in (
                (info, b"info archive"), (link, b"link archive"),
                (csv, b"port,peer\n1,fixture\n"),
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)

            valid_roles = [
                {
                    "role": role,
                    "state": "present",
                    "relative_path": path.relative_to(project).as_posix(),
                    **digest(path.read_bytes()),
                }
                for role, path in (
                    ("info_archive", info),
                    ("link_archive", link),
                    ("link_csv", csv),
                )
            ]

            def bound_result(
                roles: list[dict[str, object]],
                *, replace_binding: tuple[str, str] | None = None,
            ) -> bool:
                evidence_bytes = encoded({"roles": roles})
                evidence.write_bytes(evidence_bytes)
                envelope_bytes = encoded({
                    "identity": IDENTITY,
                    "source_slot": "infiniband/prod",
                    "state": "success",
                    "planned": 1,
                    "succeeded": 1,
                    "failed_count": 0,
                    "input_inventory_sha256": digest(
                        inventory.read_bytes()
                    )["sha256"],
                    "evidence": digest(evidence_bytes),
                })
                envelope.write_bytes(envelope_bytes)
                child = v2("infiniband/prod")
                child.update({
                    "planned": 1, "succeeded": 1,
                    "evidence": digest(evidence_bytes),
                    "envelope": digest(envelope_bytes),
                    "input_inventory_sha256": digest(
                        inventory.read_bytes()
                    )["sha256"],
                })
                binding = {
                    "evidence": str(evidence),
                    "envelope": str(envelope),
                    "input_inventory": str(inventory),
                }
                if replace_binding is not None:
                    binding[replace_binding[0]] = replace_binding[1]
                with mock.patch.object(WORKER, "HTTP_ROOT", project):
                    return WORKER._collection_slot_artifacts_match(
                        child, binding,
                    )

            self.assertTrue(bound_result(valid_roles),
                            "valid three-role fixture must remain admissible")
            copied_evidence = outer / "copied-evidence-manifest.json"
            copied_evidence.write_bytes(evidence.read_bytes())
            linked_evidence = outer / "linked-evidence-manifest.json"
            linked_evidence.symlink_to(evidence)
            copied_inventory = outer / "copied-inventory.csv"
            copied_inventory.write_bytes(inventory.read_bytes())
            for name, binding in (
                ("evidence_outside_private", ("evidence", str(copied_evidence))),
                ("evidence_symlink", ("evidence", str(linked_evidence))),
                ("inventory_outside_private", ("input_inventory", str(copied_inventory))),
            ):
                with self.subTest(case=name):
                    self.assertFalse(bound_result(valid_roles, replace_binding=binding))
            for case in (
                "path_escape", "absolute_path", "symlink_escape",
                "noncanonical_path", "empty_path", "control_character",
                "link_timestamp_mismatch", "false_not_applicable",
            ):
                with self.subTest(case=case):
                    roles = copy.deepcopy(valid_roles)
                    if case == "path_escape":
                        roles[0]["relative_path"] = "../outside.tar.gz"
                        roles[0].update(digest(outside.read_bytes()))
                    elif case == "absolute_path":
                        roles[0]["relative_path"] = str(outside)
                        roles[0].update(digest(outside.read_bytes()))
                    elif case == "symlink_escape":
                        roles[0]["relative_path"] = (
                            "infiniband/monitor/escape/outside.tar.gz"
                        )
                        roles[0].update(digest(outside.read_bytes()))
                    elif case == "noncanonical_path":
                        roles[0]["relative_path"] = (
                            "infiniband/monitor/ib-info/./20260925-0315.tar.gz"
                        )
                    elif case == "empty_path":
                        roles[0]["relative_path"] = ""
                    elif case == "control_character":
                        roles[0]["relative_path"] += "\n"
                    elif case == "link_timestamp_mismatch":
                        late_csv = csv.with_name("20260925-0316.csv")
                        late_csv.write_bytes(csv.read_bytes())
                        roles[2]["relative_path"] = late_csv.relative_to(
                            project
                        ).as_posix()
                    elif case == "false_not_applicable":
                        roles[1] = {
                            "role": "link_archive", "state": "not_applicable",
                            "relative_path": None, "sha256": None,
                            "size_bytes": None,
                        }
                    self.assertFalse(bound_result(roles))

    def test_parser_reports_distinct_marker_and_identity_causes(self):
        slot = "ethernet/prod"
        bad_identity = v2(slot)
        bad_identity["run_token"] = "ffeeddccbbaa49888776655443322110"
        cases = (
            ("collector log only\n", "missing_marker"),
            (PREFIX + "{bad-json\n", "malformed_marker"),
            (marker(legacy()) * 2, "duplicate_marker"),
            (marker(legacy()) * 3, "extra_marker"),
            (marker(bad_identity), "identity_mismatch"),
        )
        for output, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(WORKER.CollectionSlotParseError) as caught:
                    WORKER.parse_collection_slot_result(
                        output,
                        expected_context=IDENTITY,
                        expected_slot=slot,
                    )
                self.assertEqual(expected, caught.exception.outcome)

    def test_run_returns_one_immutable_terminal_wrapper_per_declared_slot(self):
        commands = [["collector", slot] for slot in (
            "ethernet/prod", "infiniband/prod", "nvlink/prod",
        )]
        outputs = iter((
            ({"returncode": 0, "stdout": marker(legacy()), "stderr": ""}, False),
            ({"returncode": 1, "stdout": marker(legacy(state="failed")),
              "stderr": "unreachable"}, False),
            ({"returncode": -15, "stdout": "", "stderr": "terminated"}, False),
        ))
        with mock.patch.object(WORKER, "commands_for_scope", return_value=commands), \
                mock.patch.object(WORKER, "run_interruptible",
                                  side_effect=lambda *a, **k: next(outputs)):
            result = WORKER.run_collection_slots(
                copy.deepcopy(IDENTITY), artifact_bindings={}, timeout=10,
                lock_wait=0,
            )

        self.assertEqual(IDENTITY, result["identity"])
        self.assertEqual({"identity", "outcomes", "summary"}, set(result))
        self.assertIsNone(result["summary"])
        self.assertEqual(
            ["ethernet/prod", "infiniband/prod", "nvlink/prod"],
            [item["source_slot"] for item in result["outcomes"]],
        )
        self.assertEqual(
            ["accepted", "accepted", "crashed"],
            [item["outcome"] for item in result["outcomes"]],
        )
        self.assertTrue(all(
            set(item) == {"source_slot", "outcome", "child_result", "evidence"}
            for item in result["outcomes"]
        ))
        self.assertEqual(1, result["outcomes"][1]["child_result"]["schema_version"])
        self.assertIsNone(result["outcomes"][2]["child_result"])
        evidence = result["outcomes"][1]["evidence"]
        self.assertEqual({"stdout", "stderr", "returncode"}, set(evidence))
        self.assertEqual(
            {"sha256": hashlib.sha256(b"unreachable").hexdigest(),
             "size_bytes": len(b"unreachable")},
            evidence["stderr"],
        )

    def test_all_accepted_v1_children_still_have_no_run_summary(self):
        slots = ("ethernet/prod", "infiniband/prod", "nvlink/prod")
        commands = [["collector", slot] for slot in slots]
        outputs = iter(
            ({"returncode": 0, "stdout": marker(legacy()), "stderr": ""}, False)
            for _slot in slots
        )
        with mock.patch.object(WORKER, "commands_for_scope", return_value=commands), \
                mock.patch.object(WORKER, "run_interruptible",
                                  side_effect=lambda *a, **k: next(outputs)):
            result = WORKER.run_collection_slots(
                copy.deepcopy(IDENTITY), artifact_bindings={}, timeout=10,
                lock_wait=0,
            )

        self.assertEqual(["accepted"] * len(slots), [
            item["outcome"] for item in result["outcomes"]
        ])
        self.assertEqual([1] * len(slots), [
            item["child_result"]["schema_version"]
            for item in result["outcomes"]
        ])
        self.assertIsNone(
            result["summary"],
            "accepted legacy evidence must never become a run summary",
        )

    def test_non_success_wrapper_cannot_carry_or_be_upgraded_to_child(self):
        evidence = {
            "stdout": {"sha256": hashlib.sha256(b"").hexdigest(),
                       "size_bytes": 0},
            "stderr": {"sha256": hashlib.sha256(b"bad").hexdigest(),
                       "size_bytes": 3},
            "returncode": 2,
        }
        invalid = {
            "source_slot": "ethernet/prod",
            "outcome": "malformed_marker",
            "child_result": legacy(),
            "evidence": evidence,
        }
        with self.assertRaises(ValueError):
            WORKER.validate_collection_slot_outcome(
                invalid, expected_slot="ethernet/prod",
                expected_context=IDENTITY,
            )


if __name__ == "__main__":
    unittest.main()
