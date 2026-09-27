"""Direct contract for a local, non-qualifying Ethernet activity witness."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import monitor.issue_tracker_activity_source as activity_source

from monitor.issue_tracker_activity_source import (
    ActivitySourceHoldError,
    load_eth_activity_evidence,
)


ROLES = ("dot", "archive", "inventory", "device_aliases")


def _cycle_binding(token: str, slot: str = "ethernet/prod") -> dict:
    identity = {
        "project_key": hashlib.sha256(b"/fixture-project").hexdigest(),
        "run_token": token,
        "scope": "all",
        "sequence": 7 if token.endswith("a") else 8,
        "source": "switch_collection",
    }
    identity["cycle_id"] = hashlib.sha256(json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    return {
        "identity": identity,
        "source_slot": slot,
        "context_sha256": hashlib.sha256((token + slot).encode()).hexdigest(),
    }


class EthActivitySourceDirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        literal = {
            "dot": b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n',
            "archive": b"literal archive witness bytes",
            "inventory": b"[Eth-SW]\nleaf-*\n",
            "device_aliases": b'{"schema_version":1,"canonical_to_aliases":{}}',
        }
        self.sources = {}
        for role, value in literal.items():
            path = self.root / role
            path.write_bytes(value)
            self.sources[role] = path
        self.report = self.root / "report.xlsx"
        self.report.write_bytes(b"literal local report bytes")
        self.evidence = self.root / "evidence.json"
        self.payload = {
            "schema_version": 1,
            "kind": "eth_lldp_report_observation",
            "sources": {
                role: {
                    "path": str(self.sources[role]),
                    "sha256": hashlib.sha256(literal[role]).hexdigest(),
                }
                for role in ROLES
            },
            "report": {
                "path": str(self.report),
                "sha256": hashlib.sha256(self.report.read_bytes()).hexdigest(),
            },
            "links": [{
                "device_a": "leaf-a",
                "interface_a": "swp1",
                "device_b": "leaf-z",
                "interface_b": "swp2",
                "status": "CONFIRMED_BOTH_SIDE",
                "dot_line": 1,
                "observation_a": {
                    "remote_host": "leaf-z", "remote_port": "swp2",
                },
                "observation_b": {
                    "remote_host": "leaf-a", "remote_port": "swp1",
                },
            }],
        }
        self._write_payload()

    def _write_payload(self) -> str:
        raw = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode()
        self.evidence.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def _load(self, **extra):
        return load_eth_activity_evidence(
            self.evidence, sources=self.sources, report_path=self.report, **extra,
        )

    def test_literal_four_source_and_az_witness_is_preview_only(self):
        digest = hashlib.sha256(self.evidence.read_bytes()).hexdigest()
        witness = self._load(expected_evidence_sha256=digest)
        self.assertEqual(
            {role: hashlib.sha256(self.sources[role].read_bytes()).hexdigest()
             for role in ROLES},
            witness.source_sha256,
        )
        self.assertEqual(digest, witness.evidence_sha256)
        self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"), (
            witness.links[0].device_a, witness.links[0].interface_a,
            witness.links[0].device_b, witness.links[0].interface_b,
        ))
        self.assertEqual("CONFIRMED_BOTH_SIDE", witness.links[0].status)
        self.assertFalse(witness.qualified)

    def test_any_changed_input_or_report_holds_even_with_unchanged_path(self):
        for role in ROLES:
            with self.subTest(role=role):
                original = self.sources[role].read_bytes()
                self.sources[role].write_bytes(original + b"x")
                with self.assertRaises(ActivitySourceHoldError):
                    self._load()
                self.sources[role].write_bytes(original)
        self.report.write_bytes(b"changed local report bytes")
        with self.assertRaises(ActivitySourceHoldError):
            self._load()

    def test_changed_evidence_bytes_hold_against_exact_external_digest(self):
        original = hashlib.sha256(self.evidence.read_bytes()).hexdigest()
        self.payload["links"][0]["status"] = "WRONG_PEER"
        self._write_payload()
        with self.assertRaises(ActivitySourceHoldError):
            self._load(expected_evidence_sha256=original)

    def test_dot_digest_must_cover_exact_bytes_used_for_edge_parsing(self):
        original_read = activity_source._regular_bytes
        source = self.sources["dot"]
        original = source.read_bytes()
        # Same-size, semantically identical DOT with different bytes models a
        # rewrite between two separate reads.  The recorded SHA is for original.
        changed = b" " + original[:-1]
        self.assertEqual(len(original), len(changed))

        def changed_dot_read(path, *, maximum):
            raw = original_read(path, maximum=maximum)
            return changed if Path(path) == source else raw

        with mock.patch.object(activity_source, "_regular_bytes",
                               side_effect=changed_dot_read):
            with self.assertRaises(ActivitySourceHoldError):
                self._load()

    def test_other_source_or_report_rewrite_during_validation_holds(self):
        original_links = activity_source._dot_links
        for victim in (self.sources["archive"], self.report):
            with self.subTest(victim=victim):
                original = victim.read_bytes()

                def rewrite_during_parse(raw):
                    victim.write_bytes(b"L" + original[1:])
                    return original_links(raw)

                try:
                    with mock.patch.object(activity_source, "_dot_links",
                                           side_effect=rewrite_during_parse):
                        with self.assertRaises(ActivitySourceHoldError):
                            self._load()
                finally:
                    victim.write_bytes(original)

    def test_failed_parent_directory_fsync_holds_unconfirmed_own_sidecar(self):
        target = self.root / "new-evidence.json"
        calls = 0
        original_fsync = activity_source.os.fsync

        def fail_second_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected parent-directory fsync failure")
            return original_fsync(descriptor)

        with mock.patch.object(activity_source.os, "fsync", side_effect=fail_second_fsync):
            with self.assertRaises(ActivitySourceHoldError):
                activity_source.write_eth_activity_evidence(
                    target,
                    sources=self.sources,
                    source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for role, path in self.sources.items()},
                    report_path=self.report,
                    result_records=self.payload["links"],
                )
        # Link succeeded, but the directory barrier did not.  Its visible
        # bytes are unconfirmed evidence, never a successful publication.
        self.assertTrue(target.is_file())
        witness = load_eth_activity_evidence(
            target, sources=self.sources, report_path=self.report,
        )
        self.assertFalse(witness.qualified)
        self.assertGreaterEqual(calls, 2)

    def test_failed_parent_fsync_does_not_delete_foreign_replacement(self):
        target = self.root / "new-evidence.json"
        foreign = self.root / "foreign-evidence.json"
        foreign_bytes = b"foreign writer's byte-for-byte evidence"
        foreign.write_bytes(foreign_bytes)
        foreign_inode = foreign.stat().st_ino
        calls = 0
        original_fsync = activity_source.os.fsync

        def replace_then_fail(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                activity_source.os.replace(foreign, target)
                raise OSError("injected parent-directory fsync failure")
            return original_fsync(descriptor)

        with mock.patch.object(activity_source.os, "fsync", side_effect=replace_then_fail):
            with self.assertRaises(ActivitySourceHoldError):
                activity_source.write_eth_activity_evidence(
                    target,
                    sources=self.sources,
                    source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for role, path in self.sources.items()},
                    report_path=self.report,
                    result_records=self.payload["links"],
                )
        self.assertEqual(foreign_bytes, target.read_bytes())
        self.assertEqual(foreign_inode, target.stat().st_ino)
        self.assertFalse(foreign.exists())

    def test_failed_file_fsync_before_link_cleans_only_private_temp(self):
        target = self.root / "new-evidence.json"
        with mock.patch.object(activity_source.os, "fsync",
                               side_effect=OSError("injected file fsync failure")):
            with self.assertRaises(ActivitySourceHoldError):
                activity_source.write_eth_activity_evidence(
                    target,
                    sources=self.sources,
                    source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for role, path in self.sources.items()},
                    report_path=self.report,
                    result_records=self.payload["links"],
                )
        self.assertFalse(target.exists())
        self.assertEqual([], list(self.root.glob(".eth-evidence-*.tmp")))

    def test_writer_cannot_publish_after_a_frozen_input_changes(self):
        target = self.root / "stale-evidence.json"
        digests = {role: hashlib.sha256(path.read_bytes()).hexdigest()
                   for role, path in self.sources.items()}
        original = self.sources["inventory"].read_bytes()
        self.sources["inventory"].write_bytes(original.replace(b"leaf-*", b"rack-*"))
        with self.assertRaises(ActivitySourceHoldError):
            activity_source.write_eth_activity_evidence(
                target, sources=self.sources, source_sha256=digests,
                report_path=self.report, result_records=self.payload["links"],
            )
        self.assertFalse(target.exists())

    def test_missing_or_synthetic_z_and_duplicate_link_hold(self):
        for synthetic in ("", "inferred-leaf-z"):
            with self.subTest(synthetic=synthetic):
                self.payload["links"][0]["device_b"] = synthetic
                self._write_payload()
                with self.assertRaises(ActivitySourceHoldError):
                    self._load()
        self.payload["links"][0]["device_b"] = "leaf-z"
        self.payload["links"].append(dict(self.payload["links"][0]))
        self._write_payload()
        with self.assertRaises(ActivitySourceHoldError):
            self._load()

    def test_cycle_or_ib_promotion_remains_hold_without_collector_binding(self):
        with self.assertRaises(ActivitySourceHoldError):
            self._load(expected_cycle_completion_sha256="a" * 64)
        with self.assertRaises(ActivitySourceHoldError):
            self._load(expected_network="ib")

    def test_worker_bound_cycle_and_slot_refuse_identical_byte_replay(self):
        target = self.root / "cycle-evidence.json"
        cycle_a = _cycle_binding("12345678123442348123456789abcdea")
        cycle_b = _cycle_binding("12345678123442348123456789abcdeb")
        activity_source.write_eth_activity_evidence(
            target, sources=self.sources,
            source_sha256={role: hashlib.sha256(path.read_bytes()).hexdigest()
                           for role, path in self.sources.items()},
            report_path=self.report, result_records=self.payload["links"],
            cycle_binding=cycle_a,
        )
        bound = load_eth_activity_evidence(
            target, sources=self.sources, report_path=self.report,
            expected_cycle_binding=cycle_a,
        )
        self.assertFalse(bound.qualified)
        with self.assertRaises(ActivitySourceHoldError):
            load_eth_activity_evidence(
                target, sources=self.sources, report_path=self.report,
                expected_cycle_binding=cycle_b,
            )
        with self.assertRaises(ActivitySourceHoldError):
            load_eth_activity_evidence(
                target, sources=self.sources, report_path=self.report,
                expected_cycle_binding={**cycle_a, "source_slot": "ethernet/air"},
            )

    def test_wrong_peer_and_missing_lldp_are_failed_observations_not_fake_source_damage(self):
        for status, remote_host, remote_port in (
            ("WRONG_PEER", "unplanned-q", "swp9"),
            ("NO_LLDP", "", ""),
        ):
            with self.subTest(status=status):
                self.payload["links"][0]["status"] = status
                self.payload["links"][0]["observation_a"] = {
                    "remote_host": remote_host, "remote_port": remote_port,
                }
                self._write_payload()
                witness = self._load()
                self.assertEqual(status, witness.links[0].status)
                self.assertFalse(witness.qualified)


if __name__ == "__main__":
    unittest.main()
