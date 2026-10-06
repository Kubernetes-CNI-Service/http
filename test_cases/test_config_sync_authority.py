"""Independent F02 local generation/veto contracts (no device operations)."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class ConfigSyncAuthorityTests(unittest.TestCase):
    @staticmethod
    def receipt_v1(**updates):
        value = {
            "schema_version": 1, "hostname": "leaf1", "type": "eth",
            "state": "triggered", "transport_ip": "192.0.2.10",
            "interface": "eth0",
            "action": "nv config replace <latest-hostname.yaml>; nv config apply -y; nv config save",
            "started_at": "2026-10-07T01:00:00+08:00",
            "command_started_at": "2026-10-07T01:00:01+08:00",
            "operation": "replace-config", "effective_operation": "replace-config",
            "requested_operation": "replace-config", "operation_id": "operation-1",
            "trigger_source": "manual_config_sync_cli", "trigger_id": "trigger-1",
            "command_ztp_log_sha256": "", "command_ztp_complete": False,
            "batch_identity_verified": True,
            "batch_identity_verified_at": "2026-10-07T01:00:02+08:00",
            "live_state_sha256": "a" * 64,
            "finished_at": "2026-10-07T01:00:03+08:00", "generation": 1,
            "source_identity": "1:2",
        }
        return {**value, **updates}

    def test_receipt_v1_has_independent_maximum_accepted_fixture_and_nondegenerate_bound(self):
        value = self.receipt_v1(
            hostname="h" * 253, type="eth_spx", state="failed", reason="\U0010ffff" * 1024,
            transport_ip="ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", interface="i" * 15,
            started_at="9999-12-31T23:59:59.999999+00:00",
            command_started_at="9999-12-31T23:59:59.999999+00:00",
            batch_identity_verified_at="9999-12-31T23:59:59.999999+00:00",
            finished_at="9999-12-31T23:59:59.999999+00:00",
            operation_id="o" * 512, trigger_id="t" * 766,
            command_ztp_log_sha256="a" * 64, batch_identity_verified=False,
            generation=9223372036854775807,
            source_identity="18446744073709551615:18446744073709551615",
        )
        # Failed receipts intentionally carry no successful observation fields.
        for field in ("transport_ip", "interface", "action", "command_ztp_log_sha256",
                      "command_ztp_complete", "batch_identity_verified",
                      "batch_identity_verified_at", "live_state_sha256"):
            value.pop(field)
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        # 16 fixed members; 1024 astral code points use 12 ASCII wire bytes
        # each. The other maximal identities/timestamps contribute 2043 B.
        self.assertEqual(14331, len(raw), "independent failed v1 field/escape maximum")
        self.assertEqual(value, self.authority.decode_receipt(raw))
        with mock.patch.object(self.authority, "RECEIPT_MAX_BYTES", len(raw) - 1):
            with self.assertRaises(self.authority.AuthorityError):
                self.authority.decode_receipt(raw)
        over = {**value, "reason": "\U0010ffff" * 1025}
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.decode_receipt(json.dumps(over).encode("ascii"))

    def test_completion_receipt_requires_closed_version_and_strict_values_before_publish(self):
        changes = (
            {"schema_version": None}, {"schema_version": True}, {"schema_version": 2},
            {"unexpected": "unreviewed"}, {"type": "server"}, {"generation": True},
            {"batch_identity_verified": 1}, {"command_ztp_complete": 0},
            {"reason": "x" * 1025}, {"interface": "i" * 16},
            {"transport_ip": "not-an-IP"}, {"action": "unreviewed action"},
            {"finished_at": "2026-10-07T01:00:00+08:00"},
            {"source_identity": "18446744073709551616:1"},
        )
        for index, change in enumerate(changes):
            with self.subTest(change=change):
                root = self.root / str(index)
                ticket = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                value = self.receipt_v1(source_identity=ticket["source_identity"])
                value.update(change)
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.finish(root, ticket, value)
                self.assertEqual(ticket, self.authority.read_current(root, "leaf1"))

    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "config_sync_authority_under_test", ROOT / "ztp/config_sync_authority.py",
        )
        self.authority = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.authority)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "manual-config-sync"
        self.root.mkdir(mode=0o700)

    def begin(self, operation="operation-1", trigger="trigger-1"):
        return self.authority.begin(
            self.root, "leaf1", operation, trigger, "manual_config_sync_cli",
        )

    @staticmethod
    def result(ticket, state="triggered", wall_clock="2099-01-01T00:00:00+00:00"):
        value = ConfigSyncAuthorityTests.receipt_v1(
            operation_id=ticket["operation_id"], trigger_id=ticket["trigger_id"],
            generation=ticket["generation"], source_identity=ticket["source_identity"],
            state=state, started_at=wall_clock, command_started_at=wall_clock,
            batch_identity_verified_at=wall_clock, finished_at=wall_clock,
        )
        if state == "failed":
            for field in ("transport_ip", "interface", "action", "command_ztp_log_sha256",
                          "command_ztp_complete", "batch_identity_verified",
                          "batch_identity_verified_at", "live_state_sha256"):
                value.pop(field)
            value["reason"] = "fixture command failed"
        return value

    def test_local_generations_increase_despite_reporter_clock_rollback(self):
        first = self.begin()
        self.assertEqual(1, first["generation"])
        self.assertIs(True, first["veto"])
        self.assertEqual("pending", first["state"])
        success = self.authority.finish(self.root, first, self.result(first))
        self.assertEqual("success", success["state"])
        self.assertIs(False, success["veto"])
        second = self.begin("operation-2", "trigger-2")
        self.assertEqual(2, second["generation"])
        self.assertIs(True, self.authority.read_current(self.root, "leaf1")["veto"])
        self.authority.finish(self.root, second, self.result(second, wall_clock="2000-01-01T00:00:00+00:00"))
        current = self.authority.read_current(self.root, "leaf1")
        self.assertEqual(2, current["generation"])
        self.assertEqual("operation-2", current["operation_id"])
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.finish(self.root, first, self.result(first))

    def test_failed_current_generation_revokes_previous_success(self):
        first = self.begin()
        self.authority.finish(self.root, first, self.result(first))
        second = self.begin("operation-2", "trigger-2")
        self.authority.finish(self.root, second, self.result(second, "failed"))
        current = self.authority.read_current(self.root, "leaf1")
        self.assertEqual((2, "failed", True), (current["generation"], current["state"], current["veto"]))
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.finish(self.root, second, self.result(second))

    def test_observer_revocation_compares_exact_current_era_under_writer_lock(self):
        first = self.begin()
        success = self.authority.finish(self.root, first, self.result(first))
        for mutant in ({**success, "generation": True}, {**success, "unknown": "field"}):
            with self.subTest(mutant=mutant), self.assertRaises(self.authority.AuthorityError):
                self.authority.revoke(self.root, "leaf1", expected=mutant)
            self.assertEqual(success, self.authority.read_current(self.root, "leaf1"))
        second = self.begin("operation-2", "trigger-2")
        self.assertIsNone(self.authority.revoke(self.root, "leaf1", expected=success))
        self.assertEqual(second, self.authority.read_current(self.root, "leaf1"))
        latest = self.authority.finish(self.root, second, self.result(second))
        revoked = self.authority.revoke(self.root, "leaf1", expected=latest)
        self.assertEqual((2, "failed", True, ""), tuple(
            revoked[field] for field in ("generation", "state", "veto", "receipt_sha256")
        ))

    def test_completion_must_carry_its_own_local_source_identity(self):
        first = self.begin()
        namespace = f"{self.root.stat().st_dev}:{self.root.stat().st_ino}"
        self.assertEqual(namespace, first["source_identity"])
        for source in (None, "", "0:0", True, 1, [], {}):
            with self.subTest(source=source):
                observed = {**self.result(first), "source_identity": source}
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.finish(self.root, first, observed)
                self.assertEqual((1, "pending", True), tuple(
                    self.authority.read_current(self.root, "leaf1")[field]
                    for field in ("generation", "state", "veto")
                ))
        self.assertEqual("success", self.authority.finish(
            self.root, first, self.result(first),
        )["state"])

    def test_teardown_revocation_is_terminal_and_new_writer_must_advance_generation(self):
        first = self.begin()
        self.authority.finish(self.root, first, self.result(first))
        revoked = self.authority.revoke(self.root, "leaf1")
        self.assertEqual((1, "failed", True, ""), (
            revoked["generation"], revoked["state"], revoked["veto"], revoked["receipt_sha256"],
        ))
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.finish(self.root, first, self.result(first))
        self.assertEqual(revoked, self.authority.revoke(self.root, "leaf1"))
        second = self.begin("operation-2", "trigger-2")
        self.assertEqual(2, second["generation"])
        self.authority.finish(self.root, second, self.result(second))
        self.assertEqual((2, "success", False), tuple(
            self.authority.read_current(self.root, "leaf1")[field]
            for field in ("generation", "state", "veto")
        ))

    def test_completion_ticket_is_closed_and_strictly_typed_before_publication(self):
        for index, change in enumerate(({"schema_version": True}, {"generation": True}, {"veto": 1},
                                       {"generation": 1.0}, {"veto": "true"}, {"extra": "field"})):
            with self.subTest(change=change):
                root = self.root.parent / f"ticket-{index}"
                root.mkdir(mode=0o700)
                first = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                private = root / ".authority"
                previous = {name: (private / name).read_bytes() for name in (
                    "leaf1.journal.json", "leaf1.witness.json",
                )}
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.finish(root, {**first, **change}, self.result(first))
                self.assertEqual(previous, {name: (private / name).read_bytes() for name in previous})
                self.assertFalse((private / "leaf1.pending").exists())
                current = self.authority.read_current(root, "leaf1")
                self.assertEqual((1, "pending", True), (
                    current["generation"], current["state"], current["veto"],
                ))

    def test_partial_journal_or_witness_rollback_is_rejected_and_retained(self):
        first = self.begin()
        self.authority.finish(self.root, first, self.result(first))
        private = self.root / ".authority"
        journal, witness = private / "leaf1.journal.json", private / "leaf1.witness.json"
        writer = private / "leaf1.lock"
        old_journal, old_witness, old_writer = journal.read_bytes(), witness.read_bytes(), writer.read_bytes()
        second = self.begin("operation-2", "trigger-2")
        self.authority.finish(self.root, second, self.result(second))
        new_journal, new_witness, new_writer = journal.read_bytes(), witness.read_bytes(), writer.read_bytes()
        for name, path, old, new in (
            ("journal", journal, old_journal, new_journal),
            ("witness", witness, old_witness, new_witness),
            ("writer", writer, old_writer, new_writer),
        ):
            with self.subTest(component=name):
                path.write_bytes(old)
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.read_current(self.root, "leaf1")
                self.assertEqual(old, path.read_bytes(), "reject-and-retain")
                path.write_bytes(new)
        self.assertEqual(2, self.authority.read_current(self.root, "leaf1")["generation"])

    def test_paired_history_replay_or_erasure_cannot_replace_current_writer_witness(self):
        first = self.begin()
        self.authority.finish(self.root, first, self.result(first))
        private = self.root / ".authority"
        names = ("leaf1.journal.json", "leaf1.witness.json")
        old = {name: (private / name).read_bytes() for name in names}
        # A veto changes state within the same generation, so checking only
        # the integer counter would incorrectly accept this old success.
        self.authority.revoke(self.root, "leaf1")
        current = {name: (private / name).read_bytes() for name in names}
        for mode in ("old-success", "erased-pair"):
            with self.subTest(mode=mode):
                for name in names:
                    if mode == "old-success":
                        (private / name).write_bytes(old[name])
                    else:
                        (private / name).unlink()
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.read_current(self.root, "leaf1")
                with self.assertRaises(self.authority.AuthorityError):
                    self.begin("operation-2", "trigger-2")
                for name in names:
                    if mode == "old-success":
                        self.assertEqual(old[name], (private / name).read_bytes())
                    else:
                        self.assertFalse((private / name).exists())
                    (private / name).write_bytes(current[name])
                    (private / name).chmod(0o600)
        second = self.begin("operation-2", "trigger-2")
        self.authority.finish(self.root, second, self.result(second))
        for name in names:
            (private / name).write_bytes(old[name])
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.read_current(self.root, "leaf1")

    def test_closed_versioned_schema_has_independent_maximum_positive_fixture(self):
        # v1 maxima: hostname 253, operation ID 512, generated trigger ID
        # operation ID + ':' + hostname = 766, uint64 namespace
        # components 20 decimal digits, generation signed-64 max, digest 64.
        # This fixture and its ACCEPTED assertion do not consult production
        # constants or derive values from the implementation.
        namespace = "18446744073709551615:18446744073709551615"
        fixture = {
            "schema_version": 1, "hostname": "h" * 253,
            "generation": 9223372036854775807,
            "operation_id": "o" * 512, "trigger_id": "t" * 766,
            "trigger_source": "manual_config_sync_web", "source_identity": namespace,
            "state": "success", "veto": False, "receipt_sha256": "f" * 64,
        }
        raw = (json.dumps(fixture, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.assertEqual(1852, len(raw), "v1 finite maximum independently derived from its fixed fields")
        self.assertLessEqual(len(raw), 2048, "independent finite v1 wire bound")
        self.assertEqual(fixture, self.authority.decode_journal(raw, namespace))
        with mock.patch.object(self.authority, "JOURNAL_MAX_BYTES", len(raw) - 1):
            with self.assertRaises(self.authority.AuthorityError):
                self.authority.decode_journal(raw, namespace)
        for change in ({"schema_version": True}, {"generation": True}, {"generation": 0},
                       {"veto": 0}, {"unexpected": "member"}, {"state": "unknown"},
                       {"state": []}, {"trigger_source": []}):
            with self.subTest(change=change), self.assertRaises(self.authority.AuthorityError):
                self.authority.decode_journal(json.dumps({**fixture, **change}).encode(), namespace)
        duplicate = raw[:-2] + b',"veto":false}\n'
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.decode_journal(duplicate, namespace)

    def test_maximum_supported_hostname_and_generated_trigger_are_writable(self):
        hostname, operation_id = "h" * 253, "o" * 512
        trigger_id = operation_id + ":" + hostname
        self.assertEqual(766, len(trigger_id))
        first = self.authority.begin(
            self.root, hostname, operation_id, trigger_id, "manual_config_sync_cli",
        )
        self.assertEqual((1, hostname, operation_id, trigger_id), tuple(
            first[field] for field in ("generation", "hostname", "operation_id", "trigger_id")
        ))
        self.authority.finish(self.root, first, {**self.result(first), "hostname": hostname})
        self.assertEqual("success", self.authority.read_current(self.root, hostname.upper())["state"])
        # Prefix is outside legal hostnames so a long-host digest cannot
        # collide with another legal hostname's literal storage component.
        import hashlib
        key = "@" + hashlib.sha256(hostname.encode("ascii")).hexdigest()
        self.assertEqual({key + suffix for suffix in (".lock", ".journal.json", ".witness.json")},
                         {path.name for path in (self.root / ".authority").iterdir()})

    def test_closed_witness_has_its_own_independent_maximum_positive_fixture(self):
        namespace = "18446744073709551615:18446744073709551615"
        fixture = {
            "schema_version": 1, "generation": 9223372036854775807,
            "source_identity": namespace, "journal_sha256": "f" * 64,
        }
        raw = (json.dumps(fixture, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.assertLessEqual(len(raw), 512, "independent finite witness-v1 wire bound")
        self.assertEqual(fixture, self.authority.decode_witness(
            raw, generation=9223372036854775807, namespace=namespace, journal_sha256="f" * 64,
        ))
        with mock.patch.object(self.authority, "WITNESS_MAX_BYTES", len(raw) - 1):
            with self.assertRaises(self.authority.AuthorityError):
                self.authority.decode_witness(
                    raw, generation=9223372036854775807, namespace=namespace, journal_sha256="f" * 64,
                )
        for change in ({"schema_version": True}, {"generation": True}, {"generation": 1},
                       {"source_identity": "0:0"}, {"journal_sha256": "0" * 64},
                       {"unexpected": "member"}):
            with self.subTest(change=change), self.assertRaises(self.authority.AuthorityError):
                self.authority.decode_witness(
                    json.dumps({**fixture, **change}).encode(), generation=9223372036854775807,
                    namespace=namespace, journal_sha256="f" * 64,
                )

    def test_late_durability_fault_leaves_a_persistent_hold_not_old_success(self):
        first = self.begin()
        self.authority.finish(self.root, first, self.result(first))
        real_fsync = os.fsync
        failed = False

        def fail_directory_once(descriptor):
            nonlocal failed
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not failed:
                failed = True
                raise OSError("injected authority directory sync failure")
            real_fsync(descriptor)

        with mock.patch.object(self.authority.os, "fsync", side_effect=fail_directory_once):
            with self.assertRaises((OSError, self.authority.AuthorityError)):
                self.begin("operation-2", "trigger-2")
        self.assertTrue(failed)
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.read_current(self.root, "leaf1")

    def test_journal_links_or_foreign_namespace_cannot_supply_authority(self):
        ticket = self.begin()
        self.authority.finish(self.root, ticket, self.result(ticket))
        journal = self.root / ".authority/leaf1.journal.json"
        raw = journal.read_bytes()
        external = self.root / "external.json"
        external.write_bytes(raw)
        external.chmod(0o600)
        for alias in ("symlink", "hardlink"):
            journal.unlink()
            journal.symlink_to(external) if alias == "symlink" else os.link(external, journal)
            with self.subTest(alias=alias), self.assertRaises(self.authority.AuthorityError):
                self.authority.read_current(self.root, "leaf1")
            self.assertEqual(raw, external.read_bytes())
            journal.unlink()
            journal.write_bytes(raw)
            journal.chmod(0o600)
        other = self.root.parent / "foreign-project"
        other.mkdir(mode=0o700)
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.decode_journal(raw, f"{other.stat().st_dev}:{other.stat().st_ino}")

    def test_publication_rejects_and_retains_destination_rebound_during_staging(self):
        first = self.begin()
        self.authority.finish(self.root, first, self.result(first))
        private = self.root / ".authority"
        witness = private / "leaf1.witness.json"
        original = witness.read_bytes()
        writer = private / "leaf1.lock"
        original_writer = writer.read_bytes()
        external = self.root / "external-witness.json"
        external.write_bytes(b"foreign-witness-image\n")
        external.chmod(0o600)
        real_fsync = os.fsync
        for alias in ("symlink", "hardlink", "regular", "mode"):
            with self.subTest(alias=alias):
                file_syncs = 0

                def rebind_after_stage_sync(descriptor):
                    nonlocal file_syncs
                    real_fsync(descriptor)
                    if stat.S_ISREG(os.fstat(descriptor).st_mode):
                        file_syncs += 1
                        # Pending guard, held writer witness, then pair stage.
                        if file_syncs == 3:
                            if alias == "mode":
                                witness.chmod(0o644)
                            else:
                                witness.unlink()
                                if alias == "symlink":
                                    witness.symlink_to(external)
                                elif alias == "hardlink":
                                    os.link(external, witness)
                                else:
                                    witness.write_bytes(b"foreign-replacement\n")
                                    witness.chmod(0o600)

                with mock.patch.object(self.authority.os, "fsync", side_effect=rebind_after_stage_sync):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.begin("operation-2", "trigger-2")
                self.assertEqual(b"foreign-witness-image\n", external.read_bytes())
                if alias == "symlink":
                    self.assertTrue(witness.is_symlink(), "reject-and-retain alias")
                elif alias == "hardlink":
                    self.assertEqual(external.stat().st_ino, witness.stat().st_ino)
                elif alias == "regular":
                    self.assertEqual(b"foreign-replacement\n", witness.read_bytes())
                else:
                    self.assertEqual(0o644, stat.S_IMODE(witness.stat().st_mode))
                self.assertTrue((private / "leaf1.pending").exists(), "uncertain publication remains HOLD")
                # This controlled fault fixture is reset only for the next
                # independent negative; production never repairs the HOLD.
                (private / "leaf1.pending").unlink()
                witness.unlink()
                witness.write_bytes(original)
                witness.chmod(0o600)
                writer.write_bytes(original_writer)

    def test_authority_namespace_or_lock_rebound_stops_before_pair_publication(self):
        for target in ("root", "private", "lock"):
            with self.subTest(target=target):
                root = self.root.parent / ("scope-" + target)
                root.mkdir(mode=0o700)
                ticket = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                self.authority.finish(root, ticket, self.result(ticket))
                private = root / ".authority"
                original = (private / "leaf1.journal.json").read_bytes()
                held_private = private
                real_fsync = os.fsync
                injected = False

                def rebind_after_marker_sync(descriptor):
                    nonlocal injected, held_private
                    real_fsync(descriptor)
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not injected:
                        injected = True
                        if target == "root":
                            backup = root.with_name(root.name + "-held")
                            root.rename(backup)
                            root.mkdir(mode=0o700)
                            held_private = backup / ".authority"
                        elif target == "private":
                            held_private = root / ".authority-held"
                            private.rename(held_private)
                            private.mkdir(mode=0o700)
                        else:
                            lock = private / "leaf1.lock"
                            lock.unlink()
                            lock.write_bytes(b"foreign-lock\n")
                            lock.chmod(0o600)

                with mock.patch.object(self.authority.os, "fsync", side_effect=rebind_after_marker_sync):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.authority.begin(root, "leaf1", "operation-2", "trigger-2", "manual_config_sync_cli")
                self.assertTrue(injected)
                self.assertEqual(original, (held_private / "leaf1.journal.json").read_bytes())
                self.assertTrue((held_private / "leaf1.pending").exists())
                if target == "lock":
                    self.assertEqual(b"foreign-lock\n", (private / "leaf1.lock").read_bytes())

    def test_changed_controlled_temporary_is_rejected_without_foreign_cleanup(self):
        for alias in ("regular", "symlink", "hardlink"):
            with self.subTest(alias=alias):
                root = self.root.parent / ("temporary-" + alias)
                root.mkdir(mode=0o700)
                first = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                self.authority.finish(root, first, self.result(first))
                private = root / ".authority"
                old_journal = (private / "leaf1.journal.json").read_bytes()
                old_witness = (private / "leaf1.witness.json").read_bytes()
                external = root / "foreign.json"
                external.write_bytes(b"foreign-image\n")
                external.chmod(0o600)
                rebound = None
                real_fsync = os.fsync

                def replace_temporary_after_file_sync(descriptor):
                    nonlocal rebound
                    real_fsync(descriptor)
                    candidates = list(private.glob(".leaf1.witness.json.*.tmp"))
                    if stat.S_ISREG(os.fstat(descriptor).st_mode) and candidates and rebound is None:
                        self.assertEqual(1, len(candidates))
                        rebound = candidates[0]
                        rebound.unlink()
                        if alias == "symlink":
                            rebound.symlink_to(external)
                        elif alias == "hardlink":
                            os.link(external, rebound)
                        else:
                            rebound.write_bytes(b"foreign-temporary\n")
                            rebound.chmod(0o600)

                with mock.patch.object(self.authority.os, "fsync", side_effect=replace_temporary_after_file_sync):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.authority.begin(root, "leaf1", "operation-2", "trigger-2", "manual_config_sync_cli")
                self.assertIsNotNone(rebound)
                self.assertTrue(rebound.exists(), "foreign controlled-name occupant must be retained")
                self.assertEqual(b"foreign-image\n", external.read_bytes())
                self.assertEqual(old_journal, (private / "leaf1.journal.json").read_bytes())
                self.assertEqual(old_witness, (private / "leaf1.witness.json").read_bytes())
                self.assertTrue((private / "leaf1.pending").exists())

    def test_rebound_or_removed_transaction_guard_cannot_reexpose_old_success(self):
        for mutation in ("remove", "replace", "mode"):
            with self.subTest(mutation=mutation):
                root = self.root.parent / ("guard-" + mutation)
                root.mkdir(mode=0o700)
                first = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                self.authority.finish(root, first, self.result(first))
                private = root / ".authority"
                journal, witness = private / "leaf1.journal.json", private / "leaf1.witness.json"
                old_pair = journal.read_bytes(), witness.read_bytes()
                marker = private / "leaf1.pending"
                real_fsync = os.fsync
                changed = False

                def mutate_guard_after_file_sync(descriptor):
                    nonlocal changed
                    real_fsync(descriptor)
                    if stat.S_ISREG(os.fstat(descriptor).st_mode) and marker.exists() and not changed:
                        changed = True
                        if mutation == "mode":
                            marker.chmod(0o644)
                        else:
                            marker.unlink()
                            if mutation == "replace":
                                marker.write_bytes(b"foreign-guard\n")
                                marker.chmod(0o600)

                with mock.patch.object(self.authority.os, "fsync", side_effect=mutate_guard_after_file_sync):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.authority.begin(root, "leaf1", "operation-2", "trigger-2", "manual_config_sync_cli")
                self.assertTrue(changed)
                self.assertEqual(old_pair, (journal.read_bytes(), witness.read_bytes()))
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.read_current(root, "leaf1")
                if mutation == "replace":
                    self.assertEqual(b"foreign-guard\n", marker.read_bytes(), "reject-and-retain foreign guard")
                elif mutation == "mode":
                    self.assertEqual(0o644, stat.S_IMODE(marker.stat().st_mode))

    def test_pair_publication_rejects_foreign_image_after_rename(self):
        for alias in ("regular", "symlink", "hardlink", "mode"):
            with self.subTest(alias=alias):
                root = self.root.parent / ("published-" + alias)
                root.mkdir(mode=0o700)
                first = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                self.authority.finish(root, first, self.result(first))
                private = root / ".authority"
                witness = private / "leaf1.witness.json"
                old_journal = (private / "leaf1.journal.json").read_bytes()
                external = root / "foreign.json"
                external.write_bytes(b"foreign-after-rename\n")
                external.chmod(0o600)
                changed = False
                real_replace = os.replace

                def replace_then_rebind(source, destination, **kwargs):
                    nonlocal changed
                    result = real_replace(source, destination, **kwargs)
                    if str(destination) == "leaf1.witness.json" and not changed:
                        changed = True
                        if alias == "mode":
                            witness.chmod(0o644)
                        else:
                            witness.unlink()
                            if alias == "symlink":
                                witness.symlink_to(external)
                            elif alias == "hardlink":
                                os.link(external, witness)
                            else:
                                witness.write_bytes(b"foreign-after-rename\n")
                                witness.chmod(0o600)
                    return result

                with mock.patch.object(self.authority.os, "replace", side_effect=replace_then_rebind):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.authority.begin(root, "leaf1", "operation-2", "trigger-2", "manual_config_sync_cli")
                self.assertTrue(changed, "fault reaches the real publication boundary")
                self.assertEqual(old_journal, (private / "leaf1.journal.json").read_bytes())
                self.assertTrue((private / "leaf1.pending").exists())
                self.assertEqual(b"foreign-after-rename\n", external.read_bytes())
                if alias == "symlink":
                    self.assertTrue(witness.is_symlink())
                elif alias == "hardlink":
                    self.assertEqual(external.stat().st_ino, witness.stat().st_ino)
                elif alias == "mode":
                    self.assertEqual(0o644, stat.S_IMODE(witness.stat().st_mode))
                else:
                    self.assertEqual(b"foreign-after-rename\n", witness.read_bytes())
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.read_current(root, "leaf1")

    def test_every_publication_file_and_directory_sync_fault_preserves_hold(self):
        # One transaction syncs marker, held writer, witness and journal files, and the
        # directory after guard creation, both replacements and guard removal.
        # These eight contract boundaries are independent of implementation
        # constants; no failure may expose either an old or incomplete success.
        for completing in (False, True):
            for kind, ordinals in (("file", (1, 2, 3, 4)), ("directory", (1, 2, 3, 4))):
                for ordinal in ordinals:
                    with self.subTest(completing=completing, kind=kind, ordinal=ordinal):
                        root = self.root.parent / f"fault-{int(completing)}-{kind}-{ordinal}"
                        root.mkdir(mode=0o700)
                        first = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
                        self.authority.finish(root, first, self.result(first))
                        second = None
                        if completing:
                            second = self.authority.begin(root, "leaf1", "operation-2", "trigger-2", "manual_config_sync_cli")
                        real_fsync = os.fsync
                        matching_syncs = 0
                        injected = False

                        def fail_selected_sync(descriptor):
                            nonlocal matching_syncs, injected
                            metadata = os.fstat(descriptor)
                            matches = stat.S_ISREG(metadata.st_mode) if kind == "file" else stat.S_ISDIR(metadata.st_mode)
                            if matches:
                                matching_syncs += 1
                                if matching_syncs == ordinal:
                                    injected = True
                                    raise OSError("injected exact publication sync fault")
                            real_fsync(descriptor)

                        with mock.patch.object(self.authority.os, "fsync", side_effect=fail_selected_sync):
                            with self.assertRaises(OSError):
                                if completing:
                                    self.authority.finish(root, second, self.result(second))
                                else:
                                    self.authority.begin(root, "leaf1", "operation-2", "trigger-2", "manual_config_sync_cli")
                        self.assertTrue(injected, "the selected boundary must actually execute")
                        with self.assertRaises(self.authority.AuthorityError):
                            self.authority.read_current(root, "leaf1")
                        private = root / ".authority"
                        self.assertTrue((private / "leaf1.pending").exists())
                        self.assertEqual([], list(private.glob(".*.tmp")), "clean unchanged owned staging files")

    def test_final_directory_sync_rechecks_both_published_images_and_retains_foreign_occupant(self):
        for component in ("witness", "journal"):
            with self.subTest(component=component):
                root = self.root.parent / ("final-sync-" + component)
                root.mkdir(mode=0o700)
                ticket = self.authority.begin(root, "leaf1", "op-1", "trigger-1", "manual_config_sync_cli")
                private = root / ".authority"
                target = private / ("leaf1." + component + ".json")
                marker = private / "leaf1.pending"
                foreign = root / "foreign.json"
                foreign.write_bytes(b"foreign-after-final-sync\n")
                foreign.chmod(0o600)
                changed = False
                real_fsync = os.fsync

                def rebind_after_guard_unlink(descriptor):
                    nonlocal changed
                    real_fsync(descriptor)
                    value = os.fstat(descriptor)
                    if (stat.S_ISDIR(value.st_mode) and value.st_ino == private.stat().st_ino
                            and not marker.exists() and not changed):
                        changed = True
                        target.unlink()
                        target.symlink_to(foreign)

                with mock.patch.object(self.authority.os, "fsync", side_effect=rebind_after_guard_unlink):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.authority.finish(root, ticket, self.result(ticket))
                self.assertTrue(changed)
                self.assertTrue(target.is_symlink(), "foreign published occupant is retained")
                self.assertEqual(b"foreign-after-final-sync\n", foreign.read_bytes())
                self.assertTrue(marker.exists(), "late rebinding must restore persistent HOLD")
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.read_current(root, "leaf1")

    def test_new_authority_parent_chain_is_durable_before_descendant_publication(self):
        root = self.root / "new-output" / "new-sync-root"
        events = []
        real_mkdir, real_fsync = os.mkdir, os.fsync

        def record_mkdir(path, mode=0o777, *, dir_fd=None):
            result = real_mkdir(path, mode, dir_fd=dir_fd)
            parent = os.fstat(dir_fd)
            events.append(("mkdir", str(path), (parent.st_dev, parent.st_ino)))
            return result

        def record_fsync(descriptor):
            metadata = os.fstat(descriptor)
            events.append(("directory" if stat.S_ISDIR(metadata.st_mode) else "file", "",
                           (metadata.st_dev, metadata.st_ino)))
            real_fsync(descriptor)

        with mock.patch.object(self.authority.os, "mkdir", side_effect=record_mkdir), \
                mock.patch.object(self.authority.os, "fsync", side_effect=record_fsync):
            pending = self.authority.begin(root, "leaf1", "operation-1", "trigger-1", "manual_config_sync_cli")
        created = [index for index, event in enumerate(events) if event[0] == "mkdir"]
        self.assertEqual(["new-output", "new-sync-root", ".authority"], [events[index][1] for index in created])
        for index in created:
            self.assertEqual(("directory", "", events[index][2]), events[index + 1],
                             "a new directory entry is fsynced in its parent before descendant writes")
        self.assertEqual((1, "pending", True), tuple(pending[field] for field in ("generation", "state", "veto")))


if __name__ == "__main__":
    unittest.main()
