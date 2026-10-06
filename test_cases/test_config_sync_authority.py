"""Independent F02 local generation/veto contracts (no device operations)."""

import importlib.util
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class ConfigSyncAuthorityTests(unittest.TestCase):
    def test_teardown_authenticates_all_histories_before_any_withdrawal(self):
        for fault in ("missing-lock", "missing-witness", "hold", "unsafe-journal"):
            with self.subTest(fault=fault):
                root = self.root / fault
                first = self.authority.begin_method(root, "leaf1", "first", "first-leaf1", "ztp_monitor_cycle")
                self.authority.finish_method(root, first, self.method_receipt_v2(first))
                second = self.authority.begin_method(root, "leaf2", "second", "second-leaf2", "ztp_monitor_cycle")
                self.authority.finish_method(root, second, self.method_receipt_v2(second, hostname="leaf2"))
                private = root / ".authority"
                if fault == "missing-lock": (private / "leaf2.lock").unlink()
                if fault == "missing-witness": (private / "leaf2.witness.json").unlink()
                if fault == "hold": (private / "leaf2.pending").write_bytes(b"uncertain held transaction")
                if fault == "unsafe-journal": (private / "leaf2.journal.json").chmod(0o644)
                before = {path.name: path.read_bytes() for path in private.iterdir()}
                with self.assertRaises(self.authority.AuthorityError):
                    self.authority.withdraw_all(root, method=True)
                self.assertEqual(before, {path.name: path.read_bytes() for path in private.iterdir()})
                self.assertEqual("success", self.authority.read_method_current(root, "leaf1")["state"])

    def test_teardown_preserves_new_writer_and_rejects_population_changes(self):
        for case in ("new-writer", "new-host"):
            with self.subTest(case=case):
                root = self.root / case
                ticket = self.authority.begin_method(root, "leaf1", "first", "first-leaf1", "ztp_monitor_cycle")
                self.authority.finish_method(root, ticket, self.method_receipt_v2(ticket))
                original = self.authority._current
                inserted = []
                def capture_then_writer(*args, **kwargs):
                    current = original(*args, **kwargs)
                    if not inserted:
                        inserted.append(True)
                        # This seam is after the read and before the next scope;
                        # the separate writer runs when capture releases its lock.
                    return current
                original_scope = self.authority._scope
                from contextlib import contextmanager
                @contextmanager
                def scope_then_writer(*args, **kwargs):
                    with original_scope(*args, **kwargs) as value:
                        yield value
                    if len(inserted) == 1:
                        inserted.append(True)
                        self.authority.begin_method(root, "leaf1" if case == "new-writer" else "leaf2",
                                                    "new", "new-own", "ztp_monitor_cycle")
                with mock.patch.object(self.authority, "_current", side_effect=capture_then_writer), \
                        mock.patch.object(self.authority, "_scope", side_effect=scope_then_writer):
                    with self.assertRaises(self.authority.AuthorityError):
                        self.authority.withdraw_all(root, method=True)
                current = self.authority.read_method_current(root, "leaf1")
                self.assertEqual((2, "pending") if case == "new-writer" else (1, "success"),
                                 (current["generation"], current["state"]))
                if case == "new-host":
                    self.assertEqual("pending", self.authority.read_method_current(root, "leaf2")["state"])

    def test_teardown_supports_hashed_hostname_without_deleting_old_receipts(self):
        hostname = "L" * 240
        ticket = self.authority.begin_method(self.root, hostname, "long", "long-own", "ztp_monitor_cycle")
        self.authority.finish_method(self.root, ticket, self.method_receipt_v2(ticket, hostname=hostname))
        receipts = {path: path.read_bytes() for path in self.root.rglob("*.json") if ".authority" not in path.parts}
        self.assertEqual(1, self.authority.withdraw_all(self.root, method=True))
        self.assertEqual("failed", self.authority.read_method_current(self.root, hostname)["state"])
        self.assertEqual(receipts, {path: path.read_bytes() for path in receipts})

    def test_project_teardown_withdraws_both_authority_formats_without_new_generations(self):
        withdraw = getattr(self.authority, "withdraw_all", None)
        self.assertTrue(callable(withdraw), "teardown must withdraw local authority, not just detach links")
        absent = self.root / "absent"
        self.assertEqual(0, withdraw(absent, method=True))
        self.assertFalse(absent.exists())
        for method in (False, True):
            with self.subTest(method=method):
                root = self.root / ("methods" if method else "manual")
                begin = self.authority.begin_method if method else self.authority.begin
                finish = self.authority.finish_method if method else self.authority.finish
                read = self.authority.read_method_current if method else self.authority.read_current
                ticket = begin(root, "leaf1", "teardown", "teardown-leaf1", "ztp_monitor_cycle" if method else "manual_config_sync_cli")
                result = self.method_receipt_v2(ticket) if method else self.result(ticket)
                finish(root, ticket, result)
                self.assertEqual(1, withdraw(root, method=method))
                self.assertEqual((1, "failed", True, ""), tuple(read(root, "leaf1")[name] for name in ("generation", "state", "veto", "receipt_sha256")))
                with self.assertRaises(self.authority.AuthorityError): finish(root, ticket, result)
                self.assertEqual(1, withdraw(root, method=method))
                second = begin(root, "leaf1", "after-teardown", "new-leaf1", "ztp_monitor_cycle" if method else "manual_config_sync_cli")
                self.assertEqual(2, second["generation"])

    def test_initial_monitor_profile_target_has_no_default_or_foreign_identity(self):
        reader = object.__new__(self.authority.InitialMethodMonitorInputs)
        reader.initial = SimpleNamespace(normalize_mac=lambda value, **kwargs: value.lower())
        target = SimpleNamespace(ib=SimpleNamespace(hostname="IB01", dev_type="ib", login_ip="192.0.2.10", eth0_mac="02:00:00:00:00:01"))
        reader.targets = [target]
        device = {"hostname": "IB01", "type": "ib", "config_method": "initial-setup", "ip": "192.0.2.10", "mac_plain": "020000000001"}
        self.assertIs(target, reader.target(device))
        for update in ({"hostname": "IB02"}, {"type": "nvl"}, {"config_method": "ztp"}, {"config_method": ""},
                       {"ip": "192.0.2.11"}, {"mac_plain": "020000000002"}):
            with self.subTest(update=update), self.assertRaises(self.authority.AuthorityError):
                reader.target({**device, **update})
        reader.targets.append(target)
        with self.assertRaises(self.authority.AuthorityError): reader.target(device)

    def test_initial_monitor_reader_cannot_inherit_writer_entry_points(self):
        reader = object.__new__(self.authority.InitialMethodMonitorInputs)
        with self.assertRaises(self.authority.AuthorityError): reader.start()
        with self.assertRaises(self.authority.AuthorityError): reader.complete()

    def test_initial_method_projection_requires_own_fresh_configuration_not_bootstrap(self):
        receipt = self.method_receipt_v2(hostname="IB01", type="ib", config_method="initial-setup",
                                         trigger_source="initial_setup_managed")
        fresh = {"schema_version": 1, "hostname": "IB01", "batch_identity_verified": True, "config_verified": True,
                 "interface": "eth0", "transport_ip": "192.0.2.10", "mac_plain": "020000000001",
                 "live_state_sha256": "a" * 64, "input_sha256": "b" * 64, "observation_sha256": "c" * 64, "reason": ""}
        receipt.update(transport_ip="192.0.2.10", live_state_sha256="a" * 64, input_sha256="b" * 64,
                       source_receipt_sha256="c" * 64)
        device = {"hostname": "IB01", "type": "ib", "config_method": "initial-setup", "ip": "192.0.2.10",
                  "mac_plain": "020000000001", "configuration_method_authority": receipt,
                  "configuration_method_observation": fresh,
                  "configuration_observation": {"schema_version": 1, "source": "monitor_batchmode", "hostname": "IB01",
                    "batch_identity_verified": True, "interface": "eth0", "transport_ip": "192.0.2.10",
                    "mac_plain": "020000000001", "live_state_sha256": "a" * 64, "reason": ""}}
        self.assertTrue(self.authority.monitor_method_observation_allows_completion(device))
        self.assertTrue(self.authority.monitor_source_observation_allows_completion(
            {**device, "configuration_source_observation": {"reason": "unrelated old bootstrap"}}),
            "a current initial-setup proof must not depend on bootstrap provenance")
        self.assertFalse(self.authority.monitor_source_observation_allows_completion(
            {key: value for key, value in device.items() if key != "configuration_method_authority"}),
            "initial-setup has no implicit completion authority")
        for update in ({"config_verified": 1}, {"batch_identity_verified": 1}, {"input_sha256": "d" * 64},
                       {"hostname": "IB02"}, {"transport_ip": "192.0.2.11"}, {"mac_plain": "020000000002"},
                       {"live_state_sha256": "d" * 64}, {"generation": 1}, {"reason": "stale"}):
            with self.subTest(update=update):
                self.assertFalse(self.authority.monitor_method_observation_allows_completion(
                    {**device, "configuration_method_observation": {**fresh, **update}}))
        self.assertFalse(self.authority.monitor_method_observation_allows_completion(
            {key: value for key, value in device.items() if key != "configuration_method_observation"}))
        self.assertFalse(self.authority.monitor_method_observation_allows_completion(
            {**device, "type": "nvl"}))

    def test_managed_initial_profile_root_is_the_explicit_project_not_loaded_code(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            cycle = self.authority.ManagedInitialMethodCycle(project, SimpleNamespace(__file__="/unrelated/repository/initial-setup.py"))
            self.assertEqual(project / "infiniband/bringup/xdr-initial-setup", cycle.tool_input_root)
            self.assertFalse(cycle.root.exists(), "binding an input root must not mint a method era")

    def test_managed_initial_cycle_strict_observation_and_late_failure_withdrawal(self):
        target = SimpleNamespace(ib=SimpleNamespace(hostname="IB01", dev_type="ib", login_ip="192.0.2.10", eth0_mac="02:00:00:00:00:01"))
        proof = {"schema_version": 1, "hostname": "IB01", "batch_identity_verified": True, "config_verified": True,
                 "interface": "eth0", "transport_ip": "192.0.2.10", "mac_plain": "020000000001",
                 "live_state_sha256": "a" * 64, "input_sha256": "b" * 64, "observation_sha256": "c" * 64, "reason": ""}
        initial = SimpleNamespace(desired_service_commands=lambda *a: None, key_install_command=lambda *a: None,
            initial_method_input_digest=lambda *a: "b" * 64, normalize_mac=lambda *a, **k: "02:00:00:00:00:01",
            observe_managed_initial_configuration=lambda *a: dict(proof))
        services, keys = {"dns": ["192.0.2.53"], "ntp": ["time.example.test"], "timezone": "Etc/UTC"}, [{"name": "fixture"}]
        for case in ("positive", "boolean", "foreign-host", "foreign-input", "extra-generation", "late-read-failure", "late-input-change", "newer-writer"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                cycle = self.authority.ManagedInitialMethodCycle(project, initial)
                observed = dict(proof)
                if case == "boolean": observed["config_verified"] = 1
                if case == "foreign-host": observed["hostname"] = "IB02"
                if case == "foreign-input": observed["input_sha256"] = "d" * 64
                if case == "extra-generation": observed["generation"] = 1
                initial.observe_managed_initial_configuration = lambda *args: observed
                with mock.patch.object(cycle, "_inputs", return_value=["literal-original-input"]):
                    cycle.start(project, project / "cache", project / "csv", project / "p2p", [target], services, keys)
                    with ExitStack() as stack:
                        if case == "late-read-failure":
                            stack.enter_context(mock.patch.object(self.authority, "read_method_receipt",
                                side_effect=self.authority.AuthorityError("injected held-read failure")))
                        elif case == "late-input-change":
                            stack.enter_context(mock.patch.object(cycle, "_inputs", side_effect=(
                                ["literal-original-input"], ["literal-original-input"], ["changed-at-publication"])))
                        elif case == "newer-writer":
                            def newer_writer(*args):
                                self.authority.begin_method(cycle.root, "IB01", "new-writer", "own-new-writer", "initial_setup_managed")
                                return observed
                            stack.enter_context(mock.patch.object(initial, "observe_managed_initial_configuration", side_effect=newer_writer))
                        else:
                            stack.enter_context(mock.patch.object(initial, "observe_managed_initial_configuration", return_value=observed))
                        result = cycle.complete(target, "admin", project / "key", 5, services, keys)
                current = self.authority.read_method_current(cycle.root, "IB01")
                self.assertEqual(case == "positive", result)
                self.assertEqual("success" if case == "positive" else "pending" if case == "newer-writer" else "failed", current["state"])
                self.assertEqual(2 if case == "newer-writer" else 1, current["generation"])

    def test_managed_initial_input_snapshot_rechecks_root_after_last_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            project = base / "project"
            project.mkdir()
            tool = project / "tool"
            (tool / "publickey").mkdir(parents=True)
            for path in (project / "cache", project / "cache.sha256", project / "csv", project / "p2p",
                         tool / "01-global.yaml", tool / "publickey/management.pub"):
                path.write_text("independent finite fixture bytes\n")
            target = SimpleNamespace(ib=SimpleNamespace(hostname="IB01", dev_type="ib"))
            def late_parser(*args, **kwargs):
                project.rename(base / "retained-original-project")
                project.mkdir()
                return 1, [target]
            cycle = self.authority.ManagedInitialMethodCycle(project, SimpleNamespace(load_target_cache=late_parser))
            cycle.tool, cycle.cache, cycle.csv, cycle.p2p, cycle.targets = tool, project / "cache", project / "csv", project / "p2p", [target]
            with self.assertRaises(self.authority.AuthorityError):
                cycle._inputs()

    def test_managed_initial_input_snapshot_rechecks_public_key_membership_after_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            tool = project / "tool"
            (tool / "publickey").mkdir(parents=True)
            for path in (project / "cache", project / "cache.sha256", project / "csv", project / "p2p",
                         tool / "01-global.yaml", tool / "publickey/management.pub"):
                path.write_text("independent original input image\n")
            target = SimpleNamespace(ib=SimpleNamespace(hostname="IB01", dev_type="ib"))
            def parser_then_new_member(*args, **kwargs):
                (tool / "publickey/new.pub").write_text("independent late key addition\n")
                return 1, [target]
            cycle = self.authority.ManagedInitialMethodCycle(project, SimpleNamespace(load_target_cache=parser_then_new_member))
            cycle.tool, cycle.cache, cycle.csv, cycle.p2p, cycle.targets = tool, project / "cache", project / "csv", project / "p2p", [target]
            with self.assertRaises(self.authority.AuthorityError):
                cycle._inputs()
            self.assertTrue((tool / "publickey/new.pub").exists(), "foreign input must be retained")

    def test_managed_initial_cli_safe_help_and_no_implicit_project(self):
        entry = getattr(self.authority, "managed_initial_main", None)
        self.assertTrue(callable(entry), "the managed producer must be reachable by a real entrypoint")
        with self.assertRaises(SystemExit) as absent:
            entry([])
        self.assertEqual(2, absent.exception.code)
        with self.assertRaises(SystemExit) as help_exit:
            entry(["--help"])
        self.assertEqual(0, help_exit.exception.code)

    def test_managed_initial_partial_begin_failure_withdraws_only_minted_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            targets = [SimpleNamespace(ib=SimpleNamespace(hostname=name, dev_type="ib")) for name in ("IB01", "IB02")]
            cycle = self.authority.ManagedInitialMethodCycle(project, SimpleNamespace())
            real_begin = self.authority.begin_method
            def first_then_failure(*args):
                if args[1] == "IB02":
                    raise self.authority.AuthorityError("independent second writer admission failure")
                return real_begin(*args)
            with mock.patch.object(self.authority, "begin_method", side_effect=first_then_failure), self.assertRaises(self.authority.AuthorityError):
                cycle.start(project, project / "cache", project / "csv", project / "p2p", targets, {"dns": []}, [{"name": "fixture"}])
            self.assertEqual("failed", self.authority.read_method_current(cycle.root, "IB01")["state"])
            self.assertIsNone(self.authority.read_method_current(cycle.root, "IB02"))
            cycle.close()

    @staticmethod
    def method_receipt_v2(ticket=None, **updates):
        # Independent method contract: deliberately NOT replace-config v1.
        value = {"schema_version": 2, "record_type": "configuration_method",
                 "hostname": "leaf1", "type": "eth", "config_method": "ztp",
                 "generation": 1, "source_identity": "1:2", "operation_id": "cycle-1",
                 "trigger_id": "leaf1-cycle-1", "trigger_source": "ztp_monitor_cycle",
                 "state": "success", "reason": "", "batch_identity_verified": True,
                 "config_verified": True, "interface": "eth0", "transport_ip": "192.0.2.10",
                 "mac_plain": "020000000001", "live_state_sha256": "a" * 64,
                 "input_sha256": "b" * 64, "source_receipt_sha256": "c" * 64}
        if ticket is not None:
            for field in ("hostname", "generation", "source_identity", "operation_id",
                          "trigger_id", "trigger_source"):
                value[field] = ticket[field]
        return {**value, **updates}

    def test_method_v2_local_cycle_cannot_borrow_manual_schema_or_reporter_clock(self):
        for name in ("begin_method", "finish_method", "read_method_current", "read_method_receipt", "revoke_method"):
            self.assertTrue(callable(getattr(self.authority, name, None)), name)
        root = self.root.parent / "configuration-methods"
        self.assertIsNone(self.authority.read_method_current(root, "leaf1"))
        self.assertFalse(root.exists(), "readers cannot manufacture history")
        first = self.authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
        self.assertEqual((2, 1, "pending", True), tuple(first[k] for k in ("schema_version", "generation", "state", "veto")))
        receipt = self.method_receipt_v2(first)
        self.authority.finish_method(root, first, receipt)
        self.assertEqual(receipt, self.authority.read_method_receipt(root, "leaf1"))
        for value in (receipt, self.receipt_v1(), {**receipt, "started_at": "2099-01-01T00:00:00+00:00"}):
            with self.subTest(value=value):
                decoder = self.authority.decode_receipt if value is receipt else self.authority.decode_method_receipt
                with self.assertRaises(self.authority.AuthorityError):
                    decoder(self.authority.wire(value))
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.read_current(root, "leaf1")
        second = self.authority.begin_method(root, "leaf1", "cycle-2", "leaf1-cycle-2", "ztp_monitor_cycle")
        self.assertEqual(2, second["generation"])
        self.assertIsNone(self.authority.read_method_receipt(root, "leaf1"))
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.finish_method(root, first, receipt)
        self.assertIsNone(self.authority.revoke_method(root, "leaf1", expected=first))
        self.assertEqual(second, self.authority.read_method_current(root, "leaf1"))
        revoked = self.authority.revoke_method(root, "leaf1", expected=second)
        self.assertEqual((2, "failed", True), tuple(revoked[k] for k in ("generation", "state", "veto")))
        self.assertIsNone(self.authority.read_method_receipt(root, "leaf1"))
        self.assertEqual(3, self.authority.begin_method(root, "leaf1", "cycle-3", "leaf1-cycle-3", "ztp_monitor_cycle")["generation"])

    def test_method_v2_closed_schema_keeps_own_strict_proof_and_executor(self):
        decoder = getattr(self.authority, "decode_method_receipt", None)
        self.assertTrue(callable(decoder))
        valid = self.method_receipt_v2()
        self.assertEqual(valid, decoder(self.authority.wire(valid)))
        initial = self.method_receipt_v2(type="ib", config_method="initial-setup", trigger_source="initial_setup_managed")
        self.assertEqual(initial, decoder(self.authority.wire(initial)))
        for updates in ({"schema_version": True}, {"generation": True}, {"generation": 1.0},
                        {"generation": 0}, {"generation": 9223372036854775808},
                        {"batch_identity_verified": 1}, {"config_verified": "true"},
                        {"type": "server"}, {"type": "pending_ib"}, {"type": "eth", "config_method": "initial-setup"},
                        {"type": "nvl", "config_method": "initial-setup", "trigger_source": "initial_setup_managed"},
                        {"trigger_source": "manual_config_sync_cli"}, {"state": "pending"}, {"state": "failed"},
                        {"input_sha256": ""}, {"source_receipt_sha256": "A" * 64},
                        {"live_state_sha256": ""}, {"mac_plain": "g020000000001"},
                        {"transport_ip": "host.example.invalid"}, {"interface": "lo"},
                        {"source_identity": "18446744073709551616:1"}, {"reason": "HOLD"}, {"extra": "not closed"}):
            with self.subTest(updates=updates), self.assertRaises(self.authority.AuthorityError):
                decoder(self.authority.wire({**valid, **updates}))

    def test_method_v2_maximum_literal_acceptance_rejects_degenerate_budget(self):
        decoder = getattr(self.authority, "decode_method_receipt", None)
        self.assertTrue(callable(decoder))
        maximum = self.method_receipt_v2(hostname="h" * 253, operation_id="o" * 512,
                                       trigger_id="t" * 766, generation=9223372036854775807,
                                       source_identity="18446744073709551615:18446744073709551615",
                                       type="ib", config_method="initial-setup", trigger_source="initial_setup_managed",
                                       transport_ip="ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")
        # Fixed v2 fields, signed64/uint64 limits and diagnostics <=1024 code
        # points. The larger failed image has no success members at all.
        failed = {k: v for k, v in maximum.items() if k in {
            "schema_version", "record_type", "hostname", "type", "config_method", "generation",
            "source_identity", "operation_id", "trigger_id", "trigger_source", "state", "reason"}}
        failed.update(state="failed", reason="\U0001f642" * 1024)
        for value, maximum_bytes in ((maximum, 2270), (failed, 14134)):
            raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self.assertEqual(maximum_bytes, len(raw), "independent V2 fixed-field canonical derivation")
            self.assertLessEqual(len(raw), 16384, "independent finite v2 bound")
            self.assertEqual(value, decoder(raw), "schema maximum MUST be ACCEPTED")
            def acceptance():
                try:
                    accepted = decoder(raw)
                except self.authority.AuthorityError:
                    accepted = None
                self.assertEqual(value, accepted, "maximum positive acceptance")
            for smaller in (0, len(raw) // 2, len(raw) - 1):
                with self.subTest(limit=smaller), mock.patch.object(self.authority, "METHOD_RECEIPT_MAX_BYTES", smaller):
                    with self.assertRaises(AssertionError):
                        acceptance()
        with self.assertRaises(self.authority.AuthorityError):
            decoder(self.authority.wire({**failed, "reason": "\U0001f642" * 1025}))

    def test_method_v2_durability_fault_after_receipt_keeps_pending_or_hold(self):
        self.assertTrue(callable(getattr(self.authority, "finish_method", None)))
        for fail_at in range(1, 11):
            with self.subTest(sync=fail_at):
                root = self.root.parent / ("method-sync-" + str(fail_at))
                ticket = self.authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
                actual_sync = self.authority.os.fsync
                calls = [0]
                def injected(fd):
                    calls[0] += 1
                    if calls[0] == fail_at:
                        raise OSError("independent method durability fault")
                    return actual_sync(fd)
                with mock.patch.object(self.authority.os, "fsync", side_effect=injected):
                    with self.assertRaises((OSError, self.authority.AuthorityError)):
                        self.authority.finish_method(root, ticket, self.method_receipt_v2(ticket))
                try:
                    current = self.authority.read_method_current(root, "leaf1")
                except self.authority.AuthorityError:
                    self.assertTrue((root / ".authority/leaf1.pending").exists())
                else:
                    self.assertEqual(("pending", True), (current["state"], current["veto"]))
                    self.assertIsNone(self.authority.read_method_receipt(root, "leaf1"))

    def test_method_invalid_boundary_is_rejected_before_any_storage_write(self):
        self.assertTrue(callable(getattr(self.authority, "begin_method", None)))
        for source in ("manual_config_sync_cli", "unknown_method", "", True, None):
            root = self.root.parent / "invalid-method-boundary"
            with self.subTest(source=source), self.assertRaises(self.authority.AuthorityError):
                self.authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", source)
            self.assertFalse(root.exists(), "an incompatible source must fail BEFORE directory, lock or journal writes")

    def test_method_invalid_completion_and_revocation_do_not_create_history(self):
        invalid = {"schema_version": 2, "hostname": "leaf1", "generation": True,
                   "operation_id": "cycle-1", "trigger_id": "leaf1-cycle-1",
                   "trigger_source": "ztp_monitor_cycle", "source_identity": "1:2",
                   "state": "pending", "veto": True, "receipt_sha256": ""}
        root = self.root.parent / "invalid-method-completion"
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.finish_method(root, invalid, self.method_receipt_v2())
        self.assertFalse(root.exists(), "invalid ticket cannot create storage before rejection")
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.revoke_method(root, "leaf1", expected=invalid)
        self.assertFalse(root.exists(), "invalid revocation cannot create storage before rejection")

    def test_method_v2_replay_and_unsafe_receipt_are_reject_and_retain(self):
        self.assertTrue(callable(getattr(self.authority, "begin_method", None)))
        root = self.root.parent / "configuration-methods"
        first = self.authority.begin_method(root, "leaf1", "cycle-1", "leaf1-cycle-1", "ztp_monitor_cycle")
        self.authority.finish_method(root, first, self.method_receipt_v2(first))
        private = root / ".authority"
        receipt = private / "leaf1.method.json"
        original = receipt.read_bytes()
        receipt.chmod(0o644)
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.read_method_receipt(root, "leaf1")
        self.assertEqual(original, receipt.read_bytes())
        receipt.chmod(0o600)
        old_pair = {name: (private / name).read_bytes() for name in ("leaf1.journal.json", "leaf1.witness.json")}
        second = self.authority.begin_method(root, "leaf1", "cycle-2", "leaf1-cycle-2", "ztp_monitor_cycle")
        self.authority.finish_method(root, second, self.method_receipt_v2(second, live_state_sha256="d" * 64))
        current_pair = {name: (private / name).read_bytes() for name in old_pair}
        receipt.write_bytes(original)
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.read_method_receipt(root, "leaf1")
        self.assertEqual(original, receipt.read_bytes())
        for name in old_pair:
            (private / name).write_bytes(old_pair[name])
        with self.assertRaises(self.authority.AuthorityError):
            self.authority.read_method_current(root, "leaf1")
        self.assertEqual(old_pair, {name: (private / name).read_bytes() for name in old_pair})
        for name in current_pair:
            (private / name).write_bytes(current_pair[name])

    def test_current_manual_application_requires_closed_authority_and_own_live_proof(self):
        gate = getattr(self.authority, "monitor_current_config_sync_allows_application", None)
        self.assertTrue(callable(gate), "manual application and bootstrap completion have independent sources")
        observed = {"schema_version": 1, "source": "monitor_batchmode", "batch_identity_verified": True,
                    "hostname": "leaf1", "interface": "eth0", "transport_ip": "192.0.2.1",
                    "mac_plain": "021122334455", "live_state_sha256": "a" * 64, "reason": ""}
        authority = {"schema_version": 1, "source": "local_config_sync_authority",
                     "observation_source": "monitor_batchmode", "state": "success", "veto": False,
                     "generation": 1, "source_identity": "123:456", "live_state_sha256": "a" * 64, "reason": ""}
        device = {"hostname": "leaf1", "ip": "192.0.2.1", "mac_plain": "021122334455",
                  "configuration_observation": observed, "configuration_authority": authority,
                  "configuration_source_observation": None}
        self.assertTrue(gate(device))
        self.assertFalse(self.authority.monitor_observation_allows_completion(device))
        for value in (None, {}, {**authority, "schema_version": True}, {**authority, "veto": 0},
                      {**authority, "generation": True}, {**authority, "generation": 0},
                      {**authority, "generation": 1.0}, {**authority, "generation": 9223372036854775808},
                      {**authority, "source": "bootstrap"}, {**authority, "state": "pending"},
                      {**authority, "source_identity": ""}, {**authority, "source_identity": "b" * 64},
                      {**authority, "source_identity": "18446744073709551616:1"},
                      {**authority, "live_state_sha256": "c" * 64},
                      {**authority, "reason": "HOLD"}, {**authority, "extra": "not closed"}):
            with self.subTest(authority=value):
                device["configuration_authority"] = value
                before = json.dumps(device, sort_keys=True)
                self.assertFalse(gate(device))
                self.assertEqual(before, json.dumps(device, sort_keys=True))
        device["configuration_authority"] = authority
        for value in (None, {}, {**observed, "hostname": "foreign"},
                      {**observed, "batch_identity_verified": 1}, {**observed, "reason": "failed"}):
            with self.subTest(observation=value):
                device["configuration_observation"] = value
                self.assertFalse(gate(device))
        device.pop("configuration_observation")
        self.assertFalse(gate(device), "legacy absence cannot authorize manual application")

    def test_source_decoder_rejects_malformed_mac_instead_of_stripping_foreign_characters(self):
        from test_cases.test_manual_applied_config import MonitorAppliedConfigObservationTests
        payload = MonitorAppliedConfigObservationTests.wire("- set: {}\n")
        for expected in ("020000000001", "02:00:00:00:00:01"):
            self.assertIs(True, self.authority.decode_applied_config(0, payload, expected)["trusted"])
        for malformed in ("g020000000001", "020000000001g", "02::00:00:00:00:01",
                          "02-00-00-00-00-01", "0200.0000.0001", " 020000000001", "020000000001 "):
            for where in ("inventory", "receipt"):
                with self.subTest(mac=malformed, where=where):
                    wire = payload if where == "inventory" else payload.replace("eth0_mac=02:00:00:00:00:01", "eth0_mac=" + malformed)
                    expected = malformed if where == "inventory" else "020000000001"
                    parsed = self.authority.decode_applied_config(0, wire, expected)
                    self.assertIs(False, parsed["trusted"], "malformed identity is not the same valid MAC")
                    self.assertEqual({}, parsed["receipt"])
                    self.assertEqual("", parsed["raw_yaml"])

    def test_explicit_source_observation_requires_closed_strict_own_identity(self):
        gate = getattr(self.authority, "monitor_source_observation_allows_completion", None)
        self.assertTrue(callable(gate), "both completion consumers must honor explicit source veto")
        row = {"hostname": "leaf01", "mac_plain": "020000000001", "config_method": "ztp"}
        source = {"schema_version": 1, "source": "monitor_bootstrap_applied", "source_receipt_verified": True,
                  "hostname": "leaf01", "mac_plain": "020000000001", "raw_sha256": "a" * 64,
                  "source_fingerprint": "b" * 64, "reason": ""}
        self.assertTrue(gate(row), "absence of this transitional field cannot mint a source receipt")
        row["configuration_source_observation"] = source
        self.assertTrue(gate(row))
        for value in (None, {}, {**source, "source_receipt_verified": 1}, {**source, "schema_version": True},
                      {**source, "hostname": "foreign"}, {**source, "mac_plain": "020000000002"},
                      {**source, "raw_sha256": ""}, {**source, "source_fingerprint": "A" * 64},
                      {**source, "generation": 999}, {**source, "reason": "HOLD"}):
            with self.subTest(source=value):
                row["configuration_source_observation"] = value
                before = json.dumps(row, sort_keys=True)
                self.assertFalse(gate(row))
                self.assertEqual(before, json.dumps(row, sort_keys=True))

    def test_applied_source_decoder_is_closed_read_only_and_shared_without_minting_an_era(self):
        from test_cases.test_manual_applied_config import MonitorAppliedConfigObservationTests
        raw = "- set:\n    system:\n      hostname: leaf01\n\n"
        payload = MonitorAppliedConfigObservationTests.wire(raw)
        prior = (self.root.stat().st_ino, self.root.stat().st_mtime_ns, list(self.root.iterdir()))
        with mock.patch.object(self.authority.os, "open", side_effect=AssertionError("a provenance decoder must not write/read a generation")):
            observed = self.authority.decode_applied_config(0, payload, "020000000001")
        self.assertIs(True, observed["trusted"])
        self.assertEqual(raw, observed["raw_yaml"])
        self.assertEqual("dedicated", observed["receipt"]["source_kind"])
        self.assertNotIn("generation", observed)
        for code, text, mac in ((23, payload, "020000000001"),
                               (0, payload, "020000000002"),
                               (0, payload.replace("schema=1\n", "schema=1\nunknown=1\n"), "020000000001")):
            with self.subTest(code=code, mac=mac):
                rejected = self.authority.decode_applied_config(code, text, mac)
                self.assertIs(False, rejected["trusted"])
                self.assertEqual({}, rejected["receipt"])
                self.assertEqual("", rejected["raw_yaml"])
        self.assertEqual(prior, (self.root.stat().st_ino, self.root.stat().st_mtime_ns, list(self.root.iterdir())),
                         "decoding must leave the pre-existing empty authority directory unchanged")

    def test_completion_observation_gate_is_read_only_and_requires_own_closed_identity(self):
        gate = getattr(self.authority, "monitor_observation_allows_completion", None)
        self.assertTrue(callable(gate), "both completion consumers must share the explicit-observation veto")
        device = {"hostname": "leaf1", "ip": "192.0.2.1", "mac_plain": "021122334455"}
        observed = {"schema_version": 1, "source": "monitor_batchmode",
                    "batch_identity_verified": True, "hostname": "leaf1", "interface": "eth0",
                    "transport_ip": "192.0.2.1", "mac_plain": "021122334455",
                    "live_state_sha256": "a" * 64, "reason": ""}
        device["configuration_observation"] = observed
        before = json.dumps(device, sort_keys=True)
        self.assertTrue(gate(device))
        self.assertEqual(before, json.dumps(device, sort_keys=True))
        for value in (None, {}, {**observed, "batch_identity_verified": 1},
                      {**observed, "schema_version": True}, {**observed, "hostname": "foreign"},
                      {**observed, "live_state_sha256": ""}, {**observed, "reason": "failed"}):
            with self.subTest(value=value):
                device["configuration_observation"] = value
                before = json.dumps(device, sort_keys=True)
                self.assertFalse(gate(device))
                self.assertEqual(before, json.dumps(device, sort_keys=True))
        # Legacy absent observations are not upgraded into a new receipt.
        device.pop("configuration_observation")
        self.assertTrue(gate(device))
        self.assertNotIn("configuration_observation", device)

    def test_present_malformed_candidate_identity_is_not_absent_primary_identity(self):
        observed = {"schema_version": 1, "source": "monitor_batchmode", "batch_identity_verified": True,
                    "hostname": "leaf1", "interface": "eth0", "transport_ip": "192.0.2.1",
                    "mac_plain": "021122334455", "live_state_sha256": "a" * 64, "reason": ""}
        device = {"hostname": "leaf1", "ip": "192.0.2.1", "mac_plain": "021122334455",
                  "configuration_observation": observed}
        gate = self.authority.monitor_observation_allows_completion
        self.assertTrue(gate(device))
        for value in (False, None, 0, "", [], ()):
            with self.subTest(candidate_identity=value):
                device["candidate_identity"] = value
                before = json.dumps(device, sort_keys=True)
                self.assertFalse(gate(device), "unknown typed identity cannot silently become an absent mapping")
                self.assertEqual(before, json.dumps(device, sort_keys=True))
        device["candidate_identity"] = {}
        self.assertTrue(gate(device), "explicit empty valid mapping still allows own primary endpoint")

    def bound_reader(self):
        reader = getattr(self.authority, "read_current_receipt", None)
        self.assertTrue(callable(reader), "observers must authenticate the current receipt under its local generation lock")
        return reader

    def publish_read_fixture(self):
        ticket = self.begin()
        receipt = self.receipt_v1(source_identity=ticket["source_identity"])
        path = self.root / "run-1/leaf1/result.json"
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_text(json.dumps(receipt) + "\n", encoding="ascii")
        path.chmod(0o600)
        self.authority.finish(self.root, ticket, receipt)
        return path, receipt

    def test_current_receipt_reader_is_read_only_and_cannot_reuse_an_old_generation(self):
        path, receipt = self.publish_read_fixture()
        raw, metadata = path.read_bytes(), path.stat()
        reader = self.bound_reader()
        self.assertEqual(receipt, reader(self.root, "leaf1", path))
        self.assertEqual((raw, metadata.st_ino), (path.read_bytes(), path.stat().st_ino))
        next_ticket = self.begin("operation-2", "trigger-2")
        self.assertEqual(2, next_ticket["generation"])
        self.assertIsNone(reader(self.root, "leaf1", path))
        self.assertEqual(raw, path.read_bytes())
        self.authority.revoke(self.root, "leaf1")
        self.assertIsNone(reader(self.root, "leaf1", path))

    def test_current_receipt_reader_rejects_unsafe_images_and_retains_exact_bytes(self):
        path, receipt = self.publish_read_fixture()
        reader = self.bound_reader()
        original = path.read_bytes()
        for mode in (0o644, 0o666):
            with self.subTest(mode=mode):
                path.chmod(mode)
                with self.assertRaises(self.authority.AuthorityError):
                    reader(self.root, "leaf1", path)
                self.assertEqual(original, path.read_bytes())
        path.chmod(0o600)
        for raw in (b'{"schema_version":1,"schema_version":1}\n',
                    json.dumps({**receipt, "live_state_sha256": "b" * 64}).encode("ascii")):
            with self.subTest(raw=raw[:50]):
                path.write_bytes(raw)
                with self.assertRaises(self.authority.AuthorityError):
                    reader(self.root, "leaf1", path)
                self.assertEqual(raw, path.read_bytes())
        path.write_bytes(original)
        foreign = self.root / "foreign.json"
        foreign.write_bytes(original)
        foreign.chmod(0o600)
        path.unlink()
        path.symlink_to(foreign)
        with self.assertRaises(self.authority.AuthorityError):
            reader(self.root, "leaf1", path)
        self.assertTrue(path.is_symlink())
        self.assertEqual(original, foreign.read_bytes())

    def test_current_receipt_reader_rechecks_the_named_parent_after_read(self):
        path, _receipt = self.publish_read_fixture()
        reader = self.bound_reader()
        original_read = self.authority._read
        moved = path.parent.with_name("isolated-old-parent")
        changed = []
        def rebind_after_read(descriptor, name, *args, **kwargs):
            raw = original_read(descriptor, name, *args, **kwargs)
            if name == "result.json" and not changed:
                path.parent.rename(moved)
                path.parent.mkdir(mode=0o700)
                changed.append(True)
            return raw
        with mock.patch.object(self.authority, "_read", side_effect=rebind_after_read):
            with self.assertRaises(self.authority.AuthorityError):
                reader(self.root, "leaf1", path)
        self.assertEqual([True], changed)
        self.assertTrue((moved / "result.json").is_file())
        self.assertEqual([], list(path.parent.iterdir()))

    def test_current_receipt_reader_rechecks_the_image_after_decode_boundary(self):
        path, _receipt = self.publish_read_fixture()
        reader = self.bound_reader()
        original_read = self.authority._read
        changed = []
        altered = b'{"state":"failed","reason":"new image after read"}\n'
        def alter_after_read(descriptor, name, *args, **kwargs):
            raw = original_read(descriptor, name, *args, **kwargs)
            if name == "result.json" and not changed:
                path.write_bytes(altered)
                changed.append(True)
            return raw
        with mock.patch.object(self.authority, "_read", side_effect=alter_after_read):
            with self.assertRaises(self.authority.AuthorityError):
                reader(self.root, "leaf1", path)
        self.assertEqual([True], changed)
        self.assertEqual(altered, path.read_bytes())

    def test_current_receipt_reader_rejects_outside_and_noncanonical_paths_without_creating_state(self):
        path, receipt = self.publish_read_fixture()
        reader = self.bound_reader()
        journal = self.authority.read_current(self.root, "leaf1")
        for candidate in (self.root.parent / "outside/result.json", self.root / "../run-1/leaf1/result.json",
                          self.root / "run-1/foreign/result.json", self.root / "run-1/leaf1/summary.json"):
            with self.subTest(path=candidate):
                with self.assertRaises(self.authority.AuthorityError):
                    reader(self.root, "leaf1", candidate)
        self.assertEqual(journal, self.authority.read_current(self.root, "leaf1"))
        self.assertEqual(receipt, json.loads(path.read_bytes()))

    def test_current_receipt_reader_accepts_independent_full_wire_budget_and_rejects_degenerate_bound(self):
        path, receipt = self.publish_read_fixture()
        raw = path.read_bytes()
        maximum = b" " * (16384 - len(raw)) + raw
        self.assertEqual(16384, len(maximum))
        path.write_bytes(maximum)
        reader = self.bound_reader()
        self.assertEqual(receipt, reader(self.root, "leaf1", path))
        with mock.patch.object(self.authority, "RECEIPT_MAX_BYTES", 16383):
            with self.assertRaises(self.authority.AuthorityError):
                reader(self.root, "leaf1", path)
        path.write_bytes(b" " + maximum)
        with self.assertRaises(self.authority.AuthorityError):
            reader(self.root, "leaf1", path)
        self.assertEqual(b" " + maximum, path.read_bytes())

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
