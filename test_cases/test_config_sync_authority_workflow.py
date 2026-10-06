"""F02 real manual writer -> local generation journal, with isolated device I/O.

These tests never connect to a device. Only the remote boundary and release
preflight are fixtures; trigger_one, receipt publication and generation/veto
transitions execute their production implementations.
"""

from contextlib import ExitStack
from datetime import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class ConfigSyncAuthorityWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "f02_authority_manual_writer", ROOT / "ztp/manual-ztp.py",
        )
        cls.manual = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.manual)
        worker_spec = importlib.util.spec_from_file_location(
            "f02_authority_worker_reader", ROOT / "monitor/manual-ztp-worker.py",
        )
        cls.worker = importlib.util.module_from_spec(worker_spec)
        worker_spec.loader.exec_module(cls.worker)

    def fixture(self, project):
        release = project / "release"
        release.mkdir(exist_ok=True)
        marker = release / ".published-complete"
        marker.write_text("ok\n", encoding="utf-8")
        expected = release / "EXAMPLE-Leaf01.yaml"
        text = "- set:\n    system:\n      hostname: EXAMPLE-Leaf01\n"
        expected.write_text(text, encoding="utf-8")
        prepared = {
            "published_marker": str(marker), "expected_yaml": str(expected),
            "published_release_dir": str(release.resolve()),
            "expected_yaml_sha256": self.manual.normalized_nvue_config(text, label="fixture")[2],
            "current_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "applied_fingerprint": "a" * 64, "published_mac_links": [],
        }
        client = mock.Mock()
        client.args.command_timeout = 20
        client.args.ssh_password = False
        client.run.side_effect = [
            SimpleNamespace(returncode=0, stdout=text, stderr=""),
            SimpleNamespace(returncode=0, stdout="saved\n", stderr=""),
            SimpleNamespace(returncode=0, stdout=text, stderr=""),
        ]
        return client, prepared, text

    def run_writer(self, project, client, prepared, *, run, ticket):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                self.manual, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
            ))
            stack.enter_context(mock.patch.object(self.manual, "verify_prepared_release_binding"))
            stack.enter_context(mock.patch.object(
                self.manual, "collect_applied_config", return_value={"fingerprint": "a" * 64},
            ))
            stack.enter_context(mock.patch.object(
                self.manual, "evaluate_replace_config_guard", return_value={"allowed": True},
            ))
            return self.manual.trigger_one(
                client, {"hostname": "EXAMPLE-Leaf01", "type": "eth"}, "",
                project / "99-output-ztp/manual-config-sync" / run,
                trigger_source="manual_config_sync_cli", trigger_id=ticket["trigger_id"],
                operation="replace-config", operation_id=ticket["operation_id"],
                prepared=prepared, requested_operation="replace-config", authority_ticket=ticket,
            )

    def test_real_writer_receipt_binds_own_current_generation_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            self.assertEqual((1, "pending", True), (ticket["generation"], ticket["state"], ticket["veto"]))
            result = self.run_writer(project, client, prepared, run="first", ticket=ticket)
            self.assertEqual("triggered", result["state"])
            self.assertIs(result["batch_identity_verified"], True)
            self.assertEqual(hashlib.sha256(text.encode("utf-8")).hexdigest(), result["live_state_sha256"])
            self.assertEqual((1, ticket["source_identity"]), (result["generation"], result["source_identity"]))
            receipt = root / "first/EXAMPLE-Leaf01/result.json"
            self.assertEqual(result, json.loads(receipt.read_text(encoding="utf-8")))
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            # Independently serialize the writer's own receipt; do not ask
            # the production digest helper to generate the expected hash.
            expected_wire = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
            self.assertEqual(hashlib.sha256(expected_wire).hexdigest(), current["receipt_sha256"])
            self.assertEqual((1, "success", False), (current["generation"], current["state"], current["veto"]))
            self.assertEqual(3, client.run.call_count)

    def test_failed_next_writer_withdraws_old_success_and_old_finish_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            first = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            previous = self.run_writer(project, client, prepared, run="first", ticket=first)
            self.assertEqual("success", authority.read_current(root, "EXAMPLE-Leaf01")["state"])
            second = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
            self.assertEqual((2, "pending", True), (second["generation"], second["state"], second["veto"]))
            client.run.side_effect = self.manual.ManualZtpError("fixture transport failed")
            failed = self.run_writer(project, client, prepared, run="second", ticket=second)
            self.assertEqual("failed", failed["state"])
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            self.assertEqual((2, "failed", True), (current["generation"], current["state"], current["veto"]))
            with self.assertRaises(authority.AuthorityError):
                authority.finish(root, first, previous)
            self.assertEqual(current, authority.read_current(root, "EXAMPLE-Leaf01"))

    def test_real_writer_identity_proof_must_be_inside_its_finished_session(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            before = receipt.read_bytes()
            self.assertTrue(self.worker.config_sync_promotion_ready(produced))
            independent = {
                **produced, "command_started_at": "2026-10-03T10:00:00+08:00",
                "batch_identity_verified_at": "2026-10-03T10:00:01+08:00",
                "finished_at": "2026-10-03T10:00:02+08:00",
            }
            for updates in (
                {"finished_at": ""}, {"finished_at": None},
                {"finished_at": "2026-10-03T10:00:02"},
                {"finished_at": "2026-10-03T09:59:59+08:00"},
                {"batch_identity_verified_at": "2026-10-03T10:00:03+08:00"},
            ):
                with self.subTest(updates=updates):
                    self.assertFalse(self.worker.config_sync_promotion_ready({
                        **independent, **updates,
                    }))
            self.assertEqual(before, receipt.read_bytes())
            project = Path(directory).resolve()
            devices = project / "02-devices_config.csv"
            devices.write_text("hostname,type\nEXAMPLE-Leaf01,eth\n", encoding="utf-8")
            self.manual.atomic_json(receipt.parent.parent / "summary.json", {
                "state": "triggered", "operation": "replace-config",
                "effective_operation": "replace-config", "operation_id": "op-1",
                "trigger_source": "manual_config_sync_cli", "generation": 1,
                "targets": [{"hostname": "EXAMPLE-Leaf01", "trigger_id": "trigger-1",
                             "effective_operation": "replace-config", "generation": 1}],
                "results": [produced],
            })
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                imported = self.worker.latest_cli_operations()["example-leaf01"]
            self.assertEqual(produced["finished_at"], imported["finished_at"])
            self.assertTrue(self.worker.config_sync_promotion_ready(imported))

    def test_interactive_writer_cannot_publish_successful_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            client.args.ssh_password = True
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            result = self.run_writer(project, client, prepared, run="interactive", ticket=ticket)
            self.assertEqual("failed", result["state"])
            self.assertNotIn("live_state_sha256", result)
            current = authority.read_current(root, "EXAMPLE-Leaf01")
            self.assertEqual((1, "failed", True), (current["generation"], current["state"], current["veto"]))

    def test_writer_late_authority_rebinding_cannot_return_a_promotable_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            authority = self.manual.config_sync_authority
            root = project / "99-output-ztp/manual-config-sync"
            ticket = authority.begin(root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli")
            private = root / ".authority"
            marker = private / "example-leaf01.pending"
            witness = private / "example-leaf01.witness.json"
            foreign = project / "foreign.json"
            foreign.write_bytes(b"foreign-writer-witness\n")
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
                    witness.unlink()
                    witness.symlink_to(foreign)

            with mock.patch.object(authority.os, "fsync", side_effect=rebind_after_guard_unlink):
                with self.assertRaises(authority.AuthorityError):
                    self.run_writer(project, client, prepared, run="late-rebind", ticket=ticket)
            self.assertTrue(changed)
            self.assertEqual(b"foreign-writer-witness\n", foreign.read_bytes())
            self.assertTrue(witness.is_symlink())
            self.assertTrue(marker.exists())
            with self.assertRaises(authority.AuthorityError):
                authority.read_current(root, "EXAMPLE-Leaf01")

    def test_real_main_preview_does_not_advance_and_failed_preflight_revokes_previous_era(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            client, prepared, _text = self.fixture(project)
            device = {"hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10", "mac_plain": "001122334455"}
            root = project / "99-output-ztp/manual-config-sync"
            authority = self.manual.config_sync_authority
            first = authority.begin(root, device["hostname"], "op-1", "trigger-1", "manual_config_sync_cli")
            previous = self.run_writer(project, client, prepared, run="first", ticket=first)
            current = authority.read_current(root, device["hostname"])
            self.assertEqual("success", current["state"])
            with ExitStack() as stack:
                for name, value in (
                    ("resolve_project", project), ("read_devices", [device]),
                    ("acquire_deployment_lock", None), ("release_deployment_lock", None),
                    ("apply_sudo_policy", None), ("dedicated_yaml_ready", (True, "")),
                    ("SshClient", client), ("display_preflight_diff", None),
                ):
                    stack.enter_context(mock.patch.object(self.manual, name, return_value=value))
                stack.enter_context(mock.patch("sys.stdout", new=io.StringIO()))
                stack.enter_context(mock.patch("sys.stderr", new=io.StringIO()))
                args = [device["hostname"], "--project", "prod", "--replace-config", "--non-interactive", "--yes"]
                with mock.patch.object(self.manual, "preflight_one", return_value=dict(prepared)):
                    self.assertEqual(0, self.manual.main(args + ["--preflight-only", "--operation-id", "preview", "--trigger-id", "preview-trigger"]))
                self.assertEqual(current, authority.read_current(root, device["hostname"]), "read-only preview cannot revoke or mint an era")

                def failed_preflight(*_args, **_kwargs):
                    pending = authority.read_current(root, device["hostname"])
                    self.assertEqual((2, "pending", True), (pending["generation"], pending["state"], pending["veto"]))
                    raise self.manual.ManualZtpError("fixture preflight failed before device writes")

                with mock.patch.object(self.manual, "preflight_one", side_effect=failed_preflight):
                    self.assertEqual(2, self.manual.main(args + ["--operation-id", "op-2", "--trigger-id", "trigger-2"]))
            pending = authority.read_current(root, device["hostname"])
            self.assertEqual((2, "pending", True), (pending["generation"], pending["state"], pending["veto"]))
            with self.assertRaises(authority.AuthorityError):
                authority.finish(root, first, previous)
            summaries = [json.loads(path.read_text(encoding="utf-8")) for path in root.glob("*/summary.json")]
            self.assertEqual({"preview_ready", "failed"}, {item["state"] for item in summaries})
            failed = next(item for item in summaries if item["state"] == "failed")
            self.assertEqual((2, 2), (failed["generation"], failed["targets"][0]["generation"]))
            self.assertEqual([], failed["results"])

    def published_receipt(self, project):
        client, prepared, _text = self.fixture(project)
        root = project / "99-output-ztp/manual-config-sync"
        ticket = self.manual.config_sync_authority.begin(
            root, "EXAMPLE-Leaf01", "op-1", "trigger-1", "manual_config_sync_cli",
        )
        produced = self.run_writer(project, client, prepared, run="first", ticket=ticket)
        return root / "first/EXAMPLE-Leaf01/result.json", produced

    def worker_bundle(self, project):
        receipt, produced = self.published_receipt(project)
        devices = project / "02-devices_config.csv"
        devices.write_text("hostname,type\nEXAMPLE-Leaf01,eth\n", encoding="utf-8")
        summary = {
            "state": "triggered", "operation": "replace-config",
            "effective_operation": "replace-config", "operation_id": "op-1",
            "trigger_source": "manual_config_sync_cli", "generation": 1,
            "targets": [{"hostname": "EXAMPLE-Leaf01", "trigger_id": "trigger-1",
                         "effective_operation": "replace-config", "generation": 1}],
            "results": [produced],
        }
        self.manual.atomic_json(receipt.parent.parent / "summary.json", summary)
        return devices, receipt, produced, summary

    def accept_own_writer(self):
        return self.worker.accepted_result(
            "trigger-1", hostname="EXAMPLE-Leaf01", operation_id="op-1",
            operation="replace-config", trigger_source="manual_config_sync_cli",
        )

    def test_worker_cannot_reuse_success_after_local_revocation_or_new_pending_era(self):
        for transition in ("revoke", "next-era", "missing-authority"):
            with self.subTest(transition=transition), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                devices, receipt, produced, _summary = self.worker_bundle(project)
                root = receipt.parents[2]
                before = receipt.read_bytes()
                authority = self.manual.config_sync_authority
                with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                    self.assertEqual(produced, self.accept_own_writer())
                    if transition == "revoke":
                        authority.revoke(root, "EXAMPLE-Leaf01")
                    elif transition == "next-era":
                        pending = authority.begin(root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli")
                        self.assertEqual((2, "pending", True), (pending["generation"], pending["state"], pending["veto"]))
                    else:
                        (root / ".authority").rename(root / "isolated-old-authority")
                    self.assertEqual({}, self.accept_own_writer())
                self.assertEqual(before, receipt.read_bytes())
                if transition == "missing-authority":
                    self.assertFalse((root / ".authority").exists(), "reader cannot mint replacement history")

    def test_worker_checks_own_generation_namespace_digest_and_summary_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, summary = self.worker_bundle(project)
            summary_path = receipt.parent.parent / "summary.json"
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                self.assertEqual(produced, self.accept_own_writer())
                for field, value in (("generation", None), ("generation", True),
                                     ("generation", 1.0), ("generation", 2),
                                     ("source_identity", "0:0"),
                                     ("live_state_sha256", "b" * 64)):
                    with self.subTest(receipt_field=field, value=value):
                        mutant = {**produced, field: value}
                        self.manual.atomic_json(receipt, mutant)
                        self.manual.atomic_json(summary_path, {**summary, "results": [mutant]})
                        before = receipt.read_bytes()
                        self.assertEqual({}, self.accept_own_writer())
                        self.assertEqual(before, receipt.read_bytes())
                self.manual.atomic_json(receipt, produced)
                for value in (None, True, 1.0, 2):
                    with self.subTest(summary_generation=value):
                        self.manual.atomic_json(summary_path, {**summary, "generation": value})
                        self.assertEqual({}, self.accept_own_writer())
                    with self.subTest(target_generation=value):
                        self.manual.atomic_json(summary_path, {**summary, "targets": [
                            {**summary["targets"][0], "generation": value},
                        ]})
                        self.assertEqual({}, self.accept_own_writer())
                self.manual.atomic_json(summary_path, summary)
                self.assertEqual(produced, self.accept_own_writer())

    def test_worker_rechecks_local_era_after_receipt_and_summary_read(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            original_read = self.worker._read_new_config_sync_receipt
            changed = False
            def next_era_after_summary(path, **kwargs):
                nonlocal changed
                value = original_read(path, **kwargs)
                if path.name == "summary.json" and not changed:
                    changed = True
                    self.manual.config_sync_authority.begin(
                        receipt.parents[2], "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
                    )
                return value
            with mock.patch.object(self.worker, "DEVICES_CSV", devices), \
                    mock.patch.object(self.worker, "_read_new_config_sync_receipt", side_effect=next_era_after_summary):
                self.assertEqual({}, self.accept_own_writer())
            self.assertTrue(changed)
            self.assertEqual(produced, json.loads(receipt.read_text()))

    def test_cli_import_uses_local_generation_not_reporter_wall_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, previous, summary = self.worker_bundle(project)
            root = receipt.parents[2]
            # Old reporter wall time is deliberately much newer than the next
            # causal era. Only the local single writer chooses the generation.
            self.manual.atomic_json(receipt.parent.parent / "summary.json", {
                **summary, "requested_at": "9999-01-01T00:00:00Z",
                "generated_at": "9999-01-01T00:00:00Z",
            })
            client, prepared, _text = self.fixture(project)
            ticket = self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.assertEqual(2, ticket["generation"])
            with mock.patch.object(self.manual, "datetime") as clock:
                clock.now.return_value = datetime.fromisoformat("2020-01-01T00:00:00+00:00")
                current = self.run_writer(project, client, prepared, run="second", ticket=ticket)
            self.manual.atomic_json(root / "second/summary.json", {
                **summary, "generation": 2, "operation_id": "op-2",
                "requested_at": "2020-01-01T00:00:00Z", "generated_at": "2020-01-01T00:00:00Z",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [current],
            })
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                imported = self.worker.latest_cli_operations()["example-leaf01"]
                self.assertEqual(("op-2", "trigger-2", 2, current["source_identity"]), (
                    imported["operation_id"], imported["trigger_id"], imported.get("generation"),
                    imported.get("source_identity"),
                ))
                self.assertTrue(self.worker.config_sync_promotion_ready(imported))
                self.manual.config_sync_authority.revoke(root, "EXAMPLE-Leaf01")
                revoked = self.worker.latest_cli_operations().get("example-leaf01", {})
                self.assertFalse(self.worker.config_sync_promotion_ready(revoked))
            self.assertEqual(previous, json.loads(receipt.read_text()))

    def test_cli_import_cannot_launder_missing_tampered_or_ambiguous_receipt(self):
        for defect in ("missing", "digest", "duplicate-summary", "unsafe-summary", "missing-authority"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                devices, receipt, produced, summary = self.worker_bundle(project)
                root = receipt.parents[2]
                before = receipt.read_bytes()
                with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                    self.assertTrue(self.worker.config_sync_promotion_ready(
                        self.worker.latest_cli_operations()["example-leaf01"],
                    ))
                    if defect == "missing":
                        receipt.rename(receipt.with_name("retained-receipt.json"))
                    elif defect == "digest":
                        mutant = {**produced, "live_state_sha256": "b" * 64}
                        self.manual.atomic_json(receipt, mutant)
                        self.manual.atomic_json(receipt.parent.parent / "summary.json", {**summary, "results": [mutant]})
                    elif defect == "duplicate-summary":
                        self.manual.atomic_json(root / "duplicate/summary.json", summary)
                    elif defect == "unsafe-summary":
                        (receipt.parent.parent / "summary.json").chmod(0o666)
                    else:
                        (root / ".authority").rename(root / "retained-authority")
                    value = self.worker.latest_cli_operations().get("example-leaf01", {})
                    self.assertFalse(self.worker.config_sync_promotion_ready(value))
                if defect == "missing":
                    self.assertEqual(before, receipt.with_name("retained-receipt.json").read_bytes())
                elif defect != "digest":
                    self.assertEqual(before, receipt.read_bytes())

    def test_cli_import_selects_current_pending_era_without_reusing_success(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, summary = self.worker_bundle(project)
            root = receipt.parents[2]
            self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.manual.atomic_json(root / "pending/summary.json", {
                **summary, "generation": 2, "operation_id": "op-2", "state": "preflight",
                "requested_at": "2020-01-01T00:00:00Z", "generated_at": "2020-01-01T00:00:00Z",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [],
            })
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                value = self.worker.latest_cli_operations()["example-leaf01"]
            self.assertEqual(("op-2", "trigger-2", 2, "running"), (
                value["operation_id"], value["trigger_id"], value.get("generation"), value["state"],
            ))
            self.assertFalse(self.worker.config_sync_promotion_ready(value))

    def test_promotion_requires_a_strict_bounded_generation_and_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            self.assertTrue(self.worker.config_sync_promotion_ready(produced))
            for field, value in (("generation", None), ("generation", True),
                                 ("generation", 1.0), ("generation", 0),
                                 ("generation", -1), ("generation", 2 ** 63),
                                 ("source_identity", None), ("source_identity", ""),
                                 ("source_identity", "-1:2"), ("source_identity", "1:2:3"),
                                 ("source_identity", f"{2 ** 64}:2")):
                with self.subTest(field=field, value=value):
                    self.assertFalse(self.worker.config_sync_promotion_ready({**produced, field: value}))
            self.assertEqual(produced, json.loads(receipt.read_text()))

    def test_cli_import_rechecks_local_era_after_last_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, _summary = self.worker_bundle(project)
            original = self.worker.accepted_result
            def advance_after_acceptance(*args, **kwargs):
                value = original(*args, **kwargs)
                self.assertTrue(value)
                self.manual.config_sync_authority.begin(
                    receipt.parents[2], "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
                )
                return value
            with mock.patch.object(self.worker, "DEVICES_CSV", devices), \
                    mock.patch.object(self.worker, "accepted_result", side_effect=advance_after_acceptance):
                self.assertEqual({}, self.worker.latest_cli_operations())

    def test_cli_pending_import_does_not_cross_into_legacy_ztp_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, summary = self.worker_bundle(project)
            root = receipt.parents[2]
            self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            pending = {
                **summary, "generation": 2, "operation_id": "op-2", "state": "preflight",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [],
            }
            path = root / "pending/summary.json"
            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                for defect in ("operation", "effective_operation", "target-effective"):
                    with self.subTest(defect=defect):
                        mutant = {**pending, defect: "ztp"} if defect != "target-effective" else {
                            **pending, "targets": [{**pending["targets"][0], "effective_operation": "ztp"}],
                        }
                        self.manual.atomic_json(path, mutant)
                        self.assertEqual({}, self.worker.latest_cli_operations())

    def run_worker_once(self, project, devices):
        """Execute the real poll/status path, entirely inside our private fixture."""
        status_dir = project / "worker-status"
        status_dir.mkdir(exist_ok=True)
        queue = status_dir / "request.json"
        if not queue.exists():
            queue.write_text("{}\n", encoding="utf-8")
        with ExitStack() as stack:
            for name, path in (
                ("DEVICES_CSV", devices), ("STATUS_DIR", status_dir),
                ("STATUS_FILE", status_dir / "status.json"),
                ("REQUEST_FILE", queue), ("PID_FILE", status_dir / "own.pid"),
                ("ZTP_STATUS_DIR", project / "isolated-ztp-status"),
            ):
                stack.enter_context(mock.patch.object(self.worker, name, path))
            stack.enter_context(mock.patch("sys.argv", ["fixture-worker", "--scope", "prod"]))
            stack.enter_context(mock.patch.object(self.worker.time, "sleep", side_effect=KeyboardInterrupt))
            self.assertEqual(130, self.worker.main())
        return json.loads((status_dir / "status.json").read_text())["devices"]

    def test_real_worker_persists_own_proof_and_receipt_loss_withdrawal_is_sticky(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            states = self.run_worker_once(project, devices)
            current = states["EXAMPLE-Leaf01"]
            self.assertEqual("config_sync_success", current["state"])
            for field in ("generation", "source_identity", "command_started_at", "finished_at",
                          "batch_identity_verified", "batch_identity_verified_at", "live_state_sha256",
                          "transport_ip", "interface"):
                with self.subTest(proof_field=field):
                    self.assertEqual(produced[field], current.get(field))
            original = receipt.read_bytes()
            retained = receipt.with_name("retained-result.json")
            receipt.rename(retained)
            revoked = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual("failed", revoked["state"])
            self.assertIs(revoked.get("authority_revoked"), True)
            retained.rename(receipt)
            restored = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual("failed", restored["state"], "restoring the same old receipt cannot undo withdrawal")
            self.assertIs(restored.get("authority_revoked"), True)
            self.assertEqual(original, receipt.read_bytes())

    def test_real_worker_adopts_new_causal_generation_despite_old_status_future_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, summary = self.worker_bundle(project)
            status_dir = project / "worker-status"
            status_dir.mkdir()
            self.manual.atomic_json(status_dir / "status.json", {
                "scope": "prod", "devices": {"EXAMPLE-Leaf01": {
                    **produced, "state": "config_sync_success",
                    "started_at": "9999-01-01T00:00:00Z",
                }},
            })
            root = receipt.parents[2]
            client, prepared, _text = self.fixture(project)
            ticket = self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.assertEqual(2, ticket["generation"])
            with mock.patch.object(self.manual, "datetime") as clock:
                clock.now.return_value = datetime.fromisoformat("2020-01-01T00:00:00+00:00")
                new = self.run_writer(project, client, prepared, run="next", ticket=ticket)
            self.manual.atomic_json(root / "next/summary.json", {
                **summary, "generation": 2, "operation_id": "op-2",
                "targets": [{**summary["targets"][0], "generation": 2, "trigger_id": "trigger-2"}],
                "results": [new],
            })
            current = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual(("config_sync_success", "op-2", 2), (
                current["state"], current["operation_id"], current.get("generation"),
            ))
            self.assertIs(current["batch_identity_verified"], True)
            self.assertEqual(new["live_state_sha256"], current["live_state_sha256"])
            # Reusing labels is not authority: a truly newer local integer
            # era may supersede the old veto, but generation 2 cannot do so.
            client, prepared, _text = self.fixture(project)
            ticket = self.manual.config_sync_authority.begin(
                root, "EXAMPLE-Leaf01", "op-2", "trigger-2", "manual_config_sync_cli",
            )
            self.assertEqual(3, ticket["generation"])
            third = self.run_writer(project, client, prepared, run="third", ticket=ticket)
            self.manual.atomic_json(root / "third/summary.json", {
                **summary, "generation": 3, "operation_id": "op-2",
                "targets": [{**summary["targets"][0], "generation": 3, "trigger_id": "trigger-2"}],
                "results": [third],
            })
            current = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
            self.assertEqual(("config_sync_success", "op-2", 3), (
                current["state"], current["operation_id"], current["generation"],
            ))
            self.assertEqual(third["finished_at"], current["finished_at"])

    def test_real_worker_rejects_corrupt_saved_proof_without_repromoting_same_era(self):
        for field, invalid in (("batch_identity_verified", 1), ("generation", True),
                               ("source_identity", "0:0"), ("authority_revoked", 0),
                               ("live_state_sha256", "b" * 64)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                devices, _receipt, _produced, _summary = self.worker_bundle(project)
                self.run_worker_once(project, devices)
                path = project / "worker-status/status.json"
                previous = json.loads(path.read_text())
                previous["devices"]["EXAMPLE-Leaf01"][field] = invalid
                self.manual.atomic_json(path, previous)
                value = self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]
                self.assertEqual("failed", value["state"])
                self.assertIs(value.get("authority_revoked"), True)

    def test_receipt_loss_revokes_journal_even_if_old_worker_status_is_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, _summary = self.worker_bundle(project)
            self.run_worker_once(project, devices)
            status_path = project / "worker-status/status.json"
            previous = status_path.read_bytes()
            retained = receipt.with_name("retained-result.json")
            receipt.rename(retained)
            self.assertEqual("failed", self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]["state"])
            current = self.manual.config_sync_authority.read_current(receipt.parents[2], "EXAMPLE-Leaf01")
            self.assertEqual((1, "failed", True), tuple(current[field] for field in ("generation", "state", "veto")))
            retained.rename(receipt)
            status_path.write_bytes(previous)
            self.assertEqual("failed", self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]["state"])

    def test_receipt_loss_observer_cannot_revoke_a_concurrently_started_new_era(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, _produced, _summary = self.worker_bundle(project)
            self.run_worker_once(project, devices)
            receipt.rename(receipt.with_name("retained-result.json"))
            authority = self.manual.config_sync_authority
            original = authority.revoke
            advanced = False
            def begin_before_revocation(root, hostname, **kwargs):
                nonlocal advanced
                self.assertEqual(1, kwargs["expected"]["generation"])
                advanced = True
                authority.begin(root, hostname, "op-2", "trigger-2", "manual_config_sync_cli")
                return original(root, hostname, **kwargs)
            with mock.patch.object(authority, "revoke", side_effect=begin_before_revocation):
                self.assertEqual("failed", self.run_worker_once(project, devices)["EXAMPLE-Leaf01"]["state"])
            self.assertTrue(advanced, "observer must attempt a guarded local revocation")
            current = authority.read_current(receipt.parents[2], "EXAMPLE-Leaf01")
            self.assertEqual((2, "pending", True, "op-2"), tuple(
                current[field] for field in ("generation", "state", "veto", "operation_id")
            ))

    def test_real_worker_cannot_leave_success_after_state_directory_sync_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            devices, receipt, produced, _summary = self.worker_bundle(project)
            status_dir = project / "worker-status"
            status_dir.mkdir()
            status_path = status_dir / "status.json"
            real_sync = os.fsync
            injected = False
            def fail_success_directory_sync(descriptor):
                nonlocal injected
                held = os.fstat(descriptor)
                if (stat.S_ISDIR(held.st_mode) and held.st_ino == status_dir.stat().st_ino
                        and status_path.exists() and not injected):
                    value = json.loads(status_path.read_text())
                    if value.get("devices", {}).get("EXAMPLE-Leaf01", {}).get("state") == "config_sync_success":
                        injected = True
                        raise OSError("injected worker success directory durability failure")
                real_sync(descriptor)
            with mock.patch.object(self.worker.os, "fsync", side_effect=fail_success_directory_sync):
                with self.assertRaisesRegex(OSError, "success directory durability failure"):
                    self.run_worker_once(project, devices)
            self.assertTrue(injected)
            saved = json.loads(status_path.read_text())
            self.assertNotEqual("config_sync_success", saved["devices"].get("EXAMPLE-Leaf01", {}).get("state"))
            self.assertEqual(produced, json.loads(receipt.read_text()))
            self.assertFalse(list(status_dir.glob(".status.json.*")))

    def test_real_worker_rejects_writer_receipt_with_unsafe_mode_or_foreign_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            self.assertEqual(produced, self.worker._read_new_config_sync_receipt(receipt))
            receipt.chmod(0o666)
            with self.subTest(metadata="unsafe-mode"):
                self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            receipt.chmod(0o600)
            real_fstat = os.fstat

            def foreign_owner(descriptor):
                observed = real_fstat(descriptor)
                fields = {name: getattr(observed, name) for name in (
                    "st_dev", "st_ino", "st_size", "st_nlink", "st_mode", "st_uid", "st_gid",
                    "st_mtime_ns", "st_ctime_ns",
                )}
                fields["st_uid"] = os.geteuid() + 1
                return SimpleNamespace(**fields)

            with mock.patch.object(self.worker.os, "fstat", side_effect=foreign_owner):
                with self.subTest(metadata="foreign-owner"):
                    self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            self.assertEqual(produced, self.worker._read_new_config_sync_receipt(receipt))

    def test_real_worker_rejects_duplicate_members_in_writer_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, produced = self.published_receipt(Path(directory).resolve())
            raw = receipt.read_bytes()
            duplicate = raw.rstrip()[:-1] + b',"hostname":"EXAMPLE-Leaf01"}\n'
            receipt.write_bytes(duplicate)
            self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            self.assertEqual(duplicate, receipt.read_bytes(), "reject-and-retain malformed evidence")
            self.assertEqual("EXAMPLE-Leaf01", produced["hostname"])

    def test_real_worker_rechecks_visible_writer_receipt_after_held_read(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, _produced = self.published_receipt(Path(directory).resolve())
            foreign = receipt.parent / "foreign.json"
            foreign.write_bytes(b'{"foreign":true}\n')
            foreign.chmod(0o600)
            real_read = os.read
            changed = False

            def rebind_visible_path(descriptor, count):
                nonlocal changed
                raw = real_read(descriptor, count)
                if raw and not changed:
                    changed = True
                    receipt.unlink()
                    receipt.symlink_to(foreign)
                return raw

            with mock.patch.object(self.worker.os, "read", side_effect=rebind_visible_path):
                self.assertEqual({}, self.worker._read_new_config_sync_receipt(receipt))
            self.assertTrue(changed)
            self.assertTrue(receipt.is_symlink())
            self.assertEqual(b'{"foreign":true}\n', foreign.read_bytes())

    def test_worker_validates_entire_summary_before_accepting_own_writer_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory).resolve()
            receipt, produced = self.published_receipt(project)
            devices = project / "02-devices_config.csv"
            devices.write_text("hostname,type\nEXAMPLE-Leaf01,eth\n", encoding="utf-8")
            target = {"hostname": "EXAMPLE-Leaf01", "trigger_id": "trigger-1", "effective_operation": "replace-config", "generation": 1}
            summary = {
                "state": "triggered", "operation": "replace-config", "effective_operation": "replace-config",
                "operation_id": "op-1", "trigger_source": "manual_config_sync_cli", "generation": 1,
                "targets": [target], "results": [produced],
            }
            summary_path = receipt.parent.parent / "summary.json"

            def accept():
                return self.worker.accepted_result(
                    "trigger-1", hostname="EXAMPLE-Leaf01", operation_id="op-1",
                    operation="replace-config", trigger_source="manual_config_sync_cli",
                )

            with mock.patch.object(self.worker, "DEVICES_CSV", devices):
                self.manual.atomic_json(summary_path, summary)
                self.assertEqual(produced, accept())
                other_target = {"hostname": "OTHER-Leaf02", "trigger_id": "other-trigger", "effective_operation": "replace-config", "generation": 1}
                other_result = {"hostname": "OTHER-Leaf02", "trigger_id": "other-trigger", "state": "triggered"}
                mutations = (
                    {"targets": [target, other_target, {**other_target, "hostname": "other-leaf02"}], "results": [produced, other_result]},
                    {"targets": [target, other_target], "results": [produced, other_result, {**other_result, "hostname": "other-leaf02"}]},
                    {"results": [produced, other_result]},
                    {"targets": [target, other_target]},
                    {"targets": [target, "malformed-host-member"]},
                    {"results": [produced, {"trigger_id": "no-hostname"}]},
                )
                for mutation in mutations:
                    with self.subTest(mutation=mutation):
                        self.manual.atomic_json(summary_path, {**summary, **mutation})
                        before = summary_path.read_bytes()
                        self.assertEqual({}, accept())
                        self.assertEqual(before, summary_path.read_bytes(), "whole-summary reject-and-retain")
                self.manual.atomic_json(summary_path, summary)
                self.assertEqual(produced, accept())


if __name__ == "__main__":
    unittest.main()
