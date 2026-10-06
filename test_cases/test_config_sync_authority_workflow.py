"""F02 real manual writer -> local generation journal, with isolated device I/O.

These tests never connect to a device. Only the remote boundary and release
preflight are fixtures; trigger_one, receipt publication and generation/veto
transitions execute their production implementations.
"""

from contextlib import ExitStack
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
        release.mkdir()
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
