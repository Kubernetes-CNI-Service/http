#!/usr/bin/env python3
"""Direct contract tests for Feedback's project-global writeback transaction."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
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

import yaml


ROOT = Path(__file__).resolve().parents[1]
FEEDBACK_PATH = ROOT / "ztp/optimize/feedback.py"


def load_feedback():
    spec = importlib.util.spec_from_file_location(
        "feedback_global_writeback_direct", FEEDBACK_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {FEEDBACK_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FEEDBACK = load_feedback()


class FeedbackGlobalWritebackTests(unittest.TestCase):
    def _authority(self, root: Path, content: bytes) -> Path:
        authority = root / "01-global.yaml"
        authority.write_bytes(content)
        return authority

    def _transaction(self, authority: Path, root: Path, **kwargs):
        return FEEDBACK.GlobalWritebackTransaction(
            authority, workspace_root=root, **kwargs,
        )

    @staticmethod
    def _state_path(authority: Path) -> Path:
        return (
            authority.parent / "99-output-ztp/optimize"
            / FEEDBACK.GLOBAL_WRITEBACK_STATE_NAME
        )

    @staticmethod
    def _timezone_candidate(value="UTC"):
        return {"common": {"switch": {"system": {"date-time": {
            "timezone": value,
        }}}}}

    @staticmethod
    def _timezone_path():
        return ("common", "switch", "system", "date-time", "timezone")

    def test_implicit_authority_is_same_directory_only_and_ambiguity_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "unrelated/captures/batch"
            nested.mkdir(parents=True)
            (root / "unrelated/01-global.yaml").write_text(
                "schema-version: 1\n", encoding="utf-8",
            )

            self.assertIsNone(FEEDBACK.find_global_config(nested))
            self.assertEqual(1, FEEDBACK.read_project_schema_version(None))

            local = nested / "01-global.yaml"
            local.write_text("schema-version: 2\n", encoding="utf-8")
            self.assertEqual(local.resolve(), FEEDBACK.find_global_config(nested))
            explicit = root / "chosen.yaml"
            explicit.write_text("schema-version: 2\n", encoding="utf-8")
            self.assertEqual(
                explicit.absolute(),
                FEEDBACK.find_global_config(nested, explicit_path=explicit),
            )
            (nested / "global.yaml").write_text("schema-version: 2\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "多个同目录全局 YAML"):
                FEEDBACK.find_global_config(nested)

    def test_missing_and_placeholder_forms_patch_bytes_but_nonempty_wins(self):
        original = (
            b"# operator header\n"
            b"common:\n"
            b"  switch:\n"
            b"    system:\n"
            b"      date-time:\n"
            b"        timezone: {}  # fill me\n"
            b"      dns:\n"
            b"        server:\n"
            b"          - {} # list placeholder\n"
            b"      ntp:\n"
            b"        server: [192.0.2.10] # operator\n"
            b"switches:\n"
            b"  - eth: {}\n"
            b"# operator footer\n"
        )
        expected = (
            b"# operator header\n"
            b"common:\n"
            b"  switch:\n"
            b"    system:\n"
            b"      date-time:\n"
            b"        timezone: UTC  # fill me\n"
            b"      dns:\n"
            b"        server:\n"
            b"          [192.0.2.53] # list placeholder\n"
            b"      ntp:\n"
            b"        server: [192.0.2.10] # operator\n"
            b"switches:\n"
            b"  - eth: {system: {ntp: {vrf: mgmt}}}\n"
            b"# operator footer\n"
        )
        evidence = {
            ("common", "switch", "system", "date-time", "timezone"),
            ("common", "switch", "system", "dns", "server"),
            ("common", "switch", "system", "ntp", "server"),
            ("switches", 0, "eth", "system", "ntp", "vrf"),
        }
        candidate = yaml.safe_load(expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            authority.chmod(0o640)
            with self._transaction(authority, root) as transaction:
                transaction.stage(
                    candidate, evidence, source_scope="prod", source_ref="prod-one",
                )

            self.assertEqual(expected, authority.read_bytes())
            self.assertEqual(0o640, authority.stat().st_mode & 0o777)
            self.assertEqual(1, transaction.commit_count)
            self.assertFalse(any(root.glob("*.bak")))

    def test_shared_first_success_keeps_air_when_prod_has_no_evidence(self):
        original = b"common:\n  switch:\n    system:\n      date-time:\n        timezone: {}\n"
        path = ("common", "switch", "system", "date-time", "timezone")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            output = io.StringIO()
            with redirect_stdout(output):
                with self._transaction(authority, root) as transaction:
                    transaction.stage(
                        {"common": {"switch": {"system": {"date-time": {"timezone": {}}}}}},
                        set(), source_scope="prod", source_ref="prod-none",
                    )
                    transaction.stage(
                        {"common": {"switch": {"system": {"date-time": {"timezone": "AIR-SECRET"}}}}},
                        {path}, source_scope="air", source_ref="air-source",
                    )
                    transaction.stage(
                        {"common": {"switch": {"system": {"date-time": {"timezone": "PROD-LATE"}}}}},
                        {path}, source_scope="prod", source_ref="prod-late",
                    )

            self.assertEqual(
                "AIR-SECRET",
                yaml.safe_load(authority.read_text(encoding="utf-8"))
                ["common"]["switch"]["system"]["date-time"]["timezone"],
            )
            log = output.getvalue()
            records = [
                json.loads(line) for line in log.splitlines()
                if line.startswith("{") and '"source_scope"' in line
            ]
            self.assertEqual(1, len(records))
            self.assertEqual(
                ["common", "switch", "system", "date-time", "timezone"],
                records[0]["path"],
            )
            self.assertEqual("air", records[0]["source_scope"])
            self.assertRegex(records[0]["source_ref_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("AIR-SECRET", log)
            self.assertNotIn("PROD-LATE", log)
            self.assertNotIn("air-source", log)

    def test_evidence_backed_absent_key_inserts_into_block_mapping_only(self):
        original = (
            b"common:\n"
            b"  switch:\n"
            b"    system:\n"
            b"      date-time:\n"
            b"        configured: keep # untouched\n"
            b"      dns:\n"
            b"        server: [192.0.2.53]\n"
        )
        expected = (
            b"common:\n"
            b"  switch:\n"
            b"    system:\n"
            b"      date-time:\n"
            b"        configured: keep # untouched\n"
            b"        timezone: UTC\n"
            b"      dns:\n"
            b"        server: [192.0.2.53]\n"
        )
        path = ("common", "switch", "system", "date-time", "timezone")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            candidate = yaml.safe_load(original)
            candidate["common"]["switch"]["system"]["date-time"]["timezone"] = "UTC"
            with self._transaction(authority, root) as transaction:
                transaction.stage(
                    candidate, {path}, source_scope="prod", source_ref="runtime",
                )
            self.assertEqual(expected, authority.read_bytes())

    def test_absent_key_without_real_evidence_is_never_created(self):
        original = b"common:\n  switch: {} # unchanged\n"
        path = ("common", "switch", "system", "date-time", "timezone")
        candidate = {"common": {"switch": {"system": {"date-time": {"timezone": "UTC"}}}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            with self._transaction(authority, root) as transaction:
                transaction.stage(
                    candidate, set(), source_scope="prod", source_ref="no-evidence",
                )
            self.assertEqual(original, authority.read_bytes())
            self.assertEqual(0, transaction.commit_count)

    def test_managed_symlink_is_never_replaced_and_exact_identity_survives(self):
        original = b"common:\n  switch:\n    system:\n      date-time:\n        timezone: {}\n"
        path = ("common", "switch", "system", "date-time", "timezone")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            sample = root / "project-sample"
            project.mkdir()
            sample.mkdir()
            authority = self._authority(project, original)
            link = sample / "01-global.yaml"
            link.symlink_to(os.path.relpath(authority, sample))
            before = os.lstat(link)

            with self._transaction(
                link, root, managed_project_root=project,
            ) as transaction:
                transaction.stage(
                    {"common": {"switch": {"system": {"date-time": {"timezone": "UTC"}}}}},
                    {path}, source_scope="prod", source_ref="generated",
                )

            after = os.lstat(link)
            self.assertTrue(link.is_symlink())
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual("UTC", yaml.safe_load(authority.read_text())["common"]["switch"]["system"]["date-time"]["timezone"])

    def test_authority_rejects_fifo_hardlink_oversize_invalid_utf8_duplicate_and_alias(self):
        cases = {
            "oversize": b"x" * (FEEDBACK.MAX_GLOBAL_CONFIG_BYTES + 1),
            "utf8": b"common: \xff\n",
            "duplicate": b"common: {}\ncommon: {}\n",
            "alias": b"common: &shared {}\nother: *shared\n",
            "non-string-key": b"1: value\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, content in cases.items():
                with self.subTest(label=label):
                    authority = root / f"{label}.yaml"
                    authority.write_bytes(content)
                    with self.assertRaises((OSError, ValueError)):
                        with self._transaction(authority, root):
                            pass

            fifo = root / "fifo.yaml"
            os.mkfifo(fifo)
            with self.assertRaises((OSError, ValueError)):
                with self._transaction(fifo, root):
                    pass

            authority = self._authority(root, b"common: {}\n")
            hardlink = root / "second-name.yaml"
            os.link(authority, hardlink)
            with self.assertRaisesRegex(ValueError, "硬链接"):
                with self._transaction(authority, root):
                    pass

    def test_unmanaged_symlink_and_unsafe_flow_insertion_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, b"common: {}\n")
            unmanaged = root / "chosen.yaml"
            unmanaged.symlink_to(authority.name)
            with self.assertRaisesRegex(ValueError, "sample_links"):
                with self._transaction(unmanaged, root):
                    pass

            flow = root / "flow.yaml"
            original = b"{common: {switch: {system: {date-time: {configured: keep}}}}}\n"
            flow.write_bytes(original)
            path = ("common", "switch", "system", "date-time", "timezone")
            transaction = self._transaction(flow, root)
            transaction.__enter__()
            transaction.stage(
                {"common": {"switch": {"system": {"date-time": {
                    "configured": "keep", "timezone": "UTC",
                }}}}},
                {path}, source_scope="prod", source_ref="runtime",
            )
            with self.assertRaisesRegex(FEEDBACK.FeedbackError, "semantic-patch"):
                transaction.commit()
            transaction.close()
            self.assertEqual(original, flow.read_bytes())

    def test_provenance_is_one_canonical_json_line_with_escaped_dynamic_path(self):
        username = "ops.dot\ncontrol\x01"
        role_path = (
            "switches", 0, "eth", "system", "aaa", "user", username, "role",
        )
        original_document = {
            "switches": [{"eth": {"system": {"aaa": {"user": {
                username: {"role": {}},
            }}}}}],
        }
        original = yaml.safe_dump(
            original_document, allow_unicode=True, sort_keys=False,
        ).encode("utf-8")
        candidate = yaml.safe_load(original)
        candidate["switches"][0]["eth"]["system"]["aaa"]["user"][username][
            "role"
        ] = "SECRET-ROLE-VALUE"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            output = io.StringIO()
            with redirect_stdout(output):
                with self._transaction(authority, root) as transaction:
                    transaction.stage(
                        candidate, {role_path}, source_scope="air",
                        source_ref="SECRET-SOURCE-REFERENCE",
                    )

            physical = [
                line for line in output.getvalue().splitlines()
                if line.startswith("{") and '"source_scope"' in line
            ]
            self.assertEqual(1, len(physical))
            encoded = (physical[0] + "\n").encode("utf-8")
            self.assertLessEqual(len(encoded), 4096)
            record = json.loads(physical[0])
            self.assertEqual(list(role_path), record["path"])
            self.assertEqual("air", record["source_scope"])
            self.assertEqual(
                physical[0],
                json.dumps(
                    record, ensure_ascii=True, sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            self.assertEqual(
                hashlib.sha256(original).hexdigest(),
                record["before_sha256"],
            )
            self.assertRegex(record["after_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                hashlib.sha256(
                    original.replace(
                        b"role: {}", b"role: SECRET-ROLE-VALUE",
                    )
                ).hexdigest(),
                record["after_sha256"],
            )
            self.assertEqual(
                original.replace(b"role: {}", b"role: SECRET-ROLE-VALUE"),
                authority.read_bytes(),
            )
            self.assertNotIn("SECRET-ROLE-VALUE", output.getvalue())
            self.assertNotIn("SECRET-SOURCE-REFERENCE", output.getvalue())

    def test_provenance_ascii_control_table_and_complete_record_boundary(self):
        controls = {
            "c0-soh": "\x01",
            "c0-bel": "\x07",
            "c0-esc": "\x1b",
            "del": "\x7f",
            "c1-csi": "\x9b",
            "nel": "\x85",
            "line-separator": "\u2028",
            "paragraph-separator": "\u2029",
            "bidi-rlo": "\u202e",
            "isolate-rli": "\u2067",
            "astral": "\U0001f642",
            "unpaired-surrogate": "\ud800",
        }
        original = b"switches:\n  - eth: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            try:
                for label, hostile in controls.items():
                    with self.subTest(label=label):
                        path = (
                            "switches", 0, "eth", "system", "aaa", "user",
                            f"ops.{hostile}.name", "role",
                        )
                        transaction._staged = {path: {
                            "value": "PRIVATE-NOT-FOR-PROVENANCE",
                            "scope": "air",
                            "source_ref_sha256": "a" * 64,
                        }}
                        line = transaction._provenance_lines("b" * 64)[0]
                        payload = (line + "\n").encode("ascii")
                        self.assertEqual(1, len((line + "\n").splitlines()))
                        self.assertNotIn(hostile, line)
                        record = json.loads(payload)
                        self.assertEqual(list(path), record["path"])
                        self.assertEqual(
                            hashlib.sha256(original).hexdigest(),
                            record["before_sha256"],
                        )
                        self.assertEqual("b" * 64, record["after_sha256"])
                        self.assertNotIn("PRIVATE-NOT-FOR-PROVENANCE", line)

                def expected_payload(username):
                    record = {
                        "after_sha256": "b" * 64,
                        "before_sha256": hashlib.sha256(original).hexdigest(),
                        "path": [
                            "switches", 0, "eth", "system", "aaa", "user",
                            username, "role",
                        ],
                        "source_ref_sha256": "a" * 64,
                        "source_scope": "prod",
                    }
                    return (json.dumps(
                        record, ensure_ascii=True, sort_keys=True,
                        separators=(",", ":"),
                    ) + "\n").encode("ascii")

                prefix = "boundary."
                fixed_size = len(expected_payload(prefix))
                exact_name = prefix + ("x" * (4096 - fixed_size))
                self.assertEqual(4096, len(expected_payload(exact_name)))
                exact_path = (
                    "switches", 0, "eth", "system", "aaa", "user",
                    exact_name, "role",
                )
                transaction._staged = {exact_path: {
                    "value": "PRIVATE",
                    "scope": "prod",
                    "source_ref_sha256": "a" * 64,
                }}
                exact_line = transaction._provenance_lines("b" * 64)[0]
                self.assertEqual(4096, len((exact_line + "\n").encode("ascii")))

                over_path = exact_path[:-2] + (exact_name + "x", "role")
                transaction._staged = {over_path: {
                    "value": "PRIVATE",
                    "scope": "prod",
                    "source_ref_sha256": "a" * 64,
                }}
                with self.assertRaisesRegex(
                    FEEDBACK.FeedbackError,
                    r"serialized_bytes=4097 limit=4096",
                ):
                    transaction._provenance_lines("b" * 64)
            finally:
                transaction.close()

    def test_serialized_provenance_bound_fails_before_candidate_or_state(self):
        username = "\x01" * 900
        path = (
            "switches", 0, "eth", "system", "aaa", "user", username, "role",
        )
        candidate = {
            "switches": [{"eth": {"system": {"aaa": {"user": {
                username: {"role": "PRIVATE"},
            }}}}}],
        }
        original = b"switches:\n  - eth: {}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(
                candidate, {path}, source_scope="prod", source_ref="runtime",
            )
            with self.assertRaisesRegex(Exception, "serialized_bytes=.*limit=4096") as raised:
                transaction.commit()
            transaction.close()

            self.assertNotIn(username, str(raised.exception))
            self.assertEqual(original, authority.read_bytes())
            self.assertEqual(0, transaction.commit_count)
            self.assertFalse(self._state_path(authority).exists())
            self.assertFalse(any(root.rglob("*.feedback-tmp.*")))

    def test_deep_parse_patch_exception_is_sanitized_at_one_boundary(self):
        canary = "".join(("SENSITIVE", "-CANARY-DEEP-EXCEPTION"))
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            stdout = io.StringIO()
            stderr = io.StringIO()
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(
                self._timezone_candidate(), {self._timezone_path()},
                source_scope="prod", source_ref="runtime",
            )
            with (
                redirect_stdout(stdout), redirect_stderr(stderr),
                mock.patch.object(
                    FEEDBACK, "_patch_global_yaml",
                    side_effect=RuntimeError(canary),
                ),
                self.assertRaises(FEEDBACK.FeedbackError) as raised,
            ):
                transaction.commit()
            transaction.close()

            combined = stdout.getvalue() + stderr.getvalue() + str(raised.exception)
            self.assertNotIn(canary, combined)
            self.assertEqual(original, authority.read_bytes())

    def test_candidate_name_fd_metadata_and_cleanup_are_identity_bound(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        for attack in ("symlink", "hardlink", "rewrite", "chmod", "fifo"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = self._authority(root, original)
                canary = root / "operator-canary"
                canary.write_bytes(b"KEEP")
                transaction = self._transaction(authority, root)
                transaction.__enter__()
                transaction.stage(
                    self._timezone_candidate(), {self._timezone_path()},
                    source_scope="prod", source_ref="runtime",
                )
                real_check = transaction._assert_candidate
                attacked_name = None
                extra = None

                def attack_before_check(name, descriptor, candidate_bytes):
                    nonlocal attacked_name, extra
                    attacked_name = name
                    path = root / name
                    if attack == "symlink":
                        path.unlink()
                        path.symlink_to(canary.name)
                    elif attack == "hardlink":
                        extra = root / "extra-link"
                        os.link(path, extra)
                    elif attack == "rewrite":
                        os.lseek(descriptor, 0, os.SEEK_SET)
                        os.write(descriptor, b"X" * len(candidate_bytes))
                        os.fsync(descriptor)
                    elif attack == "chmod":
                        os.chmod(path, 0o600)
                    else:
                        path.unlink()
                        os.mkfifo(path)
                    return real_check(name, descriptor, candidate_bytes)

                with (
                    mock.patch.object(
                        transaction, "_assert_candidate",
                        side_effect=attack_before_check,
                    ),
                    self.assertRaises(FEEDBACK.FeedbackError) as raised,
                ):
                    transaction.commit()
                transaction.close()

                self.assertIn("published=false", str(raised.exception))
                self.assertEqual(0, transaction.commit_count)
                self.assertEqual(original, authority.read_bytes())
                self.assertEqual(b"KEEP", canary.read_bytes())
                if attack in {"symlink", "fifo"}:
                    self.assertTrue(os.path.lexists(root / attacked_name))
                if extra is not None:
                    extra.unlink()

    def test_postreplace_failures_leave_durable_one_way_state_and_block_retry(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        phases = {
            "advance": ("_advance_publication_state", False),
            "parent-fsync": ("_fsync_live_parent", True),
            "postverify": ("_verify_published_candidate", True),
            "state-remove": ("_remove_publication_state", True),
        }
        for label, (method, expected_published) in phases.items():
            with self.subTest(phase=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = self._authority(root, original)
                transaction = self._transaction(authority, root)
                transaction.__enter__()
                transaction.stage(
                    self._timezone_candidate(), {self._timezone_path()},
                    source_scope="prod", source_ref="runtime",
                )
                with (
                    mock.patch.object(
                        transaction, method,
                        side_effect=OSError("SECRET-FAULT-CANARY"),
                    ),
                    self.assertRaises(
                        FEEDBACK.PublicationIndeterminateError,
                    ) as raised,
                ):
                    transaction.commit()
                transaction.close()

                self.assertEqual(1, transaction.commit_count)
                self.assertTrue(transaction.published)
                self.assertIn("publication-indeterminate", str(raised.exception))
                self.assertNotIn("SECRET-FAULT-CANARY", str(raised.exception))
                record = json.loads(self._state_path(authority).read_text())
                self.assertIs(expected_published, record["published"])
                with self.assertRaisesRegex(Exception, "state-blocked"):
                    with self._transaction(authority, root):
                        pass

    def test_state_unlink_directory_fsync_failure_is_success_with_storage_warning(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            state_path = self._state_path(authority)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(
                self._timezone_candidate(), {self._timezone_path()},
                source_scope="prod", source_ref="runtime",
            )
            real_fsync = FEEDBACK.os.fsync
            injected = False

            def fail_once_after_state_unlink(descriptor):
                nonlocal injected
                if (
                    descriptor == transaction._state_dir_fd
                    and not state_path.exists()
                    and not injected
                ):
                    injected = True
                    raise OSError("state-cleanup-fsync-canary")
                return real_fsync(descriptor)

            recovery_writes = 0
            real_write_state = transaction._write_state_record

            def reject_recovery_write(*args, **kwargs):
                nonlocal recovery_writes
                if transaction.published and not state_path.exists():
                    recovery_writes += 1
                    raise OSError("recovery-write-double-fault-canary")
                return real_write_state(*args, **kwargs)

            output = io.StringIO()
            with (
                redirect_stdout(output),
                mock.patch.object(
                    FEEDBACK.os, "fsync", side_effect=fail_once_after_state_unlink,
                ),
                mock.patch.object(
                    transaction, "_write_state_record",
                    side_effect=reject_recovery_write,
                ),
            ):
                self.assertEqual(1, transaction.commit())
            transaction.close()

            self.assertTrue(injected)
            self.assertEqual(1, transaction.commit_count)
            self.assertTrue(transaction.published)
            self.assertTrue(transaction._committed)
            self.assertEqual(0, recovery_writes)
            self.assertFalse(state_path.exists())
            self.assertEqual({
                "publication": "succeeded",
                "storage_health": "state-directory-fsync-failed",
                "consequence": (
                    "published-state-marker-may-reappear-after-crash"
                ),
            }, transaction.storage_health_warning)
            warning = output.getvalue()
            self.assertIn("feedback-warning", warning)
            self.assertIn("publication=succeeded", warning)
            self.assertIn(
                "storage_health=state-directory-fsync-failed", warning,
            )
            self.assertIn(
                "consequence=published-state-marker-may-reappear-after-crash",
                warning,
            )
            self.assertNotIn("publication-indeterminate", warning)
            self.assertNotIn("state-cleanup-fsync-canary", warning)
            self.assertNotIn("recovery-write-double-fault-canary", warning)

    def test_project_parent_mode_uid_gid_drift_fails_and_child_creation_does_not(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        for field in ("st_mode", "st_uid", "st_gid"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = self._authority(root, original)
                transaction = self._transaction(authority, root)
                transaction.__enter__()
                transaction.stage(
                    self._timezone_candidate(), {self._timezone_path()},
                    source_scope="prod", source_ref="runtime",
                )
                real_fstat = FEEDBACK.os.fstat
                real_open = FEEDBACK.os.open
                candidate_opens = []

                def changed_parent(descriptor):
                    value = real_fstat(descriptor)
                    if descriptor != transaction._parent_fd:
                        return value
                    attributes = {
                        name: getattr(value, name) for name in (
                            "st_dev", "st_ino", "st_mode", "st_nlink",
                            "st_uid", "st_gid", "st_size", "st_mtime_ns",
                            "st_ctime_ns",
                        )
                    }
                    if field == "st_mode":
                        attributes[field] ^= 0o020
                    else:
                        attributes[field] += 1
                    return SimpleNamespace(**attributes)

                def record_candidate_open(path, *args, **kwargs):
                    if isinstance(path, str) and ".feedback-tmp." in path:
                        candidate_opens.append(path)
                    return real_open(path, *args, **kwargs)

                with (
                    mock.patch.object(
                        FEEDBACK.os, "fstat", side_effect=changed_parent,
                    ),
                    mock.patch.object(
                        FEEDBACK.os, "open", side_effect=record_candidate_open,
                    ),
                    self.assertRaisesRegex(FEEDBACK.FeedbackError, "cas-parent"),
                ):
                    transaction.commit()
                transaction.close()
                self.assertEqual(original, authority.read_bytes())
                self.assertEqual(0, transaction.commit_count)
                self.assertEqual([], candidate_opens)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            # A real child directory changes nlink/mtime/ctime. Those fields
            # are intentionally outside the parent authority identity.
            (root / "legitimate-child").mkdir()
            transaction.stage(
                self._timezone_candidate(), {self._timezone_path()},
                source_scope="prod", source_ref="runtime",
            )
            self.assertEqual(1, transaction.commit())
            transaction.close()
            self.assertIn(b"timezone: UTC", authority.read_bytes())

    def test_live_replace_failure_keeps_prepared_and_after_success_error_is_indeterminate(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        for after_success in (False, True):
            with self.subTest(after_success=after_success), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = self._authority(root, original)
                original_identity = os.lstat(authority)
                real_replace = FEEDBACK.os.replace
                transaction = self._transaction(authority, root)
                transaction.__enter__()
                transaction.stage(
                    self._timezone_candidate(), {self._timezone_path()},
                    source_scope="prod", source_ref="runtime",
                )

                def fail_only_live(source, destination, *args, **kwargs):
                    if (
                        destination == authority.name
                        and kwargs.get("dst_dir_fd") == transaction._parent_fd
                    ):
                        if after_success:
                            real_replace(source, destination, *args, **kwargs)
                        raise OSError("INJECTED-CANARY")
                    return real_replace(source, destination, *args, **kwargs)

                expected_error = (
                    FEEDBACK.PublicationIndeterminateError
                    if after_success else FEEDBACK.FeedbackError
                )
                with (
                    mock.patch.object(
                        FEEDBACK.os, "replace", side_effect=fail_only_live,
                    ),
                    self.assertRaises(expected_error) as raised,
                ):
                    transaction.commit()
                transaction.close()

                state = json.loads(self._state_path(authority).read_text())
                self.assertIs(False, state["published"])
                self.assertNotIn("INJECTED-CANARY", str(raised.exception))
                if after_success:
                    self.assertEqual(1, transaction.commit_count)
                    self.assertTrue(transaction.published)
                    self.assertIn(b"timezone: UTC", authority.read_bytes())
                else:
                    current = os.lstat(authority)
                    self.assertEqual(0, transaction.commit_count)
                    self.assertFalse(transaction.published)
                    self.assertEqual(
                        (original_identity.st_dev, original_identity.st_ino),
                        (current.st_dev, current.st_ino),
                    )
                    self.assertEqual(original, authority.read_bytes())
                with self.assertRaisesRegex(Exception, "state-blocked"):
                    with self._transaction(authority, root):
                        pass

    def test_recovery_clears_only_published_true_with_matching_live_sha(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(
                self._timezone_candidate(), {self._timezone_path()},
                source_scope="prod", source_ref="runtime",
            )
            with (
                mock.patch.object(
                    transaction, "_remove_publication_state",
                    side_effect=OSError("cleanup"),
                ),
                self.assertRaises(FEEDBACK.PublicationIndeterminateError),
            ):
                transaction.commit()
            transaction.close()
            state = self._state_path(authority)
            self.assertTrue(state.exists())

            self.assertTrue(FEEDBACK.recover_global_writeback_state(
                authority, workspace_root=root,
            ))
            self.assertFalse(state.exists())

        for published, live_matches in ((False, True), (True, False)):
            with self.subTest(published=published, live_matches=live_matches), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = self._authority(root, original)
                expected = "a" * 64
                state = self._state_path(authority)
                state.parent.mkdir(parents=True)
                state.write_text(json.dumps({
                    "authority_path": str(authority.absolute()),
                    "expected_after_sha256": (
                        FEEDBACK.hashlib.sha256(original).hexdigest()
                        if live_matches else expected
                    ),
                    "published": published,
                    "schema": 1,
                    "timestamp": "2026-09-11T00:00:00Z",
                }, sort_keys=True, separators=(",", ":")) + "\n")
                state.chmod(0o600)
                with self.assertRaisesRegex(Exception, "state-blocked"):
                    FEEDBACK.recover_global_writeback_state(
                        authority, workspace_root=root,
                    )
                self.assertTrue(state.exists())

    def test_invalid_authority_is_rejected_before_convert_outputs_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "runtime"
            source.mkdir()
            authority = root / "01-global.yaml"
            authority.write_text(
                "common: &shared {}\nother: *shared\n", encoding="utf-8",
            )
            output = root / "must-not-exist.csv"
            with self.assertRaisesRegex(ValueError, "alias/anchor"):
                FEEDBACK.convert_one(
                    source, output, global_config_path=authority,
                    environment_scope="prod",
                )
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name("must-not-exist-global.yaml").exists())

    def test_short_write_retries_and_failures_or_cas_preserve_precommit_bytes(self):
        original = b"common:\n  switch:\n    system:\n      date-time:\n        timezone: {}\n"
        path = ("common", "switch", "system", "date-time", "timezone")
        candidate = {"common": {"switch": {"system": {"date-time": {"timezone": "UTC"}}}}}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            real_write = os.write

            def short_write(descriptor, data):
                return real_write(descriptor, bytes(data[:max(1, len(data) // 2)]))

            with mock.patch.object(FEEDBACK.os, "write", side_effect=short_write):
                with self._transaction(authority, root) as transaction:
                    transaction.stage(candidate, {path}, source_scope="prod", source_ref="one")
            self.assertIn(b"timezone: UTC", authority.read_bytes())

            for operation in ("fsync", "replace"):
                with self.subTest(operation=operation):
                    authority.write_bytes(original)
                    with self.assertRaises(FEEDBACK.FeedbackError):
                        with self._transaction(authority, root) as transaction:
                            transaction.stage(candidate, {path}, source_scope="prod", source_ref="one")
                            patcher = mock.patch.object(
                                FEEDBACK.os, operation, side_effect=OSError("injected failure"),
                            )
                            patcher.start()
                            self.addCleanup(patcher.stop)
                    patcher.stop()
                    self.assertEqual(original, authority.read_bytes())

            authority.write_bytes(original)
            with mock.patch.object(FEEDBACK.os, "write", return_value=0):
                with self.assertRaisesRegex(FEEDBACK.FeedbackError, "short write"):
                    with self._transaction(authority, root) as transaction:
                        transaction.stage(
                            candidate, {path}, source_scope="prod", source_ref="one",
                        )
            self.assertEqual(original, authority.read_bytes())

            authority.write_bytes(original)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(candidate, {path}, source_scope="prod", source_ref="one")
            changed = original.replace(b"timezone: {}", b"timezone: Europe/Paris")
            authority.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "CAS"):
                transaction.commit()
            transaction.close()
            self.assertEqual(changed, authority.read_bytes())

    def test_symlink_swap_is_rejected_before_commit(self):
        original = b"common:\n  switch:\n    system:\n      date-time:\n        timezone: {}\n"
        path = ("common", "switch", "system", "date-time", "timezone")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            sample = root / "project-sample"
            project.mkdir()
            sample.mkdir()
            authority = self._authority(project, original)
            other = project / "other.yaml"
            other.write_bytes(original)
            link = sample / "01-global.yaml"
            link.symlink_to(os.path.relpath(authority, sample))
            transaction = self._transaction(
                link, root, managed_project_root=project,
            )
            transaction.__enter__()
            transaction.stage(
                {"common": {"switch": {"system": {"date-time": {"timezone": "UTC"}}}}},
                {path}, source_scope="prod", source_ref="one",
            )
            link.unlink()
            link.symlink_to(os.path.relpath(other, sample))
            with self.assertRaisesRegex(ValueError, "软链接身份"):
                transaction.commit()
            transaction.close()
            self.assertEqual(original, authority.read_bytes())
            self.assertEqual(original, other.read_bytes())

    def test_managed_sample_parent_and_state_directory_rebinding_fail_closed(self):
        original = (
            b"common:\n  switch:\n    system:\n      date-time:\n"
            b"        timezone: {}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            sample = root / "project-sample"
            project.mkdir()
            sample.mkdir()
            authority = self._authority(project, original)
            link = sample / "01-global.yaml"
            link.symlink_to(os.path.relpath(authority, sample))
            transaction = self._transaction(
                link, root, managed_project_root=project,
                managed_sample_path=sample,
            )
            transaction.__enter__()
            transaction.stage(
                self._timezone_candidate(), {self._timezone_path()},
                source_scope="prod", source_ref="runtime",
            )
            displaced = root / "displaced-sample"
            sample.rename(displaced)
            sample.mkdir()
            (sample / "01-global.yaml").symlink_to(
                os.path.relpath(authority, sample),
            )
            with self.assertRaisesRegex(Exception, "managed-link-identity"):
                transaction.commit()
            transaction.close()
            self.assertEqual(original, authority.read_bytes())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(
                self._timezone_candidate(), {self._timezone_path()},
                source_scope="prod", source_ref="runtime",
            )
            state_dir = authority.parent / "99-output-ztp/optimize"
            displaced = authority.parent / "99-output-ztp/displaced"
            state_dir.rename(displaced)
            state_dir.mkdir()
            with self.assertRaisesRegex(Exception, "state-directory-identity"):
                transaction.commit()
            transaction.close()
            self.assertEqual(original, authority.read_bytes())

    def test_concurrent_atomic_inode_replacement_fails_cas_without_overwrite(self):
        original = b"common:\n  switch:\n    system:\n      date-time:\n        timezone: {}\n"
        operator = original.replace(b"timezone: {}", b"timezone: Europe/Paris")
        path = ("common", "switch", "system", "date-time", "timezone")
        candidate = {"common": {"switch": {"system": {"date-time": {"timezone": "UTC"}}}}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = self._authority(root, original)
            replacement = root / "operator.yaml"
            replacement.write_bytes(operator)
            transaction = self._transaction(authority, root)
            transaction.__enter__()
            transaction.stage(
                candidate, {path}, source_scope="prod", source_ref="runtime",
            )
            os.replace(replacement, authority)
            with self.assertRaisesRegex(ValueError, "CAS identity"):
                transaction.commit()
            transaction.close()
            self.assertEqual(operator, authority.read_bytes())


if __name__ == "__main__":
    unittest.main()
