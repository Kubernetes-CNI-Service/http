"""Owned filesystem with synthetic root metadata; never real /var/lib files."""

import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_issue_tracker_credential_shape import info, load, SECRET


class CredentialFdDirectTests(unittest.TestCase):
    def test_synthetic_root_metadata_preserves_native_timestamp_fields_for_dependency_queries(self):
        expected = os.stat(self.root)
        fields = ("st_atime", "st_mtime", "st_ctime",
                  "st_atime_ns", "st_mtime_ns", "st_ctime_ns")
        with self.fixture():
            actual = os.stat(self.root)
            uid = actual.st_uid
            observed = {field: getattr(actual, field, None) for field in fields}
        self.assertEqual(0, uid)
        for field in fields:
            with self.subTest(field=field):
                self.assertEqual(getattr(expected, field), observed[field])

    def setUp(self):
        self.module = load()
        self.assertTrue(callable(getattr(self.module, "read_service_account_info", None)),
                        "fixed-path held-FD reader is missing")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "var/lib/http-ztp-container/service-account"
        self.directory.mkdir(parents=True, mode=0o700)
        self.path = self.directory / "cre.json"
        self.path.write_bytes(json.dumps(info()).encode())
        self.path.chmod(0o600)

    def fixture(self, *, fault=None, target_path=None):
        """Only '/' open remaps; all relative openat/read/stat use real owned FDs."""
        real_open, real_fstat, real_stat, real_read = os.open, os.fstat, os.stat, os.read
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_atime", "st_mtime", "st_ctime",
                  "st_atime_ns", "st_mtime_ns", "st_ctime_ns")
        opened, reads = [], []
        target_path = self.path if target_path is None else target_path
        def metadata(value):
            result = SimpleNamespace(**{name: getattr(value, name) for name in fields})
            result.st_uid = 0  # synthetic root only; no native identity claim
            if fault == "file_uid" and stat.S_ISREG(result.st_mode):
                result.st_uid = 501
            if fault == "directory_uid" and stat.S_ISDIR(result.st_mode):
                result.st_uid = 501
            return result
        def opening(name, flags, *args, **kwargs):
            opened.append(name)
            if name == "/":
                return real_open(self.root, flags, *args, **kwargs)
            return real_open(name, flags, *args, **kwargs)
        def reading(fd, count):
            reads.append((fd, count))
            data = real_read(fd, count)
            if fault == "file_rebind":
                saved = self.directory / "preserved-original.json"
                target_path.rename(saved)
                target_path.write_bytes(data)
                target_path.chmod(0o600)
            elif fault == "file_mutate":
                target_path.write_bytes(b" " + data)
            elif fault == "directory_rebind":
                self.directory.rename(self.directory.with_name("preserved-service-account"))
                self.directory.mkdir(mode=0o700)
            elif fault == "short_read":
                return data[:-1]
            return data
        from contextlib import ExitStack, contextmanager
        @contextmanager
        def patch():
            with ExitStack() as stack:
                for target, replacement in (
                    ("os.geteuid", lambda: 0), ("os.open", opening),
                    ("os.fstat", lambda fd: metadata(real_fstat(fd))),
                    ("os.stat", lambda *a, **k: metadata(real_stat(*a, **k))),
                    ("os.read", reading)):
                    stack.enter_context(mock.patch(target, side_effect=replacement))
                yield opened, reads
        return patch()

    def test_fixed_path_opens_relative_components_and_reads_single_held_fd_once(self):
        with self.fixture() as (opened, reads):
            parsed = self.module.read_service_account_info()
        self.assertEqual(info(), dict(parsed.mapping))
        self.assertEqual(["/", "var", "lib", "http-ztp-container", "service-account", "cre.json"], opened)
        self.assertEqual(1, len(reads))
        self.assertNotIn(SECRET, repr(parsed))
        with self.assertRaises(OSError):
            os.fstat(reads[0][0])  # reader must close its owned FD, not caller state

    def test_allowlist_rebind_after_read_is_denied_not_parsed_from_unheld_name(self):
        target = "Synthetic_Approved_Target_0001"
        path = self.directory / "issue-tracker-spreadsheet-whitelist.json"
        raw = json.dumps([target]).encode()
        path.write_bytes(raw); path.chmod(0o600)
        for fault in ("file_rebind", "file_mutate", "short_read"):
            with self.subTest(fault=fault), self.fixture(fault=fault, target_path=path) as (_, reads):
                with self.assertRaises(self.module.CredentialFileHold):
                    self.module.read_target_allowlist()
                self.assertEqual(1, len(reads))
            if fault == "file_rebind":
                path.unlink(); (self.directory / "preserved-original.json").rename(path)
            if fault == "file_mutate": path.write_bytes(raw)

    def test_environment_paths_cannot_redirect_either_fixed_private_file(self):
        target = "Synthetic_Approved_Target_0001"
        path = self.directory / "issue-tracker-spreadsheet-whitelist.json"
        path.write_bytes(json.dumps([target]).encode()); path.chmod(0o600)
        foreign = self.root / "foreign-private-input.json"
        foreign.write_bytes(b"not a credential or allowlist"); foreign.chmod(0o600)
        with mock.patch.dict(os.environ, {name: str(foreign) for name in (
            "GOOGLE_APPLICATION_CREDENTIALS", "HTTP_ISSUE_TRACKER_CREDENTIAL_PATH",
            "HTTP_ISSUE_TRACKER_ALLOWLIST", "SERVICE_ACCOUNT_FILE")}):
            with self.fixture() as (opened, reads):
                credential = self.module.read_service_account_info()
                snapshot = self.module.read_target_allowlist()
        self.assertEqual(info(), dict(credential.mapping))
        self.assertEqual((target,), snapshot.spreadsheet_ids)
        self.assertEqual(2, len(reads))
        self.assertNotIn(str(foreign), opened)
        self.assertEqual(b"not a credential or allowlist", foreign.read_bytes())
        self.assertNotIn(SECRET, repr(credential))

    def test_nonroot_refuses_before_open_or_read(self):
        with mock.patch("os.geteuid", return_value=501), mock.patch("os.open") as opening:
            with self.assertRaises(self.module.CredentialFileHold):
                self.module.read_service_account_info()
        opening.assert_not_called()

    def test_internal_fixed_name_enum_rejects_pathlike_aliases_before_any_open(self):
        class EqualToAnyName:
            def __eq__(self, other): return True
            def __fspath__(self): return "/unapproved/private/input"
        class TextAlias(str): pass
        for value in (EqualToAnyName(), TextAlias("cre.json"), "../cre.json", "/tmp/cre.json", b"cre.json", None):
            with self.subTest(value_type=type(value).__name__), mock.patch("os.geteuid", return_value=0), mock.patch(
                    "os.open", side_effect=self.module.CredentialFileHold()) as opening:
                with self.assertRaises(self.module.CredentialFileHold):
                    self.module._read_private_file(value)
                opening.assert_not_called()

    def test_file_and_directory_modes_links_and_file_uid_refuse_before_read(self):
        for fault in ("file_mode", "dir_mode", "ancestor_write", "hardlink", "symlink", "file_uid", "directory_uid"):
            with self.subTest(fault=fault):
                saved = self.path.read_bytes()
                other = self.directory / "other.json"
                if fault == "file_mode": self.path.chmod(0o640)
                if fault == "dir_mode": self.directory.chmod(0o750)
                if fault == "ancestor_write": self.directory.parent.chmod(0o777)
                if fault == "hardlink": os.link(self.path, other)
                if fault == "symlink":
                    self.path.rename(other); self.path.symlink_to(other)
                try:
                    with self.fixture(fault=fault) as (_, reads):
                        with self.assertRaises(self.module.CredentialFileHold):
                            self.module.read_service_account_info()
                    self.assertEqual([], reads)
                finally:
                    if fault == "symlink": self.path.unlink(); other.rename(self.path)
                    if fault == "hardlink": other.unlink()
                    self.path.chmod(0o600); self.directory.chmod(0o700)
                    self.directory.parent.chmod(0o700)
                self.assertEqual(saved, self.path.read_bytes())

    def test_file_or_ancestor_rebind_mutation_and_partial_read_refuse_after_single_read(self):
        for fault in ("file_rebind", "file_mutate", "directory_rebind", "short_read"):
            with self.subTest(fault=fault), self.fixture(fault=fault) as (_, reads):
                with self.assertRaises(self.module.CredentialFileHold) as caught:
                    self.module.read_service_account_info()
                self.assertEqual(1, len(reads))
                self.assertNotIn(SECRET, str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
            if fault == "directory_rebind":
                self.directory.rmdir()
                self.directory.with_name("preserved-service-account").rename(self.directory)
            if fault == "file_rebind":
                self.path.unlink()
                (self.directory / "preserved-original.json").rename(self.path)
            if fault == "file_mutate":
                self.path.write_bytes(json.dumps(info()).encode())

    def test_fifo_empty_oversize_and_missing_credentials_never_read_or_repair(self):
        original = self.path.read_bytes()
        for fault in ("fifo", "empty", "oversize", "missing"):
            with self.subTest(fault=fault):
                self.path.unlink()
                if fault == "fifo": os.mkfifo(self.path, 0o600)
                if fault == "empty": self.path.write_bytes(b"")
                if fault == "oversize": self.path.write_bytes(b" " * 65537)
                if fault != "missing": self.path.chmod(0o600)
                try:
                    with self.fixture() as (_, reads):
                        with self.assertRaises(self.module.CredentialFileHold):
                            self.module.read_service_account_info()
                    self.assertEqual([], reads)
                    if fault == "missing": self.assertFalse(self.path.exists())
                    if fault == "fifo": self.assertTrue(stat.S_ISFIFO(self.path.stat().st_mode))
                finally:
                    if fault != "missing": self.path.unlink()
                    self.path.write_bytes(original); self.path.chmod(0o600)

    def test_fixed_allowlist_reader_validates_held_file_before_exact_enumeration(self):
        self.assertTrue(callable(getattr(self.module, "read_target_allowlist", None)),
                        "fixed-path whitelist reader is missing")
        target = "Synthetic_Approved_Target_0001"
        path = self.directory / "issue-tracker-spreadsheet-whitelist.json"
        raw = json.dumps([target]).encode()
        path.write_bytes(raw); path.chmod(0o600)
        with self.fixture() as (opened, reads):
            snapshot = self.module.read_target_allowlist()
        self.assertEqual((target,), snapshot.spreadsheet_ids)
        self.assertEqual(raw, snapshot.source_bytes)
        self.assertEqual("issue-tracker-spreadsheet-whitelist.json", opened[-1])
        self.assertEqual(1, len(reads))
        with self.assertRaises(OSError): os.fstat(reads[0][0])
        path.chmod(0o640)
        with self.fixture() as (_, reads):
            with self.assertRaises(self.module.CredentialFileHold):
                self.module.read_target_allowlist()
        self.assertEqual([], reads)
        self.assertEqual(0o640, stat.S_IMODE(path.stat().st_mode))
        path.chmod(0o600)
        path.write_bytes(b'["*"]')
        from monitor.issue_tracker_online_target import OnlineTargetHold
        with self.fixture() as (_, reads):
            with self.assertRaises(OnlineTargetHold): self.module.read_target_allowlist()
        self.assertEqual(1, len(reads))

    def test_missing_kernel_flags_refuse_before_open_and_ancestor_symlink_is_not_followed(self):
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            with self.subTest(flag=flag), mock.patch("os.geteuid", return_value=0), mock.patch("os.open") as opening:
                original = getattr(os, flag)
                delattr(os, flag)
                try:
                    with self.assertRaises(self.module.CredentialFileHold):
                        self.module.read_service_account_info()
                    opening.assert_not_called()
                finally:
                    setattr(os, flag, original)
        ancestor = self.root / "var/lib/http-ztp-container"
        saved = ancestor.with_name("preserved-container")
        ancestor.rename(saved); ancestor.symlink_to(saved, target_is_directory=True)
        try:
            with self.fixture() as (_, reads), self.assertRaises(self.module.CredentialFileHold):
                self.module.read_service_account_info()
            self.assertEqual([], reads)
        finally:
            ancestor.unlink(); saved.rename(ancestor)

    def test_read_and_close_errors_are_sanitized_and_all_owned_descriptors_are_closed(self):
        real_close, real_fstat = os.close, os.fstat
        for fault in ("read_error", "close_error"):
            closed = []
            def closing(fd):
                closed.append(fd)
                real_close(fd)
                if fault == "close_error": raise OSError(SECRET)
            with self.subTest(fault=fault), self.fixture(), mock.patch("os.close", side_effect=closing):
                if fault == "read_error":
                    with mock.patch("os.read", side_effect=OSError(SECRET)):
                        with self.assertRaises(self.module.CredentialFileHold) as caught:
                            self.module.read_service_account_info()
                else:
                    with self.assertRaises(self.module.CredentialFileHold) as caught:
                        self.module.read_service_account_info()
            self.assertEqual(6, len(closed))
            for fd in closed:
                with self.assertRaises(OSError): real_fstat(fd)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)


class CredentialFdTargetWorkflowTests(unittest.TestCase):
    setUp = CredentialFdDirectTests.setUp
    fixture = CredentialFdDirectTests.fixture

    def test_held_credential_and_allowlist_to_real_policy_denies_revocation_and_stale_bytes(self):
        from monitor.issue_tracker_online_target import bind_online_target, OnlineTargetHold
        self.assertTrue(callable(getattr(self.module, "read_target_allowlist", None)),
                        "fixed-path whitelist reader is missing")
        target = "Synthetic_Approved_Target_0001"
        path = self.directory / "issue-tracker-spreadsheet-whitelist.json"
        path.write_bytes(json.dumps([target]).encode()); path.chmod(0o600)
        policy = {"schema_version": 2, "common": {"mgmt": {"issue-tracker": {
            "status": "enabled", "spreadsheet_id": target}}}}
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.fixture() as (_, reads):
                credential = self.module.read_service_account_info()
                binding = bind_online_target(policy, self.module.read_target_allowlist())
            self.assertEqual(2, len(reads))
            self.assertEqual(info(), dict(credential.mapping))
            self.assertEqual(target, binding.spreadsheet_id)
            path.write_bytes(b" " + json.dumps([target]).encode())
            with self.fixture(), self.assertRaises(OnlineTargetHold) as stale:
                bind_online_target(policy, self.module.read_target_allowlist(), expected=binding)
            self.assertEqual("stale_target_binding", stale.exception.reason)
            path.write_bytes(b"[]")
            with self.fixture(), self.assertRaises(OnlineTargetHold) as revoked:
                bind_online_target(policy, self.module.read_target_allowlist())
            self.assertEqual("denied_empty_allowlist", revoked.exception.reason)
        self.assertFalse(hasattr(binding, "permit"))
        self.assertNotIn(SECRET, repr(credential))


if __name__ == "__main__":
    unittest.main()
