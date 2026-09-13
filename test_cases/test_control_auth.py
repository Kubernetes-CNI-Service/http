#!/usr/bin/env python3
"""Direct contracts for the Monitor control-auth credential helper."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import fcntl


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/control-auth.py"
EXPECTED_HELPER_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONTROL_AUTH = load_module("control_auth_under_test", SCRIPT)

# The factory bytes are intentionally consumed from the production authority,
# never duplicated in public tests.  Independently authored semantic tests
# below verify both owner-selected passwords with the real htpasswd binary.
FACTORY_BYTES = CONTROL_AUTH.FACTORY_RECORDS


def _synthetic_bcrypt_record(user: str, marker: str) -> bytes:
    """Build a parser fixture at runtime; it is not a reusable verifier."""
    body = (marker * 53)[:53]
    return f"{user}:$2y$12${body}\n".encode("ascii")


ROTATED_NVIS = (
    _synthetic_bcrypt_record("nvis", "N")
    + FACTORY_BYTES.splitlines(keepends=True)[1]
)
ROTATED_CUMULUS = (
    FACTORY_BYTES.splitlines(keepends=True)[0]
    + _synthetic_bcrypt_record("cumulus", "C")
)


class _Completed:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ControlAuthDirectTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "etc-http-ztp"
        self.auth_file = self.auth_dir / "control-users.htpasswd"
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.temporary.cleanup()

    def _make_directory(self, mode=0o750):
        self.auth_dir.mkdir()
        self.auth_dir.chmod(mode)

    def _write(self, data=FACTORY_BYTES, mode=0o640):
        if not self.auth_dir.exists():
            self._make_directory()
        self.auth_file.write_bytes(data)
        self.auth_file.chmod(mode)

    def _kwargs(self):
        return {
            "required_uid": self.uid,
            "required_gid": self.gid,
        }

    def _fake_runner(self, expected, calls):
        def run(argv, **kwargs):
            calls.append((tuple(argv), dict(kwargs)))
            user = argv[-1]
            record = next(
                line
                for line in expected.splitlines(keepends=True)
                if line.startswith(user.encode("ascii") + b":")
            )
            return _Completed(stdout=record)

        return run

    def _temporary_entries(self):
        return sorted(self.auth_dir.glob(".control-users.*"))

    def _monitor_authority_paths(self):
        boundary = self.root / f"authority-boundary-{time.monotonic_ns()}"
        parent = boundary / "var" / "lib"
        parent.mkdir(parents=True)
        boundary.chmod(0o700)
        (boundary / "var").chmod(0o755)
        parent.chmod(0o755)
        authority = parent / "http-ztp-monitor-auth"
        return boundary, authority

    def _monitor_authority_kwargs(self, boundary):
        return {
            "authority_boundary": boundary,
            "required_root_uid": self.uid,
            "required_root_gid": self.gid,
            "required_web_uid": self.uid,
            "required_web_gid": self.gid,
        }

    def _rebind_parent(self, canonical_bytes=FACTORY_BYTES):
        detached = self.root / f"detached-{time.monotonic_ns()}"
        self.auth_dir.rename(detached)
        self.auth_dir.mkdir(mode=0o750)
        self.auth_file.write_bytes(canonical_bytes)
        self.auth_file.chmod(0o640)
        return detached

    def test_ensure_initializes_exact_factory_records_and_permissions(self):
        created = CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())

        self.assertTrue(created)
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual(0o750, stat.S_IMODE(self.auth_dir.stat().st_mode))
        self.assertEqual(0o640, stat.S_IMODE(self.auth_file.stat().st_mode))
        self.assertEqual(self.uid, self.auth_dir.stat().st_uid)
        self.assertEqual(self.gid, self.auth_dir.stat().st_gid)
        self.assertEqual(self.uid, self.auth_file.stat().st_uid)
        self.assertEqual(self.gid, self.auth_file.stat().st_gid)
        self.assertEqual(1, self.auth_file.stat().st_nlink)
        self.assertEqual(
            {"valid": True, "factory_records_active": True},
            CONTROL_AUTH.status_auth_file(self.auth_file, **self._kwargs()),
        )

    def test_monitor_authority_provision_is_one_fixed_preserving_primitive(self):
        boundary, authority = self._monitor_authority_paths()
        options = self._monitor_authority_kwargs(boundary)

        CONTROL_AUTH.provision_monitor_authority(authority, **options)
        lock = authority / "status.lock"
        cache = authority / "monitor-auth"
        self.assertEqual(0o755, stat.S_IMODE(authority.stat().st_mode))
        self.assertEqual(0o660, stat.S_IMODE(lock.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(cache.stat().st_mode))
        self.assertEqual(1, lock.stat().st_nlink)

        breaker = (
            b'{"contaminant_dev":1,"contaminant_ino":2,'
            b'"failure_count":3,"schema_version":1}\n'
        )
        lock.write_bytes(breaker)
        before = (lock.stat().st_dev, lock.stat().st_ino)
        CONTROL_AUTH.provision_monitor_authority(authority, **options)
        CONTROL_AUTH.attest_monitor_authority(authority, **options)
        self.assertEqual(before, (lock.stat().st_dev, lock.stat().st_ino))
        self.assertEqual(breaker, lock.read_bytes())

    def test_monitor_authority_attestation_rejects_every_unsafe_shape(self):
        cases = (
            "missing", "root-mode", "lock-mode", "lock-hardlink",
            "lock-symlink", "lock-fifo", "cache-mode", "cache-symlink",
            "writable-parent",
        )
        for case in cases:
            with self.subTest(case=case):
                boundary, authority = self._monitor_authority_paths()
                options = self._monitor_authority_kwargs(boundary)
                if case != "missing":
                    CONTROL_AUTH.provision_monitor_authority(authority, **options)
                    lock = authority / "status.lock"
                    cache = authority / "monitor-auth"
                    if case == "root-mode":
                        authority.chmod(0o775)
                    elif case == "lock-mode":
                        lock.chmod(0o600)
                    elif case == "lock-hardlink":
                        os.link(lock, authority / "lock-alias")
                    elif case == "lock-symlink":
                        lock.unlink()
                        lock.symlink_to(authority / "victim")
                    elif case == "lock-fifo":
                        lock.unlink()
                        os.mkfifo(lock, 0o660)
                    elif case == "cache-mode":
                        cache.chmod(0o755)
                    elif case == "cache-symlink":
                        cache.rmdir()
                        cache.symlink_to(authority, target_is_directory=True)
                    elif case == "writable-parent":
                        authority.parent.chmod(0o777)
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.attest_monitor_authority(authority, **options)
                shutil.rmtree(boundary, ignore_errors=True)

    def test_monitor_authority_cli_is_fixed_and_attest_never_creates(self):
        boundary, authority = self._monitor_authority_paths()
        options = self._monitor_authority_kwargs(boundary)
        with self.assertRaises(CONTROL_AUTH.ControlAuthError):
            CONTROL_AUTH.attest_monitor_authority(authority, **options)
        self.assertFalse(authority.exists())
        help_text = CONTROL_AUTH._parser().format_help()
        self.assertIn("monitor-authority-provision", help_text)
        self.assertIn("monitor-authority-attest", help_text)
        self.assertEqual(
            Path("/var/lib/http-ztp-monitor-auth"),
            CONTROL_AUTH.MONITOR_AUTHORITY_ROOT,
        )

    def test_factory_records_verify_the_two_owner_selected_public_defaults(self):
        htpasswd = shutil.which("htpasswd")
        self.assertIsNotNone(
            htpasswd,
            "real htpasswd is required to verify the public bootstrap records",
        )
        self._write()
        owner_defaults = (("nvis", "nvidia"), ("cumulus", "cumulus"))
        for user, public_default in owner_defaults:
            with self.subTest(user=user):
                completed = subprocess.run(
                    [htpasswd, "-vi", os.fspath(self.auth_file), user],
                    input=(public_default + "\n").encode("ascii"),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=15,
                )
                self.assertEqual(
                    0,
                    completed.returncode,
                    "factory verifier did not match its independently authored default",
                )

    def test_help_records_human_terminal_only_rotation_contract(self):
        self.assertEqual(
            EXPECTED_HELPER_SHA256,
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        completed = subprocess.run(
            [sys.executable, "-B", os.fspath(SCRIPT), "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)
        self.assertIn(
            "Rotation requires a human at a terminal on the management server "
            "by design; it cannot be automated or run unattended.",
            " ".join(completed.stdout.split()),
        )

    def test_explicit_ensure_emits_one_bounded_actionable_factory_warning(self):
        self._write()
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = CONTROL_AUTH.main(
                ["ensure"],
                auth_path=self.auth_file,
                required_uid=self.uid,
                required_gid=self.gid,
            )
        expected = (
            "WARNING: factory Monitor control credentials are active; "
            "rotate both users immediately after first login.\n"
        )
        self.assertEqual(0, code)
        self.assertEqual("", output.getvalue())
        self.assertEqual(expected, errors.getvalue())
        self.assertEqual(1, len(errors.getvalue().splitlines()))
        self.assertLessEqual(len(errors.getvalue().encode("utf-8")), 192)

        self._write(ROTATED_NVIS)
        errors = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(errors):
            code = CONTROL_AUTH.main(
                ["ensure"],
                auth_path=self.auth_file,
                required_uid=self.uid,
                required_gid=self.gid,
            )
        self.assertEqual(0, code)
        self.assertEqual("", errors.getvalue())

    def test_directory_is_created_private_before_final_metadata_is_applied(self):
        real_mkdir = os.mkdir
        requested_modes = []

        def recording_mkdir(path, mode=0o777, *, dir_fd=None):
            requested_modes.append(mode)
            return real_mkdir(path, mode, dir_fd=dir_fd)

        with mock.patch.object(
            CONTROL_AUTH.os, "mkdir", side_effect=recording_mkdir
        ):
            CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())

        self.assertEqual([0o700], requested_modes)
        self.assertEqual(0o750, stat.S_IMODE(self.auth_dir.stat().st_mode))

    def test_ensure_preserves_every_byte_and_mtime_of_valid_existing_file(self):
        self._write(ROTATED_NVIS)
        before = self.auth_file.stat()

        created = CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())

        after = self.auth_file.stat()
        self.assertFalse(created)
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())
        self.assertEqual(before.st_ino, after.st_ino)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
        self.assertEqual(
            {"valid": True, "factory_records_active": False},
            CONTROL_AUTH.status_auth_file(self.auth_file, **self._kwargs()),
        )

    def test_ensure_never_repairs_or_replaces_an_existing_unsafe_file(self):
        unsafe = b"malformed-existing-state\n"
        self._write(unsafe)
        before = self.auth_file.stat()

        with self.assertRaises(CONTROL_AUTH.ControlAuthError):
            CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())

        after = self.auth_file.stat()
        self.assertEqual(unsafe, self.auth_file.read_bytes())
        self.assertEqual(before.st_ino, after.st_ino)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)

    def test_valid_existing_records_may_be_reordered_but_are_preserved(self):
        reordered = b"".join(reversed(ROTATED_NVIS.splitlines(keepends=True)))
        self._write(reordered)

        self.assertFalse(
            CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())
        )
        self.assertEqual(reordered, self.auth_file.read_bytes())
        self.assertEqual(
            {"valid": True, "factory_records_active": False},
            CONTROL_AUTH.status_auth_file(self.auth_file, **self._kwargs()),
        )

    def test_missing_state_is_invalid_for_validate_and_status(self):
        self._make_directory()
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "missing"):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
        self.assertEqual(
            {"valid": False, "factory_records_active": False},
            CONTROL_AUTH.status_auth_file(self.auth_file, **self._kwargs()),
        )

    def test_rejects_symlink_hardlink_directory_and_nonregular_target(self):
        self._make_directory()
        source = self.root / "outside"
        source.write_bytes(FACTORY_BYTES)
        source.chmod(0o640)

        os.symlink(source, self.auth_file)
        with self.assertRaises(CONTROL_AUTH.ControlAuthError):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
        self.auth_file.unlink()

        os.link(source, self.auth_file)
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "link"):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
        self.auth_file.unlink()
        source.unlink()

        self.auth_file.mkdir()
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "regular"):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
        self.auth_file.rmdir()

        fifo = self.auth_file
        os.mkfifo(fifo, 0o640)
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "regular"):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())

    def test_rejects_wrong_file_or_directory_metadata(self):
        self._write(mode=0o600)
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "0640"):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
        self.auth_file.chmod(0o640)

        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "owner"):
            CONTROL_AUTH.validate_auth_file(
                self.auth_file,
                required_uid=self.uid + 1,
                required_gid=self.gid,
            )
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "group"):
            CONTROL_AUTH.validate_auth_file(
                self.auth_file,
                required_uid=self.uid,
                required_gid=self.gid + 1,
            )

        self.auth_dir.chmod(0o700)
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "0750"):
            CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())

    def test_rejects_symlink_or_nondirectory_parent(self):
        real = self.root / "real"
        real.mkdir(mode=0o750)
        os.symlink(real, self.auth_dir)
        with self.assertRaises(CONTROL_AUTH.ControlAuthError):
            CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())
        self.auth_dir.unlink()

        self.auth_dir.write_text("not a directory", encoding="ascii")
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "directory"):
            CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())

    def test_rejects_empty_oversize_non_ascii_and_unterminated_content(self):
        cases = (
            (b"", "empty"),
            (b"x" * (CONTROL_AUTH.MAX_AUTH_FILE_SIZE + 1), "large"),
            (FACTORY_BYTES + b"\xff", "ASCII"),
            (FACTORY_BYTES.rstrip(b"\n"), "newline"),
        )
        for index, (data, message) in enumerate(cases):
            with self.subTest(index=index):
                if self.auth_file.exists():
                    self.auth_file.unlink()
                self._write(data)
                with self.assertRaisesRegex(
                    CONTROL_AUTH.ControlAuthError, message
                ):
                    CONTROL_AUTH.validate_auth_file(
                        self.auth_file, **self._kwargs()
                    )

    def test_rejects_duplicate_missing_extra_user_and_malformed_hashes(self):
        first, second = FACTORY_BYTES.splitlines(keepends=True)
        bad_cases = (
            (first + first, "duplicate"),
            (first, "users"),
            (FACTORY_BYTES + b"other:" + first.split(b":", 1)[1], "users"),
            (first.replace(b"$2y$", b"$6$", 1) + second, "bcrypt"),
            (first.replace(b"$12$", b"$11$", 1) + second, "cost 12"),
            (first.replace(b"nvis:", b"nvis :", 1) + second, "users"),
            (first.replace(b":$2y$", b"::${2y}$", 1) + second, "bcrypt"),
        )
        for index, (data, message) in enumerate(bad_cases):
            with self.subTest(index=index):
                if self.auth_file.exists():
                    self.auth_file.unlink()
                self._write(data)
                with self.assertRaisesRegex(
                    CONTROL_AUTH.ControlAuthError, message
                ):
                    CONTROL_AUTH.validate_auth_file(
                        self.auth_file, **self._kwargs()
                    )

    def test_read_detects_a_file_changed_while_held_open(self):
        self._write()
        real_read = CONTROL_AUTH.os.read
        changed = False

        def racing_read(descriptor, size):
            nonlocal changed
            data = real_read(descriptor, size)
            if not changed:
                changed = True
                self.auth_file.write_bytes(ROTATED_NVIS)
                self.auth_file.chmod(0o640)
            return data

        with mock.patch.object(CONTROL_AUTH.os, "read", side_effect=racing_read):
            with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "changed"):
                CONTROL_AUTH.validate_auth_file(
                    self.auth_file, **self._kwargs()
                )

    def test_initialization_never_clobbers_a_racing_destination(self):
        self._make_directory()

        def race(*_args, **_kwargs):
            self.auth_file.write_bytes(ROTATED_NVIS)
            self.auth_file.chmod(0o640)
            raise FileExistsError("racing target")

        with mock.patch.object(CONTROL_AUTH.os, "link", side_effect=race):
            with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "appeared"):
                CONTROL_AUTH.ensure_auth_file(
                    self.auth_file, **self._kwargs()
                )

        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_initialization_atomic_publication_failure_leaves_no_target_or_temp(self):
        self._make_directory()
        with mock.patch.object(
            CONTROL_AUTH.os, "link", side_effect=OSError("publish failed")
        ):
            with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "publish"):
                CONTROL_AUTH.ensure_auth_file(
                    self.auth_file, **self._kwargs()
                )
        self.assertFalse(self.auth_file.exists())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_rotate_uses_only_stdin_for_secret_and_changes_exact_user(self):
        self._write()
        prompts = iter(("A-long!secure7", "A-long!secure7"))
        calls = []

        result = CONTROL_AUTH.rotate_auth_file(
            self.auth_file,
            user="nvis",
            password_reader=lambda _prompt: next(prompts),
            runner=self._fake_runner(ROTATED_NVIS, calls),
            htpasswd_program="/safe/htpasswd",
            **self._kwargs(),
        )

        self.assertEqual({"valid": True, "factory_records_active": False}, result)
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())
        self.assertEqual(1, len(calls))
        argv, options = calls[0]
        self.assertEqual(
            ("/safe/htpasswd", "-niB", "-C", "12", "nvis"), argv
        )
        self.assertEqual(b"A-long!secure7\n", options["input"])
        flattened = "\0".join(argv) + repr(options.get("env", {}))
        self.assertNotIn("A-long!secure7", flattened)
        self.assertEqual(subprocess.PIPE, options["stdout"])
        self.assertEqual(subprocess.PIPE, options["stderr"])
        self.assertEqual(0o640, stat.S_IMODE(self.auth_file.stat().st_mode))

    def test_rotate_supports_only_the_two_exact_usernames(self):
        self._write()
        for user in ("NVIS", "root", "nvis ", "", "cumulus/../root"):
            with self.subTest(user=user):
                with self.assertRaisesRegex(
                    CONTROL_AUTH.ControlAuthError, "user"
                ):
                    CONTROL_AUTH.rotate_auth_file(
                        self.auth_file,
                        user=user,
                        password_reader=lambda _prompt: self.fail(
                            "invalid user must fail before password input"
                        ),
                        runner=lambda *_args, **_kwargs: self.fail(
                            "invalid user must fail before subprocess"
                        ),
                        **self._kwargs(),
                    )

    def test_rotate_reads_confirmation_twice_and_rejects_bad_passwords(self):
        bad_pairs = (
            ("short", "short"),
            ("x" * 73, "x" * 73),
            ("twelvechars!", "different-value"),
            ("validlength\n", "validlength\n"),
            ("validlength\0", "validlength\0"),
            ("validlengthé", "validlengthé"),
        )
        for index, pair in enumerate(bad_pairs):
            with self.subTest(index=index):
                self._write()
                values = iter(pair)
                prompts = []

                def reader(prompt):
                    prompts.append(prompt)
                    return next(values)

                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.rotate_auth_file(
                        self.auth_file,
                        user="nvis",
                        password_reader=reader,
                        runner=lambda *_args, **_kwargs: self.fail(
                            "bad password must fail before subprocess"
                        ),
                        **self._kwargs(),
                    )
                self.assertEqual(2, len(prompts))

    def test_rotate_transport_failure_preserves_original_and_cleans_temp(self):
        self._write()

        def failed_runner(*_args, **_kwargs):
            return _Completed(returncode=1, stdout=b"tool output", stderr=b"failure")

        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "htpasswd"):
            CONTROL_AUTH.rotate_auth_file(
                self.auth_file,
                user="nvis",
                password_reader=lambda _prompt: "A-long!secure7",
                runner=failed_runner,
                **self._kwargs(),
            )
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_rotate_transport_exception_preserves_original_and_cleans_temp(self):
        self._write()

        def raising_runner(*_args, **_kwargs):
            raise OSError("cannot execute")

        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "htpasswd"):
            CONTROL_AUTH.rotate_auth_file(
                self.auth_file,
                user="nvis",
                password_reader=lambda _prompt: "A-long!secure7",
                runner=raising_runner,
                **self._kwargs(),
            )
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_rotate_rejects_candidate_that_changes_the_other_user(self):
        self._write()
        calls = []

        def wrong_user_runner(argv, **kwargs):
            calls.append((tuple(argv), dict(kwargs)))
            return _Completed(stdout=ROTATED_CUMULUS.splitlines(keepends=True)[1])

        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "selected user"):
            CONTROL_AUTH.rotate_auth_file(
                self.auth_file,
                user="nvis",
                password_reader=lambda _prompt: "A-long!secure7",
                runner=wrong_user_runner,
                **self._kwargs(),
            )
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_rotate_rejects_symlink_candidate_before_commit(self):
        self._write()
        real_replace = os.replace
        attacker = ROTATED_CUMULUS
        raced = False

        def swap_candidate(src, dst, **kwargs):
            nonlocal raced
            if not raced and str(src).startswith(".control-users."):
                raced = True
                os.unlink(src, dir_fd=kwargs["src_dir_fd"])
                descriptor = os.open(
                    src,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o640,
                    dir_fd=kwargs["src_dir_fd"],
                )
                try:
                    os.write(descriptor, attacker)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            return real_replace(src, dst, **kwargs)

        with mock.patch.object(CONTROL_AUTH.os, "replace", side_effect=swap_candidate):
            with self.assertRaises(CONTROL_AUTH.ControlAuthIndeterminateError):
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(raced)
        self.assertEqual(attacker, self.auth_file.read_bytes())

    def test_rotate_rejects_malformed_or_unchanged_candidate_before_commit(self):
        cases = (
            b"invalid\n",
            FACTORY_BYTES.splitlines(keepends=True)[0],
        )
        for index, output in enumerate(cases):
            with self.subTest(index=index):
                self._write()
                calls = []

                def runner(argv, **kwargs):
                    calls.append((tuple(argv), dict(kwargs)))
                    return _Completed(stdout=output)

                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.rotate_auth_file(
                        self.auth_file,
                        user="nvis",
                        password_reader=lambda _prompt: "A-long!secure7",
                        runner=runner,
                        **self._kwargs(),
                    )
                self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
                self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_rotate_atomic_replace_failure_preserves_original_and_cleans_temp(self):
        self._write()
        calls = []
        with mock.patch.object(
            CONTROL_AUTH.os, "replace", side_effect=OSError("replace failed")
        ):
            with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "replace"):
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="cumulus",
                    password_reader=lambda _prompt: "Another!secure8",
                    runner=self._fake_runner(ROTATED_CUMULUS, calls),
                    **self._kwargs(),
                )
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_rotate_revalidates_original_before_atomic_replace(self):
        self._write()
        calls = []

        def runner_with_race(argv, **kwargs):
            self.auth_file.write_bytes(ROTATED_CUMULUS)
            self.auth_file.chmod(0o640)
            calls.append((argv, kwargs))
            return _Completed(stdout=ROTATED_NVIS.splitlines(keepends=True)[0])

        CONTROL_AUTH.rotate_auth_file(
            self.auth_file,
            user="nvis",
            password_reader=lambda _prompt: "A-long!secure7",
            runner=runner_with_race,
            **self._kwargs(),
        )
        combined = (
            ROTATED_NVIS.splitlines(keepends=True)[0]
            + ROTATED_CUMULUS.splitlines(keepends=True)[1]
        )
        self.assertEqual(combined, self.auth_file.read_bytes())
        self.assertEqual([], list(self.auth_dir.glob(".control-users.*")))

    def test_parent_rebind_is_rejected_by_validate_ensure_and_rotate(self):
        operations = ("validate", "ensure", "rotate")
        for operation in operations:
            with self.subTest(operation=operation):
                if self.auth_dir.exists():
                    for child in self.auth_dir.iterdir():
                        child.unlink()
                    self.auth_dir.rmdir()
                self._write()
                real_open_and_read = CONTROL_AUTH._open_and_read
                target_reads = 0
                detached = None

                def rebind_after_read(directory_descriptor, filename, **kwargs):
                    nonlocal target_reads, detached
                    snapshot = real_open_and_read(
                        directory_descriptor, filename, **kwargs
                    )
                    if filename == self.auth_file.name:
                        target_reads += 1
                        threshold = 2 if operation == "rotate" else 1
                        if target_reads == threshold:
                            detached = self._rebind_parent(ROTATED_CUMULUS)
                    return snapshot

                with mock.patch.object(
                    CONTROL_AUTH,
                    "_open_and_read",
                    side_effect=rebind_after_read,
                ):
                    with self.assertRaisesRegex(
                        CONTROL_AUTH.ControlAuthError, "directory.*changed|binding"
                    ):
                        if operation == "validate":
                            CONTROL_AUTH.validate_auth_file(
                                self.auth_file, **self._kwargs()
                            )
                        elif operation == "ensure":
                            CONTROL_AUTH.ensure_auth_file(
                                self.auth_file, **self._kwargs()
                            )
                        else:
                            CONTROL_AUTH.rotate_auth_file(
                                self.auth_file,
                                user="nvis",
                                password_reader=lambda _prompt: "A-long!secure7",
                                runner=self._fake_runner(ROTATED_NVIS, []),
                                **self._kwargs(),
                            )
                self.assertIsNotNone(detached)
                self.assertEqual(ROTATED_CUMULUS, self.auth_file.read_bytes())

    def test_concurrent_different_user_rotations_both_survive(self):
        self._write()
        real_replace = os.replace
        at_publish = threading.Barrier(2)
        errors = []
        results = []

        def serialized_or_racing_replace(src, dst, **kwargs):
            if dst == self.auth_file.name and not str(src).startswith(
                ".control-users.recovery."
            ):
                try:
                    at_publish.wait(timeout=0.4)
                except threading.BrokenBarrierError:
                    pass
            return real_replace(src, dst, **kwargs)

        def rotate(user, expected, password):
            try:
                results.append(
                    CONTROL_AUTH.rotate_auth_file(
                        self.auth_file,
                        user=user,
                        password_reader=lambda _prompt: password,
                        runner=self._fake_runner(expected, []),
                        **self._kwargs(),
                    )
                )
            except Exception as exc:  # captured for an exact aggregate assertion
                errors.append(exc)

        with mock.patch.object(
            CONTROL_AUTH.os, "replace", side_effect=serialized_or_racing_replace
        ):
            threads = (
                threading.Thread(
                    target=rotate,
                    args=("nvis", ROTATED_NVIS, "A-long!secure7"),
                ),
                threading.Thread(
                    target=rotate,
                    args=("cumulus", ROTATED_CUMULUS, "Another!secure8"),
                ),
            )
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        records = CONTROL_AUTH.validate_auth_file(
            self.auth_file, **self._kwargs()
        ).records
        self.assertEqual(
            ROTATED_NVIS.split(b":", 1)[1].splitlines()[0].decode("ascii"),
            records["nvis"],
        )
        self.assertEqual(
            ROTATED_CUMULUS.splitlines()[1].split(b":", 1)[1].decode("ascii"),
            records["cumulus"],
        )

    def test_initial_link_fsync_race_preserves_foreign_target(self):
        self._make_directory()
        real_fsync = os.fsync
        injected = False

        def racing_fsync(descriptor):
            nonlocal injected
            metadata = os.fstat(descriptor)
            if (
                not injected
                and stat.S_ISDIR(metadata.st_mode)
                and self.auth_file.exists()
                and self._temporary_entries()
            ):
                injected = True
                foreign = self.root / "foreign-auth"
                foreign.write_bytes(ROTATED_CUMULUS)
                foreign.chmod(0o640)
                os.replace(foreign, self.auth_file)
                raise OSError("injected publication fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(CONTROL_AUTH.os, "fsync", side_effect=racing_fsync):
            with self.assertRaises(CONTROL_AUTH.ControlAuthIndeterminateError):
                CONTROL_AUTH.ensure_auth_file(
                    self.auth_file, **self._kwargs()
                )
        self.assertTrue(injected)
        self.assertEqual(ROTATED_CUMULUS, self.auth_file.read_bytes())
        self.assertEqual([], self._temporary_entries())

    def test_post_replace_directory_fsync_failure_restores_exact_original(self):
        self._write()
        before = self.auth_file.stat()
        real_fsync = os.fsync
        injected = False

        def fail_first_commit_fsync(descriptor):
            nonlocal injected
            metadata = os.fstat(descriptor)
            if (
                not injected
                and stat.S_ISDIR(metadata.st_mode)
                and self.auth_file.exists()
                and self.auth_file.read_bytes() == ROTATED_NVIS
            ):
                injected = True
                raise OSError("injected commit fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(
            CONTROL_AUTH.os, "fsync", side_effect=fail_first_commit_fsync
        ):
            with self.assertRaises(CONTROL_AUTH.ControlAuthError) as raised:
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(injected)
        self.assertIs(type(raised.exception), CONTROL_AUTH.ControlAuthError)
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual(before.st_ino, self.auth_file.stat().st_ino)
        self.assertEqual([], self._temporary_entries())

    def test_precommit_candidate_file_fsync_failure_preserves_original(self):
        self._write()
        real_fsync = os.fsync
        injected = False
        cleanup_synced = False

        def fail_candidate_fsync(descriptor):
            nonlocal injected, cleanup_synced
            metadata = os.fstat(descriptor)
            if injected and stat.S_ISDIR(metadata.st_mode):
                cleanup_synced = True
            if not injected and stat.S_ISREG(metadata.st_mode):
                position = os.lseek(descriptor, 0, os.SEEK_CUR)
                os.lseek(descriptor, 0, os.SEEK_SET)
                data = os.read(descriptor, CONTROL_AUTH.MAX_AUTH_FILE_SIZE + 1)
                os.lseek(descriptor, position, os.SEEK_SET)
                if data == ROTATED_NVIS:
                    injected = True
                    raise OSError("injected candidate fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(CONTROL_AUTH.os, "fsync", side_effect=fail_candidate_fsync):
            with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(injected)
        self.assertTrue(cleanup_synced)
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual([], self._temporary_entries())

    def test_precommit_recovery_directory_fsync_failure_preserves_original(self):
        self._write()
        before = self.auth_file.stat()
        real_fsync = os.fsync
        injected = False

        def fail_recovery_fsync(descriptor):
            nonlocal injected
            metadata = os.fstat(descriptor)
            if (
                not injected
                and stat.S_ISDIR(metadata.st_mode)
                and list(self.auth_dir.glob(".control-users.recovery.*"))
                and self.auth_file.read_bytes() == FACTORY_BYTES
            ):
                injected = True
                raise OSError("injected recovery fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(CONTROL_AUTH.os, "fsync", side_effect=fail_recovery_fsync):
            with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(injected)
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())
        self.assertEqual(before.st_ino, self.auth_file.stat().st_ino)
        self.assertEqual([], self._temporary_entries())

    def test_postcommit_cleanup_fsync_has_distinct_committed_state(self):
        self._write()
        real_fsync = os.fsync
        injected = False

        def fail_cleanup_fsync(descriptor):
            nonlocal injected
            metadata = os.fstat(descriptor)
            if (
                not injected
                and stat.S_ISDIR(metadata.st_mode)
                and self.auth_file.exists()
                and self.auth_file.read_bytes() == ROTATED_NVIS
                and not list(self.auth_dir.glob(".control-users.recovery.*"))
            ):
                injected = True
                raise OSError("injected cleanup fsync failure")
            return real_fsync(descriptor)

        with mock.patch.object(CONTROL_AUTH.os, "fsync", side_effect=fail_cleanup_fsync):
            with self.assertRaises(CONTROL_AUTH.ControlAuthCommittedError) as raised:
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(injected)
        self.assertTrue(raised.exception.committed)
        self.assertTrue(raised.exception.durable)
        self.assertTrue(raised.exception.valid)
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())

    def test_postcommit_cleanup_unlink_failure_has_distinct_committed_state(self):
        self._write()
        real_unlink = os.unlink
        injected = False

        def fail_recovery_unlink(path, **kwargs):
            nonlocal injected
            if not injected and str(path).startswith(".control-users.recovery."):
                injected = True
                raise OSError("injected recovery cleanup failure")
            return real_unlink(path, **kwargs)

        with mock.patch.object(CONTROL_AUTH.os, "unlink", side_effect=fail_recovery_unlink):
            with self.assertRaises(CONTROL_AUTH.ControlAuthCommittedError) as raised:
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(injected)
        self.assertTrue(raised.exception.committed)
        self.assertTrue(raised.exception.durable)
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())
        recoveries = list(self.auth_dir.glob(".control-users.recovery.*"))
        self.assertEqual(1, len(recoveries))
        self.assertEqual(FACTORY_BYTES, recoveries[0].read_bytes())

    def test_final_postcommit_verification_failure_is_not_ordinary_failure(self):
        self._write()
        real_open_and_read = CONTROL_AUTH._open_and_read
        target_reads = 0

        def fail_final_read(directory_descriptor, filename, **kwargs):
            nonlocal target_reads
            if filename == self.auth_file.name:
                target_reads += 1
                if target_reads == 4:
                    raise CONTROL_AUTH.ControlAuthError(
                        "injected final verification failure"
                    )
            return real_open_and_read(directory_descriptor, filename, **kwargs)

        with mock.patch.object(
            CONTROL_AUTH, "_open_and_read", side_effect=fail_final_read
        ):
            with self.assertRaises(CONTROL_AUTH.ControlAuthCommittedError) as raised:
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(raised.exception.committed)
        self.assertTrue(raised.exception.durable)
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())

    def test_unresolved_recovery_evidence_blocks_mutations_but_not_status(self):
        self._write(ROTATED_NVIS)
        recovery = self.auth_dir / ".control-users.recovery.operator-evidence"
        recovery.write_bytes(FACTORY_BYTES)
        recovery.chmod(0o640)
        before = recovery.stat()

        self.assertTrue(
            CONTROL_AUTH.status_auth_file(self.auth_file, **self._kwargs())["valid"]
        )
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "recovery"):
            CONTROL_AUTH.ensure_auth_file(self.auth_file, **self._kwargs())
        with self.assertRaisesRegex(CONTROL_AUTH.ControlAuthError, "recovery"):
            CONTROL_AUTH.rotate_auth_file(
                self.auth_file,
                user="cumulus",
                password_reader=lambda _prompt: self.fail(
                    "recovery evidence must block before prompting"
                ),
                runner=lambda *_args, **_kwargs: self.fail(
                    "recovery evidence must block before htpasswd"
                ),
                **self._kwargs(),
            )
        after = recovery.stat()
        self.assertEqual(before.st_ino, after.st_ino)
        self.assertEqual(FACTORY_BYTES, recovery.read_bytes())

    def test_password_prompts_occur_without_an_exclusive_directory_lock(self):
        self._write()
        attempts = []

        def password_reader(_prompt):
            descriptor = os.open(self.auth_dir, os.O_RDONLY)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                attempts.append(True)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
            return "A-long!secure7"

        CONTROL_AUTH.rotate_auth_file(
            self.auth_file,
            user="nvis",
            password_reader=password_reader,
            runner=self._fake_runner(ROTATED_NVIS, []),
            **self._kwargs(),
        )
        self.assertEqual([True, True], attempts)

    def test_failed_rollback_retains_identity_bound_recovery(self):
        self._write()
        original = self.auth_file.stat()
        real_fsync = os.fsync
        real_replace = os.replace
        fsync_injected = False

        def fail_commit_fsync(descriptor):
            nonlocal fsync_injected
            metadata = os.fstat(descriptor)
            if (
                not fsync_injected
                and stat.S_ISDIR(metadata.st_mode)
                and self.auth_file.read_bytes() == ROTATED_NVIS
            ):
                fsync_injected = True
                raise OSError("injected commit fsync failure")
            return real_fsync(descriptor)

        def fail_rollback_replace(src, dst, **kwargs):
            if str(src).startswith(".control-users.recovery."):
                raise OSError("injected rollback failure")
            return real_replace(src, dst, **kwargs)

        with mock.patch.object(
            CONTROL_AUTH.os, "fsync", side_effect=fail_commit_fsync
        ), mock.patch.object(
            CONTROL_AUTH.os, "replace", side_effect=fail_rollback_replace
        ):
            with self.assertRaises(CONTROL_AUTH.ControlAuthCommittedError) as raised:
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )

        self.assertTrue(fsync_injected)
        recovery_name = raised.exception.recovery_name
        self.assertIsNotNone(recovery_name)
        self.assertEqual(Path(recovery_name).name, recovery_name)
        recovery = self.auth_dir / recovery_name
        self.assertTrue(recovery.exists())
        metadata = recovery.stat()
        self.assertEqual(original.st_ino, metadata.st_ino)
        self.assertEqual(1, metadata.st_nlink)
        self.assertEqual(0o640, stat.S_IMODE(metadata.st_mode))
        self.assertEqual(self.uid, metadata.st_uid)
        self.assertEqual(self.gid, metadata.st_gid)
        self.assertEqual(FACTORY_BYTES, recovery.read_bytes())
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())

    def test_postpublication_target_swap_is_detected_without_deleting_foreign(self):
        self._write()
        real_replace = os.replace
        injected = False

        def swap_after_publish(src, dst, **kwargs):
            nonlocal injected
            result = real_replace(src, dst, **kwargs)
            if (
                not injected
                and dst == self.auth_file.name
                and not str(src).startswith(".control-users.recovery.")
            ):
                injected = True
                foreign = self.root / "foreign-current"
                foreign.write_bytes(ROTATED_CUMULUS)
                foreign.chmod(0o640)
                real_replace(foreign, self.auth_file)
            return result

        with mock.patch.object(CONTROL_AUTH.os, "replace", side_effect=swap_after_publish):
            with self.assertRaises(CONTROL_AUTH.ControlAuthIndeterminateError):
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
        self.assertTrue(injected)
        self.assertEqual(ROTATED_CUMULUS, self.auth_file.read_bytes())

    def test_shared_readers_complete_while_writer_waits_for_exclusive_lock(self):
        self._write()
        real_open_and_read = CONTROL_AUTH._open_and_read
        real_replace = os.replace
        held_reader_entered = threading.Event()
        release_reader = threading.Event()
        second_reader_done = threading.Event()
        writer_published = threading.Event()
        failures = []

        def blocking_read(directory_descriptor, filename, **kwargs):
            snapshot = real_open_and_read(directory_descriptor, filename, **kwargs)
            if threading.current_thread().name == "held-reader":
                held_reader_entered.set()
                if not release_reader.wait(timeout=4):
                    raise AssertionError("reader release timeout")
            return snapshot

        def publish(src, dst, **kwargs):
            if dst == self.auth_file.name and not str(src).startswith(
                ".control-users.recovery."
            ):
                writer_published.set()
            return real_replace(src, dst, **kwargs)

        def reader_one():
            try:
                CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
            except Exception as exc:
                failures.append(exc)

        def reader_two():
            try:
                CONTROL_AUTH.validate_auth_file(self.auth_file, **self._kwargs())
                second_reader_done.set()
            except Exception as exc:
                failures.append(exc)

        def writer():
            try:
                CONTROL_AUTH.rotate_auth_file(
                    self.auth_file,
                    user="nvis",
                    password_reader=lambda _prompt: "A-long!secure7",
                    runner=self._fake_runner(ROTATED_NVIS, []),
                    **self._kwargs(),
                )
            except Exception as exc:
                failures.append(exc)

        with mock.patch.object(
            CONTROL_AUTH, "_open_and_read", side_effect=blocking_read
        ), mock.patch.object(CONTROL_AUTH.os, "replace", side_effect=publish):
            first = threading.Thread(target=reader_one, name="held-reader")
            second = threading.Thread(target=reader_two, name="second-reader")
            writing = threading.Thread(target=writer, name="writer")
            first.start()
            self.assertTrue(held_reader_entered.wait(timeout=2))
            second.start()
            self.assertTrue(second_reader_done.wait(timeout=2))
            writing.start()
            published_while_reader_held = writer_published.wait(timeout=0.25)
            release_reader.set()
            first.join(timeout=3)
            second.join(timeout=3)
            writing.join(timeout=5)

        self.assertFalse(published_while_reader_held)
        self.assertEqual([], failures)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertFalse(writing.is_alive())
        self.assertTrue(writer_published.is_set())

    def test_cli_reports_committed_and_indeterminate_without_traceback(self):
        cases = (
            (
                CONTROL_AUTH.ControlAuthCommittedError(
                    "publication durability failed",
                    durable=False,
                    valid=True,
                    recovery_name=".control-users.recovery.safe",
                ),
                2,
                "committed=true",
            ),
            (
                CONTROL_AUTH.ControlAuthIndeterminateError(
                    "publication identity became uncertain",
                    committed=None,
                    durable=None,
                    valid=None,
                    recovery_name=".control-users.recovery.safe",
                ),
                3,
                "committed=unknown",
            ),
        )
        for exception, expected_code, expected_state in cases:
            with self.subTest(expected_code=expected_code):
                output = io.StringIO()
                errors = io.StringIO()
                with mock.patch.object(
                    CONTROL_AUTH, "rotate_auth_file", side_effect=exception
                ), redirect_stdout(output), redirect_stderr(errors):
                    code = CONTROL_AUTH.main(
                        ["rotate", "--user", "nvis"],
                        auth_path=self.auth_file,
                        required_uid=self.uid,
                        required_gid=self.gid,
                        password_reader=lambda _prompt: self.fail("must not prompt"),
                    )
                self.assertEqual(expected_code, code)
                self.assertEqual("", output.getvalue())
                diagnostic = errors.getvalue()
                self.assertIn(expected_state, diagnostic)
                self.assertIn("do not blindly retry", diagnostic)
                self.assertIn("validate/status", diagnostic)
                self.assertNotIn("Traceback", diagnostic)
                self.assertLess(len(diagnostic), 640)

    def test_password_sentinel_is_confined_to_subprocess_stdin(self):
        self._write()
        sentinel = "Independent-Sentinel!8042"
        calls = []
        output = io.StringIO()
        errors = io.StringIO()

        def runner(argv, **kwargs):
            calls.append((tuple(argv), dict(kwargs)))
            return _Completed(stdout=ROTATED_NVIS.splitlines(keepends=True)[0])

        with redirect_stdout(output), redirect_stderr(errors):
            result = CONTROL_AUTH.rotate_auth_file(
                self.auth_file,
                user="nvis",
                password_reader=lambda _prompt: sentinel,
                runner=runner,
                **self._kwargs(),
            )
        self.assertTrue(result["valid"])
        self.assertEqual(1, len(calls))
        argv, options = calls[0]
        self.assertEqual((sentinel + "\n").encode("ascii"), options["input"])
        forbidden_channels = (
            repr(argv),
            repr(options["env"]),
            output.getvalue(),
            errors.getvalue(),
            SCRIPT.read_text(encoding="utf-8"),
        )
        for channel in forbidden_channels:
            self.assertNotIn(sentinel, channel)
        for entry in self.auth_dir.iterdir():
            if entry.is_file():
                self.assertNotIn(sentinel.encode("ascii"), entry.read_bytes())

        self._write()

        def hostile_failure(*_args, **_kwargs):
            raise OSError(f"transport exposed {sentinel}")

        with self.assertRaises(CONTROL_AUTH.ControlAuthError) as raised:
            CONTROL_AUTH.rotate_auth_file(
                self.auth_file,
                user="nvis",
                password_reader=lambda _prompt: sentinel,
                runner=hostile_failure,
                **self._kwargs(),
            )
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())

    def test_htpasswd_stdout_is_one_bounded_selected_user_record(self):
        self._write()
        invalid_outputs = (
            b"x" * 1024,
            ROTATED_NVIS.splitlines(keepends=True)[0]
            + ROTATED_CUMULUS.splitlines(keepends=True)[1],
            ROTATED_NVIS.splitlines()[0],
            ROTATED_CUMULUS.splitlines(keepends=True)[1],
        )
        for index, generated in enumerate(invalid_outputs):
            with self.subTest(index=index):
                self._write()
                with self.assertRaises(CONTROL_AUTH.ControlAuthError):
                    CONTROL_AUTH.rotate_auth_file(
                        self.auth_file,
                        user="nvis",
                        password_reader=lambda _prompt: "A-long!secure7",
                        runner=lambda *_args, **_kwargs: _Completed(stdout=generated),
                        **self._kwargs(),
                    )
                self.assertEqual(FACTORY_BYTES, self.auth_file.read_bytes())

    def test_htpasswd_single_record_accepts_platform_trailing_blank_line(self):
        self._write()
        generated = ROTATED_NVIS.splitlines(keepends=True)[0] + b"\n"
        result = CONTROL_AUTH.rotate_auth_file(
            self.auth_file,
            user="nvis",
            password_reader=lambda _prompt: "A-long!secure7",
            runner=lambda *_args, **_kwargs: _Completed(stdout=generated),
            **self._kwargs(),
        )
        self.assertEqual(
            {"valid": True, "factory_records_active": False}, result
        )
        self.assertEqual(ROTATED_NVIS, self.auth_file.read_bytes())

    def test_status_cli_is_exact_machine_json_and_fails_closed(self):
        output = io.StringIO()
        errors = io.StringIO()
        self._write()
        with redirect_stdout(output), redirect_stderr(errors):
            code = CONTROL_AUTH.main(
                ["status"],
                auth_path=self.auth_file,
                required_uid=self.uid,
                required_gid=self.gid,
            )
        self.assertEqual(0, code)
        self.assertEqual(
            '{"factory_records_active":true,"valid":true}\n',
            output.getvalue(),
        )
        self.assertEqual("", errors.getvalue())

        self.auth_file.write_bytes(b"malformed\n")
        self.auth_file.chmod(0o640)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = CONTROL_AUTH.main(
                ["status"],
                auth_path=self.auth_file,
                required_uid=self.uid,
                required_gid=self.gid,
            )
        self.assertNotEqual(0, code)
        self.assertEqual(
            '{"factory_records_active":false,"valid":false}\n',
            output.getvalue(),
        )

    def test_factory_status_false_is_only_a_byte_inequality_statement(self):
        self._write(ROTATED_NVIS)
        status = CONTROL_AUTH.status_auth_file(self.auth_file, **self._kwargs())
        self.assertEqual({"valid": True, "factory_records_active": False}, status)
        self.assertNotIn("rotated", status)

    def test_production_source_contains_no_forbidden_factory_plaintext(self):
        source = SCRIPT.read_text(encoding="utf-8")
        forbidden = "nvi" + "dia"
        records = CONTROL_AUTH.FACTORY_RECORDS.splitlines()
        self.assertEqual(2, len(records))
        self.assertEqual(("nvis", "cumulus"), CONTROL_AUTH.USERS)
        self.assertTrue(all(":" not in username for username in CONTROL_AUTH.USERS))
        self.assertEqual(
            list(CONTROL_AUTH.USERS),
            [record.split(b":", 1)[0].decode("ascii") for record in records],
        )
        for record in records:
            _username, verifier = record.split(b":", 1)
            self.assertRegex(
                verifier.decode("ascii"),
                r"^\$2y\$12\$[./A-Za-z0-9]{53}$",
            )
        self.assertNotIn(forbidden, source.casefold())
        self.assertEqual(FACTORY_BYTES, CONTROL_AUTH.FACTORY_RECORDS)
        self.assertNotIn(forbidden.encode("ascii"), CONTROL_AUTH.FACTORY_RECORDS)
        self.assertIn(b"cumulus:", CONTROL_AUTH.FACTORY_RECORDS)


if __name__ == "__main__":
    unittest.main()
