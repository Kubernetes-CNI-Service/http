#!/usr/bin/env python3
"""Direct and workflow contracts for the Docker management SSH identity.

The fixtures create disposable Ed25519 keys below a temporary directory.  No
Docker daemon, SSH connection, real account home, or persistent host path is
touched, and expected migration outcomes are specified independently here.
"""

from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest import mock

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows is outside the supported test platforms.
    fcntl = None


ROOT = Path(__file__).resolve().parents[1]
DOCKER_ROOT = ROOT / "infra/docker"
HELPER_PATH = DOCKER_ROOT / "management_ssh_key.py"
LOAD_PATH = ROOT / "DAY0-Prepare/11-load.py"


def deploy_action_body(source: str, action: str) -> str:
    """Return one final top-level deploy action arm without substring guessing."""
    final_case = source.rsplit('case "$action" in', 1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z0-9|_-]+)\)\n", final_case))
    for index, match in enumerate(matches):
        labels = match.group(1).split("|")
        if action not in labels:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(final_case)
        return final_case[match.end():end]
    raise AssertionError(f"missing deploy action arm: {action}")


def load_module(path: Path, name: str):
    if not path.is_file():
        raise AssertionError(f"missing production script: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load production script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def install_nonlinux_held_link_test_oracle(module) -> None:
    """Exercise state semantics on Darwin without inventing a production fallback."""
    if sys.platform.startswith("linux"):
        return
    if fcntl is None or not hasattr(fcntl, "F_GETPATH"):
        raise AssertionError("non-Linux direct test needs F_GETPATH for its narrow link oracle")

    candidate_paths: dict[int, str] = {}

    def open_candidate(_directory_descriptor: int, mode: int) -> tuple[int, int]:
        descriptor, candidate_path = tempfile.mkstemp(prefix="held-key-", dir="/tmp")
        os.fchmod(descriptor, mode)
        candidate_paths[descriptor] = candidate_path
        return descriptor, 1

    def held_link(candidate_descriptor: int, directory_descriptor: int, target_name: str) -> None:
        candidate_name = candidate_paths[candidate_descriptor]
        raw = fcntl.fcntl(candidate_descriptor, fcntl.F_GETPATH, b"\0" * 1024)
        candidate_path = os.fsdecode(raw.split(b"\0", 1)[0])
        held = os.fstat(candidate_descriptor)
        named = os.lstat(candidate_path)
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
            raise module.ManagementKeyError("test oracle refused a rebound candidate")
        os.link(candidate_path, target_name, dst_dir_fd=directory_descriptor)
        os.unlink(candidate_name)

    def close_candidate(candidate_descriptor: int) -> None:
        candidate_name = candidate_paths.pop(candidate_descriptor, None)
        if candidate_name is not None:
            try:
                named = os.lstat(candidate_name)
            except OSError:
                named = None
            if named is not None:
                held = os.fstat(candidate_descriptor)
                if (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino):
                    os.unlink(candidate_name)
        os.close(candidate_descriptor)

    module._open_anonymous_candidate = open_candidate
    module._publish_held_inode = held_link
    module._close_anonymous_candidate = close_candidate


def fingerprint(public_bytes: bytes) -> str:
    """Compute the independently specified OpenSSH SHA256 fingerprint."""
    fields = public_bytes.strip().split()
    if len(fields) < 2 or fields[0] != b"ssh-ed25519":
        raise AssertionError("fixture public key is not ssh-ed25519")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError as exc:
        raise AssertionError("fixture public key blob is not base64") from exc
    digest = base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=")
    return "SHA256:" + digest.decode("ascii")


class DisposableKeyFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.keygen = Path("/usr/bin/ssh-keygen")
        if not self.keygen.is_file():
            raise AssertionError("OpenSSH ssh-keygen is required by this contract")

    def generate(
        self, directory: Path, *, name: str = "id_ed25519",
        algorithm: str = "ed25519", passphrase: str = "",
        comment: str = "contract-fixture",
    ) -> tuple[bytes, bytes]:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        private = directory / name
        result = subprocess.run(
            [
                os.fspath(self.keygen), "-q", "-t", algorithm,
                "-N", passphrase, "-C", comment, "-f", os.fspath(private),
            ],
            env={"HOME": os.fspath(self.root), "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return private.read_bytes(), private.with_suffix(".pub").read_bytes()

    @staticmethod
    def pair(directory: Path) -> tuple[Path, Path]:
        return directory / "id_ed25519", directory / "id_ed25519.pub"


class DockerManagementSshKeyDirectTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keep AF_UNIX defect fixtures below Darwin's short pathname limit and
        # resolve the platform /var and /tmp aliases before exercising the
        # canonical component-walk contract.
        self.temporary = tempfile.TemporaryDirectory(prefix="hk-", dir="/tmp")
        self.root = Path(self.temporary.name).resolve()
        self.fixture = DisposableKeyFixture(self.root)
        self.host_home = self.root / "host-home"
        self.service = self.root / "service-ssh"
        self.host_home.mkdir(mode=0o700)
        self.host_home.chmod(0o700)
        self.uid = os.getuid()
        # Darwin's sticky /private/tmp intentionally gives new children group
        # 0; bind the expected identity to the actual private fixture root.
        self.gid = self.root.stat().st_gid

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def helper(self):
        helper = load_module(
            HELPER_PATH,
            f"docker_management_ssh_key_{id(self)}_{self._testMethodName}",
        )
        install_nonlinux_held_link_test_oracle(helper)
        return helper

    def synchronize(self):
        return self.helper().synchronize_management_key(
            **self.operation_arguments(),
        )

    def operation_arguments(self, **overrides):
        arguments = {
            "host_home": self.host_home,
            "service_directory": self.service,
            "host_uid": self.uid,
            "host_gid": self.gid,
            "service_uid": self.uid,
            "service_gid": self.gid,
            "authority_boundary": self.root,
            "keygen": self.fixture.keygen,
        }
        arguments.update(overrides)
        return arguments

    @staticmethod
    def snapshot(root: Path) -> dict[str, tuple[object, ...]]:
        result: dict[str, tuple[object, ...]] = {}
        for path in (root, *sorted(root.rglob("*"))):
            relative = "." if path == root else path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                kind = "symlink"
                content: bytes | str | None = os.readlink(path)
            elif stat.S_ISDIR(metadata.st_mode):
                kind = "directory"
                content = None
            elif stat.S_ISREG(metadata.st_mode):
                kind = "file"
                content = path.read_bytes()
            else:
                kind = "special"
                content = None
            result[relative] = (
                kind,
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
                getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
                content,
            )
        return result

    def assert_pair_bytes(
        self, directory: Path, expected: tuple[bytes, bytes],
    ) -> None:
        private, public = self.fixture.pair(directory)
        self.assertEqual(expected[0], private.read_bytes())
        self.assertEqual(expected[1], public.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(private.stat().st_mode))
        self.assertEqual(0o644, stat.S_IMODE(public.stat().st_mode))
        self.assertEqual(1, private.stat().st_nlink)
        self.assertEqual(1, public.stat().st_nlink)

    def test_cli_has_only_fixed_root_reconcile_and_check_subcommands(self) -> None:
        helper = self.helper()
        parser = helper.parser()
        self.assertEqual("reconcile", parser.parse_args(["reconcile"]).action)
        self.assertEqual("check", parser.parse_args(["check"]).action)
        with self.assertRaises(SystemExit):
            parser.parse_args([])
        for forbidden in (
            "--ssh-key-user", "--identity", "--host-home", "--service-directory",
            "--private-key", "--root", "--home",
        ):
            with self.subTest(option=forbidden), self.assertRaises(SystemExit):
                parser.parse_args(["reconcile", forbidden, "/tmp/operator-controlled"])
        self.assertEqual(Path("/root/.ssh"), helper.HOST_SSH_DIRECTORY)
        self.assertEqual(
            Path("/var/lib/http-ztp-container/ssh"), helper.SERVICE_SSH_DIRECTORY,
        )
        source = HELPER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "SUDO_USER", "SUDO_UID", "SUDO_GID", "SSH_KEY_USER",
            "os.environ", "os.getenv", "expanduser", "Path.home",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_cli_emits_one_canonical_bounded_json_line_and_empty_stderr(self) -> None:
        helper = self.helper()
        result = {
            "action": "copied-host-to-service",
            "valid": True,
            "fingerprint": "SHA256:" + "A" * 43,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(helper, "synchronize_management_key", return_value=result), mock.patch.object(
            helper, "_production_options", return_value=self.operation_arguments(),
        ):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(0, helper.main(["reconcile"]))
        self.assertEqual(
            '{"action":"copied-host-to-service","fingerprint":"SHA256:'
            + "A" * 43
            + '","valid":true}\n',
            stdout.getvalue(),
        )
        self.assertEqual("", stderr.getvalue())
        self.assertLessEqual(len(stdout.getvalue().encode("ascii")), 256)

    def test_full_named_host_service_three_by_three_matrix(self) -> None:
        expected_success = {
            ("ABSENT", "ABSENT"): "generated-host-and-copied-service",
            ("ABSENT", "VALID"): "copied-service-to-host",
            ("VALID", "ABSENT"): "copied-host-to-service",
            ("VALID", "VALID"): "preserved-identical",
        }
        invalid_combinations = {
            ("INVALID", "ABSENT"),
            ("INVALID", "VALID"),
            ("INVALID", "INVALID"),
            ("VALID", "INVALID"),
            ("ABSENT", "INVALID"),
        }
        self.assertEqual(9, len(expected_success) + len(invalid_combinations))
        for host_state in ("ABSENT", "VALID", "INVALID"):
            for service_state in ("ABSENT", "VALID", "INVALID"):
                with self.subTest(host=host_state, service=service_state), tempfile.TemporaryDirectory(
                    prefix="http-key-matrix-", dir=self.root,
                ) as case_directory:
                    case = Path(case_directory)
                    host_home = case / "host"
                    service = case / "service"
                    host_home.mkdir(mode=0o700)
                    for sentinel in ("project", "container", "activation"):
                        path = case / sentinel
                        path.mkdir(mode=0o700)
                        (path / "state").write_bytes((sentinel + "-unchanged").encode("ascii"))
                    valid_bytes = None
                    if host_state != "ABSENT":
                        valid_bytes = self.fixture.generate(
                            host_home / ".ssh",
                            algorithm="ed25519" if host_state == "VALID" else "rsa",
                        )
                    if service_state != "ABSENT":
                        if service_state == "VALID" and host_state == "VALID":
                            assert valid_bytes is not None
                            service.mkdir(mode=0o700)
                            for target, data, mode in zip(
                                self.fixture.pair(service), valid_bytes, (0o600, 0o644),
                            ):
                                target.write_bytes(data)
                                target.chmod(mode)
                        else:
                            self.fixture.generate(
                                service,
                                algorithm="ed25519" if service_state == "VALID" else "rsa",
                            )
                    before = self.snapshot(case)
                    helper = self.helper()
                    arguments = {
                        "host_home": host_home,
                        "service_directory": service,
                        "host_uid": self.uid,
                        "host_gid": self.gid,
                        "service_uid": self.uid,
                        "service_gid": self.gid,
                        "authority_boundary": case,
                        "keygen": self.fixture.keygen,
                    }
                    combination = (host_state, service_state)
                    if combination in invalid_combinations:
                        for attempt in (1, 2):
                            with self.subTest(attempt=attempt), self.assertRaises(
                                helper.ManagementKeyError,
                            ):
                                helper.synchronize_management_key(**arguments)
                            self.assertEqual(before, self.snapshot(case))
                        self.assertEqual(before, self.snapshot(case))
                    else:
                        result = helper.synchronize_management_key(**arguments)
                        self.assertEqual(expected_success[combination], result["action"])
                        self.assertIs(True, result["valid"])
                        self.assertRegex(result["fingerprint"], r"\ASHA256:[A-Za-z0-9+/]{43}\Z")
                        for sentinel in ("project", "container", "activation"):
                            self.assertEqual(
                                (sentinel + "-unchanged").encode("ascii"),
                                (case / sentinel / "state").read_bytes(),
                            )

    def test_valid_host_pair_is_copied_byte_for_byte_to_empty_service(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh", comment="host-source")
        result = self.synchronize()
        self.assertEqual("copied-host-to-service", result["action"])
        self.assertEqual(fingerprint(expected[1]), result["fingerprint"])
        self.assert_pair_bytes(self.host_home / ".ssh", expected)
        self.assert_pair_bytes(self.service, expected)

    def test_valid_service_pair_is_copied_to_absent_host_and_preserved(self) -> None:
        expected = self.fixture.generate(self.service, comment="trusted-service")
        service_private, service_public = self.fixture.pair(self.service)
        before_identity = (
            service_private.stat().st_ino, service_private.stat().st_mtime_ns,
            service_public.stat().st_ino, service_public.stat().st_mtime_ns,
        )
        result = self.synchronize()
        self.assertEqual("copied-service-to-host", result["action"])
        self.assertEqual(before_identity, (
            service_private.stat().st_ino, service_private.stat().st_mtime_ns,
            service_public.stat().st_ino, service_public.stat().st_mtime_ns,
        ))
        self.assert_pair_bytes(self.service, expected)
        self.assert_pair_bytes(self.host_home / ".ssh", expected)

    def test_both_absent_generates_at_host_then_copies_to_service(self) -> None:
        result = self.synchronize()
        self.assertEqual("generated-host-and-copied-service", result["action"])
        host_pair = tuple(
            path.read_bytes() for path in self.fixture.pair(self.host_home / ".ssh")
        )
        self.assert_pair_bytes(self.host_home / ".ssh", host_pair)
        self.assert_pair_bytes(self.service, host_pair)
        self.assertTrue(str(result["fingerprint"]).startswith("SHA256:"))
        self.assertEqual(
            [], list((self.host_home / ".ssh").glob(".management-key-stage-*")),
        )

    def test_byte_identical_pairs_are_a_true_noop(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        self.service.mkdir(mode=0o700)
        self.service.chmod(0o700)
        for target, data, mode in zip(
            self.fixture.pair(self.service), expected, (0o600, 0o644),
        ):
            target.write_bytes(data)
            target.chmod(mode)
        paths = (*self.fixture.pair(self.host_home / ".ssh"), *self.fixture.pair(self.service))
        before = [(item.stat().st_ino, item.stat().st_mtime_ns) for item in paths]
        result = self.synchronize()
        self.assertEqual("preserved-identical", result["action"])
        self.assertEqual(before, [(item.stat().st_ino, item.stat().st_mtime_ns) for item in paths])

    def test_comment_difference_is_identity_equal_and_preserves_every_inode(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh", comment="host-comment")
        service_private = self.service / "id_ed25519"
        service_public = self.service / "id_ed25519.pub"
        self.service.mkdir(mode=0o700)
        service_private.write_bytes(expected[0])
        service_private.chmod(0o600)
        public_fields = expected[1].strip().split()
        service_public.write_bytes(b" ".join(public_fields[:2]) + b" service-comment\n")
        service_public.chmod(0o644)
        paths = (
            *self.fixture.pair(self.host_home / ".ssh"),
            *self.fixture.pair(self.service),
        )
        before = [
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in paths
        ]
        result = self.synchronize()
        self.assertEqual("preserved-identical", result["action"])
        self.assertEqual(before, [
            (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            for path in paths
        ])

    def test_unrelated_ssh_children_and_unowned_hidden_files_are_never_touched(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        host_ssh = self.host_home / ".ssh"
        unrelated = {
            host_ssh / "known_hosts": b"switch.example ssh-ed25519 AAAA\n",
            host_ssh / "config": b"Host *\n  BatchMode yes\n",
            host_ssh / "authorized_keys": b"ssh-ed25519 AAAA unrelated\n",
            host_ssh / "id_other": b"not-the-managed-key\n",
            host_ssh / ".management-key-unowned": b"must-survive\n",
        }
        for path, payload in unrelated.items():
            path.write_bytes(payload)
            path.chmod(0o600)
        before = self.snapshot(host_ssh)
        outcome = self.synchronize()
        self.assertEqual("copied-host-to-service", outcome["action"])
        after = self.snapshot(host_ssh)
        self.assertEqual(before, after)
        self.assert_pair_bytes(self.service, expected)
        self.assertEqual(
            {"id_ed25519", "id_ed25519.pub"},
            {path.name for path in self.service.iterdir()},
        )

    def test_read_only_check_reports_five_safe_states_and_never_writes(self) -> None:
        cases = (
            ("ABSENT", "ABSENT", "generation-required", False),
            ("VALID", "ABSENT", "copy-host-to-service-required", False),
            ("ABSENT", "VALID", "copy-service-to-host-required", False),
            ("VALID", "VALID", "preserved-identical", True),
        )
        for host_state, service_state, action, valid in cases:
            with self.subTest(host=host_state, service=service_state), tempfile.TemporaryDirectory(
                prefix="http-key-check-", dir=self.root,
            ) as case_directory:
                case = Path(case_directory)
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                expected = None
                if host_state == "VALID":
                    expected = self.fixture.generate(host_home / ".ssh")
                if service_state == "VALID":
                    if expected is None:
                        self.fixture.generate(service)
                    else:
                        service.mkdir(mode=0o700)
                        for target, data, mode in zip(
                            self.fixture.pair(service), expected, (0o600, 0o644),
                        ):
                            target.write_bytes(data)
                            target.chmod(mode)
                before = self.snapshot(case)
                result = self.helper().check_management_key(
                    host_home=host_home,
                    service_directory=service,
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=case,
                    keygen=self.fixture.keygen,
                )
                self.assertEqual(action, result["action"])
                self.assertIs(valid, result["valid"])
                self.assertEqual(before, self.snapshot(case))

        self.fixture.generate(self.host_home / ".ssh", comment="host-conflict")
        self.fixture.generate(self.service, comment="service-conflict")
        before = self.snapshot(self.root)
        helper = self.helper()
        with self.assertRaises(helper.ManagementKeyConflict):
            helper.check_management_key(
                host_home=self.host_home,
                service_directory=self.service,
                host_uid=self.uid,
                host_gid=self.gid,
                service_uid=self.uid,
                service_gid=self.gid,
                authority_boundary=self.root,
                keygen=self.fixture.keygen,
            )
        self.assertEqual(before, self.snapshot(self.root))

    def test_two_different_valid_pairs_fail_with_only_bounded_fingerprints(self) -> None:
        host = self.fixture.generate(self.host_home / ".ssh", comment="host-secret")
        service = self.fixture.generate(self.service, comment="service-secret")
        before = self.snapshot(self.root)
        helper = self.helper()
        with self.assertRaises(helper.ManagementKeyConflict) as caught:
            helper.synchronize_management_key(
                host_home=self.host_home,
                service_directory=self.service,
                host_uid=self.uid,
                host_gid=self.gid,
                service_uid=self.uid,
                service_gid=self.gid,
                authority_boundary=self.root,
                keygen=self.fixture.keygen,
            )
        message = str(caught.exception)
        self.assertIn(f"host_fingerprint={fingerprint(host[1])}", message)
        self.assertIn(f"service_fingerprint={fingerprint(service[1])}", message)
        self.assertIn("explicit", message.casefold())
        self.assertLessEqual(len(message.encode("utf-8")), 512)
        self.assertNotIn(host[0].decode("ascii"), message)
        self.assertNotIn(service[0].decode("ascii"), message)
        self.assertEqual(before, self.snapshot(self.root))

    def test_half_pairs_never_trigger_generation_or_overwrite(self) -> None:
        for side in ("host", "service"):
            for survivor in ("private", "public"):
                with self.subTest(side=side, survivor=survivor):
                    with tempfile.TemporaryDirectory(
                        prefix="http-key-half-", dir=self.root,
                    ) as case_directory:
                        case = Path(case_directory)
                        host_home = case / "host"
                        service = case / "service"
                        host_home.mkdir(mode=0o700)
                        directory = host_home / ".ssh" if side == "host" else service
                        generated = self.fixture.generate(directory)
                        private, public = self.fixture.pair(directory)
                        (public if survivor == "private" else private).unlink()
                        before = self.snapshot(case)
                        helper = self.helper()
                        with self.assertRaisesRegex(
                            helper.ManagementKeyError, "half|incomplete|pair",
                        ):
                            helper.synchronize_management_key(
                                host_home=host_home,
                                service_directory=service,
                                host_uid=self.uid,
                                host_gid=self.gid,
                                service_uid=self.uid,
                                service_gid=self.gid,
                                authority_boundary=case,
                                keygen=self.fixture.keygen,
                            )
                        self.assertTrue(any(generated))
                        self.assertEqual(before, self.snapshot(case))

    def test_unsafe_symlink_hardlink_permissions_and_mismatch_fail_closed(self) -> None:
        helper = self.helper()
        cases = []
        host_ssh = self.host_home / ".ssh"
        self.fixture.generate(host_ssh)
        private, public = self.fixture.pair(host_ssh)

        private.chmod(0o640)
        cases.append(("private permissions", "mode|permission"))

        for label, pattern in cases:
            with self.subTest(case=label):
                before = self.snapshot(self.root)
                with self.assertRaisesRegex(helper.ManagementKeyError, pattern):
                    helper.synchronize_management_key(
                        host_home=self.host_home,
                        service_directory=self.service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=self.root,
                        keygen=self.fixture.keygen,
                    )
                self.assertEqual(before, self.snapshot(self.root))

        private.chmod(0o600)
        alias = self.root / "private-hardlink"
        os.link(private, alias)
        before = self.snapshot(self.root)
        with self.assertRaisesRegex(helper.ManagementKeyError, "link|regular"):
            helper.synchronize_management_key(**self.operation_arguments())
        self.assertEqual(before, self.snapshot(self.root))
        alias.unlink()

        other = self.fixture.generate(self.root / "other")
        public.write_bytes(other[1])
        before = self.snapshot(self.root)
        with self.assertRaisesRegex(helper.ManagementKeyError, "match|pair"):
            helper.synchronize_management_key(**self.operation_arguments())
        self.assertEqual(before, self.snapshot(self.root))

        shutil.rmtree(host_ssh)
        real_ssh = self.root / "real-ssh"
        self.fixture.generate(real_ssh)
        host_ssh.symlink_to(real_ssh, target_is_directory=True)
        before = self.snapshot(self.root)
        with self.assertRaisesRegex(helper.ManagementKeyError, "symlink|NOFOLLOW|directory"):
            helper.synchronize_management_key(**self.operation_arguments())
        self.assertEqual(before, self.snapshot(self.root))

    def test_existing_pair_directories_are_attested_and_never_repaired(self) -> None:
        helper = self.helper()
        for side, mode in (("host", 0o755), ("service", 0o750)):
            with self.subTest(side=side, defect="mode"), tempfile.TemporaryDirectory(
                prefix="http-key-dir-mode-", dir=self.root,
            ) as case_directory:
                case = Path(case_directory)
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                directory = host_home / ".ssh" if side == "host" else service
                self.fixture.generate(directory)
                directory.chmod(mode)
                before = self.snapshot(case)
                with self.assertRaisesRegex(helper.ManagementKeyError, "mode|0700|permission"):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
                self.assertEqual(before, self.snapshot(case))

        for side in ("host", "service"):
            with self.subTest(side=side, defect="owner"), tempfile.TemporaryDirectory(
                prefix="http-key-dir-owner-", dir=self.root,
            ) as case_directory:
                case = Path(case_directory)
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                directory = host_home / ".ssh" if side == "host" else service
                self.fixture.generate(directory)
                before = self.snapshot(case)
                arguments = {
                    "host_home": host_home,
                    "service_directory": service,
                    "host_uid": self.uid + (1 if side == "host" else 0),
                    "host_gid": self.gid,
                    "service_uid": self.uid + (1 if side == "service" else 0),
                    "service_gid": self.gid,
                    "authority_boundary": case,
                    "keygen": self.fixture.keygen,
                }
                with self.assertRaisesRegex(helper.ManagementKeyError, "owner|uid|root"):
                    helper.synchronize_management_key(**arguments)
                self.assertEqual(before, self.snapshot(case))

    def test_parent_component_symlink_nondirectory_and_boundary_escape_are_rejected(self) -> None:
        helper = self.helper()
        with tempfile.TemporaryDirectory(prefix="http-key-components-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            real_host = case / "real-host"
            real_host.mkdir(mode=0o700)
            self.fixture.generate(real_host / ".ssh")
            host_link = case / "host-link"
            host_link.symlink_to(real_host, target_is_directory=True)
            before = self.snapshot(case)
            with self.assertRaisesRegex(helper.ManagementKeyError, "component|symlink|NOFOLLOW"):
                helper.synchronize_management_key(
                    host_home=host_link,
                    service_directory=case / "service",
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=case,
                    keygen=self.fixture.keygen,
                )
            self.assertEqual(before, self.snapshot(case))

        with tempfile.TemporaryDirectory(prefix="http-key-nondir-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            host_home.mkdir(mode=0o700)
            (host_home / ".ssh").write_bytes(b"not-a-directory")
            before = self.snapshot(case)
            with self.assertRaisesRegex(helper.ManagementKeyError, "directory|component"):
                helper.synchronize_management_key(
                    host_home=host_home,
                    service_directory=case / "service",
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=case,
                    keygen=self.fixture.keygen,
                )
            self.assertEqual(before, self.snapshot(case))

        outside = self.root.parent / (self.root.name + "-outside-key")
        outside.mkdir(mode=0o700)
        try:
            before = self.snapshot(self.root)
            with self.assertRaisesRegex(helper.ManagementKeyError, "boundary|outside|canonical"):
                helper.synchronize_management_key(
                    **self.operation_arguments(service_directory=outside),
                )
            self.assertEqual(before, self.snapshot(self.root))
            self.assertEqual([], list(outside.iterdir()))
        finally:
            outside.rmdir()

    def test_every_leaf_mode_link_and_type_defect_is_zero_write(self) -> None:
        helper = self.helper()

        def exercise(label, mutate, pattern="mode|link|regular|FIFO|socket|type"):
            with self.subTest(defect=label), tempfile.TemporaryDirectory(
                prefix="http-key-leaf-type-", dir=self.root,
            ) as case_directory:
                case = Path(case_directory)
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                self.fixture.generate(host_home / ".ssh")
                cleanup = mutate(case, host_home / ".ssh")
                before = self.snapshot(case)
                try:
                    with self.assertRaisesRegex(helper.ManagementKeyError, pattern):
                        helper.synchronize_management_key(
                            host_home=host_home,
                            service_directory=service,
                            host_uid=self.uid,
                            host_gid=self.gid,
                            service_uid=self.uid,
                            service_gid=self.gid,
                            authority_boundary=case,
                            keygen=self.fixture.keygen,
                        )
                    self.assertEqual(before, self.snapshot(case))
                finally:
                    if callable(cleanup):
                        cleanup()

        def private_mode(_case, directory):
            (directory / "id_ed25519").chmod(0o640)

        def public_mode(_case, directory):
            (directory / "id_ed25519.pub").chmod(0o600)

        def private_symlink(case, directory):
            path = directory / "id_ed25519"
            original = case / "private-original"
            path.rename(original)
            path.symlink_to(original)

        def public_symlink(case, directory):
            path = directory / "id_ed25519.pub"
            original = case / "public-original"
            path.rename(original)
            path.symlink_to(original)

        def private_hardlink(case, directory):
            os.link(directory / "id_ed25519", case / "private-alias")

        def public_hardlink(case, directory):
            os.link(directory / "id_ed25519.pub", case / "public-alias")

        def fifo_private(_case, directory):
            path = directory / "id_ed25519"
            path.unlink()
            os.mkfifo(path, 0o600)

        def socket_public(_case, directory):
            path = directory / "id_ed25519.pub"
            path.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(os.fspath(path))
            except PermissionError:
                listener.close()
                # The desktop sandbox denies AF_UNIX bind.  Keep the
                # integration matrix for FIFO and independently exercise the
                # exact socket-mode rejection rather than vacuously skipping.
                sample = list((directory / "id_ed25519").stat())
                sample[stat.ST_MODE] = stat.S_IFSOCK | 0o600
                with self.assertRaisesRegex(
                    helper.ManagementKeyError, "regular|socket|special",
                ):
                    helper._validate_leaf_metadata(
                        os.stat_result(sample),
                        label="synthetic socket",
                        expected_mode=0o600,
                        expected_uid=self.uid,
                        expected_gid=self.gid,
                    )
                # Restore a distinct unsafe special object for the whole-tree
                # zero-write integration path.
                os.mkfifo(path, 0o644)
                return None
            return listener.close

        for label, mutate in (
            ("private-mode", private_mode),
            ("public-mode", public_mode),
            ("private-symlink", private_symlink),
            ("public-symlink", public_symlink),
            ("private-hardlink", private_hardlink),
            ("public-hardlink", public_hardlink),
            ("private-fifo", fifo_private),
            ("public-socket", socket_public),
        ):
            exercise(label, mutate)

        with tempfile.TemporaryDirectory(
            prefix="http-key-leaf-owner-", dir=self.root,
        ) as case_directory:
            directory = Path(case_directory) / "pair"
            self.fixture.generate(directory)
            for name, mode in (("id_ed25519", 0o600), ("id_ed25519.pub", 0o644)):
                with self.subTest(defect="foreign-leaf-owner", leaf=name):
                    with self.assertRaisesRegex(helper.ManagementKeyError, "owner|uid|root"):
                        helper._validate_leaf_metadata(
                            (directory / name).stat(),
                            label=name,
                            expected_mode=mode,
                            expected_uid=self.uid + 1,
                            expected_gid=self.gid,
                        )

    def test_oversize_and_noncanonical_public_payloads_are_rejected_without_read_hang(self) -> None:
        helper = self.helper()
        self.assertLessEqual(helper.MAX_PRIVATE_KEY_BYTES, 64 * 1024)
        self.assertLessEqual(helper.MAX_PUBLIC_KEY_BYTES, 64 * 1024)
        self.assertLessEqual(helper.MAX_TOOL_OUTPUT_BYTES, 64 * 1024)
        for label, target_name, payload, pattern in (
            ("private-oversize", "id_ed25519", b"P" * (64 * 1024 + 1), "large|size|limit"),
            ("public-oversize", "id_ed25519.pub", b"Q" * (64 * 1024 + 1), "large|size|limit"),
            (
                "public-extra-line", "id_ed25519.pub",
                b"ssh-ed25519 AAAA comment\nssh-ed25519 AAAA second\n",
                "public|line|format|Ed25519",
            ),
            ("public-nul", "id_ed25519.pub", b"ssh-ed25519 AAAA\x00comment\n", "public|format|NUL"),
        ):
            with self.subTest(defect=label), tempfile.TemporaryDirectory(
                prefix="http-key-bound-", dir=self.root,
            ) as case_directory:
                case = Path(case_directory)
                host_home = case / "host"
                host_home.mkdir(mode=0o700)
                directory = host_home / ".ssh"
                self.fixture.generate(directory)
                target = directory / target_name
                target.write_bytes(payload)
                target.chmod(0o600 if target_name == "id_ed25519" else 0o644)
                before = self.snapshot(case)
                with self.assertRaisesRegex(helper.ManagementKeyError, pattern):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=case / "service",
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
                self.assertEqual(before, self.snapshot(case))

    def test_source_metadata_and_name_rebind_races_fail_before_destination_write(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()
        private, public = self.fixture.pair(self.host_home / ".ssh")

        def drift(stage: str) -> None:
            if stage == "host-source-pair-held":
                private.write_bytes(expected[0] + b"\n")

        with mock.patch.object(helper, "_checkpoint", side_effect=drift):
            with self.assertRaisesRegex(helper.ManagementKeyError, "changed|metadata|stable"):
                helper.synchronize_management_key(**self.operation_arguments())
        self.assertFalse(self.service.exists())

        # Start a fresh fixture because the first adversarial write is intentional.
        with tempfile.TemporaryDirectory(prefix="http-key-rebind-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            host_home.mkdir(mode=0o700)
            self.fixture.generate(host_home / ".ssh")
            source_public = host_home / ".ssh/id_ed25519.pub"

            def rebind(stage: str) -> None:
                if stage == "host-source-pair-held":
                    original = case / "held-original.pub"
                    source_public.rename(original)
                    source_public.write_bytes(original.read_bytes())
                    source_public.chmod(0o644)

            with mock.patch.object(helper, "_checkpoint", side_effect=rebind):
                with self.assertRaisesRegex(helper.ManagementKeyError, "rebind|changed|identity"):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=case / "service",
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
            self.assertFalse((case / "service").exists())

        with tempfile.TemporaryDirectory(prefix="http-key-parent-missing-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            host_home.mkdir(mode=0o700)
            self.fixture.generate(host_home / ".ssh")
            vanished = case / "vanished-host"

            def remove_parent_name(stage: str) -> None:
                if stage == "authority-components-held":
                    host_home.rename(vanished)

            with mock.patch.object(helper, "_checkpoint", side_effect=remove_parent_name):
                with self.assertRaisesRegex(
                    helper.ManagementKeyError, "component|disappeared|changed|identity",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=case / "service",
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
            self.assertFalse((case / "service").exists())

        with tempfile.TemporaryDirectory(prefix="http-key-held-dir-missing-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            host_home.mkdir(mode=0o700)
            self.fixture.generate(host_home / ".ssh")
            vanished = case / "held-ssh"

            def remove_held_directory_name(stage: str) -> None:
                if stage == "host-source-pair-held":
                    (host_home / ".ssh").rename(vanished)

            with mock.patch.object(helper, "_checkpoint", side_effect=remove_held_directory_name):
                with self.assertRaisesRegex(
                    helper.ManagementKeyError, "directory|disappeared|rebound|identity",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=case / "service",
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
            self.assertFalse((case / "service").exists())

        with tempfile.TemporaryDirectory(prefix="http-key-parent-rebind-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            host_home.mkdir(mode=0o700)
            self.fixture.generate(host_home / ".ssh")
            held_host = case / "held-host"

            def rebind_parent(stage: str) -> None:
                if stage == "authority-components-held":
                    host_home.rename(held_host)
                    host_home.mkdir(mode=0o700)
                    self.fixture.generate(host_home / ".ssh", comment="replacement")

            with mock.patch.object(helper, "_checkpoint", side_effect=rebind_parent):
                with self.assertRaisesRegex(
                    helper.ManagementKeyError, "component|rebind|changed|identity",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=case / "service",
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
            self.assertFalse((case / "service").exists())

    def test_rsa_and_encrypted_ed25519_are_not_noninteractive_service_keys(self) -> None:
        helper = self.helper()
        for algorithm, passphrase, pattern in (
            ("rsa", "", "Ed25519"),
            ("ed25519", "fixture-passphrase", "encrypted|non.interactive|private"),
        ):
            with self.subTest(algorithm=algorithm, encrypted=bool(passphrase)):
                with tempfile.TemporaryDirectory(
                    prefix="http-key-format-", dir=self.root,
                ) as case_directory:
                    case = Path(case_directory)
                    home = case / "host"
                    home.mkdir(mode=0o700)
                    self.fixture.generate(
                        home / ".ssh", algorithm=algorithm, passphrase=passphrase,
                    )
                    before = self.snapshot(case)
                    with self.assertRaisesRegex(helper.ManagementKeyError, pattern):
                        helper.synchronize_management_key(
                            host_home=home,
                            service_directory=case / "service",
                            host_uid=self.uid,
                            host_gid=self.gid,
                            service_uid=self.uid,
                            service_gid=self.gid,
                            authority_boundary=case,
                            keygen=self.fixture.keygen,
                        )
                    self.assertEqual(before, self.snapshot(case))

    def test_implementation_has_held_nofollow_atomic_and_durable_primitives(self) -> None:
        source = HELPER_PATH.read_text(encoding="utf-8")
        for token in (
            "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK",
            "os.fstat", "os.lstat", "st_nlink", "st_mtime_ns", "st_ctime_ns",
            "os.fsync", "O_TMPFILE", "linkat", "AT_EMPTY_PATH", "pass_fds",
            "stdin=subprocess.DEVNULL", "timeout=", "/proc/self/fd",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertNotIn("os.replace", source)
        self.assertNotIn("shutil.copy", source)
        self.assertNotRegex(source, r"(?m)^\s*(?:print|logging\.[a-z]+)\(.*private")

    def test_ssh_keygen_uses_fixed_argv_sanitized_env_minimal_fds_and_bounds(self) -> None:
        self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()
        real_bounded = helper._run_bounded_command
        observed = []

        def run_and_record(argv, **kwargs):
            observed.append((list(argv), dict(kwargs)))
            return real_bounded(argv, **kwargs)

        with mock.patch.object(helper, "_run_bounded_command", side_effect=run_and_record):
            result = helper.synchronize_management_key(**self.operation_arguments())
        self.assertEqual("copied-host-to-service", result["action"])
        self.assertGreaterEqual(len(observed), 3)
        for argv, keywords in observed:
            self.assertEqual("/usr/bin/ssh-keygen", argv[0])
            self.assertEqual(["-y", "-P", "", "-f"], argv[1:5])
            self.assertRegex(argv[5], r"\A/(?:proc/self|dev)/fd/[0-9]+\Z")
            self.assertLessEqual(keywords["timeout"], 10)
            self.assertEqual(1, len(keywords["pass_fds"]))
            self.assertEqual(int(argv[5].rsplit("/", 1)[1]), keywords["pass_fds"][0])

        source = HELPER_PATH.read_text(encoding="utf-8")
        self.assertIn("subprocess.Popen", source)
        self.assertNotIn("subprocess.run", source)
        for token in (
            "start_new_session=True", "selectors.DefaultSelector", "time.monotonic",
            "os.killpg", "process.wait", "close_fds=True", "pass_fds=pass_fds",
        ):
            self.assertIn(token, source)
        self.assertIn('"HOME": "/root"', source)
        self.assertIn('"PATH": "/usr/bin:/bin"', source)
        self.assertIn('"PYTHONNOUSERSITE": "1"', source)

    def test_bounded_runner_kills_and_reaps_endless_or_oversize_producer(self) -> None:
        helper = self.helper()
        for label, body in (
            ("endless", 'echo $$ > "$1"; while :; do printf x; done'),
            ("oversize", 'echo $$ > "$1"; head -c 1048576 /dev/zero; sleep 30'),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory(
                prefix="http-key-bounded-producer-", dir=self.root,
            ) as temporary:
                pid_file = Path(temporary) / "pid"
                started = time.monotonic()
                with self.assertRaisesRegex(
                    helper.ManagementKeyError, "limit|timeout|output|large",
                ):
                    helper._run_bounded_command(
                        ["/bin/bash", "-c", body, "bounded-producer", os.fspath(pid_file)],
                        pass_fds=(),
                        timeout=1.0,
                        max_stdout=1024,
                        max_stderr=1024,
                    )
                self.assertLess(time.monotonic() - started, 4.0)
                self.assertTrue(pid_file.is_file())
                producer_pid = int(pid_file.read_text(encoding="ascii"))
                with self.assertRaises(ProcessLookupError):
                    os.kill(producer_pid, 0)

        with tempfile.TemporaryDirectory(
            prefix="http-key-held-pipe-", dir=self.root,
        ) as temporary:
            pid_file = Path(temporary) / "pid"
            script = (
                "import os,sys,time\n"
                "child=os.fork()\n"
                "if child == 0:\n"
                "    time.sleep(30)\n"
                "    os._exit(0)\n"
                "open(sys.argv[1],'w').write(str(child))\n"
            )
            started = time.monotonic()
            with self.assertRaisesRegex(helper.ManagementKeyError, "timeout|bounded"):
                helper._run_bounded_command(
                    ["/usr/bin/python3", "-c", script, os.fspath(pid_file)],
                    pass_fds=(),
                    timeout=0.3,
                    max_stdout=1024,
                    max_stderr=1024,
                )
            self.assertLess(time.monotonic() - started, 2.5)
            child_pid = int(pid_file.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    def test_bounded_runner_setup_faults_close_pipes_kill_and_reap(self) -> None:
        helper = self.helper()
        real_popen = subprocess.Popen
        real_selector = helper.selectors.DefaultSelector
        for fault in ("fileno", "set-blocking", "selector", "register"):
            with self.subTest(fault=fault):
                processes = []

                def launch(_argv, **kwargs):
                    process = real_popen(["/bin/sleep", "60"], **kwargs)
                    processes.append(process)
                    if fault == "fileno":
                        process.stdout.fileno = mock.Mock(
                            side_effect=OSError("synthetic fileno fault"),
                        )
                    return process

                class BrokenSelector:
                    def __init__(self):
                        if fault == "selector":
                            raise OSError("synthetic selector fault")
                        self.inner = real_selector()

                    def register(self, *_args, **_kwargs):
                        if fault == "register":
                            raise OSError("synthetic register fault")
                        return self.inner.register(*_args, **_kwargs)

                    def close(self):
                        self.inner.close()

                before_fds = len(os.listdir("/dev/fd"))
                with mock.patch.object(helper.subprocess, "Popen", side_effect=launch), \
                     mock.patch.object(helper.selectors, "DefaultSelector", BrokenSelector):
                    set_blocking = (
                        mock.patch.object(
                            helper.os, "set_blocking",
                            side_effect=OSError("synthetic set-blocking fault"),
                        )
                        if fault == "set-blocking" else mock.patch.object(
                            helper.os, "set_blocking", wraps=os.set_blocking,
                        )
                    )
                    with set_blocking, self.assertRaisesRegex(
                        helper.ManagementKeyError, "bounded|command|failed|start",
                    ):
                        helper._run_bounded_command(
                            ["/bin/sleep", "60"], timeout=1,
                        )
                self.assertEqual(1, len(processes))
                self.assertIsNotNone(processes[0].poll(), "setup fault leaked child")
                self.assertEqual(before_fds, len(os.listdir("/dev/fd")))

    def test_keygen_rc_stderr_and_noncanonical_output_fail_without_destination_write(self) -> None:
        helper = self.helper()
        for label, command_result, pattern in (
            (
                "nonzero",
                helper.CommandResult(returncode=3, stdout=b"", stderr=b"fixed error\n"),
                "ssh-keygen|return|failed",
            ),
            (
                "stderr-on-success",
                helper.CommandResult(
                    returncode=0,
                    stdout=b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                    stderr=b"unexpected\n",
                ),
                "stderr|output|ssh-keygen",
            ),
            (
                "extra-line",
                helper.CommandResult(
                    returncode=0,
                    stdout=(
                        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
                        b"forged-second-line\n"
                    ),
                    stderr=b"",
                ),
                "format|line|ssh-keygen|public",
            ),
        ):
            with self.subTest(case=label), tempfile.TemporaryDirectory(
                prefix="http-key-keygen-result-", dir=self.root,
            ) as temporary:
                case = Path(temporary).resolve()
                host_home = case / "host"
                host_home.mkdir(mode=0o700)
                self.fixture.generate(host_home / ".ssh")
                before = self.snapshot(case)
                case_helper = self.helper()
                with mock.patch.object(
                    case_helper, "_run_bounded_command", return_value=command_result,
                ):
                    with self.assertRaisesRegex(case_helper.ManagementKeyError, pattern):
                        case_helper.synchronize_management_key(
                            host_home=host_home,
                            service_directory=case / "service",
                            host_uid=self.uid,
                            host_gid=self.gid,
                            service_uid=self.uid,
                            service_gid=self.gid,
                            authority_boundary=case,
                            keygen=self.fixture.keygen,
                        )
                self.assertEqual(before, self.snapshot(case))

    def test_generation_uses_private_staging_and_fixed_unencrypted_ed25519_argv(self) -> None:
        helper = self.helper()
        real_bounded = helper._run_bounded_command
        generation_calls = []

        def run_and_record(argv, **kwargs):
            argv = list(argv)
            if "-t" in argv:
                fd_values = tuple(kwargs.get("pass_fds", ()))
                self.assertEqual(1, len(fd_values))
                stage_fd = fd_values[0]
                stage_metadata = os.fstat(stage_fd)
                self.assertTrue(stat.S_ISDIR(stage_metadata.st_mode))
                self.assertEqual(0o700, stat.S_IMODE(stage_metadata.st_mode))
                stage_entries = [
                    path for path in (self.host_home / ".ssh").iterdir()
                    if path.name.startswith(".management-key-stage-")
                ]
                self.assertEqual(1, len(stage_entries))
                self.assertEqual(
                    (stage_metadata.st_dev, stage_metadata.st_ino),
                    (stage_entries[0].stat().st_dev, stage_entries[0].stat().st_ino),
                )
                generation_calls.append((argv, dict(kwargs), stage_fd))
            return real_bounded(argv, **kwargs)

        previous_umask = os.umask(0)
        try:
            with mock.patch.object(helper, "_run_bounded_command", side_effect=run_and_record):
                outcome = helper.synchronize_management_key(**self.operation_arguments())
        finally:
            os.umask(previous_umask)
        self.assertEqual("generated-host-and-copied-service", outcome["action"])
        self.assertEqual(1, len(generation_calls))
        argv, keywords, stage_fd = generation_calls[0]
        self.assertEqual("/usr/bin/ssh-keygen", argv[0])
        self.assertEqual("ed25519", argv[argv.index("-t") + 1])
        self.assertEqual("", argv[argv.index("-N") + 1])
        self.assertEqual("root@management-server", argv[argv.index("-C") + 1])
        self.assertEqual("id_ed25519", argv[argv.index("-f") + 1])
        self.assertEqual((stage_fd,), keywords.get("pass_fds", ()))
        self.assertEqual(stage_fd, keywords.get("working_directory_fd"))
        self.assertLessEqual(keywords["timeout"], 10)
        self.assertEqual(0o077, helper.STAGING_UMASK)

    def test_created_directory_ignores_hostile_umask_and_rebind_is_not_adopted(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()
        previous_umask = os.umask(0o777)
        try:
            result = helper.synchronize_management_key(**self.operation_arguments())
        finally:
            os.umask(previous_umask)
        self.assertEqual("copied-host-to-service", result["action"])
        self.assertEqual(0o700, stat.S_IMODE(self.service.stat().st_mode))
        self.assert_pair_bytes(self.service, expected)

        with tempfile.TemporaryDirectory(prefix="http-key-dir-swap-", dir=self.root) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            host_home.mkdir(mode=0o700)
            self.fixture.generate(host_home / ".ssh")
            service = case / "service"
            displaced = case / "created-service"

            def replace_created_directory(stage: str) -> None:
                if stage == "service-directory-created":
                    service.rename(displaced)
                    service.mkdir(mode=0o700)
                    service.chmod(0o700)

            with mock.patch.object(helper, "_checkpoint", side_effect=replace_created_directory):
                with self.assertRaisesRegex(
                    helper.ManagementKeyError, "rebound|identity|initialize|remove",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
            self.assertTrue(service.is_dir())
            self.assertEqual([], list(service.iterdir()))
            self.assertTrue(displaced.is_dir())
            self.assertEqual([], list(displaced.iterdir()))

    def test_no_replace_publish_failure_never_overwrites_a_canonical_leaf(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()
        real_publish = helper._publish_held_inode

        def refuse_publish(*args, **kwargs):
            raise FileExistsError("synthetic no-replace collision")

        with mock.patch.object(helper, "_publish_held_inode", side_effect=refuse_publish):
            with self.assertRaises(helper.ManagementKeyError):
                helper.synchronize_management_key(**self.operation_arguments())
        self.assert_pair_bytes(self.host_home / ".ssh", expected)
        self.assertFalse((self.service / "id_ed25519").exists())
        self.assertFalse((self.service / "id_ed25519.pub").exists())
        if self.service.exists():
            self.assertFalse(any(path.name.startswith(".") for path in self.service.iterdir()))
        self.assertIs(real_publish, helper._publish_held_inode)

    def test_candidate_name_replacement_cannot_publish_attacker_inode(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()
        replacement_paths = []

        def replace_candidate(stage: str) -> None:
            if stage != "service-id_ed25519-candidate-ready":
                return
            self.assertEqual(
                [], [path for path in self.service.iterdir() if "candidate" in path.name],
            )
            canonical = self.service / "id_ed25519"
            canonical.write_bytes(b"ATTACKER-PRIVATE\n")
            canonical.chmod(0o600)
            replacement_paths.append(canonical)

        with mock.patch.object(helper, "_checkpoint", side_effect=replace_candidate):
            with self.assertRaisesRegex(
                helper.ManagementKeyError, "candidate|identity|rebound|cleanup|metadata",
            ):
                helper.synchronize_management_key(**self.operation_arguments())
        canonical = self.service / "id_ed25519"
        self.assertEqual(b"ATTACKER-PRIVATE\n", canonical.read_bytes())
        self.assertNotEqual(expected[0], canonical.read_bytes())
        self.assertEqual(1, len(replacement_paths))
        self.assertTrue(replacement_paths[0].is_file())
        self.assertEqual(b"ATTACKER-PRIVATE\n", replacement_paths[0].read_bytes())

    def test_generation_cleanup_never_unlinks_a_rebound_stage_leaf(self) -> None:
        for leaf_name, mode in (("id_ed25519", 0o600), ("id_ed25519.pub", 0o644)):
            with self.subTest(leaf=leaf_name), tempfile.TemporaryDirectory(
                prefix="http-key-stage-rebind-", dir=self.root,
            ) as temporary:
                case = Path(temporary).resolve()
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                attacker_paths: list[Path] = []
                helper = self.helper()

                def replace_generated_leaf(stage: str) -> None:
                    if stage != "host-id_ed25519-candidate-ready":
                        return
                    stages = list(
                        (host_home / ".ssh").glob(".management-key-stage-*")
                    )
                    self.assertEqual(1, len(stages))
                    target = stages[0] / leaf_name
                    target.unlink()
                    target.write_bytes(b"ATTACKER-STAGE-LEAF\n")
                    target.chmod(mode)
                    attacker_paths.append(target)

                with mock.patch.object(
                    helper, "_checkpoint", side_effect=replace_generated_leaf,
                ), self.assertRaisesRegex(
                    helper.ManagementKeyError,
                    "generation staging|identity|changed|cleanup",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
                self.assertEqual(1, len(attacker_paths))
                self.assertTrue(attacker_paths[0].is_file())
                self.assertEqual(
                    b"ATTACKER-STAGE-LEAF\n", attacker_paths[0].read_bytes(),
                )
                self.assertFalse((host_home / ".ssh/id_ed25519").exists())
                self.assertFalse((host_home / ".ssh/id_ed25519.pub").exists())
                self.assertFalse((service / "id_ed25519").exists())
                self.assertFalse((service / "id_ed25519.pub").exists())

    def test_generation_source_is_revalidated_between_leaf_publications(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="http-key-stage-between-", dir=self.root,
        ) as temporary:
            case = Path(temporary).resolve()
            host_home = case / "host"
            service = case / "service"
            host_home.mkdir(mode=0o700)
            attacker: list[Path] = []
            helper = self.helper()

            def replace_public_after_private(stage: str) -> None:
                if stage != "host-private-published":
                    return
                stages = list(
                    (host_home / ".ssh").glob(".management-key-stage-*")
                )
                self.assertEqual(1, len(stages))
                target = stages[0] / "id_ed25519.pub"
                target.unlink()
                target.write_bytes(b"ssh-ed25519 ATTACKER\n")
                target.chmod(0o644)
                attacker.append(target)

            with mock.patch.object(
                helper, "_checkpoint", side_effect=replace_public_after_private,
            ), self.assertRaisesRegex(
                helper.ManagementKeyError,
                "generation staging|identity|changed|cleanup",
            ):
                helper.synchronize_management_key(
                    host_home=host_home,
                    service_directory=service,
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=case,
                    keygen=self.fixture.keygen,
                )
            self.assertEqual(1, len(attacker))
            self.assertEqual(b"ssh-ed25519 ATTACKER\n", attacker[0].read_bytes())
            self.assertTrue((host_home / ".ssh/id_ed25519").is_file())
            self.assertFalse((host_home / ".ssh/id_ed25519.pub").exists())
            self.assertFalse((service / "id_ed25519").exists())
            self.assertFalse((service / "id_ed25519.pub").exists())

    def test_generation_precleanup_rejects_rebound_leaf_without_deleting_it(self) -> None:
        for leaf_name, mode in (("id_ed25519", 0o600), ("id_ed25519.pub", 0o644)):
            with self.subTest(leaf=leaf_name), tempfile.TemporaryDirectory(
                prefix="http-key-stage-precleanup-", dir=self.root,
            ) as temporary:
                case = Path(temporary).resolve()
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                attacker: list[tuple[Path, int]] = []
                helper = self.helper()

                def replace_before_cleanup(stage: str) -> None:
                    if stage != "generation-stage-pre-cleanup":
                        return
                    stages = list(
                        (host_home / ".ssh").glob(".management-key-stage-*")
                    )
                    self.assertEqual(1, len(stages))
                    target = stages[0] / leaf_name
                    target.unlink()
                    target.write_bytes(b"FOREIGN-PRECLEANUP\n")
                    target.chmod(mode)
                    attacker.append((target, target.stat().st_ino))

                with mock.patch.object(
                    helper, "_checkpoint", side_effect=replace_before_cleanup,
                ), self.assertRaisesRegex(
                    helper.ManagementKeyError,
                    "generation staging|identity|changed|cleanup",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
                self.assertEqual(1, len(attacker))
                target, inode = attacker[0]
                self.assertTrue(target.is_file())
                self.assertEqual(inode, target.stat().st_ino)
                self.assertEqual(b"FOREIGN-PRECLEANUP\n", target.read_bytes())
                self.assertTrue((host_home / ".ssh/id_ed25519").is_file())
                self.assertTrue((host_home / ".ssh/id_ed25519.pub").is_file())
                self.assertFalse((service / "id_ed25519").exists())
                self.assertFalse((service / "id_ed25519.pub").exists())

    def test_generation_stage_rebind_or_unexpected_child_precedes_publication(self) -> None:
        for defect in ("directory-rebind", "unexpected-child"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory(
                prefix="http-key-stage-structure-", dir=self.root,
            ) as temporary:
                case = Path(temporary).resolve()
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                preserved: list[Path] = []
                helper = self.helper()

                def corrupt_stage(stage: str) -> None:
                    if stage != "host-id_ed25519-candidate-ready":
                        return
                    stages = list(
                        (host_home / ".ssh").glob(".management-key-stage-*")
                    )
                    self.assertEqual(1, len(stages))
                    original = stages[0]
                    if defect == "directory-rebind":
                        displaced = original.with_name(original.name + ".original")
                        original.rename(displaced)
                        original.mkdir(mode=0o700)
                        preserved.extend((original, displaced))
                    else:
                        foreign = original / "foreign"
                        foreign.write_bytes(b"FOREIGN\n")
                        foreign.chmod(0o600)
                        preserved.append(foreign)

                with mock.patch.object(
                    helper, "_checkpoint", side_effect=corrupt_stage,
                ), self.assertRaisesRegex(
                    helper.ManagementKeyError,
                    "generation staging|directory|identity|unexpected|changed",
                ):
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
                self.assertTrue(all(path.exists() for path in preserved))
                self.assertFalse((host_home / ".ssh/id_ed25519").exists())
                self.assertFalse((host_home / ".ssh/id_ed25519.pub").exists())
                self.assertFalse((service / "id_ed25519").exists())

    def test_generation_cleanup_faults_fail_closed_and_close_the_stage_fd(self) -> None:
        for fault in ("unlink", "rmdir", "fsync", "revalidate"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(
                prefix="http-key-stage-cleanup-", dir=self.root,
            ) as temporary:
                case = Path(temporary).resolve()
                host_home = case / "host"
                service = case / "service"
                host_home.mkdir(mode=0o700)
                helper = self.helper()
                armed = {"value": False}
                real_unlink = helper.os.unlink
                real_rmdir = helper.os.rmdir
                real_fsync = helper.os.fsync
                real_stat = helper.os.stat

                def checkpoint(stage: str) -> None:
                    if stage == "host-pair-published":
                        armed["value"] = True

                def unlink(path, *args, **kwargs):
                    if armed["value"] and fault == "unlink" and path == "id_ed25519":
                        raise OSError("synthetic cleanup unlink fault")
                    return real_unlink(path, *args, **kwargs)

                def rmdir(path, *args, **kwargs):
                    if (
                        armed["value"] and fault == "rmdir"
                        and str(path).startswith(".management-key-stage-")
                    ):
                        raise OSError("synthetic cleanup rmdir fault")
                    return real_rmdir(path, *args, **kwargs)

                def fsync(descriptor):
                    if armed["value"] and fault == "fsync":
                        raise OSError("synthetic cleanup fsync fault")
                    return real_fsync(descriptor)

                def stat_call(path, *args, **kwargs):
                    if (
                        armed["value"] and fault == "revalidate"
                        and str(path).startswith(".management-key-stage-")
                    ):
                        raise OSError("synthetic cleanup revalidation fault")
                    return real_stat(path, *args, **kwargs)

                before_fds = len(os.listdir("/dev/fd"))
                with mock.patch.object(helper, "_checkpoint", side_effect=checkpoint), \
                     mock.patch.object(helper.os, "unlink", side_effect=unlink), \
                     mock.patch.object(helper.os, "rmdir", side_effect=rmdir), \
                     mock.patch.object(helper.os, "fsync", side_effect=fsync), \
                     mock.patch.object(helper.os, "stat", side_effect=stat_call), \
                     self.assertRaisesRegex(
                         helper.ManagementKeyError,
                         "generation staging|cleanup|failed|revalidation|residue",
                     ) as caught:
                    helper.synchronize_management_key(
                        host_home=host_home,
                        service_directory=service,
                        host_uid=self.uid,
                        host_gid=self.gid,
                        service_uid=self.uid,
                        service_gid=self.gid,
                        authority_boundary=case,
                        keygen=self.fixture.keygen,
                    )
                self.assertEqual(before_fds, len(os.listdir("/dev/fd")))
                host_private = host_home / ".ssh/id_ed25519"
                host_public = host_home / ".ssh/id_ed25519.pub"
                self.assertTrue(host_private.is_file())
                self.assertTrue(host_public.is_file())
                check = helper.check_management_key(
                    host_home=host_home,
                    service_directory=service,
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=case,
                    keygen=self.fixture.keygen,
                )
                self.assertEqual("copy-host-to-service-required", check["action"])
                self.assertEqual(fingerprint(host_public.read_bytes()), check["fingerprint"])
                self.assertFalse((service / "id_ed25519").exists())
                self.assertFalse((service / "id_ed25519.pub").exists())
                stages = list((host_home / ".ssh").glob(".management-key-stage-*"))
                self.assertEqual(1, len(stages))
                expected_residue = (
                    ["id_ed25519", "id_ed25519.pub"]
                    if fault in {"unlink", "revalidate"}
                    else []
                )
                self.assertEqual(
                    expected_residue,
                    sorted(path.name for path in stages[0].iterdir()),
                )
                diagnostic = str(caught.exception)
                self.assertIn("residue retained", diagnostic)
                self.assertNotIn("PRIVATE KEY", diagnostic)

    def test_production_held_publish_is_linux_fd_empty_path_only(self) -> None:
        raw = load_module(HELPER_PATH, "docker_key_native_publish_contract")
        source = HELPER_PATH.read_text(encoding="utf-8")
        self.assertIn("AT_EMPTY_PATH", source)
        self.assertIn("linkat", source)
        self.assertRegex(source, r"linkat\(\s*candidate_descriptor,\s*b[\"']{2}")
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(raw.ManagementKeyError, "Linux|AT_EMPTY_PATH"):
                raw._publish_held_inode(9, 10, "id_ed25519")

        class FakeLinkat:
            def __init__(self, result: int) -> None:
                self.result = result
                self.calls = []
                self.argtypes = None
                self.restype = None

            def __call__(self, *arguments):
                self.calls.append(arguments)
                return self.result

        for error_number in (0, errno.EEXIST, errno.EPERM, errno.EINVAL, errno.ENOSYS):
            with self.subTest(errno=error_number):
                linkat = FakeLinkat(0 if error_number == 0 else -1)
                fake_libc = type("FakeLibc", (), {"linkat": linkat})()
                patches = (
                    mock.patch.object(raw.sys, "platform", "linux"),
                    mock.patch.object(raw.ctypes, "CDLL", return_value=fake_libc),
                    mock.patch.object(raw.ctypes, "set_errno"),
                    mock.patch.object(raw.ctypes, "get_errno", return_value=error_number),
                )
                with patches[0], patches[1], patches[2], patches[3]:
                    if error_number:
                        with self.assertRaisesRegex(
                            raw.ManagementKeyError, "linkat|publication|failed",
                        ):
                            raw._publish_held_inode(12, 13, "id_ed25519")
                    else:
                        raw._publish_held_inode(12, 13, "id_ed25519")
                self.assertEqual(
                    [(12, b"", 13, b"id_ed25519", raw.AT_EMPTY_PATH)],
                    linkat.calls,
                )

    def test_crash_after_first_leaf_leaves_a_half_pair_that_next_run_refuses(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()

        def fail_after_private(stage: str) -> None:
            if stage == "service-private-published":
                raise RuntimeError("synthetic crash gap")

        with mock.patch.object(helper, "_checkpoint", side_effect=fail_after_private):
            with self.assertRaisesRegex(RuntimeError, "crash gap"):
                helper.synchronize_management_key(
                    host_home=self.host_home,
                    service_directory=self.service,
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=self.root,
                    keygen=self.fixture.keygen,
                )
        service_private, service_public = self.fixture.pair(self.service)
        self.assertEqual(expected[0], service_private.read_bytes())
        self.assertFalse(service_public.exists())
        before = self.snapshot(self.root)
        with self.assertRaisesRegex(helper.ManagementKeyError, "half|incomplete|pair"):
            helper.synchronize_management_key(**self.operation_arguments())
        self.assertEqual(before, self.snapshot(self.root))

    def test_postcommit_revalidation_failure_never_reports_success(self) -> None:
        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()

        def corrupt_after_publish(stage: str) -> None:
            if stage == "service-pair-published":
                public = self.service / "id_ed25519.pub"
                public.write_bytes(public.read_bytes() + b"drift\n")

        with mock.patch.object(helper, "_checkpoint", side_effect=corrupt_after_publish):
            with self.assertRaisesRegex(
                helper.ManagementKeyError, "post|changed|revalidation|identity|pair",
            ):
                helper.synchronize_management_key(**self.operation_arguments())
        self.assert_pair_bytes(self.host_home / ".ssh", expected)
        self.assertTrue((self.service / "id_ed25519").is_file())
        self.assertTrue((self.service / "id_ed25519.pub").is_file())

    def test_fsync_and_keygen_timeout_fail_without_publishing_a_complete_pair(self) -> None:
        helper = self.helper()
        with mock.patch.object(
            helper,
            "_run_bounded_command",
            side_effect=helper.ManagementKeyError("ssh-keygen timeout"),
        ):
            with self.assertRaises(helper.ManagementKeyError):
                helper.synchronize_management_key(**self.operation_arguments())
        self.assertFalse((self.host_home / ".ssh/id_ed25519").exists())
        self.assertFalse((self.service / "id_ed25519").exists())

        expected = self.fixture.generate(self.host_home / ".ssh")
        helper = self.helper()
        with mock.patch.object(helper.os, "fsync", side_effect=OSError("synthetic fsync")):
            with self.assertRaises(helper.ManagementKeyError):
                helper.synchronize_management_key(
                    host_home=self.host_home,
                    service_directory=self.service,
                    host_uid=self.uid,
                    host_gid=self.gid,
                    service_uid=self.uid,
                    service_gid=self.gid,
                    authority_boundary=self.root,
                    keygen=self.fixture.keygen,
                )
        self.assert_pair_bytes(self.host_home / ".ssh", expected)
        self.assertFalse((self.service / "id_ed25519.pub").exists())


class DockerManagementSshKeyWorkflowTests(unittest.TestCase):
    def test_private_pair_is_excluded_from_image_package_sync_diagnostics_and_evidence(self) -> None:
        for ignore_path in (
            ROOT / ".dockerignore",
            ROOT / "infra/docker/Dockerfile.dockerignore",
        ):
            rules = ignore_path.read_text(encoding="utf-8").splitlines()
            self.assertIn("**/.ssh/**", rules)
            self.assertIn("**/.[Ss][Ss][Hh]/**", rules)
        private_paths = (
            "/root/.ssh/id_ed25519",
            "/var/lib/http-ztp-container/ssh/id_ed25519",
        )
        for path in (
            ROOT / "tools/collect-ztp-diagnostics.py",
            ROOT / "tools/tar-for-upload.py",
            ROOT / "tools/sync-code.py",
            ROOT / "test_cases/run_related_tests.py",
        ):
            source = path.read_text(encoding="utf-8")
            for private_path in private_paths:
                with self.subTest(path=path.name, private_path=private_path):
                    self.assertNotIn(private_path, source)
        helper_source = HELPER_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "evidence", "receipt", "tarfile", "docker build",
        ):
            with self.subTest(helper_sink=forbidden):
                self.assertNotIn(forbidden, helper_source.casefold())

    def test_deploy_contract_uses_hostlock_and_never_mounts_the_whole_host_ssh_dir(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        self.assertNotIn("--ssh-key-user", source)
        self.assertNotIn("HTTP_ZTP_SSH_KEY_USER", source)
        helper_function = source.split("prepare_management_ssh_key()", 1)[1].split("\n}", 1)[0]
        self.assertIn("safe_lock_run", helper_function)
        self.assertIn("management_ssh_key.py", helper_function)
        self.assertIn(
            'safe_lock_run -- /usr/bin/python3 -B '
            '"$script_dir/management_ssh_key.py" reconcile',
            helper_function,
        )
        bind_function = source.split("prepare_bind_mounts()", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("/var/lib/http-ztp-container/ssh", bind_function)
        self.assertNotIn("/root/.ssh:/root/.ssh", source)
        self.assertIn(
            "/var/lib/http-ztp-container/ssh,dst=/root/.ssh", source,
        )
        for action, later in (
            ("deploy", "clear_activation_for_recreate"),
            ("deploy-preloaded", "clear_activation_for_recreate"),
            ("deploy-project-preloaded", "clear_activation_for_recreate"),
            ("load", "run_load"),
        ):
            with self.subTest(action=action):
                branch = deploy_action_body(source, action)
                self.assertIn("prepare_management_ssh_key", branch)
                self.assertLess(
                    branch.index("prepare_management_ssh_key"), branch.index(later),
                )

        doctor_action = deploy_action_body(source, "doctor")
        self.assertEqual("    doctor\n    ;;\n", doctor_action)
        doctor = source.split("doctor()", 1)[1].split("\n}", 1)[0]
        self.assertIn("check_management_ssh_key", doctor)
        self.assertNotIn("prepare_management_ssh_key", doctor)
        self.assertNotIn("prepare_bind_mounts", doctor)
        check_function = source.split("check_management_ssh_key()", 1)[1].split("\n}", 1)[0]
        self.assertIn(
            'safe_lock_run -- /usr/bin/python3 -B '
            '"$script_dir/management_ssh_key.py" check',
            check_function,
        )
        for action in (
            "build", "image-export", "build-export", "init", "status", "health",
            "logs", "reload-network", "unload", "down", "rotate-auth",
            "recover-monitor-authority",
        ):
            with self.subTest(non_mutating_action=action):
                self.assertNotRegex(
                    deploy_action_body(source, action),
                    r"(?:prepare|reconcile)_management_ssh_key",
                )

    def test_deploy_reconciliation_output_schema_is_bounded_before_lifecycle(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        function = source.split("prepare_management_ssh_key()", 1)[1].split("\n}", 1)[0]
        for required in (
            "management_key_status",
            "${#management_key_status}",
        ):
            self.assertIn(required, function)
        self.assertNotIn("eval", function)
        self.assertIn("validate_management_key_status", function)
        validator = source.split("validate_management_key_status()", 1)[1].split("\n}", 1)[0]
        for required in (
            "object_pairs_hook", "sort_keys=True", 'separators=(",", ":")',
            "copied-host-to-service", "copied-service-to-host",
            "generated-host-and-copied-service", "preserved-identical", "SHA256:",
        ):
            self.assertIn(required, validator)

    def test_real_helper_output_becomes_the_public_key_injected_by_11_load(self) -> None:
        helper = load_module(HELPER_PATH, "docker_key_workflow_helper")
        install_nonlinux_held_link_test_oracle(helper)
        loader = load_module(LOAD_PATH, "docker_key_workflow_load")
        keygen = Path(shutil.which("ssh-keygen") or "")
        self.assertTrue(keygen.is_file())
        with tempfile.TemporaryDirectory(prefix="http-key-workflow-") as temporary:
            root = Path(temporary).resolve()
            home = root / "host"
            service = root / "service"
            project = root / "project"
            home.mkdir(mode=0o700)
            project.mkdir(mode=0o755)
            uid, gid = os.getuid(), root.stat().st_gid
            outcome = helper.synchronize_management_key(
                host_home=home,
                service_directory=service,
                host_uid=uid,
                host_gid=gid,
                service_uid=uid,
                service_gid=gid,
                authority_boundary=root,
                keygen=keygen,
            )
            management_public = (service / "id_ed25519.pub").read_bytes()

            fixture = DisposableKeyFixture(root)
            _laptop_private, laptop_public = fixture.generate(root / "laptop-key")
            (project / "laptop.pub").write_bytes(laptop_public)
            (project / "mgmt-server.pub").write_bytes(b"")
            (project / ".management-pubkeys").write_text(
                "mgmt-server.pub\n", encoding="ascii",
            )
            observed = loader.prepare_pubkeys(
                project,
                ssh_dir=service,
                dry_run=False,
                inject_management_key=True,
                allow_management_key_generation=False,
            )
            self.assertEqual("generated-host-and-copied-service", outcome["action"])
            self.assertIn(project / "mgmt-server.pub", observed)
            self.assertEqual(
                management_public, (project / "mgmt-server.pub").read_bytes(),
            )

    @unittest.skipUnless(
        sys.platform.startswith("linux") and os.geteuid() == 0,
        "real byte-exact deploy/hostlock/helper/11-load workflow requires Linux EUID0",
    )
    def test_real_deploy_entrypoint_drives_locked_helper_then_11_load(self) -> None:
        """Execute the byte-exact load entrypoint with finite hermetic host shims."""
        with tempfile.TemporaryDirectory(prefix="http-key-real-workflow-") as temporary:
            sandbox = Path(temporary).resolve()
            repository = sandbox / "repository"
            docker_dir = repository / "infra/docker"
            day0 = repository / "DAY0-Prepare"
            tools_dir = repository / "tools"
            bin_dir = sandbox / "commands"
            state = sandbox / "state"
            project = day0 / "workflow"
            for directory in (docker_dir, day0, tools_dir, bin_dir, state, project):
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)

            copied = (
                (DOCKER_ROOT / "deploy.sh", docker_dir / "deploy.sh"),
                (DOCKER_ROOT / "hostlock.py", docker_dir / "hostlock.py"),
                (HELPER_PATH, docker_dir / "management_ssh_key.py"),
                (LOAD_PATH, day0 / "11-load.py"),
                (ROOT / "tools/project_contract.py", tools_dir / "project_contract.py"),
                (ROOT / "tools/deployment_lock.py", tools_dir / "deployment_lock.py"),
                (ROOT / "tools/ztp_service_runtime.py", tools_dir / "ztp_service_runtime.py"),
            )
            for source, destination in copied:
                shutil.copyfile(source, destination)
                destination.chmod(stat.S_IMODE(source.stat().st_mode))
                self.assertEqual(source.read_bytes(), destination.read_bytes())

            runtime = docker_dir / "infra-runtime.conf"
            runtime.write_text(
                "HTTP_ZTP_PROJECT=workflow\n"
                "HTTP_ZTP_SCOPE=air\n"
                "HTTP_ZTP_SWITCH_SCOPE=eth\n"
                "HTTP_ZTP_MINI=disabled\n"
                "HTTP_ZTP_MONITOR_INTERVAL=30\n"
                "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=\n"
                "HTTP_ZTP_DHCP_RELAY_INGRESS=\n"
                "HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass\n"
                "TZ=Asia/Shanghai\n",
                encoding="ascii",
            )
            runtime.chmod(0o600)
            (project / "02-dhcp-subnet_config.csv").write_text(
                "subnet,netmask,range_start,range_end,routers\n",
                encoding="ascii",
            )
            fixture = DisposableKeyFixture(sandbox)
            _laptop_private, laptop_public = fixture.generate(sandbox / "laptop")
            (project / "laptop.pub").write_bytes(laptop_public)
            (project / "laptop.pub").chmod(0o644)
            (project / "mgmt-server.pub").write_bytes(b"")
            (project / "mgmt-server.pub").chmod(0o644)
            (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
            (project / ".management-pubkeys").chmod(0o644)
            host_home = state / "host"
            host_home.mkdir(mode=0o700)
            events = state / "events.jsonl"

            dispatcher = bin_dir / "dispatcher.py"
            dispatcher.write_text(textwrap.dedent(
                r'''#!/usr/bin/python3
                import importlib.util
                import json
                import os
                from pathlib import Path
                import subprocess
                import sys

                state = Path(os.environ["SSH_WORKFLOW_STATE"])
                repository = Path(os.environ["SSH_WORKFLOW_REPOSITORY"])
                events = state / "events.jsonl"

                def load(path, name):
                    spec = importlib.util.spec_from_file_location(name, path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[name] = module
                    spec.loader.exec_module(module)
                    return module

                def event(name, **fields):
                    with events.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"event": name, **fields}, sort_keys=True) + "\n")

                command = Path(sys.argv[0]).name
                arguments = sys.argv[1:]
                if command == "id":
                    if arguments == ["-u"]:
                        print("0")
                        raise SystemExit(0)
                    raise SystemExit(2)
                if command == "ss":
                    raise SystemExit(1)
                if command == "install":
                    event("install-observed", argv=arguments)
                    raise SystemExit(0)
                if command == "docker":
                    if arguments[:2] == ["inspect", "-f"]:
                        print("true")
                        raise SystemExit(0)
                    if arguments and arguments[0] == "exec":
                        if "/opt/http-ztp/hostctl.py" in arguments and "load" in arguments:
                            event("lifecycle-load", argv=arguments)
                            event("11-load-enter")
                            loader = load(
                                repository / "DAY0-Prepare/11-load.py", "ssh_workflow_loader",
                            )
                            loader.prepare_pubkeys(
                                repository / "DAY0-Prepare/workflow",
                                ssh_dir=state / "service",
                                dry_run=False,
                                inject_management_key=True,
                                allow_management_key_generation=False,
                            )
                            event("11-load-complete")
                        raise SystemExit(0)
                    raise SystemExit(0)
                if command != "python3":
                    raise SystemExit(97)
                if arguments and arguments[0] == "-":
                    os.execv("/usr/bin/python3", ["/usr/bin/python3", *arguments])
                if not arguments or Path(arguments[0]).name != "hostlock.py":
                    os.execv("/usr/bin/python3", ["/usr/bin/python3", *arguments])

                hostlock_path = Path(arguments[0])
                hostlock = load(hostlock_path, "ssh_workflow_hostlock")
                options = arguments[1:]
                if "--validate-local-daemon" in options:
                    raise SystemExit(0)
                if "--inspect-owned-id" in options:
                    print("a" * 64)
                    raise SystemExit(0)
                if "--prepare-control-auth" in options:
                    print('{"factory_records_active":false,"valid":true}')
                    raise SystemExit(0)
                if "--prepare-monitor-authority" in options or "--attest-monitor-authority" in options:
                    print('{"valid":true}')
                    raise SystemExit(0)
                if "--verify-preloaded-image" in options:
                    print(options[options.index("--verify-preloaded-image") + 1])
                    raise SystemExit(0)
                if "--owned-action" in options:
                    event("lifecycle-remove-clear", argv=options)
                    raise SystemExit(42)
                if "--" not in options:
                    raise SystemExit(98)
                separator = options.index("--")
                protected = options[separator + 1:]
                wait = int(options[options.index("--wait") + 1])
                event("hostlock-enter", argv=protected)

                def run(command, check=False):
                    expected_prefix = [
                        "/usr/bin/python3", "-B",
                        str(repository / "infra/docker/management_ssh_key.py"),
                    ]
                    if list(command[:3]) != expected_prefix or command[3:] not in (
                        ["reconcile"], ["check"],
                    ):
                        event("protected-other", argv=list(command))
                        return subprocess.CompletedProcess(command, 0)
                    helper = load(expected_prefix[2], "ssh_workflow_management_key")
                    helper_action = command[3]
                    event(f"helper-{helper_action}-enter")
                    operation = (
                        helper.synchronize_management_key
                        if helper_action == "reconcile" else helper.check_management_key
                    )
                    result = operation(
                        host_home=state / "host",
                        service_directory=state / "service",
                        host_uid=os.geteuid(),
                        host_gid=os.getegid(),
                        service_uid=os.geteuid(),
                        service_gid=os.getegid(),
                        authority_boundary=state,
                        keygen=Path("/usr/bin/ssh-keygen"),
                    )
                    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
                    event(f"helper-{helper_action}-complete", action=result["action"])
                    return subprocess.CompletedProcess(command, 0)

                result = hostlock.run_locked(
                    protected,
                    lock_path=state / "deployment.lock",
                    wait_seconds=wait,
                    runner=run,
                )
                raise SystemExit(result)
                '''
            ).lstrip(), encoding="utf-8")
            dispatcher.chmod(0o755)
            for name in ("python3", "docker", "id", "ss", "install"):
                (bin_dir / name).symlink_to(dispatcher.name)

            environment = {
                "HOME": os.fspath(sandbox / "empty-home"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.fspath(bin_dir) + ":/usr/bin:/bin",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "SSH_WORKFLOW_REPOSITORY": os.fspath(repository),
                "SSH_WORKFLOW_STATE": os.fspath(state),
            }
            result = subprocess.run(
                [os.fspath(docker_dir / "deploy.sh"), "load"],
                cwd=repository,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            records = [json.loads(line) for line in events.read_text().splitlines()]
            names = [record["event"] for record in records]
            self.assertLess(names.index("hostlock-enter"), names.index("helper-reconcile-enter"))
            self.assertLess(
                names.index("helper-reconcile-complete"), names.index("11-load-enter"),
            )
            self.assertLess(names.index("11-load-enter"), names.index("11-load-complete"))
            self.assertEqual(
                "generated-host-and-copied-service",
                next(
                    record["action"] for record in records
                    if record["event"] == "helper-reconcile-complete"
                ),
            )
            self.assertEqual(
                (state / "service/id_ed25519.pub").read_bytes(),
                (project / "mgmt-server.pub").read_bytes(),
            )

            def protected_snapshot() -> tuple[dict[str, tuple[object, ...]], ...]:
                return tuple(
                    DockerManagementSshKeyDirectTests.snapshot(path)
                    for path in (state / "host", state / "service", project)
                )

            before_doctor = protected_snapshot()
            doctor_start = len(records)
            doctor = subprocess.run(
                [os.fspath(docker_dir / "deploy.sh"), "doctor"],
                cwd=repository,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(0, doctor.returncode, doctor.stdout + doctor.stderr)
            self.assertEqual(before_doctor, protected_snapshot())
            records = [json.loads(line) for line in events.read_text().splitlines()]
            doctor_names = [record["event"] for record in records[doctor_start:]]
            self.assertIn("helper-check-enter", doctor_names)
            self.assertIn("helper-check-complete", doctor_names)
            self.assertNotIn("helper-reconcile-enter", doctor_names)
            self.assertFalse(any(name.startswith("lifecycle-") for name in doctor_names))

            immutable_image = "sha256:" + "b" * 64
            for action, arguments in (
                ("deploy", []),
                ("deploy-preloaded", [immutable_image]),
                ("deploy-project-preloaded", [immutable_image]),
            ):
                with self.subTest(real_entrypoint=action):
                    records = [json.loads(line) for line in events.read_text().splitlines()]
                    start = len(records)
                    attempt = subprocess.run(
                        [os.fspath(docker_dir / "deploy.sh"), action, *arguments],
                        cwd=repository,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertNotEqual(0, attempt.returncode)
                    records = [json.loads(line) for line in events.read_text().splitlines()]
                    action_names = [record["event"] for record in records[start:]]
                    self.assertIn("helper-reconcile-complete", action_names)
                    self.assertIn("lifecycle-remove-clear", action_names)
                    self.assertLess(
                        action_names.index("helper-reconcile-complete"),
                        action_names.index("lifecycle-remove-clear"),
                    )

    def test_supervisor_11_load_refuses_to_generate_a_missing_container_key(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_missing_load")
        with tempfile.TemporaryDirectory(prefix="http-key-no-container-gen-") as temporary:
            root = Path(temporary).resolve()
            ssh_dir = root / "service"
            before = list(root.rglob("*"))
            with self.assertRaisesRegex(loader.LoadError, "host|宿主|prepared|准备"):
                loader.ensure_management_key(
                    ssh_dir,
                    dry_run=False,
                    allow_generation=False,
                )
            self.assertEqual(before, list(root.rglob("*")))

    def test_supervisor_missing_half_or_invalid_pair_is_zero_write_and_never_keygen(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_supervisor_invalid")
        with tempfile.TemporaryDirectory(prefix="http-key-supervisor-invalid-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            _private, laptop_public = fixture.generate(root / "laptop")

            for state in (
                "missing", "private-only", "public-only", "rsa", "unsafe-mode",
                "unsafe-public-mode", "unsafe-directory-mode", "private-symlink",
                "private-hardlink",
            ):
                with self.subTest(state=state):
                    case = root / state
                    service = case / "service"
                    project = case / "project"
                    project.mkdir(mode=0o700, parents=True)
                    (project / "laptop.pub").write_bytes(laptop_public)
                    (project / "laptop.pub").chmod(0o644)
                    (project / "mgmt-server.pub").write_bytes(b"")
                    (project / "mgmt-server.pub").chmod(0o644)
                    (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
                    (project / ".management-pubkeys").chmod(0o644)
                    if state != "missing":
                        fixture.generate(
                            service, algorithm="rsa" if state == "rsa" else "ed25519",
                        )
                        private, public = fixture.pair(service)
                        if state == "private-only":
                            public.unlink()
                        elif state == "public-only":
                            private.unlink()
                        elif state == "unsafe-mode":
                            private.chmod(0o640)
                        elif state == "unsafe-public-mode":
                            public.chmod(0o664)
                        elif state == "unsafe-directory-mode":
                            service.chmod(0o750)
                        elif state == "private-symlink":
                            private.unlink()
                            private.symlink_to(public.name)
                        elif state == "private-hardlink":
                            os.link(private, service / "private-alias")
                    before_project = DockerManagementSshKeyDirectTests.snapshot(project)
                    before_service = DockerManagementSshKeyDirectTests.snapshot(service) \
                        if service.exists() else None
                    with mock.patch.object(
                        loader,
                        "_run_bounded_management_command",
                        side_effect=AssertionError("invalid pair must fail before ssh-keygen"),
                    ) as runner, mock.patch.object(
                        loader,
                        "_generate_native_management_key",
                        side_effect=AssertionError("Supervisor must not generate"),
                    ) as generator:
                            with self.assertRaises(loader.LoadError):
                                loader.prepare_pubkeys(
                                    project,
                                    ssh_dir=service,
                                    dry_run=False,
                                    inject_management_key=True,
                                    allow_management_key_generation=False,
                                )
                            runner.assert_not_called()
                            generator.assert_not_called()
                    self.assertEqual(
                        before_project, DockerManagementSshKeyDirectTests.snapshot(project),
                    )
                    self.assertEqual(
                        before_service,
                        DockerManagementSshKeyDirectTests.snapshot(service)
                        if service.exists() else None,
                    )

    def test_supervisor_mismatch_and_encrypted_pairs_fail_without_project_write(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_supervisor_crypto_invalid")
        with tempfile.TemporaryDirectory(prefix="http-key-supervisor-crypto-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            _private, laptop_public = fixture.generate(root / "laptop")
            for state in ("mismatch", "encrypted"):
                with self.subTest(state=state):
                    service = root / f"service-{state}"
                    fixture.generate(
                        service, passphrase="contract-secret" if state == "encrypted" else "",
                    )
                    if state == "mismatch":
                        _other_private, other_public = fixture.generate(root / "other")
                        (service / "id_ed25519.pub").write_bytes(other_public)
                        (service / "id_ed25519.pub").chmod(0o644)
                    project = root / f"project-{state}"
                    project.mkdir(mode=0o700)
                    (project / "laptop.pub").write_bytes(laptop_public)
                    (project / "laptop.pub").chmod(0o644)
                    (project / "mgmt-server.pub").write_bytes(b"")
                    (project / "mgmt-server.pub").chmod(0o644)
                    (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
                    (project / ".management-pubkeys").chmod(0o644)
                    before_project = DockerManagementSshKeyDirectTests.snapshot(project)
                    before_service = DockerManagementSshKeyDirectTests.snapshot(service)
                    with self.assertRaises(loader.LoadError):
                        loader.prepare_pubkeys(
                            project,
                            ssh_dir=service,
                            dry_run=False,
                            inject_management_key=True,
                            allow_management_key_generation=False,
                        )
                    self.assertEqual(
                        before_project, DockerManagementSshKeyDirectTests.snapshot(project),
                    )
                    self.assertEqual(
                        before_service, DockerManagementSshKeyDirectTests.snapshot(service),
                    )

    def test_loader_bounded_keygen_setup_failures_kill_and_reap(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_loader_bounded_setup")
        real_popen = subprocess.Popen
        real_selector = loader.selectors.DefaultSelector
        command = [
            "/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
            "-f", "/unused", "-C", "root@management-server",
        ]

        for fault in ("fileno", "set-blocking", "selector", "register"):
            with self.subTest(fault=fault):
                processes = []

                def launch(_argv, **kwargs):
                    kwargs.pop("pass_fds", None)
                    process = real_popen(["/bin/sleep", "60"], **kwargs)
                    processes.append(process)
                    if fault == "fileno":
                        process.stdout.fileno = mock.Mock(
                            side_effect=OSError("synthetic fileno fault"),
                        )
                    return process

                patches = [mock.patch.object(loader.subprocess, "Popen", side_effect=launch)]
                if fault == "set-blocking":
                    patches.append(mock.patch.object(
                        loader.os, "set_blocking", side_effect=OSError("synthetic setup fault"),
                    ))
                else:
                    class BrokenSelector:
                        def __init__(self):
                            if fault == "selector":
                                raise OSError("synthetic selector fault")
                            self.inner = real_selector()

                        def register(self, *_args, **_kwargs):
                            raise OSError("synthetic register fault")

                        def close(self):
                            self.inner.close()

                    patches.append(mock.patch.object(
                        loader.selectors, "DefaultSelector", BrokenSelector,
                    ))
                before_fds = len(os.listdir("/dev/fd"))
                with patches[0], patches[1]:
                    with self.assertRaisesRegex(loader.LoadError, "bounded|capture|setup"):
                        loader._run_bounded_management_command(command)
                self.assertEqual(1, len(processes))
                self.assertIsNotNone(processes[0].poll(), "failed setup leaked child")
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue(processes[0].stderr.closed)
                self.assertEqual(before_fds, len(os.listdir("/dev/fd")))

    def test_management_generation_authority_is_mandatory_and_supervisor_false(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_generation_authority")
        ensure_parameter = inspect.signature(loader.ensure_management_key).parameters[
            "allow_generation"
        ]
        prepare_parameter = inspect.signature(loader.prepare_pubkeys).parameters[
            "allow_management_key_generation"
        ]
        validate_parameter = inspect.signature(loader.validate_inputs).parameters[
            "allow_management_key_generation"
        ]
        self.assertIs(inspect.Parameter.empty, ensure_parameter.default)
        self.assertIs(inspect.Parameter.empty, prepare_parameter.default)
        self.assertIs(inspect.Parameter.empty, validate_parameter.default)
        with tempfile.TemporaryDirectory(prefix="http-key-native-gen-") as temporary:
            root = Path(temporary).resolve()
            for index, invalid in enumerate((1, "false", None)):
                with self.subTest(invalid_authority=invalid):
                    before = DockerManagementSshKeyDirectTests.snapshot(root)
                    with self.assertRaisesRegex(loader.LoadError, "literal bool|bool"):
                        loader.ensure_management_key(
                            root / f"invalid-{index}",
                            dry_run=False,
                            allow_generation=invalid,
                        )
                    self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(root))
            ssh_dir = root / "ssh"
            public = loader.ensure_management_key(
                ssh_dir, dry_run=False, allow_generation=True,
            )
            self.assertTrue(public.is_file())
            self.assertTrue((ssh_dir / "id_ed25519").is_file())

        load_source = LOAD_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--allow-management-key-generation", load_source)
        self.assertNotIn("HTTP_ZTP_ALLOW_MANAGEMENT_KEY_GENERATION", load_source)
        self.assertIn("allow_management_key_generation=False", load_source)
        self.assertIn(
            'runtime_backend_instance.name != "supervisor"', load_source,
        )
        for path in (
            DOCKER_ROOT / "entrypoint.py",
            DOCKER_ROOT / "hostctl.py",
        ):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("ssh-keygen", source)
            self.assertNotIn("allow_management_key_generation=True", source)

    def test_supervisor_main_attests_fixed_pair_and_project_before_any_template_write(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_main_prewrite_gate")
        with tempfile.TemporaryDirectory(prefix="http-key-main-gate-") as temporary:
            root = Path(temporary).resolve()
            project = root / "project"
            project.mkdir(mode=0o700)
            ssh_dir = Path("/root/.ssh")

            def arguments(selected_ssh_dir=ssh_dir):
                return SimpleNamespace(
                    project=project,
                    ssh_dir=selected_ssh_dir,
                    dry_run=False,
                    update_passwords=False,
                    skip_doca=False,
                    download_doca=False,
                    skip_generate=False,
                    deployment_scope="all",
                    switch_scope=None,
                )

            common = (
                mock.patch.object(loader, "parse_args", return_value=arguments()),
                mock.patch.object(loader, "runtime_os", return_value="Linux"),
                mock.patch.object(loader, "validate_deployment_scope_options", return_value="all"),
                mock.patch.object(loader, "validate_switch_scope_options", return_value="all"),
                mock.patch.object(
                    loader, "service_runtime_backend",
                    return_value=SimpleNamespace(name="supervisor"),
                ),
                mock.patch.object(loader, "validate_runtime_options"),
                mock.patch.object(loader, "acquire_deployment_lock", return_value=91),
                mock.patch.object(loader, "release_deployment_lock"),
                mock.patch.object(loader, "resolve_project", return_value=project),
                mock.patch.object(loader, "sync_marker_present", return_value=False),
                mock.patch.object(loader, "initialize_from_template"),
            )
            with common[0], common[1], common[2], common[3], common[4], common[5], \
                 common[6], common[7] as release_lock, common[8], common[9], \
                 common[10] as initialize, mock.patch.object(
                     loader, "ensure_management_key",
                     side_effect=loader.LoadError("service pair missing"),
                 ) as attest:
                before = DockerManagementSshKeyDirectTests.snapshot(project)
                self.assertEqual(1, loader.main([]))
                self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(project))
                initialize.assert_not_called()
                attest.assert_called_once_with(
                    ssh_dir, dry_run=False, allow_generation=False,
                )
                release_lock.assert_called_once_with(91)

            (project / "meaningful").write_text("sentinel", encoding="ascii")
            common = (
                mock.patch.object(loader, "parse_args", return_value=arguments()),
                mock.patch.object(loader, "runtime_os", return_value="Linux"),
                mock.patch.object(loader, "validate_deployment_scope_options", return_value="all"),
                mock.patch.object(loader, "validate_switch_scope_options", return_value="all"),
                mock.patch.object(
                    loader, "service_runtime_backend",
                    return_value=SimpleNamespace(name="supervisor"),
                ),
                mock.patch.object(loader, "validate_runtime_options"),
                mock.patch.object(loader, "acquire_deployment_lock", return_value=92),
                mock.patch.object(loader, "release_deployment_lock"),
                mock.patch.object(loader, "resolve_project", return_value=project),
                mock.patch.object(loader, "sync_marker_present", return_value=False),
                mock.patch.object(loader, "ensure_management_key", return_value=ssh_dir / "id_ed25519.pub"),
                mock.patch.object(
                    loader, "prepare_pubkeys",
                    side_effect=loader.LoadError("project management key mismatch"),
                ),
                mock.patch.object(loader, "initialize_from_template"),
            )
            with common[0], common[1], common[2], common[3], common[4], common[5], \
                 common[6], common[7], common[8], common[9], common[10], \
                 common[11] as project_attest, common[12] as initialize:
                before = DockerManagementSshKeyDirectTests.snapshot(project)
                self.assertEqual(1, loader.main([]))
                self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(project))
                initialize.assert_not_called()
                self.assertTrue(project_attest.call_args.kwargs["dry_run"])
                self.assertFalse(
                    project_attest.call_args.kwargs["allow_management_key_generation"],
                )

            overridden = arguments(root / "operator-selected")
            with mock.patch.object(loader, "parse_args", return_value=overridden), \
                 mock.patch.object(loader, "runtime_os", return_value="Linux"), \
                 mock.patch.object(loader, "validate_deployment_scope_options", return_value="all"), \
                 mock.patch.object(loader, "validate_switch_scope_options", return_value="all"), \
                 mock.patch.object(
                     loader, "service_runtime_backend",
                     return_value=SimpleNamespace(name="supervisor"),
                 ), mock.patch.object(loader, "validate_runtime_options"), \
                 mock.patch.object(loader, "ensure_management_key") as attest:
                self.assertEqual(1, loader.main([]))
                attest.assert_not_called()

    def test_nonempty_matching_project_key_is_noop_and_mismatch_is_zero_write(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_project_binding")
        with tempfile.TemporaryDirectory(prefix="http-key-project-binding-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            _private, service_public = fixture.generate(service, comment="service")
            laptop_dir = root / "laptop"
            _laptop_private, laptop_public = fixture.generate(laptop_dir, comment="laptop")

            for matching in (True, False):
                with self.subTest(matching=matching):
                    project = root / ("matching" if matching else "mismatch")
                    project.mkdir(mode=0o700)
                    (project / ".management-pubkeys").write_text(
                        "mgmt-server.pub\n", encoding="ascii",
                    )
                    (project / ".management-pubkeys").chmod(0o644)
                    (project / "laptop.pub").write_bytes(laptop_public)
                    (project / "laptop.pub").chmod(0o644)
                    management = project / "mgmt-server.pub"
                    if matching:
                        fields = service_public.strip().split()
                        management.write_bytes(b" ".join(fields[:2]) + b" project-comment\n")
                    else:
                        _other_private, other_public = fixture.generate(
                            root / "other", comment="other",
                        )
                        management.write_bytes(other_public)
                    management.chmod(0o644)
                    before = DockerManagementSshKeyDirectTests.snapshot(project)
                    if matching:
                        observed = loader.prepare_pubkeys(
                            project,
                            ssh_dir=service,
                            dry_run=False,
                            inject_management_key=True,
                            allow_management_key_generation=False,
                        )
                        self.assertIn(management, observed)
                    else:
                        with self.assertRaisesRegex(loader.LoadError, "匹配|mismatch|管理服务器"):
                            loader.prepare_pubkeys(
                                project,
                                ssh_dir=service,
                                dry_run=False,
                                inject_management_key=True,
                                allow_management_key_generation=False,
                            )
                    self.assertEqual(
                        before, DockerManagementSshKeyDirectTests.snapshot(project),
                    )

    def test_marker_and_placeholder_are_exact_safe_managed_objects(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_project_marker")
        with tempfile.TemporaryDirectory(prefix="http-key-project-marker-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            fixture.generate(service)
            _private, laptop_public = fixture.generate(root / "laptop")

            def base_project(label: str) -> Path:
                project = root / label
                project.mkdir(mode=0o700)
                (project / "laptop.pub").write_bytes(laptop_public)
                (project / "laptop.pub").chmod(0o644)
                (project / "mgmt-server.pub").touch(mode=0o644)
                return project

            missing_marker = base_project("missing-marker")
            before = DockerManagementSshKeyDirectTests.snapshot(missing_marker)
            with self.assertRaisesRegex(loader.LoadError, "marker|管理.*标记"):
                loader.prepare_pubkeys(
                    missing_marker,
                    ssh_dir=service,
                    dry_run=False,
                    inject_management_key=True,
                    allow_management_key_generation=False,
                )
            self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(missing_marker))

            unsafe = base_project("unsafe-placeholder")
            marker = unsafe / ".management-pubkeys"
            marker.write_text("mgmt-server.pub\n", encoding="ascii")
            marker.chmod(0o644)
            placeholder = unsafe / "mgmt-server.pub"
            placeholder.unlink()
            placeholder.symlink_to(unsafe / "laptop.pub")
            before = DockerManagementSshKeyDirectTests.snapshot(unsafe)
            with self.assertRaisesRegex(loader.LoadError, "symlink|link|regular|安全"):
                loader.prepare_pubkeys(
                    unsafe,
                    ssh_dir=service,
                    dry_run=False,
                    inject_management_key=True,
                    allow_management_key_generation=False,
                )
            self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(unsafe))

    def test_project_marker_placeholder_metadata_and_exact_content_matrix(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_project_metadata")
        with tempfile.TemporaryDirectory(prefix="http-key-project-metadata-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            fixture.generate(service)
            _private, laptop_public = fixture.generate(root / "laptop")

            def make_project(label: str) -> Path:
                project = root / label
                project.mkdir(mode=0o700)
                (project / "laptop.pub").write_bytes(laptop_public)
                (project / "laptop.pub").chmod(0o644)
                (project / "mgmt-server.pub").write_bytes(b"")
                (project / "mgmt-server.pub").chmod(0o644)
                (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
                (project / ".management-pubkeys").chmod(0o644)
                return project

            def reject(label: str, mutate, pattern: str) -> None:
                project = make_project(label)
                cleanup = mutate(project)
                before = DockerManagementSshKeyDirectTests.snapshot(project)
                try:
                    with self.assertRaisesRegex(loader.LoadError, pattern):
                        loader.prepare_pubkeys(
                            project,
                            ssh_dir=service,
                            dry_run=False,
                            inject_management_key=True,
                            allow_management_key_generation=False,
                        )
                    self.assertEqual(
                        before, DockerManagementSshKeyDirectTests.snapshot(project),
                    )
                finally:
                    if callable(cleanup):
                        cleanup()

            reject(
                "marker-extra", lambda project: (project / ".management-pubkeys").write_bytes(
                    b"mgmt-server.pub\nother.pub\n",
                ), "marker|exact|管理.*标记",
            )
            reject(
                "marker-mode", lambda project: (project / ".management-pubkeys").chmod(0o664),
                "marker|mode|permission|安全",
            )
            reject(
                "placeholder-mode", lambda project: (project / "mgmt-server.pub").chmod(0o600),
                "placeholder|mode|permission|管理",
            )

            def marker_hardlink(project):
                os.link(project / ".management-pubkeys", project / "marker-alias")

            def placeholder_hardlink(project):
                os.link(project / "mgmt-server.pub", project / "placeholder-alias")

            def placeholder_fifo(project):
                target = project / "mgmt-server.pub"
                target.unlink()
                os.mkfifo(target, 0o644)

            reject("marker-hardlink", marker_hardlink, "marker|link|安全")
            reject("placeholder-hardlink", placeholder_hardlink, "placeholder|link|管理")
            reject("placeholder-fifo", placeholder_fifo, "placeholder|regular|FIFO|管理")

            foreign = make_project("foreign-owner")
            before = DockerManagementSshKeyDirectTests.snapshot(foreign)
            with mock.patch.object(loader.os, "geteuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(loader.LoadError, "owner|uid|管理|安全"):
                    loader.prepare_pubkeys(
                        foreign,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(foreign))

            foreign_group = make_project("foreign-group")
            before = DockerManagementSshKeyDirectTests.snapshot(foreign_group)
            with mock.patch.object(loader.os, "getegid", return_value=os.getegid() + 10_000):
                with self.assertRaisesRegex(loader.LoadError, "owner|gid|管理|安全"):
                    loader.prepare_pubkeys(
                        foreign_group,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(foreign_group))

    def test_static_public_keys_are_held_and_structurally_validated(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_static_held")
        with tempfile.TemporaryDirectory(prefix="http-key-static-held-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            fixture.generate(service)
            _private, valid = fixture.generate(root / "laptop")

            def make_project(label: str, payload: bytes) -> Path:
                project = root / label
                project.mkdir(mode=0o700)
                (project / "laptop.pub").write_bytes(payload)
                (project / "laptop.pub").chmod(0o644)
                (project / "mgmt-server.pub").write_bytes(b"")
                (project / "mgmt-server.pub").chmod(0o644)
                (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
                (project / ".management-pubkeys").chmod(0o644)
                return project

            fields = valid.split(b" ", 2)
            malformed = (
                b"ssh-rsa " + fields[1] + b" mislabeled\n",
                b"ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed") + b" truncated\n",
                b"ssh-ed25519 " + fields[1] + b" unsafe\tcomment\n",
            )
            for index, payload in enumerate(malformed):
                project = make_project(f"invalid-static-{index}", payload)
                before = DockerManagementSshKeyDirectTests.snapshot(project)
                with self.assertRaises(loader.LoadError):
                    loader.prepare_pubkeys(
                        project,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
                self.assertEqual(before, DockerManagementSshKeyDirectTests.snapshot(project))

    def test_project_and_service_rebind_or_metadata_drift_never_publishes(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_project_race")
        with tempfile.TemporaryDirectory(prefix="http-key-project-race-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            fixture.generate(service)
            _private, laptop_public = fixture.generate(root / "laptop")

            def project(label: str) -> Path:
                target = root / label
                target.mkdir(mode=0o700)
                (target / "laptop.pub").write_bytes(laptop_public)
                (target / "laptop.pub").chmod(0o644)
                (target / "mgmt-server.pub").write_bytes(b"")
                (target / "mgmt-server.pub").chmod(0o644)
                (target / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
                (target / ".management-pubkeys").chmod(0o644)
                return target

            drift_project = project("service-drift")
            before_project = DockerManagementSshKeyDirectTests.snapshot(drift_project)

            def drift_service(stage: str) -> None:
                if stage == "service-public-held":
                    public = service / "id_ed25519.pub"
                    public.write_bytes(public.read_bytes() + b"changed-comment\n")

            with mock.patch.object(loader, "_management_key_checkpoint", side_effect=drift_service):
                with self.assertRaisesRegex(loader.LoadError, "changed|drift|stable|变化"):
                    loader.prepare_pubkeys(
                        drift_project,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(
                before_project, DockerManagementSshKeyDirectTests.snapshot(drift_project),
            )

            # Restore a valid service pair, then replace the held empty leaf by name.
            shutil.rmtree(service)
            fixture.generate(service)
            rebind_project = project("placeholder-rebind")

            def rebind_placeholder(stage: str) -> None:
                if stage == "project-placeholder-held":
                    placeholder = rebind_project / "mgmt-server.pub"
                    placeholder.rename(rebind_project / "held-placeholder")
                    placeholder.write_bytes(b"")
                    placeholder.chmod(0o644)

            with mock.patch.object(
                loader, "_management_key_checkpoint", side_effect=rebind_placeholder,
            ):
                with self.assertRaisesRegex(loader.LoadError, "rebind|changed|identity|变化"):
                    loader.prepare_pubkeys(
                        rebind_project,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(b"", (rebind_project / "mgmt-server.pub").read_bytes())

            static_drift = project("static-drift")

            def drift_laptop_late(stage: str) -> None:
                if stage == "project-placeholder-held":
                    (static_drift / "laptop.pub").write_bytes(
                        (service / "id_ed25519.pub").read_bytes(),
                    )

            with mock.patch.object(
                loader, "_management_key_checkpoint", side_effect=drift_laptop_late,
            ):
                with self.assertRaisesRegex(loader.LoadError, "changed|drift|stable|变化"):
                    loader.prepare_pubkeys(
                        static_drift,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(b"", (static_drift / "mgmt-server.pub").read_bytes())

            late_service_drift = project("late-service-drift")

            def drift_service_late(stage: str) -> None:
                if stage == "project-placeholder-held":
                    public = service / "id_ed25519.pub"
                    public.write_bytes(public.read_bytes() + b" late-drift")

            with mock.patch.object(
                loader, "_management_key_checkpoint", side_effect=drift_service_late,
            ):
                with self.assertRaisesRegex(loader.LoadError, "changed|drift|stable|变化"):
                    loader.prepare_pubkeys(
                        late_service_drift,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(b"", (late_service_drift / "mgmt-server.pub").read_bytes())

    def test_project_publication_uses_original_service_bytes_and_revalidates(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_project_exact_bytes")
        with tempfile.TemporaryDirectory(prefix="http-key-project-original-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            _service_private, service_public_bytes = fixture.generate(
                service, comment="exact-original-comment",
            )
            _private, laptop_public = fixture.generate(root / "laptop")
            project = root / "project"
            project.mkdir(mode=0o700)
            (project / "laptop.pub").write_bytes(laptop_public)
            (project / "laptop.pub").chmod(0o644)
            (project / "mgmt-server.pub").write_bytes(b"")
            (project / "mgmt-server.pub").chmod(0o644)
            (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
            (project / ".management-pubkeys").chmod(0o644)
            expected = service_public_bytes
            loader.prepare_pubkeys(
                project,
                ssh_dir=service,
                dry_run=False,
                inject_management_key=True,
                allow_management_key_generation=False,
            )
            self.assertEqual(expected, (project / "mgmt-server.pub").read_bytes())
            self.assertNotEqual(
                fingerprint(expected), fingerprint(laptop_public),
                "laptop and management identities must remain distinct",
            )

    def test_project_publication_rejects_postwrite_drift_and_project_rebind(self) -> None:
        loader = load_module(LOAD_PATH, "docker_key_project_postwrite")
        with tempfile.TemporaryDirectory(prefix="http-key-project-postwrite-") as temporary:
            root = Path(temporary).resolve()
            fixture = DisposableKeyFixture(root)
            service = root / "service"
            fixture.generate(service)
            _private, laptop_public = fixture.generate(root / "laptop")

            def make_project(label: str) -> Path:
                project = root / label
                project.mkdir(mode=0o700)
                (project / "laptop.pub").write_bytes(laptop_public)
                (project / "laptop.pub").chmod(0o644)
                (project / "mgmt-server.pub").write_bytes(b"")
                (project / "mgmt-server.pub").chmod(0o644)
                (project / ".management-pubkeys").write_bytes(b"mgmt-server.pub\n")
                (project / ".management-pubkeys").chmod(0o644)
                return project

            drift = make_project("postwrite-drift")

            def drift_after_publish(stage: str) -> None:
                if stage == "project-management-published":
                    (drift / "mgmt-server.pub").chmod(0o600)

            with mock.patch.object(
                loader, "_management_key_checkpoint", side_effect=drift_after_publish,
            ):
                with self.assertRaisesRegex(loader.LoadError, "changed|mode|drift|变化"):
                    loader.prepare_pubkeys(
                        drift,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )

            rebound = make_project("project-rebind")
            original = root / "project-original"

            def rebind_directory(stage: str) -> None:
                if stage == "project-placeholder-held":
                    rebound.rename(original)
                    rebound.mkdir(mode=0o700)
                    (rebound / "mgmt-server.pub").write_bytes(b"")
                    (rebound / "mgmt-server.pub").chmod(0o644)

            with mock.patch.object(
                loader, "_management_key_checkpoint", side_effect=rebind_directory,
            ):
                with self.assertRaisesRegex(loader.LoadError, "directory|rebind|changed|变化"):
                    loader.prepare_pubkeys(
                        rebound,
                        ssh_dir=service,
                        dry_run=False,
                        inject_management_key=True,
                        allow_management_key_generation=False,
                    )
            self.assertEqual(b"", (rebound / "mgmt-server.pub").read_bytes())
            self.assertEqual(b"", (original / "mgmt-server.pub").read_bytes())

    def test_manifest_and_real_environment_cover_direct_and_cross_script_flow(self) -> None:
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        module = "test_cases.test_docker_management_ssh_key"
        suites = {
            suite["id"]: suite["tests"] for suite in manifest["test_suites"]
        }
        self.assertIn(module, suites["deployment-runtime"])
        helper_rule = [
            rule for rule in manifest["test_rules"]
            if any(
                Path(HELPER_PATH.relative_to(ROOT)).match(pattern)
                for pattern in rule["paths"]
            )
        ]
        self.assertTrue(helper_rule)
        self.assertTrue(any(module in rule["tests"] for rule in helper_rule))
        workflows = [
            workflow for workflow in manifest["workflows"]
            if module in workflow["tests"]
        ]
        self.assertTrue(any(
            "infra/docker/deploy.sh" in workflow["members"]
            and "infra/docker/hostlock.py" in workflow["members"]
            and "DAY0-Prepare/11-load.py" in workflow["members"]
            and "infra/docker/management_ssh_key.py" in workflow["members"]
            for workflow in workflows
        ))
        ssh_workflow = next(
            workflow for workflow in manifest["workflows"]
            if workflow["id"] == "docker_management_ssh_key_lifecycle"
        )
        self.assertTrue({
            ".dockerignore",
            "infra/docker/Dockerfile.dockerignore",
            "infra/docker/entrypoint.py",
            "infra/docker/hostctl.py",
            "tools/_package_common.py",
            "tools/package-project-image.py",
            "tools/project_contract.py",
            "tools/sync-code.py",
            "tools/tar-for-upload.py",
            "tools/collect-ztp-diagnostics.py",
        }.issubset(ssh_workflow["members"]))
        self.assertTrue({
            "test_cases.test_project_contracts",
            "test_cases.test_ztp_container_runtime",
            "test_cases.test_upload_package_contract",
            "test_cases.test_diagnostic_bundle",
            "test_cases.test_project_image_bundle",
            "test_cases.test_public_repository_contract",
        }.issubset(ssh_workflow["tests"]))
        real = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(encoding="utf-8")
        self.assertIn("TC-REAL-DOCKER-MANAGEMENT-SSH-KEY-001", real)
        self.assertIn("host→service", real)
        self.assertIn("service→host", real)
        self.assertIn("fingerprint", real.casefold())
        self.assertNotIn("private key bytes", real.casefold())
        for boundary in (
            "pre-publication",
            "pre-cleanup",
            "Linux has no conditional unlink-by-inode API",
            "non-cooperating concurrent root is outside this trust boundary",
            "private mount namespace is not used",
            "already has strictly stronger capabilities",
            "adds no capability",
        ):
            with self.subTest(real_environment_boundary=boundary):
                self.assertIn(boundary, real)

if __name__ == "__main__":
    unittest.main()
