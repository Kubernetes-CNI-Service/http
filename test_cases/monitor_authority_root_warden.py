#!/usr/bin/env python3
"""PID-1 warden for the Linux Monitor authority lifecycle proof.

This program makes a deliberately narrow claim: it is a
correctness and accidental-damage containment harness for reviewed project code
on a disposable GitHub-hosted VM.  It is NOT an adversarial-PR sandbox.  It does
not turn a privileged workflow into a safe venue for attacker-controlled code.

The workflow has three roles.  The outer launcher retains authority only long
enough to enter new mount, PID, and network namespaces.  This module is PID 1,
keeps the host references needed for final checks, constructs and enters the
private root, and seals evidence.  The repository runner is the sole child and
is started through a close-all boundary.  It can produce only raw lifecycle
artifacts; this warden alone verifies them and constructs the PASS receipt.

No function in this file is a substitute for the governed Ubuntu run.  All
unexpected descriptors, mounts, commands, evidence fields, descendants, or
source changes fail closed.
"""

from __future__ import annotations

import argparse
import ast
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import Iterable, Mapping, Sequence


PR_SET_CHILD_SUBREAPER = 36
PR_SET_DUMPABLE = 4
PR_CAPBSET_DROP = 24
PR_SET_SECUREBITS = 28
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
PR_CAP_AMBIENT_CLEAR_ALL = 4
SECBIT_NOROOT = 1
SECBIT_NOROOT_LOCKED = 2
LINUX_CAPABILITY_VERSION_3 = 0x20080522
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MNT_DETACH = 2
CLONE_NEWNS = 0x00020000
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004

FORBIDDEN_RETURN_CODE = 99
MAX_RECEIPT_BYTES = 64 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_SUPERVISOR_STREAM_BYTES = 1024 * 1024
SUPERVISOR_DEADLINE_SECONDS = 600.0
DESCENDANT_REAP_SECONDS = 3.0

TREE_ID_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SAFE_COMMAND_NAME = re.compile(r"[a-z0-9][a-z0-9.-]*\Z")

SUPERVISOR_ARGUMENTS = (
    "/source/test_cases/run_monitor_authority_entrypoints.sh",
    "--execute-private-fixtures",
)
SUPERVISOR_ENVIRONMENT = {
    "COMMAND_ROOT": "/commands",
    "EVIDENCE_ROOT": "/evidence",
    "FIXTURE_ROOT": "/fixture",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/commands",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
}
WARDEN_ENVIRONMENT = {
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
}

REQUIRED_WORKFLOW_PHASES = (
    "supervisor-preconditions",
    "argv-collision-matrix",
    "bad-payload-cgi-503",
    "recovery-marker-routine-rejection",
    "native-stopped-writer-matrix",
    "native-lifecycle-cgi-200",
    "docker-writer-stop-remove",
    "recovery-decision-enum",
    "teardown-preservation",
    "postflight-attestation",
)
RECOVERY_DECISION_TOKENS = (
    "attest-valid",
    "recovery-in-progress",
    "recovery-committed-cleanup-pending",
    "restart-allowed:complete;reset-invalid-cache=false",
    "restart-allowed:complete;reset-invalid-cache=true",
    "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false",
    "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=true",
    "restart-blocked:marker-retained;reset-invalid-cache=false",
    "restart-blocked:marker-retained;reset-invalid-cache=true",
    "restart-blocked:marker-authority-uncertain;reset-invalid-cache=false",
    "restart-blocked:marker-authority-uncertain;reset-invalid-cache=true",
)
DOCKER_IDENTIFIER = "a" * 64
MANAGED_SERVICES = (
    "apache2",
    "dhcpd",
    "ztp-monitor",
    "switch-collection",
    "manual-ztp",
    "rsyslog",
    "logrotate",
    "runtime-guardian",
)

# Each leaf has a finite set of complete argument vectors.  An empty set means
# the name is intentionally present only to prove that every invocation is
# forbidden (dpkg-query/apt-get in this scenario).
ALLOWED_COMMAND_ARGV: Mapping[str, frozenset[tuple[str, ...]]] = {
    "apache2ctl": frozenset({("configtest",)}),
    "apt-get": frozenset(),
    "docker": frozenset({
        ("context", "show"),
        ("context", "inspect", "default"),
        ("info", "--format", "{{json .}}"),
        ("container", "inspect", "http-ztp"),
        ("container", "inspect", DOCKER_IDENTIFIER),
        ("stop", "--time", "30", DOCKER_IDENTIFIER),
        ("rm", DOCKER_IDENTIFIER),
    }),
    "dpkg": frozenset({
        ("--print-architecture",),
        ("-s", "apache2"),
        ("-s", "isc-dhcp-server"),
        ("-s", "lldpd"),
    }),
    "dpkg-query": frozenset(),
    "ss": frozenset({("-ltnp",)}),
    "supervisord": frozenset({
        ("-n", "-c", "/etc/supervisor/supervisord.conf"),
    }),
    "systemctl": frozenset({
        ("show", "--property=ActiveState", "--value", "apache2"),
        ("stop", "apache2"),
        ("start", "apache2"),
        ("is-active", "--quiet", "systemd-resolved"),
        ("is-active", "--quiet", "systemd-timesyncd"),
    }),
    "supervisorctl": frozenset(
        {("status",)}
        | {("status", service) for service in MANAGED_SERVICES}
        | {
            (action, service)
            for action in ("start", "stop", "pid")
            for service in MANAGED_SERVICES
        }
    ),
}

# The runner reaches these nine ambiguous/colliding vectors in this exact
# order.  Recording the complete vectors prevents nine repetitions of one
# refusal from being mistaken for coverage of the collision matrix.
FORBIDDEN_COMMAND_ARGV_SEQUENCE = (
    ("docker", ("context show",)),
    ("docker", ("context", "show", "")),
    ("systemctl", ("stop apache2",)),
    ("systemctl", ("stop", " apache2")),
    ("dpkg", ("-s", "apache2", "extra")),
    ("supervisord", ("-n -c /etc/supervisor/supervisord.conf",)),
    ("supervisorctl", ("status", "extra")),
    ("ss", ("-ltnp", "")),
    ("apache2ctl", ("config", "test")),
)

INITIAL_SERVICE_STATE = b'{"schema_version":1}\n'
CONTROL_AUTH_HELPER_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)
APACHE_PUBLIC_BOUNDARY_SHA256 = (
    "616629333ac16e4bc0c076a499d98864959372b5a24bee3c0d4257c1aa9d15fb"
)

# These are copied by descriptor into the root-owned one-component PATH.  The
# explicit tuple is also emitted into evidence; adding a utility is a governed
# source change rather than an inherited host-PATH expansion.  `touch`, curl,
# ssh, wget, and nc are intentionally absent.
UTILITY_SOURCES: Mapping[str, str] = {
    "awk": "/usr/bin/mawk",
    "basename": "/usr/bin/basename",
    "bash": "/usr/bin/bash",
    "cat": "/usr/bin/cat",
    "chmod": "/usr/bin/chmod",
    "chown": "/usr/bin/chown",
    "cmp": "/usr/bin/cmp",
    "cp": "/usr/bin/cp",
    "cut": "/usr/bin/cut",
    "date": "/usr/bin/date",
    "dirname": "/usr/bin/dirname",
    "env": "/usr/bin/env",
    "find": "/usr/bin/find",
    "findmnt": "/usr/bin/findmnt",
    "flock": "/usr/bin/flock",
    "grep": "/usr/bin/grep",
    "head": "/usr/bin/head",
    "hostname": "/usr/bin/hostname",
    "id": "/usr/bin/id",
    "install": "/usr/bin/install",
    "ln": "/usr/bin/ln",
    "mkdir": "/usr/bin/mkdir",
    "mkfifo": "/usr/bin/mkfifo",
    "mktemp": "/usr/bin/mktemp",
    "mv": "/usr/bin/mv",
    "od": "/usr/bin/od",
    "python3": "/usr/bin/python3.12",
    "readlink": "/usr/bin/readlink",
    "realpath": "/usr/bin/realpath",
    "rm": "/usr/bin/rm",
    "rmdir": "/usr/bin/rmdir",
    "sed": "/usr/bin/sed",
    "setpriv": "/usr/bin/setpriv",
    "sha256sum": "/usr/bin/sha256sum",
    "sort": "/usr/bin/sort",
    "ssh-keygen": "/usr/bin/ssh-keygen",
    "stat": "/usr/bin/stat",
    "sync": "/usr/bin/sync",
    "tail": "/usr/bin/tail",
    "tee": "/usr/bin/tee",
    "timeout": "/usr/bin/timeout",
    "tr": "/usr/bin/tr",
    "uname": "/usr/bin/uname",
    "wc": "/usr/bin/wc",
}
COMMAND_LEAF_NAMES = frozenset(UTILITY_SOURCES) | frozenset(ALLOWED_COMMAND_ARGV)
ABSOLUTE_COMMAND_BINDINGS: Mapping[str, str] = {
    "/usr/bin/bash": "bash",
    "/usr/bin/env": "env",
    "/usr/bin/python3": "python3",
    "/usr/bin/ssh-keygen": "ssh-keygen",
    "/usr/bin/supervisord": "supervisord",
    "/usr/bin/timeout": "timeout",
    "/usr/sbin/apache2ctl": "apache2ctl",
}

HOST_SENTINEL_PATHS = (
    "test_cases/monitor_authority_root_warden.py",
    "test_cases/monitor_authority_source_guard.py",
    "test_cases/run_monitor_authority_entrypoints.sh",
    "tools/control-auth.py",
    "monitor/ztp-monitor-control.cgi",
    "infra/infra-setup.sh",
    "infra/infra-teardown.sh",
    "infra/docker/deploy.sh",
    "infra/docker/hostlock.py",
    "infra/docker/activate.py",
)

HOSTILE_TEST_CASES = frozenset({
    "leak-host-namespace-fd",
    "leak-host-source-fd",
    "leak-host-sentinel-fd",
    "nested-writable-mount",
    "host-device-bind",
    "host-sys-bind",
    "double-fork-setsid-survivor",
    "forged-final-receipt",
})

REQUIRED_PRIVATE_EVIDENCE_NAMES = frozenset({
    "operation-results.jsonl",
    "infra-audit-map.jsonl",
    "postflight-attest.out",
    "postflight-attest.err",
    "postflight-attest.invocation.json",
    "pre-teardown-attest.out",
    "pre-teardown-attest.err",
    "pre-teardown-attest.invocation.json",
    "authority-docker-container.jsonl",
    "authority-docker-native.jsonl",
    "authority-postflight.jsonl",
    "collision.stderr",
    "collision.stdout",
    "command-events.jsonl",
    "command-manifest.json",
    "docker-recover.err",
    "docker-recover.out",
    "events.log",
    "expected-tree-id",
    "phases.jsonl",
    "recovery-decisions.json",
    "service-state.json",
    "source-manifest.json",
    "teardown-before.json",
    "teardown-after.json",
    "teardown.err",
    "teardown.out",
    *{
        name
        for index in range(10)
        for name in (
            f"cgi-bad-{index}.out", f"cgi-bad-{index}.out.err",
            f"cgi-bad-{index}.invocation.json",
        )
    },
    *{f"health-{index}.out" for index in range(10)},
    *{f"bad-payload-{index}.bin" for index in range(10)},
    *{f"authority-bad-{index}.jsonl" for index in range(10)},
    *{
        name
        for index in range(3)
        for name in (
            f"cgi-good-{index}.out", f"cgi-good-{index}.out.err",
            f"cgi-good-{index}.invocation.json",
        )
    },
    *{f"authority-native-{state}.jsonl" for state in ("active", "inactive", "failed")},
    *{f"authority-stop-{mode}.jsonl" for mode in ("stop-fail", "show-fail", "stay-active")},
    *{
        f"authority-marker-{phase}.jsonl"
        for phase in (
            "recovery-in-progress", "recovery-committed-cleanup-pending",
        )
    },
    *{
        name
        for phase in (
            "recovery-in-progress", "recovery-committed-cleanup-pending",
        )
        for name in (
            f"marker-{phase}.out", f"marker-{phase}.err",
            f"marker-reset-{phase}.out", f"marker-reset-{phase}.err",
            f"marker-after-{phase}.out", f"marker-after-{phase}.err",
        )
    },
    *{
        name
        for state in ("active", "inactive", "failed")
        for name in (
            f"native-{state}.out", f"native-{state}.err",
            f"native-attest-{state}.out", f"native-attest-{state}.err",
        )
    },
    *{
        name
        for mode in ("stop-fail", "show-fail", "stay-active")
        for name in (f"stop-{mode}.out", f"stop-{mode}.err")
    },
})

RECOVERY_RESET_WARNING = (
    b"WARNING: explicit Monitor authority recovery reset invalid cache state; "
    b"review the accepted www-data denial residual.\n"
)
NATIVE_STOPPED_WARNING = (
    b"[WARN] Apache stopped for explicit Monitor cache authority recovery.\n"
)
NATIVE_RECOVERY_COMPLETE = (
    b"[OK] explicit Monitor cache authority recovery completed.\n"
)
TEARDOWN_COMPLETE = b"[OK]    infra-teardown.sh completed.\n"
CGI_AUTHORITY_DIAGNOSTIC = b"monitor-control-auth: cache-authority\n"


class WardenError(RuntimeError):
    """A fail-closed violation of the root-workflow evidence boundary."""


def _factory_control_users_from_pinned_helper(helper_payload: bytes) -> bytes:
    """Extract the sole public bootstrap verifier authority without executing it."""

    if (
        type(helper_payload) is not bytes
        or hashlib.sha256(helper_payload).hexdigest() != CONTROL_AUTH_HELPER_SHA256
    ):
        raise WardenError("control-auth helper bytes do not match the pinned authority")
    try:
        module = ast.parse(helper_payload.decode("utf-8"), filename="control-auth.py")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise WardenError("pinned control-auth helper is not parseable Python") from exc
    assignments = [
        node
        for node in module.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "FACTORY_RECORDS"
    ]
    if len(assignments) != 1:
        raise WardenError("pinned control-auth helper has no unique factory authority")
    try:
        records = ast.literal_eval(assignments[0].value)
    except (ValueError, TypeError, SyntaxError) as exc:
        raise WardenError("pinned factory authority is not a literal byte string") from exc
    if type(records) is not bytes or len(records) > 4096:
        raise WardenError("pinned factory authority has an invalid type or size")
    lines = records.splitlines(keepends=True)
    if len(lines) != 2:
        raise WardenError("pinned factory authority must contain exactly two records")
    for line, username in zip(lines, (b"nvis", b"cumulus")):
        prefix = username + b":"
        if not line.endswith(b"\n") or not line.startswith(prefix):
            raise WardenError("pinned factory authority username/order changed")
        verifier = line[len(prefix):-1]
        if re.fullmatch(rb"\$2y\$12\$[./A-Za-z0-9]{53}", verifier) is None:
            raise WardenError("pinned factory authority verifier is malformed")
    return records


class ForbiddenCommand(WardenError):
    """Exact result used by every finite-command dispatcher collision."""

    returncode = FORBIDDEN_RETURN_CODE

    def __init__(self) -> None:
        super().__init__("FORBIDDEN")


@dataclass(frozen=True)
class MountRecord:
    target: str
    filesystem_type: str
    options: frozenset[str]
    propagation: str


@dataclass(frozen=True)
class HostSentinel:
    relative_path: str
    descriptor: int
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    sha256: str


@dataclass(frozen=True)
class WardenConfig:
    tree_id: str
    source_root: Path
    private_root: Path
    command_root: Path
    evidence_dir: Path
    hostile_test_case: str | None = None


@dataclass(frozen=True)
class PrivateRootState:
    tree_id: str
    source_manifest: bytes
    command_manifest: bytes
    writable_mounts: frozenset[str]
    readonly_mounts: frozenset[str]
    infra_upper_descriptor: int


@dataclass(frozen=True)
class FrozenArtifact:
    name: str
    descriptor: int
    identity: tuple[int, ...]
    payload: bytes


@dataclass
class FrozenPrivateEvidence:
    root_descriptor: int
    root_identity: tuple[int, ...]
    required_names: frozenset[str]
    artifacts: tuple[FrozenArtifact, ...]
    closed: bool = False

    @property
    def descriptors(self) -> frozenset[int]:
        return frozenset(
            {self.root_descriptor, *(item.descriptor for item in self.artifacts)}
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for artifact in self.artifacts:
            try:
                os.close(artifact.descriptor)
            except OSError:
                pass
        try:
            os.close(self.root_descriptor)
        except OSError:
            pass


@dataclass(frozen=True)
class NonParsingAttestation:
    mount_table: bytes
    mount_table_sha256: str
    source_manifest_sha256: str
    command_manifest_sha256: str
    fixture_state_sha256: str
    host_sentinels_sha256: str
    infra_runtime_sha256: str = "0" * 64
    native_authority_sha256: str = "0" * 64
    docker_authority_sha256: str = "0" * 64


@dataclass(frozen=True)
class VerifiedWorkflowFacts:
    command_leaf_names: tuple[str, ...]
    workflow_phases: tuple[str, ...]
    recovery_decision_tokens: tuple[str, ...]
    recovery_decision_matrix: tuple[
        tuple[str, bool, bool, bool, int, str, str], ...
    ]
    entrypoint_counts: tuple[tuple[tuple[str, ...], int], ...]
    malformed_payloads: tuple[tuple[str, str], ...]
    cgi_status_counts: tuple[tuple[str, int], ...]
    marker_phases: tuple[str, ...]
    native_initial_states: tuple[str, ...]
    native_stop_failures: tuple[str, ...]
    warning_sources: tuple[str, ...]
    native_audit_warning_count: int
    post_attested_operations: tuple[str, ...]
    docker_quiesce_trace: tuple[str, ...]
    teardown_authority_paths: tuple[str, ...]
    apt_mutation_count: int
    forbidden_command_count: int
    unexpected_command_count: int
    operation_count: int
    pre_teardown_attest: str
    final_postflight_attest: str
    native_authority_continuity_sha256: str
    docker_authority_continuity_sha256: str


@dataclass(frozen=True)
class VerifiedPrivateEvidence:
    tree_id: str
    event_log_sha256: str
    phase_log_sha256: str
    source_manifest_sha256: str
    command_manifest_sha256: str
    private_evidence_sha256: str
    workflow_facts: VerifiedWorkflowFacts


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _require_digest(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise WardenError(f"invalid {label}")
    return value


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WardenError("duplicate JSON member")
        result[key] = value
    return result


def _load_canonical_json(raw: bytes, *, label: str, limit: int) -> object:
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise WardenError(f"invalid {label} size")
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\x00" in raw:
        raise WardenError(f"invalid {label} framing")
    try:
        text = raw.decode("ascii")
        document = json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WardenError(f"invalid {label} JSON") from exc
    if _canonical_json(document) != raw:
        raise WardenError(f"noncanonical {label}")
    return document


def _root_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid,
    )


def _artifact_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_nlink,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_frozen_descriptor(descriptor: int, size: int, name: str) -> bytes:
    if not _is_exact_int(size) or size < 0 or size > MAX_LOG_BYTES:
        raise WardenError(f"private evidence size is unsafe: {name}")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise WardenError(f"private evidence shortened while freezing: {name}")
        chunks.append(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise WardenError(f"private evidence grew while freezing: {name}")
    return b"".join(chunks)


def _validate_required_evidence_names(names: object) -> frozenset[str]:
    if isinstance(names, (str, bytes, bytearray)):
        raise WardenError("private evidence name set is invalid")
    try:
        required = frozenset(names)  # type: ignore[arg-type]
    except TypeError as exc:
        raise WardenError("private evidence name set is invalid") from exc
    if not required or any(
        not isinstance(name, str)
        or not name
        or "/" in name
        or name in {".", "..", "final-receipt.json"}
        or name.encode("ascii", "ignore").decode("ascii") != name
        for name in required
    ):
        raise WardenError("private evidence name set is unsafe")
    return required


def freeze_private_evidence(
    root: Path,
    *,
    required_names: frozenset[str] = REQUIRED_PRIVATE_EVIDENCE_NAMES,
) -> FrozenPrivateEvidence:
    """Open and byte-freeze the exact private artifact set without parsing it."""

    required = _validate_required_evidence_names(required_names)
    path = Path(root)
    if not path.is_absolute() or ".." in path.parts:
        raise WardenError("private evidence root must be canonical and absolute")
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open(path, flags)
    except OSError as exc:
        raise WardenError("cannot hold the private evidence root") from exc
    artifacts: list[FrozenArtifact] = []
    try:
        root_metadata = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != 0
            or root_metadata.st_gid != 0
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
        ):
            raise WardenError("private evidence root metadata is unsafe")
        try:
            actual_names = frozenset(os.listdir(root_descriptor))
        except OSError as exc:
            raise WardenError("cannot enumerate private evidence") from exc
        if actual_names != required:
            raise WardenError("private evidence does not have exact set equality")
        total_size = 0
        for name in sorted(required):
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=root_descriptor,
                )
            except OSError as exc:
                raise WardenError(f"cannot hold private evidence: {name}") from exc
            try:
                before = os.fstat(descriptor)
                try:
                    named_before = os.stat(
                        name, dir_fd=root_descriptor, follow_symlinks=False,
                    )
                except OSError as exc:
                    raise WardenError(
                        f"private evidence name cannot be rebound: {name}"
                    ) from exc
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != 0
                    or before.st_gid != 0
                    or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
                    or _artifact_identity(named_before)
                    != _artifact_identity(before)
                ):
                    raise WardenError(f"private evidence metadata is unsafe: {name}")
                payload = _read_frozen_descriptor(descriptor, before.st_size, name)
                after = os.fstat(descriptor)
                named_after = os.stat(
                    name, dir_fd=root_descriptor, follow_symlinks=False,
                )
                identity = _artifact_identity(before)
                if (
                    _artifact_identity(after) != identity
                    or _artifact_identity(named_after) != identity
                ):
                    raise WardenError(f"private evidence changed while freezing: {name}")
                total_size += len(payload)
                if total_size > 64 * 1024 * 1024:
                    raise WardenError("private evidence exceeds its total byte bound")
                artifacts.append(FrozenArtifact(name, descriptor, identity, payload))
                descriptor = -1
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        if _root_directory_identity(os.fstat(root_descriptor)) != (
            root_metadata.st_dev, root_metadata.st_ino, root_metadata.st_mode,
            root_metadata.st_uid, root_metadata.st_gid,
        ):
            raise WardenError("private evidence root identity changed")
        return FrozenPrivateEvidence(
            root_descriptor=root_descriptor,
            root_identity=_root_directory_identity(root_metadata),
            required_names=required,
            artifacts=tuple(artifacts),
        )
    except BaseException:
        for artifact in artifacts:
            os.close(artifact.descriptor)
        os.close(root_descriptor)
        raise


def _verify_frozen_evidence_bindings(
    frozen: FrozenPrivateEvidence,
    *,
    allow_published_receipt: bool = False,
) -> None:
    if not isinstance(frozen, FrozenPrivateEvidence) or frozen.closed:
        raise WardenError("private evidence hold is unavailable")
    try:
        root_metadata = os.fstat(frozen.root_descriptor)
        actual_names = frozenset(os.listdir(frozen.root_descriptor))
    except OSError as exc:
        raise WardenError("private evidence root hold changed") from exc
    permitted_names = frozen.required_names | (
        {"final-receipt.json"} if allow_published_receipt else set()
    )
    if (
        _root_directory_identity(root_metadata) != frozen.root_identity
        or actual_names != permitted_names
    ):
        raise WardenError("private evidence root or exact set changed")
    for artifact in frozen.artifacts:
        try:
            held = os.fstat(artifact.descriptor)
            named = os.stat(
                artifact.name,
                dir_fd=frozen.root_descriptor,
                follow_symlinks=False,
            )
            payload = _read_frozen_descriptor(
                artifact.descriptor, held.st_size, artifact.name,
            )
        except OSError as exc:
            raise WardenError(
                f"private evidence binding changed: {artifact.name}"
            ) from exc
        if (
            _artifact_identity(held) != artifact.identity
            or _artifact_identity(named) != artifact.identity
            or payload != artifact.payload
        ):
            raise WardenError(f"frozen private evidence changed: {artifact.name}")


def _frozen_payloads(frozen: FrozenPrivateEvidence) -> dict[str, bytes]:
    _verify_frozen_evidence_bindings(frozen)
    return {artifact.name: artifact.payload for artifact in frozen.artifacts}


def publish_private_final_receipt(
    frozen: FrozenPrivateEvidence,
    receipt: bytes,
) -> bytes:
    """Create, fsync, bind, and reread the sole private PASS receipt."""

    document = _load_canonical_json(
        receipt, label="final receipt", limit=MAX_RECEIPT_BYTES,
    )
    if not isinstance(document, dict) or document.get("result") != "PASS":
        raise WardenError("final receipt does not contain the sealed PASS result")
    # Before the first publication the set must still be the exact frozen set.
    # On a repeat call, permit only the already-published canonical name so the
    # O_EXCL open below proves that it cannot be replaced.
    try:
        current_names = frozenset(os.listdir(frozen.root_descriptor))
    except OSError as exc:
        raise WardenError("cannot enumerate private evidence before publish") from exc
    if current_names == frozen.required_names:
        _verify_frozen_evidence_bindings(frozen)
    elif current_names == frozen.required_names | {"final-receipt.json"}:
        _verify_frozen_evidence_bindings(frozen, allow_published_receipt=True)
    else:
        raise WardenError("private evidence exact set changed before publish")
    descriptor = -1
    try:
        descriptor = os.open(
            "final-receipt.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
            dir_fd=frozen.root_descriptor,
        )
        view = memoryview(receipt)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise WardenError("short private final-receipt write")
            view = view[written:]
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        written_identity = _artifact_identity(os.fstat(descriptor))
    except OSError as exc:
        raise WardenError("private final receipt already exists or cannot be created") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    descriptor = -1
    os.fsync(frozen.root_descriptor)
    try:
        descriptor = os.open(
            "final-receipt.json",
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=frozen.root_descriptor,
        )
        metadata = os.fstat(descriptor)
        named = os.stat(
            "final-receipt.json",
            dir_fd=frozen.root_descriptor,
            follow_symlinks=False,
        )
        reread = _read_frozen_descriptor(
            descriptor, metadata.st_size, "final-receipt.json",
        )
    except OSError as exc:
        raise WardenError("cannot reread private final receipt") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        _artifact_identity(metadata) != written_identity
        or _artifact_identity(named) != written_identity
        or reread != receipt
    ):
        raise WardenError("private final receipt changed before reread")
    _verify_frozen_evidence_bindings(frozen, allow_published_receipt=True)
    os.fsync(frozen.root_descriptor)
    return reread


def validate_supervisor_fd_inventory(descriptors: Iterable[int]) -> None:
    """Require the close-all child to hold exactly standard descriptors."""

    try:
        values = set(descriptors)
    except TypeError as exc:
        raise WardenError("supervisor descriptor inventory is invalid") from exc
    if any(not _is_exact_int(item) or item < 0 for item in values):
        raise WardenError("supervisor descriptor inventory is invalid")
    if values != {0, 1, 2}:
        raise WardenError("supervisor descriptor inventory is not exactly 0,1,2")


def validate_post_host_close_fd_inventory(
    descriptors: Iterable[int],
    *,
    private_descriptors: set[int],
    external_write_descriptors: set[int] = set(),
) -> None:
    """Require only private holds and write-only append evidence after host close."""

    try:
        actual = set(descriptors)
        private = set(private_descriptors)
        external = set(external_write_descriptors)
    except TypeError as exc:
        raise WardenError("post-host-close descriptor inventory is invalid") from exc
    all_sets = (actual, private, external)
    if any(
        any(not _is_exact_int(descriptor) or descriptor < 0 for descriptor in values)
        for values in all_sets
    ):
        raise WardenError("post-host-close descriptor number is invalid")
    if (
        private & external
        or ({0, 1, 2} & (private | external))
        or actual != {0, 1, 2} | private | external
    ):
        raise WardenError("post-host-close descriptor set is not exact")
    for descriptor in private:
        try:
            os.fstat(descriptor)
        except OSError as exc:
            raise WardenError("private descriptor is not held") from exc
    for descriptor in external:
        try:
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise WardenError("external evidence descriptor is not held") from exc
        if (
            flags & os.O_ACCMODE != os.O_WRONLY
            or not flags & os.O_APPEND
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise WardenError(
                "external evidence must be a private write-only append regular file"
            )


def validate_command_argv(command: str, argv: Sequence[str]) -> None:
    """Accept one complete byte-stable command vector or return FORBIDDEN/99."""

    if (
        not isinstance(command, str)
        or SAFE_COMMAND_NAME.fullmatch(command) is None
        or isinstance(argv, (str, bytes, bytearray))
    ):
        raise ForbiddenCommand()
    try:
        vector = tuple(argv)
    except TypeError as exc:
        raise ForbiddenCommand() from exc
    if any(not isinstance(item, str) or "\x00" in item for item in vector):
        raise ForbiddenCommand()
    allowed = ALLOWED_COMMAND_ARGV.get(command)
    if allowed is None or vector not in allowed:
        raise ForbiddenCommand()


def _safe_absolute_mount_path(value: object) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise WardenError("mount target is not a safe absolute path")
    path = PurePosixPath(value)
    if str(path) != value or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise WardenError("mount target is not canonical")
    return value


def validate_mount_records(
    records: Sequence[MountRecord],
    *,
    writable_paths: set[str],
    readonly_paths: set[str],
) -> None:
    """Classify the complete reachable table, not a selected mount subset."""

    writable = {_safe_absolute_mount_path(path) for path in writable_paths}
    readonly = {_safe_absolute_mount_path(path) for path in readonly_paths}
    if writable & readonly:
        raise WardenError("mount classification overlaps")
    by_target: dict[str, MountRecord] = {}
    dangerous_filesystems = {
        "bpf", "cgroup", "cgroup2", "debugfs", "devtmpfs", "securityfs",
        "tracefs",
    }
    safe_devices = {"/dev", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}
    for record in records:
        if not isinstance(record, MountRecord):
            raise WardenError("mount table contains an invalid record")
        target = _safe_absolute_mount_path(record.target)
        if target in by_target:
            raise WardenError("mount table contains a duplicate target")
        if record.propagation != "private":
            raise WardenError("shared/slave/unbindable mount propagation is forbidden")
        if not isinstance(record.filesystem_type, str) or not record.filesystem_type:
            raise WardenError("mount filesystem type is invalid")
        if record.filesystem_type in dangerous_filesystems:
            raise WardenError("control or host-device filesystem is exposed")
        if target == "/sys/fs/cgroup" or target.startswith("/sys/fs/cgroup/"):
            raise WardenError("cgroup control paths are forbidden")
        if target.startswith("/dev/") and target not in safe_devices:
            raise WardenError("non-minimal device path is exposed")
        options = frozenset(record.options)
        if bool("ro" in options) == bool("rw" in options):
            raise WardenError("mount must state exactly one of ro/rw")
        if target in writable and "rw" not in options:
            raise WardenError("declared private writable mount is not rw")
        if target in readonly and "ro" not in options:
            raise WardenError("declared read-only mount is not ro")
        if target.startswith("/sys") and "ro" not in options:
            raise WardenError("sys exposure must be read-only")
        by_target[target] = MountRecord(
            target, record.filesystem_type, options, record.propagation,
        )
    if set(by_target) != writable | readonly:
        raise WardenError("mount table does not have exact set equality")


def _decode_mount_component(value: str) -> str:
    replacements = {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value


def read_mount_records(path: Path = Path("/proc/self/mountinfo")) -> tuple[MountRecord, ...]:
    """Read the complete descendant-visible mount table from procfs."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WardenError("cannot read /proc/self/mountinfo") from exc
    if not raw or len(raw) > MAX_LOG_BYTES or b"\x00" in raw:
        raise WardenError("mountinfo has invalid framing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise WardenError("mountinfo is not ASCII") from exc
    records: list[MountRecord] = []
    for line in lines:
        fields = line.split(" ")
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise WardenError("mountinfo record lacks separator") from exc
        if separator < 6 or len(fields) < separator + 4:
            raise WardenError("mountinfo record is truncated")
        target = _decode_mount_component(fields[4])
        # The pre-separator field is the per-mount view.  The superblock field
        # after the separator may still say rw for a read-only bind and must
        # not override that view.
        mount_options = set(fields[5].split(","))
        optional = fields[6:separator]
        if any(item.startswith("shared:") for item in optional):
            propagation = "shared"
        elif any(item.startswith(("master:", "propagate_from:")) for item in optional):
            propagation = "slave"
        elif "unbindable" in optional:
            propagation = "unbindable"
        else:
            propagation = "private"
        records.append(MountRecord(
            target=target,
            filesystem_type=fields[separator + 1],
            options=frozenset(mount_options),
            propagation=propagation,
        ))
    return tuple(records)


def _validate_phase_log(phase_bytes: bytes) -> tuple[str, ...]:
    if (
        not isinstance(phase_bytes, bytes)
        or not phase_bytes
        or len(phase_bytes) > MAX_LOG_BYTES
        or b"\x00" in phase_bytes
        or not phase_bytes.endswith(b"\n")
    ):
        raise WardenError("invalid phase log framing")
    lines = phase_bytes.splitlines(keepends=True)
    if len(lines) != len(REQUIRED_WORKFLOW_PHASES):
        raise WardenError("phase log is incomplete")
    for index, (raw_line, phase) in enumerate(
        zip(lines, REQUIRED_WORKFLOW_PHASES), 1,
    ):
        document = _load_canonical_json(
            raw_line, label="phase record", limit=4096,
        )
        expected = {"index": index, "phase": phase}
        if document != expected:
            raise WardenError("phase log is missing, duplicated, or out of order")
    return tuple(REQUIRED_WORKFLOW_PHASES)


def _validate_event_log(event_bytes: bytes) -> None:
    if (
        not isinstance(event_bytes, bytes)
        or not event_bytes
        or len(event_bytes) > MAX_LOG_BYTES
        or b"\x00" in event_bytes
        or not event_bytes.endswith(b"\n")
    ):
        raise WardenError("invalid event log framing")
    lines = event_bytes.splitlines()
    if any(not line or len(line) > 4096 for line in lines):
        raise WardenError("invalid event log line")
    if any(b"FORBIDDEN" in line for line in lines):
        raise WardenError("event log records a forbidden command")
    try:
        event_bytes.decode("ascii", "strict")
    except UnicodeDecodeError as exc:
        raise WardenError("event log is not canonical ASCII") from exc


def _expected_bad_authority_payloads() -> tuple[tuple[str, bytes], ...]:
    def breaker(schema: int, count: int, *, extra: bool = False) -> bytes:
        return _canonical_json({
            "schema_version": schema,
            "contaminant_dev": 7,
            "contaminant_ino": 11,
            "failure_count": count,
            **({"extra": False} if extra else {}),
        })

    def cache(schema: int, digest: str, *, extra: bool = False) -> bytes:
        return _canonical_json({
            "schema_version": schema,
            "factory_records_active": True,
            "helper_sha256": digest,
            **({"extra": False} if extra else {}),
        })

    return (
        ("status.lock", b'{"schema_version":1'),
        ("status.lock", breaker(1, 1, extra=True)),
        ("status.lock", breaker(2, 1)),
        ("status.lock", breaker(1, 0)),
        ("status.lock", breaker(1, 4)),
        ("monitor-auth/factory-status.json", b""),
        ("monitor-auth/factory-status.json", b'{"schema_version":1'),
        ("monitor-auth/factory-status.json", cache(
            1, CONTROL_AUTH_HELPER_SHA256, extra=True,
        )),
        ("monitor-auth/factory-status.json", cache(
            2, CONTROL_AUTH_HELPER_SHA256,
        )),
        ("monitor-auth/factory-status.json", cache(1, "0" * 64)),
    )


def _expected_valid_authority_payloads() -> Mapping[str, bytes]:
    return {
        "status.lock": b"",
        "monitor-auth/factory-status.json": _canonical_json({
            "factory_records_active": True,
            "helper_sha256": CONTROL_AUTH_HELPER_SHA256,
            "schema_version": 1,
        }),
    }


def _expected_recovery_decision_rows() -> tuple[dict[str, object], ...]:
    cleanup_warning = (
        b"WARNING: Monitor authority recovery committed, but marker cleanup "
        b"durability is unknown; a stale completed marker may reappear after crash.\n"
    )
    rows: list[dict[str, object]] = []
    for cleanup, restart_allowed in (
        ("complete", True),
        ("marker-removal-durability-unknown", True),
        ("marker-retained", False),
        ("marker-authority-uncertain", False),
    ):
        for reset in (False, True):
            diagnostics = RECOVERY_RESET_WARNING if reset else b""
            if cleanup == "marker-removal-durability-unknown":
                diagnostics += cleanup_warning
            rows.append({
                "cleanup": cleanup,
                "diagnostics_sha256": hashlib.sha256(diagnostics).hexdigest(),
                "diagnostics_size": len(diagnostics),
                "recovery_committed": True,
                "reset_invalid_cache": reset,
                "restart_allowed": restart_allowed,
                "token": (
                    f"restart-{'allowed' if restart_allowed else 'blocked'}:"
                    f"{cleanup};reset-invalid-cache={'true' if reset else 'false'}"
                ),
            })
    return tuple(rows)


def _validate_recovery_decision_matrix(raw: bytes) -> tuple[
    tuple[str, bool, bool, bool, int, str, str], ...
]:
    document = _load_canonical_json(
        raw, label="recovery decision matrix", limit=MAX_RECEIPT_BYTES,
    )
    expected = _expected_recovery_decision_rows()
    if document != list(expected):
        raise WardenError("recovery decision input-to-token mapping changed")
    return tuple(
        (
            str(row["cleanup"]), bool(row["recovery_committed"]),
            bool(row["restart_allowed"]), bool(row["reset_invalid_cache"]),
            int(row["diagnostics_size"]), str(row["diagnostics_sha256"]),
            str(row["token"]),
        )
        for row in expected
    )


def _expected_operation_specs() -> tuple[dict[str, object], ...]:
    specs: list[dict[str, object]] = []
    for index, (target, _payload) in enumerate(_expected_bad_authority_payloads()):
        specs.append({
            "operation": f"bad-{index}",
            "returncode": 1,
            "argv": ("python3", "-B", "infra/docker/healthcheck.py"),
            "artifacts": (
                (f"authority-input@{target}", f"bad-payload-{index}.bin"),
                ("authority-tree-observations", f"authority-bad-{index}.jsonl"),
                ("health-combined", f"health-{index}.out"),
                ("cgi-stdout", f"cgi-bad-{index}.out"),
                ("cgi-stderr", f"cgi-bad-{index}.out.err"),
                ("cgi-invocation", f"cgi-bad-{index}.invocation.json"),
            ),
        })
    for phase in (
        "recovery-in-progress", "recovery-committed-cleanup-pending",
    ):
        specs.append({
            "operation": f"marker-{phase}",
            "returncode": 0,
            "argv": ("./infra/infra-setup.sh", "--recover-monitor-authority"),
            "artifacts": (
                ("authority-tree-observations", f"authority-marker-{phase}.jsonl"),
                ("classification-stdout", f"marker-{phase}.out"),
                ("classification-stderr", f"marker-{phase}.err"),
                ("recovery-stdout", f"marker-reset-{phase}.out"),
                ("recovery-stderr", f"marker-reset-{phase}.err"),
                ("post-attest-stdout", f"marker-after-{phase}.out"),
                ("post-attest-stderr", f"marker-after-{phase}.err"),
            ),
        })
    for mode in ("stop-fail", "show-fail", "stay-active"):
        specs.append({
            "operation": f"stop-{mode}",
            "returncode": 1,
            "argv": ("./infra/infra-setup.sh", "--recover-monitor-authority"),
            "artifacts": (
                ("authority-tree-observations", f"authority-stop-{mode}.jsonl"),
                ("recovery-stdout", f"stop-{mode}.out"),
                ("recovery-stderr", f"stop-{mode}.err"),
            ),
        })
    for index, state in enumerate(("active", "inactive", "failed")):
        specs.append({
            "operation": f"native-{state}",
            "returncode": 0,
            "argv": ("./infra/infra-setup.sh", "--recover-monitor-authority"),
            "artifacts": (
                ("authority-tree-observations", f"authority-native-{state}.jsonl"),
                ("recovery-stdout", f"native-{state}.out"),
                ("recovery-stderr", f"native-{state}.err"),
                ("post-attest-stdout", f"native-attest-{state}.out"),
                ("post-attest-stderr", f"native-attest-{state}.err"),
                ("cgi-stdout", f"cgi-good-{index}.out"),
                ("cgi-stderr", f"cgi-good-{index}.out.err"),
                ("cgi-invocation", f"cgi-good-{index}.invocation.json"),
            ),
        })
    specs.extend(({
        "operation": "docker-writer",
        "returncode": 0,
        "argv": ("./infra/docker/deploy.sh", "recover-monitor-authority"),
        "artifacts": (
            ("container-authority-observations", "authority-docker-container.jsonl"),
            ("native-authority-observations", "authority-docker-native.jsonl"),
            ("recovery-stdout", "docker-recover.out"),
            ("recovery-stderr", "docker-recover.err"),
        ),
    }, {
        "operation": "teardown",
        "returncode": 0,
        "argv": ("./infra/infra-teardown.sh", "--non-interactive", "--yes"),
        "artifacts": (
            ("pre-teardown-attest-stdout", "pre-teardown-attest.out"),
            ("pre-teardown-attest-stderr", "pre-teardown-attest.err"),
            ("pre-teardown-attest-invocation", "pre-teardown-attest.invocation.json"),
            ("authority-before", "teardown-before.json"),
            ("authority-after", "teardown-after.json"),
            ("teardown-stdout", "teardown.out"),
            ("teardown-stderr", "teardown.err"),
        ),
    }))
    return tuple(specs)


def _command_event(
    operation: str,
    command: str,
    argv: Sequence[str],
    returncode: int,
    observation: Mapping[str, object],
    *,
    result: str = "ALLOWED",
) -> dict[str, object]:
    return {
        "argv": list(argv),
        "command": command,
        "observation": dict(observation),
        "operation": operation,
        "result": result,
        "returncode": returncode,
    }


def _expected_command_events() -> tuple[dict[str, object], ...]:
    records = [
        _command_event(
            "argv-collision-matrix", command, argv, FORBIDDEN_RETURN_CODE, {},
            result="FORBIDDEN",
        )
        for command, argv in FORBIDDEN_COMMAND_ARGV_SEQUENCE
    ]

    def systemctl(
        operation: str,
        argv: Sequence[str],
        before: str,
        after: str,
        returncode: int = 0,
        mode: str = "normal",
    ) -> None:
        records.append(_command_event(
            operation, "systemctl", argv, returncode,
            {"mode": mode, "state_after": after, "state_before": before},
        ))

    show = ("show", "--property=ActiveState", "--value", "apache2")
    for phase in (
        "recovery-in-progress", "recovery-committed-cleanup-pending",
    ):
        operation = f"marker-{phase}"
        systemctl(operation, show, "active", "active")
        systemctl(operation, ("stop", "apache2"), "active", "inactive")
        systemctl(operation, show, "inactive", "inactive")
        systemctl(operation, ("start", "apache2"), "inactive", "active")
        systemctl(operation, show, "active", "active")
    systemctl("stop-stop-fail", show, "active", "active", mode="stop-fail")
    systemctl(
        "stop-stop-fail", ("stop", "apache2"), "active", "active", 1,
        "stop-fail",
    )
    systemctl("stop-show-fail", show, "active", "active", 1, "show-fail")
    systemctl("stop-stay-active", show, "active", "active", mode="stay-active")
    systemctl(
        "stop-stay-active", ("stop", "apache2"), "active", "active",
        mode="stay-active",
    )
    systemctl("stop-stay-active", show, "active", "active", mode="stay-active")
    systemctl("native-active", show, "active", "active")
    systemctl("native-active", ("stop", "apache2"), "active", "inactive")
    systemctl("native-active", show, "inactive", "inactive")
    systemctl("native-active", ("start", "apache2"), "inactive", "active")
    systemctl("native-active", show, "active", "active")
    for operation, initial in (
        ("native-inactive", "inactive"), ("native-failed", "failed"),
    ):
        systemctl(operation, show, initial, initial)
        systemctl(operation, ("stop", "apache2"), initial, "inactive")
        systemctl(operation, show, "inactive", "inactive")
    for argv in (
        ("context", "show"),
        ("context", "inspect", "default"),
        ("info", "--format", "{{json .}}"),
    ):
        records.append(_command_event(
            "docker-writer", "docker", argv, 0,
            {"state_after": "running", "state_before": "running"},
        ))
    records.append(_command_event(
        "docker-writer", "dpkg", ("--print-architecture",), 0, {},
    ))
    records.extend((
        _command_event(
            "docker-writer", "docker",
            ("container", "inspect", "http-ztp"), 0,
            {"container_id": DOCKER_IDENTIFIER, "dead": False, "pid": 4242,
             "running": True, "state_after": "running", "state_before": "running"},
        ),
        _command_event(
            "docker-writer", "docker",
            ("stop", "--time", "30", DOCKER_IDENTIFIER), 0,
            {"state_after": "stopped", "state_before": "running"},
        ),
        _command_event(
            "docker-writer", "docker",
            ("container", "inspect", DOCKER_IDENTIFIER), 0,
            {"container_id": DOCKER_IDENTIFIER, "dead": False, "pid": 0,
             "running": False, "state_after": "stopped", "state_before": "stopped"},
        ),
        _command_event(
            "docker-writer", "docker", ("rm", DOCKER_IDENTIFIER), 0,
            {"state_after": "absent", "state_before": "stopped"},
        ),
    ))
    for argv in (
        ("is-active", "--quiet", "systemd-resolved"),
        ("is-active", "--quiet", "systemd-timesyncd"),
    ):
        systemctl("teardown", argv, "inactive", "inactive", 3)
    records.append(_command_event(
        "teardown", "dpkg", ("-s", "apache2"), 1, {},
    ))
    return tuple(records)


def _validate_command_event_log(raw: bytes) -> tuple[dict[str, object], ...]:
    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_LOG_BYTES
        or b"\x00" in raw
        or not raw.endswith(b"\n")
    ):
        raise WardenError("invalid command-event log framing")
    records: list[dict[str, object]] = []
    for line in raw.splitlines(keepends=True):
        record = _load_canonical_json(
            line, label="command-event record", limit=4096,
        )
        if (
            not isinstance(record, dict)
            or set(record) != {
                "argv", "command", "observation", "operation", "result",
                "returncode",
            }
            or not isinstance(record.get("argv"), list)
            or not all(isinstance(item, str) for item in record["argv"])
            or not isinstance(record.get("command"), str)
            or not isinstance(record.get("operation"), str)
            or not isinstance(record.get("observation"), dict)
            or not _is_exact_int(record.get("returncode"))
            or record.get("result") not in {"ALLOWED", "FORBIDDEN"}
        ):
            raise WardenError("invalid command-event record")
        if record["result"] == "ALLOWED":
            try:
                validate_command_argv(record["command"], record["argv"])
            except ForbiddenCommand as exc:
                raise WardenError(
                    "command-event contains an unapproved vector"
                ) from exc
        records.append(record)
    expected = _expected_command_events()
    if tuple(records) != expected:
        raise WardenError(
            "command-event log does not prove exact operation-attributed vectors"
        )
    return tuple(records)


def _validate_verified_workflow_facts(facts: VerifiedWorkflowFacts) -> None:
    if not isinstance(facts, VerifiedWorkflowFacts):
        raise WardenError("verified workflow facts are unavailable")
    expected_bad = tuple(
        (target, hashlib.sha256(payload).hexdigest())
        for target, payload in _expected_bad_authority_payloads()
    )
    expected_entrypoints: dict[tuple[str, ...], int] = {}
    for spec in _expected_operation_specs():
        argv = tuple(spec["argv"])
        if argv[0].startswith("./infra/"):
            expected_entrypoints[argv] = expected_entrypoints.get(argv, 0) + 1
    expected = {
        "command_leaf_names": tuple(sorted(COMMAND_LEAF_NAMES)),
        "workflow_phases": tuple(REQUIRED_WORKFLOW_PHASES),
        "recovery_decision_tokens": tuple(RECOVERY_DECISION_TOKENS),
        "recovery_decision_matrix": tuple(
            (
                row["cleanup"], row["recovery_committed"],
                row["restart_allowed"], row["reset_invalid_cache"],
                row["diagnostics_size"], row["diagnostics_sha256"],
                row["token"],
            )
            for row in _expected_recovery_decision_rows()
        ),
        "entrypoint_counts": tuple(expected_entrypoints.items()),
        "malformed_payloads": expected_bad,
        "cgi_status_counts": (("200", 3), ("503", len(expected_bad))),
        "marker_phases": (
            "recovery-in-progress", "recovery-committed-cleanup-pending",
        ),
        "native_initial_states": ("active", "inactive", "failed"),
        "native_stop_failures": ("stop-fail", "show-fail", "stay-active"),
        "warning_sources": (
            "docker-recover.err", "native-active.err", "native-failed.err",
            "native-inactive.err",
        ),
        "native_audit_warning_count": 3,
        "post_attested_operations": (
            "marker-recovery-in-progress",
            "marker-recovery-committed-cleanup-pending",
            "native-active", "native-inactive", "native-failed",
        ),
        "docker_quiesce_trace": (
            "docker-inspect-writer", "docker-stop-writer",
            "docker-reinspect-writer", "docker-remove-writer",
        ),
        "teardown_authority_paths": (
            "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
            "/usr/local/lib/http-ztp/control-auth.py",
            "/var/lib/http-ztp-monitor-auth",
            "/var/lib/http-ztp-monitor-auth/monitor-auth",
            "/var/lib/http-ztp-monitor-auth/monitor-auth/factory-status.json",
            "/var/lib/http-ztp-monitor-auth/status.lock",
        ),
        "apt_mutation_count": 0,
        "forbidden_command_count": len(FORBIDDEN_COMMAND_ARGV_SEQUENCE),
        "unexpected_command_count": 0,
        "operation_count": len(_expected_operation_specs()),
        "pre_teardown_attest": "attest-valid",
        "final_postflight_attest": "attest-valid",
    }
    for field, value in expected.items():
        if getattr(facts, field) != value:
            raise WardenError(f"verified workflow facts changed: {field}")
    for field in (
        "native_authority_continuity_sha256",
        "docker_authority_continuity_sha256",
    ):
        _require_digest(
            getattr(facts, field), field.replace("_", " "), DIGEST_PATTERN,
        )


def build_final_receipt(
    verified: VerifiedPrivateEvidence,
    attestation: NonParsingAttestation,
    *,
    descendant_count: int,
) -> bytes:
    """Build PASS solely from independently verified raw and PID-1 facts."""

    if not isinstance(verified, VerifiedPrivateEvidence):
        raise WardenError("verified private evidence is unavailable")
    if not isinstance(attestation, NonParsingAttestation):
        raise WardenError("nonparsing postflight attestation is unavailable")
    facts = verified.workflow_facts
    _validate_verified_workflow_facts(facts)
    if not _is_exact_int(descendant_count) or descendant_count != 0:
        raise WardenError("cannot seal while any descendant remains")
    tree_id = _require_digest(verified.tree_id, "tree ID", TREE_ID_PATTERN)
    digest_values = {
        "command_manifest_sha256": verified.command_manifest_sha256,
        "event_log_sha256": verified.event_log_sha256,
        "fixture_state_sha256": attestation.fixture_state_sha256,
        "host_sentinels_sha256": attestation.host_sentinels_sha256,
        "infra_runtime_sha256": attestation.infra_runtime_sha256,
        "mount_table_sha256": attestation.mount_table_sha256,
        "phase_log_sha256": verified.phase_log_sha256,
        "private_evidence_sha256": verified.private_evidence_sha256,
        "source_manifest_sha256": verified.source_manifest_sha256,
        "native_authority_sha256": attestation.native_authority_sha256,
        "docker_authority_sha256": attestation.docker_authority_sha256,
    }
    if verified.source_manifest_sha256 != attestation.source_manifest_sha256:
        raise WardenError("source evidence and nonparsing attestation disagree")
    if verified.command_manifest_sha256 != attestation.command_manifest_sha256:
        raise WardenError("command evidence and nonparsing attestation disagree")
    if (
        facts.native_authority_continuity_sha256
        != attestation.native_authority_sha256
    ):
        raise WardenError("Native authority timeline and opaque freeze disagree")
    if (
        facts.docker_authority_continuity_sha256
        != attestation.docker_authority_sha256
    ):
        raise WardenError("Docker authority timeline and opaque freeze disagree")
    for label, value in digest_values.items():
        _require_digest(value, label.replace("_", " "), DIGEST_PATTERN)
    cgi_status_counts = dict(facts.cgi_status_counts)
    cleanup_decisions = len(facts.recovery_decision_matrix)
    receipt = {
        "cgi_status_counts": cgi_status_counts,
        "cleanup_decisions": cleanup_decisions,
        "command_leaf_names": list(facts.command_leaf_names),
        "command_manifest_sha256": verified.command_manifest_sha256,
        "descendants": "all-descendant-zero",
        "docker_quiesce_trace": list(facts.docker_quiesce_trace),
        "entrypoint_counts": [
            {"argv": list(argv), "count": count}
            for argv, count in facts.entrypoint_counts
        ],
        "entrypoints": [list(argv) for argv, _count in facts.entrypoint_counts],
        "event_log_sha256": verified.event_log_sha256,
        "fixture_state_sha256": attestation.fixture_state_sha256,
        "host_sentinels_sha256": attestation.host_sentinels_sha256,
        "infra_runtime_sha256": attestation.infra_runtime_sha256,
        "malformed_payload_consumers": len(facts.malformed_payloads),
        "mount_table_sha256": attestation.mount_table_sha256,
        "native_initial_states": list(facts.native_initial_states),
        "native_authority_continuity_sha256": (
            facts.native_authority_continuity_sha256
        ),
        "native_stop_failures": len(facts.native_stop_failures),
        "operation_count": facts.operation_count,
        "docker_authority_continuity_sha256": (
            facts.docker_authority_continuity_sha256
        ),
        "post_attested_operations": list(facts.post_attested_operations),
        "phase_log_sha256": verified.phase_log_sha256,
        "private_evidence_sha256": verified.private_evidence_sha256,
        "recovery_decision_tokens": list(facts.recovery_decision_tokens),
        "recovery_decision_matrix": [
            {
                "cleanup": cleanup,
                "diagnostics_sha256": diagnostics_sha256,
                "diagnostics_size": diagnostics_size,
                "recovery_committed": committed,
                "reset_invalid_cache": reset,
                "restart_allowed": restart_allowed,
                "token": token,
            }
            for (
                cleanup, committed, restart_allowed, reset,
                diagnostics_size, diagnostics_sha256, token,
            )
            in facts.recovery_decision_matrix
        ],
        "recovery_marker_phases": len(facts.marker_phases),
        "reset_warning_count": len(facts.warning_sources),
        "reset_warning_sources": list(facts.warning_sources),
        "native_audit_warning_count": facts.native_audit_warning_count,
        "result": "PASS",
        "schema_version": 1,
        "sealed_by": "namespace-pid1-warden",
        "source_manifest_sha256": verified.source_manifest_sha256,
        "teardown_authority_paths": list(facts.teardown_authority_paths),
        "teardown_apt_mutations": facts.apt_mutation_count,
        "tree_id": tree_id,
        "pre_teardown_attest": facts.pre_teardown_attest,
        "final_postflight_attest": facts.final_postflight_attest,
        "unexpected_command_count": facts.unexpected_command_count,
        "forbidden_command_count": facts.forbidden_command_count,
        "workflow_phases": list(facts.workflow_phases),
    }
    return _canonical_json(receipt)


def _fd_sha256(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise WardenError("host sentinel shortened while hashing")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise WardenError("host sentinel grew while hashing")
    return digest.hexdigest()


def capture_host_sentinels(source_directory_fd: int) -> tuple[HostSentinel, ...]:
    sentinels: list[HostSentinel] = []
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        for relative in HOST_SENTINEL_PATHS:
            descriptor = os.open(relative, flags, dir_fd=source_directory_fd)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                os.close(descriptor)
                raise WardenError(f"unsafe host sentinel: {relative}")
            sentinels.append(HostSentinel(
                relative_path=relative,
                descriptor=descriptor,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                mode=metadata.st_mode,
                uid=metadata.st_uid,
                gid=metadata.st_gid,
                links=metadata.st_nlink,
                size=metadata.st_size,
                sha256=_fd_sha256(descriptor, metadata.st_size),
            ))
    except BaseException:
        for sentinel in sentinels:
            os.close(sentinel.descriptor)
        raise
    return tuple(sentinels)


def verify_host_sentinels(
    source_directory_fd: int,
    sentinels: Sequence[HostSentinel],
) -> str:
    """Verify held bytes and their still-named source entries after all children."""

    evidence: list[dict[str, object]] = []
    for sentinel in sentinels:
        held = os.fstat(sentinel.descriptor)
        try:
            named = os.stat(
                sentinel.relative_path,
                dir_fd=source_directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise WardenError("host sentinel name is no longer reachable") from exc
        identity = (
            sentinel.device, sentinel.inode, sentinel.mode, sentinel.uid,
            sentinel.gid, sentinel.links, sentinel.size,
        )
        held_identity = (
            held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid,
            held.st_nlink, held.st_size,
        )
        named_identity = (
            named.st_dev, named.st_ino, named.st_mode, named.st_uid,
            named.st_gid, named.st_nlink, named.st_size,
        )
        digest = _fd_sha256(sentinel.descriptor, sentinel.size)
        if held_identity != identity or named_identity != identity or digest != sentinel.sha256:
            raise WardenError(f"host sentinel changed: {sentinel.relative_path}")
        evidence.append({
            "path": sentinel.relative_path,
            "sha256": digest,
            "size": sentinel.size,
        })
    return hashlib.sha256(_canonical_json(evidence)).hexdigest()


def _open_fd_inventory() -> set[int]:
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as exc:
        raise WardenError("cannot enumerate /proc/self/fd") from exc
    result: set[int] = set()
    for name in names:
        if not name.isascii() or not name.isdecimal():
            raise WardenError("invalid descriptor name in procfs")
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                # The descriptor used internally by listdir is already closed.
                continue
            raise
        result.add(descriptor)
    return result


def _namespace_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def _require_warden_preconditions(config: WardenConfig) -> None:
    if not sys.platform.startswith("linux"):
        raise WardenError("warden requires Linux")
    if os.geteuid() != 0 or os.getpid() != 1:
        raise WardenError("warden requires EUID 0 as PID 1")
    if os.environ != WARDEN_ENVIRONMENT:
        raise WardenError("warden environment is not the exact env-i contract")
    if (
        config.hostile_test_case is not None
        and config.hostile_test_case not in HOSTILE_TEST_CASES
    ):
        raise WardenError("unknown fixed hostile test case")
    _require_digest(config.tree_id, "tree ID", TREE_ID_PATTERN)
    expected_fds = {0, 1, 2, 9}
    actual_fds = _open_fd_inventory()
    if actual_fds != expected_fds:
        raise WardenError("warden inherited an unexpected descriptor")
    try:
        current_fd = os.open("/proc/self/ns/mnt", os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        raise WardenError("cannot open private mount namespace") from exc
    try:
        if _namespace_identity(9) == _namespace_identity(current_fd):
            raise WardenError("FD 9 does not identify the outer mount namespace")
    finally:
        os.close(current_fd)
    for path in (
        config.source_root, config.private_root, config.command_root,
        config.evidence_dir,
    ):
        if not path.is_absolute() or ".." in path.parts:
            raise WardenError("warden paths must be canonical absolute paths")
    if not config.source_root.is_dir() or config.source_root.is_symlink():
        raise WardenError("source root is missing or symbolic")
    base = Path("/run/http-ztp-monitor-warden")
    for path in (config.private_root, config.command_root, config.evidence_dir):
        try:
            path.relative_to(base)
        except ValueError as exc:
            raise WardenError("private paths must stay under the fixed warden root") from exc
    if len({config.private_root, config.command_root, config.evidence_dir}) != 3:
        raise WardenError("private root, command root, and evidence dir must differ")
    run_root = config.evidence_dir.parent
    if (
        config.evidence_dir != run_root / "evidence"
        or config.private_root != run_root / "root"
        or config.command_root != run_root / "commands"
        or run_root.parent != base
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", run_root.name) is None
    ):
        raise WardenError("private paths do not share the fixed per-run layout")


def _libc_call(name: str, result: int) -> None:
    if result != 0:
        value = ctypes.get_errno()
        raise WardenError(f"{name} failed: {os.strerror(value)}")


def _mount(
    source: str | None,
    target: str,
    filesystem_type: str | None,
    flags: int,
    data: str | None = None,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.mount
    operation.argtypes = (
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_ulong, ctypes.c_char_p,
    )
    operation.restype = ctypes.c_int
    encode = lambda value: None if value is None else os.fsencode(value)
    _libc_call("mount", operation(
        encode(source), encode(target), encode(filesystem_type), flags,
        encode(data),
    ))


def _umount2(target: str, flags: int = 0) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.umount2
    operation.argtypes = (ctypes.c_char_p, ctypes.c_int)
    operation.restype = ctypes.c_int
    _libc_call("umount2", operation(os.fsencode(target), flags))


class _MountAttributes(ctypes.Structure):
    _fields_ = (
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    )


def _make_readonly_recursively(target: Path) -> None:
    """Apply read-only/nodev/nosuid to a whole bind subtree atomically."""

    machine = os.uname().machine
    syscall_number = {"x86_64": 442, "aarch64": 442}.get(machine)
    if syscall_number is None:
        raise WardenError("mount_setattr syscall number is not governed")
    attributes = _MountAttributes(
        attr_set=MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        attr_clr=0,
        propagation=0,
        userns_fd=0,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.syscall
    operation.restype = ctypes.c_long
    result = operation(
        ctypes.c_long(syscall_number),
        ctypes.c_int(AT_FDCWD),
        os.fsencode(target),
        ctypes.c_uint(AT_RECURSIVE),
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
    )
    if result != 0:
        value = ctypes.get_errno()
        raise WardenError(f"recursive read-only mount_setattr failed: {os.strerror(value)}")


def _pivot_root(new_root: str, put_old: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    machine = os.uname().machine
    syscall_number = {"x86_64": 155, "aarch64": 41}.get(machine)
    if syscall_number is None:
        raise WardenError("pivot_root syscall number is not governed for this architecture")
    operation = libc.syscall
    operation.restype = ctypes.c_long
    result = operation(
        ctypes.c_long(syscall_number), os.fsencode(new_root), os.fsencode(put_old),
    )
    if result != 0:
        value = ctypes.get_errno()
        raise WardenError(f"pivot_root failed: {os.strerror(value)}")


def make_mounts_recursively_private() -> None:
    _mount(None, "/", None, MS_REC | MS_PRIVATE)


def _remount_private_root_readonly(private_root: Path) -> None:
    """Seal only the fresh root mount, preserving named writable submounts."""

    _mount(
        None,
        os.fspath(private_root),
        None,
        MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
    )
    try:
        flags = os.statvfs(private_root).f_flag
    except OSError as exc:
        raise WardenError("cannot attest the remounted private root") from exc
    if not flags & os.ST_RDONLY:
        raise WardenError("private root mount remained writable")


def pivot_into_private_root(new_root: Path) -> None:
    old_root = new_root / ".old-root"
    try:
        metadata = old_root.lstat()
    except OSError as exc:
        raise WardenError("fixed pivot old-root directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or any(old_root.iterdir())
    ):
        raise WardenError("fixed pivot old-root directory is unsafe")
    os.chdir(new_root)
    _pivot_root(".", ".old-root")
    os.chdir("/")
    _umount2("/.old-root", MNT_DETACH)
    detached = os.lstat("/.old-root")
    if (
        not stat.S_ISDIR(detached.st_mode)
        or detached.st_uid != 0
        or detached.st_gid != 0
        or stat.S_IMODE(detached.st_mode) != 0o700
        or os.listdir("/.old-root")
    ):
        raise WardenError("detached old-root mountpoint is not fixed and empty")


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir(mode=mode, parents=True, exist_ok=False)
    os.chown(path, 0, 0, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)


def _make_mountpoint(path: Path, *, directory: bool = True) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if directory:
        path.mkdir(mode=0o755, exist_ok=True)
    else:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.close(descriptor)
    os.chown(path, 0, 0, follow_symlinks=False)


def _mount_tmpfs(
    path: Path,
    *,
    mode: int,
    readonly: bool = False,
    nodev: bool = True,
) -> None:
    _make_mountpoint(path)
    flags = MS_NOSUID | (MS_NODEV if nodev else 0)
    _mount("monitor-warden", os.fspath(path), "tmpfs", flags, f"mode={mode:o},size=256m")
    if readonly:
        _mount(
            None, os.fspath(path), None,
            MS_REMOUNT | MS_RDONLY | flags,
        )


def _bind_readonly(source: Path, target: Path) -> None:
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise WardenError(f"required system object is unavailable: {source}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise WardenError(f"system bind source must not be symbolic: {source}")
    directory = stat.S_ISDIR(metadata.st_mode)
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise WardenError(f"system bind source has unsafe type: {source}")
    _make_mountpoint(target, directory=directory)
    flags = MS_BIND | (MS_REC if directory else 0)
    _mount(os.fspath(source), os.fspath(target), None, flags)
    _make_readonly_recursively(target)


def _copy_regular(source: Path, target: Path, *, mode: int = 0o555) -> str:
    source_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, source_flags)
    except OSError as exc:
        raise WardenError(f"cannot open command source: {source}") from exc
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0:
            raise WardenError(f"command source is not a root-owned regular file: {source}")
        destination_fd = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise WardenError("short command copy write")
                view = view[written:]
            total += len(chunk)
        after = os.fstat(source_fd)
        source_identity = (
            before.st_dev, before.st_ino, before.st_mode, before.st_uid,
            before.st_gid, before.st_nlink, before.st_size, before.st_mtime_ns,
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid,
            after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns,
        )
        if source_identity != after_identity or total != before.st_size:
            raise WardenError(f"command source changed while copying: {source}")
        os.fchmod(destination_fd, mode)
        os.fchown(destination_fd, 0, 0)
        os.fsync(destination_fd)
        return digest.hexdigest()
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def _stub_program(command: str) -> bytes:
    allowed = [list(item) for item in sorted(ALLOWED_COMMAND_ARGV[command])]
    operation_ids = sorted({
        "argv-collision-matrix",
        *(str(spec["operation"]) for spec in _expected_operation_specs()),
    })
    source = f'''#!/usr/bin/python3
import json
import os
import sys

NAME = {command!r}
ALLOWED = {allowed!r}
ALLOWED_OPERATIONS = {operation_ids!r}
ARGV = sys.argv[1:]
COMMAND_EVENTS = "/evidence/command-events.jsonl"
EVENTS = "/evidence/events.log"
OPERATION_FILE = "/fixture/current-operation"

def operation_id():
    try:
        value = open(OPERATION_FILE, encoding="ascii").read()
    except OSError:
        return ""
    return value[:-1] if value.endswith("\\n") and value.count("\\n") == 1 else ""

OPERATION = operation_id()

def emit(returncode, observation, result="ALLOWED"):
    descriptor = os.open(COMMAND_EVENTS, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        value = {{"argv": ARGV, "command": NAME, "observation": observation,
                 "operation": OPERATION, "result": result, "returncode": returncode}}
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\\n"
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def lifecycle_event(value):
    descriptor = os.open(EVENTS, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, value.encode("ascii") + b"\\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

if OPERATION not in ALLOWED_OPERATIONS or ARGV not in ALLOWED:
    emit({FORBIDDEN_RETURN_CODE}, {{}}, "FORBIDDEN")
    sys.stderr.write("FORBIDDEN\\n")
    raise SystemExit({FORBIDDEN_RETURN_CODE})
lifecycle_event(" ".join([NAME] + ARGV))

returncode = 0
stdout = ""
stderr = ""
observation = {{}}

if NAME == "systemctl":
    state_path = "/fixture/systemctl-state"
    mode_path = "/fixture/systemctl-mode"
    state = open(state_path, encoding="ascii").read().strip() if os.path.exists(state_path) else "active"
    mode = open(mode_path, encoding="ascii").read().strip() if os.path.exists(mode_path) else "normal"
    state_before = state
    if ARGV[:1] == ["show"]:
        if mode == "show-fail": returncode = 1
        else: stdout = state + "\\n"
    elif ARGV == ["stop", "apache2"]:
        if mode == "stop-fail": returncode = 1
        elif mode != "stay-active":
            open(state_path, "w", encoding="ascii").write("inactive\\n")
            state = "inactive"
    elif ARGV == ["start", "apache2"]:
        open(state_path, "w", encoding="ascii").write("active\\n")
        state = "active"
    else:
        returncode = 3
    observation = {{"mode": mode, "state_after": state,
                   "state_before": state_before}}
elif NAME == "docker":
    state_path = "/fixture/docker-state"
    state = open(state_path, encoding="ascii").read().strip() if os.path.exists(state_path) else "absent"
    state_before = state
    identifier = {DOCKER_IDENTIFIER!r}
    if ARGV == ["context", "show"]:
        stdout = "default\\n"
    elif ARGV == ["context", "inspect", "default"]:
        stdout = '[{{"Endpoints":{{"docker":{{"Host":"unix:///var/run/docker.sock","SkipTLSVerify":false}}}}}}]\\n'
    elif ARGV == ["info", "--format", "{{{{json .}}}}"]:
        stdout = '{{"OSType":"linux","SecurityOptions":[]}}\\n'
    elif ARGV[:2] == ["container", "inspect"]:
        if state == "absent":
            stderr = "Error: No such container: http-ztp\\n"
            returncode = 1
        else:
            lifecycle_event("docker-inspect-writer" if state == "running" else "docker-reinspect-writer")
            running = state == "running"
            status = "running" if running else "exited"
            pid = 4242 if running else 0
            stdout = json.dumps([{{"Id":identifier,"Name":"/http-ztp","Image":"sha256:"+"0"*64,"Config":{{"Labels":{{"com.nvidia.http-ztp.managed":"true","com.nvidia.http-ztp.http-root":"/var/www/html","com.nvidia.http-ztp.image":"true","com.nvidia.http-ztp.image-contract":"3","com.nvidia.http-ztp.base-os":"ubuntu-24.04"}}}},"Mounts":[{{"Type":"bind","Source":"/var/www/html","Destination":"/var/www/html","RW":True}},{{"Type":"bind","Source":"/var/lib/http-ztp-container/control-auth","Destination":"/etc/http-ztp","RW":False}},{{"Type":"bind","Source":"/var/lib/http-ztp-container/monitor-auth","Destination":"/var/lib/http-ztp-monitor-auth","RW":True}}],"State":{{"Running":running,"Restarting":False,"Paused":False,"Status":status,"Pid":pid,"Dead":False}}}}], separators=(",", ":")) + "\\n"
            observation.update({{"container_id": identifier, "dead": False,
                                "pid": pid, "running": running}})
    elif ARGV[:1] == ["stop"]:
        lifecycle_event("docker-stop-writer")
        open(state_path, "w", encoding="ascii").write("stopped\\n")
        state = "stopped"
    elif ARGV[:1] == ["rm"]:
        lifecycle_event("docker-remove-writer")
        open(state_path, "w", encoding="ascii").write("absent\\n")
        state = "absent"
    observation.update({{"state_after": state, "state_before": state_before}})
elif NAME == "dpkg":
    if ARGV == ["--print-architecture"]: stdout = "amd64\\n"
    else: returncode = 1
elif NAME in ("dpkg-query", "apt-get"):
    returncode = 99
elif NAME == "supervisorctl":
    if ARGV == ["status"]:
        stdout = "".join(service + " STOPPED Not started\\n" for service in {MANAGED_SERVICES!r})
    elif ARGV[:1] == ["pid"]:
        stdout = "0\\n"
        returncode = 7
elif NAME in ("ss", "apache2ctl", "supervisord"):
    pass
emit(returncode, observation)
sys.stdout.write(stdout)
sys.stderr.write(stderr)
raise SystemExit(returncode)
'''
    return source.encode("utf-8")


def _write_exclusive(path: Path, payload: bytes, mode: int) -> str:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise WardenError("short exclusive evidence write")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return hashlib.sha256(payload).hexdigest()


def _build_command_root(command_root: Path) -> bytes:
    if command_root.exists() or command_root.is_symlink():
        raise WardenError("command root must be absent")
    command_root.mkdir(mode=0o700, parents=False)
    os.chown(command_root, 0, 0)
    _mount(
        "monitor-commands", os.fspath(command_root), "tmpfs",
        MS_NOSUID | MS_NODEV, "mode=0700,size=64m",
    )
    entries: list[dict[str, object]] = []
    for name in sorted(UTILITY_SOURCES):
        digest = _copy_regular(Path(UTILITY_SOURCES[name]), command_root / name)
        entries.append({
            "mode": 0o555, "name": name, "sha256": digest, "type": "utility",
        })
    for name in sorted(ALLOWED_COMMAND_ARGV):
        payload = _stub_program(name)
        digest = _write_exclusive(command_root / name, payload, 0o555)
        entries.append({
            "mode": 0o555, "name": name, "sha256": digest,
            "type": "service-stub",
        })
    os.chmod(command_root, 0o555)
    _mount(
        None, os.fspath(command_root), None,
        MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
    )
    manifest = {
        "entries": entries,
        "leaf_names": sorted(COMMAND_LEAF_NAMES),
        "schema_version": 1,
    }
    return _canonical_json(manifest)


def _file_digest(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o555
        ):
            raise WardenError(f"command leaf metadata changed: {path.name}")
        return _fd_sha256(descriptor, metadata.st_size)
    finally:
        os.close(descriptor)


def validate_command_root(root: Path, manifest_bytes: bytes) -> None:
    document = _load_canonical_json(
        manifest_bytes, label="command manifest", limit=MAX_LOG_BYTES,
    )
    if (
        not isinstance(document, dict)
        or set(document) != {"entries", "leaf_names", "schema_version"}
        or document.get("schema_version") != 1
        or document.get("leaf_names") != sorted(COMMAND_LEAF_NAMES)
        or not isinstance(document.get("entries"), list)
    ):
        raise WardenError("command manifest is invalid")
    try:
        actual_names = {item.name for item in os.scandir(root)}
    except OSError as exc:
        raise WardenError("cannot enumerate command root") from exc
    if actual_names != COMMAND_LEAF_NAMES:
        raise WardenError("command root leaf set changed")
    manifest_entries = document["entries"]
    if len(manifest_entries) != len(COMMAND_LEAF_NAMES):
        raise WardenError("command manifest entry count changed")
    for entry in manifest_entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"mode", "name", "sha256", "type"}
            or not isinstance(entry.get("name"), str)
            or entry.get("mode") != 0o555
            or entry.get("type") not in {"utility", "service-stub"}
            or not isinstance(entry.get("sha256"), str)
        ):
            raise WardenError("command manifest entry is invalid")
    expected = {entry["name"]: entry for entry in manifest_entries}
    if set(expected) != COMMAND_LEAF_NAMES:
        raise WardenError("command manifest names changed")
    for name in sorted(COMMAND_LEAF_NAMES):
        entry = expected[name]
        if (
            set(entry) != {"mode", "name", "sha256", "type"}
            or entry["mode"] != 0o555
            or entry["type"] not in {"utility", "service-stub"}
            or _require_digest(entry["sha256"], "command digest", DIGEST_PATTERN)
            != _file_digest(root / name)
        ):
            raise WardenError(f"command leaf identity changed: {name}")


_SOURCE_GUARD_MODULE: object | None = None


def _load_source_guard():
    """Load the reviewed sibling once, before pivot makes the host name vanish."""

    global _SOURCE_GUARD_MODULE
    if _SOURCE_GUARD_MODULE is not None:
        return _SOURCE_GUARD_MODULE
    source = Path(__file__).with_name("monitor_authority_source_guard.py")
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise WardenError("immutable source guard sibling is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise WardenError("immutable source guard sibling metadata is unsafe")
    module_name = "_http_ztp_monitor_authority_source_guard"
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise WardenError("immutable source guard import spec is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:
        if sys.modules.get(module_name) is module:
            del sys.modules[module_name]
        raise WardenError("immutable source guard sibling cannot be loaded") from exc
    for required in (
        "hold_repository", "hold_export", "export_tree", "verify_export",
        "require_clean_head_tree",
    ):
        if not callable(getattr(module, required, None)):
            raise WardenError("immutable source guard API is incomplete")
    _SOURCE_GUARD_MODULE = module
    return module


def _prepare_external_final_receipt(path: Path) -> int:
    """Pre-open one empty append-only host output, then release its directory."""

    fixed_base = Path("/run/http-ztp-monitor-warden")
    target = Path(path)
    if not target.is_absolute() or ".." in target.parts:
        raise WardenError("external evidence path is not canonical and absolute")
    try:
        relative = target.relative_to(fixed_base)
    except ValueError as exc:
        raise WardenError("external evidence path escapes the fixed warden root") from exc
    if (
        len(relative.parts) != 2
        or relative.parts[1] != "evidence"
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", relative.parts[0]) is None
    ):
        raise WardenError("external evidence path does not have the fixed layout")

    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )

    def validate_directory(descriptor: int, *, exact_private: bool) -> None:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or mode & 0o022
            or (exact_private and mode != 0o700)
        ):
            raise WardenError("external evidence ancestor metadata is unsafe")

    def open_child(
        parent_descriptor: int,
        name: str,
        *,
        create: bool,
        must_be_new: bool,
        exact_private: bool,
    ) -> int:
        created = False
        try:
            descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            if not create:
                raise WardenError("fixed external evidence ancestor is missing")
            try:
                os.mkdir(name, 0o700, dir_fd=parent_descriptor)
            except OSError as exc:
                raise WardenError("cannot create fixed external evidence directory") from exc
            created = True
            descriptor = -1
            try:
                descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
                os.fchown(descriptor, 0, 0)
                os.fchmod(descriptor, 0o700)
                os.fsync(parent_descriptor)
            except BaseException:
                if descriptor >= 0:
                    os.close(descriptor)
                raise
        except OSError as exc:
            raise WardenError("cannot component-walk external evidence path") from exc
        try:
            if must_be_new and not created:
                raise WardenError("external evidence run directory already exists")
            validate_directory(descriptor, exact_private=exact_private)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    root_descriptor = os.open("/", directory_flags)
    run_descriptor = base_descriptor = run_leaf_descriptor = directory_fd = -1
    try:
        validate_directory(root_descriptor, exact_private=False)
        run_descriptor = open_child(
            root_descriptor, "run", create=False, must_be_new=False,
            exact_private=False,
        )
        base_descriptor = open_child(
            run_descriptor, "http-ztp-monitor-warden", create=True,
            must_be_new=False, exact_private=True,
        )
        run_leaf_descriptor = open_child(
            base_descriptor, relative.parts[0], create=True,
            must_be_new=True, exact_private=True,
        )
        directory_fd = open_child(
            run_leaf_descriptor, "evidence", create=True,
            must_be_new=True, exact_private=True,
        )
    finally:
        for ancestor in (
            run_leaf_descriptor, base_descriptor, run_descriptor, root_descriptor,
        ):
            if ancestor >= 0:
                os.close(ancestor)
    if directory_fd < 0:
        raise WardenError("external evidence directory was not held")
    try:
        directory_names = os.listdir(directory_fd)
    except OSError as exc:
        os.close(directory_fd)
        raise WardenError("cannot enumerate external evidence directory") from exc
    if directory_names:
        os.close(directory_fd)
        raise WardenError("host evidence directory must be empty")
    descriptor = -1
    try:
        descriptor = os.open(
            "final-receipt.json",
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != 0
        ):
            raise WardenError("external final-receipt file metadata is unsafe")
        os.fsync(directory_fd)
        return descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        os.close(directory_fd)


def append_external_final_receipt(descriptor: int, receipt: bytes) -> None:
    """Append one already-reread private receipt through the sole host output FD."""

    document = _load_canonical_json(
        receipt, label="external final receipt", limit=MAX_RECEIPT_BYTES,
    )
    if not isinstance(document, dict) or document.get("result") != "PASS":
        raise WardenError("external output is not a final PASS receipt")
    try:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    except OSError as exc:
        raise WardenError("external final receipt descriptor is unavailable") from exc
    before = os.fstat(descriptor)
    if (
        flags & os.O_ACCMODE != os.O_WRONLY
        or not flags & os.O_APPEND
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size != 0
    ):
        raise WardenError("external final receipt descriptor is unsafe or nonempty")
    view = memoryview(receipt)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise WardenError("short external final-receipt append")
        view = view[written:]
    os.fsync(descriptor)
    after = os.fstat(descriptor)
    if (
        (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
         after.st_nlink)
        != (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
            before.st_gid, before.st_nlink)
        or after.st_size != len(receipt)
    ):
        raise WardenError("external final receipt changed during append")


def _install_absolute_commands(private_root: Path, command_root: Path) -> set[str]:
    readonly: set[str] = set()
    for absolute, command in ABSOLUTE_COMMAND_BINDINGS.items():
        relative = absolute.removeprefix("/")
        target = private_root / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        _bind_readonly(command_root / command, target)
        readonly.add("/" + relative)
    (private_root / "bin").symlink_to("usr/bin")
    (private_root / "sbin").symlink_to("usr/sbin")
    return readonly


def _fixture_directory(
    path: Path,
    mode: int,
    *,
    uid: int = 0,
    gid: int = 0,
) -> None:
    try:
        path.mkdir(mode=mode, exist_ok=True)
        metadata = path.lstat()
    except OSError as exc:
        raise WardenError(f"cannot construct fixture directory: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise WardenError(f"fixture parent has an unsafe type: {path}")
    os.chown(path, uid, gid, follow_symlinks=False)
    os.chmod(path, mode, follow_symlinks=False)
    final = path.lstat()
    if (
        not stat.S_ISDIR(final.st_mode)
        or final.st_uid != uid
        or final.st_gid != gid
        or stat.S_IMODE(final.st_mode) != mode
    ):
        raise WardenError(f"fixture directory metadata changed: {path}")


def _fixture_regular(
    path: Path,
    payload: bytes,
    mode: int,
    *,
    uid: int = 0,
    gid: int = 0,
) -> str:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise WardenError("short private-fixture write")
            view = view[written:]
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_size != len(payload)
        ):
            raise WardenError(f"private-fixture metadata changed: {path}")
    finally:
        os.close(descriptor)
    return hashlib.sha256(payload).hexdigest()


def _regular_digest_with_metadata(
    path: Path,
    *,
    mode: int,
    uid: int = 0,
    gid: int = 0,
) -> str:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise WardenError(f"governed fixture file metadata is unsafe: {path}")
        return _fd_sha256(descriptor, metadata.st_size)
    finally:
        os.close(descriptor)


def _regular_payload_with_metadata(
    path: Path,
    *,
    mode: int,
    uid: int = 0,
    gid: int = 0,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != uid
            or before.st_gid != gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
        ):
            raise WardenError(f"governed fixture file metadata is unsafe: {path}")
        payload = _read_frozen_descriptor(descriptor, before.st_size, os.fspath(path))
        after = os.fstat(descriptor)
        rebound = os.stat(path, follow_symlinks=False)
        if (
            _artifact_identity(before) != _artifact_identity(after)
            or _artifact_identity(before) != _artifact_identity(rebound)
        ):
            raise WardenError(f"governed fixture file binding changed: {path}")
        return payload
    finally:
        os.close(descriptor)


def _bind_governed_fixture_file(
    root: Path,
    *,
    source_relative: str,
    target_relative: str,
    mode: int,
    expected_sha256: str | None = None,
) -> str:
    source = root / "immutable-source" / source_relative
    target = root / target_relative
    source_digest = _regular_digest_with_metadata(source, mode=mode)
    if expected_sha256 is not None and source_digest != expected_sha256:
        raise WardenError(f"governed fixture digest changed: {source_relative}")
    _bind_readonly(source, target)
    if _regular_digest_with_metadata(target, mode=mode) != source_digest:
        raise WardenError(f"installed fixture differs from source: {target_relative}")
    return "/" + target_relative


def _create_private_docker_socket(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise WardenError("private Docker socket fixture already exists")
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        endpoint.bind(os.fspath(path))
    except OSError as exc:
        raise WardenError("cannot create the private inert Docker socket") from exc
    finally:
        endpoint.close()
    os.chown(path, 0, 0, follow_symlinks=False)
    os.chmod(path, 0o600, follow_symlinks=False)
    metadata = path.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise WardenError("private Docker socket fixture metadata is unsafe")


def _install_private_fixtures(root: Path) -> set[str]:
    """Install only the private files needed by the real entrypoint matrix."""

    for relative, mode, uid, gid in (
        ("etc/apache2", 0o755, 0, 0),
        ("etc/apache2/conf-enabled", 0o755, 0, 0),
        ("etc/http-ztp", 0o750, 0, 33),
        ("usr/lib/cgi-bin", 0o755, 0, 0),
        ("usr/local/lib", 0o755, 0, 0),
        ("usr/local/lib/http-ztp", 0o755, 0, 0),
        ("var/lib", 0o755, 0, 0),
        ("var/lib/http-ztp-container", 0o700, 0, 0),
        ("var/lib/http-ztp-container/control-auth", 0o750, 0, 33),
        ("var/lib/http-ztp-container/monitor-auth", 0o755, 0, 0),
        ("var/lib/http-ztp-container/monitor-auth/monitor-auth", 0o700, 33, 33),
        ("var/lib/http-ztp-monitor-auth", 0o755, 0, 0),
        ("var/www", 0o755, 0, 0),
        ("var/www/html", 0o755, 0, 0),
        ("var/empty", 0o755, 0, 0),
        ("run/systemd", 0o755, 0, 0),
        ("run/systemd/system", 0o755, 0, 0),
    ):
        _fixture_directory(root / relative, mode, uid=uid, gid=gid)

    # Docker's governed local-daemon check names the conventional
    # /var/run/docker.sock spelling.  Resolve it only to the private /run
    # tmpfs; never bind either host directory or the host Docker socket.
    private_var_run = root / "var/run"
    if private_var_run.exists() or private_var_run.is_symlink():
        raise WardenError("private /var/run alias already exists")
    private_var_run.symlink_to("/run", target_is_directory=True)

    readonly = {
        _bind_governed_fixture_file(
            root,
            source_relative="tools/control-auth.py",
            target_relative="usr/local/lib/http-ztp/control-auth.py",
            mode=0o755,
            expected_sha256=CONTROL_AUTH_HELPER_SHA256,
        ),
        _bind_governed_fixture_file(
            root,
            source_relative="monitor/ztp-monitor-control.cgi",
            target_relative="usr/lib/cgi-bin/ztp-monitor-control",
            mode=0o755,
        ),
        _bind_governed_fixture_file(
            root,
            source_relative="infra/docker/apache-ztp.conf",
            target_relative="etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
            mode=0o644,
            expected_sha256=APACHE_PUBLIC_BOUNDARY_SHA256,
        ),
    }
    factory_control_users = _factory_control_users_from_pinned_helper(
        _regular_payload_with_metadata(
            root / "usr/local/lib/http-ztp/control-auth.py", mode=0o755,
        )
    )
    for relative in (
        "etc/http-ztp/control-users.htpasswd",
        "var/lib/http-ztp-container/control-auth/control-users.htpasswd",
    ):
        digest = _fixture_regular(
            root / relative, factory_control_users, 0o640, uid=0, gid=33,
        )
        if digest != hashlib.sha256(factory_control_users).hexdigest():
            raise WardenError("control credential fixture digest changed")

    # The Docker authority is deliberately malformed once.  It is separate
    # from the native tree (which the runner removes/recreates repeatedly), so
    # the Docker recovery phase supplies the fourth independently reached
    # reset warning without making either canonical pathname a symlink.
    _fixture_regular(
        root / "var/lib/http-ztp-container/monitor-auth/status.lock",
        b'{"schema_version":1', 0o660, uid=0, gid=33,
    )
    _fixture_regular(
        root
        / "var/lib/http-ztp-container/monitor-auth/monitor-auth/factory-status.json",
        _expected_valid_authority_payloads()[
            "monitor-auth/factory-status.json"
        ],
        0o600,
        uid=33,
        gid=33,
    )
    _fixture_regular(
        root / "evidence/service-state.json", INITIAL_SERVICE_STATE, 0o600,
    )
    _create_private_docker_socket(root / "run/docker.sock")
    return readonly


def _prepare_private_root(config: WardenConfig, held_repository) -> PrivateRootState:
    guard = _load_source_guard()
    try:
        guard.require_clean_head_tree(held_repository, config.tree_id)
    except Exception as exc:
        raise WardenError("working tree does not equal the selected Git tree") from exc

    if config.private_root.exists() or config.private_root.is_symlink():
        raise WardenError("private root must be absent")
    config.private_root.mkdir(mode=0o700, parents=False)
    os.chown(config.private_root, 0, 0)
    _mount(
        "monitor-root", os.fspath(config.private_root), "tmpfs",
        MS_NOSUID | MS_NODEV, "mode=0755,size=1024m",
    )
    root = config.private_root
    for relative in (
        "commands", "dev", "etc", "evidence", "fixture", "proc", "root",
        "run", "source", "sys", "tmp", "usr/bin", "usr/lib", "usr/local",
        "usr/sbin", "usr/share", "var", "opt", "immutable-source",
        "infra-runtime",
    ):
        (root / relative).mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(root / "root", 0o700)

    try:
        source_manifest = guard.export_tree(
            held_repository,
            config.tree_id,
            root / "immutable-source-export",
            required_uid=0,
            required_gid=0,
        )
        guard.verify_export(
            root / "immutable-source-export", source_manifest,
            expected_tree_id=config.tree_id,
            required_uid=0, required_gid=0,
        )
    except WardenError:
        raise
    except Exception as exc:
        raise WardenError("immutable Git-tree export failed") from exc

    # Bind the one exact immutable export into both held and execution views.
    # Only a separate overlay upper accepts infra's governed runtime logs and
    # status.  It cannot alter the lower tree and is inspected independently.
    _bind_readonly(root / "immutable-source-export", root / "immutable-source")
    _bind_readonly(root / "immutable-source-export", root / "source")
    upper = root / "infra-runtime/upper"
    work = root / "infra-runtime/work"
    upper.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    os.chown(upper, 0, 0)
    os.chown(work, 0, 0)
    infra_upper_descriptor = os.open(
        upper,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    _mount(
        "overlay",
        os.fspath(root / "source/infra"),
        "overlay",
        MS_NOSUID | MS_NODEV,
        "lowerdir=" + os.fspath(root / "immutable-source-export/infra")
        + ",upperdir=" + os.fspath(upper)
        + ",workdir=" + os.fspath(work),
    )
    _mount_tmpfs(root / "immutable-source-export", mode=0o555, readonly=True)
    _mount_tmpfs(root / "infra-runtime", mode=0o555, readonly=True)

    command_manifest = _build_command_root(config.command_root)
    _bind_readonly(config.command_root, root / "commands")
    absolute_commands = _install_absolute_commands(root, config.command_root)

    writable: set[str] = set()
    readonly = {
        "/commands", "/immutable-source", "/source",
        "/immutable-source-export", "/infra-runtime",
    } | absolute_commands
    for relative, mode in (
        ("run", 0o755),
        ("tmp", 0o1777),
        ("var", 0o755),
        ("fixture", 0o700),
        ("evidence", 0o700),
    ):
        _mount_tmpfs(root / relative, mode=mode)
        writable.add("/" + relative)
    _mount_tmpfs(root / "dev", mode=0o755, nodev=False)
    writable.add("/dev")
    writable.add("/source/infra")

    _mount_tmpfs(root / "sys", mode=0o555, readonly=True)
    readonly.add("/sys")

    # Bind only library/data directories required by the copied interpreter
    # and utilities.  Executable PATH directories, host state, cgroups, and
    # control filesystems are never imported.
    architecture = os.uname().machine
    multiarch = {
        "x86_64": "x86_64-linux-gnu",
        "aarch64": "aarch64-linux-gnu",
    }.get(architecture)
    if multiarch is None:
        raise WardenError("unsupported private-root architecture")
    system_directories = [
        Path("/usr/lib") / multiarch,
        Path("/usr/lib/python3"),
        Path("/usr/lib/locale"),
        Path("/usr/share/locale"),
        Path("/usr/share/zoneinfo"),
    ]
    versioned_python = Path(f"/usr/lib/python{sys.version_info.major}.{sys.version_info.minor}")
    if versioned_python not in system_directories:
        system_directories.append(versioned_python)
    for source in system_directories:
        if not source.exists():
            if source in {Path("/usr/lib/python3"), Path("/usr/lib/locale")}:
                continue
            raise WardenError(f"required system directory is missing: {source}")
        target = root / source.relative_to("/")
        _bind_readonly(source, target)
        readonly.add(os.fspath(source))
    lib64 = Path("/usr/lib64")
    if lib64.exists():
        _bind_readonly(lib64, root / "usr/lib64")
        readonly.add("/usr/lib64")
        (root / "lib64").symlink_to("usr/lib64")
    (root / "lib").symlink_to("usr/lib")

    for source, target_relative in (
        (Path("/etc/ld.so.cache"), Path("etc/ld.so.cache")),
        (Path("/etc/passwd"), Path("etc/passwd")),
        (Path("/etc/group"), Path("etc/group")),
        (Path("/etc/nsswitch.conf"), Path("etc/nsswitch.conf")),
        # /etc/os-release is commonly a symlink on Ubuntu.  Bind its fixed
        # root-owned regular target, never the link or the surrounding /etc.
        (Path("/usr/lib/os-release"), Path("etc/os-release")),
    ):
        if not source.exists():
            continue
        target = root / target_relative
        _bind_readonly(source, target)
        readonly.add("/" + os.fspath(target_relative))

    readonly |= _install_private_fixtures(root)

    proc_target = root / "proc"
    _mount("proc", os.fspath(proc_target), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    writable.add("/proc")

    for name, major, minor in (
        ("null", 1, 3), ("zero", 1, 5), ("random", 1, 8), ("urandom", 1, 9),
    ):
        target = root / "dev" / name
        os.mknod(target, stat.S_IFCHR | 0o666, os.makedev(major, minor))
        os.chown(target, 0, 0, follow_symlinks=False)
    (root / "dev/fd").symlink_to("/proc/self/fd")
    (root / "dev/stdin").symlink_to("/proc/self/fd/0")
    (root / "dev/stdout").symlink_to("/proc/self/fd/1")
    (root / "dev/stderr").symlink_to("/proc/self/fd/2")

    _write_exclusive(root / "evidence/source-manifest.json", source_manifest, 0o400)
    _write_exclusive(root / "evidence/command-manifest.json", command_manifest, 0o400)
    _write_exclusive(
        root / "evidence/expected-tree-id",
        (config.tree_id + "\n").encode("ascii"),
        0o400,
    )
    _mkdir(root / ".old-root", 0o700)
    _remount_private_root_readonly(root)
    readonly.add("/")
    return PrivateRootState(
        tree_id=config.tree_id,
        source_manifest=source_manifest,
        command_manifest=command_manifest,
        writable_mounts=frozenset(writable),
        readonly_mounts=frozenset(readonly),
        infra_upper_descriptor=infra_upper_descriptor,
    )


def _inject_test_hostile_mount(config: WardenConfig) -> None:
    """Create one fixed negative mount only inside the disposable namespace."""

    case = config.hostile_test_case
    if case == "nested-writable-mount":
        _mount_tmpfs(config.private_root / "fixture/hostile-nested", mode=0o700)
    elif case == "host-device-bind":
        target = config.private_root / "fixture/host-device"
        _make_mountpoint(target, directory=False)
        _mount("/dev/null", os.fspath(target), None, MS_BIND)
        _make_readonly_recursively(target)
    elif case == "host-sys-bind":
        target = config.private_root / "fixture/host-sys"
        _make_mountpoint(target)
        _mount("/sys", os.fspath(target), None, MS_BIND | MS_REC)
        _make_readonly_recursively(target)


def _inject_test_double_fork_survivor() -> None:
    first = os.fork()
    if first == 0:
        try:
            os.setsid()
            second = os.fork()
            if second != 0:
                os._exit(0)
            while True:
                signal.pause()
        finally:
            os._exit(97)
    try:
        os.waitpid(first, 0)
    except ChildProcessError as exc:
        raise WardenError("hostile double-fork parent was not observable") from exc


def _set_child_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.prctl
    operation.argtypes = (
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.c_ulong,
    )
    operation.restype = ctypes.c_int
    _libc_call(
        "prctl(PR_SET_CHILD_SUBREAPER)",
        operation(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0),
    )


def _prctl(
    option: int,
    argument: int,
    argument2: int = 0,
    argument3: int = 0,
    argument4: int = 0,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.prctl
    operation.argtypes = (
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.c_ulong,
    )
    operation.restype = ctypes.c_int
    _libc_call(
        "prctl",
        operation(option, argument, argument2, argument3, argument4),
    )


class _CapabilityHeader(ctypes.Structure):
    _fields_ = (
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    )


class _CapabilityData(ctypes.Structure):
    _fields_ = (
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    )


def _restrict_supervisor_capabilities() -> None:
    """Close the `/proc/1/fd` route to host references before child exec."""

    # The fixture needs ordinary root ownership/set-id operations, but never
    # mount/setns, ptrace, device, module, network-administration, or raw-I/O
    # authority.  Securebits and no_new_privs prevent UID 0 exec from restoring
    # capabilities which are removed here.
    retained = frozenset({0, 1, 3, 4, 5, 6, 7, 10})
    _prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED)
    _prctl(PR_SET_NO_NEW_PRIVS, 1)
    _prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    for capability in range(64):
        if capability in retained:
            continue
        libc = ctypes.CDLL(None, use_errno=True)
        result = libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0)
        if result != 0 and ctypes.get_errno() != errno.EINVAL:
            raise OSError(ctypes.get_errno(), "cannot drop capability bounding bit")
    effective = [0, 0]
    for capability in retained:
        effective[capability // 32] |= 1 << (capability % 32)
    header = _CapabilityHeader(version=LINUX_CAPABILITY_VERSION_3, pid=0)
    data = (_CapabilityData * 2)(
        _CapabilityData(effective[0], effective[0], effective[0]),
        _CapabilityData(effective[1], effective[1], effective[1]),
    )
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.capset
    operation.argtypes = (ctypes.POINTER(_CapabilityHeader), ctypes.POINTER(_CapabilityData))
    operation.restype = ctypes.c_int
    if operation(ctypes.byref(header), data) != 0:
        value = ctypes.get_errno()
        raise OSError(value, "cannot install supervisor capability set")
    for capability in retained:
        _prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, capability)


def _mount_table_bytes() -> bytes:
    try:
        raw = Path("/proc/self/mountinfo").read_bytes()
    except OSError as exc:
        raise WardenError("cannot capture mount table") from exc
    if not raw or len(raw) > MAX_LOG_BYTES or not raw.endswith(b"\n"):
        raise WardenError("mount table evidence is malformed")
    return raw


def verify_supervisor_preconditions(state: PrivateRootState) -> str:
    """Validate every authority boundary immediately before the sole child."""

    validate_command_root(Path("/commands"), state.command_manifest)
    guard = _load_source_guard()
    try:
        guard.verify_export(
            Path("/immutable-source"), state.source_manifest,
            expected_tree_id=state.tree_id,
            required_uid=0, required_gid=0,
        )
        guard.verify_export(
            Path("/source"), state.source_manifest,
            expected_tree_id=state.tree_id,
            required_uid=0, required_gid=0,
        )
    except Exception as exc:
        raise WardenError("private source changed before supervisor start") from exc
    if tuple(SUPERVISOR_ARGUMENTS) != (
        "/source/test_cases/run_monitor_authority_entrypoints.sh",
        "--execute-private-fixtures",
    ):
        raise WardenError("supervisor argv contract changed")
    validate_supervisor_environment(SUPERVISOR_ENVIRONMENT)
    mount_bytes = _mount_table_bytes()
    records = read_mount_records()
    validate_mount_records(
        records,
        writable_paths=set(state.writable_mounts),
        readonly_paths=set(state.readonly_mounts),
    )
    return hashlib.sha256(mount_bytes).hexdigest()


def validate_supervisor_environment(environment: object) -> None:
    expected = {
        "COMMAND_ROOT": "/commands",
        "EVIDENCE_ROOT": "/evidence",
        "FIXTURE_ROOT": "/fixture",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/commands",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if not isinstance(environment, dict) or environment != expected:
        raise WardenError("supervisor environment is not the exact fixed mapping")


def _hold_private_exports(state: PrivateRootState):
    guard = _load_source_guard()
    immutable = guard.hold_export(
        Path("/immutable-source"),
        state.source_manifest,
        expected_tree_id=state.tree_id,
        required_uid=0,
        required_gid=0,
        require_readonly=True,
    )
    try:
        execution = guard.hold_export(
            Path("/source"),
            state.source_manifest,
            expected_tree_id=state.tree_id,
            required_uid=0,
            required_gid=0,
            require_readonly=True,
        )
    except BaseException:
        immutable.close()
        raise
    return immutable, execution


def _verify_held_repository_after_pivot(held_repository) -> None:
    verifier = getattr(held_repository, "verify_descriptor", None)
    if callable(verifier):
        verifier()
        return
    metadata = os.fstat(held_repository.descriptor)
    current = (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid,
    )
    if current != held_repository.identity:
        raise WardenError("held source-directory descriptor changed after pivot")


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        process.poll()
        return
    except OSError as group_error:
        # Darwin can report EPERM during the short setsid/exit race.  Killing
        # the direct child is still bounded; Linux PID 1 separately reaps and
        # rejects any adopted process-group survivor.
        if process.poll() is not None:
            return
        try:
            process.kill()
        except ProcessLookupError:
            process.poll()
            return
        except OSError as child_error:
            if process.poll() is not None:
                return
            raise WardenError("supervisor process group could not be killed") from child_error
        if process.poll() is not None:
            return
        if isinstance(group_error, PermissionError):
            # `process.kill()` was accepted.  The bounded wait in the caller
            # remains the authoritative proof that the child was reaped.
            return


def _terminate_and_reap_supervisor(process: subprocess.Popen[bytes]) -> None:
    _terminate_process_group(process)
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired as exc:
            raise WardenError("supervisor could not be reaped after SIGKILL") from exc


def _read_supervisor_streams(
    process: subprocess.Popen[bytes],
    *,
    deadline_seconds: float,
    byte_limit: int,
) -> tuple[bytes, bytes]:
    if process.stdout is None or process.stderr is None:
        raise WardenError("supervisor pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + deadline_seconds
    primary_error: BaseException | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WardenError("supervisor exceeded its fixed deadline")
            events = selector.select(remaining)
            if not events:
                raise WardenError("supervisor exceeded its fixed deadline")
            for key, _mask in events:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = captured[key.data]
                target.extend(chunk)
                if len(target) > byte_limit:
                    raise WardenError(f"supervisor {key.data} exceeded its byte limit")
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise WardenError("supervisor did not exit by its fixed deadline") from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        if process.poll() is None:
            try:
                _terminate_and_reap_supervisor(process)
            except BaseException:
                # Cleanup must not replace the primary deadline/limit verdict.
                # With no primary verdict, failure to reap remains fail-closed.
                if primary_error is None:
                    raise
    return bytes(captured["stdout"]), bytes(captured["stderr"])


def _spawn_only_supervisor(pass_descriptors: tuple[int, ...] = ()) -> tuple[int, bytes, bytes]:
    # Repository code crosses exactly here.  FD 9, source-dir descriptors and
    # host sentinel descriptors remain in PID 1 and cannot reach this child.
    # The production call is exactly pass_fds=(); a fixed hostile test may
    # deliberately substitute one held descriptor and must then fail.
    validate_supervisor_environment(SUPERVISOR_ENVIRONMENT)
    process = subprocess.Popen(
        list(SUPERVISOR_ARGUMENTS),
        cwd="/source",
        env=dict(SUPERVISOR_ENVIRONMENT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=pass_descriptors,
        start_new_session=True,
        preexec_fn=_restrict_supervisor_capabilities,
    )
    stdout, stderr = _read_supervisor_streams(
        process,
        deadline_seconds=SUPERVISOR_DEADLINE_SECONDS,
        byte_limit=MAX_SUPERVISOR_STREAM_BYTES,
    )
    return int(process.returncode), stdout, stderr


def _numeric_proc_pids() -> set[int]:
    try:
        names = os.listdir("/proc")
    except OSError as exc:
        raise WardenError("cannot enumerate private procfs") from exc
    return {
        int(name) for name in names
        if name.isascii() and name.isdecimal() and int(name) != os.getpid()
    }


def _reap_exited_children() -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def require_all_descendants_zero() -> None:
    """Reap PID-namespace descendants and fail on every survivor."""

    _reap_exited_children()
    survivors = _numeric_proc_pids()
    if survivors:
        for child in sorted(survivors):
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + DESCENDANT_REAP_SECONDS
        while time.monotonic() < deadline:
            _reap_exited_children()
            if not _numeric_proc_pids():
                break
            time.sleep(0.01)
        raise WardenError("supervisor left a descendant in the private PID namespace")
    if _numeric_proc_pids():
        raise WardenError("all-descendant-zero proof is unstable")


def _read_bounded(path: Path, *, limit: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WardenError(f"missing {label}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > limit
        ):
            raise WardenError(f"unsafe {label} metadata")
        payload = os.read(descriptor, limit + 1)
        if len(payload) != metadata.st_size or os.read(descriptor, 1):
            raise WardenError(f"unstable {label}")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_mode, after.st_uid,
            after.st_gid, after.st_nlink, after.st_size, after.st_mtime_ns,
        ) != (
            metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns,
        ):
            raise WardenError(f"{label} changed while reading")
        return payload
    finally:
        os.close(descriptor)


def _read_evidence_artifact(
    name: str,
    *,
    limit: int = MAX_LOG_BYTES,
    allow_empty: bool = False,
) -> bytes:
    if (
        not isinstance(name, str)
        or not name
        or "/" in name
        or name in {".", ".."}
    ):
        raise WardenError("unsafe evidence artifact name")
    path = Path("/evidence") / name
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WardenError(f"missing reachability artifact: {name}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or before.st_size > limit
            or (before.st_size == 0 and not allow_empty)
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise WardenError(f"unsafe reachability artifact metadata: {name}")
        payload = os.read(descriptor, limit + 1)
        if len(payload) != before.st_size or os.read(descriptor, 1):
            raise WardenError(f"unstable reachability artifact: {name}")
        after = os.fstat(descriptor)
        fingerprint = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
            item.st_nlink, item.st_size, item.st_mtime_ns,
        )
        if fingerprint(before) != fingerprint(after):
            raise WardenError(f"reachability artifact changed while reading: {name}")
        return payload
    finally:
        os.close(descriptor)


def _live_snapshot_record(path: Path) -> dict[str, object]:
    try:
        named = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise WardenError(f"protected snapshot path is unavailable: {path}") from exc
    if stat.S_ISDIR(named.st_mode):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        kind = "directory"
    elif stat.S_ISREG(named.st_mode) and named.st_nlink == 1:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        kind = "file"
    else:
        raise WardenError(f"protected snapshot type is unsafe: {path}")
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WardenError(f"cannot hold protected snapshot path: {path}") from exc
    try:
        held = os.fstat(descriptor)
        digest = None
        if kind == "file":
            digest = _fd_sha256(descriptor, held.st_size)
        rebound = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if (
        _artifact_identity(named) != _artifact_identity(held)
        or _artifact_identity(named) != _artifact_identity(rebound)
    ):
        raise WardenError(f"protected snapshot path changed: {path}")
    return _opaque_metadata_record(
        held, path=os.fspath(path), kind=kind, sha256=digest,
    )


def _live_teardown_snapshot_records() -> tuple[dict[str, object], ...]:
    root = "/var/lib/http-ztp-monitor-auth"
    try:
        root_names = set(os.listdir(root))
        cache_names = set(os.listdir(root + "/monitor-auth"))
    except OSError as exc:
        raise WardenError("cannot enumerate protected Monitor authority") from exc
    if root_names != {"status.lock", "monitor-auth"} or cache_names != {
        "factory-status.json",
    }:
        raise WardenError("protected Monitor authority path set changed")
    paths = {
        Path("/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"),
        Path("/usr/local/lib/http-ztp/control-auth.py"),
        *(Path(path) for path in _authority_expected_paths(root, marker_phase=None)),
    }
    return tuple(_live_snapshot_record(path) for path in sorted(paths))


def _validate_teardown_snapshot(raw: bytes) -> None:
    expected = _parse_teardown_snapshot(raw, "teardown snapshot")
    if _live_teardown_snapshot_records() != expected:
        raise WardenError("teardown changed an authority byte or identity")


def _parse_snapshot_records(
    raw_records: object, *, label: str,
) -> tuple[dict[str, object], ...]:
    if not isinstance(raw_records, list) or not raw_records:
        raise WardenError(f"{label} records are unavailable")
    records: list[dict[str, object]] = []
    paths: set[str] = set()
    base_keys = {
        "ctime_ns", "device", "gid", "inode", "links", "mode",
        "mtime_ns", "path", "size", "type", "uid",
    }
    for raw_record in raw_records:
        if not isinstance(raw_record, dict):
            raise WardenError(f"{label} record grammar is invalid")
        kind = raw_record.get("type")
        expected_keys = base_keys | ({"sha256"} if kind == "file" else set())
        if (
            kind not in {"directory", "file"}
            or set(raw_record) != expected_keys
            or not isinstance(raw_record.get("path"), str)
            or not raw_record["path"].startswith("/")
            or raw_record["path"] in paths
            or raw_record["path"].encode(
                "ascii", "ignore",
            ).decode("ascii") != raw_record["path"]
            or any(
                not _is_exact_int(raw_record.get(field))
                for field in (
                    "ctime_ns", "device", "gid", "inode", "links", "mode",
                    "mtime_ns", "size", "uid",
                )
            )
            or raw_record["device"] < 0
            or raw_record["inode"] <= 0
            or raw_record["links"] <= 0
            or raw_record["size"] < 0
            or (
                kind == "file"
                and (
                    raw_record["links"] != 1
                    or not isinstance(raw_record.get("sha256"), str)
                    or DIGEST_PATTERN.fullmatch(raw_record["sha256"]) is None
                )
            )
        ):
            raise WardenError(f"{label} record grammar is invalid")
        paths.add(raw_record["path"])
        records.append(raw_record)
    if tuple(record["path"] for record in records) != tuple(sorted(paths)):
        raise WardenError(f"{label} records are not in canonical path order")
    return tuple(records)


def _parse_snapshot_jsonl(
    raw: bytes, *, label: str, expected_stages: Sequence[str],
) -> tuple[tuple[str, tuple[dict[str, object], ...]], ...]:
    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_LOG_BYTES
        or not raw.endswith(b"\n")
        or b"\x00" in raw
    ):
        raise WardenError(f"{label} framing is invalid")
    lines = raw.splitlines(keepends=True)
    if len(lines) != len(expected_stages):
        raise WardenError(f"{label} stage set is incomplete or duplicated")
    rows: list[tuple[str, tuple[dict[str, object], ...]]] = []
    for expected_stage, line in zip(expected_stages, lines):
        document = _load_canonical_json(
            line, label=f"{label} stage", limit=MAX_RECEIPT_BYTES,
        )
        if (
            not isinstance(document, dict)
            or set(document) != {"records", "stage"}
            or document.get("stage") != expected_stage
        ):
            raise WardenError(f"{label} stage grammar changed")
        rows.append((expected_stage, _parse_snapshot_records(
            document["records"], label=f"{label} {expected_stage}",
        )))
    return tuple(rows)


def _authority_expected_paths(root: str, *, marker_phase: str | None) -> set[str]:
    paths = {
        root,
        root + "/status.lock",
        root + "/monitor-auth",
        root + "/monitor-auth/factory-status.json",
    }
    if marker_phase is not None:
        paths.add(
            root
            + "/monitor-auth/.factory-status.11111111111111111111111111111111.tmp"
        )
    return paths


def _validate_authority_record_set(
    records: Sequence[Mapping[str, object]],
    *,
    root: str,
    state: str,
) -> None:
    marker_phase = state.removeprefix("marker:") if state.startswith("marker:") else None
    by_path = {str(record["path"]): record for record in records}
    if set(by_path) != _authority_expected_paths(
        root, marker_phase=marker_phase,
    ):
        raise WardenError("authority snapshot path set changed")
    metadata = {
        root: ("directory", stat.S_IFDIR | 0o755, 0, 0),
        root + "/monitor-auth": ("directory", stat.S_IFDIR | 0o700, 33, 33),
        root + "/status.lock": ("file", stat.S_IFREG | 0o660, 0, 33),
        root + "/monitor-auth/factory-status.json": (
            "file", stat.S_IFREG | 0o600, 33, 33,
        ),
    }
    for path, (kind, mode, uid, gid) in metadata.items():
        record = by_path[path]
        if (
            record["type"] != kind
            or record["mode"] != mode
            or record["uid"] != uid
            or record["gid"] != gid
            or (kind == "file" and record["links"] != 1)
        ):
            raise WardenError("authority snapshot metadata is not exact")

    payloads = dict(_expected_valid_authority_payloads())
    if state.startswith("bad:"):
        try:
            index = int(state.split(":", 1)[1])
            target, payload = _expected_bad_authority_payloads()[index]
        except (IndexError, ValueError) as exc:
            raise WardenError("authority snapshot bad-state index is invalid") from exc
        payloads[target] = payload
    for relative, payload in payloads.items():
        record = by_path[root + "/" + relative]
        if (
            record["size"] != len(payload)
            or record["sha256"] != hashlib.sha256(payload).hexdigest()
        ):
            raise WardenError("authority snapshot payload is not exact")

    if marker_phase is not None:
        if marker_phase not in {
            "recovery-in-progress", "recovery-committed-cleanup-pending",
        }:
            raise WardenError("authority marker phase is invalid")
        marker_path = (
            root
            + "/monitor-auth/.factory-status.11111111111111111111111111111111.tmp"
        )
        marker = by_path[marker_path]
        marker_payload = _canonical_json({
            "phase": marker_phase, "schema_version": 1,
        })
        if (
            marker["type"] != "file"
            or marker["mode"] != stat.S_IFREG | 0o600
            or marker["uid"] != 33
            or marker["gid"] != 33
            or marker["links"] != 1
            or marker["size"] != len(marker_payload)
            or marker["sha256"] != hashlib.sha256(marker_payload).hexdigest()
        ):
            raise WardenError("authority recovery marker is not exact")


def _validate_authority_observations(
    raw: bytes,
    *,
    label: str,
    root: str,
    stage_states: Sequence[tuple[str, str]],
    equal_stage_groups: Sequence[Sequence[str]] = (),
) -> tuple[tuple[str, tuple[dict[str, object], ...]], ...]:
    rows = _parse_snapshot_jsonl(
        raw, label=label,
        expected_stages=tuple(stage for stage, _state in stage_states),
    )
    by_stage = dict(rows)
    for stage, state in stage_states:
        _validate_authority_record_set(by_stage[stage], root=root, state=state)
    for group in equal_stage_groups:
        if not group:
            raise WardenError("empty authority equality group")
        baseline = by_stage[group[0]]
        if any(by_stage[stage] != baseline for stage in group[1:]):
            raise WardenError("read-only authority observation changed")
    return rows


def _authority_record_subset(
    records: Sequence[Mapping[str, object]], *, root: str,
) -> tuple[dict[str, object], ...]:
    expected_paths = _authority_expected_paths(root, marker_phase=None)
    by_path = {
        str(record.get("path")): dict(record)
        for record in records
        if str(record.get("path")) in expected_paths
    }
    if set(by_path) != expected_paths:
        raise WardenError("authority continuity record set is incomplete")
    return tuple(by_path[path] for path in sorted(expected_paths))


def _authority_record_digest(
    records: Sequence[Mapping[str, object]], *, root: str,
) -> str:
    exact = _authority_record_subset(records, root=root)
    return hashlib.sha256(_canonical_json(exact)).hexdigest()


def _parse_teardown_snapshot(
    raw: bytes, label: str,
) -> tuple[dict[str, object], ...]:
    document = _load_canonical_json(
        raw, label=label, limit=MAX_LOG_BYTES,
    )
    if not isinstance(document, dict) or set(document) != {"records"}:
        raise WardenError(f"{label} grammar is invalid")
    records = _parse_snapshot_records(document["records"], label=label)
    authority_root = "/var/lib/http-ztp-monitor-auth"
    authority_paths = _authority_expected_paths(authority_root, marker_phase=None)
    fixed_paths = {
        "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
        "/usr/local/lib/http-ztp/control-auth.py",
    }
    by_path = {str(record["path"]): record for record in records}
    if set(by_path) != authority_paths | fixed_paths:
        raise WardenError(f"{label} path set is invalid")
    _validate_authority_record_set(
        tuple(by_path[path] for path in sorted(authority_paths)),
        root=authority_root,
        state="valid",
    )
    expected_fixed = {
        "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf": (
            stat.S_IFREG | 0o644, APACHE_PUBLIC_BOUNDARY_SHA256,
        ),
        "/usr/local/lib/http-ztp/control-auth.py": (
            stat.S_IFREG | 0o755, CONTROL_AUTH_HELPER_SHA256,
        ),
    }
    for path, (mode, digest) in expected_fixed.items():
        record = by_path[path]
        if (
            record["type"] != "file"
            or record["mode"] != mode
            or record["uid"] != 0
            or record["gid"] != 0
            or record["links"] != 1
            or record["sha256"] != digest
        ):
            raise WardenError(f"{label} fixed authority is invalid")
    return records


def _validate_teardown_transition(
    before_raw: bytes, after_raw: bytes,
) -> tuple[str, ...]:
    before = _parse_teardown_snapshot(before_raw, "teardown before snapshot")
    after = _parse_teardown_snapshot(after_raw, "teardown after snapshot")
    if after != before:
        raise WardenError("teardown changed protected authority identity or bytes")
    return tuple(str(record["path"]) for record in before)


def _parse_cgi_response(
    raw: bytes,
    *,
    expected_status: str,
    expected_document: object,
) -> object:
    if not isinstance(raw, bytes) or len(raw) > MAX_RECEIPT_BYTES or b"\x00" in raw:
        raise WardenError("CGI response framing is invalid")
    if raw.count(b"\r\n\r\n") != 1:
        raise WardenError("CGI response header boundary is not exact")
    header_raw, body = raw.split(b"\r\n\r\n", 1)
    try:
        headers = header_raw.decode("ascii", "strict").split("\r\n")
    except UnicodeDecodeError as exc:
        raise WardenError("CGI headers are not ASCII") from exc
    expected_prefix = [
        f"Status: {expected_status}",
        "Content-Type: application/json; charset=utf-8",
        "Cache-Control: no-store",
    ]
    if headers[:3] != expected_prefix or len(headers) != 4:
        raise WardenError("CGI response headers are not canonical")
    length_prefix = "Content-Length: "
    if not headers[3].startswith(length_prefix):
        raise WardenError("CGI response lacks canonical Content-Length")
    length_text = headers[3][len(length_prefix):]
    if not length_text.isascii() or not length_text.isdigit():
        raise WardenError("CGI Content-Length is invalid")
    if str(int(length_text)) != length_text or int(length_text) != len(body):
        raise WardenError("CGI Content-Length does not match its body")
    try:
        document = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WardenError("CGI response body is not JSON") from exc
    expected_body = json.dumps(expected_document, ensure_ascii=False).encode("utf-8")
    if body != expected_body or document != expected_document:
        raise WardenError("CGI response body is not the exact expected JSON bytes")
    return document


def _expected_cgi_invocation_bytes() -> bytes:
    return _canonical_json({
        "argv": [
            "setpriv", "--reuid=33", "--regid=33", "--clear-groups",
            "env", "-i", "CONTROL_REQUIRE_AUTH=1", "AUTH_TYPE=Basic",
            "REMOTE_USER=nvis", "PATH_INFO=",
            "SCRIPT_NAME=/monitor/control/ztp-monitor", "REQUEST_METHOD=GET",
            "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "PATH=/commands", "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "/usr/lib/cgi-bin/ztp-monitor-control",
        ],
        "returncode": 0,
    })


def _expected_attest_invocation_bytes() -> bytes:
    return _canonical_json({
        "argv": [
            "/usr/local/lib/http-ztp/control-auth.py",
            "monitor-authority-attest-decision",
        ],
        "returncode": 0,
    })


def _validate_operation_results(
    raw: bytes,
    *,
    payloads: Mapping[str, bytes],
) -> tuple[dict[str, object], ...]:
    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_LOG_BYTES
        or b"\x00" in raw
        or not raw.endswith(b"\n")
    ):
        raise WardenError("operation-result log framing is invalid")
    lines = raw.splitlines(keepends=True)
    specs = _expected_operation_specs()
    if len(lines) != len(specs):
        raise WardenError("operation-result log is incomplete or duplicated")
    records: list[dict[str, object]] = []
    referenced: set[str] = set()
    for index, (line, spec) in enumerate(zip(lines, specs), 1):
        record = _load_canonical_json(
            line, label="operation-result record", limit=16 * 1024,
        )
        if (
            not isinstance(record, dict)
            or set(record) != {
                "argv", "artifacts", "index", "operation", "returncode",
            }
            or not _is_exact_int(record.get("index"))
            or not _is_exact_int(record.get("returncode"))
            or not isinstance(record.get("operation"), str)
            or not isinstance(record.get("argv"), list)
            or not all(isinstance(item, str) for item in record["argv"])
            or not isinstance(record.get("artifacts"), list)
        ):
            raise WardenError("operation-result record grammar is invalid")
        expected_artifacts = spec["artifacts"]
        if (
            record["index"] != index
            or record["operation"] != spec["operation"]
            or tuple(record["argv"]) != spec["argv"]
            or record["returncode"] != spec["returncode"]
            or len(record["artifacts"]) != len(expected_artifacts)
        ):
            raise WardenError("operation-result record changed order or invocation")
        for artifact, (expected_role, expected_name) in zip(
            record["artifacts"], expected_artifacts,
        ):
            if (
                not isinstance(artifact, dict)
                or set(artifact) != {"name", "role", "sha256", "size"}
                or artifact.get("role") != expected_role
                or artifact.get("name") != expected_name
                or not _is_exact_int(artifact.get("size"))
                or not isinstance(artifact.get("sha256"), str)
                or DIGEST_PATTERN.fullmatch(artifact["sha256"]) is None
                or expected_name in referenced
            ):
                raise WardenError("operation-result artifact binding is invalid")
            try:
                payload = payloads[expected_name]
            except KeyError as exc:
                raise WardenError(
                    "operation-result references an absent artifact"
                ) from exc
            if (
                artifact["size"] != len(payload)
                or artifact["sha256"] != hashlib.sha256(payload).hexdigest()
            ):
                raise WardenError("operation-result artifact bytes changed")
            referenced.add(expected_name)
        records.append(record)
    expected_references = {
        name
        for spec in specs
        for _role, name in spec["artifacts"]
    }
    if referenced != expected_references:
        raise WardenError("operation-result artifacts lack exact set equality")
    return tuple(records)


def _expected_infra_audit_operations() -> tuple[str, ...]:
    return (
        "marker-recovery-in-progress",
        "marker-recovery-committed-cleanup-pending",
        "stop-stop-fail", "stop-show-fail", "stop-stay-active",
        "native-active", "native-inactive", "native-failed", "teardown",
    )


def _validate_infra_audit_map(
    raw: bytes,
    *,
    runtime_records: Sequence[Mapping[str, object]],
) -> int:
    """Bind each Native reset warning to its actual entrypoint log leaf."""

    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > MAX_LOG_BYTES
        or b"\x00" in raw
        or not raw.endswith(b"\n")
    ):
        raise WardenError("infra audit map framing is invalid")
    lines = raw.splitlines(keepends=True)
    expected_operations = _expected_infra_audit_operations()
    if len(lines) != len(expected_operations):
        raise WardenError("infra audit map is incomplete or duplicated")

    actual_by_name: dict[str, Mapping[str, object]] = {}
    for actual in runtime_records:
        if (
            not isinstance(actual, Mapping)
            or set(actual) != {
                "log_name", "reset_warning_count", "sha256", "size",
            }
            or not isinstance(actual.get("log_name"), str)
            or not _is_exact_int(actual.get("reset_warning_count"))
            or not _is_exact_int(actual.get("size"))
            or not isinstance(actual.get("sha256"), str)
            or DIGEST_PATTERN.fullmatch(actual["sha256"]) is None
            or actual["log_name"] in actual_by_name
        ):
            raise WardenError("infra runtime audit inventory is invalid")
        actual_by_name[actual["log_name"]] = actual

    seen_names: set[str] = set()
    native_warning_count = 0
    for operation, line in zip(expected_operations, lines):
        record = _load_canonical_json(
            line, label="infra audit map record", limit=4096,
        )
        expected_warning_count = int(operation.startswith("native-"))
        expected_prefix = "infra-teardown-" if operation == "teardown" else "infra-setup-"
        if (
            not isinstance(record, dict)
            or set(record) != {
                "log_name", "operation", "reset_warning_count", "sha256",
                "size",
            }
            or record.get("operation") != operation
            or not isinstance(record.get("log_name"), str)
            or not record["log_name"].startswith(expected_prefix)
            or not _is_exact_int(record.get("reset_warning_count"))
            or record["reset_warning_count"] != expected_warning_count
            or not _is_exact_int(record.get("size"))
            or record["size"] < 0
            or not isinstance(record.get("sha256"), str)
            or DIGEST_PATTERN.fullmatch(record["sha256"]) is None
            or record["log_name"] in seen_names
        ):
            raise WardenError("infra audit operation attribution changed")
        seen_names.add(record["log_name"])
        actual = actual_by_name.get(record["log_name"])
        if actual is None or any(
            record[field] != actual[field]
            for field in ("size", "sha256", "reset_warning_count")
        ):
            raise WardenError("infra audit map does not bind the actual log bytes")
        native_warning_count += record["reset_warning_count"]
    if seen_names != set(actual_by_name):
        raise WardenError("infra audit log leaf set lacks exact equality")
    return native_warning_count


def _expected_lifecycle_lines(
    command_records: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    lines: list[str] = []
    docker_semantics = {
        ("container", "inspect", "http-ztp"): "docker-inspect-writer",
        ("stop", "--time", "30", DOCKER_IDENTIFIER): "docker-stop-writer",
        ("container", "inspect", DOCKER_IDENTIFIER): "docker-reinspect-writer",
        ("rm", DOCKER_IDENTIFIER): "docker-remove-writer",
    }
    for record in command_records:
        if record["result"] != "ALLOWED":
            continue
        command = str(record["command"])
        argv = tuple(str(item) for item in record["argv"])
        lines.append(" ".join((command, *argv)))
        if record["operation"] == "docker-writer" and argv in docker_semantics:
            lines.append(docker_semantics[argv])
    return tuple(lines)


def _validate_private_reachability_artifacts(
    *,
    payloads: Mapping[str, bytes],
    command_leaf_names: Sequence[str],
    workflow_phases: Sequence[str],
    infra_audit_records: Sequence[Mapping[str, object]],
    live_native_authority_records: Sequence[Mapping[str, object]],
    live_docker_authority_records: Sequence[Mapping[str, object]],
) -> VerifiedWorkflowFacts:
    """Recompute the lifecycle matrix instead of trusting receipt counters."""

    def artifact(name: str, *, allow_empty: bool = False) -> bytes:
        try:
            payload = payloads[name]
        except KeyError as exc:
            raise WardenError(f"missing frozen reachability artifact: {name}") from exc
        if not isinstance(payload, bytes) or len(payload) > MAX_LOG_BYTES:
            raise WardenError(f"invalid frozen reachability artifact: {name}")
        if not payload and not allow_empty:
            raise WardenError(f"empty frozen reachability artifact: {name}")
        return payload

    operation_records = _validate_operation_results(
        artifact("operation-results.jsonl"), payloads=payloads,
    )
    native_audit_warning_count = _validate_infra_audit_map(
        artifact("infra-audit-map.jsonl"),
        runtime_records=infra_audit_records,
    )

    malformed_facts: list[tuple[str, str]] = []
    expected_bad = _expected_bad_authority_payloads()
    for index, (target, expected_payload) in enumerate(expected_bad):
        payload = artifact(f"bad-payload-{index}.bin", allow_empty=True)
        if payload != expected_payload:
            raise WardenError("malformed authority case bytes were reused or forged")
        malformed_facts.append((target, hashlib.sha256(payload).hexdigest()))
        _validate_authority_observations(
            artifact(f"authority-bad-{index}.jsonl"),
            label=f"bad authority case {index}",
            root="/var/lib/http-ztp-monitor-auth",
            stage_states=(
                ("pre-health", f"bad:{index}"),
                ("post-health", f"bad:{index}"),
                ("post-cgi", f"bad:{index}"),
            ),
            equal_stage_groups=(("pre-health", "post-health", "post-cgi"),),
        )
        health = artifact(f"health-{index}.out")
        if health != (
            b"[ERROR] unhealthy ZTP container: Monitor cache authority "
            b"attestation failed\n"
        ):
            raise WardenError("real health rejection diagnostic is not exact")
        cgi = artifact(f"cgi-bad-{index}.out")
        _parse_cgi_response(
            cgi,
            expected_status="503 Service Unavailable",
            expected_document={
                "error": "control authentication state unavailable",
            },
        )
        if artifact(f"cgi-bad-{index}.out.err") != CGI_AUTHORITY_DIAGNOSTIC:
            raise WardenError("malformed CGI rejection diagnostic is not exact")
        if artifact(f"cgi-bad-{index}.invocation.json") != (
            _expected_cgi_invocation_bytes()
        ):
            raise WardenError("malformed CGI invocation identity or rc changed")

    good_cgi_count = 0
    for index in range(3):
        cgi = artifact(f"cgi-good-{index}.out")
        _parse_cgi_response(
            cgi,
            expected_status="200 OK",
            expected_document={
                "state": "running",
                "process_alive": False,
                "control_auth": {"factory_records_active": True},
            },
        )
        if artifact(f"cgi-good-{index}.out.err", allow_empty=True):
            raise WardenError("successful real CGI wrote stderr")
        if artifact(f"cgi-good-{index}.invocation.json") != (
            _expected_cgi_invocation_bytes()
        ):
            raise WardenError("successful CGI invocation identity or rc changed")
        good_cgi_count += 1

    marker_phases: list[str] = []
    for classification in (
        "recovery-in-progress", "recovery-committed-cleanup-pending",
    ):
        _validate_authority_observations(
            artifact(f"authority-marker-{classification}.jsonl"),
            label=f"marker authority case {classification}",
            root="/var/lib/http-ztp-monitor-auth",
            stage_states=(
                ("pre-classification", f"marker:{classification}"),
                ("post-classification", f"marker:{classification}"),
                ("post-recovery", "valid"),
                ("post-attest", "valid"),
            ),
            equal_stage_groups=(
                ("pre-classification", "post-classification"),
                ("post-recovery", "post-attest"),
            ),
        )
        observed = artifact(f"marker-{classification}.out")
        if observed != classification.encode("ascii"):
            raise WardenError("routine marker rejection classification changed")
        if artifact(f"marker-{classification}.err", allow_empty=True):
            raise WardenError("routine marker classification wrote stderr")
        if artifact(f"marker-reset-{classification}.out", allow_empty=True):
            raise WardenError("marker recovery unexpectedly wrote stdout")
        if artifact(f"marker-reset-{classification}.err") != (
            NATIVE_STOPPED_WARNING + NATIVE_RECOVERY_COMPLETE
        ):
            raise WardenError("marker recovery diagnostics are not exact")
        if artifact(f"marker-after-{classification}.out") != b"attest-valid":
            raise WardenError("marker cleanup did not reach read-only attest-valid")
        if artifact(f"marker-after-{classification}.err", allow_empty=True):
            raise WardenError("marker post-recovery attest wrote stderr")
        marker_phases.append(classification)

    stopped_diagnostics = {
        "stop-fail": (
            b"ERROR: Apache could not be stopped; Monitor authority was not repaired.\n"
        ),
        "show-fail": (
            b"ERROR: Apache state cannot be proven; Monitor authority was not repaired.\n"
        ),
        "stay-active": (
            b"ERROR: Apache is not provably stopped; Monitor authority was not repaired.\n"
        ),
    }
    for mode, expected_diagnostic in stopped_diagnostics.items():
        _validate_authority_observations(
            artifact(f"authority-stop-{mode}.jsonl"),
            label=f"stopped-writer authority case {mode}",
            root="/var/lib/http-ztp-monitor-auth",
            stage_states=(
                ("pre-recovery", "bad:0"),
                ("post-recovery", "bad:0"),
            ),
            equal_stage_groups=(("pre-recovery", "post-recovery"),),
        )
        if artifact(f"stop-{mode}.out", allow_empty=True):
            raise WardenError("Native stopped-writer rejection wrote stdout")
        if artifact(f"stop-{mode}.err") != expected_diagnostic:
            raise WardenError("Native stopped-writer denial is not exact")

    native_states: list[str] = []
    native_failed_final_records: tuple[dict[str, object], ...] | None = None
    for state in ("active", "inactive", "failed"):
        native_observations = _validate_authority_observations(
            artifact(f"authority-native-{state}.jsonl"),
            label=f"Native recovery authority case {state}",
            root="/var/lib/http-ztp-monitor-auth",
            stage_states=(
                ("pre-recovery", "bad:0"),
                ("post-recovery", "valid"),
                ("post-attest", "valid"),
                ("post-cgi", "valid"),
            ),
            equal_stage_groups=(("post-recovery", "post-attest", "post-cgi"),),
        )
        if state == "failed":
            native_failed_final_records = dict(native_observations)["post-cgi"]
        if artifact(f"native-{state}.out", allow_empty=True):
            raise WardenError("Native recovery unexpectedly wrote stdout")
        if artifact(f"native-{state}.err") != (
            NATIVE_STOPPED_WARNING
            + RECOVERY_RESET_WARNING
            + NATIVE_RECOVERY_COMPLETE
        ):
            raise WardenError("Native recovery diagnostics are not exact")
        if artifact(f"native-attest-{state}.out") != b"attest-valid":
            raise WardenError("Native recovery did not reach read-only attest-valid")
        if artifact(f"native-attest-{state}.err", allow_empty=True):
            raise WardenError("Native post-recovery attest wrote stderr")
        native_states.append(state)

    docker_output = artifact("docker-recover.out")
    expected_docker_output = (
        b"[OK] Ubuntu 24.04 amd64 host; Ubuntu 24.04 container\n"
        b"[OK] Monitor cache authority recovered; container remains stopped\n",
        b"[NEXT] sudo ./infra/docker/deploy.sh deploy\n"
    )
    if docker_output != b"".join(expected_docker_output):
        raise WardenError("Docker recovery did not preserve the stopped next step")
    if artifact("docker-recover.err") != RECOVERY_RESET_WARNING:
        raise WardenError("Docker recovery warning provenance changed")
    docker_container_observations = _validate_authority_observations(
        artifact("authority-docker-container.jsonl"),
        label="Docker container authority",
        root="/var/lib/http-ztp-container/monitor-auth",
        stage_states=(("pre-recovery", "bad:0"), ("post-recovery", "valid")),
    )
    docker_native_observations = _validate_authority_observations(
        artifact("authority-docker-native.jsonl"),
        label="Docker Native separation authority",
        root="/var/lib/http-ztp-monitor-auth",
        stage_states=(("pre-recovery", "valid"), ("post-recovery", "valid")),
        equal_stage_groups=(("pre-recovery", "post-recovery"),),
    )
    if artifact("collision.stdout", allow_empty=True):
        raise WardenError("a forbidden argv collision wrote stdout")
    if artifact("collision.stderr") != b"FORBIDDEN\n":
        raise WardenError("forbidden argv diagnostic is not exact")

    decisions_raw = artifact("recovery-decisions.json")
    decision_matrix = _validate_recovery_decision_matrix(decisions_raw)

    expected_warning_sources = (
        "docker-recover.err",
        "native-active.err",
        "native-failed.err",
        "native-inactive.err",
    )
    observed_warning_sources: list[str] = []
    for name in sorted(payloads):
        payload = artifact(name, allow_empty=True)
        if payload.count(RECOVERY_RESET_WARNING) != payload.splitlines(
            keepends=True,
        ).count(RECOVERY_RESET_WARNING):
            raise WardenError("recovery warning is not an exact complete line")
        if RECOVERY_RESET_WARNING in payload:
            if payload.count(RECOVERY_RESET_WARNING) != 1:
                raise WardenError("recovery warning is duplicated at one source")
            observed_warning_sources.append(name)
    if tuple(observed_warning_sources) != expected_warning_sources:
        raise WardenError("recovery warning source attribution changed")

    try:
        lines = artifact("events.log").decode("ascii", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise WardenError("lifecycle event evidence is not ASCII") from exc
    command_records = _validate_command_event_log(
        artifact("command-events.jsonl"),
    )
    if tuple(lines) != _expected_lifecycle_lines(command_records):
        raise WardenError("lifecycle event log is not the exact command-derived trace")
    before = artifact("teardown-before.json")
    after = artifact("teardown-after.json")
    if artifact("pre-teardown-attest.out") != b"attest-valid":
        raise WardenError("Native authority was not valid before teardown")
    if artifact("pre-teardown-attest.err", allow_empty=True):
        raise WardenError("pre-teardown read-only attest wrote stderr")
    if artifact("pre-teardown-attest.invocation.json") != (
        _expected_attest_invocation_bytes()
    ):
        raise WardenError("pre-teardown attest invocation changed")
    teardown_paths = _validate_teardown_transition(before, after)
    _validate_teardown_snapshot(before)
    teardown_output = artifact("teardown.out")
    if teardown_output != TEARDOWN_COMPLETE:
        raise WardenError("real teardown completion evidence is not exact")
    if artifact("teardown.err", allow_empty=True):
        raise WardenError("real teardown unexpectedly wrote stderr")
    if artifact("service-state.json") != INITIAL_SERVICE_STATE:
        raise WardenError("forbidden argv changed the fixed service-state witness")
    if artifact("postflight-attest.out") != b"attest-valid":
        raise WardenError("final read-only postflight attest is unavailable")
    if artifact("postflight-attest.err", allow_empty=True):
        raise WardenError("final read-only postflight attest wrote stderr")
    if artifact("postflight-attest.invocation.json") != (
        _expected_attest_invocation_bytes()
    ):
        raise WardenError("final read-only postflight invocation changed")
    postflight_observations = _validate_authority_observations(
        artifact("authority-postflight.jsonl"),
        label="final postflight authority",
        root="/var/lib/http-ztp-monitor-auth",
        stage_states=(("pre-attest", "valid"), ("post-attest", "valid")),
        equal_stage_groups=(("pre-attest", "post-attest"),),
    )

    native_root = "/var/lib/http-ztp-monitor-auth"
    docker_root = "/var/lib/http-ztp-container/monitor-auth"
    if native_failed_final_records is None:
        raise WardenError("Native final recovery observation is unavailable")
    teardown_before_records = _parse_teardown_snapshot(
        before, "teardown before continuity snapshot",
    )
    teardown_after_records = _parse_teardown_snapshot(
        after, "teardown after continuity snapshot",
    )
    native_timeline = (
        _authority_record_subset(native_failed_final_records, root=native_root),
        _authority_record_subset(
            dict(docker_native_observations)["pre-recovery"], root=native_root,
        ),
        _authority_record_subset(
            dict(docker_native_observations)["post-recovery"], root=native_root,
        ),
        _authority_record_subset(teardown_before_records, root=native_root),
        _authority_record_subset(teardown_after_records, root=native_root),
        _authority_record_subset(
            dict(postflight_observations)["pre-attest"], root=native_root,
        ),
        _authority_record_subset(
            dict(postflight_observations)["post-attest"], root=native_root,
        ),
        _authority_record_subset(live_native_authority_records, root=native_root),
    )
    if any(records != native_timeline[0] for records in native_timeline[1:]):
        raise WardenError("Native authority continuity changed without a writer")
    docker_final = _authority_record_subset(
        dict(docker_container_observations)["post-recovery"], root=docker_root,
    )
    live_docker_final = _authority_record_subset(
        live_docker_authority_records, root=docker_root,
    )
    if docker_final != live_docker_final:
        raise WardenError("Docker authority recovery is not bound to final state")
    native_authority_continuity_sha256 = hashlib.sha256(
        _canonical_json(native_timeline[0]),
    ).hexdigest()
    docker_authority_continuity_sha256 = hashlib.sha256(
        _canonical_json(docker_final),
    ).hexdigest()
    entrypoint_counts: dict[tuple[str, ...], int] = {}
    for record in operation_records:
        argv = tuple(record["argv"])
        if argv[0].startswith("./infra/"):
            entrypoint_counts[argv] = entrypoint_counts.get(argv, 0) + 1
    observed_decision_set = {
        "attest-valid", *marker_phases,
        *(row[-1] for row in decision_matrix),
    }
    docker_trace_names = {
        "docker-inspect-writer", "docker-stop-writer",
        "docker-reinspect-writer", "docker-remove-writer",
    }
    docker_trace = tuple(line for line in lines if line in docker_trace_names)
    apt_mutation_count = sum(
        record["command"] == "apt-get" for record in command_records
    )
    forbidden_command_count = sum(
        record["result"] == "FORBIDDEN" for record in command_records
    )
    post_attested_operations = tuple(
        [*(f"marker-{phase}" for phase in marker_phases),
         *(f"native-{state}" for state in native_states)]
    )
    return VerifiedWorkflowFacts(
        command_leaf_names=tuple(command_leaf_names),
        workflow_phases=tuple(workflow_phases),
        recovery_decision_tokens=tuple(
            token for token in RECOVERY_DECISION_TOKENS
            if token in observed_decision_set
        ),
        recovery_decision_matrix=decision_matrix,
        entrypoint_counts=tuple(entrypoint_counts.items()),
        malformed_payloads=tuple(malformed_facts),
        cgi_status_counts=(("200", good_cgi_count), ("503", len(malformed_facts))),
        marker_phases=tuple(marker_phases),
        native_initial_states=tuple(native_states),
        native_stop_failures=tuple(stopped_diagnostics),
        warning_sources=tuple(observed_warning_sources),
        native_audit_warning_count=native_audit_warning_count,
        post_attested_operations=post_attested_operations,
        docker_quiesce_trace=docker_trace,
        teardown_authority_paths=teardown_paths,
        apt_mutation_count=apt_mutation_count,
        forbidden_command_count=forbidden_command_count,
        unexpected_command_count=len(command_records) - len(
            _expected_command_events()
        ),
        operation_count=len(operation_records),
        pre_teardown_attest="attest-valid",
        final_postflight_attest="attest-valid",
        native_authority_continuity_sha256=(
            native_authority_continuity_sha256
        ),
        docker_authority_continuity_sha256=(
            docker_authority_continuity_sha256
        ),
    )


def verify_frozen_private_evidence(
    frozen: FrozenPrivateEvidence,
    *,
    expected_tree_id: str,
    source_manifest_bytes: bytes,
    command_manifest_bytes: bytes,
    attestation: NonParsingAttestation,
    infra_upper_descriptor: int,
) -> VerifiedPrivateEvidence:
    """Parse only the frozen in-memory bytes after every host reference closes."""

    if not isinstance(attestation, NonParsingAttestation):
        raise WardenError("nonparsing private-state freeze is unavailable")
    fixture_digest = _validate_private_fixture_state()
    infra_digest, infra_audit_records = _validate_infra_runtime_upper(
        infra_upper_descriptor,
    )
    if fixture_digest != attestation.fixture_state_sha256:
        raise WardenError("private fixture state changed after its opaque freeze")
    if infra_digest != attestation.infra_runtime_sha256:
        raise WardenError("infra runtime state changed after its opaque freeze")
    live_native_records, live_docker_records = _live_final_authority_records()
    if _authority_record_digest(
        live_native_records, root="/var/lib/http-ztp-monitor-auth",
    ) != attestation.native_authority_sha256:
        raise WardenError("Native authority changed after its opaque freeze")
    if _authority_record_digest(
        live_docker_records, root="/var/lib/http-ztp-container/monitor-auth",
    ) != attestation.docker_authority_sha256:
        raise WardenError("Docker authority changed after its opaque freeze")
    tree_id = _require_digest(expected_tree_id, "tree ID", TREE_ID_PATTERN)
    payloads = _frozen_payloads(frozen)
    if payloads.get("expected-tree-id") != (tree_id + "\n").encode("ascii"):
        raise WardenError("frozen expected tree identity changed")
    if payloads.get("source-manifest.json") != source_manifest_bytes:
        raise WardenError("frozen source manifest differs from the warden hold")
    if payloads.get("command-manifest.json") != command_manifest_bytes:
        raise WardenError("frozen command manifest differs from the warden hold")

    source_document = _load_canonical_json(
        source_manifest_bytes, label="source manifest", limit=MAX_LOG_BYTES,
    )
    if (
        not isinstance(source_document, dict)
        or set(source_document) != {"entries", "schema_version", "tree_id"}
        or type(source_document.get("schema_version")) is not int
        or source_document.get("schema_version") != 1
        or source_document.get("tree_id") != tree_id
        or not isinstance(source_document.get("entries"), list)
    ):
        raise WardenError("source manifest is not bound to the expected tree")
    command_document = _load_canonical_json(
        command_manifest_bytes, label="command manifest", limit=MAX_LOG_BYTES,
    )
    if (
        not isinstance(command_document, dict)
        or set(command_document) != {"entries", "leaf_names", "schema_version"}
        or type(command_document.get("schema_version")) is not int
        or command_document.get("schema_version") != 1
        or command_document.get("leaf_names") != sorted(COMMAND_LEAF_NAMES)
        or not isinstance(command_document.get("entries"), list)
    ):
        raise WardenError("frozen command manifest is invalid")

    phases = payloads["phases.jsonl"]
    events = payloads["events.log"]
    workflow_phases = _validate_phase_log(phases)
    _validate_event_log(events)
    workflow_facts = _validate_private_reachability_artifacts(
        payloads=payloads,
        command_leaf_names=tuple(command_document["leaf_names"]),
        workflow_phases=workflow_phases,
        infra_audit_records=infra_audit_records,
        live_native_authority_records=live_native_records,
        live_docker_authority_records=live_docker_records,
    )
    evidence_records = [
        {
            "name": name,
            "sha256": hashlib.sha256(payloads[name]).hexdigest(),
            "size": len(payloads[name]),
        }
        for name in sorted(payloads)
    ]
    private_digest = hashlib.sha256(_canonical_json(evidence_records)).hexdigest()
    _verify_frozen_evidence_bindings(frozen)
    return VerifiedPrivateEvidence(
        tree_id=tree_id,
        event_log_sha256=hashlib.sha256(events).hexdigest(),
        phase_log_sha256=hashlib.sha256(phases).hexdigest(),
        source_manifest_sha256=hashlib.sha256(source_manifest_bytes).hexdigest(),
        command_manifest_sha256=hashlib.sha256(command_manifest_bytes).hexdigest(),
        private_evidence_sha256=private_digest,
        workflow_facts=workflow_facts,
    )


def _opaque_metadata_record(
    metadata: os.stat_result,
    *,
    path: str,
    kind: str,
    sha256: str | None = None,
) -> dict[str, object]:
    """Serialize identity without assigning meaning to a child-produced byte."""

    record: dict[str, object] = {
        "ctime_ns": metadata.st_ctime_ns,
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "links": metadata.st_nlink,
        "mode": metadata.st_mode,
        "mtime_ns": metadata.st_mtime_ns,
        "path": path,
        "size": metadata.st_size,
        "type": kind,
        "uid": metadata.st_uid,
    }
    if sha256 is not None:
        record["sha256"] = sha256
    return record


def _opaque_tree_records_from_descriptor(
    root_descriptor: int,
    *,
    label: str,
    maximum_depth: int = 6,
    maximum_entries: int = 512,
    maximum_bytes: int = 16 * 1024 * 1024,
) -> list[dict[str, object]]:
    """Freeze one private tree as identities and hashes, without parsing bytes."""

    flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    records: list[dict[str, object]] = []
    total_bytes = 0

    root_metadata = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise WardenError(f"opaque snapshot root is not a directory: {label}")
    records.append(_opaque_metadata_record(
        root_metadata, path=label, kind="directory",
    ))

    def walk(descriptor: int, prefix: str, depth: int) -> None:
        nonlocal total_bytes
        if depth > maximum_depth:
            raise WardenError(f"opaque private snapshot is too deep: {label}")
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as exc:
            raise WardenError(f"cannot enumerate opaque private snapshot: {label}") from exc
        if len(records) + len(names) > maximum_entries:
            raise WardenError(f"opaque private snapshot has too many entries: {label}")
        for name in names:
            if (
                not name
                or name in {".", ".."}
                or "/" in name
                or name.encode("ascii", "ignore").decode("ascii") != name
            ):
                raise WardenError(f"opaque private snapshot has an unsafe name: {label}")
            relative = f"{prefix}/{name}" if prefix else name
            display = f"{label}/{relative}"
            try:
                named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as exc:
                raise WardenError(f"opaque private snapshot name vanished: {display}") from exc
            if stat.S_ISDIR(named.st_mode):
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    held = os.fstat(child)
                    if _artifact_identity(held) != _artifact_identity(named):
                        raise WardenError(
                            f"opaque private directory was rebound: {display}"
                        )
                    records.append(_opaque_metadata_record(
                        held, path=display, kind="directory",
                    ))
                    walk(child, relative, depth + 1)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
                raise WardenError(f"opaque private snapshot has unsafe type: {display}")
            if named.st_size < 0 or named.st_size > MAX_LOG_BYTES:
                raise WardenError(f"opaque private leaf is too large: {display}")
            leaf = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                held = os.fstat(leaf)
                payload = _read_frozen_descriptor(leaf, held.st_size, display)
                rebound = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            finally:
                os.close(leaf)
            if (
                _artifact_identity(held) != _artifact_identity(named)
                or _artifact_identity(rebound) != _artifact_identity(named)
            ):
                raise WardenError(f"opaque private leaf was rebound: {display}")
            total_bytes += len(payload)
            if total_bytes > maximum_bytes:
                raise WardenError(f"opaque private snapshot exceeds byte bound: {label}")
            records.append(_opaque_metadata_record(
                held,
                path=display,
                kind="file",
                sha256=hashlib.sha256(payload).hexdigest(),
            ))

    walk(root_descriptor, "", 1)
    if _root_directory_identity(os.fstat(root_descriptor)) != (
        root_metadata.st_dev,
        root_metadata.st_ino,
        root_metadata.st_mode,
        root_metadata.st_uid,
        root_metadata.st_gid,
    ):
        raise WardenError(f"opaque private snapshot root changed: {label}")
    return records


def _opaque_path_records(path: Path) -> list[dict[str, object]]:
    """Freeze a fixed private path without interpreting its contents."""

    try:
        named = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise WardenError(f"cannot stat opaque private path: {path}") from exc
    label = os.fspath(path)
    if stat.S_ISSOCK(named.st_mode):
        return [_opaque_metadata_record(named, path=label, kind="socket")]
    if stat.S_ISDIR(named.st_mode):
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            held = os.fstat(descriptor)
            if _artifact_identity(held) != _artifact_identity(named):
                raise WardenError(f"opaque private path was rebound: {path}")
            return _opaque_tree_records_from_descriptor(
                descriptor, label=label,
            )
        finally:
            os.close(descriptor)
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise WardenError(f"opaque private path has unsafe type: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        held = os.fstat(descriptor)
        payload = _read_frozen_descriptor(descriptor, held.st_size, label)
        rebound = os.stat(path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if (
        _artifact_identity(held) != _artifact_identity(named)
        or _artifact_identity(rebound) != _artifact_identity(named)
    ):
        raise WardenError(f"opaque private path was rebound: {path}")
    return [_opaque_metadata_record(
        held, path=label, kind="file",
        sha256=hashlib.sha256(payload).hexdigest(),
    )]


def _freeze_private_fixture_state() -> str:
    """Hash fixed private fixture identities/bytes without interpreting them."""

    paths = (
        Path("/fixture"),
        Path("/usr/local/lib/http-ztp/control-auth.py"),
        Path("/usr/lib/cgi-bin/ztp-monitor-control"),
        Path("/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"),
        Path("/etc/http-ztp/control-users.htpasswd"),
        Path("/var/lib/http-ztp-container/control-auth/control-users.htpasswd"),
        Path("/var/lib/http-ztp-monitor-auth"),
        Path("/var/lib/http-ztp-container/monitor-auth"),
        Path("/run/docker.sock"),
        Path("/var/www/html/.deployment.lock"),
    )
    records: list[dict[str, object]] = []
    for path in paths:
        records.extend(_opaque_path_records(path))
    return hashlib.sha256(_canonical_json(records)).hexdigest()


def _live_final_authority_records() -> tuple[
    tuple[dict[str, object], ...], tuple[dict[str, object], ...],
]:
    """Hold both private authority trees as exact final identity records."""

    native = tuple(_opaque_path_records(
        Path("/var/lib/http-ztp-monitor-auth"),
    ))
    docker = tuple(_opaque_path_records(
        Path("/var/lib/http-ztp-container/monitor-auth"),
    ))
    return native, docker


def _freeze_infra_runtime_upper(descriptor: int) -> str:
    records = _opaque_tree_records_from_descriptor(
        descriptor,
        label="/source/infra-runtime-upper",
        maximum_depth=3,
        maximum_entries=64,
        maximum_bytes=8 * 1024 * 1024,
    )
    return hashlib.sha256(_canonical_json(records)).hexdigest()


def _snapshot_private_tree(path: Path, label: str) -> list[dict[str, object]]:
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_fd = os.open(path, flags)
    except OSError as exc:
        raise WardenError(f"cannot hold private fixture tree: {label}") from exc
    records: list[dict[str, object]] = []
    total = 0

    def walk(descriptor: int, prefix: str) -> None:
        nonlocal total
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as exc:
            raise WardenError(f"cannot enumerate private fixture tree: {label}") from exc
        if len(names) > 128:
            raise WardenError(f"private fixture tree has too many leaves: {label}")
        for name in names:
            if (
                not name
                or name in {".", ".."}
                or "/" in name
                or name.encode("ascii", "ignore").decode("ascii") != name
            ):
                raise WardenError(f"private fixture tree has an unsafe name: {label}")
            relative = f"{prefix}/{name}" if prefix else name
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if metadata.st_uid not in {0, 33} or metadata.st_gid not in {0, 33}:
                raise WardenError(f"private fixture ownership is unsafe: {label}")
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) not in {0o700, 0o750, 0o755}:
                    raise WardenError(f"private fixture directory mode is unsafe: {label}")
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    records.append({
                        "gid": metadata.st_gid,
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "path": relative,
                        "type": "directory",
                        "uid": metadata.st_uid,
                    })
                    walk(child, relative)
                finally:
                    os.close(child)
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_RECEIPT_BYTES
                or stat.S_IMODE(metadata.st_mode) not in {
                    0o400, 0o600, 0o640, 0o644, 0o660,
                }
            ):
                raise WardenError(f"private fixture leaf metadata is unsafe: {label}")
            leaf = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                held = os.fstat(leaf)
                payload = _read_frozen_descriptor(leaf, held.st_size, relative)
                rebound = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            finally:
                os.close(leaf)
            if (
                _artifact_identity(held) != _artifact_identity(metadata)
                or _artifact_identity(rebound) != _artifact_identity(metadata)
            ):
                raise WardenError(f"private fixture binding changed: {label}")
            total += len(payload)
            if total > 2 * 1024 * 1024:
                raise WardenError(f"private fixture tree exceeds byte bound: {label}")
            records.append({
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "type": "file",
                "uid": metadata.st_uid,
            })

    try:
        root_metadata = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != 0
            or root_metadata.st_gid != 0
            or stat.S_IMODE(root_metadata.st_mode) != 0o755
        ):
            raise WardenError(f"private fixture root metadata is unsafe: {label}")
        walk(root_fd, "")
        return records
    finally:
        os.close(root_fd)


def _validate_private_fixture_state() -> str:
    fixture = Path("/fixture")
    try:
        names = frozenset(os.listdir(fixture))
    except OSError as exc:
        raise WardenError("cannot enumerate fixed service fixture") from exc
    expected_values = {
        "docker-state": b"absent\n",
        "systemctl-mode": b"normal\n",
        "systemctl-state": b"inactive\n",
    }
    if names != set(expected_values):
        raise WardenError("fixed service fixture does not have exact set equality")
    records: list[dict[str, object]] = []
    for name, expected in sorted(expected_values.items()):
        path = fixture / name
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            payload = _read_frozen_descriptor(descriptor, metadata.st_size, name)
        finally:
            os.close(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or payload != expected
        ):
            raise WardenError(f"fixed service fixture changed: {name}")
        records.append({"path": f"/fixture/{name}", "sha256": hashlib.sha256(payload).hexdigest()})

    factory_control_users = _factory_control_users_from_pinned_helper(
        _regular_payload_with_metadata(
            Path("/usr/local/lib/http-ztp/control-auth.py"), mode=0o755,
        )
    )
    fixed_files = (
        (Path("/usr/local/lib/http-ztp/control-auth.py"), 0o755, CONTROL_AUTH_HELPER_SHA256),
        (Path("/usr/lib/cgi-bin/ztp-monitor-control"), 0o755, None),
        (Path("/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"), 0o644, APACHE_PUBLIC_BOUNDARY_SHA256),
        (Path("/etc/http-ztp/control-users.htpasswd"), 0o640, hashlib.sha256(factory_control_users).hexdigest()),
        (Path("/var/lib/http-ztp-container/control-auth/control-users.htpasswd"), 0o640, hashlib.sha256(factory_control_users).hexdigest()),
    )
    for path, mode, expected_digest in fixed_files:
        gid = 33 if path.name == "control-users.htpasswd" else 0
        digest = _regular_digest_with_metadata(path, mode=mode, uid=0, gid=gid)
        if expected_digest is not None and digest != expected_digest:
            raise WardenError(f"fixed fixture content changed: {path}")
        records.append({"path": os.fspath(path), "sha256": digest})

    for path, label in (
        (Path("/var/lib/http-ztp-monitor-auth"), "native-authority"),
        (Path("/var/lib/http-ztp-container/monitor-auth"), "docker-authority"),
    ):
        tree = _snapshot_private_tree(path, label)
        root_names = {
            record["path"].split("/", 1)[0]
            for record in tree
        }
        if root_names != {"monitor-auth", "status.lock"}:
            raise WardenError(f"{label} does not have exact root children")
        by_relative = {record["path"]: record for record in tree}
        if set(by_relative) != {
            "monitor-auth", "monitor-auth/factory-status.json", "status.lock",
        }:
            raise WardenError(f"{label} does not have exact descendants")
        cache_dir = by_relative["monitor-auth"]
        lock = by_relative["status.lock"]
        cache = by_relative["monitor-auth/factory-status.json"]
        valid_payloads = _expected_valid_authority_payloads()
        if (
            cache_dir != {
                "gid": 33, "mode": 0o700, "path": "monitor-auth",
                "type": "directory", "uid": 33,
            }
            or lock["gid"] != 33
            or lock["uid"] != 0
            or lock["mode"] != 0o660
            or lock["type"] != "file"
            or lock["size"] != len(valid_payloads["status.lock"])
            or lock["sha256"] != hashlib.sha256(
                valid_payloads["status.lock"],
            ).hexdigest()
            or cache["gid"] != 33
            or cache["uid"] != 33
            or cache["mode"] != 0o600
            or cache["type"] != "file"
            or cache["size"] != len(
                valid_payloads["monitor-auth/factory-status.json"]
            )
            or cache["sha256"] != hashlib.sha256(
                valid_payloads["monitor-auth/factory-status.json"],
            ).hexdigest()
        ):
            raise WardenError(f"{label} is not the exact valid authority state")
        records.append({"path": os.fspath(path), "tree": tree})

    socket_metadata = os.lstat("/run/docker.sock")
    if (
        not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != 0
        or socket_metadata.st_gid != 0
        or stat.S_IMODE(socket_metadata.st_mode) != 0o600
    ):
        raise WardenError("private inert Docker socket changed")
    lock_digest = _regular_digest_with_metadata(
        Path("/var/www/html/.deployment.lock"), mode=0o600,
    )
    records.extend((
        {"path": "/run/docker.sock", "type": "inert-private-socket"},
        {"path": "/var/www/html/.deployment.lock", "sha256": lock_digest},
    ))
    # The semantic checks above cover the exact expected end state.  Return
    # the same opaque identity/content digest frozen before host authority was
    # closed so the two stages are cryptographically bound.
    return _freeze_private_fixture_state()


def verify_nonparsing_postflight(
    state: PrivateRootState,
    frozen: FrozenPrivateEvidence,
    *,
    held_repository,
    held_exports: Sequence[object],
    sentinels: Sequence[HostSentinel],
) -> NonParsingAttestation:
    """Verify kernel/private/host facts before parsing any child-produced bytes."""

    _verify_frozen_evidence_bindings(frozen)
    validate_command_root(Path("/commands"), state.command_manifest)
    mount_table = _mount_table_bytes()
    validate_mount_records(
        read_mount_records(),
        writable_paths=set(state.writable_mounts),
        readonly_paths=set(state.readonly_mounts),
    )
    fixture_digest = _freeze_private_fixture_state()
    native_records, docker_records = _live_final_authority_records()
    native_authority_sha256 = _authority_record_digest(
        native_records, root="/var/lib/http-ztp-monitor-auth",
    )
    docker_authority_sha256 = _authority_record_digest(
        docker_records, root="/var/lib/http-ztp-container/monitor-auth",
    )
    infra_digest = _freeze_infra_runtime_upper(state.infra_upper_descriptor)
    _umount2("/source/infra")
    guard = _load_source_guard()
    try:
        guard.verify_export(
            Path("/immutable-source"), state.source_manifest,
            expected_tree_id=state.tree_id, required_uid=0, required_gid=0,
        )
        guard.verify_export(
            Path("/source"), state.source_manifest,
            expected_tree_id=state.tree_id, required_uid=0, required_gid=0,
        )
        for held_export in held_exports:
            held_export.verify()
        _verify_held_repository_after_pivot(held_repository)
    except Exception as exc:
        raise WardenError("source identity changed during nonparsing postflight") from exc
    sentinel_digest = verify_host_sentinels(
        held_repository.descriptor, sentinels,
    )
    return NonParsingAttestation(
        mount_table=mount_table,
        mount_table_sha256=hashlib.sha256(mount_table).hexdigest(),
        source_manifest_sha256=hashlib.sha256(state.source_manifest).hexdigest(),
        command_manifest_sha256=hashlib.sha256(state.command_manifest).hexdigest(),
        fixture_state_sha256=fixture_digest,
        host_sentinels_sha256=sentinel_digest,
        infra_runtime_sha256=infra_digest,
        native_authority_sha256=native_authority_sha256,
        docker_authority_sha256=docker_authority_sha256,
    )


def close_host_authority(
    held_repository,
    sentinels: Sequence[HostSentinel],
    *,
    host_namespace_descriptor: int = 9,
) -> None:
    """Close every old-root/host descriptor before raw evidence parsing."""

    failures: list[str] = []
    for sentinel in sentinels:
        try:
            os.close(sentinel.descriptor)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                failures.append(sentinel.relative_path)
    try:
        held_repository.close()
    except OSError:
        failures.append("source-repository")
    try:
        os.close(host_namespace_descriptor)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            failures.append("host-mount-namespace")
    for descriptor in (
        *(sentinel.descriptor for sentinel in sentinels),
        held_repository.descriptor,
        host_namespace_descriptor,
    ):
        try:
            os.fstat(descriptor)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
        failures.append(str(descriptor))
    if failures:
        raise WardenError("host authority did not close exactly: " + ",".join(failures))


def _validate_infra_runtime_upper(
    descriptor: int,
) -> tuple[str, tuple[dict[str, object], ...]]:
    """Allow only bounded infra logs/status in the overlay's separate upper."""

    log_name = re.compile(r"infra-(?:setup|teardown)-[0-9]{8}_[0-9]{6}-[0-9]+\.log\Z")
    try:
        root_names = sorted(os.listdir(descriptor))
    except OSError as exc:
        raise WardenError("cannot enumerate the infra runtime upper") from exc
    if not set(root_names) <= {"infra-status", "logs"}:
        raise WardenError("infra runtime upper contains a source-tree mutation")
    total = 0
    audit_records: list[dict[str, object]] = []
    if "infra-status" in root_names:
        metadata = os.stat("infra-status", dir_fd=descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or metadata.st_size > 64 * 1024
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise WardenError("infra status has unsafe metadata")
        status_fd = os.open(
            "infra-status",
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        try:
            payload = os.read(status_fd, 64 * 1024 + 1)
        finally:
            os.close(status_fd)
        if (
            len(payload) != metadata.st_size
            or not payload.endswith(b"\n")
            or b"Authorization" in payload
            or b"$2y$" in payload
            or b"$apr1$" in payload
            or RECOVERY_RESET_WARNING in payload
        ):
            raise WardenError("infra status content is unsafe")
        total += len(payload)
    if "logs" in root_names:
        logs_fd = os.open(
            "logs",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=descriptor,
        )
        try:
            logs_metadata = os.fstat(logs_fd)
            if (
                not stat.S_ISDIR(logs_metadata.st_mode)
                or logs_metadata.st_uid != 0
                or logs_metadata.st_gid != 0
                or stat.S_IMODE(logs_metadata.st_mode) & 0o022
            ):
                raise WardenError("infra runtime logs directory is unsafe")
            log_names = sorted(os.listdir(logs_fd))
            if len(log_names) > 32 or any(log_name.fullmatch(name) is None for name in log_names):
                raise WardenError("infra runtime log leaf set is unsafe")
            for name in log_names:
                metadata = os.stat(name, dir_fd=logs_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != 0
                    or metadata.st_gid != 0
                    or metadata.st_nlink != 1
                    or metadata.st_size > 1024 * 1024
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                ):
                    raise WardenError("infra runtime log metadata is unsafe")
                log_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=logs_fd,
                )
                try:
                    payload = os.read(log_fd, 1024 * 1024 + 1)
                finally:
                    os.close(log_fd)
                if (
                    len(payload) != metadata.st_size
                    or b"Authorization:" in payload
                    or b"$2y$" in payload
                    or b"$apr1$" in payload
                ):
                    raise WardenError("infra runtime log contains unsafe content")
                if payload.count(RECOVERY_RESET_WARNING) != payload.splitlines(
                    keepends=True,
                ).count(RECOVERY_RESET_WARNING):
                    raise WardenError("infra audit warning is not an exact line")
                if payload.count(RECOVERY_RESET_WARNING) > 1:
                    raise WardenError(
                        "one infra execution duplicated its reset warning"
                    )
                warning_count = payload.count(RECOVERY_RESET_WARNING)
                audit_records.append({
                    "log_name": name,
                    "reset_warning_count": warning_count,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                })
                total += len(payload)
        finally:
            os.close(logs_fd)
    if total > 8 * 1024 * 1024:
        raise WardenError("infra runtime output set exceeds its total byte bound")
    return _freeze_infra_runtime_upper(descriptor), tuple(audit_records)


def execute_warden(config: WardenConfig) -> None:
    _require_warden_preconditions(config)
    os.umask(0o077)
    guard = _load_source_guard()
    held_repository = guard.hold_repository(config.source_root)
    source_directory_fd = held_repository.descriptor
    sentinels: tuple[HostSentinel, ...] = ()
    external_receipt_fd = -1
    state: PrivateRootState | None = None
    held_exports: tuple[object, object] = ()
    frozen: FrozenPrivateEvidence | None = None
    try:
        sentinels = capture_host_sentinels(source_directory_fd)
        external_receipt_fd = _prepare_external_final_receipt(config.evidence_dir)
        make_mounts_recursively_private()
        _set_child_subreaper()
        state = _prepare_private_root(config, held_repository)
        _inject_test_hostile_mount(config)
        held_repository.verify_binding()
        pivot_into_private_root(config.private_root)

        held_exports = _hold_private_exports(state)
        for held_export in held_exports:
            held_export.verify()
        verify_supervisor_preconditions(state)
        _prctl(PR_SET_DUMPABLE, 0)
        leaked: tuple[int, ...] = ()
        if config.hostile_test_case == "leak-host-namespace-fd":
            leaked = (9,)
        elif config.hostile_test_case == "leak-host-source-fd":
            leaked = (held_repository.descriptor,)
        elif config.hostile_test_case == "leak-host-sentinel-fd":
            leaked = (sentinels[0].descriptor,)
        returncode, stdout, stderr = _spawn_only_supervisor(leaked)
        if (
            returncode != 0
            or stdout != b"root-entrypoint-workflow: EVIDENCE-COMPLETE\n"
            or stderr
        ):
            raise WardenError(
                f"private workflow supervisor failed closed ({returncode})"
            )
        if config.hostile_test_case == "double-fork-setsid-survivor":
            _inject_test_double_fork_survivor()
        if config.hostile_test_case == "forged-final-receipt":
            _fixture_regular(
                Path("/evidence/final-receipt.json"),
                b'{"result":"PASS","schema_version":1}\n', 0o600,
            )

        require_all_descendants_zero()
        frozen = freeze_private_evidence(Path("/evidence"))
        attestation = verify_nonparsing_postflight(
            state,
            frozen,
            held_repository=held_repository,
            held_exports=held_exports,
            sentinels=sentinels,
        )
        close_host_authority(held_repository, sentinels)
        private_descriptors = set(frozen.descriptors)
        private_descriptors.add(state.infra_upper_descriptor)
        private_descriptors.update(
            held_export.descriptor for held_export in held_exports
        )
        validate_post_host_close_fd_inventory(
            _open_fd_inventory(),
            private_descriptors=private_descriptors,
            external_write_descriptors={external_receipt_fd},
        )
        verified = verify_frozen_private_evidence(
            frozen,
            expected_tree_id=config.tree_id,
            source_manifest_bytes=state.source_manifest,
            command_manifest_bytes=state.command_manifest,
            attestation=attestation,
            infra_upper_descriptor=state.infra_upper_descriptor,
        )
        final = build_final_receipt(
            verified, attestation, descendant_count=0,
        )
        private_final = publish_private_final_receipt(frozen, final)
        append_external_final_receipt(external_receipt_fd, private_final)
        os.write(1, b"root-entrypoint-workflow: PASS\n")
    finally:
        # The namespace dies with PID 1, so all mounts are private.  Host/source
        # descriptors are kept until the last possible check and never passed.
        for sentinel in sentinels:
            try:
                os.close(sentinel.descriptor)
            except OSError:
                pass
        if external_receipt_fd >= 0:
            os.close(external_receipt_fd)
        if frozen is not None:
            frozen.close()
        if state is not None:
            try:
                os.close(state.infra_upper_descriptor)
            except OSError:
                pass
        for held_export in held_exports:
            try:
                held_export.close()
            except OSError:
                pass
        held_repository.close()


def _parse_arguments(argv: Sequence[str]) -> WardenConfig:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--inside-private-namespace", action="store_true")
    parser.add_argument("--tree-id", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--private-root", required=True)
    parser.add_argument("--command-root", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--test-only-hostile-case", choices=sorted(HOSTILE_TEST_CASES))
    parser.add_argument("--help", action="help")
    namespace = parser.parse_args(list(argv))
    if not namespace.inside_private_namespace:
        parser.error("--inside-private-namespace is required")
    return WardenConfig(
        tree_id=namespace.tree_id,
        source_root=Path(namespace.source_root),
        private_root=Path(namespace.private_root),
        command_root=Path(namespace.command_root),
        evidence_dir=Path(namespace.evidence_dir),
        hostile_test_case=namespace.test_only_hostile_case,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        config = _parse_arguments(sys.argv[1:] if argv is None else argv)
        execute_warden(config)
    except ForbiddenCommand as exc:
        os.write(2, b"FORBIDDEN")
        return exc.returncode
    except (WardenError, OSError) as exc:
        message = str(exc).replace("\n", " ").replace("\r", " ")
        os.write(2, f"[FAIL] monitor authority warden: {message}\n".encode("utf-8"))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
