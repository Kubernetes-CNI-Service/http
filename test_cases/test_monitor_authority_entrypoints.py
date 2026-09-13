#!/usr/bin/env python3
"""Contracts for the Linux root-namespace Monitor authority entrypoint proof."""

from __future__ import annotations

import ast
import contextlib
import dataclasses
import os
import importlib.util
import hashlib
import inspect
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "test_cases/run_monitor_authority_entrypoints.sh"
WARDEN = ROOT / "test_cases/monitor_authority_root_warden.py"
SOURCE_GUARD = ROOT / "test_cases/monitor_authority_source_guard.py"
CONTROL_AUTH_HELPER = ROOT / "tools/control-auth.py"
PUBLIC_CI = ROOT / ".github/workflows/tests.yml"
ROOT_CI = ROOT / ".github/workflows/monitor-authority-root.yml"
REAL_ENVIRONMENT = ROOT / "test_cases/REAL_ENVIRONMENT.md"
NOT_COVERED = (
    "root-entrypoint-workflow: NOT COVERED "
    "(requires Linux EUID 0 private namespace)"
)
ROOT_HOSTILE_CASES = (
    "leak-host-namespace-fd",
    "leak-host-source-fd",
    "leak-host-sentinel-fd",
    "nested-writable-mount",
    "host-device-bind",
    "host-sys-bind",
    "double-fork-setsid-survivor",
    "forged-final-receipt",
)
ROOT_COMMAND_LEAF_NAMES = (
    "apache2ctl", "apt-get", "awk", "basename", "bash", "cat", "chmod",
    "chown", "cmp", "cp", "cut", "date", "dirname", "docker", "dpkg",
    "dpkg-query", "env", "find", "findmnt", "flock", "grep", "head",
    "hostname", "id", "install", "ln", "mkdir", "mkfifo", "mktemp",
    "mv", "od", "python3", "readlink", "realpath", "rm", "rmdir",
    "sed", "setpriv", "sha256sum", "sort", "ss", "ssh-keygen", "stat",
    "supervisorctl", "supervisord", "sync", "systemctl", "tail", "tee",
    "timeout", "tr", "uname", "wc",
)
ROOT_RECOVERY_DECISION_TOKENS = (
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
ROOT_WORKFLOW_PHASES = (
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
ROOT_FORBIDDEN_COMMAND_ARGV = (
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
ROOT_RECOVERY_WARNING = (
    b"WARNING: explicit Monitor authority recovery reset invalid cache state; "
    b"review the accepted www-data denial residual.\n"
)
ROOT_CLEANUP_DURABILITY_WARNING = (
    b"WARNING: Monitor authority recovery committed, but marker cleanup "
    b"durability is unknown; a stale completed marker may reappear after crash.\n"
)
ROOT_NATIVE_STOPPED_WARNING = (
    b"[WARN] Apache stopped for explicit Monitor cache authority recovery.\n"
)
ROOT_NATIVE_RECOVERY_COMPLETE = (
    b"[OK] explicit Monitor cache authority recovery completed.\n"
)
ROOT_TEARDOWN_COMPLETE = b"[OK]    infra-teardown.sh completed.\n"
ROOT_CONTROL_AUTH_HELPER_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)
ROOT_APACHE_PUBLIC_BOUNDARY_SHA256 = (
    "616629333ac16e4bc0c076a499d98864959372b5a24bee3c0d4257c1aa9d15fb"
)
ROOT_ABSOLUTE_EXECUTABLE_LITERALS = {
    "DAY0-Prepare/11-load.py": {
        "/bin/sh", "/usr/bin/env", "/usr/bin/ssh-keygen",
        "/usr/local/bin/brew",
    },
    "infra/docker/activate.py": {
        "/usr/bin/env", "/usr/bin/python3", "/usr/sbin/apache2ctl",
        "/usr/sbin/dhcpd",
    },
    "infra/docker/deploy.sh": {
        "/usr/bin/env", "/usr/bin/python3", "/usr/bin/timeout",
    },
    "infra/docker/entrypoint.py": {"/usr/bin/env", "/usr/bin/supervisord"},
    "infra/docker/healthcheck.py": {
        "/usr/bin/env", "/usr/sbin/apache2ctl", "/usr/sbin/dhcpd",
    },
    "infra/docker/hostctl.py": {
        "/usr/bin/env", "/usr/bin/python3", "/usr/sbin/logrotate",
    },
    "infra/docker/hostlock.py": {"/usr/bin/env", "/usr/bin/python3"},
    "infra/infra-setup.sh": {
        "/bin/bash", "/bin/sh", "/usr/bin/timeout", "/usr/sbin/policy-rc.d",
    },
    "infra/infra-teardown.sh": {"/bin/bash", "/usr/bin/timeout"},
    "monitor/ztp-monitor-control.cgi": {"/usr/bin/env", "/usr/bin/python3"},
    "test_cases/monitor_authority_root_warden.py": {
        "/usr/bin/basename", "/usr/bin/bash", "/usr/bin/cat",
        "/usr/bin/chmod", "/usr/bin/chown", "/usr/bin/cmp", "/usr/bin/cp",
        "/usr/bin/cut", "/usr/bin/date", "/usr/bin/dirname", "/usr/bin/env",
        "/usr/bin/find", "/usr/bin/findmnt", "/usr/bin/flock", "/usr/bin/grep",
        "/usr/bin/head", "/usr/bin/hostname", "/usr/bin/id",
        "/usr/bin/install", "/usr/bin/ln", "/usr/bin/mawk", "/usr/bin/mkdir",
        "/usr/bin/mkfifo", "/usr/bin/mktemp", "/usr/bin/mv", "/usr/bin/od",
        "/usr/bin/python3", "/usr/bin/python3.12", "/usr/bin/readlink",
        "/usr/bin/realpath", "/usr/bin/rm", "/usr/bin/rmdir", "/usr/bin/sed",
        "/usr/bin/setpriv", "/usr/bin/sha256sum", "/usr/bin/sort",
        "/usr/bin/ssh-keygen", "/usr/bin/stat", "/usr/bin/supervisord", "/usr/bin/sync",
        "/usr/bin/tail", "/usr/bin/tee", "/usr/bin/timeout", "/usr/bin/tr",
        "/usr/bin/uname", "/usr/bin/wc", "/usr/sbin/apache2ctl",
    },
    "test_cases/monitor_authority_source_guard.py": {
        "/usr/bin/env", "/usr/bin/git",
    },
    "test_cases/run_monitor_authority_entrypoints.sh": {"/usr/bin/env"},
    "tools/control-auth.py": {"/usr/bin/env", "/usr/bin/htpasswd"},
}
ROOT_BOUND_ABSOLUTE_EXECUTABLES = {
    "/usr/bin/bash": "bash",
    "/usr/bin/env": "env",
    "/usr/bin/python3": "python3",
    "/usr/bin/ssh-keygen": "ssh-keygen",
    "/usr/bin/supervisord": "supervisord",
    "/usr/bin/timeout": "timeout",
    "/usr/sbin/apache2ctl": "apache2ctl",
}
ABSOLUTE_EXECUTABLE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(/(?:usr/(?:local/)?(?:s?bin)|s?bin)/[A-Za-z0-9_.+-]+)"
)


def absolute_executable_literals(source):
    observed = set(ABSOLUTE_EXECUTABLE_PATTERN.findall(source))
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return observed
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            observed.update(ABSOLUTE_EXECUTABLE_PATTERN.findall(node.value))
    return observed


def canonical_test_json(document):
    """Independently authored canonical evidence encoding used by test fixtures."""

    return (
        json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def independent_bad_authority_payloads():
    breaker = lambda schema, count, extra=False: canonical_test_json({
        "schema_version": schema,
        "contaminant_dev": 7,
        "contaminant_ino": 11,
        "failure_count": count,
        **({"extra": False} if extra else {}),
    })
    cache = lambda schema, digest, extra=False: canonical_test_json({
        "schema_version": schema,
        "factory_records_active": True,
        "helper_sha256": digest,
        **({"extra": False} if extra else {}),
    })
    return (
        ("status.lock", b'{"schema_version":1'),
        ("status.lock", breaker(1, 1, True)),
        ("status.lock", breaker(2, 1)),
        ("status.lock", breaker(1, 0)),
        ("status.lock", breaker(1, 4)),
        ("monitor-auth/factory-status.json", b""),
        ("monitor-auth/factory-status.json", b'{"schema_version":1'),
        ("monitor-auth/factory-status.json", cache(
            1, ROOT_CONTROL_AUTH_HELPER_SHA256, True,
        )),
        ("monitor-auth/factory-status.json", cache(
            2, ROOT_CONTROL_AUTH_HELPER_SHA256,
        )),
        ("monitor-auth/factory-status.json", cache(1, "0" * 64)),
    )


def independent_valid_authority_payloads():
    return (
        b"",
        canonical_test_json({
            "factory_records_active": True,
            "helper_sha256": ROOT_CONTROL_AUTH_HELPER_SHA256,
            "schema_version": 1,
        }),
    )


def independent_authority_records(
    *,
    root="/var/lib/http-ztp-monitor-auth",
    status_payload=None,
    factory_payload=None,
    marker_phase=None,
    generation=0,
):
    """Author one complete authority tree without production snapshot helpers."""

    valid_status, valid_factory = independent_valid_authority_payloads()
    if status_payload is None:
        status_payload = valid_status
    if factory_payload is None:
        factory_payload = valid_factory
    inode_base = 1000 + generation * 100
    clock_base = 1_700_000_000_000_000_000 + generation * 10_000

    def directory(path, inode, mode, uid, gid, links):
        return {
            "ctime_ns": clock_base + inode,
            "device": 71,
            "gid": gid,
            "inode": inode_base + inode,
            "links": links,
            "mode": 0o40000 | mode,
            "mtime_ns": clock_base + inode,
            "path": path,
            "size": 4096,
            "type": "directory",
            "uid": uid,
        }

    def regular(path, inode, mode, uid, gid, payload):
        return {
            "ctime_ns": clock_base + inode,
            "device": 71,
            "gid": gid,
            "inode": inode_base + inode,
            "links": 1,
            "mode": 0o100000 | mode,
            "mtime_ns": clock_base + inode,
            "path": path,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "type": "file",
            "uid": uid,
        }

    cache = root + "/monitor-auth"
    records = [
        directory(root, 1, 0o755, 0, 0, 3),
        directory(cache, 2, 0o700, 33, 33, 2),
        regular(cache + "/factory-status.json", 3, 0o600, 33, 33,
                factory_payload),
        regular(root + "/status.lock", 4, 0o660, 0, 33, status_payload),
    ]
    if marker_phase is not None:
        marker_payload = canonical_test_json({
            "phase": marker_phase,
            "schema_version": 1,
        })
        records.append(regular(
            cache + "/.factory-status." + "1" * 32 + ".tmp",
            5, 0o600, 33, 33, marker_payload,
        ))
    return tuple(sorted(records, key=lambda record: record["path"]))


def independent_authority_observations(*stage_records):
    return b"".join(
        canonical_test_json({"records": list(records), "stage": stage})
        for stage, records in stage_records
    )


def independent_helper_attest_invocation():
    return canonical_test_json({
        "argv": [
            "/usr/local/lib/http-ztp/control-auth.py",
            "monitor-authority-attest-decision",
        ],
        "returncode": 0,
    })


def independent_recovery_decisions():
    rows = []
    for cleanup, restart_allowed in (
        ("complete", True),
        ("marker-removal-durability-unknown", True),
        ("marker-retained", False),
        ("marker-authority-uncertain", False),
    ):
        for reset in (False, True):
            diagnostics = ROOT_RECOVERY_WARNING if reset else b""
            if cleanup == "marker-removal-durability-unknown":
                diagnostics += ROOT_CLEANUP_DURABILITY_WARNING
            token = (
                f"restart-{'allowed' if restart_allowed else 'blocked'}:"
                f"{cleanup};reset-invalid-cache={str(reset).lower()}"
            )
            rows.append({
                "cleanup": cleanup,
                "diagnostics_sha256": hashlib.sha256(diagnostics).hexdigest(),
                "diagnostics_size": len(diagnostics),
                "recovery_committed": True,
                "reset_invalid_cache": reset,
                "restart_allowed": restart_allowed,
                "token": token,
            })
    return rows


def independent_recovery_decision_facts():
    return tuple(
        (
            row["cleanup"], row["recovery_committed"],
            row["restart_allowed"], row["reset_invalid_cache"],
            row["diagnostics_size"], row["diagnostics_sha256"], row["token"],
        )
        for row in independent_recovery_decisions()
    )


def independent_teardown_snapshot():
    records = list(independent_authority_records(generation=32))
    records.extend((
        {
            "ctime_ns": 1_700_000_000_000_090_001,
            "device": 71,
            "gid": 0,
            "inode": 9001,
            "links": 1,
            "mode": 0o100755,
            "mtime_ns": 1_700_000_000_000_090_001,
            "path": "/usr/local/lib/http-ztp/control-auth.py",
            "sha256": ROOT_CONTROL_AUTH_HELPER_SHA256,
            "size": 65_536,
            "type": "file",
            "uid": 0,
        },
        {
            "ctime_ns": 1_700_000_000_000_090_002,
            "device": 71,
            "gid": 0,
            "inode": 9002,
            "links": 1,
            "mode": 0o100644,
            "mtime_ns": 1_700_000_000_000_090_002,
            "path": "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
            "sha256": ROOT_APACHE_PUBLIC_BOUNDARY_SHA256,
            "size": 4096,
            "type": "file",
            "uid": 0,
        },
    ))
    return canonical_test_json({
        "records": sorted(records, key=lambda record: record["path"]),
    })


def independent_cgi_response(status, document):
    body = json.dumps(document, ensure_ascii=False).encode("utf-8")
    return (
        f"Status: {status}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Cache-Control: no-store\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii") + body


def independent_cgi_invocation():
    return canonical_test_json({
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


def independent_operation_result_specs():
    specs = []
    for index in range(10):
        target = (
            "status.lock" if index < 5
            else "monitor-auth/factory-status.json"
        )
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
    for state in ("active", "inactive", "failed"):
        index = ("active", "inactive", "failed").index(state)
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


def independent_operation_results(payloads):
    records = []
    for index, spec in enumerate(independent_operation_result_specs(), 1):
        records.append({
            "argv": list(spec["argv"]),
            "artifacts": [
                {
                    "role": role,
                    "name": name,
                    "size": len(payloads[name]),
                    "sha256": hashlib.sha256(payloads[name]).hexdigest(),
                }
                for role, name in spec["artifacts"]
            ],
            "index": index,
            "operation": spec["operation"],
            "returncode": spec["returncode"],
        })
    return b"".join(canonical_test_json(record) for record in records)


def independent_infra_audit_records():
    operations = (
        "marker-recovery-in-progress",
        "marker-recovery-committed-cleanup-pending",
        "stop-stop-fail", "stop-show-fail", "stop-stay-active",
        "native-active", "native-inactive", "native-failed", "teardown",
    )
    records = []
    for index, operation in enumerate(operations, 101):
        kind = "teardown" if operation == "teardown" else "setup"
        name = f"infra-{kind}-20260101_000000-{index}.log"
        payload = independent_infra_log_payload(operation)
        records.append({
            "log_name": name,
            "operation": operation,
            "reset_warning_count": int(operation.startswith("native-")),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        })
    return tuple(records)


def independent_infra_log_payload(operation):
    payload = f"independent-log-{operation}\n".encode("ascii")
    if operation.startswith("native-"):
        payload += ROOT_RECOVERY_WARNING
    return payload


def independent_infra_runtime_records():
    return tuple(
        {
            key: value
            for key, value in record.items()
            if key != "operation"
        }
        for record in independent_infra_audit_records()
    )


def independent_command_events():
    records = []

    def add(operation, command, argv, returncode, observation):
        records.append({
            "argv": list(argv),
            "command": command,
            "observation": observation,
            "operation": operation,
            "result": "ALLOWED",
            "returncode": returncode,
        })

    for command, argv in ROOT_FORBIDDEN_COMMAND_ARGV:
        records.append({
            "argv": list(argv),
            "command": command,
            "observation": {},
            "operation": "argv-collision-matrix",
            "result": "FORBIDDEN",
            "returncode": 99,
        })

    def systemctl(operation, argv, before, after, returncode=0, mode="normal"):
        add(operation, "systemctl", argv, returncode, {
            "mode": mode, "state_after": after, "state_before": before,
        })

    for phase in (
        "recovery-in-progress", "recovery-committed-cleanup-pending",
    ):
        operation = f"marker-{phase}"
        systemctl(operation, ("show", "--property=ActiveState", "--value", "apache2"), "active", "active")
        systemctl(operation, ("stop", "apache2"), "active", "inactive")
        systemctl(operation, ("show", "--property=ActiveState", "--value", "apache2"), "inactive", "inactive")
        systemctl(operation, ("start", "apache2"), "inactive", "active")
        systemctl(operation, ("show", "--property=ActiveState", "--value", "apache2"), "active", "active")

    systemctl("stop-stop-fail", ("show", "--property=ActiveState", "--value", "apache2"), "active", "active", mode="stop-fail")
    systemctl("stop-stop-fail", ("stop", "apache2"), "active", "active", 1, "stop-fail")
    systemctl("stop-show-fail", ("show", "--property=ActiveState", "--value", "apache2"), "active", "active", 1, "show-fail")
    systemctl("stop-stay-active", ("show", "--property=ActiveState", "--value", "apache2"), "active", "active", mode="stay-active")
    systemctl("stop-stay-active", ("stop", "apache2"), "active", "active", mode="stay-active")
    systemctl("stop-stay-active", ("show", "--property=ActiveState", "--value", "apache2"), "active", "active", mode="stay-active")

    systemctl("native-active", ("show", "--property=ActiveState", "--value", "apache2"), "active", "active")
    systemctl("native-active", ("stop", "apache2"), "active", "inactive")
    systemctl("native-active", ("show", "--property=ActiveState", "--value", "apache2"), "inactive", "inactive")
    systemctl("native-active", ("start", "apache2"), "inactive", "active")
    systemctl("native-active", ("show", "--property=ActiveState", "--value", "apache2"), "active", "active")
    for operation, initial in (("native-inactive", "inactive"), ("native-failed", "failed")):
        systemctl(operation, ("show", "--property=ActiveState", "--value", "apache2"), initial, initial)
        systemctl(operation, ("stop", "apache2"), initial, "inactive")
        systemctl(operation, ("show", "--property=ActiveState", "--value", "apache2"), "inactive", "inactive")

    docker = "docker-writer"
    for argv, before, after in (
        (("context", "show"), "running", "running"),
        (("context", "inspect", "default"), "running", "running"),
        (("info", "--format", "{{json .}}"), "running", "running"),
    ):
        add(docker, "docker", argv, 0, {
            "state_after": after, "state_before": before,
        })
    add(docker, "dpkg", ("--print-architecture",), 0, {})
    add(docker, "docker", ("container", "inspect", "http-ztp"), 0, {
        "container_id": "a" * 64, "dead": False, "pid": 4242,
        "running": True, "state_after": "running", "state_before": "running",
    })
    add(docker, "docker", ("stop", "--time", "30", "a" * 64), 0, {
        "state_after": "stopped", "state_before": "running",
    })
    add(docker, "docker", ("container", "inspect", "a" * 64), 0, {
        "container_id": "a" * 64, "dead": False, "pid": 0,
        "running": False, "state_after": "stopped", "state_before": "stopped",
    })
    add(docker, "docker", ("rm", "a" * 64), 0, {
        "state_after": "absent", "state_before": "stopped",
    })

    for argv in (
        ("is-active", "--quiet", "systemd-resolved"),
        ("is-active", "--quiet", "systemd-timesyncd"),
    ):
        systemctl("teardown", argv, "inactive", "inactive", 3)
    add("teardown", "dpkg", ("-s", "apache2"), 1, {})
    return tuple(records)


def independent_lifecycle_event_log(command_records):
    lines = []
    docker_semantics = {
        ("container", "inspect", "http-ztp"): "docker-inspect-writer",
        ("stop", "--time", "30", "a" * 64): "docker-stop-writer",
        ("container", "inspect", "a" * 64): "docker-reinspect-writer",
        ("rm", "a" * 64): "docker-remove-writer",
    }
    for record in command_records:
        if record["result"] != "ALLOWED":
            continue
        argv = tuple(record["argv"])
        lines.append(" ".join((record["command"], *argv)))
        if record["operation"] == "docker-writer" and argv in docker_semantics:
            lines.append(docker_semantics[argv])
    return ("\n".join(lines) + "\n").encode("ascii")


def independent_private_evidence_payloads(
    tree_id, source_manifest, command_manifest,
):
    """Build the complete raw evidence contract without warden helpers."""

    payloads = {
        "collision.stderr": b"FORBIDDEN\n",
        "collision.stdout": b"",
        "command-manifest.json": command_manifest,
        "docker-recover.err": ROOT_RECOVERY_WARNING,
        "docker-recover.out": (
            b"[OK] Ubuntu 24.04 amd64 host; Ubuntu 24.04 container\n"
            b"[OK] Monitor cache authority recovered; container remains stopped\n"
            b"[NEXT] sudo ./infra/docker/deploy.sh deploy\n"
        ),
        "events.log": b"pending\n",
        "expected-tree-id": (tree_id + "\n").encode("ascii"),
        "infra-audit-map.jsonl": b"".join(
            canonical_test_json(record)
            for record in independent_infra_audit_records()
        ),
        "phases.jsonl": b"".join(
            canonical_test_json({"index": index, "phase": phase})
            for index, phase in enumerate(ROOT_WORKFLOW_PHASES, 1)
        ),
        "recovery-decisions.json": canonical_test_json(
            independent_recovery_decisions()
        ),
        "service-state.json": b'{"schema_version":1}\n',
        "source-manifest.json": source_manifest,
        "teardown-before.json": independent_teardown_snapshot(),
        "teardown.err": b"",
        "teardown.out": ROOT_TEARDOWN_COMPLETE,
        "pre-teardown-attest.out": b"attest-valid",
        "pre-teardown-attest.err": b"",
        "pre-teardown-attest.invocation.json": (
            independent_helper_attest_invocation()
        ),
        "postflight-attest.out": b"attest-valid",
        "postflight-attest.err": b"",
        "postflight-attest.invocation.json": (
            independent_helper_attest_invocation()
        ),
        "authority-postflight.jsonl": independent_authority_observations(
            ("pre-attest", independent_authority_records(generation=32)),
            ("post-attest", independent_authority_records(generation=32)),
        ),
    }
    payloads["teardown-after.json"] = payloads["teardown-before.json"]
    command_records = independent_command_events()
    payloads["command-events.jsonl"] = b"".join(
        canonical_test_json(record) for record in command_records
    )
    payloads["events.log"] = independent_lifecycle_event_log(command_records)
    for index, (target, bad_payload) in enumerate(
        independent_bad_authority_payloads()
    ):
        payloads[f"bad-payload-{index}.bin"] = bad_payload
        payloads[f"cgi-bad-{index}.out"] = independent_cgi_response(
            "503 Service Unavailable",
            {"error": "control authentication state unavailable"},
        )
        payloads[f"cgi-bad-{index}.out.err"] = (
            b"monitor-control-auth: cache-authority\n"
        )
        payloads[f"cgi-bad-{index}.invocation.json"] = (
            independent_cgi_invocation()
        )
        payloads[f"health-{index}.out"] = (
            b"[ERROR] unhealthy ZTP container: Monitor cache authority "
            b"attestation failed\n"
        )
        valid_status, valid_factory = independent_valid_authority_payloads()
        records = independent_authority_records(
            status_payload=(
                bad_payload if target == "status.lock" else valid_status
            ),
            factory_payload=(
                bad_payload
                if target == "monitor-auth/factory-status.json"
                else valid_factory
            ),
            generation=index,
        )
        payloads[f"authority-bad-{index}.jsonl"] = (
            independent_authority_observations(
                ("pre-health", records),
                ("post-health", records),
                ("post-cgi", records),
            )
        )
    for index in range(3):
        payloads[f"cgi-good-{index}.out"] = independent_cgi_response(
            "200 OK", {
                "state": "running",
                "process_alive": False,
                "control_auth": {"factory_records_active": True},
            },
        )
        payloads[f"cgi-good-{index}.out.err"] = b""
        payloads[f"cgi-good-{index}.invocation.json"] = (
            independent_cgi_invocation()
        )
    for phase in (
        "recovery-in-progress", "recovery-committed-cleanup-pending",
    ):
        payloads[f"marker-{phase}.out"] = phase.encode("ascii")
        payloads[f"marker-{phase}.err"] = b""
        payloads[f"marker-reset-{phase}.out"] = b""
        payloads[f"marker-reset-{phase}.err"] = (
            ROOT_NATIVE_STOPPED_WARNING + ROOT_NATIVE_RECOVERY_COMPLETE
        )
        payloads[f"marker-after-{phase}.out"] = b"attest-valid"
        payloads[f"marker-after-{phase}.err"] = b""
        marker_records = independent_authority_records(
            marker_phase=phase,
            generation=(10 if phase == "recovery-in-progress" else 11),
        )
        recovered_records = independent_authority_records(
            generation=(12 if phase == "recovery-in-progress" else 13),
        )
        payloads[f"authority-marker-{phase}.jsonl"] = (
            independent_authority_observations(
                ("pre-classification", marker_records),
                ("post-classification", marker_records),
                ("post-recovery", recovered_records),
                ("post-attest", recovered_records),
            )
        )
    for state in ("active", "inactive", "failed"):
        index = ("active", "inactive", "failed").index(state)
        payloads[f"native-{state}.out"] = b""
        payloads[f"native-{state}.err"] = (
            ROOT_NATIVE_STOPPED_WARNING
            + ROOT_RECOVERY_WARNING
            + ROOT_NATIVE_RECOVERY_COMPLETE
        )
        payloads[f"native-attest-{state}.out"] = b"attest-valid"
        payloads[f"native-attest-{state}.err"] = b""
        bad_records = independent_authority_records(
            status_payload=independent_bad_authority_payloads()[0][1],
            generation=20 + index,
        )
        valid_records = independent_authority_records(generation=30 + index)
        payloads[f"authority-native-{state}.jsonl"] = (
            independent_authority_observations(
                ("pre-recovery", bad_records),
                ("post-recovery", valid_records),
                ("post-attest", valid_records),
                ("post-cgi", valid_records),
            )
        )
    for mode in ("stop-fail", "show-fail", "stay-active"):
        payloads[f"stop-{mode}.out"] = b""
        records = independent_authority_records(
            status_payload=independent_bad_authority_payloads()[0][1],
            generation=50 + ("stop-fail", "show-fail", "stay-active").index(mode),
        )
        payloads[f"authority-stop-{mode}.jsonl"] = (
            independent_authority_observations(
                ("pre-recovery", records),
                ("post-recovery", records),
            )
        )
    payloads["stop-stop-fail.err"] = (
        b"ERROR: Apache could not be stopped; Monitor authority was not repaired.\n"
    )
    payloads["stop-show-fail.err"] = (
        b"ERROR: Apache state cannot be proven; Monitor authority was not repaired.\n"
    )
    payloads["stop-stay-active.err"] = (
        b"ERROR: Apache is not provably stopped; Monitor authority was not repaired.\n"
    )
    docker_bad = independent_authority_records(
        root="/var/lib/http-ztp-container/monitor-auth",
        status_payload=independent_bad_authority_payloads()[0][1],
        generation=40,
    )
    docker_valid = independent_authority_records(
        root="/var/lib/http-ztp-container/monitor-auth", generation=41,
    )
    payloads["authority-docker-container.jsonl"] = (
        independent_authority_observations(
            ("pre-recovery", docker_bad),
            ("post-recovery", docker_valid),
        )
    )
    docker_native = independent_authority_records(generation=32)
    payloads["authority-docker-native.jsonl"] = (
        independent_authority_observations(
            ("pre-recovery", docker_native),
            ("post-recovery", docker_native),
        )
    )
    payloads["operation-results.jsonl"] = independent_operation_results(payloads)
    return payloads


def load_warden():
    spec = importlib.util.spec_from_file_location(
        "monitor_authority_root_warden_under_test", WARDEN,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("warden import spec is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(spec.name) is module:
            del sys.modules[spec.name]
        raise
    return module


class _OwnedStat:
    """Test-only metadata view; production APIs remain fixed to uid/gid zero."""

    def __init__(self, metadata, uid, gid):
        self._metadata = metadata
        self._uid = uid
        self._gid = gid

    def __getattr__(self, name):
        if name == "st_uid":
            return self._uid
        if name == "st_gid":
            return self._gid
        return getattr(self._metadata, name)


@contextlib.contextmanager
def owned_metadata_view(warden, uid, gid, *, suppress_fchown=False):
    """Give direct tests an explicit synthetic ownership identity."""

    real_fstat = os.fstat
    real_stat = os.stat
    real_path_stat = Path.stat

    def root_fstat(descriptor):
        return _OwnedStat(real_fstat(descriptor), uid, gid)

    def root_stat(path, *args, **kwargs):
        return _OwnedStat(real_stat(path, *args, **kwargs), uid, gid)

    def root_path_stat(path, *args, **kwargs):
        return _OwnedStat(real_path_stat(path, *args, **kwargs), uid, gid)

    patches = [
        mock.patch.object(warden.os, "fstat", side_effect=root_fstat),
        mock.patch.object(warden.os, "stat", side_effect=root_stat),
        mock.patch.object(warden.Path, "stat", new=root_path_stat),
    ]
    if suppress_fchown:
        patches.append(mock.patch.object(warden.os, "fchown", return_value=None))
    with contextlib.ExitStack() as stack:
        for patcher in patches:
            stack.enter_context(patcher)
        yield


def root_owned_metadata_view(warden):
    return owned_metadata_view(warden, 0, 0, suppress_fchown=True)


class MonitorAuthorityEntrypointRunnerContracts(unittest.TestCase):
    def test_bare_runner_refuses_before_privileged_lifecycle_work(self):
        result = subprocess.run(
            ["/bin/bash", os.fspath(RUNNER)],
            cwd=ROOT,
            env={**os.environ, "PATH": "/nonexistent"},
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(64, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(
            "[REFUSED] Monitor authority root-entrypoint runner requires the "
            "held host mount-namespace descriptor on FD 9.\n",
            result.stderr,
        )

    def test_runner_is_only_the_close_all_private_workflow_supervisor(self):
        source = RUNNER.read_text(encoding="utf-8")
        required = (
            "--execute-private-fixtures",
            "verify_supervisor_descriptor_set",
            "verify_fixture_mounts",
            "verify_private_source_copy",
            "verify_stub_authority",
            "verify_network_and_pid_namespace",
            "root-entrypoint-workflow: EVIDENCE-COMPLETE",
            "/etc/monitor-root-writable-probe",
        )
        for token in required:
            with self.subTest(token=token):
                self.assertIn(token, source)
        for forbidden in (
            "eval ", "--test-root", "fake-euid", "source_function",
            "cp -a", "jobs -pr", "original_source", "host_sentinel_",
            "exec 9<", "mount -o remount,bind,ro /", "$*",
            "importlib.util", "sys.modules",
            "--verify-completed-receipt", "final-receipt.json",
            "provisional-receipt.json", "root-entrypoint-workflow: PROVISIONAL",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source.casefold())
        self.assertRegex(source, r'export PATH="\$COMMAND_ROOT"(?:\n|$)')
        self.assertNotRegex(source, r'PATH=.*(?:/usr/bin|/bin)')

    def test_runner_executes_three_exact_repository_entrypoints(self):
        source = RUNNER.read_text(encoding="utf-8")
        for invocation in (
            "./infra/infra-setup.sh --recover-monitor-authority",
            "./infra/infra-teardown.sh --non-interactive --yes",
            "./infra/docker/deploy.sh recover-monitor-authority",
        ):
            with self.subTest(invocation=invocation):
                self.assertIn(invocation, source)
        self.assertNotIn("sed -n", source)
        self.assertNotIn("declare -f", source)

    def test_runner_captures_pre_teardown_and_final_postflight_attestations(self):
        source = RUNNER.read_text(encoding="utf-8")
        for name in (
            "pre-teardown-attest.out",
            "pre-teardown-attest.err",
            "pre-teardown-attest.invocation.json",
            "postflight-attest.out",
            "postflight-attest.err",
            "postflight-attest.invocation.json",
            "authority-postflight.jsonl",
        ):
            with self.subTest(name=name):
                self.assertIn(name, source)
        context_close = source.index('rm -f -- "$OPERATION_CONTEXT"')
        final_capture = source.index("postflight-attest.out")
        final_phase = source.index("record_phase postflight-attestation")
        self.assertLess(context_close, final_capture)
        self.assertLess(context_close, final_phase)
        self.assertLess(final_capture, final_phase)
        self.assertIsNone(
            re.search(
                r"monitor-authority-attest-decision\s*\|\s*"
                r"cmp\s+-\s+<\(printf\s+attest-valid\)",
                source,
            ),
            "every helper attestation must be captured as raw evidence",
        )

    def test_warden_derives_factory_records_from_the_pinned_helper(self):
        source = WARDEN.read_text(encoding="utf-8")
        self.assertIsNone(
            re.search(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", source),
            "the two public bootstrap verifiers must have one source authority",
        )
        warden = load_warden()
        helper_payload = CONTROL_AUTH_HELPER.read_bytes()
        records = warden._factory_control_users_from_pinned_helper(helper_payload)
        self.assertEqual(
            "197edfef9a0092e9c87f70a7a48bcbddac0dcf9d7a5005e39407ff81f8353639",
            hashlib.sha256(records).hexdigest(),
        )
        self.assertEqual([b"nvis", b"cumulus"], [
            line.split(b":", 1)[0] for line in records.splitlines()
        ])
        with self.assertRaises(warden.WardenError):
            warden._factory_control_users_from_pinned_helper(
                helper_payload.replace(b"FACTORY_RECORDS", b"FACTORY_RECORDX", 1)
            )

    def test_docker_phase_never_installs_a_native_authority_bad_payload(self):
        source = RUNNER.read_text(encoding="utf-8")
        body = source.split("exercise_docker_writer_removal() {", 1)[1].split(
            "\n}", 1,
        )[0]
        self.assertNotIn("install_literal_bad_payload", body)
        self.assertIn("install_literal_docker_bad_payload", body)
        self.assertIn('pre-recovery "$DOCKER_AUTHORITY"', body)
        fixture_source = inspect.getsource(load_warden()._install_private_fixtures)
        self.assertIn(
            'var/lib/http-ztp-container/monitor-auth/status.lock',
            fixture_source,
        )
        self.assertIn("b'{\"schema_version\":1'", fixture_source)
        self.assertIn('"monitor-auth/factory-status.json"', fixture_source)

    def test_operation_records_take_argv_from_the_same_execution_wrapper(self):
        source = RUNNER.read_text(encoding="utf-8")

        def observed_invocations(value):
            logical = []
            pending = ""
            for raw_line in value.splitlines():
                line = raw_line.strip()
                if line.endswith("\\"):
                    pending += line[:-1] + " "
                    continue
                logical.append((pending + line).strip())
                pending = ""
            if pending:
                logical.append(pending.strip())
            invocations = []
            for line in logical:
                if not line.startswith("execute_recorded_operation "):
                    continue
                tokens = shlex.split(line)
                invocations.append(tuple(tokens[4:]))
            return tuple(sorted(invocations))

        expected = tuple(sorted((
            ("python3", "-B", "infra/docker/healthcheck.py"),
            ("./infra/infra-setup.sh", "--recover-monitor-authority"),
            ("./infra/infra-setup.sh", "--recover-monitor-authority"),
            ("./infra/infra-setup.sh", "--recover-monitor-authority"),
            ("./infra/docker/deploy.sh", "recover-monitor-authority"),
            ("./infra/infra-teardown.sh", "--non-interactive", "--yes"),
        )))
        self.assertEqual(expected, observed_invocations(source))
        self.assertIn('"${RECORDED_OPERATION_ARGV[@]}"', source)
        mutated = source.replace(
            "./infra/infra-setup.sh --recover-monitor-authority\n",
            "./infra/infra-setup.sh --recover-monitor-authority extra\n",
            1,
        )
        self.assertNotEqual(expected, observed_invocations(mutated))

    def test_public_pr_workflow_contains_no_privileged_root_job(self):
        workflow = PUBLIC_CI.read_text(encoding="utf-8")
        for forbidden in (
            "Run Monitor authority root-namespace entrypoints",
            "sudo --non-interactive", "/usr/bin/unshare",
            "monitor_authority_root_warden.py",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

    def test_dedicated_root_workflow_has_one_manual_trusted_trigger(self):
        document = yaml.load(
            ROOT_CI.read_text(encoding="utf-8"), Loader=yaml.BaseLoader,
        )
        self.assertEqual({"workflow_dispatch"}, set(document["on"]))
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertNotIn("env", document)
        self.assertEqual({"root-entrypoint"}, set(document["jobs"]))
        job = document["jobs"]["root-entrypoint"]
        self.assertEqual("ubuntu-24.04", job["runs-on"])
        self.assertEqual("30", job["timeout-minutes"])
        self.assertNotIn("env", job)
        setup_python = [
            step for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/setup-python@")
        ]
        self.assertEqual(1, len(setup_python))
        self.assertEqual(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
            setup_python[0]["uses"],
        )
        self.assertEqual("3.12", setup_python[0]["with"]["python-version"])
        for step in job["steps"]:
            self.assertNotIn("env", step)
            self.assertNotIn("continue-on-error", step)
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                self.assertEqual("false", step["with"]["persist-credentials"])
        raw = ROOT_CI.read_text(encoding="utf-8")
        for forbidden in (
            "pull_request", "pull_request_target", "workflow_run",
            "schedule:", "self-hosted", "${{ secrets.", "|| true",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, raw)

    def test_dedicated_workflow_guards_tree_then_uses_sanitized_pid1_warden(self):
        workflow = ROOT_CI.read_text(encoding="utf-8")
        for required in (
            "/usr/bin/git rev-parse --verify 'HEAD^{tree}'",
            "/usr/bin/git diff --quiet --exit-code",
            "/usr/bin/git diff --cached --quiet --exit-code",
            "/usr/bin/git ls-files --others --exclude-standard",
            "test_cases/run_related_tests.py --check",
            "exec 9</proc/self/ns/mnt",
            "sudo --non-interactive /usr/bin/env -i",
            "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "PYTHONNOUSERSITE=1", "PYTHONDONTWRITEBYTECODE=1",
            "HTTP_ZTP_MONITOR_ROOT_NAMESPACE=1",
            "test_cases.test_monitor_authority_entrypoints.",
            "MonitorAuthorityRootNamespaceScenario.test_real_root_entrypoint_workflow",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        self.assertNotRegex(
            workflow,
            r"(?m)(?<!/usr/bin/)git (?:rev-parse|diff|ls-files)",
        )

    def test_guarded_tree_id_is_carried_unchanged_into_the_root_warden(self):
        workflow = ROOT_CI.read_text(encoding="utf-8")
        initial_capture = (
            "\n          tree_id=$(/usr/bin/git rev-parse --verify 'HEAD^{tree}')"
        )
        full_gate = "test_cases/run_related_tests.py --all --no-approve -v"
        final_capture = (
            "current_tree_id=$(/usr/bin/git rev-parse --verify 'HEAD^{tree}')"
        )
        equality = 'test "$current_tree_id" = "$tree_id"'
        guard = "test_cases/monitor_authority_source_guard.py check"
        privileged = "sudo --non-interactive /usr/bin/env -i"
        for required in (
            initial_capture, final_capture, equality, guard, privileged,
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        self.assertLess(workflow.index(initial_capture), workflow.index(full_gate))
        self.assertLess(workflow.index(full_gate), workflow.index(final_capture))
        self.assertLess(workflow.index(final_capture), workflow.index(equality))
        self.assertLess(workflow.index(equality), workflow.index(guard))
        self.assertLess(workflow.index(guard), workflow.index(privileged))
        self.assertIn(
            "monitor-authority-root \"$PWD\" \"$python_bin\" \"$tree_id\"",
            workflow,
        )
        self.assertIn("expected_tree_id=$3", workflow)
        self.assertIn(
            'HTTP_ZTP_MONITOR_EXPECTED_TREE_ID="$expected_tree_id"', workflow,
        )

        scenario = MonitorAuthorityRootNamespaceScenario()
        expected = "1" * 40
        observed = "2" * 40
        completed = subprocess.CompletedProcess(
            ["/usr/bin/git"], 0, stdout=observed + "\n", stderr="",
        )
        with (
            mock.patch.dict(
                os.environ,
                {"HTTP_ZTP_MONITOR_EXPECTED_TREE_ID": expected},
                clear=False,
            ),
            mock.patch.object(subprocess, "run", return_value=completed),
            self.assertRaises(AssertionError),
        ):
            scenario._workflow_bound_tree_id()
        with (
            mock.patch.object(
                scenario, "_workflow_bound_tree_id",
                side_effect=AssertionError("tree ID changed"),
            ),
            mock.patch.object(scenario, "_invoke_root_warden") as invoke,
            self.assertRaises(AssertionError),
        ):
            MonitorAuthorityRootNamespaceScenario.test_real_root_entrypoint_workflow.__wrapped__(
                scenario,
            )
        invoke.assert_not_called()

        root_method = inspect.getsource(
            MonitorAuthorityRootNamespaceScenario.test_real_root_entrypoint_workflow
        )
        self.assertLess(
            root_method.index("_workflow_bound_tree_id"),
            root_method.index("_invoke_root_warden"),
        )

    def test_dedicated_workflow_runs_linux_full_suite_without_writing_ledger(self):
        workflow = ROOT_CI.read_text(encoding="utf-8")
        full = "test_cases/run_related_tests.py --all --no-approve -v"
        approved = "test_cases/run_related_tests.py --check"
        guard = "test_cases/monitor_authority_source_guard.py check"
        privileged = "sudo --non-interactive /usr/bin/env -i"
        for required in (full, approved, guard, privileged):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        self.assertLess(workflow.index(full), workflow.index(approved))
        self.assertLess(workflow.index(approved), workflow.index(guard))
        self.assertLess(workflow.index(guard), workflow.index(privileged))
        self.assertIn('python_bin="$(command -v python3)"', workflow)
        self.assertIn('"$python_bin" -m pip install', workflow)
        self.assertIn('"$python_bin" -B test_cases/run_related_tests.py', workflow)
        self.assertIn('exec "$python_bin" -B -m unittest -v', workflow)
        self.assertNotIn("/usr/bin/python3 -B -m unittest", workflow)
        for forbidden in (
            "--check --require-full", "--approve", "--update-approval",
            "script_test_approved_hashes.json >",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)

    def test_real_environment_states_the_honest_three_role_evidence_boundary(self):
        document = REAL_ENVIRONMENT.read_text(encoding="utf-8")
        for required in (
            ".github/workflows/monitor-authority-root.yml",
            "workflow_dispatch",
            "immutable `HEAD^{tree}`",
            "namespace PID-1 warden",
            "exactly one close-all supervisor child",
            "correctness and accidental-damage containment",
            "NOT an adversarial-PR sandbox",
            "reap/zero → freeze raw evidence → nonparsing postflight",
            "close host authority → positive FD inventory → private parse",
            "no-replace/fsync/reread PASS",
            NOT_COVERED,
            "exact committed tree",
            "--all --no-approve -v",
            "ordinary `--check` (without `--require-full`)",
            "Ubuntu root workflow remains pending",
        ):
            with self.subTest(required=required):
                self.assertIn(required, document)

    def test_warden_owns_host_fds_pivot_mount_proof_and_final_seal(self):
        source = WARDEN.read_text(encoding="utf-8")
        for required in (
            "PR_SET_CHILD_SUBREAPER", "close_fds=True", "pass_fds=()",
            "/proc/self/fd", "/proc/self/mountinfo", "pivot_root",
            "MNT_DETACH", "MS_REC | MS_PRIVATE", "all-descendant-zero",
            "verify_frozen_private_evidence", "build_final_receipt",
            "publish_private_final_receipt", "verify_host_sentinels",
            "correctness and accidental-damage containment",
            "NOT an adversarial-PR sandbox",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertLess(
            source.index("verify_supervisor_preconditions"),
            source.index("subprocess.Popen("),
        )

    def test_immutable_source_guard_and_runner_are_separate_support_roles(self):
        self.assertTrue(SOURCE_GUARD.is_file())
        guard = SOURCE_GUARD.read_text(encoding="utf-8")
        for required in (
            "HEAD^{tree}", "git cat-file", "git ls-tree",
            "O_NOFOLLOW", "O_EXCL", "exact set equality",
        ):
            with self.subTest(required=required):
                self.assertIn(required, guard)
        for forbidden in ("cp -a", "git checkout", "git archive"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, guard)

    def test_absolute_executable_literals_are_statically_exact_and_bound(self):
        observed = {
            relative: absolute_executable_literals(
                (ROOT / relative).read_text(encoding="utf-8")
            )
            for relative in ROOT_ABSOLUTE_EXECUTABLE_LITERALS
        }
        self.assertEqual(ROOT_ABSOLUTE_EXECUTABLE_LITERALS, observed)
        self.assertNotEqual(
            ROOT_ABSOLUTE_EXECUTABLE_LITERALS["infra/docker/hostlock.py"],
            absolute_executable_literals(
                (ROOT / "infra/docker/hostlock.py").read_text(encoding="utf-8")
                + '\nprobe = "/usr/bin/new-unreviewed-tool"\n'
            ),
            "a new literal absolute executable escaped the static inventory",
        )
        self.assertEqual(
            {"/usr/bin/new-unreviewed-tool"},
            absolute_executable_literals(
                'subprocess.run(["/usr/" "bin/new-unreviewed-tool"])\n'
            ),
            "Python compile-time string concatenation escaped AST inventory",
        )
        warden = load_warden()
        self.assertEqual(
            ROOT_BOUND_ABSOLUTE_EXECUTABLES,
            dict(warden.ABSOLUTE_COMMAND_BINDINGS),
        )
        installer = inspect.getsource(warden._install_absolute_commands)
        self.assertIn("ABSOLUTE_COMMAND_BINDINGS.items()", installer)
        self.assertIn("_bind_readonly(command_root / command, target)", installer)


class MonitorAuthorityWardenContracts(unittest.TestCase):
    def setUp(self):
        self.warden = load_warden()

    def test_supervisor_environment_has_exact_key_and_value_equality(self):
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
        self.assertEqual(expected, self.warden.SUPERVISOR_ENVIRONMENT)
        self.warden.validate_supervisor_environment(dict(expected))
        mutations = []
        extra = dict(expected)
        extra["BASH_ENV"] = "/fixture/injected"
        mutations.append(extra)
        missing = dict(expected)
        missing.pop("PYTHONNOUSERSITE")
        mutations.append(missing)
        drift = dict(expected)
        drift["PATH"] = "/commands:/usr/bin"
        mutations.append(drift)
        for environment in mutations:
            with self.subTest(environment=environment), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden.validate_supervisor_environment(environment)

    def _verify_independent_payloads(
        self, payloads, *, tree_id, source_manifest, command_manifest,
        live_native=None, live_docker=None,
    ):
        fixture_digest = "8" * 64
        infra_digest = "a" * 64
        native_live = live_native or independent_authority_records(generation=32)
        docker_live = live_docker or independent_authority_records(
            root="/var/lib/http-ztp-container/monitor-auth", generation=41,
        )
        native_authority_digest = hashlib.sha256(
            canonical_test_json(list(native_live)),
        ).hexdigest()
        docker_authority_digest = hashlib.sha256(
            canonical_test_json(list(docker_live)),
        ).hexdigest()
        attestation = self.warden.NonParsingAttestation(
            mount_table=b"private mount table\n",
            mount_table_sha256="7" * 64,
            source_manifest_sha256=hashlib.sha256(source_manifest).hexdigest(),
            command_manifest_sha256=hashlib.sha256(command_manifest).hexdigest(),
            fixture_state_sha256=fixture_digest,
            host_sentinels_sha256="9" * 64,
            infra_runtime_sha256=infra_digest,
            native_authority_sha256=native_authority_digest,
            docker_authority_sha256=docker_authority_digest,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            root.chmod(0o700)
            for name, payload in payloads.items():
                leaf = root / name
                leaf.write_bytes(payload)
                leaf.chmod(0o600)
            with (
                root_owned_metadata_view(self.warden),
                mock.patch.object(
                    self.warden,
                    "_validate_private_fixture_state",
                    return_value=fixture_digest,
                ),
                mock.patch.object(
                    self.warden,
                    "_validate_infra_runtime_upper",
                    return_value=(infra_digest, independent_infra_runtime_records()),
                ),
                mock.patch.object(
                    self.warden,
                    "_live_final_authority_records",
                    return_value=(native_live, docker_live),
                ),
                mock.patch.object(
                    self.warden, "_validate_teardown_snapshot", return_value=None,
                ),
            ):
                frozen = self.warden.freeze_private_evidence(root)
                try:
                    return self.warden.verify_frozen_private_evidence(
                        frozen,
                        expected_tree_id=tree_id,
                        source_manifest_bytes=source_manifest,
                        command_manifest_bytes=command_manifest,
                        attestation=attestation,
                        infra_upper_descriptor=-1,
                    ), attestation
                finally:
                    frozen.close()

    def test_independent_complete_raw_evidence_recomputes_reachability_receipt(self):
        tree_id = "1" * 40
        source_manifest = canonical_test_json({
            "entries": [], "schema_version": 1, "tree_id": tree_id,
        })
        command_manifest = canonical_test_json({
            "entries": [],
            "leaf_names": sorted(ROOT_COMMAND_LEAF_NAMES),
            "schema_version": 1,
        })
        payloads = independent_private_evidence_payloads(
            tree_id, source_manifest, command_manifest,
        )
        self.assertEqual(134, len(payloads))
        self.assertEqual(
            set(payloads), set(self.warden.REQUIRED_PRIVATE_EVIDENCE_NAMES),
        )
        verified, attestation = self._verify_independent_payloads(
            payloads,
            tree_id=tree_id,
            source_manifest=source_manifest,
            command_manifest=command_manifest,
        )
        receipt = json.loads(self.warden.build_final_receipt(
            verified, attestation, descendant_count=0,
        ))
        self.assertEqual("PASS", receipt["result"])
        self.assertEqual({"200": 3, "503": 10}, receipt["cgi_status_counts"])
        self.assertEqual(4, receipt["reset_warning_count"])
        self.assertEqual(8, receipt["cleanup_decisions"])
        self.assertEqual(
            independent_recovery_decisions(), receipt["recovery_decision_matrix"],
        )
        self.assertEqual("attest-valid", receipt["pre_teardown_attest"])
        self.assertEqual("attest-valid", receipt["final_postflight_attest"])
        self.assertEqual(list(ROOT_WORKFLOW_PHASES), receipt["workflow_phases"])
        self.assertEqual(20, receipt["operation_count"])
        self.assertEqual(0, receipt["teardown_apt_mutations"])
        self.assertEqual(9, receipt["forbidden_command_count"])
        self.assertEqual(0, receipt["unexpected_command_count"])

    def test_authority_snapshot_matrix_rejects_every_tree_and_transition_forgery(self):
        def documents(raw):
            return [json.loads(line) for line in raw.splitlines()]

        def encoded(rows):
            return b"".join(canonical_test_json(row) for row in rows)

        def changed_value(value):
            if isinstance(value, int):
                return value + 1
            if value == "file":
                return "directory"
            return value + "-forged"

        def reject(raw, *, label, root, stage_states, equal_stage_groups=(), change):
            rows = documents(raw)
            change(rows)
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden._validate_authority_observations(
                    encoded(rows), label=label, root=root,
                    stage_states=stage_states,
                    equal_stage_groups=equal_stage_groups,
                )

        bad_payloads = independent_bad_authority_payloads()
        for index, (target, bad_payload) in enumerate(bad_payloads):
            records = independent_authority_records(
                status_payload=(bad_payload if target == "status.lock" else b""),
                factory_payload=(
                    bad_payload
                    if target == "monitor-auth/factory-status.json"
                    else independent_valid_authority_payloads()[1]
                ),
                generation=index,
            )
            raw = independent_authority_observations(*(
                (stage, records)
                for stage in ("pre-health", "post-health", "post-cgi")
            ))
            parameters = {
                "root": "/var/lib/http-ztp-monitor-auth",
                "stage_states": tuple(
                    (stage, f"bad:{index}")
                    for stage in ("pre-health", "post-health", "post-cgi")
                ),
                "equal_stage_groups": ((
                    "pre-health", "post-health", "post-cgi",
                ),),
            }
            target_path = "/var/lib/http-ztp-monitor-auth/" + target
            sibling_path = (
                "/var/lib/http-ztp-monitor-auth/monitor-auth/factory-status.json"
                if target == "status.lock"
                else "/var/lib/http-ztp-monitor-auth/status.lock"
            )
            for kind, path in (("target", target_path), ("sibling", sibling_path)):
                def corrupt(rows, *, selected=path):
                    for row in rows:
                        record = next(
                            item for item in row["records"]
                            if item["path"] == selected
                        )
                        record["sha256"] = "0" * 64
                reject(
                    raw, label=f"bad-{index} {kind} payload", change=corrupt,
                    **parameters,
                )

        bad_records = independent_authority_records(
            status_payload=bad_payloads[0][1], generation=0,
        )
        bad_zero = independent_authority_observations(*(
            (stage, bad_records)
            for stage in ("pre-health", "post-health", "post-cgi")
        ))
        bad_parameters = {
            "root": "/var/lib/http-ztp-monitor-auth",
            "stage_states": tuple(
                (stage, "bad:0")
                for stage in ("pre-health", "post-health", "post-cgi")
            ),
            "equal_stage_groups": (("pre-health", "post-health", "post-cgi"),),
        }

        def remove_valid_sibling(rows):
            for row in rows:
                row["records"] = [
                    record for record in row["records"]
                    if not record["path"].endswith("/factory-status.json")
                ]

        reject(
            bad_zero, label="initial bad case lacks valid sibling",
            change=remove_valid_sibling, **bad_parameters,
        )
        for field in bad_records[-1]:
            def change_field(rows, *, selected=field):
                record = next(
                    item for item in rows[1]["records"]
                    if item["path"].endswith("/status.lock")
                )
                record[selected] = changed_value(record[selected])
            reject(
                bad_zero, label=f"read-only transition field {field}",
                change=change_field, **bad_parameters,
            )

        for mode_index, mode in enumerate(("stop-fail", "show-fail", "stay-active")):
            records = independent_authority_records(
                status_payload=bad_payloads[0][1], generation=50 + mode_index,
            )
            raw = independent_authority_observations(
                ("pre-recovery", records), ("post-recovery", records),
            )
            parameters = {
                "root": "/var/lib/http-ztp-monitor-auth",
                "stage_states": (("pre-recovery", "bad:0"),
                                 ("post-recovery", "bad:0")),
                "equal_stage_groups": (("pre-recovery", "post-recovery"),),
            }
            for kind, field in (
                ("delete-recreate inode", "inode"),
                ("content", "sha256"),
                ("metadata", "mtime_ns"),
            ):
                def mutate_stop(rows, *, selected=field):
                    record = next(
                        item for item in rows[1]["records"]
                        if item["path"].endswith("/status.lock")
                    )
                    record[selected] = changed_value(record[selected])
                reject(
                    raw, label=f"{mode} {kind}", change=mutate_stop,
                    **parameters,
                )

            def add_sibling(rows):
                for row in rows:
                    sibling = dict(row["records"][-1])
                    sibling["path"] = (
                        "/var/lib/http-ztp-monitor-auth/unexpected-sibling"
                    )
                    sibling["inode"] += 5000
                    row["records"].append(sibling)
                    row["records"].sort(key=lambda record: record["path"])

            reject(
                raw, label=f"{mode} self-consistent sibling", change=add_sibling,
                **parameters,
            )

        for index, state in enumerate(("active", "inactive", "failed")):
            before = independent_authority_records(
                status_payload=bad_payloads[0][1], generation=20 + index,
            )
            after = independent_authority_records(generation=30 + index)
            raw = independent_authority_observations(
                ("pre-recovery", before), ("post-recovery", after),
                ("post-attest", after), ("post-cgi", after),
            )
            parameters = {
                "root": "/var/lib/http-ztp-monitor-auth",
                "stage_states": (("pre-recovery", "bad:0"),
                                 ("post-recovery", "valid"),
                                 ("post-attest", "valid"),
                                 ("post-cgi", "valid")),
                "equal_stage_groups": ((
                    "post-recovery", "post-attest", "post-cgi",
                ),),
            }

            def wrong_precondition(rows):
                record = next(
                    item for item in rows[0]["records"]
                    if item["path"].endswith("/status.lock")
                )
                record["sha256"] = hashlib.sha256(bad_payloads[1][1]).hexdigest()
                record["size"] = len(bad_payloads[1][1])

            reject(
                raw, label=f"native-{state} precondition is not bad-0",
                change=wrong_precondition, **parameters,
            )

            def change_post_attest(rows):
                rows[2]["records"][0]["ctime_ns"] += 1

            reject(
                raw, label=f"native-{state} post-attest tree changed",
                change=change_post_attest, **parameters,
            )

        for phase_index, phase in enumerate((
            "recovery-in-progress", "recovery-committed-cleanup-pending",
        )):
            marked = independent_authority_records(
                marker_phase=phase, generation=10 + phase_index,
            )
            valid = independent_authority_records(generation=12 + phase_index)
            raw = independent_authority_observations(
                ("pre-classification", marked),
                ("post-classification", marked),
                ("post-recovery", valid), ("post-attest", valid),
            )
            parameters = {
                "root": "/var/lib/http-ztp-monitor-auth",
                "stage_states": (("pre-classification", f"marker:{phase}"),
                                 ("post-classification", f"marker:{phase}"),
                                 ("post-recovery", "valid"),
                                 ("post-attest", "valid")),
                "equal_stage_groups": (("pre-classification", "post-classification"),
                                       ("post-recovery", "post-attest")),
            }

            def omit_marker(rows):
                for row in rows[:2]:
                    row["records"] = [
                        record for record in row["records"]
                        if ".factory-status." not in record["path"]
                    ]

            reject(
                raw, label=f"marker {phase} omitted", change=omit_marker,
                **parameters,
            )

            def marker_read_mutated(rows):
                rows[1]["records"][0]["mtime_ns"] += 1

            reject(
                raw, label=f"marker {phase} classification mutated tree",
                change=marker_read_mutated, **parameters,
            )

            def marker_survived(rows):
                rows[2]["records"] = list(rows[0]["records"])
                rows[3]["records"] = list(rows[0]["records"])

            reject(
                raw, label=f"marker {phase} survived recovery",
                change=marker_survived, **parameters,
            )

        container_root = "/var/lib/http-ztp-container/monitor-auth"
        docker_raw = independent_authority_observations(
            ("pre-recovery", independent_authority_records(
                root=container_root, status_payload=bad_payloads[0][1],
                generation=40,
            )),
            ("post-recovery", independent_authority_records(
                root=container_root, generation=41,
            )),
        )
        for label, row_index, payload in (
            ("Docker container precondition valid", 0, b""),
            ("Docker container postcondition malformed", 1, bad_payloads[0][1]),
        ):
            def mutate_docker(rows, *, selected=row_index, value=payload):
                record = next(
                    item for item in rows[selected]["records"]
                    if item["path"].endswith("/status.lock")
                )
                record["size"] = len(value)
                record["sha256"] = hashlib.sha256(value).hexdigest()
            reject(
                docker_raw, label=label, change=mutate_docker,
                root=container_root,
                stage_states=(("pre-recovery", "bad:0"),
                              ("post-recovery", "valid")),
            )

        native = independent_authority_records(generation=32)
        docker_native_raw = independent_authority_observations(
            ("pre-recovery", native), ("post-recovery", native),
        )

        def mutate_native_separation(rows):
            rows[1]["records"][0]["inode"] += 1

        reject(
            docker_native_raw, label="Docker recovery mutated Native authority",
            root="/var/lib/http-ztp-monitor-auth",
            stage_states=(("pre-recovery", "valid"),
                          ("post-recovery", "valid")),
            equal_stage_groups=(("pre-recovery", "post-recovery"),),
            change=mutate_native_separation,
        )

    def test_final_authority_timelines_reject_disconnected_snapshot_islands(self):
        tree_id = "1" * 40
        source_manifest = canonical_test_json({
            "entries": [], "schema_version": 1, "tree_id": tree_id,
        })
        command_manifest = canonical_test_json({
            "entries": [],
            "leaf_names": sorted(ROOT_COMMAND_LEAF_NAMES),
            "schema_version": 1,
        })
        baseline = independent_private_evidence_payloads(
            tree_id, source_manifest, command_manifest,
        )

        def drift_jsonl(payloads, name, stages, delta):
            rows = [json.loads(line) for line in payloads[name].splitlines()]
            for row in rows:
                if row["stage"] not in stages:
                    continue
                for record in row["records"]:
                    for field in ("inode", "mtime_ns", "ctime_ns"):
                        record[field] += delta
            payloads[name] = b"".join(canonical_test_json(row) for row in rows)

        def drift_teardown(payloads, delta):
            for name in ("teardown-before.json", "teardown-after.json"):
                document = json.loads(payloads[name])
                for record in document["records"]:
                    if record["path"].startswith(
                        "/var/lib/http-ztp-monitor-auth"
                    ):
                        for field in ("inode", "mtime_ns", "ctime_ns"):
                            record[field] += delta
                payloads[name] = canonical_test_json(document)

        def mutated(*islands):
            payloads = dict(baseline)
            for island in islands:
                if island == "native-final":
                    drift_jsonl(
                        payloads, "authority-native-failed.jsonl",
                        {"post-recovery", "post-attest", "post-cgi"}, 30_000,
                    )
                elif island == "docker-native":
                    drift_jsonl(
                        payloads, "authority-docker-native.jsonl",
                        {"pre-recovery", "post-recovery"}, 10_000,
                    )
                elif island == "teardown":
                    drift_teardown(payloads, 40_000)
                elif island == "postflight":
                    drift_jsonl(
                        payloads, "authority-postflight.jsonl",
                        {"pre-attest", "post-attest"}, 20_000,
                    )
                elif island == "docker-final":
                    drift_jsonl(
                        payloads, "authority-docker-container.jsonl",
                        {"post-recovery"}, 77_777,
                    )
                else:
                    self.fail(f"unknown continuity island: {island}")
            payloads["operation-results.jsonl"] = independent_operation_results(
                payloads,
            )
            return payloads

        for islands in (
            ("native-final",),
            ("docker-native",),
            ("teardown",),
            ("postflight",),
            ("docker-final",),
            ("native-final", "docker-native", "teardown", "postflight"),
        ):
            with self.subTest(islands=islands), self.assertRaises(
                self.warden.WardenError,
            ):
                self._verify_independent_payloads(
                    mutated(*islands),
                    tree_id=tree_id,
                    source_manifest=source_manifest,
                    command_manifest=command_manifest,
                )

        # The explicit recoveries themselves are legitimate write boundaries.
        native_rows = [
            json.loads(line)
            for line in baseline["authority-native-failed.jsonl"].splitlines()
        ]
        docker_rows = [
            json.loads(line)
            for line in baseline["authority-docker-container.jsonl"].splitlines()
        ]
        self.assertNotEqual(native_rows[0]["records"], native_rows[1]["records"])
        self.assertNotEqual(docker_rows[0]["records"], docker_rows[1]["records"])

        native_live = [
            dict(record) for record in independent_authority_records(generation=32)
        ]
        native_live[0]["inode"] += 1
        docker_live = [
            dict(record) for record in independent_authority_records(
                root="/var/lib/http-ztp-container/monitor-auth", generation=41,
            )
        ]
        docker_lock = next(
            record for record in docker_live
            if record["path"].endswith("/status.lock")
        )
        docker_lock["sha256"] = hashlib.sha256(b"forged").hexdigest()
        docker_lock["size"] = len(b"forged")
        docker_missing_path = tuple(
            record for record in independent_authority_records(
                root="/var/lib/http-ztp-container/monitor-auth", generation=41,
            )
            if not record["path"].endswith("/factory-status.json")
        )
        for label, overrides in (
            ("live Native inode", {"live_native": tuple(native_live)}),
            ("live Docker content", {"live_docker": tuple(docker_live)}),
            ("live Docker path set", {"live_docker": docker_missing_path}),
            (
                "combined live anchors",
                {"live_native": tuple(native_live), "live_docker": tuple(docker_live)},
            ),
        ):
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self._verify_independent_payloads(
                    baseline,
                    tree_id=tree_id,
                    source_manifest=source_manifest,
                    command_manifest=command_manifest,
                    **overrides,
                )
        self._verify_independent_payloads(
            baseline,
            tree_id=tree_id,
            source_manifest=source_manifest,
            command_manifest=command_manifest,
        )

    def test_teardown_snapshot_rejects_each_field_and_complete_tree_drift(self):
        before = independent_teardown_snapshot()
        self.assertEqual(
            6,
            len(self.warden._parse_teardown_snapshot(before, "independent teardown")),
        )
        baseline = json.loads(before)
        file_index = next(
            index for index, record in enumerate(baseline["records"])
            if record["path"] == "/var/lib/http-ztp-monitor-auth/status.lock"
        )

        def changed(value):
            if isinstance(value, int):
                return value + 1
            if value == "file":
                return "directory"
            return value + "-forged"

        for field in baseline["records"][file_index]:
            after = json.loads(before)
            after["records"][file_index][field] = changed(
                after["records"][file_index][field]
            )
            with self.subTest(field=field), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden._validate_teardown_transition(
                    before, canonical_test_json(after),
                )

        for label, mutate in (
            ("delete-recreate", lambda rows: rows[file_index].update({
                "inode": rows[file_index]["inode"] + 100,
                "ctime_ns": rows[file_index]["ctime_ns"] + 100,
            })),
            ("Native child missing", lambda rows: rows.pop(file_index)),
            ("fixed file missing", lambda rows: rows.pop(0)),
            ("unexpected sibling", lambda rows: rows.append({
                **rows[file_index],
                "inode": rows[file_index]["inode"] + 1000,
                "path": "/var/lib/http-ztp-monitor-auth/unexpected-sibling",
            })),
        ):
            after = json.loads(before)
            mutate(after["records"])
            after["records"].sort(key=lambda record: record["path"])
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden._validate_teardown_transition(
                    before, canonical_test_json(after),
                )

    def test_recovery_decision_rows_bind_inputs_and_diagnostics_to_ordered_tokens(self):
        baseline = independent_recovery_decisions()
        raw = canonical_test_json(baseline)
        observed = self.warden._validate_recovery_decision_matrix(raw)
        self.assertEqual(8, len(observed))
        mutations = {}
        swapped_tokens = json.loads(raw)
        swapped_tokens[0]["token"], swapped_tokens[1]["token"] = (
            swapped_tokens[1]["token"], swapped_tokens[0]["token"]
        )
        mutations["token swap"] = swapped_tokens
        reordered = json.loads(raw)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        mutations["row reorder"] = reordered
        duplicated = json.loads(raw)
        duplicated[1] = dict(duplicated[0])
        mutations["row duplicate"] = duplicated
        extra = json.loads(raw)
        extra.append(dict(extra[-1]))
        mutations["extra row"] = extra
        wrong_digest = json.loads(raw)
        wrong_digest[2]["diagnostics_sha256"] = "0" * 64
        mutations["diagnostics digest"] = wrong_digest
        wrong_size = json.loads(raw)
        wrong_size[3]["diagnostics_size"] += 1
        mutations["diagnostics size"] = wrong_size
        wrong_input = json.loads(raw)
        wrong_input[4]["restart_allowed"] = True
        mutations["input tuple"] = wrong_input
        for label, document in mutations.items():
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden._validate_recovery_decision_matrix(
                    canonical_test_json(document)
                )

    def test_final_and_pre_teardown_attest_raw_evidence_is_exact(self):
        tree_id = "1" * 40
        source_manifest = canonical_test_json({
            "entries": [], "schema_version": 1, "tree_id": tree_id,
        })
        command_manifest = canonical_test_json({
            "entries": [],
            "leaf_names": sorted(ROOT_COMMAND_LEAF_NAMES),
            "schema_version": 1,
        })
        baseline = independent_private_evidence_payloads(
            tree_id, source_manifest, command_manifest,
        )
        mutations = {}
        for prefix in ("pre-teardown-attest", "postflight-attest"):
            wrong_out = dict(baseline)
            wrong_out[f"{prefix}.out"] = b"recovery-in-progress"
            mutations[f"{prefix} stdout"] = wrong_out
            wrong_err = dict(baseline)
            wrong_err[f"{prefix}.err"] = b"forged\n"
            mutations[f"{prefix} stderr"] = wrong_err
            wrong_rc = dict(baseline)
            invocation = json.loads(wrong_rc[f"{prefix}.invocation.json"])
            invocation["returncode"] = 1
            wrong_rc[f"{prefix}.invocation.json"] = canonical_test_json(invocation)
            mutations[f"{prefix} return code"] = wrong_rc
            wrong_argv = dict(baseline)
            invocation = json.loads(wrong_argv[f"{prefix}.invocation.json"])
            invocation["argv"].append("extra")
            wrong_argv[f"{prefix}.invocation.json"] = canonical_test_json(invocation)
            mutations[f"{prefix} argv"] = wrong_argv
        changed_tree = dict(baseline)
        rows = [
            json.loads(line)
            for line in changed_tree["authority-postflight.jsonl"].splitlines()
        ]
        rows[1]["records"][0]["ctime_ns"] += 1
        changed_tree["authority-postflight.jsonl"] = b"".join(
            canonical_test_json(row) for row in rows
        )
        mutations["postflight tree changed while attesting"] = changed_tree
        for label, payloads in mutations.items():
            payloads["operation-results.jsonl"] = independent_operation_results(
                payloads,
            )
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self._verify_independent_payloads(
                    payloads,
                    tree_id=tree_id,
                    source_manifest=source_manifest,
                    command_manifest=command_manifest,
                )

    def test_independent_raw_evidence_mutations_and_set_drift_fail_closed(self):
        tree_id = "1" * 40
        source_manifest = canonical_test_json({
            "entries": [], "schema_version": 1, "tree_id": tree_id,
        })
        command_manifest = canonical_test_json({
            "entries": [],
            "leaf_names": sorted(ROOT_COMMAND_LEAF_NAMES),
            "schema_version": 1,
        })
        baseline = independent_private_evidence_payloads(
            tree_id, source_manifest, command_manifest,
        )
        mutations = {}

        forged_cgi = dict(baseline)
        forged_cgi["cgi-bad-4.out"] = b"Status: 200 OK\n\nforged\n"
        mutations["bad CGI promoted"] = forged_cgi

        missing_decision = dict(baseline)
        missing_decision["recovery-decisions.json"] = canonical_test_json(
            sorted(ROOT_RECOVERY_DECISION_TOKENS[3:-1])
        )
        mutations["decision omitted"] = missing_decision

        fifth_warning = dict(baseline)
        fifth_warning["teardown.err"] = ROOT_RECOVERY_WARNING
        mutations["warning overcount"] = fifth_warning

        late_collision = dict(baseline)
        records = late_collision["command-events.jsonl"].splitlines(keepends=True)
        late_collision["command-events.jsonl"] = b"".join(records[1:])
        mutations["collision omitted"] = late_collision

        reversed_docker = dict(baseline)
        reversed_docker["events.log"] = (
            b"docker-stop-writer\n"
            b"docker-inspect-writer\n"
            b"docker-reinspect-writer\n"
            b"docker-remove-writer\n"
        )
        mutations["Docker phases reordered"] = reversed_docker

        forged_health = dict(baseline)
        forged_health["health-0.out"] = b"NOT-A-HEALTHCHECK\n"
        forged_health["operation-results.jsonl"] = independent_operation_results(
            forged_health,
        )
        mutations["health result forged"] = forged_health

        reused_payload = dict(baseline)
        reused_payload["bad-payload-1.bin"] = baseline["bad-payload-0.bin"]
        reused_payload["operation-results.jsonl"] = independent_operation_results(
            reused_payload,
        )
        mutations["bad payload case reused"] = reused_payload

        forged_cgi_body = dict(baseline)
        forged_cgi_body["cgi-bad-2.out"] = independent_cgi_response(
            "503 Service Unavailable", {"error": "forged"},
        )
        forged_cgi_body["operation-results.jsonl"] = independent_operation_results(
            forged_cgi_body,
        )
        mutations["CGI 503 body forged"] = forged_cgi_body

        duplicate_cgi_key = dict(baseline)
        duplicate_body = (
            b'{"error":"forged","error":'
            b'"control authentication state unavailable"}'
        )
        duplicate_cgi_key["cgi-bad-6.out"] = (
            b"Status: 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            b"Cache-Control: no-store\r\n"
            + f"Content-Length: {len(duplicate_body)}\r\n\r\n".encode("ascii")
            + duplicate_body
        )
        duplicate_cgi_key[
            "operation-results.jsonl"
        ] = independent_operation_results(duplicate_cgi_key)
        mutations["CGI duplicate JSON key"] = duplicate_cgi_key

        forged_cgi_length = dict(baseline)
        forged_cgi_length["cgi-bad-3.out"] = baseline[
            "cgi-bad-3.out"
        ].replace(b"Content-Length: 53", b"Content-Length: 52")
        forged_cgi_length[
            "operation-results.jsonl"
        ] = independent_operation_results(forged_cgi_length)
        mutations["CGI Content-Length forged"] = forged_cgi_length

        forged_cgi_invocation = dict(baseline)
        invocation = json.loads(
            forged_cgi_invocation["cgi-bad-5.invocation.json"]
        )
        invocation["returncode"] = 1
        forged_cgi_invocation["cgi-bad-5.invocation.json"] = canonical_test_json(
            invocation,
        )
        forged_cgi_invocation[
            "operation-results.jsonl"
        ] = independent_operation_results(forged_cgi_invocation)
        mutations["CGI invocation rc forged"] = forged_cgi_invocation

        forged_native = dict(baseline)
        forged_native["native-active.out"] = b"NOT-NATIVE-RECOVERY\n"
        forged_native["operation-results.jsonl"] = independent_operation_results(
            forged_native,
        )
        mutations["Native result forged"] = forged_native

        forged_marker_reset = dict(baseline)
        forged_marker_reset[
            "marker-reset-recovery-in-progress.out"
        ] = b"NOT-A-RECOVERY\n"
        forged_marker_reset[
            "operation-results.jsonl"
        ] = independent_operation_results(forged_marker_reset)
        mutations["marker reset forged"] = forged_marker_reset

        forged_marker_attest = dict(baseline)
        forged_marker_attest[
            "marker-after-recovery-in-progress.out"
        ] = b"recovery-in-progress"
        forged_marker_attest[
            "operation-results.jsonl"
        ] = independent_operation_results(forged_marker_attest)
        mutations["marker post-recovery attest forged"] = forged_marker_attest

        forged_teardown = dict(baseline)
        forged_teardown["teardown.out"] = b"NOT-A-TEARDOWN\n"
        forged_teardown["operation-results.jsonl"] = independent_operation_results(
            forged_teardown,
        )
        mutations["teardown result forged"] = forged_teardown

        extra_teardown_line = dict(baseline)
        extra_teardown_line["teardown.out"] = (
            b"FORGED EXTRA LINE\n" + ROOT_TEARDOWN_COMPLETE
        )
        extra_teardown_line[
            "operation-results.jsonl"
        ] = independent_operation_results(extra_teardown_line)
        mutations["teardown stdout extra line"] = extra_teardown_line

        relocated_warning = dict(baseline)
        relocated_warning["native-active.err"] = (
            ROOT_NATIVE_STOPPED_WARNING + ROOT_NATIVE_RECOVERY_COMPLETE
        )
        relocated_warning["teardown.err"] = ROOT_RECOVERY_WARNING
        relocated_warning[
            "operation-results.jsonl"
        ] = independent_operation_results(relocated_warning)
        mutations["warning provenance relocated"] = relocated_warning

        duplicated_warning = dict(baseline)
        duplicated_warning["docker-recover.out"] += ROOT_RECOVERY_WARNING
        duplicated_warning[
            "operation-results.jsonl"
        ] = independent_operation_results(duplicated_warning)
        mutations["warning duplicated to stdout"] = duplicated_warning

        relocated_audit_warning = dict(baseline)
        audit_records = [
            json.loads(line)
            for line in relocated_audit_warning[
                "infra-audit-map.jsonl"
            ].splitlines()
        ]
        audit_records[0]["reset_warning_count"] = 1
        audit_records[5]["reset_warning_count"] = 0
        relocated_audit_warning["infra-audit-map.jsonl"] = b"".join(
            canonical_test_json(record) for record in audit_records
        )
        mutations["FD3 warning relocated across operation logs"] = (
            relocated_audit_warning
        )

        extra_docker_line = dict(baseline)
        extra_docker_line["docker-recover.out"] += b"UNVERIFIED\n"
        extra_docker_line[
            "operation-results.jsonl"
        ] = independent_operation_results(extra_docker_line)
        mutations["Docker stdout extra line"] = extra_docker_line

        missing_native_start = dict(baseline)
        event_records = missing_native_start[
            "command-events.jsonl"
        ].splitlines(keepends=True)
        missing_native_start["command-events.jsonl"] = b"".join(
            line for line in event_records
            if not (
                json.loads(line).get("operation") == "native-active"
                and json.loads(line).get("argv") == ["start", "apache2"]
            )
        )
        mutations["Native active start trace omitted"] = missing_native_start

        forged_docker_pid = dict(baseline)
        event_records = forged_docker_pid[
            "command-events.jsonl"
        ].splitlines(keepends=True)
        for offset, line in enumerate(event_records):
            record = json.loads(line)
            if (
                record.get("operation") == "docker-writer"
                and record.get("argv") == ["container", "inspect", "a" * 64]
            ):
                record["observation"]["pid"] = 99
                event_records[offset] = canonical_test_json(record)
                break
        forged_docker_pid["command-events.jsonl"] = b"".join(event_records)
        mutations["Docker stopped PID forged"] = forged_docker_pid

        inactive_started = dict(baseline)
        event_records = inactive_started[
            "command-events.jsonl"
        ].splitlines(keepends=True)
        insert_at = next(
            offset
            for offset, line in enumerate(event_records)
            if json.loads(line).get("operation") == "native-failed"
        )
        inactive_start = {
            "argv": ["start", "apache2"],
            "command": "systemctl",
            "observation": {
                "mode": "normal",
                "state_after": "active",
                "state_before": "inactive",
            },
            "operation": "native-inactive",
            "result": "ALLOWED",
            "returncode": 0,
        }
        event_records.insert(insert_at, canonical_test_json(inactive_start))
        inactive_started["command-events.jsonl"] = b"".join(event_records)
        mutations["Native inactive added start"] = inactive_started

        changed_after = dict(baseline)
        after = json.loads(changed_after["teardown-after.json"])
        next(
            record for record in after["records"]
            if record["path"] == "/usr/local/lib/http-ztp/control-auth.py"
        )["inode"] += 1
        changed_after["teardown-after.json"] = canonical_test_json(after)
        changed_after["operation-results.jsonl"] = independent_operation_results(
            changed_after,
        )
        mutations["teardown after identity changed"] = changed_after

        teardown_apt_mutation = dict(baseline)
        teardown_events = teardown_apt_mutation[
            "command-events.jsonl"
        ].splitlines(keepends=True)
        teardown_events.append(canonical_test_json({
            "argv": ["update"],
            "command": "apt-get",
            "observation": {},
            "operation": "teardown",
            "result": "ALLOWED",
            "returncode": 0,
        }))
        teardown_apt_mutation["command-events.jsonl"] = b"".join(
            teardown_events
        )
        mutations["teardown apt mutation"] = teardown_apt_mutation

        omitted_operation = dict(baseline)
        omitted_operation["operation-results.jsonl"] = b"".join(
            baseline["operation-results.jsonl"].splitlines(keepends=True)[:-1]
        )
        mutations["operation record omitted"] = omitted_operation

        wrong_argv = dict(baseline)
        records = wrong_argv["operation-results.jsonl"].splitlines(keepends=True)
        first = json.loads(records[0])
        first["argv"] = ["python3", "infra/docker/healthcheck.py"]
        records[0] = canonical_test_json(first)
        wrong_argv["operation-results.jsonl"] = b"".join(records)
        mutations["operation argv changed"] = wrong_argv

        wrong_role = dict(baseline)
        records = wrong_role["operation-results.jsonl"].splitlines(keepends=True)
        first = json.loads(records[0])
        first["artifacts"][0]["role"] = "self-reported-success"
        records[0] = canonical_test_json(first)
        wrong_role["operation-results.jsonl"] = b"".join(records)
        mutations["operation artifact role changed"] = wrong_role

        wrong_size = dict(baseline)
        records = wrong_size["operation-results.jsonl"].splitlines(keepends=True)
        first = json.loads(records[0])
        first["artifacts"][0]["size"] += 1
        records[0] = canonical_test_json(first)
        wrong_size["operation-results.jsonl"] = b"".join(records)
        mutations["operation artifact size changed"] = wrong_size

        for label, payloads in mutations.items():
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self._verify_independent_payloads(
                    payloads,
                    tree_id=tree_id,
                    source_manifest=source_manifest,
                    command_manifest=command_manifest,
                )

        for label, change in (
            ("missing", lambda value: value.pop("health-9.out")),
            ("extra", lambda value: value.__setitem__("unexpected", b"x\n")),
        ):
            payloads = dict(baseline)
            change(payloads)
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "evidence"
                root.mkdir(mode=0o700)
                root.chmod(0o700)
                for name, payload in payloads.items():
                    leaf = root / name
                    leaf.write_bytes(payload)
                    leaf.chmod(0o600)
                with (
                    root_owned_metadata_view(self.warden),
                    self.assertRaises(self.warden.WardenError),
                ):
                    self.warden.freeze_private_evidence(root)

    def test_operation_result_jsonl_grammar_and_binding_matrix_is_exact(self):
        tree_id = "1" * 40
        source_manifest = canonical_test_json({
            "entries": [], "schema_version": 1, "tree_id": tree_id,
        })
        command_manifest = canonical_test_json({
            "entries": [],
            "leaf_names": sorted(ROOT_COMMAND_LEAF_NAMES),
            "schema_version": 1,
        })
        payloads = independent_private_evidence_payloads(
            tree_id, source_manifest, command_manifest,
        )
        raw = payloads["operation-results.jsonl"]
        base_lines = raw.splitlines(keepends=True)

        def changed_first(change):
            lines = list(base_lines)
            document = json.loads(lines[0])
            change(document)
            lines[0] = canonical_test_json(document)
            return b"".join(lines)

        first = json.loads(base_lines[0])
        malformed = {
            "duplicate top-level key": b"".join((
                base_lines[0].replace(
                    b'{"argv":', b'{"argv":[],"argv":', 1,
                ),
                *base_lines[1:],
            )),
            "duplicate nested key": b"".join((
                base_lines[0].replace(
                    b'"artifacts":[{"name":',
                    b'"artifacts":[{"name":"bad-payload-0.bin","name":',
                    1,
                ),
                *base_lines[1:],
            )),
            "raw Unicode": b"".join((
                base_lines[0].replace(b'"operation":"bad-0"', b'"operation":"bad-\xc3\xa9"'),
                *base_lines[1:],
            )),
            "CRLF framing": b"".join((
                base_lines[0][:-1] + b"\r\n", *base_lines[1:],
            )),
            "noncanonical whitespace": b"".join((
                base_lines[0].replace(b'{"argv":', b'{"argv": ', 1),
                *base_lines[1:],
            )),
            "duplicate record": b"".join((base_lines[0], *base_lines)),
            "out-of-order record": b"".join((
                base_lines[1], base_lines[0], *base_lines[2:],
            )),
        }

        object_mutations = {
            "extra top-level field": lambda value: value.__setitem__("result", "PASS"),
            "missing top-level field": lambda value: value.pop("operation"),
            "empty argv": lambda value: value.__setitem__("argv", []),
            "extra argv": lambda value: value["argv"].append("extra"),
            "whitespace argv": lambda value: value["argv"].__setitem__(0, " python3"),
            "reordered argv": lambda value: value.__setitem__(
                "argv", [value["argv"][1], value["argv"][0], *value["argv"][2:]],
            ),
            "wrong return code": lambda value: value.__setitem__("returncode", 0),
            "boolean return code": lambda value: value.__setitem__("returncode", True),
            "boolean index": lambda value: value.__setitem__("index", True),
            "wrong digest": lambda value: value["artifacts"][0].__setitem__(
                "sha256", "0" * 64,
            ),
            "boolean artifact size": lambda value: value["artifacts"][0].__setitem__(
                "size", True,
            ),
            "extra artifact field": lambda value: value["artifacts"][0].__setitem__(
                "result", "PASS",
            ),
            "missing artifact field": lambda value: value["artifacts"][0].pop("sha256"),
            "artifact path traversal": lambda value: value["artifacts"][0].__setitem__(
                "name", "../bad-payload-0.bin",
            ),
            "duplicate artifact role": lambda value: value["artifacts"][1].__setitem__(
                "role", value["artifacts"][0]["role"],
            ),
            "same artifact reused": lambda value: value["artifacts"][1].update(
                value["artifacts"][0]
            ),
        }
        malformed.update({
            label: changed_first(change)
            for label, change in object_mutations.items()
        })
        self.assertEqual(first, json.loads(base_lines[0]))
        for label, candidate in malformed.items():
            with self.subTest(label=label), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden._validate_operation_results(
                    candidate, payloads=payloads,
                )

    def test_native_fd3_audit_logs_bind_each_warning_to_one_operation(self):
        audit_records = independent_infra_audit_records()
        audit_map = b"".join(
            canonical_test_json(record) for record in audit_records
        )

        def build_root(temporary):
            root = Path(temporary) / "infra-upper"
            logs = root / "logs"
            logs.mkdir(parents=True, mode=0o700)
            root.chmod(0o700)
            logs.chmod(0o700)
            for record in audit_records:
                leaf = logs / record["log_name"]
                leaf.write_bytes(independent_infra_log_payload(record["operation"]))
                leaf.chmod(0o600)
            return root, logs

        def validate(root):
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with root_owned_metadata_view(self.warden):
                    digest, runtime_records = (
                        self.warden._validate_infra_runtime_upper(descriptor)
                    )
                self.assertRegex(digest, r"\A[0-9a-f]{64}\Z")
                return self.warden._validate_infra_audit_map(
                    audit_map, runtime_records=runtime_records,
                )
            finally:
                os.close(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            root, _logs = build_root(temporary)
            self.assertEqual(3, validate(root))

        mutations = {
            "Native warning missing": lambda _root, logs: (
                logs / audit_records[5]["log_name"]
            ).write_bytes(b"native warning omitted\n"),
            "Native warning duplicated": lambda _root, logs: (
                logs / audit_records[5]["log_name"]
            ).write_bytes(
                b"native warning duplicated\n"
                + ROOT_RECOVERY_WARNING + ROOT_RECOVERY_WARNING
            ),
            "warning relocated to marker": lambda _root, logs: (
                (logs / audit_records[5]["log_name"]).write_bytes(
                    b"native warning omitted\n"
                ),
                (logs / audit_records[0]["log_name"]).write_bytes(
                    b"marker warning forged\n" + ROOT_RECOVERY_WARNING
                ),
            ),
            "log missing": lambda _root, logs: (
                logs / audit_records[2]["log_name"]
            ).unlink(),
            "log extra": lambda _root, logs: (
                (logs / "infra-setup-20260101_000000-999.log").write_bytes(
                    b"extra\n"
                )
            ),
            "log writable mode": lambda _root, logs: (
                logs / audit_records[2]["log_name"]
            ).chmod(0o666),
            "log oversized": lambda _root, logs: (
                logs / audit_records[2]["log_name"]
            ).write_bytes(b"x" * (1024 * 1024 + 1)),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root, logs = build_root(temporary)
                mutate(root, logs)
                with self.assertRaises(self.warden.WardenError):
                    validate(root)

        with self.subTest(label="log symlink"), tempfile.TemporaryDirectory() as temporary:
            root, logs = build_root(temporary)
            leaf = logs / audit_records[2]["log_name"]
            leaf.unlink()
            leaf.symlink_to(logs / audit_records[3]["log_name"])
            with self.assertRaises(self.warden.WardenError):
                validate(root)

        with self.subTest(label="log hardlink"), tempfile.TemporaryDirectory() as temporary:
            root, logs = build_root(temporary)
            os.link(
                logs / audit_records[2]["log_name"],
                logs / "infra-setup-20260101_000000-998.log",
            )
            with self.assertRaises(self.warden.WardenError):
                validate(root)

    def test_close_all_child_fd_inventory_is_exact(self):
        self.warden.validate_supervisor_fd_inventory({0, 1, 2})
        for leaked in (3, 9, 20, 31, 99):
            with self.subTest(leaked=leaked), self.assertRaises(
                self.warden.WardenError
            ):
                self.warden.validate_supervisor_fd_inventory({0, 1, 2, leaked})

    def test_supervisor_binary_capture_limits_while_reading_and_has_deadline(self):
        success = subprocess.Popen(
            [sys.executable, "-c", "import os;os.write(1,b'x\\x00y');os.write(2,b'z\\n')"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = self.warden._read_supervisor_streams(
            success, deadline_seconds=10.0, byte_limit=8,
        )
        self.assertEqual(b"x\x00y", stdout)
        self.assertEqual(b"z\n", stderr)

        oversized = subprocess.Popen(
            [sys.executable, "-c", "import os;os.write(1,b'x'*65)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            with self.assertRaisesRegex(
                self.warden.WardenError, "stdout exceeded its byte limit",
            ):
                self.warden._read_supervisor_streams(
                    oversized, deadline_seconds=10.0, byte_limit=64,
                )
        finally:
            oversized.wait(timeout=2)
        self.assertTrue(oversized.stdout.closed)
        self.assertTrue(oversized.stderr.closed)
        self.assertIsNotNone(oversized.poll())

        stalled = subprocess.Popen(
            [sys.executable, "-c", "import time;time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            with self.assertRaisesRegex(
                self.warden.WardenError, "fixed deadline",
            ):
                self.warden._read_supervisor_streams(
                    stalled, deadline_seconds=0.05, byte_limit=64,
                )
        finally:
            stalled.wait(timeout=2)
        self.assertTrue(stalled.stdout.closed)
        self.assertTrue(stalled.stderr.closed)
        self.assertIsNotNone(stalled.poll())

    def test_exact_command_argv_contract_rejects_every_collision(self):
        valid = {
            "docker": ("context", "show"),
            "systemctl": ("stop", "apache2"),
            "dpkg": ("-s", "apache2"),
            "supervisord": ("-n", "-c", "/etc/supervisor/supervisord.conf"),
            "supervisorctl": ("status",),
            "ss": ("-ltnp",),
            "apache2ctl": ("configtest",),
        }
        for command, argv in valid.items():
            with self.subTest(command=command):
                self.warden.validate_command_argv(command, argv)
        collisions = (
            ("docker", ("context show",)),
            ("docker", ("context", "show", "")),
            ("systemctl", ("stop apache2",)),
            ("systemctl", ("stop", " apache2")),
            ("dpkg", ("-s", "apache2", "extra")),
            ("dpkg-query", ()),
            ("supervisord", ()),
            ("supervisord", ("-n -c /etc/supervisor/supervisord.conf",)),
            ("supervisorctl", ("status", "extra")),
            ("ss", ("-ltnp", "")),
            ("apache2ctl", ("config", "test")),
        )
        for command, argv in collisions:
            with self.subTest(command=command, argv=argv), self.assertRaises(
                self.warden.ForbiddenCommand
            ) as raised:
                self.warden.validate_command_argv(command, argv)
            self.assertEqual(99, raised.exception.returncode)
            self.assertEqual("FORBIDDEN", str(raised.exception))

    def test_mount_table_requires_complete_declared_read_only_or_private_set(self):
        safe = (
            self.warden.MountRecord("/", "tmpfs", frozenset({"ro"}), "private"),
            self.warden.MountRecord("/proc", "proc", frozenset({"rw"}), "private"),
            self.warden.MountRecord("/fixture", "tmpfs", frozenset({"rw"}), "private"),
            self.warden.MountRecord("/commands/python3", "ext4", frozenset({"ro"}), "private"),
            self.warden.MountRecord("/sys", "sysfs", frozenset({"ro"}), "private"),
        )
        self.warden.validate_mount_records(
            safe,
            writable_paths={"/proc", "/fixture"},
            readonly_paths={"/", "/commands/python3", "/sys"},
        )
        hostile = (
            safe + (self.warden.MountRecord(
                "/fixture/nested", "tmpfs", frozenset({"rw"}), "private",
            ),),
            safe[:-1] + (self.warden.MountRecord(
                "/sys", "sysfs", frozenset({"rw"}), "private",
            ),),
            safe[:-1] + (self.warden.MountRecord(
                "/sys/fs/cgroup", "cgroup2", frozenset({"ro"}), "private",
            ),),
            safe[:-1] + (self.warden.MountRecord(
                "/dev/sda", "devtmpfs", frozenset({"ro"}), "private",
            ),),
        )
        for records in hostile:
            with self.subTest(records=records), self.assertRaises(
                self.warden.WardenError
            ):
                self.warden.validate_mount_records(
                    records,
                    writable_paths={"/proc", "/fixture"},
                    readonly_paths={"/", "/commands/python3", "/sys"},
                )

    def test_private_root_base_is_readonly_before_pivot_and_child_execution(self):
        prepare = inspect.getsource(self.warden._prepare_private_root)
        pivot = inspect.getsource(self.warden.pivot_into_private_root)
        execution = inspect.getsource(self.warden.execute_warden)
        self.assertIn("_remount_private_root_readonly", prepare)
        self.assertIn('readonly.add("/")', prepare)
        self.assertNotIn('writable = {"/"}', prepare)
        self.assertNotIn("old_root.mkdir", pivot)
        self.assertNotIn("os.rmdir", pivot)
        self.assertLess(
            execution.index("_prepare_private_root"),
            execution.index("pivot_into_private_root"),
        )

    def test_final_receipt_is_built_only_from_independent_verified_facts(self):
        tree_id = "1" * 40
        source_digest = "2" * 64
        command_digest = "3" * 64
        native_authority_digest = "a" * 64
        docker_authority_digest = "b" * 64
        bad_facts = tuple(
            (target, hashlib.sha256(payload).hexdigest())
            for target, payload in independent_bad_authority_payloads()
        )
        facts = self.warden.VerifiedWorkflowFacts(
            command_leaf_names=tuple(sorted(ROOT_COMMAND_LEAF_NAMES)),
            workflow_phases=ROOT_WORKFLOW_PHASES,
            recovery_decision_tokens=ROOT_RECOVERY_DECISION_TOKENS,
            recovery_decision_matrix=independent_recovery_decision_facts(),
            entrypoint_counts=(
                (("./infra/infra-setup.sh", "--recover-monitor-authority"), 8),
                (("./infra/docker/deploy.sh", "recover-monitor-authority"), 1),
                (("./infra/infra-teardown.sh", "--non-interactive", "--yes"), 1),
            ),
            malformed_payloads=bad_facts,
            cgi_status_counts=(("200", 3), ("503", len(bad_facts))),
            marker_phases=(
                "recovery-in-progress", "recovery-committed-cleanup-pending",
            ),
            native_initial_states=("active", "inactive", "failed"),
            native_stop_failures=("stop-fail", "show-fail", "stay-active"),
            warning_sources=(
                "docker-recover.err", "native-active.err", "native-failed.err",
                "native-inactive.err",
            ),
            native_audit_warning_count=3,
            post_attested_operations=(
                "marker-recovery-in-progress",
                "marker-recovery-committed-cleanup-pending",
                "native-active", "native-inactive", "native-failed",
            ),
            docker_quiesce_trace=(
                "docker-inspect-writer", "docker-stop-writer",
                "docker-reinspect-writer", "docker-remove-writer",
            ),
            teardown_authority_paths=(
                "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
                "/usr/local/lib/http-ztp/control-auth.py",
                "/var/lib/http-ztp-monitor-auth",
                "/var/lib/http-ztp-monitor-auth/monitor-auth",
                "/var/lib/http-ztp-monitor-auth/monitor-auth/factory-status.json",
                "/var/lib/http-ztp-monitor-auth/status.lock",
            ),
            apt_mutation_count=0,
            forbidden_command_count=len(ROOT_FORBIDDEN_COMMAND_ARGV),
            unexpected_command_count=0,
            operation_count=len(independent_operation_result_specs()),
            pre_teardown_attest="attest-valid",
            final_postflight_attest="attest-valid",
            native_authority_continuity_sha256=native_authority_digest,
            docker_authority_continuity_sha256=docker_authority_digest,
        )
        verified = self.warden.VerifiedPrivateEvidence(
            tree_id=tree_id,
            event_log_sha256="4" * 64,
            phase_log_sha256="5" * 64,
            source_manifest_sha256=source_digest,
            command_manifest_sha256=command_digest,
            private_evidence_sha256="6" * 64,
            workflow_facts=facts,
        )
        attested = self.warden.NonParsingAttestation(
            mount_table=b"private mount table\n",
            mount_table_sha256="7" * 64,
            source_manifest_sha256=source_digest,
            command_manifest_sha256=command_digest,
            fixture_state_sha256="8" * 64,
            host_sentinels_sha256="9" * 64,
            native_authority_sha256=native_authority_digest,
            docker_authority_sha256=docker_authority_digest,
        )
        sealed = self.warden.build_final_receipt(
            verified, attested, descendant_count=0,
        )
        document = json.loads(sealed)
        self.assertEqual({
            "cgi_status_counts": {"200": 3, "503": 10},
            "cleanup_decisions": 8,
            "command_leaf_names": list(ROOT_COMMAND_LEAF_NAMES),
            "command_manifest_sha256": "3" * 64,
            "descendants": "all-descendant-zero",
            "docker_quiesce_trace": [
                "docker-inspect-writer", "docker-stop-writer",
                "docker-reinspect-writer", "docker-remove-writer",
            ],
            "docker_authority_continuity_sha256": docker_authority_digest,
            "entrypoint_counts": [
                {
                    "argv": [
                        "./infra/infra-setup.sh",
                        "--recover-monitor-authority",
                    ],
                    "count": 8,
                },
                {
                    "argv": [
                        "./infra/docker/deploy.sh",
                        "recover-monitor-authority",
                    ],
                    "count": 1,
                },
                {
                    "argv": [
                        "./infra/infra-teardown.sh", "--non-interactive",
                        "--yes",
                    ],
                    "count": 1,
                },
            ],
            "entrypoints": [
                ["./infra/infra-setup.sh", "--recover-monitor-authority"],
                ["./infra/docker/deploy.sh", "recover-monitor-authority"],
                ["./infra/infra-teardown.sh", "--non-interactive", "--yes"],
            ],
            "event_log_sha256": "4" * 64,
            "fixture_state_sha256": "8" * 64,
            "forbidden_command_count": 9,
            "host_sentinels_sha256": "9" * 64,
            "infra_runtime_sha256": "0" * 64,
            "malformed_payload_consumers": 10,
            "mount_table_sha256": "7" * 64,
            "native_audit_warning_count": 3,
            "native_authority_continuity_sha256": native_authority_digest,
            "native_initial_states": ["active", "inactive", "failed"],
            "native_stop_failures": 3,
            "operation_count": 20,
            "phase_log_sha256": "5" * 64,
            "post_attested_operations": [
                "marker-recovery-in-progress",
                "marker-recovery-committed-cleanup-pending",
                "native-active", "native-inactive", "native-failed",
            ],
            "private_evidence_sha256": "6" * 64,
            "recovery_decision_matrix": independent_recovery_decisions(),
            "recovery_decision_tokens": list(ROOT_RECOVERY_DECISION_TOKENS),
            "recovery_marker_phases": 2,
            "reset_warning_count": 4,
            "reset_warning_sources": [
                "docker-recover.err", "native-active.err",
                "native-failed.err", "native-inactive.err",
            ],
            "result": "PASS",
            "schema_version": 1,
            "sealed_by": "namespace-pid1-warden",
            "source_manifest_sha256": "2" * 64,
            "teardown_apt_mutations": 0,
            "teardown_authority_paths": [
                "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
                "/usr/local/lib/http-ztp/control-auth.py",
                "/var/lib/http-ztp-monitor-auth",
                "/var/lib/http-ztp-monitor-auth/monitor-auth",
                "/var/lib/http-ztp-monitor-auth/monitor-auth/factory-status.json",
                "/var/lib/http-ztp-monitor-auth/status.lock",
            ],
            "tree_id": "1" * 40,
            "unexpected_command_count": 0,
            "pre_teardown_attest": "attest-valid",
            "final_postflight_attest": "attest-valid",
            "workflow_phases": list(ROOT_WORKFLOW_PHASES),
        }, document)
        with self.assertRaises(self.warden.WardenError):
            self.warden.build_final_receipt(
                verified, attested, descendant_count=1,
            )
        mismatched = self.warden.NonParsingAttestation(
            mount_table=b"private mount table\n",
            mount_table_sha256="7" * 64,
            source_manifest_sha256="a" * 64,
            command_manifest_sha256=command_digest,
            fixture_state_sha256="8" * 64,
            host_sentinels_sha256="9" * 64,
            native_authority_sha256=native_authority_digest,
            docker_authority_sha256=docker_authority_digest,
        )
        with self.assertRaises(self.warden.WardenError):
            self.warden.build_final_receipt(
                verified, mismatched, descendant_count=0,
            )
        for facts_field, attestation_field in (
            (
                "native_authority_continuity_sha256",
                "native_authority_sha256",
            ),
            (
                "docker_authority_continuity_sha256",
                "docker_authority_sha256",
            ),
        ):
            valid_but_different = "c" * 64
            drifted_facts = self.warden.VerifiedWorkflowFacts(
                **{**facts.__dict__, facts_field: valid_but_different}
            )
            drifted_verified = self.warden.VerifiedPrivateEvidence(
                **{**verified.__dict__, "workflow_facts": drifted_facts}
            )
            with self.subTest(facts_field=facts_field), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden.build_final_receipt(
                    drifted_verified, attested, descendant_count=0,
                )
            drifted_attestation = self.warden.NonParsingAttestation(
                **{
                    **attested.__dict__,
                    attestation_field: valid_but_different,
                }
            )
            with self.subTest(
                attestation_field=attestation_field,
            ), self.assertRaises(self.warden.WardenError):
                self.warden.build_final_receipt(
                    verified, drifted_attestation, descendant_count=0,
                )
        forged_facts = self.warden.VerifiedWorkflowFacts(
            **{
                **facts.__dict__,
                "warning_sources": ("teardown.err",) * 4,
            }
        )
        forged = self.warden.VerifiedPrivateEvidence(
            **{**verified.__dict__, "workflow_facts": forged_facts}
        )
        with self.assertRaises(self.warden.WardenError):
            self.warden.build_final_receipt(
                forged, attested, descendant_count=0,
            )
        for field in dataclasses.fields(self.warden.VerifiedWorkflowFacts):
            value = getattr(facts, field.name)
            if isinstance(value, int):
                changed = value + 1
            elif isinstance(value, str):
                changed = value + "-forged"
            else:
                self.assertIsInstance(value, tuple)
                changed = (*value, value[-1])
            drifted_facts = self.warden.VerifiedWorkflowFacts(
                **{**facts.__dict__, field.name: changed}
            )
            drifted = self.warden.VerifiedPrivateEvidence(
                **{**verified.__dict__, "workflow_facts": drifted_facts}
            )
            with self.subTest(field=field.name), self.assertRaises(
                self.warden.WardenError,
            ):
                self.warden.build_final_receipt(
                    drifted, attested, descendant_count=0,
                )

    def test_frozen_private_evidence_is_exact_and_final_publish_is_no_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            (root / "events.log").write_bytes(b"event\n")
            (root / "phases.jsonl").write_bytes(b"phase\n")
            for path in root.iterdir():
                path.chmod(0o600)
            required = frozenset({"events.log", "phases.jsonl"})
            with root_owned_metadata_view(self.warden):
                frozen = self.warden.freeze_private_evidence(
                    root, required_names=required,
                )
            self.addCleanup(frozen.close)
            receipt = b'{"result":"PASS","schema_version":1}\n'
            with root_owned_metadata_view(self.warden):
                self.assertEqual(
                    receipt,
                    self.warden.publish_private_final_receipt(frozen, receipt),
                )
            self.assertEqual(receipt, (root / "final-receipt.json").read_bytes())
            with (
                root_owned_metadata_view(self.warden),
                self.assertRaises(self.warden.WardenError),
            ):
                self.warden.publish_private_final_receipt(frozen, receipt)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            leaf = root / "events.log"
            leaf.write_bytes(b"before\n")
            leaf.chmod(0o600)
            with root_owned_metadata_view(self.warden):
                frozen = self.warden.freeze_private_evidence(
                    root, required_names=frozenset({"events.log"}),
                )
            self.addCleanup(frozen.close)
            leaf.write_bytes(b"after!\n")
            with (
                root_owned_metadata_view(self.warden),
                self.assertRaises(self.warden.WardenError),
            ):
                self.warden.publish_private_final_receipt(
                    frozen, b'{"result":"PASS","schema_version":1}\n',
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            (root / "events.log").write_bytes(b"event\n")
            (root / "extra").write_bytes(b"extra\n")
            for path in root.iterdir():
                path.chmod(0o600)
            with (
                root_owned_metadata_view(self.warden),
                self.assertRaises(self.warden.WardenError),
            ):
                self.warden.freeze_private_evidence(
                    root, required_names=frozenset({"events.log"}),
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            leaf = root / "events.log"
            leaf.write_bytes(b"event\n")
            leaf.chmod(0o600)
            with (
                owned_metadata_view(self.warden, 123, 456),
                self.assertRaises(self.warden.WardenError),
            ):
                self.warden.freeze_private_evidence(
                    root, required_names=frozenset({"events.log"}),
                )

    def test_post_host_close_inventory_allows_only_private_and_append_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            host_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
            output_path = root / "external-receipt"
            output_fd = os.open(
                output_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600,
            )
            readonly_fd = os.open(output_path, os.O_RDONLY)
            self.addCleanup(os.close, readonly_fd)
            self.addCleanup(os.close, output_fd)
            self.addCleanup(os.close, host_fd)
            self.addCleanup(os.close, private_fd)
            expected = {0, 1, 2, private_fd, output_fd}
            with root_owned_metadata_view(self.warden):
                self.warden.validate_post_host_close_fd_inventory(
                    expected,
                    private_descriptors={private_fd},
                    external_write_descriptors={output_fd},
                )
                with self.assertRaises(self.warden.WardenError):
                    self.warden.validate_post_host_close_fd_inventory(
                        expected | {host_fd},
                        private_descriptors={private_fd},
                        external_write_descriptors={output_fd},
                    )
                with self.assertRaises(self.warden.WardenError):
                    self.warden.validate_post_host_close_fd_inventory(
                        {0, 1, 2, private_fd, readonly_fd},
                        private_descriptors={private_fd},
                        external_write_descriptors={readonly_fd},
                    )

    def test_three_a_removes_every_child_provisional_receipt_authority(self):
        source = WARDEN.read_text(encoding="utf-8")
        for forbidden in (
            "validate_provisional_receipt", "provisional-receipt.json",
            '"result": "PROVISIONAL"', "only a provisional receipt",
            "_persist_final_evidence",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_three_a_execution_order_closes_host_authority_before_parsing(self):
        source = inspect.getsource(self.warden.execute_warden)
        ordered = (
            "require_all_descendants_zero",
            "freeze_private_evidence",
            "verify_nonparsing_postflight",
            "close_host_authority",
            "validate_post_host_close_fd_inventory",
            "verify_frozen_private_evidence",
            "build_final_receipt",
            "publish_private_final_receipt",
            "append_external_final_receipt",
            'os.write(1, b"root-entrypoint-workflow: PASS\\n")',
        )
        offsets = [source.index(item) for item in ordered]
        self.assertEqual(sorted(offsets), offsets)

    def test_three_a_nonparsing_stage_never_interprets_child_payloads(self):
        nonparsing = inspect.getsource(self.warden.verify_nonparsing_postflight)
        verifier = inspect.getsource(self.warden.verify_frozen_private_evidence)
        for parser in (
            "_validate_infra_runtime_upper",
            "_validate_private_fixture_state",
            "_validate_private_reachability_artifacts",
            "_load_canonical_json",
        ):
            with self.subTest(parser=parser):
                self.assertNotIn(parser, nonparsing)
        self.assertIn("_validate_infra_runtime_upper", verifier)
        self.assertIn("_validate_private_fixture_state", verifier)

    def test_external_receipt_refuses_a_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            target = alias / "evidence"
            with (
                root_owned_metadata_view(self.warden),
                self.assertRaises(self.warden.WardenError),
            ):
                descriptor = self.warden._prepare_external_final_receipt(target)
                os.close(descriptor)

    def test_external_append_never_substitutes_a_synthetic_fd_inventory(self):
        source = inspect.getsource(self.warden.append_external_final_receipt)
        self.assertNotIn("validate_post_host_close_fd_inventory", source)
        self.assertNotIn("{0, 1, 2, descriptor}", source)

    def test_linux_hostile_matrix_is_exact_and_fail_only(self):
        expected = set(ROOT_HOSTILE_CASES)
        self.assertEqual(expected, set(self.warden.HOSTILE_TEST_CASES))
        self.assertEqual(
            set(ROOT_COMMAND_LEAF_NAMES), set(self.warden.COMMAND_LEAF_NAMES),
        )
        scenario = inspect.getsource(
            MonitorAuthorityRootNamespaceScenario.test_real_root_entrypoint_workflow
        )
        self.assertIn("for hostile_case in ROOT_HOSTILE_CASES", scenario)
        self.assertIn("--test-only-hostile-case", inspect.getsource(
            MonitorAuthorityRootNamespaceScenario._invoke_root_warden
        ))
        self.assertIn("--kill-child=SIGKILL", inspect.getsource(
            MonitorAuthorityRootNamespaceScenario._invoke_root_warden
        ))
        tree_binding = inspect.getsource(
            MonitorAuthorityRootNamespaceScenario._workflow_bound_tree_id
        )
        self.assertRegex(
            tree_binding,
            r'\["/usr/bin/git",\s*"rev-parse"[\s\S]*?timeout=10',
        )
        execution = inspect.getsource(self.warden.execute_warden)
        for exact_leak in (
            "leaked = (9,)",
            "leaked = (held_repository.descriptor,)",
            "leaked = (sentinels[0].descriptor,)",
            "_spawn_only_supervisor(leaked)",
        ):
            with self.subTest(exact_leak=exact_leak):
                self.assertIn(exact_leak, execution)


class MonitorAuthorityRootNamespaceScenario(unittest.TestCase):
    def _invoke_root_warden(self, tree_id, slug, hostile_case=None):
        base = Path("/run/http-ztp-monitor-warden") / slug
        arguments = [
            "/usr/bin/unshare", "--mount", "--pid", "--fork", "--net",
            "--mount-proc", "--propagation", "private",
            "--kill-child=SIGKILL",
            "/usr/bin/python3", "-B", os.fspath(WARDEN),
            "--inside-private-namespace", "--tree-id", tree_id,
            "--source-root", os.fspath(ROOT),
            "--private-root", os.fspath(base / "root"),
            "--command-root", os.fspath(base / "commands"),
            "--evidence-dir", os.fspath(base / "evidence"),
        ]
        if hostile_case is not None:
            arguments.extend(("--test-only-hostile-case", hostile_case))
        result = subprocess.run(
            arguments,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            pass_fds=(9,),
            env={
                "HOME": "/root", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            },
            timeout=1200,
        )
        return result, base / "evidence/final-receipt.json"

    def _workflow_bound_tree_id(self):
        expected = os.environ.get("HTTP_ZTP_MONITOR_EXPECTED_TREE_ID", "")
        self.assertRegex(expected, r"^[0-9a-f]{40}$")
        observed = subprocess.run(
            ["/usr/bin/git", "rev-parse", "--verify", "HEAD^{tree}"],
            cwd=ROOT, text=True, capture_output=True, check=True,
            timeout=10,
        )
        self.assertEqual("", observed.stderr)
        self.assertEqual(expected + "\n", observed.stdout)
        return expected

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and os.geteuid() == 0
        and os.environ.get("HTTP_ZTP_MONITOR_ROOT_NAMESPACE") == "1",
        NOT_COVERED,
    )
    def test_real_root_entrypoint_workflow(self):
        tree_id = self._workflow_bound_tree_id()
        self.assertTrue(Path("/proc/self/fd/9").exists())
        result, receipt_path = self._invoke_root_warden(tree_id, "positive")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("root-entrypoint-workflow: PASS\n", result.stdout)
        self.assertEqual("", result.stderr)
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes)
        self.assertEqual("PASS", receipt["result"])
        self.assertEqual(tree_id, receipt["tree_id"])
        self.assertEqual(
            list(ROOT_COMMAND_LEAF_NAMES), receipt["command_leaf_names"],
        )
        self.assertEqual(
            list(ROOT_RECOVERY_DECISION_TOKENS),
            receipt["recovery_decision_tokens"],
        )
        print(
            "MONITOR-AUTHORITY-ROOT-EVIDENCE "
            f"tree_id={tree_id} "
            f"receipt_sha256={hashlib.sha256(receipt_bytes).hexdigest()} "
            f"source_manifest_sha256={receipt['source_manifest_sha256']} "
            "command_leaf_names=" + ",".join(receipt["command_leaf_names"]) + " "
            "recovery_decision_tokens="
            + ",".join(receipt["recovery_decision_tokens"])
        )

        for hostile_case in ROOT_HOSTILE_CASES:
            with self.subTest(hostile_case=hostile_case):
                hostile, hostile_receipt = self._invoke_root_warden(
                    tree_id, "hostile-" + hostile_case, hostile_case,
                )
                self.assertNotEqual(0, hostile.returncode)
                self.assertNotIn("PASS", hostile.stdout)
                self.assertFalse(
                    hostile_receipt.exists() and hostile_receipt.stat().st_size,
                    "hostile case published a nonempty final receipt",
                )


if __name__ == "__main__":
    unittest.main()
