#!/usr/bin/env python3
"""Health contract for the inactive control plane and activated ZTP runtime."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from typing import Mapping, Optional, Sequence


HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import activate  # noqa: E402


class HealthError(RuntimeError):
    """A required runtime invariant is not currently true."""


SAFE_INACTIVE_STATES = frozenset({"STOPPED", "EXITED", "FATAL"})
SUPERVISOR_NOT_RUNNING_EXIT = 7
MAX_SUPERVISOR_PID = 2_147_483_647
CANONICAL_SUPERVISOR_PID = re.compile(r"(?:0|[1-9][0-9]{0,9})\n")


def parse_supervisor_status(output: str) -> dict:
    states = {}
    for line in str(output).splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        states[fields[0]] = fields[1]
    return states


def require_running(states: Mapping[str, str], services: Sequence[str]) -> None:
    for service in services:
        state = states.get(service, "MISSING")
        if state != "RUNNING":
            raise HealthError(f"{service} is {state}, expected RUNNING")


def require_exact_argv(actual: Sequence[str], expected: Sequence[str]) -> None:
    if tuple(actual) != tuple(expected):
        raise HealthError(
            "dhcpd argv does not match the current explicit listener plan: "
            f"actual={tuple(actual)!r}, expected={tuple(expected)!r}"
        )


def _run(command: Sequence[str], allowed=(0,)):
    try:
        result = subprocess.run(
            list(command), capture_output=True, text=True, check=False, timeout=8,
        )
    except subprocess.TimeoutExpired as exc:
        raise HealthError(f"command timed out: {' '.join(command)}") from exc
    if result.returncode not in allowed:
        detail = str(result.stderr or result.stdout).strip()
        raise HealthError(
            f"command failed ({result.returncode}): {' '.join(command)}"
            + (f": {detail}" if detail else "")
        )
    return result


def _load_runtime_state(settings: activate.Settings) -> dict:
    try:
        value = json.loads(settings.runtime_plan.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HealthError(f"runtime plan is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise HealthError("runtime plan must be a JSON object")
    return value


def _state_file_present(path: Path, label: str) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise HealthError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise HealthError(f"{label} must be one regular file")
    return True


def require_current_plan(saved: dict, current: dict) -> None:
    for key in (
        "schema_version", "project", "scope", "switch_scope", "mini",
        "subnet_sha256",
        "listener_names", "listener_ifindexes", "direct_shared_networks",
        "relay_shared_networks", "dhcp_only_shared_networks", "endpoint_ips",
        "listener_fingerprints", "apache_listener_sha256",
    ):
        if saved.get(key) != current.get(key):
            raise HealthError(f"saved runtime plan is stale: {key} changed")


def _supervisor_states() -> dict:
    result = _run(("supervisorctl", "status"), allowed=(0, 3))
    return parse_supervisor_status(result.stdout)


def parse_supervisor_pid_result(result, service: str) -> int:
    """Parse Supervisor's exact RUNNING or LSB NOT_RUNNING PID result.

    Supervisor 4.2.5 returns exit status 7 and the single line ``0`` for a
    configured program that is not running.  Exit status 3 means an
    unimplemented feature and must not be confused with an inactive process.
    """
    try:
        returncode = int(result.returncode)
    except (AttributeError, TypeError, ValueError) as exc:
        raise HealthError(f"Supervisor returned no {service} PID status") from exc
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    if CANONICAL_SUPERVISOR_PID.fullmatch(stdout) is None:
        raise HealthError(f"Supervisor returned an invalid {service} PID")
    pid = int(stdout[:-1])
    if pid > MAX_SUPERVISOR_PID:
        raise HealthError(f"Supervisor returned an invalid {service} PID")
    if returncode == 0 and pid > 0 and not stderr:
        return pid
    if (
        returncode == SUPERVISOR_NOT_RUNNING_EXIT
        and pid == 0
        and not stderr
    ):
        return 0
    detail = str(stderr or stdout).strip()
    raise HealthError(
        f"Supervisor pid {service} failed ({returncode})"
        + (f": {detail}" if detail else "")
    )


def _supervisor_pid(service: str) -> int:
    result = _run(
        ("supervisorctl", "pid", service),
        allowed=(0, SUPERVISOR_NOT_RUNNING_EXIT),
    )
    return parse_supervisor_pid_result(result, service)


def require_inactive(states: Mapping[str, str], services: Sequence[str]) -> None:
    for service in services:
        state = states.get(service, "MISSING")
        if state not in SAFE_INACTIVE_STATES:
            raise HealthError(
                f"inactive runtime requires {service} safely stopped, got {state}"
            )
        pid = _supervisor_pid(service)
        if pid != 0:
            raise HealthError(
                f"inactive runtime requires {service} pid=0, got pid={pid} ({state})"
            )


def _dhcp_pid() -> int:
    pid = _supervisor_pid("dhcpd")
    if pid <= 1:
        raise HealthError("Supervisor returned an inactive dhcpd PID")
    return pid


def _process_argv(pid: int):
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError as exc:
        raise HealthError(f"cannot read dhcpd process argv: {exc}") from exc
    return tuple(
        item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item
    )


def _check_tcp_endpoints(endpoint_ips: Sequence[str]) -> None:
    for address in endpoint_ips:
        try:
            connection = socket.create_connection((address, 80), timeout=3.0)
        except OSError as exc:
            raise HealthError(f"Apache endpoint {address}:80 is unreachable: {exc}") from exc
        connection.close()


def check_runtime(
    *, require_active: bool = False,
    expected_services: Optional[Sequence[str]] = None,
    allow_rebuild_required: bool = False,
) -> str:
    settings = activate.Settings.from_environment(os.environ)
    activate.validate_python_runtime()
    activate.require_monitor_authority()
    activate.validate_image_source_contract(settings)
    if (
        not allow_rebuild_required
        and _state_file_present(settings.rebuild_required, "image rebuild marker")
    ):
        raise HealthError(
            "container image rebuild is required; run deploy.sh deploy"
        )
    if _state_file_present(settings.guardian_fault, "guardian lock fault"):
        raise HealthError(
            "runtime guardian cannot validate the shared deployment lock; "
            "inspect guardian-fault.json"
        )
    if expected_services is None and _state_file_present(
        settings.quarantine_marker, "runtime quarantine marker",
    ):
        raise HealthError(
            "runtime was quarantined after repeated health failures; "
            "run deploy.sh load after correcting the cause"
        )
    selected, _runtime, current, expected_apache = activate.observe_runtime(settings)
    saved = _load_runtime_state(settings)
    require_current_plan(saved, current)
    states = _supervisor_states()
    require_running(states, ("rsyslog", "logrotate", "runtime-guardian"))
    activate.validate_control_cgi(settings)
    marker = activate.read_activation_marker(settings)
    if expected_services is None:
        if marker is None:
            precommit_path = getattr(settings, "precommit_marker", None)
            if precommit_path is not None and _state_file_present(
                precommit_path, "precommit service start authority",
            ):
                raise HealthError(
                    "precommit service start authority is abandoned; "
                    "runtime must be recovered by load/resume"
                )
            if require_active:
                raise HealthError("activation marker is absent")
            require_inactive(states, activate.MANAGED_SERVICES)
            return "healthy inactive control plane; run deploy.sh load"
        valid, reason = activate.validate_activation_marker(marker, settings, selected)
        if not valid:
            raise HealthError(reason)
        services = tuple(marker["services"])
    else:
        services = tuple(expected_services)
        if services != activate.expected_services(selected):
            raise HealthError("pre-commit service set does not match current plan")
    require_running(states, services)
    inactive = tuple(
        service for service in activate.MANAGED_SERVICES if service not in services
    )
    try:
        require_inactive(states, inactive)
    except HealthError as exc:
        raise HealthError(f"unexpected service state: {exc}") from exc
    if "dhcpd" in services:
        _run((
            "/usr/sbin/dhcpd", "-4", "-t", "-cf",
            os.fspath(settings.dhcp_config),
        ))
        expected = _runtime.build_dhcpd_argv(
            selected.listener_names,
            config=os.fspath(settings.dhcp_config),
            leases=os.fspath(settings.dhcp_leases),
        )
        require_exact_argv(_process_argv(_dhcp_pid()), expected)
    if "apache2" in services:
        try:
            actual_apache = settings.apache_listeners.read_text(encoding="utf-8")
        except OSError as exc:
            raise HealthError(f"cannot read Apache listener config: {exc}") from exc
        if actual_apache != expected_apache:
            raise HealthError("Apache listener config is not the exact current plan")
        _run(("/usr/sbin/apache2ctl", "configtest"))
        _check_tcp_endpoints(selected.endpoint_ips)
    return (
        "healthy activated runtime; listeners="
        + (",".join(selected.listener_names) or "none")
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    require_active = "--require-active" in list(
        argv if argv is not None else sys.argv[1:]
    )
    try:
        control_auth = activate.require_control_auth(emit_factory_warning=False)
        message = check_runtime(require_active=require_active)
        print(json.dumps({
            "healthy": True,
            "message": message,
            "control_auth": control_auth,
        }, ensure_ascii=True, sort_keys=True))
        return 0
    except (HealthError, activate.ActivationError, OSError, ValueError) as exc:
        print(f"[ERROR] unhealthy ZTP container: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
