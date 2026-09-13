#!/usr/bin/env python3
"""Transactional management entry for the containerized ZTP runtime.

Every mutating lifecycle runs under the repository's shared deployment lock.
The exact same open-file description is inherited by 11-load/13-unload, so
prepare, generation, service verification, and activation form one exclusion
window with sync-code and all other cooperating writers.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import NamedTuple, Optional, Sequence


HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import activate  # noqa: E402
import healthcheck  # noqa: E402
import hostlock  # noqa: E402


class ControllerError(RuntimeError):
    """A transactional lifecycle operation failed."""


class GuardianFatalError(ControllerError):
    """Guardian cannot prove mutual exclusion and must stop permanently."""


STOP_ORDER = (
    "ztp-monitor", "switch-collection", "manual-ztp", "dhcpd", "apache2",
)
RESUME_STATUS = Path("/run/http-ztp/runtime-resume.status.json")
LOGROTATE_CONFIG = Path("/opt/http-ztp/logrotate-http-ztp.conf")
GUARDIAN_INTERVAL = 10
GUARDIAN_FAILURE_THRESHOLD = 3
GUARDIAN_HEALTH_TIMEOUT = 12
SUPERVISOR_COMMAND_TIMEOUT = 8


class GuardianState(NamedTuple):
    marker_identity: Optional[str]
    failures: int


GUARDIAN_INITIAL_STATE = GuardianState(None, 0)


def write_resume_status(state: str, reason: str = "") -> None:
    payload = {
        "state": state,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(),
    }
    if reason:
        payload["reason"] = reason
    activate._atomic_write(  # one private, container-internal atomic primitive
        RESUME_STATUS,
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
        0o600,
    )


def readiness() -> int:
    try:
        value = json.loads(RESUME_STATUS.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print("runtime resume has not started", file=sys.stderr)
        return 3
    except (OSError, json.JSONDecodeError) as exc:
        print(f"runtime resume status is invalid: {exc}", file=sys.stderr)
        return 2
    state = str(value.get("state") or "") if isinstance(value, dict) else ""
    if state == "ready":
        print("runtime resume is ready")
        return 0
    if state == "failed":
        print(
            "runtime resume failed: " + str(value.get("reason") or "unknown"),
            file=sys.stderr,
        )
        return 2
    print(f"runtime resume is {state or 'unknown'}", file=sys.stderr)
    return 3


def rotate_logs(settings: activate.Settings, interval: int = 300) -> None:
    """Bound persistent rsyslog files without cron or a host service manager."""
    state = settings.state_root / "logrotate.status"
    while True:
        try:
            result = subprocess.run(
                ("/usr/sbin/logrotate", "-s", os.fspath(state), os.fspath(LOGROTATE_CONFIG)),
                capture_output=True, text=True, check=False, timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            raise ControllerError("logrotate timed out after 60s") from exc
        if result.returncode != 0:
            detail = str(result.stderr or result.stdout).strip()
            raise ControllerError(
                f"logrotate failed ({result.returncode})"
                + (f": {detail}" if detail else "")
            )
        time.sleep(interval)


def _lock_contract(
    settings: activate.Settings, *, wait_seconds: float = 0,
):
    """Return only the image-owned lock implementation.

    Importing a helper from the writable bind mount before taking the lock
    would make the source receipt and the executed lock code non-atomic.
    """
    lock_path = settings.http_root / ".deployment.lock"

    @contextmanager
    def deployment_lock(_root: Path):
        with hostlock.safe_lock(lock_path, wait_seconds) as descriptor:
            yield descriptor

    return (
        hostlock.HostLockError,
        deployment_lock,
        hostlock.inherited_lock_subprocess_kwargs,
    )


def run_child(
    command: Sequence[str], lock_descriptor: int, inherited_kwargs, runner=subprocess.run,
) -> None:
    kwargs = inherited_kwargs(lock_descriptor)
    result = runner(list(command), check=False, **kwargs)
    if int(getattr(result, "returncode", 0)) != 0:
        raise ControllerError(
            f"child lifecycle failed ({result.returncode}): {' '.join(command)}"
        )


def supervisor_states() -> dict:
    try:
        result = subprocess.run(
            ("supervisorctl", "status"), capture_output=True, text=True,
            check=False, timeout=SUPERVISOR_COMMAND_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise ControllerError("timed out querying Supervisor") from exc
    if result.returncode not in {0, 3}:
        raise ControllerError(
            "cannot query Supervisor: " + str(result.stderr or result.stdout).strip()
        )
    return healthcheck.parse_supervisor_status(result.stdout)


def supervisor_action(action: str, service: str) -> None:
    if action not in {"start", "stop"} or service not in activate.MANAGED_SERVICES:
        raise ControllerError("unsafe Supervisor action")
    try:
        result = subprocess.run(
            ("supervisorctl", action, service),
            capture_output=True, text=True, check=False,
            timeout=SUPERVISOR_COMMAND_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise ControllerError(f"Supervisor {action} {service} timed out") from exc
    if result.returncode != 0:
        detail = str(result.stderr or result.stdout).strip()
        raise ControllerError(f"Supervisor {action} {service} failed: {detail}")


def supervisor_pid(service: str) -> int:
    if service not in activate.MANAGED_SERVICES:
        raise ControllerError(f"unsafe Supervisor PID target: {service}")
    try:
        result = subprocess.run(
            ("supervisorctl", "pid", service),
            capture_output=True, text=True, check=False,
            timeout=SUPERVISOR_COMMAND_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise ControllerError(f"Supervisor pid {service} timed out") from exc
    try:
        return healthcheck.parse_supervisor_pid_result(result, service)
    except healthcheck.HealthError as exc:
        raise ControllerError(str(exc)) from exc


def safely_inactive(service: str, state: str) -> tuple[bool, str]:
    if state not in healthcheck.SAFE_INACTIVE_STATES:
        return False, f"{service}={state}"
    try:
        pid = supervisor_pid(service)
    except BaseException as exc:
        return False, f"{service}={state}, pid unavailable: {exc}"
    if pid != 0:
        return False, f"{service}={state}, pid={pid}"
    return True, f"{service}={state}, pid=0"


def stop_managed_services(timeout: float = 10) -> None:
    errors = []
    try:
        states = supervisor_states()
    except BaseException as exc:
        # A broken status transport is not evidence that anything is stopped.
        # Attempt every exact managed service before reporting the aggregate.
        states = {}
        errors.append(f"initial status: {exc}")
    for service in STOP_ORDER:
        safe, _detail = safely_inactive(
            service, states.get(service, "MISSING"),
        )
        if not safe:
            try:
                supervisor_action("stop", service)
            except BaseException as exc:
                errors.append(f"{service}: {exc}")
    deadline = time.monotonic() + max(0, timeout)
    remaining = list(STOP_ORDER)
    remaining_details = [f"{name}=UNKNOWN" for name in remaining]
    while True:
        try:
            states = supervisor_states()
        except ControllerError as exc:
            errors.append(f"post-check: {exc}")
            states = {}
            break
        remaining = []
        remaining_details = []
        for service in STOP_ORDER:
            safe, detail = safely_inactive(
                service, states.get(service, "MISSING"),
            )
            if not safe:
                remaining.append(service)
                remaining_details.append(detail)
        if not remaining or errors or time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    if remaining:
        errors.append(
            "post-check not safely inactive: " + ", ".join(remaining_details)
        )
    if errors:
        raise ControllerError(
            "failed to stop all managed services: " + "; ".join(errors)
        )


def _marker_identity(marker: object) -> str:
    return hashlib.sha256(
        json.dumps(
            marker, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def guardian_snapshot(settings: activate.Settings) -> tuple[Optional[str], bool, str]:
    """Read only marker generation and the exact inactive-service invariant."""
    try:
        marker = activate.read_activation_marker(settings)
    except Exception as exc:
        # Never reopen an unsafe marker path: it may be a FIFO/device or a
        # symlink.  The classified error itself is sufficient to bind this
        # failure generation without risking an unbounded read under the lock.
        identity = hashlib.sha256(
            f"{type(exc).__name__}:{exc}".encode("utf-8")
        ).hexdigest()
        return identity, False, f"activation marker is unreadable: {exc}"
    if marker is None:
        precommit_path = getattr(settings, "precommit_marker", None)
        if precommit_path is not None:
            try:
                precommit = activate.read_precommit_activation(settings)
            except Exception as exc:
                return None, False, (
                    f"precommit service start authority is unreadable: {exc}"
                )
            if precommit is not None:
                return None, False, "abandoned precommit service start authority"
        try:
            states = supervisor_states()
        except Exception as exc:
            return None, False, str(exc)
        unsafe = []
        for name in STOP_ORDER:
            safe, detail = safely_inactive(name, states.get(name, "MISSING"))
            if not safe:
                unsafe.append(detail)
        if unsafe:
            return None, False, (
                "inactive runtime still has managed services: " + ", ".join(unsafe)
            )
        return None, True, "healthy inactive runtime"
    return _marker_identity(marker), True, "active runtime requires full probe"


def guardian_health_probe(
    _settings: activate.Settings, *, timeout: int = GUARDIAN_HEALTH_TIMEOUT,
) -> tuple[bool, str]:
    """Run the complete active health contract with one hard wall-clock limit."""
    try:
        result = subprocess.run(
            ("/opt/http-ztp/healthcheck.py", "--require-active"),
            capture_output=True, text=True, check=False, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"active health probe timed out after {timeout}s"
    except Exception as exc:
        return False, f"active health probe failed to execute: {exc}"
    detail = str(result.stderr or result.stdout or "").strip()
    if result.returncode != 0:
        return False, detail or f"health probe exited {result.returncode}"
    return True, detail or "healthy active runtime"


def guardian_probe(settings: activate.Settings) -> tuple[bool, Optional[str], str]:
    """Compatibility helper for one in-process, read-only guardian observation."""
    identity, inactive_safe, reason = guardian_snapshot(settings)
    if identity is None:
        return inactive_safe, None, reason
    try:
        healthcheck.check_runtime(require_active=True)
    except Exception as exc:
        return False, identity, str(exc)
    return True, identity, "healthy active runtime"


def _remove_state_file(path: Optional[Path]) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return


def clear_guardian_fault(settings: activate.Settings) -> None:
    _remove_state_file(getattr(settings, "guardian_fault", None))


def clear_guardian_fault_best_effort(
    settings: activate.Settings,
) -> Optional[str]:
    """Try to clear a prior lock fault without suppressing safety work.

    A persistent unlink failure deliberately leaves the fault record in place,
    so the container health contract stays unhealthy.  Guardian observation
    and service isolation must nevertheless continue in the same round.
    """
    try:
        clear_guardian_fault(settings)
    except Exception as exc:
        reason = f"guardian fault cleanup failed: {exc}"
        print(f"[ERROR] {reason}", file=sys.stderr, flush=True)
        return reason
    return None


def clear_quarantine(settings: activate.Settings) -> None:
    _remove_state_file(getattr(settings, "quarantine_marker", None))


def write_guardian_fault(settings: activate.Settings, reason: str) -> None:
    path = getattr(settings, "guardian_fault", None)
    if path is None:
        return
    activate._atomic_write(path, json.dumps({
        "schema_version": 1,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    }, ensure_ascii=False, sort_keys=True) + "\n", 0o600)


def write_quarantine(
    settings: activate.Settings, marker_identity: Optional[str], reason: str,
) -> None:
    path = getattr(settings, "quarantine_marker", None)
    if path is None:
        return
    activate._atomic_write(path, json.dumps({
        "schema_version": 1,
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
        "marker_identity": marker_identity,
        "reason": reason,
    }, ensure_ascii=False, sort_keys=True) + "\n", 0o600)


def _lock_is_busy(exc: BaseException) -> bool:
    return isinstance(exc, hostlock.HostLockBusy)


def guardian_fail_closed_without_lock(
    settings: activate.Settings, reason: str,
) -> None:
    """Stop every managed service when the shared lock itself is unsafe.

    Clearing activation without the lock would race another writer, so the
    durable guardian fault and the service stop are independent best-effort
    operations.  The guardian then exits; Supervisor's non-RUNNING state plus
    the stopped services remains observable even if the state disk is broken.
    """
    errors = []
    try:
        write_guardian_fault(settings, reason)
    except BaseException as exc:
        errors.append(f"fault persistence: {exc}")
    try:
        stop_managed_services()
    except BaseException as exc:
        errors.append(f"service cleanup: {exc}")
    detail = f"unsafe deployment lock: {reason}"
    if errors:
        detail += "; " + "; ".join(errors)
    print(f"[ERROR] runtime guardian fail-closed: {detail}",
          file=sys.stderr, flush=True)
    raise GuardianFatalError(detail)


def quarantine_inactive_locked(settings: activate.Settings, reason: str) -> None:
    """Persist inactive fault and stop services as independent best-effort steps."""
    errors = []
    try:
        activate.clear_activation(settings)
    except BaseException as exc:
        errors.append(f"activation cleanup: {exc}")
    try:
        write_quarantine(settings, None, reason)
    except BaseException as exc:
        errors.append(f"quarantine record: {exc}")
    try:
        stop_managed_services()
    except BaseException as exc:
        errors.append(f"service cleanup: {exc}")
    if not errors:
        return
    combined = "; ".join(errors)
    # A transient first write must not lose the cleanup failure.  This retry is
    # independent of service stopping and remains best effort for disk faults.
    try:
        write_quarantine(settings, None, f"{reason}; cleanup errors: {combined}")
    except BaseException as exc:
        errors.append(f"error persistence: {exc}")
    raise ControllerError(
        "guardian inactive cleanup incomplete: " + "; ".join(errors)
    )


def guardian_quarantine_locked(
    settings: activate.Settings,
    expected_identity: str,
    initial_reason: str,
    confirmed_reason: Optional[str] = None,
) -> GuardianState:
    """Quarantine one confirmed generation; caller already owns the lock."""
    current_identity, _safe, current_reason = guardian_snapshot(settings)
    if current_identity is None:
        quarantine_inactive_locked(settings, current_reason)
        return GUARDIAN_INITIAL_STATE
    if current_identity != expected_identity:
        print(
            "[INFO] runtime guardian activation marker changed; "
            "failure count reset without mutation",
            flush=True,
        )
        return GuardianState(current_identity, 0)
    cleanup_errors = []
    try:
        activate.clear_activation(settings)
    except BaseException as exc:
        cleanup_errors.append(f"activation cleanup: {exc}")
    try:
        write_quarantine(
            settings, expected_identity, confirmed_reason or current_reason,
        )
    except BaseException as exc:
        cleanup_errors.append(f"quarantine record: {exc}")
    try:
        stop_managed_services()
    except BaseException as exc:
        cleanup_errors.append(f"service cleanup: {exc}")
    if cleanup_errors:
        raise ControllerError(
            "guardian quarantine incomplete: " + "; ".join(cleanup_errors)
        )
    print(
        "[ERROR] runtime guardian quarantined unhealthy services; "
        f"initial={initial_reason}; confirmed={confirmed_reason or current_reason}; "
        "run deploy.sh load after correcting the cause",
        file=sys.stderr,
        flush=True,
    )
    return GUARDIAN_INITIAL_STATE


def guardian_step(
    settings: activate.Settings,
    state: GuardianState,
    *,
    threshold: int = GUARDIAN_FAILURE_THRESHOLD,
    lock_contract=None,
) -> GuardianState:
    if threshold < 1:
        raise ControllerError("runtime guardian threshold must be positive")
    try:
        contract = lock_contract or _lock_contract(settings)
        lock_error, deployment_lock, _inherited_kwargs = contract
    except Exception as exc:
        guardian_fail_closed_without_lock(
            settings, f"lock contract unavailable: {exc}",
        )
        raise AssertionError("unreachable")

    def lock_failure(exc: BaseException) -> GuardianState:
        if _lock_is_busy(exc):
            print(f"[INFO] runtime guardian skipped a busy lock: {exc}",
                  file=sys.stderr, flush=True)
            return GUARDIAN_INITIAL_STATE
        guardian_fail_closed_without_lock(settings, str(exc))
        raise AssertionError("unreachable")

    try:
        with deployment_lock(settings.http_root):
            clear_guardian_fault_best_effort(settings)
            try:
                activate.require_monitor_authority()
            except Exception as exc:
                quarantine_inactive_locked(
                    settings, f"Monitor authority attestation failed: {exc}",
                )
                return GUARDIAN_INITIAL_STATE
            identity, inactive_safe, reason = guardian_snapshot(settings)
            if identity is None:
                if not inactive_safe:
                    try:
                        quarantine_inactive_locked(settings, reason)
                    except Exception as exc:
                        print(f"[ERROR] {exc}",
                              file=sys.stderr, flush=True)
                return GUARDIAN_INITIAL_STATE
    except lock_error as exc:
        return lock_failure(exc)
    except Exception as exc:
        print(f"[WARN] runtime guardian snapshot failed safely: {exc}",
              file=sys.stderr, flush=True)
        return GUARDIAN_INITIAL_STATE

    try:
        healthy, health_reason = guardian_health_probe(
            settings, timeout=GUARDIAN_HEALTH_TIMEOUT,
        )
    except Exception as exc:
        healthy, health_reason = False, f"health probe raised: {exc}"
    try:
        with deployment_lock(settings.http_root):
            fault_cleanup_reason = clear_guardian_fault_best_effort(settings)
            current_identity, inactive_safe, current_reason = guardian_snapshot(settings)
            if current_identity is None:
                if not inactive_safe:
                    try:
                        quarantine_inactive_locked(settings, current_reason)
                    except Exception as exc:
                        print(f"[ERROR] {exc}",
                              file=sys.stderr, flush=True)
                return GUARDIAN_INITIAL_STATE
            if current_identity != identity:
                print("[INFO] runtime guardian activation marker changed; "
                      "failure count reset", flush=True)
                return GuardianState(current_identity, 0)
            if fault_cleanup_reason is not None:
                healthy = False
                health_reason = fault_cleanup_reason
            if healthy:
                if state.failures:
                    print("[INFO] runtime guardian health recovered without "
                          "restarting services", flush=True)
                return GuardianState(identity, 0)
            if state.marker_identity is not None and state.marker_identity != identity:
                print("[INFO] runtime guardian activation marker changed; "
                      "failure count reset", flush=True)
                return GuardianState(identity, 0)
            failures = state.failures + 1
            print(f"[WARN] runtime guardian health failure {failures}/{threshold}: "
                  f"{health_reason}", file=sys.stderr, flush=True)
            if failures < threshold:
                return GuardianState(identity, failures)
            try:
                final_healthy, final_reason = guardian_health_probe(
                    settings, timeout=GUARDIAN_HEALTH_TIMEOUT,
                )
            except Exception as exc:
                final_healthy = False
                final_reason = f"final health probe raised: {exc}"
            if fault_cleanup_reason is not None:
                final_healthy = False
                final_reason = fault_cleanup_reason
            if final_healthy:
                print("[INFO] runtime guardian observed recovery before quarantine; "
                      "no service was restarted", flush=True)
                return GuardianState(identity, 0)
            try:
                return guardian_quarantine_locked(
                    settings, identity, health_reason, final_reason,
                )
            except ControllerError as exc:
                print(f"[ERROR] {exc}; guardian will retry", file=sys.stderr, flush=True)
                return GuardianState(identity, max(threshold - 1, 0))
    except lock_error as exc:
        return lock_failure(exc)
    except Exception as exc:
        print(f"[WARN] runtime guardian round failed safely: {exc}",
              file=sys.stderr, flush=True)
        return GUARDIAN_INITIAL_STATE


def guardian_loop(
    settings: activate.Settings,
    *,
    interval: int = GUARDIAN_INTERVAL,
    threshold: int = GUARDIAN_FAILURE_THRESHOLD,
) -> None:
    if interval < 1:
        raise ControllerError("runtime guardian interval must be positive")
    # Cache the lock implementation before a future sync replaces mounted
    # source bytes.  Each round still acquires the shared workspace inode.
    lock_contract = None
    state = GUARDIAN_INITIAL_STATE
    while True:
        if lock_contract is None:
            try:
                lock_contract = _lock_contract(settings)
            except Exception as exc:
                guardian_fail_closed_without_lock(
                    settings, f"lock contract unavailable: {exc}",
                )
        try:
            activate.require_control_auth(emit_factory_warning=False)
        except Exception as exc:
            assert lock_contract is not None
            lock_error, deployment_lock, _inherited_kwargs = lock_contract
            try:
                with deployment_lock(settings.http_root):
                    quarantine_inactive_locked(
                        settings,
                        f"Monitor control credential validation failed: {exc}",
                    )
            except lock_error as lock_exc:
                guardian_fail_closed_without_lock(settings, str(lock_exc))
            except Exception as cleanup_exc:
                raise GuardianFatalError(
                    "Monitor control credential failure cleanup was incomplete: "
                    + str(cleanup_exc)
                ) from cleanup_exc
            raise GuardianFatalError(
                f"Monitor control credential validation failed: {exc}"
            ) from exc
        try:
            state = guardian_step(
                settings, state, threshold=threshold, lock_contract=lock_contract,
            )
        except GuardianFatalError:
            raise
        except Exception as exc:
            print(
                f"[ERROR] runtime guardian round raised safely: {exc}",
                file=sys.stderr, flush=True,
            )
            state = GUARDIAN_INITIAL_STATE
        time.sleep(interval)


def abort_failed_transaction(settings: activate.Settings, primary: BaseException) -> None:
    cleanup_errors = []
    try:
        activate.clear_activation(settings)
    except BaseException as exc:  # cleanup must report every failure
        cleanup_errors.append(f"activation cleanup: {exc}")
    try:
        stop_managed_services()
    except BaseException as exc:  # cleanup must report every failure
        cleanup_errors.append(f"service cleanup: {exc}")
    if cleanup_errors:
        raise ControllerError(
            f"operation failed: {primary}; cleanup incomplete: "
            + "; ".join(cleanup_errors)
        ) from primary
    raise primary


def converge_services(expected: Sequence[str], timeout: int = 60) -> None:
    desired = set(expected)
    states = supervisor_states()
    for service in STOP_ORDER:
        if service not in desired:
            safe, _detail = safely_inactive(
                service, states.get(service, "MISSING"),
            )
            if not safe:
                supervisor_action("stop", service)
    states = supervisor_states()
    for service in activate.MANAGED_SERVICES:
        if service in desired and states.get(service) != "RUNNING":
            supervisor_action("start", service)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        states = supervisor_states()
        if all(states.get(service) == "RUNNING" for service in expected):
            return
        failed = [
            service for service in expected
            if states.get(service) in {"BACKOFF", "FATAL", "EXITED", "UNKNOWN"}
        ]
        if failed:
            raise ControllerError(
                "services failed during start: "
                + ", ".join(f"{name}={states.get(name)}" for name in failed)
            )
        time.sleep(0.25)
    raise ControllerError("timed out waiting for Supervisor services")


def load_command(
    settings: activate.Settings, *, no_upgrade: bool = False,
) -> tuple:
    command = [
        "/usr/bin/python3", "-u",
        os.fspath(settings.http_root / "DAY0-Prepare/11-load.py"),
        settings.project_name,
        "--skip-infra",
        "--deployment-scope", settings.scope,
    ]
    if settings.switch_scope != "all":
        command.extend(("--switch", settings.switch_scope))
    if settings.mini:
        command.append("--mini")
    if no_upgrade:
        command.append("--no-upgrade")
    command.extend((
        "--ztp-monitor-scope", settings.scope,
        "--ztp-monitor-interval", str(settings.monitor_interval),
    ))
    return tuple(command)


def unload_command(settings: activate.Settings) -> tuple:
    return (
        "/usr/bin/python3", "-u",
        os.fspath(settings.http_root / "DAY0-Prepare/13-unload.py"),
        settings.project_name, "--yes",
    )


def transactional_load(
    settings: activate.Settings, *, no_upgrade: bool = False,
) -> None:
    lock_error, deployment_lock, inherited_kwargs = _lock_contract(settings)
    try:
        with deployment_lock(settings.http_root) as descriptor:
            if descriptor is None:
                raise ControllerError("mutating load did not receive a deployment lock")
            mutable_sources_touched = False
            try:
                activate.require_monitor_authority()
                activate.validate_image_source_contract(
                    settings, allow_mutable_drift=True,
                )
                # The legacy hostname publisher intentionally rewrites
                # default*.yaml from project global data.  Start from the
                # image copy and restore it again before any health/commit.
                activate.restore_mutable_image_sources(settings)
                mutable_sources_touched = True
                activate.validate_image_source_contract(settings)
                # The first gate is read-only.  Once it passes, stop every old
                # data-plane/worker process before changing any persistent
                # marker, CGI, listener, DHCP, or release artifact.
                activate.observe_runtime(settings)
                # Withdraw both active and abandoned precommit authority first.
                # Any Supervisor retry during the following stop must fail
                # before executing mounted worker code.
                activate.clear_activation(settings)
                stop_managed_services()
                clear_guardian_fault(settings)
                activate.install_control_cgi(settings)
                activate.prepare_runtime(settings)
                run_child(
                    load_command(settings, no_upgrade=no_upgrade),
                    descriptor, inherited_kwargs,
                )
                activate.restore_mutable_image_sources(settings)
                mutable_sources_touched = False
                activate.validate_image_source_contract(settings)
                selected, _runtime, _payload = activate.prepare_runtime(settings)
                services = activate.expected_services(selected)
                # 11-load deliberately runs in no-start mode inside the
                # container, so its legacy start_* helpers do not create or
                # reset the three CGI/worker control files.  Initialize them
                # only after setup has published the exact current-project
                # ztp/status link and before granting precommit start authority.
                activate.initialize_worker_control_files(settings)
                activate.publish_precommit_activation(settings, selected)
                converge_services(services)
                # Verify actual argv, listeners, CGI, and service state before
                # making this generation eligible for automatic restart.
                healthcheck.check_runtime(
                    expected_services=services, allow_rebuild_required=True,
                )
                activate.commit_activation(settings, selected)
                clear_quarantine(settings)
                healthcheck.check_runtime(
                    require_active=True, allow_rebuild_required=True,
                )
                # This is the final promotion: receipt, generation, service
                # state, marker, and public endpoints have all passed while
                # the shared deployment lock is still held.
                activate.clear_rebuild_required(settings)
            except BaseException:
                primary = sys.exc_info()[1]
                assert primary is not None
                if mutable_sources_touched:
                    try:
                        activate.restore_mutable_image_sources(settings)
                    except BaseException as restore_exc:
                        primary = ControllerError(
                            f"operation failed: {primary}; immutable source "
                            f"restore failed: {restore_exc}"
                        )
                abort_failed_transaction(settings, primary)
    except lock_error as exc:
        raise ControllerError(str(exc)) from exc


def transactional_reload_network(settings: activate.Settings) -> None:
    """Rebind an already-active generation after a service-IP NIC move."""
    lock_error, deployment_lock, _inherited_kwargs = _lock_contract(settings)
    try:
        with deployment_lock(settings.http_root):
            try:
                activate.require_monitor_authority()
            except BaseException:
                primary = sys.exc_info()[1]
                assert primary is not None
                abort_failed_transaction(settings, primary)
            activate.validate_image_source_contract(settings)
            for path, label, recovery in (
                (
                    settings.rebuild_required, "image rebuild marker",
                    "run deploy.sh deploy",
                ),
                (
                    settings.quarantine_marker, "runtime quarantine marker",
                    "correct the cause and run deploy.sh load",
                ),
                (
                    settings.guardian_fault, "guardian lock fault",
                    "inspect guardian-fault.json and recover with deploy.sh load",
                ),
            ):
                if activate.state_marker_present(path, label):
                    raise ControllerError(
                        f"network reload refused while {label} is present; {recovery}"
                    )
            if activate.read_precommit_activation(settings) is not None:
                raise ControllerError(
                    "network reload refused while precommit activation is present; "
                    "recover with deploy.sh load"
                )
            marker = activate.read_activation_marker(settings)
            if marker is None:
                raise ControllerError(
                    "network reload requires an active runtime; run deploy.sh load"
                )
            saved = activate.read_runtime_plan(settings)
            if saved is None:
                raise ControllerError(
                    "network reload requires the saved runtime plan; run deploy.sh load"
                )
            selected, _runtime, current, _apache = activate.observe_runtime(settings)
            valid, reason = activate.validate_activation_marker(
                marker, settings, selected,
            )
            if not valid:
                raise ControllerError(
                    f"network reload activation authority is stale: {reason}"
                )
            changed = activate.validate_network_reload_plan(saved, current)
            services = tuple(marker.get("services") or ())
            if services != activate.expected_services(selected):
                raise ControllerError(
                    "network reload service set does not match the current plan"
                )
            if not changed:
                healthcheck.check_runtime(require_active=True)
                print("[NOOP] service-IP listener plan is already current", flush=True)
                return

            # From this point onward any failure leaves the runtime inactive.
            # Restoring an old interface binding after the operator moved the
            # address would be unsafe, so rollback withdraws authority and
            # stops all managed services instead of guessing an old topology.
            try:
                activate.validate_control_cgi(settings)
                activate.clear_activation(settings)
                stop_managed_services()
                selected, _runtime, published = activate.prepare_runtime(settings)
                if activate.validate_network_reload_plan(current, published):
                    raise ControllerError(
                        "network listener identity changed while reload was running"
                    )
                services = activate.expected_services(selected)
                if tuple(marker.get("services") or ()) != services:
                    raise ControllerError(
                        "network reload would change the managed service set"
                    )
                activate.publish_precommit_activation(settings, selected)
                converge_services(services)
                healthcheck.check_runtime(expected_services=services)
                activate.commit_activation(settings, selected)
                healthcheck.check_runtime(require_active=True)
                print(
                    "[OK] service-IP listener plan reloaded without running 11-load",
                    flush=True,
                )
            except BaseException:
                primary = sys.exc_info()[1]
                assert primary is not None
                abort_failed_transaction(settings, primary)
    except lock_error as exc:
        raise ControllerError(str(exc)) from exc


def transactional_unload(settings: activate.Settings) -> None:
    lock_error, deployment_lock, inherited_kwargs = _lock_contract(settings)
    try:
        with deployment_lock(settings.http_root) as descriptor:
            if descriptor is None:
                raise ControllerError("mutating unload did not receive a deployment lock")
            try:
                activate.validate_image_source_contract(settings)
                activate.clear_activation(settings)
                run_child(unload_command(settings), descriptor, inherited_kwargs)
                stop_managed_services()
                clear_quarantine(settings)
                clear_guardian_fault(settings)
            except BaseException:
                primary = sys.exc_info()[1]
                assert primary is not None
                abort_failed_transaction(settings, primary)
    except lock_error as exc:
        raise ControllerError(str(exc)) from exc


def deactivate(settings: activate.Settings) -> None:
    lock_error, deployment_lock, _inherited_kwargs = _lock_contract(settings)
    try:
        with deployment_lock(settings.http_root):
            # Deactivate remains available during an intentional image/source
            # drift so an old embedded controller can safely stop services.
            errors = []
            for label, operation in (
                ("activation cleanup", lambda: activate.clear_activation(settings)),
                ("service cleanup", stop_managed_services),
                ("quarantine cleanup", lambda: clear_quarantine(settings)),
                ("guardian fault cleanup", lambda: clear_guardian_fault(settings)),
            ):
                try:
                    operation()
                except BaseException as exc:
                    errors.append(f"{label}: {exc}")
            if errors:
                raise ControllerError(
                    "deactivation cleanup incomplete: " + "; ".join(errors)
                )
    except lock_error as exc:
        raise ControllerError(str(exc)) from exc


def resume(settings: activate.Settings) -> None:
    lock_error, deployment_lock, _inherited_kwargs = _lock_contract(
        settings, wait_seconds=600,
    )
    try:
        with deployment_lock(settings.http_root):
            try:
                activate.require_monitor_authority()
                activate.validate_image_source_contract(settings)
                if activate.state_marker_present(
                    settings.rebuild_required, "rebuild-required marker",
                ):
                    stop_managed_services()
                    print(
                        "[INFO] image rebuild is required; runtime remains inactive "
                        "until deploy.sh deploy completes",
                        flush=True,
                    )
                    return
                if activate.state_marker_present(
                    settings.quarantine_marker, "runtime quarantine marker",
                ):
                    raise ControllerError(
                        "runtime is quarantined; use deploy.sh load after correcting the cause"
                    )
                activate.clear_precommit_activation(settings)
                activate.install_control_cgi(settings)
                selected, _runtime, _payload = activate.prepare_runtime(settings)
                marker = activate.read_activation_marker(settings)
                if marker is None:
                    stop_managed_services()
                    print("[INFO] no activation marker; runtime remains inactive")
                    return
                valid, reason = activate.validate_activation_marker(
                    marker, settings, selected,
                )
                if not valid:
                    raise ControllerError(f"stale activation marker: {reason}")
                services = tuple(marker["services"])
                converge_services(services)
                healthcheck.check_runtime(require_active=True)
                print("[OK] activated runtime resumed under shared deployment lock")
            except BaseException:
                primary = sys.exc_info()[1]
                assert primary is not None
                try:
                    stop_managed_services()
                except BaseException as cleanup_exc:
                    raise ControllerError(
                        f"runtime resume failed: {primary}; service rollback failed: "
                        f"{cleanup_exc}"
                    ) from primary
                raise
    except lock_error as exc:
        raise ControllerError(str(exc)) from exc


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "action", choices=(
            "load", "reload-network", "unload", "deactivate", "resume",
            "ready", "rotate-logs", "guardian",
        ),
    )
    result.add_argument("--no-upgrade", action="store_true")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    if args.no_upgrade and args.action != "load":
        parser().error("--no-upgrade is valid only with the load action")
    try:
        settings = activate.Settings.from_environment(os.environ)
        if args.action == "ready":
            return readiness()
        if args.action in {"load", "reload-network", "resume"}:
            activate.require_control_auth(emit_factory_warning=False)
        if args.action == "resume":
            write_resume_status("starting")
        if args.action == "load":
            transactional_load(settings, no_upgrade=args.no_upgrade)
        elif args.action == "reload-network":
            transactional_reload_network(settings)
        elif args.action == "unload":
            transactional_unload(settings)
        elif args.action == "deactivate":
            deactivate(settings)
        elif args.action == "rotate-logs":
            rotate_logs(settings)
        elif args.action == "guardian":
            guardian_loop(settings)
        else:
            resume(settings)
            write_resume_status("ready")
        return 0
    except (ControllerError, activate.ActivationError, healthcheck.HealthError, OSError, ValueError) as exc:
        if args.action == "resume":
            try:
                write_resume_status("failed", str(exc))
            except OSError:
                pass
        print(f"[ERROR] container lifecycle refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
