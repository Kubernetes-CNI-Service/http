#!/usr/bin/env python3
"""Independent root worker for fixed Switch Status collection requests."""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback

from switch_collection_gate import (
    CollectionGate,
    CollectionGateCancelled,
    CollectionGateError,
    active_project_identity,
    collection_keys_for_scope,
)


HTTP_ROOT = Path(__file__).resolve().parent.parent
STATUS_DIR = HTTP_ROOT / "monitor/status"
REQUEST_FILE = STATUS_DIR / "switch-collection.request"
STATUS_FILE = STATUS_DIR / "switch-collection.status.json"
PID_FILE = STATUS_DIR / "switch-collection.pid"
HTML_SCRIPT = HTTP_ROOT / "monitor/generate-monitor-html.py"
SCRIPTS = {
    "ethernet": HTTP_ROOT / "ethernet/monitor/cron.sh",
    "infiniband": HTTP_ROOT / "infiniband/monitor/cron.sh",
    "nvlink": HTTP_ROOT / "nvlink/monitor/cron.sh",
}


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def write_status(state: str, **extra) -> None:
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {"state": state, "updated_at": timestamp(), **extra}
    descriptor, temporary = tempfile.mkstemp(prefix=".switch-collection.", dir=STATUS_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, STATUS_FILE)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_request() -> str:
    """Compatibility read helper using the same safe file contract as claim."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(REQUEST_FILE, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 64
            ):
                return ""
            value = stream.read(64).strip()
            return value if value in {"collect", "stop"} else ""
    except OSError:
        return ""


def claim_request(expected: str = "") -> str:
    """Atomically consume one exact request without erasing a newer action."""
    if expected and expected not in {"collect", "stop"}:
        return ""
    try:
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(REQUEST_FILE, flags)
        with os.fdopen(descriptor, "r+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > 64
            ):
                return ""
            current = stream.read().strip()
            if current not in {"collect", "stop"} or (expected and current != expected):
                return ""
            stream.seek(0)
            stream.write("idle\n")
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
            return current
    except OSError as exc:
        print(f"[{timestamp()}] [WARN] cannot claim request: {exc}", flush=True)
        return ""


def commands_for_scope(scope: str, lock_wait: int = 600) -> list[list[str]]:
    commands = []
    wait_args = ["--wait-lock", str(max(lock_wait, 0))]
    if scope in {"air", "all"}:
        commands.append(["bash", str(SCRIPTS["ethernet"]), *wait_args, "--air"])
    if scope in {"prod", "all"}:
        commands.extend([
            ["bash", str(SCRIPTS["ethernet"]), *wait_args, "--prod"],
            ["bash", str(SCRIPTS["infiniband"]), *wait_args],
            ["bash", str(SCRIPTS["nvlink"]), *wait_args],
        ])
    return commands


def collection_process_ids(proc_root: Path = Path("/proc")) -> set[int]:
    """Find only processes whose argv contains one of our exact cron.sh paths."""
    if not proc_root.is_dir():
        return set()
    # argv preserves the path used to invoke a script.  IB and NVLink cron.sh
    # are deployment aliases of the Ethernet implementation, so resolving the
    # three paths would collapse them to one canonical filename and make stop
    # miss processes started through either alias.
    scripts = {str(path) for path in SCRIPTS.values()}
    scripts.update(str(path.resolve()) for path in SCRIPTS.values())
    parents: dict[int, int] = {}
    targets: set[int] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            argv = [item.decode("utf-8", errors="replace") for item in
                    (entry / "cmdline").read_bytes().split(b"\0") if item]
            stat_fields = (entry / "stat").read_text(encoding="utf-8").split(") ", 1)[1].split()
            parents[pid] = int(stat_fields[1])
        except (OSError, ValueError, IndexError):
            continue
        if any(argument in scripts for argument in argv):
            targets.add(pid)
    # Include SSH/SCP/sleep descendants belonging to those exact collectors.
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in targets and pid not in targets:
                targets.add(pid)
                changed = True
    targets.discard(os.getpid())
    return targets


def stop_all_collectors() -> list[int]:
    targets = collection_process_ids()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in sorted(targets, reverse=True):
            try:
                os.kill(pid, sig)
            except (OSError, ProcessLookupError):
                pass
        if sig == signal.SIGTERM and targets:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if not any((Path("/proc") / str(pid)).exists() for pid in targets):
                    return sorted(targets)
                time.sleep(0.2)
    return sorted(targets)


def run_interruptible(command: list[str], cwd: Path, timeout: int) -> tuple[dict, bool]:
    """Run one collector while servicing the independent stop request."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout_file, \
            tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr_file:
        process = subprocess.Popen(
            command, cwd=cwd, text=True, stdout=stdout_file, stderr=stderr_file,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        cancelled = False
        while process.poll() is None:
            if claim_request("stop") == "stop":
                cancelled = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    pass
                stop_all_collectors()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                break
            if time.monotonic() >= deadline:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        pass
                return {"returncode": 124, "stdout": "", "stderr": f"timeout after {timeout}s"}, False
            time.sleep(1)
        process.wait()
        stdout_file.seek(0)
        stderr_file.seek(0)
        return {"returncode": process.returncode,
                "stdout": stdout_file.read(), "stderr": stderr_file.read()}, cancelled


def collect(scope: str, timeout: int, lock_wait: int) -> bool:
    started_at = timestamp()
    write_status("collecting", scope=scope, started_at=started_at)
    try:
        project = active_project_identity(HTTP_ROOT)
        with CollectionGate(
            project, scope, collection_keys=collection_keys_for_scope(scope),
            status_dir=STATUS_DIR, lock_wait_seconds=lock_wait,
            cancel_check=lambda: claim_request("stop") == "stop",
        ) as gate:
            decision = gate.decision
            if not decision.allowed:
                finished_at = timestamp()
                if decision.reason == "cooldown":
                    print(
                        f"[{finished_at}] [COOLDOWN] skipped; "
                        f"next collection allowed at {decision.next_allowed_at}",
                        flush=True,
                    )
                    write_status(
                        "success", scope=scope, started_at=started_at,
                        finished_at=finished_at, cooldown_skipped=True,
                        last_success_at=decision.last_success_at,
                        next_allowed_at=decision.next_allowed_at,
                        remaining_seconds=decision.remaining_seconds,
                    )
                    return True
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at,
                    reason="another managed Switch collection is already running",
                )
                return False

            errors = []
            for command in commands_for_scope(scope, lock_wait):
                if claim_request("stop") == "stop":
                    stopped = stop_all_collectors()
                    write_status("idle", scope=scope, stopped_at=timestamp(),
                                 stopped_pids=stopped)
                    return False
                script = Path(command[1])
                if not script.is_file():
                    errors.append(f"script not found: {script}")
                    continue
                print(f"[{timestamp()}] [RUN] {' '.join(command)}", flush=True)
                result, cancelled = run_interruptible(command, script.parent, timeout)
                if cancelled:
                    write_status("idle", scope=scope, stopped_at=timestamp())
                    return False
                if result["stdout"]:
                    print(
                        result["stdout"],
                        end="" if result["stdout"].endswith("\n") else "\n",
                        flush=True,
                    )
                if result["stderr"]:
                    print(
                        result["stderr"],
                        end="" if result["stderr"].endswith("\n") else "\n",
                        file=sys.stderr, flush=True,
                    )
                if result["returncode"]:
                    detail = (
                        result["stderr"].strip()
                        or result["stdout"].strip()
                        or "no detail"
                    )[-2000:]
                    errors.append(f"{script.name} exit={result['returncode']}: {detail}")

            html_command = [sys.executable, str(HTML_SCRIPT)]
            if scope in {"air", "prod"}:
                html_command += ["--type", scope]
            if not errors:
                result = subprocess.run(
                    html_command, cwd=HTTP_ROOT, text=True,
                    capture_output=True, timeout=180, check=False,
                )
                if result.returncode:
                    errors.append(
                        (result.stderr.strip() or result.stdout.strip()
                         or "monitor.html generation failed")[-2000:]
                    )
            finished_at = timestamp()
            if errors:
                write_status(
                    "failed", scope=scope, started_at=started_at,
                    finished_at=finished_at, reason=" | ".join(errors),
                )
                return False
            successful_at = gate.mark_success()
            write_status(
                "success", scope=scope, started_at=started_at,
                finished_at=finished_at, cooldown_seconds=gate.cooldown_seconds,
                last_success_at=successful_at,
            )
            return True
    except CollectionGateCancelled:
        stopped = stop_all_collectors()
        write_status(
            "idle", scope=scope, stopped_at=timestamp(), stopped_pids=stopped,
        )
        return False
    except CollectionGateError as exc:
        finished_at = timestamp()
        write_status(
            "failed", scope=scope, started_at=started_at,
            finished_at=finished_at, reason=f"collection cooldown gate: {exc}",
        )
        return False


def collect_safely(scope: str, timeout: int, lock_wait: int) -> bool:
    """Keep the persistent worker alive if one collection has an internal error."""
    try:
        return collect(scope, timeout, lock_wait)
    except Exception as exc:  # defensive boundary for the long-running worker
        finished_at = timestamp()
        detail = f"{type(exc).__name__}: {exc}"
        write_status("failed", scope=scope, finished_at=finished_at, reason=detail)
        print(f"[{finished_at}] [ERROR] unexpected collection failure: {detail}",
              file=sys.stderr, flush=True)
        traceback.print_exc()
        return False


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Switch Status independent collection worker")
    result.add_argument("--scope", choices=("air", "prod", "all"), required=True)
    result.add_argument("--poll", type=int, default=2)
    result.add_argument("--timeout", type=int, default=3600)
    result.add_argument("--lock-wait", type=int, default=600)
    return result


def main() -> int:
    args = parser().parse_args()
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    write_status("idle", scope=args.scope)
    try:
        while True:
            action = claim_request()
            if action == "collect":
                write_status("collecting", scope=args.scope, queued_at=timestamp())
                collect_safely(
                    args.scope, max(args.timeout, 60), max(args.lock_wait, 0),
                )
            elif action == "stop":
                write_status("stopping", scope=args.scope, started_at=timestamp())
                stopped = stop_all_collectors()
                write_status("idle", scope=args.scope, stopped_at=timestamp(),
                             stopped_pids=stopped)
            time.sleep(max(args.poll, 1))
    except KeyboardInterrupt:
        return 130
    finally:
        try:
            if int(PID_FILE.read_text().strip()) == os.getpid():
                PID_FILE.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
