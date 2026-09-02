#!/usr/bin/env python3
"""Shared cooldown gate for managed automatic and page Switch collection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import fcntl
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import time
from typing import Callable, Optional


HTTP_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATUS_DIR = HTTP_ROOT / "monitor/status"
COOLDOWN_SECONDS = 30 * 60
STATE_SCHEMA = 2
STATE_NAME = ".switch-collection-cooldown.json"
LOCK_NAME = ".switch-collection-cooldown.lock"
COLLECTION_KEYS_BY_SCOPE = {
    "air": ("air-ethernet",),
    "prod": ("prod-ethernet", "prod-infiniband", "prod-nvlink"),
    "all": (
        "air-ethernet", "prod-ethernet", "prod-infiniband", "prod-nvlink",
    ),
}
VALID_COLLECTION_KEYS = frozenset(COLLECTION_KEYS_BY_SCOPE["all"])


class CollectionGateError(RuntimeError):
    """The shared gate could not be evaluated safely."""


class CollectionGateCancelled(CollectionGateError):
    """A caller cancelled while waiting for the shared gate."""


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    remaining_seconds: int = 0
    last_success_at: Optional[str] = None
    next_allowed_at: Optional[str] = None


def active_project_identity(http_root: Path = HTTP_ROOT) -> str:
    """Resolve the active project from the setup-managed inventory link."""
    inventory = http_root / "monitor/02-devices_config.csv"
    try:
        resolved = inventory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CollectionGateError(
            f"cannot resolve active project inventory: {inventory}: {exc}"
        ) from exc
    if not resolved.is_file():
        raise CollectionGateError(f"active inventory is not a regular file: {resolved}")
    return str(resolved.parent)


def _iso_at(epoch: float) -> str:
    try:
        value = float(epoch)
        if not math.isfinite(value):
            raise ValueError("timestamp is not finite")
        return (
            datetime.fromtimestamp(value).astimezone()
            .isoformat(timespec="seconds")
        )
    except (OSError, OverflowError, ValueError) as exc:
        raise CollectionGateError(
            f"invalid collection timestamp epoch: {epoch!r}"
        ) from exc


def collection_keys_for_scope(scope: str) -> tuple[str, ...]:
    """Return the fixed collection domains covered by a page/manual scope."""
    try:
        return COLLECTION_KEYS_BY_SCOPE[scope]
    except KeyError as exc:
        raise CollectionGateError(f"invalid collection scope: {scope}") from exc


def _read_state(path: Path) -> Optional[dict]:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 64 * 1024
        ):
            raise CollectionGateError(f"invalid cooldown state file: {path}")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CollectionGateError(f"cannot read cooldown state {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    # Schema 1 stored one project-wide timestamp.  It cannot be mapped to the
    # four independent collection domains without guessing, so ignore it and
    # let the next collection rebuild trustworthy schema-2 state.
    if isinstance(payload, dict) and payload.get("schema_version") == 1:
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != STATE_SCHEMA
        or not isinstance(payload.get("project"), str)
        or not isinstance(payload.get("successes"), dict)
    ):
        raise CollectionGateError(f"invalid cooldown state schema: {path}")
    successes = payload["successes"]
    if any(key not in VALID_COLLECTION_KEYS for key in successes):
        raise CollectionGateError(f"invalid cooldown state collection key: {path}")
    for key, record in successes.items():
        raw_epoch = record.get("successful_epoch") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or isinstance(raw_epoch, bool)
            or not isinstance(raw_epoch, (int, float))
            or not math.isfinite(float(raw_epoch))
            or not isinstance(record.get("successful_at"), str)
            or len(record["successful_at"]) > 128
        ):
            raise CollectionGateError(
                f"invalid cooldown state record for {key}: {path}"
            )
        try:
            _iso_at(float(raw_epoch))
        except CollectionGateError as exc:
            raise CollectionGateError(
                f"invalid cooldown state record for {key}: {path}"
            ) from exc
    return payload


def _write_state(path: Path, payload: dict) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".switch-collection-cooldown.", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


class CollectionGate:
    """Serialize collectors globally while cooling down collection domains independently."""

    def __init__(
        self,
        project: str,
        scope: str,
        *,
        collection_keys: Optional[tuple[str, ...]] = None,
        enforce_cooldown: bool = True,
        status_dir: Path = DEFAULT_STATUS_DIR,
        cooldown_seconds: int = COOLDOWN_SECONDS,
        clock: Callable[[], float] = time.time,
        lock_wait_seconds: float = 0.0,
        cancel_check: Optional[Callable[[], bool]] = None,
        wait_callback: Optional[Callable[[GateDecision], None]] = None,
        sleeper: Callable[[float], None] = time.sleep,
        poll_seconds: float = 1.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not project:
            raise CollectionGateError("collection project identity is empty")
        scope_keys = collection_keys_for_scope(scope)
        if cooldown_seconds < 0:
            raise CollectionGateError("collection cooldown cannot be negative")
        requested_keys = scope_keys if collection_keys is None else collection_keys
        selected = tuple(dict.fromkeys(requested_keys))
        if (
            not selected
            or any(key not in VALID_COLLECTION_KEYS for key in selected)
            or any(key not in scope_keys for key in selected)
        ):
            raise CollectionGateError(
                f"invalid collection keys for scope {scope}: {selected}"
            )
        self.project = project
        self.scope = scope
        self.collection_keys = selected
        self.enforce_cooldown = bool(enforce_cooldown)
        self.status_dir = Path(status_dir)
        self.cooldown_seconds = int(cooldown_seconds)
        self.clock = clock
        try:
            self.lock_wait_seconds = float(lock_wait_seconds)
            self.poll_seconds = float(poll_seconds)
        except (TypeError, ValueError) as exc:
            raise CollectionGateError("invalid collection gate wait interval") from exc
        if (
            not math.isfinite(self.lock_wait_seconds)
            or self.lock_wait_seconds < 0
            or not math.isfinite(self.poll_seconds)
            or self.poll_seconds <= 0
        ):
            raise CollectionGateError("invalid collection gate wait interval")
        self.cancel_check = cancel_check
        self.wait_callback = wait_callback
        self.sleeper = sleeper
        self.poll_seconds = max(self.poll_seconds, 0.05)
        self.monotonic = monotonic
        self._lock_fd = -1
        self.decision = GateDecision(False, "not_entered")

    def _check_cancelled(self) -> None:
        if self.cancel_check is not None and self.cancel_check():
            raise CollectionGateCancelled("collection gate wait was cancelled")

    def _announce_wait(self) -> None:
        if self.wait_callback is not None:
            self.wait_callback(self.decision)

    def __enter__(self) -> "CollectionGate":
        lock_path = self.status_dir / LOCK_NAME
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.status_dir.mkdir(parents=True, exist_ok=True)
            self._lock_fd = os.open(lock_path, flags, 0o600)
            metadata = os.fstat(self._lock_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise CollectionGateError(f"invalid collection gate lock: {lock_path}")
            os.fchmod(self._lock_fd, 0o600)
            wait_deadline = float(self.monotonic()) + self.lock_wait_seconds
            while True:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    now = float(self.monotonic())
                    wait_remaining = max(0.0, wait_deadline - now)
                    self.decision = GateDecision(
                        False, "busy", int(math.ceil(wait_remaining)),
                    )
                    if self.lock_wait_seconds <= 0 or wait_remaining <= 0:
                        os.close(self._lock_fd)
                        self._lock_fd = -1
                        return self
                    self._announce_wait()
                    self._check_cancelled()
                    self.sleeper(min(self.poll_seconds, wait_remaining))

            state = _read_state(self.status_dir / STATE_NAME)
            if (
                self.enforce_cooldown
                and state is not None
                and state["project"] == self.project
            ):
                now = float(self.clock())
                cooling: list[tuple[int, float, str]] = []
                for key in self.collection_keys:
                    record = state["successes"].get(key)
                    if record is None:
                        break
                    last_epoch = float(record["successful_epoch"])
                    remaining = max(
                        0,
                        int(math.ceil(
                            last_epoch + self.cooldown_seconds - now
                        )),
                    )
                    if remaining <= 0:
                        break
                    cooling.append((
                        remaining, last_epoch, record["successful_at"],
                    ))
                if len(cooling) == len(self.collection_keys):
                    # A multi-domain manual request is skipped only while all
                    # requested domains remain in cooldown.  Cooldown is never
                    # waited under the global lock; callers receive the skip
                    # immediately and can decide when to request another run.
                    remaining, last_epoch, successful_at = min(
                        cooling, key=lambda item: item[0],
                    )
                    self.decision = GateDecision(
                        False,
                        "cooldown",
                        remaining,
                        successful_at,
                        _iso_at(last_epoch + self.cooldown_seconds),
                    )
                    return self
            self.decision = GateDecision(True, "allowed")
            return self
        except OSError as exc:
            if self._lock_fd >= 0:
                try:
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = -1
            raise CollectionGateError(
                f"cannot acquire collection gate {lock_path}: {exc}"
            ) from exc
        except Exception:
            if self._lock_fd >= 0:
                try:
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = -1
            raise

    def mark_success(self) -> str:
        if self._lock_fd < 0 or not self.decision.allowed:
            raise CollectionGateError("cannot commit a collection without an active gate")
        try:
            epoch = float(self.clock())
            successful_at = _iso_at(epoch)
            state = _read_state(self.status_dir / STATE_NAME)
            successes = {}
            if state is not None and state["project"] == self.project:
                successes.update(state["successes"])
            for key in self.collection_keys:
                successes[key] = {
                    "successful_epoch": epoch,
                    "successful_at": successful_at,
                }
            _write_state(
                self.status_dir / STATE_NAME,
                {
                    "schema_version": STATE_SCHEMA,
                    "project": self.project,
                    "successes": successes,
                    "cooldown_seconds": self.cooldown_seconds,
                },
            )
            return successful_at
        except CollectionGateError:
            raise
        except OSError as exc:
            raise CollectionGateError(
                f"cannot write collection gate state: {exc}"
            ) from exc

    def __exit__(self, _type, _value, _traceback) -> None:
        if self._lock_fd >= 0:
            release_error = None
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            except OSError as exc:
                release_error = exc
            finally:
                try:
                    os.close(self._lock_fd)
                except OSError as exc:
                    release_error = release_error or exc
                self._lock_fd = -1
            if release_error is not None and _value is None:
                raise CollectionGateError(
                    f"cannot release collection gate: {release_error}"
                ) from release_error
