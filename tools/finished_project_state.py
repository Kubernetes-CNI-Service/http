#!/usr/bin/env python3
"""Strict shared authority for finished-project deployment interlocks."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from datetime import datetime, timezone
from typing import Any


FINISH_STATE_ROOT = Path("/var/lib/http-ztp-finish")
FINISH_PENDING_NAME = "finish-pending.json"
TRANSACTION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PROJECT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
CREATED_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
PENDING_KEYS = frozenset({
    "schema_version", "transaction_id", "project", "runtime",
    "source_manifest_sha256", "release_sha256", "created_at",
})
MAX_PENDING_SIZE = 64 * 1024
TRANSACTIONS_NAME = "transactions"
TRANSACTION_NAME = "transaction.json"
MAX_TRANSACTION_SIZE = 1024 * 1024
TRANSACTION_STATES = (
    "planned",
    "pre_stop_archiving",
    "pre_stop_complete",
    "pending_committed",
    "runtime_stopping",
    "runtime_stopped",
    "final_delta_building",
    "final_delta_complete",
    "bundle_finalizing",
    "completed",
)
TRANSACTION_EDGES = frozenset(zip(TRANSACTION_STATES, TRANSACTION_STATES[1:]))
HISTORY_KEYS = frozenset({
    "state", "committed_at", "input_sha256", "output_sha256",
})


class FinishStateError(RuntimeError):
    """Finished-project authority is unsafe, invalid, or conflicting."""


def _required_owner_uid() -> int:
    return 0


def _required_owner_gid() -> int:
    return 0


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_nlink, metadata.st_size,
    )


def _validate_private_root(root: Path) -> None:
    try:
        metadata = root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FinishStateError(f"finish state root is unreadable: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise FinishStateError("finish state root must be a real directory")
    if (
        metadata.st_uid != _required_owner_uid()
        or metadata.st_gid != _required_owner_gid()
    ):
        raise FinishStateError("finish state root must be root-owned")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise FinishStateError("finish state root mode must be 0700")


def _read_json_no_duplicates(payload: bytes) -> dict[str, Any]:
    def pairs(values):
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise FinishStateError(f"finish pending has duplicate key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FinishStateError("finish pending is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise FinishStateError("finish pending must be a JSON object")
    return value


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _stage_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _history_entry(
    *, state_name: str, committed_at: str,
    input_value: dict[str, Any], output_value: dict[str, Any],
) -> dict[str, str]:
    return {
        "state": state_name,
        "committed_at": committed_at,
        "input_sha256": _stage_digest(input_value),
        "output_sha256": _stage_digest(output_value),
    }


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != _required_owner_uid()
        or metadata.st_gid != _required_owner_gid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise FinishStateError(f"private state directory identity is invalid: {path}")


def _ensure_private_root(root: Path) -> None:
    parent = root.parent
    if not parent.exists():
        raise FinishStateError(f"finish state parent does not exist: {parent}")
    _ensure_private_directory(root)


def _write_temp(parent: Path, payload: bytes) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".finish-state-", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != _required_owner_uid()
            or metadata.st_gid != _required_owner_gid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise FinishStateError("temporary state identity is invalid")
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    return temporary


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_no_replace(path: Path, payload: bytes) -> None:
    temporary = _write_temp(path.parent, payload)
    try:
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _replace_private(path: Path, payload: bytes) -> None:
    temporary = _write_temp(path.parent, payload)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _read_private_json(path: Path, *, maximum: int) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FinishStateError(f"state file is unsafe or unreadable: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        lexical = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(lexical.st_mode)
            or before.st_nlink != 1
            or lexical.st_nlink != 1
            or before.st_uid != _required_owner_uid()
            or before.st_gid != _required_owner_gid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > maximum
            or (before.st_dev, before.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise FinishStateError(f"state file identity is invalid: {path}")
        payload = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or _identity(before) != _identity(after):
            raise FinishStateError(f"state file changed while reading: {path}")
    finally:
        os.close(descriptor)
    return _read_json_no_duplicates(payload)


def _validate_pending_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) != PENDING_KEYS or payload.get("schema_version") != 1:
        raise FinishStateError("finish pending schema is invalid")
    transaction_id = payload.get("transaction_id")
    project = payload.get("project")
    if not isinstance(transaction_id, str) or not TRANSACTION_PATTERN.fullmatch(transaction_id):
        raise FinishStateError("finish pending transaction ID is invalid")
    if not isinstance(project, str) or not PROJECT_PATTERN.fullmatch(project):
        raise FinishStateError("finish pending project is invalid")
    if payload.get("runtime") not in {"native", "docker"}:
        raise FinishStateError("finish pending runtime is invalid")
    if not isinstance(payload.get("created_at"), str) or not CREATED_PATTERN.fullmatch(
        payload["created_at"]
    ):
        raise FinishStateError("finish pending created_at is invalid")
    for key in ("source_manifest_sha256", "release_sha256"):
        value = payload.get(key)
        if value is not None and (
            not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value)
        ):
            raise FinishStateError(f"finish pending {key} is invalid")
    return payload


def read_finish_pending(root: Path | None = None) -> dict[str, Any] | None:
    state_root = FINISH_STATE_ROOT if root is None else Path(root)
    _validate_private_root(state_root)
    path = state_root / FINISH_PENDING_NAME
    if not os.path.lexists(path):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FinishStateError(f"finish pending is unsafe or unreadable: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or before.st_nlink != 1
            or path_metadata.st_nlink != 1
            or before.st_uid != _required_owner_uid()
            or before.st_gid != _required_owner_gid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > MAX_PENDING_SIZE
            or (before.st_dev, before.st_ino) != (
                path_metadata.st_dev, path_metadata.st_ino,
            )
        ):
            raise FinishStateError("finish pending authority identity is invalid")
        payload = os.read(descriptor, MAX_PENDING_SIZE + 1)
        if len(payload) != before.st_size:
            raise FinishStateError("finish pending size changed while reading")
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise FinishStateError("finish pending changed while reading")
    finally:
        os.close(descriptor)
    return _validate_pending_payload(_read_json_no_duplicates(payload))


def create_finish_pending(
    payload: dict[str, Any], *, root: Path | None = None,
) -> dict[str, Any]:
    validated = _validate_pending_payload(dict(payload))
    state_root = FINISH_STATE_ROOT if root is None else Path(root)
    _ensure_private_root(state_root)
    existing = read_finish_pending(state_root)
    if existing is not None:
        if existing == validated:
            return existing
        raise FinishStateError(
            f"different finish transaction owns pending state: {existing['transaction_id']}"
        )
    try:
        _publish_no_replace(
            state_root / FINISH_PENDING_NAME, _canonical_json(validated),
        )
    except FileExistsError:
        existing = read_finish_pending(state_root)
        if existing == validated:
            return existing
        owner = existing["transaction_id"] if existing else "unknown"
        raise FinishStateError(
            f"different finish transaction owns pending state: {owner}"
        )
    return read_finish_pending(state_root) or validated


def clear_finish_pending(
    transaction_id: str, *, root: Path | None = None,
) -> None:
    if not TRANSACTION_PATTERN.fullmatch(transaction_id):
        raise FinishStateError("finish transaction ID is invalid")
    state_root = FINISH_STATE_ROOT if root is None else Path(root)
    existing = read_finish_pending(state_root)
    if existing is None:
        return
    if existing["transaction_id"] != transaction_id:
        raise FinishStateError(
            f"different finish transaction owns pending state: {existing['transaction_id']}"
        )
    path = state_root / FINISH_PENDING_NAME
    before = path.lstat()
    current = read_finish_pending(state_root)
    after = path.lstat()
    if current != existing or _identity(before) != _identity(after):
        raise FinishStateError("finish pending changed before clear")
    path.unlink()
    _fsync_directory(state_root)


def _transaction_directory(root: Path, transaction_id: str) -> Path:
    if not TRANSACTION_PATTERN.fullmatch(transaction_id):
        raise FinishStateError("finish transaction ID is invalid")
    return root / TRANSACTIONS_NAME / transaction_id


def _validate_transaction(value: dict[str, Any], transaction_id: str) -> dict[str, Any]:
    expected = {
        "schema_version", "transaction_id", "project", "runtime", "created_at",
        "state", "evidence", "history",
    }
    if set(value) != expected or value.get("schema_version") != 1:
        raise FinishStateError("finish transaction schema is invalid")
    if value.get("transaction_id") != transaction_id:
        raise FinishStateError("finish transaction identity is invalid")
    if not isinstance(value.get("project"), str) or not PROJECT_PATTERN.fullmatch(value["project"]):
        raise FinishStateError("finish transaction project is invalid")
    if value.get("runtime") not in {"native", "docker"}:
        raise FinishStateError("finish transaction runtime is invalid")
    if not isinstance(value.get("created_at"), str) or not CREATED_PATTERN.fullmatch(value["created_at"]):
        raise FinishStateError("finish transaction created_at is invalid")
    if value.get("state") not in {*TRANSACTION_STATES, "failed"}:
        raise FinishStateError("finish transaction state is invalid")
    if not isinstance(value.get("evidence"), dict) or not isinstance(value.get("history"), list):
        raise FinishStateError("finish transaction evidence/history is invalid")
    history = value["history"]
    if not history:
        raise FinishStateError("finish transaction history is empty")
    previous_output = None
    for index, row in enumerate(history):
        if not isinstance(row, dict) or set(row) != HISTORY_KEYS:
            raise FinishStateError("finish transaction history schema is invalid")
        if row.get("state") not in {*TRANSACTION_STATES, "failed"}:
            raise FinishStateError("finish transaction history state is invalid")
        if not isinstance(row.get("committed_at"), str) or not CREATED_PATTERN.fullmatch(
            row["committed_at"]
        ):
            raise FinishStateError("finish transaction history time is invalid")
        for key in ("input_sha256", "output_sha256"):
            if not isinstance(row.get(key), str) or not SHA256_PATTERN.fullmatch(row[key]):
                raise FinishStateError(f"finish transaction history {key} is invalid")
        if index and row["input_sha256"] != previous_output:
            raise FinishStateError("finish transaction history digest chain is invalid")
        previous_output = row["output_sha256"]
    if history[-1]["state"] != value["state"]:
        raise FinishStateError("finish transaction history does not match current state")
    return value


def read_transaction(
    transaction_id: str, *, root: Path | None = None,
) -> dict[str, Any]:
    state_root = FINISH_STATE_ROOT if root is None else Path(root)
    _validate_private_root(state_root)
    directory = _transaction_directory(state_root, transaction_id)
    for candidate in (state_root / TRANSACTIONS_NAME, directory):
        metadata = candidate.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or candidate.is_symlink()
            or metadata.st_uid != _required_owner_uid()
            or metadata.st_gid != _required_owner_gid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise FinishStateError(f"transaction directory identity is invalid: {candidate}")
    value = _read_private_json(directory / TRANSACTION_NAME, maximum=MAX_TRANSACTION_SIZE)
    return _validate_transaction(value, transaction_id)


def create_transaction(
    *, transaction_id: str, project: str, runtime: str, created_at: str,
    root: Path | None = None,
) -> dict[str, Any]:
    state_root = FINISH_STATE_ROOT if root is None else Path(root)
    _ensure_private_root(state_root)
    transactions = state_root / TRANSACTIONS_NAME
    _ensure_private_directory(transactions)
    directory = _transaction_directory(state_root, transaction_id)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        return read_transaction(transaction_id, root=state_root)
    identity = {
        "created_at": created_at,
        "project": project,
        "runtime": runtime,
        "transaction_id": transaction_id,
    }
    initial_output = {"evidence": {}, "state": "planned"}
    value = _validate_transaction({
        "schema_version": 1,
        "transaction_id": transaction_id,
        "project": project,
        "runtime": runtime,
        "created_at": created_at,
        "state": "planned",
        "evidence": {},
        "history": [_history_entry(
            state_name="planned",
            committed_at=created_at,
            input_value=identity,
            output_value=initial_output,
        )],
    }, transaction_id)
    try:
        _publish_no_replace(directory / TRANSACTION_NAME, _canonical_json(value))
        _fsync_directory(transactions)
    except BaseException:
        try:
            directory.rmdir()
        except OSError:
            pass
        raise
    return read_transaction(transaction_id, root=state_root)


def advance_transaction(
    transaction_id: str, new_state: str, *, root: Path | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state_root = FINISH_STATE_ROOT if root is None else Path(root)
    current = read_transaction(transaction_id, root=state_root)
    old_state = str(current["state"])
    if old_state == new_state:
        return current
    if old_state == "failed":
        previous_states = [
            row.get("state") for row in current["history"]
            if isinstance(row, dict) and row.get("state") != "failed"
        ]
        allowed = bool(previous_states) and new_state == previous_states[-1]
    elif new_state == "failed":
        allowed = old_state != "completed"
    else:
        allowed = (old_state, new_state) in TRANSACTION_EDGES
    if not allowed:
        raise FinishStateError(
            f"invalid finish transaction transition: {old_state} -> {new_state}"
        )
    updated = dict(current)
    updated["state"] = new_state
    merged = dict(current["evidence"])
    if evidence:
        merged.update(evidence)
    updated["evidence"] = merged
    input_value = {"evidence": current["evidence"], "state": old_state}
    output_value = {"evidence": merged, "state": new_state}
    updated["history"] = [*current["history"], _history_entry(
        state_name=new_state,
        committed_at=_utc_now(),
        input_value=input_value,
        output_value=output_value,
    )]
    validated = _validate_transaction(updated, transaction_id)
    path = _transaction_directory(state_root, transaction_id) / TRANSACTION_NAME
    before = path.lstat()
    if read_transaction(transaction_id, root=state_root) != current:
        raise FinishStateError("finish transaction changed before update")
    after = path.lstat()
    if _identity(before) != _identity(after):
        raise FinishStateError("finish transaction identity changed before update")
    _replace_private(path, _canonical_json(validated))
    return read_transaction(transaction_id, root=state_root)


def assert_writer_allowed(
    *, finish_transaction_id: str | None = None,
) -> dict[str, Any] | None:
    pending = read_finish_pending()
    if pending is None:
        return None
    owner = str(pending["transaction_id"])
    project = str(pending["project"])
    if finish_transaction_id is None:
        raise FinishStateError(
            "finish transaction is pending for project "
            f"{project}; owner={owner}; use finish-project.py resume "
            f"--transaction-id {owner}"
        )
    if finish_transaction_id != owner:
        raise FinishStateError(
            f"different finish transaction owns pending state: {owner}"
        )
    return pending
