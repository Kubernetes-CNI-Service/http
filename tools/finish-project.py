#!/usr/bin/env python3
"""Create a resumable, fail-closed finished-project bundle."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from tools.deployment_lock import deployment_lock
from tools.finished_bundle import (
    BundleResult,
    create_finished_bundle,
    inventory_tree,
    verify_finished_bundle,
)
from tools import finished_project_state as state


FOOTPRINT_NAME = "deployment-footprint.json"


class FinishProjectError(RuntimeError):
    """The requested project cannot be safely planned or finished."""


@dataclass(frozen=True)
class FinishResult:
    transaction_id: str
    bundle_path: Path
    record_id: str
    content_sha256: str


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_project(repository: Path, project_name: str) -> Path:
    repository = Path(repository).resolve(strict=True)
    if not state.PROJECT_PATTERN.fullmatch(project_name):
        raise FinishProjectError("project name is invalid")
    day0 = repository / "DAY0-Prepare"
    try:
        day0_real = day0.resolve(strict=True)
        candidate = day0 / project_name
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise FinishProjectError("project must be a real direct child of DAY0-Prepare") from exc
    if (
        candidate.is_symlink()
        or not candidate.is_dir()
        or resolved.parent != day0_real
        or resolved != candidate.absolute()
        or not os.path.isdir(candidate)
        or not metadata.st_nlink
    ):
        raise FinishProjectError("project must be a real direct child of DAY0-Prepare")
    return resolved


def _read_footprint(state_root: Path, project_name: str) -> tuple[dict[str, Any], bool]:
    path = Path(state_root) / FOOTPRINT_NAME
    if not os.path.lexists(path):
        return ({
            "schema_version": 1,
            "project": project_name,
            "legacy_without_footprint": True,
            "paths": [],
        }, True)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FinishProjectError(f"deployment footprint is invalid: {exc}") from exc
    if not isinstance(value, dict) or value.get("project") != project_name:
        raise FinishProjectError("deployment footprint project identity does not match")
    return value, False


def build_plan(
    *, repository: Path, project_name: str, runtime: str,
    state_root: Path = state.FINISH_STATE_ROOT,
) -> dict[str, Any]:
    if runtime not in {"native", "docker"}:
        raise FinishProjectError("runtime must be native or docker")
    project = resolve_project(repository, project_name)
    project_inventory = inventory_tree(project)
    footprint, legacy = _read_footprint(Path(state_root), project_name)
    total_bytes = sum(
        int(row.get("size", 0)) for row in project_inventory.values()
        if row["type"] == "file"
    )
    return {
        "schema_version": 1,
        "project": project_name,
        "project_path": str(project),
        "runtime": runtime,
        "project_objects": len(project_inventory),
        "project_bytes": total_bytes,
        "legacy_without_footprint": legacy,
        "requires_runtime_only_stop": legacy,
        "deletion_class": "CONDITIONAL" if legacy else "SAFE_TO_REVIEW",
        "footprint_sha256": hashlib.sha256(_canonical_json(footprint)).hexdigest(),
        "automatic_deletion": False,
        "installed_packages_retained": True,
    }


def _copy_snapshot(source: Path, destination: Path) -> None:
    inventory_tree(source)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging = destination.with_name(f".{destination.name}.staging")
    if os.path.lexists(staging):
        metadata = staging.lstat()
        if staging.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise FinishProjectError("pre-stop staging identity is unsafe")
        shutil.rmtree(staging)
    if os.path.lexists(destination):
        raise FinishProjectError("pre-stop snapshot already exists")
    try:
        shutil.copytree(source, staging, symlinks=True)
        inventory_tree(staging)
        if os.path.lexists(destination):
            raise FinishProjectError("pre-stop snapshot appeared during publication")
        os.rename(staging, destination)
        descriptor = os.open(
            destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        inventory_tree(destination)
    finally:
        if os.path.lexists(staging):
            if staging.is_symlink() or not staging.is_dir():
                raise FinishProjectError("pre-stop staging identity changed")
            shutil.rmtree(staging)


def stop_runtime(
    *, repository: Path, project_name: str, runtime: str,
    transaction_id: str,
) -> dict[str, Any]:
    if runtime == "native":
        command = [
            sys.executable,
            str(Path(repository) / "DAY0-Prepare/13-unload.py"),
            project_name,
            "--stop-only",
            "--yes",
            "--finish-transaction",
            transaction_id,
        ]
        backend = "systemd"
    elif runtime == "docker":
        command = [
            str(Path(repository) / "infra/docker/deploy.sh"),
            "stop",
            transaction_id,
        ]
        backend = "supervisor"
    else:
        raise FinishProjectError("runtime must be native or docker")
    completed = subprocess.run(
        command, cwd=repository, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise FinishProjectError(
            f"{runtime} stop-only failed with status {completed.returncode}: "
            f"{completed.stdout[-2000:]}"
        )
    return {"stopped": True, "backend": backend, "status": completed.returncode}


def _pending(
    *, transaction_id: str, project_name: str, runtime: str, created_at: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "project": project_name,
        "runtime": runtime,
        "source_manifest_sha256": None,
        "release_sha256": None,
        "created_at": created_at,
    }


def _finish_after_runtime_stopping(
    *, repository: Path, project: Path, project_name: str, runtime: str,
    transaction_id: str, created_at: str, state_root: Path,
    transaction_dir: Path, pre_stop: Path, footprint: dict[str, Any],
    legacy: bool, runtime_already_stopped: bool = False,
    resumable_stage: str = "final_delta_building",
) -> FinishResult:
    if runtime_already_stopped:
        receipt = state.read_transaction(transaction_id, root=state_root)
        stopped = receipt["evidence"].get("runtime")
        if not isinstance(stopped, dict) or stopped.get("stopped") is not True:
            raise FinishProjectError("durable stopped evidence is missing")
    else:
        stopped = stop_runtime(
            repository=repository,
            project_name=project_name,
            runtime=runtime,
            transaction_id=transaction_id,
        )
        if stopped.get("stopped") is not True:
            raise FinishProjectError("stop backend did not provide stopped evidence")
        state.advance_transaction(
            transaction_id, "runtime_stopped", root=state_root,
            evidence={"runtime": stopped},
        )
        state.advance_transaction(
            transaction_id, "final_delta_building", root=state_root,
        )
        resumable_stage = "final_delta_building"
    components = transaction_dir / "components"
    bundle_path = components / f"http-ztp-finished-{project_name}-{transaction_id}.tar.gz"
    deletion_plan = {
        "schema_version": 1,
        "project": project_name,
        "legacy_without_footprint": legacy,
        "categories": {
            "SAFE_TO_REVIEW": [] if legacy else footprint.get("paths", []),
            "CONDITIONAL": footprint.get("paths", []) if legacy else [],
            "PRESERVE": [str(bundle_path), str(transaction_dir)],
        },
        "automatic_deletion": False,
    }
    if resumable_stage not in {
        "final_delta_building", "final_delta_complete", "bundle_finalizing",
    }:
        raise FinishProjectError(
            f"cannot finalize bundle from stage {resumable_stage}"
        )
    if not os.path.lexists(bundle_path):
        if resumable_stage != "final_delta_building":
            raise FinishProjectError("durable finished bundle is missing")
        create_finished_bundle(
            project=project_name,
            transaction_id=transaction_id,
            runtime=runtime,
            created_at=created_at,
            pre_stop_project=pre_stop,
            post_stop_project=project,
            deployment_source=repository,
            host_state={
                "schema_version": 1,
                "project": project_name,
                "runtime": runtime,
                "runtime_stopped": True,
                "stop_evidence": stopped,
                "installed_packages_retained": True,
                "infra_state_retained": True,
            },
            deployment_footprint=footprint,
            deletion_plan=deletion_plan,
            output=bundle_path,
        )
    bundle: BundleResult = verify_finished_bundle(
        bundle_path,
        expected_project=project_name,
        expected_transaction_id=transaction_id,
        expected_runtime=runtime,
        expected_created_at=created_at,
    )
    bundle_sha256 = _sha256_file(bundle.path)
    bundle_evidence = {
        "bundle_path": str(bundle.path),
        "bundle_sha256": bundle_sha256,
        "record_id": bundle.record_id,
        "content_sha256": bundle.content_sha256,
        "bundle_size": bundle.path.stat().st_size,
    }
    if resumable_stage == "final_delta_building":
        state.advance_transaction(
            transaction_id, "final_delta_complete", root=state_root,
            evidence=bundle_evidence,
        )
        resumable_stage = "final_delta_complete"
    else:
        receipt = state.read_transaction(transaction_id, root=state_root)
        for key, expected in bundle_evidence.items():
            if receipt["evidence"].get(key) != expected:
                raise FinishProjectError(
                    f"durable bundle evidence does not match bytes: {key}"
                )
    if resumable_stage == "final_delta_complete":
        state.advance_transaction(
            transaction_id, "bundle_finalizing", root=state_root,
        )
        resumable_stage = "bundle_finalizing"
    state.advance_transaction(
        transaction_id, "completed", root=state_root,
        evidence=bundle_evidence,
    )
    state.clear_finish_pending(transaction_id, root=state_root)
    return FinishResult(
        transaction_id, bundle.path, bundle.record_id, bundle.content_sha256,
    )


def execute_finish(
    *, repository: Path, project_name: str, runtime: str,
    state_root: Path = state.FINISH_STATE_ROOT,
    transaction_id: str, created_at: str,
    runtime_only_stop: bool = False,
) -> FinishResult:
    repository = Path(repository).resolve(strict=True)
    state_root = Path(state_root)
    project = resolve_project(repository, project_name)
    footprint, legacy = _read_footprint(state_root, project_name)
    if legacy and not runtime_only_stop:
        raise FinishProjectError(
            "no trustworthy deployment footprint; inspect plan and explicitly "
            "select --runtime-only-stop to archive and stop without cleanup claims"
        )
    receipt = state.create_transaction(
        transaction_id=transaction_id,
        project=project_name,
        runtime=runtime,
        created_at=created_at,
        root=state_root,
    )
    if receipt["state"] != "planned":
        raise FinishProjectError(
            f"transaction already exists in state {receipt['state']}; use resume"
        )
    transaction_dir = state_root / state.TRANSACTIONS_NAME / transaction_id
    components = transaction_dir / "components"
    components.mkdir(mode=0o700)
    pre_stop = components / "pre-stop-project"
    try:
        state.advance_transaction(
            transaction_id, "pre_stop_archiving", root=state_root,
        )
        _copy_snapshot(project, pre_stop)
        pre_inventory = inventory_tree(pre_stop)
        state.advance_transaction(
            transaction_id, "pre_stop_complete", root=state_root,
            evidence={
                "pre_stop_objects": len(pre_inventory),
                "legacy_without_footprint": legacy,
            },
        )
        with deployment_lock(repository):
            state.create_finish_pending(
                _pending(
                    transaction_id=transaction_id,
                    project_name=project_name,
                    runtime=runtime,
                    created_at=created_at,
                ),
                root=state_root,
            )
            state.advance_transaction(
                transaction_id, "pending_committed", root=state_root,
            )
        state.advance_transaction(
            transaction_id, "runtime_stopping", root=state_root,
        )
        return _finish_after_runtime_stopping(
            repository=repository,
            project=project,
            project_name=project_name,
            runtime=runtime,
            transaction_id=transaction_id,
            created_at=created_at,
            state_root=state_root,
            transaction_dir=transaction_dir,
            pre_stop=pre_stop,
            footprint=footprint,
            legacy=legacy,
        )
    except BaseException:
        try:
            current = state.read_transaction(transaction_id, root=state_root)
            if current["state"] not in {"failed", "completed"}:
                state.advance_transaction(
                    transaction_id, "failed", root=state_root,
                    evidence={"failure_recorded": True},
                )
        except BaseException:
            pass
        raise


def execute_resume(
    *, repository: Path, transaction_id: str,
    state_root: Path = state.FINISH_STATE_ROOT,
) -> FinishResult:
    repository = Path(repository).resolve(strict=True)
    state_root = Path(state_root)
    receipt = state.read_transaction(transaction_id, root=state_root)
    if receipt["state"] == "completed":
        bundle_path = Path(str(receipt["evidence"].get("bundle_path", "")))
        if not bundle_path.is_file():
            raise FinishProjectError("completed transaction bundle is missing")
        if _sha256_file(bundle_path) != receipt["evidence"].get("bundle_sha256"):
            raise FinishProjectError("completed transaction bundle hash changed")
        bundle = verify_finished_bundle(
            bundle_path,
            expected_project=str(receipt["project"]),
            expected_transaction_id=transaction_id,
            expected_runtime=str(receipt["runtime"]),
            expected_created_at=str(receipt["created_at"]),
        )
        if (
            bundle.record_id != receipt["evidence"].get("record_id")
            or bundle.content_sha256 != receipt["evidence"].get("content_sha256")
            or bundle.path.stat().st_size != receipt["evidence"].get("bundle_size")
        ):
            raise FinishProjectError("completed transaction bundle evidence changed")
        state.clear_finish_pending(transaction_id, root=state_root)
        return FinishResult(
            transaction_id,
            bundle_path,
            bundle.record_id,
            bundle.content_sha256,
        )
    if receipt["state"] != "failed":
        raise FinishProjectError(
            f"transaction is not failed/completed: {receipt['state']}"
        )
    previous = [
        row.get("state") for row in receipt["history"]
        if isinstance(row, dict) and row.get("state") != "failed"
    ]
    resumable_stage = previous[-1] if previous else "unknown"
    if resumable_stage not in {
        "pre_stop_archiving", "pre_stop_complete", "pending_committed",
        "runtime_stopping", "final_delta_building", "final_delta_complete",
        "bundle_finalizing",
    }:
        raise FinishProjectError(
            f"resume from stage {resumable_stage} is not yet safe"
        )
    project_name = str(receipt["project"])
    runtime = str(receipt["runtime"])
    project = resolve_project(repository, project_name)
    transaction_dir = state_root / state.TRANSACTIONS_NAME / transaction_id
    pre_stop = transaction_dir / "components/pre-stop-project"
    footprint, legacy = _read_footprint(state_root, project_name)
    resume_evidence = {"resume_count": sum(
        1 for row in receipt["history"] if row.get("state") == "failed"
    )}
    try:
        state.advance_transaction(
            transaction_id, resumable_stage, root=state_root,
            evidence=resume_evidence,
        )
        if resumable_stage == "pre_stop_archiving":
            if not os.path.lexists(pre_stop):
                _copy_snapshot(project, pre_stop)
            pre_inventory = inventory_tree(pre_stop)
            state.advance_transaction(
                transaction_id, "pre_stop_complete", root=state_root,
                evidence={
                    "pre_stop_objects": len(pre_inventory),
                    "legacy_without_footprint": legacy,
                },
            )
            resumable_stage = "pre_stop_complete"
        if resumable_stage == "pre_stop_complete":
            with deployment_lock(
                repository, finish_transaction_id=transaction_id,
            ):
                state.create_finish_pending(
                    _pending(
                        transaction_id=transaction_id,
                        project_name=project_name,
                        runtime=runtime,
                        created_at=str(receipt["created_at"]),
                    ),
                    root=state_root,
                )
                state.advance_transaction(
                    transaction_id, "pending_committed", root=state_root,
                )
            resumable_stage = "pending_committed"
        pending = state.read_finish_pending(state_root)
        if pending is None or pending["transaction_id"] != transaction_id:
            raise FinishProjectError(
                "matching finish-pending authority is required for resume"
            )
        inventory_tree(pre_stop)
        if resumable_stage == "pending_committed":
            state.advance_transaction(
                transaction_id, "runtime_stopping", root=state_root,
            )
            resumable_stage = "runtime_stopping"
        return _finish_after_runtime_stopping(
            repository=repository,
            project=project,
            project_name=project_name,
            runtime=runtime,
            transaction_id=transaction_id,
            created_at=str(receipt["created_at"]),
            state_root=state_root,
            transaction_dir=transaction_dir,
            pre_stop=pre_stop,
            footprint=footprint,
            legacy=legacy,
            runtime_already_stopped=resumable_stage in {
                "final_delta_building", "final_delta_complete", "bundle_finalizing",
            },
            resumable_stage=resumable_stage,
        )
    except BaseException:
        current = state.read_transaction(transaction_id, root=state_root)
        if current["state"] not in {"failed", "completed"}:
            state.advance_transaction(
                transaction_id, "failed", root=state_root,
                evidence={"failure_recorded": True},
            )
        raise


def _new_identity() -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    created_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    transaction_id = f"finish-{now.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:16]}"
    return transaction_id, created_at


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "finish", "resume"))
    parser.add_argument("project")
    parser.add_argument("--runtime", choices=("native", "docker"), required=True)
    parser.add_argument("--transaction-id")
    parser.add_argument("--runtime-only-stop", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.action == "plan":
        print(json.dumps(build_plan(
            repository=REPOSITORY,
            project_name=args.project,
            runtime=args.runtime,
        ), sort_keys=True, indent=2))
        return 0
    if os.geteuid() != 0:
        raise FinishProjectError("finish and resume require root")
    if args.action == "resume":
        if args.transaction_id is None:
            raise FinishProjectError("resume requires --transaction-id")
        result = execute_resume(
            repository=REPOSITORY,
            transaction_id=args.transaction_id,
        )
        print(f"bundle: {result.bundle_path}")
        print(f"record: {result.record_id}")
        return 0
    transaction_id, created_at = _new_identity()
    if args.transaction_id is not None:
        raise FinishProjectError("finish creates a new transaction ID; use resume for an existing one")
    result = execute_finish(
        repository=REPOSITORY,
        project_name=args.project,
        runtime=args.runtime,
        transaction_id=transaction_id,
        created_at=created_at,
        runtime_only_stop=args.runtime_only_stop,
    )
    print(f"bundle: {result.bundle_path}")
    print(f"record: {result.record_id}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FinishProjectError, state.FinishStateError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
