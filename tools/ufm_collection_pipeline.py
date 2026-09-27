#!/usr/bin/env python3
"""Local deployment-side handoff for one D-70 iblinkinfo archive.

This entry point has no UFM connection, cron trigger, or credential handling.
The archive must already have been retrieved from a verified real node.  It
bridges the D-70 tar.gz product to the existing analyzer's raw-log input, then
publishes one run-bound private result for the monitor's UFM-only evidence slot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Callable
import zipfile

# Direct execution may start outside the repository; import only this fixed
# adjacent contract, never modules resolved from the operator's cwd.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from tools.ufm_collection_contract import CollectionPlan, collection_plan
from ztp.config.ib_topology_provenance import (
    ProvenanceError, read_report_provenance, sidecar_path,
)


class PipelineError(ValueError):
    """The local handoff cannot safely claim a complete UFM result."""


_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_REPORT_SUFFIX = "-topology-validation.xlsx"
_MAX_ARCHIVE_MEMBER = 64 * 1024 * 1024
_ANALYZER = Path(__file__).resolve().parent / "ibdiagnet-analyze-tool" / "analyze.py"
_PROFILE_CATALOG = _ANALYZER.parent / "config" / "port_profiles.csv"


def _regular(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except (OSError, PipelineError):
        return False


def _real_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _fsync_regular(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PipelineError("staged artifact changed type")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise PipelineError("output directory changed type")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_real_dir(path: Path) -> int:
    descriptor = os.open(path, _DIR_FLAGS)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PipelineError("UFM output root is not a real directory")
    return descriptor


def _open_child_dir(parent_fd: int, name: str) -> int:
    descriptor = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PipelineError("UFM output child is not a real directory")
    return descriptor


def _prepare_output_parents(root_fd: int, plan: CollectionPlan) -> int:
    """Return a held run-directory fd, never a re-resolved output path."""
    parent_fd = os.dup(root_fd)
    try:
        for component in ("99-output-ufm", "runs", plan.run_id):
            try:
                os.mkdir(component, 0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileExistsError:
                pass
            child_fd = _open_child_dir(parent_fd, component)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def _read_regular_at(parent_fd: int, name: str, *, max_bytes: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                         dir_fd=parent_fd)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size <= 0 or observed.st_size > max_bytes:
            raise PipelineError("UFM receipt component is not bounded regular data")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise PipelineError("UFM receipt component exceeded bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _copy_regular_to_at(source: Path, destination_fd: int, name: str) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(source, os.O_RDONLY | nofollow)
    target_fd: int | None = None
    try:
        observed = os.fstat(source_fd)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size <= 0:
            raise PipelineError("staged UFM artifact is not nonempty regular data")
        target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                            0o600, dir_fd=destination_fd)
        total = 0
        while chunk := os.read(source_fd, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise PipelineError("short UFM publication write")
                total += written
                view = view[written:]
        if total != observed.st_size:
            raise PipelineError("staged UFM artifact changed during publication")
        os.fsync(target_fd)
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(source_fd)


def _digest_regular_at(parent_fd: int, name: str, *, max_bytes: int) -> str:
    """Digest a held result member and reject a name/inode change during read."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise PipelineError("platform cannot bind IB result reads")
    descriptor = os.open(name, os.O_RDONLY | nofollow, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= max_bytes:
            raise PipelineError("published IB result is not bounded regular data")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise PipelineError("published IB result exceeded its size bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        for current in (after, named):
            if (current.st_dev, current.st_ino, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns) != (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            ):
                raise PipelineError("published IB result changed during verification")
        if total != before.st_size:
            raise PipelineError("published IB result was truncated")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _publish_result_sidecar_at(parent_fd: int, name: str,
                               record: dict[str, object]) -> None:
    """Publish the IB schema in a held node directory with atomic no-clobber."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (not nofollow or type(name) is not str or len(name) > 200
            or not re.fullmatch(r"[A-Za-z0-9_.-]+\.provenance\.json", name)
            or ".." in name or type(record) is not dict):
        raise PipelineError("IB provenance publication is unavailable")
    data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > 16 * 1024:
        raise PipelineError("IB provenance sidecar exceeds its size bound")
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    created_inode: tuple[int, int] | None = None
    final_created = False
    completed = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                             0o600, dir_fd=parent_fd)
        try:
            created = os.fstat(descriptor)
            created_inode = (created.st_dev, created.st_ino)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise PipelineError("IB provenance write was incomplete")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        named = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != created_inode:
            raise PipelineError("IB provenance temporary was replaced")
        os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                follow_symlinks=False)
        final_created = True
        published = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (published.st_dev, published.st_ino) != created_inode:
            raise PipelineError("IB provenance final was replaced")
        os.fsync(parent_fd)
        current = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != created_inode:
            raise PipelineError("IB provenance temporary changed before cleanup")
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
        completed = True
    except OSError as exc:
        raise PipelineError("IB provenance could not be published") from exc
    finally:
        if not completed and created_inode is not None:
            for candidate in (name if final_created else None, temporary):
                if candidate is None:
                    continue
                try:
                    current = os.stat(candidate, dir_fd=parent_fd,
                                      follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == created_inode:
                        os.unlink(candidate, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass


def _result_chain_still_bound(root_fd: int, plan: CollectionPlan, node: str,
                              run_fd: int, target_fd: int) -> bool:
    """Check the current public names against held run and node directories."""
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        return False
    descriptors: list[int] = []
    try:
        parent_fd = root_fd
        for component in ("99-output-ufm", "runs", plan.run_id, node):
            parent_fd = _open_child_dir(parent_fd, component)
            descriptors.append(parent_fd)
        return all(
            (os.fstat(opened).st_dev, os.fstat(opened).st_ino)
            == (os.fstat(held).st_dev, os.fstat(held).st_ino)
            for opened, held in ((descriptors[2], run_fd), (descriptors[3], target_fd))
        )
    except (OSError, PipelineError):
        return False
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _same_root_inode(path: Path, held_fd: int) -> bool:
    try:
        current_fd = _open_real_dir(path)
    except (OSError, PipelineError):
        return False
    try:
        held = os.fstat(held_fd)
        current = os.fstat(current_fd)
        return (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)
    finally:
        os.close(current_fd)


def _validate_args(plan: CollectionPlan, node: str, archive: Path,
                   cvt: Path, project_root: Path) -> None:
    if not isinstance(plan, CollectionPlan) or plan != collection_plan(plan.kind, plan.run_id):
        raise PipelineError("noncanonical collection plan")
    if plan.kind != "iblinkinfo":
        raise PipelineError("only the iblinkinfo local handoff is implemented")
    if type(node) is not str or _NODE_RE.fullmatch(node) is None or node in {".", ".."}:
        raise PipelineError("invalid real-node label")
    if any(not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts
           for path in (archive, cvt, project_root)):
        raise PipelineError("handoff paths must be absolute without traversal")
    if archive.name != plan.archive_name or not _regular(archive) or archive.stat().st_size == 0:
        raise PipelineError("exact completed archive is unavailable")
    if not _regular(cvt) or cvt.stat().st_size == 0:
        raise PipelineError("CVT workbook is unavailable")
    if not _real_directory(project_root):
        raise PipelineError("project root must be a real directory")


def _read_one_log(archive: Path) -> bytes:
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) != 1 or members[0].name != "artifact" or not members[0].isfile():
                raise PipelineError("iblinkinfo archive must contain one regular artifact")
            if members[0].size <= 0 or members[0].size > _MAX_ARCHIVE_MEMBER:
                raise PipelineError("iblinkinfo artifact has invalid size")
            stream = bundle.extractfile(members[0])
            if stream is None:
                raise PipelineError("iblinkinfo artifact cannot be read")
            with stream:
                content = stream.read(_MAX_ARCHIVE_MEMBER + 1)
            if len(content) != members[0].size or not content:
                raise PipelineError("iblinkinfo artifact is truncated or empty")
            return content
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise PipelineError("iblinkinfo archive is invalid") from exc


def _report_name(plan: CollectionPlan) -> str:
    return f"iblinkinfo_{plan.run_id}{_REPORT_SUFFIX}"


def _staged_analysis_attestation(report: Path, log: Path, cvt: Path) -> dict:
    """Accept only the real analyzer's attestation of these exact input bytes."""
    try:
        record = read_report_provenance(report)
        paths = {
            "report": report, "actual": log, "cvt": cvt,
            "profile": _PROFILE_CATALOG,
        }
        if any(record[name]["resolved_path"] != str(path.resolve(strict=True))
               or record[name]["sha256"] != _sha256(path)
               for name, path in paths.items()):
            raise PipelineError("IB analysis attests a different source set")
        return record
    except (OSError, ProvenanceError, KeyError, TypeError) as exc:
        raise PipelineError("IB analysis provenance is missing or invalid") from exc


def run_local_iblinkinfo(plan: CollectionPlan, node: str, archive: Path,
                         cvt: Path, project_root: Path, *,
                         before_receipt: Callable[[], None] | None = None,
                         prepare_panel: Callable[[dict[str, str]], None] | None = None) -> Path:
    """Analyze one local complete archive and publish a run-bound result.

    External UFM collection/identity and remote copy are deliberately outside
    this function.  The caller must hold the project's single-writer lease.
    """
    if before_receipt is not None and not callable(before_receipt):
        raise PipelineError("pre-receipt evidence gate is invalid")
    if prepare_panel is not None and not callable(prepare_panel):
        raise PipelineError("pre-receipt panel preparation is invalid")
    _validate_args(plan, node, archive, cvt, project_root)
    content = _read_one_log(archive)
    target = project_root / "99-output-ufm" / "runs" / plan.run_id / node
    if target.exists() or target.is_symlink():
        raise PipelineError("run-bound result already exists")

    root_fd = _open_real_dir(project_root)
    try:
        stage = Path(tempfile.mkdtemp(prefix=".ufm-handoff-"))
    except BaseException:
        os.close(root_fd)
        raise
    cleanup_attempted = False
    try:
        os.chmod(stage, 0o700)
        staged_archive = stage / plan.archive_name
        shutil.copyfile(archive, staged_archive, follow_symlinks=False)
        if _sha256(staged_archive) != _sha256(archive):
            raise PipelineError("staged archive differs from source")
        log = stage / f"iblinkinfo_{plan.run_id}.log"
        log.write_bytes(content)
        report = stage / _report_name(plan)
        try:
            result = subprocess.run(
                [sys.executable, str(_ANALYZER), "--iblinkinfo", str(log),
                 "--p2p", str(cvt), "--output", str(report)],
                capture_output=True, text=True, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PipelineError("iblinkinfo analysis did not complete") from exc
        if result.returncode != 0 or not _regular(report) or report.stat().st_size == 0:
            raise PipelineError("iblinkinfo analysis failed; no receipt published")
        try:
            with zipfile.ZipFile(report) as workbook:
                if workbook.testzip() is not None or "xl/workbook.xml" not in workbook.namelist():
                    raise PipelineError("analysis workbook is incomplete")
        except (OSError, zipfile.BadZipFile) as exc:
            raise PipelineError("analysis workbook is invalid") from exc
        stage_attestation = _staged_analysis_attestation(report, log, cvt)
        for staged_file in (staged_archive, log, report, sidecar_path(report)):
            _fsync_regular(staged_file)
        _fsync_directory(stage)
        run_fd = _prepare_output_parents(root_fd, plan)
        try:
            if not _same_root_inode(project_root, root_fd):
                raise PipelineError("project root was rebound during UFM handoff")
            try:
                os.mkdir(node, 0o700, dir_fd=run_fd)
            except FileExistsError as exc:
                raise PipelineError("run-bound result already exists") from exc
            target_fd = _open_child_dir(run_fd, node)
            try:
                for staged_file in (staged_archive, log, report):
                    _copy_regular_to_at(staged_file, target_fd, staged_file.name)
                os.fsync(target_fd)
                final_report = target / report.name
                final_log = target / log.name
                if (not _same_root_inode(project_root, root_fd)
                        or not _result_chain_still_bound(
                            root_fd, plan, node, run_fd, target_fd)):
                    raise PipelineError("UFM result path was rebound before IB provenance")
                try:
                    if read_report_provenance(report) != stage_attestation:
                        raise PipelineError("staged IB analysis provenance changed")
                    expected = {
                        plan.archive_name: _sha256(staged_archive),
                        log.name: stage_attestation["actual"]["sha256"],
                        report.name: stage_attestation["report"]["sha256"],
                    }
                    for name, digest in expected.items():
                        if _digest_regular_at(target_fd, name,
                                              max_bytes=128 * 1024 * 1024) != digest:
                            raise PipelineError("published IB result differs from attested bytes")
                    final_attestation = dict(stage_attestation)
                    for role, path in (("report", final_report), ("actual", final_log)):
                        final_attestation[role] = {
                            **stage_attestation[role],
                            "path": str(path),
                            "resolved_path": str(path.resolve(strict=True)),
                        }
                    # Keep the IB schema but publish with a no-clobber link in
                    # the held new node, never through the lexical path.
                    _publish_result_sidecar_at(
                        target_fd, sidecar_path(final_report).name, final_attestation,
                    )
                    if (not _result_chain_still_bound(
                            root_fd, plan, node, run_fd, target_fd)
                            or read_report_provenance(final_report) != final_attestation):
                        raise PipelineError("published IB analysis provenance differs")
                except ProvenanceError as exc:
                    raise PipelineError("published IB analysis provenance failed") from exc
                if (not _same_root_inode(project_root, root_fd)
                        or not _result_chain_still_bound(
                            root_fd, plan, node, run_fd, target_fd)):
                    raise PipelineError("UFM result path was rebound after IB provenance")
                receipt = {
                    "schema": "ufm-collection-v1", "status": "success", "kind": plan.kind,
                    "run_id": plan.run_id, "node": node,
                    "archive": plan.archive_name, "archive_sha256": _sha256(staged_archive),
                    "report": report.name, "report_sha256": stage_attestation["report"]["sha256"],
                    "report_provenance_sha256": _digest_regular_at(
                        target_fd, sidecar_path(final_report).name, max_bytes=16 * 1024),
                }
                (stage / "receipt.json").write_text(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                _fsync_regular(stage / "receipt.json")
                _fsync_directory(stage)
                # A failed private-stage cleanup must never coexist with a
                # public success receipt. Keep a private receipt link first.
                _copy_regular_to_at(stage / "receipt.json", target_fd,
                                    ".receipt.prepared")
                os.fsync(target_fd)
                cleanup_attempted = True
                shutil.rmtree(stage)
                if (not _same_root_inode(project_root, root_fd)
                        or not _result_chain_still_bound(
                            root_fd, plan, node, run_fd, target_fd)):
                    raise PipelineError("UFM result path was rebound before receipt")
                if before_receipt is not None:
                    try:
                        before_receipt()
                    except Exception:
                        raise PipelineError("pre-receipt evidence gate failed") from None
                if prepare_panel is not None:
                    try:
                        prepare_panel(dict(receipt))
                    except Exception:
                        raise PipelineError("pre-receipt panel preparation failed") from None
                if (not _same_root_inode(project_root, root_fd)
                        or not _result_chain_still_bound(
                            root_fd, plan, node, run_fd, target_fd)):
                    raise PipelineError("UFM result path was rebound during evidence gate")
                if before_receipt is not None or prepare_panel is not None:
                    try:
                        if read_report_provenance(final_report) != final_attestation:
                            raise PipelineError("IB provenance changed during evidence gate")
                    except ProvenanceError as exc:
                        raise PipelineError("IB source changed during evidence gate") from exc
                    for name, digest in expected.items():
                        if _digest_regular_at(target_fd, name,
                                              max_bytes=128 * 1024 * 1024) != digest:
                            raise PipelineError("IB result changed during evidence gate")
                os.link(".receipt.prepared", "receipt.json",
                        src_dir_fd=target_fd, dst_dir_fd=target_fd,
                        follow_symlinks=False)
                os.fsync(target_fd)
                os.unlink(".receipt.prepared", dir_fd=target_fd)
                os.fsync(target_fd)
                os.fsync(run_fd)
                return target
            finally:
                os.close(target_fd)
        finally:
            os.close(run_fd)
    except (OSError, ValueError) as exc:
        if isinstance(exc, PipelineError):
            raise
        raise PipelineError("local UFM handoff failed") from exc
    finally:
        try:
            if not cleanup_attempted and stage.exists():
                shutil.rmtree(stage)
        finally:
            os.close(root_fd)


def validated_receipts(project_root: Path, environment: str) -> list[dict[str, str]]:
    """Read only complete, digest-bound UFM receipts for one environment."""
    if environment not in {"air", "prod"} or not isinstance(project_root, Path):
        return []
    if not _real_directory(project_root):
        return []
    results: list[dict[str, str]] = []
    try:
        root_fd = _open_real_dir(project_root)
        try:
            output_fd = _open_child_dir(root_fd, "99-output-ufm")
            try:
                runs_fd = _open_child_dir(output_fd, "runs")
                try:
                    for run_name in sorted(os.listdir(runs_fd), reverse=True):
                        try:
                            plan = collection_plan("iblinkinfo", run_name)
                        except ValueError:
                            continue
                        if f"-{environment}-" not in run_name:
                            continue
                        try:
                            run_fd = _open_child_dir(runs_fd, run_name)
                        except OSError:
                            continue
                        try:
                            for node in sorted(os.listdir(run_fd)):
                                if _NODE_RE.fullmatch(node) is None:
                                    continue
                                try:
                                    node_fd = _open_child_dir(run_fd, node)
                                except OSError:
                                    continue
                                try:
                                    receipt = _read_regular_at(node_fd, "receipt.json", max_bytes=4096)
                                    archive = _read_regular_at(node_fd, plan.archive_name,
                                                               max_bytes=128 * 1024 * 1024)
                                    report_name = _report_name(plan)
                                    report = _read_regular_at(node_fd, report_name,
                                                              max_bytes=128 * 1024 * 1024)
                                    provenance_name = sidecar_path(Path(report_name)).name
                                    provenance = _read_regular_at(node_fd, provenance_name,
                                                                  max_bytes=16 * 1024)
                                    report_path = (project_root / "99-output-ufm" / "runs"
                                                   / run_name / node / report_name)
                                    report_source = read_report_provenance(report_path)
                                    data = json.loads(receipt.decode("utf-8"))
                                    if data == {
                                        "schema": "ufm-collection-v1", "status": "success",
                                        "kind": "iblinkinfo", "run_id": run_name, "node": node,
                                        "archive": plan.archive_name,
                                        "archive_sha256": hashlib.sha256(archive).hexdigest(),
                                        "report": report_name,
                                        "report_sha256": hashlib.sha256(report).hexdigest(),
                                        "report_provenance_sha256": hashlib.sha256(
                                            provenance).hexdigest(),
                                    } and report_source["report"]["sha256"] == data["report_sha256"]:
                                        results.append(data)
                                except (OSError, ValueError, UnicodeError):
                                    continue
                                finally:
                                    os.close(node_fd)
                        finally:
                            os.close(run_fd)
                finally:
                    os.close(runs_fd)
            finally:
                os.close(output_fd)
        finally:
            os.close(root_fd)
    except (OSError, ValueError):
        return []
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local-only UFM iblinkinfo handoff")
    parser.add_argument("--run-id", required=True,
                        help="Run identifier matching the already retrieved archive")
    parser.add_argument("--node", required=True,
                        help="UFM node name from the caller's verified retrieval context")
    parser.add_argument("--archive", type=Path, required=True,
                        help="Path to the complete, previously retrieved iblinkinfo tar.gz archive")
    parser.add_argument("--cvt", type=Path, required=True,
                        help="Path to the project P2P CVT input for local analysis")
    parser.add_argument("--project", type=Path, required=True,
                        help="Project root receiving the private 99-output-ufm run result")
    args = parser.parse_args(argv)
    try:
        plan = collection_plan("iblinkinfo", args.run_id)
        output = run_local_iblinkinfo(plan, args.node, args.archive, args.cvt, args.project)
    except (PipelineError, ValueError):
        print("ERROR: local UFM handoff refused", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
