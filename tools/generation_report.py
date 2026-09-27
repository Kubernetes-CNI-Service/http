#!/usr/bin/env python3
"""REQ-16 R16-9: record the public keys actually published for a release.

This is the first report at this governed path (schema 3), not a migration of
the unrelated project-root, ad-hoc schema-2 file.  Other artifacts elsewhere
in the repository do use schema versions 1 and 2.  The parent
release and this report are two distinct file publications and cannot be
committed atomically as a pair.  An absent/stale report after a parent commit
must therefore fail inspection; a full load rerun under its deployment lock
reconstructs it before services may start.

The report proves only local published public-key identity.  It does not read
private keys, prove private-key possession, or prove installation on a device.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any

try:
    from tools.ssh_key_preparation import PUBLIC_KEY_LIMIT, public_key_identity_bytes
except ModuleNotFoundError as exc:
    if exc.name != "tools":
        raise
    # Direct execution as `python3 tools/generation_report.py` places tools/
    # rather than the repository root on sys.path.
    from ssh_key_preparation import PUBLIC_KEY_LIMIT, public_key_identity_bytes


RECORD_TYPE = "http-v3-public-key-generation-report"
REPORT_NAME = "generation-report.json"
PARENT_NAME = "current-release.json"
REPORT_LIMIT = 64 * 1024
PARENT_LIMIT = 1024 * 1024
ROLES = (("laptop", "laptop.pub"), ("management", "mgmt-server.pub"))
PARENT_BASIS = (
    "project", "deployment_scope", "switch_scope", "dhcp_status", "inputs",
    "input_sources", "components", "inventory",
)
REPORT_FIELDS = frozenset((
    "schema_version", "record_type", "project", "release_id",
    "generated_at", "public_keys",
))
KEY_FIELDS = frozenset(("role", "name", "algorithm", "fingerprint"))
# Mirror the bounded public-line parser's accepted SSH type vocabulary.  A
# previously published report must be semantically valid before replacement.
_PUBLIC_ALGORITHMS = frozenset((
    "ssh-ed25519", "ssh-rsa",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
))
_RELEASE_RE = re.compile(r"[0-9a-f]{20}\Z")
_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class GenerationReportError(ValueError):
    """A report or one of its bounded publication inputs failed closed."""


@dataclass(frozen=True)
class PreparedGenerationReport:
    destination: Path
    temporary: Path
    directory_identity: tuple[int, int]
    temporary_identity: tuple[int, int]
    old_identity: tuple[int, int] | None
    payload_sha256: str


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _require_directory(path: Path) -> tuple[int, int]:
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise GenerationReportError(f"directory unavailable: {path}") from exc
    if not stat.S_ISDIR(named.st_mode) or named.st_uid != os.geteuid():
        raise GenerationReportError(f"owned no-follow directory required: {path}")
    return _identity(named)


def _read_regular(
    path: Path, limit: int, *, missing_ok: bool = False,
    directory_fd: int | None = None,
) -> bytes | None:
    try:
        named = (os.lstat(path) if directory_fd is None else os.stat(
            path.name, dir_fd=directory_fd, follow_symlinks=False,
        ))
    except FileNotFoundError:
        if missing_ok:
            return None
        raise GenerationReportError(f"required record missing: {path}") from None
    except OSError as exc:
        raise GenerationReportError(f"cannot inspect record: {path}") from exc
    if not stat.S_ISREG(named.st_mode) or named.st_nlink != 1 or named.st_size > limit:
        raise GenerationReportError(f"unsafe regular record: {path}")
    descriptor = -1
    try:
        descriptor = os.open(
            path if directory_fd is None else path.name,
            os.O_RDONLY | _NOFOLLOW | _CLOEXEC | os.O_NONBLOCK,
            **({} if directory_fd is None else {"dir_fd": directory_fd}),
        )
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or _stable_identity(before) != _stable_identity(named)):
            raise GenerationReportError(f"record rebound before read: {path}")
        payload = bytearray()
        while len(payload) <= limit:
            part = os.read(descriptor, min(64 * 1024, limit + 1 - len(payload)))
            if not part:
                break
            payload.extend(part)
        if len(payload) > limit:
            raise GenerationReportError(f"record exceeds bound: {path}")
        after = os.fstat(descriptor)
        rebound = (os.lstat(path) if directory_fd is None else os.stat(
            path.name, dir_fd=directory_fd, follow_symlinks=False,
        ))
        if (_stable_identity(before) != _stable_identity(after)
                or _stable_identity(before) != _stable_identity(rebound)):
            raise GenerationReportError(f"record changed during read: {path}")
        return bytes(payload)
    except OSError as exc:
        raise GenerationReportError(f"cannot safely read record: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GenerationReportError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _decode_record(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GenerationReportError(f"invalid {label} JSON") from exc
    if not isinstance(value, dict):
        raise GenerationReportError(f"{label} must be an object")
    return value


def _project_name(project: Path) -> str:
    name = project.name
    if not name or name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise GenerationReportError("project must have a safe basename")
    _require_directory(project)
    return name


def _validate_parent(project: Path, parent: dict[str, Any]) -> None:
    if type(parent.get("schema_version")) is not int or parent["schema_version"] != 2:
        raise GenerationReportError("parent release must be schema 2")
    if parent.get("validation") != "passed" or parent.get("project") != _project_name(project):
        raise GenerationReportError("parent release is not validated for this project")
    release_id = parent.get("release_id")
    if not isinstance(release_id, str) or not _RELEASE_RE.fullmatch(release_id):
        raise GenerationReportError("invalid parent release ID")
    try:
        basis = {key: parent[key] for key in PARENT_BASIS}
        expected = hashlib.sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()[:20]
    except (KeyError, TypeError, ValueError) as exc:
        raise GenerationReportError("incomplete parent release basis") from exc
    if release_id != expected:
        raise GenerationReportError("parent release digest mismatch")
    generated_at = parent.get("generated_at")
    if not isinstance(generated_at, str):
        raise GenerationReportError("parent timestamp missing")
    try:
        timestamp = datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise GenerationReportError("parent timestamp invalid") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise GenerationReportError("parent timestamp must include timezone")


def _public_key(project: Path, published: Path, name: str) -> tuple[str, str]:
    leaf = project / name
    link = published / name
    try:
        link_before = os.lstat(link)
        target = os.readlink(link)
        leaf_before = os.lstat(leaf)
    except OSError as exc:
        raise GenerationReportError(f"published key missing or unreadable: {name}") from exc
    if not stat.S_ISLNK(link_before.st_mode):
        raise GenerationReportError(f"published key is not a link: {name}")
    target_path = Path(os.path.normpath(os.path.join(published, target)))
    if target_path != leaf.absolute():
        raise GenerationReportError(f"published key targets another project or role: {name}")
    if (not stat.S_ISREG(leaf_before.st_mode) or leaf_before.st_nlink != 1
            or leaf_before.st_size <= 0 or leaf_before.st_size > PUBLIC_KEY_LIMIT):
        raise GenerationReportError(f"unsafe project public key: {name}")
    descriptor = -1
    try:
        descriptor = os.open(leaf, os.O_RDONLY | _NOFOLLOW | _CLOEXEC | os.O_NONBLOCK)
        held = os.fstat(descriptor)
        if (_stable_identity(held) != _stable_identity(leaf_before)
                or not stat.S_ISREG(held.st_mode) or held.st_nlink != 1):
            raise GenerationReportError(f"project public key rebound: {name}")
        payload = bytearray()
        while len(payload) <= PUBLIC_KEY_LIMIT:
            part = os.read(descriptor, min(64 * 1024, PUBLIC_KEY_LIMIT + 1 - len(payload)))
            if not part:
                break
            payload.extend(part)
        if len(payload) > PUBLIC_KEY_LIMIT:
            raise GenerationReportError(f"project public key too large: {name}")
        after = os.fstat(descriptor)
        leaf_after = os.lstat(leaf)
        link_after = os.lstat(link)
        if (_stable_identity(held) != _stable_identity(after)
                or _stable_identity(held) != _stable_identity(leaf_after)
                or _stable_identity(link_before) != _stable_identity(link_after)
                or os.readlink(link) != target):
            raise GenerationReportError(f"published public key changed: {name}")
        algorithm, blob = public_key_identity_bytes(bytes(payload))
    except OSError as exc:
        raise GenerationReportError(f"cannot safely read published public key: {name}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")
    return algorithm.decode("ascii"), "SHA256:" + fingerprint


def build_report(
    project: Path, parent: dict[str, Any], *, published_dir: Path,
) -> dict[str, Any]:
    """Build a report from validated parent and actual same-project published links."""
    project, published = Path(project), Path(published_dir)
    _validate_parent(project, parent)
    _require_directory(published)
    keys = []
    seen: set[tuple[str, str]] = set()
    for role, name in ROLES:
        algorithm, fingerprint = _public_key(project, published, name)
        identity = algorithm, fingerprint
        if identity in seen:
            raise GenerationReportError("laptop and management published the same public key")
        seen.add(identity)
        keys.append({
            "role": role, "name": name, "algorithm": algorithm,
            "fingerprint": fingerprint,
        })
    return {
        "schema_version": 3, "record_type": RECORD_TYPE,
        "project": project.name, "release_id": parent["release_id"],
        "generated_at": parent["generated_at"], "public_keys": keys,
    }


def _validate_report_shape(report: dict[str, Any], project: Path) -> None:
    if set(report) != REPORT_FIELDS or type(report.get("schema_version")) is not int:
        raise GenerationReportError("report has unknown or missing fields")
    if report["schema_version"] != 3 or report["record_type"] != RECORD_TYPE:
        raise GenerationReportError("unsupported governed report version or type")
    if report["project"] != _project_name(project):
        raise GenerationReportError("report belongs to another project")
    release_id = report["release_id"]
    if not isinstance(release_id, str) or not _RELEASE_RE.fullmatch(release_id):
        raise GenerationReportError("invalid report release ID")
    generated_at = report["generated_at"]
    if not isinstance(generated_at, str):
        raise GenerationReportError("invalid report timestamp")
    try:
        timestamp = datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise GenerationReportError("invalid report timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise GenerationReportError("report timestamp must include timezone")
    keys = report["public_keys"]
    if not isinstance(keys, list) or len(keys) != 2:
        raise GenerationReportError("report requires two ordered public keys")
    seen_fingerprints: set[str] = set()
    for record, (role, name) in zip(keys, ROLES):
        if not isinstance(record, dict) or set(record) != KEY_FIELDS:
            raise GenerationReportError("invalid public key record")
        if record["role"] != role or record["name"] != name:
            raise GenerationReportError("public key role/order mismatch")
        fingerprint = record["fingerprint"]
        if (not isinstance(record["algorithm"], str)
                or record["algorithm"] not in _PUBLIC_ALGORITHMS
                or not isinstance(fingerprint, str)
                or not _FINGERPRINT_RE.fullmatch(fingerprint)):
            raise GenerationReportError("invalid public key identity")
        if fingerprint in seen_fingerprints:
            raise GenerationReportError("duplicate public key identity")
        seen_fingerprints.add(fingerprint)


def _output_directory(project: Path) -> Path:
    output = project / "99-output-ztp"
    _require_directory(output)
    return output


def _open_prepared_directory(output: Path, expected: tuple[int, int]) -> int:
    """Hold the prepared directory inode through its final mutation."""
    flags = os.O_RDONLY | _NOFOLLOW | _CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(output, flags)
    except OSError as exc:
        raise GenerationReportError("report output directory unavailable") from exc
    try:
        observed = os.fstat(descriptor)
        if (not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.geteuid()
                or _identity(observed) != expected):
            raise GenerationReportError("report output directory rebound")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _existing_report_identity(destination: Path, project: Path) -> tuple[int, int] | None:
    payload = _read_regular(destination, REPORT_LIMIT, missing_ok=True)
    if payload is None:
        return None
    old = _decode_record(payload, "existing governed report")
    _validate_report_shape(old, project)
    return _identity(os.lstat(destination))


def prepare_generation_report(
    project: Path, report: dict[str, Any],
) -> PreparedGenerationReport:
    """Fsync a candidate without publishing it or touching the parent record."""
    project = Path(project)
    _validate_report_shape(report, project)
    if not isinstance(report["release_id"], str) or not _RELEASE_RE.fullmatch(report["release_id"]):
        raise GenerationReportError("invalid report release ID")
    if not isinstance(report["generated_at"], str):
        raise GenerationReportError("invalid report timestamp")
    output = _output_directory(project)
    directory_identity = _require_directory(output)
    destination = output / REPORT_NAME
    old_identity = _existing_report_identity(destination, project)
    payload = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(payload) > REPORT_LIMIT:
        raise GenerationReportError("report exceeds bound")
    directory_fd = _open_prepared_directory(output, directory_identity)
    descriptor = -1
    temporary_name: str | None = None
    temporary_identity: tuple[int, int] | None = None
    try:
        for _ in range(16):
            proposed = f".generation-report.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    proposed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                    0o600, dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            temporary_name = proposed
            temporary_identity = _identity(os.fstat(descriptor))
            break
        if temporary_name is None or temporary_identity is None:
            raise GenerationReportError("cannot create unique staged report")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(descriptor, 0o644)
            os.fsync(stream.fileno())
        observed = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1
                or _identity(observed) != temporary_identity):
            raise GenerationReportError("staged report is not a single-link regular file")
        if _identity(os.lstat(output)) != directory_identity:
            raise GenerationReportError("report output directory rebound during preparation")
        return PreparedGenerationReport(
            destination=destination, temporary=output / temporary_name,
            directory_identity=directory_identity,
            temporary_identity=_identity(observed), old_identity=old_identity,
            payload_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except BaseException:
        if temporary_name is not None and temporary_identity is not None:
            try:
                named = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
                if _identity(named) == temporary_identity:
                    os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                print(f"staged report cleanup failed: {cleanup_exc}", file=sys.stderr)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def commit_prepared_generation_report(candidate: PreparedGenerationReport) -> Path:
    """Replace only a known-safe governed record, then fsync its directory.

    A successful parent commit followed by a failed report commit is not an
    atomic pair.  The inspector will reject that state; the load caller must
    prevent service start and rerun under its lock.
    """
    if not isinstance(candidate, PreparedGenerationReport):
        raise GenerationReportError("invalid prepared report candidate")
    project = candidate.destination.parent.parent
    output = _output_directory(project)
    if (_identity(os.lstat(output)) != candidate.directory_identity
            or candidate.destination != output / REPORT_NAME
            or candidate.temporary.parent != output):
        raise GenerationReportError("report output directory rebound")
    staged = _read_regular(candidate.temporary, REPORT_LIMIT)
    if staged is None or hashlib.sha256(staged).hexdigest() != candidate.payload_sha256:
        raise GenerationReportError("staged report changed")
    if _identity(os.lstat(candidate.temporary)) != candidate.temporary_identity:
        raise GenerationReportError("staged report inode changed")
    current_identity = _existing_report_identity(candidate.destination, project)
    if current_identity != candidate.old_identity:
        raise GenerationReportError("existing report changed before commit")
    descriptor = _open_prepared_directory(output, candidate.directory_identity)
    try:
        staged_named = os.stat(
            candidate.temporary.name, dir_fd=descriptor, follow_symlinks=False,
        )
        if (_identity(staged_named) != candidate.temporary_identity
                or not stat.S_ISREG(staged_named.st_mode)
                or staged_named.st_nlink != 1):
            raise GenerationReportError("staged report changed before commit")
        try:
            old_named = os.stat(REPORT_NAME, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            old_identity = None
        else:
            old_identity = _identity(old_named)
        if old_identity != candidate.old_identity:
            raise GenerationReportError("existing report changed before commit")
        os.replace(
            candidate.temporary.name, REPORT_NAME,
            src_dir_fd=descriptor, dst_dir_fd=descriptor,
        )
        os.fsync(descriptor)
        if _identity(os.lstat(output)) != candidate.directory_identity:
            raise GenerationReportError("report output directory rebound after commit")
    finally:
        os.close(descriptor)
    return candidate.destination


def discard_prepared_generation_report(
    candidate: PreparedGenerationReport | None,
) -> bool:
    """Discard only the still-staged inode owned by this preparation attempt.

    The load caller may use this in its ``finally`` block.  It never removes
    the final report or a name rebound to another inode.
    """
    if candidate is None:
        return False
    if not isinstance(candidate, PreparedGenerationReport):
        raise GenerationReportError("invalid prepared report candidate")
    try:
        named = os.lstat(candidate.temporary)
    except FileNotFoundError:
        return False
    if (_identity(named) != candidate.temporary_identity
            or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1):
        raise GenerationReportError("staged report name rebound; refusing cleanup")
    output = candidate.temporary.parent
    descriptor = _open_prepared_directory(output, candidate.directory_identity)
    try:
        staged_named = os.stat(
            candidate.temporary.name, dir_fd=descriptor, follow_symlinks=False,
        )
        if (_identity(staged_named) != candidate.temporary_identity
                or not stat.S_ISREG(staged_named.st_mode)
                or staged_named.st_nlink != 1):
            raise GenerationReportError("staged report changed before cleanup")
        os.unlink(candidate.temporary.name, dir_fd=descriptor)
        if _identity(os.lstat(output)) != candidate.directory_identity:
            raise GenerationReportError("staged report directory rebound after cleanup")
    finally:
        os.close(descriptor)
    return True


def inspect_generation_report(project: Path, *, published_dir: Path) -> dict[str, Any]:
    """Read only the governed path and reject any parent/key/report mismatch."""
    project = Path(project)
    output = _output_directory(project)
    directory_identity = _require_directory(output)
    directory_fd = _open_prepared_directory(output, directory_identity)
    try:
        parent_payload = _read_regular(
            output / PARENT_NAME, PARENT_LIMIT, directory_fd=directory_fd,
        )
        assert parent_payload is not None
        parent = _decode_record(parent_payload, "parent release")
        _validate_parent(project, parent)
        report_payload = _read_regular(
            output / REPORT_NAME, REPORT_LIMIT, directory_fd=directory_fd,
        )
        assert report_payload is not None
        report = _decode_record(report_payload, "governed report")
        _validate_report_shape(report, project)
        expected = build_report(project, parent, published_dir=published_dir)
        if report != expected:
            raise GenerationReportError("report is stale relative to parent or published keys")
        if _identity(os.lstat(output)) != directory_identity:
            raise GenerationReportError("report output directory rebound during inspection")
        return report
    finally:
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect",))
    parser.add_argument("project", type=Path)
    parser.add_argument("--json", action="store_true", help="print validated JSON")
    parser.add_argument(
        "--published-dir", type=Path,
        default=Path(__file__).resolve().parents[1] / "ztp/config/publickey",
        help="published public-key directory (default: governed ZTP path)",
    )
    args = parser.parse_args(argv)
    try:
        report = inspect_generation_report(args.project, published_dir=args.published_dir)
    except GenerationReportError as exc:
        parser.exit(2, f"generation report invalid: {exc}\n")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    else:
        for item in report["public_keys"]:
            print(f"{item['role']}: {item['algorithm']} {item['fingerprint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
