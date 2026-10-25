#!/usr/bin/env python3
"""Validate script coverage and run tests affected by approved source changes.

The impact manifest is policy.  This program never creates or edits test code;
it only selects existing unittest modules.  After a successful run it may
atomically record the exact source/test hashes that were verified.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import fnmatch
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
from importlib import metadata as importlib_metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Iterable, Mapping, Sequence


@contextmanager
def _private_bytecode_namespace():
    """Ignore operator bytecode for synchronous governance dependency imports."""
    previous = sys.pycache_prefix
    with tempfile.TemporaryDirectory(prefix="http-governance-import-pyc-") as directory:
        sys.pycache_prefix = directory
        try:
            yield
        finally:
            sys.pycache_prefix = previous


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1] / "tools"
if os.fspath(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, os.fspath(TOOLS_DIRECTORY))
with _private_bytecode_namespace():
    from project_contract import path_disposition  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "test_cases/script_test_manifest.json"
DEFAULT_APPROVALS = ROOT / "test_cases/script_test_approved_hashes.json"
CONTAINER_TOPLEVEL_LOCK = ROOT / "requirements-container-top-level.lock"
CONTAINER_TOPLEVEL_LOCK_RELATIVE = "requirements-container-top-level.lock"
CONTAINER_TOPLEVEL_REQUIREMENTS = (
    ("Jinja2", "3.1.6"),
    ("PyYAML", "6.0.3"),
    ("pandas", "2.3.3"),
    ("openpyxl", "3.1.5"),
    ("XlsxWriter", "3.2.9"),
)
SOURCE_SUFFIXES = {".py", ".cgi", ".sh"}
TEST_ID_RE = re.compile(r"^test_cases\.test_[A-Za-z0-9_]+$")
TEST_SUITE_ID_RE = re.compile(r"^[a-z][a-z0-9-]*$")
ROOT_ENTRYPOINT_SCENARIO = "root-entrypoint-workflow"
ROOT_ENTRYPOINT_NOT_COVERED = (
    "NOT COVERED (requires Linux EUID 0 private namespace)"
)
ISSUE0016_FAILURE_IDS = (
    "test_cases.test_req10c_auto_workflow.Req10CAutoUnsetupWorkflowTests."
    "test_install_preserves_noncooperating_foreign_cron_or_stops_before_write",
    "test_cases.test_req10c_auto_workflow.Req10CAutoUnsetupWorkflowTests."
    "test_remove_preserves_noncooperating_foreign_cron_or_stops_before_write",
    "test_cases.test_req10c_auto_workflow.Req10CAutoUnsetupWorkflowTests."
    "test_unsetup_preserves_noncooperating_foreign_cron_or_stops_before_write",
)
VALIDATION_BASELINE_SKIP_IDS = (
    "test_cases.test_docker_management_ssh_key.DockerManagementSshKeyWorkflowTests."
    "test_real_deploy_entrypoint_drives_locked_helper_then_11_load",
    "test_cases.test_image_context_safety.SyntheticDockerMembershipTests."
    "test_copy_membership_with_each_independent_ignore_entrypoint",
    "test_cases.test_monitor_authority_entrypoints.MonitorAuthorityRootNamespaceScenario."
    "test_real_root_entrypoint_workflow",
    "test_cases.test_monitor_stack_review.ControlPlaneTests."
    "test_yaml_backup_memory_socket_is_private_and_inode_pinned",
)
ISSUE0016_FAILURE_FRAGMENT = "silently erased a non-cooperating foreign entry"
GENERATED_RUNTIME_SCRIPTS = frozenset({
    "ztp/ztp-bootstrap_oob.sh",
    "ztp/ztp-bootstrap_oobofoob.sh",
})
NON_SOURCE_ROOTS = frozenset({".git", ".codex", ".agents", "outputs"})
# Keep this aligned with tools/project_contract.py.  These names describe
# development/test data wherever they occur; they are not deployable scripts.

# Exact historical test identities, not a stage-name or environment bypass.
# Those unchanged modules keep their original staged-proof contracts. Any other
# bytes select the ordinary V3 clean-candidate gate. Tests pin the historical
# Git blobs independently; never refresh these hashes from current test output.
PREFLIGHT_HISTORICAL_TESTS = {
    "test_cases.test_public_publication_workflow":
        "1bb652bb15f97e03e568270a57ee0a56515bc526cecd5034c6a99c031102358e",
    "test_cases.test_public_publication_contract":
        "3bc97396dd627830080b3bfcb0b3a340ce6cd9d19fdb377983edd26ca152db64",
    "test_cases.test_public_project_fixture_workflow":
        "aae51daa9f67eedd7701764289517c41defe6f264c48268e92faded9ee60849d",
    "test_cases.test_public_s_phase_workflow":
        "81c3a2606c66aa1b9cee320bfeb0366fb28ff2b865abd7c7e8f577f1e0766e4f",
}
PREFLIGHT_INET_TESTS = frozenset({
    "test_cases.test_public_publication_workflow",
    "test_cases.test_ztp_release_core_review",
    "test_cases.test_runner_preflight",
})


class ImpactError(RuntimeError):
    """Invalid impact policy, source inventory, or changed-path input."""


class GitDiscoveryError(RuntimeError):
    """Git change discovery was requested but could not be completed."""


@dataclass(frozen=True)
class Snapshot:
    manifest_sha256: str
    scripts: Mapping[str, Mapping[str, str]]
    tests: Mapping[str, str]
    support: Mapping[str, str] = field(default_factory=dict)


@dataclass
class PendingChanges:
    scripts: set[str] = field(default_factory=set)
    tests: set[str] = field(default_factory=set)
    support: set[str] = field(default_factory=set)
    deleted_tests: set[str] = field(default_factory=set)
    manifest_changed: bool = False
    approvals_missing: bool = False

    def any(self) -> bool:
        return bool(
            self.scripts
            or self.tests
            or self.support
            or self.deleted_tests
            or self.manifest_changed
            or self.approvals_missing
        )


@dataclass
class Selection:
    tests: set[str] = field(default_factory=set)
    changed_paths: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)
    full_suite: bool = False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_support_path(root: Path, relative: str) -> str:
    """Hash one governed support file, including an explicit symlink identity."""
    normalized = normalize_relative(root, relative)
    path = root / normalized
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise ImpactError(f"missing tracked support file: {relative}") from exc
    if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
        return sha256_file(path)
    if not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise ImpactError(
            "tracked support must be a single-link regular file or safe "
            f"in-repository symlink: {relative}"
        )
    try:
        raw_target = os.readlink(path)
        if Path(raw_target).is_absolute():
            raise ImpactError(
                f"tracked support symlink target must be relative: {relative}"
            )
        repository_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved_relative = resolved.relative_to(repository_root).as_posix()
        resolved_info = resolved.stat()
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ImpactError(
            f"tracked support symlink escapes or has an invalid target: {relative}"
        ) from exc
    if not stat.S_ISREG(resolved_info.st_mode) or resolved_info.st_nlink != 1:
        raise ImpactError(
            f"tracked support symlink must resolve to a single-link file: {relative}"
        )
    digest = hashlib.sha256()
    for value in ("symlink", raw_target, resolved_relative, sha256_file(resolved)):
        digest.update(value.encode("utf-8", errors="strict"))
        digest.update(b"\0")
    return digest.hexdigest()


def normalize_relative(root: Path, raw: str) -> str:
    if "\x00" in raw:
        raise ImpactError("changed path contains NUL")
    value = raw.strip()
    if not value:
        raise ImpactError("changed path is empty")
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(root.resolve())
        except ValueError as exc:
            raise ImpactError(f"changed path is outside workspace: {raw}") from exc
    normalized = Path(os.path.normpath(candidate.as_posix()))
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ImpactError(f"changed path escapes workspace: {raw}")
    result = normalized.as_posix()
    if result in {"", "."}:
        raise ImpactError(f"changed path does not name a file: {raw}")
    return result


def _registered_nested_worktrees(root: Path) -> set[str]:
    """Find only live linked checkouts registered to this exact Git worktree.

    A directory name, .gitignore match, or a forged .git file alone is not a
    source-inventory exemption.  An unverified path remains governed.
    """
    environment = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
        environment.pop(key, None)
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(root), "worktree", "list", "--porcelain", "-z"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=environment, timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return set()
    if result.returncode:
        return set()

    workspace = root.resolve()
    registered: set[Path] = set()
    for field in result.stdout.split(b"\0"):
        if not field.startswith(b"worktree "):
            continue
        path = Path(os.fsdecode(field[len(b"worktree "):]))
        if path.is_absolute():
            registered.add(path.resolve())
    if workspace not in registered:
        return set()

    nested: set[str] = set()
    for path in registered - {workspace}:
        try:
            relative = path.relative_to(workspace)
        except ValueError:
            continue
        dotgit = path / ".git"
        try:
            info = dotgit.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > 4096
            ):
                continue
            marker = dotgit.read_text(encoding="utf-8").strip()
            if not marker.startswith("gitdir: "):
                continue
            admin = Path(marker[len("gitdir: "):])
            if not admin.is_absolute():
                admin = path / admin
            admin = admin.resolve(strict=True)
            gitdir_link = admin / "gitdir"
            link_info = gitdir_link.lstat()
            if (
                not stat.S_ISREG(link_info.st_mode)
                or link_info.st_nlink != 1
                or link_info.st_size > 4096
            ):
                continue
            backlink = gitdir_link.read_text(encoding="utf-8").strip()
            backlink_path = Path(backlink)
            if not backlink_path.is_absolute():
                backlink_path = admin / backlink_path
            if backlink_path.resolve(strict=True) != dotgit.resolve(strict=True):
                continue
        except (OSError, UnicodeError, ValueError):
            continue
        nested.add(relative.as_posix())
    return nested


def discover_source_scripts(root: Path) -> dict[str, str]:
    """Return every governed source path and its in-workspace canonical path."""
    found: dict[str, str] = {}
    nested_worktrees = _registered_nested_worktrees(root)
    for directory, subdirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(directory)
        kept = []
        for name in subdirs:
            relative = (parent / name).relative_to(root)
            if (
                relative.as_posix() in nested_worktrees
                or relative.parts[0] in NON_SOURCE_ROOTS
                or relative.parts[0].startswith(".codex_tmp")
                or path_disposition(relative.as_posix()) != "production"
                or any(part.startswith("99-output") for part in relative.parts)
            ):
                continue
            kept.append(name)
        subdirs[:] = kept
        for name in files:
            path = parent / name
            if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
                continue
            relative = path.relative_to(root)
            if (
                relative.parts[0] in NON_SOURCE_ROOTS
                or relative.parts[0].startswith(".codex_tmp")
                or path_disposition(relative.as_posix()) != "production"
                or any(part.startswith("99-output") for part in relative.parts)
                or relative.as_posix() in GENERATED_RUNTIME_SCRIPTS
            ):
                continue
            try:
                canonical = path.resolve(strict=True).relative_to(root.resolve())
            except (FileNotFoundError, ValueError) as exc:
                raise ImpactError(f"unsafe or broken source path: {relative}") from exc
            found[relative.as_posix()] = canonical.as_posix()
    return dict(sorted(found.items()))


def discover_tests(root: Path) -> dict[str, Path]:
    cases = root / "test_cases"
    return {
        f"test_cases.{path.stem}": path
        for path in sorted(cases.glob("test_*.py"))
        if path.is_file() and not path.is_symlink()
    }


def _exec_current_source(spec, module) -> None:
    """Execute source bytes, never timestamp-approved disk bytecode."""
    if not isinstance(spec.loader, SourceFileLoader):
        raise ImpactError("authority requires a source file loader")
    filename = spec.loader.get_filename(spec.name)
    source = spec.loader.get_data(filename)
    code = compile(source, filename, "exec", dont_inherit=True)
    exec(code, module.__dict__)


def _load_deployment_selector(root: Path, relative: str, module_name: str):
    path = root / relative
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ImpactError("selector is not a single-link regular file")
    except (OSError, ImpactError) as exc:
        raise ImpactError(
            f"deployment selector load/configuration error for {relative}: {exc}"
        ) from exc
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImpactError(
            f"deployment selector load/configuration error for {relative}: "
            "cannot create module loader"
        )
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(module_name)
    tools_path = os.fspath(root / "tools")
    inserted = tools_path not in sys.path
    if inserted:
        sys.path.insert(0, tools_path)
    sys.modules[module_name] = module
    try:
        with _private_bytecode_namespace():
            _exec_current_source(spec, module)
    except Exception as exc:
        raise ImpactError(
            f"deployment selector load/configuration error for {relative}: {exc}"
        ) from exc
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
        if inserted:
            try:
                sys.path.remove(tools_path)
            except ValueError:
                pass
    return module


def deployment_authority_paths(root: Path) -> set[str]:
    """Load and combine the actual sync, image, and archive selectors."""
    selectors = (
        (
            "tools/sync-code.py", "_impact_sync_selector",
            lambda module: module.matching_files(root, module.ROOT_CODE_PATTERNS),
        ),
        (
            "infra/docker/activate.py", "_impact_image_selector",
            lambda module: module.image_source_paths(root),
        ),
        (
            "tools/_package_common.py", "_impact_archive_selector",
            lambda module: module.deployment_archive_source_paths(root),
        ),
    )
    selected: set[str] = set()
    for relative, module_name, invoke in selectors:
        module = _load_deployment_selector(root, relative, module_name)
        try:
            values = invoke(module)
            if isinstance(values, (str, bytes)):
                raise TypeError("selector returned one string instead of a collection")
            for value in values:
                raw = os.fspath(value)
                candidate = Path(raw)
                if candidate.is_absolute():
                    try:
                        raw = candidate.resolve(strict=True).relative_to(
                            root.resolve(strict=True),
                        ).as_posix()
                    except (OSError, ValueError) as exc:
                        raise ImpactError(
                            f"deployment selector path is outside workspace: {value}"
                        ) from exc
                selected.add(normalize_relative(root, raw))
        except Exception as exc:
            if isinstance(exc, ImpactError):
                raise
            raise ImpactError(
                f"deployment selector load/configuration error for {relative}: {exc}"
            ) from exc
    return selected


def read_json_regular(path: Path, *, required: bool = True) -> dict:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if required:
            raise ImpactError(f"missing file: {path}")
        return {}
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ImpactError(f"must be a single-link regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImpactError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ImpactError(f"JSON root must be an object: {path}")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ImpactError(f"{label} must be a list of non-empty strings")
    if not value and not allow_empty:
        raise ImpactError(f"{label} cannot be empty")
    if len(value) != len(set(value)):
        raise ImpactError(f"{label} contains duplicates")
    return list(value)


def _validate_test_ids(
    root: Path, values: Iterable[str], label: str,
    *, available: Mapping[str, Path] | None = None,
) -> None:
    if available is None:
        available = discover_tests(root)
    for test_id in values:
        if not TEST_ID_RE.fullmatch(test_id):
            raise ImpactError(f"{label} has unsafe/non-module test id: {test_id}")
        path = available.get(test_id)
        if path is None or not path.is_file() or path.is_symlink():
            raise ImpactError(f"{label} references missing test module: {test_id}")


def path_matches(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _complete_pattern_parts(pattern: str) -> tuple[tuple[str, ...], str]:
    """Parse one direct-child, repository-relative complete authority glob."""
    label = "complete tracked support pattern"
    if not isinstance(pattern, str) or not pattern or "\x00" in pattern:
        raise ImpactError(f"{label} must be a non-empty POSIX path")
    if "\\" in pattern or pattern.startswith("/"):
        raise ImpactError(f"{label} must be repository-relative POSIX: {pattern!r}")
    parts = tuple(pattern.split("/"))
    if (
        len(parts) < 2
        or any(part in {"", ".", "..", "**"} for part in parts)
        or any(any(marker in part for marker in "*?[") for part in parts[:-1])
        or not any(marker in parts[-1] for marker in "*?[")
        or "**" in parts[-1]
    ):
        raise ImpactError(
            f"{label} must name one literal authority root and a direct-child glob: "
            f"{pattern!r}"
        )
    return parts[:-1], parts[-1]


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_complete_authority_root(
    root: Path, components: Sequence[str], *, _test_hook=None,
) -> tuple[int, int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise ImpactError("complete tracked support authority root is not a real directory")
        repository_fd = os.open(root, flags)
    except (OSError, ValueError) as exc:
        raise ImpactError("cannot open complete tracked support repository root") from exc
    current_fd = repository_fd
    try:
        for index, component in enumerate(components):
            try:
                before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except OSError as exc:
                raise ImpactError(
                    "complete tracked support authority root is missing or unsafe: "
                    + "/".join(components)
                ) from exc
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise ImpactError(
                    "complete tracked support authority root contains a non-directory "
                    "or symlink component: " + "/".join(components[: index + 1])
                )
            if index == len(components) - 1 and _test_hook is not None:
                _test_hook("root-before-open", "/".join(components))
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise ImpactError(
                    "complete tracked support authority root changed while opening: "
                    + "/".join(components)
                ) from exc
            try:
                opened = os.fstat(child_fd)
            except OSError as exc:
                os.close(child_fd)
                raise ImpactError(
                    "complete tracked support authority root changed while opening: "
                    + "/".join(components)
                ) from exc
            if _stat_identity(before) != _stat_identity(opened):
                os.close(child_fd)
                raise ImpactError(
                    "complete tracked support authority root changed while opening: "
                    + "/".join(components)
                )
            if current_fd != repository_fd:
                os.close(current_fd)
            current_fd = child_fd
        return repository_fd, current_fd, os.fstat(current_fd)
    except BaseException:
        if current_fd != repository_fd:
            os.close(current_fd)
        os.close(repository_fd)
        raise


def _verify_complete_authority_binding(
    repository_fd: int,
    components: Sequence[str],
    expected: os.stat_result,
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.dup(repository_fd)
    try:
        for component in components:
            try:
                opened = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise ImpactError(
                    "complete tracked support authority root changed during validation"
                ) from exc
            os.close(current_fd)
            current_fd = opened
        if _stat_identity(os.fstat(current_fd)) != _stat_identity(expected):
            raise ImpactError(
                "complete tracked support authority root changed during validation"
            )
    finally:
        os.close(current_fd)


def _complete_tracked_support_snapshot(
    root: Path, pattern: str, *, _test_hook=None,
) -> dict[str, str]:
    """Discover and hash one direct-child authority through held descriptors."""
    components, basename_pattern = _complete_pattern_parts(pattern)
    repository_fd, authority_fd, authority_info = _open_complete_authority_root(
        root, components, _test_hook=_test_hook,
    )
    prefix = "/".join(components) + "/"
    try:
        try:
            with os.scandir(authority_fd) as entries:
                names = sorted(
                    entry.name for entry in entries
                    if fnmatch.fnmatchcase(entry.name, basename_pattern)
                )
        except OSError as exc:
            raise ImpactError(
                f"cannot scan complete tracked support authority root: {'/'.join(components)}"
            ) from exc
        if _test_hook is not None:
            _test_hook("root-after-scan", "/".join(components))
        _verify_complete_authority_binding(
            repository_fd, components, authority_info,
        )

        result: dict[str, str] = {}
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        file_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        for name in names:
            relative = prefix + name
            try:
                before = os.stat(name, dir_fd=authority_fd, follow_symlinks=False)
            except OSError as exc:
                raise ImpactError(
                    f"complete tracked support member changed before open: {relative}"
                ) from exc
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ImpactError(
                    "complete tracked support member must be a non-symlink, "
                    f"single-link regular file: {relative}"
                )
            if _test_hook is not None:
                _test_hook("member-before-open", relative)
            try:
                descriptor = os.open(name, file_flags, dir_fd=authority_fd)
            except OSError as exc:
                raise ImpactError(
                    f"complete tracked support member changed while opening: {relative}"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if _stat_identity(before) != _stat_identity(opened):
                    raise ImpactError(
                        f"complete tracked support member changed while opening: {relative}"
                    )
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                if _stat_identity(opened) != _stat_identity(os.fstat(descriptor)):
                    raise ImpactError(
                        f"complete tracked support member changed while hashing: {relative}"
                    )
                if _test_hook is not None:
                    _test_hook("member-after-read", relative)
                named = os.stat(name, dir_fd=authority_fd, follow_symlinks=False)
                if _stat_identity(opened) != _stat_identity(named):
                    raise ImpactError(
                        f"complete tracked support member changed after hashing: {relative}"
                    )
                result[relative] = digest.hexdigest()
            except OSError as exc:
                raise ImpactError(
                    f"complete tracked support member changed while hashing: {relative}"
                ) from exc
            finally:
                os.close(descriptor)
        _verify_complete_authority_binding(
            repository_fd, components, authority_info,
        )
        return result
    finally:
        if authority_fd != repository_fd:
            os.close(authority_fd)
        os.close(repository_fd)


def _complete_tracked_support_matches(root: Path, pattern: str) -> set[str]:
    return set(_complete_tracked_support_snapshot(root, pattern))


def _complete_path_matches(path: str, pattern: str) -> bool:
    components, basename_pattern = _complete_pattern_parts(pattern)
    parts = tuple(path.split("/"))
    return (
        parts[:-1] == components
        and bool(parts)
        and fnmatch.fnmatchcase(parts[-1], basename_pattern)
    )


def _reconcile_complete_tracked_support(
    label: str, discovered: set[str], pinned: set[str],
) -> None:
    unbound = sorted(discovered - pinned)
    missing = sorted(pinned - discovered)
    if unbound or missing:
        raise ImpactError(
            f"{label}: unbound-on-disk={', '.join(unbound)}; "
            f"pinned-but-missing={', '.join(missing)}; full-suite proof cannot "
            "be issued until the complete tracked support set is reconciled"
        )


def _complete_support_snapshot(root: Path, manifest: Mapping) -> dict[str, str]:
    pinned_all = set(manifest.get("tracked_support", ()))
    complete: dict[str, str] = {}
    for index, rule in enumerate(manifest.get("path_rules", ())):
        if rule.get("complete_tracked_support") is not True:
            continue
        for pattern in rule["paths"]:
            discovered = _complete_tracked_support_snapshot(root, pattern)
            pinned = {
                path for path in pinned_all if _complete_path_matches(path, pattern)
            }
            _reconcile_complete_tracked_support(
                f"path_rules[{index}] {pattern}", set(discovered), pinned,
            )
            overlap = sorted(set(complete) & set(discovered))
            if overlap:
                raise ImpactError(
                    "complete tracked support authorities overlap: "
                    + ", ".join(overlap)
                )
            complete.update(discovered)
    return complete


def load_and_validate_manifest(root: Path, manifest_path: Path) -> dict:
    manifest = read_json_regular(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ImpactError("impact manifest schema_version must be 1")

    # Invocation-local inventory only. Each reference is checked at use, and
    # the complete catalog is rediscovered below; never cache across cycles.
    available_tests = discover_tests(root)

    baseline = _string_list(manifest.get("baseline_tests"), "baseline_tests")
    _validate_test_ids(root, baseline, "baseline_tests", available=available_tests)

    test_suites = manifest.get("test_suites")
    if not isinstance(test_suites, list) or not test_suites:
        raise ImpactError("test_suites must be a non-empty list")
    suite_ids: set[str] = set()
    suite_membership: dict[str, list[str]] = {}
    for index, suite in enumerate(test_suites):
        if not isinstance(suite, dict):
            raise ImpactError(f"test_suites[{index}] must be an object")
        suite_id = suite.get("id")
        if (
            not isinstance(suite_id, str)
            or not TEST_SUITE_ID_RE.fullmatch(suite_id)
            or suite_id in suite_ids
        ):
            raise ImpactError(f"test_suites[{index}] has invalid/duplicate id")
        suite_ids.add(suite_id)
        description = suite.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ImpactError(f"test_suites.{suite_id}.description must be non-empty")
        tests = _string_list(suite.get("tests"), f"test_suites.{suite_id}.tests")
        _validate_test_ids(
            root, tests, f"test_suites.{suite_id}.tests", available=available_tests,
        )
        for test_id in tests:
            suite_membership.setdefault(test_id, []).append(suite_id)
    discovered_tests = set(available_tests)
    tests_without_suite = sorted(discovered_tests - set(suite_membership))
    if tests_without_suite:
        raise ImpactError(
            "tests without primary suite: " + ", ".join(tests_without_suite)
        )
    tests_with_multiple_suites = sorted(
        test_id
        for test_id, memberships in suite_membership.items()
        if len(memberships) != 1
    )
    if tests_with_multiple_suites:
        raise ImpactError(
            "tests in multiple primary suites: "
            + ", ".join(tests_with_multiple_suites)
        )

    recorded_scripts = manifest.get("scripts")
    if not isinstance(recorded_scripts, dict):
        raise ImpactError("scripts must be an object of path -> canonical path")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in recorded_scripts.items()):
        raise ImpactError("scripts entries must map strings to strings")
    actual_scripts = discover_source_scripts(root)
    if recorded_scripts != actual_scripts:
        missing = sorted(set(actual_scripts) - set(recorded_scripts))
        stale = sorted(set(recorded_scripts) - set(actual_scripts))
        wrong = sorted(
            path for path in set(recorded_scripts) & set(actual_scripts)
            if recorded_scripts[path] != actual_scripts[path]
        )
        details = []
        if missing:
            details.append("unmapped=" + ", ".join(missing))
        if stale:
            details.append("removed=" + ", ".join(stale))
        if wrong:
            details.append("canonical-changed=" + ", ".join(wrong))
        raise ImpactError("source inventory differs from manifest: " + "; ".join(details))

    rules = manifest.get("test_rules")
    if not isinstance(rules, list) or not rules:
        raise ImpactError("test_rules must be a non-empty list")
    rule_ids: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ImpactError(f"test_rules[{index}] must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id or rule_id in rule_ids:
            raise ImpactError(f"test_rules[{index}] has invalid/duplicate id")
        rule_ids.add(rule_id)
        patterns = _string_list(rule.get("paths"), f"test_rules.{rule_id}.paths")
        tests = _string_list(rule.get("tests"), f"test_rules.{rule_id}.tests")
        _validate_test_ids(
            root, tests, f"test_rules.{rule_id}.tests", available=available_tests,
        )
        if not any(path_matches(path, patterns) for path in actual_scripts):
            raise ImpactError(f"test rule matches no source script: {rule_id}")

    workflows = manifest.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        raise ImpactError("workflows must be a non-empty list")
    workflow_ids: set[str] = set()
    workflow_membership: dict[str, int] = {path: 0 for path in actual_scripts}
    for index, workflow in enumerate(workflows):
        if not isinstance(workflow, dict):
            raise ImpactError(f"workflows[{index}] must be an object")
        flow_id = workflow.get("id")
        if not isinstance(flow_id, str) or not flow_id or flow_id in workflow_ids:
            raise ImpactError(f"workflows[{index}] has invalid/duplicate id")
        workflow_ids.add(flow_id)
        patterns = _string_list(workflow.get("members"), f"workflows.{flow_id}.members")
        tests = _string_list(workflow.get("tests"), f"workflows.{flow_id}.tests")
        _validate_test_ids(
            root, tests, f"workflows.{flow_id}.tests", available=available_tests,
        )
        matched = [path for path in actual_scripts if path_matches(path, patterns)]
        distinct_targets = {actual_scripts[path] for path in matched}
        if len(distinct_targets) < 2:
            raise ImpactError(f"workflow must cover at least two real scripts: {flow_id}")
        for path in matched:
            workflow_membership[path] += 1

    no_direct_rule = [
        path for path in actual_scripts
        if not any(path_matches(path, rule["paths"]) for rule in rules)
    ]
    no_workflow = [path for path, count in workflow_membership.items() if count == 0]
    if no_direct_rule:
        raise ImpactError("scripts without direct tests: " + ", ".join(no_direct_rule))
    if no_workflow:
        raise ImpactError("scripts without workflow/scenario coverage: " + ", ".join(no_workflow))

    path_rules = manifest.get("path_rules", [])
    if not isinstance(path_rules, list):
        raise ImpactError("path_rules must be a list")
    for index, rule in enumerate(path_rules):
        if not isinstance(rule, dict):
            raise ImpactError(f"path_rules[{index}] must be an object")
        unknown = sorted(
            set(rule) - {"paths", "tests", "full_suite", "complete_tracked_support"}
        )
        if unknown:
            raise ImpactError(
                f"path_rules[{index}] has unknown keys: {', '.join(unknown)}"
            )
        for flag in ("full_suite", "complete_tracked_support"):
            if flag in rule and type(rule[flag]) is not bool:
                raise ImpactError(f"path_rules[{index}].{flag} must be boolean")
        _string_list(rule.get("paths"), f"path_rules[{index}].paths")
        tests = _string_list(
            rule.get("tests", []), f"path_rules[{index}].tests", allow_empty=True,
        )
        if not tests and not rule.get("full_suite", False):
            raise ImpactError(f"path_rules[{index}] needs tests or full_suite=true")
        _validate_test_ids(
            root, tests, f"path_rules[{index}].tests", available=available_tests,
        )

    tracked_support = _string_list(
        manifest.get("tracked_support", []), "tracked_support",
    )
    normalized_support: list[str] = []
    for relative in tracked_support:
        normalized = normalize_relative(root, relative)
        normalized_support.append(normalized)
        if not any(path_matches(normalized, rule["paths"]) for rule in path_rules):
            raise ImpactError(f"tracked support lacks a path rule: {relative}")
    governed = set(recorded_scripts) | set(normalized_support)
    ungoverned_deployment = sorted(deployment_authority_paths(root) - governed)
    if ungoverned_deployment:
        raise ImpactError(
            "deployment authority paths are ungoverned: "
            + ", ".join(ungoverned_deployment)
        )
    complete_support = _complete_support_snapshot(root, manifest)
    for normalized in normalized_support:
        if normalized not in complete_support:
            sha256_support_path(root, normalized)
    if discover_tests(root) != available_tests:
        raise ImpactError("test module inventory changed during manifest validation")
    return manifest


def make_snapshot(root: Path, manifest_path: Path, manifest: Mapping) -> Snapshot:
    scripts = discover_source_scripts(root)
    script_state = {
        path: {"canonical": canonical, "sha256": sha256_file(root / path)}
        for path, canonical in scripts.items()
    }
    tests = {
        test_id: sha256_file(path)
        for test_id, path in discover_tests(root).items()
    }
    complete_support = _complete_support_snapshot(root, manifest)
    support = {
        relative: complete_support.get(relative) or sha256_support_path(root, relative)
        for relative in manifest.get("tracked_support", [])
    }
    return Snapshot(
        manifest_sha256=sha256_file(manifest_path),
        scripts=script_state,
        tests=tests,
        support=support,
    )


def load_approvals(path: Path) -> dict:
    value = read_json_regular(path, required=False)
    if not value:
        return {}
    if value.get("schema_version") != 1:
        raise ImpactError("approval ledger schema_version must be 1")
    if (
        not isinstance(value.get("scripts"), dict)
        or not isinstance(value.get("tests"), dict)
        or not isinstance(value.get("support", {}), dict)
    ):
        raise ImpactError("approval ledger scripts/tests/support must be objects")
    if (
        "full_suite_attestation" in value
        and not isinstance(value["full_suite_attestation"], dict)
    ):
        raise ImpactError("approval ledger full_suite_attestation must be an object")
    return value


def detect_pending(snapshot: Snapshot, approvals: Mapping) -> PendingChanges:
    if not approvals:
        return PendingChanges(
            scripts=set(snapshot.scripts), tests=set(snapshot.tests),
            manifest_changed=True, approvals_missing=True,
        )
    approved_scripts = approvals.get("scripts", {})
    approved_tests = approvals.get("tests", {})
    approved_support = approvals.get("support", {})
    changed_scripts = {
        path for path, record in snapshot.scripts.items()
        if approved_scripts.get(path) != record
    }
    changed_scripts.update(set(approved_scripts) - set(snapshot.scripts))
    changed_tests = {
        test_id for test_id, digest in snapshot.tests.items()
        if approved_tests.get(test_id) != digest
    }
    deleted_tests = set(approved_tests) - set(snapshot.tests)
    changed_support = {
        path for path, digest in snapshot.support.items()
        if approved_support.get(path) != digest
    }
    changed_support.update(set(approved_support) - set(snapshot.support))
    return PendingChanges(
        scripts=changed_scripts,
        tests=changed_tests,
        support=changed_support,
        deleted_tests=deleted_tests,
        manifest_changed=(
            approvals.get("impact_manifest_sha256") != snapshot.manifest_sha256
        ),
    )


def _tests_for_source(manifest: Mapping, source: str) -> tuple[set[str], list[str]]:
    selected: set[str] = set()
    reasons: list[str] = []
    for rule in manifest["test_rules"]:
        if path_matches(source, rule["paths"]):
            selected.update(rule["tests"])
            reasons.append(f"script {source} -> rule {rule['id']}")
    for workflow in manifest["workflows"]:
        if path_matches(source, workflow["members"]):
            selected.update(workflow["tests"])
            reasons.append(f"script {source} -> workflow {workflow['id']}")
    return selected, reasons


def select_tests(
    root: Path,
    manifest: Mapping,
    changed_paths: Iterable[str],
    pending: PendingChanges,
) -> Selection:
    selection = Selection(tests=set(manifest["baseline_tests"]))
    inventory: Mapping[str, str] = manifest["scripts"]
    requested = {normalize_relative(root, path) for path in changed_paths}
    requested.update(path for path in pending.scripts if path in inventory)
    requested.update(pending.support)
    for test_id in pending.tests:
        if test_id in discover_tests(root):
            selection.tests.add(test_id)
            selection.reasons.append(f"modified test module {test_id}")
    if pending.deleted_tests:
        selection.full_suite = True
        selection.reasons.append("test module removed")
    if pending.manifest_changed:
        selection.full_suite = True
        selection.reasons.append("impact manifest changed or is not yet approved")

    # A canonical source edit affects every path aliasing the same file.
    expanded: set[str] = set()
    for path in requested:
        if path in inventory:
            canonical = inventory[path]
            expanded.update(p for p, target in inventory.items() if target == canonical)
        else:
            expanded.add(path)

    known_tests = discover_tests(root)
    for path in sorted(expanded):
        selection.changed_paths.add(path)
        if path in inventory:
            tests, reasons = _tests_for_source(manifest, path)
            selection.tests.update(tests)
            selection.reasons.extend(reasons)
            continue
        if path.startswith("test_cases/test_") and path.endswith(".py"):
            test_id = "test_cases." + Path(path).stem
            if test_id in known_tests:
                selection.tests.add(test_id)
                selection.reasons.append(f"explicit test change {test_id}")
                continue
        matched_rule = False
        for rule in manifest.get("path_rules", []):
            if path_matches(path, rule["paths"]):
                matched_rule = True
                selection.tests.update(rule.get("tests", []))
                selection.reasons.append(f"path {path} -> path rule")
                if rule.get("full_suite", False):
                    selection.full_suite = True
        if not matched_rule:
            selection.full_suite = True
            selection.reasons.append(f"unknown changed path requires safe full suite: {path}")
    return selection


def select_test_suites(manifest: Mapping, suite_ids: Iterable[str]) -> Selection:
    suites = {suite["id"]: suite for suite in manifest["test_suites"]}
    requested = list(dict.fromkeys(suite_ids))
    unknown = sorted(set(requested) - set(suites))
    if unknown:
        raise ImpactError("unknown test suite: " + ", ".join(unknown))
    selection = Selection()
    for suite_id in requested:
        tests = suites[suite_id]["tests"]
        selection.tests.update(tests)
        selection.reasons.append(
            f"suite {suite_id}: {suites[suite_id]['description']} ({len(tests)} modules)"
        )
    return selection


def git_changed_paths(root: Path, base: str | None) -> set[str]:
    probe = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"], cwd=root,
        text=True, capture_output=True, check=False,
    )
    if probe.returncode or probe.stdout.strip() != "true":
        raise GitDiscoveryError(f"not a Git worktree: {root}")
    commands: list[list[str]] = []
    if base:
        commands.append(["git", "diff", "--name-only", "-z", "--diff-filter=ACMRTUXB", f"{base}...HEAD"])
    commands.extend([
        ["git", "diff", "--name-only", "-z", "--diff-filter=ACMRTUXB"],
        ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRTUXB"],
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
    ])
    changed: set[str] = set()
    for command in commands:
        result = subprocess.run(command, cwd=root, capture_output=True, check=False)
        if result.returncode:
            message = result.stderr.decode("utf-8", "replace").strip()
            raise GitDiscoveryError(f"{' '.join(command)} failed: {message}")
        for raw in result.stdout.split(b"\0"):
            if raw:
                changed.add(raw.decode("utf-8", "surrogateescape"))
    return changed


def read_changed_file(path: str) -> list[str]:
    if path == "-":
        text = sys.stdin.read()
    else:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ImpactError(f"cannot read changed-path file {path}: {exc}") from exc
    return [line.strip() for line in text.splitlines() if line.strip()]


def snapshot_as_json(snapshot: Snapshot) -> dict:
    return {
        "schema_version": 1,
        "impact_manifest_sha256": snapshot.manifest_sha256,
        "scripts": dict(snapshot.scripts),
        "tests": dict(snapshot.tests),
        "support": dict(snapshot.support),
    }


def _snapshot_toplevel_lock_sha256(snapshot: Snapshot) -> str:
    value = snapshot.support.get(CONTAINER_TOPLEVEL_LOCK_RELATIVE)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ImpactError(
            "full-suite snapshot is missing the top-level container lock hash"
        )
    return value


def full_suite_environment(*, expected_lock_sha256: str | None = None) -> dict:
    """Return the local execution identity bound to a full-suite result."""
    versions = []
    for name, _expected in CONTAINER_TOPLEVEL_REQUIREMENTS:
        try:
            version = importlib_metadata.version(name)
        except importlib_metadata.PackageNotFoundError as exc:
            raise ImpactError(
                f"top-level container distribution is unavailable: {name}"
            ) from exc
        if version != _expected:
            raise ImpactError(
                f"top-level container distribution {name} must be {_expected}, "
                f"got {version}"
            )
        versions.append(f"{name}=={version}")
    try:
        lock_metadata = CONTAINER_TOPLEVEL_LOCK.lstat()
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_size > 64 * 1024
        ):
            raise ImpactError("top-level container lock is unsafe")
        lock_bytes = CONTAINER_TOPLEVEL_LOCK.read_bytes()
    except OSError as exc:
        raise ImpactError(f"cannot read top-level container lock: {exc}") from exc
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    if expected_lock_sha256 is not None and lock_sha256 != expected_lock_sha256:
        raise ImpactError(
            "top-level container lock does not match the tested source snapshot"
        )
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_implementation": platform.python_implementation(),
        "python_version": list(sys.version_info[:3]),
        "python_cache_tag": sys.implementation.cache_tag,
        "platform": sys.platform,
        "machine": platform.machine(),
        "container_toplevel_versions": sorted(versions, key=str.casefold),
        "container_toplevel_lock_sha256": lock_sha256,
    }


def full_suite_scenario_coverage() -> dict[str, str]:
    """State the exact boundary of a locally issued full-suite proof."""
    return {ROOT_ENTRYPOINT_SCENARIO: ROOT_ENTRYPOINT_NOT_COVERED}


def full_suite_attestation(
    snapshot: Snapshot, *, environment: Mapping[str, object] | None = None,
    validation_only: bool = False,
) -> dict:
    """Bind a successful full discovery run to exact bytes and environment."""
    canonical = json.dumps(
        snapshot_as_json(snapshot),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    expected_lock_sha256 = _snapshot_toplevel_lock_sha256(snapshot)
    if environment is None:
        environment = full_suite_environment(
            expected_lock_sha256=expected_lock_sha256,
        )
    elif environment.get("container_toplevel_lock_sha256") != expected_lock_sha256:
        raise ImpactError(
            "full-suite environment lock does not match the tested source snapshot"
        )
    result = {
        "schema_version": 1,
        "snapshot_sha256": hashlib.sha256(canonical).hexdigest(),
        "environment": dict(environment),
        "scenario_coverage": full_suite_scenario_coverage(),
    }
    if validation_only:
        result["validation_only"] = {
            "issue": "ISSUE-0016",
            "known_failed_tests": list(ISSUE0016_FAILURE_IDS),
            "baseline_skipped_tests": list(VALIDATION_BASELINE_SKIP_IDS),
            "not_a_release_proof": True,
        }
    return result


def full_suite_coverage_summary(value: Mapping[str, object]) -> str:
    """Render the bounded scenario field without implying unexecuted coverage."""
    coverage = value.get("scenario_coverage")
    if coverage != full_suite_scenario_coverage():
        raise ImpactError("full-suite scenario coverage is missing or malformed")
    return f"{ROOT_ENTRYPOINT_SCENARIO}: {ROOT_ENTRYPOINT_NOT_COVERED}"


def full_suite_attestation_is_current(
    snapshot: Snapshot, value: object, *, validation_only: bool = False,
) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        current = full_suite_attestation(snapshot, validation_only=validation_only)
    except ImpactError:
        return False
    return value == current


def atomic_write_approvals(
    path: Path,
    snapshot: Snapshot,
    *,
    full_suite: bool = False,
    full_suite_environment_value: Mapping[str, object] | None = None,
    validation_only: bool = False,
    post_publish_verify: Callable[[], None] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prior_payload = None
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ImpactError(f"refusing unsafe approval ledger: {path}")
        try:
            prior_payload = path.read_bytes()
        except OSError as exc:
            raise ImpactError(f"cannot preserve prior approval ledger: {exc}") from exc
    approved = snapshot_as_json(snapshot)
    if full_suite:
        expected_lock_sha256 = _snapshot_toplevel_lock_sha256(snapshot)
        if full_suite_environment_value is None:
            full_suite_environment_value = full_suite_environment(
                expected_lock_sha256=expected_lock_sha256,
            )
        current_environment = full_suite_environment(
            expected_lock_sha256=expected_lock_sha256,
        )
        if dict(full_suite_environment_value) != current_environment:
            raise ImpactError(
                "full-suite environment changed before approval write"
            )
        approved["full_suite_attestation"] = full_suite_attestation(
            snapshot, environment=full_suite_environment_value,
            validation_only=validation_only,
        )
    payload = json.dumps(
        approved, ensure_ascii=False, indent=2, sort_keys=True,
    ) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent), text=True,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if full_suite:
            final_environment = full_suite_environment(
                expected_lock_sha256=expected_lock_sha256,
            )
            if dict(full_suite_environment_value) != final_environment:
                raise ImpactError(
                    "full-suite environment changed during approval write"
                )
        os.replace(temporary, path)
        published = path.lstat()
        try:
            if post_publish_verify is not None:
                post_publish_verify()
        except BaseException:
            current = path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or (current.st_dev, current.st_ino)
                != (published.st_dev, published.st_ino)
            ):
                raise ImpactError(
                    "approval state changed and the published ledger cannot be "
                    "safely rolled back"
                )
            if prior_payload is None:
                path.unlink()
            else:
                restore_fd, restore_name = tempfile.mkstemp(
                    prefix=f".{path.name}.restore.",
                    dir=str(path.parent),
                )
                restore = Path(restore_name)
                try:
                    os.fchmod(restore_fd, 0o644)
                    with os.fdopen(restore_fd, "wb") as restore_handle:
                        restore_handle.write(prior_payload)
                        restore_handle.flush()
                        os.fsync(restore_handle.fileno())
                    os.replace(restore, path)
                finally:
                    try:
                        restore.unlink()
                    except FileNotFoundError:
                        pass
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            raise
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_preflight_authority(root: Path):
    """Import the existing authority predicate without executing its tests."""
    path = root / "test_cases/test_public_publication_workflow.py"
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ImpactError("public clean-state authority is not a regular file")
    name = "_impact_preflight_authority"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImpactError("public clean-state authority cannot be imported")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        with _private_bytecode_namespace():
            _exec_current_source(spec, module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def _git_blob_oid(payload: bytes, oid_width: int) -> str:
    framed = b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
    if oid_width == 40:
        return hashlib.sha1(framed).hexdigest()
    if oid_width == 64:
        return hashlib.sha256(framed).hexdigest()
    raise ValueError("unsupported Git object identity width")


def _worktree_differs_from_index(root: Path, authority) -> bool:
    """Compare reported worktree candidates to index blobs without refreshing it."""
    candidates = authority._git_run(
        root, ["diff-files", "--name-only", "-z", "--"],
    )
    if candidates.returncode != 0:
        raise ValueError("Git worktree candidate scan failed")
    for encoded in filter(None, candidates.stdout.split(b"\0")):
        relative = os.fsdecode(encoded)
        staged = authority._git_run(
            root, ["ls-files", "--stage", "-z", "--", relative],
        )
        records = [record for record in staged.stdout.split(b"\0") if record]
        if staged.returncode != 0 or len(records) != 1 or b"\t" not in records[0]:
            return True
        header, listed = records[0].split(b"\t", 1)
        fields = header.split()
        if len(fields) != 3 or fields[2] != b"0" or listed != encoded:
            return True
        index_mode = fields[0].decode("ascii", "strict")
        index_oid = fields[1].decode("ascii", "strict")
        path = root / relative
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                worktree_mode = "120000"
                payload = os.fsencode(os.readlink(path))
            elif stat.S_ISREG(metadata.st_mode):
                worktree_mode = "100755" if metadata.st_mode & 0o111 else "100644"
                payload = path.read_bytes()
            else:
                return True
        except OSError:
            return True
        if worktree_mode != index_mode:
            return True
        if _git_blob_oid(payload, len(index_oid)) != index_oid:
            return True
    return False


def _preflight_clean_candidate(root: Path, selected: set[str]) -> None:
    git_entry = root / ".git"
    try:
        git_mode = git_entry.lstat().st_mode
    except OSError:
        git_mode = 0
    if stat.S_ISREG(git_mode):
        raise ImpactError(
            "EFF E-3: linked Git worktree cannot supply the public authority's "
            ".git/index proof; run this proof from the repository's main checkout"
        )
    current_candidate = False
    for test_id in sorted(selected):
        path = root / (test_id.replace(".", "/") + ".py")
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ImpactError(
                "EFF E-3: selected public authority is unavailable; restore the "
                f"regular authority module {test_id} and rerun this preflight"
            )
        if sha256_file(path) != PREFLIGHT_HISTORICAL_TESTS[test_id]:
            current_candidate = True
    if not current_candidate:
        # This is only dispatch, not a successful staged-proof attestation.
        # The unchanged historical tests still check their full contract.
        return
    try:
        authority = _load_preflight_authority(root)
        captured_head = authority._head(root)
        ledger = (root / authority.P_LEDGER_PATH).read_bytes()
    except Exception as exc:
        raise ImpactError(
            "EFF E-3: selected public authority or Git metadata is unavailable; "
            "repair the main checkout's Git metadata and rerun this preflight; "
            f"required Git/authority checks must succeed ({exc})"
        ) from exc
    try:
        # The SAME predicate used by public/historical authority tests. In
        # particular, ledger-only dirt is not a special preflight exception.
        authority._assert_clean_and_ledger(root, ledger, captured_head)
    except Exception as exc:
        try:
            index_path = root / ".git/index"
            index_before = index_path.read_bytes()
            index_metadata = index_path.lstat()
            staged = authority._git_run(
                root, ["diff-index", "--cached", "--quiet", captured_head, "--"],
            )
            unstaged = _worktree_differs_from_index(root, authority)
            untracked = authority._git_run(
                root, ["ls-files", "--others", "--exclude-standard", "-z"],
            )
            index_after = index_path.read_bytes()
            after_metadata = index_path.lstat()
        except Exception as probe_exc:
            raise ImpactError(
                "EFF E-3: selected public authority or Git metadata is unavailable; "
                "repair the main checkout's Git metadata and rerun this preflight; "
                f"required Git/authority checks must succeed ({probe_exc})"
            ) from probe_exc
        if (
            staged.returncode not in (0, 1) or untracked.returncode != 0
            or index_before != index_after
            or (index_metadata.st_dev, index_metadata.st_ino, index_metadata.st_mode)
            != (after_metadata.st_dev, after_metadata.st_ino, after_metadata.st_mode)
            or authority._head(root) != captured_head
        ):
            raise ImpactError(
                "EFF E-3: selected public authority or Git metadata is unavailable; "
                "repair the main checkout's Git metadata and rerun this preflight; "
                "required Git/authority checks must succeed"
            ) from exc
        if staged.returncode or unstaged or untracked.stdout:
            raise ImpactError(
                "EFF E-3: selected public authority found staged, unstaged, "
                "untracked, or ledger changes; commit the reviewed source/test "
                "candidate after review and rerun this preflight; "
                f"required Git/authority checks must succeed ({exc})"
            ) from exc
        if str(exc) != "P clean checkout has changed or untracked content":
            raise ImpactError(
                "EFF E-3: selected public authority or Git metadata is unavailable; "
                "repair the main checkout's Git metadata and rerun this preflight; "
                f"required Git/authority checks must succeed ({exc})"
            ) from exc
        raise ImpactError(
            "EFF E-3: selected public authority found content-identical stat dirt; "
            "run `git status` to refresh the index, then rerun this preflight; "
            "commit only if Git still reports reviewed source/test changes; "
            f"required Git/authority checks must succeed ({exc})"
        ) from exc


def _preflight_loopback_bind() -> None:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", 0))
        finally:
            probe.close()
    except OSError as exc:
        raise ImpactError(
            "EFF E-1: local AF_INET TCP bind capability unavailable; use a scoped "
            "rerun in an environment permitting 127.0.0.1 loopback bind "
            f"for the selected fixtures ({exc})"
        ) from exc


def preflight_selection(root: Path, selection: Selection) -> None:
    """Read-only capability checks for the effective modules, never approval."""
    effective = set(discover_tests(root)) if selection.full_suite else selection.tests
    public_authorities = set(effective).intersection(PREFLIGHT_HISTORICAL_TESTS)
    if public_authorities:
        _preflight_clean_candidate(root, public_authorities)
    if PREFLIGHT_INET_TESTS.intersection(effective):
        _preflight_loopback_bind()


def run_selection(root: Path, selection: Selection, verbose: bool) -> int:
    preflight_selection(root, selection)
    if selection.full_suite:
        command = [
            sys.executable, "-B", "-m", "unittest", "discover", "-b",
            "-s", "test_cases", "-t", ".", "-p", "test_*.py",
        ]
        if verbose:
            command.append("-v")
    else:
        command = [sys.executable, "-B", "-m", "unittest", "-b"]
        if verbose:
            command.append("-v")
        command.extend(sorted(selection.tests))
    environment = os.environ.copy()
    # -B prevents bytecode writes, not reads. A fresh private namespace keeps
    # canonical discovery and dependency imports bound to current source bytes
    # without deleting or trusting the operator's existing cache.
    with tempfile.TemporaryDirectory(prefix="http-related-test-pyc-") as directory:
        environment["PYTHONPYCACHEPREFIX"] = directory
        result = subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    return 0 if result.returncode == 0 else 1


def issue0016_validation_report_is_exact(value: object) -> bool:
    """Approve only the original three FAILs, with no new skips or masking."""
    if not isinstance(value, dict) or set(value) != {
        "tests_run", "failures", "errors", "skipped", "expected_failures",
        "unexpected_successes",
    }:
        return False
    if type(value["tests_run"]) is not int or value["tests_run"] < 3735:
        return False
    for field in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
        if not isinstance(value[field], list):
            return False
    if value["errors"] or value["expected_failures"] or value["unexpected_successes"]:
        return False
    failures = value["failures"]
    if len(failures) != len(ISSUE0016_FAILURE_IDS):
        return False
    if not all(
        isinstance(item, dict) and set(item) == {"id", "traceback"}
        and isinstance(item["id"], str) and isinstance(item["traceback"], str)
        and ISSUE0016_FAILURE_FRAGMENT in item["traceback"]
        for item in failures
    ):
        return False
    if {item["id"] for item in failures} != set(ISSUE0016_FAILURE_IDS):
        return False
    skipped = value["skipped"]
    if len(skipped) != len(VALIDATION_BASELINE_SKIP_IDS):
        return False
    if not all(
        isinstance(item, dict) and set(item) == {"id", "reason"}
        and isinstance(item["id"], str) and isinstance(item["reason"], str)
        for item in skipped
    ):
        return False
    return {item["id"] for item in skipped} == set(VALIDATION_BASELINE_SKIP_IDS)


def validate_timings_destination(root: Path, destination: Path) -> None:
    """Require a new diagnostic file outside the governed checkout."""
    if not destination.is_absolute():
        raise ImpactError("--timings requires an absolute path")
    if os.path.lexists(destination):
        raise ImpactError("--timings destination already exists")
    try:
        repository = root.resolve(strict=True)
        parent = destination.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImpactError("--timings parent directory is unavailable") from exc
    if not parent.is_dir():
        raise ImpactError("--timings parent is not a directory")
    if parent == repository or repository in parent.parents:
        raise ImpactError("--timings destination must be outside the repository")


def run_validation_selection(
    root: Path, selection: Selection, verbose: bool,
    timings_path: Path | None = None,
) -> int:
    """Run unchanged assertions and accept only the exact validation exception."""
    if not selection.full_suite:
        raise ImpactError("validation-only mode requires canonical full discovery")
    if timings_path is not None:
        validate_timings_destination(root, timings_path)
    preflight_selection(root, selection)
    with tempfile.TemporaryDirectory(prefix="http-v3-validation-report-") as directory:
        report_path = Path(directory) / "unittest-result.json"
        command = [
            sys.executable, "-B", "-m", "test_cases.validation_unittest",
            str(report_path),
        ]
        if verbose:
            command.append("-v")
        if timings_path is not None:
            command.extend(("--timings", str(timings_path)))
        environment = os.environ.copy()
        cache = Path(directory) / "pycache"
        cache.mkdir(mode=0o700)
        environment["PYTHONPYCACHEPREFIX"] = str(cache)
        completed = subprocess.run(
            command, cwd=root, env=environment, stdin=subprocess.DEVNULL,
            check=False,
        )
        try:
            info = report_path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_000_000:
                raise ImpactError("unsafe or oversized validation test report")
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, ImpactError) as exc:
            print(f"validation-only report unavailable: {exc}", file=sys.stderr)
            return 1
        if completed.returncode != 0 or not issue0016_validation_report_is_exact(report):
            print("validation-only test report is not the exact ISSUE-0016 exception", file=sys.stderr)
            return 1
        print(
            "VALIDATION ONLY: three ISSUE-0016 tests remain FAIL; "
            "four unchanged real-environment skips; all others passed; "
            "this is not a final release proof"
        )
        return 0


# ---------------------------------------------------------------------------
# Opt-in two-phase sharded full proof (PROP-14, G5Q-RA landing form).
#
# The serial --all path above is unchanged.  --all --sharded DIR runs the SAME
# canonical discovery as lanes of a reviewed, tracked plan: phase A lanes run in
# parallel in private APFS clones, then the single phase-B (quiet) lane runs
# alone.  Every canonical row must be executed exactly once in its assigned
# lane (or be suppressed by a recognised class/module SkipTest holder, exactly
# as serial unittest would not run it); every skip entry must be a decorator
# skip of the canonical enumeration (run in the coordinator's environment) or a
# plan-allowed runtime skip with its exact reason; any failure, missing record,
# deadline, leftover, residue, gate or cleanup problem returns 1 before any
# approval.  On success the caller writes the same attestation bytes as the
# serial path; the execution form is recorded only in the external audit file.
#
# S0 (first real run, 2026-10-24): lane temporary and work roots must lie outside
# the machine-shared /tmp and /var/tmp (the suite writes into /tmp directly while
# other lanes pin every ancestor directory); a lane checkout must pass the serial
# post-run check (manifest re-validation and snapshot), and tracked or untracked
# non-ignored leftovers still block; a change of a lane checkout's ignored files
# refuses the proof unless the plan's leftover_allowlist reviewed its shape (serial
# shows it to every later test, other lanes do not); lane-TMPDIR entries and
# reviewed changes are only inventoried and removed with the lane.  Test failures
# and unreviewed ignored-file changes never skip phase B (the run still fails);
# runner-detected isolation and gate problems do.
# ---------------------------------------------------------------------------

FULL_SHARD_PLAN_RELATIVE = "test_cases/full_shard_plan.json"
FULL_SHARD_PLATFORMS = frozenset({"darwin"})
# Not below the most recent formal serial --all wall clock recorded in
# CHANGE_AWARE_TESTING.md (8,816.975 s): a lane is never stopped for running as
# long as that recorded serial suite; raise it before the serial wall clock grows
# close to it.
FULL_SHARD_MIN_LANE_DEADLINE_SECONDS = 9000
FULL_SHARD_RESIDUE_GRACE_SECONDS = 20.0
FULL_SHARD_TERMINATE_GRACE_SECONDS = 10.0
FULL_SHARD_LANE_RE = re.compile(r"^w[0-9a-z]{1,8}$")
FULL_SHARD_SLICE_RE = re.compile(r"^(test_cases\.test_[A-Za-z0-9_]+)#([0-9]+)/([0-9]+)$")
FULL_SHARD_HOLDER_RE = re.compile(r"^(setUpClass|setUpModule) \(([A-Za-z_][\w.]*)\)$")
FULL_SHARD_PLAN_KEYS = frozenset({
    "schema_version", "description", "derivation", "lane_deadline_seconds",
    "phase_a", "phase_b", "slices", "same_lane", "phase_b_reasons",
})
# Optional plan keys; an absent runtime_skips allows no runtime skip at all, and an
# absent leftover_allowlist reviews no change of a lane checkout's ignored files.
FULL_SHARD_PLAN_OPTIONAL_KEYS = frozenset({"runtime_skips", "leftover_allowlist"})
# A serial skip entry id of a test (MODULE.Class.test) or of one of its
# sub-tests (MODULE.Class.test (params)); fixture holders use FULL_SHARD_HOLDER_RE.
FULL_SHARD_SKIP_ENTRY_RE = re.compile(
    r"^test_cases\.test_[A-Za-z0-9_]+(?:\.[A-Za-z_][A-Za-z0-9_]*){2,}(?: .+)?$"
)
FULL_SHARD_ACCEPTED_OUTCOMES = frozenset({"success", "skipped", "expected_failure"})
FULL_SHARD_GIT_FORBIDDEN = (
    "commondir", "shallow", "info/grafts", "objects/info/alternates",
    "objects/info/http-alternates", "index.lock",
)
# Absolute paths: an operator PATH may omit /usr/sbin (cp is /bin/cp as well).
FULL_SHARD_PS = "/bin/ps"
FULL_SHARD_LSOF = "/usr/sbin/lsof"
# The only GIT_* variables kept for coordinator git and lanes (see _full_shard_environment).
FULL_SHARD_GIT_CONFIG_SELECTORS = frozenset({"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"})
# Machine-shared temporary directories (S0): the suite itself creates entries
# directly in /tmp (for example test_load_release_transaction's /tmp/http-rt-*
# release roots) while lanes run concurrently, and several quiet-window checks pin
# the stat of every ancestor directory from "/".  No lane root may lie below them.
FULL_SHARD_SHARED_TEMP_ROOTS = ("/tmp", "/var/tmp")
# Ignored-file shapes some test reads across the whole checkout (census of the suite's
# traversals: rglob("*.py"), os.walk for test_*.py, rglob("*.service"/"*.timer"),
# rglob("02-AIR-devices_config.csv")) or the serial source discovery considers
# (*.py, *.sh, *.cgi).  The plan's leftover_allowlist can never review them outside
# the non-source roots (NON_SOURCE_ROOTS and the .codex_tmp prefix): the serial source
# discovery skips those roots, and the suite's test-side whole-checkout walks go
# through governed_tree_paths (test_test_case_repository), which never enters them.
FULL_SHARD_OBSERVED_LEFTOVER_SUFFIXES = frozenset({".py", ".sh", ".cgi", ".service", ".timer"})
FULL_SHARD_OBSERVED_LEFTOVER_NAMES = frozenset({"02-AIR-devices_config.csv"})
FULL_SHARD_DEFAULT_MANIFEST_RELATIVE = "test_cases/script_test_manifest.json"

# Executed by `sys.executable -B -c` in a lane checkout.  It reproduces
# `python -m unittest discover -b -s test_cases -t . -p test_*.py [-v]`:
# the same sys.path[0], argv, loader, discovery (every module imported),
# TextTestRunner(buffer, verbosity, warnings) and exit status, and only runs the
# canonical rows whose indices the coordinator assigned to this lane.  Like the
# serial TestSuite.run it keeps no test instance beyond the run suite, which
# drops each test once it has run.
FULL_SHARD_LANE_SOURCE = r'''
import hashlib
import json
import os
import sys
import time
import unittest

_mode, _spec_path, _out_path = sys.argv[1:4]
if not getattr(sys.flags, "safe_path", False):
    sys.path[0] = os.getcwd()
with open(_spec_path, encoding="utf-8") as _handle:
    _spec = json.load(_handle)
_verbose = bool(_spec["verbose"])
sys.argv = ["python -m unittest", "discover", "-b", "-s", "test_cases", "-t", ".",
            "-p", "test_*.py"] + (["-v"] if _verbose else [])
_out = os.open(_out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)


def _emit(record):
    _view = memoryview((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))
    while _view:
        _view = _view[os.write(_out, _view):]


class _FullShardLoader(unittest.TestLoader):
    def loadTestsFromModule(self, module, *args, **kwargs):
        suite = super().loadTestsFromModule(module, *args, **kwargs)
        suite._full_shard_loader_module = module.__name__
        return suite


def _walk(node, tag, out):
    tag = getattr(node, "_full_shard_loader_module", tag)
    for item in node:
        if isinstance(item, unittest.TestSuite):
            _walk(item, tag, out)
        else:
            out.append((item, tag))


_BASE_SETUP = unittest.TestCase.__dict__["setUpClass"].__func__
_BASE_TEARDOWN = unittest.TestCase.__dict__["tearDownClass"].__func__


def _class_fixture(cls):
    try:
        return (getattr(cls.setUpClass, "__func__", None) is not _BASE_SETUP
                or getattr(cls.tearDownClass, "__func__", None) is not _BASE_TEARDOWN)
    except Exception:
        return True


def _module_fixture(name):
    module = sys.modules.get(name)
    return module is None or hasattr(module, "setUpModule") or hasattr(module, "tearDownModule")


def _decorator_skip(test):
    """The reason TestCase.run skips this test before setUp (class or method skip), else None."""
    cls = type(test)
    method = getattr(test, getattr(test, "_testMethodName", ""), None)
    if getattr(cls, "__unittest_skip__", False) or getattr(method, "__unittest_skip__", False):
        return str(getattr(cls, "__unittest_skip_why__", "") or getattr(method, "__unittest_skip_why__", ""))
    return None


def _row(test, tag):
    cls = type(test)
    return {
        "id": test.id(), "module": tag, "class_module": cls.__module__,
        "class": cls.__qualname__, "class_fixture": _class_fixture(cls),
        "module_fixture": _module_fixture(cls.__module__),
    }


def _discover():
    """Canonical (test, loader module) pairs; the discovery suite itself is not kept."""
    pairs = []
    _walk(_FullShardLoader().discover("test_cases", pattern="test_*.py", top_level_dir="."), None, pairs)
    return pairs


def _decorator_skips(pairs):
    found = []
    for index, (test, _tag) in enumerate(pairs):
        reason = _decorator_skip(test)
        if reason is not None:
            found.append({"index": index, "reason": reason})
    return found


def _selected_suite(pairs, indices):
    """Only this lane's tests, each tagged with its canonical index, in canonical order."""
    suite = unittest.TestSuite()
    for index, (test, _tag) in enumerate(pairs):
        if index in indices:
            test._full_shard_index = index
            suite.addTest(test)
    return suite


_pairs = _discover()
_rows = [_row(_test, _tag) for _test, _tag in _pairs]
_digest = hashlib.sha256(json.dumps(
    _rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
).encode("utf-8")).hexdigest()
_emit({"event": "start", "canonical_sha256": _digest, "count": len(_rows),
       "executable": os.path.realpath(sys.executable), "version": list(sys.version_info[:3]),
       "cache_tag": sys.implementation.cache_tag, "platform": sys.platform,
       "machine": os.uname().machine, "cwd": os.getcwd(),
       "tmpdir": os.environ.get("TMPDIR", ""), "epoch": round(time.time(), 3)})
_module_cleanups = len(getattr(unittest.case, "_module_cleanups", []))
if _mode == "enumerate":
    _emit({"event": "rows", "rows": _rows, "module_cleanups": _module_cleanups,
           "decorator_skips": _decorator_skips(_pairs)})
    _emit({"event": "finished", "tests_run": 0, "successful": True, "epoch": round(time.time(), 3)})
    os.close(_out)
    sys.exit(0)
if _spec.get("canonical_sha256") != _digest or _spec.get("count") != len(_rows):
    _emit({"event": "fatal", "reason": "lane discovery differs from the canonical enumeration"})
    os.close(_out)
    sys.exit(3)
if _module_cleanups:
    _emit({"event": "fatal", "reason": "module cleanups were registered during discovery"})
    os.close(_out)
    sys.exit(3)
_run_suite = _selected_suite(_pairs, set(int(_index) for _index in _spec["indices"]))
del _pairs
_ORDER = ("success", "skipped", "expected_failure", "unexpected_success", "failure", "error")


class _FullShardResult(unittest.TextTestResult):
    def startTest(self, test):
        self._full_shard_started = time.perf_counter()
        self._full_shard_outcome = "success"
        self._full_shard_index = getattr(test, "_full_shard_index", -1)
        super().startTest(test)

    def _full_shard_mark(self, outcome):
        current = getattr(self, "_full_shard_outcome", "success")
        if _ORDER.index(outcome) > _ORDER.index(current):
            self._full_shard_outcome = outcome

    def addError(self, test, err):
        if isinstance(test, unittest.TestCase):
            self._full_shard_mark("error")
        else:
            _emit({"event": "holder", "kind": "error", "description": str(test)})
        super().addError(test, err)

    def addFailure(self, test, err):
        self._full_shard_mark("failure")
        super().addFailure(test, err)

    def addSkip(self, test, reason):
        # One record per serial skip entry: the test (or sub-test) id, or the holder.
        if isinstance(test, unittest.TestCase):
            self._full_shard_mark("skipped")
            _emit({"event": "skip", "index": getattr(self, "_full_shard_index", -1),
                   "id": test.id(), "reason": str(reason)})
        else:
            _emit({"event": "holder", "kind": "skip", "description": str(test), "reason": str(reason)})
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self._full_shard_mark("expected_failure")
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._full_shard_mark("unexpected_success")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self._full_shard_mark("failure" if issubclass(err[0], test.failureException) else "error")
        super().addSubTest(test, subtest, err)

    def stopTest(self, test):
        super().stopTest(test)
        _emit({"event": "test", "index": getattr(test, "_full_shard_index", -1), "id": test.id(),
               "outcome": getattr(self, "_full_shard_outcome", "error"),
               "seconds": round(time.perf_counter() - getattr(self, "_full_shard_started", 0.0), 4)})


_runner = unittest.TextTestRunner(
    verbosity=2 if _verbose else 1, buffer=True, resultclass=_FullShardResult,
    warnings=None if sys.warnoptions else "default",
)
_result = _runner.run(_run_suite)
_emit({"event": "finished", "tests_run": _result.testsRun, "successful": _result.wasSuccessful(),
       "epoch": round(time.time(), 3)})
os.close(_out)
sys.exit(0 if _result.wasSuccessful() else 1)
'''


def _full_shard_platform_message() -> str:
    return (
        "--sharded is supported only on " + ", ".join(sorted(FULL_SHARD_PLATFORMS))
        + " (APFS clonefile lane checkouts); use the serial --all elsewhere"
    )


def full_shard_lane_identity() -> dict:
    """Interpreter identity every lane must report; the same interpreter as the proof."""
    machine = os.uname().machine if hasattr(os, "uname") else platform.machine()
    return {
        "executable": os.path.realpath(sys.executable),
        "version": list(sys.version_info[:3]),
        "cache_tag": sys.implementation.cache_tag,
        "platform": sys.platform,
        "machine": machine,
    }


def validate_full_shard_destination(root: Path, destination: Path) -> None:
    """Require a new evidence directory outside the governed checkout."""
    destination = Path(destination)
    if not destination.is_absolute():
        raise ImpactError("--sharded requires an absolute path for its new evidence directory")
    if os.path.lexists(destination):
        raise ImpactError("--sharded destination already exists")
    try:
        repository = Path(root).resolve(strict=True)
        parent = destination.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ImpactError("--sharded parent directory is unavailable") from exc
    if not parent.is_dir():
        raise ImpactError("--sharded parent directory is unavailable")
    if parent == repository or repository in parent.parents:
        raise ImpactError("--sharded destination must be outside the repository")


def full_shard_shared_temp_problems(
    paths: Mapping[str, object], shared_roots: Sequence[str] = FULL_SHARD_SHARED_TEMP_ROOTS,
) -> list[str]:
    """Refuse lane roots below a machine-shared temporary directory (S0).

    Lanes run concurrently; the suite itself creates entries directly in /tmp, and
    the quiet-window checks of 11-load, b-xlsx_to_dot and the monitor publication path
    pin the stat of every ancestor directory from "/".  A lane TMPDIR or checkout
    below such a directory would see another lane change its ancestor; a serial run
    never overlaps those tests.  Paths are judged by realpath, existing or not, and by
    the identity (st_dev, st_ino) of every existing ancestor, so another spelling of
    the same directory on a case-insensitive volume is refused as well.
    """
    roots: list[str] = []
    identities: dict[tuple[int, int], str] = {}
    for shared in shared_roots:
        real = os.path.realpath(shared)
        if real not in roots:
            roots.append(real)
        try:
            info = os.stat(real)
        except OSError:
            continue
        identities.setdefault((info.st_dev, info.st_ino), real)
    problems = []
    for label, path in paths.items():
        real = os.path.realpath(os.fspath(path))
        hit = next(
            (root for root in roots if real == root or real.startswith(root.rstrip(os.sep) + os.sep)),
            None,
        )
        if hit is None:
            for candidate in [Path(real), *Path(real).parents]:
                try:
                    info = os.stat(candidate)
                except OSError:
                    continue
                hit = identities.get((info.st_dev, info.st_ino))
                if hit is not None:
                    break
        if hit is not None:
            problems.append(
                f"{label} {os.fspath(path)} is inside the machine-shared temporary directory "
                f"{hit}: the suite writes there directly while other lanes pin every ancestor "
                "directory; put TMPDIR and the --sharded directory below a dedicated directory "
                "that no other process uses as its TMPDIR or writes into during the run"
            )
    return problems


def full_shard_unreviewed_leftovers(paths: Iterable[str], allowlist: Mapping[str, str]) -> list[str]:
    """Sorted paths that no reviewed plan pattern (fnmatchcase; '*' also spans '/') matches.

    A path of an observed shape (FULL_SHARD_OBSERVED_LEFTOVER_*) outside the runner's
    non-source roots is never reviewed; inside them only a reviewed pattern accepts it.
    """
    def observed(path: str) -> bool:
        top = path.split("/", 1)[0]
        if top in NON_SOURCE_ROOTS or top.startswith(".codex_tmp"):
            return False
        name = path.rsplit("/", 1)[-1]
        return (
            name in FULL_SHARD_OBSERVED_LEFTOVER_NAMES
            or os.path.splitext(name)[1] in FULL_SHARD_OBSERVED_LEFTOVER_SUFFIXES
        )

    return sorted(
        path for path in paths
        if observed(path) or not any(fnmatch.fnmatchcase(path, pattern) for pattern in allowlist)
    )


def full_shard_inventory(paths: Iterable[str]) -> dict:
    """Sorted list, count and sha256 (NUL-joined file-system bytes) of leftover paths."""
    ordered = sorted(paths)
    return {
        "paths": ordered, "count": len(ordered),
        "sha256": hashlib.sha256(b"\0".join(os.fsencode(path) for path in ordered)).hexdigest(),
    }


def full_shard_chain(path: object) -> list[list]:
    """[path, nine-field stat or None] for every directory from "/" down to realpath(path)."""
    real = Path(os.path.realpath(os.fspath(path)))
    chain: list[list] = []
    for item in [*reversed(real.parents), real]:
        try:
            info = os.lstat(item)
        except OSError:
            nine = None
        else:
            nine = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        chain.append([str(item), nine])
    return chain


def full_shard_chain_drift(before: Sequence[Sequence], after: Sequence[Sequence]) -> list[dict]:
    """Every chain entry whose stat differs (or appears/disappears) between two readings."""
    old = {path: nine for path, nine in before}
    new = {path: nine for path, nine in after}
    order = [path for path, _nine in before] + [path for path, _nine in after if path not in old]
    return [
        {"path": path, "before": old.get(path), "after": new.get(path)}
        for path in order if old.get(path) != new.get(path)
    ]


def _full_shard_serial_check(checkout: Path, root: Path, manifest_path: Path) -> dict:
    """The serial cycle's post-run predicate (_one_cycle) for one checkout.

    Re-validates the manifest against the checkout (source inventory, tests,
    deployment selectors, support) and reads its snapshot; any refusal raises.  The
    selectors run in this process and may extend sys.path at import (for example
    infra/docker/activate.py); sys.path is restored afterwards.
    """
    checkout, manifest_path = Path(checkout), Path(manifest_path)
    try:
        located = checkout / manifest_path.relative_to(root)
    except ValueError:
        located = manifest_path
    saved = list(sys.path)
    try:
        validated = load_and_validate_manifest(checkout, located)
        return snapshot_as_json(make_snapshot(checkout, located, validated))
    finally:
        sys.path[:] = saved


def _full_shard_snapshot_changes(before: Mapping, after: Mapping) -> list[str]:
    """Names of what differs between two serial source/test snapshots (snapshot_as_json)."""
    changes = []
    if before.get("impact_manifest_sha256") != after.get("impact_manifest_sha256"):
        changes.append("manifest")
    for section in ("scripts", "tests", "support"):
        old, new = before.get(section) or {}, after.get(section) or {}
        changes.extend(
            f"{section}:{key}" for key in sorted(set(old) | set(new)) if old.get(key) != new.get(key)
        )
    if not changes and before != after:
        changes.append("snapshot schema")
    return changes


def _full_shard_plan_error(message: str) -> ImpactError:
    return ImpactError(f"full shard plan: {message}")


def _parse_full_shard_unit(unit: object) -> tuple[str, str, object]:
    """('module', M, None) | ('slice', M, (index, count)) | ('case', M, case_id)."""
    if not isinstance(unit, str) or not unit:
        raise _full_shard_plan_error(f"unit must be a non-empty string: {unit!r}")
    if "::" in unit:
        module, case_id = unit.split("::", 1)
        if (
            not TEST_ID_RE.fullmatch(module)
            or not case_id.startswith(module + ".")
            or len(case_id.split(".")) < 4
        ):
            raise _full_shard_plan_error(f"case unit must be MODULE::MODULE.Class.test: {unit}")
        return "case", module, case_id
    match = FULL_SHARD_SLICE_RE.fullmatch(unit)
    if match:
        index, count = int(match.group(2)), int(match.group(3))
        if count < 2 or index >= count:
            raise _full_shard_plan_error(f"slice unit index out of range: {unit}")
        return "slice", match.group(1), (index, count)
    if TEST_ID_RE.fullmatch(unit):
        return "module", unit, None
    raise _full_shard_plan_error(f"unsupported unit: {unit}")


def validate_full_shard_plan(plan: object) -> None:
    """Structural plan contract, independent of the current canonical discovery."""
    if not isinstance(plan, dict):
        raise _full_shard_plan_error("root must be an object")
    keys = set(plan)
    unknown = keys - FULL_SHARD_PLAN_KEYS - FULL_SHARD_PLAN_OPTIONAL_KEYS
    if unknown or not FULL_SHARD_PLAN_KEYS <= keys:
        raise _full_shard_plan_error(
            "unknown keys: " + ", ".join(sorted(unknown))
            + "; missing keys: " + ", ".join(sorted(FULL_SHARD_PLAN_KEYS - keys))
        )
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise _full_shard_plan_error("schema_version must be 1")
    if not isinstance(plan["description"], str) or not plan["description"].strip():
        raise _full_shard_plan_error("description must be non-empty")
    if not isinstance(plan["derivation"], dict):
        raise _full_shard_plan_error("derivation must be an object")
    deadline = plan["lane_deadline_seconds"]
    if type(deadline) is not int or deadline < FULL_SHARD_MIN_LANE_DEADLINE_SECONDS:
        raise _full_shard_plan_error(
            "lane_deadline_seconds must be an integer >= "
            f"{FULL_SHARD_MIN_LANE_DEADLINE_SECONDS} (a hang guard, never a test time limit)"
        )
    phase_a = plan["phase_a"]
    if not isinstance(phase_a, list) or not phase_a:
        raise _full_shard_plan_error("phase_a must be a non-empty list of lane objects")
    phase_b = plan["phase_b"]
    if not isinstance(phase_b, dict):
        raise _full_shard_plan_error(
            "phase_b must be exactly one lane object (quiet phase concurrency is 1)"
        )
    names: list[str] = []
    whole: dict[str, str] = {}
    sliced: dict[str, dict[int, tuple[int, str]]] = {}
    cases: set[str] = set()
    for lane in [*phase_a, phase_b]:
        if not isinstance(lane, dict) or set(lane) != {"lane", "units"}:
            raise _full_shard_plan_error("every lane object has exactly 'lane' and 'units'")
        name = lane["lane"]
        if not isinstance(name, str) or not FULL_SHARD_LANE_RE.fullmatch(name):
            raise _full_shard_plan_error(f"invalid lane name: {name!r}")
        names.append(name)
        units = lane["units"]
        if not isinstance(units, list) or not units:
            raise _full_shard_plan_error(f"lane {name} needs a non-empty unit list")
        for unit in units:
            kind, module, extra = _parse_full_shard_unit(unit)
            if kind == "module":
                if module in whole:
                    raise _full_shard_plan_error(f"module named more than once: {module}")
                whole[module] = name
            elif kind == "slice":
                index, count = extra
                bucket = sliced.setdefault(module, {})
                if index in bucket:
                    raise _full_shard_plan_error(f"slice named more than once: {unit}")
                bucket[index] = (count, name)
            else:
                if unit in cases:
                    raise _full_shard_plan_error(f"case unit named more than once: {unit}")
                cases.add(unit)
    if len(names) != len(set(names)):
        raise _full_shard_plan_error("lane names must be unique")
    both = sorted(set(whole) & set(sliced))
    if both:
        raise _full_shard_plan_error("module is both whole and sliced: " + ", ".join(both))
    slices = plan["slices"]
    if not isinstance(slices, dict) or set(slices) != set(sliced):
        raise _full_shard_plan_error("slices must name exactly the sliced modules")
    for module, boundaries in slices.items():
        if (
            not isinstance(boundaries, list) or not boundaries
            or len(boundaries) != len(set(boundaries))
            or not all(isinstance(value, str) and value.startswith(module + ".") for value in boundaries)
        ):
            raise _full_shard_plan_error(f"slices.{module} must list distinct case ids of that module")
        count = len(boundaries) + 1
        present = sliced[module]
        if set(present) != set(range(count)) or {value[0] for value in present.values()} != {count}:
            raise _full_shard_plan_error(
                f"slices.{module} declares {count} slices but the lanes name "
                + ", ".join(f"#{index}/{value[0]}" for index, value in sorted(present.items()))
            )
    same_lane = plan["same_lane"]
    if not isinstance(same_lane, list):
        raise _full_shard_plan_error("same_lane must be a list of module groups")
    for group in same_lane:
        if (
            not isinstance(group, list) or len(group) < 2 or len(group) != len(set(group))
            or not all(isinstance(value, str) and TEST_ID_RE.fullmatch(value) for value in group)
        ):
            raise _full_shard_plan_error("each same_lane group lists at least two distinct modules")
    reasons = plan["phase_b_reasons"]
    if not isinstance(reasons, dict) or set(reasons) != set(phase_b["units"]):
        raise _full_shard_plan_error("phase_b_reasons must give exactly one reason per phase_b unit")
    if not all(isinstance(value, str) and value.strip() for value in reasons.values()):
        raise _full_shard_plan_error("phase_b_reasons must be non-empty strings")
    runtime_skips = plan.get("runtime_skips", {})
    if not isinstance(runtime_skips, dict):
        raise _full_shard_plan_error(
            "runtime_skips must map serial skip entry ids to their exact skip reasons"
        )
    for entry, reason in runtime_skips.items():
        if not isinstance(entry, str) or not (
            FULL_SHARD_SKIP_ENTRY_RE.fullmatch(entry) or FULL_SHARD_HOLDER_RE.fullmatch(entry)
        ):
            raise _full_shard_plan_error(
                f"runtime_skips entry {entry!r} is neither a test id nor a "
                "setUpClass/setUpModule holder"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise _full_shard_plan_error(f"runtime_skips reason of {entry} must be a non-empty string")
    allowlist = plan.get("leftover_allowlist", {})
    if not isinstance(allowlist, dict):
        raise _full_shard_plan_error(
            "leftover_allowlist must map reviewed checkout path patterns to their reasons"
        )
    for pattern, reason in allowlist.items():
        if (
            not isinstance(pattern, str) or not pattern or "\0" in pattern or "\\" in pattern
            or pattern.startswith("/") or any(part in ("", ".", "..") for part in pattern.split("/"))
            or any(character in pattern.split("/", 1)[0] for character in "*?[")
        ):
            raise _full_shard_plan_error(
                f"leftover_allowlist pattern {pattern!r} must be a relative POSIX pattern "
                "with a literal first component and no empty, '.' or '..' components"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise _full_shard_plan_error(f"leftover_allowlist reason of {pattern} must be a non-empty string")


def load_full_shard_plan(root: Path) -> dict:
    plan = read_json_regular(Path(root) / FULL_SHARD_PLAN_RELATIVE)
    validate_full_shard_plan(plan)
    return plan


def apply_full_shard_plan(plan: Mapping, rows: Sequence[Mapping]) -> dict:
    """Assign every canonical row index to exactly one lane, or fail closed."""
    validate_full_shard_plan(plan)
    untagged = [str(row.get("id")) for row in rows if not row.get("module")]
    if untagged:
        raise ImpactError(
            "full shard plan cannot apply: canonical discovery has untagged rows "
            "(import failures run only in serial --all): " + ", ".join(untagged[:10])
        )
    borrowed = [row["id"] for row in rows if row["class_module"] != row["module"]]
    if borrowed:
        raise ImpactError(
            "full shard plan cannot apply: a test class is collected outside its defining "
            "module (G1 single-collection invariant): " + ", ".join(borrowed[:10])
        )
    module_rows: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        module_rows.setdefault(row["module"], []).append(index)
    lane_objects = [*plan["phase_a"], plan["phase_b"]]
    whole: dict[str, str] = {}
    slice_lanes: dict[str, dict[int, str]] = {}
    case_units: list[tuple[str, str, str, str]] = []
    for lane in lane_objects:
        for unit in lane["units"]:
            kind, module, extra = _parse_full_shard_unit(unit)
            if kind == "module":
                whole[module] = lane["lane"]
            elif kind == "slice":
                slice_lanes.setdefault(module, {})[extra[0]] = lane["lane"]
            else:
                case_units.append((unit, module, extra, lane["lane"]))
    named = set(whole) | set(slice_lanes) | {module for _unit, module, _case, _lane in case_units}
    for group in plan["same_lane"]:
        named.update(group)
    stale = sorted(module for module in named if module not in module_rows)
    if stale:
        raise ImpactError(
            "full shard plan is stale: it names modules canonical discovery does not collect: "
            + ", ".join(stale)
        )
    unassigned = [module for module in module_rows if module not in whole and module not in slice_lanes]
    if unassigned:
        raise ImpactError(
            "full shard plan is stale: unassigned canonical modules: " + ", ".join(unassigned)
        )
    lane_of: dict[int, str] = {}
    for unit, module, case_id, lane in case_units:
        matches = [index for index in module_rows[module] if rows[index]["id"] == case_id]
        if len(matches) != 1:
            raise ImpactError(
                f"full shard plan is stale: case unit {unit} matches {len(matches)} canonical rows"
            )
        lane_of[matches[0]] = lane
    claimed = set(lane_of)
    for module, lane in whole.items():
        for index in module_rows[module]:
            if index not in claimed:
                lane_of[index] = lane
    for module, lanes in slice_lanes.items():
        indices = module_rows[module]
        ids = [rows[index]["id"] for index in indices]
        positions = []
        for boundary in plan["slices"][module]:
            found = [position for position, value in enumerate(ids) if value == boundary]
            if len(found) != 1 or found[0] == 0:
                raise ImpactError(
                    f"full shard plan is stale: slice boundary {boundary} is not a unique "
                    f"non-first case of {module}"
                )
            positions.append(found[0])
        if positions != sorted(set(positions)):
            raise ImpactError(
                f"full shard plan is stale: slice boundary order of {module} is not canonical"
            )
        edges = [0, *positions, len(indices)]
        for slice_index, (low, high) in enumerate(zip(edges, edges[1:])):
            for index in indices[low:high]:
                if index not in claimed:
                    lane_of[index] = lanes[slice_index]
    for group in plan["same_lane"]:
        group_lanes = {whole.get(module) for module in group}
        if None in group_lanes or len(group_lanes) != 1:
            raise ImpactError(
                "full shard plan violates same_lane: " + ", ".join(group)
                + " must be whole modules in one lane"
            )
    lanes_by_module: dict[str, set[str]] = {}
    lanes_by_class: dict[tuple[str, str], set[str]] = {}
    for index, row in enumerate(rows):
        lanes_by_module.setdefault(row["module"], set()).add(lane_of[index])
        lanes_by_class.setdefault((row["class_module"], row["class"]), set()).add(lane_of[index])
    for module, used in lanes_by_module.items():
        if len(used) > 1 and any(rows[index]["module_fixture"] for index in module_rows[module]):
            raise ImpactError(
                f"full shard plan splits {module} across processes but it defines a "
                "setUpModule/tearDownModule fixture"
            )
    for (class_module, class_name), used in lanes_by_class.items():
        if len(used) > 1 and any(
            row["class_fixture"] for row in rows
            if (row["class_module"], row["class"]) == (class_module, class_name)
        ):
            raise ImpactError(
                f"full shard plan splits {class_module}.{class_name} across processes but it "
                "defines a setUpClass/tearDownClass fixture"
            )
    lanes: dict[str, list[int]] = {lane["lane"]: [] for lane in lane_objects}
    for index in range(len(rows)):
        lanes[lane_of[index]].append(index)
    empty = [name for name, indices in lanes.items() if not indices]
    if empty:
        raise ImpactError("full shard plan is stale: lanes without canonical rows: " + ", ".join(empty))
    return {
        "lanes": lanes,
        "phase_a": [lane["lane"] for lane in plan["phase_a"]],
        "phase_b": plan["phase_b"]["lane"],
    }


def merge_full_shard_lane(
    lane: str, rows: Sequence[Mapping], assigned: Sequence[int],
    records: Sequence[Mapping] | None, exit_info: Mapping,
    *, identity: Mapping, canonical_sha256: str,
) -> dict:
    """Check one lane's records against its assignment; never trust the lane's own verdict.

    Every problem is listed in "problems".  "gate_problems" is the subset that is not a
    plain test outcome: anything about coverage, records, identity, crash, deadline or
    an exit status that the lane's own records do not explain.  A lane whose only
    problems are test outcomes (non-success results and class/module fixture errors,
    with a consistent finished record and exit 1) reports no gate problem; serial
    unittest records the same outcomes and keeps running.
    """
    problems: list[str] = []
    gate_problems: list[str] = []

    def problem(message: str, *, gate: bool = True) -> None:
        problems.append(message)
        if gate:
            gate_problems.append(message)

    assigned_set = set(assigned)
    executed: list[int] = []
    seen: set[int] = set()
    non_success: list[dict] = []
    holders: list[Mapping] = []
    skips: list[dict] = []
    finished = None
    if records is None:
        problem(f"lane {lane}: missing result file")
        records = []
    starts = [record for record in records if record.get("event") == "start"]
    if len(starts) != 1:
        problem(f"lane {lane}: expected exactly one start record, found {len(starts)}")
    else:
        reported = {key: starts[0].get(key) for key in identity}
        if reported != dict(identity):
            problem(f"lane {lane}: interpreter identity differs from the coordinator: {reported}")
        if (
            starts[0].get("canonical_sha256") != canonical_sha256
            or starts[0].get("count") != len(rows)
        ):
            problem(f"lane {lane}: canonical discovery differs from the coordinator's enumeration")
    for record in records:
        event = record.get("event")
        if event == "test":
            index = record.get("index")
            if type(index) is not int or not 0 <= index < len(rows):
                problem(f"lane {lane}: reported an unknown canonical index {index!r}")
                continue
            if record.get("id") != rows[index]["id"]:
                problem(
                    f"lane {lane}: index {index} reported id {record.get('id')!r} but the canonical "
                    f"id is {rows[index]['id']!r}"
                )
            if index not in assigned_set:
                problem(f"lane {lane}: executed {rows[index]['id']} outside its assigned lane")
            if index in seen:
                problem(f"lane {lane}: {rows[index]['id']} executed more than once")
            seen.add(index)
            executed.append(index)
            if record.get("outcome") not in FULL_SHARD_ACCEPTED_OUTCOMES:
                non_success.append({"id": rows[index]["id"], "outcome": record.get("outcome"), "lane": lane})
        elif event == "skip":
            index = record.get("index")
            entry_id = str(record.get("id"))
            if type(index) is not int or index not in assigned_set:
                problem(
                    f"lane {lane}: skip entry {record.get('id')!r} is outside its assigned rows"
                )
                continue
            # The running test's id, or a sub-test id "<test id> <params>" of it.
            if entry_id != rows[index]["id"] and not entry_id.startswith(rows[index]["id"] + " "):
                problem(
                    f"lane {lane}: skip entry {entry_id!r} does not belong to canonical row "
                    f"{rows[index]['id']!r}"
                )
                continue
            skips.append({"id": entry_id, "reason": record.get("reason")})
        elif event == "holder":
            holders.append(record)
        elif event == "fatal":
            problem(f"lane {lane}: fatal: {record.get('reason')}")
        elif event == "finished":
            finished = record
        elif event != "start":
            problem(f"lane {lane}: unknown or corrupt record {event!r}")
    suppressed: set[int] = set()
    errored: set[int] = set()
    holder_errors = 0
    for holder in holders:
        description = str(holder.get("description", ""))
        if holder.get("kind") == "error":
            # A test outcome: serial unittest records the same error and, after a failed
            # setUpClass/setUpModule, does not run that class's or module's tests either.
            holder_errors += 1
            problem(f"lane {lane}: class/module fixture error: {description}", gate=False)
            match = FULL_SHARD_HOLDER_RE.fullmatch(description)
            if match is not None:
                kind, target = match.groups()
                for index in assigned:
                    row = rows[index]
                    owner = f"{row['class_module']}.{row['class']}" if kind == "setUpClass" else row["module"]
                    if owner == target and index not in seen:
                        errored.add(index)
            continue
        match = FULL_SHARD_HOLDER_RE.fullmatch(description)
        if holder.get("kind") != "skip" or match is None:
            problem(f"lane {lane}: unrecognised holder record: {description!r}")
            continue
        kind, target = match.groups()
        skips.append({"id": description, "reason": holder.get("reason")})
        for index in assigned:
            row = rows[index]
            owner = f"{row['class_module']}.{row['class']}" if kind == "setUpClass" else row["module"]
            if owner == target and index not in seen:
                suppressed.add(index)
    missing = sorted(assigned_set - seen - suppressed)
    if missing:
        problem(
            f"lane {lane}: {len(missing)} assigned rows were not executed: "
            + ", ".join(rows[index]["id"] for index in missing[:5]),
            gate=not set(missing) <= errored,
        )
    errored &= set(missing)
    tests_run = None
    if finished is None:
        problem(f"lane {lane}: no finished record (crash, kill or early exit)")
    else:
        tests_run = finished.get("tests_run")
        if tests_run != len(executed):
            problem(
                f"lane {lane}: finished record counts {tests_run!r} tests but {len(executed)} were reported"
            )
    if exit_info.get("deadline_exceeded"):
        problem(f"lane {lane}: lane deadline exceeded; its process group was terminated")
    # The lane exits 0 exactly when its TextTestRunner result was successful and 1
    # otherwise; only then do its records explain its exit status.
    failed = bool(non_success) or holder_errors > 0
    consistent = (
        finished is not None and type(finished.get("successful")) is bool
        and finished["successful"] is (not failed)
        and exit_info.get("exit") == (1 if failed else 0)
    )
    if finished is not None and not consistent:
        problem(
            f"lane {lane}: exit {exit_info.get('exit')!r} and finished successful="
            f"{finished.get('successful')!r} disagree with the reported outcomes"
        )
    if exit_info.get("exit") != 0:
        problem(f"lane {lane}: exit {exit_info.get('exit')}", gate=not (consistent and failed))
    if non_success:
        problem(
            f"lane {lane}: {len(non_success)} non-success outcomes: "
            + ", ".join(f"{item['id']} ({item['outcome']})" for item in non_success[:5]),
            gate=False,
        )
    return {
        "problems": problems, "gate_problems": gate_problems, "executed": sorted(executed),
        "suppressed": sorted(suppressed), "errored": sorted(errored),
        "non_success": non_success, "tests_run": tests_run, "skips": skips,
    }


def full_shard_coverage_problems(count: int, merged: Mapping[str, Mapping]) -> list[str]:
    """Every canonical row executed or recognisably suppressed exactly once, nothing else.

    Rows that a recognised setUpClass/setUpModule error holder kept from running
    ("errored") are accounted for by that error, as in serial unittest; such a run has
    already failed on the error itself and never issues a proof.
    """
    problems: list[str] = []
    owner: dict[int, str] = {}
    for lane, result in merged.items():
        for index in [*result["executed"], *result["suppressed"], *result.get("errored", ())]:
            if type(index) is not int or not 0 <= index < count:
                problems.append(f"lane {lane}: index {index!r} is outside canonical discovery")
            elif index in owner:
                problems.append(f"canonical row {index} is accounted for by {owner[index]} and {lane}")
            else:
                owner[index] = lane
    missing = sorted(set(range(count)) - set(owner))
    if missing:
        problems.append(
            f"{len(missing)} canonical rows were neither executed nor suppressed by a recognised holder"
        )
    return problems


def full_shard_runtime_skip_problems(runtime_skips: Mapping[str, str], rows: Sequence[Mapping]) -> list[str]:
    """Every plan runtime_skips entry must still name a canonical test, class or module."""
    ids = {row["id"] for row in rows}
    classes = {f"{row['class_module']}.{row['class']}" for row in rows}
    modules = {row["module"] for row in rows}
    problems = []
    for entry in sorted(runtime_skips):
        match = FULL_SHARD_HOLDER_RE.fullmatch(entry)
        if match:
            kind, target = match.groups()
            known = target in (classes if kind == "setUpClass" else modules)
        else:
            known = entry.split(" ", 1)[0] in ids
        if not known:
            problems.append(
                f"full shard plan is stale: runtime_skips entry {entry} names no canonical "
                "test, class or module"
            )
    return problems


def full_shard_skip_problems(
    rows: Sequence[Mapping], decorator_skips: Sequence[Mapping],
    runtime_skips: Mapping[str, str], merged: Mapping[str, Mapping],
) -> list[str]:
    """The lanes' skip entries must be the skips the serial run would make.

    Decorator skips are facts of the canonical enumeration, which imports every
    module in the coordinator's environment; each must be reported by its lane
    with the same reason (unless a class/module holder skipped its whole fixture,
    as in serial unittest).  Every other skip entry arises only at run time and
    must be a plan runtime_skips entry with the exact reason.
    """
    problems: list[str] = []
    observed: dict[str, dict] = {}
    for lane, result in merged.items():
        for entry in result["skips"]:
            entry_id = entry["id"]
            if entry_id in observed:
                problems.append(
                    f"skip entry {entry_id} is reported more than once "
                    f"({observed[entry_id]['lane']} and {lane})"
                )
                continue
            observed[entry_id] = {"reason": entry["reason"], "lane": lane}
    suppressed = {index for result in merged.values() for index in result["suppressed"]}
    decorated: dict[str, str] = {}
    for item in decorator_skips:
        index = item["index"]
        decorated[rows[index]["id"]] = item["reason"]
        if index in suppressed:
            continue
        entry = observed.get(rows[index]["id"])
        if entry is None:
            problems.append(
                f"{rows[index]['id']} is skipped by a decorator at canonical enumeration but was "
                "not skipped in its lane"
            )
        elif entry["reason"] != item["reason"]:
            problems.append(
                f"{rows[index]['id']}: skip reason {entry['reason']!r} in lane {entry['lane']} differs "
                f"from the canonical enumeration's {item['reason']!r}"
            )
    for entry_id, entry in sorted(observed.items()):
        if entry_id in decorated:
            continue
        allowed = runtime_skips.get(entry_id)
        if allowed is None:
            problems.append(
                f"unexpected skip {entry_id} in lane {entry['lane']} ({entry['reason']!r}): neither a "
                "decorator skip of the canonical enumeration nor a plan runtime_skips entry"
            )
        elif entry["reason"] != allowed:
            problems.append(
                f"{entry_id}: skip reason {entry['reason']!r} in lane {entry['lane']} differs from "
                f"the plan runtime_skips reason {allowed!r}"
            )
    return problems


def _full_shard_kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=FULL_SHARD_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    process.wait()


def _full_shard_wait_lanes(
    launched: Mapping[str, tuple], deadline_seconds: float, *, poll: float = 1.0,
) -> dict:
    """Wait for (process, log, started_monotonic, started_epoch) lanes; a hang guard per lane."""
    finished: dict[str, dict] = {}
    try:
        while len(finished) < len(launched):
            for lane, (process, log, started, started_epoch) in launched.items():
                if lane in finished:
                    continue
                code = process.poll()
                exceeded = False
                if code is None and time.monotonic() - started >= deadline_seconds:
                    exceeded = True
                    _full_shard_kill_group(process)
                    code = process.returncode
                if code is None:
                    continue
                wall = round(time.monotonic() - started, 3)
                finished[lane] = {
                    "exit": code, "seconds": wall, "wall_seconds": wall,
                    "started_epoch": started_epoch, "ended_epoch": round(time.time(), 3),
                    "deadline_exceeded": exceeded,
                }
                log.close()
            if len(finished) < len(launched):
                time.sleep(poll)
    except BaseException:
        for lane, (process, log, _started, _epoch) in launched.items():
            if lane not in finished:
                _full_shard_kill_group(process)
                log.close()
        raise
    return finished


def _full_shard_gid_problems(paths: Iterable[Path]) -> list[str]:
    expected = os.getgid()
    problems = []
    for path in paths:
        try:
            info = os.stat(path)
        except OSError as exc:
            problems.append(f"{path}: cannot stat for the gid gate ({exc})")
            continue
        if info.st_gid != expected:
            problems.append(f"{path}: gid {info.st_gid} differs from the user's primary gid {expected}")
    return problems


def _full_shard_remove_tree(path: Path) -> str | None:
    """Remove one lane tree; return a problem instead of raising."""
    path = Path(path)

    def retry(function, target, error):
        # onexc passes the exception, onerror an exc_info triple.  Only a removal
        # (unlink/rmdir) is retried after making its directory writable; any other
        # failing step (os.open, os.scandir, os.lstat, ...) raises its original error.
        original = error[1] if isinstance(error, tuple) else error
        if function not in (os.unlink, os.rmdir, os.remove):
            raise original
        try:
            os.chmod(os.path.dirname(target) or ".", stat.S_IRWXU)
            if not os.path.islink(target):
                os.chmod(target, stat.S_IRWXU)
        except OSError:
            pass
        function(target)

    try:
        if not os.path.lexists(path):
            return None
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=retry)
        else:
            shutil.rmtree(path, onerror=retry)
    except OSError as exc:
        return f"cleanup of {path} failed: {exc}"
    if os.path.lexists(path):
        return f"cleanup of {path} left the path in place"
    return None


def _full_shard_environment() -> dict[str, str]:
    """The coordinator's environment without GIT_* (a hook's GIT_DIR, GIT_INDEX_FILE,
    GIT_WORK_TREE ... would bind `git -C <clone>` and lane tests to another repository).

    Only the config-source selectors are kept: they name no repository, index or work
    tree, and hermetic callers use them to keep user-global excludes or fsmonitor
    settings out of the leftover and checkout gates.
    """
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith("GIT_") or key in FULL_SHARD_GIT_CONFIG_SELECTORS
    }


def _full_shard_git(checkout: Path, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(checkout), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env=_full_shard_environment(),
    )


def _full_shard_paths(completed: subprocess.CompletedProcess, label: str) -> list[str]:
    if completed.returncode != 0:
        raise ImpactError(f"git {label} failed: {completed.stderr.decode('utf-8', 'replace').strip()}")
    return [os.fsdecode(raw) for raw in completed.stdout.split(b"\0") if raw]


def _full_shard_tracked_digest(checkout: Path) -> dict[str, str]:
    digests: dict[str, str] = {}
    for relative in _full_shard_paths(_full_shard_git(checkout, "ls-files", "-z"), "ls-files"):
        path = Path(checkout) / relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            digests[relative] = "missing"
            continue
        if stat.S_ISLNK(info.st_mode):
            digests[relative] = "link:" + os.readlink(path)
        elif stat.S_ISREG(info.st_mode):
            digests[relative] = ("x:" if info.st_mode & 0o111 else "-:") + sha256_file(path)
        else:
            digests[relative] = "other"
    return digests


def _full_shard_untracked(checkout: Path) -> list[str]:
    return _full_shard_paths(
        _full_shard_git(checkout, "ls-files", "-z", "--others", "--exclude-standard"),
        "ls-files --others",
    )


def _full_shard_ignored(checkout: Path) -> set[str]:
    """Ignored untracked files, minus interpreter bytecode caches (__pycache__/*.pyc)."""
    paths = _full_shard_paths(
        _full_shard_git(checkout, "ls-files", "-z", "--others", "--ignored", "--exclude-standard"),
        "ls-files --ignored",
    )
    return {
        path for path in paths
        if not ("__pycache__" in path.split("/") and path.endswith(".pyc"))
    }


def _full_shard_refs(checkout: Path) -> str:
    head = _full_shard_git(checkout, "rev-parse", "--verify", "HEAD")
    refs = _full_shard_git(checkout, "for-each-ref", "--format=%(objectname) %(refname)")
    if head.returncode or refs.returncode:
        raise ImpactError(f"cannot read HEAD/refs of {checkout}")
    return head.stdout.decode("utf-8", "replace") + refs.stdout.decode("utf-8", "replace")


def _full_shard_clone(source: Path, destination: Path) -> None:
    completed = subprocess.run(
        ["/bin/cp", "-c", "-R", str(source), str(destination)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if completed.returncode != 0:
        raise ImpactError(
            "clonefile copy of the checkout failed: "
            + completed.stderr.decode("utf-8", "replace").strip()
        )


def _full_shard_clone_gate(main_refs: str, clone: Path) -> list[str]:
    """A lane checkout must be an exact, clean, plain copy of the committed main checkout."""
    problems = []
    _full_shard_git(clone, "update-index", "-q", "--refresh")
    if _full_shard_git(clone, "diff-index", "--quiet", "HEAD", "--").returncode != 0:
        problems.append("index differs from HEAD (the main checkout is not a clean committed tree)")
    if _full_shard_git(clone, "diff-files", "--quiet").returncode != 0:
        problems.append("worktree differs from index (uncommitted change in the main checkout)")
    try:
        if _full_shard_untracked(clone):
            problems.append("untracked non-ignored files are present in the main checkout")
    except ImpactError as exc:
        problems.append(str(exc))
    gitdir = clone / ".git"
    if not gitdir.is_dir() or gitdir.is_symlink():
        problems.append(".git is not a real directory")
    for relative in FULL_SHARD_GIT_FORBIDDEN:
        if os.path.lexists(gitdir / relative):
            problems.append(f".git/{relative} is present")
    try:
        if _full_shard_refs(clone) != main_refs:
            problems.append("HEAD or refs differ from the main checkout")
    except ImpactError as exc:
        problems.append(str(exc))
    return [f"{clone.name} checkout gate: {problem}" for problem in problems]


def _full_shard_markers(paths: Iterable[Path]) -> list[str]:
    markers: list[str] = []
    for path in paths:
        for value in {os.fspath(path), os.path.realpath(path)}:
            markers.append(value.rstrip("/"))
    return sorted(set(markers))


def _full_shard_names_marker(text: str, markers: Sequence[str]) -> bool:
    return any(
        re.search(re.escape(marker) + r"(?:/|\s|$)", text) for marker in markers
    )


def _full_shard_residue(markers: Sequence[str], pgids: Iterable[int]) -> list[dict]:
    """Processes still tied to lane paths or lane process groups (three calibers)."""
    me = os.getpid()
    groups = set(pgids)
    found: dict[int, dict] = {}
    listing = subprocess.run(
        [FULL_SHARD_PS, "-axww", "-o", "pid=,pgid=,command="], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, timeout=120,
    )
    if listing.returncode != 0:
        raise ImpactError("residue gate cannot list processes")
    for line in listing.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        pid, pgid = int(parts[0]), int(parts[1])
        command = parts[2] if len(parts) > 2 else ""
        if pid == me:
            continue
        reasons = []
        if pgid in groups:
            reasons.append("lane process group")
        if _full_shard_names_marker(command, markers):
            reasons.append("argv names a lane path")
        if reasons:
            found[pid] = {"pid": pid, "pgid": pgid, "command": command[:200], "reasons": reasons}
    cwd = subprocess.run(
        [FULL_SHARD_LSOF, "-nP", "-w", "-a", "-d", "cwd", "-u", str(os.getuid()), "-Fpn"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False, timeout=120,
    )
    if cwd.returncode not in (0, 1) or f"p{me}" not in cwd.stdout.splitlines():
        raise ImpactError("residue gate cannot read process working directories (lsof)")
    current = None
    for line in cwd.stdout.splitlines():
        if line.startswith("p"):
            current = int(line[1:]) if line[1:].isdigit() else None
        elif line.startswith("n") and current is not None and current != me:
            if _full_shard_names_marker(line[1:], markers):
                entry = found.setdefault(current, {
                    "pid": current, "pgid": None, "command": "", "reasons": [],
                })
                entry["reasons"].append("working directory inside a lane path")
    return sorted(found.values(), key=lambda item: item["pid"])


def _full_shard_residue_gate(markers: Sequence[str], pgids: Iterable[int]) -> tuple[list[dict], float]:
    """Wait a bounded grace for stragglers (never signalling), then terminate what remains."""
    started = time.monotonic()
    groups = list(pgids)
    while True:
        residue = _full_shard_residue(markers, groups)
        waited = time.monotonic() - started
        if not residue or waited >= FULL_SHARD_RESIDUE_GRACE_SECONDS:
            break
        time.sleep(2.0)
    if residue:
        for item in residue:
            try:
                os.kill(item["pid"], signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        deadline = time.monotonic() + 5.0
        remaining = [item["pid"] for item in residue]
        while remaining and time.monotonic() < deadline:
            alive = []
            for pid in remaining:
                try:
                    os.kill(pid, 0)
                    alive.append(pid)
                except (ProcessLookupError, PermissionError):
                    pass
            remaining = alive
            if remaining:
                time.sleep(0.2)
        for pid in remaining:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    return residue, round(time.monotonic() - started, 1)


def _full_shard_read_records(path: Path) -> list[dict] | None:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    records: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            value = None
        records.append(value if isinstance(value, dict) else {"event": "corrupt"})
    return records


def _full_shard_write_json(path: Path, value: object) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        # ASCII: problem text carries os.fsdecode() paths whose undecodable bytes are
        # lone surrogates, which a UTF-8 writer cannot encode.
        json.dump(value, handle, ensure_ascii=True, indent=1, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


class _FullShardLane:
    """One lane: clone, private TMPDIR/pyc namespace, spec, log and result paths."""

    def __init__(self, name: str, phase: str, work: Path, lanes_dir: Path, temp_parent: Path):
        self.name = name
        self.phase = phase
        self.clone = work / name
        self.spec = lanes_dir / f"{name}.spec.json"
        self.result = lanes_dir / f"{name}.jsonl"
        self.log = lanes_dir / f"{name}.log"
        self.temp_parent = temp_parent
        self.tmpdir: Path | None = None
        self.pycache: Path | None = None
        self.ignored_before: set[str] = set()

    def prepare(self, root: Path, main_refs: str) -> list[str]:
        _full_shard_clone(root, self.clone)
        problems = _full_shard_clone_gate(main_refs, self.clone)
        self.tmpdir = Path(tempfile.mkdtemp(prefix=f"hs{self.name}-", dir=self.temp_parent))
        self.pycache = Path(tempfile.mkdtemp(prefix=f"hp{self.name}-", dir=self.temp_parent))
        problems += _full_shard_gid_problems([self.clone, self.tmpdir, self.pycache])
        self.ignored_before = _full_shard_ignored(self.clone)
        return problems

    def launch(self, mode: str, spec: Mapping, *, private_tmpdir: bool = True) -> tuple:
        """Start the lane.  The canonical enumeration passes private_tmpdir=False and
        keeps the coordinator's TMPDIR, as the serial run does, so that its decorator
        skip facts are evaluated in the serial environment, not in a lane's."""
        _full_shard_write_json(self.spec, spec)
        environment = _full_shard_environment()
        if private_tmpdir:
            environment["TMPDIR"] = str(self.tmpdir)
        environment["PYTHONPYCACHEPREFIX"] = str(self.pycache)
        log = open(self.log, "xb")
        try:
            process = subprocess.Popen(
                [sys.executable, "-B", "-c", FULL_SHARD_LANE_SOURCE, mode,
                 str(self.spec), str(self.result)],
                cwd=self.clone, env=environment, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
        except BaseException:
            log.close()
            raise
        return process, log, time.monotonic(), round(time.time(), 3)

    def leftover_gate(
        self, main_digest: Mapping[str, str], main_snapshot: Mapping | None = None,
        snapshot_of: Callable[[Path], Mapping] | None = None,
        allowlist: Mapping[str, str] | None = None,
    ) -> tuple[list[str], list[str], dict]:
        """(gate problems, proof-only problems, leftover inventory) of one finished lane.

        Gate (isolation; skips phase B), as serial --all would refuse or a lane must
        never do: changed tracked bytes, untracked non-ignored files, and a lane checkout
        that fails the serial post-run check (_one_cycle re-validates the manifest and
        re-reads the snapshot after the run and refuses approval on any difference; both
        can see ignored files, e.g. on production paths).

        Proof-only (refuses the proof, phase B still runs): a change of the checkout's
        ignored files (new or removed) that no plan leftover_allowlist pattern reviews.
        Serial --all never checks ignored files, but every later serial test sees them,
        while another lane does not; only shapes reviewed as unobservable by other
        tests keep the shard equivalent.

        Audited only: the full lists of new and removed ignored files and the lane
        TMPDIR entries (serial leaves its TMPDIR unchecked; no test lists a temporary
        root).  All of it is private to this lane and removed with it at cleanup.
        """
        gate: list[str] = []
        proof_only: list[str] = []
        ignored: list[str] = []
        removed: list[str] = []
        try:
            digest = _full_shard_tracked_digest(self.clone)
            changed = sorted(path for path in set(digest) | set(main_digest)
                             if digest.get(path) != main_digest.get(path))
            if changed:
                gate.append(
                    f"lane {self.name}: tracked bytes changed in the lane checkout: "
                    + ", ".join(changed[:10])
                )
            untracked = _full_shard_untracked(self.clone)
            if untracked:
                gate.append(f"lane {self.name}: untracked leftovers in the lane checkout: "
                            + ", ".join(untracked[:10]))
            current = _full_shard_ignored(self.clone)
            ignored = sorted(current - self.ignored_before)
            removed = sorted(self.ignored_before - current)
        except Exception as exc:
            gate.append(f"lane {self.name}: leftover gate failed: {exc}")
        # Only a checkout whose tracked bytes are intact is re-validated: the post-run
        # validation executes the checkout's deployment selectors in this process.
        if snapshot_of is not None and not gate:
            try:
                after = snapshot_of(self.clone)
            except Exception as exc:
                gate.append(
                    f"lane {self.name}: the serial source/test snapshot of the lane checkout "
                    f"fails the serial post-run validation: {exc}"
                )
            else:
                changes = _full_shard_snapshot_changes(main_snapshot or {}, after)
                if changes:
                    gate.append(
                        f"lane {self.name}: the serial source/test snapshot of the lane checkout "
                        "changed (serial --all would refuse approval): " + ", ".join(changes[:10])
                    )
        unreviewed = full_shard_unreviewed_leftovers([*ignored, *removed], allowlist or {})
        if unreviewed:
            proof_only.append(
                f"lane {self.name}: ignored files of the lane checkout changed outside the plan's "
                "leftover_allowlist (every later serial test would see the change, other lanes "
                "do not): " + ", ".join(unreviewed[:10])
            )
        try:
            tmpdir = full_shard_inventory(os.listdir(self.tmpdir))
        except OSError as exc:
            tmpdir = dict(full_shard_inventory([]), error=f"{type(exc).__name__}: {exc}")
        return gate, proof_only, {
            "ignored": full_shard_inventory(ignored), "ignored_removed": full_shard_inventory(removed),
            "unreviewed": full_shard_inventory(unreviewed), "tmpdir": tmpdir,
        }

    def record(self) -> dict:
        return {
            "phase": self.phase, "clone": str(self.clone), "tmpdir": str(self.tmpdir),
            "pycache": str(self.pycache), "log": str(self.log), "result": str(self.result),
        }


def _full_shard_record_epoch(records: Sequence[Mapping] | None, event: str) -> float | None:
    """The lane's own clock reading in its first record of this event, if any."""
    for record in records or ():
        if record.get("event") == event:
            value = record.get("epoch")
            return value if type(value) in (int, float) else None
    return None


def _full_shard_run_phase(
    lanes: Sequence[_FullShardLane], specs: Mapping[str, Mapping], deadline: int,
    rows: Sequence[Mapping], assignment: Mapping[str, Sequence[int]], canonical_sha256: str,
    main_digest: Mapping[str, str], audit: dict, label: str, *,
    main_snapshot: Mapping | None = None, snapshot_of: Callable[[Path], Mapping] | None = None,
    leftover_allowlist: Mapping[str, str] | None = None,
) -> tuple[dict, list[str]]:
    """Launch lanes together, wait (hang guard), then merge records and run lane gates.

    Returns the merged lane results and this phase's gate problems: every problem the
    runner detects that is not a plain test outcome or an unreviewed ignored-file change
    (coverage, records, crash, deadline, unexplained exit, tracked/untracked/serial-check
    leftovers, residue).  All problems of either kind go to the audit and refuse the proof.
    """
    key = label.lower()
    chains = {"temp_parent": lanes[0].temp_parent, "work": lanes[0].clone.parent}
    chains_before = {name: full_shard_chain(path) for name, path in chains.items()}
    audit[f"phase_{key}_started_epoch"] = round(time.time(), 3)
    started = time.monotonic()
    launched: dict[str, tuple] = {}
    try:
        for lane in lanes:
            launched[lane.name] = lane.launch("run", specs[lane.name])
    except BaseException:
        for process, log, _started, _epoch in launched.values():
            _full_shard_kill_group(process)
            log.close()
        raise
    print(f"sharded full: phase {label} started: " + ", ".join(
        f"{lane.name} ({len(assignment[lane.name])} cases)" for lane in lanes))
    finished = _full_shard_wait_lanes(launched, deadline)
    audit[f"phase_{key}_seconds"] = round(time.monotonic() - started, 1)
    audit[f"phase_{key}_ended_epoch"] = round(time.time(), 3)
    # Attribution only (never a gate): which ancestor of the shared lane roots changed
    # while the lanes ran.  A lane must not write there; the machine may.
    audit["chain_drift"][label] = {
        name: full_shard_chain_drift(chains_before[name], full_shard_chain(path))
        for name, path in chains.items()
    }
    merged = {}
    gate: list[str] = []
    identity = full_shard_lane_identity()
    for lane in lanes:
        info = finished[lane.name]
        records = _full_shard_read_records(lane.result)
        result = merge_full_shard_lane(
            lane.name, rows, assignment[lane.name], records, info,
            identity=identity, canonical_sha256=canonical_sha256,
        )
        merged[lane.name] = result
        entry = audit["lanes"][lane.name]
        entry.update(info)
        entry["lane_tests_started_epoch"] = _full_shard_record_epoch(records, "start")
        entry["lane_finished_epoch"] = _full_shard_record_epoch(records, "finished")
        entry["rows"] = len(assignment[lane.name])
        entry["suppressed"] = len(result["suppressed"])
        entry["suppressed_ids"] = [rows[index]["id"] for index in result["suppressed"]]
        entry["errored_ids"] = [rows[index]["id"] for index in result["errored"]]
        entry["skips"] = result["skips"]
        audit["problems"].extend(result["problems"])
        gate.extend(result["gate_problems"])
        audit["non_gate_problems"].extend(
            problem for problem in result["problems"] if problem not in result["gate_problems"]
        )
        audit["non_success"].extend(result["non_success"])
        gate_started = time.monotonic()
        blocking, proof_only, inventory = lane.leftover_gate(
            main_digest, main_snapshot, snapshot_of, leftover_allowlist,
        )
        entry["leftovers"] = inventory
        entry["gate_seconds"] = round(time.monotonic() - gate_started, 3)
        audit["problems"].extend(blocking)
        gate.extend(blocking)
        audit["problems"].extend(proof_only)
        audit["non_gate_problems"].extend(proof_only)
        print(f"sharded full: lane {lane.name} exit {info['exit']} in {info['seconds']} s")
    markers = _full_shard_markers(
        path for lane in lanes for path in (lane.clone, lane.tmpdir, lane.pycache)
    )
    try:
        residue, waited = _full_shard_residue_gate(
            markers, [launched[lane.name][0].pid for lane in lanes],
        )
    except (ImpactError, OSError, subprocess.SubprocessError) as exc:
        message = f"phase {label}: residue gate failed: {exc}"
        audit["problems"].append(message)
        gate.append(message)
        residue, waited = [], None
    audit[f"phase_{key}_residue_wait_seconds"] = waited
    if residue:
        audit["residue"].extend(residue)
        message = (
            f"phase {label}: {len(residue)} residual processes outlived their lane "
            "(recorded, then terminated)"
        )
        audit["problems"].append(message)
        gate.append(message)
    return merged, gate


def _full_shard_execute(
    root: Path, plan: Mapping, verbose: bool, work: Path, lanes_dir: Path,
    temp_parent: Path, audit: dict, *, manifest_path: Path | None = None,
) -> None:
    shared = full_shard_shared_temp_problems({
        "lane temporary parent (TMPDIR)": temp_parent, "--sharded work directory": work,
    })
    if shared:
        audit["problems"].extend(shared)
        return
    if manifest_path is None:
        manifest_path = root / FULL_SHARD_DEFAULT_MANIFEST_RELATIVE
    manifest_path = Path(manifest_path)

    def snapshot_of(checkout: Path) -> dict:
        return _full_shard_serial_check(checkout, root, manifest_path)

    allowlist = plan.get("leftover_allowlist", {})

    def gate_found() -> bool:
        # Unreviewed ignored-file changes refuse the proof but never stop the run.
        proof_only = set(audit["non_gate_problems"])
        return any(problem not in proof_only for problem in audit["problems"])

    deadline = plan["lane_deadline_seconds"]
    main_refs = _full_shard_refs(root)
    audit["head"] = main_refs.splitlines()[0] if main_refs else None
    main_digest = _full_shard_tracked_digest(root)
    main_snapshot = snapshot_of(root)
    ignored = full_shard_inventory(_full_shard_ignored(root))
    audit["ignored_inventory"] = {"count": ignored["count"], "sha256": ignored["sha256"]}
    enumeration = _FullShardLane("enum", "enumeration", work, lanes_dir, temp_parent)
    audit["enumeration"] = enumeration.record()
    audit["lanes_prepared"] = ["enum"]
    prepared = time.monotonic()
    problems = enumeration.prepare(root, main_refs)
    audit["enumeration"] = enumeration.record()
    audit["enumeration"]["prepare_seconds"] = round(time.monotonic() - prepared, 3)
    if problems:
        audit["problems"].extend(problems)
        return
    # The enumeration only imports; it keeps the coordinator's TMPDIR (as the serial
    # child does) so its decorator skip facts are the serial run's, not a lane's.
    launched = {"enum": enumeration.launch("enumerate", {
        "verbose": False, "canonical_sha256": None, "count": None, "indices": [],
    }, private_tmpdir=False)}
    info = _full_shard_wait_lanes(launched, deadline)["enum"]
    audit["enumeration"].update(info)
    try:
        residue, _waited = _full_shard_residue_gate(
            _full_shard_markers([enumeration.clone, enumeration.tmpdir, enumeration.pycache]),
            [launched["enum"][0].pid],
        )
    except (ImpactError, OSError, subprocess.SubprocessError) as exc:
        audit["problems"].append(f"enumeration: residue gate failed: {exc}")
        residue = []
    if residue:
        audit["residue"].extend(residue)
        audit["problems"].append(
            f"enumeration: {len(residue)} residual processes outlived discovery "
            "(recorded, then terminated)"
        )
    records = _full_shard_read_records(enumeration.result) or []
    starts = [record for record in records if record.get("event") == "start"]
    row_records = [record for record in records if record.get("event") == "rows"]
    gate_started = time.monotonic()
    blocking, proof_only, inventory = enumeration.leftover_gate(
        main_digest, main_snapshot, snapshot_of, allowlist,
    )
    audit["enumeration"]["leftovers"] = inventory
    audit["enumeration"]["gate_seconds"] = round(time.monotonic() - gate_started, 3)
    audit["problems"].extend(blocking)
    audit["problems"].extend(proof_only)
    audit["non_gate_problems"].extend(proof_only)
    if info["exit"] != 0 or len(starts) != 1 or len(row_records) != 1:
        audit["problems"].append(
            f"canonical enumeration failed (exit {info['exit']}); see {enumeration.log}"
        )
        return
    reported = {key: starts[0].get(key) for key in full_shard_lane_identity()}
    if reported != full_shard_lane_identity():
        audit["problems"].append(f"enumeration interpreter identity differs: {reported}")
    if row_records[0].get("module_cleanups"):
        audit["problems"].append("module cleanups were registered during discovery")
    rows = row_records[0]["rows"]
    canonical_sha256 = starts[0]["canonical_sha256"]
    audit["canonical_sha256"] = canonical_sha256
    audit["canonical_count"] = len(rows)
    decorator_skips = row_records[0].get("decorator_skips")
    if not isinstance(decorator_skips, list) or not all(
        isinstance(item, dict) and type(item.get("index")) is int
        and 0 <= item["index"] < len(rows) and isinstance(item.get("reason"), str)
        for item in decorator_skips
    ):
        audit["problems"].append("canonical enumeration did not report valid decorator skip facts")
        return
    audit["decorator_skips"] = [
        {"id": rows[item["index"]]["id"], "reason": item["reason"]} for item in decorator_skips
    ]
    if gate_found():
        return
    runtime_skips = plan.get("runtime_skips", {})
    try:
        applied = apply_full_shard_plan(plan, rows)
    except ImpactError as exc:
        audit["problems"].append(str(exc))
        return
    stale_skips = full_shard_runtime_skip_problems(runtime_skips, rows)
    if stale_skips:
        audit["problems"].extend(stale_skips)
        return
    assignment = applied["lanes"]
    phase_a = [_FullShardLane(name, "A", work, lanes_dir, temp_parent) for name in applied["phase_a"]]
    phase_b = _FullShardLane(applied["phase_b"], "B", work, lanes_dir, temp_parent)
    specs = {}
    for lane in [*phase_a, phase_b]:
        audit["lanes_prepared"].append(lane.name)
        audit["lanes"][lane.name] = lane.record()
        prepared = time.monotonic()
        problems = lane.prepare(root, main_refs)
        audit["lanes"][lane.name] = lane.record()
        audit["lanes"][lane.name]["prepare_seconds"] = round(time.monotonic() - prepared, 3)
        audit["lanes"][lane.name]["rows"] = len(assignment[lane.name])
        audit["problems"].extend(problems)
        specs[lane.name] = {
            "verbose": verbose, "canonical_sha256": canonical_sha256,
            "count": len(rows), "indices": assignment[lane.name],
        }
    if gate_found():
        return
    run_started = time.monotonic()
    merged, phase_a_gate = _full_shard_run_phase(
        phase_a, specs, deadline, rows, assignment, canonical_sha256, main_digest, audit, "A",
        main_snapshot=main_snapshot, snapshot_of=snapshot_of, leftover_allowlist=allowlist,
    )
    # Like serial --all, test failures alone do not stop the run: phase B still runs
    # and the run still fails (so do unreviewed ignored-file changes).  Runner-detected
    # isolation and gate problems (coverage, crash, deadline, records, tracked/untracked/
    # serial-check leftovers, residue) stop it here.  An isolation problem that only
    # shows as a failing test is a test outcome to this rule; it still refuses the proof.
    if phase_a_gate:
        audit["phase_b_skipped"] = True
        audit["run_wall_seconds"] = round(time.monotonic() - run_started, 1)
        return
    merged_b, _phase_b_gate = _full_shard_run_phase(
        [phase_b], specs, deadline, rows, assignment, canonical_sha256, main_digest, audit, "B",
        main_snapshot=main_snapshot, snapshot_of=snapshot_of, leftover_allowlist=allowlist,
    )
    merged.update(merged_b)
    audit["run_wall_seconds"] = round(time.monotonic() - run_started, 1)
    audit["problems"].extend(full_shard_coverage_problems(len(rows), merged))
    audit["problems"].extend(full_shard_skip_problems(rows, decorator_skips, runtime_skips, merged))
    audit["executed"] = sum(len(result["executed"]) for result in merged.values())
    audit["suppressed"] = sum(len(result["suppressed"]) for result in merged.values())
    audit["skips"] = sorted(
        ({"id": entry["id"], "reason": entry["reason"], "lane": lane}
         for lane, result in merged.items() for entry in result["skips"]),
        key=lambda item: (item["id"], item["lane"]),
    )


def _full_shard_cleanup(work: Path, audit: dict) -> None:
    """Remove every clone and private namespace, then verify; only then may a proof follow."""
    targets = [work]
    for record in [audit.get("enumeration", {}), *audit["lanes"].values()]:
        for key in ("tmpdir", "pycache"):
            value = record.get(key)
            if value and value != "None":
                targets.append(Path(value))
    for target in targets:
        problem = _full_shard_remove_tree(target)
        if problem:
            audit["cleanup"]["problems"].append(problem)
        else:
            audit["cleanup"]["removed"].append(str(target))
    audit["problems"].extend(audit["cleanup"]["problems"])


def run_sharded_selection(
    root: Path, selection: Selection, verbose: bool, evidence_dir: Path, *,
    manifest_path: Path | None = None,
) -> int:
    """Canonical full discovery as the reviewed two-phase plan; 0 only when every gate holds."""
    if sys.platform not in FULL_SHARD_PLATFORMS:
        raise ImpactError(_full_shard_platform_message())
    if not selection.full_suite:
        raise ImpactError("--sharded requires canonical full discovery")
    root = Path(root).resolve(strict=True)
    evidence_dir = Path(evidence_dir)
    validate_full_shard_destination(root, evidence_dir)
    if evidence_dir.parent.resolve(strict=True).stat().st_dev != root.stat().st_dev:
        raise ImpactError("--sharded destination must be on the repository's volume (clonefile)")
    plan = load_full_shard_plan(root)
    plan_sha256 = sha256_file(root / FULL_SHARD_PLAN_RELATIVE)
    temp_parent = Path(tempfile.gettempdir())
    preflight_selection(root, selection)
    evidence_dir.mkdir(mode=0o700)
    work = evidence_dir / "work"
    lanes_dir = evidence_dir / "lanes"
    work.mkdir(mode=0o700)
    lanes_dir.mkdir(mode=0o700)
    audit: dict = {
        "schema": "http-full-shard-audit/2", "status": None, "argv": list(sys.argv),
        "root": str(root), "head": None, "plan_path": FULL_SHARD_PLAN_RELATIVE,
        "plan_sha256": plan_sha256, "plan_derivation": plan["derivation"],
        "lane_deadline_seconds": plan["lane_deadline_seconds"],
        "identity": full_shard_lane_identity(), "evidence": str(evidence_dir),
        "temp_parent": str(temp_parent), "canonical_sha256": None, "canonical_count": None,
        "enumeration": {}, "lanes": {}, "lanes_prepared": [], "phase_a_seconds": None,
        "phase_b_seconds": None, "run_wall_seconds": None, "phase_b_skipped": False,
        "phase_a_started_epoch": None, "phase_a_ended_epoch": None,
        "phase_b_started_epoch": None, "phase_b_ended_epoch": None, "chain_drift": {},
        "problems": [], "gate_problems": [], "non_gate_problems": [],
        "non_success": [], "residue": [], "ignored_inventory": None,
        "decorator_skips": None, "runtime_skips": plan.get("runtime_skips", {}), "skips": None,
        "cleanup": {"removed": [], "problems": []}, "started_epoch": round(time.time(), 3),
    }
    started = time.monotonic()
    print(f"sharded full: evidence {evidence_dir}; plan sha256 {plan_sha256}")
    interrupted = None
    try:
        audit["problems"].extend(
            problem for problem in _full_shard_gid_problems([evidence_dir, work, lanes_dir, temp_parent])
        )
        if not audit["problems"]:
            _full_shard_execute(
                root, plan, verbose, work, lanes_dir, temp_parent, audit,
                manifest_path=manifest_path,
            )
    except (ImpactError, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        audit["problems"].append(f"coordinator error: {type(exc).__name__}: {exc}")
    except BaseException as exc:
        interrupted = exc
        audit["problems"].append(f"interrupted: {type(exc).__name__}")
    if not audit["problems"]:
        # Any exception here is a cleanup problem; the audit below is always written.
        try:
            _full_shard_cleanup(work, audit)
        except Exception as exc:
            audit["problems"].append(f"cleanup error: {type(exc).__name__}: {exc}")
        except BaseException as exc:
            interrupted = exc
            audit["problems"].append(f"cleanup interrupted: {type(exc).__name__}")
    # Everything that is not a plain test outcome or an unreviewed ignored-file change
    # is a gate problem (isolation, coverage, records, tracked/untracked/serial-check
    # leftovers, residue, cleanup or coordinator); any problem of either kind fails the run.
    non_gate = set(audit["non_gate_problems"])
    audit["gate_problems"] = [problem for problem in audit["problems"] if problem not in non_gate]
    audit["status"] = "passed" if not audit["problems"] else "failed"
    audit["total_wall_seconds"] = round(time.monotonic() - started, 1)
    audit["ended_epoch"] = round(time.time(), 3)
    _full_shard_write_json(evidence_dir / "audit.json", audit)
    if interrupted is not None:
        raise interrupted
    if audit["status"] == "passed":
        print(
            f"sharded full passed: {audit.get('executed')} executed, {audit.get('suppressed')} "
            f"suppressed by holders, {audit['canonical_count']} canonical; run_wall "
            f"{audit['run_wall_seconds']} s; audit {evidence_dir / 'audit.json'}"
        )
        return 0
    print(
        f"sharded full FAILED with {len(audit['problems'])} problems; evidence kept at "
        f"{evidence_dir} (remove it after review); audit {evidence_dir / 'audit.json'}",
        file=sys.stderr,
    )
    for problem in audit["problems"][:40]:
        print(f"  - {problem}", file=sys.stderr)
    if verbose:
        for name, record in audit["lanes"].items():
            print(f"  lane {name} log: {record.get('log')}", file=sys.stderr)
    return 1


def print_selection(selection: Selection) -> None:
    print("mode:", "full-suite" if selection.full_suite else "related-tests")
    if selection.changed_paths:
        print("changed paths:")
        for path in sorted(selection.changed_paths):
            print(f"  - {path}")
    print("tests:")
    if selection.full_suite:
        print("  - unittest discovery: test_cases/test_*.py")
    else:
        for test_id in sorted(selection.tests):
            print(f"  - {test_id}")
    if selection.reasons:
        print("reasons:")
        for reason in dict.fromkeys(selection.reasons):
            print(f"  - {reason}")


def print_test_suites(manifest: Mapping) -> None:
    print("test suites:")
    for suite in manifest["test_suites"]:
        print(f"  {suite['id']} ({len(suite['tests'])} modules)")
        print(f"    {suite['description']}")
        for test_id in suite["tests"]:
            print(f"    - {test_id}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Run unittest modules related to changed scripts. The tool never "
            "rewrites test cases or assertions."
        )
    )
    result.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    result.add_argument("--approvals", type=Path, default=DEFAULT_APPROVALS)
    result.add_argument("--changed", action="append", default=[], metavar="PATH")
    result.add_argument("--changed-file", action="append", default=[], metavar="FILE")
    result.add_argument("--git-base", metavar="REF")
    result.add_argument("--git", action="store_true", help="include staged, unstaged, and untracked Git paths")
    result.add_argument("--all", action="store_true", help="run canonical full unittest discovery")
    result.add_argument(
        "--sharded", type=Path, metavar="ABSOLUTE_NEW_DIR",
        help=("with --all: run the same canonical full discovery as the reviewed two-phase "
              "shard plan (test_cases/full_shard_plan.json) and keep lane evidence in a new "
              "directory outside the repository; issues the same proof as serial --all; macOS only"),
    )
    result.add_argument(
        "--validation-only", action="store_true",
        help=("AIR/prod validation only: require exactly the three real ISSUE-0016 "
              "FAILs and no other failure, error, or new skip; never a release proof"),
    )
    result.add_argument(
        "--timings", type=Path, metavar="ABSOLUTE_NEW_PATH",
        help="write opt-in per-test validation timings outside the repository",
    )
    result.add_argument("--check", action="store_true", help="validate mappings and require no unapproved hashes")
    result.add_argument(
        "--require-full", action="store_true",
        help="with --check, also require a current full-suite attestation",
    )
    result.add_argument("--list", action="store_true", help="show selection without running or approving")
    result.add_argument(
        "--preflight", action="store_true",
        help="validate the effective selection's capabilities without tests or approvals",
    )
    result.add_argument(
        "--suite", action="append", default=[], metavar="ID",
        help="run one logical test suite; repeat to combine suites (never updates approvals)",
    )
    result.add_argument(
        "--list-suites", action="store_true",
        help="list the complete logical test-suite catalog without running tests",
    )
    result.add_argument("--no-approve", action="store_true", help="do not update approved hashes after success")
    result.add_argument("--watch", action="store_true", help="watch approved hashes and test each new change set")
    result.add_argument("--interval", type=float, default=2.0, help="watch polling interval in seconds")
    result.add_argument("-v", "--verbose", action="store_true")
    return result


def _one_cycle(args: argparse.Namespace, *, watch: bool = False) -> tuple[int, str]:
    root = ROOT
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    approvals_path = args.approvals
    if not approvals_path.is_absolute():
        approvals_path = root / approvals_path
    manifest = load_and_validate_manifest(root, manifest_path)
    before = make_snapshot(root, manifest_path, manifest)
    approvals = load_approvals(approvals_path)
    pending = detect_pending(before, approvals)

    if args.check:
        if pending.any():
            print("unapproved source/test state detected", file=sys.stderr)
            return 4, json.dumps(snapshot_as_json(before), sort_keys=True)
        if args.require_full and not full_suite_attestation_is_current(
            before, approvals.get("full_suite_attestation"),
            validation_only=args.validation_only,
        ):
            print(
                "full-suite attestation is missing, stale, or from a different environment",
                file=sys.stderr,
            )
            return 5, json.dumps(snapshot_as_json(before), sort_keys=True)
        print(f"impact manifest and {len(before.scripts)} scripts are approved")
        return 0, json.dumps(snapshot_as_json(before), sort_keys=True)

    explicit = list(args.changed)
    for changed_file in args.changed_file:
        explicit.extend(read_changed_file(changed_file))
    if args.git or args.git_base:
        explicit.extend(git_changed_paths(root, args.git_base))

    if args.all or pending.approvals_missing:
        selection = Selection(
            tests=set(manifest["baseline_tests"]), full_suite=True,
            changed_paths=set(before.scripts),
            reasons=["explicit --all" if args.all else "approval ledger is missing"],
        )
    else:
        selection = select_tests(root, manifest, explicit, pending)

    state_key = json.dumps(snapshot_as_json(before), sort_keys=True)
    if args.preflight:
        print_selection(selection)
        try:
            preflight_selection(root, selection)
        except ImpactError as exc:
            print(
                f"preflight failed; approved hashes were not changed: {exc}",
                file=sys.stderr,
            )
            return 2, state_key
        print(
            "Git/capability preflight passed; full-suite runtime environment not "
            "checked; tests not run; approval ledger unchanged"
        )
        return 0, state_key
    if not selection.changed_paths and not pending.any() and not explicit and not args.all:
        if not watch:
            print(f"no script or test changes; {len(before.scripts)} mappings valid")
        return 0, state_key
    if selection.full_suite:
        # Refuse a non-governed TOPLEVEL-5 environment before executing tests
        # or creating/updating an approval ledger.
        before_environment = full_suite_environment(
            expected_lock_sha256=_snapshot_toplevel_lock_sha256(before),
        )
    else:
        before_environment = None
    print_selection(selection)
    if args.list:
        return 0, state_key
    try:
        if args.validation_only:
            result = run_validation_selection(
                root, selection, args.verbose, args.timings,
            )
        elif getattr(args, "sharded", None) is not None:
            result = run_sharded_selection(
                root, selection, args.verbose, args.sharded, manifest_path=manifest_path,
            )
        else:
            result = run_selection(root, selection, args.verbose)
    except ImpactError as exc:
        # Keep the failed source fingerprint for watch as well. A capability
        # refusal is an attempted selection, not a reason to busy-retry Git.
        print(f"preflight failed; approved hashes were not changed: {exc}", file=sys.stderr)
        return 2, state_key
    if result:
        print("related tests failed; approved hashes were not changed", file=sys.stderr)
        return result, state_key
    if selection.full_suite:
        print(full_suite_coverage_summary(full_suite_attestation(
            before, environment=before_environment,
            validation_only=args.validation_only,
        )))

    after_manifest = load_and_validate_manifest(root, manifest_path)
    after = make_snapshot(root, manifest_path, after_manifest)
    after_key = json.dumps(snapshot_as_json(after), sort_keys=True)
    if after_key != state_key:
        print("source/test state changed while tests ran; hashes were not approved", file=sys.stderr)
        return 2, after_key
    if not args.no_approve:
        if selection.full_suite:
            approval_environment = full_suite_environment(
                expected_lock_sha256=_snapshot_toplevel_lock_sha256(after),
            )
            full_suite_verified = True
        elif full_suite_attestation_is_current(
            after, approvals.get("full_suite_attestation"),
            validation_only=args.validation_only,
        ):
            approval_environment = full_suite_environment(
                expected_lock_sha256=_snapshot_toplevel_lock_sha256(after),
            )
            full_suite_verified = True
        else:
            approval_environment = None
            full_suite_verified = False

        def verify_published_approval() -> None:
            final_manifest = load_and_validate_manifest(root, manifest_path)
            final_snapshot = make_snapshot(root, manifest_path, final_manifest)
            final_key = json.dumps(snapshot_as_json(final_snapshot), sort_keys=True)
            if final_key != after_key:
                raise ImpactError(
                    "source/test state changed while publishing approval"
                )
            if full_suite_verified:
                final_environment = full_suite_environment(
                    expected_lock_sha256=_snapshot_toplevel_lock_sha256(
                        final_snapshot,
                    ),
                )
                if final_environment != approval_environment:
                    raise ImpactError(
                        "full-suite environment changed while publishing approval"
                    )

        atomic_write_approvals(
            approvals_path,
            after,
            full_suite=full_suite_verified,
            full_suite_environment_value=approval_environment,
            validation_only=args.validation_only,
            post_publish_verify=verify_published_approval,
        )
        print(f"approved hashes updated atomically: {approvals_path}")
    return 0, state_key


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.sharded is not None:
        if not args.all:
            parser().error("--sharded requires --all")
        conflicts = [name for name, present in (
            ("--validation-only", args.validation_only),
            ("--timings", args.timings is not None),
            ("--check", args.check), ("--require-full", args.require_full),
            ("--list", args.list), ("--preflight", args.preflight),
            ("--watch", args.watch), ("--suite", bool(args.suite)),
            ("--list-suites", args.list_suites), ("--changed", bool(args.changed)),
            ("--changed-file", bool(args.changed_file)), ("--git", args.git),
            ("--git-base", bool(args.git_base)),
        ) if present]
        if conflicts:
            parser().error("--sharded cannot be combined with " + ", ".join(conflicts))
        if sys.platform not in FULL_SHARD_PLATFORMS:
            parser().error(_full_shard_platform_message())
        try:
            validate_full_shard_destination(ROOT, args.sharded)
        except ImpactError as exc:
            parser().error(str(exc))
    if args.timings is not None:
        if not args.all or not args.validation_only or any((
            args.check, args.require_full, args.list, args.preflight,
            args.watch, args.suite, args.list_suites,
        )):
            parser().error("--timings requires --all --validation-only without other modes")
        try:
            validate_timings_destination(ROOT, args.timings)
        except ImpactError as exc:
            parser().error(str(exc))
    if args.validation_only and not (
        args.all or (args.check and args.require_full)
    ):
        parser().error("--validation-only requires --all or --check --require-full")
    if args.interval < 0.2:
        parser().error("--interval must be at least 0.2 seconds")
    if args.preflight and (args.check or args.list or args.list_suites or args.watch):
        parser().error("--preflight cannot be combined with --check, --list, --list-suites, or --watch")
    if args.watch and (
        args.check or args.require_full or args.list or args.all or args.changed or args.changed_file
        or args.git or args.git_base
    ):
        parser().error("--watch cannot be combined with one-shot selection options")
    if args.require_full and not args.check:
        parser().error("--require-full must be combined with --check")
    if args.check and (args.list or args.all or args.changed or args.changed_file or args.git or args.git_base):
        parser().error("--check cannot be combined with test-selection options")
    suite_conflicts = (
        args.check or args.require_full or args.list or args.all or args.changed or args.changed_file
        or args.git or args.git_base or args.watch
    )
    if args.suite and suite_conflicts:
        parser().error("--suite cannot be combined with change-aware selection options")
    if args.list_suites and (
        args.suite or suite_conflicts or args.no_approve or args.verbose
    ):
        parser().error("--list-suites must be used by itself")
    try:
        if args.suite or args.list_suites:
            manifest_path = args.manifest
            if not manifest_path.is_absolute():
                manifest_path = ROOT / manifest_path
            manifest = load_and_validate_manifest(ROOT, manifest_path)
            if args.list_suites:
                print_test_suites(manifest)
                return 0
            selection = select_test_suites(manifest, args.suite)
            print_selection(selection)
            try:
                if args.preflight:
                    preflight_selection(ROOT, selection)
                    print(
                        "Git/capability preflight passed; full-suite runtime "
                        "environment not checked; tests not run; approval ledger unchanged"
                    )
                    return 0
                print("approval ledger: unchanged (logical suite run)")
                return run_selection(ROOT, selection, args.verbose)
            except ImpactError as exc:
                print(
                    f"preflight failed; approved hashes were not changed: {exc}",
                    file=sys.stderr,
                )
                return 2
        if not args.watch:
            code, _state = _one_cycle(args)
            return code
        print(f"watching script/test hashes every {args.interval:g}s; Ctrl-C to stop")
        last_attempted = ""
        while True:
            try:
                manifest_path = args.manifest if args.manifest.is_absolute() else ROOT / args.manifest
                approvals_path = args.approvals if args.approvals.is_absolute() else ROOT / args.approvals
                manifest = load_and_validate_manifest(ROOT, manifest_path)
                state = make_snapshot(ROOT, manifest_path, manifest)
                pending = detect_pending(state, load_approvals(approvals_path))
                state_key = json.dumps(snapshot_as_json(state), sort_keys=True)
                if pending.any() and state_key != last_attempted:
                    _code, last_attempted = _one_cycle(args, watch=True)
            except (ImpactError, GitDiscoveryError) as exc:
                message = f"watch validation error: {exc}"
                if message != last_attempted:
                    print(message, file=sys.stderr)
                    last_attempted = message
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except GitDiscoveryError as exc:
        print(f"git discovery error: {exc}", file=sys.stderr)
        return 3
    except ImpactError as exc:
        print(f"impact configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
