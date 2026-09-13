#!/usr/bin/env python3
"""Validate script coverage and run tests affected by approved source changes.

The impact manifest is policy.  This program never creates or edits test code;
it only selects existing unittest modules.  After a successful run it may
atomically record the exact source/test hashes that were verified.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import fnmatch
import hashlib
import importlib.util
from importlib import metadata as importlib_metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Callable, Iterable, Mapping, Sequence


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1] / "tools"
if os.fspath(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, os.fspath(TOOLS_DIRECTORY))
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
GENERATED_RUNTIME_SCRIPTS = frozenset({
    "ztp/ztp-bootstrap_oob.sh",
    "ztp/ztp-bootstrap_oobofoob.sh",
})
NON_SOURCE_ROOTS = frozenset({".git", ".codex", ".agents", "outputs"})
# Keep this aligned with tools/project_contract.py.  These names describe
# development/test data wherever they occur; they are not deployable scripts.


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


def discover_source_scripts(root: Path) -> dict[str, str]:
    """Return every governed source path and its in-workspace canonical path."""
    found: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        relative = path.relative_to(root)
        if (
            relative.parts[0] in NON_SOURCE_ROOTS
            or relative.parts[0].startswith(".codex_tmp")
            or path_disposition(relative.as_posix()) != "production"
        ):
            continue
        if any(part.startswith("99-output") for part in relative.parts):
            continue
        if relative.as_posix() in GENERATED_RUNTIME_SCRIPTS:
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
        spec.loader.exec_module(module)
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


def _validate_test_ids(root: Path, values: Iterable[str], label: str) -> None:
    available = discover_tests(root)
    for test_id in values:
        if not TEST_ID_RE.fullmatch(test_id):
            raise ImpactError(f"{label} has unsafe/non-module test id: {test_id}")
        if test_id not in available:
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

    baseline = _string_list(manifest.get("baseline_tests"), "baseline_tests")
    _validate_test_ids(root, baseline, "baseline_tests")

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
        _validate_test_ids(root, tests, f"test_suites.{suite_id}.tests")
        for test_id in tests:
            suite_membership.setdefault(test_id, []).append(suite_id)
    discovered_tests = set(discover_tests(root))
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
        _validate_test_ids(root, tests, f"test_rules.{rule_id}.tests")
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
        _validate_test_ids(root, tests, f"workflows.{flow_id}.tests")
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
        _validate_test_ids(root, tests, f"path_rules[{index}].tests")

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
    return {
        "schema_version": 1,
        "snapshot_sha256": hashlib.sha256(canonical).hexdigest(),
        "environment": dict(environment),
        "scenario_coverage": full_suite_scenario_coverage(),
    }


def full_suite_coverage_summary(value: Mapping[str, object]) -> str:
    """Render the bounded scenario field without implying unexecuted coverage."""
    coverage = value.get("scenario_coverage")
    if coverage != full_suite_scenario_coverage():
        raise ImpactError("full-suite scenario coverage is missing or malformed")
    return f"{ROOT_ENTRYPOINT_SCENARIO}: {ROOT_ENTRYPOINT_NOT_COVERED}"


def full_suite_attestation_is_current(snapshot: Snapshot, value: object) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        current = full_suite_attestation(snapshot)
    except ImpactError:
        return False
    return value == current


def atomic_write_approvals(
    path: Path,
    snapshot: Snapshot,
    *,
    full_suite: bool = False,
    full_suite_environment_value: Mapping[str, object] | None = None,
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


def run_selection(root: Path, selection: Selection, verbose: bool) -> int:
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
    environment.setdefault("PYTHONPYCACHEPREFIX", "/tmp/http-related-test-pyc")
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return 0 if result.returncode == 0 else 1


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
    result.add_argument("--check", action="store_true", help="validate mappings and require no unapproved hashes")
    result.add_argument(
        "--require-full", action="store_true",
        help="with --check, also require a current full-suite attestation",
    )
    result.add_argument("--list", action="store_true", help="show selection without running or approving")
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
    result = run_selection(root, selection, args.verbose)
    if result:
        print("related tests failed; approved hashes were not changed", file=sys.stderr)
        return result, state_key
    if selection.full_suite:
        print(full_suite_coverage_summary(full_suite_attestation(
            before, environment=before_environment,
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
            post_publish_verify=verify_published_approval,
        )
        print(f"approved hashes updated atomically: {approvals_path}")
    return 0, state_key


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.interval < 0.2:
        parser().error("--interval must be at least 0.2 seconds")
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
            print("approval ledger: unchanged (logical suite run)")
            return run_selection(ROOT, selection, args.verbose)
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
