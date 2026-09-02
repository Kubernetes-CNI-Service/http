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
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "test_cases/script_test_manifest.json"
DEFAULT_APPROVALS = ROOT / "test_cases/script_test_approved_hashes.json"
SOURCE_SUFFIXES = {".py", ".cgi", ".sh"}
TEST_ID_RE = re.compile(r"^test_cases\.test_[A-Za-z0-9_]+$")
GENERATED_RUNTIME_SCRIPTS = frozenset({
    "ztp/ztp-bootstrap_oob.sh",
    "ztp/ztp-bootstrap_oobofoob.sh",
})
NON_SOURCE_ROOTS = frozenset({".git", ".codex", ".agents"})
# Keep this aligned with tools/project_contract.py.  These names describe
# development/test data wherever they occur; they are not deployable scripts.
NON_DEPLOYMENT_DIR_NAMES = frozenset({
    "test", "tests", "test_cases", "test-results", "__pycache__",
    ".pytest_cache", "node_modules",
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
            or any(part in NON_DEPLOYMENT_DIR_NAMES for part in relative.parts)
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


def load_and_validate_manifest(root: Path, manifest_path: Path) -> dict:
    manifest = read_json_regular(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ImpactError("impact manifest schema_version must be 1")

    baseline = _string_list(manifest.get("baseline_tests"), "baseline_tests")
    _validate_test_ids(root, baseline, "baseline_tests")

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
    for relative in tracked_support:
        normalized = normalize_relative(root, relative)
        path = root / normalized
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise ImpactError(f"missing tracked support file: {relative}") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ImpactError(f"tracked support must be a single-link regular file: {relative}")
        if not any(path_matches(normalized, rule["paths"]) for rule in path_rules):
            raise ImpactError(f"tracked support lacks a path rule: {relative}")
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
    support = {
        relative: sha256_file(root / relative)
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


def atomic_write_approvals(path: Path, snapshot: Snapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ImpactError(f"refusing unsafe approval ledger: {path}")
    payload = json.dumps(
        snapshot_as_json(snapshot), ensure_ascii=False, indent=2, sort_keys=True,
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
        os.replace(temporary, path)
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
            sys.executable, "-B", "-m", "unittest", "discover",
            "-s", "test_cases", "-t", ".", "-p", "test_*.py",
        ]
        if verbose:
            command.append("-v")
    else:
        command = [sys.executable, "-B", "-m", "unittest"]
        if verbose:
            command.append("-v")
        command.extend(sorted(selection.tests))
    environment = os.environ.copy()
    environment.setdefault("PYTHONPYCACHEPREFIX", "/tmp/http-related-test-pyc")
    result = subprocess.run(command, cwd=root, env=environment, check=False)
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
    result.add_argument("--list", action="store_true", help="show selection without running or approving")
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
    print_selection(selection)
    if args.list:
        return 0, state_key
    result = run_selection(root, selection, args.verbose)
    if result:
        print("related tests failed; approved hashes were not changed", file=sys.stderr)
        return result, state_key

    after_manifest = load_and_validate_manifest(root, manifest_path)
    after = make_snapshot(root, manifest_path, after_manifest)
    after_key = json.dumps(snapshot_as_json(after), sort_keys=True)
    if after_key != state_key:
        print("source/test state changed while tests ran; hashes were not approved", file=sys.stderr)
        return 2, after_key
    if not args.no_approve:
        atomic_write_approvals(approvals_path, after)
        print(f"approved hashes updated atomically: {approvals_path}")
    return 0, state_key


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.interval < 0.2:
        parser().error("--interval must be at least 0.2 seconds")
    if args.watch and (
        args.check or args.list or args.all or args.changed or args.changed_file
        or args.git or args.git_base
    ):
        parser().error("--watch cannot be combined with one-shot selection options")
    if args.check and (args.list or args.all or args.changed or args.changed_file or args.git or args.git_base):
        parser().error("--check cannot be combined with test-selection options")
    try:
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
