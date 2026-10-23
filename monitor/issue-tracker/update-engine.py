#!/usr/bin/env python3
"""Take a new CableTracker version's sync engine into monitor/issue-tracker/cabletracker/, byte for byte.

The CableTracker project and the online Issue Tracker both evolve (owner 2026-10-23); REQ7 only copies
the engine's sync part and calls it through its command line. The owner drops the current project in
tools/cabletracker/ (reference only, never shipped). This script:

1. copies the engine files below from that directory into a staging directory;
2. checks the staged engine with the given interpreter: `cabletracker_runner.py --help` and
   `ibdiagnet/generate_report.py --help` must run and still list every option issue-tracker-sync.py
   passes (a new local module the runner now needs, or a renamed option, stops the update here);
3. only then replaces the copy and records every file's sha256 in engine.lock.json.

    python3 monitor/issue-tracker/update-engine.py [--from DIR] [--engine-python PY] [--check]

--check verifies that the copy still matches engine.lock.json and changes nothing.
After an update: run the issue-tracker tests and `issue-tracker-sync.py --precheck-only` against the
project document before the next real sync.
Exit 0: updated (or already current, or --check passed). Exit 2: refused; the copy is unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable

BASE = Path(__file__).resolve().parent
HTTP_ROOT = BASE.parent.parent
ENGINE_DIR = BASE / "cabletracker"
LOCK = BASE / "engine.lock.json"
DEFAULT_SOURCE = HTTP_ROOT / "tools/cabletracker"
SYNC_FILES = (
    "cabletracker_runner.py",
    "mapping_v4.json",
    "ibdiagnet/__init__.py",
    "ibdiagnet/generate_report.py",
)
# every option issue-tracker-sync.py passes to the engine and to generate_report
RUNNER_OPTIONS = (
    "--credentials", "--spreadsheet-id", "--timezone", "--mapping-config", "--source-type",
    "--source-transport", "--source-file", "--cvt-sheet", "--ib-cabling-sheet", "--eth-cabling-sheet",
    "--operation", "--max-runs", "--include-warnings",
)
REPORT_OPTIONS = ("--p2p", "--ibdiagnet-tar", "--output", "--summary-output", "--force")


class UpdateError(Exception):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_lock() -> dict:
    try:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UpdateError(f"cannot read {LOCK.name}: {exc}") from None
    if lock.get("schema") != "cabletracker-engine-lock-v1" or not isinstance(lock.get("files"), dict):
        raise UpdateError(f"{LOCK.name} has an unexpected shape")
    return lock


def check_copy() -> list:
    """Differences between the copy and engine.lock.json (empty when they agree)."""
    lock = read_lock()
    problems = []
    if sorted(lock["files"]) != sorted(SYNC_FILES):
        problems.append("engine.lock.json does not list exactly the sync files")
    for relative, expected in lock["files"].items():
        path = ENGINE_DIR / relative
        if not path.is_file():
            problems.append(f"missing {relative}")
        elif sha256(path) != expected:
            problems.append(f"{relative} differs from engine.lock.json")
    return problems


def help_text(python: str, script: Path) -> str:
    completed = subprocess.run([python, str(script), "--help"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=120, check=False)
    if completed.returncode != 0:
        tail = " | ".join((completed.stderr or completed.stdout).strip().splitlines()[-3:])
        raise UpdateError(f"{script.name} --help failed ({completed.returncode}): {tail}")
    return completed.stdout


def missing_options(text: str, options: Iterable[str]) -> list:
    return [option for option in options if not re.search(re.escape(option) + r"(?![\w-])", text)]


def stage(source: Path, staging: Path) -> dict:
    hashes = {}
    for relative in SYNC_FILES:
        origin = source / relative
        if not origin.is_file():
            raise UpdateError(f"{origin} is missing; is {source} a CableTracker project?")
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
        if sha256(target) != sha256(origin):
            raise UpdateError(f"copy of {relative} is not byte-identical")
        hashes[relative] = sha256(target)
    return hashes


def install(staging: Path, hashes: dict, source: Path) -> list:
    changed = []
    for relative, digest in hashes.items():
        live = ENGINE_DIR / relative
        before = sha256(live) if live.is_file() else None
        if before != digest:
            live.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging / relative, live)
            changed.append((relative, before, digest))
    try:
        shown = source.relative_to(HTTP_ROOT.resolve()).as_posix()
    except ValueError:
        shown = source.name
    lock = {"schema": "cabletracker-engine-lock-v1", "source": shown,
            "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"), "files": hashes}
    descriptor, temporary = tempfile.mkstemp(prefix=".engine.lock.", dir=BASE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(lock, handle, indent=1)
        handle.write("\n")
    os.replace(temporary, LOCK)
    return changed


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Copy a new CableTracker sync engine into monitor/issue-tracker/cabletracker/.")
    parser.add_argument("--from", dest="source", type=Path, default=DEFAULT_SOURCE,
                        help=f"CableTracker project directory (default: {DEFAULT_SOURCE})")
    parser.add_argument("--engine-python", default=sys.executable,
                        help="interpreter with the engine's libraries, used for the --help checks")
    parser.add_argument("--check", action="store_true",
                        help="only verify the copy against engine.lock.json")
    args = parser.parse_args(argv)
    try:
        if args.check:
            problems = check_copy()
            for problem in problems:
                print(f"ERROR: {problem}")
            print("engine copy matches engine.lock.json" if not problems else "engine copy is not the locked one")
            return 0 if not problems else 2
        source = args.source.expanduser().resolve()
        with tempfile.TemporaryDirectory(prefix=".engine-staging-", dir=BASE) as directory:
            staging = Path(directory)
            hashes = stage(source, staging)
            missing = missing_options(help_text(args.engine_python, staging / "cabletracker_runner.py"),
                                      RUNNER_OPTIONS)
            missing += missing_options(help_text(sys.executable, staging / "ibdiagnet/generate_report.py"),
                                       REPORT_OPTIONS)
            if missing:
                raise UpdateError("the new engine no longer accepts options the sync uses: "
                                  + ", ".join(missing) + " (adapt issue-tracker-sync.py first)")
            changed = install(staging, hashes, source)
    except (UpdateError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}; the engine copy is unchanged")
        return 2
    if not changed:
        print("engine copy is already this version")
    for relative, before, after in changed:
        print(f"updated {relative}: {(before or 'absent')[:12]} -> {after[:12]}")
    print("next: run the issue-tracker tests and issue-tracker-sync.py --precheck-only before the next sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
