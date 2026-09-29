#!/usr/bin/env python3
"""Canonical unittest discovery with an exact, machine-readable result report.

The ordinary unittest output still reports the three ISSUE-0016 cases as FAIL.
Only the parent governance runner may turn that exact result into a validation-
only attestation. This helper never edits a test, manifest, or approval ledger.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import unittest

from test_cases.run_related_tests import issue0016_validation_report_is_exact


class TimedTextTestResult(unittest.TextTestResult):
    """Collect diagnostic durations without changing unittest outcomes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timings: list[dict[str, str | float]] = []
        self._started: dict[int, float] = {}

    def startTest(self, test: unittest.case.TestCase) -> None:
        super().startTest(test)
        self._started[id(test)] = time.perf_counter()

    def stopTest(self, test: unittest.case.TestCase) -> None:
        started = self._started.pop(id(test), None)
        if started is not None:
            self.timings.append({
                "id": test.id(),
                "duration_seconds": max(0.0, time.perf_counter() - started),
            })
        super().stopTest(test)


def result_report(result: unittest.TestResult) -> dict:
    return {
        "tests_run": result.testsRun,
        "failures": [
            {"id": test.id(), "traceback": traceback}
            for test, traceback in result.failures
        ],
        "errors": [
            {"id": test.id(), "traceback": traceback}
            for test, traceback in result.errors
        ],
        "skipped": [
            {"id": test.id(), "reason": reason}
            for test, reason in result.skipped
        ],
        "expected_failures": [
            {"id": test.id(), "traceback": traceback}
            for test, traceback in result.expectedFailures
        ],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    usage = "usage: validation_unittest REPORT_PATH [-v] [--timings ABSOLUTE_NEW_PATH]"
    if not args or args[0].startswith("-"):
        print(usage, file=sys.stderr)
        return 2
    report_path = Path(args[0])
    remaining = args[1:]
    if remaining.count("-v") > 1:
        print(usage, file=sys.stderr)
        return 2
    verbose = "-v" in remaining
    if verbose:
        remaining.remove("-v")
    timings_path = None
    if remaining:
        if len(remaining) != 2 or remaining[0] != "--timings" or not remaining[1]:
            print(usage, file=sys.stderr)
            return 2
        timings_path = Path(remaining[1])
        if (
            not timings_path.is_absolute()
            or os.path.abspath(timings_path) == os.path.abspath(report_path)
            or os.path.lexists(timings_path)
            or not timings_path.parent.is_dir()
        ):
            print("timings path must be an absolute, new file in an existing directory", file=sys.stderr)
            return 2
    suite = unittest.defaultTestLoader.discover(
        start_dir="test_cases", pattern="test_*.py", top_level_dir=".",
    )
    runner_options = {"verbosity": 2 if verbose else 1, "buffer": True}
    if timings_path is not None:
        runner_options["resultclass"] = TimedTextTestResult
    result = unittest.TextTestRunner(**runner_options).run(suite)
    report = result_report(result)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(report_path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    if timings_path is not None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(timings_path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            for record in result.timings:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    return 0 if issue0016_validation_report_is_exact(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
