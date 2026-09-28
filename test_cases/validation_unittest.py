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
import unittest

from test_cases.run_related_tests import issue0016_validation_report_is_exact


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
    if not args or len(args) > 2 or (len(args) == 2 and args[1] != "-v"):
        print("usage: validation_unittest REPORT_PATH [-v]", file=sys.stderr)
        return 2
    report_path = Path(args[0])
    suite = unittest.defaultTestLoader.discover(
        start_dir="test_cases", pattern="test_*.py", top_level_dir=".",
    )
    result = unittest.TextTestRunner(
        verbosity=2 if len(args) == 2 else 1,
        buffer=True,
    ).run(suite)
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
    return 0 if issue0016_validation_report_is_exact(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
