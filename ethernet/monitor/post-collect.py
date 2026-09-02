#!/usr/bin/env python3
"""Turn one Ethernet collection archive into a validation report and HTML."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Iterable


BASE = Path(__file__).resolve().parent
HTTP_ROOT = BASE.parent.parent
ANALYZER = HTTP_ROOT / "tools/lldp-analyze-tool/analyze_lldp.py"
OUTPUT_DIR = HTTP_ROOT / "tools/lldp-analyze-tool/99-output-p2p"
HTML_GENERATOR = HTTP_ROOT / "monitor/generate-monitor-html.py"


def log(message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"[{timestamp}] [ETH-CLOSED-LOOP] {message}", flush=True)


def archive_stem(path: Path) -> str:
    return re.sub(r"\.(?:tar\.gz|tgz)$", "", path.name, flags=re.IGNORECASE)


def select_expected_dot(output_dir: Path, environment: str) -> Path:
    """Select the current P2P source's AIR or Production expected topology."""
    output_dir = output_dir.resolve()
    suffix = "-air.dot" if environment == "air" else "-lldpq.dot"
    p2p_input = output_dir.parent / "p2p.xlsx"
    if p2p_input.is_file():
        expected = output_dir / f"{p2p_input.resolve().stem}{suffix}"
        if expected.is_file():
            return expected
    candidates = sorted(path for path in output_dir.glob(f"*{suffix}") if path.is_file())
    if not candidates:
        raise ValueError(f"no *{suffix} found in {output_dir}")
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise ValueError(f"multiple *{suffix} files found in {output_dir}: {names}")
    return candidates[0]


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def emit_process_output(completed: subprocess.CompletedProcess[str]) -> None:
    for stream_name, output in (("stdout", completed.stdout), ("stderr", completed.stderr)):
        for line in (output or "").splitlines():
            log(f"[{stream_name}] {line}")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze one exact Ethernet collection archive, publish its validation "
            "XLSX, then refresh monitor.html for the same environment."
        ),
    )
    parser.add_argument("--archive", type=Path, required=True,
                        help="exact Ethernet collection .tar.gz/.tgz from this run")
    parser.add_argument("--environment", choices=("air", "prod"), required=True,
                        help="collection environment and HTML generation scope")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    archive = args.archive.expanduser().resolve()
    if not archive.is_file():
        log(f"ERROR: collection archive does not exist: {archive}")
        return 2
    if not re.search(r"\.(?:tar\.gz|tgz)$", archive.name, re.IGNORECASE):
        log(f"ERROR: collection archive must be .tar.gz or .tgz: {archive}")
        return 2
    for label, path in (("LLDP analyzer", ANALYZER), ("HTML generator", HTML_GENERATOR)):
        if not path.is_file():
            log(f"ERROR: {label} does not exist: {path}")
            return 2
    if not OUTPUT_DIR.is_dir():
        log(
            "ERROR: setup-managed 99-output-p2p link/directory is missing: "
            f"{OUTPUT_DIR}; rerun DAY0-Prepare/01-a-setup.py"
        )
        return 2
    try:
        expected_dot = select_expected_dot(OUTPUT_DIR, args.environment)
    except ValueError as exc:
        log(f"ERROR: {exc}")
        return 2

    report = OUTPUT_DIR / f"{archive_stem(archive)}-ethernet-topology-validation.xlsx"
    previous_signature = None
    if report.is_file():
        stat = report.stat()
        previous_signature = (stat.st_mtime_ns, stat.st_size)

    analyze_command = [
        sys.executable,
        str(ANALYZER),
        "--archive",
        str(archive),
        "--dot",
        str(expected_dot),
        "--output-dir",
        str(OUTPUT_DIR),
    ]
    log(f"analyzing exact archive: {archive}")
    log(f"expected topology ({args.environment}): {expected_dot}")
    analyzed = run_command(analyze_command)
    emit_process_output(analyzed)
    # analyze_lldp.py returns 1 when it successfully creates a report that has
    # mismatches.  Return code 2 means the analysis/report generation failed.
    if analyzed.returncode not in (0, 1):
        log(f"ERROR: LLDP analyzer failed with exit code {analyzed.returncode}")
        return 2
    if not report.is_file() or report.stat().st_size == 0:
        log(f"ERROR: LLDP analyzer did not publish the expected report: {report}")
        return 2
    current = report.stat()
    if previous_signature == (current.st_mtime_ns, current.st_size):
        log(f"ERROR: LLDP analyzer left a stale report unchanged: {report}")
        return 2
    if analyzed.returncode == 1:
        log("validation report generated with link mismatches (visible in the XLSX/HTML)")
    else:
        log("validation report generated without detected link mismatches")

    html_command = [
        sys.executable,
        str(HTML_GENERATOR),
        "--type",
        args.environment,
    ]
    log(f"refreshing monitor.html with scope={args.environment}")
    generated = run_command(html_command)
    emit_process_output(generated)
    if generated.returncode != 0:
        log(f"ERROR: HTML generator failed with exit code {generated.returncode}")
        return 2
    log(f"closed loop complete: {report.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
