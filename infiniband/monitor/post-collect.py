#!/usr/bin/env python3
"""Turn one UFM fabric snapshot (ibdiagnet archive or iblinkinfo log) into the IB topology validation report.

The InfiniBand counterpart of ethernet/monitor/post-collect.py (owner 2026-10-21): cron.sh hands over
the exact file it fetched from the UFM in this run, and this script publishes
<run-id>_<node>-{ibdiagnet|iblinkinfo}-topology-validation.xlsx into the setup-managed 99-output-p2p,
where monitor.html's IB Link Validation tab reads it. Unlike the Ethernet loop it does not refresh
monitor.html itself: cron.sh refreshes the page after it in every case, so a failed analysis stays a
UFM warning and never holds back the collected data (infiniband/monitor/UFM-MONITOR.md section 13).

Owner 2026-10-22: the report is accepted only when the provenance the analyser writes beside it names
this run's input and the CVT by their sha256 (no modification-time check), and a receipt records which
run, which UFM and whether iblinkinfo stood in for ibdiagnet.

Run by hand without --archive, it analyses the newest input in ./ufm-ibdiagnet/; every input is read
from this script's own directory (./ufm-ibdiagnet, ./99-output-p2p).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


BASE = Path(__file__).resolve().parent
HTTP_ROOT = BASE.parent.parent
# Self-contained (owner 2026-10-21): every input sits in this script's own directory, as links that
# setup creates; only the shared analyzer code is taken from tools/.
ANALYZER = HTTP_ROOT / "tools/ibdiagnet-analyze-tool/analyze.py"
ARCHIVE_DIR = BASE / "ufm-ibdiagnet"      # setup link -> 99-output-monitor/infiniband/ufm-ibdiagnet
OUTPUT_DIR = BASE / "99-output-p2p"       # setup link -> the project's 99-output-p2p (CVT + reports)
# cron.sh names what it fetched <run-id>_<node>_ibdiagnet2.tgz or <run-id>_<node>_iblinkinfo.log
# (owner 2026-10-22: the run-id, YYYYMMDD-HHMM-(prod|air)-<16 hex>, carries the minute timestamp),
# with the UFM's completion record beside it as <run-id>_<node>_<kind>.done.
ARCHIVE_NAME = re.compile(
    r"^(?P<stem>(?P<run_id>\d{8}-\d{4}-(?:prod|air)-[0-9a-f]{16})_(?P<node>[A-Za-z0-9][A-Za-z0-9-]*))"
    r"_(?P<file>ibdiagnet2\.tgz|iblinkinfo\.log)$"
)
PROVENANCE_SCHEMA = "ib-report-provenance-v1"
RECEIPT_SCHEMA = "ufm-ib-report-receipt-v1"


def log(message: str) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"[{timestamp}] [IB-CLOSED-LOOP] {message}", flush=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_cvt(output_dir: Path) -> Path:
    """Select the CVT of the current P2P source, as analyze.py's batch mode does."""
    output_dir = output_dir.resolve()
    p2p_input = output_dir.parent / "p2p.xlsx"
    if p2p_input.is_file():
        expected = output_dir / f"{p2p_input.resolve().stem}-cvt.xlsx"
        if expected.is_file():
            return expected
    candidates = sorted(path for path in output_dir.glob("*-cvt.xlsx")
                        if path.is_file() and not path.name.startswith("~$"))
    if not candidates:
        raise ValueError(f"no *-cvt.xlsx found in {output_dir}; generate it with p2p-to-validation.py")
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise ValueError(f"multiple *-cvt.xlsx files found in {output_dir}: {names}")
    return candidates[0]


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False,
                          stdin=subprocess.DEVNULL)


def emit_process_output(completed: subprocess.CompletedProcess[str]) -> None:
    for stream_name, output in (("stdout", completed.stdout), ("stderr", completed.stderr)):
        for line in (output or "").splitlines():
            log(f"[{stream_name}] {line}")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze one exact UFM ibdiagnet archive or iblinkinfo log from this run "
            "and publish its IB topology validation XLSX."
        ),
    )
    parser.add_argument("--archive", type=Path,
                        help="exact <run-id>_<node>_ibdiagnet2.tgz or <run-id>_<node>_iblinkinfo.log "
                             "fetched by cron.sh; default: the newest one in ./ufm-ibdiagnet/")
    return parser.parse_args(argv)


def newest_archive(directory: Path) -> Path:
    """A standalone run analyses the newest input of this collector in its own directory."""
    candidates = [path for path in directory.iterdir()
                  if path.is_file() and ARCHIVE_NAME.fullmatch(path.name)]
    if not candidates:
        raise ValueError(f"no <run-id>_<node>_ibdiagnet2.tgz or _iblinkinfo.log in {directory}")
    # the run-id starts with its UTC minute; the modification time orders runs within one minute
    return max(candidates, key=lambda path: (path.name[:13], path.stat().st_mtime_ns, path.name))


def check_provenance(report: Path, actual: Path, cvt: Path) -> Path:
    """Owner 2026-10-22: the analyser's provenance must name this run's input and this CVT by sha256,
    and the report bytes it was written for; a report left from another input cannot pass."""
    sidecar = report.with_name(report.name + ".provenance.json")
    try:
        record = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"report provenance is missing or unreadable: {sidecar.name}: {exc}") from exc
    if not isinstance(record, dict) or record.get("schema") != PROVENANCE_SCHEMA:
        raise ValueError(f"report provenance has an unexpected schema: {sidecar.name}")
    for label, path, key in (("report", report, "report"), ("input", actual, "actual"), ("CVT", cvt, "cvt")):
        identity = record.get(key)
        if (not isinstance(identity, dict) or identity.get("sha256") != sha256(path)
                or identity.get("resolved_path") != str(path.resolve())):
            raise ValueError(f"report provenance does not name this run's {label}: {path.name}")
    return sidecar


def completion_record(done: Path) -> dict:
    """The UFM's own .done record that cron.sh keeps beside the input (exit code, reason, host)."""
    try:
        lines = done.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    fields = dict(line.split("=", 1) for line in lines if "=" in line)
    return {key: fields.get(key, "") for key in ("rc", "reason", "hostname")}


def write_receipt(report: Path, named: re.Match, actual: Path, cvt: Path, sidecar: Path) -> Path:
    kind = "ibdiagnet" if named.group("file").startswith("ibdiagnet") else "iblinkinfo"
    receipt = report.with_name(report.name[:-len(".xlsx")] + ".receipt.json")
    done = actual.with_name(actual.name.rsplit(".", 1)[0] + ".done")
    record = {
        "schema": RECEIPT_SCHEMA,
        "run_id": named.group("run_id"),
        "node": named.group("node"),
        "kind": kind,
        # cron.sh collects iblinkinfo only once ibdiagnet failed three times in a row
        "degraded": kind == "iblinkinfo",
        "collector": completion_record(done),
        # codex review 2026-10-22: the receipt names the exact .done of this run
        "done": {"name": done.name, "sha256": sha256(done)} if done.is_file() else None,
        "input": {"name": actual.name, "sha256": sha256(actual)},
        "cvt": {"name": cvt.name, "sha256": sha256(cvt)},
        "report": {"name": report.name, "sha256": sha256(report)},
        "provenance": {"name": sidecar.name, "sha256": sha256(sidecar)},
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    descriptor, temporary = tempfile.mkstemp(prefix=".receipt.", dir=report.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary, receipt)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return receipt


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.archive is None:
        try:
            args.archive = newest_archive(ARCHIVE_DIR)
        except (OSError, ValueError) as exc:
            log(f"ERROR: {exc}")
            return 2
    archive = args.archive.expanduser().resolve()
    named = ARCHIVE_NAME.fullmatch(archive.name)
    if not named:
        log(f"ERROR: not a UFM fabric snapshot of this collector: {archive.name}")
        return 2
    if not archive.is_file():
        log(f"ERROR: input does not exist: {archive}")
        return 2
    if not ANALYZER.is_file():
        log(f"ERROR: IB analyzer does not exist: {ANALYZER}")
        return 2
    if not OUTPUT_DIR.is_dir():
        log(
            "ERROR: setup-managed 99-output-p2p link/directory is missing: "
            f"{OUTPUT_DIR}; rerun DAY0-Prepare/01-a-setup.py"
        )
        return 2
    try:
        cvt = select_cvt(OUTPUT_DIR)
    except ValueError as exc:
        log(f"ERROR: {exc}")
        return 2

    kind = "ibdiagnet" if named.group("file").startswith("ibdiagnet") else "iblinkinfo"
    report = OUTPUT_DIR.resolve() / f"{named.group('stem')}-{kind}-topology-validation.xlsx"
    command = [sys.executable, str(ANALYZER), f"--{kind}", str(archive),
               "--p2p", str(cvt), "--output", str(report)]
    log(f"analyzing exact input ({kind}): {archive}")
    log(f"planned topology (CVT): {cvt}")
    analyzed = run_command(command)
    emit_process_output(analyzed)
    # validate_ib_topology.py exits 0 once the report is written, mismatches included; any
    # non-zero exit means the analysis itself failed.
    if analyzed.returncode != 0:
        log(f"ERROR: IB analyzer failed with exit code {analyzed.returncode}")
        return 2
    if not report.is_file() or report.stat().st_size == 0:
        log(f"ERROR: IB analyzer did not publish the expected report: {report}")
        return 2
    try:
        sidecar = check_provenance(report, archive, cvt)
        receipt = write_receipt(report, named, archive, cvt, sidecar)
    except (OSError, ValueError) as exc:
        log(f"ERROR: {exc}")
        return 2
    log(f"validation report published: {report.name} (receipt {receipt.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
