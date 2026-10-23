#!/usr/bin/env python3
"""Archiving of the collected-data directories (owner 2026-10-22: one module in tools/, replacing the
cleanup_data_dirs / cleanup_bundle_day functions of cron.sh).

Every regular file whose name starts with its UTC date (YYYYMMDD-...) follows one rule, whatever its
type (switch and UFM archives, ibdiagnet/iblinkinfo inputs and their .done, run records, dated reports):

  - today's files stay as they are;
  - the files of the previous RETAIN_DAYS-1 days are bundled per day into YYYYMMDD-daily.tar.gz, then
    removed; CSVs stay loose (the monitor page reads them directly) and *.part (still being written)
    is never touched. The bundle's first member is YYYYMMDD-daily.index ("<sha256>  <size>  <name>" for
    every other member, all stored flat under their own names); it is written as .part, its listing
    checked, then linked into place (an existing bundle is never replaced), and only then are the
    originals removed;
  - a file of a day that is already bundled (a run that started before midnight) stays beside the
    bundle and leaves with it;
  - days older than RETAIN_DAYS are deleted, bundles included; collector batch directories
    (YYYYMMDD-HHMM[-air|-prod]) past that window are removed. Links are never followed into.

    python3 tools/collection_archive.py [--retain-days N] <directory or link> [...]

prints one line per action (cron.sh logs them).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import tarfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Union

RETAIN_DAYS = 3
DATED = re.compile(r"^([0-9]{8})-")
BATCH_PREFIX = re.compile(r"^[0-9]{8}-[0-9]{4}")
BATCH = re.compile(r"^([0-9]{8})-[0-9]{4}(-(air|prod))?$")


def _day(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime(text, "%Y%m%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_day(directory: Path, date_text: str, members: List[Path]) -> bool:
    """Bundle one day's files; True when the bundle is in place and the originals are gone."""
    bundle = directory / f"{date_text}-daily.tar.gz"
    part = directory / f"{bundle.name}.part"
    index_name = f"{date_text}-daily.index"
    try:
        index = "".join(f"{_digest(path)}  {path.stat().st_size}  {path.name}\n" for path in members).encode()
        with tarfile.open(part, "w:gz") as archive:
            entry = tarfile.TarInfo(index_name)
            entry.size, entry.mtime, entry.mode = len(index), int(time.time()), 0o644
            archive.addfile(entry, io.BytesIO(index))
            for path in members:
                archive.add(str(path), arcname=path.name, recursive=False)
        with tarfile.open(part) as archive:
            listed = archive.getnames()
        if listed != [index_name] + [path.name for path in members]:
            raise OSError(f"bundle listing differs: {listed}")
        os.link(part, bundle)   # an existing bundle is never replaced
    except (OSError, tarfile.TarError):
        part.unlink(missing_ok=True)
        return False
    part.unlink(missing_ok=True)
    for path in members:
        path.unlink(missing_ok=True)
    return True


def archive_directory(directory: Union[str, Path], retain_days: int = RETAIN_DAYS,
                      now: Optional[datetime] = None) -> List[str]:
    """Apply the rule to one directory (a link is followed to its real directory); the lines to log."""
    real = Path(os.path.realpath(directory))
    if not real.is_dir():
        return []
    now = now or datetime.now(timezone.utc)
    today = now.strftime("%Y%m%d")
    cutoff = now - timedelta(days=retain_days)
    entries = sorted(real.iterdir())
    files = [path for path in entries if path.is_file() and not path.is_symlink()]
    lines = [f"[CLN] ── {directory} ──"]
    to_bundle = sum(1 for path in files if DATED.match(path.name) and not path.name.endswith(
        (".csv", "-daily.tar.gz", ".part")))
    csvs = sum(1 for path in files if path.name.endswith(".csv"))
    batches = [path for path in entries if path.is_dir() and not path.is_symlink()]
    lines.append(f"[CLN] found {to_bundle} file(s) to bundle + {csvs} csv + {len(batches)} batch dir(s)")

    # A successful collection is archived and its batch directory removed at once; the ones left are
    # failed or interrupted batches, kept for troubleshooting within the same window. Only exact
    # collector batch names are eligible; links and unrelated directories are never touched.
    for path in batches:
        if not BATCH_PREFIX.match(path.name):
            continue
        named = BATCH.match(path.name)
        if not named:
            lines.append(f"[CLN] WARN: unrelated directory retained: {path.name}")
            continue
        date = _day(named.group(1))
        if date is None:
            lines.append(f"[CLN] WARN: invalid batch date retained: {path.name}")
            continue
        if date < cutoff:
            try:
                shutil.rmtree(path)
                lines.append(f"[CLN] deleted stale batch directory {path.name} (> {retain_days} days old)")
            except OSError:
                lines.append(f"[CLN] WARN: could not delete stale batch directory {path.name}")

    # every date that still has files, daily bundles included (a day kept only as a bundle must leave too)
    dates = sorted({DATED.match(path.name).group(1) for path in files
                    if DATED.match(path.name) and not path.name.endswith(".part")})
    for date_text in dates:
        date = _day(date_text)
        if date is None:
            continue
        of_day = [path for path in files if path.name.startswith(date_text + "-") and not path.name.endswith(".part")]
        if date < cutoff:
            for path in of_day:
                path.unlink(missing_ok=True)
            lines.append(f"[CLN] deleted files for {date_text} (> {retain_days} days old)")
            continue
        if date_text == today:
            continue
        bundle = real / f"{date_text}-daily.tar.gz"
        loose = [path for path in of_day if path != bundle and not path.name.endswith(".csv")]
        if bundle.exists():
            if loose:
                lines.append(f"[CLN] {date_text}: 每日包已存在；{len(loose)} 个迟到文件留在包旁边，到期与每日包一起删除")
            else:
                lines.append(f"[CLN] {date_text}: daily bundle already exists, skipping")
            continue
        if not loose:
            continue
        if bundle_day(real, date_text, loose):
            lines.append(f"[CLN] {date_text}: bundled {len(loose)} file(s) → {bundle.name}")
        else:
            lines.append(f"[CLN] {date_text}: WARN bundle failed, originals kept")
    return lines


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Bundle and expire the dated files of collected-data directories.")
    parser.add_argument("directories", nargs="+", help="data directories (or links to them); missing ones are skipped")
    parser.add_argument("--retain-days", type=int, default=RETAIN_DAYS, help=f"days kept (default {RETAIN_DAYS})")
    args = parser.parse_args(argv)
    for directory in args.directories:
        for line in archive_directory(directory, args.retain_days):
            print(line, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
