#!/usr/bin/env python3
"""Size-based log rotation shared by every script that writes a log (owner 2026-10-22: whoever writes a
log rotates it; one module does the work).

A log that has reached MAX_BYTES is compressed to <log>.1.gz and emptied in place: its writers append
(crontab `>>`, the page generator, the switch-collection worker started by 11-load.py), so they keep
writing to the same file. Older copies shift up (.1.gz -> .2.gz ...) and at most KEEP are kept. A log
reached through a setup link is rotated where the real file is, and the copies sit beside it.

    python3 tools/log_rotation.py [--max-bytes N] [--keep N] <log>

prints one line when it rotated, nothing when the log is still small, and exits non-zero (the log kept
as it was) when the copy cannot be written.
"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import sys
from pathlib import Path
from typing import Optional, Union

MAX_BYTES = 10 * 1024 * 1024
KEEP = 7


def rotate(path: Union[str, Path], max_bytes: int = MAX_BYTES, keep: int = KEEP) -> Optional[str]:
    """Rotate `path` when it has reached `max_bytes`; the message to log, or None when nothing was done.
    Raises OSError when the compressed copy cannot be written; the log is then left as it was."""
    real = Path(os.path.realpath(path))
    if not real.is_file():
        return None
    size = real.stat().st_size
    if size < max_bytes:
        return None
    copy = real.with_name(f"{real.name}.1.gz")
    part = real.with_name(f"{real.name}.1.gz.part")
    try:
        with real.open("rb") as source, gzip.open(part, "wb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
    except OSError:
        part.unlink(missing_ok=True)
        raise
    real.with_name(f"{real.name}.{keep}.gz").unlink(missing_ok=True)
    for number in range(keep - 1, 0, -1):
        older = real.with_name(f"{real.name}.{number}.gz")
        if older.is_file():
            older.replace(real.with_name(f"{real.name}.{number + 1}.gz"))
    part.replace(copy)
    with real.open("r+b") as handle:
        handle.truncate(0)
    return f"{real.name} 达到 {size} 字节：已压缩为 {copy.name}（最多保留 {keep} 个）"


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Compress a log that reached its size limit and empty it in place.")
    parser.add_argument("log", help="the log file (or a link to it)")
    parser.add_argument("--max-bytes", type=int, default=MAX_BYTES, help=f"size limit (default {MAX_BYTES})")
    parser.add_argument("--keep", type=int, default=KEEP, help=f"compressed copies kept (default {KEEP})")
    args = parser.parse_args(argv)
    try:
        message = rotate(args.log, args.max_bytes, args.keep)
    except OSError as exc:
        print(f"{Path(args.log).name} 压缩失败，原文件保留: {exc}", file=sys.stderr)
        return 1
    if message:
        print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
