"""
Parser for ibdiagnet2.db_csv — a multi-section CSV database file.

Each section is delimited by START_<NAME> / END_<NAME> lines.
"""

from __future__ import annotations

import functools
import re
from io import StringIO
from pathlib import Path

import pandas as pd

# Matches "START_<NAME>" at start of line; captures the section name.
_SECTION_RE = re.compile(r"^START_(.+)$", re.MULTILINE)


@functools.lru_cache(maxsize=4)
def _read_db_csv(path: Path) -> str:
    """Read and cache the full text of a db_csv file (one read per unique path)."""
    return path.read_text(encoding="utf-8", errors="replace")


def extract_section(section_name: str, db_csv_path: Path) -> pd.DataFrame:
    """Return the CSV table between START_<section_name> and END_<section_name>.

    Tries three strategies in order:
    1. Standard format:  START_<name> … END_<name>
    2. No-prefix format: <name>       … END_<name>  (some ibdiagnet versions omit START_)
    3. Truncated header: scans backwards from END_<name> for the last standalone
       ALL-CAPS line — handles files where the header prefix was corrupted/truncated
       (e.g. XDR ibdiagnet2.db_csv where CABLE_INFO appears as "_INFO").

    Returns an empty DataFrame if the section is absent or has no data rows.
    """
    text = _read_db_csv(db_csv_path)

    body: str | None = None

    # Strategies 1 & 2: standard and bare section headers.
    for prefix in (f"START_{section_name}", section_name):
        m = re.search(
            rf"^{re.escape(prefix)}\n(.*?)^END_{re.escape(section_name)}",
            text,
            re.MULTILINE | re.DOTALL,
        )
        if m:
            body = m.group(1)
            break

    # Strategy 3: truncated header fallback.
    if body is None:
        end_m = re.search(rf"^END_{re.escape(section_name)}", text, re.MULTILINE)
        if end_m:
            body_end = end_m.start()
            # Scan up to 50 MB before END_<name> for a standalone section-header line
            # (all uppercase letters, digits, underscores — on its own line).
            window = text[max(0, body_end - 50_000_000) : body_end]
            hdrs = list(re.finditer(r"^[A-Z_][A-Z0-9_]*\s*$", window, re.MULTILINE))
            if hdrs:
                body = window[hdrs[-1].end() :]

    if body is None:
        return pd.DataFrame()

    body = body.strip()
    if not body:
        return pd.DataFrame()

    try:
        df = pd.read_csv(
            StringIO(body),
            dtype=str,
            keep_default_na=False,
        )
    except Exception:
        return pd.DataFrame()

    # Strip surrounding whitespace from column names and string values.
    df.columns = [c.strip() for c in df.columns]
    for col in df.select_dtypes(include=["object", "string"]):
        df[col] = df[col].str.strip()

    return df


def list_sections(db_csv_path: Path) -> list[str]:
    """Return all section names present in the file (useful for diagnostics).

    Includes sections with START_X headers and bare sections that only have END_X.
    """
    text = _read_db_csv(db_csv_path)
    names = set(_SECTION_RE.findall(text))
    for end_name in re.findall(r"^END_(.+)$", text, re.MULTILINE):
        names.add(end_name)
    return sorted(names)


def is_xdr(ibdiagnet_dir: Path) -> bool:
    """Return True if the ibdiagnet folder contains ibdiagnet2.aports (XDR/multi-plane fabric)."""
    return (ibdiagnet_dir / "ibdiagnet2.aports").exists()
