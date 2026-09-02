"""Shared CLI-summary and Excel-writing helpers used by all scripts.

Centralises formatting that previously appeared (with minor variations) in
each `scripts/*.py` file: section dividers, label/count lines, label/text
lines, and the conditional sheet-write loop for xlsxwriter workbooks.

All scripts use a 60-char divider and right-aligned counts. Two label widths
are used: 44 chars for count-based lines (most sections), and 30 chars for
sections with long string values (e.g. SM Version, Master Start Time).
"""

from __future__ import annotations

from typing import Iterable, Sequence

import pandas as pd
import xlsxwriter

from lib.excel import write_dataframe


# ─── Constants ───────────────────────────────────────────────────────────────

LINE_W = 60
SEP = "─" * LINE_W
LBL_W = 44          # default label-column width for count-based lines
LBL_W_NARROW = 30   # narrow label width for text-value lines (SM section, etc.)
CNT_W = 7           # right-aligned count field


# ─── Section headers ─────────────────────────────────────────────────────────


def section(title: str, total: int | None = None) -> None:
    """Print a section header bracketed by `─`-lines.

    With `total=None`:
        ────…
          Title
        ────…

    With `total=N`:
        ────…
          Title                                      Total:       N
        ────…
    """
    print(f"\n{SEP}")
    if total is None:
        print(f"  {title}")
    else:
        hdr = f"  {title}"
        right = f"Total: {total:>{CNT_W}}"
        pad = " " * max(1, LINE_W - len(hdr) - len(right))
        print(f"{hdr}{pad}{right}")
    print(SEP)


# ─── Body lines ──────────────────────────────────────────────────────────────


def count_line(
    label: str, count: int, *, lbl_w: int = LBL_W, indent: int = 4,
) -> None:
    """Print a label + right-aligned count line.

    `'    Label                                          :       N'`

    `lbl_w` is the *label-area* width including the indent; defaults to 44.
    `indent` controls leading spaces (4 by default; pass 8 for nested stanzas).
    """
    right = f": {count:>{CNT_W}}"
    left = f"{' ' * indent}{label}"
    pad = " " * max(1, LINE_W - len(left) - len(right))
    print(f"{left}{pad}{right}")


def text_line(label: str, value: str, *, lbl_w: int = LBL_W_NARROW) -> None:
    """Print a label + free-text value line, with narrow label width.

    `'    Label                : <value>'`

    Used by the SM section to fit long values like `OpenSM 5.19.1_56393c9`
    or `2026 Jan 30 19:06:12:193215` without wrapping.
    """
    print(f"    {label:<{lbl_w - 4}}: {value}")


# ─── Histogram (bin-distribution table) ──────────────────────────────────────

# Layout constants — every right edge lands on column LINE_W = 60, matching
# `count_line()` output (where the right-aligned count's last digit also lands
# on col LINE_W). Numeric columns line up across all sections.
HIST_INDENT = 4
HIST_BIN_LABEL_W = 10        # "40 – 50 °C" → 10 visible chars
HIST_COL_W = 11              # numeric columns: 11 chars wide each, right-aligned


def histogram_table(
    headers: list[str],
    rows: list[tuple[str, list[int | str]]],
    *,
    indent: int = HIST_INDENT,
) -> None:
    """Render a tabular histogram block.

    Args:
        headers: column header labels (excluding the Bin column). Pass `[]` to
                 skip the header row — used for single-column histograms where
                 only bin/qty pairs are emitted.
                 Examples:
                   `['Current', 'Max']` for single-snapshot Switch (n=2),
                   `['Cur X', 'Cur Y', 'Max X', 'Max Y']` for compare Switch (n=4),
                   `['X', 'Y']` for compare HCA / Transceiver (n=2),
                   `[]` for single-snapshot HCA / Transceiver (n=1, headerless).
        rows: list of `(bin_label, [qty, …])`. The qty list length defines `n`
              when `headers` is empty.

    Right edges of all numeric columns land on column `LINE_W = 60`, matching
    the `count_line()` convention so values line up with the surrounding
    `Snapshot X` / `Snapshot Y` lines.
    """
    if not rows:
        return
    n = len(headers) if headers else len(rows[0][1])
    bin_area_w = LINE_W - HIST_COL_W * n - indent
    pad = " " * indent

    if headers:
        parts = [pad, f"{'Bin':<{bin_area_w}}"]
        for h in headers:
            parts.append(f"{h:>{HIST_COL_W}}")
        print("".join(parts))

    for bin_label, qtys in rows:
        if len(qtys) != n:
            raise ValueError(f"row '{bin_label}': {len(qtys)} qtys for {n} columns")
        line = [pad, f"{bin_label:<{bin_area_w}}"]
        for q in qtys:
            line.append(f"{q:>{HIST_COL_W}}")
        print("".join(line))


# ─── Excel sheet writing ─────────────────────────────────────────────────────


SheetSpec = tuple[str, pd.DataFrame, bool]
"""(sheet_name, dataframe, write_when_empty)."""


def write_sheets(
    workbook: xlsxwriter.Workbook,
    specs: Sequence[SheetSpec] | Iterable[SheetSpec],
) -> None:
    """Write each `(sheet_name, df, write_when_empty)` spec to the workbook.

    - If `write_when_empty` is False, sheets whose DataFrame is empty are skipped.
    - If True, the sheet is always written (with just the header row if empty).
    - Sheet name is truncated to 31 chars by `write_dataframe()`.
    """
    for name, df, allow_empty in specs:
        if df is None or df.empty:
            if not allow_empty:
                continue
            df = df if df is not None else pd.DataFrame()
        write_dataframe(workbook, name, df)
