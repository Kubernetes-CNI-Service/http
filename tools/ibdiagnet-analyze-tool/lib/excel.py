"""
Shared xlsxwriter helpers for IB health check scripts.
"""

from __future__ import annotations

import xlsxwriter
import pandas as pd


def _col_width(series: pd.Series, header: str, max_width: int = 50) -> int:
    """Estimate a reasonable column width from header length and data."""
    raw_max = series.astype(str).str.len().max() if not series.empty else 0
    data_max = 0 if (raw_max is None or (not isinstance(raw_max, int) and pd.isna(raw_max))) else raw_max
    return min(max(len(header) + 2, int(data_max) + 2, 8), max_width)


def write_dataframe(
    workbook: xlsxwriter.Workbook,
    sheet_name: str,
    df: pd.DataFrame,
    header_format=None,
    freeze_row: bool = True,
) -> None:
    """Write a DataFrame to a new worksheet with auto-sized columns."""
    ws = workbook.add_worksheet(sheet_name[:31])  # Excel sheet name limit

    if header_format is None:
        header_format = workbook.add_format({
            "bold": True,
            "bg_color": "#76B900",
            "font_color": "#FFFFFF",
            "border": 1,
        })

    cell_format = workbook.add_format({"border": 1})

    for col_idx, col_name in enumerate(df.columns):
        ws.write(0, col_idx, col_name, header_format)
        width = _col_width(df[col_name], col_name)
        ws.set_column(col_idx, col_idx, width)

    for row_idx, row in enumerate(df.itertuples(index=False), start=1):
        for col_idx, val in enumerate(row):
            ws.write(row_idx, col_idx, val if pd.notna(val) else "", cell_format)

    if freeze_row:
        ws.freeze_panes(1, 0)


def write_pivot(
    workbook: xlsxwriter.Workbook,
    sheet_name: str,
    df: pd.DataFrame,
    index_col: str,
    columns_col: str,
    title: str | None = None,
) -> None:
    """Write a pivot table (index × columns → count) to a new worksheet."""
    if df.empty:
        return

    pivot = pd.pivot_table(
        df.fillna("N/A"),
        index=index_col,
        columns=columns_col,
        aggfunc="size",
        fill_value=0,
    )

    ws = workbook.add_worksheet(sheet_name[:31])

    title_fmt = workbook.add_format({"bold": True, "font_size": 12})
    header_fmt = workbook.add_format({
        "bold": True, "bg_color": "#76B900", "font_color": "#FFFFFF", "border": 1,
    })
    index_fmt = workbook.add_format({"bold": True, "border": 1})
    cell_fmt = workbook.add_format({"border": 1})
    total_fmt = workbook.add_format({"bold": True, "bg_color": "#D9D9D9", "border": 1})

    row = 0
    if title:
        ws.write(row, 0, title, title_fmt)
        row += 1

    # Header: blank corner + column labels
    ws.write(row, 0, index_col, header_fmt)
    ws.write(row, 1, "Total", header_fmt)
    for ci, col_val in enumerate(pivot.columns, start=2):
        ws.write(row, ci, str(col_val), header_fmt)
    row += 1

    for idx_val in pivot.index:
        ws.write(row, 0, idx_val, index_fmt)
        row_total = int(pivot.loc[idx_val].sum())
        ws.write(row, 1, row_total, cell_fmt)
        for ci, col_val in enumerate(pivot.columns, start=2):
            ws.write(row, ci, int(pivot.loc[idx_val, col_val]), cell_fmt)
        row += 1

    # Totals row
    ws.write(row, 0, "Total", total_fmt)
    ws.write(row, 1, int(pivot.values.sum()), total_fmt)
    for ci in range(len(pivot.columns)):
        ws.write(row, ci + 2, int(pivot.iloc[:, ci].sum()), total_fmt)

    ws.set_column(0, 0, 30)
    ws.set_column(1, 1 + len(pivot.columns), 15)
    ws.freeze_panes(row_start := (1 if title else 0) + 1, 0)


def write_psu_pivot(
    workbook: xlsxwriter.Workbook,
    sheet_name: str,
    df: pd.DataFrame,
) -> None:
    """Write PSU pivot: Part Number × (Total / Good / Bad) counts."""
    if df.empty:
        return

    ws = workbook.add_worksheet(sheet_name[:31])
    header_fmt = workbook.add_format({
        "bold": True, "bg_color": "#76B900", "font_color": "#FFFFFF", "border": 1,
    })
    cell_fmt = workbook.add_format({"border": 1})
    total_fmt = workbook.add_format({"bold": True, "bg_color": "#D9D9D9", "border": 1})

    ws.write(0, 0, "Part Number", header_fmt)
    ws.write(0, 1, "Total PSU", header_fmt)
    ws.write(0, 2, "Good PSU", header_fmt)
    ws.write(0, 3, "Bad PSU", header_fmt)

    present = df[df["PSU Present"] == "Yes"]
    good = present[(present["PSU DC State"] == "OK") & (present["PSU Fan State"] == "OK")]
    bad = present[~((present["PSU DC State"] == "OK") & (present["PSU Fan State"] == "OK"))]

    parts = sorted(present["Part Number"].fillna("N/A").unique())
    for ri, pn in enumerate(parts, start=1):
        total = int((present["Part Number"] == pn).sum())
        g = int(((good["Part Number"] == pn)).sum())
        b = int(((bad["Part Number"] == pn)).sum())
        ws.write(ri, 0, pn, cell_fmt)
        ws.write(ri, 1, total, cell_fmt)
        ws.write(ri, 2, g, cell_fmt)
        ws.write(ri, 3, b, cell_fmt)

    last = len(parts) + 1
    ws.write(last, 0, "Total", total_fmt)
    ws.write(last, 1, len(present), total_fmt)
    ws.write(last, 2, len(good), total_fmt)
    ws.write(last, 3, len(bad), total_fmt)

    ws.set_column(0, 0, 30)
    ws.set_column(1, 3, 12)
    ws.freeze_panes(1, 0)


def write_temp_histogram(
    workbook: xlsxwriter.Workbook,
    sheet_name: str,
    hist_df: pd.DataFrame,
    title: str,
    value_cols: list[str],
) -> None:
    """Write a temperature-distribution sheet: bin table + embedded column chart.

    Args:
        hist_df: DataFrame with `Bin Label` plus one column per name in
                 `value_cols`. Each value column holds Qty per bin.
        title:   Chart title (e.g. ``Switch Temperature Distribution``).
        value_cols: list of Qty column names in the order they should appear
                    as chart series. E.g. ``["Current", "Max"]`` for single-
                    snapshot Switch, ``["X", "Y"]`` for compare HCA, or
                    ``["Qty"]`` for single-column populations.

    The chart is anchored two columns past the table for readability.
    """
    if hist_df is None or hist_df.empty:
        return

    ws = workbook.add_worksheet(sheet_name[:31])
    header_fmt = workbook.add_format({
        "bold": True, "bg_color": "#76B900", "font_color": "#FFFFFF", "border": 1,
    })
    cell_fmt = workbook.add_format({"border": 1})

    cols = ["Bin Label"] + value_cols
    for ci, name in enumerate(cols):
        ws.write(0, ci, name, header_fmt)
    for ri in range(len(hist_df)):
        ws.write(ri + 1, 0, hist_df.iloc[ri]["Bin Label"], cell_fmt)
        for ci, name in enumerate(value_cols, start=1):
            ws.write(ri + 1, ci, int(hist_df.iloc[ri][name]), cell_fmt)

    ws.set_column(0, 0, 18)
    ws.set_column(1, len(cols) - 1, 12)
    ws.freeze_panes(1, 0)

    n_rows = len(hist_df)
    chart = workbook.add_chart({"type": "column"})
    for ci, name in enumerate(value_cols, start=1):
        chart.add_series({
            "name":       [sheet_name[:31], 0, ci],
            "categories": [sheet_name[:31], 1, 0, n_rows, 0],
            "values":     [sheet_name[:31], 1, ci, n_rows, ci],
        })
    chart.set_title({"name": title})
    chart.set_x_axis({"name": "Temperature bin"})
    chart.set_y_axis({"name": "Count"})
    chart.set_legend({"position": "bottom"})
    chart.set_size({"width": 540, "height": 320})

    # Anchor chart two columns past the last data column.
    anchor_col = len(cols) + 1
    ws.insert_chart(0, anchor_col, chart)
