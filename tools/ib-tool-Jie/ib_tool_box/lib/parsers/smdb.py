"""Parser for OpenSM smdb files (`opensm-smdb.dump`).

Format: multi-section, `START_<NAME> / END_<NAME>` delimited, comma-separated
values with space padding around values. Same top-level shape as
`ibdiagnet2.db_csv`, so the underlying `extract_section()` from `db_csv.py`
already handles both quirks (column names are stripped via list comprehension;
string values are `.str.strip()`-ed). This module is a thin semantic wrapper
so callers can import from a file-type-specific namespace.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from lib.parsers.db_csv import extract_section as _extract_section


def extract_section(section_name: str, smdb_path: Path) -> pd.DataFrame:
    """Return the smdb section body as a DataFrame.

    Ignored sections: `INDEX_TABLE` (diagnostic only), `AN2AN` (SHARP routing,
    out of scope for health-check), `CHAINS` (typically empty).

    Section names used by `parse_ib_smdb.py`:
        SM, SMS, SM_PORTS, NODES, SWITCHES, PORTS, LINKS
    """
    return _extract_section(section_name, Path(smdb_path))
