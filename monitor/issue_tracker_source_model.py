"""Source-neutral Issue Tracker business DATA, not qualification or send authority.

Collectors and future external-source adapters share these values. Neither
online row coordinates nor credentials, permits or completion state belong
here. Workbook projectors validate business values; protected callers retain
source qualification, K/N, whitelist and local-commit responsibilities.
"""

from __future__ import annotations

from dataclasses import dataclass


PANEL_SHEETS = {
    "Switch Status": ("ETH&IB Switch", "switch"),
    "Eth Link Validation": ("ETH Cabling", "eth_cabling"),
    "IB Link Validation": ("IB Cabling", "ib_cabling"),
}


@dataclass(frozen=True)
class CablingSourceRow:
    """Typed source values for a pure image; qualification belongs to the caller."""

    sheet: str
    activity_key: tuple[str, str, str, str]
    expected_endpoints: tuple[str, str, str, str]
    actual_endpoints: tuple[str, str, str, str] | tuple[()]
    source_status: str
    evidence_description: str
    recorded_at_utc: str


@dataclass(frozen=True)
class SwitchSourceWorkbookRow:
    """Typed Switch values; this image helper never grants commit authority."""

    activity_key: tuple[str, str, str, str]
    evidence_description: str
    fabric: str
    fabric_source: str
    priority: str
    recorded_at_utc: str


@dataclass(frozen=True)
class TrackerChanges:
    """Immutable values shared by local and online projections, never a permit.

    Actions/row coordinates are determined independently against each current
    destination. A future CVT adapter may construct this model, but no external
    source fetcher or trust/qualification shortcut is installed here.
    """

    cabling: tuple[CablingSourceRow, ...]
    switch: tuple[SwitchSourceWorkbookRow, ...]

    def __post_init__(self):
        if (type(self.cabling) is not tuple or type(self.switch) is not tuple
                or any(type(row) is not CablingSourceRow for row in self.cabling)
                or any(type(row) is not SwitchSourceWorkbookRow for row in self.switch)):
            raise ValueError("invalid_issue_tracker_change_values")
