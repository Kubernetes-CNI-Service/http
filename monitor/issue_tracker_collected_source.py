"""Pure self-collected Stage-L values → common Issue Tracker model adapter.

    This does not read devices, qualify candidates, commit an XLSX, read Cloud
    or grant network authority. In particular candidate.qualified is not a
    permit. The C5/C6 protected caller still requalifies the original sources.
"""

from monitor.issue_tracker_local_commit import LocalCommitHold
from monitor.issue_tracker_source_model import (
    CablingSourceRow, PANEL_SHEETS, SwitchSourceWorkbookRow, TrackerChanges,
)


def collected_changes(candidates, *, selected_panel=None):
    """Adapt existing three-panel data without a second workbook/sync engine."""
    if selected_panel is not None and selected_panel not in PANEL_SHEETS:
        raise LocalCommitHold("C6 selected panel is invalid")
    cabling = []
    switch = []
    for candidate in candidates:
        expected = next((name for name, (_, family) in PANEL_SHEETS.items()
                         if family == candidate.activity_key[0]), None)
        if expected is None or candidate.panel != expected:
            raise LocalCommitHold("C6 candidate panel differs from source family")
        # Validate family/panel before selection so a broken other-panel
        # candidate cannot be silently hidden by a manual selection.
        if selected_panel is not None and candidate.panel != selected_panel:
            continue
        if candidate.panel in {"Eth Link Validation", "IB Link Validation"}:
            sheet = PANEL_SHEETS[candidate.panel][0]
            actual = (() if sheet == "IB Cabling" and candidate.source_status == "Link Down"
                      else candidate.actual_endpoints)
            cabling.append(CablingSourceRow(
                sheet=sheet, activity_key=candidate.activity_key,
                expected_endpoints=candidate.expected_endpoints,
                actual_endpoints=actual, source_status=candidate.source_status,
                evidence_description=candidate.evidence_description,
                recorded_at_utc=candidate.recorded_at_utc,
            ))
        else:
            switch.append(SwitchSourceWorkbookRow(
                activity_key=candidate.activity_key,
                evidence_description=candidate.evidence_description,
                fabric=candidate.fabric, fabric_source=candidate.fabric_source,
                priority="P2", recorded_at_utc=candidate.recorded_at_utc,
            ))
    return TrackerChanges(tuple(cabling), tuple(switch))
