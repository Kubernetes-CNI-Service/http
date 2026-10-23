"""Standard online Issue Tracker template (owner 2026-10-23) and an in-memory Sheets service for tests.

TEMPLATE holds only worksheet titles, the title row and the header row of every worksheet the template
defines (no data). FakeSheets answers the read calls the CableTracker engine makes against such a
document; writes never reach it (the format gate intercepts them), and any write that does is an error.
"""

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_PRECHECK = ROOT / "monitor/issue-tracker/format_precheck.py"

# Worksheets and header rows of the standard Issue Tracker template (owner 2026-10-23); timestamp title
# rows carry a fixed time. The engine must fill this format, never change it.
TEMPLATE = {
 "GPU Server": {
  "title": [
   "NVIDIA - GPU Server Issue Tracker"
  ],
  "headers": [
   "Issue#",
   "Submit Date",
   "Submitor",
   "Rack",
   "RU",
   "Host Name",
   "BMC IP",
   "SN",
   "Category",
   "Priority",
   "Issue Description",
   "Status",
   "Owner",
   "Action Description",
   "P-Status",
   "Replacement SN",
   "Replacement BMC MAC",
   "Remark \n(Partner)",
   "Remark\n(NV)"
  ]
 },
 "ETH&IB Switch": {
  "title": [
   "NVIDIA - ETH and IB Issue Tracker"
  ],
  "headers": [
   "Issue#",
   "Submit Date",
   "Submitor",
   "Rack",
   "RU",
   "Host Name",
   "OOB IP",
   "SN",
   "Model",
   "Fabric",
   "Priority",
   "Issue Description",
   "NVEX Case ID",
   "Status",
   "Owner",
   "Action Description",
   "P-Status",
   "Replacement SN",
   "Replacement ETH0 MAC",
   "Remark \n(Partner)",
   "Remark\n(NV)"
  ]
 },
 "ETH Cabling": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Fault ID",
   "Source",
   "Reported by",
   "Opened At",
   "Link Type",
   "Issue Type",
   "Issue Desc",
   "A-SU",
   "A-Rack",
   "A-RU",
   "A-Node",
   "A-Port",
   "A Actual Node",
   "A Actual Port",
   "Z-Rack",
   "Z-RU",
   "Z-Node",
   "Z-Port",
   "Z Actual Node",
   "Z Actual Port",
   "Status",
   "Notes",
   "AI Recommendation (Refer only)",
   "NV Comments",
   "Assigned to",
   "Engineer Assigned",
   "Action Description",
   "P-status",
   "CVT",
   "Closed At",
   "Instance"
  ]
 },
 "IB Cabling": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Fault ID",
   "Source",
   "Reported by",
   "Opened At",
   "Link Type",
   "Issue Type",
   "Issue Desc",
   "A-SU",
   "A-Rack",
   "A-RU",
   "A-Node",
   "A-Port",
   "A Actual Node",
   "A Actual Port",
   "Z-Rack",
   "Z-RU",
   "Z-Node",
   "Z-Port",
   "Z Actual Node",
   "Z Actual Port",
   "Status",
   "Notes",
   "AI Recommendation (Refer only)",
   "NV Comments",
   "Assigned to",
   "Engineer Assigned",
   "Action Description",
   "P-status",
   "CVT",
   "Closed At",
   "Instance"
  ]
 },
 "ETH Cabling_Bak": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Fault ID",
   "Source",
   "Reported by",
   "Opened At",
   "Link Type",
   "Issue Type",
   "Issue Desc",
   "A-SU",
   "A-Rack",
   "A-RU",
   "A-Node",
   "A-Port",
   "A Actual Node",
   "A Actual Port",
   "Z-Rack",
   "Z-RU",
   "Z-Node",
   "Z-Port",
   "Z Actual Node",
   "Z Actual Port",
   "Status",
   "Notes",
   "AI Recommendation (Refer only)",
   "NV Comments",
   "Assigned to",
   "Engineer Assigned",
   "Action Description",
   "P-status",
   "CVT",
   "Closed At",
   "CVT Instance"
  ]
 },
 "Inventory": {
  "title": [],
  "headers": [
   "Type",
   "Part No.",
   "HOSTNAME",
   "OS IP",
   "BMC IPMI IP",
   "BMC User",
   "Model",
   "IPMI MAC",
   "Server Serial No.",
   "Rack",
   "RU",
   "Row",
   "Floor"
  ]
 },
 "ServerProfile": {
  "title": [],
  "headers": [
   "ServerProfile",
   "PhysicalPort",
   "RDMAName",
   "CustomNICName",
   "NICOSName"
  ]
 },
 "PortProfile": {
  "title": [],
  "headers": [
   "Type",
   "Node Type",
   "PortName",
   "CustomNICName"
  ]
 },
 "CVT_SUM": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "CVT Instance",
   "A-SU",
   "Link Type",
   "Protocol",
   "Total",
   "Pass",
   "Fail - Link Down",
   "Fail - Mis-wiring",
   "Fail - Flapping",
   "Fail - Others",
   "Warning",
   "No Status",
   "Pass Rate"
  ]
 },
 "Cabling_Events": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Event Time",
   "Event Type",
   "Fault ID",
   "Instance",
   "Cabling Type",
   "A-SU",
   "Link Type",
   "Issue Type",
   "Source",
   "Open Count"
  ]
 },
 "CVT_Import_GS": {
  "title": [
   "Imported at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Circuit ID",
   "Status",
   "Status Cycles",
   "Protocol",
   "A SU Number",
   "A Rack",
   "A RU",
   "A Node Type",
   "A Node",
   "A Port",
   "A Custom NIC Name",
   "A RDMA Name",
   "A Actual Node",
   "A Actual Port",
   "A Port Status",
   "A Link Down Counter",
   "A Module Temperature (C)",
   "A Raw BER",
   "A Effective BER",
   "A Symbol BER",
   "A BER Status",
   "A RX Power Lanes (dBm)",
   "A TX Power Lanes (dBm)",
   "A RX Power Low Threshold",
   "A RX Power High Threshold",
   "A TX Power Low Threshold",
   "A TX Power High Threshold",
   "A Power Data Stale",
   "A Cable Serial",
   "A Cable PN",
   "A Report",
   "A Recommended Action",
   "Z SU Number",
   "Z Rack",
   "Z RU",
   "Z Node Type",
   "Z Node",
   "Z Port",
   "Z Custom NIC Name",
   "Z RDMA Name",
   "Z Actual Node",
   "Z Actual Port",
   "Z Port Status",
   "Z Link Down Counter",
   "Z Module Temperature (C)",
   "Z Raw BER",
   "Z Effective BER",
   "Z Symbol BER",
   "Z BER Status",
   "Z RX Power Lanes (dBm)",
   "Z TX Power Lanes (dBm)",
   "Z RX Power Low Threshold",
   "Z RX Power High Threshold",
   "Z TX Power Low Threshold",
   "Z TX Power High Threshold",
   "Z Power Data Stale",
   "Z Cable Serial",
   "Z Cable PN",
   "Z Report",
   "Z Recommended Action",
   "Last Update (UTC)",
   "Tracking Status",
   "Instance"
  ]
 },
 "LLDPQ_Import_GS": {
  "title": [
   "Imported at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Circuit ID",
   "Status",
   "Status Cycles",
   "Protocol",
   "A SU Number",
   "A Node Type",
   "A Node",
   "A Rack",
   "A Port",
   "A Custom NIC Name",
   "A RDMA Name",
   "A RU",
   "A Actual Node",
   "A Actual Port",
   "A Port Status",
   "A Cable Serial",
   "A Cable PN",
   "A Link Down Counter",
   "A Module Temperature (C)",
   "A RX Power Lanes (dBm)",
   "A TX Power Lanes (dBm)",
   "A RX Power Low Threshold",
   "A RX Power High Threshold",
   "A TX Power Low Threshold",
   "A TX Power High Threshold",
   "A Power Data Stale",
   "A Report",
   "A Recommended Action",
   "Z SU Number",
   "Z Node Type",
   "Z Node",
   "Z Rack",
   "Z Port",
   "Z Custom NIC Name",
   "Z RDMA Name",
   "Z RU",
   "Z Actual Node",
   "Z Actual Port",
   "Z Port Status",
   "Z Cable Serial",
   "Z Cable PN",
   "Z Link Down Counter",
   "Z Module Temperature (C)",
   "Z RX Power Lanes (dBm)",
   "Z TX Power Lanes (dBm)",
   "Z RX Power Low Threshold",
   "Z RX Power High Threshold",
   "Z TX Power Low Threshold",
   "Z TX Power High Threshold",
   "Z Power Data Stale",
   "Z Report",
   "Z Recommended Action",
   "Last Update (UTC)",
   "Source Line",
   "A Raw BER",
   "A Effective BER",
   "A Symbol BER",
   "A BER Status",
   "Z Raw BER",
   "Z Effective BER",
   "Z Symbol BER",
   "Z BER Status",
   "Tracking Status",
   "Instance"
  ]
 },
 "CVT_Import": {
  "title": [
   "Imported at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Circuit ID",
   "Status",
   "Status Cycles",
   "Protocol",
   "A SU Number",
   "A Rack",
   "A RU",
   "A Node Type",
   "A Node",
   "A Port",
   "A Custom NIC Name",
   "A RDMA Name",
   "A Actual Node",
   "A Actual Port",
   "A Port Status",
   "A Link Down Counter",
   "A Module Temperature (C)",
   "A Raw BER",
   "A Effective BER",
   "A Symbol BER",
   "A BER Status",
   "A RX Power Lanes (dBm)",
   "A TX Power Lanes (dBm)",
   "A RX Power Low Threshold",
   "A RX Power High Threshold",
   "A TX Power Low Threshold",
   "A TX Power High Threshold",
   "A Power Data Stale",
   "A Cable Serial",
   "A Cable PN",
   "A Report",
   "A Recommended Action",
   "Z SU Number",
   "Z Rack",
   "Z RU",
   "Z Node Type",
   "Z Node",
   "Z Port",
   "Z Custom NIC Name",
   "Z RDMA Name",
   "Z Actual Node",
   "Z Actual Port",
   "Z Port Status",
   "Z Link Down Counter",
   "Z Module Temperature (C)",
   "Z Raw BER",
   "Z Effective BER",
   "Z Symbol BER",
   "Z BER Status",
   "Z RX Power Lanes (dBm)",
   "Z TX Power Lanes (dBm)",
   "Z RX Power Low Threshold",
   "Z RX Power High Threshold",
   "Z TX Power Low Threshold",
   "Z TX Power High Threshold",
   "Z Power Data Stale",
   "Z Cable Serial",
   "Z Cable PN",
   "Z Report",
   "Z Recommended Action",
   "Last Update (UTC)",
   "Tracking Status",
   "CVT Instance"
  ]
 },
 "Agent_status": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Hostname",
   "IP",
   "Ping",
   "Agent Health",
   "Device Status",
   "JSON API",
   "Node Type",
   "Node OS",
   "DNS Resolved",
   "DNS Attempts",
   "DNS Last Attempt",
   "Last Updated (UTC)",
   "Time Since Update",
   "DH",
   "SU",
   "Rack",
   "RU",
   "Comment",
   "Instance"
  ]
 },
 "BCM_status": {
  "title": [
   "Updated at: 2026-10-23 21:21:00"
  ],
  "headers": [
   "Hostname",
   "Status",
   "Health Check Failed",
   "Health Check Unknown",
   "Provisioning Failed",
   "Restart Required",
   "CVT Instance"
  ]
 },
 "Whitelist": {
  "title": [],
  "headers": [
   "Submit Date",
   "Submitor",
   "Datahalll",
   "Instance",
   "Filter Type",
   "Filter"
  ]
 },
 "BasicData": {
  "title": [],
  "headers": [
   "Cable - NV Status",
   "Cable Team Status",
   "HW - NV Status",
   "HW Vendor Status",
   "Category",
   "Fabric",
   "Instance"
  ]
 }
}


def _parse_range():
    spec = importlib.util.spec_from_file_location("issue_tracker_template_precheck", _PRECHECK)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.parse_range


class _Request:
    def __init__(self, value):
        self._value = value

    def execute(self, *args, **kwargs):
        if isinstance(self._value, Exception):
            raise self._value
        return json.loads(json.dumps(self._value))


class FakeSheets:
    """Reads of a header-only document; titles map to sheet ids in template order."""

    def __init__(self, document: dict):
        self.document = document
        self.parse_range = _parse_range()
        self.reads = []

    def _rows(self, title):
        item = self.document[title]
        return ([item["title"]] if item["title"] else []) + [item["headers"]]

    def _slice(self, text):
        sheet, first_row, last_row, first_col, last_col = self.parse_range(text)
        title = next((name for name in self.document if name.casefold() == sheet.casefold()), None)
        if title is None:
            return []
        rows = self._rows(title)
        rows = rows[(first_row or 1) - 1:last_row]
        rows = [row[(first_col or 1) - 1:last_col] for row in rows]
        while rows and not any(rows[-1]):
            rows.pop()
        return rows

    def spreadsheets(self):
        return self

    def values(self):
        return self

    def get(self, spreadsheetId=None, range=None, **kwargs):
        if range is None:
            return _Request({"properties": {"title": "fake"}, "sheets": [
                {"properties": {"title": title, "sheetId": index + 1,
                                "gridProperties": {"rowCount": 1000, "columnCount": 64}}}
                for index, title in enumerate(self.document)]})
        self.reads.append(range)
        return _Request({"range": range, "values": self._slice(range)})

    def batchGet(self, spreadsheetId=None, ranges=(), **kwargs):
        return _Request({"valueRanges": [{"range": text, "values": self._slice(text)} for text in ranges]})

    def __getattr__(self, name):
        def write(**kwargs):
            return _Request(AssertionError(f"a write reached the document: {name}"))
        return write
