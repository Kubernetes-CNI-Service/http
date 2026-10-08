"""Independent G1 visible budget accounting; no online enrollment/permission."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_req7_sheets_read_plan as plans

TARGET = "synthetic_spreadsheet_id_0001"
FIELDS = "matchedDeveloperMetadata(developerMetadata(metadataId,metadataKey,metadataValue,location,visibility))"
BODY = b'{"dataFilters":[{"developerMetadataLookup":{}}]}'


def load():
    from test_req7_sheets_read_decode import load as decoder
    decoder()
    path = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_metadata_capacity.py"
    if not path.is_file(): raise AssertionError("REQ7 permanent-fence budget observer missing")
    from test_cases.test_req7_history_read import load as canonical_loader
    return canonical_loader('issue_tracker_metadata_capacity',path=path)


def entry(identifier, key="z", value="1", *, sheet=101, visibility="DOCUMENT"):
    location = {"locationType": "SPREADSHEET", "spreadsheet": True} if sheet is None else {
        "locationType": "SHEET", "sheetId": sheet}
    return {"metadataId": identifier, "metadataKey": key, "metadataValue": value,
            "location": location, "visibility": visibility}


def reply(entries=()):
    value = {"matchedDeveloperMetadata": [{"developerMetadata": item} for item in entries]} if entries else {}
    # Escaped invalid Unicode must reach the product decoder, not fail in the fixture.
    return SimpleNamespace(status=200, complete=True, data=json.dumps(value, ensure_ascii=True).encode())


class Req7MetadataCapacityDirectTests(unittest.TestCase):
    def setUp(self):
        plans.Req7SheetsReadPlanDirectTests.setUp(self)
        self.planner = self.module; self.module = load()
        from test_req7_sheets_read_decode import identity_response, response
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        self.identity = decode_template_identity(self.planner.prepare_template_identity_read(self.binding, self.token),
                                                 response(identity_response()))

    def plan(self): return self.module.prepare_metadata_capacity_read(self.binding, self.token)

    def observe(self, entries=(), reservations=(), response=None):
        return self.module.observe_metadata_capacity(self.plan(), response or reply(entries), self.identity,
                                                     reservations=reservations)

    def test_fixed_search_reads_all_visible_locations_without_caller_query_or_mutation(self):
        with mock.patch("socket.socket", side_effect=AssertionError("pure plan must not connect")):
            plan = self.plan()
        self.assertEqual("sheets.googleapis.com", plan.host); self.assertEqual("POST", plan.method)
        self.assertEqual("/v4/spreadsheets/" + TARGET + "/developerMetadata:search", urlsplit(plan.path).path)
        self.assertEqual({"fields": [FIELDS]}, parse_qs(urlsplit(plan.path).query))
        self.assertEqual(BODY, plan.body); self.assertEqual(30.0, plan.budget_seconds)
        self.assertNotIn(self.token.value, repr(plan)); self.assertFalse(hasattr(plan, "permit"))

    def test_empty_visible_inventory_is_not_global_capacity_proof_or_send_permission(self):
        value = self.observe()
        self.assertEqual("VISIBLE_ONLY_UNPROVED", value.outcome)
        self.assertEqual((None, 0, 0, 30000), value.pools[0])
        self.assertEqual(15, len(value.pools)); self.assertFalse(value.inventory_complete)
        self.assertFalse(hasattr(value, "permit")); self.assertFalse(hasattr(value, "receipt"))
        with self.assertRaises(FrozenInstanceError): value.inventory_complete = True

    def test_all_visible_metadata_enrollment_foreign_and_outstanding_reservations_are_charged(self):
        entries = (entry(1), entry(2, "nonce", "abc"), entry(3, "other", "xyz", sheet=None),
                   entry(4, "foreign", "project", sheet=102, visibility="PROJECT"))
        reserves = (entry(5), entry(6, "nonce", "history", sheet=105))
        value = self.observe(entries, reserves)
        pools = {row[0]: row[1:] for row in value.pools}
        self.assertEqual((8, 0, 29992), pools[None]); self.assertEqual((10, 2, 29988), pools[101])
        self.assertEqual((14, 0, 29986), pools[102]); self.assertEqual((0, 12, 29988), pools[105])
        self.assertEqual(2, value.outstanding_reservations)
        self.assertEqual(hashlib.sha256(reply(entries).data).hexdigest(), value.source_sha256)
        self.assertNotIn("history", repr(value))

    def test_row_and_column_metadata_are_charged_to_their_sheet_not_spreadsheet_pool(self):
        row = entry(1, "row", "value"); row["location"] = {"locationType": "ROW", "dimensionRange": {
            "sheetId": 101, "dimension": "ROWS", "startIndex": 3, "endIndex": 4}}
        column = entry(2, "col", "value"); column["location"] = {"locationType": "COLUMN", "dimensionRange": {
            "sheetId": 102, "dimension": "COLUMNS", "startIndex": 0, "endIndex": 1}}
        pools = {row[0]: row[1:] for row in self.observe((row, column)).pools}
        self.assertEqual((8, 0, 29992), pools[101]); self.assertEqual((8, 0, 29992), pools[102])
        self.assertEqual((0, 0, 30000), pools[None])

    def test_per_sheet_limit_is_not_shared_global_limit_and_overflow_stops_before_sends(self):
        entries = (entry(1, "k", "x" * 29997), entry(2, "k", "x" * 29999, sheet=102))
        self.assertEqual("VISIBLE_ONLY_UNPROVED", self.observe(entries, (entry(3),)).outcome)
        overflow = self.observe(entries, (entry(3), entry(4)))
        self.assertEqual("STOP_CAPACITY", overflow.outcome)
        self.assertEqual((101, 29998, 4, -2), next(row for row in overflow.pools if row[0] == 101))
        self.assertEqual("STOP_CAPACITY", self.observe((entry(1, "k", "x" * 30000, sheet=None),)).outcome)

    def test_utf8_count_is_explicit_conservative_representation_not_empty_pool_lifetime_promise(self):
        value = self.observe((entry(1, "é", "😀"),))
        self.assertEqual("utf8_bytes_conservative", value.counting)
        self.assertEqual((101, 6, 0, 29994), next(row for row in value.pools if row[0] == 101))
        self.assertFalse(hasattr(value, "days_remaining"))

    def test_matching_observed_id_does_not_duplicate_capacity_or_clear_outstanding_reservation(self):
        fence = entry(1)
        value = self.observe((fence,), (deepcopy(fence),))
        self.assertEqual((101, 2, 0, 29998), next(row for row in value.pools if row[0] == 101))
        self.assertEqual(1, value.outstanding_reservations); self.assertFalse(value.inventory_complete)
        changed = entry(1, value="2")
        with self.assertRaises(self.module.MetadataCapacityHold): self.observe((fence,), (changed,))

    def test_duplicate_ids_and_invalid_locations_types_or_visibility_never_silently_drop(self):
        cases = [(entry(1), entry(1))]
        for key, value in (("metadataId", True), ("metadataId", 0), ("metadataId", -1),
                           ("metadataId", 2147483648), ("metadataKey", ""), ("metadataKey", True),
                           ("metadataValue", 7), ("metadataValue", "\ud800"), ("visibility", "PRIVATE"),
                           ("location", {"locationType": "SHEET", "sheetId": 999}),
                           ("location", {"locationType": "SHEET", "sheetId": True}),
                           ("location", {"locationType": "SHEET", "sheetId": 101, "spreadsheet": True}),
                           ("location", {"locationType": "ROW", "dimensionRange": {
                               "sheetId": 101, "dimension": "ROWS", "startIndex": 3, "endIndex": 5}})):
            item = entry(1); item[key] = value; cases.append((item,))
        for items in cases:
            with self.subTest(items=items), self.assertRaises(self.module.MetadataCapacityHold) as caught:
                self.observe(items)
            self.assertEqual("req7_metadata_capacity_unproved", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)

    def test_incomplete_non200_duplicate_json_oversize_and_foreign_plan_are_denied(self):
        raw = reply((entry(1),))
        cases = [SimpleNamespace(status=200, complete=False, data=raw.data),
                 SimpleNamespace(status=503, complete=True, data=raw.data),
                 SimpleNamespace(status=True, complete=True, data=raw.data),
                 SimpleNamespace(status=200, complete=True, data=b'{"matchedDeveloperMetadata":[],"matchedDeveloperMetadata":[]}'),
                 SimpleNamespace(status=200, complete=True, data=b" " * (2 * 1024 * 1024 + 1)),
                 SimpleNamespace(status=200, complete=True, data=b'{"extra":[]}')]
        for response in cases:
            with self.assertRaises(self.module.MetadataCapacityHold): self.observe(response=response)
        plan = self.plan()
        for changed in (replace(plan, body=b"{}"), replace(plan, method="GET"), replace(plan, path=plan.path + "&ranges=A1"),
                        replace(plan, budget_seconds=60.0), replace(plan, host="evil.example")):
            with self.assertRaises(self.module.MetadataCapacityHold):
                self.module.observe_metadata_capacity(changed, raw, self.identity, reservations=())
        with self.assertRaises(self.module.MetadataCapacityHold):
            self.module.observe_metadata_capacity(plan, raw, replace(self.identity, spreadsheet_id="foreign_spreadsheet_00002"), reservations=())

    def test_retained_reservations_are_explicit_bounded_never_mutated_or_reclaimed(self):
        reservations = (entry(1),)
        before = deepcopy(reservations)
        self.observe(reservations=reservations); self.assertEqual(before, reservations)
        for invalid in ([entry(1)], (entry(1), entry(1)), (entry(1),) * 15001):
            with self.assertRaises(self.module.MetadataCapacityHold): self.observe(reservations=invalid)

    def test_forged_padding_cannot_bypass_the_fixed_private_token_header_byte_bound(self):
        plan = self.plan()
        valid = replace(plan, headers=(plan.headers[0], ("Authorization", "Bearer " + "A" * 8191 + "="), plan.headers[2]))
        self.assertEqual(TARGET, self.module._validate_plan(valid))
        for token in ("A" + "=" * 8192, "A" * 8192 + "=" * 8192):
            changed = replace(plan, headers=(plan.headers[0], ("Authorization", "Bearer " + token), plan.headers[2]))
            with self.assertRaises(self.module.MetadataCapacityHold): self.module._validate_plan(changed)


class Req7MetadataCapacityNativeWorkflowTests(unittest.TestCase):
    setUp = plans.Req7SheetsNativeReadWorkflowTests.setUp
    fixture = plans.Req7SheetsNativeReadWorkflowTests.fixture
    certificates = plans.Req7SheetsNativeReadWorkflowTests.certificates
    server = plans.Req7SheetsNativeReadWorkflowTests.server

    def inputs(self):
        import time
        from test_req7_sdk_authentication import load as auth_loader
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        auth = auth_loader(); plans.load(); module = load()
        binding = OnlineTargetBinding(TARGET, "a" * 64, "b" * 64)
        token = auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600)
        return module, binding, token

    def test_native_post_allowance_cannot_be_used_for_batchupdate_foreign_filter_or_untyped_plan(self):
        module, binding, token = self.inputs(); plan = module.prepare_metadata_capacity_read(binding, token)
        invalid = (replace(plan, path="/v4/spreadsheets/" + TARGET + ":batchUpdate"),
                   replace(plan, body=b'{"requests":[]}'), replace(plan, headers=()),
                   SimpleNamespace(**plan.__dict__))
        for item in invalid:
            with self.subTest(type=type(item).__name__), mock.patch("socket.socket") as networking:
                with self.assertRaises(self.module.TlsInputHold): self.module._native_complete_read(item)
                networking.assert_not_called()

    def test_redirect_auth_failure_and_server_failure_each_use_exactly_one_read_wire_without_replay(self):
        module, binding, token = self.inputs()
        for status in (302, 401, 503):
            wire = ("HTTP/1.1 %d Synthetic\r\nContent-Length: 2\r\nLocation: https://foreign.invalid/\r\nConnection: close\r\n\r\n{}" % status).encode()
            unit = module.NativeMetadataCapacityReadUnit(binding, token)
            with self.server(wire, hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
                with self.fixture(), mock.patch.dict(sys.modules, {"monitor.issue_tracker_tls_inputs": self.module}):
                    with self.assertRaises(module.MetadataCapacityHold) as caught: unit.send_once()
                    with self.assertRaises(module.MetadataCapacityHold): unit.send_once()
            self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(BODY, records[0][2])
            self.assertEqual("req7_metadata_capacity_unproved", str(caught.exception)); self.assertIsNone(caught.exception.__context__)

    def test_real_tls_search_and_template_identity_decoder_charge_one_response_without_resend(self):
        import time
        from test_req7_sdk_authentication import load as auth_loader
        from test_req7_sheets_read_decode import identity_response, response
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        auth = auth_loader(); planner = plans.load(); module = load()
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        binding = OnlineTargetBinding(TARGET, "a" * 64, "b" * 64)
        token = auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600)
        identity = decode_template_identity(planner.prepare_template_identity_read(binding, token), response(identity_response()))
        payload = reply((entry(1), entry(2, "nonce", "abc"))).data
        wire = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)).encode() + payload
        unit = module.NativeMetadataCapacityReadUnit(binding, token)
        with self.server(wire, hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
            with self.fixture(), mock.patch.dict(sys.modules, {"monitor.issue_tracker_tls_inputs": self.module}):
                result = module.observe_metadata_capacity(module.prepare_metadata_capacity_read(binding, token), unit.send_once(), identity, reservations=(entry(3),))
                with self.assertRaises(module.MetadataCapacityHold): unit.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(BODY, records[0][2])
        self.assertTrue(records[0][0].startswith(b"POST /v4/spreadsheets/" + TARGET.encode() + b"/developerMetadata:search?"))
        self.assertEqual((101, 10, 2, 29988), next(row for row in result.pools if row[0] == 101))
        self.assertFalse(result.inventory_complete); self.assertEqual("VISIBLE_ONLY_UNPROVED", result.outcome)


class Req7MetadataCapacityManifestTests(unittest.TestCase):
    def test_canonical_direct_multi_script_workflow_primary_suite_and_not_run_obligation(self):
        root = Path(__file__).resolve().parents[1]
        source = "monitor/issue_tracker_metadata_capacity.py"; test = "test_cases.test_req7_metadata_capacity"
        manifest = json.loads((root / "test_cases/script_test_manifest.json").read_text())
        self.assertEqual(source, manifest["scripts"].get(source), "new capacity observer needs canonical script registration")
        self.assertTrue(any(source in rule["paths"] and test in rule["tests"] for rule in manifest["test_rules"]))
        self.assertTrue(any({source, "monitor/issue_tracker_tls_inputs.py", "monitor/issue_tracker_sheets_read_plan.py",
                             "monitor/issue_tracker_sheets_read_decode.py"} <= set(rule["members"])
                            and test in rule["tests"] for rule in manifest["workflows"]))
        self.assertEqual(["issue-tracker-local"], [suite["id"] for suite in manifest["test_suites"] if test in suite["tests"]])
        card = (root / "test_cases/REAL_ENVIRONMENT.md").read_text()
        for text in ("TC-REAL-REQ7-METADATA-CAPACITY-001", "NOT RUN / REAL_ENV REQUIRED", source,
                     "PROJECT", "永久", "预留", "不是发送许可"):
            self.assertIn(text, card)
        readme = (root / "test_cases/README.md").read_text()
        self.assertIn(test, readme); self.assertIn("VISIBLE_ONLY_UNPROVED", readme)
        updater = (root / "tools/update-user-manual.py").read_text()
        self.assertIn('"' + source + '"', updater)


if __name__ == "__main__": unittest.main()
