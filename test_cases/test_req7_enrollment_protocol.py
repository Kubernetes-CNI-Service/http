"""Fixed four-marker protocol DATA, never an enrollment/send authority.

SOURCE ONLY. No SDK, OAuth, HTTP, child, real root ownership or Cloud activity.
The workflow uses real private files/flock under the established root double.
"""
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
SOURCE = ROOT / "monitor/issue_tracker_enrollment_protocol.py"
TARGET = "synthetic_spreadsheet_id_0001"
TITLES = ("GPU Server", "ETH&IB Switch", "ETH Cabling", "IB Cabling", "Dashboard", "Update_History",
          "Inventory", "ServerProfile", "PortProfile", "CVT_SUM", "CVT_Import", "Agent_status", "Whitelist", "BasicData")
FOUR = (("ETH&IB Switch", 101), ("ETH Cabling", 102), ("IB Cabling", 103), ("Update_History", 105))
VALUES = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
KEY = "http-ztp-enrollment-v1"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def response(value, *, status=200, complete=True):
    return SimpleNamespace(status=status, complete=complete, data=canonical(value))


def expected_body(values=VALUES):
    return canonical({"requests": [{"createDeveloperMetadata": {"developerMetadata": {
        "metadataKey": KEY, "metadataValue": nonce, "visibility": "DOCUMENT", "location": {"sheetId": sid}}}}
        for (_, sid), nonce in zip(FOUR, values)], "includeSpreadsheetInResponse": False})


def metadata_entries(values=VALUES):
    return [{"metadataId": 301 + index, "metadataKey": KEY, "metadataValue": nonce,
             "visibility": "DOCUMENT", "location": {"locationType": "SHEET", "sheetId": sid}}
            for index, ((_, sid), nonce) in enumerate(zip(FOUR, values))]


def reply_document(values=VALUES):
    return {"spreadsheetId": TARGET, "replies": [
        {"createDeveloperMetadata": {"developerMetadata": item}} for item in metadata_entries(values)]}


def metadata_document(values=VALUES):
    return {"matchedDeveloperMetadata": [{"developerMetadata": item} for item in metadata_entries(values)]}


def load_protocol(case):
    case.assertTrue(SOURCE.is_file(), "REQ7 fixed four-nonce enrollment protocol capability missing")
    spec = importlib.util.spec_from_file_location("monitor.issue_tracker_enrollment_protocol", SOURCE)
    case.assertIsNotNone(spec)
    case.assertIsNotNone(spec.loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # Match Python's qualified/package import identity after this fixture's
    # deliberate reload; do not leave a stale typed protocol on the package.
    setattr(sys.modules['monitor'], 'issue_tracker_enrollment_protocol', module)
    for name in ("prepare_enrollment_mutation", "validate_prepared_enrollment_mutation",
                 "decode_enrollment_reply", "decode_enrollment_metadata"):
        case.assertTrue(callable(getattr(module, name, None)), "REQ7 fixed enrollment API missing: " + name)
    case.assertTrue(isinstance(getattr(module, "PreparedEnrollmentMutation", None), type),
                    "REQ7 typed enrollment mutation missing")
    case.assertTrue(isinstance(getattr(module, "EnrollmentProtocolHold", None), type),
                    "REQ7 fixed enrollment rejection missing")
    return module


class Req7EnrollmentProtocolDirectTests(unittest.TestCase):
    def setUp(self):
        self.module = load_protocol(self)  # Literal FAIL before fixtures if absent.
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
        from monitor.issue_tracker_enrollment_journal import JournaledEnrollments
        self.binding = OnlineTargetBinding(TARGET, "1" * 64, "2" * 64)
        self.token = AuthenticatedToken("SYNTHETIC_TOKEN", time.time() + 3600)
        self.identity = ObservedTemplateIdentity(TARGET, tuple((title, 100 + i) for i, title in enumerate(TITLES)), "3" * 64)
        self.journal = JournaledEnrollments(tuple((title, sid, nonce) for (title, sid), nonce in zip(FOUR, VALUES)), "4" * 64)

    def prepared(self):
        return self.module.prepare_enrollment_mutation(self.binding, self.token, self.identity, self.journal)

    def test_literal_four_creates_are_one_closed_typed_body_without_business_writes(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("Protocol DATA cannot connect")):
            prepared = self.prepared()
            self.module.validate_prepared_enrollment_mutation(prepared)
        self.assertIs(type(prepared), self.module.PreparedEnrollmentMutation)
        self.assertEqual((prepared.host, prepared.path, prepared.method),
                         ("sheets.googleapis.com", "/v4/spreadsheets/" + TARGET + ":batchUpdate", "POST"))
        self.assertEqual(prepared.headers, (("Accept", "application/json"), ("Authorization", "Bearer SYNTHETIC_TOKEN"),
                                            ("Content-Type", "application/json")))
        self.assertIs(type(prepared.budget_seconds), float)
        self.assertEqual(prepared.budget_seconds, 60.0)
        self.assertEqual(prepared.body, expected_body())
        self.assertEqual(prepared.wire_sha256, hashlib.sha256(expected_body()).hexdigest())
        self.assertNotIn("SYNTHETIC_TOKEN", repr(prepared))
        for nonce in VALUES:
            self.assertNotIn(nonce, repr(prepared))
        for attribute in ("permit", "complete", "receipt", "attempt_count", "claim"):
            self.assertFalse(hasattr(prepared, attribute))
        with self.assertRaises(FrozenInstanceError):
            prepared.body = b"{}"

    def test_request_validator_rejects_endpoint_header_budget_and_body_mutation(self):
        prepared = self.prepared()
        body = json.loads(expected_body())
        tampered = []
        for mutate in (
            lambda v: v["requests"].pop(),
            lambda v: v["requests"].append(copy.deepcopy(v["requests"][0])),
            lambda v: v["requests"][0]["createDeveloperMetadata"]["developerMetadata"].update(metadataKey="z"),
            lambda v: v["requests"][0]["createDeveloperMetadata"]["developerMetadata"].update(visibility="PROJECT"),
            lambda v: v["requests"][0]["createDeveloperMetadata"]["developerMetadata"].update(metadataId=123),
            lambda v: v.update(includeSpreadsheetInResponse=True),
            lambda v: v["requests"].append({"updateCells": {}}),
        ):
            changed = copy.deepcopy(body); mutate(changed); tampered.append(canonical(changed))
        candidates = [replace(prepared, **change) for change in (
            {"host": "example.invalid"}, {"path": prepared.path + "?fields=*"}, {"method": "GET"},
            {"headers": ()}, {"budget_seconds": 60}, {"budget_seconds": 61.0}, {"budget_seconds": True},
            {"wire_sha256": "0" * 64})]
        candidates += [replace(prepared, body=raw, wire_sha256=hashlib.sha256(raw).hexdigest()) for raw in tampered]
        for candidate in candidates:
            with self.subTest(kind=repr(candidate)), self.assertRaises(self.module.EnrollmentProtocolHold):
                self.module.validate_prepared_enrollment_mutation(candidate)

    def test_malformed_or_misbound_original_nonce_and_sheet_shapes_are_rejected(self):
        changed_rows = (
            self.journal.nonces[:-1], self.journal.nonces + (self.journal.nonces[0],),
            tuple((title, sid, VALUES[0]) for title, sid, nonce in self.journal.nonces),
            (("ETH&IB Switch", True, VALUES[0]),) + self.journal.nonces[1:],
            (("ETH&IB Switch", 999, VALUES[0]),) + self.journal.nonces[1:],
        )
        for rows in changed_rows:
            with self.subTest(rows=rows), self.assertRaises(self.module.EnrollmentProtocolHold):
                self.module.prepare_enrollment_mutation(self.binding, self.token, self.identity, replace(self.journal, nonces=rows))
        for identity in (replace(self.identity, spreadsheet_id=TARGET + "foreign"),
                         replace(self.identity, sheet_ids=self.identity.sheet_ids[:-1]),
                         replace(self.identity, sheet_ids=self.identity.sheet_ids[:-1] + (self.identity.sheet_ids[0],))):
            with self.assertRaises(self.module.EnrollmentProtocolHold):
                self.module.prepare_enrollment_mutation(self.binding, self.token, identity, self.journal)
        with self.assertRaises(self.module.EnrollmentProtocolHold):
            self.module.prepare_enrollment_mutation(self.binding, replace(self.token, expires_at=0), self.identity, self.journal)

    def test_http_reply_is_only_data_and_must_echo_all_four_original_nonce_locations(self):
        prepared, raw = self.prepared(), response(reply_document())
        observed = self.module.decode_enrollment_reply(prepared, raw)
        self.assertEqual(observed.outcome, "ENROLLMENT_REPLY_DATA")
        self.assertEqual(observed.metadata_ids, ((101, 301), (102, 302), (103, 303), (105, 304)))
        self.assertEqual(observed.wire_sha256, hashlib.sha256(expected_body()).hexdigest())
        self.assertEqual(observed.response_sha256, hashlib.sha256(raw.data).hexdigest())
        for attribute in ("permit", "complete", "receipt", "remote_enrolled"):
            self.assertFalse(hasattr(observed, attribute))
        bad = []
        for mutate in (
            lambda v: v.update(spreadsheetId=TARGET + "foreign"),
            lambda v: v["replies"].pop(),
            lambda v: v["replies"].append(copy.deepcopy(v["replies"][0])),
            lambda v: v["replies"][0]["createDeveloperMetadata"]["developerMetadata"].update(metadataId=True),
            lambda v: v["replies"][1]["createDeveloperMetadata"]["developerMetadata"].update(metadataId=301),
            lambda v: v["replies"][0]["createDeveloperMetadata"]["developerMetadata"].update(metadataValue="e" * 64),
            lambda v: v["replies"][0]["createDeveloperMetadata"]["developerMetadata"].update(visibility="PROJECT"),
        ):
            document = reply_document(); mutate(document); bad.append(response(document))
        bad.extend((response(reply_document(), status=403), response(reply_document(), status=True),
                    response(reply_document(), complete=False), SimpleNamespace(status=200, complete=True, data=b'{"replies":[],"replies":[]}')))
        for rejected in bad:
            with self.subTest(status=rejected.status), self.assertRaises(self.module.EnrollmentProtocolHold):
                self.module.decode_enrollment_reply(prepared, rejected)

    def test_metadata_readback_requires_all_four_original_ids_nonces_and_fixed_search(self):
        from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
        prepared = self.prepared()
        reply = self.module.decode_enrollment_reply(prepared, response(reply_document()))
        plan = prepare_metadata_capacity_read(self.binding, self.token)
        raw = response(metadata_document())
        observed = self.module.decode_enrollment_metadata(prepared, plan, raw, reply)
        self.assertEqual(observed.outcome, "ENROLLMENT_READBACK_DATA")
        self.assertEqual(observed.metadata_ids, ((101, 301), (102, 302), (103, 303), (105, 304)))
        self.assertEqual(observed.metadata_sha256, hashlib.sha256(raw.data).hexdigest())
        for attribute in ("permit", "complete", "receipt", "remote_enrolled"):
            self.assertFalse(hasattr(observed, attribute))
        bad = []
        for mutate in (
            lambda v: v["matchedDeveloperMetadata"].pop(),
            lambda v: v["matchedDeveloperMetadata"].append(copy.deepcopy(v["matchedDeveloperMetadata"][0])),
            lambda v: v["matchedDeveloperMetadata"][0]["developerMetadata"].update(metadataId=999),
            lambda v: v["matchedDeveloperMetadata"][0]["developerMetadata"].update(metadataValue="e" * 64),
            lambda v: v["matchedDeveloperMetadata"][0]["developerMetadata"].update(visibility="PROJECT"),
            lambda v: v["matchedDeveloperMetadata"][0]["developerMetadata"].update(location={"locationType": "SPREADSHEET", "spreadsheet": True}),
            lambda v: v["matchedDeveloperMetadata"][0]["developerMetadata"].update(location={"locationType": "ROW", "dimensionRange": {
                "sheetId": 101, "dimension": "ROWS", "startIndex": 2, "endIndex": 3}}),
            lambda v: v["matchedDeveloperMetadata"].append({"developerMetadata": {
                "metadataId": 999, "metadataKey": "unrelated-key", "metadataValue": "unrelated",
                "visibility": "DOCUMENT", "location": {"locationType": "SHEET", "sheetId": 100}}}),
            lambda v: v.update(unexpected=True),
        ):
            document = metadata_document(); mutate(document); bad.append(response(document))
        bad.extend((response(metadata_document(), status=500), response(metadata_document(), complete=False),
                    SimpleNamespace(status=200, complete=True, data=b'{"matchedDeveloperMetadata":[],"matchedDeveloperMetadata":[]}')))
        for rejected in bad:
            with self.assertRaises(self.module.EnrollmentProtocolHold):
                self.module.decode_enrollment_metadata(prepared, plan, rejected, reply)
        with self.assertRaises(self.module.EnrollmentProtocolHold):
            self.module.decode_enrollment_metadata(prepared, replace(plan, path=plan.path + "&foreign=1"), raw, reply)


class Req7EnrollmentProtocolJournalWorkflowTests(unittest.TestCase):
    def test_real_four_nonce_journal_to_wire_and_real_metadata_reader_remain_data_only(self):
        module = load_protocol(self)  # No TD or journal if capability missing.
        from test_cases import test_req7_spreadsheet_owner as owners
        from monitor import issue_tracker_spreadsheet_owner as owner
        from monitor import issue_tracker_enrollment_journal as journal
        from monitor import issue_tracker_metadata_capacity as metadata
        from monitor import issue_tracker_sheets_read_decode as decoder
        from monitor import issue_tracker_sheets_read_plan as planner
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        binding = owners.binding()
        token = AuthenticatedToken("SYNTHETIC_TOKEN", time.time() + 3600)
        identity_raw = response({"spreadsheetId": TARGET, "sheets": [
            {"properties": {"sheetId": 100 + index, "title": title}} for index, title in enumerate(TITLES)]})
        identity = decoder.decode_template_identity(planner.prepare_template_identity_read(binding, token), identity_raw)
        with tempfile.TemporaryDirectory(prefix="req7-enrollment-protocol-") as raw:
            root = Path(raw).resolve()
            state = root / "var/lib/http-ztp-container/issue-tracker"
            state.mkdir(parents=True, mode=0o700)
            with owners.fixture(root), owner.spreadsheet_owner(binding) as owner_token, \
                 mock.patch.object(socket, "socket", side_effect=AssertionError("Local protocol workflow must not connect")):
                original = journal.prepare_enrollment_journal(owner_token, binding, identity)
                self.assertEqual(tuple((title, sid) for title, sid, nonce in original.nonces), FOUR)
                values = tuple(nonce for title, sid, nonce in original.nonces)
                self.assertEqual(len(set(values)), 4)
                for nonce in values:
                    self.assertRegex(nonce, r"\A[0-9a-f]{64}\Z")
                folder = state / (hashlib.sha256(TARGET.encode()).hexdigest() + ".enrollment")
                before = {p.name: p.read_bytes() for p in folder.iterdir()}
                self.assertEqual(set(before), {"NONCES", "HEADER", "INITIALIZED"})
                self.assertEqual(json.loads(before["NONCES"]), [list(row) for row in original.nonces])
                prepared = module.prepare_enrollment_mutation(binding, token, identity, original)
                self.assertEqual(prepared.body, expected_body(values))
                reply = module.decode_enrollment_reply(prepared, response(reply_document(values)))
                plan, raw_metadata = metadata.prepare_metadata_capacity_read(binding, token), response(metadata_document(values))
                capacity = metadata.observe_metadata_capacity(plan, raw_metadata, identity, reservations=())
                self.assertEqual(capacity.outcome, "VISIBLE_ONLY_UNPROVED")
                self.assertFalse(capacity.inventory_complete)
                for sheet in ("ETH&IB Switch", "ETH Cabling", "IB Cabling"):
                    pair = journal.observe_enrollment_pair(owner_token, binding, identity, plan, raw_metadata, sheet=sheet)
                    self.assertTrue(pair.target_nonce_valid)
                    self.assertTrue(pair.history_nonce_valid)
                    self.assertFalse(hasattr(pair, "permit"))
                observed = module.decode_enrollment_metadata(prepared, plan, raw_metadata, reply)
                self.assertEqual(observed.outcome, "ENROLLMENT_READBACK_DATA")
                self.assertFalse(hasattr(observed, "complete"))
                self.assertFalse(hasattr(observed, "permit"))
                self.assertEqual(before, {p.name: p.read_bytes() for p in folder.iterdir()})
                self.assertEqual(original, journal.inspect_enrollment_journal(owner_token, binding, identity))
                self.assertEqual({p.name for p in folder.iterdir()}, {"NONCES", "HEADER", "INITIALIZED"})
                self.assertFalse(any(p.name in {"COUNT", "CLAIM", "COMPLETE", "UNKNOWN"} for p in state.rglob("*")))
