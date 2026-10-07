"""Independent immutable C-19 batch composition, not online admission."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TARGET = "synthetic_spreadsheet_id_0001"


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load():
    path = ROOT / "monitor/issue_tracker_send_unit.py"
    if not path.is_file(): raise AssertionError("C-19 immutable unit composer missing")
    spec = importlib.util.spec_from_file_location("monitor.issue_tracker_send_unit", path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


def inputs(count=2):
    operations = [{"operation_id": "switch:%04d" % i, "activity_key": ["switch", "node%04d" % i, "down", "fabric"], "action": "upsert"}
                  for i in range(count)]
    manifest = canonical({"schema_version": 1, "operations": operations, "fixture": "not protected qualification"})
    business = tuple({"operation_id": op["operation_id"], "action": "update", "row_index": i + 2,
                      "values": {"L": "down"}, "observed_values": {"L": {"stringValue": "old"}},
                      "recorded_at_utc": "2026-10-08T10:00:00Z"} for i, op in enumerate(operations))
    return dict(manifest=manifest, manifest_id=hashlib.sha256(manifest).hexdigest(),
                generation_id="a" * 64, publish_id="b" * 64, spreadsheet_id=TARGET,
                sheet="ETH&IB Switch", sheet_id=17, history_sheet_id=99,
                target_nonce="c" * 64, history_nonce="d" * 64, preread_sha256="e" * 64,
                business=business, audits=(), occupied_metadata_ids=())


class Req7SendUnitDirectTests(unittest.TestCase):
    def setUp(self): self.module = load()

    def test_exact_single_batch_contains_literal_cells_all_history_and_one_document_fence(self):
        args = inputs(); unit = self.module.freeze_send_unit(**args)
        document = json.loads(unit.wire_bytes)
        self.assertEqual({"requests", "includeSpreadsheetInResponse"}, set(document))
        self.assertIs(False, document["includeSpreadsheetInResponse"])
        requests = document["requests"]; self.assertEqual(4, len(requests))
        for i in range(2):
            self.assertEqual({"updateCells": {"start": {"sheetId": 17, "rowIndex": i + 2, "columnIndex": 11},
                "rows": [{"values": [{"userEnteredValue": {"stringValue": "down"}}]}], "fields": "userEnteredValue"}}, requests[i])
        history = requests[2]["appendCells"]
        self.assertEqual(99, history["sheetId"]); self.assertEqual("userEnteredValue", history["fields"])
        self.assertEqual(2, len(history["rows"]))
        for i, row in enumerate(history["rows"]):
            cells = [cell["userEnteredValue"]["stringValue"] for cell in row["values"]]
            self.assertEqual(["2026-10-08T10:00:00Z", "ETH&IB Switch", "update", "switch:%04d" % i], cells[:4])
            details = json.loads(cells[4])
            for key, expected in (("unit_id", unit.unit_id), ("manifest_id", args["manifest_id"]),
                                  ("generation_id", "a" * 64), ("publish_id", "b" * 64),
                                  ("target_nonce", "c" * 64), ("history_nonce", "d" * 64),
                                  ("action_digest", unit.action_digest), ("outcome_mapping_sha256", unit.outcome_mapping_sha256)):
                self.assertEqual(expected, details[key])
        self.assertEqual({"createDeveloperMetadata": {"developerMetadata": {
            "metadataId": unit.fence_metadata_id, "metadataKey": "z", "metadataValue": "1",
            "visibility": "DOCUMENT", "location": {"sheetId": 17}}}}, requests[3])
        self.assertEqual(hashlib.sha256(unit.wire_bytes).hexdigest(), unit.wire_sha256)
        self.assertFalse(hasattr(unit, "permit")); self.assertFalse(hasattr(unit, "send_once"))

    def test_unit_and_marker_encoding_are_canonical_and_ambiguous_concatenation_is_impossible(self):
        args = inputs(); unit = self.module.freeze_send_unit(**args)
        identity = {"schema_version": 1, "generation_id": "a" * 64, "publish_id": "b" * 64,
                    "spreadsheet_id": TARGET, "sheet": "ETH&IB Switch", "sheet_id": 17}
        expected_id = hashlib.sha256(canonical(identity)).hexdigest()
        self.assertEqual(expected_id, unit.unit_id)
        self.assertEqual((int(expected_id[:8], 16) & 0x7fffffff) or 1, unit.fence_metadata_id)
        with self.assertRaises(FrozenInstanceError): unit.wire_bytes = b"{}"
        self.assertEqual(unit, self.module.freeze_send_unit(**deepcopy(args)))
        for key in ("generation_id", "publish_id"):
            altered = dict(args); altered[key] = "f" * 64
            self.assertNotEqual(unit.unit_id, self.module.freeze_send_unit(**altered).unit_id)

    def test_noop_rows_have_no_fabricated_history_but_full_mapping_stays_bound(self):
        args = inputs(); args["business"][0]["observed_values"] = {"L": {"stringValue": "down"}}
        unit = self.module.freeze_send_unit(**args); requests = json.loads(unit.wire_bytes)["requests"]
        self.assertEqual(3, len(requests)); self.assertEqual(3, requests[0]["updateCells"]["start"]["rowIndex"])
        rows = requests[1]["appendCells"]["rows"]; self.assertEqual(1, len(rows))
        self.assertEqual("switch:0001", rows[0]["values"][3]["userEnteredValue"]["stringValue"])
        self.assertEqual((('switch:0000', 'OBSERVED-SATISFIED-AT-READ'), ('switch:0001', 'WIRE-CANDIDATE')), unit.outcomes)
        self.assertEqual(hashlib.sha256(canonical([list(row) for row in unit.outcomes])).hexdigest(), unit.outcome_mapping_sha256)

    def test_all_noop_keeps_settings_pending_without_intent_history_fence_or_audit_only_unit(self):
        args = inputs()
        for item in args["business"]: item["observed_values"] = {"L": {"stringValue": "down"}}
        args["audits"] = ({"event_id": "settings:001", "recorded_at_utc": "2026-10-08T10:00:00Z", "details": "K=3"},)
        unit = self.module.freeze_send_unit(**args)
        self.assertEqual("NO_SEND", unit.outcome); self.assertEqual(b"", unit.wire_bytes)
        self.assertIsNone(unit.fence_metadata_id); self.assertEqual(0, unit.history_rows_expected)
        self.assertEqual(("settings:001",), unit.pending_audit_ids)
        self.assertNotIn("COMPLETE", repr(unit)); self.assertNotIn("APPLIED", repr(unit))

    def test_noop_intended_values_still_bind_action_digest_and_pending_preimage_is_bounded(self):
        args = inputs(1)
        args["business"][0]["observed_values"] = {"L": {"stringValue": "down"}}
        first = self.module.freeze_send_unit(**args)
        changed = deepcopy(args); changed["business"][0]["values"]["L"] = "different"
        changed["business"][0]["observed_values"] = {"L": {"stringValue": "different"}}
        second = self.module.freeze_send_unit(**changed)
        self.assertEqual(first.outcomes, second.outcomes); self.assertEqual("NO_SEND", second.outcome)
        self.assertNotEqual(first.action_digest, second.action_digest)
        args["audits"] = tuple({"event_id": "settings:%03d" % i, "recorded_at_utc": "2026-10-08T10:00:00Z",
                                "details": "x" * 32768} for i in range(40))
        with self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**args)

    def test_later_caller_dict_mutation_cannot_change_frozen_wire_or_action_preimage(self):
        args = inputs(); unit = self.module.freeze_send_unit(**args)
        before = (unit.wire_bytes, unit.action_preimage, unit.action_digest, unit.outcomes)
        args["business"][0]["values"]["L"] = "mutated"
        self.assertEqual(before, (unit.wire_bytes, unit.action_preimage, unit.action_digest, unit.outcomes))

    def test_every_piggyback_settings_audit_is_in_history_and_nonrecursive_action_digest(self):
        args = inputs(); args["audits"] = tuple({"event_id": "settings:%03d" % i,
            "recorded_at_utc": "2026-10-08T10:00:00Z", "details": "K=%d" % (i + 2)} for i in range(2))
        unit = self.module.freeze_send_unit(**args); requests = json.loads(unit.wire_bytes)["requests"]
        rows = requests[-2]["appendCells"]["rows"]; self.assertEqual(4, len(rows))
        self.assertEqual(["settings:000", "settings:001"], [row["values"][3]["userEnteredValue"]["stringValue"] for row in rows[2:]])
        preimage = json.loads(unit.action_preimage)
        self.assertNotIn("action_digest", preimage); self.assertNotIn("wire_bytes", preimage)
        self.assertNotIn("History", unit.action_preimage.decode())
        self.assertEqual(2, len(preimage["audits"])); self.assertEqual(2, len(preimage["business"]))
        self.assertEqual(hashlib.sha256(unit.action_preimage).hexdigest(), unit.action_digest)
        self.assertEqual((), unit.pending_audit_ids)
        altered = deepcopy(args); altered["audits"][1]["details"] = "K=4"
        self.assertNotEqual(unit.action_digest, self.module.freeze_send_unit(**altered).action_digest)

    def test_complete_operation_set_and_target_family_are_mandatory_not_caller_filterable(self):
        for fault in ("missing", "duplicate", "foreign", "mixed-family", "out-of-order", "conflicting-coordinate"):
            args = inputs()
            if fault == "missing": args["business"] = args["business"][:1]
            elif fault == "duplicate": args["business"] = (args["business"][0],) * 2
            elif fault == "foreign": args["business"][1]["operation_id"] = "foreign"
            elif fault == "mixed-family": args["sheet"] = "ETH Cabling"
            elif fault == "out-of-order": args["business"] = args["business"][::-1]
            else: args["business"][1]["row_index"] = 2
            with self.subTest(fault=fault), self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**args)

    def test_formula_like_text_is_literal_and_operator_formula_id_status_columns_remain_unwritable(self):
        args = inputs(); args["business"][0]["values"]["L"] = "=HYPERLINK(\"literal\")"
        unit = self.module.freeze_send_unit(**args)
        self.assertNotIn(b"formulaValue", unit.wire_bytes); self.assertIn(b"stringValue", unit.wire_bytes)
        for column in ("A", "D", "E", "G", "H", "I", "N", "O"):
            args = inputs(); args["business"][0]["values"][column] = "unexpected"
            with self.subTest(column=column), self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**args)

    def test_marker_collision_with_any_observed_or_reserved_id_stops_without_substitute_id(self):
        args = inputs(); first = self.module.freeze_send_unit(**args)
        args["occupied_metadata_ids"] = (first.fence_metadata_id,)
        with mock.patch("socket.socket") as network, self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**args)
        network.assert_not_called()
        for occupied in ((True,), (0,), (-1,), (2147483648,), (7, 7), [7]):
            args = inputs(); args["occupied_metadata_ids"] = occupied
            with self.subTest(occupied=occupied), self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**args)

    def test_both_bounds_include_history_fence_and_audits_without_chunking(self):
        # 249 four-run inserts + two one-run updates + History + fence = 1000.
        # Keep the independent request-count case below the separate byte bound.
        args = inputs(251)
        for item in args["business"][:249]:
            item["action"] = "insert"; item["observed_values"] = None
            item["values"] = {"B": "2026-10-08", "C": "ZTP Monitor", "F": item["operation_id"],
                              "J": "Compute", "K": "High", "L": "down", "N": "New"}
        unit = self.module.freeze_send_unit(**args)
        self.assertEqual(1000, len(json.loads(unit.wire_bytes)["requests"]))
        overflow = inputs(252); overflow["business"] = args["business"] + overflow["business"][-1:]
        with self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**overflow)
        args = inputs(40)
        for item in args["business"]: item["values"]["L"] = "x" * 32768
        with self.assertRaises(self.module.SendUnitHold): self.module.freeze_send_unit(**args)

    def test_invalid_identity_manifest_nonce_or_audit_returns_sanitized_hold_without_mutation(self):
        changes = (("sheet_id", True), ("sheet_id", -1), ("history_sheet_id", 17),
                   ("spreadsheet_id", "https://foreign.invalid"), ("manifest_id", "0" * 64),
                   ("manifest", b'{"operations":[],"operations":[]}'), ("generation_id", "a:b"),
                   ("target_nonce", ""), ("preread_sha256", "e" * 63),
                   ("audits", ({"event_id": "settings:001", "recorded_at_utc": "bad", "details": "x"},)))
        for key, value in changes:
            args = inputs(); args[key] = value; before = deepcopy(args)
            with self.subTest(key=key), self.assertRaises(self.module.SendUnitHold) as caught: self.module.freeze_send_unit(**args)
            self.assertEqual("req7_send_unit_unproved", str(caught.exception)); self.assertIsNone(caught.exception.__context__)
            self.assertEqual(before, args)


class Req7SendUnitJournalWorkflowTests(unittest.TestCase):
    def test_real_cells_composer_journal_freeze_identical_bytes_and_refuse_changed_retry(self):
        module = load()
        from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner
        from monitor.issue_tracker_attempt_journal import prepare_unit, record_attempt_intent, AttemptJournalHold
        with tempfile.TemporaryDirectory(prefix="req7-frozen-wire-") as directory:
            project = Path(directory).resolve(); publication = project / "publication"; publication.mkdir(mode=0o700)
            create_local_commit_store(project, publication)
            args = inputs(); unit = module.freeze_send_unit(**args)
            with writer_owner(project, publication) as token:
                prepare_unit(token, unit.unit_id, unit.wire_bytes)
                for count in range(1, 7):
                    record = record_attempt_intent(token, unit.unit_id, unit.wire_bytes)
                    self.assertEqual(count, record.attempt_count); self.assertEqual(unit.wire_sha256, record.wire_sha256)
                with self.assertRaises(AttemptJournalHold): record_attempt_intent(token, unit.unit_id, unit.wire_bytes)
                altered = deepcopy(args); altered["business"][0]["values"]["L"] = "changed"
                other = module.freeze_send_unit(**altered); self.assertEqual(unit.unit_id, other.unit_id)
                with self.assertRaises(AttemptJournalHold): record_attempt_intent(token, other.unit_id, other.wire_bytes)
            self.assertEqual(unit.wire_bytes, (project / ".tracker/remote-attempts" / unit.unit_id / "WIRE").read_bytes())
            self.assertFalse(hasattr(record, "permit"))  # Six intents still do not prove six actual sends.


class Req7SendUnitManifestTests(unittest.TestCase):
    def test_composer_has_direct_real_multi_script_workflow_primary_suite_and_real_env_card(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        source = "monitor/issue_tracker_send_unit.py"; test = "test_cases.test_req7_send_unit"
        self.assertEqual(source, manifest["scripts"].get(source))
        self.assertTrue(any(source in rule["paths"] and test in rule["tests"] for rule in manifest["test_rules"]))
        self.assertTrue(any({source, "monitor/issue_tracker_online_cells.py", "monitor/issue_tracker_attempt_journal.py",
                             "monitor/issue_tracker_local_commit.py"} <= set(rule["members"]) and test in rule["tests"]
                            for rule in manifest["workflows"]))
        self.assertEqual(["issue-tracker-local"], [suite["id"] for suite in manifest["test_suites"] if test in suite["tests"]])
        for text in ("TC-REAL-REQ7-IMMUTABLE-SEND-UNIT-001", "NOT RUN / REAL_ENV REQUIRED", source, "非递归", "不是发送许可"):
            self.assertIn(text, (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text())
        self.assertIn(test, (ROOT / "test_cases/README.md").read_text())
        self.assertIn('"' + source + '"', (ROOT / "tools/update-user-manual.py").read_text())


if __name__ == "__main__": unittest.main()
