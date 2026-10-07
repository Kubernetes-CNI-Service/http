"""Independent C-19 rejection observations; no network or journal authority."""
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


def error(code=403, status="PERMISSION_DENIED", **extra):
    return json.dumps({"error":{"code":code,"status":status,"message":"private diagnostic",**extra}},
                      separators=(",",":"),ensure_ascii=False).encode()


class Req7MutationRejectionDirectTests(unittest.TestCase):
    def module(self):
        path=Path(__file__).resolve().parents[1]/"monitor/issue_tracker_mutation_rejection.py"
        self.assertTrue(path.is_file(),"C-19 rejection observer missing")
        spec=importlib.util.spec_from_file_location("isolated_req7_rejection",path)
        module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
        return module

    def test_four_consistent_statuses_are_observations_not_complete_or_resend_permission(self):
        module=self.module()
        for code,status in ((400,"INVALID_ARGUMENT"),(400,"FAILED_PRECONDITION"),
                            (403,"PERMISSION_DENIED"),(404,"NOT_FOUND")):
            with self.subTest(status=status):
                raw=error(code,status)
                observed=module.observe_rejection(code,raw,complete=True)
                self.assertEqual("DEFINITE_REJECTION",observed.outcome)
                self.assertEqual(hashlib.sha256(raw).hexdigest(),observed.body_sha256)
                self.assertFalse(hasattr(observed,"permit")); self.assertFalse(hasattr(observed,"receipt"))
                self.assertNotIn("private diagnostic",repr(observed))
                with self.assertRaises(FrozenInstanceError): observed.outcome="COMPLETE"

    def test_no_status_code_inference_partial_boolean_or_ack_can_resolve_unknown(self):
        module=self.module()
        cases=[(200,b"{}",True),(403,error(),False),(403,error(),1),
               (True,error(),True),(400,error(),True),(403,error(403,"NOT_FOUND"),True),
               (403,error(7,"PERMISSION_DENIED"),True),(403,error("403"),True),
               (400,error(True,"INVALID_ARGUMENT"),True),(401,error(401,"UNAUTHENTICATED"),True),
               (429,error(429,"RESOURCE_EXHAUSTED"),True),(500,error(500,"INTERNAL"),True),
               (503,error(503,"UNAVAILABLE"),True),(302,error(302,"PERMISSION_DENIED"),True)]
        for status,raw,complete in cases:
            with self.subTest(status=status,complete=complete):
                self.assertEqual("UNKNOWN",module.observe_rejection(status,raw,complete=complete).outcome)

    def test_strict_bounded_json_and_well_formed_details_fail_closed_without_leaking(self):
        module=self.module()
        invalid=[b"",b"\xff",b"{}",b"[]",b'{"error":{"code":403,"code":403,"status":"PERMISSION_DENIED","message":"x"}}',
                 b'{"error":{"code":403,"status":"PERMISSION_DENIED","message":"x","details":[NaN]}}',
                 error(message2="extra"),error(details={}),error(details=[{}]),
                 error(details=[{"@type":7}]),error(details=[{"@type":"not-a-type-url"}]),
                 error(details=[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":float("inf")}]),
                 b'['*1100+b']'*1100, bytearray(error()),error()+b"trailing", b" "*(2*1024*1024+1),
                 b'{"error":{"code":403,"status":"PERMISSION_DENIED","message":"\\ud800"}}',
                 b'{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","number":1e999}]}}']
        for raw in invalid:
            with self.subTest(type=type(raw).__name__,size=len(raw)):
                result=module.observe_rejection(403,raw,complete=True)
                self.assertEqual("UNKNOWN",result.outcome)
                self.assertNotIn("private diagnostic",repr(result))
        details=[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"FORBIDDEN","domain":"sheets.googleapis.com","metadata":{"key":"value"}}]
        self.assertEqual("DEFINITE_REJECTION",module.observe_rejection(403,error(details=details),complete=True).outcome)

    def test_unknown_is_sticky_across_all_six_attempts_and_never_reset_by_later_rejection(self):
        module=self.module()
        self.assertEqual("DEFINITE_REJECTION",module.fold_attempt_observations(("DEFINITE_REJECTION",)))
        for index in range(6):
            outcomes=tuple("UNKNOWN" if i==index else "DEFINITE_REJECTION" for i in range(6))
            self.assertEqual("UNKNOWN",module.fold_attempt_observations(outcomes))
        self.assertEqual("DEFINITE_REJECTION",module.fold_attempt_observations(("DEFINITE_REJECTION",)*6))
        for invalid in ((),("UNKNOWN",)*7,["UNKNOWN"],("COMPLETE",),(True,),("UNKNOWN","PASS")):
            with self.subTest(invalid=invalid),self.assertRaises(module.RejectionHold):
                module.fold_attempt_observations(invalid)


class Req7MutationRejectionWorkflowTests(Req7MutationRejectionDirectTests):
    def test_real_literal_cell_intent_rejection_does_not_create_applied_receipt_or_rewrite_wire(self):
        module=self.module()
        from monitor.issue_tracker_online_cells import encode_tool_cells
        with mock.patch("socket.socket",side_effect=AssertionError("no network")):
            intent=encode_tool_cells("ETH&IB Switch",17,"update",{"L":"literal = evidence"},row_index=31)
            before=intent.requests_json
            self.assertEqual({"stringValue":"literal = evidence"},json.loads(before)[0]["updateCells"]["rows"][0]["values"][0]["userEnteredValue"])
            uncertain=module.observe_rejection(503,error(503,"UNAVAILABLE"),complete=True)
            later=module.observe_rejection(403,error(),complete=True)
            self.assertEqual("UNKNOWN",module.fold_attempt_observations((uncertain.outcome,later.outcome)))
            self.assertEqual(before,intent.requests_json)
            self.assertEqual("WIRE-CANDIDATE",intent.outcome)
            self.assertFalse(hasattr(later,"permit")); self.assertFalse(hasattr(later,"receipt"))


if __name__=="__main__": unittest.main()
