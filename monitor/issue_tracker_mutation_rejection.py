"""Pure C-19 error observations, not transport, reconciliation or send authority.

HTTP/JSON represents google.rpc.Status.code with an HTTP code and the enum
name in error.status: https://google.aip.dev/193#http11json-representation
Only the four owner-approved consistent errors can mean a definite rejection.
A caller's bytes/complete flag do NOT establish an intact correlated native
connection. The eventual governed mutation boundary must establish that itself.
Neither observation nor folding writes a journal, counts durable SEND_INTENT,
clears reservations/UNKNOWN, permits retry, or proves COMPLETE/APPLIED.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

_MAX_RESPONSE = 2 * 1024 * 1024
_REJECTIONS = {"INVALID_ARGUMENT":400,"FAILED_PRECONDITION":400,
               "PERMISSION_DENIED":403,"NOT_FOUND":404}


class RejectionHold(ValueError):
    def __init__(self): super().__init__("req7_attempt_observations_unproved")


@dataclass(frozen=True)
class RejectionObservation:
    outcome: str
    body_sha256: str | None


def _pairs(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError("duplicate field")
        value[key]=item
    return value


def _nonfinite(_value): raise ValueError("nonfinite JSON")


def observe_rejection(http_status, body, *, complete):
    """Necessary bounded syntax only; malformed, partial or success is UNKNOWN.

Never infer rejection from HTTP alone, grpc numeric codes in REST JSON, a
200 ACK, transport exception, later response or an incomplete/ragged stream.
No remote diagnostic/private body is retained or returned to logging.
"""
    digest=None; outcome="UNKNOWN"
    if type(body) is not bytes or not 1<=len(body)<=_MAX_RESPONSE:
        return RejectionObservation(outcome,digest)
    digest=hashlib.sha256(body).hexdigest()
    try:
        if complete is not True or type(http_status) is not int: raise ValueError("incomplete")
        document=json.loads(body.decode("utf-8","strict"),object_pairs_hook=_pairs,parse_constant=_nonfinite)
        # JSON's exponent parser can produce inf without invoking parse_constant;
        # escaped unpaired surrogates also survive loads. Validate the entire
        # parsed tree, including opaque Any details, without exposing its bytes.
        json.dumps(document,ensure_ascii=False,allow_nan=False,separators=(",",":")).encode("utf-8","strict")
        if type(document) is not dict or set(document)!={"error"}: raise ValueError("shape")
        error=document["error"]
        if (type(error) is not dict or not {"code","status"}<=set(error)<={"code","status","message","details"}
                or type(error["code"]) is not int or type(error["status"]) is not str
                or error["status"] not in _REJECTIONS or error["code"]!=http_status
                or _REJECTIONS[error["status"]]!=http_status
                or ("message" in error and type(error["message"]) is not str)):
            raise ValueError("inconsistent status")
        details=error.get("details",[])
        if type(details) is not list or len(details)>100: raise ValueError("details")
        types=set()
        for detail in details:
            if type(detail) is not dict: raise ValueError("detail")
            name=detail.get("@type")
            if (type(name) is not str or len(name)>256
                    or re.fullmatch(r"type\.googleapis\.com/[A-Za-z_][A-Za-z0-9_.]*",name) is None
                    or name in types): raise ValueError("Any type")
            types.add(name)
        outcome="DEFINITE_REJECTION"
    except (ValueError,UnicodeError,RecursionError,OverflowError,KeyError,TypeError):
        pass
    return RejectionObservation(outcome,digest)


def fold_attempt_observations(outcomes):
    """At most six supplied observations; UNKNOWN is sticky over ALL attempts.

This pure necessary consistency check has no durable attempt authority. The
complete immutable journal must supply the entire history, not a suffix/reset.
A definite rejection after an uncertain send cannot resolve that earlier send.
"""
    if (type(outcomes) is not tuple or not 1<=len(outcomes)<=6
            or any(type(value) is not str or value not in ("DEFINITE_REJECTION","UNKNOWN") for value in outcomes)):
        raise RejectionHold()
    return "UNKNOWN" if "UNKNOWN" in outcomes else "DEFINITE_REJECTION"
