"""Fixed four-marker wire DATA, never enrollment/send authority.

No transport, owner acquisition, nonce generation, local state or completion
receipt is provided. Typed inputs and matching replies do not grant permission.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re

_TITLES = ("ETH&IB Switch", "ETH Cabling", "IB Cabling", "Update_History")
_KEY = "http-ztp-enrollment-v1"


class EnrollmentProtocolHold(ValueError):
    def __init__(self):
        super().__init__("req7_enrollment_protocol_denied")


@dataclass(frozen=True)
class PreparedEnrollmentMutation:
    host: str
    path: str = field(repr=False)
    method: str
    headers: tuple = field(repr=False)
    body: bytes = field(repr=False)
    wire_sha256: str
    binding: object = field(repr=False)
    token: object = field(repr=False)
    identity: object = field(repr=False)
    journal: object = field(repr=False)
    budget_seconds: float = 60.0


@dataclass(frozen=True)
class EnrollmentReplyData:
    outcome: str
    metadata_ids: tuple
    wire_sha256: str
    response_sha256: str
    spreadsheet_id: str = field(repr=False)


@dataclass(frozen=True)
class EnrollmentMetadataData:
    outcome: str
    metadata_ids: tuple
    metadata_sha256: str


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _facts(binding, token, identity, journal):
    from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read
    from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity, _TEMPLATE_SHEETS
    from monitor.issue_tracker_enrollment_journal import JournaledEnrollments
    failed = False
    try:
        prepare_template_identity_read(binding, token)
        if (type(identity) is not ObservedTemplateIdentity
                or identity.spreadsheet_id != binding.spreadsheet_id
                or type(identity.sheet_ids) is not tuple or len(identity.sheet_ids) != 14
                or not _digest(identity.source_sha256)
                or type(journal) is not JournaledEnrollments or not _digest(journal.journal_sha256)
                or type(journal.nonces) is not tuple or len(journal.nonces) != 4):
            raise EnrollmentProtocolHold()
        mapping = {}; ids = set()
        for item in identity.sheet_ids:
            if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
                    or item[0] not in _TEMPLATE_SHEETS or item[0] in mapping
                    or type(item[1]) is not int or not 0 <= item[1] <= 2147483647 or item[1] in ids):
                raise EnrollmentProtocolHold()
            mapping[item[0]] = item[1]; ids.add(item[1])
        if set(mapping) != set(_TEMPLATE_SHEETS): raise EnrollmentProtocolHold()
        nonces = set()
        for title, row in zip(_TITLES, journal.nonces):
            if (type(row) is not tuple or len(row) != 3 or type(row[0]) is not str or row[0] != title
                    or type(row[1]) is not int or row[1] != mapping[title] or not _digest(row[2])
                    or row[2] in nonces):
                raise EnrollmentProtocolHold()
            nonces.add(row[2])
    except Exception:
        failed = True
    if failed: raise EnrollmentProtocolHold()
    return journal.nonces


def _body(rows):
    value = {"requests": [{"createDeveloperMetadata": {"developerMetadata": {
        "metadataKey": _KEY, "metadataValue": nonce, "visibility": "DOCUMENT",
        "location": {"sheetId": sid}}}} for _title, sid, nonce in rows],
        "includeSpreadsheetInResponse": False}
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def prepare_enrollment_mutation(binding, token, identity, journal):
    rows = _facts(binding, token, identity, journal)
    body = _body(rows)
    return PreparedEnrollmentMutation("sheets.googleapis.com",
        "/v4/spreadsheets/" + binding.spreadsheet_id + ":batchUpdate", "POST",
        (("Accept", "application/json"), ("Authorization", "Bearer " + token.value),
         ("Content-Type", "application/json")), body, hashlib.sha256(body).hexdigest(),
        binding, token, identity, journal)


def validate_prepared_enrollment_mutation(prepared):
    failed = False
    try:
        if (type(prepared) is not PreparedEnrollmentMutation
                or type(prepared.budget_seconds) is not float or prepared.budget_seconds != 60.0
                or type(prepared.body) is not bytes or type(prepared.headers) is not tuple
                or any(type(pair) is not tuple or len(pair) != 2
                       or any(type(part) is not str for part in pair) for pair in prepared.headers)
                or any(type(part) is not str for part in (prepared.host, prepared.path, prepared.method))
                or not _digest(prepared.wire_sha256)):
            raise EnrollmentProtocolHold()
        expected = prepare_enrollment_mutation(prepared.binding, prepared.token, prepared.identity, prepared.journal)
        for name in ("host", "path", "method", "headers", "body", "wire_sha256", "budget_seconds"):
            if getattr(prepared, name) != getattr(expected, name): raise EnrollmentProtocolHold()
    except Exception:
        failed = True
    if failed: raise EnrollmentProtocolHold()


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise EnrollmentProtocolHold()
        value[key] = item
    return value


def _nonfinite(_value):
    raise EnrollmentProtocolHold()


def _document(response):
    failed = False
    try:
        if (type(response.status) is not int or response.status != 200 or response.complete is not True
                or type(response.data) is not bytes or not 1 <= len(response.data) <= 2097152):
            raise EnrollmentProtocolHold()
        value = json.loads(response.data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if type(value) is not dict: raise EnrollmentProtocolHold()
    except Exception:
        failed = True
    if failed: raise EnrollmentProtocolHold()
    return value


def _entries(prepared, entries, *, ordered):
    from monitor.issue_tracker_metadata_capacity import _entry
    failed = False
    try:
        rows = prepared.journal.nonces
        expected = {sid: nonce for _title, sid, nonce in rows}
        if type(entries) is not list or len(entries) != 4: raise EnrollmentProtocolHold()
        seen = {}; ids = set()
        for index, value in enumerate(entries):
            if type(value) is not dict or set(value) != {"metadataId", "metadataKey", "metadataValue", "visibility", "location"}:
                raise EnrollmentProtocolHold()
            mid, _pool, _size, image = _entry(value, set(dict(prepared.identity.sheet_ids).values()))
            key, nonce, visibility, kind, sid, _coordinate = image
            if (key != _KEY or visibility != "DOCUMENT" or kind != "SHEET" or sid not in expected
                    or nonce != expected[sid] or sid in seen or mid in ids
                    or (ordered and sid != rows[index][1])):
                raise EnrollmentProtocolHold()
            seen[sid] = mid; ids.add(mid)
        result = tuple((sid, seen[sid]) for _title, sid, _nonce in rows)
    except Exception:
        failed = True
    if failed: raise EnrollmentProtocolHold()
    return result


def decode_enrollment_reply(prepared, response):
    validate_prepared_enrollment_mutation(prepared)
    value = _document(response)
    failed = False
    try:
        if (set(value) != {"spreadsheetId", "replies"} or type(value["spreadsheetId"]) is not str
                or value["spreadsheetId"] != prepared.binding.spreadsheet_id
                or type(value["replies"]) is not list or len(value["replies"]) != 4):
            raise EnrollmentProtocolHold()
        entries = []
        for item in value["replies"]:
            if type(item) is not dict or set(item) != {"createDeveloperMetadata"}: raise EnrollmentProtocolHold()
            created = item["createDeveloperMetadata"]
            if type(created) is not dict or set(created) != {"developerMetadata"}: raise EnrollmentProtocolHold()
            entries.append(created["developerMetadata"])
        ids = _entries(prepared, entries, ordered=True)
    except Exception:
        failed = True
    if failed: raise EnrollmentProtocolHold()
    return EnrollmentReplyData("ENROLLMENT_REPLY_DATA", ids, prepared.wire_sha256,
                               hashlib.sha256(response.data).hexdigest(), prepared.binding.spreadsheet_id)


def decode_enrollment_metadata(prepared, metadata_plan, response, reply):
    from monitor.issue_tracker_metadata_capacity import _validate_plan, prepare_metadata_capacity_read
    validate_prepared_enrollment_mutation(prepared)
    failed = False
    try:
        if (_validate_plan(metadata_plan) != prepared.binding.spreadsheet_id
                or metadata_plan != prepare_metadata_capacity_read(prepared.binding, prepared.token)
                or type(reply) is not EnrollmentReplyData or reply.outcome != "ENROLLMENT_REPLY_DATA"
                or reply.spreadsheet_id != prepared.binding.spreadsheet_id
                or reply.wire_sha256 != prepared.wire_sha256 or not _digest(reply.response_sha256)
                or type(reply.metadata_ids) is not tuple or len(reply.metadata_ids) != 4):
            raise EnrollmentProtocolHold()
        previous_ids = set()
        for row, item in zip(prepared.journal.nonces, reply.metadata_ids):
            if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not int or item[0] != row[1]
                    or type(item[1]) is not int or not 1 <= item[1] <= 2147483647 or item[1] in previous_ids):
                raise EnrollmentProtocolHold()
            previous_ids.add(item[1])
        value = _document(response)
        if set(value) != {"matchedDeveloperMetadata"} or type(value["matchedDeveloperMetadata"]) is not list:
            raise EnrollmentProtocolHold()
        entries = []
        for item in value["matchedDeveloperMetadata"]:
            if type(item) is not dict or set(item) != {"developerMetadata"}: raise EnrollmentProtocolHold()
            entries.append(item["developerMetadata"])
        ids = _entries(prepared, entries, ordered=False)
        if ids != reply.metadata_ids: raise EnrollmentProtocolHold()
    except Exception:
        failed = True
    if failed: raise EnrollmentProtocolHold()
    return EnrollmentMetadataData("ENROLLMENT_READBACK_DATA", ids, hashlib.sha256(response.data).hexdigest())
