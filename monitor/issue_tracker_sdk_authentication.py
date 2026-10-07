"""Uninstalled C-14 SDK bridge; a wire unit must supply the bounded response.

No concrete network unit, worker activation, mutation permission or deadline
supervisor is provided here. The public SDK handles signing and OAuth parsing;
the caller must separately prove target admission, CA and the supervised unit.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import threading
import time
from types import MappingProxyType

from monitor.issue_tracker_credential_shape import (
    ParsedServiceAccountInfo, TOKEN_ENDPOINT, SHEETS_SCOPE,
    parse_service_account_info, read_service_account_info,
)

SOURCE_ROOT = Path(__file__).resolve().parents[1]
_MAX_TOKEN_BYTES = 65536
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_TOKEN_CONTENT_TYPE = "application/x-www-form-urlencoded"


class AuthenticationHold(ValueError):
    def __init__(self): super().__init__("req7_authentication_denied")


def _sdk():
    failed = False
    try:
        from req7_dependency_contract import load_dependency_contract, installed_dependency_identity
        installed_dependency_identity(load_dependency_contract(SOURCE_ROOT))
        from google.oauth2 import service_account
        from google.auth.exceptions import TransportError
    except Exception:
        failed = True
    if failed:
        raise AuthenticationHold()
    return service_account, TransportError


@dataclass(frozen=True)
class TokenWireRequest:
    url: str
    method: str
    body: bytes = field(repr=False)
    headers: tuple = field(repr=False)
    budget_seconds: float = 30.0


@dataclass(frozen=True)
class SdkTokenResponse:
    status: int
    data: bytes = field(repr=False)
    headers: object = field(repr=False)


def _request_headers(headers):
    if type(headers) is not dict or not {"Content-Type"} <= set(headers) <= {"Content-Type", "x-goog-api-client"}:
        raise AuthenticationHold()
    if headers["Content-Type"] != _TOKEN_CONTENT_TYPE:
        raise AuthenticationHold()
    for value in headers.values():
        if (type(value) is not str or not 1 <= len(value) <= 1024
                or any(not 32 <= ord(character) <= 126 for character in value)):
            raise AuthenticationHold()
    return tuple(sorted(headers.items()))


def _response_headers(headers):
    if type(headers) is not tuple or len(headers) > 100:
        raise AuthenticationHold()
    result = {}; seen = set(); total = 0
    for pair in headers:
        if type(pair) is not tuple or len(pair) != 2:
            raise AuthenticationHold()
        name, value = pair
        if (type(name) is not str or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}", name) is None
                or name.lower() in seen or type(value) is not str or len(value) > 8192
                or any(not 32 <= ord(character) <= 126 for character in value)):
            raise AuthenticationHold()
        seen.add(name.lower()); result[name] = value; total += len(name) + len(value)
    if total > 65536:
        raise AuthenticationHold()
    return MappingProxyType(result)


class OneShotTokenRequest:
    """The SDK may call once; all rejection paths terminate outside except.

The unit boundary, not this adapter or SDK timeout, must enforce the total
budget, TLS authority and orphan/lock ownership. No automatic resend exists.
"""
    def __init__(self, unit):
        _service_account, self._transport_error = _sdk()
        failed = False
        try:
            sender = getattr(unit, "send_once", None)
            if not callable(sender):
                raise AuthenticationHold()
        except Exception:
            failed = True
        if failed:
            raise AuthenticationHold()
        # Hold the one observed unit method rather than re-resolving a mutable
        # sender after the SDK has constructed its secret assertion.
        self._send_once = sender; self._called = False; self._lock = threading.Lock()

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
        failed = False
        with self._lock:
            consumed = self._called
            self._called = True
        if consumed:
            raise self._transport_error("req7_token_transport_denied")
        try:
            if (type(url) is not str or url != TOKEN_ENDPOINT or type(method) is not str or method != "POST"
                    or type(body) is not bytes or not 1 <= len(body) <= _MAX_TOKEN_BYTES or kwargs):
                raise AuthenticationHold()
            budget = 30.0
            if timeout is not None:
                if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= budget:
                    raise AuthenticationHold()
                budget = float(timeout)
            wire = TokenWireRequest(TOKEN_ENDPOINT, "POST", body, _request_headers(headers), budget)
            response = self._send_once(wire)
            status, complete, data, response_headers = (
                response.status, response.complete, response.data, response.headers,
            )
            if (type(status) is not int or status != 200
                    or complete is not True or type(data) is not bytes
                    or not 1 <= len(data) <= _MAX_RESPONSE_BYTES):
                raise AuthenticationHold()
            result = SdkTokenResponse(200, data, _response_headers(response_headers))
        except Exception:
            failed = True
        if failed:
            # Raised after leaving the caught exception, so even hidden
            # __context__ cannot retain an SDK or transport secret payload.
            raise self._transport_error("req7_token_transport_denied")
        return result


def credentials_from_validated_info(parsed):
    """Consume only a strict immutable mapping; this is not FD/send authority.

The fixed-file entry below establishes its file provenance. Passing a parsed
object alone remains API discipline, and supplies no real wire unit.
"""
    failed = False
    try:
        if (type(parsed) is not ParsedServiceAccountInfo or parsed.scope != SHEETS_SCOPE
                or type(parsed.mapping) is not MappingProxyType
                or len(parsed.mapping) > 12 or any(type(value) is not str for value in parsed.mapping.values())
                or sum(len(value.encode("utf-8")) for value in parsed.mapping.values()) > _MAX_TOKEN_BYTES):
            raise AuthenticationHold()
        checked = parse_service_account_info(json.dumps(dict(parsed.mapping), ensure_ascii=True).encode())
        service_account, _transport_error = _sdk()
        result = service_account.Credentials.from_service_account_info(
            dict(checked.mapping), scopes=(SHEETS_SCOPE,), always_use_jwt_access=False,
        )
        if tuple(result.scopes) != (SHEETS_SCOPE,) or result.universe_domain != "googleapis.com":
            raise AuthenticationHold()
    except Exception:
        failed = True
    if failed:
        raise AuthenticationHold()
    return result


def credentials_from_fixed_file():
    """Root-only fixed C-11 reader; no path argument or environment fallback."""
    failed = False
    try:
        if os.geteuid() != 0:
            raise AuthenticationHold()
        result = credentials_from_validated_info(read_service_account_info())
    except Exception:
        failed = True
    if failed:
        raise AuthenticationHold()
    return result


@dataclass(frozen=True)
class AuthenticatedToken:
    """Private refresh output only, never a target or mutation permission."""
    value: str = field(repr=False)
    expires_at: float = field(repr=False)


def _refresh(credential, unit):
    """Public SDK only; SDK parsing failures cannot escape with response bytes."""
    failed = False
    try:
        credential.refresh(OneShotTokenRequest(unit))
        value, expiry = credential.token, credential.expiry
        # A future controlled Sheets boundary may use this as a header value,
        # but must separately perform all admission and durable permit checks.
        if (type(value) is not str or not 1 <= len(value) <= 8192
                or re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", value) is None
                or type(expiry) is not datetime):
            raise AuthenticationHold()
        expires_at = (expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry).timestamp()
        if not math.isfinite(expires_at) or expires_at <= time.time():
            raise AuthenticationHold()
        result = AuthenticatedToken(value, expires_at)
    except Exception:
        failed = True
    if failed:
        raise AuthenticationHold()
    return result


def refresh_validated_service_account(parsed, unit):
    """Mapping-only local proof entry; parsed info is not held-FD authority."""
    return _refresh(credentials_from_validated_info(parsed), unit)


def refresh_fixed_service_account(unit):
    """Fixed root reader -> public constructor -> one callback -> private token."""
    return _refresh(credentials_from_fixed_file(), unit)
