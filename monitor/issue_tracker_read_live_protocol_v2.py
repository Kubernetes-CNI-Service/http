"""Fixed-read v2 DATA codec. No native/source/SDK or launch permission."""
import hashlib
import json
import math
import re

DATA_LIMIT = 2 * 1024 * 1024
READY_LIMIT = DATA_LIMIT + 1024
CONTROL_LIMIT = 65536
CONTROL_FRAME_LIMIT = 1024
CONTROL_RESERVE = 1024
MAX_SERIAL = 1024
_NONCE = re.compile(r'[0-9a-f]{64}\Z')


class ProtocolHold(ValueError):
    def __init__(self):
        super().__init__('fixed_read_v2_protocol_denied')


def _nonce(value):
    if type(value) is not str or _NONCE.fullmatch(value) is None:
        raise ProtocolHold()


def _digest(value):
    if type(value) is not str or _NONCE.fullmatch(value) is None:
        raise ProtocolHold()


def _serial(value):
    if type(value) is not int or not 1 <= value <= MAX_SERIAL:
        raise ProtocolHold()


def _number(value):
    if type(value) not in (int, float) or not 0 <= value < 1e15 or not math.isfinite(value):
        raise ProtocolHold()


def _data(value, depth=0):
    if depth > 64:
        raise ProtocolHold()
    kind = type(value)
    if kind in (str, int, bool, type(None)):
        return
    if kind is float and math.isfinite(value):
        return
    if kind is list:
        for item in value:
            _data(item, depth + 1)
        return
    if kind is dict and all(type(key) is str for key in value):
        for item in value.values():
            _data(item, depth + 1)
        return
    raise ProtocolHold()


def _canonical(data):
    try:
        if type(data) is not dict:
            raise ProtocolHold()
        _data(data)
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode('utf-8')
        if len(raw) > DATA_LIMIT:
            raise ProtocolHold()
        return raw
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise ProtocolHold() from None


def data_digest(data):
    return hashlib.sha256(_canonical(data)).hexdigest()


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ProtocolHold()
        result[key] = value
    return result


def _reject(_value):
    raise ProtocolHold()


def _decode(raw, nonce, limit):
    _nonce(nonce)
    try:
        if (type(raw) is not bytes or not 1 <= len(raw) <= limit
                or not raw.endswith(b'\n') or raw.count(b'\n') != 1):
            raise ProtocolHold()
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=_reject)
        _data(value)
        if (type(value) is not dict or type(value.get('v')) is not int
                or value['v'] != 2 or value.get('nonce') != nonce):
            raise ProtocolHold()
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise ProtocolHold() from None


def _encode(value, limit):
    try:
        _data(value)
        raw = (json.dumps(value, ensure_ascii=False, separators=(',', ':'),
                          allow_nan=False) + '\n').encode('utf-8')
        if len(raw) > limit:
            raise ProtocolHold()
        return raw
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise ProtocolHold() from None


def encode_ready(nonce, data, ready_at):
    _nonce(nonce)
    _number(ready_at)
    return _encode(dict(v=2, nonce=nonce, event='READY', data=data,
                        ready_at=ready_at, expires_at=ready_at + 60.0,
                        digest=data_digest(data)), READY_LIMIT)


def encode_live(nonce, serial, digest):
    _nonce(nonce)
    _serial(serial)
    _digest(digest)
    return _encode(dict(v=2, nonce=nonce, event='LIVE', serial=serial,
                        digest=digest), CONTROL_FRAME_LIMIT)


def encode_closed(nonce):
    _nonce(nonce)
    return _encode(dict(v=2, nonce=nonce, event='CLOSED'), CONTROL_FRAME_LIMIT)


def decode_event(raw, nonce):
    value = _decode(raw, nonce, READY_LIMIT)
    event = value.get('event')
    if event == 'READY' and set(value) == {'v', 'nonce', 'event', 'data', 'ready_at', 'expires_at', 'digest'}:
        _number(value['ready_at'])
        _number(value['expires_at'])
        _digest(value['digest'])
        if (value['expires_at'] != value['ready_at'] + 60.0
                or data_digest(value['data']) != value['digest']):
            raise ProtocolHold()
        return value
    if len(raw) > CONTROL_FRAME_LIMIT:
        raise ProtocolHold()
    if event == 'LIVE' and set(value) == {'v', 'nonce', 'event', 'serial', 'digest'}:
        _serial(value['serial'])
        _digest(value['digest'])
        return value
    if event == 'CLOSED' and set(value) == {'v', 'nonce', 'event'}:
        return value
    raise ProtocolHold()


def encode_command(nonce, command, serial=None):
    _nonce(nonce)
    if command == 'CLOSE' and serial is None:
        return _encode(dict(v=2, nonce=nonce, command=command), CONTROL_FRAME_LIMIT)
    if command == 'CHECK':
        _serial(serial)
        return _encode(dict(v=2, nonce=nonce, command=command, serial=serial), CONTROL_FRAME_LIMIT)
    raise ProtocolHold()


def decode_command(raw, nonce):
    value = _decode(raw, nonce, CONTROL_FRAME_LIMIT)
    command = value.get('command')
    if command == 'CLOSE' and set(value) == {'v', 'nonce', 'command'}:
        return value
    if command == 'CHECK' and set(value) == {'v', 'nonce', 'command', 'serial'}:
        _serial(value['serial'])
        return value
    raise ProtocolHold()
