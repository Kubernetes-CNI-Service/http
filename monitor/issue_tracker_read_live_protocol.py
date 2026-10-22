"""Finite process-control DATA codec; never source/credential/send authority."""
import json
import math
import re

LIMIT = 2 * 1024 * 1024
_NONCE = re.compile(r'[0-9a-f]{64}\Z')


class ProtocolHold(ValueError):
    def __init__(self):
        super().__init__('read_session_protocol_denied')


def _nonce(value):
    if type(value) is not str or _NONCE.fullmatch(value) is None:
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
    if kind is dict and all(type(k) is str for k in value):
        for item in value.values():
            _data(item, depth + 1)
        return
    raise ProtocolHold()


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ProtocolHold()
        result[key] = value
    return result


def _reject(_value):
    raise ProtocolHold()


def _decode(raw, nonce):
    _nonce(nonce)
    try:
        if (type(raw) is not bytes or not 1 <= len(raw) <= LIMIT
                or not raw.endswith(b'\n') or raw.count(b'\n') != 1):
            raise ProtocolHold()
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=_reject)
        _data(value)
        if (type(value) is not dict or type(value.get('v')) is not int
                or value['v'] != 1 or value.get('nonce') != nonce):
            raise ProtocolHold()
        return value
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise ProtocolHold() from None


def _encode(value):
    try:
        _data(value)
        raw = (json.dumps(value, ensure_ascii=False, separators=(',', ':'),
                          allow_nan=False) + '\n').encode('utf-8')
        if len(raw) > LIMIT:
            raise ProtocolHold()
        return raw
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        raise ProtocolHold() from None


def encode_event(nonce, event, data=None):
    _nonce(nonce)
    if type(event) is not str or event not in ('READY', 'LIVE', 'CLOSED'):
        raise ProtocolHold()
    value = dict(v=1, nonce=nonce, event=event)
    if event != 'CLOSED':
        if type(data) is not dict:
            raise ProtocolHold()
        value['data'] = data
    elif data is not None:
        raise ProtocolHold()
    return _encode(value)


def decode_event(raw, nonce):
    value = _decode(raw, nonce)
    event = value.get('event')
    if event == 'CLOSED' and set(value) == {'v', 'nonce', 'event'}:
        return event, None
    if (event in ('READY', 'LIVE') and set(value) == {'v', 'nonce', 'event', 'data'}
            and type(value['data']) is dict):
        return event, value['data']
    raise ProtocolHold()


def encode_command(nonce, command):
    _nonce(nonce)
    if type(command) is not str or command not in ('CHECK', 'CLOSE'):
        raise ProtocolHold()
    return _encode(dict(v=1, nonce=nonce, command=command))


def decode_command(raw, nonce):
    value = _decode(raw, nonce)
    if set(value) != {'v', 'nonce', 'command'} or value['command'] not in ('CHECK', 'CLOSE'):
        raise ProtocolHold()
    return value['command']
