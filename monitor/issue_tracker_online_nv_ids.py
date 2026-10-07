"""Pure C-17 shared sequence planning, never durable reservation authority.

Both Cabling A-column observations and ALL retained prior reservations must
be supplied by a future protected caller. This helper never reads Sheets,
establishes template/source authority, writes a reservation journal or grants
send permission. The plan must be durably reserved under the spreadsheet-wide
lock before use. UNKNOWN retries consume their original frozen unit rather
than rebuilding or invoking this allocator. No clock, expiry or reclamation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


class OnlineNvIdHold(ValueError):
    def __init__(self): super().__init__("online_nv_reservation_unproved")


@dataclass(frozen=True)
class NvReservationPlan:
    reservations: tuple
    requested: tuple
    plan_sha256: str


_ID = re.compile(r"NV[0-9]{5}\Z")
_MAX_ROWS = 100000
_MAX_REQUESTED = 1000


def _id(value):
    if type(value) is not str or _ID.fullmatch(value) is None: raise OnlineNvIdHold()
    return int(value[2:])


def _key(value):
    if (type(value) is not tuple or len(value) != 4
            or any(type(part) is not str or not part or len(part) > 255
                   or any(char in part for char in "\x00\r\n") for part in value)
            or value[0] not in ("eth_cabling", "ib_cabling")
            or value[3] not in ("Link Down", "Mis-wiring")):
        raise OnlineNvIdHold()
    try:
        for part in value: part.encode("utf-8", "strict")
    except UnicodeError: raise OnlineNvIdHold() from None
    return value


def plan_nv_reservations(eth_ids, ib_ids, prior_reservations, requested_keys, *, unknown_units=()):
    """Retain every prior ID; allocate above both actual columns and reservations.

    The seed is an observed row, never a hard-coded initial sequence. Caller
    must include closed rows too: their IDs are never reused. No partial plan
    returns on exhausted capacity, malformed reads or duplicate identities.
    """
    if (type(eth_ids) is not tuple or type(ib_ids) is not tuple
            or len(eth_ids) + len(ib_ids) > _MAX_ROWS
            or type(prior_reservations) is not tuple or len(prior_reservations) > _MAX_ROWS
            or type(requested_keys) is not tuple or len(requested_keys) > _MAX_REQUESTED
            or type(unknown_units) is not tuple
            or any(type(item) is not str or not item for item in unknown_units)
            or unknown_units):
        raise OnlineNvIdHold()
    observed = eth_ids + ib_ids
    numbers = [_id(value) for value in observed]
    if len(set(observed)) != len(observed): raise OnlineNvIdHold()
    reservations = {}
    reserved_ids = set()
    for pair in prior_reservations:
        if type(pair) is not tuple or len(pair) != 2: raise OnlineNvIdHold()
        key, value = _key(pair[0]), pair[1]
        number = _id(value)
        if key in reservations or value in reserved_ids: raise OnlineNvIdHold()
        reservations[key] = value
        reserved_ids.add(value)
        numbers.append(number)
    keys = [_key(value) for value in requested_keys]
    if len(set(keys)) != len(keys) or (keys and not observed): raise OnlineNvIdHold()
    highest = max(numbers) if numbers else None
    requested = []
    for key in sorted(keys):
        if key not in reservations:
            if highest is None or highest >= 99999: raise OnlineNvIdHold()
            highest += 1
            reservations[key] = f"NV{highest:05d}"
        requested.append((key, reservations[key]))
    frozen = tuple(sorted(reservations.items()))
    digest = hashlib.sha256((json.dumps({"observed": sorted(observed), "reservations": frozen,
                                        "requested": requested}, sort_keys=True, ensure_ascii=False,
                                       separators=(",", ":"), allow_nan=False) + "\n").encode()).hexdigest()
    return NvReservationPlan(frozen, tuple(requested), digest)
