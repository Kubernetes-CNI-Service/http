"""Parser for OpenSM `partitions.conf`.

Returns a list of partition dicts — see specification.MD §6.2 for the schema.
"""

from __future__ import annotations

import re
from pathlib import Path


_GUID_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_KEYWORDS = frozenset({"ALL", "ALL_CAS", "ALL_SWITCHES", "ALL_ROUTERS", "SELF"})
_MEMBERSHIP = frozenset({"full", "limited", "both"})


def _normalize_pkey(pkey_str: str) -> str:
    """Normalise PKey to lowercase `0x` + minimum-width hex (no leading zeros).

    `0x0115` → `0x115`, `0x7FFF` → `0x7fff`, `0x1` → `0x1`. Preserves the
    natural width admins use in `partitions.conf` while canonicalising case
    and stripping superfluous left-padding so two spellings of the same PKey
    collapse to one key.

    Raises ValueError on non-hex input or values ≥ 0x8000 (PKeys are 15-bit).
    """
    s = pkey_str.strip().lower()
    if not s.startswith("0x"):
        raise ValueError(f"PKey must be hex with 0x prefix: {pkey_str!r}")
    try:
        val = int(s, 16)
    except ValueError as exc:
        raise ValueError(f"Invalid PKey hex: {pkey_str!r}") from exc
    if val >= 0x8000:
        raise ValueError(
            f"PKey must be 15-bit (0x0000–0x7fff): {pkey_str!r}"
        )
    return f"0x{val:x}"


def _normalize_guid(guid_str: str) -> str:
    """Normalise GUID to lowercase `0x` + 16 hex chars; empty string on invalid."""
    s = guid_str.strip().lower()
    if not s.startswith("0x"):
        return ""
    hex_part = s[2:].lstrip("0") or "0"
    return "0x" + hex_part.zfill(16)


def _parse_header(hdr: str) -> dict | None:
    """Parse the part before ':' — 'Name=PKey,flag1,flag2=val,...'."""
    hdr = hdr.strip()
    if not hdr:
        return None

    parts = [p.strip() for p in hdr.split(",") if p.strip()]
    if not parts:
        return None

    # First element: 'Name=PKey' (name may be empty: '=0x1234').
    first = parts[0]
    if "=" not in first:
        # Auto-generated PKey case (rare) — not supported.
        return None
    name, pkey_raw = first.split("=", 1)
    name = name.strip()
    try:
        pkey = _normalize_pkey(pkey_raw)
    except ValueError:
        return None

    flags = {"indx0": False, "ipoib": False,
             "rate": None, "mtu": None, "sl": None, "scope": None}
    defmember = "limited"

    for flag in parts[1:]:
        if "=" in flag:
            k, v = flag.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "defmember":
                if v in _MEMBERSHIP:
                    defmember = v
            elif k in ("rate", "mtu", "sl", "scope"):
                try:
                    flags[k] = int(v)
                except ValueError:
                    pass
        else:
            kl = flag.lower()
            if kl == "indx0":
                flags["indx0"] = True
            elif kl == "ipoib":
                flags["ipoib"] = True

    return {"name": name, "pkey": pkey, "flags": flags, "defmember": defmember}


def _parse_member_list(body: str, defmember: str) -> list[dict]:
    """Parse the part after ':' — 'GUID[=type],KEYWORD[=type],…'."""
    body = body.strip()
    if not body:
        return []

    out: list[dict] = []
    for entry in (e.strip() for e in body.split(",")):
        if not entry:
            continue
        if "=" in entry:
            ident, mem = entry.split("=", 1)
            ident = ident.strip()
            mem = mem.strip().lower()
            if mem not in _MEMBERSHIP:
                mem = defmember
        else:
            ident = entry
            mem = defmember

        ident_upper = ident.upper()
        if ident_upper in _KEYWORDS:
            out.append({"kind": "keyword", "keyword": ident_upper, "membership": mem})
        elif _GUID_RE.match(ident):
            g = _normalize_guid(ident)
            if g:
                out.append({"kind": "guid", "guid": g, "membership": mem})
        # else: unknown entry — silently dropped
    return out


def _default_mgmt_partition() -> dict:
    """Synthesise the default management partition when partitions.conf omits 0x7fff.

    Equivalent to:
        management=0x7fff, ipoib, sl=0, defmember=full :
            ALL, ALL_SWITCHES=full, SELF=full ;
    """
    return {
        "name": "management",
        "pkey": "0x7fff",
        "flags": {
            "indx0": False, "ipoib": True,
            "rate": None, "mtu": None, "sl": 0, "scope": None,
        },
        "defmember": "full",
        "members": [
            {"kind": "keyword", "keyword": "ALL", "membership": "full"},
            {"kind": "keyword", "keyword": "ALL_SWITCHES", "membership": "full"},
            {"kind": "keyword", "keyword": "SELF", "membership": "full"},
        ],
    }


def parse_partitions_conf(path: Path) -> list[dict]:
    """Parse `partitions.conf` → list of partition dicts.

    See specification.MD §6.2 for the full output schema.
    """
    raw = Path(path).read_text(encoding="utf-8", errors="replace")

    # Strip comments ('#' to EOL) per line, then join everything and split on ';'.
    stripped_lines = []
    for ln in raw.splitlines():
        i = ln.find("#")
        if i >= 0:
            ln = ln[:i]
        stripped_lines.append(ln)
    text = " ".join(stripped_lines)

    records = [r.strip() for r in text.split(";")]
    records = [r for r in records if r]

    # Each record → one parsed partition. Keep insertion order but merge
    # records that share the same PKey (common convention: every explicit
    # GUID member is declared on its own line with the same partition header).
    partition_order: list[str] = []
    by_pkey: dict[str, dict] = {}

    for record in records:
        if ":" in record:
            header_part, members_part = record.split(":", 1)
        else:
            header_part, members_part = record, ""

        hdr = _parse_header(header_part)
        if hdr is None:
            continue
        new_members = _parse_member_list(members_part, hdr["defmember"])

        pkey = hdr["pkey"]
        if pkey in by_pkey:
            # Merge into the existing partition record.
            existing = by_pkey[pkey]
            # Union boolean flags; keep first-seen numeric flag.
            for bflag in ("indx0", "ipoib"):
                existing["flags"][bflag] = existing["flags"][bflag] or hdr["flags"][bflag]
            for nflag in ("rate", "mtu", "sl", "scope"):
                if existing["flags"][nflag] is None:
                    existing["flags"][nflag] = hdr["flags"][nflag]
            # Append member entries; dedup identical (kind+id+membership) triples.
            seen = {_member_key(m) for m in existing["members"]}
            for m in new_members:
                if _member_key(m) not in seen:
                    existing["members"].append(m)
                    seen.add(_member_key(m))
        else:
            hdr["members"] = new_members
            by_pkey[pkey] = hdr
            partition_order.append(pkey)

    partitions = [by_pkey[pk] for pk in partition_order]

    if "0x7fff" not in by_pkey:
        partitions.insert(0, _default_mgmt_partition())

    return partitions


def _member_key(m: dict) -> tuple:
    """Dedup key for member entries across repeated same-PKey declarations."""
    if m["kind"] == "guid":
        return ("guid", m["guid"], m["membership"])
    return ("keyword", m["keyword"], m["membership"])
