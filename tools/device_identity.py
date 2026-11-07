"""Device identity shared by every script: short host names and MAC addresses (P3b; I-007, I-018, I-041).

Host names (I-007, owner 2026-11-01):
- `short_name` is the display short name and keeps the case as written (the --devices letter ranges
  and the R-004 /etc/hosts entries need it); `short_key` is the same name casefolded, for comparing.
  Both follow rule 6: trim surrounding blanks, drop trailing ".", take the part before the first ".";
  never split on "-" or "_".
- Two names are the same device when their short keys are equal (rule 4).  Short keys must be unique
  (rule 5): `duplicate_short_names` lists every clash and `resolve` refuses to guess between several
  hosts.  There is no fuzzy matching (rule 7): no endswith, no dropping "-" or "_"; an alias needs an
  explicit alias file.

MAC addresses (I-018; P3b points 5-7, owner 2026-11-07):
- `normalize_mac` accepts ":", "-", "." or no separator, in any mix and case, and returns the lowercase
  colon form.  A missing value (blank or one of the NA words) gives "".  Anything else that does not
  leave exactly 12 hexadecimal digits once ".:-" are removed (one digit per group, blank-separated
  groups, other characters) raises ValueError naming the value.
- `eth1_follows_eth0` answers the I-041 hint: is eth1_mac eth0_mac + 1 as a 48-bit number.

Library module: no command line; callers own printing and exit codes.  The MAC rule is pinned by the
shared fixture test_cases/fixtures/mac_spellings.tsv.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

# P3b point 5: the union of setup `_vna`, load `_device_csv_na` and initial-setup/UFM `NA_VALUES`.
MAC_NA_WORDS = frozenset({"", "na", "n/a", "none", "null", "tbd", "-"})
_MAC_SEPARATORS = re.compile(r"[.:-]")
_MAC_DIGITS = re.compile(r"[0-9A-Fa-f]{12}")


class AmbiguousNameError(ValueError):
    """More than one host has the short name asked for (I-007 rule 5)."""


def short_name(hostname: str) -> str:
    """The display short name: blanks and trailing dots removed, the part before the first ".", case kept."""
    return hostname.strip().rstrip(".").split(".", 1)[0]


def short_key(hostname: str) -> str:
    """The short name for comparisons (casefolded)."""
    return short_name(hostname).casefold()


def same_device(a: str, b: str) -> bool:
    return short_key(a) == short_key(b)


def duplicate_short_names(hostnames: Iterable[str]) -> dict[str, list[str]]:
    """Short keys used by more than one host, each with its hosts in input order."""
    groups: dict[str, list[str]] = {}
    for hostname in hostnames:
        groups.setdefault(short_key(hostname), []).append(hostname)
    return {key: names for key, names in groups.items() if len(names) > 1}


def resolve(name: str, hostnames: Iterable[str]) -> Optional[str]:
    """The one host whose short name is the short name of `name`; None when there is none.

    Raises AmbiguousNameError when several hosts share that short name.
    """
    key = short_key(name)
    matches = [hostname for hostname in hostnames if short_key(hostname) == key]
    if len(matches) > 1:
        raise AmbiguousNameError(f"{name!r} matches {len(matches)} hosts: {', '.join(matches)}")
    return matches[0] if matches else None


def normalize_mac(value: str) -> str:
    """The lowercase colon form of a MAC cell, "" when it is missing; ValueError when it is not a MAC."""
    text = value.strip()
    if text.casefold() in MAC_NA_WORDS:
        return ""
    digits = _MAC_SEPARATORS.sub("", text)
    if not _MAC_DIGITS.fullmatch(digits):
        raise ValueError(f"invalid MAC address: {value!r}")
    digits = digits.lower()
    return ":".join(digits[index:index + 2] for index in range(0, 12, 2))


def eth1_follows_eth0(eth0: str, eth1: str) -> Optional[bool]:
    """True when eth1 is eth0 + 1 (carries included), False when it is not, None when either is missing."""
    first, second = normalize_mac(eth0), normalize_mac(eth1)
    if not first or not second:
        return None
    return int(second.replace(":", ""), 16) == int(first.replace(":", ""), 16) + 1
