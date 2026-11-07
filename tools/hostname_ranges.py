"""Device-name ranges shared by every script that lists or selects devices (R-002, R-003; P3b).

compress(hostnames) -> lines (R-002, owner 2026-10-26)
  Names that differ in one segment only fold into one "[start-end]" line.  A segment is a run of digits
  or a single letter.  The text before and after the segment must be the same (compared without case,
  printed as written in the first name of the line); digits merge only with the same width, so 001
  stays 001 and 9 never joins 010; a gap starts a new line; letters merge one at a time and
  case-sensitively (a and A are not neighbours).  One range per line: each name merges on its rightmost
  segment that differs among names otherwise equal to it, the other segments group (so pods a-d x leaf
  01-12 give four lines).  A run of one is the plain name.  Lines follow the natural order of their
  first name.  The caller adds any "- " prefix (P3b point 9).

parse_selector(text, *, option="--devices", allow_all=False) -> Selector (R-003, owner 2026-10-26)
  A comma list in one argument; blanks around an item are dropped and an empty item is an error.  An
  item is host-name text ([A-Za-z0-9._-]) combined freely with "*" (any characters), digit ranges
  "[001-039]" (both ends the same width; the range takes exactly that many digits) and single-letter
  ranges "[a-d]" (case-sensitive; both ends the same case).  Everything else ("?", "[abc]", "[!a-c]",
  "[1-12]", "[a-D]", "[a-9]", "[aa-ad]", a start after its end, an unfinished bracket) raises
  SelectorError naming the option, the item and the three supported forms.  "all" alone selects every
  device only when allow_all is true (I-037 --direct-access); otherwise it is an ordinary name.  Every
  line of compress() is a valid item (R-003 Q6 A).

select(selector, hostnames) -> the selected hosts in inventory order (P3b point 1)
  An item with "." is compared with the CSV value, an item without "." with the display short name of
  tools/device_identity.py; both ignore case except inside letter ranges.  Ranges are matched in place
  by a backtracking matcher, so "*leaf[01-05]*" finds leaf03 in "leaf03leaf99".  The items that match
  no device are listed in one SelectorError (P3b point 4).

Library module: no command line; a caller turns SelectorError into its usage error (exit 2).  Import
it as tools.hostname_ranges with the repository root on sys.path.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from tools.device_identity import short_name

ALL = "all"
FORMS = ("supported forms: literal text with * (ew-leaf*), a digit range with both ends the same width "
         "(ew-leaf[001-039]), a single-letter range, case-sensitive (ib-pod[a-d])")
_SEGMENT = re.compile(r"[0-9]+|[A-Za-z]")
_PIECE = re.compile(r"\*+|\[([^\[\]]*)\]|[A-Za-z0-9._-]+")
_DIGIT_RANGE = re.compile(r"([0-9]+)-([0-9]+)")
_LETTER_RANGE = re.compile(r"([A-Za-z])-([A-Za-z])")
_DIGITS = re.compile(r"[0-9]+")


class SelectorError(ValueError):
    """An invalid selector value, or items that match no device; the message names the option."""


@dataclass(frozen=True)
class Selector:
    """A parsed selector.  `patterns` holds (item, compare-full-name, pieces); a piece is ("*",),
    ("text", casefolded literal), ("digits", low, high, width) or ("letter", low, high)."""
    patterns: tuple
    select_all: bool
    option: str


def compress(hostnames: Iterable[str]) -> list[str]:
    names = list(dict.fromkeys(hostnames))
    segments = {name: [match.span() for match in _SEGMENT.finditer(name)] for name in names}

    def key(name: str, start: int, end: int) -> tuple:
        text = name[start:end]
        shape = ("digits", len(text)) if text.isdigit() else ("letter", text.islower())
        return name[:start].casefold(), shape, name[end:].casefold()

    values: dict[tuple, set] = {}
    for name in names:
        for start, end in segments[name]:
            values.setdefault(key(name, start, end), set()).add(name[start:end])

    lines = []                       # (first name, line)
    groups: dict[tuple, dict] = {}   # key of the merging segment -> {segment value: (name, start, end)}
    for name in names:
        varying = [span for span in segments[name] if len(values[key(name, *span)]) > 1]
        if not varying:
            lines.append((name, name))
            continue
        start, end = varying[-1]
        groups.setdefault(key(name, start, end), {}).setdefault(name[start:end], (name, start, end))

    for members in groups.values():
        number = int if next(iter(members)).isdigit() else ord
        order = sorted(members, key=number)
        runs = [[order[0]]]
        for value in order[1:]:
            if number(value) - number(runs[-1][-1]) == 1:
                runs[-1].append(value)
            else:
                runs.append([value])
        for run in runs:
            name, start, end = members[run[0]]
            lines.append((name, name if len(run) == 1 else f"{name[:start]}[{run[0]}-{run[-1]}]{name[end:]}"))

    def natural(entry: tuple) -> tuple:
        first = entry[0]
        return [int(part) if part.isdigit() else part.casefold() for part in re.split(r"([0-9]+)", first)], first

    return [line for _, line in sorted(lines, key=natural)]


def parse_selector(text: str, *, option: str = "--devices", allow_all: bool = False) -> Selector:
    if allow_all and text.strip() == ALL:
        return Selector((), True, option)
    patterns = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            raise SelectorError(f"{option}: empty item in {text!r}; {FORMS}")
        pieces, position = [], 0
        while position < len(item):
            match = _PIECE.match(item, position)
            if match is None:
                raise SelectorError(f"{option}: {item!r}: {item[position]!r} is not supported; {FORMS}")
            piece, inside = match.group(), match.group(1)
            if piece.startswith("*"):
                pieces.append(("*",))
            elif inside is None:
                pieces.append(("text", piece.casefold()))
            elif _DIGIT_RANGE.fullmatch(inside):
                low, high = inside.split("-")
                if len(low) != len(high) or int(low) > int(high):
                    raise SelectorError(f"{option}: {item!r}: {piece} needs two ends of the same width, "
                                        f"the start not after the end; {FORMS}")
                pieces.append(("digits", int(low), int(high), len(low)))
            elif _LETTER_RANGE.fullmatch(inside):
                low, high = inside[0], inside[2]
                if low.islower() != high.islower() or low > high:
                    raise SelectorError(f"{option}: {item!r}: {piece} needs two letters of the same case, "
                                        f"the start not after the end; {FORMS}")
                pieces.append(("letter", low, high))
            else:
                raise SelectorError(f"{option}: {item!r}: {piece} is not a range; {FORMS}")
            position = match.end()
        patterns.append((item, "." in item, tuple(pieces)))
    return Selector(tuple(patterns), False, option)


def _matches(pieces: tuple, subject: str) -> bool:
    failed: set = set()

    def at(index: int, offset: int) -> bool:
        if (index, offset) in failed:
            return False
        if index == len(pieces):
            return offset == len(subject)
        piece = pieces[index]
        if piece[0] == "*":
            found = any(at(index + 1, end) for end in range(offset, len(subject) + 1))
        elif piece[0] == "text":
            end = offset + len(piece[1])
            found = subject[offset:end].casefold() == piece[1] and at(index + 1, end)
        elif piece[0] == "digits":
            end = offset + piece[3]
            digits = subject[offset:end]
            found = len(digits) == piece[3] and bool(_DIGITS.fullmatch(digits)) \
                and piece[1] <= int(digits) <= piece[2] and at(index + 1, end)
        else:
            found = offset < len(subject) and piece[1] <= subject[offset] <= piece[2] and at(index + 1, offset + 1)
        if not found:
            failed.add((index, offset))
        return found

    return at(0, 0)


def select(selector: Selector, hostnames: Iterable[str]) -> list[str]:
    names = list(hostnames)
    if selector.select_all:
        return names
    chosen, unmatched = set(), []
    for item, full_name, pieces in selector.patterns:
        hits = {name for name in names if _matches(pieces, name if full_name else short_name(name))}
        if not hits:
            unmatched.append(item)
        chosen |= hits
    if unmatched:
        raise SelectorError(f"{selector.option}: no device matches {', '.join(unmatched)}")
    return [name for name in names if name in chosen]
