#!/usr/bin/env python3
"""Shared normalization for compact selectors emitted by ``nv config show``.

NVUE uses mapping keys such as ``swp1-8s0-3`` and ``bond1-36s0-1`` to
apply one block to many interfaces.  Consumers must expand those keys before
comparing or reverse-parsing configuration, otherwise common bond/bridge
attributes appear to be missing from the individual interfaces.
"""

import copy
import re


MAX_EXPANDED_SELECTOR_ITEMS = 10_001


def expand_nvue_selector(key):
    """Expand one compact NVUE selector, failing closed on ambiguity/overflow."""
    key = str(key)
    if "," not in key and not re.search(r"\d-\d", key):
        return [key]
    expanded = []
    prefix = ""
    suffix = ""
    major = None
    suffix_kind = ""

    def append_range(values):
        pending = []
        for value in values:
            pending.append(value)
            if len(expanded) + len(pending) > MAX_EXPANDED_SELECTOR_ITEMS:
                return False
        if not pending:
            return False
        expanded.extend(pending)
        return True

    def checked_range(start, end):
        if end < start or end - start > 10_000:
            return None
        return range(start, end + 1)

    for token in key.split(","):
        token = token.strip()

        # Breakout selectors have independent physical-port and lane axes.
        # Examples: swp1s0-3, swp1-2s0-3, bond1-36s0-1.
        breakout = re.fullmatch(
            r"([A-Za-z_][A-Za-z_-]*)(\d+)(?:-(\d+))?"
            r"s(\d+)(?:-(\d+))?",
            token,
        )
        if breakout:
            prefix = breakout.group(1)
            major_start = int(breakout.group(2))
            major_end = int(breakout.group(3) or major_start)
            minor_start = int(breakout.group(4))
            minor_end = int(breakout.group(5) or minor_start)
            majors = checked_range(major_start, major_end)
            minors = checked_range(minor_start, minor_end)
            if majors is None or minors is None:
                return [key]
            if not append_range(
                f"{prefix}{port}s{lane}"
                for port in majors
                for lane in minors
            ):
                return [key]
            major = major_start if major_start == major_end else None
            suffix = f"s{minor_start}"
            suffix_kind = "breakout"
            continue

        # A later token can omit only the alphabetic prefix.
        breakout = re.fullmatch(
            r"(\d+)(?:-(\d+))?s(\d+)(?:-(\d+))?",
            token,
        )
        if breakout:
            if not prefix:
                return [key]
            major_start = int(breakout.group(1))
            major_end = int(breakout.group(2) or major_start)
            minor_start = int(breakout.group(3))
            minor_end = int(breakout.group(4) or minor_start)
            majors = checked_range(major_start, major_end)
            minors = checked_range(minor_start, minor_end)
            if majors is None or minors is None:
                return [key]
            if not append_range(
                f"{prefix}{port}s{lane}"
                for port in majors
                for lane in minors
            ):
                return [key]
            major = major_start if major_start == major_end else None
            suffix = f"s{minor_start}"
            suffix_kind = "breakout"
            continue

        # Lane-only shorthand keeps the preceding single physical port.
        breakout = re.fullmatch(r"s(\d+)(?:-(\d+))?", token)
        if breakout:
            if not prefix or major is None or suffix_kind != "breakout":
                return [key]
            minor_start = int(breakout.group(1))
            minor_end = int(breakout.group(2) or minor_start)
            minors = checked_range(minor_start, minor_end)
            if minors is None or not append_range(
                f"{prefix}{major}s{lane}" for lane in minors
            ):
                return [key]
            suffix = f"s{minor_start}"
            continue

        match = re.fullmatch(
            r"([A-Za-z_][A-Za-z_-]*)(\d+)"
            r"((?:s\d+)|(?:\.[A-Za-z0-9_-]+)|(?:_[A-Za-z0-9_-]+))?"
            r"(?:-(\d+))?",
            token,
        )
        if match:
            prefix = match.group(1)
            start = int(match.group(2))
            major = start
            suffix = match.group(3) or ""
            suffix_kind = (
                "dot" if suffix.startswith(".")
                else "other" if suffix
                else "major"
            )
            end = int(match.group(4) or start)
        else:
            match = re.fullmatch(
                r"(\d+)((?:s\d+)|(?:\.[A-Za-z0-9_-]+)|"
                r"(?:_[A-Za-z0-9_-]+))?(?:-(\d+))?",
                token,
            )
            if not match:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", token):
                    expanded.append(token)
                    continue
                return [key]
            start = int(match.group(1))
            token_suffix = match.group(2)
            end = int(match.group(3) or start)
            if token_suffix is None and suffix.startswith(".") and major is not None:
                numbers = checked_range(start, end)
                if numbers is None or not append_range(
                    f"{prefix}{major}.{number}" for number in numbers
                ):
                    return [key]
                continue
            if token_suffix is None and suffix_kind == "breakout":
                if major is None:
                    return [key]
                numbers = checked_range(start, end)
                if numbers is None or not append_range(
                    f"{prefix}{major}s{number}" for number in numbers
                ):
                    return [key]
                continue
            if token_suffix is not None:
                suffix = token_suffix
                suffix_kind = (
                    "dot" if suffix.startswith(".")
                    else "breakout" if suffix.startswith("s")
                    else "other"
                )
        numbers = checked_range(start, end)
        if numbers is None or not append_range(
            f"{prefix}{number}{suffix}" for number in numbers
        ):
            return [key]
    return expanded


def deep_merge_nvue(current, update):
    """Recursively merge an NVUE mapping, copying all inserted values."""
    if isinstance(current, dict) and isinstance(update, dict):
        for key, value in update.items():
            if key in current:
                current[key] = deep_merge_nvue(current[key], value)
            else:
                current[key] = copy.deepcopy(value)
        return current
    return copy.deepcopy(update)


def normalize_nvue_selectors(value):
    """Recursively expand selectors and merge common blocks into each key."""
    if isinstance(value, list):
        return [normalize_nvue_selectors(item) for item in value]
    if not isinstance(value, dict):
        return value

    normalized = {}
    entries = []
    for key, child in value.items():
        keys = expand_nvue_selector(key)
        entries.append((
            0 if len(keys) > 1 else 1,
            keys,
            normalize_nvue_selectors(child),
        ))
    # Common selectors apply first; explicit keys then override them.
    for _priority, keys, child in sorted(entries, key=lambda item: item[0]):
        for key in keys:
            if key in normalized:
                normalized[key] = deep_merge_nvue(normalized[key], child)
            else:
                normalized[key] = copy.deepcopy(child)
    return normalized
