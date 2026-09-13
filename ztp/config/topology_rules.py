#!/usr/bin/env python3
"""Shared, dependency-free inventory classification rules."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from pathlib import Path
from typing import Optional, Union


@dataclass(frozen=True)
class InventorySection:
    """One ordered inventory section and its ordered glob patterns."""

    name: str
    patterns: tuple[str, ...]


def load_inventory_sections(path: Union[Path, str]) -> tuple[InventorySection, ...]:
    """Parse inventory rules while preserving section-first precedence."""
    ordered: list[tuple[str, list[str]]] = []
    seen_sections: set[str] = set()
    current: Optional[list[str]] = None
    in_metadata = False
    for line_number, raw_line in enumerate(
        Path(path).read_text(encoding="utf-8-sig").splitlines(), 1,
    ):
        line = raw_line.strip()
        if not line:
            current = None
            in_metadata = False
            continue
        if line.startswith("#"):
            continue
        if line.startswith("[[") and line.endswith("]]" ):
            if len(line) <= 4 or not line[2:-2].strip():
                raise ValueError(f"invalid inventory metadata header at line {line_number}")
            current = None
            in_metadata = True
            continue
        if line.startswith("[") and line.endswith("]"):
            if in_metadata:
                continue
            name = line[1:-1].strip()
            if not name or "[" in name or "]" in name:
                raise ValueError(f"invalid inventory section at line {line_number}")
            key = name.casefold()
            if key in seen_sections:
                raise ValueError(
                    f"duplicate inventory section {name!r} at line {line_number}"
                )
            seen_sections.add(key)
            patterns: list[str] = []
            ordered.append((name, patterns))
            current = patterns
            continue
        if line.startswith("[") or line.endswith("]"):
            raise ValueError(f"malformed inventory header at line {line_number}")
        if in_metadata:
            continue
        if current is None:
            raise ValueError(f"orphan inventory pattern at line {line_number}")
        current.append(line)
    return tuple(InventorySection(name, tuple(patterns)) for name, patterns in ordered)


def legacy_inventory(
    sections: tuple[InventorySection, ...],
) -> tuple[dict[str, list[str]], list[str]]:
    """Return the historical ``patterns, order`` representation."""
    return (
        {section.name: list(section.patterns) for section in sections},
        [section.name for section in sections],
    )


def load_inventory(path: Union[Path, str]) -> tuple[dict[str, list[str]], list[str]]:
    """Load inventory in the historical representation."""
    return legacy_inventory(load_inventory_sections(path))


def sections_from_legacy(
    patterns: dict[str, list[str]], order: list[str],
) -> tuple[InventorySection, ...]:
    """Adapt historical caller-owned structures without changing precedence."""
    return tuple(
        InventorySection(name, tuple(patterns.get(name, ())))
        for name in order
    )


def resolve_inventory_device_type(
    name: str,
    sections_or_patterns: Union[tuple[InventorySection, ...], dict[str, list[str]]],
    order: Optional[list[str]] = None,
) -> str:
    """Return the first matching section; never apply longest-pattern wins."""
    sections = (
        sections_from_legacy(sections_or_patterns, order or [])
        if isinstance(sections_or_patterns, dict)
        else sections_or_patterns
    )
    candidate = name.casefold()
    for section in sections:
        if any(
            fnmatch.fnmatchcase(candidate, pattern.casefold())
            for pattern in section.patterns
        ):
            return section.name
    return "unknown"
