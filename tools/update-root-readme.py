#!/usr/bin/env python3
"""Atomically rebuild the root README's generated module-document catalog."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ROOT_README = ROOT / "README.md"
BEGIN = "<!-- BEGIN EMBEDDED READMES -->"
END = "<!-- END EMBEDDED READMES -->"


class CatalogError(RuntimeError):
    """The source catalog or destination does not satisfy the safe contract."""


def source_readmes(root: Path) -> list[Path]:
    """Return source-module READMEs using the repository documentation contract."""
    result = []
    for path in root.rglob("README.md"):
        relative = path.relative_to(root)
        parts = relative.parts
        if relative == Path("README.md"):
            continue
        if any(part.startswith(".") or part == "node_modules" for part in parts):
            continue
        if parts[0] == "DAY0-Prepare" and len(parts) > 2:
            continue
        if any(part.startswith("99-output-") for part in parts):
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise CatalogError(
                f"module README escapes the workspace or is broken: {relative}"
            ) from exc
        if not resolved.is_file():
            raise CatalogError(f"module README target must be regular: {relative}")
        result.append(path)
    return sorted(result, key=lambda item: item.relative_to(root).as_posix())


def generated_catalog(root: Path) -> str:
    sections = []
    for path in source_readmes(root):
        relative = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8").rstrip()
        sections.append(f"### `{relative}`\n\n{source}")
    if not sections:
        raise CatalogError("no module README files were discovered")
    return "\n\n".join(sections)


def render_root_readme(current: str, catalog: str) -> str:
    if current.count(BEGIN) != 1 or current.count(END) != 1:
        raise CatalogError("root README must contain exactly one catalog marker pair")
    prefix, remainder = current.split(BEGIN, 1)
    _old_catalog, suffix = remainder.split(END, 1)
    return f"{prefix}{BEGIN}\n\n{catalog.rstrip()}\n{END}{suffix}"


def _safe_destination(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CatalogError(f"cannot inspect {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise CatalogError("root README must be a non-symlink, single-link regular file")
    return metadata


def atomic_write(path: Path, content: str, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(mode))
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="rebuild or verify the generated README catalog",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="verify that README.md is current without writing it",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    metadata = _safe_destination(ROOT_README)
    current = ROOT_README.read_text(encoding="utf-8")
    readmes = source_readmes(ROOT)
    rendered = render_root_readme(current, generated_catalog(ROOT))
    if current == rendered:
        print(f"[OK] README catalog is current ({len(readmes)} module READMEs)")
        return 0
    if args.check:
        print("[ERROR] README catalog is stale; run tools/update-root-readme.py")
        return 1
    atomic_write(ROOT_README, rendered, metadata.st_mode)
    print(f"[OK] rebuilt README catalog ({len(readmes)} module READMEs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
