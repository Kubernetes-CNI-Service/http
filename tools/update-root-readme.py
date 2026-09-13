#!/usr/bin/env python3
"""Atomically rebuild the root README's generated module-document catalog."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[1]
ROOT_README = ROOT / "README.md"
BEGIN = "<!-- BEGIN GENERATED DOCUMENTATION CATALOG -->"
END = "<!-- END GENERATED DOCUMENTATION CATALOG -->"


class CatalogError(RuntimeError):
    """The source catalog or destination does not satisfy the safe contract."""


class CatalogEntry(NamedTuple):
    """One canonical README and any repository-local compatibility aliases."""

    path: Path
    title: str
    category: str
    aliases: tuple[Path, ...]


def _excluded(relative: Path) -> bool:
    parts = relative.parts
    if relative == Path("README.md"):
        return True
    if any(part.startswith(".") or part == "node_modules" for part in parts):
        return True
    if parts[0] in {"download", "outputs", "package-imports"}:
        return True
    if parts[0] == "DAY0-Prepare" and len(parts) > 2:
        return True
    if any(part.startswith("99-output-") for part in parts):
        return True
    if (
        len(parts) > 4
        and parts[:3] == ("ztp", "optimize", "issue-tracker")
        and parts[3].startswith("OPT-")
    ):
        return True
    return False


def _candidate_readmes(root: Path) -> list[Path]:
    result: list[Path] = []
    for path in root.rglob("README.md"):
        relative = path.relative_to(root)
        if _excluded(relative):
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved_relative = resolved.relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise CatalogError(
                f"module README escapes the workspace or is broken: {relative}"
            ) from exc
        if not resolved.is_file():
            raise CatalogError(f"module README target must be regular: {relative}")
        if resolved.name != "README.md" or _excluded(resolved_relative):
            raise CatalogError(
                f"module README alias points to an excluded target: {relative}"
            )
        result.append(path)
    return sorted(result, key=lambda item: item.relative_to(root).as_posix())


def _title(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"#\s+(.+?)\s*", line)
        if match:
            return match.group(1).replace("|", "\\|")
    raise CatalogError(f"module README has no H1 title: {path}")


def _category(relative: Path) -> str:
    top = relative.parts[0]
    return {
        "apps": "基础设施",
        "DAY0-Prepare": "项目生命周期",
        "docs": "使用与架构",
        "ethernet": "采集与监控",
        "examples": "示例",
        "infiniband": "采集与监控",
        "infra": "基础设施",
        "monitor": "采集与监控",
        "nvlink": "采集与监控",
        "test_cases": "验证与治理",
        "tools": "工具",
        "ztp": "ZTP 与配置",
    }.get(top, "其他")


def catalog_entries(root: Path) -> list[CatalogEntry]:
    """Return canonical README entries, coalescing symlinks by resolved target."""
    workspace = root.resolve(strict=True)
    groups: dict[Path, list[Path]] = {}
    for path in _candidate_readmes(root):
        groups.setdefault(path.resolve(strict=True), []).append(path)

    entries: list[CatalogEntry] = []
    for resolved, paths in groups.items():
        canonical = root / resolved.relative_to(workspace)
        if canonical not in paths:
            raise CatalogError(
                "module README alias target is not independently discoverable: "
                f"{paths[0].relative_to(root)}"
            )
        aliases = tuple(path for path in paths if path != canonical)
        relative = canonical.relative_to(root)
        entries.append(
            CatalogEntry(
                path=canonical,
                title=_title(canonical),
                category=_category(relative),
                aliases=aliases,
            )
        )
    return sorted(entries, key=lambda entry: entry.path.relative_to(root).as_posix())


def source_readmes(root: Path) -> list[Path]:
    """Return unique canonical READMEs using the documentation catalog contract."""
    return [entry.path for entry in catalog_entries(root)]


def generated_catalog(root: Path) -> str:
    entries = catalog_entries(root)
    if not entries:
        raise CatalogError("no module README files were discovered")
    rows = [
        "此表由 `tools/update-root-readme.py` 生成；源 README 保持在所属模块，"
        "这里仅保留去重后的入口。历史 issue 详情由各自索引导航，不在根文档重复展开。",
        "",
        "| 分类 | 文档 | 兼容别名 |",
        "|---|---|---|",
    ]
    for entry in entries:
        relative = entry.path.relative_to(root).as_posix()
        aliases = "<br>".join(
            f"`{alias.relative_to(root).as_posix()}`" for alias in entry.aliases
        ) or "—"
        rows.append(
            f"| `{entry.category}` | [{entry.title}]({relative}) | {aliases} |"
        )
    return "\n".join(rows)


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
    entries = catalog_entries(ROOT)
    rendered = render_root_readme(current, generated_catalog(ROOT))
    if current == rendered:
        print(f"[OK] README catalog is current ({len(entries)} unique READMEs)")
        return 0
    if args.check:
        print("[ERROR] README catalog is stale; run tools/update-root-readme.py")
        return 1
    atomic_write(ROOT_README, rendered, metadata.st_mode)
    print(f"[OK] rebuilt README catalog ({len(entries)} unique READMEs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
