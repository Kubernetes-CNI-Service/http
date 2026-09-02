#!/usr/bin/env python3
"""Shared deployment-project schema and transfer exclusion contract."""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re

GLOBAL_SCHEMA_VERSION = 1
ZTP_PREFIX_PUBLICATION_MARKER = ".ztp-prefix-publication.json"
_SAFE_ZTP_PREFIX = re.compile(
    r"/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*"
)
# Apache's static publication boundary reserves these physical/URL path
# components for management-server-only state.  Every producer and consumer
# of ztp_url_prefix must reject them up front; otherwise Apache would accept a
# prefix that can never serve the public bootstrap/config tree.
ZTP_PREFIX_RESERVED_SEGMENTS = frozenset({
    "day0-prepare", "status", "backup", "optimize",
})
ZTP_PREFIX_RESERVED_SEQUENCES = (
    ("monitor", "ztp-status"),
    ("config", "isc-dhcp-server"),
    ("config", "cumulus", "template"),
    ("config", "nvos", "template"),
)

ANALYSIS_TOOL_NAMES = frozenset({
    "ib-tool-Jie",
    "ibdiagnet-analyze-tool",
})
DEPLOYABLE_TOOL_SUBTREES = frozenset({"lldp-analyze-tool"})

NON_DEPLOYMENT_DIR_NAMES = frozenset({
    "test", "tests", "test_cases", "test-results", "__pycache__", ".pytest_cache",
})

# tools/ is primarily an entrypoint directory.  Top-level runtime source files
# are transferred; README files are documentation-only and always excluded.
# DEPLOYABLE_TOOL_SUBTREES lists the small runtime exception.
# Other subdirectories remain workstation-only analyzers, imports, or samples.
TOOLS_CODE_SUFFIXES = frozenset({".py", ".sh", ".js", ".cjs", ".mjs"})

MANUAL_BACKUP_PATTERNS = (
    "*_副本.*",
    "*_copy.*",
    "*_bak.*",
)


def validate_ztp_url_prefix(value: object) -> str:
    """Return a canonical Apache-reachable ZTP URL prefix.

    In addition to traversal-safe URL syntax, this rejects path components
    reserved by the Apache publication boundary.  Matching is case-insensitive
    and applies at every depth so a nested custom prefix cannot bypass the
    same policy that protects the real ``/var/www/html/ztp`` tree.
    """
    prefix = str(value or "").strip().rstrip("/")
    if (
        not _SAFE_ZTP_PREFIX.fullmatch(prefix)
        or any(part in {".", ".."} for part in prefix.split("/"))
    ):
        raise ValueError(
            "common.mgmt.ztp.ztp_url_prefix 必须是安全绝对 URL path，"
            "只能包含字母、数字、/、-、_、.、~"
        )

    parts = tuple(part.casefold() for part in prefix.lstrip("/").split("/"))
    if any(part in ZTP_PREFIX_RESERVED_SEGMENTS for part in parts):
        raise ValueError(
            "common.mgmt.ztp.ztp_url_prefix 使用了 Apache 保留发布路径"
        )
    for reserved in ZTP_PREFIX_RESERVED_SEQUENCES:
        width = len(reserved)
        if any(parts[index:index + width] == reserved
               for index in range(len(parts) - width + 1)):
            raise ValueError(
                "common.mgmt.ztp.ztp_url_prefix 使用了 Apache 保留发布路径"
            )
    return prefix


def is_manual_backup_name(name: str) -> bool:
    """Identify common ad-hoc backup copies that are not deployment inputs."""
    folded = name.casefold()
    return any(fnmatch.fnmatch(folded, pattern.casefold())
               for pattern in MANUAL_BACKUP_PATTERNS)


def is_readme_name(name: str) -> bool:
    """Return whether *name* is a README document in any common extension."""
    return Path(name).name.casefold().startswith("readme")


def ztp_prefix_publication_relative(root: Path | str) -> PurePosixPath | None:
    """Return the load-owned custom ZTP publication link below *root*.

    The marker and link are management-server runtime, not deployable source.
    A present marker is an ownership boundary: malformed metadata, an unsafe
    path, a symlinked parent, or a conflicting leaf raises ``ValueError`` so
    callers fail closed instead of transferring an untrusted path.

    A valid marker may outlive a missing leaf after an interrupted operation;
    callers that intend to delete runtime state must additionally require the
    returned leaf to exist and revalidate it immediately before mutation.
    """
    workspace = Path(root).resolve(strict=True)
    marker = workspace / ZTP_PREFIX_PUBLICATION_MARKER
    if not os.path.lexists(marker):
        return None
    if marker.is_symlink() or not marker.is_file():
        raise ValueError(f"ZTP prefix marker is not a regular file: {marker}")
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid ZTP prefix marker {marker}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"ZTP prefix marker must contain an object: {marker}")
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError("ZTP prefix marker schema_version must be 1")

    raw_prefix = payload.get("prefix")
    try:
        prefix = validate_ztp_url_prefix(raw_prefix)
    except ValueError as exc:
        raise ValueError(f"unsafe custom ZTP prefix: {raw_prefix!r}: {exc}") from exc
    if prefix == "/ztp":
        raise ValueError(f"unsafe custom ZTP prefix in marker: {prefix!r}")
    relative = PurePosixPath(prefix.lstrip("/"))
    if relative.parts[0] == "ztp":
        raise ValueError(f"custom ZTP prefix cannot be below /ztp: {prefix}")

    leaf = workspace.joinpath(*relative.parts)
    expected_target = workspace / "ztp"
    if expected_target.is_symlink() or not expected_target.is_dir():
        raise ValueError(f"ZTP runtime target is not a real directory: {expected_target}")
    if str(payload.get("path") or "") != str(leaf):
        raise ValueError("ZTP prefix marker prefix/path do not match this workspace")
    if str(payload.get("target") or "") != str(expected_target):
        raise ValueError("ZTP prefix marker target does not match this workspace")

    cursor = workspace
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"ZTP prefix parent must not be a symlink: {cursor}")
        if os.path.lexists(cursor) and not cursor.is_dir():
            raise ValueError(f"ZTP prefix parent is not a directory: {cursor}")
    if os.path.lexists(leaf):
        if not leaf.is_symlink():
            raise ValueError(f"managed ZTP prefix leaf is not a symlink: {leaf}")
        try:
            resolved = leaf.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"managed ZTP prefix symlink is invalid: {leaf}: {exc}") from exc
        if resolved != expected_target.resolve(strict=True):
            raise ValueError(
                f"managed ZTP prefix symlink has unexpected target: {leaf}"
            )
    return relative


def is_tools_deployable_file(path: PurePosixPath | str) -> bool:
    """Return whether a tools/ source file belongs on a management server."""
    value = PurePosixPath(path)
    if not value.parts or value.parts[0] != "tools":
        return False
    if len(value.parts) > 2:
        if value.parts[1] not in DEPLOYABLE_TOOL_SUBTREES:
            return False
        if any(part in {"node_modules", "99-output-p2p", "99-output-monitor"}
               for part in value.parts[2:]):
            return False
        return not is_readme_name(value.name) and (
            value.suffix.casefold() in TOOLS_CODE_SUFFIXES
        )
    if len(value.parts) != 2:
        return False
    return not is_readme_name(value.name) and (
        value.suffix.casefold() in TOOLS_CODE_SUFFIXES
    )


def transfer_exclude_reason(path: PurePosixPath | str) -> str | None:
    """Return why a path is not deployable, or None when it may be transferred."""
    value = PurePosixPath(path)
    parts = value.parts
    if is_readme_name(value.name):
        return "README documentation"
    if any(part in ANALYSIS_TOOL_NAMES for part in parts):
        return "offline analysis tool"
    if any(part in NON_DEPLOYMENT_DIR_NAMES for part in parts):
        return "test/development data"
    if any(part == ".DS_Store" or part.startswith("._") for part in parts):
        return "macOS metadata"
    if value.name.startswith("~$"):
        return "Office temporary file"
    if value.name.casefold().startswith("deprecated-"):
        return "deprecated input"
    if value.name == "infra-runtime.conf":
        return "host-specific infra runtime"
    if value.name == ZTP_PREFIX_PUBLICATION_MARKER:
        return "host-specific ZTP prefix runtime"
    if value.suffix == ".pyc":
        return "Python cache"
    return None


def rsync_excludes() -> tuple[str, ...]:
    """Patterns shared by every sync-code job."""
    return (
        ".DS_Store", "._*", "~$*", "DEPRECATED-*", "deprecated-*", "*.pyc", "*.bak",
        "*_副本.*", "*_copy.*", "*_bak.*",
        "__pycache__/", ".pytest_cache/", "test/", "tests/", "test_cases/", "test-results/",
        "ib-tool-Jie/", "ibdiagnet-analyze-tool/",
        "[Rr][Ee][Aa][Dd][Mm][Ee]*",
        "infra-runtime.conf", ZTP_PREFIX_PUBLICATION_MARKER,
    )
