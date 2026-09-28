#!/usr/bin/env python3
"""Require a committed exact full-suite proof for every pushed Git tip.

The full proof remains byte-based and environment-bound.  This gate adds the
Git transport boundary: the pushed object must be the checked-out HEAD and the
tracked approval ledger in that commit must be byte-for-byte identical to the
ledger validated by ``run_related_tests.py --check --require-full``.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "test_cases/run_related_tests.py"
APPROVALS_RELATIVE = "test_cases/script_test_approved_hashes.json"
ZERO_OID = re.compile(r"^0+$")
OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class PushProofError(RuntimeError):
    """The push cannot prove the exact governed bytes being transferred."""


def _git(*arguments: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", os.fspath(ROOT), *arguments],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _git_stdout(*arguments: str) -> bytes:
    completed = _git(*arguments)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise PushProofError(detail or f"git {' '.join(arguments)} failed")
    return completed.stdout


def parse_updates(lines: list[str]) -> list[tuple[str, str, str, str]]:
    updates: list[tuple[str, str, str, str]] = []
    for number, raw in enumerate(lines, 1):
        fields = raw.rstrip("\n").split()
        if not fields:
            continue
        if len(fields) != 4:
            raise PushProofError(f"malformed pre-push update at stdin line {number}")
        local_ref, local_oid, remote_ref, remote_oid = fields
        if not OID.fullmatch(local_oid) or not OID.fullmatch(remote_oid):
            raise PushProofError(f"invalid object id at stdin line {number}")
        updates.append((local_ref, local_oid, remote_ref, remote_oid))
    return updates


def require_committed_current_proof(local_oids: set[str]) -> None:
    head = _git_stdout("rev-parse", "HEAD").decode("ascii").strip()
    non_deletions = {oid for oid in local_oids if not ZERO_OID.fullmatch(oid)}
    if not non_deletions:
        return
    if non_deletions != {head}:
        raise PushProofError(
            "每个待推送分支/标签必须指向当前 checkout 的 HEAD；"
            "请 checkout 对应 tip，完成正式 load 后再 push"
        )

    tracked = _git("ls-files", "--error-unmatch", "--", APPROVALS_RELATIVE)
    if tracked.returncode != 0:
        raise PushProofError(f"full proof 未被 Git 跟踪：{APPROVALS_RELATIVE}")
    committed = _git_stdout("show", f"HEAD:{APPROVALS_RELATIVE}")
    try:
        working = (ROOT / APPROVALS_RELATIVE).read_bytes()
    except OSError as exc:
        raise PushProofError(f"无法读取 full proof：{exc}") from exc
    if committed != working:
        raise PushProofError(
            "full proof 尚未提交到待推送 HEAD；请提交 approval ledger 后重试"
        )

    validation_value = os.environ.get("HTTP_VALIDATION_ONLY", "")
    if validation_value not in {"", "1"}:
        raise PushProofError("HTTP_VALIDATION_ONLY 只能为空或精确设置为 1")
    validation_only = validation_value == "1"
    command = [
        sys.executable, "-B", os.fspath(RUNNER), "--check", "--require-full",
    ]
    if validation_only:
        command.append("--validation-only")
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise PushProofError(
            "待推送 HEAD 没有与当前受管字节和执行环境匹配的正式 full proof "
            f"(exit={completed.returncode})；请先成功执行本机正式 load"
        )


def main() -> int:
    try:
        updates = parse_updates(list(sys.stdin))
        require_committed_current_proof({item[1] for item in updates})
    except PushProofError as exc:
        print(f"[BLOCK] {exc}", file=sys.stderr)
        return 1
    intent = "validation-only" if os.environ.get("HTTP_VALIDATION_ONLY") == "1" else "release"
    print(f"[OK] 待推送 HEAD 包含已提交且仍有效的精确 {intent} full proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
