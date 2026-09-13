#!/usr/bin/env python3
"""No-local-clone workflow proof for the reviewed S integration phase."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
Q02_COMMIT = "623bf4ec48203c3c02a3d0bf79271d6c4c637a2a"
EXPECTED_S_TREE_PATH_COUNT = 322
EXPECTED_S_TREE_PATH_DIGEST = (
    "ddf77456465cf22b193b87e8c687128e00f710b20466449e2cf8dc4ef805a52c"
)
EXPECTED_S_TREE_RECORD_DIGEST = (
    "a11eec6c47521374642d817c4c8399e119c282a31950fe34dab4ad8c638b3d24"
)
EXPECTED_S_STAGE_PATH_COUNT = 160
EXPECTED_S_STAGE_PATH_DIGEST = (
    "708f4674dc58e26e9a66ef67bde19d7caae32040775b08026fd9468be219c16a"
)
EXPECTED_S_COMMIT_OVERLAY_PATH_COUNT = 159
EXPECTED_S_COMMIT_OVERLAY_PATH_DIGEST = (
    "10a49d4696371801d7b0c7099661a3e38a020d703cea1f44f9ec289db50547c3"
)
S_LEDGER_PATH = "test_cases/script_test_approved_hashes.json"
S_PHASE_INDEX_PATHS = (
    ".github/README.md",
    "test_cases/README.md",
    "test_cases/REAL_ENVIRONMENT.md",
    "test_cases/script_test_manifest.json",
    "user-manual.html",
)
S_PHASE_TEST_PATHS = (
    "test_cases/test_public_s_phase_contract.py",
    "test_cases/test_public_s_phase_workflow.py",
)
S_SELF_RECORD_PATH = "test_cases/test_public_s_phase_workflow.py"
S_PHASE_DOC_TRANSFORMS = {
    ".github/README.md": {
        "source_sha256": "d6ef8e75f5e745c1991bea9c97d41b0f21ceb7653c0e9112faa84bf513dda35a",
        "remove": (
            "- `docs/` 中不含现场身份、地址或证据的通用架构、部署和验证导航；\n",
            "通用文档从 [`docs/README.md`](../docs/README.md) 开始；内部根 README/User Manual 和真实项目\n"
            "记录仍受公开边界隔离，不能因为 docs 索引存在而被纳入版本控制。\n\n",
        ),
        "target_size": 4452,
        "target_sha256": "12e5b057f055f123bc05fc2f0994d439e90caa3b99e74fe22b7c24d0878bfa33",
    },
    "test_cases/README.md": {
        "source_sha256": "f50686606e914d0aceb869ce97ca614fd2f02ebd96da0d370bbe59bb5490a8fd",
        "remove": (
            "四类交付制品的自动化与真实环境分工见\n"
            "[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)。\n\n",
        ),
        "target_size": 41382,
        "target_sha256": "bcc9c95bc6026dbd643466bf1a5c0869eb41c192d63c6d30005499fb88604fce",
    },
    "test_cases/REAL_ENVIRONMENT.md": {
        "source_sha256": "cb14298daca40852f2e9bdab169d9ad7704d3c27f2ca0ebd0229b25d00d2192a",
        "remove": (
            "四类 bundle 的边界和 `2026-12-vb-gb300` 场景选择见\n"
            "[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)；下面只登记必须在\n"
            "Ubuntu、Docker、adapter、网络隔离或真实设备上取得的证据。\n\n",
        ),
        "target_size": 78096,
        "target_sha256": "8f8ecb83ff4ae664bc669e0f3c7ce3261eb5fbb624edd402c1770d066de57424",
    },
}
S_HTML_SOURCE_SHA256 = "2a7ea2a7d1977a3ea1b4ac859c0c3af9e04d5e024be3904b043ff9bdf3da01f0"
S_HTML_STATIC_REMOVAL = "<code>infra/docker/README.md</code>、"
S_HTML_SEED_SHA256 = "9048f2835a59a042ca9777506f960b928f8399298d8dfc40b326aca477f3c9cf"
S_HTML_SKELETON_SIZE = 123465
S_HTML_SKELETON_SHA256 = (
    "e00256da6278b508f6ca83f9b350970f9e15c4957227d08ea3792f4dea9e972d"
)
S_HTML_TARGET_SIZE = 710570
S_HTML_TARGET_SHA256 = (
    "516c73b23bc5d74f332c7d649cf99a60fd52585f57db467e97ad53237411ca39"
)
S_HTML_FILE_BEGIN = "        <!-- BEGIN GENERATED USER MANUAL FILE CATALOG -->"
S_HTML_FILE_END = "        <!-- END GENERATED USER MANUAL FILE CATALOG -->"
S_HTML_SCRIPT_BEGIN = "        <!-- BEGIN GENERATED USER MANUAL SCRIPT REFERENCE -->"
S_HTML_SCRIPT_END = "        <!-- END GENERATED USER MANUAL SCRIPT REFERENCE -->"
Q01_PUBLIC_DOCUMENT_PATHS = (
    "docs/README.md", "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md", "docs/deployment/README.md",
    "docs/operations/README.md", "docs/reference/README.md",
    "docs/validation/README.md", "infra/docker/README.md",
)
LIFECYCLE_PATHS = tuple(
    f"docs/v3/finished-project-lifecycle/{name}.md"
    for name in (
        "ARCHITECTURE", "OPEN_QUESTIONS", "OVERVIEW", "REQUIREMENTS",
        "TEST_PLAN", "USER_GUIDE", "WORKFLOWS",
    )
)
PRIVATE_DOCUMENT_PATHS = (
    "README.md", "USER_MANUAL.md", "DAY0-Prepare/README.md", "infra/README.md",
    "monitor/README.md", "tools/README.md",
    "tools/ibdiagnet-analyze-tool/README.md", "tools/lldp-analyze-tool/README.md",
    "ztp/README.md", "ztp/config/cumulus/template/README.md",
    "ztp/config/cumulus/template/P2P/README.md",
    "ztp/config/nvos/template/P2P/README.md",
    "ztp/config/isc-dhcp-server/README.md", "ztp/optimize/issue-tracker/README.md",
    "ztp/optimize/issue-tracker/OPT-001-ethernet-scope-filter/README.md",
    "ztp/optimize/issue-tracker/OPT-002-dhcp-device-identity/README.md",
    "ztp/optimize/issue-tracker/OPT-003-vrf-bond-semantic-compare/README.md",
    "ztp/optimize/issue-tracker/OPT-004-multi-member-bond-roundtrip/README.md",
    "ztp/optimize/issue-tracker/OPT-005-report-sort-order/README.md",
    "ztp/optimize/issue-tracker/OPT-006-global-placeholder-backfill/README.md",
    "ztp/optimize/issue-tracker/OPT-007-mixed-bond-profile-alignment/README.md",
    "ztp/optimize/issue-tracker/OPT-008-oobofoob-dhcp-vs-static/README.md",
    "ztp/optimize/issue-tracker/OPT-009-script-rename-feedback/README.md",
)
CABLETRACKER_PATHS = tuple("""\
monitor/cabletracker-main/.env.example
monitor/cabletracker-main/.gitignore
monitor/cabletracker-main/.gitlab-ci.yml
monitor/cabletracker-main/Dockerfile
monitor/cabletracker-main/README.md
monitor/cabletracker-main/cabletracker_runner.py
monitor/cabletracker-main/docker-compose.yaml
monitor/cabletracker-main/mapping_v4.json
monitor/cabletracker-main/refresh_cvt_sum.py
monitor/cabletracker-main/requirements.txt
monitor/cabletracker-main/tests/fixtures/cvt_offline_sample.json
monitor/cabletracker-main/tests/test_cvt_sum.py
monitor/cabletracker-main/tests/test_offline_workflow.py
monitor/cabletracker-main/tmp.json""".splitlines())
P_PUBLICATION_TEST_PATHS = (
    "test_cases/test_public_publication_contract.py",
    "test_cases/test_public_publication_workflow.py",
)
S_DEFERRED_PATHS = (
    "Finished-projects/.gitignore",
    "Finished-projects/README.txt",
    "v3-requirements.md",
)
S_DEFERRED_DELTA_PATHS = ("PUBLIC_REPOSITORY.md",)


def _run(command, *, cwd: Path, timeout: int = 60):
    return subprocess.run(
        command, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=timeout,
    )


def _run_bytes(command, *, cwd: Path, timeout: int = 60):
    return subprocess.run(
        command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=timeout,
    )


def _nul_paths(payload: bytes, *, source: str) -> set[str]:
    fields = payload.split(b"\0")
    if not fields or fields[-1] != b"":
        raise AssertionError(f"{source} is not NUL terminated")
    result = set()
    for raw in fields[:-1]:
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AssertionError(f"non-UTF-8 path from {source}") from error
        if not relative or relative.startswith("/") or "\0" in relative:
            raise AssertionError(f"unsafe path from {source}: {relative!r}")
        if relative in result:
            raise AssertionError(f"duplicate path from {source}: {relative!r}")
        result.add(relative)
    return result


def _path_digest(paths) -> str:
    digest = hashlib.sha256()
    for relative in sorted(paths):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _phase_document_contract(relative: str, payload: bytes) -> tuple[str, bytes]:
    contract = S_PHASE_DOC_TRANSFORMS[relative]
    digest = hashlib.sha256(payload).hexdigest()
    if digest == contract["target_sha256"]:
        if len(payload) != contract["target_size"]:
            raise AssertionError(f"S documentation target size mismatch: {relative}")
        return "target", payload
    if digest != contract["source_sha256"]:
        raise AssertionError(f"unreviewed S documentation source: {relative}")
    target = payload
    for snippet in contract["remove"]:
        encoded = snippet.encode("utf-8")
        if target.count(encoded) != 1:
            raise AssertionError(
                f"S documentation transform is not exactly once: {relative}"
            )
        target = target.replace(encoded, b"", 1)
    if len(target) != contract["target_size"]:
        raise AssertionError(f"S documentation size mismatch: {relative}")
    if hashlib.sha256(target).hexdigest() != contract["target_sha256"]:
        raise AssertionError(f"S documentation digest mismatch: {relative}")
    return "source", target


def _expected_phase_documents() -> dict[str, bytes]:
    expected = {}
    for relative in S_PHASE_DOC_TRANSFORMS:
        _state, target = _phase_document_contract(
            relative, (ROOT / relative).read_bytes(),
        )
        expected[relative] = target
    return expected


def _expected_manifest_payload() -> bytes:
    from test_cases import test_public_s_phase_contract as direct_contract

    return direct_contract.expected_s_manifest_bytes()


def _html_contract(payload: bytes) -> tuple[str, bytes]:
    digest = hashlib.sha256(payload).hexdigest()
    if digest == S_HTML_TARGET_SHA256:
        if len(payload) != S_HTML_TARGET_SIZE:
            raise AssertionError("S user-manual target size mismatch")
        return "target", payload
    if digest != S_HTML_SOURCE_SHA256:
        raise AssertionError("unreviewed S user-manual source")
    removal = S_HTML_STATIC_REMOVAL.encode("utf-8")
    if payload.count(removal) != 1:
        raise AssertionError("S user-manual static transform is not exactly once")
    seed = payload.replace(removal, b"", 1)
    if hashlib.sha256(seed).hexdigest() != S_HTML_SEED_SHA256:
        raise AssertionError("S user-manual seed digest mismatch")
    text = seed.decode("utf-8")
    for marker in (
        S_HTML_FILE_BEGIN, S_HTML_FILE_END,
        S_HTML_SCRIPT_BEGIN, S_HTML_SCRIPT_END,
    ):
        if text.count(marker) != 1:
            raise AssertionError(f"ambiguous S user-manual marker: {marker}")
    if not (
        text.index(S_HTML_FILE_BEGIN) < text.index(S_HTML_FILE_END)
        < text.index(S_HTML_SCRIPT_BEGIN) < text.index(S_HTML_SCRIPT_END)
    ):
        raise AssertionError("S user-manual markers are out of order")
    return "source", seed


def _html_skeleton(payload: bytes) -> bytes:
    text = payload.decode("utf-8")
    for begin, end, placeholder in (
        (S_HTML_FILE_BEGIN, S_HTML_FILE_END, "<S-FILE-CATALOG>"),
        (S_HTML_SCRIPT_BEGIN, S_HTML_SCRIPT_END, "<S-SCRIPT-REFERENCE>"),
    ):
        if text.count(begin) != 1 or text.count(end) != 1:
            raise AssertionError("ambiguous S user-manual generated section")
        start = text.index(begin) + len(begin)
        finish = text.index(end, start)
        text = text[:start] + "\n" + placeholder + "\n" + text[finish:]
    return text.encode("utf-8")


def _expected_tree_paths() -> set[str]:
    from test_cases import test_public_s_phase_contract as direct_contract

    return (
        set(direct_contract.S_PRODUCTION_PATHS)
        | {module.replace(".", "/") + ".py"
           for module in direct_contract.S_TEST_MODULES}
        | set(direct_contract.S_TRACKED_SUPPORT_PATHS)
        | set(direct_contract.S_ORDINARY_PATHS)
    )


def _assert_html_target(payload: bytes) -> None:
    if len(payload) != S_HTML_TARGET_SIZE:
        raise AssertionError("S user-manual target size mismatch")
    if hashlib.sha256(payload).hexdigest() != S_HTML_TARGET_SHA256:
        raise AssertionError("S user-manual target digest mismatch")
    rendered = payload.decode("utf-8")
    for marker in (
        S_HTML_FILE_BEGIN, S_HTML_FILE_END,
        S_HTML_SCRIPT_BEGIN, S_HTML_SCRIPT_END,
    ):
        if rendered.count(marker) != 1:
            raise AssertionError(f"ambiguous S user-manual marker: {marker}")
    if "infra/docker/README.md" in rendered:
        raise AssertionError("deferred Docker README leaked into S user-manual")
    skeleton = _html_skeleton(payload)
    if len(skeleton) != S_HTML_SKELETON_SIZE:
        raise AssertionError("S user-manual skeleton size mismatch")
    if hashlib.sha256(skeleton).hexdigest() != S_HTML_SKELETON_SHA256:
        raise AssertionError("S user-manual non-generated bytes drifted")
    file_rows = re.findall(r'data-file-path="([^"]+)"', rendered)
    script_rows = re.findall(r'data-script-reference="([^"]+)"', rendered)
    expected_paths = _expected_tree_paths()
    expected_scripts = {
        path for path in expected_paths
        if Path(path).suffix in {".py", ".sh", ".cgi"}
    }
    if len(file_rows) != 322 or len(set(file_rows)) != 322:
        raise AssertionError("S user-manual file catalog is not exact/unique")
    if set(file_rows) != expected_paths:
        raise AssertionError("S user-manual file catalog differs from literal tree")
    if len(script_rows) != 203 or len(set(script_rows)) != 203:
        raise AssertionError("S user-manual script catalog is not exact/unique")
    if set(script_rows) != expected_scripts:
        raise AssertionError("S user-manual script catalog differs from suffix authority")


def _assert_markdown_links(
    relative: str, payload: bytes, tree_records: dict[str, tuple[str, str, str, bytes]],
) -> None:
    text = payload.decode("utf-8")
    for raw_target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = raw_target.strip().split(None, 1)[0].strip("<>")
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path_part, _separator, fragment = target.partition("#")
        if not path_part:
            destination = relative
        else:
            destination = posixpath.normpath(
                posixpath.join(posixpath.dirname(relative), path_part)
            )
        if (
            destination.startswith("/") or destination == ".."
            or destination.startswith("../") or "\0" in destination
        ):
            raise AssertionError(f"unsafe Markdown link in {relative}: {raw_target}")
        record = tree_records.get(destination)
        if record is None or record[0] != "100644":
            raise AssertionError(
                f"missing/nonregular Markdown target in {relative}: {destination}"
            )
        if fragment:
            headings = set()
            for heading in re.findall(r"^#{1,6}\s+(.+?)\s*$", record[3].decode("utf-8"), re.M):
                slug = heading.strip().lower()
                slug = re.sub(r"[^\w\-\u4e00-\u9fff ]", "", slug)
                slug = re.sub(r"\s+", "-", slug)
                headings.add(slug)
            if fragment.lower() not in headings:
                raise AssertionError(
                    f"missing Markdown fragment in {relative}: {raw_target}"
                )


def _assert_runner_cli_contract(relative: str, payload: bytes) -> None:
    text = payload.decode("utf-8")
    allowed = {
        "--all", "--check", "--interval", "--list", "--list-suites",
        "--no-approve", "--require-full", "--suite", "--watch",
    }
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "run_related_tests.py" not in line:
            continue
        command = line
        cursor = index + 1
        while command.rstrip().endswith("\\") and cursor < len(lines):
            command += " " + lines[cursor]
            cursor += 1
        options = set(re.findall(r"(?<!\w)--[a-z][a-z-]*", command))
        unknown = options - allowed
        if unknown:
            raise AssertionError(f"unsupported runner CLI in {relative}: {sorted(unknown)}")


def _markdown_repo_targets(relative: str, payload: bytes) -> set[str]:
    targets = set()
    for raw_target in re.findall(
        r"\[[^\]]*\]\(([^)]+)\)", payload.decode("utf-8"),
    ):
        target = raw_target.strip().split(None, 1)[0].strip("<>")
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        path_part = target.partition("#")[0]
        targets.add(posixpath.normpath(
            posixpath.join(posixpath.dirname(relative), path_part)
        ))
    return targets


def _tree_paths(repository: Path) -> set[str]:
    result = _run_bytes(
        ["git", "ls-tree", "-rz", "--full-tree", "--name-only", "HEAD"],
        cwd=repository,
    )
    if result.returncode:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    return _nul_paths(result.stdout, source="git ls-tree")


def _tree_records(repository: Path) -> dict[str, tuple[str, str, str, bytes]]:
    result = _run_bytes(
        ["git", "ls-tree", "-rz", "--full-tree", "HEAD"], cwd=repository,
    )
    if result.returncode:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    fields = result.stdout.split(b"\0")
    if fields[-1] != b"":
        raise AssertionError("git ls-tree records are not NUL terminated")
    records = {}
    for raw in fields[:-1]:
        metadata, raw_path = raw.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ", 2)
        path = raw_path.decode("utf-8")
        if path in records:
            raise AssertionError(f"duplicate tree path: {path}")
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise AssertionError(f"unsafe S tree record: {raw!r}")
        payload = _run_bytes(["git", "cat-file", "blob", object_id], cwd=repository)
        if payload.returncode:
            raise AssertionError(payload.stderr.decode("utf-8", "replace"))
        records[path] = (mode, kind, object_id, payload.stdout)
    return records


def _tree_record_digest(records) -> str:
    digest = hashlib.sha256()
    for path in sorted(records):
        mode, kind, object_id, payload = records[path]
        digest.update(path.encode("utf-8") + b"\0")
        digest.update(mode.encode("ascii") + b"\0")
        digest.update(kind.encode("ascii") + b"\0")
        if path == S_LEDGER_PATH:
            if mode != "100644" or kind != "blob":
                raise AssertionError("runner-owned ledger is not a regular 100644 blob")
            digest.update(b"<runner-owned-ledger-object>\0")
            digest.update(b"<runner-owned-ledger-content>\0")
        elif path == S_SELF_RECORD_PATH:
            pattern = (
                rb'EXPECTED_S_TREE_RECORD_DIGEST = \(\n'
                rb'    "[0-9a-f]{64}"\n\)'
            )
            if len(re.findall(pattern, payload)) != 1:
                raise AssertionError("S workflow self-record token is ambiguous")
            normalized = re.sub(
                pattern,
                b'EXPECTED_S_TREE_RECORD_DIGEST = (\n'
                b'    "<self-record-digest>"\n)',
                payload,
            )
            digest.update(b"<self-record-object>\0")
            digest.update(hashlib.sha256(normalized).hexdigest().encode("ascii") + b"\0")
        else:
            digest.update(object_id.encode("ascii") + b"\0")
            digest.update(hashlib.sha256(payload).hexdigest().encode("ascii") + b"\0")
        if mode == "120000":
            target = payload.decode("utf-8")
            if not target or target.startswith("/") or "\0" in target:
                raise AssertionError(f"unsafe S symlink target: {path} -> {target!r}")
            digest.update(target.encode("utf-8") + b"\0")
    return digest.hexdigest()


def _head(repository: Path) -> str:
    result = _run(["git", "rev-parse", "HEAD"], cwd=repository)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def _status_paths(repository: Path) -> set[str]:
    changed = _run_bytes(
        ["git", "diff", "--name-only", "-z", Q02_COMMIT, "--"], cwd=repository,
    )
    others = _run_bytes(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=repository,
    )
    if changed.returncode or others.returncode:
        raise AssertionError(
            (changed.stderr + others.stderr).decode("utf-8", "replace")
        )
    return (
        _nul_paths(changed.stdout, source="git diff")
        | _nul_paths(others.stdout, source="git ls-files")
    )


def _cached_paths(repository: Path) -> set[str]:
    result = _run_bytes(
        ["git", "diff", "--cached", "--name-only", "-z", "--"],
        cwd=repository,
    )
    if result.returncode:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    return _nul_paths(result.stdout, source="git diff --cached")


def _assert_clean_index(repository: Path) -> None:
    unmerged = _run_bytes(["git", "ls-files", "-u", "-z"], cwd=repository)
    if unmerged.returncode or unmerged.stdout:
        raise AssertionError("S index contains unmerged entries")
    status = _run_bytes(["git", "status", "--porcelain=v1", "-z"], cwd=repository)
    if status.returncode or status.stdout:
        raise AssertionError(
            "S final checkout is not clean: "
            + status.stdout.decode("utf-8", "backslashreplace")
        )


def _assert_runner_state_stable(repository: Path, expected_ledger: bytes) -> None:
    _assert_clean_index(repository)
    actual = (repository / S_LEDGER_PATH).read_bytes()
    if actual != expected_ledger:
        raise AssertionError("runner command changed the approved ledger")


def _ran_count(stderr: str) -> int:
    matches = re.findall(r"^Ran (\d+) tests?", stderr, re.M)
    if len(matches) != 1 or int(matches[0]) <= 0:
        raise AssertionError("runner did not execute a positive unittest set exactly once")
    return int(matches[0])


def _full_selection_stdout(manifest: dict, *, approval_path: Path | None) -> str:
    lines = ["mode: full-suite", "changed paths:"]
    lines.extend(f"  - {path}" for path in sorted(manifest["scripts"]))
    lines.extend((
        "tests:",
        "  - unittest discovery: test_cases/test_*.py",
        "reasons:",
        "  - explicit --all",
        "root-entrypoint-workflow: NOT COVERED (requires Linux EUID 0 private namespace)",
    ))
    if approval_path is not None:
        lines.append(f"approved hashes updated atomically: {approval_path}")
    return "\n".join(lines) + "\n"


def _forbidden(path: str) -> bool:
    exact = {
        *Q01_PUBLIC_DOCUMENT_PATHS, *LIFECYCLE_PATHS,
        *PRIVATE_DOCUMENT_PATHS, *CABLETRACKER_PATHS,
        *P_PUBLICATION_TEST_PATHS, *S_DEFERRED_PATHS,
    }
    forbidden_roots = (
        "monitor/cabletracker-main",
        "docs/v3/finished-project-lifecycle",
    )
    return (
        any(path == item or path.startswith(item + "/") for item in exact)
        or any(path == root or path.startswith(root + "/")
               for root in forbidden_roots)
    )


def _index_blob(repository: Path, relative: str) -> tuple[str, bytes]:
    first = _run(["git", "ls-files", "--stage", "--", relative], cwd=repository)
    if first.returncode or len(first.stdout.splitlines()) != 1:
        raise AssertionError(f"missing/ambiguous S index blob: {relative}: {first.stderr}")
    metadata, indexed_path = first.stdout.rstrip("\n").split("\t", 1)
    mode, object_id, stage = metadata.split(" ", 2)
    if indexed_path != relative or mode != "100644" or stage != "0":
        raise AssertionError(f"unsafe S index record: {first.stdout!r}")
    payload = subprocess.run(
        ["git", "cat-file", "blob", object_id], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if payload.returncode:
        raise AssertionError(payload.stderr.decode("utf-8", "replace"))
    second = _run(["git", "ls-files", "--stage", "--", relative], cwd=repository)
    if second.stdout != first.stdout or second.returncode:
        raise AssertionError(f"S index record changed while reading: {relative}")
    return object_id, payload.stdout


def _copy_worktree_entry(destination: Path, relative: str) -> None:
    source = ROOT / relative
    metadata = source.lstat()
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if stat.S_ISLNK(metadata.st_mode):
        target.symlink_to(os.readlink(source))
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AssertionError(f"unsafe S worktree overlay: {relative}")
    shutil.copyfile(source, target, follow_symlinks=False)
    target.chmod(stat.S_IMODE(metadata.st_mode))


class PublicSPhaseWorkflowTests(unittest.TestCase):
    def test_s_stage_delta_is_exact_and_excludes_deferred_families(self):
        candidates = {
            path for path in _status_paths(ROOT)
            if not _forbidden(path) and path not in S_DEFERRED_DELTA_PATHS
        }
        state = (
            len(candidates), _path_digest(candidates), S_LEDGER_PATH in candidates,
        )
        accepted_states = {
            (
                EXPECTED_S_COMMIT_OVERLAY_PATH_COUNT,
                EXPECTED_S_COMMIT_OVERLAY_PATH_DIGEST,
                False,
            ),
            (
                EXPECTED_S_STAGE_PATH_COUNT,
                EXPECTED_S_STAGE_PATH_DIGEST,
                True,
            ),
        }
        self.assertIn(
            state,
            accepted_states,
            "S delta must be exactly pre-ledger or exactly final-with-ledger",
        )
        self.assertEqual(set(), {path for path in candidates if _forbidden(path)})
        hostile = set(candidates)
        hostile.discard(next(iter(sorted(hostile))))
        hostile.add("monitor/cabletracker-main/new.py")
        self.assertEqual(len(candidates), len(hostile))
        hostile_state = (
            len(hostile), _path_digest(hostile), S_LEDGER_PATH in hostile,
        )
        self.assertNotIn(hostile_state, accepted_states)

    def test_s_index_owns_three_phase_docs_manifest_and_generated_html(self):
        self.assertEqual(5, len(S_PHASE_INDEX_PATHS))
        expected_documents = _expected_phase_documents()
        expected_manifest = _expected_manifest_payload()
        html_state, html_basis = _html_contract(
            (ROOT / "user-manual.html").read_bytes()
        )
        for relative in S_PHASE_INDEX_PATHS:
            with self.subTest(path=relative):
                object_id, payload = _index_blob(ROOT, relative)
                self.assertEqual(40, len(object_id))
                self.assertTrue(payload, relative)
                if relative in expected_documents:
                    self.assertEqual(expected_documents[relative], payload)
                if relative == "test_cases/script_test_manifest.json":
                    self.assertEqual(expected_manifest, payload)
                if relative == "user-manual.html":
                    if html_state == "source":
                        self.assertNotEqual(html_basis, payload)
                    else:
                        self.assertEqual(html_basis, payload)
                    _assert_html_target(payload)
                base = _run(
                    ["git", "show", f"{Q02_COMMIT}:{relative}"], cwd=ROOT,
                )
                if base.returncode == 0:
                    self.assertNotEqual(
                        base.stdout.encode("utf-8"), payload,
                        f"S phase blob still equals Q02: {relative}",
                    )

    def test_phase_document_links_cli_and_deferred_refs_are_fail_closed(self):
        documents = _expected_phase_documents()
        expected_paths = _expected_tree_paths()
        records = {}
        for path in expected_paths:
            if path in documents:
                payload = documents[path]
                mode = "100644"
            elif path == "PUBLIC_REPOSITORY.md":
                result = _run_bytes(
                    ["git", "show", f"{Q02_COMMIT}:{path}"], cwd=ROOT,
                )
                self.assertEqual(0, result.returncode)
                payload, mode = result.stdout, "100644"
            else:
                metadata = (ROOT / path).lstat()
                mode = "120000" if stat.S_ISLNK(metadata.st_mode) else (
                    "100755" if metadata.st_mode & 0o111 else "100644"
                )
                payload = (
                    os.readlink(ROOT / path).encode("utf-8")
                    if mode == "120000" else (ROOT / path).read_bytes()
                )
            records[path] = (mode, "blob", "0" * 40, payload)
        deferred_paths = {
            *Q01_PUBLIC_DOCUMENT_PATHS, *LIFECYCLE_PATHS,
            *PRIVATE_DOCUMENT_PATHS, *CABLETRACKER_PATHS,
            *P_PUBLICATION_TEST_PATHS, *S_DEFERRED_PATHS,
        }
        for relative, payload in documents.items():
            with self.subTest(path=relative):
                _assert_markdown_links(relative, payload, records)
                _assert_runner_cli_contract(relative, payload)
                self.assertEqual(
                    set(), _markdown_repo_targets(relative, payload) & deferred_paths,
                )
        legal = b"[test cases](../test_cases/README.md) plus README.md USER_MANUAL.md\n"
        self.assertEqual(
            {"test_cases/README.md"},
            _markdown_repo_targets(".github/README.md", legal),
        )
        for private_target in (b"../README.md", b"../USER_MANUAL.md"):
            hostile_private = b"[private](" + private_target + b")\n"
            self.assertTrue(
                _markdown_repo_targets(".github/README.md", hostile_private)
                & deferred_paths
            )
        bad_link = documents[".github/README.md"] + b"\n[bad](../docs/missing.md)\n"
        with self.assertRaises(AssertionError):
            _assert_markdown_links(".github/README.md", bad_link, records)
        bad_fragment = documents["test_cases/README.md"] + b"\n[bad](README.md#missing)\n"
        with self.assertRaises(AssertionError):
            _assert_markdown_links("test_cases/README.md", bad_fragment, records)
        bad_cli = documents["test_cases/README.md"] + (
            b"\npython3 test_cases/run_related_tests.py --future-mode\n"
        )
        with self.assertRaises(AssertionError):
            _assert_runner_cli_contract("test_cases/README.md", bad_cli)

    def test_phase_sources_accept_only_reviewed_source_or_target_bytes(self):
        for relative in S_PHASE_DOC_TRANSFORMS:
            payload = (ROOT / relative).read_bytes()
            state, target = _phase_document_contract(relative, payload)
            self.assertIn(state, {"source", "target"})
            target_state, target_again = _phase_document_contract(relative, target)
            self.assertEqual("target", target_state)
            self.assertEqual(target, target_again)
            with self.assertRaises(AssertionError):
                _phase_document_contract(relative, payload + b"hostile")
        html_payload = (ROOT / "user-manual.html").read_bytes()
        html_state, html_value = _html_contract(html_payload)
        self.assertIn(html_state, {"source", "target"})
        if html_state == "target":
            _assert_html_target(html_value)
        with self.assertRaises(AssertionError):
            _html_contract(html_payload + b"hostile")

    def test_each_read_only_runner_step_detects_mutate_then_restore(self):
        with tempfile.TemporaryDirectory(prefix="http-s-runner-order-") as directory:
            repository = Path(directory)
            ledger = repository / S_LEDGER_PATH
            ledger.parent.mkdir(parents=True)
            ledger.write_bytes(b"reviewed-ledger\n")
            initialized = _run(["git", "init", "--quiet"], cwd=repository)
            self.assertEqual(0, initialized.returncode, initialized.stderr)
            added = _run(["git", "add", "--", S_LEDGER_PATH], cwd=repository)
            self.assertEqual(0, added.returncode, added.stderr)
            committed = _run(
                ["git", "-c", "user.name=S Test", "-c", "user.email=s@test.invalid",
                 "commit", "--quiet", "-m", "ledger baseline"],
                cwd=repository,
            )
            self.assertEqual(0, committed.returncode, committed.stderr)
            ledger.write_bytes(b"mutated-by-first-command\n")
            with self.assertRaises(AssertionError):
                _assert_runner_state_stable(repository, b"reviewed-ledger\n")
            ledger.write_bytes(b"reviewed-ledger\n")
            _assert_runner_state_stable(repository, b"reviewed-ledger\n")
            with self.assertRaises(AssertionError):
                _ran_count("")
            with self.assertRaises(AssertionError):
                _ran_count("runner returned success without unittest evidence\n")

    def test_committed_s_tree_has_exact_partition_and_no_forbidden_entries(self):
        records = _tree_records(ROOT)
        paths = set(records)
        self.assertEqual(EXPECTED_S_TREE_PATH_COUNT, len(paths))
        self.assertEqual(EXPECTED_S_TREE_PATH_DIGEST, _path_digest(paths))
        self.assertEqual(set(), {path for path in paths if _forbidden(path)})
        # The digest binds every path to its mode, Git object, content SHA-256,
        # and (for symlinks) literal target; a path-only tree is insufficient.
        self.assertEqual(EXPECTED_S_TREE_RECORD_DIGEST, _tree_record_digest(records))
        for relative, payload in _expected_phase_documents().items():
            self.assertEqual(payload, records[relative][3])
            _assert_markdown_links(relative, payload, records)

    def test_s_exact_overlay_runs_formal_runner_in_no_local_clone(self):
        if _head(ROOT) != Q02_COMMIT:
            with tempfile.TemporaryDirectory(prefix="http-s-replay-") as directory:
                checkout = Path(directory) / "checkout"
                clone = _run(
                    ["git", "clone", "--quiet", "--no-local", ROOT, checkout],
                    cwd=ROOT, timeout=120,
                )
                self.assertEqual(0, clone.returncode, clone.stderr)
                command = [
                    sys.executable, "-B", "-m", "unittest", "-v",
                    "test_cases.test_public_s_phase_contract",
                    (
                        "test_cases.test_public_s_phase_workflow."
                        "PublicSPhaseWorkflowTests."
                        "test_committed_s_tree_has_exact_partition_and_no_forbidden_entries"
                    ),
                ]
                replay = _run(command, cwd=checkout, timeout=180)
                self.assertEqual(0, replay.returncode, replay.stdout + replay.stderr)
                self.assertIn("Ran 6 tests", replay.stderr)
            return

        stage_paths = {
            path for path in _status_paths(ROOT)
            if not _forbidden(path) and path not in S_DEFERRED_DELTA_PATHS
        }
        self.assertEqual(EXPECTED_S_STAGE_PATH_COUNT, len(stage_paths))
        self.assertEqual(EXPECTED_S_STAGE_PATH_DIGEST, _path_digest(stage_paths))
        commit_overlay = stage_paths - {S_LEDGER_PATH}
        self.assertEqual(EXPECTED_S_COMMIT_OVERLAY_PATH_COUNT, len(commit_overlay))
        self.assertEqual(
            EXPECTED_S_COMMIT_OVERLAY_PATH_DIGEST, _path_digest(commit_overlay),
        )
        with tempfile.TemporaryDirectory(prefix="http-s-candidate-") as directory:
            base = Path(directory)
            candidate = base / "candidate"
            proof = base / "proof"
            clone = _run(
                ["git", "clone", "--quiet", "--no-local", ROOT, candidate],
                cwd=ROOT, timeout=120,
            )
            self.assertEqual(0, clone.returncode, clone.stderr)
            checkout = _run(
                ["git", "checkout", "--quiet", "--detach", Q02_COMMIT],
                cwd=candidate,
            )
            self.assertEqual(0, checkout.returncode, checkout.stderr)
            phase_blobs = {
                relative: _index_blob(ROOT, relative)[1]
                for relative in S_PHASE_INDEX_PATHS
            }
            for relative in sorted(stage_paths - {S_LEDGER_PATH}):
                target = candidate / relative
                if relative in phase_blobs:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(phase_blobs[relative])
                    target.chmod(0o644)
                else:
                    _copy_worktree_entry(candidate, relative)
            add_paths = sorted(stage_paths - {S_LEDGER_PATH})
            added = _run(["git", "add", "--", *add_paths], cwd=candidate)
            self.assertEqual(0, added.returncode, added.stderr)
            self.assertEqual(set(add_paths), _cached_paths(candidate))
            unmerged = _run_bytes(["git", "ls-files", "-u", "-z"], cwd=candidate)
            self.assertEqual(b"", unmerged.stdout)
            committed = _run(
                ["git", "-c", "user.name=S Test", "-c", "user.email=s@test.invalid",
                 "commit", "--quiet", "-m", "S reviewed integration"],
                cwd=candidate,
            )
            self.assertEqual(0, committed.returncode, committed.stderr)
            self.assertEqual(EXPECTED_S_TREE_PATH_DIGEST, _path_digest(_tree_paths(candidate)))
            candidate_records = _tree_records(candidate)
            self.assertEqual(
                EXPECTED_S_TREE_RECORD_DIGEST,
                _tree_record_digest(candidate_records),
            )
            hostile_records = dict(candidate_records)
            mode, kind, object_id, payload = hostile_records[S_PHASE_TEST_PATHS[0]]
            hostile_records[S_PHASE_TEST_PATHS[0]] = (
                mode, kind, "f" * 40, payload + b"hostile same-path replacement",
            )
            self.assertNotEqual(
                EXPECTED_S_TREE_RECORD_DIGEST,
                _tree_record_digest(hostile_records),
            )
            hostile_workflow = dict(candidate_records)
            mode, kind, object_id, payload = hostile_workflow[S_SELF_RECORD_PATH]
            hostile_workflow[S_SELF_RECORD_PATH] = (
                mode, kind, "e" * 40, payload + b"hostile nonconstant workflow byte",
            )
            self.assertNotEqual(
                EXPECTED_S_TREE_RECORD_DIGEST,
                _tree_record_digest(hostile_workflow),
            )
            generated = _run(
                [sys.executable, "-B", "tools/update-user-manual.py", "--check"],
                cwd=candidate, timeout=180,
            )
            self.assertEqual(0, generated.returncode, generated.stdout + generated.stderr)
            no_local = _run(
                ["git", "clone", "--quiet", "--no-local", candidate, proof],
                cwd=candidate, timeout=120,
            )
            self.assertEqual(0, no_local.returncode, no_local.stderr)
            runner = [sys.executable, "-B", "test_cases/run_related_tests.py"]
            before = _run(["git", "status", "--porcelain=v1"], cwd=proof)
            listed = _run([*runner, "--list-suites"], cwd=proof, timeout=120)
            self.assertEqual(0, listed.returncode, listed.stdout + listed.stderr)
            after_list = _run(["git", "status", "--porcelain=v1"], cwd=proof)
            self.assertEqual(before.stdout, after_list.stdout)
            proof_manifest = json.loads(
                (proof / "test_cases/script_test_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            full = _run([*runner, "--all", "-v"], cwd=proof, timeout=600)
            self.assertEqual(0, full.returncode, full.stdout + full.stderr)
            full_count = _ran_count(full.stderr)
            self.assertEqual(
                _full_selection_stdout(
                    proof_manifest, approval_path=proof / S_LEDGER_PATH,
                ),
                full.stdout,
            )
            changed = _run(["git", "status", "--porcelain=v1"], cwd=proof)
            self.assertEqual(f" M {S_LEDGER_PATH}\n", changed.stdout)
            ledger_payload = (proof / S_LEDGER_PATH).read_bytes()
            staged_ledger = _run(["git", "add", "--", S_LEDGER_PATH], cwd=proof)
            self.assertEqual(0, staged_ledger.returncode, staged_ledger.stderr)
            self.assertEqual({S_LEDGER_PATH}, _cached_paths(proof))
            final_commit = _run(
                ["git", "-c", "user.name=S Test", "-c", "user.email=s@test.invalid",
                 "commit", "--quiet", "-m", "S full-suite attestation"],
                cwd=proof,
            )
            self.assertEqual(0, final_commit.returncode, final_commit.stderr)
            final_clone = base / "final-proof"
            final = _run(
                ["git", "clone", "--quiet", "--no-local", proof, final_clone],
                cwd=proof, timeout=120,
            )
            self.assertEqual(0, final.returncode, final.stderr)
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())
            self.assertEqual(
                EXPECTED_S_TREE_RECORD_DIGEST,
                _tree_record_digest(_tree_records(final_clone)),
            )
            final_runner = [sys.executable, "-B", "test_cases/run_related_tests.py"]
            manifest = json.loads(
                (final_clone / "test_cases/script_test_manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            suite_modules = {
                test
                for suite in manifest["test_suites"]
                for test in suite["tests"]
            }
            self.assertEqual(75, len(suite_modules))
            checked = _run(
                [*final_runner, "--check", "--require-full"],
                cwd=final_clone, timeout=180,
            )
            self.assertEqual(0, checked.returncode, checked.stdout + checked.stderr)
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())
            listed = _run(
                [*final_runner, "--all", "--list"], cwd=final_clone, timeout=180,
            )
            self.assertEqual(0, listed.returncode, listed.stdout + listed.stderr)
            self.assertEqual("", listed.stderr)
            expected_list = ["mode: full-suite", "changed paths:"]
            expected_list.extend(f"  - {path}" for path in sorted(manifest["scripts"]))
            expected_list.extend((
                "tests:",
                "  - unittest discovery: test_cases/test_*.py",
                "reasons:",
                "  - explicit --all",
            ))
            self.assertEqual("\n".join(expected_list) + "\n", listed.stdout)
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())
            suite_catalog = _run(
                [*final_runner, "--list-suites"], cwd=final_clone, timeout=180,
            )
            self.assertEqual(0, suite_catalog.returncode, suite_catalog.stderr)
            self.assertEqual("", suite_catalog.stderr)
            expected_catalog = ["test suites:"]
            for suite in manifest["test_suites"]:
                expected_catalog.append(
                    f"  {suite['id']} ({len(suite['tests'])} modules)"
                )
                expected_catalog.append(f"    {suite['description']}")
                expected_catalog.extend(f"    - {test}" for test in suite["tests"])
            self.assertEqual("\n".join(expected_catalog) + "\n", suite_catalog.stdout)
            self.assertEqual(75, suite_catalog.stdout.count("    - test_cases."))
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())
            repository_suite = next(
                suite for suite in manifest["test_suites"]
                if suite["id"] == "repository-governance"
            )
            selected = _run(
                [*final_runner, "--suite", repository_suite["id"], "-v"],
                cwd=final_clone, timeout=600,
            )
            self.assertEqual(0, selected.returncode, selected.stdout + selected.stderr)
            ran = re.findall(r"^Ran (\d+) tests?", selected.stderr, re.M)
            self.assertEqual(1, len(ran), selected.stderr)
            self.assertGreater(int(ran[0]), 0)
            for test in repository_suite["tests"]:
                self.assertIn(f"  - {test}\n", selected.stdout)
            for test in suite_modules - set(repository_suite["tests"]):
                self.assertNotIn(f"  - {test}\n", selected.stdout)
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())
            no_approve = _run(
                [*final_runner, "--all", "--no-approve", "-v"],
                cwd=final_clone, timeout=600,
            )
            self.assertEqual(0, no_approve.returncode, no_approve.stdout + no_approve.stderr)
            self.assertEqual(full_count, _ran_count(no_approve.stderr))
            self.assertEqual(
                _full_selection_stdout(manifest, approval_path=None),
                no_approve.stdout,
            )
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())
            final_check = _run(
                [*final_runner, "--check", "--require-full"],
                cwd=final_clone, timeout=180,
            )
            self.assertEqual(0, final_check.returncode, final_check.stdout + final_check.stderr)
            _assert_clean_index(final_clone)
            self.assertEqual(ledger_payload, (final_clone / S_LEDGER_PATH).read_bytes())


if __name__ == "__main__":
    unittest.main()
