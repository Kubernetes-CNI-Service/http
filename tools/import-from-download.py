#!/usr/bin/env python3
"""Safely review/import legacy downloads and immutable V3 finished bundles."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from datetime import datetime
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import stat
import sys
import tarfile
import tempfile
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import _package_common as project_contract

ROOT = TOOLS_DIR.parent
DAY0 = ROOT / "DAY0-Prepare"
DEFAULT_REVIEW_ROOT = ROOT / "package-imports"
FINISHED_ROOT = ROOT / "Finished-projects"
MAX_MEMBERS = 500_000
SAFE_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GLOBAL_SYNC_STATE = Path("99-output-ztp/.sync-code-global.sha256")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FINISHED_BUNDLE_ROOT = "http-ztp-finished"
FINISHED_BUNDLE_TYPE = "http-ztp-finished"
FINISHED_FINAL_STATE = "FINISHED_BACKUP_VERIFIED_RUNTIME_STOPPED"
FINISHED_RECORD_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
FINISHED_TRANSACTION_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
FINISHED_CREATED_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
FINISHED_REQUIRED_COMPONENTS = frozenset({
    "pre-stop/project.tar.gz",
    "pre-stop/deployment-source.tar.gz",
    "final-delta/delta.tar.gz",
    "final-delta/delta-manifest.json",
    "host-state/runtime.json",
    "deployment-footprint.json",
    "deletion-plan.json",
    "deletion-plan.md",
})
FINISHED_HISTORY_DIR_NAME = "finished-history"
FINISHED_PRODUCTION_CLASSES = frozenset({
    "legacy", "result-data", "runtime-security",
})
FINISHED_EXCLUDED_CLASSES = frozenset({
    "finished project history link", "metadata", "transport-artifact",
})


HELP_EPILOG = """
安全导入流程：
  1. 脚本只接受 tar/tar.gz/tgz，并检查成员数量、展开大小、绝对路径、.. 路径
     穿越、重复路径、设备文件、硬链接和越界软链接。
  2. 自动识别归档中 DAY0-Prepare/<project>/ 下且包含
     02-devices_config.csv 的项目数据。归档中的脚本及其他非项目文件不会解压或
     覆盖；macOS 元数据、传输归档、old/staging 和管理 key marker 也不会导入。
     若非项目文件修改时间晚于本地同路径文件，只在终端和报告中提示。
     download 包必须且只能包含一个项目；脚本自动识别源项目。默认匹配同名
     DAY0-Prepare/<project>，也可用 -p/--project 明确本地目标项目文件夹。
  3. 所有内容先解压到唯一的 package-imports/<archive>-<timestamp>/ 审核快照；
     审核目录固定 0700、普通文件固定 0600。
  4. 默认把本地项目中不存在的新文件合并进去；同名同内容文件跳过，同名
     但内容不同的文件记录为 conflict，绝不覆盖、截断或删除本地文件。新增项
     恢复归档中的安全权限；相同或冲突的本地项不改权限。
  5. 使用 --review-only 时只创建审核快照和报告，完全不修改 DAY0-Prepare。
  6. import-report.json 和 import-report.md 记录新增、相同、冲突和错误明细。
     对 01-global.yaml 会列出 Mac 与 VM/归档 SHA-256；若归档携带旧版
     sync-code 共同基线，仅作历史取证信息。报告不自动选择或覆盖任一版本。
  7. 99-output-*/latest 属于运行态控制链接，不从归档导入。普通导入完成后，
     若发现更新且完整的 ZTP report.json，会打印原子切换 latest 并刷新页面的命令。

V3 finished bundle：
  * 自动识别固定根 http-ztp-finished/；格式存在但验证失败时绝不降级成 legacy 导入。
  * 默认 review-only：验证外层 manifest/checksum、组件身份和 final delta，并在
    package-imports/ 生成 reconstructed-final；DAY0-Prepare 与 Finished-projects 均不修改。
  * 审核通过后显式增加 --finish，才以 no-replace 方式发布到
    Finished-projects/<project>/<record-id>/。相同归档重复导入幂等，同 ID 不同归档拒绝覆盖。
  * 导入报告逐对象比较 reconstructed-final 与同名 DAY0 项目；99-output-*、运行 marker、
    历史目录等生产数据单列，不参与“项目输入一致”结论。
  * 发布 record 后，如果同名 DAY0 项目安全存在，只在该项目的 finished-history/<record-id>
    建立只读历史入口。该入口和 Finished-projects 不得作为 load、upload 或 sync 输入，
    也不会进入 download 包。
    不会创建或替换任何活动 99-output-*、latest 或项目输入。
  * finished record 目录/文件发布为 0555/0444，防止误编辑；完整 inventory 提供字节完整性
    证明。文件 owner 仍可主动 chmod，因此这是误操作保护，不是权限安全边界。

常用示例：
  # 推荐：先只审查
  python3 tools/import-from-download.py ~/Downloads/project-download.tar.gz --review-only

  # 确认包可信后，安全合并所有新文件；已有文件不会被覆盖
  python3 tools/import-from-download.py ~/Downloads/project-download.tar.gz

  # 明确本地目标项目文件夹；名称不一致时正式导入会要求确认
  python3 tools/import-from-download.py ~/Downloads/project-download.tar.gz \
    --project DAY0-Prepare/2099-example-site

  # 源/目标目录名不一致时，正式导入会要求输入 IMPORT；自动化必须显式 --yes
  python3 tools/import-from-download.py ~/Downloads/project-download.tar.gz \
    --project DAY0-Prepare/local-project-name --yes

  # V3 finished bundle：先审查，再显式发布不可变记录
  python3 tools/import-from-download.py ~/Downloads/http-ztp-finished-example.tar.gz
  python3 tools/import-from-download.py \
    ~/Downloads/http-ztp-finished-example.tar.gz --finish

后续比较：
  diff -ruN \
    DAY0-Prepare/2099-example-site \
    package-imports/<本次目录>/DAY0-Prepare/2099-example-site

说明：
  * 本工具只用于把管理服务器的 download 项目数据带回本地。管理服务器部署
    upload 包时不要运行本工具；应在本地使用 tools/tar-for-upload.py --deploy，
    并显式选择 --runtime native 或 --runtime docker，由归档内 source manifest 绑定的
    deployment_prewrite_guard.py 受控写入。禁止对 live HTTP 根目录手工解压。
  * 本工具刻意不提供覆盖开关。确认确实需要采用管理服务器版本后，请先查看
    conflict 报告，再手工复制具体文件。
  * package-imports/ 和 Finished-projects/ 不会被 tools/tar-for-upload.py、
    tools/tar-for-download.py、tools/sync-code.py 或 Docker build context 上传。
"""


class ImportErrorSafe(RuntimeError):
    pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "archive", type=Path,
        help="legacy DAY0 download 或固定根 V3 finished bundle",
    )
    parser.add_argument(
        "-p", "--project", type=Path,
        help=(
            "本地目标项目文件夹；必须是 DAY0-Prepare 的直接子目录；"
            "名称不一致需确认，已有 release 身份必须匹配源名或目标名"
        ),
    )
    parser.add_argument(
        "--review-root", type=Path, default=DEFAULT_REVIEW_ROOT,
        help="审核快照根目录（默认 workspace/package-imports）",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--review-only", action="store_true",
        help="只安全解压和生成报告，不向本地 DAY0 项目添加文件",
    )
    mode.add_argument(
        "--finish", action="store_true",
        help=(
            "仅 finished bundle：验证后原子发布为 Finished-projects 下的"
            "不可变记录；legacy download 包不接受此参数"
        ),
    )
    parser.add_argument(
        "-y", "--yes", action="store_true",
        help="源项目名与本地目标名不一致时，明确同意非交互导入",
    )
    parser.add_argument(
        "--max-expanded-gib", type=float, default=20.0,
        help="允许的最大展开大小 GiB（默认 20；必须大于 0）",
    )
    return parser.parse_args(argv)


def normalized_member_name(value: str) -> str:
    value = value.removeprefix("./")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ImportErrorSafe(f"归档包含不安全路径：{value!r}")
    normalized = posixpath.normpath(value)
    if normalized in {"", "."} or normalized.startswith("../"):
        raise ImportErrorSafe(f"归档包含路径穿越：{value!r}")
    return normalized


def raw_day0_parts(value: str) -> tuple[str, ...] | None:
    """Return raw DAY0 path parts without validating unrelated archive data."""
    value = value.removeprefix("./")
    path = PurePosixPath(value)
    if path.is_absolute() or len(path.parts) < 2 or path.parts[0] != "DAY0-Prepare":
        return None
    return path.parts


def safe_non_project_name(value: str) -> str | None:
    """Return a safe relative name for comparison, or None when irrelevant."""
    value = value.removeprefix("./")
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts
            or path.parts in {(), (".",)}):
        return None
    normalized = posixpath.normpath(value)
    if normalized in {"", "."} or normalized.startswith("../"):
        return None
    return normalized


def project_names(members: list[tarfile.TarInfo]) -> list[str]:
    result = set()
    for member in members:
        raw_parts = raw_day0_parts(member.name)
        if raw_parts is None:
            continue
        name = normalized_member_name(member.name)
        parts = PurePosixPath(name).parts
        if (len(parts) == 3 and parts[0] == "DAY0-Prepare"
                and parts[2] == "02-devices_config.csv" and member.isfile()):
            result.add(validate_project_name(parts[1]))
    return sorted(result)


def validate_project_name(value: str) -> str:
    name = str(value or "").strip()
    if not SAFE_PROJECT_NAME.fullmatch(name) or name in {".", ".."}:
        raise ImportErrorSafe(f"项目名不安全：{value!r}")
    return name


def select_projects(available: list[str]) -> list[str]:
    if not available:
        raise ImportErrorSafe("归档中没有可导入的 DAY0 项目")
    if len(available) != 1:
        raise ImportErrorSafe(
            "download 归档必须只包含一个 DAY0 项目；发现："
            f"{', '.join(available)}"
        )
    return available


def _existing_target_identity(target: Path) -> str | None:
    """Return a trustworthy local project identity when one is published."""
    release = target / "99-output-ztp/current-release.json"
    if not os.path.lexists(release):
        return None
    if release.is_symlink() or not release.is_file():
        raise ImportErrorSafe(f"目标项目 current-release 不是普通文件：{release}")
    try:
        payload = json.loads(release.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorSafe(f"目标项目 current-release 无法解析：{release}") from exc
    identity = payload.get("project") if isinstance(payload, dict) else None
    if identity is None:
        return None
    return validate_project_name(str(identity))


def resolve_target_project(source_project: str, requested: Path | None) -> Path:
    """Resolve and validate the one local destination for *source_project*."""
    source = validate_project_name(source_project)
    day0 = DAY0.resolve()
    if requested is None:
        target = day0 / source
    else:
        raw = requested.expanduser()
        if not raw.is_absolute():
            target = (DAY0 / raw) if len(raw.parts) == 1 else (ROOT / raw)
        else:
            target = raw
        target = target.resolve(strict=False)
    if target.parent != day0:
        raise ImportErrorSafe(
            f"--project 必须是 {day0} 的直接子目录：{target}"
        )
    target_name = validate_project_name(target.name)
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_dir():
            raise ImportErrorSafe(f"目标项目不是实际目录：{target}")
        devices = target / "02-devices_config.csv"
        if any(target.iterdir()) and (
            devices.is_symlink() or not devices.is_file()
        ):
            raise ImportErrorSafe(
                f"现有目标目录不是完整 DAY0 项目（缺少普通 02-devices_config.csv）：{target}"
            )
        identity = _existing_target_identity(target)
        if identity is not None and identity not in {source, target_name}:
            raise ImportErrorSafe(
                "目标项目 release 身份与归档源/本地目标均不一致："
                f"source={source!r}, target={target_name!r}, release={identity!r}"
            )
    return target


def target_name_mismatches(targets: dict[str, Path]) -> list[dict[str, str]]:
    return [
        {"source_project": source, "target_project": target.name,
         "target_path": str(target)}
        for source, target in targets.items()
        if source != target.name
    ]


def confirm_mismatched_targets(
    mismatches: list[dict[str, str]], *, assume_yes: bool = False,
    interactive: bool | None = None, input_func=input,
) -> bool:
    """Require explicit operator intent before importing across project names."""
    if not mismatches:
        return True
    for item in mismatches:
        print(
            "[WARN] 归档项目名与本地目标名不一致："
            f"{item['source_project']} -> {item['target_project']} "
            f"({item['target_path']})"
        )
    if assume_yes:
        print("[WARN] --yes：已明确接受跨项目名称导入")
        return True
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        raise ImportErrorSafe(
            "源/目标项目名不一致；非交互导入必须显式增加 --yes"
        )
    answer = input_func(
        "确认把上述归档项目导入不同名称的本地项目？输入 IMPORT 继续："
    )
    return answer.strip() == "IMPORT"


def selected_member_project(name: str, selected: set[str]) -> str | None:
    parts = PurePosixPath(name).parts
    if len(parts) >= 2 and parts[0] == "DAY0-Prepare" and parts[1] in selected:
        return parts[1]
    return None


def is_rebuildable_latest_link(member: tarfile.TarInfo, name: str) -> bool:
    parts = PurePosixPath(name).parts
    return bool(
        member.issym() and parts and parts[-1] == "latest"
        and any(part.startswith("99-output-") for part in parts)
    )


def validate_members(
    members: list[tarfile.TarInfo], selected: list[str], max_bytes: int,
) -> list[tuple[tarfile.TarInfo, str]]:
    chosen: list[tuple[tarfile.TarInfo, str]] = []
    names: set[str] = set()
    symlink_names: set[str] = set()
    total = 0
    selected_set = set(selected)
    for member in members:
        raw_parts = raw_day0_parts(member.name)
        if raw_parts is None or raw_parts[1] not in selected_set:
            continue
        if len(chosen) >= MAX_MEMBERS:
            raise ImportErrorSafe(
                f"所选项目成员过多：超过 {MAX_MEMBERS}"
            )
        name = normalized_member_name(member.name)
        if not selected_member_project(name, selected_set):
            raise ImportErrorSafe(f"归档包含不安全的项目路径：{member.name!r}")
        entry_class = project_contract.classify_project_entry(
            PurePosixPath(*PurePosixPath(name).parts[2:])
        )
        if entry_class in {
            "metadata", "legacy", "runtime-security", "transport-artifact",
            "finished project history link",
        }:
            continue
        if is_rebuildable_latest_link(member, name):
            continue
        if name in names:
            raise ImportErrorSafe(f"归档包含重复路径：{name}")
        names.add(name)
        if member.ischr() or member.isblk() or member.isfifo() or member.issparse():
            raise ImportErrorSafe(f"归档包含不允许的特殊文件：{name}")
        if member.islnk():
            raise ImportErrorSafe(f"归档包含不允许的硬链接：{name} → {member.linkname}")
        if not (member.isdir() or member.isfile() or member.issym()):
            raise ImportErrorSafe(f"归档包含不支持的成员类型：{name}")
        if member.isfile():
            total += member.size
            if total > max_bytes:
                raise ImportErrorSafe(
                    f"归档展开大小超过限制：{total} > {max_bytes} bytes"
                )
        if member.issym():
            symlink_names.add(name)
        chosen.append((member, name))

    # Validate links after all names are known.  Chained links are rejected so
    # extraction cannot use one symlink as the parent/target of another.
    for member, name in chosen:
        if not member.issym():
            continue
        link = PurePosixPath(member.linkname)
        if link.is_absolute():
            raise ImportErrorSafe(f"软链接使用绝对目标：{name} → {member.linkname}")
        target = posixpath.normpath(
            posixpath.join(posixpath.dirname(name), member.linkname)
        )
        project = selected_member_project(name, selected_set)
        if not project or not target.startswith(f"DAY0-Prepare/{project}/"):
            raise ImportErrorSafe(f"软链接越出项目目录：{name} → {member.linkname}")
        if target in symlink_names:
            raise ImportErrorSafe(f"不允许链式软链接：{name} → {member.linkname}")
    return chosen


def find_newer_non_project_files(
    members: list[tarfile.TarInfo], projects: set[str], root: Path,
) -> list[dict[str, Any]]:
    """Compare, but never extract, regular files outside DAY0 project trees."""
    newer: list[dict[str, Any]] = []
    root_resolved = root.resolve()
    for member in members:
        if not member.isfile():
            continue
        name = safe_non_project_name(member.name)
        if name is None:
            continue
        parts = PurePosixPath(name).parts
        if (len(parts) >= 2 and parts[0] == "DAY0-Prepare"
                and parts[1] in projects):
            continue
        local = root.joinpath(*parts)
        try:
            local.resolve().relative_to(root_resolved)
        except (OSError, ValueError):
            continue
        if not local.is_file() or local.is_symlink():
            continue
        local_mtime = local.stat().st_mtime
        if member.mtime > local_mtime:
            newer.append({
                "path": name,
                "archive_mtime": datetime.fromtimestamp(member.mtime).astimezone().isoformat(),
                "local_mtime": datetime.fromtimestamp(local_mtime).astimezone().isoformat(),
            })
    return sorted(newer, key=lambda item: item["path"])


def unique_review_dir(root: Path, archive: Path) -> Path:
    label = re.sub(r"[^A-Za-z0-9._-]", "_", archive.name)
    for suffix in (".tar.gz", ".tgz", ".tar"):
        if label.casefold().endswith(suffix):
            label = label[:-len(suffix)]
            break
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = root / f"{label}-{stamp}"
    index = 1
    while candidate.exists():
        candidate = root / f"{label}-{stamp}_{index}"
        index += 1
    candidate.mkdir(parents=True, mode=0o700)
    candidate.chmod(0o700)
    return candidate


def safe_destination(root: Path, name: str) -> Path:
    destination = root.joinpath(*PurePosixPath(name).parts)
    try:
        destination.parent.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ImportErrorSafe(f"提取目标越界：{name}") from exc
    return destination


def safe_extract(
    archive: tarfile.TarFile, chosen: list[tuple[tarfile.TarInfo, str]], root: Path,
) -> None:
    # Directories and regular files first; links last.  The new unique review
    # root guarantees that no pre-existing symlink can redirect writes.
    for member, name in chosen:
        if member.issym():
            continue
        destination = safe_destination(root, name)
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.chmod(0o700)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists() or destination.is_symlink():
            raise ImportErrorSafe(f"提取时发现重复目标：{name}")
        source = archive.extractfile(member)
        if source is None:
            raise ImportErrorSafe(f"无法读取归档成员：{name}")
        with source, destination.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        destination.chmod(0o600)
    for member, name in chosen:
        if not member.issym():
            continue
        destination = safe_destination(root, name)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.path.lexists(destination):
            raise ImportErrorSafe(f"提取时发现重复链接目标：{name}")
        destination.symlink_to(member.linkname)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _optional_regular_digest(path: Path) -> tuple[str | None, str | None]:
    """Return one safe file digest plus an optional inspection error."""
    if not os.path.lexists(path):
        return None, None
    try:
        metadata = path.lstat()
    except OSError as exc:
        return None, str(exc)
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
        return None, "不是单链接普通文件"
    try:
        return digest(path), None
    except OSError as exc:
        return None, str(exc)


def compare_project_global_authority(
    archive_project: Path, local_project: Path,
) -> dict[str, Any] | None:
    """Describe Mac/archive divergence and retain any legacy baseline evidence."""
    archive_global = archive_project / "01-global.yaml"
    local_global = local_project / "01-global.yaml"
    archive_sha256, archive_error = _optional_regular_digest(archive_global)
    local_sha256, local_error = _optional_regular_digest(local_global)
    if archive_sha256 is None and local_sha256 is None and not (
        archive_error or local_error
    ):
        return None

    baseline_path = archive_project / GLOBAL_SYNC_STATE
    baseline = None
    baseline_error = None
    if os.path.lexists(baseline_path):
        try:
            metadata = baseline_path.lstat()
            if (
                baseline_path.is_symlink()
                or not baseline_path.is_file()
                or metadata.st_nlink != 1
            ):
                raise ValueError("不是单链接普通文件")
            raw = baseline_path.read_text(encoding="ascii")
            if raw.endswith("\n"):
                raw = raw[:-1]
            if not SHA256_PATTERN.fullmatch(raw):
                raise ValueError("内容不是单个 SHA-256")
            baseline = raw
        except (OSError, UnicodeError, ValueError) as exc:
            baseline_error = str(exc)

    if archive_error or local_error or baseline_error:
        classification = "unsafe"
    elif archive_sha256 == local_sha256:
        classification = "identical"
    elif baseline is None:
        classification = "unbased-conflict"
    elif local_sha256 == baseline and archive_sha256 != baseline:
        classification = "remote-only"
    elif archive_sha256 == baseline and local_sha256 != baseline:
        classification = "local-only"
    else:
        classification = "diverged"
    return {
        "classification": classification,
        "local_sha256": local_sha256,
        "archive_sha256": archive_sha256,
        "sync_baseline_sha256": baseline,
        "local_error": local_error,
        "archive_error": archive_error,
        "sync_baseline_error": baseline_error,
    }


def sanitized_import_mode(mode: int, *, directory: bool = False) -> int:
    """Return a safe local mode derived from an archive member mode."""
    # Never import special bits or group/other write permission.  Keep useful
    # read/execute bits while guaranteeing that the local owner can manage the
    # newly imported entry.
    safe = int(mode) & 0o755
    return (safe | 0o700) if directory else (safe | 0o600)


def archive_member_modes(
    chosen: list[tuple[tarfile.TarInfo, str]],
) -> dict[str, int]:
    return {
        name: sanitized_import_mode(member.mode, directory=member.isdir())
        for member, name in chosen if member.isdir() or member.isfile()
    }


def merge_entry(source: Path, destination: Path, relative: str,
                report: dict[str, Any], member_modes: dict[str, int],
                archive_name: str) -> None:
    destination_exists = os.path.lexists(destination)
    if source.is_symlink():
        target = os.readlink(source)
        if not destination_exists:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.symlink_to(target)
            report["added"].append(relative)
        elif destination.is_symlink() and os.readlink(destination) == target:
            report["identical"].append(relative)
        else:
            report["conflicts"].append(relative)
        return
    if source.is_dir():
        if destination_exists and (destination.is_symlink() or not destination.is_dir()):
            report["conflicts"].append(relative + "/")
            return
        created = not destination_exists
        destination.mkdir(parents=True, exist_ok=True)
        if created:
            destination.chmod(member_modes.get(archive_name, 0o755))
        for child in sorted(source.iterdir(), key=lambda item: item.name):
            child_relative = f"{relative}/{child.name}" if relative else child.name
            child_archive_name = f"{archive_name}/{child.name}"
            merge_entry(
                child, destination / child.name, child_relative, report,
                member_modes, child_archive_name,
            )
        return
    if not source.is_file():
        report["errors"].append(f"unsupported local snapshot entry: {relative}")
        return
    if not destination_exists:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination, follow_symlinks=False)
        destination.chmod(member_modes.get(archive_name, 0o600))
        report["added"].append(relative)
    elif destination.is_file() and not destination.is_symlink() and digest(source) == digest(destination):
        report["identical"].append(relative)
    else:
        report["conflicts"].append(relative)


def merge_projects(
    review: Path, targets: dict[str, Path], report: dict[str, Any],
    member_modes: dict[str, int],
) -> None:
    for project, requested_target in targets.items():
        source = review / "DAY0-Prepare" / project
        # Revalidate immediately before the first destination write.  The
        # target mapping is recorded in the report and cannot silently drift
        # to another project between review and merge.
        destination = resolve_target_project(project, requested_target)
        if os.path.lexists(destination) and (
            destination.is_symlink() or not destination.is_dir()
        ):
            report["projects"][project]["errors"].append(
                f"local project path is not a real directory: {destination}"
            )
            continue
        destination_created = not os.path.lexists(destination)
        destination.mkdir(parents=True, exist_ok=True)
        if destination_created:
            destination.chmod(
                member_modes.get(f"DAY0-Prepare/{project}", 0o755)
            )
        for child in sorted(source.iterdir(), key=lambda item: item.name):
            merge_entry(
                child, destination / child.name, child.name,
                report["projects"][project], member_modes,
                f"DAY0-Prepare/{project}/{child.name}",
            )


def newest_complete_ztp_run(project: Path) -> str | None:
    output = project / "99-output-ztp"
    if not output.is_dir():
        return None
    candidates: list[tuple[float, str]] = []
    for run in output.iterdir():
        if not run.is_dir() or run.is_symlink() or run.name.startswith("."):
            continue
        report_path = run / "report.json"
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
            continue
        generated_at = str(data.get("generated_at") or "")
        try:
            timestamp = datetime.fromisoformat(
                generated_at.replace("Z", "+00:00")
            ).timestamp()
        except ValueError:
            timestamp = report_path.stat().st_mtime
        candidates.append((timestamp, run.name))
    return max(candidates)[1] if candidates else None


def post_import_actions(targets: dict[str, Path]) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    for project_name, project in targets.items():
        target = newest_complete_ztp_run(project)
        if target is None:
            continue
        output = project / "99-output-ztp"
        latest = output / "latest"
        current = os.readlink(latest) if latest.is_symlink() else ""
        if current == target:
            continue
        if os.path.lexists(latest) and not latest.is_symlink():
            actions.append({
                "project": project_name,
                "local_project": project.name,
                "target": target,
                "command": "",
                "reason": f"{latest} 不是软链接，请先人工检查",
            })
            continue
        switch_code = (
            "from pathlib import Path; "
            f"d=Path({str(output)!r}); "
            "t=d/'.latest.import'; "
            "t.unlink(missing_ok=True); "
            f"t.symlink_to({target!r}); "
            "t.replace(d/'latest')"
        )
        switch = f"python3 -c {shlex.quote(switch_code)}"
        regenerate = (
            f"python3 {shlex.quote(str(ROOT / 'monitor/generate-monitor-html.py'))}"
        )
        actions.append({
            "project": project_name,
            "local_project": project.name,
            "target": target,
            "command": f"{switch} && {regenerate}",
            "reason": f"当前 latest={current or '（无）'}",
        })
    return actions


def new_project_report() -> dict[str, Any]:
    return {
        "added": [], "identical": [], "conflicts": [], "errors": [],
        "global_sync": None,
    }


def write_report(review: Path, report: dict[str, Any]) -> None:
    (review / "import-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Package import report", "", f"- Archive: `{report['archive']}`",
        f"- Review snapshot: `{review}`", f"- Mode: `{report['mode']}`", "",
    ]
    newer_non_project = report.get("newer_non_project_files", [])
    lines += [
        "## Non-project files", "",
        "- Imported or overwritten: 0",
        f"- Archive files newer than local: {len(newer_non_project)}", "",
    ]
    if newer_non_project:
        lines += [
            "| Path | Archive mtime | Local mtime |",
            "|---|---|---|",
        ]
        lines += [
            f"| `{item['path']}` | {item['archive_mtime']} | {item['local_mtime']} |"
            for item in newer_non_project
        ]
        lines.append("")
    mismatches = report.get("target_name_mismatches", [])
    if mismatches:
        lines += ["## Project-name confirmation", "",
                  "The archive source and local target names differ.", ""]
        lines += [
            f"- `{item['source_project']}` → `{item['target_project']}` "
            f"(`{item['target_path']}`)"
            for item in mismatches
        ]
        lines.append("")
    actions = report.get("post_import_actions", [])
    if actions:
        lines += ["## Suggested post-import actions", ""]
        for action in actions:
            display = action["project"]
            if action.get("local_project") != action["project"]:
                display += f" → {action['local_project']}"
            lines += [
                f"### {display}", "",
                f"- Suggested ZTP latest: `{action['target']}`",
                f"- Reason: {action['reason']}", "",
            ]
            if action.get("command"):
                lines += ["```bash", action["command"], "```", ""]
    for project, result in report["projects"].items():
        target = report.get("project_targets", {}).get(project, "")
        lines += [f"## {project}", "",
                  f"- Local target: `{target}`",
                  f"- Added: {len(result['added'])}",
                  f"- Identical: {len(result['identical'])}",
                  f"- Conflicts (not overwritten): {len(result['conflicts'])}",
                  f"- Errors: {len(result['errors'])}", ""]
        comparison = result.get("global_sync")
        if comparison is not None:
            lines += [
                "### 01-global.yaml comparison", "",
                f"- Classification: `{comparison['classification']}`",
                f"- Mac/local SHA-256: `{comparison['local_sha256'] or '<missing>'}`",
                f"- VM/archive SHA-256: `{comparison['archive_sha256'] or '<missing>'}`",
                "- Legacy sync baseline SHA-256 (forensics only): "
                f"`{comparison['sync_baseline_sha256'] or '<missing>'}`",
                "- Existing Mac files are never overwritten by import.", "",
            ]
        if result["conflicts"]:
            lines += ["### Conflicts", ""] + [f"- `{item}`" for item in result["conflicts"]] + [""]
        if result["errors"]:
            lines += ["### Errors", ""] + [f"- {item}" for item in result["errors"]] + [""]
    (review / "import-report.md").write_text("\n".join(lines), encoding="utf-8")


def _fd_digest(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = hashlib.sha256()
    while True:
        block = os.read(descriptor, 4 * 1024 * 1024)
        if not block:
            break
        result.update(block)
    return result.hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


@contextmanager
def stable_tar_archive(path: Path):
    """Open one single-link archive without following a terminal symlink."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ImportErrorSafe("归档必须是 single-link 普通文件")
        first_sha256 = _fd_digest(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            with tarfile.open(fileobj=stream, mode="r:*") as archive:
                yield archive, first_sha256
        after = os.fstat(descriptor)
        second_sha256 = _fd_digest(descriptor)
        final = os.fstat(descriptor)
        if (
            _stat_identity(before) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(final)
            or first_sha256 != second_sha256
        ):
            raise ImportErrorSafe("归档在验证期间发生变化")
    finally:
        os.close(descriptor)


def archive_kind(members: list[tarfile.TarInfo]) -> str:
    """Return ``finished`` without allowing a malformed V3 bundle to downgrade."""
    for member in members:
        parts = tuple(
            part for part in PurePosixPath(member.name).parts if part != "."
        )
        if FINISHED_BUNDLE_ROOT in parts:
            return "finished"
    return "legacy"


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ImportErrorSafe(f"{label} 包含重复 JSON key：{key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=reject_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorSafe(f"{label} 不是有效 UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ImportErrorSafe(f"{label} 顶层必须是 JSON object")
    return value


def _finished_relative(value: str) -> str:
    normalized = normalized_member_name(value)
    parts = PurePosixPath(normalized).parts
    if not parts or parts[0] != FINISHED_BUNDLE_ROOT:
        raise ImportErrorSafe(
            f"finished bundle 只能包含固定根 {FINISHED_BUNDLE_ROOT}/：{value!r}"
        )
    return PurePosixPath(*parts[1:]).as_posix() if len(parts) > 1 else "."


def _component_stage(path: str) -> str:
    if path.startswith("pre-stop/"):
        return "pre-stop"
    if path.startswith("final-delta/"):
        return "final-delta"
    if path.startswith("host-state/"):
        return "host-state"
    if path == "deployment-footprint.json":
        return "footprint"
    if path.startswith("deletion-plan."):
        return "deletion-plan"
    raise ImportErrorSafe(f"finished component 路径不属于已知阶段：{path}")


def validate_finished_bundle(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    max_bytes: int,
) -> dict[str, Any]:
    """Validate the complete outer bundle and return immutable metadata."""
    if len(members) > MAX_MEMBERS:
        raise ImportErrorSafe(f"finished bundle 成员超过 {MAX_MEMBERS}")
    names: dict[str, tarfile.TarInfo] = {}
    payloads: dict[str, bytes] = {}
    chosen: list[tuple[tarfile.TarInfo, str]] = []
    total = 0
    for member in members:
        relative = _finished_relative(member.name)
        normalized = (
            FINISHED_BUNDLE_ROOT
            if relative == "."
            else f"{FINISHED_BUNDLE_ROOT}/{relative}"
        )
        if normalized in names:
            raise ImportErrorSafe(f"finished bundle 包含重复路径：{normalized}")
        names[normalized] = member
        if not (member.isdir() or member.isfile()):
            raise ImportErrorSafe(
                f"finished bundle 不允许链接或特殊文件：{normalized}"
            )
        expected_mode = 0o700 if member.isdir() else 0o600
        if stat.S_IMODE(member.mode) != expected_mode:
            raise ImportErrorSafe(
                f"finished bundle 成员权限必须是 {expected_mode:04o}：{normalized}"
            )
        if member.uid != 0 or member.gid != 0:
            raise ImportErrorSafe(f"finished bundle 成员必须记录为 root:root：{normalized}")
        if member.isfile():
            total += member.size
            if total > max_bytes:
                raise ImportErrorSafe(
                    f"finished bundle 展开大小超过限制：{total} > {max_bytes} bytes"
                )
            source = archive.extractfile(member)
            if source is None:
                raise ImportErrorSafe(f"无法读取 finished bundle 成员：{normalized}")
            with source:
                payload = source.read(member.size + 1)
            if len(payload) != member.size:
                raise ImportErrorSafe(f"finished bundle 成员大小不一致：{normalized}")
            payloads[relative] = payload
        chosen.append((member, normalized))

    root_member = names.get(FINISHED_BUNDLE_ROOT)
    if root_member is None or not root_member.isdir():
        raise ImportErrorSafe("finished bundle 缺少固定根目录")
    for normalized, member in names.items():
        if normalized == FINISHED_BUNDLE_ROOT:
            continue
        parent = PurePosixPath(normalized).parent
        while parent.as_posix() != ".":
            parent_member = names.get(parent.as_posix())
            if parent_member is None or not parent_member.isdir():
                raise ImportErrorSafe(
                    f"finished bundle 缺少显式父目录：{normalized} -> {parent}"
                )
            if parent.as_posix() == FINISHED_BUNDLE_ROOT:
                break
            parent = parent.parent

    try:
        manifest_payload = payloads["bundle-manifest.json"]
        checksum_payload = payloads["SHA256SUMS"]
    except KeyError as exc:
        raise ImportErrorSafe("finished bundle 缺少 manifest 或 SHA256SUMS") from exc
    manifest = _json_object(manifest_payload, "bundle-manifest.json")
    expected_manifest_keys = {
        "schema_version", "bundle_type", "project", "record_id",
        "transaction_id", "runtime", "state", "created_at",
        "content_sha256", "components",
    }
    if set(manifest) != expected_manifest_keys:
        raise ImportErrorSafe("bundle-manifest.json 字段集合不符合 schema 1")
    if manifest["schema_version"] != 1 or manifest["bundle_type"] != FINISHED_BUNDLE_TYPE:
        raise ImportErrorSafe("finished bundle schema/type 不受支持")
    project = validate_project_name(manifest["project"])
    record_id = str(manifest["record_id"])
    transaction_id = str(manifest["transaction_id"])
    if not FINISHED_RECORD_PATTERN.fullmatch(record_id):
        raise ImportErrorSafe("finished record ID 格式不安全")
    if not FINISHED_TRANSACTION_PATTERN.fullmatch(transaction_id):
        raise ImportErrorSafe("finished transaction ID 格式不安全")
    if manifest["runtime"] not in {"native", "docker"}:
        raise ImportErrorSafe("finished runtime 必须是 native 或 docker")
    if manifest["state"] != FINISHED_FINAL_STATE:
        raise ImportErrorSafe("finished bundle 尚未达到最终停止状态")
    created_at = manifest["created_at"]
    if not isinstance(created_at, str) or not FINISHED_CREATED_PATTERN.fullmatch(created_at):
        raise ImportErrorSafe("finished created_at 必须是 UTC RFC3339 秒级时间")
    try:
        datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ImportErrorSafe("finished created_at 不是有效时间") from exc
    if not SHA256_PATTERN.fullmatch(str(manifest["content_sha256"])):
        raise ImportErrorSafe("finished content_sha256 无效")

    rows = manifest["components"]
    if not isinstance(rows, list):
        raise ImportErrorSafe("finished components 必须是数组")
    component_paths: set[str] = set()
    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "path", "size", "sha256", "mode", "schema_version", "stage",
        }:
            raise ImportErrorSafe("finished component 记录字段不符合 schema 1")
        path = str(row["path"])
        if normalized_member_name(path) != path or path in {
            "bundle-manifest.json", "SHA256SUMS",
        }:
            raise ImportErrorSafe(f"finished component 路径不安全：{path!r}")
        if path in component_paths:
            raise ImportErrorSafe(f"finished components 包含重复路径：{path}")
        component_paths.add(path)
        payload = payloads.get(path)
        if payload is None:
            raise ImportErrorSafe(f"finished component 缺少 payload：{path}")
        if (
            isinstance(row["size"], bool)
            or not isinstance(row["size"], int)
            or row["size"] != len(payload)
        ):
            raise ImportErrorSafe(f"finished component size 不匹配：{path}")
        if row["mode"] != 0o600 or row["schema_version"] != 1:
            raise ImportErrorSafe(f"finished component mode/schema 不匹配：{path}")
        if row["stage"] != _component_stage(path):
            raise ImportErrorSafe(f"finished component stage 不匹配：{path}")
        if row["sha256"] != sha256_bytes(payload):
            raise ImportErrorSafe(f"finished component SHA-256 不匹配：{path}")
        normalized_rows.append(dict(row))
    if normalized_rows != sorted(normalized_rows, key=lambda row: row["path"]):
        raise ImportErrorSafe("finished components 必须按 path 排序")
    if not FINISHED_REQUIRED_COMPONENTS.issubset(component_paths):
        missing = sorted(FINISHED_REQUIRED_COMPONENTS - component_paths)
        raise ImportErrorSafe(f"finished bundle 缺少必要组件：{', '.join(missing)}")
    expected_payload_paths = set(payloads) - {"bundle-manifest.json", "SHA256SUMS"}
    if component_paths != expected_payload_paths:
        raise ImportErrorSafe("finished components 与 payload 文件集合不一致")

    identity_basis = {
        "schema_version": 1,
        "project": project,
        "transaction_id": transaction_id,
        "runtime": manifest["runtime"],
        "state": manifest["state"],
        "components": normalized_rows,
    }
    identity_sha256 = hashlib.sha256(json.dumps(
        identity_basis, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")).hexdigest()
    if manifest["content_sha256"] != identity_sha256:
        raise ImportErrorSafe("finished content SHA-256 与组件身份不一致")
    if record_id.rsplit("-", 1)[1] != identity_sha256[:12]:
        raise ImportErrorSafe("finished record ID 未绑定 content SHA-256")

    try:
        checksum_text = checksum_payload.decode("ascii")
    except UnicodeError as exc:
        raise ImportErrorSafe("SHA256SUMS 必须是 ASCII") from exc
    if not checksum_text.endswith("\n"):
        raise ImportErrorSafe("SHA256SUMS 必须以换行结尾")
    checksum_rows: dict[str, str] = {}
    raw_lines = checksum_text.splitlines()
    for line in raw_lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00-\x1f\x7f]+)", line)
        if match is None:
            raise ImportErrorSafe("SHA256SUMS 包含非规范行")
        sha256, path = match.groups()
        if normalized_member_name(path) != path or path in checksum_rows:
            raise ImportErrorSafe("SHA256SUMS 包含重复或不安全路径")
        checksum_rows[path] = sha256
    if raw_lines != sorted(raw_lines, key=lambda line: line[66:]):
        raise ImportErrorSafe("SHA256SUMS 必须按路径排序")
    checksummed = set(payloads) - {"SHA256SUMS"}
    if set(checksum_rows) != checksummed:
        raise ImportErrorSafe("SHA256SUMS 与 finished 文件集合不一致")
    for path in sorted(checksummed):
        if checksum_rows[path] != hashlib.sha256(payloads[path]).hexdigest():
            raise ImportErrorSafe(f"finished SHA-256 校验失败：{path}")
    return {
        "manifest": manifest,
        "chosen": chosen,
        "payloads": payloads,
    }


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _nested_members(
    archive: tarfile.TarFile, expected_root: str, max_bytes: int,
    *, allow_symlinks: bool,
) -> list[tuple[tarfile.TarInfo, str]]:
    members = archive.getmembers()
    if len(members) > MAX_MEMBERS:
        raise ImportErrorSafe(f"嵌套组件成员超过 {MAX_MEMBERS}")
    chosen: list[tuple[tarfile.TarInfo, str]] = []
    names: set[str] = set()
    link_names: set[str] = set()
    total = 0
    root_seen = False
    for member in members:
        normalized = normalized_member_name(member.name)
        parts = PurePosixPath(normalized).parts
        if not parts or parts[0] != expected_root:
            raise ImportErrorSafe(f"嵌套组件路径不在 {expected_root}/：{member.name!r}")
        if normalized in names:
            raise ImportErrorSafe(f"嵌套组件包含重复路径：{normalized}")
        names.add(normalized)
        if len(parts) == 1:
            if not member.isdir():
                raise ImportErrorSafe(f"嵌套组件根不是目录：{expected_root}")
            root_seen = True
            continue
        relative = PurePosixPath(*parts[1:]).as_posix()
        if member.islnk() or member.ischr() or member.isblk() or member.isfifo() or member.issparse():
            raise ImportErrorSafe(f"嵌套组件包含不允许的成员：{normalized}")
        if not (member.isdir() or member.isfile() or (allow_symlinks and member.issym())):
            raise ImportErrorSafe(f"嵌套组件成员类型不受支持：{normalized}")
        if member.isfile():
            total += member.size
            if total > max_bytes:
                raise ImportErrorSafe("嵌套组件展开大小超过限制")
        if member.issym():
            link_names.add(relative)
        chosen.append((member, relative))
    if not root_seen:
        raise ImportErrorSafe(f"嵌套组件缺少固定根：{expected_root}")
    for member, relative in chosen:
        if not member.issym():
            continue
        target = PurePosixPath(member.linkname)
        if not member.linkname or target.is_absolute():
            raise ImportErrorSafe(f"嵌套组件软链接目标不安全：{relative}")
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), member.linkname))
        if resolved == ".." or resolved.startswith("../") or resolved in link_names:
            raise ImportErrorSafe(f"嵌套组件软链接越界或形成链：{relative}")
    return chosen


def extract_nested_component(
    payload: bytes, expected_root: str, destination: Path,
    max_bytes: int, *, allow_symlinks: bool,
) -> None:
    destination.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as nested:
        chosen = _nested_members(
            nested, expected_root, max_bytes, allow_symlinks=allow_symlinks,
        )
        safe_extract(nested, chosen, destination)


def _safe_reconstructed_leaf(root: Path, relative: str) -> Path:
    normalized = normalized_member_name(relative)
    if normalized != relative:
        raise ImportErrorSafe(f"final delta 路径不规范：{relative!r}")
    leaf = root.joinpath(*PurePosixPath(relative).parts)
    cursor = root
    for part in PurePosixPath(relative).parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink() or not cursor.is_dir():
            raise ImportErrorSafe(f"final delta 父路径不是实际目录：{relative}")
    return leaf


def _regular_sha256(path: Path) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1:
        raise ImportErrorSafe(f"final delta 基线不是 single-link 普通文件：{path}")
    return digest(path)


def reconstruct_finished_project(
    review: Path, payloads: dict[str, bytes], max_bytes: int,
) -> Path:
    reconstructed = review / "reconstructed-final"
    extract_nested_component(
        payloads["pre-stop/project.tar.gz"], "project", reconstructed,
        max_bytes, allow_symlinks=True,
    )
    delta_root = review / ".finished-delta"
    extract_nested_component(
        payloads["final-delta/delta.tar.gz"], "delta", delta_root,
        max_bytes, allow_symlinks=False,
    )
    delta_manifest = _json_object(
        payloads["final-delta/delta-manifest.json"], "delta-manifest.json",
    )
    if set(delta_manifest) != {"schema_version", "base_component", "changes"}:
        raise ImportErrorSafe("delta-manifest.json 字段集合不符合 schema 1")
    if (
        delta_manifest["schema_version"] != 1
        or delta_manifest["base_component"] != "pre-stop/project.tar.gz"
        or not isinstance(delta_manifest["changes"], list)
    ):
        raise ImportErrorSafe("delta-manifest.json 身份不受支持")
    changes = delta_manifest["changes"]
    paths: set[str] = set()
    payload_paths: set[str] = set()
    prepared: list[tuple[dict[str, Any], Path, Path | None]] = []
    for change in changes:
        if not isinstance(change, dict) or set(change) != {
            "path", "action", "before_sha256", "sha256", "size",
        }:
            raise ImportErrorSafe("final delta change 字段不符合 schema 1")
        path = str(change["path"])
        if path in paths:
            raise ImportErrorSafe(f"final delta 包含重复路径：{path}")
        paths.add(path)
        leaf = _safe_reconstructed_leaf(reconstructed, path)
        action = change["action"]
        if action not in {"create", "replace", "delete"}:
            raise ImportErrorSafe(f"final delta action 不受支持：{action!r}")
        source: Path | None = None
        if action == "create":
            if os.path.lexists(leaf) or change["before_sha256"] is not None:
                raise ImportErrorSafe(f"final delta create 基线不为空：{path}")
        else:
            before = _regular_sha256(leaf)
            if change["before_sha256"] != before:
                raise ImportErrorSafe(f"final delta pre-stop SHA-256 不匹配：{path}")
        if action == "delete":
            if change["sha256"] is not None or change["size"] is not None:
                raise ImportErrorSafe(f"final delta delete 不得携带新 payload：{path}")
        else:
            source = _safe_reconstructed_leaf(delta_root, path)
            payload_paths.add(path)
            actual = _regular_sha256(source)
            size = source.stat().st_size
            if (
                change["sha256"] != actual
                or isinstance(change["size"], bool)
                or change["size"] != size
            ):
                raise ImportErrorSafe(f"final delta payload 身份不匹配：{path}")
        prepared.append((change, leaf, source))
    if [item["path"] for item in changes] != sorted(paths):
        raise ImportErrorSafe("final delta changes 必须按 path 排序")
    actual_payloads = {
        path.relative_to(delta_root).as_posix()
        for path in delta_root.rglob("*") if path.is_file() and not path.is_symlink()
    }
    if actual_payloads != payload_paths:
        raise ImportErrorSafe("final delta tar 与 change payload 集合不一致")

    for change, leaf, source in prepared:
        if change["action"] == "delete":
            leaf.unlink()
            continue
        assert source is not None
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{leaf.name}.finished-", dir=leaf.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as incoming:
                shutil.copyfileobj(incoming, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o600)
            if change["action"] == "create" and os.path.lexists(leaf):
                raise ImportErrorSafe(f"final delta create 目标并发出现：{change['path']}")
            os.replace(temporary, leaf)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()
    shutil.rmtree(delta_root)
    return reconstructed


def _stable_regular_identity(path: Path) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        path_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ImportErrorSafe(f"无法安全读取项目文件 {path}：{exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or path_before.st_dev != before.st_dev
            or path_before.st_ino != before.st_ino
            or before.st_nlink != 1
        ):
            raise ImportErrorSafe(f"项目文件不是 single-link 普通文件：{path}")
        hasher = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 4 * 1024 * 1024)
            if not block:
                break
            hasher.update(block)
            size += len(block)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        identity_before = (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_nlink,
        )
        identity_after = (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_nlink,
        )
        path_identity_after = (
            path_after.st_dev, path_after.st_ino, path_after.st_size,
            path_after.st_mtime_ns, path_after.st_nlink,
        )
        if identity_before != identity_after or identity_after != path_identity_after:
            raise ImportErrorSafe(f"读取期间项目文件发生变化：{path}")
        if size != before.st_size:
            raise ImportErrorSafe(f"项目文件读取长度发生变化：{path}")
        return {
            "type": "file",
            "size": size,
            "sha256": hasher.hexdigest(),
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
        }
    finally:
        os.close(descriptor)


def _stable_small_regular_bytes(path: Path, *, maximum: int = 16 * 1024 * 1024) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        path_before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ImportErrorSafe(f"无法安全读取 finished record 文件 {path}：{exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(path_before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or path_before.st_dev != before.st_dev
            or path_before.st_ino != before.st_ino
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            raise ImportErrorSafe(f"finished record 文件身份或大小不安全：{path}")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > maximum:
                raise ImportErrorSafe(f"finished record 文件超过读取上限：{path}")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        before_identity = (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_nlink,
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_nlink,
        )
        path_identity = (
            path_after.st_dev, path_after.st_ino, path_after.st_size,
            path_after.st_mtime_ns, path_after.st_nlink,
        )
        if before_identity != after_identity or after_identity != path_identity:
            raise ImportErrorSafe(f"读取期间 finished record 文件发生变化：{path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _project_tree_inventory(root: Path) -> dict[str, dict[str, Any]]:
    root_before = root.lstat()
    if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
        raise ImportErrorSafe(f"项目比较根不是实际目录：{root}")
    result: dict[str, dict[str, Any]] = {}

    def walk(directory: Path, prefix: PurePosixPath) -> None:
        before = directory.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise ImportErrorSafe(f"项目比较目录发生类型变化：{directory}")
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise ImportErrorSafe(f"无法读取项目比较目录 {directory}：{exc}") from exc
        for entry in entries:
            relative = prefix / entry.name
            relative_name = relative.as_posix()
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(path)
                except OSError as exc:
                    raise ImportErrorSafe(f"无法读取项目软链接 {path}：{exc}") from exc
                result[relative_name] = {
                    "type": "symlink",
                    "target": target,
                }
            elif stat.S_ISDIR(metadata.st_mode):
                result[relative_name] = {
                    "type": "directory",
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                }
                walk(path, relative)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative_name] = _stable_regular_identity(path)
            else:
                result[relative_name] = {
                    "type": "special",
                    "mode": f"{stat.S_IFMT(metadata.st_mode):06o}",
                }
        after = directory.lstat()
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise ImportErrorSafe(f"读取期间项目目录发生变化：{directory}")

    walk(root, PurePosixPath())
    root_after = root.lstat()
    if (
        root_before.st_dev != root_after.st_dev
        or root_before.st_ino != root_after.st_ino
        or root_before.st_mtime_ns != root_after.st_mtime_ns
    ):
        raise ImportErrorSafe(f"读取期间项目根发生变化：{root}")
    return result


def _local_finished_project(project: str) -> tuple[Path | None, str | None]:
    candidate = DAY0 / project
    if not os.path.lexists(candidate):
        return None, None
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        return None, str(exc)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return None, "同名 DAY0 项目不是实际目录"
    devices = candidate / "02-devices_config.csv"
    try:
        devices_metadata = devices.lstat()
    except OSError as exc:
        return None, f"缺少安全的 02-devices_config.csv：{exc}"
    if (
        stat.S_ISLNK(devices_metadata.st_mode)
        or not stat.S_ISREG(devices_metadata.st_mode)
        or devices_metadata.st_nlink != 1
    ):
        return None, "02-devices_config.csv 不是 single-link 普通文件"
    return candidate, None


def _comparison_category(relative: str) -> str:
    category = project_contract.classify_project_entry(PurePosixPath(relative))
    if category in FINISHED_PRODUCTION_CLASSES:
        return "production"
    if category in FINISHED_EXCLUDED_CLASSES:
        return "excluded"
    return "source"


def _same_project_object(
    bundle: dict[str, Any], local: dict[str, Any],
) -> bool:
    if bundle.get("type") != local.get("type"):
        return False
    if bundle["type"] == "file":
        return (
            bundle.get("size") == local.get("size")
            and bundle.get("sha256") == local.get("sha256")
        )
    if bundle["type"] == "symlink":
        return bundle.get("target") == local.get("target")
    return bundle["type"] == "directory"


def compare_finished_project(
    reconstructed: Path, project: str, record_id: str,
) -> dict[str, Any]:
    bundle_inventory = _project_tree_inventory(reconstructed)
    local_project, local_error = _local_finished_project(project)
    local_inventory = (
        _project_tree_inventory(local_project) if local_project is not None else {}
    )
    source_entries: list[dict[str, Any]] = []
    production_entries: list[dict[str, Any]] = []
    excluded_entries: list[dict[str, Any]] = []
    differences = 0
    for relative in sorted(set(bundle_inventory) | set(local_inventory)):
        bundle_object = bundle_inventory.get(relative)
        local_object = local_inventory.get(relative)
        category = _comparison_category(relative)
        row: dict[str, Any] = {
            "path": relative,
            "bundle": bundle_object,
            "local": local_object,
        }
        if category == "production":
            production_entries.append(row)
            continue
        if category == "excluded":
            excluded_entries.append(row)
            continue
        if local_project is None:
            status = "not-compared"
        elif bundle_object is None:
            status = "local-only"
        elif local_object is None:
            status = "bundle-only"
        elif bundle_object.get("type") != local_object.get("type"):
            status = "type-different"
        elif _same_project_object(bundle_object, local_object):
            status = "identical"
        else:
            status = "content-different"
        row["status"] = status
        source_entries.append(row)
        if status not in {"identical", "not-compared"}:
            differences += 1

    if local_error is not None:
        status = "local-project-invalid"
    elif local_project is None:
        status = "local-project-missing"
    elif differences:
        status = "different"
    else:
        status = "identical"
    return {
        "schema_version": 1,
        "project": project,
        "record_id": record_id,
        "status": status,
        "local_project": f"DAY0-Prepare/{project}",
        "local_project_error": local_error,
        "comparison_policy": {
            "source": "compare object type and file bytes or symlink target",
            "production": "reported separately and excluded from consistency status",
            "production_classes": sorted(FINISHED_PRODUCTION_CLASSES),
            "excluded_classes": sorted(FINISHED_EXCLUDED_CLASSES),
        },
        "summary": {
            "source_entries": len(source_entries),
            "differences": differences,
            "production_entries": len(production_entries),
            "excluded_entries": len(excluded_entries),
        },
        "source_entries": source_entries,
        "production_data": production_entries,
        "excluded_entries": excluded_entries,
    }


def _comparison_markdown(report: dict[str, Any]) -> bytes:
    summary = report["summary"]
    lines = [
        "# Finished project comparison report",
        "",
        f"- Project: `{report['project']}`",
        f"- Record ID: `{report['record_id']}`",
        f"- Source consistency: `{report['status']}`",
        f"- Source objects compared: `{summary['source_entries']}`",
        f"- Source differences: `{summary['differences']}`",
        f"- Production/history objects excluded from verdict: `{summary['production_entries']}`",
        "",
        "`99-output-*`, runtime-security and legacy production data are listed in JSON",
        "but do not change the source consistency verdict.",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _write_private(path: Path, payload: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def _copy_private_tree(source: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for child in sorted(source.iterdir(), key=lambda item: item.name):
        target = destination / child.name
        if child.is_symlink():
            target.symlink_to(os.readlink(child))
        elif child.is_dir():
            _copy_private_tree(child, target)
        elif child.is_file() and child.lstat().st_nlink == 1:
            _write_private(target, child.read_bytes())
        else:
            raise ImportErrorSafe(f"finished record 源包含不安全对象：{child}")


def _tree_identity(
    root: Path, *, directory_mode: int, file_mode: int,
    excluded: frozenset[str] = frozenset(),
) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    root_metadata = root.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ImportErrorSafe(f"finished record 不是实际目录：{root}")
    if stat.S_IMODE(root_metadata.st_mode) != directory_mode:
        raise ImportErrorSafe(f"finished record 根目录权限漂移：{root}")

    def walk(directory: Path, prefix: PurePosixPath) -> None:
        with os.scandir(directory) as scanner:
            entries = sorted(scanner, key=lambda item: item.name)
        for entry in entries:
            relative_path = prefix / entry.name
            relative = relative_path.as_posix()
            if relative in excluded:
                continue
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                result.append((relative, "symlink", os.readlink(path)))
            elif stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != directory_mode:
                    raise ImportErrorSafe(f"finished record 目录权限漂移：{path}")
                result.append((relative, "directory", "directory"))
                walk(path, relative_path)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                if stat.S_IMODE(metadata.st_mode) != file_mode:
                    raise ImportErrorSafe(f"finished record 文件权限漂移：{path}")
                result.append((relative, "file", _stable_regular_identity(path)["sha256"]))
            else:
                raise ImportErrorSafe(f"finished record 包含不安全对象：{path}")

    walk(root, PurePosixPath())
    return result


def _freeze_finished_tree(root: Path) -> None:
    directories: list[Path] = [root]
    for directory, child_directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        for name in child_directories:
            child = current / name
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise ImportErrorSafe(f"finished record 包含不安全目录对象：{child}")
            directories.append(child)
        for name in files:
            child = current / name
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ImportErrorSafe(f"finished record 包含不安全文件对象：{child}")
            child.chmod(0o444)
    for directory in reversed(directories):
        directory.chmod(0o555)


def _thaw_private_stage(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ImportErrorSafe(f"无法清理非目录 finished stage：{root}")
    root.chmod(0o700)
    for directory, child_directories, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        current.chmod(0o700)
        for name in child_directories:
            child = current / name
            if not child.is_symlink():
                child.chmod(0o700)
        for name in files:
            child = current / name
            if not child.is_symlink():
                child.chmod(0o600)


def _record_inventory_payload(stage: Path) -> bytes:
    entries = [
        {"path": path, "type": kind, "identity": identity}
        for path, kind, identity in _tree_identity(
            stage, directory_mode=0o700, file_mode=0o600,
            excluded=frozenset({"record-inventory.json"}),
        )
    ]
    payload = {
        "schema_version": 1,
        "entries": entries,
        "entries_sha256": hashlib.sha256(json.dumps(
            entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")).hexdigest(),
    }
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _verify_published_record(
    target: Path, manifest: dict[str, Any], archive_sha256: str,
) -> None:
    identity = _tree_identity(
        target, directory_mode=0o555, file_mode=0o444,
        excluded=frozenset({"record-inventory.json"}),
    )
    inventory_path = target / "record-inventory.json"
    inventory_identity = _stable_regular_identity(inventory_path)
    if inventory_identity["mode"] != "0444":
        raise ImportErrorSafe(f"finished record inventory 权限漂移：{inventory_path}")
    try:
        inventory = json.loads(
            _stable_small_regular_bytes(inventory_path).decode("utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorSafe(f"finished record inventory 无效：{exc}") from exc
    expected_entries = [
        {"path": path, "type": kind, "identity": value}
        for path, kind, value in identity
    ]
    expected_sha256 = hashlib.sha256(json.dumps(
        expected_entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")).hexdigest()
    if inventory != {
        "schema_version": 1,
        "entries": expected_entries,
        "entries_sha256": expected_sha256,
    }:
        raise ImportErrorSafe("finished record inventory 与冻结文件不一致")
    report_path = target / "import-report.json"
    try:
        report = json.loads(
            _stable_small_regular_bytes(report_path).decode("utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ImportErrorSafe(f"finished import report 无效：{exc}") from exc
    expected = {
        "archive_sha256": archive_sha256,
        "content_sha256": manifest["content_sha256"],
        "project": manifest["project"],
        "record_id": manifest["record_id"],
    }
    if any(report.get(key) != value for key, value in expected.items()):
        raise ImportErrorSafe(
            "finished record ID 已对应 different bundle，拒绝覆盖"
        )


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        result = libc.renamex_np(
            ctypes.c_char_p(source_bytes), ctypes.c_char_p(destination_bytes),
            ctypes.c_uint(0x00000004),
        )
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        result = libc.renameat2(
            ctypes.c_int(-100), ctypes.c_char_p(source_bytes),
            ctypes.c_int(-100), ctypes.c_char_p(destination_bytes),
            ctypes.c_uint(1),
        )
    else:
        raise ImportErrorSafe("当前平台不支持原子 no-replace finished publish")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(destination)
    raise OSError(error, os.strerror(error), destination)


def _private_directory(path: Path) -> None:
    if os.path.lexists(path):
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ImportErrorSafe(f"finished parent 不是实际目录：{path}")
        if metadata.st_uid != os.geteuid():
            raise ImportErrorSafe(f"finished parent owner 不属于当前用户：{path}")
    else:
        path.mkdir(mode=0o700)
    path.chmod(0o700)


def _history_link_plan(
    project: str, record_id: str, target: Path,
) -> tuple[Path, Path, str] | None:
    local_project, error = _local_finished_project(project)
    if error is not None:
        raise ImportErrorSafe(f"无法建立 finished-history：{error}")
    if local_project is None:
        return None
    history_root = local_project / FINISHED_HISTORY_DIR_NAME
    if os.path.lexists(history_root):
        metadata = history_root.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
        ):
            raise ImportErrorSafe(
                f"finished-history 必须是当前用户拥有的实际目录：{history_root}"
            )
    leaf = history_root / record_id
    relative_target = os.path.relpath(target, history_root)
    if os.path.lexists(leaf):
        if not leaf.is_symlink() or os.readlink(leaf) != relative_target:
            raise ImportErrorSafe(f"finished-history 已有冲突对象：{leaf}")
    return history_root, leaf, relative_target


def _publish_history_link(plan: tuple[Path, Path, str] | None) -> Path | None:
    if plan is None:
        return None
    history_root, leaf, relative_target = plan
    if not os.path.lexists(history_root):
        try:
            history_root.mkdir(mode=0o700)
        except FileExistsError:
            pass
    metadata = history_root.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise ImportErrorSafe(
            f"finished-history 必须是当前用户拥有的实际目录：{history_root}"
        )
    if os.path.lexists(leaf):
        if not leaf.is_symlink() or os.readlink(leaf) != relative_target:
            raise ImportErrorSafe(f"finished-history 并发出现冲突对象：{leaf}")
    else:
        try:
            leaf.symlink_to(relative_target, target_is_directory=True)
        except FileExistsError:
            if not leaf.is_symlink() or os.readlink(leaf) != relative_target:
                raise ImportErrorSafe(f"finished-history 并发出现冲突对象：{leaf}")
    descriptor = os.open(
        history_root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return leaf


def publish_finished_record(
    review: Path, metadata: dict[str, Any], archive_sha256: str,
    comparison: dict[str, Any],
) -> tuple[Path, bool, Path | None]:
    manifest = metadata["manifest"]
    project = validate_project_name(manifest["project"])
    record_id = str(manifest["record_id"])
    target = FINISHED_ROOT / project / record_id
    history_plan = _history_link_plan(project, record_id, target)
    _private_directory(FINISHED_ROOT)
    project_root = FINISHED_ROOT / project
    _private_directory(project_root)
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_dir():
            raise ImportErrorSafe(f"finished record ID 已被非目录占用：{target}")
        _verify_published_record(target, manifest, archive_sha256)
        history_link = _publish_history_link(history_plan)
        return target, True, history_link
    stage = Path(tempfile.mkdtemp(
        prefix=f".{record_id}.import-", dir=project_root,
    ))
    stage.chmod(0o700)
    try:
        bundle_root = review / FINISHED_BUNDLE_ROOT
        for child in sorted(bundle_root.iterdir(), key=lambda item: item.name):
            if child.is_dir():
                _copy_private_tree(child, stage / child.name)
            elif child.is_file() and not child.is_symlink():
                _write_private(stage / child.name, child.read_bytes())
            else:
                raise ImportErrorSafe(f"finished outer review 包含不安全对象：{child}")
        _copy_private_tree(review / "reconstructed-final", stage / "reconstructed-final")
        for report_name in (
            "project-comparison-report.json", "project-comparison-report.md",
        ):
            source = review / report_name
            _write_private(stage / report_name, source.read_bytes())
        report = {
            "schema_version": 1,
            "status": "published",
            "archive_sha256": archive_sha256,
            "content_sha256": manifest["content_sha256"],
            "project": project,
            "record_id": record_id,
            "runtime": manifest["runtime"],
            "state": manifest["state"],
            "project_consistency": comparison["status"],
            "history_link": (
                f"DAY0-Prepare/{project}/{FINISHED_HISTORY_DIR_NAME}/{record_id}"
                if history_plan is not None else None
            ),
        }
        report_payload = (
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        _write_private(stage / "import-report.json", report_payload)
        markdown = (
            "# Finished project import report\n\n"
            f"- Project: `{project}`\n"
            f"- Record ID: `{record_id}`\n"
            f"- Archive SHA-256: `{archive_sha256}`\n"
            "- Result: immutable finished record published\n"
        ).encode("utf-8")
        _write_private(stage / "import-report.md", markdown)
        _write_private(stage / "record-inventory.json", _record_inventory_payload(stage))
        _freeze_finished_tree(stage)
        _tree_identity(stage, directory_mode=0o555, file_mode=0o444)
        try:
            _rename_noreplace(stage, target)
        except FileExistsError:
            if target.is_symlink() or not target.is_dir():
                raise ImportErrorSafe(f"finished record ID 并发被非目录占用：{target}")
            _verify_published_record(target, manifest, archive_sha256)
            history_link = _publish_history_link(history_plan)
            return target, True, history_link
        descriptor = os.open(project_root, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        history_link = _publish_history_link(history_plan)
        return target, False, history_link
    finally:
        if os.path.lexists(stage):
            _thaw_private_stage(stage)
            shutil.rmtree(stage)


def import_finished_archive(
    args: argparse.Namespace,
    archive_path: Path,
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    archive_sha256: str,
    review_root: Path,
) -> int:
    if args.project is not None or args.yes:
        raise ImportErrorSafe(
            "finished bundle 不接受 legacy --project/--yes；项目身份来自 manifest"
        )
    max_bytes = int(args.max_expanded_gib * 1024 ** 3)
    metadata = validate_finished_bundle(archive, members, max_bytes)
    review = unique_review_dir(review_root, archive_path)
    safe_extract(archive, metadata["chosen"], review)
    reconstructed = reconstruct_finished_project(
        review, metadata["payloads"], max_bytes,
    )
    manifest = metadata["manifest"]
    comparison = compare_finished_project(
        reconstructed, manifest["project"], manifest["record_id"],
    )
    _write_private(
        review / "project-comparison-report.json",
        (json.dumps(comparison, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(),
    )
    _write_private(
        review / "project-comparison-report.md", _comparison_markdown(comparison),
    )
    review_report = {
        "schema_version": 1,
        "status": "verified-review-only" if not args.finish else "verified-for-finish",
        "archive": str(archive_path),
        "archive_sha256": archive_sha256,
        "project": manifest["project"],
        "record_id": manifest["record_id"],
        "content_sha256": manifest["content_sha256"],
        "finished_target": str(
            FINISHED_ROOT / manifest["project"] / manifest["record_id"]
        ),
        "project_consistency": comparison["status"],
    }
    _write_private(
        review / "finished-import-report.json",
        (json.dumps(review_report, ensure_ascii=False, indent=2) + "\n").encode(),
    )
    print(
        f"[OK] verified finished bundle review: {review} "
        f"(record={manifest['record_id']})"
    )
    print(
        "[INFO] project consistency: "
        f"{comparison['status']} "
        f"(source differences={comparison['summary']['differences']}; "
        f"production entries excluded={comparison['summary']['production_entries']})"
    )
    if not args.finish:
        print("[INFO] review-only：Finished-projects 和 DAY0-Prepare 均未修改")
        print(f"[NEXT] 审核后使用同一归档增加 --finish 发布不可变 record")
        return 0
    target, already_imported, history_link = publish_finished_record(
        review, metadata, archive_sha256, comparison,
    )
    if already_imported:
        print(f"[OK] already imported：{target}")
    else:
        print(f"[OK] finished record published：{target}")
    if history_link is None:
        print("[INFO] 同名 DAY0 项目不存在；未创建 finished-history 入口")
    else:
        print(f"[OK] DAY0 history link：{history_link}")
    print(
        "[INFO] DAY0 项目输入和活动 99-output 未修改；"
        "finished-history/ 与 finished record 不可作为 load/sync 输入"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    review: Path | None = None
    try:
        args = parse_args(argv)
        archive_path = args.archive.expanduser().resolve()
        if not archive_path.is_file():
            raise ImportErrorSafe(f"归档不存在：{archive_path}")
        if not archive_path.name.casefold().endswith((".tar", ".tar.gz", ".tgz")):
            raise ImportErrorSafe("只支持 .tar、.tar.gz 或 .tgz 归档")
        if args.max_expanded_gib <= 0:
            raise ImportErrorSafe("--max-expanded-gib 必须大于 0")
        review_root = args.review_root.expanduser().resolve()
        review_root.mkdir(parents=True, exist_ok=True)
        with stable_tar_archive(archive_path) as (archive, archive_sha256):
            members = archive.getmembers()
            if archive_kind(members) == "finished":
                return import_finished_archive(
                    args, archive_path, archive, members, archive_sha256,
                    review_root,
                )
            if args.finish:
                raise ImportErrorSafe(
                    "--finish 只支持 V3 finished bundle；legacy download 包保持原导入语义"
                )
            available = project_names(members)
            selected = select_projects(available)
            targets = {
                name: resolve_target_project(name, args.project)
                for name in selected
            }
            newer_non_project = find_newer_non_project_files(
                members, set(available), ROOT,
            )
            chosen = validate_members(
                members, selected, int(args.max_expanded_gib * 1024 ** 3)
            )
            member_modes = archive_member_modes(chosen)
            review = unique_review_dir(review_root, archive_path)
            safe_extract(archive, chosen, review)
        report: dict[str, Any] = {
            "schema_version": 5,
            "archive": str(archive_path),
            "review": str(review),
            "mode": "review-only" if args.review_only else "merge-new-only",
            "newer_non_project_files": newer_non_project,
            "project_targets": {
                name: str(target) for name, target in targets.items()
            },
            "target_name_mismatches": target_name_mismatches(targets),
            "projects": {name: new_project_report() for name in selected},
        }
        for name, target in targets.items():
            report["projects"][name]["global_sync"] = (
                compare_project_global_authority(
                    review / "DAY0-Prepare" / name, target,
                )
            )
        proceed = True
        if not args.review_only:
            proceed = confirm_mismatched_targets(
                report["target_name_mismatches"], assume_yes=args.yes,
            )
        elif report["target_name_mismatches"]:
            for item in report["target_name_mismatches"]:
                print(
                    "[WARN] review-only 发现源/目标项目名不一致："
                    f"{item['source_project']} -> {item['target_project']}"
                )
        if not args.review_only and proceed:
            merge_projects(review, targets, report, member_modes)
            report["post_import_actions"] = post_import_actions(targets)
        else:
            report["post_import_actions"] = []
            if not args.review_only:
                report["mode"] = "review-only-declined"
        write_report(review, report)
        print(f"[OK] 安全审核快照：{review}")
        for project, result in report["projects"].items():
            print(f"[TARGET] {project} -> {report['project_targets'][project]}")
            print(
                f"[RESULT] {project}: added={len(result['added'])}, "
                f"identical={len(result['identical'])}, "
                f"conflicts={len(result['conflicts'])}, errors={len(result['errors'])}"
            )
            comparison = result.get("global_sync")
            if comparison and comparison["classification"] == "remote-only":
                print(
                    "[WARN] 01-global.yaml：VM/归档端单边修改；"
                    "Mac 本地版本保持不变，请先审核两个 SHA-256"
                )
            elif comparison and comparison["classification"] in {
                "diverged", "unbased-conflict", "unsafe",
            }:
                print(
                    "[WARN] 01-global.yaml 权威来源无法自动判定；"
                    "Mac 本地版本保持不变，请查看 import-report"
                )
        print(f"[OK] 导入报告：{review / 'import-report.md'}")
        if newer_non_project:
            print(
                f"[WARN] 归档中有 {len(newer_non_project)} 个非项目文件比本地新；"
                "这些文件未导入，请查看报告"
            )
        else:
            print("[INFO] 未发现比本地更新的非项目文件")
        for action in report["post_import_actions"]:
            if action.get("command"):
                print(
                    f"[NEXT] {action['project']} 可切换 ZTP latest → "
                    f"{action['target']}（{action['reason']}）"
                )
                print(f"       {action['command']}")
            else:
                print(f"[WARN] {action['project']}: {action['reason']}")
        if args.review_only:
            print("[INFO] review-only：本地 DAY0 项目未修改")
        elif not proceed:
            print("[INFO] 用户未确认跨项目名称导入；本地 DAY0 项目未修改")
        elif any(item["conflicts"] for item in report["projects"].values()):
            print("[WARN] 存在冲突；本地文件均未覆盖，请在审核快照中比较后手工处理")
        else:
            print("[OK] 新文件已安全合并，没有覆盖任何本地文件")
        if not args.review_only and proceed:
            added_total = sum(
                len(item["added"]) for item in report["projects"].values()
            )
            identical_total = sum(
                len(item["identical"]) for item in report["projects"].values()
            )
            conflict_total = sum(
                len(item["conflicts"]) for item in report["projects"].values()
            )
            error_total = sum(
                len(item["errors"]) for item in report["projects"].values()
            )
            print("[SUMMARY] 导入结果")
            print(f"新文件：{added_total} 个，已经导入。")
            print(f"相同文件：{identical_total} 个，跳过。")
            print(
                f"冲突文件：{conflict_total} 个，"
                "保留本地版本，没有覆盖。"
            )
            if error_total:
                print(f"错误：{error_total} 个，请查看导入报告。")
        return 0
    except (OSError, ImportErrorSafe, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        if review is not None:
            print(f"[INFO] 未完成的审核目录保留用于排查：{review}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
