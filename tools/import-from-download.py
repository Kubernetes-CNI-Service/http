#!/usr/bin/env python3
"""Safely import management-server project archives without overwriting local files."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import sys
import tarfile
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = SCRIPT_DIR
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import _package_common as project_contract

ROOT = TOOLS_DIR.parent
DAY0 = ROOT / "DAY0-Prepare"
DEFAULT_REVIEW_ROOT = ROOT / "package-imports"
MAX_MEMBERS = 500_000
SAFE_PROJECT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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
  7. 99-output-*/latest 属于运行态控制链接，不从归档导入。普通导入完成后，
     若发现更新且完整的 ZTP report.json，会打印原子切换 latest 并刷新页面的命令。

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

后续比较：
  diff -ruN \
    DAY0-Prepare/2099-example-site \
    package-imports/<本次目录>/DAY0-Prepare/2099-example-site

说明：
  * 本工具只用于把管理服务器的 download 项目数据带回本地。管理服务器部署
    upload 包时不要运行本工具，直接把归档解压到 HTTP 根目录即可。
  * 本工具刻意不提供覆盖开关。确认确实需要采用管理服务器版本后，请先查看
    conflict 报告，再手工复制具体文件。
  * package-imports/ 不会被 tools/tar-for-upload.py、tools/tar-for-download.py
    或 tools/sync-code.py 上传。
"""


class ImportErrorSafe(RuntimeError):
    pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("archive", type=Path, help="包含 DAY0 项目数据的归档")
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
    parser.add_argument(
        "--review-only", action="store_true",
        help="只安全解压和生成报告，不向本地 DAY0 项目添加文件",
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


def new_project_report() -> dict[str, list[str]]:
    return {"added": [], "identical": [], "conflicts": [], "errors": []}


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
        if result["conflicts"]:
            lines += ["### Conflicts", ""] + [f"- `{item}`" for item in result["conflicts"]] + [""]
        if result["errors"]:
            lines += ["### Errors", ""] + [f"- {item}" for item in result["errors"]] + [""]
    (review / "import-report.md").write_text("\n".join(lines), encoding="utf-8")


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
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
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
            "schema_version": 4,
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
