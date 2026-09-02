#!/usr/bin/env python3
"""Package management-server project data for downloading and safekeeping.

The safe default archives only the selected DAY0 project's data, including its
inputs, 99-output-* tree, logs, backups and large files, but excluding README files.
Historical result symlinks are retained, while rebuildable 99-output-*/latest links are omitted. Use
--all-day0 for every DAY0 project, or --full-workspace for the legacy workspace
archive containing common source trees as well.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile

# Resolve the shared implementation relative to this command, not the caller's
# current directory or import path.  This also keeps file-based imports used by
# tests and higher-level tooling working.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import _package_common as package_core


HELP_EPILOG = """
操作步骤：
  1. 登录 AIR 管理服务器并进入 /var/www/html。
  2. 推荐直接把项目目录作为位置参数（也保留 -p/--project）。默认归档只包含
     该项目目录，不包含公共 load.py、infra、
     ztp、monitor 或 tools 源代码，因此下载到本地后不会覆盖本地代码。
  3. 项目包完整保留规划输入、99-output-*、ZTP 状态、历史监控、备份、
     大文件和历史结果内部软连接，不做文件大小过滤。README 文档、macOS 元数据、旧 old/staging、
     已下载/上传的传输归档和管理服务器 key marker 不属于项目数据，会被排除。各 99-output-* 下
     可重建的 latest 链接不打包，避免运行中切换造成归档断链；import 会在本地
     给出切换最新完整 ZTP 报告的命令。由 load 注入的
     管理服务器公钥例外：归档内只保留同名空占位文件。
  4. 需要保存 DAY0-Prepare 下所有项目时使用 --all-day0。
  5. 只有完整迁移管理服务器时才使用 --full-workspace；此模式会包含公共
     源代码，并可通过 include 参数加入共享 image/apps/firmware，但仍排除所有 README。
  6. 脚本在输出目录先写临时文件并重新打开验证，成功后原子替换，
     最终归档权限为 0644，并打印路径、大小和 SHA-256。归档可能包含内部
     配置和日志，因此只应放在受控的管理服务器上，不得写入 Web 发布目录。
  7. 回到本地通过 SCP 下载，始终先解压到新目录查看。

常用示例：
  # 推荐：只打包当前 AIR 项目的全部数据
  cd /var/www/html
  python3 tools/tar-for-download.py DAY0-Prepare/2099-example-site/

  # 兼容旧写法
  python3 tools/tar-for-download.py -p 2099-example-site

  # 打包 DAY0-Prepare 下所有项目，但不包含公共工作区代码
  python3 tools/tar-for-download.py --all-day0 --force

  # 完整迁移工作区，并包含共享镜像/APT/固件
  python3 tools/tar-for-download.py --full-workspace \\
    -p 2099-example-site \\
    --include-images --include-apps --include-firmware

从本地下载：
  scp -P 21018 \\
    ubuntu@ztp-admin.example:/tmp/*-download.tar.gz \\
    .

安全解压：
  review_dir=~/Downloads/air-project-review
  mkdir -p "$review_dir"
  tar -xzf <下载的归档.tar.gz> -C "$review_dir"

权限与容量提示：
  * 请使用能读取目标项目全部文件的用户运行，通常是 root。
  * 打包前使用 df -h /tmp 检查空间。
  * 输出必须位于待打包 DAY0 目录之外，防止归档包含自身。
  * 输出文件已存在时不会覆盖，除非明确使用 --force。
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--all-day0", action="store_true",
        help="完整打包 DAY0-Prepare，但不包含公共工作区代码",
    )
    scope.add_argument(
        "--full-workspace", action="store_true",
        help="使用兼容模式打包工作区公共代码和 DAY0-Prepare",
    )
    parser.add_argument(
        "project_folder", nargs="?", metavar="PROJECT",
        help=("PROJECT 项目名或项目目录，例如 "
              "DAY0-Prepare/2099-example-site/"),
    )
    parser.add_argument(
        "-p", "--project",
        help="位置 PROJECT 的兼容写法；未指定时尝试读取活动项目",
    )
    parser.add_argument(
        "-o", "--output", type=Path,
        help="归档路径（默认根据范围和时间生成在 /tmp）",
    )
    parser.add_argument("--include-images", action="store_true",
                        help="仅 full-workspace：包含共享 image/ 和 ztp/image/")
    parser.add_argument("--include-apps", action="store_true",
                        help="仅 full-workspace：包含共享离线 APT apps/")
    parser.add_argument("--include-firmware", action="store_true",
                        help="仅 full-workspace：包含共享 firmware/")
    parser.add_argument(
        "--max-file-size-mib", type=int, default=package_core.DEFAULT_MAX_FILE_MIB,
        help="仅 full-workspace：限制 DAY0 之外的其他大文件（默认 50）",
    )
    parser.add_argument("--force", action="store_true", help="覆盖已有输出归档")
    args = parser.parse_args(argv)
    if args.project and args.project_folder:
        parser.error("PROJECT 位置参数与 -p/--project 不能同时使用")
    args.project = args.project or args.project_folder
    del args.project_folder
    return args


def default_output(label: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in label)
    return Path("/tmp") / f"{safe}-{stamp}-download.tar.gz"


def resolve_output(value: Path | None, label: str, source: Path, *, force: bool) -> Path:
    raw_output = (value or default_output(label)).expanduser()
    if not raw_output.is_absolute():
        raw_output = Path.cwd() / raw_output
    output = raw_output.parent.resolve() / raw_output.name
    try:
        output.relative_to(source.resolve())
    except ValueError:
        pass
    else:
        raise ValueError(f"输出归档不能位于待打包目录内：{output}")
    if output.is_symlink():
        raise ValueError(f"输出归档不能是软链接：{output}")
    if output.exists():
        if not force:
            raise FileExistsError(f"输出已存在；确认后使用 --force：{output}")
        if not output.is_file():
            raise ValueError(f"--force 只能替换普通归档文件：{output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def create_day0_archive(args: argparse.Namespace) -> Path:
    project = None if args.all_day0 else package_core.resolve_project(args.project)
    if args.all_day0:
        sources = package_core.project_directories()
        if not sources:
            raise ValueError("DAY0-Prepare 下没有可归档的项目")
    else:
        assert project is not None
        sources = [project]
    source = package_core.DAY0 if args.all_day0 else sources[0]
    label = "DAY0-Prepare-all" if args.all_day0 else project.name
    output_label = "DAY0-Prepare-all" if args.all_day0 else project.name
    output = resolve_output(args.output, output_label, source, force=args.force)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{label}-", suffix=".tar.gz", dir=output.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    projects_for_keys = sources
    managed_names = {
        (Path("DAY0-Prepare") / path.relative_to(package_core.DAY0)).as_posix()
        for path in package_core.managed_pubkey_paths(projects_for_keys)
    }

    omitted: dict[str, int] = {}

    def omit(reason: str) -> None:
        omitted[reason] = omitted.get(reason, 0) + 1

    def sanitize_project_archive(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = info.name.removeprefix("./")
        shared_reason = package_core.transfer_exclude_reason(PurePosixPath(name))
        if shared_reason:
            omit(shared_reason)
            return None
        if name in managed_names:
            omit("management-server public key")
            return None
        parts = PurePosixPath(name).parts
        if len(parts) >= 3 and parts[0] == "DAY0-Prepare":
            entry_class = package_core.classify_project_entry(
                PurePosixPath(*parts[2:])
            )
            if entry_class in {
                "metadata", "legacy", "runtime-security", "transport-artifact",
            }:
                omit(entry_class)
                return None
        if (info.issym() and parts and parts[-1] == "latest"
                and any(part.startswith("99-output-") for part in parts)):
            omit("rebuildable latest link")
            return None
        return info

    try:
        with tarfile.open(temporary, "w:gz", dereference=False) as archive:
            if args.all_day0:
                archive.add(package_core.DAY0, arcname="DAY0-Prepare", recursive=False)
                for item in sources:
                    archive.add(
                        item, arcname=f"DAY0-Prepare/{item.name}", recursive=True,
                        filter=sanitize_project_archive,
                    )
            else:
                for item in sources:
                    archive.add(
                        item, arcname=f"DAY0-Prepare/{item.name}", recursive=True,
                        filter=sanitize_project_archive,
                    )
            for name in sorted(managed_names):
                placeholder = tarfile.TarInfo(name)
                placeholder.mode = 0o644
                placeholder.mtime = int(datetime.now().timestamp())
                placeholder.size = 0
                archive.addfile(placeholder)
        with tarfile.open(temporary, "r:gz") as archive:
            names = set(archive.getnames())
            required = (
                {f"DAY0-Prepare/{item.name}/02-devices_config.csv" for item in sources}
                if args.all_day0
                else {f"DAY0-Prepare/{project.name}/02-devices_config.csv"}
            )
            missing = sorted(required - names)
            if missing:
                raise RuntimeError(f"归档验证缺少：{', '.join(missing)}")
        os.replace(temporary, output)
        # mkstemp keeps the in-progress archive private.  Only after the
        # archive has been reopened, validated and atomically published do we
        # apply the operator-facing download mode requested by the workflow.
        output.chmod(0o644)
    finally:
        if temporary.exists():
            temporary.unlink()

    scope_text = "all DAY0 projects" if args.all_day0 else ", ".join(map(str, sources))
    print(f"[OK] Archive scope    : {scope_text}")
    print(f"[OK] Archive          : {output}")
    source_size = sum(package_core.directory_size(item) for item in sources)
    print(f"[OK] Source size      : {package_core.human_size(source_size)}")
    print(f"[OK] Archive size     : {package_core.human_size(output.stat().st_size)}")
    print(f"[OK] SHA-256          : {package_core.sha256(output)}")
    print(f"[OK] Omitted entries  : {sum(omitted.values())}")
    for reason, count in sorted(omitted.items()):
        print(f"     {reason:<32} {count}")
    return output


def validate_scope_options(args: argparse.Namespace) -> None:
    include_requested = args.include_images or args.include_apps or args.include_firmware
    if include_requested and not args.full_workspace:
        raise ValueError("include-images/apps/firmware 仅能与 --full-workspace 一起使用")
    if args.all_day0 and args.project:
        raise ValueError("--all-day0 不需要 --project；请删除 --project")


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        validate_scope_options(args)
        if args.full_workspace:
            if args.output is None:
                args.output = default_output("http-air-full-workspace")
            package_core.create_package(args, day0_all=True)
        else:
            create_day0_archive(args)
        return 0
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
