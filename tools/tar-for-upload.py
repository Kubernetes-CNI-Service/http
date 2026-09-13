#!/usr/bin/env python3
"""Build a compact local deployment package and upload it to a management server.

Only DAY0 inputs consumed by setup/load and the deployable source tree are retained;
the selected P2P XLSX is copied without embedded images, while alternate planning
workbooks, all project 99-output-* contents, and setup-managed links are omitted.
Use --dry-run/--list-only to build and inspect the verified local archive without
connecting to SSH. Remote extraction only occurs with the explicit --deploy flag
because it overwrites matching files below the remote HTTP root.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from datetime import datetime
import errno
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

# Resolve the shared implementation relative to this command, not the caller's
# current directory or import path.  This also keeps file-based imports used by
# tests and higher-level tooling working.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import _package_common as package_core


ROOT = SCRIPT_DIR.parent
PREDEPLOY_TEST_RUNNER = ROOT / "test_cases" / "run_related_tests.py"
RELAY_INSTALLER = ROOT / "tools" / "deploy-upload-archive.py"
MAX_RELAY_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_RELAY_AUTHORITY_BYTES = 16 * 1024 * 1024
SAFE_REMOTE_DIR = re.compile(r"^/[A-Za-z0-9._/-]+$")
SAFE_ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
SAFE_HOST = re.compile(r"^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+$")
REQUIRED_OFFLINE_PACKAGES = {
    "wget", "lldpd", "tzdata", "ipmitool", "sshpass", "docker.io",
    "unzip", "nfs-common", "arping", "python3", "python3-yaml",
    "python3-jinja2", "python3-openpyxl", "python3-pandas",
    "python3-xlsxwriter", "openssh-client", "curl",
    "apache2", "ssl-cert", "isc-dhcp-server", "jq",
}

HELP_EPILOG = """
操作步骤：
  1. 在本地 HTTP 工作区根目录运行本命令。
  2. 脚本识别项目参数，默认在 DAY0-Prepare/dumps/ 下生成只适合部署的紧凑 tar.gz。
     正式交互上传会先询问目标管理服务器是否可访问 Internet；不能访问时包含
     与目标 OS/架构匹配的 apps/ 离线 APT 仓库，能访问时排除。非交互上传必须明确指定
     --include-apps 或 --exclude-apps；dry-run 默认排除，可用 --include-apps 预览。
  3. 部署包保留源代码、模板和指定项目中代码实际消费的输入：三份固定配置、
     存在时的 03-air-topology-policy.json、setup/load 当前选择的 P2P XLSX、
     项目公钥和镜像文件。P2P 在临时副本中删除
     xl/media、图片关系和 drawing anchor 后以原文件名入包，源文件不会修改。
     其他规划附件、其他 XLSX、项目说明、Markdown/README/用户手册、
     其他 DAY0 项目和全部
     99-output-* 内容、历史监控、备份、运行时日志及 setup 管理的动态链接
     均不进入部署包。
     ztp/optimize 属于正式代码，保留其中的 Python/Shell 源文件，但不打包
     *-sample、分析报告和 issue-tracker 等非代码/运行时内容。
     输出目录本身可以作为空目录保留，实际链接和结果由管理服务器 setup/load 重建。
  4. 脚本默认自动探测本地和远端 rsync：可用时上传到 `.partial` 并支持
     中断续传；不可用时回退到实时显示进度的 SCP。两种方式都启用 SSH
     keepalive/连接超时，随后比较本地和远端 SHA-256，匹配后才原子改名。
  5. 默认到此停止，明确显示“已上传、未部署”，并打印一条可在本地运行的简短
     --deploy-uploaded <ARCHIVE> 命令。该入口复用刚才审核并上传的精确归档，
     不会重新打包、不会重新传输，也不会输出难以审核的超长远端 shell。
  6. 所有非 dry-run 上传都会先验证本机正式 load 记录的精确全量测试证明；若当前源码、测试、
     manifest 与 Python/平台身份完全匹配则直接复用。此脚本绝不运行全量测试；证明缺失或
     过期时会要求先重跑本机正式 load，并在打包和远端连接前终止。归档生成后、首次 SSH 前
     还会执行
     --check --require-full，拒绝打包期间的源码、测试、环境或影响矩阵漂移。
     dry-run/list-only 不运行此门禁；不存在无条件跳过正式门禁的参数。
  7. 门禁通过后，--deploy 或 --deploy-uploaded 才在 --remote-root 上独占与 11-load.py 共用的
     .deployment.lock；锁内先复制到 /tmp 的私有目录并再次校验 SHA-256，
     然后创建持久同步门禁并解压。成功清除门禁后才释放锁；解包失败时门禁保留，
     防止 load 消费半套代码。SSH 用户必须具备无密码 sudo；root SSH 登录请同时使用
     --no-sudo。仅本地打包、dry-run 或只上传不会取得远端锁。
     管理服务器部署不使用 import-from-download.py；
     禁止对 live /var/www/html 手工解压。校验后的归档也只能由 --deploy 或
     --deploy-uploaded 调用归档内
     source manifest 绑定的 deployment_prewrite_guard.py，在共享 deployment lock 内应用。
     选择 Docker 时必须显式传 --runtime docker，确保 guard 建立 Docker owner 并执行
     quiesce；省略 --runtime 会按 native 处理。部署成功后脚本会打印下一步命令。

常用示例（正式上传首选 PROJECT HOST；--host 仅保留为兼容写法）：
  # 只在本地构建、验证并列出归档内容；不连接 SSH
  python3 tools/tar-for-upload.py \\
    2099-example-site --runtime native --dry-run

  # 仅打包、上传和校验；推荐先使用此模式
  python3 tools/tar-for-upload.py \\
    2099-example-site \\
    ubuntu@ztp-admin.example \\
    --port 21018 --runtime native

  # 上传并自动部署（要求 ubuntu 可以 sudo -n）
  python3 tools/tar-for-upload.py \\
    2099-example-site \\
    ubuntu@ztp-admin.example \\
    --port 21018 --runtime native --deploy

  # 已经只上传并审核：复用同一归档受控部署，不重新打包或传输
  python3 tools/tar-for-upload.py \
    2099-example-site \
    ubuntu@ztp-admin.example \
    --port 21018 --runtime native \
    --deploy-uploaded DAY0-Prepare/dumps/2099-example-site-<timestamp>-upload.tar.gz

  # Docker/Supervisor 上传并受控部署；runtime 必须显式选择
  python3 tools/tar-for-upload.py \\
    2099-example-site \\
    ubuntu@ztp-admin.example \\
    --port 21018 --runtime docker --deploy

  # 使用指定私钥，并把共享系统镜像加入部署包
  python3 tools/tar-for-upload.py \\
    -p 2099-example-site \\
    ubuntu@ztp-admin.example --port 21018 \\
    --identity ~/.ssh/id_ed25519 --include-images --runtime native

  # 目标管理服务器没有 Internet：明确归档已准备好的离线 APT 仓库
  python3 tools/tar-for-upload.py \
    -p 2099-example-site ubuntu@ztp-admin.example \
    --runtime native --include-apps --target-os ubuntu-22.04 --target-arch amd64

  # mgmt 是 22.04/amd64，同时还要服务离线的 24.04/arm64 client
  python3 tools/tar-for-upload.py \
    -p 2099-example-site ubuntu@ztp-admin.example \
    --runtime native --include-apps --target-os ubuntu-22.04 --target-arch amd64 \
    --client-platform ubuntu-24.04/arm64

权限与故障处理：
  * 默认远端暂存目录是 /tmp，部署根目录是 /var/www/html。
  * `.partial` 会在传输中断后保留；使用相同归档名重新执行会从已有长度续传。
    SHA-256 不一致时脚本会删除不可信前缀并完整重传一次。
  * Permission denied：不要反复重试 --deploy；登录管理服务器，以 root
    身份从本地重新运行同一命令并增加 --deploy --no-sudo；不要绕过锁单独解包。
  * REMOTE HOST IDENTIFICATION HAS CHANGED：先通过可信渠道核对新指纹，
    再清理对应 hostname/IP 的旧 known_hosts 记录。
  * 默认输出位于 DAY0-Prepare/dumps/；本地同名包已存在时，更换 -o，
    或确认后使用 --force。
"""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-p", "--project", dest="project_option", metavar="PROJECT",
                        help="single DAY0 project name/path to deploy")
    parser.add_argument("project_path", nargs="?", metavar="PROJECT",
                        help="project directory (alternative to -p/--project)")
    parser.add_argument(
        "host_path", nargs="?", metavar="HOST",
        help="SSH destination as a second positional operand",
    )
    parser.add_argument("--host",
                        help=("SSH destination, for example ubuntu@worker.example "
                              "(legacy alternative to positional HOST)"))
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--identity", type=Path, help="SSH private key")
    parser.add_argument(
        "--transport", choices=("auto", "rsync", "scp"), default="auto",
        help=("upload transport (default: auto; prefer resumable rsync when it is "
              "available locally and remotely, otherwise use scp)"),
    )
    parser.add_argument(
        "--upload-retries", type=int, default=3,
        help="maximum transfer attempts after an interrupted SSH connection (default: 3)",
    )
    parser.add_argument(
        "--transfer-timeout", type=int, default=3600,
        help="maximum seconds for one transfer attempt (default: 3600)",
    )
    parser.add_argument("--remote-dir", default="/tmp",
                        help="remote archive directory (default: /tmp)")
    parser.add_argument("--remote-root", default="/var/www/html",
                        help="deployment extraction root (default: /var/www/html)")
    parser.add_argument(
        "--runtime", choices=("native", "docker"), default="native",
        help=(
            "management-server runtime (default: native; select docker for "
            "the host-network container deployment)"
        ),
    )
    parser.add_argument("--deploy", action="store_true",
                        help="after verification, remotely extract with sudo -n")
    parser.add_argument(
        "--deploy-uploaded", type=Path, metavar="ARCHIVE",
        help=(
            "deploy one already uploaded local archive after rechecking its "
            "identity and the matching remote SHA; do not rebuild or retransmit"
        ),
    )
    parser.add_argument("--no-sudo", action="store_true",
                        help="with --deploy, extract directly (for a root SSH login)")
    parser.add_argument(
        "-o", "--output", type=Path,
        help=(
            "local deployment archive (default: DAY0-Prepare/dumps/"
            "<project>-<timestamp>-upload.tar.gz; forbidden with dry-run/list-only)"
        ),
    )
    parser.add_argument(
        "--relay-bundle", type=Path, metavar="DIRECTORY",
        help=(
            "create a transportable upload-release directory containing only "
            "the project archive, its matching deploy-upload-archive.py, "
            "metadata, and SHA256SUMS; no HOST or SSH is used"
        ),
    )
    parser.add_argument("--include-images", action="store_true")
    apps = parser.add_mutually_exclusive_group()
    apps.add_argument(
        "--include-apps", dest="include_apps", action="store_true",
        help="include the prepared apps/ offline APT repository",
    )
    apps.add_argument(
        "--exclude-apps", "--no-include-apps", dest="include_apps",
        action="store_false",
        help="omit apps/ because the target management server has Internet access",
    )
    parser.set_defaults(include_apps=None)
    parser.add_argument(
        "--target-os", choices=("ubuntu-22.04", "ubuntu-24.04"),
        help="target management-server OS; required with offline apps in non-interactive mode",
    )
    parser.add_argument(
        "--target-arch", choices=("amd64", "arm64"),
        help="target management-server architecture; required with offline apps in non-interactive mode",
    )
    parser.add_argument(
        "--client-platform", action="append", default=[],
        choices=(
            "ubuntu-22.04/amd64", "ubuntu-22.04/arm64",
            "ubuntu-24.04/amd64", "ubuntu-24.04/arm64",
        ),
        help=("additional offline client OS/architecture repository to include; "
              "repeat for multiple client platforms"),
    )
    parser.add_argument("--include-firmware", action="store_true")
    parser.add_argument("--max-file-size-mib", type=int,
                        default=package_core.DEFAULT_MAX_FILE_MIB)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "-n", "--dry-run", "--list-only", dest="dry_run", action="store_true",
        help="build, verify and list the local archive without SSH/upload",
    )
    # HOST is intentionally a second positional operand.  Use argparse's
    # intermixed parser so operators can put ordinary options (for example
    # ``--port``) between PROJECT and HOST without changing their command.
    args = parser.parse_intermixed_args(argv)
    positional_host = args.host_path
    if args.project_option:
        if args.host_path:
            parser.error("too many positional operands after -p/--project")
        positional_host = args.project_path
        args.project = args.project_option
    else:
        args.project = args.project_path
    if not args.project:
        parser.error("provide a project directory, or use -p/--project")
    if args.dry_run and args.output is not None:
        parser.error(
            "--dry-run/--list-only cannot be combined with --output; "
            "preview archives are private temporary files and are deleted on exit"
        )
    if positional_host and args.host:
        parser.error("provide HOST positionally or with --host, not both")
    args.host = args.host or positional_host
    if not args.dry_run and args.relay_bundle is None and not args.host:
        parser.error("HOST is required unless --dry-run/--list-only is used")
    if args.runtime == "docker" and args.remote_root != "/var/www/html":
        parser.error("--runtime docker requires --remote-root /var/www/html")
    if args.deploy_uploaded is not None:
        if args.deploy or args.dry_run:
            parser.error("--deploy-uploaded cannot be combined with --deploy/--dry-run")
        package_options = (
            args.output is not None
            or args.include_images
            or args.include_apps is not None
            or args.target_os is not None
            or args.target_arch is not None
            or bool(args.client_platform)
            or args.include_firmware
            or args.force
            or args.max_file_size_mib != package_core.DEFAULT_MAX_FILE_MIB
        )
        if package_options:
            parser.error("--deploy-uploaded cannot be combined with package-building options")
        args.deploy = True
    if args.relay_bundle is not None:
        if args.host:
            parser.error("--relay-bundle is local-only and cannot be combined with HOST")
        if args.deploy or args.deploy_uploaded is not None or args.dry_run:
            parser.error(
                "--relay-bundle cannot be combined with --deploy, "
                "--deploy-uploaded, or --dry-run"
            )
        package_conflicts = (
            args.output is not None
            or args.include_images
            or args.include_apps is not None
            or args.target_os is not None
            or args.target_arch is not None
            or bool(args.client_platform)
            or args.include_firmware
            or args.force
        )
        if package_conflicts:
            parser.error(
                "--relay-bundle externalizes images/apps/firmware; do not combine "
                "it with legacy package-content or output options"
            )
        transport_conflicts = (
            args.identity is not None
            or args.port != 22
            or args.transport != "auto"
            or args.upload_retries != 3
            or args.transfer_timeout != 3600
            or args.remote_dir != "/tmp"
            or args.remote_root != "/var/www/html"
            or args.no_sudo
        )
        if transport_conflicts:
            parser.error("--relay-bundle cannot be combined with SSH/remote options")
    del args.project_option
    del args.project_path
    del args.host_path
    return args


def validate_flat_apt_repository(repository: Path, platform: str) -> None:
    """Reject an indexed repository whose payload is missing or mismatched."""
    index = repository / "Packages.gz"
    try:
        with gzip.open(index, "rt", encoding="utf-8", errors="strict") as stream:
            content = stream.read()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"apps/{platform}/Packages.gz 无法读取：{exc}") from exc
    filenames = re.findall(r"^Filename:\s*(\S+)\s*$", content, flags=re.MULTILINE)
    packages = set(re.findall(r"^Package:\s*(\S+)\s*$", content, flags=re.MULTILINE))
    architectures = re.findall(r"^Architecture:\s*(\S+)\s*$", content, flags=re.MULTILINE)
    if not filenames:
        raise ValueError(f"apps/{platform}/Packages.gz 没有软件包记录")
    expected_arch = platform.rsplit("/", 1)[1]
    mismatched = sorted({item for item in architectures if item not in {expected_arch, "all"}})
    if mismatched:
        raise ValueError(
            f"apps/{platform}/Packages.gz 含错误架构：{', '.join(mismatched)}"
        )
    missing = []
    for filename in filenames:
        relative = filename.removeprefix("./")
        candidate = repository / relative
        try:
            candidate.resolve().relative_to(repository.resolve())
        except ValueError:
            raise ValueError(f"apps/{platform}/Packages.gz 含越界路径：{filename}")
        if not candidate.is_file():
            missing.append(relative)
    if missing:
        preview = ", ".join(missing[:5])
        suffix = f"（另有 {len(missing) - 5} 个）" if len(missing) > 5 else ""
        raise ValueError(f"apps/{platform} 索引引用缺失文件：{preview}{suffix}")
    missing_roots = sorted(REQUIRED_OFFLINE_PACKAGES - packages)
    if missing_roots:
        raise ValueError(
            f"apps/{platform} 缺少 infra 管理服务器必需包："
            f"{', '.join(missing_roots)}；请用当前 infra-setup.sh 重新构建仓库"
        )
    expected_os, expected_arch = platform.split("/", 1)
    expected_version = expected_os.removeprefix("ubuntu-")
    metadata_path = repository / "repository.meta"
    if not metadata_path.is_file():
        raise ValueError(
            f"apps/{platform}/repository.meta 不存在；请用当前 infra-setup.sh 重新构建仓库"
        )
    metadata = {}
    for line in metadata_path.read_text(encoding="utf-8", errors="strict").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            metadata[key.strip()] = value.strip()
    expected = {
        "schema_version": "1", "os_id": "ubuntu",
        "os_version": expected_version, "architecture": expected_arch,
    }
    mismatched_meta = [
        f"{key}={metadata.get(key, '<missing>')}（应为 {value}）"
        for key, value in expected.items() if metadata.get(key) != value
    ]
    if mismatched_meta:
        raise ValueError(
            f"apps/{platform}/repository.meta 与目标平台不一致："
            + ", ".join(mismatched_meta)
        )


def resolve_apps_policy(args: argparse.Namespace) -> None:
    """Choose whether an upload must carry the offline APT repository."""
    if args.include_apps is None:
        if args.dry_run:
            args.include_apps = False
            args.apps_platform = None
            args.apps_platforms = set()
            print(
                "[INFO] Dry-run defaults to excluding apps/; use --include-apps "
                "to preview the offline repository payload"
            )
            return
        if not sys.stdin.isatty():
            raise ValueError(
                "non-interactive upload must specify --include-apps when the target "
                "has no Internet, or --exclude-apps when it has Internet"
            )
        print(
            "目标管理服务器能否直接访问 Internet？直接回车或 15 秒无输入默认 yes；"
            "回答 no 时归档 apps/ 离线仓库 [Y/n]：",
            end="", flush=True,
        )
        ready, _, _ = select.select([sys.stdin], [], [], 15)
        answer = sys.stdin.readline().strip().casefold() if ready else ""
        if not ready:
            print("yes")
        if answer not in {"", "y", "yes", "n", "no"}:
            raise ValueError("Internet 选择必须是 yes 或 no")
        args.include_apps = answer in {"n", "no"}
    if args.include_apps:
        if not args.target_os or not args.target_arch:
            if not sys.stdin.isatty():
                raise ValueError(
                    "--include-apps requires --target-os ubuntu-22.04|ubuntu-24.04 "
                    "and --target-arch amd64|arm64 in non-interactive mode"
                )
            if not args.target_os:
                args.target_os = input(
                    "目标管理服务器 OS（ubuntu-22.04 或 ubuntu-24.04）："
                ).strip().casefold()
            if not args.target_arch:
                args.target_arch = input(
                    "目标管理服务器架构（amd64 或 arm64）："
                ).strip().casefold()
        if args.target_os not in {"ubuntu-22.04", "ubuntu-24.04"}:
            raise ValueError("目标 OS 必须是 ubuntu-22.04 或 ubuntu-24.04")
        if args.target_arch not in {"amd64", "arm64"}:
            raise ValueError("目标架构必须是 amd64 或 arm64")
        args.apps_platform = f"{args.target_os}/{args.target_arch}"
        args.apps_platforms = {
            args.apps_platform,
            *getattr(args, "client_platform", []),
        }
        for platform in sorted(args.apps_platforms):
            repository = package_core.ROOT / "apps" / platform
            if not (repository / "Packages.gz").is_file():
                raise ValueError(
                    f"选择了离线部署，但缺少 apps/{platform}/Packages.gz；"
                    "请先在相同 Ubuntu 版本/架构的联网服务器运行 infra-setup.sh --mgmt"
                )
            if not any(repository.glob("*.deb")):
                raise ValueError(f"apps/{platform} 没有 .deb，离线仓库不完整")
            validate_flat_apt_repository(repository, platform)
        joined = ", ".join(f"apps/{item}" for item in sorted(args.apps_platforms))
        print(f"[INFO] 目标无 Internet：仅归档 {joined}")
    else:
        if args.target_os or args.target_arch or getattr(args, "client_platform", []):
            raise ValueError(
                "--target-os/--target-arch/--client-platform 仅与 --include-apps 一起使用"
            )
        args.apps_platform = None
        args.apps_platforms = set()
        print("[INFO] 目标有 Internet：不归档 apps/ 离线仓库")


def default_output(project: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in project.name
    )
    return package_core.DAY0 / "dumps" / f"{safe}-{stamp}-upload.tar.gz"


def command_base(tool: str, args: argparse.Namespace) -> list[str]:
    command = [tool]
    if tool == "scp":
        command += ["-P", str(args.port)]
    else:
        command += ["-p", str(args.port)]
    command += [
        "-o", "ConnectTimeout=20",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "TCPKeepAlive=yes",
    ]
    if args.identity:
        command += ["-i", str(args.identity)]
    return command


def run(command: list[str], *, timeout: int | None = None) -> str:
    try:
        completed = subprocess.run(
            command, text=True, check=False, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"command timed out after {timeout}s: {command[0]}"
        ) from exc
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"command failed: {command[0]}")
    return completed.stdout


def run_streaming(command: list[str], *, timeout: int) -> None:
    """Run a transfer with live progress instead of buffering its stderr."""
    print(f"[RUN] {shlex.join(command)}")
    try:
        completed = subprocess.run(command, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"transfer timed out after {timeout}s: {command[0]}"
        ) from exc
    if completed.returncode != 0:
        raise RuntimeError(
            f"transfer command failed (exit={completed.returncode}): {command[0]}"
        )


def run_predeploy_test_gate() -> None:
    """Require the exact full-suite attestation created by local load."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式上传/部署测试门禁不存在或不是普通文件：{runner}")
    check = [
        sys.executable, "-B", str(runner), "--check", "--require-full",
    ]
    print("[TEST] 正式上传/部署前复用精确全量测试证明：" + shlex.join(check))
    completed = subprocess.run(check, cwd=ROOT, shell=False, check=False)
    if completed.returncode == 0:
        print("[OK] 当前精确字节已有本机 load 生成的全量测试证明；不运行全量测试")
        return
    raise RuntimeError(
        f"正式上传/部署缺少本机 load 生成的有效全量测试证明"
        f"（exit={completed.returncode}）；请先在当前工作树成功执行本机正式 load；"
        "尚未打包，远端未连接、未修改"
    )


def verify_predeploy_test_approval() -> None:
    """Reject source/test drift after packaging and before the first SSH call."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式上传/部署测试门禁不存在或不是普通文件：{runner}")
    command = [
        sys.executable, "-B", str(runner), "--check", "--require-full",
    ]
    print("[TEST] 上传前复核批准状态：" + shlex.join(command))
    completed = subprocess.run(
        command, cwd=ROOT, shell=False, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"打包后批准状态已变化（exit={completed.returncode}）；"
            "远端未连接、未修改，请重新运行"
        )
    print("[OK] 源码、测试和影响矩阵仍与全量测试批准状态一致")


def _copy_stable_regular(
    source: Path,
    destination: Path,
    *,
    mode: int,
    maximum_size: int,
) -> tuple[int, str]:
    """Copy one current-user-owned, no-follow authority into a private bundle."""
    source = source.expanduser()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    output = -1
    try:
        descriptor = os.open(source, flags)
        before = os.fstat(descriptor)
        path_before = os.lstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > maximum_size
            or (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino)
        ):
            raise RuntimeError(f"unsafe relay-bundle source file: {source}")
        output = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
            if not block:
                raise RuntimeError(f"relay-bundle source was truncated: {source}")
            digest.update(block)
            _write_all(output, block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise RuntimeError(f"relay-bundle source grew while copying: {source}")
        os.fsync(output)
        os.fchmod(output, mode)
        after = os.fstat(descriptor)
        path_after = os.lstat(source)
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable):
            raise RuntimeError(f"relay-bundle source changed while copying: {source}")
        if (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError(f"relay-bundle source path changed while copying: {source}")
        return before.st_size, digest.hexdigest()
    finally:
        if output >= 0:
            os.close(output)
        if descriptor >= 0:
            os.close(descriptor)


def _write_private_file(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _load_relay_installer(path: Path):
    name = "_http_ztp_relay_bundle_installer"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load relay installer authority: {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def _open_relay_bundle_parent(destination: Path) -> tuple[Path, str, int, os.stat_result]:
    """Open/create the lexical parent without following any path component."""
    expanded = destination.expanduser()
    absolute = Path(os.path.abspath(os.fspath(expanded)))
    name = absolute.name
    if name in {"", ".", ".."} or not SAFE_ARCHIVE_NAME.fullmatch(name):
        raise ValueError(f"unsafe relay bundle destination name: {name!r}")
    parent = absolute.parent
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(parent.anchor, flags)
    current = Path(parent.anchor)
    try:
        for part in parent.parts[1:]:
            current /= part
            try:
                metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError(
                    f"relay bundle output parent cannot contain a symlink: {current}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise RuntimeError(
                    f"relay bundle output parent component is not a directory: {current}"
                )
            child = os.open(part, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                os.close(child)
                raise RuntimeError(
                    f"relay bundle output parent changed while opening: {current}"
                )
            os.close(descriptor)
            descriptor = child
        parent_status = os.fstat(descriptor)
        named_status = os.lstat(parent)
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or (parent_status.st_dev, parent_status.st_ino)
            != (named_status.st_dev, named_status.st_ino)
            or parent_status.st_uid != os.geteuid()
            or stat.S_IMODE(parent_status.st_mode) & 0o022
        ):
            raise RuntimeError(
                "relay bundle output parent must be one current-user-owned, "
                f"non-group/world-writable real directory: {parent}"
            )
        return parent, name, descriptor, parent_status
    except BaseException:
        os.close(descriptor)
        raise


def _make_relay_bundle_stage(
    parent: Path, parent_descriptor: int, destination_name: str,
) -> tuple[Path, str, os.stat_result]:
    prefix = f".{destination_name}.tmp."
    for _attempt in range(128):
        stage_name = prefix + secrets.token_hex(12)
        try:
            os.mkdir(stage_name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        stage_status = os.stat(
            stage_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(stage_status.st_mode)
            or stage_status.st_uid != os.geteuid()
            or stat.S_IMODE(stage_status.st_mode) != 0o700
        ):
            raise RuntimeError("relay bundle private staging directory is unsafe")
        return parent / stage_name, stage_name, stage_status
    raise RuntimeError("cannot allocate a unique relay bundle staging directory")


def _relay_bundle_parent_is_unchanged(
    parent: Path, descriptor: int, expected: os.stat_result,
) -> bool:
    opened = os.fstat(descriptor)
    try:
        named = os.lstat(parent)
    except OSError:
        return False
    return (
        stat.S_ISDIR(opened.st_mode)
        and stat.S_ISDIR(named.st_mode)
        and not stat.S_ISLNK(named.st_mode)
        and (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
        and (named.st_dev, named.st_ino) == (expected.st_dev, expected.st_ino)
        and opened.st_uid == os.geteuid()
        and not (stat.S_IMODE(opened.st_mode) & 0o022)
    )


def _rename_relay_bundle_noreplace(
    parent_descriptor: int, stage_name: str, destination_name: str,
) -> None:
    """Atomically publish within the held parent, refusing any replacement."""
    libc = ctypes.CDLL(None, use_errno=True)
    result = None
    if sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        if operation is not None:
            operation.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            operation.restype = ctypes.c_int
            result = operation(
                parent_descriptor, os.fsencode(stage_name),
                parent_descriptor, os.fsencode(destination_name), 1,
            )
    elif sys.platform == "darwin":
        operation = getattr(libc, "renameatx_np", None)
        if operation is not None:
            operation.argtypes = (
                ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_uint,
            )
            operation.restype = ctypes.c_int
            result = operation(
                parent_descriptor, os.fsencode(stage_name),
                parent_descriptor, os.fsencode(destination_name), 0x00000004,
            )
    if result is None:
        raise RuntimeError(
            "atomic no-replace relay bundle publication is unavailable"
        )
    if result != 0:
        number = ctypes.get_errno()
        if number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                number, "relay bundle destination appeared during publication",
                destination_name,
            )
        raise OSError(number, os.strerror(number), destination_name)


def _remove_relay_bundle_stage(
    parent_descriptor: int, stage_name: str, expected: os.stat_result,
) -> None:
    """Remove only the exact private stage through its held parent descriptor."""
    try:
        current = os.stat(
            stage_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)
        or current.st_uid != os.geteuid()
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        raise RuntimeError(
            "relay bundle staging identity changed; refusing recursive cleanup"
        )
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    stage_descriptor = os.open(stage_name, flags, dir_fd=parent_descriptor)
    try:
        opened = os.fstat(stage_descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError("relay bundle staging changed before cleanup")
        for name in os.listdir(stage_descriptor):
            member = os.stat(name, dir_fd=stage_descriptor, follow_symlinks=False)
            if stat.S_ISDIR(member.st_mode):
                raise RuntimeError(
                    "relay bundle staging contains an unexpected directory; "
                    "refusing recursive cleanup"
                )
            os.unlink(name, dir_fd=stage_descriptor)
        os.fsync(stage_descriptor)
    finally:
        os.close(stage_descriptor)
    os.rmdir(stage_name, dir_fd=parent_descriptor)


def publish_relay_bundle(
    destination: Path,
    frozen_archive: Path,
    *,
    project_name: str,
    runtime: str,
    expected_archive_sha256: str,
    installer_path: Path = RELAY_INSTALLER,
) -> Path:
    """Publish one independently versioned upload release without image payloads."""
    if runtime not in {"native", "docker"}:
        raise ValueError(f"unsupported runtime: {runtime}")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", project_name):
        raise ValueError(f"unsafe project name for relay bundle: {project_name!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256):
        raise ValueError("expected relay archive SHA-256 is invalid")
    parent, destination_name, parent_descriptor, parent_status = (
        _open_relay_bundle_parent(destination)
    )
    destination = parent / destination_name
    try:
        os.stat(destination_name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except BaseException:
        os.close(parent_descriptor)
        raise
    else:
        os.close(parent_descriptor)
        raise FileExistsError(f"relay bundle destination already exists: {destination}")

    try:
        staging, stage_name, stage_status = _make_relay_bundle_stage(
            parent, parent_descriptor, destination_name,
        )
    except BaseException:
        os.close(parent_descriptor)
        raise
    archive_name = f"{project_name}-upload.tar.gz"
    archive_output = staging / archive_name
    installer_output = staging / "deploy-upload-archive.py"
    completed = False
    cleanup_name = stage_name
    try:
        archive_size, archive_sha256 = _copy_stable_regular(
            frozen_archive,
            archive_output,
            mode=0o600,
            maximum_size=MAX_RELAY_ARCHIVE_BYTES,
        )
        if archive_sha256 != expected_archive_sha256:
            raise RuntimeError("frozen upload archive digest changed before relay publish")
        installer_size, installer_sha256 = _copy_stable_regular(
            installer_path,
            installer_output,
            mode=0o500,
            maximum_size=MAX_RELAY_AUTHORITY_BYTES,
        )
        installer = _load_relay_installer(installer_output)
        try:
            verified = installer.verify_inputs(
                archive_output,
                installer_output,
                required_uid=os.getuid(),
            )
        except Exception as exc:
            raise RuntimeError(f"relay upload archive verification failed: {exc}") from exc
        if verified.project != project_name:
            raise RuntimeError(
                "relay upload archive project mismatch: "
                f"expected={project_name} actual={verified.project}"
            )
        if verified.archive_sha256 != archive_sha256:
            raise RuntimeError("relay installer observed a different archive digest")

        metadata = {
            "artifact_type": "http-ztp-upload-release",
            "schema_version": 1,
            "project": project_name,
            "runtime": runtime,
            "source_manifest_sha256": verified.source_manifest_sha256,
            "upload_archive": {
                "name": archive_name,
                "size": archive_size,
                "sha256": archive_sha256,
            },
            "installer": {
                "name": installer_output.name,
                "size": installer_size,
                "sha256": installer_sha256,
            },
        }
        metadata_bytes = (
            json.dumps(metadata, ensure_ascii=True, sort_keys=True, indent=2).encode("ascii")
            + b"\n"
        )
        metadata_path = staging / "upload-metadata.json"
        _write_private_file(metadata_path, metadata_bytes)
        records = []
        for item in (archive_output, installer_output, metadata_path):
            records.append(f"{package_core.sha256(item)}  {item.name}\n")
        _write_private_file(
            staging / "SHA256SUMS",
            "".join(records).encode("ascii"),
        )
        directory_fd = os.open(
            stage_name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            opened_stage = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(opened_stage.st_mode)
                or (opened_stage.st_dev, opened_stage.st_ino)
                != (stage_status.st_dev, stage_status.st_ino)
            ):
                raise RuntimeError("relay bundle staging changed before sync")
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if not _relay_bundle_parent_is_unchanged(
            parent, parent_descriptor, parent_status,
        ):
            raise RuntimeError("relay bundle output parent changed before publish")
        named_stage = os.stat(
            stage_name, dir_fd=parent_descriptor, follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(named_stage.st_mode)
            or (named_stage.st_dev, named_stage.st_ino)
            != (stage_status.st_dev, stage_status.st_ino)
        ):
            raise RuntimeError("relay bundle staging path changed before publish")
        try:
            os.stat(
                destination_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(
                f"relay bundle destination appeared: {destination}"
            )
        _rename_relay_bundle_noreplace(
            parent_descriptor, stage_name, destination_name,
        )
        cleanup_name = destination_name
        published = os.stat(
            destination_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(published.st_mode)
            or (published.st_dev, published.st_ino)
            != (stage_status.st_dev, stage_status.st_ino)
        ):
            raise RuntimeError("relay bundle published directory identity changed")
        os.fsync(parent_descriptor)
        if not _relay_bundle_parent_is_unchanged(
            parent, parent_descriptor, parent_status,
        ):
            raise RuntimeError("relay bundle output parent changed during publish")
        completed = True
        print(f"[OK] upload release bundle: {destination}")
        print(f"[OK] upload archive SHA-256={archive_sha256} bytes={archive_size}")
        print(
            f"[OK] relay installer SHA-256={installer_sha256} bytes={installer_size}"
        )
        print("[INFO] Docker image and shared artifacts are independently versioned")
        return destination
    finally:
        try:
            if not completed:
                _remove_relay_bundle_stage(
                    parent_descriptor, cleanup_name, stage_status,
                )
        finally:
            os.close(parent_descriptor)


def build_relay_bundle(args: argparse.Namespace, project: Path) -> Path:
    """Build, freeze, recheck, and publish one local relay upload release."""
    with tempfile.TemporaryDirectory(prefix="http-upload-relay-build-") as directory:
        package_args = argparse.Namespace(**vars(args))
        package_args.output = Path(directory) / f"{project.name}-upload.tar.gz"
        package_args.force = False
        package_args.include_images = False
        package_args.include_apps = False
        package_args.apps_platform = None
        package_args.apps_platforms = set()
        package_args.include_firmware = False
        package_args.exclude_project_images = True
        archive = package_core.create_package(
            package_args, day0_all=False, artifact_kind="upload",
        )
        with frozen_archive_for_upload(archive) as frozen:
            frozen_archive, frozen_sha256 = frozen
            verify_predeploy_test_approval()
            return publish_relay_bundle(
                args.relay_bundle,
                frozen_archive,
                project_name=project.name,
                runtime=args.runtime,
                expected_archive_sha256=frozen_sha256,
            )


def remote_rsync_available(args: argparse.Namespace, ssh: list[str]) -> bool:
    if shutil.which("rsync") is None:
        return False
    try:
        output = run(
            ssh + [args.host, "command", "-v", "rsync"],
            timeout=30,
        )
    except RuntimeError:
        return False
    return bool(output.strip())


def remote_sha256(ssh: list[str], host: str, path: str) -> str | None:
    try:
        output = run(ssh + [host, "sha256sum", path], timeout=60)
    except RuntimeError:
        return None
    fields = output.split()
    if not fields or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[0]):
        return None
    return fields[0].lower()


def deployment_payload_command(
    args: argparse.Namespace, remote_path: str, expected_sha256: str | None = None,
) -> str:
    """Build the locked, fail-closed safe-overlay command run on the server."""
    root = args.remote_root.rstrip("/") or "/"
    lock_path = root.rstrip("/") + "/.deployment.lock"
    if expected_sha256 is None or not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_sha256,
    ):
        raise ValueError("expected SHA-256 must contain exactly 64 hex digits")
    payload = package_core.remote_locked_archive_argv(
        lock_path, remote_path, expected_sha256.casefold(),
        use_sudo=not args.no_sudo, http_root=root,
        runtime=getattr(args, "runtime", "native"),
        guard_source=getattr(args, "deployment_guard_source", ""),
        source_manifest_sha256=getattr(
            args, "deployment_source_manifest_sha256", "",
        ),
    )
    return shlex.join(payload)


def deployment_guard_source_from_archive(archive_path: Path) -> str:
    """Load the already-tested guard bytes from the immutable upload archive."""
    guard_name = "./tools/deployment_prewrite_guard.py"
    manifest_name = "./infra/docker/deployment-source-manifest.json"
    try:
        with package_core.tarfile.open(archive_path, "r:gz") as archive:
            guard_member = archive.getmember(guard_name)
            manifest_member = archive.getmember(manifest_name)
            if (
                not guard_member.isfile()
                or not manifest_member.isfile()
                or guard_member.size <= 0
                or guard_member.size > 4 * 1024 * 1024
                or manifest_member.size <= 0
                or manifest_member.size > 4 * 1024 * 1024
            ):
                raise RuntimeError("archive deployment guard authority is unsafe")
            guard_stream = archive.extractfile(guard_member)
            manifest_stream = archive.extractfile(manifest_member)
            if guard_stream is None or manifest_stream is None:
                raise RuntimeError("archive deployment guard authority is unreadable")
            guard_bytes = guard_stream.read()
            manifest_bytes = manifest_stream.read()
        manifest = json.loads(manifest_bytes.decode("ascii"))
        matches = [
            record for record in manifest.get("files", ())
            if isinstance(record, dict)
            and record.get("path") == "tools/deployment_prewrite_guard.py"
        ]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError,
            package_core.tarfile.TarError) as exc:
        raise RuntimeError(f"cannot freeze archive deployment guard: {exc}") from exc
    if (
        len(matches) != 1
        or matches[0].get("type") != "file"
        or matches[0].get("sha256") != hashlib.sha256(guard_bytes).hexdigest()
    ):
        raise RuntimeError("archive deployment guard does not match source manifest")
    try:
        return guard_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise RuntimeError(f"archive deployment guard is not UTF-8: {exc}") from exc


def deployment_source_manifest_sha256_from_archive(archive_path: Path) -> str:
    """Hash the separately tested source authority carried by the archive."""
    name = "./infra/docker/deployment-source-manifest.json"
    try:
        with package_core.tarfile.open(archive_path, "r:gz") as archive:
            member = archive.getmember(name)
            if not member.isfile() or member.size <= 0 or member.size > 16 * 1024 * 1024:
                raise RuntimeError("archive source manifest authority is unsafe")
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError("archive source manifest authority is unreadable")
            payload = stream.read()
    except (OSError, KeyError, package_core.tarfile.TarError) as exc:
        raise RuntimeError(f"cannot freeze archive source manifest: {exc}") from exc
    return hashlib.sha256(payload).hexdigest()


def validate_uploaded_archive_for_deploy(archive_path: Path, project: Path) -> None:
    """Revalidate one reviewed archive without rebuilding it.

    The archive must still carry the current tested production-source manifest
    and the selected project's core inputs.  This mode intentionally deploys
    the immutable reviewed bytes rather than packaging the mutable workspace a
    second time.
    """
    manifest_name = f"./{package_core.DEPLOYMENT_SOURCE_MANIFEST_RELATIVE.as_posix()}"
    project_relative = project.relative_to(ROOT).as_posix()
    required = {
        manifest_name,
        "./tools/deployment_prewrite_guard.py",
        f"./{project_relative}/01-global.yaml",
        f"./{project_relative}/02-devices_config.csv",
        f"./{project_relative}/02-dhcp-subnet_config.csv",
    }
    try:
        with package_core.tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            package_core.validate_deployment_archive_members(members)
            by_name = {member.name: member for member in members}
            missing = sorted(required - set(by_name))
            if missing:
                raise RuntimeError(
                    "reviewed archive is missing required deployment members: "
                    + ", ".join(missing)
                )
            for name in sorted(required):
                member = by_name[name]
                if not member.isfile() or member.size <= 0:
                    raise RuntimeError(
                        f"reviewed archive member must be a non-empty regular file: {name}"
                    )
            stream = archive.extractfile(manifest_name)
            if stream is None:
                raise RuntimeError("reviewed archive source manifest is unreadable")
            archive_manifest = stream.read()
    except (OSError, KeyError, package_core.tarfile.TarError) as exc:
        raise RuntimeError(f"cannot validate reviewed upload archive: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="http-upload-current-manifest-") as directory:
        current_path = package_core.write_deployment_source_manifest(
            Path(directory) / "deployment-source-manifest.json",
        )
        current_manifest = current_path.read_bytes()
    if archive_manifest != current_manifest:
        raise RuntimeError(
            "reviewed archive does not match the current tested production source; "
            "run local load and create a new upload archive"
        )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while freezing deployment archive")
        view = view[written:]


@contextmanager
def frozen_archive_for_upload(archive_path: Path):
    """Yield a private, read-only copy of one no-follow archive FD.

    The formal approval check and every subsequent archive inspection/upload
    use this copy.  Replacing or editing the public output path after the copy
    therefore cannot substitute bytes after the local gate has approved the
    release.
    """
    archive_path = archive_path.expanduser()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    temporary = None
    try:
        descriptor = os.open(archive_path, flags)
        before = os.fstat(descriptor)
        path_status = os.lstat(archive_path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (path_status.st_dev, path_status.st_ino)
        ):
            raise RuntimeError("deployment archive must be one direct regular file")
        temporary = tempfile.TemporaryDirectory(
            prefix=".http-upload-frozen-", dir=archive_path.parent,
        )
        snapshot = Path(temporary.name) / archive_path.name
        output = os.open(
            snapshot,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        digest = hashlib.sha256()
        try:
            while True:
                block = os.read(descriptor, 4 * 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                _write_all(output, block)
            os.fsync(output)
            os.fchmod(output, 0o400)
        finally:
            os.close(output)
        after = os.fstat(descriptor)
        current = os.lstat(archive_path)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, name) != getattr(after, name) for name in stable_fields):
            raise RuntimeError("deployment archive changed while it was being frozen")
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("deployment archive path changed while it was being frozen")
        frozen_digest = digest.hexdigest()
        if package_core.sha256(snapshot) != frozen_digest:
            raise RuntimeError("private archive snapshot verification failed")
        yield snapshot, frozen_digest
    except OSError as exc:
        raise RuntimeError(f"cannot freeze deployment archive: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.cleanup()


def remote_deployment_command(
    args: argparse.Namespace, remote_path: str, expected_sha256: str | None = None,
) -> list[str]:
    """Return the local SSH argv for one locked remote archive deployment."""
    return command_base("ssh", args) + [
        args.host, deployment_payload_command(args, remote_path, expected_sha256),
    ]


def transfer_with_retries(
    command_factory,
    *,
    attempts: int,
    timeout: int,
    resumable: bool,
) -> None:
    for attempt in range(1, attempts + 1):
        try:
            run_streaming(command_factory(), timeout=timeout)
            return
        except RuntimeError as exc:
            if attempt >= attempts:
                raise
            mode = "保留 .partial 并续传" if resumable else "从头重试"
            print(
                f"[WARN] 上传第 {attempt}/{attempts} 次中断：{exc}；"
                f"2 秒后{mode}",
                file=sys.stderr,
            )
            time.sleep(2)


def recommended_deploy_rerun_command(args: argparse.Namespace) -> list[str]:
    """Build a short command that deploys the exact archive just uploaded."""
    archive = getattr(args, "output", None)
    if archive is None:
        raise ValueError("uploaded archive path is unavailable")
    command = [
        "python3", "tools/tar-for-upload.py", str(getattr(args, "project", "<project>")),
        args.host, "--port", str(args.port),
        "--runtime", getattr(args, "runtime", "native"),
        "--deploy-uploaded", str(archive),
    ]
    if getattr(args, "identity", None):
        command += ["--identity", str(args.identity)]
    if getattr(args, "transport", "auto") != "auto":
        command += ["--transport", args.transport]
    if getattr(args, "upload_retries", 3) != 3:
        command += ["--upload-retries", str(args.upload_retries)]
    if getattr(args, "transfer_timeout", 3600) != 3600:
        command += ["--transfer-timeout", str(args.transfer_timeout)]
    if getattr(args, "remote_dir", "/tmp") != "/tmp":
        command += ["--remote-dir", args.remote_dir]
    if getattr(args, "remote_root", "/var/www/html") != "/var/www/html":
        command += ["--remote-root", args.remote_root]
    if getattr(args, "no_sudo", False):
        command.append("--no-sudo")
    return command


def recommended_remote_load_command(
    args: argparse.Namespace, project: Path,
) -> list[str]:
    """Return one local SSH command that starts the required post-deploy load."""
    day0 = args.remote_root.rstrip("/") + "/DAY0-Prepare"
    privilege = "" if args.no_sudo else "sudo -n "
    remote = (
        f"cd {shlex.quote(day0)} && "
        f"{privilege}python3 11-load.py {shlex.quote(project.name)}"
    )
    return command_base("ssh", args) + ["-t", args.host, remote]


def recommended_server_archive_commands(
    args: argparse.Namespace, remote_path: str,
) -> tuple[str, ...]:
    """Return the root-owned relay installer sequence for the target server."""
    import_root = "/root/http-ztp-import"
    installer = import_root + "/deploy-upload-archive.py"
    archive = import_root + "/" + Path(remote_path).name
    runtime = getattr(args, "runtime", "native")
    return (
        f"sudo install -d -o root -g root -m 0700 {import_root}",
        "sudo install -o root -g root -m 0500 "
        f"/tmp/deploy-upload-archive.py {installer}",
        f"sudo install -o root -g root -m 0600 {remote_path} {archive}",
        f"sudo python3 {installer} {archive} --runtime {runtime} --verify-only",
        f"sudo python3 {installer} {archive} --runtime {runtime}",
    )


def upload(
    args: argparse.Namespace, archive: Path, *, expected_sha256: str | None = None,
) -> str:
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    if not args.host or not SAFE_HOST.fullmatch(args.host):
        raise ValueError("--host must be a non-empty SSH destination without whitespace")
    for label, value in (("--remote-dir", args.remote_dir),
                         ("--remote-root", args.remote_root)):
        if not SAFE_REMOTE_DIR.fullmatch(value) or ".." in Path(value).parts:
            raise ValueError(f"{label} must be a safe absolute POSIX path: {value}")
    if not SAFE_ARCHIVE_NAME.fullmatch(archive.name):
        raise ValueError(
            "archive filename must contain only letters, digits, dot, underscore or dash"
        )
    if not 1 <= args.upload_retries <= 10:
        raise ValueError("--upload-retries must be between 1 and 10")
    if not 60 <= args.transfer_timeout <= 86400:
        raise ValueError("--transfer-timeout must be between 60 and 86400 seconds")

    remote_path = args.remote_dir.rstrip("/") + "/" + archive.name
    partial_path = remote_path + ".partial"
    ssh = command_base("ssh", args)
    observed_hash = package_core.sha256(archive)
    if expected_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("expected private archive SHA-256 is invalid")
        if observed_hash != expected_sha256:
            raise RuntimeError("private archive snapshot changed before upload")
        local_hash = expected_sha256
    else:
        local_hash = observed_hash

    # A previous run may have completed the atomic rename just before its SSH
    # connection disappeared.  Reuse only a byte-identical final artifact.
    if remote_sha256(ssh, args.host, remote_path) == local_hash:
        print(f"[SKIP] Remote archive already verified: {remote_path}")
    else:
        rsync_available = remote_rsync_available(args, ssh)
        use_rsync = args.transport == "rsync" or (
            args.transport == "auto" and rsync_available
        )
        if args.transport == "rsync" and not rsync_available:
            raise RuntimeError(
                "--transport rsync requested, but rsync is unavailable locally or remotely"
            )

        if use_rsync:
            print(
                f"[RUN] Resumable upload to {args.host}:{partial_path} "
                f"(attempts={args.upload_retries})"
            )
            rsh = shlex.join(command_base("ssh", args))

            def rsync_command(*, append: bool = True) -> list[str]:
                command = [
                    "rsync", "--partial", "--progress",
                    "--timeout=300", "-e", rsh,
                ]
                if append:
                    command.append("--append")
                command += [str(archive), f"{args.host}:{partial_path}"]
                return command

            transfer_with_retries(
                rsync_command,
                attempts=args.upload_retries,
                timeout=args.transfer_timeout,
                resumable=True,
            )
        else:
            print(
                "[WARN] rsync unavailable; falling back to non-resumable SCP "
                "with live progress"
            )

            def scp_command() -> list[str]:
                return command_base("scp", args) + [
                    str(archive), f"{args.host}:{partial_path}",
                ]

            transfer_with_retries(
                scp_command,
                attempts=args.upload_retries,
                timeout=args.transfer_timeout,
                resumable=False,
            )

        remote_hash = remote_sha256(ssh, args.host, partial_path)
        if remote_hash != local_hash and use_rsync:
            # --append trusts the existing prefix.  A stale/corrupt partial
            # therefore gets one clean retransmission before failing closed.
            print(
                "[WARN] resumed partial failed SHA-256; removing it and "
                "performing one complete retransmission",
                file=sys.stderr,
            )
            run(ssh + [args.host, "rm", "-f", "--", partial_path], timeout=60)
            transfer_with_retries(
                lambda: rsync_command(append=False),
                attempts=args.upload_retries,
                timeout=args.transfer_timeout,
                resumable=True,
            )
            remote_hash = remote_sha256(ssh, args.host, partial_path)
        if remote_hash != local_hash:
            raise RuntimeError(
                f"upload checksum mismatch: local={local_hash} "
                f"remote={remote_hash or '<unavailable>'}; partial retained at "
                f"{partial_path}"
            )
        if package_core.sha256(archive) != local_hash:
            raise RuntimeError("private archive snapshot changed during upload")
        run(
            ssh + [args.host, "mv", "-f", "--", partial_path, remote_path],
            timeout=60,
        )
        print(f"[OK] Remote SHA-256  : {remote_hash}")
        print(f"[OK] Remote published: {remote_path}")

    if package_core.sha256(archive) != local_hash:
        raise RuntimeError("private archive snapshot changed before deployment")
    if args.deploy:
        print(
            f"[LOCK] Deploying below {args.remote_root} while holding "
            f"{args.remote_root.rstrip('/')}/.deployment.lock"
        )
        deployment_output = run(
            remote_deployment_command(args, remote_path, local_hash)
        )
        args.docker_rebuild_required = (
            getattr(args, "runtime", "native") == "docker"
            or "HTTP_ZTP_DOCKER_REBUILD_REQUIRED" in deployment_output.splitlines()
        )
        print(f"[OK] Remote deployed : {args.remote_root}")
    else:
        print(f"[STATE] 已上传并校验，但尚未部署到 {args.remote_root}")
        print("[NEXT A] 本机可直连该服务器时，受控部署刚上传的同一归档：")
        print("       " + shlex.join(recommended_deploy_rerun_command(args)))
        print(
            "       该命令会重新核对本地归档、远端同名文件的 SHA-256 和全量测试证明，"
            "不会重新打包、不会重新传输，然后只执行持锁受控解包。"
        )
        print(
            "[NEXT B] 经可信中转部署时，再把 tools/deploy-upload-archive.py "
            "放到服务器 /tmp，然后在服务器执行："
        )
        for command in recommended_server_archive_commands(args, remote_path):
            print("       " + command)
        print(
            "       verify-only 不写 live root；最后一步成功后会打印唯一正确的 load/deploy 命令。"
        )
    return remote_path


def print_archive_manifest(archive: Path) -> None:
    """Print the exact verified payload used by a dry-run."""
    with package_core.tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
    files = sum(member.isfile() for member in members)
    links = sum(member.issym() for member in members)
    total = sum(member.size for member in members if member.isfile())
    print(
        f"[DRY-RUN] members={len(members)} files={files} links={links} "
        f"expanded={package_core.human_size(total)}"
    )
    for member in members:
        kind = "d" if member.isdir() else "l" if member.issym() else "f"
        suffix = f" -> {member.linkname}" if member.issym() else ""
        print(f"  [{kind}] {member.name}{suffix}")


def main(argv: list[str] | None = None) -> int:
    preview_dir = None
    try:
        args = parse_args(argv)
        project = package_core.resolve_project(args.project)
        if getattr(args, "relay_bundle", None) is not None:
            run_predeploy_test_gate()
            build_relay_bundle(args, project)
            print("[NEXT] Copy the complete directory to the target server, then run:")
            print("       sha256sum --check SHA256SUMS")
            print(
                f"       sudo python3 deploy-upload-archive.py "
                f"{shlex.quote(project.name + '-upload.tar.gz')} "
                f"--runtime {args.runtime} --verify-only"
            )
            print(
                f"       sudo python3 deploy-upload-archive.py "
                f"{shlex.quote(project.name + '-upload.tar.gz')} "
                f"--runtime {args.runtime}"
            )
            return 0
        if args.deploy_uploaded is not None:
            args.deploy = True
            run_predeploy_test_gate()
            with frozen_archive_for_upload(args.deploy_uploaded) as frozen:
                frozen_archive, frozen_sha256 = frozen
                verify_predeploy_test_approval()
                validate_uploaded_archive_for_deploy(frozen_archive, project)
                args.deployment_guard_source = deployment_guard_source_from_archive(
                    frozen_archive,
                )
                args.deployment_source_manifest_sha256 = (
                    deployment_source_manifest_sha256_from_archive(frozen_archive)
                )
                upload(args, frozen_archive, expected_sha256=frozen_sha256)
            if getattr(args, "docker_rebuild_required", False):
                print(
                    "[NEXT] 受管容器已停止且必须重建；不要运行宿主 systemd load。"
                )
            else:
                print("[NEXT] 归档已受控部署；现在从本机启动管理服务器 load：")
                print("       " + shlex.join(
                    recommended_remote_load_command(args, project)
                ))
            return 0
        resolve_apps_policy(args)
        if not args.dry_run:
            run_predeploy_test_gate()
        if args.output is None:
            if args.dry_run:
                preview_dir = tempfile.TemporaryDirectory(prefix="http-upload-preview-")
                args.output = Path(preview_dir.name) / f"{project.name}-preview-upload.tar.gz"
            else:
                args.output = default_output(project)
        archive = package_core.create_package(
            args, day0_all=False,
            artifact_kind="preview" if args.dry_run else "upload",
        )
        if args.dry_run:
            print_archive_manifest(archive)
            print("[DRY-RUN] SSH/upload skipped")
            return 0
        with frozen_archive_for_upload(archive) as frozen:
            frozen_archive, frozen_sha256 = frozen
            verify_predeploy_test_approval()
            args.deployment_guard_source = deployment_guard_source_from_archive(
                frozen_archive,
            )
            args.deployment_source_manifest_sha256 = (
                deployment_source_manifest_sha256_from_archive(frozen_archive)
            )
            upload(args, frozen_archive, expected_sha256=frozen_sha256)
        if args.deploy:
            if getattr(args, "docker_rebuild_required", False):
                print(
                    "[NEXT] 受管容器已停止且必须重建；不要运行宿主 systemd load："
                )
                root = args.remote_root.rstrip("/") or "/"
                remote = (
                    f"cd {shlex.quote(root)} && "
                    + ("" if args.no_sudo else "sudo -n ")
                    + "./infra/docker/deploy.sh deploy"
                )
                print(
                    "       " + shlex.join(
                        command_base("ssh", args) + ["-t", args.host, remote]
                    )
                )
            else:
                print("[NEXT] 归档已部署；现在从本机启动管理服务器 load：")
                print("       " + shlex.join(recommended_remote_load_command(args, project)))
        return 0
    except (OSError, ValueError, RuntimeError, package_core.tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    finally:
        if preview_dir is not None:
            preview_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
