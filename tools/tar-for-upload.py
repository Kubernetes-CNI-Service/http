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
from datetime import datetime
import gzip
from pathlib import Path
import re
import select
import shlex
import shutil
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
     setup/load 当前选择的 P2P XLSX、项目公钥和镜像文件。P2P 在临时副本中删除
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
  5. 默认到此停止，明确显示“已上传、未部署”，并打印一条可在本地重新运行的简短
     --deploy 命令；不会输出难以审核的超长远端 shell，也不会覆盖远端代码树。
  6. 所有非 dry-run 上传都会先在本地运行 test_cases/run_related_tests.py；
     测试通过并更新批准哈希后才允许打包或创建 SSH 连接。runner 缺失、manifest 非法或
     任一全量测试失败都会终止，远端不会被触碰。归档生成后、首次 SSH 前还会执行
     --check，拒绝打包期间的源码、测试或影响矩阵漂移。dry-run/list-only 不运行此门禁。
  7. 门禁通过后，--deploy 才在 --remote-root 上独占与 11-load.py 共用的
     .deployment.lock；锁内先复制到 /tmp 的私有目录并再次校验 SHA-256，
     然后创建持久同步门禁并解压。成功清除门禁后才释放锁；解包失败时门禁保留，
     防止 load 消费半套代码。SSH 用户必须具备无密码 sudo；root SSH 登录请同时使用
     --no-sudo。仅本地打包、dry-run 或不带 --deploy 的上传不会取得远端锁。
     管理服务器部署不使用 import-from-download.py；
     校验归档后直接解压即可。部署成功后脚本会打印一条本地 SSH 命令，用 TTY 在
     管理服务器启动本项目的 11-load.py。

常用示例：
  # 只在本地构建、验证并列出归档内容；不连接 SSH
  python3 tools/tar-for-upload.py \\
    2099-example-site --dry-run

  # 仅打包、上传和校验；推荐先使用此模式
  python3 tools/tar-for-upload.py \\
    2099-example-site \\
    --host ubuntu@ztp-admin.example \\
    --port 21018

  # 上传并自动部署（要求 ubuntu 可以 sudo -n）
  python3 tools/tar-for-upload.py \\
    2099-example-site \\
    --host ubuntu@ztp-admin.example \\
    --port 21018 --deploy

  # 使用指定私钥，并把共享系统镜像加入部署包
  python3 tools/tar-for-upload.py \\
    -p 2099-example-site \\
    --host ubuntu@ztp-admin.example --port 21018 \\
    --identity ~/.ssh/id_ed25519 --include-images

  # 目标管理服务器没有 Internet：明确归档已准备好的离线 APT 仓库
  python3 tools/tar-for-upload.py \
    -p 2099-example-site --host ubuntu@ztp-admin.example \
    --include-apps --target-os ubuntu-22.04 --target-arch amd64

  # mgmt 是 22.04/amd64，同时还要服务离线的 24.04/arm64 client
  python3 tools/tar-for-upload.py \
    -p 2099-example-site --host ubuntu@ztp-admin.example \
    --include-apps --target-os ubuntu-22.04 --target-arch amd64 \
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
    parser.add_argument("--host",
                        help="SSH destination, for example ubuntu@worker.example")
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
    parser.add_argument("--deploy", action="store_true",
                        help="after verification, remotely extract with sudo -n")
    parser.add_argument("--no-sudo", action="store_true",
                        help="with --deploy, extract directly (for a root SSH login)")
    parser.add_argument(
        "-o", "--output", type=Path,
        help=(
            "local deployment archive (default: DAY0-Prepare/dumps/"
            "<project>-<timestamp>-upload.tar.gz)"
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
    args = parser.parse_args(argv)
    if args.project_option and args.project_path:
        parser.error("provide the project either positionally or with -p/--project, not both")
    args.project = args.project_option or args.project_path
    if not args.project:
        parser.error("provide a project directory, or use -p/--project")
    if not args.dry_run and not args.host:
        parser.error("--host is required unless --dry-run/--list-only is used")
    del args.project_option
    del args.project_path
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
    """Run and approve the full local suite before building a formal archive."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式上传/部署测试门禁不存在或不是普通文件：{runner}")
    command = [sys.executable, "-B", str(runner), "--all"]
    print("[TEST] 正式上传/部署前运行全量测试：" + shlex.join(command))
    completed = subprocess.run(
        command, cwd=ROOT, shell=False, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"正式上传/部署测试门禁失败（exit={completed.returncode}）；"
            "尚未打包，远端未连接、未修改"
        )
    print("[OK] 正式上传/部署全量测试通过，批准哈希已更新")


def verify_predeploy_test_approval() -> None:
    """Reject source/test drift after packaging and before the first SSH call."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式上传/部署测试门禁不存在或不是普通文件：{runner}")
    command = [sys.executable, "-B", str(runner), "--check"]
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
    """Build the locked, fail-closed extraction command run on the server."""
    root = args.remote_root.rstrip("/") or "/"
    lock_path = root.rstrip("/") + "/.deployment.lock"
    marker_path = root.rstrip("/") + "/.sync-code-in-progress"
    install_marker = shlex.join([
        "install", "-m", "0644", "/dev/null", marker_path,
    ])
    marker_guard = (
        f"if [ -L {shlex.quote(marker_path)} ] || "
        f"{{ [ -e {shlex.quote(marker_path)} ] && "
        f"{{ [ ! -f {shlex.quote(marker_path)} ] || "
        f"[ \"$(stat -Lc %h -- {shlex.quote(marker_path)})\" != 1 ]; }}; }}; "
        "then echo 'unsafe sync marker' >&2; exit 74; fi"
    )
    create_staging = "staging=$(mktemp -d /tmp/http-deployment.XXXXXX)"
    cleanup_staging = "trap 'rm -rf -- \"$staging\"' EXIT HUP INT TERM"
    copy_to_staging = (
        f"install -m 0600 -- {shlex.quote(remote_path)} "
        '"$staging/payload.tar.gz"'
    )
    extract = (
        "tar --no-same-owner --no-same-permissions -xzf "
        f'"$staging/payload.tar.gz" -C {shlex.quote(root)}'
    )
    clear_marker = shlex.join(["rm", "-f", "--", marker_path])
    clear_marker_guard = (
        f"[ ! -L {shlex.quote(marker_path)} ] && "
        f"[ -f {shlex.quote(marker_path)} ] && "
        f"[ \"$(stat -Lc %h -- {shlex.quote(marker_path)})\" = 1 ]"
    )
    verification = ""
    if expected_sha256 is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise ValueError("expected SHA-256 must contain exactly 64 hex digits")
        checksum_input = (
            "printf '%s  %s\\n' "
            f"{shlex.quote(expected_sha256.casefold())} "
            '"$staging/payload.tar.gz"'
        )
        verification = f"{checksum_input} | sha256sum -c --status -; "
    # set -e intentionally leaves the marker behind after an interrupted or
    # failed extraction.  11-load.py then fails closed until a complete deploy
    # or sync reaches the final marker removal.
    script = (
        f"set -eu; {create_staging}; {cleanup_staging}; {copy_to_staging}; "
        f"{verification}{marker_guard}; {install_marker}; {extract}; "
        f"{clear_marker_guard}; {clear_marker}"
    )
    payload = package_core.remote_locked_shell_argv(
        lock_path, script, use_sudo=not args.no_sudo,
    )
    return shlex.join(payload)


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
    """Build a short, auditable local command for a fresh tested deployment."""
    command = [
        "python3", "tools/tar-for-upload.py", str(getattr(args, "project", "<project>")),
        "--host", args.host, "--port", str(args.port), "--deploy",
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
    if getattr(args, "include_images", False):
        command.append("--include-images")
    command.append(
        "--include-apps" if getattr(args, "include_apps", False) else "--exclude-apps"
    )
    if getattr(args, "target_os", None):
        command += ["--target-os", args.target_os]
    if getattr(args, "target_arch", None):
        command += ["--target-arch", args.target_arch]
    for platform in getattr(args, "client_platform", []):
        command += ["--client-platform", platform]
    if getattr(args, "include_firmware", False):
        command.append("--include-firmware")
    if getattr(
        args, "max_file_size_mib", package_core.DEFAULT_MAX_FILE_MIB
    ) != package_core.DEFAULT_MAX_FILE_MIB:
        command += ["--max-file-size-mib", str(args.max_file_size_mib)]
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


def upload(args: argparse.Namespace, archive: Path) -> str:
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
    local_hash = package_core.sha256(archive)

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
        run(
            ssh + [args.host, "mv", "-f", "--", partial_path, remote_path],
            timeout=60,
        )
        print(f"[OK] Remote SHA-256  : {remote_hash}")
        print(f"[OK] Remote published: {remote_path}")

    if args.deploy:
        print(
            f"[LOCK] Deploying below {args.remote_root} while holding "
            f"{args.remote_root.rstrip('/')}/.deployment.lock"
        )
        run(remote_deployment_command(args, remote_path, local_hash))
        print(f"[OK] Remote deployed : {args.remote_root}")
    else:
        print(f"[STATE] 已上传并校验，但尚未部署到 {args.remote_root}")
        print("[NEXT] 审核后在本地工作区根目录运行以下简短命令：")
        print("       " + shlex.join(recommended_deploy_rerun_command(args)))
        print("       该命令会重新执行全量测试、打包、校验、上传并持锁部署。")
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
        resolve_apps_policy(args)
        if not args.dry_run:
            run_predeploy_test_gate()
        if args.output is None:
            if args.dry_run:
                preview_dir = tempfile.TemporaryDirectory(prefix="http-upload-preview-")
                args.output = Path(preview_dir.name) / f"{project.name}-preview-upload.tar.gz"
            else:
                args.output = default_output(project)
        archive = package_core.create_package(args, day0_all=False)
        if args.dry_run:
            print_archive_manifest(archive)
            print("[DRY-RUN] SSH/upload skipped")
            return 0
        verify_predeploy_test_approval()
        upload(args, archive)
        if args.deploy:
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
