#!/usr/bin/env python3
"""Incrementally sync local HTTP/ZTP code and one DAY0 project to a host.

The deployable code scope is maintained as directory lists and filename
patterns below.  Individual script filenames are intentionally not listed.
The selected project's deployment inputs are synchronized with rsync, while
all 99-output-* data, management-server public keys, and load-rendered ZTP
runtime entrypoints are protected.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import types

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import _package_common as project_contract
from project_contract import (
    is_readme_name,
    is_tools_deployable_file,
    path_disposition,
    rsync_excludes,
    transfer_exclude_reason,
)

ROOT = Path(__file__).resolve().parent.parent
DAY0 = ROOT / "DAY0-Prepare"
PREDEPLOY_TEST_RUNNER = ROOT / "test_cases" / "run_related_tests.py"

# Maintain synchronization scope here.  Add a directory instead of adding all
# of its individual code files to this script.
CODE_DIRECTORIES = (
    "infra",
    "ztp",
    "monitor",
    "ethernet",
    "infiniband",
    "nvlink",
    "tools",
)
DAY0_CODE_DIRECTORIES = (
    "template",
)
ROOT_CODE_PATTERNS = (
    "*.py", "*.md", "*.html", ".dockerignore",
    "requirements-container-top-level.lock",
)
DAY0_CODE_PATTERNS = ("*.py", "*.md")
OPTIMIZE_CODE_PATTERNS = ("*.py", "*.sh")

COMMON_EXCLUDES = rsync_excludes() + ("*.tar.gz", "*.lock")
WORKSPACE_EXCLUDES = tuple(
    pattern for pattern in COMMON_EXCLUDES if pattern != "*.lock"
)
CODE_RUNTIME_EXCLUDES = (
    "/status/",
    "/old/",
    "/optimize/",
    "/logs/",
    "/collected/",
    "/monitor.html",
    "cronjob.log",
    "generate-monitor.log",
    "/test/results/",
    "/.setup_manifest",
    "/config/cumulus/latest_yaml",
    "/config/nvos/latest_yaml",
    "/config/cumulus/template/99-output/",
    "/config/nvos/template/99-output-ib_nvl/",
    "/config/cumulus/template/P2P/lldp-analyze-tool",
    "/config/nvos/template/P2P/ib-tool-Jie",
    "/config/nvos/template/P2P/ibdiagnet-analyze-tool",
)
ZTP_RENDERED_RUNTIME_EXCLUDES = (
    # 11-load.py rewrites these files with the active project's service IPs,
    # public-key list, image version and upgrade policy.  The copies in the
    # source workspace are only safe defaults.  Replacing the rendered remote
    # files during an incremental code sync can remove the management-server
    # key while switches are provisioning.
    "/ztp-bootstrap_oob.sh",
    "/ztp-bootstrap_oobofoob.sh",
    "/ztp.json",
)
PROJECT_RUNTIME_EXCLUDES = (
    "/99-output-*/",
    "/99-backup-all/",
    "/old/",
    "/staging/",
)
PROJECT_PROTECTED_FILES = (
    "/01-global.yaml",
    ".management-pubkeys",
    "mgmt-server.pub",
)

SAFE_HOST = re.compile(r"^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+$")
SAFE_REMOTE_ROOT = re.compile(r"^/[A-Za-z0-9._/-]+$")
DEPLOYMENT_LOCK_READY = "DEPLOYMENT_LOCK_READY"
DEPLOYMENT_LOCK_TIMEOUT = 30
DEPLOYMENT_PREWRITE_TIMEOUT = 90
MAX_GLOBAL_SIZE = 4 * 1024 * 1024
PASSWORD_SECTIONS = ("eth", "ib", "nvl")
PASSWORD_UPDATE_RELATIVE = "tools/password-update.py"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


HELP_EPILOG = """
操作步骤：
  1. 首次部署仍使用 tools/tar-for-upload.py；tools/sync-code.py 适合之后反复修改代码、模板、
     CSV、DOT 或其他项目部署文件时快速增量同步。
  2. 脚本同步 CODE_DIRECTORIES 中的公共代码目录、DAY0-Prepare 下的公共
     Python/非 README Markdown 文件及 template，再同步指定项目的部署文件；所有 README、test/tests/test_cases
     目录、历史监控、
     备份和 ZTP 运行状态不会从本地反向写回管理服务器。
     当前本机 setup 创建的动态链接也不传输，由远端 setup 维护自己的链接目标。
  3. rsync 只发送有差异的内容，默认不会删除远端多余文件。
  4. 项目中的 mgmt-server.pub 和 .management-pubkeys 不同步，防止本地空
     占位文件覆盖管理服务器 load 已注入的公钥。首次同步到全新服务器时，
     如果远端两者都不存在，脚本会安全创建空 mgmt-server.pub 供 load 注入。
  5. ztp-bootstrap_oob.sh、ztp-bootstrap_oobofoob.sh 和 ztp.json 是 load
     根据活动项目渲染的运行时文件，增量同步默认保护远端版本，避免覆盖 service IP、
     公钥列表、目标版本和升级策略。确需同步这些文件本身的代码时，显式增加
     --include-ztp-runtime；它仍是 source write，必须按下面的 runtime 分支重新发布。
  6. 先使用 --dry-run 查看逐文件变化；确认后删除 --dry-run 正式同步。
     正式同步会在任何 SSH/rsync 连接前验证本机正式 load 记录的精确 full-suite attestation。
     当前源码、测试、manifest 与 Python/平台身份完全匹配时直接复用；此脚本绝不运行全量
     测试。证明缺失或过期时会要求先重跑本机正式 load，并在任何远端连接前终止；dry-run
     不运行此门禁，也不存在无条件跳过正式证明检查的参数。
  7. 01-global.yaml 走独立合并，不进入项目 rsync：除 eth/ib/nvl 当前密码哈希外，
     本机文件是唯一权威；管理服务器上的密码哈希会逐项校验并保留。若远端只修改了
     密码，同步为真正零写入；若远端还修改了 YAML/CSV 等普通输入，则以本机内容覆盖，
     仍保留远端密码。远端密码字段缺失、格式非法、alias 共享或写入前发生变化都会
     在首个写入前 fail closed。旧 .sync-code-global.sha256 不再参与判断。
  8. 正式同步只更新磁盘文件，不会热加载已运行的 worker，也不会直接更新
     受保护的 monitor.html。等脚本清除 .sync-code-in-progress 并打印 [OK]
     后必须按显式 runtime 进入且只进入一个后端：
     Native/systemd：重新执行 DAY0-Prepare/11-load.py。
     Docker/Supervisor：source write 后必须执行 infra/docker/deploy.sh deploy；若已有与
     当前 live 来源身份链匹配且经验证的镜像，可重新执行 deploy-preloaded <IMAGE_ID>。
     load 仅用于没有 source write 且已有运行中的 inactive 控制容器。
     tools/sync-code.py 本身不会自动执行上述生命周期事务。

常用示例：
  # Native/systemd 先预览、再正式同步
  python3 tools/sync-code.py 2099-example-site \
    --host ubuntu@ztp-admin.example --port 21018 --runtime native --dry-run
  python3 tools/sync-code.py 2099-example-site \
    --host ubuntu@ztp-admin.example --port 21018 --runtime native

  # Docker/Supervisor 先预览、再正式同步
  python3 tools/sync-code.py 2099-example-site \
    --host ubuntu@ztp-admin.example --port 21018 --runtime docker --dry-run
  python3 tools/sync-code.py 2099-example-site \
    --host ubuntu@ztp-admin.example --port 21018 --runtime docker

  # 使用指定 SSH 私钥
  python3 tools/sync-code.py -p 2099-example-site \
    --host ubuntu@ztp-admin.example --identity ~/.ssh/id_ed25519 --runtime native

  # root 登录或远端目录允许当前 SSH 用户直接写入时关闭默认 sudo
  python3 tools/sync-code.py -p 2099-example-site \
    --host root@ztp-admin.example --no-sudo --runtime docker

兼容说明：
  项目既可以直接作为第一个位置参数，也可以用 ``-p/--project`` 指定。
  旧的 ``sync-code.py PROJECT HOST`` 双位置参数写法暂时继续支持。

范围说明：
  * image/apps/firmware 等大型共享制品不在快速同步范围；仍通过
    tools/tar-for-upload.py 的 include 参数部署。
  * 本命令不使用 --delete，因此不会清理管理服务器上的 ZTP 状态和历史数据。
"""


@dataclass(frozen=True)
class SyncJob:
    label: str
    sources: tuple[Path, ...]
    remote_dir: str
    excludes: tuple[str, ...] = ()


@dataclass
class RemoteDeploymentLock:
    """Long-lived SSH process holding the server's deployment flock."""

    process: subprocess.Popen
    path: str
    docker_managed: bool | None = None
    prewrite_ready: bool = False
    source_committed: bool = False


@dataclass(frozen=True)
class GlobalSyncPlan:
    """Candidate built from local inputs and validated remote password hashes."""

    local_sha256: str
    remote_sha256: str | None
    candidate_sha256: str
    action: str
    candidate_bytes: bytes = field(repr=False)
    preserved_password_sections: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return self.remote_sha256 != self.candidate_sha256


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-p", "--project", dest="project_option", metavar="PROJECT",
        help="DAY0-Prepare 下的基础项目名或绝对路径",
    )
    parser.add_argument(
        "--host", dest="host_option", metavar="HOST",
        help="管理主机，例如 ubuntu@worker.example",
    )
    parser.add_argument(
        "legacy_project", nargs="?", metavar="PROJECT",
        help="项目目录（可替代 -p/--project）",
    )
    parser.add_argument(
        "legacy_host", nargs="?", help=argparse.SUPPRESS,
    )
    parser.add_argument("--port", type=int, default=22, help="SSH 端口（默认 22）")
    parser.add_argument("--identity", type=Path, help="SSH 私钥路径")
    parser.add_argument(
        "--remote-root", default="/var/www/html",
        help="管理服务器 HTTP 根目录（默认 /var/www/html）",
    )
    parser.add_argument(
        "--runtime", choices=("native", "docker"), default="native",
        help=(
            "管理服务器运行后端（默认 native；Docker 部署必须显式选择 docker）"
        ),
    )
    privilege = parser.add_mutually_exclusive_group()
    privilege.add_argument(
        "--sudo", dest="sudo", action="store_true",
        help="远端使用 sudo -n（默认；保留该参数用于命令兼容）",
    )
    privilege.add_argument(
        "--no-sudo", dest="sudo", action="store_false",
        help="远端目录由 SSH 用户直接写入，不使用 sudo（适用于 root 登录等场景）",
    )
    parser.set_defaults(sudo=True)
    parser.add_argument(
        "-n", "--dry-run", action="store_true",
        help="通过 rsync --dry-run 预览变化，不写入远端",
    )
    parser.add_argument(
        "--include-ztp-runtime", action="store_true",
        help=(
            "同时覆盖 load 已渲染的 bootstrap/ztp.json（危险 source write；Native 后续执行 "
            "11-load.py，Docker 后续执行 deploy 或经身份链验证的 deploy-preloaded，不能 load）"
        ),
    )
    args = parser.parse_args(argv)
    if args.project_option:
        if args.legacy_project or args.legacy_host:
            parser.error("使用 -p/--project 时不要再提供位置参数")
        if not args.host_option:
            parser.error("使用 -p/--project 时必须同时提供 --host")
        args.project = args.project_option
        args.host = args.host_option
    else:
        if not args.legacy_project:
            parser.error("必须提供项目目录，或使用 -p/--project")
        args.project = args.legacy_project
        if args.host_option:
            if args.legacy_host:
                parser.error("使用 --host 时不要再提供第二个 host 位置参数")
            args.host = args.host_option
        else:
            if not args.legacy_host:
                parser.error("必须提供 --host")
            args.host = args.legacy_host
    del args.project_option
    del args.host_option
    del args.legacy_project
    del args.legacy_host
    if args.runtime == "docker" and args.remote_root != "/var/www/html":
        parser.error("--runtime docker requires --remote-root /var/www/html")
    return args


def resolve_project(value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        direct = (ROOT / candidate).resolve()
        candidate = direct if direct.is_dir() else (DAY0 / candidate).resolve()
    else:
        candidate = candidate.resolve()
    try:
        candidate.relative_to(DAY0.resolve())
    except ValueError as exc:
        raise ValueError(f"项目必须位于 {DAY0} 下：{candidate}") from exc
    if not candidate.is_dir() or not (candidate / "02-devices_config.csv").is_file():
        raise ValueError(f"项目不存在或缺少 02-devices_config.csv：{candidate}")
    return candidate


def validate_args(args: argparse.Namespace) -> None:
    if not 1 <= args.port <= 65535:
        raise ValueError("--port 必须在 1..65535 之间")
    if not SAFE_HOST.fullmatch(args.host):
        raise ValueError("host 只能是 hostname 或 user@hostname，不能包含空格或 shell 字符")
    root = PurePosixPath(args.remote_root)
    if (not SAFE_REMOTE_ROOT.fullmatch(args.remote_root)
            or not root.is_absolute() or ".." in root.parts):
        raise ValueError(f"--remote-root 必须是安全的绝对 POSIX 路径：{args.remote_root}")
    if args.identity:
        args.identity = args.identity.expanduser().resolve()
        if not args.identity.is_file():
            raise ValueError(f"SSH 私钥不存在：{args.identity}")
    if not shutil.which("rsync"):
        raise RuntimeError("本机未找到 rsync")
    if not shutil.which("ssh"):
        raise RuntimeError("本机未找到 ssh")


def run_predeploy_test_gate() -> None:
    """Require the exact full-suite attestation created by local load."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式同步测试门禁不存在或不是普通文件：{runner}")
    check = [
        sys.executable, "-B", str(runner), "--check", "--require-full",
    ]
    print("[TEST] 正式同步前复用精确全量测试证明：" + shlex.join(check))
    completed = subprocess.run(check, cwd=ROOT, shell=False, check=False)
    if completed.returncode == 0:
        print("[OK] 当前精确字节已有本机 load 生成的全量测试证明；不运行全量测试")
        return
    raise RuntimeError(
        f"正式同步缺少本机 load 生成的有效全量测试证明（exit={completed.returncode}）；"
        "请先在当前工作树成功执行本机正式 load；远端未连接、未修改"
    )


def verify_predeploy_test_approval() -> None:
    """Recheck approved bytes after freezing the exact deployment receipt."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式同步批准状态门禁不存在或不是普通文件：{runner}")
    command = [
        sys.executable, "-B", str(runner), "--check", "--require-full",
    ]
    print("[TEST] 冻结部署源码后的批准状态复核：" + shlex.join(command))
    completed = subprocess.run(
        command, cwd=ROOT, shell=False, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"冻结部署源码后的批准状态复核失败（exit={completed.returncode}）；"
            "远端未连接、未修改"
        )


def matching_files(root: Path, patterns: tuple[str, ...]) -> tuple[Path, ...]:
    if root == ROOT and "requirements-container-top-level.lock" in patterns:
        lock = ROOT / "requirements-container-top-level.lock"
        descriptor = None
        try:
            before = lock.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size == 0
                or before.st_size > 64 * 1024
            ):
                raise RuntimeError(
                    "requirements-container-top-level.lock 必须是非空、单链接、"
                    "不超过 64 KiB 的普通文件；远端未连接、未修改"
                )
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(lock, flags)
            held = os.fstat(descriptor)
            if (
                not stat.S_ISREG(held.st_mode)
                or held.st_nlink != 1
                or held.st_size != before.st_size
                or (held.st_dev, held.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise RuntimeError(
                    "requirements-container-top-level.lock 在选择时发生变化；"
                    "远端未连接、未修改"
                )
            chunks = []
            remaining = 64 * 1024 + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) != held.st_size:
                raise RuntimeError(
                    "requirements-container-top-level.lock 无法被完整冻结；"
                    "远端未连接、未修改"
                )
        except OSError as exc:
            raise RuntimeError(
                "requirements-container-top-level.lock 不安全或不可读取；"
                f"远端未连接、未修改：{exc}"
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def is_deployable(path: Path) -> bool:
        if not path.is_file() or is_readme_name(path.name):
            return False
        try:
            relative = path.relative_to(ROOT)
        except ValueError:
            # This helper is also useful for isolated external fixtures; the
            # repository-root contract cannot classify those paths.
            return True
        if path_disposition(PurePosixPath(relative.as_posix())) != "production":
            return False
        return transfer_exclude_reason(PurePosixPath(relative.as_posix())) is None

    return tuple(sorted({
        path for pattern in patterns for path in root.glob(pattern)
        if is_deployable(path)
    }))


def build_jobs(
    project: Path, remote_root: str, *, include_ztp_runtime: bool = False,
) -> list[SyncJob]:
    jobs: list[SyncJob] = []
    managed_links = package_setup_managed_links()

    def runtime_link_excludes(source_relative: str) -> tuple[str, ...]:
        """Translate workspace-relative runtime links for one rsync root."""
        prefix = source_relative.rstrip("/") + "/"
        return tuple(
            "/" + relative.removeprefix(prefix)
            for relative in sorted(managed_links)
            if relative.startswith(prefix)
        )

    for name in CODE_DIRECTORIES:
        source = ROOT / name
        if not source.is_dir():
            raise ValueError(f"同步目录不存在：{source}")
        if name == "tools":
            tool_files = tuple(sorted(
                path for path in source.iterdir()
                if path.is_file()
                and is_tools_deployable_file(PurePosixPath("tools", path.name))
            ))
            if tool_files:
                jobs.append(SyncJob(
                    "code:tools", tool_files, f"{remote_root}/tools",
                    COMMON_EXCLUDES,
                ))
            lldp_analyzer = source / "lldp-analyze-tool"
            if not lldp_analyzer.is_dir():
                raise ValueError(f"同步目录不存在：{lldp_analyzer}")
            jobs.append(SyncJob(
                "code:tools/lldp-analyze-tool", (lldp_analyzer,),
                f"{remote_root}/tools/lldp-analyze-tool",
                COMMON_EXCLUDES + (
                    "/node_modules/", "/99-output-p2p", "/99-output-monitor",
                ) + runtime_link_excludes("tools/lldp-analyze-tool"),
            ))
            continue
        rendered_runtime_excludes = (
            () if name != "ztp" or include_ztp_runtime
            else ZTP_RENDERED_RUNTIME_EXCLUDES
        )
        jobs.append(SyncJob(
            f"code:{name}", (source,), f"{remote_root}/{name}",
            COMMON_EXCLUDES + CODE_RUNTIME_EXCLUDES + rendered_runtime_excludes
            + runtime_link_excludes(name),
        ))
        if name == "ztp":
            optimize = source / "optimize"
            optimize_files = matching_files(optimize, OPTIMIZE_CODE_PATTERNS)
            if optimize_files:
                # ztp's main job excludes optimize runtime/sample data.  Sync
                # only the production source files through this separate job.
                jobs.append(SyncJob(
                    "code:ztp/optimize", optimize_files,
                    f"{remote_root}/ztp/optimize", COMMON_EXCLUDES,
                ))
    root_files = matching_files(ROOT, ROOT_CODE_PATTERNS)
    if root_files:
        jobs.append(SyncJob(
            "workspace files", root_files, remote_root, WORKSPACE_EXCLUDES,
        ))
    day0_root_files = matching_files(DAY0, DAY0_CODE_PATTERNS)
    if day0_root_files:
        jobs.append(SyncJob(
            "DAY0 files", day0_root_files, f"{remote_root}/DAY0-Prepare",
            COMMON_EXCLUDES,
        ))
    for name in DAY0_CODE_DIRECTORIES:
        source = DAY0 / name
        if not source.is_dir():
            raise ValueError(f"DAY0 同步目录不存在：{source}")
        jobs.append(SyncJob(
            f"DAY0:{name}", (source,), f"{remote_root}/DAY0-Prepare/{name}",
            COMMON_EXCLUDES + runtime_link_excludes(f"DAY0-Prepare/{name}"),
        ))
    protected = list(PROJECT_PROTECTED_FILES)
    marker = project / ".management-pubkeys"
    if marker.is_file():
        protected.extend(
            line.strip() for line in marker.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if line.strip().endswith(".pub") and Path(line.strip()).name == line.strip()
        )
    jobs.append(SyncJob(
        f"project:{project.name}", (project,),
        f"{remote_root}/DAY0-Prepare/{project.name}",
        COMMON_EXCLUDES + PROJECT_RUNTIME_EXCLUDES + tuple(sorted(set(protected)))
        + runtime_link_excludes(f"DAY0-Prepare/{project.name}"),
    ))
    return jobs


def deployment_source_manifest_job(
    manifest: Path, remote_root: str,
) -> SyncJob:
    return SyncJob(
        "code:deployment-source-manifest", (manifest,),
        f"{remote_root.rstrip('/')}/infra/docker", (),
    )


def package_setup_managed_links() -> set[str]:
    """Return setup-owned links from the shared workspace contract."""
    return project_contract.setup_managed_links()


def ssh_transport(args: argparse.Namespace) -> str:
    parts = ["ssh", "-p", str(args.port)]
    if args.identity:
        parts += ["-i", str(args.identity)]
    return shlex.join(parts)


def ssh_command_base(args: argparse.Namespace) -> list[str]:
    """Return the argv shared by non-rsync SSH control connections."""
    command = [
        "ssh", "-p", str(args.port),
        "-o", "ConnectTimeout=20",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "TCPKeepAlive=yes",
    ]
    if args.identity:
        command += ["-i", str(args.identity)]
    return command


def _checked_sha256(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    normalized = value.casefold()
    if not SHA256_PATTERN.fullmatch(normalized):
        raise RuntimeError(f"{label} 不是合法 SHA-256：{value!r}")
    return normalized


def _regular_file_bytes(path: Path, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"无法读取 {label}：{path}: {exc}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_GLOBAL_SIZE
    ):
        raise RuntimeError(
            f"{label} 必须是非空、最大 {MAX_GLOBAL_SIZE} bytes 的"
            f"单链接普通文件：{path}"
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"无法安全打开 {label}：{path}: {exc}") from exc
    chunks: list[bytes] = []
    remaining = before.st_size
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError(f"读取期间 {label} 发生变化：{path}")
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            if not block:
                raise RuntimeError(f"读取期间 {label} 被截断：{path}")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise RuntimeError(f"读取期间 {label} 增长：{path}")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    ):
        raise RuntimeError(f"读取期间 {label} 发生变化：{path}")
    return b"".join(chunks)


def load_frozen_password_contract(authority_manifest: Path):
    """Load approved password parsing code from the exact frozen source bytes."""
    manifest_bytes = project_contract._read_frozen_regular_bytes(
        authority_manifest, "deployment source manifest",
    )
    try:
        payload = json.loads(manifest_bytes.decode("ascii"))
        records = payload["files"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RuntimeError(f"部署源码清单无法绑定密码合同：{exc}") from exc
    matches = [
        record for record in records
        if isinstance(record, dict)
        and record.get("path") == PASSWORD_UPDATE_RELATIVE
    ]
    if len(matches) != 1 or matches[0].get("type") != "file":
        raise RuntimeError("部署源码清单未唯一绑定 password-update.py")
    source_path = ROOT / PASSWORD_UPDATE_RELATIVE
    source = project_contract._read_frozen_regular_bytes(
        source_path, "password update contract",
    )
    if hashlib.sha256(source).hexdigest() != matches[0].get("sha256"):
        raise RuntimeError("password-update.py 在部署源码清单生成后发生变化")
    module_name = "_http_ztp_frozen_password_contract"
    module = types.ModuleType(module_name)
    module.__file__ = str(source_path)
    module.__package__ = ""
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        exec(compile(source, str(source_path), "exec"), module.__dict__)
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    for name in (
        "PasswordUpdateError", "extract_password_hashes",
        "locate_password_targets", "rewrite_global_passwords",
    ):
        if not hasattr(module, name):
            raise RuntimeError(f"密码合同缺少必需 API: {name}")
    return module


def _masked_password_text(text: str, password_contract) -> str:
    """Mask exact credential scalar spans so ordinary input bytes can be compared."""
    targets = password_contract.locate_password_targets(
        text, sections=PASSWORD_SECTIONS,
    )
    masked = text
    for target in sorted(
        targets, key=lambda item: item.node.start_mark.index, reverse=True,
    ):
        masked = (
            masked[:target.node.start_mark.index]
            + '"<http-ztp-password>"'
            + masked[target.node.end_mark.index:]
        )
    return masked


def build_global_sync_plan(
    local_bytes: bytes,
    remote_bytes: bytes | None,
    *,
    password_contract,
) -> GlobalSyncPlan:
    """Merge one global file with local authority and remote password ownership."""
    try:
        local_text = local_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise password_contract.PasswordUpdateError(
            f"本机 01-global.yaml 必须是 UTF-8: {exc}"
        ) from exc
    local_hashes = password_contract.extract_password_hashes(
        local_text, sections=PASSWORD_SECTIONS,
    )
    local_sha256 = hashlib.sha256(local_bytes).hexdigest()
    if remote_bytes is None:
        return GlobalSyncPlan(
            local_sha256=local_sha256,
            remote_sha256=None,
            candidate_sha256=local_sha256,
            action="initialize-remote",
            candidate_bytes=local_bytes,
        )

    try:
        remote_text = remote_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise password_contract.PasswordUpdateError(
            f"管理服务器 01-global.yaml 必须是 UTF-8: {exc}"
        ) from exc
    remote_hashes = password_contract.extract_password_hashes(
        remote_text, sections=PASSWORD_SECTIONS,
    )
    remote_sha256 = hashlib.sha256(remote_bytes).hexdigest()

    if _masked_password_text(local_text, password_contract) == _masked_password_text(
        remote_text, password_contract,
    ):
        candidate_bytes = remote_bytes
        action = "identical-after-password-preservation"
    else:
        candidate_text = password_contract.rewrite_global_passwords(
            local_text, remote_hashes, sections=PASSWORD_SECTIONS,
        )
        candidate_bytes = candidate_text.encode("utf-8")
        action = "merge-local-preserve-remote-passwords"

    candidate_hashes = password_contract.extract_password_hashes(
        candidate_bytes.decode("utf-8"), sections=PASSWORD_SECTIONS,
    )
    if candidate_hashes != remote_hashes or set(local_hashes) != set(remote_hashes):
        raise password_contract.PasswordUpdateError(
            "01-global.yaml 合并后密码哈希内部校验失败"
        )
    candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
    return GlobalSyncPlan(
        local_sha256=local_sha256,
        remote_sha256=remote_sha256,
        candidate_sha256=candidate_sha256,
        action=action,
        candidate_bytes=candidate_bytes,
        preserved_password_sections=PASSWORD_SECTIONS,
    )


def remote_global_paths(
    project: Path, args: argparse.Namespace,
) -> PurePosixPath:
    project_dir = (
        PurePosixPath(args.remote_root.rstrip("/"))
        / "DAY0-Prepare" / project.name
    )
    return project_dir / "01-global.yaml"


_REMOTE_GLOBAL_PROBE = r"""
import base64, hashlib, json, os, stat, sys

global_path = sys.argv[1]
maximum_size = 4 * 1024 * 1024

def read_regular(path, label, allow_missing=False):
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size <= 0 or before.st_size > maximum_size):
        raise RuntimeError(label + " must be one bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise RuntimeError(label + " changed while opening")
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            if not block:
                raise RuntimeError(label + " changed while reading")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise RuntimeError(label + " grew while reading")
        after = os.fstat(descriptor)
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)):
            raise RuntimeError(label + " changed while reading")
    finally:
        os.close(descriptor)
    return b"".join(chunks)

project_dir = os.path.dirname(global_path)
try:
    project_meta = os.lstat(project_dir)
except FileNotFoundError:
    global_data = None
else:
    if not stat.S_ISDIR(project_meta.st_mode):
        raise RuntimeError("remote project must be one real directory")
    global_data = read_regular(global_path, "remote global", allow_missing=True)
print(json.dumps({
    "content_b64": (
        base64.b64encode(global_data).decode("ascii")
        if global_data is not None else None
    ),
    "sha256": (
        hashlib.sha256(global_data).hexdigest()
        if global_data is not None else None
    ),
}, sort_keys=True))
""".strip()


_REMOTE_GLOBAL_COMMIT = r"""
import hashlib, os, re, stat, sys

global_path, prior, expected = sys.argv[1:4]
maximum_size = 4 * 1024 * 1024
if prior != "-" and re.fullmatch(r"[0-9a-f]{64}", prior) is None:
    raise RuntimeError("invalid prior digest")
if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
    raise RuntimeError("invalid candidate digest")

def read_regular(path, label, allow_missing=False):
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size <= 0 or before.st_size > maximum_size):
        raise RuntimeError(label + " must be one bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise RuntimeError(label + " changed while opening")
        chunks, remaining = [], before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 65536))
            if not block:
                raise RuntimeError(label + " changed while reading")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise RuntimeError(label + " grew while reading")
    finally:
        os.close(descriptor)
    return b"".join(chunks)

candidate = sys.stdin.buffer.read(maximum_size + 1)
if not candidate or len(candidate) > maximum_size:
    raise RuntimeError("candidate global must be one bounded non-empty payload")
if hashlib.sha256(candidate).hexdigest() != expected:
    raise RuntimeError("candidate global digest mismatch")

project_dir = os.path.dirname(global_path)
project_meta = os.lstat(project_dir)
if not stat.S_ISDIR(project_meta.st_mode):
    raise RuntimeError("remote project is not one real directory")
current_data = read_regular(global_path, "remote global", allow_missing=True)
current_digest = hashlib.sha256(current_data).hexdigest() if current_data is not None else None
if current_digest != (None if prior == "-" else prior):
    raise RuntimeError("remote global changed after preflight")
current_meta = os.lstat(global_path) if current_data is not None else None

temporary = global_path + ".sync-code.tmp." + str(os.getpid())
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(temporary, flags, 0o600)
try:
    payload = candidate
    while payload:
        written = os.write(descriptor, payload)
        if written <= 0:
            raise RuntimeError("short write while committing remote global")
        payload = payload[written:]
    os.fchmod(descriptor, stat.S_IMODE(current_meta.st_mode) if current_meta else 0o644)
    if current_meta is not None and hasattr(os, "fchown"):
        os.fchown(descriptor, current_meta.st_uid, current_meta.st_gid)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
try:
    latest = read_regular(global_path, "remote global", allow_missing=True)
    latest_digest = hashlib.sha256(latest).hexdigest() if latest is not None else None
    if latest_digest != current_digest:
        raise RuntimeError("remote global changed immediately before commit")
    os.replace(temporary, global_path)
    directory = os.open(
        project_dir,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
print(expected)
""".strip()


def _remote_python_command(
    args: argparse.Namespace, code: str, *values: str,
) -> list[str]:
    remote = ([] if not args.sudo else ["sudo", "-n"]) + [
        "python3", "-c", code, *values,
    ]
    return ssh_command_base(args) + [args.host, shlex.join(remote)]


def remote_global_snapshot_command(
    project: Path, args: argparse.Namespace,
) -> list[str]:
    global_path = remote_global_paths(project, args)
    return _remote_python_command(
        args, _REMOTE_GLOBAL_PROBE, str(global_path),
    )


def remote_global_commit_command(
    project: Path,
    args: argparse.Namespace,
    prior_sha256: str | None,
    candidate_sha256: str,
) -> list[str]:
    global_path = remote_global_paths(project, args)
    return _remote_python_command(
        args, _REMOTE_GLOBAL_COMMIT, str(global_path),
        prior_sha256 or "-", candidate_sha256,
    )


def read_remote_global_snapshot(
    project: Path, args: argparse.Namespace,
) -> tuple[bytes | None, str | None]:
    completed = subprocess.run(
        remote_global_snapshot_command(project, args),
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "无法安全读取远端 global 同步状态："
            + (completed.stderr.strip() or f"exit={completed.returncode}")
        )
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("远端 global 同步状态不是合法 JSON") from exc
    if not isinstance(result, dict) or set(result) != {"content_b64", "sha256"}:
        raise RuntimeError("远端 global 同步状态字段不完整")
    remote_sha256 = _checked_sha256(result["sha256"], "远端 global")
    encoded = result["content_b64"]
    if encoded is None:
        if remote_sha256 is not None:
            raise RuntimeError("远端 global 缺失但返回了哈希")
        return None, None
    if not isinstance(encoded, str) or remote_sha256 is None:
        raise RuntimeError("远端 global 内容/哈希字段不一致")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError("远端 global 内容不是合法 base64") from exc
    if (
        not data or len(data) > MAX_GLOBAL_SIZE
        or hashlib.sha256(data).hexdigest() != remote_sha256
    ):
        raise RuntimeError("远端 global 内容与 SHA-256 不一致")
    return data, remote_sha256


def prepare_global_sync(
    project: Path, args: argparse.Namespace,
) -> GlobalSyncPlan:
    local_bytes = _regular_file_bytes(
        project / "01-global.yaml", "Mac 01-global.yaml",
    )
    remote_bytes, remote_sha256 = read_remote_global_snapshot(project, args)
    password_contract = getattr(args, "password_contract", None)
    if password_contract is None:
        raise RuntimeError("未冻结本次已批准的密码合同")
    plan = build_global_sync_plan(
        local_bytes, remote_bytes, password_contract=password_contract,
    )
    print(
        f"[GLOBAL] action={plan.action}; Mac={plan.local_sha256}; "
        f"VM={remote_sha256 or '<missing>'}; candidate={plan.candidate_sha256}; "
        f"preserved-passwords={','.join(plan.preserved_password_sections) or '<none>'}"
    )
    return plan


def commit_remote_global(
    project: Path, args: argparse.Namespace, plan: GlobalSyncPlan,
) -> None:
    if not plan.changed:
        return
    global_path = remote_global_paths(project, args)
    if args.dry_run:
        print(
            f"[DRY] 将以 CAS 原子写入合并后 global：{global_path}; "
            f"{plan.remote_sha256 or '<missing>'} -> {plan.candidate_sha256}"
        )
        return
    completed = subprocess.run(
        remote_global_commit_command(
            project, args, plan.remote_sha256, plan.candidate_sha256,
        ),
        input=plan.candidate_bytes,
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = completed.stdout.decode("ascii", errors="replace").strip()
    error = completed.stderr.decode("utf-8", errors="replace").strip()
    if completed.returncode != 0 or output != plan.candidate_sha256:
        raise RuntimeError(
            "远端 global CAS 原子提交失败；同步门禁将保留："
            + (error or f"exit={completed.returncode}")
        )
    print(f"[GLOBAL] 已原子提交合并内容：{plan.candidate_sha256}")


def remote_deployment_lock_command(args: argparse.Namespace) -> list[str]:
    """Build a persistent remote command sharing 11-load.py's flock inode."""
    lock_path = f"{args.remote_root.rstrip('/')}/.deployment.lock"
    remote = project_contract.remote_lock_holder_argv(
        lock_path, http_root=args.remote_root.rstrip("/") or "/",
        use_sudo=args.sudo, runtime=args.runtime,
        guard_source=getattr(args, "deployment_guard_source", None),
        source_manifest_sha256=getattr(
            args, "deployment_source_manifest_sha256", "",
        ),
    )
    return ssh_command_base(args) + [args.host, shlex.join(remote)]


def _finish_failed_lock_process(
    process: subprocess.Popen, *, timeout: int = 5,
) -> str:
    """Stop a lock handshake and return its bounded diagnostic stderr."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)
    return process.stderr.read().strip() if process.stderr else ""


def acquire_remote_deployment_lock(
    args: argparse.Namespace,
) -> RemoteDeploymentLock | None:
    """Hold the management server's exclusive deployment lock until released.

    rsync opens separate SSH connections, so a small long-lived SSH process
    owns the same advisory flock used by 11-load.py and manual operations.  The
    sync marker remains the crash-persistent fail-closed gate.
    """
    lock_path = f"{args.remote_root.rstrip('/')}/.deployment.lock"
    if args.dry_run:
        print(f"[DRY] 正式同步会独占远端部署锁：{lock_path}")
        return None
    command = remote_deployment_lock_command(args)
    print("[LOCK] 独占远端部署锁：" + lock_path)
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    if process.stdout is None:
        detail = _finish_failed_lock_process(process)
        raise RuntimeError(f"无法读取远端部署锁握手：{detail or lock_path}")
    ready, _, _ = select.select(
        [process.stdout], [], [], DEPLOYMENT_LOCK_TIMEOUT,
    )
    if not ready:
        detail = _finish_failed_lock_process(process)
        raise RuntimeError(
            "等待远端部署锁超时；请确认 SSH/sudo/flock 可用："
            + (detail or lock_path)
        )
    handshake = process.stdout.readline().strip()
    if handshake != DEPLOYMENT_LOCK_READY:
        detail = _finish_failed_lock_process(process)
        if process.returncode == 75:
            raise RuntimeError(
                "另一个 load、unload、人工操作或部署正在使用远端 deployment lock；"
                "请等待其完成后重试"
            )
        raise RuntimeError(
            "无法取得远端 deployment lock：" + (detail or lock_path)
        )
    return RemoteDeploymentLock(process=process, path=lock_path)


def prepare_remote_source_write(lock: RemoteDeploymentLock | None) -> bool:
    """Trigger Docker quiesce immediately before the first remote write."""
    if lock is None:
        return False
    if lock.prewrite_ready:
        return bool(lock.docker_managed)
    process = lock.process
    if process.poll() is not None or process.stdin is None or process.stdout is None:
        raise RuntimeError("远端 deployment lock 在 prewrite 前已经丢失")
    process.stdin.write("HTTP_ZTP_PREWRITE\n")
    process.stdin.flush()
    ready, _, _ = select.select(
        [process.stdout], [], [], DEPLOYMENT_PREWRITE_TIMEOUT,
    )
    if not ready:
        detail = _finish_failed_lock_process(process)
        raise RuntimeError(
            "等待远端 Docker prewrite 隔离超时：" + (detail or lock.path)
        )
    frame = process.stdout.readline().strip()
    fields = frame.split()
    if len(fields) != 2 or fields[1] != "HTTP_ZTP_PREWRITE_READY":
        detail = _finish_failed_lock_process(process)
        raise RuntimeError(
            "远端 Docker prewrite 隔离失败："
            + (detail or frame or lock.path)
        )
    if fields[0] not in {
        "HTTP_ZTP_DOCKER_REBUILD_REQUIRED", "HTTP_ZTP_NO_MANAGED_DOCKER",
    }:
        raise RuntimeError("远端 Docker prewrite 返回未知状态：" + fields[0])
    lock.docker_managed = fields[0] == "HTTP_ZTP_DOCKER_REBUILD_REQUIRED"
    lock.prewrite_ready = True
    return bool(lock.docker_managed)


def commit_remote_source_write(lock: RemoteDeploymentLock | None) -> None:
    """Ask the same holder to verify/prune/bind source before unlocking."""
    if lock is None:
        return
    if not lock.prewrite_ready:
        raise RuntimeError("远端 deployment lock 尚未完成 prewrite")
    if lock.source_committed:
        return
    process = lock.process
    if process.poll() is not None or process.stdin is None or process.stdout is None:
        raise RuntimeError("远端 deployment lock 在 source commit 前已经丢失")
    process.stdin.write("HTTP_ZTP_COMMIT\n")
    process.stdin.flush()
    ready, _, _ = select.select(
        [process.stdout], [], [], DEPLOYMENT_PREWRITE_TIMEOUT,
    )
    if not ready:
        detail = _finish_failed_lock_process(process)
        raise RuntimeError(
            "等待远端 source receipt 提交超时：" + (detail or lock.path)
        )
    acknowledgement = process.stdout.readline().strip()
    if acknowledgement != "HTTP_ZTP_COMMIT_READY":
        detail = _finish_failed_lock_process(process)
        raise RuntimeError(
            "远端 source receipt 提交失败："
            + (detail or acknowledgement or lock.path)
        )
    lock.source_committed = True


def assert_remote_deployment_lock(lock: RemoteDeploymentLock | None) -> None:
    """Fail closed if the lock-holder SSH connection disappeared."""
    if lock is None or lock.process.poll() is None:
        return
    detail = lock.process.stderr.read().strip() if lock.process.stderr else ""
    raise RuntimeError(
        "远端 deployment lock 在同步完成前丢失；同步门禁会保留，请重新执行完整 sync："
        + (detail or lock.path)
    )


def release_remote_deployment_lock(lock: RemoteDeploymentLock | None) -> None:
    """Close the holder's stdin, causing remote flock to exit and unlock."""
    if lock is None:
        return
    process = lock.process
    if process.stdin and not process.stdin.closed:
        process.stdin.close()
        # communicate() otherwise attempts to flush the already closed pipe.
        process.stdin = None
    try:
        _stdout, stderr = process.communicate(timeout=DEPLOYMENT_LOCK_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        raise RuntimeError(f"释放远端 deployment lock 超时：{lock.path}") from exc
    if process.returncode != 0:
        detail = (stderr or "").strip()
        raise RuntimeError(
            f"远端 deployment lock 连接异常退出（exit={process.returncode}）："
            + (detail or lock.path)
        )
    print(f"[UNLOCK] 已释放远端部署锁：{lock.path}")


def rsync_command(job: SyncJob, args: argparse.Namespace) -> list[str]:
    # macOS ships an old openrsync sender.  GNU ownership mapping options are
    # not part of that protocol boundary: putting --chown into --rsync-path is
    # rejected by Ubuntu rsync 3.2.x as a duplicate user-affecting mapping.
    # Preserve archive semantics explicitly for Docker except owner/group.
    # The root receiver owns newly written objects; the locked source-commit
    # guard then normalizes and verifies every exact manifest member, including
    # unchanged objects, before it publishes the new source receipt.
    transfer_flags = "-rlptDz" if args.runtime == "docker" else "-az"
    command = [
        "rsync", transfer_flags,
        "--itemize-changes", "--human-readable", "--stats",
        "-e", ssh_transport(args),
    ]
    if args.dry_run:
        command.append("--dry-run")
    if args.runtime == "docker":
        remote_rsync = "sudo -n /usr/bin/rsync" if args.sudo else "/usr/bin/rsync"
    else:
        remote_rsync = "sudo -n rsync" if args.sudo else "rsync"
    if args.sudo or args.runtime == "docker":
        command.append(f"--rsync-path={remote_rsync}")
    for pattern in job.excludes:
        command += ["--exclude", pattern]
    for source in job.sources:
        command.append(str(source) + ("/" if source.is_dir() else ""))
    command.append(f"{args.host}:{job.remote_dir.rstrip('/')}/")
    return command


def ensure_remote_directories(jobs: list[SyncJob], args: argparse.Namespace) -> None:
    if args.dry_run:
        return
    command = ssh_command_base(args) + [args.host]
    if args.sudo:
        command += ["sudo", "-n"]
    command += ["mkdir", "-p", "--"]
    command += sorted({job.remote_dir for job in jobs})
    print("[RUN] " + shlex.join(command))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise RuntimeError("无法在管理主机创建同步目标目录")


def remote_sync_marker_command(
    args: argparse.Namespace, *, present: bool,
) -> list[str]:
    """Build one safely quoted SSH remote command for the sync marker.

    OpenSSH joins every local argv item after the host with spaces and asks the
    remote login shell to parse the result.  Therefore the complete ``sh -c``
    invocation must be serialized as one quoted argument; passing the script
    as several local argv items lets the login shell expand ``$1`` too early.
    """
    marker = f"{args.remote_root.rstrip('/')}/.sync-code-in-progress"
    if present:
        marker_script = (
            "set -eu; marker=$1; "
            "if [ -L \"$marker\" ] || { [ -e \"$marker\" ] && "
            "{ [ ! -f \"$marker\" ] || "
            "[ \"$(stat -Lc %h -- \"$marker\")\" != 1 ]; }; }; then "
            "echo 'unsafe sync marker' >&2; exit 74; fi; "
            "install -m 0644 /dev/null \"$marker\"; "
            "[ ! -L \"$marker\" ] && [ -f \"$marker\" ] && "
            "[ \"$(stat -Lc %h -- \"$marker\")\" = 1 ]"
        )
    else:
        marker_script = (
            "set -eu; marker=$1; "
            "if [ ! -e \"$marker\" ] && [ ! -L \"$marker\" ]; then exit 0; fi; "
            "if [ -L \"$marker\" ] || [ ! -f \"$marker\" ] || "
            "[ \"$(stat -Lc %h -- \"$marker\")\" != 1 ]; then "
            "echo 'unsafe sync marker' >&2; exit 74; fi; "
            "rm -f -- \"$marker\""
        )
    remote = ([] if not args.sudo else ["sudo", "-n"]) + [
        "sh", "-c", marker_script, "sync-marker", marker,
    ]
    return ssh_command_base(args) + [args.host, shlex.join(remote)]


def set_remote_sync_marker(args: argparse.Namespace, *, present: bool) -> None:
    """Publish a cross-process gate so load cannot consume a partial sync."""
    marker = f"{args.remote_root.rstrip('/')}/.sync-code-in-progress"
    if args.dry_run:
        print(f"[DRY] 将在同步期间维护远端门禁：{marker}")
        return
    command = remote_sync_marker_command(args, present=present)
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        action = "创建" if present else "清除"
        raise RuntimeError(f"无法{action}远端同步门禁：{marker}")


def remote_management_placeholder_command(
    project: Path, args: argparse.Namespace,
) -> list[str]:
    """Build a non-overwriting remote placeholder initialization command."""
    project_dir = (
        PurePosixPath(args.remote_root.rstrip("/"))
        / "DAY0-Prepare" / project.name
    )
    marker = project_dir / ".management-pubkeys"
    placeholder = project_dir / "mgmt-server.pub"
    marker_q = shlex.quote(str(marker))
    placeholder_q = shlex.quote(str(placeholder))
    script = (
        f"if test -e {marker_q}; then "
        "echo '[KEY] Retained remote management-key marker'; "
        f"elif test -e {placeholder_q}; then "
        "echo '[KEY] Retained remote mgmt-server.pub'; "
        "else "
        f"install -m 0644 /dev/null {placeholder_q} && "
        "echo '[KEY] Created empty remote mgmt-server.pub for first load'; "
        "fi"
    )
    remote = ("sudo -n " if args.sudo else "") + "sh -c " + shlex.quote(script)
    command = ssh_command_base(args) + [args.host, remote]
    return command


def ensure_remote_management_placeholder(
    project: Path, args: argparse.Namespace,
) -> None:
    """Initialize only a missing first-deploy placeholder; never overwrite keys."""
    if args.dry_run:
        print(
            "[DRY] 远端无管理 key 标记/占位文件时，将创建空 mgmt-server.pub；"
            "已有文件不会覆盖"
        )
        return
    command = remote_management_placeholder_command(project, args)
    print("\n[RUN] " + shlex.join(command))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise RuntimeError("无法初始化远端管理服务器公钥占位文件")


def remote_management_placeholder_needed(
    project: Path, args: argparse.Namespace,
) -> bool:
    """Read-only check used to avoid disrupting a true no-op Docker sync."""
    project_dir = (
        PurePosixPath(args.remote_root.rstrip("/"))
        / "DAY0-Prepare" / project.name
    )
    marker = project_dir / ".management-pubkeys"
    placeholder = project_dir / "mgmt-server.pub"
    remote = ("sudo -n " if args.sudo else "") + "test -e " + shlex.quote(
        str(marker)
    ) + " -o -e " + shlex.quote(str(placeholder))
    completed = subprocess.run(
        ssh_command_base(args) + [args.host, remote], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if completed.returncode == 0:
        return False
    if completed.returncode == 1:
        return True
    raise RuntimeError(
        "无法预检远端管理公钥占位状态："
        + (completed.stderr.strip() or f"exit={completed.returncode}")
    )


def run_job(job: SyncJob, args: argparse.Namespace) -> None:
    command = rsync_command(job, args)
    print(f"\n[SYNC] {job.label} → {args.host}:{job.remote_dir}/")
    print("[RUN]  " + shlex.join(command))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"rsync 失败（exit={completed.returncode}）：{job.label}")


def sync_jobs_have_changes(
    jobs: list[SyncJob], args: argparse.Namespace,
) -> tuple[SyncJob, ...]:
    """Preview the exact rsync jobs while the remote deployment lock is held."""
    preview_args = argparse.Namespace(**vars(args))
    preview_args.dry_run = True
    changed: list[SyncJob] = []
    for job in jobs:
        command = rsync_command(job, preview_args)
        command.insert(1, "--out-format=%i|%n%L")
        completed = subprocess.run(
            command, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"rsync 写入预检失败（exit={completed.returncode}）：{job.label}："
                + completed.stderr.strip()
            )
        if any("|" in line for line in completed.stdout.splitlines()):
            changed.append(job)
    return tuple(changed)


def main(argv: list[str] | None = None) -> int:
    manifest_stage = None
    try:
        args = parse_args(argv)
        validate_args(args)
        project = resolve_project(args.project)
        jobs = build_jobs(
            project, args.remote_root.rstrip("/"),
            include_ztp_runtime=args.include_ztp_runtime,
        )
        print(f"[INFO] 项目：{project}")
        print(f"[INFO] 主机：{args.host}:{args.port}")
        print(f"[INFO] 模式：{'dry-run 预览' if args.dry_run else '正式同步'}")
        print(f"[INFO] 同步任务：{len(jobs) + 1} 个；不会删除远端额外文件")
        if args.include_ztp_runtime:
            if args.runtime == "docker":
                print(
                    "[WARN] 将覆盖远端 load 已渲染的 bootstrap/ztp.json；"
                    "这是 Docker source write，成功后必须 deploy（或验证身份链后 "
                    "deploy-preloaded），不得 load"
                )
            else:
                print(
                    "[WARN] 将覆盖远端 load 已渲染的 bootstrap/ztp.json；"
                    "Native 同步成功后、交换机再次 ZTP 前必须重新执行 11-load.py"
                )
        else:
            print(
                "[SAFE] 保留远端 load 已渲染的 bootstrap/ztp.json，"
                "不会覆盖 service IP、公钥列表、版本或升级策略"
            )
        if not args.dry_run:
            run_predeploy_test_gate()
        # Freeze the exact post-gate source authority.  In formal mode these
        # bytes are generated only after a current full-suite attestation check,
        # so an older helper
        # can never be executed remotely under approval for newer bytes.
        manifest_stage = tempfile.TemporaryDirectory(
            prefix="http-deployment-source-manifest-",
        )
        manifest_path = Path(manifest_stage.name) / (
            project_contract.DEPLOYMENT_SOURCE_MANIFEST_RELATIVE.name
        )
        project_contract.write_deployment_source_manifest(manifest_path)
        args.deployment_source_manifest_sha256 = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        args.deployment_guard_source = (
            project_contract.deployment_prewrite_guard_source(manifest_path)
        )
        args.password_contract = load_frozen_password_contract(manifest_path)
        if not args.dry_run:
            verify_predeploy_test_approval()
        # Publish the authority receipt last.  A partial rsync therefore
        # cannot authorize a mixed old/new source tree at image build time.
        jobs.append(deployment_source_manifest_job(
            manifest_path, args.remote_root.rstrip("/"),
        ))
        remote_lock = acquire_remote_deployment_lock(args)
        docker_rebuild_required = False
        sync_error: BaseException | None = None
        try:
            assert_remote_deployment_lock(remote_lock)
            global_plan = prepare_global_sync(project, args)
            assert_remote_deployment_lock(remote_lock)
            changed_jobs = sync_jobs_have_changes(jobs, args)
            placeholder_needed = remote_management_placeholder_needed(project, args)
            if not (changed_jobs or placeholder_needed or global_plan.changed):
                print("[OK] 远端代码/输入已一致，密码哈希已保留；本次同步零写入")
                return 0
            assert_remote_deployment_lock(remote_lock)
            docker_rebuild_required = prepare_remote_source_write(remote_lock)
            if (
                not args.dry_run
                and args.runtime == "docker"
                and not docker_rebuild_required
            ):
                raise RuntimeError(
                    "远端 prewrite 未建立 Docker rebuild-required 状态；拒绝写入"
                )
            assert_remote_deployment_lock(remote_lock)
            ensure_remote_directories(jobs, args)
            assert_remote_deployment_lock(remote_lock)
            set_remote_sync_marker(args, present=True)
            for job in changed_jobs:
                assert_remote_deployment_lock(remote_lock)
                run_job(job, args)
            assert_remote_deployment_lock(remote_lock)
            ensure_remote_management_placeholder(project, args)
            assert_remote_deployment_lock(remote_lock)
            commit_remote_global(project, args, global_plan)
            assert_remote_deployment_lock(remote_lock)
            # The holder authenticates the previous receipt, validates the
            # new tree, prunes only receipt-owned stale source, binds the new
            # receipt to persistent Docker ownership, and clears the marker.
            commit_remote_source_write(remote_lock)
        except BaseException as exc:
            sync_error = exc
            raise
        finally:
            try:
                release_remote_deployment_lock(remote_lock)
            except BaseException as release_error:
                if sync_error is None:
                    raise
                print(
                    "[WARN] 远端锁清理同时失败，但不会覆盖原始同步错误："
                    f"{release_error}",
                    file=sys.stderr,
                )
        print("\n[OK] " + ("dry-run 完成，远端未修改" if args.dry_run else "同步完成"))
        if not args.dry_run:
            if docker_rebuild_required:
                print(
                    "[WARN] 已停止受管 http-ztp 容器并写入 rebuild-required；"
                    "禁止用宿主 systemd 版 11-load 恢复"
                )
                print("[NEXT] 仅执行容器镜像重建和事务 load：")
                print(
                    f"       cd {args.remote_root} && "
                    "sudo ./infra/docker/deploy.sh deploy"
                )
            else:
                print(
                    "[WARN] 磁盘同步不会热加载 resident worker，也不会直接更新受保护的 "
                    "monitor.html；必须由 load 重启/重建"
                )
                print("[NEXT] 远端同步门禁已清除；登录管理服务器并必须重新执行：")
                print(
                    f"       cd {args.remote_root}/DAY0-Prepare && "
                    f"sudo python3 11-load.py {project.name}"
                )
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    finally:
        if manifest_stage is not None:
            manifest_stage.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
