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
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re
import select
import shlex
import shutil
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import _package_common as project_contract
from project_contract import is_readme_name, is_tools_deployable_file, rsync_excludes

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
ROOT_CODE_PATTERNS = ("*.py", "*.md", "*.html")
DAY0_CODE_PATTERNS = ("*.py", "*.md")
OPTIMIZE_CODE_PATTERNS = ("*.py", "*.sh")

COMMON_EXCLUDES = rsync_excludes() + ("*.tar.gz",)
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
    ".management-pubkeys",
    "mgmt-server.pub",
)

SAFE_HOST = re.compile(r"^(?:[A-Za-z0-9_.-]+@)?[A-Za-z0-9_.-]+$")
SAFE_REMOTE_ROOT = re.compile(r"^/[A-Za-z0-9._/-]+$")
DEPLOYMENT_LOCK_READY = "DEPLOYMENT_LOCK_READY"
DEPLOYMENT_LOCK_TIMEOUT = 30


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
     --include-ztp-runtime，并在同步后立即到管理服务器重新执行 load。
  6. 先使用 --dry-run 查看逐文件变化；确认后删除 --dry-run 正式同步。
     正式同步会在任何 SSH/rsync 连接前自动运行本地 test_cases/run_related_tests.py；
     测试通过并更新批准哈希后才允许连接管理服务器。runner 缺失、manifest 非法或
     任一相关测试失败都会终止，远端不会被触碰；dry-run 不运行此门禁。
  7. 正式同步只更新磁盘文件，不会热加载已运行的 worker，也不会直接更新
     受保护的 monitor.html。等脚本清除 .sync-code-in-progress 并打印 [OK]
     后，必须在管理服务器上重新执行 load，由 load 重启 worker、重新生成
     页面并绑定本次发布。tools/sync-code.py 本身不会自动执行 load。

常用示例：
  # 先预览
  python3 tools/sync-code.py 2099-example-site \
    --host ubuntu@ztp-admin.example --port 21018 --dry-run

  # 正式同步
  python3 tools/sync-code.py 2099-example-site \
    --host ubuntu@ztp-admin.example --port 21018

  # 使用指定 SSH 私钥
  python3 tools/sync-code.py -p 2099-example-site \
    --host ubuntu@ztp-admin.example --identity ~/.ssh/id_ed25519

  # root 登录或远端目录允许当前 SSH 用户直接写入时关闭默认 sudo
  python3 tools/sync-code.py -p 2099-example-site \
    --host root@ztp-admin.example --no-sudo

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
            "同时覆盖 load 已渲染的 bootstrap/ztp.json（危险；同步后必须立即重新 load）"
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
    """Run, approve, and recheck the full local suite before remote contact."""
    runner = PREDEPLOY_TEST_RUNNER
    if not runner.is_file() or runner.is_symlink():
        raise RuntimeError(f"正式同步测试门禁不存在或不是普通文件：{runner}")
    for label, extra in (("全量测试", ["--all"]), ("批准状态复核", ["--check"])):
        command = [sys.executable, "-B", str(runner), *extra]
        print(f"[TEST] 正式同步前{label}：" + shlex.join(command))
        completed = subprocess.run(
            command, cwd=ROOT, shell=False, check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"正式同步{label}失败（exit={completed.returncode}）；"
                "远端未连接、未修改"
            )
    print("[OK] 正式同步全量测试及批准状态门禁通过")


def matching_files(root: Path, patterns: tuple[str, ...]) -> tuple[Path, ...]:
    return tuple(sorted({path for pattern in patterns for path in root.glob(pattern)
                         if path.is_file() and not is_readme_name(path.name)}))


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
        jobs.append(SyncJob("workspace files", root_files, remote_root, COMMON_EXCLUDES))
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


def remote_deployment_lock_command(args: argparse.Namespace) -> list[str]:
    """Build a persistent remote command sharing 11-load.py's flock inode."""
    lock_path = f"{args.remote_root.rstrip('/')}/.deployment.lock"
    holder_script = (
        f"printf '%s\\n' {shlex.quote(DEPLOYMENT_LOCK_READY)}; "
        "cat >/dev/null"
    )
    remote = project_contract.remote_locked_shell_argv(
        lock_path, holder_script, use_sudo=args.sudo,
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
        raise RuntimeError(
            "远端 deployment lock 连接异常退出："
            + ((stderr or "").strip() or lock.path)
        )
    print(f"[UNLOCK] 已释放远端部署锁：{lock.path}")


def rsync_command(job: SyncJob, args: argparse.Namespace) -> list[str]:
    command = [
        "rsync", "-az", "--itemize-changes", "--human-readable", "--stats",
        "-e", ssh_transport(args),
    ]
    if args.dry_run:
        command.append("--dry-run")
    if args.sudo:
        command.append("--rsync-path=sudo -n rsync")
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


def run_job(job: SyncJob, args: argparse.Namespace) -> None:
    command = rsync_command(job, args)
    print(f"\n[SYNC] {job.label} → {args.host}:{job.remote_dir}/")
    print("[RUN]  " + shlex.join(command))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"rsync 失败（exit={completed.returncode}）：{job.label}")


def main(argv: list[str] | None = None) -> int:
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
        print(f"[INFO] 同步任务：{len(jobs)} 个；不会删除远端额外文件")
        if args.include_ztp_runtime:
            print(
                "[WARN] 将覆盖远端 load 已渲染的 bootstrap/ztp.json；"
                "同步结束后、交换机再次 ZTP 前必须重新执行 load"
            )
        else:
            print(
                "[SAFE] 保留远端 load 已渲染的 bootstrap/ztp.json，"
                "不会覆盖 service IP、公钥列表、版本或升级策略"
            )
        if not args.dry_run:
            run_predeploy_test_gate()
        remote_lock = acquire_remote_deployment_lock(args)
        try:
            ensure_remote_directories(jobs, args)
            assert_remote_deployment_lock(remote_lock)
            set_remote_sync_marker(args, present=True)
            for job in jobs:
                assert_remote_deployment_lock(remote_lock)
                run_job(job, args)
            assert_remote_deployment_lock(remote_lock)
            ensure_remote_management_placeholder(project, args)
            assert_remote_deployment_lock(remote_lock)
            # Clearing the persistent marker is the final promotion.  Keep the
            # advisory lock until this succeeds so load cannot check old code
            # and then race with a last rsync/placeholder write.
            set_remote_sync_marker(args, present=False)
        finally:
            release_remote_deployment_lock(remote_lock)
        print("\n[OK] " + ("dry-run 完成，远端未修改" if args.dry_run else "同步完成"))
        if not args.dry_run:
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


if __name__ == "__main__":
    raise SystemExit(main())
