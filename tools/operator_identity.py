"""Operator identity on the management server: who owns the project, who may run, how root re-runs as them (I-006).

The operator is the owner of the project directory (I-006 design §4.2; v3.1.2 O7 ①).  Compute it once at
the entry point and pass it down (coding rule 2).  Library module: no command line.  Callers put
<tree>/tools on sys.path and import it as operator_identity; the top level imports only the standard library.

skips_identity(argv) -> bool
  True when argv holds -h, --help or --version: the caller runs unchanged, no identity step.

active_project(http_root) -> Path | None
  project_contract.active_project_dir(http_root), imported inside the call (http dev 2026-11-08: the
  diagnostics collector must start without PyYAML).  None: no DAY0-Prepare/activate-project pointer.  An
  invalid pointer raises project_contract.ActiveProjectPointerError (a ValueError); never treat it as None.
  A failed import raises ImportError unchanged, so a caller may fall back to its old default.

resolve_operator(project_dir, *, euid, environ, getpwuid, getpwnam, stat) -> Resolution
  Pure rule; every input defaults to the live process.  project_dir None: action "plain" (no project, no
  check).  A project_dir that does not exist yet is a new project (O11 ④): its operator is the sudo invoker,
  else the current user.  Otherwise the owner of project_dir (stat follows links) is the operator, and:
    current user          project of U                      project of root
    U                     "self" (runs as U)                "refuse"
    root via sudo by U    "represent" (root acts for U)     "self" (root)
    root, no sudo         "represent"                       "self" (root)
    V                     "refuse"                          "refuse"
    root via sudo by V    "refuse" (O7 ②)                   "self" (root)
  SUDO_USER/SUDO_UID count only when euid is 0; the invoker must exist in passwd with the same uid and not
  be root, otherwise "refuse" (owner 2026-10-27 scheme item 1; O7 ④).  A project owner missing from passwd
  is refused too.  Home and group come from passwd (pw_dir, pw_gid), never from HOME.

Resolution(action, operator, banner, refusal)
  action: "plain" | "self" | "represent" | "refuse".  operator: Operator(name, uid, gid, home) or None
  ("plain", or a refused project whose owner has no passwd entry).  banner: one identity line for the
  caller to print.  refusal: None, or the message (owner, current user, the ways out) for a non-zero exit.

needs_reexec(resolution, environ) -> bool
  An operator tool (upgrade, cron.sh; D1 initial-setup) re-runs as the operator when action is
  "represent" (euid 0, operator not root) and ROOT_PARENT_MARKER is absent.

reexec_command(operator, script, args, *, environ, keep, interpreter, root_parent) -> argv
  runuser -u <name> -- env -i PATH= LANG= LC_ALL= TERM= (those present) <keep names present>
  HOME=<pw_dir> USER=<name> LOGNAME=<name> [HTTP_ZTP_ROOT_PARENT=1] <interpreter or sys.executable>
  <absolute script> <args>.  keep may not name ROOT_PARENT_MARKER.

exec_as_operator(..., inherit_fds) -> does not return: marks inherit_fds inheritable, flushes stdout and
  stderr, os.execvp; the exit code is the operator run's.  No marker: no root parent stays behind.
run_as_operator(..., pass_fds) -> int: root parent form (D1, H4).  Starts the command with the marker and
  pass_fds, forwards SIGINT and SIGTERM to it, waits, restores the handlers and returns its exit code
  (128 + n when signal n killed it).  Call it from the main thread.

ROOT_PARENT_MARKER = "HTTP_ZTP_ROOT_PARENT", value "1" (已定 2): only "a root parent started this process".
  The wait form sets it; the worker and 12-ztp-monitor set it for cron.sh (WP-11); H4 and L1 reuse it.  A
  process that sees it never re-runs.  It is inherited by every descendant.
"""
from __future__ import annotations

import os
import pwd
import signal
import subprocess
import sys
from typing import Iterable, Mapping, NamedTuple, Sequence

ROOT_PARENT_MARKER = "HTTP_ZTP_ROOT_PARENT"
ROOT_PARENT_MARKER_VALUE = "1"
IDENTITY_SKIP_ARGUMENTS = frozenset({"-h", "--help", "--version"})
REEXEC_ENV_WHITELIST = ("PATH", "LANG", "LC_ALL", "TERM")


class Operator(NamedTuple):
    name: str
    uid: int
    gid: int
    home: str


class Resolution(NamedTuple):
    action: str
    operator: Operator | None
    banner: str
    refusal: str | None


def skips_identity(argv: Iterable[str]) -> bool:
    return any(argument in IDENTITY_SKIP_ARGUMENTS for argument in argv)


def active_project(http_root):
    from project_contract import active_project_dir

    return active_project_dir(http_root)


def resolve_operator(project_dir, *, euid=None, environ=None, getpwuid=None, getpwnam=None,
                     stat=None) -> Resolution:
    euid = os.geteuid() if euid is None else euid
    environ = os.environ if environ is None else environ
    getpwuid = pwd.getpwuid if getpwuid is None else getpwuid
    getpwnam = pwd.getpwnam if getpwnam is None else getpwnam
    stat = os.stat if stat is None else stat

    # Who is running: the first column of the design §4.2 table.
    invoker = problem = None
    if euid != 0:
        try:
            current = getpwuid(euid).pw_name
        except KeyError:
            current = f"uid {euid}"
    elif "SUDO_USER" not in environ:
        current = "root（由 root 父进程启动）" if ROOT_PARENT_MARKER in environ else "root 直接运行"
    else:
        sudo_user, sudo_uid = environ["SUDO_USER"], environ.get("SUDO_UID")
        current = f"root 经 sudo（发起人 {sudo_user}）"
        try:
            entry = getpwnam(sudo_user)
        except KeyError:
            problem = f"SUDO_USER={sudo_user} 在 passwd 里查不到"
        else:
            if entry.pw_uid == 0:
                problem = f"SUDO_USER={sudo_user} 是 root"
            elif sudo_uid != str(entry.pw_uid):
                problem = f"SUDO_UID={sudo_uid} 与 passwd 里 {sudo_user} 的 uid {entry.pw_uid} 不一致"
            else:
                invoker = Operator(entry.pw_name, entry.pw_uid, entry.pw_gid, entry.pw_dir)
    # Full-width punctuation takes no space before the arrow (design §4.2 example line).
    arrow = "→" if current.endswith("）") else " →"
    if project_dir is None:
        return Resolution("plain", None, f"操作员：未判定（没有当前项目）；当前：{current}{arrow} 原样运行", None)

    try:
        owner_uid = stat(project_dir).st_uid
    except FileNotFoundError:
        owner_uid = None
    source = "项目目录属主" if owner_uid is not None else "新项目，取当前用户"
    if owner_uid is None and invoker is not None:
        owner_uid, source = invoker.uid, "新项目，取 sudo 发起人"
    elif owner_uid is None:
        owner_uid = euid
    try:
        entry = getpwuid(owner_uid)
    except KeyError:
        operator, owner = None, f"uid {owner_uid}（passwd 里查不到）"
    else:
        operator = Operator(entry.pw_name, entry.pw_uid, entry.pw_gid, entry.pw_dir)
        owner = operator.name

    def refuse(reason: str, remedy: str) -> Resolution:
        return Resolution("refuse", operator, f"操作员：{owner}（{source}）；当前：{current}{arrow} 拒绝",
                          f"{reason}：项目 {project_dir} 属于 {owner}；当前：{current}。{remedy}")

    if problem is not None:
        return refuse(f"sudo 发起人无效（{problem}）",
                      "请检查 sudo 的环境变量 SUDO_USER、SUDO_UID，或由 root 直接登录运行。")
    if operator is None:
        return refuse("项目属主没有账户",
                      f"请把项目目录交给操作员：sudo chown <操作员>:<操作员主组> {project_dir}")
    if euid != 0 and operator.uid == 0:
        return refuse("项目属于 root", "请用 sudo 或以 root 运行。")
    if euid != 0 and operator.uid != euid:
        return refuse("当前用户不是项目属主",
                      f"请以 {owner} 运行，或由 root 直接登录运行（会代表 {owner} 执行）。")
    if invoker is not None and operator.uid not in (0, invoker.uid):
        return refuse("sudo 发起人不是项目属主",
                      f"请切换到 {owner} 运行（需要 root 的步骤由 {owner} 加 sudo），"
                      f"或由 root 直接登录运行（会代表 {owner} 执行）。")
    if euid == 0 and operator.uid != 0:
        return Resolution("represent", operator,
                          f"操作员：{owner}（{source}）；当前：{current}{arrow} 项目侧以 {owner} 执行", None)
    return Resolution("self", operator, f"操作员：{owner}（{source}）；当前：{current}{arrow} 以 {owner} 执行", None)


def needs_reexec(resolution: Resolution, environ: Mapping[str, str] | None = None) -> bool:
    environ = os.environ if environ is None else environ
    return resolution.action == "represent" and ROOT_PARENT_MARKER not in environ


def reexec_command(operator: Operator, script, args: Sequence[str], *, environ=None, keep=(), interpreter=None,
                   root_parent=False) -> list:
    environ = os.environ if environ is None else environ
    if ROOT_PARENT_MARKER in keep:
        raise ValueError(f"{ROOT_PARENT_MARKER} is set only by the root parent form, never kept from the caller")
    assignments = {name: environ[name] for name in (*REEXEC_ENV_WHITELIST, *keep) if name in environ}
    assignments.update(HOME=operator.home, USER=operator.name, LOGNAME=operator.name)
    if root_parent:
        assignments[ROOT_PARENT_MARKER] = ROOT_PARENT_MARKER_VALUE
    return ["runuser", "-u", operator.name, "--", "env", "-i",
            *(f"{name}={value}" for name, value in assignments.items()),
            *(interpreter or (sys.executable,)), os.path.abspath(script), *args]


def exec_as_operator(operator: Operator, script, args: Sequence[str], *, environ=None, keep=(), interpreter=None,
                     inherit_fds=()):
    command = reexec_command(operator, script, args, environ=environ, keep=keep, interpreter=interpreter)
    for descriptor in inherit_fds:
        os.set_inheritable(descriptor, True)
    sys.stdout.flush()
    sys.stderr.flush()
    os.execvp(command[0], command)


def run_as_operator(operator: Operator, script, args: Sequence[str], *, environ=None, keep=(), interpreter=None,
                    pass_fds=()) -> int:
    command = reexec_command(operator, script, args, environ=environ, keep=keep, interpreter=interpreter,
                             root_parent=True)
    sys.stdout.flush()
    sys.stderr.flush()
    child = subprocess.Popen(command, pass_fds=tuple(pass_fds))

    def forward(number, _frame):
        child.send_signal(number)

    previous = {number: signal.signal(number, forward) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        code = child.wait()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 128 - code if code < 0 else code
