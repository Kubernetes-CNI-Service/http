#!/usr/bin/env python3
"""Direct contracts for the final Q01 publication phase on v2."""

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test_cases/script_test_manifest.json"
SYSTEM_EXECUTABLE_PATH = os.confstr("CS_PATH") or "/usr/bin:/bin"
_SYSTEM_GIT = shutil.which("git", path=SYSTEM_EXECUTABLE_PATH)
if not _SYSTEM_GIT:
    raise RuntimeError("trusted system Git executable is unavailable")
GIT_BINARY = str(Path(_SYSTEM_GIT).resolve())
S_COMMIT = "991a64476cfe1de2a0ab45bca8b7b6d75d5e9149"
S_MANIFEST_SHA256 = (
    "aef45f0621332318af9bc4cb4710b2f5a3062b2bc962964f9b6fd1201d540ed0"
)
P_MANIFEST_SIZE = 53298
P_MANIFEST_SHA256 = (
    "b3bd5315bce55679e9aae86336cee77a86af8d97de9fde9088557719e528a964"
)
P_MANIFEST_SECTION_DIGESTS = {
    "baseline_tests": "a16e66c6173de4bad1d5533c340ed7f4f0707094b27e1b40ca3485a658621147",
    "test_suites": "1741ffc5790997eeb73eb8054ecb7ce9534b8b6dea69983214a487ac59395ab7",
    "test_rules": "c12e83c6aeaa5f741de1ed9884cd87a43c1f9851831add71517eff7da20ba88d",
    "workflows": "6a5862e24cd334b8c9521132e59b8b2e6f4ab5511b55aa95dbf82bd0102ce4e8",
    "path_rules": "2a024015bb95c7ce20e332edd89f53afa8836a2bda15345b3b45c67ddf90885a",
    "scripts": "f21e1537befe39436053ec3f921ce98f2dd8864120f3b103d52ceb9cca2ab525",
    "tracked_support": "7f8cea166970162daa88bf4cb7e6ea66bfd7917cc7cddc618b5d6128529cd1ba",
}
Q01_PUBLIC_DOCUMENT_PATHS = (
    "docs/README.md",
    "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md",
    "docs/deployment/README.md",
    "docs/operations/README.md",
    "docs/reference/README.md",
    "docs/validation/README.md",
    "infra/docker/README.md",
)
Q01_PUBLIC_DOCUMENT_SHA256 = {
    "docs/README.md": "e646ad967d9bd418451f152fd2c48f41fe3415dc7acea55e434ae610ff1b57fd",
    "docs/architecture/README.md": "153837bcd62f49edf8591ceec8b1b6ccefe9a3b5638a91bed6452ac87264a0e4",
    "docs/deployment/BUNDLE_WORKFLOWS.md": "adab10445e130f3335113c5b35072b81b5d7e10d28d3d1214ace45e120199a1b",
    "docs/deployment/README.md": "f1914024ab82546239f9424abaca44380f22d6c4331c76e3e6ede218333a036e",
    "docs/operations/README.md": "da1fb0570f8277d7304c1446ab49d7ae49dcf52a320c86b90babdf15e4a6dd05",
    "docs/reference/README.md": "717f023b3016420b61e8889493fd0e2ab9d0106388483025f8d66dee75c75039",
    "docs/validation/README.md": "2a2ee457e01074db1994363a2f8ed62029a9febb14d7c4ea92243b93ec61d98f",
    "infra/docker/README.md": "8355b6cf2bea57f072a689da6a4c3e4979cfd3da26c87f585a728c42972fb996",
}
P_PHASE_STATIC_TARGET_SHA256 = {
    ".github/README.md": "d6ef8e75f5e745c1991bea9c97d41b0f21ceb7653c0e9112faa84bf513dda35a",
    "PUBLIC_REPOSITORY.md": "dd5541aa172c431290bc9060905927773c668d7fea907b9d82ddb24d252e8a60",
    "test_cases/README.md": "670466172c97db3092db21345414b048b1acad1ed69898566132925b52c900cb",
    "test_cases/REAL_ENVIRONMENT.md": "cbf4d5b5623a117f13e06b154ebd0147243a585bcb4084e2476d17d68ff38676",
}
P_CAPSULE_DOCUMENT_APPEND = {
    "test_cases/README.md": (
        "\n### P 阶段正式证明的 Python 依赖 capsule\n\n"
        "P 阶段在绑定的 macOS CPython 3.9 环境中，把独立审定的依赖文件构造成确定性 USTAR archive。父进程在关闭唯一写 descriptor 后，以 `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` 重新打开并立即 unlink；正式流程只复用这个 anonymous read-only inode。每个顶层需要第三方依赖的 Python child 都从它重新安全解包到独立 `0700` snapshot，逐项核对固定清单、SHA-256、模式、Mach-O/ABI 和包版本，再经固定 `/usr/bin/sandbox-exec` profile 启动 `-I -S` Python。该顶层 child 创建的普通 Python 后代仍在同一 sandbox 中运行，并使用经逐级验证的 exact-layout `PYTHONHOME` 与 exact-empty `site-packages`；它们的 `PYTHONPATH` 精确包含 snapshot、绑定的标准库和 `lib-dynload` 三项，从而阻断 ambient、user 或 system site-packages 的意外回退。该 profile 禁止 child 及其后代写入、重命名或建立 snapshot alias；任何 sandbox 不可用、依赖漂移、非法 archive、FD/identity 漂移或清理失败都阻断证明，不能回退到 user/system site-packages。只负责启动正式 FQN 的 orchestration harness 使用绝对路径 CPython `-I -S` 和受信任标准库，不导入第三方依赖、也不套外层 sandbox；它只把同一个 anonymous archive FD 交给正式 full runner。该 runner 作为顶层依赖 child 建立并持有经过认证的 snapshot、exact-layout `PYTHONHOME` 和 archive identity。只有精确批准的 test-runner argv 才能进入 reentrant 模式；每次 reentry 都重新认证这些 held authority，证明嵌套 `sandbox-exec` 精确返回 71 且 snapshot 写入被内核拒绝，然后在既有 sandbox 中用有界 direct child 运行，绝不嵌套 sandbox、重建 archive、回退或清理继承状态。\n\n"
        "只有 `-B test_cases/run_related_tests.py --all -v`、`-B test_cases/run_related_tests.py --suite repository-governance -v` 与 `-B test_cases/run_related_tests.py --all --no-approve -v` 三组精确审定的 runner argv 会在进入顶层 child sandbox 前，由父进程在同一个私有 state root 内预启动受管 loopback OpenSSH fixture。父进程使用固定的 `/usr/sbin/sshd`、`/usr/bin/ssh-keygen` 与 `/usr/bin/ssh-keyscan`，以临时 host key 在 `127.0.0.1` ephemeral port 完成真实 KEX，并用持久 held read-only descriptor 绑定 key、config、manifest 与 daemon log identity；每轮另通过 held root dirfd 对 PID file 做短持有 `NOFOLLOW` open、双 `pread`/`fstat` 与精确 `pid\\n` 验证。near-miss、hidden probe 与普通 child 均不得触发或继承该 fixture。父进程只向精确三类 child 传递 routing marker，不传 fixture 路径或 descriptor；child 先认证既有的 exact-nine environment protocol 与 archive、snapshot、`PYTHONHOME` exact-seven dependency descriptor，再从 authenticated `snapshot.parent` 派生固定 sibling 路径并以 `NOFOLLOW` held reads 自行验证 fixture，因此不会增加任何传入 FD。顶层 sandbox profile 另以 literal/subpath 规则禁止 child 及其后代写入、重命名或建立指向 fixture subtree 的可写别名。child 返回或抛出任何异常后，父进程都重新核对 held identity 与 payload，并以有界 TERM→KILL process-group 流程回收 daemon、关闭全部 descriptor、删除 fixture；创建、KEX、认证、内核写保护、回收或清理任一步失败都会阻断正式证明。\n\n"
        "这项自动化保证覆盖当前证明进程、child/grandchild 以及其可执行的 snapshot 篡改；它明确不承诺抵御另一个已在运行且拥有同一 UID 的独立恶意进程在 archive 建立窗口内抢占 writable FD。正式证明必须在无不受信任同 UID 进程的专用会话中执行；该剩余边界与人工证据登记在 `REAL_ENVIRONMENT.md`。\n"
    ),
    "test_cases/REAL_ENVIRONMENT.md": (
        "\n## TC-REAL-P-DEPENDENCY-CAPSULE-001 — macOS 正式证明的同 UID 并发边界\n\n"
        "- 状态：**NOT RUN / REAL_ENV REQUIRED**。自动化会验证 anonymous read-only archive、逐个依赖 child 的 snapshot 与 `sandbox-exec` 写保护；只使用标准库的 orchestration harness 不套外层 sandbox。仅 `-B test_cases/run_related_tests.py --all -v`、`-B test_cases/run_related_tests.py --suite repository-governance -v` 与 `-B test_cases/run_related_tests.py --all --no-approve -v` 三组精确审定的 runner argv 会在进入 child sandbox 前，由父进程预启动受管 loopback OpenSSH fixture。sshd 本身不在该 child profile 内启动，但只监听 `127.0.0.1` ephemeral port，使用临时 host key、禁用交互认证且不读取真实项目凭据。父进程只传 routing marker，不传 fixture 路径或 FD；child 先认证既有 exact-nine environment protocol 与 exact-seven dependency descriptor，再从 authenticated `snapshot.parent` 派生固定 sibling 并自行验证 fixture。自动化不会创建一个独立恶意同 UID 进程去抢占 archive 建立窗口；不得把单元/workflow 结果解释为抵御该外部进程。\n"
        "- 前置条件：绑定的 macOS/arm64/CPython 3.9 主机与专用本地会话；没有不受信任的同 UID watch、IDE agent、cron、测试或调试进程。正式 runner 必须在允许 `/usr/bin/sandbox-exec` 应用子 profile 的非嵌套 sandbox 环境运行。只记录脱敏 UID、OS/Python/sandbox identity 与 allowlisted 进程摘要，不保存完整 argv、环境、项目内容或凭据。\n"
        "- 步骤与预期：先核对同 UID 进程摘要，再在允许 `/usr/bin/sandbox-exec` 建立顶层 profile 的非嵌套环境中执行正式 full/check/list/list-suites/repository/no-approve 链。保存 archive 的 dev/ino/mode/nlink/size/SHA-256、每个 fresh snapshot 与 `PYTHONHOME` 的 identity、精确三类父进程 loopback scope 的 `/usr/sbin/sshd` identity、临时 key/config/manifest/log 的持久 held identity、经 held root dirfd 对 PID file 执行的短持有 `NOFOLLOW` 双 `pread`/`fstat` 证据、父进程真实 KEX、child exact-seven FD 集合、fixture subtree 写入与重命名拒绝、完整 KnownHostsCommand 正负矩阵、daemon process-group 回收、退出码、ledger 与最终 clean tree；任何意外同 UID 进程、sandbox 不可用、依赖/ABI 漂移、ownership 漂移、daemon 未回收或临时对象残留都使本次证据无效，不能回退或手工批准。\n"
        "- 清理与风险：确认所有 archive/snapshot/`PYTHONHOME`/loopback fixture FD 已关闭、受管 sshd process group 已回收且随机 state root 已删除；异常时终止本次证明、以有界 TERM→KILL 流程回收受管 daemon、清理受控临时目录，并在新的专用会话重跑。sshd 不在 child sandbox 内，但该自动化场景只使用 `127.0.0.1` loopback、ephemeral port、临时 key 与禁用交互认证的固定配置，属于非破坏性本机证明；它不发送外部网络流量、不读取真实凭据，也不修改系统 sshd 配置、服务或状态。独立恶意同 UID 进程仍可能在 transient named archive window 内预先取得 writable FD，这是用户明确接受且自动化不覆盖的剩余风险；root/ptrace 或内核级攻击同样不在该证明边界内。\n"
    ),
}
P_CAPSULE_DOCUMENT_SOURCE = {
    "test_cases/README.md": (41382, "bcc9c95bc6026dbd643466bf1a5c0869eb41c192d63c6d30005499fb88604fce"),
    "test_cases/REAL_ENVIRONMENT.md": (78096, "8f8ecb83ff4ae664bc669e0f3c7ce3261eb5fbb624edd402c1770d066de57424"),
}
P_PRECAPSULE_DOCUMENT_INSERT = {
    "test_cases/README.md": (
        "真实交换机、Docker 或端到端部署测试。\n",
        "\n四类交付制品的自动化与真实环境分工见\n"
        "[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)。\n",
    ),
    "test_cases/REAL_ENVIRONMENT.md": (
        "对应解析、事务和失败分支仍应在 `test_*.py` 中使用 fixture 自动覆盖。\n",
        "\n四类 bundle 的边界和 `2026-12-vb-gb300` 场景选择见\n"
        "[《四类交付制品与 2026-12 部署流程》](../docs/deployment/BUNDLE_WORKFLOWS.md)；下面只登记必须在\n"
        "Ubuntu、Docker、adapter、网络隔离或真实设备上取得的证据。\n",
    ),
}
P_PRECAPSULE_DOCUMENT_SOURCE = {
    "test_cases/README.md": (41532, "f50686606e914d0aceb869ce97ca614fd2f02ebd96da0d370bbe59bb5490a8fd"),
    "test_cases/REAL_ENVIRONMENT.md": (78354, "cb14298daca40852f2e9bdab169d9ad7704d3c27f2ca0ebd0229b25d00d2192a"),
}
P_CAPSULE_DOCUMENT_TARGET_SIZE = {
    "test_cases/README.md": 45400,
    "test_cases/REAL_ENVIRONMENT.md": 81672,
}
S_HTML_SHA256 = (
    "516c73b23bc5d74f332c7d649cf99a60fd52585f57db467e97ad53237411ca39"
)
P_HTML_STATIC_SEED_SIZE = 710608
P_HTML_STATIC_SEED_SHA256 = (
    "31926c7c07dbcfa0a4f2ea7ff1a31568747572f4a85e4452f04889c013efe5b4"
)
P_HTML_FINAL_SIZE = 718686
P_HTML_FINAL_SHA256 = (
    "392c8fb10c62d1926385cfc0fde4eb37300130dc9bd051c300653f210f31e0f9"
)
Q05_V2_FORBIDDEN_LIFECYCLE_PATHS = (
    "docs/v3/finished-project-lifecycle/ARCHITECTURE.md",
    "docs/v3/finished-project-lifecycle/OPEN_QUESTIONS.md",
    "docs/v3/finished-project-lifecycle/OVERVIEW.md",
    "docs/v3/finished-project-lifecycle/REQUIREMENTS.md",
    "docs/v3/finished-project-lifecycle/TEST_PLAN.md",
    "docs/v3/finished-project-lifecycle/USER_GUIDE.md",
    "docs/v3/finished-project-lifecycle/WORKFLOWS.md",
)
P_V2_FORBIDDEN_REFERENCE_PATHS = (
    "Finished-projects/.gitignore",
    "Finished-projects/README.txt",
    "v3-requirements.md",
    "monitor/cabletracker-main/.env.example",
    "monitor/cabletracker-main/.gitignore",
    "monitor/cabletracker-main/.gitlab-ci.yml",
    "monitor/cabletracker-main/Dockerfile",
    "monitor/cabletracker-main/README.md",
    "monitor/cabletracker-main/cabletracker_runner.py",
    "monitor/cabletracker-main/docker-compose.yaml",
    "monitor/cabletracker-main/mapping_v4.json",
    "monitor/cabletracker-main/refresh_cvt_sum.py",
    "monitor/cabletracker-main/requirements.txt",
    "monitor/cabletracker-main/tests/fixtures/cvt_offline_sample.json",
    "monitor/cabletracker-main/tests/test_cvt_sum.py",
    "monitor/cabletracker-main/tests/test_offline_workflow.py",
    "monitor/cabletracker-main/tmp.json",
)
P_V2_FORBIDDEN_ROOTS = (
    "docs/v3/finished-project-lifecycle",
    "Finished-projects",
    "monitor/cabletracker-main",
)
P_PHASE_TEST_MODULES = (
    "test_cases.test_public_publication_contract",
    "test_cases.test_public_publication_workflow",
)
P_FINAL_TRACKED_SUPPORT_PATHS = (
    ".dockerignore",
    ".gitattributes",
    ".github/workflows/monitor-authority-root.yml",
    ".github/workflows/tests.yml",
    ".gitignore",
    "AGENTS.md",
    "DAY0-Prepare/template/.management-pubkeys",
    "DAY0-Prepare/template/01-global.yaml",
    "DAY0-Prepare/template/02-devices_config.csv",
    "DAY0-Prepare/template/02-dhcp-subnet_config.csv",
    "DAY0-Prepare/template/99-output-backup/.gitkeep",
    "DAY0-Prepare/template/99-output-dhcp/.gitkeep",
    "DAY0-Prepare/template/99-output-eth/.gitkeep",
    "DAY0-Prepare/template/99-output-ib_nvl/.gitkeep",
    "DAY0-Prepare/template/99-output-ib_nvl/bringup/ndr-upgrade-logs/.gitkeep",
    "DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-initial-setup-logs/.gitkeep",
    "DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-upgrade-logs/.gitkeep",
    "DAY0-Prepare/template/99-output-monitor/.gitkeep",
    "DAY0-Prepare/template/99-output-p2p/.gitkeep",
    "DAY0-Prepare/template/99-output-ztp/.gitkeep",
    "DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-amd64.bin",
    "DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-vx.bin",
    "DAY0-Prepare/template/laptop.pub",
    "DAY0-Prepare/template/mgmt-server.pub",
    "DAY0-Prepare/template/nvosv25-02-7002amd64.bin",
    "DAY0-Prepare/template/nvosv25-02-8008amd64.bin",
    "DAY0-Prepare/template/p2p.xlsx",
    "PUBLIC_REPOSITORY.md",
    "SECURITY.md",
    "docs/README.md",
    "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md",
    "docs/deployment/README.md",
    "docs/operations/README.md",
    "docs/reference/README.md",
    "docs/validation/README.md",
    "examples/public-project/01-global.yaml.example",
    "examples/public-project/02-devices_config.csv.example",
    "examples/public-project/02-dhcp-subnet_config.csv.example",
    "index.html",
    "infra/docker/.dockerignore",
    "infra/docker/.gitignore",
    "infra/docker/Dockerfile",
    "infra/docker/Dockerfile.dockerignore",
    "infra/docker/README.md",
    "infra/docker/apache-ztp.conf",
    "infra/docker/compose.yaml",
    "infra/docker/container.env.example",
    "infra/docker/logrotate-http-ztp.conf",
    "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/runtime-contract.json",
    "infra/docker/supervisord.conf",
    "requirements-container-top-level.lock",
    "requirements-dev.txt",
    "test_cases/REAL_ENVIRONMENT.md",
    "test_cases/audit_public_tree.py",
    "test_cases/monitor_authority_root_warden.py",
    "test_cases/monitor_authority_source_guard.py",
    "test_cases/public_project_fixture.py",
    "test_cases/run_monitor_authority_entrypoints.sh",
    "test_cases/run_related_tests.py",
    "test_cases/run_vm_validation.py",
    "tools/lldp-analyze-tool/04-lldp-device-aliases.json",
    "user-manual.html",
    "ztp/config/cumulus/ar_profile_custom.conf",
    "ztp/config/cumulus/default.yaml",
    "ztp/config/cumulus/default_5.16.5.yaml",
    "ztp/config/cumulus/template/03-templates-j2/_bridge_l2vlans.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/_dhcp_relay.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/_direct_vlan_ports.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/_extra_aaa_users.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/_global_evpn.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/_l2_svis.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/border.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oob-core.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oob-leaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oob-rack-tor.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oob-su-leaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oob-su-spine.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oobofoob-leaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/oobofoob-spine.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/tan-cp-1gleaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/tan-cp-leaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/tan-hps-leaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/tan-leaf.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/tan-spine.yaml.j2",
    "ztp/config/cumulus/template/03-templates-j2/tan-su-leaf.yaml.j2",
    "ztp/config/cumulus/template/P2P/01-inventory.log",
    "ztp/config/cumulus/template/P2P/02-port-mapping.log",
    "ztp/config/cumulus/template/P2P/03-splitter.log",
    "ztp/config/cumulus/template/P2P/air-template-no-oob.json",
    "ztp/config/cumulus/template/P2P/air-template.json",
    "ztp/config/cumulus/template/P2P/lldpq-template.dot",
    "ztp/config/nvos/default.yaml",
    "ztp/config/nvos/disable-password-hardening.nv",
    "ztp/config/nvos/template/P2P/01-inventory.log",
    "ztp/config/nvos/template/P2P/02-port-mapping.log",
    "ztp/config/nvos/template/P2P/03-splitter.log",
    "ztp/templates/ztp.json",
)
P_UNEXPECTED_TRACKED_SUPPORT = "test_cases/CASE_TEMPLATE.md"


def _canonical_git_environment():
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("GIT_"):
            environment.pop(key, None)
    environment.update({
        "GIT_CONFIG": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return environment


def _canonical_git(repository: Path, *args: str, text: bool = False):
    return subprocess.run(
        [GIT_BINARY, "--no-replace-objects", "-c", f"core.hooksPath={os.devnull}",
         "-C", str(repository), *args],
        env=_canonical_git_environment(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=text, check=False,
    )


def p_manifest_support_violations(manifest) -> set[str]:
    return set(manifest.get("tracked_support", ())).symmetric_difference(
        P_FINAL_TRACKED_SUPPORT_PATHS
    )


def _normalized_digest(value) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def expected_p_manifest() -> dict:
    source = _canonical_git(
        ROOT, "show", f"{S_COMMIT}:test_cases/script_test_manifest.json",
    )
    if source.returncode != 0:
        raise AssertionError(source.stderr.decode("utf-8", "replace"))
    if hashlib.sha256(source.stdout).hexdigest() != S_MANIFEST_SHA256:
        raise AssertionError("unreviewed S manifest source")
    manifest = json.loads(source.stdout.decode("utf-8"))

    repository_suite = next(
        suite for suite in manifest["test_suites"]
        if suite["id"] == "repository-governance"
    )
    repository_suite["tests"].extend(P_PHASE_TEST_MODULES)

    support = manifest["tracked_support"]
    security_index = support.index("SECURITY.md") + 1
    support[security_index:security_index] = list(Q01_PUBLIC_DOCUMENT_PATHS[:7])
    index_index = support.index("index.html") + 1
    support[index_index:index_index] = ["infra/docker/README.md"]

    public_rule = next(
        rule for rule in manifest["path_rules"]
        if "PUBLIC_REPOSITORY.md" in rule["paths"]
    )
    public_rule["tests"].extend(P_PHASE_TEST_MODULES)
    documentation_rule = next(
        rule for rule in manifest["path_rules"]
        if rule["paths"] == [
            "AGENTS.md", "index.html", "user-manual.html",
            "*/README.md", "*/*/README.md", "*/*/*/README.md",
        ]
    )
    documentation_rule["paths"][3:3] = list(Q01_PUBLIC_DOCUMENT_PATHS)
    documentation_rule["tests"].extend(P_PHASE_TEST_MODULES)
    return manifest


def expected_p_manifest_payload() -> bytes:
    manifest = expected_p_manifest()
    for key, digest in P_MANIFEST_SECTION_DIGESTS.items():
        if _normalized_digest(manifest[key]) != digest:
            raise AssertionError(f"reviewed P manifest {key} drift")
    payload = (
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    if len(payload) != P_MANIFEST_SIZE:
        raise AssertionError("reviewed P manifest size drift")
    if hashlib.sha256(payload).hexdigest() != P_MANIFEST_SHA256:
        raise AssertionError("reviewed P manifest digest drift")
    return payload


def expected_p_html_static_seed() -> bytes:
    source = _canonical_git(ROOT, "show", f"{S_COMMIT}:user-manual.html")
    if source.returncode != 0:
        raise AssertionError(source.stderr.decode("utf-8", "replace"))
    if hashlib.sha256(source.stdout).hexdigest() != S_HTML_SHA256:
        raise AssertionError("unreviewed S HTML source")
    old = b"<code>deploy.sh --help</code>"
    new = b"<code>infra/docker/README.md</code>\xe3\x80\x81" + old
    if source.stdout.count(old) != 1:
        raise AssertionError("reviewed P HTML static anchor is ambiguous")
    seed = source.stdout.replace(old, new)
    if len(seed) != P_HTML_STATIC_SEED_SIZE:
        raise AssertionError("reviewed P HTML static seed size drift")
    if hashlib.sha256(seed).hexdigest() != P_HTML_STATIC_SEED_SHA256:
        raise AssertionError("reviewed P HTML static seed digest drift")
    return seed


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return _canonical_git(ROOT, *args, text=True)


def _present_directory_entries(root: Path, paths) -> set[str]:
    present = set()
    for relative in paths:
        try:
            (root / relative).lstat()
        except FileNotFoundError:
            continue
        present.add(relative)
    return present


def _p_v2_path_violations(paths) -> set[str]:
    exact = (*Q05_V2_FORBIDDEN_LIFECYCLE_PATHS, *P_V2_FORBIDDEN_REFERENCE_PATHS)
    return {
        path
        for path in paths
        if any(
            path == forbidden or path.startswith(forbidden + "/")
            for forbidden in exact
        )
        or any(path == root or path.startswith(root + "/") for root in P_V2_FORBIDDEN_ROOTS)
    }


def _manifest_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _manifest_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _manifest_strings(item)


def _assert_git_object_authority(repository: Path) -> Path:
    git_directory = repository / ".git"
    try:
        metadata = git_directory.lstat()
    except OSError as error:
        raise AssertionError("P Git directory is missing") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise AssertionError("P Git directory is not a real directory")
    for forbidden in (
        git_directory / "commondir",
        git_directory / "objects/info/alternates",
        git_directory / "objects/info/http-alternates",
    ):
        if os.path.lexists(forbidden):
            raise AssertionError(f"P Git object authority is redirected: {forbidden}")
    return git_directory


def _read_raw_git_object(
    repository: Path, object_id: str, expected_kind: str,
) -> tuple[str, str, int, bytes]:
    if not re.fullmatch(r"[0-9a-f]{40}", object_id):
        raise AssertionError(f"invalid P object id: {object_id!r}")
    if expected_kind not in {"blob", "tree", "commit"}:
        raise AssertionError(f"invalid P expected object kind: {expected_kind!r}")
    environment = _canonical_git_environment()
    for key in tuple(environment):
        if key.startswith(("LD_", "DYLD_")):
            environment.pop(key, None)
    environment["PATH"] = SYSTEM_EXECUTABLE_PATH
    try:
        result = subprocess.run(
            [GIT_BINARY, "--no-replace-objects", "-c",
             f"core.hooksPath={os.devnull}", "-C", str(repository),
             "cat-file", "--batch"],
            env=environment, input=(object_id + "\n").encode("ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
            check=False, timeout=1,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AssertionError("P raw object authority read failed") from error
    if result.returncode != 0 or result.stderr != b"":
        raise AssertionError("P raw object authority process failed")
    header, separator, remainder = result.stdout.partition(b"\n")
    fields = header.split(b" ") if separator else ()
    if len(fields) != 3:
        raise AssertionError("P raw object response header is malformed")
    try:
        echoed = fields[0].decode("ascii")
        kind = fields[1].decode("ascii")
        raw_size = fields[2].decode("ascii")
    except UnicodeError as error:
        raise AssertionError("P raw object response header is not ASCII") from error
    if echoed != object_id or kind != expected_kind:
        raise AssertionError("P raw object response identity/type mismatch")
    if not re.fullmatch(r"0|[1-9][0-9]*", raw_size):
        raise AssertionError("P raw object response size is noncanonical")
    size = int(raw_size)
    if len(remainder) != size + 1 or remainder[-1:] != b"\n":
        raise AssertionError("P raw object response length/delimiter mismatch")
    payload = remainder[:-1]
    canonical = (
        kind.encode("ascii") + b" " + str(len(payload)).encode("ascii")
        + b"\0" + payload
    )
    if hashlib.sha1(canonical).hexdigest() != object_id:
        raise AssertionError("P raw object payload does not match its object id")
    return echoed, kind, size, payload


def _verified_commit_records(
    repository: Path, object_id: str,
) -> dict[str, tuple[str, str, str, bytes]]:
    if object_id == "HEAD":
        object_id = _direct_head_oid(repository)
    _assert_git_object_authority(repository)
    _oid, _kind, _size, commit = _read_raw_git_object(
        repository, object_id, "commit",
    )
    headers, separator, _body = commit.partition(b"\n\n")
    lines = headers.split(b"\n") if separator else ()
    if not lines or not re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]):
        raise AssertionError("P commit tree header is not exact and first")
    if any(line.startswith(b"tree") for line in lines[1:]):
        raise AssertionError("P commit has a duplicate/misplaced tree header")
    root_tree = lines[0][5:].decode("ascii")
    records = {}

    def walk(tree_id: str, prefix: str, ancestors: tuple[str, ...]) -> None:
        if tree_id in ancestors:
            raise AssertionError("P tree graph contains a cycle")
        _tree_oid, _tree_kind, _tree_size, payload = _read_raw_git_object(
            repository, tree_id, "tree",
        )
        offset = 0
        previous_key = None
        logical_names = set()
        entries = []
        while offset < len(payload):
            space = payload.find(b" ", offset)
            nul = payload.find(b"\0", space + 1 if space >= 0 else offset)
            if space <= offset or nul < 0 or nul + 21 > len(payload):
                raise AssertionError("P tree object has a truncated entry")
            raw_mode = payload[offset:space]
            raw_name = payload[space + 1:nul]
            raw_oid = payload[nul + 1:nul + 21]
            offset = nul + 21
            if raw_mode not in {b"100644", b"100755", b"120000", b"40000"}:
                raise AssertionError("P tree object has a noncanonical mode")
            if not raw_name or raw_name in {b".", b".."} or b"/" in raw_name:
                raise AssertionError("P tree object has an unsafe name")
            try:
                name = raw_name.decode("utf-8")
            except UnicodeError as error:
                raise AssertionError("P tree object name is not UTF-8") from error
            if name in logical_names:
                raise AssertionError("P tree object has a duplicate logical name")
            logical_names.add(name)
            is_tree = raw_mode == b"40000"
            order_key = raw_name + (b"/" if is_tree else b"")
            if previous_key is not None and order_key <= previous_key:
                raise AssertionError("P tree object order is noncanonical")
            previous_key = order_key
            entries.append((raw_mode.decode("ascii"), name, raw_oid.hex(), is_tree))
        for mode, name, child_oid, is_tree in entries:
            relative = f"{prefix}/{name}" if prefix else name
            if is_tree:
                walk(child_oid, relative, (*ancestors, tree_id))
            else:
                _blob_oid, kind, _blob_size, blob = _read_raw_git_object(
                    repository, child_oid, "blob",
                )
                if relative in records:
                    raise AssertionError(f"duplicate P tree path: {relative}")
                records[relative] = (mode, kind, child_oid, blob)

    walk(root_tree, "", ())
    return records


def _direct_head_oid(repository: Path) -> str:
    git_directory = _assert_git_object_authority(repository)
    try:
        head = (git_directory / "HEAD").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise AssertionError("P HEAD cannot be read exactly") from error
    if re.fullmatch(r"[0-9a-f]{40}", head):
        return head
    if not head.startswith("ref: "):
        raise AssertionError("P HEAD is neither detached nor a canonical ref")
    ref = head[5:]
    if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", ref) or ".." in ref.split("/"):
        raise AssertionError("P HEAD ref is unsafe")
    loose = git_directory / ref
    if os.path.lexists(loose):
        try:
            value = loose.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise AssertionError("P HEAD loose ref cannot be read") from error
        if re.fullmatch(r"[0-9a-f]{40}", value):
            return value
        raise AssertionError("P HEAD loose ref is malformed")
    packed = git_directory / "packed-refs"
    try:
        lines = packed.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise AssertionError("P HEAD ref is missing") from error
    matches = [line[:40] for line in lines if line[41:] == ref]
    if len(matches) != 1 or not re.fullmatch(r"[0-9a-f]{40}", matches[0]):
        raise AssertionError("P packed HEAD ref is ambiguous")
    return matches[0]


def _tree_blob_records() -> dict[str, tuple[str, bytes]]:
    records = _verified_commit_records(ROOT, "HEAD")
    return {
        relative: (mode, payload)
        for relative, (mode, kind, _object_id, payload) in records.items()
        if kind == "blob"
    }


def _markdown_slug(heading: str) -> str:
    slug = heading.strip().lower()
    slug = re.sub(r"[^\w\-\u4e00-\u9fff ]", "", slug)
    return re.sub(r"\s+", "-", slug)


def _assert_local_markdown_links(relative: str, payload: bytes, records) -> None:
    text = payload.decode("utf-8")
    for raw_target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = raw_target.strip().split(None, 1)[0].strip("<>")
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path_part, _separator, fragment = target.partition("#")
        destination = relative if not path_part else posixpath.normpath(
            posixpath.join(posixpath.dirname(relative), path_part)
        )
        if (
            destination.startswith("/") or destination == ".."
            or destination.startswith("../") or "\0" in destination
        ):
            raise AssertionError(f"unsafe Markdown link: {relative} -> {raw_target}")
        record = records.get(destination)
        if record is None or record[0] != "100644":
            raise AssertionError(f"missing/nonregular Markdown link: {destination}")
        if fragment:
            headings = {
                _markdown_slug(heading)
                for heading in re.findall(
                    r"^#{1,6}\s+(.+?)\s*$", record[1].decode("utf-8"), re.M,
                )
            }
            if fragment.lower() not in headings:
                raise AssertionError(f"missing Markdown fragment: {destination}#{fragment}")
class PublicPublicationDirectTests(unittest.TestCase):
    def test_p_phase_modules_have_one_repository_governance_suite(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(expected_p_manifest(), manifest)
        memberships = {
            module: [
                suite["id"] for suite in manifest["test_suites"]
                if module in suite["tests"]
            ]
            for module in P_PHASE_TEST_MODULES
        }
        self.assertEqual(
            {module: ["repository-governance"] for module in P_PHASE_TEST_MODULES},
            memberships,
        )

    def test_p_phase_public_document_exact8_are_tracked_regular_files(self):
        self.assertEqual(8, len(Q01_PUBLIC_DOCUMENT_PATHS))
        for relative in Q01_PUBLIC_DOCUMENT_PATHS:
            with self.subTest(path=relative):
                tracked = _git("ls-files", "--error-unmatch", "--", relative)
                self.assertEqual(0, tracked.returncode, tracked.stderr or relative)
                ignored = _git("check-ignore", "--no-index", "--quiet", "--", relative)
                self.assertEqual(1, ignored.returncode, relative)
                metadata = (ROOT / relative).lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode), relative)
                self.assertEqual(0o644, stat.S_IMODE(metadata.st_mode), relative)
                self.assertEqual(
                    Q01_PUBLIC_DOCUMENT_SHA256[relative],
                    hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                )

    def test_p_phase_v2_worktree_and_index_exclude_exact7_lifecycle_documents(self):
        self.assertEqual(7, len(Q05_V2_FORBIDDEN_LIFECYCLE_PATHS))
        for relative in Q05_V2_FORBIDDEN_LIFECYCLE_PATHS:
            for hostile_type in ("regular", "symlink", "descendant"):
                with self.subTest(path=relative, hostile_type=hostile_type):
                    with tempfile.TemporaryDirectory() as directory:
                        hostile_root = Path(directory)
                        path = hostile_root / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        if hostile_type == "regular":
                            path.write_bytes(b"future lifecycle\n")
                        elif hostile_type == "symlink":
                            path.symlink_to("missing-lifecycle-target")
                        else:
                            path.mkdir()
                            (path / "child").write_bytes(b"future lifecycle\n")
                        self.assertEqual(
                            {relative},
                            _present_directory_entries(hostile_root, (relative,)),
                        )
                        candidate = (
                            relative if hostile_type != "descendant"
                            else relative + "/child"
                        )
                        self.assertEqual({candidate}, _p_v2_path_violations((candidate,)))
                        self.assertEqual(
                            set(),
                            _p_v2_path_violations((
                                "docs/v3/finished-project-lifecycle-sibling/"
                                + Path(relative).name,
                            )),
                        )
        for root in P_V2_FORBIDDEN_ROOTS:
            for hostile_type in ("regular", "symlink", "descendant"):
                with self.subTest(root=root, hostile_type=hostile_type):
                    candidate = root if hostile_type != "descendant" else root + "/new.py"
                    self.assertEqual({candidate}, _p_v2_path_violations((candidate,)))
                    self.assertEqual(set(), _p_v2_path_violations((root + "-sibling",)))
        lifecycle_root = P_V2_FORBIDDEN_ROOTS[0]
        for hostile_type in ("regular", "symlink", "descendant"):
            with self.subTest(lifecycle_root_type=hostile_type):
                with tempfile.TemporaryDirectory() as directory:
                    hostile_root = Path(directory)
                    path = hostile_root / lifecycle_root
                    path.parent.mkdir(parents=True)
                    if hostile_type == "regular":
                        path.write_bytes(b"unknown lifecycle entry\n")
                    elif hostile_type == "symlink":
                        path.symlink_to("missing-lifecycle-root")
                    else:
                        path.mkdir()
                        (path / "unknown.bin").write_bytes(b"unknown lifecycle entry\n")
                    self.assertEqual(
                        {lifecycle_root},
                        _present_directory_entries(hostile_root, (lifecycle_root,)),
                    )
        self.assertFalse(
            os.path.lexists(ROOT / lifecycle_root),
            "the entire v2 lifecycle prefix must be absent from the worktree",
        )
        present = _present_directory_entries(
            ROOT, Q05_V2_FORBIDDEN_LIFECYCLE_PATHS,
        )
        tracked = _git("ls-files", "-z")
        self.assertEqual(0, tracked.returncode, tracked.stderr)
        tracked_paths = {
            item for item in tracked.stdout.split("\0") if item
        }
        tree = _git("ls-tree", "-r", "--name-only", "HEAD")
        self.assertEqual(0, tree.returncode, tree.stderr)
        tree_paths = set(tree.stdout.splitlines())
        self.assertEqual(set(), _p_v2_path_violations(tracked_paths))
        self.assertEqual(set(), _p_v2_path_violations(tree_paths))
        for relative in Q05_V2_FORBIDDEN_LIFECYCLE_PATHS:
            with self.subTest(path=relative):
                self.assertNotIn(relative, present, relative)
                self.assertNotEqual(
                    0, _git("ls-files", "--error-unmatch", "--", relative).returncode,
                )
                self.assertNotIn(relative, tree_paths)

        html_text = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        catalog_paths = set(re.findall(r'data-file-path="([^"]+)"', html_text))
        self.assertEqual(set(), _p_v2_path_violations(catalog_paths))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            set(), _p_v2_path_violations(set(_manifest_strings(manifest))),
        )

    def test_p_phase_manifest_tracks_exact8_and_only_git_public_support(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(expected_p_manifest(), manifest)
        self.assertEqual(expected_p_manifest_payload(), MANIFEST.read_bytes())
        tracked_support = set(manifest["tracked_support"])
        self.assertEqual(99, len(P_FINAL_TRACKED_SUPPORT_PATHS))
        self.assertEqual(set(), p_manifest_support_violations(manifest))
        swapped = json.loads(json.dumps(manifest))
        removed = P_FINAL_TRACKED_SUPPORT_PATHS[0]
        swapped["tracked_support"].remove(removed)
        swapped["tracked_support"].append(P_UNEXPECTED_TRACKED_SUPPORT)
        self.assertEqual(
            {removed, P_UNEXPECTED_TRACKED_SUPPORT},
            p_manifest_support_violations(swapped),
            "same-count replacement by another safe tracked file must fail",
        )
        self.assertNotIn("USER_MANUAL.md", tracked_support)
        self.assertEqual(
            set(Q01_PUBLIC_DOCUMENT_PATHS),
            tracked_support.intersection(Q01_PUBLIC_DOCUMENT_PATHS),
        )
        for relative in sorted(tracked_support):
            with self.subTest(path=relative):
                self.assertEqual(
                    0, _git("ls-files", "--error-unmatch", "--", relative).returncode,
                    f"tracked_support is absent from Git: {relative}",
                )
                self.assertEqual(
                    1, _git("check-ignore", "--no-index", "--quiet", "--", relative).returncode,
                    f"tracked_support is ignored: {relative}",
                )

    def test_p_phase_static_documents_and_html_seed_are_literal(self):
        for relative, expected_hash in P_PHASE_STATIC_TARGET_SHA256.items():
            with self.subTest(path=relative):
                path = ROOT / relative
                metadata = path.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode), relative)
                self.assertEqual(0o644, stat.S_IMODE(metadata.st_mode), relative)
                if relative in P_CAPSULE_DOCUMENT_APPEND:
                    source = _canonical_git(
                        ROOT, "show", f"{S_COMMIT}:{relative}",
                    )
                    self.assertEqual(0, source.returncode, source.stderr)
                    expected_size, expected_source_hash = P_CAPSULE_DOCUMENT_SOURCE[relative]
                    self.assertEqual(expected_size, len(source.stdout))
                    self.assertEqual(
                        expected_source_hash,
                        hashlib.sha256(source.stdout).hexdigest(),
                    )
                    anchor, prior_insert = P_PRECAPSULE_DOCUMENT_INSERT[relative]
                    self.assertEqual(1, source.stdout.count(anchor.encode("utf-8")))
                    precapsule = source.stdout.replace(
                        anchor.encode("utf-8"),
                        (anchor + prior_insert).encode("utf-8"),
                    )
                    precapsule_size, precapsule_hash = P_PRECAPSULE_DOCUMENT_SOURCE[relative]
                    self.assertEqual(precapsule_size, len(precapsule))
                    self.assertEqual(precapsule_hash, hashlib.sha256(precapsule).hexdigest())
                    reviewed = precapsule + P_CAPSULE_DOCUMENT_APPEND[relative].encode(
                        "utf-8"
                    )
                    self.assertEqual(P_CAPSULE_DOCUMENT_TARGET_SIZE[relative], len(reviewed))
                    self.assertEqual(expected_hash, hashlib.sha256(reviewed).hexdigest())
                    self.assertEqual(reviewed, path.read_bytes())
                self.assertEqual(
                    expected_hash, hashlib.sha256(path.read_bytes()).hexdigest(),
                )
        seed = expected_p_html_static_seed()
        target = (ROOT / "user-manual.html").read_bytes()
        self.assertEqual(P_HTML_FINAL_SIZE, len(target))
        self.assertEqual(P_HTML_FINAL_SHA256, hashlib.sha256(target).hexdigest())
        self.assertNotEqual(seed, target)

    def test_p_public_markdown_links_resolve_only_to_tracked_regular_files(self):
        synthetic = {
            "docs/source.md": ("100644", b"# Source\n"),
            "docs/target.md": ("100644", b"# Exact Heading\n"),
        }
        _assert_local_markdown_links(
            "docs/source.md", b"[valid](target.md#exact-heading)\n", synthetic,
        )
        for hostile in (
            b"[missing](ignored.md)\n",
            b"[escape](../../outside.md)\n",
            b"[fragment](target.md#missing-heading)\n",
        ):
            with self.subTest(hostile=hostile):
                with self.assertRaises(AssertionError):
                    _assert_local_markdown_links("docs/source.md", hostile, synthetic)
        nonregular = dict(synthetic)
        nonregular["docs/target.md"] = ("120000", b"elsewhere.md")
        with self.assertRaises(AssertionError):
            _assert_local_markdown_links(
                "docs/source.md", b"[nonregular](target.md)\n", nonregular,
            )

        records = _tree_blob_records()
        sources = {
            relative for relative in records
            if (relative.startswith("docs/") and relative.endswith(".md"))
        }
        sources.update((
            ".github/README.md", "PUBLIC_REPOSITORY.md", "infra/docker/README.md",
        ))
        self.assertTrue(set(Q01_PUBLIC_DOCUMENT_PATHS).issubset(sources))
        for relative in sorted(sources):
            with self.subTest(source=relative):
                self.assertIn(relative, records)
                self.assertEqual("100644", records[relative][0])
                _assert_local_markdown_links(relative, records[relative][1], records)


if __name__ == "__main__":
    unittest.main()
