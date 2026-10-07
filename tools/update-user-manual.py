#!/usr/bin/env python3
"""Generate the exhaustive file and script reference in user-manual.html."""

from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import html
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import warnings


ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "user-manual.html"
FILE_BEGIN = "        <!-- BEGIN GENERATED USER MANUAL FILE CATALOG -->"
FILE_END = "        <!-- END GENERATED USER MANUAL FILE CATALOG -->"
SCRIPT_BEGIN = "        <!-- BEGIN GENERATED USER MANUAL SCRIPT REFERENCE -->"
SCRIPT_END = "        <!-- END GENERATED USER MANUAL SCRIPT REFERENCE -->"
SCRIPT_SUFFIXES = {".py", ".sh", ".cgi"}
UNINSTALLED_RUNTIME_COMPONENTS = frozenset({
    "monitor/issue_tracker_manual_channel.py",
    "monitor/issue_tracker_manual_listener.py",
    "monitor/issue-tracker-control.cgi",
})
REQ7_ONLINE_PRIMITIVE_LIBRARIES = frozenset({
    "monitor/issue_tracker_credential_shape.py",
    "monitor/issue_tracker_online_cells.py",
    "monitor/issue_tracker_online_nv_ids.py",
    "monitor/issue_tracker_online_rows.py",
})

REQ7_READ_ONLY_LIBRARIES = frozenset({
    "monitor/issue_tracker_ib_per_key_source.py",
    "monitor/issue_tracker_per_key_source.py",
    "monitor/issue_tracker_switch_per_key_source.py",
    "monitor/issue_tracker_receipt_snapshot.py",
})

REQ7_CONTROLLED_TRANSPORT_LIBRARIES = frozenset({
    "monitor/issue_tracker_sdk_authentication.py",
    "monitor/issue_tracker_tls_inputs.py",
    "monitor/issue_tracker_attempt_supervision.py",
    "monitor/issue_tracker_sheets_read_plan.py",
    "monitor/issue_tracker_sheets_read_decode.py",
    "monitor/issue_tracker_online_whitelist_read.py",
    "monitor/issue_tracker_mutation_rejection.py",
    "monitor/issue_tracker_attempt_journal.py",
    "monitor/issue_tracker_metadata_capacity.py",
    "monitor/issue_tracker_send_unit.py",
    "monitor/issue_tracker_send_intent.py",
})

RUNTIME_PATTERNS = (
    (
        "DAY0-Prepare/<project>/",
        "项目部署输入与项目级生成结果。01-global、devices/subnet CSV、P2P 和策略是输入；"
        "99-output-*、marker、receipt 与 latest 链接由事务生成，禁止手工拼接。",
    ),
    (
        "DAY0-Prepare/dumps/*",
        "tar-for-upload 生成的私有上传归档。按项目、时间、size 和 SHA-256 识别；旧包不能因文件名相近就复用。",
    ),
    (
        "image/*",
        "共享交换机 OS、UFM、NetQ 等大制品。真实 payload 与项目根空占位不同，必须按平台、版本、size、header 和 SHA-256 管理。",
    ),
    (
        "apps/ubuntu-24.04/<arch>/",
        "Ubuntu 24.04 离线 APT 仓库，按 amd64/arm64 分架构；repository.meta、Packages、Packages.gz 和依赖闭包必须一致。",
    ),
    (
        "outputs/*",
        "本机生成的交付表格、审计报告和 review evidence。它们用于人工交付或复核，不是 live /var/www/html 的部署输入。",
    ),
    (
        "download/*",
        "管理服务器回收的 download bundle 暂存区。只能交给 import-from-download.py 检查，不能手工解压覆盖项目。",
    ),
    (
        "package-imports/*",
        "download 导入后的 review 快照和 import report。保留来源身份，用于比较；不能直接成为生产发布根。",
    ),
    (
        "firmware/*",
        "交换机/平台固件 payload。默认不随源码同步；只有明确场景、设备族和受信摘要时才通过制品流程交付。",
    ),
    (
        "monitor/status/*",
        "采集 worker、持续任务、冷却、请求队列与状态 JSON。由锁和 worker 管理；浏览器刷新不会主动重采设备。",
    ),
    (
        "Finished-projects/*",
        "V3-dev 拟议的只读 finished record。保存生产全量项目 bundle、比较报告和 checksum；V2 load/upload 不得把它当输入。",
    ),
)

TOP_LEVEL_PURPOSE = {
    ".github": "GitHub CI、公开仓库维护与贡献说明",
    "DAY0-Prepare": "项目创建、输入校验、统一 load、监控与 unload 生命周期",
    "docs": "架构、部署、运维、参考、验证与 V3-dev 设计文档",
    "ethernet": "Ethernet 拓扑数据、交换机信息与链路采集",
    "examples": "不含客户秘密的公开项目示例",
    "Finished-projects": "V3-dev finished project 只读记录入口",
    "infiniband": "InfiniBand 采集、分析、初始化与升级",
    "infra": "Native 基础设施与 Docker/Supervisor 运行时",
    "monitor": "Switch/Link/ZTP 网页、CGI、worker 与状态发布",
    "nvlink": "NVLink/NVOS 采集和 bring-up 数据",
    "test_cases": "direct、workflow、治理、真机计划与批准状态测试",
    "tools": "跨主机打包、同步、导入、诊断、制品与分析工具",
    "ztp": "设备 bootstrap、配置生成、DHCP、手工 ZTP、备份和运行态辅助",
}

FILE_PURPOSE_OVERRIDES = {
    ".dockerignore": "Docker 构建上下文排除合同，防止项目数据、测试、秘密和运行输出进入镜像。",
    ".gitattributes": "Git 文本属性和换行规范；不承担秘密脱敏或加密。",
    ".gitignore": "公开仓库边界，隔离客户项目、生成物、运行状态、大制品和本机缓存。",
    "AGENTS.md": "仓库级测试治理合同，规定 tests-first、direct/workflow、manifest、full proof 与真机证据要求。",
    "README.md": "仓库首页与受支持入口索引，帮助用户先选择 Native 或 Docker 生命周期。",
    "user-manual.html": "可离线打开并随 upload/sync 发布的版本化网页用户手册。",
    "index.html": "HTTP 文档入口页，链接 Switch Status、ZTP Status 与 User Manual。",
    "PUBLIC_REPOSITORY.md": "公开仓库内容、敏感信息和发布边界说明。",
    "SECURITY.md": "安全报告、凭据、制品和漏洞处理要求。",
    "requirements-dev.txt": "开发和测试依赖清单，不是管理服务器运行时安装清单。",
    "test_cases/script_test_manifest.json": "生产脚本到 direct 测试、workflow 和 canonical target 的影响矩阵。",
    "test_cases/script_test_approved_hashes.json": "正式 runner 成功后原子更新的批准字节身份；禁止手工编辑。",
    "test_cases/REAL_ENVIRONMENT.md": "无法在本机安全自动化的 VM、AIR、Docker、服务和物理设备验收案例。",
    "test_cases/CASE_TEMPLATE.md": "新增真机/破坏性验证案例时必须填写的证据模板。",
    "infra/docker/Dockerfile": "Ubuntu 24.04 HTTP ZTP 容器镜像定义，安装运行依赖并固定镜像合同。",
    "infra/docker/compose.yaml": "Docker Compose 表达的容器用户、网络、bind、tmpfs、capability 和 health 合同。",
    "infra/docker/runtime-contract.json": "Docker 容器运行身份、路径、服务和安全设置的机器可读合同。",
    "infra/docker/supervisord.conf": "容器内 Supervisor 程序、依赖顺序、日志与自动重启配置。",
    "infra/docker/apache-ztp.conf": "容器 Apache 虚拟主机、CGI 与公开/私有路径边界。",
    "infra/docker/container.env.example": "Docker runtime 配置示例；复制后由 init 生成受保护的实际配置。",
}

OPERATOR_EXAMPLES = {
    "DAY0-Prepare/01-a-setup.py": "python3 -B DAY0-Prepare/01-a-setup.py --list-projects",
    "DAY0-Prepare/02-unsetup.py": "sudo python3 -B DAY0-Prepare/02-unsetup.py <project> --dry-run",
    "DAY0-Prepare/11-load.py": "python3 -B DAY0-Prepare/11-load.py DAY0-Prepare/<project> --host-role=workstation --prod --switch eth",
    "DAY0-Prepare/12-ztp-monitor.py": "python3 -B DAY0-Prepare/12-ztp-monitor.py <project> --watch 30 --type prod",
    "DAY0-Prepare/13-unload.py": "sudo python3 -B DAY0-Prepare/13-unload.py <project> --dry-run",
    "tools/tar-for-upload.py": "python3 -B tools/tar-for-upload.py DAY0-Prepare/<project> user@server --runtime native --deploy --exclude-apps",
    "tools/deploy-upload-archive.py": "sudo python3 -B tools/deploy-upload-archive.py /tmp/<upload.tar.gz> --verify-only",
    "tools/sync-code.py": "python3 -B tools/sync-code.py DAY0-Prepare/<project> user@server --runtime native",
    "tools/tar-for-download.py": "sudo python3 -B tools/tar-for-download.py <project>",
    "tools/import-from-download.py": "python3 -B tools/import-from-download.py ~/Downloads/<bundle.tar.gz> --review-only",
    "tools/collect-ztp-diagnostics.py": "sudo python3 -B tools/collect-ztp-diagnostics.py -p <project> --prod",
    "tools/password-update.py": "python3 -B tools/password-update.py DAY0-Prepare/<project> --platform all --dry-run",
    "tools/package-project-image.py": "python3 -B tools/package-project-image.py build <upload.tar.gz> --base-image <image-id> --output <dir>",
    "tools/package-shared-artifacts.py": "python3 -B tools/package-shared-artifacts.py <project> --switch eth --output <dir>",
    "tools/deploy-shared-artifacts.py": "sudo python3 -B tools/deploy-shared-artifacts.py <bundle.tar> --verify-only",
    "infra/check_infra.py": "python3 -B infra/check_infra.py --host <management-server>",
    "infra/deploy_infra.py": "python3 -B infra/deploy_infra.py --help",
    "infra/infra-setup.sh": "sudo bash infra/infra-setup.sh --help",
    "infra/infra-teardown.sh": "sudo bash infra/infra-teardown.sh --help",
    "infra/docker/deploy.sh": "sudo ./infra/docker/deploy.sh doctor",
    "ztp/manual-ztp.py": "sudo python3 -B ztp/manual-ztp.py <device> -p <project> --prod",
    "ztp/manual-reset.py": "sudo python3 -B ztp/manual-reset.py --help",
    "ztp/backup/yaml-collect.py": "sudo python3 -B ztp/backup/yaml-collect.py --prod",
    "test_cases/run_related_tests.py": "PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B test_cases/run_related_tests.py -v",
    "test_cases/run_vm_validation.py": "sudo python3 -B test_cases/run_vm_validation.py <project> --full-systemd",
}


def repository_inventory(root: Path) -> tuple[str, ...]:
    """Return the deterministic Git tracked + untracked/nonignored inventory."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    paths = result.stdout.decode("utf-8").split("\0")
    inventory = tuple(sorted(path for path in paths if path))
    for relative in inventory:
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise RuntimeError(f"unsafe Git inventory path: {relative!r}")
    return inventory


def source_summary(path: Path) -> str | None:
    """Extract a short checked-in title/docstring without reading binary payloads."""
    if path.is_symlink():
        return f"相对软链接入口，canonical target 为 {os.readlink(path)}。"
    suffix = path.suffix.lower()
    if suffix not in {".py", ".sh", ".cgi", ".md", ".txt"}:
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if suffix in {".py", ".cgi"}:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                warnings.simplefilter("ignore", SyntaxWarning)
                module = ast.parse(text)
        except SyntaxError:
            module = None
        if module is not None:
            doc = ast.get_docstring(module, clean=True)
            if doc:
                return doc.splitlines()[0].strip().rstrip(".。") + "。"
    if suffix in {".md", ".txt"}:
        for line in text.splitlines():
            title = line.strip().lstrip("#").strip()
            if title and not title.startswith(("<!--", "```")):
                return f"文档：{title.rstrip('.。')}。"
    for line in text.splitlines()[:40]:
        stripped = line.strip()
        if stripped.startswith("#") and not stripped.startswith("#!"):
            summary = stripped.lstrip("#").strip()
            if summary:
                return summary.rstrip(".。") + "。"
    return None


def file_category(relative: str) -> str:
    path = Path(relative)
    suffix = path.suffix.lower()
    if suffix in SCRIPT_SUFFIXES:
        return "脚本/程序"
    if path.name.startswith("README") or suffix == ".md":
        return "文档"
    if suffix in {".yaml", ".yml", ".j2", ".nv", ".conf"}:
        return "配置/模板"
    if suffix in {".json", ".csv", ".xlsx", ".log"}:
        return "数据/合同"
    if suffix in {".html"}:
        return "Web 页面"
    if suffix in {".bin", ".tar", ".gz", ".cab", ".vme", ".qcow2"}:
        return "制品/占位"
    if path.name in {"Dockerfile", ".dockerignore", ".gitignore", ".gitattributes"}:
        return "构建/仓库配置"
    return "仓库支持文件"


def generic_file_purpose(relative: str) -> str:
    path = Path(relative)
    name = path.name
    suffix = path.suffix.lower()
    top = path.parts[0]
    area = TOP_LEVEL_PURPOSE.get(top, "HTTP ZTP 仓库根级支持")
    if name == ".gitkeep":
        return f"保留 {path.parent.as_posix()} 空目录结构；不代表运行数据或发布成功。"
    if suffix == ".j2":
        role = path.stem.replace("_", " ").replace("-", " ")
        return f"Cumulus NVUE Jinja 模板片段，负责 {role} 角色或共享配置块，由统一生成器渲染。"
    if suffix in {".yaml", ".yml", ".nv", ".conf"}:
        return f"{area}使用的声明式配置或模板；由所属模块校验后消费，不能脱离对应事务随意覆盖。"
    if suffix == ".json":
        return f"{area}使用的机器可读合同、状态或夹具；字段身份由生产脚本或测试严格验证。"
    if suffix == ".csv":
        return f"{area}使用的表格输入、映射或测试夹具；保留表头、类型和来源语义。"
    if suffix == ".log":
        return f"{area}使用的受管日志/输入夹具；是否可编辑取决于所属 README 与生成流程。"
    if suffix == ".xlsx":
        return f"{area}使用的 Excel 输入或空模板；正式项目源需要经过 parser、图片剥离和摘要校验。"
    if suffix in {".bin", ".cab", ".vme", ".tar", ".gz", ".qcow2"}:
        return f"{area}使用的二进制制品或受控空占位；不能仅凭文件名判断为可部署 payload。"
    if suffix == ".html":
        return f"{area}的本地/HTTP 页面；由相应生成器或文档流程维护并接受链接与发布测试。"
    return f"属于“{area}”的 {name}；具体边界由当前文件、已跟踪的上层入口和测试合同共同约束。"


def file_responsibility(relative: str) -> str:
    path = Path(relative)
    if path.parts[0] == "test_cases":
        return "开发者维护；测试断言必须独立评审，批准 ledger 仅由正式 runner 成功后更新。"
    if path.parts[0] == "docs" or path.name.startswith("README") or path.suffix == ".md":
        return "文档维护者随行为变更同步更新；生成索引不得手工改写生成块。"
    if ".gitkeep" == path.name:
        return "目录骨架文件；保留为空，不写运行数据。"
    if "template" in path.parts or path.parts[0] == "examples":
        return "模板/示例维护者修改；真实项目和生成输出不得反向覆盖模板。"
    if path.parts[0] in {"DAY0-Prepare", "monitor", "ztp"}:
        return "项目输入由项目维护者编辑；发布链接、receipt、状态和输出只允许对应事务/worker 生成。"
    if path.parts[0] in {"infra", "tools", "ethernet", "infiniband", "nvlink"}:
        return "代码维护者按 tests-first 修改；生产操作员只通过本文标记为可直接运行的入口调用。"
    return "仓库维护者按公开边界和测试治理修改；不得绕过 Git/manifest/发布检查。"


def render_file_catalog(root: Path, inventory: tuple[str, ...]) -> str:
    groups: dict[str, list[str]] = defaultdict(list)
    for relative in inventory:
        groups[Path(relative).parts[0]].append(relative)
    lines = [
        "        <div class=\"catalog-summary\">",
        f"          <span><strong>{len(inventory)}</strong> 个受维护文件</span>",
        f"          <span><strong>{len(groups)}</strong> 个根级分组</span>",
        "          <span>清单范围：Git tracked + untracked/nonignored</span>",
        "        </div>",
        "        <h4 id=\"v2-runtime-data\" data-nav-title=\"运行与大型数据目录\">被忽略的大型数据与运行目录</h4>",
        "        <table class=\"file-catalog\"><thead><tr><th>路径模式</th><th>作用与边界</th></tr></thead><tbody>",
    ]
    for pattern, description in RUNTIME_PATTERNS:
        lines.append(
            "          <tr data-path-pattern=\"{}\"><td><code>{}</code></td><td>{}</td></tr>".format(
                html.escape(pattern, quote=True), html.escape(pattern), html.escape(description)
            )
        )
    lines += [
        "        </tbody></table>",
        "        <h4 id=\"v2-maintained-files\" data-nav-title=\"受维护文件目录\">受维护文件逐项说明</h4>",
    ]
    for group in sorted(groups, key=lambda value: (value.startswith("."), value.lower())):
        members = groups[group]
        group_id = re.sub(r"[^a-z0-9]+", "-", group.lower()).strip("-")
        nav_attribute = ""
        if any("/" in relative for relative in members):
            nav_attribute = f' data-nav-title="{html.escape(group, quote=True)}/ 文件"'
        lines += [
            f"        <details id=\"v2-file-group-{group_id}\"{nav_attribute} class=\"catalog-group\">",
            f"          <summary><code>{html.escape(group)}/</code> — {len(members)} 个文件</summary>",
            "          <div><table class=\"file-catalog\"><thead><tr><th>文件</th><th>说明</th></tr></thead><tbody>",
        ]
        for relative in members:
            source = root / relative
            purpose = FILE_PURPOSE_OVERRIDES.get(relative) or source_summary(source) or generic_file_purpose(relative)
            category = file_category(relative)
            responsibility = file_responsibility(relative)
            lines.append(
                "            <tr data-file-path=\"{}\"><td><code>{}</code></td>"
                "<td><strong>类别：</strong>{}；<strong>作用：</strong>{} "
                "<strong>维护/生成责任：</strong>{}</td></tr>".format(
                    html.escape(relative, quote=True), html.escape(relative),
                    html.escape(category), html.escape(purpose), html.escape(responsibility),
                )
            )
        lines += ["          </tbody></table></div>", "        </details>"]
    return "\n".join(lines)


def script_options(path: Path) -> tuple[str, ...]:
    if path.is_symlink():
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ()
    options: list[str] = []
    if path.suffix.lower() in {".py", ".cgi"}:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "add_argument":
                    continue
                for argument in node.args:
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        if argument.value.startswith("-") and argument.value not in options:
                            options.append(argument.value)
    else:
        for option in re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", text):
            if option not in options:
                options.append(option)
    return tuple(options)


def is_python_main(path: Path) -> bool:
    if path.is_symlink() or path.suffix.lower() not in {".py", ".cgi"}:
        return False
    try:
        return '__name__ == "__main__"' in path.read_text(encoding="utf-8") or "__name__ == '__main__'" in path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False


def script_profile(root: Path, relative: str) -> dict[str, str]:
    path = Path(relative)
    source = root / relative
    purpose = source_summary(source) or generic_file_purpose(relative)
    top = path.parts[0]
    is_test = top == "test_cases"
    is_validation_entrypoint = relative in {
        "test_cases/run_related_tests.py",
        "test_cases/run_vm_validation.py",
    }
    is_validation_report_helper = relative == "test_cases/validation_unittest.py"
    is_library = (
        path.name == "__init__.py" or "/lib/" in f"/{relative}"
        or relative in REQ7_READ_ONLY_LIBRARIES
        or relative in REQ7_ONLINE_PRIMITIVE_LIBRARIES
        or relative == "monitor/issue_tracker_online_target.py"
        or relative == "tools/req7_dependency_contract.py"
        or relative in REQ7_CONTROLLED_TRANSPORT_LIBRARIES
        or (relative in UNINSTALLED_RUNTIME_COMPONENTS and path.suffix.lower() == ".py")
        or path.name in {
            "_package_common.py", "deployment_lock.py", "deployment_prewrite_guard.py",
            "project_contract.py", "ztp_service_runtime.py", "switch_collection_gate.py",
            "dhcp_runtime_inventory.py", "dynamic_air_inventory.py", "environment_probe.py",
            "nvue_normalizer.py", "config_sync_authority.py",
        }
    )
    is_cgi = path.suffix.lower() == ".cgi"
    is_uninstalled = relative in UNINSTALLED_RUNTIME_COMPONENTS
    is_worker = path.name.endswith("-worker.py") or path.name.endswith("_worker.py")
    is_docker_internal = relative.startswith("infra/docker/") and path.name != "deploy.sh"
    is_docker_operator = relative == "infra/docker/deploy.sh"
    is_bootstrap = relative.startswith("ztp/templates/") or path.name.startswith("ztp-bootstrap")
    is_alias = source.is_symlink()

    if is_validation_entrypoint:
        direct = "是；这是开发治理或只读验收入口，不是生产服务依赖。"
        if relative == "test_cases/run_related_tests.py":
            environment = "canonical 开发工作树；使用当前仓库 Python、平台身份和 /tmp 下的 pycache。"
            scenario = ("开发时选择受影响的 direct/workflow，或在正式 load 前签发并复核绑定当前字节的 full proof。"
                        "--validation-only 仅供 owner 授权的 AIR/prod 验证，非 dry-run，绝非最终生产发布许可。")
            prerequisite = ("工作树暂时冻结；manifest 映射完整；测试预期已独立评审；禁止手工修改批准 ledger。"
                            "AIR/prod 验证还须见证其他同 UID crontab 写者在安装、自动移除和 unsetup 各自整个读—改—写窗口保持静默。")
            syntax = "python3 -B test_cases/run_related_tests.py [options]"
            parameters = ", ".join(script_options(source))
            inputs = "当前生产脚本、测试、script_test_manifest.json、批准状态以及 Python/平台身份。"
            outputs = ("选测清单、unittest 结果和退出码；普通 related/full 成功后可按合同原子更新批准状态。"
                       "验证模式仍如实报告三项 FAIL，只签发与普通发布证明严格区分的验证证明。")
            success = ("普通模式要求零 failure/error；正式发布还必须让 --all 成功，并让普通 --check --require-full 返回 0。"
                       "--validation-only 只接受 ISSUE-0016 安装、自动移除、unsetup 的恰好三项原断言 FAIL，"
                       "无其他 failure/error/新增 skip；普通发布证明检查必须拒绝该验证证明。")
            recovery = "按首个失败区分实现、测试、夹具或平台问题；修复后完整重跑，禁止弱化断言或手改 ledger。"
        else:
            environment = "已完成 Native load 的 Ubuntu 管理服务器；full-systemd 需要读取 systemd、DHCP、Apache 和 HTTP 状态。"
            scenario = "load 完成后只读核对 release、source、服务、worker、DHCP 监听、HTTP 发布边界和项目 scope。"
            prerequisite = "目标项目已部署且身份明确；参数与实际 prod/air/mini 场景一致；测试脚本单独安全传入 VM。"
            syntax = "sudo python3 -B test_cases/run_vm_validation.py <project> [options]"
            parameters = ", ".join(script_options(source))
            inputs = "目标 VM 的项目、parent/child release、source receipt、运行配置、systemd 状态和可选 HTTP 响应。"
            outputs = "终端检查结果及可选 JSON 报告；工具只读，但主动 HTTP GET 会正常写 Apache access log。"
            success = "退出码 0，选择的 strict/full-systemd 检查全部通过；mock 或局部 HTTP 成功不能替代设备验收。"
            recovery = "保留 JSON/终端证据，在受支持的 load 流程修复根因后重跑；不要由验收器修改服务、NIC 或项目。"
        example = OPERATOR_EXAMPLES[relative]
    elif is_validation_report_helper:
        direct = "是，仅供开发验证；这是治理 runner 的内部全量发现助手，不是普通 unittest 测试模块或生产入口。"
        environment = "canonical 开发工作树；由 --validation-only 治理 runner 提供一次性报告路径和当前 Python 环境。"
        scenario = "对当前测试树做完整 unittest discovery，保留原始三项 FAIL 并产生精确机器可读报告。"
        prerequisite = "REPORT_PATH 必须是尚不存在的受控文件；只在授权的 AIR/prod 验证流程中解释其结果。"
        syntax = "python3 -B -m test_cases.validation_unittest REPORT_PATH [-v]"
        parameters = "必填 REPORT_PATH；可选 -v 输出详细测试结果。"
        inputs = "当前测试树及独立断言；由父治理 runner 校验报告身份，不从实现复制预期。"
        outputs = "标准 unittest 结果仍显示 FAIL；另将 tests_run、failures、errors、skipped 等写入机器可读 JSON 报告。"
        success = "仅精确 ISSUE-0016 三项已知 FAIL、无其他失败或新增跳过时返回 0；不签发普通发布证明。"
        recovery = "报告不精确或路径不安全时停止验证；保留原始 FAIL，勿改断言或手工修改批准 ledger。"
        example = "PYTHONPYCACHEPREFIX=/tmp/http-test-pyc python3 -B -m test_cases.validation_unittest REPORT_PATH"
    elif is_test:
        direct = "是，仅在开发/验证工作树运行；不得把 test_cases 作为生产服务依赖。"
        environment = "canonical 开发工作树；使用仓库 Python 和 /tmp 下的 pycache。"
        scenario = "修改相关生产行为后运行 direct/workflow 回归，或由 change-aware/full runner 选择。"
        prerequisite = "测试夹具完整、当前工作树已冻结；需要外部环境的案例只能使用 mock 或 REAL_ENVIRONMENT 计划。"
        module = relative.removesuffix(".py").replace("/", ".")
        syntax = f"python3 -B -m unittest -v {module}"
        parameters = "unittest 的模块、类或方法选择；正式治理另使用 run_related_tests.py。"
        inputs = "被测源码、独立固定夹具、manifest 以及必要的临时目录；预期值不得从实现生成。"
        outputs = "测试进度与退出码；普通 unittest 不签发批准证明，也不应修改生产数据。"
        success = "退出码 0，testsRun 与选择一致，零 failure/error；跳过项必须有明确理由。"
        recovery = "保留第一个失败和最小复现，判断实现/测试/夹具/平台原因；禁止弱化断言或手改 ledger。"
        example = f"PYTHONPYCACHEPREFIX=/tmp/http-test-pyc {syntax}"
    elif is_alias:
        target = os.readlink(source)
        direct = "否；这是兼容/平台发布别名，应使用其 canonical target 或上层统一入口。"
        environment = "与 canonical target 相同；路径存在是为了多 fabric/历史入口兼容。"
        scenario = "上层代码按别名路径发现模块时复用同一实现，保证行为和治理映射一致。"
        prerequisite = f"软链接必须保持相对、位于仓库内并解析到 {target}；manifest canonical 映射必须匹配。"
        syntax = f"由上层入口解析 {relative} -> {target}"
        parameters = "继承 canonical target；别名本身不定义独立参数。"
        inputs = "继承 canonical target 的输入，并保留调用方的 fabric/路径上下文。"
        outputs = "与 canonical target 相同；不得产生一份分叉实现或不同状态。"
        success = "链接身份、canonical target、direct test 和 workflow 映射全部一致。"
        recovery = "链接断裂或目标变化时停止发布；按 manifest 和 setup 合同修复，禁止复制文件替代链接。"
        example = f"readlink {relative}  # 预期解析到 {target}"
    elif is_library:
        direct = "否；这是共享库/安全边界，由其列出的生产入口导入。"
        environment = "随所属 Native、Docker、打包、监控或分析流程运行，不单独取得运行权限。"
        scenario = "上层入口需要路径校验、锁、解析、事务、状态投影或分析算法时调用。"
        prerequisite = "调用者已建立正确 root、权限、锁、输入身份和失败处理；不得绕过上层 preflight。"
        syntax = f"由上层 Python 模块导入 {relative} 中的公开函数/类"
        opts = script_options(source)
        parameters = "无受支持的独立 CLI" + (f"；源码中出现的内部选项包括 {', '.join(opts)}" if opts else "。")
        inputs = "调用者已验证的数据结构、文件描述符或路径；具体 schema 由模块 direct 测试锁定。"
        outputs = "返回值、受控异常或调用者事务内的状态变化；库自身不构成完整部署。"
        success = "调用者完成后置校验且整个上层事务提交；单个函数返回不等于部署成功。"
        recovery = "让异常向上层 fail closed；保留锁、marker 和原始输入证据，不在库外手工补写。"
        example = f"rg -n \"{path.stem}\" DAY0-Prepare infra monitor tools ztp  # 查找受支持调用者"
        if relative in REQ7_READ_ONLY_LIBRARIES:
            environment = "由受管 monitor worker/Stage L 状态流程导入；只读库不单独取得运行或写入权限。"
            scenario = "读取受保护的当前 K 窗口、逐键连续性或当前周期 C6 receipt 事实，供本地状态投影。"
            prerequisite = "调用者持有同一项目 owner 锁，并核对当前 K、周期顺序、来源身份和原始受保护证据；不可用时 fail closed。"
            inputs = "当前 K 链、受保护的已完成周期、Switch/ETH/IB 来源绑定或当前周期的 C6 INTENT/RECEIPT。"
            outputs = "只读逐键观察计数、最新业务值或周期绑定的本地 receipt 事实；不修补历史、不写源数据或在线项目。"
            success = "来源与周期复核完成，返回值仅供状态展示；不授予在线发布资格，不替代 C5/C6 或真机验收。"
            recovery = "证据缺失、顺序断裂、K 或来源身份变化时交由调用者 HOLD；保留原始证据，不伪造零值或手工补写 receipt。"
        if relative == "tools/req7_dependency_contract.py":
            scenario = "REQ7 C-14 公开依赖策略和精确锁校验；不导入 SDK、不安装、不访问网络或启用服务。"
            prerequisite = "调用方冻结受测源码；固定相对路径无链接、单链接普通文件、有界读取且名字/字节身份复核一致。"
            inputs = "infra/docker/req7-dependency-policy.json、requirements-req7-online.txt 及当前 Python 的已安装分发元数据。"
            outputs = "不可变策略/锁 SHA256、平台 wheel 清单与精确版本元数据身份，或脱敏拒绝；不写文件。"
            success = "仅表示公开依赖合同和元数据一致；不授予发送许可、不证明 Linux wheel 已执行、SDK 鉴权或整个 REQ7。"
            recovery = "缺包、版本/路径/架构/锁漂移时 fail closed；保留证据，不能自动安装、猜测依赖或手改批准 ledger。"
        if relative == "monitor/issue_tracker_online_target.py":
            scenario = "本地验证精确 JSON 字符串枚举及每次项目策略重核；不从配置推导白名单。"
            prerequisite = "纯函数只检查调用方提供的字节；真实文件权威必须另由固定路径 root held-FD 加载器建立，发送仍须完整准入与传输证明。"
            inputs = "有界原始白名单字节、schema v2 项目策略和可选旧目标绑定；不读取凭据或真实文件。"
            outputs = "纯内存精确目标/策略/枚举字节绑定或脱敏 HOLD；无文件修改、网络或发送许可。"
            success = "通过只表示本次纯校验一致，不授予发送资格，不证明凭据、文件来源、在线写入或整个 REQ7。"
            recovery = "空白名单、禁用、撤销或身份变化拒绝；保留来源证据，不重定向、不猜测授权。"
        if relative in REQ7_ONLINE_PRIMITIVE_LIBRARIES:
            scenario = "REQ7 本地输入与纯候选校验；不是在线发布入口，不启动服务。"
            prerequisite = "调用方另证来源、模板、目标、持久化预留和发送合同；本地测试不构成 Stage O 许可。"
            inputs = "已验证的来源行、typed userEnteredValue 精确矩形、所有保留序号／行预留；不会从局部差异重建未知发送单元。"
            outputs = "不可变字面单元格／序号／空闲行候选或 HOLD／CONFLICT；不发生文件修改或网络发送。"
            success = "通过仅表示本次候选校验一致，不授予发送资格，不证明原子提交、完整回执或整个 REQ7。"
            recovery = "占用、位移、歧义、容量耗尽或 UNKNOWN 拒绝；不覆盖人工／公式列、不回收预留、不伪造回滚。"
            if relative == "monitor/issue_tracker_credential_shape.py":
                prerequisite = "未来仅 root worker 调用固定路径 held-FD 读取；目录 root 0700、文件 root 0600、无链接；原生身份／RO bind 尚须单独验证。"
                inputs = "固定路径 /var/lib/http-ztp-container/service-account/cre.json 与 issue-tracker-spreadsheet-whitelist.json；无 argv／环境路径覆盖。"
                outputs = "单次 FD 字节解析的私有映射／精确枚举或脱敏 HOLD；不导入认证 SDK、不签名、不刷新令牌或打开网络。"
                success = "本地 fake held-FD 测试不授予发送资格，也不证明真机身份、SDK 认证、线上发布或整个 REQ7。"
                recovery = "身份、权限、大小、单读或名字绑定变化拒绝；不自动创建／修复文件，不向日志／异常输出凭据。"
        if relative == "monitor/issue_tracker_sdk_authentication.py":
            direct = "否；这是未安装、未启用的公共 SDK 桥接库，不是操作员 CLI。"
            environment = "当前未安装、未启用；未来仅由受管 root worker 导入，当前仅做隔离开发验证。"
            scenario = "用公共 SDK 构造固定 scope 凭据并通过一次回调适配器刷新令牌；不使用 ADC、委托或自签 access JWT。"
            prerequisite = "SDK 导入前通过精确依赖校验；凭据由 C11 单次固定路径 held-FD 读取；受控 CA、完整传输、监督预算及发送准入须另证。"
            syntax = "开发测试导入公开函数；无已安装操作员入口。"
            parameters = "无独立 CLI，也无凭据路径、目标 host/port、代理或 CA 覆盖参数。"
            inputs = "单次 held-FD 验证后的私有凭据映射和受控请求单元；固定 Sheets scope。"
            outputs = "私有不可变 token/到期时间或脱敏 HOLD；不是在线写入许可。"
            success = "本地 fake/direct/workflow 通过不授予发送资格，不证明完整传输、线上可用或整个 REQ7。"
            recovery = "非 200、不完整响应、异常或第二次回调拒绝；不允许 SDK 隐藏重试，不向日志或异常输出凭据。"
            example = "python3 -B -m unittest -v test_cases.test_req7_sdk_authentication  # 仅开发测试"
        elif relative in REQ7_CONTROLLED_TRANSPORT_LIBRARIES:
            direct = "否；这是未安装、未启用的受控传输／只读库，不是操作员 CLI 或在线发布入口。"
            environment = "当前未安装、未启用；仅在本地隔离候选中验证，不启动受管服务。"
            prerequisite = "未来发送须受固定 root launcher、精确部署 Python/SSL/CA 身份、完整总预算监督和每次新鲜准入支配；本地对象不是授权。"
            syntax = "开发测试导入函数；无已安装操作员入口。"
            parameters = "无独立 CLI；不提供目标 URL、代理、凭据路径、CA 或重试覆盖开关。"
            inputs = "严格不可变请求形状、受控响应或本案隔离子进程；不会从旧成功或调用方声明推导发送资格。"
            outputs = "必要的本地只读观察、不可变 HTTP 字节或已确认／未确认终止状态；不是完整远程结果。"
            success = "本地 direct/workflow 通过不授予在线发送或写入资格，不证明部署环境、完整准入或整个 REQ7。"
            recovery = "任何身份、坐标、响应或终止不确定时 HOLD；保留锁和证据，不刷新重放、不伪造 APPLIED。"
            if relative == "monitor/issue_tracker_tls_inputs.py":
                scenario = "验证固定 held-FD 受控 CA、原生 TLS/hostname 与一次 OAuth POST／Sheets GET／固定只读 metadata search POST；非 200 和重定向拒绝。"
                inputs = "固定 /etc/ssl/certs/ca-certificates.crt 的持有字节及受控请求；不加载环境信任目录或代理。"
                example = "python3 -B -m unittest -v test_cases.test_req7_tls_inputs  # 仅开发测试"
            elif relative == "monitor/issue_tracker_attempt_supervision.py":
                scenario = "监督调用方已经启动的自有隔离子进程；固定单调总预算覆盖启动、DNS 和慢速读取。"
                inputs = "固定受审 launcher 创建的 Popen、启动前单调时钟和类型；子进程须继承已持有的 spreadsheet 锁。"
                recovery = "未确认终止时 HOLD／升级处置，绝不解锁重发；不接受任意 PID 或启动命令，不清除外来进程。"
                example = "python3 -B -m unittest -v test_cases.test_req7_attempt_supervision  # 仅开发测试"
            elif relative == "monitor/issue_tracker_sheets_read_plan.py":
                scenario = "构造精确发现列、单行矩形、十四表身份及四张 tracker 表头的纯 Sheets GET 请求；不接收任意 A1 范围，不读取宽列或自动分页。"
                inputs = "typed 目标绑定、私有 token、固定业务 sheet 名和有限行坐标；对象纪律不证明活的来源或准入。"
                example = "python3 -B -m unittest -v test_cases.test_req7_sheets_read_plan  # 仅开发测试"
            elif relative == "monitor/issue_tracker_online_whitelist_read.py":
                scenario = "完整有界 Whitelist 只读结果必须匹配冻结本地规则；不得重筛已应用的本地 manifest。"
                inputs = "固定六列、原始文本、实际 sheet 行容量和冻结本地 Whitelist；容量超过 10000 行拒绝，不分页掩盖截断。"
                recovery = "缺失／不可读、规则不同、公式或容量超限时 HOLD；不修改本地快照、不从比较成功推导新鲜准入。"
                example = "python3 -B -m unittest -v test_cases.test_req7_online_whitelist_read  # 仅开发测试"
            elif relative == "monitor/issue_tracker_attempt_journal.py":
                scenario = "在现有本地 owner 锁内持久保存不可变字节及六次意图计数；重启／进程死亡不重置 UNKNOWN。"
                inputs = "ACTIVE 本地 writer token、单元标识和不超过 1 MiB 的冻结字节；它们不是合格 Sheets batch 或发送能力。"
                recovery = "计数耗尽、部分／外来文件、字节变化或 fsync 失败均 HOLD，保留证据；无清理、重置或新单元接管。"
                example = "python3 -B -m unittest -v test_cases.test_req7_attempt_journal  # 仅开发测试"
            elif relative == "monitor/issue_tracker_send_intent.py":
                scenario = "在实际本地 owner 内先持久保存非递归 ACTION-PREIMAGE 和 action/wire 摘要，再保存不可变 wire，最后记录 UNKNOWN 意图。"
                inputs = "ACTIVE C-6 token 与冻结单表组合；摘要一致不证明 protected 准入、跨项目 spreadsheet 锁或发送许可。"
                recovery = "旧 wire store、部分记录、篡改、位移、fsync 失败或计数耗尽时 HOLD；保留原像，不补建、不修复、不重置 UNKNOWN。"
                example = "python3 -B -m unittest -v test_cases.test_req7_send_intent  # 仅开发测试"
            elif relative == "monitor/issue_tracker_send_unit.py":
                scenario = "冻结单表业务变更、全部对应 History 与一个永久 fence；非递归 action_digest 绑定完整 outcome 和审计集合。"
                inputs = "同目标 family 的完整有序 manifest 操作与明确字面值／观察；身份、nonce、占用 ID 只被绑定，未证明准入。"
                recovery = "缺项、重复、坐标冲突、marker 投影碰撞或 1000 请求／1 MiB 上界越界均 HOLD；不分批、不换 ID；全 NOOP 时审计 pending。"
                example = "python3 -B -m unittest -v test_cases.test_req7_send_unit  # 仅开发测试"
            elif relative == "monitor/issue_tracker_metadata_capacity.py":
                scenario = "有界只读 metadata search；按各 sheet 与独立 spreadsheet 池核永久栅、enrollment、其他元数据及未决预留。"
                inputs = "同一目标的十四表身份、完整可见查询与显式预留；UTF-8 字节保守计量，不从不可见 PROJECT 元数据推导空池。"
                recovery = "溢出 STOP_CAPACITY，非溢出仍 VISIBLE_ONLY_UNPROVED／HOLD；不是发送许可，不清除预留、不回收栅、不承诺剩余天数。"
                example = "python3 -B -m unittest -v test_cases.test_req7_metadata_capacity  # 仅开发测试"
            elif relative == "monitor/issue_tracker_mutation_rejection.py":
                scenario = "只观察四类完整一致 HTTP/JSON 错误，其他情况 UNKNOWN；六次内的任一 UNKNOWN 不被后续拒绝清除。"
                inputs = "有界原始响应和完整性声明；它们不证明响应来自承载请求的原生连接，也不是 durable journal。"
                recovery = "不完整、格式不符、前次 UNKNOWN 均 HOLD；不允许重发，不清除预留或证明 APPLIED。"
                example = "python3 -B -m unittest -v test_cases.test_req7_mutation_rejection  # 仅开发测试"
            else:
                scenario = "按精确目标、sheetId 和坐标解码 userEnteredValue；保留原类型，分别核十四表身份和四张 row-2 表头的多行字面值。"
                inputs = "固定读取形状与完整有界 HTTP 200；不得用 formatted/effectiveValue 替代原值或用缺失 grid 制造空行。"
                example = "python3 -B -m unittest -v test_cases.test_req7_sheets_read_decode  # 仅开发测试"
        if is_uninstalled:
            direct = "否；这是未安装、未启用的库级接点，不是可直接运行的生产入口。"
            environment = "当前未安装、未启用；未来仅在经真机验收的受管 Linux 环境中按正确身份导入，不是操作员 CLI。"
            scenario = "仅供本地 direct/workflow 验证；未来受管 CGI/root worker 接入后才可处理手工请求。"
            prerequisite = "启用前须完成真机验收，并配置独占 CGI UID/GID、受保护 socket、独立 root launcher 和私有队列。"
            syntax = f"开发测试导入 {relative}；未来受管组件可按真机验收后的合同导入，当前无操作员 CLI。"
            success = "本地测试只证明库级接点行为；不构成服务已启动、CGI 已发布或生产可用的证据。"
            example = f"python3 -B -m unittest -v test_cases.test_{path.stem}  # 仅开发测试"
    elif is_cgi and is_uninstalled:
        direct = "否；这是未安装、未发布的 CGI 接点，不能作为当前可用的 HTTP 路由调用。"
        environment = "当前 Apache/Native/Docker 均未发布此路由；未来身份和服务生命周期仍待真机验证。"
        scenario = "仅在开发测试中验证 HTTP 边界与本地中继；不提供现行生产操作入口。"
        prerequisite = "启用前须完成真机验收，并为该路由配置独占 CGI UID/GID、受保护 Unix socket 和 root worker。"
        syntax = f"开发测试导入 {relative} 的 handle()/main() 并注入环境；当前无已安装 HTTP 调用方式。"
        parameters = "未来 HTTP method、Content-Length、字段和身份边界以 direct/workflow 测试为准；当前无操作员参数。"
        inputs = "开发测试中校验的有界 HTTP 请求；当前无生产请求入口。"
        outputs = "测试中仅向受保护 Unix socket 转发规范请求并返回受限 HTTP/JSON；CGI 自身不写队列或控制文件。"
        success = "本地测试验证失败关闭和中继协议；不证明 Apache 路由已发布或 root worker 已运行。"
        recovery = "未安装状态保持不可用；未来接入失败时保留证据并按真机计划回退，不手工补写私有队列。"
        example = "python3 -B -m unittest -v test_cases.test_issue_tracker_manual_channel  # 仅开发测试"
    elif is_cgi:
        direct = "否；由 Apache CGI 环境调用，不能在 shell 中伪造为生产成功。"
        environment = "Native Apache 或 Docker 容器 Apache，以受限请求方法和 www-data 权限运行。"
        scenario = "Switch/ZTP 页面提交手工收集、备份、持续任务或 manual-ZTP 控制请求。"
        prerequisite = "当前 release、CGI 发布边界、请求 schema、互斥/冷却锁和 worker 状态均有效。"
        syntax = f"由网页通过 HTTP 请求已发布的 {path.name} CGI；开发测试调用 main() 并注入环境。"
        parameters = "HTTP method、Content-Length、表单/JSON 字段和 CSRF/身份边界由对应测试固定。"
        inputs = "经过大小、编码、字段和状态机校验的 HTTP 请求；敏感字段不得进入 URL 或日志。"
        outputs = "HTTP 状态、JSON/文本响应以及受锁保护的 request/control 文件；不直接执行长任务。"
        success = "返回预期 HTTP/JSON，request 原子发布，worker 接收且没有越过冷却或互斥边界。"
        recovery = "根据响应 reason 和 worker 状态等待/重试；禁止手工编辑队列、锁或 PID 文件。"
        example = f"python3 -B -m unittest -v test_cases.test_monitor_stack_review  # 验证 {relative} 的 CGI 合同"
    elif is_docker_operator:
        direct = "生产否；当前仅允许在隔离 VM 按 REAL_ENVIRONMENT 计划执行 Docker 准入验证。"
        environment = "fresh 隔离 Docker 验证 VM；宿主 Apache/DHCP 禁用，rootful Docker、网络、端口和持久目录身份明确。"
        scenario = "验证容器 build/deploy/load/health/restart/unload/down 的实现合同；尚未取得成功端到端真机证据前不服务生产项目。"
        prerequisite = "当前源码 full gate、fresh image/upload、immutable identity、批准 runner、回滚和证据目录全部就绪；旧 artifact 一律 stale。"
        syntax = "bash infra/docker/deploy.sh --help；生产部署命令在 Docker 正式准入前不提供"
        parameters = ", ".join(script_options(source)) or "动作及参数以 --help 和隔离验证计划为准。"
        inputs = "fresh source manifest、upload、镜像、runtime config 和目标 VM 只读基线；不得复用历史 image ID。"
        outputs = "容器/image/CID/receipt/Supervisor/health/restart 证据；任何单项成功都不能单独构成生产准入。"
        success = "完整 VM 场景零失败、清理可恢复且独立 review 明确 GO；在此之前一律保持未准入。"
        recovery = "第一处失败立即停止，保存证据并回到 canonical 工作树 tests-first 修复；不操作生产 NIC/Netplan 或宿主服务。"
        example = "bash infra/docker/deploy.sh --help  # 只读查看；当前禁止作为已支持生产流程执行 deploy"
    elif is_worker or is_docker_internal or is_bootstrap:
        direct = "否；由 systemd、Supervisor、Docker entrypoint、浏览器控制面或设备 bootstrap 流程编排。"
        environment = (
            "所属 runtime 的受管用户、目录、网络和 capability 环境；以下 load 示例仅适用"
            "于 Native 管理服务器，Docker 仍由 deploy.sh 编排。"
        )
        scenario = "上层生命周期启动后执行后台采集、恢复、健康检查、配置应用或容器激活。"
        prerequisite = "上层入口已验证 release/receipt、路径类型、权限、锁和依赖服务；当前身份必须匹配。"
        syntax = f"由所属上层配置调用 {relative}；人工只使用对应 deploy/load/status/CGI 入口"
        opts = script_options(source)
        parameters = ", ".join(opts) if opts else "无公开操作员参数；参数由上层配置固定。"
        inputs = "已发布 release、受管配置/请求、日志或设备端 HTTP 资源。"
        outputs = "受管状态、日志、配置、health 或设备应用回执；所有写入应留在规定根目录。"
        success = "上层 health/status、PID/退出码、receipt 与输出身份同时满足合同。"
        recovery = "使用上层 status/health/logs 或事务恢复；不要脱离 supervisor/systemd 手工重启子进程。"
        example = (
            "sudo ./infra/docker/deploy.sh status"
            if relative.startswith("infra/docker/")
            else "python3 -B DAY0-Prepare/11-load.py DAY0-Prepare/<project> --host-role=management-server --prod"
        )
    else:
        direct = "是，但仅在本节场景和权限边界内；先运行 --help、dry-run、verify-only、doctor 或 status（若提供）。"
        environment = {
            "DAY0-Prepare": "canonical 项目电脑、Native 管理服务器，或由 Docker hostctl 在容器内调用。",
            "tools": "通常在 canonical 项目电脑；deploy/import/diagnostic 类按说明在目标服务器运行。",
            "infra": "项目电脑或 Linux 管理服务器；Native 与 Docker 后端不得混用。",
            "monitor": "管理服务器/容器的受管 monitor 根；生成器可在开发工作树验证。",
            "ztp": "管理服务器、容器或设备 bootstrap 环境，取决于脚本职责。",
            "ethernet": "管理服务器的 Ethernet 采集/分析环境。",
            "infiniband": "具备对应 NVIDIA/Mellanox 工具和设备访问的受控 bring-up 主机。",
            "nvlink": "具备 NVOS/NVLink 设备访问的受控 bring-up 主机。",
        }.get(top, "canonical 工作树或所属模块 README 指定的受控主机。")
        scenario = f"执行“{TOP_LEVEL_PURPOSE.get(top, 'HTTP ZTP 维护')}”中的明确操作步骤；不要把一次子步骤当作完整发布。"
        prerequisite = "项目、设备范围、运行后端、权限和输入身份已确认；任何 destructive/remote 动作先完成本地 proof 和只读检查。"
        if source.suffix.lower() == ".sh":
            syntax = f"bash {relative} [options]"
        else:
            syntax = f"python3 -B {relative} [options]"
        opts = script_options(source)
        parameters = ", ".join(opts) if opts else "该入口没有可静态提取的长选项；以文件头、所属 README 和实际 --help 为准。"
        inputs = "所属场景的项目输入、设备清单、受信 archive/制品或运行日志；正式写入前必须完成 preflight。"
        outputs = "命令日志、退出码以及该脚本声明的配置、报告、归档或运行状态；输出需按 receipt/SHA/health 复核。"
        success = "退出码 0，并且脚本打印的后置检查、receipt、状态或生成清单全部通过；仅生成文件不等于部署完成。"
        recovery = "在第一个失败处停止，保留原日志和 marker；按脚本给出的 NEXT/README 修复后从完整受支持入口重试。"
        example = OPERATOR_EXAMPLES.get(relative)
        if relative == "DAY0-Prepare/11-load.py":
            environment = (
                "以下示例仅在 canonical 项目电脑运行；Linux 项目电脑须声明 "
                "--host-role=workstation。Native 管理服务器须另用 "
                "--host-role=management-server；Docker 由 hostctl 编排。"
            )
        if not example:
            if is_python_main(source):
                example = f"python3 -B {relative} --help"
            elif source.suffix.lower() == ".sh":
                example = f"sed -n '1,120p' {relative}  # 先读文件头 Usage/安全边界，再由所属流程调用"
            else:
                example = f"python3 -B -m py_compile {relative}  # 仅语法验证；实际运行由上层流程负责"
    return {
        "purpose": purpose,
        "direct": direct,
        "environment": environment,
        "scenario": scenario,
        "prerequisite": prerequisite,
        "syntax": syntax,
        "parameters": parameters,
        "inputs": inputs,
        "outputs": outputs,
        "success": success,
        "recovery": recovery,
        "example": example,
    }


def render_script_reference(root: Path, inventory: tuple[str, ...]) -> str:
    scripts = tuple(
        relative for relative in inventory
        if Path(relative).suffix.lower() in SCRIPT_SUFFIXES
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for relative in scripts:
        groups[Path(relative).parts[0]].append(relative)
    lines = [
        "        <div class=\"catalog-summary\">",
        f"          <span><strong>{len(scripts)}</strong> 个脚本型文件</span>",
        f"          <span><strong>{len(groups)}</strong> 个功能分组</span>",
        "          <span>每项均含运行、输入输出、示例与恢复合同</span>",
        "        </div>",
        "        <div class=\"callout warning\"><strong>先判断是否可直接运行</strong>worker、CGI、库、容器内部组件和设备 bootstrap 必须由上层事务调用；复制内部命令不能替代 load/deploy/health。</div>",
    ]
    labels = (
        ("作用：", "purpose"), ("是否直接运行：", "direct"),
        ("运行环境：", "environment"), ("使用场景：", "scenario"),
        ("前置条件：", "prerequisite"), ("语法/调用方式：", "syntax"),
        ("主要参数：", "parameters"), ("输入：", "inputs"),
        ("输出/状态：", "outputs"), ("成功判据：", "success"),
        ("失败恢复：", "recovery"),
    )
    for group in sorted(groups, key=lambda value: (value.startswith("."), value.lower())):
        group_id = re.sub(r"[^a-z0-9]+", "-", group.lower()).strip("-")
        lines.append(
            f"        <h4 id=\"v2-script-group-{group_id}\" "
            f"data-nav-title=\"{html.escape(group, quote=True)}/ 脚本\">"
            f"{html.escape(group)}/ — {len(groups[group])} 个脚本</h4>"
        )
        for relative in groups[group]:
            profile = script_profile(root, relative)
            lines += [
                f"        <details data-script-reference=\"{html.escape(relative, quote=True)}\" class=\"script-reference\">",
                f"          <summary><code>{html.escape(relative)}</code> — {html.escape(profile['purpose'])}</summary>",
                "          <div class=\"script-body\"><dl>",
            ]
            for label, key in labels:
                lines.append(f"            <dt>{label}</dt><dd>{html.escape(profile[key])}</dd>")
            lines += [
                "          </dl>",
                "          <p><strong>示例：</strong></p>",
                f"          <pre><code>{html.escape(profile['example'])}</code></pre></div>",
                "        </details>",
            ]
    return "\n".join(lines)


def replace_block(text: str, begin: str, end: str, generated: str) -> str:
    if text.count(begin) != 1 or text.count(end) != 1:
        raise RuntimeError(f"manual must contain exactly one marker pair: {begin}")
    prefix, remainder = text.split(begin, 1)
    _old, suffix = remainder.split(end, 1)
    return f"{prefix}{begin}\n{generated}\n{end}{suffix}"


def render_manual(root: Path = ROOT) -> str:
    manual = root / "user-manual.html"
    current = manual.read_text(encoding="utf-8")
    inventory = repository_inventory(root)
    rendered = replace_block(
        current, FILE_BEGIN, FILE_END, render_file_catalog(root, inventory),
    )
    return replace_block(
        rendered, SCRIPT_BEGIN, SCRIPT_END,
        render_script_reference(root, inventory),
    )


def atomic_write(path: Path, text: str) -> None:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError(f"refusing unsafe manual target: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(before.st_mode))
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Regenerate the exhaustive catalog blocks in user-manual.html.",
    )
    result.add_argument(
        "--check", action="store_true",
        help="verify that the checked-in User Manual matches the current inventory",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    current = MANUAL.read_text(encoding="utf-8")
    rendered = render_manual(ROOT)
    if args.check:
        if current != rendered:
            print("user-manual.html is stale; run tools/update-user-manual.py")
            return 1
        print("user-manual.html exhaustive catalog is current")
        return 0
    if current == rendered:
        print("user-manual.html is already current")
        return 0
    atomic_write(MANUAL, rendered)
    print("updated user-manual.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
