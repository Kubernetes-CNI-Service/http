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
    "USER_MANUAL.md": "详细文字版操作手册和部署边界；网页 UM 对其关键流程进行结构化呈现。",
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
    "DAY0-Prepare/11-load.py": "python3 -B DAY0-Prepare/11-load.py DAY0-Prepare/<project> --prod --switch eth",
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
    return f"属于“{area}”的 {name}，由该目录的 README、上层入口和测试合同共同约束。"


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
    return tuple(options[:18])


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
    is_library = (
        path.name == "__init__.py" or "/lib/" in f"/{relative}"
        or path.name in {
            "_package_common.py", "deployment_lock.py", "deployment_prewrite_guard.py",
            "project_contract.py", "ztp_service_runtime.py", "switch_collection_gate.py",
            "dhcp_runtime_inventory.py", "dynamic_air_inventory.py", "environment_probe.py",
            "nvue_normalizer.py",
        }
    )
    is_cgi = path.suffix.lower() == ".cgi"
    is_worker = path.name.endswith("-worker.py") or path.name.endswith("_worker.py")
    is_docker_internal = relative.startswith("infra/docker/") and path.name != "deploy.sh"
    is_docker_operator = relative == "infra/docker/deploy.sh"
    is_bootstrap = relative.startswith("ztp/templates/") or path.name.startswith("ztp-bootstrap")
    is_alias = source.is_symlink()

    if is_validation_entrypoint:
        direct = "是；这是开发治理或只读验收入口，不是生产服务依赖。"
        if relative == "test_cases/run_related_tests.py":
            environment = "canonical 开发工作树；使用当前仓库 Python、平台身份和 /tmp 下的 pycache。"
            scenario = "开发时选择受影响的 direct/workflow，或在正式 load 前签发并复核绑定当前字节的 full proof。"
            prerequisite = "工作树暂时冻结；manifest 映射完整；测试预期已独立评审；禁止手工修改批准 ledger。"
            syntax = "python3 -B test_cases/run_related_tests.py [options]"
            parameters = ", ".join(script_options(source))
            inputs = "当前生产脚本、测试、script_test_manifest.json、批准状态以及 Python/平台身份。"
            outputs = "选测清单、unittest 结果和退出码；只有成功的 related/full 才能按合同原子更新批准状态。"
            success = "所有选中测试零 failure/error；正式发布还必须让 --all 成功，并让 --check --require-full 返回 0。"
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
        environment = "所属 runtime 的受管用户、目录、网络和 capability 环境。"
        scenario = "上层生命周期启动后执行后台采集、恢复、健康检查、配置应用或容器激活。"
        prerequisite = "上层入口已验证 release/receipt、路径类型、权限、锁和依赖服务；当前身份必须匹配。"
        syntax = f"由所属上层配置调用 {relative}；人工只使用对应 deploy/load/status/CGI 入口"
        opts = script_options(source)
        parameters = ", ".join(opts) if opts else "无公开操作员参数；参数由上层配置固定。"
        inputs = "已发布 release、受管配置/请求、日志或设备端 HTTP 资源。"
        outputs = "受管状态、日志、配置、health 或设备应用回执；所有写入应留在规定根目录。"
        success = "上层 health/status、PID/退出码、receipt 与输出身份同时满足合同。"
        recovery = "使用上层 status/health/logs 或事务恢复；不要脱离 supervisor/systemd 手工重启子进程。"
        example = "sudo ./infra/docker/deploy.sh status" if relative.startswith("infra/docker/") else "python3 -B DAY0-Prepare/11-load.py DAY0-Prepare/<project> --prod"
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
