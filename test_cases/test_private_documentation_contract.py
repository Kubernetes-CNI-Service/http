#!/usr/bin/env python3
"""Private-document assertions with one whole-tier clean-clone gate."""

from pathlib import Path
import importlib.util
import json
import sys
import tempfile
import unittest

from test_cases.test_documentation_catalog import *  # public catalog helpers
from test_cases.test_documentation_catalog import DocumentationCatalogTests


ROOT = Path(__file__).resolve().parents[1]
DOCKER_ROOT = ROOT / "infra/docker"
PRIVATE_DOCUMENT_PATHS = (
    "README.md",
    "USER_MANUAL.md",
    "DAY0-Prepare/README.md",
    "infra/README.md",
    "monitor/README.md",
    "tools/README.md",
    "tools/ibdiagnet-analyze-tool/README.md",
    "tools/lldp-analyze-tool/README.md",
    "ztp/README.md",
    "ztp/config/cumulus/template/README.md",
    "ztp/config/cumulus/template/P2P/README.md",
    "ztp/config/nvos/template/P2P/README.md",
    "ztp/config/isc-dhcp-server/README.md",
    "ztp/optimize/issue-tracker/README.md",
    "ztp/optimize/issue-tracker/OPT-001-ethernet-scope-filter/README.md",
    "ztp/optimize/issue-tracker/OPT-002-dhcp-device-identity/README.md",
    "ztp/optimize/issue-tracker/OPT-003-vrf-bond-semantic-compare/README.md",
    "ztp/optimize/issue-tracker/OPT-004-multi-member-bond-roundtrip/README.md",
    "ztp/optimize/issue-tracker/OPT-005-report-sort-order/README.md",
    "ztp/optimize/issue-tracker/OPT-006-global-placeholder-backfill/README.md",
    "ztp/optimize/issue-tracker/OPT-007-mixed-bond-profile-alignment/README.md",
    "ztp/optimize/issue-tracker/OPT-008-oobofoob-dhcp-vs-static/README.md",
    "ztp/optimize/issue-tracker/OPT-009-script-rename-feedback/README.md",
)
PRIVATE_TIER_SKIP_REASON = "private documentation tier absent in public checkout"
PRIVATE_INVENTORY_REPAIR = (
    "test_cases.test_private_documentation_contract:PRIVATE_DOCUMENT_PATHS"
)


def require_complete_private_document_tier(root: Path) -> None:
    expected = {Path(path) for path in PRIVATE_DOCUMENT_PATHS}
    present = {path for path in expected if (root / path).is_file()}
    issue_root = root / "ztp/optimize/issue-tracker"
    discovered_opt = {
        path.relative_to(root)
        for path in issue_root.glob("OPT-*/README.md")
        if path.is_file()
    }
    expected_opt = {path for path in expected if "issue-tracker/OPT-" in path.as_posix()}
    unexpected_opt = sorted(discovered_opt - expected_opt, key=lambda item: item.as_posix())
    if unexpected_opt:
        names = ", ".join(path.as_posix() for path in unexpected_opt)
        raise AssertionError(
            f"unreviewed private OPT documentation: {names}; add it to "
            f"{PRIVATE_INVENTORY_REPAIR}"
        )
    if not present:
        raise unittest.SkipTest(PRIVATE_TIER_SKIP_REASON)
    missing = sorted(expected - present, key=lambda item: item.as_posix())
    if missing:
        raise AssertionError(
            "partial private documentation tier; missing: "
            + ", ".join(path.as_posix() for path in missing)
        )


class PrivateDocumentationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        require_complete_private_document_tier(ROOT)
        DocumentationCatalogTests.setUpClass.__func__(cls)

    def test_user_manual_scenario_two_uses_the_real_two_step_setup_flow(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        section = manual.split("## 7. 场景二：创建并准备项目", 1)[1].split(
            "\n## 8.", 1,
        )[0]
        create = "python3 DAY0-Prepare/01-a-setup.py --create <project>"
        activate = "python3 DAY0-Prepare/01-a-setup.py <project>"
        self.assertIn(create, section)
        self.assertIn(activate, section)
        self.assertLess(section.index(create), section.index(activate))
        self.assertIn("不激活", section)
        self.assertIn("填写", section)
        self.assertIn("校验并激活", section)

    def test_gb300_mini_air_sampling_is_the_exact_project_policy_authority(self):
        project = ROOT / "DAY0-Prepare/2026-12-vb-gb300"
        expected = {
            "location_prefix_regex": r"^[A-Za-z]\d{2}-(?P<logical>.+)$",
            "unknown_role_action": "error",
            "anchors": [{
                "name": "management-eth0",
                "local_roles": ["oob-core-leaf"],
                "local_hostname_regex": r"^oob-leaf.+$",
                "peer_hostname_regex": r"^(?:tan|ib)(?:-|.+)$",
                "peer_port_regex": r"^eth0$",
            }],
            "roles": [
                {"name": "firewall", "hostname_regex": r"^fgt-.+-fw(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "border", "hostname_regex": r"^border(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "oob-core", "hostname_regex": r"^oob-core(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "oob-core-leaf", "hostname_regex": r"^oob-leaf(?P<index>\d+)$",
                 "selection": {"mode": "indices", "capture_group": "index",
                               "indices": [1, 5, 13, 17], "group_by": []}},
                {"name": "oob-pod-leaf",
                 "hostname_regex": r"^oob-pod(?P<zone>\d+)-leaf(?P<index>\d+)$",
                 "selection": {"mode": "anchor",
                               "peer_hostname_regex": r"^(?:tan|ib)(?:-|.+)$",
                               "peer_port_regex": r"^eth0$", "group_by": []}},
                {"name": "oob-pod-spine",
                 "hostname_regex": r"^oob-pod(?P<zone>\d+)-spine(?P<index>\d+)$",
                 "selection": {"mode": "indices", "capture_group": "index",
                               "indices": [1, 3], "group_by": ["zone"]}},
                {"name": "oob-rack-tor",
                 "hostname_regex": r"^oob-pod(?P<zone>\d+)r(?P<rack>\d+)-tor(?P<index>\d+)$",
                 "selection": {"mode": "match_fields",
                               "fields": {"index": [1], "rack": [1]},
                               "group_by": ["zone"]}},
                {"name": "oobofoob-leaf", "hostname_regex": r"^oobofoob-leaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "oobofoob-spine", "hostname_regex": r"^oobofoob-spine(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "oobofoob-pod-leaf",
                 "hostname_regex": r"^oobofoob-pod(?P<zone>\d+)-leaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 1, "group_by": ["zone"]}},
                {"name": "tan-spine", "hostname_regex": r"^tan-spine(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 1, "group_by": []}},
                {"name": "tan-pod-leaf",
                 "hostname_regex": r"^tan-pod(?P<zone>\d+)-leaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "tan-cp-leaf", "hostname_regex": r"^tan-cp-leaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 4, "group_by": []}},
                {"name": "tan-cp-1g-leaf", "hostname_regex": r"^tan-cp-1gleaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 1, "group_by": []}},
                {"name": "tan-hps-leaf", "hostname_regex": r"^tan-hps-leaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
                {"name": "tan-obj-leaf", "hostname_regex": r"^tan-obj-leaf(?P<index>\d+)$",
                 "selection": {"mode": "first", "count": 2, "group_by": []}},
            ],
        }
        source = project / "03-air-topology-policy.json"
        raw = json.loads(source.read_text(encoding="utf-8"))
        self.assertEqual({"FW": ["g01-fgt-7081f-fw02", "h01-fgt-7081f-fw01"]},
                         raw["node_allowlist"])
        self.assertEqual(1, len(raw["link_rewrites"]))

        module_path = ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py"
        spec = importlib.util.spec_from_file_location("private_h19_topology", module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        loaded = module.load_air_topology_policy(source, project_root=project)
        self.assertEqual(expected, loaded["mini_sampling"])

        devices = {
            "g04-border01", "g05-border02", "g06-border03",
            "h04-oob-leaf01", "h05-oob-leaf14", "h05-oob-leaf18",
        }
        edges = [("h05-oob-leaf14", "swp1", "a01-tan-spine01", "eth0")]
        selected, _omitted, reasons = module._select_mini_air_nodes(
            devices, edges, {"Eth-SW": ["*"]}, ["Eth-SW"],
            air_topology_policy=loaded,
        )
        self.assertEqual({
            "g04-border01", "g05-border02",
            "h04-oob-leaf01", "h05-oob-leaf14",
        }, selected)
        self.assertIn("anchor=management-eth0", next(
            item["reason"] for item in reasons
            if item["hostname"] == "h05-oob-leaf14"
        ))

        current_mini = (project / "04-air-mini-devices.txt").read_text(
            encoding="utf-8",
        )
        self.assertIn("\nborder01\n", current_mini)
        self.assertIn("\noob-leaf14\n", current_mini)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            customer = root / "customer.txt"
            canonical = root / "04-air-mini-devices.txt"
            customer.write_text("border01\noob-leaf14\n", encoding="utf-8")
            resolved, _report = module._resolve_mini_air_device_selection(
                customer, canonical, selected, devices,
                mini_sampling=loaded["mini_sampling"],
            )
        self.assertEqual(selected, resolved)

    def test_user_manual_validation_and_short_checklist_start_with_create(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        validation = manual.split("### 7.5 本地验证", 1)[1].split("\n## 8.", 1)[0]
        checklist = manual.split("## 20. 最短操作清单", 1)[1]
        create = "01-a-setup.py --create <project>"
        activate = "01-a-setup.py <project>"
        for name, section in (("7.5", validation), ("20", checklist)):
            with self.subTest(section=name):
                self.assertIn(create, section)
                self.assertIn(activate, section)
                self.assertLess(section.index(create), section.index(activate))

    def test_monitor_auth_docs_define_one_initial_prompt_and_authenticated_operations(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        monitor = (ROOT / "monitor/README.md").read_text(encoding="utf-8")
        docker = (ROOT / "infra/docker/README.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs/deployment/README.md").read_text(
            encoding="utf-8",
        )
        operations = (ROOT / "docs/operations/README.md").read_text(
            encoding="utf-8",
        )
        real_environment = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        public_manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")

        for document in (manual, monitor, docker, deployment, operations):
            with self.subTest(document=document[:40]):
                self.assertIn("/monitor/monitor.html", document)
                self.assertIn("nvis", document)
                self.assertIn("cumulus", document)
                self.assertIn("每个控制请求", document)

        self.assertIn("/monitor/control/ztp-monitor", monitor)
        self.assertIn("/monitor/control/switch-collection", monitor)
        self.assertIn("/monitor/control/manual-ztp", monitor)
        self.assertIn("首次", monitor)
        self.assertIn("不会再次弹出", monitor)
        self.assertIn("认证兼容入口", monitor)
        self.assertIn("/var/lib/http-ztp-container/control-auth", docker)
        self.assertIn("deploy.sh rotate-auth", docker)
        self.assertIn("image contract `3`", docker)
        self.assertIn("contract label 3", docker)
        self.assertIn("contract `2`", docker)
        self.assertIn("只允许身份匹配的旧容器清理", docker)
        self.assertNotIn(
            "runtime-contract.json` 必须明确兼容 image contract `2`",
            docker,
        )
        self.assertNotIn("全部通过后才会移除旧的受管容器", docker)
        self.assertIn("control-users.htpasswd", manual)
        self.assertNotIn("nvis`/`nvidia", manual)

        self.assertIn("/monitor/monitor.html", public_manual)
        self.assertIn("nvis", public_manual)
        self.assertIn("cumulus", public_manual)
        self.assertIn("首次打开", public_manual)
        self.assertIn("不会再次弹出登录框", public_manual)
        self.assertIn("每个控制请求", public_manual)
        self.assertIn("HTTP 401", public_manual)
        self.assertNotIn(
            "curl -fsS http://&lt;ztp-service-ip&gt;/monitor/monitor.html",
            public_manual,
        )

        self.assertIn("TC-REAL-MONITOR-AUTH-001", real_environment)
        for browser in ("Chrome", "Safari", "Firefox"):
            with self.subTest(browser=browser):
                self.assertIn(browser, real_environment)
        self.assertIn("两组用户名各执行一次", real_environment)
        self.assertIn("后续操作不再出现第二次登录提示", real_environment)

    def test_repository_catalog_is_current_and_all_local_links_resolve(self):
        current = (ROOT / "README.md").read_text(encoding="utf-8")
        rendered = self.catalog.render_root_readme(
            current, self.catalog.generated_catalog(ROOT),
        )
        self.assertEqual(current, rendered, "run tools/update-root-readme.py")

        generated = current.split(self.catalog.BEGIN, 1)[1].split(
            self.catalog.END, 1
        )[0]
        destinations = re.findall(r"\[[^\]]+\]\(([^)]+)\)", generated)
        self.assertTrue(destinations)
        for destination in destinations:
            with self.subTest(destination=destination):
                self.assertFalse(destination.startswith(("/", "file:")))
                target = destination.split("#", 1)[0]
                self.assertTrue((ROOT / target).exists(), destination)

    def test_user_manual_generator_is_current(self):
        self.assertTrue(
            USER_MANUAL_SCRIPT.is_file(),
            "the exhaustive User Manual must have one deterministic updater",
        )
        result = subprocess.run(
            [sys.executable, "-B", str(USER_MANUAL_SCRIPT), "--check"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        tools_readme = (ROOT / "tools/README.md").read_text(encoding="utf-8")
        self.assertIn("update-user-manual.py", tools_readme)
        self.assertIn("Git tracked + untracked/nonignored", tools_readme)
        self.assertIn("python3 -B tools/update-user-manual.py --check", tools_readme)

    def test_runtime_choice_and_backend_boundaries_are_explicit(self):
        root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        day0 = (ROOT / "DAY0-Prepare/README.md").read_text(encoding="utf-8")
        dhcp = (ROOT / "ztp/config/isc-dhcp-server/README.md").read_text(
            encoding="utf-8"
        )
        monitor = (ROOT / "monitor/README.md").read_text(encoding="utf-8")
        apache = (ROOT / "infra/apache-publication-boundary/README.md").read_text(
            encoding="utf-8"
        )

        for text in (root_readme, manual):
            self.assertIn("Native/systemd", text)
            self.assertIn("Docker/Supervisor", text)
            self.assertIn("infra/docker/README.md", text)
        self.assertIn("原生（Native/systemd）专用", day0)
        self.assertIn("--skip-infra", day0)
        self.assertIn("原生（Native/systemd）专用", dhcp)
        self.assertIn("原生（Native/systemd）专用", monitor)
        self.assertIn("Docker/Supervisor", apache)

    def test_local_formal_load_owns_full_tests_before_upload_or_sync(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        checklist = manual[manual.index("## 20. 最短操作清单"):]
        local_load = "python3 DAY0-Prepare/11-load.py DAY0-Prepare/<project>"
        upload = "python3 tools/tar-for-upload.py <project>"
        self.assertIn(local_load, checklist)
        self.assertLess(checklist.index(local_load), checklist.index(upload))

        update_start = manual.index("## 14. 场景九：后续代码和项目输入更新")
        update_end = manual.index("\n## 15.", update_start)
        update = manual[update_start:update_end]
        self.assertIn("先在项目电脑执行正式 load", update)
        self.assertIn(local_load, update)
        self.assertLess(update.index(local_load), update.index("tools/sync-code.py"))

        deployment = (
            ROOT / "docs/deployment/README.md"
        ).read_text(encoding="utf-8")
        deployment_logical = re.sub(r"\s+", "", deployment)
        self.assertIn("本机正式load→tar-for-upload", deployment_logical)
        self.assertIn("本机正式load→sync-code", deployment_logical)
        self.assertIn(
            "tar-for-upload.py`和`sync-code.py`只复核", deployment_logical,
        )
        self.assertIn("绝不自行执行全量测试", deployment_logical)

    def test_load_deployment_scope_and_monitor_inheritance_are_documented(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        day0 = (ROOT / "DAY0-Prepare/README.md").read_text(encoding="utf-8")
        test_contract = (ROOT / "test_cases/README.md").read_text(
            encoding="utf-8"
        )
        real_environment = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8"
        )

        for text in (manual, day0):
            self.assertIn("默认同时生成并发布 Production 与 AIR", text)
            self.assertIn("--air", text)
            self.assertIn("仅生成并发布 AIR", text)
            self.assertIn("--prod", text)
            self.assertIn("仅生成并发布 Production", text)
            self.assertIn("--mini", text)
            self.assertIn("自动", text)
            self.assertIn("AIR", text)
            self.assertIn("Ethernet", text)
            self.assertNotIn("`--mini` 必须与 `--air`", text)
            self.assertIn("--ztp-monitor-scope auto", text)
            self.assertIn("自动继承", text)
            self.assertNotIn("`--air` 是监控环境选择", text)
            self.assertNotIn("Production/IB/NVL 仍完整生成", text)

        self.assertIn("deployment scope", test_contract)
        self.assertIn("TC-REAL-LOAD-SCOPE-001", real_environment)

    def test_switch_scope_and_positional_upload_host_are_documented(self):
        load = load_path("documentation_switch_scope", ROOT / "DAY0-Prepare/11-load.py")
        upload = load_path("documentation_positional_host", ROOT / "tools/tar-for-upload.py")
        load_help = load._build_parser().format_help()
        upload_help = upload.parse_args
        del upload_help  # The real parser behavior is covered by direct tests.

        self.assertIn("--switch {eth,ib,nvl}", load_help)
        self.assertEqual(
            "eth",
            load.validate_switch_scope_options(
                load.parse_args(["example", "--air"]), "air",
            ),
        )

        documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "README.md",
                "USER_MANUAL.md",
                "DAY0-Prepare/README.md",
                "docs/deployment/README.md",
                "tools/README.md",
                "test_cases/README.md",
                "test_cases/REAL_ENVIRONMENT.md",
            )
        }
        joined = "\n".join(documents.values())
        self.assertIn("--switch eth", joined)
        self.assertIn("--switch ib", joined)
        self.assertIn("--switch nvl", joined)
        self.assertIn("AIR", joined)
        self.assertIn("默认选择 `eth`", joined)
        self.assertIn("退役", joined)
        self.assertIn("TC-REAL-LOAD-SWITCH-001", documents["test_cases/REAL_ENVIRONMENT.md"])

        primary_examples = "\n".join(
            documents[relative]
            for relative in (
                "USER_MANUAL.md", "docs/deployment/README.md", "tools/README.md",
            )
        )
        self.assertRegex(
            primary_examples,
            r"tar-for-upload\.py\s+<project>\s+<user>@<mgmt-host>",
        )
        self.assertIn("`--host` 兼容", primary_examples)
        self.assertIn("PROJECT HOST", upload.HELP_EPILOG)

    def test_copy_paste_examples_use_canonical_inputs_and_working_directories(self):
        day0 = (ROOT / "DAY0-Prepare/README.md").read_text(encoding="utf-8")
        cumulus = (
            ROOT / "ztp/config/cumulus/template/README.md"
        ).read_text(encoding="utf-8")

        self.assertIn("python3 b-xlsx_to_dot.py -y\n", cumulus)
        self.assertNotRegex(
            cumulus,
            r"python3 b-xlsx_to_dot\.py -y\s+[\"']?Project P2P",
        )
        self.assertIn(
            "cd ../ztp/backup\npython3 yaml-collect.py",
            day0,
        )
        self.assertNotIn("\ncd ztp/backup\n", day0)
        self.assertIn(
            "生成 MAC 软链接\n"
            "  └─ cd ztp/config/cumulus\n"
            "  └─ python3 d-hostname2mac.py \\",
            day0,
        )

    def test_dhcp_preview_docs_have_no_standalone_runtime_install_path(self):
        dhcp = (ROOT / "ztp/config/isc-dhcp-server/README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "生成器不提供复制到 `/etc/dhcp` 的交互或命令",
            dhcp,
        )
        self.assertNotIn("复制配置到 `/etc/dhcp` 仍默认选择 `no`", dhcp)

    def test_cux_01_user_manual_routes_each_runtime_to_one_lifecycle(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        self.assertIn("CUX-01", manual)
        self.assertIn("运行模式一经选择，同一轮部署不得混用", manual)
        self.assertRegex(
            manual,
            r"Native/systemd[\s\S]+DAY0-Prepare/11-load\.py[\s\S]+"
            r"Docker/Supervisor[\s\S]+infra/docker/deploy\.sh",
        )

    def test_cux_02_dhcp_preview_is_not_a_production_activation_path(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        dhcp = (ROOT / "ztp/config/isc-dhcp-server/README.md").read_text(
            encoding="utf-8"
        )
        docker = (ROOT / "infra/docker/README.md").read_text(encoding="utf-8")
        for text in (manual, dhcp):
            self.assertIn("CUX-02", text)
            self.assertIn("独立 DHCP 生成仅用于开发预览", text)
            self.assertIn("统一发布事务", text)
        self.assertIn("禁止在宿主运行 `systemctl`", docker)
        self.assertNotIn("sudo systemctl restart isc-dhcp-server", docker)

    def test_cux_02_day0_steps_one_through_six_are_one_developer_preview(self):
        day0 = (ROOT / "DAY0-Prepare/README.md").read_text(encoding="utf-8")
        begin = "## 开发者分解预览（非生产操作清单）"
        end = "## 链接映射说明"
        self.assertIn(begin, day0)
        self.assertIn(end, day0)
        block = day0.split(begin, 1)[1].split(end, 1)[0]
        self.assertIn("以下第 1–6 节仅用于隔离开发预览", block)
        self.assertIn("生产不得逐步执行", block)
        self.assertIn("统一发布事务", block)
        self.assertIn("DAY0-Prepare/11-load.py", block)
        self.assertIn("infra/docker/deploy.sh deploy", block)
        self.assertIn("deploy-preloaded <IMAGE_ID>", block)
        self.assertIn("没有 source write", block)
        for number in range(1, 7):
            with self.subTest(step=number):
                self.assertRegex(block, rf"(?m)^### {number}\. 开发预览：")
        cumulus = block.split("### 3.", 1)[1].split("### 4.", 1)[0]
        self.assertRegex(
            cumulus,
            r"(?m)^# 仅隔离开发预览；[^\n]+\n"
            r"python3 ztp/config/isc-dhcp-server/c1-generate_dhcp\.py -y$",
        )
        self.assertNotIn("systemctl", block)

    def test_docker_documentation_matches_atomic_deploy_action_branches(self):
        shell = (ROOT / "infra/docker/deploy.sh").read_text(encoding="utf-8")
        self.assertIn(
            "deploy [--no-upgrade]",
            shell,
        )
        self.assertIn(
            "Build, recreate inactive, run load, activate, and health-check",
            shell,
        )

        def action_branch(action: str) -> str:
            marker = f"  {action})"
            self.assertIn(marker, shell)
            return shell.rsplit(marker, 1)[1].split("    ;;", 1)[0]

        online = action_branch("deploy")
        self.assertLess(online.index("build_image"), online.index("start_inactive_container"))
        self.assertLess(online.index("start_inactive_container"), online.index("run_load"))
        offline = action_branch("deploy-preloaded")
        self.assertLess(
            offline.index("verify_preloaded_image"),
            offline.index("start_inactive_container"),
        )
        self.assertLess(offline.index("start_inactive_container"), offline.index("run_load"))
        existing = action_branch("load")
        self.assertIn("owned_container_id true true false", existing)
        self.assertIn("run_load", existing)

        documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "USER_MANUAL.md",
                "docs/deployment/README.md",
                "docs/operations/README.md",
                "infra/docker/README.md",
            )
        }
        joined = "\n".join(documents.values())
        self.assertIn("首次在线：`init → doctor → deploy → status`", joined)
        self.assertIn(
            "首次离线：`init → doctor → deploy-preloaded <IMAGE_ID> → status`",
            joined,
        )
        self.assertIn("没有 source write 且受管容器仍在运行", joined)
        self.assertIn("Service IP 从接口 A 移到接口 B", joined)
        self.assertIn("`load → health/status`", joined)
        for relative, text in documents.items():
            with self.subTest(relative=relative):
                self.assertNotIn("init → doctor → deploy → load", text)
                self.assertNotIn("deploy-preloaded → load", text)
                for block in re.findall(
                    r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL,
                ):
                    actions = []
                    fenced = "```bash\n" + block + "```"
                    for command in bash_commands(fenced):
                        match = re.search(
                            r"(?:^|\s)(?:\./)?infra/docker/deploy\.sh\s+"
                            r"(deploy-preloaded|deploy|load|health|status)(?:\s|$)",
                            command,
                        )
                        if match:
                            actions.append(match.group(1))
                    for index, action in enumerate(actions):
                        if (
                            action in {"deploy", "deploy-preloaded"}
                            and index + 1 < len(actions)
                        ):
                            self.assertNotEqual("load", actions[index + 1], actions)

    def test_docker_source_write_docs_require_redeploy_and_reserve_load_for_recovery(self):
        operator_documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "README.md",
                "USER_MANUAL.md",
                "docs/deployment/README.md",
                "docs/operations/README.md",
                "infra/docker/README.md",
                "tools/README.md",
            )
        }
        for relative, text in operator_documents.items():
            with self.subTest(relative=relative):
                self.assertIn("Docker tar/sync 成功写入", text)
                self.assertIn("stop + rebuild-required", text)
                self.assertRegex(text, r"下一步必须执行\s+`deploy`")
                self.assertIn("`deploy-preloaded <IMAGE_ID>`", text)
                self.assertIn("没有 source write", text)
                self.assertRegex(text, r"受管容器仍在运行")
                self.assertNotRegex(
                    text,
                    r"(?:同步完成|sync)[^。\n]{0,80}(?:执行|使用) `?(?:deploy\.sh )?load",
                )

        preview_documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "DAY0-Prepare/README.md",
                "ztp/config/isc-dhcp-server/README.md",
            )
        }
        for relative, text in preview_documents.items():
            with self.subTest(relative=relative):
                self.assertRegex(
                    text,
                    r"生产不得在\s+Docker source write\s+后执行 `load`",
                )
                self.assertRegex(text, r"已有运行中的\s+inactive 控制容器")

        supporting_documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "docs/architecture/README.md",
                "test_cases/README.md",
                "ztp/templates/README.md",
            )
        }
        self.assertIn("rebuild-required", supporting_documents["docs/architecture/README.md"])
        self.assertIn("Docker 写入先 stop", supporting_documents["test_cases/README.md"])
        self.assertIn(
            "不得直接运行 `deploy.sh load`",
            supporting_documents["ztp/templates/README.md"],
        )
        ethernet = (ROOT / "ethernet/monitor/README.md").read_text(encoding="utf-8")
        self.assertIn("Native/systemd", ethernet)
        self.assertIn("DAY0-Prepare/11-load.py", ethernet)
        self.assertIn("Docker/Supervisor", ethernet)
        self.assertIn("infra/docker/deploy.sh deploy", ethernet)
        self.assertIn("deploy-preloaded <IMAGE_ID>", ethernet)
        self.assertIn("source write 后不得 load", ethernet)
        self.assertNotIn("02-devices_config.csv`、重新 load 后", ethernet)

        day0 = (ROOT / "DAY0-Prepare/README.md").read_text(encoding="utf-8")
        drift_start = day0.index("策略文件参与统一 release 输入哈希")
        drift_policy = day0[drift_start:day0.index("\n\n", drift_start)]
        self.assertIn("发布后漂移属于 source write", drift_policy)
        self.assertIn("Native/systemd", drift_policy)
        self.assertIn("DAY0-Prepare/11-load.py", drift_policy)
        self.assertIn("Docker/Supervisor", drift_policy)
        self.assertIn("infra/docker/deploy.sh deploy", drift_policy)
        self.assertIn("deploy-preloaded <IMAGE_ID>", drift_policy)
        self.assertIn("source write 后不得 load", drift_policy)

        root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
        root_identity_start = root_readme.index("Production 中缺 MAC")
        root_identity = root_readme[
            root_identity_start:root_readme.index("\n\n", root_identity_start)
        ]
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        manual_identity_start = manual.index("计划设备缺 MAC 时")
        manual_identity = manual[
            manual_identity_start:manual.index("\n\n", manual_identity_start)
        ]
        service_start = manual.index("### load 报告 service IP 不属于本机")
        service_recovery = manual[
            service_start:manual.index("\n\n### ", service_start + 4)
        ]
        for label, policy in (
            ("root identity binding", root_identity),
            ("manual identity binding", manual_identity),
        ):
            with self.subTest(policy=label):
                self.assertIn("source write", policy)
                self.assertIn("Native/systemd", policy)
                self.assertIn("Docker/Supervisor", policy)
                self.assertIn("infra/docker/deploy.sh deploy", policy)
                self.assertIn("deploy-preloaded <IMAGE_ID>", policy)
                self.assertIn("source write 后不得 load", policy)
        self.assertIn("Native/systemd", service_recovery)
        self.assertIn("Docker/Supervisor", service_recovery)
        self.assertIn("infra/docker/deploy.sh deploy", service_recovery)
        self.assertIn("deploy-preloaded <IMAGE_ID>", service_recovery)
        self.assertIn("没有 source write", service_recovery)
        self.assertNotIn("再重新 load", service_recovery)
        monitor_help_start = manual.index("如果 Switch Status 显示")
        monitor_help = manual[
            monitor_help_start:manual.index("\n\n", monitor_help_start)
        ]
        self.assertIn("需按当前后端恢复", monitor_help)
        self.assertIn("Native/systemd", monitor_help)
        self.assertIn("Docker/Supervisor", monitor_help)
        self.assertIn("infra/docker/deploy.sh deploy", monitor_help)
        self.assertIn("deploy-preloaded <IMAGE_ID>", monitor_help)
        self.assertIn("source write 后不得 load", monitor_help)
        self.assertNotIn("需运行 load", monitor_help)
        password_start = manual.index("工具只原子替换 `01-global.yaml`")
        password_policy = manual[
            password_start:manual.index("\n\n", password_start)
        ]
        password_policy_logical = " ".join(password_policy.split())
        self.assertIn("global 变化属于 source write", password_policy_logical)
        self.assertIn("Native/systemd", password_policy)
        self.assertIn("Docker/Supervisor", password_policy)
        self.assertIn("infra/docker/deploy.sh deploy", password_policy)
        self.assertIn("deploy-preloaded <IMAGE_ID>", password_policy)
        self.assertIn("source write 后不得 load", password_policy)
        self.assertNotIn("完整重跑 `11-load.py`", password_policy)

    def test_transfer_docs_require_explicit_runtime_and_match_guard_behavior(self):
        upload = load_path("documentation_upload", ROOT / "tools/tar-for-upload.py")
        sync = load_path("documentation_sync", ROOT / "tools/sync-code.py")
        guard = load_path(
            "documentation_guard", ROOT / "tools/deployment_prewrite_guard.py"
        )
        self.assertEqual(
            "native", upload.parse_args(["-p", "customer", "--dry-run"]).runtime
        )
        self.assertEqual(
            "native",
            sync.parse_args(["-p", "customer", "--host", "worker.example"]).runtime,
        )
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            self.assertFalse(
                guard.quiesce_for_source_update(
                    Path("/var/www/html"), state_root=state,
                    which=lambda _name: None, docker_requested=False,
                )
            )
            self.assertFalse((state / "deployment-owner.json").exists())
            self.assertTrue(
                guard.quiesce_for_source_update(
                    Path("/var/www/html"), state_root=state,
                    which=lambda _name: None, docker_requested=True,
                )
            )
            owner = (state / "deployment-owner.json").read_text(encoding="utf-8")
            self.assertIn('"runtime": "docker"', owner)
            self.assertTrue((state / "rebuild-required.json").is_file())

        documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "README.md",
                "USER_MANUAL.md",
                "docs/deployment/README.md",
                "infra/docker/README.md",
                "tools/README.md",
            )
        }
        for relative, text in documents.items():
            commands = [
                command for command in bash_commands(text)
                if "tools/tar-for-upload.py" in command
                or "tools/sync-code.py" in command
            ]
            self.assertTrue(commands, relative)
            for command in commands:
                with self.subTest(relative=relative, command=command):
                    self.assertRegex(command, r"(?:^|\s)--runtime (?:native|docker)(?:\s|$)")
            self.assertTrue(
                any("tools/tar-for-upload.py" in command and "--runtime docker" in command
                    for command in commands),
                f"{relative}: missing Docker upload example",
            )
            self.assertTrue(
                any("tools/sync-code.py" in command and "--runtime docker" in command
                    for command in commands),
                f"{relative}: missing Docker sync example",
            )
        joined = "\n".join(documents.values())
        self.assertIn("省略 `--runtime` 会按 `native` 处理", joined)
        self.assertIn("Docker owner", joined)
        self.assertIn("quiesce", joined)

    def test_cux_03_live_tree_never_accepts_manual_tar_extraction(self):
        documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "README.md",
                "USER_MANUAL.md",
                "infra/docker/README.md",
                "tools/README.md",
                "docs/deployment/README.md",
            )
            if (ROOT / relative).is_file()
        }
        for relative, text in documents.items():
            with self.subTest(relative=relative):
                self.assertNotIn("直接解压到 `/var/www/html`", text)
                self.assertNotIn("解压到宿主 `/var/www/html`", text)
        joined = "\n".join(documents.values())
        self.assertIn("CUX-03", joined)
        self.assertIn("禁止对 live `/var/www/html` 手工执行 `tar`", joined)
        self.assertIn("tar-for-upload.py <project>", joined)
        self.assertIn("--deploy", joined)
        self.assertIn("deployment_prewrite_guard.py", joined)

    def test_cux_03_separates_remote_upload_deploy_from_local_download_import(self):
        tools_readme = (ROOT / "tools/README.md").read_text(encoding="utf-8")
        upload_section = tools_readme.split(
            "## tar-for-upload.py", 1
        )[1].split("## sync-code.py", 1)[0]
        import_section = tools_readme.split(
            "## import-from-download.py", 1
        )[1].split("## collect-ztp-diagnostics.py", 1)[0]

        self.assertIn("本地 → 管理服务器", tools_readme)
        self.assertIn("--deploy", upload_section)
        self.assertIn("deployment_prewrite_guard.py", upload_section)
        self.assertIn("download 包中的项目数据带回本地", import_section)
        self.assertIn("package-imports/", import_section)
        self.assertIn("而不是在管理服务器部署 upload 包", import_section)
        self.assertNotIn("解压到 HTTP 根目录", import_section)

    def test_uploaded_archive_followup_reuses_exact_bytes_without_manual_tar(self):
        upload = load_path("documentation_upload_resume", ROOT / "tools/tar-for-upload.py")
        self.assertIn("--deploy-uploaded", upload.HELP_EPILOG)
        self.assertIn("不会重新打包", upload.HELP_EPILOG)
        self.assertIn("不会重新传输", upload.HELP_EPILOG)

        documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "USER_MANUAL.md", "tools/README.md", "docs/deployment/README.md",
                "test_cases/REAL_ENVIRONMENT.md",
            )
        }
        for relative, text in documents.items():
            with self.subTest(relative=relative):
                self.assertIn("--deploy-uploaded", text)
                self.assertIn("不会重新打包", text)
                self.assertIn("不会重新传输", text)
                self.assertIn("禁止", text)
                self.assertNotIn("审核后再按上例增加 `--deploy`", text)

    def test_deployment_scenario_matrix_covers_topology_runtime_and_recovery_axes(self):
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        deployment = (
            ROOT / "docs/deployment/README.md"
        ).read_text(encoding="utf-8")
        operations = (
            ROOT / "docs/operations/README.md"
        ).read_text(encoding="utf-8")
        real_environment = (
            ROOT / "test_cases/REAL_ENVIRONMENT.md"
        ).read_text(encoding="utf-8")
        joined = "\n".join((manual, deployment, operations))

        self.assertIn("部署位置 × 运行后端 × 操作类型", deployment)
        for scenario in (
            "Mac 本机开发（不连接交换机）",
            "本机 Ubuntu VM（adapter 直通）",
            "可直连管理服务器 Native",
            "可直连管理服务器 Docker 在线 build",
            "可直连管理服务器 Docker 预构建镜像",
            "可信中转 Native",
            "可信中转 Docker 在线 build",
            "可信中转 Docker 预构建镜像",
        ):
            with self.subTest(scenario=scenario):
                self.assertIn(scenario, deployment)

        self.assertIn("macOS 只做配置准备和全量测试", joined)
        self.assertIn("adapter 必须直通给 Ubuntu VM", joined)
        self.assertIn("Docker image 不能替代 Native 的离线 apps 仓库", joined)
        self.assertIn("中转环境不使用 `sync-code.py`", joined)
        self.assertIn("重新生成并中转新的 upload archive", joined)

        self.assertIn("同一 Service IP 换接口", operations)
        self.assertIn("Service IP 地址值改变", operations)
        self.assertIn("Native：重新执行完整 `11-load.py`", operations)
        self.assertIn("Docker：`reload-network → health → status`", operations)
        self.assertIn("Service IP 地址值改变属于 source write", operations)
        self.assertIn("宿主或容器重启恢复", operations)
        self.assertIn("部署事务中断恢复", operations)
        self.assertIn("多 Service IP、VLAN 子接口与 DHCP relay", operations)
        self.assertIn("amd64 与 arm64 预构建镜像", operations)
        self.assertIn("最终物理交换机验收", operations)

        for case_id in (
            "TC-REAL-DEPLOYMENT-MATRIX-001",
            "TC-REAL-SERVICE-IP-LIFECYCLE-001",
            "TC-REAL-RESTART-RECOVERY-001",
            "TC-REAL-ARCHITECTURE-MATRIX-001",
        ):
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, real_environment)

    def test_service_ip_move_and_formal_gate_guidance_match_current_contract(self):
        for relative in (
            "README.md",
            "docs/architecture/README.md",
            "docs/deployment/README.md",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(relative=relative):
                self.assertNotIn(
                    "Service IP 在宿主接口间移动后的动态 listener 重建",
                    text,
                )
                self.assertIn("reload-network", text)

        guide = (ROOT / "docs/deployment/BUNDLE_WORKFLOWS.md").read_text(
            encoding="utf-8",
        )
        self.assertIn("run_related_tests.py --check --require-full", guide)

    def test_relayed_upload_archive_has_one_server_side_safe_install_path(self):
        documents = {
            relative: (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "USER_MANUAL.md", "tools/README.md",
                "docs/deployment/README.md", "test_cases/REAL_ENVIRONMENT.md",
            )
        }
        for relative, text in documents.items():
            with self.subTest(relative=relative):
                self.assertIn("deploy-upload-archive.py", text)
                self.assertIn("--verify-only", text)
                self.assertIn("可信中转", text)
                self.assertIn("禁止", text)
        joined = "\n".join(documents.values())
        self.assertIn("installer 与 upload archive 一起被恶意替换", joined)
        self.assertIn("sudo install -o root -g root -m 0500", joined)
        self.assertIn("sudo install -o root -g root -m 0600", joined)

    def test_four_bundle_workflow_guide_is_linked_and_matches_public_clis(self):
        guide_path = ROOT / "docs/deployment/BUNDLE_WORKFLOWS.md"
        self.assertTrue(guide_path.is_file(), "four-bundle workflow guide is missing")
        guide = guide_path.read_text(encoding="utf-8")

        links = {
            "docs/deployment/README.md": "BUNDLE_WORKFLOWS.md",
            "infra/docker/README.md": "../../docs/deployment/BUNDLE_WORKFLOWS.md",
            "tools/README.md": "../docs/deployment/BUNDLE_WORKFLOWS.md",
            "USER_MANUAL.md": "docs/deployment/BUNDLE_WORKFLOWS.md",
            "test_cases/README.md": "../docs/deployment/BUNDLE_WORKFLOWS.md",
            "test_cases/REAL_ENVIRONMENT.md": "../docs/deployment/BUNDLE_WORKFLOWS.md",
        }
        for relative, target in links.items():
            with self.subTest(relative=relative):
                document = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(f"]({target})", document)

        for bundle_id in (
            "BUNDLE-1-GENERIC-IMAGE",
            "BUNDLE-2-UPLOAD-RELEASE",
            "BUNDLE-3-SHARED-ARTIFACTS",
            "BUNDLE-4-PROJECT-IMAGE",
        ):
            with self.subTest(bundle_id=bundle_id):
                self.assertIn(bundle_id, guide)

        self.assertIn("image-export /root/http-ztp-generic-amd64", guide)
        self.assertIn("`build-export` 只是 `image-export` 的兼容别名", guide)
        self.assertIn("项目无关", guide)
        self.assertIn("`http-ztp-ubuntu-24.04.tar`", guide)
        self.assertIn("`image-metadata.json`", guide)
        self.assertIn("--relay-bundle", guide)
        self.assertIn("deploy-upload-archive.py", guide)
        self.assertIn("package-shared-artifacts.py", guide)
        self.assertIn("自动从项目输入", guide)
        self.assertIn("`--apps-platform` 只在离线", guide)
        self.assertIn("`--firmware` 必须显式", guide)
        self.assertIn("`--no-upgrade` 不包含交换机镜像", guide)
        self.assertIn("package-project-image.py build", guide)
        self.assertIn("精确 upload release", guide)
        self.assertIn("可选 shared-artifact bundle", guide)
        self.assertIn("bootstrap-only", guide)
        self.assertIn("deploy-project-preloaded", guide)
        self.assertIn("自动绑定 shared metadata 中的 `upgrade_policy`", guide)
        self.assertIn(
            "`disabled` 时只输出并接受带 `--no-upgrade` 的部署命令",
            guide,
        )
        self.assertNotIn("工具不会自动\n从 shared metadata 推导该参数", guide)

        for scenario_id in (
            "BWF-2026-12-MAC",
            "BWF-2026-12-VM",
            "BWF-2026-12-DIRECT-NATIVE",
            "BWF-2026-12-DIRECT-DOCKER",
            "BWF-2026-12-GENERIC-PREBUILT",
            "BWF-2026-12-RELAY-NATIVE",
            "BWF-2026-12-RELAY-DOCKER",
            "BWF-2026-12-RELAY-PREBUILT",
            "BWF-2026-12-PROJECT-IMAGE",
        ):
            with self.subTest(scenario_id=scenario_id):
                self.assertIn(scenario_id, guide)

        self.assertIn("Native：重新执行统一 `11-load.py`", guide)
        self.assertIn("Docker：`reload-network → health → status`", guide)
        self.assertIn("Service IP 地址值改变属于项目输入变更", guide)

        deploy_shell = (ROOT / "infra/docker/deploy.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("image-export OUTPUT_DIR", deploy_shell)
        self.assertIn("build-export OUTPUT_DIR", deploy_shell)
        self.assertIn("deploy-project-preloaded IMAGE_ID [--no-upgrade]", deploy_shell)
        shared = load_path(
            "documentation_shared_bundle",
            ROOT / "tools/package-shared-artifacts.py",
        )
        shared_help = shared.parser().format_help()
        for option in ("--no-upgrade", "--apps-platform", "--firmware"):
            with self.subTest(shared_option=option):
                self.assertIn(option, shared_help)
        project_image = load_path(
            "documentation_project_image",
            ROOT / "tools/package-project-image.py",
        )
        project_parser = project_image.parser()
        project_help = project_parser.format_help()
        self.assertIn("{build,install}", project_help)
        build_parser = next(
            action.choices["build"]
            for action in project_parser._actions
            if getattr(action, "choices", None) and "build" in action.choices
        )
        self.assertIn("--no-upgrade", build_parser.format_help())
        upload = load_path(
            "documentation_upload_bundle",
            ROOT / "tools/tar-for-upload.py",
        )
        upload_args = upload.parse_args([
            "2026-12-vb-gb300", "--runtime", "docker",
            "--relay-bundle", "/tmp/2026-12-upload",
        ])
        self.assertEqual("docker", upload_args.runtime)
        self.assertEqual(Path("/tmp/2026-12-upload"), upload_args.relay_bundle)

        current_documents = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in (
                "USER_MANUAL.md",
                "docs/deployment/README.md",
                "docs/operations/README.md",
                "infra/docker/README.md",
                "tools/README.md",
                "test_cases/README.md",
                "test_cases/REAL_ENVIRONMENT.md",
            )
        )
        for stale_claim in (
            "included_upload_archive",
            "build-export` 在 build 前自动生成并验证当前项目 upload archive",
            "bundle 同时包含该 archive",
            "image tar、项目 upload、matching installer",
        ):
            with self.subTest(stale_claim=stale_claim):
                self.assertNotIn(stale_claim, current_documents)

        real_environment = (
            ROOT / "test_cases/REAL_ENVIRONMENT.md"
        ).read_text(encoding="utf-8")
        for case_id in (
            "TC-REAL-BUNDLE-GENERIC-001",
            "TC-REAL-BUNDLE-UPLOAD-001",
            "TC-REAL-BUNDLE-SHARED-001",
            "TC-REAL-BUNDLE-PROJECT-001",
        ):
            with self.subTest(case_id=case_id):
                self.assertIn(case_id, real_environment)
        self.assertIn(
            "shared upgrade policy 的 enabled/disabled 两条部署路径",
            real_environment,
        )

    def test_operator_docs_define_fixed_root_management_key_and_safe_remediation(self) -> None:
        authorities = (
            ROOT / "infra/docker/README.md",
            ROOT / "docs/operations/README.md",
            ROOT / "USER_MANUAL.md",
        )
        for path in authorities:
            text = path.read_text(encoding="utf-8")
            folded = text.casefold()
            flattened = " ".join(folded.split())
            with self.subTest(document=path.relative_to(ROOT).as_posix()):
                self.assertIn("/root/.ssh/id_ed25519", text)
                self.assertIn(
                    "/var/lib/http-ztp-container/ssh/id_ed25519", text,
                )
                self.assertIn("root", folded)
                self.assertIn("doctor", folded)
                self.assertIn("fingerprint", folded)
                self.assertIn("supervisor", folded)
                self.assertIn("hostlock", folded)
                self.assertIn("0700", folded)
                self.assertIn("unlink-by-inode", folded)
                self.assertIn("concurrent root", folded)
                self.assertIn("mount namespace", folded)
                self.assertIn("strictly stronger capabilities", flattened)
                self.assertIn("adds no capability", flattened)
                self.assertRegex(
                    flattened,
                    r"(?:不得|不能|never).{0,80}(?:手工|manual).{0,80}(?:复制|copy|删除|delete)",
                )
                self.assertRegex(
                    flattened,
                    r"(?:upload|sync|image|诊断).{0,160}(?:排除|exclude).{0,80}[.]ssh",
                )

    def test_opt006_docs_state_atomic_scope_provenance_and_air_policy(self):
        optimize = (ROOT / "ztp/optimize/README.md").read_text(encoding="utf-8")
        tracker = (
            ROOT / "ztp/optimize/issue-tracker/OPT-006-global-placeholder-backfill/README.md"
        ).read_text(encoding="utf-8")
        for document in (optimize, tracker):
            self.assertIn("deployment lock", document)
            self.assertIn("CAS", document)
            self.assertIn("source_scope", document)
            self.assertIn("AIR", document)
            self.assertIn("一次", document)
            self.assertIn("不参与 comparison", document)
            self.assertIn("publication-indeterminate", document)
            self.assertIn("published=true", document)
            self.assertIn("PREPARED", document)
            self.assertIn("4096", document)
            self.assertIn("O_DIRECTORY|O_NOFOLLOW", document)
            self.assertIn("ensure_ascii=True", document)
            self.assertIn("before_sha256", document)
            self.assertIn("after_sha256", document)
            self.assertIn("state-directory-fsync-failed", document)
            self.assertIn("storage_health", document)
            self.assertIn(
                "The implementation must not claim impossible compare-and-swap "
                "semantics from portable rename.",
                document,
            )

    def test_switch_collection_operator_docs_match_manual_and_continuous_contract(self):
        monitor_doc = (ROOT / "monitor/README.md").read_text(encoding="utf-8")
        user_doc = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        backup_doc = (ROOT / "ztp/backup/README.md").read_text(encoding="utf-8")
        real_cases = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8"
        )
        combined = "\n".join((monitor_doc, user_doc, backup_doc, real_cases))
        self.assertIn("Switch Status 默认关闭", combined)
        self.assertIn("信息收集", combined)
        self.assertIn("配置备份", combined)
        self.assertIn("持续收集", combined)
        self.assertIn("持续备份", combined)
        self.assertIn("最小 10 分钟", combined)
        self.assertIn("收集与备份可以同时运行", combined)
        self.assertIn("同类型共用 10 分钟冷却", combined)
        self.assertIn("停止持续收集不会停止配置备份", combined)
        self.assertIn("停止中，等待当前任务完成", combined)
        self.assertIn("单次执行；开始后不可中断", combined)
        self.assertIn("停止只取消后续轮次", combined)
        self.assertIn("完成但有警告", combined)
        self.assertIn("失败设备", combined)
        self.assertNotIn("点击收集后按钮立即变为“停止收集”", combined)
        self.assertIn("持续备份凭据仅保存在 root worker 内存", combined)
        self.assertIn("inode 绑定的 `0600` FIFO", combined)
        self.assertIn("项目 + scope + target", combined)
        self.assertIn("AIR 与 Production 可以使用同一用户名和密码", combined)
        self.assertIn("不会合并 host-key pin 身份", combined)
        self.assertIn("`StrictHostKeyChecking=yes`", combined)
        self.assertIn("`KnownHostsCommand`", combined)
        self.assertIn("首次连接 TOFU", combined)
        self.assertIn("唯一修复命令", combined)
        self.assertIn("TC-REAL-BACKUP-KHC-SSHD-001", real_cases)
        self.assertIn("CI NOT-COVERED", real_cases)
        self.assertIn("TC-REAL-BACKUP-SCOPE-PIN-002", real_cases)
        self.assertIn("askpass/sudo 之前", real_cases)
        self.assertIn("worker 重启后不会自动恢复", combined)

    def test_rotation_operator_docs_record_defaults_human_tty_and_machine_record(self) -> None:
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        self.assertIn(
            "初始用户名/密码为 `nvis` / `nvidia` 和 `cumulus` / `cumulus`",
            manual,
        )
        self.assertIn("首次登录后立即轮换两组初始凭据", manual)
        self.assertIn("必须由人类操作员在管理服务器的交互终端执行", manual)
        self.assertIn("不能用于无人值守或自动化任务", manual)
        self.assertIn(
            "容器内提示和诊断只显示在该终端；hostlock 独立输出的 JSON 才是机器记录",
            manual,
        )

        real = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        self.assertIn("TC-REAL-DOCKER-AUTH-ROTATE-TTY-001", real)
        self.assertIn("`nvis` / `nvidia`", real)
        self.assertIn("`cumulus` / `cumulus`", real)
        self.assertIn("人类操作员", real)
        self.assertIn("不可自动化", real)
        self.assertIn("两个密码提示均不回显字符", real)
        self.assertIn("hostlock JSON", real)

        public_manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        monitor_section = public_manual.split(
            '<p><strong>Monitor 登录：</strong>', 1,
        )[1].split('<p><strong>操作命令</strong>', 1)[0]
        self.assertIn("受控交付的初始凭据", monitor_section)
        self.assertIn("立即轮换", monitor_section)
        self.assertIn("人类操作员", monitor_section)
        self.assertIn("不可自动化", monitor_section)
        self.assertIn("hostlock", monitor_section)
        self.assertIn("JSON", monitor_section)
        self.assertNotRegex(
            monitor_section.casefold(),
            r"nvis.{0,80}nvidia|初始密码.{0,80}<code>[^<]+</code>",
        )

    def test_generated_init_and_offline_export_are_the_documented_primary_paths(self) -> None:
        docker = (DOCKER_ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        operations = (ROOT / "docs/operations/README.md").read_text(
            encoding="utf-8",
        )
        governance = (ROOT / "test_cases/README.md").read_text(encoding="utf-8")
        real = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        for document in (docker, manual, operations):
            with self.subTest(document=document[:40]):
                self.assertIn("deploy.sh init --project", document)
                self.assertIn("--scope air --mini", document)
                self.assertIn("build-export", document)
                self.assertIn("SHA256SUMS", document)
                self.assertIn("deploy-preloaded", document)
        first_deploy = docker.split("## 初次部署", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("sudoedit", first_deploy)
        self.assertIn("参数化 init", governance)
        self.assertIn("build-export", governance)
        self.assertIn("TC-REAL-DOCKER-PRELOADED-001", real)
        self.assertIn("sha256sum --check SHA256SUMS", real)
        self.assertIn("docker load --input", real)

    def test_noexec_tmp_askpass_contract_spans_container_and_collector(self) -> None:
        compose = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        supervisor = (DOCKER_ROOT / "supervisord.conf").read_text(encoding="utf-8")
        collector = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        activate = (DOCKER_ROOT / "activate.py").read_text(encoding="utf-8")
        deploy = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        docker_doc = (DOCKER_ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")

        self.assertRegex(compose, r"(?m)^\s*- /run:.*\bexec\b")
        self.assertRegex(compose, r"(?m)^\s*- /tmp:.*\bnoexec\b")
        self.assertIn(
            "HTTP_ZTP_ASKPASS_TMPDIR: /run/http-ztp/askpass", compose,
        )
        switch_section = supervisor.split(
            "[program:switch-collection]", 1,
        )[1].split("[program:", 1)[0]
        self.assertIn(
            'environment=HTTP_ZTP_ASKPASS_TMPDIR="/run/http-ztp/askpass"',
            switch_section,
        )
        runtime_dirs = activate.split(
            "def ensure_runtime_directories", 1,
        )[1].split("\ndef ", 1)[0]
        self.assertIn('Path("/run/http-ztp/askpass"), 0o700', runtime_dirs)
        self.assertIn("HTTP_ZTP_ASKPASS_TMPDIR", collector)
        self.assertIn("HTTP_ZTP_ASKPASS_TMPDIR", deploy)
        self.assertNotIn(
            'mktemp "${TMPDIR:-/tmp}/monitor-ssh-askpass.XXXXXX"',
            collector,
        )
        for document in (docker_doc, manual):
            with self.subTest(document=document[:40]):
                self.assertIn("`0600` FIFO", document)
                self.assertIn("`StrictHostKeyChecking=yes`", document)
                self.assertIn("`KnownHostsCommand`", document)
                self.assertIn("`CheckHostIP=no`", document)
                self.assertIn("`UpdateHostKeys=no`", document)
                self.assertIn("OpenSSH 8.5", document)

    def test_ubuntu_22_host_keeps_the_container_contract_on_ubuntu_24(self) -> None:
        deploy = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        dockerfile = (DOCKER_ROOT / "Dockerfile").read_text(encoding="utf-8")
        compose = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        docker_readme = (DOCKER_ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs/deployment/README.md").read_text(
            encoding="utf-8",
        )
        reference = (ROOT / "docs/reference/README.md").read_text(
            encoding="utf-8",
        )

        for document in (docker_readme, manual, deployment, reference):
            with self.subTest(document=document[:40]):
                self.assertIn("Ubuntu 22.04", document)
                self.assertIn("Ubuntu 24.04", document)
        self.assertIn("Ubuntu 22.04 或 24.04", docker_readme)
        self.assertIn("FROM ubuntu:24.04", dockerfile)
        self.assertIn(
            'com.nvidia.http-ztp.base-os="ubuntu-24.04"', dockerfile,
        )
        self.assertIn("image: http-ztp:ubuntu-24.04", compose)
        self.assertIn('image_name="http-ztp:ubuntu-24.04"', deploy)
        self.assertNotIn("FROM ubuntu:22.04", dockerfile)

    def test_docker_docs_cover_server_scenarios_and_service_ip_move(self) -> None:
        docker = (DOCKER_ROOT / "README.md").read_text(encoding="utf-8")
        operations = (ROOT / "docs/operations/README.md").read_text(
            encoding="utf-8",
        )
        manual = (ROOT / "USER_MANUAL.md").read_text(encoding="utf-8")
        tools = (ROOT / "tools/README.md").read_text(encoding="utf-8")
        for text in (docker, operations, manual, tools):
            with self.subTest(document=text[:40]):
                self.assertIn("Service IP 从接口 A 移到接口 B", text)
                self.assertIn("reload-network", text)
                self.assertIn("不得运行宿主 `systemctl restart isc-dhcp-server`", text)
                self.assertIn("不得直接执行 `supervisorctl restart dhcpd`", text)
                self.assertIn("项目或源码有写入", text)
                self.assertIn("deploy-preloaded", text)
        self.assertIn("## 服务器部署场景矩阵", docker)
        matrix = docker.split("## 服务器部署场景矩阵", 1)[1].split("\n## ", 1)[0]
        for scenario in (
            "首次在线部署", "首次离线部署", "AIR mini", "Production",
            "源码或项目输入更新", "unload/隔离恢复", "Service IP 换接口",
            "宿主或容器重启", "DHCP relay", "停止并保留数据",
        ):
            with self.subTest(scenario=scenario):
                self.assertIn(scenario, matrix)
        for relative in (
            "README.md", "USER_MANUAL.md", "docs/architecture/README.md",
            "docs/deployment/README.md", "docs/operations/README.md",
            "infra/docker/README.md",
        ):
            normalized = " ".join((ROOT / relative).read_text(
                encoding="utf-8",
            ).split())
            with self.subTest(runtime_boundary=relative):
                self.assertIn("没有 source write 且受管容器仍在运行", normalized)
                self.assertNotIn(
                    "仅用于没有 source write 且已有运行中的 inactive 控制容器",
                    normalized,
                )
                self.assertNotIn(
                    "若没有 source write 且已有运行中的 inactive 控制容器",
                    normalized,
                )


if __name__ == "__main__":
    unittest.main()
