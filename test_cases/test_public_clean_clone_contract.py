#!/usr/bin/env python3
"""Direct contracts for public/private docs and clean-checkout governance."""

import ast
import importlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test_cases/script_test_manifest.json"
PRIVATE_MODULE = "test_cases/test_private_documentation_contract.py"
EXPECTED_PRIVATE_DOCUMENT_PATHS = (
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
Q02_FUTURE_TRACKED_SUPPORT_PATHS = (
    ".dockerignore",
    ".github/workflows/monitor-authority-root.yml",
    "docs/README.md",
    "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md",
    "docs/deployment/README.md",
    "docs/operations/README.md",
    "docs/reference/README.md",
    "docs/validation/README.md",
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
    "test_cases/monitor_authority_root_warden.py",
    "test_cases/monitor_authority_source_guard.py",
    "test_cases/public_project_fixture.py",
    "test_cases/run_monitor_authority_entrypoints.sh",
    "test_cases/run_vm_validation.py",
    "tools/lldp-analyze-tool/04-lldp-device-aliases.json",
    "user-manual.html",
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
Q02_PHASE_TEST_MODULES = (
    "test_cases.test_public_clean_clone_contract",
    "test_cases.test_private_documentation_contract",
    "test_cases.test_public_clean_clone_workflow",
)
P_PHASE_TEST_MODULES = (
    "test_cases.test_public_publication_contract",
    "test_cases.test_public_publication_workflow",
)
Q02_TRACKED_SUPPORT_SYMLINK_TARGETS = {
    "ztp/config/nvos/template/P2P/01-inventory.log": (
        "../../../cumulus/template/P2P/01-inventory.log"
    ),
    "ztp/config/nvos/template/P2P/02-port-mapping.log": (
        "../../../cumulus/template/P2P/02-port-mapping.log"
    ),
    "ztp/config/nvos/template/P2P/03-splitter.log": (
        "../../../cumulus/template/P2P/03-splitter.log"
    ),
}
Q02_REMAINING_TRACKED_SUPPORT_PATHS = (
    ".gitattributes",
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
    "examples/public-project/01-global.yaml.example",
    "examples/public-project/02-devices_config.csv.example",
    "examples/public-project/02-dhcp-subnet_config.csv.example",
    "index.html",
    "requirements-dev.txt",
    "test_cases/REAL_ENVIRONMENT.md",
    "test_cases/audit_public_tree.py",
    "test_cases/run_related_tests.py",
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
Q02_UNEXPECTED_TRACKED_SUPPORT = "test_cases/CASE_TEMPLATE.md"
PUBLIC_DOC_AUTHORITIES = Q01_PUBLIC_DOCUMENT_PATHS
V2_FORBIDDEN_LIFECYCLE_DOCS = Q05_V2_FORBIDDEN_LIFECYCLE_PATHS


def _manifest_path_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _manifest_path_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _manifest_path_values(item)


def q02_manifest_violations(manifest) -> set[str]:
    tracked_support = set(manifest.get("tracked_support", ()))
    violations = tracked_support.intersection(
        {"USER_MANUAL.md", *Q02_FUTURE_TRACKED_SUPPORT_PATHS}
    )
    violations.update(
        set(_manifest_path_values(manifest)).intersection(
            Q05_V2_FORBIDDEN_LIFECYCLE_PATHS
        )
    )
    return violations


def tracked_support_path_violations(
    root: Path, paths, symlink_targets,
) -> set[str]:
    violations = set()
    for relative in paths:
        tracked = subprocess.run(
            ["git", "ls-files", "-z", "--", relative], cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        expected = relative.encode("utf-8") + b"\0"
        ignored = subprocess.run(
            ["git", "check-ignore", "--no-index", "--quiet", "--", relative],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        try:
            metadata = (root / relative).lstat()
        except OSError:
            violations.add(relative)
            continue
        expected_target = symlink_targets.get(relative)
        safe_type = (
            stat.S_ISLNK(metadata.st_mode)
            and metadata.st_nlink == 1
            and expected_target is not None
            and os.readlink(root / relative) == expected_target
        ) if stat.S_ISLNK(metadata.st_mode) else (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and expected_target is None
        )
        if tracked.returncode != 0 or tracked.stdout != expected:
            violations.add(relative)
        if ignored.returncode != 1:
            violations.add(relative)
        if not safe_type:
            violations.add(relative)
    return violations


def q02_tracked_support_violations(root: Path, manifest) -> set[str]:
    future = {"USER_MANUAL.md", *Q02_FUTURE_TRACKED_SUPPORT_PATHS}
    remaining = set(manifest.get("tracked_support", ())) - future
    expected_remaining = set(Q02_REMAINING_TRACKED_SUPPORT_PATHS)
    violations = remaining.symmetric_difference(expected_remaining)
    violations.update(tracked_support_path_violations(
        root, expected_remaining, Q02_TRACKED_SUPPORT_SYMLINK_TARGETS,
    ))
    return violations


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


class _PrivateReadScanner(ast.NodeVisitor):
    READ_METHODS = {"read_text", "read_bytes", "open"}

    def __init__(self, private_paths):
        self.private_paths = set(private_paths)
        self.environments = [{}]
        self.call_returns = {}
        self.hits = set()
        self.skip_hits = set()

    @property
    def environment(self):
        return self.environments[-1]

    def _values(self, node):
        non_root_bases = {
            item.id for item in ast.walk(node)
            if isinstance(item, ast.Name) and item.id in {"CASES", "DOCKER_ROOT"}
        }
        values = {
            value for value in (
                item.value for item in ast.walk(node)
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            ) if value in self.private_paths
            and not (value == "README.md" and non_root_bases)
        }
        for item in ast.walk(node):
            if isinstance(item, ast.Name):
                values.update(self.environment.get(item.id, ()))
                values.update(self.call_returns.get(item.id, ()))
            elif isinstance(item, ast.Attribute):
                values.update(self.call_returns.get(item.attr, ()))
        return values

    def _bind(self, target, values):
        if isinstance(target, ast.Name):
            self.environment[target.id] = set(values)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._bind(item, values)

    def visit_Assign(self, node):
        values = self._values(node.value)
        for target in node.targets:
            self._bind(target, values)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._bind(node.target, self._values(node.value))
        self.generic_visit(node)

    def visit_For(self, node):
        saved = dict(self.environment)
        self._bind(node.target, self._values(node.iter))
        for statement in node.body:
            self.visit(statement)
        self.environments[-1] = saved
        for statement in node.orelse:
            self.visit(statement)

    def visit_ListComp(self, node):
        saved = dict(self.environment)
        for generator in node.generators:
            self._bind(generator.target, self._values(generator.iter))
        self.visit(node.elt)
        self.environments[-1] = saved

    visit_SetComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_FunctionDef(self, node):
        returned = set()
        for item in ast.walk(node):
            if isinstance(item, ast.Return) and item.value is not None:
                returned.update(self._values(item.value))
        if returned:
            self.call_returns.setdefault(node.name, set()).update(returned)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        function_name = None
        if isinstance(node.func, ast.Attribute):
            function_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            function_name = node.func.id
        if function_name in {"skip", "skipIf", "skipUnless", "skipTest"}:
            self.skip_hits.update(self._values(node))
        if isinstance(node.func, ast.Attribute) and node.func.attr in self.READ_METHODS:
            self.hits.update(self._values(node.func.value))
        elif isinstance(node.func, ast.Name) and node.func.id == "open" and node.args:
            self.hits.update(self._values(node.args[0]))
        self.generic_visit(node)


def private_root_reads(source: str, private_paths) -> set[str]:
    scanner = _PrivateReadScanner(private_paths)
    tree = ast.parse(source)
    function_count = sum(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for node in ast.walk(tree)
    )
    for _ in range(function_count + 1):
        before = {name: frozenset(values) for name, values in scanner.call_returns.items()}
        scanner.visit(tree)
        after = {name: frozenset(values) for name, values in scanner.call_returns.items()}
        if after == before:
            break
    return scanner.hits


def private_individual_skips(source: str, private_paths) -> set[str]:
    scanner = _PrivateReadScanner(private_paths)
    scanner.visit(ast.parse(source))
    return scanner.skip_hits


def individual_skip_calls(source: str) -> list[str]:
    skip_names = {"skip", "skipIf", "skipUnless", "skipTest"}

    class AliasAwareSkipScanner(ast.NodeVisitor):
        def __init__(self):
            self.aliases = {name: name for name in skip_names}
            self.calls = []

        def resolve(self, node):
            if isinstance(node, ast.Name):
                return self.aliases.get(node.id)
            if isinstance(node, ast.Attribute) and node.attr in skip_names:
                return node.attr
            return None

        def bind(self, target, canonical):
            if canonical is not None and isinstance(target, ast.Name):
                self.aliases[target.id] = canonical

        def visit_ImportFrom(self, node):
            if node.module == "unittest":
                for alias in node.names:
                    if alias.name in skip_names:
                        self.aliases[alias.asname or alias.name] = alias.name

        def visit_Assign(self, node):
            canonical = self.resolve(node.value)
            for target in node.targets:
                self.bind(target, canonical)
            self.generic_visit(node)

        def visit_AnnAssign(self, node):
            if node.value is not None:
                self.bind(node.target, self.resolve(node.value))
            self.generic_visit(node)

        def visit_Call(self, node):
            canonical = self.resolve(node.func)
            if canonical is not None:
                self.calls.append(canonical)
            self.generic_visit(node)

    scanner = AliasAwareSkipScanner()
    scanner.visit(ast.parse(source))
    return sorted(scanner.calls)


class PublicCleanCloneDirectTests(unittest.TestCase):
    def test_q02_phase_modules_have_one_repository_governance_suite(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        memberships = {
            module: [
                suite["id"] for suite in manifest["test_suites"]
                if module in suite["tests"]
            ]
            for module in Q02_PHASE_TEST_MODULES
        }
        self.assertEqual(
            {module: ["repository-governance"] for module in Q02_PHASE_TEST_MODULES},
            memberships,
        )
        p_memberships = {
            module: [
                suite["id"] for suite in manifest["test_suites"]
                if module in suite["tests"]
            ]
            for module in P_PHASE_TEST_MODULES
        }
        self.assertEqual(
            {module: [] for module in P_PHASE_TEST_MODULES}, p_memberships,
            "P-phase modules must not be registered in the Q02 manifest",
        )

    def test_q02_manifest_excludes_private_and_future_publication_paths(self):
        self.assertEqual(8, len(Q01_PUBLIC_DOCUMENT_PATHS))
        self.assertEqual(29, len(Q02_FUTURE_TRACKED_SUPPORT_PATHS))
        self.assertEqual(7, len(Q05_V2_FORBIDDEN_LIFECYCLE_PATHS))
        self.assertEqual(
            set(Q01_PUBLIC_DOCUMENT_PATHS),
            set(Q01_PUBLIC_DOCUMENT_PATHS).intersection(
                Q02_FUTURE_TRACKED_SUPPORT_PATHS
            ),
        )
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            set(), q02_manifest_violations(manifest),
            "Q02 manifest must not publish USER_MANUAL.md, the future 29-path "
            "support set, or the seven Q05 lifecycle paths",
        )

    def test_q02_manifest_rejects_each_readded_future_authority(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["tracked_support"] = [
            path for path in manifest["tracked_support"]
            if path not in {"USER_MANUAL.md", *Q02_FUTURE_TRACKED_SUPPORT_PATHS}
        ]
        self.assertEqual(set(), q02_manifest_violations(manifest))
        for relative in (
            "USER_MANUAL.md",
            *Q02_FUTURE_TRACKED_SUPPORT_PATHS,
            *Q05_V2_FORBIDDEN_LIFECYCLE_PATHS,
        ):
            with self.subTest(path=relative):
                candidate = json.loads(json.dumps(manifest))
                candidate["tracked_support"].append(relative)
                self.assertEqual(
                    {relative}, q02_manifest_violations(candidate),
                )

    def test_q02_remaining_tracked_support_is_exact_nonignored_and_safe(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        remaining = set(manifest["tracked_support"]) - {
            "USER_MANUAL.md", *Q02_FUTURE_TRACKED_SUPPORT_PATHS,
        }
        self.assertEqual(70, len(Q02_REMAINING_TRACKED_SUPPORT_PATHS))
        self.assertEqual(set(Q02_REMAINING_TRACKED_SUPPORT_PATHS), remaining)
        self.assertEqual(
            set(Q02_TRACKED_SUPPORT_SYMLINK_TARGETS),
            {
                relative for relative in remaining
                if (ROOT / relative).is_symlink()
            },
        )
        self.assertEqual(set(), q02_tracked_support_violations(ROOT, manifest))

        swapped = json.loads(json.dumps(manifest))
        removed = Q02_REMAINING_TRACKED_SUPPORT_PATHS[0]
        swapped["tracked_support"].remove(removed)
        swapped["tracked_support"].append(Q02_UNEXPECTED_TRACKED_SUPPORT)
        self.assertEqual(
            {removed, Q02_UNEXPECTED_TRACKED_SUPPORT},
            q02_tracked_support_violations(ROOT, swapped),
            "same-count replacement by another safe tracked file must fail",
        )

        with tempfile.TemporaryDirectory() as directory:
            hostile = Path(directory)
            subprocess.run(
                ["git", "init", "--quiet"], cwd=hostile,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            child = hostile / "support/authority/child.txt"
            child.parent.mkdir(parents=True)
            child.write_text("descendant only\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "--", "support/authority/child.txt"], cwd=hostile,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            self.assertEqual(
                {"support/authority"},
                tracked_support_path_violations(
                    hostile, ("support/authority",), {},
                ),
            )

    def test_q02_private_gate_is_all_none_partial_and_opt_growth_fail_closed(self):
        private = importlib.import_module(
            "test_cases.test_private_documentation_contract"
        )
        self.assertEqual(
            EXPECTED_PRIVATE_DOCUMENT_PATHS, private.PRIVATE_DOCUMENT_PATHS,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(unittest.SkipTest, private.PRIVATE_TIER_SKIP_REASON):
                private.require_complete_private_document_tier(root)

            expected = [Path(item) for item in EXPECTED_PRIVATE_DOCUMENT_PATHS]
            for relative in expected:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("private fixture\n", encoding="utf-8")
            private.require_complete_private_document_tier(root)

            missing = expected[-1]
            (root / missing).unlink()
            with self.assertRaisesRegex(AssertionError, missing.as_posix()) as raised:
                private.require_complete_private_document_tier(root)
            reported = str(raised.exception).split("missing: ", 1)[1].split(", ")
            self.assertEqual([missing.as_posix()], reported)

            (root / missing).write_text("private fixture\n", encoding="utf-8")
            unexpected = root / "ztp/optimize/issue-tracker/OPT-010-new/README.md"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_text("private fixture\n", encoding="utf-8")
            with self.assertRaisesRegex(
                AssertionError, r"OPT-010-new.*test_cases\.test_private_documentation_contract:PRIVATE_DOCUMENT_PATHS",
            ):
                private.require_complete_private_document_tier(root)

    def test_q02_static_guard_finds_direct_list_loop_and_comprehension_reads(self):
        private = importlib.import_module(
            "test_cases.test_private_documentation_contract"
        )
        self.assertEqual(
            EXPECTED_PRIVATE_DOCUMENT_PATHS, private.PRIVATE_DOCUMENT_PATHS,
        )
        helper_fixture = '''
PRIVATE = ROOT / "USER_MANUAL.md"
def source():
    return PRIVATE
alias = source
source().read_text()
alias().read_bytes()
class SourceFactory:
    def source(self):
        return PRIVATE
SourceFactory().source().read_text()
'''
        self.assertEqual(
            {"USER_MANUAL.md"},
            private_root_reads(helper_fixture, EXPECTED_PRIVATE_DOCUMENT_PATHS),
        )
        attribute_fixture = '''
PRIVATE = ROOT / "USER_MANUAL.md"
class SourceFactory:
    def source(self):
        return PRIVATE
SourceFactory().source().read_text()
'''
        self.assertEqual(
            {"USER_MANUAL.md"},
            private_root_reads(attribute_fixture, EXPECTED_PRIVATE_DOCUMENT_PATHS),
        )

    def test_q02_no_test_individually_skips_an_expected_private_document(self):
        fixture = '''
private = ROOT / "USER_MANUAL.md"
@unittest.skipUnless(private.is_file(), "private")
def test_private():
    pass
'''
        self.assertEqual(
            {"USER_MANUAL.md"},
            private_individual_skips(fixture, EXPECTED_PRIVATE_DOCUMENT_PATHS),
        )
        computed_fixture = '''
PRIVATE_READY = bool(chr(112))
@unittest.skipUnless(PRIVATE_READY, chr(112))
def test_private():
    self.skipTest(chr(112))
'''
        self.assertEqual(
            ["skipTest", "skipUnless"], individual_skip_calls(computed_fixture),
        )
        alias_fixture = '''
from unittest import skipUnless as gate
import unittest as u
block = u.skipIf
@gate(False, chr(112))
def one():
    pass
@block(True, chr(112))
def two():
    pass
'''
        self.assertEqual(
            ["skipIf", "skipUnless"], individual_skip_calls(alias_fixture),
        )
        offenders = {}
        for path in sorted((ROOT / "test_cases").glob("test_*.py")):
            hits = private_individual_skips(
                path.read_text(encoding="utf-8"), EXPECTED_PRIVATE_DOCUMENT_PATHS,
            )
            if hits:
                offenders[path.relative_to(ROOT).as_posix()] = sorted(hits)
        self.assertEqual({}, offenders)

        private_source = (ROOT / PRIVATE_MODULE).read_text(encoding="utf-8")
        self.assertEqual([], individual_skip_calls(private_source))
        private_tree = ast.parse(private_source)
        skip_calls = [
            node for node in ast.walk(private_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "SkipTest"
        ]
        self.assertEqual(1, len(skip_calls), "private tier must have one whole-tier skip")
        fixture = '''
direct = (ROOT / "USER_MANUAL.md").read_text()
paths = [ROOT / name for name in ("monitor/README.md", "docs/README.md")]
for path in paths:
    path.read_bytes()
texts = [(ROOT / name).read_text() for name in ("tools/README.md",)]
mention_only = "DAY0-Prepare/README.md"
'''
        self.assertEqual(
            {"USER_MANUAL.md", "monitor/README.md", "tools/README.md"},
            private_root_reads(fixture, EXPECTED_PRIVATE_DOCUMENT_PATHS),
        )

    def test_q02_no_public_test_module_reads_a_private_document(self):
        private = importlib.import_module(
            "test_cases.test_private_documentation_contract"
        )
        self.assertEqual(
            EXPECTED_PRIVATE_DOCUMENT_PATHS, private.PRIVATE_DOCUMENT_PATHS,
        )
        offenders = {}
        for path in sorted((ROOT / "test_cases").glob("test_*.py")):
            relative = path.relative_to(ROOT).as_posix()
            if relative == PRIVATE_MODULE:
                continue
            hits = private_root_reads(
                path.read_text(encoding="utf-8"), EXPECTED_PRIVATE_DOCUMENT_PATHS,
            )
            if hits:
                offenders[relative] = sorted(hits)
        self.assertEqual({}, offenders)


if __name__ == "__main__":
    unittest.main()
