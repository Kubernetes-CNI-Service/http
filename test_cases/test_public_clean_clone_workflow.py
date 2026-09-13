#!/usr/bin/env python3
"""Workflow proof for the public test surface in a private-doc-free checkout."""

import copy
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from test_cases.test_public_clean_clone_contract import (
    Q02_REMAINING_TRACKED_SUPPORT_PATHS,
    Q02_TRACKED_SUPPORT_SYMLINK_TARGETS,
)

ROOT = Path(__file__).resolve().parents[1]
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
Q02_PHASE_OVERLAY_PATHS = (
    "test_cases/test_public_clean_clone_contract.py",
    "test_cases/test_private_documentation_contract.py",
    "test_cases/test_public_clean_clone_workflow.py",
    "test_cases/script_test_manifest.json",
    "test_cases/README.md",
)
P_PHASE_TEST_PATHS = (
    "test_cases/test_public_publication_contract.py",
    "test_cases/test_public_publication_workflow.py",
)
Q02_FUTURE_TEST_MODULE_PATHS = (
    "test_cases/test_backup_auth_transport_workflow.py",
    "test_cases/test_bootstrap_config_fetch_contract.py",
    "test_cases/test_bootstrap_config_fetch_workflow.py",
    "test_cases/test_collector_inventory_pubkey.py",
    "test_cases/test_collector_inventory_pubkey_workflow.py",
    "test_cases/test_control_auth.py",
    "test_cases/test_deploy_upload_archive.py",
    "test_cases/test_dhcp_switch_scope_preservation.py",
    "test_cases/test_dhcp_switch_scope_preservation_workflow.py",
    "test_cases/test_docker_destructive_confirmation.py",
    "test_cases/test_docker_destructive_confirmation_workflow.py",
    "test_cases/test_docker_management_ssh_key.py",
    "test_cases/test_feedback_global_writeback.py",
    "test_cases/test_feedback_global_writeback_workflow.py",
    "test_cases/test_monitor_authority_entrypoints.py",
    "test_cases/test_monitor_authority_semantic_workflow.py",
    "test_cases/test_monitor_authority_source_guard.py",
    "test_cases/test_monitor_writer_quiesce.py",
    "test_cases/test_monitor_writer_quiesce_workflow.py",
    "test_cases/test_password_update.py",
    "test_cases/test_project_image_bundle.py",
    "test_cases/test_public_project_fixture_contract.py",
    "test_cases/test_public_project_fixture_workflow.py",
    "test_cases/test_shared_artifact_bundle.py",
    "test_cases/test_topology_consistency.py",
    "test_cases/test_vm_validation_runner.py",
    "test_cases/test_xlsx_zero_row_fail_closed.py",
    "test_cases/test_xlsx_zero_row_workflow.py",
    "test_cases/test_ztp_container_runtime.py",
    "test_cases/test_ztp_monitor_watch_resilience.py",
    "test_cases/test_ztp_monitor_watch_runtime_workflow.py",
    "test_cases/test_ztp_service_runtime.py",
)
Q02_CABLETRACKER_PREFIX = "monitor/cabletracker-main"
Q02_PUBLIC_PRIVATE_README_SECTION = """
## Q02 公开/私有测试分层

Q02 公开提交的测试边界遵循以下五点合同：

1. 公开测试只读取 Git 已跟踪且未被 ignore 的公开文件，不依赖本地私有文档。
2. 私有层固定精确 23 条文档清单，`PrivateDocumentationContractTests.setUpClass` 是唯一 class-level 整层门禁；全部缺失时仅以 `unittest.SkipTest("private documentation tier absent in public checkout")` 恰好 skip 一次，部分缺失时硬失败，全部存在时全部运行。
3. 禁止按单个私有文件 skip，也禁止把私有文档复制进公开候选树。
4. no-local clean clone 是唯一承重语义证据；AST guard 仅用于防御纵深，不能替代 clean clone，也不能单独作为通过证据。
5. `tracked_support` 仅列出已跟踪且未被 ignore 的支持文件，不得吸收 ignored 或 untracked 路径。
"""
Q02_BASE_REVISION = "133f985ad4b5bd2d8d90713a51bb01f23bc7d89c"
Q02_PHASE_REVISION = "623bf4ec48203c3c02a3d0bf79271d6c4c637a2a"
Q02_PHASE_MANIFEST_SHA256 = "320e6489cf041eca71af44b192657b10d5bf06c27391d179739a4b57f33dfd54"
Q02_BASE_README_SHA256 = "ecad054661280bdfe5d92a300ca44b17a861c674bff77042a45a5b00de321795"
Q02_PHASE_README_SHA256 = "9df3ef0f9851c7b4622ca358bbfb9d2abca2fea2884b4023c0245fedc4b46c47"
Q02_PHASE_MAPPING_DIGESTS = {
    "baseline_tests": "a16e66c6173de4bad1d5533c340ed7f4f0707094b27e1b40ca3485a658621147",
    "test_rules": "ec19144051217d373bc30f62adc177b68e59cf7bbee3856f54addeebff6b04aa",
    "workflows": "8b4faae40df871de0d27f59976b4a7d59b1cdb65822401b4e169fe3ebfebbc57",
    "path_rules": "24c4352e651e3018fd687c4469f42bcb2dd715cea0cd357983e4abc87ccad2f9",
}
Q02_PHASE_TEST_SUITES = (
    {
        "id": "repository-governance",
        "description": "仓库入口、测试治理、公开边界和文档目录合同",
        "tests": (
            "test_cases.test_all_script_entrypoints",
            "test_cases.test_change_aware_test_runner",
            "test_cases.test_documentation_catalog",
            "test_cases.test_private_documentation_contract",
            "test_cases.test_public_clean_clone_contract",
            "test_cases.test_public_clean_clone_workflow",
            "test_cases.test_public_repository_contract",
            "test_cases.test_test_case_repository",
        ),
    },
    {
        "id": "packaging-sync",
        "description": "上传、下载、同步、诊断和部署前门禁",
        "tests": (
            "test_cases.test_deployment_writer_lock",
            "test_cases.test_diagnostic_bundle",
            "test_cases.test_download_cli_contract",
            "test_cases.test_import_from_download_target",
            "test_cases.test_predeploy_test_gate",
            "test_cases.test_upload_package_contract",
        ),
    },
    {
        "id": "deployment-runtime",
        "description": "宿主部署、发布事务、Apache、DHCP 和服务运行时",
        "tests": (
            "test_cases.test_apache_publication_boundary",
            "test_cases.test_infra_check_and_manual_reset",
            "test_cases.test_load_release_transaction",
            "test_cases.test_ops_deployment_review",
        ),
    },
    {
        "id": "configuration-generation",
        "description": "项目 schema、Cumulus/NVUE、MLAG/EVPN、QoS、STP 和配置生成",
        "tests": (
            "test_cases.test_cumulus_snippet_rendering",
            "test_cases.test_flow_release_platform_matrix",
            "test_cases.test_mlag_evpn_generation",
            "test_cases.test_nvue_normalizer",
            "test_cases.test_optimize_output_layout",
            "test_cases.test_project_contracts",
            "test_cases.test_qos_evpn_uplink_generation",
            "test_cases.test_terminal_l2_stp_generation",
            "test_cases.test_v2_generation_flow",
            "test_cases.test_v2_project_schema",
        ),
    },
    {
        "id": "monitoring-collection",
        "description": "监控页面、IB 分析、手工比对和分组交接",
        "tests": (
            "test_cases.test_ib_analysis_domain",
            "test_cases.test_manual_applied_config",
            "test_cases.test_monitor_stack_review",
            "test_cases.test_ztp_group_handoff",
            "test_cases.test_ztp_group_handoff_display",
        ),
    },
    {
        "id": "ztp-runtime",
        "description": "DHCP 租约、ZTP 身份、前缀边界、应用回执和端到端运行流",
        "tests": (
            "test_cases.test_dhcp_runtime_reassignment",
            "test_cases.test_full_flow_integration",
            "test_cases.test_ztp_applied_receipt",
            "test_cases.test_ztp_http_identity_binding",
            "test_cases.test_ztp_prefix_runtime_boundary",
            "test_cases.test_ztp_release_core_review",
        ),
    },
)
Q02_BASE_PRODUCTION_SCRIPT_PATHS = frozenset("""\
DAY0-Prepare/01-a-setup.py
DAY0-Prepare/02-unsetup.py
DAY0-Prepare/11-load.py
DAY0-Prepare/12-ztp-monitor.py
DAY0-Prepare/13-unload.py
ethernet/monitor/cron.sh
ethernet/monitor/post-collect.py
ethernet/monitor/sw-info.sh
ethernet/monitor/sw-link.sh
infiniband/bringup/ndr/OS-CPLD-upgrade.sh
infiniband/bringup/ndr/data-collect-IB.sh
infiniband/bringup/xdr-initial-setup/initial-setup.py
infiniband/bringup/xdr-upgrade/upgrade.sh
infiniband/monitor/cron.sh
infiniband/monitor/sw-info.sh
infiniband/monitor/sw-link.sh
infra/check_infra.py
infra/deploy_infra.py
infra/infra-setup.sh
infra/infra-teardown.sh
monitor/dot_to_html.py
monitor/generate-monitor-html.py
monitor/manual-ztp-control.cgi
monitor/manual-ztp-worker.py
monitor/switch-collection-control.cgi
monitor/switch-collection-worker.py
monitor/switch_collection_gate.py
monitor/ztp-monitor-control.cgi
nvlink/monitor/cron.sh
nvlink/monitor/sw-info.sh
nvlink/monitor/sw-link.sh
tools/_package_common.py
tools/collect-ztp-diagnostics.py
tools/deployment_lock.py
tools/ib-tool-Jie/ib_tool_box/lib/__init__.py
tools/ib-tool-Jie/ib_tool_box/lib/connection.py
tools/ib-tool-Jie/ib_tool_box/lib/excel.py
tools/ib-tool-Jie/ib_tool_box/lib/inventory.py
tools/ib-tool-Jie/ib_tool_box/lib/link_errors.py
tools/ib-tool-Jie/ib_tool_box/lib/parsers/__init__.py
tools/ib-tool-Jie/ib_tool_box/lib/parsers/db_csv.py
tools/ib-tool-Jie/ib_tool_box/lib/parsers/net_dump.py
tools/ib-tool-Jie/ib_tool_box/lib/parsers/net_dump_ext.py
tools/ib-tool-Jie/ib_tool_box/lib/parsers/partitions_conf.py
tools/ib-tool-Jie/ib_tool_box/lib/parsers/smdb.py
tools/ib-tool-Jie/ib_tool_box/lib/reporting.py
tools/ib-tool-Jie/ib_tool_box/scripts/check_hca_ooo_sl_mask.py
tools/ib-tool-Jie/ib_tool_box/scripts/check_ib_link_errors.py
tools/ib-tool-Jie/ib_tool_box/scripts/parse_ib_partition_config.py
tools/ib-tool-Jie/ib_tool_box/scripts/parse_ib_smdb.py
tools/ib-tool-Jie/ib_tool_box/scripts/parse_m_keys.py
tools/ib-tool-Jie/ib_tool_box/scripts/show_ib_inventory.py
tools/ib-tool-Jie/ib_tool_box/scripts/trace_ib_path.py
tools/ib-tool-Jie/ib_tool_box/scripts/validate_ib_topology.py
tools/ibdiagnet-analyze-tool/analyze.py
tools/ibdiagnet-analyze-tool/lib/__init__.py
tools/ibdiagnet-analyze-tool/lib/connection.py
tools/ibdiagnet-analyze-tool/lib/excel.py
tools/ibdiagnet-analyze-tool/lib/inventory.py
tools/ibdiagnet-analyze-tool/lib/link_errors.py
tools/ibdiagnet-analyze-tool/lib/parsers/__init__.py
tools/ibdiagnet-analyze-tool/lib/parsers/db_csv.py
tools/ibdiagnet-analyze-tool/lib/parsers/iblinkinfo.py
tools/ibdiagnet-analyze-tool/lib/parsers/net_dump.py
tools/ibdiagnet-analyze-tool/lib/parsers/net_dump_ext.py
tools/ibdiagnet-analyze-tool/lib/parsers/partitions_conf.py
tools/ibdiagnet-analyze-tool/lib/parsers/smdb.py
tools/ibdiagnet-analyze-tool/lib/reporting.py
tools/ibdiagnet-analyze-tool/lib/snapshot.py
tools/ibdiagnet-analyze-tool/lib/topology.py
tools/ibdiagnet-analyze-tool/scripts/check_hca_ooo_sl_mask.py
tools/ibdiagnet-analyze-tool/scripts/check_ib_link_errors.py
tools/ibdiagnet-analyze-tool/scripts/parse_ib_partition_config.py
tools/ibdiagnet-analyze-tool/scripts/parse_ib_smdb.py
tools/ibdiagnet-analyze-tool/scripts/parse_m_keys.py
tools/ibdiagnet-analyze-tool/scripts/show_ib_inventory.py
tools/ibdiagnet-analyze-tool/scripts/trace_ib_path.py
tools/ibdiagnet-analyze-tool/scripts/validate_ib_topology.py
tools/import-from-download.py
tools/lldp-analyze-tool/analyze_lldp.py
tools/lldp-analyze-tool/build_report.py
tools/project_contract.py
tools/sync-code.py
tools/tar-for-download.py
tools/tar-for-upload.py
tools/update-root-readme.py
ztp/backup/yaml-collect.py
ztp/config/cumulus/d-hostname2mac.py
ztp/config/cumulus/template/90-c2-generate_configs.py
ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py
ztp/config/isc-dhcp-server/c1-generate_dhcp.py
ztp/config/nvos/d-hostname2mac.py
ztp/config/nvos/template/90-c2-generate_configs.py
ztp/config/nvos/template/P2P/p2p-to-validation.py
ztp/dhcp_runtime_inventory.py
ztp/dynamic_air_inventory.py
ztp/environment_probe.py
ztp/manual-reset.py
ztp/manual-ztp.py
ztp/nvue_normalizer.py
ztp/optimize/feedback.py
ztp/optimize/sample_links.py
ztp/templates/ztp-bootstrap.sh""".splitlines())


def _index_regular_blob(repository: Path, relative: str, after_snapshot=None):
    command = ["git", "ls-files", "--stage", "--", relative]
    staged = subprocess.run(
        command, cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if staged.returncode != 0:
        raise AssertionError(staged.stderr)
    records = staged.stdout.splitlines()
    if len(records) != 1:
        raise AssertionError(f"{relative} needs one exact index entry")
    metadata, indexed_path = records[0].split("\t", 1)
    mode, object_id, stage_number = metadata.split(" ", 2)
    if indexed_path != relative or mode != "100644" or stage_number != "0":
        raise AssertionError(f"{relative} index entry must be stage-0 100644")
    if after_snapshot is not None:
        after_snapshot()
    indexed = subprocess.run(
        ["git", "cat-file", "blob", object_id], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if indexed.returncode != 0:
        raise AssertionError(indexed.stderr.decode("utf-8", errors="replace"))
    confirmed = subprocess.run(
        command, cwd=repository, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, check=False,
    )
    if confirmed.returncode != 0:
        raise AssertionError(confirmed.stderr)
    if confirmed.stdout != staged.stdout:
        raise AssertionError(f"{relative} index entry changed during snapshot")
    return staged.stdout, indexed.stdout


def _expected_q02_staged_overlay_paths(indexed_readme_snapshot) -> set[str]:
    expected = set(Q02_PHASE_OVERLAY_PATHS)
    _record, indexed_readme = indexed_readme_snapshot
    if hashlib.sha256(indexed_readme).hexdigest() == Q02_BASE_README_SHA256:
        expected.remove("test_cases/README.md")
    return expected


def _fixed_q02_overlay_snapshot(repository: Path) -> dict[str, bytes]:
    snapshot = {
        relative: _tree_blob_bytes(repository, relative, Q02_PHASE_REVISION)
        for relative in Q02_PHASE_OVERLAY_PATHS
    }
    if hashlib.sha256(
        snapshot["test_cases/script_test_manifest.json"]
    ).hexdigest() != Q02_PHASE_MANIFEST_SHA256:
        raise AssertionError("fixed Q02 manifest bytes drift")
    if hashlib.sha256(
        snapshot["test_cases/README.md"]
    ).hexdigest() != Q02_PHASE_README_SHA256:
        raise AssertionError("fixed Q02 README bytes drift")
    return snapshot


def _copy_candidate_overlay(
    destination: Path, relative: Path, overlay_snapshot: dict[str, bytes],
) -> None:
    target = destination / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(overlay_snapshot[relative.as_posix()])
    target.chmod(0o644)


def _tree_paths(repository: Path, revision: str = "HEAD") -> set[str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", revision], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return set(result.stdout.splitlines())


def _tree_modes(repository: Path, revision: str = "HEAD") -> dict[str, str]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", revision], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    modes = {}
    for line in result.stdout.splitlines():
        metadata, path = line.split("\t", 1)
        mode, _kind, _object_id = metadata.split(" ", 2)
        modes[path] = mode
    return modes


def _tree_entries(repository: Path, revision: str = "HEAD") -> dict[str, tuple[str, str]]:
    result = subprocess.run(
        ["git", "ls-tree", "-r", revision], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    entries = {}
    for line in result.stdout.splitlines():
        metadata, path = line.split("\t", 1)
        mode, kind, _object_id = metadata.split(" ", 2)
        entries[path] = (mode, kind)
    return entries


def _tree_blob(repository: Path, path: str, revision: str = "HEAD") -> str:
    result = subprocess.run(
        ["git", "show", f"{revision}:{path}"], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def _tree_blob_bytes(repository: Path, path: str, revision: str = "HEAD") -> bytes:
    result = subprocess.run(
        ["git", "show", f"{revision}:{path}"], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def _manifest_test_references(manifest) -> set[str]:
    references = set(manifest.get("baseline_tests", ()))
    for field in ("test_suites", "test_rules", "workflows", "path_rules"):
        for record in manifest.get(field, ()):
            references.update(record.get("tests", ()))
    return references


def _normalized_digest(value) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_tree_reference(reference: str) -> bool:
    if not isinstance(reference, str) or not reference:
        return False
    if reference.startswith("/") or "\\" in reference or "\0" in reference:
        return False
    if "[" in reference or "]" in reference or "//" in reference:
        return False
    return all(part not in {"", ".", ".."} for part in reference.split("/"))


def _tree_reference_matches(reference: str, paths: set[str]) -> set[str]:
    if not _safe_tree_reference(reference):
        return set()
    if "*" in reference or "?" in reference:
        return {path for path in paths if fnmatch.fnmatchcase(path, reference)}
    return {reference} if reference in paths else set()


def _valid_script_symlink_target(path: str, canonical: str, target: str) -> bool:
    parent = posixpath.dirname(path) or "."
    expected = posixpath.relpath(canonical, parent)
    return (
        "\0" not in target and "\n" not in target and not target.startswith("/")
        and target == expected
    )


def _q02_expected_path_rules(base_manifest):
    rules = copy.deepcopy(base_manifest["path_rules"])
    rules = [rule for rule in rules if rule["paths"] != ["infra/apache/*"]]
    for rule in rules:
        rule["paths"] = [
            path for path in rule["paths"]
            if path not in {"README.md", "USER_MANUAL.md"}
        ]
    return rules


def _q02_phase_manifest_fixture(repository: Path):
    base_manifest = json.loads(_tree_blob(
        repository, "test_cases/script_test_manifest.json", Q02_BASE_REVISION,
    ))
    phase_manifest = copy.deepcopy(base_manifest)
    phase_manifest["test_suites"] = copy.deepcopy(Q02_PHASE_TEST_SUITES)
    phase_manifest["tracked_support"] = list(Q02_REMAINING_TRACKED_SUPPORT_PATHS)
    phase_manifest["path_rules"] = _q02_expected_path_rules(base_manifest)
    for field, expected in Q02_PHASE_MAPPING_DIGESTS.items():
        if _normalized_digest(phase_manifest[field]) != expected:
            raise AssertionError(f"independent Q02 {field} fixture digest drift")
    return phase_manifest


def _q02_phase_readme_bytes(repository: Path) -> bytes:
    base = _tree_blob_bytes(
        repository, "test_cases/README.md", Q02_BASE_REVISION,
    )
    if hashlib.sha256(base).hexdigest() != Q02_BASE_README_SHA256:
        raise AssertionError("fixed Q02 base README bytes drift")
    expected = base + b"\n" + Q02_PUBLIC_PRIVATE_README_SECTION.encode("utf-8")
    if hashlib.sha256(expected).hexdigest() != Q02_PHASE_README_SHA256:
        raise AssertionError("independent Q02 phase README bytes drift")
    return expected


def _markdown_heading_fragments(content: str) -> set[str]:
    fragments = set()
    occurrences = {}
    for line in content.splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        heading = re.sub(r"[^\w\- ]", "", match.group(1).strip().lower())
        fragment = re.sub(r"[ ]+", "-", heading)
        suffix = occurrences.get(fragment, 0)
        occurrences[fragment] = suffix + 1
        fragments.add(fragment if suffix == 0 else f"{fragment}-{suffix}")
    return fragments


def _safe_markdown_tree_target(readme_path: str, target: str):
    if (
        not target or "\0" in target or "\\" in target or "%" in target
        or target.startswith("/") or "://" in target
    ):
        return None
    path, separator, fragment = target.partition("#")
    if not path:
        resolved = readme_path
    else:
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return None
        resolved = posixpath.normpath(posixpath.join(
            posixpath.dirname(readme_path), path,
        ))
        if resolved == ".." or resolved.startswith("../"):
            return None
    return resolved, fragment if separator else ""


def q02_phase_readme_violations(
    repository: Path, revision: str = "HEAD", readme_override=None,
):
    """Bind Q02 README bytes, links and documented runner CLI to its tree."""
    readme_path = "test_cases/README.md"
    entries = _tree_entries(repository, revision)
    actual = readme_override
    if actual is None:
        actual = _tree_blob_bytes(repository, readme_path, revision)
    expected = _q02_phase_readme_bytes(repository)
    issues = {}
    if entries.get(readme_path) != ("100644", "blob"):
        issues["readme_mode"] = entries.get(readme_path)
    if actual != expected:
        issues["readme_exact_bytes"] = {
            "actual": hashlib.sha256(actual).hexdigest(),
            "expected": Q02_PHASE_README_SHA256,
        }
    try:
        content = actual.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        issues["readme_utf8"] = str(error)
        return issues

    section_heading = "## Q02 公开/私有测试分层"
    if content.count(section_heading) != 1:
        issues["q02_section_count"] = content.count(section_heading)

    bad_links = []
    bad_fragments = []
    for target in re.findall(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)", content):
        parsed = _safe_markdown_tree_target(readme_path, target)
        if parsed is None:
            bad_links.append(target)
            continue
        resolved, fragment = parsed
        if entries.get(resolved) != ("100644", "blob"):
            bad_links.append(target)
            continue
        if fragment:
            linked = _tree_blob(repository, resolved, revision)
            if fragment not in _markdown_heading_fragments(linked):
                bad_fragments.append(target)
    if bad_links:
        issues["unsafe_or_missing_links"] = sorted(set(bad_links))
    if bad_fragments:
        issues["missing_link_fragments"] = sorted(set(bad_fragments))

    allowed_runner_options = {
        "--all", "--check", "--interval", "--list", "--watch",
    }
    unsupported_runner_options = set()
    for line in content.splitlines():
        if "test_cases/run_related_tests.py" not in line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            unsupported_runner_options.add("<invalid-shell-command>")
            continue
        unsupported_runner_options.update(
            token.split("=", 1)[0] for token in tokens
            if token.startswith("--")
            and token.split("=", 1)[0] not in allowed_runner_options
        )
    explicit_future_cli = {
        option for option in ("--suite", "--list-suites", "--require-full")
        if option in content
    }
    unsupported_runner_options.update(explicit_future_cli)
    if unsupported_runner_options:
        issues["unsupported_runner_options"] = sorted(unsupported_runner_options)

    forbidden_references = set()
    forbidden_paths = (
        *Q01_PUBLIC_DOCUMENT_PATHS,
        *Q05_V2_FORBIDDEN_LIFECYCLE_PATHS,
        *P_PHASE_TEST_PATHS,
        *Q02_FUTURE_TEST_MODULE_PATHS,
    )
    for path in forbidden_paths:
        dotted = path[:-3].replace("/", ".") if path.endswith(".py") else None
        basename = posixpath.basename(path) if path.startswith("test_cases/") else None
        if path in content or (dotted and dotted in content) or (
            basename and basename in content
        ):
            forbidden_references.add(path)
    lowered = content.lower()
    if Q02_CABLETRACKER_PREFIX.lower() in lowered or "cabletracker" in lowered:
        forbidden_references.add(Q02_CABLETRACKER_PREFIX)
    if "finished-project-lifecycle" in lowered:
        forbidden_references.add("docs/v3/finished-project-lifecycle")
    if forbidden_references:
        issues["future_or_private_references"] = sorted(forbidden_references)
    return issues


def q02_commit_manifest_violations(
    repository: Path, revision: str = "HEAD", manifest_override=None,
):
    """Validate every Q02 manifest authority against committed tree bytes."""
    entries = _tree_entries(repository, revision)
    paths = set(entries)
    manifest = manifest_override
    if manifest is None:
        manifest = json.loads(_tree_blob(
            repository, "test_cases/script_test_manifest.json", revision,
        ))
    issues = {}

    phase_readme_issues = q02_phase_readme_violations(repository, revision)
    if phase_readme_issues:
        issues["phase_readme"] = phase_readme_issues

    mapping_digest_mismatches = sorted(
        field for field, expected in Q02_PHASE_MAPPING_DIGESTS.items()
        if _normalized_digest(manifest.get(field)) != expected
    )
    if mapping_digest_mismatches:
        issues["mapping_table_digest"] = mapping_digest_mismatches

    scripts = manifest.get("scripts", {})
    script_paths = set(scripts) if isinstance(scripts, dict) else set()
    if script_paths != Q02_BASE_PRODUCTION_SCRIPT_PATHS:
        issues["production_authority_missing"] = sorted(
            Q02_BASE_PRODUCTION_SCRIPT_PATHS - script_paths
        )
        issues["production_authority_extra"] = sorted(
            script_paths - Q02_BASE_PRODUCTION_SCRIPT_PATHS
        )

    missing_scripts = sorted(path for path in script_paths if path not in entries)
    if missing_scripts:
        issues["missing_scripts"] = missing_scripts
    invalid_script_authority = []
    for path, canonical in scripts.items() if isinstance(scripts, dict) else ():
        if path not in entries:
            continue
        mode, kind = entries[path]
        if mode == "120000" and kind == "blob":
            target = _tree_blob(repository, path, revision)
            if not _valid_script_symlink_target(path, canonical, target):
                invalid_script_authority.append(path)
        elif mode in {"100644", "100755"} and kind == "blob":
            if canonical != path:
                invalid_script_authority.append(path)
        else:
            invalid_script_authority.append(path)
        if (
            canonical not in entries
            or entries.get(canonical) not in {("100644", "blob"), ("100755", "blob")}
        ):
            invalid_script_authority.append(path)
    if invalid_script_authority:
        issues["invalid_script_authority"] = sorted(set(invalid_script_authority))

    invalid_test_references = []
    missing_test_modules = []
    for reference in sorted(_manifest_test_references(manifest)):
        parts = reference.split(".") if isinstance(reference, str) else ()
        if (
            len(parts) < 2 or parts[0] != "test_cases"
            or any(not part.isidentifier() for part in parts)
        ):
            invalid_test_references.append(reference)
            continue
        path = reference.replace(".", "/") + ".py"
        if entries.get(path) != ("100644", "blob"):
            missing_test_modules.append(reference)
    if invalid_test_references:
        issues["invalid_test_references"] = invalid_test_references
    if missing_test_modules:
        issues["missing_test_modules"] = missing_test_modules

    suite_memberships = {}
    for suite in manifest.get("test_suites", ()):
        for reference in suite.get("tests", ()):
            suite_memberships.setdefault(reference, []).append(suite.get("id"))
    tree_test_modules = {
        path[:-3].replace("/", ".") for path, entry in entries.items()
        if (
            path.startswith("test_cases/test_") and path.endswith(".py")
            and "/" not in path[len("test_cases/"):]
            and entry == ("100644", "blob")
        )
    }
    unprimary_test_modules = sorted(
        reference for reference in tree_test_modules
        if len(suite_memberships.get(reference, ())) != 1
    )
    if unprimary_test_modules:
        issues["unprimary_test_modules"] = unprimary_test_modules

    mapped_test_references = set(manifest.get("baseline_tests", ()))
    for field in ("test_rules", "workflows", "path_rules"):
        for record in manifest.get(field, ()):
            mapped_test_references.update(record.get("tests", ()))
    unprimary_mapped_tests = sorted(
        reference for reference in mapped_test_references
        if len(suite_memberships.get(reference, ())) != 1
    )
    if unprimary_mapped_tests:
        issues["unprimary_mapped_tests"] = unprimary_mapped_tests

    for field, path_field in (
        ("test_rules", "paths"),
        ("workflows", "members"),
        ("path_rules", "paths"),
    ):
        invalid = []
        missing = []
        for record in manifest.get(field, ()):
            for reference in record.get(path_field, ()):
                if not _safe_tree_reference(reference):
                    invalid.append(reference)
                elif not _tree_reference_matches(reference, paths):
                    missing.append(reference)
        if invalid:
            issues[f"invalid_{field}_paths"] = sorted(set(invalid))
        if missing:
            issues[f"missing_{field}_paths"] = sorted(set(missing))

    direct_covered_scripts = set()
    for rule in manifest.get("test_rules", ()):
        existing_tests = {
            reference for reference in rule.get("tests", ())
            if entries.get(reference.replace(".", "/") + ".py")
            == ("100644", "blob")
        }
        if not existing_tests:
            continue
        for reference in rule.get("paths", ()):
            direct_covered_scripts.update(
                script_paths.intersection(_tree_reference_matches(reference, paths))
            )
    uncovered_direct_scripts = sorted(script_paths - direct_covered_scripts)
    if uncovered_direct_scripts:
        issues["uncovered_direct_scripts"] = uncovered_direct_scripts

    workflow_covered_scripts = set()
    for workflow in manifest.get("workflows", ()):
        existing_tests = {
            reference for reference in workflow.get("tests", ())
            if entries.get(reference.replace(".", "/") + ".py")
            == ("100644", "blob")
        }
        expanded_members = set()
        for reference in workflow.get("members", ()):
            expanded_members.update(_tree_reference_matches(reference, paths))
        real_members = expanded_members.intersection(script_paths)
        if existing_tests and len(real_members) >= 2:
            workflow_covered_scripts.update(real_members)
    uncovered_workflow_scripts = sorted(script_paths - workflow_covered_scripts)
    if uncovered_workflow_scripts:
        issues["uncovered_workflow_scripts"] = uncovered_workflow_scripts

    tracked_support = set(manifest.get("tracked_support", ()))
    expected_support = set(Q02_REMAINING_TRACKED_SUPPORT_PATHS)
    if tracked_support != expected_support:
        issues["tracked_support_missing"] = sorted(expected_support - tracked_support)
        issues["tracked_support_extra"] = sorted(tracked_support - expected_support)
    invalid_support = []
    for path in expected_support:
        entry = entries.get(path)
        target = Q02_TRACKED_SUPPORT_SYMLINK_TARGETS.get(path)
        if target is None:
            if entry not in {("100644", "blob"), ("100755", "blob")}:
                invalid_support.append(path)
        elif entry != ("120000", "blob") or _tree_blob(
            repository, path, revision,
        ) != target:
            invalid_support.append(path)
    if invalid_support:
        issues["invalid_tracked_support"] = sorted(invalid_support)

    return {name: values for name, values in issues.items() if values}


def _q02_tree_violations(paths) -> set[str]:
    forbidden = {
        *Q02_FUTURE_TRACKED_SUPPORT_PATHS,
        *Q01_PUBLIC_DOCUMENT_PATHS,
        *Q05_V2_FORBIDDEN_LIFECYCLE_PATHS,
        *P_PHASE_TEST_PATHS,
    }
    return {
        path for path in paths
        if any(path == item or path.startswith(item + "/") for item in forbidden)
    }


def _commit(repository: Path, paths, message: str) -> None:
    subprocess.run(
        ["git", "add", "--", *paths], cwd=repository,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    subprocess.run(
        [
            "git", "-c", "user.name=Public Contract",
            "-c", "user.email=public-contract@example.invalid",
            "commit", "--quiet", "-m", message,
        ],
        cwd=repository, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True,
    )


class PublicCleanCloneWorkflowTests(unittest.TestCase):
    def test_q02_commit_tree_rejects_q01_and_lifecycle_paths(self):
        self.assertTrue(_valid_script_symlink_target(
            "infiniband/monitor/cron.sh",
            "ethernet/monitor/cron.sh",
            "../../ethernet/monitor/cron.sh",
        ))
        self.assertFalse(_valid_script_symlink_target(
            "alias/cron.sh",
            "monitor/cron.sh",
            "../monitor/nonexistent/../cron.sh",
        ))
        forbidden = (
            *Q02_FUTURE_TRACKED_SUPPORT_PATHS,
            *Q01_PUBLIC_DOCUMENT_PATHS,
            *Q05_V2_FORBIDDEN_LIFECYCLE_PATHS,
            *P_PHASE_TEST_PATHS,
        )
        with tempfile.TemporaryDirectory(prefix="http-q02-hostile-tree-") as directory:
            repository = Path(directory)
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            for relative in forbidden:
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("hostile future publication\n", encoding="utf-8")
            _commit(repository, forbidden, "hostile q02 tree")
            self.assertEqual(set(forbidden), _q02_tree_violations(
                _tree_paths(repository),
            ))
        for category, paths in (
            ("future-support", Q02_FUTURE_TRACKED_SUPPORT_PATHS),
            ("q01", Q01_PUBLIC_DOCUMENT_PATHS),
            ("lifecycle", Q05_V2_FORBIDDEN_LIFECYCLE_PATHS),
            ("p-tests", P_PHASE_TEST_PATHS),
        ):
            for relative in paths:
                with self.subTest(category=category, descendant=relative):
                    descendant = relative + "/hostile-child"
                    self.assertEqual(
                        {descendant}, _q02_tree_violations({descendant}),
                    )
                    self.assertEqual(
                        set(), _tree_reference_matches(relative, {descendant}),
                        "a literal manifest authority must not accept a descendant",
                    )

        descendants = {
            relative + "/hostile-child" for relative in forbidden
        }
        with tempfile.TemporaryDirectory(prefix="http-q02-hostile-prefix-") as directory:
            repository = Path(directory)
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            for relative in descendants:
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("hostile descendant\n", encoding="utf-8")
            _commit(repository, sorted(descendants), "hostile q02 prefixes")
            self.assertEqual(
                descendants, _q02_tree_violations(_tree_paths(repository)),
            )

        with tempfile.TemporaryDirectory(prefix="http-q02-index-race-") as directory:
            repository = Path(directory)
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            relative = "test_cases/README.md"
            readme = repository / relative
            readme.parent.mkdir(parents=True)
            readme.write_bytes(b"validated index blob A\n")
            subprocess.run(
                ["git", "add", "--", relative], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )

            def swap_index_blob():
                readme.write_bytes(b"replacement index blob B\n")
                subprocess.run(
                    ["git", "add", "--", relative], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )

            with self.assertRaisesRegex(AssertionError, "changed during snapshot"):
                _index_regular_blob(
                    repository, relative, after_snapshot=swap_index_blob,
                )

    def test_q02_exact5_commit_runs_private_free_clone_with_one_tier_skip(self):
        self.assertEqual(5, len(Q02_PHASE_OVERLAY_PATHS))
        self.assertEqual(103, len(Q02_BASE_PRODUCTION_SCRIPT_PATHS))
        self.assertEqual(29, len(Q02_FUTURE_TRACKED_SUPPORT_PATHS))
        self.assertEqual(8, len(Q01_PUBLIC_DOCUMENT_PATHS))
        self.assertEqual(7, len(Q05_V2_FORBIDDEN_LIFECYCLE_PATHS))
        with tempfile.TemporaryDirectory(prefix="http-q02-checkout-") as directory:
            base = Path(directory)
            candidate = base / "candidate"
            checkout = base / "checkout"
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", ROOT, candidate],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", Q02_BASE_REVISION],
                cwd=candidate, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
            base_revision = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=True,
            )
            self.assertEqual(Q02_BASE_REVISION, base_revision.stdout.strip())
            overlay_snapshot = _fixed_q02_overlay_snapshot(ROOT)
            for relative in Q02_PHASE_OVERLAY_PATHS:
                _copy_candidate_overlay(
                    candidate, Path(relative), overlay_snapshot,
                )
            subprocess.run(
                ["git", "add", "--", *Q02_PHASE_OVERLAY_PATHS], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            staged = subprocess.run(
                ["git", "diff", "--cached", "--name-only"], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=True,
            )
            self.assertEqual(
                set(Q02_PHASE_OVERLAY_PATHS),
                set(staged.stdout.splitlines()),
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Public Contract",
                    "-c", "user.email=public-contract@example.invalid",
                    "commit", "--quiet", "-m", "Q02 public/private test tier",
                ],
                cwd=candidate, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
            compile_environment = os.environ.copy()
            compile_environment["PYTHONPYCACHEPREFIX"] = str(base / "pycache")
            compile_result = subprocess.run(
                [
                    sys.executable, "-B", "-m", "py_compile",
                    "test_cases/test_public_clean_clone_workflow.py",
                ],
                cwd=candidate, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=False, timeout=30, env=compile_environment,
            )
            self.assertEqual(0, compile_result.returncode, compile_result.stderr)
            tree = _tree_paths(candidate)
            modes = _tree_modes(candidate)
            self.assertEqual(set(), _q02_tree_violations(tree))
            self.assertEqual(
                set(), tree.intersection(Q02_FUTURE_TRACKED_SUPPORT_PATHS),
            )
            self.assertEqual(
                {relative: "100644" for relative in Q02_PHASE_OVERLAY_PATHS},
                {
                    relative: modes[relative]
                    for relative in Q02_PHASE_OVERLAY_PATHS
                },
            )
            manifest = json.loads(_tree_blob(
                candidate, "test_cases/script_test_manifest.json",
            ))
            baseline_violations = q02_commit_manifest_violations(candidate)

            expected_readme = _q02_phase_readme_bytes(candidate)
            self.assertEqual(
                {}, q02_phase_readme_violations(
                    candidate, readme_override=expected_readme,
                ),
            )
            readme_hostiles = (
                (
                    "bad-link",
                    expected_readme + b"\n[escape](../outside.md)\n",
                    "unsafe_or_missing_links",
                ),
                (
                    "bad-fragment",
                    expected_readme
                    + b"\n[missing](CHANGE_AWARE_TESTING.md#not-a-heading)\n",
                    "missing_link_fragments",
                ),
                (
                    "unsupported-suite",
                    expected_readme + (
                        "\n```bash\npython3 -B test_cases/run_related_tests.py "
                        "--suite repository-governance\n```\n"
                    ).encode("utf-8"),
                    "unsupported_runner_options",
                ),
                (
                    "future-test",
                    expected_readme
                    + b"\ntest_cases/test_xlsx_zero_row_fail_closed.py\n",
                    "future_or_private_references",
                ),
                (
                    "missing-section",
                    _tree_blob_bytes(
                        candidate, "test_cases/README.md", Q02_BASE_REVISION,
                    ),
                    "q02_section_count",
                ),
            )
            for name, hostile_readme, expected_issue in readme_hostiles:
                with self.subTest(readme_hostile=name):
                    violations = q02_phase_readme_violations(
                        candidate, readme_override=hostile_readme,
                    )
                    self.assertIn(expected_issue, violations)
                    self.assertIn("readme_exact_bytes", violations)

            base_manifest = json.loads(_tree_blob(
                candidate, "test_cases/script_test_manifest.json",
                Q02_BASE_REVISION,
            ))
            phase_mapping_manifest = copy.deepcopy(manifest)
            for field in ("baseline_tests", "test_rules", "workflows"):
                phase_mapping_manifest[field] = copy.deepcopy(base_manifest[field])
                self.assertEqual(
                    Q02_PHASE_MAPPING_DIGESTS[field],
                    _normalized_digest(phase_mapping_manifest[field]),
                )
            phase_mapping_manifest["path_rules"] = _q02_expected_path_rules(
                base_manifest,
            )
            self.assertEqual(
                Q02_PHASE_MAPPING_DIGESTS["path_rules"],
                _normalized_digest(phase_mapping_manifest["path_rules"]),
            )
            phase_mapping_violations = q02_commit_manifest_violations(
                candidate, manifest_override=phase_mapping_manifest,
            )
            self.assertNotIn("mapping_table_digest", phase_mapping_violations)
            for cleared_field in ("baseline_tests", "path_rules"):
                with self.subTest(cleared_mapping=cleared_field):
                    cleared = copy.deepcopy(phase_mapping_manifest)
                    cleared[cleared_field] = []
                    cleared_violations = q02_commit_manifest_violations(
                        candidate, manifest_override=cleared,
                    )
                    self.assertIn(
                        cleared_field,
                        cleared_violations.get("mapping_table_digest", ()),
                        f"clearing {cleared_field} must fail closed",
                    )

            without_direct = copy.deepcopy(manifest)
            without_direct["test_rules"] = [
                rule for rule in without_direct["test_rules"]
                if rule["id"] != "diagnostic_bundle"
            ]
            direct_violations = q02_commit_manifest_violations(
                candidate, manifest_override=without_direct,
            )
            self.assertNotIn(
                "tools/collect-ztp-diagnostics.py",
                baseline_violations.get("uncovered_direct_scripts", ()),
            )
            self.assertIn(
                "tools/collect-ztp-diagnostics.py",
                direct_violations.get("uncovered_direct_scripts", ()),
                "removing a script's only direct rule must fail closed",
            )

            without_workflow = copy.deepcopy(manifest)
            for workflow in without_workflow["workflows"]:
                if workflow["id"] == "ib_nvl_bringup_observability":
                    workflow["members"] = []
            workflow_script = "infiniband/bringup/ndr/OS-CPLD-upgrade.sh"
            workflow_violations = q02_commit_manifest_violations(
                candidate, manifest_override=without_workflow,
            )
            self.assertNotIn(
                workflow_script,
                baseline_violations.get("uncovered_workflow_scripts", ()),
            )
            self.assertIn(
                workflow_script,
                workflow_violations.get("uncovered_workflow_scripts", ()),
                "emptying a script's only multi-real workflow must fail closed",
            )

            without_primary = copy.deepcopy(manifest)
            primary_module = "test_cases.test_public_clean_clone_workflow"
            for suite in without_primary["test_suites"]:
                if suite["id"] == "repository-governance":
                    suite["tests"].remove(primary_module)
            primary_violations = q02_commit_manifest_violations(
                candidate, manifest_override=without_primary,
            )
            self.assertNotIn(
                primary_module,
                baseline_violations.get("unprimary_test_modules", ()),
            )
            self.assertIn(
                primary_module,
                primary_violations.get("unprimary_test_modules", ()),
                "removing a committed test's primary suite must fail closed",
            )

            self.assertEqual(
                {}, baseline_violations,
                "every Q02 manifest authority must resolve in the exact5 commit tree",
            )
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", candidate, checkout],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            command = [
                sys.executable, "-B", "-m", "unittest", "-v",
                "test_cases.test_public_clean_clone_contract",
                "test_cases.test_private_documentation_contract."
                "PrivateDocumentationContractTests",
            ]
            result = subprocess.run(
                command, cwd=checkout, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False, timeout=120,
            )
            combined = result.stdout + result.stderr
            skip_line = "skipped 'private documentation tier absent in public checkout'"
            self.assertEqual(1, combined.count(skip_line), combined)
            self.assertRegex(combined, r"\bskipped=1\b")
            self.assertNotIn("FileNotFoundError", combined)
            self.assertEqual(0, result.returncode, combined)

    def test_q02_committed_phase_replays_the_whole_workflow_once(self):
        with tempfile.TemporaryDirectory(prefix="http-q02-self-replay-") as directory:
            base = Path(directory)
            candidate = base / "candidate"
            checkout = base / "checkout"
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", ROOT, candidate],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", Q02_BASE_REVISION],
                cwd=candidate, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
            overlay_snapshot = _fixed_q02_overlay_snapshot(ROOT)
            for relative in Q02_PHASE_OVERLAY_PATHS:
                _copy_candidate_overlay(
                    candidate, Path(relative), overlay_snapshot,
                )
            phase_manifest = _q02_phase_manifest_fixture(candidate)
            phase_manifest_bytes = (
                json.dumps(phase_manifest, indent=2, ensure_ascii=False) + "\n"
            ).encode("utf-8")
            self.assertEqual(
                overlay_snapshot["test_cases/script_test_manifest.json"],
                phase_manifest_bytes,
            )
            self.assertEqual(
                Q02_PHASE_MANIFEST_SHA256,
                hashlib.sha256(phase_manifest_bytes).hexdigest(),
            )
            (candidate / "test_cases/script_test_manifest.json").write_bytes(
                phase_manifest_bytes,
            )
            subprocess.run(
                ["git", "add", "--", *Q02_PHASE_OVERLAY_PATHS], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            staged = subprocess.run(
                ["git", "diff", "--cached", "--name-only"], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=True,
            )
            self.assertEqual(
                set(Q02_PHASE_OVERLAY_PATHS),
                set(staged.stdout.splitlines()),
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Public Contract",
                    "-c", "user.email=public-contract@example.invalid",
                    "commit", "--quiet", "-m", "Q02 self-replay candidate",
                ],
                cwd=candidate, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
            self.assertEqual({}, q02_commit_manifest_violations(candidate))
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", candidate, checkout],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            replay_environment = os.environ.copy()
            replay_environment["PYTHONPYCACHEPREFIX"] = str(base / "pycache")
            result = subprocess.run(
                [
                    sys.executable, "-B", "-m", "unittest", "-v",
                    "test_cases.test_public_clean_clone_workflow."
                    "PublicCleanCloneWorkflowTests."
                    "test_q02_commit_tree_rejects_q01_and_lifecycle_paths",
                    "test_cases.test_public_clean_clone_workflow."
                    "PublicCleanCloneWorkflowTests."
                    "test_q02_exact5_commit_runs_private_free_clone_with_one_tier_skip",
                ],
                cwd=checkout, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=False, timeout=180, env=replay_environment,
            )
            combined = result.stdout + result.stderr
            self.assertIn("Ran 2 tests", combined)
            self.assertNotIn("skipped=", combined)
            self.assertEqual(0, result.returncode, combined)

if __name__ == "__main__":
    unittest.main()
