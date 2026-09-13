#!/usr/bin/env python3
"""Direct contracts for the reviewed S integration phase."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
Q02_COMMIT = "623bf4ec48203c3c02a3d0bf79271d6c4c637a2a"
MANIFEST = ROOT / "test_cases/script_test_manifest.json"

S_PRODUCTION_PATHS = tuple("""\
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
infra/docker/activate.py
infra/docker/deploy.sh
infra/docker/entrypoint.py
infra/docker/healthcheck.py
infra/docker/hostctl.py
infra/docker/hostlock.py
infra/docker/management_ssh_key.py
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
tools/control-auth.py
tools/deploy-shared-artifacts.py
tools/deploy-upload-archive.py
tools/deployment_lock.py
tools/deployment_prewrite_guard.py
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
tools/package-project-image.py
tools/package-shared-artifacts.py
tools/password-update.py
tools/project_contract.py
tools/sync-code.py
tools/tar-for-download.py
tools/tar-for-upload.py
tools/update-root-readme.py
tools/update-user-manual.py
tools/ztp_service_runtime.py
ztp/backup/yaml-collect.py
ztp/config/cumulus/d-hostname2mac.py
ztp/config/cumulus/template/90-c2-generate_configs.py
ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py
ztp/config/isc-dhcp-server/c1-generate_dhcp.py
ztp/config/nvos/d-hostname2mac.py
ztp/config/nvos/template/90-c2-generate_configs.py
ztp/config/nvos/template/P2P/p2p-to-validation.py
ztp/config/topology_rules.py
ztp/dhcp_runtime_inventory.py
ztp/dynamic_air_inventory.py
ztp/environment_probe.py
ztp/manual-reset.py
ztp/manual-ztp.py
ztp/nvue_normalizer.py
ztp/optimize/feedback.py
ztp/optimize/sample_links.py
ztp/templates/ztp-bootstrap.sh""".splitlines())

S_CANONICAL_OVERRIDES = {
    "infiniband/monitor/cron.sh": "ethernet/monitor/cron.sh",
    "infiniband/monitor/sw-info.sh": "ethernet/monitor/sw-info.sh",
    "infiniband/monitor/sw-link.sh": "ethernet/monitor/sw-link.sh",
    "nvlink/monitor/cron.sh": "ethernet/monitor/cron.sh",
    "nvlink/monitor/sw-info.sh": "ethernet/monitor/sw-info.sh",
    "nvlink/monitor/sw-link.sh": "ethernet/monitor/sw-link.sh",
    "ztp/config/nvos/d-hostname2mac.py": "ztp/config/cumulus/d-hostname2mac.py",
    "ztp/config/nvos/template/90-c2-generate_configs.py": (
        "ztp/config/cumulus/template/90-c2-generate_configs.py"
    ),
}

S_TEST_MODULES = tuple("""\
test_cases.test_all_script_entrypoints
test_cases.test_apache_publication_boundary
test_cases.test_backup_auth_transport_workflow
test_cases.test_bootstrap_config_fetch_contract
test_cases.test_bootstrap_config_fetch_workflow
test_cases.test_change_aware_test_runner
test_cases.test_collector_inventory_pubkey
test_cases.test_collector_inventory_pubkey_workflow
test_cases.test_control_auth
test_cases.test_cumulus_snippet_rendering
test_cases.test_deploy_upload_archive
test_cases.test_deployment_writer_lock
test_cases.test_dhcp_runtime_reassignment
test_cases.test_dhcp_switch_scope_preservation
test_cases.test_dhcp_switch_scope_preservation_workflow
test_cases.test_diagnostic_bundle
test_cases.test_docker_destructive_confirmation
test_cases.test_docker_destructive_confirmation_workflow
test_cases.test_docker_management_ssh_key
test_cases.test_documentation_catalog
test_cases.test_download_cli_contract
test_cases.test_feedback_global_writeback
test_cases.test_feedback_global_writeback_workflow
test_cases.test_flow_release_platform_matrix
test_cases.test_full_flow_integration
test_cases.test_ib_analysis_domain
test_cases.test_import_from_download_target
test_cases.test_infra_check_and_manual_reset
test_cases.test_load_release_transaction
test_cases.test_manual_applied_config
test_cases.test_mlag_evpn_generation
test_cases.test_monitor_authority_entrypoints
test_cases.test_monitor_authority_semantic_workflow
test_cases.test_monitor_authority_source_guard
test_cases.test_monitor_stack_review
test_cases.test_monitor_writer_quiesce
test_cases.test_monitor_writer_quiesce_workflow
test_cases.test_nvue_normalizer
test_cases.test_ops_deployment_review
test_cases.test_optimize_output_layout
test_cases.test_password_update
test_cases.test_predeploy_test_gate
test_cases.test_private_documentation_contract
test_cases.test_project_contracts
test_cases.test_project_image_bundle
test_cases.test_public_clean_clone_contract
test_cases.test_public_clean_clone_workflow
test_cases.test_public_project_fixture_contract
test_cases.test_public_project_fixture_workflow
test_cases.test_public_repository_contract
test_cases.test_public_s_phase_contract
test_cases.test_public_s_phase_workflow
test_cases.test_qos_evpn_uplink_generation
test_cases.test_reference_only_path_disposition
test_cases.test_reference_only_selector_workflow
test_cases.test_shared_artifact_bundle
test_cases.test_terminal_l2_stp_generation
test_cases.test_test_case_repository
test_cases.test_topology_consistency
test_cases.test_upload_package_contract
test_cases.test_v2_generation_flow
test_cases.test_v2_project_schema
test_cases.test_vm_validation_runner
test_cases.test_xlsx_zero_row_fail_closed
test_cases.test_xlsx_zero_row_workflow
test_cases.test_ztp_applied_receipt
test_cases.test_ztp_container_runtime
test_cases.test_ztp_group_handoff
test_cases.test_ztp_group_handoff_display
test_cases.test_ztp_http_identity_binding
test_cases.test_ztp_monitor_watch_resilience
test_cases.test_ztp_monitor_watch_runtime_workflow
test_cases.test_ztp_prefix_runtime_boundary
test_cases.test_ztp_release_core_review
test_cases.test_ztp_service_runtime""".splitlines())

S_TRACKED_SUPPORT_PATHS = tuple("""\
.dockerignore
.gitattributes
.github/workflows/monitor-authority-root.yml
.github/workflows/tests.yml
.gitignore
AGENTS.md
DAY0-Prepare/template/.management-pubkeys
DAY0-Prepare/template/01-global.yaml
DAY0-Prepare/template/02-devices_config.csv
DAY0-Prepare/template/02-dhcp-subnet_config.csv
DAY0-Prepare/template/99-output-backup/.gitkeep
DAY0-Prepare/template/99-output-dhcp/.gitkeep
DAY0-Prepare/template/99-output-eth/.gitkeep
DAY0-Prepare/template/99-output-ib_nvl/.gitkeep
DAY0-Prepare/template/99-output-ib_nvl/bringup/ndr-upgrade-logs/.gitkeep
DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-initial-setup-logs/.gitkeep
DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-upgrade-logs/.gitkeep
DAY0-Prepare/template/99-output-monitor/.gitkeep
DAY0-Prepare/template/99-output-p2p/.gitkeep
DAY0-Prepare/template/99-output-ztp/.gitkeep
DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-amd64.bin
DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-vx.bin
DAY0-Prepare/template/laptop.pub
DAY0-Prepare/template/mgmt-server.pub
DAY0-Prepare/template/nvosv25-02-7002amd64.bin
DAY0-Prepare/template/nvosv25-02-8008amd64.bin
DAY0-Prepare/template/p2p.xlsx
PUBLIC_REPOSITORY.md
SECURITY.md
examples/public-project/01-global.yaml.example
examples/public-project/02-devices_config.csv.example
examples/public-project/02-dhcp-subnet_config.csv.example
index.html
infra/docker/.dockerignore
infra/docker/.gitignore
infra/docker/Dockerfile
infra/docker/Dockerfile.dockerignore
infra/docker/apache-ztp.conf
infra/docker/compose.yaml
infra/docker/container.env.example
infra/docker/logrotate-http-ztp.conf
infra/docker/rsyslog-dhcp.conf
infra/docker/runtime-contract.json
infra/docker/supervisord.conf
requirements-container-top-level.lock
requirements-dev.txt
test_cases/REAL_ENVIRONMENT.md
test_cases/audit_public_tree.py
test_cases/monitor_authority_root_warden.py
test_cases/monitor_authority_source_guard.py
test_cases/public_project_fixture.py
test_cases/run_monitor_authority_entrypoints.sh
test_cases/run_related_tests.py
test_cases/run_vm_validation.py
tools/lldp-analyze-tool/04-lldp-device-aliases.json
user-manual.html
ztp/config/cumulus/ar_profile_custom.conf
ztp/config/cumulus/default.yaml
ztp/config/cumulus/default_5.16.5.yaml
ztp/config/cumulus/template/03-templates-j2/_bridge_l2vlans.yaml.j2
ztp/config/cumulus/template/03-templates-j2/_dhcp_relay.yaml.j2
ztp/config/cumulus/template/03-templates-j2/_direct_vlan_ports.yaml.j2
ztp/config/cumulus/template/03-templates-j2/_extra_aaa_users.yaml.j2
ztp/config/cumulus/template/03-templates-j2/_global_evpn.yaml.j2
ztp/config/cumulus/template/03-templates-j2/_l2_svis.yaml.j2
ztp/config/cumulus/template/03-templates-j2/border.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oob-core.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oob-leaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oob-rack-tor.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oob-su-leaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oob-su-spine.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oobofoob-leaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/oobofoob-spine.yaml.j2
ztp/config/cumulus/template/03-templates-j2/tan-cp-1gleaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/tan-cp-leaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/tan-hps-leaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/tan-leaf.yaml.j2
ztp/config/cumulus/template/03-templates-j2/tan-spine.yaml.j2
ztp/config/cumulus/template/03-templates-j2/tan-su-leaf.yaml.j2
ztp/config/cumulus/template/P2P/01-inventory.log
ztp/config/cumulus/template/P2P/02-port-mapping.log
ztp/config/cumulus/template/P2P/03-splitter.log
ztp/config/cumulus/template/P2P/air-template-no-oob.json
ztp/config/cumulus/template/P2P/air-template.json
ztp/config/cumulus/template/P2P/lldpq-template.dot
ztp/config/nvos/default.yaml
ztp/config/nvos/disable-password-hardening.nv
ztp/config/nvos/template/P2P/01-inventory.log
ztp/config/nvos/template/P2P/02-port-mapping.log
ztp/config/nvos/template/P2P/03-splitter.log
ztp/templates/ztp.json""".splitlines())

S_ORDINARY_PATHS = tuple("""\
.github/README.md
DAY0-Prepare/template/README.txt
DAY0-Prepare/template/p2p/README.txt
apps/README.md
ethernet/monitor/README.md
examples/public-project/README.md
infiniband/bringup/ndr/README.md
infiniband/bringup/xdr-initial-setup/README.md
infiniband/bringup/xdr-upgrade/README.md
infiniband/monitor/README.md
infra/apache-publication-boundary/README.md
nvlink/monitor/README.md
test_cases/CASE_TEMPLATE.md
test_cases/CHANGE_AWARE_TESTING.md
test_cases/README.md
test_cases/__init__.py
test_cases/script_test_approved_hashes.json
test_cases/script_test_manifest.json
tools/ib-tool-Jie/ib_tool_box/lib/README.md
tools/ib-tool-Jie/ib_tool_box/lib/parsers/README.md
tools/ib-tool-Jie/ib_tool_box/scripts/README.md
tools/ibdiagnet-analyze-tool/config/port_profiles.csv
tools/ibdiagnet-analyze-tool/lib/README.md
tools/ibdiagnet-analyze-tool/lib/parsers/README.md
tools/ibdiagnet-analyze-tool/requirements.txt
tools/ibdiagnet-analyze-tool/scripts/README.md
ztp/backup/README.md
ztp/config/cumulus/README.md
ztp/config/cumulus/template/P2P/lldp-analyze-tool
ztp/config/nvos/README.md
ztp/config/nvos/template/P2P/ib-tool-Jie
ztp/config/nvos/template/P2P/ibdiagnet-analyze-tool
ztp/config/nvos/template/README.md
ztp/optimize/README.md
ztp/optimize/issue-tracker/BUNDLE_TEMPLATE.md
ztp/templates/README.md""".splitlines())

Q01_PUBLIC_DOCUMENT_PATHS = (
    "docs/README.md", "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md", "docs/deployment/README.md",
    "docs/operations/README.md", "docs/reference/README.md",
    "docs/validation/README.md", "infra/docker/README.md",
)
LIFECYCLE_PATHS = tuple(
    f"docs/v3/finished-project-lifecycle/{name}.md"
    for name in (
        "ARCHITECTURE", "OPEN_QUESTIONS", "OVERVIEW", "REQUIREMENTS",
        "TEST_PLAN", "USER_GUIDE", "WORKFLOWS",
    )
)
PRIVATE_DOCUMENT_PATHS = (
    "README.md", "USER_MANUAL.md", "DAY0-Prepare/README.md", "infra/README.md",
    "monitor/README.md", "tools/README.md",
    "tools/ibdiagnet-analyze-tool/README.md", "tools/lldp-analyze-tool/README.md",
    "ztp/README.md", "ztp/config/cumulus/template/README.md",
    "ztp/config/cumulus/template/P2P/README.md",
    "ztp/config/nvos/template/P2P/README.md",
    "ztp/config/isc-dhcp-server/README.md", "ztp/optimize/issue-tracker/README.md",
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
CABLETRACKER_PATHS = tuple("""\
monitor/cabletracker-main/.env.example
monitor/cabletracker-main/.gitignore
monitor/cabletracker-main/.gitlab-ci.yml
monitor/cabletracker-main/Dockerfile
monitor/cabletracker-main/README.md
monitor/cabletracker-main/cabletracker_runner.py
monitor/cabletracker-main/docker-compose.yaml
monitor/cabletracker-main/mapping_v4.json
monitor/cabletracker-main/refresh_cvt_sum.py
monitor/cabletracker-main/requirements.txt
monitor/cabletracker-main/tests/fixtures/cvt_offline_sample.json
monitor/cabletracker-main/tests/test_cvt_sum.py
monitor/cabletracker-main/tests/test_offline_workflow.py
monitor/cabletracker-main/tmp.json""".splitlines())
P_PUBLICATION_TEST_PATHS = (
    "test_cases/test_public_publication_contract.py",
    "test_cases/test_public_publication_workflow.py",
)
S_PHASE_INDEX_PATHS = (
    ".github/README.md",
    "test_cases/README.md",
    "test_cases/REAL_ENVIRONMENT.md",
    "test_cases/script_test_manifest.json",
    "user-manual.html",
)

EXPECTED_PRODUCTION_RECORD_DIGEST = (
    "86f56d87da117f3d44430a97ed319318da37ade8fb9e43a3337e937e230e3a7d"
)
EXPECTED_REVIEWED_TEST_RECORD_DIGEST = (
    "b1f3e271b269a8ea1e5b499b9aa328ab391e9ea96a1a7986baf494d7b50e0f52"
)
EXPECTED_REVIEWED_SUPPORT_RECORD_DIGEST = (
    "23f7fdee169b0bfae9d25d713edfea7d970fb0c4804d1800dc3770401fd8bcbe"
)
EXPECTED_Q02_PUBLIC_REPOSITORY_SHA256 = (
    "fa5ba8e06fba3432c5206c2efdcd1ffe8bb0f40b98745138fa446b863dcdd22f"
)
EXPECTED_REVIEWED_ORDINARY_RECORD_DIGEST = (
    "4a84410b229ee55e4876300e292c094e2782e1f2de3f2467ab67c8075a85e55c"
)
EXPECTED_S_MAPPING_DIGESTS = {
    "baseline_tests": "a16e66c6173de4bad1d5533c340ed7f4f0707094b27e1b40ca3485a658621147",
    "test_suites": "ea54372e6c6d43f5e0f05222b56eb4f2963a8fadfafcc973c0f4f1c8280152ff",
    "test_rules": "c12e83c6aeaa5f741de1ed9884cd87a43c1f9851831add71517eff7da20ba88d",
    "workflows": "6a5862e24cd334b8c9521132e59b8b2e6f4ab5511b55aa95dbf82bd0102ce4e8",
    "path_rules": "631fbd2a7a171ba8ea4e581eba582eeb3838a02845c3a69309c5435d4c85ed46",
}
EXPECTED_S_MANIFEST_SIZE = 52414
EXPECTED_S_MANIFEST_SHA256 = (
    "aef45f0621332318af9bc4cb4710b2f5a3062b2bc962964f9b6fd1201d540ed0"
)
EXPECTED_S_MAPPING_TABLES = json.loads(r'''{"baseline_tests":["test_cases.test_all_script_entrypoints","test_cases.test_change_aware_test_runner","test_cases.test_public_repository_contract","test_cases.test_test_case_repository"],"test_suites":[{"id":"repository-governance","description":"仓库入口、测试治理、公开边界和文档目录合同","tests":["test_cases.test_all_script_entrypoints","test_cases.test_change_aware_test_runner","test_cases.test_documentation_catalog","test_cases.test_private_documentation_contract","test_cases.test_public_clean_clone_contract","test_cases.test_public_clean_clone_workflow","test_cases.test_public_repository_contract","test_cases.test_test_case_repository","test_cases.test_reference_only_path_disposition","test_cases.test_public_s_phase_contract","test_cases.test_public_s_phase_workflow"]},{"id":"packaging-sync","description":"上传、下载、同步、诊断、密码更新和部署前门禁","tests":["test_cases.test_deployment_writer_lock","test_cases.test_deploy_upload_archive","test_cases.test_diagnostic_bundle","test_cases.test_download_cli_contract","test_cases.test_import_from_download_target","test_cases.test_password_update","test_cases.test_predeploy_test_gate","test_cases.test_project_image_bundle","test_cases.test_public_project_fixture_contract","test_cases.test_public_project_fixture_workflow","test_cases.test_shared_artifact_bundle","test_cases.test_upload_package_contract","test_cases.test_reference_only_selector_workflow"]},{"id":"deployment-runtime","description":"宿主及容器部署、发布事务、Apache、DHCP 和服务运行时","tests":["test_cases.test_apache_publication_boundary","test_cases.test_control_auth","test_cases.test_docker_destructive_confirmation","test_cases.test_docker_destructive_confirmation_workflow","test_cases.test_docker_management_ssh_key","test_cases.test_infra_check_and_manual_reset","test_cases.test_load_release_transaction","test_cases.test_monitor_authority_entrypoints","test_cases.test_monitor_authority_semantic_workflow","test_cases.test_monitor_authority_source_guard","test_cases.test_monitor_writer_quiesce","test_cases.test_monitor_writer_quiesce_workflow","test_cases.test_ops_deployment_review","test_cases.test_ztp_container_runtime","test_cases.test_ztp_service_runtime"]},{"id":"configuration-generation","description":"项目 schema、Cumulus/NVUE、MLAG/EVPN、QoS、STP 和配置生成","tests":["test_cases.test_cumulus_snippet_rendering","test_cases.test_dhcp_switch_scope_preservation","test_cases.test_dhcp_switch_scope_preservation_workflow","test_cases.test_feedback_global_writeback","test_cases.test_feedback_global_writeback_workflow","test_cases.test_flow_release_platform_matrix","test_cases.test_mlag_evpn_generation","test_cases.test_nvue_normalizer","test_cases.test_optimize_output_layout","test_cases.test_project_contracts","test_cases.test_qos_evpn_uplink_generation","test_cases.test_terminal_l2_stp_generation","test_cases.test_topology_consistency","test_cases.test_v2_generation_flow","test_cases.test_v2_project_schema","test_cases.test_xlsx_zero_row_fail_closed","test_cases.test_xlsx_zero_row_workflow"]},{"id":"monitoring-collection","description":"监控页面、采集 worker、IB 分析、手工比对和分组交接","tests":["test_cases.test_backup_auth_transport_workflow","test_cases.test_collector_inventory_pubkey","test_cases.test_collector_inventory_pubkey_workflow","test_cases.test_ib_analysis_domain","test_cases.test_manual_applied_config","test_cases.test_monitor_stack_review","test_cases.test_ztp_monitor_watch_resilience","test_cases.test_ztp_monitor_watch_runtime_workflow","test_cases.test_ztp_group_handoff","test_cases.test_ztp_group_handoff_display"]},{"id":"ztp-runtime","description":"DHCP 租约、ZTP 身份、前缀边界、应用回执和端到端运行流","tests":["test_cases.test_bootstrap_config_fetch_contract","test_cases.test_bootstrap_config_fetch_workflow","test_cases.test_dhcp_runtime_reassignment","test_cases.test_full_flow_integration","test_cases.test_ztp_applied_receipt","test_cases.test_ztp_http_identity_binding","test_cases.test_ztp_prefix_runtime_boundary","test_cases.test_ztp_release_core_review"]},{"id":"vm-validation","description":"Ubuntu 管理 VM 只读验收器自身的本地合同","tests":["test_cases.test_vm_validation_runner"]}],"test_rules":[{"id":"day0_release_operations","paths":["DAY0-Prepare/01-a-setup.py","DAY0-Prepare/02-unsetup.py","DAY0-Prepare/11-load.py","DAY0-Prepare/13-unload.py"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_load_release_transaction","test_cases.test_dhcp_switch_scope_preservation","test_cases.test_dhcp_switch_scope_preservation_workflow","test_cases.test_bootstrap_config_fetch_contract","test_cases.test_bootstrap_config_fetch_workflow","test_cases.test_flow_release_platform_matrix","test_cases.test_project_contracts","test_cases.test_terminal_l2_stp_generation","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow","test_cases.test_ztp_service_runtime","test_cases.test_ztp_container_runtime","test_cases.test_docker_management_ssh_key","test_cases.test_docker_destructive_confirmation","test_cases.test_docker_destructive_confirmation_workflow","test_cases.test_ztp_monitor_watch_runtime_workflow","test_cases.test_xlsx_zero_row_fail_closed","test_cases.test_xlsx_zero_row_workflow"]},{"id":"ztp_monitor_runtime","paths":["DAY0-Prepare/12-ztp-monitor.py"],"tests":["test_cases.test_monitor_stack_review","test_cases.test_project_contracts","test_cases.test_full_flow_integration","test_cases.test_ztp_http_identity_binding","test_cases.test_ztp_group_handoff","test_cases.test_ztp_group_handoff_display","test_cases.test_ztp_service_runtime","test_cases.test_ztp_container_runtime","test_cases.test_ztp_monitor_watch_resilience","test_cases.test_ztp_monitor_watch_runtime_workflow"]},{"id":"shared_switch_collectors","paths":["ethernet/monitor/*","infiniband/monitor/*","nvlink/monitor/*"],"tests":["test_cases.test_monitor_stack_review","test_cases.test_project_contracts","test_cases.test_collector_inventory_pubkey","test_cases.test_collector_inventory_pubkey_workflow"]},{"id":"ib_nvos_bringup","paths":["infiniband/bringup/*"],"tests":["test_cases.test_monitor_stack_review"]},{"id":"infra_lifecycle","paths":["infra/*"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_apache_publication_boundary","test_cases.test_infra_check_and_manual_reset","test_cases.test_monitor_authority_entrypoints","test_cases.test_monitor_authority_semantic_workflow"]},{"id":"container_ztp_runtime","paths":["infra/docker/*.py","infra/docker/*.sh"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_ztp_service_runtime","test_cases.test_deployment_writer_lock","test_cases.test_load_release_transaction","test_cases.test_monitor_authority_entrypoints","test_cases.test_monitor_authority_semantic_workflow","test_cases.test_docker_management_ssh_key","test_cases.test_docker_destructive_confirmation","test_cases.test_docker_destructive_confirmation_workflow","test_cases.test_ztp_monitor_watch_runtime_workflow","test_cases.test_reference_only_selector_workflow"]},{"id":"monitor_controls_workers","paths":["monitor/*"],"tests":["test_cases.test_monitor_stack_review","test_cases.test_project_contracts","test_cases.test_ztp_group_handoff","test_cases.test_ztp_group_handoff_display","test_cases.test_monitor_authority_entrypoints","test_cases.test_monitor_authority_semantic_workflow","test_cases.test_ztp_monitor_watch_resilience","test_cases.test_ztp_monitor_watch_runtime_workflow"]},{"id":"package_transfer_and_locking","paths":["tools/_package_common.py","tools/deploy-upload-archive.py","tools/deployment_lock.py","tools/deployment_prewrite_guard.py","tools/import-from-download.py","tools/sync-code.py","tools/tar-for-download.py","tools/tar-for-upload.py"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_deployment_writer_lock","test_cases.test_deploy_upload_archive","test_cases.test_upload_package_contract","test_cases.test_download_cli_contract","test_cases.test_import_from_download_target","test_cases.test_predeploy_test_gate","test_cases.test_reference_only_selector_workflow"]},{"id":"deployment_artifact_bundles","paths":["tools/deploy-shared-artifacts.py","tools/package-project-image.py","tools/package-shared-artifacts.py"],"tests":["test_cases.test_project_image_bundle","test_cases.test_shared_artifact_bundle","test_cases.test_deploy_upload_archive","test_cases.test_upload_package_contract","test_cases.test_load_release_transaction","test_cases.test_ztp_container_runtime"]},{"id":"diagnostic_bundle","paths":["tools/collect-ztp-diagnostics.py"],"tests":["test_cases.test_diagnostic_bundle"]},{"id":"control_auth","paths":["tools/control-auth.py"],"tests":["test_cases.test_control_auth","test_cases.test_monitor_authority_semantic_workflow","test_cases.test_monitor_authority_entrypoints","test_cases.test_apache_publication_boundary","test_cases.test_ztp_container_runtime"]},{"id":"ztp_service_runtime","paths":["tools/ztp_service_runtime.py"],"tests":["test_cases.test_ztp_service_runtime","test_cases.test_ztp_container_runtime","test_cases.test_load_release_transaction","test_cases.test_monitor_stack_review","test_cases.test_monitor_writer_quiesce","test_cases.test_ztp_monitor_watch_resilience","test_cases.test_ztp_monitor_watch_runtime_workflow"]},{"id":"monitor_governed_writer_quiesce","paths":["DAY0-Prepare/01-a-setup.py","DAY0-Prepare/02-unsetup.py","DAY0-Prepare/11-load.py","DAY0-Prepare/13-unload.py","ztp/config/isc-dhcp-server/c1-generate_dhcp.py","ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py","tools/password-update.py","ztp/optimize/feedback.py","tools/deployment_prewrite_guard.py"],"tests":["test_cases.test_monitor_writer_quiesce"]},{"id":"password_update","paths":["tools/password-update.py"],"tests":["test_cases.test_password_update"]},{"id":"repository_governance","paths":["tools/project_contract.py","tools/update-root-readme.py","tools/update-user-manual.py"],"tests":["test_cases.test_project_contracts","test_cases.test_documentation_catalog","test_cases.test_change_aware_test_runner","test_cases.test_test_case_repository","test_cases.test_terminal_l2_stp_generation","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow","test_cases.test_reference_only_path_disposition"]},{"id":"network_analysis_tools","paths":["tools/ib-tool-Jie/*","tools/ibdiagnet-analyze-tool/*","tools/lldp-analyze-tool/*"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_project_contracts","test_cases.test_ib_analysis_domain"]},{"id":"ztp_backup","paths":["ztp/backup/*"],"tests":["test_cases.test_ztp_release_core_review","test_cases.test_backup_auth_transport_workflow","test_cases.test_project_contracts","test_cases.test_monitor_stack_review","test_cases.test_ztp_container_runtime"]},{"id":"topology_consistency","paths":["ztp/config/topology_rules.py","ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py","ztp/config/nvos/template/P2P/p2p-to-validation.py","tools/lldp-analyze-tool/analyze_lldp.py"],"tests":["test_cases.test_topology_consistency"]},{"id":"ztp_config_generation","paths":["ztp/config/*"],"tests":["test_cases.test_ztp_release_core_review","test_cases.test_project_contracts","test_cases.test_load_release_transaction","test_cases.test_dhcp_switch_scope_preservation","test_cases.test_dhcp_switch_scope_preservation_workflow","test_cases.test_ztp_prefix_runtime_boundary","test_cases.test_flow_release_platform_matrix","test_cases.test_cumulus_snippet_rendering","test_cases.test_mlag_evpn_generation","test_cases.test_terminal_l2_stp_generation","test_cases.test_qos_evpn_uplink_generation","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow","test_cases.test_xlsx_zero_row_fail_closed","test_cases.test_xlsx_zero_row_workflow"]},{"id":"dhcp_runtime_identity","paths":["ztp/dhcp_runtime_inventory.py","ztp/dynamic_air_inventory.py"],"tests":["test_cases.test_dhcp_runtime_reassignment","test_cases.test_project_contracts","test_cases.test_full_flow_integration","test_cases.test_load_release_transaction","test_cases.test_flow_release_platform_matrix"]},{"id":"environment_probe","paths":["ztp/environment_probe.py"],"tests":["test_cases.test_ztp_http_identity_binding","test_cases.test_project_contracts"]},{"id":"manual_ztp_reset","paths":["ztp/manual-reset.py","ztp/manual-ztp.py"],"tests":["test_cases.test_monitor_stack_review","test_cases.test_manual_applied_config","test_cases.test_ztp_applied_receipt","test_cases.test_project_contracts","test_cases.test_infra_check_and_manual_reset"]},{"id":"nvue_normalization","paths":["ztp/nvue_normalizer.py"],"tests":["test_cases.test_nvue_normalizer","test_cases.test_manual_applied_config"]},{"id":"optimization_feedback","paths":["ztp/optimize/*"],"tests":["test_cases.test_feedback_global_writeback","test_cases.test_feedback_global_writeback_workflow","test_cases.test_optimize_output_layout","test_cases.test_nvue_normalizer","test_cases.test_ztp_release_core_review","test_cases.test_project_contracts","test_cases.test_terminal_l2_stp_generation","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow"]},{"id":"bootstrap_runtime","paths":["ztp/templates/ztp-bootstrap.sh"],"tests":["test_cases.test_bootstrap_config_fetch_contract","test_cases.test_bootstrap_config_fetch_workflow","test_cases.test_ztp_applied_receipt","test_cases.test_ztp_release_core_review","test_cases.test_ztp_prefix_runtime_boundary"]}],"workflows":[{"id":"monitor_authority_lifecycle_to_cgi","members":["tools/control-auth.py","monitor/ztp-monitor-control.cgi","infra/infra-setup.sh","infra/infra-teardown.sh","infra/docker/deploy.sh","infra/docker/hostlock.py","infra/docker/entrypoint.py","infra/docker/activate.py","infra/docker/healthcheck.py","infra/docker/hostctl.py"],"tests":["test_cases.test_monitor_authority_semantic_workflow","test_cases.test_monitor_authority_entrypoints","test_cases.test_monitor_authority_source_guard","test_cases.test_control_auth","test_cases.test_monitor_stack_review","test_cases.test_apache_publication_boundary","test_cases.test_ztp_container_runtime"]},{"id":"docker_management_ssh_key_lifecycle","members":[".dockerignore","infra/docker/Dockerfile.dockerignore","infra/docker/deploy.sh","infra/docker/entrypoint.py","infra/docker/hostctl.py","infra/docker/hostlock.py","infra/docker/management_ssh_key.py","DAY0-Prepare/11-load.py","tools/_package_common.py","tools/package-project-image.py","tools/project_contract.py","tools/sync-code.py","tools/tar-for-upload.py","tools/collect-ztp-diagnostics.py"],"tests":["test_cases.test_docker_management_ssh_key","test_cases.test_project_contracts","test_cases.test_ztp_container_runtime","test_cases.test_upload_package_contract","test_cases.test_diagnostic_bundle","test_cases.test_project_image_bundle","test_cases.test_public_repository_contract","test_cases.test_deployment_writer_lock","test_cases.test_reference_only_selector_workflow"]},{"id":"deployment_release_transaction","members":["DAY0-Prepare/01-a-setup.py","DAY0-Prepare/02-unsetup.py","DAY0-Prepare/11-load.py","DAY0-Prepare/13-unload.py","infra/*","tools/control-auth.py","tools/deployment_lock.py","ztp/config/*"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_load_release_transaction","test_cases.test_apache_publication_boundary","test_cases.test_flow_release_platform_matrix","test_cases.test_terminal_l2_stp_generation","test_cases.test_v2_generation_flow"]},{"id":"containerized_ztp_lifecycle","members":[".dockerignore","requirements-container-top-level.lock","infra/docker/Dockerfile.dockerignore","infra/docker/activate.py","infra/docker/deploy.sh","infra/docker/entrypoint.py","infra/docker/healthcheck.py","infra/docker/hostlock.py","infra/docker/hostctl.py","DAY0-Prepare/11-load.py","DAY0-Prepare/12-ztp-monitor.py","DAY0-Prepare/13-unload.py","tools/_package_common.py","tools/control-auth.py","tools/deploy-shared-artifacts.py","tools/deploy-upload-archive.py","tools/deployment_lock.py","tools/deployment_prewrite_guard.py","tools/package-project-image.py","tools/package-shared-artifacts.py","tools/sync-code.py","tools/tar-for-upload.py","tools/ztp_service_runtime.py","monitor/switch-collection-worker.py","monitor/manual-ztp-worker.py"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_ztp_service_runtime","test_cases.test_deployment_writer_lock","test_cases.test_deploy_upload_archive","test_cases.test_project_image_bundle","test_cases.test_shared_artifact_bundle","test_cases.test_upload_package_contract","test_cases.test_load_release_transaction","test_cases.test_monitor_stack_review","test_cases.test_ztp_monitor_watch_runtime_workflow","test_cases.test_reference_only_selector_workflow"]},{"id":"docker_destructive_confirmation","members":["infra/docker/deploy.sh","infra/docker/hostlock.py","infra/docker/hostctl.py","DAY0-Prepare/13-unload.py"],"tests":["test_cases.test_docker_destructive_confirmation","test_cases.test_docker_destructive_confirmation_workflow"]},{"id":"ztp_monitor_watch_resilience","members":["DAY0-Prepare/11-load.py","DAY0-Prepare/12-ztp-monitor.py","infra/docker/activate.py","monitor/generate-monitor-html.py","tools/ztp_service_runtime.py"],"tests":["test_cases.test_ztp_monitor_watch_resilience","test_cases.test_ztp_monitor_watch_runtime_workflow"]},{"id":"dhcp_to_ztp_identity","members":["DAY0-Prepare/12-ztp-monitor.py","ztp/config/isc-dhcp-server/c1-generate_dhcp.py","ztp/dhcp_runtime_inventory.py","ztp/dynamic_air_inventory.py","ztp/environment_probe.py","ztp/templates/ztp-bootstrap.sh"],"tests":["test_cases.test_full_flow_integration","test_cases.test_ztp_http_identity_binding","test_cases.test_dhcp_runtime_reassignment","test_cases.test_ztp_prefix_runtime_boundary","test_cases.test_flow_release_platform_matrix","test_cases.test_v2_generation_flow"]},{"id":"bootstrap_config_fetch","members":["DAY0-Prepare/11-load.py","ztp/templates/ztp-bootstrap.sh"],"tests":["test_cases.test_bootstrap_config_fetch_contract","test_cases.test_bootstrap_config_fetch_workflow"]},{"id":"manual_ztp_monitor_compare","members":["DAY0-Prepare/12-ztp-monitor.py","monitor/*","ztp/manual-reset.py","ztp/manual-ztp.py","ztp/nvue_normalizer.py","ztp/templates/ztp-bootstrap.sh"],"tests":["test_cases.test_monitor_stack_review","test_cases.test_manual_applied_config","test_cases.test_nvue_normalizer","test_cases.test_ztp_applied_receipt"]},{"id":"switch_collection_publication","members":["DAY0-Prepare/12-ztp-monitor.py","monitor/*","ethernet/monitor/*","infiniband/monitor/*","nvlink/monitor/*","ztp/backup/*"],"tests":["test_cases.test_backup_auth_transport_workflow","test_cases.test_monitor_stack_review","test_cases.test_project_contracts","test_cases.test_ztp_container_runtime","test_cases.test_ztp_http_identity_binding","test_cases.test_ztp_group_handoff","test_cases.test_ztp_group_handoff_display","test_cases.test_collector_inventory_pubkey","test_cases.test_collector_inventory_pubkey_workflow"]},{"id":"switch_backup_authentication","members":["monitor/switch-collection-control.cgi","monitor/switch-collection-worker.py","ztp/backup/yaml-collect.py"],"tests":["test_cases.test_backup_auth_transport_workflow","test_cases.test_monitor_stack_review","test_cases.test_ztp_container_runtime","test_cases.test_ztp_release_core_review"]},{"id":"package_sync_load","members":["DAY0-Prepare/01-a-setup.py","DAY0-Prepare/11-load.py","infra/*","tools/_package_common.py","tools/collect-ztp-diagnostics.py","tools/control-auth.py","tools/deploy-shared-artifacts.py","tools/deploy-upload-archive.py","tools/deployment_lock.py","tools/deployment_prewrite_guard.py","tools/import-from-download.py","tools/package-project-image.py","tools/package-shared-artifacts.py","tools/sync-code.py","tools/tar-for-download.py","tools/tar-for-upload.py"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_deployment_writer_lock","test_cases.test_deploy_upload_archive","test_cases.test_project_image_bundle","test_cases.test_shared_artifact_bundle","test_cases.test_upload_package_contract","test_cases.test_download_cli_contract","test_cases.test_import_from_download_target","test_cases.test_diagnostic_bundle","test_cases.test_predeploy_test_gate","test_cases.test_load_release_transaction","test_cases.test_reference_only_selector_workflow"]},{"id":"config_generate_publish_compare","members":["DAY0-Prepare/11-load.py","tools/deployment_lock.py","ztp/backup/*","ztp/config/*","ztp/dhcp_runtime_inventory.py","ztp/dynamic_air_inventory.py","ztp/manual-ztp.py","ztp/nvue_normalizer.py","ztp/optimize/*"],"tests":["test_cases.test_feedback_global_writeback","test_cases.test_feedback_global_writeback_workflow","test_cases.test_load_release_transaction","test_cases.test_dhcp_switch_scope_preservation","test_cases.test_dhcp_switch_scope_preservation_workflow","test_cases.test_ztp_release_core_review","test_cases.test_manual_applied_config","test_cases.test_nvue_normalizer","test_cases.test_optimize_output_layout","test_cases.test_flow_release_platform_matrix","test_cases.test_cumulus_snippet_rendering","test_cases.test_mlag_evpn_generation","test_cases.test_terminal_l2_stp_generation","test_cases.test_qos_evpn_uplink_generation","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow","test_cases.test_xlsx_zero_row_fail_closed","test_cases.test_xlsx_zero_row_workflow"]},{"id":"password_rotation_config_generation","members":["DAY0-Prepare/11-load.py","tools/password-update.py","ztp/config/cumulus/template/90-c2-generate_configs.py"],"tests":["test_cases.test_password_update"]},{"id":"password_rotation_sync_preservation","members":["tools/password-update.py","tools/sync-code.py"],"tests":["test_cases.test_password_update","test_cases.test_deployment_writer_lock"]},{"id":"ib_nvl_bringup_observability","members":["infiniband/bringup/*","ethernet/monitor/*","infiniband/monitor/*","nvlink/monitor/*","monitor/dot_to_html.py","monitor/generate-monitor-html.py"],"tests":["test_cases.test_monitor_stack_review","test_cases.test_project_contracts"]},{"id":"offline_network_analysis","members":["tools/ib-tool-Jie/*","tools/ibdiagnet-analyze-tool/*","tools/lldp-analyze-tool/*"],"tests":["test_cases.test_ops_deployment_review","test_cases.test_project_contracts","test_cases.test_ib_analysis_domain"]},{"id":"topology_inventory_and_lldp_identity","members":["ztp/config/topology_rules.py","ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py","ztp/config/nvos/template/P2P/p2p-to-validation.py","tools/lldp-analyze-tool/analyze_lldp.py"],"tests":["test_cases.test_topology_consistency","test_cases.test_upload_package_contract"]},{"id":"user_manual_publication","members":["tools/update-user-manual.py","tools/_package_common.py","tools/sync-code.py","user-manual.html"],"tests":["test_cases.test_documentation_catalog","test_cases.test_project_contracts","test_cases.test_upload_package_contract","test_cases.test_deployment_writer_lock"]},{"id":"test_and_documentation_governance","members":["tools/project_contract.py","tools/update-root-readme.py","tools/update-user-manual.py"],"tests":["test_cases.test_change_aware_test_runner","test_cases.test_test_case_repository","test_cases.test_documentation_catalog","test_cases.test_project_contracts","test_cases.test_terminal_l2_stp_generation","test_cases.test_reference_only_path_disposition","test_cases.test_reference_only_selector_workflow"]},{"id":"monitor_governed_writer_quiesce","members":["tools/ztp_service_runtime.py","DAY0-Prepare/01-a-setup.py","DAY0-Prepare/02-unsetup.py","DAY0-Prepare/11-load.py","DAY0-Prepare/12-ztp-monitor.py","DAY0-Prepare/13-unload.py","ztp/config/isc-dhcp-server/c1-generate_dhcp.py","ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py","tools/password-update.py","ztp/optimize/feedback.py","tools/deployment_prewrite_guard.py","tools/import-from-download.py"],"tests":["test_cases.test_monitor_writer_quiesce_workflow"]}],"path_rules":[{"paths":["test_cases/script_test_manifest.json","test_cases/run_related_tests.py"],"tests":[],"full_suite":true},{"paths":["test_cases/run_vm_validation.py"],"tests":["test_cases.test_vm_validation_runner"]},{"paths":["test_cases/public_project_fixture.py"],"tests":["test_cases.test_public_project_fixture_contract","test_cases.test_public_project_fixture_workflow"]},{"paths":[".github/workflows/monitor-authority-root.yml","test_cases/monitor_authority_root_warden.py","test_cases/monitor_authority_source_guard.py","test_cases/run_monitor_authority_entrypoints.sh","test_cases/REAL_ENVIRONMENT.md"],"tests":["test_cases.test_monitor_authority_entrypoints","test_cases.test_monitor_authority_semantic_workflow","test_cases.test_monitor_authority_source_guard"]},{"paths":[".gitattributes",".gitignore",".github/README.md",".github/workflows/tests.yml","PUBLIC_REPOSITORY.md","SECURITY.md","examples/public-project/*","requirements-container-top-level.lock","requirements-dev.txt","test_cases/audit_public_tree.py"],"tests":["test_cases.test_public_repository_contract","test_cases.test_ztp_container_runtime","test_cases.test_change_aware_test_runner","test_cases.test_reference_only_path_disposition","test_cases.test_reference_only_selector_workflow","test_cases.test_public_s_phase_contract","test_cases.test_public_s_phase_workflow"]},{"paths":["AGENTS.md","index.html","user-manual.html","*/README.md","*/*/README.md","*/*/*/README.md"],"tests":["test_cases.test_documentation_catalog","test_cases.test_project_contracts","test_cases.test_upload_package_contract","test_cases.test_deployment_writer_lock"]},{"paths":[".dockerignore","infra/docker/*"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_ztp_service_runtime","test_cases.test_deployment_writer_lock","test_cases.test_upload_package_contract"]},{"paths":["ztp/templates/ztp.json"],"tests":["test_cases.test_project_contracts","test_cases.test_ztp_release_core_review"]},{"paths":["ztp/config/cumulus/template/P2P/01-inventory.log"],"tests":["test_cases.test_ztp_release_core_review","test_cases.test_load_release_transaction"]},{"paths":["tools/lldp-analyze-tool/04-lldp-device-aliases.json"],"tests":["test_cases.test_topology_consistency","test_cases.test_upload_package_contract"]},{"paths":["DAY0-Prepare/template/*","ztp/config/cumulus/ar_profile_custom.conf","ztp/config/cumulus/template/P2P/*.log","ztp/config/cumulus/template/P2P/*.json","ztp/config/cumulus/template/P2P/*.dot","ztp/config/nvos/disable-password-hardening.nv","ztp/config/nvos/template/P2P/*.log"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_load_release_transaction","test_cases.test_project_contracts","test_cases.test_upload_package_contract","test_cases.test_v2_generation_flow","test_cases.test_v2_project_schema"]},{"paths":["DAY0-Prepare/template/01-global.yaml","DAY0-Prepare/template/02-devices_config.csv"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_project_contracts","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow"]},{"paths":["ztp/config/cumulus/template/03-templates-j2/*.yaml.j2"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_project_contracts","test_cases.test_v2_project_schema","test_cases.test_v2_generation_flow","test_cases.test_change_aware_test_runner","test_cases.test_flow_release_platform_matrix"],"complete_tracked_support":true},{"paths":["ztp/config/cumulus/default*.yaml","ztp/config/nvos/default*.yaml"],"tests":["test_cases.test_ztp_container_runtime","test_cases.test_load_release_transaction","test_cases.test_project_contracts","test_cases.test_upload_package_contract","test_cases.test_v2_generation_flow","test_cases.test_v2_project_schema","test_cases.test_change_aware_test_runner"],"complete_tracked_support":true},{"paths":["ztp/config/cumulus/template/03-templates-j2/border.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oobofoob-spine.yaml.j2"],"tests":["test_cases.test_mlag_evpn_generation","test_cases.test_project_contracts","test_cases.test_ztp_release_core_review"]}]}''')
S_MANIFEST_SCRIPT_ORDER = tuple(json.loads(r'''["DAY0-Prepare/01-a-setup.py","DAY0-Prepare/02-unsetup.py","DAY0-Prepare/11-load.py","DAY0-Prepare/12-ztp-monitor.py","DAY0-Prepare/13-unload.py","ethernet/monitor/cron.sh","ethernet/monitor/post-collect.py","ethernet/monitor/sw-info.sh","ethernet/monitor/sw-link.sh","infiniband/bringup/ndr/OS-CPLD-upgrade.sh","infiniband/bringup/ndr/data-collect-IB.sh","infiniband/bringup/xdr-initial-setup/initial-setup.py","infiniband/bringup/xdr-upgrade/upgrade.sh","infiniband/monitor/cron.sh","infiniband/monitor/sw-info.sh","infiniband/monitor/sw-link.sh","infra/check_infra.py","infra/deploy_infra.py","infra/docker/activate.py","infra/docker/deploy.sh","infra/docker/entrypoint.py","infra/docker/healthcheck.py","infra/docker/hostlock.py","infra/docker/hostctl.py","infra/docker/management_ssh_key.py","infra/infra-setup.sh","infra/infra-teardown.sh","monitor/dot_to_html.py","monitor/generate-monitor-html.py","monitor/manual-ztp-control.cgi","monitor/manual-ztp-worker.py","monitor/switch-collection-control.cgi","monitor/switch-collection-worker.py","monitor/switch_collection_gate.py","monitor/ztp-monitor-control.cgi","nvlink/monitor/cron.sh","nvlink/monitor/sw-info.sh","nvlink/monitor/sw-link.sh","tools/_package_common.py","tools/collect-ztp-diagnostics.py","tools/control-auth.py","tools/deployment_prewrite_guard.py","tools/deploy-shared-artifacts.py","tools/deploy-upload-archive.py","tools/deployment_lock.py","tools/ib-tool-Jie/ib_tool_box/lib/__init__.py","tools/ib-tool-Jie/ib_tool_box/lib/connection.py","tools/ib-tool-Jie/ib_tool_box/lib/excel.py","tools/ib-tool-Jie/ib_tool_box/lib/inventory.py","tools/ib-tool-Jie/ib_tool_box/lib/link_errors.py","tools/ib-tool-Jie/ib_tool_box/lib/parsers/__init__.py","tools/ib-tool-Jie/ib_tool_box/lib/parsers/db_csv.py","tools/ib-tool-Jie/ib_tool_box/lib/parsers/net_dump.py","tools/ib-tool-Jie/ib_tool_box/lib/parsers/net_dump_ext.py","tools/ib-tool-Jie/ib_tool_box/lib/parsers/partitions_conf.py","tools/ib-tool-Jie/ib_tool_box/lib/parsers/smdb.py","tools/ib-tool-Jie/ib_tool_box/lib/reporting.py","tools/ib-tool-Jie/ib_tool_box/scripts/check_hca_ooo_sl_mask.py","tools/ib-tool-Jie/ib_tool_box/scripts/check_ib_link_errors.py","tools/ib-tool-Jie/ib_tool_box/scripts/parse_ib_partition_config.py","tools/ib-tool-Jie/ib_tool_box/scripts/parse_ib_smdb.py","tools/ib-tool-Jie/ib_tool_box/scripts/parse_m_keys.py","tools/ib-tool-Jie/ib_tool_box/scripts/show_ib_inventory.py","tools/ib-tool-Jie/ib_tool_box/scripts/trace_ib_path.py","tools/ib-tool-Jie/ib_tool_box/scripts/validate_ib_topology.py","tools/ibdiagnet-analyze-tool/analyze.py","tools/ibdiagnet-analyze-tool/lib/__init__.py","tools/ibdiagnet-analyze-tool/lib/connection.py","tools/ibdiagnet-analyze-tool/lib/excel.py","tools/ibdiagnet-analyze-tool/lib/inventory.py","tools/ibdiagnet-analyze-tool/lib/link_errors.py","tools/ibdiagnet-analyze-tool/lib/parsers/__init__.py","tools/ibdiagnet-analyze-tool/lib/parsers/db_csv.py","tools/ibdiagnet-analyze-tool/lib/parsers/iblinkinfo.py","tools/ibdiagnet-analyze-tool/lib/parsers/net_dump.py","tools/ibdiagnet-analyze-tool/lib/parsers/net_dump_ext.py","tools/ibdiagnet-analyze-tool/lib/parsers/partitions_conf.py","tools/ibdiagnet-analyze-tool/lib/parsers/smdb.py","tools/ibdiagnet-analyze-tool/lib/reporting.py","tools/ibdiagnet-analyze-tool/lib/snapshot.py","tools/ibdiagnet-analyze-tool/lib/topology.py","tools/ibdiagnet-analyze-tool/scripts/check_hca_ooo_sl_mask.py","tools/ibdiagnet-analyze-tool/scripts/check_ib_link_errors.py","tools/ibdiagnet-analyze-tool/scripts/parse_ib_partition_config.py","tools/ibdiagnet-analyze-tool/scripts/parse_ib_smdb.py","tools/ibdiagnet-analyze-tool/scripts/parse_m_keys.py","tools/ibdiagnet-analyze-tool/scripts/show_ib_inventory.py","tools/ibdiagnet-analyze-tool/scripts/trace_ib_path.py","tools/ibdiagnet-analyze-tool/scripts/validate_ib_topology.py","tools/import-from-download.py","tools/lldp-analyze-tool/analyze_lldp.py","tools/lldp-analyze-tool/build_report.py","tools/password-update.py","tools/package-project-image.py","tools/package-shared-artifacts.py","tools/project_contract.py","tools/sync-code.py","tools/tar-for-download.py","tools/tar-for-upload.py","tools/update-root-readme.py","tools/update-user-manual.py","tools/ztp_service_runtime.py","ztp/backup/yaml-collect.py","ztp/config/cumulus/d-hostname2mac.py","ztp/config/cumulus/template/90-c2-generate_configs.py","ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py","ztp/config/isc-dhcp-server/c1-generate_dhcp.py","ztp/config/nvos/d-hostname2mac.py","ztp/config/nvos/template/90-c2-generate_configs.py","ztp/config/nvos/template/P2P/p2p-to-validation.py","ztp/config/topology_rules.py","ztp/dhcp_runtime_inventory.py","ztp/dynamic_air_inventory.py","ztp/environment_probe.py","ztp/manual-reset.py","ztp/manual-ztp.py","ztp/nvue_normalizer.py","ztp/optimize/feedback.py","ztp/optimize/sample_links.py","ztp/templates/ztp-bootstrap.sh"]'''))
S_MANIFEST_SUPPORT_ORDER = tuple(json.loads(r'''[".dockerignore",".gitattributes",".github/workflows/monitor-authority-root.yml",".github/workflows/tests.yml",".gitignore","AGENTS.md","PUBLIC_REPOSITORY.md","SECURITY.md","examples/public-project/01-global.yaml.example","examples/public-project/02-devices_config.csv.example","examples/public-project/02-dhcp-subnet_config.csv.example","index.html","requirements-container-top-level.lock","requirements-dev.txt","test_cases/audit_public_tree.py","test_cases/REAL_ENVIRONMENT.md","test_cases/monitor_authority_root_warden.py","test_cases/monitor_authority_source_guard.py","test_cases/public_project_fixture.py","test_cases/run_monitor_authority_entrypoints.sh","test_cases/run_related_tests.py","test_cases/run_vm_validation.py","user-manual.html","DAY0-Prepare/template/.management-pubkeys","DAY0-Prepare/template/01-global.yaml","DAY0-Prepare/template/02-devices_config.csv","DAY0-Prepare/template/02-dhcp-subnet_config.csv","DAY0-Prepare/template/99-output-backup/.gitkeep","DAY0-Prepare/template/99-output-dhcp/.gitkeep","DAY0-Prepare/template/99-output-eth/.gitkeep","DAY0-Prepare/template/99-output-ib_nvl/.gitkeep","DAY0-Prepare/template/99-output-ib_nvl/bringup/ndr-upgrade-logs/.gitkeep","DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-initial-setup-logs/.gitkeep","DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-upgrade-logs/.gitkeep","DAY0-Prepare/template/99-output-monitor/.gitkeep","DAY0-Prepare/template/99-output-p2p/.gitkeep","DAY0-Prepare/template/99-output-ztp/.gitkeep","DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-amd64.bin","DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-vx.bin","DAY0-Prepare/template/laptop.pub","DAY0-Prepare/template/mgmt-server.pub","DAY0-Prepare/template/nvosv25-02-7002amd64.bin","DAY0-Prepare/template/nvosv25-02-8008amd64.bin","DAY0-Prepare/template/p2p.xlsx","infra/docker/.dockerignore","infra/docker/.gitignore","infra/docker/Dockerfile","infra/docker/Dockerfile.dockerignore","infra/docker/apache-ztp.conf","infra/docker/compose.yaml","infra/docker/container.env.example","infra/docker/logrotate-http-ztp.conf","infra/docker/rsyslog-dhcp.conf","infra/docker/runtime-contract.json","infra/docker/supervisord.conf","tools/lldp-analyze-tool/04-lldp-device-aliases.json","ztp/config/cumulus/ar_profile_custom.conf","ztp/config/cumulus/default.yaml","ztp/config/cumulus/default_5.16.5.yaml","ztp/config/cumulus/template/P2P/01-inventory.log","ztp/config/cumulus/template/P2P/02-port-mapping.log","ztp/config/cumulus/template/P2P/03-splitter.log","ztp/config/cumulus/template/P2P/air-template-no-oob.json","ztp/config/cumulus/template/P2P/air-template.json","ztp/config/cumulus/template/P2P/lldpq-template.dot","ztp/config/cumulus/template/03-templates-j2/_bridge_l2vlans.yaml.j2","ztp/config/cumulus/template/03-templates-j2/_dhcp_relay.yaml.j2","ztp/config/cumulus/template/03-templates-j2/_direct_vlan_ports.yaml.j2","ztp/config/cumulus/template/03-templates-j2/_extra_aaa_users.yaml.j2","ztp/config/cumulus/template/03-templates-j2/_global_evpn.yaml.j2","ztp/config/cumulus/template/03-templates-j2/_l2_svis.yaml.j2","ztp/config/cumulus/template/03-templates-j2/border.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oob-core.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oob-leaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oob-rack-tor.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oob-su-leaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oob-su-spine.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oobofoob-leaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/oobofoob-spine.yaml.j2","ztp/config/cumulus/template/03-templates-j2/tan-cp-1gleaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/tan-cp-leaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/tan-hps-leaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/tan-leaf.yaml.j2","ztp/config/cumulus/template/03-templates-j2/tan-spine.yaml.j2","ztp/config/cumulus/template/03-templates-j2/tan-su-leaf.yaml.j2","ztp/config/nvos/default.yaml","ztp/config/nvos/disable-password-hardening.nv","ztp/config/nvos/template/P2P/01-inventory.log","ztp/config/nvos/template/P2P/02-port-mapping.log","ztp/config/nvos/template/P2P/03-splitter.log","ztp/templates/ztp.json"]'''))


def _load_runner():
    path = ROOT / "test_cases/run_related_tests.py"
    spec = importlib.util.spec_from_file_location("s_phase_runner", path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load S runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _mode_and_bytes(path: Path) -> tuple[str, bytes]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        return "120000", os.readlink(path).encode("utf-8")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AssertionError(f"S authority must be regular or symlink: {path}")
    return ("100755" if metadata.st_mode & 0o111 else "100644"), path.read_bytes()


def _record_digest(paths, canonical=None) -> str:
    digest = hashlib.sha256()
    for relative in sorted(paths):
        mode, payload = _mode_and_bytes(ROOT / relative)
        target = canonical.get(relative, relative) if canonical else relative
        record = "\0".join((
            relative, target, mode, hashlib.sha256(payload).hexdigest(),
        )).encode("utf-8") + b"\0"
        digest.update(record)
    return digest.hexdigest()


def _manifest_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _manifest_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _manifest_values(item)


def _normalized_digest(value) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _assert_exact_mapping_tables(manifest) -> None:
    for key, expected in EXPECTED_S_MAPPING_TABLES.items():
        actual = manifest.get(key)
        if actual != expected:
            raise AssertionError(f"S manifest {key} differs from reviewed literal")
        if _normalized_digest(actual) != EXPECTED_S_MAPPING_DIGESTS[key]:
            raise AssertionError(f"S manifest {key} digest differs from reviewed literal")


def expected_s_manifest() -> dict:
    if set(S_MANIFEST_SCRIPT_ORDER) != set(S_PRODUCTION_PATHS):
        raise AssertionError("S manifest script serialization order is incomplete")
    if set(S_MANIFEST_SUPPORT_ORDER) != set(S_TRACKED_SUPPORT_PATHS):
        raise AssertionError("S manifest support serialization order is incomplete")
    value = {
        "schema_version": 1,
        "policy": (
            "Tests and assertions are human-reviewed; only approved hashes are "
            "updated automatically after a passing run."
        ),
        "baseline_tests": copy.deepcopy(EXPECTED_S_MAPPING_TABLES["baseline_tests"]),
        "test_suites": copy.deepcopy(EXPECTED_S_MAPPING_TABLES["test_suites"]),
        "tracked_support": list(S_MANIFEST_SUPPORT_ORDER),
        "scripts": {
            path: S_CANONICAL_OVERRIDES.get(path, path)
            for path in S_MANIFEST_SCRIPT_ORDER
        },
        "test_rules": copy.deepcopy(EXPECTED_S_MAPPING_TABLES["test_rules"]),
        "workflows": copy.deepcopy(EXPECTED_S_MAPPING_TABLES["workflows"]),
        "path_rules": copy.deepcopy(EXPECTED_S_MAPPING_TABLES["path_rules"]),
    }
    return value


def expected_s_manifest_bytes() -> bytes:
    payload = (
        json.dumps(expected_s_manifest(), ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    if len(payload) != EXPECTED_S_MANIFEST_SIZE:
        raise AssertionError("reviewed S manifest size drift")
    if hashlib.sha256(payload).hexdigest() != EXPECTED_S_MANIFEST_SHA256:
        raise AssertionError("reviewed S manifest digest drift")
    return payload


class PublicSPhaseDirectTests(unittest.TestCase):
    def test_literal_inventory_and_current_reviewed_bytes_are_frozen(self):
        self.assertEqual((120, 75, 91, 36), (
            len(S_PRODUCTION_PATHS), len(S_TEST_MODULES),
            len(S_TRACKED_SUPPORT_PATHS), len(S_ORDINARY_PATHS),
        ))
        self.assertEqual(len(S_PRODUCTION_PATHS), len(set(S_PRODUCTION_PATHS)))
        self.assertEqual(len(S_TEST_MODULES), len(set(S_TEST_MODULES)))
        self.assertEqual(len(S_TRACKED_SUPPORT_PATHS), len(set(S_TRACKED_SUPPORT_PATHS)))
        test_paths = {
            module.replace(".", "/") + ".py" for module in S_TEST_MODULES
        }
        partition = (
            set(S_PRODUCTION_PATHS), test_paths,
            set(S_TRACKED_SUPPORT_PATHS), set(S_ORDINARY_PATHS),
        )
        self.assertEqual(322, len(set().union(*partition)))
        for index, left in enumerate(partition):
            for right in partition[index + 1:]:
                self.assertEqual(set(), left & right)
        expected_canonical = {
            path: S_CANONICAL_OVERRIDES.get(path, path)
            for path in S_PRODUCTION_PATHS
        }
        actual = _load_runner().discover_source_scripts(ROOT)
        self.assertEqual(expected_canonical, actual)
        self.assertEqual(
            EXPECTED_PRODUCTION_RECORD_DIGEST,
            _record_digest(S_PRODUCTION_PATHS, expected_canonical),
        )
        reviewed_tests = tuple(
            module.replace(".", "/") + ".py"
            for module in S_TEST_MODULES
            if module not in {
                "test_cases.test_public_s_phase_contract",
                "test_cases.test_public_s_phase_workflow",
            }
        )
        self.assertEqual(73, len(reviewed_tests))
        self.assertEqual(
            EXPECTED_REVIEWED_TEST_RECORD_DIGEST,
            _record_digest(reviewed_tests),
        )
        self.assertEqual(
            EXPECTED_REVIEWED_SUPPORT_RECORD_DIGEST,
            _record_digest(
                path for path in S_TRACKED_SUPPORT_PATHS
                if path not in {
                    "test_cases/REAL_ENVIRONMENT.md", "user-manual.html",
                    "PUBLIC_REPOSITORY.md",
                }
            ),
        )
        public_repository = __import__("subprocess").run(
            ["git", "show", f"{Q02_COMMIT}:PUBLIC_REPOSITORY.md"],
            cwd=ROOT, stdout=__import__("subprocess").PIPE,
            stderr=__import__("subprocess").PIPE, check=False,
        )
        self.assertEqual(0, public_repository.returncode)
        self.assertEqual(
            EXPECTED_Q02_PUBLIC_REPOSITORY_SHA256,
            hashlib.sha256(public_repository.stdout).hexdigest(),
        )
        self.assertEqual(
            EXPECTED_REVIEWED_ORDINARY_RECORD_DIGEST,
            _record_digest(
                path for path in S_ORDINARY_PATHS
                if path not in {
                    ".github/README.md", "test_cases/README.md",
                    "test_cases/script_test_manifest.json",
                    "test_cases/script_test_approved_hashes.json",
                }
            ),
        )

    def test_s_manifest_has_exact_forward_and_reverse_closure(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(expected_s_manifest(), manifest)
        _assert_exact_mapping_tables(manifest)
        expected_scripts = {
            path: S_CANONICAL_OVERRIDES.get(path, path)
            for path in S_PRODUCTION_PATHS
        }
        self.assertEqual(expected_scripts, manifest.get("scripts"))
        self.assertEqual(
            set(S_TRACKED_SUPPORT_PATHS), set(manifest.get("tracked_support", ())),
        )
        memberships = {
            test: [suite["id"] for suite in manifest.get("test_suites", ())
                   if test in suite.get("tests", ())]
            for test in S_TEST_MODULES
        }
        self.assertEqual(
            set(S_TEST_MODULES),
            {test for test, suites in memberships.items() if len(suites) == 1},
        )
        all_suite_tests = [
            test for suite in manifest.get("test_suites", ())
            for test in suite.get("tests", ())
        ]
        self.assertEqual(set(S_TEST_MODULES), set(all_suite_tests))
        self.assertEqual(len(S_TEST_MODULES), len(all_suite_tests))
        runner = _load_runner()
        canonical_targets = set(expected_scripts.values())
        for script, canonical in expected_scripts.items():
            direct = [rule for rule in manifest.get("test_rules", ())
                      if any(runner.path_matches(script, [pattern])
                             for pattern in rule.get("paths", ()))]
            workflows = [flow for flow in manifest.get("workflows", ())
                         if any(runner.path_matches(script, [pattern])
                                for pattern in flow.get("members", ()))]
            with self.subTest(script=script):
                self.assertTrue(direct, f"missing direct rule: {script}")
                self.assertTrue(workflows, f"missing workflow: {script}")
                real_workflows = []
                for flow in workflows:
                    selected = {
                        target
                        for candidate, target in expected_scripts.items()
                        if any(runner.path_matches(candidate, [pattern])
                               for pattern in flow.get("members", ()))
                    }
                    if len(selected & canonical_targets) >= 2:
                        real_workflows.append(flow)
                self.assertTrue(
                    real_workflows,
                    f"workflow lacks two real canonical targets: {canonical}",
                )
        primary = {
            test: sum(
                test in suite.get("tests", ())
                for suite in manifest.get("test_suites", ())
            )
            for test in S_TEST_MODULES
        }
        self.assertEqual({test: 1 for test in S_TEST_MODULES}, primary)
        for table_name in ("test_rules", "workflows", "path_rules"):
            for record in manifest.get(table_name, ()):
                unknown = set(record.get("tests", ())) - set(S_TEST_MODULES)
                self.assertEqual(set(), unknown, (table_name, record.get("id")))

    def test_s_mapping_tables_reject_clear_swap_and_overbroad_mutations(self):
        reviewed = copy.deepcopy(EXPECTED_S_MAPPING_TABLES)
        _assert_exact_mapping_tables(reviewed)
        mutations = []
        for key in EXPECTED_S_MAPPING_TABLES:
            candidate = copy.deepcopy(reviewed)
            candidate[key] = []
            mutations.append((f"clear-{key}", candidate))
        swapped = copy.deepcopy(reviewed)
        tests = swapped["test_suites"][0]["tests"]
        tests[0] = swapped["test_suites"][1]["tests"][0]
        mutations.append(("same-count-suite-swap", swapped))
        broad_rule = copy.deepcopy(reviewed)
        broad_rule["test_rules"][0]["paths"] = ["*"]
        mutations.append(("overbroad-direct-rule", broad_rule))
        broad_workflow = copy.deepcopy(reviewed)
        broad_workflow["workflows"][0]["members"] = ["*"]
        mutations.append(("overbroad-workflow", broad_workflow))
        broad_path = copy.deepcopy(reviewed)
        broad_path["path_rules"][0]["paths"] = ["**"]
        mutations.append(("overbroad-path-rule", broad_path))
        empty_path = copy.deepcopy(reviewed)
        empty_path["path_rules"].append({
            "paths": ["infra/apache/*"],
            "tests": ["test_cases.test_apache_publication_boundary"],
        })
        mutations.append(("empty-stale-path-rule", empty_path))
        for label, candidate in mutations:
            with self.subTest(mutation=label):
                with self.assertRaises(AssertionError):
                    _assert_exact_mapping_tables(candidate)

    def test_s_contract_excludes_every_deferred_or_private_family(self):
        self.assertEqual((8, 7, 23, 14, 2), (
            len(Q01_PUBLIC_DOCUMENT_PATHS), len(LIFECYCLE_PATHS),
            len(PRIVATE_DOCUMENT_PATHS), len(CABLETRACKER_PATHS),
            len(P_PUBLICATION_TEST_PATHS),
        ))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        values = set(_manifest_values(manifest))
        forbidden = {
            *Q01_PUBLIC_DOCUMENT_PATHS, *LIFECYCLE_PATHS,
            *PRIVATE_DOCUMENT_PATHS, *CABLETRACKER_PATHS,
            *P_PUBLICATION_TEST_PATHS,
        }
        self.assertEqual(set(), values & forbidden)
        self.assertTrue(set(S_TRACKED_SUPPORT_PATHS).isdisjoint(forbidden))
        self.assertNotIn("test_cases.test_public_publication_contract", S_TEST_MODULES)
        self.assertNotIn("test_cases.test_public_publication_workflow", S_TEST_MODULES)

    def test_s_phase_blobs_are_index_owned_not_worktree_rewrites(self):
        self.assertEqual(5, len(S_PHASE_INDEX_PATHS))
        for relative in S_PHASE_INDEX_PATHS:
            with self.subTest(path=relative):
                result = __import__("subprocess").run(
                    ["git", "ls-files", "--stage", "--", relative], cwd=ROOT,
                    text=True, stdout=__import__("subprocess").PIPE,
                    stderr=__import__("subprocess").PIPE, check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertRegex(result.stdout, rf"^100644 [0-9a-f]{{40}} 0\t{relative}\n$")


if __name__ == "__main__":
    unittest.main()
