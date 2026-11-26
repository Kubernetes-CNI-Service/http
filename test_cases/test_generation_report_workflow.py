#!/usr/bin/env python3
"""REQ-16 R16-9 isolated multi-script setup/load/report workflow.

This invokes real setup publication and real load parent-release functions in
private fixtures.  It never runs host infrastructure, DHCP installation,
service switching, or production/AIR operations.
"""

from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import fcntl
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_generation_report_contract import (
    LAPTOP_FINGERPRINT, MANAGEMENT_FINGERPRINT, parent_release, report_helper,
)
from test_cases import test_load_collection_worker_contract as _systemd_main
from test_cases import test_load_release_transaction as _load_fixture
from test_cases.module_loader import load_script
from test_cases.test_ssh_key_preparation_contract import (
    NATIVE_NO_LAPTOP_LOAD_LINE, NATIVE_NO_LAPTOP_SETUP_WARNING, disposable_server_pair,
    fingerprint, native_project, public_line,
)


LOAD = _load_fixture.LOAD
SETUP = _load_fixture.SETUP
ROOT = Path(__file__).resolve().parents[1]
INITIAL = load_script(
    "ns2_report_workflow_initial_setup", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
)
HOST = load_script("ns2_report_workflow_ubuntu24_host", ROOT / "infra/ubuntu24_host.py")
PACKAGE = load_script("ns2_report_workflow_package_common", ROOT / "tools/_package_common.py")
PUBLICKEY_DIRECTORIES = (
    "ztp/config/publickey", "ethernet/publickey", "infiniband/publickey", "nvlink/publickey",
)


def _main_report_order_errors(source: str) -> list[str]:
    """Fail-closed AST check of the two-publication load-main boundary.

    This is intentionally narrower than execution: it proves the visible main
    branch and call order, not runtime fault behavior inside either helper.
    The isolated workflow tests below cover real setup/load/report functions;
    a later full-tree test must still run the complete entrypoint.
    """
    tree = ast.parse(textwrap.dedent(source))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if len(functions) != 1 or functions[0].name != "main":
        return ["expected exactly one main function"]
    main = functions[0]
    sites: dict[str, list[tuple[int, str]]] = {}
    none_inits: list[int] = []

    def visit(node: ast.AST, guards: tuple[str, ...] = ()) -> None:
        if isinstance(node, ast.If):
            visit(node.test, guards)
            predicate = ast.unparse(node.test)
            for child in node.body:
                visit(child, (*guards, predicate))
            for child in node.orelse:
                visit(child, (*guards, f"not ({predicate})"))
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "report_candidate" for target in targets):
                if isinstance(node.value, ast.Constant) and node.value.value is None:
                    none_inits.append(node.lineno)
        if isinstance(node, ast.Call):
            function = node.func
            name = (function.id if isinstance(function, ast.Name)
                    else function.attr if isinstance(function, ast.Attribute) else "")
            sites.setdefault(name, []).append((node.lineno, " and ".join(guards)))
            if name == "section" and len(node.args) == 1 and (
                isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "服务启动门禁"
            ):
                sites.setdefault("service_start_section", []).append(
                    (node.lineno, " and ".join(guards)),
                )
        for child in ast.iter_child_nodes(node):
            visit(child, guards)

    visit(main)
    names = (
        "validate_and_publish_release", "prepare_current_release",
        "prepare_generation_report", "mount_and_test_dhcp",
        "commit_prepared_release", "commit_prepared_generation_report",
        "service_start_section", "start_services",
    )
    errors = [f"{name}: expected exactly one call" for name in names
              if len(sites.get(name, ())) != 1]
    if errors:
        return errors
    positions = [sites[name][0][0] for name in names]
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        errors.append("parent/report staging, both parent commit paths, report commit, service start must remain ordered")

    stage_line, stage_guard = sites["prepare_generation_report"][0]
    if not all(token in stage_guard for token in (
        "local_services_supported", "not args.dry_run", "parent_release is not None",
    )):
        errors.append("report staging must be guarded by real server, non-dry run and validated parent")
    if not any(line < stage_line for line in none_inits):
        errors.append("report_candidate must initialize to None before guarded staging")
    _commit_line, commit_guard = sites["commit_prepared_generation_report"][0]
    if "report_candidate is not None" not in commit_guard:
        errors.append("report commit must require a prepared candidate")
    return errors


class GenerationReportWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        # Reuse the independent real child-release fixture, not an expected
        # report copied from the new producer under test.
        self.fixture = _load_fixture.ReleaseTransactionTests(
            methodName="test_writes_parent_release_after_all_components_match",
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.project = self.fixture.project
        self.ztp = self.fixture.ztp
        self.published = self.ztp / "config/publickey"
        # R-016 §2, §3.2: setup's per-key links name DAY0-Prepare/activate-project, selecting this project.
        self.fixture._activate_pointer()
        for name, content in (
            ("laptop.pub", public_line("ssh-ed25519", 31, "laptop")),
            ("mgmt-server.pub", public_line("ssh-ed25519", 47, "management")),
        ):
            path = self.project / name
            path.write_bytes(content)
            path.chmod(0o644)
        (self.project / ".management-pubkeys").write_text(
            "mgmt-server.pub\n", encoding="utf-8",
        )

    def real_setup_publish(self) -> None:
        with mock.patch.object(SETUP, "ZTP", str(self.ztp)), \
             mock.patch.object(SETUP, "HTTP_BASE", str(self.fixture.root)), \
             mock.patch.object(SETUP, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            SETUP._require_delegated_laptop_public_key(str(self.project))
            SETUP._process_pubkeys(str(self.project))
        for name in ("laptop.pub", "mgmt-server.pub"):
            published = self.published / name
            self.assertTrue(published.is_symlink())
            self.assertEqual((self.project / name).resolve(), published.resolve(strict=True))

    def populate_private_dhcp_candidate(self, *_args, **kwargs) -> None:
        """Model c1's private five-file output without publishing over old flat files."""
        candidate = kwargs.get("dhcp_candidate_dir")
        self.assertIsNotNone(candidate)
        source = self.ztp / "config/isc-dhcp-server"
        for name in (
            "dhcp-release-manifest.json", "dhcpd.conf", "dhcpd_eth.hosts",
            "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            shutil.copy2(source / name, candidate / name)

    def real_load_prepare(self):
        parent = LOAD.validate_and_publish_release(
            self.project, self.fixture.inputs, publish=False,
        )
        self.assertEqual("passed", parent["validation"])
        candidate = LOAD.prepare_current_release(self.project, parent)
        self.assertFalse(candidate.committed)
        return parent, candidate

    def test_real_load_main_stages_and_commits_report_in_safe_order(self):
        # The earlier workflow methods compose real functions, but this guard
        # separately rejects a main entrypoint that forgets to call the helper.
        self.assertEqual([], _main_report_order_errors(inspect.getsource(LOAD.main)))

    def test_main_order_guard_reddens_deleted_reordered_and_unguarded_hooks(self):
        good = textwrap.dedent('''
            def main():
                report_candidate = None
                parent_release = validate_and_publish_release()
                parent_candidate = prepare_current_release(parent_release)
                if local_services_supported and not args.dry_run and parent_release is not None:
                    report_candidate = generation_report.prepare_generation_report(project, report)
                if local_services_supported:
                    mount_and_test_dhcp(parent_candidate)
                commit_prepared_release(parent_candidate)
                if report_candidate is not None:
                    generation_report.commit_prepared_generation_report(report_candidate)
                section("服务启动门禁")
                start_services()
        ''')
        self.assertEqual([], _main_report_order_errors(good))
        deletion = good.replace(
            "generation_report.prepare_generation_report", "generation_report.noop", 1,
        )
        reorder = good.replace(
            "    commit_prepared_release(parent_candidate)\n"
            "    if report_candidate is not None:\n"
            "        generation_report.commit_prepared_generation_report(report_candidate)",
            "    if report_candidate is not None:\n"
            "        generation_report.commit_prepared_generation_report(report_candidate)\n"
            "    commit_prepared_release(parent_candidate)", 1,
        )
        unguarded = good.replace(
            "local_services_supported and not args.dry_run and parent_release is not None",
            "parent_release is not None", 1,
        )
        for label, mutant in (
            ("deleted", deletion), ("reordered", reorder), ("unguarded", unguarded),
        ):
            with self.subTest(mutant=label):
                self.assertNotEqual(good, mutant)
                self.assertTrue(_main_report_order_errors(mutant))

    def test_real_setup_and_load_parent_bind_report_to_published_public_keys(self):
        self.real_setup_publish()
        parent, parent_candidate = self.real_load_prepare()
        helper = report_helper()
        report = helper.build_report(
            self.project, parent, published_dir=self.published,
        )
        report_candidate = helper.prepare_generation_report(self.project, report)
        self.assertFalse((self.project / "99-output-ztp/generation-report.json").exists())
        LOAD.commit_prepared_release(parent_candidate)
        helper.commit_prepared_generation_report(report_candidate)

        observed = helper.inspect_generation_report(
            self.project, published_dir=self.published,
        )
        self.assertEqual(parent["release_id"], observed["release_id"])
        self.assertEqual(parent["generated_at"], observed["generated_at"])
        self.assertEqual(
            [LAPTOP_FINGERPRINT, MANAGEMENT_FINGERPRINT],
            [entry["fingerprint"] for entry in observed["public_keys"]],
        )
        self.assertEqual(
            ["laptop", "management"],
            [entry["role"] for entry in observed["public_keys"]],
        )

        # The two-file publication is deliberately non-atomic.  A later
        # published key replacement must not leave a plausible old report.
        (self.project / "mgmt-server.pub").write_bytes(
            public_line("ssh-ed25519", 48, "different-server"),
        )
        with self.assertRaises(Exception):
            helper.inspect_generation_report(
                self.project, published_dir=self.published,
            )

    def test_parent_commit_before_report_commit_has_no_valid_inspection(self):
        self.real_setup_publish()
        parent, parent_candidate = self.real_load_prepare()
        helper = report_helper()
        report = helper.build_report(
            self.project, parent, published_dir=self.published,
        )
        report_candidate = helper.prepare_generation_report(self.project, report)
        LOAD.commit_prepared_release(parent_candidate)
        self.assertEqual(
            parent["release_id"],
            json.loads((self.project / "99-output-ztp/current-release.json").read_text())[
                "release_id"
            ],
        )
        self.assertFalse((self.project / "99-output-ztp/generation-report.json").exists())
        with self.assertRaises(Exception):
            helper.inspect_generation_report(
                self.project, published_dir=self.published,
            )
        helper.commit_prepared_generation_report(report_candidate)
        self.assertEqual(
            report,
            helper.inspect_generation_report(
                self.project, published_dir=self.published,
            ),
        )

    def test_main_report_directory_fsync_failure_preserves_primary_and_stops_services(self):
        """Run real parent/report commits in a private project, never host services."""
        self.fixture._http_main_public_source_fixture()
        self.real_setup_publish()
        with redirect_stdout(io.StringIO()):
            parent = LOAD.validate_and_publish_release(
                self.project, self.fixture.inputs, publish=False,
            )
        expected_report = LOAD.generation_report.build_report(
            self.project, parent, published_dir=self.published,
        )
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=True,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
            host_role="management-server",
        )
        backend = SimpleNamespace(name="supervisor")
        plan = SimpleNamespace(
            listener_names=("eno2",), endpoint_ips=("192.0.2.10",),
        )
        events: list[str] = []
        quiesce = mock.Mock(side_effect=lambda *_args, **_kwargs: events.append("stop"))
        unlock = mock.Mock(side_effect=lambda *_args: events.append("unlock"))
        preflight = mock.Mock()
        start = mock.Mock()
        restore_links = mock.Mock()
        restore_prefix = mock.Mock()
        real_report_commit = LOAD.generation_report.commit_prepared_generation_report
        real_report_discard = LOAD.generation_report.discard_prepared_generation_report
        report_path = self.project / "99-output-ztp/generation-report.json"
        fsync_calls: list[int] = []

        def commit_parent_in_private_dhcp(_dry_run, *, parent_candidate):
            self.assertFalse(parent_candidate.committed)
            LOAD.commit_prepared_release(parent_candidate)
            events.append("parent-commit")

        def fail_report_directory_fsync(candidate):
            self.assertEqual("parent-commit", events[-1])
            with mock.patch.object(
                LOAD.generation_report.os, "fsync",
                side_effect=OSError("injected report directory fsync failure"),
            ) as fsync:
                try:
                    return real_report_commit(candidate)
                finally:
                    fsync_calls.append(fsync.call_count)
                    events.append("report-fsync-failed")

        def fail_report_discard(candidate):
            self.assertFalse(real_report_discard(candidate))
            events.append("report-discard-failed")
            raise LOAD.generation_report.GenerationReportError(
                "injected report cleanup failure"
            )

        stderr = io.StringIO()
        result = None
        caught = None
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", self.fixture.root))
            stack.enter_context(self.fixture._http_linux_public_ancestor_model())
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            # v3.1.2 WP-5: plays root by replacing the check, never os.geteuid (guide 2.2 #6).
            stack.enter_context(mock.patch.object(LOAD, "_require_root_for_load"))
            stack.enter_context(mock.patch.object(LOAD, "acquire_deployment_lock", return_value=97))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock", unlock))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "supports_local_ztp_services", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "service_runtime_backend", return_value=backend))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(self.fixture.inputs, {}),
            ))
            stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "plan_local_dhcp_runtime", return_value=plan))
            stack.enter_context(mock.patch.object(LOAD, "confirm_ztp_monitor_start", return_value=False))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", return_value=mock.sentinel.prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(LOAD, "configure_ztp_prefix_publication"))
            stack.enter_context(mock.patch.object(LOAD, "verify_monitor_authority"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links",
                return_value={self.project / "99-output-eth/latest": "old-release"},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", side_effect=self.populate_private_dhcp_candidate,
            ))
            stack.enter_context(mock.patch.object(LOAD, "retire_unselected_release_links"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=parent,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", side_effect=commit_parent_in_private_dhcp,
            ))
            stack.enter_context(mock.patch.object(
                LOAD.generation_report, "commit_prepared_generation_report",
                side_effect=fail_report_directory_fsync,
            ))
            stack.enter_context(mock.patch.object(
                LOAD.generation_report, "discard_prepared_generation_report",
                side_effect=fail_report_discard,
            ))
            stack.enter_context(mock.patch.object(LOAD, "preflight_services", preflight))
            stack.enter_context(mock.patch.object(LOAD, "start_services", start))
            stack.enter_context(mock.patch.object(LOAD, "restore_release_links", restore_links))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_ztp_prefix_publication", restore_prefix,
            ))
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                try:
                    result = LOAD.main([])
                except BaseException as exc:
                    caught = exc

        self.assertEqual([1], fsync_calls)  # The failure is after the real replace.
        self.assertEqual(
            ["stop", "parent-commit", "report-fsync-failed", "stop", "report-discard-failed", "unlock"],
            events,
        )
        self.assertEqual(parent["release_id"], json.loads(
            (self.project / "99-output-ztp/current-release.json").read_text(encoding="utf-8"),
        )["release_id"])
        self.assertEqual(expected_report, json.loads(report_path.read_text(encoding="utf-8")))
        preflight.assert_not_called()
        start.assert_not_called()
        self.assertEqual(2, quiesce.call_count)
        restore_links.assert_not_called()
        restore_prefix.assert_not_called()
        output = stderr.getvalue()
        self.assertIn("[FAILED] load 阶段失败：提交本次实际使用公钥报告", output)
        self.assertIn("[ERROR] injected report directory fsync failure", output)
        self.assertIn("[STATE] release 已提交，但受管服务因后续失败保持停止", output)
        self.assertNotIn("未提交 release 的发布状态已回滚", output)
        self.assertIsNone(caught, "cleanup must not mask the primary report-commit failure")
        self.assertEqual(1, result)

    def test_main_success_path_report_cleanup_failure_cannot_claim_success(self):
        """A final cleanup fault is not a completed load or a parent rollback."""
        self.fixture._http_main_public_source_fixture()
        self.real_setup_publish()
        with redirect_stdout(io.StringIO()):
            parent = LOAD.validate_and_publish_release(
                self.project, self.fixture.inputs, publish=False,
            )
        expected_report = LOAD.generation_report.build_report(
            self.project, parent, published_dir=self.published,
        )
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
            host_role="management-server",
        )
        backend = SimpleNamespace(name="supervisor")
        plan = SimpleNamespace(
            listener_names=("eno2",), endpoint_ips=("192.0.2.10",),
        )
        events: list[str] = []
        quiesce = mock.Mock(side_effect=lambda *_args, **_kwargs: events.append("stop"))
        unlock = mock.Mock(side_effect=lambda *_args: events.append("unlock"))
        preflight = mock.Mock()
        start = mock.Mock()
        restore_links = mock.Mock()
        restore_prefix = mock.Mock()
        real_report_discard = LOAD.generation_report.discard_prepared_generation_report
        real_parent_discard = LOAD.discard_prepared_release
        report_path = self.project / "99-output-ztp/generation-report.json"

        def commit_parent_in_private_dhcp(_dry_run, *, parent_candidate):
            self.assertFalse(parent_candidate.committed)
            LOAD.commit_prepared_release(parent_candidate)
            events.append("parent-commit")

        def fail_report_discard(candidate):
            self.assertEqual(report_path, candidate.destination)
            self.assertFalse(real_report_discard(candidate))
            events.append("report-discard-failed")
            raise LOAD.generation_report.GenerationReportError(
                "injected report cleanup failure"
            )

        def discard_parent(candidate):
            self.assertTrue(candidate.committed)
            real_parent_discard(candidate)
            events.append("parent-discard")

        stdout = io.StringIO()
        stderr = io.StringIO()
        result = None
        caught = None
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "HTTP_ROOT", self.fixture.root))
            stack.enter_context(self.fixture._http_linux_public_ancestor_model())
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            # v3.1.2 WP-5: plays root by replacing the check, never os.geteuid (guide 2.2 #6).
            stack.enter_context(mock.patch.object(LOAD, "_require_root_for_load"))
            stack.enter_context(mock.patch.object(LOAD, "acquire_deployment_lock", return_value=98))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock", unlock))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "supports_local_ztp_services", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "service_runtime_backend", return_value=backend))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(self.fixture.inputs, {}),
            ))
            stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "plan_local_dhcp_runtime", return_value=plan))
            stack.enter_context(mock.patch.object(LOAD, "confirm_ztp_monitor_start", return_value=False))
            stack.enter_context(mock.patch.object(LOAD, "confirm_service_start", return_value=False))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", return_value=mock.sentinel.prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(LOAD, "configure_ztp_prefix_publication"))
            stack.enter_context(mock.patch.object(LOAD, "verify_monitor_authority"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links",
                return_value={self.project / "99-output-eth/latest": "old-release"},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", side_effect=self.populate_private_dhcp_candidate,
            ))
            stack.enter_context(mock.patch.object(LOAD, "retire_unselected_release_links"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=parent,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", side_effect=commit_parent_in_private_dhcp,
            ))
            stack.enter_context(mock.patch.object(
                LOAD.generation_report, "discard_prepared_generation_report",
                side_effect=fail_report_discard,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "discard_prepared_release", side_effect=discard_parent,
            ))
            # T+ (11-load batch L7): the post-commit flat DHCP publish is isolated here, as in
            # tlrt's _exercise_main_transaction_failure (P7); test_committed_dhcp_* run it for real.
            dhcp_publish = stack.enter_context(mock.patch.object(
                LOAD, "publish_committed_dhcp_candidate",
            ))
            stack.enter_context(mock.patch.object(LOAD, "preflight_services", preflight))
            stack.enter_context(mock.patch.object(LOAD, "start_services", start))
            stack.enter_context(mock.patch.object(LOAD, "restore_release_links", restore_links))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_ztp_prefix_publication", restore_prefix,
            ))
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    result = LOAD.main([])
                except BaseException as exc:
                    caught = exc

        self.assertEqual(
            ["stop", "parent-commit", "report-discard-failed", "parent-discard", "unlock"],
            events,
        )
        unlock.assert_called_once_with(98)
        dhcp_publish.assert_called_once()
        preflight.assert_called_once()
        start.assert_not_called()
        self.assertEqual(1, quiesce.call_count)
        restore_links.assert_not_called()
        restore_prefix.assert_not_called()
        self.assertEqual(parent["release_id"], json.loads(
            (self.project / "99-output-ztp/current-release.json").read_text(encoding="utf-8"),
        )["release_id"])
        self.assertEqual(expected_report, json.loads(report_path.read_text(encoding="utf-8")))
        self.assertIsInstance(caught, LOAD.generation_report.GenerationReportError)
        self.assertIn("injected report cleanup failure", str(caught))
        self.assertIsNone(result)
        self.assertIn("injected report cleanup failure", stderr.getvalue())
        self.assertNotIn("未提交 release 的发布状态已回滚", stderr.getvalue())
        self.assertNotIn("load 流程完成", stdout.getvalue())

    def test_config_only_setup_does_not_claim_an_empty_management_key(self):
        (self.project / "mgmt-server.pub").write_bytes(b"")
        with mock.patch.object(SETUP, "ZTP", str(self.ztp)), \
             mock.patch.object(SETUP, "HTTP_BASE", str(self.fixture.root)), \
             mock.patch.object(SETUP, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            SETUP._process_pubkeys(str(self.project))
        self.assertTrue((self.published / "laptop.pub").is_symlink())
        self.assertFalse((self.published / "mgmt-server.pub").exists())
        parent, parent_candidate = self.real_load_prepare()
        LOAD.commit_prepared_release(parent_candidate)
        helper = report_helper()
        with self.assertRaises(Exception):
            helper.build_report(
                self.project, parent, published_dir=self.published,
            )
        self.assertFalse((self.project / "99-output-ztp/generation-report.json").exists())

    def test_ad_hoc_project_root_schema2_is_untouched_by_governed_report(self):
        self.real_setup_publish()
        ad_hoc = self.project / "generation-report.json"
        original = b'{"schema_version":2,"report_format_version":1,"ad_hoc":true}\n'
        ad_hoc.write_bytes(original)
        parent, parent_candidate = self.real_load_prepare()
        helper = report_helper()
        candidate = helper.prepare_generation_report(
            self.project,
            helper.build_report(self.project, parent, published_dir=self.published),
        )
        LOAD.commit_prepared_release(parent_candidate)
        helper.commit_prepared_generation_report(candidate)
        self.assertEqual(original, ad_hoc.read_bytes())
        self.assertEqual(
            3,
            helper.inspect_generation_report(
                self.project, published_dir=self.published,
            )["schema_version"],
        )

    def test_real_load_derived_parent_and_setup_keys_commit_inspectable_report(self):
        self.real_setup_publish()
        private = Path(tempfile.mkdtemp(prefix=".load-inventory-report-", dir=self.project))
        private.chmod(0o700)
        derived = private / "02-devices_config.csv"
        derived.write_bytes(self.fixture.devices_file.read_bytes() + b"\n")
        derived.chmod(0o600)
        derived_sha = hashlib.sha256(derived.read_bytes()).hexdigest()
        inputs = LOAD.replace(
            self.fixture.inputs, effective_devices_file=derived,
            effective_devices_sha256=derived_sha,
        )
        parent = LOAD.validate_and_publish_release(self.project, inputs, publish=False)
        self.assertEqual({"path": derived.relative_to(self.project).as_posix(),
                          "sha256": derived_sha},
                         parent["generated_inputs"]["effective_devices"])
        # This is the real load producer, not a parent fixture synthesized by
        # the report consumer.  The report must accept precisely its release ID.
        helper = report_helper()
        report = helper.build_report(self.project, parent, published_dir=self.published)
        self.assertEqual(parent["release_id"], report["release_id"])
        parent_candidate = LOAD.prepare_current_release(self.project, parent)
        report_candidate = helper.prepare_generation_report(self.project, report)
        LOAD.commit_prepared_release(parent_candidate)
        helper.commit_prepared_generation_report(report_candidate)
        self.assertEqual(report, helper.inspect_generation_report(
            self.project, published_dir=self.published,
        ))

    # ---- R-035/P053 (v3.1.6 guide WP-NS2 workflow 3-4 :794-795) ----

    def test_native_no_laptop_http_source_gate_and_probes_name_only_management(self):
        """guide :795: the source gate checks only existing leaves; the probe never names laptop.pub."""
        self.fixture._http_main_public_source_fixture()
        laptop = self.project / "laptop.pub"
        laptop.write_bytes(b"")
        with self.fixture._http_linux_public_ancestor_model():
            LOAD.require_http_project_source_access(self.project, http_root=self.fixture.root, ztp_dir=self.ztp)
            laptop.unlink()
            LOAD.require_http_project_source_access(self.project, http_root=self.fixture.root, ztp_dir=self.ztp)
        commands: list[list[str]] = []
        inputs = LOAD.replace(self.fixture.inputs, pubkeys=(self.project / "mgmt-server.pub",))
        with mock.patch.object(LOAD, "run", side_effect=lambda command, **_kw: commands.append(list(command))):
            LOAD.verify_http_publication(inputs, {}, False)
        probed = [command[-1] for command in commands]
        self.assertTrue(any(url.endswith("/config/publickey/mgmt-server.pub") for url in probed), probed)
        self.assertFalse(any("laptop.pub" in url for url in probed), probed)
        for command in commands:
            self.assertEqual(["curl", "-fsSI"], command[:2])  # HEAD reachability only, never the bytes

    # ---- Q-106 (owner default (a), relayed by http dev 2026-11-26 03:4x) ----
    # At load's 「冻结旧版 release 以供显式回退」 step the A capture checks only A's report against A's
    # published link set, never the current project key bytes: a laptop key that returns, is emptied or
    # is rotated before the rerun must not block the load.  Every original refusal stays.

    def publish_project_keys(self) -> None:
        """setup's real four-directory publication of the project's non-empty keys."""
        with mock.patch.object(SETUP, "ZTP", str(self.ztp)), \
             mock.patch.object(SETUP, "HTTP_BASE", str(self.fixture.root)), \
             mock.patch.object(SETUP, "_DRY_RUN", False), \
             redirect_stdout(io.StringIO()):
            SETUP._process_pubkeys(str(self.project))

    def freeze_a(self, *, laptop: bytes, policy: bool):
        """A committed, pinned and selected A with its governed report (load's real producers)."""
        leaf = self.project / "laptop.pub"
        leaf.write_bytes(laptop)
        leaf.chmod(0o644)
        self.publish_project_keys()
        with redirect_stdout(io.StringIO()):
            parent = LOAD.validate_and_publish_release(self.project, self.fixture.inputs)
        helper = LOAD.generation_report
        record = helper.build_report(
            self.project, parent, published_dir=self.published, laptop_key_optional=policy,
        )
        helper.commit_prepared_generation_report(
            helper.prepare_generation_report(self.project, record, laptop_key_optional=policy),
        )
        generation = LOAD.stage_pinned_generation(
            self.project, self.project / "99-output-ztp/current-release.json",
            self.ztp / "config/isc-dhcp-server" if parent["dhcp_status"] == "enabled" else None,
        )
        LOAD.commit_pinned_generation(self.project, generation, expected_current=None)
        for name, content in (
            ("ztp-bootstrap_oob.sh", b"A oob bootstrap\n"),
            ("ztp-bootstrap_oobofoob.sh", b"A oobofoob bootstrap\n"),
            ("ztp.json", b'{"release":"A"}\n'),
        ):
            (self.ztp / name).write_bytes(content)
        return parent, generation, record

    def capture_a(self, generation, policy: bool):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return LOAD.prepare_runtime_rollback_receipt(
                self.project, generation, laptop_key_optional=policy,
            )

    def assert_capture_accepted(self, generation, policy: bool, parent) -> None:
        try:
            receipt = self.capture_a(generation, policy)
        except LOAD.LoadError as exc:
            self.fail(f"Q-106 (a): A capture must not read the current project key bytes: {exc}")
        self.assertEqual(parent["release_id"], receipt.name)
        self.assertTrue(receipt.is_dir())

    def test_q106_a_capture_after_the_laptop_key_returns(self):
        parent, generation, record = self.freeze_a(laptop=b"", policy=True)
        self.assertEqual(["management"], [entry["role"] for entry in record["public_keys"]])
        self.assertFalse(os.path.lexists(self.published / "laptop.pub"))
        (self.project / "laptop.pub").write_bytes(public_line("ssh-ed25519", 31, "laptop"))
        self.assert_capture_accepted(generation, True, parent)

    def test_q106_a_capture_after_the_laptop_key_is_emptied(self):
        parent, generation, record = self.freeze_a(
            laptop=public_line("ssh-ed25519", 31, "laptop"), policy=True,
        )
        self.assertEqual(["laptop", "management"], [entry["role"] for entry in record["public_keys"]])
        (self.project / "laptop.pub").write_bytes(b"")
        self.assert_capture_accepted(generation, True, parent)

    def test_q106_a_capture_after_a_two_key_rotation(self):
        parent, generation, _record = self.freeze_a(
            laptop=public_line("ssh-ed25519", 31, "laptop"), policy=False,
        )
        (self.project / "laptop.pub").write_bytes(public_line("ssh-ed25519", 32, "rotated-laptop"))
        self.assert_capture_accepted(generation, False, parent)

    def test_q106_a_capture_keeps_the_original_refusals(self):
        """A's report must still match A's published link set, parent and shape."""
        _parent, generation, _record = self.freeze_a(
            laptop=public_line("ssh-ed25519", 31, "laptop"), policy=False,
        )
        link = self.published / "laptop.pub"
        text = os.readlink(link)
        report_path = self.project / "99-output-ztp/generation-report.json"
        report_bytes = report_path.read_bytes()

        def refused(label):
            with self.subTest(case=label), self.assertRaises(LOAD.LoadError):
                self.capture_a(generation, False)

        link.unlink()
        refused("published laptop link missing")
        link.symlink_to(text.replace("laptop.pub", "mgmt-server.pub"))
        refused("published laptop link targets another role")
        link.unlink()
        link.symlink_to(text)
        record = json.loads(report_bytes)
        record["generated_at"] = "2026-09-24T13:00:00+08:00"
        report_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        refused("report no longer bound to A's parent")
        record = json.loads(report_bytes)
        record["public_keys"][0]["fingerprint"] = "SHA256:not-a-fingerprint"
        report_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        refused("malformed report record")
        record = json.loads(report_bytes)
        record["public_keys"] = record["public_keys"][1:]
        report_path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        refused("single record without the Native policy")
        with self.subTest(case="single record while a laptop link is published"), \
                self.assertRaises(LOAD.LoadError):
            self.capture_a(generation, True)
        report_path.write_bytes(report_bytes)
        self.assertFalse((self.project / "99-output-ztp/rollback-receipts" / _parent["release_id"]).exists())


class NativeNoLaptopLoadMainWorkflow(_systemd_main.SystemdLoadMainFixture, unittest.TestCase):
    """R-035/P053 workflow (v3.1.6 guide WP-NS2 :786-797): the real load main as a Native management server.

    Real: load main's role decision, validate_inputs -> prepare_pubkeys with a disposable management pair,
    activate_project -> run (environment and lock FD) -> the delegated setup entry, its key gate, strict
    step 1, the pointer switch and the four public-key directories, and the governed report build,
    prepare, commit and inspection.  Only host services, generators and unrelated setup stages are inert.
    """

    UNRELATED_SETUP_STAGES = (
        "_initialize_project_from_template", "_remove_legacy_links", "_process_bin_files",
        "_process_bringup_image_links", "_process_xlsx_files", "_process_latest_yaml",
        "_process_optimize_sample", "_restore_pending_infra_log_backup", "_bind_infra_logs",
        "_write_manifest", "_finalize_infra_log_migration",
    )

    def native_tree(self, *, laptop: bytes | None) -> SimpleNamespace:
        directory = tempfile.TemporaryDirectory(prefix="ns2-native-main-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        for area in ("ethernet", "infiniband", "nvlink"):
            (root / area / "monitor").mkdir(parents=True)
        (root / "infra").mkdir()
        (root / "ztp").mkdir()
        (root / "DAY0-Prepare").mkdir()
        project = native_project(root / "DAY0-Prepare/demo", laptop=laptop)
        (project / "01-global.yaml").write_text(
            "common:\n  mgmt:\n    dhcp-server:\n      status: disabled\n"
            "    ztp:\n      status: disabled\n      ztp_url_prefix: /ztp\n", encoding="utf-8",
        )
        (project / "02-dhcp-subnet_config.csv").write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n", encoding="utf-8",
        )
        # A schema-1 header only (the global above has no schema_version): load's parser is inert here
        # (load_device_types); setup's strict step 1 reads it.
        (project / "02-devices_config.csv").write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,"
            "vrf_default,vlan_id,svi_ip,netmask,vrr_ip,vrr_mac,vlan_ports,"
            "bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,"
            "evpn_vrf,evpn_l3vni,evpn_l3vlan,dhcp_relay,evpn_l2vni,evpn_l2vlan,svi_ip,netmask,vrr_ip,vrr_mac,"
            "vlan_ports\n", encoding="utf-8",
        )
        (project / "p2p").mkdir()
        p2p = project / "p2p/demo.xlsx"
        p2p.write_bytes(b"synthetic workbook placeholder\n")
        (project / "p2p.xlsx").symlink_to("p2p/demo.xlsx")
        ssh = root / "server-home/.ssh"
        server = disposable_server_pair(ssh)
        lock_path = root / ".deployment.lock"
        lock_path.touch(mode=0o600)
        parent_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(parent_fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, parent_fd)
        return SimpleNamespace(root=root, project=project, p2p=p2p, ssh=ssh, server=server,
                               parent_fd=parent_fd)

    def run_native_main(self, tree: SimpleNamespace, *, patches: dict | None = None) -> SimpleNamespace:
        load = self.load_module
        real = {name: getattr(load, name) for name in (
            "validate_inputs", "prepare_pubkeys", "ensure_management_key", "activate_project", "run",
        )}
        inputs = self.main_inputs(http=False, dhcp=False)
        inputs.p2p_file = tree.p2p
        produced: dict = {}
        validate_calls: list[dict] = []
        setup_modes: list[str | None] = []
        setup_output = io.StringIO()
        child_fd = os.dup(tree.parent_fd)

        def validate_inputs(project, args, **kwargs):
            """The real input gate; only unrelated customer-input parsers are inert (fixture shape of
            test_ssh_key_preparation_contract.test_macos_input_prevalidation_preserves_two_empty_template_keys_for_setup)."""
            validate_calls.append(dict(kwargs))
            settings = SimpleNamespace(schema_version=1, http_enabled=False)
            with ExitStack() as stack:
                for name, value in (
                    ("_load_global_document", {}), ("load_global", settings),
                    ("find_placeholder_password_sections", ()), ("apply_subnet_service_ips", settings),
                    ("load_device_types", frozenset()), ("select_p2p", tree.p2p),
                    ("validate_subnet_file", None), ("project_air_topology_policy", None),
                    ("project_mini_air_devices", (None, None)), ("validate_shared_artifact_receipts", None),
                    ("prepare_images", {}),
                ):
                    stack.enter_context(mock.patch.object(load, name, return_value=value))
                checked, _images = real["validate_inputs"](project, args, **kwargs)
            # main continues with the real result; only the inert parsers' settings/types are the fixture's
            produced["inputs"] = load.replace(
                checked, settings=inputs.settings, device_types=inputs.device_types, p2p_file=tree.p2p,
            )
            return produced["inputs"], {}

        def child(command, **kwargs):
            if Path(command[1]).name != "01-a-setup.py":
                return SimpleNamespace(returncode=0)
            environment = dict(kwargs.get("env") or {})
            setup_modes.append(environment.get("HTTP_SETUP_KEY_MODE"))
            self.assertEqual((child_fd,), kwargs.get("pass_fds"))
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
                stack.enter_context(mock.patch("platform.system", return_value="Linux"))
                stack.enter_context(mock.patch.multiple(
                    SETUP, HTTP_BASE=str(tree.root), HERE=str(tree.root / "DAY0-Prepare"),
                    ZTP=str(tree.root / "ztp"), MANIFEST_FILE=str(tree.root / "ztp/.setup_manifest"),
                    IMAGE_DIR=str(tree.root / "image"), _P2P_SOURCE=None,
                ))
                stack.enter_context(mock.patch.dict(
                    SETUP.deployment_lock.__globals__, {"assert_writer_allowed": lambda **_kw: None},
                ))
                stack.enter_context(mock.patch.object(SETUP, "stop_native_ztp_monitors"))
                for name in self.UNRELATED_SETUP_STAGES:
                    stack.enter_context(mock.patch.object(SETUP, name))
                for name, result in (
                    ("_reconcile_table_links", []), ("_select_p2p_source", str(tree.p2p)),
                    ("_ensure_project_p2p_link", str(tree.p2p)), ("_validate_xlsx", ([], [])),
                ):
                    stack.enter_context(mock.patch.object(SETUP, name, return_value=result))
                stack.enter_context(redirect_stdout(setup_output))
                try:
                    code = SETUP.main(command[2:])
                except SystemExit as exc:
                    code = exc.code
            return SimpleNamespace(returncode=code or 0)

        real_popen = load._popen_subprocess

        def popen(command, **kwargs):
            # The management pair's real ssh-keygen validation runs; every service/worker launch stays inert.
            if Path(str(command[0])).name == "ssh-keygen":
                return real_popen(command, **kwargs)
            return _systemd_main._FakeProcess()

        parent = parent_release(tree.project)
        parent_candidate = SimpleNamespace(
            committed=False, precommit_check=None, temporary=tree.project / ".parent-candidate",
        )

        def commit_parent(candidate):
            # The parent record is the independent schema-2 fixture; its real two-file transaction has its own
            # tests (test_load_release_transaction).  The report inspector reads exactly this record.
            output = tree.project / "99-output-ztp"
            output.mkdir(exist_ok=True)
            (output / "current-release.json").write_text(json.dumps(parent, sort_keys=True) + "\n",
                                                         encoding="utf-8")
            candidate.committed = True

        overrides = {
            "prepare_current_release": mock.Mock(return_value=parent_candidate),
            "commit_prepared_release": mock.Mock(side_effect=commit_parent),
            "discard_prepared_release": mock.Mock(),
            "_popen_subprocess": popen,
            "HTTP_ROOT": tree.root, "ZTP_DIR": tree.root / "ztp",
            "resolve_project": mock.Mock(return_value=tree.project),
            "acquire_deployment_lock": mock.Mock(return_value=child_fd),
            "validate_inputs": validate_inputs,
            "prepare_pubkeys": real["prepare_pubkeys"],
            "ensure_management_key": real["ensure_management_key"],
            "activate_project": real["activate_project"], "run": real["run"],
            "_run_subprocess": mock.Mock(side_effect=child),
            "validate_and_publish_release": mock.Mock(return_value=parent),
            "stage_pinned_generation": mock.Mock(return_value=None),
            # the workbook is a placeholder; P2P parsing is outside this key workflow
            "select_upload_p2p": mock.Mock(return_value=tree.p2p),
        }
        overrides.update(patches or {})
        result = self.run_load_main(
            self.main_args(ssh_dir=tree.ssh, no_upgrade=False), inputs, patches=overrides,
        )
        result.validate_calls = validate_calls
        result.setup_modes = setup_modes
        result.setup_output = setup_output.getvalue()
        result.inputs = produced.get("inputs")
        return result

    def test_native_main_without_laptop_publishes_management_and_commits_one_record(self):
        for label, payload in (("0-byte", b""), ("missing", None)):
            with self.subTest(laptop=label):
                tree = self.native_tree(laptop=payload)
                result = self.run_native_main(tree)
                self.assertEqual(0, result.rc, result.stderr + result.setup_output)
                # load main decided the policy itself (guide :743-744, :758)
                self.assertEqual([True], [call.get("laptop_key_optional") for call in result.validate_calls])
                self.assertEqual(["server-delegated-native"], result.setup_modes)
                self.assertIn(NATIVE_NO_LAPTOP_LOAD_LINE, result.stdout)
                self.assertIn(NATIVE_NO_LAPTOP_SETUP_WARNING, result.setup_output)
                self.assertEqual(tree.server, (tree.project / "mgmt-server.pub").read_bytes())
                self.assertEqual((tree.project / "mgmt-server.pub",), tuple(result.inputs.pubkeys))
                # four directories: only the management link, through the pointer (guide :789)
                for directory in PUBLICKEY_DIRECTORIES:
                    published = tree.root / directory
                    self.assertEqual(["mgmt-server.pub"], sorted(item.name for item in published.iterdir()))
                    self.assertEqual(
                        (tree.project / "mgmt-server.pub").resolve(),
                        (published / "mgmt-server.pub").resolve(strict=True),
                    )
                # the governed report: exactly one management record, independently fingerprinted
                report_path = tree.project / "99-output-ztp/generation-report.json"
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    [{"role": "management", "name": "mgmt-server.pub", "algorithm": "ssh-ed25519",
                      "fingerprint": fingerprint(tree.server)}],
                    report["public_keys"],
                )
                self.assertEqual(report, report_helper().inspect_generation_report(
                    tree.project, published_dir=tree.root / "ztp/config/publickey", laptop_key_optional=True,
                ))
                # reached the start gate after the report commit (guide :789 正控必须走到报告提交之后)
                self.assertIn("服务启动门禁", result.stdout)
                # guide :794: the same tree's consumers see the management key alone, without errors
                profile = INITIAL._public_key_profile(
                    tree.root / "ib-tool", validate_with_ssh_keygen=False,
                    public_key_dir=tree.root / "infiniband/publickey",
                )
                self.assertEqual([tree.server.decode().strip()], [entry["line"] for entry in profile])
                names, lines, errors, _warnings = HOST.read_public_keys(tree.root / "infiniband/publickey")
                self.assertEqual((["mgmt-server.pub"], [tree.server.decode().strip()], []),
                                 (names, lines, errors))
                # guide :795 packaging: the runtime-injected management key stays out of every archive
                self.assertEqual({tree.project / "mgmt-server.pub"}, PACKAGE.managed_pubkey_paths([tree.project]))
                (tree.root / "ztp/templates").mkdir()
                shutil.copy2(ROOT / "ztp/templates/ztp-bootstrap.sh", tree.root / "ztp/templates/ztp-bootstrap.sh")
                settings = self.load_module.GlobalSettings(
                    dhcp_enabled=False, dhcp_package="isc-dhcp-server",
                    http_enabled=True, http_package="apache2", http_root=tree.root,
                    http_address="192.0.2.10", ztp_enabled=True, ztp_prefix="/ztp",
                    ztp_ips={"air_oob": ("192.0.2.20",)}, versions={},
                )
                with mock.patch.object(self.load_module, "ZTP_DIR", tree.root / "ztp"), \
                        mock.patch.object(self.load_module, "HTTP_ROOT", tree.root), \
                        redirect_stdout(io.StringIO()):
                    self.load_module.render_ztp_runtime(
                        settings, tuple(result.inputs.pubkeys), frozenset({"eth"}), upgrade_enabled=False,
                    )
                rendered = (tree.root / "ztp/ztp-bootstrap_oob.sh").read_text(encoding="utf-8")
                block = re.search(r"^PUBKEY_PATHS=\(\n(.*?)^\)$", rendered, flags=re.MULTILINE | re.DOTALL)
                self.assertIsNotNone(block)
                self.assertEqual(['"${ZTP_URL_PREFIX}/config/publickey/mgmt-server.pub"'],
                                 [line.strip() for line in block.group(1).splitlines() if line.strip()])

    def test_native_main_bad_management_key_fails_with_zero_publication(self):
        tree = self.native_tree(laptop=b"")
        (tree.project / ".management-pubkeys").write_bytes(b"other.pub\n")
        result = self.run_native_main(tree)
        self.assertEqual(1, result.rc)
        self.assertIn("项目输入合法性与制品检查", result.stderr)
        self.assertEqual([], result.setup_modes)
        self.assertEqual(b"", (tree.project / "mgmt-server.pub").read_bytes())
        for directory in PUBLICKEY_DIRECTORIES:
            self.assertFalse(os.path.lexists(tree.root / directory))
        self.assertFalse(os.path.lexists(tree.project / "99-output-ztp/generation-report.json"))
        self.assertNotIn("服务启动门禁", result.stdout)

    def test_native_main_report_commit_failure_keeps_primary_and_secondary_errors(self):
        tree = self.native_tree(laptop=b"")
        helper = self.load_module.generation_report
        real_discard = helper.discard_prepared_generation_report

        def commit_fails(_candidate, **_kwargs):
            raise helper.GenerationReportError("injected native report commit failure")

        def discard_then_fail(candidate):
            real_discard(candidate)
            raise helper.GenerationReportError("injected native report discard failure")

        with mock.patch.object(helper, "commit_prepared_generation_report", side_effect=commit_fails), \
                mock.patch.object(helper, "discard_prepared_generation_report", side_effect=discard_then_fail):
            result = self.run_native_main(tree)
        self.assertEqual(1, result.rc)
        self.assertIn("[FAILED] load 阶段失败：提交本次实际使用公钥报告", result.stderr)
        self.assertIn("injected native report commit failure", result.stderr)
        self.assertIn("[ERROR] 公钥报告暂存清理失败：injected native report discard failure", result.stderr)
        self.assertFalse(os.path.lexists(tree.project / "99-output-ztp/generation-report.json"))
        self.assertNotIn("服务启动门禁", result.stdout)


if __name__ == "__main__":
    unittest.main()
