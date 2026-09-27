#!/usr/bin/env python3
"""REQ-16 R16-9 isolated multi-script setup/load/report workflow.

This invokes real setup publication and real load parent-release functions in
private fixtures.  It never runs host infrastructure, DHCP installation,
service switching, or production/AIR operations.
"""

from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import inspect
import io
import json
from pathlib import Path
import textwrap
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_generation_report_contract import (
    LAPTOP_FINGERPRINT, MANAGEMENT_FINGERPRINT, report_helper,
)
from test_cases import test_load_release_transaction as _load_fixture
from test_cases.test_ssh_key_preparation_contract import public_line


LOAD = _load_fixture.LOAD
SETUP = _load_fixture.SETUP


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
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
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
            stack.enter_context(mock.patch.object(LOAD, "generate_configs"))
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
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
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
            stack.enter_context(mock.patch.object(LOAD, "generate_configs"))
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


if __name__ == "__main__":
    unittest.main()
