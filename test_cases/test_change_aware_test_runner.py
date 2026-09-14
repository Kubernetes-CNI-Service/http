#!/usr/bin/env python3
"""Contracts for complete script impact mapping and change-aware test runs."""

from __future__ import annotations

import importlib.util
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from jinja2 import Environment, FileSystemLoader, meta, nodes


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
RUNNER_PATH = ROOT / "test_cases/run_related_tests.py"
MANIFEST_PATH = ROOT / "test_cases/script_test_manifest.json"
CONTAINER_TOPLEVEL_LOCK = ROOT / "requirements-container-top-level.lock"
EXPECTED_CONTAINER_TOPLEVEL_VERSIONS = sorted(
    (
        "Jinja2==3.1.6",
        "PyYAML==6.0.3",
        "pandas==2.3.3",
        "openpyxl==3.1.5",
        "XlsxWriter==3.2.9",
    ),
    key=str.casefold,
)
CONTAINER_TOPLEVEL_LOCK_SUPPORT = {
    "requirements-container-top-level.lock": hashlib.sha256(
        CONTAINER_TOPLEVEL_LOCK.read_bytes()
    ).hexdigest(),
}
EXPECTED_TEST_SUITES = [
    "repository-governance",
    "packaging-sync",
    "deployment-runtime",
    "configuration-generation",
    "monitoring-collection",
    "ztp-runtime",
    "vm-validation",
]


def load_runner():
    spec = importlib.util.spec_from_file_location("change_aware_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = load_runner()


def load_repository_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SYNC = load_repository_module(
    "change_aware_sync_authority", ROOT / "tools/sync-code.py",
)
ACTIVATE = load_repository_module(
    "change_aware_image_authority", ROOT / "infra/docker/activate.py",
)
ARCHIVE = load_repository_module(
    "change_aware_archive_authority", ROOT / "tools/_package_common.py",
)
CUMULUS_GENERATOR = load_repository_module(
    "change_aware_cumulus_generator",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)


TEMPLATE_AUTHORITY_PATTERN = (
    "ztp/config/cumulus/template/03-templates-j2/*.yaml.j2"
)
DEFAULT_AUTHORITY_PATTERNS = (
    "ztp/config/cumulus/default*.yaml",
    "ztp/config/nvos/default*.yaml",
)
EXPECTED_TEMPLATE_AUTHORITY_NAMES = {
    "_bridge_l2vlans.yaml.j2",
    "_dhcp_relay.yaml.j2",
    "_direct_vlan_ports.yaml.j2",
    "_extra_aaa_users.yaml.j2",
    "_global_evpn.yaml.j2",
    "_l2_svis.yaml.j2",
    "border.yaml.j2",
    "oob-core.yaml.j2",
    "oob-leaf.yaml.j2",
    "oob-rack-tor.yaml.j2",
    "oob-su-leaf.yaml.j2",
    "oob-su-spine.yaml.j2",
    "oobofoob-leaf.yaml.j2",
    "oobofoob-spine.yaml.j2",
    "tan-cp-1gleaf.yaml.j2",
    "tan-cp-leaf.yaml.j2",
    "tan-hps-leaf.yaml.j2",
    "tan-leaf.yaml.j2",
    "tan-spine.yaml.j2",
    "tan-su-leaf.yaml.j2",
}


def assert_static_jinja_closure(template_root: Path, governed: set[str]) -> None:
    """Independent full-suite oracle for the governed Jinja reference graph."""
    environment = Environment(autoescape=False)
    visited: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in active:
            raise AssertionError(f"template reference cycle is not resolvable: {name}")
        if name not in governed or Path(name).name != name:
            raise AssertionError(f"template reference is outside governed set: {name}")
        path = template_root / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AssertionError(f"governed template is not one regular file: {name}")
        syntax = environment.parse(path.read_text(encoding="utf-8"))
        reference_nodes = tuple(syntax.find_all((
            nodes.Extends, nodes.Include, nodes.Import, nodes.FromImport,
        )))
        literal_references: list[str] = []
        for reference in reference_nodes:
            target = reference.template
            if not isinstance(target, nodes.Const) or not isinstance(
                target.value, str
            ):
                raise AssertionError(
                    f"template reference must be one static string: {name}"
                )
            literal_references.append(target.value)
        discovered = tuple(meta.find_referenced_templates(syntax))
        if any(not isinstance(item, str) for item in discovered):
            raise AssertionError(
                f"template reference has an unsupported dynamic shape: {name}"
            )
        if sorted(discovered) != sorted(literal_references):
            raise AssertionError(
                f"template reference has an unsupported candidate shape: {name}"
            )
        active.add(name)
        try:
            for target in literal_references:
                visit(target)
        finally:
            active.remove(name)
        visited.add(name)

    for template_name in sorted(governed):
        visit(template_name)


class ImpactManifestTests(unittest.TestCase):
    @staticmethod
    def _write_hostile_deployment_selectors(
        root: Path,
    ) -> tuple[set[str], set[str]]:
        nonce = hashlib.sha256(os.fspath(root).encode("utf-8")).hexdigest()[:12]
        selected = {
            f"SYNC-SELECTOR-{nonce}.opaque",
            f"infra/docker/IMAGE-SELECTOR-{nonce}.opaque",
            f"tools/ARCHIVE-SELECTOR-{nonce}.opaque",
        }
        decoys = {
            f"SYNC-DECOY-{nonce}.opaque",
            f"infra/docker/IMAGE-DECOY-{nonce}.opaque",
            f"tools/ARCHIVE-DECOY-{nonce}.opaque",
        }
        for relative in selected | decoys:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"sentinel: {relative}\n", encoding="utf-8")

        sync_selected, image_selected, archive_selected = sorted(selected)

        sync = root / "tools/sync-code.py"
        sync.parent.mkdir(parents=True, exist_ok=True)
        sync.write_text(
            "from pathlib import Path\n"
            "ROOT_CODE_PATTERNS = ('selector-owned-pattern',)\n"
            "def matching_files(root, patterns):\n"
            "    assert patterns == ROOT_CODE_PATTERNS\n"
            f"    return (Path(root) / {sync_selected!r},)\n",
            encoding="utf-8",
        )
        activate = root / "infra/docker/activate.py"
        activate.parent.mkdir(parents=True, exist_ok=True)
        activate.write_text(
            "def image_source_paths(root):\n"
            f"    return ({image_selected!r},)\n",
            encoding="utf-8",
        )
        package_selector = root / "tools/_package_common.py"
        package_selector.write_text(
            "def deployment_archive_source_paths(root):\n"
            f"    return ({archive_selected!r},)\n",
            encoding="utf-8",
        )
        return selected, decoys

    def test_runner_consumes_each_real_selector_through_unpatched_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected, decoys = self._write_hostile_deployment_selectors(root)
            actual = RUNNER.deployment_authority_paths(root)
            self.assertEqual(expected, actual)
            self.assertTrue(decoys.isdisjoint(actual))

    def test_real_archive_selector_matches_real_package_filter_growth(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            project = day0 / "customer"
            project.mkdir(parents=True)
            for name in (
                "01-global.yaml",
                "02-devices_config.csv",
                "02-dhcp-subnet_config.csv",
            ):
                (project / name).write_text(f"fixture: {name}\n", encoding="utf-8")
            required = (
                ".dockerignore",
                "infra/docker/Dockerfile",
                "infra/docker/Dockerfile.dockerignore",
                "infra/docker/compose.yaml",
                "infra/docker/activate.py",
                "infra/docker/entrypoint.py",
                "infra/docker/healthcheck.py",
                "infra/docker/hostctl.py",
                "infra/docker/hostlock.py",
                "infra/docker/management_ssh_key.py",
                "infra/docker/deploy.sh",
                "infra/docker/supervisord.conf",
                "infra/docker/apache-ztp.conf",
                "infra/docker/rsyslog-dhcp.conf",
                "infra/docker/logrotate-http-ztp.conf",
                "infra/docker/container.env.example",
                "tools/_package_common.py",
                "tools/deployment_prewrite_guard.py",
                "tools/deploy-upload-archive.py",
                "tools/deployment_lock.py",
                "tools/tar-for-upload.py",
                "tools/tar-for-download.py",
                "tools/sync-code.py",
                "tools/password-update.py",
                "DAY0-Prepare/11-load.py",
                "DAY0-Prepare/12-ztp-monitor.py",
                "DAY0-Prepare/13-unload.py",
                "ztp/nvue_normalizer.py",
                "ztp/optimize/feedback.py",
                "ztp/optimize/sample_links.py",
                "ztp/templates/ztp-bootstrap.sh",
                "ztp/templates/ztp.json",
            )
            for relative in required:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"fixture: {relative}\n", encoding="utf-8")
            nonce = hashlib.sha256(
                os.fspath(root).encode("utf-8"),
            ).hexdigest()[:12]
            selected = f"tools/archive-selector-{nonce}.mjs"
            decoys = {
                f"tools/README-{nonce}.md",
                f"tools/archive-selector-{nonce}.txt",
            }
            for relative in {selected} | decoys:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"candidate: {relative}\n", encoding="utf-8")

            def write_manifest(destination: Path) -> Path:
                destination.write_text(
                    '{"schema_version":1,"files":[]}\n', encoding="ascii",
                )
                return destination

            with mock.patch.multiple(
                ARCHIVE,
                ROOT=root,
                DAY0=day0,
                MANIFEST=root / "ztp/.setup_manifest",
                TOOLS_DIR=root / "tools",
            ), mock.patch.object(
                ARCHIVE, "write_deployment_source_manifest",
                side_effect=write_manifest,
            ), redirect_stdout(io.StringIO()):
                output = root / "archive.tar.gz"
                args = type("Args", (), {
                    "project": os.fspath(project),
                    "output": output,
                    "force": False,
                    "max_file_size_mib": 50,
                    "include_images": False,
                    "include_apps": False,
                    "apps_platform": None,
                    "apps_platforms": set(),
                    "include_firmware": False,
                    "exclude_project_images": False,
                })()
                package_keywords = {"day0_all": True}
                if "artifact_kind" in inspect.signature(
                    ARCHIVE.create_package,
                ).parameters:
                    package_keywords["artifact_kind"] = "upload"
                ARCHIVE.create_package(args, **package_keywords)
                with tarfile.open(output, "r:gz") as archive:
                    packaged = {
                        member.name.removeprefix("./")
                        for member in archive.getmembers()
                    }
                selector_selected = set(
                    ARCHIVE.deployment_archive_source_paths(root),
                )

            self.assertIn(selected, packaged)
            self.assertIn(selected, selector_selected)
            self.assertTrue(decoys.isdisjoint(packaged))
            self.assertTrue(decoys.isdisjoint(selector_selected))

    def test_runner_distinguishes_selector_load_errors_from_ungoverned_output(self):
        selector_paths = (
            "tools/sync-code.py",
            "infra/docker/activate.py",
            "tools/_package_common.py",
        )
        for relative in selector_paths:
            for failure in ("missing", "import-error"):
                with self.subTest(relative=relative, failure=failure), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self._write_hostile_deployment_selectors(root)
                    selector = root / relative
                    if failure == "missing":
                        selector.unlink()
                    else:
                        selector.write_text(
                            "raise RuntimeError('hostile selector import')\n",
                            encoding="utf-8",
                        )
                    with self.assertRaisesRegex(
                        RUNNER.ImpactError,
                        rf"selector.*(?:load|configuration).*{re.escape(relative)}|"
                        rf"{re.escape(relative)}.*selector.*(?:load|configuration)",
                    ) as raised:
                        RUNNER.deployment_authority_paths(root)
                    self.assertNotRegex(
                        str(raised.exception),
                        r"ungoverned|unmapped|deployment authority paths? missing",
                    )

    def test_manifest_rejects_every_real_selector_growth_before_approval(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        governed = set(manifest["scripts"]) | set(manifest["tracked_support"])
        forbidden = (
            "UNBOUND-ROOT.html",
            "ztp/config/cumulus/template/03-templates-j2/UNBOUND.yaml.j2",
            "infra/docker/UNBOUND.runtime-support",
        )
        for relative in forbidden:
            with self.subTest(relative=relative), mock.patch.object(
                RUNNER, "discover_source_scripts", return_value=manifest["scripts"],
            ), mock.patch.object(
                RUNNER, "deployment_authority_paths", create=True,
                return_value=governed | {relative},
            ), self.assertRaisesRegex(
                RUNNER.ImpactError,
                rf"deployment.*authority.*{re.escape(relative)}|"
                rf"{re.escape(relative)}.*deployment.*authority",
            ):
                RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)

    def test_all_runner_modes_reject_selector_growth_without_touching_ledger(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        governed = set(manifest["scripts"]) | set(manifest["tracked_support"])
        relative = "UNBOUND-SELECTED.html"
        modes = (
            ("require-full", ("--check", "--require-full")),
            ("list", ("--list",)),
            ("list-suites", ("--list-suites",)),
        )
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            with mock.patch.object(
                RUNNER, "discover_source_scripts", return_value=manifest["scripts"],
            ), mock.patch.object(
                RUNNER, "deployment_authority_paths", return_value=governed,
            ):
                valid = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
                snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, valid)
            RUNNER.atomic_write_approvals(approvals, snapshot)
            before = approvals.read_bytes()
            for label, mode in modes:
                with self.subTest(mode=label), mock.patch.object(
                    RUNNER, "discover_source_scripts", return_value=manifest["scripts"],
                ), mock.patch.object(
                    RUNNER, "deployment_authority_paths", create=True,
                    return_value=governed | {relative},
                ), redirect_stdout(io.StringIO()), redirect_stderr(
                    io.StringIO(),
                ) as stderr:
                    code = RUNNER.main([
                        "--manifest", str(MANIFEST_PATH),
                        "--approvals", str(approvals),
                        *mode,
                    ])
                    self.assertEqual(2, code)
                    self.assertRegex(
                        stderr.getvalue(),
                        rf"deployment.*authority.*{relative}|"
                        rf"{relative}.*deployment.*authority",
                    )
                    self.assertEqual(before, approvals.read_bytes())

    def test_every_deployment_writer_source_is_governed(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        governed = set(manifest["scripts"]) | set(manifest["tracked_support"])
        native_root_sources = {
            path.relative_to(ROOT).as_posix()
            for path in SYNC.matching_files(ROOT, SYNC.ROOT_CODE_PATTERNS)
        }
        reusable_image_sources = set(ACTIVATE.image_source_paths(ROOT))

        self.assertLessEqual(
            native_root_sources | reusable_image_sources,
            governed,
            "every byte selected by either deployment authority must invalidate "
            "the local full-test approval when it changes",
        )

    def test_tracked_support_symlink_binds_link_target_and_resolved_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.log"
            second = root / "second.log"
            first.write_text("same payload\n", encoding="utf-8")
            second.write_text("same payload\n", encoding="utf-8")
            link = root / "selected.log"
            link.symlink_to("first.log")
            first_digest = RUNNER.sha256_support_path(root, "selected.log")
            link.unlink()
            link.symlink_to("second.log")
            second_digest = RUNNER.sha256_support_path(root, "selected.log")

        self.assertNotEqual(
            first_digest, second_digest,
            "retargeting a governed support link must invalidate approval even "
            "when both targets currently have identical bytes",
        )

    def test_every_test_module_has_exactly_one_primary_suite(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        suites = manifest["test_suites"]
        self.assertEqual(EXPECTED_TEST_SUITES, [suite["id"] for suite in suites])

        memberships = {}
        for suite in suites:
            self.assertTrue(suite["description"].strip())
            for test_id in suite["tests"]:
                memberships.setdefault(test_id, []).append(suite["id"])

        discovered = set(RUNNER.discover_tests(ROOT))
        self.assertEqual(discovered, set(memberships))
        self.assertEqual(
            {},
            {
                test_id: suite_ids
                for test_id, suite_ids in memberships.items()
                if len(suite_ids) != 1
            },
        )

    def test_manifest_rejects_test_missing_from_primary_suites(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        removed = manifest["test_suites"][0]["tests"].pop()
        self.assertTrue(removed.startswith("test_cases.test_"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RUNNER.ImpactError, "tests without primary suite"):
                RUNNER.load_and_validate_manifest(ROOT, path)

    def test_suite_selection_unions_categories_without_full_discovery(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        selection = RUNNER.select_test_suites(
            manifest, ["deployment-runtime", "ztp-runtime"],
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_ztp_container_runtime", selection.tests)
        self.assertIn("test_cases.test_ztp_release_core_review", selection.tests)
        self.assertNotIn("test_cases.test_documentation_catalog", selection.tests)
        self.assertTrue(any("deployment-runtime" in item for item in selection.reasons))
        self.assertTrue(any("ztp-runtime" in item for item in selection.reasons))

    def test_suite_dispatch_is_read_only_for_approval_ledger(self):
        with (
            mock.patch.object(RUNNER, "run_selection", return_value=0) as run,
            mock.patch.object(RUNNER, "atomic_write_approvals") as approve,
        ):
            code = RUNNER.main([
                "--suite", "repository-governance",
                "--suite", "vm-validation",
            ])
        self.assertEqual(0, code)
        approve.assert_not_called()
        selection = run.call_args.args[1]
        self.assertIn("test_cases.test_change_aware_test_runner", selection.tests)
        self.assertIn("test_cases.test_vm_validation_runner", selection.tests)

    def test_list_suites_prints_catalog_without_running_tests(self):
        output = io.StringIO()
        with (
            redirect_stdout(output),
            mock.patch.object(RUNNER, "run_selection") as run,
        ):
            code = RUNNER.main(["--list-suites"])
        self.assertEqual(0, code)
        run.assert_not_called()
        rendered = output.getvalue()
        for suite_id in EXPECTED_TEST_SUITES:
            self.assertIn(suite_id, rendered)

    def test_unittest_output_is_buffered_for_success_but_replayed_for_failure(self):
        real_run = subprocess.run

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = root / "test_cases"
            cases.mkdir()
            (cases / "__init__.py").write_text("", encoding="utf-8")
            (cases / "test_noisy_pass.py").write_text(
                "import unittest\n"
                "class NoisyPass(unittest.TestCase):\n"
                "    def test_expected_negative_path(self):\n"
                "        print('EXPECTED-NEGATIVE-OUTPUT')\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )

            calls = []

            def capture(command, **kwargs):
                completed = real_run(
                    command, capture_output=True, text=True, **kwargs,
                )
                calls.append((command, completed))
                return completed

            with mock.patch.object(RUNNER.subprocess, "run", side_effect=capture):
                result = RUNNER.run_selection(
                    root, RUNNER.Selection(full_suite=True), verbose=False,
                )

            self.assertEqual(0, result)
            command, completed = calls.pop()
            self.assertIn("-b", command)
            self.assertNotIn(
                "EXPECTED-NEGATIVE-OUTPUT", completed.stdout + completed.stderr,
            )

            (cases / "test_noisy_failure.py").write_text(
                "import unittest\n"
                "class NoisyFailure(unittest.TestCase):\n"
                "    def test_real_failure(self):\n"
                "        print('REAL-FAILURE-DIAGNOSTIC')\n"
                "        self.fail('real failure')\n",
                encoding="utf-8",
            )
            with mock.patch.object(RUNNER.subprocess, "run", side_effect=capture):
                result = RUNNER.run_selection(
                    root,
                    RUNNER.Selection(tests={"test_cases.test_noisy_failure"}),
                    verbose=False,
                )

            self.assertEqual(1, result)
            command, completed = calls.pop()
            self.assertIn("-b", command)
            combined = completed.stdout + completed.stderr
            self.assertIn("REAL-FAILURE-DIAGNOSTIC", combined)
            self.assertIn("FAILED", combined)

    def test_unittest_children_never_inherit_operator_stdin(self):
        selections = (
            RUNNER.Selection(full_suite=True),
            RUNNER.Selection(tests={"test_cases.test_dummy"}),
        )
        for selection in selections:
            with self.subTest(full_suite=selection.full_suite), mock.patch.object(
                RUNNER.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as execute:
                self.assertEqual(0, RUNNER.run_selection(ROOT, selection, False))

            call = execute.call_args
            self.assertEqual(ROOT, call.kwargs["cwd"])
            self.assertFalse(call.kwargs["check"])
            self.assertEqual(
                subprocess.DEVNULL, call.kwargs.get("stdin"),
                "unittest must not consume an operator terminal or deployment prompt input",
            )

    def test_rendered_runtime_bootstraps_are_not_source_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (
                "ztp/templates/ztp-bootstrap.sh",
                "ztp/ztp-bootstrap_oob.sh",
                "ztp/ztp-bootstrap_oobofoob.sh",
            )
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\n", encoding="utf-8")
            scratch = root / ".codex_tmp_review/audit.py"
            scratch.parent.mkdir(parents=True)
            scratch.write_text("print('scratch')\n", encoding="utf-8")
            ignored_production = root / ".private/production.py"
            ignored_production.parent.mkdir(parents=True)
            ignored_production.write_text("print('production')\n", encoding="utf-8")
            exported_installer = (
                root / "outputs/docker-bundles/example/deploy-upload-archive.py"
            )
            exported_installer.parent.mkdir(parents=True)
            exported_installer.write_text(
                "print('immutable exported artifact copy')\n", encoding="utf-8",
            )
            (root / ".gitignore").write_text(
                ".private/production.py\n", encoding="utf-8"
            )

            discovered = RUNNER.discover_source_scripts(root)

        self.assertIn("ztp/templates/ztp-bootstrap.sh", discovered)
        self.assertNotIn("ztp/ztp-bootstrap_oob.sh", discovered)
        self.assertNotIn("ztp/ztp-bootstrap_oobofoob.sh", discovered)
        self.assertNotIn(".codex_tmp_review/audit.py", discovered)
        self.assertNotIn(
            "outputs/docker-bundles/example/deploy-upload-archive.py",
            discovered,
            "output bundles are immutable artifacts, not executable source roots",
        )
        self.assertIn(
            ".private/production.py", discovered,
            "an arbitrary hidden/ignored script must still fail closed into inventory",
        )

    def test_every_source_and_symlink_alias_has_direct_and_workflow_mapping(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        actual = RUNNER.discover_source_scripts(ROOT)
        self.assertEqual(actual, manifest["scripts"])
        self.assertGreaterEqual(len(actual), 100)
        self.assertNotIn("test_cases/run_related_tests.py", actual)
        self.assertEqual(
            [
                ".dockerignore",
                ".gitattributes",
                ".github/workflows/monitor-authority-root.yml",
                ".github/workflows/tests.yml",
                ".gitignore",
                "AGENTS.md",
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
                "infra/docker/README.md",
                "requirements-container-top-level.lock",
                "requirements-dev.txt",
                "test_cases/audit_public_tree.py",
                "test_cases/REAL_ENVIRONMENT.md",
                "test_cases/monitor_authority_root_warden.py",
                "test_cases/monitor_authority_source_guard.py",
                "test_cases/public_project_fixture.py",
                "test_cases/run_monitor_authority_entrypoints.sh",
                "test_cases/run_related_tests.py",
                "test_cases/run_vm_validation.py",
                "user-manual.html",
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
                "infra/docker/.dockerignore",
                "infra/docker/.gitignore",
                "infra/docker/Dockerfile",
                "infra/docker/Dockerfile.dockerignore",
                "infra/docker/apache-ztp.conf",
                "infra/docker/compose.yaml",
                "infra/docker/container.env.example",
                "infra/docker/logrotate-http-ztp.conf",
                "infra/docker/rsyslog-dhcp.conf",
                "infra/docker/runtime-contract.json",
                "infra/docker/supervisord.conf",
                "tools/lldp-analyze-tool/04-lldp-device-aliases.json",
                "ztp/config/cumulus/ar_profile_custom.conf",
                "ztp/config/cumulus/default.yaml",
                "ztp/config/cumulus/default_5.16.5.yaml",
                "ztp/config/cumulus/template/P2P/01-inventory.log",
                "ztp/config/cumulus/template/P2P/02-port-mapping.log",
                "ztp/config/cumulus/template/P2P/03-splitter.log",
                "ztp/config/cumulus/template/P2P/air-template-no-oob.json",
                "ztp/config/cumulus/template/P2P/air-template.json",
                "ztp/config/cumulus/template/P2P/lldpq-template.dot",
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
                "ztp/config/nvos/default.yaml",
                "ztp/config/nvos/disable-password-hardening.nv",
                "ztp/config/nvos/template/P2P/01-inventory.log",
                "ztp/config/nvos/template/P2P/02-port-mapping.log",
                "ztp/config/nvos/template/P2P/03-splitter.log",
                "ztp/templates/ztp.json",
            ],
            manifest["tracked_support"],
        )
        self.assertNotEqual(
            actual["infiniband/monitor/cron.sh"],
            "infiniband/monitor/cron.sh",
        )

    def test_new_unmapped_script_fails_closed(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        removed = next(iter(manifest["scripts"]))
        del manifest["scripts"][removed]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(RUNNER.ImpactError, "source inventory differs"):
                RUNNER.load_and_validate_manifest(ROOT, path)

    def test_runtime_contract_asset_change_invalidates_approval_and_selects_tests(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        relative = "infra/docker/runtime-contract.json"
        self.assertIn(relative, manifest["tracked_support"])
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        approvals = RUNNER.snapshot_as_json(snapshot)
        changed = RUNNER.Snapshot(
            manifest_sha256=snapshot.manifest_sha256,
            scripts=snapshot.scripts,
            tests=snapshot.tests,
            support={
                **snapshot.support,
                relative: "f" * 64,
            },
        )
        pending = RUNNER.detect_pending(changed, approvals)
        self.assertEqual({relative}, pending.support)

        selection = RUNNER.select_tests(ROOT, manifest, [], pending)
        self.assertIn(relative, selection.changed_paths)
        self.assertIn("test_cases.test_ztp_container_runtime", selection.tests)

    def test_script_selects_direct_contract_and_multi_script_workflow(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        approvals = RUNNER.snapshot_as_json(snapshot)
        pending = RUNNER.detect_pending(snapshot, approvals)
        selection = RUNNER.select_tests(
            ROOT, manifest, ["ztp/config/isc-dhcp-server/c1-generate_dhcp.py"], pending,
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_load_release_transaction", selection.tests)
        self.assertIn("test_cases.test_full_flow_integration", selection.tests)
        self.assertTrue(any("workflow" in reason for reason in selection.reasons))

    def test_nvos_ztp_template_selects_its_render_contract(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        selection = RUNNER.select_tests(
            ROOT, manifest, ["ztp/templates/ztp.json"],
            RUNNER.detect_pending(snapshot, RUNNER.snapshot_as_json(snapshot)),
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_project_contracts", selection.tests)
        self.assertIn("test_cases.test_ztp_release_core_review", selection.tests)

    def test_canonical_script_change_expands_all_shared_symlink_paths(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        selection = RUNNER.select_tests(
            ROOT,
            manifest,
            ["ethernet/monitor/cron.sh"],
            RUNNER.detect_pending(snapshot, RUNNER.snapshot_as_json(snapshot)),
        )
        self.assertTrue(
            {
                "ethernet/monitor/cron.sh",
                "infiniband/monitor/cron.sh",
                "nvlink/monitor/cron.sh",
            }.issubset(selection.changed_paths)
        )
        self.assertIn("test_cases.test_monitor_stack_review", selection.tests)

    def test_unknown_changed_path_falls_back_to_full_suite(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        selection = RUNNER.select_tests(
            ROOT, manifest, ["new-domain/behavior.conf"],
            RUNNER.detect_pending(snapshot, RUNNER.snapshot_as_json(snapshot)),
        )
        self.assertTrue(selection.full_suite)

    def test_complete_rules_bind_exact_template_and_default_authorities(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        complete = [
            rule for rule in manifest["path_rules"]
            if rule.get("complete_tracked_support") is True
        ]
        self.assertEqual(2, len(complete))
        by_paths = {tuple(rule["paths"]): rule for rule in complete}
        self.assertEqual(
            {TEMPLATE_AUTHORITY_PATTERN, *DEFAULT_AUTHORITY_PATTERNS},
            {path for paths in by_paths for path in paths},
        )
        template_rule = by_paths[(TEMPLATE_AUTHORITY_PATTERN,)]
        default_rule = by_paths[DEFAULT_AUTHORITY_PATTERNS]
        self.assertNotIn("full_suite", template_rule)
        self.assertNotIn("full_suite", default_rule)
        self.assertEqual(
            [
                "test_cases.test_ztp_container_runtime",
                "test_cases.test_project_contracts",
                "test_cases.test_v2_project_schema",
                "test_cases.test_v2_generation_flow",
                "test_cases.test_change_aware_test_runner",
                "test_cases.test_flow_release_platform_matrix",
            ],
            template_rule["tests"],
        )
        self.assertEqual(
            [
                "test_cases.test_ztp_container_runtime",
                "test_cases.test_load_release_transaction",
                "test_cases.test_project_contracts",
                "test_cases.test_upload_package_contract",
                "test_cases.test_v2_generation_flow",
                "test_cases.test_v2_project_schema",
                "test_cases.test_change_aware_test_runner",
            ],
            default_rule["tests"],
        )

    def test_manifest_rejects_unbound_complete_member_with_proof_diagnostic(self):
        template_missing = (
            "_bridge_l2vlans.yaml.j2", "_dhcp_relay.yaml.j2",
            "_extra_aaa_users.yaml.j2", "_global_evpn.yaml.j2",
        )
        missing_paths = [
            "ztp/config/cumulus/template/03-templates-j2/" + name
            for name in template_missing
        ] + [
            "ztp/config/cumulus/default.yaml",
            "ztp/config/cumulus/default_5.16.5.yaml",
            "ztp/config/nvos/default.yaml",
        ]
        for missing in missing_paths:
            with self.subTest(missing=missing):
                manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
                complete = [
                    rule for rule in manifest["path_rules"]
                    if rule.get("complete_tracked_support") is True
                    and any(
                        RUNNER.path_matches(missing, [pattern])
                        for pattern in rule["paths"]
                    )
                ]
                self.assertEqual(1, len(complete), missing)
                manifest["tracked_support"].remove(missing)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "manifest.json"
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                    deployment_authority = RUNNER.deployment_authority_paths(ROOT)
                    self.assertIn(missing, deployment_authority)
                    with self.assertRaisesRegex(
                        RUNNER.ImpactError,
                        rf"^deployment authority paths are ungoverned: "
                        rf"{re.escape(missing)}$",
                    ):
                        RUNNER.load_and_validate_manifest(ROOT, path)
                    with mock.patch.object(
                        RUNNER, "deployment_authority_paths",
                        return_value=deployment_authority - {missing},
                    ), self.assertRaisesRegex(
                        RUNNER.ImpactError,
                        rf"unbound-on-disk=.*{re.escape(Path(missing).name)}"
                        r".*full-suite proof",
                    ):
                        RUNNER.load_and_validate_manifest(ROOT, path)

    def test_complete_set_reconciliation_reports_both_sorted_asymmetries(self):
        with self.assertRaisesRegex(
            RUNNER.ImpactError,
            r"unbound-on-disk=a/one, a/two; pinned-but-missing=a/old; "
            r"full-suite proof",
        ):
            RUNNER._reconcile_complete_tracked_support(
                "path_rules[fixture]",
                {"a/two", "a/one"},
                {"a/old"},
            )

    def test_complete_rule_schema_rejects_unknown_keys_and_non_boolean_flag(self):
        mutations = (
            ("unknown", "unreviewed_complete_policy", True, "unknown keys"),
            ("string", "complete_tracked_support", "true", "boolean"),
            ("integer", "complete_tracked_support", 1, "boolean"),
            ("null", "complete_tracked_support", None, "boolean"),
            ("full-suite-string", "full_suite", "true", "boolean"),
            ("full-suite-integer", "full_suite", 1, "boolean"),
        )
        for label, key, value, diagnostic in mutations:
            with self.subTest(label=label):
                manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
                manifest["path_rules"][1][key] = value
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "manifest.json"
                    path.write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaisesRegex(RUNNER.ImpactError, diagnostic):
                        RUNNER.load_and_validate_manifest(ROOT, path)

    def test_complete_discovery_uses_positive_direct_authority_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            templates = root / "authority/templates"
            templates.mkdir(parents=True)
            (templates / "role.yaml.j2").write_text("role\n", encoding="utf-8")
            (templates / "_partial.yaml.j2").write_text(
                "partial\n", encoding="utf-8",
            )
            nested = templates / "nested"
            nested.mkdir()
            (nested / "hidden.yaml.j2").write_text("hidden\n", encoding="utf-8")
            generated = root / "DAY0-Prepare/demo/99-output-eth/x_combine"
            generated.mkdir(parents=True)
            (generated / "default.yaml").write_text("output\n", encoding="utf-8")
            defaults = root / "authority/defaults"
            defaults.mkdir()
            (defaults / "default.yaml").write_text("input\n", encoding="utf-8")

            self.assertEqual(
                {
                    "authority/templates/_partial.yaml.j2",
                    "authority/templates/role.yaml.j2",
                },
                RUNNER._complete_tracked_support_matches(
                    root, "authority/templates/*.yaml.j2",
                ),
            )
            self.assertEqual(
                {"authority/defaults/default.yaml"},
                RUNNER._complete_tracked_support_matches(
                    root, "authority/defaults/default*.yaml",
                ),
            )

    def test_manifest_never_hashes_complete_members_through_ordinary_path_api(self):
        complete_paths = {
            "ztp/config/cumulus/template/03-templates-j2/" + name
            for name in EXPECTED_TEMPLATE_AUTHORITY_NAMES
        } | {
            "ztp/config/cumulus/default.yaml",
            "ztp/config/cumulus/default_5.16.5.yaml",
            "ztp/config/nvos/default.yaml",
        }
        ordinary_hasher = RUNNER.sha256_support_path

        def guarded_hash(root, relative):
            if relative in complete_paths:
                self.fail(
                    f"complete member reached ordinary pathname hasher: {relative}"
                )
            return ordinary_hasher(root, relative)

        with mock.patch.object(
            RUNNER, "sha256_support_path", side_effect=guarded_hash,
        ):
            RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)

    def test_complete_root_fstat_fault_closes_every_held_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = root / "authority"
            authority.mkdir()
            (authority / "match.yaml").write_text("safe\n", encoding="utf-8")
            before = set(os.listdir("/dev/fd"))
            with (
                mock.patch.object(
                    RUNNER.os, "fstat", side_effect=OSError("injected fstat fault"),
                ),
                self.assertRaisesRegex(RUNNER.ImpactError, "authority root"),
            ):
                RUNNER._complete_tracked_support_matches(
                    root, "authority/*.yaml",
                )
            self.assertEqual(before, set(os.listdir("/dev/fd")))

    def test_complete_discovery_rejects_unsafe_pattern_grammar(self):
        bad_patterns = (
            "/absolute/*.yaml", "../outside/*.yaml", "authority/**/x.yaml",
            "authority/wild*/x.yaml", "authority/exact.yaml",
            "authority/nu\x00l/*.yaml", r"authority\windows\*.yaml",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "authority").mkdir()
            for pattern in bad_patterns:
                with self.subTest(pattern=pattern), self.assertRaisesRegex(
                    RUNNER.ImpactError, "complete tracked support pattern",
                ):
                    RUNNER._complete_tracked_support_matches(root, pattern)

    def test_complete_discovery_rejects_root_and_matching_member_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            (outside / "x.yaml").write_text("x\n", encoding="utf-8")
            (root / "linked-root").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(RUNNER.ImpactError, "authority root"):
                RUNNER._complete_tracked_support_matches(
                    root, "linked-root/*.yaml",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real-parent"
            authority = real_parent / "authority"
            authority.mkdir(parents=True)
            (authority / "x.yaml").write_text("x\n", encoding="utf-8")
            (root / "linked-parent").symlink_to(
                real_parent, target_is_directory=True,
            )
            with self.assertRaisesRegex(RUNNER.ImpactError, "authority root"):
                RUNNER._complete_tracked_support_matches(
                    root, "linked-parent/authority/*.yaml",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = root / "authority"
            authority.mkdir()
            (authority / "match.yaml").write_text("payload\n", encoding="utf-8")
            self.assertEqual(
                {"authority/match.yaml"},
                RUNNER._complete_tracked_support_matches(root, "authority/*.yaml"),
            )

        for shape in ("symlink-inside", "symlink-outside", "hardlink", "directory"):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = root / "authority"
                authority.mkdir()
                target = (
                    authority / "nonmatching.source"
                    if shape == "symlink-inside" else root / "target"
                )
                target.write_text("payload\n", encoding="utf-8")
                member = authority / "match.yaml"
                if shape.startswith("symlink"):
                    member.symlink_to(target)
                elif shape == "hardlink":
                    os.link(target, member)
                else:
                    member.mkdir()
                with self.assertRaisesRegex(
                    RUNNER.ImpactError, "complete tracked support member",
                ):
                    RUNNER._complete_tracked_support_matches(
                        root, "authority/*.yaml",
                    )

    def test_complete_snapshot_rejects_root_and_member_rebinding_races(self):
        phases = (
            "root-before-open",
            "root-after-scan",
            "member-before-open",
            "member-after-read",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                authority = root / "authority"
                authority.mkdir()
                member = authority / "match.yaml"
                member.write_text("reviewed\n", encoding="utf-8")
                mutated = False

                def mutate(observed_phase, _relative):
                    nonlocal mutated, authority, member
                    if mutated or observed_phase != phase:
                        return
                    mutated = True
                    if phase.startswith("root-"):
                        authority.rename(root / "held-authority")
                        authority = root / "authority"
                        authority.mkdir()
                        member = authority / "match.yaml"
                        member.write_text("replacement-root\n", encoding="utf-8")
                    else:
                        member.rename(authority / "held.source")
                        member.write_text("replacement-member\n", encoding="utf-8")

                with self.assertRaisesRegex(
                    RUNNER.ImpactError, "authority root|complete tracked support member",
                ):
                    RUNNER._complete_tracked_support_snapshot(
                        root, "authority/*.yaml", _test_hook=mutate,
                    )
                self.assertTrue(mutated, phase)

    def test_governed_jinja_reference_closure_is_static_and_complete(self):
        template_root = ROOT / "ztp/config/cumulus/template/03-templates-j2"
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        prefix = template_root.relative_to(ROOT).as_posix() + "/"
        governed = {
            path[len(prefix):]
            for path in manifest["tracked_support"]
            if path.startswith(prefix) and path.endswith(".yaml.j2")
        }
        self.assertEqual(EXPECTED_TEMPLATE_AUTHORITY_NAMES, governed)
        assert_static_jinja_closure(template_root, governed)

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / "a.yaml.j2").write_text(
                "{% include 'b.yaml.j2' %}\n", encoding="utf-8",
            )
            (fixture / "b.yaml.j2").write_text(
                "{% import 'c.yaml.j2' as c %}\n", encoding="utf-8",
            )
            (fixture / "c.yaml.j2").write_text(
                "{% from 'd.yaml.j2' import value %}\n", encoding="utf-8",
            )
            (fixture / "d.yaml.j2").write_text(
                "{% extends 'e.yaml.j2' %}\n", encoding="utf-8",
            )
            (fixture / "e.yaml.j2").write_text(
                "{% macro value() %}value{% endmacro %}\n"
                "{% block body %}body{% endblock %}\n",
                encoding="utf-8",
            )
            assert_static_jinja_closure(
                fixture, {
                    "a.yaml.j2", "b.yaml.j2", "c.yaml.j2", "d.yaml.j2",
                    "e.yaml.j2",
                },
            )

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / "a.yaml.j2").write_text(
                "{% include 'b.yaml.j2' %}\n", encoding="utf-8",
            )
            (fixture / "b.yaml.j2").write_text(
                "{% extends 'a.yaml.j2' %}\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(AssertionError, "cycle"):
                assert_static_jinja_closure(
                    fixture, {"a.yaml.j2", "b.yaml.j2"},
                )

        bad_sources = {
            "dynamic": "{% include selected_template %}\n",
            "candidate-list": "{% include ['b.yaml.j2', 'c.yaml.j2'] %}\n",
            "nested": "{% include 'nested/b.yaml.j2' %}\n",
            "missing": "{% include 'missing.yaml.j2' %}\n",
            "unpinned": "{% include 'b.yaml.j2' %}\n",
        }
        for label, source in bad_sources.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                (fixture / "a.yaml.j2").write_text(source, encoding="utf-8")
                (fixture / "b.yaml.j2").write_text("b\n", encoding="utf-8")
                (fixture / "c.yaml.j2").write_text("c\n", encoding="utf-8")
                with self.assertRaises(AssertionError):
                    assert_static_jinja_closure(fixture, {"a.yaml.j2"})

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            (fixture / "target.source").write_text("safe: true\n", encoding="utf-8")
            (fixture / "linked.yaml.j2").symlink_to("target.source")
            with self.assertRaisesRegex(AssertionError, "regular file"):
                assert_static_jinja_closure(fixture, {"linked.yaml.j2"})

    def test_governed_jinja_closure_test_has_no_skip_predicate(self):
        method = type(self).test_governed_jinja_reference_closure_is_static_and_complete
        self.assertFalse(getattr(method, "__unittest_skip__", False))
        self.assertFalse(getattr(method, "__unittest_skip_why__", ""))

    def test_complete_authority_change_drops_proof_without_eager_full_selection(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        relatives = (
            "ztp/config/cumulus/template/03-templates-j2/"
            "_extra_aaa_users.yaml.j2",
            "ztp/config/cumulus/template/03-templates-j2/tan-leaf.yaml.j2",
            "ztp/config/cumulus/default.yaml",
            "ztp/config/cumulus/default_5.16.5.yaml",
            "ztp/config/nvos/default.yaml",
        )
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        prior_attestation = RUNNER.full_suite_attestation(snapshot)
        for index, relative in enumerate(relatives, start=1):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                changed = RUNNER.Snapshot(
                    manifest_sha256=snapshot.manifest_sha256,
                    scripts=snapshot.scripts,
                    tests=snapshot.tests,
                    support={**snapshot.support, relative: f"{index:x}" * 64},
                )
                self.assertFalse(
                    RUNNER.full_suite_attestation_is_current(
                        changed, prior_attestation,
                    )
                )
                pending = RUNNER.detect_pending(
                    changed,
                    {**RUNNER.snapshot_as_json(snapshot),
                     "full_suite_attestation": prior_attestation},
                )
                selection = RUNNER.select_tests(ROOT, manifest, [], pending)
                self.assertFalse(selection.full_suite)
                self.assertIn(
                    "test_cases.test_change_aware_test_runner", selection.tests,
                )
                if relative.endswith(".yaml.j2"):
                    self.assertIn(
                        "test_cases.test_flow_release_platform_matrix",
                        selection.tests,
                    )

                approvals = Path(directory) / "approved.json"
                RUNNER.atomic_write_approvals(
                    approvals, snapshot, full_suite=True,
                )
                args = RUNNER.parser().parse_args([
                    "--approvals", str(approvals), "--changed", relative,
                ])
                with (
                    mock.patch.object(
                        RUNNER, "make_snapshot", return_value=changed,
                    ),
                    mock.patch.object(RUNNER, "run_selection", return_value=0),
                ):
                    code, _state = RUNNER._one_cycle(args)
                self.assertEqual(0, code)
                approved = json.loads(approvals.read_text(encoding="utf-8"))
                self.assertNotIn("full_suite_attestation", approved)

                check = RUNNER.parser().parse_args([
                    "--approvals", str(approvals), "--check", "--require-full",
                ])
                with (
                    mock.patch.object(
                        RUNNER, "make_snapshot", return_value=changed,
                    ),
                    redirect_stderr(io.StringIO()),
                ):
                    code, _state = RUNNER._one_cycle(check)
                self.assertEqual(5, code)

    def test_new_runtime_template_is_rejected_until_safely_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = root / "templates"
            authority.mkdir()
            (authority / "tan-new-role.yaml.j2").write_text(
                "{% include '_partial.yaml.j2' %}\n", encoding="utf-8",
            )
            (authority / "_partial.yaml.j2").write_text(
                "safe: true\n", encoding="utf-8",
            )
            discovered = RUNNER._complete_tracked_support_matches(
                root, "templates/*.yaml.j2",
            )
            pinned = {"templates/tan-new-role.yaml.j2"}
            with self.assertRaisesRegex(RUNNER.ImpactError, "unbound-on-disk"):
                RUNNER._reconcile_complete_tracked_support(
                    "runtime-template-fixture", discovered, pinned,
                )
            pinned.add("templates/_partial.yaml.j2")
            RUNNER._reconcile_complete_tracked_support(
                "runtime-template-fixture", discovered, pinned,
            )
            assert_static_jinja_closure(
                authority, {Path(path).name for path in pinned},
            )
            with mock.patch.object(
                CUMULUS_GENERATOR, "TEMPLATES_DIR", str(authority),
            ):
                template_name, is_exact = CUMULUS_GENERATOR._best_template(
                    "tan-new-role", "Tan-New-Role-01",
                )
                self.assertEqual("tan-new-role.yaml.j2", template_name)
                self.assertTrue(is_exact)
                rendered = CUMULUS_GENERATOR.render(
                    CUMULUS_GENERATOR.build_env(), {}, "Tan-New-Role-01",
                    {"template": "tan-new-role"},
                )
            self.assertEqual("safe: true", rendered.strip())


class ApprovalLedgerTests(unittest.TestCase):
    def test_hash_change_is_pending_and_approval_snapshot_is_exact(self):
        snapshot = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={"x.py": {"canonical": "x.py", "sha256": "b" * 64}},
            tests={"test_cases.test_x": "c" * 64},
        )
        approved = RUNNER.snapshot_as_json(snapshot)
        self.assertFalse(RUNNER.detect_pending(snapshot, approved).any())
        changed = RUNNER.Snapshot(
            manifest_sha256=snapshot.manifest_sha256,
            scripts={"x.py": {"canonical": "x.py", "sha256": "d" * 64}},
            tests=snapshot.tests,
        )
        self.assertEqual({"x.py"}, RUNNER.detect_pending(changed, approved).scripts)

    def test_test_harness_change_is_hash_tracked_without_becoming_runtime_source(self):
        baseline = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={}, tests={},
            support={"test_cases/run_related_tests.py": "b" * 64},
        )
        approved = RUNNER.snapshot_as_json(baseline)
        changed = RUNNER.Snapshot(
            manifest_sha256=baseline.manifest_sha256,
            scripts={}, tests={},
            support={"test_cases/run_related_tests.py": "c" * 64},
        )
        self.assertEqual(
            {"test_cases/run_related_tests.py"},
            RUNNER.detect_pending(changed, approved).support,
        )

    def test_failed_related_tests_do_not_update_approval_ledger(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(approvals, snapshot)
            before = approvals.read_bytes()
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals),
                "--changed", "DAY0-Prepare/11-load.py",
            ])
            with mock.patch.object(RUNNER, "run_selection", return_value=1):
                code, _state = RUNNER._one_cycle(args)
            self.assertEqual(1, code)
            self.assertEqual(before, approvals.read_bytes())

    def test_full_suite_success_records_a_distinct_exact_attestation(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--all",
            ])
            with mock.patch.object(RUNNER, "run_selection", return_value=0):
                code, _state = RUNNER._one_cycle(args)

            self.assertEqual(0, code)
            payload = json.loads(approvals.read_text(encoding="utf-8"))
            expected_snapshot_digest = hashlib.sha256(
                json.dumps(
                    RUNNER.snapshot_as_json(snapshot),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                {
                    "schema_version": 1,
                    "snapshot_sha256": expected_snapshot_digest,
                    "environment": {
                        "python_executable": str(Path(sys.executable).resolve()),
                        "python_implementation": platform.python_implementation(),
                        "python_version": list(sys.version_info[:3]),
                        "python_cache_tag": sys.implementation.cache_tag,
                        "platform": sys.platform,
                        "machine": platform.machine(),
                        "container_toplevel_versions": (
                            EXPECTED_CONTAINER_TOPLEVEL_VERSIONS
                        ),
                        "container_toplevel_lock_sha256": hashlib.sha256(
                            CONTAINER_TOPLEVEL_LOCK.read_bytes()
                        ).hexdigest(),
                    },
                    "scenario_coverage": {
                        "root-entrypoint-workflow": (
                            "NOT COVERED (requires Linux EUID 0 private namespace)"
                        ),
                    },
                },
                payload.get("full_suite_attestation"),
            )

    def test_full_suite_environment_binds_sorted_toplevel_versions_and_lock(self):
        self.assertTrue(CONTAINER_TOPLEVEL_LOCK.is_file())
        environment = RUNNER.full_suite_environment()
        self.assertEqual(
            EXPECTED_CONTAINER_TOPLEVEL_VERSIONS,
            environment["container_toplevel_versions"],
        )
        self.assertEqual(
            hashlib.sha256(CONTAINER_TOPLEVEL_LOCK.read_bytes()).hexdigest(),
            environment["container_toplevel_lock_sha256"],
        )
        self.assertEqual(
            sorted(environment["container_toplevel_versions"], key=str.casefold),
            environment["container_toplevel_versions"],
        )
        self.assertEqual(5, len(environment["container_toplevel_versions"]))

        exact_versions = {
            item.split("==", 1)[0]: item.split("==", 1)[1]
            for item in EXPECTED_CONTAINER_TOPLEVEL_VERSIONS
        }
        with mock.patch.object(
            RUNNER.importlib_metadata,
            "version",
            side_effect=lambda name: exact_versions[name],
        ) as version:
            self.assertEqual(environment, RUNNER.full_suite_environment())
        self.assertEqual(
            [mock.call(name) for name, _expected in RUNNER.CONTAINER_TOPLEVEL_REQUIREMENTS],
            version.call_args_list,
            "metadata lookup must use the five canonical distribution names exactly once",
        )

        for changed_name, expected in RUNNER.CONTAINER_TOPLEVEL_REQUIREMENTS:
            drifted = dict(exact_versions)
            drifted[changed_name] = "9.9.9"
            with (
                self.subTest(version_drift=changed_name),
                mock.patch.object(
                    RUNNER.importlib_metadata,
                    "version",
                    side_effect=lambda name, values=drifted: values[name],
                ),
                self.assertRaisesRegex(
                    RUNNER.ImpactError,
                    rf"{re.escape(changed_name)}.*{re.escape(expected)}|"
                    rf"{re.escape(expected)}.*{re.escape(changed_name)}",
                ),
            ):
                RUNNER.full_suite_environment()

        def version_without_pandas(name):
            if name == "pandas":
                raise RUNNER.importlib_metadata.PackageNotFoundError(name)
            return dict(
                item.split("==", 1) for item in EXPECTED_CONTAINER_TOPLEVEL_VERSIONS
            )[name]

        with (
            mock.patch.object(
                RUNNER.importlib_metadata,
                "version",
                side_effect=version_without_pandas,
            ),
            self.assertRaisesRegex(RUNNER.ImpactError, "top-level.*pandas|pandas.*top-level"),
        ):
            RUNNER.full_suite_environment()

        snapshot = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={}, tests={}, support=dict(CONTAINER_TOPLEVEL_LOCK_SUPPORT),
        )
        current = RUNNER.full_suite_attestation(snapshot)
        current["environment"]["container_toplevel_versions"][0] = "Jinja2==0"
        self.assertFalse(RUNNER.full_suite_attestation_is_current(snapshot, current))

        current = RUNNER.full_suite_attestation(snapshot)
        current["environment"]["container_toplevel_lock_sha256"] = "0" * 64
        self.assertFalse(RUNNER.full_suite_attestation_is_current(snapshot, current))

    def test_toplevel_version_drift_blocks_full_run_and_stales_existing_proof(self):
        manifest = {"baseline_tests": []}
        snapshot = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={}, tests={}, support=dict(CONTAINER_TOPLEVEL_LOCK_SUPPORT),
        )
        exact_versions = dict(RUNNER.CONTAINER_TOPLEVEL_REQUIREMENTS)

        def drifted_version(name):
            return "9.9.9" if name == "pandas" else exact_versions[name]

        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            with mock.patch.object(
                RUNNER.importlib_metadata,
                "version",
                side_effect=lambda name: exact_versions[name],
            ):
                RUNNER.atomic_write_approvals(
                    approvals, snapshot, full_suite=True,
                )
            before = approvals.read_bytes()

            with self.subTest(operation="full-run"):
                all_args = RUNNER.parser().parse_args([
                    "--approvals", str(approvals), "--all",
                ])
                with (
                    mock.patch.object(
                        RUNNER, "load_and_validate_manifest", return_value=manifest,
                    ),
                    mock.patch.object(RUNNER, "make_snapshot", return_value=snapshot),
                    mock.patch.object(
                        RUNNER.importlib_metadata,
                        "version",
                        side_effect=drifted_version,
                    ),
                    mock.patch.object(
                        RUNNER, "run_selection", return_value=0,
                    ) as selected,
                    self.assertRaisesRegex(
                        RUNNER.ImpactError, "pandas.*2[.]3[.]3|2[.]3[.]3.*pandas",
                    ),
                ):
                    RUNNER._one_cycle(all_args)
                selected.assert_not_called()
                self.assertEqual(before, approvals.read_bytes())

            with self.subTest(operation="require-full-check"):
                check_args = RUNNER.parser().parse_args([
                    "--approvals", str(approvals), "--check", "--require-full",
                ])
                with (
                    mock.patch.object(
                        RUNNER, "load_and_validate_manifest", return_value=manifest,
                    ),
                    mock.patch.object(RUNNER, "make_snapshot", return_value=snapshot),
                    mock.patch.object(
                        RUNNER.importlib_metadata,
                        "version",
                        side_effect=drifted_version,
                    ),
                    redirect_stderr(io.StringIO()),
                ):
                    code, _state = RUNNER._one_cycle(check_args)
                self.assertEqual(5, code)

    def test_full_suite_reports_exact_root_entrypoint_coverage_boundary(self):
        snapshot = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={},
            tests={},
            support=dict(CONTAINER_TOPLEVEL_LOCK_SUPPORT),
        )
        expected = {
            "root-entrypoint-workflow": (
                "NOT COVERED (requires Linux EUID 0 private namespace)"
            ),
        }
        self.assertEqual(expected, RUNNER.full_suite_scenario_coverage())
        rendered = RUNNER.full_suite_coverage_summary(
            RUNNER.full_suite_attestation(snapshot),
        )
        self.assertEqual(
            "root-entrypoint-workflow: NOT COVERED "
            "(requires Linux EUID 0 private namespace)",
            rendered,
        )

    def test_require_full_rejects_plain_related_approval(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(approvals, snapshot)
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--check",
            ])
            args.require_full = True
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code, _state = RUNNER._one_cycle(args)

            self.assertEqual(5, code)
            self.assertIn("full-suite attestation", stderr.getvalue())

    def test_full_approval_never_mixes_snapshot_with_post_snapshot_lock_bytes(self):
        exact_versions = dict(RUNNER.CONTAINER_TOPLEVEL_REQUIREMENTS)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            lock = base / "requirements-container-top-level.lock"
            original = CONTAINER_TOPLEVEL_LOCK.read_bytes()
            replacement = original + b"# post-snapshot replacement\n"
            lock.write_bytes(original)
            original_hash = hashlib.sha256(original).hexdigest()
            replacement_hash = hashlib.sha256(replacement).hexdigest()
            snapshot = RUNNER.Snapshot(
                manifest_sha256="a" * 64,
                scripts={}, tests={},
                support={
                    "requirements-container-top-level.lock": original_hash,
                },
            )
            approvals = base / "approved.json"
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--all",
            ])

            def successful_selection(_root, _selection, _verbose):
                return 0

            real_atomic_write = RUNNER.atomic_write_approvals

            def replace_lock_at_atomic_write(*call_args, **call_kwargs):
                lock.write_bytes(replacement)
                return real_atomic_write(*call_args, **call_kwargs)

            with (
                mock.patch.object(RUNNER, "CONTAINER_TOPLEVEL_LOCK", lock),
                mock.patch.object(
                    RUNNER, "load_and_validate_manifest",
                    return_value={"baseline_tests": []},
                ),
                mock.patch.object(RUNNER, "make_snapshot", return_value=snapshot),
                mock.patch.object(
                    RUNNER.importlib_metadata, "version",
                    side_effect=lambda name: exact_versions[name],
                ),
                mock.patch.object(
                    RUNNER, "run_selection", side_effect=successful_selection,
                ),
                mock.patch.object(
                    RUNNER,
                    "atomic_write_approvals",
                    side_effect=replace_lock_at_atomic_write,
                ),
                self.assertRaisesRegex(
                    RUNNER.ImpactError,
                    "top-level.*lock|lock.*snapshot|source.*changed",
                ),
            ):
                RUNNER._one_cycle(args)
            self.assertFalse(
                approvals.exists(),
                "lock replacement must not mint or overwrite an approval ledger",
            )
            self.assertNotEqual(original_hash, replacement_hash)

    def test_full_approval_rolls_back_if_lock_changes_at_publish_boundary(self):
        exact_versions = dict(RUNNER.CONTAINER_TOPLEVEL_REQUIREMENTS)
        original = CONTAINER_TOPLEVEL_LOCK.read_bytes()
        replacement = original + b"# approval-publish replacement\n"
        original_hash = hashlib.sha256(original).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            lock = base / "requirements-container-top-level.lock"
            lock.write_bytes(original)
            snapshot = RUNNER.Snapshot(
                manifest_sha256="a" * 64,
                scripts={}, tests={},
                support={
                    "requirements-container-top-level.lock": original_hash,
                },
            )
            prior_payload = (
                json.dumps(RUNNER.snapshot_as_json(snapshot), sort_keys=True)
                + "\n"
            ).encode("utf-8")
            real_replace = RUNNER.os.replace

            for prior in (None, prior_payload):
                with self.subTest(prior_ledger=prior is not None):
                    lock.write_bytes(original)
                    approvals = base / "approved.json"
                    if prior is None:
                        approvals.unlink(missing_ok=True)
                    else:
                        approvals.write_bytes(prior)
                    replaced = False

                    def replace_and_swap_lock(source, destination, *args, **kwargs):
                        nonlocal replaced
                        if Path(destination) == approvals and not replaced:
                            replaced = True
                            lock.write_bytes(replacement)
                        return real_replace(source, destination, *args, **kwargs)

                    args = RUNNER.parser().parse_args([
                        "--approvals", str(approvals), "--all",
                    ])
                    with (
                        mock.patch.object(RUNNER, "CONTAINER_TOPLEVEL_LOCK", lock),
                        mock.patch.object(
                            RUNNER, "load_and_validate_manifest",
                            return_value={"baseline_tests": []},
                        ),
                        mock.patch.object(
                            RUNNER, "make_snapshot", return_value=snapshot,
                        ),
                        mock.patch.object(
                            RUNNER.importlib_metadata, "version",
                            side_effect=lambda name: exact_versions[name],
                        ),
                        mock.patch.object(RUNNER, "run_selection", return_value=0),
                        mock.patch.object(
                            RUNNER.os, "replace", side_effect=replace_and_swap_lock,
                        ),
                        self.assertRaisesRegex(
                            RUNNER.ImpactError,
                            "changed.*approval|approval.*changed|lock.*snapshot",
                        ),
                    ):
                        RUNNER._one_cycle(args)
                    self.assertTrue(replaced)
                    if prior is None:
                        self.assertFalse(approvals.exists())
                    else:
                        self.assertEqual(prior, approvals.read_bytes())

    def test_full_attestation_rejects_environment_or_snapshot_drift(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        payload = RUNNER.snapshot_as_json(snapshot)
        payload["full_suite_attestation"] = {
            "schema_version": 1,
            "snapshot_sha256": hashlib.sha256(
                json.dumps(
                    RUNNER.snapshot_as_json(snapshot),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "environment": {
                "python_executable": str(Path(sys.executable).resolve()),
                "python_implementation": platform.python_implementation(),
                "python_version": list(sys.version_info[:3]),
                "python_cache_tag": sys.implementation.cache_tag,
                "platform": sys.platform,
                "machine": "tampered-machine",
            },
            "scenario_coverage": {
                "root-entrypoint-workflow": (
                    "NOT COVERED (requires Linux EUID 0 private namespace)"
                ),
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            approvals.write_text(json.dumps(payload), encoding="utf-8")
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--check",
            ])
            args.require_full = True
            with redirect_stderr(io.StringIO()):
                code, _state = RUNNER._one_cycle(args)
        self.assertEqual(5, code)

        current = RUNNER.full_suite_attestation(snapshot)
        current.pop("scenario_coverage")
        self.assertFalse(RUNNER.full_suite_attestation_is_current(snapshot, current))

        current = RUNNER.full_suite_attestation(snapshot)
        current["scenario_coverage"]["root-entrypoint-workflow"] = "PASS"
        self.assertFalse(RUNNER.full_suite_attestation_is_current(snapshot, current))

    def test_related_rerun_preserves_only_an_already_current_full_attestation(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(
                approvals, snapshot, full_suite=True,
            )
            before = json.loads(approvals.read_text(encoding="utf-8"))[
                "full_suite_attestation"
            ]
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals),
                "--changed", "DAY0-Prepare/11-load.py",
            ])
            with mock.patch.object(RUNNER, "run_selection", return_value=0):
                code, _state = RUNNER._one_cycle(args)

            self.assertEqual(0, code)
            after = json.loads(approvals.read_text(encoding="utf-8"))
            self.assertEqual(before, after.get("full_suite_attestation"))

            RUNNER.atomic_write_approvals(approvals, snapshot)
            with mock.patch.object(RUNNER, "run_selection", return_value=0):
                code, _state = RUNNER._one_cycle(args)
            self.assertEqual(0, code)
            self.assertNotIn(
                "full_suite_attestation",
                json.loads(approvals.read_text(encoding="utf-8")),
            )

    def test_require_full_is_check_only_and_no_skip_option_exists(self):
        help_text = RUNNER.parser().format_help()
        self.assertIn("--require-full", help_text)
        self.assertNotIn("--skip-tests", help_text)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            RUNNER.main(["--require-full"])

    def test_list_mode_never_rewrites_tests_or_approvals(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        test_hashes = dict(snapshot.tests)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(approvals, snapshot)
            before = approvals.read_bytes()
            result = subprocess.run(
                [
                    sys.executable, "-B", str(RUNNER_PATH),
                    "--approvals", str(approvals),
                    "--changed", "ztp/manual-ztp.py", "--list",
                ],
                cwd=ROOT, text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("test_cases.test_manual_applied_config", result.stdout)
            self.assertEqual(before, approvals.read_bytes())
            current = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
            self.assertEqual(test_hashes, current.tests)


if __name__ == "__main__":
    unittest.main()
