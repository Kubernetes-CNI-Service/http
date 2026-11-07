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
    "operator-cli-help",
    "issue-tracker-local",
    "ufm-local-source-bridge",
    "ibsw225-canonical-runtime",
    # Added by codex 6eb4a97 (2026-10-20) .. 7c44779 (2026-10-22) without updating this pin;
    # brought up to the committed manifest on 2026-10-23 (owner approval).
    "ibsw3-source-stage-related",
    "ibsw3-scp-declaration-related",
    "ibsw3-scp-request-content-related",
    "fleet-upgrade-v2",
    "issue-tracker-sync",
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


# Literal census of the DEV tree before G1 (v3.1 work clone 29232ec, static AST census
# scripts/shard/census_ast.py in the v3.1 docs): the three module-level TestCase re-exports
# through which canonical discovery ran a borrowed class a second time (165 executions).
# TEST's census of e769395 had seven; the other four borrowers do not exist on DEV.  The
# fourth DEV borrower, test_switch_status_workflow, binds UfmCronCase, which has no test
# methods and never ran twice, so it is not an edge.  After the re-exports became module
# aliases, every non-full related selection that runs the borrower must keep running the
# defining module, as the re-export used to do.  Deliberately NOT generalised to every
# module-alias borrower: that would add selections that never ran before.
FORMER_REEXPORT_EDGES = (
    ("test_cases.test_p2p_selection_workflow", "test_cases.test_load_release_transaction"),
    ("test_cases.test_private_documentation_contract", "test_cases.test_documentation_catalog"),
    ("test_cases.test_finished_project_lifecycle", "test_cases.test_finished_project_rehydrate"),
)


def former_reexport_closure_violations(root, manifest, paths):
    """(path, borrower, definer) for each non-full related selection that loses a definer."""
    violations = []
    for path in paths:
        selection = RUNNER.select_tests(root, manifest, [path], RUNNER.PendingChanges())
        if selection.full_suite:
            continue
        for borrower, definer in FORMER_REEXPORT_EDGES:
            if borrower in selection.tests and definer not in selection.tests:
                violations.append((path, borrower, definer))
    return violations


def former_reexport_manifest_gaps(manifest):
    """(table, entry, borrower, definer) for each mapping entry that names a borrower alone."""
    entries = [("baseline_tests", "baseline_tests", manifest.get("baseline_tests", []))]
    for table in ("test_rules", "workflows", "path_rules"):
        for index, entry in enumerate(manifest.get(table, [])):
            label = entry.get("id") or f"{index}:{entry['paths'][0]}"
            entries.append((table, label, entry.get("tests", [])))
    return [
        (table, label, borrower, definer)
        for table, label, tests in entries
        for borrower, definer in FORMER_REEXPORT_EDGES
        if borrower in tests and definer not in tests
    ]


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
from test_cases import validation_unittest as VALIDATION_UNITTEST


TEMPLATE_AUTHORITY_PATTERN = (
    "ztp/config/cumulus/template/03-templates-j2/*.yaml.j2"
)
DEFAULT_AUTHORITY_PATTERNS = (
    "ztp/config/cumulus/default*.yaml",
    "ztp/config/nvos/default*.yaml",
)
IBSW225_FIXTURE_SUPPORT_PATTERN = "test_cases/ibsw225_fixture_support/*.py"
EXPECTED_TEMPLATE_AUTHORITY_NAMES = {
    "_bridge_l2vlans.yaml.j2",
    "_dhcp_relay.yaml.j2",
    "_direct_vlan_ports.yaml.j2",
    "_extra_aaa_users.yaml.j2",
    "_global_evpn.yaml.j2",
    "_l2_svis.yaml.j2",
    "_management_eth0_dhcp.yaml.j2",
    "_management_eth0_static.yaml.j2",
    "_management_eth1.yaml.j2",
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
    def test_manifest_catalog_is_bounded_and_rechecked_per_invocation(self):
        with mock.patch.object(
            RUNNER, "discover_tests", wraps=RUNNER.discover_tests,
        ) as discover:
            first = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
            self.assertEqual(2, discover.call_count)
            second = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
            self.assertEqual(4, discover.call_count)
        self.assertEqual(first, second)

    def test_catalog_cli_keeps_real_selectors_and_ledger_unchanged(self):
        ledger = ROOT / "test_cases/script_test_approved_hashes.json"
        before = ledger.read_bytes()
        output = io.StringIO()
        with (
            redirect_stdout(output),
            mock.patch.object(RUNNER, "discover_tests", wraps=RUNNER.discover_tests) as discover,
            mock.patch.object(
                RUNNER, "_load_deployment_selector", wraps=RUNNER._load_deployment_selector,
            ) as selectors,
        ):
            self.assertEqual(0, RUNNER.main(["--list-suites"]))
        self.assertEqual(2, discover.call_count)
        self.assertEqual(
            ["tools/sync-code.py", "infra/docker/activate.py", "tools/_package_common.py"],
            [call.args[1] for call in selectors.call_args_list],
        )
        self.assertEqual(before, ledger.read_bytes())
        for suite_id in EXPECTED_TEST_SUITES:
            self.assertIn(suite_id, output.getvalue())

    def test_cached_test_reference_rechecks_actual_leaf_at_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "test_probe.py"
            path.write_text("# independent probe\n", encoding="utf-8")
            available = {"test_cases.test_probe": path}
            RUNNER._validate_test_ids(
                root, available, "probe", available=available,
            )
            path.unlink()
            for kind in ("missing", "symlink", "directory"):
                with self.subTest(kind=kind):
                    if kind == "symlink":
                        target = root / "target.py"
                        target.write_text("# different leaf\n", encoding="utf-8")
                        path.symlink_to(target)
                    elif kind == "directory":
                        path.mkdir()
                    with self.assertRaisesRegex(RUNNER.ImpactError, "missing test module"):
                        RUNNER._validate_test_ids(
                            root, available, "probe", available=available,
                        )
                    if kind == "symlink":
                        path.unlink()

    def test_catalog_end_rescan_rejects_added_removed_and_rebound_mapping(self):
        original = RUNNER.discover_tests(ROOT)
        for kind in ("added", "removed", "rebound"):
            changed = dict(original)
            key = sorted(original)[0]
            if kind == "added":
                changed["test_cases.test_unmapped_private_probe"] = ROOT / "test_cases/probe.py"
            elif kind == "removed":
                changed.pop(key)
            else:
                changed[key] = ROOT / "test_cases/different_probe.py"
            with (
                self.subTest(kind=kind),
                mock.patch.object(RUNNER, "discover_tests", side_effect=[original, changed]),
                self.assertRaisesRegex(RUNNER.ImpactError, "inventory changed"),
            ):
                RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)

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
            # Archive selection is the subject of this test; keep its project
            # inputs valid under the independent R22 package-input contract.
            (project / "01-global.yaml").write_text(
                "common:\n  mgmt:\n    dhcp-server:\n      status: disabled\n"
                "    ztp:\n      status: disabled\n", encoding="utf-8",
            )
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n", encoding="utf-8",
            )
            # The upload selector now requires the setup-selected real workbook.
            # Keep this archive-growth fixture on that supported path so a
            # missing selector entry, rather than an invalid P2P input, fails it.
            from openpyxl import Workbook

            workbook = Workbook()
            workbook.active.title = "P2P"
            workbook.active.append(("src", "dst"))
            workbook.save(project / "p2p-20260923.xlsx")
            (project / "p2p.xlsx").symlink_to("p2p-20260923.xlsx")
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
            ) as execute, mock.patch.object(RUNNER, "preflight_selection"):
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

    def test_source_discovery_prunes_only_known_non_source_subtrees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "infra/entry.py",
                ".private/ignored_but_governed.py",
                ".codex_tmp-decoy.py",
                "99-output-decoy.py",
                "test_cases/node_modules/deep/irrelevant.py",
                "outputs/docker-bundles/deep/irrelevant.py",
                "monitor/cabletracker-main/deep/irrelevant.py",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("pass\n", encoding="utf-8")

            scanned = []
            real_scandir = os.scandir

            def observing_scandir(path):
                scanned.append(Path(path).relative_to(root).as_posix())
                return real_scandir(path)

            with mock.patch.object(os, "scandir", side_effect=observing_scandir), \
                    mock.patch.object(Path, "rglob", side_effect=AssertionError(
                        "source discovery traversed the entire tree"
                    )):
                discovered = RUNNER.discover_source_scripts(root)

        self.assertEqual(
            {".private/ignored_but_governed.py": ".private/ignored_but_governed.py",
             "infra/entry.py": "infra/entry.py"},
            discovered,
        )
        self.assertFalse(
            any(path.startswith(("test_cases", "outputs", "monitor/cabletracker-main"))
                for path in scanned),
            scanned,
        )

    def test_registered_nested_worktree_is_not_governed_but_decoys_are(self):
        public = load_repository_module(
            "nested_worktree_public_entrypoints",
            ROOT / "test_cases/test_all_script_entrypoints.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "-c", "user.name=Fixture",
                 "-c", "user.email=fixture@example.invalid", "commit",
                 "--allow-empty", "-qm", "baseline"],
                check=True,
            )
            parent = root / "ztp/config/cumulus/template/.claude/worktrees"
            parent.mkdir(parents=True)
            nested = parent / "real-linked"
            subprocess.run(
                ["git", "-C", str(root), "worktree", "add", "-q", "--detach",
                 str(nested), "HEAD"],
                check=True,
            )
            (nested / "unrelated.py").write_text("pass\n", encoding="utf-8")
            decoy = parent / "fake-linked"
            decoy.mkdir()
            (decoy / ".git").write_text(
                "gitdir: /nonexistent/worktree\n", encoding="utf-8"
            )
            (decoy / "new-production.py").write_text(
                "pass\n", encoding="utf-8"
            )
            source = root / "infra/new-production.py"
            source.parent.mkdir()
            source.write_text("pass\n", encoding="utf-8")

            actual = RUNNER.discover_source_scripts(root)
            with mock.patch.object(public, "ROOT", root):
                public_paths = {
                    path.relative_to(root).as_posix()
                    for path in public.source_scripts()
                }
            dotgit = nested / ".git"
            original_marker = dotgit.read_text(encoding="utf-8")
            dotgit.write_text(
                "gitdir: /nonexistent/worktree\n", encoding="utf-8"
            )
            try:
                tampered = RUNNER.discover_source_scripts(root)
            finally:
                dotgit.write_text(original_marker, encoding="utf-8")

        self.assertNotIn(
            "ztp/config/cumulus/template/.claude/worktrees/real-linked/unrelated.py",
            actual,
        )
        self.assertIn(
            "ztp/config/cumulus/template/.claude/worktrees/fake-linked/new-production.py",
            actual,
        )
        self.assertIn("infra/new-production.py", actual)
        self.assertEqual(set(actual), public_paths)
        self.assertIn(
            "ztp/config/cumulus/template/.claude/worktrees/real-linked/unrelated.py",
            tampered,
            "a stale or forged Git marker must not exempt a production script",
        )

    def test_unmapped_governed_script_still_rejects_manifest(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        actual = dict(manifest["scripts"])
        actual["infra/new-production.py"] = "infra/new-production.py"
        with mock.patch.object(
            RUNNER, "discover_source_scripts", return_value=actual,
        ):
            with self.assertRaisesRegex(
                RUNNER.ImpactError,
                r"source inventory differs from manifest: unmapped=infra/new-production.py",
            ):
                RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)

    def test_public_entrypoint_gate_uses_same_pruned_source_frame(self):
        public = load_repository_module(
            "h22_public_entrypoints", ROOT / "test_cases/test_all_script_entrypoints.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "infra/entry.py", ".private/entry.py",
                "outputs/deep/ignored.py", "test_cases/deep/ignored.py",
                "ztp/99-output-old/deep/ignored.py",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("pass\n", encoding="utf-8")
            (root / "alias.py").symlink_to("infra/entry.py")
            with mock.patch.object(public, "ROOT", root), mock.patch.object(
                Path, "rglob", side_effect=AssertionError(
                    "public entrypoint gate must share pruned discovery"
                ),
            ):
                public_paths = {
                    path.relative_to(root).as_posix()
                    for path in public.source_scripts()
                }
            governed = RUNNER.discover_source_scripts(root)
        self.assertEqual(set(governed), public_paths)
        self.assertEqual("infra/entry.py", governed["alias.py"])
        self.assertEqual(
            {".private/entry.py", "alias.py", "infra/entry.py"},
            public_paths,
        )

    def test_every_source_and_symlink_alias_has_direct_and_workflow_mapping(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        actual = RUNNER.discover_source_scripts(ROOT)
        self.assertEqual(actual, manifest["scripts"])
        self.assertGreaterEqual(len(actual), 100)
        self.assertNotIn("test_cases/run_related_tests.py", actual)
        self.assertEqual(
            [
                "requirements-f01-ssh.lock",
                "test_cases/fixtures/bounded_inner_fd_fixture.py",
                ".dockerignore",
                ".gitattributes",
                ".github/workflows/monitor-authority-root.yml",
                ".github/workflows/tests.yml",
                ".gitignore",
                "AGENTS.md",
                "Finished-projects/.gitignore",
                "Finished-projects/README.txt",
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
                "infra/infra-neutral.conf",
                "requirements-container-top-level.lock",
                "requirements-dev.txt",
                "test_cases/audit_public_tree.py",
                "test_cases/REAL_ENVIRONMENT.md",
                "test_cases/monitor_authority_root_warden.py",
                "test_cases/monitor_authority_source_guard.py",
                "test_cases/private_public_fixture_input.py",
                "test_cases/public_project_fixture.py",
                "test_cases/splitter_profile_fixture.py",
                "test_cases/module_loader.py",
                "test_cases/project_image_owned_guard_outer.py",
                "test_cases/run_monitor_authority_entrypoints.sh",
                "test_cases/run_related_tests.py",
                "test_cases/full_shard_plan.json",
                "test_cases/run_vm_validation.py",
                "test_cases/user_manual_contract.json",
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
                "DAY0-Prepare/template/99-output-infra/.gitkeep",
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
                "ztp/config/cumulus/template/03-templates-j2/_management_eth0_dhcp.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/_management_eth0_static.yaml.j2",
                "ztp/config/cumulus/template/03-templates-j2/_management_eth1.yaml.j2",
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
                "infiniband/bringup/xdr-upgrade/requirements.txt",
                "test_cases/ibsw225_fixture_support/runtime_source_support.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_upgrade_cli.py",
                "test_cases/fixtures/nvos-system-health.txt",
                "test_cases/fixtures/nvos-25.02.8008-system-version.txt",
                "test_cases/fixtures/nvos-six-cpld-firmware.txt",
                "test_cases/ibsw225_fixture_support/_fixture_test_known_hosts.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_manual_execution.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_nvos_observations.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_three_component_workflow.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_access_recovery.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_grouped_summary.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_runtime_budgets.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_os_alternatives.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_input_isolation.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_health_upgrade_gate.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_compact_summary.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_os_download_telemetry.py",
                "test_cases/ibsw225_fixture_support/_fixture_test_standalone_links.py",
                "test_cases/ibsw225_fixture_support/fixed_fixture_registry.py",
                "test_cases/ibsw225_fixture_support/legacy_shell_workflow.py",
                "test_cases/ibsw3_scp_test_isolation.py",
                "test_cases/ibsw3_scp_request_test_isolation.py",
                "test_cases/ibsw3_scp_cpld_test_isolation.py",
                "test_cases/fixtures/native-cpld-template-pre-os22.sh.txt",
                "test_cases/fixtures/native-cpld-template-with-os22.sh.txt",
                "test_cases/native_bios_flow.py",
                "test_cases/native_bios_isolation.py",
                "test_cases/native_bios_physical_io.py",
                "test_cases/native_bios_safe_image.py",
                "test_cases/native_bios_stub_sources.py",
                "test_cases/native_cpld_physical_io.py",
                "test_cases/native_cpld_safe_image.py",
                "test_cases/native_cpld_stub_sources.py",
                "test_cases/native_os_dual_channel.py",
                "test_cases/native_os_physical_bridge.py",
                "test_cases/native_os_safe_image.py",
                "test_cases/native_os_stub_sources.py",
                "test_cases/native_os_test_isolation.py",
                "test_cases/scp_foreign_probe_fixture.py",
                "test_cases/scp_main_selector_fixture.py",
                "test_cases/scp_native_cli_fixture_v2.py",
                "test_cases/scp_native_cpld_bridge_fixture.py",
                "test_cases/scp_native_cpld_bridge_isolation.py",
                "test_cases/scp_native_os_manager_fixture.py",
                "test_cases/scp_native_source_preflight_fixture.py",
                "test_cases/scp_source_cli_fixture.py",
                "test_cases/scp_stdin_cpld_protocol_fixture.py",
                "test_cases/fixtures/ibsw3-source-inverse/os22/before/tools/ibsw_upgrade_driver.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/before/tools/ibsw_upgrade_executor.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/before/tools/ibsw_upgrade_component.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/before/infiniband/bringup/xdr-upgrade/upgrade-component.sh.txt",
                "test_cases/fixtures/ibsw3-source-inverse/display/before/infiniband/bringup/xdr-upgrade/upgrade.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/candidate/tools/ibsw_upgrade_driver.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/candidate/tools/ibsw_upgrade_executor.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/candidate/tools/ibsw_upgrade_component.py.txt",
                "test_cases/fixtures/ibsw3-source-inverse/os22/candidate/infiniband/bringup/xdr-upgrade/upgrade-component.sh.txt",
                "test_cases/fixtures/ibsw3-source-inverse/display/candidate/infiniband/bringup/xdr-upgrade/upgrade.py.txt",
                "test_cases/ibsw_v2_switch_sim.py",
                "monitor/issue-tracker/cabletracker/mapping_v4.json",
                "test_cases/issue_tracker_template.py",
                "monitor/issue-tracker/engine.lock.json",
                # 2026-10-23 unified dependency table (phase 1).
                "infra/dependencies.json",
                "infra/docker/requirements-issue-tracker-engine.txt",
                "infra/requirements-ibsw-upgrade.txt",
                # 2026-10-24: macOS cp39 arm64 list of venv-ibsw-upgrade and the F01 SDK venv routing helper.
                "infra/requirements-ibsw-upgrade-macos-cp39.txt",
                "test_cases/f01_sdk_venv.py",
                "infiniband/bringup/xdr-initial-setup/infra-neutral.conf",
                # 2026-11-07 (v3.1.0 M1a): support modules of the tests the 11-load batch brought in.
                "test_cases/linux_runtime_lock_model.py",
                "test_cases/source_tools_fixture.py",
                "test_cases/subprocess_timeout_evidence.py",
                # 2026-11-07 (v3.1.1 WP-14, M4): the shared MAC spelling fixture of the identity module.
                "test_cases/fixtures/mac_spellings.tsv",
                # 2026-11-07 (v3.1.1 WP-13, I-034): the IB analyzer's port model table ships
                # with its code until G14-1, so it is deployment authority.
                "tools/ibdiagnet-analyze-tool/config/port_profiles.csv",
                # 2026-11-07 (v3.1.1 WP-8, R-013): the template's new directory sentinels.
                "DAY0-Prepare/template/99-output-ib_nvl/bringup/ufm-setup-upgrade-logs/.gitkeep",
                "DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-upgrade-v2-logs/.gitkeep",
                "DAY0-Prepare/template/99-output-monitor/ethernet/.gitkeep",
                "DAY0-Prepare/template/99-output-monitor/infiniband/.gitkeep",
                "DAY0-Prepare/template/99-output-monitor/infiniband/ufm-ibdiagnet/.gitkeep",
                "DAY0-Prepare/template/99-output-monitor/infiniband/ufm-info/.gitkeep",
                "DAY0-Prepare/template/99-output-monitor/nvlink/.gitkeep",
                "DAY0-Prepare/template/ib.csv",
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

    def test_output_infra_sentinel_bytes_invalidate_approval_and_select_req19(self):
        relative = "DAY0-Prepare/template/99-output-infra/.gitkeep"
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        self.assertIn(relative, manifest["tracked_support"])
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        self.assertEqual(
            hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
            snapshot.support[relative],
        )
        changed = RUNNER.Snapshot(
            manifest_sha256=snapshot.manifest_sha256,
            scripts=snapshot.scripts,
            tests=snapshot.tests,
            support={**snapshot.support, relative: "f" * 64},
        )
        pending = RUNNER.detect_pending(
            changed, RUNNER.snapshot_as_json(snapshot),
        )
        self.assertEqual({relative}, pending.support)
        selected = RUNNER.select_tests(ROOT, manifest, [], pending)
        self.assertIn(relative, selected.changed_paths)
        self.assertIn("test_cases.test_req19_infra_log_contract", selected.tests)
        self.assertIn("test_cases.test_req19_infra_log_workflow", selected.tests)

    def test_real_environment_card_change_selects_req10c_and_req14_contracts(self):
        relative = "test_cases/REAL_ENVIRONMENT.md"
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        self.assertIn(relative, manifest["tracked_support"])
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        changed = RUNNER.Snapshot(
            manifest_sha256=snapshot.manifest_sha256,
            scripts=snapshot.scripts,
            tests=snapshot.tests,
            support={**snapshot.support, relative: "f" * 64},
        )
        pending = RUNNER.detect_pending(
            changed, RUNNER.snapshot_as_json(snapshot),
        )
        self.assertEqual({relative}, pending.support)
        selected = RUNNER.select_tests(ROOT, manifest, [], pending)
        self.assertIn(relative, selected.changed_paths)
        self.assertIn("test_cases.test_req10c_auto_contract", selected.tests)
        self.assertIn("test_cases.test_req14_active_provenance_workflow", selected.tests)

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

    def test_req8_emitter_change_selects_public_cli_help_contract(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        selection = RUNNER.select_tests(
            ROOT,
            manifest,
            ["monitor/collection_v2_emitter.py"],
            RUNNER.PendingChanges(),
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_req8_public_cli_help_contract", selection.tests)
        self.assertTrue(
            any("-> rule req8_public_cli_help" in reason for reason in selection.reasons)
        )

    def test_global_template_change_selects_service_endpoint_contract(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        selection = RUNNER.select_tests(
            ROOT,
            manifest,
            ["DAY0-Prepare/template/01-global.yaml"],
            RUNNER.PendingChanges(),
        )
        self.assertFalse(selection.full_suite)
        self.assertIn("test_cases.test_service_endpoint_convergence", selection.tests)

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
        # The third rule, the IBSW 2.25 fixture support, came with codex 4693d8d (2026-10-19).
        self.assertEqual(3, len(complete))
        by_paths = {tuple(rule["paths"]): rule for rule in complete}
        self.assertEqual(
            {TEMPLATE_AUTHORITY_PATTERN, *DEFAULT_AUTHORITY_PATTERNS,
             IBSW225_FIXTURE_SUPPORT_PATTERN},
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
                "test_cases.test_issue0007_role_link_contract",
                "test_cases.test_issue0007_role_link_workflow",
                "test_cases.test_req8_template_refactor_contract",
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

    def test_former_reexport_closure_detects_a_borrower_without_its_definer(self):
        lifecycle = "test_cases.test_finished_project_lifecycle"
        rehydrate = "test_cases.test_finished_project_rehydrate"
        toy = {
            "baseline_tests": [],
            "scripts": {"tools/x.py": "tools/x.py"},
            "test_rules": [{"id": "x", "paths": ["tools/x.py"], "tests": [lifecycle]}],
            "workflows": [],
            "path_rules": [{"paths": ["docs/y.md"], "tests": [lifecycle, rehydrate]}],
        }
        self.assertEqual(
            [("tools/x.py", lifecycle, rehydrate)],
            former_reexport_closure_violations(ROOT, toy, ["tools/x.py", "docs/y.md"]),
        )
        self.assertEqual(
            [("test_rules", "x", lifecycle, rehydrate)], former_reexport_manifest_gaps(toy),
        )
        toy["path_rules"].append({"paths": ["docs/z.md"], "tests": [], "full_suite": True})
        toy["baseline_tests"] = [lifecycle]
        self.assertEqual(
            [("tools/x.py", lifecycle, rehydrate)],
            former_reexport_closure_violations(ROOT, toy, ["tools/x.py", "docs/z.md"]),
        )
        self.assertEqual(
            [("baseline_tests", "baseline_tests", lifecycle, rehydrate),
             ("test_rules", "x", lifecycle, rehydrate)],
            former_reexport_manifest_gaps(toy),
        )

    def test_former_testcase_reexport_borrowers_keep_definers_in_related_selection(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout.decode("utf-8").split("\0")
        paths = sorted(
            path for path in set(filter(None, listed)) | set(manifest["scripts"])
            if not (path.startswith("test_cases/test_") and path.endswith(".py"))
        )
        self.assertGreater(len(paths), 0)
        self.assertEqual([], former_reexport_closure_violations(ROOT, manifest, paths))

    def test_manifest_entries_naming_a_former_borrower_also_name_its_definer(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        self.assertEqual([], former_reexport_manifest_gaps(manifest))


class ApprovalLedgerTests(unittest.TestCase):
    def test_issue0016_validation_report_accepts_only_three_real_known_failures(self):
        report = {
            "tests_run": 3735,
            "failures": [
                {"id": test_id,
                 "traceback": "AssertionError: install silently erased a non-cooperating foreign entry"}
                for test_id in RUNNER.ISSUE0016_FAILURE_IDS
            ],
            "errors": [],
            "skipped": [
                {"id": test_id, "reason": "existing real-environment exclusion"}
                for test_id in RUNNER.VALIDATION_BASELINE_SKIP_IDS
            ],
            "expected_failures": [],
            "unexpected_successes": [],
        }
        self.assertTrue(RUNNER.issue0016_validation_report_is_exact(report))
        for changed in (
            {**report, "tests_run": 3734},
            {**report, "failures": report["failures"][:-1]},
            {**report, "failures": report["failures"] + [{"id": "other", "traceback": "x"}]},
            {**report, "failures": [{**report["failures"][0], "traceback": "unrelated failure"}] + report["failures"][1:]},
            {**report, "errors": [{"id": "other", "traceback": "x"}]},
            {**report, "skipped": report["skipped"][:-1]},
            {**report, "skipped": report["skipped"] + [{"id": "other", "reason": "x"}]},
            {**report, "expected_failures": [{"id": "other", "traceback": "x"}]},
            {**report, "unexpected_successes": ["other"]},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(RUNNER.issue0016_validation_report_is_exact(changed))

    def test_issue0016_validation_attestation_is_not_normal_release_proof(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        validation = RUNNER.full_suite_attestation(snapshot, validation_only=True)
        self.assertEqual(
            list(RUNNER.ISSUE0016_FAILURE_IDS),
            validation["validation_only"]["known_failed_tests"],
        )
        self.assertTrue(RUNNER.full_suite_attestation_is_current(
            snapshot, validation, validation_only=True,
        ))
        self.assertFalse(RUNNER.full_suite_attestation_is_current(snapshot, validation))
        self.assertFalse(RUNNER.full_suite_attestation_is_current(
            snapshot, RUNNER.full_suite_attestation(snapshot), validation_only=True,
        ))

    def test_validation_only_runner_intent_is_explicit(self):
        self.assertTrue(RUNNER.parser().parse_args(["--all", "--validation-only"]).validation_only)
        self.assertTrue(RUNNER.parser().parse_args([
            "--check", "--require-full", "--validation-only",
        ]).validation_only)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            RUNNER.main(["--validation-only"])

    def test_validation_only_ledger_cannot_pass_the_normal_full_gate(self):
        manifest = RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH)
        snapshot = RUNNER.make_snapshot(ROOT, MANIFEST_PATH, manifest)
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            RUNNER.atomic_write_approvals(
                approvals, snapshot, full_suite=True, validation_only=True,
            )
            strict = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--check", "--require-full",
            ])
            validation = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--check", "--require-full",
                "--validation-only",
            ])
            with redirect_stderr(io.StringIO()):
                self.assertEqual(5, RUNNER._one_cycle(strict)[0])
            self.assertEqual(0, RUNNER._one_cycle(validation)[0])

    def test_validation_only_full_approval_requires_the_exact_runner_result(self):
        with tempfile.TemporaryDirectory() as directory:
            approvals = Path(directory) / "approved.json"
            args = RUNNER.parser().parse_args([
                "--approvals", str(approvals), "--all", "--validation-only",
            ])
            with mock.patch.object(RUNNER, "run_validation_selection", return_value=1):
                self.assertEqual(1, RUNNER._one_cycle(args)[0])
            self.assertFalse(approvals.exists())
            with mock.patch.object(RUNNER, "run_validation_selection", return_value=0):
                self.assertEqual(0, RUNNER._one_cycle(args)[0])
            payload = json.loads(approvals.read_text(encoding="utf-8"))
            self.assertEqual(
                "ISSUE-0016",
                payload["full_suite_attestation"]["validation_only"]["issue"],
            )

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

    def test_environment_drift_before_or_during_approval_write_keeps_the_prior_ledger(self):
        # Moved from the retired test_req7_cable_runner_workflow (7d5518d:249-310, its drift loop; REQ7
        # retirement step 3b, 2026-10-24), which drifted the retired Cable metadata: atomic_write_approvals
        # re-derives the full-suite environment before writing and again while the temporary ledger exists;
        # a drift at either point refuses, leaves no temporary file and keeps the prior ledger bytes.
        snapshot = RUNNER.Snapshot(
            manifest_sha256="a" * 64,
            scripts={}, tests={}, support=dict(CONTAINER_TOPLEVEL_LOCK_SUPPORT),
        )
        environment = RUNNER.full_suite_environment()
        real_machine = platform.machine()
        prior = b'{"prior":"must-preserve"}\n'
        for drift_call, message in ((1, "changed before approval write"),
                                    (2, "changed during approval write")):
            with self.subTest(drift=message), tempfile.TemporaryDirectory() as directory:
                approvals = Path(directory) / "approved.json"
                approvals.write_bytes(prior)
                calls = []

                def machine(drift_call=drift_call):
                    calls.append(sorted(path.name for path in Path(directory).glob(".approved.json.*")))
                    return "drifted-machine" if len(calls) == drift_call else real_machine

                with mock.patch.object(RUNNER.platform, "machine", side_effect=machine), \
                        self.assertRaisesRegex(RUNNER.ImpactError, message):
                    RUNNER.atomic_write_approvals(
                        approvals, snapshot, full_suite=True,
                        full_suite_environment_value=environment,
                    )
                self.assertEqual(drift_call, len(calls))
                self.assertEqual([], calls[0], "nothing is written before the first re-check")
                if drift_call == 2:
                    self.assertEqual(1, len(calls[1]), "the second re-check sees the temporary ledger")
                self.assertEqual(prior, approvals.read_bytes())
                self.assertEqual([], sorted(path.name for path in Path(directory).iterdir()
                                            if path.name != "approved.json"))

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
                    **CONTAINER_TOPLEVEL_LOCK_SUPPORT,
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
                    **CONTAINER_TOPLEVEL_LOCK_SUPPORT,
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


class ValidationTimingDiagnosticTests(unittest.TestCase):
    """Timing is diagnostic only; the canonical validation result stays exact."""

    class _ExactValidationProbe(unittest.TestCase):
        def __init__(self, identity, outcome):
            super().__init__("runTest")
            self.identity = identity
            self.outcome = outcome

        def id(self):
            return self.identity

        def runTest(self):
            if self.outcome == "fail":
                self.fail(RUNNER.ISSUE0016_FAILURE_FRAGMENT)
            if self.outcome == "skip":
                self.skipTest("unchanged real-environment skip")

    def _exact_validation_suite(self):
        cases = [
            self._ExactValidationProbe(identity, "fail")
            for identity in RUNNER.ISSUE0016_FAILURE_IDS
        ]
        cases.extend(
            self._ExactValidationProbe(identity, "skip")
            for identity in RUNNER.VALIDATION_BASELINE_SKIP_IDS
        )
        cases.extend(
            self._ExactValidationProbe(f"synthetic.success.{index}", "pass")
            for index in range(3735 - len(cases))
        )
        return unittest.TestSuite(cases)

    class _Probe(unittest.TestCase):
        def test_success(self):
            return None

        def test_failure(self):
            self.fail("intentional diagnostic failure")

    def _suite(self):
        return unittest.TestSuite([
            self._Probe("test_success"),
            self._Probe("test_failure"),
        ])

    def test_result_measures_one_test_between_start_and_stop(self):
        case = self._Probe("test_success")
        result = VALIDATION_UNITTEST.TimedTextTestResult(io.StringIO(), True, 2)
        with mock.patch.object(
            VALIDATION_UNITTEST.time, "perf_counter", side_effect=[10.0, 10.375],
        ):
            result.startTest(case)
            result.stopTest(case)
        self.assertEqual([
            {"id": case.id(), "duration_seconds": 0.375},
        ], result.timings)

    def test_opt_in_timing_preserves_result_and_writes_one_record_per_test(self):
        with tempfile.TemporaryDirectory(prefix="validation-timing-contract-") as directory:
            root = Path(directory)
            ordinary_report = root / "ordinary-result.json"
            timed_report = root / "timed-result.json"
            timings = root / "timings.jsonl"
            with mock.patch.object(
                VALIDATION_UNITTEST.unittest.defaultTestLoader,
                "discover", side_effect=lambda **_kwargs: self._suite(),
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                ordinary_code = VALIDATION_UNITTEST.main([str(ordinary_report)])
                self.assertFalse(timings.exists())
                timed_code = VALIDATION_UNITTEST.main([
                    str(timed_report), "-v", "--timings", str(timings),
                ])
            self.assertEqual(1, ordinary_code)
            self.assertEqual(ordinary_code, timed_code)
            ordinary = json.loads(ordinary_report.read_text(encoding="utf-8"))
            timed = json.loads(timed_report.read_text(encoding="utf-8"))
            self.assertEqual(ordinary, timed)
            self.assertEqual(2, ordinary["tests_run"])
            self.assertEqual(1, len(ordinary["failures"]))
            self.assertEqual([], ordinary["errors"])
            self.assertEqual([], ordinary["skipped"])
            self.assertEqual([], list(root.glob("ordinary-*.jsonl")))
            rows = [json.loads(line) for line in timings.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                {self._Probe("test_success").id(), self._Probe("test_failure").id()},
                {row["id"] for row in rows},
            )
            self.assertEqual(2, len(rows))
            for row in rows:
                self.assertEqual({"id", "duration_seconds"}, set(row))
                self.assertIsInstance(row["duration_seconds"], float)
                self.assertGreaterEqual(row["duration_seconds"], 0.0)
            self.assertEqual(0o600, stat.S_IMODE(timings.stat().st_mode))

    def test_timing_requires_absolute_new_destination_before_discovery(self):
        with tempfile.TemporaryDirectory(prefix="validation-timing-destination-") as directory:
            root = Path(directory)
            existing = root / "existing.jsonl"
            existing.write_text("keep\n", encoding="utf-8")
            with mock.patch.object(
                VALIDATION_UNITTEST.unittest.defaultTestLoader, "discover",
            ) as discover, redirect_stderr(io.StringIO()):
                self.assertEqual(2, VALIDATION_UNITTEST.main([
                    str(root / "result.json"), "--timings", "relative.jsonl",
                ]))
                self.assertEqual(2, VALIDATION_UNITTEST.main([
                    str(root / "result.json"), "--timings", str(existing),
                ]))
                self.assertEqual(2, VALIDATION_UNITTEST.main([
                    os.path.relpath(root / "result.json", start=Path.cwd()),
                    "--timings", str(root / "result.json"),
                ]))
            discover.assert_not_called()
            self.assertEqual("keep\n", existing.read_text(encoding="utf-8"))
            self.assertFalse((root / "result.json").exists())

    def test_governance_runner_rejects_invalid_timing_before_selection(self):
        with tempfile.TemporaryDirectory(prefix="governance-timing-destination-") as directory:
            root = Path(directory)
            existing = root / "existing.jsonl"
            existing.write_text("keep\n", encoding="utf-8")
            into_repository = root / "repository-alias"
            into_repository.symlink_to(ROOT, target_is_directory=True)
            invalid = (
                ("--all", "--validation-only", "--timings", "relative.jsonl"),
                ("--all", "--validation-only", "--timings", str(existing)),
                ("--all", "--validation-only", "--timings", str(ROOT / "timings.jsonl")),
                ("--all", "--validation-only", "--timings", str(into_repository / "timings.jsonl")),
                ("--all", "--timings", str(root / "ordinary.jsonl")),
                ("--check", "--require-full", "--validation-only", "--timings", str(root / "check.jsonl")),
                ("--all", "--validation-only", "--list", "--timings", str(root / "list.jsonl")),
            )
            with mock.patch.object(RUNNER, "_one_cycle") as cycle:
                for arguments in invalid:
                    with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                        RUNNER.main(list(arguments))
                    self.assertEqual(2, raised.exception.code)
            cycle.assert_not_called()
            self.assertEqual("keep\n", existing.read_text(encoding="utf-8"))

    def test_governance_runner_preserves_exact_validation_with_opt_in_timings(self):
        selection = RUNNER.Selection(full_suite=True)
        with tempfile.TemporaryDirectory(prefix="governance-timing-workflow-") as directory:
            root = Path(directory)
            timing_path = root / "timings.jsonl"
            observed_commands = []
            observed_reports = []

            def run_helper(command, **kwargs):
                observed_commands.append(list(command))
                self.assertEqual(
                    [sys.executable, "-B", "-m", "test_cases.validation_unittest"],
                    list(command[:4]),
                )
                with mock.patch.object(
                    VALIDATION_UNITTEST.unittest.defaultTestLoader,
                    "discover", side_effect=lambda **_kwargs: self._exact_validation_suite(),
                ):
                    code = VALIDATION_UNITTEST.main(list(command[4:]))
                observed_reports.append(json.loads(Path(command[4]).read_text(encoding="utf-8")))
                return subprocess.CompletedProcess(command, code)

            with mock.patch.object(RUNNER, "preflight_selection"), mock.patch.object(
                RUNNER.subprocess, "run", side_effect=run_helper,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                ordinary_code = RUNNER.run_validation_selection(ROOT, selection, False)
                self.assertFalse(timing_path.exists())
                timed_code = RUNNER.run_validation_selection(
                    ROOT, selection, False, timing_path,
                )

            self.assertEqual(0, ordinary_code)
            self.assertEqual(ordinary_code, timed_code)
            self.assertEqual(observed_reports[0], observed_reports[1])
            self.assertTrue(RUNNER.issue0016_validation_report_is_exact(observed_reports[1]))
            self.assertEqual(2, len(observed_commands))
            self.assertEqual(5, len(observed_commands[0]))
            self.assertEqual(["--timings", str(timing_path)], observed_commands[1][-2:])
            rows = [json.loads(line) for line in timing_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(3735, len(rows))
            self.assertEqual(0o600, stat.S_IMODE(timing_path.stat().st_mode))

    def test_opt_in_timings_do_not_change_validation_approval_payload(self):
        with tempfile.TemporaryDirectory(prefix="governance-timing-ledger-") as directory:
            root = Path(directory)
            ordinary_ledger = root / "ordinary-approvals.json"
            timed_ledger = root / "timed-approvals.json"
            timing_path = root / "timings.jsonl"
            ordinary = RUNNER.parser().parse_args([
                "--approvals", str(ordinary_ledger), "--all", "--validation-only",
            ])
            timed = RUNNER.parser().parse_args([
                "--approvals", str(timed_ledger), "--all", "--validation-only",
                "--timings", str(timing_path),
            ])
            with mock.patch.object(RUNNER, "run_validation_selection", return_value=0) as run:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(0, RUNNER._one_cycle(ordinary)[0])
                    self.assertEqual(0, RUNNER._one_cycle(timed)[0])
            self.assertEqual(ordinary_ledger.read_bytes(), timed_ledger.read_bytes())
            self.assertIsNone(run.call_args_list[0].args[3])
            self.assertEqual(timing_path, run.call_args_list[1].args[3])
            self.assertFalse(timing_path.exists())


# DEV re-derivation (v3.1.0 step 3, 2026-11-06): the quiet phase of the DEV plan, frozen here from the
# reviewed decision list (v3.1 docs scripts/shard/dev_shard_config.py, with the evidence per item),
# independent of the runner and of the plan file.  TEST's twelve modules and six cases were re-checked on
# DEV: five issue-tracker modules and the gib cases do not exist here, collection_cycle_worker_contract
# lost its failing case and runs in parallel; DEV adds the host-wide runtime-guard users and the DEV
# timing hazards found by the census.
FROZEN_QUIET_MODULES = tuple("test_cases.test_" + name for name in (
    "backup_bounded_process_workflow", "collector_retrieval", "config_sync_authority",
    "config_sync_authority_workflow", "docker_management_ssh_key",
    "f01_recovery_project_key_backup_durable_workflow",
    "f01_recovery_staging_sftp_encrypted_workflow", "ibsw3_native_cpld_bridge",
    "ibsw3_native_os_event_clock", "ibsw3_scp_parent_content_owner", "ibsw3_scp_source_binding",
    "ibsw3_stdin_owned_cpld_protocol", "monitor_authority_semantic_workflow",
    "monitor_stack_review", "req10b_services_keys_workflow", "req10c_auto_workflow",
    "ztp_monitor_watch_resilience", "ztp_release_core_review",
))
FROZEN_QUIET_CASES = (
    "test_cases.test_bootstrap_config_fetch_workflow::"
    "test_cases.test_bootstrap_config_fetch_workflow.RenderedBootstrapFetchWorkflowTests.test_both_rendered_entrypoints_retry_transient_fetch_then_apply_dedicated",
    "test_cases.test_collection_cycle_handoff_workflow::"
    "test_cases.test_collection_cycle_handoff_workflow.CollectionCycleHandoffWorkflowTests.test_runtime_snapshot_mutation_between_plan_and_full_fails_closed",
    "test_cases.test_ibsw225_three_component_workflow::"
    "test_cases.test_ibsw225_three_component_workflow.ThreeComponentWorkflowTests.test_nine_devices_five_real_workers_overlap_after_native_canary",
    "test_cases.test_manual_applied_config::"
    "test_cases.test_manual_applied_config.MonitorLiveConfigTransportTests.test_actual_private_shell_monitor_and_manual_observe_same_raw_live_bytes",
    "test_cases.test_public_publication_workflow::"
    "test_cases.test_public_publication_workflow.PublicPublicationWorkflowTests.test_formal_children_share_one_isolated_dependency_capsule",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_backspace_and_line_kill_edit_the_input",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_ctrl_c_cancels",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_no_key_within_the_deadline_counts_as_enter",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_the_first_key_cancels_the_deadline",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_typed_password_is_read_without_echo",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_without_a_terminal_there_is_no_answer",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_yes_no_question_defaults_to_no_after_the_deadline",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_yes_no_question_echoes_and_accepts_y",
    "test_cases.test_ufm_setup_upgrade::"
    "test_cases.test_ufm_setup_upgrade.TimedSecretTest.test_yes_no_question_without_a_terminal_is_no",
    "test_cases.test_ufm_worker_collection::"
    "test_cases.test_ufm_worker_collection.UfmWorkerCollectionWorkflowTest.test_the_worker_plan_reaches_the_ufm_phase_and_the_switch_result_still_qualifies",
    "test_cases.test_ztp_applied_receipt::"
    "test_cases.test_ztp_applied_receipt.AppliedReceiptPersistenceTests.test_writer_rejects_fifo_rebound_at_receipt_stage_without_blocking",
    "test_cases.test_ztp_applied_receipt::"
    "test_cases.test_ztp_applied_receipt.AppliedReceiptPersistenceTests.test_writer_rejects_fifo_rebound_at_yaml_stage_without_blocking",
    "test_cases.test_ztp_applied_receipt::"
    "test_cases.test_ztp_applied_receipt.AppliedReceiptPersistenceTests.test_writer_rejects_fifo_rebound_before_stage_fsync_without_blocking",
)
P_SHARED_GROUP = (
    "test_cases.test_public_project_fixture_workflow",
    "test_cases.test_public_publication_contract",
    "test_cases.test_public_publication_v3_overlap",
    "test_cases.test_public_publication_workflow",
)


def shard_rows(spec):
    """Canonical rows in loader order from {module: [(class, [methods], class_fixture)]}.

    module keys may end with '!' to mark setUpModule/tearDownModule on that module.
    """
    rows = []
    for raw_module, classes in spec:
        module_fixture = raw_module.endswith("!")
        module = raw_module.rstrip("!")
        for class_name, methods, class_fixture in classes:
            for method in methods:
                rows.append({
                    "id": f"{module}.{class_name}.{method}", "module": module,
                    "class_module": module, "class": class_name,
                    "class_fixture": class_fixture, "module_fixture": module_fixture,
                })
    return rows


SHARD_ROWS_SPEC = (
    ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
    ("test_cases.test_b", [("B", ["test_1", "test_2", "test_3", "test_4"], False)]),
    ("test_cases.test_c", [("C", ["test_1"], True)]),
    ("test_cases.test_d", [("D", ["test_1", "test_2"], False)]),
)


def shard_plan(**overrides):
    plan = {
        "schema_version": 1,
        "description": "synthetic direct-test plan",
        "derivation": {"status": "synthetic"},
        "lane_deadline_seconds": 9000,
        "phase_a": [
            {"lane": "w0", "units": ["test_cases.test_a", "test_cases.test_d"]},
            {"lane": "w1", "units": ["test_cases.test_b#0/2"]},
            {"lane": "w2", "units": ["test_cases.test_b#1/2"]},
        ],
        "phase_b": {"lane": "wq", "units": [
            "test_cases.test_c", "test_cases.test_d::test_cases.test_d.D.test_2",
        ]},
        "slices": {"test_cases.test_b": ["test_cases.test_b.B.test_3"]},
        "same_lane": [["test_cases.test_a", "test_cases.test_d"]],
        "phase_b_reasons": {
            "test_cases.test_c": "synthetic quiet module",
            "test_cases.test_d::test_cases.test_d.D.test_2": "synthetic quiet case",
        },
    }
    plan.update(overrides)
    return plan


class FullShardDirectTests(unittest.TestCase):
    """PROP-14 D-series: the opt-in two-phase sharded full mode, argv, plan and merge.

    Expectations come from PROP-14 (D1-D17, Q2(a), Q17-Q19, Q22) and the G5Q-RA
    landing form, not from the runner implementation.
    """

    def parse_error(self, argv):
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            RUNNER.main(argv)
        self.assertEqual(2, raised.exception.code)
        return stderr.getvalue()

    def evidence_path(self):
        directory = tempfile.TemporaryDirectory(prefix="shard-direct-")
        self.addCleanup(directory.cleanup)
        return Path(directory.name).resolve() / "evidence"

    def test_sharded_argv_is_opt_in_and_serial_default_is_unchanged(self):
        default = RUNNER.parser().parse_args(["--all", "-v"])
        self.assertIsNone(default.sharded)
        destination = self.evidence_path()
        args = RUNNER.parser().parse_args(["--all", "--sharded", str(destination), "-v"])
        self.assertEqual(destination, args.sharded)
        self.assertIn("--sharded requires --all", self.parse_error(["--sharded", str(destination)]))

    def test_sharded_rejects_validation_only_and_every_non_full_mode(self):
        destination = str(self.evidence_path())
        self.assertIn(
            "--sharded cannot be combined with --validation-only",
            self.parse_error(["--all", "--validation-only", "--sharded", destination]),
        )
        for extra in (
            ["--check", "--require-full"], ["--list"], ["--preflight"],
            ["--changed", "DAY0-Prepare/11-load.py"], ["--git"], ["--suite", "repository-governance"],
        ):
            with self.subTest(extra=extra):
                message = self.parse_error(["--all", "--sharded", destination, *extra])
                self.assertTrue(
                    "--sharded cannot be combined with" in message or "cannot be combined" in message,
                    message,
                )
                self.assertNotIn("unrecognized arguments: --sharded", message)

    def test_sharded_destination_is_absolute_new_and_outside_the_repository(self):
        with tempfile.TemporaryDirectory(prefix="shard-destination-") as directory:
            existing = Path(directory).resolve()
            cases = (
                ("relative/evidence", "--sharded requires an absolute path"),
                (str(existing), "--sharded destination already exists"),
                (str(ROOT / "outputs-shard-evidence"), "--sharded destination must be outside the repository"),
                (str(existing / "missing-parent" / "evidence"), "--sharded parent directory is unavailable"),
            )
            for value, expected in cases:
                with self.subTest(value=value):
                    with self.assertRaisesRegex(RUNNER.ImpactError, re.escape(expected)):
                        RUNNER.validate_full_shard_destination(ROOT, Path(value))
            RUNNER.validate_full_shard_destination(ROOT, existing / "evidence")

    def test_help_lists_sharded_and_still_offers_no_proof_skip(self):
        help_text = RUNNER.parser().format_help()
        self.assertIn("--sharded", help_text)
        options = {
            option for action in RUNNER.parser()._actions for option in action.option_strings
        }
        self.assertFalse({option for option in options if "skip" in option or "force" in option})

    def test_managed_loopback_argv_allowlist_never_names_sharded_mode(self):
        # D13: the formal-child loopback fixture is keyed to exactly three runner argv;
        # the sharded argv exists in the runner but is never one of them.
        self.assertIn("--sharded", {
            option for action in RUNNER.parser()._actions for option in action.option_strings
        })
        text = (ROOT / "test_cases/test_public_publication_workflow.py").read_text(encoding="utf-8")
        self.assertIn('("-B", "test_cases/run_related_tests.py", "--all", "-v"),', text)
        self.assertNotIn("--sharded", text)

    def test_real_plan_has_one_quiet_lane_with_the_frozen_g5_units(self):
        plan = RUNNER.load_full_shard_plan(ROOT)
        RUNNER.validate_full_shard_plan(plan)
        self.assertIsInstance(plan["phase_b"], dict)  # N-c: phase B concurrency is one lane
        units = plan["phase_b"]["units"]
        self.assertEqual(set(FROZEN_QUIET_MODULES), {unit for unit in units if "::" not in unit})
        self.assertEqual(set(FROZEN_QUIET_CASES), {unit for unit in units if "::" in unit})
        self.assertEqual(len(units), len(set(units)))
        self.assertEqual(set(units), set(plan["phase_b_reasons"]))
        self.assertTrue(all(reason.strip() for reason in plan["phase_b_reasons"].values()))
        self.assertGreaterEqual(plan["lane_deadline_seconds"], RUNNER.FULL_SHARD_MIN_LANE_DEADLINE_SECONDS)
        self.assertGreaterEqual(RUNNER.FULL_SHARD_MIN_LANE_DEADLINE_SECONDS, 7800)

    def test_real_plan_keeps_p_group_whole_and_splits_only_fixture_free_units(self):
        import ast as ast_module
        plan = RUNNER.load_full_shard_plan(ROOT)
        self.assertIn(list(P_SHARED_GROUP), plan["same_lane"])
        lanes = {
            unit: lane["lane"]
            for lane in [*plan["phase_a"], plan["phase_b"]] for unit in lane["units"]
        }
        self.assertEqual(1, len({lanes[module] for module in P_SHARED_GROUP}))
        split_modules = set(plan["slices"]) | {unit.split("::", 1)[0] for unit in FROZEN_QUIET_CASES}
        self.assertEqual({"test_cases.test_ufm_setup_upgrade"}, set(plan["slices"]))
        for module in sorted(split_modules):
            with self.subTest(module=module):
                tree = ast_module.parse(
                    (ROOT / (module.replace(".", "/") + ".py")).read_text(encoding="utf-8"),
                )
                names = {node.name for node in ast_module.walk(tree) if isinstance(node, ast_module.FunctionDef)}
                self.assertFalse(names & {"setUpModule", "tearDownModule", "setUpClass", "tearDownClass"})

    def test_plan_schema_rejects_concurrent_quiet_lanes_and_malformed_units(self):
        RUNNER.validate_full_shard_plan(shard_plan())
        bad = {
            "phase B list": shard_plan(phase_b=[shard_plan()["phase_b"]]),
            "unknown key": {**shard_plan(), "jobs": 2},
            "short deadline": shard_plan(lane_deadline_seconds=RUNNER.FULL_SHARD_MIN_LANE_DEADLINE_SECONDS - 1),
            "boolean deadline": shard_plan(lane_deadline_seconds=True),
            "missing reason": shard_plan(phase_b_reasons={"test_cases.test_c": "x"}),
            "blank reason": shard_plan(phase_b_reasons={
                "test_cases.test_c": " ", "test_cases.test_d::test_cases.test_d.D.test_2": "x",
            }),
            "duplicate unit": shard_plan(phase_a=[
                {"lane": "w0", "units": ["test_cases.test_a", "test_cases.test_d", "test_cases.test_a"]},
                {"lane": "w1", "units": ["test_cases.test_b#0/2"]},
                {"lane": "w2", "units": ["test_cases.test_b#1/2"]},
            ]),
            "whole and sliced": shard_plan(phase_a=[
                {"lane": "w0", "units": ["test_cases.test_a", "test_cases.test_d", "test_cases.test_b"]},
                {"lane": "w1", "units": ["test_cases.test_b#0/2"]},
                {"lane": "w2", "units": ["test_cases.test_b#1/2"]},
            ]),
            "slice count": shard_plan(slices={"test_cases.test_b": ["test_cases.test_b.B.test_2",
                                                                     "test_cases.test_b.B.test_3"]}),
            "duplicate lane": shard_plan(phase_a=[
                {"lane": "w0", "units": ["test_cases.test_a", "test_cases.test_d"]},
                {"lane": "w0", "units": ["test_cases.test_b#0/2"]},
                {"lane": "w2", "units": ["test_cases.test_b#1/2"]},
            ]),
            "bad lane name": shard_plan(phase_b={"lane": "../wq", "units": shard_plan()["phase_b"]["units"]}),
            "case outside module": shard_plan(phase_b={"lane": "wq", "units": [
                "test_cases.test_c", "test_cases.test_d::test_cases.test_a.A.test_1",
            ]}),
        }
        for label, plan in bad.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(RUNNER.ImpactError, "full shard plan"):
                    RUNNER.validate_full_shard_plan(plan)

    def test_plan_application_is_an_exact_partition_in_canonical_order(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        applied = RUNNER.apply_full_shard_plan(shard_plan(), rows)
        self.assertEqual(["w0", "w1", "w2"], applied["phase_a"])
        self.assertEqual("wq", applied["phase_b"])
        # rows: a.1=0 a.2=1 b.1=2 b.2=3 b.3=4 b.4=5 c.1=6 d.1=7 d.2=8
        self.assertEqual(
            {"w0": [0, 1, 7], "w1": [2, 3], "w2": [4, 5], "wq": [6, 8]},
            applied["lanes"],
        )
        flat = sorted(index for indices in applied["lanes"].values() for index in indices)
        self.assertEqual(list(range(len(rows))), flat)

    def test_unassigned_or_stale_plan_modules_fail_closed(self):
        rows = shard_rows(SHARD_ROWS_SPEC + (("test_cases.test_e", [("E", ["test_1"], False)]),))
        with self.assertRaisesRegex(RUNNER.ImpactError, "unassigned canonical modules: test_cases.test_e"):
            RUNNER.apply_full_shard_plan(shard_plan(), rows)
        rows = shard_rows(SHARD_ROWS_SPEC[:2] + SHARD_ROWS_SPEC[3:])
        with self.assertRaisesRegex(RUNNER.ImpactError, "names modules canonical discovery does not collect"):
            RUNNER.apply_full_shard_plan(shard_plan(), rows)

    def test_stale_slice_boundary_or_case_unit_fails_closed(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        for label, plan, pattern in (
            ("missing boundary", shard_plan(slices={"test_cases.test_b": ["test_cases.test_b.B.test_9"]}),
             "slice boundary"),
            ("boundary at first row", shard_plan(slices={"test_cases.test_b": ["test_cases.test_b.B.test_1"]}),
             "slice boundary"),
            ("missing case", shard_plan(
                phase_b={"lane": "wq", "units": ["test_cases.test_c", "test_cases.test_d::test_cases.test_d.D.test_9"]},
                phase_b_reasons={"test_cases.test_c": "x", "test_cases.test_d::test_cases.test_d.D.test_9": "x"},
            ), "case unit"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(RUNNER.ImpactError, pattern):
                    RUNNER.apply_full_shard_plan(plan, rows)
        reversed_rows = shard_rows((
            ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
            ("test_cases.test_b", [("B", ["test_1", "test_3", "test_2", "test_4"], False)]),
            ("test_cases.test_c", [("C", ["test_1"], True)]),
            ("test_cases.test_d", [("D", ["test_1", "test_2"], False)]),
        ))
        RUNNER.apply_full_shard_plan(shard_plan(), reversed_rows)
        with self.assertRaisesRegex(RUNNER.ImpactError, "slice boundary"):
            RUNNER.apply_full_shard_plan(shard_plan(slices={"test_cases.test_b": [
                "test_cases.test_b.B.test_2", "test_cases.test_b.B.test_3",
            ]}, phase_a=[
                {"lane": "w0", "units": ["test_cases.test_a", "test_cases.test_d"]},
                {"lane": "w1", "units": ["test_cases.test_b#0/3", "test_cases.test_b#2/3"]},
                {"lane": "w2", "units": ["test_cases.test_b#1/3"]},
            ]), reversed_rows)

    def test_units_split_across_processes_must_have_no_class_or_module_fixture(self):
        with_class_fixture = shard_rows((
            ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
            ("test_cases.test_b", [("B", ["test_1", "test_2", "test_3", "test_4"], True)]),
            ("test_cases.test_c", [("C", ["test_1"], True)]),
            ("test_cases.test_d", [("D", ["test_1", "test_2"], False)]),
        ))
        with self.assertRaisesRegex(RUNNER.ImpactError, "fixture"):
            RUNNER.apply_full_shard_plan(shard_plan(), with_class_fixture)
        with_module_fixture = shard_rows((
            ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
            ("test_cases.test_b", [("B", ["test_1", "test_2", "test_3", "test_4"], False)]),
            ("test_cases.test_c", [("C", ["test_1"], True)]),
            ("test_cases.test_d!", [("D", ["test_1", "test_2"], False)]),
        ))
        with self.assertRaisesRegex(RUNNER.ImpactError, "fixture"):
            RUNNER.apply_full_shard_plan(shard_plan(), with_module_fixture)
        # A whole module with class fixtures (test_c) is not split and stays accepted.
        RUNNER.apply_full_shard_plan(shard_plan(), shard_rows(SHARD_ROWS_SPEC))

    def test_same_lane_declaration_is_enforced(self):
        plan = shard_plan(phase_a=[
            {"lane": "w0", "units": ["test_cases.test_a"]},
            {"lane": "w1", "units": ["test_cases.test_b#0/2", "test_cases.test_d"]},
            {"lane": "w2", "units": ["test_cases.test_b#1/2"]},
        ])
        with self.assertRaisesRegex(RUNNER.ImpactError, "same_lane"):
            RUNNER.apply_full_shard_plan(plan, shard_rows(SHARD_ROWS_SPEC))

    def test_rows_outside_their_defining_module_or_untagged_fail_closed(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        borrowed = [dict(row) for row in rows]
        borrowed[0]["class_module"] = "test_cases.test_b"
        with self.assertRaisesRegex(RUNNER.ImpactError, "outside its defining module"):
            RUNNER.apply_full_shard_plan(shard_plan(), borrowed)
        untagged = [dict(row) for row in rows]
        untagged[3]["module"] = None
        with self.assertRaisesRegex(RUNNER.ImpactError, "untagged"):
            RUNNER.apply_full_shard_plan(shard_plan(), untagged)

    def lane_records(self, rows, indices, *, outcome="success", digest="c" * 64, identity=None):
        identity = identity or RUNNER.full_shard_lane_identity()
        records = [{"event": "start", "canonical_sha256": digest, "count": len(rows), **identity}]
        for index in indices:
            records.append({"event": "test", "index": index, "id": rows[index]["id"],
                            "outcome": outcome, "seconds": 0.01})
        records.append({"event": "finished", "tests_run": len(indices), "successful": True})
        return records

    def merge(self, rows, assigned, records, exit_code=0, **extra):
        return RUNNER.merge_full_shard_lane(
            "w1", rows, assigned, records,
            {"exit": exit_code, "seconds": 1.0, "deadline_exceeded": extra.pop("deadline", False)},
            identity=RUNNER.full_shard_lane_identity(), canonical_sha256="c" * 64,
        )

    def test_merge_accepts_the_exact_lane_and_rejects_every_coverage_fault(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        assigned = [2, 3]
        clean = self.merge(rows, assigned, self.lane_records(rows, assigned))
        self.assertEqual([], clean["problems"])
        self.assertEqual([2, 3], clean["executed"])
        faults = {
            "missing result file": (None, 0, "missing result file"),
            "wrong lane": (self.lane_records(rows, [2, 3, 4]), 0, "outside its assigned lane"),
            "duplicate": (self.lane_records(rows, [2, 3, 3]), 0, "executed more than once"),
            "not executed": (self.lane_records(rows, [2]), 0, "assigned rows were not executed"),
            "no finished": (self.lane_records(rows, assigned)[:-1], 0, "no finished record"),
            "killed": (self.lane_records(rows, [2])[:-1], -9, "exit"),
            "id mismatch": ([*self.lane_records(rows, [2])[:-1],
                             {"event": "test", "index": 3, "id": "test_cases.test_b.B.other",
                              "outcome": "success", "seconds": 0.1},
                             {"event": "finished", "tests_run": 2, "successful": True}], 0, "id"),
            "fatal": ([*self.lane_records(rows, assigned)[:1], {"event": "fatal", "reason": "x"}], 3, "fatal"),
        }
        for label, (records, exit_code, pattern) in faults.items():
            with self.subTest(label=label):
                merged = self.merge(rows, assigned, records, exit_code)
                self.assertTrue(any(pattern in problem for problem in merged["problems"]), merged["problems"])
        deadline = self.merge(rows, assigned, self.lane_records(rows, assigned), -15, deadline=True)
        self.assertTrue(any("lane deadline" in problem for problem in deadline["problems"]))

    def test_merge_suppresses_only_rows_of_a_recognised_holder_skip(self):
        rows = shard_rows((
            ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
            ("test_cases.test_b", [("B", ["test_1"], False), ("S", ["test_1", "test_2"], True)]),
        ))
        assigned = [2, 3, 4]
        records = self.lane_records(rows, [2])
        records.insert(-1, {"event": "holder", "kind": "skip",
                            "description": "setUpClass (test_cases.test_b.S)"})
        merged = self.merge(rows, assigned, records)
        self.assertEqual([], merged["problems"])
        self.assertEqual([3, 4], merged["suppressed"])
        unknown = self.lane_records(rows, [2])
        unknown.insert(-1, {"event": "holder", "kind": "skip", "description": "tearDownClass (x.Y)"})
        merged = self.merge(rows, assigned, unknown)
        self.assertTrue(any("unrecognised holder" in problem for problem in merged["problems"]))
        error = self.lane_records(rows, [2])
        error.insert(-1, {"event": "holder", "kind": "error",
                          "description": "setUpClass (test_cases.test_b.S)"})
        merged = self.merge(rows, assigned, error, 1)
        self.assertTrue(any("fixture error" in problem for problem in merged["problems"]))

    def test_merge_outcomes_follow_serial_was_successful(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        for outcome, accepted in (
            ("success", True), ("skipped", True), ("expected_failure", True),
            ("unexpected_success", False), ("failure", False), ("error", False),
        ):
            with self.subTest(outcome=outcome):
                merged = self.merge(rows, [2, 3], self.lane_records(rows, [2, 3], outcome=outcome),
                                    0 if accepted else 1)
                self.assertEqual(accepted, merged["problems"] == [], merged["problems"])

    def test_merge_rejects_foreign_interpreter_or_discovery(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        identity = dict(RUNNER.full_shard_lane_identity())
        identity["executable"] = "/nonexistent/python"
        merged = self.merge(rows, [2, 3], self.lane_records(rows, [2, 3], identity=identity))
        self.assertTrue(any("interpreter identity" in problem for problem in merged["problems"]))
        merged = self.merge(rows, [2, 3], self.lane_records(rows, [2, 3], digest="d" * 64))
        self.assertTrue(any("canonical discovery differs" in problem for problem in merged["problems"]))

    def test_coverage_requires_every_canonical_row_exactly_once(self):
        complete = {"w0": {"executed": [0, 1], "suppressed": []}, "wq": {"executed": [2], "suppressed": [3]}}
        self.assertEqual([], RUNNER.full_shard_coverage_problems(4, complete))
        for label, merged in (
            ("missing", {"w0": {"executed": [0, 1], "suppressed": []}, "wq": {"executed": [2], "suppressed": []}}),
            ("twice", {"w0": {"executed": [0, 1, 2], "suppressed": []}, "wq": {"executed": [2], "suppressed": [3]}}),
            ("extra", {"w0": {"executed": [0, 1, 4], "suppressed": []}, "wq": {"executed": [2], "suppressed": [3]}}),
        ):
            with self.subTest(label=label):
                self.assertNotEqual([], RUNNER.full_shard_coverage_problems(4, merged))

    def test_lane_deadline_terminates_the_whole_process_group(self):
        import time as time_module
        with tempfile.TemporaryDirectory(prefix="shard-deadline-") as directory:
            marker = Path(directory) / "grandchild"
            program = (
                "import pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                f"pathlib.Path({str(marker)!r}).write_text(str(child.pid))\n"
                "time.sleep(60)\n"
            )
            process = subprocess.Popen(
                [sys.executable, "-B", "-c", program], start_new_session=True,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

            def reap_group():
                try:
                    os.killpg(process.pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
                process.wait(timeout=10)

            self.addCleanup(reap_group)
            log = open(os.devnull, "wb")
            self.addCleanup(log.close)
            started = time_module.monotonic()
            while not marker.exists() and time_module.monotonic() - started < 10:
                time_module.sleep(0.05)
            finished = RUNNER._full_shard_wait_lanes(
                {"w0": (process, log, time_module.monotonic(), time_module.time())},
                deadline_seconds=0.5, poll=0.05,
            )
            self.assertTrue(finished["w0"]["deadline_exceeded"])
            self.assertNotEqual(0, finished["w0"]["exit"])
            grandchild = int(marker.read_text())
            deadline = time_module.monotonic() + 10
            while time_module.monotonic() < deadline:
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    break
                time_module.sleep(0.05)
            with self.assertRaises(ProcessLookupError):
                os.kill(grandchild, 0)

    def test_lane_temporary_roots_must_carry_the_user_primary_gid(self):
        with tempfile.TemporaryDirectory(prefix="shard-gid-") as directory:
            path = Path(directory)
            # M1 (REVIEW-1): on BSD a new directory inherits its parent's group, so the
            # positive case must not depend on the group that owns TMPDIR's parent.
            os.chown(path, -1, os.getgid())
            self.assertEqual([], RUNNER._full_shard_gid_problems([path]))
            real_stat = os.stat

            def foreign_group(target, *args, **kwargs):
                info = real_stat(target, *args, **kwargs)
                values = list(info)
                values[stat.ST_GID] = os.getgid() + 1
                return os.stat_result(values)

            with mock.patch.object(RUNNER.os, "stat", side_effect=foreign_group):
                problems = RUNNER._full_shard_gid_problems([path])
            self.assertTrue(any("gid" in problem for problem in problems), problems)

    def test_cleanup_failure_is_reported_and_keeps_the_tree(self):
        with tempfile.TemporaryDirectory(prefix="shard-cleanup-") as directory:
            tree = Path(directory) / "lane"
            (tree / "inner").mkdir(parents=True)
            (tree / "inner/file").write_text("x", encoding="utf-8")
            with mock.patch.object(RUNNER.shutil, "rmtree", side_effect=OSError("denied")):
                problem = RUNNER._full_shard_remove_tree(tree)
            self.assertIn("cleanup", problem)
            self.assertTrue(tree.exists())
            self.assertIsNone(RUNNER._full_shard_remove_tree(tree))
            self.assertFalse(tree.exists())

    def test_sharded_success_records_the_serial_attestation_bytes(self):
        # Q2(a): the attestation is byte-identical to the serial one; execution form is
        # recorded only in the external audit. A failed sharded run writes nothing (D11).
        with tempfile.TemporaryDirectory(prefix="shard-attestation-") as directory:
            base = Path(directory).resolve()
            serial_ledger = base / "serial.json"
            sharded_ledger = base / "sharded.json"
            serial = RUNNER.parser().parse_args(["--approvals", str(serial_ledger), "--all"])
            sharded = RUNNER.parser().parse_args([
                "--approvals", str(sharded_ledger), "--all", "--sharded", str(base / "evidence"),
            ])
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with mock.patch.object(RUNNER, "run_sharded_selection", return_value=1) as failed:
                    self.assertEqual(1, RUNNER._one_cycle(sharded)[0])
                self.assertFalse(sharded_ledger.exists())
                self.assertEqual(base / "evidence", failed.call_args.args[3])
                with mock.patch.object(RUNNER, "run_selection", return_value=0):
                    self.assertEqual(0, RUNNER._one_cycle(serial)[0])
                with mock.patch.object(RUNNER, "run_sharded_selection", return_value=0), \
                        mock.patch.object(RUNNER, "run_selection", side_effect=AssertionError("serial path")):
                    self.assertEqual(0, RUNNER._one_cycle(sharded)[0])
            self.assertEqual(serial_ledger.read_bytes(), sharded_ledger.read_bytes())
            check = RUNNER.parser().parse_args([
                "--approvals", str(sharded_ledger), "--check", "--require-full",
            ])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, RUNNER._one_cycle(check)[0])


class FullShardReviewFixTests(unittest.TestCase):
    """REVIEW-1 M2, L1-L3, L5 and L6 of the opt-in sharded full mode.

    Expectations come from the review findings and the serial unittest contract
    (what `python -m unittest discover` reports as skipped), not from the runner.
    """

    SKIP_ROWS_SPEC = (
        ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
        ("test_cases.test_b", [("B", ["test_1"], False), ("S", ["test_1", "test_2"], True)]),
    )
    HOLDER = "setUpClass (test_cases.test_b.S)"

    def test_lane_deadline_floor_is_not_below_the_recorded_serial_wall_clock(self):
        # L3: the hang guard must never stop a lane that legitimately runs as long as the
        # whole serial suite.  CHANGE_AWARE_TESTING.md records 8,816.975 s for the most
        # recent formal serial --all baseline; the floor may not be lower than that.
        recorded_serial_wall_seconds = 8816.975
        self.assertGreaterEqual(RUNNER.FULL_SHARD_MIN_LANE_DEADLINE_SECONDS, recorded_serial_wall_seconds)
        with self.assertRaisesRegex(RUNNER.ImpactError, "lane_deadline_seconds"):
            RUNNER.validate_full_shard_plan(shard_plan(lane_deadline_seconds=8816))
        RUNNER.validate_full_shard_plan(
            shard_plan(lane_deadline_seconds=RUNNER.FULL_SHARD_MIN_LANE_DEADLINE_SECONDS),
        )

    def test_plan_runtime_skips_are_exact_reasons_for_serial_skip_entries(self):
        # M2: skips that only arise at run time (skipTest, SkipTest in setUp/setUpClass/
        # setUpModule) cannot be known before the run; the plan may allow them only by
        # their serial skip entry id with the exact reason.  The key is optional and its
        # absence allows no runtime skip at all.
        RUNNER.validate_full_shard_plan(shard_plan())
        RUNNER.validate_full_shard_plan(shard_plan(runtime_skips={
            "test_cases.test_b.B.test_2": "requires a private tier",
            "test_cases.test_b.B.test_3 (case=1)": "sub-test skip",
            "setUpClass (test_cases.test_c.C)": "fixture holder skip",
            "setUpModule (test_cases.test_d)": "fixture module skip",
        }))
        for label, value in (
            ("list", ["test_cases.test_b.B.test_2"]),
            ("module id", {"test_cases.test_b": "x"}),
            ("class id", {"test_cases.test_b.B": "x"}),
            ("teardown holder", {"tearDownClass (test_cases.test_c.C)": "x"}),
            ("blank reason", {"test_cases.test_b.B.test_2": " "}),
            ("non-string reason", {"test_cases.test_b.B.test_2": 1}),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(RUNNER.ImpactError, "full shard plan: runtime_skips"):
                    RUNNER.validate_full_shard_plan(shard_plan(runtime_skips=value))

    def test_real_plan_allows_only_the_private_documentation_tier_holder_skip(self):
        # M2: the only runtime skip site of the suite is the private documentation tier
        # gate in PrivateDocumentationContractTests.setUpClass (test_public_clean_clone_contract
        # pins it as the unique class-level gate); it skips in checkouts without the ignored
        # private tier and runs where the tier is present.  The reason is read from that
        # module's source, never from the runner.
        import ast as ast_module
        source = (ROOT / "test_cases/test_private_documentation_contract.py").read_text(encoding="utf-8")
        reasons = [
            ast_module.literal_eval(node.value) for node in ast_module.parse(source).body
            if isinstance(node, ast_module.Assign)
            and [getattr(target, "id", None) for target in node.targets] == ["PRIVATE_TIER_SKIP_REASON"]
        ]
        self.assertEqual(1, len(reasons))
        plan = RUNNER.load_full_shard_plan(ROOT)
        self.assertEqual(
            {
                "setUpClass (test_cases.test_private_documentation_contract."
                "PrivateDocumentationContractTests)": reasons[0],
            },
            plan.get("runtime_skips"),
        )

    def test_runtime_skip_entries_must_name_canonical_tests_classes_or_modules(self):
        rows = shard_rows(SHARD_ROWS_SPEC)
        self.assertEqual([], RUNNER.full_shard_runtime_skip_problems({
            "test_cases.test_b.B.test_2": "r",
            "test_cases.test_b.B.test_3 (case=1)": "r",
            "setUpClass (test_cases.test_c.C)": "r",
            "setUpModule (test_cases.test_d)": "r",
        }, rows))
        for entry in (
            "test_cases.test_b.B.test_9",
            "test_cases.test_b.B.test_9 (case=1)",
            "setUpClass (test_cases.test_c.Missing)",
            "setUpClass (test_cases.test_d)",
            "setUpModule (test_cases.test_e)",
        ):
            with self.subTest(entry=entry):
                problems = RUNNER.full_shard_runtime_skip_problems({entry: "r"}, rows)
                self.assertTrue(any("stale" in problem and entry in problem for problem in problems), problems)

    def lane_records(self, rows, indices):
        records = [{"event": "start", "canonical_sha256": "c" * 64, "count": len(rows),
                    **RUNNER.full_shard_lane_identity()}]
        for index in indices:
            records.append({"event": "test", "index": index, "id": rows[index]["id"],
                            "outcome": "success", "seconds": 0.01})
        records.append({"event": "finished", "tests_run": len(indices), "successful": True})
        return records

    def merge(self, rows, assigned, records):
        return RUNNER.merge_full_shard_lane(
            "w1", rows, assigned, records, {"exit": 0, "seconds": 1.0, "deadline_exceeded": False},
            identity=RUNNER.full_shard_lane_identity(), canonical_sha256="c" * 64,
        )

    def test_merge_records_every_skip_entry_with_its_reason(self):
        # M2: the audit must name every skip entry (as serial unittest reports them:
        # the test id, or the class/module fixture holder) together with its reason.
        rows = shard_rows(self.SKIP_ROWS_SPEC)
        assigned = [1, 2, 3, 4]
        records = self.lane_records(rows, [1, 2])
        records[1]["outcome"] = "skipped"
        records.insert(1, {"event": "skip", "index": 1, "id": rows[1]["id"], "reason": "platform"})
        records.insert(-1, {"event": "holder", "kind": "skip", "description": self.HOLDER,
                            "reason": "holder reason"})
        merged = self.merge(rows, assigned, records)
        self.assertEqual([], merged["problems"])
        self.assertEqual([3, 4], merged["suppressed"])
        self.assertEqual(
            sorted([(rows[1]["id"], "platform"), (self.HOLDER, "holder reason")]),
            sorted((entry["id"], entry["reason"]) for entry in merged["skips"]),
        )
        outside = self.lane_records(rows, [1, 2])
        outside.insert(1, {"event": "skip", "index": 0, "id": rows[0]["id"], "reason": "x"})
        merged = self.merge(rows, assigned, outside)
        self.assertTrue(
            any("skip entry" in problem and "outside" in problem for problem in merged["problems"]),
            merged["problems"],
        )
        # A skip entry is the running test's id or one of its sub-test ids, never another row's.
        foreign = self.lane_records(rows, [1, 2])
        foreign[1]["outcome"] = "skipped"
        foreign.insert(1, {"event": "skip", "index": 1, "id": rows[2]["id"], "reason": "platform"})
        merged = self.merge(rows, assigned, foreign)
        self.assertTrue(
            any("skip entry" in problem and "does not belong" in problem for problem in merged["problems"]),
            merged["problems"],
        )
        subtest = self.lane_records(rows, [1, 2])
        subtest.insert(1, {"event": "skip", "index": 1, "id": rows[1]["id"] + " (case=1)", "reason": "sub"})
        merged = self.merge(rows, [1, 2], subtest)
        self.assertEqual([], merged["problems"])
        self.assertEqual(
            [(rows[1]["id"] + " (case=1)", "sub")],
            [(entry["id"], entry["reason"]) for entry in merged["skips"]],
        )

    def test_skip_entries_must_match_enumeration_decorators_and_plan_runtime_skips(self):
        # M2: decorator skips are known at canonical enumeration (evaluated in the
        # coordinator's environment) and must be reported, with the same reason, by their
        # lane; every other skip entry must be an allowed runtime skip with the exact
        # reason.  Anything else is a skip the serial run would not have made.
        rows = shard_rows(self.SKIP_ROWS_SPEC)
        a1, a2, b1 = rows[0]["id"], rows[1]["id"], rows[2]["id"]
        decorated = [{"index": 1, "reason": "platform"}]
        runtime = {b1: "runtime reason", self.HOLDER: "holder reason"}

        def merged(*lanes):
            return {
                name: {"skips": [{"id": entry_id, "reason": reason} for entry_id, reason in entries],
                       "suppressed": list(suppressed)}
                for name, entries, suppressed in lanes
            }

        clean = merged(("w0", [(a2, "platform")], []),
                       ("wq", [(b1, "runtime reason"), (self.HOLDER, "holder reason")], [3, 4]))
        self.assertEqual([], RUNNER.full_shard_skip_problems(rows, decorated, runtime, clean))
        # An allowed runtime skip that does not happen in this checkout is not a problem.
        self.assertEqual([], RUNNER.full_shard_skip_problems(
            rows, decorated, runtime, merged(("w0", [(a2, "platform")], []), ("wq", [], [])),
        ))
        # A decorated test of a class whose setUpClass skipped is reported by the holder
        # only, exactly as in serial unittest.
        self.assertEqual([], RUNNER.full_shard_skip_problems(
            rows, [{"index": 3, "reason": "platform"}], runtime,
            merged(("wq", [(self.HOLDER, "holder reason")], [3, 4])),
        ))
        faults = {
            "decorator skip ran": (decorated, runtime, merged(("w0", [], [])), a2),
            "decorator reason": (decorated, runtime, merged(("w0", [(a2, "other")], [])), "reason"),
            "lane-only skip": (decorated, runtime,
                               merged(("w0", [(a2, "platform"), (a1, "lane only")], [])), "unexpected skip"),
            "runtime reason": (decorated, runtime,
                               merged(("w0", [(a2, "platform")], []), ("wq", [(b1, "other")], [])), "reason"),
            "holder not allowed": (decorated, {}, clean, "unexpected skip"),
            "duplicate": (decorated, runtime,
                          merged(("w0", [(a2, "platform")], []), ("w1", [(a2, "platform")], [])),
                          "more than once"),
        }
        for label, (decorator_skips, runtime_skips, result, keyword) in faults.items():
            with self.subTest(label=label):
                problems = RUNNER.full_shard_skip_problems(rows, decorator_skips, runtime_skips, result)
                self.assertTrue(any(keyword in problem for problem in problems), problems)

    def test_cleanup_retry_reraises_the_original_error_for_non_unlink_functions(self):
        # L1: Python 3.12's fd-based rmtree reports os.open/os.scandir failures through
        # onexc; re-calling os.open(path) raised TypeError and escaped the problem path.
        with tempfile.TemporaryDirectory(prefix="shard-onexc-") as directory:
            tree = Path(directory) / "lane"
            tree.mkdir()
            original = PermissionError(13, "fixture refusal", str(tree))
            raised = []

            def fake_rmtree(path, **kwargs):
                callback = kwargs.get("onexc") or kwargs.get("onerror")
                argument = original if "onexc" in kwargs else (PermissionError, original, None)
                try:
                    callback(os.open, os.fspath(path), argument)
                except BaseException as exc:
                    raised.append(exc)
                    raise

            with mock.patch.object(RUNNER.shutil, "rmtree", side_effect=fake_rmtree):
                problem = RUNNER._full_shard_remove_tree(tree)
            self.assertEqual([original], raised)
            self.assertIn("fixture refusal", problem)
            self.assertTrue(tree.exists())

    def test_cleanup_retry_still_removes_entries_of_read_only_directories(self):
        with tempfile.TemporaryDirectory(prefix="shard-readonly-") as directory:
            tree = Path(directory) / "lane"
            inner = tree / "inner"
            inner.mkdir(parents=True)
            (inner / "file").write_text("x", encoding="utf-8")
            inner.chmod(0o500)
            self.assertIsNone(RUNNER._full_shard_remove_tree(tree))
            self.assertFalse(tree.exists())

    def test_cleanup_exception_is_a_problem_and_the_audit_is_still_written(self):
        # L1: an unexpected exception during cleanup must not skip the audit; the run
        # fails closed with a recorded problem.
        with tempfile.TemporaryDirectory(prefix="shard-cleanup-audit-") as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            (root / "test_cases").mkdir(parents=True)
            (root / "test_cases/full_shard_plan.json").write_text("{}\n", encoding="utf-8")
            evidence = base / "evidence"
            with mock.patch.object(RUNNER, "FULL_SHARD_PLATFORMS", frozenset({sys.platform})), \
                    mock.patch.object(RUNNER, "load_full_shard_plan", return_value=shard_plan()), \
                    mock.patch.object(RUNNER, "preflight_selection"), \
                    mock.patch.object(RUNNER, "_full_shard_gid_problems", return_value=[]), \
                    mock.patch.object(RUNNER, "_full_shard_execute"), \
                    mock.patch.object(RUNNER, "_full_shard_cleanup", side_effect=TypeError("cleanup callback")), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = RUNNER.run_sharded_selection(root, RUNNER.Selection(full_suite=True), False, evidence)
            self.assertEqual(1, code)
            audit = json.loads((evidence / "audit.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", audit["status"])
            self.assertTrue(
                any("cleanup" in problem and "TypeError" in problem for problem in audit["problems"]),
                audit["problems"],
            )

    def test_audit_json_is_ascii_and_keeps_undecodable_path_text(self):
        # L2: problem text carries os.fsdecode() output; a non-UTF-8 file name decodes to
        # a lone surrogate, which a UTF-8 writer cannot encode.
        with tempfile.TemporaryDirectory(prefix="shard-ascii-") as directory:
            path = Path(directory) / "audit.json"
            value = {"problems": ["lane w0: untracked leftovers in the lane checkout: bad-\udcff-name"]}
            RUNNER._full_shard_write_json(path, value)
            text = path.read_bytes().decode("ascii")
            self.assertEqual(value, json.loads(text))

    def test_coordinator_git_ignores_inherited_git_environment(self):
        # L5: in a hook context GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE would redirect
        # `git -C <lane clone>` to another repository.
        with tempfile.TemporaryDirectory(prefix="shard-git-env-") as directory:
            base = Path(directory).resolve()
            lane, foreign = base / "lane", base / "foreign"
            clean = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            for repository in (lane, foreign):
                repository.mkdir()
                subprocess.run(
                    ["git", "init", "--quiet", str(repository)], env=clean, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                )
            hostile = {
                "GIT_DIR": str(foreign / ".git"), "GIT_WORK_TREE": str(foreign),
                "GIT_INDEX_FILE": str(foreign / ".git/index"),
            }
            with mock.patch.dict(os.environ, hostile):
                completed = RUNNER._full_shard_git(lane, "rev-parse", "--absolute-git-dir")
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(
                os.path.realpath(lane / ".git"),
                os.path.realpath(completed.stdout.decode("utf-8").strip()),
            )

    def test_lane_environment_drops_inherited_git_variables(self):
        # L5: a lane runs in its own clone; inherited repository-location variables
        # would point its tests at the main checkout.  The three config-source selectors
        # name no repository, index or work tree and keep hermetic callers (this suite's
        # own fixtures set GIT_CONFIG_NOSYSTEM/GIT_CONFIG_GLOBAL) independent of the
        # user's global excludes or fsmonitor settings.
        config_selectors = {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"}
        with tempfile.TemporaryDirectory(prefix="shard-lane-env-") as directory:
            base = Path(directory).resolve()
            lanes_dir = base / "lanes"
            lanes_dir.mkdir()
            lane = RUNNER._FullShardLane("w0", "A", base / "work", lanes_dir, base)
            lane.tmpdir = base / "lane-tmp"
            lane.pycache = base / "lane-pyc"
            captured = {}

            def fake_popen(argv, **kwargs):
                captured.update(kwargs)
                return mock.Mock(pid=0)

            hostile = {
                "GIT_DIR": "/nonexistent/foreign/.git", "GIT_INDEX_FILE": "/nonexistent/foreign/index",
                "GIT_WORK_TREE": "/nonexistent/foreign", "GIT_CONFIG_GLOBAL": os.devnull,
                "SHARD_ENV_SENTINEL": "kept",
            }
            with mock.patch.dict(os.environ, hostile), \
                    mock.patch.object(RUNNER.subprocess, "Popen", side_effect=fake_popen):
                launched = lane.launch("run", {"verbose": False, "indices": []})
            launched[1].close()
            environment = captured["env"]
            self.assertEqual(
                [], sorted(key for key in environment if key.startswith("GIT_") and key not in config_selectors),
            )
            self.assertEqual(os.devnull, environment["GIT_CONFIG_GLOBAL"])
            self.assertEqual("kept", environment["SHARD_ENV_SENTINEL"])
            self.assertEqual(str(lane.tmpdir), environment["TMPDIR"])
            self.assertEqual(str(lane.pycache), environment["PYTHONPYCACHEPREFIX"])

    def test_residue_gate_runs_ps_and_lsof_by_absolute_path(self):
        # L6: lsof lives in /usr/sbin, which an operator PATH may omit; a PATH lookup
        # failure made every sharded run fail closed.
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(list(argv))
            stdout = "" if len(calls) == 1 else f"p{os.getpid()}\nn/\n"
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        with mock.patch.object(RUNNER.subprocess, "run", side_effect=fake_run):
            self.assertEqual([], RUNNER._full_shard_residue(["/nonexistent/shard-lane"], []))
        self.assertEqual(["/bin/ps", "/usr/sbin/lsof"], [argv[0] for argv in calls])


class FullShardS0FixTests(unittest.TestCase):
    """S0 (first real sharded run, 2026-10-24) fixes of the opt-in sharded full mode.

    Expectations come from the S0 evidence and from the serial `--all` contract (what
    the serial path runs, re-reads and refuses), not from the runner implementation.
    """

    SKIP_ROWS_SPEC = (
        ("test_cases.test_a", [("A", ["test_1", "test_2"], False)]),
        ("test_cases.test_b", [("B", ["test_1"], False), ("S", ["test_1", "test_2"], True)]),
    )

    def test_lane_roots_must_be_outside_the_machine_shared_temporary_directories(self):
        # S0: every lane TMPDIR sat below /private/tmp.  The suite writes there directly
        # (test_load_release_transaction creates /tmp/http-rt-*.noindex in each
        # ReleaseTransactionTests.setUp) while other lanes run quiet-window checks that pin
        # the stat of every ancestor directory from "/" (11-load escrow, b-xlsx_to_dot
        # private workspace, monitor publication path).  Serial runs never overlap them.
        self.assertEqual(("/tmp", "/var/tmp"), RUNNER.FULL_SHARD_SHARED_TEMP_ROOTS)
        with tempfile.TemporaryDirectory(prefix="shard-shared-") as directory:
            base = Path(directory).resolve()
            shared, other, sibling = base / "shared", base / "other", base / "shared-sibling"
            for path in (shared, other, sibling):
                path.mkdir()
            alias = base / "alias"
            alias.symlink_to(shared)

            def problems(path):
                return RUNNER.full_shard_shared_temp_problems(
                    {"lane temporary parent": path}, shared_roots=(str(shared),),
                )

            for inside in (shared, shared / "lane", alias / "lane"):
                with self.subTest(inside=str(inside)):
                    found = problems(inside)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("machine-shared temporary directory", found[0])
                    self.assertIn("lane temporary parent", found[0])
            for outside in (other, other / "lane", sibling / "lane"):
                with self.subTest(outside=str(outside)):
                    self.assertEqual([], problems(outside))
            # Second review C3: on a case-insensitive volume another spelling of the same
            # directory is the same directory and must be refused as well.
            respelled = Path(str(shared).swapcase())
            if respelled.exists() and os.path.samefile(respelled, shared):
                found = problems(respelled / "lane")
                self.assertEqual(1, len(found), found)
        # The real defaults refuse anything below /tmp (on macOS the /private/tmp alias
        # target), judged by path whether or not it exists.
        found = RUNNER.full_shard_shared_temp_problems(
            {"evidence work directory": Path("/tmp/shard-s0-probe-never-created/work")},
        )
        self.assertEqual(1, len(found), found)
        self.assertIn("evidence work directory", found[0])

    def test_leftover_inventory_lists_counts_and_hashes_the_paths(self):
        # S0: ignored files and lane-TMPDIR entries are recorded per lane (list, count,
        # sha256 over the NUL-joined file-system bytes of the sorted list), not judged.
        inventory = RUNNER.full_shard_inventory(["outputs/b.txt", ".deployment.lock", "a/c"])
        self.assertEqual({
            "paths": [".deployment.lock", "a/c", "outputs/b.txt"],
            "count": 3,
            "sha256": hashlib.sha256(b".deployment.lock\0a/c\0outputs/b.txt").hexdigest(),
        }, inventory)
        self.assertEqual(
            {"paths": [], "count": 0, "sha256": hashlib.sha256(b"").hexdigest()},
            RUNNER.full_shard_inventory([]),
        )
        undecodable = RUNNER.full_shard_inventory(["bad-\udcff-name"])
        self.assertEqual(hashlib.sha256(b"bad-\xff-name").hexdigest(), undecodable["sha256"])

    def test_plan_leftover_allowlist_is_reviewed_patterns_with_reasons(self):
        # S0 review: a lane cannot see another lane's ignored files, while serial --all
        # shows every later test the ignored files of earlier tests.  Only shapes reviewed
        # as unobservable by other tests may change a lane checkout's ignored set without
        # refusing the proof.  The key is optional; absent, every change refuses it.
        RUNNER.validate_full_shard_plan(shard_plan())
        RUNNER.validate_full_shard_plan(shard_plan(leftover_allowlist={
            ".deployment.lock": "lock file, never read for content",
            "outputs/test-diagnostics/collector-prefix-feedback-*": "retained fixture",
        }))
        for label, value in (
            ("list", [".deployment.lock"]),
            ("absolute", {"/tmp/x": "r"}),
            ("parent component", {"outputs/../x": "r"}),
            ("empty pattern", {"": "r"}),
            ("blank reason", {"x.lock": " "}),
            ("non-string reason", {"x.lock": 1}),
            # Second review A5b: the first component must be literal, never a catch-all.
            ("match everything", {"*": "r"}),
            ("wildcard first component", {"*/x": "r"}),
            ("character class first component", {"[o]utputs/x": "r"}),
            ("single-character wildcard", {"?utputs/x": "r"}),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(RUNNER.ImpactError, "full shard plan: leftover_allowlist"):
                    RUNNER.validate_full_shard_plan(shard_plan(leftover_allowlist=value))

    def test_unreviewed_leftovers_are_the_paths_no_allowlist_pattern_matches(self):
        allowlist = {
            ".deployment.lock": "r",
            "outputs/test-diagnostics/collector-prefix-feedback-*": "r",
        }
        self.assertEqual(
            ["DAY0-Prepare/x.py", "outputs/test-diagnostics/download-parent-red-ab12cd34/http/13-unload.py"],
            RUNNER.full_shard_unreviewed_leftovers([
                ".deployment.lock",
                "outputs/test-diagnostics/collector-prefix-feedback-65y3krn9/bin/ssh",
                "outputs/test-diagnostics/download-parent-red-ab12cd34/http/13-unload.py",
                "DAY0-Prepare/x.py",
            ], allowlist),
        )
        self.assertEqual([".Deployment.lock"], RUNNER.full_shard_unreviewed_leftovers([".Deployment.lock"], allowlist))
        self.assertEqual(["a"], RUNNER.full_shard_unreviewed_leftovers(["a"], {}))
        # Second review A5a, scoped by F6 (integration, after batch A): a file of a shape the
        # suite's whole-checkout traversals or the serial source discovery read (*.py, *.sh,
        # *.cgi, *.service, *.timer, 02-AIR-devices_config.csv) is never accepted outside the
        # runner's non-source roots, even inside a reviewed tree.
        names = ("a.py", "test_b.py", "c.sh", "d.cgi", "e.service", "f.timer", "deep/02-AIR-devices_config.csv")
        source_tree = "DAY0-Prepare/scratch-65y3krn9/"
        observed = [source_tree + name for name in names]
        self.assertEqual(
            sorted(observed),
            RUNNER.full_shard_unreviewed_leftovers(
                [*observed, source_tree + "kept.csv"], {"DAY0-Prepare/scratch-*": "r"},
            ),
        )
        self.assertEqual(
            ["monitor/x/a.py"], RUNNER.full_shard_unreviewed_leftovers(["monitor/x/a.py"], {"monitor/x/*": "r"}),
        )
        # Inside the non-source roots (outputs/, .codex*, .agents: the serial source discovery
        # skips them and, after batch A, no test-side whole-checkout walk enters them) a
        # reviewed pattern accepts those shapes too ...
        tree = "outputs/test-diagnostics/collector-prefix-feedback-65y3krn9/"
        under_outputs = [tree + name for name in names]
        self.assertEqual(
            [], RUNNER.full_shard_unreviewed_leftovers([*under_outputs, tree + "kept.csv", tree + "bin/ssh"], allowlist),
        )
        for root in (".codex_tmp-ab12/", ".codex/", ".agents/"):
            with self.subTest(root=root):
                self.assertEqual(
                    [], RUNNER.full_shard_unreviewed_leftovers([root + "x/a.py"], {root + "x/*": "r"}),
                )
        # ... but only a reviewed one: an unmatched path there stays unreviewed.
        self.assertEqual(
            ["outputs/elsewhere/a.py"], RUNNER.full_shard_unreviewed_leftovers(["outputs/elsewhere/a.py"], allowlist),
        )

    def test_real_plan_reviews_no_leftover_shape_on_dev(self):
        # DEV re-derivation (v3.1.0 step 3, 2026-11-06).  TEST reviewed two retained fixture
        # trees under outputs/test-diagnostics because, after its batch A, no test-side
        # whole-checkout walk entered outputs/.  DEV has no test that writes
        # outputs/test-diagnostics (static census: only the runner and its own tests name it)
        # and no batch A (governed_tree_paths), so the DEV plan reviews nothing: every ignored
        # leftover a lane leaves fails the run until a diagnostic sharded run shows the actual
        # DEV shapes and they are reviewed one by one.  The two lock files stay unreviewed, as
        # on TEST: a sharded run needs them to exist in the main checkout beforehand.
        plan = RUNNER.load_full_shard_plan(ROOT)
        self.assertEqual({}, plan.get("leftover_allowlist"))
        leftovers = [
            ".deployment.lock",
            "monitor/.generate-monitor-html.lock",
            "outputs/test-diagnostics/download-parent-red-26amxbnl/http/DAY0-Prepare/13-unload.py",
            "outputs/test-diagnostics/collector-prefix-feedback-65y3krn9/bin/ssh",
        ]
        self.assertEqual(sorted(leftovers), RUNNER.full_shard_unreviewed_leftovers(leftovers, {}))

    def test_serial_post_run_check_of_a_checkout_restores_sys_path(self):
        # Second review E1: the post-run check executes the checkout's deployment
        # selectors in the coordinator; infra/docker/activate.py inserts its own
        # directories into sys.path at import.  The check must leave sys.path as it was
        # and return exactly the serial cycle's snapshot of that checkout.
        before = list(sys.path)
        checked = RUNNER._full_shard_serial_check(ROOT, ROOT, MANIFEST_PATH)
        self.assertEqual(before, sys.path)
        expected = RUNNER.snapshot_as_json(RUNNER.make_snapshot(
            ROOT, MANIFEST_PATH, RUNNER.load_and_validate_manifest(ROOT, MANIFEST_PATH),
        ))
        self.assertEqual(expected, checked)

    def test_leftover_gate_turns_unexpected_errors_into_problems(self):
        # Second review E2: an unexpected exception in a lane gate must become a recorded
        # problem, never escape and skip the residue gate of the phase.
        with tempfile.TemporaryDirectory(prefix="shard-gate-error-") as directory:
            base = Path(directory).resolve()
            (base / "lanes").mkdir()
            lane = RUNNER._FullShardLane("w0", "A", base / "work", base / "lanes", base)
            lane.tmpdir = base / "lane-tmp"
            lane.tmpdir.mkdir()
            with mock.patch.object(RUNNER, "_full_shard_tracked_digest", side_effect=RuntimeError("fixture boom")):
                gate, proof_only, inventory = lane.leftover_gate({})
            self.assertTrue(any("fixture boom" in problem for problem in gate), gate)
            self.assertEqual([], proof_only)
            self.assertEqual(0, inventory["tmpdir"]["count"])

    def records(self, rows, outcomes, *, successful, finished=True, holders=()):
        records = [{"event": "start", "canonical_sha256": "c" * 64, "count": len(rows),
                    **RUNNER.full_shard_lane_identity()}]
        for index, outcome in outcomes:
            records.append({"event": "test", "index": index, "id": rows[index]["id"],
                            "outcome": outcome, "seconds": 0.01})
        records.extend(holders)
        if finished:
            records.append({"event": "finished", "tests_run": len(outcomes), "successful": successful})
        return records

    def merge(self, rows, assigned, records, exit_code, *, deadline=False):
        return RUNNER.merge_full_shard_lane(
            "w1", rows, assigned, records,
            {"exit": exit_code, "seconds": 1.0, "deadline_exceeded": deadline},
            identity=RUNNER.full_shard_lane_identity(), canonical_sha256="c" * 64,
        )

    def test_merge_separates_isolation_and_coverage_problems_from_test_outcomes(self):
        # S0: serial --all runs every test even after a failure.  A lane whose only
        # problems are test outcomes (consistent records, exit 1) reports no gate
        # problem, so the quiet phase still runs; the run still fails without a proof.
        rows = shard_rows(self.SKIP_ROWS_SPEC)
        assigned = [0, 1, 2, 3, 4]
        everything = [(index, "success") for index in assigned]
        failed = self.merge(rows, assigned, self.records(
            rows, [(0, "success"), (1, "failure"), (2, "error"), (3, "success"), (4, "success")],
            successful=False,
        ), 1)
        self.assertTrue(failed["problems"])
        self.assertEqual([], failed["gate_problems"])
        # A setUpClass error: serial unittest does not run that class's tests either.
        holder = {"event": "holder", "kind": "error", "description": "setUpClass (test_cases.test_b.S)"}
        errored = self.merge(rows, assigned, self.records(
            rows, [(0, "success"), (1, "success"), (2, "success")], successful=False, holders=[holder],
        ), 1)
        self.assertTrue(any("fixture error" in problem for problem in errored["problems"]))
        self.assertEqual([], errored["gate_problems"])
        self.assertEqual([3, 4], errored["errored"])
        self.assertEqual([], RUNNER.full_shard_coverage_problems(5, {"w1": errored}))
        gate_cases = {
            "crash": (self.records(rows, everything[:2], successful=False, finished=False), -9, {}),
            "exit 1 with a successful finished record": (
                self.records(rows, everything, successful=True), 1, {}),
            "failure with a successful finished record": (
                self.records(rows, [(0, "failure"), *everything[1:]], successful=True), 1, {}),
            "exit 0 with an unsuccessful finished record": (
                self.records(rows, [(0, "failure"), *everything[1:]], successful=False), 0, {}),
            "rows not executed": (self.records(rows, everything[:3], successful=True), 0, {}),
            "error holder explains other rows only": (
                self.records(rows, everything[:2], successful=False, holders=[holder]), 1, {}),
            "deadline": (self.records(rows, everything, successful=True), -15, {"deadline": True}),
            "fatal": (self.records(rows, [], successful=False, finished=False)
                      + [{"event": "fatal", "reason": "x"}], 3, {}),
            "duplicate": (self.records(rows, [*everything, (0, "success")], successful=True), 0, {}),
        }
        for label, (records, exit_code, extra) in gate_cases.items():
            with self.subTest(label=label):
                merged = self.merge(rows, assigned, records, exit_code, **extra)
                self.assertTrue(merged["gate_problems"], merged["problems"])
                self.assertTrue(set(merged["gate_problems"]) <= set(merged["problems"]))

    def test_ancestor_chain_and_drift_name_each_changed_directory(self):
        # S0 attribution: the audit records which ancestor of the lane temporary parent and
        # of the lane work directory changed while a phase ran (it is not a gate).
        with tempfile.TemporaryDirectory(prefix="shard-chain-") as directory:
            top = Path(directory).resolve() / "top"
            leaf = top / "leaf"
            leaf.mkdir(parents=True)
            chain = RUNNER.full_shard_chain(leaf)
            self.assertEqual([str(path) for path in [*reversed(leaf.parents), leaf]],
                             [path for path, _nine in chain])
            self.assertEqual("/", chain[0][0])
            self.assertTrue(all(isinstance(nine, list) and len(nine) == 9 for _path, nine in chain))
            before = RUNNER.full_shard_chain(leaf)
            (top / "sibling").mkdir()
            after = RUNNER.full_shard_chain(leaf)
            drifted = {item["path"] for item in RUNNER.full_shard_chain_drift(before, after)}
            self.assertIn(str(top), drifted)
            self.assertNotIn(str(leaf), drifted)
        self.assertEqual(
            [{"path": "/a", "before": [2], "after": [3]}, {"path": "/a/b", "before": None, "after": [4]}],
            RUNNER.full_shard_chain_drift(
                [["/", [1]], ["/a", [2]]], [["/", [1]], ["/a", [3]], ["/a/b", [4]]],
            ),
        )

    def test_lane_wait_records_epochs_and_wall_seconds(self):
        import time as time_module
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", "pass"], start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(process.wait)
        log = open(os.devnull, "wb")
        self.addCleanup(log.close)
        finished = RUNNER._full_shard_wait_lanes(
            {"w0": (process, log, time_module.monotonic(), round(time_module.time(), 3))}, 9000, poll=0.05,
        )
        info = finished["w0"]
        self.assertEqual(0, info["exit"])
        self.assertEqual(info["seconds"], info["wall_seconds"])
        self.assertGreaterEqual(info["wall_seconds"], 0)
        self.assertLessEqual(info["started_epoch"], info["ended_epoch"])

    def test_one_cycle_hands_its_manifest_path_to_the_sharded_run(self):
        # Each lane checkout must pass the serial post-run check (manifest re-validation
        # and snapshot), which needs the manifest path the serial cycle reads (--manifest).
        with tempfile.TemporaryDirectory(prefix="shard-manifest-") as directory:
            base = Path(directory).resolve()
            args = RUNNER.parser().parse_args([
                "--approvals", str(base / "approvals.json"), "--all", "--sharded", str(base / "evidence"),
            ])
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                    mock.patch.object(RUNNER, "run_sharded_selection", return_value=1) as run:
                self.assertEqual(1, RUNNER._one_cycle(args)[0])
            self.assertEqual(base / "evidence", run.call_args.args[3])
            self.assertEqual(MANIFEST_PATH, run.call_args.kwargs["manifest_path"])
            self.assertFalse((base / "approvals.json").exists())


if __name__ == "__main__":
    unittest.main()
