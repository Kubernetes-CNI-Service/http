"""REQ-10-B B10-5: real setup mapping and unsetup cleanup on a temporary project."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_req10b_services_keys_workflow import public_key


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("req10b_global_link_setup_flow", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_script("req10b_global_link_unsetup_flow", ROOT / "DAY0-Prepare/02-unsetup.py")
INITIAL = load_script("req10b_global_link_initial_setup_flow", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")

GLOBAL_MAPPING = ("infiniband/01-global.yaml", "01-global.yaml", "file")
GLOBAL_BYTES = b"system:\n  timezone: Etc/UTC\n"
DEVICES_BYTES = b"hostname,ip\nleaf-01,192.0.2.10\n"
EXPECTED_WORKSPACE_LINKS = (
    ("infra/01-global.yaml", "01-global.yaml", GLOBAL_BYTES),
    ("infra/02-devices_config.csv", "02-devices_config.csv", DEVICES_BYTES),
    ("monitor/01-global.yaml", "01-global.yaml", GLOBAL_BYTES),
    ("infiniband/01-global.yaml", "01-global.yaml", GLOBAL_BYTES),
)


class Req10BGlobalLinkWorkflowTests(unittest.TestCase):
    def test_public_key_transaction_failure_restores_both_roots_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "laptop.pub").write_text(public_key(29, "site-a"), encoding="utf-8")
            roots = (root / "ztp/config/publickey", root / "infiniband/publickey")
            stale = []
            active = []
            for key_root in roots:
                key_root.mkdir(parents=True)
                old = key_root / "stale.pub"
                old.symlink_to("../../DAY0-Prepare/old-site/stale.pub")
                stale.append(old)
                active.append(key_root / "laptop.pub")
            manifest = root / "ztp/.setup_manifest"
            manifest.write_bytes(b"original manifest\n")
            with mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"), MANIFEST_FILE=str(manifest),
                _DRY_RUN=False, _LINK_ERRORS=0,
            ):
                all_paths = SETUP._setup_transaction_paths(str(project))
                for path in (*stale, *active):
                    self.assertIn(str(path), all_paths)
                transaction = SETUP._SetupLinkTransaction([str(p) for p in (*stale, *active)])
                original_make_link = SETUP._make_link

                def fail_second_root(link_path: str, target_path: str) -> str:
                    if link_path == str(active[1]):
                        raise RuntimeError("injected IB publication failure")
                    return original_make_link(link_path, target_path)

                with mock.patch.object(SETUP, "_make_link", side_effect=fail_second_root):
                    with redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(RuntimeError, "injected IB publication failure"):
                            SETUP._process_pubkeys(str(project))
                self.assertTrue(active[0].is_symlink(), "ZTP link must exist before failure")
                manifest.write_bytes(b"interrupted manifest\n")
                with redirect_stdout(io.StringIO()):
                    transaction.rollback()

            self.assertEqual(b"original manifest\n", manifest.read_bytes())
            for old, new in zip(stale, active):
                with self.subTest(root=str(old.parent)):
                    self.assertTrue(old.is_symlink())
                    self.assertEqual("../../DAY0-Prepare/old-site/stale.pub", os.readlink(old))
                    self.assertFalse(new.is_symlink())
            self.assertTrue((project / "laptop.pub").is_file())

    def test_real_setup_p1_key_profile_then_unsetup_cleans_both_publication_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_bytes(GLOBAL_BYTES)
            (project / "02-devices_config.csv").write_bytes(DEVICES_BYTES)
            p2p = project / "p2p.xlsx"
            p2p.write_bytes(b"fixture")
            line = public_key(23, "site-a-laptop")
            (project / "laptop.pub").write_text(line, encoding="utf-8")
            (root / "infra").mkdir()
            tool = root / "infiniband/bringup/xdr-initial-setup"
            tool.mkdir(parents=True)
            (tool / "publickey").symlink_to("../../publickey")

            # Keep unrelated stages inert. The real setup mapping loop and
            # _process_pubkeys must run before the real P1 profile reader.
            unrelated_stages = (
                "_initialize_project_from_template", "_prepare_laptop_public_key",
                "_remove_legacy_nvos_output_links", "_process_bin_files",
                "_process_xlsx_files", "_process_bringup_links",
                "_process_analyzer_links", "_process_latest_yaml",
                "_process_optimize_sample", "_process_net_csv_links",
                "_process_monitor_links", "_write_manifest", "_print_next_steps",
            )
            with ExitStack() as patches:
                patches.enter_context(mock.patch.multiple(
                    SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                    ZTP=str(root / "ztp"),
                    MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
                    MAPPINGS=[], _CSV_DIR=None, _DRY_RUN=False,
                    _P2P_SOURCE=None, _LINK_TRANSACTION=None,
                ))
                for name in unrelated_stages:
                    patches.enter_context(mock.patch.object(SETUP, name))
                for name, result in (
                    ("_select_p2p_source", str(p2p)),
                    ("_validate_project", True),
                    ("_ensure_project_p2p_link", str(p2p)),
                    ("_unsetup_previous", True),
                    ("_check_conflicts", True),
                    ("_setup_transaction_paths", [str(root / row[0]) for row in EXPECTED_WORKSPACE_LINKS]),
                ):
                    patches.enter_context(mock.patch.object(SETUP, name, return_value=result))
                with redirect_stdout(io.StringIO()):
                    SETUP._setup_impl(str(project))

            profile = INITIAL._public_key_profile(tool)
            with mock.patch.multiple(
                UNSETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"),
                MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
                _AUTO_YES=True, _DRY_RUN=False,
            ), redirect_stdout(io.StringIO()):
                unsetup_result = UNSETUP._main_locked(SimpleNamespace(project=None))

            self.assertEqual([line.strip()], [entry["line"] for entry in profile])
            self.assertEqual(0, unsetup_result)
            self.assertEqual(line, (project / "laptop.pub").read_text(encoding="utf-8"))
            self.assertFalse((root / "ztp/config/publickey/laptop.pub").is_symlink())
            self.assertFalse((root / "infiniband/publickey/laptop.pub").is_symlink())

    def test_real_setup_impl_links_all_workspace_inputs_and_resolves_bringup_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_bytes(GLOBAL_BYTES)
            (project / "02-devices_config.csv").write_bytes(DEVICES_BYTES)
            p2p = project / "p2p.xlsx"
            p2p.write_bytes(b"fixture")
            bridge = root / "infiniband/bringup/xdr-initial-setup/01-global.yaml"
            bridge.parent.mkdir(parents=True)
            bridge.symlink_to("../../01-global.yaml")

            # Keep unrelated setup stages inert while the actual _setup_impl
            # mapping loop, _process_mapping, and _make_link run together.
            unrelated_stages = (
                "_initialize_project_from_template", "_prepare_laptop_public_key",
                "_remove_legacy_nvos_output_links", "_process_bin_files",
                "_process_xlsx_files", "_process_bringup_links",
                "_process_analyzer_links", "_process_pubkeys",
                "_process_latest_yaml", "_process_optimize_sample",
                "_process_net_csv_links", "_process_monitor_links",
                "_write_manifest", "_print_next_steps",
            )
            with ExitStack() as patches:
                patches.enter_context(mock.patch.multiple(
                    SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                    ZTP=str(root / "ztp"),
                    MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
                    MAPPINGS=[], _CSV_DIR=None, _DRY_RUN=False,
                    _P2P_SOURCE=None, _LINK_TRANSACTION=None,
                ))
                for name in unrelated_stages:
                    patches.enter_context(mock.patch.object(SETUP, name))
                patches.enter_context(mock.patch.object(
                    SETUP, "_select_p2p_source", return_value=str(p2p)
                ))
                patches.enter_context(mock.patch.object(
                    SETUP, "_validate_project", return_value=True
                ))
                patches.enter_context(mock.patch.object(
                    SETUP, "_ensure_project_p2p_link", return_value=str(p2p)
                ))
                patches.enter_context(mock.patch.object(
                    SETUP, "_unsetup_previous", return_value=True
                ))
                patches.enter_context(mock.patch.object(
                    SETUP, "_check_conflicts", return_value=True
                ))
                patches.enter_context(mock.patch.object(
                    SETUP, "_setup_transaction_paths",
                    return_value=[str(root / row[0]) for row in EXPECTED_WORKSPACE_LINKS],
                ))
                with redirect_stdout(io.StringIO()):
                    SETUP._setup_impl(str(project))

            for workspace_rel, project_rel, expected_bytes in EXPECTED_WORKSPACE_LINKS:
                managed = root / workspace_rel
                source = project / project_rel
                with self.subTest(workspace_rel=workspace_rel):
                    self.assertTrue(managed.is_symlink(), workspace_rel)
                    self.assertEqual(
                        os.path.relpath(source, managed.parent), os.readlink(managed)
                    )
                    self.assertEqual(expected_bytes, managed.read_bytes())
            self.assertTrue(bridge.is_symlink())
            self.assertEqual("../../01-global.yaml", os.readlink(bridge))
            self.assertEqual((project / "01-global.yaml").resolve(), bridge.resolve())
            self.assertEqual(GLOBAL_BYTES, bridge.read_bytes())

    def test_setup_publishes_project_global_through_registered_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_bytes(GLOBAL_BYTES)
            managed = root / "infiniband/01-global.yaml"
            matches = [entry for entry in SETUP.WORKSPACE_INPUT_MAPPINGS
                       if entry[0] == GLOBAL_MAPPING[0]]
            with mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"), _DRY_RUN=False,
            ), redirect_stdout(io.StringIO()):
                results = [
                    SETUP._process_mapping(str(project), *entry, link_root=str(root))
                    for entry in matches
                ]
            self.assertEqual(["linked"], results)
            self.assertTrue(managed.is_symlink())
            self.assertEqual("../DAY0-Prepare/site-a/01-global.yaml", os.readlink(managed))
            self.assertEqual(GLOBAL_BYTES, managed.read_bytes())

    def test_real_setup_mapping_then_unsetup_fallback_preserves_project_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            project_global = project / "01-global.yaml"
            project_global.write_bytes(GLOBAL_BYTES)
            managed = root / "infiniband/01-global.yaml"
            retained = root / "infiniband/operator-owned.txt"
            retained.parent.mkdir(parents=True)
            retained.write_bytes(b"do not remove\n")
            # A real checkout has an infra/ directory for the independent
            # log-root lock; keep that safety gate active in this fixture.
            (root / "infra").mkdir()
            with mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"), _DRY_RUN=False,
            ), redirect_stdout(io.StringIO()):
                self.assertEqual(
                    "linked",
                    SETUP._process_mapping(
                        str(project), *GLOBAL_MAPPING, link_root=str(root)
                    ),
                )
            self.assertTrue(managed.is_symlink())
            with mock.patch.multiple(
                UNSETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"),
                MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
                _AUTO_YES=True, _DRY_RUN=False,
            ), redirect_stdout(io.StringIO()):
                result = UNSETUP._main_locked(SimpleNamespace(project=None))
            self.assertFalse(managed.is_symlink())
            self.assertEqual(0, result)
            self.assertEqual(GLOBAL_BYTES, project_global.read_bytes())
            self.assertEqual(b"do not remove\n", retained.read_bytes())


if __name__ == "__main__":
    unittest.main()
