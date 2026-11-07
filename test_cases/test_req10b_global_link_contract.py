"""REQ-10-B B10-5: the project global input has two managed link levels."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("req10b_global_link_setup_direct", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_script("req10b_global_link_unsetup_direct", ROOT / "DAY0-Prepare/02-unsetup.py")
CONTRACT = load_script("req10b_global_link_project_contract", ROOT / "tools/project_contract.py")

GLOBAL_MAPPING = ("infiniband/01-global.yaml", "01-global.yaml", "file")
BRIDGE_RELATIVE_TARGET = "../../01-global.yaml"
EXPECTED_WORKSPACE_INPUTS = {
    ("infra/01-global.yaml", "01-global.yaml", "file"),
    ("infra/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("infra/logs", "99-output-infra", "dir"),
    ("monitor/01-global.yaml", "01-global.yaml", "file"),
    GLOBAL_MAPPING,
    # IBSW 2.25 (4693d8d): upgrade.py reads 01-global.yaml next to itself.
    ("infiniband/bringup/xdr-upgrade/01-global.yaml", "01-global.yaml", "file"),
}


class Req10BGlobalLinkContractTests(unittest.TestCase):
    def test_ib_public_key_foreign_link_and_regular_file_are_not_silently_replaced(self) -> None:
        # Contract changed by R-014 第 1 条 (v3.1.1 WP-2; O4 left column, owner 2026-11-02 「如果发现需要创建的
        # 链接已经存在，那么可以先解开再创建」, 2026-11-03 「只有不存在或者链接文件指向了别的地方才改正」):
        # the cross-project switch of the whole set keeps its explicit confirmation (R-014 第 1 条, owner
        # 2026-11-02), but setup itself replaces a managed link that points elsewhere without a prompt and
        # reports old -> new, so it is never silent; a real file is reported, counted and never replaced (kept).
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            foreign_project = root / "DAY0-Prepare/site-b"
            project.mkdir(parents=True)
            foreign_project.mkdir(parents=True)
            (project / "laptop.pub").write_bytes(b"ssh-ed25519 project-key laptop\n")
            (foreign_project / "laptop.pub").write_bytes(b"foreign-key\n")
            ib_key = root / "infiniband/publickey/laptop.pub"
            ib_key.parent.mkdir(parents=True)
            ib_key.symlink_to(foreign_project / "laptop.pub")
            # R-016 R16-13 (v3.1.1 WP-3): key links are refreshed after the switch, through the pointer.
            (root / "DAY0-Prepare/activate-project").symlink_to(project.name)
            with mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"),
                ZTP=str(root / "ztp"), _AUTO_YES=False,
                _CONFIRM_PROJECT_SWITCH=False, _DRY_RUN=False,
            ):
                self.assertIn(str(ib_key), SETUP._collect_expected_links(str(project)))
                with mock.patch.object(SETUP, "_collect_expected_links", return_value=[str(ib_key)]), \
                        mock.patch.object(SETUP, "_authorize_project_switch", return_value=False):
                    with redirect_stdout(io.StringIO()):
                        self.assertFalse(SETUP._check_conflicts(str(project)))
                self.assertTrue(ib_key.is_symlink())
                self.assertEqual((foreign_project / "laptop.pub").resolve(), ib_key.resolve())

                old_text = os.readlink(ib_key)
                output = io.StringIO()
                with mock.patch.object(SETUP, "_LINK_ERRORS", 0), mock.patch(
                    "builtins.input", side_effect=AssertionError("R-014 第 1 条: no prompt"),
                ):
                    with redirect_stdout(output):
                        SETUP._process_pubkeys(str(project))
                    self.assertEqual(0, SETUP._LINK_ERRORS)
                self.assertTrue(ib_key.is_symlink())
                self.assertEqual((project / "laptop.pub").resolve(), ib_key.resolve())
                self.assertIn(old_text, output.getvalue(), "the replacement names the old target")
                self.assertIn(os.readlink(ib_key), output.getvalue(), "and the new one")

                ib_key.unlink()
                ib_key.write_bytes(b"operator-owned key\n")
                with mock.patch.object(SETUP, "_LINK_ERRORS", 0):
                    with redirect_stdout(io.StringIO()):
                        SETUP._process_pubkeys(str(project))
                    self.assertEqual(1, SETUP._LINK_ERRORS)
                self.assertFalse(ib_key.is_symlink())
                self.assertEqual(b"operator-owned key\n", ib_key.read_bytes())

    def test_project_public_keys_publish_to_both_managed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "laptop.pub").write_bytes(b"ssh-ed25519 project-key laptop\n")
            (project / "empty.pub").write_bytes(b"")
            # R-016 R16-13 (v3.1.1 WP-3): key links are refreshed after the switch, through the pointer.
            (root / "DAY0-Prepare/activate-project").symlink_to(project.name)
            roots = (root / "ztp/config/publickey", root / "infiniband/publickey")
            for key_root in roots:
                key_root.mkdir(parents=True)
                (key_root / "stale.pub").symlink_to(project / "stale.pub")
                (key_root / "operator.pub").write_bytes(b"operator-owned\n")
            with mock.patch.multiple(
                SETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp"), _DRY_RUN=False,
            ), redirect_stdout(io.StringIO()):
                SETUP._process_pubkeys(str(project))
            for key_root in roots:
                with self.subTest(key_root=str(key_root)):
                    self.assertTrue((key_root / "laptop.pub").is_symlink())
                    self.assertEqual((project / "laptop.pub").resolve(),
                                     (key_root / "laptop.pub").resolve())
                    self.assertFalse((key_root / "stale.pub").is_symlink())
                    self.assertFalse((key_root / "empty.pub").exists())
                    self.assertEqual(b"operator-owned\n",
                                     (key_root / "operator.pub").read_bytes())

    def test_bringup_publickey_bridge_is_tracked_relative_symlink(self) -> None:
        bridge = ROOT / "infiniband/bringup/xdr-initial-setup/publickey"
        self.assertTrue(bridge.is_symlink(), f"missing tracked public-key bridge: {bridge}")
        self.assertEqual("../../publickey", os.readlink(bridge))
        indexed = subprocess.run(
            ["git", "ls-files", "--stage", "--", str(bridge.relative_to(ROOT))],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertTrue(indexed.startswith("120000 "), "public-key bridge must be tracked")

    def test_setup_registers_the_project_global_input(self) -> None:
        self.assertIn(GLOBAL_MAPPING, CONTRACT.SETUP_WORKSPACE_INPUT_MAPPINGS)
        self.assertIn(GLOBAL_MAPPING, SETUP.WORKSPACE_INPUT_MAPPINGS)

    def test_setup_and_unsetup_workspace_input_tables_have_exact_membership(self) -> None:
        self.assertEqual(EXPECTED_WORKSPACE_INPUTS, set(CONTRACT.SETUP_WORKSPACE_INPUT_MAPPINGS))
        self.assertEqual(EXPECTED_WORKSPACE_INPUTS, set(SETUP.WORKSPACE_INPUT_MAPPINGS))
        # Contract changed by G12 and O14 (v3.1.1 WP-6; O4 right column, owner 2026-11-07 「同意你的建议。」 via
        # http dev): unsetup's fallback is derived from the link table plus the legacy names, no longer a
        # literal list holding the workspace inputs.  The inputs are fixed links that unsetup keeps (Q7).
        legacy = {
            "ztp/config/nvos/template/99-output-ib", "ztp/config/nvos/template/99-output-nvl",
            "ztp/config/nvos/template/99-output-published", "ztp/config/cumulus/template/AIR/output-p2p",
            # The fifth legacy name: WP-8 待决 1, settled by http dev 2026-11-08.
            "monitor/99-output-ufm",
        }
        dynamic = {pattern.replace("*-sample/*", "site-a-sample/01-global.yaml").replace("*", "laptop")
                   for pattern in CONTRACT.setup_dynamic_link_patterns()}
        inputs = {row[0] for row in EXPECTED_WORKSPACE_INPUTS}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in sorted(legacy | dynamic | inputs):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).symlink_to("synthetic-target")
            with mock.patch.multiple(UNSETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp")):
                found = UNSETUP._known_ztp_project_links() + UNSETUP._known_workspace_links()
            fallback = {os.path.relpath(path, root) for path in found}
        self.assertEqual(legacy | dynamic, fallback)
        self.assertEqual(set(), inputs & fallback)

    def test_bringup_bridge_is_a_tracked_relative_symlink(self) -> None:
        bridge = ROOT / "infiniband/bringup/xdr-initial-setup/01-global.yaml"
        self.assertTrue(bridge.is_symlink(), f"missing tracked input bridge: {bridge}")
        self.assertEqual(BRIDGE_RELATIVE_TARGET, os.readlink(bridge))
        self.assertEqual(
            os.path.normpath(os.path.join(bridge.parent, BRIDGE_RELATIVE_TARGET)),
            str(ROOT / GLOBAL_MAPPING[0]),
        )
        indexed = subprocess.run(
            ["git", "ls-files", "--stage", "--", str(bridge.relative_to(ROOT))],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertTrue(indexed.startswith("120000 "), "bridge must be tracked as a Git symlink")

    def test_unsetup_fallback_names_the_managed_global_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_global = root / "DAY0-Prepare/site-a/01-global.yaml"
            project_global.parent.mkdir(parents=True)
            project_global.write_bytes(b"project-global\n")
            managed = root / "infiniband/01-global.yaml"
            managed.parent.mkdir(parents=True)
            managed.symlink_to(project_global)
            with mock.patch.multiple(
                UNSETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp")
            ):
                # Contract changed by Q7 (R-016 §13, owner 2026-11-03 「好的」) and O14 (owner 2026-11-07
                # 「同意你的建议。」 via http dev): the managed global link is a fixed link unsetup keeps.
                self.assertNotIn(str(managed), UNSETUP._known_workspace_links())
                self.assertNotIn(str(managed), UNSETUP._known_ztp_project_links())

    def test_real_latest_entry_is_reported_counted_and_left_untouched(self) -> None:
        # Owner 2026-11-03 (需求文档 :925, rule :933; R-014 :834): when a link
        # setup must create meets a same-named real file or directory, setup
        # reports an error, does not stop, and neither replaces nor deletes it.
        def snapshot(path: Path):
            # Total over every outcome, so a deleted, renamed or replaced
            # entry fails the equality assertion instead of the helper.
            if not os.path.lexists(path):
                return None
            info = os.lstat(path)
            if path.is_symlink():
                content = os.readlink(path)
            elif path.is_dir():
                content = {
                    item.relative_to(path).as_posix(): item.read_bytes()
                    for item in sorted(path.rglob("*")) if item.is_file()
                }
            else:
                content = path.read_bytes()
            return info.st_dev, info.st_ino, path.is_symlink(), path.is_dir(), content

        cases = (
            ("directory", True), ("file", True),
            # Nothing to publish: the entry still is never deleted.
            ("directory", False),
        )
        for kind, published in cases:
            with self.subTest(kind=kind, published=published), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "DAY0-Prepare/site-a"
                ztp = root / "ztp"
                eth_output = project / "99-output-eth"
                eth_output.mkdir(parents=True)
                if published:
                    release = eth_output / "20260101_000000_combine"
                    release.mkdir()
                    (release / ".published-complete").write_bytes(b"complete\n")
                    (release / "leaf01.yaml").write_bytes(b"hostname: leaf01\n")
                occupied = eth_output / "latest"
                if kind == "directory":
                    # An operator copy identical to the release: exactly the
                    # case a rename-and-adopt implementation would take over.
                    occupied.mkdir()
                    (occupied / ".published-complete").write_bytes(b"complete\n")
                    (occupied / "leaf01.yaml").write_bytes(b"hostname: leaf01\n")
                else:
                    occupied.write_bytes(b"operator-owned latest\n")
                nvos_output = project / "99-output-ib_nvl"
                nvos_release = nvos_output / "20260101_000000-combine"
                nvos_release.mkdir(parents=True)
                (nvos_release / ".published-complete").write_bytes(b"complete\n")
                for platform, name, target in (
                    ("cumulus", "99-output", eth_output),
                    ("nvos", "99-output-ib_nvl", nvos_output),
                ):
                    alias = ztp / "config" / platform / "template" / name
                    alias.parent.mkdir(parents=True)
                    alias.symlink_to(target)
                before = snapshot(occupied)
                members = sorted(item.name for item in eth_output.iterdir())
                output = io.StringIO()
                with mock.patch.multiple(
                    SETUP, HTTP_BASE=str(root), ZTP=str(ztp),
                    LATEST_YAML_SPECS=(("cumulus", "99-output"), ("nvos", "99-output-ib_nvl")),
                    _DRY_RUN=False, _AUTO_YES=True, _LINK_ERRORS=0,
                ):
                    with redirect_stdout(output):
                        SETUP._process_latest_yaml(str(project))
                    errors = SETUP._LINK_ERRORS

                self.assertEqual(before, snapshot(occupied))
                self.assertEqual(members, sorted(item.name for item in eth_output.iterdir()))
                if published:
                    self.assertEqual(1, errors)
                    self.assertIn("ERROR", output.getvalue())
                    self.assertIn("99-output/latest", output.getvalue())
                # Not interrupted: the platform after the refusal is still published.
                self.assertEqual(
                    nvos_release.resolve(), (ztp / "config/nvos/latest_yaml").resolve(),
                )


if __name__ == "__main__":
    unittest.main()
