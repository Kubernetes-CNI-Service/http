"""G12 (v3.1.1 WP-1): one link specification table in tools/project_contract.py.

Every expected value below is written out from the design, never read back from the implementation:
R-016 详细设计 v1.1 §2 (pointer layout), §3.1 (the table and its columns), §3.2, §3.4 (classes), §7 and §11
(git ignore), its appendix A (the 74 rows measured on DEV c074d27), the v3.1.1 详细工作指导 WP-1 table of new
rows (O2, O3 settled by the owner 2026-11-07, 「同意你的建议。」 via http dev), R16-14 (packaging never reads
the manifest body), O14 (unsetup removes the per-key public-key links) and C99 (TEST 88f9cb3: new public-key
directories follow the process umask).
"""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = load_script("setup_link_spec_project_contract", ROOT / "tools/project_contract.py")
SETUP = load_script("setup_link_spec_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_script("setup_link_spec_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")
PACKAGE = load_script("setup_link_spec_package_common", ROOT / "tools/_package_common.py")

POINTER = "DAY0-Prepare/activate-project"

# R-016 appendix A: (tree link, "project" | "repository", project-relative or repository target).
APPENDIX_A = """\
ethernet/eth.csv project 02-devices_config.csv
ethernet/monitor/cronjob.log project 99-output-monitor/ethernet/cronjob.log
ethernet/monitor/eth-info project 99-output-monitor/ethernet/eth-info
ethernet/monitor/eth.csv repository ethernet/eth.csv
ethernet/monitor/spx-link project 99-output-monitor/ethernet/spx-link
ethernet/p2p.xlsx project p2p.xlsx
infiniband/01-global.yaml project 01-global.yaml
infiniband/bringup/ndr/ndr-upgrade-logs project 99-output-ib_nvl/bringup/ndr-upgrade-logs
infiniband/bringup/ufm-setup-upgrade/ib.csv repository infiniband/ib.csv
infiniband/bringup/ufm-setup-upgrade/p2p.xlsx repository infiniband/p2p.xlsx
infiniband/bringup/ufm-setup-upgrade/ufm-setup-upgrade-logs project 99-output-ib_nvl/bringup/ufm-setup-upgrade-logs
infiniband/bringup/xdr-initial-setup/xdr-initial-setup-logs project 99-output-ib_nvl/bringup/xdr-initial-setup-logs
infiniband/bringup/xdr-upgrade/01-global.yaml project 01-global.yaml
infiniband/bringup/xdr-upgrade/ib.csv repository infiniband/ib.csv
infiniband/bringup/xdr-upgrade/xdr-upgrade-logs project 99-output-ib_nvl/bringup/xdr-upgrade-logs
infiniband/ib.csv project 02-devices_config.csv
infiniband/monitor/01-global.yaml repository infiniband/01-global.yaml
infiniband/monitor/99-output-p2p project 99-output-p2p
infiniband/monitor/cronjob.log project 99-output-monitor/infiniband/cronjob.log
infiniband/monitor/ib-info project 99-output-monitor/infiniband/ib-info
infiniband/monitor/ib-link project 99-output-monitor/infiniband/ib-link
infiniband/monitor/ib.csv repository infiniband/ib.csv
infiniband/monitor/ufm-ibdiagnet project 99-output-monitor/infiniband/ufm-ibdiagnet
infiniband/monitor/ufm-info project 99-output-monitor/infiniband/ufm-info
infiniband/p2p.xlsx project p2p.xlsx
infra/01-global.yaml project 01-global.yaml
infra/02-devices_config.csv project 02-devices_config.csv
infra/logs project 99-output-infra
monitor/01-global.yaml project 01-global.yaml
monitor/02-devices_config.csv project 02-devices_config.csv
monitor/99-output-monitor project 99-output-monitor
monitor/99-output-p2p project 99-output-p2p
monitor/99-output-ufm project 99-output-ufm
monitor/ethernet project 99-output-monitor/ethernet
monitor/infiniband project 99-output-monitor/infiniband
monitor/nvlink project 99-output-monitor/nvlink
monitor/ztp-status repository ztp/status
nvlink/monitor/cronjob.log project 99-output-monitor/nvlink/cronjob.log
nvlink/monitor/nvsw-info project 99-output-monitor/nvlink/nvsw-info
nvlink/monitor/nvsw-link project 99-output-monitor/nvlink/nvsw-link
nvlink/monitor/nvsw.csv repository nvlink/nvsw.csv
nvlink/nvsw.csv project 02-devices_config.csv
nvlink/p2p.xlsx project p2p.xlsx
tools/ibdiagnet-analyze-tool/99-output-p2p project 99-output-p2p
tools/lldp-analyze-tool/99-output-monitor project 99-output-monitor
tools/lldp-analyze-tool/99-output-p2p project 99-output-p2p
ztp/backup/02-devices_config.csv project 02-devices_config.csv
ztp/backup/yaml-backup project 99-output-backup
ztp/config/cumulus/latest_yaml repository ztp/config/cumulus/template/99-output/latest
ztp/config/cumulus/template/01-global.yaml project 01-global.yaml
ztp/config/cumulus/template/02-devices_config.csv project 02-devices_config.csv
ztp/config/cumulus/template/91-devices.yaml project 99-output-eth/91-devices.yaml
ztp/config/cumulus/template/99-output project 99-output-eth
ztp/config/cumulus/template/P2P/eth-info project 99-output-monitor/ethernet/eth-info
ztp/config/cumulus/template/P2P/output-p2p project 99-output-p2p
ztp/config/cumulus/template/P2P/p2p.xlsx project p2p.xlsx
ztp/config/isc-dhcp-server/01-global.yaml project 01-global.yaml
ztp/config/isc-dhcp-server/02-devices_config.csv project 02-devices_config.csv
ztp/config/isc-dhcp-server/02-subnet_config.csv project 02-dhcp-subnet_config.csv
ztp/config/isc-dhcp-server/dhcp-release-manifest.json project 99-output-dhcp/dhcp-release-manifest.json
ztp/config/isc-dhcp-server/dhcpd.conf project 99-output-dhcp/dhcpd.conf
ztp/config/isc-dhcp-server/dhcpd_eth.hosts project 99-output-dhcp/dhcpd_eth.hosts
ztp/config/isc-dhcp-server/dhcpd_ib.hosts project 99-output-dhcp/dhcpd_ib.hosts
ztp/config/isc-dhcp-server/dhcpd_nvl.hosts project 99-output-dhcp/dhcpd_nvl.hosts
ztp/config/isc-dhcp-server/p2p-air.json project 99-output-p2p/p2p-air.json
ztp/config/nvos/latest_yaml repository ztp/config/nvos/template/99-output-ib_nvl/latest
ztp/config/nvos/template/01-global.yaml project 01-global.yaml
ztp/config/nvos/template/02-devices_config.csv project 02-devices_config.csv
ztp/config/nvos/template/99-output-ib_nvl project 99-output-ib_nvl
ztp/config/nvos/template/P2P/02-devices_config.csv project 02-devices_config.csv
ztp/config/nvos/template/P2P/ib-info project 99-output-monitor/infiniband/ib-info
ztp/config/nvos/template/P2P/output-p2p project 99-output-p2p
ztp/config/nvos/template/P2P/p2p.xlsx project p2p.xlsx
ztp/status project 99-output-ztp
"""
# 详细工作指导 WP-1 new rows: tree link -> (base, target, class).
NEW_ROWS = {
    # R-016 第 9 条 structure alignment (owner 2026-11-04).
    "ethernet/01-global.yaml": ("project", "01-global.yaml", "required"),
    "nvlink/01-global.yaml": ("project", "01-global.yaml", "required"),
    "ethernet/monitor/01-global.yaml": ("repository", "ethernet/01-global.yaml", "required"),
    "nvlink/monitor/01-global.yaml": ("repository", "nvlink/01-global.yaml", "required"),
    "ethernet/monitor/99-output-p2p": ("project", "99-output-p2p", "prepared"),
    "nvlink/monitor/99-output-p2p": ("project", "99-output-p2p", "prepared"),
    # R-016 2026-11-05 (Codex RV31-16): one 02 link in each network directory.
    "ethernet/02-devices_config.csv": ("project", "02-devices_config.csv", "required"),
    "infiniband/02-devices_config.csv": ("project", "02-devices_config.csv", "required"),
    "nvlink/02-devices_config.csv": ("project", "02-devices_config.csv", "required"),
    # G14-1 alias tables: optional, dangling is not an error.
    "ethernet/monitor/04-device-aliases.csv": ("project", "04-device-aliases.csv", "optional"),
    "infiniband/monitor/04-device-aliases.csv": ("project", "04-device-aliases.csv", "optional"),
    "nvlink/monitor/04-device-aliases.csv": ("project", "04-device-aliases.csv", "optional"),
    # G14-2 status directories.
    "ethernet/monitor/eth-status": ("project", "99-output-monitor/ethernet/eth-status", "prepared"),
    "infiniband/monitor/ib-status": ("project", "99-output-monitor/infiniband/ib-status", "prepared"),
    "infiniband/monitor/ufm-status": ("project", "99-output-monitor/infiniband/ufm-status", "prepared"),
    "nvlink/monitor/nvsw-status": ("project", "99-output-monitor/nvlink/nvsw-status", "prepared"),
    # BU0.5, O3 default ①.
    "infiniband/bringup/99-output-bringup": ("project", "99-output-bringup", "prepared"),
    # O2 default: setup builds initial-setup's two inputs beside it.
    "infiniband/bringup/xdr-initial-setup/ib.csv": ("repository", "infiniband/ib.csv", "required"),
    "infiniband/bringup/xdr-initial-setup/p2p.xlsx": ("repository", "infiniband/p2p.xlsx", "required"),
}
# Link texts the guide writes out for the new repository aliases.
NEW_ALIAS_TEXTS = {
    "ethernet/monitor/01-global.yaml": "../01-global.yaml",
    "nvlink/monitor/01-global.yaml": "../01-global.yaml",
    "infiniband/bringup/xdr-initial-setup/ib.csv": "../../ib.csv",
    "infiniband/bringup/xdr-initial-setup/p2p.xlsx": "../../p2p.xlsx",
}
# R-016 §3.4.
REQUIRED_INPUTS = {"01-global.yaml", "02-devices_config.csv", "02-dhcp-subnet_config.csv", "ib.csv", "p2p.xlsx"}
OPTIONAL_TARGETS = {
    "99-output-p2p/p2p-air.json", "04-device-aliases.csv",
    # "ndr-upgrade-logs 这类只有某些项目用的": the bringup tool logs.
    "99-output-ib_nvl/bringup/ndr-upgrade-logs", "99-output-ib_nvl/bringup/xdr-initial-setup-logs",
    "99-output-ib_nvl/bringup/xdr-upgrade-logs", "99-output-ib_nvl/bringup/ufm-setup-upgrade-logs",
}
PREPARED_FILE_NAMES = {"91-devices.yaml", "dhcpd.conf", "dhcp-release-manifest.json", "cronjob.log",
                       "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"}
PUBLICKEY_DIRECTORIES = {"ztp/config/publickey", "ethernet/publickey", "infiniband/publickey", "nvlink/publickey"}
# I-024: the project-independent section holds exactly the two shared-image families.
SHARED_PATHS = {"ztp/image/*/*.bin", "infiniband/bringup/ufm-setup-upgrade/image"}
# Git-tracked bridges; packaging keeps excluding them (test_upload_package_contract, test_deploy_upload_archive).
TRACKED_BRIDGES = {
    "infiniband/bringup/xdr-initial-setup/01-global.yaml", "infiniband/bringup/xdr-initial-setup/publickey",
    "infiniband/bringup/ufm-setup-upgrade/01-global.yaml", "infiniband/bringup/ufm-setup-upgrade/publickey",
}
# Dynamic families, one example name each.
DYNAMIC_EXAMPLES = {
    *(directory + "/laptop.pub" for directory in PUBLICKEY_DIRECTORIES),
    "ztp/image/cumulus/cumulus-linux-example.bin",
    "ztp/optimize/site-a-sample/configuration",
}


def appendix_rows():
    return {path: (base, target) for path, base, target in
            (line.split() for line in APPENDIX_A.splitlines())}


class LinkSpecificationTableTest(unittest.TestCase):
    def table(self):
        self.assertTrue(hasattr(CONTRACT, "SETUP_LINK_SPECS"),
                        "R-016 §3.1: tools/project_contract.py holds one link specification table")
        return {row.path: row for row in CONTRACT.SETUP_LINK_SPECS}

    def test_every_row_names_a_type_class_and_writer(self):
        rows = self.table()
        self.assertEqual(len(rows), len(CONTRACT.SETUP_LINK_SPECS), "one row per tree path")
        for path, row in rows.items():
            with self.subTest(path=path):
                self.assertIn(row.kind, {"file", "dir"})
                self.assertIn(row.role, {"required", "prepared", "optional", "publisher"})
                self.assertIn(row.writer, {"setup", "publisher"})
                self.assertIn(row.base, {"project", "repository"})
                self.assertIsInstance(row.note, str)
                # R-016 §3.4: only latest_yaml belongs to the publisher, in both columns.
                self.assertEqual(path.endswith("/latest_yaml"), row.role == "publisher")
                self.assertEqual(row.role == "publisher", row.writer == "publisher")

    def test_table_holds_appendix_a_and_the_new_rows(self):
        rows = self.table()
        expected = appendix_rows()
        self.assertEqual(74, len(expected))
        for path, (base, target, _role) in NEW_ROWS.items():
            expected[path] = (base, target)
        # 74 + 6 structure + 3 networks' 02 + 3 alias tables + 4 status + 99-output-bringup + 2 (O2) = 93;
        # WP-8 (R-013) removes monitor/99-output-ufm and G14-1 the three tools/ rows later.
        self.assertEqual(93, len(expected))
        self.assertEqual(set(expected), set(rows))
        for path, (base, target) in expected.items():
            with self.subTest(path=path):
                self.assertEqual((base, target), (rows[path].base, rows[path].target))
        for path, (_base, _target, role) in NEW_ROWS.items():
            with self.subTest(new=path):
                self.assertEqual(role, rows[path].role)

    def test_classes_and_types_follow_r016_section_3_4(self):
        rows = self.table()

        def project_target(row):
            seen = set()
            while row.base == "repository" and row.path not in seen:
                seen.add(row.path)
                if row.target not in rows:
                    return None  # latest_yaml: a publisher directory, not a table row
                row = rows[row.target]
            return row.target if row.base == "project" else None

        for path, row in rows.items():
            with self.subTest(path=path):
                target = project_target(row)
                if path.endswith("/latest_yaml"):
                    self.assertIsNone(target)
                    self.assertEqual(("dir", "publisher"), (row.kind, row.role))
                    continue
                self.assertIsNotNone(target, "every other row ends in a project file")
                if target in REQUIRED_INPUTS:
                    self.assertEqual(("file", "required"), (row.kind, row.role))
                elif target in OPTIONAL_TARGETS:
                    self.assertEqual("optional", row.role)
                else:
                    self.assertTrue(target.startswith("99-output-"), target)
                    self.assertEqual("prepared", row.role)
                if target not in REQUIRED_INPUTS:
                    file_like = (target.rsplit("/", 1)[-1] in PREPARED_FILE_NAMES
                                 or target in {"99-output-p2p/p2p-air.json", "04-device-aliases.csv"})
                    self.assertEqual("file" if file_like else "dir", row.kind)

    def test_project_rows_link_through_the_activate_project_pointer(self):
        rows = self.table()
        self.assertTrue(hasattr(CONTRACT, "pointer_link_specs"), "R-016 §2: the canonical link text")
        canonical = dict(CONTRACT.pointer_link_specs())
        self.assertEqual(set(rows), set(canonical))
        for path, row in rows.items():
            with self.subTest(path=path):
                if row.base == "project":
                    expected = os.path.relpath(os.path.join(POINTER, row.target), os.path.dirname(path))
                else:
                    expected = os.path.relpath(row.target, os.path.dirname(path))
                self.assertEqual(expected, canonical[path])
        # R-016 §2 layout examples, written out.
        self.assertEqual("../DAY0-Prepare/activate-project/02-devices_config.csv", canonical["ethernet/eth.csv"])
        self.assertEqual("../DAY0-Prepare/activate-project/99-output-ztp", canonical["ztp/status"])
        self.assertEqual("../ib.csv", canonical["infiniband/monitor/ib.csv"])
        self.assertEqual("../../../DAY0-Prepare/activate-project/laptop.pub",
                         CONTRACT.pointer_link_target("ztp/config/publickey/laptop.pub", "laptop.pub"))
        for path, text in NEW_ALIAS_TEXTS.items():
            with self.subTest(alias=path):
                self.assertEqual(text, canonical[path])

    def test_shared_section_holds_the_two_shared_image_families(self):
        self.table()
        self.assertEqual(SHARED_PATHS, {row.path for row in CONTRACT.SHARED_LINK_SPECS})
        self.assertEqual(("infiniband/bringup/ufm-setup-upgrade/image",), tuple(CONTRACT.BRINGUP_IMAGE_LINKS))
        self.assertFalse(SHARED_PATHS & set(self.table()), "shared links are not project rows")

    def test_runtime_and_published_specs_are_derived_from_the_table(self):
        rows = self.table()
        self.assertEqual(set(rows), {name for name, _target in CONTRACT.runtime_link_specs()})
        published = {name for name, _target, _project in CONTRACT.published_runtime_link_specs()}
        self.assertEqual({path for path, row in rows.items() if row.published}, published)
        self.assertTrue(set(rows) <= CONTRACT.IMAGE_HOST_STATE_PATHS)


class PublicKeyDirectoriesTest(unittest.TestCase):
    def setup_tree(self, root: Path) -> Path:
        project = root / "DAY0-Prepare/site-a"
        project.mkdir(parents=True)
        (project / "laptop.pub").write_bytes(b"synthetic laptop key\n")
        (project / "mgmt-server.pub").write_bytes(b"synthetic management key\n")
        return project

    def publish(self, root: Path, project: Path) -> None:
        with mock.patch.multiple(SETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp"), _DRY_RUN=False,
                                 _AUTO_YES=True, _LINK_ERRORS=0), redirect_stdout(io.StringIO()):
            SETUP._process_pubkeys(str(project))
            self.assertEqual(0, SETUP._LINK_ERRORS)

    def test_four_directories_are_declared_host_state_and_used_by_setup(self):
        self.assertEqual(PUBLICKEY_DIRECTORIES, set(getattr(CONTRACT, "PUBLICKEY_DIRECTORIES", ())))
        for directory in PUBLICKEY_DIRECTORIES:
            with self.subTest(directory=directory):
                self.assertIn(directory, CONTRACT.IMAGE_HOST_STATE_SUBTREES)
                self.assertTrue(CONTRACT.is_image_host_state_path(directory + "/laptop.pub"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.multiple(SETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp")):
                roots = {os.path.relpath(path, root) for path in SETUP._publickey_roots()}
        self.assertEqual(PUBLICKEY_DIRECTORIES, roots)

    def test_setup_publishes_every_key_into_four_real_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self.setup_tree(root)
            self.publish(root, project)
            for key_dir in sorted(PUBLICKEY_DIRECTORIES):
                path = root / key_dir
                with self.subTest(directory=key_dir):
                    self.assertTrue(path.is_dir() and not path.is_symlink(), "a real directory (R-016 §3.2)")
                    for name in ("laptop.pub", "mgmt-server.pub"):
                        self.assertTrue((path / name).is_symlink())
                        self.assertEqual((project / name).resolve(), (path / name).resolve())
            with mock.patch.multiple(SETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp"),
                                     IMAGE_DIR=str(root / "image")):
                candidates = {os.path.relpath(path, root) for path in SETUP._managed_ztp_link_candidates()}
                # The manifest records these and --status checks every manifest link against the project.
                expected = {os.path.relpath(path, root) for path in SETUP._collect_expected_links(str(project))}
            keys = {key_dir + "/" + name for key_dir in PUBLICKEY_DIRECTORIES
                    for name in ("laptop.pub", "mgmt-server.pub")}
            self.assertLessEqual(keys, candidates)
            self.assertLessEqual(keys, expected)

    def test_new_public_key_directories_follow_the_process_umask(self):
        # C99 (TEST 88f9cb3): os.makedirs's default mode, never a private mkdtemp directory.
        for mask, expected in ((0o022, 0o755), (0o077, 0o700)):
            with self.subTest(umask=oct(mask)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = self.setup_tree(root)
                previous = os.umask(mask)
                try:
                    self.publish(root, project)
                finally:
                    os.umask(previous)
                for key_dir in sorted(PUBLICKEY_DIRECTORIES):
                    path = root / key_dir
                    self.assertTrue(path.is_dir(), key_dir)
                    self.assertEqual(expected, stat.S_IMODE(path.stat().st_mode), key_dir)


class DerivedConsumersTest(unittest.TestCase):
    def table_paths(self):
        self.assertTrue(hasattr(CONTRACT, "SETUP_LINK_SPECS"), "R-016 §3.1: one link table")
        return {row.path for row in CONTRACT.SETUP_LINK_SPECS}

    @staticmethod
    def symlinks(root: Path, names) -> None:
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to("synthetic-missing-target")

    def test_packaging_exclusions_come_from_the_table_not_the_manifest_body(self):
        expected = (self.table_paths() | {"infiniband/bringup/ufm-setup-upgrade/image"}
                    | TRACKED_BRIDGES | DYNAMIC_EXAMPLES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "DAY0-Prepare").mkdir()
            self.symlinks(root, DYNAMIC_EXAMPLES)
            manifest = root / "ztp/.setup_manifest"
            # R16-14: a manifest body line is no authority for what packaging excludes.
            manifest.write_text("# setup manifest — proj: " + str(root / "DAY0-Prepare/site-a") + "\n"
                                + str(root / "monitor/operator-link") + "\n", encoding="utf-8")
            self.symlinks(root, ("monitor/operator-link",))
            with mock.patch.multiple(PACKAGE, ROOT=root, DAY0=root / "DAY0-Prepare", MANIFEST=manifest):
                links = PACKAGE.setup_managed_links()
        self.assertFalse(hasattr(PACKAGE, "STATIC_SETUP_MANAGED_LINKS"), "G12: no second hand-written table")
        self.assertEqual(expected, links)

    def test_unsetup_fallback_knows_the_four_public_key_directories(self):
        # The per-key links are a dynamic family unsetup removes (O14).  Deriving the rest of the fallback
        # from the table (N2) moves to WP-6 with O14/Q7: the W-1 writer census discovers unsetup through
        # its literal fallback names (test_monitor_writer_quiesce_workflow).
        keys = {directory + "/laptop.pub" for directory in PUBLICKEY_DIRECTORIES}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.symlinks(root, keys)
            (root / "nvlink/publickey/operator.pub").write_bytes(b"operator-owned file\n")
            with mock.patch.multiple(UNSETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp")):
                found = UNSETUP._known_ztp_project_links() + UNSETUP._known_workspace_links()
            names = {os.path.relpath(path, root) for path in found}
        self.assertEqual(keys, names, "only links; an operator's regular key file is never a candidate")


class GitIgnoreCoverageTest(unittest.TestCase):
    # Names that must never show as untracked (R-016 §7, §11 E-3) beyond the table rows themselves.
    IGNORED = (
        *sorted(NEW_ROWS),
        *(directory + "/laptop.pub" for directory in sorted(PUBLICKEY_DIRECTORIES)),
        "DAY0-Prepare/activate-project",
        "DAY0-Prepare/.activate-project.12345.tmp",
        "DAY0-Prepare/site-a/99-output-bringup",
    )
    PUBLIC = ("DAY0-Prepare/template/ib.csv",)

    def ignored(self, names):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", "--stdin"], cwd=ROOT, input="\n".join(names) + "\n",
            capture_output=True, text=True, check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return set(result.stdout.splitlines())

    def test_every_table_row_and_runtime_name_is_git_ignored(self):
        names = set(self.IGNORED)
        if hasattr(CONTRACT, "SETUP_LINK_SPECS"):
            names.update(row.path for row in CONTRACT.SETUP_LINK_SPECS)
        self.assertEqual(set(), names - self.ignored(sorted(names)))

    def test_the_template_inventory_link_stays_public(self):
        self.assertEqual(set(), self.ignored(self.PUBLIC))


if __name__ == "__main__":
    unittest.main()
