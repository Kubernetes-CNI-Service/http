"""Workflow: setup-created bringup links are the only inputs ufm-setup-upgrade needs; unsetup knows them."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_ufm_setup_upgrade import make_inputs

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "infiniband/bringup/ufm-setup-upgrade"
SETUP = load_script("ufm_workflow_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_script("ufm_workflow_unsetup", ROOT / "DAY0-Prepare/02-unsetup.py")


class SetupLinksFeedUfmToolTest(unittest.TestCase):
    def build_repository(self, root):
        project = root / "DAY0-Prepare/2026-09-site-b300"
        project.mkdir(parents=True)
        make_inputs(project)
        (project / "ib.csv").rename(project / "02-devices_config.csv")
        infiniband = root / "infiniband"
        infiniband.mkdir()
        for alias, target in (("ib.csv", "02-devices_config.csv"), ("p2p.xlsx", "p2p.xlsx"),
                              ("01-global.yaml", "01-global.yaml"), ("publickey", "publickey")):
            (infiniband / alias).symlink_to(os.path.relpath(project / target, infiniband))
        tool = infiniband / "bringup/ufm-setup-upgrade"
        tool.mkdir(parents=True)
        shutil.copy2(TOOL / "ufm-setup-upgrade.py", tool)
        (root / "infra").mkdir()
        shutil.copy2(ROOT / "infra/ubuntu24_host.py", root / "infra/ubuntu24_host.py")
        for name in ("01-global.yaml", "publickey"):
            self.assertTrue((TOOL / name).is_symlink(), f"{name} must be a tracked repository link")
            (tool / name).symlink_to(os.readlink(TOOL / name))
        return project, tool

    def test_setup_links_feed_the_tool_and_unsetup_knows_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project, tool = self.build_repository(root)
            outputs = [(str(root / name), target) for name, target in SETUP.BRINGUP_OUTPUT_SPECS]
            with mock.patch.multiple(SETUP, HTTP_BASE=str(root), _DRY_RUN=False, _AUTO_YES=True,
                                     _LINK_ERRORS=0, BRINGUP_OUTPUT_MAPPINGS=outputs):
                SETUP._process_bringup_input_links(str(project))
                SETUP._process_bringup_links(str(project))

            self.assertEqual(os.readlink(tool / "ib.csv"), "../../ib.csv")
            self.assertEqual(os.readlink(tool / "p2p.xlsx"), "../../p2p.xlsx")
            logs = tool / "ufm-setup-upgrade-logs"
            archive = (project / "99-output-ib_nvl/bringup/ufm-setup-upgrade-logs").resolve()
            self.assertTrue(logs.is_symlink())
            self.assertEqual(logs.resolve(), archive)
            self.assertEqual((tool / "ib.csv").resolve(), (project / "02-devices_config.csv").resolve())

            env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
            result = subprocess.run([sys.executable, "-B", str(tool / "ufm-setup-upgrade.py"), "check", "--inputs-only"],
                                    cwd=tmp, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("oob-leaf117 (203.0.112.119) swp17", result.stdout)
            self.assertIn("      eno8403: ufm02.site01.example.test eno8403", result.stdout)
            self.assertIn("publickey: mgmt-server.pub", result.stdout)

            ufm = load_script("ufm_workflow_tool", tool / "ufm-setup-upgrade.py")
            run_dir = ufm.prepare_run_dir(tool, "login")
            self.assertEqual(run_dir.resolve().parent, archive)

            with mock.patch.object(UNSETUP, "HTTP_BASE", str(root)):
                known = set(UNSETUP._known_workspace_links())
            for name in ("ib.csv", "p2p.xlsx", "ufm-setup-upgrade-logs"):
                self.assertIn(os.fspath(tool / name), known, name)


if __name__ == "__main__":
    unittest.main()
