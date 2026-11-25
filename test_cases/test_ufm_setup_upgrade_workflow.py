"""Workflows: setup links feed ufm-setup-upgrade; a running HA pair reloads only its HA link (ubuntu24_host).

Setup-created bringup links are the only inputs the tool needs and unsetup knows them. A running HA pair
takes the HA link's ignore-carrier by networkd reload only, then checks clean (v3.1.6 B6, B6-O8 (b)).
"""

import json
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
import test_cases.test_ufm_setup_upgrade as tufm

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
            # v3.1.1 WP-3: setup's one reconcile engine writes the bringup rows of the link table, a project row
            # through DAY0-Prepare/activate-project (R-016 §2); the project's log directory comes with the
            # template and the pointer names the activated project.
            (project / "99-output-ib_nvl/bringup/ufm-setup-upgrade-logs").mkdir(parents=True, exist_ok=True)
            (root / "DAY0-Prepare/activate-project").symlink_to(project.name)
            rows = [row for row in SETUP.SETUP_LINK_SPECS if row.view in ("bringup-input", "bringup-output")]
            with mock.patch.multiple(SETUP, HTTP_BASE=str(root), _DRY_RUN=False, _AUTO_YES=True, _LINK_ERRORS=0):
                SETUP._reconcile_links([(str(root / row.path), SETUP._spec_link_text(row)) for row in rows])
                self.assertEqual(0, SETUP._LINK_ERRORS)

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

            # Contract changed by Q7 (R-016 §13, owner 2026-11-03 「好的」) and O14 (owner 2026-11-07 「同意你的建议。」
            # via http dev): the tool links are fixed table rows unsetup keeps, never fallback candidates.
            with mock.patch.multiple(UNSETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp")):
                known = set(UNSETUP._known_workspace_links()) | set(UNSETUP._known_ztp_project_links())
            for name in ("ib.csv", "p2p.xlsx", "ufm-setup-upgrade-logs"):
                self.assertNotIn(os.fspath(tool / name), known, name)


class UfmHaLinkCarrierScenarioTest(tufm.ConfiguredPairCase):
    """问题文档 I-055 (:1890-1895) end to end through the UFM script and the host module: a running HA pair whose
    netplan predates ignore-carrier gets it by generate + networkctl reload (no whole netplan apply, the VIP
    stays), and the following check finds netplan unchanged and the HA configuration OK."""

    def test_a_running_ha_pair_takes_ignore_carrier_then_checks_clean(self):
        import yaml
        for name, document in (("ufm01", tufm.desired_netplan("198.51.101.130/23", "192.0.2.1/30", "100.126.255.1/16",
                                                              "100.126.255.2/16", carrier=False)),
                               ("ufm02", tufm.desired_netplan("198.51.101.132/23", "192.0.2.2/30", "100.126.255.3/16",
                                                              "100.126.255.4/16", carrier=False))):
            files = self.state["ufms"][name]["files"]
            files["etc/netplan/01-netcfg.yaml"] = yaml.safe_dump(document)
            for unit, text in tufm.networkd_units(document["network"]["ethernets"]).items():
                files[f"run/systemd/network/{unit}"] = text
        self.make_upgraded()
        state = json.loads(self.state_path.read_text())
        state["ha"] = {"master": "ufm01", "standby": "ufm02", "vip": "198.51.101.133", "started": True,
                       "sync_left": 0}
        state["ufms"]["ufm01"]["ipv4"] += " 198.51.101.133/23"
        self.state_path.write_text(json.dumps(state))

        results, state, _calls, _logs = self.run_login(action="config_upgrade_all")
        for name in ("ufm01", "ufm02"):
            self.assertEqual(dict(self.outcomes(results[name]))["netplan"], "CHANGED", results[name].steps)
            self.assertEqual(state["ufms"][name]["networkctl"], ["reload"])
            self.assertEqual(state["ufms"][name].get("applied", 0), 0, "no whole netplan apply")
        self.assertIn("198.51.101.133/23", state["ufms"]["ufm01"]["ipv4"].split(), "the VIP stays on the master")

        checked, state, _calls, _logs = self.run_login(action="check", apply=False)
        for name in ("ufm01", "ufm02"):
            outcomes = dict(self.outcomes(checked[name]))
            self.assertEqual((outcomes["netplan"], outcomes["ha_config"]), ("UNCHANGED", "OK"), checked[name].steps)
            self.assertEqual(state["ufms"][name]["networkctl"], ["reload"])


if __name__ == "__main__":
    unittest.main()
