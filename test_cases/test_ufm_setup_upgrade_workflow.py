"""Workflows: setup links feed ufm-setup-upgrade; a running HA pair reloads only its HA link (ubuntu24_host).

Setup-created bringup links are the only inputs the tool needs and unsetup knows them. A running HA pair
takes the HA link's ignore-carrier by networkd reload only, then checks clean (v3.1.6 B6, B6-O8 (b)).
ha-post-config sets the root port group from opensm.conf's default state and leaves the generated root
script on the VIP holder (v3.1.6 B7, R-031).
"""

import hashlib
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
        (root / "tools").mkdir()   # v3.1.6 B0: the tool imports four shared tools modules
        for name in tufm.STANDALONE_TOOLS:
            shutil.copy2(ROOT / "tools" / name, root / "tools" / name)
        # B0-O6 (b): the repository's master inventory, here the project's 02 itself (需求文档 :974, :976)
        (infiniband / "02-devices_config.csv").symlink_to(os.path.relpath(project / "02-devices_config.csv", infiniband))
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


class UfmRootPortGroupScenarioTest(tufm.ConfiguredPairCase):
    """R-031 end to end through the UFM script, the host module and the generated root script (指导 8.18 workflow):
    from opensm.conf's default state ha-post-config writes the three root files, fails over once, waits 60 s once
    (fake clock), keeps both original phases, verifies root by rank and load line on the new master and leaves a
    0700 script only there; a second run changes nothing, fails over and waits for nothing, checks nothing and
    still leaves the script."""
    VIP = "198.51.101.133"

    def make_ha_running(self):
        state = dict(self.state, image_url=tufm.IMAGE_URL)
        state["ha"] = {"master": "ufm01", "standby": "ufm02", "vip": self.VIP, "started": True, "sync_left": 0,
                       "loaded_licenses": []}
        state["ufms"]["ufm01"]["ipv4"] += f" {self.VIP}/23"
        self.state_path.write_text(json.dumps(state))
        self.make_upgraded()

    def run_post_config(self):
        now, events = [1000.0], []

        def sleep(seconds):
            if seconds >= 1:   # subprocess.Popen.wait polls through time.sleep in steps of a few ms
                events.append(seconds)
            now[0] += seconds

        with mock.patch.object(tufm.ufm.time, "sleep", sleep), \
                mock.patch.object(tufm.ufm.time, "monotonic", lambda: now[0]):
            results, state, _calls, _logs = self.run_login(action="ha_post_config_command", failover_settle=60,
                                                           ha_wait=(0, 60, 15, 900))
        return results, state, events

    def script(self, node):
        return (self.sandbox / node / "root/ufm-setup-upgrade-backup" / self.run_dir.name / "post-ha"
                / "ufm-root-switches.py")

    def test_default_state_to_root_port_group_then_a_quiet_second_run(self):
        self.make_ha_running()
        results, state, sleeps = self.run_post_config()
        for name in ("ufm01", "ufm02"):
            self.assertEqual(results[name].status, "HA_POST_CONFIGURED", results[name].detail)
        files = self.files / "conf/opensm"
        self.assertEqual((files / "opensm.conf").read_text(), tufm.OPENSM_CONF_DONE)
        self.assertEqual((files / "port_groups_policy_file.conf").read_text(), tufm.ROOT_POLICY)
        self.assertEqual((files / "root_guid.conf").read_text(), "root_switches\n")
        self.assertEqual(state["ha"]["failovers"], 1)
        self.assertEqual(sleeps, [60], "one 60 s wait; both phases pass on their first read")
        self.assertEqual(self.outcomes(results["ufm02"]), [("post_ha_verify", "OK"), ("post_ha_root_verify", "VERIFIED"),
                                                          ("post_ha_root_script", "WRITTEN")])
        script = self.script("ufm02")
        self.assertEqual(script.stat().st_mode & 0o777, 0o700)
        self.assertFalse(self.script("ufm01").exists(), "only on the host holding the VIP")
        header = script.read_text(encoding="utf-8")
        digest = hashlib.sha256((self.inputs / "ib.csv").read_bytes()).hexdigest()
        self.assertIn(f"ib.csv sha256: {digest}", header)
        self.assertIn("rule: " + tufm.SPINE_RULE, header)

        again, state, sleeps = self.run_post_config()
        for name in ("ufm01", "ufm02"):
            self.assertEqual(again[name].status, "HA_POST_UP_TO_DATE", again[name].detail)
        self.assertEqual(state["ha"]["failovers"], 1)
        self.assertEqual(sleeps, [], "no failover: no wait and no check loop")
        steps = [step["step"] for item in again.values() for step in item.steps]
        self.assertNotIn("post_ha_verify", steps)
        self.assertNotIn("post_ha_root_verify", steps)
        self.assertEqual(self.script("ufm02").stat().st_mode & 0o777, 0o700, "the script is left again")


if __name__ == "__main__":
    unittest.main()
