"""Workflow: the real cron.sh runs the real ufm-info.sh on each server_ufm and archives the snapshots
(infiniband/monitor/UFM-MONITOR.md). SSH/SCP reach per-IP sandboxes; the UFM commands are fakes."""

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from test_cases.test_ufm_monitor_scripts import FAKE_DOCKER, FAKES

ROOT = Path(__file__).resolve().parents[1]
UFMS = {
    "ufm01.example.test": ("198.51.101.130", "02:00:00:00:01:01"),
    "ufm02.example.test": ("198.51.101.132", "02:00:00:00:02:01"),
}
MGMT = ("mgmt01.example.test", "198.51.101.140", "02:00:00:00:03:01")
VIP = "198.51.101.133"
PINNED_PATH = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
# The owner timing (wait a minute, then every 5 s), shortened in the staged copy only.
TIMING = {"RETRIEVE_FIRST_WAIT=60": "RETRIEVE_FIRST_WAIT=1", "RETRIEVE_POLL=5 ": "RETRIEVE_POLL=1 ",
          # owner 2026-10-22: 5 minutes / 30 s / 17 minutes for ibdiagnet and iblinkinfo
          "UFM_IBDIAG_FIRST_WAIT=300": "UFM_IBDIAG_FIRST_WAIT=1", "UFM_IBDIAG_POLL=30": "UFM_IBDIAG_POLL=1",
          "UFM_IBDIAG_WAIT=1020": "UFM_IBDIAG_WAIT=60"}

# ssh/scp stand-ins: user@IP is the sandbox <root>/hosts/<IP>; "/root/" maps into it.
FAKE_REMOTE = r'''#!{python}
import glob, json, os, shutil, subprocess, sys
state = json.load(open(os.environ["FAKE_UFM_STATE"]))
tool = os.path.basename(sys.argv[0])
args, words = sys.argv[1:], []
i = 0
while i < len(args):
    if args[i] == "-o":
        i += 2
        continue
    if args[i].startswith("-") and len(words) == 0 and args[i] != "--":
        i += 1
        continue
    words.append(args[i])
    i += 1
log = open(os.environ["FAKE_UFM_CALLS"], "a")
def home(ip):
    return os.path.join(os.environ["FAKE_UFM_HOSTS"], ip)
def local(ip, path):
    return path.replace("/root", home(ip) + "/root", 1) if path.startswith("/root") else path
def down(ip):
    if ip in state.get("down", []) or ip not in state["ufms"]:
        print(f"ssh: connect to host {ip} port 22: Connection timed out", file=sys.stderr)
        sys.exit(255)
FAILOVER = os.path.join(os.environ["FAKE_UFM_HOSTS"], "failover-done")
def holder(ip):
    # owner 2026-10-22: `ufm_ha_cluster failover` moves the VIP to the other UFM at any moment
    if os.path.exists(FAILOVER) and ip in state.get("failover", {}).get("vip", {}):
        return state["failover"]["vip"][ip]
    return state.get("vip", {}).get(ip, ip)
def refuse_key(ip):
    if ip in state.get("no_key", []) and "BatchMode=yes" in sys.argv:
        print(f"root@{ip}: Permission denied (publickey,password).", file=sys.stderr)
        sys.exit(255)
if tool == "ssh":
    target, command = words[0], " ".join(words[1:])
    user, ip = target.split("@", 1)
    log.write(json.dumps({"tool": "ssh", "user": user, "ip": ip, "command": command,
                          "alive": "ServerAliveInterval=10" in sys.argv}) + "\n")
    vip_address = ip
    ip = holder(ip)
    down(ip)
    refuse_key(ip)
    ufm = state["ufms"][ip]
    for device, mac in (("lo", "00:00:00:00:00:00"), ("eno8303", ufm["mac"])):
        os.makedirs(f"{home(ip)}/sys/class/net/{device}", exist_ok=True)
        with open(f"{home(ip)}/sys/class/net/{device}/address", "w") as handle:
            handle.write(mac + "\n")
    os.makedirs(home(ip) + "/root", exist_ok=True)
    os.makedirs(home(ip) + "/tmp", exist_ok=True)
    # HOME is the sandbox: key preparation writes ~/.ssh/authorized_keys there, never on this machine.
    env = dict(os.environ, HOME=home(ip) + "/root", PATH=os.environ["FAKE_UFM_BIN"] + os.pathsep + os.environ["PATH"],
               FAKE_HOSTNAME=ufm["hostname"], FAKE_MAC=ufm["mac"], TMPDIR=home(ip) + "/tmp",
               UFM_INFO_IB_SYSFS=os.environ["FAKE_UFM_SYSFS"], FAKE_CONTAINER=home(ip) + "/container",
               UFM_HOST_FILES=home(ip) + "/container/opt/ufm/files",   # the master's bind mount
               FAKE_DOCKER_LOG=home(ip) + "/docker.log", COPYFILE_DISABLE="1")
    for sub in ("/container/opt/ufm/files", "/container/var/tmp"):
        os.makedirs(home(ip) + sub, exist_ok=True)
    after = state.get("failover", {}).get("after")
    trigger = after and after in command and vip_address in state.get("failover", {}).get("vip", {})
    command = command.replace("/root", home(ip) + "/root").replace("/sys/class/net", home(ip) + "/sys/class/net")
    rc = subprocess.call(["bash", "-c", command], env=env, cwd=home(ip) + "/root")
    if trigger:
        open(FAILOVER, "w").close()
    sys.exit(rc)
src, dst = words[-2], words[-1]
remote = src if "@" in src else dst
ip = remote.split("@", 1)[1].split(":", 1)[0]
log.write(json.dumps({"tool": "scp", "ip": ip, "src": src, "dst": dst,
                      "alive": "ServerAliveInterval=10" in sys.argv}) + "\n")
ip = holder(ip)
down(ip)
refuse_key(ip)
if "@" in src:
    matches = sorted(glob.glob(local(ip, src.split(":", 1)[1])))
    if not matches:
        print("scp: No such file or directory", file=sys.stderr)
        sys.exit(1)
    shutil.copy(matches[0], dst)
else:
    path = local(ip, dst.split(":", 1)[1])
    shutil.copy(src, os.path.join(path, os.path.basename(src)) if path.endswith("/") else path)
'''


class UfmCronCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        # the published tree: the shared collector and its infiniband entry point. cron.sh pins PATH, so
        # the staged copy puts the fake ssh/scp/flock in front of it; the pinned line must exist exactly once.
        self.bin = self.mkdir("bin")
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        self.assertEqual(source.count(PINNED_PATH), 1)
        staged = self.mkdir("ethernet/monitor") / "cron.sh"
        source = source.replace(PINNED_PATH, PINNED_PATH.replace("PATH=", f"PATH={self.bin}:"))
        for line, short in TIMING.items():
            self.assertEqual(source.count(line), 1, line)
            source = source.replace(line, short)
        staged.write_text(source, encoding="utf-8")
        monitor = self.mkdir("infiniband/monitor")
        (monitor / "cron.sh").symlink_to("../../ethernet/monitor/cron.sh")
        # the page generator cron.sh calls at the end: records how it was called
        self.generated = self.root / "generated.jsonl"
        self.order = self.root / "order.log"
        self.write_exec(self.mkdir("monitor") / "generate-monitor-html.py",
                        "import json, sys\n"
                        f"open({str(self.generated)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
                        f"open({str(self.order)!r}, 'a').write('generate\\n')\n")
        shutil.copy(ROOT / "infiniband/monitor/ufm-info.sh", monitor / "ufm-info.sh")
        shutil.copy(ROOT / "infiniband/monitor/ufm-ibdiagnet.sh", monitor / "ufm-ibdiagnet.sh")
        # the IB closed loop: the real post-collect, a stand-in analyzer, the setup output link and a CVT
        shutil.copy(ROOT / "infiniband/monitor/post-collect.py", monitor / "post-collect.py")
        for module in ("log_rotation.py", "collection_archive.py"):   # cronjob.log and the data retention
            shutil.copy(ROOT / "tools" / module, self.mkdir("tools") / module)
        self.analyzed = self.root / "analyzed.jsonl"
        tool = self.mkdir("tools/ibdiagnet-analyze-tool")
        # like the real analyzer: the report, and its provenance naming the input and the CVT
        (tool / "analyze.py").write_text(
            "import hashlib, json, os, sys\n"
            "args = sys.argv[1:]\n"
            f"open({str(self.analyzed)!r}, 'a').write(json.dumps(args) + '\\n')\n"
            f"open({str(self.order)!r}, 'a').write('analyze\\n')\n"
            f"if os.path.exists({str(self.root / 'analyzer-fails')!r}): sys.exit('ERROR: fixture')\n"
            "def identity(path):\n"
            "    real = os.path.realpath(path)\n"
            "    return {'path': os.path.abspath(path), 'resolved_path': real, 'kind': 'file',\n"
            "            'sha256': hashlib.sha256(open(real, 'rb').read()).hexdigest()}\n"
            "output = args[args.index('--output') + 1]\n"
            # records whether the shared report lock is held while the report is written
            "probe = os.environ.get('FAKE_REPORT_LOCK_PROBE')\n"
            "if probe:\n"
            "    import fcntl\n"
            "    with open(os.path.join(os.path.dirname(os.path.realpath(output)), '.report-writer.lock'), 'a') as lock:\n"
            "        try:\n"
            "            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "            state = 'free'\n"
            "        except BlockingIOError:\n"
            "            state = 'held'\n"
            "    open(probe, 'w').write(state)\n"
            "open(output, 'wb').write(b'PK report')\n"
            "json.dump({'schema': 'ib-report-provenance-v1', 'report': identity(output),\n"
            "           'cvt': identity(args[args.index('--p2p') + 1]), 'actual': identity(args[1])},\n"
            "          open(output + '.provenance.json', 'w'))\n", encoding="utf-8")
        self.p2p_output = self.mkdir("DAY0-Prepare/site/99-output-p2p")
        (self.p2p_output / "site-cvt.xlsx").write_bytes(b"cvt")
        (monitor / "99-output-p2p").symlink_to(self.p2p_output)   # post-collect's own-directory link
        # the project and the links setup creates (ib.csv, the ufm-info data directory)
        self.project = self.mkdir("DAY0-Prepare/site")
        rows = ["hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac"]
        rows += [f"{name},server_ufm,NA,{ip},23,198.51.101.254,{mac}" for name, (ip, mac) in UFMS.items()]
        rows.append(f"{MGMT[0]},server_mgmt,NA,{MGMT[1]},23,198.51.101.254,{MGMT[2]}")
        (self.project / "02-devices_config.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
        key = self.root / "fixture-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        shutil.copy(key.with_suffix(".pub"), self.project / "mgmt-server.pub")
        (monitor / "ib.csv").symlink_to(self.project / "02-devices_config.csv")
        self.output = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband/ufm-info")
        (monitor / "ufm-info").symlink_to(self.output)
        self.ibdiag_output = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband/ufm-ibdiagnet")
        (monitor / "ufm-ibdiagnet").symlink_to(self.ibdiag_output)
        (self.project / "01-global.yaml").write_text(f'servers:\n  - ufm:\n      vip: "{VIP}"\n', encoding="utf-8")
        (monitor / "01-global.yaml").symlink_to(self.project / "01-global.yaml")
        # fakes: ssh/scp, flock (absent on macOS), and the UFM's own commands
        self.ufm_bin = self.mkdir("ufm-bin")
        for tool in ("ssh", "scp"):
            self.write_exec(self.bin / tool, FAKE_REMOTE.replace("{python}", sys.executable))
        self.write_exec(self.bin / "flock", "#!/bin/sh\nexit 0\n")
        fakes = dict(FAKES, hostname='echo "$FAKE_HOSTNAME"',
                     ip='echo "eno8303          UP             $FAKE_MAC <BROADCAST,MULTICAST,UP>"')
        for name, body in fakes.items():
            self.write_exec(self.ufm_bin / name, f"#!/bin/sh\n{body}\n")
        self.write_exec(self.ufm_bin / "docker", FAKE_DOCKER.replace("{python}", sys.executable))
        self.sysfs = self.mkdir("sys-infiniband")
        (self.sysfs / "mlx5_0").mkdir()
        self.state = {"ufms": {ip: {"hostname": name, "mac": mac} for name, (ip, mac) in UFMS.items()},
                      "down": []}

    def tearDown(self):
        self.tmp.cleanup()

    def mkdir(self, relative):
        path = self.root / relative
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def write_exec(path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o755)

    def run_cron(self, *args, pass_fds=(), **extra_env):
        state_path = self.root / "state.json"
        state_path.write_text(json.dumps(self.state), encoding="utf-8")
        self.calls = self.root / "calls.jsonl"
        # COPYFILE_DISABLE: macOS tar would otherwise add "._" metadata members (GNU tar never does).
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}", LC_ALL="C", COPYFILE_DISABLE="1",
                   FAKE_UFM_STATE=str(state_path), FAKE_UFM_CALLS=str(self.calls),
                   FAKE_UFM_HOSTS=str(self.mkdir("hosts")), FAKE_UFM_BIN=str(self.ufm_bin),
                   FAKE_UFM_SYSFS=str(self.sysfs), **extra_env)
        return subprocess.run(["bash", str(self.root / "infiniband/monitor/cron.sh"), *args], cwd=self.root, env=env,
                              capture_output=True, text=True, timeout=240, pass_fds=pass_fds)

    def archives(self):
        return sorted(self.output.glob("*.tar.gz"))

    def members(self, archive):
        with tarfile.open(archive) as bundle:
            return {Path(member.name).name: bundle.extractfile(member).read().decode()
                    for member in bundle.getmembers() if member.isfile()}

    def contacted(self):
        if not self.calls.exists():
            return set()
        return {json.loads(line)["ip"] for line in self.calls.read_text().splitlines()}

    def ibdiag_archives(self):
        return sorted(path.name for path in self.ibdiag_output.iterdir()
                      if path.name.endswith(("_ibdiagnet2.tgz", "_iblinkinfo.log")))


class UfmCronWorkflowTest(UfmCronCase):
    def test_cron_runs_ufm_info_on_every_ufm_and_archives_the_snapshots(self):
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        archives = self.archives()
        self.assertEqual(len(archives), 1, result.stdout)
        members = self.members(archives[0])
        self.assertEqual(sorted(members), sorted(f"{name}.info" for name in UFMS))
        for name, text in members.items():
            self.assertIn(f"Device:       {name[:-5]}\n", text)
            self.assertIn("Server Type:  UFM", text)
            self.assertIn("# Collect complete", text)
        self.assertNotIn(MGMT[1], self.contacted(), "server_mgmt is not collected in this phase")
        self.assertIn("HA 未就绪", result.stdout, "no device answers the VIP yet: ibdiagnet is skipped")
        self.assertEqual([path.name for path in self.ibdiag_output.iterdir() if not path.name.endswith(".ufm-run.json")],
                         [], "only the run record says the run was skipped")
        self.assertEqual({json.loads(line)["user"] for line in self.calls.read_text().splitlines()
                          if json.loads(line)["tool"] == "ssh"}, {"root"})
        self.assertIn('"planned":0', result.stdout, "UFMs never join the switch result")
        self.assertIn("cron finish ==========", result.stdout)
        self.assertEqual(self.generated.read_text().splitlines(), ['["--type", "prod"]'],
                         "owner 2026-10-21: any data collected in this run is published")
        key = (self.project / "mgmt-server.pub").read_text().split()[:2]
        for ip, _mac in UFMS.values():
            keys = (self.root / "hosts" / ip / "root/.ssh/authorized_keys").read_text()
            self.assertIn(" ".join(key), keys, "the deployment key is installed at key preparation")
        self.assertRegex(result.stdout, r"ufm-info ──\n.*\[CLN\] found +1 file\(s\) to bundle", "counted through the link")

    def test_an_unreachable_ufm_is_reported_without_failing_the_switch_result(self):
        self.state["down"] = ["198.51.101.132"]
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(self.members(self.archives()[0])), ["ufm01.example.test.info"])
        self.assertIn("UFM ufm02.example.test: SSH authentication or transport unavailable", result.stdout)
        self.assertIn('"state":"success"', result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_a_machine_with_another_management_mac_is_rejected_at_key_preparation(self):
        self.state["ufms"]["198.51.101.132"]["mac"] = "02:00:00:00:09:09"
        result = self.run_cron()
        self.assertEqual(sorted(self.members(self.archives()[0])), ["ufm01.example.test.info"])
        self.assertIn("management MAC identity mismatch", result.stdout + result.stderr)
        self.assertIn("ufm02.example.test", result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)
        self.assertFalse((self.root / "hosts/198.51.101.132/root/.ssh/authorized_keys").exists(),
                         "nothing is installed on the wrong machine")

    def test_a_refused_key_without_a_terminal_leaves_only_a_ufm_warning(self):
        self.state["no_key"] = ["198.51.101.132"]
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sorted(self.members(self.archives()[0])), ["ufm01.example.test.info"])
        self.assertIn("UFM ufm02.example.test: SSH authentication or transport unavailable", result.stdout)
        self.assertIn('"state":"success"', result.stdout, "the switch result is untouched")
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_without_the_setup_data_links_no_ufm_is_touched(self):
        (self.root / "infiniband/monitor/ufm-info").unlink()
        (self.root / "infiniband/monitor/ufm-ibdiagnet").unlink()
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("setup", result.stdout)
        self.assertEqual(self.archives(), [])
        self.assertFalse(self.generated.exists(), "nothing collected, nothing to publish")
        self.assertFalse((self.root / "infiniband/monitor/ufm-info").exists())
        self.assertEqual(self.contacted(), set(), "no UFM is touched without a place to store the result")
        self.assertFalse((self.root / "infiniband/monitor/ufm-ibdiagnet").exists())

    def test_a_missing_info_link_stops_only_the_info_phase(self):
        (self.root / "infiniband/monitor/ufm-info").unlink()
        self.state["vip"] = {VIP: "198.51.101.130"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ufm-info 不存在", result.stdout)
        self.assertFalse((self.root / "infiniband/monitor/ufm-info").exists())
        self.assertEqual(len(self.ibdiag_archives()), 1, "ibdiagnet still runs")

    def test_ibdiagnet_runs_on_the_vip_holder_and_lands_under_the_real_node(self):
        self.state["vip"] = {VIP: "198.51.101.132"}   # ufm02 holds the VIP
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = self.ibdiag_archives()
        self.assertEqual(len(names), 1, result.stdout)
        # owner 2026-10-22: run-id (minute timestamp) first for the daily bundling, then the real node
        self.assertRegex(names[0], r"^\d{8}-\d{4}-prod-[0-9a-f]{16}_ufm02_ibdiagnet2\.tgz$")
        done = (self.ibdiag_output / names[0].replace(".tgz", ".done")).read_text()
        self.assertIn("result=ok", done, "the UFM's completion record is kept beside it")
        with tarfile.open(self.ibdiag_output / names[0]) as bundle:
            self.assertIn("ibdiagnet2/ibdiagnet2.log", bundle.getnames(), "the ibdiagnet archive as is")
        self.assertIn("cron finish ==========", result.stdout)

    def test_the_fetched_ibdiagnet_archive_becomes_the_ib_link_validation_report_before_the_page(self):
        # Owner 2026-10-21: IB modelled on Ethernet's closed loop, on this run's exact archive.
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        [archive] = self.ibdiag_archives()
        [argv] = [json.loads(line) for line in self.analyzed.read_text().splitlines()]
        self.assertEqual(["--ibdiagnet", str((self.ibdiag_output / archive).resolve()),
                          "--p2p", str((self.p2p_output / "site-cvt.xlsx").resolve())], argv[:4])
        report = archive.replace("_ibdiagnet2.tgz", "-ibdiagnet-topology-validation.xlsx")
        self.assertTrue((self.p2p_output / report).is_file())
        self.assertTrue((self.p2p_output / report.replace(".xlsx", ".receipt.json")).is_file())
        self.assertEqual(["analyze", "generate"], self.order.read_text().split())
        self.assertIn("cron finish ==========", result.stdout)

    def test_a_failed_ib_analysis_is_a_ufm_warning_and_the_page_is_still_refreshed(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        (self.root / "analyzer-fails").write_text("1")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(["analyze", "generate"], self.order.read_text().split())
        self.assertIn("[IB-CLOSED-LOOP] ERROR", result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)
        self.assertIn('"state":"success"', result.stdout, "the switch result is untouched")

    def test_without_an_ibdiagnet_archive_no_analysis_runs(self):
        result = self.run_cron()   # no device holds the VIP: ibdiagnet is skipped
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.analyzed.exists())
        self.assertEqual(["generate"], self.order.read_text().split())

    def test_a_vip_held_by_another_machine_is_not_collected(self):
        self.state["ufms"]["198.51.101.150"] = {"hostname": "intruder.example.test", "mac": "02:00:00:00:09:09"}
        self.state["vip"] = {VIP: "198.51.101.150"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.ibdiag_archives(), [])
        self.assertEqual(sorted(self.members(self.archives()[0])), sorted(f"{name}.info" for name in UFMS),
                         "nor is its HA state")
        self.assertIn("不是 ib.csv 中的 UFM", result.stdout)
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_the_ha_state_is_read_on_the_vip_holder_and_kept_under_that_node(self):
        # Owner 2026-10-21: the HA state comes only from the primary, through the VIP.
        self.state["vip"] = {VIP: "198.51.101.132"}   # ufm02 is the primary
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        members = self.members(self.archives()[0])
        self.assertEqual(sorted(members), sorted([f"{name}.info" for name in UFMS] + ["ufm02.example.test.ha"]))
        ha = members["ufm02.example.test.ha"]
        self.assertIn("Server Type:  UFM-HA", ha)
        self.assertIn("Sanity tests completed successfully!", ha)
        for name in UFMS:
            self.assertNotIn("ufm_ha_cluster", members[f"{name}.info"], "no HA command runs per node")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any(call["tool"] == "scp" and call["ip"] == VIP and call["dst"].endswith("/root/monitor/ha/")
                            for call in calls),
                        "the VIP copy never overwrites the node script that may still be running there")
        self.assertIn("cron finish ==========", result.stdout)

    def failover_after(self, launched):
        """ufm02 holds the VIP when the collector starts; right after `launched` the VIP moves to ufm01,
        which still keeps the HA state it wrote when it was the primary."""
        self.state["vip"] = {VIP: "198.51.101.132"}
        self.state["failover"] = {"after": launched, "vip": {VIP: "198.51.101.130"}}
        stale = self.mkdir("hosts/198.51.101.130/root/monitor")
        (stale / "ufm01.example.test.ha").write_text(
            "Device:       ufm01.example.test\nServer Type:  UFM-HA\nSTALE 02:00:00:00:01:01\n"
            "# Collect complete\n", encoding="utf-8")

    def test_a_failover_after_the_ha_start_still_fetches_this_runs_state_from_that_node(self):
        # Owner 2026-10-22: the code must cope with a UFM failover; the VIP may move mid-collection.
        self.failover_after("ufm-info.sh --ha")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        members = self.members(self.archives()[0])
        self.assertIn("ufm02.example.test.ha", members)
        self.assertNotIn("ufm01.example.test.ha", members, "the old primary's leftover state is never taken")
        self.assertNotIn("STALE", "".join(members.values()))
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        fetched = [call for call in calls if call["tool"] == "scp" and call["src"].endswith("/*.ha")]
        self.assertEqual([call["ip"] for call in fetched], ["198.51.101.132"],
                         "fetched from the node that ran it, by its own address")

    def test_a_failover_during_ibdiagnet_fetches_from_the_node_that_ran_it(self):
        self.failover_after("ufm-ibdiagnet.sh")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        names = self.ibdiag_archives()
        self.assertEqual(len(names), 1, result.stdout)
        self.assertRegex(names[0], r"_ufm02_ibdiagnet2\.tgz$")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        done_reads = [call["ip"] for call in calls if call["tool"] == "ssh" and ".done" in call["command"]]
        self.assertTrue(done_reads)
        self.assertEqual(set(done_reads), {"198.51.101.132"})

    def test_every_ufm_session_detects_a_dead_peer(self):
        # A VIP that nobody holds for a while would otherwise leave scp waiting on TCP retransmits.
        self.state["vip"] = {VIP: "198.51.101.132"}
        self.run_cron()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(calls)
        self.assertEqual([call for call in calls if not call["alive"]], [])

    def test_an_unanswered_vip_skips_only_the_ha_state(self):
        result = self.run_cron()   # no device holds the VIP yet
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"\[UFM\] SKIPPED: .*HA 未就绪")
        self.assertEqual(sorted(self.members(self.archives()[0])), sorted(f"{name}.info" for name in UFMS))
        self.assertNotIn("UFM warnings", result.stdout, "HA that is not set up yet is not a failure")


class UfmCronFabricModeAndRetentionTest(UfmCronCase):
    """Owner 2026-10-22: ibdiagnet by default, iblinkinfo after three failures in a row, ibdiagnet again
    every sixth run; 3-day retention for everything collected; cronjob.log rotation; skipped overlap."""

    def state_file(self):
        return self.ibdiag_output / ".ibdiagnet-state"

    def counts(self):
        text = self.state_file().read_text()
        return tuple(int(re.search(rf"^{key}=(\d+)$", text, re.M).group(1)) for key in ("failures", "since_probe"))

    def kinds_run(self):
        log = self.root / "hosts/198.51.101.132/docker.log"
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return [call[-1].rsplit("/", 1)[-1] if call[-1].endswith("iblinkinfo") else "ibdiagnet"
                for call in calls if call[-1].endswith("/iblinkinfo") or "--rail_validation" in call]

    def test_three_ibdiagnet_failures_switch_to_iblinkinfo_and_every_sixth_run_tries_ibdiagnet(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        for attempt in (1, 2, 3):
            result = self.run_cron(FAKE_IBDIAGNET_NO_NET_DUMP="1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(self.counts(), (attempt, 0))
            self.assertIn("cron finish with UFM warnings", result.stdout)
        self.assertIn("已连续失败 3 次：之后改采 iblinkinfo", result.stdout)
        self.assertEqual(self.kinds_run(), ["ibdiagnet"] * 3)
        result = self.run_cron(FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.kinds_run()[-1], "iblinkinfo", "the fourth run collects iblinkinfo")
        [log] = [name for name in self.ibdiag_archives() if name.endswith("_iblinkinfo.log")]
        self.assertRegex(log, r"^\d{8}-\d{4}-prod-[0-9a-f]{16}_ufm02_iblinkinfo\.log$")
        self.assertTrue((self.p2p_output / log.replace("_iblinkinfo.log", "-iblinkinfo-topology-validation.xlsx")).is_file())
        self.assertEqual(self.counts(), (3, 1), "an iblinkinfo run only advances the countdown")
        # the sixth run in that state tries ibdiagnet again; a success clears the count
        self.state_file().write_text("failures=3\nsince_probe=5\n")
        result = self.run_cron()
        self.assertEqual(self.kinds_run()[-1], "ibdiagnet")
        self.assertIn("本轮再试一次 ibdiagnet", result.stdout)
        self.assertIn("ibdiagnet 恢复成功", result.stdout)
        self.assertEqual(self.counts(), (0, 0))

    def run_record(self):
        [path] = list(self.ibdiag_output.glob("*.ufm-run.json"))
        self.assertRegex(path.name, r"^\d{8}-\d{4}-prod-[0-9a-f]{16}\.ufm-run\.json$")
        return json.loads(path.read_text())

    def test_every_run_leaves_a_record_naming_only_its_own_files(self):
        # Codex review 2026-10-22: what each run did is persisted; a failed or skipped run names no
        # report, so an older report can never be counted for it.
        import hashlib
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.run_record()
        [archive] = self.ibdiag_archives()
        run_id = archive.split("_", 1)[0]
        stem = f"{run_id}_ufm02-ibdiagnet-topology-validation"
        self.assertEqual((record["schema"], record["outcome"], record["run_id"], record["node"], record["kind"],
                          record["analysis"], record["cycle"]),
                         ("ufm-ib-run-record-v1", "ok", run_id, "ufm02", "ibdiagnet", "ok", None))
        for key, path in (("input", self.ibdiag_output / archive),
                          ("done", self.ibdiag_output / archive.replace(".tgz", ".done")),
                          ("report", self.p2p_output / f"{stem}.xlsx"),
                          ("receipt", self.p2p_output / f"{stem}.receipt.json")):
            content = path.read_bytes()
            self.assertEqual(record[key], {"name": path.name, "sha256": hashlib.sha256(content).hexdigest(),
                                           "size": len(content)}, key)
        receipt = json.loads((self.p2p_output / f"{stem}.receipt.json").read_text())
        self.assertEqual(receipt["done"]["sha256"], record["done"]["sha256"], "the receipt names this .done")

    def test_a_worker_run_record_carries_the_worker_cycle_identity(self):
        # Codex review 2026-10-22: REQ7 maps a worker cycle to this run through the record, not by time.
        import hashlib
        import tempfile
        identity = {"cycle_id": "c" * 64, "project_key": "site", "run_token": "t" * 32,
                    "scope": "infiniband/prod", "sequence": 7, "source": "page"}
        plan = {"eth": [], "spx": [], "ib": [], "nv": [], "dynamic_identities": [],
                "ufm": [f"{name}|{ip}" for name, (ip, _mac) in UFMS.items()]}
        plan_line = (json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        inventory = self.project / "02-devices_config.csv"
        context = {"identity": identity, "target_plan": plan,
                   "target_plan_sha256": hashlib.sha256(plan_line).hexdigest(),
                   "artifacts": {"input_inventory": str(inventory)},
                   "input_inventory_sha256": hashlib.sha256(inventory.read_bytes()).hexdigest()}
        self.state["vip"] = {VIP: "198.51.101.132"}
        with tempfile.TemporaryFile() as handle:
            handle.write(json.dumps(context).encode())
            handle.flush()
            handle.seek(0)
            result = self.run_cron("--worker-context-fd", str(handle.fileno()), pass_fds=(handle.fileno(),))
        self.assertIn("loaded frozen target plan", result.stdout, result.stdout + result.stderr)
        record = self.run_record()
        self.assertEqual((record["cycle"], record["outcome"]), (identity, "ok"), result.stdout + result.stderr)

    def test_a_failed_run_is_recorded_with_its_own_done_and_no_report(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        result = self.run_cron(FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.run_record()
        self.assertEqual((record["outcome"], record["input"], record["report"], record["receipt"],
                          record["analysis"], record["ibdiagnet_failures_in_a_row"]),
                         ("failed", None, None, None, "not_run", 1))
        self.assertIn("net_dump", record["reason"])
        done = self.ibdiag_output / record["done"]["name"]
        self.assertIn("result=failed", done.read_text(), "the UFM's failed .done is kept as evidence")
        self.assertEqual(self.ibdiag_archives(), [])

    def test_a_skipped_run_is_recorded_as_skipped(self):
        result = self.run_cron()   # no device holds the VIP
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = self.run_record()
        self.assertEqual((record["outcome"], record["run_id"], record["done"], record["report"]),
                         ("skipped", None, None, None))
        self.assertIn("HA 未就绪", record["reason"])

    def test_a_second_run_in_the_same_minute_never_replaces_an_archive(self):
        # Codex review 2026-10-22: minute names; a rerun within the minute fails instead of overwriting.
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        kept = {}
        for moment in (now, now + timedelta(minutes=1)):
            path = self.output / (moment.strftime("%Y%m%d-%H%M") + ".tar.gz")
            path.write_bytes(b"first run")
            kept[path] = b"first run"
        result = self.run_cron()
        self.assertIn("already exists (not replaced)", result.stdout)
        for path, content in kept.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertIn("cron finish with UFM warnings", result.stdout)

    def test_a_skipped_run_does_not_touch_the_failure_count(self):
        self.ibdiag_output.mkdir(exist_ok=True)
        self.state_file().write_text("failures=2\nsince_probe=0\n")
        result = self.run_cron()   # no device holds the VIP: HA not ready
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state_file().read_text(), "failures=2\nsince_probe=0\n")

    def test_everything_collected_is_kept_three_days_and_the_two_days_before_today_are_bundled(self):
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc)
        yesterday, old = ((today - timedelta(days=days)).strftime("%Y%m%d") for days in (1, 4))
        for day in (yesterday, old):
            for suffix in ("_ufm01_ibdiagnet2.tgz", "_ufm01_ibdiagnet2.done", "_ufm02_iblinkinfo.log"):
                (self.ibdiag_output / f"{day}-0100-prod-0000000000000001{suffix}").write_text("x")
        link = self.mkdir("infiniband/monitor/ib-link")
        for day in (yesterday, old):
            (link / f"{day}-0100.csv").write_text("csv")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        today_name = today.strftime("%Y%m%d")
        names = sorted(path.name for path in self.ibdiag_output.iterdir() if not path.name.startswith(today_name))
        self.assertEqual(names, [f"{yesterday}-daily.tar.gz"], "yesterday bundled, four days ago deleted")
        members = [f"{yesterday}-0100-prod-0000000000000001{suffix}"
                   for suffix in ("_ufm01_ibdiagnet2.tgz", "_ufm01_ibdiagnet2.done", "_ufm02_iblinkinfo.log")]
        with tarfile.open(self.ibdiag_output / names[0]) as bundle:
            self.assertEqual(sorted(bundle.getnames()), sorted(members + [f"{yesterday}-daily.index"]))
            index = bundle.extractfile(f"{yesterday}-daily.index").read().decode()
        # codex review 2026-10-22: every member by sha256, size and its original name
        import hashlib
        self.assertEqual(sorted(index.splitlines()), sorted(
            f"{hashlib.sha256(b'x').hexdigest()}  1  {name}" for name in members))
        self.assertFalse(list(self.ibdiag_output.glob("*.part")))
        self.assertEqual(sorted(path.name for path in link.iterdir()), [f"{yesterday}-0100.csv"],
                         "CSVs stay unbundled for the page, and go after three days")

    def test_cronjob_log_is_compressed_at_10_mb_keeping_seven_copies(self):
        import gzip
        real = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband") / "cronjob.log"
        real.write_bytes(b"first line\n" + b"x" * (10 * 1024 * 1024))
        (self.root / "infiniband/monitor/cronjob.log").symlink_to(real)
        for number in range(1, 8):
            with gzip.open(real.with_name(f"cronjob.log.{number}.gz"), "wb") as handle:
                handle.write(f"copy {number}\n".encode())
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(real.stat().st_size, 0, "emptied in place: the crontab redirection keeps writing to it")
        self.assertTrue((self.root / "infiniband/monitor/cronjob.log").is_symlink())
        with gzip.open(real.with_name("cronjob.log.1.gz")) as handle:
            self.assertTrue(handle.read().startswith(b"first line\n"))
        for number in range(2, 8):
            with gzip.open(real.with_name(f"cronjob.log.{number}.gz")) as handle:
                self.assertEqual(handle.read(), f"copy {number - 1}\n".encode())
        self.assertFalse(real.with_name("cronjob.log.8.gz").exists(), "at most seven copies")
        self.assertIn("cronjob.log 达到", result.stdout)

    def test_dated_reports_in_99_output_p2p_follow_the_same_rule_and_the_cvt_stays(self):
        # Owner 2026-10-22: every file with a date in its name follows the cron.sh rule, reports too.
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc)
        yesterday, old = ((today - timedelta(days=days)).strftime("%Y%m%d") for days in (1, 4))
        (self.root / "monitor/99-output-p2p").symlink_to(self.p2p_output)   # the page's setup link
        names = ("-0100-prod-0000000000000001_ufm01-ibdiagnet-topology-validation.xlsx",
                 "-0100-prod-0000000000000001_ufm01-ibdiagnet-topology-validation.xlsx.provenance.json",
                 "-0100-prod-0000000000000001_ufm01-ibdiagnet-topology-validation.receipt.json",
                 "-0100-prod-ethernet-topology-validation.xlsx")
        for day in (yesterday, old):
            for name in names:
                (self.p2p_output / f"{day}{name}").write_text("x")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # the hidden report lock lives in the directory (codex review 2026-10-22) and is not data
        self.assertTrue((self.p2p_output / ".report-writer.lock").is_file())
        self.assertEqual(sorted(path.name for path in self.p2p_output.iterdir() if not path.name.startswith(".")),
                         sorted(["site-cvt.xlsx", f"{yesterday}-daily.tar.gz"]))
        with tarfile.open(self.p2p_output / f"{yesterday}-daily.tar.gz") as bundle:
            self.assertEqual(sorted(bundle.getnames()),
                             sorted([f"{yesterday}{name}" for name in names] + [f"{yesterday}-daily.index"]))

    def test_cron_leaves_the_logs_other_scripts_write_to_them(self):
        # Owner 2026-10-22: whoever writes a log rotates it; cron.sh rotates only its cronjob.log
        # (test_log_rotation covers the generator and the worker rotating their own).
        logs = [self.root / "monitor/generate-monitor.log", self.mkdir("monitor/status") / "switch-collection.log"]
        for log in logs:
            log.write_bytes(b"x" * (10 * 1024 * 1024))
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for log in logs:
            self.assertEqual(log.stat().st_size, 10 * 1024 * 1024, log.name)
            self.assertFalse(log.with_name(log.name + ".1.gz").exists(), log.name)

    def test_a_small_cronjob_log_is_left_alone(self):
        real = self.mkdir("DAY0-Prepare/site/99-output-monitor/infiniband") / "cronjob.log"
        real.write_text("short\n")
        (self.root / "infiniband/monitor/cronjob.log").symlink_to(real)
        self.run_cron()
        self.assertEqual(real.read_text(), "short\n")
        self.assertFalse(real.with_name("cronjob.log.1.gz").exists())

    def test_a_run_that_finds_the_previous_one_still_running_says_so_and_skips(self):
        self.write_exec(self.bin / "flock", "#!/bin/sh\nexit 1\n")   # the lock is held
        result = self.run_cron()
        self.assertEqual(result.returncode, 1)
        self.assertIn("上一轮采集仍在运行", result.stderr)
        self.assertIn("本轮跳过", result.stderr)
        self.assertFalse(self.calls.exists(), "nothing is contacted")


REAL_FLOCK = r'''#!{python}
"""flock(1) for the tests: locks the inherited descriptor, as util-linux does (-n, -s, -w seconds)."""
import fcntl, sys, time
mode, blocking, wait, fd, args = fcntl.LOCK_EX, True, None, None, sys.argv[1:]
while args:
    arg = args.pop(0)
    if arg == "-n":
        blocking = False
    elif arg == "-s":
        mode = fcntl.LOCK_SH
    elif arg == "-w":
        wait = float(args.pop(0))
    else:
        fd = int(arg)
deadline = None if wait is None else time.monotonic() + wait
while True:
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
        sys.exit(0)
    except BlockingIOError:
        if not blocking or (deadline is not None and time.monotonic() >= deadline):
            sys.exit(1)
        time.sleep(0.05)
'''


class UfmSharedReportCleanupTest(UfmCronCase):
    """Codex review 2026-10-22: the shared 99-output-p2p is written by the post-collect of every lane and
    cleaned by whichever lane finishes; a report still being written is never bundled or deleted, a file
    that arrives after its day was bundled stays beside the bundle, and an old day leaves in full."""

    def setUp(self):
        super().setUp()
        self.write_exec(self.bin / "flock", REAL_FLOCK.replace("{python}", sys.executable))
        (self.root / "monitor/99-output-p2p").symlink_to(self.p2p_output)   # the page's setup link

    @staticmethod
    def days(*ago):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        return [(now - timedelta(days=days)).strftime("%Y%m%d") for days in ago]

    def test_the_cleanup_leaves_reports_alone_while_a_report_is_being_written(self):
        import fcntl
        [yesterday] = self.days(1)
        report = self.p2p_output / f"{yesterday}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx"
        report.write_text("half written")
        with open(self.p2p_output / ".report-writer.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)   # another lane's post-collect is writing
            result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report.read_text(), "half written")
        self.assertFalse((self.p2p_output / f"{yesterday}-daily.tar.gz").exists())
        self.assertIn("正在写报告", result.stdout)
        result = self.run_cron()   # the writer is gone: the day is bundled as usual
        self.assertFalse(report.exists())
        self.assertTrue((self.p2p_output / f"{yesterday}-daily.tar.gz").is_file())

    def test_the_ib_report_is_written_under_the_shared_report_lock(self):
        self.state["vip"] = {VIP: "198.51.101.132"}
        probe = self.root / "lock-probe"
        result = self.run_cron(FAKE_REPORT_LOCK_PROBE=str(probe))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(probe.read_text(), "held", "the cleanup of another lane cannot take the directory")

    def test_a_late_file_stays_beside_the_bundle_of_its_day(self):
        [yesterday] = self.days(1)
        (self.p2p_output / f"{yesterday}-0100-prod-ethernet-topology-validation.xlsx").write_text("x")
        self.run_cron()
        bundle = self.p2p_output / f"{yesterday}-daily.tar.gz"
        before = bundle.read_bytes()
        # a run that started before midnight published its report after the day was bundled
        late = self.p2p_output / f"{yesterday}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx"
        late.write_text("late")
        result = self.run_cron()
        self.assertEqual((late.read_text(), bundle.read_bytes()), ("late", before), "neither is rewritten")
        self.assertIn("1 个迟到文件", result.stdout)

    def test_an_old_day_kept_only_as_a_bundle_is_deleted_with_its_late_files(self):
        [old] = self.days(4)
        for directory in (self.p2p_output, self.ibdiag_output):
            (directory / f"{old}-daily.tar.gz").write_bytes(b"bundle")
        late = self.p2p_output / f"{old}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx"
        late.write_text("late")
        result = self.run_cron()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for directory in (self.p2p_output, self.ibdiag_output):
            self.assertEqual([path.name for path in directory.iterdir() if path.name.startswith(old)], [], directory)
        self.assertTrue((self.p2p_output / "site-cvt.xlsx").is_file(), "the CVT has no date and stays")


if __name__ == "__main__":
    unittest.main()
