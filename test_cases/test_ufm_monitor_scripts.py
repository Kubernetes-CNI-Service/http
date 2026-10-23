"""Direct tests for the UFM collectors that cron.sh runs on the UFM (infiniband/monitor/UFM-MONITOR.md)."""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UFM_INFO = ROOT / "infiniband/monitor/ufm-info.sh"
UFM_IBDIAGNET = ROOT / "infiniband/monitor/ufm-ibdiagnet.sh"
HOST = "ufm01.example.test"

# The Switch Status columns, in the order the owner verified them on a UFM (2026-10-21).
EXPECTED_COMMANDS = [
    "hostname",
    "dmidecode -s system-serial-number",
    "dmidecode -s system-manufacturer",
    "dmidecode -s system-product-name",
    "dmidecode -s bios-version",
    "cat /etc/ufm-release",
    "cat /etc/os-release",
    "uname -r",
    "lsblk -d -o NAME,MODEL,SERIAL,REV,SIZE,TYPE",
    "ibstat",
    "mget_temp -d mlx5_0",
    "mget_temp -d mlx5_1",
    "ipmitool sdr type Temperature",
    "ipmitool sdr type 'Power Supply'",
    "ipmitool sdr type Fan",
    "top -bn2 -d 1",
    "df -PT",
    "free -b",
    "timedatectl",
    "ip -br link",
    "ip -br addr",
    "systemctl is-active ufm-enterprise",
    "systemctl list-units 'ufm*' --no-pager",
    "uptime -p",
]

# Owner 2026-10-21: the HA state is read only on the primary, through the VIP (ufm-info.sh --ha).
EXPECTED_HA_COMMANDS = [
    "hostname",
    "ip -br link",
    "ufm_ha_cluster status",
    "ufm_enterprise_sanity.sh",
]

FAKES = {
    "hostname": f'echo "{HOST}"',
    "dmidecode": 'case "$2" in system-serial-number) echo SN0001;; system-manufacturer) echo NVIDIA;; '
                 'system-product-name) echo UFM3.5;; bios-version) echo 2.8.2;; esac',
    "uname": "echo 6.8.0-test",
    "lsblk": 'echo "NAME MODEL SERIAL REV SIZE TYPE"; echo "nvme0n1 TestDisk S1 3.0.1 2.9T disk"',
    "ibstat": "echo \"CA 'mlx5_0'\"; echo '        Firmware version: 40.50.1002'",
    "mget_temp": 'echo "temp-of-$2"',
    "ipmitool": 'echo "sdr $*"',
    "top": 'echo "%Cpu(s):  1.0 us"',
    "df": 'echo "Filesystem Type 1024-blocks Used Available Capacity Mounted on"',
    "free": 'echo "Mem: 100 10 90"',
    "timedatectl": 'echo "System clock synchronized: no"',
    "ip": 'echo "ip $*"',
    "ufm_ha_cluster": 'echo "Online: [ ufm01 ufm02 ]"',
    "ufm_enterprise_sanity.sh": 'echo "Sanity tests completed successfully!"',
    "systemctl": 'echo "systemctl $*"',
    "uptime": 'echo "up 1 day"',
}


class UfmInfoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        for name, body in FAKES.items():
            self.fake(name, body)
        self.sysfs = self.base / "sys-infiniband"
        for device in ("mlx5_0", "mlx5_1", "smi0", "smi1"):
            (self.sysfs / device).mkdir(parents=True)
        self.work = self.base / "root"
        self.work.mkdir()
        self.lock_tmp = self.base / "tmp"
        self.lock_tmp.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def fake(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    def run_info(self, *args):
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   TMPDIR=str(self.lock_tmp), UFM_INFO_IB_SYSFS=str(self.sysfs))
        return subprocess.run(["bash", str(UFM_INFO), *args], cwd=self.work, env=env,
                              capture_output=True, text=True, timeout=60)

    def snapshot(self):
        return (self.work / "monitor" / f"{HOST}.info").read_text(encoding="utf-8")

    def test_snapshot_has_every_switch_status_command_in_the_sw_info_layout(self):
        result = self.run_info()
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.snapshot()
        self.assertIn(f"Device:       {HOST}\n", text)
        self.assertIn("Server Type:  UFM\n", text)
        self.assertRegex(text, r"Collect Time: \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\n")
        self.assertEqual(re.findall(r"^# Execute Command: (.*)$", text, re.M), EXPECTED_COMMANDS)
        self.assertTrue(text.endswith("\n====================================================\n# Collect complete\n"
                                      "====================================================\n"), text[-200:])
        self.assertIn("temp-of-mlx5_1", text)
        self.assertIn("SN0001", text)
        self.assertEqual(sorted(path.name for path in (self.work / "monitor").iterdir()), [f"{HOST}.info"],
                         "only the finished snapshot is left behind")

    def test_hca_temperature_skips_the_smi_views_of_the_same_hca(self):
        self.run_info()
        self.assertNotIn("mget_temp -d smi", self.snapshot())

    def test_a_failing_command_is_recorded_and_the_snapshot_still_completes(self):
        self.fake("ipmitool", 'echo "Could not open device at /dev/ipmi0" >&2; exit 1')
        result = self.run_info()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Could not open device at /dev/ipmi0", self.snapshot())
        self.assertIn("# Collect complete", self.snapshot())

    def test_a_running_collection_is_not_started_twice(self):
        lock = self.lock_tmp / "ufm-info.lock"
        lock.mkdir()
        (lock / "pid").write_text(f"{os.getpid()}\n")   # a live process holds it
        result = self.run_info()
        self.assertEqual(result.returncode, 1)
        self.assertIn("still running", result.stderr)
        self.assertFalse((self.work / "monitor" / f"{HOST}.info").exists())

    def test_a_lock_being_taken_is_not_mistaken_for_a_stale_one(self):
        lock = self.lock_tmp / "ufm-info.lock"
        lock.mkdir()   # another run has just made it and not yet written its pid
        result = self.run_info()
        self.assertEqual(result.returncode, 1)
        self.assertIn("still running", result.stderr)
        os.utime(lock, (time.time() - 600, time.time() - 600))
        self.assertEqual(self.run_info().returncode, 0, "a lock left without a pid for long is stale")

    def test_an_interrupted_collection_publishes_nothing(self):
        self.fake("dmidecode", "sleep 3")
        environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                           TMPDIR=str(self.lock_tmp), UFM_INFO_IB_SYSFS=str(self.sysfs))
        process = subprocess.Popen(["bash", str(UFM_INFO)], cwd=self.work, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + 20
            while not (self.lock_tmp / "ufm-info.lock" / "pid").exists():
                self.assertLess(time.time(), deadline)
                time.sleep(0.1)
            time.sleep(0.5)
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=40)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse((self.work / "monitor" / f"{HOST}.info").exists())
        self.assertFalse((self.lock_tmp / "ufm-info.lock").exists())

    def test_an_unsafe_hostname_is_refused(self):
        self.fake("hostname", 'echo "bad;host"')
        result = self.run_info()
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.work / "monitor").exists())

    def test_the_ha_mode_reads_only_the_cluster_state_into_its_own_file(self):
        result = self.run_info("--ha")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(path.name for path in (self.work / "monitor").iterdir()), [f"{HOST}.ha"])
        text = (self.work / "monitor" / f"{HOST}.ha").read_text(encoding="utf-8")
        self.assertIn("Server Type:  UFM-HA\n", text)
        self.assertEqual(re.findall(r"^# Execute Command: (.*)$", text, re.M), EXPECTED_HA_COMMANDS)
        self.assertIn("Sanity tests completed successfully!", text)
        self.assertTrue(text.endswith("# Collect complete\n====================================================\n"))

    def test_the_ha_mode_runs_beside_the_node_collection_on_the_vip_holder(self):
        lock = self.lock_tmp / "ufm-info.lock"
        lock.mkdir()
        (lock / "pid").write_text(f"{os.getpid()}\n")   # this node's own snapshot is being taken
        self.assertEqual(self.run_info("--ha").returncode, 0)
        self.assertTrue((self.work / "monitor" / f"{HOST}.ha").exists())
        held = self.lock_tmp / "ufm-info-ha.lock"
        held.mkdir()
        (held / "pid").write_text(f"{os.getpid()}\n")
        result = self.run_info("--ha")
        self.assertEqual(result.returncode, 1)
        self.assertIn("still running", result.stderr)

    def test_an_unknown_option_is_refused(self):
        result = self.run_info("--bogus")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.work / "monitor").exists())

    def test_the_collector_only_reads(self):
        source = UFM_INFO.read_text(encoding="utf-8")
        commands = re.findall(r'^\s*"([^"]+)"\s*$', source, re.M)
        for command in commands:
            self.assertNotRegex(command, r"\b(set|start|stop|restart|enable|disable|reset|delete|write)\b", command)
        self.assertEqual(subprocess.run(["bash", "-n", str(UFM_INFO)]).returncode, 0)


# D-70 fixed arguments, run inside the UFM container exactly as the owner does by hand (2026-10-21).
IBDIAGNET_ARGV = ["/opt/ufm/opensm/bin/ibdiagnet", "--sc", "--extended_speeds", "all", "-P", "all=1",
                  "--pm_per_lane", "--get_cable_info", "--cable_info_disconnected", "--get_phy_info",
                  "--routing", "--sharp", "--phy_cable_disconnected", "--rail_validation"]
RUN_ID = "20261021-0322-prod-3f9c0a1b2c3d4e5f"

# A stand-in for `docker exec ufm ...`: the container's /var/tmp and /opt/ufm/files live under
# FAKE_CONTAINER (the test points UFM_HOST_FILES at the same /opt/ufm/files, as the master's bind mount
# does); every call is logged.
FAKE_DOCKER = r"""#!{python}
import json, os, shutil, subprocess, sys, time
root = os.environ["FAKE_CONTAINER"]
def inside(path):
    return root + path if path.startswith(("/var/tmp", "/opt/ufm/files")) else path
with open(os.environ["FAKE_DOCKER_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if os.environ.get("FAKE_DOCKER_DOWN"):
    print("Error response from daemon: container ufm is not running", file=sys.stderr)
    sys.exit(1)
if args[0] == "cp":
    shutil.copy(inside(args[1].split(":", 1)[1]), args[2])
    sys.exit(0)
assert args[:2] == ["exec", "ufm"], args
command = args[2:]
if command[:2] == ["sh", "-c"] and len(command) > 4 and command[4].endswith(("/ibdiagnet", "/iblinkinfo")):
    command = command[4:]   # `sh -c <timeout wrapper> sh <tool argv>`: the wrapper is in the log
if command[0].endswith("/ibdiagnet"):
    if os.environ.get("FAKE_IBDIAGNET_STALE"):
        print("-E- ibdiagnet could not start")
        sys.exit(1)
    out = root + "/var/tmp/ibdiagnet2"
    os.makedirs(out, exist_ok=True)
    with open(out + "/ibdiagnet2.log", "w") as handle:
        handle.write("ibdiagnet run " + " ".join(command[1:]) + "\n")
    with open(out + "/ibdiagnet2.db_csv", "w") as handle:
        handle.write("db\n")
    time.sleep(float(os.environ.get("FAKE_IBDIAGNET_SLEEP", "0")))
    if not os.environ.get("FAKE_IBDIAGNET_NO_NET_DUMP"):   # a run that stops half way leaves no net_dump
        with open(out + "/ibdiagnet2.net_dump", "w") as handle:
            handle.write("net dump\n")
    if os.environ.get("FAKE_IBDIAGNET_FIXTURE"):   # a real snapshot the analyzer can read (REQ7 R1 test)
        for name in os.listdir(os.environ["FAKE_IBDIAGNET_FIXTURE"]):
            if name != "ibdiagnet2.net_dump" or not os.environ.get("FAKE_IBDIAGNET_NO_NET_DUMP"):
                shutil.copy(os.path.join(os.environ["FAKE_IBDIAGNET_FIXTURE"], name), out + "/" + name)
    print("-I- Done")
    sys.exit(int(os.environ.get("FAKE_IBDIAGNET_RC", "0")))
if command[0].endswith("/iblinkinfo"):
    # ufm01 on 2026-10-22 printed warnings like this on stderr next to the link table on stdout
    print("Node Neighbor GUID of GUID: 0x0200000000000001 Port: 39 doesn't exist", file=sys.stderr)
    size = int(os.environ.get("FAKE_IBLINKINFO_BYTES", "0"))
    try:
        if not os.environ.get("FAKE_IBLINKINFO_EMPTY"):
            print("Switch: 0x0200000000000001 MF0;sw01:Q3400/U1:", flush=True)
        chunk = b"x" * 1048576
        while size > 0:
            sys.stdout.buffer.write(chunk[:size])
            size -= len(chunk)
        sys.stdout.flush()
    except BrokenPipeError:
        sys.exit(141)
    sys.exit(int(os.environ.get("FAKE_IBLINKINFO_RC", "0")))
if command[:2] == ["sh", "-c"]:
    script = command[2]
    for prefix in ("/var/tmp", "/opt/ufm/files"):
        script = script.replace(prefix, root + prefix)
    sys.exit(subprocess.call(["sh", "-c", script]))
if command[0] == "stat":
    print(int(os.stat(inside(command[-1])).st_mtime))
    sys.exit(0)
if command[:2] == ["rm", "-f"]:
    for path in command[2:]:
        if os.path.exists(inside(path)):
            os.remove(inside(path))
    sys.exit(0)
print("unexpected docker call", args, file=sys.stderr)
sys.exit(97)
"""


class UfmIbdiagnetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.container = self.base / "container"
        (self.container / "opt/ufm/files").mkdir(parents=True)
        (self.container / "var/tmp").mkdir(parents=True)
        self.docker_log = self.base / "docker.log"
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER.replace("{python}", sys.executable), encoding="utf-8")
        docker.chmod(0o755)
        for name, body in (("hostname", f'echo "{HOST}"'),
                           ("ip", 'echo "eno8303          UP             02:00:00:00:01:01 <UP>"')):
            path = self.bin / name
            path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
            path.chmod(0o755)
        self.work = self.base / "root"
        self.work.mkdir()
        self.lock_tmp = self.base / "tmp"
        self.lock_tmp.mkdir()
        self.out = self.work / "monitor/ibdiagnet"
        self.links = self.work / "monitor/iblinkinfo"

    def tearDown(self):
        self.tmp.cleanup()

    def run_ibdiagnet(self, *args, **env):
        environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                           TMPDIR=str(self.lock_tmp), FAKE_CONTAINER=str(self.container),
                           UFM_HOST_FILES=str(self.container / "opt/ufm/files"),
                           FAKE_DOCKER_LOG=str(self.docker_log), COPYFILE_DISABLE="1", **env)
        return subprocess.run(["bash", str(UFM_IBDIAGNET), *args], cwd=self.work, env=environment,
                              capture_output=True, text=True, timeout=60)

    def done(self, prefix="ibdiagnet2"):
        directory = self.out if prefix == "ibdiagnet2" else self.links
        text = (directory / f"{prefix}_{RUN_ID}.done").read_text(encoding="utf-8")
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    def docker_calls(self):
        return [json.loads(line) for line in self.docker_log.read_text().splitlines()]

    def test_the_owners_procedure_with_the_run_id_naming(self):
        result = self.run_ibdiagnet(RUN_ID)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.docker_calls()
        runs = [call for call in calls if call[-len(IBDIAGNET_ARGV):] == IBDIAGNET_ARGV]
        self.assertEqual(len(runs), 1, calls)
        self.assertEqual(runs[0][:4], ["exec", "ufm", "sh", "-c"], "D-70 arguments, inside the container, no -it")
        # Owner 2026-10-22: ibdiagnet runs at most 15 minutes.
        self.assertIn('exec timeout -k 30 900 "$@"', runs[0][4])
        # Owner 2026-10-22: the owner's name prefix plus the run-id (minute timestamp included), .tgz
        archive = self.out / f"ibdiagnet2_{RUN_ID}.tgz"
        with tarfile.open(archive) as bundle:
            names = bundle.getnames()
        self.assertIn("ibdiagnet2/ibdiagnet2.log", names)
        self.assertIn("ibdiagnet2/ibdiagnet2.net_dump", names)
        done = self.done()
        self.assertEqual((done["result"], done["kind"], done["run_id"], done["artifact"]),
                         ("ok", "ibdiagnet", RUN_ID, archive.name))
        self.assertEqual(done["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(done["size"], str(archive.stat().st_size))
        self.assertEqual(done["hostname"], HOST)
        self.assertIn("02:00:00:00:01:01", (self.out / f"ibdiagnet2_{RUN_ID}.node").read_text())
        # Owner 2026-10-22: /opt/ufm/files is the master's own directory mounted into the container,
        # so the archive is moved on the host; no docker cp.
        self.assertFalse([call for call in calls if call[0] == "cp"])
        self.assertEqual(list((self.container / "opt/ufm/files").iterdir()), [])
        self.assertFalse(list(self.out.glob("*.part")))
        self.assertFalse(self.links.exists(), "iblinkinfo is not run by default")

    def test_a_non_zero_ibdiagnet_exit_with_fresh_output_is_still_collected(self):
        result = self.run_ibdiagnet(RUN_ID, FAKE_IBDIAGNET_RC="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.done()["result"], self.done()["rc"]), ("ok", "1"))

    def test_output_left_by_an_earlier_run_is_never_collected(self):
        stale = self.container / "var/tmp/ibdiagnet2"
        stale.mkdir()
        (stale / "ibdiagnet2.log").write_text("old run\n")
        os.utime(stale / "ibdiagnet2.log", (1, 1))
        result = self.run_ibdiagnet(RUN_ID, FAKE_IBDIAGNET_STALE="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.done()["result"], "failed")
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.tgz").exists())
        self.assertFalse(any("/opt/ufm/opensm/sbin/iblinkinfo" in call for call in self.docker_calls()),
                         "a failed ibdiagnet does not fall back within the run")

    def test_a_run_without_net_dump_is_not_a_success(self):
        # Owner 2026-10-22: no ibdiagnet2.net_dump, no success; a half-finished run must not pass as ok.
        for env in ({"FAKE_IBDIAGNET_NO_NET_DUMP": "1"}, {"FAKE_IBDIAGNET_NO_NET_DUMP": "1", "FAKE_IBDIAGNET_RC": "124"}):
            with self.subTest(env=env):
                shutil.rmtree(self.out, ignore_errors=True)
                shutil.rmtree(self.container / "var/tmp/ibdiagnet2", ignore_errors=True)
                result = self.run_ibdiagnet(RUN_ID, **env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                done = self.done()
                self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
                self.assertIn("ibdiagnet2.net_dump", done["reason"])
                if env.get("FAKE_IBDIAGNET_RC") == "124":
                    self.assertIn("900", done["reason"], "the timeout is named")
                self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.tgz").exists())

    def test_an_old_net_dump_left_in_place_is_not_this_runs_output(self):
        stale = self.container / "var/tmp/ibdiagnet2"
        stale.mkdir()
        (stale / "ibdiagnet2.net_dump").write_text("old\n")
        os.utime(stale / "ibdiagnet2.net_dump", (1, 1))
        result = self.run_ibdiagnet(RUN_ID, FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.done()["result"], "failed")

    def test_an_interrupted_run_writes_no_done_marker_and_frees_the_lock(self):
        # Owner 2026-10-22: INT/TERM must end the script; it must not go on and write .done.
        environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                           TMPDIR=str(self.lock_tmp), FAKE_CONTAINER=str(self.container),
                           UFM_HOST_FILES=str(self.container / "opt/ufm/files"),
                           FAKE_DOCKER_LOG=str(self.docker_log), COPYFILE_DISABLE="1", FAKE_IBDIAGNET_SLEEP="3")
        process = subprocess.Popen(["bash", str(UFM_IBDIAGNET), RUN_ID], cwd=self.work, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + 20
            while not (self.container / "var/tmp/ibdiagnet2/ibdiagnet2.log").exists():
                self.assertLess(time.time(), deadline, "ibdiagnet never started")
                time.sleep(0.1)
            process.send_signal(signal.SIGTERM)   # bash acts on it once ibdiagnet returns
            process.communicate(timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.done").exists())
        self.assertFalse((self.lock_tmp / "ufm-ibdiagnet.lock").exists())

    def test_a_lock_being_taken_is_not_mistaken_for_a_stale_one(self):
        # Owner 2026-10-22: between mkdir and writing the pid the lock has no pid; that is not stale.
        lock = self.lock_tmp / "ufm-ibdiagnet.lock"
        lock.mkdir()
        result = self.run_ibdiagnet(RUN_ID)
        self.assertEqual(result.returncode, 1)
        self.assertIn("still running", result.stderr)
        self.assertFalse(self.docker_log.exists())
        os.utime(lock, (time.time() - 600, time.time() - 600))   # long without a pid: really left behind
        self.assertEqual(self.run_ibdiagnet(RUN_ID).returncode, 0)

    def test_the_iblinkinfo_mode_keeps_stdout_only(self):
        # Owner 2026-10-22: iblinkinfo only when cron.sh switched to it; stdout only, as the owner runs it.
        result = self.run_ibdiagnet(RUN_ID, "--iblinkinfo")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.docker_calls()
        self.assertFalse([call for call in calls if call[-len(IBDIAGNET_ARGV):] == IBDIAGNET_ARGV])
        [run] = [call for call in calls if call[-1] == "/opt/ufm/opensm/sbin/iblinkinfo"]
        self.assertIn('exec timeout -k 30 900 "$@"', run[4])
        log = self.links / f"iblinkinfo_{RUN_ID}.log"
        done = self.done("iblinkinfo")
        self.assertEqual((done["result"], done["kind"], done["artifact"]), ("ok", "iblinkinfo", log.name))
        self.assertEqual(done["sha256"], hashlib.sha256(log.read_bytes()).hexdigest())
        self.assertIn("Switch: 0x0200000000000001", log.read_text())
        self.assertNotIn("doesn't exist", log.read_text(), "warnings never mix into the analyser input")
        self.assertIn("doesn't exist", (self.links / f"iblinkinfo_{RUN_ID}.stderr").read_text())
        self.assertFalse(self.out.exists())

    def test_an_iblinkinfo_output_over_the_limit_or_without_switches_fails(self):
        for env, needle in (({"FAKE_IBLINKINFO_BYTES": str(64 * 1024 * 1024 + 10)}, "exceeds 67108864 bytes"),
                            ({"FAKE_IBLINKINFO_EMPTY": "1"}, "no switch lines"),
                            ({"FAKE_IBLINKINFO_RC": "124"}, "timed out after 900s")):
            with self.subTest(env=sorted(env)):
                shutil.rmtree(self.links, ignore_errors=True)
                result = self.run_ibdiagnet(RUN_ID, "--iblinkinfo", **env)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                done = self.done("iblinkinfo")
                self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
                self.assertIn(needle, done["reason"])
                self.assertFalse(list(self.links.glob("*.log*")), "no partial output is left")

    def test_an_invalid_run_id_writes_nothing(self):
        for bad in ("", "latest", "20261021-0322-prod-xyz", "20261021-0322-prod-3f9c0a1b2c3d4e5f/../x"):
            result = self.run_ibdiagnet(bad)
            self.assertEqual(result.returncode, 2, bad)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.docker_log.exists())

    def test_without_arguments_it_runs_on_its_own_with_a_run_id_of_the_same_form(self):
        # Owner 2026-10-21: every script is self-contained and runs without its caller.
        result = self.run_ibdiagnet()
        self.assertEqual(result.returncode, 0, result.stderr)
        match = re.search(r"^run-id: (\d{8}-\d{4}-prod-[0-9a-f]{16})$", result.stdout, re.M)
        self.assertIsNotNone(match, result.stdout)
        done = self.out / f"ibdiagnet2_{match.group(1)}.done"
        self.assertIn("result=ok", done.read_text(encoding="utf-8"))

    def test_only_the_latest_three_runs_stay_on_the_ufm(self):
        self.out.mkdir(parents=True)
        for minute, age in (("0100", 400), ("0200", 300), ("0300", 200)):
            old = f"20261021-{minute}-prod-0000000000000000"
            for suffix in (".tgz", ".done", ".node", ".log"):
                path = self.out / f"ibdiagnet2_{old}{suffix}"
                path.write_text("old\n")
                os.utime(path, (time.time() - age, time.time() - age))
        self.run_ibdiagnet(RUN_ID)
        kept = sorted(path.name for path in self.out.glob("*.tgz"))
        self.assertEqual(kept, sorted([f"ibdiagnet2_{RUN_ID}.tgz",
                                       "ibdiagnet2_20261021-0300-prod-0000000000000000.tgz",
                                       "ibdiagnet2_20261021-0200-prod-0000000000000000.tgz"]))
        self.assertFalse(list(self.out.glob("ibdiagnet2_20261021-0100-*")), "its .done/.node/.log go too")

    def test_a_running_collection_is_not_started_twice(self):
        lock = self.lock_tmp / "ufm-ibdiagnet.lock"
        lock.mkdir()
        (lock / "pid").write_text(f"{os.getpid()}\n")
        result = self.run_ibdiagnet(RUN_ID)
        self.assertEqual(result.returncode, 1)
        self.assertIn("still running", result.stderr)
        self.assertFalse(self.docker_log.exists())

    def test_the_collector_only_reads_the_fabric(self):
        source = UFM_IBDIAGNET.read_text(encoding="utf-8")
        self.assertNotIn("docker exec -it", source)
        self.assertEqual(subprocess.run(["bash", "-n", str(UFM_IBDIAGNET)]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
