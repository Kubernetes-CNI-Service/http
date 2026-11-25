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

    def test_missing_mst_devices_are_loaded_once_before_the_hca_temperature(self):
        # Owner 2026-10-23 (lab): on the standby UFM `mst status -v` listed no /dev/mst device until
        # `mst start` ran, and every mget_temp failed with "mopen: No such file or directory".
        marker = self.base / "mst-started"
        self.fake("mst", f'case "$1" in status) echo "MST PCI module is not loaded";; '
                         f'start) echo started >> "{marker}"; echo "Loading MST PCI module - Success";; esac')
        result = self.run_info()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = re.findall(r"^# Execute Command: (.*)$", self.snapshot(), re.M)
        first_temp = EXPECTED_COMMANDS.index("mget_temp -d mlx5_0")
        self.assertEqual(EXPECTED_COMMANDS[:first_temp] + ["mst start"] + EXPECTED_COMMANDS[first_temp:], commands)
        self.assertEqual("started\n", marker.read_text(), "loaded exactly once")
        self.assertIn("Loading MST PCI module - Success", self.snapshot())
        self.assertIn("temp-of-mlx5_0", self.snapshot())

    def test_loaded_mst_devices_are_left_alone(self):
        marker = self.base / "mst-started"
        self.fake("mst", f'case "$1" in status) echo "ConnectX8(rev:0)  /dev/mst/mt4131_pciconf0  0d:00.0";; '
                         f'start) echo started >> "{marker}";; esac')
        result = self.run_info()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(EXPECTED_COMMANDS, re.findall(r"^# Execute Command: (.*)$", self.snapshot(), re.M))
        self.assertFalse(marker.exists())

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


# D-70 fixed arguments, run inside the UFM container exactly as the owner does by hand (2026-10-21);
# Q-057 (I-065): the periodic collection drops only --routing, the rest keeps its content and order.
IBDIAGNET_ARGV = ["/opt/ufm/opensm/bin/ibdiagnet", "--sc", "--extended_speeds", "all", "-P", "all=1",
                  "--pm_per_lane", "--get_cable_info", "--cable_info_disconnected", "--get_phy_info",
                  "--sharp", "--phy_cable_disconnected", "--rail_validation"]
# I-065 fixed expectation (Q-056, http dev material section 6 C1 :296-297): a run that timed out (124/137)
# but left this run's net_dump, archived, stays ok with its rc and carries this reason.
PARTIAL_NOTICE = "ibdiagnet timed out after 900s; partial output"
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
# R-037 (owner 2026-11-20): `docker ps -a` names the ufm container whether it runs or not (a stopped
# container still lists); FAKE_DOCKER_PS=empty: docker without a ufm container, =fail: daemon unreachable.
if args[:2] == ["ps", "-a"]:
    listing = os.environ.get("FAKE_DOCKER_PS", "")
    if listing == "fail":
        print("Cannot connect to the Docker daemon", file=sys.stderr)
        sys.exit(1)
    if listing != "empty":
        print("ufm")
    sys.exit(0)
if os.environ.get("FAKE_DOCKER_DOWN"):
    print("Error response from daemon: container ufm is not running", file=sys.stderr)
    sys.exit(1)
if args[0] == "cp":
    shutil.copy(inside(args[1].split(":", 1)[1]), args[2])
    sys.exit(0)
assert args[:2] == ["exec", "ufm"], args
command = args[2:]
# R-037: the tool lookup inside the container, `sh -c '[ -x <fixed path> ] ... || command -v "$1"' sh <name>`;
# FAKE_CONTAINER_TOOL=fixed (default) has the fixed path, =path only /usr/local/bin/<name>, =none neither.
if command[:2] == ["sh", "-c"] and command[2].startswith("[ -x "):
    found = os.environ.get("FAKE_CONTAINER_TOOL", "fixed")
    if found == "none":
        sys.exit(1)
    print(command[2].split()[2] if found == "fixed" else "/usr/local/bin/" + command[-1])
    sys.exit(0)
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

# R-037 (guide 8.23 item 1): how the collector asks docker whether UFM runs in the ufm container.
PS_CALL = ["ps", "-a", "--filter", "name=^/ufm$", "--format", "{{.Names}}"]

# R-037: ibdiagnet / iblinkinfo installed on the host (the ufm-enterprise package, no docker). Logs its
# argv to FAKE_TOOL_LOG; ibdiagnet writes its output to UFM_HOST_OUT, the host's /var/tmp/ibdiagnet2.
FAKE_HOST_TOOL = r"""#!{python}
import json, os, sys
with open(os.environ["FAKE_TOOL_LOG"], "a") as log:
    log.write(json.dumps(sys.argv) + "\n")
if sys.argv[0].endswith("/ibdiagnet"):
    out = os.environ["UFM_HOST_OUT"]
    os.makedirs(out, exist_ok=True)
    with open(out + "/ibdiagnet2.log", "w") as handle:
        handle.write("ibdiagnet run " + " ".join(sys.argv[1:]) + "\n")
    if not os.environ.get("FAKE_IBDIAGNET_NO_NET_DUMP"):
        with open(out + "/ibdiagnet2.net_dump", "w") as handle:
            handle.write("net dump\n")
    print("-I- Done")
    sys.exit(int(os.environ.get("FAKE_IBDIAGNET_RC", "0")))
print("Node Neighbor GUID of GUID: 0x0200000000000001 Port: 39 doesn't exist", file=sys.stderr)
print("Switch: 0x0200000000000001 MF0;sw01:Q3400/U1:")
sys.exit(int(os.environ.get("FAKE_IBLINKINFO_RC", "0")))
"""


def path_without_docker(path, farm):
    """The given PATH with no docker in it, as on a UFM installed from the ufm-enterprise package (R-037).
    A directory that holds a docker (Docker Desktop's /usr/local/bin, a CI runner's /usr/bin) is replaced by
    a directory of symlinks to its other entries under `farm`, so this machine's docker is never reached."""
    kept = []
    for index, directory in enumerate(part for part in path.split(os.pathsep) if part):
        if not os.path.lexists(os.path.join(directory, "docker")):
            kept.append(directory)
            continue
        copy = Path(farm) / str(index)
        copy.mkdir(parents=True)
        for entry in os.listdir(directory):
            if entry != "docker":
                (copy / entry).symlink_to(os.path.join(directory, entry))
        kept.append(str(copy))
    return os.pathsep.join(kept)


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
        # R-037 host mode: the host's /opt/ufm/opensm and /var/tmp/ibdiagnet2 (UFM_OPENSM, UFM_HOST_OUT),
        # a PATH directory for the tools, and hostname/ip without docker
        self.opensm = self.base / "host/opt/ufm/opensm"
        self.host_out = self.base / "host/var/tmp/ibdiagnet2"
        self.path_bin = self.base / "path-bin"
        self.tool_log = self.base / "tools.log"
        self.host_bin = self.base / "host-bin"
        self.host_bin.mkdir()
        for name in ("hostname", "ip"):
            os.symlink(self.bin / name, self.host_bin / name)

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

    def host_tool(self, where, name):
        """A host ibdiagnet/iblinkinfo: at its fixed path under /opt/ufm/opensm, or in a PATH directory."""
        if where == "fixed":
            directory = self.opensm / ("bin" if name == "ibdiagnet" else "sbin")
        else:
            directory = self.path_bin
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text(FAKE_HOST_TOOL.replace("{python}", sys.executable), encoding="utf-8")
        path.chmod(0o755)
        return str(path)

    def tool_calls(self):
        if not self.tool_log.exists():
            return []
        return [json.loads(line) for line in self.tool_log.read_text().splitlines()]

    def run_on_host(self, *args, docker=False, **env):
        """The collector on a UFM: no docker at all, or (docker=True) the docker stand-in in front."""
        directories = [str(self.host_bin), str(self.path_bin)] + ([str(self.bin)] if docker else [])
        system = path_without_docker(os.environ["PATH"], self.base / "no-docker")
        path = os.pathsep.join(directories + [system])
        if not docker:
            self.assertIsNone(shutil.which("docker", path=path), "this UFM has no docker")
        environment = dict(os.environ, PATH=path, TMPDIR=str(self.lock_tmp), FAKE_CONTAINER=str(self.container),
                           UFM_HOST_FILES=str(self.container / "opt/ufm/files"),
                           FAKE_DOCKER_LOG=str(self.docker_log), UFM_OPENSM=str(self.opensm),
                           UFM_HOST_OUT=str(self.host_out), FAKE_TOOL_LOG=str(self.tool_log),
                           COPYFILE_DISABLE="1", **env)
        return subprocess.run(["bash", str(UFM_IBDIAGNET), *args], cwd=self.work, env=environment,
                              capture_output=True, text=True, timeout=60)

    def assert_ok_archive(self, done):
        archive = self.out / f"ibdiagnet2_{RUN_ID}.tgz"
        with tarfile.open(archive) as bundle:
            self.assertIn("ibdiagnet2/ibdiagnet2.net_dump", bundle.getnames())
        self.assertEqual((done["result"], done["kind"], done["artifact"], done["sha256"]),
                         ("ok", "ibdiagnet", archive.name, hashlib.sha256(archive.read_bytes()).hexdigest()))
        self.assertFalse(list(self.out.glob("*.part")))

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

    def test_the_periodic_argv_has_no_routing_and_keeps_the_rest(self):
        # Q-057 (I-065): only --routing goes; content and order of the rest, 900 s, kill-after 30 stay.
        self.assertEqual(self.run_ibdiagnet(RUN_ID).returncode, 0)
        [run] = [call for call in self.docker_calls() if "/opt/ufm/opensm/bin/ibdiagnet" in call]
        self.assertEqual(run[6:], IBDIAGNET_ARGV)   # exec ufm sh -c <wrapper> sh <argv>
        self.assertEqual(len(IBDIAGNET_ARGV), 13)
        self.assertNotIn("--routing", run)
        self.assertIn('exec timeout -k 30 900 "$@"', run[4])

    def test_a_timed_out_run_with_fresh_output_is_ok_with_the_partial_notice(self):
        # I-065 8.2 item 1: 124/137 with this run's net_dump, archived: result=ok, the vendor rc, the notice.
        for rc in ("124", "137"):
            with self.subTest(rc=rc):
                shutil.rmtree(self.out, ignore_errors=True)
                result = self.run_ibdiagnet(RUN_ID, FAKE_IBDIAGNET_RC=rc)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                done = self.done()
                self.assertEqual((done["result"], done["rc"], done["reason"]), ("ok", rc, PARTIAL_NOTICE))
                archive = self.out / f"ibdiagnet2_{RUN_ID}.tgz"
                self.assertEqual((done["artifact"], done["sha256"]),
                                 (archive.name, hashlib.sha256(archive.read_bytes()).hexdigest()))

    def test_rc_and_output_matrix_keeps_the_original_classification(self):
        # I-065 8.4 C1 direct: rc 0/1/124/137 x fresh / only old / no net_dump, plus a failed archive.
        # Only 124/137 with usable output gains the notice; rc 1 stays the original plain success.
        for rc in ("0", "1", "124", "137"):
            for state in ("fresh", "old only", "none", "archive fails"):
                with self.subTest(rc=rc, state=state):
                    shutil.rmtree(self.out, ignore_errors=True)
                    shutil.rmtree(self.container / "var/tmp/ibdiagnet2", ignore_errors=True)
                    env = {"FAKE_IBDIAGNET_RC": rc}
                    if state in ("old only", "none"):
                        env["FAKE_IBDIAGNET_NO_NET_DUMP"] = "1"
                    if state == "old only":
                        stale = self.container / "var/tmp/ibdiagnet2"
                        stale.mkdir()
                        (stale / "ibdiagnet2.net_dump").write_text("old\n")
                        os.utime(stale / "ibdiagnet2.net_dump", (1, 1))
                    shared = self.container / "opt/ufm/files"
                    if state == "archive fails":   # packing inside the container cannot write its archive
                        shared.chmod(0o500)
                    try:
                        result = self.run_ibdiagnet(RUN_ID, **env)
                    finally:
                        shared.chmod(0o700)
                    done = self.done()
                    archive = self.out / f"ibdiagnet2_{RUN_ID}.tgz"
                    self.assertEqual(done["rc"], rc, "the vendor rc is kept as it was")
                    if state == "fresh":
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual((done["result"], done["artifact"]), ("ok", archive.name))
                        self.assertEqual(done["reason"], PARTIAL_NOTICE if rc in ("124", "137") else "")
                    else:
                        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
                        self.assertFalse(archive.exists())
                        self.assertNotIn("partial output", done["reason"], "a failure is never a partial success")
                        if rc in ("124", "137") and state != "archive fails":
                            self.assertIn("timed out after 900s", done["reason"], "the timeout is still named")

    def test_an_interrupted_timed_out_run_writes_no_done_marker(self):
        # I-065 8.2 item 2: an interrupted run publishes no completion, whatever its rc would have been.
        environment = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                           TMPDIR=str(self.lock_tmp), FAKE_CONTAINER=str(self.container),
                           UFM_HOST_FILES=str(self.container / "opt/ufm/files"),
                           FAKE_DOCKER_LOG=str(self.docker_log), COPYFILE_DISABLE="1",
                           FAKE_IBDIAGNET_SLEEP="3", FAKE_IBDIAGNET_RC="124")
        process = subprocess.Popen(["bash", str(UFM_IBDIAGNET), RUN_ID], cwd=self.work, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + 20
            while not (self.container / "var/tmp/ibdiagnet2/ibdiagnet2.log").exists():
                self.assertLess(time.time(), deadline, "ibdiagnet never started")
                time.sleep(0.1)
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.done").exists())
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.tgz").exists())

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

    # ── R-037 (L4): UFM in the ufm container or installed on the host (guide 8.23) ──────────────────
    # Owner (record :1917): "iblinkinfo 优先用 /opt/ufm/opensm/sbin/iblinkinfo，没有的话就直接跑；ibdiagnet
    # 优先用 /opt/ufm/opensm/bin/ibdiagnet，没有的话就直接跑"; owner 2026-11-20: "两种模式都是先尝试全路径的
    # 命令，不存在再按PATH跑". A real failure of the command found never falls back; neither one is an error.

    def test_host_mode_uses_the_fixed_ibdiagnet_path_first(self):
        fixed = self.host_tool("fixed", "ibdiagnet")
        self.host_tool("path", "ibdiagnet")   # also in PATH: the fixed path still comes first
        result = self.run_on_host(RUN_ID)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Q-057 (I-065): the same periodic arguments as in the container, without --routing
        self.assertEqual(self.tool_calls(), [[fixed, *IBDIAGNET_ARGV[1:]]])
        done = self.done()
        self.assert_ok_archive(done)
        self.assertEqual((done["rc"], done["reason"]), ("0", ""))

    def test_host_mode_falls_back_to_path_without_the_fixed_path(self):
        in_path = self.host_tool("path", "ibdiagnet")
        result = self.run_on_host(RUN_ID)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.tool_calls(), [[in_path, *IBDIAGNET_ARGV[1:]]])
        self.assert_ok_archive(self.done())

    def test_host_mode_without_any_ibdiagnet_names_the_cause_and_runs_nothing(self):
        # Owner 2026-11-20: neither the fixed path nor PATH has it: say so, run nothing.
        result = self.run_on_host(RUN_ID)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.tool_calls(), [])
        done = self.done()
        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
        self.assertIn("ibdiagnet not found on the host", done["reason"])
        self.assertIn(str(self.opensm / "bin/ibdiagnet"), done["reason"])
        self.assertIn("PATH", done["reason"])
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.tgz").exists())

    def test_host_mode_fixed_path_failure_does_not_fall_back_to_path(self):
        # Owner 2026-11-20: the fixed path exists but really fails: report it, never try PATH as well.
        fixed = self.host_tool("fixed", "ibdiagnet")
        self.host_tool("path", "ibdiagnet")
        result = self.run_on_host(RUN_ID, FAKE_IBDIAGNET_RC="1", FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.tool_calls(), [[fixed, *IBDIAGNET_ARGV[1:]]], "the PATH ibdiagnet is never run")
        done = self.done()
        self.assertEqual((done["result"], done["artifact"], done["rc"]), ("failed", "", "1"))
        self.assertIn("no new ibdiagnet2.net_dump", done["reason"])

    def test_host_mode_old_dump_is_not_this_runs_output(self):
        # Owner 2026-10-22 (the container's contract, the same on the host): only this run's net_dump counts.
        fixed = self.host_tool("fixed", "ibdiagnet")
        self.host_out.mkdir(parents=True)
        (self.host_out / "ibdiagnet2.net_dump").write_text("old\n")
        os.utime(self.host_out / "ibdiagnet2.net_dump", (1, 1))
        result = self.run_on_host(RUN_ID, FAKE_IBDIAGNET_NO_NET_DUMP="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.tool_calls(), [[fixed, *IBDIAGNET_ARGV[1:]]])
        done = self.done()
        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
        self.assertIn("no new ibdiagnet2.net_dump", done["reason"])
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.tgz").exists())

    def test_host_mode_timeout_with_fresh_output_keeps_ok_and_the_partial_notice(self):
        # I-065 8.2 item 1, the same values on the host (guide 8.23 item 5)
        self.host_tool("fixed", "ibdiagnet")
        for rc in ("124", "137"):
            with self.subTest(rc=rc):
                shutil.rmtree(self.out, ignore_errors=True)
                shutil.rmtree(self.host_out, ignore_errors=True)
                result = self.run_on_host(RUN_ID, FAKE_IBDIAGNET_RC=rc)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                done = self.done()
                self.assert_ok_archive(done)
                self.assertEqual((done["rc"], done["reason"]), (rc, PARTIAL_NOTICE))

    def test_host_mode_packing_failure_is_a_failure(self):
        # The container's contract (packing fails: failed, nothing half written left), on the host.
        fixed = self.host_tool("fixed", "ibdiagnet")
        self.host_out.mkdir(parents=True)
        locked = self.host_out / "ibdiagnet2.unreadable"
        locked.write_text("x\n")
        locked.chmod(0o000)   # tar cannot read it
        try:
            result = self.run_on_host(RUN_ID)
        finally:
            locked.chmod(0o600)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.tool_calls(), [[fixed, *IBDIAGNET_ARGV[1:]]])
        done = self.done()
        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
        self.assertIn("packing", done["reason"])
        self.assertFalse((self.out / f"ibdiagnet2_{RUN_ID}.tgz").exists())
        self.assertFalse(list(self.out.glob("*.part")), "no half-written archive is left")

    def test_host_mode_iblinkinfo_fixed_path_then_path_then_none(self):
        for where in ("fixed", "path", "none"):
            with self.subTest(where=where):
                for directory in (self.opensm, self.path_bin, self.links):
                    shutil.rmtree(directory, ignore_errors=True)
                if self.tool_log.exists():
                    self.tool_log.unlink()
                expected = None
                if where != "none":
                    expected = self.host_tool(where, "iblinkinfo")
                    if where == "fixed":
                        self.host_tool("path", "iblinkinfo")   # the fixed path still comes first
                result = self.run_on_host(RUN_ID, "--iblinkinfo")
                done = self.done("iblinkinfo")
                if expected is None:
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(self.tool_calls(), [])
                    self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
                    self.assertIn("iblinkinfo not found on the host", done["reason"])
                    self.assertIn(str(self.opensm / "sbin/iblinkinfo"), done["reason"])
                    continue
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.tool_calls(), [[expected]])
                log = self.links / f"iblinkinfo_{RUN_ID}.log"
                self.assertEqual((done["result"], done["kind"], done["artifact"]), ("ok", "iblinkinfo", log.name))
                self.assertTrue(log.read_text().startswith("Switch: 0x0200000000000001"), "stdout only")
                self.assertIn("doesn't exist", (self.links / f"iblinkinfo_{RUN_ID}.stderr").read_text())

    def test_container_mode_falls_back_to_path_inside_the_container(self):
        result = self.run_ibdiagnet(RUN_ID, FAKE_CONTAINER_TOOL="path")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.docker_calls()
        lookups = [call for call in calls if call[:4] == ["exec", "ufm", "sh", "-c"] and call[-1] == "ibdiagnet"]
        runs = [call for call in calls if call[-len(IBDIAGNET_ARGV) + 1:] == IBDIAGNET_ARGV[1:]]
        self.assertEqual((len(lookups), len(runs)), (1, 1), calls)
        self.assertIn("/opt/ufm/opensm/bin/ibdiagnet", lookups[0][4], "the fixed path is tried first")
        self.assertLess(calls.index(lookups[0]), calls.index(runs[0]))
        self.assertEqual(runs[0][:4], ["exec", "ufm", "sh", "-c"])
        self.assertEqual(runs[0][5:], ["sh", "/usr/local/bin/ibdiagnet", *IBDIAGNET_ARGV[1:]])
        self.assertEqual(self.done()["result"], "ok")

    def test_container_mode_without_the_tool_names_the_cause_and_runs_nothing(self):
        result = self.run_ibdiagnet(RUN_ID, FAKE_CONTAINER_TOOL="none")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        calls = self.docker_calls()
        self.assertEqual(calls[0], PS_CALL)
        self.assertEqual(len(calls), 2, "only the mode check and the lookup, no run")
        self.assertEqual(calls[1][-1], "ibdiagnet")
        done = self.done()
        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
        self.assertIn("ibdiagnet not found in the ufm container", done["reason"])
        self.assertIn("/opt/ufm/opensm/bin/ibdiagnet", done["reason"])
        self.assertIn("PATH", done["reason"])

    def test_container_mode_iblinkinfo_fixed_path_then_path_then_none(self):
        for found, expected in (("fixed", "/opt/ufm/opensm/sbin/iblinkinfo"), ("path", "/usr/local/bin/iblinkinfo"),
                                ("none", None)):
            with self.subTest(found=found):
                shutil.rmtree(self.links, ignore_errors=True)
                if self.docker_log.exists():
                    self.docker_log.unlink()
                result = self.run_ibdiagnet(RUN_ID, "--iblinkinfo", FAKE_CONTAINER_TOOL=found)
                calls = self.docker_calls()
                runs = [call for call in calls if call[-1].endswith("/iblinkinfo")]
                done = self.done("iblinkinfo")
                if expected is None:
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(runs, [])
                    self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
                    self.assertIn("iblinkinfo not found in the ufm container", done["reason"])
                    self.assertIn("/opt/ufm/opensm/sbin/iblinkinfo", done["reason"])
                    continue
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(runs), 1, calls)
                self.assertEqual(runs[0][:4], ["exec", "ufm", "sh", "-c"])
                self.assertEqual(runs[0][5:], ["sh", expected])
                self.assertEqual(done["result"], "ok")

    def test_a_stopped_ufm_container_is_a_container_failure_not_a_host_run(self):
        # R-037: `docker ps -a` still lists a stopped ufm container; that is the container mode and its real
        # failure is reported, never a host run (TC-REAL-UFM-MONITOR-001 step 3 keeps its meaning).
        self.host_tool("fixed", "ibdiagnet")
        self.host_tool("path", "ibdiagnet")
        result = self.run_on_host(RUN_ID, docker=True, FAKE_DOCKER_DOWN="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.docker_calls()[0], PS_CALL)
        self.assertEqual(self.tool_calls(), [], "no host ibdiagnet is run")
        done = self.done()
        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))

    def test_docker_without_a_ufm_container_runs_on_the_host(self):
        fixed = self.host_tool("fixed", "ibdiagnet")
        result = self.run_on_host(RUN_ID, docker=True, FAKE_DOCKER_PS="empty")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.docker_calls(), [PS_CALL], "docker is only asked, nothing runs in a container")
        self.assertEqual(self.tool_calls(), [[fixed, *IBDIAGNET_ARGV[1:]]])
        self.assert_ok_archive(self.done())

    def test_unknown_docker_state_fails_without_a_host_run(self):
        # R-037: docker ps fails (daemon unreachable, no permission): unknown, never taken as "no container".
        self.host_tool("fixed", "ibdiagnet")
        result = self.run_on_host(RUN_ID, docker=True, FAKE_DOCKER_PS="fail")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(self.docker_calls(), [PS_CALL])
        self.assertEqual(self.tool_calls(), [])
        done = self.done()
        self.assertEqual((done["result"], done["artifact"]), ("failed", ""))
        self.assertIn("cannot tell whether UFM runs in the ufm container: docker ps failed (exit 1)", done["reason"])


if __name__ == "__main__":
    unittest.main()
