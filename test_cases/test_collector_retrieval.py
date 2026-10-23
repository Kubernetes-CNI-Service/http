"""Direct tests for cron.sh's shared fetch: wait, then poll and fetch each device as soon as its file is
complete; a device that never gets ready only records its own failure (owner 2026-10-21)."""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRON = ROOT / "ethernet/monitor/cron.sh"

FAKE_SCP = r"""#!{python}
import json, os, sys, time
plan = json.load(open(os.environ["FAKE_SCP_PLAN"]))
src, dst = sys.argv[-2], sys.argv[-1]
host = src.split("@", 1)[1].split(":", 1)[0]
counter = os.path.join(os.environ["FAKE_SCP_COUNTS"], host)
attempt = int(open(counter).read()) + 1 if os.path.exists(counter) else 1
open(counter, "w").write(str(attempt))
with open(os.environ["FAKE_SCP_TIMES"], "a") as log:
    log.write(f"{host} {time.time()}\n")
rule = plan.get(host, {})
if rule.get("never") or attempt < rule.get("ready_after", 1):
    print(f"scp: {src.split(':', 1)[1]}: No such file or directory", file=sys.stderr)
    sys.exit(1)
complete = attempt >= rule.get("complete_after", 1)
with open(dst, "w") as handle:
    handle.write("Device: x\n" + ("# Collect complete\n" if complete else "partial\n"))
"""


def functions(*names):
    source = CRON.read_text(encoding="utf-8")
    bodies = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.S | re.M)
        assert match, name
        bodies.append(match.group(0))
    return "\n".join(bodies)


class RetrieveWhenReadyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        (self.base / "bin").mkdir()
        scp = self.base / "bin/scp"
        scp.write_text(FAKE_SCP.replace("{python}", sys.executable), encoding="utf-8")
        scp.chmod(0o755)
        self.dest = self.base / "dest"
        self.dest.mkdir()
        self.counts = self.base / "counts"
        self.counts.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def retrieve(self, plan, ext="info", first=2, poll=1, limit=6, stub_sleep=False):
        hosts = self.base / "hosts"
        hosts.write_text("".join(f"dev{i}|{ip}\n" for i, ip in enumerate(plan, 1)), encoding="utf-8")
        failures = self.base / "failures"
        failures.write_text("")
        (self.base / "plan.json").write_text(json.dumps(plan))
        harness = self.base / "harness.sh"
        harness.write_text(
            "#!/bin/bash\n"
            f"DEVICE_FAILURES={failures}\nSSH_OPTS=''\nMAX_PARALLEL=8\n"
            f"RETRIEVE_FIRST_WAIT={first}\nRETRIEVE_POLL={poll}\n"
            + ("sleep() { return 0; }\n" if stub_sleep else "")
            + functions("log", "valid_host_entry", "hosts_file_has_entries", "record_device_failure",
                        "retrieve_when_ready")
            + f'\nretrieve_when_ready {hosts} admin /home/admin/monitor {ext} {self.dest} {limit} "[TEST]"\n',
            encoding="utf-8")
        env = dict(os.environ, PATH=f"{self.base / 'bin'}{os.pathsep}{os.environ['PATH']}",
                   FAKE_SCP_PLAN=str(self.base / "plan.json"), FAKE_SCP_COUNTS=str(self.counts),
                   FAKE_SCP_TIMES=str(self.base / "times.log"))
        started = time.time()
        result = subprocess.run(["bash", str(harness)], env=env, capture_output=True, text=True, timeout=60)
        self.elapsed = time.time() - started
        self.started = started
        return result, hosts.read_text().splitlines(), failures.read_text().splitlines()

    def first_attempt(self):
        return min(float(line.split()[1]) for line in (self.base / "times.log").read_text().splitlines())

    def test_each_device_is_fetched_once_its_file_is_complete_and_others_are_unaffected(self):
        result, kept, failures = self.retrieve({
            "198.51.100.1": {"ready_after": 1},
            "198.51.100.2": {"ready_after": 3},          # appears at the third check
            "198.51.100.3": {"never": True},             # never ready
            "198.51.100.4": {"complete_after": 2},       # first copy is still being written
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(kept, ["dev1|198.51.100.1", "dev2|198.51.100.2", "dev4|198.51.100.4"])
        self.assertEqual(len(failures), 1)
        self.assertTrue(failures[0].startswith("dev3\tcollection\t"), failures)
        self.assertIn("within 6s", failures[0])
        self.assertEqual(sorted(os.listdir(self.dest)), ["dev1.info", "dev2.info", "dev4.info"],
                         "nothing is kept for the device that never became ready")
        for name in ("dev1", "dev2", "dev4"):
            self.assertIn("# Collect complete", (self.dest / f"{name}.info").read_text())
        self.assertGreaterEqual(self.first_attempt() - self.started, 2 - 0.2, "the first check waits first")
        self.assertLess(self.elapsed, 6 + 4, "the limit bounds the wait")

    def test_a_link_file_is_taken_as_soon_as_it_exists(self):
        result, kept, failures = self.retrieve({"198.51.100.1": {"complete_after": 9}}, ext="link", limit=4)
        self.assertEqual((kept, failures), (["dev1|198.51.100.1"], []))
        self.assertTrue((self.dest / "dev1.link").exists())

    def test_a_stubbed_sleep_still_ends_after_the_bounded_number_of_checks(self):
        # Workflow tests replace sleep with a no-op; the wait must end by its check count, not spin.
        result, kept, failures = self.retrieve({"198.51.100.3": {"never": True}}, first=0, poll=1, limit=6,
                                               stub_sleep=True)
        self.assertEqual((kept, len(failures)), ([], 1))
        self.assertEqual(int((self.counts / "198.51.100.3").read_text()), 7, "1 + (6 - 0) / 1 checks")

    def test_the_owner_timing_and_every_switch_phase_uses_it(self):
        source = CRON.read_text(encoding="utf-8")
        self.assertIn("RETRIEVE_FIRST_WAIT=60", source)
        self.assertIn("RETRIEVE_POLL=5", source)
        for hosts, wait, ext in (("ETH", "ETH_WAIT", "info"), ("SPX", "SPX_WAIT", "link"),
                                 ("IB", "IB_WAIT", "info"), ("IB", "IBL_WAIT", "link"),
                                 ("NV", "NV_WAIT", "info"), ("NV", "NVL_WAIT", "link")):
            self.assertRegex(source, rf'retrieve_when_ready "\${hosts}" "\$\{{\w+_SSH_USER\}}" '
                                     rf'"\$\{{\w+_REMOTE_DIR\}}" {ext} "\$dir" "\${wait}"')
            self.assertNotIn(f'sleep "${wait}"', source)


if __name__ == "__main__":
    unittest.main()
