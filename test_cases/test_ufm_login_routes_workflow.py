"""Workflow: ufm-setup-upgrade with the four shared tools modules, end to end (v3.1.6 B0, WP-7).

A temporary repository holds the real entry script, infra/ubuntu24_host.py and tools/login_path.py,
inventory_subset.py, device_identity.py and hostname_ranges.py; main() runs in a subprocess with only ssh, ping
and this server's ip replaced on PATH (the fakes of test_ufm_setup_upgrade). The inventory check against 02 comes
first, the route table next, and only then any session (需求文档 R-016 :974-976; I-037 设计 :24-48).
"""

import json
import os
import pty
import select
import shutil
import subprocess
import sys
import threading
import unittest
from pathlib import Path

import test_cases.test_ufm_setup_upgrade as tufm

ROOT = Path(__file__).resolve().parents[1]
U1, U2 = "ufm01.site01.example.test", "ufm02.site01.example.test"


class UfmLoginRoutesWorkflowTests(tufm.FakeSshCase):
    def setUp(self):
        super().setUp()
        repository = Path(self.tmp.name) / "repository"
        self.tool = repository / "infiniband/bringup/ufm-setup-upgrade"
        self.tool.mkdir(parents=True)
        shutil.copy2(tufm.SCRIPT, self.tool / tufm.SCRIPT.name)
        (repository / "infra").mkdir()
        shutil.copy2(ROOT / "infra/ubuntu24_host.py", repository / "infra/ubuntu24_host.py")
        (repository / "tools").mkdir()
        for name in ("login_path.py", "inventory_subset.py", "device_identity.py", "hostname_ranges.py"):
            shutil.copy2(ROOT / "tools" / name, repository / "tools" / name)
        # ufm02 answers on its CSV IPv4 with the new password; ufm01 only over its jump
        self.state["ufms"]["ufm02"].update(password=self.NEW, expired=False, ipv4="198.51.101.132/23",
                                           answers_on="198.51.101.132",
                                           default="default via 198.51.101.254 dev eno8303 proto static")

    def run_tool(self, *argv):
        self.state.setdefault("image_url", tufm.IMAGE_URL)
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen([sys.executable, "-B", str(self.tool / tufm.SCRIPT.name), "--input-dir",
                                        str(self.inputs), *argv], stdin=slave, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=env, cwd=self.tmp.name,
                                       start_new_session=True)
            done = threading.Event()

            def typist():
                # getpass flushes what was typed before its prompt and waits for the terminal's output (the
                # echo) to drain: read the terminal like a screen does, and type the password for the first 20 s
                typed = 0
                while not done.wait(0.5):
                    while select.select([master], [], [], 0)[0]:
                        os.read(master, 4096)
                    if typed < 40:
                        os.write(master, (self.NEW + "\n").encode())
                        typed += 1
            thread = threading.Thread(target=typist, daemon=True)
            thread.start()
            try:
                stdout, stderr = process.communicate(timeout=300)
            finally:
                done.set()
                thread.join(5)
                if process.poll() is None:
                    process.kill()
                    process.wait()
            result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        finally:
            os.close(master)
            os.close(slave)
        calls_path = Path(str(self.state_path) + ".calls")
        calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
        return result, calls

    def test_inventory_then_route_table_then_login(self):
        master = [row.replace("oob-leaf117,eth_jump,", "oob-leaf117,eth,") for row in tufm.OTHER_ROWS]
        (self.inputs / "02-devices_config.csv").write_text(
            tufm.HEADER + "\n" + "\n".join(master + [tufm.csv_row("oob-leaf130", "eth"), tufm.UFM01, tufm.UFM02])
            + "\n", encoding="utf-8")
        result, calls = self.run_tool("check", "--direct-access", "ufm02")
        out = result.stdout
        self.assertNotIn("INVENTORY MISMATCH", out + result.stderr)   # a subset, eth -> eth_jump allowed
        table = out.find("登录路径")
        self.assertGreater(table, -1, out + result.stderr)
        self.assertLess(table, out.find("地址占用检查"), "the route table comes before any session")
        self.assertTrue(calls, out + result.stderr)
        runs = sorted((self.inputs / tufm.ufm.LOGS_NAME).glob("*/result.json"))
        self.assertEqual(len(runs), 1, out + result.stderr)
        nodes = {item["hostname"]: item for item in json.loads(runs[0].read_text())["nodes"]}
        self.assertEqual((nodes[U1]["login_route"]["path"], nodes[U1]["login_route"]["jump"], nodes[U1]["path"]),
                         ("jump", "oob-leaf117", "OOB-IPv6"))
        self.assertEqual(nodes[U1]["facts"]["cabling"]["outcome"], "MATCH")
        self.assertEqual((nodes[U2]["login_route"]["path"], nodes[U2]["login_route"]["reason"], nodes[U2]["path"]),
                         ("direct", "DIRECT_ACCESS", "IPv4"))
        self.assertIn("--direct-access", nodes[U2]["facts"]["cabling"]["detail"])
        for item in nodes.values():
            self.assertIn("identity", item)
            self.assertEqual(item["facts"].get("mac"), {U1: "02:00:00:00:01:01", U2: "02:00:00:00:02:01"}[item["hostname"]])

    def test_inventory_mismatch_stops_before_any_session(self):
        rows = [row.replace("02:00:00:00:02:01", "02:00:00:00:02:09") for row in tufm.OTHER_ROWS + [tufm.UFM01, tufm.UFM02]]
        (self.inputs / "02-devices_config.csv").write_text(tufm.HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
        result, calls = self.run_tool("check")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(f"INVENTORY MISMATCH: {U2}; eth0_mac; ib.csv=02:00:00:00:02:01; 02=02:00:00:00:02:09; value",
                      result.stdout)
        self.assertEqual(calls, [], "no ssh at all")
        self.assertFalse((self.inputs / tufm.ufm.LOGS_NAME).exists())


if __name__ == "__main__":
    unittest.main()
