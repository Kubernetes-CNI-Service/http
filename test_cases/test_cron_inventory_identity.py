"""Direct tests for cron.sh's inventory MAC rule and key-preparation failure reasons (I-018, v3.1.6 C1).

The shell functions are cut out of the real ethernet/monitor/cron.sh and run with a fake ssh, as in
TemplateContractTests.test_dynamic_air_monitor_accepts_default_hostname_only_after_mac_match. The MAC
expectations are read from the shared fixture test_cases/fixtures/mac_spellings.tsv (P3b §2.1); this
module never imports tools/ (v3.1.6 guide C1-O9: the comparison with tools/device_identity.py is the
workflow test_cron_mac_rule_workflow)."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRON = ROOT / "ethernet/monitor/cron.sh"
MAC_SPELLINGS = ROOT / "test_cases/fixtures/mac_spellings.tsv"


def functions(*names):
    source = CRON.read_text(encoding="utf-8")
    bodies = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", source, re.S | re.M)
        assert match, name
        bodies.append(match.group(0))
    return "\n".join(bodies)


def mac_spellings():
    rows = MAC_SPELLINGS.read_text(encoding="utf-8").splitlines()
    assert rows[0] == "input\texpected", rows[0]
    return [tuple(row.split("\t", 1)) for row in rows[1:]]


# A fake ssh: FAKE_HOSTS has "ip<TAB>mode<TAB>hostname<TAB>eth0 MAC" rows; mode "ok" runs the remote
# command here (HOME is the test directory), "auth" refuses the key, "down" cannot connect.
FAKE_SSH = r'''
log() { printf '[log] %s\n' "$*"; }
create_ssh_askpass_helper() { echo "unexpected password prompt" >&2; return 1; }
ssh() {
    local remote="${!#}" target="${@: -2:1}" ip mode name mac
    ip=${target#*@}
    printf '%s\n' "$ip" >> "$SSH_CALLS"
    IFS=$'\t' read -r mode name mac < <(awk -F'\t' -v ip="$ip" '$1 == ip { print $2 "\t" $3 "\t" $4 }' "$FAKE_HOSTS")
    case "$mode" in
        auth) echo "admin@${ip}: Permission denied (publickey,password)." >&2; return 255 ;;
        down) echo "ssh: connect to host ${ip} port 22: Connection timed out" >&2; return 255 ;;
    esac
    (
        hostname() { printf '%s\n' "$name"; }
        cat() {
            if [[ "$1" == "/sys/class/net/eth0/address" ]]; then
                printf '%s\n' "$mac"
            else
                command cat "$@"
            fi
        }
        eval "$remote"
    )
}
SSH_OPTS=''
SSH_PASSWORD_OPTS=''
MAX_PARALLEL=8
ASKPASS_FILE=''
SSH_KEY='ssh-ed25519 AAAATEST monitor-test'
'''

PREPARE_ONE = r'''
load_inventory_macs "$TEST_CSV"
PREPARED_ENTRY=''
prepare_ssh_host_resilient "$TEST_ENTRY" admin "$TEST_ROOT/remote" ''
printf '__RC__=%s\n__PREPARED__=%s\n' "$?" "$PREPARED_ENTRY"
'''

DEPLOY = r'''
load_inventory_macs "$TEST_CSV"
deploy_ssh_keys "$TEST_HOSTS" "$TEST_LABEL" admin "$TEST_ROOT/remote"
printf '__RC__=%s\n' "$?"
'''

KEY_FUNCTIONS = ("valid_host_entry", "hosts_file_has_entries", "hosts_file_entry_count",
                 "record_device_failure", "load_inventory_macs", "inventory_mac", "prepare_ssh_host_resilient",
                 "prepare_ssh_batch_resilient", "key_device_kind", "deploy_ssh_keys")

# The eight outcomes of key preparation and the reason each one keeps (v3.1.6 guide C1-O4: the seven
# phrases prepare_ssh_host_resilient already prints, plus "eth0_mac not recognised").
# name, entry, ssh mode, remote hostname, remote eth0 MAC, CSV eth0_mac, runtime identity row
OUTCOMES = (
    ("sw-a", "sw-a|192.0.2.300", "ok", "sw-a", "", "", ""),
    ("sw-b", "sw-b|192.0.2.12|192.0.2.999", "ok", "sw-b", "", "", ""),
    ("sw-c", "sw-c|192.0.2.13", "ok", "sw-c", "02:00:00:00:00:13", "", "sw-c|not-a-mac|dhcp-lease"),
    ("sw-d", "sw-d|192.0.2.14", "ok", "other-d", "", "", ""),
    ("sw-e", "sw-e|192.0.2.15", "ok", "sw-e", "02:00:00:00:00:99", "02:00:00:00:00:15", ""),
    ("sw-f", "sw-f|192.0.2.16", "ok", "sw-f", "02:00:00:00:00:16", "02:00:00:00:16", ""),
    ("sw-g", "sw-g|192.0.2.17", "auth", "sw-g", "", "", ""),
    ("sw-h", "sw-h|192.0.2.18", "down", "sw-h", "", "", ""),
)
EXPECTED_REASONS = {
    "sw-a": "unsafe hostname/IP entry",
    "sw-b": "unsafe fallback IP entry",
    "sw-c": "invalid authoritative runtime eth0 MAC",
    "sw-d": "hostname identity mismatch",
    "sw-e": "management MAC identity mismatch",
    "sw-f": "eth0_mac not recognised",
    "sw-g": "authentication rejected",
    "sw-h": "SSH transport or remote preparation failed",
}


class CronInventoryIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.csv = self.root / "inventory.csv"
        self.hosts = self.root / "fake-hosts.tsv"
        self.calls = self.root / "ssh-calls"
        self.identities = self.root / "dynamic-identities"
        self.failures = self.root / "device-failures"
        self.inventory_macs = self.root / "inventory-macs"
        for path in (self.hosts, self.calls, self.identities, self.failures, self.inventory_macs):
            path.write_text("", encoding="utf-8")

    def run_shell(self, body, *names, **env):
        harness = self.root / "harness.sh"
        harness.write_text("#!/bin/bash\n" + functions(*names) + FAKE_SSH + body, encoding="utf-8")
        environment = dict(os.environ, TEST_ROOT=str(self.root), TEST_CSV=str(self.csv), HOME=str(self.root / "home"),
                           FAKE_HOSTS=str(self.hosts), SSH_CALLS=str(self.calls),
                           DYNAMIC_AIR_IDENTITIES=str(self.identities), DEVICE_FAILURES=str(self.failures),
                           INVENTORY_MACS=str(self.inventory_macs), **env)
        # No terminal on any stream: the password prompt is never offered (as under cron).
        return subprocess.run(["bash", str(harness)], env=environment, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=60, check=False)

    def load_macs(self, csv_text):
        self.csv.write_bytes(csv_text.encode("utf-8"))
        result = self.run_shell('load_inventory_macs "$TEST_CSV"\n', "load_inventory_macs")
        self.assertEqual(result.returncode, 0, result)
        return self.inventory_macs.read_text(encoding="utf-8").splitlines()

    def write_hosts(self, rows):
        self.hosts.write_text("".join("\t".join(row) + "\n" for row in rows), encoding="utf-8")

    def prepare_one(self, entry, csv_mac, remote_hostname, remote_mac):
        name, ip = entry.split("|")[:2]
        self.csv.write_text(f"hostname,type,eth0_ip,eth0_mac\n{name},ib,{ip},{csv_mac}\n", encoding="utf-8")
        self.write_hosts([(ip, "ok", remote_hostname, remote_mac)])
        return self.run_shell(PREPARE_ONE, "valid_host_entry", "load_inventory_macs", "inventory_mac",
                              "prepare_ssh_host_resilient", TEST_ENTRY=entry)

    def deploy(self, rows, label, sink):
        lines = ["hostname,type,eth0_ip,eth0_mac"]
        lines += [f"{name},ib,{entry.split('|')[1]},{csv_mac}" for name, entry, _m, _h, _r, csv_mac, _i in rows]
        self.csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.write_hosts([(entry.split("|")[1], mode, hostname, mac)
                          for _n, entry, mode, hostname, mac, _c, _i in rows])
        self.identities.write_text("".join(identity + "\n" for *_rest, identity in rows if identity),
                                   encoding="utf-8")
        hosts = self.root / "hosts"
        hosts.write_text("".join(entry + "\n" for _n, entry, *_rest in rows), encoding="utf-8")
        self.failures.write_text("", encoding="utf-8")
        return self.run_shell(DEPLOY, *KEY_FUNCTIONS, TEST_HOSTS=str(hosts), TEST_LABEL=label,
                              KEY_FAILURE_SINK=sink)

    def recorded_reasons(self):
        reasons = {}
        for line in self.failures.read_text(encoding="utf-8").splitlines():
            name, operation, reason = line.split("\t")
            self.assertEqual(operation, "ssh_prepare", line)
            reasons[name] = reason
        return reasons

    def test_load_inventory_macs_follows_the_shared_fixture(self):
        # P3b §2.1 (设计/P3b设备身份规则.md :46-65); 问题文档 I-018 验收 :1123
        spellings = mac_spellings()
        rows = ["hostname,type,eth0_ip,eth0_mac"]
        rows += [f"dev{index:02d},ib,192.0.2.{index},{text}" for index, (text, _expected) in enumerate(spellings, 1)]
        expected = []
        for index, (_text, wanted) in enumerate(spellings, 1):
            if wanted == "MISSING":
                continue   # an empty or NA cell stays "no MAC": no row at all
            expected.append(f"dev{index:02d}|{'invalid' if wanted == 'INVALID' else wanted}")
        self.assertEqual(self.load_macs("\n".join(rows) + "\n"), expected)

    def test_crlf_and_missing_mac_column(self):
        # 问题文档 I-018 期望 2 :1107「MAC 栏为空时，行为保持现在这样」; a CRLF inventory is read the same way
        crlf = ("hostname,type,eth0_ip,eth0_mac\r\n"
                "dev01,ib,192.0.2.1,02:00:00:00:00:01\r\n"
                "dev02,ib,192.0.2.2,02-AB-CD-EF-00-02\r\n"
                "dev03,ib,192.0.2.3,\r\n")
        self.assertEqual(self.load_macs(crlf), ["dev01|02:00:00:00:00:01", "dev02|02:ab:cd:ef:00:02"])
        without_column = ("hostname,type,eth0_ip\n"
                          "dev01,ib,192.0.2.1\n"
                          "dev02,ib,192.0.2.2\n")
        self.assertEqual(self.load_macs(without_column), [], "no eth0_mac column: every device has no MAC")

    def test_unrecognised_mac_rejects_before_any_ssh(self):
        # 问题文档 I-018 期望 2 :1107; v3.1.6 guide WP-8 第 2 条 (:1416)
        result = self.prepare_one("sw-f|192.0.2.16", "02:00:00:00:16", "sw-f", "02:00:00:00:00:16")
        self.assertIn("__RC__=11", result.stdout, result)
        self.assertIn("[KEY][ETH0-MAC-INVALID] sw-f (192.0.2.16): eth0_mac not recognised", result.stderr)
        self.assertEqual(self.calls.read_text(encoding="utf-8"), "", "no ssh to a device whose MAC is unreadable")
        self.assertIn("__PREPARED__=\n", result.stdout)

    def test_missing_mac_still_checks_the_hostname(self):
        # 问题文档 I-018 期望 2 :1107「MAC 栏为空时，行为保持现在这样」(exit 42 path)
        rejected = self.prepare_one("sw-d|192.0.2.14", "", "other-d", "02:00:00:00:00:14")
        self.assertIn("__RC__=11", rejected.stdout, rejected)
        self.assertIn("[KEY][HOSTNAME-MISMATCH][ERROR] 192.0.2.14: CSV=sw-d, switch=other-d", rejected.stdout)
        self.assertIn("hostname identity mismatch", rejected.stderr)
        self.assertEqual(self.calls.read_text(encoding="utf-8"), "192.0.2.14\n")
        self.calls.write_text("", encoding="utf-8")
        accepted = self.prepare_one("sw-d|192.0.2.14", "NA", "sw-d", "02:00:00:00:00:14")
        self.assertIn("__RC__=0", accepted.stdout, accepted)
        self.assertIn("__PREPARED__=sw-d|192.0.2.14", accepted.stdout)

    def test_identity_mismatch_is_not_tagged_unreachable(self):
        # 问题文档 I-018 期望 4 :1117「身份不符的标签不用 UNREACHABLE」; guide WP-8 第 2 条 (:1416)
        hostname = self.prepare_one("sw-d|192.0.2.14", "", "other-d", "02:00:00:00:00:14")
        mac = self.prepare_one("sw-e|192.0.2.15", "02:00:00:00:00:15", "sw-e", "02:00:00:00:00:99")
        for result, phrase in ((hostname, "hostname identity mismatch"),
                               (mac, "management MAC identity mismatch")):
            self.assertIn("__RC__=11", result.stdout, result)
            output = result.stdout + result.stderr
            self.assertNotIn("[KEY][UNREACHABLE]", output)
            self.assertIn("[KEY][IDENTITY-MISMATCH]", result.stderr)
            self.assertIn(phrase, result.stderr)

    def test_each_failure_keeps_its_own_reason(self):
        # 问题文档 I-018 期望 4 :1117「汇总和结果 JSON 保留每台的具体原因 … 不再统一写成「认证或连接失败」」
        switches = self.deploy(OUTCOMES, "IB", "result")
        self.assertIn("__RC__=0", switches.stdout, switches)
        self.assertEqual(self.recorded_reasons(), EXPECTED_REASONS)
        ufm = self.deploy(OUTCOMES, "UFM", "log")
        self.assertIn("__RC__=0", ufm.stdout, ufm)
        self.assertEqual(self.failures.read_text(encoding="utf-8"), "", "a UFM never joins the switch result")
        logged = {}
        for line in ufm.stdout.splitlines():
            match = re.fullmatch(r"\[log\] \[KEY\] ERROR: UFM (\S+): (.+)", line)
            if match:
                logged[match.group(1)] = match.group(2)
        self.assertEqual(logged, EXPECTED_REASONS)
        for result in (switches, ufm):
            self.assertNotIn("authentication or transport", result.stdout + result.stderr)

    def test_auth_failures_moved_without_a_terminal_say_authentication(self):
        # 问题文档 I-018 期望 4 :1117 (认证失败); guide WP-8 第 4 条 (:1418)
        refused = [row for row in OUTCOMES if row[0] == "sw-g"]
        result = self.deploy(refused, "IB", "result")
        self.assertIn("no interactive terminal for password authentication", result.stdout, result)
        self.assertNotIn("unexpected password prompt", result.stderr)
        self.assertEqual(self.recorded_reasons(), {"sw-g": "authentication rejected"})


if __name__ == "__main__":
    unittest.main()
