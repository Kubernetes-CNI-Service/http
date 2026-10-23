"""Direct tests for infra/ubuntu24_host.py; device output fixtures are verbatim from ufm-manual.log."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
host = load_script("ubuntu24_host_under_test", ROOT / "infra/ubuntu24_host.py")

MANUAL_NETPLAN = """\
network:
  version: 2
  ethernets:
    eno8303:
      dhcp4: no
      addresses: [198.51.101.132/23]
      gateway4: 198.51.101.254
    eno8403:
      dhcp4: no
      addresses: [192.0.2.2/30]
    ib0:
      dhcp4: no
      addresses: [198.19.255.3/16]
    ib1:
      dhcp4: no
      addresses: [198.19.255.4/16]
"""
MANUAL_LAN_BEFORE = """\
Set in Progress         : Set Complete
Auth Type Support       : MD5
Auth Type Enable        : Callback : MD5
                        : User     : MD5
IP Address Source       : DHCP Address
IP Address              : 0.0.0.0
Subnet Mask             : 0.0.0.0
MAC Address             : 02:00:00:00:b0:01
Default Gateway IP      : 0.0.0.0
Default Gateway MAC     : 00:00:00:00:00:00
"""
MANUAL_LAN_AFTER = """\
IP Address Source       : Static Address
IP Address              : 198.51.101.131
Subnet Mask             : 255.255.254.0
MAC Address             : 02:00:00:00:b0:01
Default Gateway IP      : 198.51.101.254
Default Gateway MAC     : 00:00:00:00:00:00
"""
MANUAL_USER_LIST = """\
ID  Name             Callin  Link Auth  IPMI Msg   Channel Priv Limit
1                    true    false      false      NO ACCESS
2   root             true    true       true       ADMINISTRATOR
3                    true    false      false      NO ACCESS
4                    true    false      false      NO ACCESS
"""
MANUAL_GETACCESS_3 = """\
Maximum User IDs     : 16
Enabled User IDs     : 2

User ID              : 3
User Name            : admin
Fixed Name           : No
Access Available     : call-in / callback
Link Authentication  : enabled
IPMI Messaging       : enabled
Privilege Level      : ADMINISTRATOR
Enable Status        : enabled
"""
DESIRED = {"network": {"version": 2, "ethernets": {
    "eno8303": {"dhcp4": False, "addresses": ["198.51.101.132/23"],
                "routes": [{"to": "default", "via": "198.51.101.254"}]},
    "eno8403": {"dhcp4": False, "addresses": ["192.0.2.2/30"]},
    "ib0": {"dhcp4": False, "addresses": ["100.126.255.3/16"]},
    "ib1": {"dhcp4": False, "addresses": ["100.126.255.4/16"]}}}}
FAKE_SYSTEMCTL = """#!/bin/bash
case "$1" in
  show) if [ "${FAKE_MISSING:-}" = "$4" ]; then echo not-found; else echo loaded; fi ;;
  is-enabled) if [ "${FAKE_MASKED:-}" = "$2" ]; then echo masked; else echo enabled; fi ;;
  is-active) echo active ;;
  *) echo "$*" >> "$FAKE_SYSTEMCTL_LOG" ;;
esac
"""


class NetplanTest(unittest.TestCase):
    def test_document_uses_routes_and_static_addresses(self):
        self.assertEqual(host.netplan_document("eno8303", "198.51.101.132/23", "198.51.101.254", {
            "eno8403": "192.0.2.2/30", "ib0": "100.126.255.3/16", "ib1": "100.126.255.4/16"}), DESIRED)
        import yaml
        self.assertEqual(yaml.safe_load(host.render_netplan(DESIRED)), DESIRED)
        with self.assertRaises(host.HostConfigError):
            host.netplan_document("eno 8303", "198.18.0.1/24", "198.18.0.254", {})

    def test_manual_file_is_rewritten_for_addresses_and_deprecated_gateway4(self):
        def equivalent(text):
            return host.netplan_equivalent(host.effective_ethernets({host.NETPLAN_TARGET: text}), DESIRED)
        self.assertFalse(equivalent(MANUAL_NETPLAN))
        addresses_fixed = MANUAL_NETPLAN.replace("198.19.255.", "100.126.255.")   # the manual file had wrong IB addresses
        self.assertFalse(equivalent(addresses_fixed), "gateway4 is deprecated")
        routes = addresses_fixed.replace("      gateway4: 198.51.101.254\n",
                                         "      routes:\n      - to: default\n        via: 198.51.101.254\n")
        self.assertTrue(equivalent(routes))
        self.assertFalse(equivalent(routes.replace("eno8303:\n      dhcp4: no", "eno8303:\n      dhcp4: yes")))

    def test_conflicting_files_and_unsafe_names(self):
        files = {host.NETPLAN_TARGET: "network: {version: 2}\n",
                 "/etc/netplan/50-cloud-init.yaml": "network:\n  ethernets:\n    eno8303: {dhcp4: true}\n",
                 "/etc/netplan/60-other.yaml": "network:\n  ethernets:\n    eno9999: {dhcp4: true}\n"}
        self.assertEqual(host.netplan_conflicts(files, DESIRED), ["/etc/netplan/50-cloud-init.yaml"])
        with self.assertRaises(host.HostConfigError):
            host.parse_netplan_listing("__NETPLAN_FILE__ ../../etc/shadow\nAAAA\n")
        with self.assertRaises(host.HostConfigError):
            host.effective_ethernets({host.NETPLAN_TARGET: "network: [unclosed\n"})

    def test_apply_script_backs_up_validates_restores_and_defers(self):
        script = host.netplan_apply_script("network: {}\n", ["/etc/netplan/50-cloud-init.yaml"],
                                           "/root/backup/run", write=True)
        order = [script.index(text) for text in (
            'cp -a /etc/netplan/. "$backup/netplan/"', "50-cloud-init.yaml", "base64 -d",
            "netplan generate", 'cp -a "$backup/netplan/." /etc/netplan/', "systemd-run",
            "sleep 3; netplan apply", "  sleep 1\n")]
        self.assertEqual(order, sorted(order))
        self.assertNotIn("\nnetplan apply", script)
        self.assertIn("--on-active=3", script)

    def test_network_problems_require_management_and_skip_down_links(self):
        facts = host.parse_network_facts(
            "dev=eno8303 oper=up mac=02:00:00:00:02:01 addrs=198.51.101.132/23,\n"
            "dev=eno8403 oper=up mac=02:00:00:00:02:02 addrs=192.0.2.2/30,\n"
            "dev=ib0 oper=down mac= addrs=\n"
            "default=default via 198.51.101.254 dev eno8303 proto static\n")
        problems, pending = host.network_problems(facts, "eno8303", "02:00:00:00:02:01", "198.51.101.132/23",
                                                  "198.51.101.254", {"eno8403": "192.0.2.2/30",
                                                                     "ib0": "100.126.255.3/16"})
        self.assertEqual(problems, [])
        self.assertEqual([item.split()[0] for item in pending], ["ib0"])
        problems, _ = host.network_problems(facts, "eno8303", "02:00:00:00:02:01", "198.51.101.130/23",
                                            "198.51.101.1", {})
        self.assertEqual(len(problems), 2)


CHANNEL_INFO = """Channel 0x1 info:
  Channel Medium Type   : 802.3 LAN
  Channel Protocol Type : IPMB-1.0
  Session Support       : multi-session
  Active Session Count  : 0
  Protocol Vendor ID    : 7154
  Volatile(active) Settings
    Alerting            : enabled
    Per-message Auth    : disabled
    User Level Auth     : disabled
    Access Mode         : {volatile}
  Non-Volatile Settings
    Alerting            : enabled
    Per-message Auth    : disabled
    User Level Auth     : disabled
    Access Mode         : {saved}
"""


class IpmiTest(unittest.TestCase):
    def test_lan_access_mode_is_read_from_both_settings(self):
        # ufm01 2026-10-21: Access Mode disabled kept every lanplus session out, root's too.
        self.assertEqual(host.parse_channel_access(CHANNEL_INFO.format(volatile="disabled", saved="disabled")),
                         {"volatile": "disabled", "non_volatile": "disabled"})
        after = host.parse_channel_access(CHANNEL_INFO.format(volatile="always available", saved="always available"))
        self.assertTrue(host.lan_access_on(after))
        self.assertFalse(host.lan_access_on({"volatile": "always available", "non_volatile": "disabled"}))

    def test_power_status_over_lan_prompts_for_the_password(self):
        script = host.ipmi_lan_power_status_script("198.51.101.129", "admin")
        self.assertIn("ipmitool -I lanplus -H 198.51.101.129 -U admin -a chassis power status", script)
        self.assertNotIn(" -P ", script)
        self.assertRegex("Password: ", host.IPMI_LAN_PASSWORD_PROMPT)
        self.assertNotRegex("root@198.51.101.130's password: ", host.IPMI_LAN_PASSWORD_PROMPT)
        with self.assertRaises(host.HostConfigError):
            host.ipmi_lan_power_status_script("198.51.101.129", "admin; reboot")

    def test_lan_access_scripts_use_the_commands_the_owner_ran(self):
        self.assertEqual(host.ipmi_channel_access_script(1), "set -eu\nipmitool channel info 1\n")
        self.assertEqual(host.ipmi_channel_access_script(1, enable=True),
                         "set -eu\nipmitool lan set 1 access on\nipmitool channel info 1\n")

    def test_lan_parsing_matches_manual_before_and_after(self):
        want = {"ip": "198.51.101.131", "mask": "255.255.254.0", "gateway": "198.51.101.254"}
        self.assertFalse(host.lan_matches(host.parse_lan_print(MANUAL_LAN_BEFORE), want))
        self.assertEqual(host.parse_lan_print(MANUAL_LAN_AFTER),
                         {"source": "Static Address", "ip": "198.51.101.131", "mask": "255.255.254.0",
                          "gateway": "198.51.101.254"})
        self.assertTrue(host.lan_matches(host.parse_lan_print(MANUAL_LAN_AFTER), want))

    def test_user_slot_follows_manual(self):
        users = host.parse_user_list(MANUAL_USER_LIST)
        self.assertEqual(users, [(1, ""), (2, "root"), (3, ""), (4, "")])
        self.assertEqual(host.pick_ipmi_user_id(users, "admin"), (3, True))
        self.assertEqual(host.pick_ipmi_user_id(users[:2] + [(3, "admin")], "admin"), (3, False))
        with self.assertRaises(host.HostConfigError):
            host.pick_ipmi_user_id([(1, ""), (2, "root")], "admin")
        self.assertEqual(host.parse_getaccess(MANUAL_GETACCESS_3), {"User Name": "admin", **host.IPMI_ADMIN_ACCESS})

    def test_password_is_never_an_argument(self):
        script = host.ipmi_user_set_script(1, 3, "admin", True)
        self.assertIn("ipmitool user set password 3\n", script)
        self.assertIn("privilege=4", script)


class InputsTest(unittest.TestCase):
    def test_infra_settings_from_common_switch_system(self):
        document = {"common": {"switch": {"system": {
            "dns": {"server": ["160.250.70.5", "160.250.71.202"]},
            "ntp": {"server": ["160.250.71.253", "ntp.ubuntu.com"]},
            "date-time": {"timezone": "Etc/UTC"}}}}}
        self.assertEqual(host.infra_settings(document),
                         (["160.250.70.5", "160.250.71.202"], ["160.250.71.253", "ntp.ubuntu.com"], "Etc/UTC", [], []))
        _dns, _ntp, _zone, errors, _warnings = host.infra_settings(
            {"common": {"switch": {"system": {"dns": {"server": ["ntp.ubuntu.com"]}}}}})
        self.assertTrue(errors, "DNS servers must be addresses")

    def test_absent_keys_are_skipped_but_present_empty_or_non_string_values_fail(self):
        _dns, _ntp, _zone, errors, warnings = host.infra_settings({"common": {"switch": {"system": {}}}})
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 3)
        for system in ({"dns": None}, {"dns": {"server": []}}, {"ntp": {"server": [1234]}},
                       {"date-time": {"timezone": 8}}, {"date-time": None}):
            with self.subTest(system=system):
                errors = host.infra_settings({"common": {"switch": {"system": system}}})[3]
                self.assertTrue(errors, system)

    def test_config_line_value_matches_the_script_reading(self):
        text = "[Time]\n#NTP=old\n NTP =  a   b \nNTP=second\n"
        self.assertEqual(host.config_line_value(text, "NTP"), "a b")
        self.assertEqual(host.config_line_value("[Time]\n#NTP=x\n", "NTP"), "")

    def test_public_keys_are_plain_lines_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "publickey"
            keys.mkdir()
            (keys / "mgmt-server.pub").write_text("ssh-ed25519 AAAAtestkeyMGMT1 mgmt\n")
            (keys / "forced.pub").write_text('command="reboot" ssh-ed25519 AAAAtestkeyMGMT1 x\n')
            (keys / "empty.pub").write_text("")
            names, lines, errors, warnings = host.read_public_keys(keys)
        self.assertEqual((names, lines), (["mgmt-server.pub"], ["ssh-ed25519 AAAAtestkeyMGMT1 mgmt"]))
        self.assertTrue([error for error in errors if "forced.pub" in error])
        self.assertTrue([warning for warning in warnings if "empty.pub" in warning])


class LocalScriptCase(unittest.TestCase):
    """Generated scripts run under the real local shell tools; systemctl is a recording stand-in."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        fakebin = self.base / "bin"
        fakebin.mkdir()
        (fakebin / "systemctl").write_text(FAKE_SYSTEMCTL)
        (fakebin / "systemctl").chmod(0o755)
        self.log = self.base / "systemctl.log"
        self.env = dict(os.environ, PATH=f"{fakebin}{os.pathsep}{os.environ['PATH']}",
                        FAKE_SYSTEMCTL_LOG=str(self.log))

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, script, **env):
        result = subprocess.run(["/bin/bash", "-c", script], env={**self.env, **env},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return host.parse_kv(result.stdout)

    def config(self, initial, value="160.250.70.5 160.250.71.202", **env):
        path = self.base / "resolved.conf"
        if initial is not None:
            path.write_text(initial)
        facts = self.run_script(host.config_line_script(str(path), "DNS", value, "systemd-resolved",
                                                        str(self.base / "backup")), **env)
        restarts = self.log.read_text().splitlines() if self.log.exists() else []
        self.log.unlink(missing_ok=True)
        return facts, (path.read_text() if path.exists() else None), restarts


class LocalScriptTest(LocalScriptCase):
    def test_commented_default_line_is_replaced_and_service_restarted(self):
        facts, text, calls = self.config("[Resolve]\n#DNS=\n#FallbackDNS=\n")
        self.assertEqual(text, "[Resolve]\nDNS=160.250.70.5 160.250.71.202\n#FallbackDNS=\n")
        self.assertEqual((facts["before"], facts["after"], facts["active"]),
                         ("", "160.250.70.5 160.250.71.202", "active"))
        self.assertEqual(calls, ["restart systemd-resolved.service"])
        self.assertEqual((self.base / "backup/resolved.conf").read_text(), "[Resolve]\n#DNS=\n#FallbackDNS=\n")

    def test_only_the_active_line_changes_when_both_exist(self):
        _facts, text, _calls = self.config("[Resolve]\n DNS = 1.1.1.1 8.8.8.8\n#DNS=\n")
        self.assertEqual(text, "[Resolve]\nDNS=160.250.70.5 160.250.71.202\n#DNS=\n")

    def test_same_value_with_other_spacing_is_unchanged(self):
        original = "[Resolve]\nDNS=160.250.70.5    160.250.71.202\n"
        facts, text, calls = self.config(original)
        self.assertEqual((text, calls, facts["before"]), (original, [], "160.250.70.5 160.250.71.202"))
        self.assertFalse((self.base / "backup").exists())

    def test_second_edit_in_the_same_run_keeps_the_original_backup(self):
        original = "[Resolve]\nDNS=1.1.1.1 8.8.8.8\n#Domains=\n"
        self.config(original)
        path = self.base / "resolved.conf"
        self.run_script(host.config_line_script(str(path), "Domains", "example.test", "systemd-resolved",
                                                str(self.base / "backup")))
        self.assertEqual((self.base / "backup/resolved.conf").read_text(), original)
        self.assertEqual(path.read_text(), "[Resolve]\nDNS=160.250.70.5 160.250.71.202\nDomains=example.test\n")

    def test_backup_can_be_left_to_the_caller(self):
        path = self.base / "timesyncd.conf"
        path.write_text("[Time]\n#NTP=\n")
        self.run_script(host.config_line_script(str(path), "NTP", "ntp.example", "systemd-timesyncd", None))
        self.assertEqual(path.read_text(), "[Time]\nNTP=ntp.example\n")
        self.assertFalse((self.base / "backup").exists())

    def test_missing_line_is_appended(self):
        _facts, text, _calls = self.config("[Resolve]\n")
        self.assertEqual(text, "[Resolve]\nDNS=160.250.70.5 160.250.71.202\n")

    def test_masked_unit_is_unmasked_and_enabled(self):
        _facts, _text, calls = self.config("[Resolve]\n#DNS=\n", FAKE_MASKED="systemd-resolved.service")
        self.assertEqual(calls, ["unmask systemd-resolved.service", "enable --now systemd-resolved.service"])

    def test_missing_unit_is_skipped_without_touching_the_file(self):
        facts, text, calls = self.config("[Resolve]\n#DNS=\n", FAKE_MISSING="systemd-resolved.service")
        self.assertEqual((facts.get("result"), text, calls), ("service_missing", "[Resolve]\n#DNS=\n", []))

    def test_authorized_keys_appends_missing_keys_once(self):
        home = self.base / "home"
        (home / ".ssh").mkdir(parents=True)
        existing = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBB other-comment"
        (home / ".ssh/authorized_keys").write_text(existing)
        keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA laptop", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBB mgmt"]
        facts = self.run_script(host.authorized_keys_script(keys, str(home)))
        self.assertEqual((facts["added"], facts["missing"]), ("1", "0"))
        self.assertEqual((home / ".ssh/authorized_keys").read_text(), existing + "\n" + keys[0] + "\n")
        self.assertEqual(self.run_script(host.authorized_keys_script(keys, str(home)))["added"], "0")


class DockerFindingsTest(LocalScriptCase):
    """Behaviour of real Ubuntu 24.04 that the 2026-10-19 container run exposed."""

    def fake(self, name, body):
        path = self.base / "bin" / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def test_netplan_apply_records_its_own_exit_code_and_asks_for_an_accurate_timer(self):
        etc, backup = self.base / "netplan", self.base / "backup"
        etc.mkdir()
        (etc / "50-cloud-init.yaml").write_text("network: {}\n")
        self.fake("netplan", 'case "$1" in generate) exit 0;; apply) exit 3;; esac; exit 9')
        self.fake("systemd-run", f'echo "$*" > {self.base}/timer-args\n'
                                 'while [ "${1#--}" != "$1" ]; do [ "$1" = --unit ] && shift; shift; done\n"$@"')
        script = host.netplan_apply_script("network: {}\n", [], str(backup), write=False)
        self.run_script(script.replace("/etc/netplan", str(etc)))
        self.assertIn("--timer-property=AccuracySec=100ms", (self.base / "timer-args").read_text())
        self.assertEqual((backup / "netplan-apply.rc").read_text().strip(), "3",
                         "the rc file must hold netplan's exit code, not the scheduler's")

    def test_ipmi_lan_set_reports_every_command_even_when_the_bmc_fails_silently(self):
        # ufm01 on 2026-10-20: `ipmi-lan-set` ended with exit 1 and no output at all.
        self.fake("ipmitool", 'if [ "$4" = ipsrc ]; then exit 1; fi\n'
                              'if [ "$1" = lan ] && [ "$2" = set ]; then echo "Setting LAN $4 to $5"; exit 0; fi\n'
                              'echo "IP Address Source       : DHCP Address"\necho "IP Address              : 0.0.0.0"')
        script = host.ipmi_lan_set_script(1, "198.51.101.129", "255.255.254.0", "198.51.101.254").replace(
            "sleep 1\n", "")
        result = subprocess.run(["/bin/bash", "-c", script], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, "the read-back, not a command's exit code, decides")
        lines = [line for line in result.stdout.splitlines() if line.startswith("lanset=")]
        self.assertEqual([line.split(" | ")[0] for line in lines], [
            "lanset=1 1 ipsrc static", "lanset=0 1 ipaddr 198.51.101.129", "lanset=0 1 netmask 255.255.254.0",
            "lanset=0 1 defgw ipaddr 198.51.101.254"])
        self.assertEqual(host.parse_lan_print(result.stdout)["source"], "DHCP Address")

    def test_ipmi_lan_set_only_runs_the_commands_of_the_manual(self):
        # Owner 2026-10-20: ufm-manual.log configures the BMC with `ipmitool lan set` and checks it with
        # `lan print`; a diagnostic `ipmitool raw` write is not part of the deployment.
        script = host.ipmi_lan_set_script(1, "198.51.101.129", "255.255.254.0", "198.51.101.254")
        commands = {" ".join(word for word in line.split("ipmitool ", 1)[1].split()[:2])
                    for line in script.splitlines() if "ipmitool " in line}
        self.assertEqual(commands, {"lan set", "lan print"}, script)

    def test_ipmi_password_test_never_puts_the_password_in_argv(self):
        script = host.ipmi_user_test_script(3)
        self.assertIn("ipmitool user test 3 16;", script)
        self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0)

    def test_hosts_file_mode_decides_on_etc_hosts_not_the_resolver(self):
        hosts = self.base / "hosts"
        hosts.write_text("127.0.0.1\tlocalhost\n# 127.0.1.1 ufm01.example.test\n")
        self.fake("hostname", "echo ufm01.example.test")
        self.fake("getent", "echo 'getent must not be used'; exit 0")   # resolved synthesises every name
        script = host.hostname_script("ufm01.example.test", str(self.base / "b"), hosts_file=True)
        facts = self.run_script(script.replace("/etc/hosts", str(hosts)))
        self.assertEqual((facts["hosts_added"], facts["in_hosts"]), ("yes", "yes"))
        self.assertTrue(hosts.read_text().endswith("127.0.1.1\tufm01.example.test ufm01\n"))
        facts = self.run_script(script.replace("/etc/hosts", str(hosts)))
        self.assertNotIn("hosts_added", facts)
        self.assertNotIn("getent", script)
        self.assertIn("getent", host.hostname_script("ufm01.example.test", None), "infra keeps its contract")

    def test_hosts_entries_add_only_the_missing_lines(self):
        # Owner 2026-10-22 (ufm-manual.log): both UFMs by their HA link address in /etc/hosts; only these
        # two lines are added, nothing else in the file is touched.
        hosts = self.base / "hosts"
        original = ("127.0.0.1 localhost\n127.0.1.1 ubuntu\n# 192.0.2.2 ufm02.example.test ufm02\n"
                    "192.0.2.1 ufm01.example.test ufm01")   # no newline at the end
        hosts.write_text(original)
        entries = [("192.0.2.1", "ufm01.example.test", "ufm01"), ("192.0.2.2", "ufm02.example.test", "ufm02")]
        check = host.hosts_entries_script(entries, None, check_only=True).replace("/etc/hosts", str(hosts))
        facts = self.run_script(check)
        self.assertEqual((facts["entry_a"], facts["entry_b"], facts["would_hosts"]), ("present", "missing", "yes"),
                         "a commented line does not count")
        self.assertEqual(original, hosts.read_text(), "check only reads")
        apply = host.hosts_entries_script(entries, str(self.base / "b")).replace("/etc/hosts", str(hosts))
        facts = self.run_script(apply)
        self.assertEqual(facts["hosts_ok"], "yes")
        self.assertEqual(original + "\n192.0.2.2    ufm02.example.test  ufm02\n", hosts.read_text())
        self.assertEqual(original, (self.base / "b/hosts").read_text(), "the file before the change is kept")
        facts = self.run_script(apply)
        self.assertEqual((facts["would_hosts"], facts["hosts_ok"]), ("no", "yes"))
        self.assertEqual(1, hosts.read_text().count("ufm02.example.test  ufm02"), "a second run adds nothing")

    def test_hosts_entries_refuse_unsafe_values(self):
        for entry in (("192.0.2.1;x", "ufm01.example.test", "ufm01"), ("192.0.2.1", "bad host", "ufm01")):
            with self.assertRaises(host.HostConfigError):
                host.hosts_entries_script([entry], None)

    def test_peer_check_verifies_by_address_from_stdout_only(self):
        # Owner 2026-10-19: verification by IP/IPv6 address, never by host name.
        record = self.base / "ssh-args"
        self.fake("ssh", f'echo "$*" > {record}\n'
                         "echo \"Warning: Permanently added '192.0.2.2' (ED25519) to the list of known hosts.\" >&2\n"
                         "echo '1: lo    inet 127.0.0.1/8 scope host lo'\n"
                         "echo '3: eno8403    inet 192.0.2.20/30 scope global eno8403'\n"
                         "echo '2: eno8303    inet 198.51.101.132/23 scope global eno8303'")
        for address, owned in (("198.51.101.132", "yes"), ("192.0.2.2", "no")):
            script = host.peer_ssh_check_script(address).replace("/tmp/", f"{self.base}/")
            facts = self.run_script(script)
            self.assertEqual((facts["rc"], facts["peer_has_address"]), ("0", owned), address)
            self.assertIn("Permanently added", facts["error"])
            self.assertTrue(record.read_text().strip().endswith(f"root@{address} ip -o addr show"))
        self.assertNotIn("hostname", host.peer_ssh_check_script("198.51.101.132"))
        self.assertIn("LogLevel=ERROR", script)
        self.assertEqual(list(self.base.glob("host-peer-ssh.*")), [])


class CheckOnlyTest(LocalScriptCase):
    """Inspect mode (no --apply) runs the same reads and decisions but never writes."""

    def check_config(self, initial, **env):
        path = self.base / "resolved.conf"
        path.write_text(initial)
        facts = self.run_script(host.config_line_script(
            str(path), "DNS", "160.250.70.5 160.250.71.202", "systemd-resolved", str(self.base / "backup"),
            check_only=True), **env)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return facts, path.read_text(), calls

    def test_config_line_reports_pending_changes_without_writing(self):
        original = "[Resolve]\n#DNS=\n#FallbackDNS=\n"
        facts, text, calls = self.check_config(original, FAKE_MASKED="systemd-resolved.service")
        self.assertEqual((facts["before"], facts["would_write"], facts["would_unmask"]), ("", "yes", "yes"))
        self.assertEqual((text, calls), (original, []))
        self.assertFalse((self.base / "backup").exists())
        done = "[Resolve]\nDNS=160.250.70.5  160.250.71.202\n"
        facts, text, calls = self.check_config(done)
        self.assertEqual((facts["would_write"], facts["would_unmask"], text, calls), ("no", "no", done, []))

    def test_authorized_keys_counts_missing_keys_without_creating_anything(self):
        home = self.base / "home"
        keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA laptop", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBB mgmt"]
        facts = self.run_script(host.authorized_keys_script(keys, str(home), check_only=True))
        self.assertEqual((facts["added"], facts["missing"]), ("0", "2"))
        self.assertFalse(home.exists())
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh/authorized_keys").write_text(keys[1] + "\n")
        facts = self.run_script(host.authorized_keys_script(keys, str(home), check_only=True))
        self.assertEqual(facts["missing"], "1")
        self.assertEqual((home / ".ssh/authorized_keys").read_text(), keys[1] + "\n")

    def test_hostname_and_timezone_report_without_calling_writers(self):
        fakebin = self.base / "bin"
        record = self.base / "writers.log"
        for name, body in (("hostname", "echo localhost"), ("getent", "exit 2"),
                           ("hostnamectl", f'echo "hostnamectl $*" >> {record}'),
                           ("timedatectl", f'case "$*" in "show -p Timezone --value") echo Etc/UTC;; '
                                           f'"show -p NTPSynchronized --value") echo no;; '
                                           f'*) echo "timedatectl $*" >> {record};; esac')):
            (fakebin / name).write_text(f"#!/bin/sh\n{body}\n")
            (fakebin / name).chmod(0o755)
        facts = self.run_script(host.hostname_script("ufm01.example.test", str(self.base / "backup"),
                                                     check_only=True))
        self.assertEqual((facts["before"], facts["would_hostname"], facts["would_hosts"], facts["after"]),
                         ("localhost", "yes", "yes", "localhost"))
        zone = self.base / "zoneinfo"
        script = host.timezone_script("Australia/Sydney", check_only=True).replace("/usr/share/zoneinfo", str(zone))
        (zone / "Australia").mkdir(parents=True)
        (zone / "Australia/Sydney").write_text("TZif2\n")
        facts = self.run_script(script)
        self.assertEqual((facts["before"], facts["would_timezone"], facts["after"]), ("Etc/UTC", "yes", "Etc/UTC"))
        self.assertFalse(record.exists(), record.read_text() if record.exists() else "")
        self.assertFalse((self.base / "backup").exists())

    def test_check_only_scripts_contain_no_writers(self):
        scripts = {
            "hostname": host.hostname_script("ufm01.example.test", "/root/b", check_only=True),
            "timezone": host.timezone_script("Etc/UTC", check_only=True),
            "config": host.config_line_script("/etc/systemd/resolved.conf", "DNS", "1.1.1.1", "systemd-resolved",
                                              "/root/b", check_only=True),
            "keys": host.authorized_keys_script(["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAA x"], check_only=True),
            "keypair": host.root_keypair_script(check_only=True),
        }
        for name, script in scripts.items():
            for writer in ("hostnamectl", "set-timezone", ">>", "mkdir", "cp -a", "ssh-keygen", "chmod",
                           'systemctl restart', 'systemctl unmask', 'systemctl enable', "touch", "host-new"):
                self.assertNotIn(writer, script, (name, writer))
            self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True).returncode, 0, name)
        self.assertIn("StrictHostKeyChecking=yes",
                      host.peer_ssh_check_script("192.0.2.2", record_host_key=False))
        self.assertIn("StrictHostKeyChecking=accept-new", host.peer_ssh_check_script("192.0.2.2"))


if __name__ == "__main__":
    unittest.main()
