"""ufm-setup-upgrade, management-server side of a changed UFM host key (v3.1.6 B0, WP-6).

Only this server's own ~/.ssh/known_hosts, only the one address, only with --apply, verified through another
session of this run whose MAC was checked, or skipped by name with --refresh-host-key (B0-O2 (a), O8 (b);
v3.1.4 指导 :359, :411, :725, :731, :740). The known_hosts file is a temporary one with keys generated at run
time by the real ssh-keygen; the fake ssh treats it as OpenSSH does under StrictHostKeyChecking=accept-new.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_cases.test_ufm_setup_upgrade as tufm

ufm = tufm.ufm
U1 = "ufm01.site01.example.test"


def warning(address, fingerprint, path, line):
    """The OpenSSH warning for a changed host key, layout as OpenSSH prints it."""
    return ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"
            "The fingerprint for the ED25519 key sent by the remote host is\n"
            f"{fingerprint}.\n"
            f"Add correct host key in {path} to get rid of this message.\n"
            f"Offending ED25519 key in {path}:{line}\n"
            "  remove with:\n"
            f"  ssh-keygen -f '{path}' -R '{address}'\n"
            f"Host key for {address} has changed and you have requested strict checking.\n"
            "Host key verification failed.\n")


class UfmHostKeyRefreshTests(tufm.ConfiguredPairCase):
    def setUp(self):
        super().setUp()
        base = Path(self.tmp.name)
        self.home = base / "home"
        (self.home / ".ssh").mkdir(parents=True)
        self.known = self.home / ".ssh" / "known_hosts"
        keys = base / "keys"
        keys.mkdir()
        self.old, self.new, self.stranger, other, ufm02 = (
            self.keygen(keys / name) for name in ("old", "new", "stranger", "other", "ufm02"))
        self.lines = [f"203.0.113.9 {other}", f"198.51.101.132 {ufm02}"]
        self.known.write_text(f"{self.lines[0]}\n198.51.101.130 {self.old}\n{self.lines[1]}\n")
        self.before = self.known.read_bytes()
        self.state["ufms"]["ufm01"]["host_key"] = self.new   # ufm01 was factory reset: a new host key
        self.state["ufms"]["ufm02"]["host_key"] = ufm02
        saved = os.environ.get("FAKE_KNOWN_HOSTS")
        os.environ["FAKE_KNOWN_HOSTS"] = str(self.known)
        self.addCleanup(lambda: os.environ.pop("FAKE_KNOWN_HOSTS") if saved is None
                        else os.environ.__setitem__("FAKE_KNOWN_HOSTS", saved))
        patcher = mock.patch.object(ufm, "local_home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def keygen(path):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture", "-f", str(path)],
                       check=True, capture_output=True, timeout=30)
        return " ".join(Path(str(path) + ".pub").read_text().split()[:2])

    def fingerprint(self, key):
        with tempfile.TemporaryDirectory() as tmp:
            pub = Path(tmp) / "key.pub"
            pub.write_text(key + "\n")
            return subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", str(pub)], check=True,
                                  capture_output=True, text=True, timeout=30).stdout.split()[1]

    def entries(self, address):
        return [line.split(None, 1)[1] for line in self.known.read_text().splitlines() if line.split()[:1] == [address]]

    def others(self):
        return [line for line in self.known.read_text().splitlines() if not line.startswith("198.51.101.130 ")]

    def fresh(self, **kwargs):
        self.state_path.write_text(json.dumps(dict(self.state, image_url=tufm.IMAGE_URL)), encoding="utf-8")
        return self.run_login(**kwargs)

    def test_verified_change_on_ipv4_is_refreshed_once(self):
        # v3.1.4 指导 :359, :411, :740; I-037 设计 :116: verified through the jump session whose MAC was checked
        results, _state, _calls, logs = self.fresh(action="open_node")
        one = results["ufm01"]
        self.assertEqual(one.status, "VERIFIED", one.detail)
        record = one.host_key
        self.assertEqual((record["result"], record["verification"], record["address"]),
                         ("refreshed", "verified", "198.51.101.130"))
        self.assertEqual(list(record["old_fingerprints"]), [self.fingerprint(self.old)])
        self.assertEqual(record["new_fingerprint"], self.fingerprint(self.new))
        self.assertEqual(self.entries("198.51.101.130"), [self.new], "only this address, only the new key")
        self.assertEqual(self.others(), self.lines, "every other line as it was")
        self.assertEqual(one.path, "IPv4-KEY", "the one retry of the key login worked")
        self.assertNotIn("REMOTE HOST IDENTIFICATION", logs.split("\n")[-1])

    def test_unverifiable_change_is_reported_and_file_untouched(self):
        # v3.1.4 指导 :411, :725; 问题文档 :137, :149: only IPv4 (no jump, another subnet), not named
        results, _state, _calls, _logs = self.fresh(action="open_node", direct_access=frozenset({U1}))
        one = results["ufm01"]
        self.assertEqual(one.status, "HOSTKEY_CONFLICT")
        self.assertIn("--refresh-host-key ufm01", one.detail)
        self.assertIn("ssh-keygen", one.detail)
        self.assertEqual(one.attempts, [], "no password to a device whose key changed")
        self.assertEqual(self.known.read_bytes(), self.before)

    def test_operator_forced_refresh_on_an_ipv4_only_ufm(self):
        # 问题文档 :141; v3.1.4 指导 :731; B0-O8 (b): named, not verified, this one entry, one retry, then IPv4
        self.state["ufms"]["ufm01"]["files"].pop("root/.ssh/authorized_keys")
        results, _state, _calls, _logs = self.fresh(action="check", apply=False, direct_access=frozenset({U1}),
                                                    refresh_host_key=frozenset({U1}))
        one = results["ufm01"]
        self.assertEqual(one.status, "NEEDS_CONFIGURATION", one.detail)
        self.assertEqual((one.host_key["result"], one.host_key["note"]), ("refresh-pending", "未核实（操作员指定）"))
        self.assertEqual(self.known.read_bytes(), self.before, "check writes nothing")
        results, _state, _calls, _logs = self.fresh(action="open_node", direct_access=frozenset({U1}),
                                                    refresh_host_key=frozenset({U1}))
        one = results["ufm01"]
        self.assertEqual(one.status, "VERIFIED", one.detail)
        self.assertEqual((one.host_key["verification"], one.host_key["note"]),
                         ("operator-forced-unverified", "未核实（操作员指定）"))
        self.assertEqual((list(one.host_key["old_fingerprints"]), one.host_key["new_fingerprint"]),
                         ([self.fingerprint(self.old)], self.fingerprint(self.new)))
        self.assertEqual(self.entries("198.51.101.130"), [self.new])
        self.assertIn(("IPv4", "new", "OK"), [(a["path"], a["password"], a["outcome"]) for a in one.attempts])

    def test_refresh_host_key_selector(self):
        # v3.1.4 指导 :337 (D34-O5); B0-O8 (b): as --direct-access but all is no keyword; matched against every
        # server_ufm, --node or not; no match (a jump name too) exits 2 before any device is touched
        with tempfile.TemporaryDirectory() as tmp:
            inputs = tufm.make_inputs(tmp)
            for argv, code in ((["--refresh-host-key", "ufm01"], 0), (["--refresh-host-key", "ufm0[1-2]"], 0),
                               (["--node", "ufm01", "--refresh-host-key", "ufm02"], 0),
                               (["--refresh-host-key", "all"], 2), (["--refresh-host-key", "ufm09"], 2),
                               (["--refresh-host-key", "oob-leaf117"], 2)):
                with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(ufm.main(["--input-dir", str(inputs), "check", "--inputs-only"] + argv), code)
            with mock.patch.object(ufm, "read_secret", side_effect=AssertionError("prompted")), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(ufm.main(["--input-dir", str(inputs), "check", "--refresh-host-key", "ufm09"]), 2)
            self.assertFalse((inputs / ufm.LOGS_NAME).exists())

    def test_fingerprint_mismatch_refuses(self):
        # 问题文档 :137: the key the address presents is not the one the verified session reads on the device
        self.state["ufms"]["ufm01"]["presented_key"] = self.stranger
        asked = []
        results, _state, _calls, _logs = self.fresh(action="open_node",
                                                    confirm=lambda host, action: asked.append(action) or True)
        self.assertEqual(results["ufm01"].status, "HOSTKEY_CONFLICT")
        self.assertEqual(self.known.read_bytes(), self.before)
        self.assertEqual(asked, [], "a mismatch is never asked about")

    def test_check_mode_never_writes(self):
        # B0-O8 (a); UFM README (check changes nothing): verified -> WOULD_REFRESH, a change for --apply
        with mock.patch.object(ufm.login_rules, "refresh_target_host_key", side_effect=AssertionError("called")):
            results, _state, _calls, _logs = self.fresh(action="check", apply=False)
        one = results["ufm01"]
        self.assertEqual(one.status, "NEEDS_CONFIGURATION", one.detail)
        self.assertIn(("host_key", "WOULD_REFRESH"), [(step["step"], step["outcome"]) for step in one.steps])
        self.assertEqual((one.host_key["result"], one.host_key["removal"]), ("refresh-pending", None))
        self.assertEqual(self.known.read_bytes(), self.before)

    def test_jump_side_change_is_never_deleted(self):
        # 问题文档 :123-127; 00 原则 :68; v3.1.4 指导 :1399: the inner ssh's entry lives on the jump: report only
        self.state["no_direct"] = ["198.51.101.130"]
        self.state["ufms"]["ufm01"]["jump_known_hosts_conflict"] = True
        results, _state, calls, _logs = self.fresh(action="open_node")
        one = results["ufm01"]
        self.assertEqual(one.status, "HOSTKEY_CONFLICT")
        self.assertIn("oob-leaf117", one.detail)
        self.assertFalse([call for call in calls if call["target"].startswith("cumulus@") and "ssh-keygen" in call["remote"]])
        self.assertEqual(self.known.read_bytes(), self.before)

    def test_vip_known_hosts_is_never_edited(self):
        # UFM README (owner 10-22): the VIP's own file of the run is never edited; v3.1.4 指导 :411
        self.fresh(action="open_node")   # a session of this run
        vip_file = self.run_dir / "vip-known-hosts"
        vip_file.write_text(f"198.51.101.133 {self.old}\n")
        before = vip_file.read_bytes()
        node = next(node for node in self.session.plan.nodes if node.hostname == U1)
        for address in ("198.51.101.133", "198.51.101.130"):
            with self.subTest(address=address):
                change = ufm.login_rules.parse_host_key_change(
                    warning(address, self.fingerprint(self.new), vip_file, 1))
                result = self.session.host_key_changed(node, ufm.NodeResult(U1, "primary"),
                                                       ufm.HostKeyConflict("changed", change), True)
                self.assertEqual(result.status, "HOSTKEY_CONFLICT")
                self.assertEqual(vip_file.read_bytes(), before)

    def test_refresh_survives_the_deployment_key_being_gone(self):
        # tools/login_path.py::refresh_target_host_key reads known_hosts after the retry; B0-O8; 问题文档 :137
        self.state["ufms"]["ufm01"]["files"].pop("root/.ssh/authorized_keys")
        results, _state, _calls, _logs = self.fresh(action="open_node")
        one = results["ufm01"]
        self.assertEqual((one.status, one.path), ("VERIFIED", "OOB-IPv6"), one.detail)
        self.assertEqual(one.host_key["result"], "refreshed")
        self.assertEqual(self.entries("198.51.101.130"), [self.new])
        self.known.write_bytes(self.before)
        self.state["no_direct_after_refresh"] = True
        results, _state, _calls, _logs = self.fresh(action="open_node")
        one = results["ufm01"]
        self.assertEqual(one.status, "HOSTKEY_CONFLICT", one.detail)
        self.assertNotEqual(one.host_key.get("result"), "refreshed")

    def test_apply_asks_before_removing_and_declining_keeps_the_file(self):
        # login_path.py:181-182 (before_remove after verification); initial-setup's own precedent
        asked = []
        results, _state, _calls, _logs = self.fresh(action="open_node",
                                                    confirm=lambda host, action: asked.append(action) or False)
        self.assertEqual(results["ufm01"].status, "NOT_AUTHORIZED")
        self.assertEqual(len(asked), 1)
        self.assertIn("known_hosts", asked[0])
        self.assertEqual(self.known.read_bytes(), self.before)


if __name__ == "__main__":
    unittest.main()
