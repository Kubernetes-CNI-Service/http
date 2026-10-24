"""IB adapter of the v2 upgrade (owner 2026-10-23; review 15.2, 15.3, 15.5, 15.10, 15.13).

Pure judgements: which failures count as "before install" (allow-list, CPLD burn is
never one), BUSY/PENDING from the switch's step directories, the component plan. Then
one simulated switch end to end with the real scripts: the key is rejected so the
password imports the management key, the image is pulled and verified, the v1 component
step and owned runner run with the local method, the reboot drops the key (restored
after readiness), a lost configuration line is repaired before verification, and the
password never reaches any evidence file. A verification that loses a query to a timeout
tells the engine whether that attempt had already requested a repair (owner 2026-10-23).

Mistyped password (field 2026-10-24): the switch refuses it with PASSWORD_REJECTED before
any write, whether it was the fallback after a rejected key or the bootstrap session; a
rejected key still falls back to the typed password; the probes keep reporting a refused
login as auth_fail; the entry's password check logs in with the password only and runs
nothing that writes.
"""
import hashlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))

import fleet_engine  # noqa: E402
import fleet_ssh as ssh  # noqa: E402
import ibsw_v2_device as ib  # noqa: E402
from ibsw_upgrade_contract import InventoryDevice, load_global_text, normalize_upgrade  # noqa: E402
from ibsw_v2_switch_sim import LocalSwitch, SimFleet  # noqa: E402

SENTINEL = "Sentinel-Fixture-Secret-31"
TYPO = SENTINEL[:-2] + SENTINEL[-1] + SENTINEL[-2]       # the same password with two characters swapped
BOOT_A, BOOT_B = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"


def policy_for(http_root):
    text = f"""schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.10
      port: 8088
      http_root: {http_root}
switches:
- ib:
    version: '25.02.8008'
    upgrade:
      package_dir: {http_root}
      packages:
        os:
          sub_dir: image
          files:
          - file: nvos-amd64-25.02.6077.bin
          - file: nvos-amd64-25.02.7002.bin
          - file: nvos-amd64-25.02.8008.bin
"""
    (Path(http_root) / "image").mkdir(parents=True, exist_ok=True)
    for version in ("25.02.6077", "25.02.7002", "25.02.8008"):
        (Path(http_root) / "image" / f"nvos-amd64-{version}.bin").write_bytes(f"image {version}\n".encode() * 64)
    return normalize_upgrade(load_global_text(text), selected=("os",), method="http")


def step_text(header, *lines, exit_code=None, launch=BOOT_A + " 42"):
    text = f"header {header}\nlaunch {launch}\nexit "
    if exit_code is not None:
        text += f"IBSW_OWNED_EXIT_V1 r1 sw01 cpld cpld {'a' * 64} {exit_code}"
    return text + "\n" + "".join(line + "\n" for line in lines)


class PureTest(unittest.TestCase):
    def step(self, component="cpld"):
        return ib.Step(component, 0, component, "CPLD000123_REV0400", b"x", ("r1", "sw01", "192.0.2.5",
                       "02:00:00:00:00:05", component, "CPLD000123_REV0400"), "POWER_CYCLE_EXPECTED")

    def test_only_the_allow_listed_stages_count_as_before_install(self):
        step = self.step()
        step = ib.Step(step.component, 0, "cpld", step.target_version, b"x", step.binding, step.effect)
        sha = hashlib.sha256(b"x").hexdigest()

        def text(*lines, code):
            return (f"header {step.header}\nlaunch {BOOT_A} 42\nexit IBSW_OWNED_EXIT_V1 r1 sw01 cpld cpld {sha} {code}\n"
                    + "".join(line + "\n" for line in lines))
        self.assertEqual(ib.classify_step(f"header {step.header}\nlaunch -\nexit \nIBSW_STAGE=PACKAGE_READY\n", step, BOOT_A),
                         ("running", None))
        ok = text("IBSW_STAGE=PACKAGE_READY", "IBSW_EXECUTION_RC=0 IBSW_ACTIVATION_STATE=UNKNOWN", code=0)
        self.assertEqual(ib.classify_step(ok, step, BOOT_A), ("exit_zero", None))
        before = text("IBSW_STAGE=PACKAGE_DOWNLOAD", "IBSW_STAGE=PACKAGE_READY",
                      "IBSW_EXECUTION_RC=66 IBSW_ACTIVATION_STATE=UNKNOWN", code=66)
        self.assertEqual(ib.classify_step(before, step, BOOT_A), ("preinstall_failed", "PACKAGE_READY"))
        burn = text("IBSW_STAGE=PACKAGE_READY", "IBSW_COMPONENT_STAGE=BURN_REQUESTED", "IBSW_STAGE=CPLD_BURN",
                    "IBSW_EXECUTION_RC=1 IBSW_ACTIVATION_STATE=UNKNOWN", code=1)
        self.assertEqual(ib.classify_step(burn, step, BOOT_A), ("exit_after_install", None),
                         "a failed CPLD burn may have written hardware: never 'before install' (review 15.2)")
        install = text("IBSW_STAGE=IMAGE_FETCH", "IBSW_STAGE=INSTALL_REQUESTED",
                       "IBSW_EXECUTION_RC=1 IBSW_ACTIVATION_STATE=UNKNOWN", "IBSW_EXPECTED_EFFECT=REBOOT_EXPECTED",
                       code=1)
        self.assertEqual(ib.classify_step(install, step, BOOT_A), ("exit_after_install", None))
        wrong_header = before.replace(step.header, '["other"]')
        self.assertEqual(ib.classify_step(wrong_header, step, BOOT_A), ("exit_after_install", None))
        foreign = before.replace(sha, "b" * 64)
        self.assertEqual(ib.classify_step(foreign, step, BOOT_A), ("exit_after_install", "EXIT_RECORD_INVALID"))

    def test_busy_and_pending_come_from_the_switch(self):
        def facts(*runs, now=10_000, uptime=1_000):
            return ib.Facts(BOOT_A, uptime, now, "25.02.8008", None, None, None, True, b"x", b"", list(runs), {})
        run = ib.Run
        self.assertEqual(facts(run(".ibsw-a", None, 1, True, False, None)).guard()[0], "BUSY")
        self.assertEqual(facts(run(".ibsw-b", BOOT_A, 9_500, False, True, "0")).guard()[0], "PREVIOUS_INSTALL_PENDING")
        self.assertEqual(facts(run(".ibsw-c", BOOT_B, 9_500, False, True, "1")).guard(), (None, None),
                         "a step from an earlier boot has already taken effect or failed")
        self.assertEqual(facts(run(".ibsw-d", None, 9_500, False, True, None)).guard()[0], "PREVIOUS_INSTALL_PENDING",
                         "a v1 directory written after this boot (no launch record)")
        self.assertEqual(facts(run(".ibsw-e", None, 8_000, False, True, None)).guard(), (None, None))
        self.assertEqual(facts(run(".ibsw-f", BOOT_A, 9_500, False, False, "66")).guard(), (None, None),
                         "no install marker: nothing pending")

    def test_plan_and_step_rendering_use_the_v1_rules_with_the_local_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = policy_for(tmp)
            facts = ib.Facts(BOOT_A, 1.0, None, "25.02.6077", None, None, None, True, b"x", b"", [], {})
            plan = ib.plan_device(policy, ("os",), facts)
            self.assertEqual([package.version for package in plan.os_path], ["25.02.7002", "25.02.8008"])
            self.assertEqual(plan.needed, ("os",))
            device = InventoryDevice("sw01", "192.0.2.5", "02:00:00:00:00:05")
            step = ib.render_step(policy, device, component="os", package_index=1, run_id="r1", switch_dir="/home/admin")
            self.assertEqual((step.stage, step.target_version, step.effect), ("os-0001", "25.02.7002", "REBOOT_EXPECTED"))
            script = step.script.decode()
            self.assertIn("IBSW_METHOD=local", script)
            self.assertIn("IBSW_LOCAL_PACKAGE=/home/admin/nvos-amd64-25.02.7002.bin", script)
            self.assertIn('nv action fetch system image "file://${IBSW_LOCAL_PACKAGE}"', script)
            self.assertEqual(json.loads(step.header), ["r1", "sw01", "192.0.2.5", "02:00:00:00:00:05", "os", "25.02.7002"])
            family = ib.IbFamily(policy)
            self.assertEqual(family.components, ("os", "bios", "cpld"))
            self.assertTrue(family.relay("os") and not family.relay("bios"))


class LiveSwitchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.policy = policy_for(base / "http")
        self.key = ssh._sdk().ECDSAKey.generate()
        self.switch = LocalSwitch(base / "switches", "sw01", "192.0.2.5", "02:00:00:00:00:05", "25.02.6077",
                                  password=SENTINEL, drop_keys_on_reboot=True,
                                  lose_config_line="nv set system ntp server 192.0.2.123\n")
        self.fleet = SimFleet([self.switch], base / "http", self.key.get_base64())
        self.device = InventoryDevice("sw01", "192.0.2.5", "02:00:00:00:00:05")
        creds = ssh.Credentials("admin", self.key, ssh.fingerprint(self.key.asbytes()), SENTINEL)
        self.ops = ib.LiveOps(pins=ssh.HostPins(b""), credentials=creds, policy=self.policy, selected=("os",),
                              run_id="r1", management_line=f"{self.key.get_name()} {self.key.get_base64()} mgmt\n".encode(),
                              connector=self.fleet.connector, ping_run=self.fleet.ping_run, tcp_probe=self.fleet.tcp,
                              dir_for=self.fleet.dir_for)
        self.evidence = fleet_engine.Evidence(base / "run")
        self.journal = self.evidence.journal("sw01")

    def until(self, predicate, seconds=10.0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        self.fail("condition not reached")

    def test_one_switch_from_precheck_to_verified(self):
        result = self.ops.precheck(self.device, upgrade=True, staged_names=["nvos-amd64-25.02.7002.bin"],
                                   journal=self.journal)
        self.assertTrue(result["key_rejected"], "the management key was not authorized yet")
        self.assertEqual([package.version for package in result["plan"].os_path], ["25.02.7002", "25.02.8008"])
        self.assertEqual(result["guard"], (None, None))
        self.assertTrue(result["health"]["admitted"])
        self.assertTrue(self.switch.key_allowed(self.key.get_base64()), "the management key was imported")
        self.assertIn("operator", (self.switch.home / ".ssh/authorized_keys").read_text(), "other keys stay")
        self.assertEqual(json.loads((self.evidence.directory("sw01") / "access-bootstrap.json").read_text())["state"],
                         "MANAGEMENT_KEY_IMPORT_REQUESTED")
        backup = result["backup"]

        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        fetched = self.ops.fetch(self.device, info, size=info.size, sha256=info.sha256)
        self.assertEqual((fetched["ok"], fetched["code"]), (True, "OK"), fetched)
        self.assertEqual(self.fleet.contexts[-1]["url"], "http://192.0.2.10:8088/image/nvos-amd64-25.02.7002.bin")

        step = ib.render_step(self.policy, self.device, component="os", package_index=1, run_id="r1",
                              switch_dir=str(self.switch.home))
        frozen, self.switch.tick = self.switch.tick, (lambda: False)       # hold the reboot until we look
        dispatched = self.ops.dispatch(self.device, step, backup=backup,
                                       staged={info.file: (info.size, info.sha256)}, journal=self.journal)
        self.assertEqual((dispatched["state"], dispatched["confirmed"]), ("DISPATCHED", True), dispatched)
        self.assertEqual(json.loads((self.evidence.directory("sw01") / "dispatch.json").read_text())["state"], "REQUESTED")
        step = ib.Step(**{**step.__dict__, "remote_dir": dispatched["remote_dir"]})
        self.until(lambda: (Path(dispatched["remote_dir"]) / "owned-exit.record").exists())
        with self.fleet.connector(self.device, "key") as session:
            status = ib.status(session, step, dispatched["boot_before"])
        self.assertEqual((status["kind"], status["outcome"]), ("ok", "exit_zero"), status)
        pending = self.ops.precheck(self.device, upgrade=False, staged_names=[], journal=self.journal)
        self.assertEqual(pending["guard"][0], "PREVIOUS_INSTALL_PENDING", "same boot after an install request")
        self.switch.tick = frozen

        ladder = self.until(lambda: (lambda r: r if r["kind"] == "ready" else None)(
            self.ops.ladder(self.device, dispatched["boot_before"], backup=backup, journal=self.journal)))
        self.assertEqual((ladder["version"], ladder.get("restored")), ("25.02.7002", True),
                         "the reboot dropped the key; it is restored once the switch is ready")
        self.assertTrue(self.switch.key_allowed(self.key.get_base64()))

        verified = self.ops.verify(self.device, step, boot_after=ladder["boot_id"], before=dispatched["before_commands"],
                                   baseline_health=dispatched["health_record"], backup=backup, journal=self.journal)
        self.assertEqual((verified["state"], verified["os_version"], verified["repaired"]), ("VERIFIED", "25.02.7002", True),
                         verified)
        self.assertIn("ntp server 192.0.2.123", (self.switch.state / "config").read_text(), "missing line restored")
        self.assertEqual(json.loads((self.evidence.directory("sw01") / "repair-result.json").read_text())["state"],
                         "REPAIRED")
        after = self.ops.precheck(self.device, upgrade=False, staged_names=[], journal=self.journal)
        self.assertEqual(after["guard"], (None, None), "the install took effect on a new boot")
        for path in Path(self.tmp.name, "run").rglob("*"):
            if path.is_file():
                self.assertNotIn(SENTINEL.encode(), path.read_bytes(), path)

    # ------------------------------------------------------------ verification errors (owner 2026-10-23)
    def ready_to_verify(self):
        """Precheck, stage, dispatch and wait until the rebooted switch is ready; returns verify()."""
        result = self.ops.precheck(self.device, upgrade=True, staged_names=["nvos-amd64-25.02.7002.bin"],
                                   journal=self.journal)
        backup = result["backup"]
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        fetched = self.ops.fetch(self.device, info, size=info.size, sha256=info.sha256)
        self.assertTrue(fetched["ok"], fetched)
        step = ib.render_step(self.policy, self.device, component="os", package_index=1, run_id="r1",
                              switch_dir=str(self.switch.home))
        dispatched = self.ops.dispatch(self.device, step, backup=backup,
                                       staged={info.file: (info.size, info.sha256)}, journal=self.journal)
        self.assertEqual(dispatched["state"], "DISPATCHED", dispatched)
        step = ib.Step(**{**step.__dict__, "remote_dir": dispatched["remote_dir"]})
        self.until(lambda: (Path(dispatched["remote_dir"]) / "owned-exit.record").exists())
        ladder = self.until(lambda: (lambda r: r if r["kind"] == "ready" else None)(
            self.ops.ladder(self.device, dispatched["boot_before"], backup=backup, journal=self.journal)))
        return lambda: self.ops.verify(self.device, step, boot_after=ladder["boot_id"],
                                       before=dispatched["before_commands"],
                                       baseline_health=dispatched["health_record"], backup=backup,
                                       journal=self.journal)

    def evidence_file(self, name):
        return self.evidence.directory("sw01") / name

    def test_a_query_timeout_before_the_repair_request_is_marked_not_requested(self):
        verify = self.ready_to_verify()
        self.switch.fail_command("/bin/bash -s -- verify", "COMMAND_TIMEOUT")
        with self.assertRaises(ssh.SshError) as caught:
            verify()
        self.assertEqual(caught.exception.code, "COMMAND_TIMEOUT")
        self.assertIs(caught.exception.repair_requested, False)
        self.assertFalse(self.evidence_file("repair-requested.json").exists())
        verified = verify()                                 # what the engine's single retry runs
        self.assertEqual((verified["state"], verified["os_version"], verified["repaired"]),
                         ("VERIFIED", "25.02.7002", True), verified)
        self.assertEqual(json.loads(self.evidence_file("repair-requested.json").read_text())["state"],
                         "REPAIR_REQUESTED")

    def test_a_query_timeout_after_the_repair_request_is_marked_requested(self):
        verify = self.ready_to_verify()
        self.switch.fail_command("/bin/bash -s -- verify", "COMMAND_TIMEOUT", occurrence=2)
        with self.assertRaises(ssh.SshError) as caught:
            verify()
        self.assertEqual(caught.exception.code, "COMMAND_TIMEOUT")
        self.assertIs(caught.exception.repair_requested, True)
        self.assertEqual(json.loads(self.evidence_file("repair-requested.json").read_text())["state"],
                         "REPAIR_REQUESTED")
        self.assertEqual(json.loads(self.evidence_file("repair-result.json").read_text())["state"], "REPAIRED",
                         "the repair ran; the re-check after it timed out")

    def test_a_channel_failure_in_the_final_key_check_without_repair_is_marked_not_requested(self):
        self.switch.lose_config_line = None                 # nothing to repair after the reboot
        verify = self.ready_to_verify()
        self.switch.fail_command("cat /proc/sys/kernel/random/boot_id", "CHANNEL_FAILED")
        with self.assertRaises(ssh.SshError) as caught:
            verify()
        self.assertEqual(caught.exception.code, "CHANNEL_FAILED")
        self.assertIs(caught.exception.repair_requested, False)
        self.assertFalse(self.evidence_file("repair-requested.json").exists())
        verified = verify()
        self.assertEqual((verified["state"], verified["repaired"]), ("VERIFIED", False), verified)

    # ------------------------------------------------------------ mistyped password (field 2026-10-24)
    def typing(self, password):
        """LiveOps whose simulated sshd checks the typed switch password."""
        creds = ssh.Credentials("admin", self.key, ssh.fingerprint(self.key.asbytes()), password)
        return ib.LiveOps(pins=ssh.HostPins(b""), credentials=creds, policy=self.policy, selected=("os",),
                          run_id="r1", management_line=f"{self.key.get_name()} {self.key.get_base64()} mgmt\n".encode(),
                          connector=self.fleet.connector_for(creds), ping_run=self.fleet.ping_run,
                          tcp_probe=self.fleet.tcp, dir_for=self.fleet.dir_for)

    def test_a_rejected_key_still_falls_back_to_the_typed_password(self):
        result = self.typing(SENTINEL).precheck(self.device, upgrade=True, staged_names=[], journal=self.journal)
        self.assertTrue(result["key_rejected"])
        self.assertTrue(self.switch.key_allowed(self.key.get_base64()), "the password imported the management key")
        self.assertTrue(self.fleet.password_logins)
        self.assertTrue(all(accepted for _host, accepted in self.fleet.password_logins))

    def test_a_mistyped_password_is_refused_before_any_write(self):
        keys = self.switch.home / ".ssh/authorized_keys"
        for key_installed in (False, True):
            with self.subTest(key_installed=key_installed):
                if key_installed:                          # key login works; the bootstrap session meets the typo
                    keys.write_text(keys.read_text() + f"{self.key.get_name()} {self.key.get_base64()} mgmt\n")
                before = keys.read_bytes()
                with self.assertRaises(ssh.SshError) as caught:
                    self.typing(TYPO).precheck(self.device, upgrade=True, staged_names=[], journal=self.journal)
                self.assertEqual(caught.exception.code, "PASSWORD_REJECTED")
                self.assertFalse(caught.exception.reboot_like)
                self.assertNotIn(TYPO, str(caught.exception))
                self.assertEqual(keys.read_bytes(), before, "nothing written to authorized_keys")
                self.assertFalse(self.evidence_file("access-bootstrap.json").exists())
                self.assertEqual([path.name for path in self.switch.home.iterdir() if path.name.startswith(".ibsw-")], [])

    def test_probes_keep_reporting_a_refused_login_as_auth_fail(self):
        ops = self.typing(TYPO)                            # the key is not authorized, the password is refused
        self.assertEqual(ops.status(self.device, None, BOOT_A), {"kind": "auth_fail"})
        self.assertEqual(ops.ladder(self.device, BOOT_A, backup=None, journal=self.journal), {"kind": "auth_fail"})

    def test_the_password_check_logs_in_with_the_password_only_and_writes_nothing(self):
        keys = (self.switch.home / ".ssh/authorized_keys").read_bytes()
        self.typing(SENTINEL).password_login(self.device)
        self.assertEqual(self.fleet.password_logins, [("sw01", True)])
        self.assertEqual({(method, command) for _host, method, command in self.fleet.commands}, {("password", "true")},
                         "a no-op over the password session, nothing else")
        with self.assertRaises(ssh.SshError) as caught:
            self.typing(TYPO).password_login(self.device)
        self.assertEqual(caught.exception.code, "PASSWORD_REJECTED")
        self.assertEqual(self.fleet.password_logins, [("sw01", True), ("sw01", False)])
        self.assertEqual(len(self.fleet.commands), 1, "a refused login runs nothing")
        self.assertEqual((self.switch.home / ".ssh/authorized_keys").read_bytes(), keys)


if __name__ == "__main__":
    unittest.main()
