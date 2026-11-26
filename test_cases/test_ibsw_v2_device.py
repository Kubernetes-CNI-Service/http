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
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))

import fleet_engine  # noqa: E402
import fleet_ssh as ssh  # noqa: E402
import ibsw_v2_device as ib  # noqa: E402
from ibsw_upgrade_contract import InventoryDevice, load_global_text, normalize_upgrade  # noqa: E402
from ibsw_v2_switch_sim import LocalFile, LocalSwitch, SimFleet  # noqa: E402

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


def global_yaml(http_root, *, ssd_version=None):
    """01-global.yaml text for os -> bios -> cpld (policy_for's OS images plus a BIOS and a CPLD BURN/REFRESH
    pair, optionally packages.ssd.version); writes the package files under http_root."""
    policy_for(http_root)
    firmware = Path(http_root) / "firmware"
    firmware.mkdir(parents=True, exist_ok=True)
    for name in ("FUI1_BURN_CPLD000123_REV0400.vme", "FUI1_REFRESH_CPLD000123_REV0400.vme", "0ACQF.cab"):
        (firmware / name).write_bytes(name.encode() * 16)
    return f"""schema_version: 2
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
        bios:
          sub_dir: firmware
          file: 0ACQF.cab
          version: '0ACQF_06.01.008'
        cpld:
          sub_dir: firmware
          burn:
            file: FUI1_BURN_CPLD000123_REV0400.vme
          refresh:
            file: FUI1_REFRESH_CPLD000123_REV0400.vme
""" + (f"        ssd:\n          version: '{ssd_version}'\n" if ssd_version else "")


def policy_three(http_root, *, ssd_version=None, selected=("os", "bios", "cpld")):
    return normalize_upgrade(load_global_text(global_yaml(http_root, ssd_version=ssd_version)), selected=selected,
                             method="http")


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


class LaunchCommandTest(unittest.TestCase):
    """G8 (R-047; OWNER-DECISIONS 第21条; 指导 8.25.7): the launch command must not keep the SSH channel
    open while the runner works (prod 11-24: 24 launches without a confirmation; `cd / && nohup sleep 6 … &`
    took 6.004 s to return). Real /bin/bash: with a runner that keeps working for 30 s the command returns
    long before that, prints exactly the launch marker and records the runner's own PID."""

    def test_the_launch_returns_at_once_and_records_the_runner_pid(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder).resolve() / ".ibsw-r1-sw01-os-0001-g8"
            directory.mkdir()
            (directory / "runner.sh").write_text("for tick in $(seq 300); do sleep 0.1; done\n")   # about 30 s
            for name in ("execution.stdout", "execution.stderr"):
                (directory / name).write_text("")
            started = time.monotonic()
            done = subprocess.run(["/bin/bash", "-c", ib.launch_command(str(directory))], capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=90)
            elapsed = time.monotonic() - started
            pid = int((directory / "launch.record").read_text().split()[-1])

            def stop():
                try:
                    os.kill(pid, signal.SIGTERM)          # only the PID this test launched
                except ProcessLookupError:
                    pass
            self.addCleanup(stop)
            self.assertLess(elapsed, 10.0, "the launch must not wait for the runner")
            self.assertEqual(done.stdout, b"IBSW_LAUNCH_REQUESTED\n")
            command = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True,
                                     timeout=10).stdout.strip()
            self.assertEqual(command, "/bin/bash runner.sh", "launch.record holds the runner's PID")


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

    # ------------------------------------------------------------ v3.1.6 A4c
    def ops_with(self, policy, selected, *, password=SENTINEL, **extra):
        creds = ssh.Credentials("admin", self.key, ssh.fingerprint(self.key.asbytes()), password)
        return ib.LiveOps(pins=ssh.HostPins(b""), credentials=creds, policy=policy, selected=selected,
                          run_id="r1", management_line=f"{self.key.get_name()} {self.key.get_base64()} mgmt\n".encode(),
                          connector=self.fleet.connector_for(creds), ping_run=self.fleet.ping_run,
                          tcp_probe=self.fleet.tcp, dir_for=self.fleet.dir_for, **extra)

    def test_a_firmware_query_failure_still_bootstraps_access_for_the_os(self):
        """G1 (R-043; 指导 8.25.1 改法 4): BIOS/CPLD judgement errors hold only those components, so an OS that
        needs an upgrade still gets the access bootstrap in precheck."""
        policy = policy_three(Path(self.tmp.name) / "http")
        (self.switch.state / "firmware_fail").write_text("1")          # `nv show platform firmware` fails once
        result = self.ops_with(policy, ("os", "bios", "cpld")).precheck(
            self.device, upgrade=True, staged_names=[], journal=self.journal)
        self.assertEqual(set(result["plan"].issues), {("bios", "FIRMWARE_QUERY_FAILED"),
                                                      ("cpld", "FIRMWARE_QUERY_FAILED")})
        self.assertEqual(result["plan"].needed, ("os",))
        self.assertTrue(self.evidence_file("access-bootstrap.json").exists(), "the OS still gets the bootstrap")
        self.assertIsNotNone(result["backup"])
        self.assertTrue(self.switch.key_allowed(self.key.get_base64()))

    def staged_for_dispatch(self, ops):
        """Precheck (with the access bootstrap), stage the next image and render its step."""
        result = ops.precheck(self.device, upgrade=True, staged_names=[], journal=self.journal)
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        self.assertTrue(ops.fetch(self.device, info, size=info.size, sha256=info.sha256)["ok"])
        step = ib.render_step(self.policy, self.device, component="os", package_index=1, run_id="r1",
                              switch_dir=str(self.switch.home))
        return result["backup"], step, {info.file: (info.size, info.sha256)}

    def test_dispatch_checks_the_password_before_any_write(self):
        """G6 (R-044; 指导 8.25.2): like v1's VERIFY_RECOVERY_PASSWORD, one password-only login right before
        the step directory is uploaded and dispatch.json is written."""
        ops = self.ops_with(self.policy, ("os",))
        backup, step, staged = self.staged_for_dispatch(ops)
        self.switch.tick = lambda: False                     # no reboot while we look
        before = list(self.fleet.password_logins)
        seen = []
        original = ib.upload_step

        def upload(*args, **kwargs):
            seen.append(list(self.fleet.password_logins))
            return original(*args, **kwargs)
        with mock.patch.object(ib, "upload_step", upload):
            dispatched = ops.dispatch(self.device, step, backup=backup, staged=staged, journal=self.journal)
        self.assertEqual(dispatched["state"], "DISPATCHED", dispatched)
        self.assertEqual(seen, [before + [("sw01", True)]], "one accepted password login before the upload")
        self.assertEqual(self.fleet.password_logins, before + [("sw01", True)])

    def test_a_refused_password_stops_the_dispatch_before_any_write(self):
        """G6: the switch refuses the password at dispatch -> FAILED PASSWORD_PREWRITE_REJECTED, nothing
        uploaded, no write-ahead record (safe to rerun)."""
        ops = self.ops_with(self.policy, ("os",))
        backup, step, staged = self.staged_for_dispatch(ops)
        self.switch.login_password = "changed-after-precheck"
        dispatched = ops.dispatch(self.device, step, backup=backup, staged=staged, journal=self.journal)
        self.assertEqual((dispatched["state"], dispatched.get("reason")), ("FAILED", "PASSWORD_PREWRITE_REJECTED"))
        self.assertEqual([path.name for path in self.switch.home.iterdir() if path.name.startswith(".ibsw-")], [])
        self.assertFalse(self.evidence_file("dispatch.json").exists())
        self.assertEqual(self.fleet.password_logins[-1], ("sw01", False))

    def test_a_switch_at_target_gets_an_informational_ssd_row_in_precheck(self):
        """U8 (问题文件 §38; 指导 8.25.3): an OS already at target is compared with packages.ssd.version in
        precheck from the same `nv show platform firmware` output (no new login or command), like v1's
        PREFLIGHT_OS_AT_TARGET row; informational only."""
        (self.switch.state / "version").write_text("25.02.8008")
        cases = (("SSD-1.2", "SSD-1.2", ("PASS", "MATCH", None)),
                 ("SSD-1.2", "SSD-0.9", ("WARNING", "MISMATCH", "SSD_VERSION_MISMATCH")),
                 ("SSD-1.2", None, ("WARNING", "UNAVAILABLE", "SSD_VERSION_UNAVAILABLE")),
                 (None, "SSD-1.2", None))
        for configured, reported, expected in cases:
            with self.subTest(configured=configured, reported=reported):
                ssd = self.switch.state / "ssd"
                ssd.write_text(reported or "")
                policy = policy_three(Path(self.tmp.name) / "http", ssd_version=configured, selected=("os",))
                del self.fleet.commands[:]
                result = self.ops_with(policy, ("os",)).precheck(self.device, upgrade=False, staged_names=[],
                                                                 journal=self.journal)
                self.assertEqual(result["plan"].needed, ())
                self.assertIn("ssd", result, "the precheck gives an SSD row or None")
                row = result["ssd"]
                if expected is None:
                    self.assertIsNone(row)
                else:
                    self.assertEqual((row["state"], row["status"], row["reason_code"]), expected, row)
                    self.assertEqual(row["verification_basis"], "PREFLIGHT_OS_AT_TARGET")
                    self.assertTrue(row["informational_only"])
                self.assertEqual([command.split(" ")[:4] for _host, _method, command in self.fleet.commands],
                                 [["/bin/bash", "-s", "--", "precheck"]], "no extra device command")

    def test_a_switch_below_the_target_os_gets_no_precheck_ssd_row(self):
        """U8: the comparison only exists for a final OS (ssd_row); an OS upgrade gets its POST_UPGRADE row."""
        (self.switch.state / "ssd").write_text("SSD-0.9")
        policy = policy_three(Path(self.tmp.name) / "http", ssd_version="SSD-1.2", selected=("os",))
        result = self.ops_with(policy, ("os",)).precheck(self.device, upgrade=False, staged_names=[],
                                                         journal=self.journal)
        self.assertTrue(result["plan"].needed)
        self.assertIn("ssd", result, "the precheck gives an SSD row or None")
        self.assertIsNone(result["ssd"])

    # ------------------------------------------------------------ U10 --push (owner 11-20 第7条)
    def pushed(self):
        """[(name, bytes)] of push temporaries left in the switch directory."""
        return [path.name for path in self.switch.home.iterdir() if ".push-" in path.name]

    def test_push_writes_a_temporary_file_and_renames_it_after_the_switch_read_its_sha256(self):
        """U10 (问题文件 §41; 指导 8.25.5 改法 2): the management server pushes over its own key session (no
        switch connects back), the switch's sha256sum of the temporary file must match before the rename."""
        ops = self.ops_with(self.policy, ("os",), method="push")
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        result = ops.fetch(self.device, info, size=info.size, sha256=info.sha256)
        self.assertEqual((result["ok"], result["code"], result.get("pushed"), result.get("sha256")),
                         (True, "OK", True, info.sha256), result)
        final = self.switch.home / info.file
        self.assertEqual(hashlib.sha256(final.read_bytes()).hexdigest(), info.sha256)
        self.assertEqual(self.pushed(), [], "no temporary file left")
        self.assertEqual(self.fleet.contexts, [], "the switch pulled nothing")

    def test_a_pushed_copy_with_a_wrong_sha256_is_removed(self):
        ops = self.ops_with(self.policy, ("os",), method="push")
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        original = LocalFile.write

        def corrupt(handle, data):
            return original(handle, data[:-1] + bytes([data[-1] ^ 1]))
        with mock.patch.object(LocalFile, "write", corrupt):
            result = ops.fetch(self.device, info, size=info.size, sha256=info.sha256)
        self.assertEqual((result["ok"], result["code"]), (False, "PUSH_SHA256_MISMATCH"), result)
        self.assertEqual(self.pushed(), [])
        self.assertFalse((self.switch.home / info.file).exists(), "nothing under the real name")

    def test_a_push_interrupted_while_writing_is_removed(self):
        ops = self.ops_with(self.policy, ("os",), method="push")
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        self.switch.fail_sftp("write", ".push-", OSError("synthetic write failure"), inactive=False)
        result = ops.fetch(self.device, info, size=info.size, sha256=info.sha256)
        self.assertEqual((result["ok"], result["code"]), (False, "PUSH_WRITE_FAILED"), result)
        self.assertEqual(self.pushed(), [])
        self.assertFalse((self.switch.home / info.file).exists())
        self.assertEqual([entry[0] for entry in self.switch.sftp_fault_log], ["write"])

    def test_a_relay_from_a_holder_switch_is_unchanged_with_push(self):
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        contexts = []
        for method in ("http", "push"):
            ops = self.ops_with(self.policy, ("os",), method=method)
            ops.fetch(self.device, info, size=info.size, sha256=info.sha256, holder=self.device)
            contexts.append(self.fleet.contexts[-1])
        self.assertEqual(contexts[0], contexts[1], "switch-to-switch forwarding is the same scp pull")
        self.assertEqual(contexts[1]["method"], "scp")
        self.assertEqual(self.pushed(), [])

    # ------------------------------------------------------------ G7 (R-046; 指导 8.25.8)
    HEALTH_NA = ("            operational  applied\n----------  -----------  -------\nstatus      N/A\n"
                 "status-led  N/A\n\nHealth issues\n=============\nNo Data\n")
    HEALTH_NOT_OK = ("            operational  applied\n----------  -----------  -------\nstatus      Not OK\n"
                     "status-led  amber\n\nHealth issues\n=============\nComponent  Status information\n"
                     "---------  ------------------\nFan1       Fan speed low\n")   # Not OK needs an issue row

    def test_an_na_health_after_the_upgrade_asks_for_a_recheck_and_then_verifies(self):
        """The engine owns the waiting; the verification only says the health was N/A (no sleep here)."""
        verify = self.ready_to_verify()
        health = self.switch.state / "health"
        ok = health.read_text()
        health.write_text(self.HEALTH_NA)
        result = verify()
        self.assertEqual((result["state"], result.get("reason")), ("HEALTH_PENDING", "HEALTH_STATUS_UNAVAILABLE"))
        self.assertEqual((result.get("health") or {}).get("command"), "nv show system health",
                         "R-046: the raw health output goes to the engine's health-wait evidence")
        self.assertIn(b"status      N/A", __import__("base64").b64decode(result["health"]["stdout_base64"]))
        self.assertIs(result.get("version_at_target"), True, "Q-113: the version read back is the target")
        (self.switch.state / "version").write_text("25.02.6077")
        other = verify()
        self.assertEqual((other["state"], other.get("reason"), other.get("version_at_target")),
                         ("UNKNOWN", "COMPONENT_VERSION_NOT_VERIFIED", False), "Q-113: another version")
        (self.switch.state / "version").write_text("25.02.7002")
        health.write_text(ok)
        verified = verify()
        self.assertEqual((verified["state"], verified["os_version"]), ("VERIFIED", "25.02.7002"), verified)

    def test_force_and_a_not_ok_health_never_ask_for_a_recheck(self):
        verify = self.ready_to_verify()
        health = self.switch.state / "health"
        health.write_text(self.HEALTH_NOT_OK)
        result = verify()
        self.assertEqual((result["state"], result.get("reason")), ("UNKNOWN", "HEALTH_DEGRADED"),
                         "not N/A: judged at once")
        self.assertIs(result.get("version_at_target"), True, "Q-113: the version read back is the target")
        health.write_text(self.HEALTH_NA)
        self.ops.force_health = True
        self.assertEqual(verify()["state"], "VERIFIED", "--force lets N/A through as FORCED, no recheck")

    # ------------------------------------------------------------ G9 (R-049; 指导 8.25.9)
    def test_dispatch_json_keeps_the_raw_health_record_for_a_later_recheck(self):
        verify = self.ready_to_verify()
        record = json.loads(self.evidence_file("dispatch.json").read_text())
        self.assertIn("health", record, "the pre-dispatch health goes into dispatch.json")
        self.assertEqual(record["health"]["command"], "nv show system health")
        self.assertIn(b"status      OK", __import__("base64").b64decode(record["health"]["stdout_base64"]))
        self.assertEqual(verify()["state"], "VERIFIED")

    def test_a_recheck_uses_the_saved_health_or_judges_the_current_one_alone(self):
        """G9 改法 4: the baseline from an earlier dispatch.json is compared as usual; without one (old
        evidence) only a clean current health passes, otherwise REVIEW HEALTH_BASELINE_MISSING."""
        result = self.ops.precheck(self.device, upgrade=True, staged_names=[], journal=self.journal)
        backup = result["backup"]
        self.assertTrue(hasattr(self.ops, "previous_backup"), "G9 reads an earlier run's access backup")
        self.assertEqual(self.ops.previous_backup(self.evidence.directory("sw01")), backup,
                         "the access backup an earlier run saved is read back")
        info = fleet_engine.PackageInfo.read(self.policy.os[1])
        self.assertTrue(self.ops.fetch(self.device, info, size=info.size, sha256=info.sha256)["ok"])
        step = ib.render_step(self.policy, self.device, component="os", package_index=1, run_id="r1",
                              switch_dir=str(self.switch.home))
        dispatched = self.ops.dispatch(self.device, step, backup=backup, staged={info.file: (info.size, info.sha256)},
                                       journal=self.journal)
        saved = json.loads(self.evidence_file("dispatch.json").read_text())
        step = ib.Step(**{**step.__dict__, "remote_dir": dispatched["remote_dir"]})
        self.until(lambda: (Path(dispatched["remote_dir"]) / "owned-exit.record").exists())
        ladder = self.until(lambda: (lambda r: r if r["kind"] == "ready" else None)(
            self.ops.ladder(self.device, dispatched["boot_before"], backup=backup, journal=self.journal)))

        def verify(baseline):
            return self.ops.verify(self.device, step, boot_after=ladder["boot_id"], before=dispatched["before_commands"],
                                   baseline_health=baseline, backup=backup, journal=self.journal)
        self.assertEqual(verify(saved["health"])["state"], "VERIFIED", "the saved raw record is the baseline")
        self.assertEqual(verify(None)["state"], "VERIFIED", "no baseline: a clean current health passes")
        (self.switch.state / "health").write_text(self.HEALTH_NOT_OK)
        self.assertEqual((lambda r: (r["state"], r.get("reason")))(verify(None)), ("REVIEW", "HEALTH_BASELINE_MISSING"))

    def test_an_os_issue_still_skips_the_access_bootstrap(self):
        """G1 (指导 8.25.1 改法 4): an OS issue holds the whole switch, so nothing is written, as before."""
        policy = policy_three(Path(self.tmp.name) / "http", selected=("bios", "cpld"))   # OS 6077 is not final
        result = self.ops_with(policy, ("bios", "cpld")).precheck(
            self.device, upgrade=True, staged_names=[], journal=self.journal)
        self.assertIn(("os", "OS_FINAL_NOT_REACHED"), result["plan"].issues)
        self.assertIsNone(result["backup"])
        self.assertFalse(self.evidence_file("access-bootstrap.json").exists())


if __name__ == "__main__":
    unittest.main()
