"""v2 upgrade: the two scripts that run ON the switch (owner 2026-10-23; review 15.3, 15.8, 15.13).

ibsw-v2-check.sh is sent over SSH stdin and only reads: every fact comes back as one
IBSW_ITEM line, commands that read stdin cannot eat the rest of the script, upgrade step
directories report launch boot, liveness, post-install markers and exit code.
tools/fleet_fetch_helper.py pulls one package (HTTP, or scp with the password on stdin only),
checks size and sha256 before the final rename and reports which side failed.
Stub `nv`, `curl` and `scp` programs stand in for the switch.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "infiniband/bringup/xdr-upgrade/ibsw-v2-check.sh"
FETCH = ROOT / "tools/fleet_fetch_helper.py"
BOOT = "11111111-2222-3333-4444-555555555555"
PASSWORD = "secret-value"
WRONG = "example"


def stub(directory: Path, name: str, body: str):
    path = directory / name
    path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)
    return path


def items(stdout: str):
    found = {}
    for line in stdout.splitlines():
        if line.startswith("IBSW_ITEM "):
            _tag, name, rc, out, err = line.split(" ")
            decode = lambda value: "" if value == "-" else base64.b64decode(value).decode()  # noqa: E731
            found[name] = (int(rc), decode(out), decode(err))
    return found


class CheckScriptTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.bin, self.sysroot, self.home = base / "bin", base / "root", base / "home"
        for path in (self.bin, self.home, self.sysroot / "proc/sys/kernel/random", self.sysroot / "sys/class/net/eth0"):
            path.mkdir(parents=True)
        self.home.chmod(0o755)
        (self.sysroot / "proc/sys/kernel/random/boot_id").write_text(BOOT + "\n")
        (self.sysroot / "proc/uptime").write_text("1234.56 999.00\n")
        (self.sysroot / "sys/class/net/eth0/address").write_text("02:00:00:00:00:01\n")
        stub(self.bin, "nv", """
            import sys
            words = sys.argv[1:]
            if words[:2] == ["config", "show"]:
                sys.stdin.read()                        # a reader of stdin must not eat the script
                print("nv set system hostname sw01")
            elif words[:2] == ["config", "diff"]:
                pass
            elif words == ["show", "system", "version"]:
                print("operational  applied\\nbuild-date  2026\\nimage  25.02.0001")
            elif words == ["show", "platform", "firmware"]:
                print("BIOS 0ACQF_06.01.003")
            elif words == ["show", "system", "health"]:
                print("status OK")
            else:
                sys.exit(2)
        """)
        stub(self.bin, "hostname", "print('sw01')\n")
        stub(self.bin, "timeout", """
            import os, sys
            os.execvp(sys.argv[2], sys.argv[2:])
        """)
        stub(self.bin, "stat", """
            import os, sys
            fmt, path = sys.argv[2], sys.argv[-1]
            item = os.stat(path)
            print(item.st_size if fmt == "%s" else int(item.st_mtime))
        """)
        stub(self.bin, "sha256sum", """
            import hashlib, sys
            path = sys.argv[-1]
            print(hashlib.sha256(open(path, "rb").read()).hexdigest() + "  " + path)
        """)
        stub(self.bin, "getent", "print('admin:x:1000:1000::/home/admin:/bin/bash')\n")
        stub(self.bin, "systemctl", "print('ActiveState=active\\nSubState=running')\n")
        stub(self.bin, "pgrep", """
            import os, sys
            pattern = sys.argv[-1]
            step = pattern.split("/(runner")[0]
            sys.exit(0 if os.path.exists(os.path.join(step, "ALIVE")) else 1)
        """)

    def run_check(self, *args):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "IBSW_SYSROOT": str(self.sysroot), "LC_ALL": "C"}
        return subprocess.run(["/bin/bash", "-s", "--", *args], input=CHECK.read_bytes(), capture_output=True,
                              env=env, timeout=60)

    def step(self, name, *, stdout="", launch=None, exit_record=None, alive=False, runner=True):
        path = self.home / name
        path.mkdir()
        (path / ("runner.sh" if runner else "step.sh")).write_text("#\n")
        (path / "execution.stdout").write_text(stdout)
        if launch:
            (path / "launch.record").write_text(launch + "\n")
        if exit_record:
            (path / "owned-exit.record").write_text(exit_record)
        if alive:
            (path / "ALIVE").write_text("")
        return path

    def test_precheck_reports_every_fact_and_survives_stdin_readers(self):
        package = self.home / "image.bin"
        package.write_bytes(b"image-bytes")
        self.step(".ibsw-r1-sw01-os-0000-" + "a" * 32, stdout="IBSW_STAGE=PACKAGE_READY\nIBSW_STAGE=INSTALL_REQUESTED\n",
                  launch=BOOT + " 4242", exit_record="IBSW_OWNED_EXIT_V1\nr1\nsw01\nos\nos-0000\n" + "b" * 64 + "\n0\n")
        self.step(".ibsw-r0-sw01-cpld-" + "c" * 32, stdout="IBSW_STAGE=PACKAGE_DOWNLOAD\n", alive=True, runner=False)
        (self.home / ".ibsw-r1-tmpdownload").write_bytes(b"v1 temporary download file")   # not a step directory
        (self.home / (".ibsw-r2-sw01-bios-" + "d" * 32)).mkdir()                       # no runner/step: ignored
        done = self.run_check("precheck", str(self.home), "image.bin", "missing.bin")
        self.assertEqual(done.returncode, 0, done.stderr)
        out = done.stdout.decode()
        self.assertTrue(out.startswith("IBSW_CHECK_BEGIN precheck\n") and out.endswith("IBSW_CHECK_END ok\n"), out)
        found = items(out)
        self.assertEqual(list(found), ["identity", "boot_id", "uptime", "now", "account", "version", "firmware", "health",
                                       "config_show", "config_diff", "capability", "free_kib", "runs", "staged"])
        self.assertEqual(found["identity"], (0, "sw01\n02:00:00:00:00:01\n", ""))
        self.assertEqual(found["boot_id"][1].strip(), BOOT)
        self.assertEqual(found["uptime"][1].strip(), "1234.56")
        self.assertTrue(found["now"][1].strip().isdigit())
        self.assertEqual(found["config_show"], (0, "nv set system hostname sw01\n", ""))
        self.assertEqual(found["config_diff"], (0, "", ""))
        self.assertIn("image  25.02.0001", found["version"][1])
        self.assertEqual(found["staged"][1].splitlines(), [
            f"image.bin 11 {hashlib.sha256(b'image-bytes').hexdigest()}", "missing.bin - -"])
        runs = sorted(line.split(" ") for line in found["runs"][1].splitlines())
        self.assertEqual([(row[0], row[1], row[3], row[4], row[5]) for row in runs], [
            (".ibsw-r0-sw01-cpld-" + "c" * 32, "-", "1", "0", "-"),
            (".ibsw-r1-sw01-os-0000-" + "a" * 32, BOOT, "0", "1", "0")])
        self.assertTrue(all(row[2].isdigit() for row in runs), "stdout mtime is reported for the boot comparison")

    def test_status_ladder_and_unknown_mode(self):
        step = self.step(".ibsw-r1-sw01-cpld-" + "e" * 32, launch=BOOT + " 77",
                         stdout="{binding}\nIBSW_STAGE=PACKAGE_READY\nIBSW_COMPONENT_STAGE=BURN_REQUESTED\n"
                                "IBSW_STAGE=CPLD_BURN\nnoise\n")
        found = items(self.run_check("status", str(step)).stdout.decode())
        self.assertEqual(found["step"][1].splitlines(), [
            "header {binding}", "launch " + BOOT + " 77", "exit ", "IBSW_STAGE=PACKAGE_READY", "IBSW_COMPONENT_STAGE=BURN_REQUESTED",
            "IBSW_STAGE=CPLD_BURN"])
        found = items(self.run_check("ladder").stdout.decode())
        self.assertEqual(list(found), ["boot_id", "nvued", "version"])
        self.assertIn("SubState=running", found["nvued"][1])
        done = self.run_check("reboot")
        self.assertEqual((done.returncode, done.stdout.decode().splitlines()[-1]), (64, "IBSW_CHECK_END unknown-mode"))


class FetchHelperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.bin, self.dest, self.source = base / "bin", base / "dest", base / "source"
        for path in (self.bin, self.dest, self.source):
            path.mkdir()
        self.dest.chmod(0o700)
        self.payload = b"nvos-image-payload" * 1000
        (self.source / "image.bin").write_bytes(self.payload)
        self.state = base / "state"
        self.state.mkdir()
        self.curl = stub(self.bin, "curl", f"""
            import os, sys
            state = {str(self.state)!r}
            argv = sys.argv[1:]
            out = argv[argv.index("-o") + 1]
            counter = os.path.join(state, "curl-calls")
            calls = int(open(counter).read()) + 1 if os.path.exists(counter) else 1
            open(counter, "w").write(str(calls))
            mode = open(os.path.join(state, "curl-mode")).read().strip()
            if mode == "refuse-once" and calls == 1:
                sys.stdout.write("000|0|0.0|0"); sys.exit(7)
            if mode == "404":
                sys.stdout.write("404|0|0.1|0"); sys.exit(22)
            data = open({str(self.source / "image.bin")!r}, "rb").read()
            if mode == "corrupt":
                data = data[:-1] + b"X"
            open(out, "wb").write(data)
            sys.stdout.write("200|%d|0.5|1000" % len(data))
        """)
        self.scp = stub(self.bin, "scp", f"""
            import json, os, sys
            state = {str(self.state)!r}
            argv = sys.argv[1:]
            options = [argv[i + 1] for i, word in enumerate(argv) if word == "-o"]
            trust = next(o.split("=", 1)[1] for o in options if o.startswith("UserKnownHostsFile="))
            json.dump(dict(argv=argv, trust=open(trust).read()), open(os.path.join(state, "scp-call"), "w"))
            for attempt in range(2):
                sys.stdout.write("admin@192.0.2.20's password: "); sys.stdout.flush()
                if sys.stdin.readline().rstrip("\\n") == open(os.path.join(state, "password")).read():
                    break
                sys.stdout.write("Permission denied, please try again.\\n")
            else:
                sys.stdout.write("admin@192.0.2.20: Permission denied (password).\\n"); sys.exit(1)
            remote = argv[-2].split(":", 1)[1].strip("'")
            open(argv[-1], "wb").write(open(remote, "rb").read())
        """)

    def fetch(self, **overrides):
        cfg = dict(method="http", dest_dir=str(self.dest), name="image.bin", size=len(self.payload),
                   sha256=hashlib.sha256(self.payload).hexdigest(), timeout=30, retry_sleep=0,
                   url="http://192.0.2.10/images/image.bin", curl=str(self.curl), scp=str(self.scp))
        cfg.update(overrides)
        done = subprocess.run([sys.executable, "-B", str(FETCH)], input=json.dumps(cfg).encode(),
                              capture_output=True, timeout=60)
        lines = done.stdout.decode().splitlines()
        self.assertEqual(len(lines), 1, done.stdout + done.stderr)
        self.assertTrue(lines[0].startswith("IBSW_FETCH_RESULT="))
        result = json.loads(lines[0].split("=", 1)[1])
        self.assertEqual(done.returncode, 0 if result["ok"] else 1)
        self.assertNotIn(PASSWORD.encode(), done.stdout + done.stderr)
        self.assertEqual([p.name for p in self.dest.iterdir() if p.name.startswith(".fleet-")], [],
                         "no temporary file or trust directory is left behind")
        return result

    def mode(self, value):
        (self.state / "curl-mode").write_text(value)

    def test_http_pull_retries_transient_failures_and_verifies_before_rename(self):
        self.mode("refuse-once")
        result = self.fetch()
        self.assertEqual((result["ok"], result["code"], len(result["attempts"])), (True, "OK", 2))
        self.assertEqual((self.dest / "image.bin").read_bytes(), self.payload)
        self.assertEqual(self.fetch()["code"], "ALREADY_PRESENT")

    def test_http_failures_are_classified_and_leave_no_file(self):
        self.mode("corrupt")
        result = self.fetch()
        self.assertEqual((result["ok"], result["class"], result["code"]), (False, "source", "CONTENT_MISMATCH"))
        self.assertFalse((self.dest / "image.bin").exists())
        self.mode("404")
        result = self.fetch()
        self.assertEqual((result["class"], result["code"], len(result["attempts"])), ("source", "HTTP_FAILED", 1))
        result = self.fetch(size=10 ** 15)
        self.assertEqual((result["class"], result["code"]), ("receiver", "NO_SPACE"))
        self.dest.chmod(0o770)
        result = self.fetch()
        self.assertEqual((result["class"], result["code"]), ("receiver", "DESTINATION_UNSAFE"))
        self.dest.chmod(0o700)
        result = self.fetch(name="../escape")
        self.assertEqual((result["class"], result["code"]), ("receiver", "CONTEXT_INVALID"))

    def test_scp_pull_uses_the_password_only_once_and_only_on_stdin(self):
        (self.state / "password").write_text(PASSWORD)
        keys = "192.0.2.20 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureOnlyHostKeyMaterialAAAAAAAAAAAAAAA"
        common = dict(method="scp", host="192.0.2.20", user="admin", port=22, host_keys=keys,
                      path=str(self.source / "image.bin"))
        result = self.fetch(**{"password": PASSWORD}, **common)
        self.assertEqual((result["ok"], result["code"]), (True, "OK"))
        call = json.loads((self.state / "scp-call").read_text())
        options = [call["argv"][i + 1] for i, word in enumerate(call["argv"]) if word == "-o"]
        self.assertIn("PubkeyAuthentication=no", options)
        self.assertIn("PreferredAuthentications=password,keyboard-interactive", options)
        self.assertIn("StrictHostKeyChecking=yes", options)
        self.assertEqual(call["trust"].strip(), keys, "only the pinned source keys are trusted")
        self.assertNotIn(PASSWORD, json.dumps(call["argv"]))
        (self.dest / "image.bin").unlink()
        result = self.fetch(**{"password": WRONG}, **common)
        self.assertEqual((result["ok"], result["class"], result["code"]), (False, "source", "SOURCE_AUTH_FAILED"))


if __name__ == "__main__":
    unittest.main()
