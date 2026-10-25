"""Real C2/P1 -> stage -> SSH carrier/PTY -> generated key shell -> receipt.

The SSH executable is a fixed PUBLIC owned program, not a real network client.
No installer, parser, receipt consumer or generated shell is mocked.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

import test_cases.test_req10b_services_keys_workflow as support
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
APP = load_script("initial_N2_receipt_real_workflow", support.INITIAL)

# This program never logs unknown argv. It only executes the pinned current
# key-install program in its owned HOME after closed PUBLIC carrier checks.
SSH_MODEL = r'''
import base64, hashlib, json, os, pathlib, re, shlex, subprocess, sys
root=pathlib.Path(os.environ["N2_MODEL_ROOT"])
def event(value):
 with (root/"events.jsonl").open("a",encoding="ascii") as stream:
  stream.write(json.dumps(value,sort_keys=True)+"\n")
def refuse():
 event({"kind":"ADAPTER_REJECT"})
 raise SystemExit(79)
args=sys.argv[1:]
outer=["-tt","-o","ConnectTimeout=2","-o","ServerAliveInterval=10",
 "-o","ServerAliveCountMax=2","-o","StrictHostKeyChecking=accept-new",
 "-o","LogLevel=ERROR","-o","ControlMaster=no","-o","ControlPath=none",
 "PUBLIC-OOB-USER@192.0.2.10"]
if len(args)!=len(outer)+1 or args[:-1]!=outer: refuse()
try: wrapper=shlex.split(args[-1])
except ValueError: refuse()
if len(wrapper)!=3 or wrapper[:2]!=["sh","-c"]: refuse()
prefix="export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
if not wrapper[2].startswith(prefix): refuse()
try: nested=shlex.split(wrapper[2][len(prefix):])
except ValueError: refuse()
inner=["ip","vrf","exec","default","ssh","-6","-tt","-o","ConnectTimeout=2",
 "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR",
 "-o","ControlMaster=no","-o","ControlPath=none",
 "-o","NumberOfPasswordPrompts=1","-B","swp7","admin@fe80::1"]
if len(nested)!=len(inner)+1 or nested[:-1]!=inner: refuse()
try: framed=shlex.split(nested[-1])
except ValueError: refuse()
if len(framed)!=3 or framed[:2]!=["sh","-c"]: refuse()
script=framed[2]
match=re.match(r'^printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; ',script)
if match is None: refuse()
nonce=match.group(1)
suffix='; task_rc=$?; printf "\\n__HTTP_IB_END_'+nonce+'__=%s\\n" "$task_rc"; exit "$task_rc"'
if not script.endswith(suffix): refuse()
try: command=shlex.split(script[match.end():-len(suffix)])
except ValueError: refuse()
if len(command)!=5 or command[:2]!=["sh","-c"] or command[3]!="--": refuse()
trusted=(root/"key-program.txt").read_text(encoding="utf-8")
if hashlib.sha256(trusted.encode()).hexdigest()!=os.environ["N2_PROGRAM_SHA"]: refuse()
if command[2]!=trusted: refuse()
try: payload=base64.b64decode(command[4],validate=True)
except ValueError: refuse()
if payload!=(root/"expected-requested-keys.txt").read_bytes(): refuse()
# No arbitrary remote command path is executable. The actual frame and
# generated shell run under an owned HOME and fixed ordinary utility PATH.
result=subprocess.run(["sh","-c",script],stdin=subprocess.DEVNULL,
 capture_output=True,timeout=5,check=False,cwd=root/"home",
 env={"HOME":str(root/"home"),"PATH":os.defpath,"LC_ALL":"C","LANG":"C"})
receipt="NONE"
begin=("\n__HTTP_IB_BEGIN_"+nonce+"__\n").encode("ascii")
end=("\n__HTTP_IB_END_"+nonce+"__="+str(result.returncode)+"\n").encode("ascii")
if result.stdout.startswith(begin) and result.stdout.endswith(end):
 body=result.stdout[len(begin):-len(end)]
 if body==b"IBSW_PUBLIC_KEYS_UPDATED\n": receipt="IBSW_PUBLIC_KEYS_UPDATED"
 if body==b"IBSW_PUBLIC_KEYS_UNCHANGED\n": receipt="IBSW_PUBLIC_KEYS_UNCHANGED"
event({"kind":"ACTUAL_SHELL","status":result.returncode,"receipt":receipt})
wire=result.stdout
mode=os.environ.get("N2_WIRE_EXTRA","0")
if mode not in ("0","1"): refuse()
if mode=="1":
 # Qualify the *real* completed shell and on-disk public output before
 # injecting a wire-only extra line. No SessionResult/receipt is fabricated.
 auth=root/"home/.ssh/authorized_keys"
 expected=(root/"expected-requested-keys.txt").read_bytes()
 if result.returncode!=0 or receipt not in (
     "IBSW_PUBLIC_KEYS_UPDATED","IBSW_PUBLIC_KEYS_UNCHANGED"): refuse()
 if not auth.is_file() or auth.is_symlink() or auth.read_bytes()!=expected: refuse()
 if not result.stdout.startswith(begin) or not result.stdout.endswith(end): refuse()
 original_body=result.stdout[len(begin):-len(end)]
 extra=b"PUBLIC-N2-EXTRA-LINE\n"
 wire=begin+original_body+extra+end
 event({"kind":"WIRE_EXTRA_AFTER_REAL_SHELL","original_status":0,
        "original_receipt":receipt,"auth_expected":True,
        "original_body_preserved":wire[len(begin):len(begin)+len(original_body)]==original_body,
        "frame_preserved":wire.startswith(begin) and wire.endswith(end),
        "extra_line_count":1})
sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
sys.stderr.buffer.write(result.stderr);sys.stderr.buffer.flush()
raise SystemExit(result.returncode)
'''


def nine(path):
    value = path.lstat()
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


class InitialKeyReceiptRealWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.initial = APP
        with mock.patch.object(sys, "argv", ["90-c2-generate_configs.py"]):
            cls.generator = load_script("N2_receipt_C2", support.GENERATOR)

    def prepare(self, directory):
        root, tool, global_path, ib_csv, p2p, _, cache, laptop, management = (
            support.Req10BServicesKeysWorkflowTests.fixture(self, directory))
        with mock.patch.object(self.generator, "_GLOBAL_FILE", str(global_path)):
            merged = self.generator.load_global("ib")
        self.assertEqual(merged["system"]["dns"]["server"], ["203.0.113.53"])
        self.assertEqual(merged["system"]["ntp"]["server"],
                         ["ntp.ubuntu.com", "time.ib.example.test"])
        self.assertEqual(merged["system"]["date-time"]["timezone"], "Asia/Taipei")
        self.assertEqual(
            support.Req10BServicesKeysWorkflowTests.run_initial(
                self, tool, ib_csv, p2p, cache, "--generate-json"), 0)
        loaded = APP.load_target_cache(cache, ib_csv, p2p, public_key_tool=tool)
        self.assertIsNotNone(loaded, "FIXTURE HOLD: real P1 cache unavailable")
        count, targets = loaded
        self.assertEqual(count, 1)
        self.assertEqual(len(targets), 1)
        target = targets[0]
        self.assertEqual(target.ib.hostname, "EXAMPLE-IB01")
        self.assertEqual(target.ethernet.login_ip, "192.0.2.10")
        baked = json.loads(cache.read_text(encoding="utf-8"))["public_keys"]
        expected = [
            {"name": "laptop.pub", "line": laptop.strip(),
             "fingerprint": support.fingerprint(laptop)},
            {"name": "mgmt-server.pub", "line": management.strip(),
             "fingerprint": support.fingerprint(management)},
        ]
        self.assertEqual(baked, expected)
        model = root / "owned-ssh-model"
        model.mkdir()
        (model / "home").mkdir()
        (model / "key-program.txt").write_text(APP._KEY_INSTALL_SCRIPT, encoding="utf-8")
        (model / "expected-requested-keys.txt").write_text(
            laptop.strip() + "\n" + management.strip() + "\n", encoding="ascii")
        executable = model / "ssh"
        executable.write_text("#!" + sys.executable + "\n" + SSH_MODEL, encoding="utf-8")
        executable.chmod(0o700)
        return root, target, baked, model, laptop.strip(), management.strip()

    def stage(self, target, keys, model, *, wire_extra=False,
              management_private_key=None):
        output = io.StringIO()
        error = None
        returned = None
        # Only the external ssh executable is substituted. Actual run_on_ib,
        # interactive_run, frame extractor, stage and generated shell execute.
        env = {
            "HOME": str(model / "home"),
            "PATH": str(model) + os.pathsep + os.defpath,
            "N2_MODEL_ROOT": str(model),
            "N2_PROGRAM_SHA": hashlib.sha256(
                APP._KEY_INSTALL_SCRIPT.encode("utf-8")).hexdigest(),
            "N2_WIRE_EXTRA": "1" if wire_extra else "0",
        }
        with mock.patch.dict(os.environ, env), redirect_stdout(output):
            try:
                returned = APP.run_key_stage(
                    target, APP.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17"),
                    "PUBLIC-OOB-USER", "PUBLIC-OOB-NOT-USED-BY-MODEL",
                    "admin", 2, keys, local=False, apply=True, authorized=True,
                    management_private_key=management_private_key)
            except BaseException as caught:
                error = caught
        events_file = model / "events.jsonl"
        self.assertTrue(events_file.is_file(), "FIXTURE HOLD: owned SSH did not report")
        events = [json.loads(line) for line in events_file.read_text(
            encoding="ascii").splitlines()]
        self.assertFalse(any(event["kind"] == "ADAPTER_REJECT" for event in events),
                         "FIXTURE HOLD: closed owned SSH carrier rejected")
        return returned, error, output.getvalue(), events

    def test_real_p1_shell_receipt_consumes_updated_and_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="N2-real-receipt-") as directory:
            _, target, keys, model, laptop, management = self.prepare(directory)
            home = model / "home"
            (home / ".ssh").mkdir()
            old = "no-agent-forwarding " + support.public_key(19, "old").strip()
            auth = home / ".ssh/authorized_keys"
            auth.write_text(old, encoding="ascii")
            result, error, printed, events = self.stage(target, keys, model)
            self.assertIsNone(error)
            self.assertIs(result, True)
            self.assertEqual(events, [{"kind": "ACTUAL_SHELL", "status": 0,
                                      "receipt": "IBSW_PUBLIC_KEYS_UPDATED"}])
            self.assertEqual(auth.read_text(encoding="ascii").splitlines(),
                             [old, laptop, management])
            self.assertEqual(printed.count("已写入，未验证"), 2)
            self.assertNotIn(": 已验证", printed)
            before = auth.read_bytes()
            inode = auth.stat().st_ino
            result, error, printed, events = self.stage(target, keys, model)
            self.assertIsNone(error)
            self.assertIs(result, True)
            self.assertEqual(events[-1], {"kind": "ACTUAL_SHELL", "status": 0,
                                         "receipt": "IBSW_PUBLIC_KEYS_UNCHANGED"})
            self.assertEqual(len(events), 2)
            self.assertEqual(auth.read_bytes(), before)
            self.assertEqual(auth.stat().st_ino, inode)
            self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o600)
            self.assertEqual(printed.count("已写入，未验证"), 2)
            self.assertNotIn(": 已验证", printed)

    def test_actual_shell_refusal_preserves_foreign_file_and_no_install_success(self):
        with tempfile.TemporaryDirectory(prefix="N2-real-refusal-") as directory:
            root, target, keys, model, _, _ = self.prepare(directory)
            home = model / "home"
            (home / ".ssh").mkdir()
            foreign = root / "PUBLIC-FOREIGN-CANARY"
            foreign.write_text("PUBLIC-CANARY-DO-NOT-TOUCH\n", encoding="ascii")
            (home / ".ssh/authorized_keys").symlink_to(foreign)
            before = (nine(foreign), foreign.read_bytes())
            result, error, printed, events = self.stage(target, keys, model)
            self.assertIsInstance(error, APP.SetupError)
            self.assertIsNone(result)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["kind"], "ACTUAL_SHELL")
            self.assertNotEqual(events[0]["status"], 0)
            self.assertEqual(events[0]["receipt"], "NONE")
            self.assertEqual((nine(foreign), foreign.read_bytes()), before)
            self.assertTrue((home / ".ssh/authorized_keys").is_symlink())
            self.assertNotIn("已写入，未验证", printed)
            self.assertNotIn(": 已验证", printed)

    def test_real_success_with_frame_internal_extra_line_is_not_promoted(self):
        with tempfile.TemporaryDirectory(prefix="N2-wire-extra-") as directory:
            root, target, keys, model, laptop, management = self.prepare(directory)
            private = root / "PUBLIC-NOT-A-PRIVATE-KEY"
            private.write_text("PUBLIC-POSSESSION-TRIPWIRE-ONLY\n", encoding="ascii")
            actual_returns = []
            real_run_on_ib = APP.run_on_ib

            def observed_run_on_ib(*args, **kwargs):
                actual = real_run_on_ib(*args, **kwargs)
                actual_returns.append((actual.exit_code, actual.output))
                return actual

            with mock.patch.object(APP, "verify_management_key_possession") as possession, \
                 mock.patch.object(APP, "run_on_ib", side_effect=observed_run_on_ib):
                result, error, printed, events = self.stage(
                    target, keys, model, wire_extra=True,
                    management_private_key=private)
            # These outside observations must establish the original real shell
            # completed before any claim about the injected consumer refusal.
            self.assertEqual(events, [
                {"kind": "ACTUAL_SHELL", "status": 0,
                 "receipt": "IBSW_PUBLIC_KEYS_UPDATED"},
                {"kind": "WIRE_EXTRA_AFTER_REAL_SHELL", "original_status": 0,
                 "original_receipt": "IBSW_PUBLIC_KEYS_UPDATED",
                 "auth_expected": True, "original_body_preserved": True,
                 "frame_preserved": True, "extra_line_count": 1},
            ], "FIXTURE HOLD: actual shell or extra-wire witness unavailable")
            auth = model / "home/.ssh/authorized_keys"
            self.assertEqual(auth.read_text(encoding="ascii"),
                             laptop + "\n" + management + "\n")
            self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o600)
            self.assertEqual(
                actual_returns,
                [(0, "IBSW_PUBLIC_KEYS_UPDATED\nPUBLIC-N2-EXTRA-LINE\n")],
                "FIXTURE HOLD: real frame extractor did not return the injected PUBLIC payload",
            )
            self.assertIsInstance(error, APP.SetupError)
            self.assertIsNone(result)
            possession.assert_not_called()
            self.assertNotIn("已写入，未验证", printed)
            self.assertNotIn(": 已验证", printed)


if __name__ == "__main__":
    unittest.main()
