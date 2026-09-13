#!/usr/bin/env python3
"""Hermetic real-script workflow contracts for BACKUP-AUTH-R1."""

from __future__ import annotations

import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SECRET = "SENTINEL spaces 'quotes' $dollar \\slash 密码"
TARGET = "192.0.2.10"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def public_key_blob(fill: int) -> str:
    algorithm = b"ssh-ed25519"
    raw = (
        struct.pack(">I", len(algorithm)) + algorithm
        + struct.pack(">I", 32) + bytes([fill]) * 32
    )
    return base64.b64encode(raw).decode("ascii")


def public_fingerprint(blob: str) -> str:
    digest = hashlib.sha256(base64.b64decode(blob)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


PINNED_BLOB = public_key_blob(0x11)
OFFERED_BLOB = public_key_blob(0x22)
PINNED_FINGERPRINT = public_fingerprint(PINNED_BLOB)
OFFERED_FINGERPRINT = public_fingerprint(OFFERED_BLOB)


class Gate:
    cooldown_seconds = 600
    decision = SimpleNamespace(allowed=True, reason="allowed")

    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    @staticmethod
    def mark_success():
        return "2026-09-11T23:00:00+08:00"


class BackupAuthenticationWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = load_module(
            "backup_auth_real_worker",
            ROOT / "monitor/switch-collection-worker.py",
        )

    @staticmethod
    def _expected_pin_name(scope: str, target: str) -> str:
        identity = json.dumps(
            {"scope": scope, "target": target},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(identity).hexdigest() + ".known_hosts"

    @staticmethod
    def _write_fake_ssh(path: Path) -> None:
        source = f'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import shlex
import sys

PINNED_BLOB = {PINNED_BLOB!r}
OFFERED_BLOB = {OFFERED_BLOB!r}
OFFERED_FINGERPRINT = {OFFERED_FINGERPRINT!r}

args = sys.argv[1:]
if args == ["-V"]:
    print("OpenSSH_10.2p1 fake-hermetic", file=sys.stderr)
    raise SystemExit(0)
if "-G" in args:
    print("knownhostscommand /usr/bin/printf")
    raise SystemExit(0)
options = {{}}
index = 0
while index < len(args) - 2:
    if args[index] == "-o" and index + 1 < len(args):
        key, _, value = args[index + 1].partition("=")
        options.setdefault(key.casefold(), []).append(value)
        index += 2
    else:
        index += 1
target = args[-2].split("@", 1)[-1]
command = args[-1]
stdin_bytes = sys.stdin.buffer.read()
expected_hash = os.environ["TEST_SECRET_SHA256"]
secret = {SECRET!r}
matching_env_keys = sorted(
    key for key, value in os.environ.items()
    if secret in value
)
event = {{
    "argv": args,
    "target": target,
    "command": command,
    "options": options,
    "secret_env_keys": matching_env_keys,
    "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
    "askpass_invoked": False,
    "askpass_sha256": None,
    "fifo": None,
    "fifo_mode": None,
    "fifo_nlink": None,
    "fifo_owner": None,
    "fifo_is_fifo": None,
    "helper": os.environ.get("SSH_ASKPASS"),
    "known_hosts_command_invoked": False,
    "known_hosts_command_rc": None,
}}

is_password = options.get("batchmode") == ["no"]
known_values = options.get("userknownhostsfile", [])
known = Path(known_values[0]) if len(known_values) == 1 else None

if is_password:
    changed_mode = os.environ.get("FAKE_SSH_CHANGED", "")
    changed = changed_mode not in ("", "0")
    server_algorithm = (
        "ssh-rsa" if changed_mode == "different-algorithm"
        else "ssh-ed25519"
    )
    server_blob = (
        OFFERED_BLOB if changed else PINNED_BLOB
    )
    commands = options.get("knownhostscommand", [])
    command_mode = os.environ.get("FAKE_KHC_MODE", "normal")
    khc_rc = 0
    khc_stdout = ""
    if len(commands) != 1 or command_mode == "missing":
        khc_rc = 127
    elif command_mode == "nonzero":
        khc_rc = 9
        event["known_hosts_command_invoked"] = True
    elif command_mode == "empty":
        event["known_hosts_command_invoked"] = True
    else:
        invoked = subprocess.run(
            shlex.split(commands[0].replace("%%", "%")), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, check=False,
        )
        event["known_hosts_command_invoked"] = True
        khc_rc = invoked.returncode
        khc_stdout = invoked.stdout
    event["known_hosts_command_rc"] = khc_rc
    records = [line.split() for line in khc_stdout.splitlines() if line.strip()]
    matched = any(
        len(fields) >= 3 and target in fields[0].split(",")
        and fields[1] == server_algorithm and fields[2] == server_blob
        for fields in records
    )
    secure_options = (
        options.get("stricthostkeychecking") == ["yes"]
        and options.get("userknownhostsfile") == ["/dev/null"]
        and options.get("globalknownhostsfile") == ["/dev/null"]
        and options.get("hostkeyalgorithms") == [server_algorithm]
        and options.get("checkhostip") == ["no"]
        and options.get("updatehostkeys") == ["no"]
    )
    if khc_rc or not matched or not secure_options:
        fifo_text = os.environ.get("ZTP_BACKUP_PASSWORD_FIFO")
        if fifo_text:
            fifo = Path(fifo_text)
            metadata = fifo.lstat()
            event.update({{
                "fifo": fifo_text,
                "fifo_mode": stat.S_IMODE(metadata.st_mode),
                "fifo_nlink": metadata.st_nlink,
                "fifo_owner": metadata.st_uid,
                "fifo_is_fifo": stat.S_ISFIFO(metadata.st_mode),
            }})
        with open(os.environ["FAKE_SSH_RECORD"], "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\\n")
        print("REMOTE HOST IDENTIFICATION HAS CHANGED!", file=sys.stderr)
        print("offered_fingerprint=" + OFFERED_FINGERPRINT, file=sys.stderr)
        print("Host key verification failed.", file=sys.stderr)
        raise SystemExit(255)

if is_password and changed:
    fifo_text = os.environ.get("ZTP_BACKUP_PASSWORD_FIFO")
    if fifo_text:
        fifo = Path(fifo_text)
        metadata = fifo.lstat()
        event.update({{
            "fifo": fifo_text,
            "fifo_mode": stat.S_IMODE(metadata.st_mode),
            "fifo_nlink": metadata.st_nlink,
            "fifo_owner": metadata.st_uid,
            "fifo_is_fifo": stat.S_ISFIFO(metadata.st_mode),
        }})
    with open(os.environ["FAKE_SSH_RECORD"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\\n")
    print("REMOTE HOST IDENTIFICATION HAS CHANGED!", file=sys.stderr)
    print("offered_fingerprint=" + OFFERED_FINGERPRINT, file=sys.stderr)
    print("Host key verification failed.", file=sys.stderr)
    raise SystemExit(255)

if is_password:
    fifo_text = os.environ.get("ZTP_BACKUP_PASSWORD_FIFO")
    if fifo_text:
        fifo = Path(fifo_text)
        metadata = fifo.lstat()
        event.update({{
            "fifo": fifo_text,
            "fifo_mode": stat.S_IMODE(metadata.st_mode),
            "fifo_nlink": metadata.st_nlink,
            "fifo_owner": metadata.st_uid,
            "fifo_is_fifo": stat.S_ISFIFO(metadata.st_mode),
        }})
    helper = os.environ.get("SSH_ASKPASS")
    if helper:
        asked = subprocess.run(
            [helper], env=os.environ, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        event["askpass_invoked"] = True
        event["askpass_sha256"] = hashlib.sha256(asked.stdout.rstrip(b"\\n")).hexdigest()
        if asked.returncode:
            print("askpass helper failed", file=sys.stderr)
            raise SystemExit(253)
    if known is not None and not known.exists():
        known.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        known.write_text(
            target + " ssh-ed25519 " + PINNED_BLOB + "\\n", encoding="utf-8",
        )
        known.chmod(0o600)

with open(os.environ["FAKE_SSH_RECORD"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\\n")

if options.get("batchmode") == ["yes"]:
    print("key rejected", file=sys.stderr)
    raise SystemExit(255)
if command.startswith("hostname"):
    print("leaf01")
elif command.startswith("sudo "):
    print("set:")
    print("  system:")
    print("    hostname: leaf01")
elif "eth0/address" in command:
    print("02:00:00:00:00:01")
elif "addr show eth0" in command and "a[1]" in command:
    print("192.0.2.10")
elif "addr show eth0" in command and "a[2]" in command:
    print("24")
elif "route show default" in command:
    print("192.0.2.1")
elif "platform inventory" in command:
    print("SN-LEAF01")
'''
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def _write_fake_keyscan(path: Path) -> None:
        source = f'''#!/usr/bin/env python3
import json
import os
import sys

SECRET = {SECRET!r}
TARGET = {TARGET!r}
PINNED_BLOB = {PINNED_BLOB!r}
OFFERED_BLOB = {OFFERED_BLOB!r}
args = sys.argv[1:]
expected = ["-T", "10", "-t", "ed25519", TARGET]
secret_env_keys = sorted(
    key for key, value in os.environ.items() if SECRET in value
)
event = {{
    "event_type": "keyscan",
    "argv": args,
    "target": TARGET,
    "command": "ssh-keyscan",
    "options": {{}},
    "secret_env_keys": secret_env_keys,
    "stdin_sha256": None,
    "askpass_invoked": False,
    "askpass_sha256": None,
    "fifo": None,
    "fifo_mode": None,
    "fifo_nlink": None,
    "fifo_owner": None,
    "fifo_is_fifo": None,
    "helper": None,
}}
with open(os.environ["FAKE_SSH_RECORD"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\\n")
if args != expected or any(SECRET in value for value in args):
    print("unexpected ssh-keyscan invocation", file=sys.stderr)
    raise SystemExit(64)
changed = os.environ.get("FAKE_SSH_CHANGED", "") not in ("", "0")
blob = OFFERED_BLOB if changed else PINNED_BLOB
print(TARGET + " ssh-ed25519 " + blob)
'''
        path.write_text(source, encoding="utf-8")
        path.chmod(0o755)

    @staticmethod
    def _stage_real_collector(root: Path) -> tuple[Path, Path]:
        ztp = root / "ztp"
        backup = ztp / "backup"
        backup.mkdir(parents=True)
        for relative in (
            "ztp/backup/yaml-collect.py",
            "ztp/environment_probe.py",
            "ztp/dynamic_air_inventory.py",
        ):
            source = ROOT / relative
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

        project = root / "project output [prod] $literal"
        project.mkdir()
        inventory = project / "02-devices_config.csv"
        inventory.write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw,eth1_mac\n"
            "leaf01,eth,leaf,192.0.2.10,24,192.0.2.1,"
            "02:00:00:00:00:01,,,,\n",
            encoding="utf-8",
        )
        (backup / "02-devices_config.csv").symlink_to(inventory)
        output = project / "99-output-backup"
        output.mkdir()
        (backup / "yaml-backup").symlink_to(output, target_is_directory=True)
        return backup / "yaml-collect.py", output

    @staticmethod
    def _events(record: Path) -> list[dict]:
        if not record.exists():
            return []
        return [json.loads(line) for line in record.read_text().splitlines() if line]

    def _run_worker(self, collector: Path, password: str, scope: str):
        statuses = []
        stdout = io.StringIO()
        stderr = io.StringIO()
        self.worker._LANE_CANCEL[self.worker.BACKUP_LANE].clear()
        with mock.patch.object(self.worker, "YAML_BACKUP_SCRIPT", collector), \
                mock.patch.object(
                    self.worker, "active_project_identity", return_value="project-a",
                ), mock.patch.object(self.worker, "CollectionGate", Gate), \
                mock.patch.object(
                    self.worker, "write_yaml_backup_status",
                    side_effect=lambda state, **extra: statuses.append((state, extra)),
                ), redirect_stdout(stdout), redirect_stderr(stderr):
            result = self.worker.run_yaml_backup(password, scope, 30, 1)
        return result, statuses, stdout.getvalue(), stderr.getvalue()

    def test_real_worker_collector_fake_ssh_fifo_tofu_and_changed_key(self):
        secret_hash = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
        sudo_hash = hashlib.sha256((SECRET + "\n").encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            collector, project_output = self._stage_real_collector(root)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_ssh = fake_bin / "ssh"
            self._write_fake_ssh(fake_ssh)
            self._write_fake_keyscan(fake_bin / "ssh-keyscan")
            record = root / "fake-ssh.jsonl"
            askpass_root = root / "configured askpass root"
            askpass_root.mkdir(mode=0o700)
            askpass_root.chmod(0o700)
            unusable_tmp = root / "not-a-directory"
            unusable_tmp.write_text("no fallback\n", encoding="utf-8")
            environment = {
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                "HTTP_ZTP_ASKPASS_TMPDIR": str(askpass_root),
                "TMPDIR": str(unusable_tmp),
                "TEST_SECRET_SHA256": secret_hash,
                "FAKE_SSH_RECORD": str(record),
                "FAKE_SSH_CHANGED": "0",
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                ok, statuses, stdout, stderr = self._run_worker(
                    collector, SECRET, "prod",
                )

            self.assertTrue(ok, stdout + stderr)
            self.assertEqual("success", statuses[-1][0])
            self.assertNotIn(SECRET, stdout + stderr + repr(statuses))
            self.assertNotIn(SECRET, record.read_text(encoding="utf-8"))
            events = self._events(record)
            key_events = [
                event for event in events
                if event["options"].get("batchmode") == ["yes"]
            ]
            password_events = [
                event for event in events
                if event["options"].get("batchmode") == ["no"]
            ]
            initial_scan_events = [
                event for event in events if event.get("event_type") == "keyscan"
            ]
            self.assertEqual(1, len(key_events))
            self.assertGreater(len(password_events), 1)
            self.assertEqual(1, len(initial_scan_events))
            self.assertEqual([], initial_scan_events[0]["secret_env_keys"])
            self.assertEqual(["no"], key_events[0]["options"]["stricthostkeychecking"])
            self.assertEqual(["/dev/null"], key_events[0]["options"]["userknownhostsfile"])

            fifo_paths = []
            for event in password_events:
                self.assertEqual([], event["secret_env_keys"])
                self.assertTrue(event["askpass_invoked"])
                self.assertEqual(secret_hash, event["askpass_sha256"])
                self.assertTrue(event["fifo_is_fifo"])
                self.assertEqual(0o600, event["fifo_mode"])
                self.assertEqual(1, event["fifo_nlink"])
                self.assertEqual(os.geteuid(), event["fifo_owner"])
                self.assertEqual(
                    ["yes"],
                    event["options"]["stricthostkeychecking"],
                )
                self.assertEqual(
                    ["/dev/null"], event["options"]["globalknownhostsfile"],
                )
                self.assertEqual(["1"], event["options"]["numberofpasswordprompts"])
                self.assertEqual(1, len(event["options"]["userknownhostsfile"]))
                self.assertEqual(
                    ["/dev/null"], event["options"]["userknownhostsfile"],
                )
                self.assertEqual(
                    ["ssh-ed25519"], event["options"]["hostkeyalgorithms"],
                )
                self.assertEqual(["no"], event["options"]["checkhostip"])
                self.assertEqual(["no"], event["options"]["updatehostkeys"])
                self.assertTrue(event["known_hosts_command_invoked"])
                self.assertEqual(0, event["known_hosts_command_rc"])
                fifo_paths.append(Path(event["fifo"]))
                self.assertTrue(Path(event["helper"]).is_relative_to(askpass_root))
            self.assertEqual(len(fifo_paths), len(set(fifo_paths)))
            self.assertTrue(all(not path.exists() for path in fifo_paths))
            self.assertEqual([], list(askpass_root.iterdir()))
            sudo_events = [
                event for event in password_events
                if event["command"].startswith("sudo ")
            ]
            self.assertEqual(1, len(sudo_events))
            self.assertEqual(sudo_hash, sudo_events[0]["stdin_sha256"])

            pins = list((project_output / ".ssh-known-hosts").glob("*.known_hosts"))
            self.assertEqual(1, len(pins))
            pin = pins[0].resolve()
            self.assertEqual(
                self._expected_pin_name("prod", TARGET), pin.name,
            )
            self.assertEqual(0o600, stat.S_IMODE(pin.stat().st_mode))
            self.assertEqual(1, pin.stat().st_nlink)
            self.assertIn(PINNED_BLOB, pin.read_text(encoding="utf-8"))

            for helper_mode in ("missing", "nonzero", "empty"):
                record.write_text("", encoding="utf-8")
                environment["FAKE_KHC_MODE"] = helper_mode
                with self.subTest(helper_mode=helper_mode), mock.patch.dict(
                    os.environ, environment, clear=False,
                ):
                    failed, failed_statuses, failed_stdout, failed_stderr = (
                        self._run_worker(collector, SECRET, "prod")
                    )
                self.assertFalse(failed, failed_stdout + failed_stderr)
                self.assertEqual("failed", failed_statuses[-1][0])
                failed_password = [
                    event for event in self._events(record)
                    if event["options"].get("batchmode") == ["no"]
                ]
                self.assertEqual(1, len(failed_password))
                self.assertFalse(failed_password[0]["askpass_invoked"])
                self.assertFalse(any(
                    event["command"].startswith("sudo ")
                    for event in failed_password
                ))
                self.assertNotIn(
                    SECRET,
                    failed_stdout + failed_stderr + record.read_text(encoding="utf-8"),
                )
            environment.pop("FAKE_KHC_MODE", None)

            record.write_text("", encoding="utf-8")
            environment["FAKE_SSH_CHANGED"] = "1"
            with mock.patch.dict(os.environ, environment, clear=False):
                ok, statuses, stdout, stderr = self._run_worker(
                    collector, SECRET, "prod",
                )
            combined = stdout + stderr
            self.assertFalse(ok, combined)
            self.assertEqual("failed", statuses[-1][0])
            changed_events = [
                event for event in self._events(record)
                if event["options"].get("batchmode") == ["no"]
            ]
            scan_events = [
                event for event in self._events(record)
                if event.get("event_type") == "keyscan"
            ]
            self.assertEqual(1, len(changed_events))
            self.assertEqual(1, len(scan_events))
            self.assertEqual([], scan_events[0]["secret_env_keys"])
            self.assertNotIn(SECRET, " ".join(scan_events[0]["argv"]))
            self.assertFalse(changed_events[0]["askpass_invoked"])
            self.assertEqual([], changed_events[0]["secret_env_keys"])
            self.assertTrue(changed_events[0]["fifo_is_fifo"])
            self.assertFalse(Path(changed_events[0]["fifo"]).exists())
            self.assertIn("pinned_fingerprint=" + PINNED_FINGERPRINT, combined)
            self.assertIn("offered_fingerprint=" + OFFERED_FINGERPRINT, combined)
            self.assertNotIn(PINNED_BLOB, combined)
            self.assertNotIn(OFFERED_BLOB, combined)
            self.assertNotIn(SECRET, combined + record.read_text(encoding="utf-8"))
            remedy_lines = [
                line.strip() for line in combined.splitlines()
                if line.strip().startswith("rm -- ")
            ]
            self.assertEqual(1, len(remedy_lines), combined)
            self.assertEqual(["rm", "--", str(pin)], shlex.split(remedy_lines[0]))
            self.assertTrue(pin.is_file())
            self.assertFalse(pin.is_symlink())
            self.assertNotIn("*", remedy_lines[0])
            self.assertNotIn(str(pin.parent) + "'", remedy_lines[0])

            record.write_text("", encoding="utf-8")
            environment["FAKE_SSH_CHANGED"] = "different-algorithm"
            with mock.patch.dict(os.environ, environment, clear=False):
                ok, statuses, stdout, stderr = self._run_worker(
                    collector, SECRET, "prod",
                )
            self.assertFalse(ok, stdout + stderr)
            different_events = [
                event for event in self._events(record)
                if event["options"].get("batchmode") == ["no"]
            ]
            self.assertEqual(1, len(different_events))
            self.assertFalse(different_events[0]["askpass_invoked"])
            self.assertFalse(any(
                event["command"].startswith("sudo ") for event in different_events
            ))

    def test_pin_oracle_separates_same_target_between_prod_and_air(self):
        prod = self._expected_pin_name("prod", TARGET)
        air = self._expected_pin_name("air", TARGET)
        self.assertRegex(prod, r"^[0-9a-f]{64}\.known_hosts$")
        self.assertRegex(air, r"^[0-9a-f]{64}\.known_hosts$")
        self.assertNotEqual(prod, air)


if __name__ == "__main__":
    unittest.main()
