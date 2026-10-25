"""REQ10C direct contract for --auto, cache origin, and credential safety.

Values and safety predicates come from requirements §10C, not the implementation.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import base64
import hashlib
import json
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(os.environ.get("REQ10C_TEST_ROOT") or Path(__file__).resolve().parents[1])
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
UNSETUP = ROOT / "DAY0-Prepare/02-unsetup.py"


def _h1_owned_scheduler(test, app, base, credentials=None, *, guard_kind,
                        expected_target=None):
    """Only H1: real early guard/pause, owned external scheduler and state."""
    from contextlib import ExitStack, contextmanager
    from functools import wraps
    import shlex
    import shutil
    import stat
    import subprocess

    @contextmanager
    def scope(base=base):
        def hold():
            error = RuntimeError("FIXTURE HOLD: H1 owned scheduler prerequisite unavailable")
            try:
                raise error from None
            except RuntimeError:
                error.__cause__ = error.__context__ = None
                raise

        if guard_kind not in ("world-mode", "symlink", "unlinked"):
            hold()
        if not all(getattr(os, key, 0) for key in ("O_NOFOLLOW", "O_CLOEXEC", "O_DIRECTORY")):
            hold()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")

        def nine(info):
            return tuple(getattr(info, name) for name in fields)

        def snapshot(path):
            before = nine(path.lstat())
            if stat.S_ISLNK(before[2]):
                raw = os.readlink(path)
                if before != nine(path.lstat()):
                    hold()
                return before, raw
            if not stat.S_ISREG(before[2]) or before[5] != 1 or before[6] > 1048576:
                hold()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                if nine(os.fstat(fd)) != before:
                    hold()
                readings = []
                for _ in range(2):
                    os.lseek(fd, 0, os.SEEK_SET)
                    parts, total = [], 0
                    while True:
                        part = os.read(fd, min(65536, 1048577 - total))
                        if not part:
                            break
                        total += len(part)
                        if total > 1048576:
                            hold()
                        parts.append(part)
                    if nine(os.fstat(fd)) != before or nine(path.lstat()) != before:
                        hold()
                    readings.append(b"".join(parts))
                if readings[0] != readings[1] or len(readings[0]) != before[6]:
                    hold()
                return before, readings[0]
            finally:
                os.close(fd)

        def directory(path):
            path.mkdir(mode=0o700)
            path.chmod(0o700)  # This exact freshly created owned directory only.
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o777 != 0o700:
                hold()

        def stage(path, raw, mode):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
            try:
                os.fchmod(fd, mode)
                offset = 0
                while offset < len(raw):
                    amount = os.write(fd, raw[offset:])
                    if type(amount) is not int or not 0 < amount <= len(raw) - offset:
                        hold()
                    offset += amount
                os.fsync(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != os.geteuid() or info.st_mode & 0o777 != mode
                        or info.st_size != len(raw)):
                    hold()
                sealed = nine(info)
            finally:
                os.close(fd)
            if snapshot(path) != (sealed, raw):
                hold()
            return sealed

        base = Path(base)
        tool = (base / "h1-owned-tool").resolve()
        directory(tool)
        state = tool / "xdr-initial-setup-logs"
        directory(state)
        bin_dir = tool / "bin"
        directory(bin_dir)
        original_source = snapshot(Path(app.__file__))
        script = tool / "initial-setup.py"
        stage(script, original_source[1], 0o600)  # Public source, identity route only; never executed.
        marker = state / "auto-watch.state"
        stage(marker, b"http-v3-req10c-auto-v1\n", 0o600)
        lock = state / "auto-crontab.lock"
        stage(lock, b"", 0o600)
        credential_path = (state / "auto.env" if credentials is None
                           else Path(os.path.abspath(credentials)))
        protected = {marker: snapshot(marker), script: snapshot(script), lock: snapshot(lock)}
        if guard_kind == "unlinked":
            if credentials is not None or os.path.lexists(credential_path):
                hold()
            if type(expected_target) is not app.Target:
                hold()
        else:
            protected[credential_path] = snapshot(credential_path)
            info = protected[credential_path][0]
            if guard_kind == "world-mode":
                if not stat.S_ISREG(info[2]) or info[3] != os.geteuid() or info[2] & 0o777 != 0o644:
                    hold()
            else:
                target_path = base / "real.env"
                if (not stat.S_ISLNK(info[2])
                        or protected[credential_path][1] != str(target_path)):
                    hold()
                protected[target_path] = snapshot(target_path)
                target_info = protected[target_path][0]
                if (not stat.S_ISREG(target_info[2]) or target_info[3] != os.geteuid()
                        or target_info[2] & 0o777 != 0o600):
                    hold()

        foreign = "17 * * * * /usr/bin/true # PUBLIC-H1-FOREIGN\n"
        own = ("*/10 * * * * cd " + shlex.quote(str(tool)) + " && "
               + shlex.join(["python3", str(script), "--auto", "--apply", "--yes",
                             "--credentials-file", str(credential_path)])
               + " # http-v3-req10c-auto\n")
        initial = foreign + own
        database = tool / "cron.db"
        stage(database, initial.encode("utf-8"), 0o600)
        fake = bin_dir / "crontab"
        program = (
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "p = pathlib.Path(os.environ['REQ10C_H1_CRON_DB'])\n"
            "if sys.argv[1:] == ['-l']:\n"
            "    sys.stdout.write(p.read_text(encoding='utf-8'))\n"
            "elif sys.argv[1:] == ['-']:\n"
            "    p.write_text(sys.stdin.read(), encoding='utf-8')\n"
            "else:\n"
            "    sys.exit(2)\n"
        )
        stage(fake, program.encode("ascii"), 0o700)
        fake_before = snapshot(fake)
        directory_seals = {path: nine(path.lstat()) for path in (tool, state, bin_dir)}
        real_run = subprocess.run
        real_pause = app._pause_auto_watch
        real_reader = app.read_auto_credentials
        real_coverage = app.require_auto_full_target_coverage
        seen = {"events": [], "scheduler": [], "writes": 0,
                "main_error": None}

        @wraps(real_run)
        def run(argv, *args, **kwargs):
            if type(argv) is not list or argv not in (["crontab", "-l"], ["crontab", "-"]):
                raise AssertionError("PUBLIC H1 unexpected external command; blocked before dispatch")
            if shutil.which("crontab") != str(fake) or snapshot(fake) != fake_before:
                hold()
            kind = "L" if argv == ["crontab", "-l"] else "W"
            seen["events"].append(kind + "_BEGIN")
            expected = initial if seen["writes"] == 0 else foreign
            payload_ok = kind != "W" or kwargs.get("input") == foreign
            result = real_run(argv, *args, **kwargs)
            seen["events"].append(kind + "_RETURN")
            seen["scheduler"].append(
                type(result.returncode) is int and result.returncode == 0
                and payload_ok and (kind != "L" or result.stdout == expected)
            )
            if kind == "W":
                seen["writes"] += 1
            return result

        @wraps(real_pause)
        def pause(actual_tool, actual_credentials):
            if actual_tool != tool or actual_credentials != credential_path:
                raise AssertionError("PUBLIC H1 pause attempted a foreign tool/state role")
            seen["events"].append("PAUSE_ENTRY")
            result = real_pause(actual_tool, actual_credentials)
            seen["events"].append("PAUSE_RETURN")
            return result

        @wraps(real_reader)
        def reader(path):
            if path != credential_path:
                raise AssertionError("PUBLIC H1 credential guard attempted a foreign input")
            seen["events"].append("TARGET_GUARD_ENTRY")
            try:
                return real_reader(path)
            except app.SetupError:
                seen["events"].append("TARGET_GUARD_REJECT")
                raise

        @wraps(real_coverage)
        def coverage(count, targets):
            cached = app.load_target_cache.return_value
            if (type(count) is not int or count != 2 or type(targets) is not list
                    or len(targets) != 1 or targets[0] is not expected_target
                    or type(cached) is not tuple or len(cached) != 2 or targets is not cached[1]):
                raise AssertionError("PUBLIC H1 coverage guard did not receive original actual fixture")
            seen["events"].append("TARGET_GUARD_ENTRY")
            try:
                return real_coverage(count, targets)
            except app.SetupError:
                seen["events"].append("TARGET_GUARD_REJECT")
                raise

        def forbidden_discovery(*args, **kwargs):
            raise AssertionError("PUBLIC H1 credential guard must precede input discovery")

        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, {
                "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                "REQ10C_H1_CRON_DB": str(database), "PYTHONDONTWRITEBYTECODE": "1",
            }))
            stack.enter_context(mock.patch.object(app, "__file__", str(script)))
            stack.enter_context(mock.patch.object(subprocess, "run", new=run))
            stack.enter_context(mock.patch.object(app, "_pause_auto_watch", new=pause))
            if guard_kind == "unlinked":
                stack.enter_context(mock.patch.object(app, "require_auto_full_target_coverage", new=coverage))
                stack.enter_context(mock.patch.object(app.socket, "gethostname", return_value="PUBLIC-H1-MANAGEMENT"))
                stack.enter_context(mock.patch.object(app.socket, "getfqdn", return_value="PUBLIC-H1-MANAGEMENT.example.test"))
            else:
                stack.enter_context(mock.patch.object(app, "read_auto_credentials", new=reader))
                stack.enter_context(mock.patch.object(app, "discover_input_file", side_effect=forbidden_discovery))
            yield seen

        test.assertTrue(type(seen["main_error"]) is app.SetupError,
                        "actual main error was not captured; details suppressed")
        seen["events"].append("MAIN_ERROR")
        test.assertEqual([
            "TARGET_GUARD_ENTRY", "TARGET_GUARD_REJECT", "PAUSE_ENTRY",
            "L_BEGIN", "L_RETURN", "L_BEGIN", "L_RETURN", "W_BEGIN", "W_RETURN",
            "L_BEGIN", "L_RETURN", "L_BEGIN", "L_RETURN", "PAUSE_RETURN", "MAIN_ERROR",
        ], seen["events"], "actual H1 guard/pause/scheduler order was not reached")
        test.assertTrue(len(seen["scheduler"]) == 5 and all(seen["scheduler"])
                        and seen["writes"] == 1,
                        "actual owned scheduler results or replacement input differ")
        test.assertTrue(database.read_bytes() == foreign.encode("utf-8"),
                        "pause did not preserve the independent foreign cron bytes")
        test.assertTrue(all(snapshot(path) == value for path, value in protected.items()),
                        "H1 pause changed protected input/marker/lock/source identity or bytes")
        test.assertTrue(snapshot(fake) == fake_before
                        and all(nine(path.lstat()) == value for path, value in directory_seals.items()),
                        "H1 owned fixture identities changed outside the authorized DB write")
        if guard_kind == "unlinked":
            test.assertTrue(not os.path.lexists(credential_path),
                            "unlinked pre-authority guard must preserve absent default auto.env")

    return scope()


class Req10CAutoDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10c_auto_direct_initial", INITIAL)
        cls.unsetup = load_script("req10c_auto_direct_unsetup", UNSETUP)

    def test_crontab_update_requires_two_identical_snapshots(self) -> None:
        stable = "1 * * * * /usr/bin/true\n"
        changed = stable + "2 * * * * /usr/bin/false\n"

        with mock.patch.object(
            self.initial, "_read_auto_crontab", side_effect=[stable, stable]
        ) as reads:
            self.assertEqual(stable, self.initial._read_stable_auto_crontab())
        self.assertEqual(2, reads.call_count)

        with mock.patch.object(
            self.initial, "_read_auto_crontab", side_effect=[stable, changed]
        ):
            with self.assertRaisesRegex(
                self.initial.SetupError, "changed during the protected read window"
            ):
                self.initial._read_stable_auto_crontab()

        with mock.patch.object(
            self.unsetup, "_read_req10c_crontab", side_effect=[stable, stable]
        ) as reads:
            self.assertEqual(stable, self.unsetup._read_stable_req10c_crontab())
        self.assertEqual(2, reads.call_count)

        with mock.patch.object(
            self.unsetup, "_read_req10c_crontab", side_effect=[stable, changed]
        ):
            with self.assertRaisesRegex(
                OSError, "changed during the protected read window"
            ):
                self.unsetup._read_stable_req10c_crontab()

    def test_real_environment_card_has_title_and_remains_not_run(self) -> None:
        document = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8"
        )
        card_id = "TC-REAL-REQ10C-AUTO-001"
        marker = f"## {card_id}"
        self.assertEqual(document.count(marker), 1)
        section = document.split(marker, 1)[1].split("\n## ", 1)[0]
        self.assertTrue(
            section.startswith(" — 自动部署与同 UID crontab 静默验证\n"),
            "REQ10C real-environment card needs a nonempty fixed title",
        )
        status_lines = [
            line for line in section.splitlines() if line.startswith("- Status:")
        ]
        self.assertEqual(
            status_lines,
            ["- Status: OPEN / NOT RUN. Hermetic tests do not satisfy real cron UID, OOB Leaf, or IB device claims."],
        )
        self.assertIn("Same-user crontab writer exclusion", section)
        self.assertIn("owner explicitly selects", section)
        self.assertIn("foreign crontab", section)

    def parse(self, *extra: str):
        with mock.patch.object(sys, "argv", ["initial-setup.py", *extra]):
            with redirect_stderr(io.StringIO()):
                try:
                    return self.initial.parse_args()
                except SystemExit as exc:
                    self.fail(f"REQ10C flags must parse, got exit {exc.code}")

    def cache_fixture(self, base: Path):
        p1 = base / "management-tool"
        p2 = base / "leaf-tool"
        p1.mkdir()
        p2.mkdir()
        global_file = p1 / "01-global.yaml"
        global_file.write_text("system:\n  timezone: UTC\n", encoding="ascii")
        csv = base / "ib.csv"
        csv.write_text("fixture CSV\n", encoding="ascii")
        p2p = base / "p2p.dot"
        p2p.write_text("fixture P2P\n", encoding="ascii")
        cache = base / "targets.json"
        ib = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        eth = self.initial.Device(
            "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
            "192.0.2.1", "", "", "",
        )
        target = self.initial.Target(ib, eth, "swp7", "eth0")
        self.initial.save_target_cache(
            cache, csv, p2p, 1, [target], global_file=global_file,
            services=None, public_keys=[],
        )
        return p1, p2, global_file, csv, p2p, cache

    @staticmethod
    def resign_cache(cache: Path, payload: dict) -> None:
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n",
            encoding="ascii",
        )

    def test_watch_auto_is_distinct_from_execution_location_auto(self) -> None:
        args = self.parse("--auto")
        self.assertTrue(args.auto, "--auto is watch mode, not --execution-mode auto")
        self.assertEqual("auto", args.execution_mode)

    def test_credentials_file_is_a_path_not_a_password_argv(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cli-") as directory:
            credentials = Path(directory) / "auto.env"
            args = self.parse("--auto", "--credentials-file", str(credentials))
            self.assertEqual(credentials, args.credentials_file)

    def test_non_tty_watch_rejects_world_readable_credentials_before_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-unsafe-creds-") as directory:
            base = Path(directory)
            csv = base / "ib.csv"
            csv.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-LEAF01,eth,192.0.2.10,,,,,,\n",
                encoding="utf-8",
            )
            p2p = base / "p2p.dot"
            p2p.write_text('"EXAMPLE-IB01":"eth0" -- "EXAMPLE-LEAF01":"7";\n')
            credentials = base / "auto.env"
            credentials.write_text(
                "NVOS_INITIAL_PASSWORD=fixture-initial\n"
                "ZTP_ETH_PASSWORD=fixture-ethernet\n",
                encoding="ascii",
            )
            credentials.chmod(0o644)
            argv = [
                "initial-setup.py", "--auto", "--credentials-file", str(credentials),
                "--ib-csv", str(csv), "--p2p", str(p2p),
                "--target-cache", str(base / "targets.json"),
                "--report", str(base / "report.log"),
                "--snapshot-dir", str(base / "snapshots"),
            ]
            with _h1_owned_scheduler(self, self.initial, base, credentials,
                                     guard_kind="world-mode") as h1, \
                 mock.patch.object(sys, "argv", argv), mock.patch.object(
                sys.stdin, "isatty", return_value=False
            ), mock.patch.object(
                self.initial, "collect_ethernet_interfaces",
                side_effect=AssertionError("network must not start"),
            ), mock.patch.object(
                self.initial, "run_on_ib",
                side_effect=AssertionError("network must not start"),
            ), redirect_stderr(io.StringIO()):
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                except SystemExit as exc:
                    self.fail(f"unsafe credential guard is unreachable: exit {exc.code}")
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
                h1["main_error"] = caught.exception
            message = str(caught.exception).casefold()
            self.assertTrue("auto.env" in message or "credential" in message)
            self.assertTrue(
                any(token in message for token in ("permission", "mode", "owner", "unsafe")),
                message,
            )

    def test_auto_env_fd_rejects_symlink_hardlink_and_broad_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-fd-") as directory:
            base = Path(directory)
            secret = base / "auto.env"
            secret.write_text(
                "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n",
                encoding="utf-8",
            )
            secret.chmod(0o600)
            self.assertEqual("initial", self.initial.read_auto_credentials(secret)["NVOS_INITIAL_PASSWORD"])
            secret.chmod(0o644)
            with self.assertRaises(self.initial.SetupError):
                self.initial.read_auto_credentials(secret)
            secret.chmod(0o600)
            hardlink = base / "hardlink"
            os.link(secret, hardlink)
            with self.assertRaises(self.initial.SetupError):
                self.initial.read_auto_credentials(secret)
            hardlink.unlink()
            symlink = base / "symlink"
            symlink.symlink_to(secret)
            with self.assertRaises(self.initial.SetupError):
                self.initial.read_auto_credentials(symlink)

    def test_project_crontab_lock_is_owned_single_link_and_nofollow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cron-lock-") as directory:
            base = Path(directory)
            tool = base / "xdr-initial-setup"
            state = tool / "xdr-initial-setup-logs"
            state.mkdir(parents=True, mode=0o700)
            lock = state / "auto-crontab.lock"
            with self.initial._auto_crontab_lock(tool):
                self.assertTrue(lock.is_file())
                self.assertEqual(os.geteuid(), lock.stat().st_uid)
                self.assertEqual(1, lock.stat().st_nlink)
                self.assertEqual(0o600, lock.stat().st_mode & 0o777)
            state.chmod(0o777)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("group/world-writable lock directory was admitted")
            state.chmod(0o700)
            lock.chmod(0o644)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("broad lock file was admitted")
            lock.chmod(0o600)
            alias = state / "alias"
            os.link(lock, alias)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("hardlinked lock file was admitted")
            alias.unlink()
            lock.unlink()
            foreign = base / "foreign"
            foreign.write_text("MUST PRESERVE\n", encoding="ascii")
            lock.symlink_to(foreign)
            with self.assertRaises(self.initial.SetupError):
                with self.initial._auto_crontab_lock(tool):
                    self.fail("symlink lock file was admitted")
            self.assertEqual("MUST PRESERVE\n", foreign.read_text(encoding="ascii"))
            lock.unlink()
            with self.initial._auto_crontab_lock(tool):
                pass
            real_flock = self.initial.fcntl.flock

            def replace_after_acquire(fd: int, operation: int) -> None:
                real_flock(fd, operation)
                if operation == self.initial.fcntl.LOCK_EX:
                    lock.unlink()
                    lock.write_bytes(b"")
                    lock.chmod(0o600)

            with mock.patch.object(self.initial.fcntl, "flock", side_effect=replace_after_acquire):
                with self.assertRaises(self.initial.SetupError):
                    with self.initial._auto_crontab_lock(tool):
                        self.fail("rebound lock pathname was admitted")

    def test_cli_preserves_credential_symlink_for_nofollow_validation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cli-symlink-") as directory:
            base = Path(directory)
            real = base / "real.env"
            real.write_text(
                "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n",
                encoding="ascii",
            )
            real.chmod(0o600)
            link = base / "auto.env"
            link.symlink_to(real)
            with _h1_owned_scheduler(self, self.initial, base, link,
                                     guard_kind="symlink") as h1, mock.patch.object(
                sys, "argv", ["initial-setup.py", "--auto", "--credentials-file", str(link)]
            ), mock.patch.object(sys.stdin, "isatty", return_value=False), \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(self.initial.SetupError) as caught:
                    self.initial.main()
                h1["main_error"] = caught.exception
            self.assertIn("auto.env", str(caught.exception).casefold())
            self.assertIn("symbolic links", str(caught.exception).casefold())

    def test_fd_reader_fails_closed_without_required_flags_or_current_owner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-fd-flags-") as directory:
            secret = Path(directory) / "auto.env"
            secret.write_text(
                "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n",
                encoding="ascii",
            )
            secret.chmod(0o600)
            with mock.patch.object(self.initial.os, "geteuid",
                                   return_value=os.geteuid() + 1):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.read_auto_credentials(secret)
            with mock.patch.object(self.initial.os, "O_NOFOLLOW", 0):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.read_auto_credentials(secret)
            with mock.patch.object(self.initial.os, "O_CLOEXEC", 0):
                with self.assertRaises(self.initial.SetupError):
                    self.initial.read_auto_credentials(secret)

    def test_auto_env_strict_grammar_rejects_unknown_duplicate_case_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-grammar-") as directory:
            secret = Path(directory) / "auto.env"
            valid = "NVOS_INITIAL_PASSWORD=initial\nZTP_ETH_PASSWORD=ethernet\n"
            invalid = (
                valid + "ARBITRARY_SHELL=sh -c rm\n",
                valid + "NVOS_INITIAL_PASSWORD=duplicate\n",
                valid + "nvos_initial_password=lowercase-collision\n",
                valid + "source other-file\n",
                valid + "X=" + "x" * 65536 + "\n",
            )
            for value in invalid:
                with self.subTest(shape=value[:35]):
                    secret.write_text(value, encoding="utf-8")
                    secret.chmod(0o600)
                    with self.assertRaises(self.initial.SetupError):
                        self.initial.read_auto_credentials(secret)

    def test_host_specific_ethernet_password_precedes_global_fallback(self) -> None:
        targets = [
            SimpleNamespace(ethernet=SimpleNamespace(hostname="EXAMPLE-LEAF01")),
            SimpleNamespace(ethernet=SimpleNamespace(hostname="EXAMPLE-LEAF02")),
        ]
        values = {
            "NVOS_INITIAL_PASSWORD": "initial",
            "ZTP_ETH_PASSWORD": "fallback",
            "ZTP_ETH_PASSWORD_EXAMPLE_LEAF01": "specific",
        }
        self.assertEqual(
            {"example-leaf01": "specific", "example-leaf02": "fallback"},
            self.initial._auto_passwords_for_targets(values, targets),
        )

    def test_oob_leaf_key_install_is_exact_and_eth_jump_never_receives_write(self) -> None:
        def field(value: bytes) -> bytes:
            return struct.pack(">I", len(value)) + value

        blob = field(b"ssh-ed25519") + field(b"k" * 32)
        line = "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " fixture"
        digest = base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")
        entry = {
            "name": "mgmt-server.pub", "line": line,
            "fingerprint": "SHA256:" + digest,
        }

        def ethernet(kind: str):
            return self.initial.Device(
                "EXAMPLE-LEAF01", kind, "192.0.2.10", "192.0.2.10/24",
                "192.0.2.1", "", "", "",
            )

        with mock.patch.object(self.initial, "interactive_run") as remote:
            remote.return_value = self.initial.SessionResult("", 0)
            self.initial.install_oob_management_key(
                ethernet("eth"), "cumulus", "fixture-ethernet", entry, 10,
            )
            remote.assert_called_once()
            args = remote.call_args.args
            self.assertEqual("ssh", args[0][0])
            self.assertIn("authorized_keys", " ".join(args[0]))
            self.assertNotIn("fixture-ethernet", " ".join(args[0]))

        with mock.patch.object(
            self.initial, "interactive_run",
            side_effect=AssertionError("eth_jump must not receive any write"),
        ):
            with self.assertRaises(self.initial.SetupError):
                self.initial.install_oob_management_key(
                    ethernet("eth_jump"), "cumulus", "fixture-ethernet", entry, 10,
                )

    def test_auto_day0_classification_never_treats_partial_config_as_complete(self) -> None:
        device = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        state = self.initial.DeviceState
        empty = state((), (), (), (), "nvos", "")
        complete = state(("203.0.113.2/24",), (), ("203.0.113.1",), (),
                         "EXAMPLE-IB01", "")
        partial = state(("203.0.113.2/24",), (), (), (), "EXAMPLE-IB01", "")
        conflict = state(("203.0.113.99/24",), (), ("203.0.113.1",), (),
                         "EXAMPLE-IB01", "")
        self.assertEqual("unconfigured", self.initial.classify_auto_day0(device, empty))
        self.assertEqual("complete", self.initial.classify_auto_day0(device, complete))
        self.assertEqual("terminal", self.initial.classify_auto_day0(device, partial))
        self.assertEqual("terminal", self.initial.classify_auto_day0(device, conflict))

    def test_auto_local_leaf_refusal_names_management_server_and_never_touches_crontab(self) -> None:
        """§10C: the watch runs only on the management server; a Leaf never holds one.

        The refusal must stay an operator-actionable diagnostic, and because no
        watch can exist on a Leaf it must not read or write that host's crontab
        (no pause), nor create the Leaf's lock, marker or auto.env.
        """
        with tempfile.TemporaryDirectory(prefix="req10c-leaf-refusal-") as directory:
            base = Path(directory)
            tool = base / "leaf-tool"
            state = tool / "xdr-initial-setup-logs"
            # A pause attempt would succeed here, so only the product decision
            # (not a missing directory) can keep the crontab untouched.
            state.mkdir(parents=True, mode=0o700)
            state.chmod(0o700)
            csv = base / "ib.csv"
            p2p = base / "p2p.dot"
            csv.write_text("fixture CSV\n", encoding="ascii")
            p2p.write_text("fixture P2P\n", encoding="ascii")
            cache = base / "targets.json"
            cache.write_text(
                '{"services":{},"public_keys":[{"name":"mgmt-server.pub",'
                '"line":"fixture","fingerprint":"SHA256:fixture"}]}',
                encoding="ascii",
            )
            ib = self.initial.Device(
                "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                "203.0.113.1", "", "", "",
            )
            eth = self.initial.Device(
                "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
                "192.0.2.1", "", "", "",
            )
            target = self.initial.Target(ib, eth, "swp7", "eth0")
            foreign = "17 * * * * /usr/bin/true # PUBLIC-LEAF-FOREIGN\n"
            cron_db = base / "cron.db"
            cron_db.write_text(foreign, encoding="ascii")
            events = base / "crontab-events"
            bin_dir = base / "bin"
            bin_dir.mkdir()
            fake = bin_dir / "crontab"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys\n"
                "kind = 'L' if sys.argv[1:] == ['-l'] else 'W'\n"
                "with open(os.environ['REQ10C_LEAF_CRON_EVENTS'], 'a') as out:\n"
                "    out.write(kind + '\\n')\n"
                "db = pathlib.Path(os.environ['REQ10C_LEAF_CRON_DB'])\n"
                "if kind == 'L':\n"
                "    sys.stdout.write(db.read_text())\n"
                "else:\n"
                "    db.write_text(sys.stdin.read())\n",
                encoding="ascii",
            )
            fake.chmod(0o700)
            real_pause = self.initial._pause_auto_watch
            pauses = []

            def pause(*args, **kwargs):
                pauses.append("entry")
                return real_pause(*args, **kwargs)

            argv = [
                "initial-setup.py", "--auto", "--ib-csv", str(csv),
                "--p2p", str(p2p), "--target-cache", str(cache),
                "--report", str(base / "report.log"),
            ]
            blocked = AssertionError("a local Leaf --auto refusal must precede this actor")
            with mock.patch.dict(os.environ, {
                "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                "REQ10C_LEAF_CRON_DB": str(cron_db),
                "REQ10C_LEAF_CRON_EVENTS": str(events),
                # Generated PUBLIC token: the refusal precedes any IB use of it.
                "NVOS_INITIAL_PASSWORD": os.urandom(8).hex(),
            }), mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")), \
                 mock.patch.object(self.initial, "load_target_cache", return_value=(1, [target])), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value={"example-leaf01"}), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", side_effect=blocked), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces", side_effect=blocked), \
                 mock.patch.object(self.initial, "run_on_ib", side_effect=blocked), \
                 mock.patch.object(self.initial, "_install_auto_watch", side_effect=blocked), \
                 mock.patch.object(self.initial, "_pause_auto_watch", new=pause), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
            message = str(caught.exception).casefold()
            self.assertIn("management server", message)
            self.assertIn("leaf", message)
            self.assertEqual([], pauses, "a Leaf holds no watch, so nothing may be paused")
            self.assertFalse(events.exists(), "a Leaf refusal must not read or write any crontab")
            self.assertEqual(foreign, cron_db.read_text(encoding="ascii"))
            for name in ("auto-crontab.lock", "auto-watch.state", "auto.env"):
                self.assertFalse((state / name).exists(), f"Leaf refusal created {name}")

    def test_auto_local_leaf_refusal_precedes_every_credential_prompt(self) -> None:
        """§10C: on a local OOB Leaf, --auto refuses before asking for any credential.

        The refusal states that no device, credential or watch was touched, so
        with no initial-password variable exported and an interactive terminal
        it must not prompt for the Initial NVOS password (or any other secret)
        first.  The prompt model answers with a generated PUBLIC token so that a
        prompt cannot itself stop the run before the refusal is observed.
        """
        with tempfile.TemporaryDirectory(prefix="req10c-leaf-prompt-") as directory:
            base = Path(directory)
            tool = base / "leaf-tool"
            state = tool / "xdr-initial-setup-logs"
            state.mkdir(parents=True, mode=0o700)
            state.chmod(0o700)
            csv = base / "ib.csv"
            p2p = base / "p2p.dot"
            csv.write_text("fixture CSV\n", encoding="ascii")
            p2p.write_text("fixture P2P\n", encoding="ascii")
            cache = base / "targets.json"
            cache.write_text(
                '{"services":{},"public_keys":[{"name":"mgmt-server.pub",'
                '"line":"fixture","fingerprint":"SHA256:fixture"}]}',
                encoding="ascii",
            )
            ib = self.initial.Device(
                "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                "203.0.113.1", "", "", "",
            )
            eth = self.initial.Device(
                "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
                "192.0.2.1", "", "", "",
            )
            target = self.initial.Target(ib, eth, "swp7", "eth0")
            prompts = []

            def prompt(label=""):
                prompts.append(label)
                return os.urandom(8).hex()

            argv = [
                "initial-setup.py", "--auto", "--ib-csv", str(csv),
                "--p2p", str(p2p), "--target-cache", str(cache),
                "--report", str(base / "report.log"),
            ]
            blocked = AssertionError("a local Leaf --auto refusal must precede this actor")
            with mock.patch.dict(os.environ, {}), mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(self.initial.getpass, "getpass", new=prompt), \
                 mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")), \
                 mock.patch.object(self.initial, "load_target_cache", return_value=(1, [target])), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value={"example-leaf01"}), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", side_effect=blocked), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces", side_effect=blocked), \
                 mock.patch.object(self.initial, "run_on_ib", side_effect=blocked), \
                 mock.patch.object(self.initial, "_install_auto_watch", side_effect=blocked), \
                 mock.patch.object(self.initial, "_pause_auto_watch", side_effect=blocked), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                for name in ("NVOS_INITIAL_PASSWORD", "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD"):
                    os.environ.pop(name, None)
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
            self.assertIn("management server", str(caught.exception).casefold())
            self.assertEqual([], prompts, "a local Leaf --auto refusal must precede every credential prompt")

    def test_auto_rejects_unlinked_csv_ib_instead_of_installing_endless_watch(self) -> None:
        ib = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        eth = self.initial.Device(
            "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
            "192.0.2.1", "", "", "",
        )
        target = self.initial.Target(ib, eth, "swp7", "eth0")
        with self.assertRaises(self.initial.SetupError) as caught:
            self.initial.require_auto_full_target_coverage(2, [target])
        self.assertIn("csv", str(caught.exception).casefold())
        self.assertIn("p2p", str(caught.exception).casefold())
        self.initial.require_auto_full_target_coverage(1, [target])

    def test_p1_missing_current_global_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-p1-") as directory:
            p1, _, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            global_file.unlink()
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p1,
                allow_baked_missing_global=False,
            ))

    def test_p2_baked_global_remains_valid_without_local_yaml(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-p2-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            with mock.patch.object(
                self.initial, "_global_yaml_subset",
                side_effect=AssertionError("Leaf must not parse global YAML"),
            ):
                cached = self.initial.load_target_cache(
                    cache, csv, p2p, public_key_tool=p2,
                    allow_baked_missing_global=True,
                )
            self.assertIsNotNone(cached, "P2 uses authenticated baked global")
            self.assertEqual(1, cached[0])

    def test_p2_changed_input_still_invalidates_baked_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-stale-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            newer = cache.stat().st_mtime + 30
            os.utime(csv, (newer, newer))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))

    def test_cache3_attestation_binds_source_generator_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-fields-") as directory:
            _, p2, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            authority = payload["cache_authority"]
            self.assertEqual(
                hashlib.sha256(csv.read_bytes()).hexdigest(), authority["ib_csv_sha256"]
            )
            self.assertEqual(
                hashlib.sha256(p2p.read_bytes()).hexdigest(), authority["p2p_sha256"]
            )
            self.assertEqual(
                hashlib.sha256(global_file.read_bytes()).hexdigest(),
                authority["global_sha256"],
            )
            self.assertEqual("initial-setup.py", authority["generator"])
            self.assertEqual(
                hashlib.sha256(INITIAL.read_bytes()).hexdigest(),
                authority["generator_sha256"],
            )
            self.assertEqual(
                f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}",
                authority["python"],
            )
            self.assertFalse(authority["pyyaml_required"])
            self.assertEqual("not-required", authority["pyyaml_version"])
            self.assertIsNotNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))

    def test_cache3_content_changes_invalidate_even_when_mtime_is_older(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-content-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            older = cache.stat().st_mtime - 30
            csv.write_text("changed CSV but old mtime\n", encoding="ascii")
            os.utime(csv, (older, older))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-global-content-") as directory:
            p1, _, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            older = cache.stat().st_mtime - 30
            global_file.write_text("system:\n  timezone: Europe/Paris\n", encoding="ascii")
            os.utime(global_file, (older, older))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p1,
                allow_baked_missing_global=False,
            ))

    def test_cache3_resigned_identity_mismatch_fails_closed(self) -> None:
        for field, value in (
            ("generator_sha256", "0" * 64),
            ("python", "cpython:0.0"),
            ("pyyaml_required", True),
            ("pyyaml_version", "6.0"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory(
                prefix="req10c-cache3-mutated-"
            ) as directory:
                _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
                payload = json.loads(cache.read_text(encoding="utf-8"))
                payload["cache_authority"][field] = value
                self.resign_cache(cache, payload)
                self.assertIsNone(self.initial.load_target_cache(
                    cache, csv, p2p, public_key_tool=p2,
                    allow_baked_missing_global=True,
                ))


if __name__ == "__main__":
    unittest.main()
