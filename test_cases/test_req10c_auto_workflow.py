"""REQ10C initial-setup/unsetup workflow with isolated fake device boundaries."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import base64
import io
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(os.environ.get("REQ10C_TEST_ROOT") or Path(__file__).resolve().parents[1])
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
UNSETUP = ROOT / "DAY0-Prepare/02-unsetup.py"


class Req10CAutoUnsetupWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10c_auto_workflow_initial", INITIAL)
        cls.unsetup = load_script("req10c_auto_workflow_unsetup", UNSETUP)

    @staticmethod
    def fake_crontab(base: Path, initial: str) -> tuple[Path, Path]:
        cron_db = base / "cron.db"
        cron_db.write_text(initial, encoding="utf-8")
        bin_dir = base / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "crontab"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, sys\n"
            "p = pathlib.Path(os.environ['REQ10C_CRON_DB'])\n"
            "if sys.argv[1:] == ['-l']:\n"
            "    sys.stdout.write(p.read_text())\n"
            "elif sys.argv[1:] == ['-']:\n"
            "    p.write_text(sys.stdin.read())\n"
            "elif sys.argv[1:] == ['-r']:\n"
            "    p.write_text('')\n"
            "else:\n"
            "    sys.exit(2)\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        return cron_db, bin_dir

    @staticmethod
    def noncooperating_crontab(base: Path, initial: str) -> tuple[Path, Path]:
        """Return an isolated crontab whose read has a foreign-process interleave.

        Every fake `-l` takes an old snapshot, waits for a separate child to
        append and fsync a unique unrelated entry without the project lock,
        then returns that old snapshot. A finite re-read cannot erase the last
        read/write gap. The eighth injection is a hard test bound; the next
        read fails closed instead of looping forever. No real crontab runs.
        """
        cron_db, bin_dir = Req10CAutoUnsetupWorkflowTests.fake_crontab(base, initial)
        fake = bin_dir / "crontab"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, subprocess, sys\n"
            "base=pathlib.Path(os.environ['REQ10C_FAKE_BASE'])\n"
            "db=base/'cron.db'; events=base/'cron-events'; count_file=base/'read-count'; injected=base/'foreign-injected'\n"
            "with events.open('a', encoding='ascii') as out: out.write('L\\n' if sys.argv[1:] == ['-l'] else 'W\\n')\n"
            "if sys.argv[1:] == ['-l']:\n"
            "    old=db.read_text(encoding='utf-8')\n"
            "    count=int(count_file.read_text())+1 if count_file.exists() else 1\n"
            "    count_file.write_text(str(count), encoding='ascii')\n"
            "    if count > 8: sys.exit(3)\n"
            "    added=f'{17+count} * * * * /usr/bin/true # foreign-after-read-{count}\\n'\n"
            "    child=(\"import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_APPEND);\"\n"
            "           \" os.write(fd,sys.argv[2].encode()); os.fsync(fd); os.close(fd)\")\n"
            "    subprocess.run([sys.executable,'-c',child,str(db),added],check=True)\n"
            "    with injected.open('a', encoding='ascii') as out: out.write(added)\n"
            "    sys.stdout.write(old)\n"
            "elif sys.argv[1:] == ['-']:\n"
            "    db.write_text(sys.stdin.read(), encoding='utf-8')\n"
            "else: sys.exit(2)\n",
            encoding="ascii",
        )
        fake.chmod(0o700)
        return cron_db, bin_dir

    def assert_foreign_interleave_safe(self, mode: str) -> None:
        """A non-cooperating same-UID edit must survive or stop before writing."""
        with tempfile.TemporaryDirectory(prefix=f"req10c-foreign-{mode}-") as directory:
            base = Path(directory)
            tool = base / "infiniband/bringup/xdr-initial-setup"
            state = tool / "xdr-initial-setup-logs"
            state.mkdir(parents=True)
            credentials = state / "auto.env"
            credentials.write_text(
                "NVOS_INITIAL_PASSWORD=fixture\nZTP_ETH_PASSWORD=fixture\n",
                encoding="ascii",
            )
            credentials.chmod(0o600)
            self.initial._auto_marker(state / "auto-watch.state")
            own = (
                "*/10 * * * * cd " + str(tool) + " && python3 "
                + str(tool / "initial-setup.py")
                + " --auto --apply --yes --credentials-file "
                + str(credentials) + " # http-v3-req10c-auto\n"
            )
            existing = "1 * * * * /usr/bin/true # foreign-before-read\n"
            initial = existing if mode == "install" else existing + own
            cron_db, bin_dir = self.noncooperating_crontab(base, initial)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(bin_dir) + os.pathsep + environment.get("PATH", ""),
                "REQ10C_FAKE_BASE": str(base),
            })
            original_run = subprocess.run

            def guarded_run(argv, *args, **kwargs):
                self.assertEqual("crontab", argv[0], "unexpected scheduler command")
                self.assertEqual(str(bin_dir / "crontab"), shutil.which("crontab"))
                return original_run(argv, *args, **kwargs)

            failure = None
            with mock.patch.dict(os.environ, environment), \
                 mock.patch.object(subprocess, "run", side_effect=guarded_run):
                try:
                    if mode == "install":
                        self.initial._install_auto_watch(
                            tool, credentials, base / "ib.csv", base / "p2p.dot",
                            base / "cache.json", base / "report.log", base / "snapshots",
                            force=False,
                        )
                    elif mode == "remove":
                        self.initial._remove_auto_watch(tool, credentials)
                    else:
                        with mock.patch.object(self.unsetup, "HTTP_BASE", str(base)):
                            self.unsetup._cleanup_req10c_auto_watch()
                except (self.initial.SetupError, OSError) as exc:
                    failure = exc

            events = (base / "cron-events").read_text(encoding="ascii") if (base / "cron-events").exists() else ""
            final = cron_db.read_text(encoding="utf-8")
            injected = (base / "foreign-injected").read_text(encoding="ascii") if (base / "foreign-injected").exists() else ""
            injected_lines = injected.splitlines(keepends=True)
            self.assertEqual(len(injected_lines), len(set(injected_lines)), "each read needs a distinct foreign job")
            self.assertLessEqual(len(injected_lines), 8, "fake read injection must remain bounded")
            self.assertEqual(min(events.count("L\n"), 8), len(injected_lines),
                             "each successful fake read must have a foreign child write")
            if failure is not None:
                self.assertNotIn("W\n", events, f"{mode} failed after replacing fake crontab: {failure}")
                expected = initial + injected
                self.assertEqual(expected, final, f"{mode} failed but lost a foreign entry")
                return
            self.assertTrue(injected_lines, "no read/write interleave was exercised")
            self.assertIn("L\n", events)
            for line in injected_lines:
                self.assertIn(line, final, f"{mode} silently erased a non-cooperating foreign entry")
            self.assertIn(existing, final)
            if mode == "install":
                self.assertEqual(1, final.count("# http-v3-req10c-auto"))
            else:
                self.assertNotIn("# http-v3-req10c-auto", final)

    def test_install_preserves_noncooperating_foreign_cron_or_stops_before_write(self) -> None:
        self.assert_foreign_interleave_safe("install")

    def test_remove_preserves_noncooperating_foreign_cron_or_stops_before_write(self) -> None:
        self.assert_foreign_interleave_safe("remove")

    def test_unsetup_preserves_noncooperating_foreign_cron_or_stops_before_write(self) -> None:
        self.assert_foreign_interleave_safe("unsetup")

    def test_project_install_remove_unsetup_serialize_crontab_across_processes(self) -> None:
        """A paused read must exclude another project writer until its write ends."""
        worker = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "from test_cases.module_loader import load_script\n"
            "mode, root, tool = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])\n"
            "initial = load_script('req10c_lock_initial', root / 'infiniband/bringup/xdr-initial-setup/initial-setup.py')\n"
            "Path(os.environ['REQ10C_READY']).write_text('ready')\n"
            "credentials = tool / 'xdr-initial-setup-logs/auto.env'\n"
            "if mode == 'install':\n"
            "    initial._install_auto_watch(tool, credentials, root / 'ib.csv', root / 'p2p.dot', "
            "root / 'cache.json', root / 'report.log', root / 'snapshots', force=False)\n"
            "elif mode == 'remove':\n"
            "    initial._remove_auto_watch(tool, credentials)\n"
            "else:\n"
            "    unsetup = load_script('req10c_lock_unsetup', root / 'DAY0-Prepare/02-unsetup.py')\n"
            "    unsetup.HTTP_BASE = str(tool.parents[2])\n"
            "    unsetup._cleanup_req10c_auto_watch()\n"
        )
        for first_mode in ("install", "remove", "unsetup"):
            with self.subTest(first_mode=first_mode), tempfile.TemporaryDirectory(
                prefix="req10c-project-cron-"
            ) as directory:
                base = Path(directory)
                tool = base / "infiniband/bringup/xdr-initial-setup"
                state = tool / "xdr-initial-setup-logs"
                state.mkdir(parents=True)
                credentials = state / "auto.env"
                credentials.write_text(
                    "NVOS_INITIAL_PASSWORD=fixture\nZTP_ETH_PASSWORD=fixture\n",
                    encoding="ascii",
                )
                credentials.chmod(0o600)
                self.initial._auto_marker(state / "auto-watch.state")
                foreign = "1 * * * * /usr/bin/true\n"
                own = (
                    "*/10 * * * * cd " + str(tool)
                    + " && python3 initial-setup.py --auto --apply --yes "
                    + "--credentials-file " + str(credentials)
                    + " # http-v3-req10c-auto\n"
                )
                cron_db = base / "cron.db"
                cron_db.write_text(foreign if first_mode == "install" else foreign + own)
                events = base / "events"
                claim = base / "claimed"
                entered = base / "entered"
                release = base / "release"
                bin_dir = base / "bin"
                bin_dir.mkdir()
                fake = bin_dir / "crontab"
                fake.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os, pathlib, sys, time\n"
                    "base=pathlib.Path(os.environ['REQ10C_FAKE_BASE'])\n"
                    "kind='L' if sys.argv[1:] == ['-l'] else 'W'\n"
                    "fd=os.open(base/'events', os.O_WRONLY|os.O_CREAT|os.O_APPEND, 0o600)\n"
                    "os.write(fd, (kind+'\\n').encode()); os.close(fd)\n"
                    "if kind == 'L':\n"
                    "    try: fd=os.open(base/'claimed', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)\n"
                    "    except FileExistsError: pass\n"
                    "    else:\n"
                    "        os.close(fd); (base/'entered').write_text('entered')\n"
                    "        deadline=time.monotonic()+10\n"
                    "        while not (base/'release').exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
                    "    sys.stdout.write((base/'cron.db').read_text())\n"
                    "else: (base/'cron.db').write_text(sys.stdin.read())\n",
                    encoding="ascii",
                )
                fake.chmod(0o700)
                environment = dict(os.environ)
                environment.update({
                    "PATH": str(bin_dir) + os.pathsep + environment.get("PATH", ""),
                    "PYTHONPATH": str(ROOT),
                    "REQ10C_FAKE_BASE": str(base),
                })

                def await_file(path: Path) -> None:
                    deadline = time.monotonic() + 8
                    while not path.exists() and time.monotonic() < deadline:
                        if processes and processes[-1].poll() is not None:
                            stdout, stderr = processes[-1].communicate()
                            self.fail(
                                f"worker exited {processes[-1].returncode} "
                                f"before {path.name}: {stdout}{stderr}"
                            )
                        time.sleep(0.01)
                    self.assertTrue(path.exists(), f"worker did not reach {path.name}")

                processes = []
                try:
                    for index, mode in enumerate((first_mode, "install")):
                        current_env = dict(environment)
                        ready = base / f"ready-{index}"
                        current_env["REQ10C_READY"] = str(ready)
                        process = subprocess.Popen(
                            [sys.executable, "-B", "-c", worker, mode, str(ROOT), str(tool)],
                            cwd=str(ROOT), env=current_env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True,
                        )
                        processes.append(process)
                        await_file(entered if index == 0 else ready)
                    time.sleep(0.35)
                    before_release = events.read_text(encoding="ascii")
                finally:
                    release.touch()
                    results = [process.communicate(timeout=15) for process in processes]
                for process, (stdout, stderr) in zip(processes, results):
                    self.assertEqual(0, process.returncode, stdout + stderr)
                self.assertEqual("L\n", before_release,
                                 "second project operation read while first held the RMW window")
                self.assertEqual("L\nW\nL\nW\n", events.read_text(encoding="ascii"))
                lock = state / "auto-crontab.lock"
                self.assertTrue(lock.is_file(), "lock inode must survive cleanup")
                self.assertEqual(0o600, lock.stat().st_mode & 0o777)
                self.assertEqual(1, lock.stat().st_nlink)
                self.assertTrue(cron_db.read_text(encoding="ascii").startswith(foreign))
                self.assertEqual(1, cron_db.read_text(encoding="ascii").count("# http-v3-req10c-auto"))

    def unsetup_with_no_links(self, base: Path, bin_dir: Path, cron_db: Path,
                              *, dry_run: bool = False):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                "REQ10C_CRON_DB": str(cron_db),
            },
        ), mock.patch.object(self.unsetup, "HTTP_BASE", str(base)), \
             mock.patch.object(self.unsetup, "HERE", str(base / "DAY0-Prepare")), \
             mock.patch.object(self.unsetup, "MANIFEST_FILE", str(base / "ztp/.setup_manifest")), \
             mock.patch.object(self.unsetup, "_read_manifest", return_value=(None, None)), \
             mock.patch.object(self.unsetup, "_known_ztp_project_links", return_value=[]), \
             mock.patch.object(self.unsetup, "_known_workspace_links", return_value=[]), \
             mock.patch.object(self.unsetup, "_AUTO_YES", True), \
             mock.patch.object(self.unsetup, "_DRY_RUN", dry_run), \
             redirect_stdout(io.StringIO()):
            return self.unsetup._main_locked_impl(SimpleNamespace(project=None))

    def test_real_initial_auto_state_is_removed_by_real_unsetup_without_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-unsetup-") as directory:
            base = Path(directory)
            state_dir = base / "infiniband/bringup/xdr-initial-setup/xdr-initial-setup-logs"
            state_dir.mkdir(parents=True)
            credentials = state_dir / "auto.env"
            credentials.write_text("NVOS_INITIAL_PASSWORD=fixture-only\n", encoding="ascii")
            credentials.chmod(0o600)
            foreign = "1 * * * * /usr/bin/true\n"
            watch = (
                "*/10 * * * * cd " + str(state_dir.parent)
                + " && /usr/bin/python3 initial-setup.py --auto --apply --yes "
                + "--credentials-file " + str(credentials) + "\n"
            )
            cron_db, bin_dir = self.fake_crontab(base, foreign + watch)

            # Both real scripts participate.  Capture CLI failure but still
            # test unsetup independently, avoiding a masked cleanup failure.
            with mock.patch.object(
                sys, "argv", ["initial-setup.py", "--auto", "--credentials-file", str(credentials)]
            ), redirect_stderr(io.StringIO()):
                try:
                    auto_args = self.initial.parse_args()
                except SystemExit as exc:
                    auto_args = None
                    parse_error = exc.code
                else:
                    parse_error = None
            result = self.unsetup_with_no_links(base, bin_dir, cron_db)
            self.assertIn(result, (None, 0))
            self.assertFalse(credentials.exists(), "unsetup must delete auto.env even without links")
            self.assertEqual(foreign, cron_db.read_text(encoding="utf-8"))
            self.assertIsNotNone(auto_args, f"initial-setup cannot parse watch state: exit {parse_error}")
            self.assertTrue(auto_args.auto)
            self.assertEqual(credentials, auto_args.credentials_file)

    def test_real_first_round_installs_own_watch_then_real_unsetup_removes_it(self) -> None:
        """Real main, fake network+crontab, real unsetup: no device operations."""
        with tempfile.TemporaryDirectory(prefix="req10c-watch-round-") as directory:
            base = Path(directory)
            tool = base / "infiniband/bringup/xdr-initial-setup"
            tool.mkdir(parents=True)
            (tool / "initial-setup.py").write_bytes(INITIAL.read_bytes())
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
            pubdir = tool / "publickey"
            pubdir.mkdir()
            blob = (
                struct.pack(">I", len(b"ssh-ed25519")) + b"ssh-ed25519"
                + struct.pack(">I", 32) + b"m" * 32
            )
            (pubdir / "mgmt-server.pub").write_text(
                "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " fixture\n",
                encoding="ascii",
            )
            state_dir = tool / "xdr-initial-setup-logs"
            credentials = state_dir / "auto.env"
            foreign = "1 * * * * /usr/bin/true\n"
            cron_db, bin_dir = self.fake_crontab(base, foreign)
            argv = [
                "initial-setup.py", "--auto", "--ib-csv", str(csv),
                "--p2p", str(p2p), "--target-cache", str(state_dir / "targets.json"),
                "--report", str(state_dir / "report.log"),
                "--snapshot-dir", str(state_dir / "snapshots"),
            ]
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                    "REQ10C_CRON_DB": str(cron_db),
                    "NVOS_INITIAL_PASSWORD": "fixture-initial",
                },
            ), mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")), \
                 mock.patch.object(Path, "home", return_value=base), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", return_value={"example-leaf01": "fixture-ethernet"}), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces", return_value=("EXAMPLE-LEAF01", "table")) as interfaces, \
                 mock.patch.object(self.initial, "collect_ethernet_network_tables", return_value=("links", "fdb", "neighbors")) as network, \
                 mock.patch.object(self.initial, "save_ethernet_snapshot", return_value=state_dir / "snapshot"), \
                 mock.patch.object(self.initial, "interface_status_line", return_value="swp7 down"), \
                 mock.patch.object(self.initial, "interface_oper_status", return_value="down") as port_status, \
                 mock.patch.object(self.initial, "install_oob_management_key", side_effect=[self.initial.SetupError("transient OOB login"), None]) as key_stage, \
                 mock.patch.object(self.initial, "run_on_ib", side_effect=AssertionError("IB network must not start")), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    try:
                        initial_result = self.initial.main()
                    except SystemExit as exc:
                        self.fail(f"first --auto round not implemented: exit {exc.code}")
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
                self.assertEqual(0, initial_result)
                self.assertTrue(credentials.is_file())
                argv.extend(["--credentials-file", str(credentials)])
                try:
                    second_result = self.initial.main()
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
                self.assertEqual(0, second_result)
                self.assertEqual(2, interfaces.call_count)
                self.assertEqual(2, network.call_count)
                self.assertEqual(2, key_stage.call_count)
                self.assertTrue(credentials.is_file(), "unresolved IB must retain auto.env")
                self.assertEqual(0, credentials.stat().st_mode & 0o077)
                installed = cron_db.read_text(encoding="utf-8")
                self.assertIn("*/10 * * * *", installed)
                self.assertIn("flock -w 0", installed)
                self.assertEqual(1, installed.count("*/10 * * * *"))
                self.assertIn("--auto", installed)
                self.assertIn("--credentials-file", installed)
                self.assertNotIn("fixture-initial", installed)
                self.assertNotIn("fixture-ethernet", installed)
                port_status.return_value = "up"
                key_stage.side_effect = None
                ib = self.initial.DeviceState((), (), (), (), "nvos", "")
                configured = self.initial.DeviceState(
                    ("203.0.113.2/24",), (), ("203.0.113.1",), (),
                    "EXAMPLE-IB01", "",
                )
                with ExitStack() as round_three:
                    for patch in (
                        mock.patch.object(self.initial, "fdb_port_for_interface", return_value="swp7"),
                        mock.patch.object(self.initial, "neighbor_for_port", return_value=self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:01")),
                        mock.patch.object(self.initial, "verify_fdb_eth0_mac"),
                        mock.patch.object(self.initial, "interface_vrf", return_value="default"),
                        mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("fixture", 0)),
                        mock.patch.object(self.initial, "parse_nvue_state", side_effect=[ib, configured]),
                        mock.patch.object(self.initial, "verify_ipv4_login"),
                        mock.patch.object(self.initial, "run_service_stage", return_value=(True, False)),
                        mock.patch.object(self.initial, "run_key_stage", return_value=True),
                    ):
                        round_three.enter_context(patch)
                    try:
                        third_result = self.initial.main()
                    finally:
                        if self.initial.REPORT_HANDLE is not None:
                            self.initial.REPORT_HANDLE.close()
                            self.initial.REPORT_HANDLE = None
                self.assertEqual(0, third_result)
                self.assertEqual(3, interfaces.call_count)
                self.assertEqual(3, network.call_count)
                self.assertFalse(credentials.exists(), "online next round must converge and erase secret")
            self.assertEqual(0, initial_result)
            self.assertEqual(foreign, cron_db.read_text(encoding="utf-8"))
            self.assertIn(self.unsetup_with_no_links(base, bin_dir, cron_db), (None, 0))
            self.assertFalse(credentials.exists())
            self.assertEqual(foreign, cron_db.read_text(encoding="utf-8"))

    def test_real_unsetup_removes_owned_cron_when_secret_was_deleted_separately(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-marker-cleanup-") as directory:
            base = Path(directory)
            tool = base / "infiniband/bringup/xdr-initial-setup"
            state_dir = tool / "xdr-initial-setup-logs"
            state_dir.mkdir(parents=True)
            marker = state_dir / "auto-watch.state"
            marker.write_text("http-v3-req10c-auto-v1\n", encoding="ascii")
            marker.chmod(0o600)
            terminal = state_dir / "auto-terminal.json"
            terminal.write_text(
                '{"version":1,"inputs":"' + "a" * 64
                + '","terminal":["example-ib01"]}\n', encoding="ascii",
            )
            terminal.chmod(0o600)
            credentials = state_dir / "auto.env"
            foreign = "1 * * * * /usr/bin/true\n"
            own = (
                "*/10 * * * * cd " + str(tool)
                + " && flock -w 0 " + str(state_dir / "auto.lock")
                + " /usr/bin/python3 " + str(tool / "initial-setup.py")
                + " --auto --credentials-file " + str(credentials)
                + " # http-v3-req10c-auto\n"
            )
            cron_db, bin_dir = self.fake_crontab(base, foreign + own)
            self.unsetup_with_no_links(base, bin_dir, cron_db, dry_run=True)
            self.assertEqual(foreign + own, cron_db.read_text(encoding="utf-8"))
            self.assertTrue(marker.exists())
            self.assertTrue(terminal.exists())
            result = self.unsetup_with_no_links(base, bin_dir, cron_db)
            self.assertIn(result, (None, 0))
            self.assertEqual(foreign, cron_db.read_text(encoding="utf-8"))
            self.assertFalse(marker.exists())
            self.assertFalse(terminal.exists())

    def test_real_auto_round_complete_stops_without_watch_partial_is_terminal(self) -> None:
        """Main must use the entire CSV IB denominator and not repair partial Day-0."""
        for kind in ("complete", "partial"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(
                prefix="req10c-auto-state-"
            ) as directory:
                base = Path(directory)
                tool = base / "infiniband/bringup/xdr-initial-setup"
                tool.mkdir(parents=True)
                csv = base / "ib.csv"
                csv.write_text("fixture CSV\n", encoding="ascii")
                p2p = base / "p2p.dot"
                p2p.write_text("fixture P2P\n", encoding="ascii")
                state_dir = tool / "xdr-initial-setup-logs"
                state_dir.mkdir()
                cache = state_dir / "targets.json"
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
                actual = self.initial.DeviceState(
                    ("203.0.113.2/24",), (),
                    ("203.0.113.1",) if kind == "complete" else (),
                    (), "EXAMPLE-IB01", "",
                )
                cron_db, bin_dir = self.fake_crontab(
                    base, "1 * * * * /usr/bin/true\n"
                )
                argv = [
                    "initial-setup.py", "--auto", "--ib-csv", str(csv),
                    "--p2p", str(p2p), "--target-cache", str(cache),
                    "--report", str(state_dir / "report.log"),
                    "--snapshot-dir", str(state_dir / "snapshots"),
                ]
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, {
                        "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                        "REQ10C_CRON_DB": str(cron_db),
                        "NVOS_INITIAL_PASSWORD": "fixture-initial",
                    }))
                    patches = (
                        mock.patch.object(sys, "argv", argv),
                        mock.patch.object(sys.stdin, "isatty", return_value=True),
                        mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")),
                        mock.patch.object(Path, "home", return_value=base),
                        mock.patch.object(self.initial, "load_target_cache", return_value=(1, [target])),
                        mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()),
                        mock.patch.object(self.initial, "prompt_ethernet_passwords", return_value={"example-leaf01": "fixture-ethernet"}),
                        mock.patch.object(self.initial, "collect_ethernet_interfaces", return_value=("EXAMPLE-LEAF01", "table")),
                        mock.patch.object(self.initial, "collect_ethernet_network_tables", return_value=("links", "fdb", "neighbors")),
                        mock.patch.object(self.initial, "save_ethernet_snapshot", return_value=state_dir / "snapshot"),
                        mock.patch.object(self.initial, "interface_status_line", return_value="swp7 up"),
                        mock.patch.object(self.initial, "interface_oper_status", return_value="up"),
                        mock.patch.object(self.initial, "fdb_port_for_interface", return_value="swp7"),
                        mock.patch.object(self.initial, "neighbor_for_port", return_value=self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:01")),
                        mock.patch.object(self.initial, "verify_fdb_eth0_mac"),
                        mock.patch.object(self.initial, "interface_vrf", return_value="default"),
                        mock.patch.object(self.initial, "parse_nvue_state", return_value=actual),
                        mock.patch.object(self.initial, "install_oob_management_key"),
                    )
                    for patch in patches:
                        stack.enter_context(patch)
                    ib_run = stack.enter_context(mock.patch.object(
                        self.initial, "run_on_ib",
                        return_value=self.initial.SessionResult("fixture", 0),
                    ))
                    service = stack.enter_context(mock.patch.object(
                        self.initial, "run_service_stage", return_value=(True, False)
                    ))
                    key = stack.enter_context(mock.patch.object(
                        self.initial, "run_key_stage", return_value=True
                    ))
                    output = io.StringIO()
                    stack.enter_context(redirect_stdout(output))
                    stack.enter_context(redirect_stderr(io.StringIO()))
                    try:
                        result = self.initial.main()
                    finally:
                        if self.initial.REPORT_HANDLE is not None:
                            self.initial.REPORT_HANDLE.close()
                            self.initial.REPORT_HANDLE = None
                    if kind == "partial":
                        first_summaries = [
                            line for line in output.getvalue().splitlines()
                            if line.startswith("Summary:")
                        ]
                        self.assertEqual(1, len(first_summaries))
                        self.assertIn(
                            "terminal-devices=EXAMPLE-IB01", first_summaries[0],
                            "10C.5 requires terminal device names in the final summary, "
                            "not only earlier per-target logs or JSON",
                        )
                        self.assertTrue((state_dir / "auto.env").exists())
                        self.assertTrue((state_dir / "auto-terminal.json").exists())
                        argv.extend(["--credentials-file", str(state_dir / "auto.env")])
                        ib_run.reset_mock()
                        output.truncate(0)
                        output.seek(0)
                        try:
                            second_result = self.initial.main()
                        finally:
                            if self.initial.REPORT_HANDLE is not None:
                                self.initial.REPORT_HANDLE.close()
                                self.initial.REPORT_HANDLE = None
                        self.assertEqual(1, second_result)
                        ib_run.assert_not_called()
                        self.assertIn("Day-0 TERMINAL", output.getvalue())
                        retry_summaries = [
                            line for line in output.getvalue().splitlines()
                            if line.startswith("Summary:")
                        ]
                        self.assertEqual(1, len(retry_summaries))
                        self.assertIn(
                            "terminal-devices=EXAMPLE-IB01", retry_summaries[0],
                            "persisted terminal state must remain visible in each round summary",
                        )
                        csv.write_text("fixture CSV changed by operator\n", encoding="ascii")
                        ib_run.reset_mock()
                        try:
                            third_result = self.initial.main()
                        finally:
                            if self.initial.REPORT_HANDLE is not None:
                                self.initial.REPORT_HANDLE.close()
                                self.initial.REPORT_HANDLE = None
                        self.assertEqual(1, third_result)
                        ib_run.assert_called()
                if kind == "complete":
                    self.assertEqual(0, result)
                    service.assert_called_once()
                    key.assert_called_once()
                    self.assertFalse((state_dir / "auto.env").exists())
                    self.assertEqual("1 * * * * /usr/bin/true\n", cron_db.read_text())
                else:
                    self.assertEqual(1, result)
                    service.assert_not_called()
                    key.assert_not_called()

    def test_real_unsetup_reports_unsafe_secret_failure_without_unlinking_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-unsafe-cleanup-") as directory:
            base = Path(directory)
            state_dir = base / "infiniband/bringup/xdr-initial-setup/xdr-initial-setup-logs"
            state_dir.mkdir(parents=True)
            foreign_secret = base / "foreign-secret"
            foreign_secret.write_text("MUST PRESERVE\n", encoding="ascii")
            credential = state_dir / "auto.env"
            credential.symlink_to(foreign_secret)
            cron_db, bin_dir = self.fake_crontab(base, "1 * * * * /usr/bin/true\n")
            result = self.unsetup_with_no_links(base, bin_dir, cron_db)
            self.assertEqual(1, result)
            self.assertTrue(credential.is_symlink())
            self.assertEqual("MUST PRESERVE\n", foreign_secret.read_text(encoding="ascii"))

    def test_emitted_cron_line_nonblocking_lock_blocks_second_round(self) -> None:
        """Run the emitted shell job under a portable fcntl-backed flock fixture."""
        with tempfile.TemporaryDirectory(prefix="req10c-race-") as directory:
            base = Path(directory)
            tool = base / "xdr-initial-setup"
            tool.mkdir()
            marker = base / "entered.log"
            (tool / "initial-setup.py").write_text(
                "import os, pathlib, time\n"
                "with pathlib.Path(os.environ['REQ10C_NETWORK_MARKER']).open('a') as out:\n"
                "    out.write('entered\\n')\n"
                "time.sleep(0.7)\n",
                encoding="ascii",
            )
            cron_db, bin_dir = self.fake_crontab(base, "")
            fake_flock = bin_dir / "flock"
            fake_flock.write_text(
                "#!/usr/bin/env python3\n"
                "import fcntl, os, sys\n"
                "if sys.argv[1:3] != ['-w', '0']: sys.exit(2)\n"
                "fd = os.open(sys.argv[3], os.O_CREAT | os.O_RDWR, 0o600)\n"
                "try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                "except BlockingIOError: sys.exit(1)\n"
                "os.set_inheritable(fd, True)\n"
                "os.execvp(sys.argv[4], sys.argv[4:])\n",
                encoding="ascii",
            )
            fake_flock.chmod(0o700)
            credentials = tool / "xdr-initial-setup-logs/auto.env"
            env = dict(os.environ)
            env.update({
                "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
                "REQ10C_CRON_DB": str(cron_db),
                "REQ10C_NETWORK_MARKER": str(marker),
            })
            with mock.patch.dict(os.environ, env):
                self.initial._install_auto_watch(
                    tool, credentials, base / "ib.csv", base / "p2p.dot",
                    base / "targets.json", base / "report.log", base / "snapshots",
                    force=False,
                )
            installed = cron_db.read_text(encoding="utf-8")
            self.assertEqual(1, installed.count("*/10 * * * *"))
            shell = installed.removeprefix("*/10 * * * * ")
            first = subprocess.Popen(["/bin/sh", "-c", shell], env=env)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(marker.exists(), "first job must enter protected body")
                second = subprocess.run(
                    ["/bin/sh", "-c", shell], env=env,
                    capture_output=True, text=True, timeout=3, check=False,
                )
                self.assertNotEqual(0, second.returncode, "overlap must fail immediately")
                self.assertEqual("entered\n", marker.read_text(encoding="ascii"))
            finally:
                first.wait(timeout=5)
            self.assertEqual(0, first.returncode)

    def test_main_rejects_unlinked_csv_ib_before_network_or_cron(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-unlinked-") as directory:
            base = Path(directory)
            csv = base / "ib.csv"
            p2p = base / "p2p.dot"
            csv.write_text("fixture CSV\n", encoding="ascii")
            p2p.write_text("fixture P2P\n", encoding="ascii")
            ib = self.initial.Device(
                "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                "203.0.113.1", "", "", "",
            )
            eth = self.initial.Device(
                "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
                "192.0.2.1", "", "", "",
            )
            target = self.initial.Target(ib, eth, "swp7", "eth0")
            argv = [
                "initial-setup.py", "--auto", "--ib-csv", str(csv),
                "--p2p", str(p2p), "--target-cache", str(base / "target.json"),
                "--report", str(base / "report.log"),
                "--snapshot-dir", str(base / "snapshots"),
            ]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(self.initial, "load_target_cache", return_value=(2, [target])), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces") as network, \
                 mock.patch.object(self.initial, "_install_auto_watch") as cron, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
            self.assertIn("csv", str(caught.exception).casefold())
            self.assertIn("p2p", str(caught.exception).casefold())
            network.assert_not_called()
            cron.assert_not_called()

    def test_p2_invalid_baked_cache_fails_closed_before_local_yaml_or_network(self) -> None:
        self.assertIsNotNone(
            importlib.util.find_spec("yaml"),
            "fail-closed proof must run where PyYAML is installed",
        )
        with tempfile.TemporaryDirectory(prefix="req10c-p2-invalid-") as directory:
            base = Path(directory)
            p1 = base / "management-tool"
            p2_tool = base / "leaf-tool"
            p1.mkdir()
            p2_tool.mkdir()
            (p2_tool / "initial-setup.py").write_bytes(INITIAL.read_bytes())
            global_file = p1 / "01-global.yaml"
            global_file.write_text("system:\n  timezone: UTC\n", encoding="ascii")
            csv = base / "ib.csv"
            p2p = base / "p2p.dot"
            csv.write_text("fixture CSV\n", encoding="ascii")
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
            self.initial.save_target_cache(
                cache, csv, p2p, 1,
                [self.initial.Target(ib, eth, "swp7", "eth0")],
                global_file=global_file, services=None, public_keys=[],
            )
            newer = cache.stat().st_mtime + 30
            os.utime(csv, (newer, newer))
            argv = [
                "initial-setup.py", "--execution-mode", "ethernet",
                "--ib-csv", str(csv), "--p2p", str(p2p),
                "--target-cache", str(cache), "--report", str(base / "report.log"),
            ]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(self.initial, "__file__", str(p2_tool / "initial-setup.py")), \
                 mock.patch.object(self.initial, "_global_yaml_subset") as yaml, \
                 mock.patch.object(self.initial, "load_devices") as parse_csv, \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces") as network, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
            self.assertIn("management server", str(caught.exception).casefold())
            yaml.assert_not_called()
            parse_csv.assert_not_called()
            network.assert_not_called()

    def test_auto_refuses_local_leaf_and_never_installs_leaf_cron(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-no-leaf-cron-") as directory:
            base = Path(directory)
            tool = base / "leaf-tool"
            tool.mkdir()
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
            argv = [
                "initial-setup.py", "--auto", "--ib-csv", str(csv),
                "--p2p", str(p2p), "--target-cache", str(cache),
                "--report", str(base / "report.log"),
            ]
            with mock.patch.dict(os.environ, {"NVOS_INITIAL_PASSWORD": "fixture"}), \
                 mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")), \
                 mock.patch.object(self.initial, "load_target_cache", return_value=(1, [target])), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value={"example-leaf01"}), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", side_effect=AssertionError("Leaf auto must fail before password prompt")), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces") as network, \
                 mock.patch.object(self.initial, "_install_auto_watch") as cron, \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                try:
                    with self.assertRaises(self.initial.SetupError) as caught:
                        self.initial.main()
                finally:
                    if self.initial.REPORT_HANDLE is not None:
                        self.initial.REPORT_HANDLE.close()
                        self.initial.REPORT_HANDLE = None
            self.assertIn("management server", str(caught.exception).casefold())
            network.assert_not_called()
            cron.assert_not_called()


if __name__ == "__main__":
    unittest.main()
