"""REQ10C 02-unsetup old-watch cleanup workflow with isolated fake crontab boundaries.

The initial-setup --auto watch retired in v3.1.3 (owner 2026-11-02; guide O3, table 4-1); the
02-unsetup cleanup of an old watch stays until K6r (O11), so its workflows stay here, together
with the P2 baked-cache refusal that is not an --auto case.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import importlib.util
import os
from pathlib import Path
import shutil
import stat
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

# Moved with the unsetup halves of test_initial_setup_auto_watch_pause (v3.1.3 guide table
# 4-1: its two "待核" workflows; the install/pause halves retired with --auto).
PAUSED_FOREIGN = (
    "MAILTO=PUBLIC-operator@example.test\n"
    "3 4 * * * /PUBLIC/foreign-before # retain-order\n\n"
    "7 6 * * * /PUBLIC/foreign-after # retain-bytes\n"
    "# PUBLIC final comment without final LF"
)
PAUSED_MARKER_BYTES = b"http-v3-req10c-auto-v1\n"
PAUSED_ENV_BYTES = (
    b"NVOS_INITIAL_PASSWORD=PUBLIC-INITIAL-Only-17!\n"
    b"NVOS_TARGET_PASSWORD=PUBLIC-TARGET-Only-81!\n"
    b"ZTP_ETH_PASSWORD_EXAMPLE_JUMP01=PUBLIC-OOB-Only-91!\n"
)
_NINE = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
         "st_size", "st_mtime_ns", "st_ctime_ns")


def _bound_file(path: Path) -> tuple[tuple, bytes]:
    """Identity (nine stat fields) and bytes of one regular single-link file."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError("FIXTURE HOLD: bound file is not a regular single-link file")
    return tuple(getattr(info, name) for name in _NINE), path.read_bytes()


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
            # Marker bytes written directly (v3.1.3 guide WP-4: initial-setup's writer retires).
            marker = state / "auto-watch.state"
            marker.write_bytes(b"http-v3-req10c-auto-v1\n")
            marker.chmod(0o600)
            own = (
                "*/10 * * * * cd " + str(tool) + " && python3 "
                + str(tool / "initial-setup.py")
                + " --auto --apply --yes --credentials-file "
                + str(credentials) + " # http-v3-req10c-auto\n"
            )
            existing = "1 * * * * /usr/bin/true # foreign-before-read\n"
            initial = existing + own
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
                # v3.1.3 (guide table 4-1): only the 02-unsetup writer remains; the install and
                # remove modes retired with initial-setup --auto.
                try:
                    with mock.patch.object(self.unsetup, "HTTP_BASE", str(base)):
                        self.unsetup._cleanup_req10c_auto_watch()
                except OSError as exc:
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
            self.assertNotIn("# http-v3-req10c-auto", final)

    def test_unsetup_preserves_noncooperating_foreign_cron_or_stops_before_write(self) -> None:
        self.assert_foreign_interleave_safe("unsetup")

    def test_project_unsetup_serializes_crontab_across_processes(self) -> None:
        """A paused read must exclude another project writer until its write ends.

        v3.1.3 split (guide table 4-1, :251-368): the install/remove halves retired with
        initial-setup --auto; the unsetup half stays (O11).  The second project writer is now a
        cooperating fixture writer that takes the same project lock inode through 02-unsetup's
        own lock and read helpers and appends one owned line, in place of the retired install;
        every assertion is unchanged.
        """
        worker = (
            "import os, subprocess, sys\n"
            "from pathlib import Path\n"
            "from test_cases.module_loader import load_script\n"
            "mode, root, tool = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])\n"
            "unsetup = load_script('req10c_lock_unsetup', root / 'DAY0-Prepare/02-unsetup.py')\n"
            "Path(os.environ['REQ10C_READY']).write_text('ready')\n"
            "if mode == 'writer':\n"
            "    with unsetup._req10c_crontab_lock(str(tool / 'xdr-initial-setup-logs')):\n"
            "        current = unsetup._read_stable_req10c_crontab()\n"
            "        subprocess.run(['crontab', '-'], input=current + os.environ['REQ10C_OWN_LINE'],\n"
            "                       text=True, check=True)\n"
            "else:\n"
            "    unsetup.HTTP_BASE = str(tool.parents[2])\n"
            "    unsetup._cleanup_req10c_auto_watch()\n"
        )
        for first_mode in ("unsetup",):
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
                # Marker bytes written directly (v3.1.3 guide WP-4: initial-setup's writer retires).
                marker = state / "auto-watch.state"
                marker.write_bytes(b"http-v3-req10c-auto-v1\n")
                marker.chmod(0o600)
                foreign = "1 * * * * /usr/bin/true\n"
                own = (
                    "*/10 * * * * cd " + str(tool)
                    + " && python3 initial-setup.py --auto --apply --yes "
                    + "--credentials-file " + str(credentials)
                    + " # http-v3-req10c-auto\n"
                )
                cron_db = base / "cron.db"
                cron_db.write_text(foreign + own)
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
                    "REQ10C_OWN_LINE": own,
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
                    for index, mode in enumerate((first_mode, "writer")):
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
                self.assertEqual("L\nL\nW\nL\nL\nW\n", events.read_text(encoding="ascii"))
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

            # v3.1.3 (guide O3): initial-setup no longer parses --auto/--credentials-file, so
            # the half that parsed the old watch arguments retired; the unsetup half is unchanged.
            result = self.unsetup_with_no_links(base, bin_dir, cron_db)
            self.assertIn(result, (None, 0))
            self.assertFalse(credentials.exists(), "unsetup must delete auto.env even without links")
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

    def paused_watch_fixture(self, folder: Path) -> dict:
        """State an operator has after a paused old watch: own cron line already gone,
        auto.env, marker and the project lock still present, plus a foreign control leaf."""
        root = Path(folder)
        tool = root / "infiniband/bringup/xdr-initial-setup"
        state = tool / "xdr-initial-setup-logs"
        state.mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        credentials = state / "auto.env"
        credentials.write_bytes(PAUSED_ENV_BYTES)
        credentials.chmod(0o600)
        marker = state / "auto-watch.state"
        marker.write_bytes(PAUSED_MARKER_BYTES)
        marker.chmod(0o600)
        lock = state / "auto-crontab.lock"
        os.close(os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        control = root / "foreign-control"
        control.write_bytes(b"PUBLIC immutable foreign control\n")
        control.chmod(0o600)
        cron = root / "owned-crontab.db"
        cron.write_text(PAUSED_FOREIGN + "\n", encoding="utf-8")
        cron.chmod(0o600)
        return dict(root=root, credentials=credentials, marker=marker, lock=lock,
                    control=control, cron=cron)

    def paused_crontab_adapter(self, f: dict):
        """The external crontab process as an owned model; counts reads and writes."""
        observed = dict(reads=0, writes=0, adapter_errors=[])

        def run(command, *args, **kwargs):
            if command == ["crontab", "-l"]:
                if args or kwargs != {"capture_output": True, "text": True,
                                      "timeout": 10, "check": False}:
                    observed["adapter_errors"].append("read-shape")
                    raise AssertionError("PUBLIC owned adapter shape")
                observed["reads"] += 1
                return subprocess.CompletedProcess(command, 0, f["cron"].read_text(encoding="utf-8"), "")
            if command == ["crontab", "-"]:
                observed["writes"] += 1
                f["cron"].write_text(kwargs["input"], encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            observed["adapter_errors"].append("unexpected-boundary")
            raise AssertionError("PUBLIC only owned crontab boundary is permitted")

        return run, observed

    def run_unsetup_after_paused_watch(self, f: dict) -> tuple:
        before_control = _bound_file(f["control"])
        lock_before = _bound_file(f["lock"])[0]
        cleanup_run, cleanup = self.paused_crontab_adapter(f)
        with mock.patch.object(self.unsetup, "HTTP_BASE", str(f["root"])), \
                mock.patch.object(self.unsetup.subprocess, "run", new=cleanup_run):
            self.unsetup._cleanup_req10c_auto_watch()
        if cleanup["adapter_errors"]:
            raise RuntimeError("FIXTURE HOLD: owned crontab adapter prerequisite unavailable")
        return before_control, lock_before, cleanup

    def test_real_unsetup_after_paused_watch_preserves_foreign_lifecycle(self) -> None:
        # Unsetup half of test_initial_setup_auto_watch_pause::
        # test_real_install_pause_and_real_unsetup_preserve_foreign_lifecycle (assertions as there).
        with tempfile.TemporaryDirectory(prefix="req10c-paused-unsetup-") as folder:
            f = self.paused_watch_fixture(Path(folder))
            before_control, lock_before, cleanup = self.run_unsetup_after_paused_watch(f)
            self.assertFalse(f["credentials"].exists())
            self.assertFalse(f["marker"].exists())
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == PAUSED_FOREIGN + "\n")
            self.assertEqual(0, cleanup["writes"])
            self.assertTrue(_bound_file(f["control"]) == before_control,
                            "real unsetup must preserve the foreign control leaf")
            self.assertTrue(_bound_file(f["lock"])[0][:2] == lock_before[:2],
                            "real unsetup must not delete the retained project lock")

    def test_real_unsetup_after_paused_watch_with_canonical_quoted_paths(self) -> None:
        # Unsetup half of test_initial_setup_auto_watch_pause::
        # test_real_canonical_quoted_paths_pause_and_unsetup (assertions as there).
        with tempfile.TemporaryDirectory(prefix="req10c-paused-quoted-") as outer:
            f = self.paused_watch_fixture(Path(outer) / "PUBLIC project 'alpha'")
            self.assertTrue(" " in str(f["root"]) and "'" in str(f["credentials"]),
                            "owned input must actually exercise both path quoting boundaries")
            before_control, lock_before, cleanup = self.run_unsetup_after_paused_watch(f)
            self.assertFalse(f["credentials"].exists())
            self.assertFalse(f["marker"].exists())
            self.assertTrue(f["cron"].read_text(encoding="utf-8") == PAUSED_FOREIGN + "\n")
            self.assertEqual(0, cleanup["writes"])
            self.assertTrue(_bound_file(f["control"]) == before_control)
            self.assertTrue(_bound_file(f["lock"])[0][:2] == lock_before[:2])

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

if __name__ == "__main__":
    unittest.main()
