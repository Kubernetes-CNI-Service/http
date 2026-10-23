"""Log rotation (owner 2026-10-22): whoever writes a log rotates it, with one shared module,
tools/log_rotation.py: at 10 MB the log is compressed to <log>.1.gz and emptied in place (its writers
append), older copies shift up, at most 7 are kept. cron.sh rotates only its own cronjob.log, the page
generator its generate-monitor.log, the switch-collection worker its switch-collection.log when it
writes that file itself (11-load.py); under Docker supervisord owns that log and rotates it."""

import gzip
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tools/log_rotation.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LogRotationModuleTest(unittest.TestCase):
    def setUp(self):
        self.rotation = load(MODULE, "log_rotation_under_test")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_a_log_below_the_limit_is_left_alone(self):
        log = self.dir / "x.log"
        log.write_bytes(b"a" * 99)
        self.assertIsNone(self.rotation.rotate(log, max_bytes=100))
        self.assertEqual(sorted(path.name for path in self.dir.iterdir()), ["x.log"])

    def test_at_the_limit_the_log_is_compressed_emptied_and_older_copies_shift(self):
        log = self.dir / "x.log"
        log.write_bytes(b"first line\n" + b"a" * 100)
        for number in range(1, 8):
            with gzip.open(self.dir / f"x.log.{number}.gz", "wb") as handle:
                handle.write(f"copy {number}\n".encode())
        message = self.rotation.rotate(log, max_bytes=100, keep=7)
        self.assertIn("x.log", message)
        self.assertEqual(log.read_bytes(), b"", "emptied in place: its writers append")
        with gzip.open(self.dir / "x.log.1.gz") as handle:
            self.assertTrue(handle.read().startswith(b"first line\n"))
        for number in range(2, 8):
            with gzip.open(self.dir / f"x.log.{number}.gz") as handle:
                self.assertEqual(handle.read(), f"copy {number - 1}\n".encode())
        self.assertFalse((self.dir / "x.log.8.gz").exists(), "at most seven copies")
        self.assertFalse(list(self.dir.glob("*.part")))

    def test_a_link_is_followed_and_the_copies_sit_beside_the_real_file(self):
        real = self.dir / "data" / "cronjob.log"
        real.parent.mkdir()
        real.write_bytes(b"b" * 200)
        link = self.dir / "cronjob.log"
        link.symlink_to(real)
        self.rotation.rotate(link, max_bytes=100)
        self.assertTrue(link.is_symlink())
        self.assertTrue((real.parent / "cronjob.log.1.gz").is_file())
        self.assertFalse((self.dir / "cronjob.log.1.gz").exists())

    def test_the_command_line_reports_and_fails_loudly(self):
        log = self.dir / "x.log"
        log.write_bytes(b"c" * 200)
        done = subprocess.run([sys.executable, "-B", str(MODULE), "--max-bytes", "100", "--keep", "7", str(log)],
                              capture_output=True, text=True)
        self.assertEqual((done.returncode, log.read_bytes()), (0, b""), done.stderr)
        self.assertIn("x.log.1.gz", done.stdout)
        quiet = subprocess.run([sys.executable, "-B", str(MODULE), str(log)], capture_output=True, text=True)
        self.assertEqual((quiet.returncode, quiet.stdout), (0, ""), "nothing to do: nothing printed")
        if os.geteuid() != 0:
            log.write_bytes(b"d" * 200)
            self.dir.chmod(0o555)   # the copy cannot be written
            try:
                failed = subprocess.run([sys.executable, "-B", str(MODULE), "--max-bytes", "100", str(log)],
                                        capture_output=True, text=True)
            finally:
                self.dir.chmod(0o755)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(log.read_bytes(), b"d" * 200, "a failed rotation keeps the log")


class LogWritersRotateTheirOwnLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_the_page_generator_rotates_its_log_before_its_first_line(self):
        page = load(ROOT / "monitor/generate-monitor-html.py", "page_log_rotation_under_test")
        log = self.dir / "generate-monitor.log"
        log.write_bytes(b"e" * (10 * 1024 * 1024))
        order = []

        class Stop(Exception):
            pass

        def first_line(message):
            order.append("log")
            raise Stop()

        with mock.patch.object(page, "LOG_FILE", log), mock.patch.object(page, "log", first_line):
            real_rotate = page.rotate_own_log
            with mock.patch.object(page, "rotate_own_log", lambda: (order.append("rotate"), real_rotate())):
                with self.assertRaises(Stop):
                    page._generate_monitor_html("prod")
        self.assertEqual(order[:2], ["rotate", "log"])
        self.assertTrue((self.dir / "generate-monitor.log.1.gz").is_file())

    def test_the_worker_rotates_its_log_only_when_its_stdout_is_that_file(self):
        worker = load(ROOT / "monitor/switch-collection-worker.py", "worker_log_rotation_under_test")
        log = self.dir / "switch-collection.log"
        log.write_bytes(b"f" * (10 * 1024 * 1024))
        read_end, write_end = os.pipe()   # under Docker the worker's stdout is supervisord's pipe
        try:
            with mock.patch.object(worker, "WORKER_LOG", log):
                worker.rotate_own_log(stdout_fd=write_end)
                self.assertFalse((self.dir / "switch-collection.log.1.gz").exists(), "supervisord rotates it")
                with log.open("a") as stdout:   # started by 11-load.py: stdout is the log, opened to append
                    with mock.patch("sys.stdout", io.StringIO()):
                        worker.rotate_own_log(stdout_fd=stdout.fileno())
        finally:
            os.close(read_end)
            os.close(write_end)
        self.assertTrue((self.dir / "switch-collection.log.1.gz").is_file())
        self.assertEqual(log.stat().st_size, 0)
        source = (ROOT / "monitor/switch-collection-worker.py").read_text(encoding="utf-8")
        loop = source[source.index("        while not _shutdown_requested():"):]
        self.assertIn("rotate_own_log()", loop[:loop.index("time.sleep(max(args.poll, 1))")],
                      "the main loop rotates it while the worker runs")


if __name__ == "__main__":
    unittest.main()
