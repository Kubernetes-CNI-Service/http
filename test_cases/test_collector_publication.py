"""Direct tests: the on-device collectors publish a complete file or nothing (owner 2026-10-21).

cron.sh now fetches each device's file as soon as it appears, so a file that exists must be complete:
the working copy is written next to the final file and renamed into place on the same filesystem."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECTORS = {
    "ethernet/monitor/sw-info.sh": ".info",
    "ethernet/monitor/sw-link.sh": ".link",
    "infiniband/monitor/ufm-info.sh": ".info",
}


class CollectorPublicationTest(unittest.TestCase):
    def test_every_collector_keeps_its_working_copy_beside_the_output(self):
        for relative in COLLECTORS:
            source = (ROOT / relative).read_text(encoding="utf-8")
            name = Path(relative).stem
            self.assertIn(f'TMP_DIR=$(mktemp -d "${{BASEDIR}}/.{name}.XXXXXX")', source, relative)
            self.assertNotIn(f'"${{TMPDIR:-/tmp}}/{name}.XXXXXX"', source, relative)

    def test_a_snapshot_is_never_visible_before_it_is_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, bin_dir, probe = root / "home", root / "bin", root / "probe.log"
            work.mkdir()
            bin_dir.mkdir()
            # Every command the collector runs records what a poller would see in ./monitor right then.
            seen = f'ls -A monitor >> {probe} 2>/dev/null; echo --- >> {probe}\n'
            fakes = {
                "hostname": 'echo TestIB',
                "nv": seen + 'if [ "$2" = platform ] && [ -z "$3" ]; then echo "system-type  QM9790"; '
                             'else echo stub; fi',
            }
            for command in ("timedatectl", "df", "free", "top", "uptime"):
                fakes[command] = seen + "echo stub"
            for name, body in fakes.items():
                path = bin_dir / name
                path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
                path.chmod(0o755)
            env = dict(os.environ, PATH=f"{bin_dir}:/usr/bin:/bin", TMPDIR=str(root / "elsewhere"))
            (root / "elsewhere").mkdir()
            result = subprocess.run(["bash", str(ROOT / "ethernet/monitor/sw-info.sh")], cwd=work, env=env,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            views = probe.read_text().split("---\n")
            self.assertTrue(any(".sw-info." in view for view in views), "working copy beside the output")
            self.assertFalse(any("TestIB.info" in view for view in views), "no file before it is complete")
            self.assertEqual(sorted(os.listdir(work / "monitor")), ["TestIB.info"])
            self.assertTrue((work / "monitor/TestIB.info").read_text().rstrip().endswith(
                "====================================================\n# Collect complete\n"
                "===================================================="))


if __name__ == "__main__":
    unittest.main()
