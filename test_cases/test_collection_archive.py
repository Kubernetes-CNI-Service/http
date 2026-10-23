"""Archiving of the collected-data directories (owner 2026-10-22: one module in tools/). Every file named
YYYYMMDD-... follows one rule: today's stay as they are, the previous days are bundled per day into
YYYYMMDD-daily.tar.gz (an index of sha256, size and name first, members flat; CSVs stay loose for the
page), older days are deleted; a file of a day that is already bundled stays beside the bundle; failed
collector batch directories past the window are removed; the newest file of each kind always stays loose
(owner 2026-10-23). cron.sh and the shared 99-output-p2p cleanup call it."""

import gzip
import hashlib
import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tools/collection_archive.py"


def day(ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=ago)).strftime("%Y%m%d")


class CollectionArchiveTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("collection_archive_under_test", MODULE)
        self.archive = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.archive)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "data"
        self.dir.mkdir()

    def write(self, name: str, data: bytes = b"x") -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_today_stays_previous_days_are_bundled_with_an_index_and_older_days_leave(self):
        today, yesterday, two, old = day(0), day(1), day(2), day(4)
        self.write(f"{today}-0100.tar.gz")
        self.write(f"{today}-0100_u_ibdiagnet2.done")   # a newer file of each kind (see the newest-kind test)
        members = [self.write(f"{yesterday}-0100.tar.gz", b"archive"), self.write(f"{yesterday}-0100_u_ibdiagnet2.done")]
        self.write(f"{yesterday}-0100.csv")              # the page reads CSVs directly: never bundled
        self.write(f"{yesterday}-0200.tar.gz.part")      # still being written
        self.write(f"{two}-0100.tar.gz")
        for name in (f"{old}-0100.tar.gz", f"{old}-0100.csv", f"{old}-daily.tar.gz"):
            self.write(name)
        self.write("site-cvt.xlsx")                      # no date: never touched
        lines = self.archive.archive_directory(self.dir, retain_days=3)
        names = sorted(path.name for path in self.dir.iterdir())
        self.assertEqual(names, sorted([
            f"{today}-0100.tar.gz", f"{today}-0100_u_ibdiagnet2.done", f"{yesterday}-0100.csv",
            f"{yesterday}-0200.tar.gz.part", f"{yesterday}-daily.tar.gz", f"{two}-daily.tar.gz", "site-cvt.xlsx"]))
        with tarfile.open(self.dir / f"{yesterday}-daily.tar.gz") as bundle:
            self.assertEqual(bundle.getnames()[0], f"{yesterday}-daily.index", "the index comes first")
            self.assertEqual(sorted(bundle.getnames()[1:]), sorted(path.name for path in members))
            index = bundle.extractfile(f"{yesterday}-daily.index").read().decode()
        self.assertEqual(sorted(index.splitlines()), sorted(
            f"{hashlib.sha256(data).hexdigest()}  {len(data)}  {name}"
            for name, data in ((f"{yesterday}-0100.tar.gz", b"archive"), (f"{yesterday}-0100_u_ibdiagnet2.done", b"x"))))
        self.assertTrue(any(f"{yesterday}: bundled 2 file(s)" in line for line in lines), lines)
        self.assertTrue(any(f"deleted files for {old}" in line for line in lines), lines)

    def test_a_late_file_stays_beside_the_bundle_and_a_day_kept_only_as_a_bundle_leaves(self):
        yesterday, old = day(1), day(4)
        self.write(f"{yesterday}-0100.tar.gz")
        self.write(f"{day(0)}-0100.tar.gz")   # a newer collection, so yesterday's is no longer the newest
        self.archive.archive_directory(self.dir, retain_days=3)
        bundle = self.dir / f"{yesterday}-daily.tar.gz"
        before = bundle.read_bytes()
        late = self.write(f"{yesterday}-2358-prod-0000000000000009_ufm01-ibdiagnet-topology-validation.xlsx", b"late")
        self.write(f"{old}-daily.tar.gz")               # only the bundle is left of that day
        lines = self.archive.archive_directory(self.dir, retain_days=3)
        self.assertEqual((late.read_bytes(), bundle.read_bytes()), (b"late", before), "neither is rewritten")
        self.assertTrue(any("1 个迟到文件" in line for line in lines), lines)
        self.assertFalse((self.dir / f"{old}-daily.tar.gz").exists())

    def test_the_newest_file_of_each_kind_always_stays_loose(self):
        # Owner 2026-10-23 (lab): yesterday's IB switch archive was the newest one, was bundled at the end of
        # a UFM-only run, and the page lost every IB switch. Owner: 所有采集信息一定要留一份最新的散放；可以打包，
        # 但是不要删除掉最新的一份. The newest file of each kind goes into its day's bundle like the others,
        # but its loose copy stays until a newer file of that kind arrives.
        yesterday, old = day(1), day(5)
        older = self.write(f"{yesterday}-0100.tar.gz", b"older")
        newest = self.write(f"{yesterday}-0659.tar.gz", b"newest")
        lines = self.archive.archive_directory(self.dir, retain_days=3)
        bundle = self.dir / f"{yesterday}-daily.tar.gz"
        self.assertEqual(newest.read_bytes(), b"newest", "the newest switch archive stays for the page")
        self.assertFalse(older.exists())
        with tarfile.open(bundle) as archive:
            self.assertEqual(archive.getnames()[1:], [older.name, newest.name], "both are in the day's bundle")
        self.assertTrue(any("newest" in line and newest.name in line for line in lines), lines)

        # later runs: it stays while it is the newest and leaves once a newer one is in (the bundle holds it);
        # a loose file that differs from its bundled copy is a late file and stays beside the bundle
        before = bundle.read_bytes()
        self.archive.archive_directory(self.dir, retain_days=3)
        self.assertTrue(newest.is_file())
        rewritten = self.write(older.name, b"rewritten")
        current = self.write(f"{day(0)}-0100.tar.gz")
        lines = self.archive.archive_directory(self.dir, retain_days=3)
        self.assertFalse(newest.exists(), "a newer archive arrived and the bundle already holds this one")
        self.assertTrue(current.is_file() and rewritten.is_file())
        self.assertEqual(bundle.read_bytes(), before, "the bundle is never rewritten")
        self.assertTrue(any("1 file(s) already in the daily bundle" in line for line in lines), lines)
        self.assertTrue(any("1 个迟到文件" in line for line in lines), lines)

        # a shared report directory: each kind (the name without its date, minute and run nonce) keeps its own
        reports = Path(self.tmp.name) / "reports"
        reports.mkdir()
        ib = reports / f"{yesterday}-0355-prod-4aa1a9de3b44a5e3_ufm02-ibdiagnet-topology-validation.xlsx"
        receipt = reports / f"{yesterday}-0355-prod-4aa1a9de3b44a5e3_ufm02-ibdiagnet-topology-validation.receipt.json"
        eth = reports / f"{day(0)}-0400-prod-ethernet-topology-validation.xlsx"
        stale = reports / f"{old}-0300-prod-ethernet-topology-validation.xlsx"
        stale_ib = reports / f"{old}-0300-prod-0123456789abcdef_ufm02-ibdiagnet-topology-validation.xlsx"
        lonely = reports / f"{old}-0300-prod-0000000000000001_ufm01-iblinkinfo-topology-validation.xlsx"
        for path in (ib, receipt, eth, stale, stale_ib, lonely):
            path.write_bytes(b"r")
        (reports / f"{old}-daily.tar.gz").write_bytes(b"x")
        self.archive.archive_directory(reports, retain_days=3)
        self.assertTrue(ib.is_file() and receipt.is_file() and eth.is_file(),
                        "the newest IB report and its receipt stay beside today's Ethernet report")
        self.assertFalse(stale.exists() or stale_ib.exists(),
                         "an older file of a kind with a newer one still expires, whatever its run nonce")
        self.assertTrue(lonely.is_file(), "the only (so the newest) file of its kind never expires")
        self.assertFalse((reports / f"{old}-daily.tar.gz").exists(), "the expired day's bundle still leaves")

    def test_expired_collector_batch_directories_leave_and_nothing_else_is_followed(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (outside / "evidence.info").write_text("fixture\n")
        old, recent, today = day(8), day(1), day(0)
        batches = {name: self.dir / name for name in (f"{old}-1200-air", f"{recent}-1200-air", f"{today}-1200")}
        for path in batches.values():
            path.mkdir()
            (path / "evidence.info").write_text("fixture\n")
        (self.dir / "operator-notes").mkdir()
        (self.dir / f"{old}-1300-air").symlink_to(outside, target_is_directory=True)
        lines = self.archive.archive_directory(self.dir, retain_days=7)
        self.assertFalse(batches[f"{old}-1200-air"].exists())
        self.assertTrue(batches[f"{recent}-1200-air"].is_dir() and batches[f"{today}-1200"].is_dir())
        self.assertTrue((self.dir / "operator-notes").is_dir())
        self.assertTrue((self.dir / f"{old}-1300-air").is_symlink())
        self.assertTrue((outside / "evidence.info").is_file())
        self.assertTrue(any("deleted stale batch directory" in line for line in lines), lines)

    def test_a_bundle_that_cannot_be_completed_keeps_the_originals(self):
        if os.geteuid() == 0:
            self.skipTest("root reads any file")
        yesterday = day(1)
        good = self.write(f"{yesterday}-0100.tar.gz")
        unreadable = self.write(f"{yesterday}-0200.tar.gz")
        unreadable.chmod(0)
        try:
            lines = self.archive.archive_directory(self.dir, retain_days=3)
        finally:
            unreadable.chmod(0o644)
        self.assertTrue(good.is_file() and unreadable.is_file())
        self.assertEqual(sorted(path.name for path in self.dir.iterdir() if "daily" in path.name), [])
        self.assertTrue(any("WARN bundle failed, originals kept" in line for line in lines), lines)

    def test_the_command_line_follows_directory_links_and_skips_missing_ones(self):
        link = Path(self.tmp.name) / "eth-info"
        link.symlink_to(self.dir, target_is_directory=True)
        self.write(f"{day(1)}-0100.tar.gz")
        done = subprocess.run([sys.executable, "-B", str(MODULE), "--retain-days", "3", str(link),
                               str(Path(self.tmp.name) / "missing")], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((self.dir / f"{day(1)}-daily.tar.gz").is_file(), "the real directory behind the link")
        self.assertIn(f"── {link} ──", done.stdout)

    def test_days_are_utc_whatever_the_local_time_zone(self):
        # collectors name files in UTC; UTC+14 and UTC-12 are 26 h apart, so at any moment one of them
        # is on another calendar day than UTC and a local-time "today" would bundle today's file
        for zone in ("Etc/GMT-14", "Etc/GMT+12"):
            with self.subTest(zone=zone):
                for path in self.dir.iterdir():
                    path.unlink()
                today = self.write(f"{day(0)}-0100.tar.gz")
                self.write(f"{day(1)}-0100.tar.gz")
                done = subprocess.run([sys.executable, "-B", str(MODULE), "--retain-days", "3", str(self.dir)],
                                      capture_output=True, text=True, env={**os.environ, "TZ": zone})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(today.is_file(), done.stdout)
                self.assertEqual(sorted(path.name for path in self.dir.iterdir()),
                                 sorted([today.name, f"{day(1)}-daily.tar.gz"]))


if __name__ == "__main__":
    unittest.main()
