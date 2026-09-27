"""C-25 local settings authority contract; every path is a private fixture."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_k_chain import KChainHoldError
from monitor.issue_tracker_k_store import (
    apply_local_k_change, initialize_local_k_store, read_local_k_store,
)


T0 = "2026-09-25T00:00:00Z"
T1 = "2026-09-25T00:01:00Z"


class IssueTrackerKStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracker-k-store-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(os.path.realpath(self.temp.name)) / ".tracker"

    def initialize(self):
        return initialize_local_k_store(self.root, initialized_at=T0,
                                        acquisition_id="acquisition-0")

    def change(self, new_k=5, *, request_id="request-1", expected_revision=0,
               actor="operator:fixture"):
        return apply_local_k_change(
            self.root, new_k=new_k, actor=actor, recorded_at=T1,
            request_id=request_id, expected_revision=expected_revision,
        )

    def test_legitimate_first_use_creates_event_zero_and_fsynced_projection(self):
        state = self.initialize()
        self.assertEqual((0, 3), (state.revision, state.k))
        self.assertEqual((0, 3), (read_local_k_store(self.root).revision,
                                  read_local_k_store(self.root).k))
        first = self.root / "settings" / "events" / "0.json"
        self.assertTrue(first.is_file())
        self.assertEqual("system:default", json.loads(first.read_text())["actor"])
        self.assertTrue((self.root / "INITIALIZED").is_file())
        self.assertTrue((self.root / "settings" / "outbox" / "0.json").is_file())
        for path in (self.root, self.root / "settings", first):
            self.assertEqual(0, path.stat().st_mode & 0o077)
        with self.assertRaises(KChainHoldError):
            self.initialize()  # Never re-create an existing state root.

    def test_accepted_transition_and_exact_idempotent_request_replay(self):
        self.initialize()
        first = self.change(new_k=9000)
        self.assertEqual((1, 9000, False), (first.revision, first.k, first.replay))
        self.assertEqual((1, 9000), (read_local_k_store(self.root).revision,
                                      read_local_k_store(self.root).k))
        replay = self.change(new_k=9000)
        self.assertEqual((1, 9000, True), (replay.revision, replay.k, replay.replay))
        self.assertEqual(["0.json", "1.json"], sorted(
            item.name for item in (self.root / "settings" / "events").iterdir()))
        second = self.change(new_k=7, request_id="request-2", expected_revision=1)
        self.assertEqual((2, 7, False), (second.revision, second.k, second.replay))
        earlier = self.change(new_k=9000)
        self.assertEqual((1, 9000, True), (earlier.revision, earlier.k, earlier.replay))
        self.assertEqual((2, 7), (read_local_k_store(self.root).revision,
                                  read_local_k_store(self.root).k))
        with self.assertRaises(KChainHoldError):
            self.change(new_k=6)  # Same ID, different payload is not a replay.

    def test_invalid_k_stale_revision_and_unsafe_actor_do_not_write(self):
        self.initialize()
        for value in (True, False, 0, -1, 1.5, "5"):
            with self.subTest(value=value), self.assertRaises(KChainHoldError):
                self.change(new_k=value)
        with self.assertRaises(KChainHoldError):
            self.change(expected_revision=2)
        with self.assertRaises(KChainHoldError):
            self.change(actor="operator:\nunsafe")
        self.assertEqual(["0.json"], sorted(
            item.name for item in (self.root / "settings" / "events").iterdir()))

    def test_initialized_deletion_stale_current_missing_projection_and_tail_stop(self):
        self.initialize()
        self.change()
        settings = self.root / "settings"
        original = (settings / "current").read_bytes()
        (settings / "current").write_bytes(
            (json.dumps({"schema_version": 1, "revision": 0,
                         "event_sha256": json.loads((self.root / "INITIALIZED").read_text())["event0_sha256"]},
                        sort_keys=True, separators=(",", ":")) + "\n").encode())
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        (settings / "current").write_bytes(original)
        (settings / "outbox" / "1.json").unlink()
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        (settings / "outbox" / "1.json").write_bytes(
            (json.dumps({"schema_version": 1, "revision": 1,
                         "event_sha256": json.loads(original)["event_sha256"]},
                        sort_keys=True, separators=(",", ":")) + "\n").encode())
        (settings / "events" / ".interrupted.tmp").write_bytes(b"unknown")
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        (settings / "events" / ".interrupted.tmp").unlink()
        (self.root / "INITIALIZED").unlink()
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        with self.assertRaises(KChainHoldError):
            self.initialize()  # Missing witness after first use is deletion, not first use.

    def test_corrupt_event_and_symlink_are_never_followed_or_repaired(self):
        self.initialize()
        event = self.root / "settings" / "events" / "0.json"
        original = event.read_bytes()
        event.write_bytes(original + b" ")
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        self.assertEqual(original + b" ", event.read_bytes())
        event.unlink()
        target = Path(self.temp.name) / "foreign"
        target.write_bytes(original)
        event.symlink_to(target)
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)

    def test_symlink_in_ancestor_is_not_a_settings_authority(self):
        real = Path(os.path.realpath(self.temp.name)) / "real"
        real.mkdir()
        (real / "project").mkdir()
        real_root = real / "project" / ".tracker"
        initialize_local_k_store(real_root, initialized_at=T0,
                                 acquisition_id="acquisition-real")
        alias = Path(os.path.realpath(self.temp.name)) / "alias"
        alias.symlink_to(real, target_is_directory=True)
        aliased_root = alias / "project" / ".tracker"
        with self.assertRaises(KChainHoldError):
            read_local_k_store(aliased_root)
        with self.assertRaises(KChainHoldError):
            apply_local_k_change(
                aliased_root, new_k=5, actor="operator:fixture",
                recorded_at=T1, request_id="request-alias", expected_revision=0,
            )
        self.assertEqual(0, read_local_k_store(real_root).revision)

    def test_invalid_root_argument_holds_with_settings_error(self):
        for root in (None, "relative/.tracker", self.root.parent / ".." / ".tracker"):
            with self.subTest(root=root), self.assertRaises(KChainHoldError):
                read_local_k_store(root)

    def test_special_current_and_lock_paths_fail_closed_without_hanging(self):
        self.initialize()
        current = self.root / "settings" / "current"
        current.unlink()
        os.mkfifo(current, 0o600)
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        current.unlink()
        lock = self.root / "LOCK"
        lock.unlink()
        os.mkfifo(lock, 0o600)
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)

    def test_crash_during_first_use_never_turns_existing_root_into_new_default(self):
        with mock.patch("monitor.issue_tracker_k_store.os.link", side_effect=OSError("injected")):
            with self.assertRaises(KChainHoldError):
                self.initialize()
        self.assertTrue(self.root.is_dir())
        with self.assertRaises(KChainHoldError):
            self.initialize()
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)

    def test_failure_after_event_install_never_acks_or_falls_back(self):
        self.initialize()
        with mock.patch("monitor.issue_tracker_k_store.os.replace", side_effect=OSError("injected")):
            with self.assertRaises(KChainHoldError):
                self.change()
        self.assertTrue((self.root / "settings" / "events" / "1.json").is_file())
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)
        with self.assertRaises(KChainHoldError):
            self.change(request_id="another-request")

    def test_event_directory_barrier_failure_never_acks_or_reuses_old_k(self):
        self.initialize()
        event_dir = (self.root / "settings" / "events").stat()
        real_fsync = os.fsync
        injected = False

        def fail_event_barrier(descriptor):
            nonlocal injected
            info = os.fstat(descriptor)
            if (not injected and info.st_dev == event_dir.st_dev
                    and info.st_ino == event_dir.st_ino):
                injected = True
                raise OSError("event directory fsync injection")
            return real_fsync(descriptor)

        with mock.patch("monitor.issue_tracker_k_store.os.fsync",
                        side_effect=fail_event_barrier):
            with self.assertRaises(KChainHoldError):
                self.change()
        self.assertTrue(injected)
        self.assertTrue((self.root / "settings" / "events" / "1.json").exists())
        with self.assertRaises(KChainHoldError):
            read_local_k_store(self.root)


if __name__ == "__main__":
    unittest.main()
