#!/usr/bin/env python3
"""D-70 exact-name retrieval rejects weak identity and incomplete archives."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from tools import ufm_collection_contract as COLLECTION


ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = load_script("ufm_archive_transport_direct", ROOT / "infra/ufm_jump_transport.py")
RUN_ID = "20260926-0315-air-0123456789abcdef"


def _archive(payload: bytes, *, member_name: str = "artifact") -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
        item = tarfile.TarInfo(member_name)
        item.size = len(payload)
        bundle.addfile(item, io.BytesIO(payload))
    return stream.getvalue()


def _symlink_archive() -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
        item = tarfile.TarInfo("artifact")
        item.type = tarfile.SYMTYPE
        item.linkname = "../outside"
        bundle.addfile(item)
    return stream.getvalue()


class UfmArchiveRetrievalTests(unittest.TestCase):
    def _site(self, root: Path):
        jump = TRANSPORT.JumpEndpoint("jump.example.invalid", "synthetic", root / "known_hosts")
        far = TRANSPORT.BoundFarEndpoint(
            "192.0.2.21", "synthetic", "synthetic-only-not-host-proof", jump
        )
        return jump, far

    def _runner(self, payload: bytes, plan, seen: list[list[str]], *, remote_hash=None):
        digest = remote_hash or hashlib.sha256(payload).hexdigest()

        def run(argv):
            seen.append(argv)
            if argv[0] == "scp":
                self.assertFalse(any("*" in token for token in argv))
                self.assertIn(plan.ufm_remote_path, argv[-2])
                Path(argv[-1]).write_bytes(payload)
                return TRANSPORT.CommandResult(0, "", "")
            if "sha256sum" in argv[-1]:
                return TRANSPORT.CommandResult(0, f"{digest}  {plan.ufm_remote_path}\n", "")
            if "test" in argv[-1]:
                return TRANSPORT.CommandResult(0, "", "")
            self.fail(f"unexpected synthetic command {argv}")

        return run

    def test_unverified_binding_refuses_before_any_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
            seen = []
            dest = root / plan.archive_name
            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, dest, timeout=10,
                    binding_check=lambda *_: False,
                    runner=lambda argv: seen.append(argv),
                )
            self.assertEqual([], seen)
            self.assertFalse(dest.exists())

    def test_operator_interrupt_during_binding_is_not_swallowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
            seen = []
            def interrupted(*_args):
                raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, root / plan.archive_name, timeout=10,
                    binding_check=interrupted,
                    runner=lambda argv: seen.append(argv),
                )
            self.assertEqual([], seen)

    def test_missing_nofollow_capability_refuses_before_remote_or_publication(self):
        payload = _archive(b"synthetic")
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        for flag in ("O_DIRECTORY", "O_NOFOLLOW"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                jump, far = self._site(root)
                seen = []
                destination = root / plan.archive_name
                with mock.patch.object(TRANSPORT.os, flag, 0):
                    with self.assertRaises(TRANSPORT.TransportError):
                        TRANSPORT.retrieve_collection_archive(
                            jump, far, plan, destination, timeout=10,
                            binding_check=lambda *_: True,
                            runner=self._runner(payload, plan, seen),
                        )
                self.assertEqual([], seen)
                self.assertFalse(destination.exists())

    def test_symlinked_ancestor_refuses_before_remote_or_external_write(self):
        payload = _archive(b"synthetic")
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            outside = root / "outside"
            runs = outside / "runs"
            runs.mkdir(parents=True)
            sentinel = runs / "sentinel"
            sentinel.write_bytes(b"original")
            (root / "alias").symlink_to(outside, target_is_directory=True)
            seen = []
            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, root / "alias" / "runs" / plan.archive_name,
                    timeout=10, binding_check=lambda *_: True,
                    runner=self._runner(payload, plan, seen),
                )
            self.assertEqual([], seen)
            self.assertEqual([sentinel], list(runs.iterdir()))
            self.assertEqual(b"original", sentinel.read_bytes())

    def test_exact_final_name_remote_digest_and_complete_archive_publish_once(self):
        payload = _archive(b"synthetic-link-data\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
            dest = root / plan.archive_name
            seen = []
            runner = self._runner(payload, plan, seen)
            def check(jump_arg, far_arg, plan_arg):
                self.assertEqual((jump, far, plan), (jump_arg, far_arg, plan_arg))
                return True  # synthetic test assertion, never real identity evidence

            actual = TRANSPORT.retrieve_collection_archive(
                jump, far, plan, dest, timeout=10, binding_check=check, runner=runner,
            )
            self.assertEqual(dest, actual)
            self.assertEqual(payload, dest.read_bytes())
            self.assertEqual(["ssh", "ssh", "scp"], [argv[0] for argv in seen])
            self.assertFalse(any("*" in token for argv in seen for token in argv))
            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, dest, timeout=10,
                    binding_check=check, runner=lambda argv: self.fail("must not run"),
                )
            self.assertEqual(payload, dest.read_bytes())

    def test_pinned_producer_digest_change_before_or_after_copy_never_links_final(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        payload = _archive(b"synthetic-link-data\n")
        expected = hashlib.sha256(payload).hexdigest()
        changed = "f" * 64 if expected != "f" * 64 else "e" * 64
        for phase in ("before-copy", "after-copy"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                jump, far = self._site(root)
                destination = root / plan.archive_name
                calls: list[list[str]] = []
                digests = 0

                def fake_service(argv):
                    nonlocal digests
                    calls.append(argv)
                    if argv[0] == "scp":
                        Path(argv[-1]).write_bytes(payload)
                        return TRANSPORT.CommandResult(0, "", "")
                    if "sha256sum" in argv[-1]:
                        digests += 1
                        value = changed if phase == "before-copy" or digests > 1 else expected
                        return TRANSPORT.CommandResult(
                            0, f"{value}  {plan.ufm_remote_path}\n", "")
                    if "test -f" in argv[-1]:
                        return TRANSPORT.CommandResult(0, "", "")
                    self.fail(f"unexpected fake command: {argv!r}")

                with self.assertRaises(TRANSPORT.TransportError):
                    TRANSPORT.retrieve_collection_archive(
                        jump, far, plan, destination, timeout=10,
                        expected_sha256=expected,
                        binding_check=lambda *_: True, runner=fake_service,
                    )
                self.assertFalse(destination.exists())
                self.assertEqual(1 if phase == "before-copy" else 2, digests)
                self.assertEqual(phase == "after-copy", any(x[0] == "scp" for x in calls))

    def test_malformed_pinned_digest_rejects_without_remote_action(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            seen = []
            for invalid in ("", "F" * 64, "0" * 63, True):
                with self.subTest(invalid=invalid), self.assertRaises(
                    TRANSPORT.TransportError
                ):
                    TRANSPORT.retrieve_collection_archive(
                        jump, far, plan, root / plan.archive_name,
                        timeout=10, expected_sha256=invalid,
                        binding_check=lambda *_: True,
                        runner=lambda argv: seen.append(argv),
                    )
            self.assertEqual([], seen)

    def test_wrong_archive_member_or_digest_has_no_completion_name(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        for payload, digest in (
            (_archive(b"secret", member_name="../outside"), None),
            (_archive(b""), None),
            (_symlink_archive(), None),
            (b"not-gzip", None),
            (_archive(b"synthetic"), "0" * 64),
        ):
            with self.subTest(payload=payload[:12], digest=digest), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                jump, far = self._site(root)
                seen = []
                dest = root / plan.archive_name
                with self.assertRaises(TRANSPORT.TransportError):
                    TRANSPORT.retrieve_collection_archive(
                        jump, far, plan, dest, timeout=10,
                        binding_check=lambda *_: True,
                        runner=self._runner(payload, plan, seen, remote_hash=digest),
                    )
                self.assertFalse(dest.exists())
                self.assertFalse((root / "outside").exists())

    def test_diagnostic_noncanonical_dot_member_path_is_rejected(self):
        payload = _archive(b"synthetic", member_name="artifact/./topology.txt")
        plan = COLLECTION.collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            dest = root / plan.archive_name
            seen = []
            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, dest, timeout=10,
                    binding_check=lambda *_: True,
                    runner=self._runner(payload, plan, seen),
                )
            self.assertFalse(dest.exists())

    def test_oversized_sparse_archive_refuses_before_publication(self):
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            dest = root / plan.archive_name

            def runner(argv):
                if argv[0] == "scp":
                    with Path(argv[-1]).open("wb") as stream:
                        stream.truncate(513 * 1024 * 1024)
                if argv[0] != "scp" and "sha256sum" in argv[-1]:
                    return TRANSPORT.CommandResult(
                        0, f"{'0' * 64}  {plan.ufm_remote_path}\n", ""
                    )
                return TRANSPORT.CommandResult(0, "", "")

            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, dest, timeout=10,
                    binding_check=lambda *_: True, runner=runner,
                )
            self.assertFalse(dest.exists())

    def test_exact_wait_is_bounded_and_never_publishes_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
            now = [0.0]
            seen = []
            def runner(argv):
                seen.append(argv)
                return TRANSPORT.CommandResult(1, "", "untrusted diagnostic")
            with self.assertRaises(TRANSPORT.TransportError) as caught:
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, root / plan.archive_name, timeout=3,
                    binding_check=lambda *_: True, runner=runner,
                    clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
                )
            self.assertNotIn("untrusted diagnostic", str(caught.exception))
            self.assertGreaterEqual(now[0], 3.0)
            self.assertTrue(seen)
            self.assertTrue(all(argv[0] == "ssh" and "test" in argv[-1] for argv in seen))
            self.assertFalse((root / plan.archive_name).exists())

    def test_symlinked_parent_or_existing_final_never_overwrites(self):
        payload = _archive(b"synthetic")
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            outside = root / "outside"
            outside.mkdir()
            marker = outside / "marker"
            marker.write_bytes(b"outside-original")
            alias = root / "alias"
            alias.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, alias / plan.archive_name, timeout=3,
                    binding_check=lambda *_: True, runner=lambda _: self.fail("must not run"),
                )
            incumbent = root / plan.archive_name
            incumbent.write_bytes(b"existing-evidence")
            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, incumbent, timeout=3,
                    binding_check=lambda *_: True, runner=lambda _: self.fail("must not run"),
                )
            self.assertEqual(b"existing-evidence", incumbent.read_bytes())
            self.assertEqual([marker], list(outside.iterdir()))

    def test_concurrent_final_name_creation_cannot_be_replaced(self):
        payload = _archive(b"synthetic")
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            destination = root / plan.archive_name
            seen = []
            real_link = os.link

            def concurrent_link(source, target, **kwargs):
                if target == destination.name:
                    destination.write_bytes(b"concurrent-owner-evidence")
                return real_link(source, target, **kwargs)

            with mock.patch.object(TRANSPORT.os, "link", side_effect=concurrent_link):
                with self.assertRaises(TRANSPORT.TransportError):
                    TRANSPORT.retrieve_collection_archive(
                        jump, far, plan, destination, timeout=10,
                        binding_check=lambda *_: True,
                        runner=self._runner(payload, plan, seen),
                    )
            self.assertEqual(b"concurrent-owner-evidence", destination.read_bytes())

    def test_hidden_cleanup_failure_cannot_leave_public_completion_name(self):
        payload = _archive(b"synthetic")
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            destination = root / plan.archive_name
            seen = []
            real_unlink = os.unlink
            injected = []

            def fail_first_hidden_unlink(path, **kwargs):
                if str(path).endswith(".part") and not injected:
                    injected.append(True)
                    raise OSError("synthetic private cleanup failure")
                return real_unlink(path, **kwargs)

            with mock.patch.object(TRANSPORT.os, "unlink", side_effect=fail_first_hidden_unlink):
                with self.assertRaises(TRANSPORT.TransportError):
                    TRANSPORT.retrieve_collection_archive(
                        jump, far, plan, destination, timeout=10,
                        binding_check=lambda *_: True,
                        runner=self._runner(payload, plan, seen),
                    )
            self.assertEqual([True], injected)
            self.assertFalse(destination.exists())

    def test_destination_parent_rebind_cannot_claim_new_path_success(self):
        payload = _archive(b"synthetic")
        plan = COLLECTION.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            jump, far = self._site(root)
            parent = root / "project-result"
            parent.mkdir()
            destination = parent / plan.archive_name
            seen = []
            real_runner = self._runner(payload, plan, seen)
            swapped = []

            def runner(argv):
                result = real_runner(argv)
                if argv[0] == "scp" and not swapped:
                    parent.rename(root / "retained-original-result")
                    parent.mkdir()
                    swapped.append(True)
                return result

            with self.assertRaises(TRANSPORT.TransportError):
                TRANSPORT.retrieve_collection_archive(
                    jump, far, plan, destination, timeout=10,
                    binding_check=lambda *_: True, runner=runner,
                )
            self.assertEqual([True], swapped)
            self.assertEqual([], list(parent.iterdir()))
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
