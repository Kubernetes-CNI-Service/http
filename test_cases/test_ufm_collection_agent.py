#!/usr/bin/env python3
"""D-70 UFM-local producer: exact argv and fail-closed local publication."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
AGENT = load_script("ufm_collection_agent_direct", ROOT / "tools/ufm_collection_agent.py")
CONTRACT = AGENT
RUN_ID = "20260926-0315-prod-0123456789abcdef"


class UfmCollectionAgentTests(unittest.TestCase):
    def test_cli_entrypoint_is_importable_outside_repository_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools/ufm_collection_agent.py"), "--help"],
                cwd=directory, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("--run-id", result.stdout)

    def test_iblinkinfo_exact_no_tty_command_publishes_nonempty_archive(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "out"
            output.mkdir()
            seen = []

            def runner(argv):
                seen.append(argv)
                return AGENT.InvocationResult(0, b"synthetic-link-info\n", b"")

            final = AGENT.collect_local(plan, output, runner=runner)
            self.assertEqual([list(plan.vendor_argv)], seen)
            self.assertEqual(output / plan.archive_name, final)
            self.assertFalse((output / plan.part_name).exists())
            with tarfile.open(final, "r:gz") as archive:
                self.assertEqual(b"synthetic-link-info\n", archive.extractfile("artifact").read())

    def test_ibdiagnet_uses_exact_container_source_without_glob(self):
        plan = CONTRACT.collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "out"
            output.mkdir()
            staging = root / "files"
            staging.mkdir()
            seen = []

            def runner(argv):
                seen.append(argv)
                if argv[:2] == ["docker", "cp"]:
                    artifact = Path(argv[-1])
                    artifact.mkdir()
                    (artifact / "ibdiagnet2.net_dump").write_bytes(b"synthetic-topology\n")
                return AGENT.InvocationResult(0, b"", b"")

            final = AGENT.collect_local(plan, output, runner=runner, staging_dir=staging)
            self.assertEqual(
                ["docker", "exec", "ufm", "test", "!", "-e", "/var/tmp/ibdiagnet2"],
                seen[0],
            )
            self.assertEqual(["docker", "exec", "ufm", *plan.vendor_argv], seen[1])
            self.assertEqual("ufm:/var/tmp/ibdiagnet2", seen[2][-2])
            self.assertFalse(any("*" in word or word == "-it" for argv in seen for word in argv))
            self.assertEqual(output / plan.archive_name, final)
            with tarfile.open(final, "r:gz") as archive:
                self.assertEqual(b"synthetic-topology\n", archive.extractfile(
                    "artifact/ibdiagnet2.net_dump"
                ).read())

    def test_zero_output_or_vendor_failure_never_has_final_name(self):
        for kind in ("iblinkinfo", "ibdiagnet"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                output = root / "out"
                output.mkdir()
                staging = root / "files"
                staging.mkdir()
                plan = CONTRACT.collection_plan(kind, RUN_ID)
                def vendor_fails(argv):
                    if argv == ["docker", "exec", "ufm", "test", "!", "-e",
                                "/var/tmp/ibdiagnet2"]:
                        return AGENT.InvocationResult(0, b"", b"")
                    return AGENT.InvocationResult(7, b"", b"secret-123")
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(
                        plan, output, runner=vendor_fails,
                        staging_dir=staging,
                    )
                self.assertFalse((output / plan.archive_name).exists())
                self.assertFalse((output / plan.part_name).exists())

    def test_stale_diagnostic_container_source_fails_before_vendor(self):
        plan = CONTRACT.collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "out"
            output.mkdir()
            staging = root / "files"
            staging.mkdir()
            seen = []

            def runner(argv):
                seen.append(argv)
                return AGENT.InvocationResult(1, b"", b"private-existing-source")

            with self.assertRaises(AGENT.AgentError):
                AGENT.collect_local(plan, output, runner=runner, staging_dir=staging)
            self.assertEqual(
                [["docker", "exec", "ufm", "test", "!", "-e", "/var/tmp/ibdiagnet2"]],
                seen,
            )
            self.assertFalse((output / plan.archive_name).exists())

    def test_empty_iblinkinfo_output_and_missing_diagnostic_copy_are_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "out"
            output.mkdir()
            staging = root / "files"
            staging.mkdir()
            for kind in ("iblinkinfo", "ibdiagnet"):
                plan = CONTRACT.collection_plan(kind, RUN_ID)
                def empty_result(argv):
                    return AGENT.InvocationResult(0, b"", b"")
                with self.subTest(kind=kind), self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(
                        plan, output, runner=empty_result,
                        staging_dir=staging,
                    )
                self.assertFalse((output / plan.archive_name).exists())

    def test_busy_lock_and_prior_final_fail_before_vendor_call(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            called = []
            lock = output / ".ufm-iblinkinfo.lock"
            lock.mkdir()
            with self.assertRaises(AGENT.AgentError):
                AGENT.collect_local(plan, output, runner=lambda argv: called.append(argv))
            lock.rmdir()
            (output / plan.archive_name).write_bytes(b"prior-result")
            with self.assertRaises(AGENT.AgentError):
                AGENT.collect_local(plan, output, runner=lambda argv: called.append(argv))
            self.assertEqual([], called)
            self.assertEqual(b"prior-result", (output / plan.archive_name).read_bytes())

    def test_live_pid_lock_uses_kill_zero_and_preserves_foreign_state(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            lock = output / ".ufm-iblinkinfo.lock"
            lock.mkdir(mode=0o700)
            pid = lock / "pid"
            pid.write_bytes(b"424242\n")
            pid.chmod(0o600)
            seen = []
            with mock.patch.object(AGENT.os, "kill", return_value=None) as kill:
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(plan, output, runner=lambda argv: seen.append(argv))
            kill.assert_called_once_with(424242, 0)
            self.assertEqual([], seen)
            self.assertEqual(b"424242\n", pid.read_bytes())

    def test_exact_dead_pid_lock_is_reclaimed_before_vendor(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            lock = output / ".ufm-iblinkinfo.lock"
            lock.mkdir(mode=0o700)
            pid = lock / "pid"
            pid.write_bytes(b"424242\n")
            pid.chmod(0o600)
            seen = []

            def runner(argv):
                seen.append(argv)
                return AGENT.InvocationResult(0, b"synthetic-link-info\n", b"")

            with mock.patch.object(AGENT.os, "kill", side_effect=ProcessLookupError) as kill:
                final = AGENT.collect_local(plan, output, runner=runner)
            kill.assert_called_once_with(424242, 0)
            self.assertEqual([list(plan.vendor_argv)], seen)
            self.assertTrue(final.is_file())
            self.assertFalse(lock.exists())

    def test_unknown_lock_shape_never_reclaimed_or_touches_vendor(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        for shape in ("missing-pid", "bad-pid", "oversize-pid", "symlink-pid",
                      "hardlink-pid", "executable-pid", "extra-child", "loose-mode"):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve()
                lock = output / ".ufm-iblinkinfo.lock"
                lock.mkdir(mode=0o700)
                pid = lock / "pid"
                if shape != "missing-pid":
                    if shape == "symlink-pid":
                        pid.symlink_to(output / "foreign")
                    else:
                        raw = (b"invalid\n" if shape == "bad-pid" else
                               b"9999999999\n" if shape == "oversize-pid" else
                               b"424242\n")
                        pid.write_bytes(raw)
                        pid.chmod(0o600)
                if shape == "executable-pid":
                    pid.chmod(0o700)
                if shape == "hardlink-pid":
                    os.link(pid, output / "foreign-link")
                if shape == "extra-child":
                    (lock / "other").write_bytes(b"foreign")
                if shape == "loose-mode":
                    lock.chmod(0o777)
                seen = []
                with mock.patch.object(AGENT.os, "kill", side_effect=ProcessLookupError):
                    with self.assertRaises(AGENT.AgentError):
                        AGENT.collect_local(plan, output, runner=lambda argv: seen.append(argv))
                self.assertEqual([], seen)
                self.assertTrue(lock.is_dir())
                self.assertEqual(shape == "missing-pid", not os.path.lexists(pid))

    def test_dead_pid_recheck_preserves_replaced_pid_and_refuses_vendor(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            lock = output / ".ufm-iblinkinfo.lock"
            lock.mkdir(mode=0o700)
            pid = lock / "pid"
            pid.write_bytes(b"424242\n")
            pid.chmod(0o600)
            replacement = output / "replacement"
            replacement.write_bytes(b"foreign-evidence")
            seen = []

            def replace_while_probing(_pid, _signal):
                os.replace(replacement, pid)
                raise ProcessLookupError()

            with mock.patch.object(AGENT.os, "kill", side_effect=replace_while_probing):
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(plan, output, runner=lambda argv: seen.append(argv))
            self.assertEqual([], seen)
            self.assertEqual(b"foreign-evidence", pid.read_bytes())
            self.assertTrue(lock.is_dir())

    def test_dead_pid_recheck_preserves_same_inode_rewrite(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            lock = output / ".ufm-iblinkinfo.lock"
            lock.mkdir(mode=0o700)
            pid = lock / "pid"
            pid.write_bytes(b"424242\n")
            pid.chmod(0o600)
            seen = []

            def rewrite_while_probing(_pid, _signal):
                pid.write_bytes(b"111111\n")
                raise ProcessLookupError()

            with mock.patch.object(AGENT.os, "kill", side_effect=rewrite_while_probing):
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(plan, output, runner=lambda argv: seen.append(argv))
            self.assertEqual([], seen)
            self.assertEqual(b"111111\n", pid.read_bytes())
            self.assertTrue(lock.is_dir())

    def test_own_pid_cleanup_preserves_same_inode_rewrite(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            lock = output / ".ufm-iblinkinfo.lock"
            pid = lock / "pid"

            def runner(_argv):
                pid.write_bytes(b"999999\n")
                return AGENT.InvocationResult(0, b"synthetic-link-info\n", b"")

            with self.assertRaises(AGENT.AgentError):
                AGENT.collect_local(plan, output, runner=runner)
            self.assertEqual(b"999999\n", pid.read_bytes())
            self.assertTrue(lock.is_dir())

    def test_forged_plan_or_symlinked_destination_fails_before_vendor(self):
        from dataclasses import replace

        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "out"
            output.mkdir()
            alias = root / "alias"
            alias.symlink_to(output, target_is_directory=True)
            called = []
            for candidate, target in ((replace(plan, archive_name="bad.tar.gz"), output),
                                      (plan, alias)):
                with self.subTest(target=target), self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(candidate, target,
                                        runner=lambda argv: called.append(argv))
            self.assertEqual([], called)

    def test_invocation_failures_do_not_echo_vendor_secret(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AGENT.AgentError) as caught:
                AGENT.collect_local(
                    plan, Path(directory).resolve(),
                    runner=lambda _: AGENT.InvocationResult(1, b"", b"raw-license-secret"),
                )
            self.assertNotIn("raw-license-secret", str(caught.exception))
            self.assertFalse((Path(directory).resolve() / plan.archive_name).exists())

    def test_operator_interrupt_propagates_and_cleans_private_lock(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            def interrupted(_argv):
                raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                AGENT.collect_local(plan, output, runner=interrupted)
            self.assertFalse((output / plan.archive_name).exists())
            self.assertFalse((output / plan.part_name).exists())
            self.assertFalse((output / ".ufm-iblinkinfo.lock").exists())

    def test_missing_nofollow_capability_refuses_before_vendor(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        for flag in ("O_DIRECTORY", "O_NOFOLLOW"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve()
                seen = []
                with mock.patch.object(AGENT.os, flag, 0):
                    with self.assertRaises(AGENT.AgentError):
                        AGENT.collect_local(
                            plan, output, runner=lambda argv: seen.append(argv)
                        )
                self.assertEqual([], seen)
                self.assertEqual([], list(output.iterdir()))

    def test_unsafe_local_hostname_refuses_before_vendor_or_lock(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        for hostname in ("", "bad host", "bad/name", "bad\nname", "☃", "x" * 254):
            with self.subTest(hostname=hostname), tempfile.TemporaryDirectory() as directory:
                output = Path(directory).resolve()
                seen = []
                with mock.patch("socket.gethostname", return_value=hostname):
                    with self.assertRaises(AGENT.AgentError):
                        AGENT.collect_local(
                            plan, output,
                            runner=lambda argv: seen.append(argv) or AGENT.InvocationResult(
                                0, b"synthetic-link-info\n", b""),
                        )
                self.assertEqual([], seen)
                self.assertEqual([], list(output.iterdir()))

    def test_symlinked_output_ancestor_refuses_before_vendor_or_external_write(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "outside"
            output = outside / "output"
            output.mkdir(parents=True)
            sentinel = output / "sentinel"
            sentinel.write_bytes(b"original")
            (root / "alias").symlink_to(outside, target_is_directory=True)
            seen = []
            with self.assertRaises(AGENT.AgentError):
                AGENT.collect_local(
                    plan, root / "alias" / "output",
                    runner=lambda argv: seen.append(argv) or AGENT.InvocationResult(
                        0, b"synthetic-link-info\n", b""),
                )
            self.assertEqual([], seen)
            self.assertEqual([sentinel], list(output.iterdir()))
            self.assertEqual(b"original", sentinel.read_bytes())

    def test_output_rebound_during_vendor_cannot_create_external_scratch(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "output"
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"preserve-me")
            scratch_creations = []
            original_mkdir = os.mkdir

            def runner(_argv):
                output.rename(root / "original-output")
                output.symlink_to(outside, target_is_directory=True)
                return AGENT.InvocationResult(0, b"synthetic-link-info\n", b"")

            def observe_scratch(path, *args, **kwargs):
                if ".ufm-collect-" in os.fspath(path):
                    scratch_creations.append(path)
                return original_mkdir(path, *args, **kwargs)

            with mock.patch.object(AGENT.os, "mkdir",
                                   side_effect=observe_scratch):
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(plan, output, runner=runner)
            self.assertEqual([], scratch_creations,
                             "rebound output must be rejected before creating scratch")
            self.assertEqual([sentinel], list(outside.iterdir()))
            self.assertEqual(b"preserve-me", sentinel.read_bytes())

    def test_staging_rebound_during_vendor_cannot_be_docker_copy_target(self):
        plan = CONTRACT.collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "output"
            output.mkdir()
            staging = root / "staging"
            staging.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"preserve-me")
            seen = []

            def runner(argv):
                seen.append(argv)
                if (argv[:3] == ["docker", "exec", "ufm"]
                        and any(word.endswith("/ibdiagnet") for word in argv)):
                    staging.rename(root / "original-staging")
                    staging.symlink_to(outside, target_is_directory=True)
                return AGENT.InvocationResult(0, b"", b"")

            with self.assertRaises(AGENT.AgentError):
                AGENT.collect_local(plan, output, staging_dir=staging, runner=runner)
            self.assertEqual(2, len(seen), "docker cp must not see rebound staging")
            self.assertFalse(any(argv[:2] == ["docker", "cp"] for argv in seen))
            self.assertEqual([sentinel], list(outside.iterdir()))
            self.assertEqual(b"preserve-me", sentinel.read_bytes())

    def test_output_rebound_at_scratch_mkdir_never_uses_external_parent(self):
        plan = CONTRACT.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "output"
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"preserve-me")
            original_mkdir = os.mkdir
            swapped = False
            external_mkdir = []

            def rebind_at_scratch_mkdir(path, *args, **kwargs):
                nonlocal swapped
                if not swapped and ".ufm-collect-" in os.fspath(path):
                    output.rename(root / "original-output")
                    output.symlink_to(outside, target_is_directory=True)
                    swapped = True
                if (swapped and ".ufm-collect-" in os.fspath(path)
                        and kwargs.get("dir_fd") is None):
                    external_mkdir.append(path)
                return original_mkdir(path, *args, **kwargs)

            with mock.patch.object(AGENT.os, "mkdir", side_effect=rebind_at_scratch_mkdir):
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(
                        plan, output,
                        runner=lambda _: AGENT.InvocationResult(
                            0, b"synthetic-link-info\n", b""),
                    )
            self.assertTrue(swapped)
            self.assertEqual([], external_mkdir)
            self.assertEqual([sentinel], list(outside.iterdir()))

    def test_staging_rebound_at_scratch_mkdir_never_reaches_docker_copy(self):
        plan = CONTRACT.collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "output"
            output.mkdir()
            staging = root / "staging"
            staging.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"preserve-me")
            original_mkdir = os.mkdir
            swapped = False
            external_mkdir = []
            seen = []

            def rebind_at_scratch_mkdir(path, *args, **kwargs):
                nonlocal swapped
                if not swapped and ".ufm-collect-" in os.fspath(path):
                    staging.rename(root / "original-staging")
                    staging.symlink_to(outside, target_is_directory=True)
                    swapped = True
                if (swapped and ".ufm-collect-" in os.fspath(path)
                        and kwargs.get("dir_fd") is None):
                    external_mkdir.append(path)
                return original_mkdir(path, *args, **kwargs)

            with mock.patch.object(AGENT.os, "mkdir", side_effect=rebind_at_scratch_mkdir):
                with self.assertRaises(AGENT.AgentError):
                    AGENT.collect_local(
                        plan, output, staging_dir=staging,
                        runner=lambda argv: seen.append(argv) or AGENT.InvocationResult(
                            0, b"", b""),
                    )
            self.assertTrue(swapped)
            self.assertEqual([], external_mkdir)
            self.assertFalse(any(argv[:2] == ["docker", "cp"] for argv in seen))
            self.assertEqual([sentinel], list(outside.iterdir()))


if __name__ == "__main__":
    unittest.main()
