#!/usr/bin/env python3
"""Direct contracts for the standalone UFM jump transport."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import traceback
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "infra/ufm_jump_transport.py"


def load_module():
    spec = importlib.util.spec_from_file_location("ufm_jump_transport", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if old is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = old
    return module


class UfmJumpTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    def jump(self):
        return self.module.JumpEndpoint(
            host="192.0.2.10",
            user="admin",
            known_hosts=Path("/secure/known_hosts"),
            identity=Path("/secure/id_ed25519"),
        )

    def far(self, host="fe80::2:c9ff:fe12:3456"):
        return self.module.BoundFarEndpoint(
            host=host,
            user="admin",
            identity_evidence="port=swp7;mac=02:02:c9:12:34:56;source=neighbor",
            jump=self.jump(),
            bind_interface="vlan4001" if ":" in host else None,
        )

    def test_typed_argv_and_scalar_fields_fail_closed(self):
        self.assertEqual(
            ["nv", "config", "show"],
            self.module.typed_argv(["nv", "config", "show"], label="command"),
        )
        for invalid in (
            "nv config show",
            [],
            ["nv", "config\nshow"],
            ["nv", ""],
            ["nv", 1],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                self.module.TransportError
            ):
                self.module.typed_argv(invalid, label="command")

        for invalid_user in ("-oProxyCommand=bad", "root;id", "", "a b"):
            with self.subTest(invalid_user=invalid_user), self.assertRaises(
                self.module.TransportError
            ):
                self.module.JumpEndpoint(
                    host="192.0.2.10",
                    user=invalid_user,
                    known_hosts=Path("/secure/known_hosts"),
                )

    def test_jump_read_and_transit_quote_once_at_each_ssh_boundary(self):
        read = self.module.jump_read(
            self.jump(), ["bridge", "fdb", "show"], timeout=11
        )
        self.assertEqual("ssh", read[0])
        self.assertNotIn("sh", read)
        self.assertNotIn("-c", read)
        self.assertEqual(
            ["bridge", "fdb", "show"],
            shlex.split(read[-1]),
            "jump_read must join typed argv exactly once at the SSH boundary",
        )

        transit = self.module.jump_transit(
            self.jump(), self.far(), ["printf", "%s", "value with spaces"], timeout=13
        )
        self.assertEqual("ssh", transit[0])
        proxy = next(
            token.removeprefix("ProxyCommand=")
            for token in transit
            if token.startswith("ProxyCommand=")
        )
        proxy_argv = shlex.split(proxy)
        self.assertEqual("ssh", proxy_argv[0])
        self.assertIn("StrictHostKeyChecking=yes", proxy_argv)
        self.assertIn("UserKnownHostsFile=/secure/known_hosts", proxy_argv)
        self.assertEqual("admin@192.0.2.10", proxy_argv[-1])
        self.assertIn("%vlan4001", transit[-2])
        self.assertEqual(
            ["printf", "%s", "value with spaces"],
            shlex.split(transit[-1]),
            "far argv must be joined exactly once at the far SSH boundary",
        )

    def test_jump_read_closed_allowlist_rejects_other_typed_commands(self):
        for command in (
            ["hostname", "-f"],
            ["ip", "neighbor", "flush", "all"],
            ["sh", "-c", "hostname"],
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    self.module.TransportError, "outside the closed allowlist"
                ):
                    self.module.jump_read(self.jump(), command, timeout=11)

    def test_copy_in_and_out_are_always_bound_to_the_jump(self):
        copy_in = self.module.jump_copy_to(
            self.jump(), self.far("203.0.113.20"), Path("/safe/license.lic"),
            "/var/tmp/ufm/license.lic", timeout=17,
        )
        copy_out = self.module.jump_copy_from(
            self.jump(), self.far("203.0.113.20"),
            "/var/tmp/ufm/run-0001.log", Path("/safe/run-0001.log.part"), timeout=17,
        )
        for command in (copy_in, copy_out):
            self.assertEqual("scp", command[0])
            proxy = next(
                token.removeprefix("ProxyCommand=")
                for token in command
                if token.startswith("ProxyCommand=")
            )
            self.assertEqual("admin@192.0.2.10", shlex.split(proxy)[-1])
            self.assertNotIn("sh", command)
            self.assertNotIn("-c", command)

        plans = self.module.plan_copy_inputs(
            self.jump(), self.far("203.0.113.20"),
            certificate=Path("/safe/cert.pem"),
            certificate_remote="/var/tmp/ufm/cert.pem",
            license_file=Path("/safe/license.lic"),
            license_remote="/var/tmp/ufm/license.lic",
            timeout=17,
        )
        self.assertEqual({"certificate", "license"}, set(plans))
        self.assertTrue(all(
            any(token.startswith("ProxyCommand=") for token in command)
            for command in plans.values()
        ))

    def test_unbound_far_identity_and_unsafe_remote_paths_never_build(self):
        with self.assertRaises(self.module.TransportError):
            self.module.BoundFarEndpoint(
                host="203.0.113.20", user="admin", identity_evidence="",
                jump=self.jump(),
            )
        for remote_path in (
            "relative/path",
            "/tmp/a;id",
            "/tmp/a\nnext",
            "/tmp/a b",
            "/tmp/../etc/shadow",
        ):
            with self.subTest(remote_path=remote_path), self.assertRaises(
                self.module.TransportError
            ):
                self.module.jump_copy_to(
                    self.jump(), self.far("203.0.113.20"), Path("/safe/source"),
                    remote_path, timeout=10,
                )

        other_jump = self.module.JumpEndpoint(
            host="192.0.2.99", user="admin",
            known_hosts=Path("/secure/known_hosts"),
        )
        with self.assertRaisesRegex(self.module.TransportError, "binding"):
            self.module.jump_transit(
                other_jump, self.far("203.0.113.20"), ["true"], timeout=10
            )

    def test_cluster_and_vip_require_one_exact_jump_binding(self):
        jump = self.jump()
        inherited = self.module.bind_cluster_and_vip(
            {"ufm-a": jump, "ufm-b": jump}
        )
        self.assertEqual(jump, inherited)

        other = self.module.JumpEndpoint(
            host="192.0.2.11", user="admin", known_hosts=Path("/secure/known_hosts")
        )
        with self.assertRaisesRegex(self.module.TransportError, "same jump"):
            self.module.bind_cluster_and_vip({"ufm-a": jump, "ufm-b": other})
        with self.assertRaisesRegex(self.module.TransportError, "VIP jump"):
            self.module.bind_cluster_and_vip(
                {"ufm-a": jump, "ufm-b": jump}, vip_jump=other
            )

    def test_copy_from_is_no_overwrite_and_uses_private_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "ufm-a-run-0001.log"

            def runner(command):
                Path(command[-1]).write_bytes(
                    b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n"
                )
                return self.module.CommandResult(0, "", "")

            self.module.copy_from_no_overwrite(
                self.jump(), self.far("203.0.113.20"),
                "/var/tmp/ufm/run-0001.log", destination,
                timeout=10, runner=runner,
            )
            self.assertEqual(
                b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n",
                destination.read_bytes(),
            )
            with self.assertRaisesRegex(self.module.TransportError, "exists"):
                self.module.copy_from_no_overwrite(
                    self.jump(), self.far("203.0.113.20"),
                    "/var/tmp/ufm/run-0001.log", destination,
                    timeout=10, runner=runner,
                )
            self.assertEqual(
                b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n",
                destination.read_bytes(),
            )

    def test_copy_in_checks_regular_source_and_reports_failure_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "certificate.pem"
            source.write_bytes(b"certificate bytes")
            observed = []

            def passing(command):
                observed.append(command)
                return self.module.CommandResult(0, "", "")

            self.module.copy_to_verified(
                self.jump(), self.far("203.0.113.20"), source,
                "/var/tmp/ufm/certificate.pem", timeout=10, runner=passing,
            )
            self.assertEqual(1, len(observed))
            self.assertTrue(any(
                token.startswith("ProxyCommand=") for token in observed[0]
            ))

            with self.assertRaisesRegex(self.module.TransportError, "regular"):
                self.module.copy_to_verified(
                    self.jump(), self.far("203.0.113.20"), root,
                    "/var/tmp/ufm/not-a-file", timeout=10, runner=passing,
                )

            def failing(_command):
                return self.module.CommandResult(
                    1, "", "license_key=TOPSECRET customer=ACME"
                )

            with self.assertRaises(self.module.TransportError) as captured:
                self.module.copy_to_verified(
                    self.jump(), self.far("203.0.113.20"), source,
                    "/var/tmp/ufm/certificate.pem", timeout=10, runner=failing,
                )
            self.assertNotIn("TOPSECRET", str(captured.exception))
            self.assertNotIn("ACME", str(captured.exception))

    def test_zero_byte_input_and_retrieved_log_never_claim_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty_source = root / "empty-certificate.pem"
            empty_source.write_bytes(b"")
            commands = []

            def unexpected_copy(command):
                commands.append(command)
                return self.module.CommandResult(0, "", "")

            with self.assertRaises(self.module.TransportError):
                self.module.copy_to_verified(
                    self.jump(), self.far("203.0.113.20"), empty_source,
                    "/var/tmp/ufm/certificate.pem", timeout=10,
                    runner=unexpected_copy,
                )
            self.assertEqual([], commands, "empty input must reject before SSH/SCP")

            destination = root / "ufm-a-empty.log"

            def empty_retrieval(command):
                Path(command[-1]).write_bytes(b"")
                return self.module.CommandResult(0, "", "")

            with self.assertRaises(self.module.TransportError):
                self.module.copy_from_no_overwrite(
                    self.jump(), self.far("203.0.113.20"),
                    "/var/tmp/ufm/empty.log", destination,
                    timeout=10, runner=empty_retrieval,
                )
            self.assertFalse(destination.exists(), "empty log is not published evidence")

    def test_retrieved_log_payload_is_redacted_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "ufm-a-run-0002.log"

            def runner(command):
                Path(command[-1]).write_bytes(
                    b"UFM_EVENT|stage=bootstrap|status=started|code=none\n"
                    b"ufmlicense customer=ACME token=TOPSECRET\n"
                )
                return self.module.CommandResult(0, "", "")

            with self.assertRaises(self.module.TransportError):
                self.module.copy_from_no_overwrite(
                    self.jump(), self.far("203.0.113.20"),
                    "/var/tmp/ufm/run-0002.log", destination,
                    timeout=10, runner=runner,
                )
            self.assertFalse(destination.exists(), "untrusted raw log must not publish")

    def test_unlabelled_secret_in_raw_log_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "ufm-a-run-0004.log"
            raw_secret = "SYNTHETIC" + "-OPAQUE-739182"

            def runner(command):
                Path(command[-1]).write_text(raw_secret + "\n", encoding="utf-8")
                return self.module.CommandResult(0, "", "")

            with self.assertRaises(self.module.TransportError) as captured:
                self.module.copy_from_no_overwrite(
                    self.jump(), self.far("203.0.113.20"),
                    "/var/tmp/ufm/run-0004.log", destination,
                    timeout=10, runner=runner,
                )
            self.assertFalse(destination.exists())
            self.assertNotIn(raw_secret, str(captured.exception))

    def test_upload_cleanup_failure_is_visible_not_silent_success(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "certificate.pem"
            source.write_bytes(b"synthetic certificate")
            observed = []

            def denied_cleanup(path, *, ignore_errors=False):
                if ignore_errors:
                    return None
                raise OSError("synthetic cleanup refusal")

            with mock.patch.object(self.module.shutil, "rmtree", side_effect=denied_cleanup):
                with self.assertRaises(self.module.TransportError):
                    self.module.copy_to_verified(
                        self.jump(), self.far("203.0.113.20"), source,
                        "/var/tmp/ufm/certificate.pem", timeout=10,
                        runner=lambda command: (
                            observed.append(command), self.module.CommandResult(0, "", "")
                        )[1],
                    )
            self.assertEqual(1, len(observed), "copy happened before cleanup fault")

    def test_public_log_name_appears_only_after_complete_file_and_directory_sync(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "ufm-a-run-0005.log"
            payload = b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n"
            observed_during_write = []
            fsynced_modes = []
            original_write = self.module._write_all
            original_fsync = self.module.os.fsync

            def recording_write(fd, data):
                observed_during_write.append(destination.exists())
                return original_write(fd, data)

            def recording_fsync(fd):
                fsynced_modes.append(self.module.os.fstat(fd).st_mode)
                return original_fsync(fd)

            def runner(command):
                Path(command[-1]).write_bytes(payload)
                return self.module.CommandResult(0, "", "")

            with mock.patch.object(self.module, "_write_all", side_effect=recording_write):
                with mock.patch.object(self.module.os, "fsync", side_effect=recording_fsync):
                    self.module.copy_from_no_overwrite(
                        self.jump(), self.far("203.0.113.20"),
                        "/var/tmp/ufm/run-0005.log", destination,
                        timeout=10, runner=runner,
                    )
            self.assertEqual([False], observed_during_write)
            self.assertEqual(payload, destination.read_bytes())
            self.assertGreaterEqual(
                sum(stat.S_ISDIR(mode) for mode in fsynced_modes), 2,
                "both final link and private staging removal need parent durability",
            )

    def test_retrieval_cleanup_failure_unpublishes_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "ufm-a-run-0006.log"

            def runner(command):
                Path(command[-1]).write_bytes(
                    b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n"
                )
                return self.module.CommandResult(0, "", "")

            def denied_cleanup(path, *, ignore_errors=False):
                if ignore_errors:
                    return None
                raise OSError("synthetic cleanup refusal")

            with mock.patch.object(self.module.shutil, "rmtree", side_effect=denied_cleanup):
                with self.assertRaisesRegex(self.module.TransportError, "cleanup"):
                    self.module.copy_from_no_overwrite(
                        self.jump(), self.far("203.0.113.20"),
                        "/var/tmp/ufm/run-0006.log", destination,
                        timeout=10, runner=runner,
                    )
            self.assertFalse(destination.exists())

    def test_default_subprocess_has_total_deadline_and_redacted_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "license.lic"
            source.write_bytes(b"synthetic licence")
            with mock.patch.object(self.module.subprocess, "run") as run:
                run.return_value = self.module.subprocess.CompletedProcess(
                    ["scp"], 0, "", ""
                )
                self.module.copy_to_verified(
                    self.jump(), self.far("203.0.113.20"), source,
                    "/var/tmp/ufm/license.lic", timeout=7,
                )
                self.assertEqual(7, run.call_args.kwargs["timeout"])

                raw_secret = "SYNTHETIC" + "-TIMEOUT-SECRET"
                run.side_effect = self.module.subprocess.TimeoutExpired(
                    ["scp", raw_secret], 7, output=raw_secret,
                )
                with self.assertRaises(self.module.TransportError) as captured:
                    self.module.copy_to_verified(
                        self.jump(), self.far("203.0.113.20"), source,
                        "/var/tmp/ufm/license.lic", timeout=7,
                    )
                self.assertNotIn(raw_secret, str(captured.exception))

    def test_copy_out_race_short_write_and_unredactable_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "ufm-a-run-0003.log"

            def racing_runner(command):
                Path(command[-1]).write_bytes(
                    b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n"
                )
                destination.write_bytes(b"preexisting evidence\n")
                return self.module.CommandResult(0, "", "")

            with self.assertRaises(self.module.TransportError):
                self.module.copy_from_no_overwrite(
                    self.jump(), self.far("203.0.113.20"),
                    "/var/tmp/ufm/run-0003.log", destination,
                    timeout=10, runner=racing_runner,
                )
            self.assertEqual(b"preexisting evidence\n", destination.read_bytes())

            destination.unlink()

            def safe_runner(command):
                Path(command[-1]).write_bytes(
                    b"UFM_EVENT|stage=bootstrap|status=succeeded|code=none\n"
                )
                return self.module.CommandResult(0, "", "")

            with mock.patch.object(self.module.os, "write", return_value=0):
                with self.assertRaises(OSError):
                    self.module.copy_from_no_overwrite(
                        self.jump(), self.far("203.0.113.20"),
                        "/var/tmp/ufm/run-0003.log", destination,
                        timeout=10, runner=safe_runner,
                    )
            self.assertFalse(destination.exists())

            def binary_runner(command):
                Path(command[-1]).write_bytes(b"invalid utf8: \xff\xfe")
                return self.module.CommandResult(0, "", "")

            with self.assertRaisesRegex(self.module.TransportError, "UTF-8"):
                self.module.copy_from_no_overwrite(
                    self.jump(), self.far("203.0.113.20"),
                    "/var/tmp/ufm/run-0003.log", destination,
                    timeout=10, runner=binary_runner,
                )
            self.assertFalse(destination.exists())

    def test_every_exit_retrieves_and_preserves_primary_failure(self):
        attempts = []

        def retrieve(source):
            attempts.append(source.provenance)
            raise RuntimeError(
                "token=TOPSECRET customer=ACME opaque-SUPERSECRET-998877"
            )

        sources = [
            self.module.LogSource(
                endpoint=self.far("203.0.113.20"),
                remote_path="/var/tmp/ufm/run-0001.log",
                destination=Path("/safe/ufm-a-run-0001.log"),
                provenance="configured-ipv4",
            ),
            self.module.LogSource(
                endpoint=self.far(),
                remote_path="/var/tmp/ufm/run-0001.log",
                destination=Path("/safe/ufm-a-run-0001-linklocal.log"),
                provenance="matched-link-local",
            ),
        ]

        synthetic_secret = "SYNTHETIC-DEMO-VALUE"
        with self.assertRaises(self.module.UfmOperationFailure) as captured:
            self.module.run_with_mandatory_retrieval(
                lambda: (_ for _ in ()).throw(
                    RuntimeError(f"primary password={synthetic_secret} opaque-PRIMARY-665544")
                ),
                sources,
                retrieve,
            )
        error = captured.exception
        self.assertEqual(["configured-ipv4", "matched-link-local"], attempts)
        self.assertEqual("log_retrieval_unreachable", error.retrieval.status)
        self.assertIn("primary", error.primary_failure)
        self.assertNotIn(synthetic_secret, str(error))
        self.assertNotIn("TOPSECRET", str(error))
        self.assertNotIn("ACME", str(error))
        self.assertNotIn("SUPERSECRET", str(error))
        self.assertNotIn("PRIMARY-665544", str(error))
        self.assertIsInstance(error.__cause__, self.module.PrimaryFailureEvidence)
        self.assertIs(RuntimeError, error.__cause__.exception_class)
        self.assertNotIn(
            "PRIMARY-665544",
            "".join(traceback.format_exception(type(error), error, error.__traceback__)),
        )

        attempts.clear()
        with self.assertRaises(self.module.UfmOperationFailure) as normal_exit:
            self.module.run_with_mandatory_retrieval(
                lambda: "ok", sources, retrieve
            )
        self.assertIsNone(normal_exit.exception.primary_failure)
        self.assertEqual(["configured-ipv4", "matched-link-local"], attempts)

        attempts.clear()

        def one_success(source):
            attempts.append(source.provenance)
            if source.provenance == "matched-link-local":
                raise RuntimeError("unreachable")

        with self.assertRaises(self.module.UfmOperationFailure) as partial:
            self.module.run_with_mandatory_retrieval(
                lambda: "result", sources, one_success
            )
        self.assertEqual(["configured-ipv4", "matched-link-local"], attempts)
        self.assertIsNone(partial.exception.primary_failure)
        self.assertEqual("log_retrieval_partial", partial.exception.retrieval.status)
        self.assertEqual(
            ("retrieved", "failed"),
            tuple(item.status for item in partial.exception.retrieval.attempts),
        )
        self.assertEqual(
            ("203.0.113.20", "fe80::2:c9ff:fe12:3456"),
            tuple(item.endpoint for item in partial.exception.retrieval.attempts),
        )
        self.assertEqual(
            ("configured-ipv4", "matched-link-local"),
            tuple(item.provenance for item in partial.exception.retrieval.attempts),
        )
        failed_detail = partial.exception.retrieval.attempts[1].detail
        self.assertEqual(
            "redacted-diagnostic[sha256="
            "5e6017027437e595ec72adee0718d78f092cddaa8d31048c9d5ba2ed647ded5e"
            ",bytes=11]",
            failed_detail,
            "failure detail must fingerprint the fixture's exact exception text",
        )
        self.assertNotIn("unreachable", failed_detail)

        attempts.clear()
        self.assertEqual(
            "result",
            self.module.run_with_mandatory_retrieval(
                lambda: "result", sources,
                lambda source: attempts.append(source.provenance),
            ),
        )
        self.assertEqual(["configured-ipv4", "matched-link-local"], attempts)

    def test_base_exception_action_still_retrieves_every_source(self):
        sources = [
            self.module.LogSource(
                endpoint=self.far("203.0.113.20"),
                remote_path="/var/tmp/ufm/first.log",
                destination=Path("/safe/first.log"),
                provenance="configured-ipv4",
            ),
            self.module.LogSource(
                endpoint=self.far(),
                remote_path="/var/tmp/ufm/second.log",
                destination=Path("/safe/second.log"),
                provenance="matched-link-local",
            ),
        ]
        attempts = []
        for failure in (SystemExit(7), KeyboardInterrupt("secret=DO-NOT-REPORT")):
            with self.subTest(failure=type(failure).__name__):
                attempts.clear()

                def action():
                    raise failure

                try:
                    with self.assertRaises(self.module.UfmOperationFailure) as captured:
                        self.module.run_with_mandatory_retrieval(
                            action, sources, lambda source: attempts.append(source.provenance)
                        )
                except BaseException as escaped:
                    self.fail(f"action escaped retrieval as {type(escaped).__name__}")
                self.assertEqual(
                    ["configured-ipv4", "matched-link-local"], attempts
                )
                self.assertEqual("retrieved", captured.exception.retrieval.status)
                self.assertIn(type(failure).__name__, captured.exception.primary_failure)
                self.assertNotIn("DO-NOT-REPORT", str(captured.exception))
                self.assertIs(
                    type(failure), captured.exception.__cause__.exception_class
                )
                self.assertNotIn(
                    "DO-NOT-REPORT",
                    "".join(traceback.format_exception(
                        type(captured.exception), captured.exception,
                        captured.exception.__traceback__,
                    )),
                )

    def test_retrieval_base_exception_does_not_skip_later_source(self):
        sources = [
            self.module.LogSource(
                endpoint=self.far("203.0.113.20"),
                remote_path="/var/tmp/ufm/first.log",
                destination=Path("/safe/first.log"),
                provenance="configured-ipv4",
            ),
            self.module.LogSource(
                endpoint=self.far(),
                remote_path="/var/tmp/ufm/second.log",
                destination=Path("/safe/second.log"),
                provenance="matched-link-local",
            ),
        ]
        attempts = []

        def retrieve(source):
            attempts.append(source.provenance)
            if source.provenance == "configured-ipv4":
                raise SystemExit("token=DO-NOT-REPORT")

        try:
            with self.assertRaises(self.module.UfmOperationFailure) as captured:
                self.module.run_with_mandatory_retrieval(
                    lambda: "not-a-success", sources, retrieve
                )
        except BaseException as escaped:
            self.fail(f"retrieval escaped as {type(escaped).__name__}")
        self.assertEqual(["configured-ipv4", "matched-link-local"], attempts)
        self.assertEqual("log_retrieval_partial", captured.exception.retrieval.status)
        self.assertEqual(
            ("failed", "retrieved"),
            tuple(item.status for item in captured.exception.retrieval.attempts),
        )
        self.assertEqual(
            ("203.0.113.20", "fe80::2:c9ff:fe12:3456"),
            tuple(item.endpoint for item in captured.exception.retrieval.attempts),
        )
        self.assertEqual(
            ("configured-ipv4", "matched-link-local"),
            tuple(item.provenance for item in captured.exception.retrieval.attempts),
        )
        self.assertEqual(
            "redacted-diagnostic[sha256="
            "bd8eb3bed9e8e0b233e2de8fdec72d23c3387c5f0c9f51dc9bbde6acb0f7dfd0"
            ",bytes=19]",
            captured.exception.retrieval.attempts[0].detail,
            "SystemExit detail must fingerprint the fixture's exact exception text",
        )
        self.assertNotIn("DO-NOT-REPORT", str(captured.exception))


if __name__ == "__main__":
    unittest.main()
