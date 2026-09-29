"""Direct fail-closed contract for a server-owned UFM remote producer."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest import mock

from infra.ufm_jump_transport import CommandResult
from test_cases.test_ufm_identity_binding import NOW, make_site
from test_cases.test_ufm_identity_binding_workflow import write_project
from tools.ufm_collection_contract import collection_plan


RUN_ID = "20260926-0000-air-0123456789abcdef"
AGENT_PIN = "a" * 64
CONTRACT_PIN = "b" * 64
PYTHON_PIN = "c" * 64


class UfmRemoteProducerTests(unittest.TestCase):
    def test_retrieved_handoff_rejects_wrong_destination_before_remote_action(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            calls = []
            with self.assertRaises(producer.RemoteProducerError):
                producer.observe_and_retrieve_remote_producer(
                    collection_plan("iblinkinfo", RUN_ID), install=install,
                    project=project, lease_path=lease, jump=jump, far=far,
                    known_hosts_pin=pin, destination=root / "wrong.tar.gz",
                    timeout=10, clock=lambda: NOW,
                    runner=lambda argv: calls.append(argv),
                )
            self.assertEqual([], calls)

    def test_no_approved_install_or_unsafe_path_rejects_before_remote_action(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            calls = []
            scope = dict(project=project, lease_path=lease, jump=jump, far=far,
                         known_hosts_pin=pin, timeout=10,
                         clock=lambda: NOW, runner=lambda argv: calls.append(argv))
            plan = collection_plan("iblinkinfo", RUN_ID)
            for install in (None,
                            producer.RemoteAgentInstall(
                                "/tmp/../escape", "/usr/bin/python3",
                                AGENT_PIN, CONTRACT_PIN, PYTHON_PIN),
                            producer.RemoteAgentInstall(
                                "/opt/http-v3", "python3", AGENT_PIN, CONTRACT_PIN,
                                PYTHON_PIN),
                            producer.RemoteAgentInstall(
                                "/opt/http-v3", "/usr/bin/python3", "", CONTRACT_PIN,
                                PYTHON_PIN),
                            producer.RemoteAgentInstall(
                                "/opt/http-v3", "/usr/bin/python3", AGENT_PIN,
                                CONTRACT_PIN, "")):
                with self.subTest(install=install), self.assertRaises(
                    producer.RemoteProducerError
                ):
                    producer.observe_remote_producer(plan, install=install, **scope)
            self.assertEqual([], calls)

    def test_mismatched_install_digest_never_invokes_vendor_agent(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            calls = []
            observed = producer.VerifiedManagementIdentity(
                "EXAMPLE-UFM01", far.host, "aa:bb:cc:dd:ee:ff",
                NOW + dt.timedelta(hours=1), NOW, pin, "c" * 64, "eno8303")

            def fake_remote(argv):
                calls.append(argv[-1])
                if "sha256sum" in argv[-1]:
                    return CommandResult(0, f"{'f' * 64}  {install.agent_path}\n", "")
                if "stat " in argv[-1]:
                    mode = ("0:644:regular file\n" if install.agent_path in argv[-1]
                            or install.contract_path in argv[-1]
                            or install.python_path in argv[-1]
                            else "0:755:directory\n")
                    return CommandResult(0, mode, "")
                return CommandResult(0, "", "")

            with mock.patch.object(producer, "verify_project_management_identity",
                                   return_value=observed):
                with self.assertRaisesRegex(producer.RemoteProducerError, "digest"):
                    producer.observe_remote_producer(
                        collection_plan("iblinkinfo", RUN_ID), install=install,
                        project=project, lease_path=lease, jump=jump, far=far,
                        known_hosts_pin=pin, timeout=10, clock=lambda: NOW,
                        runner=fake_remote,
                    )
            self.assertTrue(calls)
            self.assertFalse(any("--kind" in command for command in calls))

    def test_source_replaced_during_vendor_run_cannot_yield_success_observation(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            observed = producer.VerifiedManagementIdentity(
                "EXAMPLE-UFM01", far.host, "aa:bb:cc:dd:ee:ff",
                NOW + dt.timedelta(hours=1), NOW, pin, "c" * 64, "eno8303")
            ran_vendor = False
            calls = []

            def fake_remote(argv):
                nonlocal ran_vendor
                args = shlex.split(argv[-1])
                calls.append(args)
                if args[:3] == ["stat", "-c", "%u:%a:%F"]:
                    is_file = args[-1] in (install.agent_path, install.contract_path,
                                           install.python_path)
                    return CommandResult(0, "0:644:regular file\n" if is_file
                                         else "0:755:directory\n", "")
                if args[:2] == ["sha256sum", "--"]:
                    digest = {install.agent_path: AGENT_PIN,
                              install.contract_path: CONTRACT_PIN,
                              install.python_path: PYTHON_PIN,
                              collection_plan("iblinkinfo", RUN_ID).ufm_remote_path:
                                  "d" * 64}[args[-1]]
                    if ran_vendor and args[-1] == install.contract_path:
                        digest = "f" * 64
                    return CommandResult(0, f"{digest}  {args[-1]}\n", "")
                if args[0] == install.python_path:
                    ran_vendor = True
                    return CommandResult(0, "", "")
                self.fail(f"unexpected remote command: {args!r}")

            with mock.patch.object(producer, "verify_project_management_identity",
                                   return_value=observed):
                with self.assertRaisesRegex(producer.RemoteProducerError, "digest"):
                    producer.observe_remote_producer(
                        collection_plan("iblinkinfo", RUN_ID), install=install,
                        project=project, lease_path=lease, jump=jump, far=far,
                        known_hosts_pin=pin, timeout=10, clock=lambda: NOW,
                        runner=fake_remote,
                    )
            self.assertTrue(ran_vendor)
            self.assertEqual([], [args for args in calls if args[:2] == ["scp", "--"]])

    def test_ambiguous_install_metadata_stderr_rejects_before_vendor(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            observed = producer.VerifiedManagementIdentity(
                "EXAMPLE-UFM01", far.host, "aa:bb:cc:dd:ee:ff",
                NOW + dt.timedelta(hours=1), NOW, pin, "c" * 64, "eno8303")
            calls = []

            def fake_remote(argv):
                args = shlex.split(argv[-1])
                calls.append(args)
                if args[:3] == ["stat", "-c", "%u:%a:%F"]:
                    return CommandResult(0, "0:755:directory\n", "unexpected warning")
                self.fail(f"source ambiguity must block before {args!r}")

            with mock.patch.object(producer, "verify_project_management_identity",
                                   return_value=observed):
                with self.assertRaises(producer.RemoteProducerError):
                    producer.observe_remote_producer(
                        collection_plan("iblinkinfo", RUN_ID), install=install,
                        project=project, lease_path=lease, jump=jump, far=far,
                        known_hosts_pin=pin, timeout=10, clock=lambda: NOW,
                        runner=fake_remote,
                    )
            self.assertEqual(1, len(calls))

    def test_final_digest_with_warning_cannot_become_observation(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            plan = collection_plan("iblinkinfo", RUN_ID)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            observed = producer.VerifiedManagementIdentity(
                "EXAMPLE-UFM01", far.host, "aa:bb:cc:dd:ee:ff",
                NOW + dt.timedelta(hours=1), NOW, pin, "c" * 64, "eno8303")
            ran_vendor = False

            def fake_remote(argv):
                nonlocal ran_vendor
                args = shlex.split(argv[-1])
                if args[:3] == ["stat", "-c", "%u:%a:%F"]:
                    is_file = args[-1] in (install.agent_path, install.contract_path,
                                           install.python_path)
                    return CommandResult(0, "0:644:regular file\n" if is_file
                                         else "0:755:directory\n", "")
                if args[:2] == ["sha256sum", "--"]:
                    digest = {install.agent_path: AGENT_PIN,
                              install.contract_path: CONTRACT_PIN,
                              install.python_path: PYTHON_PIN,
                              plan.ufm_remote_path: "d" * 64}[args[-1]]
                    warning = "unexpected diagnostic" if args[-1] == plan.ufm_remote_path else ""
                    return CommandResult(0, f"{digest}  {args[-1]}\n", warning)
                if args[0] == install.python_path:
                    ran_vendor = True
                    return CommandResult(0, "", "")
                self.fail(f"unexpected remote command: {args!r}")

            with mock.patch.object(producer, "verify_project_management_identity",
                                   return_value=observed):
                with self.assertRaises(producer.RemoteProducerError):
                    producer.observe_remote_producer(
                        plan, install=install, project=project, lease_path=lease,
                        jump=jump, far=far, known_hosts_pin=pin, timeout=10,
                        clock=lambda: NOW, runner=fake_remote,
                    )
            self.assertTrue(ran_vendor)


if __name__ == "__main__":
    unittest.main()
