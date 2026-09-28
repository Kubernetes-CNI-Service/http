"""Synthetic protected UFM producer -> exact retrieval -> real local analyzer."""

from __future__ import annotations

import hashlib
import datetime as dt
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest import mock

from infra.ufm_jump_transport import CommandResult
from test_cases.test_ib_analysis_domain import write_ibdiagnet_fixture
from test_cases.test_ufm_collection_pipeline_workflow import _write_cvt
from test_cases.test_ufm_identity_binding import NOW, NODES, make_site
from test_cases.test_ufm_identity_binding_workflow import write_project
from tools import ufm_collection_agent as agent
from tools import ufm_remote_producer as remote
from tools.ufm_collection_contract import collection_plan, publish_local_archive
from tools.ufm_collection_pipeline import PipelineError, run_local_ibdiagnet, validated_receipts


RUN_ID = "20260926-0000-air-0123456789abcdef"
PIN_A, PIN_C, PIN_P = "a" * 64, "b" * 64, "c" * 64


class UfmIbdiagnetRemoteWorkflowTests(unittest.TestCase):
    def test_retrieved_source_cannot_be_used_for_another_archive_or_project(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            first_root = root / "first"
            second_root = root / "second"
            first_root.mkdir()
            second_root.mkdir()
            first = write_project(first_root)
            second = write_project(second_root)
            self.assertEqual((first / "02-devices_config.csv").read_bytes(),
                             (second / "02-devices_config.csv").read_bytes())
            source = root / "source"
            source.mkdir()
            write_ibdiagnet_fixture(source)
            private = root / "private"
            private.mkdir()
            source_archive = publish_local_archive(plan, source, private)
            digest = hashlib.sha256(source_archive.read_bytes()).hexdigest()
            incoming = root / "incoming"
            incoming.mkdir()
            destination = incoming / plan.archive_name
            unrelated = root / "unrelated"
            unrelated.mkdir()
            other_archive = unrelated / plan.archive_name
            other_archive.write_bytes(source_archive.read_bytes())
            self.assertEqual(digest, hashlib.sha256(other_archive.read_bytes()).hexdigest())
            cvt = root / "cvt.xlsx"
            _write_cvt(cvt)
            identity = remote.VerifiedManagementIdentity(
                "EXAMPLE-UFM01", far.host, NODES[0].management_mac,
                NOW + dt.timedelta(hours=1), NOW, pin, "c" * 64, "eno8303")
            observation = remote.RemoteCollectionObservation(
                identity.hostname, RUN_ID, "ibdiagnet", plan.ufm_remote_path,
                digest)
            install = remote.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", PIN_A, PIN_C, PIN_P)
            calls = []

            def copy_exact(_project, _lease, _jump, _far, _pin, _plan,
                           target, **_kwargs):
                target.write_bytes(source_archive.read_bytes())
                return target

            def observe_digest(_jump, _far, argv, *, runner, timeout):
                calls.append(argv)
                self.assertEqual(["sha256sum", "--", plan.ufm_remote_path], argv)
                return CommandResult(0, f"{digest}  {plan.ufm_remote_path}\n", "")

            scope = dict(lease_path=lease, jump=jump, far=far,
                         known_hosts_pin=pin, timeout=600, clock=lambda: NOW,
                         runner=lambda argv: self.fail("unexpected real transport"))
            with mock.patch.object(remote, "verify_project_management_identity",
                                   return_value=identity), mock.patch.object(
                                       remote, "observe_remote_producer",
                                       return_value=observation), mock.patch.object(
                                           remote, "retrieve_project_collection_archive",
                                           side_effect=copy_exact), mock.patch.object(
                                               remote, "_remote",
                                               side_effect=observe_digest):
                retrieved = remote.observe_and_retrieve_remote_producer(
                    plan, install=install, project=first,
                    destination=destination, **scope)
                self.assertEqual(first, retrieved.project_path)
                calls.clear()
                with self.assertRaises(remote.RemoteProducerError):
                    remote.run_verified_retrieved_ibdiagnet(
                        plan, retrieved, archive=other_archive, cvt=cvt,
                        project=first, **scope)
                with self.assertRaises(remote.RemoteProducerError):
                    remote.run_verified_retrieved_ibdiagnet(
                        plan, retrieved, archive=destination, cvt=cvt,
                        project=second, **scope)
                self.assertEqual([], calls)
                self.assertEqual([], validated_receipts(first, "air"))
                self.assertEqual([], validated_receipts(second, "air"))
                result = remote.run_verified_retrieved_ibdiagnet(
                    plan, retrieved, archive=destination, cvt=cvt,
                    project=first, **scope)
                self.assertTrue((result / f"ibdiagnet2_{RUN_ID}-topology-validation.xlsx").is_file())
                receipt, = validated_receipts(first, "air")
                self.assertEqual(digest, receipt["archive_sha256"])
                self.assertEqual([], validated_receipts(second, "air"))

    def test_pinned_synthetic_producer_exact_retrieval_and_real_analyzer(self):
        plan = collection_plan("ibdiagnet", RUN_ID)
        for phase in ("stable", "pre-copy-drift", "local-before-receipt",
                      "remote-before-receipt", "lease-before-receipt"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                lease, _known, jump, far, pin = make_site(root)
                project = write_project(root)
                install = remote.RemoteAgentInstall(
                    "/opt/http-v3-ufm", "/usr/bin/python3", PIN_A, PIN_C, PIN_P)
                output = root / "fake-ufm-output"
                staging = root / "fake-container-copy"
                output.mkdir()
                staging.mkdir()
                destination = root / plan.archive_name
                cvt = root / "cvt.xlsx"
                _write_cvt(cvt)
                events: list[list[str]] = []
                produced: list[Path] = []
                remote_digest_calls = 0
                vendor_events: list[list[str]] = []
                remote_receipt_drift = False

                def fake_vendor(argv):
                    vendor_events.append(argv)
                    if argv[:2] == ["docker", "cp"]:
                        source = Path(argv[-1])
                        source.mkdir()
                        write_ibdiagnet_fixture(source)
                    return agent.InvocationResult(0, b"", b"")

                def fake_service(argv):
                    nonlocal remote_digest_calls
                    connect_timeouts = [arg for arg in argv
                                        if arg.startswith("ConnectTimeout=")]
                    self.assertEqual(1, len(connect_timeouts))
                    connect_timeout = int(connect_timeouts[0].split("=", 1)[1])
                    self.assertGreater(connect_timeout, 0)
                    self.assertLessEqual(connect_timeout, 600)
                    if argv[0] == "scp":
                        events.append(["scp", argv[-2], argv[-1]])
                        self.assertEqual(1, len(produced))
                        self.assertIn(plan.ufm_remote_path, argv[-2])
                        Path(argv[-1]).write_bytes(produced[0].read_bytes())
                        return CommandResult(0, "", "")
                    self.assertEqual("ssh", argv[0])
                    self.assertIn(far.target, argv)
                    args = shlex.split(argv[-1])
                    if args == [install.python_path, "-I", "-S", "-B",
                                install.agent_path, "--kind", "ibdiagnet",
                                "--run-id", RUN_ID]:
                        self.assertEqual(600, connect_timeout)
                    events.append(args)
                    if args == ["hostname"]:
                        return CommandResult(0, "EXAMPLE-UFM01\n", "")
                    if args == ["ip", "-j", "link", "show", "dev", "eno8303"]:
                        return CommandResult(0, json.dumps([{
                            "ifname": "eno8303", "address": NODES[0].management_mac,
                        }]), "")
                    if args == ["ip", "-j", "address", "show", "dev", "eno8303"]:
                        return CommandResult(0, json.dumps([{
                            "ifname": "eno8303", "addr_info": [{
                                "family": "inet", "local": NODES[0].address,
                            }],
                        }]), "")
                    if args[:3] == ["stat", "-c", "%u:%a:%F"]:
                        is_file = args[-1] in {
                            install.agent_path, install.contract_path, install.python_path,
                        }
                        return CommandResult(
                            0, "0:644:regular file\n" if is_file
                            else "0:755:directory\n", "")
                    if args[:2] == ["sha256sum", "--"]:
                        if args[-1] == plan.ufm_remote_path:
                            self.assertEqual(1, len(produced))
                            remote_digest_calls += 1
                            digest = hashlib.sha256(produced[0].read_bytes()).hexdigest()
                            if ((phase == "pre-copy-drift" and remote_digest_calls == 2)
                                    or remote_receipt_drift):
                                digest = "f" * 64
                        else:
                            digest = {
                                install.agent_path: PIN_A,
                                install.contract_path: PIN_C,
                                install.python_path: PIN_P,
                            }[args[-1]]
                        return CommandResult(0, f"{digest}  {args[-1]}\n", "")
                    if args == [install.python_path, "-I", "-S", "-B",
                                install.agent_path, "--kind", "ibdiagnet",
                                "--run-id", RUN_ID]:
                        with mock.patch.object(agent.socket, "gethostname",
                                               return_value="EXAMPLE-UFM01"):
                            produced.append(agent.collect_local(
                                plan, output, staging_dir=staging, runner=fake_vendor))
                        return CommandResult(0, "", "")
                    if args == ["test", "-f", plan.ufm_remote_path]:
                        return CommandResult(0, "", "")
                    self.fail(f"unexpected synthetic command: {args!r}")

                if phase == "pre-copy-drift":
                    with self.assertRaises(remote.RemoteProducerError):
                        remote.observe_and_retrieve_remote_producer(
                            plan, install=install, project=project, lease_path=lease,
                            jump=jump, far=far, known_hosts_pin=pin,
                            destination=destination, timeout=600, clock=lambda: NOW,
                            runner=fake_service)
                    self.assertFalse(destination.exists())
                    self.assertEqual([], validated_receipts(project, "air"))
                    self.assertFalse(any(event[0] == "scp" for event in events))
                    continue

                retrieved = remote.observe_and_retrieve_remote_producer(
                    plan, install=install, project=project, lease_path=lease,
                    jump=jump, far=far, known_hosts_pin=pin,
                    destination=destination, timeout=600, clock=lambda: NOW,
                    runner=fake_service)
                self.assertEqual("verified-retrieved", retrieved.state)
                self.assertEqual(plan.ufm_remote_path, retrieved.remote.archive_path)
                self.assertEqual(hashlib.sha256(destination.read_bytes()).hexdigest(),
                                 retrieved.local_sha256)
                self.assertEqual(retrieved.remote_sha256_before,
                                 retrieved.remote_sha256_after)
                self.assertEqual(retrieved.identity_before_sha256,
                                 retrieved.identity_after_sha256)
                self.assertEqual([
                    ["docker", "exec", "ufm", "test", "!", "-e",
                     "/var/tmp/ibdiagnet2"],
                    ["docker", "exec", "ufm", *plan.vendor_argv],
                ], vendor_events[:2])
                self.assertEqual("ufm:/var/tmp/ibdiagnet2", vendor_events[2][-2])
                self.assertFalse(any("*" in arg or arg == "-it"
                                     for event in vendor_events for arg in event))
                receipt_gate = remote.retrieved_observation_receipt_gate(
                    plan, retrieved, project=project, lease_path=lease,
                    jump=jump, far=far, known_hosts_pin=pin,
                    timeout=600, clock=lambda: NOW, runner=fake_service,
                )

                def before_receipt():
                    nonlocal remote_receipt_drift
                    if phase == "local-before-receipt":
                        destination.write_bytes(b"changed after retrieval")
                    elif phase == "remote-before-receipt":
                        remote_receipt_drift = True
                    elif phase == "lease-before-receipt":
                        lease.write_text("lease 192.0.2.21 { binding state free; }\n")
                    receipt_gate()

                if phase != "stable":
                    with self.assertRaisesRegex(PipelineError,
                                                "pre-receipt evidence gate failed"):
                        run_local_ibdiagnet(
                            plan, retrieved.remote.node, retrieved.local_path,
                            cvt, project, before_receipt=before_receipt)
                    self.assertEqual([], validated_receipts(project, "air"))
                    continue
                result = run_local_ibdiagnet(
                    plan, retrieved.remote.node, retrieved.local_path, cvt,
                    project, before_receipt=before_receipt)
                self.assertTrue((result / f"ibdiagnet2_{RUN_ID}-topology-validation.xlsx").is_file())
                receipt, = validated_receipts(project, "air")
                self.assertEqual(retrieved.local_sha256, receipt["archive_sha256"])
                self.assertEqual("ibdiagnet", receipt["kind"])


if __name__ == "__main__":
    unittest.main()
