"""Project/lease/SSH → pinned UFM agent → exact final name; fake service only."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from infra.ufm_jump_transport import CommandResult
from test_cases.test_ufm_identity_binding import NOW, NODES, make_site
from test_cases.test_ufm_identity_binding_workflow import write_project
from tools import ufm_collection_agent as AGENT
from tools.ufm_collection_contract import collection_plan


RUN_ID = "20260926-0000-air-0123456789abcdef"
AGENT_PIN = "a" * 64
CONTRACT_PIN = "b" * 64
PYTHON_PIN = "c" * 64
RAW = b"Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
ROOT = Path(__file__).resolve().parents[1]


class UfmRemoteProducerWorkflowTests(unittest.TestCase):
    def test_real_producer_to_formal_retrieval_binds_same_digest_and_node(self):
        from tools import ufm_remote_producer as producer

        plan = collection_plan("iblinkinfo", RUN_ID)
        for phase in ("stable", "changed-before-copy", "changed-after-copy",
                      "changed-at-attestation",
                      "node-changed-during-copy", "lease-changed-during-copy",
                      "host-pin-changed-during-copy"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                lease, known, jump, far, pin = make_site(root)
                project = write_project(root)
                install = producer.RemoteAgentInstall(
                    "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                    CONTRACT_PIN, PYTHON_PIN)
                output = root / "fake-ufm-output"
                output.mkdir()
                destination = root / plan.archive_name
                events = []
                produced = []
                final_digest_calls = 0
                node_changed = False

                def fake_service(argv):
                    nonlocal final_digest_calls, node_changed
                    if argv[0] == "scp":
                        events.append(["scp", argv[-2], argv[-1]])
                        self.assertIn(plan.ufm_remote_path, argv[-2])
                        self.assertEqual(1, len(produced))
                        Path(argv[-1]).write_bytes(produced[0].read_bytes())
                        if phase == "node-changed-during-copy":
                            node_changed = True
                        if phase == "lease-changed-during-copy":
                            lease.write_text("lease 192.0.2.21 { binding state free; }\n")
                        if phase == "host-pin-changed-during-copy":
                            known.write_text(known.read_text() + "# changed during copy\n")
                        return CommandResult(0, "", "")
                    self.assertEqual("ssh", argv[0])
                    self.assertIn(far.target, argv)
                    args = shlex.split(argv[-1])
                    events.append(args)
                    if args == ["hostname"]:
                        return CommandResult(
                            0, "EXAMPLE-UFM02\n" if node_changed else "EXAMPLE-UFM01\n", "")
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
                            install.agent_path, install.contract_path,
                            install.python_path,
                        }
                        return CommandResult(
                            0, "0:644:regular file\n" if is_file
                            else "0:755:directory\n", "")
                    if args[:2] == ["sha256sum", "--"]:
                        if args[-1] == plan.ufm_remote_path:
                            self.assertEqual(1, len(produced))
                            final_digest_calls += 1
                            digest = hashlib.sha256(produced[0].read_bytes()).hexdigest()
                            if ((phase == "changed-before-copy" and final_digest_calls == 2)
                                    or (phase == "changed-after-copy" and final_digest_calls == 3)
                                    or (phase == "changed-at-attestation"
                                        and final_digest_calls == 4)):
                                digest = "f" * 64 if digest != "f" * 64 else "e" * 64
                        else:
                            digest = {
                                install.agent_path: AGENT_PIN,
                                install.contract_path: CONTRACT_PIN,
                                install.python_path: PYTHON_PIN,
                            }[args[-1]]
                        return CommandResult(0, f"{digest}  {args[-1]}\n", "")
                    if args == [install.python_path, "-I", "-S", "-B",
                                install.agent_path, "--kind", "iblinkinfo",
                                "--run-id", RUN_ID]:
                        with mock.patch.object(AGENT.socket, "gethostname",
                                               return_value="EXAMPLE-UFM01"):
                            produced.append(AGENT.collect_local(
                                plan, output,
                                runner=lambda vendor: AGENT.InvocationResult(0, RAW, b""),
                            ))
                        return CommandResult(0, "", "")
                    if args == ["test", "-f", plan.ufm_remote_path]:
                        return CommandResult(0, "", "")
                    self.fail(f"unexpected fake SSH command: {args!r}")

                if phase == "stable":
                    result = producer.observe_and_retrieve_remote_producer(
                        plan, install=install, project=project, lease_path=lease,
                        jump=jump, far=far, known_hosts_pin=pin,
                        destination=destination, timeout=10, clock=lambda: NOW,
                        runner=fake_service,
                    )
                    self.assertEqual("verified-retrieved", result.state)
                    self.assertEqual("remote-final-observed", result.remote.state)
                    self.assertEqual("EXAMPLE-UFM01", result.remote.node)
                    self.assertEqual(RUN_ID, result.remote.run_id)
                    self.assertEqual(destination, result.local_path)
                    self.assertEqual(produced[0].read_bytes(), destination.read_bytes())
                    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
                    self.assertEqual(digest, result.local_sha256)
                    self.assertEqual(digest, result.remote.remote_sha256)
                    self.assertEqual(digest, result.remote_sha256_before)
                    self.assertEqual(digest, result.remote_sha256_after)
                    self.assertRegex(result.identity_before_sha256, r"^[0-9a-f]{64}$")
                    self.assertEqual(
                        result.identity_before_sha256, result.identity_after_sha256,
                    )
                    self.assertEqual(4, final_digest_calls)
                else:
                    with self.assertRaises(producer.RemoteProducerError):
                        producer.observe_and_retrieve_remote_producer(
                            plan, install=install, project=project, lease_path=lease,
                            jump=jump, far=far, known_hosts_pin=pin,
                            destination=destination, timeout=10, clock=lambda: NOW,
                            runner=fake_service,
                        )
                    if phase != "changed-at-attestation":
                        self.assertFalse(destination.exists())
                    self.assertEqual(
                        phase != "changed-before-copy",
                        any(event and event[0] == "scp" for event in events),
                    )
                self.assertTrue(any(event == ["hostname"] for event in events))

    def test_exact_absolute_agent_is_importable_without_ambient_site_or_pythonpath(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            poisoned = root / "ambient"
            poisoned.mkdir()
            sentinel = root / "site-executed"
            (poisoned / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('poison')\n"
            )
            foreign_tools = poisoned / "tools"
            foreign_tools.mkdir()
            (foreign_tools / "__init__.py").write_text("")
            (foreign_tools / "ufm_collection_contract.py").write_text(
                "raise RuntimeError('foreign tools package loaded')\n"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B",
                 str(ROOT / "tools/ufm_collection_agent.py"), "--help"],
                cwd=root, env={**os.environ, "PYTHONPATH": str(poisoned)},
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("--run-id", result.stdout)
            self.assertFalse(sentinel.exists())

    def test_real_project_verifier_precedes_exact_fake_ssh_agent_and_final_observation(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            output = root / "fake-ufm-output"
            output.mkdir()
            plan = collection_plan("iblinkinfo", RUN_ID)
            events = []
            produced = []

            def fake_service(argv):
                self.assertEqual("ssh", argv[0])
                self.assertIn(far.target, argv)
                args = shlex.split(argv[-1])
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
                    is_file = args[-1] in {install.agent_path, install.contract_path,
                                          install.python_path}
                    return CommandResult(0, "0:644:regular file\n" if is_file
                                         else "0:755:directory\n", "")
                if args == ["sha256sum", "--", install.agent_path]:
                    return CommandResult(0, f"{AGENT_PIN}  {install.agent_path}\n", "")
                if args == ["sha256sum", "--", install.contract_path]:
                    return CommandResult(0, f"{CONTRACT_PIN}  {install.contract_path}\n", "")
                if args == ["sha256sum", "--", install.python_path]:
                    return CommandResult(0, f"{PYTHON_PIN}  {install.python_path}\n", "")
                if args == [install.python_path, "-I", "-S", "-B", install.agent_path,
                            "--kind", "iblinkinfo", "--run-id", RUN_ID]:
                    with mock.patch.object(AGENT.socket, "gethostname",
                                           return_value="EXAMPLE-UFM01"):
                        produced.append(AGENT.collect_local(
                            plan, output,
                            runner=lambda vendor: AGENT.InvocationResult(0, RAW, b""),
                        ))
                    return CommandResult(0, "", "")
                if args == ["sha256sum", "--", plan.ufm_remote_path]:
                    self.assertEqual(1, len(produced))
                    digest = hashlib.sha256(produced[0].read_bytes()).hexdigest()
                    return CommandResult(0,
                                         f"{digest}  {plan.ufm_remote_path}\n", "")
                self.fail(f"unexpected fake SSH command: {args!r}")

            observation = producer.observe_remote_producer(
                plan, install=install, project=project, lease_path=lease,
                jump=jump, far=far, known_hosts_pin=pin,
                timeout=10, clock=lambda: NOW, runner=fake_service,
            )
            self.assertEqual("remote-final-observed", observation.state)
            self.assertEqual(RUN_ID, observation.run_id)
            self.assertEqual("EXAMPLE-UFM01", observation.node)
            self.assertEqual(plan.ufm_remote_path, observation.archive_path)
            self.assertEqual(hashlib.sha256(produced[0].read_bytes()).hexdigest(),
                             observation.remote_sha256)
            self.assertEqual(1, len(produced))
            vendor_index = events.index([install.python_path, "-I", "-S", "-B",
                                         install.agent_path,
                                         "--kind", "iblinkinfo", "--run-id", RUN_ID])
            self.assertGreater(vendor_index, 3)
            self.assertIn(["sha256sum", "--", install.agent_path], events[:vendor_index])
            self.assertIn(["sha256sum", "--", install.contract_path],
                          events[:vendor_index])
            self.assertNotIn("completed", observation.state)

    def test_expired_lease_at_recheck_blocks_before_vendor_agent(self):
        from tools import ufm_remote_producer as producer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            install = producer.RemoteAgentInstall(
                "/opt/http-v3-ufm", "/usr/bin/python3", AGENT_PIN,
                CONTRACT_PIN, PYTHON_PIN)
            calls = []

            def fake_service(argv):
                args = shlex.split(argv[-1])
                calls.append(args)
                if args == ["hostname"]:
                    return CommandResult(0, "EXAMPLE-UFM01\n", "")
                if args[:5] == ["ip", "-j", "link", "show", "dev"]:
                    return CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": NODES[0].management_mac,
                    }]), "")
                if args[:5] == ["ip", "-j", "address", "show", "dev"]:
                    return CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "addr_info": [{
                            "family": "inet", "local": NODES[0].address,
                        }],
                    }]), "")
                if args[:3] == ["stat", "-c", "%u:%a:%F"]:
                    is_file = args[-1] in {install.agent_path, install.contract_path,
                                          install.python_path}
                    return CommandResult(0, "0:644:regular file\n" if is_file
                                         else "0:755:directory\n", "")
                if args[:2] == ["sha256sum", "--"]:
                    digest = {install.agent_path: AGENT_PIN,
                              install.contract_path: CONTRACT_PIN,
                              install.python_path: PYTHON_PIN}[args[-1]]
                    if args[-1] == install.contract_path:
                        lease.write_text("lease 192.0.2.21 { binding state free; }\n")
                    return CommandResult(0, f"{digest}  {args[-1]}\n", "")
                self.fail(f"vendor must not run: {args!r}")

            with self.assertRaises(producer.RemoteProducerError):
                producer.observe_remote_producer(
                    collection_plan("iblinkinfo", RUN_ID), install=install,
                    project=project, lease_path=lease, jump=jump, far=far,
                    known_hosts_pin=pin, timeout=10, clock=lambda: NOW,
                    runner=fake_service,
                )
            self.assertFalse(any("--kind" in args for args in calls))


if __name__ == "__main__":
    unittest.main()
