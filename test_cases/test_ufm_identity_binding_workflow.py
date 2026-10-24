#!/usr/bin/env python3
"""Discovery→pinned management identity→exact archive retrieval handoff."""

from __future__ import annotations

import hashlib
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import yaml

from infra import ufm_jump_transport as transport
from test_cases.test_ufm_identity_binding import NODES, NOW, make_site
from test_cases.test_ufm_collection_archive_retrieval import _archive
from tools import ufm_collection_contract as collection
from tools import ufm_identity_binding as binding


RUN_ID = "20260926-0315-air-0123456789abcdef"


def write_project(root: Path, *, first_mac: str = "02:00:00:00:00:21") -> Path:
    project = root / "project"
    project.mkdir()
    (project / "01-global.yaml").write_text(yaml.safe_dump({
        "servers": [{"ufm": {"version": "2.5.1-8", "interfaces": {
            "alias": {"eth0": "eno8303", "eth1": "eno8403"},
        }}}],
    }))
    (project / "02-devices_config.csv").write_text(
        "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
        f"EXAMPLE-UFM01,ufm,NA,192.0.2.21,24,192.0.2.1,{first_mac}\n"
        "EXAMPLE-UFM02,ufm,NA,192.0.2.22,24,192.0.2.1,02:00:00:00:00:22\n"
    )
    return project


class UfmIdentityBindingWorkflowTests(unittest.TestCase):
    def test_discovery_cli_enforces_top_level_server_shape_without_rewriting_nested_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, _jump, _far, _pin = make_site(root)
            project = write_project(root)
            global_path = project / "01-global.yaml"
            valid = (
                "servers:\n"
                "  - ufm:\n"
                "      version: '2.5.1-8'\n"
                "      interfaces:\n"
                "        alias: {eth0: eno8303, eth1: eno8403}\n"
                "switches:\n"
                "  - eth:\n"
                "      services:\n"
                "        dhcp_relay:\n"
                "          inband:\n"
                "            server_group:\n"
                "              servers: [192.0.2.53]\n"
            )
            command = [
                sys.executable, "-B", str(Path(__file__).resolve().parents[1]
                                            / "tools/ufm-discover.py"),
                "--project", str(project), "--leases", str(lease),
            ]

            global_path.write_text(valid, encoding="utf-8")
            accepted = subprocess.run(command, text=True, capture_output=True,
                                      check=False)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            product = json.loads(accepted.stdout)
            self.assertEqual("discovery_only", product["phase"])
            self.assertEqual(2, len(product["nodes"]))
            self.assertFalse(product["vip_configured"])
            self.assertEqual(valid, global_path.read_text(encoding="utf-8"))
            self.assertFalse((project / "99-output-ufm").exists())

            malformed_documents = (
                valid.replace("  - ufm:\n", "  ufm:\n", 1),
                valid.replace("'2.5.1-8'", "2.5", 1),
                valid.replace("alias: {eth0: eno8303, eth1: eno8403}",
                              "alias: {eth0: eno8303, eth0: eno8403, eth1: eno8403}", 1),
            )
            for malformed in malformed_documents:
                with self.subTest(malformed=malformed.splitlines()[:5]):
                    global_path.write_text(malformed, encoding="utf-8")
                    rejected = subprocess.run(command, text=True, capture_output=True,
                                              check=False)
                    self.assertNotEqual(0, rejected.returncode)
                    self.assertEqual("", rejected.stdout,
                                     "invalid schema must publish no JSON product")
                    self.assertFalse((project / "99-output-ufm").exists())

    def test_project_csv_and_global_sources_bind_before_any_ssh_or_archive_probe(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root, first_mac="02:00:00:00:00:99")
            seen: list[list[str]] = []
            with self.assertRaises(binding.IdentityBindingError):
                binding.retrieve_project_collection_archive(
                    project, lease, jump, far, pin, plan,
                    root / plan.archive_name, now=NOW,
                    runner=lambda argv: seen.append(argv), timeout=10,
                )
            self.assertEqual([], seen)
            self.assertFalse((root / plan.archive_name).exists())

    def test_project_global_or_csv_symlink_ancestor_refuses_before_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root)
            real = root / "real"
            project.rename(real)
            project.symlink_to(real, target_is_directory=True)
            discovery = subprocess.run([
                sys.executable, "-B", str(Path(__file__).resolve().parents[1]
                                           / "tools/ufm-discover.py"),
                "--project", str(project), "--leases", str(lease),
            ], text=True, capture_output=True, check=False)
            self.assertNotEqual(0, discovery.returncode)
            self.assertEqual("", discovery.stdout)
            seen: list[list[str]] = []
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_project_management_identity(
                    project, lease, jump, far, pin, now=NOW,
                    runner=lambda argv: seen.append(argv), timeout=10,
                )
            self.assertEqual([], seen)

    def test_malformed_global_is_sanitized_before_any_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root)
            (project / "01-global.yaml").write_text("servers: [SYNTHETIC-PRIVATE-PATH-TOKEN\n")
            seen: list[list[str]] = []
            with self.assertRaises(binding.IdentityBindingError) as caught:
                binding.verify_project_management_identity(
                    project, lease, jump, far, pin, now=NOW,
                    runner=lambda argv: seen.append(argv), timeout=10,
                )
            self.assertNotIn("SYNTHETIC-PRIVATE-PATH-TOKEN", str(caught.exception))
            self.assertEqual([], seen)

    def test_project_caller_refuses_missing_no_follow_capability_before_remote(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root)
            seen: list[list[str]] = []
            with mock.patch.object(binding.os, "O_NOFOLLOW", 0):
                with self.assertRaises(binding.IdentityBindingError):
                    binding.retrieve_project_collection_archive(
                        project, lease, jump, far, pin, plan,
                        root / plan.archive_name, now=NOW,
                        runner=lambda argv: seen.append(argv), timeout=10,
                    )
            self.assertEqual([], seen)
            self.assertFalse((root / plan.archive_name).exists())

    def test_formal_retrieval_caller_requires_fresh_pinned_lease_and_remote_identity(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        payload = _archive(b"synthetic-link-data\n")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root)
            seen: list[list[str]] = []
            digest = hashlib.sha256(payload).hexdigest()

            def runner(argv):
                seen.append(argv)
                if argv[0] == "scp":
                    Path(argv[-1]).write_bytes(payload)
                    return transport.CommandResult(0, "", "")
                remote = argv[-1]
                if remote == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if "-j link show dev eno8303" in remote:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": NODES[0].management_mac,
                    }]), "")
                if "-j address show dev eno8303" in remote:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "addr_info": [{
                            "family": "inet", "local": NODES[0].address,
                        }],
                    }]), "")
                if "sha256sum" in remote:
                    return transport.CommandResult(
                        0, f"{digest}  {plan.ufm_remote_path}\n", "")
                if "test -f" in remote:
                    return transport.CommandResult(0, "", "")
                self.fail(f"unexpected synthetic command: {remote}")

            destination = root / plan.archive_name
            with self.assertRaises(binding.IdentityBindingError):
                binding.retrieve_project_collection_archive(
                    project, lease, jump, far, "0" * 64,
                    plan, destination, now=NOW, runner=runner, timeout=10,
                )
            self.assertEqual([], seen)
            self.assertFalse(destination.exists())
            self.assertEqual(destination, binding.retrieve_project_collection_archive(
                project, lease, jump, far, pin,
                plan, destination, now=NOW, runner=runner, timeout=10,
            ))
            self.assertEqual(payload, destination.read_bytes())
            self.assertEqual(["ssh", "ssh", "ssh", "ssh", "ssh", "scp"],
                             [argv[0] for argv in seen])
            self.assertFalse(any("*" in token for argv in seen for token in argv))

    def test_lease_mac_mismatch_never_dispatches_archive_probe(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            seen: list[list[str]] = []
            def wrong_mac(argv):
                seen.append(argv)
                if argv[-1] == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if "-j link show dev eno8303" in argv[-1]:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": "02:00:00:00:00:99",
                    }]), "")
                self.fail("archive command must not run after identity mismatch")
            with self.assertRaises(binding.IdentityBindingError):
                binding.retrieve_bound_collection_archive(
                    NODES, lease, jump, far, "eno8303", pin,
                    plan, root / plan.archive_name, now=NOW, runner=wrong_mac,
                    timeout=10,
                )
            self.assertEqual(2, len(seen))
            self.assertFalse((root / plan.archive_name).exists())

    def test_host_pin_change_after_ssh_observation_blocks_archive_probe(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            seen: list[list[str]] = []

            def rebind(argv):
                seen.append(argv)
                if argv[-1] == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if "-j link show dev eno8303" in argv[-1]:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": NODES[0].management_mac,
                    }]), "")
                if "-j address show dev eno8303" in argv[-1]:
                    known.write_text(known.read_text() + "# changed after SSH\n")
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "addr_info": [{
                            "family": "inet", "local": NODES[0].address,
                        }],
                    }]), "")
                self.fail("archive probe must not follow a changed host-key pin")

            with self.assertRaises(transport.TransportError):
                binding.retrieve_bound_collection_archive(
                    NODES, lease, jump, far, "eno8303", pin,
                    plan, root / plan.archive_name, now=NOW, runner=rebind,
                    timeout=10,
                )
            self.assertEqual(3, len(seen))
            self.assertFalse((root / plan.archive_name).exists())

    def test_project_csv_change_after_ssh_observation_blocks_archive_probe(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root)
            seen: list[list[str]] = []

            def rebind(argv):
                seen.append(argv)
                if argv[-1] == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if "-j link show dev eno8303" in argv[-1]:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": NODES[0].management_mac,
                    }]), "")
                if "-j address show dev eno8303" in argv[-1]:
                    csv_path = project / "02-devices_config.csv"
                    csv_path.write_text(csv_path.read_text().replace(
                        "02:00:00:00:00:21", "02:00:00:00:00:99"))
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "addr_info": [{
                            "family": "inet", "local": NODES[0].address,
                        }],
                    }]), "")
                self.fail("archive probe must not follow changed project intent")

            with self.assertRaises(transport.TransportError):
                binding.retrieve_project_collection_archive(
                    project, lease, jump, far, pin, plan,
                    root / plan.archive_name, now=NOW, runner=rebind, timeout=10,
                )
            self.assertEqual(3, len(seen))
            self.assertFalse((root / plan.archive_name).exists())

    def test_project_source_change_during_copy_cannot_publish_final_archive(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        payload = _archive(b"synthetic-link-data\n")
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, known, jump, far, pin = make_site(root)
            project = write_project(root)
            seen: list[list[str]] = []

            def change_during_copy(argv):
                seen.append(argv)
                if argv[0] == "scp":
                    Path(argv[-1]).write_bytes(payload)
                    csv_path = project / "02-devices_config.csv"
                    csv_path.write_text(csv_path.read_text().replace(
                        "02:00:00:00:00:21", "02:00:00:00:00:99"))
                    return transport.CommandResult(0, "", "")
                remote = argv[-1]
                if remote == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if "-j link show dev eno8303" in remote:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": NODES[0].management_mac,
                    }]), "")
                if "-j address show dev eno8303" in remote:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "addr_info": [{
                            "family": "inet", "local": NODES[0].address,
                        }],
                    }]), "")
                if "sha256sum" in remote:
                    return transport.CommandResult(
                        0, f"{digest}  {plan.ufm_remote_path}\n", "")
                if "test -f" in remote:
                    return transport.CommandResult(0, "", "")
                self.fail(f"unexpected synthetic command: {remote}")

            destination = root / plan.archive_name
            with self.assertRaises(transport.TransportError):
                binding.retrieve_project_collection_archive(
                    project, lease, jump, far, pin, plan, destination,
                    now=NOW, runner=change_during_copy, timeout=10,
                )
            self.assertEqual(["ssh", "ssh", "ssh", "ssh", "ssh", "scp"],
                             [argv[0] for argv in seen])
            self.assertFalse(destination.exists())

    def test_lease_expiring_during_exact_copy_cannot_publish_final_archive(self):
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        payload = _archive(b"synthetic-link-data\n")
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = make_site(root)
            project = write_project(root)
            seen: list[list[str]] = []
            current = [NOW]

            def copy_past_lease(argv):
                seen.append(argv)
                if argv[0] == "scp":
                    Path(argv[-1]).write_bytes(payload)
                    current[0] = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
                    return transport.CommandResult(0, "", "")
                remote = argv[-1]
                if remote == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if "-j link show dev eno8303" in remote:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "address": NODES[0].management_mac,
                    }]), "")
                if "-j address show dev eno8303" in remote:
                    return transport.CommandResult(0, json.dumps([{
                        "ifname": "eno8303", "addr_info": [{
                            "family": "inet", "local": NODES[0].address,
                        }],
                    }]), "")
                if "sha256sum" in remote:
                    return transport.CommandResult(
                        0, f"{digest}  {plan.ufm_remote_path}\n", "")
                if "test -f" in remote:
                    return transport.CommandResult(0, "", "")
                self.fail(f"unexpected synthetic command: {remote}")

            destination = root / plan.archive_name
            with self.assertRaises(transport.TransportError):
                binding.retrieve_project_collection_archive(
                    project, lease, jump, far, pin, plan, destination,
                    now=NOW, clock=lambda: current[0],
                    runner=copy_past_lease, timeout=10,
                )
            self.assertEqual(["ssh", "ssh", "ssh", "ssh", "ssh", "scp"],
                             [argv[0] for argv in seen])
            self.assertFalse(destination.exists())

    def _retrieval_runner(self, plan, payload, seen, copied, *, on_copy=None, host_after_copy=None,
                          digest_after_copy=None):
        """Synthetic SSH/scp service for one exact archive; once the copy ran, the node may answer with another
        hostname and the remote archive with another digest. Unexpected commands are recorded on
        runner.unexpected (a failure raised here could be turned into a refusal by the binding check)."""
        digest = hashlib.sha256(payload).hexdigest()
        unexpected: list[str] = []

        def runner(argv):
            seen.append(argv)
            if argv[0] == "scp":
                Path(argv[-1]).write_bytes(payload)
                copied[0] = True
                if on_copy is not None:
                    on_copy()
                return transport.CommandResult(0, "", "")
            remote = argv[-1]
            if remote == "hostname":
                host = host_after_copy if copied[0] and host_after_copy else "EXAMPLE-UFM01"
                return transport.CommandResult(0, host + "\n", "")
            if "-j link show dev eno8303" in remote:
                return transport.CommandResult(0, json.dumps([{
                    "ifname": "eno8303", "address": NODES[0].management_mac,
                }]), "")
            if "-j address show dev eno8303" in remote:
                return transport.CommandResult(0, json.dumps([{
                    "ifname": "eno8303", "addr_info": [{
                        "family": "inet", "local": NODES[0].address,
                    }],
                }]), "")
            if "sha256sum" in remote:
                value = digest_after_copy if copied[0] and digest_after_copy else digest
                return transport.CommandResult(0, f"{value}  {plan.ufm_remote_path}\n", "")
            if "test -f" in remote:
                return transport.CommandResult(0, "", "")
            unexpected.append(remote)
            return transport.CommandResult(2, "", "unexpected synthetic command")

        runner.unexpected = unexpected
        return runner

    def test_producer_pinned_retrieval_reobserves_the_node_after_the_copy(self):
        # Moved from the retired test_ufm_remote_producer_workflow (7d5518d:32-162, phases "stable",
        # "node-changed-during-copy" and "changed-after-copy"; REQ7 retirement batch 2, 2026-10-24). With an
        # approved producer digest the formal caller hands the digest to the transport, which reads the remote
        # digest again after the exact copy, and observes the SSH node again before publication; a node or an
        # archive that changed during the copy publishes nothing. The retired tools/ufm_remote_producer.py was
        # the only caller with a digest.
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        payload = _archive(b"synthetic-link-data\n")
        digest = hashlib.sha256(payload).hexdigest()
        phases = {
            "stable": {},
            "node-changed-during-copy": {"host_after_copy": "EXAMPLE-UFM02"},
            "digest-changed-after-copy": {"digest_after_copy": hashlib.sha256(b"replaced archive").hexdigest()},
        }
        for phase, change in phases.items():
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                lease, _known, jump, far, pin = make_site(root)
                project = write_project(root)
                seen: list[list[str]] = []
                copied = [False]
                runner = self._retrieval_runner(plan, payload, seen, copied, **change)
                destination = root / plan.archive_name
                if phase == "stable":
                    self.assertEqual(destination, binding.retrieve_project_collection_archive(
                        project, lease, jump, far, pin, plan, destination,
                        now=NOW, clock=lambda: NOW, runner=runner, timeout=10,
                        expected_sha256=digest,
                    ))
                    self.assertEqual(payload, destination.read_bytes())
                    after_copy = [argv[-1] for argv in seen[[argv[0] for argv in seen].index("scp") + 1:]]
                    self.assertIn("hostname", after_copy, "the node is observed again after the copy")
                    self.assertTrue(any("sha256sum" in command for command in after_copy),
                                    "the remote digest is read again after the copy")
                else:
                    with self.assertRaises((transport.TransportError, binding.IdentityBindingError)):
                        binding.retrieve_project_collection_archive(
                            project, lease, jump, far, pin, plan, destination,
                            now=NOW, clock=lambda: NOW, runner=runner, timeout=10,
                            expected_sha256=digest,
                        )
                    self.assertTrue(copied[0], "the copy ran; a check after it refused publication")
                    self.assertFalse(destination.exists())
                self.assertEqual([], runner.unexpected)

    def test_formal_retrieval_rechecks_lease_and_host_pin_after_the_copy(self):
        # Moved from the retired test_ufm_remote_producer_workflow (7d5518d:32-162, phases
        # "lease-changed-during-copy" and "host-pin-changed-during-copy"; REQ7 retirement batch 2, review B1).
        # Without a producer digest nothing re-observes the node, so the lease and known-hosts byte rechecks
        # of the binding check before publication are the only guards after the copy.
        plan = collection.collection_plan("iblinkinfo", RUN_ID)
        payload = _archive(b"synthetic-link-data\n")
        for phase in ("lease-changed-during-copy", "host-pin-changed-during-copy"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                lease, known, jump, far, pin = make_site(root)
                project = write_project(root)
                seen: list[list[str]] = []
                copied = [False]

                def change(phase=phase, lease=lease, known=known):
                    if phase == "lease-changed-during-copy":
                        lease.write_text("lease 192.0.2.21 { binding state free; }\n")
                    else:
                        known.write_text(known.read_text() + "# changed during copy\n")

                runner = self._retrieval_runner(plan, payload, seen, copied, on_copy=change)
                destination = root / plan.archive_name
                with self.assertRaises((transport.TransportError, binding.IdentityBindingError)):
                    binding.retrieve_project_collection_archive(
                        project, lease, jump, far, pin, plan, destination,
                        now=NOW, clock=lambda: NOW, runner=runner, timeout=10,
                    )
                self.assertTrue(copied[0], "the copy ran; the recheck before publication refused it")
                self.assertFalse(destination.exists())
                self.assertEqual([], [path.name for path in root.iterdir() if path.name.startswith(".ufm-")],
                                 "no partial archive is left next to the destination")
                self.assertEqual([], runner.unexpected)


if __name__ == "__main__":
    unittest.main()
