#!/usr/bin/env python3
"""Synthetic, independently expected UFM management-identity contracts."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from infra import ufm_jump_transport as transport
from test_cases.test_ufm_input_contract import lease_block
from tools.ufm_input_contract import UfmNode
from tools import ufm_identity_binding as binding


NOW = dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc)
NODES = (
    UfmNode("EXAMPLE-UFM01", "192.0.2.21", "02:00:00:00:00:21", "192.0.2.0/24"),
    UfmNode("EXAMPLE-UFM02", "192.0.2.22", "02:00:00:00:00:22", "192.0.2.0/24"),
)


def make_site(root: Path):
    lease = root / "synthetic.leases"
    lease.write_text("".join(lease_block(n.address, n.management_mac) for n in NODES))
    known = root / "known_hosts"
    known.write_text("jump.example.invalid ssh-ed25519 c3ludGhldGljLWtleQ==\n"
                     "192.0.2.21 ssh-ed25519 c3ludGhldGljLWtleQ==\n"
                     "192.0.2.22 ssh-ed25519 c3ludGhldGljLWtleQ==\n")
    known.chmod(0o600)
    jump = transport.JumpEndpoint("jump.example.invalid", "synthetic", known)
    far = transport.BoundFarEndpoint("192.0.2.21", "synthetic", "declared", jump)
    pin = hashlib.sha256(known.read_bytes()).hexdigest()
    return lease, known, jump, far, pin


class UfmIdentityBindingTests(unittest.TestCase):
    def test_malformed_producer_digest_rejects_before_pinned_ssh(self):
        from tools.ufm_collection_contract import collection_plan

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            lease, _known, jump, far, pin = self._site(root)
            seen = []
            with self.assertRaises(binding.IdentityBindingError):
                binding.retrieve_bound_collection_archive(
                    NODES, lease, jump, far, "eno8303", pin,
                    collection_plan("iblinkinfo", "20260926-0315-air-0123456789abcdef"),
                    root / "iblinkinfo_20260926-0315-air-0123456789abcdef.tar.gz",
                    timeout=5, now=NOW, expected_sha256="X" * 64,
                    runner=lambda command: seen.append(command),
                )
            self.assertEqual([], seen)

    def _site(self, root: Path):
        return make_site(root)

    def _runner(self, seen: list[list[str]], *, hostname="EXAMPLE-UFM01",
                mac="02:00:00:00:00:21", address="192.0.2.21"):
        def run(argv: list[str]):
            seen.append(argv)
            if argv[-1] == "hostname":
                return transport.CommandResult(0, hostname + "\n", "")
            if "-j link show dev eno8303" in argv[-1]:
                return transport.CommandResult(0, json.dumps([{
                    "ifname": "eno8303", "address": mac,
                }]), "")
            if "-j address show dev eno8303" in argv[-1]:
                return transport.CommandResult(0, json.dumps([{
                    "ifname": "eno8303", "addr_info": [{
                        "family": "inet", "local": address,
                    }],
                }]), "")
            self.fail("unexpected remote identity command")
        return run

    def test_pinned_current_lease_and_authenticated_remote_observation_bind_one_node(self):
        with tempfile.TemporaryDirectory() as directory:
            lease, known, jump, far, pin = self._site(Path(directory).resolve())
            seen: list[list[str]] = []
            result = binding.verify_management_identity(
                NODES, lease, jump, far, "eno8303", pin, now=NOW,
                runner=self._runner(seen), timeout=5,
            )
            self.assertEqual(("EXAMPLE-UFM01", "192.0.2.21", "02:00:00:00:00:21"),
                             (result.hostname, result.address, result.management_mac))
            self.assertFalse(result.license_mac_verified)
            self.assertEqual(3, len(seen))
            self.assertTrue(all("StrictHostKeyChecking=yes" in argv for argv in seen))
            self.assertTrue(all("UpdateHostKeys=no" in argv for argv in seen))
            self.assertTrue(all("ProxyCommand=" in " ".join(argv) for argv in seen))
            self.assertTrue(all("192.0.2.21" in " ".join(argv) for argv in seen))

    def test_unpinned_or_changed_host_keys_and_stale_lease_refuse_before_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            lease, known, jump, far, pin = self._site(Path(directory).resolve())
            seen: list[list[str]] = []
            for bad_pin in ("0" * 64, "", pin.upper()):
                with self.subTest(pin=bad_pin), self.assertRaises(binding.IdentityBindingError):
                    binding.verify_management_identity(
                        NODES, lease, jump, far, "eno8303", bad_pin, now=NOW,
                        runner=self._runner(seen), timeout=5,
                    )
            self.assertEqual([], seen)
            known.write_text(known.read_text() + "192.0.2.99 ssh-ed25519 c3ludGhldGljLWtleQ==\n")
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_management_identity(
                    NODES, lease, jump, far, "eno8303", pin, now=NOW,
                    runner=self._runner(seen), timeout=5,
                )
            self.assertEqual([], seen)
            pin = hashlib.sha256(known.read_bytes()).hexdigest()
            lease.write_text(lease_block(NODES[0].address, NODES[0].management_mac,
                                         end="2026/09/25 00:00:00")
                             + lease_block(NODES[1].address, NODES[1].management_mac))
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_management_identity(
                    NODES, lease, jump, far, "eno8303", pin, now=NOW,
                    runner=self._runner(seen), timeout=5,
                )
            self.assertEqual([], seen)

    def test_remote_self_report_must_match_independent_csv_and_lease(self):
        for changed in ({"hostname": "EXAMPLE-OTHER"},
                        {"mac": "02:00:00:00:00:99"},
                        {"address": "192.0.2.99"}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                lease, known, jump, far, pin = self._site(Path(directory).resolve())
                with self.assertRaises(binding.IdentityBindingError):
                    binding.verify_management_identity(
                        NODES, lease, jump, far, "eno8303", pin, now=NOW,
                        runner=self._runner([], **changed), timeout=5,
                    )

    def test_wrong_endpoint_or_missing_pinned_entry_never_sends_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            lease, known, jump, far, pin = self._site(Path(directory).resolve())
            wrong = transport.BoundFarEndpoint("192.0.2.99", "synthetic", "declared", jump)
            seen: list[list[str]] = []
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_management_identity(
                    NODES, lease, jump, wrong, "eno8303", pin, now=NOW,
                    runner=self._runner(seen), timeout=5,
                )
            self.assertEqual([], seen)
            known.write_text("jump.example.invalid ssh-ed25519 c3ludGhldGljLWtleQ==\n")
            pin = hashlib.sha256(known.read_bytes()).hexdigest()
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_management_identity(
                    NODES, lease, jump, far, "eno8303", pin, now=NOW,
                    runner=self._runner(seen), timeout=5,
                )
            self.assertEqual([], seen)

    def test_symlinked_lease_or_host_key_ancestor_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real"
            real.mkdir()
            lease, known, jump, far, pin = self._site(real)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            seen: list[list[str]] = []
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_management_identity(
                    NODES, alias / lease.name, jump, far, "eno8303", pin,
                    now=NOW, runner=self._runner(seen), timeout=5,
                )
            aliased_jump = transport.JumpEndpoint(
                jump.host, jump.user, alias / known.name,
            )
            aliased_far = transport.BoundFarEndpoint(
                far.host, far.user, far.identity_evidence, aliased_jump,
            )
            with self.assertRaises(binding.IdentityBindingError):
                binding.verify_management_identity(
                    NODES, lease, aliased_jump, aliased_far, "eno8303", pin,
                    now=NOW, runner=self._runner(seen), timeout=5,
                )
            self.assertEqual([], seen)

    def test_missing_platform_no_follow_or_directory_flag_refuses_before_ssh(self):
        for missing in ("O_NOFOLLOW", "O_DIRECTORY"):
            with self.subTest(flag=missing), tempfile.TemporaryDirectory() as directory:
                lease, known, jump, far, pin = self._site(Path(directory).resolve())
                seen: list[list[str]] = []
                with mock.patch.object(binding.os, missing, 0):
                    with self.assertRaises(binding.IdentityBindingError):
                        binding.verify_management_identity(
                            NODES, lease, jump, far, "eno8303", pin, now=NOW,
                            runner=self._runner(seen), timeout=5,
                        )
                self.assertEqual([], seen)

    def test_operator_interrupt_is_not_relabelled_as_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            lease, known, jump, far, pin = self._site(Path(directory).resolve())
            def interrupted(_argv):
                raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                binding.verify_management_identity(
                    NODES, lease, jump, far, "eno8303", pin, now=NOW,
                    runner=interrupted, timeout=5,
                )


if __name__ == "__main__":
    unittest.main()
