#!/usr/bin/env python3
"""Contracts for the read-only Ubuntu management-VM acceptance runner."""

from __future__ import annotations

import hashlib
import base64
import importlib.util
import ipaddress
import json
import io
import os
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "test_cases/run_vm_validation.py"
SPEC = importlib.util.spec_from_file_location("vm_validation_runner", SCRIPT)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VM
SPEC.loader.exec_module(VM)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@contextmanager
def actual_deployment_contract_fixture(root: Path):
    """Give the VM CLI real source at --root, isolated from producer imports.

    This is fixture setup, not a mock of the actual-root/source gate. The
    LOAD producer has already run before entry; its repo tools modules are
    restored afterward, exactly as a separate VM verifier process would be.
    """
    canonical = root.resolve(strict=True)
    tools = canonical / "tools"
    tools.mkdir(mode=0o700, exist_ok=True)
    tools.chmod(0o700)
    # A private regular package prevents Python namespace-package search
    # from merging this actual deployment with repo tools on sys.path.
    package = tools / "__init__.py"
    package.write_bytes(b"")
    package.chmod(0o600)
    for name in ("project_contract.py", "generation_report.py", "ssh_key_preparation.py"):
        destination = tools / name
        destination.write_bytes((ROOT / "tools" / name).read_bytes())
        destination.chmod(0o600)
    previous_path = sys.path[:]
    previous_modules = {name: module for name, module in sys.modules.copy().items()
                        if name == "tools" or name.startswith("tools.")}
    try:
        for name in tuple(sys.modules):
            if name == "tools" or name.startswith("tools."):
                sys.modules.pop(name, None)
        sys.path.insert(0, str(canonical))
        yield
    finally:
        sys.path[:] = previous_path
        for name in tuple(sys.modules):
            if name == "tools" or name.startswith("tools."):
                sys.modules.pop(name, None)
        sys.modules.update(previous_modules)


class VmCopiedDeploymentRootContracts(unittest.TestCase):
    def test_actual_root_not_copied_validator_location_drives_contract(self):
        with mock.patch.object(VM, "_VALIDATION_DEPLOYMENT_ROOT", ROOT), \
                mock.patch.object(VM, "__file__", "/tmp/private-copied-validator.py"):
            module = VM.deployment_project_contract()
        self.assertEqual(ROOT / "tools/project_contract.py", Path(module.__file__).resolve())

    def test_foreign_cached_contract_is_not_reused(self):
        with mock.patch.object(VM, "_VALIDATION_DEPLOYMENT_ROOT", ROOT), \
                mock.patch.dict(sys.modules, {
                    "tools.project_contract": type("Foreign", (), {"__file__": "/tmp/foreign-project-contract.py"})(),
                }):
            with self.assertRaisesRegex(ValueError, "foreign cached"):
                VM.deployment_project_contract()

    def test_missing_actual_root_contract_does_not_fallback_repo(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value).resolve()
            (root / "tools").mkdir(mode=0o700)
            with mock.patch.object(VM, "_VALIDATION_DEPLOYMENT_ROOT", root):
                with self.assertRaises((ValueError, OSError)):
                    VM.deployment_project_contract()

    def test_main_restores_import_root_modules_and_path_after_exception(self):
        sentinel = type("Original", (), {})()
        original_path = sys.path[:]
        def failed_main(argv):
            VM._VALIDATION_DEPLOYMENT_ROOT = Path("/tmp/private-other-root")
            sys.path.insert(0, "/tmp/private-other-root")
            sys.modules["tools.independent-test-private-probe"] = sentinel
            raise RuntimeError("independent verifier early exception")
        with mock.patch.object(VM, "_VALIDATION_DEPLOYMENT_ROOT", ROOT), \
                mock.patch.object(VM, "_main_bound_deployment", side_effect=failed_main):
            with self.assertRaisesRegex(RuntimeError, "independent verifier"):
                VM.main([])
            self.assertEqual(ROOT, VM._VALIDATION_DEPLOYMENT_ROOT)
            self.assertEqual(original_path, sys.path)
            self.assertNotIn("tools.independent-test-private-probe", sys.modules)


class VmRegularByteReaderRaceContracts(unittest.TestCase):
    @staticmethod
    @contextmanager
    def owned_fifo_rebind(path, owned_root):
        """Inject one real owned FIFO, but never issue a blocking syscall.

        Missing NONBLOCK raises an independent model error before open; this
        deliberately cannot count as the expected production ValueError.
        """
        path, owned_root = Path(path), Path(owned_root).resolve(strict=True)
        if path.resolve(strict=True) != path or not path.is_relative_to(owned_root):
            raise AssertionError("FIFO injection requires the owned private fixture")
        held = path.with_name("independent-original-" + path.name)
        if held.exists() or held.is_symlink():
            raise AssertionError("independent held preimage must not preexist")
        namespace = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        original_open, original_close = os.open, os.close
        attempts, opened, closed, injected = [], [], [], []
        def open_reader(name, flags, *args, **kwargs):
            if Path(name) == path:
                attempts.append(flags)
                if not injected:
                    path.rename(held)
                    os.mkfifo(path, 0o600)
                    injected.append(path.lstat())
                if not flags & os.O_NONBLOCK:
                    raise RuntimeError("independent FIFO model: blocking open would hang")
                descriptor = original_open(name, flags, *args, **kwargs)
                opened.append(descriptor)
                return descriptor
            return original_open(name, flags, *args, **kwargs)
        def close_reader(descriptor):
            if descriptor in opened: closed.append(descriptor)
            original_close(descriptor)
        namespace.open, namespace.close = open_reader, close_reader
        try:
            with mock.patch.object(VM, "os", namespace):
                yield attempts, opened, closed, injected
        finally:
            # Only exact recorded owned objects/FDs may be cleaned. A changed
            # unknown name must remain untouched and fail the fixture closed.
            for descriptor in opened:
                if descriptor not in closed: original_close(descriptor)
            if injected:
                named = path.lstat()
                before = injected[0]
                if (named.st_dev, named.st_ino, named.st_mode) != (before.st_dev, before.st_ino, before.st_mode):
                    raise AssertionError("owned FIFO name changed; refuse cleanup")
                path.unlink()
                held.rename(path)

    def test_regular_byte_reader_fifo_rebind_is_nonblocking_and_closes_rejected_fd(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value).resolve(strict=True)
            path = root / "independent-reader-input"
            path.write_bytes(b"independent regular bytes before open\n")
            with self.owned_fifo_rebind(path, root) as (attempts, opened, closed, injected):
                with self.assertRaisesRegex(ValueError, "打开期间文件发生变化"):
                    VM.read_regular_bytes(path)
                self.assertEqual(1, len(attempts)); self.assertTrue(attempts[0] & os.O_NONBLOCK)
                self.assertEqual(1, len(opened)); self.assertEqual(opened, closed)
                self.assertEqual(1, len(injected))
            self.assertEqual(b"independent regular bytes before open\n", path.read_bytes())

    def test_regular_byte_reader_nonblock_preserves_regular_bytes_and_limits(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value).resolve(strict=True)
            path = root / "independent-reader-input"
            payload = b"independent ordinary regular bytes\n"
            path.write_bytes(payload)
            self.assertEqual(payload, VM.read_regular_bytes(path, max_bytes=len(payload)))
            with self.assertRaisesRegex(ValueError, "bytes"):
                VM.read_regular_bytes(path, max_bytes=len(payload) - 1)


class VmCumulusUpgradePolicyContracts(unittest.TestCase):
    @staticmethod
    def _independent_template_contract():
        # This minimal expected executable body is authored independently;
        # do not invoke LOAD's renderer or candidate normalizer to create it.
        return (
            b'#!/bin/bash\nset -euo pipefail\n'
            b'ZTP_SERVER="http://127.0.0.1"\nZTP_SERVER_HOST="127.0.0.1"\n'
            b'ZTP_URL_PREFIX="/ztp"\nMANUAL_ZTP_OOB_URL=""\n'
            b'MANUAL_ZTP_OOBOFOOB_URL=""\nTARGET_CL_VER="0.0.0"\n'
            b'ZTP_UPGRADE_ENABLED="false"\nPUBKEY_PATHS=(\n'
            b'    "${ZTP_URL_PREFIX}/config/publickey/laptop.pub"\n'
            b'    "${ZTP_URL_PREFIX}/config/publickey/mgmt-server.pub"\n)\n'
            b'if [[ "${RUN_VER}" != "${TARGET_CL_VER}" && "${ZTP_UPGRADE_ENABLED}" == "true" ]];then\n'
            b'    onie-install -fa -i "${USE_IMG_URL}"\nfi\n'
        )

    def test_bootstrap_whole_template_contract_accepts_only_exact_literal_render_slots(self):
        template = self._independent_template_contract()
        rendered = template.replace(b'http://127.0.0.1', b'http://192.0.2.40:8080')
        rendered = rendered.replace(b'ZTP_SERVER_HOST="127.0.0.1"', b'ZTP_SERVER_HOST="192.0.2.40"')
        rendered = rendered.replace(b'TARGET_CL_VER="0.0.0"', b'TARGET_CL_VER="5.15.0"')
        rendered = rendered.replace(b'ZTP_UPGRADE_ENABLED="false"', b'ZTP_UPGRADE_ENABLED="true"')
        rendered = rendered.replace(b'/config/publickey/laptop.pub', b'/config/publickey/_operator-key.pub')
        VM.qualify_bootstrap_template_body(rendered, template)

    def test_bootstrap_whole_template_contract_rejects_body_and_nonexecuted_or_expanding_slots(self):
        template = self._independent_template_contract()
        policy = b'ZTP_UPGRADE_ENABLED="false"\n'
        for fault, candidate in (
            ("upgrade-guard-removed", template.replace(b' && "${ZTP_UPGRADE_ENABLED}" == "true"', b'')),
            ("extra-image-command", template + b'onie-install -fa -i "${USE_IMG_URL}"\n'),
            ("nonexecuted-policy", template.replace(policy, b"cat <<'INDEPENDENT_POLICY'\n" + policy + b'INDEPENDENT_POLICY\n')),
            ("expanding-url", template.replace(b'MANUAL_ZTP_OOB_URL=""', b'MANUAL_ZTP_OOB_URL="$(independent-probe)"')),
            ("key-block-command", template.replace(b'    "${ZTP_URL_PREFIX}/config/publickey/laptop.pub"', b'    "$(independent-probe)"')),
            ("duplicate-policy", template + policy),
        ):
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):
                    VM.qualify_bootstrap_template_body(candidate, template)

    def test_exact_false_and_true_are_the_only_known_policies(self):
        self.assertIs(False, VM.strict_bootstrap_upgrade_policy(b'#!/bin/bash\nZTP_UPGRADE_ENABLED="false"\n'))
        self.assertIs(True, VM.strict_bootstrap_upgrade_policy(b'#!/bin/bash\nZTP_UPGRADE_ENABLED="true"\n'))

    def test_missing_duplicate_export_and_expression_policies_fail_closed(self):
        for payload in (
            b'#!/bin/bash\n# ZTP_UPGRADE_ENABLED="false"\n',
            b'ZTP_UPGRADE_ENABLED="false"\nZTP_UPGRADE_ENABLED="false"\n',
            b'ZTP_UPGRADE_ENABLED="true"\nZTP_UPGRADE_ENABLED="false"\n',
            b'export ZTP_UPGRADE_ENABLED="false"\n',
            b' ZTP_UPGRADE_ENABLED="false"\n',
            b'ZTP_UPGRADE_ENABLED = "false"\n',
            b'ZTP_UPGRADE_ENABLED=0\n',
            b'ZTP_UPGRADE_ENABLED="FALSE"\n',
            b'ZTP_UPGRADE_ENABLED="false" # guessed waiver\n',
            b'\xffZTP_UPGRADE_ENABLED="false"\n',
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    VM.strict_bootstrap_upgrade_policy(payload)


class VmNetworkAcceptanceTests(unittest.TestCase):
    def test_one_nic_cannot_match_two_dhcp_shared_networks(self) -> None:
        subnets = (
            VM.DhcpSubnet(
                "direct-one", ipaddress.ip_network("192.0.2.0/25"),
                ipaddress.ip_address("192.0.2.100"),
            ),
            VM.DhcpSubnet(
                "relay-only", ipaddress.ip_network("198.51.100.0/25"),
                None,
            ),
            VM.DhcpSubnet(
                "direct-two", ipaddress.ip_network("203.0.113.0/25"),
                ipaddress.ip_address("203.0.113.100"),
            ),
        )
        collapsed = {
            "enp0s10": {
                ipaddress.ip_address("192.0.2.100"),
                ipaddress.ip_address("203.0.113.100"),
            },
        }
        self.assertEqual(
            {"enp0s10": ("direct-one", "direct-two")},
            VM.shared_network_conflicts(subnets, collapsed),
        )

        split = {
            "enp0s10": {ipaddress.ip_address("203.0.113.100")},
            "enp0s11": {ipaddress.ip_address("192.0.2.100")},
        }
        self.assertEqual({}, VM.shared_network_conflicts(subnets, split))
        self.assertEqual(
            {
                "192.0.2.100": ("enp0s11",),
                "203.0.113.100": ("enp0s10",),
            },
            VM.service_ip_assignments(subnets, split),
        )


class VmReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "DAY0-Prepare/customer"
        self.project.mkdir(parents=True)
        self.payloads = {
            "global": (
                "01-global.yaml",
                b"schema_version: 2\ncommon:\n  mgmt:\n"
                b"    dhcp-server:\n      status: enabled\n",
            ),
            "devices": ("02-devices_config.csv", b"hostname,type\none,eth\n"),
            "subnet": (
                "02-dhcp-subnet_config.csv",
                b"shared_network,subnet,netmask,range_start,range_end,routers,"
                b"ztp_service_ip,cumulus_profile,nvos_ztp\n",
            ),
            "air_topology_policy": (
                "03-air-topology-policy.json", b'{"link_rewrites":[]}\n',
            ),
            "mini_air_devices": (
                "04-air-mini-devices.txt",
                b"[minimum-required]\nborder01\n[customer-provided]\n",
            ),
            "p2p": ("p2p.xlsx", b"synthetic-p2p"),
        }
        for _label, (name, payload) in self.payloads.items():
            (self.project / name).write_bytes(payload)
        self.parent = {
            "schema_version": 1,
            "release_id": "placeholder",
            "project": "customer",
            "validation": "passed",
            "deployment_scope": "all",
            "switch_scope": "all",
            "inputs": {
                key: sha256(payload)
                for key, (_name, payload) in self.payloads.items()
            },
            "input_sources": {"p2p": {"sha256": sha256(b"synthetic-p2p")}},
            "components": {"dhcp": {
                "release_id": "legacy-dhcp", "manifest_sha256": "0" * 64,
            }},
            "inventory": [],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seal_parent(self) -> None:
        basis_keys = (
            "project", "deployment_scope", "switch_scope", "inputs",
            "input_sources", "components", "inventory",
        )
        if self.parent["schema_version"] == 2:
            basis_keys += ("dhcp_status",)
        self.parent["release_id"] = sha256(json.dumps(
            {key: self.parent[key] for key in basis_keys},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))[:20]

    @staticmethod
    def _real_load_parent(*, enabled: bool):
        """Use the real producer and its project inputs, not a VM-shaped copy."""
        from test_cases import test_load_release_transaction as release_fixture

        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        if not enabled:
            fixture.global_file.write_text(
                fixture.global_file.read_text(encoding="utf-8").replace(
                    "status: enabled", "status: disabled"
                ), encoding="utf-8",
            )
        inputs = release_fixture.LOAD.replace(
            fixture.inputs,
            settings=release_fixture.LOAD.replace(
                fixture.inputs.settings, dhcp_enabled=enabled,
            ),
        )
        parent = release_fixture.LOAD.validate_and_publish_release(
            fixture.project, inputs, publish=True,
        )
        return fixture, parent

    @staticmethod
    def _real_derived_parent():
        """Obtain a derived parent from load, without assembling its ID here."""
        from test_cases import test_load_release_transaction as release_fixture

        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        directory = Path(tempfile.mkdtemp(
            prefix=".load-inventory-", dir=fixture.project,
        ))
        directory.chmod(0o700)
        derived = directory / "02-devices_config.csv"
        derived.write_bytes(fixture.devices_file.read_bytes() + b"\n")
        derived.chmod(0o600)
        inputs = release_fixture.LOAD.replace(
            fixture.inputs, effective_devices_file=derived,
            effective_devices_sha256=sha256(derived.read_bytes()),
        )
        parent = release_fixture.LOAD.validate_and_publish_release(
            fixture.project, inputs, publish=True,
        )
        return fixture, parent, derived

    def test_real_derived_parent_binds_identity_path_and_current_bytes(self) -> None:
        fixture, parent, derived = self._real_derived_parent()
        try:
            self.assertIn("generated_inputs", parent)
            self.assertEqual([], VM.parent_release_errors(parent, "demo"))
            self.assertEqual([], VM.release_input_errors(fixture.project, parent))
            self.assertEqual(
                "enabled", VM.validated_parent_dhcp_status(fixture.project, parent),
            )

            changed_path = json.loads(json.dumps(parent))
            changed_path["generated_inputs"]["effective_devices"]["path"] = (
                "../outside/02-devices_config.csv"
            )
            self.assertTrue(VM.parent_release_errors(changed_path, "demo"))

            changed_path["release_id"] = sha256(json.dumps(
                {key: changed_path[key] for key in (
                    "project", "deployment_scope", "switch_scope", "inputs",
                    "input_sources", "components", "inventory", "dhcp_status",
                    "generated_inputs",
                )}, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))[:20]
            with self.assertRaisesRegex(ValueError, "generated|derived|路径|path"):
                VM.validated_parent_dhcp_status(fixture.project, changed_path)

            derived.write_bytes(derived.read_bytes() + b"tampered\n")
            with self.assertRaisesRegex(ValueError, "generated|derived|SHA|hash"):
                VM.validated_parent_dhcp_status(fixture.project, parent)
        finally:
            fixture.tearDown()

    def test_real_load_v2_modes_and_legacy_v1_are_strictly_distinguished(self) -> None:
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                fixture, parent = self._real_load_parent(enabled=enabled)
                try:
                    self.assertEqual(2, parent["schema_version"])
                    self.assertEqual([], VM.parent_release_errors(parent, "demo"))
                    self.assertEqual([], VM.release_input_errors(fixture.project, parent))
                    self.assertEqual(
                        "enabled" if enabled else "disabled",
                        VM.validated_parent_dhcp_status(fixture.project, parent),
                    )
                    if enabled:
                        self.assertIn("dhcp", parent["components"])
                    else:
                        self.assertNotIn("dhcp", parent["components"])
                        # Old files are not current proof when disabled.
                        (fixture.ztp / "config/isc-dhcp-server/"
                         "dhcp-release-manifest.json").write_text(
                            '{"stale":"not-current"}\n', encoding="utf-8",
                        )
                        self.assertEqual(
                            "disabled",
                            VM.validated_parent_dhcp_status(fixture.project, parent),
                        )
                    forged = dict(parent)
                    forged["dhcp_status"] = "disabled" if enabled else "enabled"
                    basis_keys = (
                        "project", "deployment_scope", "switch_scope", "inputs",
                        "input_sources", "dhcp_status", "components", "inventory",
                    )
                    forged["release_id"] = sha256(json.dumps(
                        {key: forged[key] for key in basis_keys},
                        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8"))[:20]
                    self.assertTrue(VM.parent_release_errors(forged, "demo"))
                finally:
                    fixture.tearDown()

        fixture, parent = self._real_load_parent(enabled=True)
        try:
            legacy = dict(parent)
            legacy["schema_version"] = 1
            legacy.pop("dhcp_status")
            basis_keys = (
                "project", "deployment_scope", "switch_scope", "inputs",
                "input_sources", "components", "inventory",
            )
            legacy["release_id"] = sha256(json.dumps(
                {key: legacy[key] for key in basis_keys},
                ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))[:20]
            self.assertEqual([], VM.parent_release_errors(legacy, "demo"))
            self.assertEqual(
                "enabled", VM.validated_parent_dhcp_status(fixture.project, legacy),
            )
            legacy["dhcp_status"] = "disabled"
            self.assertTrue(VM.parent_release_errors(legacy, "demo"))
            legacy.pop("dhcp_status")
            legacy["components"] = dict(legacy["components"])
            legacy["components"].pop("dhcp")
            legacy["release_id"] = sha256(json.dumps(
                {key: legacy[key] for key in basis_keys},
                ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))[:20]
            self.assertTrue(VM.parent_release_errors(legacy, "demo"))
        finally:
            fixture.tearDown()

    def test_disabled_mode_requires_current_global_hash_and_matching_status(self) -> None:
        fixture, parent = self._real_load_parent(enabled=False)
        try:
            self.assertEqual(
                "disabled", VM.validated_parent_dhcp_status(fixture.project, parent),
            )
            fixture.global_file.write_text(
                fixture.global_file.read_text(encoding="utf-8") + "# drift\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "global|hash|SHA|输入"):
                VM.validated_parent_dhcp_status(fixture.project, parent)
            fixture.global_file.write_text(
                fixture.global_file.read_text(encoding="utf-8").replace(
                    "status: disabled", "status: enabled"
                ), encoding="utf-8",
            )
            rebased = dict(parent)
            rebased["inputs"] = dict(parent["inputs"])
            rebased["inputs"]["global"] = sha256(fixture.global_file.read_bytes())
            basis_keys = (
                "project", "deployment_scope", "switch_scope", "inputs",
                "input_sources", "dhcp_status", "components", "inventory",
            )
            rebased["release_id"] = sha256(json.dumps(
                {key: rebased[key] for key in basis_keys},
                ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))[:20]
            self.assertEqual([], VM.parent_release_errors(rebased, "demo"))
            self.assertEqual([], VM.release_input_errors(fixture.project, rebased))
            with self.assertRaisesRegex(ValueError, "global|status|DHCP|输入"):
                VM.validated_parent_dhcp_status(fixture.project, rebased)

            # A self-consistent parent + input hash cannot override the
            # current global mode and suppress runtime DHCP checks.
            (fixture.project / "99-output-ztp/current-release.json").write_text(
                json.dumps(rebased), encoding="utf-8",
            )
            report = fixture.root / "vm-forged-mode-report.json"
            with mock.patch.object(
                VM, "command_result", return_value=(True, "active"),
            ), mock.patch.object(
                VM.shutil, "which", return_value="/usr/bin/mock",
            ), mock.patch.object(
                VM, "check_password_backend", return_value="test backend",
            ), mock.patch("sys.stdout", new_callable=io.StringIO):
                with actual_deployment_contract_fixture(fixture.root):
                    VM.main([
                        "demo", "--root", str(fixture.root),
                        "--expect-services", "--output", str(report),
                    ])
            findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
            self.assertTrue(any(
                item["check"] == "dhcp-mode" and item["level"] == "FAIL"
                for item in findings
            ))
            self.assertFalse(any(
                item["check"] == "release-artifacts" and item["level"] == "PASS"
                for item in findings
            ))
            self.assertTrue(any(
                item["check"] == "release-artifacts"
                and item["level"] == "FAIL"
                and "DHCP" in item["detail"]
                for item in findings
            ))
            self.assertTrue(any(
                item["check"] == "service:isc-dhcp-server"
                for item in findings
            ))
        finally:
            fixture.tearDown()

    def test_disabled_vm_service_probe_retains_apache_but_omits_dhcp_only(self) -> None:
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                fixture, parent = self._real_load_parent(enabled=enabled)
                try:
                    observed: list[tuple[str, ...]] = []

                    def offline_command(argv, **_kwargs):
                        observed.append(tuple(argv))
                        return True, "active" if "is-active" in argv else "valid"

                    def fake_which(name):
                        if name == "dhcpd":
                            return None
                        return "/usr/bin/" + name

                    report = fixture.root / "vm-report.json"
                    with mock.patch.object(
                        VM, "command_result", side_effect=offline_command,
                    ), mock.patch.object(
                        VM.shutil, "which", side_effect=fake_which,
                    ), mock.patch.object(
                        VM, "check_password_backend", return_value="test backend",
                    ), mock.patch("sys.stdout", new_callable=io.StringIO):
                        with actual_deployment_contract_fixture(fixture.root):
                            VM.main([
                                "demo", "--root", str(fixture.root),
                                "--expect-services", "--output", str(report),
                            ])
                    findings = json.loads(report.read_text(encoding="utf-8"))["findings"]
                    self.assertTrue(any(
                        item["check"] == "dhcp-mode" and item["level"] == "PASS"
                        and item["detail"] == ("global-bound enabled" if enabled else "global-bound disabled")
                        for item in findings
                    ), findings)
                    checks = {item["check"] for item in findings}
                    self.assertIn("service:apache2", checks)
                    self.assertIn("apache-config", checks)
                    self.assertEqual(enabled, "service:isc-dhcp-server" in checks)
                    self.assertEqual(enabled, "dhcpd-syntax" in checks)
                    self.assertEqual(enabled, "installed-dhcp" in checks)
                    self.assertEqual(enabled, ("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf") in observed)
                    if not enabled:
                        self.assertFalse(any(
                            item["check"] == "commands" and "dhcpd" in item["detail"]
                            for item in findings
                        ))
                finally:
                    fixture.tearDown()

    def test_full_systemd_dhcp_modes_preserve_other_active_evidence(self) -> None:
        """Only a current, trusted disabled release can omit DHCP runtime probes."""
        common_checks = {
            "source-syntax", "service:apache2", "service-enabled:apache2",
            "service-process:apache2", "apache-config", "apache-public-boundary",
            "installed-control-cgi", "http-listener", "worker:ztp-monitor",
            "worker:switch-collection", "worker:manual-ztp", "worker-scope",
            "worker-status:switch-collection", "worker-status:manual-ztp",
            "ztp-monitor-report", "http-content-plan", "http-content",
            "http-control-auth", "http-monitor-authenticated", "http-image",
            "http-deny-boundary", "http-control-cgi",
        }
        dhcp_checks = {
            "service:isc-dhcp-server", "service-enabled:isc-dhcp-server",
            "service-process:isc-dhcp-server", "dhcpd-syntax",
            "installed-dhcp", "dhcp-runtime-interfaces",
        }
        for mode in ("disabled", "enabled", "mismatched"):
            with self.subTest(mode=mode):
                fixture, parent = self._real_load_parent(enabled=mode == "enabled")
                try:
                    if mode == "mismatched":
                        # The parent is internally consistent, but its disabled
                        # claim contradicts the current, hash-bound global mode.
                        fixture.global_file.write_text(
                            fixture.global_file.read_text(encoding="utf-8").replace(
                                "status: disabled", "status: enabled"
                            ), encoding="utf-8",
                        )
                        parent = dict(parent)
                        parent["inputs"] = dict(parent["inputs"])
                        parent["inputs"]["global"] = sha256(
                            fixture.global_file.read_bytes()
                        )
                        basis_keys = (
                            "project", "deployment_scope", "switch_scope", "inputs",
                            "input_sources", "dhcp_status", "components", "inventory",
                        )
                        parent["release_id"] = sha256(json.dumps(
                            {key: parent[key] for key in basis_keys},
                            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                        ).encode("utf-8"))[:20]
                        (fixture.project / "99-output-ztp/current-release.json").write_text(
                            json.dumps(parent), encoding="utf-8",
                        )
                        self.assertEqual([], VM.parent_release_errors(parent, "demo"))
                        self.assertEqual([], VM.release_input_errors(fixture.project, parent))

                    monitor_html = fixture.root / "monitor/monitor.html"
                    monitor_html.parent.mkdir(parents=True, exist_ok=True)
                    monitor_html.write_text("offline monitor\n", encoding="utf-8")
                    public_key = fixture.ztp / "config/publickey/offline.pub"
                    public_key.parent.mkdir(parents=True, exist_ok=True)
                    public_key.write_text("ssh-ed25519 offline\n", encoding="utf-8")
                    image = fixture.ztp / "image/cumulus/offline.img"
                    image.parent.mkdir(parents=True, exist_ok=True)
                    image.write_bytes(b"offline image")
                    status_dir = fixture.root / "monitor/status"
                    status_dir.mkdir(parents=True, exist_ok=True)
                    for label in ("switch-collection", "manual-ztp"):
                        (status_dir / f"{label}.status.json").write_text(
                            json.dumps({"scope": "prod", "state": "running"}),
                            encoding="utf-8",
                        )

                    observed: list[tuple[str, ...]] = []
                    original_read = VM.read_regular_bytes

                    def offline_command(argv, **_kwargs):
                        observed.append(tuple(argv))
                        if "is-active" in argv:
                            return True, "active"
                        if "is-enabled" in argv:
                            return True, "enabled"
                        return True, "valid"

                    def offline_read(path, **kwargs):
                        if str(path).endswith("http-ztp-public-boundary.conf"):
                            return b"offline boundary"
                        if str(path) == "/etc/default/isc-dhcp-server":
                            return b'INTERFACESv4="enp0"\n'
                        return original_read(path, **kwargs)

                    report = fixture.root / "vm-full-systemd-report.json"
                    with ExitStack() as stack:
                        def patch(target, **kwargs):
                            return stack.enter_context(mock.patch.object(VM, target, **kwargs))

                        patch("command_result", side_effect=offline_command)
                        stack.enter_context(mock.patch.object(
                            VM.shutil, "which", side_effect=lambda name: "/offline/" + name,
                        ))
                        stack.enter_context(mock.patch.object(VM.os, "geteuid", return_value=0))
                        patch("source_syntax_errors", return_value=(
                            {"python": 1, "shell": 1}, [],
                        ))
                        patch("check_password_backend", return_value="offline backend")
                        patch("parse_dhcp_subnets", return_value=(VM.DhcpSubnet(
                            "direct", ipaddress.ip_network("192.0.2.0/24"),
                            ipaddress.ip_address("192.0.2.1"),
                        ),))
                        patch("local_interface_addresses", return_value={
                            "enp0": {ipaddress.ip_address("192.0.2.1")},
                        })
                        patch("read_ztp_prefix", return_value="/ztp")
                        patch("systemd_main_process", side_effect=lambda service: (
                            42, "apache2" if service == "apache2" else "dhcpd",
                        ))
                        patch("expected_apache_boundary", return_value=b"offline boundary")
                        patch("read_regular_bytes", side_effect=offline_read)
                        patch("installed_cgi_errors", return_value=[])
                        runtime_probe = patch("dhcp_runtime_interface_errors", return_value=[])
                        stack.enter_context(mock.patch.object(VM.socket, "create_connection"))
                        patch("check_worker", return_value=(True, "python --scope prod"))
                        patch("worker_command_errors", return_value=[])
                        patch("monitor_runtime_evidence", return_value="offline fresh")
                        patch("read_control_authorization", return_value="Basic offline")
                        patch("bootstrap_http_assets", return_value=())
                        patch("release_http_assets", return_value=())
                        # This is the service/HTTP evidence routing test. Its
                        # synthetic parent does not render bootstraps; declare
                        # the independent upgrade=true branch explicitly, as
                        # we do for its other offline HTTP plans. Real LOAD ->
                        # render -> policy qualification is covered separately.
                        image_policy = patch("cumulus_runtime_image_required", return_value=True)
                        get_probe = patch("verify_http_asset", return_value="offline GET")
                        denial_probe = patch("verify_http_status", return_value="offline 403")
                        patch("verify_control_auth_challenge", return_value="offline 401")
                        cgi_probe = patch("verify_control_cgi", return_value="offline CGI")
                        head_probe = patch("verify_http_head", return_value="offline HEAD")
                        stack.enter_context(mock.patch("sys.stdout", new_callable=io.StringIO))
                        with actual_deployment_contract_fixture(fixture.root):
                            VM.main([
                                "demo", "--root", str(fixture.root), "--full-systemd",
                                "--worker-scope", "prod", "--control-auth-user", "nvis",
                                "--output", str(report),
                            ])
                    payload = json.loads(report.read_text(encoding="utf-8"))
                    self.assertEqual("full-systemd", payload["validation_profile"])
                    findings = payload["findings"]
                    checks = {item["check"] for item in findings}
                    self.assertFalse(common_checks - checks, common_checks - checks)
                    passed_checks = {
                        item["check"] for item in findings if item["level"] == "PASS"
                    }
                    self.assertFalse(
                        common_checks - passed_checks, common_checks - passed_checks,
                    )
                    self.assertGreater(get_probe.call_count, 0)
                    self.assertGreater(denial_probe.call_count, 0)
                    self.assertGreater(cgi_probe.call_count, 0)
                    self.assertGreater(head_probe.call_count, 0)
                    image_policy.assert_called_once()
                    self.assertEqual(
                        mode != "disabled", dhcp_checks <= checks,
                    )
                    self.assertEqual(
                        mode != "disabled", runtime_probe.call_count == 1,
                    )
                    self.assertEqual(
                        mode != "disabled",
                        ("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf") in observed,
                    )
                    if mode == "disabled":
                        self.assertFalse(dhcp_checks & checks)
                        self.assertTrue(any(
                            item["check"] == "dhcp-mode" and item["level"] == "PASS"
                            for item in findings
                        ))
                    elif mode == "mismatched":
                        self.assertTrue(any(
                            item["check"] == "dhcp-mode" and item["level"] == "FAIL"
                            for item in findings
                        ))
                finally:
                    fixture.tearDown()

    def test_parent_release_binds_every_current_project_input(self) -> None:
        self.assertEqual(
            [], VM.release_input_errors(self.project, self.parent),
        )
        (self.project / "02-devices_config.csv").write_bytes(b"changed\n")
        errors = VM.release_input_errors(self.project, self.parent)
        self.assertEqual(1, len(errors))
        self.assertIn("devices", errors[0])
        self.assertIn("SHA-256", errors[0])

    def test_release_id_is_recomputed_from_canonical_basis(self) -> None:
        basis = {
            key: self.parent[key]
            for key in (
                "project", "deployment_scope", "switch_scope", "inputs",
                "input_sources", "components", "inventory",
            )
        }
        expected = sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))[:20]
        self.parent["release_id"] = expected
        self.assertEqual([], VM.parent_release_errors(self.parent, "customer"))
        self.parent["release_id"] = "0" * 20
        self.assertIn(
            "canonical basis",
            "\n".join(VM.parent_release_errors(self.parent, "customer")),
        )

    def test_runtime_latest_pointers_match_parent_components(self) -> None:
        eth_release = self.project / "99-output-eth/release-eth"
        nvos_release = self.project / "99-output-ib_nvl/release-nvos"
        eth_release.mkdir(parents=True)
        nvos_release.mkdir(parents=True)
        (self.project / "99-output-eth/latest").symlink_to("release-eth")
        (self.project / "99-output-ib_nvl/latest").symlink_to("release-nvos")

        for relative, target in (
            ("ztp/config/cumulus/latest_yaml", eth_release),
            ("ztp/config/nvos/latest_yaml", nvos_release),
        ):
            pointer = self.root / relative
            pointer.parent.mkdir(parents=True)
            pointer.symlink_to(target)
        dhcp = self.project / "99-output-dhcp/dhcp-release-manifest.json"
        dhcp.parent.mkdir(parents=True)
        dhcp.write_text("{}\n", encoding="utf-8")
        dhcp_pointer = (
            self.root / "ztp/config/isc-dhcp-server/dhcp-release-manifest.json"
        )
        dhcp_pointer.parent.mkdir(parents=True)
        dhcp_pointer.symlink_to(dhcp)
        self.parent["components"] = {
            "cumulus": {"release_dir": "99-output-eth/release-eth"},
            "nvos": {"release_dir": "99-output-ib_nvl/release-nvos"},
            "dhcp": {},
        }
        self._seal_parent()

        self.assertEqual(
            [], VM.runtime_pointer_errors(self.root, self.project, self.parent),
        )
        (self.project / "99-output-eth/latest").unlink()
        (self.project / "99-output-eth/latest").symlink_to("../release-eth")
        self.assertIn(
            "cumulus project latest",
            "\n".join(
                VM.runtime_pointer_errors(self.root, self.project, self.parent)
            ),
        )

    def test_real_load_eth_scope_retains_cumulus_gate_without_requiring_nvos(self):
        from test_cases import test_load_release_transaction as release_fixture

        fixture = release_fixture.ReleaseTransactionTests()
        fixture.setUp()
        try:
            for path in (fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
                         fixture.project / "99-output-eth/20260830_120000_combine/release-manifest.json"):
                record = json.loads(path.read_bytes())
                record["switch_scope"] = "eth"
                path.write_text(json.dumps(record), encoding="utf-8")
            inputs = release_fixture.LOAD.replace(fixture.inputs, switch_scope="eth")
            parent = release_fixture.LOAD.validate_and_publish_release(fixture.project, inputs, publish=True)
            self.assertEqual("eth", parent["switch_scope"])
            self.assertNotIn("nvos", parent["components"])
            self.assertEqual([], VM.parent_release_errors(parent, "demo"))
            # The transaction fixture uses a materialized DHCP candidate;
            # SETUP's public runtime layout instead links the same manifest.
            flat = fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
            published = fixture.project / "99-output-dhcp/dhcp-release-manifest.json"
            published.parent.mkdir(exist_ok=True)
            published.write_bytes(flat.read_bytes())
            flat.unlink()
            flat.symlink_to(published)
            self.assertEqual([], VM.runtime_pointer_errors(fixture.root, fixture.project, parent))
            # An eth-only selection is not permission to hide corrupt inventory
            # or a missing Cumulus publication. Canonicalize each independent
            # bad record so the semantic guard, not a stale digest, is tested.
            for inventory in ([], [{"type": "ib"}], [{"type": "unknown"}], [None]):
                with self.subTest(inventory=inventory):
                    bad = dict(parent, inventory=inventory)
                    keys = ("project", "deployment_scope", "switch_scope", "dhcp_status",
                            "inputs", "input_sources", "components", "inventory")
                    bad["release_id"] = hashlib.sha256(json.dumps(
                        {key: bad[key] for key in keys}, ensure_ascii=False,
                        sort_keys=True, separators=(",", ":"),
                    ).encode()).hexdigest()[:20]
                    self.assertTrue(VM.runtime_pointer_errors(fixture.root, fixture.project, bad))
            (fixture.project / "99-output-eth/latest").unlink()
            errors = VM.runtime_pointer_errors(fixture.root, fixture.project, parent)
            self.assertTrue(any("cumulus" in error for error in errors))
        finally:
            fixture.tearDown()

    def test_explicit_disabled_parent_ignores_stale_dhcp_pointer_only(self) -> None:
        self.parent["schema_version"] = 2
        self.parent["dhcp_status"] = "disabled"
        self.parent["components"] = {}
        global_path = self.project / "01-global.yaml"
        global_path.write_bytes(global_path.read_bytes().replace(
            b"status: enabled", b"status: disabled",
        ))
        self.parent["inputs"]["global"] = sha256(global_path.read_bytes())
        self._seal_parent()
        errors = VM.runtime_pointer_errors(self.root, self.project, self.parent)
        # Without Cumulus/NVOS proof this still fails; only the DHCP pointer
        # requirement can disappear under an explicit disabled record.
        self.assertTrue(any("cumulus" in error for error in errors))
        self.assertTrue(any("nvos" in error for error in errors))
        self.assertFalse(any("dhcp" in error.lower() for error in errors))
        self.parent["components"]["dhcp"] = {}
        self._seal_parent()
        self.assertIn(
            "disabled",
            "\n".join(VM.runtime_pointer_errors(self.root, self.project, self.parent)),
        )
        self.parent["components"].pop("dhcp")
        self._seal_parent()
        global_path.write_bytes(global_path.read_bytes().replace(
            b"status: disabled", b"status: enabled",
        ))
        self.parent["inputs"]["global"] = sha256(global_path.read_bytes())
        self._seal_parent()
        self.assertIn(
            "DHCP",
            "\n".join(VM.runtime_pointer_errors(self.root, self.project, self.parent)),
        )


class VmMiniSelectedOutputTests(unittest.TestCase):
    def _project(self, directory):
        project = Path(directory).resolve()
        (project / "04-air-mini-devices.txt").write_text(
            "[minimum-required]\nleaf10\n[customer-provided]\n", encoding="utf-8",
        )
        output = project / "99-output-p2p"
        output.mkdir()
        return project, output

    def test_selected_output_ignores_retained_historical_air_json(self):
        with tempfile.TemporaryDirectory() as directory:
            project, output = self._project(directory)
            source = project / "Pinned P2P_v1.0.xlsx"
            source.write_bytes(b"selected workbook bytes")
            (project / "p2p.xlsx").symlink_to(source.name)
            (output / (source.stem + "-air.json")).write_text(
                json.dumps({"content": {"nodes": {"leaf10": {}}}}), encoding="utf-8",
            )
            historical = output / "Other P2P_v99.0-air.json"
            historical.write_bytes(b"retained invalid historical bytes")
            original = historical.read_bytes(), historical.stat().st_ino
            self.assertEqual((1, 1), VM.mini_air_summary(project))
            self.assertEqual(original, (historical.read_bytes(), historical.stat().st_ino))

    def test_missing_selected_output_never_falls_back_to_sole_history(self):
        with tempfile.TemporaryDirectory() as directory:
            project, output = self._project(directory)
            source = project / "Selected P2P_v2.0.xlsx"
            source.write_bytes(b"selected workbook bytes")
            (project / "p2p.xlsx").symlink_to(source.name)
            (output / "Historical P2P_v1.0-air.json").write_text(
                json.dumps({"content": {"nodes": {"old": {}}}}), encoding="utf-8",
            )
            with self.assertRaises((OSError, ValueError)):
                VM.mini_air_summary(project)

    def test_selected_workbook_drift_during_summary_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            project, output = self._project(directory)
            source = project / "Selected P2P_v2.0.xlsx"
            source.write_bytes(b"selected workbook A")
            (project / "p2p.xlsx").symlink_to(source.name)
            (output / (source.stem + "-air.json")).write_text(
                json.dumps({"content": {"nodes": {"leaf10": {}}}}), encoding="utf-8",
            )
            read_json = VM.load_json
            def mutate_after_read(path):
                value = read_json(path)
                source.write_bytes(b"selected workbook B")
                return value
            with mock.patch.object(VM, "load_json", side_effect=mutate_after_read):
                with self.assertRaisesRegex(ValueError, "P2P.*changed|P2P.*变化"):
                    VM.mini_air_summary(project)

    def test_real_setup_load_older_pin_drives_vm_selected_air_summary(self):
        from test_cases.test_p2p_selection_workflow import P2PSelectionWorkflowTests, workbook

        P2PSelectionWorkflowTests.setUpClass()
        workflow = P2PSelectionWorkflowTests()
        with tempfile.TemporaryDirectory() as directory:
            project, output = self._project(directory)
            older = workbook(project / "Fabric P2P_v1.0.xlsx", "selected")
            newer = workbook(project / "Fabric P2P_v9.0.xlsx", "unselected")
            workflow.select_and_link(project, older.name)
            self.assertEqual(older, workflow.load.select_p2p(project, older.name))
            (output / (older.stem + "-air.json")).write_text(
                json.dumps({"content": {"nodes": {"leaf10": {}, "spine": {}}}}), encoding="utf-8",
            )
            retained = output / (newer.stem + "-air.json")
            retained.write_text(json.dumps({"content": {"nodes": {"wrong": {}}}}), encoding="utf-8")
            self.assertEqual((1, 2), VM.mini_air_summary(project))
            self.assertEqual({"wrong": {}}, json.loads(retained.read_text())["content"]["nodes"])


class VmDeviceCsvAcceptanceTests(unittest.TestCase):
    def test_repeated_schema_group_headers_are_valid_but_identity_is_unique(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "02-devices_config.csv"
            path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_mac,eth1_ip,netmask,eth1_mac,"
                "vlan_id,svi_ip,netmask,vlan_ports,"
                "evpn_vrf,dhcp_relay,svi_ip,netmask,vlan_ports\n"
                "leaf01,eth,192.0.2.1,255.255.255.0,02:10:c0:00:02:01,,,,"
                "100,198.51.100.1,255.255.255.0,swp1,"
                "oob,bcm,203.0.113.1,255.255.255.0,bond1\n",
                encoding="utf-8",
            )
            errors, counts, fake_macs = VM.devices_csv_errors(path)
            self.assertEqual([], errors)
            self.assertEqual({"eth": 1}, counts)
            self.assertEqual(1, fake_macs)

            path.write_text(
                "hostname,type,hostname,eth0_mac,eth1_mac\n"
                "leaf01,eth,leaf01,02:10:c0:00:02:01,\n",
                encoding="utf-8",
            )
            errors, _counts, _fake_macs = VM.devices_csv_errors(path)
            self.assertIn("身份列必须且只能出现一次", "\n".join(errors))


class VmFullSystemdProfileTests(unittest.TestCase):
    def test_full_profile_enables_native_service_worker_and_active_http_checks(self) -> None:
        args = VM.parse_args([
            "customer", "--full-systemd", "--worker-scope", "prod",
            "--control-auth-user", "nvis",
        ])

        VM.apply_validation_profile(args)

        self.assertTrue(args.expect_services)
        self.assertTrue(args.expect_workers)
        self.assertTrue(args.check_http_content)
        self.assertTrue(args.check_source_syntax)
        self.assertEqual("prod", args.worker_scope)
        self.assertEqual("nvis", args.control_auth_user)

    def test_active_http_checks_require_an_explicit_control_user(self) -> None:
        args = VM.parse_args(["customer", "--check-http-content"])

        with self.assertRaisesRegex(ValueError, "--control-auth-user"):
            VM.apply_validation_profile(args)

    def test_legacy_air_flag_maps_to_scope_air(self) -> None:
        args = VM.parse_args(["customer", "--expect-workers", "--expect-air-workers"])

        VM.apply_validation_profile(args)

        self.assertEqual("air", args.worker_scope)

    def test_worker_commands_use_scope_pair_and_exact_project(self) -> None:
        root = Path("/var/www/html")
        project = root / "DAY0-Prepare/customer"
        commands = {
            "ztp-monitor": (
                "/usr/bin/python3 -u /var/www/html/DAY0-Prepare/12-ztp-monitor.py "
                "/var/www/html/DAY0-Prepare/customer --watch 30 --generate-html "
                "--collect-on-complete --known-hosts "
                "/var/www/html/ztp/status/ztp-known-hosts --scope prod"
            ),
            "switch-collection": (
                "/usr/bin/python3 -u /var/www/html/monitor/"
                "switch-collection-worker.py --scope prod"
            ),
            "manual-ztp": (
                "/usr/bin/python3 -u /var/www/html/monitor/"
                "manual-ztp-worker.py --scope prod"
            ),
        }
        for label, command in commands.items():
            with self.subTest(label=label):
                self.assertEqual(
                    [],
                    VM.worker_command_errors(
                        label, command, root=root, project=project,
                        expected_scope="prod",
                    ),
                )

        wrong_scope = commands["switch-collection"].replace(
            "--scope prod", "--scope air",
        )
        self.assertIn(
            "scope",
            "\n".join(VM.worker_command_errors(
                "switch-collection", wrong_scope, root=root, project=project,
                expected_scope="prod",
            )),
        )
        wrong_project = commands["ztp-monitor"].replace(
            "/DAY0-Prepare/customer", "/DAY0-Prepare/other",
        )
        self.assertIn(
            "project",
            "\n".join(VM.worker_command_errors(
                "ztp-monitor", wrong_project, root=root, project=project,
                expected_scope="prod",
            )),
        )

    def test_interfacesv4_parser_is_data_only_and_rejects_unsafe_names(self) -> None:
        self.assertEqual(
            ("enp0s10", "enp0s11"),
            VM.parse_interfacesv4(
                '# comment\nINTERFACESv4="enp0s10 enp0s11"\nINTERFACESv6=""\n'
            ),
        )
        self.assertEqual((), VM.parse_interfacesv4('INTERFACESv4=""\n'))
        with self.assertRaisesRegex(ValueError, "接口名"):
            VM.parse_interfacesv4('INTERFACESv4="enp0s10 --all"\n')
        with self.assertRaisesRegex(ValueError, "重复"):
            VM.parse_interfacesv4('INTERFACESv4="enp0s10 enp0s10"\n')

    def test_dhcp_runtime_accepts_automatic_or_validates_explicit_interfaces(self) -> None:
        assignments = {
            "192.0.2.100": ("enp0s10",),
            "198.51.100.100": ("enp0s11",),
        }
        self.assertEqual(
            [],
            VM.dhcp_runtime_interface_errors(
                (), assignments,
                "/usr/sbin/dhcpd -4 -f -cf /etc/dhcp/dhcpd.conf",
                {"enp0s10", "enp0s11", "enp0s8"},
            ),
        )
        command = (
            "/usr/sbin/dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf "
            "enp0s10 enp0s11"
        )
        self.assertEqual(
            [],
            VM.dhcp_runtime_interface_errors(
                ("enp0s10", "enp0s11"), assignments, command,
                {"enp0s10", "enp0s11", "enp0s8"},
            ),
        )
        self.assertIn(
            "service_ip",
            "\n".join(VM.dhcp_runtime_interface_errors(
                ("enp0s10",), assignments, command, {"enp0s10", "enp0s11"},
            )),
        )
        self.assertIn(
            "cmdline",
            "\n".join(VM.dhcp_runtime_interface_errors(
                ("enp0s10", "enp0s11"), assignments,
                command.replace(" enp0s11", ""), {"enp0s10", "enp0s11"},
            )),
        )

    def test_ztp_prefix_is_read_from_schema_v2_without_importing_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "01-global.yaml"
            path.write_text(
                "schema_version: 2\n"
                "common:\n"
                "  mgmt:\n"
                "    ztp:\n"
                "      status: enabled\n"
                "      ztp_url_prefix: /factory/ztp\n",
                encoding="utf-8",
            )
            self.assertEqual("/factory/ztp", VM.read_ztp_prefix(path))
            path.write_text(
                "common:\n  mgmt:\n    ztp:\n"
                "      ztp_url_prefix: ../../escape\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ztp_url_prefix"):
                VM.read_ztp_prefix(path)

    def test_http_bootstrap_plan_preserves_relay_reference_to_direct_service(self) -> None:
        root = Path("/var/www/html")
        direct = ipaddress.ip_address("192.0.2.100")
        subnets = (
            VM.DhcpSubnet(
                "direct", ipaddress.ip_network("192.0.2.0/24"), direct,
                configured_service_ip=direct, cumulus_profile="oob",
                nvos_ztp=True,
            ),
            VM.DhcpSubnet(
                "relayed", ipaddress.ip_network("198.51.100.0/24"), None,
                configured_service_ip=direct, cumulus_profile="oob",
                nvos_ztp=True,
            ),
            VM.DhcpSubnet(
                "direct-two", ipaddress.ip_network("203.0.113.0/24"),
                ipaddress.ip_address("203.0.113.100"),
                configured_service_ip=ipaddress.ip_address("203.0.113.100"),
                cumulus_profile="oobofoob", nvos_ztp=False,
            ),
        )

        actual = VM.bootstrap_http_assets(root, subnets, "/ztp")

        self.assertEqual(
            {
                (
                    "192.0.2.100", "/ztp/ztp-bootstrap_oob.sh",
                    root / "ztp/ztp-bootstrap_oob.sh",
                ),
                ("192.0.2.100", "/ztp/ztp.json", root / "ztp/ztp.json"),
                (
                    "203.0.113.100", "/ztp/ztp-bootstrap_oobofoob.sh",
                    root / "ztp/ztp-bootstrap_oobofoob.sh",
                ),
            },
            {(item.address, item.url_path, item.source) for item in actual},
        )

    def test_release_http_samples_use_mac_entry_and_parent_bound_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "DAY0-Prepare/customer"
            release = project / "99-output-eth/release-1"
            release.mkdir(parents=True)
            config = release / "leaf01.yaml"
            config.write_text("hostname: leaf01\n", encoding="utf-8")
            link = release / "020000000001.yaml"
            link.symlink_to(config.name)
            manifest = {
                "devices": [{
                    "hostname": "leaf01", "config": config.name,
                    "macs": ["02:00:00:00:00:01"],
                }],
            }
            (release / "release-manifest.json").write_text(
                json.dumps(manifest) + "\n", encoding="utf-8",
            )
            parent = {
                "components": {
                    "cumulus": {"release_dir": "99-output-eth/release-1"},
                },
            }

            actual = VM.release_http_assets(
                root, project, parent, ("192.0.2.100",), "/ztp", samples=3,
            )

            self.assertEqual(1, len(actual))
            self.assertEqual("192.0.2.100", actual[0].address)
            self.assertEqual(
                "/ztp/config/cumulus/latest_yaml/020000000001.yaml",
                actual[0].url_path,
            )
            self.assertEqual(config.resolve(), actual[0].source)

    def test_http_asset_probe_compares_exact_body_without_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "ztp.json"
            source.write_bytes(b'{"url":"http://192.0.2.100/ztp"}\n')
            asset = VM.HttpAsset("192.0.2.100", "/ztp/ztp.json", source)
            response = mock.Mock()
            response.status = 200
            response.getheaders.return_value = [
                ("Content-Type", "application/json"),
            ]
            response.read.return_value = source.read_bytes()
            connection = mock.Mock()
            connection.getresponse.return_value = response

            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ) as constructor:
                detail = VM.verify_http_asset(asset, timeout=2.5)

            constructor.assert_called_once_with("192.0.2.100", 80, timeout=2.5)
            connection.request.assert_called_once_with(
                "GET", "/ztp/ztp.json",
                headers={
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Host": "192.0.2.100",
                    "User-Agent": "http-ztp-systemd-vm-validator/1",
                },
            )
            connection.close.assert_called_once_with()
            self.assertIn(f"bytes={source.stat().st_size}", detail)

            response.read.return_value = b"changed\n"
            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ):
                with self.assertRaisesRegex(ValueError, "内容 hash"):
                    VM.verify_http_asset(asset, timeout=2.5)

    def test_http_policy_probe_requires_exact_status(self) -> None:
        response = mock.Mock()
        response.status = 403
        response.getheaders.return_value = []
        response.read.return_value = b"Forbidden"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            detail = VM.verify_http_status(
                "192.0.2.100", "/DAY0-Prepare/customer/01-global.yaml",
                expected=403, timeout=2.0,
            )
        self.assertIn("HTTP 403", detail)

        response.status = 404
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            with self.assertRaisesRegex(ValueError, "expected=403"):
                VM.verify_http_status(
                    "192.0.2.100", "/DAY0-Prepare/customer/01-global.yaml",
                    expected=403, timeout=2.0,
                )

    def test_http_head_probe_binds_content_length_without_reading_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "switch.bin"
            image.write_bytes(b"firmware-bytes")
            response = mock.Mock()
            response.status = 200
            response.getheaders.return_value = [
                ("Content-Length", str(image.stat().st_size)),
            ]
            response.read.return_value = b""
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ):
                detail = VM.verify_http_head(
                    "192.0.2.100", "/ztp/image/cumulus/switch.bin", image,
                    timeout=2.0,
                )
            self.assertIn(f"bytes={image.stat().st_size}", detail)
            connection.request.assert_called_once_with(
                "HEAD", "/ztp/image/cumulus/switch.bin",
                headers={
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Host": "192.0.2.100",
                    "User-Agent": "http-ztp-systemd-vm-validator/1",
                },
            )

    def test_control_cgi_get_requires_live_worker_json(self) -> None:
        response = mock.Mock()
        response.status = 200
        response.getheaders.return_value = [
            ("Content-Type", "application/json; charset=utf-8"),
        ]
        response.read.return_value = json.dumps({
            "state": "idle", "process_alive": True,
        }).encode("utf-8")
        connection = mock.Mock()
        connection.getresponse.return_value = response
        authorization = "Basic " + base64.b64encode(
            b"nvis:operator-secret",
        ).decode("ascii")
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            detail = VM.verify_control_cgi(
                "192.0.2.100", "ztp-monitor-control",
                url_path="/monitor/control/ztp-monitor",
                authorization=authorization, timeout=2.0,
            )
        self.assertIn("process_alive=true", detail)
        self.assertNotIn("operator-secret", detail)
        self.assertEqual(
            authorization,
            connection.request.call_args.kwargs["headers"]["Authorization"],
        )

        response.read.return_value = json.dumps({
            "state": "idle", "process_alive": False,
        }).encode("utf-8")
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            with self.assertRaisesRegex(ValueError, "process_alive"):
                VM.verify_control_cgi(
                    "192.0.2.100", "ztp-monitor-control",
                    url_path="/cgi-bin/ztp-monitor-control",
                    authorization=authorization, timeout=2.0,
                )

    def test_control_auth_prompts_once_and_challenges_before_credentials(self) -> None:
        password_reader = mock.Mock(return_value="one-use-secret")

        authorization = VM.read_control_authorization(
            "cumulus", password_reader=password_reader,
        )

        password_reader.assert_called_once_with(
            "Monitor control password for cumulus: ",
        )
        self.assertEqual(
            "Basic " + base64.b64encode(
                b"cumulus:one-use-secret",
            ).decode("ascii"),
            authorization,
        )
        self.assertNotIn("one-use-secret", repr(password_reader.call_args))

        response = mock.Mock()
        response.status = 401
        response.getheaders.return_value = [
            ("WWW-Authenticate", 'Basic realm="HTTP ZTP Monitor Control"'),
        ]
        response.read.return_value = b"Authorization Required"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            detail = VM.verify_control_auth_challenge(
                "192.0.2.100", timeout=2.0,
            )

        self.assertIn("HTTP 401", detail)
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])

    def test_authenticated_monitor_and_both_control_routes_share_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            monitor = Path(temporary) / "monitor.html"
            monitor.write_bytes(b"<!doctype html><title>Monitor</title>\n")
            authorization = "Basic " + base64.b64encode(
                b"nvis:sentinel-password",
            ).decode("ascii")
            response = mock.Mock()
            response.status = 200
            response.getheaders.return_value = [
                ("Content-Type", "text/html; charset=utf-8"),
            ]
            response.read.return_value = monitor.read_bytes()
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ):
                detail = VM.verify_http_asset(
                    VM.HttpAsset(
                        "192.0.2.100", "/monitor/monitor.html", monitor,
                    ),
                    timeout=2.0,
                    authorization=authorization,
                )
            self.assertNotIn("sentinel-password", detail)
            self.assertEqual(
                authorization,
                connection.request.call_args.kwargs["headers"]["Authorization"],
            )

        expected_routes = {
            "ztp-monitor-control": (
                "/monitor/control/ztp-monitor",
                "/cgi-bin/ztp-monitor-control",
            ),
            "switch-collection-control": (
                "/monitor/control/switch-collection",
                "/cgi-bin/switch-collection-control",
            ),
            "manual-ztp-control": (
                "/monitor/control/manual-ztp",
                "/cgi-bin/manual-ztp-control",
            ),
        }
        self.assertEqual(expected_routes, VM.CONTROL_CGI_ROUTES)

    def test_source_syntax_scan_is_read_only_and_reports_python_and_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            good_python = tools / "good.py"
            good_python.write_text("value = 1\n", encoding="utf-8")
            empty_init = tools / "__init__.py"
            empty_init.write_bytes(b"")
            good_shell = tools / "good.sh"
            good_shell.write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
            before = {
                path: (path.stat().st_mode, path.stat().st_mtime_ns, path.read_bytes())
                for path in (good_python, good_shell)
            }

            counts, errors = VM.source_syntax_errors(root)

            self.assertEqual({"python": 2, "shell": 1}, counts)
            self.assertEqual([], errors)
            for path, snapshot in before.items():
                self.assertEqual(snapshot, (
                    path.stat().st_mode, path.stat().st_mtime_ns,
                    path.read_bytes(),
                ))
            self.assertFalse(any(root.rglob("__pycache__")))

            (tools / "broken.py").write_text("if True print('bad')\n", encoding="utf-8")
            (tools / "broken.sh").write_text("if then\n", encoding="utf-8")
            counts, errors = VM.source_syntax_errors(root)
            self.assertEqual({"python": 3, "shell": 2}, counts)
            self.assertIn("broken.py", "\n".join(errors))
            self.assertIn("broken.sh", "\n".join(errors))

    def test_apache_boundary_is_extracted_from_managed_heredoc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "infra-setup.sh"
            source.write_text(
                "before\n"
                "  cat <<'APACHE_PUBLIC_BOUNDARY_EOF'\n"
                "# HTTP-ZTP-PUBLIC-BOUNDARY-V1\n"
                "<Directory \"/var/www/html\">\n"
                "    Options -Indexes\n"
                "</Directory>\n"
                "APACHE_PUBLIC_BOUNDARY_EOF\n"
                "after\n",
                encoding="utf-8",
            )

            payload = VM.expected_apache_boundary(source)

            self.assertEqual(
                b'# HTTP-ZTP-PUBLIC-BOUNDARY-V1\n'
                b'<Directory "/var/www/html">\n'
                b'    Options -Indexes\n'
                b'</Directory>\n',
                payload,
            )

    def test_current_infra_v2_boundary_is_accepted_without_rewriting_bytes(self) -> None:
        source = ROOT / "infra/infra-setup.sh"
        payload = VM.expected_apache_boundary(source)
        self.assertIn(b"# HTTP-ZTP-PUBLIC-BOUNDARY-V2\n", payload)
        self.assertNotIn(b"# HTTP-ZTP-PUBLIC-BOUNDARY-V1\n", payload)
        # Independent wire contract: never silently downgrade the emitted policy.
        self.assertIn(b"APACHE_PUBLIC_BOUNDARY_EOF", source.read_bytes())

    def test_apache_boundary_rejects_unknown_missing_or_duplicate_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "infra-setup.sh"
            for markers in ("", "# HTTP-ZTP-PUBLIC-BOUNDARY-V3\n",
                            "# HTTP-ZTP-PUBLIC-BOUNDARY-V1\n# HTTP-ZTP-PUBLIC-BOUNDARY-V2\n"):
                with self.subTest(markers=markers):
                    source.write_text("cat <<'APACHE_PUBLIC_BOUNDARY_EOF'\n" + markers
                                      + "Options -Indexes\nAPACHE_PUBLIC_BOUNDARY_EOF\n",
                                      encoding="utf-8")
                    with self.assertRaises(ValueError):
                        VM.expected_apache_boundary(source)

    def test_installed_cgi_contract_requires_hash_and_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            cgi_root = Path(temporary) / "cgi-bin"
            source_dir = root / "monitor"
            source_dir.mkdir(parents=True)
            cgi_root.mkdir()
            for name in VM.CONTROL_CGI_NAMES:
                source = source_dir / f"{name}.cgi"
                destination = cgi_root / name
                source.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o755)

            self.assertEqual([], VM.installed_cgi_errors(root, cgi_root))

            (cgi_root / VM.CONTROL_CGI_NAMES[0]).chmod(0o644)
            self.assertIn(
                "executable",
                "\n".join(VM.installed_cgi_errors(root, cgi_root)),
            )

    def test_monitor_report_must_be_current_project_scope_and_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            snapshot = root / "ztp/status/20260906_120000"
            snapshot.mkdir(parents=True)
            latest = snapshot.parent / "latest"
            latest.symlink_to(snapshot.name)
            report = {
                "schema_version": 1,
                "project": "customer",
                "scope": "prod",
                "generated_at": datetime.now().astimezone().isoformat(
                    timespec="seconds"
                ),
                "devices": [{"hostname": "leaf01"}],
            }
            (snapshot / "report.json").write_text(
                json.dumps(report) + "\n", encoding="utf-8",
            )

            detail = VM.monitor_runtime_evidence(root, project, "prod")
            self.assertIn("devices=1", detail)

            report["generated_at"] = (
                datetime.now().astimezone() - timedelta(hours=2)
            ).isoformat(timespec="seconds")
            (snapshot / "report.json").write_text(
                json.dumps(report) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "不新鲜"):
                VM.monitor_runtime_evidence(
                    root, project, "prod", max_age_seconds=1800,
                )

    def test_regular_source_scanner_does_not_follow_output_or_directory_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            (tools / "ok.py").write_text("pass\n", encoding="utf-8")
            output = root / "DAY0-Prepare/customer/99-output-ztp"
            output.mkdir(parents=True)
            (output / "broken.py").write_text("if True print('bad')\n", encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            (outside / "broken.py").write_text("if True print('bad')\n", encoding="utf-8")
            (tools / "linked").symlink_to(outside, target_is_directory=True)

            counts, errors = VM.source_syntax_errors(root)

            self.assertEqual({"python": 1, "shell": 0}, counts)
            self.assertEqual([], errors)
            self.assertTrue(stat.S_ISLNK((tools / "linked").lstat().st_mode))



class VmSelectedDhcpConsumerContractTests(unittest.TestCase):
    def test_installed_selected_empty_hosts_are_hash_bound_and_different_inodes_allowed(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory)
            payloads = {"dhcpd.conf": b"# independently specified conf\n",
                        "dhcpd_eth.hosts": b"host independent-leaf {}\n",
                        "dhcpd_ib.hosts": b"", "dhcpd_nvl.hosts": b""}
            selected = SimpleNamespace(mode="pinned", binding={"independent": True},
                                       output_hashes={name: sha256(payload)
                                                      for name, payload in payloads.items()})
            for name, payload in payloads.items():
                (installed / name).write_bytes(payload)
            with mock.patch.object(VM, "selected_dhcp_authority", return_value=selected), \
                 mock.patch.object(VM, "_recheck_selected_dhcp_authority", return_value=selected):
                self.assertEqual([], VM.installed_dhcp_errors(installed, {}, installed))
                (installed / "dhcpd_ib.hosts").write_bytes(b"unexpected host\n")
                errors = VM.installed_dhcp_errors(installed, {}, installed)
                self.assertEqual(1, len(errors))
                self.assertIn("dhcpd_ib.hosts", errors[0])

    def test_installed_selected_identity_failure_cannot_pass_using_flat_files(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory)
            for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
                (installed / name).write_bytes(b"independent plausible legacy bytes\n")
            with mock.patch.object(VM, "selected_dhcp_authority",
                                   side_effect=ValueError("independent bad selector")):
                errors = VM.installed_dhcp_errors(installed, {}, installed)
            self.assertTrue(errors)
            self.assertIn("selector", errors[0])


if __name__ == "__main__":
    unittest.main()
