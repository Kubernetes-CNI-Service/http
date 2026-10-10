#!/usr/bin/env python3
"""Direct contract for the fail-closed DHCP enable/disable authority."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

import yaml
from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "dhcp_optional_direct_load", ROOT / "DAY0-Prepare/11-load.py",
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot import DAY0 load")
LOAD = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = LOAD
_SPEC.loader.exec_module(LOAD)
DHCP = load_script(
    "dhcp_optional_handoff_generator",
    ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
SETUP = load_script(
    "dhcp_optional_handoff_setup", ROOT / "DAY0-Prepare/01-a-setup.py",
)

_TEMPLATE_TEXT = (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
    encoding="utf-8"
)
_TEMPLATE = yaml.safe_load(_TEMPLATE_TEXT)
_STATUS_LABEL = "common.mgmt.dhcp-server.status"
EMPTY_SUBNET_TABLE = (
    b"shared_network,subnet,netmask,range_start,range_end,routers,"
    b"ztp_service_ip,cumulus_profile,nvos_ztp\n"
)
EMPTY_SUBNET_TABLE_SHA256 = (
    "1e4e2db5cbb609d34080451f7940ec84e6a396a7fe3627e4452980caac27c1c0"
)


def global_document(status: object = "disabled") -> dict[str, object]:
    """Fresh, otherwise-valid input; package and siblings cannot pre-empt status."""
    document = deepcopy(_TEMPLATE)
    document["common"]["mgmt"]["dhcp-server"]["status"] = status
    return document


def settings_for(status: str):
    return LOAD.load_global(Path("unused-global.yaml"), global_data=global_document(status))


class DhcpOptionalDirectTests(unittest.TestCase):
    def test_r22_middle_physical_blank_lines_keep_valid_data_rows(self):
        """Only real CSV records count; blank whitespace between rows is allowed."""
        row = (
            b"mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            b"192.0.2.1,192.0.2.10,oob,no\n"
        )
        for middle in (b"\n", b" \t\r\n"):
            with self.subTest(middle=middle), tempfile.TemporaryDirectory() as name:
                subnet = Path(name) / "02-dhcp-subnet_config.csv"
                subnet.write_bytes(EMPTY_SUBNET_TABLE + middle + row)
                errors, warnings = SETUP._validate_subnet_csv(
                    subnet, dhcp_enabled=True, ztp_enabled=True,
                )
                self.assertEqual(([], []), (errors, warnings))
                LOAD.validate_subnet_file(subnet, settings_for("enabled"))

    def test_r22_middle_blank_preserves_following_invalid_record_line(self):
        """Skipping a blank line never hides a delimiter record or its real line."""
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE + b" \t\n" + b",,,,,,,,\n")
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertIn("行3", " ".join(errors))
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            with self.assertRaisesRegex(LOAD.LoadError, r"第 3 行|line 3"):
                LOAD.validate_subnet_file(subnet, disabled)

    def test_r22_trailing_whitespace_is_not_an_empty_csv_record(self):
        """Only literal trailing whitespace may follow a canonical empty table."""
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            subnet.write_bytes(EMPTY_SUBNET_TABLE + b" \t\r\n\t\n")
            self.assertEqual(([], []), SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            ))
            LOAD.validate_subnet_file(subnet, disabled)
            for label, suffix in (
                ("delimiters", b",,,,,,,,\n"),
                ("quoted-empty", b'""\n'),
            ):
                with self.subTest(case=label):
                    subnet.write_bytes(EMPTY_SUBNET_TABLE + suffix)
                    errors, _warnings = SETUP._validate_subnet_csv(
                        subnet, dhcp_enabled=False, ztp_enabled=False,
                    )
                    self.assertIn("行2", " ".join(errors))
                    with self.assertRaisesRegex(LOAD.LoadError, r"第 2 行|line 2"):
                        LOAD.validate_subnet_file(subnet, disabled)

    def test_r22_first_physical_record_cannot_be_blank(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            for prefix in (b"\n", b" \t\n"):
                with self.subTest(prefix=prefix):
                    subnet.write_bytes(prefix + EMPTY_SUBNET_TABLE)
                    errors, _warnings = SETUP._validate_subnet_csv(
                        subnet, dhcp_enabled=False, ztp_enabled=False,
                    )
                    self.assertIn("行1", " ".join(errors))
                    with self.assertRaisesRegex(LOAD.LoadError, r"行1|line 1"):
                        LOAD.validate_subnet_file(subnet, disabled)

    def test_r22_subnet_readers_require_explicit_builtin_bool_modes(self):
        """Neither setup nor load may infer one service state from an empty flag."""
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)

            for omitted in ("dhcp_enabled", "ztp_enabled"):
                modes = {"dhcp_enabled": False, "ztp_enabled": False}
                modes.pop(omitted)
                with self.subTest(reader="setup", omitted=omitted):
                    with self.assertRaises(TypeError):
                        SETUP._validate_subnet_csv(subnet, **modes)

            for field in ("dhcp_enabled", "ztp_enabled"):
                for invalid in (None, 0, 1, "disabled", "enabled"):
                    with self.subTest(reader="setup", field=field, value=invalid):
                        modes = {"dhcp_enabled": False, "ztp_enabled": False}
                        modes[field] = invalid
                        errors, _warnings = SETUP._validate_subnet_csv(
                            subnet, **modes,
                        )
                        self.assertTrue(errors, "non-bool mode must be rejected")
                        self.assertIn("布尔", " ".join(errors))
                    with self.subTest(reader="load", field=field, value=invalid):
                        settings = LOAD.replace(disabled, **{field: invalid})
                        with self.assertRaisesRegex(LOAD.LoadError, "布尔|bool"):
                            LOAD.validate_subnet_file(subnet, settings)

    def test_r22_setup_and_load_reject_off_on_before_empty_table_exception(self):
        """A forbidden global pair is distinct from the legal off/off empty table."""
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)

            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual([], errors)
            LOAD.validate_subnet_file(subnet, disabled)

            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=True,
            )
            self.assertIn("DHCP", " ".join(errors))
            self.assertIn("ZTP", " ".join(errors))
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP.*ZTP"):
                LOAD.validate_subnet_file(
                    subnet, LOAD.replace(disabled, ztp_enabled=True),
                )

    def test_empty_unowned_candidate_requires_proof_before_replacing_old_live_host(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            candidate_dir = directory / "candidate"
            candidate_dir.mkdir()
            payloads = {
                "dhcpd.conf": b"include hosts;\n",
                "dhcpd_eth.hosts": b"host current-air {}\n",
                "dhcpd_ib.hosts": b"",
                "dhcpd_nvl.hosts": b"",
            }
            for filename, payload in payloads.items():
                (candidate_dir / filename).write_bytes(payload)
            live = directory / "live/dhcpd_ib.hosts"
            live.parent.mkdir()
            live.write_bytes(b"host old-ib { hardware ethernet 02:00:00:00:00:01; }\n")
            before = live.read_bytes(), live.stat().st_ino
            mappings = {
                candidate_dir / filename: live.parent / filename
                for filename in payloads
            }
            manifest = {
                "schema_version": 1, "release_id": "direct-old-live-fixture",
                "switch_scope": "eth",
                "counts": {"host_declarations_by_family": {
                    "eth": 1, "ib": 0, "nvl": 0,
                }},
                "outputs": {
                    filename: {"sha256": hashlib.sha256(payload).hexdigest()}
                    for filename, payload in payloads.items()
                },
            }
            receipt = candidate_dir / "dhcp-release-manifest.json"
            receipt.write_text(json.dumps(manifest), encoding="utf-8")
            LOAD.validate_dhcp_output_sources(mappings)
            manifest["counts"]["host_declarations_by_family"]["ib"] = 1
            receipt.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_dhcp_output_sources(mappings)
            manifest["counts"]["host_declarations_by_family"]["ib"] = 0
            manifest["outputs"]["dhcpd_ib.hosts"]["sha256"] = "0" * 64
            receipt.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_dhcp_output_sources(mappings)
            self.assertEqual(before, (live.read_bytes(), live.stat().st_ino))

    def test_disabled_preflight_never_requires_missing_dhcp_artifacts(self):
        disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
        inputs = SimpleNamespace(settings=disabled)
        missing = Path("/missing-dhcp-artifacts-for-disabled-contract")
        mappings = {missing / filename: missing / filename for filename in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts",
        )}
        with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                mock.patch.object(LOAD, "run") as command:
            LOAD.preflight_services(
                inputs, {}, runtime_backend=SimpleNamespace(name="systemd"),
            )
            LOAD.preflight_services(
                inputs, {}, dhcp_runtime_plan=SimpleNamespace(
                    listener_names=(), endpoint_ips=(),
                ), runtime_backend=SimpleNamespace(name="supervisor"),
            )
            command.assert_not_called()
        with self.assertRaisesRegex(LOAD.LoadError, "DHCP listener 规划非空"):
            LOAD.preflight_services(
                inputs, {}, dhcp_runtime_plan=SimpleNamespace(
                    listener_names=("eno7",), endpoint_ips=(),
                ), runtime_backend=SimpleNamespace(name="supervisor"),
            )

    def test_empty_unowned_host_requires_exact_zero_declaration_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts",
            )
            mappings = {}
            for filename in names:
                source = directory / filename
                source.write_bytes(
                    b"" if filename in {"dhcpd_ib.hosts", "dhcpd_nvl.hosts"}
                    else b"valid generated DHCP text\n"
                )
                mappings[source] = directory / "live" / filename
            manifest_path = directory / "dhcp-release-manifest.json"
            manifest = {
                "schema_version": 1, "release_id": "direct-fixture",
                "switch_scope": "eth",
                "counts": {"host_declarations_by_family": {
                    "eth": 1, "ib": 0, "nvl": 0,
                }},
                "outputs": {
                    source.name: {"sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
                    for source in mappings
                },
            }

            def check():
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                LOAD.validate_dhcp_output_sources(mappings)

            check()
            for mutation in (
                lambda: manifest.update(switch_scope="ib"),
                lambda: manifest["counts"]["host_declarations_by_family"].update(ib=1),
                lambda: manifest["outputs"]["dhcpd_ib.hosts"].update(sha256="0" * 64),
                lambda: manifest.pop("counts"),
            ):
                with self.subTest(mutation=mutation):
                    candidate = deepcopy(manifest)
                    mutation()
                    with self.assertRaises(LOAD.LoadError):
                        check()
                    manifest = candidate
            manifest_path.unlink()
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_dhcp_output_sources(mappings)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (directory / "dhcpd.conf").write_bytes(b"")
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_dhcp_output_sources(mappings)
            (directory / "dhcpd.conf").write_bytes(b"valid generated DHCP text\n")
            (directory / "dhcpd_eth.hosts").write_bytes(b"")
            manifest["counts"]["host_declarations_by_family"]["eth"] = 0
            manifest["outputs"]["dhcpd_eth.hosts"]["sha256"] = hashlib.sha256(b"").hexdigest()
            with self.assertRaises(LOAD.LoadError):
                check()

    def test_zero_byte_subnet_is_invalid_in_both_dhcp_modes(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(b"")
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            for settings in (
                disabled,
                LOAD.replace(disabled, dhcp_enabled=True),
                LOAD.replace(disabled, ztp_enabled=True),
            ):
                with self.subTest(dhcp=settings.dhcp_enabled, ztp=settings.ztp_enabled):
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.apply_subnet_service_ips(settings, subnet)
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.validate_subnet_file(subnet, settings)
            for allow_empty in (False, True):
                with self.subTest(setup_allows_no_rows=allow_empty):
                    errors, _warnings = SETUP._validate_subnet_csv(
                        subnet, dhcp_enabled=not allow_empty,
                        ztp_enabled=not allow_empty,
                    )
                    self.assertTrue(errors, "zero bytes cannot be an empty CSV table")

    def test_missing_whitespace_and_symlink_subnet_are_never_valid_inputs(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            subnet = root / "02-dhcp-subnet_config.csv"
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            with self.assertRaises(LOAD.LoadError):
                LOAD.apply_subnet_service_ips(disabled, subnet)
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_subnet_file(subnet, disabled)
            for payload in (b" \t\r\n", b"wrong,columns\n"):
                subnet.write_bytes(payload)
                with self.subTest(payload=payload):
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.apply_subnet_service_ips(disabled, subnet)
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.validate_subnet_file(subnet, disabled)
                    errors, _warnings = SETUP._validate_subnet_csv(
                        subnet, dhcp_enabled=False, ztp_enabled=False,
                    )
                    self.assertTrue(errors)
            source = root / "elsewhere.csv"
            source.write_bytes(EMPTY_SUBNET_TABLE)
            subnet.unlink()
            subnet.symlink_to(source)
            with self.assertRaises(LOAD.LoadError):
                LOAD.apply_subnet_service_ips(disabled, subnet)
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_subnet_file(subnet, disabled)
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors, "setup must reject a symlinked source CSV")

    def test_subnet_replacement_after_lstat_is_rejected_by_setup_and_load(self):
        """Both real readers must verify the opened file, not a stale path stat."""
        disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
        for reader in ("setup", "load"):
            with self.subTest(reader=reader), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                subnet = root / "02-dhcp-subnet_config.csv"
                subnet.write_bytes(EMPTY_SUBNET_TABLE)
                alternate = root / "alternate.csv"
                alternate.write_bytes(EMPTY_SUBNET_TABLE)
                original_lstat = os.lstat if reader == "setup" else Path.lstat
                swapped = False

                def replace_after_stat(path, *args, **kwargs):
                    nonlocal swapped
                    metadata = original_lstat(path, *args, **kwargs)
                    if os.fspath(path) == os.fspath(subnet) and not swapped:
                        swapped = True
                        subnet.unlink()
                        subnet.symlink_to(alternate)
                    return metadata

                patcher = (
                    mock.patch.object(os, "lstat", side_effect=replace_after_stat)
                    if reader == "setup" else
                    mock.patch.object(Path, "lstat", new=replace_after_stat)
                )
                with patcher:
                    if reader == "setup":
                        errors, _warnings = SETUP._validate_subnet_csv(
                            subnet, dhcp_enabled=False, ztp_enabled=False,
                        )
                        self.assertTrue(errors, "setup followed replacement symlink")
                    else:
                        with self.assertRaises(LOAD.LoadError):
                            LOAD.validate_subnet_file(subnet, disabled)
                self.assertTrue(swapped, "race injection did not run")

    def test_header_only_subnet_is_optional_but_malformed_nonempty_is_not(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
            self.assertEqual(disabled, LOAD.apply_subnet_service_ips(disabled, subnet))
            LOAD.validate_subnet_file(subnet, disabled)
            self.assertEqual(([], []), SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            ))
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_subnet_file(subnet, LOAD.replace(disabled, dhcp_enabled=True))
            subnet.write_text("subnet,bad\n", encoding="utf-8")
            with self.assertRaises(LOAD.LoadError):
                LOAD.apply_subnet_service_ips(disabled, subnet)
            with self.assertRaises(LOAD.LoadError):
                LOAD.validate_subnet_file(subnet, disabled)
            errors, _ = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors)

    def test_native_handoff_requires_explicit_server_role_without_changing_docker(self):
        guidance = DHCP._production_handoff_text()
        native = next(
            line.removeprefix("[NEXT] Native/systemd：")
            for line in guidance.splitlines()
            if line.startswith("[NEXT] Native/systemd：")
        )
        self.assertEqual(
            "sudo python3 DAY0-Prepare/11-load.py DAY0-Prepare/<project> "
            "--host-role=management-server", native,
        )
        for command in (
            "sudo ./infra/docker/deploy.sh deploy",
            "sudo ./infra/docker/deploy.sh deploy-preloaded <IMAGE_ID>",
            "sudo ./infra/docker/deploy.sh load",
        ):
            self.assertIn(command, guidance)

    @staticmethod
    def _real_one_listener_plan(root: Path, status: str):
        subnet = root / "02-dhcp-subnet_config.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no\n",
            encoding="utf-8",
        )
        links = [{
            "ifindex": 7, "ifname": "eno7", "link_type": "ether",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "operstate": "UP",
        }]
        addresses = [{
            "ifindex": 7, "ifname": "eno7", "addr_info": [{
                "family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                "scope": "global",
            }],
        }]
        inputs = SimpleNamespace(subnet_file=subnet, settings=settings_for(status))
        return LOAD.plan_local_dhcp_runtime(
            inputs, link_snapshot=links, address_snapshot=addresses,
            environment={},
        )

    def test_real_disabled_runtime_plan_rejects_ztp_endpoint_without_dhcp(self):
        with tempfile.TemporaryDirectory() as name:
            enabled = self._real_one_listener_plan(Path(name), "enabled")
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP disabled.*ZTP enabled"):
                self._real_one_listener_plan(Path(name), "disabled")
        self.assertEqual(("eno7",), enabled.listener_names)
        self.assertEqual((7,), enabled.listener_ifindexes)
        self.assertEqual(("192.0.2.10",), enabled.endpoint_ips)

    def test_disabled_supervisor_rejects_nonempty_real_listener_plan(self):
        with tempfile.TemporaryDirectory() as name:
            enabled_plan = self._real_one_listener_plan(Path(name), "enabled")
        self.assertEqual(("eno7",), enabled_plan.listener_names)
        disabled_inputs = SimpleNamespace(settings=settings_for("disabled"))
        with mock.patch.object(
            LOAD, "validate_management_host", return_value=True,
        ), self.assertRaisesRegex(LOAD.LoadError, "DHCP listener 规划非空"):
            LOAD.supervisor_service_availability(disabled_inputs, enabled_plan)

    def test_literal_enabled_and_disabled_are_distinct(self):
        self.assertTrue(settings_for("enabled").dhcp_enabled)
        self.assertFalse(settings_for("disabled").dhcp_enabled)

    def test_case_and_outer_whitespace_are_tolerated_without_boolean_aliases(self):
        self.assertTrue(settings_for(" ENABLED ").dhcp_enabled)
        self.assertFalse(settings_for(" Disabled ").dhcp_enabled)

    def test_status_key_absent_is_not_a_disabled_default(self):
        document = global_document()
        document["common"]["mgmt"]["dhcp-server"].pop("status")
        with self.assertRaisesRegex(LOAD.LoadError, _STATUS_LABEL):
            LOAD.load_global(Path("unused-global.yaml"), global_data=document)

    def test_dhcp_mapping_absent_has_its_own_missing_section_error(self):
        document = global_document()
        document["common"]["mgmt"].pop("dhcp-server")
        with self.assertRaisesRegex(
            LOAD.LoadError, "global 缺少 common.mgmt.dhcp-server/http/ztp",
        ):
            LOAD.load_global(Path("unused-global.yaml"), global_data=document)

    def test_dhcp_status_does_not_change_http_or_ztp_siblings(self):
        enabled = settings_for("enabled")
        disabled = settings_for("disabled")
        self.assertEqual(enabled.http_enabled, disabled.http_enabled)
        self.assertEqual(enabled.ztp_enabled, disabled.ztp_enabled)
        self.assertEqual(enabled.http_port, disabled.http_port)

    def test_disabled_dhcp_keeps_eligible_native_http_available(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            ztp_ips={"air_oob": ("192.0.2.10",)},
        )
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"},
        ), mock.patch.object(LOAD, "warn") as warning, mock.patch.object(
            LOAD, "info",
        ) as information:
            self.assertTrue(LOAD.validate_management_host(settings))
        report = " ".join(
            str(call) for call in (*warning.call_args_list, *information.call_args_list)
        )
        self.assertIn("dhcp-server", report)

    def test_disabled_dhcp_keeps_http_only_supervisor_plan_available(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            ztp_ips={"air_oob": ("192.0.2.10",)},
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=("192.0.2.10",))
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"},
        ), mock.patch.object(LOAD, "warn"), mock.patch.object(LOAD, "info"):
            self.assertEqual(
                (True, False), LOAD.supervisor_service_availability(inputs, plan),
            )

    def test_r22_supervisor_http_only_uses_explicit_address_without_ztp_endpoint(self):
        """An off/off subnet cannot suppress an independently enabled HTTP service."""
        settings = LOAD.replace(
            settings_for("disabled"), ztp_enabled=False,
            http_enabled=True, http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.88", ztp_ips={}, boot_ips=(),
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        backend = SimpleNamespace(name="supervisor")
        actions = []
        commands = []
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.88"},
        ), mock.patch.object(LOAD, "verify_control_auth"), \
                mock.patch.object(LOAD, "verify_published_files"), \
                mock.patch.object(LOAD, "verify_apache_publication_boundary"), \
                mock.patch.object(LOAD, "verify_http_publication") as published, \
                mock.patch.object(LOAD, "ensure_ztp_url_network_ready") as ztp_gate, \
                mock.patch.object(LOAD, "_runtime_service_action",
                                  side_effect=lambda _backend, action, service, **_kw:
                                  actions.append((action, service))), \
                mock.patch.object(LOAD, "run",
                                  side_effect=lambda command, **_kw: commands.append(command)):
            self.assertEqual(
                (True, False), LOAD.supervisor_service_availability(inputs, plan),
            )
            LOAD.preflight_services(
                inputs, {}, dry_run=True, dhcp_runtime_plan=plan,
                runtime_backend=backend,
            )
            LOAD.start_services(
                inputs, {}, dry_run=True, dhcp_runtime_plan=plan,
                runtime_backend=backend,
            )
        self.assertIn("apache2ctl configtest", " ".join(map(str, commands[0])))
        self.assertEqual([("start", "apache2")], actions)
        published.assert_called_once_with(inputs, {}, True)
        ztp_gate.assert_not_called()

    def test_r22_supervisor_http_only_requires_local_address_before_actions(self):
        settings = LOAD.replace(
            settings_for("disabled"), ztp_enabled=False,
            http_enabled=True, http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.88", ztp_ips={}, boot_ips=(),
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.99"},
        ), mock.patch.object(LOAD, "_runtime_service_action") as action, \
                mock.patch.object(LOAD, "run") as run:
            with self.assertRaisesRegex(LOAD.LoadError, "管理服务器门禁"):
                LOAD.supervisor_service_availability(inputs, plan)
            with self.assertRaisesRegex(LOAD.LoadError, "管理服务器门禁"):
                LOAD.start_services(
                    inputs, {}, dry_run=True, dhcp_runtime_plan=plan,
                    runtime_backend=SimpleNamespace(name="supervisor"),
                )
        action.assert_not_called()
        run.assert_not_called()

    def test_r22_supervisor_http_disabled_and_dhcp_only_never_infer_apache(self):
        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        disabled = LOAD.replace(
            settings_for("disabled"), ztp_enabled=False,
            http_enabled=False, http_address="192.0.2.88", ztp_ips={},
            boot_ips=(),
        )
        self.assertEqual(
            (False, False), LOAD.supervisor_service_availability(
                SimpleNamespace(settings=disabled), plan,
            ),
        )
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.88"},
        ), self.assertRaisesRegex(LOAD.LoadError, "管理服务器门禁"):
            LOAD.supervisor_service_availability(
                SimpleNamespace(settings=disabled),
                SimpleNamespace(listener_names=(), endpoint_ips=("192.0.2.88",)),
            )
        dhcp_only = LOAD.replace(disabled, dhcp_enabled=True)
        relay = SimpleNamespace(listener_names=("eno7",), endpoint_ips=())
        self.assertEqual(
            (False, True), LOAD.supervisor_service_availability(
                SimpleNamespace(settings=dhcp_only), relay,
            ),
        )
        actions = []
        with tempfile.TemporaryDirectory() as project_directory, \
                mock.patch.object(LOAD, "validate_dhcp_output_sources"), \
                mock.patch.object(LOAD, "run") as run, \
                mock.patch.object(LOAD, "ensure_ztp_url_network_ready") as ztp_gate, \
                mock.patch.object(LOAD, "verify_http_publication") as publication, \
                mock.patch.object(
                    LOAD, "_runtime_service_action",
                    side_effect=lambda _backend, action, service, **_kw:
                    actions.append((action, service)),
                ):
            LOAD.preflight_services(
                SimpleNamespace(settings=dhcp_only,
                    global_file=Path(project_directory) / "01-global.yaml"), {}, dry_run=True,
                dhcp_runtime_plan=relay,
                runtime_backend=SimpleNamespace(name="supervisor"),
            )
            LOAD.start_services(
                SimpleNamespace(settings=dhcp_only), {}, dry_run=True,
                dhcp_runtime_plan=relay,
                runtime_backend=SimpleNamespace(name="supervisor"),
            )
        self.assertEqual([("restart", "isc-dhcp-server")], actions)
        self.assertFalse(any("apache2ctl" in str(call) for call in run.call_args_list))
        ztp_gate.assert_not_called()
        publication.assert_not_called()

    def test_disabled_dhcp_native_preflight_checks_http_without_dhcp_outputs(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            ztp_ips={"air_oob": ("192.0.2.10",)},
        )
        inputs = SimpleNamespace(settings=settings)
        commands = []
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"},
        ), mock.patch.object(LOAD, "verify_control_auth"), mock.patch.object(
            LOAD, "verify_published_files",
        ), mock.patch.object(LOAD, "verify_apache_publication_boundary"), mock.patch.object(
            LOAD, "dhcp_file_mappings", side_effect=AssertionError("read DHCP outputs"),
        ), mock.patch.object(
            LOAD, "run", side_effect=lambda command, **_kw: commands.append(command),
        ), mock.patch.object(LOAD, "warn"), mock.patch.object(LOAD, "info"):
            LOAD.preflight_services(
                inputs, {}, runtime_backend=SimpleNamespace(name="systemd"),
            )
        command_text = " ".join(" ".join(map(str, command)) for command in commands)
        self.assertIn("apache2ctl configtest", command_text)
        self.assertNotIn("dhcpd -t", command_text)

    def test_disabled_dhcp_native_start_keeps_active_apache_and_does_not_start_dhcp(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            ztp_ips={"air_oob": ("192.0.2.10",)},
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=("192.0.2.10",))
        states = {
            "apache2": LOAD.ServiceRuntimeState(enabled=True, active=True),
            "isc-dhcp-server": LOAD.ServiceRuntimeState(enabled=False, active=False),
        }
        commands = []
        with mock.patch.object(LOAD, "ensure_ztp_url_network_ready"), mock.patch.object(
            LOAD, "snapshot_service_states", return_value=states,
        ), mock.patch.object(
            LOAD, "run", side_effect=lambda command, **_kw: commands.append(command),
        ), mock.patch.object(LOAD, "verify_http_publication") as verify_http:
            LOAD.start_services(
                inputs, {}, dhcp_runtime_plan=plan,
                runtime_backend=SimpleNamespace(name="systemd"),
            )
        command_text = " ".join(" ".join(map(str, command)) for command in commands)
        self.assertNotIn("systemctl stop apache2", command_text)
        self.assertNotIn("systemctl start isc-dhcp-server", command_text)
        self.assertNotIn("systemctl restart isc-dhcp-server", command_text)
        verify_http.assert_called_once_with(inputs, {}, False)

    def test_disabled_status_still_rejects_nonempty_listener_plan(self):
        disabled = SimpleNamespace(settings=settings_for("disabled"))
        enabled = SimpleNamespace(settings=settings_for("enabled"))
        plan = SimpleNamespace(listener_names=("eno7",), endpoint_ips=())
        with self.assertRaisesRegex(LOAD.LoadError, "DHCP listener 规划非空"):
            LOAD.supervisor_service_availability(disabled, plan)
        with mock.patch.object(LOAD, "info"):
            self.assertEqual(
                (False, True), LOAD.supervisor_service_availability(enabled, plan),
            )

    def test_disabled_status_still_omits_infra_install_flag(self):
        settings = LOAD.replace(
            settings_for("disabled"), ztp_ips={"air_oob": ("192.0.2.10",)},
        )
        inputs = SimpleNamespace(
            settings=settings, global_file=Path("01-global.yaml"),
            devices_file=Path("02-devices_config.csv"),
        )
        with mock.patch.object(LOAD, "run") as runner:
            LOAD.prepare_infra(inputs, dry_run=True, skip_doca=True)
        self.assertEqual(2, runner.call_count)
        self.assertNotIn("--install-dhcp", runner.call_args_list[-1].args[0])


# One independent test ID per illegal token: accepting one cannot be hidden by
# another still failing inside an aggregated assertRaises loop.
_ILLEGAL = {
    "true_string": "true", "false_string": "false", "yes": "yes",
    "no": "no", "on": "on", "off": "off", "zero": "0",
    "one": "1", "empty": "", "tilde": "~", "null": None,
    "python_boolean": False, "unrelated": "enable",
}

# These are source tokens, not already-decoded Python values. PyYAML coerces
# yes/on to bool and unquoted numerals to int before load_global sees them.
_YAML_COERCED_ILLEGAL = {
    "yes_boolean_true": ("yes", True),
    "on_boolean_true": ("on", True),
    "integer_zero": ("0", 0),
    "integer_one": ("1", 1),
}


def _illegal_case(value: object):
    def test(self):
        document = global_document(value)
        self.assertEqual(value, document["common"]["mgmt"]["dhcp-server"]["status"])
        with self.assertRaisesRegex(LOAD.LoadError, _STATUS_LABEL):
            LOAD.load_global(Path("unused-global.yaml"), global_data=document)
    return test


for _case_id, _case_value in _ILLEGAL.items():
    setattr(
        DhcpOptionalDirectTests, f"test_rejects_illegal_status_{_case_id}",
        _illegal_case(_case_value),
    )


def _yaml_coerced_illegal_case(token: str, expected: object):
    def test(self):
        anchor = "    dhcp-server:\n      status: enabled\n"
        self.assertEqual(1, _TEMPLATE_TEXT.count(anchor))
        source = _TEMPLATE_TEXT.replace(
            anchor, f"    dhcp-server:\n      status: {token}\n", 1,
        )
        parsed = yaml.safe_load(source)
        actual = parsed["common"]["mgmt"]["dhcp-server"]["status"]
        self.assertIs(type(expected), type(actual))
        self.assertEqual(expected, actual)
        with tempfile.TemporaryDirectory() as name:
            global_path = Path(name) / "01-global.yaml"
            global_path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, _STATUS_LABEL):
                LOAD.load_global(global_path)
    return test


for _case_id, (_token, _expected) in _YAML_COERCED_ILLEGAL.items():
    setattr(
        DhcpOptionalDirectTests, f"test_rejects_yaml_coerced_status_{_case_id}",
        _yaml_coerced_illegal_case(_token, _expected),
    )


if __name__ == "__main__":
    unittest.main()
