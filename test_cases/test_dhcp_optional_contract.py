#!/usr/bin/env python3
"""Direct contract for the fail-closed DHCP enable/disable authority."""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import importlib.util
import io
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
from test_cases import test_load_release_transaction as release_fixture


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
SETUP = load_script("r22_csv_setup_direct", ROOT / "DAY0-Prepare/01-a-setup.py")
RUNTIME = load_script("r22_csv_runtime_direct", ROOT / "tools/ztp_service_runtime.py")
ACTIVATE = load_script("r22_subnet_identity_docker_direct", ROOT / "infra/docker/activate.py")

_TEMPLATE_TEXT = (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
    encoding="utf-8"
)
_TEMPLATE = yaml.safe_load(_TEMPLATE_TEXT)
_STATUS_LABEL = "common.mgmt.dhcp-server.status"
_R22_SUBNET_HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)
_R22_ACTIVE_ROW = (
    "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
    "192.0.2.1,192.0.2.10,oob,no\n"
)


def global_document(status: object = "disabled") -> dict[str, object]:
    """Fresh, otherwise-valid input; package and siblings cannot pre-empt status."""
    document = deepcopy(_TEMPLATE)
    document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
    document["common"]["mgmt"]["dhcp-server"]["status"] = status
    if isinstance(status, str) and status.strip().casefold() == "disabled":
        # R22 forbids DHCP-off/ZTP-on.  Keep ordinary disabled fixtures legal;
        # dedicated matrix tests above construct the illegal combination.
        document["common"]["mgmt"]["ztp"]["status"] = "disabled"
    return document


def settings_for(status: str):
    return LOAD.load_global(Path("unused-global.yaml"), global_data=global_document(status))


class DhcpOptionalDirectTests(unittest.TestCase):
    def test_f02_infra_cli_describes_explicit_http_input_as_required(self):
        deploy = load_script(
            "f02_infra_http_cli_help", ROOT / "infra/deploy_infra.py",
        )
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["deploy_infra.py", "--help"]), \
                mock.patch.object(sys, "stdout", output), \
                self.assertRaises(SystemExit) as stopped:
            deploy.parse_args()
        self.assertEqual(0, stopped.exception.code)
        self.assertIn("必须显式指定 HTTP Server IPv4", output.getvalue())
        self.assertNotIn("特殊环境显式指定", output.getvalue())

    def test_f02_infra_consumer_refuses_route_derived_http_authority(self):
        deploy = load_script(
            "f02_direct_infra_http_authority", ROOT / "infra/deploy_infra.py",
        )
        servers = [{"hostname": "server-a", "address": "192.0.2.50"}]
        with mock.patch.object(
            deploy, "detect_route_source_ipv4",
            side_effect=AssertionError("route-derived HTTP authority"),
        ), self.assertRaisesRegex(deploy.DeployError, "--http-server-ip"):
            deploy.determine_http_source_ip(servers)

    def test_f02_http_address_never_falls_back_to_subnet_ztp_service_ip(self):
        settings = LOAD.replace(
            settings_for("enabled"),
            ztp_ips={"eth": ("192.0.2.10",)},
            http_address=None,
        )
        with mock.patch.object(
            LOAD, "local_ipv4_addresses",
            side_effect=AssertionError("subnet fallback consulted local addresses"),
        ), self.assertRaisesRegex(LOAD.LoadError, "common.mgmt.http.address"):
            LOAD.select_http_ip(settings)
        explicit = LOAD.replace(settings, http_address="198.51.100.20")
        self.assertEqual("198.51.100.20", LOAD.select_http_ip(explicit))

    def test_f02_disabled_http_never_creates_listener_from_explicit_address(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_enabled=False,
            http_address="198.51.100.20", ztp_ips={},
        )
        self.assertEqual((), settings.http_listener_ips)

    def test_r22_docker_observation_rejects_same_size_subnet_path_replacement(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            project = root / "DAY0-Prepare" / "fixture"
            project.mkdir(parents=True)
            document = global_document("disabled")
            document["common"]["mgmt"]["http"]["status"] = "disabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type,mac\n", encoding="utf-8",
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER + " \n", encoding="utf-8")
            replacement = project / "replacement.csv"
            replacement.write_text(_R22_SUBNET_HEADER + "\t\n", encoding="utf-8")
            self.assertEqual(subnet.stat().st_size, replacement.stat().st_size)
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=root,
                state_root=root / "state", log_root=root / "log",
                apache_listeners=root / "apache.conf",
                dhcp_leases=root / "dhcp" / "leases",
            )
            actual_plan = RUNTIME.plan_dhcp_runtime
            switched = False

            def replace_after_parse(*args, **kwargs):
                nonlocal switched
                plan = actual_plan(*args, **kwargs)
                if not switched:
                    subnet.rename(project / "old-subnet.csv")
                    replacement.rename(subnet)
                    switched = True
                return plan

            with mock.patch.object(
                ACTIVATE, "capture_stable_network_snapshot", return_value=([], []),
            ), mock.patch.object(
                ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
            ), mock.patch.object(
                RUNTIME, "plan_dhcp_runtime", side_effect=replace_after_parse,
            ), mock.patch.object(
                ACTIVATE, "ensure_runtime_directories",
            ) as mkdir, mock.patch.object(ACTIVATE, "_atomic_write") as write:
                with self.assertRaisesRegex(ACTIVATE.ActivationError, "subnet.*(changed|drift)"):
                    ACTIVATE.observe_runtime(settings)
            self.assertTrue(switched)
            mkdir.assert_not_called()
            write.assert_not_called()
            self.assertFalse(settings.state_root.exists())

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
        selected = status == "enabled"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            + ("192.0.2.1,192.0.2.10,oob,no\n" if selected else
               "192.0.2.1,,none,no\n"),
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

    def test_real_disabled_runtime_plan_keeps_http_endpoint_without_dhcp_listener(self):
        with tempfile.TemporaryDirectory() as name:
            enabled = self._real_one_listener_plan(Path(name), "enabled")
            disabled = self._real_one_listener_plan(Path(name), "disabled")
        self.assertEqual(("eno7",), enabled.listener_names)
        self.assertEqual((7,), enabled.listener_ifindexes)
        self.assertEqual(("192.0.2.10",), enabled.endpoint_ips)
        self.assertEqual((), disabled.endpoint_ips)
        self.assertEqual((), disabled.listener_names)
        self.assertEqual((), disabled.listener_ifindexes)
        self.assertEqual(
            ("192.0.2.10",),
            LOAD.replace(settings_for("disabled"), http_address="192.0.2.10").http_listener_ips,
        )

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
        enabled_document = global_document("enabled")
        enabled_document["common"]["mgmt"]["ztp"]["status"] = "disabled"
        enabled = LOAD.load_global(
            Path("unused-global.yaml"), global_data=enabled_document,
        )
        disabled = settings_for("disabled")
        self.assertEqual(enabled.http_enabled, disabled.http_enabled)
        self.assertEqual(enabled.ztp_enabled, disabled.ztp_enabled)
        self.assertEqual(enabled.http_port, disabled.http_port)

    def test_disabled_dhcp_keeps_eligible_native_http_available(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.10",
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
            http_address="192.0.2.10",
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=("192.0.2.10",))
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"},
        ), mock.patch.object(LOAD, "warn"), mock.patch.object(LOAD, "info"):
            self.assertEqual(
                (True, False), LOAD.supervisor_service_availability(inputs, plan),
            )

    def test_supervisor_http_authority_is_independent_of_dhcp_listener(self):
        disabled_http = LOAD.replace(
            settings_for("disabled"), http_enabled=False, http_address="",
        )
        explicit_http = LOAD.replace(
            settings_for("disabled"), http_enabled=True,
            http_address="192.0.2.10",
        )
        enabled_dhcp = LOAD.replace(
            settings_for("enabled"), http_enabled=False, http_address="",
        )
        cases = (
            (disabled_http, (), (), False),
            (enabled_dhcp, ("eno7",), (), False),
            (explicit_http, (), (), True),
            (disabled_http, (), ("192.0.2.10",), True),
        )
        for settings, listeners, endpoints, expected in cases:
            with self.subTest(listeners=listeners, endpoints=endpoints,
                              expected=expected):
                inputs = SimpleNamespace(settings=settings)
                plan = SimpleNamespace(listener_names=listeners,
                                       endpoint_ips=endpoints)
                self.assertIs(expected,
                              LOAD.supervisor_http_required(inputs, plan))

    def test_disabled_dhcp_real_plan_keeps_explicit_http_available_to_supervisor(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.10",
        )
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
            inputs = SimpleNamespace(settings=settings, subnet_file=subnet)
            with mock.patch.object(
                LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"},
            ), mock.patch.object(LOAD, "warn"), mock.patch.object(LOAD, "info"):
                plan = LOAD.plan_local_dhcp_runtime(inputs)
                self.assertEqual((), plan.listener_names)
                self.assertEqual((), plan.listener_ifindexes)
                self.assertEqual(
                    (True, False),
                    LOAD.supervisor_service_availability(inputs, plan),
                )

    def test_disabled_dhcp_real_plan_preflights_and_starts_only_supervisor_http(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.10",
        )
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
            inputs = SimpleNamespace(settings=settings, subnet_file=subnet)
            plan = LOAD.plan_local_dhcp_runtime(inputs)
            backend = SimpleNamespace(name="supervisor")
            actions = []
            commands = []
            with mock.patch.object(LOAD, "ensure_ztp_url_network_ready"), \
                    mock.patch.object(LOAD, "verify_control_auth") as control, \
                    mock.patch.object(LOAD, "verify_published_files") as published, \
                    mock.patch.object(LOAD, "verify_apache_publication_boundary"), \
                    mock.patch.object(LOAD, "verify_http_publication") as verified, \
                    mock.patch.object(LOAD, "dhcp_file_mappings", side_effect=AssertionError("DHCP read")), \
                    mock.patch.object(LOAD, "run", side_effect=lambda command, **kw: commands.append((command, kw))), \
                    mock.patch.object(LOAD, "_runtime_service_action", side_effect=lambda _backend, action, service, **kw: actions.append((action, service, kw))):
                LOAD.preflight_services(
                    inputs, {}, dry_run=True,
                    dhcp_runtime_plan=plan, runtime_backend=backend,
                )
                LOAD.start_services(
                    inputs, {}, dry_run=True,
                    dhcp_runtime_plan=plan, runtime_backend=backend,
                )
            control.assert_called_once()
            published.assert_called_once()
            verified.assert_called_once_with(inputs, {}, True)
            self.assertEqual([("start", "apache2", {"dry_run": True})], actions)
            self.assertTrue(all(kw.get("dry_run") is True for _, kw in commands))
            self.assertIn("apache2ctl configtest", " ".join(
                " ".join(map(str, command)) for command, _ in commands
            ))

    def test_empty_supervisor_plan_with_http_off_has_no_service_actions(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_enabled=False, http_address="",
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        backend = SimpleNamespace(name="supervisor")
        with mock.patch.object(LOAD, "validate_management_host") as host, \
                mock.patch.object(LOAD, "verify_control_auth") as control, \
                mock.patch.object(LOAD, "dhcp_file_mappings") as dhcp_files, \
                mock.patch.object(LOAD, "run") as runner, \
                mock.patch.object(LOAD, "_runtime_service_action") as service, \
                mock.patch.object(LOAD, "ensure_ztp_url_network_ready") as network:
            self.assertEqual(
                (False, False),
                LOAD.supervisor_service_availability(inputs, plan),
            )
            LOAD.preflight_services(
                inputs, {}, dry_run=True,
                dhcp_runtime_plan=plan, runtime_backend=backend,
            )
            LOAD.start_services(
                inputs, {}, dry_run=True,
                dhcp_runtime_plan=plan, runtime_backend=backend,
            )
        for action in (host, control, dhcp_files, runner, service, network):
            action.assert_not_called()

    def test_explicit_supervisor_http_refuses_nonlocal_address_before_actions(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.10",
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        with mock.patch.object(
            LOAD, "local_ipv4_addresses", return_value={"192.0.2.11"},
        ), mock.patch.object(LOAD, "_runtime_service_action") as service:
            with self.assertRaisesRegex(LOAD.LoadError, "门禁未通过"):
                LOAD.supervisor_service_availability(inputs, plan)
        service.assert_not_called()

    def test_dhcp_only_supervisor_plan_never_starts_apache(self):
        settings = LOAD.replace(
            settings_for("enabled"), http_enabled=False, http_address="",
            ztp_enabled=False,
        )
        inputs = SimpleNamespace(settings=settings)
        plan = SimpleNamespace(listener_names=("eno7",), endpoint_ips=())
        backend = SimpleNamespace(name="supervisor")
        with mock.patch.object(LOAD, "validate_management_host") as host, \
                mock.patch.object(LOAD, "ensure_ztp_url_network_ready") as network, \
                mock.patch.object(LOAD, "verify_http_publication") as http, \
                mock.patch.object(LOAD, "_runtime_service_action") as service:
            self.assertEqual(
                (False, True),
                LOAD.supervisor_service_availability(inputs, plan),
            )
            LOAD.start_services(
                inputs, {}, dry_run=True,
                dhcp_runtime_plan=plan, runtime_backend=backend,
            )
        host.assert_not_called()
        network.assert_not_called()
        http.assert_not_called()
        service.assert_called_once_with(
            backend, "restart", "isc-dhcp-server", dry_run=True,
        )

    def test_supervisor_dry_run_service_and_command_runners_do_not_mutate(self):
        backend = SimpleNamespace(
            name="supervisor",
            start=mock.Mock(side_effect=AssertionError("service mutation")),
        )
        with mock.patch.object(
            LOAD, "_run_subprocess",
            side_effect=AssertionError("subprocess mutation"),
        ):
            LOAD._runtime_service_action(
                backend, "start", "apache2", dry_run=True,
            )
            LOAD.run(["apache2ctl", "configtest"], dry_run=True)
        backend.start.assert_not_called()

    def test_disabled_dhcp_native_preflight_checks_http_without_dhcp_outputs(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.10",
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
            http_address="192.0.2.10",
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
        disabled = SimpleNamespace(settings=LOAD.replace(
            settings_for("disabled"), http_enabled=False,
        ))
        enabled = SimpleNamespace(settings=LOAD.replace(
            settings_for("enabled"), http_enabled=False,
        ))
        plan = SimpleNamespace(listener_names=("eno7",), endpoint_ips=())
        with self.assertRaisesRegex(LOAD.LoadError, "DHCP listener 规划非空"):
            LOAD.supervisor_service_availability(disabled, plan)
        with mock.patch.object(LOAD, "info"):
            self.assertEqual(
                (False, True), LOAD.supervisor_service_availability(enabled, plan),
            )

    def test_disabled_status_still_omits_infra_install_flag(self):
        settings = LOAD.replace(
            settings_for("disabled"), http_address="192.0.2.10",
        )
        inputs = SimpleNamespace(
            settings=settings, global_file=Path("01-global.yaml"),
            devices_file=Path("02-devices_config.csv"),
        )
        with mock.patch.object(LOAD, "run") as runner:
            LOAD.prepare_infra(inputs, dry_run=True, skip_doca=True)
        self.assertEqual(2, runner.call_count)
        self.assertNotIn("--install-dhcp", runner.call_args_list[-1].args[0])


class R22LoadInputMatrixTests(unittest.TestCase):
    @staticmethod
    def _settings(dhcp: str, ztp: str):
        document = global_document(dhcp)
        document["common"]["mgmt"]["ztp"]["status"] = ztp
        return LOAD.load_global(Path("unused-global.yaml"), global_data=document)

    def test_disabled_dhcp_with_enabled_ztp_is_rejected_before_any_input_write(self):
        with self.assertRaisesRegex(LOAD.LoadError, "DHCP disabled.*ZTP enabled"):
            self._settings("disabled", "enabled")

    def test_header_only_is_valid_only_for_both_modes_disabled(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER + "\n \n", encoding="utf-8")
            off_off = self._settings("disabled", "disabled")
            self.assertEqual((), LOAD.apply_subnet_service_ips(off_off, subnet).service_ips)
            LOAD.validate_subnet_file(subnet, off_off)
            with self.assertRaisesRegex(LOAD.LoadError, "subnet 记录"):
                LOAD.validate_subnet_file(
                    subnet, self._settings("enabled", "disabled"),
                )

    def test_zero_byte_and_whitespace_are_never_legal_empty_tables(self):
        for payload in ("", " \n\t\n"):
            with self.subTest(payload=repr(payload)), tempfile.TemporaryDirectory() as name:
                subnet = Path(name) / "02-dhcp-subnet_config.csv"
                subnet.write_text(payload, encoding="utf-8")
                for dhcp in ("enabled", "disabled"):
                    with self.subTest(dhcp=dhcp), self.assertRaises(LOAD.LoadError):
                        LOAD.validate_subnet_file(
                            subnet, self._settings(dhcp, "disabled"),
                        )

    def test_delimiter_only_record_is_not_an_empty_subnet_table(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(
                _R22_SUBNET_HEADER + "\n \n,,,,,,,,\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(LOAD.LoadError, "第 4 行.*空字段"):
                LOAD.validate_subnet_file(
                    subnet, self._settings("disabled", "disabled"),
                )

    def test_global_ztp_disabled_rejects_selected_platform_row_with_line(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER + "\n" + _R22_ACTIVE_ROW, encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "第 3 行.*ZTP"):
                LOAD.validate_subnet_file(
                    subnet, self._settings("enabled", "disabled"),
                )

    def test_dhcp_enabled_ztp_disabled_still_checks_native_dhcp_configuration(self):
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / "dhcpd.conf"
            source.write_text("default-lease-time 600;\n", encoding="utf-8")
            inputs = SimpleNamespace(settings=LOAD.replace(
                self._settings("enabled", "disabled"), http_enabled=False,
            ))
            commands = []
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=[source]), \
                    mock.patch.object(LOAD, "run", side_effect=lambda command, **_kw: commands.append(command)):
                LOAD.preflight_services(
                    inputs, {}, runtime_backend=SimpleNamespace(name="systemd"),
                )
            flattened = " ".join(" ".join(map(str, command)) for command in commands)
            self.assertIn("dhcpd -t", flattened)
            self.assertNotIn("apache2ctl configtest", flattened)

    def test_disabled_runtime_plan_keeps_csv_validation_without_local_dhcp_listener(self):
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER + "\n", encoding="utf-8")
            inputs = SimpleNamespace(
                subnet_file=subnet, settings=self._settings("disabled", "disabled"),
            )
            plan = LOAD.plan_local_dhcp_runtime(
                inputs, link_snapshot=[], address_snapshot=[], environment={},
            )
            self.assertEqual((), plan.listener_names)
            self.assertEqual((), plan.endpoint_ips)
            subnet.write_text(
                _R22_SUBNET_HEADER
                + "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
                  "192.0.2.1,,none,no\n",
                encoding="utf-8",
            )
            plan = LOAD.plan_local_dhcp_runtime(
                inputs, link_snapshot=[], address_snapshot=[], environment={},
            )
            self.assertEqual((), plan.listener_names)
            subnet.write_text(_R22_SUBNET_HEADER + "mgmt,not-ip,,,,,,,\n", encoding="utf-8")
            with self.assertRaises(LOAD.LoadError):
                LOAD.plan_local_dhcp_runtime(
                    inputs, link_snapshot=[], address_snapshot=[], environment={},
                )


class R22CsvConsumerMatrixTests(unittest.TestCase):
    """Literal CSV expectations, independent of either consumer's parser."""

    _CASES = (
        ("missing file", None, True),
        ("zero-byte", "", True),
        ("whitespace-only", " \t\n\r\n", True),
        ("bad canonical header", _R22_SUBNET_HEADER.replace(
            "shared_network", "shared_networb"), True),
        ("canonical header-only", _R22_SUBNET_HEADER, False),
        ("canonical header with tail whitespace", _R22_SUBNET_HEADER + " \t\n", False),
        ("delimiter-only record", _R22_SUBNET_HEADER + ",,,,,,,,\n", True),
    )

    def test_activation_accepts_manifest_proven_empty_unselected_for_ib_and_nvl(self):
        """The selected NVOS family has hosts; the other two can be 0B."""
        from test_cases.test_dhcp_optional_workflow import (
            prepare_r22_selected_nvos_core_flow,
        )

        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                flow, outputs, parent = prepare_r22_selected_nvos_core_flow(
                    Path(name), selected,
                )
                counts = {"eth": 0, "ib": 0, "nvl": 0}
                counts[selected] = 2 if selected == "ib" else 1
                child_path = outputs / "dhcp-release-manifest.json"
                child = json.loads(child_path.read_text(encoding="utf-8"))
                self.assertEqual(counts, child["counts"]["host_declarations_by_family"])
                self.assertEqual("prod", child["deployment_scope"])
                self.assertEqual(selected, child["switch_scope"])
                for family in ("eth", "ib", "nvl"):
                    output = outputs / f"dhcpd_{family}.hosts"
                    body = output.read_bytes()
                    self.assertEqual(family == selected, bool(body))
                    self.assertEqual(hashlib.sha256(body).hexdigest(),
                                     child["outputs"][output.name]["sha256"])
                    public = flow.dhcp / output.name
                    self.assertTrue(public.is_symlink())
                    self.assertEqual(output.resolve(strict=True),
                                     public.resolve(strict=True))
                current = flow.project / "99-output-ztp/current-release.json"
                self.assertEqual(parent["release_id"], json.loads(current.read_text())[
                    "release_id"
                ])
                self.assertEqual("passed", parent["validation"])
                self.assertEqual(selected, parent["switch_scope"])
                self.assertEqual(release_fixture.sha256(child_path),
                                 parent["components"]["dhcp"]["manifest_sha256"])
                settings = ACTIVATE.Settings(
                    project_name="demo", scope="prod", switch_scope=selected,
                    http_root=flow.root,
                )
                ACTIVATE.validate_project_mount(settings)
                self.assertEqual("enabled", ACTIVATE.current_project_dhcp_status(
                    settings,
                ))
                try:
                    ACTIVATE.validate_parent_release(settings, current)
                except ACTIVATE.ActivationError as exc:
                    self.fail(f"valid selected {selected} parent rejected: {exc}")

    def test_activation_rejects_selected_zero_even_with_matching_count_and_hash(self):
        """A selected family cannot be made empty by a consistent false count."""
        from test_cases.test_dhcp_optional_workflow import (
            prepare_r22_selected_nvos_core_flow,
        )

        basis_keys = (
            "project", "deployment_scope", "switch_scope", "inputs",
            "input_sources", "components", "inventory", "dhcp_status",
        )
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                flow, outputs, _parent = prepare_r22_selected_nvos_core_flow(
                    Path(name), selected,
                )
                selected_path = outputs / f"dhcpd_{selected}.hosts"
                child_path = outputs / "dhcp-release-manifest.json"
                current = flow.project / "99-output-ztp/current-release.json"
                before_parent = (current.read_bytes(), current.stat().st_ino,
                                 current.stat().st_mtime_ns)
                selected_path.write_bytes(b"")
                child = json.loads(child_path.read_text(encoding="utf-8"))
                child["counts"]["host_declarations_by_family"][selected] = 0
                child["outputs"][selected_path.name]["sha256"] = hashlib.sha256(
                    b""
                ).hexdigest()
                child_path.write_text(json.dumps(child), encoding="utf-8")
                altered_parent = json.loads(before_parent[0])
                altered_parent["components"]["dhcp"]["manifest_sha256"] = (
                    release_fixture.sha256(child_path)
                )
                basis = {key: altered_parent[key] for key in basis_keys}
                altered_parent["release_id"] = hashlib.sha256(json.dumps(
                    basis, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")).hexdigest()[:20]
                current.write_text(json.dumps(altered_parent), encoding="utf-8")
                self.assertEqual(0, child["counts"]["host_declarations_by_family"][selected])
                self.assertEqual(hashlib.sha256(b"").hexdigest(),
                                 child["outputs"][selected_path.name]["sha256"])
                self.assertEqual(release_fixture.sha256(child_path),
                                 altered_parent["components"]["dhcp"]["manifest_sha256"])
                candidate_parent_stat = current.stat()
                settings = ACTIVATE.Settings(
                    project_name="demo", scope="prod", switch_scope=selected,
                    http_root=flow.root,
                )
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_parent_release(settings, current)
                self.assertEqual(b"", selected_path.read_bytes())
                self.assertEqual(json.dumps(altered_parent), current.read_text())
                self.assertEqual(candidate_parent_stat.st_ino, current.stat().st_ino)
                self.assertEqual(candidate_parent_stat.st_mtime_ns,
                                 current.stat().st_mtime_ns)

    def test_activation_accepts_only_manifest_proven_empty_unselected_hosts(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            self.assertEqual(
                {"eth": 1, "ib": 0, "nvl": 0},
                child["counts"]["host_declarations_by_family"],
            )
            for family in ("ib", "nvl"):
                path = outputs / f"dhcpd_{family}.hosts"
                self.assertEqual(b"", path.read_bytes())
                self.assertEqual(
                    release_fixture.sha256(path),
                    child["outputs"][path.name]["sha256"],
                )
            for name in ("dhcpd.conf", "dhcpd_eth.hosts"):
                self.assertTrue((outputs / name).read_bytes())
            release_fixture.LOAD.validate_and_publish_release(
                fixture.project, inputs,
            )
            current = fixture.project / "99-output-ztp/current-release.json"
            settings = ACTIVATE.Settings(
                project_name="demo", scope="prod", switch_scope="eth",
                http_root=fixture.root,
            )
            activation_error = None
            try:
                ACTIVATE.validate_parent_release(settings, current)
            except ACTIVATE.ActivationError as exc:
                activation_error = exc
            self.assertIsNone(activation_error, str(activation_error))
        finally:
            fixture.tearDown()

    def test_activation_still_rejects_empty_selected_or_counted_dhcp_outputs(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            child_path = outputs / "dhcp-release-manifest.json"
            for family in ("ib", "nvl"):
                path = outputs / f"dhcpd_{family}.hosts"
                path.write_bytes(b"# no host declarations\n")
                child["outputs"][path.name]["sha256"] = release_fixture.sha256(path)
            child_path.write_text(json.dumps(child), encoding="utf-8")
            release_fixture.LOAD.validate_and_publish_release(fixture.project, inputs)
            current = fixture.project / "99-output-ztp/current-release.json"
            settings = ACTIVATE.Settings(
                project_name="demo", scope="prod", switch_scope="eth",
                http_root=fixture.root,
            )
            ACTIVATE.validate_parent_release(settings, current)
            accepted_parent = current.read_bytes()
            accepted_child = child_path.read_bytes()
            output_names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts",
            )
            accepted_outputs = {
                name: (outputs / name).read_bytes() for name in output_names
            }
            basis_keys = (
                "project", "deployment_scope", "switch_scope", "inputs",
                "input_sources", "components", "inventory", "dhcp_status",
            )
            for name, family in (
                ("dhcpd.conf", None), ("dhcpd_eth.hosts", None),
                ("dhcpd_ib.hosts", "ib"), ("dhcpd_nvl.hosts", "nvl"),
            ):
                with self.subTest(output=name):
                    path = outputs / name
                    path.write_bytes(b"")
                    changed_child = json.loads(accepted_child)
                    changed_child["outputs"][name]["sha256"] = (
                        hashlib.sha256(b"").hexdigest()
                    )
                    if family is not None:
                        changed_child["counts"]["host_declarations_by_family"][
                            family
                        ] = 1
                    child_path.write_text(json.dumps(changed_child), encoding="utf-8")
                    changed_parent = json.loads(accepted_parent)
                    changed_parent["components"]["dhcp"]["manifest_sha256"] = (
                        release_fixture.sha256(child_path)
                    )
                    basis = {key: changed_parent[key] for key in basis_keys}
                    changed_parent["release_id"] = hashlib.sha256(json.dumps(
                        basis, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")).hexdigest()[:20]
                    current.write_text(json.dumps(changed_parent), encoding="utf-8")
                    try:
                        with self.assertRaises(ACTIVATE.ActivationError):
                            ACTIVATE.validate_parent_release(settings, current)
                    finally:
                        path.write_bytes(accepted_outputs[name])
                        child_path.write_bytes(accepted_child)
                        current.write_bytes(accepted_parent)
        finally:
            fixture.tearDown()

    def test_load_rejects_missing_or_inconsistent_empty_host_proof_before_parent_write(self):
        """A 0-byte host file needs an exact child count/scope basis, not a hash alone."""
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            release_fixture.LOAD.validate_and_publish_release(fixture.project, inputs)
            child_path = outputs / "dhcp-release-manifest.json"
            current = fixture.project / "99-output-ztp/current-release.json"
            accepted_child = child_path.read_bytes()
            accepted_parent = current.read_bytes()
            for label, mutate in (
                ("missing counts", lambda document: document.pop("counts")),
                ("missing family counts", lambda document: document["counts"].pop(
                    "host_declarations_by_family"
                )),
                ("missing ib count", lambda document: document["counts"][
                    "host_declarations_by_family"
                ].pop("ib")),
                ("boolean ib count", lambda document: document["counts"][
                    "host_declarations_by_family"
                ].__setitem__("ib", False)),
                ("negative ib count", lambda document: document["counts"][
                    "host_declarations_by_family"
                ].__setitem__("ib", -1)),
                ("extra family count", lambda document: document["counts"][
                    "host_declarations_by_family"
                ].__setitem__("extra", 0)),
                ("selected eth count zero", lambda document: document["counts"][
                    "host_declarations_by_family"
                ].__setitem__("eth", 0)),
                ("empty ib count one", lambda document: document["counts"][
                    "host_declarations_by_family"
                ].__setitem__("ib", 1)),
            ):
                with self.subTest(case=label):
                    altered = json.loads(accepted_child)
                    mutate(altered)
                    child_path.write_text(json.dumps(altered), encoding="utf-8")
                    parent_stat = current.stat()
                    try:
                        with self.assertRaises(release_fixture.LOAD.LoadError):
                            release_fixture.LOAD.validate_and_publish_release(
                                fixture.project, inputs,
                            )
                        self.assertEqual(accepted_parent, current.read_bytes())
                        self.assertEqual(parent_stat.st_ino, current.stat().st_ino)
                        self.assertEqual(parent_stat.st_mtime_ns, current.stat().st_mtime_ns)
                    finally:
                        child_path.write_bytes(accepted_child)
                        current.write_bytes(accepted_parent)
        finally:
            fixture.tearDown()

    def test_load_rejects_zero_count_with_hash_matched_preserved_host_before_parent_write(self):
        """A child count of zero cannot describe one preserved IB declaration."""
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            release_fixture.LOAD.validate_and_publish_release(fixture.project, inputs)
            current = fixture.project / "99-output-ztp/current-release.json"
            child_path = outputs / "dhcp-release-manifest.json"
            ib_hosts = outputs / "dhcpd_ib.hosts"
            accepted_parent = current.read_bytes()
            accepted_child = child_path.read_bytes()
            self.assertEqual(b"", ib_hosts.read_bytes())
            self.assertEqual(0, child["counts"]["host_declarations_by_family"]["ib"])
            preserved_declaration = (
                b"host preserved-ib01 {\n"
                b"  hardware ethernet 02:00:00:00:20:01;\n"
                b"}\n"
            )
            ib_hosts.write_bytes(preserved_declaration)
            child["outputs"]["dhcpd_ib.hosts"]["sha256"] = (
                hashlib.sha256(preserved_declaration).hexdigest()
            )
            child_path.write_text(json.dumps(child), encoding="utf-8")
            self.assertEqual(
                child["outputs"]["dhcpd_ib.hosts"]["sha256"],
                release_fixture.sha256(ib_hosts),
            )
            parent_stat = current.stat()
            try:
                with self.assertRaises(release_fixture.LOAD.LoadError):
                    release_fixture.LOAD.validate_and_publish_release(
                        fixture.project, inputs,
                    )
                self.assertEqual(accepted_parent, current.read_bytes())
                self.assertEqual(parent_stat.st_ino, current.stat().st_ino)
                self.assertEqual(parent_stat.st_mtime_ns, current.stat().st_mtime_ns)
            finally:
                ib_hosts.write_bytes(b"")
                child_path.write_bytes(accepted_child)
                current.write_bytes(accepted_parent)
        finally:
            fixture.tearDown()

    def test_load_preserves_legacy_all_nonempty_child_without_family_counts(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            dhcp_dir = fixture.ztp / "config/isc-dhcp-server"
            child = json.loads(
                (dhcp_dir / "dhcp-release-manifest.json").read_text(
                    encoding="utf-8",
                )
            )
            self.assertNotIn("counts", child)
            self.assertNotIn("deployment_scope", child)
            self.assertNotIn("switch_scope", child)
            for name in (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts",
            ):
                path = dhcp_dir / name
                self.assertTrue(path.read_bytes())
                self.assertEqual(
                    release_fixture.sha256(path), child["outputs"][name]["sha256"],
                )
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, fixture.inputs,
            )
            self.assertEqual("passed", parent["validation"])
            self.assertEqual("dhcp-release", parent["components"]["dhcp"]["release_id"])
            current = fixture.project / "99-output-ztp/current-release.json"
            self.assertEqual(parent, json.loads(current.read_text(encoding="utf-8")))
        finally:
            fixture.tearDown()

    def test_c1_preserved_zero_host_count_binds_checked_leaf_identity(self):
        """A same-empty-byte alias or new inode cannot inherit the checked leaf."""
        for replacement_kind in ("symlink", "new regular inode"):
            with self.subTest(replacement=replacement_kind), \
                 tempfile.TemporaryDirectory() as name:
                root = Path(name)
                output = root / "outputs" / "dhcpd_ib.hosts"
                output.parent.mkdir()
                output.write_bytes(b"")
                detached = root / "detached-accepted-empty.hosts"
                foreign = root / "foreign" / "same-empty.hosts"
                foreign.parent.mkdir()
                foreign.write_bytes(b"")
                original_lstat = os.lstat
                switched = False

                def rebind_after_checked_stat(path, *args, **kwargs):
                    nonlocal switched
                    metadata = original_lstat(path, *args, **kwargs)
                    if os.fspath(path) == os.fspath(output) and not switched:
                        switched = True
                        output.rename(detached)
                        if replacement_kind == "symlink":
                            output.symlink_to(foreign)
                        else:
                            output.write_bytes(b"")
                    return metadata

                with mock.patch.object(
                    DHCP.os, "lstat", side_effect=rebind_after_checked_stat,
                ):
                    rejection = None
                    accepted_count = None
                    try:
                        accepted_count = DHCP._count_preserved_host_declarations(output)
                    except OSError as exc:
                        rejection = exc
                self.assertTrue(switched)
                self.assertEqual(b"", detached.read_bytes())
                self.assertEqual(b"", foreign.read_bytes())
                self.assertIsNotNone(
                    rejection, f"rebound same-empty leaf accepted count={accepted_count}",
                )

    def test_c1_selected_pending_zero_count_can_have_nonempty_host_artifact(self):
        """A selected family may have no declarations yet still emit comments."""
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "dhcpd_eth.hosts"
            DHCP.write_hosts(output, [{
                "hostname": "leaf01", "type": "eth", "iface": "eth0",
                "identity_pending": True,
            }])
            payload = output.read_bytes()
            self.assertTrue(payload)
            self.assertNotIn(b"host leaf01 {", payload)
            self.assertEqual(0, DHCP._count_preserved_host_declarations(output))

    def test_c1_unselected_zero_byte_regular_host_counts_zero(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "dhcpd_ib.hosts"
            output.write_bytes(b"")
            before = output.stat()
            self.assertEqual(0, DHCP._count_preserved_host_declarations(output))
            self.assertEqual(b"", output.read_bytes())
            self.assertEqual(before.st_ino, output.stat().st_ino)

    def test_native_dhcp_dry_run_accepts_proven_empty_unselected_hosts(self):
        """Dry-run preflight must not require content in unselected hosts."""
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            _inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            self.assertEqual(
                {"eth": 1, "ib": 0, "nvl": 0},
                child["counts"]["host_declarations_by_family"],
            )
            for family in ("ib", "nvl"):
                path = outputs / f"dhcpd_{family}.hosts"
                self.assertEqual(b"", path.read_bytes())
                self.assertEqual(
                    release_fixture.sha256(path),
                    child["outputs"][path.name]["sha256"],
                )
            with mock.patch.object(release_fixture.LOAD, "run") as runner:
                preflight_error = None
                try:
                    release_fixture.LOAD.mount_and_test_dhcp(dry_run=True)
                except release_fixture.LOAD.LoadError as exc:
                    preflight_error = exc
            self.assertIsNone(preflight_error, str(preflight_error))
            self.assertEqual(5, runner.call_count)
            self.assertTrue(all(
                call.kwargs.get("dry_run") is True
                for call in runner.call_args_list
            ))
        finally:
            fixture.tearDown()

    def test_native_dhcp_dry_run_rejects_empty_selected_or_counted_outputs(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            _inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            child_path = outputs / "dhcp-release-manifest.json"
            for family in ("ib", "nvl"):
                path = outputs / f"dhcpd_{family}.hosts"
                path.write_bytes(b"# no host declarations\n")
                child["outputs"][path.name]["sha256"] = release_fixture.sha256(path)
            child_path.write_text(json.dumps(child), encoding="utf-8")
            with mock.patch.object(release_fixture.LOAD, "run") as runner:
                release_fixture.LOAD.mount_and_test_dhcp(dry_run=True)
            self.assertEqual(5, runner.call_count)
            accepted_child = child_path.read_bytes()
            for name, family in (
                ("dhcpd.conf", None), ("dhcpd_eth.hosts", None),
                ("dhcpd_ib.hosts", "ib"), ("dhcpd_nvl.hosts", "nvl"),
            ):
                with self.subTest(output=name):
                    path = outputs / name
                    accepted = path.read_bytes()
                    path.write_bytes(b"")
                    changed_child = json.loads(accepted_child)
                    changed_child["outputs"][name]["sha256"] = (
                        hashlib.sha256(b"").hexdigest()
                    )
                    if family is not None:
                        changed_child["counts"]["host_declarations_by_family"][
                            family
                        ] = 1
                    child_path.write_text(json.dumps(changed_child), encoding="utf-8")
                    try:
                        with mock.patch.object(release_fixture.LOAD, "run") as runner:
                            with self.assertRaises(release_fixture.LOAD.LoadError):
                                release_fixture.LOAD.mount_and_test_dhcp(dry_run=True)
                        runner.assert_not_called()
                    finally:
                        path.write_bytes(accepted)
                        child_path.write_bytes(accepted_child)
        finally:
            fixture.tearDown()

    def test_package_input_binding_rejects_missing_bad_header_and_symlink_in_both_modes(self):
        package = load_script(
            "r22_missing_badheader_package_direct",
            ROOT / "tools/_package_common.py",
        )
        bad_header = _R22_SUBNET_HEADER.replace(
            "shared_network", "shared_networb",
        )
        for dhcp_status in ("disabled", "enabled"):
            for label, payload in (
                ("missing", None), ("bad header", bad_header),
                ("symlink", _R22_SUBNET_HEADER),
            ):
                with self.subTest(mode=dhcp_status, case=label), \
                     tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    project = root / "DAY0-Prepare/fixture"
                    project.mkdir(parents=True)
                    document = global_document(dhcp_status)
                    document["common"]["mgmt"]["ztp"]["status"] = "disabled"
                    (project / "01-global.yaml").write_text(
                        yaml.safe_dump(document), encoding="utf-8",
                    )
                    (project / "02-devices_config.csv").write_text(
                        "hostname,type,mac\n", encoding="utf-8",
                    )
                    subnet = project / "02-dhcp-subnet_config.csv"
                    if label == "symlink":
                        target = project / "real-subnet.csv"
                        target.write_text(payload, encoding="utf-8")
                        subnet.symlink_to(target.name)
                    elif payload is not None:
                        subnet.write_text(payload, encoding="utf-8")
                    previous = root / "prior-upload.tar.gz"
                    previous.write_bytes(b"prior archive sentinel\n")
                    witness = (
                        previous.read_bytes(), previous.stat().st_ino,
                        previous.stat().st_mtime_ns,
                    )
                    with mock.patch.object(package, "ROOT", root):
                        with self.assertRaises(ValueError):
                            package._bind_package_project_inputs(
                                [project], maximum_size=None,
                            )
                    self.assertEqual(
                        witness,
                        (previous.read_bytes(), previous.stat().st_ino,
                         previous.stat().st_mtime_ns),
                    )

    def test_setup_requires_explicit_modes_and_never_mistakes_invalid_csv_for_empty(self):
        for dhcp_enabled in (False, True):
            for label, payload, intrinsically_invalid in self._CASES:
                with self.subTest(dhcp_enabled=dhcp_enabled, case=label):
                    with tempfile.TemporaryDirectory() as name:
                        subnet = Path(name) / "02-dhcp-subnet_config.csv"
                        if payload is not None:
                            subnet.write_text(payload, encoding="utf-8")
                        errors, _warnings = SETUP._validate_subnet_csv(
                            subnet,
                            dhcp_enabled=dhcp_enabled, ztp_enabled=False,
                        )
                    self.assertEqual(
                        intrinsically_invalid or dhcp_enabled,
                        bool(errors), (label, dhcp_enabled, errors),
                    )

    def test_runtime_requires_explicit_modes_and_rejects_invalid_empty_rows(self):
        for dhcp_enabled in (False, True):
            for label, payload, intrinsically_invalid in self._CASES:
                with self.subTest(dhcp_enabled=dhcp_enabled, case=label):
                    with tempfile.TemporaryDirectory() as name:
                        subnet = Path(name) / "02-dhcp-subnet_config.csv"
                        if payload is not None:
                            subnet.write_text(payload, encoding="utf-8")
                        call = lambda: RUNTIME.plan_dhcp_runtime(
                            subnet, link_snapshot=[], address_snapshot=[],
                            dhcp_enabled=dhcp_enabled, ztp_enabled=False,
                        )
                        if intrinsically_invalid or dhcp_enabled:
                            with self.assertRaises(RUNTIME.RuntimeContractError):
                                call()
                        else:
                            plan = call()
                            self.assertEqual((), plan.listener_names)
                            self.assertEqual((), plan.endpoint_ips)

    def test_subnet_csv_symlink_is_not_a_regular_input_in_each_mode(self):
        for dhcp_enabled in (False, True):
            with self.subTest(dhcp_enabled=dhcp_enabled), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                target = root / "real-subnet.csv"
                target.write_text(
                    _R22_SUBNET_HEADER + (_R22_ACTIVE_ROW if dhcp_enabled else ""),
                    encoding="utf-8",
                )
                subnet = root / "02-dhcp-subnet_config.csv"
                subnet.symlink_to(target)
                errors, _warnings = SETUP._validate_subnet_csv(
                    subnet, dhcp_enabled=dhcp_enabled,
                    ztp_enabled=dhcp_enabled,
                )
                self.assertTrue(errors)
                mode = "enabled" if dhcp_enabled else "disabled"
                document = global_document(mode)
                document["common"]["mgmt"]["ztp"]["status"] = mode
                with self.assertRaisesRegex(LOAD.LoadError, "symlink|软链接|普通文件"):
                    LOAD.validate_subnet_file(
                        subnet,
                        LOAD.load_global(Path("unused-global.yaml"), global_data=document),
                    )
                with self.assertRaisesRegex(
                    RUNTIME.RuntimeContractError, "symlink|regular"
                ):
                    RUNTIME.plan_dhcp_runtime(
                        subnet, link_snapshot=[], address_snapshot=[],
                        dhcp_enabled=dhcp_enabled, ztp_enabled=dhcp_enabled,
                    )

    def test_hardlink_subnet_is_rejected_by_single_link_consumer_contracts(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "real-subnet.csv"
            target.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
            subnet = root / "02-dhcp-subnet_config.csv"
            os.link(target, subnet)
            self.assertEqual(2, subnet.stat().st_nlink)
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors)
            with self.assertRaisesRegex(LOAD.LoadError, "single-link|硬链接"):
                LOAD.validate_subnet_file(subnet, settings_for("disabled"))
            with self.assertRaisesRegex(
                RUNTIME.RuntimeContractError, "single-link|hardlink"
            ):
                RUNTIME.plan_dhcp_runtime(
                    subnet, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=False, ztp_enabled=False,
                )

    def test_load_and_runtime_reject_regular_inode_swap_before_csv_open(self):
        for label, call, error in (
            (
                "load",
                lambda path: LOAD.validate_subnet_file(path, settings_for("disabled")),
                LOAD.LoadError,
            ),
            (
                "runtime",
                lambda path: RUNTIME.plan_dhcp_runtime(
                    path, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=False, ztp_enabled=False,
                ),
                RUNTIME.RuntimeContractError,
            ),
        ):
            with self.subTest(consumer=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                subnet = root / "02-dhcp-subnet_config.csv"
                subnet.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
                replacement = root / "replacement.csv"
                replacement.write_text(_R22_SUBNET_HEADER + " \n", encoding="utf-8")
                old = root / "old.csv"
                actual_open = os.open
                swapped = False

                def swap_then_open(path, flags, *args, **kwargs):
                    nonlocal swapped
                    if not swapped and Path(path) == subnet:
                        subnet.rename(old)
                        replacement.rename(subnet)
                        swapped = True
                    return actual_open(path, flags, *args, **kwargs)

                with mock.patch.object(os, "open", side_effect=swap_then_open):
                    with self.assertRaisesRegex(error, "identity|身份"):
                        call(subnet)
                self.assertTrue(swapped)
                self.assertTrue(old.exists())

    def test_setup_csv_rejects_same_size_inplace_or_path_swap_at_open(self):
        original = _R22_SUBNET_HEADER + " \n"
        replacement_text = _R22_SUBNET_HEADER + "\t\n"
        self.assertEqual(len(original.encode()), len(replacement_text.encode()))
        for mode in ("inplace", "replacement"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                subnet = root / "02-dhcp-subnet_config.csv"
                subnet.write_text(original, encoding="utf-8")
                old = root / "old.csv"
                replacement = root / "replacement.csv"
                if mode == "replacement":
                    replacement.write_text(replacement_text, encoding="utf-8")
                actual_lstat = os.lstat
                swapped = False

                def mutate_after_lstat(path, *args, **kwargs):
                    nonlocal swapped
                    metadata = actual_lstat(path, *args, **kwargs)
                    if not swapped and Path(path) == subnet:
                        if mode == "inplace":
                            subnet.write_text(replacement_text, encoding="utf-8")
                        else:
                            subnet.rename(old)
                            replacement.rename(subnet)
                        swapped = True
                    return metadata

                with mock.patch.object(os, "lstat", side_effect=mutate_after_lstat):
                    errors, _warnings = SETUP._validate_subnet_csv(
                        subnet, dhcp_enabled=False, ztp_enabled=False,
                    )
                self.assertTrue(swapped)
                self.assertTrue(errors, mode)
                if mode == "inplace":
                    self.assertFalse(old.exists())
                else:
                    self.assertTrue(old.exists())

    def test_setup_project_rejects_mixed_valid_csv_generations_even_with_force(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(global_document("disabled")), encoding="utf-8"
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER + " \n", encoding="utf-8")
            replacement = project / "replacement.csv"
            replacement.write_text(_R22_SUBNET_HEADER + "\t\n", encoding="utf-8")
            old = project / "old.csv"
            actual_validate = SETUP._validate_subnet_csv
            calls = 0

            def swap_after_first_validation(path, **kwargs):
                nonlocal calls
                result = actual_validate(path, **kwargs)
                calls += 1
                if calls == 1:
                    subnet.rename(old)
                    replacement.rename(subnet)
                return result

            with mock.patch.object(
                SETUP, "_validate_subnet_csv", side_effect=swap_after_first_validation,
            ), mock.patch.object(
                SETUP, "_validate_global_yaml", return_value=([], []),
            ), mock.patch.object(SETUP, "_FORCE", True), mock.patch.object(
                SETUP, "_P2P_SOURCE", None,
            ), mock.patch.object(SETUP, "_CSV_DIR", None), mock.patch.object(
                SETUP, "IMAGE_DIR", str(project / "no-shared-images"),
            ), mock.patch.object(sys, "stdout", io.StringIO()):
                self.assertFalse(SETUP._validate_project(project))
            # The first gate catches drift before a second path read is allowed.
            self.assertEqual(1, calls)
            self.assertTrue(old.exists())

    def test_load_rejects_subnet_sha_drift_before_release_prewrite_admission(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(global_document("disabled")), encoding="utf-8"
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type,mac\n", encoding="utf-8"
            )
            header = _R22_SUBNET_HEADER
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_text(header, encoding="utf-8")
            replacement = project / "replacement.csv"
            replacement.write_text(
                header.replace("shared_network", "shared_networb"), encoding="utf-8"
            )
            self.assertEqual(subnet.stat().st_size, replacement.stat().st_size)
            p2p = project / "p2p.xlsx"
            p2p.write_bytes(b"read-only fixture\n")
            actual_validate = LOAD.validate_subnet_file
            swapped = False

            def swap_after_validation(path, settings):
                nonlocal swapped
                actual_validate(path, settings)
                subnet.rename(project / "old.csv")
                replacement.rename(subnet)
                swapped = True

            args = SimpleNamespace(
                p2p_file=None, deployment_scope="all", switch_scope="all",
                no_upgrade=True, mini=None, ssh_dir=None,
            )
            with mock.patch.object(
                LOAD, "find_placeholder_password_sections", return_value=(),
            ), mock.patch.object(
                LOAD, "apply_subnet_service_ips", side_effect=lambda settings, _path: settings,
            ), mock.patch.object(
                LOAD, "load_device_types", return_value=frozenset(),
            ), mock.patch.object(
                LOAD, "select_p2p", return_value=p2p,
            ), mock.patch.object(
                LOAD, "project_air_topology_policy", return_value=None,
            ), mock.patch.object(
                LOAD, "project_mini_air_devices", return_value=(None, None),
            ), mock.patch.object(
                LOAD, "validate_subnet_file", side_effect=swap_after_validation,
            ), mock.patch.object(
                LOAD, "validate_shared_artifact_receipts",
                side_effect=AssertionError("release prewrite boundary reached"),
            ) as receipts:
                with self.assertRaisesRegex(LOAD.LoadError, "subnet|source|来源|changed"):
                    LOAD.validate_inputs(
                        project, args, allow_management_key_generation=False,
                        host_role="workstation",
                    )
            self.assertTrue(swapped)
            receipts.assert_not_called()

    def test_load_rejects_same_sha_new_inode_during_source_identity_collection(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(global_document("disabled")), encoding="utf-8"
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type,mac\n", encoding="utf-8"
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
            replacement = project / "replacement.csv"
            replacement.write_bytes(subnet.read_bytes())
            p2p = project / "p2p.xlsx"
            p2p.write_bytes(b"read-only fixture\n")
            actual_sha = LOAD._sha256_path
            swapped = False

            def replace_before_source_hash(path):
                nonlocal swapped
                if Path(path) == subnet and not swapped:
                    subnet.rename(project / "old.csv")
                    replacement.rename(subnet)
                    swapped = True
                return actual_sha(path)

            args = SimpleNamespace(
                p2p_file=None, deployment_scope="all", switch_scope="all",
                no_upgrade=True, mini=None, ssh_dir=None,
            )
            with mock.patch.object(
                LOAD, "find_placeholder_password_sections", return_value=(),
            ), mock.patch.object(
                LOAD, "apply_subnet_service_ips", side_effect=lambda settings, _path: settings,
            ), mock.patch.object(
                LOAD, "load_device_types", return_value=frozenset(),
            ), mock.patch.object(
                LOAD, "select_p2p", return_value=p2p,
            ), mock.patch.object(
                LOAD, "project_air_topology_policy", return_value=None,
            ), mock.patch.object(
                LOAD, "project_mini_air_devices", return_value=(None, None),
            ), mock.patch.object(
                LOAD, "_sha256_path", side_effect=replace_before_source_hash,
            ), mock.patch.object(
                LOAD, "validate_shared_artifact_receipts",
                side_effect=AssertionError("release prewrite boundary reached"),
            ) as receipts:
                with self.assertRaisesRegex(LOAD.LoadError, "subnet|source|来源|changed"):
                    LOAD.validate_inputs(
                        project, args, allow_management_key_generation=False,
                        host_role="workstation",
                    )
            self.assertTrue(swapped)
            receipts.assert_not_called()

    def test_force_cannot_turn_invalid_subnet_input_into_setup_permission(self):
        cases = (
            ("missing", None),
            ("zero-byte", ""),
            ("bad header", _R22_SUBNET_HEADER.replace(
                "shared_network", "shared_networb")),
        )
        for label, payload in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as name:
                project = Path(name)
                (project / "01-global.yaml").write_text(
                    yaml.safe_dump(global_document("disabled")), encoding="utf-8"
                )
                if payload is not None:
                    (project / "02-dhcp-subnet_config.csv").write_text(
                        payload, encoding="utf-8",
                    )
                with mock.patch.object(SETUP, "_FORCE", True), mock.patch.object(
                    SETUP, "_P2P_SOURCE", None
                ), mock.patch.object(SETUP, "_CSV_DIR", None), mock.patch.object(
                    SETUP, "IMAGE_DIR", str(project / "no-shared-images")
                ), mock.patch.object(sys, "stdout", io.StringIO()):
                    self.assertFalse(SETUP._validate_project(project))

    def test_production_csv_consumer_calls_cannot_omit_explicit_modes(self):
        """Historical unbound parser calls are allowed in tests, not entrypoints."""
        expected = {
            "DAY0-Prepare/01-a-setup.py": {"_validate_subnet_csv": 2},
            "DAY0-Prepare/11-load.py": {"plan_dhcp_runtime": 1},
            "infra/docker/activate.py": {
                "plan_dhcp_runtime": 1,
                "revalidate_dhcp_runtime_plan": 1,
            },
            "tools/ztp_service_runtime.py": {"plan_dhcp_runtime": 1},
        }
        for relative, symbols in expected.items():
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            parents = {
                child: parent for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            for symbol, count in symbols.items():
                references = [
                    node for node in ast.walk(tree)
                    if isinstance(node, (ast.Name, ast.Attribute))
                    and (node.id if isinstance(node, ast.Name) else node.attr) == symbol
                    and isinstance(node.ctx, ast.Load)
                ]
                self.assertEqual(count, len(references), (relative, symbol))
                for reference in references:
                    call = parents[reference]
                    self.assertIsInstance(call, ast.Call, (relative, symbol, reference.lineno))
                    self.assertIs(call.func, reference)
                    keywords = {item.arg for item in call.keywords}
                    self.assertIn("dhcp_enabled", keywords, (relative, reference.lineno))
                    self.assertIn("ztp_enabled", keywords, (relative, reference.lineno))


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
