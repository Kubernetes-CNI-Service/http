#!/usr/bin/env python3
"""Direct contract for the fail-closed DHCP enable/disable authority."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
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

_TEMPLATE_TEXT = (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
    encoding="utf-8"
)
_TEMPLATE = yaml.safe_load(_TEMPLATE_TEXT)
_STATUS_LABEL = "common.mgmt.dhcp-server.status"


def global_document(status: object = "disabled") -> dict[str, object]:
    """Fresh, otherwise-valid input; package and siblings cannot pre-empt status."""
    document = deepcopy(_TEMPLATE)
    document["common"]["mgmt"]["dhcp-server"]["status"] = status
    return document


def settings_for(status: str):
    return LOAD.load_global(Path("unused-global.yaml"), global_data=global_document(status))


class DhcpOptionalDirectTests(unittest.TestCase):
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

    def test_real_disabled_runtime_plan_keeps_http_endpoint_without_dhcp_listener(self):
        with tempfile.TemporaryDirectory() as name:
            enabled = self._real_one_listener_plan(Path(name), "enabled")
            disabled = self._real_one_listener_plan(Path(name), "disabled")
        self.assertEqual(("eno7",), enabled.listener_names)
        self.assertEqual((7,), enabled.listener_ifindexes)
        self.assertEqual(("192.0.2.10",), enabled.endpoint_ips)
        self.assertEqual(enabled.endpoint_ips, disabled.endpoint_ips)
        self.assertEqual((), disabled.listener_names)
        self.assertEqual((), disabled.listener_ifindexes)

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
