"""Dynamic DHCP listeners and explicit service-runtime backend contracts.

These tests are deliberately independent from the implementation: subnet CSV
rows and Linux ``ip -j`` snapshots are hand-authored fixtures, and every
expected listener/argv is stated explicitly.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_PATH = ROOT / "tools/ztp_service_runtime.py"


def load_runtime_module():
    if not RUNTIME_PATH.is_file():
        raise AssertionError(
            "missing production runtime module: tools/ztp_service_runtime.py"
        )
    spec = importlib.util.spec_from_file_location(
        "ztp_service_runtime_contract", RUNTIME_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_script_module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def load_container_hostctl_module():
    """Load the real container controller with its sibling production modules."""
    docker_root = ROOT / "infra/docker"
    saved = {name: sys.modules.get(name) for name in ("activate", "healthcheck")}
    old_path = list(sys.path)
    try:
        sys.path.insert(0, str(docker_root))
        activate = load_script_module(
            "activate", "infra/docker/activate.py",
        )
        load_script_module("healthcheck", "infra/docker/healthcheck.py")
        return load_script_module(
            "container_workflow_hostctl", "infra/docker/hostctl.py",
        )
    finally:
        sys.path[:] = old_path
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def link(
    ifindex: int, ifname: str, *, up: bool = True,
    lower: int | None = None, kind: str | None = None,
    link_type: str = "ether", flags: list[str] | None = None,
    operstate: str | None = None,
):
    if flags is None:
        flags = [
            "BROADCAST", "MULTICAST",
            *(["UP", "LOWER_UP"] if up else []),
        ]
    record = {
        "ifindex": ifindex,
        "ifname": ifname,
        "flags": flags,
        "operstate": operstate or ("UP" if up else "DOWN"),
        "link_type": link_type,
    }
    if lower is not None:
        record["link_index"] = lower
        kind = kind or "vlan"
    if kind is not None:
        record["linkinfo"] = {"info_kind": kind}
    return record


def addresses(
    ifindex: int, ifname: str, *cidrs: str,
    valid_life_time: int = 4294967295,
    preferred_life_time: int = 4294967295,
):
    addr_info = []
    for cidr in cidrs:
        address, prefix = cidr.split("/", 1)
        addr_info.append({
            "family": "inet",
            "local": address,
            "prefixlen": int(prefix),
            "scope": "global",
            "valid_life_time": valid_life_time,
            "preferred_life_time": preferred_life_time,
        })
    return {
        "ifindex": ifindex,
        "ifname": ifname,
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "addr_info": addr_info,
    }


class DynamicDhcpInterfaceContractTests(unittest.TestCase):
    HEADER = (
        "shared_network,subnet,netmask,range_start,range_end,routers,"
        "ztp_service_ip,cumulus_profile,nvos_ztp\n"
    )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_subnets(self, *rows: str) -> Path:
        path = self.root / "02-dhcp-subnet_config.csv"
        path.write_text(self.HEADER + "".join(f"{row}\n" for row in rows), encoding="utf-8")
        return path

    @staticmethod
    def vm_snapshot():
        links = [
            link(2, "enp0s8"),
            link(3, "enp0s9"),
            link(4, "enp0s10"),
            link(5, "enp0s11"),
            link(6, "docker0"),
        ]
        addr = [
            addresses(2, "enp0s8", "203.0.113.3/27"),
            addresses(3, "enp0s9", "203.0.113.67/27"),
            addresses(4, "enp0s10", "192.0.2.50/26"),
            addresses(5, "enp0s11", "198.51.100.50/26"),
            addresses(6, "docker0", "203.0.113.131/27"),
        ]
        return links, addr

    def test_2026_12_fixture_selects_only_two_data_derived_interfaces(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct-one,192.0.2.0,255.255.255.192,192.0.2.51,192.0.2.60,"
            "192.0.2.62,192.0.2.50,oob,yes",
            "relay-only,192.0.2.64,255.255.255.192,192.0.2.115,192.0.2.120,"
            "192.0.2.126,192.0.2.50,oob,yes",
            "direct-two,198.51.100.0,255.255.255.192,198.51.100.51,"
            "198.51.100.60,198.51.100.62,198.51.100.50,oobofoob,no",
        )
        links, addr = self.vm_snapshot()

        plan = runtime.plan_dhcp_runtime(
            subnet_csv, link_snapshot=links, address_snapshot=addr,
        )

        # Order comes from the project rows, not lexical interface naming or
        # hard-coded meanings such as "first NIC is OOB".
        self.assertEqual(("enp0s10", "enp0s11"), plan.listener_names)
        self.assertEqual((4, 5), plan.listener_ifindexes)
        self.assertNotIn("enp0s8", plan.listener_names)
        self.assertNotIn("enp0s9", plan.listener_names)
        self.assertNotIn("docker0", plan.listener_names)
        self.assertEqual(
            (
                "/usr/sbin/dhcpd", "-4", "-f",
                "-cf", "/etc/dhcp/dhcpd.conf",
                "-lf", "/var/lib/dhcp/dhcpd.leases",
                "-pf", "/run/http-ztp/dhcpd.pid",
                "enp0s10", "enp0s11",
            ),
            runtime.build_dhcpd_argv(plan.listener_names),
        )

    def test_allowlist_is_a_ceiling_not_an_interface_source(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        links = [link(2, "enp0s8"), link(3, "enp0s10"), link(4, "docker0")]
        addr = [
            addresses(2, "enp0s8", "198.51.100.10/24"),
            addresses(3, "enp0s10", "192.0.2.10/24"),
            addresses(4, "docker0", "203.0.113.131/27"),
        ]

        plan = runtime.plan_dhcp_runtime(
            subnet_csv,
            link_snapshot=links,
            address_snapshot=addr,
            allowlist=("enp0s8", "enp0s10", "docker0"),
        )

        self.assertEqual(("enp0s10",), plan.listener_names)

    def test_allowlist_cannot_hide_a_globally_duplicated_endpoint(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        links = [link(7, "eno2"), link(8, "dummy0", kind="dummy")]
        addr = [
            addresses(7, "eno2", "192.0.2.10/24"),
            addresses(8, "dummy0", "192.0.2.10/24"),
        ]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError,
            r"192\.0\.2\.10.*exactly one.*eno2.*dummy0",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=links,
                address_snapshot=addr,
                allowlist=("eno2",),
            )

    def test_automatic_listener_policy_rejects_unsafe_link_types(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        cases = (
            link(
                7, "lo", link_type="loopback",
                flags=["LOOPBACK", "UP", "LOWER_UP"], operstate="UNKNOWN",
            ),
            link(
                7, "dummy0", kind="dummy",
                flags=["BROADCAST", "NOARP", "UP", "LOWER_UP"],
                operstate="UNKNOWN",
            ),
            link(7, "veth123", kind="veth"),
            link(
                7, "br0", kind="bridge",
                flags=["BROADCAST", "MULTICAST", "MASTER", "UP", "LOWER_UP"],
            ),
            link(7, "mystery0", kind="future-kind"),
            link(
                7, "eno2", flags=[
                    "BROADCAST", "MULTICAST", "SLAVE", "UP", "LOWER_UP",
                ],
            ),
            link(
                7, "eno2", flags=[
                    "BROADCAST", "MULTICAST", "NOARP", "UP", "LOWER_UP",
                ],
            ),
            link(
                7, "ppp0", flags=[
                    "POINTOPOINT", "MULTICAST", "UP", "LOWER_UP",
                ],
            ),
        )
        for unsafe in cases:
            for ceiling in ((), (unsafe["ifname"],)):
                with self.subTest(interface=unsafe["ifname"], allowlist=ceiling):
                    with self.assertRaisesRegex(
                        runtime.RuntimeContractError,
                        r"interface.*not eligible|unsafe link",
                    ):
                        runtime.plan_dhcp_runtime(
                            subnet_csv,
                            link_snapshot=[unsafe],
                            address_snapshot=[addresses(
                                unsafe["ifindex"], unsafe["ifname"],
                                "192.0.2.10/24",
                            )],
                            allowlist=ceiling,
                        )

    def test_physical_bond_and_vlan_parent_chain_are_supported(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "physical,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
            "bond,198.51.100.0,255.255.255.0,198.51.100.100,198.51.100.120,"
            "198.51.100.1,198.51.100.10,oob,no",
            "vlan,203.0.113.0,255.255.255.0,203.0.113.100,203.0.113.120,"
            "203.0.113.1,203.0.113.10,oob,no",
        )
        links = [
            link(2, "eno1"),
            link(
                3, "bond0", kind="bond",
                flags=["BROADCAST", "MULTICAST", "MASTER", "UP", "LOWER_UP"],
            ),
            link(4, "bond0.114", lower=3),
        ]
        addr = [
            addresses(2, "eno1", "192.0.2.10/24"),
            addresses(3, "bond0", "198.51.100.10/24"),
            addresses(4, "bond0.114", "203.0.113.10/24"),
        ]

        plan = runtime.plan_dhcp_runtime(
            subnet_csv, link_snapshot=links, address_snapshot=addr,
        )

        self.assertEqual(("eno1", "bond0", "bond0.114"), plan.listener_names)
        self.assertEqual((2, 3, 4), plan.listener_ifindexes)

    def test_vlan_requires_a_known_supported_parent_chain(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        cases = (
            [link(10, "eno1.114", lower=99)],
            [link(2, "veth0", kind="veth"), link(10, "veth0.114", lower=2)],
        )
        for links in cases:
            with self.subTest(links=links):
                with self.assertRaisesRegex(
                    runtime.RuntimeContractError, r"parent|not eligible|unsafe link",
                ):
                    runtime.plan_dhcp_runtime(
                        subnet_csv,
                        link_snapshot=links,
                        address_snapshot=[addresses(10, links[-1]["ifname"], "192.0.2.10/24")],
                    )

    def test_relay_network_does_not_multiply_direct_listener(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
            "relay-a,198.51.100.0,255.255.255.0,198.51.100.100,"
            "198.51.100.120,198.51.100.1,192.0.2.10,oob,no",
            "relay-b,203.0.113.0,255.255.255.0,203.0.113.100,"
            "203.0.113.120,203.0.113.1,192.0.2.10,oob,no",
        )
        nic = link(7, "eno2")
        addr = addresses(7, "eno2", "192.0.2.10/24")

        plan = runtime.plan_dhcp_runtime(
            subnet_csv, link_snapshot=[nic], address_snapshot=[addr],
        )

        self.assertEqual(("eno2",), plan.listener_names)

    def test_dhcp_only_network_requires_explicit_scoped_ingress(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "dhcp-only,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,,none,no",
        )
        links = [link(7, "eno2")]
        addr = [addresses(7, "eno2", "192.0.2.254/24")]

        with self.assertRaisesRegex(runtime.RuntimeContractError, "DHCP.*ingress"):
            runtime.plan_dhcp_runtime(
                subnet_csv, link_snapshot=links, address_snapshot=addr,
            )

        plan = runtime.plan_dhcp_runtime(
            subnet_csv,
            link_snapshot=links,
            address_snapshot=addr,
            relay_ingress=("eno2",),
        )
        self.assertEqual(("eno2",), plan.listener_names)
        self.assertEqual((7,), plan.listener_ifindexes)
        self.assertEqual(("dhcp-only",), plan.dhcp_only_shared_networks)

    def test_mixed_direct_and_dhcp_only_requires_explicit_ingress(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
            "dhcp-only,198.51.100.0,255.255.255.0,198.51.100.100,"
            "198.51.100.120,198.51.100.1,,none,no",
        )
        links = [link(7, "eno2"), link(8, "eno3")]
        addr = [
            addresses(7, "eno2", "192.0.2.10/24"),
            addresses(8, "eno3", "198.51.100.254/24"),
        ]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"DHCP-only.*explicit.*ingress",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv, link_snapshot=links, address_snapshot=addr,
            )

        relayed = runtime.plan_dhcp_runtime(
            subnet_csv,
            link_snapshot=links,
            address_snapshot=addr,
            relay_ingress=("eno2",),
        )
        self.assertEqual(("eno2",), relayed.listener_names)
        self.assertEqual(("dhcp-only",), relayed.dhcp_only_shared_networks)

        directly_attached = runtime.plan_dhcp_runtime(
            subnet_csv,
            link_snapshot=links,
            address_snapshot=addr,
            relay_ingress=("eno3",),
        )
        self.assertEqual(("eno2", "eno3"), directly_attached.listener_names)
        self.assertEqual(("dhcp-only",), directly_attached.dhcp_only_shared_networks)

    def test_empty_network_set_rejects_stale_ingress_and_otherwise_is_zero(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets()
        links = [link(7, "eno2")]
        addr = [addresses(7, "eno2", "192.0.2.10/24")]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"no DHCP networks|empty.*ingress",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=links,
                address_snapshot=addr,
                relay_ingress=("eno2",),
            )

        plan = runtime.plan_dhcp_runtime(
            subnet_csv, link_snapshot=links, address_snapshot=addr,
        )
        self.assertEqual((), plan.listener_names)
        self.assertEqual((), plan.listener_ifindexes)
        self.assertEqual((), plan.dhcp_only_shared_networks)

    def test_relay_ingress_requires_a_usable_ipv4_address(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "dhcp-only,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,,none,no",
        )

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"eno2.*usable.*IPv4",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=[link(7, "eno2")],
                address_snapshot=[addresses(7, "eno2")],
                relay_ingress=("eno2",),
            )

    def test_relay_only_requires_explicit_scoped_ingress(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "relay-only,198.51.100.0,255.255.255.0,198.51.100.100,"
            "198.51.100.120,198.51.100.1,192.0.2.10,oob,no",
        )
        nic = link(7, "eno2")
        addr = addresses(7, "eno2", "192.0.2.10/24")

        with self.assertRaisesRegex(runtime.RuntimeContractError, "relay.*ingress"):
            runtime.plan_dhcp_runtime(
                subnet_csv, link_snapshot=[nic], address_snapshot=[addr],
            )

        plan = runtime.plan_dhcp_runtime(
            subnet_csv,
            link_snapshot=[nic],
            address_snapshot=[addr],
            relay_ingress=("eno2",),
        )
        self.assertEqual(("eno2",), plan.listener_names)

    def test_selected_ifindex_with_secondary_ip_in_another_shared_network_fails(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
            "relay,198.51.100.0,255.255.255.0,198.51.100.100,198.51.100.120,"
            "198.51.100.1,192.0.2.10,oob,no",
        )
        links = [link(7, "eno2")]
        addr = [addresses(7, "eno2", "192.0.2.10/24", "198.51.100.9/24")]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError,
            r"eno2.*ifindex.*7.*multiple shared networks",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv, link_snapshot=links, address_snapshot=addr,
            )

    def test_secondary_ip_in_dhcp_only_shared_network_also_fails(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
            "dhcp-only,198.51.100.0,255.255.255.0,198.51.100.100,"
            "198.51.100.120,198.51.100.1,,none,no",
        )
        links = [link(7, "eno2")]
        addr = [addresses(7, "eno2", "192.0.2.10/24", "198.51.100.9/24")]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError,
            r"eno2.*ifindex.*7.*multiple shared networks.*dhcp-only.*direct|"
            r"eno2.*ifindex.*7.*multiple shared networks.*direct.*dhcp-only",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv, link_snapshot=links, address_snapshot=addr,
            )

    def test_exact_service_ip_with_wrong_prefix_is_not_a_direct_match(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        links = [link(7, "eno2")]
        addr = [addresses(7, "eno2", "192.0.2.10/25")]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"direct.*192\.0\.2\.10/24",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv, link_snapshot=links, address_snapshot=addr,
            )

    def test_down_interface_cannot_satisfy_endpoint_or_listener(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"192\.0\.2\.10.*eligible interface",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=[link(7, "eno2", up=False)],
                address_snapshot=[addresses(7, "eno2", "192.0.2.10/24")],
            )

    def test_tentative_endpoint_address_is_not_eligible(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        addr = addresses(7, "eno2", "192.0.2.10/24")
        addr["addr_info"][0]["flags"] = ["tentative"]

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"192\.0\.2\.10.*eligible interface",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=[link(7, "eno2")],
                address_snapshot=[addr],
            )

    def test_zero_valid_lifetime_endpoint_address_is_not_eligible(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )

        with self.assertRaisesRegex(
            runtime.RuntimeContractError, r"192\.0\.2\.10.*exactly one",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=[link(7, "eno2")],
                address_snapshot=[addresses(
                    7, "eno2", "192.0.2.10/24", valid_life_time=0,
                )],
            )

    def test_endpoint_assigned_to_two_ifindexes_is_ambiguous(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )

        with self.assertRaisesRegex(
            runtime.RuntimeContractError,
            r"192\.0\.2\.10.*exactly one eligible interface.*eno2.*eno3",
        ):
            runtime.plan_dhcp_runtime(
                subnet_csv,
                link_snapshot=[link(7, "eno2"), link(8, "eno3")],
                address_snapshot=[
                    addresses(7, "eno2", "192.0.2.10/24"),
                    addresses(8, "eno3", "192.0.2.10/24"),
                ],
            )

    def test_two_vlan_ifindexes_on_one_parent_remain_distinct(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "first,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
            "second,198.51.100.0,255.255.255.0,198.51.100.100,198.51.100.120,"
            "198.51.100.1,198.51.100.10,oob,no",
        )
        links = [
            link(2, "eno1"),
            link(10, "eno1.100", lower=2),
            link(11, "eno1.200", lower=2),
        ]
        addr = [
            addresses(2, "eno1"),
            addresses(10, "eno1.100", "192.0.2.10/24"),
            addresses(11, "eno1.200", "198.51.100.10/24"),
        ]

        plan = runtime.plan_dhcp_runtime(
            subnet_csv, link_snapshot=links, address_snapshot=addr,
        )

        self.assertEqual(("eno1.100", "eno1.200"), plan.listener_names)
        self.assertEqual((10, 11), plan.listener_ifindexes)

    def test_plan_revalidation_detects_ifindex_name_and_prefix_changes(self) -> None:
        runtime = load_runtime_module()
        subnet_csv = self.write_subnets(
            "direct,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no",
        )
        initial = runtime.plan_dhcp_runtime(
            subnet_csv,
            link_snapshot=[link(7, "eno2")],
            address_snapshot=[addresses(7, "eno2", "192.0.2.10/24")],
        )

        current = runtime.revalidate_dhcp_runtime_plan(
            initial,
            subnet_csv,
            link_snapshot=[link(7, "eno2")],
            address_snapshot=[addresses(7, "eno2", "192.0.2.10/24")],
        )
        self.assertEqual(initial, current)

        changed_snapshots = (
            (
                [link(91, "eno2")],
                [addresses(91, "eno2", "192.0.2.10/24")],
            ),
            (
                [link(7, "eno9")],
                [addresses(7, "eno9", "192.0.2.10/24")],
            ),
            (
                [link(7, "eno2")],
                [addresses(7, "eno2", "192.0.2.10/25")],
            ),
        )
        for links, addr in changed_snapshots:
            with self.subTest(links=links, addresses=addr):
                with self.assertRaisesRegex(
                    runtime.RuntimeContractError, r"changed|expected.*runtime plan|/24",
                ):
                    runtime.revalidate_dhcp_runtime_plan(
                        initial,
                        subnet_csv,
                        link_snapshot=links,
                        address_snapshot=addr,
                    )

    def test_empty_or_option_like_listener_argv_is_rejected(self) -> None:
        runtime = load_runtime_module()
        with self.assertRaisesRegex(runtime.RuntimeContractError, "empty.*interface"):
            runtime.build_dhcpd_argv(())
        with self.assertRaisesRegex(runtime.RuntimeContractError, "interface"):
            runtime.build_dhcpd_argv(("--no-pid",))

    def test_arbitrary_n_direct_networks_have_deterministic_argv(self) -> None:
        runtime = load_runtime_module()
        rows = []
        links = [link(2, "eno1")]
        addr = []
        for number in range(1, 6):
            network = (number - 1) * 32
            rows.append(
                f"net-{number},198.51.100.{network},255.255.255.224,"
                f"198.51.100.{network + 10},198.51.100.{network + 20},"
                f"198.51.100.{network + 1},198.51.100.{network + 5},oob,no"
            )
            links.append(link(20 + number, f"eno1.{100 + number}", lower=2))
            addr.append(addresses(
                20 + number, f"eno1.{100 + number}",
                f"198.51.100.{network + 5}/27",
            ))
        subnet_csv = self.write_subnets(*rows)

        plan = runtime.plan_dhcp_runtime(
            subnet_csv, link_snapshot=links, address_snapshot=addr,
        )

        expected = tuple(f"eno1.{100 + number}" for number in range(1, 6))
        self.assertEqual(expected, plan.listener_names)
        self.assertEqual(expected, runtime.build_dhcpd_argv(expected)[-5:])


class RuntimeBackendContractTests(unittest.TestCase):
    def test_backend_name_is_explicit_and_unknown_value_fails_closed(self) -> None:
        runtime = load_runtime_module()
        systemd = runtime.runtime_backend_from_environment({})
        supervisor = runtime.runtime_backend_from_environment({
            "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
        })
        self.assertEqual("systemd", systemd.name)
        self.assertEqual("supervisor", supervisor.name)
        with self.assertRaisesRegex(runtime.RuntimeContractError, "backend"):
            runtime.runtime_backend_from_environment({
                "HTTP_ZTP_RUNTIME_BACKEND": "auto",
            })

    def test_supervisor_backend_never_calls_systemctl_or_journalctl(self) -> None:
        runtime = load_runtime_module()
        calls = []

        def record(command, **_kwargs):
            calls.append(tuple(str(item) for item in command))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        backend = runtime.runtime_backend_from_environment(
            {"HTTP_ZTP_RUNTIME_BACKEND": "supervisor"},
            command_runner=record,
        )
        backend.start("apache2")
        backend.restart("isc-dhcp-server")
        backend.status("isc-dhcp-server")
        backend.read_log("apache2")
        backend.stop("apache2")

        self.assertTrue(calls)
        flattened = " ".join(item for call in calls for item in call)
        self.assertIn("supervisorctl", flattened)
        self.assertNotIn("systemctl", flattened)
        self.assertNotIn("journalctl", flattened)

    def test_supervisor_dhcp_log_is_a_bounded_regular_persistent_file(self) -> None:
        runtime = load_runtime_module()
        calls = []

        def record(command, **_kwargs):
            calls.append(tuple(str(item) for item in command))
            return SimpleNamespace(returncode=0, stdout="console", stderr="")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dhcp_log = root / "dhcpd.log"
            dhcp_log.write_text(
                "discard-this-complete-line\n"
                "2026-09-05 DHCPDISCOVER from 02:00:00:00:00:01\n",
                encoding="utf-8",
            )
            backend = runtime.SupervisorRuntimeBackend(
                record, dhcp_log_path=dhcp_log, max_log_bytes=56,
            )

            output = backend.read_log("isc-dhcp-server")

            self.assertLessEqual(len(output.encode("utf-8")), 56)
            self.assertIn("DHCPDISCOVER", output)
            self.assertFalse(calls, "DHCP evidence must come from its persistent log")

            link_path = root / "dhcpd-link.log"
            link_path.symlink_to(dhcp_log)
            unsafe = runtime.SupervisorRuntimeBackend(
                record, dhcp_log_path=link_path, max_log_bytes=56,
            )
            with self.assertRaisesRegex(
                runtime.RuntimeContractError, r"regular file|symlink",
            ):
                unsafe.read_log("isc-dhcp-server")

            directory = runtime.SupervisorRuntimeBackend(
                record, dhcp_log_path=root, max_log_bytes=56,
            )
            with self.assertRaisesRegex(runtime.RuntimeContractError, "regular file"):
                directory.read_log("isc-dhcp-server")

    def test_supervisor_non_dhcp_log_tail_is_bounded_and_explicit(self) -> None:
        runtime = load_runtime_module()
        calls = []

        def record(command, **_kwargs):
            calls.append(tuple(str(item) for item in command))
            return SimpleNamespace(returncode=0, stdout="console", stderr="")

        backend = runtime.SupervisorRuntimeBackend(record)
        self.assertEqual("console", backend.read_log("apache2"))
        self.assertEqual(
            ("supervisorctl", "tail", "-1048576", "apache2", "stdout"),
            calls[-1],
        )

    def test_supervisor_inactive_is_a_state_and_reload_uses_hup(self) -> None:
        runtime = load_runtime_module()
        calls = []
        service_state = {"dhcpd": "STOPPED", "apache2": "RUNNING"}

        def record(command, **_kwargs):
            command = tuple(str(item) for item in command)
            calls.append(command)
            if command[:2] == ("supervisorctl", "status"):
                program = command[2]
                state = service_state[program]
                return SimpleNamespace(
                    returncode=0 if state == "RUNNING" else 3,
                    stdout=f"{program} {state} test fixture\n",
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        backend = runtime.runtime_backend_from_environment(
            {"HTTP_ZTP_RUNTIME_BACKEND": "supervisor"},
            command_runner=record,
        )

        self.assertFalse(backend.is_active("isc-dhcp-server"))
        self.assertTrue(backend.is_active("apache2"))
        backend.reload("apache2")
        self.assertIn(
            ("supervisorctl", "signal", "HUP", "apache2"), calls,
        )

    def test_supervisor_unknown_status_fails_closed(self) -> None:
        runtime = load_runtime_module()

        def unknown(_command, **_kwargs):
            return SimpleNamespace(returncode=0, stdout="dhcpd CONFUSED\n", stderr="")

        backend = runtime.runtime_backend_from_environment(
            {"HTTP_ZTP_RUNTIME_BACKEND": "supervisor"},
            command_runner=unknown,
        )
        with self.assertRaisesRegex(runtime.RuntimeContractError, "status"):
            backend.is_active("isc-dhcp-server")

    def test_systemd_exposes_active_enabled_and_reload(self) -> None:
        runtime = load_runtime_module()
        calls = []

        def record(command, **_kwargs):
            command = tuple(str(item) for item in command)
            calls.append(command)
            if command[1] == "is-active":
                return SimpleNamespace(returncode=3, stdout="inactive\n", stderr="")
            if command[1] == "is-enabled":
                return SimpleNamespace(returncode=1, stdout="disabled\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        backend = runtime.runtime_backend_from_environment(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"},
            command_runner=record,
        )

        self.assertFalse(backend.is_active("isc-dhcp-server"))
        self.assertFalse(backend.is_enabled("isc-dhcp-server"))
        backend.reload("apache2")
        self.assertIn(("systemctl", "reload", "apache2"), calls)


class ContainerRuntimeWorkflowContractTests(unittest.TestCase):
    def test_day0_lifecycle_scripts_delegate_to_shared_runtime_module(self) -> None:
        for relative in (
            "DAY0-Prepare/11-load.py",
            "DAY0-Prepare/12-ztp-monitor.py",
            "DAY0-Prepare/13-unload.py",
        ):
            with self.subTest(script=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("ztp_service_runtime", source)

    def test_container_declares_host_network_and_supervisor_backend(self) -> None:
        docker_root = ROOT / "infra/docker"
        compose = (docker_root / "compose.yaml").read_text(encoding="utf-8")
        supervisor = (docker_root / "supervisord.conf").read_text(encoding="utf-8")
        entrypoint = (docker_root / "entrypoint.py").read_text(encoding="utf-8")

        self.assertIn("network_mode: host", compose)
        self.assertIn("HTTP_ZTP_RUNTIME_BACKEND: supervisor", compose)
        self.assertNotRegex(compose, r"(?m)^\s*ports\s*:")
        self.assertIn("nodaemon=true", supervisor)
        self.assertIn("dhcpd", supervisor)
        self.assertNotIn("systemctl", entrypoint)
        self.assertNotIn("journalctl", entrypoint)

    def test_real_lifecycle_scripts_share_one_supervisor_program_contract(self) -> None:
        """Exercise real load/monitor/unload functions, not copied facsimiles."""
        load = load_script_module(
            "container_workflow_load", "DAY0-Prepare/11-load.py",
        )
        monitor = load_script_module(
            "container_workflow_monitor", "DAY0-Prepare/12-ztp-monitor.py",
        )
        unload = load_script_module(
            "container_workflow_unload", "DAY0-Prepare/13-unload.py",
        )
        calls = []
        active = {
            "apache2": True,
            "isc-dhcp-server": True,
            "ztp-monitor": True,
            "switch-collection": True,
            "manual-ztp": True,
        }

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                calls.append(("active", service))
                return active[service]

            @staticmethod
            def is_enabled(_service):
                return None

            @staticmethod
            def start(service):
                calls.append(("start", service))
                active[service] = True

            @staticmethod
            def stop(service):
                calls.append(("stop", service))
                active[service] = False

            @staticmethod
            def restart(service):
                calls.append(("restart", service))
                active[service] = True

            @staticmethod
            def reload(service):
                calls.append(("reload", service))

            @staticmethod
            def read_log(service):
                calls.append(("log", service))
                return "DHCPDISCOVER from 02:00:00:00:00:01\n"

        plan = SimpleNamespace(listener_names=("eno2",), listener_ifindexes=(7,))
        inputs = SimpleNamespace(settings=SimpleNamespace(service_ips=()))
        forbidden = AssertionError(
            "supervisor workflow must not invoke systemctl or journalctl"
        )
        with mock.patch.object(
            load, "plan_local_dhcp_runtime", return_value=plan,
        ), mock.patch.object(
            load, "supports_local_ztp_services", return_value=True,
        ), mock.patch.object(
            load.subprocess, "run", side_effect=forbidden,
        ):
            self.assertIs(
                plan,
                load.quiesce_services(
                    False, inputs=inputs, runtime_backend=Backend(),
                ),
            )
        state = monitor.service_state("apache2", runtime_backend=Backend())
        text_value, error = monitor.collect_dhcp(30, runtime_backend=Backend())
        unload.stop_monitor(None, dry_run=False, runtime_backend=Backend())
        unload.stop_monitor_workers(dry_run=False, runtime_backend=Backend())
        unload.stop_services(dry_run=False, runtime_backend=Backend())

        self.assertIn(state["active"], {"active", "inactive"})
        self.assertIn("DHCPDISCOVER", text_value)
        self.assertEqual("", error)
        touched = {service for action, service in calls if action in {"active", "stop"}}
        self.assertEqual(
            {
                "apache2", "isc-dhcp-server", "ztp-monitor",
                "switch-collection", "manual-ztp",
            },
            touched,
        )
        self.assertEqual(
            [
                "ztp-monitor", "switch-collection", "manual-ztp",
                "isc-dhcp-server", "apache2",
            ],
            [service for action, service in calls if action == "stop"],
        )

    def test_dhcp_only_plan_matches_load_and_hostctl_service_convergence(self) -> None:
        """11-load and the real controller must both select only dhcpd."""
        load = load_script_module(
            "dhcp_only_workflow_load", "DAY0-Prepare/11-load.py",
        )
        hostctl = load_container_hostctl_module()
        plan = SimpleNamespace(
            listener_names=("eno7",), listener_ifindexes=(17,),
            direct_shared_networks=(), relay_shared_networks=(),
            dhcp_only_shared_networks=("provisioning",), endpoint_ips=(),
        )
        events = []
        active = {"apache2": True, "isc-dhcp-server": False}

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                return active[service]

            @staticmethod
            def start(service):
                events.append(("start", service))
                active[service] = True

            @staticmethod
            def stop(service):
                events.append(("stop", service))
                active[service] = False

            @staticmethod
            def restart(service):
                events.append(("restart", service))
                active[service] = True

        inputs = SimpleNamespace(settings=SimpleNamespace(service_ips=()))
        with mock.patch.object(
            load, "ensure_ztp_url_network_ready",
            side_effect=AssertionError("DHCP-only plan has no HTTP endpoint"),
        ), mock.patch.object(
            load, "verify_http_publication",
            side_effect=AssertionError("DHCP-only plan has no HTTP publication"),
        ), mock.patch.object(
            load.subprocess, "run",
            side_effect=AssertionError("Supervisor path cannot call systemctl"),
        ):
            load.start_services(
                inputs, {}, dhcp_runtime_plan=plan,
                runtime_backend=Backend(),
            )

        controller_expected = hostctl.activate.expected_services(plan)
        controller_state = {
            service: "STOPPED" for service in hostctl.activate.MANAGED_SERVICES
        }
        controller_state["apache2"] = "RUNNING"
        controller_events = []

        def controller_action(action, service):
            controller_events.append((action, service))
            controller_state[service] = "RUNNING" if action == "start" else "STOPPED"

        with mock.patch.object(
            hostctl, "supervisor_states",
            side_effect=lambda: dict(controller_state),
        ), mock.patch.object(
            hostctl, "supervisor_action", side_effect=controller_action,
        ):
            hostctl.converge_services(controller_expected, timeout=1)

        self.assertEqual(("dhcpd",), controller_expected)
        self.assertEqual(
            [("stop", "apache2"), ("start", "isc-dhcp-server")],
            events,
        )
        self.assertEqual(
            [
                ("stop", "ztp-monitor"),
                ("stop", "switch-collection"),
                ("stop", "manual-ztp"),
                ("stop", "apache2"),
                ("start", "dhcpd"),
            ],
            controller_events,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
