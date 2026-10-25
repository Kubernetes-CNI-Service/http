"""I06 stage1 independent contract TEXT; O-only, NOTRUN, not a W test.

Proposed placement: test_cases/test_infra_component_contract.py.
Requires a separately reviewed future tools/infra_components.py; this file is
not permission to add that implementation or register an idle workflow.
All literals below are handwritten contract expectations, never SUT output.
"""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InfraComponentCodecContractTests(unittest.TestCase):
    def _subject(self):
        path = ROOT / "tools" / "infra_components.py"
        spec = importlib.util.spec_from_file_location("_i06_component_subject", path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        subject = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(subject)
        return subject

    def test_target_packet_and_host_function_selection_are_literal(self):
        subject = self._subject()
        actual = subject.select_load_components(
            http_enabled=True, dhcp_enabled=False, ztp_enabled=False,
            device_types=("ib",), workbook_selected=True, features=(),
        )
        expected = (
            "load-core", "http", "render-ib", "validate-xlsx",
            "init-dns", "init-ntp", "init-timezone", "init-lldp",
        )
        self.assertEqual(expected, actual)
        self.assertEqual(
            "load-core,http,render-ib,validate-xlsx,init-dns,init-ntp,init-timezone,init-lldp",
            subject.encode_load_components(actual),
        )
        # No arbitrary host package names and no guessed optional consumers.
        for forbidden in (
            "dhcp", "ztp-runtime", "render-eth", "password-hash",
            "password-ssh", "docker", "nfs", "power-cycle", "analysis", "doca",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, actual)

    def test_all_explicit_consumers_keep_fixed_order_and_default_initialization(self):
        subject = self._subject()
        # Reverse supplied order cannot become shell execution/package order.
        actual = subject.select_load_components(
            http_enabled=True, dhcp_enabled=True, ztp_enabled=True,
            device_types=("nvl", "ib", "eth"), workbook_selected=True,
            features=("doca", "analysis", "power-cycle", "nfs", "docker",
                      "password-ssh", "password-hash"),
        )
        expected = (
            "load-core", "http", "dhcp", "ztp-runtime", "render-eth",
            "render-ib", "render-nvl", "validate-xlsx", "password-hash",
            "password-ssh", "docker", "nfs", "power-cycle", "analysis", "doca",
            "init-dns", "init-ntp", "init-timezone", "init-lldp",
        )
        self.assertEqual(expected, actual)
        wire = (
            "load-core,http,dhcp,ztp-runtime,render-eth,render-ib,render-nvl,"
            "validate-xlsx,password-hash,password-ssh,docker,nfs,power-cycle,"
            "analysis,doca,init-dns,init-ntp,init-timezone,init-lldp"
        )
        self.assertEqual(wire, subject.encode_load_components(actual))
        self.assertEqual(expected, subject.parse_load_components(wire))
        self.assertLessEqual(len(wire.encode("ascii")), 512)
        # no_upgrade is intentionally NOT an API input. Caller provenance must
        # preserve actual password/DOCA decisions independently of image policy.

    def test_parse_encode_are_strict_canonical_codec_not_package_authority(self):
        subject = self._subject()
        minimal = ("load-core", "init-dns", "init-ntp", "init-timezone", "init-lldp")
        literal = "load-core,init-dns,init-ntp,init-timezone,init-lldp"
        self.assertEqual(minimal, subject.parse_load_components(literal))
        self.assertEqual(literal, subject.encode_load_components(tuple(reversed(minimal))))
        bad_wires = (
            "", "load-core", "init-dns,load-core,init-ntp,init-timezone,init-lldp",
            literal + ",", "," + literal, literal + ",http",
            literal + ",http,http", literal.replace("load-core", "LOAD-CORE"),
            literal.replace("load-core", "load_core"), literal + ",apt-get",
            literal + ",python3", literal + ",../../x",
            literal + ",$(id)", literal + ";touch X", literal + "\n",
            literal + "\x00", literal + ",é", "x" * 512, "x" * 513,
            literal.encode("ascii"), None, True, 1,
        )
        for wire in bad_wires:
            with self.subTest(wire=repr(wire)):
                with self.assertRaises(ValueError):
                    subject.parse_load_components(wire)
        for components in (
            (), ("load-core",), minimal + ("http", "http"),
            minimal + ("python3",), minimal + ("$(id)",),
            ("LOAD-CORE",) + minimal[1:], list(minimal), literal, None,
        ):
            with self.subTest(components=repr(components)):
                with self.assertRaises(ValueError):
                    subject.encode_load_components(components)

    def test_selection_rejects_unknown_or_unresolved_input_instead_of_guessing_false(self):
        subject = self._subject()
        valid = dict(
            http_enabled=True, dhcp_enabled=False, ztp_enabled=False,
            device_types=("ib",), workbook_selected=False, features=(),
        )
        self.assertEqual(
            ("load-core", "http", "render-ib", "init-dns", "init-ntp",
             "init-timezone", "init-lldp"),
            subject.select_load_components(**valid),
        )
        bad_values = {
            "http_enabled": (0, 1, None, "true"),
            "dhcp_enabled": (0, 1, None, "false"),
            "ztp_enabled": (0, 1, None, "false"),
            "workbook_selected": (0, 1, None, "false"),
            "device_types": (("ib", "ib"), ("ethernet",), ("IB",), ("../eth",), ["ib"], "ib", None),
            "features": (("doca", "doca"), ("unknown",), ("jq",), ("--all",),
                         ("password-hash;id",), ["doca"], "doca", None),
        }
        for field, values in bad_values.items():
            for value in values:
                with self.subTest(field=field, value=repr(value)):
                    supplied = dict(valid)
                    supplied[field] = value
                    with self.assertRaises(ValueError):
                        subject.select_load_components(**supplied)


    def test_each_optional_feature_alone_and_each_family_has_literal_output(self):
        subject = self._subject()
        cases = (
            ((), (), ("load-core", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            (("eth",), (), ("load-core", "render-eth", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            (("nvl",), (), ("load-core", "render-nvl", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("password-hash",), ("load-core", "password-hash", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("password-ssh",), ("load-core", "password-ssh", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("docker",), ("load-core", "docker", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("nfs",), ("load-core", "nfs", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("power-cycle",), ("load-core", "power-cycle", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("analysis",), ("load-core", "analysis", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
            ((), ("doca",), ("load-core", "doca", "init-dns", "init-ntp", "init-timezone", "init-lldp")),
        )
        for families, features, expected in cases:
            with self.subTest(families=families, features=features):
                self.assertEqual(
                    expected,
                    subject.select_load_components(
                        http_enabled=False, dhcp_enabled=False, ztp_enabled=False,
                        device_types=families, workbook_selected=False, features=features,
                    ),
                )

    def test_wrong_tuple_elements_raise_valueerror_not_typeerror(self):
        subject = self._subject()
        valid = dict(
            http_enabled=True, dhcp_enabled=False, ztp_enabled=False,
            device_types=("ib",), workbook_selected=False, features=(),
        )
        for field in ("device_types", "features"):
            for element in (True, 1, None, [], {}):
                with self.subTest(field=field, element=repr(element)):
                    supplied = dict(valid)
                    supplied[field] = (element,)
                    with self.assertRaises(ValueError):
                        subject.select_load_components(**supplied)
        for element in (True, 1, None, [], {}):
            with self.subTest(encoder_element=repr(element)):
                supplied = (
                    "load-core", element, "init-dns", "init-ntp",
                    "init-timezone", "init-lldp",
                )
                with self.assertRaises(ValueError):
                    subject.encode_load_components(supplied)


if __name__ == "__main__":
    unittest.main()
