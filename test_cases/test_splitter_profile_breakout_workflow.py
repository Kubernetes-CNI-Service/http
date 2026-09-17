#!/usr/bin/env python3
"""REQ-14 P2P inference -> bound disk authority -> real NVUE template workflow.

Source: owner-pinned 0915 workbook, SHA256
15cf6d52ac11ddcab38ca64306fdee04b84ce7bc3dc002176a389d758c559df3.
This digest documents the manual transcription source; the automated fixture
does not access or rehash that private workbook at runtime.
Only hostnames are anonymized below. Port tokens, placeholder capitalization,
sheet names, row numbers and physical/empty distribution are retained from the
32 actual records: TAN OBJ-LF 75..82 / 155..162 and OOB LF-SP-CR-BL
764..771 / 804..811. No production output supplies an expected value.

The literal four-defect corpus covers mode and empty-lane semantics. Disk
workflows also cover the real producer/consumer entrypoints and fail-closed
binding. The private 436-port corpus byte comparison is separate evidence.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.test_mlag_evpn_generation import border_globals
from test_cases.test_qos_evpn_uplink_generation import ROOT, load_script
from test_cases.test_splitter_profile_breakout import GENERATOR, device_for_ports


P2P = load_script(
    "req14_splitter_topology", ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
)
P2P_DIR = ROOT / "ztp/config/cumulus/template/P2P"
CASES = (
    ("EXAMPLE-OOB-CORE01", "9", "bgp"),
    ("EXAMPLE-OOB-CORE02", "9", "bgp"),
    ("EXAMPLE-TAN-OBJ-LEAF01", "19", "bond"),
    ("EXAMPLE-TAN-OBJ-LEAF02", "19", "bond"),
)
CONNECTED_PORTS = {
    "EXAMPLE-OOB-CORE01": ["swp9s0", "swp9s1", "swp9s2", "swp9s3"],
    "EXAMPLE-OOB-CORE02": ["swp9s0", "swp9s1", "swp9s2", "swp9s3"],
    "EXAMPLE-TAN-OBJ-LEAF01": ["swp19s0"],
    "EXAMPLE-TAN-OBJ-LEAF02": ["swp19s0"],
}
UNUSED_PORTS = {
    "EXAMPLE-OOB-CORE01": {"swp9s4", "swp9s5", "swp9s6", "swp9s7"},
    "EXAMPLE-OOB-CORE02": {"swp9s4", "swp9s5", "swp9s6", "swp9s7"},
    "EXAMPLE-TAN-OBJ-LEAF01": {"swp19s1", "swp19s2", "swp19s3", "swp19s4", "swp19s5", "swp19s6", "swp19s7"},
    "EXAMPLE-TAN-OBJ-LEAF02": {"swp19s1", "swp19s2", "swp19s3", "swp19s4", "swp19s5", "swp19s6", "swp19s7"},
}


def corpus_rows():
    # Literal rows are not inferred from the generator or from its desired mode.
    groups = (
        ("TAN OBJ-LF", 75, "EXAMPLE-TAN-OBJ-LEAF01", (
            ("EXAMPLE-WEKA-NODE01", "P3", "19/1/1"),
            ("Empty", "Empty", "19/1/2"),
            ("Empty", "Empty", "19/1/3"),
            ("Empty", "Empty", "19/1/4"),
            ("Empty", "Empty", "19/2/1"),
            ("Empty", "Empty", "19/2/2"),
            ("Empty", "Empty", "19/2/3"),
            ("Empty", "Empty", "19/2/4"),
        )),
        ("TAN OBJ-LF", 155, "EXAMPLE-TAN-OBJ-LEAF02", (
            ("EXAMPLE-WEKA-NODE01", "P4", "19/1/1"),
            ("Empty", "Empty", "19/1/2"),
            ("Empty", "Empty", "19/1/3"),
            ("Empty", "Empty", "19/1/4"),
            ("Empty", "Empty", "19/2/1"),
            ("Empty", "Empty", "19/2/2"),
            ("Empty", "Empty", "19/2/3"),
            ("Empty", "Empty", "19/2/4"),
        )),
        ("OOB LF-SP-CR-BL", 764, "EXAMPLE-OOB-CORE01", (
            ("EXAMPLE-OOB-SPINE01", "31", "9/1/1"),
            ("EXAMPLE-OOB-SPINE02", "31", "9/1/2"),
            ("EXAMPLE-OOB-SPINE03", "31", "9/1/3"),
            ("EXAMPLE-OOB-SPINE04", "31", "9/1/4"),
            ("empty", "empty", "9/2/1"),
            ("empty", "empty", "9/2/2"),
            ("empty", "empty", "9/2/3"),
            ("empty", "empty", "9/2/4"),
        )),
        ("OOB LF-SP-CR-BL", 804, "EXAMPLE-OOB-CORE02", (
            ("EXAMPLE-OOB-SPINE01", "32", "9/1/1"),
            ("EXAMPLE-OOB-SPINE02", "32", "9/1/2"),
            ("EXAMPLE-OOB-SPINE03", "32", "9/1/3"),
            ("EXAMPLE-OOB-SPINE04", "32", "9/1/4"),
            ("empty", "empty", "9/2/1"),
            ("empty", "empty", "9/2/2"),
            ("empty", "empty", "9/2/3"),
            ("empty", "empty", "9/2/4"),
        )),
    )
    return [
        {"sheet": sheet, "row": first + offset,
         "fields": (peer, peer_port, hostname, port)}
        for sheet, first, hostname, records in groups
        for offset, (peer, peer_port, port) in enumerate(records)
    ]


def inferred_inputs():
    rows = corpus_rows()
    inventory, order = P2P.load_inventory(P2P_DIR / "01-inventory.log")
    direct, switch = P2P.load_port_map(P2P_DIR / "02-port-mapping.log")
    profiles, warnings = P2P.infer_splitter_profiles(
        [row["fields"] for row in rows], inventory, order, direct, switch,
    )
    if warnings:
        raise AssertionError(warnings)
    arguments = dict(inv_patterns=inventory, type_order=order,
                     port_direct=direct, port_switch=switch,
                     splitter_profiles=profiles)
    physical, _ = P2P._resolved_physical_links(
        [row["fields"] for row in rows], **arguments,
    )
    return rows, profiles, arguments, physical


class SplitterProfileWorkflowTests(unittest.TestCase):
    def test_real_p2p_entrypoint_writes_authority_consumed_before_generator_staging(self):
        from test_cases.test_xlsx_zero_row_fail_closed import prepare_runtime, invoke_main
        from openpyxl import Workbook

        def workbook_writer(path):
            book = Workbook()
            book.remove(book.active)
            # Preserve the real two-row, 23-column endpoint layout and source
            # row numbers. This is a transcribed fixture, not the private XLSX.
            for row in corpus_rows():
                if row["sheet"] not in book.sheetnames:
                    sheet = book.create_sheet(row["sheet"])
                    sheet.cell(1, 5, "Source")
                    sheet.cell(1, 11, "Dest")
                    for col, label in ((7, "name"), (8, "HCA/port"), (13, "name"), (14, "port")):
                        sheet.cell(2, col, label)
                    sheet.cell(2, 23)
                sheet = book[row["sheet"]]
                for col, value in zip((7, 8, 13, 14), row["fields"]):
                    sheet.cell(row["row"], col, value)
            book.save(path)
            book.close()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = prepare_runtime(root, workbook_writer)
            for key, filename in (("inventory", "01-inventory.log"), ("port_map", "02-port-mapping.log")):
                paths[key].write_bytes((P2P_DIR / filename).read_bytes())
            policy = root / "03-air-topology-policy.json"
            policy.write_text('{}\n', encoding="utf-8")
            caught, stdout, stderr = invoke_main(paths, [
                "-y", "--deployment-scope", "prod", "--air-link-policy", str(policy),
            ])
            self.assertTrue(caught is None or isinstance(caught, SystemExit) and caught.code == 0,
                            (repr(caught), stdout, stderr))
            sidecar = paths["output"] / "rack-links-splitter-profiles.json"
            self.assertTrue(sidecar.is_file())
            document = json.loads(sidecar.read_text())
            self.assertEqual(4, len(document["profiles"]))
            self.assertEqual({"1to8"}, {entry["profile"] for entry in document["profiles"]})
            self.assertEqual({
                ("example-oob-core01", "swp9"), ("example-oob-core02", "swp9"),
                ("example-tan-obj-leaf01", "swp19"), ("example-tan-obj-leaf02", "swp19"),
            }, {(entry["device"], entry["parent"]) for entry in document["profiles"]})
            output = root / "generated"
            device = device_for_ports("EXAMPLE-OOB-CORE01", ["swp9s0"], {})
            with mock.patch.multiple(GENERATOR, P2P_INPUT_DIR=str(paths["p2p_dir"]),
                                     P2P_OUTPUT_DIR=str(paths["output"]), OUTPUT_DIR=str(output)), \
                    mock.patch.object(GENERATOR, "load_devices", return_value=(
                        border_globals(), {"EXAMPLE-OOB-CORE01": device},
                    )), contextlib.redirect_stdout(io.StringIO()):
                GENERATOR.generate_all()
                rendered = yaml.safe_load((output / "EXAMPLE-OOB-CORE01.yaml").read_text())
                self.assertEqual({"8x": {"lanes-per-port": "1"}},
                                 rendered[0]["set"]["interface"]["swp9"]["link"]["breakout"])
                before = (output / "EXAMPLE-OOB-CORE01.yaml").read_bytes()
                sidecar.unlink()
                with self.assertRaisesRegex(ValueError, "splitter"), \
                        mock.patch.object(GENERATOR.os, "makedirs") as mkdir:
                    GENERATOR.generate_all()
                mkdir.assert_not_called()
                self.assertEqual(before, (output / "EXAMPLE-OOB-CORE01.yaml").read_bytes())

    def disk_fixture(self, root):
        rows, profiles, arguments, physical = inferred_inputs()
        workbook = root / "example.xlsx"
        from openpyxl import Workbook
        book = Workbook()
        sheet = book.active
        sheet.title = "P2P"
        sheet.append(["source_device", "source_port", "destination_device", "destination_port"])
        for row in rows:
            sheet.append(row["fields"])
        book.save(workbook)
        book.close()
        (root / "p2p.xlsx").symlink_to(workbook.name)
        inventory = root / "01-inventory.log"
        mapping = root / "02-port-mapping.log"
        inventory.write_bytes((P2P_DIR / inventory.name).read_bytes())
        mapping.write_bytes((P2P_DIR / mapping.name).read_bytes())
        output = root / "output-p2p"
        output.mkdir()
        dot = output / "example-lldpq.dot"
        dot.write_text('graph "example" {\n' + ''.join(
            f'"{a}":"{ap}" -- "{b}":"{bp}"\n' for a, ap, b, bp in physical
        ) + '}\n')
        P2P._write_splitter_profiles(str(dot), profiles, workbook, inventory, mapping)
        return workbook, inventory, mapping, dot, output / "example-splitter-profiles.json"

    def test_disk_profile_authority_reaches_real_generator_and_ignores_other_stems(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, _, _, sidecar = self.disk_fixture(root)
            (sidecar.parent / "newer-splitter-profiles.json").write_text("invalid unrelated")
            device = device_for_ports("OOB-CORE01", ["swp9s0"], {})
            with mock.patch.object(GENERATOR, "P2P_INPUT_DIR", str(root)), mock.patch.object(
                GENERATOR, "P2P_OUTPUT_DIR", str(sidecar.parent),
            ):
                GENERATOR._attach_splitter_profiles({"OOB-CORE01": device})
            self.assertEqual({"swp9": "1to8"}, device["splitter_profiles"])
            rendered = GENERATOR.render(GENERATOR.build_env(), border_globals(), "OOB-CORE01", device)
            interface = yaml.safe_load(rendered)[0]["set"]["interface"]
            self.assertEqual({"8x": {"lanes-per-port": "1"}}, interface["swp9"]["link"]["breakout"])
            self.assertEqual({"type": "swp"}, interface["swp9s7"])

    def test_disk_binding_and_schema_fail_closed(self):
        reasons = {
            "workbook": "stale splitter profile binding: workbook_sha256",
            "inventory": "stale splitter profile binding: inventory_sha256",
            "mapping": "stale splitter profile binding: port_mapping_sha256",
            "dot": "stale splitter profile binding: lldpq_sha256",
            "missing": "No such file or directory",
            "schema": "invalid splitter profile schema/source identity",
            "source": "invalid splitter profile schema/source identity",
            "source-case": "invalid splitter profile schema/source identity",
            "duplicate-profile": "duplicate splitter profile example-",
            "ambiguous-host": "ambiguous P2P splitter profile device ownership for OOB-CORE01",
            "duplicate-json": "duplicate splitter profile JSON key: schema_version",
            "profiles-object": "splitter profiles must be a list",
            "entry-not-object": "invalid splitter profile entry",
            "entry-extra-key": "invalid splitter profile entry",
            "entry-non-string": "invalid splitter profile entry",
            "entry-invalid-profile": "invalid splitter profile entry",
            "entry-invalid-parent": "invalid splitter profile entry",
            "entry-invalid-host": "invalid splitter profile entry",
            "symlink": "sidecar must be a single-link regular file",
            "hardlink": "sidecar must be a single-link regular file",
        }
        for mutation, reason in reasons.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                workbook, inventory, mapping, dot, sidecar = self.disk_fixture(root)
                paths = dict(workbook=workbook, inventory=inventory, mapping=mapping, dot=dot)
                if mutation in paths:
                    with paths[mutation].open("ab") as stream:
                        stream.write(b"changed")
                elif mutation == "missing":
                    sidecar.rename(sidecar.with_name("other-splitter-profiles.json"))
                elif mutation == "duplicate-json":
                    text = sidecar.read_text()
                    sidecar.write_text(text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
                elif mutation in {"symlink", "hardlink"}:
                    target = sidecar.with_name("preserved-sidecar.json")
                    if mutation == "symlink":
                        sidecar.rename(target)
                        sidecar.symlink_to(target.name)
                    else:
                        os.link(sidecar, target)
                else:
                    document = json.loads(sidecar.read_text())
                    if mutation == "schema":
                        document["schema_version"] = 2
                    elif mutation == "source":
                        document["source_workbook"] = "other.xlsx"
                    elif mutation == "source-case":
                        document["source_workbook"] = "EXAMPLE.xlsx"
                    elif mutation == "duplicate-profile":
                        document["profiles"].append(dict(document["profiles"][0]))
                    elif mutation == "ambiguous-host":
                        document["profiles"].append(dict(device="SECOND-OOB-CORE01", parent="swp9", profile="1to8"))
                    elif mutation == "profiles-object":
                        document["profiles"] = {}
                    elif mutation == "entry-not-object":
                        document["profiles"][0] = "invalid"
                    else:
                        field, value = {
                            "entry-extra-key": ("extra", "invalid"),
                            "entry-non-string": ("device", 123),
                            "entry-invalid-profile": ("profile", "1to16"),
                            "entry-invalid-parent": ("parent", "swp9s0"),
                            "entry-invalid-host": ("device", "host/escape"),
                        }[mutation]
                        document["profiles"][0][field] = value
                    sidecar.write_text(json.dumps(document))
                with mock.patch.object(GENERATOR, "P2P_INPUT_DIR", str(root)), mock.patch.object(
                    GENERATOR, "P2P_OUTPUT_DIR", str(sidecar.parent),
                ), self.assertRaisesRegex(ValueError, reason):
                    GENERATOR._attach_splitter_profiles({"OOB-CORE01": device_for_ports(
                        "OOB-CORE01", ["swp9s0"], {},
                    )})

    def test_bond_only_model_loads_disk_authority_and_does_not_render_unused_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, _, _, sidecar = self.disk_fixture(root)
            document = json.loads(sidecar.read_text())
            document["profiles"].append(dict(device="EXAMPLE-TAN-OBJ-LEAF01", parent="swp20", profile="1to8"))
            sidecar.write_text(json.dumps(document))
            device = device_for_ports("TAN-OBJ-LEAF01", ["swp19s0"], {"swp19": "1to2"}, role="bond")
            with mock.patch.object(GENERATOR, "P2P_INPUT_DIR", str(root)), mock.patch.object(
                GENERATOR, "P2P_OUTPUT_DIR", str(sidecar.parent),
            ):
                GENERATOR._attach_splitter_profiles({"TAN-OBJ-LEAF01": device})
            self.assertEqual({"swp19": "1to8", "swp20": "1to8"}, device["splitter_profiles"])
            rendered = GENERATOR.render(GENERATOR.build_env(), border_globals(), "TAN-OBJ-LEAF01", device)
            interfaces = yaml.safe_load(rendered)[0]["set"]["interface"]
            self.assertEqual({"8x": {"lanes-per-port": "1"}}, interfaces["swp19"]["link"]["breakout"])
            self.assertFalse(any(name == "swp20" or name.startswith("swp20s") for name in interfaces))

    def test_missing_owner_clears_cached_authority_and_suffix_requires_hyphen_boundary(self):
        for unmatched_host in ("EXAMPLEOOB-CORE01", "UNRELATED-HOST"):
            with self.subTest(host=unmatched_host), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _, _, _, _, sidecar = self.disk_fixture(root)
                document = json.loads(sidecar.read_text())
                document["profiles"] = [dict(device=unmatched_host, parent="swp9", profile="1to8")]
                sidecar.write_text(json.dumps(document))
                device = device_for_ports("OOB-CORE01", ["swp9s0"], {"swp9": "1to8"})
                with mock.patch.object(GENERATOR, "P2P_INPUT_DIR", str(root)), mock.patch.object(
                    GENERATOR, "P2P_OUTPUT_DIR", str(sidecar.parent),
                ):
                    GENERATOR._attach_splitter_profiles({"OOB-CORE01": device})
                self.assertEqual({}, device["splitter_profiles"])
                with self.assertRaisesRegex(ValueError, "splitter profile missing/invalid for swp9"):
                    GENERATOR.preprocess_device(device)

    def test_csv_model_generation_rejects_stale_sidecar_before_intermediate_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, _, _, sidecar = self.disk_fixture(root)
            document = json.loads(sidecar.read_text())
            document["workbook_sha256"] = "0" * 64
            sidecar.write_text(json.dumps(document))
            global_file = root / "01-global.yaml"
            global_file.write_text(yaml.safe_dump({
                "schema_version": 2,
                "common": {"mgmt": {"ztp": {"ztp_url_prefix": "/ztp"}}},
                "switches": [{"eth": {
                    "version": "5.18.1", "bridge": {}, "system": {}, "mlag": {},
                    "vrr": {"base_mac": "02:00:5e:01:00:00", "gateway_ip": "subnet_maximum"},
                }}],
            }))
            devices_file = root / "02-devices_config.csv"
            header = [
                "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac",
                "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
                "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac", "peerlink_ports", "vrl",
                "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan",
                "svi_ip", "netmask", "vlan_ports",
            ]
            row = [
                "OOB-CORE01", "eth", "oob-core", "192.0.2.10", "24", "192.0.2.1", "02:00:00:00:00:10",
                "NA", "NA", "NA", "NA", "198.51.100.10", "65001", "swp9s0",
                "NA", "NA", "NA", "NA", "false", "BLUE", "NA", "NA", "NA", "NA", "100",
                "NA", "NA", "NA",
            ]
            with devices_file.open("w", newline="") as stream:
                csv.writer(stream).writerows([header, row])
            intermediate = root / "91-devices.yaml"
            intermediate.write_bytes(b"previous model must remain intact\n")
            output = io.StringIO()
            with mock.patch.multiple(
                GENERATOR, _CSV_FILE=str(devices_file), _GLOBAL_FILE=str(global_file),
                DEVICES_FILE=str(intermediate), P2P_INPUT_DIR=str(root), P2P_OUTPUT_DIR=str(sidecar.parent),
            ), mock.patch.object(GENERATOR, "_refresh_cumulus_defaults_from_global"), \
                    contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
                GENERATOR._generate_devices_yaml()
            self.assertEqual(1, caught.exception.code)
            self.assertIn("stale splitter profile binding: workbook_sha256", output.getvalue())
            self.assertEqual(b"previous model must remain intact\n", intermediate.read_bytes())
            self.assertFalse(intermediate.with_suffix(".yaml.tmp").exists())

    def test_stale_cleanup_is_exact_stem_and_source_receipts_do_not_require_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, _, _, dot, sidecar = self.disk_fixture(root)
            unrelated = sidecar.with_name("unrelated-splitter-profiles.json")
            unrelated.write_bytes(b"keep")
            P2P._remove_stale_workbook_outputs(str(dot))
            self.assertFalse(sidecar.exists())
            self.assertEqual(b"keep", unrelated.read_bytes())
            receipt = {"source_yaml_b64": "receipt", "bgp_neighbors": ["swp9s0"]}
            with mock.patch.object(GENERATOR, "P2P_INPUT_DIR", str(root)):
                GENERATOR._attach_splitter_profiles({"RECEIPT": receipt})
            self.assertEqual({"source_yaml_b64": "receipt", "bgp_neighbors": ["swp9s0"]}, receipt)

    def test_producer_refuses_changed_inputs_before_atomic_profile_publication(self):
        for changed in (0, 1, 2):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                inputs = self.disk_fixture(Path(directory))
                workbook, inventory, mapping, dot, sidecar = inputs
                expected = P2P._splitter_source_hashes(workbook, inventory, mapping)
                before = sidecar.read_bytes()
                inputs[changed].write_bytes(inputs[changed].read_bytes() + b"changed")
                with self.assertRaisesRegex(ValueError, "inputs changed"), mock.patch.object(
                    P2P, "_mini_air_atomic_write",
                ) as publish:
                    P2P._write_splitter_profiles(dot, {}, workbook, inventory, mapping,
                                                expected_hashes=expected)
                publish.assert_not_called()
                self.assertEqual(before, sidecar.read_bytes())

    def test_real_partial_lane_records_generate_eight_way_parents_and_fillers(self):
        rows, profiles, arguments, physical = inferred_inputs()
        self.assertEqual(10, len(physical), "empty peers must never create DOT links")
        with tempfile.TemporaryDirectory() as directory:
            for hostname, base, role in CASES:
                with self.subTest(hostname=hostname):
                    self.assertEqual("1to8", profiles[(hostname.casefold(), base)])
                    ports = [port for link in physical for host, port in
                             ((link[0], link[1]), (link[2], link[3])) if host == hostname]
                    self.assertEqual(CONNECTED_PORTS[hostname], sorted(ports))
                    device = device_for_ports(
                        hostname, ports, {f"swp{base}": profiles[(hostname.casefold(), base)]},
                        role=role,
                    )
                    rendered = GENERATOR.render(
                        GENERATOR.build_env(), border_globals(), hostname, device,
                    )
                    path = Path(directory) / f"{hostname}.yaml"
                    path.write_text(rendered, encoding="utf-8")
                    interfaces = yaml.safe_load(rendered)[0]["set"]["interface"]
                    self.assertEqual(
                        {"8x": {"lanes-per-port": "1"}},
                        interfaces[f"swp{base}"]["link"]["breakout"],
                    )
                    unused = UNUSED_PORTS[hostname]
                    self.assertEqual(unused, GENERATOR._unused_breakout_filler_ports(path, unused))
                    for port in unused:
                        self.assertEqual({"type": "swp"}, interfaces[port])

    def test_real_empty_intent_is_not_reported_missing_after_generation(self):
        rows, profiles, arguments, physical = inferred_inputs()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "generated"
            output.mkdir()
            for hostname, base, role in CASES:
                ports = [port for link in physical for host, port in
                         ((link[0], link[1]), (link[2], link[3])) if host == hostname]
                self.assertEqual(CONNECTED_PORTS[hostname], sorted(ports))
                device = device_for_ports(hostname, ports, {f"swp{base}": "1to8"}, role=role)
                (output / f"{hostname}.yaml").write_text(GENERATOR.render(
                    GENERATOR.build_env(), border_globals(), hostname, device,
                ), encoding="utf-8")
            dot = root / "p2p-lldpq.dot"
            dot.write_text('graph "example" {\n' + ''.join(
                f'"{a}":"{ap}" -- "{b}":"{bp}"\n' for a, ap, b, bp in physical
            ) + '}\n', encoding="utf-8")
            intent = P2P._build_description_intent_document(
                rows, **arguments, lldpq_bytes=dot.read_bytes(), source_workbook="p2p.xlsx",
            )
            self.assertEqual(22, len(intent["empty_endpoints"]))
            self.assertEqual({(host, port) for host, ports in UNUSED_PORTS.items() for port in ports},
                             {(entry["device"], entry["port"]) for entry in intent["empty_endpoints"]})
            P2P._write_description_intent(str(dot), intent)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), mock.patch.object(
                GENERATOR, "_load_csv_hostnames", return_value=set(),
            ):
                GENERATOR._run_patch_descriptions(str(dot), str(output))
            self.assertNotIn("P2P 标记为空的接口未出现在 yaml 中", stdout.getvalue())
            for endpoint in intent["empty_endpoints"]:
                path = Path(str(output) + "_with_desc") / f"{endpoint['device']}.yaml"
                interfaces = yaml.safe_load(path.read_text())[0]["set"]["interface"]
                self.assertEqual("P2P:----UNUSED-----NO-PEER",
                                 interfaces[endpoint["port"]]["description"])


if __name__ == "__main__":
    unittest.main()
