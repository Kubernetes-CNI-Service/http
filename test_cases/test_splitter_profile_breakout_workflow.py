#!/usr/bin/env python3
"""REQ-14 P2P inference -> bound disk authority -> real NVUE template workflow.

Source: owner-pinned 0915 workbook, SHA256
15cf6d52ac11ddcab38ca64306fdee04b84ce7bc3dc002176a389d758c559df3.
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
import io
import json
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
            sheet = book.active
            sheet.title = "TAN-OOB"
            sheet.append(["Source", "", "Dest", ""])
            sheet.append(["name", "port", "name", "port"])
            for row in corpus_rows():
                sheet.append(row["fields"])
            book.save(path)
            book.close()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = prepare_runtime(root, workbook_writer)
            for key, filename in (("inventory", "01-inventory.log"), ("port_map", "02-port-mapping.log")):
                paths[key].write_bytes((P2P_DIR / filename).read_bytes())
            caught, stdout, stderr = invoke_main(paths, ["-y", "--deployment-scope", "prod"])
            self.assertTrue(caught is None or isinstance(caught, SystemExit) and caught.code == 0,
                            (repr(caught), stdout, stderr))
            sidecar = paths["output"] / "rack-links-splitter-profiles.json"
            self.assertTrue(sidecar.is_file())
            document = json.loads(sidecar.read_text())
            self.assertEqual(4, len(document["profiles"]))
            self.assertEqual({"1to8"}, {entry["profile"] for entry in document["profiles"]})
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
        for mutation in ("workbook", "inventory", "mapping", "dot", "missing",
                         "schema", "source", "duplicate-profile", "ambiguous-host", "duplicate-json"):
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
                else:
                    document = json.loads(sidecar.read_text())
                    if mutation == "schema":
                        document["schema_version"] = 2
                    elif mutation == "source":
                        document["source_workbook"] = "other.xlsx"
                    elif mutation == "duplicate-profile":
                        document["profiles"].append(dict(document["profiles"][0]))
                    else:
                        document["profiles"].append(dict(device="SECOND-OOB-CORE01", parent="swp9", profile="1to8"))
                    sidecar.write_text(json.dumps(document))
                with mock.patch.object(GENERATOR, "P2P_INPUT_DIR", str(root)), mock.patch.object(
                    GENERATOR, "P2P_OUTPUT_DIR", str(sidecar.parent),
                ), self.assertRaisesRegex(ValueError, "splitter|profile|P2P"):
                    GENERATOR._attach_splitter_profiles({"OOB-CORE01": device_for_ports(
                        "OOB-CORE01", ["swp9s0"], {},
                    )})

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
        self.assertEqual(32, len(rows))
        self.assertEqual(10, len(physical), "empty peers must never create DOT links")
        with tempfile.TemporaryDirectory() as directory:
            for hostname, base, role in CASES:
                with self.subTest(hostname=hostname):
                    self.assertEqual("1to8", profiles[(hostname.casefold(), base)])
                    ports = [port for link in physical for host, port in
                             ((link[0], link[1]), (link[2], link[3])) if host == hostname]
                    self.assertEqual(4 if role == "bgp" else 1, len(ports))
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
                    unused = {f"swp{base}s{i}" for i in range(8)} - set(ports)
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
