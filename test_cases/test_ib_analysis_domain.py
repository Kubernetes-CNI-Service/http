"""Domain fixtures for both bundled InfiniBand analysis tool trees."""

from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import importlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import pandas as pd
import xlsxwriter


ROOT = Path(__file__).resolve().parents[1]
TOOL_ROOTS = (
    ROOT / "tools/ib-tool-Jie/ib_tool_box",
    ROOT / "tools/ibdiagnet-analyze-tool",
)
IBDIAGNET_ROOT = TOOL_ROOTS[1]

SHARED_MODULES = (
    "lib.connection",
    "lib.excel",
    "lib.inventory",
    "lib.link_errors",
    "lib.reporting",
    "lib.parsers.db_csv",
    "lib.parsers.net_dump",
    "lib.parsers.net_dump_ext",
    "lib.parsers.partitions_conf",
    "lib.parsers.smdb",
)
SCRIPT_MODULES = (
    "scripts.check_hca_ooo_sl_mask",
    "scripts.check_ib_link_errors",
    "scripts.parse_ib_partition_config",
    "scripts.parse_ib_smdb",
    "scripts.parse_m_keys",
    "scripts.show_ib_inventory",
    "scripts.trace_ib_path",
    "scripts.validate_ib_topology",
)


def python_module_names(tool_root: Path) -> set[str]:
    result: set[str] = set()
    for path in tool_root.rglob("*.py"):
        relative = path.relative_to(tool_root)
        if relative.name == "__init__.py":
            result.add(".".join(relative.parent.parts))
        else:
            result.add(".".join(relative.with_suffix("").parts))
    return result


@contextmanager
def isolated_tool_imports(tool_root: Path):
    """Import one copied tool without leaking its generic lib/scripts names."""
    prefixes = ("lib", "scripts", "analyze")
    saved_modules = {
        name: module for name, module in sys.modules.items()
        if name in prefixes or name.startswith(("lib.", "scripts."))
    }
    for name in list(saved_modules):
        sys.modules.pop(name, None)
    old_path = sys.path[:]
    sys.path.insert(0, str(tool_root))
    try:
        yield importlib.import_module
    finally:
        for name in list(sys.modules):
            if name in prefixes or name.startswith(("lib.", "scripts.")):
                sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
        sys.path[:] = old_path


def write_ibdiagnet_fixture(directory: Path) -> None:
    """Create one switch-to-HCA link plus small inventory/counter sections."""
    (directory / "ibdiagnet2.db_csv").write_text(
        "START_NODES\n"
        "NodeGUID,NodeType,NodeDesc,SystemImageGUID\n"
        "0x1,2,MF0;leaf01:MQM9700/U1,0x1\n"
        "0x2,1,server01 mlx5_0,0x2\n"
        "END_NODES\n"
        "START_NODES_INFO\n"
        "NodeGUID,FWInfo_PSID,FWInfo_Major,FWInfo_Minor,FWInfo_SubMinor\n"
        "0x1,SW-PSID,0x1,0x2,0x3\n"
        "0x2,HCA-PSID,0x4,0x5,0x6\n"
        "END_NODES_INFO\n"
        "START_CABLE_INFO\n"
        "NodeGuid,PortNum,Vendor,PN,SN,Rev,FWVersion,Temperature\n"
        "0x1,1,NVIDIA,CAB-1,SN-1,A,1.0,42C\n"
        "END_CABLE_INFO\n"
        "START_PM_INFO\n"
        "NodeGUID,PortNumber,LinkDownedCounterExt,LinkErrorRecoveryCounterExt,"
        "PortRcvErrorsExt,PortXmitDiscardsExt,PortXmitPktsExtended,PortXmitWaitExt\n"
        "0x1,1,1,0,0,0,1000,10\n"
        "END_PM_INFO\n"
        "START_EXTENDED_PORT_INFO\n"
        "NodeGuid,PortNum,OOOSLMask,AdaptiveTimeoutSLMask\n"
        "0x2,1,0xffff,0xffff\n"
        "END_EXTENDED_PORT_INFO\n",
        encoding="utf-8",
    )
    (directory / "ibdiagnet2.net_dump").write_text(
        '"MF0;leaf01:MQM9700/U1", Mellanox, 0x1, LID 10\n'
        "# : IB# : Sta : PhysSta : MTU : LWA : LSA : FEC : RTR : "
        "Neighbor Guid : N# : NLID : Neighbor Description\n"
        'sw1p1 : 1 : ACT : LINK_UP : 5 : 4x : 200 : RS : NO-RTR : '
        '0x2 : 1 : 20 : "server01 mlx5_0"\n',
        encoding="utf-8",
    )
    (directory / "ibdiagnet2.net_dump_ext").write_text(
        "Ty : # : #IB : GUID : LID : Sta : PhysSta : LWA : LSA : "
        "Conn LID : FEC mode : RTR : Raw BER : Effective BER : Symbol BER : "
        "Symbol Err : Effective Err : Node Desc\n"
        'SW : sw1p1 : 1 : 0x1 : 10 (0xa) : ACT : LINK_UP : 4x : 200 : '
        '20 (0x14) : RS : NO-RTR : 1e-12 : 2e-13 : 3e-14 : 4 : 5 : '
        '"MF0;leaf01:MQM9700/U1"\n',
        encoding="utf-8",
    )


def write_opensm_fixture(root: Path) -> tuple[Path, Path]:
    config = root / "opensm-config"
    logs = root / "opensm-logs"
    config.mkdir()
    logs.mkdir()
    (config / "partitions.conf").write_text(
        "tenant=0x115,ipoib,defmember=limited : 0x2=full;\n",
        encoding="utf-8",
    )
    (config / "guid2mkey").write_text("0x2 0xabc\n", encoding="utf-8")
    (config / "guid2lid").write_text("0x2 0x14 0x14\n", encoding="utf-8")
    (logs / "opensm-smdb.dump").write_text(
        "START_NODES\n"
        "NodeGUID,NodeType,NodeDesc\n"
        "0x2,1,server01 mlx5_0\n"
        "END_NODES\n"
        "START_PORTS\n"
        "PortGUID,NodeGUID,LID,PortNum\n"
        "0x2,0x2,20,1\n"
        "END_PORTS\n"
        "START_SMS\n"
        "PortGUID,LID,Priority,State\n"
        "0x2,20,5,3\n"
        "END_SMS\n",
        encoding="utf-8",
    )
    return config, logs


class SharedIbLibraryDomainTests(unittest.TestCase):
    def test_domain_inventory_accounts_for_every_python_module(self):
        shared = {"lib", "lib.parsers", *SHARED_MODULES, *SCRIPT_MODULES}
        self.assertEqual(shared, python_module_names(TOOL_ROOTS[0]))
        self.assertEqual(
            shared | {
                "analyze", "lib.parsers.iblinkinfo", "lib.snapshot", "lib.topology",
            },
            python_module_names(IBDIAGNET_ROOT),
        )

    def test_shared_packages_parsers_models_and_reports_in_both_copies(self):
        for tool_root in TOOL_ROOTS:
            with self.subTest(tool=tool_root.name), tempfile.TemporaryDirectory() as name:
                fixture = Path(name)
                write_ibdiagnet_fixture(fixture)
                partitions_file = fixture / "partitions.conf"
                partitions_file.write_text(
                    "tenant=0x115,ipoib : 0x2=full,ALL_CAS=limited;\n",
                    encoding="utf-8",
                )
                with isolated_tool_imports(tool_root) as load:
                    package = load("lib")
                    parsers_package = load("lib.parsers")
                    self.assertEqual(tool_root / "lib/__init__.py", Path(package.__file__))
                    self.assertEqual(
                        tool_root / "lib/parsers/__init__.py",
                        Path(parsers_package.__file__),
                    )

                    modules = {name: load(name) for name in SHARED_MODULES}
                    db = modules["lib.parsers.db_csv"]
                    nodes = db.extract_section("NODES", fixture / "ibdiagnet2.db_csv")
                    self.assertEqual(["2", "1"], nodes["NodeType"].tolist())
                    self.assertIn("CABLE_INFO", db.list_sections(fixture / "ibdiagnet2.db_csv"))
                    self.assertTrue(db.extract_section("ABSENT", fixture / "ibdiagnet2.db_csv").empty)

                    smdb = modules["lib.parsers.smdb"]
                    self.assertEqual(2, len(smdb.extract_section(
                        "NODES", fixture / "ibdiagnet2.db_csv"
                    )))

                    net_dump = modules["lib.parsers.net_dump"]
                    links = net_dump.parse_links(fixture / "ibdiagnet2.net_dump")
                    self.assertEqual("leaf01", links.iloc[0]["hostname"])
                    self.assertEqual(20, net_dump.parse_guid_lid_map(
                        fixture / "ibdiagnet2.net_dump"
                    )["0x2"])

                    net_ext = modules["lib.parsers.net_dump_ext"]
                    extended = net_ext.parse_links_ext(fixture / "ibdiagnet2.net_dump_ext")
                    self.assertAlmostEqual(2e-13, extended.iloc[0]["eff_ber"])

                    part_parser = modules["lib.parsers.partitions_conf"]
                    partitions = part_parser.parse_partitions_conf(partitions_file)
                    self.assertEqual(["0x7fff", "0x115"], [p["pkey"] for p in partitions])

                    inventory = modules["lib.inventory"]
                    self.assertEqual(("server01", "mlx5_0"), inventory.split_hca_desc(
                        "server01 mlx5_0"
                    ))
                    node_types = inventory.build_node_type_map(fixture)
                    self.assertEqual("2", node_types["0x0000000000000001"])
                    diff = inventory.compare_dataframes(
                        pd.DataFrame([{"id": "a", "fw": "1"}]),
                        pd.DataFrame([{"id": "a", "fw": "2"}]),
                        ["id"], ["fw"],
                    )
                    self.assertEqual("Yes", diff.iloc[0]["Changed"])

                    connection = modules["lib.connection"]
                    built = connection.build_link_table(fixture, node_types)
                    self.assertEqual("server01", built.iloc[0]["neighbor_name"])
                    cable = connection.parse_cable_info(fixture)
                    self.assertEqual("SN-1", cable.iloc[0]["SN"])

                    errors = modules["lib.link_errors"]
                    error_rows = pd.DataFrame([
                        {"Src Device": "leaf01", "Src Port": "sw1p1",
                         "Src LinkDowned": 1, "Dst LinkDowned": 0,
                         "Src Transceiver Temp.": "80C"}
                    ])
                    self.assertEqual(1, len(errors.build_flapped_links(error_rows)))
                    self.assertEqual(1, len(errors.build_high_temp_links(error_rows, 70)))

                    excel = modules["lib.excel"]
                    report_path = fixture / f"{tool_root.name}-shared.xlsx"
                    workbook = xlsxwriter.Workbook(str(report_path))
                    excel.write_dataframe(workbook, "Rows", nodes)
                    excel.write_pivot(workbook, "NodeTypes", nodes, "NodeType", "NodeDesc")
                    modules["lib.reporting"].write_sheets(
                        workbook, [("Always", pd.DataFrame(columns=["empty"]), True)]
                    )
                    workbook.close()
                    self.assertGreater(report_path.stat().st_size, 0)

                    output = io.StringIO()
                    with redirect_stdout(output):
                        modules["lib.reporting"].section("Fabric", total=1)
                        modules["lib.reporting"].count_line("Links", 1)
                    self.assertIn("Fabric", output.getvalue())
                    self.assertIn("Links", output.getvalue())

    def test_shared_failure_paths_are_fail_closed(self):
        for tool_root in TOOL_ROOTS:
            with self.subTest(tool=tool_root.name), tempfile.TemporaryDirectory() as name:
                fixture = Path(name)
                malformed = fixture / "malformed.txt"
                malformed.write_text("not a supported record\n", encoding="utf-8")
                with isolated_tool_imports(tool_root) as load:
                    db = load("lib.parsers.db_csv")
                    net_dump = load("lib.parsers.net_dump")
                    net_ext = load("lib.parsers.net_dump_ext")
                    parts = load("lib.parsers.partitions_conf")
                    connection = load("lib.connection")
                    inventory = load("lib.inventory")
                    reporting = load("lib.reporting")
                    self.assertTrue(db.extract_section("NODES", malformed).empty)
                    self.assertTrue(net_dump.parse_links(malformed).empty)
                    self.assertTrue(net_ext.parse_links_ext(malformed).empty)
                    with self.assertRaises(ValueError):
                        parts._normalize_pkey("0x8000")
                    self.assertTrue(connection.build_link_table(fixture, {}).empty)
                    self.assertTrue(inventory.compare_dataframes(
                        pd.DataFrame(), pd.DataFrame(), ["id"], ["fw"]
                    ).empty)
                    with redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                        reporting.histogram_table([], [("0-10", [1, 2]), ("10-20", [1])])


class IbdiagnetExtensionDomainTests(unittest.TestCase):
    def test_iblinkinfo_snapshot_topology_and_dispatch_success_and_failure(self):
        with tempfile.TemporaryDirectory() as name, isolated_tool_imports(IBDIAGNET_ROOT) as load:
            root = Path(name)
            iblinkinfo_path = root / "iblinkinfo.log"
            iblinkinfo_path.write_text(
                "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                ' 10 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                '20 1[  ] "server01 mlx5_0"\n',
                encoding="utf-8",
            )
            iblinkinfo = load("lib.parsers.iblinkinfo")
            details = iblinkinfo.parse_iblinkinfo(iblinkinfo_path)
            self.assertEqual("sw1p1", details.iloc[0]["SrcPort"])
            bad_log = root / "iblinkinfo-empty.log"
            bad_log.write_text("no links\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                iblinkinfo.parse_iblinkinfo(bad_log)

            snapshot_dir = root / "snapshot"
            snapshot_dir.mkdir()
            write_ibdiagnet_fixture(snapshot_dir)
            archive = root / "ibdiagnet-sample.tar.gz"
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(snapshot_dir / "ibdiagnet2.net_dump", arcname="dump/ibdiagnet2.net_dump")
            snapshot = load("lib.snapshot")
            with snapshot.open_snapshot(archive) as opened:
                self.assertTrue((opened / "ibdiagnet2.net_dump").is_file())
            unsupported = root / "ibdiagnet.bin"
            unsupported.write_bytes(b"not an archive")
            with self.assertRaises(ValueError):
                with snapshot.open_snapshot(unsupported):
                    pass

            topology = load("lib.topology")
            planned = pd.DataFrame([{
                "SrcDevice": "leaf01", "SrcPort_Alias": "sw1p1", "SrcPort": "sw1p1",
                "DstDevice": "server01", "DstPort_Alias": "mlx5_0", "DstPort": "mlx5_0",
                "SrcType": "switch", "DstType": "host", "Source-Ref": "fixture",
            }])
            actual = pd.DataFrame([{
                "SrcDevice": "leaf01", "SrcPort": "sw1p1",
                "DstDevice": "server01", "DstPort": "mlx5_0", "_dst_is_sw": False,
            }])
            compared = topology.compare_links(actual, planned)
            self.assertEqual(1, len(compared.matching))
            actual.loc[0, "DstDevice"] = "wrong-server"
            self.assertEqual(1, len(topology.compare_links(actual, planned).miswired))
            with self.assertRaises(ValueError):
                topology.detect_plan_format({"Unknown": pd.DataFrame()})

            analyze = load("analyze")
            workbook = root / "cvt.xlsx"
            workbook.write_bytes(b"fixture identity only")
            found_snapshot, found_workbook = analyze.classify_inputs([
                str(workbook), str(snapshot_dir),
            ])
            self.assertEqual(snapshot_dir.resolve(), found_snapshot)
            self.assertEqual(workbook.resolve(), found_workbook)
            with self.assertRaises(ValueError):
                analyze.classify_inputs([str(workbook), str(workbook)])


class IbCliModuleDomainTests(unittest.TestCase):
    def test_each_cli_module_is_imported_and_calls_domain_code(self):
        for tool_root in TOOL_ROOTS:
            with self.subTest(tool=tool_root.name), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                ibdir = root / "ibdiagnet"
                ibdir.mkdir()
                write_ibdiagnet_fixture(ibdir)
                config, logs = write_opensm_fixture(root)
                with isolated_tool_imports(tool_root) as load:
                    modules = {name: load(name) for name in SCRIPT_MODULES}

                    sl_mask = modules["scripts.check_hca_ooo_sl_mask"].build_sl_mask_df(ibdir)
                    self.assertEqual("server01", sl_mask.iloc[0]["Hostname"])

                    link_report = root / "link-errors.xlsx"
                    empty = pd.DataFrame()
                    with redirect_stdout(io.StringIO()):
                        modules["scripts.check_ib_link_errors"].single_snapshot_excel(
                            link_report, *([empty] * 12)
                        )
                    self.assertGreater(link_report.stat().st_size, 0)

                    part_module = modules["scripts.parse_ib_partition_config"]
                    partitions = load("lib.parsers.partitions_conf").parse_partitions_conf(
                        config / "partitions.conf"
                    )
                    partition_rows = part_module.build_partitions_df(
                        partitions, logs / "opensm-smdb.dump"
                    )
                    self.assertIn("0x115", partition_rows.columns)
                    with self.assertRaises(SystemExit):
                        part_module._resolve_required_file(root / "missing", "x", "--fixture")

                    smdb_module = modules["scripts.parse_ib_smdb"]
                    normalized_guids = smdb_module._normalize_guid_col(
                        pd.Series(["0x2", float("nan")])
                    )
                    self.assertEqual("0x0000000000000002", normalized_guids.iloc[0])
                    self.assertEqual("", normalized_guids.iloc[1])
                    self.assertEqual(
                        {"0x0000000000000002": "0x0000000000000003"},
                        smdb_module._port_to_node_map(pd.DataFrame([
                            {"PortGUID": "0x2", "NodeGUID": "0x3"}
                        ])),
                    )

                    mkey_module = modules["scripts.parse_m_keys"]
                    mkeys = mkey_module.build_m_keys_df(config, logs)
                    self.assertEqual("0xabc", mkeys.iloc[0]["M_Key"])
                    with self.assertRaises(SystemExit):
                        mkey_module._check_config_files(root / "missing", "--fixture")

                    inventory_module = modules["scripts.show_ib_inventory"]
                    inventory_report = root / "inventory.xlsx"
                    with redirect_stdout(io.StringIO()):
                        inventory_module.single_snapshot_excel(
                            inventory_report, empty, None, empty, empty, empty, empty
                        )
                    self.assertGreater(inventory_report.stat().st_size, 0)

                    trace_module = modules["scripts.trace_ib_path"]
                    self.assertEqual([0, 1, 2], trace_module._parse_path("0,1,2"))
                    with self.assertRaises(Exception) as raised:
                        trace_module._parse_path("1,0")
                    self.assertEqual("ArgumentTypeError", type(raised.exception).__name__)

                    topology_module = modules["scripts.validate_ib_topology"]
                    if tool_root == IBDIAGNET_ROOT:
                        actual_type = topology_module.ActualResult(
                            links=pd.DataFrame([{
                                "SrcDevice": "leaf", "SrcPort": "sw1p1",
                                "DstDevice": "host", "DstPort": "mlx5_0",
                                "_dst_is_sw": False,
                            }])
                        )
                        self.assertEqual((1, 1, 0), topology_module._logical_actual_counts(actual_type))
                    else:
                        actual = pd.DataFrame([{
                            "SrcDevice": "leaf", "SrcPort": "sw1p1",
                            "DstDevice": "host", "DstPort": "mlx5_0",
                        }])
                        plan = pd.DataFrame([{
                            "SrcDevice": "leaf", "SrcPort": "sw1p1",
                            "DstDevice": "host", "DstPort": "mlx5_0",
                            "DstPort_Alias": "mlx5_0",
                        }])
                        matching, missing, undefined, miswired = topology_module.compare_links(
                            actual, plan
                        )
                        self.assertEqual((1, 0, 0, 0), tuple(map(
                            len, (matching, missing, undefined, miswired)
                        )))

    def test_real_cli_main_has_success_and_failure_contract_in_both_copies(self):
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for tool_root in TOOL_ROOTS:
            with self.subTest(tool=tool_root.name), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                ibdir = root / "ibdiagnet"
                ibdir.mkdir()
                write_ibdiagnet_fixture(ibdir)
                script = tool_root / "scripts/check_hca_ooo_sl_mask.py"
                output = root / "sl-mask.xlsx"
                success = subprocess.run(
                    [sys.executable, "-B", str(script), "-i", str(ibdir), "-o", str(output)],
                    cwd=ROOT, env=environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30, check=False,
                )
                self.assertEqual(0, success.returncode, success.stdout)
                self.assertGreater(output.stat().st_size, 0)
                failure = subprocess.run(
                    [sys.executable, "-B", str(script), "-i", str(root / "missing"),
                     "-o", str(root / "unused.xlsx")],
                    cwd=ROOT, env=environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30, check=False,
                )
                self.assertNotEqual(0, failure.returncode)
                self.assertIn("not found", failure.stdout.casefold())


if __name__ == "__main__":
    unittest.main()
