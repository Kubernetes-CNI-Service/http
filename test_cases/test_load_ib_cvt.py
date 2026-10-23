"""Load turns the project P2P into the IB expected topology, as it does for Ethernet.

Owner 2026-10-21 ("review load 处理 eth 设备的流程，然后用来做 ib 的处理"; CVT "放项目的 99-output-p2p"):
Ethernet runs cumulus/template/P2P/b-xlsx_to_dot.py and verifies its splitter sidecar and lldpq.dot;
for IB devices load runs nvos/template/P2P/p2p-to-validation.py from its own directory and verifies
the published <p2p>-cvt.xlsx and its provenance against this load's P2P
(infiniband/monitor/UFM-MONITOR.md section 13)."""

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_cases.test_ib_cvt_project_output import write_p2p

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("day0_load_ib_cvt", ROOT / "DAY0-Prepare/11-load.py")
LOAD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LOAD
SPEC.loader.exec_module(LOAD)


def converter_layout(root: Path) -> tuple[Path, Path, Path]:
    """root/ztp as load's ZTP_DIR with the converter and the links setup creates."""
    config = root / "ztp/config"
    p2p_dir = config / "nvos/template/P2P"
    p2p_dir.mkdir(parents=True)
    shutil.copy2(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py", p2p_dir / "p2p-to-validation.py")
    for name in ("topology_rules.py", "ib_topology_provenance.py"):
        shutil.copy2(ROOT / "ztp/config" / name, config / name)
    project = root / "DAY0-Prepare/fabric-a"
    (project / "99-output-p2p").mkdir(parents=True)
    write_p2p(project / "fabric-blue.xlsx")
    (project / "p2p.xlsx").symlink_to("fabric-blue.xlsx")
    (p2p_dir / "p2p.xlsx").symlink_to("../../../../../DAY0-Prepare/fabric-a/p2p.xlsx")
    (p2p_dir / "output-p2p").symlink_to("../../../../../DAY0-Prepare/fabric-a/99-output-p2p")
    for name, text in (("01-inventory.log", "[IB-SW]\n*leaf*\n\n[server]\n*server*\n"),
                       ("02-port-mapping.log", ""), ("03-splitter.log", "")):
        (p2p_dir / name).write_text(text, encoding="utf-8")
    return p2p_dir, project, project / "fabric-blue.xlsx"


def run_converter(p2p_dir: Path) -> None:
    completed = subprocess.run([sys.executable, "-B", "p2p-to-validation.py"], cwd=p2p_dir,
                               capture_output=True, text=True, timeout=120, check=False,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert completed.returncode == 0, completed.stdout + completed.stderr


class IbCvtVerificationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.p2p_dir, self.project, self.workbook = converter_layout(self.root)
        run_converter(self.p2p_dir)
        self.cvt = self.project / "99-output-p2p/fabric-blue-cvt.xlsx"
        self.identities = {"p2p": hashlib.sha256(self.workbook.read_bytes()).hexdigest()}
        patcher = mock.patch.object(LOAD, "ZTP_DIR", self.root / "ztp")
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_published_cvt_is_bound_to_this_loads_p2p(self):
        record = LOAD.verify_ib_cvt(self.identities)
        self.assertEqual(str(self.cvt), record["cvt"])
        self.assertEqual(hashlib.sha256(self.cvt.read_bytes()).hexdigest(), record["cvt_sha256"])
        sidecar = Path(f"{self.cvt}.provenance.json")
        self.assertEqual(hashlib.sha256(sidecar.read_bytes()).hexdigest(), record["provenance_sha256"])

    def test_another_p2p_than_this_load_selected_is_refused(self):
        with self.assertRaisesRegex(LOAD.LoadError, "P2P"):
            LOAD.verify_ib_cvt({"p2p": "0" * 64})

    def test_a_p2p_changed_after_the_cvt_is_refused(self):
        with open(self.workbook, "ab") as stream:
            stream.write(b"\0")
        with self.assertRaises(LOAD.LoadError):
            LOAD.verify_ib_cvt(None)

    def test_a_missing_cvt_or_sidecar_is_refused(self):
        Path(f"{self.cvt}.provenance.json").unlink()
        with self.assertRaises(LOAD.LoadError):
            LOAD.verify_ib_cvt(self.identities)
        self.cvt.unlink()
        with self.assertRaises(LOAD.LoadError):
            LOAD.verify_ib_cvt(self.identities)

    def test_a_cvt_that_is_not_one_regular_file_is_refused(self):
        os.link(self.cvt, self.root / "second-name.xlsx")
        with self.assertRaisesRegex(LOAD.LoadError, "单链接"):
            LOAD.verify_ib_cvt(self.identities)


class IbCvtGenerationOrderTest(unittest.TestCase):
    def commands(self, device_types, deployment_scope="prod"):
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(LOAD, "ZTP_DIR", Path(directory)), \
                mock.patch.object(LOAD, "_device_types_after_dhcp", return_value=frozenset(device_types)), \
                mock.patch.object(LOAD, "run") as runner:
            LOAD.generate_configs(frozenset(device_types), install_dhcp=False, dry_run=True,
                                  eth_version="5.18.1", deployment_scope=deployment_scope,
                                  switch_scope="all")
            return [(call.args[0], call.kwargs.get("cwd")) for call in runner.call_args_list]

    def test_ib_devices_get_the_cvt_before_their_configs(self):
        calls = self.commands({"ib"})
        argv = [command for command, _cwd in calls]
        converter = argv.index([sys.executable, "p2p-to-validation.py"])   # no P2P identity: no binding
        generator = next(index for index, command in enumerate(argv) if "--branch" in command)
        self.assertLess(converter, generator, "like b-xlsx_to_dot.py before the Ethernet generator")
        self.assertEqual("config/nvos/template/P2P", "/".join(Path(calls[converter][1]).parts[-4:]))

    def test_no_cvt_without_ib_devices_or_in_air(self):
        for device_types, scope in (({"eth"}, "prod"), ({"nvl"}, "prod"), ({"ib"}, "air")):
            with self.subTest(device_types=device_types, scope=scope):
                argv = [command for command, _cwd in self.commands(device_types, scope)]
                self.assertNotIn([sys.executable, "p2p-to-validation.py"], argv)

    def test_a_real_load_binds_the_converter_to_the_p2p_it_validated(self):
        # The converter itself refuses another P2P (test_ib_cvt_project_output), as Ethernet's
        # b-xlsx_to_dot.py does its own work; the parent release check is verify_ib_cvt.
        commands = []

        def fake_run(command, **_kwargs):
            commands.append(list(command))
            if "--branch" in command:
                raise RuntimeError("stop after the ordering is known")

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(LOAD, "ZTP_DIR", Path(directory)), \
                mock.patch.object(LOAD, "_device_types_after_dhcp", return_value=frozenset({"ib"})), \
                mock.patch.object(LOAD, "run", side_effect=fake_run):
            with self.assertRaises(RuntimeError):
                LOAD.generate_configs(frozenset({"ib"}), install_dhcp=False, dry_run=False,
                                      deployment_scope="prod", switch_scope="ib",
                                      source_identities={"p2p": "a" * 64})
        self.assertEqual([sys.executable, "p2p-to-validation.py", "--expect-p2p-sha256", "a" * 64],
                         commands[-2])
        self.assertIn("--branch", commands[-1])


if __name__ == "__main__":
    unittest.main()
