"""I-034: the IB analyzer ships with the upload package and with sync, and runs from either tree.

Owner 2026-11-04 (问题文档 I-034): 「打包和 sync 都像 lldp-analyze-tool 一样放行ibdiagnet-analyze-tool的
代码。……我们需要保证被调用的脚本都要放行」; config/port_profiles.csv ships on its own until G14-1
(owner's plan B).  The issue's test line: on the tree an upload package unpacks to, the IB
post-collect finds the analyzer.

One workspace holds the git-tracked analyzers, the real infiniband/monitor/post-collect.py that
calls the IB one and the provenance module that analyzer imports.  The real upload builder
(tools/_package_common.py::create_package, what tools/tar-for-upload.py runs) packs it; the real
tools/sync-code.py::build_jobs plans the sync, replayed job by job with a local rsync.  On each
shipped tree the shipped post-collect.py analyses one UFM ibdiagnet archive with the shipped
analyzer: the report provenance must name that tree's config/port_profiles.csv, and without the
file the same run fails.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import xlsxwriter

from test_cases import test_upload_package_contract as upload_contract
from test_cases.test_ib_post_collect import ibdiagnet_archive
from test_cases.test_project_contracts import load_module


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = "tools/ibdiagnet-analyze-tool"
PORT_PROFILES = ANALYZER + "/config/port_profiles.csv"
RUN_ID = "20261107-0300-prod-0123456789abcdef"
# O9 (owner 2026-11-07 「同意你的建议。」): neither channel ships these git-tracked template links.
TEMPLATE_LINKS = {
    "ztp/config/nvos/template/P2P/ibdiagnet-analyze-tool": "../../../../../tools/ibdiagnet-analyze-tool",
    "ztp/config/cumulus/template/P2P/lldp-analyze-tool": "../../../../../tools/lldp-analyze-tool",
}


def tracked(*paths: str) -> list[str]:
    listed = subprocess.run(["git", "ls-files", "-z", "--", *paths], cwd=ROOT,
                            capture_output=True, check=True)
    return [item.decode("utf-8") for item in listed.stdout.split(b"\0") if item]


class IbAnalyzerShippingWorkflowTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ib-analyzer-shipping-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.workspace, self.day0, self.project = (
            upload_contract.UploadPackageContractTests._minimal_package_workspace(self.base))
        workspace = self.workspace
        sources = tracked("tools/ibdiagnet-analyze-tool", "tools/lldp-analyze-tool")
        sources += ["infiniband/monitor/post-collect.py", "ztp/config/ib_topology_provenance.py"]
        for relative in sources:
            target = workspace / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
            target.chmod((ROOT / relative).stat().st_mode & 0o777)
        # The analyzer's code plus the data file it reads by default (I-034); nothing else of it.
        self.expected = {relative[len(ANALYZER) + 1:] for relative in sources
                         if relative.startswith(ANALYZER + "/") and relative.endswith(".py")}
        self.expected.add("config/port_profiles.csv")
        # What stays local: setup's output link beside the analyzer and a data file not listed.
        (workspace / ANALYZER / "99-output-p2p").symlink_to("../../DAY0-Prepare/customer/99-output-p2p")
        (workspace / ANALYZER / "config/site-profiles.csv").write_text("model\n", encoding="utf-8")
        for link, target in TEMPLATE_LINKS.items():
            (workspace / link).parent.mkdir(parents=True, exist_ok=True)
            (workspace / link).symlink_to(target)
        # sync-code.py syncs every code directory, DAY0-Prepare/template and the root lock file.
        for name in ("monitor", "ethernet", "infiniband", "nvlink"):
            (workspace / name).mkdir(exist_ok=True)
        (self.day0 / "template").mkdir()
        (workspace / "requirements-container-top-level.lock").write_text("fixture\n", encoding="utf-8")
        self.output = self._planned_topology()

    def _planned_topology(self) -> Path:
        """The server project's 99-output-p2p with a CVT from the real P2P converter."""
        project = self.base / "server-project"
        output = project / "99-output-p2p"
        output.mkdir(parents=True)
        # P2P: leaf01 sw1p1 <-> server01 mlx5_0, the link of the ibdiagnet fixture
        book = xlsxwriter.Workbook(str(project / "fabric-blue.xlsx"))
        sheet = book.add_worksheet("CL links")
        for row, values in enumerate((("Name", "Port", "Name", "Port"),
                                      ("leaf01", "sw1p1", "server01", "mlx5_0"))):
            for column, value in enumerate(values):
                sheet.write(row, column, value)
        book.close()
        (project / "p2p.xlsx").symlink_to("fabric-blue.xlsx")
        setup = self.base / "converter"
        setup.mkdir()
        for name, text in (("01-inventory.log", "[IB-SW]\n*leaf*\n\n[server]\n*server*\n"),
                           ("02-port-mapping.log", ""), ("03-splitter.log", "")):
            (setup / name).write_text(text, encoding="utf-8")
        (setup / "p2p.xlsx").symlink_to(project / "p2p.xlsx")
        converted = subprocess.run(
            [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
             "--output", str(output / "fabric-blue-cvt.xlsx"),
             "--inventory", str(setup / "01-inventory.log"),
             "--port-map", str(setup / "02-port-mapping.log"),
             "--splitter", str(setup / "03-splitter.log")],
            cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "XLSX_TO_CSV_BASE_DIR": str(setup)},
            capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
        return output

    def _post_collect(self, tree: Path, node: str) -> subprocess.CompletedProcess:
        """Run the shipped post-collect as cron.sh does, on this run's exact archive."""
        monitor = tree / "infiniband/monitor"
        if not (monitor / "99-output-p2p").is_symlink():
            (monitor / "99-output-p2p").symlink_to(self.output)   # setup's link, never shipped
        archive = ibdiagnet_archive(self.base / "fetched" / f"{tree.name}-{node}",
                                    f"{RUN_ID}_{node}_ibdiagnet2.tgz")
        return subprocess.run(
            [sys.executable, "-B", str(monitor / "post-collect.py"), "--archive", str(archive)],
            cwd=tree, capture_output=True, text=True, timeout=300, check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    def _assert_shipped_analyzer_runs(self, tree: Path) -> None:
        analyzer = tree / ANALYZER
        shipped = {path.relative_to(analyzer).as_posix() for path in analyzer.rglob("*")
                   if path.is_file() or path.is_symlink()}
        self.assertEqual(self.expected, shipped)
        for link in TEMPLATE_LINKS:
            self.assertFalse(os.path.lexists(tree / link), link)

        completed = self._post_collect(tree, "ufm01")
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        report = self.output / f"{RUN_ID}_ufm01-ibdiagnet-topology-validation.xlsx"
        provenance = json.loads(report.with_name(report.name + ".provenance.json").read_text())
        catalog = tree / PORT_PROFILES
        self.assertEqual(str(catalog), provenance["profile"]["resolved_path"])
        self.assertEqual(hashlib.sha256((ROOT / PORT_PROFILES).read_bytes()).hexdigest(),
                         provenance["profile"]["sha256"])

        # The same run without the shipped catalog fails: the tree's own file was what it read.
        os.replace(catalog, self.base / "port_profiles.csv.aside")
        completed = self._post_collect(tree, "ufm02")
        self.assertEqual(2, completed.returncode, completed.stdout + completed.stderr)
        self.assertIn("port profile catalog not found", completed.stdout)

    def test_the_upload_package_tree_runs_the_ib_analyzer_with_its_port_profiles(self):
        package = upload_contract.package
        output = self.base / "upload.tar.gz"
        args = upload_contract.UploadPackageContractTests._r22_package_args(self.project, output)

        def isolated_manifest(path):
            # O10: the analyzer stays out of the deployment source manifest; not under test here.
            path.write_text('{"schema_version":1,"files":[]}\n', encoding="ascii")
            return path

        with mock.patch.multiple(package, ROOT=self.workspace, DAY0=self.day0,
                                 MANIFEST=self.workspace / "ztp/.setup_manifest",
                                 TOOLS_DIR=self.workspace / "tools"), \
                mock.patch.object(package, "write_deployment_source_manifest",
                                  side_effect=isolated_manifest):
            package.create_package(args, day0_all=False, artifact_kind="upload")
        tree = self.base / "upload-tree"
        tree.mkdir()
        with tarfile.open(output, "r:gz") as archive:
            archive.extractall(tree)
        self._assert_shipped_analyzer_runs(tree)

    def test_the_sync_tree_runs_the_ib_analyzer_with_its_port_profiles(self):
        sync = load_module("ib_analyzer_shipping_sync", ROOT / "tools/sync-code.py")
        with mock.patch.multiple(sync, ROOT=self.workspace, DAY0=self.day0), \
                mock.patch.multiple(sync.project_contract, ROOT=self.workspace, DAY0=self.day0,
                                    MANIFEST=self.workspace / "ztp/.setup_manifest"):
            jobs = sync.build_jobs(self.project, "/var/www/html")
        tree = self.base / "sync-tree"
        for job in jobs:
            destination = tree / job.remote_dir.removeprefix("/var/www/html").strip("/")
            destination.mkdir(parents=True, exist_ok=True)   # sync-code.py: mkdir -p, then rsync
            command = ["rsync", "-a"]
            for pattern in job.excludes:
                command += ["--exclude", pattern]
            command += [os.fspath(source) + ("/" if source.is_dir() else "") for source in job.sources]
            command.append(os.fspath(destination) + "/")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, f"{job.label}: {result.stderr}")
        self._assert_shipped_analyzer_runs(tree)


if __name__ == "__main__":
    unittest.main()
