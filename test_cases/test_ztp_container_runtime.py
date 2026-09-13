"""Contracts for the Ubuntu host-network ZTP service container.

The tests use hand-written interface and service fixtures.  They do not need a
Docker daemon and deliberately do not derive expected values from the runtime
implementation.
"""

from __future__ import annotations

import ast
import configparser
import copy
import fnmatch
import importlib.util
import hashlib
import io
import json
from contextlib import contextmanager, ExitStack, redirect_stderr, redirect_stdout
from functools import wraps
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DOCKER_ROOT = ROOT / "infra/docker"
EXPECTED_CONTROL_AUTH_HELPER_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)
EXPECTED_IMAGE_ENVIRONMENT = [
    "PATH=/opt/http-ztp/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE=1",
]
CONTAINER_TOPLEVEL_LOCK = "requirements-container-top-level.lock"
CONTAINER_TOPLEVEL_REQUIREMENTS = (
    ("Jinja2", "3.1.6", "jinja2"),
    ("PyYAML", "6.0.3", "yaml"),
    ("pandas", "2.3.3", "pandas"),
    ("openpyxl", "3.1.5", "openpyxl"),
    ("XlsxWriter", "3.2.9", "xlsxwriter"),
)
CONTAINER_APT_TRANSITIVE_PACKAGES = (
    "python3-dateutil",
    "python3-et-xmlfile",
    "python3-markupsafe",
    "python3-numpy",
    "python3-tz",
    "tzdata",
)
CONTAINER_TRANSITIVE_IMPORTS = (
    "dateutil",
    "et_xmlfile",
    "markupsafe",
    "numpy",
    "pytz",
)
PROJECT_BOOTSTRAP_LABELS = {
    "package-project-image.py": (
        "com.nvidia.http-ztp.project-bootstrap-package-sha256"
    ),
    "deploy-upload-archive.py": (
        "com.nvidia.http-ztp.project-bootstrap-upload-sha256"
    ),
    "deploy-shared-artifacts.py": (
        "com.nvidia.http-ztp.project-bootstrap-shared-sha256"
    ),
}
PROJECT_UPGRADE_POLICY_LABEL = "com.nvidia.http-ztp.upgrade-policy"
REQUIRED_ACTIVE_SOURCE_PATHS = (
    "infra/docker/activate.py",
    "infra/docker/entrypoint.py",
    "infra/docker/healthcheck.py",
    "infra/docker/hostctl.py",
    "infra/docker/supervisord.conf",
    "infra/docker/apache-ztp.conf",
    "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/logrotate-http-ztp.conf",
    "tools/ztp_service_runtime.py",
    "tools/control-auth.py",
    "tools/deployment_lock.py",
    "tools/project_contract.py",
    "DAY0-Prepare/12-ztp-monitor.py",
    "monitor/switch-collection-worker.py",
    "monitor/manual-ztp-worker.py",
    "monitor/switch_collection_gate.py",
    "monitor/generate-monitor-html.py",
    "monitor/dot_to_html.py",
    "monitor/ztp-monitor-control.cgi",
    "monitor/switch-collection-control.cgi",
    "monitor/manual-ztp-control.cgi",
    "ztp/dynamic_air_inventory.py",
    "ztp/dhcp_runtime_inventory.py",
    "ztp/environment_probe.py",
    "ztp/manual-ztp.py",
    "ztp/manual-reset.py",
    "ztp/nvue_normalizer.py",
    "ethernet/monitor/cron.sh",
    "ethernet/monitor/sw-info.sh",
    "ethernet/monitor/sw-link.sh",
    "ethernet/monitor/post-collect.py",
    "tools/lldp-analyze-tool/analyze_lldp.py",
    "tools/lldp-analyze-tool/build_report.py",
    "infiniband/monitor/cron.sh",
    "infiniband/monitor/sw-info.sh",
    "infiniband/monitor/sw-link.sh",
    "nvlink/monitor/cron.sh",
    "nvlink/monitor/sw-info.sh",
    "nvlink/monitor/sw-link.sh",
)
REQUIRED_LIFECYCLE_SOURCE_PATHS = (
    "infra/docker/hostlock.py",
    "tools/deployment_prewrite_guard.py",
    "DAY0-Prepare/01-a-setup.py",
    "DAY0-Prepare/02-unsetup.py",
    "DAY0-Prepare/11-load.py",
    "DAY0-Prepare/13-unload.py",
    "ztp/optimize/sample_links.py",
    "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
    "ztp/config/cumulus/d-hostname2mac.py",
    "ztp/config/cumulus/template/90-c2-generate_configs.py",
    "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
    "ztp/config/cumulus/template/P2P/01-inventory.log",
    "ztp/config/cumulus/template/P2P/02-port-mapping.log",
    "ztp/config/cumulus/template/P2P/lldpq-template.dot",
    "ztp/config/cumulus/template/P2P/air-template-no-oob.json",
    "ztp/config/cumulus/template/03-templates-j2/_global_evpn.yaml.j2",
    "ztp/templates/ztp-bootstrap.sh",
    "ztp/templates/ztp.json",
)
IMAGE_COUPLED_SOURCE_PATHS_EXPECTED = (
    "requirements-container-top-level.lock",
    "infra/docker/activate.py",
    "infra/docker/entrypoint.py",
    "infra/docker/healthcheck.py",
    "infra/docker/hostctl.py",
    "infra/docker/hostlock.py",
    "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/supervisord.conf",
    "infra/docker/apache-ztp.conf",
    "infra/docker/logrotate-http-ztp.conf",
    "tools/ztp_service_runtime.py",
    "tools/control-auth.py",
)
REQUIRED_PUBLISHED_LINKS = {
    "monitor/01-global.yaml": (
        "../DAY0-Prepare/{project}/01-global.yaml", "01-global.yaml", "file",
    ),
    "monitor/02-devices_config.csv": (
        "../DAY0-Prepare/{project}/02-devices_config.csv",
        "02-devices_config.csv", "file",
    ),
    "monitor/99-output-p2p": (
        "../DAY0-Prepare/{project}/99-output-p2p", "99-output-p2p", "dir",
    ),
    "monitor/ethernet": (
        "../DAY0-Prepare/{project}/99-output-monitor/ethernet",
        "99-output-monitor/ethernet", "dir",
    ),
    "monitor/infiniband": (
        "../DAY0-Prepare/{project}/99-output-monitor/infiniband",
        "99-output-monitor/infiniband", "dir",
    ),
    "monitor/nvlink": (
        "../DAY0-Prepare/{project}/99-output-monitor/nvlink",
        "99-output-monitor/nvlink", "dir",
    ),
    "monitor/ztp-status": ("../ztp/status", "99-output-ztp", "dir"),
    "ztp/status": (
        "../DAY0-Prepare/{project}/99-output-ztp", "99-output-ztp", "dir",
    ),
    "ethernet/eth.csv": (
        "../DAY0-Prepare/{project}/02-devices_config.csv",
        "02-devices_config.csv", "file",
    ),
    "ethernet/monitor/eth.csv": (
        "../eth.csv", "02-devices_config.csv", "file",
    ),
    "infiniband/ib.csv": (
        "../DAY0-Prepare/{project}/02-devices_config.csv",
        "02-devices_config.csv", "file",
    ),
    "infiniband/monitor/ib.csv": (
        "../ib.csv", "02-devices_config.csv", "file",
    ),
    "nvlink/nvsw.csv": (
        "../DAY0-Prepare/{project}/02-devices_config.csv",
        "02-devices_config.csv", "file",
    ),
    "nvlink/monitor/nvsw.csv": (
        "../nvsw.csv", "02-devices_config.csv", "file",
    ),
    "ethernet/monitor/eth-info": (
        "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/eth-info",
        "99-output-monitor/ethernet/eth-info", "dir",
    ),
    "ethernet/monitor/spx-link": (
        "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/spx-link",
        "99-output-monitor/ethernet/spx-link", "dir",
    ),
    "ethernet/monitor/cronjob.log": (
        "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/cronjob.log",
        "99-output-monitor/ethernet/cronjob.log", "file",
    ),
    "infiniband/monitor/ib-info": (
        "../../DAY0-Prepare/{project}/99-output-monitor/infiniband/ib-info",
        "99-output-monitor/infiniband/ib-info", "dir",
    ),
    "infiniband/monitor/ib-link": (
        "../../DAY0-Prepare/{project}/99-output-monitor/infiniband/ib-link",
        "99-output-monitor/infiniband/ib-link", "dir",
    ),
    "infiniband/monitor/cronjob.log": (
        "../../DAY0-Prepare/{project}/99-output-monitor/infiniband/cronjob.log",
        "99-output-monitor/infiniband/cronjob.log", "file",
    ),
    "nvlink/monitor/nvsw-info": (
        "../../DAY0-Prepare/{project}/99-output-monitor/nvlink/nvsw-info",
        "99-output-monitor/nvlink/nvsw-info", "dir",
    ),
    "nvlink/monitor/nvsw-link": (
        "../../DAY0-Prepare/{project}/99-output-monitor/nvlink/nvsw-link",
        "99-output-monitor/nvlink/nvsw-link", "dir",
    ),
    "nvlink/monitor/cronjob.log": (
        "../../DAY0-Prepare/{project}/99-output-monitor/nvlink/cronjob.log",
        "99-output-monitor/nvlink/cronjob.log", "file",
    ),
    "tools/lldp-analyze-tool/99-output-p2p": (
        "../../DAY0-Prepare/{project}/99-output-p2p",
        "99-output-p2p", "dir",
    ),
    "tools/lldp-analyze-tool/99-output-monitor": (
        "../../DAY0-Prepare/{project}/99-output-monitor",
        "99-output-monitor", "dir",
    ),
}

REQUIRED_DYNAMIC_P2P_LINKS = {
    "ztp/config/cumulus/template/P2P/p2p.xlsx": (
        "../../../../../DAY0-Prepare/{project}/p2p.xlsx",
        "p2p.xlsx",
    ),
    "ztp/config/isc-dhcp-server/p2p-air.json": (
        "../../../DAY0-Prepare/{project}/99-output-p2p/fixture-p2p-air.json",
        "99-output-p2p/fixture-p2p-air.json",
    ),
}


def load_script(name: str):
    path = DOCKER_ROOT / name
    if not path.is_file():
        raise AssertionError(f"missing production container script: {path}")
    spec = importlib.util.spec_from_file_location(
        "container_" + name.replace(".", "_"), path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def with_valid_monitor_authority_fixture(test_method):
    """Give one legacy lifecycle test an explicit method-local valid gate."""
    @wraps(test_method)
    def wrapped(*args, **kwargs):
        patches = []
        real_loader = load_script

        def load_with_gate(name: str):
            module = real_loader(name)
            target = module if name == "activate.py" else getattr(module, "activate", None)
            if target is not None and hasattr(target, "require_monitor_authority"):
                patcher = mock.patch.object(
                    target, "require_monitor_authority", return_value=None,
                )
                patcher.start()
                patches.append(patcher)
            return module

        try:
            with mock.patch(
                f"{__name__}.load_script", side_effect=load_with_gate,
            ):
                return test_method(*args, **kwargs)
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    return wrapped


def plan(*, names=("eno2",), indexes=(7,), endpoints=("192.0.2.10",)):
    return SimpleNamespace(
        listener_names=tuple(names),
        listener_ifindexes=tuple(indexes),
        direct_shared_networks=("direct",) if names else (),
        relay_shared_networks=(),
        endpoint_ips=tuple(endpoints),
    )


class QuietContractTest(unittest.TestCase):
    """Keep deliberately injected production failures out of user test output."""

    def setUp(self) -> None:
        super().setUp()
        self.contract_output = io.StringIO()
        self._quiet_stack = ExitStack()
        self._quiet_stack.enter_context(redirect_stdout(self.contract_output))
        self._quiet_stack.enter_context(redirect_stderr(self.contract_output))

    def tearDown(self) -> None:
        self._quiet_stack.close()
        super().tearDown()


class ContainerArtifactContractTests(QuietContractTest):
    @staticmethod
    def _run_deploy_function_harness(body: str) -> subprocess.CompletedProcess[str]:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        definitions = source.split("\naction=${1:-}", 1)[0]
        return subprocess.run(
            ["/bin/bash"], input=definitions + "\n" + body,
            cwd=ROOT, text=True, capture_output=True, check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_legacy_and_buildkit_use_one_strict_repository_context_contract(self) -> None:
        legacy = ROOT / ".dockerignore"
        buildkit = DOCKER_ROOT / "Dockerfile.dockerignore"
        self.assertTrue(legacy.is_file(), "legacy Docker builder ignore is missing")
        self.assertEqual(buildkit.read_bytes(), legacy.read_bytes())

        lines = legacy.read_text(encoding="utf-8").splitlines()
        effective = [line for line in lines if line and not line.startswith("#")]
        self.assertEqual("**", effective[0])
        for source_root in (
            "infra", "monitor", "ethernet", "infiniband", "nvlink", "ztp",
            "tools",
        ):
            with self.subTest(source_root=source_root):
                self.assertIn(f"!{source_root}/", effective)
                self.assertIn(f"!{source_root}/**", effective)
        self.assertIn("!DAY0-Prepare/template/", effective)
        self.assertIn("!DAY0-Prepare/template/**", effective)
        self.assertNotIn("!DAY0-Prepare/**", effective)
        self.assertNotIn("!apps/**", effective)
        self.assertNotIn("!firmware/**", effective)

        # Re-exclusions after broad source-root includes are what keep a field
        # workspace (images, outputs and credentials) out of both contexts.
        for exclusion, broad_include in (
            ("infra/logs/**", "!infra/**"),
            ("monitor/status/**", "!monitor/**"),
            ("ztp/image/**", "!ztp/**"),
            ("ztp/backup/**", "!ztp/**"),
            ("ztp/config/publickey/**", "!ztp/**"),
            ("tools/ib-tool-Jie/**", "!tools/**"),
            ("tools/ibdiagnet-analyze-tool/**", "!tools/**"),
        ):
            with self.subTest(exclusion=exclusion):
                self.assertIn(exclusion, effective)
                self.assertGreater(
                    effective.index(exclusion), effective.index(broad_include),
                )

    def test_auth_state_names_are_excluded_from_both_real_build_contexts(
        self,
    ) -> None:
        helper_source = (ROOT / "tools/control-auth.py").read_text(
            encoding="utf-8",
        )
        constants = {}
        for node in ast.parse(helper_source).body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in {
                "_CANDIDATE_PREFIX", "_RECOVERY_PREFIX",
            }:
                constants[target.id] = ast.literal_eval(node.value)
        self.assertEqual(
            {"_CANDIDATE_PREFIX", "_RECOVERY_PREFIX"}, set(constants),
        )

        ignore_paths = (
            ROOT / ".dockerignore",
            DOCKER_ROOT / "Dockerfile.dockerignore",
        )
        self.assertEqual(ignore_paths[0].read_bytes(), ignore_paths[1].read_bytes())

        def included(relative: str, rules: list[str]) -> bool:
            selected = True
            for raw_rule in rules:
                rule = raw_rule.strip()
                if not rule or rule.startswith("#"):
                    continue
                negate = rule.startswith("!")
                pattern = rule[1:] if negate else rule
                if fnmatch.fnmatchcase(relative, pattern):
                    selected = negate
            return selected

        with tempfile.TemporaryDirectory() as temporary:
            context = Path(temporary)
            inventory = {
                "tools/control-auth.py": helper_source,
                "tools/" + constants["_CANDIDATE_PREFIX"] + "012345": "candidate",
                (
                    "DAY0-Prepare/template/private/"
                    + constants["_RECOVERY_PREFIX"] + "abcdef"
                ): "recovery",
                "infra/docker/control-users.htpasswd": "canonical",
                "monitor/control-users.htpasswd.operator-copy": "copy",
                "infra/.SSH/id_ed25519": "docker-management-private-sentinel",
            }
            for relative, content in inventory.items():
                target = context / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            observed = sorted(
                path.relative_to(context).as_posix()
                for path in context.rglob("*") if path.is_file()
            )
            self.assertEqual(sorted(inventory), observed)

            for ignore_path in ignore_paths:
                rules = ignore_path.read_text(encoding="utf-8").splitlines()
                with self.subTest(ignore=ignore_path.name):
                    self.assertIn("**/.control-users.*", rules)
                    self.assertIn("**/*.htpasswd*", rules)
                    self.assertIn("**/.[Ss][Ss][Hh]/**", rules)
                    self.assertTrue(included("tools/control-auth.py", rules))
                    for relative in observed:
                        if relative != "tools/control-auth.py":
                            self.assertFalse(included(relative, rules), relative)

    def test_dockerfile_is_ubuntu_2404_and_installs_foreground_runtime(self) -> None:
        source = (DOCKER_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^FROM ubuntu:24\.04$")
        self.assertIn(
            "ENV PATH=/opt/http-ztp/venv/bin:/usr/local/sbin:/usr/local/bin:"
            "/usr/sbin:/usr/bin:/sbin:/bin \\\n"
            "    PYTHONDONTWRITEBYTECODE=1",
            source,
        )
        self.assertNotRegex(source, r"(?m)^ENV TMPDIR=")
        for package in (
            "apache2", "isc-dhcp-server", "supervisor", "rsyslog",
            "logrotate",
            "iproute2", "python3", "python3-venv",
            "openssh-client", "sshpass", "rsync", "curl", "whois",
            *CONTAINER_APT_TRANSITIVE_PACKAGES,
        ):
            with self.subTest(package=package):
                self.assertIn(package, source)
        apt_block = source.split("apt-get install -y --no-install-recommends", 1)[1].split(
            "&& command -v ip", 1,
        )[0]
        for forbidden in (
            "python3-jinja2", "python3-yaml", "python3-pandas",
            "python3-openpyxl", "python3-xlsxwriter",
        ):
            with self.subTest(apt_top_level=forbidden):
                self.assertNotRegex(apt_block, rf"(?m)^\s*{re.escape(forbidden)}\s*\\?$",)
        self.assertIn(
            "python3 -m venv --system-site-packages /opt/http-ztp/venv",
            source,
        )
        install_match = re.search(
            r"/opt/http-ztp/venv/bin/python -m pip install\s+"
            r"(?:--[^\s]+\s+)*--no-deps\s+(?:--[^\s]+\s+)*"
            r"--require-hashes\s+(?:--[^\s]+\s+)*-r\s+"
            r"/opt/http-ztp/source-tree/requirements-container-top-level\.lock",
            source,
        )
        self.assertIsNotNone(install_match)
        build_probe = (
            "/opt/http-ztp/venv/bin/python "
            "/opt/http-ztp/source-tree/infra/docker/activate.py "
            "verify-python-runtime"
        )
        self.assertIn(build_probe, source)
        self.assertLess(install_match.end(), source.index(build_probe))
        for command in ("ip", "ssh", "ss", "mkpasswd"):
            with self.subTest(required_command=command):
                self.assertIn(f"command -v {command}", source)
        self.assertIn("HEALTHCHECK", source)
        self.assertIn("image-source.sha256", source)
        self.assertIn("deployment-source-manifest.json", source)
        self.assertIn("verify-source-manifest", source)
        self.assertNotIn("build-source-manifest", source)
        self.assertIn("infra/docker/hostlock.py", source)
        for label in (
            'com.nvidia.http-ztp.image="true"',
            'com.nvidia.http-ztp.image-contract="3"',
            'com.nvidia.http-ztp.base-os="ubuntu-24.04"',
        ):
            self.assertIn(label, source)
        runtime_contract = json.loads(
            (DOCKER_ROOT / "runtime-contract.json").read_text(encoding="ascii")
        )
        self.assertEqual(1, runtime_contract["schema_version"])
        self.assertEqual(["3"], runtime_contract["compatible_image_contracts"])
        self.assertNotIn("systemd", source.casefold())
        compose = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertRegex(compose, r"(?m)^\s*context:\s*\.\./\.\.$")
        self.assertIn("infra/docker/Dockerfile", compose)
        ignore = set(
            (DOCKER_ROOT / "Dockerfile.dockerignore").read_text(
                encoding="utf-8",
            ).splitlines()
        )
        for relative in REQUIRED_ACTIVE_SOURCE_PATHS + REQUIRED_LIFECYCLE_SOURCE_PATHS:
            with self.subTest(build_context_source=relative):
                self.assertTrue(
                    any(
                        entry == "!" + relative
                        or (
                            entry.endswith("/**")
                            and relative.startswith(entry[1:-3] + "/")
                        )
                        or (
                            entry.startswith("!")
                            and Path(relative).match(entry[1:])
                        )
                        for entry in ignore
                    ),
                    relative,
                )

    def test_toplevel_lock_is_in_build_context_and_image_source_receipt(self) -> None:
        lock_path = ROOT / CONTAINER_TOPLEVEL_LOCK
        self.assertTrue(lock_path.is_file())
        for ignore_path in (
            ROOT / ".dockerignore",
            DOCKER_ROOT / "Dockerfile.dockerignore",
        ):
            rules = ignore_path.read_text(encoding="utf-8").splitlines()
            with self.subTest(ignore=ignore_path):
                self.assertIn("!" + CONTAINER_TOPLEVEL_LOCK, rules)
                self.assertGreater(
                    rules.index("!" + CONTAINER_TOPLEVEL_LOCK),
                    rules.index("**/*.lock"),
                )

        activate = load_script("activate.py")
        selected = set(activate.image_source_paths(ROOT))
        self.assertIn(CONTAINER_TOPLEVEL_LOCK, selected)
        self.assertIn(CONTAINER_TOPLEVEL_LOCK, activate.IMAGE_COUPLED_SOURCE_PATHS)
        with tempfile.TemporaryDirectory() as temporary:
            source_root = Path(temporary)
            for relative in selected:
                source = ROOT / relative
                destination = source_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_symlink():
                    destination.symlink_to(os.readlink(source))
                else:
                    shutil.copy2(source, destination)
            receipt = source_root / "image-source.sha256"
            activate.write_image_source_manifest(source_root, receipt)
            payload = json.loads(receipt.read_text(encoding="utf-8"))
            records = {item["path"]: item for item in payload["files"]}
            self.assertEqual(
                hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                records[CONTAINER_TOPLEVEL_LOCK]["sha256"],
            )

    def test_toplevel_lock_receipt_rejects_unsafe_or_unbounded_objects(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            outside = base / "outside"
            outside.write_bytes(b"outside sentinel\n")
            sentinel = outside.read_bytes()
            for kind in ("symlink", "hardlink", "empty", "oversize"):
                with self.subTest(kind=kind):
                    source_root = base / kind
                    source_root.mkdir()
                    lock = source_root / CONTAINER_TOPLEVEL_LOCK
                    if kind == "symlink":
                        payload = source_root / "lock-payload"
                        payload.write_bytes(sentinel)
                        lock.symlink_to(payload.name)
                    elif kind == "hardlink":
                        os.link(outside, lock)
                    elif kind == "empty":
                        lock.write_bytes(b"")
                    else:
                        lock.write_bytes(b"x" * (64 * 1024 + 1))
                    with self.assertRaisesRegex(
                        activate.ActivationError,
                        "top-level.*lock|lock.*unsafe|unsafe.*lock|"
                        "lock.*empty|lock.*large",
                    ):
                        activate._source_record(
                            source_root, CONTAINER_TOPLEVEL_LOCK,
                        )
                    self.assertEqual(sentinel, outside.read_bytes())

    def test_import_origin_requires_canonical_existing_regular_path(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            venv = base / "venv"
            package = venv / "site-packages/good"
            package.mkdir(parents=True)
            origin = package / "__init__.py"
            origin.write_text("VALUE = 1\n", encoding="utf-8")
            self.assertTrue(activate._origin_within(os.fspath(origin), venv))

            attacker = base / "attacker"
            attacker.mkdir()
            escaped = attacker / "__init__.py"
            escaped.write_text("VALUE = 2\n", encoding="utf-8")
            traversal = venv / ".." / "attacker" / "__init__.py"
            self.assertFalse(
                activate._origin_within(os.fspath(traversal), venv),
                "lexical '..' must not satisfy the venv import-origin boundary",
            )

            linked = venv / "site-packages/linked"
            linked.symlink_to(attacker, target_is_directory=True)
            self.assertFalse(
                activate._origin_within(
                    os.fspath(linked / "__init__.py"), venv,
                ),
                "an in-venv symlink must not make an outside import trusted",
            )
            directory_origin = venv / "site-packages/directory-origin"
            directory_origin.mkdir()
            self.assertFalse(
                activate._origin_within(os.fspath(directory_origin), venv),
            )

    def test_runtime_rechecks_exact_toplevel_versions_and_venv_import_origins(self) -> None:
        activate = load_script("activate.py")
        expected_versions = {
            name: version for name, version, _module in CONTAINER_TOPLEVEL_REQUIREMENTS
        }
        expected_modules = {
            module for _name, _version, module in CONTAINER_TOPLEVEL_REQUIREMENTS
        }
        self.assertEqual(
            expected_versions,
            activate.CONTAINER_TOPLEVEL_REQUIREMENTS,
        )
        self.assertEqual(
            {
                name: module
                for name, _version, module in CONTAINER_TOPLEVEL_REQUIREMENTS
            },
            activate.CONTAINER_TOPLEVEL_IMPORTS,
        )
        self.assertEqual(
            CONTAINER_TRANSITIVE_IMPORTS,
            activate.CONTAINER_TRANSITIVE_IMPORTS,
        )

        def version_of(name):
            return expected_versions[name]

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        runtime_root = Path(temporary.name)
        venv_root = runtime_root / "venv"
        system_root = runtime_root / "system-site"
        venv_python = venv_root / "bin/python"
        venv_python.parent.mkdir(parents=True)
        venv_python.write_bytes(b"python fixture\n")
        module_origins = {}
        for module in expected_modules:
            origin = venv_root / "site-packages" / module / "__init__.py"
            origin.parent.mkdir(parents=True)
            origin.write_text("VALUE = 1\n", encoding="utf-8")
            module_origins[module] = origin
        for module in CONTAINER_TRANSITIVE_IMPORTS:
            origin = system_root / module / "__init__.py"
            origin.parent.mkdir(parents=True)
            origin.write_text("VALUE = 1\n", encoding="utf-8")
            module_origins[module] = origin

        def find_spec(module):
            return SimpleNamespace(origin=os.fspath(module_origins[module]))

        with (
            mock.patch.object(activate, "CONTAINER_VENV", venv_root),
            mock.patch.object(activate, "CONTAINER_SYSTEM_SITE", system_root),
            mock.patch.object(activate, "CONTAINER_VENV_PYTHON", venv_python),
            mock.patch.object(activate.sys, "executable", os.fspath(venv_python)),
            mock.patch("importlib.metadata.version", side_effect=version_of) as version,
            mock.patch("importlib.util.find_spec", side_effect=find_spec) as spec,
            mock.patch("importlib.import_module", return_value=SimpleNamespace()) as imported,
        ):
            activate.validate_python_runtime()
        self.assertEqual(
            [mock.call(name) for name, _version, _module in CONTAINER_TOPLEVEL_REQUIREMENTS],
            version.call_args_list,
        )
        self.assertEqual(
            [
                *(
                    mock.call(module)
                    for _name, _version, module in CONTAINER_TOPLEVEL_REQUIREMENTS
                ),
                *(mock.call(module) for module in CONTAINER_TRANSITIVE_IMPORTS),
            ],
            spec.call_args_list,
        )
        self.assertEqual(spec.call_args_list, imported.call_args_list)

        with (
            mock.patch.object(activate, "CONTAINER_VENV", venv_root),
            mock.patch.object(activate, "CONTAINER_SYSTEM_SITE", system_root),
            mock.patch.object(activate, "CONTAINER_VENV_PYTHON", venv_python),
            mock.patch.object(activate.sys, "executable", os.fspath(venv_python)),
            mock.patch(
                "importlib.metadata.version",
                side_effect=lambda name: "0.0" if name == "pandas" else expected_versions[name],
            ),
            mock.patch("importlib.util.find_spec", side_effect=find_spec),
            mock.patch("importlib.import_module", return_value=SimpleNamespace()),
            self.assertRaisesRegex(activate.ActivationError, "pandas.*2[.]3[.]3"),
        ):
            activate.validate_python_runtime()

        with (
            mock.patch.object(activate, "CONTAINER_VENV", venv_root),
            mock.patch.object(activate, "CONTAINER_SYSTEM_SITE", system_root),
            mock.patch.object(activate, "CONTAINER_VENV_PYTHON", venv_python),
            mock.patch.object(activate.sys, "executable", os.fspath(venv_python)),
            mock.patch("importlib.metadata.version", side_effect=version_of),
            mock.patch("importlib.util.find_spec", side_effect=find_spec),
            mock.patch(
                "importlib.import_module",
                side_effect=lambda module: (
                    (_ for _ in ()).throw(ModuleNotFoundError(module))
                    if module == "numpy"
                    else SimpleNamespace()
                ),
            ),
            self.assertRaisesRegex(activate.ActivationError, "numpy|transitive|import"),
        ):
            activate.validate_python_runtime()

        with (
            mock.patch.object(activate, "CONTAINER_VENV", venv_root),
            mock.patch.object(activate, "CONTAINER_SYSTEM_SITE", system_root),
            mock.patch.object(activate, "CONTAINER_VENV_PYTHON", venv_python),
            mock.patch.object(activate.sys, "executable", os.fspath(venv_python)),
            mock.patch("importlib.metadata.version", side_effect=version_of),
            mock.patch(
                "importlib.util.find_spec",
                side_effect=lambda module: SimpleNamespace(
                    origin=os.fspath(module_origins["numpy"]),
                ),
            ),
            mock.patch("importlib.import_module", return_value=SimpleNamespace()),
            self.assertRaisesRegex(activate.ActivationError, "venv|import path"),
        ):
            activate.validate_python_runtime()

    def test_entrypoint_and_health_recheck_toplevel_venv_before_runtime(self) -> None:
        entrypoint = (DOCKER_ROOT / "entrypoint.py").read_text(encoding="utf-8")
        entry_main = entrypoint.split("def main(", 1)[1]
        self.assertIn("activate.validate_python_runtime()", entry_main)
        self.assertLess(
            entry_main.index("activate.validate_python_runtime()"),
            entry_main.index("activate.validate_image_source_contract"),
        )
        self.assertLess(
            entry_main.index("activate.validate_python_runtime()"),
            entry_main.index("os.execv"),
        )

        health = (DOCKER_ROOT / "healthcheck.py").read_text(encoding="utf-8")
        health_check = health.split("def check_runtime(", 1)[1].split("\ndef main(", 1)[0]
        self.assertIn("activate.validate_python_runtime()", health_check)
        self.assertLess(
            health_check.index("activate.validate_python_runtime()"),
            health_check.index("activate.validate_image_source_contract"),
        )

    def test_contract3_image_couples_control_auth_and_mounts_only_its_directory_read_only(
        self,
    ) -> None:
        dockerfile = (DOCKER_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("apache2-utils", dockerfile)
        self.assertIn("command -v htpasswd", dockerfile)
        self.assertRegex(
            dockerfile,
            r"getent\s+group\s+www-data.*(?:cut|awk).*33|www-data.*gid.*33",
        )
        self.assertIn(
            "/opt/http-ztp/source-tree/tools/control-auth.py",
            dockerfile,
        )
        self.assertIn("/opt/http-ztp/control-auth.py", dockerfile)
        for module in (
            "auth_basic", "authn_file", "authn_core", "authz_user",
            "authz_core", "env", "alias", "cgid", "headers",
        ):
            with self.subTest(apache_module=module):
                self.assertRegex(dockerfile, rf"a2enmod[^\n]*\b{module}\b")

        compose = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("/var/lib/http-ztp-container/control-auth", compose)
        self.assertIn("/etc/http-ztp", compose)
        auth_section = compose.split(
            "/var/lib/http-ztp-container/control-auth", 1,
        )[1].split("tmpfs:", 1)[0]
        self.assertRegex(auth_section, r"(?:read_only:\s*true|:ro(?:\s|$))")

        activate = load_script("activate.py")
        self.assertEqual("3", activate.IMAGE_RUNTIME_CONTRACT)
        self.assertIn("tools/control-auth.py", activate.IMAGE_COUPLED_SOURCE_PATHS)
        contract = json.loads(
            (DOCKER_ROOT / "runtime-contract.json").read_text(encoding="ascii")
        )
        self.assertEqual(["3"], contract["compatible_image_contracts"])

        plain = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8").split(
            "plain_docker_run() {", 1,
        )[1].split("\n}", 1)[0]
        auth_mount = (
            "type=bind,src=/var/lib/http-ztp-container/control-auth,"
            "dst=/etc/http-ztp,readonly"
        )
        self.assertIn(auth_mount, plain)
        self.assertNotIn(
            "src=/var/lib/http-ztp-container/control-auth/control-users.htpasswd",
            plain,
        )

    def test_monitor_authority_has_one_exact_persistent_rw_bind_in_both_launchers(
        self,
    ) -> None:
        host = "/var/lib/http-ztp-container/monitor-auth"
        runtime = "/var/lib/http-ztp-monitor-auth"
        compose = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertEqual(1, compose.count(f"source: {host}"))
        self.assertEqual(1, compose.count(f"target: {runtime}"))
        section = compose.split(f"source: {host}", 1)[1].split("tmpfs:", 1)[0]
        self.assertRegex(section, r"read_only:\s*false")

        plain = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8").split(
            "plain_docker_run() {", 1,
        )[1].split("\n}", 1)[0]
        mount = f"type=bind,src={host},dst={runtime}"
        self.assertEqual(1, plain.count(mount))
        self.assertNotIn(mount + ",readonly", plain)

        hostlock = load_script("hostlock.py")
        self.assertEqual(Path(host), hostlock.MONITOR_AUTHORITY_HOST_ROOT)
        self.assertEqual(Path(runtime), hostlock.MONITOR_AUTHORITY_CONTAINER_ROOT)

    def test_contract3_installs_and_attests_three_exact_helper_copies(self) -> None:
        dockerfile = (DOCKER_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "install -d -o root -g root -m 0755 /usr/local/lib/http-ztp",
            dockerfile,
        )
        self.assertIn(
            "/usr/local/lib/http-ztp/control-auth.py", dockerfile,
        )
        self.assertIn("verify-control-auth-image", dockerfile)
        self.assertLess(
            dockerfile.index("/usr/local/lib/http-ztp/control-auth.py"),
            dockerfile.index("verify-control-auth-image"),
        )
        self.assertRegex(
            dockerfile,
            r"install -d -m 0700 /opt/http-ztp(?:\s|/)",
        )

        activate = load_script("activate.py")
        self.assertEqual(
            EXPECTED_CONTROL_AUTH_HELPER_SHA256,
            activate.CONTROL_AUTH_HELPER_SHA256,
        )
        fixture = b"#!/usr/bin/python3\nprint('independent fixture')\n"
        fixture_sha256 = hashlib.sha256(fixture).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            image_root = base / "opt/http-ztp"
            source_root = image_root / "source-tree"
            source_tools = source_root / "tools"
            common_usr = base / "usr"
            common_local = common_usr / "local"
            common_lib = common_local / "lib"
            common_parent = common_lib / "http-ztp"
            for directory, mode in (
                (image_root, 0o700),
                (source_root, 0o755),
                (source_tools, 0o755),
                (common_usr, 0o755),
                (common_local, 0o755),
                (common_lib, 0o755),
                (common_parent, 0o755),
            ):
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(mode)
            source_helper = source_tools / "control-auth.py"
            lifecycle_helper = image_root / "control-auth.py"
            common_helper = common_parent / "control-auth.py"
            for helper in (source_helper, lifecycle_helper, common_helper):
                helper.write_bytes(fixture)
                helper.chmod(0o755)
            manifest = base / "image-source.sha256"
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/control-auth.py",
                    "type": "file",
                    "target": None,
                    "sha256": fixture_sha256,
                }],
            }) + "\n", encoding="ascii")
            directories = (
                (image_root, 0o700),
                (source_root, 0o755),
                (source_tools, 0o755),
                (common_usr, 0o755),
                (common_local, 0o755),
                (common_lib, 0o755),
                (common_parent, 0o755),
            )

            def verify(**overrides):
                arguments = {
                    "source_helper": source_helper,
                    "lifecycle_helper": lifecycle_helper,
                    "status_helper": common_helper,
                    "directory_contracts": directories,
                    "manifest": manifest,
                    "expected_sha256": fixture_sha256,
                    "required_uid": os.getuid(),
                    "required_gid": os.getgid(),
                }
                arguments.update(overrides)
                return activate.verify_control_auth_image_copies(**arguments)

            verified = verify()
            self.assertEqual({"verified": True, "copies": 3}, verified)

            for mutation, expected_error in (
                ("missing-status", "regular|unavailable"),
                ("writable-status", "mode|writable"),
                ("mismatched-status", "digest|byte"),
                ("symlink-status", "regular|alias|symlink"),
                ("hardlink-status", "link count|regular"),
            ):
                with self.subTest(mutation=mutation):
                    if common_helper.is_symlink() or common_helper.exists():
                        common_helper.unlink()
                    if mutation == "missing-status":
                        pass
                    elif mutation == "writable-status":
                        common_helper.write_bytes(fixture)
                        common_helper.chmod(0o775)
                    elif mutation == "mismatched-status":
                        common_helper.write_bytes(fixture + b"changed\n")
                        common_helper.chmod(0o755)
                    elif mutation == "symlink-status":
                        common_helper.symlink_to(lifecycle_helper)
                    else:
                        os.link(lifecycle_helper, common_helper)
                    with self.assertRaisesRegex(
                        activate.ActivationError, expected_error,
                    ):
                        verify()

            if common_helper.is_symlink() or common_helper.exists():
                common_helper.unlink()
            common_helper.write_bytes(fixture)
            common_helper.chmod(0o755)
            common_parent.chmod(0o775)
            with self.assertRaisesRegex(
                activate.ActivationError, "directory.*mode",
            ):
                verify()
            common_parent.chmod(0o755)
            with self.assertRaisesRegex(
                activate.ActivationError, "owner",
            ):
                verify(required_uid=os.getuid() + 1)

    def test_installed_helper_attestation_precedes_every_apache_start_path(self) -> None:
        entrypoint = (DOCKER_ROOT / "entrypoint.py").read_text(encoding="utf-8")
        entry_main = entrypoint.split("def main(", 1)[1]
        self.assertLess(
            entry_main.index("verify_control_auth_image_copies"),
            entry_main.index("require_control_auth"),
        )
        self.assertLess(
            entry_main.index("require_monitor_authority"),
            entry_main.index("/usr/bin/supervisord"),
        )
        self.assertLess(
            entry_main.index("verify_control_auth_image_copies"),
            entry_main.index("/usr/bin/supervisord"),
        )

        activate = (DOCKER_ROOT / "activate.py").read_text(encoding="utf-8")
        activate_main = activate.split("def main(", 1)[1]
        self.assertLess(
            activate_main.index("verify_control_auth_image_copies"),
            activate_main.index("exec_managed_service"),
        )
        self.assertIn(
            '"verify-control-auth-image"',
            activate.split("def parser()", 1)[1].split("def main(", 1)[0],
        )

    def test_monitor_authority_attestation_covers_all_docker_activation_paths(self) -> None:
        entrypoint = (DOCKER_ROOT / "entrypoint.py").read_text(encoding="utf-8")
        self.assertLess(
            entrypoint.index("require_monitor_authority"),
            entrypoint.index("/usr/bin/supervisord"),
        )

        activate = (DOCKER_ROOT / "activate.py").read_text(encoding="utf-8")
        service = activate[
            activate.index("def exec_managed_service("):
            activate.index("\ndef _print_json", activate.index("def exec_managed_service("))
        ]
        self.assertLess(
            service.index("require_monitor_authority"),
            service.index("os.execv"),
        )

        health = (DOCKER_ROOT / "healthcheck.py").read_text(encoding="utf-8")
        check = health[health.index("def check_runtime("):health.index("\ndef main(")]
        self.assertIn("require_monitor_authority", check)

        hostctl = (DOCKER_ROOT / "hostctl.py").read_text(encoding="utf-8")
        for function in (
            "guardian_step", "transactional_load", "transactional_reload_network",
            "resume",
        ):
            start = hostctl.index(f"def {function}(")
            end = hostctl.find("\ndef ", start + 5)
            body = hostctl[start:end if end >= 0 else None]
            with self.subTest(function=function):
                self.assertIn("require_monitor_authority", body)

    def test_control_auth_helper_is_invoked_fail_closed_and_status_is_exact(self) -> None:
        activate = load_script("activate.py")
        calls = []

        def runner(command, **kwargs):
            calls.append((list(command), dict(kwargs)))
            if command[-1] == "validate":
                return SimpleNamespace(
                    returncode=0, stdout="",
                    stderr="WARNING: factory Monitor control credentials are active\n",
                )
            if command[-1] == "status":
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        '{"factory_records_active":true,"valid":true}\n'
                    ),
                    stderr="",
                )
            self.fail(f"unexpected auth helper command: {command}")

        default_errors = io.StringIO()
        with redirect_stderr(default_errors):
            status = activate.require_control_auth(runner=runner)
        self.assertEqual(
            {"valid": True, "factory_records_active": True}, status,
        )
        self.assertEqual(
            [
                ["/opt/http-ztp/control-auth.py", "validate"],
                ["/opt/http-ztp/control-auth.py", "status"],
            ],
            [command for command, _kwargs in calls],
        )
        for _command, kwargs in calls:
            self.assertEqual(
                {
                    "capture_output": True, "text": True, "check": False,
                    "timeout": 10,
                },
                kwargs,
            )
        self.assertEqual("", default_errors.getvalue())

        calls.clear()
        explicit_errors = io.StringIO()
        with redirect_stderr(explicit_errors):
            explicit = activate.require_control_auth(
                runner=runner, emit_factory_warning=True,
            )
        self.assertEqual(status, explicit)
        self.assertEqual(
            "WARNING: factory Monitor control credentials are active\n",
            explicit_errors.getvalue(),
        )
        self.assertEqual(2, len(calls))

        for result, message in (
            (
                SimpleNamespace(returncode=1, stdout="", stderr="invalid"),
                "validation",
            ),
            (
                SimpleNamespace(
                    returncode=0, stdout="", stderr=""
                ),
                "status",
            ),
        ):
            with self.subTest(failure=message), self.assertRaisesRegex(
                activate.ActivationError, "control.*credential|credential.*control",
            ):
                activate.require_control_auth(
                    runner=mock.Mock(return_value=result),
                )

        for name in ("entrypoint.py", "healthcheck.py", "hostctl.py"):
            source = (DOCKER_ROOT / name).read_text(encoding="utf-8")
            with self.subTest(lifecycle=name):
                self.assertIn("require_control_auth", source)
        hostctl = (DOCKER_ROOT / "hostctl.py").read_text(encoding="utf-8")
        self.assertRegex(
            hostctl,
            r"(?s)def guardian_loop\(.*?while True:.*?require_control_auth",
        )

    def test_monitor_authority_attestor_is_exact_bounded_and_fail_closed(self) -> None:
        activate = load_script("activate.py")
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout="", stderr="",
        ))
        self.assertIsNone(activate.require_monitor_authority(runner=runner))
        runner.assert_called_once_with(
            ["/opt/http-ztp/control-auth.py", "monitor-authority-attest"],
            capture_output=True, text=True, check=False, timeout=10,
        )

        failures = (
            SimpleNamespace(returncode=1, stdout="", stderr="invalid"),
            SimpleNamespace(returncode=0, stdout="unexpected\n", stderr=""),
            SimpleNamespace(returncode=0, stdout="", stderr="unexpected\n"),
        )
        for result in failures:
            with self.subTest(result=result), self.assertRaisesRegex(
                activate.ActivationError, "authority.*attestation",
            ):
                activate.require_monitor_authority(
                    runner=mock.Mock(return_value=result),
                )

    def test_deploy_stops_writer_before_auth_prepare_and_rotate_never_transports_a_secret(
        self,
    ) -> None:
        result = self._run_deploy_function_harness("""
events=()
prepare_bind_mounts() { events+=(binds); }
prepare_control_auth() { events+=(auth); }
prepare_monitor_authority() { events+=(authority); }
clear_activation_for_recreate() { events+=(remove); }
compose_available() { return 1; }
plain_docker_run() { events+=(create); }
owned_container_id() { printf '%064d' 0; }
wait_control_plane() { events+=(ready); }
start_inactive_container recover sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa plain required already-prepared already-prepared
printf '%s\n' "${events[*]}"
""")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            "binds remove create ready", result.stdout.splitlines()[-1],
        )

        deploy = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        for action, later in (
            ("deploy", "build_image"),
            ("deploy-preloaded", "verify_preloaded_image"),
            ("deploy-project-preloaded", "verify_preloaded_image"),
        ):
            with self.subTest(action=action):
                branch = deploy.rsplit(f"  {action})", 1)[1].split("    ;;", 1)[0]
                self.assertIn("prepare_control_auth", branch)
                self.assertIn("prepare_monitor_authority", branch)
                self.assertIn("clear_activation_for_recreate", branch)
                self.assertLess(
                    branch.index("prepare_control_auth"),
                    branch.index("prepare_monitor_authority"),
                )
                self.assertLess(
                    branch.index("clear_activation_for_recreate"),
                    branch.index("prepare_control_auth"),
                )
                self.assertLess(
                    branch.index("prepare_monitor_authority"),
                    branch.index(later),
                )
                self.assertIn("already-prepared", branch)
        down = deploy.rsplit("  down)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("clear_activation_for_recreate", down)
        self.assertNotIn("prepare_control_auth", down)
        self.assertNotIn("prepare_monitor_authority", down)
        self.assertIn("rotate-auth USER", deploy)
        rotate = deploy.rsplit("  rotate-auth)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("--rotate-control-auth", rotate)
        self.assertNotRegex(rotate, r"read\s+-[rsp]|getpass|PASSWORD|password=")
        self.assertNotIn("one or both factory credential records remain active", rotate)

    def test_explicit_host_prepare_emits_exactly_one_bounded_factory_warning(self) -> None:
        factory = self._run_deploy_function_harness(r'''
safe_lock_run() { printf '%s\n' '{"factory_records_active":true,"valid":true}'; }
prepare_control_auth
''')
        self.assertEqual(0, factory.returncode, factory.stderr)
        self.assertEqual("", factory.stderr)
        expected = (
            "[WARN] factory Monitor control credentials are active; "
            "rotate both users immediately after first login\n"
        )
        self.assertEqual(expected, factory.stdout)
        self.assertEqual(1, len(factory.stdout.splitlines()))
        self.assertLessEqual(len(factory.stdout.encode("utf-8")), 192)

        rotated = self._run_deploy_function_harness(r'''
safe_lock_run() { printf '%s\n' '{"factory_records_active":false,"valid":true}'; }
prepare_control_auth
''')
        self.assertEqual(0, rotated.returncode, rotated.stderr)
        self.assertEqual("", rotated.stdout)

    def test_docker_build_context_excludes_runtime_state_secrets_and_outputs(self) -> None:
        lines = (DOCKER_ROOT / "Dockerfile.dockerignore").read_text(
            encoding="utf-8",
        ).splitlines()
        required_exclusions = (
            "infra/logs/**",
            "infra/docker/infra-runtime.conf",
            "infra/docker/.env",
            "infra/docker/.env.*",
            "infra/docker/container.env",
            "infra/docker/desired-state.json",
            "infra/docker/runtime-state.json",
            "monitor/status/**",
            "ztp/image/**",
            "ztp/backup/**",
            "ztp/config/publickey/**",
            "ztp/config/isc-dhcp-server/dhcpd_*.hosts",
            "ztp/status",
            "**/99-output*",
            "**/99-output*/**",
            "**/.ssh/**",
            "**/.[Ss][Ss][Hh]/**",
            "**/*.key",
            "**/*.pem",
            "**/*.lock",
        )
        for pattern in required_exclusions:
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, lines)
                top = pattern.split("/", 1)[0]
                broad = f"!{top}/**"
                if broad in lines:
                    self.assertGreater(lines.index(pattern), lines.index(broad))
        activate = load_script("activate.py")
        for runtime_prefix in (
            "ztp/backup/", "ztp/config/publickey/", "monitor/status/",
        ):
            with self.subTest(runtime_prefix=runtime_prefix):
                self.assertIn(
                    runtime_prefix, activate.IMAGE_SOURCE_EXCLUDED_PREFIXES,
                )

    def test_compose_uses_host_network_without_expansive_host_authority(self) -> None:
        source = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("network_mode: host", source)
        self.assertIn("HTTP_ZTP_RUNTIME_BACKEND: supervisor", source)
        self.assertRegex(source, r"(?m)^\s*- /var/www/html:/var/www/html$")
        self.assertRegex(source, r"(?m)^\s*cap_drop:\s*\n\s*- ALL$")
        self.assertNotRegex(source, r"(?m)^\s*ports\s*:")
        self.assertNotRegex(source, r"(?m)^\s*privileged\s*:")
        self.assertNotRegex(source, r"(?m)^\s*pid\s*:")
        self.assertNotIn("NET_ADMIN", source)
        self.assertNotIn("/var/run/docker.sock", source)
        self.assertNotIn("/run/docker.sock", source)
        for mount in (
            "/var/lib/http-ztp-container/runtime:/var/lib/http-ztp",
            "/var/lib/http-ztp-container/dhcp-etc:/etc/dhcp",
            "/var/lib/http-ztp-container/dhcp-lib:/var/lib/dhcp",
            "/var/lib/http-ztp-container/ssh:/root/.ssh",
            "/var/lib/http-ztp-container/logs:/var/log/http-ztp",
            "/var/lib/http-ztp-container/apache-logs:/var/log/apache2",
        ):
            with self.subTest(mount=mount):
                self.assertIn(mount, source)
        self.assertNotIn("/var/lib/http-ztp:/var/lib/http-ztp", source)
        self.assertRegex(source, r"(?m)^\s*tmpfs:\s*\n\s*- /run:")
        self.assertRegex(source, r"(?m)^\s*- /tmp:")
        self.assertIn("com.nvidia.http-ztp.managed: \"true\"", source)
        self.assertIn("com.nvidia.http-ztp.http-root: /var/www/html", source)

    def test_python_runtime_imports_do_not_write_bytecode_to_the_bind_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "tools/ztp_service_runtime.py"
            module.parent.mkdir(parents=True)
            module.write_text("VALUE = 42\n", encoding="utf-8")
            script = (
                "import importlib.util, pathlib, sys; "
                "assert sys.dont_write_bytecode; "
                f"p=pathlib.Path({str(module)!r}); "
                "s=importlib.util.spec_from_file_location('runtime_fixture', p); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                "assert m.VALUE == 42"
            )
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            result = __import__("subprocess").run(
                [sys.executable, "-c", script], env=environment,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse((module.parent / "__pycache__").exists())

    def test_supervisor_owns_all_five_services_without_network_control(self) -> None:
        source = (DOCKER_ROOT / "supervisord.conf").read_text(encoding="utf-8")
        self.assertIn("nodaemon=true", source)
        self.assertIn("chmod=0700", source)
        for name in (
            "apache2", "dhcpd", "ztp-monitor", "switch-collection",
            "manual-ztp",
        ):
            with self.subTest(program=name):
                self.assertIn(f"[program:{name}]", source)
        self.assertNotIn("[inet_http_server]", source)
        self.assertNotIn("ip addr", source)
        self.assertNotIn("netplan", source)
        self.assertIn("[program:runtime-resume]", source)
        self.assertIn("[program:runtime-guardian]", source)
        self.assertIn("[program:logrotate]", source)
        # Active services may self-heal, but every restart re-enters the exact
        # marker/precommit authority gate in activate.py.  Explicit stop still
        # disables Supervisor restart.
        for name in ("apache2", "dhcpd"):
            with self.subTest(unexpected_restart=name):
                section = source.split(f"[program:{name}]", 1)[1].split(
                    "[program:", 1,
                )[0]
                self.assertIn("autorestart=unexpected", section)
        for name in ("ztp-monitor", "switch-collection", "manual-ztp"):
            with self.subTest(worker_restart=name):
                section = source.split(f"[program:{name}]", 1)[1].split(
                    "[program:", 1,
                )[0]
                self.assertIn("autorestart=true", section)

    def test_ztp_monitor_supervisor_log_does_not_depend_on_published_status(self) -> None:
        """Supervisor must parse cleanly before load publishes ztp/status."""
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(DOCKER_ROOT / "supervisord.conf", encoding="utf-8")

        log_path = parser["program:ztp-monitor"]["stdout_logfile"]
        self.assertEqual(
            "/var/log/http-ztp/ztp-monitor-background.log",
            log_path,
        )
        self.assertFalse(log_path.startswith("/var/www/html/ztp/status/"))

    def test_actual_runtime_env_is_excluded_and_example_is_topology_neutral(self) -> None:
        example = (DOCKER_ROOT / "container.env.example").read_text(encoding="utf-8")
        ignore = (DOCKER_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("HTTP_ZTP_PROJECT=", example)
        self.assertIn("HTTP_ZTP_SWITCH_SCOPE=", example)
        self.assertIn("HTTP_ZTP_MINI=", example)
        self.assertIn("HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=", example)
        self.assertIn("HTTP_ZTP_DHCP_RELAY_INGRESS=", example)
        self.assertNotIn("enp0s10", example)
        self.assertNotIn("enp0s11", example)
        self.assertNotIn("10.43.", example)
        self.assertIn("/infra-runtime.conf", ignore)

    def test_parameterized_init_writes_exact_private_runtime_contract_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_root = root / "infra/docker"
            project = root / "DAY0-Prepare/2026-12-vb-gb300"
            docker_root.mkdir(parents=True)
            project.mkdir(parents=True)
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet,netmask,ztp_service_ip\n",
                encoding="utf-8",
            )
            result = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
require_root() {{ :; }}
parse_init_options --project 2026-12-vb-gb300 --scope air --mini
initialize_runtime_env
'''
            )
            self.assertEqual(0, result.returncode, result.stderr)
            runtime = docker_root / "infra-runtime.conf"
            self.assertEqual(
                """HTTP_ZTP_PROJECT=2026-12-vb-gb300
HTTP_ZTP_SCOPE=air
HTTP_ZTP_SWITCH_SCOPE=eth
HTTP_ZTP_MINI=enabled
HTTP_ZTP_MONITOR_INTERVAL=30
HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=
HTTP_ZTP_DHCP_RELAY_INGRESS=
HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass
TZ=Asia/Shanghai
""",
                runtime.read_text(encoding="utf-8"),
            )
            metadata = runtime.lstat()
            self.assertEqual(0o600, metadata.st_mode & 0o777)
            self.assertEqual(1, metadata.st_nlink)
            self.assertTrue(runtime.is_file())
            self.assertFalse(runtime.is_symlink())

            before = runtime.read_bytes()
            retry = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
require_root() {{ :; }}
parse_init_options --project other --scope prod
initialize_runtime_env
'''
            )
            self.assertNotEqual(0, retry.returncode)
            self.assertIn("refusing to overwrite", retry.stderr)
            self.assertEqual(before, runtime.read_bytes())

    def test_parameterized_init_rejects_ambiguous_or_unsafe_profiles(self) -> None:
        invalid = (
            ("--project site-a", "--scope"),
            ("--project site-a --project site-b --scope air", "duplicate"),
            ("--project ../site-a --scope air", "project"),
            ("--project site-a --scope prod --mini", "mini"),
            ("--project site-a --scope air --switch ib", "AIR"),
            ("--project site-a --scope prod --switch bad", "switch"),
            ("--project site-a --scope air --monitor-interval 4", "interval"),
            ("--project site-a --scope air --timezone '../UTC'", "timezone"),
            ("--project site-a --scope air --timezone Mars/Base", "timezone"),
            ("--project site-a --scope air --timezone Asia", "timezone"),
            ("--project site-a --scope air --dhcp-interface-allowlist 'eno2 eno2'", "duplicate"),
        )
        for arguments, expected in invalid:
            with self.subTest(arguments=arguments):
                result = self._run_deploy_function_harness(
                    f"parse_init_options {arguments}\n"
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn(expected.casefold(), result.stderr.casefold())

    def test_runtime_env_reader_requires_stable_private_single_link_file(self) -> None:
        payload = b"""HTTP_ZTP_PROJECT=site-a
HTTP_ZTP_SCOPE=air
HTTP_ZTP_SWITCH_SCOPE=eth
HTTP_ZTP_MINI=enabled
HTTP_ZTP_MONITOR_INTERVAL=30
HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=
HTTP_ZTP_DHCP_RELAY_INGRESS=
HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass
TZ=Asia/Shanghai
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker_root = root / "infra/docker"
            project = root / "DAY0-Prepare/site-a"
            docker_root.mkdir(parents=True)
            project.mkdir(parents=True)
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet,netmask,ztp_service_ip\n",
                encoding="utf-8",
            )
            runtime = docker_root / "infra-runtime.conf"

            def invoke() -> subprocess.CompletedProcess[str]:
                return self._run_deploy_function_harness(
                    f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env={str(runtime)!r}
stable_runtime_env_text "$runtime_env"
'''
                )

            runtime.write_bytes(payload)
            runtime.chmod(0o600)
            accepted = invoke()
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual(payload.decode("utf-8"), accepted.stdout)

            runtime.chmod(0o644)
            permissive = invoke()
            self.assertNotEqual(0, permissive.returncode)
            self.assertIn("private", permissive.stderr.casefold())

            runtime.chmod(0o600)
            alias = docker_root / "runtime.alias"
            os.link(runtime, alias)
            linked = invoke()
            self.assertNotEqual(0, linked.returncode)
            self.assertIn("single-link", linked.stderr.casefold())
            alias.unlink()

            source = docker_root / "runtime.source"
            runtime.rename(source)
            runtime.symlink_to(source.name)
            symlinked = invoke()
            self.assertNotEqual(0, symlinked.returncode)
            self.assertIn("nofollow", symlinked.stderr.casefold())

        source_text = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        load_body = source_text.split("load_runtime_env() {", 1)[1].split(
            "\ncompose_available()", 1,
        )[0]
        self.assertIn('stable_runtime_env_text "$runtime_env"', load_body)
        self.assertNotIn('done < "$runtime_env"', load_body)
        self.assertFalse(os.path.lexists(DOCKER_ROOT / "README.md"))
        documentation = (ROOT / "test_cases/README.md").read_text(
            encoding="utf-8",
        )
        self.assertIn("root 私有、single-link", documentation)
        self.assertIn("不可覆盖的 `infra-runtime.conf`", documentation)

    def test_image_export_creates_project_independent_generic_bundle(self) -> None:
        image_id = "sha256:" + "a" * 64
        tar_payload = b"independent immutable docker archive fixture\n"
        manifest_payload = b'{"schema_version":1,"files":[]}\n'
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            docker_root = root / "infra/docker"
            docker_root.mkdir(parents=True)
            (docker_root / "deployment-source-manifest.json").write_bytes(
                manifest_payload
            )
            # A generic developer image export must work without a runtime
            # profile, project tree, upload packager, or relay installer.
            output = base / "offline-http-ztp-amd64"
            events = base / "events.log"
            result = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{
  [[ -n "$1" ]] || return 92
  printf '%s\n' {image_id!r} > "$1"
  printf '%s\n' build >> {str(events)!r}
}}
verify_preloaded_image() {{
  printf '%s\n' verify >> {str(events)!r}
  printf '%s' "$1"
}}
safe_lock_run() {{
  [[ "$1" == -- ]] && shift
  "$@"
}}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    [[ "${{!#}}" == {image_id!r} ]] || return 93
    printf '%s|linux|amd64\n' {image_id!r}
  elif [[ "$1" == save && "$2" == --output ]]; then
    [[ "${{!#}}" == {image_id!r} ]] || return 94
    printf 'independent immutable docker archive fixture\n' > "$3"
  else
    printf 'unexpected fake docker argv: %s\n' "$*" >&2
    return 91
  fi
}}
run_image_export {str(output)!r}
'''
            )
            self.assertEqual(0, result.returncode, result.stderr)
            archive = output / "http-ztp-ubuntu-24.04.tar"
            metadata_path = output / "image-metadata.json"
            sums = output / "SHA256SUMS"
            self.assertEqual(
                {archive.name, metadata_path.name, sums.name},
                {path.name for path in output.iterdir()},
            )
            self.assertEqual(tar_payload, archive.read_bytes())
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual({
                "architecture", "artifact_type", "image_archive",
                "image_archive_sha256", "image_archive_size", "image_contract",
                "image_flavor", "image_id", "image_name",
                "image_source_manifest_sha256", "os", "schema_version",
            }, set(metadata))
            self.assertEqual(1, metadata["schema_version"])
            self.assertEqual("http-ztp-generic-image", metadata["artifact_type"])
            self.assertEqual("generic", metadata["image_flavor"])
            self.assertEqual("3", metadata["image_contract"])
            self.assertEqual(image_id, metadata["image_id"])
            self.assertEqual("linux", metadata["os"])
            self.assertEqual("amd64", metadata["architecture"])
            self.assertEqual(archive.name, metadata["image_archive"])
            self.assertEqual(len(tar_payload), metadata["image_archive_size"])
            self.assertEqual(
                hashlib.sha256(tar_payload).hexdigest(),
                metadata["image_archive_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(manifest_payload).hexdigest(),
                metadata["image_source_manifest_sha256"],
            )
            for path, mode in (
                (output, 0o700), (archive, 0o600),
                (metadata_path, 0o600), (sums, 0o600),
            ):
                with self.subTest(path=path):
                    info = path.lstat()
                    self.assertEqual(mode, info.st_mode & 0o777)
                    if path.is_file():
                        self.assertEqual(1, info.st_nlink)
                    else:
                        self.assertGreaterEqual(info.st_nlink, 2)
                    self.assertFalse(path.is_symlink())
            lines = sums.read_text(encoding="ascii").splitlines()
            self.assertEqual(2, len(lines))
            self.assertEqual(
                f"{hashlib.sha256(tar_payload).hexdigest()}  {archive.name}",
                lines[0],
            )
            self.assertEqual(
                f"{hashlib.sha256(metadata_path.read_bytes()).hexdigest()}  image-metadata.json",
                lines[1],
            )
            self.assertEqual(
                ["build", "verify", "verify"],
                events.read_text().splitlines(),
            )
            self.assertNotIn("run_load", result.stdout + result.stderr)
            self.assertNotIn("start_inactive_container", result.stdout + result.stderr)

    def test_image_export_rejects_unsafe_path_and_publish_race(self) -> None:
        image_id = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            docker_root = root / "infra/docker"
            docker_root.mkdir(parents=True)
            (docker_root / "deployment-source-manifest.json").write_text(
                '{"schema_version":1,"files":[]}\n', encoding="ascii",
            )

            unsafe_parent = base / "unsafe"
            unsafe_parent.mkdir(mode=0o777)
            unsafe_parent.chmod(0o777)
            preflight = base / "unsafe-preflight"
            unsafe = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ : > {str(preflight)!r}; host_architecture=amd64; }}
run_image_export {str(unsafe_parent / 'bundle')!r}
'''
            )
            self.assertNotEqual(0, unsafe.returncode)
            self.assertIn("output parent", unsafe.stderr.casefold())
            self.assertFalse(preflight.exists(), "unsafe parent must fail before host work")

            real_parent = base / "real/private"
            real_parent.mkdir(parents=True, mode=0o700)
            alias = base / "alias"
            alias.symlink_to(base / "real", target_is_directory=True)
            aliased_preflight = base / "alias-preflight"
            aliased = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ : > {str(aliased_preflight)!r}; host_architecture=amd64; }}
run_image_export {str(alias / 'private/bundle')!r}
'''
            )
            self.assertNotEqual(0, aliased.returncode)
            self.assertIn("symlink", aliased.stderr.casefold())
            self.assertFalse(aliased_preflight.exists())

            output = base / "race-bundle"
            marker = output / "concurrent-owner"
            verify_seen = base / "verify-seen"
            race = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{ printf '%s\n' {image_id!r} > "$1"; }}
safe_lock_run() {{ [[ "$1" == -- ]] && shift; "$@"; }}
verify_preloaded_image() {{
  if [[ -e {str(verify_seen)!r} ]]; then
    mkdir {str(output)!r}
    printf '%s\n' keep > {str(marker)!r}
  else
    : > {str(verify_seen)!r}
  fi
  printf '%s' "$1"
}}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {image_id!r}
  elif [[ "$1" == save && "$2" == --output ]]; then
    printf 'archive\n' > "$3"
  else
    return 91
  fi
}}
run_image_export {str(output)!r}
'''
            )
            self.assertNotEqual(0, race.returncode)
            self.assertIn("publish", race.stderr.casefold())
            self.assertEqual("keep\n", marker.read_text(encoding="ascii"))
            self.assertEqual({"concurrent-owner"}, {item.name for item in output.iterdir()})

    def test_image_export_holds_parent_and_stage_across_path_replacement(self) -> None:
        image_id = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            docker_root = root / "infra/docker"
            docker_root.mkdir(parents=True)
            (docker_root / "deployment-source-manifest.json").write_text(
                '{"schema_version":1,"files":[]}\n', encoding="ascii",
            )

            # Replace the approved parent after its initial validation but
            # before staging.  No image-export pathname may ever be handed to
            # a writer through the replacement symlink.
            parent = base / "export-parent"
            parent.mkdir(mode=0o700)
            held_parent = base / "held-parent"
            external = base / "external"
            external.mkdir(mode=0o700)
            build_path = base / "build-path"
            replaced_before_stage = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{
  mv -- {str(parent)!r} {str(held_parent)!r}
  ln -s -- {str(external)!r} {str(parent)!r}
  host_architecture=amd64
}}
build_image() {{
  printf '%s\n' "$1" > {str(build_path)!r}
  printf '%s\n' {image_id!r} > "$1"
}}
safe_lock_run() {{ [[ "$1" == -- ]] && shift; "$@"; }}
verify_preloaded_image() {{ printf '%s' "$1"; }}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {image_id!r}
  elif [[ "$1" == save && "$2" == --output ]]; then
    printf 'archive\n' > "$3"
  else
    return 91
  fi
}}
run_image_export {str(parent / 'bundle')!r}
'''
            )
            self.assertNotEqual(0, replaced_before_stage.returncode)
            self.assertEqual(
                "image.iid",
                build_path.read_text(encoding="utf-8").strip(),
                "a mutable absolute parent pathname reached an image-export writer",
            )
            self.assertEqual([], list(external.iterdir()))
            self.assertEqual([], list(held_parent.glob(".bundle.tmp.*")))

            # Replace the pathname after the private stage exists.  Cleanup
            # must still remove that exact stage through the held parent,
            # without following or deleting anything below the replacement.
            parent.unlink()
            held_parent.rename(parent)
            external_marker = external / "must-survive"
            external_marker.write_text("external\n", encoding="ascii")
            replaced_during_build = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{
  printf '%s\n' {image_id!r} > "$1"
  mv -- {str(parent)!r} {str(held_parent)!r}
  ln -s -- {str(external)!r} {str(parent)!r}
}}
safe_lock_run() {{ [[ "$1" == -- ]] && shift; "$@"; }}
verify_preloaded_image() {{ printf '%s' "$1"; }}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {image_id!r}
  elif [[ "$1" == save && "$2" == --output ]]; then
    printf 'archive\n' > "$3"
  else
    return 91
  fi
}}
run_image_export {str(parent / 'bundle')!r}
'''
            )
            self.assertNotEqual(0, replaced_during_build.returncode)
            self.assertEqual("external\n", external_marker.read_text(encoding="ascii"))
            self.assertEqual(
                {"must-survive"}, {entry.name for entry in external.iterdir()},
            )
            self.assertEqual([], list(held_parent.glob(".bundle.tmp.*")))

    def test_image_export_rolls_back_if_parent_path_changes_after_fsync(self) -> None:
        image_id = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            docker_root = root / "infra/docker"
            docker_root.mkdir(parents=True)
            (docker_root / "deployment-source-manifest.json").write_text(
                '{"schema_version":1,"files":[]}\n', encoding="ascii",
            )
            parent = base / "export-parent"
            parent.mkdir(mode=0o700)
            displaced = base / "displaced-parent"
            output = parent / "bundle"
            result = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{ printf '%s\n' {image_id!r} > "$1"; }}
safe_lock_run() {{ [[ "$1" == -- ]] && shift; "$@"; }}
verify_preloaded_image() {{ printf '%s' "$1"; }}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {image_id!r}
  elif [[ "$1" == save && "$2" == --output ]]; then
    printf 'archive\n' > "$3"
  else
    return 91
  fi
}}
eval "$(declare -f fsync_image_export_stage | \
  sed '1s/^fsync_image_export_stage/real_fsync_image_export_stage/')"
fsync_image_export_stage() {{
  real_fsync_image_export_stage "$@"
  mv -- {str(parent)!r} {str(displaced)!r}
  mkdir -m 0700 -- {str(parent)!r}
}}
run_image_export {str(output)!r}
'''
            )
            self.assertNotEqual(
                0, result.returncode,
                "a detached publication was incorrectly reported as successful",
            )
            self.assertNotIn("[OK] generic image bundle", result.stdout)
            self.assertIn("rolled back", result.stderr.casefold())
            self.assertFalse(
                (displaced / "bundle").exists(),
                "the exact detached output inode was not rolled back",
            )
            self.assertEqual([], list(parent.iterdir()))

    def test_image_export_revalidates_every_file_at_the_publish_boundary(self) -> None:
        image_id = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            docker_root = root / "infra/docker"
            docker_root.mkdir(parents=True)
            (docker_root / "deployment-source-manifest.json").write_text(
                '{"schema_version":1,"files":[]}\n', encoding="ascii",
            )
            output = base / "bundle"
            result = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{ printf '%s\n' {image_id!r} > "$1"; }}
safe_lock_run() {{ [[ "$1" == -- ]] && shift; "$@"; }}
verify_preloaded_image() {{ printf '%s' "$1"; }}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {image_id!r}
  elif [[ "$1" == save && "$2" == --output ]]; then
    printf 'archive\n' > "$3"
  else
    return 91
  fi
}}
eval "$(declare -f fsync_image_export_stage | \
  sed '1s/^fsync_image_export_stage/real_fsync_image_export_stage/')"
fsync_image_export_stage() {{
  real_fsync_image_export_stage "$@"
  printf 'post-freeze mutation\n' >> SHA256SUMS
}}
run_image_export {str(output)!r}
'''
            )
            self.assertNotEqual(
                0, result.returncode,
                "post-freeze checksum mutation was published as a valid bundle",
            )
            self.assertNotIn("[OK] generic image bundle", result.stdout)
            self.assertFalse(
                output.exists(), "an invalid published output was not rolled back",
            )
            self.assertEqual([], list(base.glob(".bundle.tmp.*")))

    def test_image_export_preflights_manifest_and_removes_private_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            docker_root = root / "infra/docker"
            docker_root.mkdir(parents=True)
            manifest = docker_root / "deployment-source-manifest.json"
            manifest.write_text(
                '{"schema_version":1,"files":[]}\n', encoding="ascii",
            )
            alias = docker_root / "manifest.alias"
            os.link(manifest, alias)
            output = base / "offline"
            event = base / "build-ran"
            result = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{
  printf '%s\n' {'sha256:' + 'a' * 64!r} > "$1"
  : > {str(event)!r}
}}
verify_preloaded_image() {{ printf '%s' "$1"; }}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {'sha256:' + 'a' * 64!r}
  else
    printf 'unexpected fake docker argv: %s\n' "$*" >&2
    return 91
  fi
}}
run_image_export {str(output)!r}
'''
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("source manifest", result.stderr)
            self.assertFalse(event.exists(), "unsafe manifest must fail before build")
            self.assertFalse(output.exists())
            self.assertEqual([], list(base.glob(".offline.tmp.*")))

            alias.unlink()
            inside_repo = root / "exported-bundle"
            rejected = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{ : > {str(event)!r}; }}
run_image_export {str(inside_repo)!r}
'''
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("outside", rejected.stderr.casefold())
            self.assertFalse(inside_repo.exists())

            save_failure = base / "offline-save-failure"
            event.unlink(missing_ok=True)
            failed_save = self._run_deploy_function_harness(
                f'''script_dir={str(docker_root)!r}
repo_root={str(root)!r}
runtime_env="$script_dir/infra-runtime.conf"
host_preflight() {{ host_architecture=amd64; }}
build_image() {{
  printf '%s\n' {'sha256:' + 'a' * 64!r} > "$1"
  : > {str(event)!r}
}}
verify_preloaded_image() {{ printf '%s' "$1"; }}
safe_lock_run() {{ return 75; }}
docker() {{
  if [[ "$1 $2 $3" == "image inspect --format" ]]; then
    printf '%s|linux|amd64\n' {'sha256:' + 'a' * 64!r}
  else
    return 91
  fi
}}
run_image_export {str(save_failure)!r}
'''
            )
            self.assertNotEqual(0, failed_save.returncode)
            self.assertIn("docker save", failed_save.stderr)
            self.assertTrue(event.exists(), "save failure follows a successful build")
            self.assertFalse(save_failure.exists())
            self.assertEqual(
                [], list(base.glob(".offline-save-failure.tmp.*")),
            )

    def test_image_export_cli_is_generic_and_binds_to_deploy_preloaded(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        usage = source.split("usage() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("image-export OUTPUT_DIR", usage)
        self.assertIn("build-export OUTPUT_DIR", usage)
        argument_gate = source.split("case \"$action\" in", 1)[1].split(
            "case \"$action\" in", 1,
        )[0]
        self.assertIn("image-export|build-export)", argument_gate)
        execution = source.rsplit(
            "  image-export|build-export)", 1,
        )[1].split("    ;;", 1)[0]
        self.assertIn('run_image_export "$2"', execution)
        for forbidden in (
            "start_inactive_container", "run_load", "run_reload_network",
            "docker load", "docker run",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, execution)
        export_body = source.split("run_image_export() {", 1)[1].split(
            "\nverify_preloaded_image()", 1,
        )[0]
        self.assertLess(export_body.index("build_image"), export_body.index("docker save"))
        self.assertGreaterEqual(export_body.count("verify_preloaded_image"), 2)
        for forbidden in (
            "load_runtime_env", "infra-runtime.conf", "HTTP_ZTP_PROJECT",
            "tar-for-upload.py", "deploy-upload-archive.py",
            "included_upload_archive", '"installer"',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, export_body)
        self.assertIn("deployment-source-manifest.json", export_body)
        self.assertIn("image-metadata.json", export_body)
        self.assertIn("SHA256SUMS", export_body)
        preloaded = source.rsplit("  deploy-preloaded)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("verify_preloaded_image", preloaded)
        self.assertIn(
            'start_inactive_container recover "$preloaded_image_id" plain '
            "already-cleared",
            preloaded,
        )

        dockerfile = (DOCKER_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('com.nvidia.http-ztp.image-flavor="generic"', dockerfile)

    def test_generic_build_can_freeze_the_exact_iid_without_changing_deploy_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            iidfile = Path(temporary).resolve() / "image.iid"
            captured = self._run_deploy_function_harness(
                f'''repo_root=/safe/source
script_dir=/safe/source/infra/docker
image_name=http-ztp:ubuntu-24.04
safe_lock_run() {{ printf '%s\n' "$@"; }}
build_image {str(iidfile)!r}
'''
            )
            self.assertEqual(0, captured.returncode, captured.stderr)
            arguments = captured.stdout.splitlines()
            self.assertEqual("--", arguments[1])
            self.assertEqual("docker", arguments[2])
            self.assertIn("--iidfile", arguments)
            position = arguments.index("--iidfile")
            self.assertEqual(str(iidfile), arguments[position + 1])
            self.assertEqual("/safe/source", arguments[-1])

            ordinary = self._run_deploy_function_harness(
                '''repo_root=/safe/source
script_dir=/safe/source/infra/docker
image_name=http-ztp:ubuntu-24.04
safe_lock_run() { printf '%s\n' "$@"; }
build_image
'''
            )
            self.assertEqual(0, ordinary.returncode, ordinary.stderr)
            self.assertNotIn("--iidfile", ordinary.stdout.splitlines())

    def test_deploy_wrapper_has_explicit_lifecycle_and_never_configures_nics(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        for action in (
            "build", "deploy", "deploy-preloaded", "load", "status", "logs",
            "down", "unload",
        ):
            with self.subTest(action=action):
                self.assertIn(action, source)
        self.assertIn("Ubuntu 24.04", source)
        self.assertIn("arm64", source)
        self.assertIn("docker build", source)
        self.assertIn("docker run", source)
        self.assertIn("docker exec", source)
        self.assertIn('command -v ss', source)
        self.assertIn("/opt/http-ztp/hostctl.py load", source)
        self.assertIn("/opt/http-ztp/hostctl.py ready", source)
        lowered = source.casefold()
        for forbidden in ("ip addr add", "ip address add", "netplan apply"):
            self.assertNotIn(forbidden, lowered)
        self.assertIn("--tmpfs /run:", source)
        self.assertIn("--tmpfs /tmp:", source)
        self.assertRegex(
            source,
            r"(?s)deploy\).*?start_inactive_container recover.*?run_load",
        )

    def test_deploy_host_os_gate_accepts_only_ubuntu_22_and_24(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        preflight = source.split("host_preflight() {", 1)[1].split("\n}", 1)[0]

        self.assertIn('case "${ID:-}:${VERSION_ID:-}" in', preflight)
        self.assertIn("ubuntu:22.04|ubuntu:24.04)", preflight)
        self.assertIn(
            'fail "this runtime requires Ubuntu 22.04 or 24.04"', preflight,
        )
        self.assertNotIn('"${VERSION_ID:-}" == "24.04"', preflight)
        for unsupported in ("20.04", "23.10", "25.04", "26.04"):
            with self.subTest(unsupported=unsupported):
                self.assertNotIn(f"ubuntu:{unsupported}", preflight)

    def test_reload_network_help_names_safe_service_ip_move_boundary(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        usage = source.split("usage() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("no source write", usage)
        self.assertIn("reload-network", usage)
        self.assertIn("same service IP", usage)
        self.assertIn("another interface", usage)
        load_help = usage.split("  load", 1)[1].split("  reload-network", 1)[0]
        self.assertNotIn("service-IP/NIC move", load_help)
        self.assertIn("Supervisor", usage)
        self.assertNotIn("systemctl restart", usage)
        self.assertNotIn("supervisorctl restart", usage)

    def test_preloaded_deploy_is_explicit_id_only_and_never_builds(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        # The first deploy-preloaded branch validates argv before any host or
        # Docker action.  Inspect the final execution branch independently.
        body = source.rsplit("  deploy-preloaded)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("verify_preloaded_image", body)
        self.assertIn("start_inactive_container recover", body)
        self.assertIn("plain", body)
        self.assertIn("run_load", body)
        self.assertNotIn("build_image", body)
        self.assertNotIn("$image_name", body)
        self.assertRegex(source, r"sha256:\[0-9a-f\].*64")

        start_body = source.split("start_inactive_container() {", 1)[1].split(
            "\n}", 1,
        )[0]
        self.assertIn("$image_ref", start_body)
        self.assertRegex(start_body, r"(?s)plain\).*?plain_docker_run.*\$image_ref")
        plain_body = source.split("plain_docker_run() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("$image_ref", plain_body)

    def test_deploy_wrapper_uses_validated_ids_and_normalized_runtime_contract(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        self.assertIn('hostlock.py" --validate-local-daemon', source)
        self.assertIn("--inspect-owned-id", source)
        self.assertIn("--expect-env", source)
        self.assertNotIn('docker exec "$container_name"', source)
        self.assertNotIn('docker logs --follow --tail 200 "$container_name"', source)
        self.assertIn(
            '--env HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass', source,
        )
        for key in ("HTTP_ZTP_SWITCH_SCOPE", "HTTP_ZTP_MINI"):
            with self.subTest(runtime_selection=key):
                self.assertIn(f'--env "{key}=${key}"', source)
                self.assertIn(f'--expect-env "{key}=${key}"', source)
        self.assertNotIn('--env-file "$runtime_env"', source)

        compose = (DOCKER_ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("HTTP_ZTP_SWITCH_SCOPE: ${HTTP_ZTP_SWITCH_SCOPE}", compose)
        self.assertIn("HTTP_ZTP_MINI: ${HTTP_ZTP_MINI}", compose)

        for function_name in (
            "wait_control_plane", "run_load", "run_unload", "show_status",
        ):
            with self.subTest(function=function_name):
                body = source.split(f"{function_name}() {{", 1)[1].split(
                    "\n}", 1,
                )[0]
                self.assertIn("$container_id", body)
                self.assertNotIn("$container_name", body)

        for action_name in ("load", "health", "status", "unload"):
            with self.subTest(action=action_name):
                body = source.split(f"  {action_name})", 1)[1].split(
                    "    ;;", 1,
                )[0]
                self.assertIn("owned_container_id", body)
        logs_body = source.split("  logs)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("owned_container_id", logs_body)
        doctor_body = source.split("doctor() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("owned_container_id", doctor_body)

    def test_rebuild_quiesces_old_image_without_calling_drifted_controller(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        clear_body = source.split("clear_activation_for_recreate() {", 1)[1].split(
            "\n}", 1,
        )[0]
        self.assertIn("safe_lock_run", clear_body)
        self.assertIn("--owned-action", clear_body)
        self.assertIn("remove-clear", clear_body)
        self.assertNotIn("docker exec", clear_body)
        self.assertNotIn("hostctl.py", clear_body)
        self.assertNotIn("docker stop", clear_body)
        self.assertNotIn("exec 9>", source)

        build_body = source.split("build_image() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(build_body.index("safe_lock_run"), build_body.index("docker build"))

        down_body = source.split("  down)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("clear_activation_for_recreate", down_body)

        start_body = source.split("start_inactive_container() {", 1)[1].split(
            "\n}", 1,
        )[0]
        self.assertIn("safe_lock_run --require-owned-or-absent", start_body)
        plain_body = source.split("plain_docker_run() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("safe_lock_run --require-owned-or-absent", plain_body)

    def test_owned_container_action_rejects_name_collision_before_mutation(self) -> None:
        hostlock = load_script("hostlock.py")
        record = [{
            "Id": "a" * 64,
            "Name": "/http-ztp",
            "Config": {"Labels": {
                "com.nvidia.http-ztp.managed": "false",
                "com.nvidia.http-ztp.http-root": "/var/www/html",
            }},
            "Mounts": [{
                "Type": "bind", "Source": "/var/www/html",
                "Destination": "/var/www/html", "RW": True,
            }],
            "State": {
                "Running": True, "Restarting": False, "Paused": False,
                "Status": "running", "Pid": 123, "Dead": False,
            },
        }]
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(record), stderr="",
        ))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(hostlock.HostLockError, "ownership label"):
                hostlock.run_owned_container_action(
                    "remove-clear",
                    lock_path=Path(temporary) / ".deployment.lock",
                    activation_marker=Path(temporary) / "activation.json",
                    runner=runner,
                )
        self.assertEqual(1, runner.call_count)
        self.assertEqual(
            ["docker", "container", "inspect", "http-ztp"],
            runner.call_args.args[0],
        )

    def test_owned_container_inspection_rejects_runtime_drift_and_wrong_bind(self) -> None:
        hostlock = load_script("hostlock.py")
        expected_environment = {
            "HTTP_ZTP_PROJECT": "fixture-site",
            "HTTP_ZTP_SCOPE": "air",
            "HTTP_ZTP_SWITCH_SCOPE": "eth",
            "HTTP_ZTP_MINI": "disabled",
            "HTTP_ZTP_MONITOR_INTERVAL": "30",
            "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST": "",
            "HTTP_ZTP_DHCP_RELAY_INGRESS": "",
            "HTTP_ZTP_ASKPASS_TMPDIR": "/run/http-ztp/askpass",
            "TZ": "Asia/Shanghai",
            "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
            "HTTP_ZTP_ROOT": "/var/www/html",
        }

        def record(
            *, source="/var/www/html", destination="/var/www/html",
            writable=True, project="fixture-site",
        ):
            environment = dict(expected_environment)
            environment["HTTP_ZTP_PROJECT"] = project
            return [{
                "Id": "a" * 64,
                "Image": "sha256:" + "1" * 64,
                "Name": "/http-ztp",
                "Config": {
                    "Labels": {
                        "com.nvidia.http-ztp.managed": "true",
                        "com.nvidia.http-ztp.http-root": "/var/www/html",
                        "com.nvidia.http-ztp.image": "true",
                        "com.nvidia.http-ztp.image-contract": "3",
                        "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                    },
                    "Env": [f"{key}={value}" for key, value in environment.items()],
                },
                "Mounts": [
                    {
                        "Type": "bind", "Source": source,
                        "Destination": destination, "RW": writable,
                    },
                    {
                        "Type": "bind",
                        "Source": "/var/lib/http-ztp-container/control-auth",
                        "Destination": "/etc/http-ztp", "RW": False,
                    },
                    {
                        "Type": "bind",
                        "Source": "/var/lib/http-ztp-container/monitor-auth",
                        "Destination": "/var/lib/http-ztp-monitor-auth",
                        "RW": True,
                    },
                ],
                "State": {
                    "Running": True, "Restarting": False, "Paused": False,
                    "Status": "running", "Pid": 123, "Dead": False,
                },
            }]

        valid = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(record()), stderr="",
        ))
        inspected = hostlock.inspect_owned_container(
            valid, expected_environment=expected_environment,
        )
        self.assertEqual("a" * 64, inspected["Id"])

        for bad_record in (
            record(source="/srv/http"),
            record(destination="/srv/http"),
            record(writable=False),
        ):
            with self.subTest(mount=bad_record[0]["Mounts"][0]):
                runner = mock.Mock(return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(bad_record), stderr="",
                ))
                with self.assertRaisesRegex(hostlock.HostLockError, "exact.*RW bind"):
                    hostlock.inspect_owned_container(
                        runner, expected_environment=expected_environment,
                    )

        drifted = mock.Mock(return_value=SimpleNamespace(
            returncode=0,
            stdout=json.dumps(record(project="other-site")), stderr="",
        ))
        with self.assertRaisesRegex(
            hostlock.HostLockError, "runtime configuration drift.*deploy",
        ):
            hostlock.inspect_owned_container(
                drifted, expected_environment=expected_environment,
            )

    def test_contract3_container_requires_exact_auth_mount_and_contract2_is_cleanup_only(
        self,
    ) -> None:
        hostlock = load_script("hostlock.py")
        container_id = "a" * 64
        image_id = "sha256:" + "b" * 64

        def record(
            contract="3", *, auth=True, auth_rw=False, monitor=True,
            monitor_rw=True, running=False,
        ):
            mounts = [{
                "Type": "bind", "Source": "/var/www/html",
                "Destination": "/var/www/html", "RW": True,
            }]
            if auth:
                mounts.append({
                    "Type": "bind",
                    "Source": "/var/lib/http-ztp-container/control-auth",
                    "Destination": "/etc/http-ztp", "RW": auth_rw,
                })
            if contract == "3" and monitor:
                mounts.append({
                    "Type": "bind",
                    "Source": "/var/lib/http-ztp-container/monitor-auth",
                    "Destination": "/var/lib/http-ztp-monitor-auth",
                    "RW": monitor_rw,
                })
            return [{
                "Id": container_id,
                "Image": image_id,
                "Name": "/http-ztp",
                "Config": {"Labels": {
                    "com.nvidia.http-ztp.managed": "true",
                    "com.nvidia.http-ztp.http-root": "/var/www/html",
                    "com.nvidia.http-ztp.image": "true",
                    "com.nvidia.http-ztp.image-contract": contract,
                    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                }},
                "Mounts": mounts,
                "State": {
                    "Running": running, "Restarting": False, "Paused": False,
                    "Status": "running" if running else "exited",
                    "Pid": 55 if running else 0, "Dead": False,
                },
            }]

        valid = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(record()), stderr="",
        ))
        self.assertEqual(container_id, hostlock.inspect_owned_container(valid)["Id"])

        mutations = []
        writable = record(auth_rw=True)
        mutations.append(writable)
        missing = record(auth=False)
        mutations.append(missing)
        file_bind = record()
        file_bind[0]["Mounts"][1]["Source"] += "/control-users.htpasswd"
        file_bind[0]["Mounts"][1]["Destination"] += "/control-users.htpasswd"
        mutations.append(file_bind)
        duplicate = record()
        duplicate[0]["Mounts"].append(dict(duplicate[0]["Mounts"][1]))
        mutations.append(duplicate)
        mutations.append(record(monitor=False))
        mutations.append(record(monitor_rw=False))
        parent_source = record()
        parent_source[0]["Mounts"].append({
            "Type": "bind",
            "Source": "/var/lib/http-ztp-container",
            "Destination": "/mnt/container-state",
            "RW": True,
        })
        mutations.append(parent_source)
        parent_destination = record()
        parent_destination[0]["Mounts"].append({
            "Type": "bind", "Source": "/srv/host-etc",
            "Destination": "/etc", "RW": True,
        })
        mutations.append(parent_destination)
        for changed in mutations:
            with self.subTest(mounts=changed[0]["Mounts"]), self.assertRaisesRegex(
                hostlock.HostLockError,
                "auth.*bind|bind.*auth|/etc/http-ztp|Monitor authority.*bind",
            ):
                hostlock.inspect_owned_container(mock.Mock(return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(changed), stderr="",
                )))

        legacy = record("2", auth=False)
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(legacy), stderr="",
        ))
        with self.assertRaisesRegex(
            hostlock.HostLockError, "contract 2.*cleanup|legacy.*cleanup",
        ):
            hostlock.inspect_owned_container(runner)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "activation.json"
            marker.write_text("active\n", encoding="ascii")
            replies = iter((
                SimpleNamespace(returncode=0, stdout=json.dumps(legacy), stderr=""),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ))
            cleanup_runner = mock.Mock(
                side_effect=lambda *_args, **_kwargs: next(replies),
            )
            with mock.patch.object(hostlock, "ACTIVATION_MARKER", marker):
                self.assertEqual(0, hostlock.run_owned_container_action(
                    "remove-clear", lock_path=root / ".deployment.lock",
                    activation_marker=marker, runner=cleanup_runner,
                ))
            self.assertFalse(marker.exists())
            self.assertEqual(
                [
                    ["docker", "container", "inspect", "http-ztp"],
                    ["docker", "rm", container_id],
                ],
                [call.args[0] for call in cleanup_runner.call_args_list],
            )

    def test_contract2_preloaded_image_is_rejected_before_any_probe_or_create(self) -> None:
        hostlock = load_script("hostlock.py")
        identifier = "sha256:" + "2" * 64
        legacy = [{
            "Id": identifier, "Os": "linux", "Architecture": "amd64",
            "Config": {"Labels": {
                "com.nvidia.http-ztp.image": "true",
                "com.nvidia.http-ztp.image-flavor": "generic",
                "com.nvidia.http-ztp.image-contract": "2",
                "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
            }},
        }]
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(legacy), stderr="",
        ))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            hostlock.HostLockError, "contract 2.*rebuild|contract 2.*re-export",
        ):
            hostlock.verify_preloaded_image(
                identifier, "amd64",
                lock_path=Path(temporary) / ".deployment.lock",
                wait_seconds=0, runner=runner,
            )
        self.assertEqual(1, runner.call_count)
        self.assertEqual(
            ["docker", "image", "inspect", identifier],
            runner.call_args.args[0],
        )

    def test_rotation_terminal_is_exact_nofollow_character_tty_and_always_closed(
        self,
    ) -> None:
        hostlock = load_script("hostlock.py")
        self.assertEqual(0o755, hostlock.CONTROL_AUTH_SOURCE_MODE)
        descriptor = 73
        expected_flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        opened = mock.Mock(return_value=descriptor)
        closed = mock.Mock()
        character = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
        with mock.patch.object(hostlock.os, "open", opened), mock.patch.object(
            hostlock.os, "fstat", return_value=character,
        ), mock.patch.object(
            hostlock.os, "isatty", return_value=True,
        ) as isatty, mock.patch.object(hostlock.os, "close", closed):
            with hostlock._validated_rotation_terminal() as authority:
                self.assertEqual(descriptor, authority)
        opened.assert_called_once_with("/dev/tty", expected_flags)
        isatty.assert_called_once_with(descriptor)
        closed.assert_called_once_with(descriptor)

        for metadata, terminal in (
            (SimpleNamespace(st_mode=stat.S_IFREG | 0o600), True),
            (character, False),
        ):
            with self.subTest(mode=metadata.st_mode, terminal=terminal), \
                    mock.patch.object(
                        hostlock.os, "open", return_value=descriptor,
                    ), mock.patch.object(
                        hostlock.os, "fstat", return_value=metadata,
                    ), mock.patch.object(
                        hostlock.os, "isatty", return_value=terminal,
                    ), mock.patch.object(hostlock.os, "close") as close, \
                    self.assertRaisesRegex(
                        hostlock.HostLockError, "human.*terminal|interactive.*terminal",
                    ):
                with hostlock._validated_rotation_terminal():
                    self.fail("unsafe terminal authority was accepted")
            close.assert_called_once_with(descriptor)

        with mock.patch.object(
            hostlock.os, "open", side_effect=OSError("no controlling terminal"),
        ), mock.patch.object(hostlock.os, "close") as close, \
                self.assertRaisesRegex(
                    hostlock.HostLockError, "human.*terminal|interactive.*terminal",
                ):
            with hostlock._validated_rotation_terminal():
                self.fail("missing terminal authority was accepted")
        close.assert_not_called()

    def test_rotation_rejects_non_tty_before_any_docker_subprocess(self) -> None:
        hostlock = load_script("hostlock.py")
        runner = mock.Mock()

        @contextmanager
        def unavailable_terminal():
            raise hostlock.HostLockError(
                "credential rotation requires a human at an interactive terminal"
            )
            yield -1

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_validated_rotation_terminal",
            unavailable_terminal, create=True,
        ), mock.patch.object(
            hostlock, "_load_control_auth",
        ) as loader, self.assertRaisesRegex(
            hostlock.HostLockError, "human.*terminal|interactive.*terminal",
        ):
            hostlock.rotate_control_auth(
                "nvis", lock_path=Path(temporary) / ".deployment.lock",
                runner=runner,
            )
        runner.assert_not_called()
        loader.assert_not_called()

    def test_rotation_cli_stdout_is_only_the_host_post_validation_json(self) -> None:
        hostlock = load_script("hostlock.py")
        expected = {"valid": True, "factory_records_active": False}
        output = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "rotate_control_auth", return_value=expected,
        ), redirect_stdout(output), redirect_stderr(errors):
            code = hostlock.main([
                "--lock", os.fspath(Path(temporary) / ".deployment.lock"),
                "--rotate-control-auth", "nvis",
            ])
        self.assertEqual(0, code)
        self.assertEqual(
            '{"factory_records_active":false,"valid":true}\n',
            output.getvalue(),
        )
        self.assertEqual("", errors.getvalue())

    def test_host_side_auth_prepare_preserves_valid_bytes_and_rotation_is_stdin_only(
        self,
    ) -> None:
        hostlock = load_script("hostlock.py")
        events = []

        class AuthModule:
            @staticmethod
            def ensure_auth_file(path, *, required_uid, required_gid):
                events.append(("ensure", path, required_uid, required_gid))
                return False

            @staticmethod
            def validate_auth_file(path, *, required_uid, required_gid):
                events.append(("validate", path, required_uid, required_gid))
                return object()

            @staticmethod
            def status_auth_file(path, *, required_uid, required_gid):
                events.append(("status", path, required_uid, required_gid))
                return {"valid": True, "factory_records_active": False}

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_load_control_auth", return_value=AuthModule,
        ):
            status = hostlock.prepare_control_auth(
                lock_path=Path(temporary) / ".deployment.lock",
            )
        self.assertEqual(
            {"valid": True, "factory_records_active": False}, status,
        )
        self.assertEqual("ensure", events[0][0])
        self.assertEqual("validate", events[1][0])
        self.assertEqual("status", events[2][0])

        self.assertIn("provision_monitor_authority", hostlock.CONTROL_AUTH_REQUIRED_APIS)
        self.assertIn("attest_monitor_authority", hostlock.CONTROL_AUTH_REQUIRED_APIS)

        authority_events = []

        class AuthorityModule:
            _CONTROL_AUTH_SOURCE_SHA256 = "a" * 64

            @staticmethod
            def provision_monitor_authority(path, **kwargs):
                authority_events.append(("provision", path, dict(kwargs)))

            @staticmethod
            def attest_monitor_authority(path, **kwargs):
                authority_events.append(("attest", path, dict(kwargs)))

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_load_control_auth", return_value=AuthorityModule,
        ):
            hostlock.prepare_monitor_authority(
                lock_path=Path(temporary) / ".deployment.lock",
            )
        self.assertEqual(["provision", "attest"], [item[0] for item in authority_events])
        self.assertEqual(
            [hostlock.MONITOR_AUTHORITY_HOST_ROOT] * 2,
            [item[1] for item in authority_events],
        )

        events.clear()
        container_id = "c" * 64
        image_id = "sha256:" + "d" * 64
        owned = {
            "Id": container_id, "Image": image_id, "Name": "/http-ztp",
            "Config": {"Labels": {
                "com.nvidia.http-ztp.managed": "true",
                "com.nvidia.http-ztp.http-root": "/var/www/html",
                "com.nvidia.http-ztp.image": "true",
                "com.nvidia.http-ztp.image-contract": "3",
                "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
            }},
            "Mounts": [
                {"Type": "bind", "Source": "/var/www/html",
                 "Destination": "/var/www/html", "RW": True},
                {"Type": "bind",
                 "Source": "/var/lib/http-ztp-container/control-auth",
                 "Destination": "/etc/http-ztp", "RW": False},
                {"Type": "bind",
                 "Source": "/var/lib/http-ztp-container/monitor-auth",
                 "Destination": "/var/lib/http-ztp-monitor-auth", "RW": True},
            ],
            "State": {"Running": True, "Restarting": False, "Paused": False,
                      "Status": "running", "Pid": 33, "Dead": False},
        }
        image = [{
            "Id": image_id, "Os": "linux", "Architecture": "amd64",
            "Config": {
                "Labels": {
                    "com.nvidia.http-ztp.image": "true",
                    "com.nvidia.http-ztp.image-contract": "3",
                    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                },
            },
        }]
        docker_events = []
        run_returncode = 0
        terminal_events = []

        @contextmanager
        def validated_terminal():
            terminal_events.append("open")
            try:
                yield 83
            finally:
                terminal_events.append("close")

        def runner(command, **kwargs):
            docker_events.append((list(command), dict(kwargs)))
            if command[:3] == ["docker", "container", "inspect"]:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps([owned]), stderr="",
                )
            if command[:3] == ["docker", "image", "inspect"]:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(image), stderr="",
                )
            if command[:2] == ["docker", "run"]:
                return SimpleNamespace(returncode=run_returncode)
            self.fail(f"unexpected Docker command: {command}")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_load_control_auth", return_value=AuthModule,
        ), mock.patch.object(
            hostlock, "_validated_rotation_terminal",
            validated_terminal, create=True,
        ):
            rotated = hostlock.rotate_control_auth(
                "nvis", lock_path=Path(temporary) / ".deployment.lock",
                runner=runner,
            )
        self.assertEqual(
            {"valid": True, "factory_records_active": False}, rotated,
        )
        run_command, run_kwargs = next(
            item for item in docker_events if item[0][:2] == ["docker", "run"]
        )
        self.assertIn("--network", run_command)
        self.assertEqual("none", run_command[run_command.index("--network") + 1])
        self.assertIn("--read-only", run_command)
        self.assertEqual("0:33", run_command[run_command.index("--user") + 1])
        self.assertIn("--cap-drop", run_command)
        self.assertEqual("ALL", run_command[run_command.index("--cap-drop") + 1])
        self.assertNotIn("--cap-add", run_command)
        self.assertIn("--security-opt", run_command)
        self.assertIn("no-new-privileges:true", run_command)
        self.assertIn("--log-driver", run_command)
        self.assertEqual("none", run_command[run_command.index("--log-driver") + 1])
        self.assertIn(
            "type=bind,src=/var/lib/http-ztp-container/control-auth,"
            "dst=/etc/http-ztp",
            run_command,
        )
        self.assertNotIn("readonly", " ".join(run_command))
        self.assertEqual(image_id, run_command[-4])
        self.assertEqual(["rotate", "--user", "nvis"], run_command[-3:])
        for forbidden in ("nvidia", "cumulus", "password", "secret"):
            self.assertNotIn(forbidden, " ".join(run_command).casefold())
        self.assertNotIn("input", run_kwargs)
        self.assertNotIn("env", run_kwargs)
        self.assertNotIn("capture_output", run_kwargs)
        self.assertEqual(
            {
                "check": False,
                "stdin": 83,
                "stdout": 83,
                "stderr": 83,
                "close_fds": True,
            },
            run_kwargs,
        )
        self.assertEqual(["open", "close"], terminal_events)
        self.assertEqual(
            ["docker", "run", "--rm", "--interactive", "--tty"],
            run_command[:5],
        )
        self.assertEqual(2, sum(item[0] == "validate" for item in events))
        self.assertEqual(2, sum(item[0] == "status" for item in events))

        events.clear()
        docker_events.clear()
        run_returncode = 17
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_load_control_auth", return_value=AuthModule,
        ), mock.patch.object(
            hostlock, "_validated_rotation_terminal",
            validated_terminal, create=True,
        ), self.assertRaises(hostlock.HostLockError) as raised:
            hostlock.rotate_control_auth(
                "nvis", lock_path=Path(temporary) / ".deployment.lock",
                runner=runner,
            )
        failure = str(raised.exception).casefold()
        self.assertIn("control_auth.valid=true", failure)
        self.assertIn("do not blindly retry", failure)
        self.assertNotIn("old password", failure)
        self.assertNotIn("new password", failure)
        self.assertEqual(2, sum(item[0] == "validate" for item in events))
        self.assertEqual(2, sum(item[0] == "status" for item in events))

        events.clear()
        docker_events.clear()
        run_returncode = None
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_load_control_auth", return_value=AuthModule,
        ), mock.patch.object(
            hostlock, "_validated_rotation_terminal",
            validated_terminal, create=True,
        ), self.assertRaises(hostlock.HostLockError) as malformed:
            hostlock.rotate_control_auth(
                "nvis", lock_path=Path(temporary) / ".deployment.lock",
                runner=runner,
            )
        self.assertIn(
            "control_auth.valid=true", str(malformed.exception).casefold(),
        )
        self.assertEqual(2, sum(item[0] == "validate" for item in events))
        self.assertEqual(2, sum(item[0] == "status" for item in events))

        validation_calls = 0

        class InvalidAfterOneShot(AuthModule):
            @staticmethod
            def validate_auth_file(path, *, required_uid, required_gid):
                nonlocal validation_calls
                validation_calls += 1
                if validation_calls > 1:
                    raise RuntimeError("invalid post-state fixture")
                return object()

        run_returncode = 0
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            hostlock, "_load_control_auth", return_value=InvalidAfterOneShot,
        ), mock.patch.object(
            hostlock, "_validated_rotation_terminal",
            validated_terminal, create=True,
        ), self.assertRaisesRegex(
            hostlock.HostLockError, "post-validation|indeterminate",
        ):
            hostlock.rotate_control_auth(
                "nvis", lock_path=Path(temporary) / ".deployment.lock",
                runner=runner,
            )
        self.assertEqual(2, validation_calls)
        self.assertEqual(["open", "close"] * 4, terminal_events)

    @staticmethod
    def _control_auth_loader_fixture(value: str = "trusted") -> str:
        return f'''from dataclasses import dataclass

@dataclass(frozen=True)
class LoaderMarker:
    value: str

MARKER = LoaderMarker({value!r})

def ensure_auth_file(*_args, **_kwargs):
    return False

def validate_auth_file(*_args, **_kwargs):
    return object()

def status_auth_file(*_args, **_kwargs):
    return {{"valid": True, "factory_records_active": False}}

def rotate_auth_file(*_args, **_kwargs):
    return {{"valid": True, "factory_records_active": False}}

def provision_monitor_authority(*_args, **_kwargs):
    return None

def attest_monitor_authority(*_args, **_kwargs):
    return None

def recover_monitor_authority(*_args, **_kwargs):
    return {{
        "cleanup": "complete",
        "recovery_committed": True,
        "restart_allowed": True,
    }}

def monitor_authority_recovery_decision(_payload, _diagnostics):
    return "restart-allowed:complete"
'''

    def test_host_auth_loader_uses_unique_held_modules_and_writes_no_pyc(
        self,
    ) -> None:
        hostlock = load_script("hostlock.py")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve() / "tools"
            parent.mkdir(mode=0o755)
            parent.chmod(0o755)
            helper = parent / "control-auth.py"
            helper.write_text(
                self._control_auth_loader_fixture(), encoding="utf-8",
            )
            helper.chmod(0o755)
            with mock.patch.object(sys, "dont_write_bytecode", False):
                first = hostlock._load_control_auth(helper)
                second = hostlock._load_control_auth(helper)

            self.assertEqual("trusted", first.MARKER.value)
            self.assertEqual("trusted", second.MARKER.value)
            self.assertNotEqual(first.__name__, second.__name__)
            self.assertNotIn(first.__name__, sys.modules)
            self.assertNotIn(second.__name__, sys.modules)
            self.assertFalse((parent / "__pycache__").exists())

        loader_source = (DOCKER_ROOT / "hostlock.py").read_text(
            encoding="utf-8",
        ).split("def _source_identity", 1)[1].split(
            "\ndef _control_auth_status", 1,
        )[0]
        for required in ("O_NOFOLLOW", "O_NONBLOCK", "os.fstat", "os.read", "compile("):
            self.assertIn(required, loader_source)
        self.assertNotIn("spec_from_file_location", loader_source)

    def test_host_auth_loader_rejects_unsafe_source_before_returning(self) -> None:
        hostlock = load_script("hostlock.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()

            def directory(name: str) -> Path:
                target = root / name
                target.mkdir(mode=0o755)
                target.chmod(0o755)
                return target

            cases = []

            symlink_parent = directory("symlink")
            symlink_target = root / "symlink-target.py"
            symlink_target.write_text(
                self._control_auth_loader_fixture(), encoding="utf-8",
            )
            symlink_target.chmod(0o755)
            (symlink_parent / "control-auth.py").symlink_to(symlink_target)
            cases.append(symlink_parent / "control-auth.py")

            real_parent = directory("real-parent")
            real_helper = real_parent / "control-auth.py"
            real_helper.write_text(
                self._control_auth_loader_fixture(), encoding="utf-8",
            )
            real_helper.chmod(0o755)
            parent_alias = root / "parent-alias"
            parent_alias.symlink_to(real_parent, target_is_directory=True)
            cases.append(parent_alias / "control-auth.py")

            hardlink_parent = directory("hardlink")
            hardlink_source = root / "hardlink-source.py"
            hardlink_source.write_text(
                self._control_auth_loader_fixture(), encoding="utf-8",
            )
            hardlink_source.chmod(0o755)
            os.link(hardlink_source, hardlink_parent / "control-auth.py")
            cases.append(hardlink_parent / "control-auth.py")

            fifo_parent = directory("fifo")
            os.mkfifo(fifo_parent / "control-auth.py", 0o644)
            cases.append(fifo_parent / "control-auth.py")

            large_parent = directory("large")
            large = large_parent / "control-auth.py"
            large.write_bytes(b"#" * (256 * 1024 + 1))
            large.chmod(0o755)
            cases.append(large)

            empty_parent = directory("empty")
            empty = empty_parent / "control-auth.py"
            empty.touch(mode=0o755)
            empty.chmod(0o755)
            cases.append(empty)

            encoding_parent = directory("encoding")
            encoding = encoding_parent / "control-auth.py"
            encoding.write_bytes(b"\xff\xfe\n")
            encoding.chmod(0o755)
            cases.append(encoding)

            declared_encoding_parent = directory("declared-encoding")
            declared_encoding = declared_encoding_parent / "control-auth.py"
            declared_encoding.write_bytes(
                b"# coding: latin-1\nVALUE = '\xe9'\n"
                + self._control_auth_loader_fixture().encode("utf-8")
            )
            declared_encoding.chmod(0o755)
            cases.append(declared_encoding)

            api_parent = directory("api")
            api = api_parent / "control-auth.py"
            api.write_text("VALUE = 'missing APIs'\n", encoding="utf-8")
            api.chmod(0o755)
            cases.append(api)

            execution_parent = directory("execution")
            execution = execution_parent / "control-auth.py"
            execution.write_text(
                self._control_auth_loader_fixture()
                + "\nraise RuntimeError('execution fixture')\n",
                encoding="utf-8",
            )
            execution.chmod(0o755)
            cases.append(execution)

            mode_parent = directory("mode")
            wrong_mode = mode_parent / "control-auth.py"
            wrong_mode.write_text(
                self._control_auth_loader_fixture(), encoding="utf-8",
            )
            wrong_mode.chmod(0o600)
            cases.append(wrong_mode)

            wrong_parent = directory("parent-mode")
            parent_mode_helper = wrong_parent / "control-auth.py"
            parent_mode_helper.write_text(
                self._control_auth_loader_fixture(), encoding="utf-8",
            )
            parent_mode_helper.chmod(0o755)
            wrong_parent.chmod(0o777)
            cases.append(parent_mode_helper)

            for candidate in cases:
                with self.subTest(candidate=candidate.parent.name), \
                        self.assertRaises(hostlock.HostLockError):
                    hostlock._load_control_auth(candidate)
            self.assertFalse(any(root.rglob("*.pyc")))

    def test_host_auth_loader_rejects_leaf_and_parent_rebinding(self) -> None:
        for mutation in ("leaf", "parent"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                hostlock = load_script("hostlock.py")
                root = Path(temporary).resolve()
                parent = root / "tools"
                parent.mkdir(mode=0o755)
                parent.chmod(0o755)
                helper = parent / "control-auth.py"
                helper.write_text(
                    self._control_auth_loader_fixture(), encoding="utf-8",
                )
                helper.chmod(0o755)
                executed = root / "replacement-executed"
                replacement_source = (
                    self._control_auth_loader_fixture("replacement")
                    + f"\nfrom pathlib import Path\nPath({str(executed)!r}).write_text('bad')\n"
                )
                real_read = os.read
                swapped = False

                def swap_after_first_read(descriptor, size):
                    nonlocal swapped
                    chunk = real_read(descriptor, size)
                    if not swapped:
                        swapped = True
                        if mutation == "leaf":
                            replacement = parent / "replacement.py"
                            replacement.write_text(replacement_source, encoding="utf-8")
                            replacement.chmod(0o755)
                            os.replace(replacement, helper)
                        else:
                            detached = root / "detached-tools"
                            parent.rename(detached)
                            parent.mkdir(mode=0o755)
                            parent.chmod(0o755)
                            helper.write_text(replacement_source, encoding="utf-8")
                            helper.chmod(0o755)
                    return chunk

                with mock.patch.object(
                    hostlock.os, "read", side_effect=swap_after_first_read,
                ), self.assertRaisesRegex(
                    hostlock.HostLockError, "changed|binding|identity",
                ):
                    hostlock._load_control_auth(helper)
                self.assertTrue(swapped)
                self.assertFalse(executed.exists())
                self.assertFalse(any(root.rglob("*.pyc")))

    def test_owned_container_capture_releases_lock_before_caller_uses_id(self) -> None:
        hostlock = load_script("hostlock.py")
        events = []
        record = [{
            "Id": "b" * 64,
            "Image": "sha256:" + "1" * 64,
            "Name": "/http-ztp",
            "Config": {
                "Labels": {
                    "com.nvidia.http-ztp.managed": "true",
                    "com.nvidia.http-ztp.http-root": "/var/www/html",
                    "com.nvidia.http-ztp.image": "true",
                    "com.nvidia.http-ztp.image-contract": "3",
                    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                },
                "Env": ["HTTP_ZTP_PROJECT=fixture-site"],
            },
            "Mounts": [
                {
                    "Type": "bind", "Source": "/var/www/html",
                    "Destination": "/var/www/html", "RW": True,
                },
                {
                    "Type": "bind",
                    "Source": "/var/lib/http-ztp-container/control-auth",
                    "Destination": "/etc/http-ztp", "RW": False,
                },
                {
                    "Type": "bind",
                    "Source": "/var/lib/http-ztp-container/monitor-auth",
                    "Destination": "/var/lib/http-ztp-monitor-auth",
                    "RW": True,
                },
            ],
            "State": {
                "Running": True, "Restarting": False, "Paused": False,
                "Status": "running", "Pid": 321, "Dead": False,
            },
        }]

        @contextmanager
        def held(_path, _wait):
            events.append("lock-enter")
            try:
                yield 7
            finally:
                events.append("lock-release")

        def inspected(*_args, **_kwargs):
            events.append("inspect")
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(record), stderr="",
            )

        with mock.patch.object(hostlock, "safe_lock", side_effect=held):
            identifier = hostlock.capture_owned_container_id(
                lock_path=Path("/unused/.deployment.lock"),
                wait_seconds=1,
                require_running=True,
                expected_environment={"HTTP_ZTP_PROJECT": "fixture-site"},
                runner=inspected,
            )
        events.append("caller-exec")
        self.assertEqual("b" * 64, identifier)
        self.assertEqual(
            ["lock-enter", "inspect", "lock-release", "caller-exec"], events,
        )

    def test_owned_container_down_happy_path_and_id_change_are_fail_closed(self) -> None:
        hostlock = load_script("hostlock.py")

        def record(identifier, *, running):
            return [{
                "Id": identifier,
                "Image": "sha256:" + "1" * 64,
                "Name": "/http-ztp",
                "Config": {"Labels": {
                    "com.nvidia.http-ztp.managed": "true",
                    "com.nvidia.http-ztp.http-root": "/var/www/html",
                    "com.nvidia.http-ztp.image": "true",
                    "com.nvidia.http-ztp.image-contract": "3",
                    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                }},
                "Mounts": [
                    {
                        "Type": "bind", "Source": "/var/www/html",
                        "Destination": "/var/www/html", "RW": True,
                    },
                    {
                        "Type": "bind",
                        "Source": "/var/lib/http-ztp-container/control-auth",
                        "Destination": "/etc/http-ztp", "RW": False,
                    },
                    {
                        "Type": "bind",
                        "Source": "/var/lib/http-ztp-container/monitor-auth",
                        "Destination": "/var/lib/http-ztp-monitor-auth",
                        "RW": True,
                    },
                ],
                "State": {
                    "Running": running, "Restarting": False, "Paused": False,
                    "Status": "running" if running else "exited",
                    "Pid": 123 if running else 0, "Dead": False,
                },
            }]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "activation.json"
            marker.write_text("active\n", encoding="ascii")
            identifier = "c" * 64
            responses = iter((
                SimpleNamespace(
                    returncode=0, stdout=json.dumps(record(identifier, running=True)),
                    stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(
                    returncode=0, stdout=json.dumps(record(identifier, running=False)),
                    stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ))
            runner = mock.Mock(side_effect=lambda *_args, **_kwargs: next(responses))
            with mock.patch.object(hostlock, "ACTIVATION_MARKER", marker):
                self.assertEqual(0, hostlock.run_owned_container_action(
                    "remove-clear", lock_path=root / ".deployment.lock",
                    activation_marker=marker, runner=runner,
                ))
            self.assertFalse(marker.exists())
            self.assertEqual(
                [
                    ["docker", "container", "inspect", "http-ztp"],
                    ["docker", "stop", "--time", "30", identifier],
                    ["docker", "container", "inspect", identifier],
                    ["docker", "rm", identifier],
                ],
                [call.args[0] for call in runner.call_args_list],
            )

            marker.write_text("active\n", encoding="ascii")
            changed = "d" * 64
            responses = iter((
                SimpleNamespace(
                    returncode=0, stdout=json.dumps(record(identifier, running=True)),
                    stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(
                    returncode=0, stdout=json.dumps(record(changed, running=False)),
                    stderr="",
                ),
            ))
            runner = mock.Mock(side_effect=lambda *_args, **_kwargs: next(responses))
            with mock.patch.object(hostlock, "ACTIVATION_MARKER", marker), \
                    self.assertRaisesRegex(
                        hostlock.HostLockError, "immutable identity",
                    ):
                hostlock.run_owned_container_action(
                    "remove-clear", lock_path=root / ".deployment.lock",
                    activation_marker=marker, runner=runner,
                )
            self.assertTrue(marker.exists())
            self.assertEqual(3, runner.call_count)

            wrong_bind = record(identifier, running=False)
            wrong_bind[0]["Mounts"][0]["Source"] = "/srv/foreign-http"
            runner = mock.Mock(return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(wrong_bind), stderr="",
            ))
            with mock.patch.object(hostlock, "ACTIVATION_MARKER", marker), \
                    self.assertRaisesRegex(hostlock.HostLockError, "exact.*RW bind"):
                hostlock.run_owned_container_action(
                    "remove-clear", lock_path=root / ".deployment.lock",
                    activation_marker=marker, runner=runner,
                )
            self.assertTrue(marker.exists())
            self.assertEqual(1, runner.call_count)

    def test_local_rootful_daemon_contract_rejects_remote_and_rootless(self) -> None:
        hostlock = load_script("hostlock.py")
        socket_status = SimpleNamespace(
            st_mode=hostlock.stat.S_IFSOCK | 0o660, st_uid=0,
        )

        def local_runner(command, **_kwargs):
            if command == ["docker", "context", "show"]:
                return SimpleNamespace(returncode=0, stdout="default\n", stderr="")
            if command == ["docker", "context", "inspect", "default"]:
                payload = [{"Endpoints": {"docker": {
                    "Host": "unix:///var/run/docker.sock",
                    "SkipTLSVerify": False,
                }}}]
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(payload), stderr="",
                )
            if command == ["docker", "info", "--format", "{{json .}}"]:
                payload = {
                    "OSType": "linux", "DockerRootDir": "/var/lib/docker",
                    "SecurityOptions": ["name=seccomp,profile=builtin"],
                }
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(payload), stderr="",
                )
            self.fail(f"unexpected Docker command: {command}")

        with mock.patch.object(hostlock.os, "lstat", return_value=socket_status):
            hostlock.validate_local_rootful_docker(
                runner=local_runner, environ={},
            )

            for environment in (
                {"DOCKER_HOST": "ssh://operator@docker.example.test"},
                {"DOCKER_CONTEXT": "production"},
                {"DOCKER_TLS_VERIFY": "1"},
            ):
                with self.subTest(environment=environment), self.assertRaisesRegex(
                    hostlock.HostLockError, "local rootful|remote",
                ):
                    hostlock.validate_local_rootful_docker(
                        runner=local_runner, environ=environment,
                    )

            def rootless_runner(command, **kwargs):
                result = local_runner(command, **kwargs)
                if command == ["docker", "info", "--format", "{{json .}}"]:
                    payload = json.loads(result.stdout)
                    payload["SecurityOptions"].append("name=rootless")
                    result.stdout = json.dumps(payload)
                return result

            with self.assertRaisesRegex(hostlock.HostLockError, "rootless"):
                hostlock.validate_local_rootful_docker(
                    runner=rootless_runner, environ={},
                )

    def test_preloaded_image_verification_is_locked_immutable_and_offline(self) -> None:
        hostlock = load_script("hostlock.py")
        identifier = "sha256:" + "a" * 64

        def image_record():
            return [{
                "Id": identifier,
                "Os": "linux",
                "Architecture": "arm64",
                "Config": {
                    "Labels": {
                        "com.nvidia.http-ztp.image": "true",
                        "com.nvidia.http-ztp.image-flavor": "generic",
                        "com.nvidia.http-ztp.image-contract": "3",
                        "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                    },
                    "Entrypoint": ["/opt/http-ztp/entrypoint.py"],
                    "Cmd": ["serve"],
                    "User": "root",
                    "WorkingDir": "/var/www/html",
                    "Env": list(EXPECTED_IMAGE_ENVIRONMENT),
                    "Healthcheck": {
                        "Test": ["CMD", "/opt/http-ztp/healthcheck.py"],
                        "Interval": 30_000_000_000,
                        "Timeout": 15_000_000_000,
                        "StartPeriod": 30_000_000_000,
                        "Retries": 3,
                    },
                },
            }]

        events = []

        def runner(command, **kwargs):
            events.append((list(command), dict(kwargs)))
            if command[:3] == ["docker", "image", "inspect"]:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(image_record()), stderr="",
                )
            if command[:2] == ["docker", "create"]:
                return SimpleNamespace(
                    returncode=0, stdout="d" * 64 + "\n", stderr="",
                )
            if command[:2] == ["docker", "start"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            if command[:2] == ["docker", "wait"]:
                return SimpleNamespace(returncode=0, stdout="0\n", stderr="")
            if command[:2] == ["docker", "logs"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        '{"files":123,"os":"ubuntu","verified":true,'
                        '"version":"24.04"}\n'
                    ),
                    stderr="",
                )
            if command[:3] == ["docker", "rm", "--force"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            self.fail(f"unexpected Docker command: {command}")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(
                identifier,
                hostlock.verify_preloaded_image(
                    identifier, "arm64", lock_path=root / ".deployment.lock",
                    wait_seconds=1, runner=runner,
                ),
            )

        self.assertEqual(6, len(events))
        self.assertEqual(
            ["docker", "image", "inspect", identifier], events[0][0],
        )
        probe = events[1][0]
        self.assertEqual(["docker", "create"], probe[:2])
        self.assertEqual("none", probe[probe.index("--network") + 1])
        self.assertIn("--read-only", probe)
        self.assertIn("--no-healthcheck", probe)
        for option, expected in (
            ("--memory", "256m"),
            ("--memory-swap", "256m"),
            ("--pids-limit", "128"),
            ("--cpus", "1"),
            ("--log-driver", "local"),
        ):
            with self.subTest(probe_option=option):
                self.assertEqual(expected, probe[probe.index(option) + 1])
        self.assertEqual(
            ["max-size=64k", "max-file=1"],
            [probe[index + 1] for index, item in enumerate(probe) if item == "--log-opt"],
        )
        self.assertEqual("ALL", probe[probe.index("--cap-drop") + 1])
        self.assertIn("no-new-privileges:true", probe)
        self.assertIn(
            "type=bind,src=/var/www/html,dst=/var/www/html,readonly", probe,
        )
        self.assertEqual(
            "/opt/http-ztp/activate.py",
            probe[probe.index("--entrypoint") + 1],
        )
        self.assertIn(identifier, probe)
        self.assertIn("verify-deployment-image", probe)
        self.assertIn("/opt/http-ztp/image-source.sha256", probe)
        self.assertNotIn("http-ztp:ubuntu-24.04", probe)
        self.assertEqual(
            ["docker", "start", "d" * 64], events[2][0],
        )
        self.assertNotIn("--attach", events[2][0])
        self.assertEqual(30, events[2][1]["timeout"])
        self.assertEqual(
            ["docker", "wait", "d" * 64], events[3][0],
        )
        self.assertEqual(600, events[3][1]["timeout"])
        self.assertEqual(
            ["docker", "logs", "--tail", "1", "d" * 64], events[4][0],
        )
        self.assertEqual(30, events[4][1]["timeout"])
        self.assertEqual(
            ["docker", "rm", "--force", "d" * 64], events[5][0],
        )

    def test_preloaded_image_rejects_bad_id_platform_config_and_source(self) -> None:
        hostlock = load_script("hostlock.py")
        identifier = "sha256:" + "b" * 64

        def valid_record():
            return {
                "Id": identifier, "Os": "linux", "Architecture": "amd64",
                "Config": {
                    "Labels": {
                        "com.nvidia.http-ztp.image": "true",
                        "com.nvidia.http-ztp.image-flavor": "generic",
                        "com.nvidia.http-ztp.image-contract": "3",
                        "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                    },
                    "Entrypoint": ["/opt/http-ztp/entrypoint.py"],
                    "Cmd": ["serve"], "User": "root",
                    "WorkingDir": "/var/www/html",
                    "Env": list(EXPECTED_IMAGE_ENVIRONMENT),
                    "Healthcheck": {
                        "Test": ["CMD", "/opt/http-ztp/healthcheck.py"],
                        "Interval": 30_000_000_000,
                        "Timeout": 15_000_000_000,
                        "StartPeriod": 30_000_000_000, "Retries": 3,
                    },
                },
            }

        mutations = {
            "immutable identity": lambda item: item.update(Id="sha256:" + "c" * 64),
            "Linux": lambda item: item.update(Os="windows"),
            "architecture": lambda item: item.update(Architecture="arm64"),
            "image contract label": lambda item: item["Config"]["Labels"].update(
                {"com.nvidia.http-ztp.image-contract": "0"}
            ),
            "image flavor": lambda item: item["Config"]["Labels"].update(
                {"com.nvidia.http-ztp.image-flavor": "project"}
            ),
            "forbidden project labels": lambda item: item["Config"]["Labels"].update(
                {next(iter(PROJECT_BOOTSTRAP_LABELS.values())): "d" * 64}
            ),
            "base OS label": lambda item: item["Config"]["Labels"].update(
                {"com.nvidia.http-ztp.base-os": "ubuntu-22.04"}
            ),
            "entrypoint": lambda item: item["Config"].update(Entrypoint=["/bin/sh"]),
            "command": lambda item: item["Config"].update(Cmd=["sleep", "infinity"]),
            "root user": lambda item: item["Config"].update(User="1000"),
            "working directory": lambda item: item["Config"].update(WorkingDir="/tmp"),
            "environment": lambda item: item["Config"].update(Env=[]),
            "image environment": lambda item: item["Config"].update(
                Env=list(EXPECTED_IMAGE_ENVIRONMENT) + ["PYTHONDONTWRITEBYTECODE=0"]
            ),
            "environment injection": lambda item: item["Config"].update(
                Env=list(EXPECTED_IMAGE_ENVIRONMENT) + ["LD_PRELOAD=/evil.so"]
            ),
            "environment PATH": lambda item: item["Config"].update(
                Env=["PATH=/tmp", "PYTHONDONTWRITEBYTECODE=1"]
            ),
            "environment order": lambda item: item["Config"].update(
                Env=list(reversed(EXPECTED_IMAGE_ENVIRONMENT))
            ),
            "environment value": lambda item: item["Config"].update(
                Env=[None, "PYTHONDONTWRITEBYTECODE=1"]
            ),
            "healthcheck": lambda item: item["Config"]["Healthcheck"].update(Retries=1),
        }
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / ".deployment.lock"
            for message, mutate in mutations.items():
                with self.subTest(message=message):
                    record = valid_record()
                    mutate(record)
                    runner = mock.Mock(return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps([record]), stderr="",
                    ))
                    with self.assertRaisesRegex(hostlock.HostLockError, message):
                        hostlock.verify_preloaded_image(
                            identifier, "amd64", lock_path=lock_path,
                            wait_seconds=0, runner=runner,
                        )
                    self.assertEqual(1, runner.call_count)

            runner = mock.Mock()
            with self.assertRaisesRegex(hostlock.HostLockError, "immutable image ID"):
                hostlock.verify_preloaded_image(
                    "http-ztp:ubuntu-24.04", "amd64", lock_path=lock_path,
                    wait_seconds=0, runner=runner,
                )
            runner.assert_not_called()

            responses = iter((
                SimpleNamespace(
                    returncode=0, stdout=json.dumps([valid_record()]), stderr="",
                ),
                SimpleNamespace(
                    returncode=0, stdout="e" * 64 + "\n", stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(returncode=0, stdout="2\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="", stderr="source manifest drift"),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ))
            runner = mock.Mock(side_effect=lambda *_args, **_kwargs: next(responses))
            with self.assertRaisesRegex(
                hostlock.HostLockError, "preloaded image source verification.*drift",
            ):
                hostlock.verify_preloaded_image(
                    identifier, "amd64", lock_path=lock_path,
                    wait_seconds=0, runner=runner,
                )
            self.assertEqual(6, runner.call_count)

            responses = iter((
                SimpleNamespace(
                    returncode=0, stdout=json.dumps([valid_record()]), stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="f" * 64 + "\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
                SimpleNamespace(
                    returncode=0,
                    stdout='{"files":0,"verified":false}\n', stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ))
            runner = mock.Mock(side_effect=lambda *_args, **_kwargs: next(responses))
            with self.assertRaisesRegex(
                hostlock.HostLockError, "verification result is invalid",
            ):
                hostlock.verify_preloaded_image(
                    identifier, "amd64", lock_path=lock_path,
                    wait_seconds=0, runner=runner,
                )
            self.assertEqual(
                ["docker", "rm", "--force", "f" * 64],
                runner.call_args_list[-1].args[0],
            )

    def test_preloaded_probe_bounds_output_and_cleans_every_runtime_failure(self) -> None:
        hostlock = load_script("hostlock.py")
        probe_id = "6" * 64

        def run_case(failure):
            events = []

            def runner(command, **kwargs):
                events.append((list(command), dict(kwargs)))
                if command[:2] == ["docker", "create"]:
                    return SimpleNamespace(returncode=0, stdout=probe_id + "\n", stderr="")
                if command[:2] == ["docker", "start"]:
                    if failure == "start-timeout":
                        raise subprocess.TimeoutExpired(command, 30)
                    if failure == "start":
                        return SimpleNamespace(returncode=2, stdout="", stderr="start failed")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "wait"]:
                    if failure == "wait-timeout":
                        raise subprocess.TimeoutExpired(command, 17)
                    if failure == "wait-command":
                        return SimpleNamespace(returncode=2, stdout="", stderr="wait failed")
                    if failure == "invalid-exit-status":
                        return SimpleNamespace(returncode=0, stdout="not-a-status\n", stderr="")
                    status = "9\n" if failure == "container-exit" else "0\n"
                    return SimpleNamespace(returncode=0, stdout=status, stderr="")
                if command[:2] == ["docker", "logs"]:
                    if failure == "logs-timeout":
                        raise subprocess.TimeoutExpired(command, 30)
                    if failure == "logs-command":
                        return SimpleNamespace(returncode=2, stdout="", stderr="logs failed")
                    output = "x" * (hostlock.PRELOADED_PROBE_OUTPUT_LIMIT + 1)
                    if failure != "oversized-output":
                        output = '{"verified":true}\n'
                    stderr = "unexpected warning" if failure == "unexpected-stderr" else ""
                    return SimpleNamespace(returncode=0, stdout=output, stderr=stderr)
                if command[:3] == ["docker", "rm", "--force"]:
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected Docker command: {command}")

            with self.assertRaises(hostlock.HostLockError):
                hostlock._run_preloaded_probe(
                    runner, ["docker", "create", "immutable-image-id"],
                    label="contract probe", run_timeout=17,
                )
            self.assertEqual(
                ["docker", "rm", "--force", probe_id], events[-1][0],
            )
            self.assertEqual(
                1,
                sum(command[:3] == ["docker", "rm", "--force"] for command, _ in events),
            )

        for failure in (
            "start", "start-timeout", "wait-command", "wait-timeout",
            "invalid-exit-status", "container-exit", "logs-command",
            "logs-timeout", "oversized-output", "unexpected-stderr",
        ):
            with self.subTest(failure=failure):
                run_case(failure)

        events = []

        def invalid_identity_runner(command, **kwargs):
            events.append((list(command), dict(kwargs)))
            if command[:2] == ["docker", "create"]:
                return SimpleNamespace(returncode=0, stdout="invalid-id\n", stderr="")
            if command[:3] == ["docker", "rm", "--force"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            self.fail(f"unexpected Docker command: {command}")

        with mock.patch.object(hostlock.secrets, "token_hex", return_value="a" * 32), \
                self.assertRaisesRegex(hostlock.HostLockError, "identity"):
            hostlock._run_preloaded_probe(
                invalid_identity_runner,
                ["docker", "create", "immutable-image-id"],
                label="contract probe", run_timeout=17,
            )
        expected_name = "http-ztp-preloaded-probe-" + "a" * 32
        self.assertEqual(expected_name, events[0][0][events[0][0].index("--name") + 1])
        self.assertEqual(
            ["docker", "rm", "--force", expected_name], events[-1][0],
        )

        for create_failure, expected_message in (
            ("timeout", "could not be created"),
            ("nonzero", "creation failed"),
        ):
            with self.subTest(create_failure=create_failure):
                events = []

                def failed_create_runner(command, **kwargs):
                    events.append((list(command), dict(kwargs)))
                    if command[:2] == ["docker", "create"]:
                        if create_failure == "timeout":
                            raise subprocess.TimeoutExpired(command, 30)
                        return SimpleNamespace(
                            returncode=2, stdout="", stderr="create failed",
                        )
                    if command[:3] == ["docker", "rm", "--force"]:
                        return SimpleNamespace(returncode=0, stdout="", stderr="")
                    self.fail(f"unexpected Docker command: {command}")

                with mock.patch.object(
                    hostlock.secrets, "token_hex", return_value="b" * 32,
                ), self.assertRaisesRegex(
                    hostlock.HostLockError, expected_message,
                ):
                    hostlock._run_preloaded_probe(
                        failed_create_runner,
                        ["docker", "create", "immutable-image-id"],
                        label="contract probe", run_timeout=17,
                    )
                expected_name = "http-ztp-preloaded-probe-" + "b" * 32
                self.assertEqual(
                    expected_name,
                    events[0][0][events[0][0].index("--name") + 1],
                )
                self.assertEqual(
                    ["docker", "rm", "--force", expected_name], events[-1][0],
                )
                self.assertEqual(
                    1,
                    sum(
                        command[:3] == ["docker", "rm", "--force"]
                        for command, _kwargs in events
                    ),
                )

    def test_preloaded_flavor_gate_separates_generic_and_project_images(self) -> None:
        hostlock = load_script("hostlock.py")
        identifier = "sha256:" + "9" * 64

        def record(labels):
            return [{
                "Id": identifier, "Os": "linux", "Architecture": "amd64",
                "Config": {
                    "Labels": labels,
                    "Entrypoint": ["/opt/http-ztp/entrypoint.py"],
                    "Cmd": ["serve"], "User": "root",
                    "WorkingDir": "/var/www/html",
                    "Env": list(EXPECTED_IMAGE_ENVIRONMENT),
                    "Healthcheck": {
                        "Test": ["CMD", "/opt/http-ztp/healthcheck.py"],
                        "Interval": 30_000_000_000,
                        "Timeout": 15_000_000_000,
                        "StartPeriod": 30_000_000_000,
                        "Retries": 3,
                    },
                },
            }]

        common = {
            "com.nvidia.http-ztp.image": "true",
            "com.nvidia.http-ztp.image-contract": "3",
            "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
        }

        def verify(labels, *, flavor, project=None, upgrade_policy=None):
            replies = [
                SimpleNamespace(
                    returncode=0, stdout=json.dumps(record(labels)), stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="7" * 64 + "\n", stderr=""),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
                SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
                SimpleNamespace(
                    returncode=0,
                    stdout=(
                        '{"files":123,"os":"ubuntu","verified":true,'
                        '"version":"24.04"}\n'
                    ),
                    stderr="",
                ),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ]
            if flavor == "project":
                replies.extend((
                    SimpleNamespace(
                        returncode=0, stdout="8" * 64 + "\n", stderr="",
                    ),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                    SimpleNamespace(returncode=0, stdout="0\n", stderr=""),
                    SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps({
                            "bootstrap_tools": {
                                name: labels.get(label)
                                for name, label in PROJECT_BOOTSTRAP_LABELS.items()
                            },
                            "image_contract": "3",
                            "project": project,
                            "shared_archive_sha256": labels.get(
                                "com.nvidia.http-ztp.shared-artifacts-sha256"
                            ),
                            "source_manifest_sha256": labels.get(
                                "com.nvidia.http-ztp.source-manifest-sha256"
                            ),
                            "upload_archive_sha256": labels.get(
                                "com.nvidia.http-ztp.upload-sha256"
                            ),
                            "upgrade_policy": labels.get(
                                PROJECT_UPGRADE_POLICY_LABEL
                            ),
                            "verified": True,
                        }) + "\n",
                        stderr="",
                    ),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                ))
            replies = iter(replies)
            runner = mock.Mock(side_effect=lambda *_args, **_kwargs: next(replies))
            with tempfile.TemporaryDirectory() as directory:
                result = hostlock.verify_preloaded_image(
                    identifier, "amd64",
                    expected_flavor=flavor,
                    expected_project=project,
                    expected_upgrade_policy=upgrade_policy,
                    lock_path=Path(directory) / ".deployment.lock",
                    wait_seconds=0,
                    runner=runner,
                )
            self.assertEqual(identifier, result)

        verify({**common, "com.nvidia.http-ztp.image-flavor": "generic"},
               flavor="generic")
        project_labels = {
            **common,
            "com.nvidia.http-ztp.image-flavor": "project",
            "com.nvidia.http-ztp.project": "customer",
            "com.nvidia.http-ztp.upload-sha256": "a" * 64,
            "com.nvidia.http-ztp.source-manifest-sha256": "b" * 64,
            PROJECT_UPGRADE_POLICY_LABEL: "enabled",
            **{
                label: digest
                for (name, label), digest in zip(
                    PROJECT_BOOTSTRAP_LABELS.items(), ("c" * 64, "d" * 64, "e" * 64),
                )
            },
        }
        verify(
            project_labels, flavor="project", project="customer",
            upgrade_policy="enabled",
        )
        no_shared_no_upgrade_labels = dict(project_labels)
        no_shared_no_upgrade_labels[PROJECT_UPGRADE_POLICY_LABEL] = "disabled"
        verify(
            no_shared_no_upgrade_labels, flavor="project", project="customer",
            upgrade_policy="disabled",
        )

        for expected_flavor, expected_project in (
            ("generic", None), ("project", "other-project"),
        ):
            with self.subTest(
                expected_flavor=expected_flavor,
                expected_project=expected_project,
            ), tempfile.TemporaryDirectory() as directory:
                runner = mock.Mock(return_value=SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(record(project_labels)),
                    stderr="",
                ))
                with self.assertRaisesRegex(
                    hostlock.HostLockError, "flavor|project",
                ):
                    hostlock.verify_preloaded_image(
                        identifier, "amd64",
                        expected_flavor=expected_flavor,
                        expected_project=expected_project,
                        expected_upgrade_policy=(
                            "enabled" if expected_flavor == "project" else None
                        ),
                        lock_path=Path(directory) / ".deployment.lock",
                        wait_seconds=0,
                        runner=runner,
                    )
                self.assertEqual(1, runner.call_count)

    def test_project_preloaded_gate_verifies_embedded_payload_against_labels(self) -> None:
        hostlock = load_script("hostlock.py")
        identifier = "sha256:" + "8" * 64
        upload_sha = "a" * 64
        source_sha = "b" * 64
        shared_sha = "c" * 64
        bootstrap_hashes = {
            "package-project-image.py": "d" * 64,
            "deploy-upload-archive.py": "e" * 64,
            "deploy-shared-artifacts.py": "f" * 64,
        }
        record = [{
            "Id": identifier, "Os": "linux", "Architecture": "amd64",
            "Config": {
                "Labels": {
                    "com.nvidia.http-ztp.image": "true",
                    "com.nvidia.http-ztp.image-contract": "3",
                    "com.nvidia.http-ztp.base-os": "ubuntu-24.04",
                    "com.nvidia.http-ztp.image-flavor": "project",
                    "com.nvidia.http-ztp.project": "customer",
                    "com.nvidia.http-ztp.upload-sha256": upload_sha,
                    "com.nvidia.http-ztp.source-manifest-sha256": source_sha,
                    "com.nvidia.http-ztp.shared-artifacts-sha256": shared_sha,
                    PROJECT_UPGRADE_POLICY_LABEL: "disabled",
                    **{
                        PROJECT_BOOTSTRAP_LABELS[name]: digest
                        for name, digest in bootstrap_hashes.items()
                    },
                },
                "Entrypoint": ["/opt/http-ztp/entrypoint.py"],
                "Cmd": ["serve"], "User": "root",
                "WorkingDir": "/var/www/html",
                "Env": list(EXPECTED_IMAGE_ENVIRONMENT),
                "Healthcheck": {
                    "Test": ["CMD", "/opt/http-ztp/healthcheck.py"],
                    "Interval": 30_000_000_000,
                    "Timeout": 15_000_000_000,
                    "StartPeriod": 30_000_000_000,
                    "Retries": 3,
                },
            },
        }]

        def verify(payload):
            events = []

            def runner(command, **kwargs):
                events.append((list(command), dict(kwargs)))
                if command[:3] == ["docker", "image", "inspect"]:
                    return SimpleNamespace(
                        returncode=0, stdout=json.dumps(record), stderr="",
                    )
                if command[:2] == ["docker", "create"]:
                    identity = "7" * 64 if sum(
                        event[0][:2] == ["docker", "create"] for event in events
                    ) == 1 else "8" * 64
                    return SimpleNamespace(returncode=0, stdout=identity + "\n", stderr="")
                if command[:2] == ["docker", "start"]:
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                if command[:2] == ["docker", "wait"]:
                    return SimpleNamespace(returncode=0, stdout="0\n", stderr="")
                if command[:2] == ["docker", "logs"] and command[-1] == "7" * 64:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(
                            '{"files":123,"os":"ubuntu","verified":true,'
                            '"version":"24.04"}\n'
                        ),
                        stderr="",
                    )
                if command[:2] == ["docker", "logs"] and command[-1] == "8" * 64:
                    return SimpleNamespace(
                        returncode=0, stdout=json.dumps(payload) + "\n", stderr="",
                    )
                if command[:3] == ["docker", "rm", "--force"]:
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"unexpected Docker command: {command}")

            with tempfile.TemporaryDirectory() as directory:
                outcome = None
                error = None
                try:
                    outcome = hostlock.verify_preloaded_image(
                        identifier, "amd64", expected_flavor="project",
                        expected_project="customer",
                        expected_upgrade_policy="disabled",
                        lock_path=Path(directory) / ".deployment.lock",
                        wait_seconds=0, runner=runner,
                    )
                except hostlock.HostLockError as exc:
                    error = exc
            return outcome, error, events

        valid_payload = {
            "bootstrap_tools": bootstrap_hashes,
            "image_contract": "3",
            "project": "customer", "shared_archive_sha256": shared_sha,
            "source_manifest_sha256": source_sha,
            "upload_archive_sha256": upload_sha,
            "upgrade_policy": "disabled", "verified": True,
        }
        outcome, error, events = verify(valid_payload)
        self.assertIsNone(error)
        self.assertEqual(identifier, outcome)
        payload_probe = [
            command for command, _kwargs in events
            if command[:2] == ["docker", "create"]
            and any(str(item).endswith("/package-project-image.py") for item in command)
        ]
        self.assertEqual(1, len(payload_probe))
        self.assertIn("--verify-only", payload_probe[0])
        self.assertIn("--machine-readable", payload_probe[0])
        self.assertIn(
            "/opt/http-ztp/project-bootstrap/tools/package-project-image.py",
            payload_probe[0],
        )
        self.assertNotIn(
            "/opt/http-ztp/source-tree/tools/package-project-image.py",
            payload_probe[0],
        )
        self.assertIn("readonly", payload_probe[0][payload_probe[0].index("--mount") + 1])
        for option, expected in (
            ("--memory", "256m"), ("--memory-swap", "256m"),
            ("--pids-limit", "128"), ("--cpus", "1"),
            ("--log-driver", "local"),
        ):
            self.assertEqual(expected, payload_probe[0][payload_probe[0].index(option) + 1])

        invalid = dict(valid_payload, upload_archive_sha256="d" * 64)
        outcome, error, _events = verify(invalid)
        self.assertIsNone(outcome)
        self.assertRegex(str(error), "embedded project payload.*match")

        invalid = copy.deepcopy(valid_payload)
        invalid["bootstrap_tools"]["package-project-image.py"] = "0" * 64
        outcome, error, _events = verify(invalid)
        self.assertIsNone(outcome)
        self.assertRegex(str(error), "embedded project payload.*match")

        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            hostlock.HostLockError, "upgrade policy",
        ):
            hostlock.verify_preloaded_image(
                identifier, "amd64", expected_flavor="project",
                expected_project="customer", expected_upgrade_policy="enabled",
                lock_path=Path(directory) / ".deployment.lock",
                wait_seconds=0,
                runner=mock.Mock(return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(record), stderr="",
                )),
            )

    def test_safe_host_lock_rejects_symlink_and_orders_stop_clear_release(self) -> None:
        hostlock = load_script("hostlock.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.lock"
            target.write_text("do-not-touch\n", encoding="ascii")
            unsafe = root / ".deployment.lock"
            unsafe.symlink_to(target)
            runner = mock.Mock(return_value=SimpleNamespace(returncode=0))
            with self.assertRaisesRegex(hostlock.HostLockError, "regular|open"):
                hostlock.run_locked(
                    ("docker", "stop", "http-ztp"),
                    lock_path=unsafe,
                    wait_seconds=0,
                    runner=runner,
                )
            runner.assert_not_called()
            self.assertEqual("do-not-touch\n", target.read_text(encoding="ascii"))

            unsafe.unlink()
            marker = root / "activation.json"
            marker.write_text("active\n", encoding="ascii")
            events = []

            @contextmanager
            def held(_path, _wait):
                events.append("lock-enter")
                yield 9
                events.append("lock-release")

            def stopped(_command, check=False):
                self.assertFalse(check)
                events.append("docker-stop")
                self.assertTrue(marker.exists())
                return SimpleNamespace(returncode=0)

            with mock.patch.object(hostlock, "safe_lock", side_effect=held), \
                    mock.patch.object(
                        hostlock, "clear_activation_marker",
                        side_effect=lambda _path: (
                            events.append("clear-marker"), marker.unlink(),
                        ),
                    ):
                result = hostlock.run_locked(
                    ("docker", "stop", "http-ztp"),
                    lock_path=unsafe,
                    wait_seconds=10,
                    clear_activation=marker,
                    runner=stopped,
                )
            self.assertEqual(0, result)
            self.assertEqual(
                ["lock-enter", "docker-stop", "clear-marker", "lock-release"],
                events,
            )

    def test_hostlock_reports_busy_and_unsafe_operating_system_failures_by_type(self) -> None:
        hostlock = load_script("hostlock.py")
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / ".deployment.lock"
            lock.write_text("", encoding="ascii")
            with mock.patch.object(
                hostlock.fcntl, "flock", side_effect=BlockingIOError("busy"),
            ):
                with self.assertRaises(hostlock.HostLockBusy):
                    with hostlock.safe_lock(lock, 0):
                        self.fail("busy lock must never enter")
            with mock.patch.object(
                hostlock.fcntl, "flock", side_effect=OSError("ENOLCK"),
            ):
                with self.assertRaises(hostlock.HostLockUnsafe):
                    with hostlock.safe_lock(lock, 0):
                        self.fail("unsafe lock must never enter")

    def test_entrypoint_holds_trusted_image_lock_through_receipt_and_supervisor_exec(self) -> None:
        entrypoint = load_script("entrypoint.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []

        @contextmanager
        def held(path, wait_seconds):
            self.assertEqual(Path("/var/www/html/.deployment.lock"), path)
            self.assertGreater(wait_seconds, 0)
            events.append("lock-enter")
            try:
                yield 17
            finally:
                events.append("lock-release")

        with mock.patch.object(
            entrypoint.activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            entrypoint.hostlock, "safe_lock", side_effect=held,
        ), mock.patch.object(
            entrypoint.activate, "validate_python_runtime",
            side_effect=lambda: events.append("python-runtime"),
        ) as python_runtime, mock.patch.object(
            entrypoint.activate, "verify_control_auth_image_copies",
            side_effect=lambda: events.append("helper-attestation"),
        ) as attestation, mock.patch.object(
            entrypoint.activate, "require_monitor_authority",
            side_effect=lambda: events.append("monitor-authority"),
        ) as monitor_authority, mock.patch.object(
            entrypoint.activate, "require_control_auth",
            side_effect=lambda **_kwargs: events.append("control-auth"),
        ) as auth, mock.patch.object(
            entrypoint.activate, "validate_image_source_contract",
            side_effect=lambda _settings, **kwargs: events.append(
                "receipt-mutable" if kwargs.get("allow_mutable_drift") else "receipt-strict"
            ),
        ), mock.patch.object(
            entrypoint.activate, "restore_mutable_image_sources",
            side_effect=lambda _settings: events.append("restore-mutable"),
        ), mock.patch.object(
            entrypoint.activate, "ensure_runtime_directories",
            side_effect=lambda _settings: events.append("directories"),
        ), mock.patch.object(
            entrypoint.activate, "ensure_docker_deployment_owner",
            side_effect=lambda _settings: events.append("docker-owner"),
        ), mock.patch.object(
            entrypoint.activate, "clear_precommit_activation",
            side_effect=lambda _settings: events.append("clear-precommit"),
        ), mock.patch.object(
            entrypoint.activate, "clear_stale_worker_pid_files",
            side_effect=lambda _settings: events.append("pid-cleanup"),
        ), mock.patch.object(
            entrypoint, "initialize_resume_status",
            side_effect=lambda: events.append("starting-status"),
        ), mock.patch.object(
            entrypoint.os, "execv", side_effect=lambda *_args: events.append("exec"),
        ):
            self.assertEqual(0, entrypoint.main([]))
        python_runtime.assert_called_once_with()
        attestation.assert_called_once_with()
        monitor_authority.assert_called_once_with()
        auth.assert_called_once_with(emit_factory_warning=False)
        self.assertEqual(
            ["lock-enter", "python-runtime", "helper-attestation", "monitor-authority", "control-auth",
             "receipt-mutable", "restore-mutable",
             "receipt-strict",
             "directories", "docker-owner", "clear-precommit", "pid-cleanup",
             "starting-status", "exec", "lock-release"],
            events,
        )

    def test_entrypoint_persists_exact_docker_runtime_ownership(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state_root = root / "state"
            state_root.mkdir()
            http_root = root / "html"
            manifest = http_root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_bytes(b'{"schema_version":1,"files":[]}\n')
            image_manifest = root / "image-source-manifest.json"
            image_manifest.write_bytes(manifest.read_bytes())
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
                state_root=state_root,
            )
            with mock.patch.object(
                activate, "verify_compatible_live_source", return_value=[],
            ):
                activate.ensure_docker_deployment_owner(
                    settings, image_manifest=image_manifest,
                )
                activate.ensure_docker_deployment_owner(
                    settings, image_manifest=image_manifest,
                )
            path = state_root / "deployment-owner.json"
            self.assertEqual({
                "schema_version": 2, "runtime": "docker",
                "http_root": os.fspath(http_root),
                "source_manifest_sha256": hashlib.sha256(
                    manifest.read_bytes()
                ).hexdigest(),
            }, json.loads(path.read_text(encoding="utf-8")))
            path.unlink()
            outside = state_root / "outside"
            outside.write_text("do not replace\n", encoding="utf-8")
            path.symlink_to(outside.name)
            with mock.patch.object(
                activate, "verify_compatible_live_source", return_value=[],
            ), self.assertRaisesRegex(
                activate.ActivationError, "owner.*regular",
            ):
                activate.ensure_docker_deployment_owner(
                    settings, image_manifest=image_manifest,
                )

    def test_entrypoint_never_binds_owner_to_unverified_live_source_manifest(self):
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            http_root = root / "html"
            state_root = root / "state"
            state_root.mkdir()
            live = http_root / "infra/docker/deployment-source-manifest.json"
            live.parent.mkdir(parents=True)
            live.write_bytes(b'{"schema_version":1,"files":[{"path":"evil"}]}\n')
            image = root / "image-source-manifest.json"
            image.write_bytes(b'{"schema_version":1,"files":[]}\n')
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
                state_root=state_root,
            )
            with self.assertRaisesRegex(
                activate.ActivationError, "manifest.*image authority|match",
            ):
                activate.ensure_docker_deployment_owner(
                    settings, image_manifest=image,
                )
            self.assertFalse((state_root / "deployment-owner.json").exists())

    def test_persistent_rsyslog_files_have_bounded_rotation(self) -> None:
        policy = (DOCKER_ROOT / "logrotate-http-ztp.conf").read_text(
            encoding="utf-8",
        )
        for path in (
            "/var/log/http-ztp/dhcpd.log", "/var/log/http-ztp/syslog",
            "/var/log/apache2/*.log",
        ):
            self.assertIn(path, policy)
        self.assertRegex(policy, r"(?m)^\s*size\s+\d+[kM]$")
        self.assertRegex(policy, r"(?m)^\s*rotate\s+[1-9]\d*$")
        self.assertIn("compress", policy)
        self.assertIn("copytruncate", policy)

    def test_docker_readme_states_control_cgi_trust_boundary(self) -> None:
        self.assertFalse(os.path.lexists(DOCKER_ROOT / "README.md"))
        source = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        for phrase in (
            "TC-REAL-MONITOR-ORIGIN-001",
            "exact service-IP Origin authority",
            "manual=`ManualZTPControl`",
            "switch=`SwitchCollectionControl`",
            "ztp=`ZTPMonitorControl`",
            "`0.0.0.0`", "`[::]`", "`:443`",
            "Status: OPEN / NOT RUN",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, source)


class ActivationContractTests(QuietContractTest):
    @staticmethod
    def _stable_snapshot_fixtures():
        links = [
            {
                "ifindex": 5,
                "ifname": "enp0s11",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "address": "02:00:00:00:00:05",
                "operstate": "UP",
                "link_type": "ether",
            },
            {
                "ifindex": 4,
                "ifname": "enp0s10",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "address": "02:00:00:00:00:04",
                "operstate": "UP",
                "link_type": "ether",
            },
            {
                "ifindex": 6,
                "ifname": "br-fixture",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "address": "02:00:00:00:00:06",
                "operstate": "UP",
                "link_type": "ether",
                "linkinfo": {
                    "info_kind": "bridge",
                    "info_data": {
                        "forward_delay": 1500,
                        "stp_state": 0,
                        "vlan_filtering": 0,
                        "gc_timer": 31.42,
                    },
                },
            },
            {
                "ifindex": 7,
                "ifname": "enp0s10.114",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "address": "02:00:00:00:01:14",
                "operstate": "UP",
                "link_type": "ether",
                "link_index": 4,
                "linkinfo": {
                    "info_kind": "vlan",
                    "info_data": {"protocol": "802.1Q", "id": 114},
                },
            },
        ]
        addresses = [
            {
                "ifindex": 5,
                "ifname": "enp0s11",
                "addr_info": [{
                    "family": "inet",
                    "local": "198.51.100.50",
                    "prefixlen": 26,
                    "scope": "global",
                    "flags": [],
                    "valid_life_time": 3598,
                    "preferred_life_time": 1798,
                }],
            },
            {
                "ifindex": 4,
                "ifname": "enp0s10",
                "addr_info": [{
                    "family": "inet",
                    "local": "192.0.2.50",
                    "prefixlen": 26,
                    "scope": "global",
                    "flags": [],
                    "valid_life_time": "forever",
                    "preferred_life_time": "forever",
                }],
            },
        ]
        return links, addresses

    @staticmethod
    def _snapshot_runner(
        first_links,
        first_addresses,
        second_links,
        second_addresses,
        *,
        first_routes=(),
        second_routes=None,
        commands=None,
    ):
        if second_routes is None:
            second_routes = first_routes
        responses = {
            ("ip", "-d", "-j", "link", "show"): iter(
                (first_links, second_links),
            ),
            ("ip", "-j", "-4", "address", "show"): iter(
                (first_addresses, second_addresses),
            ),
            ("ip", "-j", "-4", "route", "show", "table", "all"): iter(
                (first_routes, second_routes),
            ),
        }

        def runner(command, **_kwargs):
            key = tuple(command)
            if commands is not None:
                commands.append(key)
            if key not in responses:
                raise AssertionError(f"unexpected network snapshot command: {key!r}")
            try:
                snapshot = next(responses[key])
            except StopIteration as exc:
                raise AssertionError(
                    f"network snapshot command ran too many times: {key!r}"
                ) from exc
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(snapshot), stderr="",
            )

        return runner

    def test_settings_accept_dynamic_zero_to_n_interface_policy(self) -> None:
        activate = load_script("activate.py")
        settings = activate.Settings.from_environment({
            "HTTP_ZTP_PROJECT": "site-a",
            "HTTP_ZTP_SCOPE": "prod",
            "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST": "eno2, eno3.114 eno4",
            "HTTP_ZTP_DHCP_RELAY_INGRESS": "eno4",
        })
        self.assertEqual(("eno2", "eno3.114", "eno4"), settings.allowlist)
        self.assertEqual(("eno4",), settings.relay_ingress)

        no_ceiling = activate.Settings.from_environment({
            "HTTP_ZTP_PROJECT": "site-a", "HTTP_ZTP_SCOPE": "air",
        })
        self.assertEqual((), no_ceiling.allowlist)
        self.assertEqual((), no_ceiling.relay_ingress)

    def test_settings_resolve_release_scope_switch_and_mini_before_runtime(self) -> None:
        activate = load_script("activate.py")
        air = activate.Settings.from_environment({
            "HTTP_ZTP_PROJECT": "site-a",
            "HTTP_ZTP_SCOPE": "air",
        })
        self.assertEqual("eth", getattr(air, "switch_scope", None))
        self.assertIs(False, getattr(air, "mini", None))

        prod = activate.Settings.from_environment({
            "HTTP_ZTP_PROJECT": "site-a",
            "HTTP_ZTP_SCOPE": "prod",
        })
        self.assertEqual("all", getattr(prod, "switch_scope", None))
        self.assertIs(False, getattr(prod, "mini", None))

        prod_nvl = activate.Settings.from_environment({
            "HTTP_ZTP_PROJECT": "site-a",
            "HTTP_ZTP_SCOPE": "prod",
            "HTTP_ZTP_SWITCH_SCOPE": "nvl",
            "HTTP_ZTP_MINI": "disabled",
        })
        self.assertEqual("nvl", getattr(prod_nvl, "switch_scope", None))

        air_mini = activate.Settings.from_environment({
            "HTTP_ZTP_PROJECT": "site-a",
            "HTTP_ZTP_SCOPE": "air",
            "HTTP_ZTP_SWITCH_SCOPE": "eth",
            "HTTP_ZTP_MINI": "enabled",
        })
        self.assertEqual("eth", getattr(air_mini, "switch_scope", None))
        self.assertIs(True, getattr(air_mini, "mini", None))

        for environment, expected in (
            ({"HTTP_ZTP_SWITCH_SCOPE": "all"}, "AIR.*eth"),
            ({"HTTP_ZTP_SWITCH_SCOPE": "ib"}, "AIR.*eth"),
            ({"HTTP_ZTP_SWITCH_SCOPE": "nvl"}, "AIR.*eth"),
            ({"HTTP_ZTP_MINI": "maybe"}, "HTTP_ZTP_MINI"),
        ):
            with self.subTest(environment=environment), self.assertRaisesRegex(
                activate.ActivationError, expected,
            ):
                activate.Settings.from_environment({
                    "HTTP_ZTP_PROJECT": "site-a",
                    "HTTP_ZTP_SCOPE": "air",
                    **environment,
                })

        with self.assertRaisesRegex(activate.ActivationError, "mini.*AIR|AIR.*mini"):
            activate.Settings.from_environment({
                "HTTP_ZTP_PROJECT": "site-a",
                "HTTP_ZTP_SCOPE": "prod",
                "HTTP_ZTP_SWITCH_SCOPE": "eth",
                "HTTP_ZTP_MINI": "enabled",
            })

    def test_runtime_init_creates_private_executable_askpass_directory(self) -> None:
        activate = load_script("activate.py")
        settings = activate.Settings(
            project_name="site-a", scope="air", http_root=Path("/var/www/html"),
        )
        with mock.patch.object(Path, "mkdir", autospec=True) as mkdir, mock.patch.object(
            Path, "exists", return_value=True,
        ), mock.patch.object(activate.os, "chmod") as chmod:
            activate.ensure_runtime_directories(settings)

        askpass = Path("/run/http-ztp/askpass")
        self.assertIn(
            mock.call(askpass, parents=True, exist_ok=True),
            mkdir.call_args_list,
        )
        self.assertIn(mock.call(askpass, 0o700), chmod.call_args_list)

    def test_runtime_init_uses_canonical_run_lock_on_ubuntu(self) -> None:
        """A fresh /run tmpfs leaves Ubuntu's /var/lock symlink dangling."""
        activate = load_script("activate.py")
        settings = activate.Settings(
            project_name="site-a", scope="air", http_root=Path("/var/www/html"),
        )
        with mock.patch.object(Path, "mkdir", autospec=True) as mkdir, mock.patch.object(
            Path, "exists", return_value=True,
        ), mock.patch.object(activate.os, "chmod") as chmod:
            activate.ensure_runtime_directories(settings)

        created = [call.args[0] for call in mkdir.call_args_list]
        run_lock = Path("/run/lock")
        apache_lock = Path("/var/lock/apache2")
        self.assertIn(run_lock, created)
        self.assertIn(apache_lock, created)
        self.assertLess(created.index(run_lock), created.index(apache_lock))
        self.assertIn(mock.call(run_lock, 0o1777), chmod.call_args_list)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "run").mkdir()
            (root / "var").mkdir()
            (root / "var/lock").symlink_to("../run/lock")
            with self.assertRaises(FileExistsError):
                (root / "var/lock/apache2").mkdir(parents=True, exist_ok=True)
            (root / "run/lock").mkdir(mode=0o1777)
            (root / "var/lock/apache2").mkdir(parents=True, exist_ok=True)
            self.assertTrue((root / "run/lock/apache2").is_dir())

    def test_project_mount_rejects_project_alias_and_cross_project_core_input(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            day0 = root / "DAY0-Prepare"
            site_b = day0 / "site-b"
            site_b.mkdir(parents=True)
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv",
            ):
                (site_b / name).write_text("fixture\n", encoding="utf-8")
            site_a = day0 / "site-a"
            site_a.symlink_to("site-b")
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=root,
            )
            with self.assertRaisesRegex(
                activate.ActivationError, "project.*directory|symlink",
            ):
                activate.validate_project_mount(settings)

            site_a.unlink()
            site_a.mkdir()
            for name in ("02-devices_config.csv", "02-dhcp-subnet_config.csv"):
                (site_a / name).write_text("fixture\n", encoding="utf-8")
            (site_a / "01-global.yaml").symlink_to(
                "../site-b/01-global.yaml",
            )
            with self.assertRaisesRegex(
                activate.ActivationError, "01-global.*regular",
            ):
                activate.validate_project_mount(settings)

    def test_published_runtime_requires_all_fixed_bootstrap_artifacts(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "html"
            ztp = http_root / "ztp"
            ztp.mkdir(parents=True)
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )
            for relative in activate.PUBLISHED_RUNTIME_FILES:
                path = http_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"fixture for {relative}\n", encoding="utf-8")

            identity = activate.published_runtime_identity(settings)
            self.assertEqual(
                {path.as_posix() for path in activate.PUBLISHED_RUNTIME_FILES},
                set(identity),
            )

            missing = http_root / activate.PUBLISHED_RUNTIME_FILES[1]
            missing.unlink()
            with self.assertRaisesRegex(
                activate.ActivationError, "published runtime.*missing",
            ):
                activate.published_runtime_identity(settings)

            missing.symlink_to("ztp-bootstrap_oob.sh")
            with self.assertRaisesRegex(
                activate.ActivationError, "regular file",
            ):
                activate.published_runtime_identity(settings)

    def test_published_public_keys_are_canonical_current_project_links(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary).resolve() / "html"
            project = http_root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv",
            ):
                (project / name).write_text("fixture\n", encoding="utf-8")
            key = project / "laptop.pub"
            key.write_text("ssh-ed25519 fixture\n", encoding="utf-8")
            public = http_root / "ztp/config/publickey/laptop.pub"
            public.parent.mkdir(parents=True)
            public.symlink_to("../../../DAY0-Prepare/site-a/laptop.pub")
            for relative in activate.PUBLISHED_RUNTIME_FILES:
                artifact = http_root / relative
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text("fixture\n", encoding="utf-8")
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )
            identity = activate.published_runtime_identity(settings)
            self.assertEqual(
                "../../../DAY0-Prepare/site-a/laptop.pub",
                identity["ztp/config/publickey/laptop.pub"]["target"],
            )

            sibling = http_root / "DAY0-Prepare/site-b/laptop.pub"
            sibling.parent.mkdir(parents=True)
            sibling.write_text(key.read_text(encoding="utf-8"), encoding="utf-8")
            public.unlink()
            public.symlink_to("../../../DAY0-Prepare/site-b/laptop.pub")
            with self.assertRaisesRegex(
                activate.ActivationError, "current project|non-canonical",
            ):
                activate.published_runtime_identity(settings)

    def test_apache_binds_each_service_ip_exactly_and_never_wildcard(self) -> None:
        activate = load_script("activate.py")
        source = activate.render_apache_listener_config(
            ("192.0.2.10", "198.51.100.10"),
        )
        self.assertEqual(1, source.count("Listen 192.0.2.10:80"))
        self.assertEqual(1, source.count("Listen 198.51.100.10:80"))
        self.assertIn("<VirtualHost 192.0.2.10:80>", source)
        self.assertIn("<VirtualHost 198.51.100.10:80>", source)
        self.assertNotIn("Listen 80", source)
        self.assertNotIn("0.0.0.0", source)
        self.assertNotIn("*:80", source)

    def test_network_snapshot_requests_link_address_and_all_ipv4_routes_twice(
        self,
    ) -> None:
        activate = load_script("activate.py")
        commands = []
        responses = iter(("[]", "[]", "[]", "[]", "[]", "[]"))

        def runner(command, **_kwargs):
            commands.append(tuple(command))
            return SimpleNamespace(returncode=0, stdout=next(responses), stderr="")

        links, addresses = activate.capture_stable_network_snapshot(runner)
        self.assertEqual([], links)
        self.assertEqual([], addresses)
        self.assertEqual(
            [
                ("ip", "-d", "-j", "link", "show"),
                ("ip", "-j", "-4", "address", "show"),
                ("ip", "-j", "-4", "route", "show", "table", "all"),
                ("ip", "-d", "-j", "link", "show"),
                ("ip", "-j", "-4", "address", "show"),
                ("ip", "-j", "-4", "route", "show", "table", "all"),
            ],
            commands,
        )

    def test_snapshot_projection_accepts_only_bridge_timer_churn_without_mutation(
        self,
    ) -> None:
        activate = load_script("activate.py")
        first_links, first_addresses = self._stable_snapshot_fixtures()
        second_links = copy.deepcopy(first_links)
        second_links[2]["linkinfo"]["info_data"]["gc_timer"] = 30.01
        original_first = copy.deepcopy(first_links)
        original_second = copy.deepcopy(second_links)

        links, addresses = activate.capture_stable_network_snapshot(
            self._snapshot_runner(
                first_links, first_addresses, second_links, first_addresses,
            ),
        )

        self.assertEqual(original_first, links)
        self.assertEqual(first_addresses, addresses)
        self.assertEqual(original_first, first_links)
        self.assertEqual(original_second, second_links)
        self.assertEqual(31.42, links[2]["linkinfo"]["info_data"]["gc_timer"])

    def test_snapshot_projection_rejects_link_topology_changes(self) -> None:
        activate = load_script("activate.py")
        mutations = (
            ("ifindex", (0, "ifindex"), 105),
            ("ifname", (0, "ifname"), "enp0s12"),
            ("MAC", (0, "address"), "02:00:00:00:00:ff"),
            ("flags", (0, "flags"), ["BROADCAST", "MULTICAST", "UP"]),
            ("operstate", (0, "operstate"), "DOWN"),
            ("link_type", (0, "link_type"), "none"),
            ("link_index", (3, "link_index"), 5),
            ("info_kind", (3, "linkinfo", "info_kind"), "bridge"),
            ("VLAN ID", (3, "linkinfo", "info_data", "id"), 115),
            (
                "bridge forward delay",
                (2, "linkinfo", "info_data", "forward_delay"),
                1600,
            ),
        )
        for label, path, value in mutations:
            with self.subTest(field=label):
                first_links, addresses = self._stable_snapshot_fixtures()
                second_links = copy.deepcopy(first_links)
                target = second_links[path[0]]
                for key in path[1:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaisesRegex(
                    activate.ActivationError, "network links changed",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            first_links, addresses, second_links, addresses,
                        ),
                    )

        first_links, addresses = self._stable_snapshot_fixtures()
        second_links = copy.deepcopy(first_links)
        first_links[3]["linkinfo"]["info_data"]["gc_timer"] = 10
        second_links[3]["linkinfo"]["info_data"]["gc_timer"] = 9
        with self.assertRaisesRegex(
            activate.ActivationError, "network links changed",
        ):
            activate.capture_stable_network_snapshot(
                self._snapshot_runner(
                    first_links, addresses, second_links, addresses,
                ),
            )

    def test_snapshot_projection_accepts_positive_address_lifetime_countdown(
        self,
    ) -> None:
        activate = load_script("activate.py")
        links, first_addresses = self._stable_snapshot_fixtures()
        second_addresses = copy.deepcopy(first_addresses)
        second_addresses[0]["addr_info"][0]["valid_life_time"] = 3596
        second_addresses[0]["addr_info"][0]["preferred_life_time"] = 1796
        original_first = copy.deepcopy(first_addresses)
        original_second = copy.deepcopy(second_addresses)

        returned_links, returned_addresses = activate.capture_stable_network_snapshot(
            self._snapshot_runner(
                links, first_addresses, links, second_addresses,
            ),
        )

        self.assertEqual(links, returned_links)
        self.assertEqual(original_first, returned_addresses)
        self.assertEqual(original_first, first_addresses)
        self.assertEqual(original_second, second_addresses)

    def test_snapshot_projection_rejects_lifetime_growth_and_uint32_overflow(
        self,
    ) -> None:
        activate = load_script("activate.py")
        for field, before, after in (
            ("valid_life_time", 3598, 3599),
            ("preferred_life_time", 1798, 1799),
            ("valid_life_time", 4_294_967_295, 4_294_967_294),
            ("preferred_life_time", 4_294_967_295, 4_294_967_294),
            ("valid_life_time", 4_294_967_294, 4_294_967_295),
            ("preferred_life_time", 4_294_967_294, 4_294_967_295),
        ):
            with self.subTest(field=field, before=before, after=after):
                links, first_addresses = self._stable_snapshot_fixtures()
                second_addresses = copy.deepcopy(first_addresses)
                first_addresses[0]["addr_info"][0][field] = before
                second_addresses[0]["addr_info"][0][field] = after
                with self.assertRaisesRegex(
                    activate.ActivationError, "IPv4 addresses changed",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, first_addresses, links, second_addresses,
                        ),
                    )

        for position, value in (
            ("first", 4_294_967_296),
            ("second", 4_294_967_296),
            ("first", 10 ** 1000),
            ("second", 10 ** 1000),
        ):
            with self.subTest(position=position, out_of_range=value):
                links, first_addresses = self._stable_snapshot_fixtures()
                second_addresses = copy.deepcopy(first_addresses)
                target = first_addresses if position == "first" else second_addresses
                target[0]["addr_info"][0]["valid_life_time"] = value
                with self.assertRaisesRegex(
                    activate.ActivationError, "lifetime",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, first_addresses, links, second_addresses,
                        ),
                    )

        links, first_addresses = self._stable_snapshot_fixtures()
        second_addresses = copy.deepcopy(first_addresses)
        first_addresses[0]["addr_info"][0]["valid_life_time"] = 4_294_967_294
        second_addresses[0]["addr_info"][0]["valid_life_time"] = 4_294_967_293
        returned_links, returned_addresses = (
            activate.capture_stable_network_snapshot(
                self._snapshot_runner(
                    links, first_addresses, links, second_addresses,
                ),
            )
        )
        self.assertEqual(links, returned_links)
        self.assertEqual(first_addresses, returned_addresses)

        permanent_addresses = copy.deepcopy(first_addresses)
        permanent_addresses[0]["addr_info"][0]["valid_life_time"] = 4_294_967_295
        _links, returned_permanent = activate.capture_stable_network_snapshot(
            self._snapshot_runner(
                links, permanent_addresses, links, permanent_addresses,
            ),
        )
        self.assertEqual(permanent_addresses, returned_permanent)

    def test_snapshot_projection_rejects_address_availability_and_identity_changes(
        self,
    ) -> None:
        activate = load_script("activate.py")
        cases = (
            ("positive-to-zero-valid", "valid_life_time", 3598, 0),
            ("zero-to-positive-valid", "valid_life_time", 0, 3598),
            ("positive-to-zero-preferred", "preferred_life_time", 1798, 0),
            ("zero-to-positive-preferred", "preferred_life_time", 0, 1798),
            ("local", "local", "198.51.100.50", "198.51.100.51"),
            ("prefixlen", "prefixlen", 26, 25),
            ("scope", "scope", "global", "site"),
        )
        for label, key, before, after in cases:
            with self.subTest(field=label):
                links, first_addresses = self._stable_snapshot_fixtures()
                second_addresses = copy.deepcopy(first_addresses)
                first_addresses[0]["addr_info"][0][key] = before
                second_addresses[0]["addr_info"][0][key] = after
                with self.assertRaisesRegex(
                    activate.ActivationError, "IPv4 addresses changed",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, first_addresses, links, second_addresses,
                        ),
                    )

        for flag in ("tentative", "dadfailed", "deprecated"):
            for before, after in (([], [flag]), ([flag], [])):
                with self.subTest(flag=flag, before=before, after=after):
                    links, first_addresses = self._stable_snapshot_fixtures()
                    second_addresses = copy.deepcopy(first_addresses)
                    first_addresses[0]["addr_info"][0]["flags"] = before
                    second_addresses[0]["addr_info"][0]["flags"] = after
                    with self.assertRaisesRegex(
                        activate.ActivationError, "IPv4 addresses changed",
                    ):
                        activate.capture_stable_network_snapshot(
                            self._snapshot_runner(
                                links, first_addresses, links, second_addresses,
                            ),
                        )

        for key, value in (("ifindex", 15), ("ifname", "enp0s12")):
            with self.subTest(field=key):
                links, first_addresses = self._stable_snapshot_fixtures()
                second_addresses = copy.deepcopy(first_addresses)
                second_addresses[0][key] = value
                with self.assertRaisesRegex(
                    activate.ActivationError, "IPv4 addresses changed",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, first_addresses, links, second_addresses,
                        ),
                    )

    def test_snapshot_projection_preserves_forever_zero_and_rejects_malformed_values(
        self,
    ) -> None:
        activate = load_script("activate.py")
        for before, after in (
            ("forever", 3598),
            (3598, "forever"),
            (4_294_967_295, "forever"),
            ("forever", 4_294_967_295),
        ):
            with self.subTest(boundary=(before, after)):
                links, first_addresses = self._stable_snapshot_fixtures()
                second_addresses = copy.deepcopy(first_addresses)
                first_addresses[0]["addr_info"][0]["valid_life_time"] = before
                second_addresses[0]["addr_info"][0]["valid_life_time"] = after
                with self.assertRaisesRegex(
                    activate.ActivationError, "IPv4 addresses changed",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, first_addresses, links, second_addresses,
                        ),
                    )

        malformed_lifetimes = (
            -1, True, 1.5, float(4_294_967_295), "3598", "unknown", {},
        )
        for value in malformed_lifetimes:
            with self.subTest(lifetime=value):
                links, addresses = self._stable_snapshot_fixtures()
                addresses[0]["addr_info"][0]["valid_life_time"] = value
                with self.assertRaisesRegex(
                    activate.ActivationError, "lifetime",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, addresses, links, addresses,
                        ),
                    )

        malformed_timers = (
            -1,
            True,
            float("nan"),
            float("inf"),
            float("-inf"),
            "31.42",
            "unknown",
            {},
            [31.42],
        )
        for value in malformed_timers:
            with self.subTest(gc_timer=value):
                links, addresses = self._stable_snapshot_fixtures()
                links[2]["linkinfo"]["info_data"]["gc_timer"] = value
                with self.assertRaisesRegex(
                    activate.ActivationError, "gc_timer",
                ):
                    activate.capture_stable_network_snapshot(
                        self._snapshot_runner(
                            links, addresses, links, addresses,
                        ),
                    )

    def test_snapshot_projection_rejects_unrepresentable_bridge_timer_cleanly(
        self,
    ) -> None:
        activate = load_script("activate.py")
        links, addresses = self._stable_snapshot_fixtures()
        links[2]["linkinfo"]["info_data"]["gc_timer"] = 10 ** 1000
        try:
            activate.capture_stable_network_snapshot(
                self._snapshot_runner(links, addresses, links, addresses),
            )
        except activate.ActivationError as exc:
            self.assertIn("gc_timer", str(exc))
        except Exception as exc:  # pragma: no cover - assertion reports type
            self.fail(
                "unrepresentable gc_timer must fail closed with ActivationError, "
                f"not {type(exc).__name__}: {exc}"
            )
        else:
            self.fail("unrepresentable gc_timer was accepted")

    def test_snapshot_rejects_any_ipv4_route_change(self) -> None:
        activate = load_script("activate.py")
        links, addresses = self._stable_snapshot_fixtures()
        first_routes = [{
            "dst": "default",
            "gateway": "192.0.2.1",
            "dev": "enp0s10",
            "protocol": "dhcp",
            "metric": 100,
            "table": "main",
        }]
        second_routes = copy.deepcopy(first_routes)
        second_routes[0]["gateway"] = "192.0.2.254"
        original_first = copy.deepcopy(first_routes)
        original_second = copy.deepcopy(second_routes)
        commands = []
        with self.assertRaisesRegex(
            activate.ActivationError, "IPv4 routes changed",
        ):
            activate.capture_stable_network_snapshot(
                self._snapshot_runner(
                    links,
                    addresses,
                    links,
                    addresses,
                    first_routes=first_routes,
                    second_routes=second_routes,
                    commands=commands,
                ),
            )
        self.assertEqual(
            2,
            commands.count(
                ("ip", "-j", "-4", "route", "show", "table", "all"),
            ),
        )
        self.assertEqual(original_first, first_routes)
        self.assertEqual(original_second, second_routes)

        with self.assertRaisesRegex(
            activate.ActivationError, r"route stability snapshot\[0\]",
        ):
            activate.capture_stable_network_snapshot(
                self._snapshot_runner(
                    links,
                    addresses,
                    links,
                    addresses,
                    first_routes=["not-a-route-object"],
                    second_routes=["not-a-route-object"],
                ),
            )

    def test_ubuntu_bridge_snapshot_workflow_plans_before_any_write(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            project = http_root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text(
                "project: independent-fixture\n", encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,mac\nfixture,02:00:00:00:00:01\n", encoding="utf-8",
            )
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet,netmask,ztp_service_ip,"
                "cumulus_profile,nvos_ztp\n"
                "fabric-b,198.51.100.0,255.255.255.192,198.51.100.50,oob,no\n"
                "fabric-a,192.0.2.0,255.255.255.192,192.0.2.50,oob,no\n",
                encoding="utf-8",
            )
            tools = http_root / "tools"
            tools.mkdir()
            shutil.copyfile(
                ROOT / "tools/ztp_service_runtime.py",
                tools / "ztp_service_runtime.py",
            )
            settings = activate.Settings(
                project_name="site-a",
                scope="prod",
                http_root=http_root,
                state_root=root / "state",
                apache_listeners=root / "apache-listeners.conf",
            )
            first_links, first_addresses = self._stable_snapshot_fixtures()
            second_links = copy.deepcopy(first_links)
            second_addresses = copy.deepcopy(first_addresses)
            second_links[2]["linkinfo"]["info_data"]["gc_timer"] = 29.87
            second_addresses[0]["addr_info"][0]["valid_life_time"] = 3596
            second_addresses[0]["addr_info"][0]["preferred_life_time"] = 1796

            selected, _runtime, payload, _apache = activate.observe_runtime(
                settings,
                self._snapshot_runner(
                    first_links,
                    first_addresses,
                    second_links,
                    second_addresses,
                ),
            )
            self.assertEqual(("enp0s11", "enp0s10"), selected.listener_names)
            self.assertEqual((5, 4), selected.listener_ifindexes)
            self.assertEqual(
                [("enp0s11", 5), ("enp0s10", 4)],
                [
                    (item["ifname"], item["ifindex"])
                    for item in payload["listener_fingerprints"]
                ],
            )
            second_selected, _runtime, second_payload, _apache = (
                activate.observe_runtime(
                    settings,
                    self._snapshot_runner(
                        second_links,
                        second_addresses,
                        second_links,
                        second_addresses,
                    ),
                )
            )
            self.assertEqual(selected.listener_names, second_selected.listener_names)
            self.assertEqual(
                payload["listener_fingerprints"],
                second_payload["listener_fingerprints"],
            )
            self.assertNotEqual(
                payload["link_snapshot_sha256"],
                second_payload["link_snapshot_sha256"],
            )
            self.assertNotEqual(
                payload["address_snapshot_sha256"],
                second_payload["address_snapshot_sha256"],
            )

            drifted_links = copy.deepcopy(first_links)
            drifted_links[0]["address"] = "02:00:00:00:00:ff"
            with mock.patch.object(
                activate, "ensure_runtime_directories",
            ) as ensure_directories, mock.patch.object(
                activate, "_atomic_write",
            ) as atomic_write:
                with self.assertRaisesRegex(
                    activate.ActivationError, "network links changed",
                ):
                    activate.prepare_runtime(
                        settings,
                        self._snapshot_runner(
                            first_links,
                            first_addresses,
                            drifted_links,
                            first_addresses,
                        ),
                    )
            ensure_directories.assert_called_once_with(settings)
            atomic_write.assert_not_called()
            self.assertFalse(settings.runtime_plan.exists())
            self.assertFalse(settings.apache_listeners.exists())
            self.assertFalse(settings.activation_marker.exists())
            self.assertFalse(settings.precommit_marker.exists())

            first_routes = [{
                "dst": "default",
                "gateway": "192.0.2.1",
                "dev": "enp0s10",
                "protocol": "dhcp",
                "metric": 100,
                "table": "main",
            }]
            drifted_routes = copy.deepcopy(first_routes)
            drifted_routes[0]["metric"] = 101
            with mock.patch.object(
                activate, "ensure_runtime_directories",
            ) as ensure_directories, mock.patch.object(
                activate, "_atomic_write",
            ) as atomic_write:
                with self.assertRaisesRegex(
                    activate.ActivationError, "IPv4 routes changed",
                ):
                    activate.prepare_runtime(
                        settings,
                        self._snapshot_runner(
                            first_links,
                            first_addresses,
                            first_links,
                            first_addresses,
                            first_routes=first_routes,
                            second_routes=drifted_routes,
                        ),
                    )
            ensure_directories.assert_called_once_with(settings)
            atomic_write.assert_not_called()
            self.assertFalse(settings.runtime_plan.exists())
            self.assertFalse(settings.apache_listeners.exists())
            self.assertFalse(settings.activation_marker.exists())
            self.assertFalse(settings.precommit_marker.exists())

    def test_reboot_activation_replans_ifindex_instead_of_pinning_snapshot(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            project = http_root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            inputs = {
                "global": project / "01-global.yaml",
                "devices": project / "02-devices_config.csv",
                "subnet": project / "02-dhcp-subnet_config.csv",
                "p2p": project / "p2p.xlsx",
            }
            for name, path in inputs.items():
                path.write_text(f"independent-{name}-fixture\n", encoding="utf-8")
            subnet = inputs["subnet"]
            dhcp = root / "dhcpd.conf"
            release = root / "current-release.json"
            dhcp.write_text("authoritative;\n", encoding="utf-8")
            hashes = {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in inputs.items()
            }
            release.write_text(json.dumps({
                "release_id": "fixture",
                "deployment_scope": "prod",
                "switch_scope": "all",
                "inputs": hashes,
                "components": {},
            }) + "\n", encoding="utf-8")
            bootstrap = http_root / "ztp/ztp-bootstrap_oob.sh"
            bootstrap.parent.mkdir(parents=True)
            for relative in activate.PUBLISHED_RUNTIME_FILES:
                (http_root / relative).write_text(
                    "#!/bin/sh\n# release fixture\n", encoding="utf-8",
                )
            settings = activate.Settings(
                project_name="site-a", scope="prod", http_root=http_root,
                dhcp_config=dhcp,
            )

            source_identity = [{
                "path": "fixture.py", "type": "file", "target": None,
                "sha256": "a" * 64,
            }]
            with mock.patch.object(
                activate, "validate_image_source_contract",
                return_value=source_identity,
            ), mock.patch.object(
                activate, "published_link_identity", return_value={
                    "ztp/config/cumulus/template/P2P/p2p.xlsx": {
                        "sha256": hashes["p2p"],
                    },
                },
            ):
                marker = activate.build_activation_marker(
                    settings, plan(indexes=(4,)), subnet_csv=subnet,
                    dhcp_config=dhcp, release_manifest=release,
                )
                valid, reason = activate.validate_activation_marker(
                    marker, settings, plan(indexes=(91,)), subnet_csv=subnet,
                    dhcp_config=dhcp, release_manifest=release,
                )
                selection_drift = dict(marker)
                selection_drift["switch_scope"] = "nvl"
                selection_valid, selection_reason = activate.validate_activation_marker(
                    selection_drift, settings, plan(indexes=(91,)),
                    subnet_csv=subnet, dhcp_config=dhcp,
                    release_manifest=release,
                )

                bootstrap.write_text(
                    "#!/bin/sh\n# mixed newer bootstrap\n", encoding="utf-8",
                )
                mixed_valid, mixed_reason = activate.validate_activation_marker(
                    marker, settings, plan(indexes=(91,)), subnet_csv=subnet,
                    dhcp_config=dhcp, release_manifest=release,
                )
                bootstrap.write_text(
                    "#!/bin/sh\n# release fixture\n", encoding="utf-8",
                )
                inputs["global"].write_text("changed-after-load\n", encoding="utf-8")
                drift_valid, drift_reason = activate.validate_activation_marker(
                    marker, settings, plan(indexes=(91,)), subnet_csv=subnet,
                    dhcp_config=dhcp, release_manifest=release,
                )

        self.assertTrue(valid, reason)
        self.assertNotIn("listener_ifindexes", marker)
        self.assertEqual("all", marker["switch_scope"])
        self.assertIs(False, marker["mini"])
        self.assertFalse(selection_valid)
        self.assertIn("switch_scope", selection_reason)
        self.assertEqual(source_identity, marker["runtime_source"])
        self.assertIn("ztp/ztp-bootstrap_oob.sh", marker["published_runtime"])
        self.assertFalse(mixed_valid)
        self.assertIn("published_runtime", mixed_reason)
        self.assertFalse(drift_valid)
        self.assertIn("global", drift_reason)

    def test_parent_release_requires_public_latest_yaml_to_match_component(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            project = http_root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            inputs = {
                "global": project / "01-global.yaml",
                "devices": project / "02-devices_config.csv",
                "subnet": project / "02-dhcp-subnet_config.csv",
                "p2p": project / "p2p.xlsx",
                "mini_air_devices": project / "04-air-mini-devices.txt",
            }
            for name, path in inputs.items():
                path.write_text(f"fixture-{name}\n", encoding="utf-8")
            release_dir = project / "99-output-eth/release-a"
            release_dir.mkdir(parents=True)
            child_manifest = release_dir / "release-manifest.json"
            child_marker = release_dir / ".published-complete"
            child_manifest.write_text('{"release_id":"child-a"}\n', encoding="utf-8")
            child_marker.write_text("complete\n", encoding="utf-8")
            current = project / "99-output-ztp/current-release.json"
            current.parent.mkdir(parents=True)
            parent_payload = {
                "release_id": "parent-a",
                "deployment_scope": "air",
                "switch_scope": "eth",
                "inputs": {
                    name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in inputs.items()
                },
                "components": {
                    "cumulus": {
                        "release_id": "child-a",
                        "release_dir": "99-output-eth/release-a",
                        "manifest_sha256": hashlib.sha256(
                            child_manifest.read_bytes(),
                        ).hexdigest(),
                        "published_marker_sha256": hashlib.sha256(
                            child_marker.read_bytes(),
                        ).hexdigest(),
                    },
                },
            }
            current.write_text(
                json.dumps(parent_payload) + "\n", encoding="utf-8",
            )
            latest = http_root / "ztp/config/cumulus/latest_yaml"
            latest.parent.mkdir(parents=True)
            latest.symlink_to(release_dir)
            settings = activate.Settings(
                project_name="site-a", scope="air", switch_scope="eth",
                mini=True, http_root=http_root,
            )

            activate.validate_parent_release(settings, current)
            parent_payload["switch_scope"] = "nvl"
            current.write_text(
                json.dumps(parent_payload) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(
                activate.ActivationError, "switch scope|switch_scope",
            ):
                activate.validate_parent_release(settings, current)

            parent_payload["switch_scope"] = "eth"
            mini_hash = parent_payload["inputs"].pop("mini_air_devices")
            current.write_text(
                json.dumps(parent_payload) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(activate.ActivationError, "mini"):
                activate.validate_parent_release(settings, current)

            parent_payload["inputs"]["mini_air_devices"] = mini_hash
            current.write_text(
                json.dumps(parent_payload) + "\n", encoding="utf-8",
            )
            latest.unlink()
            wrong = project / "99-output-eth/release-b"
            wrong.mkdir(parents=True)
            latest.symlink_to(wrong)
            with self.assertRaisesRegex(
                activate.ActivationError, "latest_yaml.*parent release",
            ):
                activate.validate_parent_release(settings, current)

    def test_parent_release_rejects_cross_project_p2p_and_dhcp_manifest_aliases(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary).resolve() / "html"
            project = http_root / "DAY0-Prepare/site-a"
            sibling = http_root / "DAY0-Prepare/site-b"
            project.mkdir(parents=True)
            sibling.mkdir(parents=True)
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv",
            ):
                (project / name).write_text(f"site-a-{name}\n", encoding="utf-8")
            sibling_p2p = sibling / "fixture.xlsx"
            sibling_p2p.write_text("same-hash-is-not-authority\n", encoding="utf-8")
            (project / "p2p.xlsx").symlink_to("../site-b/fixture.xlsx")
            p2p_sha = hashlib.sha256(sibling_p2p.read_bytes()).hexdigest()
            with self.assertRaisesRegex(activate.ActivationError, "P2P input"):
                activate._matching_p2p_input(project, p2p_sha)

            (project / "p2p.xlsx").unlink()
            (project / "p2p.xlsx").write_text("site-a-p2p\n", encoding="utf-8")
            inputs = {
                "global": project / "01-global.yaml",
                "devices": project / "02-devices_config.csv",
                "subnet": project / "02-dhcp-subnet_config.csv",
                "p2p": project / "p2p.xlsx",
            }
            target_manifest = (
                project / "99-output-dhcp/dhcp-release-manifest.json"
            )
            target_manifest.parent.mkdir(parents=True)
            target_manifest.write_text(
                '{"release_id":"dhcp"}\n', encoding="utf-8",
            )
            outside = http_root.parent / "outside-dhcp-release.json"
            outside.write_bytes(target_manifest.read_bytes())
            dhcp = http_root / "ztp/config/isc-dhcp-server"
            dhcp.mkdir(parents=True)
            public_manifest = dhcp / "dhcp-release-manifest.json"
            public_manifest.symlink_to(
                "../../../DAY0-Prepare/site-a/99-output-dhcp/"
                "dhcp-release-manifest.json",
            )
            current = project / "99-output-ztp/current-release.json"
            current.parent.mkdir(parents=True)
            current.write_text(json.dumps({
                "release_id": "parent",
                "deployment_scope": "air",
                "switch_scope": "eth",
                "inputs": {
                    name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in inputs.items()
                },
                "components": {
                    "dhcp": {
                        "release_id": "dhcp",
                        "manifest_sha256": hashlib.sha256(
                            target_manifest.read_bytes(),
                        ).hexdigest(),
                    },
                },
            }) + "\n", encoding="utf-8")
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )
            activate.validate_parent_release(settings, current)
            public_manifest.unlink()
            public_manifest.symlink_to(outside)
            with self.assertRaisesRegex(
                activate.ActivationError, "dhcp manifest.*(canonical|current project)",
            ):
                activate.validate_parent_release(settings, current)

    def test_worker_commands_preserve_existing_pid_and_scope_contracts(self) -> None:
        activate = load_script("activate.py")
        settings = activate.Settings(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope="air", monitor_interval=30,
        )
        monitor = activate.worker_spec("ztp-monitor", settings)
        switch = activate.worker_spec("switch-collection", settings)
        manual = activate.worker_spec("manual-ztp", settings)

        self.assertEqual(Path("/var/www/html/ztp/status/ztp-monitor.pid"), monitor.pid_file)
        self.assertIn("/var/www/html/DAY0-Prepare/12-ztp-monitor.py", monitor.argv)
        self.assertNotIn("--dhcp-log", monitor.argv)
        self.assertNotIn("--offline", monitor.argv)
        self.assertIn("--dhcp-leases", monitor.argv)
        self.assertIn("--known-hosts", monitor.argv)
        self.assertIn("air", monitor.argv)
        self.assertIn("--watch", monitor.argv)
        self.assertNotIn("--exit-on-complete", monitor.argv)
        self.assertEqual(
            Path("/var/www/html/monitor/status/switch-collection.pid"),
            switch.pid_file,
        )
        self.assertIn("/var/www/html/monitor/switch-collection-worker.py", switch.argv)
        self.assertEqual(
            Path("/var/www/html/monitor/status/manual-ztp.pid"), manual.pid_file,
        )
        self.assertIn("/var/www/html/monitor/manual-ztp-worker.py", manual.argv)

    def test_container_monitor_argv_is_valid_live_supervisor_mode(self) -> None:
        activate = load_script("activate.py")
        monitor_path = ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        spec = importlib.util.spec_from_file_location(
            "container_monitor_live_mode_contract", monitor_path,
        )
        assert spec is not None and spec.loader is not None
        monitor = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = monitor
        spec.loader.exec_module(monitor)
        settings = activate.Settings(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope="air", monitor_interval=30,
        )
        argv = list(activate.worker_spec("ztp-monitor", settings).argv[3:])
        parsed = monitor.parser().parse_args(argv)
        with mock.patch.object(monitor, "require_active_project"):
            monitor.validate_monitor_mode(parsed, settings.project_dir)
        self.assertFalse(parsed.offline)
        self.assertIsNone(parsed.dhcp_log)
        self.assertEqual(Path("/var/lib/dhcp/dhcpd.leases"), parsed.dhcp_leases)

    def test_zero_listener_plan_has_no_managed_ztp_services(self) -> None:
        activate = load_script("activate.py")
        self.assertEqual((), activate.expected_services(plan(names=(), indexes=(), endpoints=())))
        self.assertEqual(
            ("apache2", "dhcpd", "ztp-monitor", "switch-collection", "manual-ztp"),
            activate.expected_services(plan()),
        )

    def test_dhcp_only_or_relay_ingress_plan_still_runs_exact_dhcp_service(self) -> None:
        activate = load_script("activate.py")
        self.assertEqual(
            ("dhcpd",),
            activate.expected_services(plan(names=("eno7",), indexes=(17,), endpoints=())),
        )

    def test_dhcp_exec_revalidates_ifindex_and_prefix_immediately_before_exec(self) -> None:
        source = (DOCKER_ROOT / "activate.py").read_text(encoding="utf-8")
        revalidate = source.index("runtime.revalidate_dhcp_runtime_plan(")
        fingerprint = source.index("selected_interface_fingerprints(", revalidate)
        build_argv = source.index("runtime.build_dhcpd_argv(", revalidate)
        exec_call = source.index("os.execv(argv[0], argv)", build_argv)
        self.assertLess(revalidate, fingerprint)
        self.assertLess(fingerprint, build_argv)
        self.assertLess(revalidate, build_argv)
        self.assertLess(build_argv, exec_call)

    def test_runtime_plan_fingerprints_only_selected_interface_identity(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "html/DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "02-dhcp-subnet_config.csv").write_text(
                "independent-subnet-fixture\n", encoding="utf-8",
            )
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=root / "html",
            )
            links = [
                {
                    "ifindex": 5, "ifname": "eno1", "link_type": "ether",
                    "address": "02:00:00:00:00:05",
                },
                {
                    "ifindex": 7, "ifname": "eno1.114", "link_type": "ether",
                    "address": "02:00:00:00:00:07", "link_index": 5,
                    "linkinfo": {"info_kind": "vlan", "info_data": {"id": 114}},
                },
                {
                    "ifindex": 99, "ifname": "docker0", "link_type": "ether",
                    "address": "02:00:00:00:00:99",
                },
            ]
            addresses = [
                {
                    "ifindex": 7, "ifname": "eno1.114",
                    "addr_info": [{
                        "family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                        "scope": "global",
                    }],
                },
                {
                    "ifindex": 99, "ifname": "docker0",
                    "addr_info": [{
                        "family": "inet", "local": "198.51.100.99", "prefixlen": 24,
                        "scope": "global",
                    }],
                },
            ]
            payload = activate.runtime_plan_payload(
                settings, plan(names=("eno1.114",), indexes=(7,)), links, addresses,
            )

        self.assertEqual([{
            "ifindex": 7,
            "ifname": "eno1.114",
            "mac": "02:00:00:00:00:07",
            "link_type": "ether",
            "link_kind": "vlan",
            "vlan_id": 114,
            "parent_ifindex": 5,
            "parent_ifname": "eno1",
            "parent_mac": "02:00:00:00:00:05",
            "ipv4_addresses": ["192.0.2.10/24"],
        }], payload["listener_fingerprints"])
        changed = dict(payload)
        changed["link_snapshot_sha256"] = "unrelated-veth-churn"
        load_script("healthcheck.py").require_current_plan(payload, changed)
        changed = dict(payload)
        changed["listener_fingerprints"] = [
            {**payload["listener_fingerprints"][0], "vlan_id": 115},
        ]
        with self.assertRaisesRegex(Exception, "listener_fingerprints"):
            load_script("healthcheck.py").require_current_plan(payload, changed)

    def test_runtime_plan_identity_includes_switch_and_mini_selection(self) -> None:
        activate = load_script("activate.py")
        health = load_script("healthcheck.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "html/DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "02-dhcp-subnet_config.csv").write_text(
                "independent-subnet-fixture\n", encoding="utf-8",
            )
            settings = SimpleNamespace(
                project_name="site-a", scope="air", switch_scope="eth",
                mini=True, http_root=root / "html",
                subnet_csv=project / "02-dhcp-subnet_config.csv",
            )
            selected = plan(names=(), indexes=(), endpoints=())
            payload = activate.runtime_plan_payload(settings, selected, [], [])

        self.assertEqual("eth", payload.get("switch_scope"))
        self.assertIs(True, payload.get("mini"))
        for key, value in (("switch_scope", "all"), ("mini", False)):
            with self.subTest(key=key):
                changed = dict(payload)
                changed[key] = value
                with self.assertRaisesRegex(Exception, key):
                    health.require_current_plan(payload, changed)

    def test_plan_and_status_are_strictly_read_only(self) -> None:
        activate = load_script("activate.py")
        observed = (plan(), object(), {"schema_version": 1}, "apache")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(http_root=root)
            before = tuple(root.iterdir())
            with mock.patch.object(
                activate.Settings, "from_environment", return_value=settings,
            ), mock.patch.object(
                activate, "verify_control_auth_image_copies",
            ) as helper_attestation, mock.patch.object(
                activate, "validate_image_source_contract",
            ) as receipt, mock.patch.object(
                activate, "observe_runtime", return_value=observed,
            ) as observe, mock.patch.object(
                activate, "prepare_runtime",
            ) as prepare, mock.patch.object(
                activate, "read_activation_marker", return_value=None,
            ), mock.patch.object(
                activate, "require_control_auth",
                return_value={"valid": True, "factory_records_active": False},
            ), mock.patch.object(
                activate.hostlock, "safe_lock",
                side_effect=AssertionError("read-only diagnostics must not lock/write"),
            ), mock.patch.object(activate, "_print_json"):
                self.assertEqual(0, activate.main(["plan"]))
                self.assertEqual(3, activate.main(["status"]))
            self.assertEqual(before, tuple(root.iterdir()))
            self.assertFalse((root / ".deployment.lock").exists())
        self.assertEqual(2, receipt.call_count)
        self.assertEqual(2, helper_attestation.call_count)
        self.assertEqual(2, observe.call_count)
        prepare.assert_not_called()

    def test_exec_service_revalidates_receipt_without_relocking_parent_transaction(self) -> None:
        activate = load_script("activate.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []

        with mock.patch.object(
            activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            activate.hostlock, "safe_lock",
            side_effect=AssertionError(
                "Supervisor child must not deadlock on its parent's transaction lock"
            ),
        ), mock.patch.object(
            activate, "verify_control_auth_image_copies",
            side_effect=lambda: events.append("helper-attestation"),
        ) as helper_attestation, mock.patch.object(
            activate, "validate_image_source_contract",
            side_effect=lambda _settings: events.append("receipt"),
        ), mock.patch.object(
            activate, "require_control_auth",
            side_effect=lambda **_kwargs: events.append("control-auth"),
        ) as auth, mock.patch.object(
            activate, "exec_managed_service",
            side_effect=lambda _name, _settings: events.append("exec-service"),
        ):
            self.assertEqual(0, activate.main(["exec-service", "dhcpd"]))
        helper_attestation.assert_called_once_with()
        auth.assert_called_once_with(emit_factory_warning=False)
        self.assertEqual(
            ["helper-attestation", "receipt", "control-auth", "exec-service"],
            events,
        )

    def test_managed_service_requires_active_or_exact_precommit_authority(self) -> None:
        activate = load_script("activate.py")
        settings = SimpleNamespace(
            activation_marker=Path("/state/activation.json"),
            precommit_marker=Path("/state/precommit-activation.json"),
        )
        selected = object()
        with mock.patch.object(
            activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(
            activate, "read_precommit_activation", return_value=None,
        ), self.assertRaisesRegex(activate.ActivationError, "start authority"):
            activate.require_service_start_authority("dhcpd", settings, selected)

        precommit = {
            "start_authority": "precommit",
            "services": ["dhcpd"],
        }
        with mock.patch.object(
            activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(
            activate, "read_precommit_activation", return_value=precommit,
        ), mock.patch.object(
            activate, "validate_activation_marker", return_value=(True, "ok"),
        ):
            activate.require_service_start_authority("dhcpd", settings, selected)
            with self.assertRaisesRegex(activate.ActivationError, "not authorized"):
                activate.require_service_start_authority(
                    "ztp-monitor", settings, selected,
                )

    def test_active_marker_never_falls_back_to_precommit_when_stale(self) -> None:
        activate = load_script("activate.py")
        settings = SimpleNamespace(
            activation_marker=Path("/state/activation.json"),
            precommit_marker=Path("/state/precommit-activation.json"),
        )
        with mock.patch.object(
            activate, "read_activation_marker", return_value={"services": ["dhcpd"]},
        ), mock.patch.object(
            activate, "read_precommit_activation",
        ) as read_precommit, mock.patch.object(
            activate, "validate_activation_marker", return_value=(False, "stale"),
        ), self.assertRaisesRegex(activate.ActivationError, "stale"):
            activate.require_service_start_authority("dhcpd", settings, object())
        read_precommit.assert_not_called()

    def test_delayed_supervisor_child_cannot_exec_after_authority_is_cleared(self) -> None:
        """A late autorestart may validate inputs, but cannot enter the service."""
        activate = load_script("activate.py")
        selected = plan()
        settings = SimpleNamespace(
            activation_marker=Path("/state/activation.json"),
            precommit_marker=Path("/state/precommit-activation.json"),
        )
        with mock.patch.object(
            activate, "observe_runtime",
            return_value=(selected, object(), {}, "Listen 192.0.2.10:80\n"),
        ), mock.patch.object(
            activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(
            activate, "read_precommit_activation", return_value=None,
        ), mock.patch.object(
            activate, "require_monitor_authority",
        ), mock.patch.object(activate.os, "execv") as actual_exec:
            with self.assertRaisesRegex(activate.ActivationError, "authority is absent"):
                activate.exec_managed_service("apache2", settings)
        actual_exec.assert_not_called()

    def test_activation_marker_reader_is_bounded_and_never_opens_special_files(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(
                activation_marker=root / "activation.json",
            )
            settings.activation_marker.write_text(
                '{"schema_version": 1}\n', encoding="utf-8",
            )
            self.assertEqual(
                1, activate.read_activation_marker(settings)["schema_version"],
            )

            settings.activation_marker.unlink()
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            settings.activation_marker.symlink_to(target.name)
            with self.assertRaisesRegex(activate.ActivationError, "bounded regular"):
                activate.read_activation_marker(settings)

            settings.activation_marker.unlink()
            settings.activation_marker.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(activate.ActivationError, "bounded regular"):
                activate.read_activation_marker(settings)

            settings.activation_marker.unlink()
            os.mkfifo(settings.activation_marker)
            with mock.patch.object(
                activate.os, "open",
                side_effect=AssertionError("FIFO must be rejected before open"),
            ) as opened:
                with self.assertRaisesRegex(activate.ActivationError, "bounded regular"):
                    activate.read_activation_marker(settings)
            opened.assert_not_called()

    def test_activate_cli_does_not_expose_unlocked_mutating_actions(self) -> None:
        activate = load_script("activate.py")
        choices = activate.parser()._actions[1].choices
        for action in ("prepare", "commit", "clear"):
            with self.subTest(action=action):
                self.assertNotIn(action, choices)

    def test_control_cgi_is_reinstalled_from_mounted_repository_and_hash_checked(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            cgi_root = root / "cgi-bin"
            (http_root / "monitor").mkdir(parents=True)
            for source, destination in activate.CONTROL_CGI:
                path = http_root / source
                path.write_text(f"#!/bin/sh\n# {destination}\n", encoding="utf-8")
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )
            activate.install_control_cgi(settings, cgi_root=cgi_root)
            activate.validate_control_cgi(settings, cgi_root=cgi_root)
            target = cgi_root / "ztp-monitor-control"
            target.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(activate.ActivationError, "CGI.*hash"):
                activate.validate_control_cgi(settings, cgi_root=cgi_root)

    def test_entrypoint_clears_only_safe_managed_worker_pid_files(self) -> None:
        activate = load_script("activate.py")
        entrypoint = load_script("entrypoint.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=root / "html",
            )
            paths = [
                activate.worker_spec(name, settings).pid_file
                for name in ("ztp-monitor", "switch-collection", "manual-ztp")
            ]
            for path in paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("123\n", encoding="ascii")
            paths[-1].unlink()
            paths[-1].symlink_to(paths[0])

            with self.assertRaisesRegex(activate.ActivationError, "PID.*regular"):
                activate.clear_stale_worker_pid_files(settings)
            self.assertTrue(paths[0].is_file())
            self.assertTrue(paths[-1].is_symlink())

            paths[-1].unlink()
            paths[-1].write_text("456\n", encoding="ascii")
            activate.clear_stale_worker_pid_files(settings)
            self.assertTrue(all(not path.exists() for path in paths))

        source = (DOCKER_ROOT / "entrypoint.py").read_text(encoding="utf-8")
        main_source = source[source.index("def main("):]
        self.assertLess(
            main_source.index("activate.clear_stale_worker_pid_files"),
            main_source.index("initialize_resume_status"),
        )

    def test_fresh_runtime_init_does_not_create_setup_owned_ztp_status_leaf(self) -> None:
        activate = load_script("activate.py")
        body = (DOCKER_ROOT / "activate.py").read_text(encoding="utf-8").split(
            "def ensure_runtime_directories", 1,
        )[1].split("\ndef ", 1)[0]
        self.assertNotIn('settings.http_root / "ztp/status"', body)
        self.assertIn('settings.http_root / "monitor/status"', body)

    def test_post_load_worker_controls_are_initialized_with_safe_defaults(self) -> None:
        """The no-start generator leaves hostctl responsible for CGI state."""
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            project_output = (
                http_root / "DAY0-Prepare/site-a/99-output-ztp"
            )
            project_output.mkdir(parents=True)
            (http_root / "ztp").mkdir()
            (http_root / "ztp/status").symlink_to(
                "../DAY0-Prepare/site-a/99-output-ztp"
            )
            monitor_status = http_root / "monitor/status"
            monitor_status.mkdir(parents=True)
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )
            paths = {
                project_output / "ztp-monitor.control": "running\n",
                monitor_status / "switch-collection.request": "idle\n",
                monitor_status / "manual-ztp.request.json": '{"requests":[]}\n',
            }

            # Prove both a completely fresh tree and stale persistent state use
            # the same deterministic initialization contract.
            activate.initialize_worker_control_files(
                settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
            )
            for path, expected in paths.items():
                with self.subTest(fresh=path.name):
                    self.assertEqual(expected, path.read_text(encoding="utf-8"))
                    metadata = path.lstat()
                    self.assertEqual(1, metadata.st_nlink)
                    self.assertEqual(0o664, metadata.st_mode & 0o777)
                    self.assertEqual(os.getuid(), metadata.st_uid)
                    self.assertEqual(os.getgid(), metadata.st_gid)

            stale = (
                "paused\n", "collect\n",
                '{"requests":[{"action":"reset","hostname":"old-leaf"}]}\n',
            )
            for path, value in zip(paths, stale):
                path.write_text(value, encoding="utf-8")
            activate.initialize_worker_control_files(
                settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
            )
            self.assertEqual(
                {path: expected for path, expected in paths.items()},
                {path: path.read_text(encoding="utf-8") for path in paths},
            )

    def test_worker_control_init_rejects_unsafe_targets_before_any_reset(self) -> None:
        """One symlink/hardlink substitution must fail closed as one set."""
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            project_output = (
                http_root / "DAY0-Prepare/site-a/99-output-ztp"
            )
            project_output.mkdir(parents=True)
            (http_root / "ztp").mkdir()
            (http_root / "ztp/status").symlink_to(
                "../DAY0-Prepare/site-a/99-output-ztp"
            )
            monitor_status = http_root / "monitor/status"
            monitor_status.mkdir(parents=True)
            control = project_output / "ztp-monitor.control"
            switch = monitor_status / "switch-collection.request"
            manual = monitor_status / "manual-ztp.request.json"
            control.write_text("paused\n", encoding="utf-8")
            switch.write_text("collect\n", encoding="utf-8")
            outside = root / "outside"
            outside.write_text("do-not-touch\n", encoding="utf-8")
            manual.symlink_to(outside)
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )

            with self.assertRaisesRegex(
                activate.ActivationError, "control|request|regular|symlink",
            ):
                activate.initialize_worker_control_files(
                    settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
                )
            self.assertEqual("paused\n", control.read_text(encoding="utf-8"))
            self.assertEqual("collect\n", switch.read_text(encoding="utf-8"))
            self.assertEqual("do-not-touch\n", outside.read_text(encoding="utf-8"))

            manual.unlink()
            manual.write_text('{"requests":[]}\n', encoding="utf-8")
            hardlink = root / "request-hardlink"
            os.link(switch, hardlink)
            with self.assertRaisesRegex(
                activate.ActivationError, "control|request|regular|link",
            ):
                activate.initialize_worker_control_files(
                    settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
                )
            self.assertEqual("collect\n", hardlink.read_text(encoding="utf-8"))

            hardlink.unlink()
            switch.unlink()
            os.mkfifo(switch)
            with mock.patch.object(
                activate.os, "open",
                side_effect=AssertionError("FIFO must be rejected before open"),
            ) as opened:
                with self.assertRaisesRegex(
                    activate.ActivationError, "control|request|regular",
                ):
                    activate.initialize_worker_control_files(
                        settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
                    )
            opened.assert_not_called()
            self.assertEqual("paused\n", control.read_text(encoding="utf-8"))

    def test_worker_control_init_requires_exact_setup_owned_status_link(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            own_output = http_root / "DAY0-Prepare/site-a/99-output-ztp"
            other_output = http_root / "DAY0-Prepare/site-b/99-output-ztp"
            own_output.mkdir(parents=True)
            other_output.mkdir(parents=True)
            (http_root / "ztp").mkdir()
            (http_root / "ztp/status").symlink_to(
                "../DAY0-Prepare/site-b/99-output-ztp"
            )
            (http_root / "monitor/status").mkdir(parents=True)
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )

            with self.assertRaisesRegex(
                activate.ActivationError, "status.*link|current project|canonical",
            ):
                activate.initialize_worker_control_files(
                    settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
                )
            self.assertFalse((own_output / "ztp-monitor.control").exists())
            self.assertFalse(
                (http_root / "monitor/status/switch-collection.request").exists()
            )

            (http_root / "ztp/status").unlink()
            (http_root / "ztp/status").symlink_to(
                "../DAY0-Prepare/site-a/99-output-ztp"
            )
            (http_root / "monitor/status").rmdir()
            outside_status = root / "outside-status"
            outside_status.mkdir()
            (http_root / "monitor/status").symlink_to(outside_status)
            with self.assertRaisesRegex(
                activate.ActivationError, "monitor status.*canonical|unsafe",
            ):
                activate.initialize_worker_control_files(
                    settings, owner_uid=os.getuid(), owner_gid=os.getgid(),
                )
            self.assertFalse((own_output / "ztp-monitor.control").exists())

    def test_fresh_runtime_init_covers_every_supervisor_log_parent(self) -> None:
        """Entrypoint-created directories must cover Supervisor's eager log opens."""
        activate = load_script("activate.py")
        settings = activate.Settings(
            project_name="site-a", scope="air", http_root=Path("/var/www/html"),
        )
        with mock.patch.object(Path, "mkdir", autospec=True) as mkdir, mock.patch.object(
            Path, "exists", return_value=True,
        ), mock.patch.object(activate.os, "chmod"):
            activate.ensure_runtime_directories(settings)

        created = {call.args[0] for call in mkdir.call_args_list}
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(DOCKER_ROOT / "supervisord.conf", encoding="utf-8")
        log_parents = {
            Path(parser[section]["stdout_logfile"]).parent
            for section in parser.sections()
            if section.startswith("program:") and "stdout_logfile" in parser[section]
        }
        log_parents.add(Path(parser["supervisord"]["logfile"]).parent)
        log_parents.add(Path(parser["supervisord"]["childlogdir"]))

        self.assertLessEqual(log_parents, created)

    def test_entrypoint_replaces_stale_ready_status_before_supervisor(self) -> None:
        entrypoint = load_script("entrypoint.py")
        with tempfile.TemporaryDirectory() as temporary:
            status = Path(temporary) / "runtime-resume.status.json"
            status.write_text('{"state":"ready","pid":99}\n', encoding="utf-8")
            entrypoint.initialize_resume_status(status)
            payload = json.loads(status.read_text(encoding="utf-8"))
        self.assertEqual("starting", payload["state"])
        self.assertNotEqual(99, payload["pid"])

    def test_embedded_image_scripts_must_match_mounted_docker_sources(self) -> None:
        activate = load_script("activate.py")
        selected = set(activate.image_source_paths(ROOT))
        impact_manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(encoding="utf-8")
        )
        governed_sources = set(impact_manifest["scripts"]) | set(
            impact_manifest["tracked_support"]
        )
        self.assertLessEqual(
            selected,
            governed_sources,
            "every byte copied into the reusable image must invalidate the local "
            "full-test approval when it changes",
        )
        self.assertLessEqual(
            {
                "infra/docker/runtime-contract.json",
                "ztp/config/cumulus/default.yaml",
                "ztp/config/nvos/default.yaml",
                "ztp/config/cumulus/template/03-templates-j2/_extra_aaa_users.yaml.j2",
                "ztp/config/cumulus/template/P2P/air-template.json",
                "DAY0-Prepare/template/02-dhcp-subnet_config.csv",
            },
            set(impact_manifest["tracked_support"]),
        )
        required = set(REQUIRED_ACTIVE_SOURCE_PATHS + REQUIRED_LIFECYCLE_SOURCE_PATHS)
        self.assertTrue(required <= selected, sorted(required - selected))
        self.assertNotIn("DAY0-Prepare/template/README.txt", selected)
        self.assertNotIn("DAY0-Prepare/template/p2p/README.txt", selected)
        self.assertFalse(
            activate._source_path_selected("ztp/optimize/another-site-sample/evil.py")
        )
        self.assertIn(
            "ztp/optimize/*-sample/**",
            (DOCKER_ROOT / "Dockerfile.dockerignore").read_text(encoding="utf-8"),
        )
        self.assertTrue(
            set(
                path.relative_to(ROOT).as_posix()
                for path in (ROOT / "ztp/config/cumulus/template/03-templates-j2").glob(
                    "*.yaml.j2"
                )
            ) <= selected
        )
        self.assertFalse(any(path.startswith("DAY0-Prepare/2026-") for path in selected))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            manifest = root / "image-source.sha256"
            for relative in selected:
                source = ROOT / relative
                destination = http_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not source.is_symlink():
                    shutil.copy2(source, destination)
            for relative in selected:
                source = ROOT / relative
                if source.is_symlink():
                    (http_root / relative).symlink_to(os.readlink(source))
            activate.write_image_source_manifest(http_root, manifest)
            live_manifest = (
                http_root / "infra/docker/deployment-source-manifest.json"
            )
            live_manifest.write_bytes(manifest.read_bytes())
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )

            activate.validate_image_source_contract(settings, manifest=manifest)
            hostctl_source = http_root / "infra/docker/hostctl.py"
            original_hostctl = hostctl_source.read_bytes()
            hostctl_source.write_text(
                "new source requires rebuild\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(activate.ActivationError, "rebuild"):
                activate.validate_image_source_contract(settings, manifest=manifest)
            hostctl_source.write_bytes(original_hostctl)

            original = http_root / "infiniband/monitor/cron.sh"
            original_target = os.readlink(original)
            original.unlink()
            original.symlink_to("../../ethernet/monitor/sw-info.sh")
            with self.assertRaisesRegex(activate.ActivationError, "target.*rebuild"):
                activate.validate_image_source_contract(settings, manifest=manifest)

            original.unlink()
            original.symlink_to("../../../../outside-runtime.py")
            with self.assertRaisesRegex(activate.ActivationError, "rebuild"):
                activate.validate_image_source_contract(settings, manifest=manifest)

            original.unlink()
            original.symlink_to(original_target)
            hostctl_source.unlink()
            hardlink_source = http_root / "infra/docker/activate.py"
            os.link(hardlink_source, hostctl_source)
            with self.assertRaisesRegex(activate.ActivationError, "hard links.*rebuild"):
                activate.validate_image_source_contract(settings, manifest=manifest)

            hostctl_source.unlink()
            shutil.copy2(ROOT / "infra/docker/hostctl.py", hostctl_source)
            for extra in (
                http_root / "ztp/config/cumulus/template/03-templates-j2/evil.yaml.j2",
                http_root / "ztp/config/cumulus/default_evil.yaml",
            ):
                extra.write_text("unsafe extra discovery input\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    activate.ActivationError, "membership.*rebuild",
                ):
                    activate.validate_image_source_contract(settings, manifest=manifest)
                extra.unlink()

            for relative in (
                "DAY0-Prepare/11-load.py",
                "ztp/config/cumulus/template/03-templates-j2/border.yaml.j2",
            ):
                changed = http_root / relative
                original_bytes = changed.read_bytes()
                changed.write_bytes(original_bytes + b"\n# injected drift\n")
                with self.assertRaisesRegex(activate.ActivationError, "rebuild"):
                    activate.validate_image_source_contract(settings, manifest=manifest)
                changed.write_bytes(original_bytes)

            noncoupled = http_root / "DAY0-Prepare/11-load.py"
            original_noncoupled = noncoupled.read_bytes()
            noncoupled.write_bytes(original_noncoupled + b"\n# compatible update\n")
            activate.write_image_source_manifest(http_root, live_manifest)
            activate.validate_image_source_contract(settings, manifest=manifest)
            noncoupled.write_bytes(original_noncoupled)

            coupled = http_root / "infra/docker/hostctl.py"
            original_coupled = coupled.read_bytes()
            coupled.write_bytes(original_coupled + b"\n# incompatible infra update\n")
            activate.write_image_source_manifest(http_root, live_manifest)
            with self.assertRaisesRegex(
                activate.ActivationError, "image-coupled|compatible image",
            ):
                activate.validate_image_source_contract(settings, manifest=manifest)
            coupled.write_bytes(original_coupled)
            activate.write_image_source_manifest(http_root, live_manifest)

        for name in ("entrypoint.py", "hostctl.py", "healthcheck.py"):
            source = (DOCKER_ROOT / name).read_text(encoding="utf-8")
            self.assertIn("validate_image_source_contract", source)

        main = (DOCKER_ROOT / "activate.py").read_text(encoding="utf-8").split(
            "def main(", 1,
        )[1]
        self.assertLess(
            main.index("validate_image_source_contract"),
            main.index("exec_managed_service"),
        )

    def test_remote_build_verifies_local_manifest_and_cannot_self_sign_stale_source(self) -> None:
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in activate.IMAGE_SOURCE_SCAN_ROOTS:
                path = root / directory
                path.mkdir(parents=True)
                (path / "fixture.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "DAY0-Prepare/template").mkdir(parents=True)
            (root / "DAY0-Prepare/11-load.py").write_text(
                "print('load')\n", encoding="utf-8",
            )
            (root / CONTAINER_TOPLEVEL_LOCK).write_bytes(
                (ROOT / CONTAINER_TOPLEVEL_LOCK).read_bytes()
            )
            manifest = root / "local-authority.json"
            activate.write_image_source_manifest(root, manifest)
            self.assertEqual(0, activate.main([
                "verify-source-manifest", "--source-root", os.fspath(root),
                "--manifest", os.fspath(manifest),
            ]))
            (root / "ztp/evil.yaml.j2").write_text(
                "malicious stale remote template\n", encoding="utf-8",
            )
            self.assertEqual(2, activate.main([
                "verify-source-manifest", "--source-root", os.fspath(root),
                "--manifest", os.fspath(manifest),
            ]))

    def test_preloaded_probe_binds_ubuntu_os_live_manifest_and_source_tree(self) -> None:
        activate = load_script("activate.py")
        self.assertEqual(
            frozenset(IMAGE_COUPLED_SOURCE_PATHS_EXPECTED),
            activate.IMAGE_COUPLED_SOURCE_PATHS,
        )
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_root = base / "html"
            for directory in activate.IMAGE_SOURCE_SCAN_ROOTS:
                path = source_root / directory
                path.mkdir(parents=True)
                (path / "fixture.py").write_text("VALUE = 1\n", encoding="utf-8")
            (source_root / "DAY0-Prepare/template").mkdir(parents=True)
            (source_root / "DAY0-Prepare/11-load.py").write_text(
                "print('load')\n", encoding="utf-8",
            )
            for relative in IMAGE_COUPLED_SOURCE_PATHS_EXPECTED:
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"fixture for {relative}\n", encoding="utf-8")
            runtime_contract = source_root / "infra/docker/runtime-contract.json"
            runtime_contract.write_text(
                json.dumps({
                    "schema_version": 1,
                    "compatible_image_contracts": ["3"],
                }) + "\n",
                encoding="ascii",
            )
            image_manifest = base / "image-source.sha256"
            activate.write_image_source_manifest(source_root, image_manifest)
            live_manifest = (
                source_root / "infra/docker/deployment-source-manifest.json"
            )
            live_manifest.parent.mkdir(parents=True, exist_ok=True)
            live_manifest.write_bytes(image_manifest.read_bytes())
            os_release = base / "etc/os-release"
            canonical_os_release = base / "usr/lib/os-release"
            os_release.parent.mkdir()
            canonical_os_release.parent.mkdir(parents=True)
            canonical_os_release.write_text(
                'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n',
                encoding="ascii",
            )
            os_release.symlink_to("../usr/lib/os-release")

            verified = activate.verify_deployment_image(
                source_root, image_manifest, os_release=os_release,
            )
            self.assertGreater(len(verified), 3)

            live_manifest.write_bytes(b'{"schema_version":1,"files":[]}\n')
            with self.assertRaisesRegex(
                activate.ActivationError, "deployment source manifest.*authority",
            ):
                activate.verify_deployment_image(
                    source_root, image_manifest, os_release=os_release,
                )
            live_manifest.write_bytes(image_manifest.read_bytes())

            (source_root / "monitor/fixture.py").write_text(
                "VALUE = 2\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(activate.ActivationError, "source.*drift"):
                activate.verify_deployment_image(
                    source_root, image_manifest, os_release=os_release,
                )

            activate.write_image_source_manifest(source_root, live_manifest)
            compatible = activate.verify_deployment_image(
                source_root, image_manifest, os_release=os_release,
            )
            self.assertGreater(len(compatible), 3)

            coupled = source_root / "infra/docker/hostctl.py"
            original_coupled = coupled.read_bytes()
            coupled.write_bytes(original_coupled + b"incompatible\n")
            activate.write_image_source_manifest(source_root, live_manifest)
            with self.assertRaisesRegex(
                activate.ActivationError, "image-coupled|compatible image",
            ):
                activate.verify_deployment_image(
                    source_root, image_manifest, os_release=os_release,
                )
            coupled.write_bytes(original_coupled)

            runtime_contract.write_text(
                '{"schema_version":1,"compatible_image_contracts":["2"]}\n',
                encoding="ascii",
            )
            activate.write_image_source_manifest(source_root, live_manifest)
            with self.assertRaisesRegex(
                activate.ActivationError, "image contract|compatible",
            ):
                activate.verify_deployment_image(
                    source_root, image_manifest, os_release=os_release,
                )

            for malformed_contracts in (
                ["3", "3"],
                ["3", {"not": "a contract identifier"}],
                ["3", ["nested"]],
            ):
                with self.subTest(malformed_contracts=malformed_contracts):
                    runtime_contract.write_text(
                        json.dumps({
                            "schema_version": 1,
                            "compatible_image_contracts": malformed_contracts,
                        }) + "\n",
                        encoding="ascii",
                    )
                    activate.write_image_source_manifest(
                        source_root, live_manifest,
                    )
                    with self.assertRaisesRegex(
                        activate.ActivationError, "compatibility contract.*invalid",
                    ):
                        activate.verify_deployment_image(
                            source_root, image_manifest, os_release=os_release,
                        )

            (source_root / "monitor/fixture.py").write_text(
                "VALUE = 1\n", encoding="utf-8",
            )
            canonical_os_release.write_text(
                'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\n',
                encoding="ascii",
            )
            with self.assertRaisesRegex(activate.ActivationError, "Ubuntu 24.04"):
                activate.verify_deployment_image(
                    source_root, image_manifest, os_release=os_release,
                )

    def test_container_os_release_allows_only_the_canonical_safe_alias(self) -> None:
        activate = load_script("activate.py")
        ubuntu = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            etc = base / "etc"
            canonical = base / "usr/lib/os-release"
            etc.mkdir()
            canonical.parent.mkdir(parents=True)
            canonical.write_text(ubuntu, encoding="ascii")
            alias = etc / "os-release"
            alias.symlink_to("../usr/lib/os-release")
            self.assertEqual(
                {"ID": "ubuntu", "VERSION_ID": "24.04"},
                dict(activate._container_os_release(alias)),
            )

        unsafe_aliases = (
            "../../outside/os-release",
            "/usr/lib/os-release",
            "../usr/lib/../lib/os-release",
        )
        for target in unsafe_aliases:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                (base / "etc").mkdir()
                alias = base / "etc/os-release"
                alias.symlink_to(target)
                with self.assertRaisesRegex(
                    activate.ActivationError, "canonical.*alias",
                ):
                    activate._container_os_release(alias)

        for unsafe_kind in ("hardlink", "terminal-symlink", "fifo"):
            with self.subTest(kind=unsafe_kind), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                etc = base / "etc"
                canonical = base / "usr/lib/os-release"
                etc.mkdir()
                canonical.parent.mkdir(parents=True)
                if unsafe_kind == "hardlink":
                    canonical.write_text(ubuntu, encoding="ascii")
                    os.link(canonical, base / "second-link")
                elif unsafe_kind == "terminal-symlink":
                    alternate = base / "usr/lib/os-release.real"
                    alternate.write_text(ubuntu, encoding="ascii")
                    canonical.symlink_to("os-release.real")
                else:
                    os.mkfifo(canonical)
                alias = etc / "os-release"
                alias.symlink_to("../usr/lib/os-release")
                with self.assertRaisesRegex(
                    activate.ActivationError, "canonical|bounded regular",
                ):
                    activate._container_os_release(alias)

    def test_activation_binds_project_inventory_and_output_symlink_targets(self) -> None:
        activate = load_script("activate.py")
        self.assertEqual(
            set(REQUIRED_PUBLISHED_LINKS),
            {relative.as_posix() for relative, _target, _resolved in activate.PUBLISHED_RUNTIME_LINKS},
        )
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "html"
            project = http_root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "02-dhcp-subnet_config.csv").write_text(
                "network,netmask,interface\n", encoding="utf-8",
            )
            for relative, (target_template, resolved_name, kind) in (
                REQUIRED_PUBLISHED_LINKS.items()
            ):
                resolved = project / resolved_name
                if kind == "dir":
                    resolved.mkdir(parents=True, exist_ok=True)
                else:
                    resolved.parent.mkdir(parents=True, exist_ok=True)
                    if not resolved.exists():
                        resolved.write_text(
                            f"independent fixture for {resolved_name}\n",
                            encoding="utf-8",
                        )
                link = http_root / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target_template.format(project="site-a"))
            for dynamic_relative, (dynamic_target, dynamic_resolved) in (
                REQUIRED_DYNAMIC_P2P_LINKS.items()
            ):
                dynamic_link = http_root / dynamic_relative
                dynamic_link.parent.mkdir(parents=True, exist_ok=True)
                dynamic_link.symlink_to(dynamic_target.format(project="site-a"))
                dynamic_file = project / dynamic_resolved
                dynamic_file.parent.mkdir(parents=True, exist_ok=True)
                if dynamic_file.suffix == ".xlsx":
                    workbook = project / "fixture-p2p.xlsx"
                    workbook.write_text("fixture workbook\n", encoding="utf-8")
                    dynamic_file.symlink_to(workbook.name)
                else:
                    dynamic_file.write_text("{}\n", encoding="utf-8")
            settings = activate.Settings(
                project_name="site-a", scope="air", http_root=http_root,
            )
            identity = activate.published_link_identity(settings)
            self.assertEqual(
                set(REQUIRED_PUBLISHED_LINKS) | set(REQUIRED_DYNAMIC_P2P_LINKS),
                set(identity),
            )
            self.assertEqual(
                "DAY0-Prepare/site-a/01-global.yaml",
                identity["monitor/01-global.yaml"]["resolved"],
            )
            air_relative = "ztp/config/isc-dhcp-server/p2p-air.json"
            air_target = REQUIRED_DYNAMIC_P2P_LINKS[air_relative][0]
            dynamic_link = http_root / air_relative
            self.assertEqual(
                air_target.format(project="site-a"),
                identity[air_relative]["target"],
            )
            original_air_sha = identity[air_relative]["sha256"]
            (project / "99-output-p2p/fixture-p2p-air.json").write_text(
                '{"changed": true}\n', encoding="utf-8",
            )
            self.assertNotEqual(
                original_air_sha,
                activate.published_link_identity(settings)[air_relative]["sha256"],
            )

            dynamic_link.unlink()
            wrong_air = http_root / "DAY0-Prepare/site-b/99-output-p2p/fixture-p2p-air.json"
            wrong_air.parent.mkdir(parents=True, exist_ok=True)
            wrong_air.write_text("{}\n", encoding="utf-8")
            dynamic_link.symlink_to(
                "../../../DAY0-Prepare/site-b/99-output-p2p/fixture-p2p-air.json",
            )
            with self.assertRaisesRegex(activate.ActivationError, "current project|canonical"):
                activate.published_link_identity(settings)
            dynamic_link.unlink()
            dynamic_link.symlink_to(air_target.format(project="site-a"))

            # A collector's first-level CSV pointer cannot silently select a
            # different project even when its static monitor alias is intact.
            wrong = http_root / "DAY0-Prepare/site-b/01-global.yaml"
            wrong.parent.mkdir(parents=True, exist_ok=True)
            wrong.write_text("version: 2\n", encoding="utf-8")
            link = http_root / "ethernet/eth.csv"
            link.unlink()
            link.symlink_to("../DAY0-Prepare/site-b/01-global.yaml")
            with self.assertRaisesRegex(activate.ActivationError, "project"):
                activate.published_link_identity(settings)

            link.unlink()
            link.symlink_to(
                REQUIRED_PUBLISHED_LINKS["ethernet/eth.csv"][0].format(
                    project="site-a",
                ),
            )
            escaped = http_root / "infiniband/monitor/ib.csv"
            escaped.unlink()
            escaped.symlink_to("../../../../outside.csv")
            with self.assertRaisesRegex(activate.ActivationError, "unsafe|escape"):
                activate.published_link_identity(settings)

            escaped.unlink()
            escaped.symlink_to("../ib.csv")
            tampered = http_root / "nvlink/monitor/nvsw.csv"
            tampered.unlink()
            os.link(project / "02-devices_config.csv", tampered)
            with self.assertRaisesRegex(activate.ActivationError, "symlink|real regular"):
                activate.published_link_identity(settings)

            tampered.unlink()
            tampered.symlink_to("../nvsw.csv")
            missing = http_root / "ethernet/monitor/spx-link"
            missing.unlink()
            with self.assertRaisesRegex(activate.ActivationError, "missing"):
                activate.published_link_identity(settings)


class HealthContractTests(QuietContractTest):
    def test_supervisor_status_requires_exact_running_state(self) -> None:
        health = load_script("healthcheck.py")
        states = health.parse_supervisor_status(
            "apache2 RUNNING pid 7, uptime 0:01:00\n"
            "dhcpd STOPPED Not started\n"
        )
        self.assertEqual("RUNNING", states["apache2"])
        self.assertEqual("STOPPED", states["dhcpd"])
        with self.assertRaisesRegex(health.HealthError, "dhcpd.*STOPPED"):
            health.require_running(states, ("apache2", "dhcpd"))

        source = (DOCKER_ROOT / "healthcheck.py").read_text(encoding="utf-8")
        self.assertIn('("rsyslog", "logrotate", "runtime-guardian")', source)

    def test_health_supervisor_pid_parses_exact_supervisor_425_results(self) -> None:
        """Supervisor 4.2.5 uses LSB NOT_RUNNING=7 with stdout ``0``."""
        health = load_script("healthcheck.py")
        accepted = (
            (0, "271\n", "", 271),
            (7, "0\n", "", 0),
        )
        for returncode, stdout, stderr, expected in accepted:
            with self.subTest(accepted=(returncode, stdout)):
                result = SimpleNamespace(
                    returncode=returncode, stdout=stdout, stderr=stderr,
                )
                with mock.patch.object(
                    health.subprocess, "run", return_value=result,
                ) as runner:
                    self.assertEqual(expected, health._supervisor_pid("apache2"))
                runner.assert_called_once_with(
                    ["supervisorctl", "pid", "apache2"],
                    capture_output=True, text=True, check=False, timeout=8,
                )

        rejected = (
            (0, "0\n", ""),
            (0, "271\n", "warning/error\n"),
            (7, "271\n", ""),
            (7, "0\n", "supervisor transport error\n"),
            (3, "0\n", ""),
            (1, "0\n", ""),
            (7, "", ""),
            (7, "not-a-pid\n", ""),
            (0, "-1\n", ""),
            (0, "+271\n", ""),
            (0, "0271\n", ""),
            (0, " 271\n", ""),
            (0, "271", ""),
            (0, "271\n272\n", ""),
            (0, "999999999999999999999999\n", ""),
        )
        for returncode, stdout, stderr in rejected:
            with self.subTest(rejected=(returncode, stdout, stderr)):
                result = SimpleNamespace(
                    returncode=returncode, stdout=stdout, stderr=stderr,
                )
                with mock.patch.object(
                    health.subprocess, "run", return_value=result,
                ):
                    with self.assertRaises(health.HealthError):
                        health._supervisor_pid("apache2")

    def test_markerless_inactive_accepts_only_stable_pid_zero_terminal_states(self) -> None:
        health = load_script("healthcheck.py")
        selected = plan(names=(), indexes=(), endpoints=())
        control = {
            "rsyslog": "RUNNING", "logrotate": "RUNNING",
            "runtime-guardian": "RUNNING",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(
                rebuild_required=root / "rebuild-required.json",
                guardian_fault=root / "guardian-fault.json",
                quarantine_marker=root / "quarantine.json",
            )
            for abnormal in ("STARTING", "BACKOFF", "MISSING"):
                with self.subTest(abnormal=abnormal):
                    states = {
                        **control,
                        **{
                            service: "STOPPED"
                            for service in health.activate.MANAGED_SERVICES
                        },
                    }
                    if abnormal == "MISSING":
                        states.pop("dhcpd")
                    else:
                        states["dhcpd"] = abnormal
                    with mock.patch.object(
                        health.activate.Settings, "from_environment",
                        return_value=settings,
                    ), mock.patch.object(
                        health.activate, "validate_python_runtime",
                    ), mock.patch.object(
                        health.activate, "require_monitor_authority",
                    ), mock.patch.object(
                        health.activate, "validate_image_source_contract",
                    ), mock.patch.object(
                        health.activate, "observe_runtime",
                        return_value=(selected, object(), {}, ""),
                    ), mock.patch.object(
                        health, "_load_runtime_state", return_value={},
                    ), mock.patch.object(
                        health, "_supervisor_states", return_value=states,
                    ), mock.patch.object(
                        health, "_supervisor_pid", return_value=0,
                    ), mock.patch.object(
                        health.activate, "validate_control_cgi",
                    ), mock.patch.object(
                        health.activate, "read_activation_marker", return_value=None,
                    ):
                        with self.assertRaisesRegex(
                            health.HealthError,
                            rf"inactive runtime.*dhcpd.*{abnormal}",
                        ):
                            health.check_runtime()

            for terminal in ("STOPPED", "EXITED", "FATAL"):
                with self.subTest(terminal=terminal):
                    states = {
                        **control,
                        **{service: "STOPPED" for service in health.activate.MANAGED_SERVICES},
                    }
                    states["dhcpd"] = terminal
                    with mock.patch.object(
                        health.activate.Settings, "from_environment",
                        return_value=settings,
                    ), mock.patch.object(
                        health.activate, "validate_python_runtime",
                    ), mock.patch.object(
                        health.activate, "require_monitor_authority",
                    ), mock.patch.object(
                        health.activate, "validate_image_source_contract",
                    ), mock.patch.object(
                        health.activate, "observe_runtime",
                        return_value=(selected, object(), {}, ""),
                    ), mock.patch.object(
                        health, "_load_runtime_state", return_value={},
                    ), mock.patch.object(
                        health, "_supervisor_states", return_value=states,
                    ), mock.patch.object(
                        health, "_supervisor_pid", return_value=0,
                    ), mock.patch.object(
                        health.activate, "validate_control_cgi",
                    ), mock.patch.object(
                        health.activate, "read_activation_marker", return_value=None,
                    ):
                        self.assertIn("healthy inactive", health.check_runtime())

            states = {
                **control,
                **{service: "STOPPED" for service in health.activate.MANAGED_SERVICES},
            }
            states["dhcpd"] = "EXITED"
            with mock.patch.object(
                health.activate.Settings, "from_environment", return_value=settings,
            ), mock.patch.object(
                health.activate, "validate_python_runtime",
            ), mock.patch.object(
                health.activate, "require_monitor_authority",
            ), mock.patch.object(
                health.activate, "validate_image_source_contract",
            ), mock.patch.object(
                health.activate, "observe_runtime",
                return_value=(selected, object(), {}, ""),
            ), mock.patch.object(
                health, "_load_runtime_state", return_value={},
            ), mock.patch.object(
                health, "_supervisor_states", return_value=states,
            ), mock.patch.object(
                health, "_supervisor_pid",
                side_effect=lambda service: 99 if service == "dhcpd" else 0,
            ), mock.patch.object(
                health.activate, "validate_control_cgi",
            ), mock.patch.object(
                health.activate, "read_activation_marker", return_value=None,
            ):
                with self.assertRaisesRegex(health.HealthError, "dhcpd.*pid=99"):
                    health.check_runtime()

    def test_markerless_health_rejects_abandoned_precommit_start_authority(self) -> None:
        health = load_script("healthcheck.py")
        selected = plan(names=(), indexes=(), endpoints=())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            precommit = root / "precommit-activation.json"
            precommit.write_text('{"start_authority":"precommit"}\n', encoding="utf-8")
            settings = SimpleNamespace(
                rebuild_required=root / "rebuild-required.json",
                guardian_fault=root / "guardian-fault.json",
                quarantine_marker=root / "quarantine.json",
                precommit_marker=precommit,
            )
            states = {
                "rsyslog": "RUNNING", "logrotate": "RUNNING",
                "runtime-guardian": "RUNNING",
                **{
                    service: "STOPPED"
                    for service in health.activate.MANAGED_SERVICES
                },
            }
            with mock.patch.object(
                health.activate.Settings, "from_environment", return_value=settings,
            ), mock.patch.object(
                health.activate, "validate_python_runtime",
            ), mock.patch.object(
                health.activate, "require_monitor_authority",
            ), mock.patch.object(
                health.activate, "validate_image_source_contract",
            ), mock.patch.object(
                health.activate, "observe_runtime",
                return_value=(selected, object(), {}, ""),
            ), mock.patch.object(
                health, "_load_runtime_state", return_value={},
            ), mock.patch.object(
                health, "_supervisor_states", return_value=states,
            ), mock.patch.object(
                health, "_supervisor_pid", return_value=0,
            ), mock.patch.object(
                health.activate, "validate_control_cgi",
            ), mock.patch.object(
                health.activate, "read_activation_marker", return_value=None,
            ):
                with self.assertRaisesRegex(
                    health.HealthError, "precommit.*abandoned|start authority",
                ):
                    health.check_runtime()

    def test_active_contract_requires_every_unselected_service_exactly_stopped(self) -> None:
        health = load_script("healthcheck.py")
        selected = plan(names=(), indexes=(), endpoints=())
        control = {
            "rsyslog": "RUNNING", "logrotate": "RUNNING",
            "runtime-guardian": "RUNNING",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(
                rebuild_required=root / "rebuild-required.json",
                guardian_fault=root / "guardian-fault.json",
                quarantine_marker=root / "quarantine.json",
            )
            for abnormal in ("STARTING", "BACKOFF", "MISSING"):
                with self.subTest(abnormal=abnormal):
                    states = {
                        **control,
                        **{
                            service: "STOPPED"
                            for service in health.activate.MANAGED_SERVICES
                        },
                    }
                    if abnormal == "MISSING":
                        states.pop("dhcpd")
                    else:
                        states["dhcpd"] = abnormal
                    with mock.patch.object(
                        health.activate.Settings, "from_environment",
                        return_value=settings,
                    ), mock.patch.object(
                        health.activate, "validate_python_runtime",
                    ), mock.patch.object(
                        health.activate, "require_monitor_authority",
                    ), mock.patch.object(
                        health.activate, "validate_image_source_contract",
                    ), mock.patch.object(
                        health.activate, "observe_runtime",
                        return_value=(selected, object(), {}, ""),
                    ), mock.patch.object(
                        health, "_load_runtime_state", return_value={},
                    ), mock.patch.object(
                        health, "_supervisor_states", return_value=states,
                    ), mock.patch.object(
                        health, "_supervisor_pid", return_value=0,
                    ), mock.patch.object(
                        health.activate, "validate_control_cgi",
                    ), mock.patch.object(
                        health.activate, "read_activation_marker", return_value=None,
                    ):
                        with self.assertRaisesRegex(
                            health.HealthError, rf"unexpected.*dhcpd.*{abnormal}",
                        ):
                            health.check_runtime(expected_services=())

    def test_dhcp_process_must_have_the_exact_explicit_interface_suffix(self) -> None:
        health = load_script("healthcheck.py")
        expected = (
            "/usr/sbin/dhcpd", "-4", "-f", "-cf",
            "/etc/dhcp/dhcpd.conf", "-lf", "/var/lib/dhcp/dhcpd.leases",
            "-pf", "/run/http-ztp/dhcpd.pid",
            "eno2", "eno3.114",
        )
        health.require_exact_argv(expected, expected)
        with self.assertRaisesRegex(health.HealthError, "argv"):
            health.require_exact_argv(expected[:-1], expected)

    def test_entrypoint_and_healthcheck_have_no_host_service_manager_fallback(self) -> None:
        combined = "\n".join(
            (DOCKER_ROOT / name).read_text(encoding="utf-8")
            for name in ("entrypoint.py", "activate.py", "healthcheck.py")
        )
        self.assertNotIn("systemctl", combined)
        self.assertNotIn("journalctl", combined)

    def test_healthcheck_is_read_only_and_ignores_unrelated_snapshot_churn(self) -> None:
        health_source = (DOCKER_ROOT / "healthcheck.py").read_text(encoding="utf-8")
        self.assertNotIn("prepare_runtime(", health_source)
        health = load_script("healthcheck.py")
        saved = {
            "schema_version": 1, "project": "site-a", "scope": "air",
            "subnet_sha256": "a" * 64,
            "listener_names": ["eno2"], "listener_ifindexes": [7],
            "direct_shared_networks": ["direct"],
            "relay_shared_networks": [], "endpoint_ips": ["192.0.2.10"],
            "apache_listener_sha256": "b" * 64,
            "link_snapshot_sha256": "old", "address_snapshot_sha256": "old",
        }
        current = dict(saved)
        current["link_snapshot_sha256"] = "new-unrelated-veth"
        current["address_snapshot_sha256"] = "new-unrelated-veth-address"
        health.require_current_plan(saved, current)

    def test_quarantine_or_unsafe_guardian_lock_is_reported_unhealthy(self) -> None:
        health = load_script("healthcheck.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(
                rebuild_required=root / "rebuild-required.json",
                quarantine_marker=root / "quarantine.json",
                guardian_fault=root / "guardian-fault.json",
            )
            with mock.patch.object(
                health.activate.Settings, "from_environment", return_value=settings,
            ), mock.patch.object(
                health.activate, "validate_python_runtime",
            ), mock.patch.object(
                health.activate, "require_monitor_authority",
            ), mock.patch.object(health.activate, "validate_image_source_contract"):
                settings.quarantine_marker.write_text("{}\n", encoding="utf-8")
                with self.assertRaisesRegex(health.HealthError, "quarantined"):
                    health.check_runtime()
                settings.quarantine_marker.unlink()
                settings.guardian_fault.write_text("{}\n", encoding="utf-8")
                with self.assertRaisesRegex(health.HealthError, "guardian.*lock"):
                    health.check_runtime()

    def test_rebuild_required_is_persistent_and_public_health_fails_closed(self) -> None:
        health = load_script("healthcheck.py")
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "rebuild-required.json"
            marker.write_text('{"schema_version":1}\n', encoding="utf-8")
            settings = SimpleNamespace(rebuild_required=marker)
            with mock.patch.object(
                health.activate.Settings, "from_environment", return_value=settings,
            ), mock.patch.object(
                health.activate, "validate_python_runtime",
            ), mock.patch.object(
                health.activate, "require_monitor_authority",
            ), mock.patch.object(
                health.activate, "validate_image_source_contract",
            ), mock.patch.object(health.activate, "observe_runtime") as observe:
                with self.assertRaisesRegex(health.HealthError, "rebuild|deploy"):
                    health.check_runtime()
            observe.assert_not_called()


class ContainerTransactionContractTests(QuietContractTest):
    def test_public_status_and_health_report_the_exact_control_auth_status(
        self,
    ) -> None:
        expected = {"valid": True, "factory_records_active": False}

        activate = load_script("activate.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        with mock.patch.object(
            activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            activate, "validate_image_source_contract",
        ), mock.patch.object(
            activate, "observe_runtime", return_value=(plan(), object(), {}, ""),
        ), mock.patch.object(
            activate, "verify_control_auth_image_copies", create=True,
        ) as status_attestation, mock.patch.object(
            activate, "require_control_auth", return_value=expected,
        ) as status_auth, mock.patch.object(
            activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(activate, "_print_json") as emit:
            self.assertEqual(3, activate.main(["status"]))
        self.assertEqual(expected, emit.call_args.args[0]["control_auth"])
        status_attestation.assert_called_once_with()
        status_auth.assert_called_once_with(emit_factory_warning=False)

        health = load_script("healthcheck.py")
        with mock.patch.object(
            health.activate, "require_control_auth", return_value=expected,
        ) as health_auth, mock.patch.object(
            health, "check_runtime", return_value="healthy fixture",
        ), mock.patch("builtins.print") as emit:
            self.assertEqual(0, health.main([]))
        payload = json.loads(emit.call_args.args[0])
        self.assertIs(True, payload["healthy"])
        self.assertEqual(expected, payload["control_auth"])
        health_auth.assert_called_once_with(emit_factory_warning=False)

    def test_every_exec_service_attests_image_and_uses_machine_silent_auth(self) -> None:
        activate = load_script("activate.py")
        expected = {"valid": True, "factory_records_active": True}
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        for service in activate.MANAGED_SERVICES:
            with self.subTest(service=service), mock.patch.object(
                activate.Settings, "from_environment", return_value=settings,
            ), mock.patch.object(
                activate, "verify_control_auth_image_copies", create=True,
            ) as attestation, mock.patch.object(
                activate, "validate_image_source_contract",
            ), mock.patch.object(
                activate, "require_control_auth", return_value=expected,
            ) as auth, mock.patch.object(
                activate, "exec_managed_service",
            ) as execute:
                self.assertEqual(0, activate.main(["exec-service", service]))
            attestation.assert_called_once_with()
            auth.assert_called_once_with(emit_factory_warning=False)
            execute.assert_called_once_with(service, settings)

    @with_valid_monitor_authority_fixture
    def test_each_container_lifecycle_fails_before_work_when_control_auth_is_invalid(
        self,
    ) -> None:
        entrypoint = load_script("entrypoint.py")
        entry_settings = SimpleNamespace(http_root=Path("/var/www/html"))
        entry_order = []
        with mock.patch.object(
            entrypoint.activate.Settings, "from_environment",
            return_value=entry_settings,
        ), mock.patch.object(
            entrypoint.hostlock, "safe_lock",
        ) as lock, mock.patch.object(
            entrypoint.activate, "validate_python_runtime",
            side_effect=lambda: entry_order.append("python-runtime"),
        ) as python_runtime, mock.patch.object(
            entrypoint.activate, "verify_control_auth_image_copies", create=True,
            side_effect=lambda: entry_order.append("control-auth-attestation"),
        ) as entry_attestation, mock.patch.object(
            entrypoint.activate, "require_control_auth",
            side_effect=lambda **_kwargs: (
                entry_order.append("control-auth")
                or (_ for _ in ()).throw(
                    entrypoint.activate.ActivationError("invalid auth")
                )
            ),
        ) as entry_auth, mock.patch.object(
            entrypoint.activate, "validate_image_source_contract",
        ) as receipt, mock.patch.object(entrypoint.os, "execv") as execute:
            lock.return_value.__enter__.return_value = 7
            self.assertEqual(2, entrypoint.main([]))
        receipt.assert_not_called()
        execute.assert_not_called()
        entry_attestation.assert_called_once_with()
        entry_auth.assert_called_once_with(emit_factory_warning=False)
        python_runtime.assert_called_once_with()
        self.assertEqual(
            ["python-runtime", "control-auth-attestation", "control-auth"],
            entry_order,
        )

        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        lifecycle = {
            "load": "transactional_load",
            "reload-network": "transactional_reload_network",
            "resume": "resume",
        }
        for action, target in lifecycle.items():
            with self.subTest(action=action), mock.patch.object(
                hostctl.activate.Settings, "from_environment",
                return_value=settings,
            ), mock.patch.object(
                hostctl.activate, "require_control_auth",
                side_effect=hostctl.activate.ActivationError("invalid auth"),
            ) as lifecycle_auth, mock.patch.object(
                hostctl, target,
            ) as operation, mock.patch.object(
                hostctl, "write_resume_status",
            ) as resume_status:
                self.assertEqual(2, hostctl.main([action]))
            operation.assert_not_called()
            lifecycle_auth.assert_called_once_with(emit_factory_warning=False)
            if action == "resume":
                self.assertEqual("failed", resume_status.call_args.args[0])

        health = load_script("healthcheck.py")
        with mock.patch.object(
            health.activate, "require_control_auth",
            side_effect=health.activate.ActivationError("invalid auth"),
        ) as health_auth, mock.patch.object(health, "check_runtime") as check:
            self.assertEqual(1, health.main([]))
        check.assert_not_called()
        health_auth.assert_called_once_with(emit_factory_warning=False)

        activate = load_script("activate.py")
        with mock.patch.object(
            activate.Settings, "from_environment", return_value=settings,
        ), mock.patch.object(
            activate, "validate_image_source_contract",
        ), mock.patch.object(
            activate, "observe_runtime", return_value=(plan(), object(), {}, ""),
        ), mock.patch.object(
            activate, "verify_control_auth_image_copies", create=True,
        ), mock.patch.object(
            activate, "require_control_auth",
            side_effect=activate.ActivationError("invalid auth"),
        ) as status_auth, mock.patch.object(
            activate, "read_activation_marker",
        ) as marker:
            self.assertEqual(2, activate.main(["status"]))
        marker.assert_not_called()
        status_auth.assert_called_once_with(emit_factory_warning=False)

    def test_guardian_revalidates_control_auth_each_round_and_quarantines_immediately(
        self,
    ) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []

        @contextmanager
        def deployment_lock(_root):
            events.append("lock")
            yield 9

        contract = (
            hostctl.hostlock.HostLockError,
            deployment_lock,
            lambda _descriptor: {},
        )
        with mock.patch.object(
            hostctl, "_lock_contract", return_value=contract,
        ), mock.patch.object(
            hostctl.activate, "require_control_auth",
            side_effect=hostctl.activate.ActivationError("invalid auth"),
        ) as auth, mock.patch.object(
            hostctl, "quarantine_inactive_locked",
            side_effect=lambda _settings, _reason: events.append("quarantine"),
        ), mock.patch.object(hostctl, "guardian_step") as step, \
                self.assertRaises(hostctl.GuardianFatalError):
            hostctl.guardian_loop(settings, interval=1)
        auth.assert_called_once_with(emit_factory_warning=False)
        step.assert_not_called()
        self.assertEqual(["lock", "quarantine"], events)

    def test_container_controller_holds_and_inherits_one_deployment_lock(self) -> None:
        source = (DOCKER_ROOT / "hostctl.py").read_text(encoding="utf-8")
        self.assertIn("hostlock.safe_lock", source)
        self.assertIn("inherited_lock_subprocess_kwargs", source)
        self.assertNotIn("from deployment_lock import", source)
        self.assertIn("activate.prepare_runtime", source)
        self.assertIn("11-load.py", source)
        self.assertIn("healthcheck.check_runtime", source)
        self.assertIn("activate.commit_activation", source)
        self.assertIn("--skip-infra", source)
        self.assertNotIn('"--start-services"', source)
        self.assertNotIn('"--start-ztp-monitor"', source)
        self.assertIn("publish_precommit_activation", source)

    def test_container_child_generates_only_and_hostctl_owns_service_convergence(self) -> None:
        hostctl = load_script("hostctl.py")
        air_mini = SimpleNamespace(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope="air", switch_scope="eth", mini=True, monitor_interval=30,
        )
        self.assertEqual((
            "/usr/bin/python3", "-u",
            "/var/www/html/DAY0-Prepare/11-load.py", "site-a",
            "--skip-infra",
            "--deployment-scope", "air",
            "--switch", "eth",
            "--mini",
            "--ztp-monitor-scope", "air",
            "--ztp-monitor-interval", "30",
        ), hostctl.load_command(air_mini))

        prod_all = SimpleNamespace(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope="prod", switch_scope="all", mini=False, monitor_interval=45,
        )
        prod_command = hostctl.load_command(prod_all)
        self.assertEqual("prod", prod_command[prod_command.index(
            "--deployment-scope"
        ) + 1])
        self.assertNotIn("--switch", prod_command)
        self.assertNotIn("--mini", prod_command)
        self.assertNotIn("--start-services", prod_command)
        self.assertNotIn("--start-ztp-monitor", prod_command)

        prod_ib = SimpleNamespace(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope="prod", switch_scope="ib", mini=False, monitor_interval=30,
        )
        ib_command = hostctl.load_command(prod_ib)
        self.assertEqual("ib", ib_command[ib_command.index("--switch") + 1])

        no_upgrade = hostctl.load_command(prod_ib, no_upgrade=True)
        self.assertEqual(1, no_upgrade.count("--no-upgrade"))
        parsed = hostctl.parser().parse_args(["load", "--no-upgrade"])
        self.assertTrue(parsed.no_upgrade)
        for action in ("unload", "resume", "ready", "guardian"):
            with self.subTest(action=action), redirect_stderr(io.StringIO()), \
                    mock.patch.object(
                        hostctl.activate.Settings, "from_environment",
                    ) as settings, self.assertRaises(SystemExit):
                hostctl.main([action, "--no-upgrade"])
            settings.assert_not_called()

    def test_deploy_no_upgrade_is_explicit_and_forwarded_only_to_load(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        self.assertFalse(os.path.lexists(DOCKER_ROOT / "README.md"))
        documentation = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        usage = source.split("usage() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("deploy [--no-upgrade]", usage)
        self.assertIn("deploy-preloaded IMAGE_ID [--no-upgrade]", usage)
        run_load = source.split("run_load() {", 1)[1].split("\n}", 1)[0]
        self.assertIn('hostctl.py load "$@"', run_load)
        deploy = source.rsplit("  deploy)", 1)[1].split("    ;;", 1)[0]
        preloaded = source.rsplit("  deploy-preloaded)", 1)[1].split("    ;;", 1)[0]
        project_preloaded = source.rsplit(
            "  deploy-project-preloaded)", 1,
        )[1].split("    ;;", 1)[0]
        self.assertIn('run_load "$started_container_id" "${load_options[@]}"', deploy)
        self.assertIn('run_load "$started_container_id" "${load_options[@]}"', preloaded)
        self.assertIn(
            'run_load "$started_container_id" "${load_options[@]}"',
            project_preloaded,
        )
        self.assertIn("project_upgrade_policy=enabled", project_preloaded)
        self.assertIn("project_upgrade_policy=disabled", project_preloaded)
        self.assertIn(
            'verify_preloaded_image "$2" project "$HTTP_ZTP_PROJECT" '
            '"$project_upgrade_policy"',
            project_preloaded,
        )
        verifier = source.split("verify_preloaded_image() {", 1)[1].split(
            "\n}", 1,
        )[0]
        self.assertIn("expected_upgrade_policy=${4:-}", verifier)
        self.assertIn(
            'flavor_args+=(--expected-upgrade-policy "$expected_upgrade_policy")',
            verifier,
        )
        for action in ("doctor", "build", "load", "health", "status", "logs", "unload", "down"):
            with self.subTest(action=action):
                body = source.split(f"  {action})", 1)[1].split("    ;;", 1)[0]
                self.assertNotIn("load_options", body)
        self.assertIn("`--no-upgrade` 不含 switch image", documentation)
        self.assertIn("只能使用带 `--no-upgrade` 的命令", documentation)

    def test_container_selection_round_trips_through_real_load_parser(self) -> None:
        hostctl = load_script("hostctl.py")
        activate = load_script("activate.py")
        load_path = ROOT / "DAY0-Prepare/11-load.py"
        spec = importlib.util.spec_from_file_location(
            "container_load_parser_contract", load_path,
        )
        assert spec is not None and spec.loader is not None
        load = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = load
        spec.loader.exec_module(load)

        example_environment = {}
        for raw_line in (DOCKER_ROOT / "container.env.example").read_text(
            encoding="utf-8",
        ).splitlines():
            if raw_line and not raw_line.startswith("#"):
                key, value = raw_line.split("=", 1)
                example_environment[key] = value
        example_environment["HTTP_ZTP_PROJECT"] = "site-a"
        example_environment["HTTP_ZTP_MINI"] = "enabled"

        for environment, expected in (
            (example_environment,
             ("air", "eth", load.MINI_AIR_DEVICES_NAME, "air")),
            ({
                "HTTP_ZTP_PROJECT": "site-a",
                "HTTP_ZTP_SCOPE": "prod",
                "HTTP_ZTP_SWITCH_SCOPE": "nvl",
                "HTTP_ZTP_MINI": "disabled",
                "HTTP_ZTP_MONITOR_INTERVAL": "45",
            }, ("prod", "nvl", None, "prod")),
        ):
            with self.subTest(expected=expected):
                settings = activate.Settings.from_environment(environment)
                command = hostctl.load_command(settings)
                parsed = load.parse_args(list(command[3:]))
                deployment_scope = load.validate_deployment_scope_options(parsed)
                switch_scope = load.validate_switch_scope_options(
                    parsed, deployment_scope,
                )
                self.assertEqual(
                    expected,
                    (
                        deployment_scope, switch_scope, parsed.mini,
                        parsed.ztp_monitor_scope,
                    ),
                )

    @with_valid_monitor_authority_fixture
    def test_no_start_load_initializes_controls_before_worker_convergence(self) -> None:
        """Exercise hostctl's real no-start child boundary on a fresh tree."""
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            http_root = Path(temporary) / "html"
            (http_root / "ztp").mkdir(parents=True)
            (http_root / "monitor/status").mkdir(parents=True)
            settings = SimpleNamespace(
                http_root=http_root, project_name="site-a", scope="air",
                switch_scope="eth", mini=False, monitor_interval=30,
            )
            selected = object()
            events = []

            @contextmanager
            def held(_root):
                yield 41

            def no_start_generation(command, *_args):
                self.assertNotIn("--start-services", command)
                self.assertNotIn("--start-ztp-monitor", command)
                output = http_root / "DAY0-Prepare/site-a/99-output-ztp"
                output.mkdir(parents=True)
                (http_root / "ztp/status").symlink_to(
                    "../DAY0-Prepare/site-a/99-output-ztp"
                )
                events.append("11-load-no-start")

            def converge(_services):
                controls = (
                    http_root / "ztp/status/ztp-monitor.control",
                    http_root / "monitor/status/switch-collection.request",
                    http_root / "monitor/status/manual-ztp.request.json",
                )
                self.assertEqual(
                    ("running\n", "idle\n", '{"requests":[]}\n'),
                    tuple(path.read_text(encoding="utf-8") for path in controls),
                )
                events.append("converge")

            def publish_precommit(_settings, _selected):
                self.assertTrue(
                    (http_root / "ztp/status/ztp-monitor.control").is_file()
                )
                self.assertEqual(
                    "idle\n",
                    (http_root / "monitor/status/switch-collection.request")
                    .read_text(encoding="utf-8"),
                )
                events.append("precommit")

            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl.activate, "restore_mutable_image_sources",
            ), mock.patch.object(
                hostctl.activate, "observe_runtime",
                return_value=(selected, None, {}),
            ), mock.patch.object(hostctl.activate, "clear_activation"), \
                    mock.patch.object(hostctl, "stop_managed_services"), \
                    mock.patch.object(hostctl, "clear_guardian_fault"), \
                    mock.patch.object(hostctl.activate, "install_control_cgi"), \
                    mock.patch.object(
                        hostctl.activate, "prepare_runtime",
                        return_value=(selected, None, {}),
                    ), mock.patch.object(
                        hostctl, "run_child", side_effect=no_start_generation,
                    ), mock.patch.object(
                        hostctl.activate, "expected_services",
                        return_value=(
                            "apache2", "dhcpd", "ztp-monitor",
                            "switch-collection", "manual-ztp",
                        ),
                    ), mock.patch.object(
                        hostctl.activate, "_www_data_gid", create=True,
                        return_value=os.getgid(),
                    ), mock.patch.object(
                        hostctl.activate.os, "fchown",
                        side_effect=lambda _fd, _uid, _gid: None,
                    ), mock.patch.object(
                        hostctl.activate, "publish_precommit_activation",
                        side_effect=publish_precommit,
                    ), mock.patch.object(
                        hostctl, "converge_services", side_effect=converge,
                    ), mock.patch.object(hostctl.healthcheck, "check_runtime"), \
                    mock.patch.object(hostctl.activate, "commit_activation"), \
                    mock.patch.object(hostctl, "clear_quarantine"), \
                    mock.patch.object(hostctl.activate, "clear_rebuild_required"):
                hostctl.transactional_load(settings)
            self.assertEqual(
                ["11-load-no-start", "precommit", "converge"], events,
            )

    @with_valid_monitor_authority_fixture
    def test_load_validates_receipt_only_after_trusted_lock_and_before_observe(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []

        @contextmanager
        def held(_root):
            events.append("lock-enter")
            try:
                yield 31
            finally:
                events.append("lock-release")

        inherited = lambda _descriptor: {}
        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, inherited),
        ), mock.patch.object(
            hostctl.activate, "validate_image_source_contract",
            side_effect=lambda _settings, **_kwargs: events.append("receipt"),
        ), mock.patch.object(
            hostctl.activate, "restore_mutable_image_sources",
            side_effect=lambda _settings: events.append("restore-defaults"),
        ), mock.patch.object(
            hostctl.activate, "observe_runtime",
            side_effect=hostctl.ControllerError("stop after ordering evidence"),
        ), mock.patch.object(
            hostctl, "abort_failed_transaction", side_effect=lambda *_args: None,
        ):
            hostctl.transactional_load(settings)
        self.assertEqual(
            ["lock-enter", "receipt", "restore-defaults", "receipt",
             "restore-defaults", "lock-release"], events,
        )

    def test_child_lifecycle_receives_the_exact_inherited_lock_descriptor(self) -> None:
        hostctl = load_script("hostctl.py")
        observed = {}

        def inherited(descriptor):
            self.assertEqual(19, descriptor)
            return {
                "env": {"HTTP_DEPLOYMENT_LOCK_FD": "19"},
                "pass_fds": (19,),
            }

        def runner(command, **kwargs):
            observed["command"] = tuple(command)
            observed["kwargs"] = kwargs
            return SimpleNamespace(returncode=0)

        hostctl.run_child(("/usr/bin/python3", "11-load.py"), 19, inherited, runner)
        self.assertEqual((19,), observed["kwargs"]["pass_fds"])
        self.assertEqual(
            "19", observed["kwargs"]["env"]["HTTP_DEPLOYMENT_LOCK_FD"],
        )

    @with_valid_monitor_authority_fixture
    def test_successful_load_clears_rebuild_marker_only_after_final_health(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "rebuild-required.json"
            marker.write_text('{"schema_version":1}\n', encoding="utf-8")
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"), rebuild_required=marker,
                project_name="site-a", scope="air", switch_scope="eth",
                mini=False, monitor_interval=30,
            )
            events = []

            @contextmanager
            def held(_root):
                yield 9

            def health(**kwargs):
                events.append(("health", kwargs))
                self.assertTrue(marker.exists())

            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl.activate, "restore_mutable_image_sources",
            ), mock.patch.object(
                hostctl.activate, "observe_runtime", return_value=(object(), None, {}),
            ), mock.patch.object(hostctl, "stop_managed_services"), \
                    mock.patch.object(hostctl.activate, "clear_activation"), \
                    mock.patch.object(hostctl, "clear_guardian_fault"), \
                    mock.patch.object(hostctl.activate, "install_control_cgi"), \
                    mock.patch.object(
                        hostctl.activate, "prepare_runtime",
                        return_value=(object(), None, {}),
                    ), mock.patch.object(hostctl, "run_child"), \
                    mock.patch.object(
                        hostctl.activate, "expected_services", return_value=(),
                    ), mock.patch.object(
                        hostctl.activate, "initialize_worker_control_files",
                    ), mock.patch.object(
                        hostctl.activate, "publish_precommit_activation",
                    ), mock.patch.object(hostctl, "converge_services"), \
                    mock.patch.object(
                        hostctl.healthcheck, "check_runtime", side_effect=health,
                    ), mock.patch.object(hostctl.activate, "commit_activation"), \
                    mock.patch.object(hostctl, "clear_quarantine"), \
                    mock.patch.object(
                        hostctl.activate, "clear_rebuild_required",
                        side_effect=lambda _settings: (
                            events.append(("clear-rebuild", {})), marker.unlink(),
                        ),
                    ):
                hostctl.transactional_load(settings)
            self.assertFalse(marker.exists())
            self.assertEqual("clear-rebuild", events[-1][0])
            self.assertEqual(2, sum(event[0] == "health" for event in events))

    @with_valid_monitor_authority_fixture
    def test_load_withdraws_start_authority_before_stop_and_publishes_candidate_late(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(
            http_root=Path("/var/www/html"), project_name="site-a",
            scope="air", switch_scope="eth", mini=False, monitor_interval=30,
        )
        selected = object()
        events = []

        @contextmanager
        def held(_root):
            yield 23

        def event(name, value=None):
            events.append((name, value))

        def observe(_settings):
            event("observe")
            return selected, None, {}

        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
        ), mock.patch.object(
            hostctl.activate, "validate_image_source_contract",
        ), mock.patch.object(
            hostctl.activate, "restore_mutable_image_sources",
        ), mock.patch.object(
            hostctl.activate, "observe_runtime",
            side_effect=observe,
        ), mock.patch.object(
            hostctl.activate, "clear_activation",
            side_effect=lambda _settings: event("clear-authority"),
        ), mock.patch.object(
            hostctl, "stop_managed_services", side_effect=lambda: event("stop"),
        ), mock.patch.object(hostctl, "clear_guardian_fault"), \
                mock.patch.object(hostctl.activate, "install_control_cgi"), \
                mock.patch.object(
                    hostctl.activate, "prepare_runtime",
                    return_value=(selected, None, {}),
                ), mock.patch.object(
                    hostctl, "run_child", side_effect=lambda *_args: event("generate"),
                ), mock.patch.object(
                    hostctl.activate, "expected_services", return_value=("dhcpd",),
                ), mock.patch.object(
                    hostctl.activate, "initialize_worker_control_files",
                    side_effect=lambda _settings: event("controls"),
                ), mock.patch.object(
                    hostctl.activate, "publish_precommit_activation",
                    side_effect=lambda _settings, _selected: event("precommit"),
                ), mock.patch.object(
                    hostctl, "converge_services",
                    side_effect=lambda _services: event("converge"),
                ), mock.patch.object(hostctl.healthcheck, "check_runtime"), \
                mock.patch.object(
                    hostctl.activate, "commit_activation",
                    side_effect=lambda _settings, _selected: event("commit"),
                ), mock.patch.object(hostctl, "clear_quarantine"), \
                mock.patch.object(hostctl.activate, "clear_rebuild_required"):
            hostctl.transactional_load(settings)
        names = [name for name, _value in events]
        self.assertLess(names.index("clear-authority"), names.index("stop"))
        self.assertLess(names.index("stop"), names.index("generate"))
        self.assertLess(names.index("generate"), names.index("controls"))
        self.assertLess(names.index("controls"), names.index("precommit"))
        self.assertLess(names.index("generate"), names.index("precommit"))
        self.assertLess(names.index("precommit"), names.index("converge"))
        self.assertLess(names.index("converge"), names.index("commit"))

    @with_valid_monitor_authority_fixture
    def test_service_ip_move_replans_and_restarts_dhcp_in_one_load_transaction(self) -> None:
        """A no-source-write NIC move must use the real planner and load boundary."""
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            http_root = root / "html"
            project = http_root / "DAY0-Prepare/site-a"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text(
                "project: independent-service-ip-move\n", encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,mac\nfixture,02:00:00:00:00:01\n", encoding="utf-8",
            )
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet,netmask,ztp_service_ip,"
                "cumulus_profile,nvos_ztp\n"
                "fabric,192.0.2.0,255.255.255.192,192.0.2.50,oob,no\n",
                encoding="utf-8",
            )
            tools = http_root / "tools"
            tools.mkdir()
            shutil.copyfile(
                ROOT / "tools/ztp_service_runtime.py",
                tools / "ztp_service_runtime.py",
            )
            settings = hostctl.activate.Settings(
                project_name="site-a", scope="prod", http_root=http_root,
                state_root=root / "state",
                apache_listeners=root / "apache-listeners.conf",
            )

            links = [
                {
                    "ifindex": 7, "ifname": "eno2",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "address": "02:00:00:00:00:07", "operstate": "UP",
                    "link_type": "ether",
                },
                {
                    "ifindex": 8, "ifname": "eno3",
                    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                    "address": "02:00:00:00:00:08", "operstate": "UP",
                    "link_type": "ether",
                },
            ]

            def address(ifindex, ifname, *values):
                return {
                    "ifindex": ifindex, "ifname": ifname,
                    "addr_info": [
                        {
                            "family": "inet", "local": value,
                            "prefixlen": 26, "scope": "global", "flags": [],
                            "valid_life_time": "forever",
                            "preferred_life_time": "forever",
                        }
                        for value in values
                    ],
                }

            old_addresses = [
                address(7, "eno2", "192.0.2.50"), address(8, "eno3"),
            ]
            moved_addresses = [
                address(7, "eno2"), address(8, "eno3", "192.0.2.50"),
            ]
            old_selected, runtime, old_payload, _old_apache = (
                hostctl.activate.observe_runtime(
                    settings,
                    ActivationContractTests._snapshot_runner(
                        links, old_addresses, links, old_addresses,
                    ),
                )
            )
            moved_selected, _runtime, moved_payload, _moved_apache = (
                hostctl.activate.observe_runtime(
                    settings,
                    ActivationContractTests._snapshot_runner(
                        links, moved_addresses, links, moved_addresses,
                    ),
                )
            )
            self.assertEqual(("eno2",), old_selected.listener_names)
            self.assertEqual((7,), old_selected.listener_ifindexes)
            self.assertEqual(("eno3",), moved_selected.listener_names)
            self.assertEqual((8,), moved_selected.listener_ifindexes)
            self.assertEqual(old_payload["endpoint_ips"], moved_payload["endpoint_ips"])
            self.assertEqual(
                old_payload["direct_shared_networks"],
                moved_payload["direct_shared_networks"],
            )
            self.assertNotEqual(
                old_payload["listener_fingerprints"],
                moved_payload["listener_fingerprints"],
            )
            old_argv = runtime.build_dhcpd_argv(old_selected.listener_names)
            moved_argv = runtime.build_dhcpd_argv(moved_selected.listener_names)
            self.assertEqual("eno2", old_argv[-1])
            self.assertEqual("eno3", moved_argv[-1])

            events = []

            @contextmanager
            def held(_root):
                events.append("lock-enter")
                try:
                    yield 37
                finally:
                    events.append("lock-exit")

            def prepare(_settings):
                events.append("prepare-eno3")
                return moved_selected, runtime, moved_payload

            def converge(services):
                self.assertEqual(
                    ("apache2", "dhcpd", "ztp-monitor", "switch-collection", "manual-ztp"),
                    tuple(services),
                )
                self.assertIn("stop-old", events)
                self.assertEqual("eno3", moved_argv[-1])
                events.append("converge-eno3")

            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl.activate, "restore_mutable_image_sources",
            ), mock.patch.object(
                hostctl.activate, "observe_runtime",
                side_effect=lambda _settings: (
                    events.append("observe-eno3")
                    or (moved_selected, runtime, moved_payload, "apache")
                ),
            ), mock.patch.object(
                hostctl.activate, "clear_activation",
                side_effect=lambda _settings: events.append("clear-authority"),
            ), mock.patch.object(
                hostctl, "stop_managed_services",
                side_effect=lambda: events.append("stop-old"),
            ), mock.patch.object(hostctl, "clear_guardian_fault"), \
                    mock.patch.object(hostctl.activate, "install_control_cgi"), \
                    mock.patch.object(
                        hostctl.activate, "prepare_runtime", side_effect=prepare,
                    ), mock.patch.object(
                        hostctl, "run_child",
                        side_effect=lambda command, *_args: (
                            self.assertIn("11-load.py", command[2]),
                            events.append("generate"),
                        ),
                    ), mock.patch.object(
                        hostctl.activate, "initialize_worker_control_files",
                    ), mock.patch.object(
                        hostctl.activate, "publish_precommit_activation",
                        side_effect=lambda *_args: events.append("precommit"),
                    ), mock.patch.object(
                        hostctl, "converge_services", side_effect=converge,
                    ), mock.patch.object(
                        hostctl.healthcheck, "check_runtime",
                        side_effect=lambda **_kwargs: events.append("health"),
                    ), mock.patch.object(
                        hostctl.activate, "commit_activation",
                        side_effect=lambda *_args: events.append("commit"),
                    ), mock.patch.object(
                        hostctl, "clear_quarantine",
                        side_effect=lambda *_args: events.append("clear-quarantine"),
                    ), mock.patch.object(hostctl.activate, "clear_rebuild_required"):
                hostctl.transactional_load(settings)

            self.assertEqual(2, events.count("prepare-eno3"))
            self.assertEqual(2, events.count("health"))
            self.assertLess(events.index("observe-eno3"), events.index("stop-old"))
            self.assertLess(events.index("stop-old"), events.index("generate"))
            self.assertLess(events.index("generate"), events.index("precommit"))
            self.assertLess(events.index("precommit"), events.index("converge-eno3"))
            self.assertLess(events.index("converge-eno3"), events.index("commit"))
            self.assertLess(events.index("commit"), events.index("clear-quarantine"))

    def test_reload_network_cli_is_narrow_and_never_invokes_load(self) -> None:
        hostctl = load_script("hostctl.py")
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        usage = source.split("usage() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("reload-network", usage)
        body = source.rsplit("  reload-network)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("owned_container_id true true false", body)
        self.assertIn('run_reload_network "$container_id"', body)
        self.assertNotIn("run_load", body)
        self.assertNotIn("11-load.py", body)
        self.assertNotIn("build_image", body)
        self.assertNotIn("start_inactive_container", body)
        runner = source.split("run_reload_network() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("/opt/http-ztp/hostctl.py reload-network", runner)
        self.assertNotIn("hostctl.py load", runner)
        self.assertFalse(os.path.lexists(DOCKER_ROOT / "README.md"))
        governance = (ROOT / "test_cases/README.md").read_text(encoding="utf-8")
        real_environment = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8",
        )
        self.assertIn("transactional_reload_network()", governance)
        self.assertIn("deploy.sh reload-network → health → status", real_environment)
        parsed = hostctl.parser().parse_args(["reload-network"])
        self.assertEqual("reload-network", parsed.action)

    def test_network_reload_plan_allows_only_listener_rebinding(self) -> None:
        activate = load_script("activate.py")
        saved = {
            "schema_version": 2,
            "generated_at": "old",
            "project": "site-a",
            "scope": "air",
            "switch_scope": "eth",
            "mini": True,
            "subnet_csv": "/var/www/html/DAY0-Prepare/site-a/02-dhcp-subnet_config.csv",
            "subnet_sha256": "a" * 64,
            "listener_names": ["eth2"],
            "listener_ifindexes": [7],
            "direct_shared_networks": ["air"],
            "relay_shared_networks": [],
            "dhcp_only_shared_networks": [],
            "endpoint_ips": ["192.0.2.50"],
            "listener_fingerprints": [{"ifname": "eth2", "ifindex": 7}],
            "link_snapshot_sha256": "b" * 64,
            "address_snapshot_sha256": "c" * 64,
            "apache_listener_sha256": "d" * 64,
        }
        moved = copy.deepcopy(saved)
        moved.update({
            "generated_at": "new",
            "listener_names": ["eth4"],
            "listener_ifindexes": [9],
            "listener_fingerprints": [{"ifname": "eth4", "ifindex": 9}],
            "link_snapshot_sha256": "e" * 64,
            "address_snapshot_sha256": "f" * 64,
        })
        self.assertTrue(activate.validate_network_reload_plan(saved, moved))

        unchanged = copy.deepcopy(saved)
        unchanged.update({
            "generated_at": "later",
            "link_snapshot_sha256": "1" * 64,
            "address_snapshot_sha256": "2" * 64,
        })
        self.assertFalse(activate.validate_network_reload_plan(saved, unchanged))

        same_name_drift = copy.deepcopy(saved)
        same_name_drift.update({
            "listener_ifindexes": [99],
            "listener_fingerprints": [{"ifname": "eth2", "ifindex": 99}],
        })
        with self.assertRaisesRegex(
            activate.ActivationError, "listener name did not change",
        ):
            activate.validate_network_reload_plan(saved, same_name_drift)

        for key, value in (
            ("project", "site-b"),
            ("scope", "prod"),
            ("switch_scope", "all"),
            ("mini", False),
            ("subnet_sha256", "9" * 64),
            ("direct_shared_networks", ["other"]),
            ("relay_shared_networks", ["relay"]),
            ("dhcp_only_shared_networks", ["dhcp-only"]),
            ("endpoint_ips", ["192.0.2.51"]),
            ("apache_listener_sha256", "8" * 64),
        ):
            with self.subTest(key=key):
                invalid = copy.deepcopy(moved)
                invalid[key] = value
                with self.assertRaisesRegex(
                    activate.ActivationError, rf"network reload.*{key}",
                ):
                    activate.validate_network_reload_plan(saved, invalid)

    @with_valid_monitor_authority_fixture
    def test_reload_network_rebinds_services_without_generation(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(
            http_root=Path("/var/www/html"),
            rebuild_required=Path("/state/rebuild-required.json"),
            quarantine_marker=Path("/state/quarantine.json"),
            guardian_fault=Path("/state/guardian-fault.json"),
        )
        old_plan = {
            "schema_version": 2, "generated_at": "old",
            "project": "site-a", "scope": "air", "switch_scope": "eth",
            "mini": True,
            "subnet_csv": "/var/www/html/DAY0-Prepare/site-a/02-dhcp-subnet_config.csv",
            "subnet_sha256": "a" * 64,
            "listener_names": ["eth2"], "listener_ifindexes": [7],
            "direct_shared_networks": ["air"], "relay_shared_networks": [],
            "dhcp_only_shared_networks": [], "endpoint_ips": ["192.0.2.50"],
            "listener_fingerprints": [{"ifname": "eth2", "ifindex": 7}],
            "link_snapshot_sha256": "b" * 64,
            "address_snapshot_sha256": "c" * 64,
            "apache_listener_sha256": "d" * 64,
        }
        new_plan = copy.deepcopy(old_plan)
        new_plan.update({
            "generated_at": "new", "listener_names": ["eth4"],
            "listener_ifindexes": [9],
            "listener_fingerprints": [{"ifname": "eth4", "ifindex": 9}],
            "link_snapshot_sha256": "e" * 64,
            "address_snapshot_sha256": "f" * 64,
        })
        selected = plan(names=("eth4",), indexes=(9,), endpoints=("192.0.2.50",))
        marker = {"services": list(hostctl.activate.MANAGED_SERVICES)}
        events = []

        @contextmanager
        def held(_root):
            events.append("lock")
            yield 31

        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
        ), mock.patch.object(
            hostctl.activate, "validate_image_source_contract",
            side_effect=lambda _settings: events.append("source"),
        ), mock.patch.object(
            hostctl.activate, "state_marker_present", return_value=False,
        ), mock.patch.object(
            hostctl.activate, "read_precommit_activation", return_value=None,
        ), mock.patch.object(
            hostctl.activate, "read_activation_marker", return_value=marker,
        ), mock.patch.object(
            hostctl.activate, "read_runtime_plan", return_value=old_plan,
        ), mock.patch.object(
            hostctl.activate, "observe_runtime",
            return_value=(selected, object(), new_plan, "apache"),
        ), mock.patch.object(
            hostctl.activate, "validate_activation_marker", return_value=(True, "ok"),
        ), mock.patch.object(
            hostctl.activate, "clear_activation",
            side_effect=lambda _settings: events.append("clear"),
        ), mock.patch.object(
            hostctl, "stop_managed_services", side_effect=lambda: events.append("stop"),
        ), mock.patch.object(
            hostctl.activate, "validate_control_cgi",
            side_effect=lambda _settings: events.append("cgi"),
        ), mock.patch.object(
            hostctl.activate, "prepare_runtime",
            side_effect=lambda _settings: (
                events.append("prepare") or (selected, object(), new_plan)
            ),
        ), mock.patch.object(
            hostctl.activate, "expected_services",
            return_value=tuple(hostctl.activate.MANAGED_SERVICES),
        ), mock.patch.object(
            hostctl.activate, "publish_precommit_activation",
            side_effect=lambda *_args: events.append("precommit"),
        ), mock.patch.object(
            hostctl, "converge_services", side_effect=lambda _services: events.append("start"),
        ), mock.patch.object(
            hostctl.healthcheck, "check_runtime",
            side_effect=lambda **kwargs: events.append(("health", kwargs)),
        ), mock.patch.object(
            hostctl.activate, "commit_activation",
            side_effect=lambda *_args: events.append("commit"),
        ), mock.patch.object(hostctl, "run_child") as child, mock.patch.object(
            hostctl.activate, "initialize_worker_control_files",
        ) as initialize:
            hostctl.transactional_reload_network(settings)

        child.assert_not_called()
        initialize.assert_not_called()
        self.assertLess(events.index("source"), events.index("clear"))
        self.assertLess(events.index("clear"), events.index("stop"))
        self.assertLess(events.index("stop"), events.index("prepare"))
        self.assertLess(events.index("prepare"), events.index("precommit"))
        self.assertLess(events.index("precommit"), events.index("start"))
        self.assertLess(events.index("start"), events.index("commit"))
        self.assertEqual(2, sum(event[0] == "health" for event in events if isinstance(event, tuple)))

    @with_valid_monitor_authority_fixture
    def test_reload_network_noop_keeps_runtime_untouched(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(
            http_root=Path("/var/www/html"),
            rebuild_required=Path("/state/rebuild-required.json"),
            quarantine_marker=Path("/state/quarantine.json"),
            guardian_fault=Path("/state/guardian-fault.json"),
        )
        selected = plan()
        marker = {"services": list(hostctl.activate.MANAGED_SERVICES)}

        @contextmanager
        def held(_root):
            yield 31

        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
        ), mock.patch.object(hostctl.activate, "validate_image_source_contract"), \
                mock.patch.object(hostctl.activate, "state_marker_present", return_value=False), \
                mock.patch.object(hostctl.activate, "read_precommit_activation", return_value=None), \
                mock.patch.object(hostctl.activate, "read_activation_marker", return_value=marker), \
                mock.patch.object(hostctl.activate, "read_runtime_plan", return_value={}), \
                mock.patch.object(
                    hostctl.activate, "observe_runtime",
                    return_value=(selected, object(), {}, "apache"),
                ), mock.patch.object(
                    hostctl.activate, "validate_activation_marker", return_value=(True, "ok"),
                ), mock.patch.object(
                    hostctl.activate, "validate_network_reload_plan", return_value=False,
                ), mock.patch.object(hostctl.healthcheck, "check_runtime") as health, \
                mock.patch.object(hostctl.activate, "clear_activation") as clear, \
                mock.patch.object(hostctl, "stop_managed_services") as stop, \
                mock.patch.object(hostctl.activate, "prepare_runtime") as prepare:
            hostctl.transactional_reload_network(settings)
        health.assert_called_once_with(require_active=True)
        clear.assert_not_called()
        stop.assert_not_called()
        prepare.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_reload_network_rejects_stale_authority_before_mutation(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(
            http_root=Path("/var/www/html"),
            rebuild_required=Path("/state/rebuild-required.json"),
            quarantine_marker=Path("/state/quarantine.json"),
            guardian_fault=Path("/state/guardian-fault.json"),
        )

        @contextmanager
        def held(_root):
            yield 31

        for blocked_path, expected in (
            (settings.rebuild_required, "rebuild"),
            (settings.quarantine_marker, "quarantine"),
            (settings.guardian_fault, "guardian"),
        ):
            with self.subTest(marker=blocked_path.name), mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(hostctl.activate, "validate_image_source_contract"), \
                    mock.patch.object(
                        hostctl.activate, "state_marker_present",
                        side_effect=lambda path, _label, target=blocked_path: path == target,
                    ), mock.patch.object(hostctl.activate, "clear_activation") as clear, \
                    mock.patch.object(hostctl, "stop_managed_services") as stop:
                with self.assertRaisesRegex(hostctl.ControllerError, expected):
                    hostctl.transactional_reload_network(settings)
                clear.assert_not_called()
                stop.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_reload_network_requires_committed_current_authority(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(
            http_root=Path("/var/www/html"),
            rebuild_required=Path("/state/rebuild-required.json"),
            quarantine_marker=Path("/state/quarantine.json"),
            guardian_fault=Path("/state/guardian-fault.json"),
        )

        @contextmanager
        def held(_root):
            yield 31

        for precommit, activation, expected in (
            ({"start_authority": "precommit"}, {"services": []}, "precommit"),
            (None, None, "active runtime"),
        ):
            with self.subTest(expected=expected), mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(hostctl.activate, "validate_image_source_contract"), \
                    mock.patch.object(
                        hostctl.activate, "state_marker_present", return_value=False,
                    ), mock.patch.object(
                        hostctl.activate, "read_precommit_activation",
                        return_value=precommit,
                    ), mock.patch.object(
                        hostctl.activate, "read_activation_marker",
                        return_value=activation,
                    ), mock.patch.object(
                        hostctl.activate, "clear_activation",
                    ) as clear, mock.patch.object(
                        hostctl, "stop_managed_services",
                    ) as stop:
                with self.assertRaisesRegex(hostctl.ControllerError, expected):
                    hostctl.transactional_reload_network(settings)
                clear.assert_not_called()
                stop.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_reload_network_failure_withdraws_authority_and_stops_services(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(
            http_root=Path("/var/www/html"),
            rebuild_required=Path("/state/rebuild-required.json"),
            quarantine_marker=Path("/state/quarantine.json"),
            guardian_fault=Path("/state/guardian-fault.json"),
        )
        selected = plan(names=("eth4",), indexes=(9,))
        marker = {"services": list(hostctl.activate.MANAGED_SERVICES)}
        events = []

        @contextmanager
        def held(_root):
            yield 31

        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
        ), mock.patch.object(hostctl.activate, "validate_image_source_contract"), \
                mock.patch.object(hostctl.activate, "state_marker_present", return_value=False), \
                mock.patch.object(hostctl.activate, "read_precommit_activation", return_value=None), \
                mock.patch.object(hostctl.activate, "read_activation_marker", return_value=marker), \
                mock.patch.object(hostctl.activate, "read_runtime_plan", return_value={}), \
                mock.patch.object(
                    hostctl.activate, "observe_runtime",
                    return_value=(selected, object(), {"listener_names": ["eth4"]}, "apache"),
                ), mock.patch.object(
                    hostctl.activate, "validate_activation_marker", return_value=(True, "ok"),
                ), mock.patch.object(
                    hostctl.activate, "validate_network_reload_plan", return_value=True,
                ), mock.patch.object(
                    hostctl.activate, "clear_activation",
                    side_effect=lambda _settings: events.append("clear"),
                ), mock.patch.object(
                    hostctl, "stop_managed_services",
                    side_effect=lambda: events.append("stop"),
                ), mock.patch.object(hostctl.activate, "validate_control_cgi"), \
                mock.patch.object(
                    hostctl.activate, "prepare_runtime",
                    side_effect=hostctl.activate.ActivationError("injected replan failure"),
                ):
            with self.assertRaisesRegex(Exception, "injected replan failure"):
                hostctl.transactional_reload_network(settings)
        self.assertEqual(["clear", "stop", "clear", "stop"], events)

    def test_failed_load_never_clears_rebuild_required_marker(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "rebuild-required.json"
            marker.write_text('{"schema_version":1}\n', encoding="utf-8")
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"), rebuild_required=marker,
                project_name="site-a", scope="air", switch_scope="eth",
                mini=False, monitor_interval=30,
            )

            @contextmanager
            def held(_root):
                yield 9

            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl.activate, "restore_mutable_image_sources",
            ), mock.patch.object(
                hostctl.activate, "observe_runtime",
                side_effect=hostctl.ControllerError("injected validation failure"),
            ), mock.patch.object(hostctl, "abort_failed_transaction"), \
                    mock.patch.object(
                        hostctl.activate, "clear_rebuild_required",
                    ) as clear:
                hostctl.transactional_load(settings)
            self.assertTrue(marker.exists())
            clear.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_resume_rejects_unsafe_rebuild_marker_and_stops_every_service(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "rebuild-required.json"
            marker.symlink_to(root / "missing-target")
            settings = SimpleNamespace(
                http_root=root, rebuild_required=marker,
                quarantine_marker=root / "quarantine.json",
            )

            @contextmanager
            def held(_root):
                yield 9

            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl, "stop_managed_services",
            ) as stop, mock.patch.object(
                hostctl.activate, "install_control_cgi",
            ) as install:
                with self.assertRaisesRegex(
                    (hostctl.ControllerError, hostctl.activate.ActivationError),
                    "rebuild-required.*regular",
                ):
                    hostctl.resume(settings)
            stop.assert_called_once_with()
            install.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_resume_health_failure_rolls_back_started_services(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(
                http_root=root, rebuild_required=root / "rebuild-required.json",
                quarantine_marker=root / "quarantine.json",
            )

            @contextmanager
            def held(_root):
                yield 9

            selected = object()
            marker = {"services": ["apache2"]}
            events = []
            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl.activate, "clear_precommit_activation",
            ), mock.patch.object(
                hostctl.activate, "install_control_cgi",
            ), mock.patch.object(
                hostctl.activate, "prepare_runtime",
                return_value=(selected, object(), {}),
            ), mock.patch.object(
                hostctl.activate, "read_activation_marker", return_value=marker,
            ), mock.patch.object(
                hostctl.activate, "validate_activation_marker",
                return_value=(True, "ok"),
            ), mock.patch.object(
                hostctl, "converge_services",
                side_effect=lambda _services: events.append("start"),
            ), mock.patch.object(
                hostctl.healthcheck, "check_runtime",
                side_effect=hostctl.healthcheck.HealthError("injected health failure"),
            ), mock.patch.object(
                hostctl, "stop_managed_services",
                side_effect=lambda: events.append("stop"),
            ):
                with self.assertRaisesRegex(Exception, "injected health failure"):
                    hostctl.resume(settings)
            self.assertEqual(["start", "stop"], events)

    def test_unload_clear_failure_still_stops_services_and_aggregates(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))

        @contextmanager
        def held(_root):
            yield 9

        events = []
        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
        ), mock.patch.object(
            hostctl.activate, "validate_image_source_contract",
        ), mock.patch.object(
            hostctl.activate, "clear_activation",
            side_effect=OSError("injected marker disk failure"),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=lambda: events.append("stop-all-five"),
        ), mock.patch.object(hostctl, "run_child") as child:
            with self.assertRaisesRegex(Exception, "marker disk failure"):
                hostctl.transactional_unload(settings)
        self.assertEqual(["stop-all-five"], events)
        child.assert_not_called()

    def test_deactivate_clear_failure_still_stops_services_and_aggregates(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))

        @contextmanager
        def held(_root):
            yield 9

        events = []
        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(hostctl.hostlock.HostLockError, held, lambda _fd: {}),
        ), mock.patch.object(
            hostctl.activate, "clear_activation",
            side_effect=OSError("injected marker disk failure"),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=lambda: events.append("stop-all-five"),
        ), mock.patch.object(hostctl, "clear_quarantine"), \
                mock.patch.object(hostctl, "clear_guardian_fault"):
            with self.assertRaisesRegex(Exception, "marker disk failure"):
                hostctl.deactivate(settings)
        self.assertEqual(["stop-all-five"], events)

    def test_host_wrapper_does_not_hold_a_host_fd_across_container_load(self) -> None:
        source = (DOCKER_ROOT / "deploy.sh").read_text(encoding="utf-8")
        load_call = source.index("/opt/http-ztp/hostctl.py load")
        preceding = source[max(0, load_call - 300):load_call]
        self.assertNotIn("acquire_lock", preceding)

    def test_stop_is_best_effort_but_cleanup_failure_is_not_hidden(self) -> None:
        hostctl = load_script("hostctl.py")
        attempted = []

        def fail_one(action, service):
            attempted.append((action, service))
            if service == "dhcpd":
                raise hostctl.ControllerError("injected stop failure")

        running = {name: "RUNNING" for name in hostctl.activate.MANAGED_SERVICES}
        with mock.patch.object(hostctl, "supervisor_states", return_value=running), \
                mock.patch.object(hostctl, "supervisor_action", side_effect=fail_one):
            with self.assertRaisesRegex(hostctl.ControllerError, "dhcpd.*injected"):
                hostctl.stop_managed_services()

        self.assertEqual(
            [
                ("stop", "ztp-monitor"), ("stop", "switch-collection"),
                ("stop", "manual-ztp"), ("stop", "dhcpd"),
                ("stop", "apache2"),
            ],
            attempted,
        )

    def test_stop_accepts_supervisor_terminal_states_only_with_zero_pid(self) -> None:
        hostctl = load_script("hostctl.py")
        initial = {name: "STOPPED" for name in hostctl.activate.MANAGED_SERVICES}
        initial["ztp-monitor"] = "EXITED"
        initial["manual-ztp"] = "FATAL"
        with mock.patch.object(
            hostctl, "supervisor_states", side_effect=[initial, initial],
        ), mock.patch.object(
            hostctl, "supervisor_pid", return_value=0,
        ), mock.patch.object(hostctl, "supervisor_action") as action:
            hostctl.stop_managed_services(timeout=0)
        action.assert_not_called()

    def test_hostctl_supervisor_pid_uses_exact_not_running_exit_contract(self) -> None:
        hostctl = load_script("hostctl.py")
        accepted = (
            (0, "812\n", "", 812),
            (7, "0\n", "", 0),
        )
        for returncode, stdout, stderr, expected in accepted:
            with self.subTest(accepted=(returncode, stdout)):
                result = SimpleNamespace(
                    returncode=returncode, stdout=stdout, stderr=stderr,
                )
                with mock.patch.object(
                    hostctl.subprocess, "run", return_value=result,
                ) as runner:
                    self.assertEqual(expected, hostctl.supervisor_pid("apache2"))
                runner.assert_called_once_with(
                    ("supervisorctl", "pid", "apache2"),
                    capture_output=True, text=True, check=False,
                    timeout=hostctl.SUPERVISOR_COMMAND_TIMEOUT,
                )

        for returncode, stdout, stderr in (
            (0, "0\n", ""),
            (0, "812\n", "warning/error\n"),
            (7, "812\n", ""),
            (7, "0\n", "error\n"),
            (3, "0\n", ""),
            (7, "", ""),
            (0, "812", ""),
            (0, "-1\n", ""),
        ):
            with self.subTest(rejected=(returncode, stdout, stderr)):
                result = SimpleNamespace(
                    returncode=returncode, stdout=stdout, stderr=stderr,
                )
                with mock.patch.object(
                    hostctl.subprocess, "run", return_value=result,
                ):
                    with self.assertRaises(hostctl.ControllerError):
                        hostctl.supervisor_pid("apache2")

    @with_valid_monitor_authority_fixture
    def test_fresh_markerless_resume_accepts_real_stopped_pid_results(self) -> None:
        """Fresh Supervisor must remain inactive without false quarantine."""
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = SimpleNamespace(
                http_root=root,
                rebuild_required=root / "rebuild-required.json",
                quarantine_marker=root / "quarantine.json",
            )
            stopped = {
                name: "STOPPED" for name in hostctl.activate.MANAGED_SERVICES
            }
            pid_result = SimpleNamespace(
                returncode=7, stdout="0\n", stderr="",
            )
            with mock.patch.object(
                hostctl, "_lock_contract",
                return_value=self._guardian_lock(),
            ), mock.patch.object(
                hostctl.activate, "validate_image_source_contract",
            ), mock.patch.object(
                hostctl.activate, "clear_precommit_activation",
            ), mock.patch.object(
                hostctl.activate, "install_control_cgi",
            ), mock.patch.object(
                hostctl.activate, "prepare_runtime",
                return_value=(plan(), object(), {}),
            ), mock.patch.object(
                hostctl.activate, "read_activation_marker", return_value=None,
            ), mock.patch.object(
                hostctl, "supervisor_states", return_value=stopped,
            ), mock.patch.object(
                hostctl.subprocess, "run", return_value=pid_result,
            ) as runner, mock.patch.object(
                hostctl, "supervisor_action",
                side_effect=AssertionError("STOPPED pid=0 must not be stopped again"),
            ) as action:
                self.assertIsNone(hostctl.resume(settings))
            action.assert_not_called()
            self.assertEqual(10, runner.call_count)

    @with_valid_monitor_authority_fixture
    def test_fresh_markerless_guardian_accepts_real_stopped_pid_results(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        stopped = {
            name: "STOPPED" for name in hostctl.activate.MANAGED_SERVICES
        }
        pid_result = SimpleNamespace(returncode=7, stdout="0\n", stderr="")
        with mock.patch.object(
            hostctl.activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(
            hostctl, "supervisor_states", return_value=stopped,
        ), mock.patch.object(
            hostctl.subprocess, "run", return_value=pid_result,
        ) as runner, mock.patch.object(
            hostctl, "stop_managed_services",
        ) as stop, mock.patch.object(
            hostctl, "write_quarantine",
        ) as quarantine:
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("old", 2),
                lock_contract=self._guardian_lock(),
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        self.assertEqual(5, runner.call_count)
        stop.assert_not_called()
        quarantine.assert_not_called()

    def test_stop_attempts_every_service_when_initial_status_is_unavailable(self) -> None:
        hostctl = load_script("hostctl.py")
        attempted = []
        stopped = {name: "STOPPED" for name in hostctl.STOP_ORDER}

        def action(_verb, service):
            attempted.append(service)

        with mock.patch.object(
            hostctl, "supervisor_states",
            side_effect=[hostctl.ControllerError("status unavailable"), stopped],
        ), mock.patch.object(
            hostctl, "supervisor_action", side_effect=action,
        ):
            with self.assertRaisesRegex(
                hostctl.ControllerError, "initial status.*unavailable",
            ):
                hostctl.stop_managed_services(timeout=0)
        self.assertEqual(list(hostctl.STOP_ORDER), attempted)

    def test_stop_aggregates_oserror_and_continues_all_service_attempts(self) -> None:
        hostctl = load_script("hostctl.py")
        attempted = []
        running = {name: "RUNNING" for name in hostctl.STOP_ORDER}
        stopped = {name: "STOPPED" for name in hostctl.STOP_ORDER}

        def action(_verb, service):
            attempted.append(service)
            if service == "ztp-monitor":
                raise OSError("injected supervisor transport failure")

        with mock.patch.object(
            hostctl, "supervisor_states", side_effect=[running, stopped],
        ), mock.patch.object(
            hostctl, "supervisor_action", side_effect=action,
        ):
            with self.assertRaisesRegex(
                hostctl.ControllerError, "ztp-monitor.*transport failure",
            ):
                hostctl.stop_managed_services(timeout=0)
        self.assertEqual(list(hostctl.STOP_ORDER), attempted)

    def test_primary_transaction_error_reports_incomplete_cleanup(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace()
        with mock.patch.object(
            hostctl.activate, "clear_activation",
            side_effect=hostctl.activate.ActivationError("marker injected"),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=hostctl.ControllerError("stop injected"),
        ):
            with self.assertRaisesRegex(
                hostctl.ControllerError,
                "primary injected.*marker injected.*stop injected",
            ):
                hostctl.abort_failed_transaction(
                    settings, hostctl.ControllerError("primary injected"),
                )

    @with_valid_monitor_authority_fixture
    def test_load_observes_then_quiesces_before_mutation_and_rolls_back_failure(self) -> None:
        hostctl = load_script("hostctl.py")
        events = []

        class LockError(Exception):
            pass

        @contextmanager
        def locked(_root):
            yield 19

        settings = SimpleNamespace(http_root=Path("/var/www/html"))

        def observe(_settings):
            events.append("observe")
            return plan(), object(), {}, "apache"

        def stop():
            events.append("stop")

        def clear(_settings):
            events.append("clear")

        def fail_install(_settings):
            events.append("install-cgi")
            raise hostctl.activate.ActivationError("injected CGI write failure")

        with mock.patch.object(
            hostctl, "_lock_contract",
            return_value=(LockError, locked, lambda descriptor: {}),
        ), mock.patch.object(
            hostctl.activate, "validate_image_source_contract",
        ), mock.patch.object(
            hostctl.activate, "restore_mutable_image_sources",
        ), mock.patch.object(
            hostctl.activate, "observe_runtime", side_effect=observe,
        ), mock.patch.object(
            hostctl, "stop_managed_services", side_effect=stop,
        ), mock.patch.object(
            hostctl.activate, "clear_activation", side_effect=clear,
        ), mock.patch.object(
            hostctl.activate, "install_control_cgi", side_effect=fail_install,
        ):
            with self.assertRaisesRegex(
                hostctl.activate.ActivationError, "injected CGI write failure",
            ):
                hostctl.transactional_load(settings)

        self.assertEqual(
            ["observe", "clear", "stop", "install-cgi", "clear", "stop"],
            events,
        )

    @staticmethod
    def _guardian_lock(events=None):
        class LockError(Exception):
            pass

        @contextmanager
        def locked(_root):
            if events is not None:
                events.append("lock-enter")
            yield 23
            if events is not None:
                events.append("lock-exit")

        return LockError, locked, lambda descriptor: {}

    @with_valid_monitor_authority_fixture
    def test_guardian_treats_inactive_stopped_runtime_as_safe_under_lock(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        stopped = {name: "STOPPED" for name in hostctl.activate.MANAGED_SERVICES}
        events = []
        with mock.patch.object(
            hostctl.activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(
            hostctl, "supervisor_states", return_value=stopped,
        ), mock.patch.object(
            hostctl, "supervisor_pid", return_value=0,
        ), mock.patch.object(
            hostctl.healthcheck, "check_runtime",
        ) as health, mock.patch.object(
            hostctl.activate, "clear_activation",
        ) as clear, mock.patch.object(
            hostctl, "stop_managed_services",
        ) as stop:
            state = hostctl.guardian_step(
                settings,
                hostctl.GuardianState("old-marker", 2),
                lock_contract=self._guardian_lock(events),
            )
        self.assertEqual(hostctl.GuardianState(None, 0), state)
        self.assertEqual(["lock-enter", "lock-exit"], events)
        health.assert_not_called()
        clear.assert_not_called()
        stop.assert_not_called()

    def test_guardian_markerless_running_service_is_stopped_without_failure_count(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        states = {name: "STOPPED" for name in hostctl.activate.MANAGED_SERVICES}
        states["dhcpd"] = "RUNNING"
        with mock.patch.object(
            hostctl.activate, "read_activation_marker", return_value=None,
        ), mock.patch.object(
            hostctl, "supervisor_states", return_value=states,
        ), mock.patch.object(hostctl, "stop_managed_services") as stop:
            state = hostctl.guardian_step(
                settings,
                hostctl.GuardianState("old-marker", 2),
                lock_contract=self._guardian_lock(),
            )
        self.assertEqual(hostctl.GuardianState(None, 0), state)
        stop.assert_called_once_with()

    def test_guardian_clears_abandoned_precommit_before_markerless_stop(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            precommit = root / "precommit-activation.json"
            precommit.write_text(
                '{"start_authority":"precommit"}\n', encoding="utf-8",
            )
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"),
                activation_marker=root / "activation.json",
                precommit_marker=precommit,
            )
            stopped = {
                name: "STOPPED" for name in hostctl.activate.MANAGED_SERVICES
            }
            events = []

            def clear_authority(_settings):
                events.append("clear-authority")
                precommit.unlink()

            with mock.patch.object(
                hostctl, "supervisor_states", return_value=stopped,
            ), mock.patch.object(
                hostctl, "supervisor_pid", return_value=0,
            ), mock.patch.object(
                hostctl.activate, "clear_activation", side_effect=clear_authority,
            ), mock.patch.object(
                hostctl, "write_quarantine",
                side_effect=lambda *_args: events.append("quarantine"),
            ), mock.patch.object(
                hostctl, "stop_managed_services",
                side_effect=lambda: events.append("stop"),
            ):
                state = hostctl.guardian_step(
                    settings, hostctl.GuardianState("old", 2),
                    lock_contract=self._guardian_lock(),
                )
            self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
            self.assertEqual(["clear-authority", "quarantine", "stop"], events)
            self.assertFalse(precommit.exists())

    def test_guardian_markerless_first_snapshot_stops_even_if_quarantine_write_fails(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        with mock.patch.object(
            hostctl, "guardian_snapshot",
            return_value=(None, False, "inactive dhcpd is RUNNING"),
        ), mock.patch.object(
            hostctl, "write_quarantine",
            side_effect=hostctl.ControllerError("injected persistent write failure"),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=lambda: events.append("stop-managed"),
        ), mock.patch.object(hostctl, "guardian_health_probe") as health:
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("old", 2),
                lock_contract=self._guardian_lock(events),
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        self.assertIn("stop-managed", events)
        health.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_guardian_first_fault_unlink_failure_does_not_block_markerless_stop(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        with mock.patch.object(
            hostctl, "clear_guardian_fault",
            side_effect=OSError("injected fault unlink failure"),
        ), mock.patch.object(
            hostctl, "guardian_snapshot",
            return_value=(None, False, "inactive dhcpd is RUNNING"),
        ) as snapshot, mock.patch.object(
            hostctl, "quarantine_inactive_locked",
        ) as cleanup, mock.patch.object(hostctl, "guardian_health_probe") as health:
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("old", 2),
                lock_contract=self._guardian_lock(),
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        snapshot.assert_called_once_with(settings)
        cleanup.assert_called_once_with(settings, "inactive dhcpd is RUNNING")
        health.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_guardian_second_fault_unlink_failure_does_not_block_markerless_stop(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        with mock.patch.object(
            hostctl, "clear_guardian_fault",
            side_effect=[None, OSError("injected second unlink failure")],
        ), mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[
                ("marker-a", True, "active"),
                (None, False, "inactive apache2 is STARTING"),
            ],
        ) as snapshot, mock.patch.object(
            hostctl, "guardian_health_probe", return_value=(False, "probe failed"),
        ), mock.patch.object(
            hostctl, "quarantine_inactive_locked",
        ) as cleanup:
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("marker-a", 2),
                lock_contract=self._guardian_lock(),
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        self.assertEqual(2, snapshot.call_count)
        cleanup.assert_called_once_with(settings, "inactive apache2 is STARTING")

    @with_valid_monitor_authority_fixture
    def test_guardian_fault_unlink_failure_remains_unhealthy_and_quarantines_across_rounds(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            fault = Path(temporary) / "guardian-fault.json"
            fault.write_text('{"reason":"unsafe lock"}\n', encoding="utf-8")
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"), guardian_fault=fault,
            )
            marker = ("marker-a", True, "active")
            with mock.patch.object(
                hostctl, "clear_guardian_fault",
                side_effect=OSError("injected persistent unlink failure"),
            ), mock.patch.object(
                hostctl, "guardian_snapshot", side_effect=[marker] * 7,
            ), mock.patch.object(
                hostctl, "guardian_health_probe", return_value=(True, "nominal"),
            ), mock.patch.object(
                hostctl, "guardian_quarantine_locked",
                return_value=hostctl.GUARDIAN_INITIAL_STATE,
            ) as quarantine:
                state = hostctl.GUARDIAN_INITIAL_STATE
                for _round in range(3):
                    state = hostctl.guardian_step(
                        settings, state, threshold=3,
                        lock_contract=self._guardian_lock(),
                    )
            self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
            self.assertTrue(fault.is_file())
            quarantine.assert_called_once()

    def test_guardian_marker_removed_during_probe_stops_even_if_quarantine_write_fails(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        with mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[
                ("marker-a", True, "active"),
                (None, False, "inactive apache2 is STARTING"),
            ],
        ), mock.patch.object(
            hostctl, "guardian_health_probe",
            return_value=(False, "marker vanished while probing"),
        ), mock.patch.object(
            hostctl, "write_quarantine",
            side_effect=hostctl.ControllerError("injected persistent write failure"),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=lambda: events.append("stop-managed"),
        ):
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("marker-a", 2),
                lock_contract=self._guardian_lock(events),
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        self.assertIn("stop-managed", events)

    @with_valid_monitor_authority_fixture
    def test_guardian_markerless_cleanup_retries_across_rounds_and_persists_quarantine(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"),
                quarantine_marker=Path(temporary) / "quarantine.json",
            )
            unsafe = (None, False, "inactive runtime still has dhcpd")
            safe = (None, True, "healthy inactive runtime")
            attempts = []

            def stop():
                attempts.append("stop")
                if len(attempts) == 1:
                    raise hostctl.ControllerError("injected first stop failure")

            real_write = hostctl.write_quarantine
            writes = {"count": 0}

            def transient_write(current_settings, identity, reason):
                writes["count"] += 1
                if writes["count"] == 1:
                    raise OSError("injected first quarantine write failure")
                real_write(current_settings, identity, reason)

            with mock.patch.object(
                hostctl, "guardian_snapshot", side_effect=[unsafe, unsafe, safe],
            ), mock.patch.object(
                hostctl, "write_quarantine", side_effect=transient_write,
            ), mock.patch.object(
                hostctl, "stop_managed_services", side_effect=stop,
            ), mock.patch.object(hostctl, "guardian_health_probe") as health:
                state = hostctl.GUARDIAN_INITIAL_STATE
                for _round in range(3):
                    state = hostctl.guardian_step(
                        settings, state, lock_contract=self._guardian_lock(),
                    )
            self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
            self.assertEqual(["stop", "stop"], attempts)
            self.assertTrue(settings.quarantine_marker.is_file())
            persisted = settings.quarantine_marker.read_text(encoding="utf-8")
            self.assertIn("inactive runtime still has dhcpd", persisted)
            health.assert_not_called()

    def test_guardian_probe_binds_failure_to_marker_identity(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace()
        marker = {"schema_version": 1, "activated_at": "fixture"}
        with mock.patch.object(
            hostctl.activate, "read_activation_marker", return_value=marker,
        ), mock.patch.object(
            hostctl.healthcheck, "check_runtime",
            side_effect=hostctl.activate.ActivationError("image source drift"),
        ):
            healthy, identity, reason = hostctl.guardian_probe(settings)
        self.assertFalse(healthy)
        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        self.assertIn("source drift", reason)

    def test_guardian_lock_busy_makes_no_mutation_and_resets_failures(self) -> None:
        hostctl = load_script("hostctl.py")

        @contextmanager
        def busy(_root):
            raise hostctl.hostlock.HostLockBusy(
                "another load/setup/unsetup/unload or deployment operation is active"
            )
            yield  # pragma: no cover

        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        with mock.patch.object(hostctl, "guardian_probe") as probe, \
                mock.patch.object(hostctl.activate, "clear_activation") as clear, \
                mock.patch.object(hostctl, "stop_managed_services") as stop:
            state = hostctl.guardian_step(
                settings,
                hostctl.GuardianState("same-marker", 2),
                lock_contract=(hostctl.hostlock.HostLockError, busy, lambda descriptor: {}),
            )
        self.assertEqual(hostctl.GuardianState(None, 0), state)
        probe.assert_not_called()
        clear.assert_not_called()
        stop.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_guardian_health_runs_outside_short_lock_then_rechecks_generation(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        held = {"value": False}

        class LockError(Exception):
            pass

        @contextmanager
        def locked(_root):
            self.assertFalse(held["value"])
            held["value"] = True
            events.append("lock-enter")
            try:
                yield 23
            finally:
                events.append("lock-exit")
                held["value"] = False

        def probe(_settings, *, timeout):
            self.assertFalse(held["value"])
            self.assertGreater(timeout, 0)
            events.append("bounded-health")
            return False, "timed out safely"

        with mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[("marker-a", True, "active"), ("marker-a", True, "active")],
        ), mock.patch.object(
            hostctl, "guardian_health_probe", side_effect=probe,
        ):
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("marker-a", 0),
                threshold=3, lock_contract=(LockError, locked, lambda _fd: {}),
            )
        self.assertEqual(hostctl.GuardianState("marker-a", 1), state)
        self.assertEqual(
            ["lock-enter", "lock-exit", "bounded-health", "lock-enter", "lock-exit"],
            events,
        )

    def test_guardian_health_probe_has_a_hard_timeout(self) -> None:
        hostctl = load_script("hostctl.py")
        with mock.patch.object(
            hostctl.subprocess, "run",
            side_effect=hostctl.subprocess.TimeoutExpired(
                cmd=["healthcheck.py"], timeout=4,
            ),
        ) as runner:
            healthy, reason = hostctl.guardian_health_probe(
                SimpleNamespace(), timeout=4,
            )
        self.assertFalse(healthy)
        self.assertIn("timed out", reason)
        self.assertEqual(4, runner.call_args.kwargs["timeout"])

    @with_valid_monitor_authority_fixture
    def test_guardian_final_bounded_recheck_holds_lock_and_quarantines(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        held = {"value": False}

        class LockError(Exception):
            pass

        @contextmanager
        def locked(_root):
            held["value"] = True
            events.append("lock-enter")
            try:
                yield 23
            finally:
                events.append("lock-exit")
                held["value"] = False

        def probe(_settings, *, timeout):
            self.assertGreater(timeout, 0)
            events.append("health-inside" if held["value"] else "health-outside")
            return False, "bounded failure"

        with mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[("marker-a", True, "active"), ("marker-a", True, "active")],
        ), mock.patch.object(
            hostctl, "guardian_health_probe", side_effect=probe,
        ), mock.patch.object(
            hostctl, "guardian_quarantine_locked",
            side_effect=lambda *_args: (
                events.append("quarantine") or hostctl.GUARDIAN_INITIAL_STATE
            ),
        ):
            state = hostctl.guardian_step(
                settings, hostctl.GuardianState("marker-a", 2),
                threshold=3, lock_contract=(LockError, locked, lambda _fd: {}),
            )
        self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, state)
        self.assertEqual(
            [
                "lock-enter", "lock-exit", "health-outside", "lock-enter",
                "health-inside", "quarantine", "lock-exit",
            ],
            events,
        )

    def test_guardian_distinguishes_busy_lock_from_unsafe_lock(self) -> None:
        hostctl = load_script("hostctl.py")
        events = []

        def contract(error):
            @contextmanager
            def failed(_root):
                raise error
                yield  # pragma: no cover
            return hostctl.hostlock.HostLockError, failed, lambda _fd: {}

        with tempfile.TemporaryDirectory() as temporary:
            settings = SimpleNamespace(
                http_root=Path("/var/www/html"),
                guardian_fault=Path(temporary) / "guardian-fault.json",
            )
            with mock.patch.object(hostctl, "stop_managed_services") as stop:
                busy = hostctl.guardian_step(
                    settings, hostctl.GuardianState("marker", 2),
                    lock_contract=contract(
                        hostctl.hostlock.HostLockBusy("writer owns lock")
                    ),
                )
            self.assertEqual(hostctl.GUARDIAN_INITIAL_STATE, busy)
            self.assertFalse(settings.guardian_fault.exists())
            stop.assert_not_called()

            with mock.patch.object(
                hostctl, "stop_managed_services",
                side_effect=lambda: events.append("stop-all-five"),
            ):
                with self.assertRaises(hostctl.GuardianFatalError):
                    hostctl.guardian_step(
                        settings, hostctl.GuardianState("marker", 2),
                        lock_contract=contract(
                            hostctl.hostlock.HostLockUnsafe(
                                "deployment lock must be a regular file"
                            )
                        ),
                    )
            self.assertEqual(["stop-all-five"], events)
            self.assertTrue(settings.guardian_fault.is_file())
            self.assertIn(
                "regular file", settings.guardian_fault.read_text(encoding="utf-8"),
            )

    def test_guardian_unsafe_lock_attempts_stop_even_when_fault_write_fails(self) -> None:
        hostctl = load_script("hostctl.py")

        @contextmanager
        def unsafe(_root):
            raise hostctl.hostlock.HostLockUnsafe("ENOLCK")
            yield  # pragma: no cover

        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        with mock.patch.object(
            hostctl, "write_guardian_fault",
            side_effect=lambda *_args: (
                events.append("fault-write") or (_ for _ in ()).throw(OSError("disk RO"))
            ),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=lambda: events.append("stop-all-five"),
        ):
            with self.assertRaises(hostctl.GuardianFatalError):
                hostctl.guardian_step(
                    settings, hostctl.GUARDIAN_INITIAL_STATE,
                    lock_contract=(hostctl.hostlock.HostLockError, unsafe, lambda _fd: {}),
                )
        self.assertEqual(["fault-write", "stop-all-five"], events)

    def test_guardian_loop_does_not_swallow_fatal_lock_safety_failure(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        fatal = hostctl.GuardianFatalError("unsafe deployment lock")
        with mock.patch.object(
            hostctl, "_lock_contract", return_value=self._guardian_lock(),
        ), mock.patch.object(
            hostctl, "guardian_step", side_effect=fatal,
        ), mock.patch.object(hostctl.time, "sleep") as sleep:
            with self.assertRaises(hostctl.GuardianFatalError):
                hostctl.guardian_loop(settings, interval=1)
        sleep.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_guardian_marker_change_and_healthy_probe_clear_failure_count(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        with mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[
                ("marker-b", True, "active"), ("marker-b", True, "active"),
                ("marker-b", True, "active"), ("marker-b", True, "active"),
                ("marker-b", True, "active"), ("marker-b", True, "active"),
            ],
        ), mock.patch.object(
            hostctl, "guardian_health_probe",
            side_effect=[
                (False, "new release failed once"),
                (False, "same release failed once"),
                (True, "recovered"),
            ],
        ):
            state = hostctl.guardian_step(
                settings,
                hostctl.GuardianState("marker-a", 2),
                lock_contract=self._guardian_lock(),
            )
            self.assertEqual(hostctl.GuardianState("marker-b", 0), state)
            state = hostctl.guardian_step(
                settings, state, lock_contract=self._guardian_lock(),
            )
            self.assertEqual(hostctl.GuardianState("marker-b", 1), state)
            state = hostctl.guardian_step(
                settings, state, lock_contract=self._guardian_lock(),
            )
        self.assertEqual(hostctl.GuardianState("marker-b", 0), state)

    @with_valid_monitor_authority_fixture
    def test_guardian_threshold_rechecks_under_same_lock_and_recovery_does_not_mutate(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        with mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[("marker-a", True, "active"), ("marker-a", True, "active")],
        ), mock.patch.object(
            hostctl, "guardian_health_probe",
            side_effect=[(False, "third failure"), (True, "recovered under lock")],
        ), mock.patch.object(
            hostctl.activate, "clear_activation",
        ) as clear, mock.patch.object(
            hostctl, "stop_managed_services",
        ) as stop:
            state = hostctl.guardian_step(
                settings,
                hostctl.GuardianState("marker-a", 2),
                threshold=3,
                lock_contract=self._guardian_lock(events),
            )
        self.assertEqual(hostctl.GuardianState("marker-a", 0), state)
        self.assertEqual(
            ["lock-enter", "lock-exit", "lock-enter", "lock-exit"], events,
        )
        clear.assert_not_called()
        stop.assert_not_called()

    @with_valid_monitor_authority_fixture
    def test_guardian_quarantine_clears_before_ordered_stop_and_never_self_stops(self) -> None:
        hostctl = load_script("hostctl.py")
        settings = SimpleNamespace(http_root=Path("/var/www/html"))
        events = []
        with mock.patch.object(
            hostctl, "guardian_snapshot",
            side_effect=[
                ("marker-a", True, "active"),
                ("marker-a", True, "active"),
                ("marker-a", True, "active"),
            ],
        ), mock.patch.object(
            hostctl, "guardian_health_probe",
            side_effect=[(False, "third failure"), (False, "confirmed failure")],
        ), mock.patch.object(
            hostctl.activate, "clear_activation",
            side_effect=lambda _settings: events.append("clear-marker"),
        ), mock.patch.object(
            hostctl, "stop_managed_services",
            side_effect=lambda: events.append("stop-managed"),
        ):
            state = hostctl.guardian_step(
                settings,
                hostctl.GuardianState("marker-a", 2),
                threshold=3,
                lock_contract=self._guardian_lock(events),
            )
        self.assertEqual(hostctl.GuardianState(None, 0), state)
        self.assertEqual(
            [
                "lock-enter", "lock-exit", "lock-enter", "clear-marker",
                "stop-managed", "lock-exit",
            ],
            events,
        )
        self.assertNotIn("runtime-guardian", hostctl.activate.MANAGED_SERVICES)
        self.assertNotIn("runtime-guardian", hostctl.STOP_ORDER)
        guardian_source = (DOCKER_ROOT / "hostctl.py").read_text(encoding="utf-8")
        body = guardian_source.split("def guardian_quarantine_locked", 1)[1].split(
            "\ndef ", 1,
        )[0]
        self.assertNotIn("deployment_lock", body)
        self.assertNotIn("converge_services", body)

    def test_guardian_partial_stop_failure_leaves_marker_cleared_and_reports(self) -> None:
        hostctl = load_script("hostctl.py")
        with tempfile.TemporaryDirectory() as temporary:
            settings = SimpleNamespace(
                quarantine_marker=Path(temporary) / "quarantine.json",
            )
            events = []
            with mock.patch.object(
                hostctl, "guardian_snapshot",
                return_value=("marker-a", True, "active"),
            ), mock.patch.object(
                hostctl.activate, "clear_activation",
                side_effect=lambda _settings: events.append("clear-marker"),
            ), mock.patch.object(
                hostctl, "stop_managed_services",
                side_effect=hostctl.ControllerError("dhcpd stop failed"),
            ):
                with self.assertRaisesRegex(
                    hostctl.ControllerError, "quarantine incomplete.*dhcpd stop failed",
                ):
                    hostctl.guardian_quarantine_locked(
                        settings, "marker-a", "initial failure", "confirmed failure",
                    )
            self.assertEqual(["clear-marker"], events)
            quarantine = json.loads(
                settings.quarantine_marker.read_text(encoding="utf-8"),
            )
            self.assertEqual("marker-a", quarantine["marker_identity"])
            self.assertIn("confirmed failure", quarantine["reason"])


class ContainerTransferContractTests(QuietContractTest):
    def test_container_assets_are_in_existing_transfer_tree_but_runtime_env_is_not(self) -> None:
        package = (ROOT / "tools/_package_common.py").read_text(encoding="utf-8")
        sync = (ROOT / "tools/sync-code.py").read_text(encoding="utf-8")
        self.assertIn('CODE_TREE_NAMES = {"infra",', package)
        self.assertIn('CODE_DIRECTORIES = (\n    "infra",', sync)

        contract_path = ROOT / "tools/project_contract.py"
        spec = importlib.util.spec_from_file_location("container_transfer_contract", contract_path)
        assert spec is not None and spec.loader is not None
        contract = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = contract
        spec.loader.exec_module(contract)
        self.assertIsNotNone(
            contract.transfer_exclude_reason("infra/docker/infra-runtime.conf")
        )
        self.assertIsNone(
            contract.transfer_exclude_reason("infra/docker/container.env.example")
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
