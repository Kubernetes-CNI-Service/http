"""D67-O10 B: real package/installer/guard-main/setup/reader lifecycle.

This is not tar/sync CLI full-proof admission, remote rsync, or the guard's
anonymous child carrier. Those old tests remain untouched. Only the guard's
process seam and host-runtime discovery inputs are locally bounded below;
its actual parser, archive validation/overlay and deployment lock still run.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.module_loader import load_script
from test_cases.native_cpld_physical_io import owned_test_root


ROOT = Path(__file__).resolve().parents[1]
ALIAS = "infiniband/bringup/xdr-initial-setup/latest_yaml"
TEXT = "../../../ztp/config/nvos/latest_yaml"
PUBLISHERS = {"ztp/config/cumulus/latest_yaml", "ztp/config/nvos/latest_yaml"}
OLD_AUDIT_BRIDGES = {
    "infiniband/bringup/xdr-initial-setup/01-global.yaml",
    "infiniband/bringup/xdr-initial-setup/publickey",
    "infiniband/bringup/ufm-setup-upgrade/01-global.yaml",
    "infiniband/bringup/ufm-setup-upgrade/publickey",
}


class Facade:
    def __init__(self, original, **overrides):
        self.original, self.overrides = original, overrides

    def __getattr__(self, name):
        return self.overrides[name] if name in self.overrides else getattr(self.original, name)


class LatestYamlLinkWorkflowTests(unittest.TestCase):
    def setUp(self):
        owned = owned_test_root()
        if os.environ.get("TMPDIR") != str(owned):
            raise RuntimeError("FIXTURE HOLD: explicit TMPDIR/owned-root binding required")
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="d7-bridge-", dir=owned))
        self.base = Path(directory)
        self.home = self.base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        self.home.chmod(0o700)
        blob = (struct.pack(">I", 11) + b"ssh-ed25519"
                + struct.pack(">I", 32) + bytes([41]) * 32)
        self.public = b"ssh-ed25519 " + base64.b64encode(blob) + b" PUBLIC-d7-operator\n"
        (self.home / ".ssh/id_ed25519.pub").write_bytes(self.public)
        # Only the already installed ordinary yaml package is copied. The
        # child cannot search the operator HOME/user-site for dependencies.
        public_python = self.home / "public-python"
        shutil.copytree(Path(yaml.__file__).resolve().parent, public_python / "yaml",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"))
        self.env = {"PATH": os.defpath, "HOME": str(self.home), "TMPDIR": str(owned),
                    "TMP": str(owned), "TEMP": str(owned), "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONNOUSERSITE": "1", "PYTHONPATH": str(public_python),
                    "HTTP_TEST_OWNED_ROOT": str(owned), "LC_ALL": "C"}
        self.child_env = dict(self.env, PYTHONDONTWRITEBYTECODE="1")
        self.child_run = subprocess.run
        self.stack.enter_context(mock.patch.dict(os.environ, self.env, clear=True))
        self.stack.enter_context(mock.patch.object(tempfile, "tempdir", str(self.base)))
        self.stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
        self.stack.enter_context(mock.patch.dict(sys.modules))
        self.effects, self.events = [], []
        self.addCleanup(self.assert_no_unknown_effects)
        self.proc = self.base / "empty-proc"
        self.proc.mkdir(mode=0o700)
        self.state = self.base / "docker-state-not-created"
        self.http = self.base / "source"
        self.http.mkdir(mode=0o700)
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--cached", "-z"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, env=self.env, check=True).stdout
        for value in listed.split(b"\0"):
            if not value:
                continue
            relative = Path(os.fsdecode(value))
            if relative.parts[0] == "test_cases":
                continue
            source, target = ROOT / relative, self.http / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                target.symlink_to(os.readlink(source))
            elif source.is_file():
                shutil.copy2(source, target)
        self.project = self.http / "DAY0-Prepare/PUBLIC-site"
        self.project.mkdir()
        example = ROOT / "examples/public-project"
        document = yaml.safe_load((example / "01-global.yaml.example").read_text())
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [row for row in document["switches"] if set(row) == {"eth"}]
        document["switches"][0]["eth"]["system"]["aaa"]["user"]["cumulus"]["hashed-password"] = "$6$fixture$safe-value"
        (self.project / "01-global.yaml").write_text(yaml.safe_dump(document, sort_keys=False))
        shutil.copy2(example / "02-dhcp-subnet_config.csv.example", self.project / "02-dhcp-subnet_config.csv")
        lines = (example / "02-devices_config.csv.example").read_text().splitlines()
        (self.project / "02-devices_config.csv").write_text("\n".join(lines[:2]) + "\n")
        import openpyxl
        book = openpyxl.Workbook()
        book.active["A1"] = "PUBLIC selected workbook; no network"
        book.save(self.project / "PUBLIC_P2P_v1.0.xlsx")

    def deny(self, *_args, **_kwargs):
        self.effects.append("unknown-external-effect")
        raise AssertionError("FIXTURE HOLD: unknown D7 bridge external effect")

    def assert_no_unknown_effects(self):
        self.assertEqual([], self.effects, "refused effect is not a product verdict")

    def load_copied(self, name, relative):
        self.assertEqual(self.loaded_root, self.tree_loader.ROOT)
        expected = self.loaded_root / relative
        module = self.tree_loader.load_script(name, expected)
        self.assertEqual(expected.resolve(strict=True), Path(module.__file__).resolve(strict=True))
        return module

    def load_tree(self, root):
        # Fresh real copied modules, never a cached PC/NEW from source ROOT.
        owned_names = []
        for name, module in list(sys.modules.items()):
            filename = getattr(module, "__file__", None)
            if name.startswith("test_cases"):
                continue
            locations = [Path(filename).resolve()] if filename else []
            if name in {"tools", "ztp"} or name.startswith(("tools.", "ztp.")):
                locations += [Path(path).resolve() for path in getattr(module, "__path__", ())]
            if any(path.is_relative_to(ROOT) or path.is_relative_to(self.base) for path in locations):
                owned_names.append(name)
        for name in owned_names:
            sys.modules.pop(name, None)
        sys.path[:] = [entry for entry in sys.path
                       if not (Path(entry).resolve().is_relative_to(ROOT)
                               or Path(entry).resolve().is_relative_to(self.base))]
        sys.path[:0] = [str(root / "tools"), str(root)]
        helper_path = ROOT / "test_cases/module_loader.py"
        loader = load_script("d7_bridge_loader_" + format(id(self), "x") + "_" + root.name, helper_path)
        self.assertEqual(helper_path, Path(loader.__file__).resolve(strict=True))
        self.assertEqual(helper_path, Path(loader.load_script.__code__.co_filename).resolve(strict=True))
        self.assertIs(loader.__dict__, loader.load_script.__globals__)
        self.assertIsNot(load_script, loader.load_script)
        loader.ROOT = root  # New private helper instance only, not any production module.
        self.assertEqual(ROOT, load_script.__globals__["ROOT"])
        self.loaded_root, self.tree_loader = root, loader
        pointer = self.load_copied("project_pointer", "tools/project_pointer.py")
        contract = self.load_copied("project_contract", "tools/project_contract.py")
        self.assertEqual((root / "tools/project_pointer.py").resolve(), Path(contract._project_pointer.__file__).resolve())
        self.assertIs(pointer, contract._project_pointer)
        self.assertEqual((ROOT / "tools/project_pointer.py").read_bytes(), (root / "tools/project_pointer.py").read_bytes())
        self.assertEqual((ROOT / "tools/project_contract.py").read_bytes(), (root / "tools/project_contract.py").read_bytes())
        package = self.load_copied("_package_common", "tools/_package_common.py")
        setup = self.load_copied("d7_bridge_setup", "DAY0-Prepare/01-a-setup.py")
        unsetup = self.load_copied("d7_bridge_unsetup", "DAY0-Prepare/02-unsetup.py")
        origins = {"project_pointer": "tools/project_pointer.py", "project_contract": "tools/project_contract.py",
            "_package_common": "tools/_package_common.py", "deployment_lock": "tools/deployment_lock.py",
            "finished_project_state": "tools/finished_project_state.py", "ztp_service_runtime": "tools/ztp_service_runtime.py",
            "ssh_key_preparation": "tools/ssh_key_preparation.py", "operator_identity": "tools/operator_identity.py",
            "sample_links": "ztp/optimize/sample_links.py", "ztp.config_sync_authority": "ztp/config_sync_authority.py"}
        for name, relative in origins.items():
            self.assertEqual((root / relative).resolve(strict=True),
                             Path(sys.modules[name].__file__).resolve(strict=True), name)
        self.assertIs(pointer, sys.modules["project_pointer"])
        self.assertIs(contract, sys.modules["project_contract"])
        self.assertIs(package, sys.modules["_package_common"])
        self.assertEqual(root, package.ROOT)
        self.assertEqual(root / "DAY0-Prepare", package.DAY0)
        self.assertIs(package.__dict__, package.resolve_project.__globals__)
        self.assertIs(contract.active_project_dir, setup.active_project_dir)
        self.assertIs(contract.active_project_dir, unsetup.active_project_dir)
        self.assertIs(package.newest_project_p2p, setup.newest_project_p2p)
        self.assertIs(package.select_project_p2p_source, setup.select_project_p2p_source)
        self.assertIs(sys.modules["ztp.config_sync_authority"], unsetup.config_sync_authority)
        for name in ("tools", "ztp"):
            if name in sys.modules:
                self.assertEqual([(root / name).resolve(strict=True)],
                                 [Path(path).resolve(strict=True) for path in sys.modules[name].__path__])
        finish = sys.modules["finished_project_state"]
        # Absent own state preserves the real no-pending branch; no host read.
        self.stack.enter_context(mock.patch.object(finish, "FINISH_STATE_ROOT", self.base / "finish-state-not-created"))
        for module in list(sys.modules.values()):
            filename = getattr(module, "__file__", None)
            if filename and Path(filename).resolve().is_relative_to(root):
                self.bound_effects(module)
        actual_stop = unsetup.stop_native_ztp_monitors

        def stop(http_root):
            self.assertEqual(root, Path(http_root))
            self.assertEqual([], list(self.proc.iterdir()))
            self.events.append("unsetup-own-proc")
            return actual_stop(http_root, proc_root=self.proc, kill=self.deny)

        self.stack.enter_context(mock.patch.object(unsetup, "stop_native_ztp_monitors", stop))
        return contract, setup, unsetup

    def bound_effects(self, module):
        if getattr(module, "subprocess", None) is subprocess:
            self.stack.enter_context(mock.patch.object(module, "subprocess", Facade(subprocess,
                run=self.public_run, Popen=self.deny, call=self.deny,
                check_call=self.deny, check_output=self.deny)))
        if getattr(module, "socket", None) is socket:
            self.stack.enter_context(mock.patch.object(module, "socket", Facade(socket,
                socket=self.deny, create_connection=self.deny)))
        if getattr(module, "os", None) is os:
            forbidden = {key: self.deny for key in (
                "system", "fork", "forkpty", "execv", "execve", "execvp", "execvpe",
                "execl", "execlp", "execlpe", "posix_spawn", "posix_spawnp",
                "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve",
                "spawnvp", "spawnvpe", "kill", "killpg", "waitpid")}
            self.stack.enter_context(mock.patch.object(module, "os", Facade(os, **forbidden)))

    def public_run(self, command, **kwargs):
        try:
            return self.admitted_public_run(command, **kwargs)
        except AssertionError:
            self.effects.append("invalid-public-child-binding")
            raise

    def admitted_public_run(self, command, **kwargs):
        words = list(command)
        self.assertTrue(all(type(word) is str for word in words))
        if len(words) == 4 and words[:3] == ["ssh-keygen", "-l", "-f"]:
            self.assertEqual({"capture_output", "text", "timeout"}, set(kwargs))
            self.assertIs(True, kwargs["capture_output"])
            self.assertIs(True, kwargs["text"])
            self.assertIs(int, type(kwargs["timeout"]))
            self.assertEqual(5, kwargs["timeout"])
            public = Path(words[3])
            self.assertTrue(public.is_absolute())
            self.assertEqual(str(public), words[3])
            try:
                canonical_public = public.resolve(strict=True)
                info = public.lstat()
            except OSError:
                self.fail("FIXTURE HOLD: public key is unavailable")
            self.assertEqual(public, canonical_public)
            self.assertTrue(canonical_public.is_relative_to(self.base))
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(os.geteuid(), info.st_uid)
            self.assertEqual(self.public, public.read_bytes())
            self.events.append("public-key-fingerprint")
            return self.child_run(["/usr/bin/ssh-keygen", *words[1:]],
                **dict(kwargs, env=self.env, stdin=subprocess.DEVNULL))
        expected = [sys.executable, "-B", str(self.http / "infra/docker/activate.py"),
                    "build-source-manifest", "--source-root", str(self.http), "--manifest"]
        if len(words) == 8 and words[:7] == expected:
            self.assertEqual({"cwd", "capture_output", "text", "check", "env"}, set(kwargs))
            self.assertIs(type(self.http), type(kwargs["cwd"]))
            self.assertEqual(self.http, kwargs["cwd"])
            self.assertIs(True, kwargs["capture_output"])
            self.assertIs(True, kwargs["text"])
            self.assertIs(False, kwargs["check"])
            self.assertIs(dict, type(kwargs["env"]))
            self.assertTrue(all(type(key) is str and type(value) is str for key, value in kwargs["env"].items()))
            self.assertEqual(self.child_env, kwargs["env"])
            destination = Path(words[7])
            self.assertTrue(destination.is_absolute())
            self.assertEqual(str(destination), words[7])
            self.assertEqual(destination, destination.resolve())
            self.assertTrue(destination.is_relative_to(self.base))
            self.assertEqual("deployment-source-manifest.json", destination.name)
            try:
                parent = destination.parent
                info = parent.lstat()
                canonical_parent = parent.resolve(strict=True)
            except OSError:
                self.fail("FIXTURE HOLD: manifest parent is unavailable")
            self.assertEqual(parent, canonical_parent)
            self.assertTrue(stat.S_ISDIR(info.st_mode))
            self.assertEqual(os.geteuid(), info.st_uid)
            self.assertEqual(0o700, stat.S_IMODE(info.st_mode))
            self.events.append("real-source-manifest-child")
            return self.child_run(words, **dict(kwargs, env=self.env,
                stdin=subprocess.DEVNULL, timeout=120))
        return self.deny()

    def call(self, entry, words):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(out):
            result = entry(words)
        self.assertEqual(0, result, out.getvalue())

    def assert_alias(self, root, *, resolves):
        link = root / ALIAS
        self.assertTrue(link.is_symlink(), "setup alone must create the new named alias")
        self.assertEqual(TEXT, os.readlink(link))
        self.assertEqual(resolves, link.exists())

    def setup(self, root, setup):
        self.call(setup.main, ["-y", "--host-role=workstation", "--no-upgrade",
                               str(root / "DAY0-Prepare/PUBLIC-site")])

    def unsetup(self, root, unsetup):
        log = root / "infiniband/bringup/xdr-initial-setup/xdr-initial-setup-logs"
        for name in ("auto.env", "auto-watch.state", "auto-terminal.json"):
            self.assertFalse(os.path.lexists(log / name))
        self.call(unsetup.main, ["-y"])

    def publish(self, root):
        self.assertEqual(root, self.loaded_root)
        publisher = self.load_copied("d7_bridge_publisher", "ztp/config/cumulus/d-hostname2mac.py")
        self.bound_effects(publisher)
        project = root / "DAY0-Prepare/PUBLIC-site"
        release = project / "99-output-ib_nvl/20261118_010203-ib"
        release.mkdir()
        # This bridge case tests the real publisher, not the generator or
        # replace. PUBLIC NVOS input has no password or private material.
        (release / "PUBLIC-IB01.yaml").write_text(
            "- set:\n    interface:\n      eth0:\n        ipv4:\n"
            "          address:\n            203.0.113.11/24: {}\n"
            "          gateway:\n            203.0.113.1: {}\n"
            "    system:\n      hostname: PUBLIC-IB01\n")
        service = root / "ztp/config/nvos"
        # Existing eth-only project remains unchanged. Give the real NVOS
        # defaults renderer an independently bounded explicit IB section.
        global_path = project / "01-global.yaml"
        document = yaml.safe_load(global_path.read_text())
        document["switches"].append({"ib": {"system": {"hostname": "PUBLIC-NVOS"}}})
        global_path.write_text(yaml.safe_dump(document, sort_keys=False))
        devices = {"public-ib01": {"hostname": "PUBLIC-IB01", "dev_type": "ib",
            "eth0_mac": "02:00:00:00:00:11", "eth0_ip_cidr": "203.0.113.11/24",
            "eth0_gw": "203.0.113.1", "eth1_mac": "", "eth1_ip_cidr": "", "eth1_gw": ""}}
        logical_root = service / "template/99-output-ib_nvl"
        logical_release = logical_root / "20261118_010203-ib"
        self.assertEqual(project / "99-output-ib_nvl", logical_root.resolve(strict=True))
        self.assertEqual(release, logical_release.resolve(strict=True))
        context = publisher._nvos_dir_context(str(logical_release))
        self.assertEqual(str(logical_release), context["path"])
        self.assertEqual(str(service), context["service_dir"])
        self.assertEqual("ib", context["kind"])
        self.assertEqual("20261118_010203", context["timestamp"])
        with redirect_stdout(io.StringIO()):
            self.assertTrue(publisher._publish_single_nvos(context, devices, switch_scope="ib"))
        self.assertTrue((release / ".published-complete").read_bytes())
        manifest = json.loads((release / "release-manifest.json").read_text())
        self.assertEqual("PUBLIC-IB01", manifest["devices"][0]["hostname"])
        self.assertEqual(hashlib.sha256((release / "PUBLIC-IB01.yaml").read_bytes()).hexdigest(),
                         manifest["devices"][0]["config_sha256"])
        self.assertEqual("PUBLIC-IB01.yaml", os.readlink(release / "020000000011.yaml"))
        self.assertEqual("20261118_010203-ib", os.readlink(release.parent / "latest"))
        self.assertEqual("template/99-output-ib_nvl/latest", os.readlink(service / "latest_yaml"))
        return release

    def test_preload_setup_unsetup_current_reader_and_published_setup_keep_exact_alias(self):
        contract, setup, unsetup = self.load_tree(self.http)
        self.setup(self.http, setup)
        self.assert_alias(self.http, resolves=False)
        self.assertEqual(self.project, contract.active_project_dir(self.http))
        self.unsetup(self.http, unsetup)
        self.assert_alias(self.http, resolves=False)
        self.assertIsNone(contract.active_project_dir(self.http))
        self.assertFalse(os.path.lexists(self.http / "DAY0-Prepare/activate-project"))
        self.setup(self.http, setup)
        self.assert_alias(self.http, resolves=False)
        release = self.publish(self.http)
        self.assert_alias(self.http, resolves=True)
        self.assertEqual(release, (self.http / ALIAS).resolve(strict=True))
        self.unsetup(self.http, unsetup)
        self.assert_alias(self.http, resolves=False)
        self.assertIsNone(contract.active_project_dir(self.http))
        self.setup(self.http, setup)
        self.assert_alias(self.http, resolves=True)
        self.assertEqual(release, (self.http / ALIAS).resolve(strict=True))
        publishers = [row for row in contract.SETUP_LINK_SPECS if row.view == "latest-yaml"]
        self.assertEqual(PUBLISHERS, {row.path for row in publishers})
        self.assertTrue(all(row.writer == "publisher" and row.published is False for row in publishers))
        self.assertEqual(2, self.events.count("unsetup-own-proc"))

    def test_real_package_controlled_guard_main_deploy_and_lifecycle_exclude_host_alias(self):
        contract, setup, _unsetup = self.load_tree(self.http)
        self.setup(self.http, setup)
        self.assert_alias(self.http, resolves=False)
        package = sys.modules["_package_common"]
        archive = self.base / "PUBLIC-upload.tar.gz"
        args = argparse.Namespace(project=str(self.project), output=archive, force=False,
            max_file_size_mib=50, include_images=False, include_apps=False,
            apps_platform=None, apps_platforms=set(), include_firmware=False)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(archive, package.create_package(args, day0_all=False, artifact_kind="upload"))
        with tarfile.open(archive, "r:gz") as uploaded:
            names = {row.name.removeprefix("./") for row in uploaded.getmembers()}
            self.assertNotIn(ALIAS, names)
            self.assertIn("tools/project_contract.py", names)
            self.assertIn("tools/project_pointer.py", names)
            manifest_body = uploaded.extractfile("./infra/docker/deployment-source-manifest.json").read()
        sync = self.load_copied("d7_bridge_sync", "tools/sync-code.py")
        self.bound_effects(sync)
        with redirect_stdout(io.StringIO()):
            jobs = sync.build_jobs(self.project, "/srv/PUBLIC-http")
        ib = [job for job in jobs if job.label == "code:infiniband"]
        self.assertEqual(1, len(ib))
        self.assertIn("/bringup/xdr-initial-setup/latest_yaml", ib[0].excludes)
        self.assertFalse(any((self.http / ALIAS) in job.sources for job in jobs))
        audit = load_script("d7_bridge_audit", ROOT / "test_cases/audit_public_tree.py")
        self.assertEqual(OLD_AUDIT_BRIDGES, set(audit.SETUP_RUNTIME_BRIDGES))
        self.assertFalse(audit.exact_setup_runtime_bridge(self.http, ALIAS, TEXT,
            audit.IndexEntry("120000", "0" * 40)))
        indexed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "--", ALIAS],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, env=self.env, check=False)
        self.assertNotEqual(0, indexed.returncode, "B alias is not a tracked public bridge")
        installer = self.load_copied("d7_bridge_installer", "tools/deploy-upload-archive.py")
        guard = self.load_copied("d7_bridge_guard", "tools/deployment_prewrite_guard.py")
        self.bound_effects(installer)
        self.bound_effects(guard)
        live = self.base / "deployed"
        live.mkdir(mode=0o700)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest_digest = hashlib.sha256(manifest_body).hexdigest()
        guard_bytes = (self.http / "tools/deployment_prewrite_guard.py").read_text()
        real_archive, real_quiesce, real_stop = guard.run_locked_archive, guard.quiesce_for_source_update, guard.stop_native_ztp_monitors

        def stop(root):
            self.assertEqual(live, root)
            self.assertEqual([], list(self.proc.iterdir()))
            self.events.append("guard-own-proc")
            return real_stop(root, proc_root=self.proc, kill=self.deny)

        def which(name):
            self.assertEqual("docker", name)
            self.events.append("no-host-docker-probe")
            return None

        def quiesce(root, *, state_root, docker_requested, native_requested):
            self.assertEqual(self.state, state_root)
            self.assertIs(False, docker_requested)
            self.assertIs(True, native_requested)
            return real_quiesce(root, state_root=state_root, runner=self.deny, which=which,
                                 docker_requested=docker_requested, native_requested=native_requested)

        def archive_call(*args, **kwargs):
            self.assertNotIn("state_root", kwargs)
            return real_archive(*args, **kwargs, state_root=self.state)

        def run_guard(command, *, env, archive_fd, guard_source):
            self.assertEqual(self.env, env)
            self.assertEqual(guard_bytes, guard_source)
            self.assertEqual([sys.executable, "-", "--lock", str(live / ".deployment.lock"),
                "--root", str(live), "--runtime", "native", "--archive-fd", str(archive_fd),
                "--archive-sha256", digest, "--source-manifest-sha256", manifest_digest], list(command))
            self.assertTrue(stat.S_ISREG(os.fstat(archive_fd).st_mode))
            self.events.append("real-guard-main")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = guard.main(command[2:])
            return subprocess.CompletedProcess(command, code, out.getvalue().encode(), err.getvalue().encode())

        with mock.patch.object(installer, "run_guard", run_guard), \
                mock.patch.object(guard, "run_locked_archive", archive_call), \
                mock.patch.object(guard, "quiesce_for_source_update", quiesce), \
                mock.patch.object(guard, "stop_native_ztp_monitors", stop):
            result = installer.deploy_archive(archive, root=live, runtime="native", verify_only=False,
                installer_path=self.http / "tools/deploy-upload-archive.py", required_uid=os.getuid(),
                python_executable=sys.executable, staging_parent=self.base, guard_environment=self.env)
        self.assertEqual("PUBLIC-site", result.project)
        self.assertFalse(os.path.lexists(live / ALIAS), "archive deployment must not carry the source host alias")
        deployed_project = live / "DAY0-Prepare/PUBLIC-site"
        copied, deployed_setup, deployed_unsetup = self.load_tree(live)
        self.setup(live, deployed_setup)
        self.assert_alias(live, resolves=False)
        self.assertEqual(deployed_project, copied.active_project_dir(live))
        self.unsetup(live, deployed_unsetup)
        self.assert_alias(live, resolves=False)
        self.assertIsNone(copied.active_project_dir(live))
        self.setup(live, deployed_setup)
        self.assert_alias(live, resolves=False)
        release = self.publish(live)
        self.assert_alias(live, resolves=True)
        self.assertEqual(release, (live / ALIAS).resolve(strict=True))
        self.assertEqual(1, self.events.count("real-source-manifest-child"))
        self.assertEqual(1, self.events.count("real-guard-main"))
        self.assertEqual(1, self.events.count("guard-own-proc"))
        self.assertEqual(1, self.events.count("no-host-docker-probe"))


    def test_upload_wrapper_keeps_both_local_proof_gates_and_excludes_setup_alias(self):
        _contract, setup, _unsetup = self.load_tree(self.http)
        self.setup(self.http, setup)
        self.assert_alias(self.http, resolves=False)
        package = sys.modules["_package_common"]
        command = self.load_copied("d7_bridge_upload_wrapper", "tools/tar-for-upload.py")
        self.assertIs(package, command.package_core)
        self.assertEqual(self.http, command.ROOT)
        self.bound_effects(command)
        runner = command.PREDEPLOY_TEST_RUNNER
        self.assertEqual(self.http / "test_cases/run_related_tests.py", runner)
        runner.parent.mkdir(exist_ok=True)
        original_runner = ROOT / "test_cases/run_related_tests.py"
        shutil.copyfile(original_runner, runner)
        self.assertEqual(original_runner.read_bytes(), runner.read_bytes())
        actual_create = package.create_package
        for label, statuses, events, message in (
                ("missing", (5,), ["check"], "尚未打包"),
                ("changed", (0, 5), ["check", "package", "check"], "打包后批准状态已变化")):
            with self.subTest(label=label):
                archive = self.base / ("PUBLIC-" + label + ".tar.gz")
                observed = []
                checks = iter(statuses)

                def model_proof_check(argv, **kwargs):
                    self.assertEqual([sys.executable, "-B", str(runner), "--check", "--require-full"], argv)
                    self.assertEqual({"cwd": self.http, "shell": False, "check": False}, kwargs)
                    observed.append("check")
                    return mock.Mock(returncode=next(checks))

                def create_local(args, **kwargs):
                    self.assertEqual(archive, args.output)
                    self.assertEqual({"day0_all": False, "artifact_kind": "upload"}, kwargs)
                    observed.append("package")
                    return actual_create(args, **kwargs)

                stdout, stderr = io.StringIO(), io.StringIO()
                with mock.patch.object(command, "subprocess", Facade(command.subprocess,
                        run=model_proof_check, Popen=self.deny)), \
                     mock.patch.object(package, "create_package", side_effect=create_local), \
                     mock.patch.object(command, "upload", side_effect=self.deny), \
                     redirect_stdout(stdout), redirect_stderr(stderr):
                    code = command.main([str(self.project), "not-connected.invalid",
                                         "--exclude-apps", "--output", str(archive)])
                self.assertEqual(1, code)
                self.assertEqual(events, observed)
                self.assertIn(message, stderr.getvalue())
                self.assertIn("远端未连接、未修改", stderr.getvalue())
                if label == "missing":
                    self.assertFalse(archive.exists())
                else:
                    with tarfile.open(archive, "r:gz") as uploaded:
                        names = {row.name.removeprefix("./") for row in uploaded.getmembers()}
                    self.assertNotIn(ALIAS, names)
                    self.assertIn("tools/project_contract.py", names)
                    self.assertIn("tools/project_pointer.py", names)
                self.assertFalse((runner.parent / "script_test_approved_hashes.json").exists())
                self.assert_no_unknown_effects()


class LatestYamlChildBoundaryTests(unittest.TestCase):
    """Pure negative probes of this instance's child seam; never spawn."""
    def world(self):
        owned = owned_test_root()
        self.assertEqual(str(owned), os.environ.get("TMPDIR"))
        directory = tempfile.TemporaryDirectory(prefix="d7-child-controls-", dir=owned)
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        world = LatestYamlLinkWorkflowTests(
            "test_preload_setup_unsetup_current_reader_and_published_setup_keep_exact_alias")
        # Do not call the business setUp: no Git copy, source load or child.
        world.base, world.http = root / "scope", root / "scope/source"
        world.http.mkdir(parents=True, mode=0o700)
        world.base.chmod(0o700)
        world.env = {"PATH": os.defpath, "HOME": str(world.base),
                     "TMPDIR": str(owned), "PYTHONDONTWRITEBYTECODE": "1"}
        world.child_env = dict(world.env, PYTHONDONTWRITEBYTECODE="1")
        world.effects, world.events = [], []
        blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes([41]) * 32
        world.public = b"ssh-ed25519 " + base64.b64encode(blob) + b" PUBLIC-d7-boundary\n"
        key = world.base / "PUBLIC.pub"
        key.write_bytes(world.public)
        parent = world.base / "manifest-parent"
        parent.mkdir(mode=0o700)
        started = []

        def refused_child(*_args, **_kwargs):
            started.append("child-seam-entered")
            raise AssertionError("PURE CONTROL: no child may start")

        world.child_run = refused_child
        commands = [(["ssh-keygen", "-l", "-f", str(key)],
                     {"capture_output": True, "text": True, "timeout": 5}),
                    ([sys.executable, "-B", str(world.http / "infra/docker/activate.py"),
                      "build-source-manifest", "--source-root", str(world.http), "--manifest",
                      str(parent / "deployment-source-manifest.json")],
                     {"cwd": world.http, "capture_output": True, "text": True,
                      "check": False, "env": dict(world.child_env)})]
        return world, root, commands, started

    def test_unknown_changed_or_missing_child_kwargs_reject_before_spawn(self):
        world, _root, commands, started = self.world()
        rejected = 0
        unknown = {"shell": True, "preexec_fn": lambda: None, "pass_fds": (99,),
                   "stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                   "start_new_session": True}
        for command, original in commands:
            bad_sets = [dict(original, **{name: value}) for name, value in unknown.items()]
            bad_sets += [dict(original, capture_output=1), dict(original, text=1)]
            bad_sets += [{name: value for name, value in original.items() if name != missing}
                         for missing in original]
            if "timeout" in original:
                bad_sets += [dict(original, timeout=6)]
            else:
                bad_sets += [dict(original, check=True), dict(original, cwd=str(world.http)),
                             dict(original, env=dict(world.child_env, PUBLIC_UNKNOWN="extra"))]
            for index, supplied in enumerate(bad_sets):
                with self.subTest(command=command[0], variant=index), self.assertRaises(AssertionError):
                    world.public_run(command, **supplied)
                rejected += 1
                self.assertEqual([], started)
        self.assertEqual(["invalid-public-child-binding"] * rejected, world.effects)
        self.assertEqual([], world.events)

    def test_manifest_output_escape_and_unsafe_parent_reject_before_spawn(self):
        world, root, commands, started = self.world()
        foreign = root / "foreign"
        foreign.mkdir(mode=0o700)
        (world.base / "linked-parent").symlink_to(foreign, target_is_directory=True)
        unsafe = world.base / "unsafe-parent"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        basename = "deployment-source-manifest.json"
        paths = [str(world.base / ".." / "foreign" / basename),
                 str(world.base / "linked-parent" / basename),
                 str(foreign / basename), str(unsafe / basename),
                 str(world.base / "manifest-parent/wrong.json"), basename]
        command, supplied = commands[1]
        for path in paths:
            with self.subTest(path=Path(path).name), self.assertRaises(AssertionError):
                world.public_run([*command[:-1], path], **supplied)
            self.assertEqual([], started)
        self.assertEqual(["invalid-public-child-binding"] * len(paths), world.effects)
        self.assertEqual([], world.events)

    def test_public_key_path_binding_rejects_before_spawn(self):
        world, root, commands, started = self.world()
        foreign = root / "foreign.pub"
        foreign.write_bytes(world.public)
        linked = world.base / "linked.pub"
        linked.symlink_to("PUBLIC.pub")
        wrong = world.base / "wrong.pub"
        wrong.write_bytes(b"PUBLIC wrong bytes\n")
        directory = world.base / "not-a-key.pub"
        directory.mkdir()
        paths = [str(foreign), str(linked), str(wrong), str(directory), "PUBLIC.pub"]
        command, supplied = commands[0]
        for path in paths:
            with self.subTest(path=Path(path).name), self.assertRaises(AssertionError):
                world.public_run([*command[:-1], path], **supplied)
            self.assertEqual([], started)
        self.assertEqual(["invalid-public-child-binding"] * len(paths), world.effects)
        self.assertEqual([], world.events)


if __name__ == "__main__":
    unittest.main()
