#!/usr/bin/env python3
"""Isolated contracts for remote code-tree deployment writers."""

from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.public_project_fixture import materialized_public_project


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
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


SYNC = load_module("deployment_writer_sync", TOOLS / "sync-code.py")
UPLOAD = load_module("deployment_writer_upload", TOOLS / "tar-for-upload.py")
PASSWORD = load_module("deployment_writer_password", TOOLS / "password-update.py")


def unwrap_argparse_hyphenated_words(text: str) -> str:
    """Remove whitespace that argparse inserts after a wrapped ASCII hyphen."""
    return re.sub(
        r"(?<=[A-Za-z])-\r?\n[ \t]+(?=[A-Za-z])", "-", text,
    )


def argparse_option_help(help_text: str, option: str) -> str:
    """Return one complete argparse option block independent of terminal width."""
    match = re.search(
        rf"(?m)^[ \t]+{re.escape(option)}(?:[ \t]|$)", help_text,
    )
    if match is None:
        raise AssertionError(f"missing argparse option block: {option}")
    block = help_text[match.start():].split("\n\n", 1)[0]
    unwrapped = unwrap_argparse_hyphenated_words(block)
    return " ".join(
        line.strip() for line in unwrapped.splitlines()
    )


ETH_LOCAL_HASH = "$6$local-salt$local-cumulus-password-hash"
ETH_REMOTE_HASH = "$6$remote-salt$remote-cumulus-password-hash"
IB_LOCAL_HASH = "$y$j9T$local-ib-salt$local-ib-password-hash"
IB_REMOTE_HASH = "$y$j9T$remote-ib-salt$remote-ib-password-hash"
NVL_LOCAL_HASH = "$y$j9T$local-nvl-salt$local-nvl-password-hash"
NVL_REMOTE_HASH = "$y$j9T$remote-nvl-salt$remote-nvl-password-hash"


def global_yaml(
    *, timezone: str = "Asia/Taipei",
    eth_hash: str = ETH_LOCAL_HASH,
    ib_hash: str = IB_LOCAL_HASH,
    nvl_hash: str = NVL_LOCAL_HASH,
) -> str:
    return f"""schema_version: 2
common:
  switch:
    system:
      date-time:
        timezone: {timezone}
switches:
- eth:
    system:
      aaa:
        user:
          cumulus:
            hashed-password: {eth_hash}
- ib:
    system:
      aaa:
        user:
          admin:
            password: {ib_hash}
      security:
        password-hardening:
          state: disabled
- nvl:
    system:
      aaa:
        user:
          admin:
            password: {nvl_hash}
      security:
        password-hardening:
          state: disabled
"""


def guard_module():
    return load_module(
        "deployment_prewrite_guard_contract",
        TOOLS / "deployment_prewrite_guard.py",
    )


def sync_args(**overrides):
    values = {
        "project": "customer",
        "host": "ubuntu@worker.example",
        "port": 24995,
        "identity": None,
        "remote_root": "/var/www/html",
        "sudo": True,
        "dry_run": False,
        "include_ztp_runtime": False,
        "runtime": "native",
        "deployment_source_manifest_sha256": "a" * 64,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def upload_args(**overrides):
    values = {
        "project": "customer",
        "host": "ubuntu@worker.example",
        "port": 24995,
        "identity": None,
        "remote_dir": "/tmp",
        "remote_root": "/var/www/html",
        "deploy": False,
        "deploy_uploaded": None,
        "dry_run": False,
        "output": Path("/tmp/customer-upload.tar.gz"),
        "no_sudo": False,
        "transport": "auto",
        "upload_retries": 3,
        "transfer_timeout": 3600,
        "runtime": "native",
        "deployment_guard_source": (
            TOOLS / "deployment_prewrite_guard.py"
        ).read_text(encoding="utf-8"),
        "deployment_source_manifest_sha256": "b" * 64,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class SyncDeploymentLockTests(unittest.TestCase):
    def test_docker_rsync_uses_root_receiver_without_cross_version_chown_options(self):
        job = SYNC.SyncJob(
            label="code",
            sources=(ROOT / "tools",),
            remote_dir="/var/www/html/tools",
        )

        native = SYNC.rsync_command(job, sync_args(runtime="native", sudo=True))
        docker_sudo = SYNC.rsync_command(
            job, sync_args(runtime="docker", sudo=True),
        )
        docker_root = SYNC.rsync_command(
            job, sync_args(runtime="docker", sudo=False),
        )

        self.assertEqual("-az", native[1])
        self.assertIn("--rsync-path=sudo -n rsync", native)
        self.assertNotIn("--chown=0:0", " ".join(native))
        self.assertNotIn("-rlptDz", native)
        self.assertEqual("-rlptDz", docker_sudo[1])
        self.assertEqual("-rlptDz", docker_root[1])
        self.assertIn("--rsync-path=sudo -n /usr/bin/rsync", docker_sudo)
        self.assertIn("--rsync-path=/usr/bin/rsync", docker_root)
        for command in (docker_sudo, docker_root):
            with self.subTest(command=command):
                rendered = " ".join(command)
                self.assertNotIn("--chown", rendered)
                self.assertNotIn("--usermap", rendered)
                self.assertNotIn("--groupmap", rendered)
                self.assertNotIn("-az", command)
                self.assertNotIn("--owner", command)
                self.assertNotIn("--group", command)

    def test_upload_accepts_host_as_second_positional_operand(self):
        positional = UPLOAD.parse_args([
            "customer", "ubuntu@worker.example", "--port", "10518",
        ])
        interspersed = UPLOAD.parse_args([
            "customer", "--port", "10518", "ubuntu@worker.example",
        ])
        option = UPLOAD.parse_args([
            "customer", "--host", "ubuntu@worker.example", "--port", "10518",
        ])
        project_option = UPLOAD.parse_args([
            "--project", "customer", "ubuntu@worker.example", "--port", "10518",
        ])

        for args in (positional, interspersed, option, project_option):
            self.assertEqual("customer", args.project)
            self.assertEqual("ubuntu@worker.example", args.host)
            self.assertEqual(10518, args.port)

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                UPLOAD.parse_args([
                    "customer", "ubuntu@worker.example",
                    "--host", "root@other.example",
                ])

    def test_positional_upload_host_drives_pinned_remote_commands(self):
        args = UPLOAD.parse_args([
            "customer", "ubuntu@worker.example", "--port", "10518",
            "--identity", "/tmp/id_ed25519",
        ])
        command = UPLOAD.recommended_remote_load_command(
            args, Path("/tmp/customer"),
        )
        self.assertEqual("ssh", command[0])
        self.assertIn("10518", command)
        self.assertIn("/tmp/id_ed25519", command)
        self.assertEqual("ubuntu@worker.example", command[-2])
        self.assertIn("11-load.py customer", command[-1])

    def test_sync_payload_covers_every_local_source_manifest_member(self):
        self.assertIsNotNone(shutil.which("rsync"), "rsync is required by sync-code")
        fixture = materialized_public_project(ROOT)
        project = fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "deployment-source-manifest.json"
            SYNC.project_contract.write_deployment_source_manifest(manifest)
            jobs = SYNC.build_jobs(project, "/var/www/html")
            workspace = next(job for job in jobs if job.label == "workspace files")
            self.assertIn(ROOT / ".dockerignore", workspace.sources)
            self.assertIn(
                ROOT / "requirements-container-top-level.lock",
                workspace.sources,
            )
            self.assertIn(ROOT / "user-manual.html", workspace.sources)
            jobs.append(SYNC.deployment_source_manifest_job(
                manifest, "/var/www/html",
            ))
            transmitted = set()
            for job in jobs:
                command = ["rsync", "-a", "--dry-run", "--out-format=%n"]
                for pattern in job.excludes:
                    command += ["--exclude", pattern]
                command += [
                    os.fspath(source) + ("/" if source.is_dir() else "")
                    for source in job.sources
                ]
                command.append(os.fspath(Path(temporary) / "destination") + "/")
                result = subprocess.run(
                    command, capture_output=True, text=True, check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                prefix = job.remote_dir.removeprefix("/var/www/html").strip("/")
                for raw_name in result.stdout.splitlines():
                    name = raw_name.rstrip("/")
                    if not name:
                        continue
                    transmitted.add("/".join(part for part in (prefix, name) if part))
            authority = json.loads(manifest.read_text(encoding="ascii"))
            required = {record["path"] for record in authority["files"]}
        self.assertTrue(required <= transmitted, sorted(required - transmitted))
        for runtime_path in (
            "ethernet/monitor/cron.lock",
            "monitor/.generate-monitor-html.lock",
            "monitor/status/.switch-collection-cooldown.lock",
            "monitor/status/.yaml-backup-cooldown.lock",
            "ethernet/monitor/eth.csv",
            "infiniband/monitor/ib.csv",
            "nvlink/monitor/nvsw.csv",
            "infiniband/bringup/xdr-upgrade/ib.csv",
            "infiniband/bringup/xdr-initial-setup/ib.csv",
        ):
            with self.subTest(runtime_path=runtime_path):
                self.assertNotIn(runtime_path, transmitted)

    def test_sync_rejects_unsafe_toplevel_lock_before_remote_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            outside = base / "outside-lock"
            outside.write_bytes(b"outside sentinel\n")
            sentinel = outside.read_bytes()
            for kind in ("symlink", "hardlink", "empty", "oversize"):
                with self.subTest(kind=kind):
                    root = base / kind
                    day0 = root / "DAY0-Prepare"
                    project = day0 / "project"
                    project.mkdir(parents=True)
                    (project / "02-devices_config.csv").write_text(
                        "hostname\n", encoding="utf-8",
                    )
                    for directory in SYNC.CODE_DIRECTORIES:
                        (root / directory).mkdir(exist_ok=True)
                    (root / "tools/lldp-analyze-tool").mkdir()
                    (day0 / "template").mkdir()
                    lock = root / "requirements-container-top-level.lock"
                    if kind == "symlink":
                        lock.symlink_to(outside)
                    elif kind == "hardlink":
                        os.link(outside, lock)
                    elif kind == "empty":
                        lock.write_bytes(b"")
                    else:
                        lock.write_bytes(b"x" * (64 * 1024 + 1))

                    with (
                        mock.patch.object(SYNC, "ROOT", root),
                        mock.patch.object(SYNC, "DAY0", day0),
                        mock.patch.object(SYNC.shutil, "which", return_value="/bin/tool"),
                        mock.patch.object(
                            SYNC.project_contract,
                            "write_deployment_source_manifest",
                            side_effect=lambda path: Path(path).write_bytes(b"receipt\n"),
                        ),
                        mock.patch.object(
                            SYNC.project_contract,
                            "deployment_prewrite_guard_source",
                            return_value="guard",
                        ),
                        mock.patch.object(
                            SYNC, "load_frozen_password_contract",
                            return_value=SimpleNamespace(),
                        ),
                        mock.patch.object(
                            SYNC,
                            "acquire_remote_deployment_lock",
                            side_effect=RuntimeError(
                                "remote operation must not be reached",
                            ),
                        ) as remote,
                        redirect_stderr(io.StringIO()),
                    ):
                        code = SYNC.main([
                            "--project", "project",
                            "--host", "worker.example",
                            "--dry-run",
                        ])
                    self.assertEqual(1, code)
                    remote.assert_not_called()
                    self.assertEqual(sentinel, outside.read_bytes())

    def test_runtime_selection_defaults_native_and_accepts_docker(self):
        sync_native = SYNC.parse_args([
            "-p", "customer", "--host", "ubuntu@worker.example",
        ])
        sync_docker = SYNC.parse_args([
            "-p", "customer", "--host", "ubuntu@worker.example",
            "--runtime", "docker",
        ])
        upload_native = UPLOAD.parse_args(["-p", "customer", "--dry-run"])
        upload_docker = UPLOAD.parse_args([
            "-p", "customer", "--dry-run", "--runtime", "docker",
        ])
        self.assertEqual("native", sync_native.runtime)
        self.assertEqual("docker", sync_docker.runtime)
        self.assertEqual("native", upload_native.runtime)
        self.assertEqual("docker", upload_docker.runtime)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                SYNC.parse_args([
                    "-p", "customer", "--host", "ubuntu@worker.example",
                    "--runtime", "docker", "--remote-root", "/srv/http",
                ])
            with self.assertRaises(SystemExit):
                UPLOAD.parse_args([
                    "-p", "customer", "--dry-run", "--runtime", "docker",
                    "--remote-root", "/srv/http",
                ])

    def test_sync_help_routes_source_writes_by_explicit_runtime(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            SYNC.parse_args(["--help"])
        self.assertEqual(0, stopped.exception.code)
        help_text = output.getvalue()
        self.assertIn(
            "Native/systemd：重新执行 DAY0-Prepare/11-load.py", help_text,
        )
        self.assertIn(
            "Docker/Supervisor：source write 后必须执行 infra/docker/deploy.sh deploy",
            help_text,
        )
        self.assertIn("deploy-preloaded <IMAGE_ID>", help_text)
        self.assertIn(
            "load 仅用于没有 source write 且已有运行中的 inactive 控制容器",
            help_text,
        )
        self.assertNotIn("同步后立即到管理服务器重新执行 load", help_text)
        self.assertNotIn("同步后必须立即重新 load", help_text)

        include_option = argparse_option_help(help_text, "--include-ztp-runtime")
        self.assertIn("Native 后续执行 11-load.py", include_option)
        self.assertIn("Docker 后续执行 deploy", include_option)
        self.assertIn("deploy-preloaded", include_option)
        self.assertIn("不能 load", include_option)

        examples = help_text.split("常用示例：", 1)[1]
        logical = examples.replace("\\\n", " ")
        commands = [
            line.strip() for line in logical.splitlines()
            if line.strip().startswith("python3 tools/sync-code.py")
        ]
        self.assertGreaterEqual(len(commands), 4)
        for command in commands:
            with self.subTest(command=command):
                self.assertRegex(
                    command, r"(?:^|\s)--runtime (?:native|docker)(?:\s|$)",
                )
        self.assertTrue(any("--runtime native" in command for command in commands))
        self.assertTrue(any("--runtime docker" in command for command in commands))

    def test_sync_help_contract_is_terminal_width_independent(self):
        for width in ("40", "70", "90", "140", "160"):
            with self.subTest(columns=width), mock.patch.dict(
                os.environ, {"COLUMNS": width}, clear=False,
            ):
                output = io.StringIO()
                with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
                    SYNC.parse_args(["--help"])
                self.assertEqual(0, stopped.exception.code)
                include_option = argparse_option_help(
                    output.getvalue(), "--include-ztp-runtime",
                )
                self.assertIn("deploy-preloaded", include_option)

    def test_help_wrap_normalizer_does_not_hide_a_same_line_typo(self):
        self.assertEqual(
            "deploy-preloaded",
            unwrap_argparse_hyphenated_words("deploy-\n    preloaded"),
        )
        self.assertEqual(
            "deploy- preloaded",
            unwrap_argparse_hyphenated_words("deploy- preloaded"),
        )

    def test_upload_help_routes_live_tree_through_the_frozen_guard(self):
        help_text = UPLOAD.HELP_EPILOG
        guard_source = (TOOLS / "deployment_prewrite_guard.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("校验归档后直接解压即可", help_text)
        self.assertIn("禁止对 live /var/www/html 手工解压", help_text)
        self.assertIn("deployment_prewrite_guard.py", help_text)
        self.assertIn("--runtime docker", help_text)
        self.assertIn("run_locked_archive", guard_source)
        self.assertIn('runtime == "docker"', guard_source)

    def test_explicit_docker_runtime_persists_ownership_without_existing_container(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory).resolve()
            changed = guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=state_root,
                which=lambda _name: None, docker_requested=True,
            )
            self.assertTrue(changed)
            owner = json.loads(
                (state_root / "deployment-owner.json").read_text(encoding="utf-8")
            )
            self.assertEqual("docker", owner["runtime"])
            self.assertEqual("/var/www/html", owner["http_root"])
            self.assertTrue((state_root / "rebuild-required.json").is_file())

            with self.assertRaisesRegex(guard.GuardError, "Docker.*unavailable"):
                guard.quiesce_for_source_update(
                    Path("/var/www/html"), state_root=state_root,
                    which=lambda _name: None,
                )

    def test_docker_source_commit_normalizes_exact_manifest_members_before_receipt(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            state = base / "state"
            source = root / "tools/source.py"
            manifest = root / "infra/docker/deployment-source-manifest.json"
            source.parent.mkdir(parents=True)
            manifest.parent.mkdir(parents=True)
            state.mkdir()
            source.write_bytes(b"source\n")
            records = {
                "tools/source.py": {
                    "path": "tools/source.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                },
            }
            manifest.write_text(json.dumps({
                "schema_version": 1, "files": list(records.values()),
            }) + "\n", encoding="ascii")
            events = []
            with mock.patch.object(
                guard, "_normalize_manifest_tree_ownership_held",
                side_effect=lambda *_args, **kwargs: events.append(
                    ("normalize", kwargs["target_uid"], kwargs["target_gid"])
                ),
            ) as normalize, mock.patch.object(
                guard, "_verify_manifest_tree_held",
                side_effect=lambda *_args, **kwargs: events.append(
                    ("verify", kwargs["required_owner"])
                ),
            ) as verify, mock.patch.object(
                guard, "write_deployment_owner",
                side_effect=lambda *_args, **_kwargs: events.append(("receipt",)),
            ):
                guard._finalize_live_source_update(
                    root, state, {}, docker_managed=True,
                )
            normalize.assert_called_once()
            self.assertEqual(4, verify.call_count)
            self.assertEqual(
                [
                    ("normalize", 0, 0),
                    ("verify", (0, 0)),
                    ("verify", (0, 0)),
                    ("verify", (0, 0)),
                    ("receipt",),
                    ("verify", (0, 0)),
                ],
                events,
            )

    def test_manifest_ownership_normalizer_is_no_follow_and_content_preserving(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "html"
            source = root / "tools/source.py"
            alias = root / "tools/source-link.py"
            manifest = root / "infra/docker/deployment-source-manifest.json"
            source.parent.mkdir(parents=True)
            manifest.parent.mkdir(parents=True)
            source.write_bytes(b"source\n")
            alias.symlink_to("source.py")
            manifest.write_bytes(b"manifest\n")
            records = {
                "tools/source.py": {
                    "path": "tools/source.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                },
                "tools/source-link.py": {
                    "path": "tools/source-link.py", "type": "symlink",
                    "target": "source.py",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                },
            }
            before = (source.read_bytes(), os.readlink(alias), manifest.read_bytes())
            guard._normalize_manifest_tree_ownership(
                root, records, target_uid=os.getuid(), target_gid=os.getgid(),
            )
            self.assertEqual(
                before, (source.read_bytes(), os.readlink(alias), manifest.read_bytes()),
            )
            alias.unlink()
            alias.symlink_to("../outside")
            with self.assertRaisesRegex(guard.GuardError, "symlink changed"):
                guard._normalize_manifest_tree_ownership(
                    root, records, target_uid=os.getuid(), target_gid=os.getgid(),
                )

    def test_absent_container_with_persistent_docker_owner_stays_docker_managed(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory).resolve()
            guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=state_root,
                which=lambda _name: None, docker_requested=True,
            )
            absent = mock.Mock(return_value=SimpleNamespace(
                returncode=1, stdout="", stderr="Error: No such object: http-ztp",
            ))
            self.assertTrue(guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=state_root,
                runner=absent, which=lambda _name: "/usr/bin/docker",
            ))

    def test_prewrite_guard_stops_exact_labeled_container_before_state_mutation(self):
        guard = guard_module()
        events = []
        inspections = iter((True, False))

        def runner(command, **_kwargs):
            if command[:3] == ["docker", "container", "inspect"]:
                running = next(inspections)
                payload = [{
                    "Id": "a" * 64,
                    "Name": "/http-ztp",
                    "Config": {"Labels": {
                        "com.nvidia.http-ztp.managed": "true",
                        "com.nvidia.http-ztp.http-root": "/var/www/html",
                    }},
                    "Mounts": [{
                        "Type": "bind", "Source": "/var/www/html",
                        "Destination": "/var/www/html", "RW": True,
                    }],
                    "State": {
                        "Running": running, "Restarting": False,
                        "Paused": False, "Status": "running" if running else "exited",
                        "Pid": 321 if running else 0, "Dead": False,
                    },
                }]
                events.append("inspect-running" if running else "inspect-stopped")
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(payload), stderr="",
                )
            if command[:2] == ["docker", "stop"]:
                self.assertEqual("a" * 64, command[-1])
                events.append("docker-stop")
                return SimpleNamespace(returncode=0, stdout="http-ztp\n", stderr="")
            self.fail(f"unexpected command: {command}")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            guard, "clear_activation_marker",
            side_effect=lambda _path: events.append("clear-activation"),
        ), mock.patch.object(
            guard, "write_rebuild_required",
            side_effect=lambda _path, _reason: events.append("write-rebuild-required"),
        ):
            changed = guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=Path(directory).resolve(),
                runner=runner, which=lambda _name: "/usr/bin/docker",
            )
        self.assertTrue(changed)
        self.assertEqual(
            ["inspect-running", "docker-stop", "inspect-stopped",
             "clear-activation", "write-rebuild-required"],
            events,
        )

    def test_docker_source_write_contract_requires_redeploy_and_running_load(self):
        """Bind guard quiesce, sync NEXT, and deploy load as one workflow."""
        guard = guard_module()
        inspections = iter((True, False))
        events: list[str] = []

        def runner(command, **_kwargs):
            if command[:3] == ["docker", "container", "inspect"]:
                running = next(inspections)
                payload = [{
                    "Id": "c" * 64,
                    "Name": "/http-ztp",
                    "Config": {"Labels": {
                        "com.nvidia.http-ztp.managed": "true",
                        "com.nvidia.http-ztp.http-root": "/var/www/html",
                    }},
                    "Mounts": [{
                        "Type": "bind", "Source": "/var/www/html",
                        "Destination": "/var/www/html", "RW": True,
                    }],
                    "State": {
                        "Running": running, "Restarting": False,
                        "Paused": False,
                        "Status": "running" if running else "exited",
                        "Pid": 456 if running else 0, "Dead": False,
                    },
                }]
                events.append("inspect-running" if running else "inspect-stopped")
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(payload), stderr="",
                )
            if command[:2] == ["docker", "stop"]:
                self.assertEqual("c" * 64, command[-1])
                events.append("docker-stop")
                return SimpleNamespace(returncode=0, stdout="http-ztp\n", stderr="")
            self.fail(f"unexpected command: {command}")

        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory).resolve()
            changed = guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=state_root,
                runner=runner, which=lambda _name: "/usr/bin/docker",
            )
            self.assertTrue(changed)
            marker = json.loads(
                (state_root / "rebuild-required.json").read_text(encoding="utf-8")
            )
        self.assertEqual(
            ["inspect-running", "docker-stop", "inspect-stopped"], events,
        )
        self.assertIn("rebuilt http-ztp image", marker["reason"])

        sync_source = (TOOLS / "sync-code.py").read_text(encoding="utf-8")
        next_branch = sync_source.split(
            'print("\\n[OK] " +', 1
        )[1].split("else:", 1)[0]
        self.assertIn("if docker_rebuild_required:", next_branch)
        self.assertIn("./infra/docker/deploy.sh deploy", next_branch)
        self.assertNotIn("./infra/docker/deploy.sh load", next_branch)

        deploy_source = (ROOT / "infra/docker/deploy.sh").read_text(encoding="utf-8")
        owned_function = deploy_source.split("owned_container_id() {", 1)[1].split(
            "container_id_running()", 1
        )[0]
        self.assertIn(
            '[[ "$require_running" == "true" ]] && arguments+=(--require-running)',
            owned_function,
        )
        load_branch = deploy_source.split("  load)", 1)[1].split("    ;;", 1)[0]
        self.assertIn("owned_container_id true true false", load_branch)
        self.assertIn('run_load "$container_id"', load_branch)

    def test_prewrite_guard_failure_prevents_payload_and_state_promotion(self):
        guard = guard_module()
        events = []

        @contextmanager
        def held(_path, **_kwargs):
            events.append("lock-enter")
            try:
                yield 9
            finally:
                events.append("lock-release")

        with mock.patch.object(guard, "safe_lock", side_effect=held), \
                mock.patch.object(
                    guard, "quiesce_for_source_update",
                    side_effect=guard.GuardError("injected docker stop failure"),
                ), mock.patch.object(guard.subprocess, "run") as payload:
            with self.assertRaisesRegex(guard.GuardError, "stop failure"):
                guard.run_locked_payload(
                    Path("/var/www/html/.deployment.lock"),
                    Path("/var/www/html"), "printf payload", protect_docker=True,
                )
        self.assertEqual(["lock-enter", "lock-release"], events)
        payload.assert_not_called()

    def test_prewrite_guard_rejects_wrong_label_without_stopping_or_writing(self):
        guard = guard_module()
        payload = [{
            "Id": "b" * 64,
            "Name": "/http-ztp",
            "Config": {"Labels": {
                "com.nvidia.http-ztp.managed": "false",
                "com.nvidia.http-ztp.http-root": "/var/www/html",
            }},
            "State": {
                "Running": True, "Restarting": False,
                "Paused": False, "Status": "running", "Pid": 321,
                "Dead": False,
            },
        }]
        runner = mock.Mock(return_value=SimpleNamespace(
            returncode=0, stdout=json.dumps(payload), stderr="",
        ))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            guard, "clear_activation_marker",
        ) as clear, mock.patch.object(
            guard, "write_rebuild_required",
        ) as rebuild:
            with self.assertRaisesRegex(guard.GuardError, "label"):
                guard.quiesce_for_source_update(
                    Path("/var/www/html"), state_root=Path(directory),
                    runner=runner, which=lambda _name: "/usr/bin/docker",
                )
        self.assertEqual(1, runner.call_count)
        clear.assert_not_called()
        rebuild.assert_not_called()

    def test_prewrite_guard_requires_exact_readwrite_http_root_bind(self):
        guard = guard_module()
        base = {
            "Id": "c" * 64,
            "Name": "/http-ztp",
            "Config": {"Labels": {
                "com.nvidia.http-ztp.managed": "true",
                "com.nvidia.http-ztp.http-root": "/var/www/html",
            }},
            "State": {
                "Running": False, "Restarting": False, "Paused": False,
                "Status": "exited", "Pid": 0, "Dead": False,
            },
        }
        invalid_mounts = (
            [],
            [{"Type": "bind", "Source": "/srv/http", "Destination": "/var/www/html", "RW": True}],
            [{"Type": "bind", "Source": "/var/www/html", "Destination": "/srv/http", "RW": True}],
            [{"Type": "bind", "Source": "/var/www/html", "Destination": "/var/www/html", "RW": False}],
            [{"Type": "volume", "Source": "/var/www/html", "Destination": "/var/www/html", "RW": True}],
        )
        for mounts in invalid_mounts:
            with self.subTest(mounts=mounts):
                record = {**base, "Mounts": mounts}
                runner = mock.Mock(return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps([record]), stderr="",
                ))
                with tempfile.TemporaryDirectory() as directory, \
                        self.assertRaisesRegex(guard.GuardError, "bind"):
                    guard.quiesce_for_source_update(
                        Path("/var/www/html"), state_root=Path(directory),
                        runner=runner, which=lambda _name: "/usr/bin/docker",
                    )

    def test_prewrite_guard_is_noop_without_docker_or_managed_container(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            guard, "clear_activation_marker",
        ) as clear, mock.patch.object(
            guard, "write_rebuild_required",
        ) as rebuild:
            self.assertFalse(guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=Path(directory),
                which=lambda _name: None,
            ))
            absent = mock.Mock(return_value=SimpleNamespace(
                returncode=1, stdout="", stderr="Error: No such object: http-ztp",
            ))
            self.assertFalse(guard.quiesce_for_source_update(
                Path("/var/www/html"), state_root=Path(directory),
                runner=absent, which=lambda _name: "/usr/bin/docker",
            ))
        clear.assert_not_called()
        rebuild.assert_not_called()

    def test_remote_holders_forward_explicit_runtime_contract(self):
        sync = SYNC.remote_deployment_lock_command(sync_args(runtime="docker"))
        self.assertIn("--runtime docker", sync[-1])
        payload = UPLOAD.deployment_payload_command(
            upload_args(runtime="docker"), "/tmp/customer-upload.tar.gz",
            "a" * 64,
        )
        self.assertIn("--runtime docker", payload)

    def test_embedded_guard_is_single_fd_frozen_and_bound_to_source_manifest(self):
        common = SYNC.project_contract
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard = root / "deployment_prewrite_guard.py"
            guard.write_text("print('approved guard')\n", encoding="utf-8")
            manifest = root / "deployment-source-manifest.json"
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/deployment_prewrite_guard.py",
                    "type": "file", "target": None,
                    "sha256": hashlib.sha256(guard.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            with mock.patch.object(common, "DEPLOYMENT_PREWRITE_GUARD", guard):
                frozen = common.deployment_prewrite_guard_source(manifest)
                self.assertEqual("print('approved guard')\n", frozen)
                guard.write_text("print('changed guard')\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "changed"):
                    common.deployment_prewrite_guard_source(manifest)

    def test_project_rsync_excludes_global_for_dedicated_merge(self):
        fixture = materialized_public_project(ROOT)
        project = fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        project_job = next(
            job for job in SYNC.build_jobs(project, "/var/www/html")
            if job.label == f"project:{project.name}"
        )
        self.assertIn("/01-global.yaml", project_job.excludes)

    def test_global_plan_preserves_only_remote_password_hashes(self):
        local = global_yaml(timezone="Asia/Taipei").encode()
        remote = global_yaml(
            timezone="UTC", eth_hash=ETH_REMOTE_HASH,
            ib_hash=IB_REMOTE_HASH, nvl_hash=NVL_REMOTE_HASH,
        ).encode()
        plan = SYNC.build_global_sync_plan(
            local, remote, password_contract=PASSWORD,
        )
        candidate = plan.candidate_bytes.decode()
        self.assertEqual("merge-local-preserve-remote-passwords", plan.action)
        self.assertIn("timezone: Asia/Taipei", candidate)
        self.assertNotIn("timezone: UTC", candidate)
        self.assertEqual(
            {
                "eth": ETH_REMOTE_HASH,
                "ib": IB_REMOTE_HASH,
                "nvl": NVL_REMOTE_HASH,
            },
            PASSWORD.extract_password_hashes(
                candidate, sections=("eth", "ib", "nvl"),
            ),
        )

    def test_password_only_remote_drift_is_a_true_noop(self):
        local = global_yaml().encode()
        remote = global_yaml(
            eth_hash=ETH_REMOTE_HASH,
            ib_hash=IB_REMOTE_HASH,
            nvl_hash=NVL_REMOTE_HASH,
        ).encode()
        plan = SYNC.build_global_sync_plan(
            local, remote, password_contract=PASSWORD,
        )
        self.assertEqual("identical-after-password-preservation", plan.action)
        self.assertEqual(remote, plan.candidate_bytes)
        self.assertFalse(plan.changed)

    def test_missing_remote_global_initializes_from_valid_local(self):
        local = global_yaml().encode()
        plan = SYNC.build_global_sync_plan(
            local, None, password_contract=PASSWORD,
        )
        self.assertEqual("initialize-remote", plan.action)
        self.assertEqual(local, plan.candidate_bytes)
        self.assertTrue(plan.changed)

    def test_malformed_remote_password_fails_before_any_write(self):
        remote = global_yaml(eth_hash="not-a-crypt-hash").encode()
        with self.assertRaisesRegex(PASSWORD.PasswordUpdateError, "eth.*合法"):
            SYNC.build_global_sync_plan(
                global_yaml().encode(), remote, password_contract=PASSWORD,
            )

    def test_password_update_to_sync_workflow_preserves_vm_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            remote_global = Path(directory) / "01-global.yaml"
            remote_global.write_text(global_yaml(timezone="UTC"), encoding="utf-8")
            PASSWORD.update_global_file(
                remote_global,
                {
                    "eth": ETH_REMOTE_HASH,
                    "ib": IB_REMOTE_HASH,
                    "nvl": NVL_REMOTE_HASH,
                },
                sections=("eth", "ib", "nvl"), dry_run=False,
            )
            plan = SYNC.build_global_sync_plan(
                global_yaml(timezone="Asia/Taipei").encode(),
                remote_global.read_bytes(), password_contract=PASSWORD,
            )
        candidate = plan.candidate_bytes.decode("utf-8")
        self.assertIn("timezone: Asia/Taipei", candidate)
        self.assertEqual(
            {
                "eth": ETH_REMOTE_HASH,
                "ib": IB_REMOTE_HASH,
                "nvl": NVL_REMOTE_HASH,
            },
            PASSWORD.extract_password_hashes(
                candidate, sections=("eth", "ib", "nvl"),
            ),
        )

    def test_remote_global_atomic_commit_is_cas_bound_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote_project = root / "DAY0-Prepare/customer"
            remote_project.mkdir(parents=True)
            remote_global = remote_project / "01-global.yaml"
            original = global_yaml(timezone="UTC").encode()
            candidate = global_yaml(timezone="Asia/Taipei").encode()
            remote_global.write_bytes(original)
            original_sha = hashlib.sha256(original).hexdigest()
            candidate_sha = hashlib.sha256(candidate).hexdigest()
            args = sync_args(remote_root=str(root), sudo=False)
            project = Path("/local/customer")

            probe = shlex.split(
                SYNC.remote_global_snapshot_command(project, args)[-1]
            )
            before = subprocess.run(
                probe, check=False, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, before.returncode, before.stderr)
            snapshot = json.loads(before.stdout)
            self.assertEqual(original_sha, snapshot["sha256"])

            commit = shlex.split(
                SYNC.remote_global_commit_command(
                    project, args, original_sha, candidate_sha,
                )[-1]
            )
            committed = subprocess.run(
                commit, input=candidate, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, committed.returncode, committed.stderr)
            self.assertEqual(candidate, remote_global.read_bytes())
            self.assertEqual(candidate_sha, committed.stdout.decode().strip())

            raced = global_yaml(timezone="Europe/London").encode()
            remote_global.write_bytes(raced)
            rejected = subprocess.run(
                commit, input=candidate, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual(raced, remote_global.read_bytes())

            outside = root / "outside-global"
            outside.write_bytes(original)
            remote_global.unlink()
            remote_global.symlink_to(outside)
            symlink_rejected = subprocess.run(
                commit, input=candidate, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, symlink_rejected.returncode)
            self.assertEqual(original, outside.read_bytes())

    def test_rsync_preview_returns_every_changed_job_in_original_order(self):
        jobs = [
            SYNC.SyncJob("one", (Path("/one"),), "/remote/one"),
            SYNC.SyncJob("two", (Path("/two"),), "/remote/two"),
            SYNC.SyncJob("three", (Path("/three"),), "/remote/three"),
        ]
        results = iter((
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=0, stdout=">f.st......|changed.py\n", stderr=""),
            SimpleNamespace(returncode=0, stdout=">f.st......|also-changed.py\n", stderr=""),
        ))
        with mock.patch.object(SYNC.subprocess, "run", side_effect=lambda *_a, **_k: next(results)) as run:
            changed = SYNC.sync_jobs_have_changes(jobs, sync_args())
        self.assertEqual((jobs[1], jobs[2]), changed)
        self.assertEqual(3, run.call_count)

    def test_remote_holder_uses_same_nonblocking_flock_as_load(self):
        command = SYNC.remote_deployment_lock_command(sync_args())
        self.assertEqual("ssh", command[0])
        self.assertIn("ServerAliveInterval=15", command)
        remote = shlex.split(command[-1])
        self.assertEqual(["sudo", "-n", "python3", "-c"], remote[:4])
        self.assertIn("O_NOFOLLOW", remote[4])
        self.assertIn("flock", remote[4])
        self.assertIn(SYNC.DEPLOYMENT_LOCK_READY, remote[4])
        self.assertIn("--holder", remote)
        self.assertEqual(
            "/var/www/html/.deployment.lock",
            remote[remote.index("--lock") + 1],
        )
        self.assertEqual("/var/www/html", remote[remote.index("--root") + 1])

    def test_prewrite_timeout_exceeds_bounded_inspect_stop_postinspect_window(self):
        self.assertGreaterEqual(SYNC.DEPLOYMENT_PREWRITE_TIMEOUT, 90)
        self.assertGreater(
            SYNC.DEPLOYMENT_PREWRITE_TIMEOUT, SYNC.DEPLOYMENT_LOCK_TIMEOUT,
        )

    def test_dry_run_never_opens_remote_lock_connection(self):
        with mock.patch.object(SYNC.subprocess, "Popen") as popen, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = SYNC.acquire_remote_deployment_lock(sync_args(dry_run=True))
        self.assertIsNone(result)
        popen.assert_not_called()

    def test_remote_marker_command_survives_openssh_shell_round_trip(self):
        """The command after the SSH host must be one fully quoted string."""
        with tempfile.TemporaryDirectory() as directory:
            args = sync_args(remote_root=directory, sudo=False)
            marker = Path(directory) / ".sync-code-in-progress"
            # Production runs on GNU/Linux; provide the one GNU stat operation
            # used by the guard so this wire-format test is also portable to
            # the macOS development host.
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_stat = fake_bin / "stat"
            fake_stat.write_text("#!/bin/sh\nprintf '1\\n'\n", encoding="utf-8")
            fake_stat.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = f"{fake_bin}:{environment.get('PATH', '')}"

            create = SYNC.remote_sync_marker_command(args, present=True)
            self.assertEqual(args.host, create[-2])
            self.assertEqual(len(create), create.index(args.host) + 2)
            create_remote = shlex.split(create[-1])
            self.assertEqual(["sh", "-c"], create_remote[:2])
            self.assertEqual("sync-marker", create_remote[-2])
            self.assertEqual(str(marker), create_remote[-1])
            created = subprocess.run(
                ["sh", "-c", create[-1]], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=environment,
            )
            self.assertEqual(0, created.returncode, created.stderr)
            self.assertTrue(marker.is_file())

            remove = SYNC.remote_sync_marker_command(args, present=False)
            removed = subprocess.run(
                ["sh", "-c", remove[-1]], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=environment,
            )
            self.assertEqual(0, removed.returncode, removed.stderr)
            self.assertFalse(marker.exists())

    def test_main_holds_lock_through_marker_and_prints_docker_redeploy(self):
        events: list[str] = []
        args = sync_args()
        project = Path("/tmp/customer")
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        lock = object()
        plan = SimpleNamespace(
            changed=True,
        )

        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(SYNC, "resolve_project", return_value=project),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.multiple(
                SYNC,
                run_predeploy_test_gate=mock.Mock(
                    side_effect=lambda: events.append("gate"),
                ),
                verify_predeploy_test_approval=mock.Mock(
                    side_effect=lambda: events.append("approval:recheck"),
                ),
                load_frozen_password_contract=mock.Mock(
                    side_effect=lambda _path: events.append(
                        "password-contract:frozen"
                    ) or PASSWORD,
                ),
            ),
            mock.patch.object(
                SYNC.project_contract, "write_deployment_source_manifest",
                side_effect=lambda path: (
                    events.append("manifest"),
                    path.write_text('{"schema_version":1,"files":[]}\n', encoding="ascii"),
                )[-1],
            ),
            mock.patch.object(
                SYNC.project_contract, "deployment_prewrite_guard_source",
                side_effect=lambda _path: events.append("guard:frozen") or "# guard\n",
            ),
            mock.patch.object(
                SYNC, "acquire_remote_deployment_lock",
                side_effect=lambda _args: events.append("lock") or lock,
            ),
            mock.patch.object(
                SYNC, "prepare_global_sync",
                side_effect=lambda _project, _args: events.append(
                    "global:preflight"
                ) or plan,
            ),
            mock.patch.object(
                SYNC, "sync_jobs_have_changes",
                side_effect=lambda received, _args: events.append("preview")
                or (received[0],),
            ),
            mock.patch.object(
                SYNC, "remote_management_placeholder_needed", return_value=False,
            ),
            mock.patch.object(
                SYNC, "prepare_remote_source_write",
                side_effect=lambda _lock: events.append("prewrite") or True,
            ),
            mock.patch.object(
                SYNC, "ensure_remote_directories",
                side_effect=lambda _jobs, _args: events.append("directories"),
            ),
            mock.patch.object(
                SYNC, "assert_remote_deployment_lock",
                side_effect=lambda _lock: events.append("held"),
            ),
            mock.patch.multiple(
                SYNC,
                set_remote_sync_marker=mock.Mock(
                    side_effect=lambda _args, *, present: events.append(
                        "marker:on" if present else "marker:off"
                    ),
                ),
                commit_remote_source_write=mock.Mock(
                    side_effect=lambda _lock: events.append("source:commit"),
                ),
            ),
            mock.patch.object(
                SYNC, "run_job",
                side_effect=lambda received, _args: events.append(
                    f"rsync:{received.label}"
                ),
            ),
            mock.patch.object(
                SYNC, "ensure_remote_management_placeholder",
                side_effect=lambda _project, _args: events.append("placeholder"),
            ),
            mock.patch.object(
                SYNC, "commit_remote_global",
                side_effect=lambda _project, _args, received: events.append(
                    "global:commit"
                ) if received is plan else self.fail("wrong global plan"),
            ),
            mock.patch.object(
                SYNC, "release_remote_deployment_lock",
                side_effect=lambda _lock: events.append("unlock"),
            ),
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                result = SYNC.main([])

        self.assertEqual(0, result)
        self.assertEqual(
            [
                "gate", "manifest", "guard:frozen", "password-contract:frozen",
                "approval:recheck", "lock", "held",
                "global:preflight", "held", "preview",
                "held", "prewrite", "held", "directories", "held",
                "marker:on", "held", "rsync:one", "held", "placeholder",
                "held", "global:commit", "held", "source:commit", "unlock",
            ],
            events,
        )
        text = output.getvalue()
        self.assertIn("./infra/docker/deploy.sh deploy", text)
        self.assertIn("rebuild-required", text)
        self.assertNotIn("python3 11-load.py", text)

    def test_remote_source_commit_uses_explicit_holder_acknowledgement(self):
        stdin = io.StringIO()
        stdout = io.StringIO("HTTP_ZTP_COMMIT_READY\n")
        process = mock.Mock(
            stdin=stdin, stdout=stdout, stderr=io.StringIO(), returncode=None,
        )
        process.poll.return_value = None
        lock = SYNC.RemoteDeploymentLock(
            process=process, path="/var/www/html/.deployment.lock",
            docker_managed=True, prewrite_ready=True,
        )
        with mock.patch.object(SYNC.select, "select", return_value=([stdout], [], [])):
            SYNC.commit_remote_source_write(lock)
        self.assertEqual("HTTP_ZTP_COMMIT\n", stdin.getvalue())
        self.assertTrue(lock.source_committed)

    def test_prewrite_holder_and_sync_client_use_one_buffer_safe_frame(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(
                    guard.sys, "stdin", io.StringIO("HTTP_ZTP_PREWRITE\n"),
                ), mock.patch.object(
                    guard, "quiesce_for_source_update", return_value=True,
                ), mock.patch.object(
                    guard, "begin_source_update", return_value={},
                ), redirect_stdout(io.StringIO()) as holder_output:
            self.assertEqual(0, guard.run_lock_holder(
                Path(directory) / ".deployment.lock",
                Path("/var/www/html"), runtime="docker",
                expected_source_manifest_sha256="a" * 64,
            ))
        holder_lines = holder_output.getvalue().splitlines()
        self.assertEqual(guard.LOCK_READY, holder_lines[0])
        self.assertEqual(
            f"{guard.DOCKER_REBUILD_REQUIRED} {guard.PREWRITE_READY}",
            holder_lines[1],
        )

        stdin = io.StringIO()
        stdout = io.StringIO(holder_lines[1] + "\n")
        process = mock.Mock(
            stdin=stdin, stdout=stdout, stderr=io.StringIO(), returncode=None,
        )
        process.poll.return_value = None
        lock = SYNC.RemoteDeploymentLock(
            process=process, path="/var/www/html/.deployment.lock",
        )
        with mock.patch.object(
            SYNC.select, "select", return_value=([stdout], [], []),
        ) as select_call:
            self.assertTrue(SYNC.prepare_remote_source_write(lock))
        select_call.assert_called_once()
        self.assertEqual("HTTP_ZTP_PREWRITE\n", stdin.getvalue())
        self.assertTrue(lock.prewrite_ready)
        self.assertTrue(lock.docker_managed)

    def test_noop_sync_never_requests_prewrite_or_mutates_remote_tree(self):
        args = sync_args()
        project = Path("/tmp/customer")
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        lock = object()
        plan = SimpleNamespace(
            changed=False,
        )
        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(SYNC, "resolve_project", return_value=project),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(SYNC, "verify_predeploy_test_approval"),
            mock.patch.object(
                SYNC, "load_frozen_password_contract", return_value=PASSWORD,
            ),
            mock.patch.object(SYNC, "acquire_remote_deployment_lock", return_value=lock),
            mock.patch.object(SYNC, "assert_remote_deployment_lock"),
            mock.patch.object(SYNC, "prepare_global_sync", return_value=plan),
            mock.patch.object(SYNC, "sync_jobs_have_changes", return_value=()),
            mock.patch.object(
                SYNC, "remote_management_placeholder_needed", return_value=False,
            ),
            mock.patch.object(SYNC, "prepare_remote_source_write") as prewrite,
            mock.patch.object(SYNC, "ensure_remote_directories") as directories,
            mock.patch.object(SYNC, "set_remote_sync_marker") as marker,
            mock.patch.object(SYNC, "run_job") as rsync,
            mock.patch.object(SYNC, "commit_remote_global") as commit,
            mock.patch.object(SYNC, "release_remote_deployment_lock") as release,
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(0, SYNC.main([]))
        prewrite.assert_not_called()
        directories.assert_not_called()
        marker.assert_not_called()
        rsync.assert_not_called()
        commit.assert_not_called()
        release.assert_called_once_with(lock)

    def test_global_conflict_fails_before_prewrite_or_any_remote_mutation(self):
        args = sync_args()
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        lock = object()
        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(
                SYNC, "resolve_project", return_value=Path("/tmp/customer"),
            ),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(SYNC, "verify_predeploy_test_approval"),
            mock.patch.object(
                SYNC, "load_frozen_password_contract", return_value=PASSWORD,
            ),
            mock.patch.object(SYNC, "acquire_remote_deployment_lock", return_value=lock),
            mock.patch.object(SYNC, "assert_remote_deployment_lock"),
            mock.patch.object(
                SYNC, "prepare_global_sync", side_effect=RuntimeError("global conflict"),
            ),
            mock.patch.object(SYNC, "prepare_remote_source_write") as prewrite,
            mock.patch.object(SYNC, "ensure_remote_directories") as directories,
            mock.patch.object(SYNC, "set_remote_sync_marker") as marker,
            mock.patch.object(SYNC, "run_job") as rsync,
            mock.patch.object(SYNC, "release_remote_deployment_lock") as release,
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(1, SYNC.main([]))
        prewrite.assert_not_called()
        directories.assert_not_called()
        marker.assert_not_called()
        rsync.assert_not_called()
        release.assert_called_once_with(lock)

    def test_prewrite_failure_blocks_first_remote_write(self):
        args = sync_args()
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        lock = object()
        plan = SimpleNamespace(
            changed=False,
        )
        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(
                SYNC, "resolve_project", return_value=Path("/tmp/customer"),
            ),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(SYNC, "verify_predeploy_test_approval"),
            mock.patch.object(
                SYNC, "load_frozen_password_contract", return_value=PASSWORD,
            ),
            mock.patch.object(SYNC, "acquire_remote_deployment_lock", return_value=lock),
            mock.patch.object(SYNC, "assert_remote_deployment_lock"),
            mock.patch.object(SYNC, "prepare_global_sync", return_value=plan),
            mock.patch.object(SYNC, "sync_jobs_have_changes", return_value=(job,)),
            mock.patch.object(
                SYNC, "remote_management_placeholder_needed", return_value=False,
            ),
            mock.patch.object(
                SYNC, "prepare_remote_source_write",
                side_effect=RuntimeError("docker stop failed"),
            ),
            mock.patch.object(SYNC, "ensure_remote_directories") as directories,
            mock.patch.object(SYNC, "set_remote_sync_marker") as marker,
            mock.patch.object(SYNC, "run_job") as rsync,
            mock.patch.object(SYNC, "release_remote_deployment_lock") as release,
            redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(1, SYNC.main([]))
        directories.assert_not_called()
        marker.assert_not_called()
        rsync.assert_not_called()
        release.assert_called_once_with(lock)

    def test_lock_release_failure_does_not_hide_prewrite_failure(self):
        args = sync_args()
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        lock = object()
        plan = SimpleNamespace(changed=False)
        error_output = io.StringIO()
        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(
                SYNC, "resolve_project", return_value=Path("/tmp/customer"),
            ),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(SYNC, "verify_predeploy_test_approval"),
            mock.patch.object(
                SYNC, "load_frozen_password_contract", return_value=PASSWORD,
            ),
            mock.patch.object(
                SYNC, "acquire_remote_deployment_lock", return_value=lock,
            ),
            mock.patch.object(SYNC, "assert_remote_deployment_lock"),
            mock.patch.object(SYNC, "prepare_global_sync", return_value=plan),
            mock.patch.object(
                SYNC, "sync_jobs_have_changes", return_value=(job,),
            ),
            mock.patch.object(
                SYNC, "remote_management_placeholder_needed", return_value=False,
            ),
            mock.patch.object(
                SYNC, "prepare_remote_source_write",
                side_effect=RuntimeError("docker prewrite root cause"),
            ),
            mock.patch.object(SYNC, "ensure_remote_directories") as directories,
            mock.patch.object(SYNC, "set_remote_sync_marker") as marker,
            mock.patch.object(SYNC, "run_job") as rsync,
            mock.patch.object(
                SYNC, "release_remote_deployment_lock",
                side_effect=RuntimeError("holder cleanup rc=255"),
            ),
            redirect_stdout(io.StringIO()), redirect_stderr(error_output),
        ):
            self.assertEqual(1, SYNC.main([]))
        self.assertIn("docker prewrite root cause", error_output.getvalue())
        self.assertIn("holder cleanup rc=255", error_output.getvalue())
        directories.assert_not_called()
        marker.assert_not_called()
        rsync.assert_not_called()

    def test_failed_sync_releases_lock_but_keeps_persistent_marker(self):
        events: list[str] = []
        args = sync_args()
        job = SYNC.SyncJob("one", (Path("/tmp/source"),), "/var/www/html/one")
        with (
            mock.patch.object(SYNC, "parse_args", return_value=args),
            mock.patch.object(SYNC, "validate_args"),
            mock.patch.object(SYNC, "resolve_project", return_value=Path("/tmp/customer")),
            mock.patch.object(SYNC, "build_jobs", return_value=[job]),
            mock.patch.object(SYNC, "run_predeploy_test_gate"),
            mock.patch.object(SYNC, "verify_predeploy_test_approval"),
            mock.patch.object(
                SYNC, "load_frozen_password_contract", return_value=PASSWORD,
            ),
            mock.patch.object(SYNC, "acquire_remote_deployment_lock", return_value=object()),
            mock.patch.object(
                SYNC, "prepare_global_sync",
                return_value=SimpleNamespace(
                    changed=False,
                ),
            ),
            mock.patch.object(SYNC, "sync_jobs_have_changes", return_value=(job,)),
            mock.patch.object(
                SYNC, "remote_management_placeholder_needed", return_value=False,
            ),
            mock.patch.object(SYNC, "prepare_remote_source_write", return_value=True),
            mock.patch.object(SYNC, "ensure_remote_directories"),
            mock.patch.object(SYNC, "assert_remote_deployment_lock"),
            mock.patch.object(
                SYNC, "set_remote_sync_marker",
                side_effect=lambda _args, *, present: events.append(
                    "marker:on" if present else "marker:off"
                ),
            ),
            mock.patch.object(SYNC, "run_job", side_effect=RuntimeError("broken rsync")),
            mock.patch.object(SYNC, "commit_remote_global") as commit,
            mock.patch.object(
                SYNC, "release_remote_deployment_lock",
                side_effect=lambda _lock: events.append("unlock"),
            ),
        ):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = SYNC.main([])
        self.assertEqual(1, result)
        self.assertEqual(["marker:on", "unlock"], events)
        commit.assert_not_called()


class ArchiveDeploymentLockTests(unittest.TestCase):
    def test_formal_upload_uses_one_private_archive_snapshot_after_approval(self):
        approved_guard = b"print('approved guard')\n"
        changed_guard = b"print('changed after snapshot')\n"

        def archive_bytes(guard_bytes):
            manifest = json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/deployment_prewrite_guard.py",
                    "type": "file", "target": None,
                    "sha256": hashlib.sha256(guard_bytes).hexdigest(),
                }],
            }).encode("ascii")
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                for name, payload in (
                    ("./tools/deployment_prewrite_guard.py", guard_bytes),
                    ("./infra/docker/deployment-source-manifest.json", manifest),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            return stream.getvalue()

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "customer-upload.tar.gz"
            source.write_bytes(archive_bytes(approved_guard))
            with UPLOAD.frozen_archive_for_upload(source) as frozen:
                frozen_path, frozen_sha256 = frozen
                source.write_bytes(archive_bytes(changed_guard))
                self.assertNotEqual(
                    hashlib.sha256(source.read_bytes()).hexdigest(), frozen_sha256,
                )
                self.assertEqual(
                    approved_guard.decode("utf-8"),
                    UPLOAD.deployment_guard_source_from_archive(frozen_path),
                )
                self.assertEqual(
                    frozen_sha256, hashlib.sha256(frozen_path.read_bytes()).hexdigest(),
                )
                self.assertEqual(source.name, frozen_path.name)
                self.assertNotEqual(source.parent, frozen_path.parent)
                self.assertEqual(
                    source.parent, frozen_path.parent.parent,
                    "the full-size freeze copy must stay beside the archive, not /tmp",
                )
            self.assertFalse(frozen_path.exists())

    def test_main_freezes_archive_before_final_approval_and_uploads_snapshot(self):
        args = upload_args(deploy=False)
        args.project = "customer"
        args.dry_run = False
        args.output = Path("/tmp/customer-upload.tar.gz")
        project = Path("/tmp/customer")
        events = []

        @contextmanager
        def frozen(_archive):
            events.append("freeze-enter")
            yield Path("/private/frozen/customer-upload.tar.gz"), "a" * 64
            events.append("freeze-exit")

        def approved():
            events.append("approval-check")

        def uploaded(_args, archive, *, expected_sha256=None):
            events.append(("upload", archive, expected_sha256))
            return "/tmp/customer-upload.tar.gz"

        with mock.patch.object(
            UPLOAD, "parse_args", return_value=args,
        ), mock.patch.object(
            UPLOAD.package_core, "resolve_project", return_value=project,
        ), mock.patch.object(UPLOAD, "resolve_apps_policy"), \
                mock.patch.object(UPLOAD, "run_predeploy_test_gate"), \
                mock.patch.object(
                    UPLOAD.package_core, "create_package", return_value=args.output,
                ), mock.patch.object(
                    UPLOAD, "frozen_archive_for_upload", side_effect=frozen,
                ), mock.patch.object(
                    UPLOAD, "verify_predeploy_test_approval", side_effect=approved,
                ), mock.patch.object(
                    UPLOAD, "deployment_guard_source_from_archive",
                    return_value="# approved guard\n",
                ), mock.patch.object(
                    UPLOAD, "deployment_source_manifest_sha256_from_archive",
                    return_value="b" * 64,
                ), mock.patch.object(UPLOAD, "upload", side_effect=uploaded), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, UPLOAD.main([]))
        self.assertEqual(
            [
                "freeze-enter", "approval-check",
                ("upload", Path("/private/frozen/customer-upload.tar.gz"), "a" * 64),
                "freeze-exit",
            ],
            events,
        )

    def test_upload_rejects_private_snapshot_drift_before_remote_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "customer-upload.tar.gz"
            archive.write_bytes(b"changed")
            args = upload_args(deploy=False)
            with mock.patch.object(UPLOAD, "remote_sha256") as remote, \
                    self.assertRaisesRegex(RuntimeError, "private archive snapshot"):
                UPLOAD.upload(args, archive, expected_sha256="a" * 64)
        remote.assert_not_called()

    @staticmethod
    def _write_archive(path: Path, members) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for member, payload in members:
                if isinstance(member, str):
                    info = tarfile.TarInfo(member)
                    info.size = len(payload)
                else:
                    info = member
                archive.addfile(info, io.BytesIO(payload) if info.isfile() else None)

    @staticmethod
    def _tree_snapshot(root: Path):
        """Capture exact visible tree state without following symlinks."""
        result = {}
        if not root.exists():
            return result
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            mode = stat.S_IMODE(metadata.st_mode)
            if stat.S_ISLNK(metadata.st_mode):
                result[relative] = ("symlink", mode, os.readlink(path))
            elif stat.S_ISDIR(metadata.st_mode):
                result[relative] = ("directory", mode)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative] = ("file", mode, path.read_bytes())
            else:
                result[relative] = ("other", mode)
        return result

    def _transaction_fixture(self, base: Path):
        root = base / "html"
        tools = root / "tools"
        tools.mkdir(parents=True, mode=0o755)
        (tools / "a.py").write_bytes(b"old-a\n")
        (tools / "b.py").write_bytes(b"old-b\n")
        (tools / "stale.py").write_bytes(b"old-stale\n")
        manifest = root / "infra/docker/deployment-source-manifest.json"
        manifest.parent.mkdir(parents=True)
        old_records = [
            {
                "path": f"tools/{name}.py", "type": "file", "target": None,
                "sha256": hashlib.sha256((tools / f"{name}.py").read_bytes()).hexdigest(),
            }
            for name in ("a", "b", "stale")
        ]
        old_manifest = (
            json.dumps({"schema_version": 1, "files": old_records}, sort_keys=True)
            + "\n"
        ).encode("ascii")
        manifest.write_bytes(old_manifest)

        new_payloads = {
            "tools/a.py": b"new-a\n",
            "tools/b.py": b"new-b\n",
            "newdir/new.py": b"brand-new\n",
            "implicit/deep/new.py": b"implicit-parent\n",
        }
        new_records = [
            {
                "path": name, "type": "file", "target": None,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for name, payload in sorted(new_payloads.items())
        ]
        new_records.append({
            "path": "aliases/a.py", "type": "symlink", "target": "../tools/a.py",
            "sha256": hashlib.sha256(new_payloads["tools/a.py"]).hexdigest(),
        })
        new_manifest = (
            json.dumps({"schema_version": 1, "files": new_records}, sort_keys=True)
            + "\n"
        ).encode("ascii")
        archive_path = base / "payload.tar.gz"
        tools_directory = tarfile.TarInfo("tools")
        tools_directory.type = tarfile.DIRTYPE
        tools_directory.mode = 0o700
        new_directory = tarfile.TarInfo("newdir")
        new_directory.type = tarfile.DIRTYPE
        new_directory.mode = 0o750
        alias = tarfile.TarInfo("aliases/a.py")
        alias.type = tarfile.SYMTYPE
        alias.linkname = "../tools/a.py"
        alias.mode = 0o777
        self._write_archive(archive_path, [
            (tools_directory, b""),
            (new_directory, b""),
            (alias, b""),
            *[(name, payload) for name, payload in new_payloads.items()],
            ("infra/docker/deployment-source-manifest.json", new_manifest),
        ])
        return root, archive_path, old_manifest, new_manifest

    def _minimal_overlay_archive(
        self, base: Path, *, extra_members=(), name: str = "minimal.tar.gz",
    ):
        payload = b"verified-source\n"
        manifest = (
            json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/example.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }],
            }, sort_keys=True) + "\n"
        ).encode("ascii")
        archive_path = base / name
        self._write_archive(archive_path, [
            ("tools/example.py", payload),
            ("infra/docker/deployment-source-manifest.json", manifest),
            *extra_members,
        ])
        return archive_path, hashlib.sha256(archive_path.read_bytes()).hexdigest(), manifest

    @staticmethod
    def _filesystem_capacity(
        available_bytes: int, *, fragment_size: int = 4096,
        files: int = 1_000_000, available_inodes: int = 1_000_000,
    ):
        return SimpleNamespace(
            f_bavail=available_bytes // fragment_size,
            f_frsize=fragment_size,
            f_files=files,
            f_favail=available_inodes,
        )

    def _old_manifest_race_fixture(self, base: Path):
        guard = guard_module()
        root = base / "html"
        manifest = root / guard.SOURCE_MANIFEST_NAME
        manifest.parent.mkdir(parents=True)
        state = base / "state"
        state.mkdir()
        record_a = {
            "path": "tools/a.py", "type": "file", "target": None,
            "sha256": hashlib.sha256(b"a\n").hexdigest(),
        }
        record_b = {
            "path": "tools/b-only.py", "type": "file", "target": None,
            "sha256": hashlib.sha256(b"untrusted\n").hexdigest(),
        }
        manifest_a = (
            json.dumps({"schema_version": 1, "files": [record_a]}, sort_keys=True)
            + "\n"
        ).encode("ascii")
        manifest_b = (
            json.dumps(
                {"schema_version": 1, "files": [record_a, record_b]},
                sort_keys=True,
            ) + "\n"
        ).encode("ascii")
        manifest.write_bytes(manifest_a)
        owner = {
            "schema_version": 2,
            "runtime": "docker",
            "http_root": os.fspath(root),
            "source_manifest_sha256": hashlib.sha256(manifest_a).hexdigest(),
        }
        (state / guard.DEPLOYMENT_OWNER_NAME).write_text(
            json.dumps(owner, sort_keys=True) + "\n", encoding="ascii",
        )
        return guard, root, state, manifest, manifest_a, manifest_b

    def test_old_manifest_leaf_replacement_never_mixes_a_digest_with_b_records(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            guard, root, state, manifest, manifest_a, manifest_b = (
                self._old_manifest_race_fixture(base)
            )
            replacement = base / "manifest-b"
            replacement.write_bytes(manifest_b)
            manifest_inode = manifest.stat().st_ino
            original_read = guard.os.read
            replaced = False

            def replace_after_a_was_read(descriptor, count):
                nonlocal replaced
                result = original_read(descriptor, count)
                if (
                    not replaced
                    and not result
                    and os.fstat(descriptor).st_ino == manifest_inode
                ):
                    os.replace(replacement, manifest)
                    replaced = True
                return result

            records = None
            with mock.patch.object(guard.os, "read", side_effect=replace_after_a_was_read):
                try:
                    records = guard.begin_source_update(
                        root, state, hashlib.sha256(b"next").hexdigest(),
                    )
                except guard.GuardError:
                    pass
            self.assertTrue(replaced, "the exact A-to-B replacement was not exercised")
            if records is not None:
                self.assertNotIn("tools/b-only.py", records)
            pending = state / guard.PENDING_SOURCE_UPDATE_NAME
            if pending.exists():
                pending_paths = {
                    record["path"]
                    for record in json.loads(pending.read_text(encoding="ascii"))["files"]
                }
                self.assertNotIn("tools/b-only.py", pending_paths)
            self.assertEqual(hashlib.sha256(manifest_a).hexdigest(), (
                json.loads((state / guard.DEPLOYMENT_OWNER_NAME).read_text(encoding="ascii"))
                ["source_manifest_sha256"]
            ))

    def test_old_manifest_parent_detach_never_mixes_a_digest_with_b_records(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            guard, root, state, manifest, _manifest_a, manifest_b = (
                self._old_manifest_race_fixture(base)
            )
            manifest_inode = manifest.stat().st_ino
            original_read = guard.os.read
            detached = base / "detached-docker"
            replaced = False

            def detach_parent_after_a_was_read(descriptor, count):
                nonlocal replaced
                result = original_read(descriptor, count)
                if (
                    not replaced
                    and not result
                    and os.fstat(descriptor).st_ino == manifest_inode
                ):
                    manifest.parent.rename(detached)
                    manifest.parent.mkdir()
                    manifest.write_bytes(manifest_b)
                    replaced = True
                return result

            records = None
            with mock.patch.object(guard.os, "read", side_effect=detach_parent_after_a_was_read):
                try:
                    records = guard.begin_source_update(
                        root, state, hashlib.sha256(b"next").hexdigest(),
                    )
                except guard.GuardError:
                    pass
            self.assertTrue(replaced, "the manifest-parent detach was not exercised")
            if records is not None:
                self.assertNotIn("tools/b-only.py", records)
            pending = state / guard.PENDING_SOURCE_UPDATE_NAME
            if pending.exists():
                self.assertNotIn(
                    "tools/b-only.py",
                    {record["path"] for record in json.loads(
                        pending.read_text(encoding="ascii"),
                    )["files"]},
                )
            self.assertFalse(hasattr(guard, "_manifest_digest"))
            self.assertFalse(hasattr(guard, "_manifest_records"))

    def test_b_only_record_from_manifest_replacement_can_never_authorize_pruning(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            guard, root, state, manifest, manifest_a, manifest_b = (
                self._old_manifest_race_fixture(base)
            )
            tools = root / "tools"
            tools.mkdir()
            (tools / "a.py").write_bytes(b"a\n")
            b_only = tools / "b-only.py"
            b_only.write_bytes(b"untrusted\n")
            replacement = base / "manifest-b"
            replacement.write_bytes(manifest_b)
            manifest_inode = manifest.stat().st_ino
            original_read = guard.os.read
            replaced = False

            def replace_after_a_was_read(descriptor, count):
                nonlocal replaced
                result = original_read(descriptor, count)
                if (
                    not replaced and not result
                    and os.fstat(descriptor).st_ino == manifest_inode
                ):
                    os.replace(replacement, manifest)
                    replaced = True
                return result

            old_records = None
            with mock.patch.object(guard.os, "read", side_effect=replace_after_a_was_read):
                try:
                    old_records = guard.begin_source_update(
                        root, state, hashlib.sha256(b"next").hexdigest(),
                    )
                except guard.GuardError:
                    pass
            self.assertTrue(replaced)
            if old_records is not None:
                manifest.write_bytes(manifest_a)
                guard._finalize_live_source_update(
                    root, state, old_records, docker_managed=False,
                )
            self.assertEqual(b"untrusted\n", b_only.read_bytes())

    def test_tiny_file_bomb_uses_allocated_blocks_and_namespace_budget(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive_path = base / "tiny-bomb.tar.gz"
            self._write_archive(
                archive_path,
                [(f"tiny/{index:05d}", b"x") for index in range(20_001)],
            )
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            # The old byte-sum gate admitted this exact value: compressed data
            # plus 20,001 logical bytes and 64 MiB.  A 4 KiB filesystem needs
            # over 81 MiB for file blocks alone, before namespace allowance.
            filesystem = self._filesystem_capacity(67_129_344)
            with mock.patch.object(
                guard.os, "fstatvfs", return_value=filesystem,
            ), self.assertRaisesRegex(
                guard.GuardError, "capacity|space|blocks",
            ):
                staging, _members = guard._extract_archive_staging(
                    archive_path, digest,
                )
                shutil.rmtree(staging, ignore_errors=True)

    def test_capacity_formula_counts_rounded_files_and_every_unique_node(self):
        guard = guard_module()
        tiny = SimpleNamespace(size=1)
        block = SimpleNamespace(size=4096)
        empty = SimpleNamespace(size=0)
        directory = SimpleNamespace(size=0)
        symlink = SimpleNamespace(size=0)
        members = [
            (tiny, ("tree", "tiny"), "file"),
            (block, ("tree", "block"), "file"),
            (empty, ("empty",), "file"),
            (directory, ("directory",), "dir"),
            (symlink, ("tree", "alias"), "symlink"),
        ]
        # Unique payload nodes are tree, its three leaves, empty, and directory
        # (6), plus one private staging directory supplied by the caller.
        expected_nodes = 7
        expected_bytes = (
            2 * 4096 + expected_nodes * 16_384 + 64 * 1024 * 1024
        )
        self.assertEqual(
            (expected_bytes, expected_nodes + 4096),
            guard._deployment_capacity_budget(
                members, 4096, extra_nodes=1,
            ),
        )

    def test_zero_size_nodes_still_consume_inode_and_namespace_budget(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive_path = base / "zero-nodes.tar.gz"
            directory_member = tarfile.TarInfo("tree")
            directory_member.type = tarfile.DIRTYPE
            directory_member.mode = 0o755
            empty_file = tarfile.TarInfo("tree/empty")
            empty_file.size = 0
            alias = tarfile.TarInfo("tree/alias")
            alias.type = tarfile.SYMTYPE
            alias.linkname = "empty"
            self._write_archive(archive_path, [
                (directory_member, b""), (empty_file, b""), (alias, b""),
            ])
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            # 3 payload nodes + 1 private staging directory + 4096 reserve.
            filesystem = self._filesystem_capacity(
                256 * 1024 * 1024, files=1_000_000, available_inodes=4099,
            )
            with mock.patch.object(
                guard.os, "fstatvfs", return_value=filesystem,
            ), self.assertRaisesRegex(guard.GuardError, "inode"):
                staging, _members = guard._extract_archive_staging(
                    archive_path, digest,
                )
                shutil.rmtree(staging, ignore_errors=True)

    def test_unreported_zero_zero_inode_accounting_skips_only_inode_gate(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive_path = base / "dynamic-inodes.tar.gz"
            self._write_archive(archive_path, [("tree/empty", b"")])
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            filesystem = self._filesystem_capacity(
                256 * 1024 * 1024, files=0, available_inodes=0,
            )
            output = io.StringIO()
            with mock.patch.object(
                guard.os, "fstatvfs", return_value=filesystem,
            ), redirect_stdout(output):
                staging, _members = guard._extract_archive_staging(
                    archive_path, digest,
                )
            shutil.rmtree(staging)
            self.assertRegex(output.getvalue(), "inode.*(unreported|skip)")

    def test_inherited_archive_fd_is_revalidated_after_complete_extraction(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            archive_path, digest, _manifest = self._minimal_overlay_archive(base)
            descriptor = os.open(archive_path, os.O_RDWR)
            original_write_all = guard._write_all
            mutated = False

            def mutate_fd_after_final_member_copy(output_fd, payload, label):
                nonlocal mutated
                result = original_write_all(output_fd, payload, label)
                if "deployment-source-manifest.json" in label and not mutated:
                    os.pwrite(descriptor, b"X", 0)
                    mutated = True
                return result

            try:
                with mock.patch.object(
                    guard.tempfile, "gettempdir", return_value=os.fspath(staging_parent),
                ), mock.patch.object(
                    guard, "_write_all", side_effect=mutate_fd_after_final_member_copy,
                ), self.assertRaisesRegex(
                    guard.GuardError, "archive.*(changed|identity|digest)",
                ):
                    guard._extract_archive_staging_descriptor(descriptor, digest)
            finally:
                os.close(descriptor)
            self.assertTrue(mutated)
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_archive_cli_path_and_inherited_fd_are_mutually_exclusive(self):
        guard = guard_module()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
            guard.parser().parse_args([
                "--lock", "/tmp/.deployment.lock",
                "--root", "/tmp/http-root",
                "--archive", "/tmp/upload.tar.gz",
                "--archive-fd", "9",
            ])
        self.assertEqual(2, stopped.exception.code)

    def test_staging_success_but_live_capacity_failure_precedes_live_effects(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            root.mkdir()
            archive_path, digest, _manifest = self._minimal_overlay_archive(base)
            before = self._tree_snapshot(root)
            capacities = [
                self._filesystem_capacity(512 * 1024 * 1024),
                self._filesystem_capacity(1024),
            ]
            self.assertEqual(
                root.stat().st_dev,
                Path(tempfile.gettempdir()).resolve(strict=True).stat().st_dev,
                "this counterexample must exercise the same-filesystem peak",
            )
            with mock.patch.object(
                guard.os, "fstatvfs", side_effect=capacities,
            ) as capacity_check, mock.patch.object(
                guard, "quiesce_for_source_update",
            ) as quiesce, mock.patch.object(
                guard, "_write_sync_marker",
            ) as marker, self.assertRaisesRegex(
                guard.GuardError, "live.*(capacity|space|blocks)",
            ):
                guard.apply_archive_overlay(
                    root, archive_path, digest,
                    lock_path=root / ".deployment.lock",
                )
            quiesce.assert_not_called()
            marker.assert_not_called()
            self.assertEqual(2, capacity_check.call_count)
            self.assertEqual(before, self._tree_snapshot(root))

    def test_live_capacity_rejection_precedes_root_lock_quiesce_and_marker(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "missing" / "html"
            archive_path, digest, manifest = self._minimal_overlay_archive(base)
            capacities = [
                self._filesystem_capacity(512 * 1024 * 1024),
                self._filesystem_capacity(1024),
            ]
            events = []

            def record(label):
                def call(*_args, **_kwargs):
                    events.append(label)
                return call

            with mock.patch.object(
                guard.os, "fstatvfs", side_effect=capacities,
            ), mock.patch.object(
                guard, "ensure_deployment_root", side_effect=record("ensure-root"),
            ), mock.patch.object(
                guard, "safe_lock", side_effect=record("lock"),
            ), mock.patch.object(
                guard, "quiesce_for_source_update", side_effect=record("quiesce"),
            ), mock.patch.object(
                guard, "_write_sync_marker", side_effect=record("marker"),
            ), mock.patch.object(
                guard, "_apply_prepared_archive_overlay", side_effect=record("apply"),
            ), self.assertRaisesRegex(
                guard.GuardError, "live-root.*(capacity|blocks)",
            ):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, archive_path, digest,
                    hashlib.sha256(manifest).hexdigest(),
                )
            self.assertEqual([], events)
            self.assertFalse(root.exists())

    def test_first_install_device_change_rechecks_capacity_on_held_root_fd(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            measured = base / "measured-parent"
            root = base / "new-root"
            measured.mkdir()
            root.mkdir()
            archive_path, _digest, _manifest = self._minimal_overlay_archive(base)
            with tarfile.open(archive_path, "r:gz") as archive:
                members = guard._validated_archive_members(archive)
            measured_fd, measured_identity = guard._open_held_directory(
                measured, "test measured parent",
            )
            root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            root_status = os.fstat(root_fd)
            authority = (measured, measured_fd, measured_identity, 1)
            fake_root_status = SimpleNamespace(st_dev=measured_identity[0] + 1)
            original_fstat = guard.os.fstat

            def device_change(descriptor):
                if descriptor == root_fd:
                    return fake_root_status
                return original_fstat(descriptor)

            def open_root(path, label):
                self.assertEqual(root, path)
                self.assertEqual("deployment root", label)
                return root_fd, (root_status.st_dev, root_status.st_ino)

            exhausted = self._filesystem_capacity(1024)
            try:
                with mock.patch.object(
                    guard, "_open_held_directory", side_effect=open_root,
                ), mock.patch.object(
                    guard.os, "fstat", side_effect=device_change,
                ), mock.patch.object(
                    guard.os, "fstatvfs", return_value=exhausted,
                ) as capacity_check, self.assertRaisesRegex(
                    guard.GuardError, "device recheck.*(capacity|blocks)",
                ):
                    guard._recheck_live_capacity_after_root_creation(
                        root, authority, members,
                    )
                capacity_check.assert_called_once_with(root_fd)
            finally:
                # The helper owns and closes root_fd.  The authority remains
                # caller-owned until the outer transaction finishes.
                os.close(measured_fd)

    def test_root_bootstrap_allocation_failure_rolls_back_only_new_components(self):
        guard = guard_module()
        for error_number in (errno.ENOSPC, errno.EDQUOT):
            with self.subTest(error_number=error_number), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                existing = base / "existing"
                existing.mkdir()
                root = existing / "first" / "html"
                staging_parent = base / "staging"
                staging_parent.mkdir()
                archive_path, digest, manifest = self._minimal_overlay_archive(base)
                original_mkdir = guard.os.mkdir

                def fail_root_leaf(path, mode=0o777, *args, **kwargs):
                    candidate = os.fspath(path)
                    if candidate in {"html", os.fspath(root)}:
                        raise OSError(error_number, "injected root allocation failure")
                    return original_mkdir(path, mode, *args, **kwargs)

                with mock.patch.object(
                    guard.tempfile, "gettempdir",
                    return_value=os.fspath(staging_parent),
                ), mock.patch.object(
                    guard.os, "mkdir", side_effect=fail_root_leaf,
                ), self.assertRaisesRegex(
                    guard.GuardError, "deployment root component|allocation",
                ):
                    guard.run_locked_archive(
                        root / ".deployment.lock", root, archive_path, digest,
                        hashlib.sha256(manifest).hexdigest(),
                    )
                self.assertTrue(existing.is_dir())
                self.assertFalse((existing / "first").exists())
                self.assertEqual([], list(staging_parent.iterdir()))

    def test_root_bootstrap_device_recheck_failure_rolls_back_new_components(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            existing = base / "existing"
            existing.mkdir()
            root = existing / "first" / "html"
            staging_parent = base / "staging"
            staging_parent.mkdir()
            archive_path, digest, manifest = self._minimal_overlay_archive(base)

            with mock.patch.object(
                guard.tempfile, "gettempdir",
                return_value=os.fspath(staging_parent),
            ), mock.patch.object(
                guard, "_recheck_live_capacity_after_root_creation",
                side_effect=guard.GuardError(
                    "deployment live-root device recheck has insufficient capacity",
                ),
            ) as recheck, mock.patch.object(
                guard, "safe_lock",
            ) as lock, self.assertRaisesRegex(
                guard.GuardError, "device recheck.*capacity",
            ):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, archive_path, digest,
                    hashlib.sha256(manifest).hexdigest(),
                )
            recheck.assert_called_once()
            lock.assert_not_called()
            self.assertTrue(existing.is_dir())
            self.assertFalse((existing / "first").exists())
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_allocation_failures_clean_staging_or_rollback_live_tree(self):
        guard = guard_module()
        for error_number in (errno.ENOSPC, errno.EDQUOT):
            with self.subTest(error_number=error_number), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root = base / "html"
                root.mkdir()
                staging_parent = base / "staging"
                staging_parent.mkdir()
                archive_path, digest, _manifest = self._minimal_overlay_archive(base)
                before = self._tree_snapshot(root)

                with mock.patch.object(
                    guard.tempfile, "gettempdir", return_value=os.fspath(staging_parent),
                ), mock.patch.object(
                    guard.os, "write",
                    side_effect=OSError(error_number, "injected staging allocation failure"),
                ), self.assertRaisesRegex(guard.GuardError, "stage|archive|write"):
                    guard.apply_archive_overlay(
                        root, archive_path, digest,
                        lock_path=root / ".deployment.lock",
                    )
                self.assertEqual([], list(staging_parent.iterdir()))
                self.assertEqual(before, self._tree_snapshot(root))

                live_writes = 0
                original_write_all = guard._write_all

                def fail_second_live_copy(descriptor, payload, label):
                    nonlocal live_writes
                    if label == "deployment archive member":
                        live_writes += 1
                        if live_writes == 2:
                            raise OSError(error_number, "injected live allocation failure")
                    return original_write_all(descriptor, payload, label)

                with mock.patch.object(
                    guard, "_write_all", side_effect=fail_second_live_copy,
                ), self.assertRaisesRegex(guard.GuardError, "promote|allocation|overlay"):
                    guard.apply_archive_overlay(
                        root, archive_path, digest,
                        lock_path=root / ".deployment.lock",
                    )
                self.assertEqual(2, live_writes)
                self.assertEqual(before, self._tree_snapshot(root))

    def test_reserved_custom_lock_rejects_before_every_side_effect_boundary(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "missing-live"
            cases = (
                ".custom.lock", ".custom.lock/child", ".deployment.lock",
                ".payload.http-ztp-new-0123456789abcdef01234567",
                "nested/../.custom.lock",
            )
            for index, reserved in enumerate(cases):
                with self.subTest(reserved=reserved):
                    archive_path, digest, manifest = self._minimal_overlay_archive(
                        base,
                        name=f"reserved-order-{index}.tar.gz",
                        extra_members=((reserved, b"attacker\n"),),
                    )
                    events = []

                    def recorded(label, result=None):
                        def call(*_args, **_kwargs):
                            events.append(label)
                            return result
                        return call

                    with mock.patch.object(
                        guard.tempfile, "mkdtemp", side_effect=recorded("mkdtemp"),
                    ), mock.patch.object(
                        guard, "ensure_deployment_root", side_effect=recorded("ensure"),
                    ), mock.patch.object(
                        guard, "safe_lock", side_effect=recorded("lock"),
                    ), mock.patch.object(
                        guard, "quiesce_for_source_update", side_effect=recorded("quiesce"),
                    ), mock.patch.object(
                        guard, "_write_sync_marker", side_effect=recorded("marker"),
                    ), mock.patch.object(
                        guard, "_apply_prepared_archive_overlay", side_effect=recorded("apply"),
                    ), self.assertRaisesRegex(
                        guard.GuardError, "reserved|control|traversal",
                    ):
                        guard.run_locked_archive(
                            root / ".custom.lock", root, archive_path, digest,
                            hashlib.sha256(manifest).hexdigest(),
                        )
                    self.assertEqual([], events)
                    events.clear()
                    with mock.patch.object(
                        guard.tempfile, "mkdtemp", side_effect=recorded("mkdtemp"),
                    ), mock.patch.object(
                        guard, "ensure_deployment_root", side_effect=recorded("ensure"),
                    ), mock.patch.object(
                        guard, "safe_lock", side_effect=recorded("lock"),
                    ), mock.patch.object(
                        guard, "quiesce_for_source_update", side_effect=recorded("quiesce"),
                    ), mock.patch.object(
                        guard, "_write_sync_marker", side_effect=recorded("marker"),
                    ), mock.patch.object(
                        guard, "_apply_prepared_archive_overlay", side_effect=recorded("apply"),
                    ), self.assertRaisesRegex(
                        guard.GuardError, "reserved|control|traversal",
                    ):
                        guard.apply_archive_overlay(
                            root, archive_path, digest,
                            lock_path=root / ".custom.lock",
                        )
                    self.assertEqual([], events)

    def test_raw_archive_traversal_rejects_before_every_side_effect_boundary(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "missing-live"
            archive_path, digest, manifest = self._minimal_overlay_archive(
                base,
                name="raw-traversal.tar.gz",
                extra_members=(("safe/../ordinary.txt", b"attacker\n"),),
            )
            events = []

            def recorded(label):
                def call(*_args, **_kwargs):
                    events.append(label)
                return call

            with mock.patch.object(
                guard.tempfile, "mkdtemp", side_effect=recorded("mkdtemp"),
            ), mock.patch.object(
                guard, "ensure_deployment_root", side_effect=recorded("ensure"),
            ), mock.patch.object(
                guard, "safe_lock", side_effect=recorded("lock"),
            ), mock.patch.object(
                guard, "quiesce_for_source_update", side_effect=recorded("quiesce"),
            ), mock.patch.object(
                guard, "_write_sync_marker", side_effect=recorded("marker"),
            ), mock.patch.object(
                guard, "_apply_prepared_archive_overlay", side_effect=recorded("apply"),
            ), self.assertRaisesRegex(guard.GuardError, "traversal|\.\."):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, archive_path, digest,
                    hashlib.sha256(manifest).hexdigest(),
                )
            self.assertEqual([], events)
            self.assertFalse(root.exists())

    def test_python_overlay_api_requires_explicit_lock_authority(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive_path, digest, _manifest = self._minimal_overlay_archive(base)
            root = base / "html"
            root.mkdir()
            with self.assertRaises(TypeError):
                guard.apply_archive_overlay(root, archive_path, digest)
            self.assertEqual([], list(root.iterdir()))

    def test_archive_control_paths_are_rejected_before_root_quiesce_or_marker(self):
        guard = guard_module()
        reserved = (
            ".deployment.lock",
            ".deployment.lock/child",
            ".sync-code-in-progress",
            ".source.py.http-ztp-old-0123456789abcdef01234567",
            ".custom-deployment.lock",
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            for index, reserved_name in enumerate(reserved):
                with self.subTest(reserved_name=reserved_name):
                    root = base / f"live-{index}"
                    archive_path = base / f"reserved-{index}.tar.gz"
                    payload = b"new\n"
                    manifest = json.dumps({
                        "schema_version": 1,
                        "files": [{
                            "path": "tools/new.py", "type": "file", "target": None,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }],
                    }).encode("ascii")
                    self._write_archive(archive_path, [
                        ("tools/new.py", payload),
                        ("infra/docker/deployment-source-manifest.json", manifest),
                        (reserved_name, b"attacker-controlled\n"),
                    ])
                    lock_name = (
                        reserved_name if reserved_name == ".custom-deployment.lock"
                        else ".deployment.lock"
                    )
                    with mock.patch.object(
                        guard, "quiesce_for_source_update", return_value=False,
                    ) as quiesce, mock.patch.object(
                        guard, "_write_sync_marker",
                    ) as marker, self.assertRaisesRegex(
                        guard.GuardError, "reserved|control",
                    ):
                        guard.run_locked_archive(
                            root / lock_name, root, archive_path,
                            hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                            hashlib.sha256(manifest).hexdigest(),
                        )
                    quiesce.assert_not_called()
                    marker.assert_not_called()
                    self.assertFalse(root.exists())

    def test_overlay_rolls_back_every_member_directory_mode_and_stale_prune(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            before = self._tree_snapshot(root)
            original_replace = guard.os.replace

            def fail_manifest_promotion(source, destination, *args, **kwargs):
                if (
                    os.fspath(destination) == "deployment-source-manifest.json"
                    and ".deployment-source-manifest.json.http-ztp-new-"
                    in os.fspath(source)
                ):
                    raise OSError(5, "injected final-manifest promotion failure")
                return original_replace(source, destination, *args, **kwargs)

            with mock.patch.object(
                guard.os, "replace", side_effect=fail_manifest_promotion,
            ), self.assertRaisesRegex(
                guard.GuardError, "final-manifest|promote",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertEqual(before, self._tree_snapshot(root))

    def test_overlay_rolls_back_a_parent_created_before_its_open_fails(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            before = self._tree_snapshot(root)
            root_identity = root.stat().st_ino
            original_open = guard.os.open
            failed = False

            def fail_created_parent_open(path, flags, *args, **kwargs):
                nonlocal failed
                directory_fd = kwargs.get("dir_fd")
                if (
                    not failed
                    and os.fspath(path) == "implicit"
                    and directory_fd is not None
                    and os.fstat(directory_fd).st_ino == root_identity
                    and (root / "implicit").is_dir()
                ):
                    failed = True
                    raise OSError(5, "injected created-parent open failure")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                guard.os, "open", side_effect=fail_created_parent_open,
            ), self.assertRaisesRegex(
                guard.GuardError, "created-parent|parent|promote",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertTrue(failed)
            self.assertEqual(before, self._tree_snapshot(root))

    def test_overlay_rolls_back_an_explicit_directory_when_open_fails(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            before = self._tree_snapshot(root)
            root_identity = root.stat().st_ino
            original_open = guard.os.open
            failed = False

            def fail_created_directory_open(path, flags, *args, **kwargs):
                nonlocal failed
                directory_fd = kwargs.get("dir_fd")
                if (
                    not failed
                    and os.fspath(path) == "newdir"
                    and directory_fd is not None
                    and os.fstat(directory_fd).st_ino == root_identity
                    and (root / "newdir").is_dir()
                ):
                    failed = True
                    raise OSError(5, "injected explicit-directory open failure")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                guard.os, "open", side_effect=fail_created_directory_open,
            ), self.assertRaisesRegex(
                guard.GuardError, "explicit-directory|directory|promote",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertTrue(failed)
            self.assertEqual(before, self._tree_snapshot(root))

    def test_overlay_rolls_back_a_parent_when_identity_stat_fails_after_mkdir(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            before = self._tree_snapshot(root)
            root_identity = root.stat().st_ino
            original_stat = guard.os.stat
            failed = False

            def fail_created_parent_stat(path, *args, **kwargs):
                nonlocal failed
                directory_fd = kwargs.get("dir_fd")
                if (
                    not failed
                    and os.fspath(path) == "implicit"
                    and directory_fd is not None
                    and os.fstat(directory_fd).st_ino == root_identity
                ):
                    current = original_stat(path, *args, **kwargs)
                    if stat.S_ISDIR(current.st_mode):
                        failed = True
                        raise OSError(5, "injected created-parent identity stat failure")
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(
                guard.os, "stat", side_effect=fail_created_parent_stat,
            ), self.assertRaisesRegex(
                guard.GuardError, "identity stat|parent|promote",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertTrue(failed)
            self.assertEqual(before, self._tree_snapshot(root))

    def test_overlay_rolls_back_an_explicit_directory_when_identity_stat_fails(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            before = self._tree_snapshot(root)
            root_identity = root.stat().st_ino
            original_stat = guard.os.stat
            failed = False

            def fail_created_directory_stat(path, *args, **kwargs):
                nonlocal failed
                directory_fd = kwargs.get("dir_fd")
                if (
                    not failed
                    and os.fspath(path) == "newdir"
                    and directory_fd is not None
                    and os.fstat(directory_fd).st_ino == root_identity
                ):
                    current = original_stat(path, *args, **kwargs)
                    if stat.S_ISDIR(current.st_mode):
                        failed = True
                        raise OSError(5, "injected explicit-directory identity stat failure")
                return original_stat(path, *args, **kwargs)

            with mock.patch.object(
                guard.os, "stat", side_effect=fail_created_directory_stat,
            ), self.assertRaisesRegex(
                guard.GuardError, "identity stat|directory|promote",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertTrue(failed)
            self.assertEqual(before, self._tree_snapshot(root))

    def test_overlay_directory_name_swap_reports_incomplete_rollback(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            tools = root / "tools"
            displaced = base / "tools.displaced"
            outside = base / "outside"
            outside.mkdir()
            (outside / "sentinel").write_bytes(b"outside\n")
            original_promote = guard._promote_staged_member
            swapped = False

            def swap_existing_directory_after_mode_change(*args, **kwargs):
                nonlocal swapped
                result = original_promote(*args, **kwargs)
                item = args[6]
                if not swapped and item[1] == ("tools",) and item[2] == "dir":
                    tools.rename(displaced)
                    tools.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return result

            try:
                with mock.patch.object(
                    guard, "_promote_staged_member",
                    side_effect=swap_existing_directory_after_mode_change,
                ), self.assertRaisesRegex(
                    guard.GuardError, "roll back|rollback|directory.*changed",
                ):
                    guard.apply_archive_overlay(
                        root, archive_path,
                        hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                        lock_path=root / ".deployment.lock",
                        trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                    )
                self.assertTrue(swapped)
                self.assertEqual(b"outside\n", (outside / "sentinel").read_bytes())
            finally:
                if tools.is_symlink():
                    tools.unlink()
                if displaced.exists():
                    displaced.rename(tools)

    def test_overlay_parent_fsync_failure_restores_old_file_instead_of_losing_both(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root, archive_path, old_manifest, _new_manifest = self._transaction_fixture(base)
            before = self._tree_snapshot(root)
            tools_identity = (root / "tools").stat().st_ino
            original_fsync = guard.os.fsync
            failed = False

            def fail_first_tools_directory_fsync(descriptor):
                nonlocal failed
                metadata = os.fstat(descriptor)
                if (
                    not failed
                    and stat.S_ISDIR(metadata.st_mode)
                    and metadata.st_ino == tools_identity
                ):
                    failed = True
                    raise OSError(5, "injected promotion directory fsync failure")
                return original_fsync(descriptor)

            with mock.patch.object(
                guard.os, "fsync", side_effect=fail_first_tools_directory_fsync,
            ), self.assertRaisesRegex(
                guard.GuardError, "fsync|promote|publication",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertTrue(failed)
            self.assertEqual(before, self._tree_snapshot(root))

    def test_committed_overlay_cleanup_fsync_failure_keeps_complete_new_tree(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            target = tools / "only.py"
            target.write_bytes(b"old\n")
            old_record = {
                "path": "tools/only.py", "type": "file", "target": None,
                "sha256": hashlib.sha256(b"old\n").hexdigest(),
            }
            manifest_path = root / "infra/docker/deployment-source-manifest.json"
            manifest_path.parent.mkdir(parents=True)
            old_manifest = (
                json.dumps({"schema_version": 1, "files": [old_record]}, sort_keys=True)
                + "\n"
            ).encode("ascii")
            manifest_path.write_bytes(old_manifest)
            new_record = {
                "path": "tools/only.py", "type": "file", "target": None,
                "sha256": hashlib.sha256(b"new\n").hexdigest(),
            }
            new_manifest = (
                json.dumps({"schema_version": 1, "files": [new_record]}, sort_keys=True)
                + "\n"
            ).encode("ascii")
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/only.py", b"new\n"),
                ("infra/docker/deployment-source-manifest.json", new_manifest),
            ])
            tools_identity = (root / "tools").stat().st_ino
            original_fsync = guard.os.fsync
            tools_syncs = 0

            def fail_tools_cleanup_fsync(descriptor):
                nonlocal tools_syncs
                metadata = os.fstat(descriptor)
                if stat.S_ISDIR(metadata.st_mode) and metadata.st_ino == tools_identity:
                    tools_syncs += 1
                    if tools_syncs == 2:
                        raise OSError(5, "injected committed cleanup fsync failure")
                return original_fsync(descriptor)

            with mock.patch.object(
                guard.os, "fsync", side_effect=fail_tools_cleanup_fsync,
            ), self.assertRaisesRegex(
                guard.GuardError, "committed.*cleanup|cleanup.*committed",
            ):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256=hashlib.sha256(old_manifest).hexdigest(),
                )
            self.assertEqual(b"new\n", target.read_bytes())
            self.assertEqual(
                new_manifest, manifest_path.read_bytes(),
            )

    def test_finalize_parent_swap_after_verification_never_unlinks_outside_root(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            displaced = base / "tools.displaced"
            outside = base / "outside"
            outside.mkdir()
            old_payload = b"receipt-bound-old\n"
            (tools / "old.py").write_bytes(old_payload)
            (outside / "old.py").write_bytes(old_payload)
            new_payload = b"new\n"
            (tools / "new.py").write_bytes(new_payload)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            swapped = False

            def swap_parent_after_verification():
                nonlocal swapped
                if not swapped:
                    tools.rename(displaced)
                    tools.symlink_to(outside, target_is_directory=True)
                    swapped = True

            try:
                with mock.patch.object(
                    guard, "_TEST_AFTER_STALE_VERIFY",
                    side_effect=swap_parent_after_verification,
                ), self.assertRaisesRegex(
                    guard.GuardError, "parent|directory|identity|symlink",
                ):
                    guard._finalize_live_source_update(
                        root, base / "state", old_records, docker_managed=False,
                    )
                self.assertTrue(swapped)
                self.assertEqual(old_payload, (outside / "old.py").read_bytes())
                self.assertEqual(old_payload, (displaced / "old.py").read_bytes())
            finally:
                if tools.is_symlink():
                    tools.unlink()
                if displaced.exists():
                    displaced.rename(tools)

    def test_finalize_manifest_swap_rolls_back_stale_prune_before_receipt(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            old_payload = b"old\n"
            new_payload = b"new\n"
            old = tools / "old.py"
            new = tools / "new.py"
            old.write_bytes(old_payload)
            new.write_bytes(new_payload)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            displaced_manifest = base / "verified-manifest"
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            original_verify = guard._verify_manifest_tree_held
            swapped = False

            def swap_manifest_after_tree_verification(*args, **kwargs):
                nonlocal swapped
                result = original_verify(*args, **kwargs)
                manifest.rename(displaced_manifest)
                manifest.write_bytes(b"attacker replacement\n")
                swapped = True
                return result

            with mock.patch.object(
                guard, "_verify_manifest_tree_held",
                side_effect=swap_manifest_after_tree_verification,
            ), mock.patch.object(
                guard, "write_deployment_owner",
            ) as receipt, self.assertRaisesRegex(
                guard.GuardError, "manifest authority",
            ):
                guard._finalize_live_source_update(
                    root, base / "state", old_records, docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertTrue(swapped)
            self.assertEqual(old_payload, old.read_bytes())
            receipt.assert_not_called()

    def test_finalize_rejects_a_manifest_parent_detached_from_held_root(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            old_payload = b"old\n"
            new_payload = b"new\n"
            old = tools / "old.py"
            new = tools / "new.py"
            old.write_bytes(old_payload)
            new.write_bytes(new_payload)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            detached = base / "docker.detached"
            swapped = False

            def detach_manifest_parent():
                nonlocal swapped
                if not swapped:
                    manifest.parent.rename(detached)
                    manifest.parent.mkdir()
                    manifest.write_text(
                        json.dumps({"schema_version": 1, "files": []}) + "\n",
                        encoding="ascii",
                    )
                    swapped = True

            with mock.patch.object(
                guard, "_TEST_AFTER_STALE_VERIFY",
                side_effect=detach_manifest_parent,
            ), mock.patch.object(
                guard, "write_deployment_owner",
            ) as receipt, self.assertRaisesRegex(
                guard.GuardError, "manifest.*parent|parent.*identity|directory.*changed",
            ):
                guard._finalize_live_source_update(
                    root, base / "state", old_records, docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertTrue(swapped)
            self.assertEqual(old_payload, old.read_bytes())
            receipt.assert_not_called()

    def test_finalize_restores_a_stale_replacement_moved_by_late_rename_race(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            old_payload = b"receipt-bound-old\n"
            replacement_payload = b"concurrent-replacement\n"
            old = tools / "old.py"
            new = tools / "new.py"
            old.write_bytes(old_payload)
            new.write_bytes(b"new\n")
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(b"new\n").hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            original_replace = guard.os.replace
            raced = False

            def replace_stale_after_identity_check(source, destination, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and os.fspath(source) == "old.py"
                    and ".old.py.http-ztp-stale-" in os.fspath(destination)
                ):
                    old.unlink()
                    old.write_bytes(replacement_payload)
                    raced = True
                return original_replace(source, destination, *args, **kwargs)

            with mock.patch.object(
                guard.os, "replace", side_effect=replace_stale_after_identity_check,
            ), mock.patch.object(
                guard, "write_deployment_owner",
            ) as receipt, self.assertRaisesRegex(
                guard.GuardError, "stale.*changed|rollback|roll back|identity",
            ):
                guard._finalize_live_source_update(
                    root, base / "state", old_records, docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertTrue(raced)
            self.assertEqual(replacement_payload, old.read_bytes())
            self.assertFalse(any(
                ".old.py.http-ztp-stale-" in path.name
                for path in tools.iterdir()
            ))
            receipt.assert_not_called()

    def test_finalize_rejects_in_place_manifest_mutation_before_receipt(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            old_payload = b"old\n"
            new_payload = b"new\n"
            old = tools / "old.py"
            new = tools / "new.py"
            old.write_bytes(old_payload)
            new.write_bytes(new_payload)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            mutated = False

            def mutate_manifest_in_place():
                nonlocal mutated
                if not mutated:
                    with manifest.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(b"{\"attacker\":true}\n")
                        stream.truncate()
                    mutated = True

            with mock.patch.object(
                guard, "_TEST_AFTER_STALE_VERIFY",
                side_effect=mutate_manifest_in_place,
            ), mock.patch.object(
                guard, "write_deployment_owner",
            ) as receipt, self.assertRaisesRegex(
                guard.GuardError, "manifest authority|manifest.*changed",
            ):
                guard._finalize_live_source_update(
                    root, base / "state", old_records, docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertTrue(mutated)
            self.assertEqual(old_payload, old.read_bytes())
            receipt.assert_not_called()

    def test_finalize_reverifies_manifest_content_after_stale_prune(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            old_payload = b"old\n"
            new_payload = b"new\n"
            old = tools / "old.py"
            new = tools / "new.py"
            old.write_bytes(old_payload)
            new.write_bytes(new_payload)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            mutated = False

            def mutate_verified_new_content():
                nonlocal mutated
                if not mutated:
                    new.write_bytes(b"MUTATED\n")
                    mutated = True

            with mock.patch.object(
                guard, "_TEST_AFTER_STALE_VERIFY",
                side_effect=mutate_verified_new_content,
            ), mock.patch.object(
                guard, "write_deployment_owner",
            ) as receipt, self.assertRaisesRegex(
                guard.GuardError, "manifest member hash|changed",
            ):
                guard._finalize_live_source_update(
                    root, base / "state", old_records, docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertTrue(mutated)
            self.assertEqual(old_payload, old.read_bytes())
            receipt.assert_not_called()

    def test_finalize_reverifies_manifest_content_after_transaction_commit(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            tools = root / "tools"
            tools.mkdir(parents=True)
            old_payload = b"old\n"
            new_payload = b"new\n"
            old = tools / "old.py"
            new = tools / "new.py"
            old.write_bytes(old_payload)
            new.write_bytes(new_payload)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_records = {
                "tools/old.py": {
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old_payload).hexdigest(),
                },
            }
            original_commit = guard._OverlayTransaction.commit
            mutated = False

            def commit_then_mutate(transaction):
                nonlocal mutated
                result = original_commit(transaction)
                new.write_bytes(b"MUTATED\n")
                mutated = True
                return result

            with mock.patch.object(
                guard._OverlayTransaction, "commit", commit_then_mutate,
            ), mock.patch.object(
                guard, "write_deployment_owner",
            ) as receipt, self.assertRaisesRegex(
                guard.GuardError, "manifest member hash|changed",
            ):
                guard._finalize_live_source_update(
                    root, base / "state", old_records, docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertTrue(mutated)
            receipt.assert_not_called()

    def test_safe_overlay_rejects_live_parent_symlink_before_any_write(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "sentinel").write_text("unchanged\n", encoding="utf-8")
            (root / "tools").symlink_to(outside)
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/new.py", b"print('new')\n"),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1,
                    "files": [{
                        "path": "tools/new.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(b"print('new')\n").hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(guard.GuardError, "ancestor.*symlink|directory"):
                guard.apply_archive_overlay(
                    root, archive_path, digest,
                    lock_path=root / ".deployment.lock",
                )
            self.assertEqual(
                "unchanged\n", (outside / "sentinel").read_text(encoding="utf-8"),
            )
            self.assertFalse((outside / "new.py").exists())

    def test_safe_overlay_root_swap_at_publish_is_contained_and_rolled_back(self):
        guard = guard_module()
        payload = b"verified-source\n"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/example.py", payload),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1,
                    "files": [{
                        "path": "tools/example.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            root = base / "html"
            root.mkdir()
            displaced = base / "html.displaced"
            attacker = base / "attacker"
            (attacker / "tools").mkdir(parents=True)
            (attacker / "infra" / "docker").mkdir(parents=True)
            real_mkstemp = guard.tempfile.mkstemp
            real_replace = guard.os.replace
            swapped = False

            def swap_root_once():
                nonlocal swapped
                if not swapped:
                    root.rename(displaced)
                    root.symlink_to(attacker, target_is_directory=True)
                    swapped = True

            def swap_root_then_mkstemp(*args, **kwargs):
                swap_root_once()
                return real_mkstemp(*args, **kwargs)

            def swap_root_then_replace(*args, **kwargs):
                swap_root_once()
                return real_replace(*args, **kwargs)

            try:
                with mock.patch.object(
                    guard.tempfile, "mkstemp", side_effect=swap_root_then_mkstemp,
                ), mock.patch.object(
                    guard.os, "replace", side_effect=swap_root_then_replace,
                ):
                    with self.assertRaisesRegex(
                        guard.GuardError, "root.*(changed|identity)",
                    ):
                        guard.apply_archive_overlay(
                            root, archive_path, digest,
                            lock_path=root / ".deployment.lock",
                        )
            finally:
                if root.is_symlink():
                    root.unlink()
                if displaced.exists():
                    displaced.rename(root)

            self.assertTrue(swapped)
            self.assertEqual(
                [],
                [
                    path.relative_to(attacker).as_posix()
                    for path in attacker.rglob("*")
                    if path.is_file() or path.is_symlink()
                ],
            )
            self.assertFalse((root / "tools" / "example.py").exists())
            self.assertFalse(
                (root / "infra" / "docker" / "deployment-source-manifest.json").exists()
            )

    def test_safe_overlay_rejects_expanded_capacity_before_live_write(self):
        guard = guard_module()
        payload = b"verified-source\n"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/example.py", payload),
                ("DAY0-Prepare/customer/highly-compressible.bin", b"0" * (2 * 1024 * 1024)),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1,
                    "files": [{
                        "path": "tools/example.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            root = base / "html"
            root.mkdir()
            staging_parent = base / "staging"
            staging_parent.mkdir()
            available = 65 * 1024 * 1024
            filesystem = SimpleNamespace(
                f_bavail=available, f_frsize=1,
                f_files=1_000_000, f_favail=1_000_000,
            )
            real_mkdtemp = tempfile.mkdtemp

            def private_stage(*, prefix):
                return real_mkdtemp(prefix=prefix, dir=staging_parent)

            with mock.patch.object(
                guard.tempfile, "mkdtemp", side_effect=private_stage,
            ), mock.patch.object(
                guard.os, "fstatvfs", return_value=filesystem,
            ), self.assertRaisesRegex(
                guard.GuardError, "expanded.*(space|capacity)",
            ):
                guard.apply_archive_overlay(
                    root, archive_path, digest,
                    lock_path=root / ".deployment.lock",
                )

            self.assertEqual([], list(root.iterdir()))
            self.assertEqual([], list(staging_parent.iterdir()))

    def test_safe_overlay_rejects_duplicate_hardlink_and_special_members(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cases = {}
            duplicate = base / "duplicate.tar.gz"
            self._write_archive(duplicate, [("same", b"a"), ("./same", b"b")])
            cases["duplicate"] = duplicate
            hardlink = base / "hardlink.tar.gz"
            hard = tarfile.TarInfo("hard")
            hard.type = tarfile.LNKTYPE
            hard.linkname = "target"
            self._write_archive(hardlink, [(hard, b"")])
            cases["hardlink"] = hardlink
            special = base / "special.tar.gz"
            fifo = tarfile.TarInfo("fifo")
            fifo.type = tarfile.FIFOTYPE
            self._write_archive(special, [(fifo, b"")])
            cases["special"] = special
            for label, path in cases.items():
                with self.subTest(label=label), self.assertRaises(guard.GuardError):
                    guard.apply_archive_overlay(
                        base / "html", path,
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                        lock_path=base / "html" / ".deployment.lock",
                    )

    def test_safe_overlay_prunes_only_hash_bound_previous_source(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            old = root / "ztp/removed-source.py"
            old.parent.mkdir(parents=True)
            old.write_bytes(b"old source\n")
            manifest_path = root / "infra/docker/deployment-source-manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "ztp/removed-source.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            new_payload = b"new source\n"
            new_manifest = json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "ztp/new-source.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }).encode("ascii")
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("ztp/new-source.py", new_payload),
                ("infra/docker/deployment-source-manifest.json", new_manifest),
            ])
            old_manifest_sha256 = hashlib.sha256(
                manifest_path.read_bytes()
            ).hexdigest()
            guard.apply_archive_overlay(
                root, archive_path,
                hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                lock_path=root / ".deployment.lock",
                trusted_old_manifest_sha256=old_manifest_sha256,
            )
            self.assertFalse(old.exists())
            self.assertEqual(new_payload, (root / "ztp/new-source.py").read_bytes())

    def test_safe_overlay_never_trusts_unbound_old_manifest_for_pruning(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            protected = root / "DAY0-Prepare/customer/01-global.yaml"
            protected.parent.mkdir(parents=True)
            protected.write_bytes(b"project authority\n")
            old_manifest = root / "infra/docker/deployment-source-manifest.json"
            old_manifest.parent.mkdir(parents=True)
            old_manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "DAY0-Prepare/customer/01-global.yaml",
                    "type": "file", "target": None,
                    "sha256": hashlib.sha256(protected.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            new_payload = b"new\n"
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/new.py", new_payload),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1, "files": [{
                        "path": "tools/new.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(new_payload).hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            guard.apply_archive_overlay(
                root, archive_path,
                hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                lock_path=root / ".deployment.lock",
            )
            self.assertEqual(b"project authority\n", protected.read_bytes())

    def test_safe_overlay_rejects_old_manifest_digest_mismatch_before_pruning(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            stale = root / "tools/removed.py"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"old\n")
            old_manifest = root / "infra/docker/deployment-source-manifest.json"
            old_manifest.parent.mkdir(parents=True)
            old_manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/removed.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(stale.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            new_payload = b"new\n"
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/new.py", new_payload),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1, "files": [{
                        "path": "tools/new.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(new_payload).hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            with self.assertRaisesRegex(guard.GuardError, "old source manifest.*digest"):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                    trusted_old_manifest_sha256="0" * 64,
                )
            self.assertEqual(b"old\n", stale.read_bytes())

    def test_safe_overlay_retries_partial_os_write_until_member_is_complete(self):
        guard = guard_module()
        payload = b"x" * 8192
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            root.mkdir()
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                ("tools/x.py", payload),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1,
                    "files": [{
                        "path": "tools/x.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            original_write = guard.os.write

            def partial_write(descriptor, value):
                return original_write(descriptor, value[: max(1, len(value) // 2)])

            with mock.patch.object(guard.os, "write", side_effect=partial_write):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                )
            self.assertEqual(payload, (root / "tools/x.py").read_bytes())

    def test_safe_overlay_rejects_symlink_chain_that_resolves_outside_root(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret").write_text("outside\n", encoding="utf-8")
            (root / "escape").symlink_to(outside)
            symlink = tarfile.TarInfo("safe/link")
            symlink.type = tarfile.SYMTYPE
            symlink.linkname = "../escape/secret"
            new_payload = b"new\n"
            archive_path = base / "payload.tar.gz"
            self._write_archive(archive_path, [
                (symlink, b""),
                ("tools/new.py", new_payload),
                ("infra/docker/deployment-source-manifest.json", json.dumps({
                    "schema_version": 1, "files": [{
                        "path": "tools/new.py", "type": "file", "target": None,
                        "sha256": hashlib.sha256(new_payload).hexdigest(),
                    }],
                }).encode("ascii")),
            ])
            with self.assertRaisesRegex(guard.GuardError, "symlink.*root|escape"):
                guard.apply_archive_overlay(
                    root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    lock_path=root / ".deployment.lock",
                )
            self.assertFalse((root / "safe").exists())

    def test_archive_parse_failure_precedes_container_quiesce_and_marker(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.mkdir(exist_ok=True)
            state = root / "state"
            state.mkdir()
            archive_path = root / "payload.tar.gz"
            archive_path.write_bytes(b"not a tar")
            with mock.patch.object(
                guard, "safe_lock", side_effect=lambda *_args, **_kwargs: contextmanager(
                    lambda: (yield 9)
                )(),
            ) as lock, mock.patch.object(
                guard, "quiesce_for_source_update", return_value=True,
            ) as quiesce, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(guard.GuardError):
                    guard.run_locked_archive(
                        root / ".deployment.lock", root, archive_path,
                        hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                        "a" * 64,
                        runtime="docker", state_root=state,
                    )
            lock.assert_not_called()
            quiesce.assert_not_called()
            self.assertFalse((root / ".sync-code-in-progress").exists())

    def test_archive_runtime_binds_trusted_receipt_and_prunes_on_next_upgrade(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            state = base / "state"
            root.mkdir()
            state.mkdir()

            def package(path, member_name, payload):
                manifest = json.dumps({
                    "schema_version": 1,
                    "files": [{
                        "path": member_name, "type": "file", "target": None,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }],
                }).encode("ascii")
                self._write_archive(path, [
                    (member_name, payload),
                    ("infra/docker/deployment-source-manifest.json", manifest),
                ])
                return hashlib.sha256(manifest).hexdigest()

            first = base / "first.tar.gz"
            first_manifest = package(first, "tools/old.py", b"old\n")
            with mock.patch.object(
                guard, "quiesce_for_source_update", return_value=True,
            ), redirect_stdout(io.StringIO()):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, first,
                    hashlib.sha256(first.read_bytes()).hexdigest(),
                    first_manifest,
                    runtime="docker", state_root=state,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            owner = json.loads(
                (state / "deployment-owner.json").read_text(encoding="utf-8")
            )
            self.assertRegex(owner["source_manifest_sha256"], r"^[0-9a-f]{64}$")

            second = base / "second.tar.gz"
            second_manifest = package(second, "tools/new.py", b"new\n")
            with mock.patch.object(
                guard, "quiesce_for_source_update", return_value=True,
            ), redirect_stdout(io.StringIO()):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, second,
                    hashlib.sha256(second.read_bytes()).hexdigest(),
                    second_manifest,
                    runtime="docker", state_root=state,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertFalse((root / "tools/old.py").exists())
            self.assertEqual(b"new\n", (root / "tools/new.py").read_bytes())

    def test_archive_owner_promotion_failure_retries_from_pending_authority(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            state = base / "state"
            old = root / "tools/old.py"
            old.parent.mkdir(parents=True)
            state.mkdir()
            old.write_bytes(b"old\n")
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            old_manifest_payload = (json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                }],
            }) + "\n").encode("ascii")
            manifest.write_bytes(old_manifest_payload)
            old_digest = hashlib.sha256(old_manifest_payload).hexdigest()
            guard.write_deployment_owner(
                state / "deployment-owner.json", root,
                source_manifest_sha256=old_digest,
            )

            new_payload = b"new\n"
            new_manifest_payload = (json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n").encode("ascii")
            new_digest = hashlib.sha256(new_manifest_payload).hexdigest()
            archive = base / "new.tar.gz"
            self._write_archive(archive, [
                ("tools/new.py", new_payload),
                ("infra/docker/deployment-source-manifest.json", new_manifest_payload),
            ])
            archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            original_write_owner = guard.write_deployment_owner
            failed = False

            def fail_new_owner(path, http_root, *, source_manifest_sha256=None):
                nonlocal failed
                if source_manifest_sha256 == new_digest and not failed:
                    failed = True
                    raise guard.GuardError("injected owner fsync failure")
                return original_write_owner(
                    path, http_root,
                    source_manifest_sha256=source_manifest_sha256,
                )

            with mock.patch.object(
                guard, "quiesce_for_source_update", return_value=True,
            ), mock.patch.object(
                guard, "write_deployment_owner", side_effect=fail_new_owner,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(guard.GuardError, "owner fsync"):
                    guard.run_locked_archive(
                        root / ".deployment.lock", root, archive, archive_digest,
                        new_digest, runtime="docker", state_root=state,
                        _ownership_target=(os.getuid(), os.getgid()),
                    )
            self.assertTrue((state / guard.PENDING_SOURCE_UPDATE_NAME).is_file())
            self.assertTrue((root / ".sync-code-in-progress").is_file())
            self.assertEqual(new_manifest_payload, manifest.read_bytes())
            self.assertEqual(
                old_digest,
                json.loads((state / "deployment-owner.json").read_text())["source_manifest_sha256"],
            )

            with mock.patch.object(
                guard, "quiesce_for_source_update", return_value=True,
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, archive, archive_digest,
                    new_digest, runtime="docker", state_root=state,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            self.assertFalse((state / guard.PENDING_SOURCE_UPDATE_NAME).exists())
            self.assertFalse((root / ".sync-code-in-progress").exists())
            self.assertEqual(
                new_digest,
                json.loads((state / "deployment-owner.json").read_text())["source_manifest_sha256"],
            )

    def test_sync_owner_failure_recovers_old_prune_authority_from_pending_state(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            state = base / "state"
            old = root / "tools/old.py"
            old.parent.mkdir(parents=True)
            state.mkdir()
            old.write_bytes(b"old\n")
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1, "files": [{
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            old_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            guard.write_deployment_owner(
                state / "deployment-owner.json", root,
                source_manifest_sha256=old_digest,
            )
            new_payload = b"new\n"
            new = root / "tools/new.py"
            new_digest_payload = (json.dumps({
                "schema_version": 1, "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new_payload).hexdigest(),
                }],
            }) + "\n").encode("ascii")
            new_digest = hashlib.sha256(new_digest_payload).hexdigest()

            old_records = guard.begin_source_update(
                root, state, new_digest,
            )
            new.write_bytes(new_payload)
            manifest.write_bytes(new_digest_payload)
            with mock.patch.object(
                guard, "write_deployment_owner",
                side_effect=guard.GuardError("injected owner write failure"),
            ), self.assertRaisesRegex(guard.GuardError, "owner write"):
                guard.finalize_source_update(
                    root, state, old_records,
                    expected_new_manifest_sha256=new_digest,
                    docker_managed=True,
                    _ownership_target=(os.getuid(), os.getgid()),
                )
            recovered = guard.begin_source_update(root, state, new_digest)
            self.assertEqual(set(old_records), set(recovered))
            guard.finalize_source_update(
                root, state, recovered,
                expected_new_manifest_sha256=new_digest,
                docker_managed=True,
                _ownership_target=(os.getuid(), os.getgid()),
            )
            self.assertFalse(old.exists())
            self.assertFalse((state / guard.PENDING_SOURCE_UPDATE_NAME).exists())

    def test_sync_finalize_prunes_only_owner_authenticated_stale_source(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            state = base / "state"
            old = root / "tools/old.py"
            old.parent.mkdir(parents=True)
            state.mkdir()
            old.write_bytes(b"old\n")
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/old.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(old.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            guard.write_deployment_owner(
                state / "deployment-owner.json", root,
                source_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            )
            old_records, bound = guard._trusted_old_source_records(root, state)
            self.assertRegex(bound, r"^[0-9a-f]{64}$")

            new = root / "tools/new.py"
            new.write_bytes(b"new\n")
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(new.read_bytes()).hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            guard._finalize_live_source_update(
                root, state, old_records, docker_managed=True,
                _ownership_target=(os.getuid(), os.getgid()),
            )
            self.assertFalse(old.exists())
            owner = json.loads(
                (state / "deployment-owner.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                hashlib.sha256(manifest.read_bytes()).hexdigest(),
                owner["source_manifest_sha256"],
            )

    def test_interrupted_sync_can_resume_with_old_receipt_and_new_member_bytes(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "html"
            state = base / "state"
            source = root / "tools/source.py"
            source.parent.mkdir(parents=True)
            state.mkdir()
            source.write_bytes(b"old\n")
            manifest = root / "infra/docker/deployment-source-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/source.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(b"old\n").hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            guard.write_deployment_owner(
                state / "deployment-owner.json", root,
                source_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            )
            # Simulate a killed first rsync after replacing one source member
            # but before publishing the new manifest.
            source.write_bytes(b"new\n")
            old_records, _digest = guard._trusted_old_source_records(root, state)
            manifest.write_text(json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/source.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(b"new\n").hexdigest(),
                }],
            }) + "\n", encoding="ascii")
            guard._finalize_live_source_update(
                root, state, old_records, docker_managed=True,
                _ownership_target=(os.getuid(), os.getgid()),
            )
            self.assertEqual(b"new\n", source.read_bytes())

    def test_archive_mode_safely_bootstraps_missing_deployment_root(self):
        guard = guard_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            (base / "var").mkdir()
            root = base / "var/www/html"
            state = base / "state"
            state.mkdir()
            payload = b"new\n"
            archive_path = base / "payload.tar.gz"
            manifest_payload = json.dumps({
                "schema_version": 1,
                "files": [{
                    "path": "tools/new.py", "type": "file", "target": None,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }],
            }).encode("ascii")
            self._write_archive(archive_path, [
                ("tools/new.py", payload),
                ("infra/docker/deployment-source-manifest.json", manifest_payload),
            ])
            with mock.patch.object(
                guard, "quiesce_for_source_update", return_value=False,
            ), redirect_stdout(io.StringIO()):
                guard.run_locked_archive(
                    root / ".deployment.lock", root, archive_path,
                    hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                    hashlib.sha256(manifest_payload).hexdigest(),
                    state_root=state,
                )
            self.assertTrue(root.is_dir())
            self.assertTrue(root.parent.is_dir())
            self.assertEqual(payload, (root / "tools/new.py").read_bytes())

    def test_archive_deploy_uses_guard_bytes_bound_inside_tested_archive(self):
        approved = b"print('approved archive guard')\n"
        manifest = json.dumps({
            "schema_version": 1,
            "files": [{
                "path": "tools/deployment_prewrite_guard.py",
                "type": "file", "target": None,
                "sha256": hashlib.sha256(approved).hexdigest(),
            }],
        }).encode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "upload.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, payload in (
                    ("./tools/deployment_prewrite_guard.py", approved),
                    ("./infra/docker/deployment-source-manifest.json", manifest),
                ):
                    member = tarfile.TarInfo(name)
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
            frozen = UPLOAD.deployment_guard_source_from_archive(archive_path)
        self.assertEqual(approved.decode("utf-8"), frozen)
        args = upload_args(runtime="docker")
        args.deployment_guard_source = frozen
        payload = UPLOAD.deployment_payload_command(
            args, "/tmp/customer-upload.tar.gz", "a" * 64,
        )
        self.assertIn("approved archive guard", payload)

    def test_extract_payload_holds_lock_and_clears_marker_only_after_tar(self):
        payload = UPLOAD.deployment_payload_command(
            upload_args(), "/tmp/customer-upload.tar.gz", "a" * 64,
        )
        remote = shlex.split(payload)
        self.assertEqual(["sudo", "-n", "python3", "-c"], remote[:4])
        self.assertIn("O_NOFOLLOW", remote[4])
        self.assertNotIn("/bin/sh", remote)
        self.assertNotIn("tar", remote)
        self.assertIn("--archive", remote)
        self.assertEqual(
            "/tmp/customer-upload.tar.gz",
            remote[remote.index("--archive") + 1],
        )
        self.assertEqual("a" * 64, remote[remote.index("--archive-sha256") + 1])
        self.assertEqual(
            "/var/www/html/.deployment.lock",
            remote[remote.index("--lock") + 1],
        )

    def test_upload_without_deploy_does_not_execute_remote_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "customer-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = upload_args(deploy=False, output=archive)
            with (
                mock.patch.object(UPLOAD, "remote_sha256", return_value=digest),
                mock.patch.object(UPLOAD, "run") as run,
                redirect_stdout(io.StringIO()),
            ):
                UPLOAD.upload(args, archive)
        run.assert_not_called()

    def test_deploy_executes_one_locked_remote_command(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "customer-upload.tar.gz"
            archive.write_bytes(b"payload")
            digest = hashlib.sha256(b"payload").hexdigest()
            args = upload_args(deploy=True)
            with (
                mock.patch.object(UPLOAD, "remote_sha256", return_value=digest),
                mock.patch.object(UPLOAD, "run", return_value="") as run,
                redirect_stdout(io.StringIO()),
            ):
                UPLOAD.upload(args, archive)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual("ssh", command[0])
        remote = shlex.split(command[-1])
        self.assertEqual(["sudo", "-n", "python3", "-c"], remote[:4])
        self.assertIn("O_NOFOLLOW", remote[4])
        self.assertIn("--archive", remote)
        self.assertIn("/var/www/html/.deployment.lock", remote)
        self.assertIn(".sync-code-in-progress", remote[4])

    def test_managed_container_archive_deploy_only_recommends_image_rebuild(self):
        args = upload_args(deploy=True)
        args.project = "customer"
        args.dry_run = False
        args.output = Path("/tmp/customer-upload.tar.gz")
        args.no_sudo = False
        project = Path("/tmp/customer")

        @contextmanager
        def frozen(archive):
            yield archive, "c" * 64

        def deployed(current_args, _archive, *, expected_sha256=None):
            self.assertEqual("c" * 64, expected_sha256)
            current_args.docker_rebuild_required = True
            return "/tmp/customer-upload.tar.gz"

        output = io.StringIO()
        with mock.patch.object(
            UPLOAD, "parse_args", return_value=args,
        ), mock.patch.object(
            UPLOAD.package_core, "resolve_project", return_value=project,
        ), mock.patch.object(UPLOAD, "resolve_apps_policy"), \
                mock.patch.object(UPLOAD, "run_predeploy_test_gate"), \
                mock.patch.object(
                    UPLOAD.package_core, "create_package", return_value=args.output,
                ), mock.patch.object(
                    UPLOAD, "frozen_archive_for_upload", side_effect=frozen,
                ), mock.patch.object(UPLOAD, "verify_predeploy_test_approval"), \
                mock.patch.object(
                    UPLOAD, "deployment_guard_source_from_archive",
                    return_value="# approved guard\n",
                ), \
                mock.patch.object(
                    UPLOAD, "deployment_source_manifest_sha256_from_archive",
                    return_value="a" * 64,
                ), \
                mock.patch.object(UPLOAD, "upload", side_effect=deployed), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(0, UPLOAD.main([]))
        rendered = output.getvalue()
        self.assertIn("./infra/docker/deploy.sh deploy", rendered)
        self.assertNotIn("python3 11-load.py", rendered)


if __name__ == "__main__":
    unittest.main()
