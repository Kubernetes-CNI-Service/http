#!/usr/bin/env python3
"""Workflow: deploy_infra.py --prepare-only -> infra-setup.py (ubuntu24_host) -> check_infra.classify.

The DNS/NTP/timezone that infra-setup.py applies must be the values deploy_infra.py derives from
the same global (its runtime block is what remote clients consume), and the run-info/infra-status
files infra-setup.py writes must satisfy check_infra.py's verdict.  Runs entirely in the sandbox of
test_infra_setup_py (fake system commands, HOST_ROOT seam); nothing on this machine is changed.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.test_infra_setup_py import GLOBAL, ROOT, Sandbox


def load(name: str, path: Path):
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(path.parent))


DEPLOY = load("infra_setup_py_workflow_deploy", ROOT / "infra/deploy_infra.py")
CHECK = load("infra_setup_py_workflow_check", ROOT / "infra/check_infra.py")
PARTIAL_GLOBAL = "common:\n  switch:\n    system:\n      ntp:\n        server: [192.0.2.123]\n"


def first_active(text: str, key: str) -> str:
    """check_infra.py's effective.<key> probe: first active KEY= line, value trimmed."""
    for line in text.splitlines():
        if re.match(rf"^\s*{key}\s*=", line):
            return line.split("=", 1)[1].strip()
    return ""


class InfraSetupPyWorkflow(unittest.TestCase):
    def prepare(self, base: Path, global_text: str) -> Sandbox:
        box = Sandbox(base, global_text=global_text)
        # deploy_infra.py writes infra-runtime.conf beside --setup-script (the sandbox copy of
        # infra-setup.py) and syntax-checks it, its ubuntu24_host.py and the teardown entry.
        shutil.copy2(ROOT / "infra/infra-teardown.sh", box.infra / "infra-teardown.sh")
        args = SimpleNamespace(
            global_file=box.infra / "01-global.yaml", devices_file=box.infra / "02-devices_config.csv",
            setup_script=box.infra / "infra-setup.py", teardown_script=box.infra / "infra-teardown.sh",
            teardown=False, http_server_ip="192.0.2.10", user="operator", identity=None, hosts=None,
            prepare_only=True, dry_run=False, max_workers=1)
        with mock.patch.object(DEPLOY, "parse_args", return_value=args), \
                mock.patch.object(DEPLOY, "load_servers", return_value=[]), \
                mock.patch.object(DEPLOY, "_local_ipv4_addresses", return_value={"192.0.2.10"}), \
                mock.patch.object(DEPLOY, "http_service_works", return_value=False), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(0, DEPLOY.main())
        self.assertTrue((box.infra / "infra-runtime.conf").is_file())
        return box

    def verdict(self, box: Sandbox) -> tuple:
        values = {f"public.{key}": value for key, value in box.key_values(box.infra / "infra-status").items()}
        values.update({f"run_info.{key}": value for key, value in
                       box.key_values(box.root / "var/lib/http-infra/run-info").items()})
        values.update({"system.os_id": "ubuntu", "system.os_version": "24.04", "privileged.available": "true",
                       "effective.dns": first_active(box.read("etc/systemd/resolved.conf"), "DNS"),
                       "effective.ntp": first_active(box.read("etc/systemd/timesyncd.conf"), "NTP"),
                       "effective.timezone": box.state["timezone"], "packages.missing": ""})
        return CHECK.classify(values)

    def test_values_flow_from_global_through_runtime_into_the_host(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-wf-") as directory:
            for index, (global_text, with_global) in enumerate(
                    ((GLOBAL, True), (GLOBAL, False), (PARTIAL_GLOBAL, True), (PARTIAL_GLOBAL, False))):
                with self.subTest(global_text=global_text, with_global=with_global):
                    box = self.prepare(Path(directory) / f"case{index}", global_text)
                    dns, ntp, zone = DEPLOY.load_common(box.infra / "01-global.yaml", box.infra / "infra-neutral.conf")
                    if not with_global:
                        (box.infra / "01-global.yaml").unlink()  # a remote client's release directory
                    result, _calls, spy, _chown = box.apply("--client", "--non-interactive")
                    self.assertEqual(0, result.returncode, result.stderr + result.stdout)
                    # The applied host is what a check-only run then finds: nothing pending.
                    checked, _calls2, _spy2, _chown2 = box.run("--client", "--non-interactive")
                    self.assertEqual(0, checked.returncode, checked.stdout)
                    self.assertNotIn("differs from 01-global.yaml", result.stdout)
                    self.assertEqual(with_global, "infra_settings" in [entry["name"] for entry in spy])
                    self.assertEqual(" ".join(dns), first_active(box.read("etc/systemd/resolved.conf"), "DNS"))
                    self.assertEqual(" ".join(ntp), first_active(box.read("etc/systemd/timesyncd.conf"), "NTP"))
                    self.assertEqual(zone, box.state["timezone"])
                    run_info = box.key_values(box.root / "var/lib/http-infra/run-info")
                    self.assertEqual("http://192.0.2.10/apps/ubuntu-24.04/amd64", run_info["http_server"])
                    self.assertEqual(("OK", []), self.verdict(box))
                    box.write("etc/systemd/resolved.conf", "[Resolve]\nDNS=192.0.2.250\n")
                    severity, issues = self.verdict(box)
                    self.assertEqual("ERROR", severity)
                    self.assertTrue(any(issue.startswith("DNS 生效值不匹配") for issue in issues), issues)

    def test_client_deploy_ships_the_python_entry_with_its_module(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-wf-deploy-") as directory:
            box = self.prepare(Path(directory), GLOBAL)
            for username, prefix in (("root", ""), ("operator", "sudo -n ")):
                with self.subTest(username=username):
                    commands = []

                    def fake_run(command, **kwargs):
                        commands.append(command)
                        stdout = "/home/operator" if command[-1] == "printf '%s' \"$HOME\"" else ""
                        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

                    with mock.patch.object(DEPLOY.subprocess, "run", side_effect=fake_run):
                        DEPLOY.deploy_server(
                            {"hostname": "client01", "address": "192.0.2.21"}, username, None,
                            box.infra / "infra-setup.py", box.infra / "infra-teardown.sh",
                            box.infra / "infra-runtime.conf", box.infra / "infra-neutral.conf",
                            Path(directory) / f"client-{username}.log",
                        )
                    copies = {command[-2]: command[-1].rsplit("/", 1)[-1] for command in commands
                              if command[0] == "scp"}
                    self.assertEqual(
                        {str(box.infra / name): name for name in (
                            "infra-setup.py", "ubuntu24_host.py", "infra-teardown.sh",
                            "infra-runtime.conf", "infra-neutral.conf")},
                        copies,
                    )
                    activation = next(command[-1] for command in commands
                                      if command[0] == "ssh" and "sha256sum -c -" in command[-1])
                    for name in ("infra-setup.py", "ubuntu24_host.py"):
                        digest = hashlib.sha256((box.infra / name).read_bytes()).hexdigest()
                        self.assertIn(digest, activation)
                    self.assertIn("ln -sfn -- current/infra-setup.py /home/operator/http-infra/infra-setup.py",
                                  activation)
                    self.assertIn("[ ! -L /home/operator/http-infra/infra-setup.sh ] || rm -f --", activation)
                    self.assertRegex(activation, r"(?s)^python3 -B -c .* /home/operator/http-infra/releases/[^ ]+/"
                                                 r"infra-setup\.py /home/operator/http-infra/releases/[^ ]+/"
                                                 r"ubuntu24_host\.py && bash -n ")
                    action = commands[-1][-1]
                    self.assertIn(
                        f"{prefix}python3 -B ./current/infra-setup.py --client --non-interactive "
                        "--enable-bluefield-nic --apply --yes", action)
                    self.assertNotIn("bash ./current/infra-setup", action)

            # The remote syntax gate is real Python: it accepts the entry and module, rejects junk.
            check = [sys.executable, "-B", "-c", DEPLOY.REMOTE_PYTHON_SYNTAX_CHECK]
            accepted = subprocess.run(check + [str(box.infra / "infra-setup.py"),
                                               str(box.infra / "ubuntu24_host.py")],
                                      capture_output=True, text=True)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            broken = Path(directory) / "broken.py"
            broken.write_text("def broken(:\n", encoding="utf-8")
            self.assertNotEqual(0, subprocess.run(check + [str(broken)], capture_output=True).returncode)
            self.assertEqual([], list(box.infra.rglob("__pycache__")))
            with self.assertRaises(DEPLOY.DeployError):
                DEPLOY.validate_entry_syntax(broken)

    def test_check_infra_probes_the_repository_only_by_ip_literal(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-wf-probe-") as directory:
            base = Path(directory)
            infra, fake_bin, calls = base / "http-infra", base / "bin", base / "calls"
            infra.mkdir()
            fake_bin.mkdir()
            for name in ("wget", "curl"):
                tool = fake_bin / name
                tool.write_text(f"#!/bin/sh\nprintf '{name} %s\\n' \"$*\" >> {calls}\nexit 0\n", encoding="utf-8")
                tool.chmod(0o755)
            for tool, script in (("sudo", "exit 1"), ("systemctl", "exit 1"), ("hostname", "echo isolated")):
                (fake_bin / tool).write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
                (fake_bin / tool).chmod(0o755)
            environment = dict(os.environ, INFRA_BASE=str(infra), PATH=f"{fake_bin}:{os.environ.get('PATH', '')}")
            for server, expected in (("http://192.0.2.10/apps/ubuntu-24.04/amd64", "true"),
                                     ("http://[2001:db8::10]:8080/apps/ubuntu-24.04/amd64", "true"),
                                     ("http://mgmt01.lab.example/apps/ubuntu-24.04/amd64", "not_ip_literal")):
                with self.subTest(server=server):
                    calls.unlink(missing_ok=True)
                    (infra / "infra-status").write_text(f"status=completed\nhttp_server={server}\n", encoding="utf-8")
                    probe = subprocess.run(["bash", "-s"], input=CHECK.remote_probe_script(), cwd=infra,
                                           env=environment, text=True, capture_output=True, timeout=30)
                    self.assertIn(f"repository.reachable={expected}\n", probe.stdout)
                    probed = calls.read_text(encoding="utf-8") if calls.exists() else ""
                    if expected == "true":
                        self.assertIn(f"{server}/Packages.gz", probed)
                    else:
                        self.assertEqual("", probed)

    def test_failed_setup_is_reported_by_check_infra(self):
        with tempfile.TemporaryDirectory(prefix="infra-setup-py-wf-fail-") as directory:
            box = self.prepare(Path(directory), GLOBAL)
            box.state["fail"]["systemctl restart lldpd"] = 1
            result, _calls, _spy, _chown = box.apply("--client", "--non-interactive")
            self.assertEqual(1, result.returncode)
            severity, issues = self.verdict(box)
            self.assertEqual("ERROR", severity)
            self.assertIn("setup 执行失败，exit_code=1", issues)


if __name__ == "__main__":
    unittest.main()
