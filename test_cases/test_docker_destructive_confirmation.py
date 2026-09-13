#!/usr/bin/env python3
"""Direct shell contracts for Docker unload/down confirmation and blast radius."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "infra/docker/deploy.sh"
HOSTCTL = ROOT / "infra/docker/hostctl.py"
HOSTLOCK = ROOT / "infra/docker/hostlock.py"
CONTAINER_ID = "a" * 64
PROJECT = "h28-project"
SCOPE = "prod"

EXPECTED_FACTS = {
    "unload": (
        "[PLAN] action=unload",
        f"[PLAN] project={PROJECT}",
        f"[PLAN] scope={SCOPE}",
        f"[PLAN] container_id={CONTAINER_ID}",
        "[DELETE] activation marker, managed Apache/DHCP/worker runtime, project publication links",
        "[RETAIN] owned container, project inputs/outputs, status/log history, images, persistent bind data",
    ),
    "down": (
        "[PLAN] action=down",
        f"[PLAN] project={PROJECT}",
        f"[PLAN] scope={SCOPE}",
        f"[PLAN] container_id={CONTAINER_ID}",
        "[DELETE] owned container, activation marker",
        "[RETAIN] project inputs/outputs, status/log history, images, persistent bind data",
    ),
}


def mutation_events(events: list[str]) -> list[str]:
    return [
        event for event in events
        if event.startswith(("wait:", "docker:", "hostlock:"))
    ]


def load_hostctl():
    spec = importlib.util.spec_from_file_location("h28_hostctl", HOSTCTL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {HOSTCTL}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    sys.path[:0] = [str(HOSTCTL.parent), str(ROOT / "tools"), str(ROOT)]
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[:3]
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    return module


def load_hostlock():
    spec = importlib.util.spec_from_file_location("h28_hostlock", HOSTLOCK)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {HOSTLOCK}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_dispatch(
    root: Path, action: str, *arguments: str, answer: str | None = "",
    replacement_container_id: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the real deploy argument parser/dispatch with hermetic host boundaries."""
    source = DEPLOY.read_text(encoding="utf-8")
    definitions, dispatch = source.split("\naction=${1:-}", 1)
    events = root / "events"
    activation = root / "activation.json"
    replacement_enabled = replacement_container_id is not None
    if replacement_container_id is not None:
        activation.write_text("active\n", encoding="ascii")
    read_override = ""
    if replacement_container_id is not None:
        read_override = f'''read() {{
  builtin read "$@"
  local status=$?
  printf 'prompt-replaced:{replacement_container_id}\\n' >> {os.fspath(events)!r}
  return "$status"
}}
'''
    harness = root / "deploy-harness.sh"
    harness.write_text(
        definitions
        + f'''\n
host_preflight() {{ :; }}
load_runtime_env() {{
  HTTP_ZTP_PROJECT={PROJECT!r}
  HTTP_ZTP_SCOPE={SCOPE!r}
  HTTP_ZTP_SWITCH_SCOPE=all
  HTTP_ZTP_MINI=disabled
  HTTP_ZTP_MONITOR_INTERVAL=30
  HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=
  HTTP_ZTP_DHCP_RELAY_INGRESS=
  HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass
  TZ=Asia/Shanghai
}}
owned_container_id() {{ printf '%s' {CONTAINER_ID!r}; }}
say() {{
  printf '%s\n' "$*"
  printf 'say:%s\n' "$*" >> {os.fspath(events)!r}
}}
{read_override}
wait_control_plane() {{ printf 'wait:%s\n' "$*" >> {os.fspath(events)!r}; }}
safe_lock_run() {{
  if [[ "$1 $2" == "--owned-action remove-clear" && {str(replacement_enabled).lower()!r} == "true" ]]; then
    local expected="" previous=""
    for item in "$@"; do
      if [[ "$previous" == "--expected-owned-id" ]]; then expected=$item; fi
      previous=$item
    done
    if [[ -n "$expected" && "$expected" != {replacement_container_id or ''!r} ]]; then
      printf 'rejected-current:%s\n' {replacement_container_id or 'absent'!r} >> {os.fspath(events)!r}
      return 1
    fi
    rm -f -- {os.fspath(activation)!r}
  fi
  printf 'hostlock:%s\n' "$*" >> {os.fspath(events)!r}
}}
docker() {{ printf 'docker:%s\n' "$*" >> {os.fspath(events)!r}; }}
action=${{1:-}}'''
        + dispatch,
        encoding="utf-8",
    )
    command = ["/bin/bash", os.fspath(harness), action, *arguments]
    run_options = {
        "text": True,
        "capture_output": True,
        "check": False,
        "cwd": ROOT,
        "env": {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        "timeout": 10,
    }
    if answer is None:
        run_options["stdin"] = subprocess.DEVNULL
    else:
        run_options["input"] = answer
    completed = subprocess.run(command, **run_options)
    return completed, (
        events.read_text(encoding="utf-8").splitlines() if events.exists() else []
    )


class DockerDestructiveConfirmationTests(unittest.TestCase):
    @staticmethod
    def _owned_record(identifier: str, *, running: bool = False) -> list[dict]:
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
                {"Type": "bind", "Source": "/var/www/html",
                 "Destination": "/var/www/html", "RW": True},
                {"Type": "bind",
                 "Source": "/var/lib/http-ztp-container/control-auth",
                 "Destination": "/etc/http-ztp", "RW": False},
                {"Type": "bind",
                 "Source": "/var/lib/http-ztp-container/monitor-auth",
                 "Destination": "/var/lib/http-ztp-monitor-auth", "RW": True},
            ],
            "State": {
                "Running": running, "Restarting": False, "Paused": False,
                "Status": "running" if running else "exited",
                "Pid": 123 if running else 0, "Dead": False,
            },
        }]

    def test_usage_keeps_down_away_from_read_only_status_and_logs(self):
        source = DEPLOY.read_text(encoding="utf-8")
        usage = source.split("usage() {", 1)[1].split("EOF\n}", 1)[0]
        positions = [
            usage.index(f"  {action}")
            for action in ("unload", "down", "health", "status", "logs")
        ]
        self.assertEqual(sorted(positions), positions)

    def test_hostctl_keeps_native_unload_noninteractive_inside_container(self):
        hostctl = load_hostctl()
        command = hostctl.unload_command(SimpleNamespace(
            http_root=Path("/var/www/html"), project_name=PROJECT,
        ))
        self.assertEqual(
            (
                "/usr/bin/python3", "-u",
                "/var/www/html/DAY0-Prepare/13-unload.py", PROJECT, "--yes",
            ),
            command,
        )
        self.assertEqual(1, command.count("--yes"))

    def test_eof_and_every_nonliteral_answer_cancel_without_mutation(self):
        for action in ("unload", "down"):
            for label, answer in (
                ("eof", None), ("empty", ""), ("short", "y\n"),
                ("negative", "no\n"), ("wrong-case", "YES\n"),
                ("space-padded", " yes \n"),
            ):
                with self.subTest(action=action, answer=label), tempfile.TemporaryDirectory() as name:
                    result, events = run_dispatch(
                        Path(name), action, answer=answer,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual([], mutation_events(events))
                    self.assertIn("[CANCEL] no Docker/runtime state changed", result.stdout)
                    for fact in EXPECTED_FACTS[action]:
                        self.assertIn(fact, result.stdout)
                        self.assertLess(
                            result.stdout.index(fact),
                            result.stdout.index("Type literal yes to continue"),
                        )

    def test_literal_yes_runs_only_after_printing_exact_facts(self):
        for action, expected_event in (
            ("unload", f"docker:exec {CONTAINER_ID} /opt/http-ztp/hostctl.py unload"),
            ("down", f"hostlock:--owned-action remove-clear --expected-owned-id {CONTAINER_ID}"),
        ):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as name:
                result, events = run_dispatch(Path(name), action, answer="yes\n")
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn(expected_event, events)
                mutations = mutation_events(events)
                self.assertTrue(mutations, events)
                first_mutation = events.index(mutations[0])
                for fact in EXPECTED_FACTS[action]:
                    self.assertIn(fact, result.stdout)
                    self.assertLess(
                        events.index(f"say:{fact}"), first_mutation,
                    )
                    self.assertLess(
                        result.stdout.index(fact),
                        result.stdout.index("Type literal yes to continue"),
                    )

    def test_yes_flag_bypasses_input_but_still_prints_exact_facts(self):
        for action, expected_event in (
            ("unload", f"docker:exec {CONTAINER_ID} /opt/http-ztp/hostctl.py unload"),
            ("down", f"hostlock:--owned-action remove-clear --expected-owned-id {CONTAINER_ID}"),
        ):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as name:
                result, events = run_dispatch(
                    Path(name), action, "--yes", answer=None,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn(expected_event, events)
                self.assertNotIn("Type literal yes to continue", result.stdout)
                mutations = mutation_events(events)
                self.assertTrue(mutations, events)
                first_mutation = events.index(mutations[0])
                for fact in EXPECTED_FACTS[action]:
                    self.assertIn(fact, result.stdout)
                    self.assertLess(
                        events.index(f"say:{fact}"), first_mutation,
                    )

    def test_down_confirmation_cannot_remove_a_replacement_container(self):
        for label, replacement, event_value in (
            ("replacement", "b" * 64, "b" * 64),
            ("absent", "", "absent"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                result, events = run_dispatch(
                    root, "down", answer="yes\n",
                    replacement_container_id=replacement,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertTrue((root / "activation.json").exists())
                self.assertNotIn("hostlock:--owned-action remove-clear", events)
                self.assertIn(f"rejected-current:{event_value}", events)
                self.assertIn(f"prompt-replaced:{replacement}", events)
                self.assertLess(
                    events.index(f"say:[PLAN] container_id={CONTAINER_ID}"),
                    events.index(f"prompt-replaced:{replacement}"),
                )
                self.assertIn(f"[PLAN] container_id={CONTAINER_ID}", result.stdout)

    def test_hostlock_cli_requires_one_valid_expected_owned_identity(self):
        hostlock = load_hostlock()
        action = mock.Mock(return_value=0)
        with mock.patch.object(hostlock, "run_owned_container_action", action):
            self.assertEqual(2, hostlock.main([
                "--owned-action", "remove-clear",
            ]))
        action.assert_not_called()

        action = mock.Mock(return_value=0)
        with mock.patch.object(hostlock, "run_owned_container_action", action):
            try:
                status = hostlock.main([
                    "--owned-action", "remove-clear",
                    "--expected-owned-id", CONTAINER_ID,
                ])
            except SystemExit as exc:
                self.fail(f"valid expected identity was rejected by parser: {exc}")
        self.assertEqual(0, status)
        action.assert_called_once_with(
            "remove-clear", expected_owned_id=CONTAINER_ID,
            lock_path=hostlock.DEFAULT_LOCK, wait_seconds=600,
        )

        for label, value in (
            ("empty", ""), ("short", "a" * 63),
            ("uppercase", "A" * 64),
            ("prefixed", "sha256:" + "a" * 64),
        ):
            with self.subTest(label=label), self.assertRaises(SystemExit) as caught:
                hostlock.parser().parse_args([
                    "--owned-action", "remove-clear",
                    "--expected-owned-id", value,
                ])
            self.assertEqual(2, caught.exception.code)

    def test_hostlock_expected_identity_is_checked_before_remove_or_clear(self):
        hostlock = load_hostlock()
        for label, reply in (
            ("replacement", SimpleNamespace(
                returncode=0,
                stdout=json.dumps(self._owned_record("b" * 64)), stderr="",
            )),
            ("absent", SimpleNamespace(
                returncode=1, stdout="",
                stderr="Error: No such container: http-ztp",
            )),
        ):
            runner = mock.Mock(return_value=reply)
            with self.subTest(label=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                marker = root / "activation.json"
                marker.write_text("active\n", encoding="ascii")
                with self.assertRaisesRegex(
                    hostlock.HostLockError, "expected|identity|changed|absent",
                ):
                    hostlock.run_owned_container_action(
                        "remove-clear", expected_owned_id=CONTAINER_ID,
                        lock_path=root / ".deployment.lock",
                        activation_marker=marker, runner=runner,
                    )
                self.assertTrue(marker.exists())
            self.assertEqual(
                [["docker", "container", "inspect", "http-ztp"]],
                [call.args[0] for call in runner.call_args_list],
            )

        matching = mock.Mock(side_effect=(
            SimpleNamespace(
                returncode=0,
                stdout=json.dumps(self._owned_record(CONTAINER_ID)), stderr="",
            ),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
        ))
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            marker = root / "activation.json"
            marker.write_text("active\n", encoding="ascii")
            with mock.patch.object(hostlock, "ACTIVATION_MARKER", marker):
                self.assertEqual(0, hostlock.run_owned_container_action(
                    "remove-clear", expected_owned_id=CONTAINER_ID,
                    lock_path=root / ".deployment.lock",
                    activation_marker=marker, runner=matching,
                ))
            self.assertFalse(marker.exists())
        self.assertEqual(
            [
                ["docker", "container", "inspect", "http-ztp"],
                ["docker", "rm", CONTAINER_ID],
            ],
            [call.args[0] for call in matching.call_args_list],
        )


if __name__ == "__main__":
    unittest.main()
