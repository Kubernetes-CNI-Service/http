"""I-028 workflow (v3.1.2 M3 WP-3): load's worker start, the real worker, and unload's stop.

Three real scripts in one private HTTP_ROOT: ``11-load.py::start_switch_collection_worker`` without
the page endpoint (no HTTP) launches the real ``monitor/switch-collection-worker.py``, which comes
up idle with the deployment scope; the real ``13-unload.py::stop_monitor_workers`` stops it by its
PID file.  Expectations: I-028 expected fix (问题文档 I-028: the worker starts idle and does not
collect by itself; the CGI/control auth only with HTTP; ``--scope`` from the deployment scope), the
worker ``--scope`` choices (air, prod, all; load never passes all), and unload's PID stop contract.

Only privilege-bound edges are substituted: ``sudo install -o root -g www-data`` becomes a plain
copy with the same mode, and macOS has no ``/proc`` so unload reads argv through ``ps``.  The test
reaps the worker as init would after load exits.  Collection results and slot counts are not
asserted (they belong to C2).
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script(
    "load_collection_worker_workflow_load", ROOT / "DAY0-Prepare/11-load.py",
)
UNLOAD = load_script(
    "load_collection_worker_workflow_unload", ROOT / "DAY0-Prepare/13-unload.py",
)
WORKER_FILES = (
    "tools/project_contract.py",
    "tools/log_rotation.py",
    "tools/operator_identity.py",   # WP-11: the worker imports the root-parent marker from it
    "monitor/switch-collection-worker.py",
    "monitor/switch_collection_gate.py",
)


def _ps_cmdline(pid: int) -> str | None:
    """macOS stand-in for 13-unload.py::process_cmdline, which reads /proc/<pid>/cmdline."""
    result = subprocess.run(
        ["ps", "-o", "command=", "-p", str(pid)],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() or None


class LoadCollectionWorkerWorkflowTests(unittest.TestCase):
    """Real load start -> real worker idle -> real unload stop."""

    def make_layout(self, directory: str) -> Path:
        root = Path(directory)
        for relative in WORKER_FILES:
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, root / relative)
        return root

    def test_real_worker_starts_idle_with_deployment_scope_and_unload_stops_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_layout(directory)
            cgi_bin = root / "cgi-bin"
            cgi_bin.mkdir()
            status = root / "monitor/status"
            worker = root / "monitor/switch-collection-worker.py"
            launched: list[tuple[list[str], subprocess.Popen]] = []
            installs: list[tuple[str, ...]] = []
            real_popen = LOAD._popen_subprocess

            def install_without_root(command, **_kwargs):
                # Stands in for `sudo install -m 0664 -o root -g www-data SRC DEST`.
                installs.append(tuple(command))
                self.assertEqual(
                    ("install", "-m", "0664", "-o", "root", "-g", "www-data"),
                    tuple(command[:7]),
                )
                shutil.copyfile(command[7], command[8])
                os.chmod(command[8], 0o664)

            def spy_popen(command, **kwargs):
                process = real_popen(command, **kwargs)
                launched.append((list(command), process))
                return process

            forbidden = mock.Mock(side_effect=AssertionError("endpoint step without HTTP"))
            backend = LOAD.SystemdRuntimeBackend(
                command_runner=mock.Mock(side_effect=AssertionError("systemctl")),
            )
            with mock.patch.object(LOAD, "HTTP_ROOT", root), \
                    mock.patch.object(LOAD, "SWITCH_COLLECTION_WORKER", worker), \
                    mock.patch.object(
                        LOAD, "SWITCH_COLLECTION_CONTROL_DEST",
                        cgi_bin / "switch-collection-control",
                    ), \
                    mock.patch.object(LOAD, "verify_control_auth", forbidden), \
                    mock.patch.object(LOAD, "verify_apache_publication_boundary", forbidden), \
                    mock.patch.object(LOAD, "_reload_apache_if_active", forbidden), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *c: list(c)), \
                    mock.patch.object(LOAD, "run", side_effect=install_without_root), \
                    mock.patch.object(LOAD, "_popen_subprocess", side_effect=spy_popen), \
                    redirect_stdout(io.StringIO()):
                LOAD.start_switch_collection_worker(
                    "prod", runtime_backend=backend, control_endpoint=False,
                )

            self.assertEqual(1, len(launched))
            argv, process = launched[0]
            self.addCleanup(lambda: process.poll() is None and process.kill())
            # Load exits after starting it; init reaps the worker.  Here the test does.
            reaper = threading.Thread(target=process.wait, daemon=True)
            reaper.start()
            forbidden.assert_not_called()
            self.assertEqual(str(worker), argv[2])
            self.assertEqual(1, argv.count("--scope"))
            self.assertEqual("prod", argv[argv.index("--scope") + 1])
            self.assertEqual(1, len(installs))
            self.assertEqual("idle\n", (status / "switch-collection.request").read_text())
            self.assertEqual([], list(cgi_bin.iterdir()))
            pid_file = status / "switch-collection.pid"
            self.assertEqual(f"{process.pid}\n", pid_file.read_text(encoding="utf-8"))

            status_file = status / "switch-collection.status.json"
            deadline = time.monotonic() + 30
            while not status_file.is_file() and process.poll() is None:
                self.assertLess(time.monotonic(), deadline, "worker never wrote its status")
                time.sleep(0.05)
            self.assertIsNone(process.poll(), (status / "switch-collection.log").read_text())
            payload = json.loads(status_file.read_text(encoding="utf-8"))
            self.assertEqual("idle", payload["state"])
            self.assertEqual("prod", payload["scope"])
            self.assertEqual("idle\n", (status / "switch-collection.request").read_text())

            with mock.patch.object(UNLOAD, "MONITOR_WORKERS", (
                (pid_file, "switch-collection-worker.py"),
                (status / "manual-ztp.pid", "manual-ztp-worker.py"),
            )), mock.patch.object(UNLOAD, "process_cmdline", _ps_cmdline), \
                    redirect_stdout(io.StringIO()):
                UNLOAD.stop_monitor_workers(dry_run=False, runtime_backend=backend)

            reaper.join(timeout=10)
            self.assertIsNotNone(process.poll())
            self.assertFalse(pid_file.exists())


if __name__ == "__main__":
    unittest.main()
