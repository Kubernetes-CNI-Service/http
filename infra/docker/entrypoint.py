#!/usr/bin/env python3
"""Create private runtime directories and run Supervisor as container PID 1."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Optional, Sequence


HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
import activate  # noqa: E402
import hostlock  # noqa: E402


RESUME_STATUS = Path("/run/http-ztp/runtime-resume.status.json")


def initialize_resume_status(path: Path = RESUME_STATUS) -> None:
    """Replace any previous-container readiness before Supervisor can start."""
    payload = {
        "state": "starting",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "pid": os.getpid(),
    }
    activate._atomic_write(  # container-private atomic state primitive
        path, json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", 0o600,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args not in ([], ["serve"]):
        print("usage: entrypoint.py [serve]", file=sys.stderr)
        return 2
    try:
        settings = activate.Settings.from_environment(os.environ)
        with hostlock.safe_lock(
            settings.http_root / ".deployment.lock", 600,
        ):
            activate.validate_python_runtime()
            activate.verify_control_auth_image_copies()
            activate.require_monitor_authority()
            activate.require_control_auth(emit_factory_warning=False)
            # A SIGKILL/power loss can interrupt the legacy generator while it
            # temporarily renders default*.yaml in the mounted tree.  Only
            # those declared mutable paths may drift; restore them from the
            # immutable image before the strict receipt check.
            activate.validate_image_source_contract(
                settings, allow_mutable_drift=True,
            )
            activate.restore_mutable_image_sources(settings)
            activate.validate_image_source_contract(settings)
            activate.ensure_runtime_directories(settings)
            activate.ensure_docker_deployment_owner(settings)
            activate.clear_precommit_activation(settings)
            activate.clear_stale_worker_pid_files(settings)
            initialize_resume_status()
            print("[INFO] starting inactive Supervisor control plane", flush=True)
            # O_CLOEXEC releases the shared lock only after Supervisor has
            # replaced this process; a concurrent writer can then stop the
            # exact labelled container before changing repository bytes.
            os.execv(
                "/usr/bin/supervisord",
                ("/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"),
            )
    except (activate.ActivationError, hostlock.HostLockError, OSError, ValueError) as exc:
        print(f"[ERROR] container entrypoint refused startup: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
