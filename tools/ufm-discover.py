#!/usr/bin/env python3
"""Read-only UFM DHCP discovery; never an SSH or licence identity proof."""

from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "tools", ROOT):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from project_contract import safe_load_global_yaml
from ufm_input_contract import bind_ufm_inventory_text, plan_ufm_vip
from ufm_identity_binding import _read_regular_no_follow
from ztp.dhcp_runtime_inventory import bind_ufm_current_leases


def _system_root_alias(path: Path) -> Path:
    """Honor macOS's fixed /var and /tmp aliases, not project-local links."""
    parts = path.parts
    if len(parts) > 1 and parts[1] in {"var", "tmp"}:
        prefix = Path("/") / parts[1]
        if prefix.is_symlink():
            expected = f"private/{parts[1]}"
            if os.readlink(prefix) not in {expected, f"/{expected}"}:
                raise ValueError("unexpected system-root alias")
            return Path("/private") / parts[1] / Path(*parts[2:])
    return path


def discover(project: Path, leases_path: Path) -> dict[str, object]:
    """Return a static-and-current-lease observation without external writes."""
    project = Path(project)
    leases_path = Path(leases_path)
    if not project.is_absolute() or not leases_path.is_absolute():
        raise ValueError("UFM discovery requires absolute project and lease paths")
    project = _system_root_alias(project)
    leases_path = _system_root_alias(leases_path)
    # A discovery result is not an SSH identity proof, but it must not obtain
    # its local intent from symlinked or unbounded path aliases.
    global_bytes = _read_regular_no_follow(project / "01-global.yaml",
                                           limit=4 * 1024 * 1024, private=False)
    csv_bytes = _read_regular_no_follow(project / "02-devices_config.csv",
                                        limit=4 * 1024 * 1024, private=False)
    lease_bytes = _read_regular_no_follow(leases_path, limit=32 * 1024 * 1024,
                                          private=False)
    document = safe_load_global_yaml(io.StringIO(global_bytes.decode("utf-8")))
    nodes = bind_ufm_inventory_text(document, csv_bytes.decode("utf-8-sig"))
    if not nodes:
        raise ValueError("project has no UFM HA nodes")
    vip_plan = plan_ufm_vip(document, nodes)
    bound = bind_ufm_current_leases(nodes, lease_bytes.decode("utf-8"))
    return {
        "phase": "discovery_only",
        "ha_requested": len(nodes) == 2,
        "vip_candidate": vip_plan.candidate,
        "vip_candidate_source": vip_plan.source,
        "vip_configured": False,
        "vip_live_verified": False,
        "vip_operator_approved": False,
        "ssh_identity_verified": False,
        "license_mac_verified": False,
        "nodes": [
            {
                "hostname": item.hostname,
                "address": item.address,
                "management_mac": item.management_mac,
                "lease_ends": item.lease_ends.isoformat(),
            }
            for item in bound
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True,
                        help="Absolute project directory containing UFM global and device inventory files")
    parser.add_argument("--leases", type=Path, required=True,
                        help="Absolute path to the current read-only DHCP lease file")
    args = parser.parse_args(argv)
    try:
        observation = discover(args.project, args.leases)
    except Exception as exc:
        # Exception text can contain customer paths or YAML excerpts. Keep the
        # failure visible without copying untrusted input into a public log.
        print(f"UFM discovery failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(observation, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
