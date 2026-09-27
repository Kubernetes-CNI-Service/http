#!/usr/bin/env python3
"""Read-only UFM DHCP discovery; never an SSH or licence identity proof."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "tools", ROOT):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from project_contract import safe_load_global_yaml
from ufm_input_contract import bind_ufm_inventory, plan_ufm_vip
from ztp.dhcp_runtime_inventory import bind_ufm_current_leases


def discover(project: Path, leases_path: Path) -> dict[str, object]:
    """Return a static-and-current-lease observation without external writes."""
    project = Path(project)
    leases_path = Path(leases_path)
    if not project.is_absolute() or not leases_path.is_absolute():
        raise ValueError("UFM discovery requires absolute project and lease paths")
    with (project / "01-global.yaml").open(encoding="utf-8") as stream:
        document = safe_load_global_yaml(stream)
    nodes = bind_ufm_inventory(document, project / "02-devices_config.csv")
    if not nodes:
        raise ValueError("project has no UFM HA nodes")
    vip_plan = plan_ufm_vip(document, nodes)
    lease_text = leases_path.read_text(encoding="utf-8")
    bound = bind_ufm_current_leases(nodes, lease_text)
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
