#!/usr/bin/env python3
"""UFM local preparation and fail-closed four-phase deployment plan.

This entry never invents vendor write recipes. A plan, generated probe, or
successful key installation is not seven-step deployment completion.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import warnings

# A directly executed tool owns this single repository path. Normal package
# imports need no tools/ injection, PYTHONPATH, or catch-all import fallback.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools import ufm_identity_binding as identity
from tools.ufm_input_contract import (
    bind_ufm_inventory_text, parse_ufm_servers,
    plan_ufm_operation_version, plan_ufm_vip,
)
from tools.project_contract import safe_load_global_yaml


class SetupHold(ValueError):
    """No device mutation may be inferred from this failure."""


def classify_ipv4_outcome(outcome):
    """Policy only: callers must not treat a supplied string as live evidence."""
    decisions = {
        "verified": "CONTINUE",
        "unreachable": "OOB_DISCOVERY_REQUIRED",
        "connect_timeout": "OOB_DISCOVERY_REQUIRED",
        "authentication_rejected": "CREDENTIAL_RECOVERY_REQUIRED",
        "host_key_conflict": "STOP",
        "management_mac_mismatch": "STOP",
        "unknown": "STOP",
    }
    if type(outcome) is not str or outcome not in decisions:
        raise SetupHold("unclassified IPv4 outcome")
    return decisions[outcome]


def build_plan(project):
    """Read complete fresh, no-follow project sources; never return secrets."""
    project = Path(project)
    paths = (project / "01-global.yaml", project / "02-devices_config.csv")
    try:
        raw = tuple(identity._read_regular_no_follow(
            path, limit=4 * 1024 * 1024, private=False) for path in paths)
        document = safe_load_global_yaml(io.StringIO(raw[0].decode("utf-8")))
        policy = parse_ufm_servers(document)["ufm"]
        members = bind_ufm_inventory_text(document, raw[1].decode("utf-8-sig"))
        if not members:
            raise SetupHold("no UFM member")
        version = plan_ufm_operation_version(document)
        vip = plan_ufm_vip(document, members)
        primary = secondary = None
        if len(members) == 2:
            candidates = [node for node in members
                          if re.search(r"(?:^|[-_])UFM01$", node.hostname, re.I)]
            if len(candidates) != 1:
                raise SetupHold("installation UFM01 is not unique")
            primary = candidates[0].hostname
            secondary = next(node.hostname for node in members
                             if node.hostname != primary)
    except Exception:
        # YAML and argv exceptions can include credentials/customer content.
        raise SetupHold("project input is invalid, ambiguous, or unavailable") from None
    operations = (
        (1, 2, "base"), (2, 2, "mutual_trust"), (3, 2, "upgrade"),
        (4, 3, "ha"), (5, 4, "subnet_manager"), (6, 4, "license"),
        (7, 4, "license_activation"),
    )
    steps = []
    for number, phase, operation in operations:
        skipped = (number == 3 and version.upgrade == "SKIPPED"
                   or number in (4, 7) and len(members) == 1)
        steps.append({
            "step": number, "phase": phase, "operation": operation,
            "state": "SKIPPED" if skipped else "HOLD",
            "reason": ("not applicable to declared intent" if skipped else
                       "confirmed vendor grammar and live preconditions required"),
        })
    return {
        "schema_version": 1, "state": "PLANNED_NOT_EXECUTED",
        "completion": False, "execution_permitted": False,
        "phases": [
            {"phase": 1, "id": "access", "steps": [],
             "capabilities": ["generate", "authenticate", "establish-keys"]},
            {"phase": 2, "id": "base_trust_upgrade", "steps": [1, 2, 3]},
            {"phase": 3, "id": "ha", "steps": [4]},
            {"phase": 4, "id": "sm_license_activation", "steps": [5, 6, 7]},
        ],
        "steps": steps,
        "nodes": [{"hostname": node.hostname, "ipv4": node.address,
                   "management_mac": node.management_mac} for node in members],
        "management_interface": policy["interfaces"]["alias"]["eth0"],
        "installation_roles": {"primary": primary, "secondary": secondary},
        "requested_version": version.version,
        "vip": {"candidate": vip.candidate, "source": vip.source, "occupancy": "NOT_OBSERVED"},
        "input_sha256": {path.name: hashlib.sha256(data).hexdigest()
                         for path, data in zip(paths, raw)},
        "access": {
            "policy": "CSV_IPV4_FIRST", "dhcp_required": False,
            "oob": "HOLD_UNTIL_EXPLICIT_UNREACHABLE_AND_UNIQUE_PINNED_P2P_OBSERVATION",
            "automatic_oob_execution": False,
            "password_change": "HOLD_VENDOR_GRAMMAR_UNCONFIRMED",
        },
    }


def _selected(args, plan):
    if args.address not in {node["ipv4"] for node in plan["nodes"]}:
        raise SetupHold("address must be an exact CSV UFM node, never VIP")


def _generate(args, plan):
    from tools import ufm_deployment_script_builder as builder
    from monitor.switch_collection_gate import active_project_identity
    _selected(args, plan)
    if args.private_logs_root is None:
        raise SetupHold("private logs root is required")
    # The builder owns active selection and held-source/readback checks.
    if Path(active_project_identity(builder.HTTP_ROOT)) != args.project:
        raise SetupHold("requested project is not the selected active project")
    artifact = builder.generate_stage_script(
        address=args.address, private_logs_root=args.private_logs_root)
    return {"state": "GENERATED_NOT_EXECUTED", "completion": False,
            "execution_permitted": False, "run_id": artifact.run_id,
            "script": str(artifact.script_path), "manifest": str(artifact.manifest_path)}








def _live_inputs(args, plan):
    _selected(args, plan)
    if not args.allow_device_access:
        raise SetupHold("explicit --allow-device-access is required")
    if (args.known_hosts is None or type(args.known_hosts_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", args.known_hosts_sha256) is None):
        raise SetupHold("independent known_hosts pin is required")
    known = identity._read_regular_no_follow(
        args.known_hosts, limit=256 * 1024, private=True)
    if hashlib.sha256(known).hexdigest() != args.known_hosts_sha256:
        raise SetupHold("independent known_hosts pin changed")


def _passwords():
    if not sys.stdin.isatty():
        raise SetupHold("passwords require a private interactive terminal")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        default = getpass.getpass("Default password: ")
        new = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm new password: ")
    if not default or not new or default == new or new != confirmation:
        raise SetupHold("password confirmation is invalid")
    return default, new


def _live(args, plan):
    _live_inputs(args, plan)
    if args.command == "establish-keys":
        if (not args.allow_key_change or args.management_identity is None
                or args.private_logs_root is None):
            raise SetupHold("explicit key-change consent, identity and private logs are required")
    default = new = None
    try:
        default, new = _passwords()
        from tools import ufm_bootstrap_auth_adapter as auth
        if args.command == "authenticate":
            observed = auth.observe_project_direct_bootstrap_authentication(
                args.project, args.address, args.known_hosts, args.known_hosts_sha256,
                new_password=new, default_password=default, timeout=10)
            return {"state": "AUTHENTICATION_OBSERVED_NOT_DEPLOYED",
                    "authentication": observed.authentication,
                    "completion": False, "execution_permitted": False}
        # This original API retains/fsyncs backups before any HOME key apply,
        # closes the password client and proves a fresh management-key session.
        result = auth.establish_project_direct_management_key_access(
            args.project, args.address, args.known_hosts, args.known_hosts_sha256,
            args.management_identity, new_password=new, default_password=default,
            timeout=10, private_logs_root=args.private_logs_root)
        return {key: result[key] for key in (
            "state", "node", "address", "run_id", "backup_state",
            "backup_sha256", "evidence_directory", "completion", "execution_permitted")}
    finally:
        # Reference release is not a claim of Python string zeroization.
        default = new = None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # Never echo an unknown argument or attacker-controlled value.
        self.exit(2, "UFM arguments invalid; see --help (details suppressed)\n")


def main(argv=None):
    parser = _Parser(
        description="UFM initial setup: local preparation and explicit live gates; NOT DEPLOYED")
    parser.add_argument("command", choices=(
        "validate", "plan", "generate", "authenticate", "establish-keys", "execute"),
        help="validate/plan are local only; execute always HOLDs (no vendor write recipe)")
    parser.add_argument("--project", type=Path, required=True,
                        help="DAY0-Prepare project directory holding the UFM inventory and global")
    parser.add_argument("--address", help="UFM management IPv4; must be a node of the project plan")
    parser.add_argument("--private-logs-root", type=Path,
                        help="private xdr-initial-setup-logs root for generated probes and key evidence")
    parser.add_argument("--known-hosts", type=Path, help="pinned known_hosts file for live commands")
    parser.add_argument("--known-hosts-sha256", help="expected SHA-256 of --known-hosts")
    parser.add_argument("--management-identity", type=Path,
                        help="management SSH private identity whose public key establish-keys installs")
    parser.add_argument("--allow-device-access", action="store_true",
                        help="explicit gate for authenticate/establish-keys to contact the device")
    parser.add_argument("--allow-key-change", action="store_true",
                        help="explicit gate for establish-keys to change the device password and keys")
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.project)
        if args.command == "validate":
            result = {"state": "VALIDATED_NOT_DEPLOYED", "completion": False,
                      "input_sha256": plan["input_sha256"]}
        elif args.command == "plan":
            result = plan
        elif args.command == "execute":
            raise SetupHold("vendor write recipes are unconfirmed; seven steps NOT_EXECUTED")
        elif args.command == "generate":
            result = _generate(args, plan)
        else:
            result = _live(args, plan)
    except Exception:
        print(json.dumps({"state": "HOLD", "completion": False,
                          "execution_permitted": False,
                          "reason": "precondition or original operation not proven; no deployment success"},
                         sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
