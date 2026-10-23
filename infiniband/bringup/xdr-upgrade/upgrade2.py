#!/usr/bin/env python3
"""IB switch upgrade v2: OS/BIOS/CPLD with the fleet engine (owner 2026-10-23).

Same inputs, credentials, canary rules, prechecks and verification as upgrade.py, with
a different engine: a main process with check, upgrade and probe workers, reboot probing
through two queues (ping, TCP/22, SSH boot_id, nvued, `nv show system version`), and OS
images distributed according to the ztp-server link (relay per OOB leaf below 10G,
staggered direct pulls at 10G and above). Every package is staged in /home/admin and
verified on the switch before installation. upgrade.py stays unchanged; read-only
inspection remains `upgrade.py --inspect-only`.

  upgrade2.py --project <dir>                  plan only: precheck, link, groups (no writes)
  upgrade2.py --project <dir> --upgrade -y     upgrade
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import importlib
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import warnings

VERSION = "ibsw-upgrade-v2 2026-10-23"
ENTRY = Path(__file__).resolve()
REPOSITORY = ENTRY.parents[3]
TOOLS = REPOSITORY / "tools"
for _root in (REPOSITORY, TOOLS):
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))

COMPONENTS = ("os", "bios", "cpld")
EXIT_BAD_INPUT, EXIT_BUSY = 2, 75


def parser():
    p = argparse.ArgumentParser(prog="upgrade2.py", allow_abbrev=False,
                                description="IB switch upgrade v2 (plan by default; --upgrade -y to change switches)")
    mode = p.add_argument_group("mode")
    mode.add_argument("--plan", action="store_true", help="precheck and print the plan; never writes a switch (default)")
    mode.add_argument("--upgrade", action="store_true", help="upgrade the selected components")
    mode.add_argument("-y", "--yes", action="store_true", help="confirm --upgrade")
    mode.add_argument("--version", action="version", version=VERSION, help="print the version and exit")
    parts = p.add_argument_group("components (default: all three, in the order os -> bios -> cpld)")
    for name in COMPONENTS:
        parts.add_argument("--" + name, action="store_true", help=f"select {name.upper()}")
    parts.add_argument("--all", "-A", action="store_true", help="select os, bios and cpld")
    parts.add_argument("--skip-canary", action="store_true", help="no canary switch per component")
    parts.add_argument("--force", action="store_true", help="health-only override (the observation is still recorded)")
    inputs = p.add_argument_group("inputs")
    inputs.add_argument("--project", help="project directory with 02-devices_config.csv and 01-global.yaml")
    inputs.add_argument("--ib-csv", help="device CSV (default: project CSV or ib.csv next to this script)")
    inputs.add_argument("--global", dest="global_path", help="01-global.yaml")
    inputs.add_argument("--devices", help="hostname glob (case-insensitive)")
    inputs.add_argument("--p2p", help="P2P XLSX/DOT/CSV with the eth0/mgmt links (default: p2p.xlsx in the project)")
    inputs.add_argument("--package-dir", help="override upgrade.package_dir")
    inputs.add_argument("--local-dir", default="/home/admin", help="package/step directory on the switch")
    auth = p.add_argument_group("credentials (the switch password is always typed, never an argument)")
    auth.add_argument("--known-hosts", default=str(Path.home() / ".ssh/known_hosts"),
                      help="known_hosts that pins the switch host keys (default: ~/.ssh/known_hosts)")
    auth.add_argument("--user", default="admin", help="switch account (default: admin)")
    auth.add_argument("--identity", help="management private key (with --management-public-key)")
    auth.add_argument("--management-public-key", help="management public key")
    auth.add_argument("--password", action="store_true", help="--plan: also ask for the switch password")
    pull = p.add_argument_group("how switches pull packages from the ztp-server")
    pull.add_argument("--method", choices=("http", "scp"), default="http",
                      help="how a switch fetches its packages from the ztp-server (default: http)")
    pull.add_argument("--mgmt-server", help="scp: ztp-server address")
    pull.add_argument("--mgmt-user", help="scp: ztp-server account")
    pull.add_argument("--mgmt-port", type=int, default=22, help="scp: ztp-server SSH port (default: 22)")
    pull.add_argument("--scp-known-hosts", help="scp: known_hosts that pins the ztp-server host key")
    tune = p.add_argument_group("link and concurrency")
    tune.add_argument("--server-link", choices=("1G", "2G", "10G", "20G", "25G", "40G", "50G", "100G", "200G", "400G"),
                      help="override the detected ztp-server link speed")
    tune.add_argument("--in-flight", type=int, default=32, help="switches between dispatch and verification (1-64)")
    tune.add_argument("--check-workers", type=int, default=8,
                      help="parallel prechecks and post-upgrade verifications (default: 8)")
    tune.add_argument("--upgrade-workers", type=int, default=8,
                      help="parallel upgrade dispatches, per component (default: 8)")
    tune.add_argument("--probe-workers", type=int, default=16,
                      help="parallel reboot probes: ping, TCP/22 and SSH status reads (default: 16)")
    tune.add_argument("--relay-fanout", type=int, default=4, help="switches one holder serves at a time")
    tune.add_argument("--relay-transfers", type=int, default=32, help="relay transfers at a time")
    tune.add_argument("--progress-seconds", type=float, default=30.0,
                      help="seconds between progress lines (default: 30)")
    return p


def _selected(args):
    picked = tuple(name for name in COMPONENTS if getattr(args, name))
    return COMPONENTS if args.all or not picked else picked


def _validate(args):
    problems = []
    if args.upgrade and not args.yes:
        problems.append("--upgrade needs --yes")
    if args.plan and args.upgrade:
        problems.append("choose --plan or --upgrade")
    if bool(args.identity) != bool(args.management_public_key):
        problems.append("--identity and --management-public-key go together")
    if args.method == "scp" and not (args.mgmt_server and args.mgmt_user and args.scp_known_hosts):
        problems.append("--method scp needs --mgmt-server, --mgmt-user and --scp-known-hosts")
    for name, low, high in (("in_flight", 1, 64), ("check_workers", 1, 32), ("upgrade_workers", 1, 32),
                            ("probe_workers", 1, 64), ("relay_fanout", 1, 8), ("relay_transfers", 1, 64)):
        if not low <= getattr(args, name) <= high:
            problems.append(f"--{name.replace('_', '-')} must be {low}..{high}")
    return problems


def _key_pair(args):
    if args.identity:
        return Path(args.identity), Path(args.management_public_key)
    for name in ("id_ed25519", "id_rsa"):
        private = Path.home() / ".ssh" / name
        if private.is_file() and private.with_suffix(".pub").is_file():
            return private, private.with_suffix(".pub")
    return None, None


def _ask(prompt, reader):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            value = reader(prompt)
        except (EOFError, getpass.GetPassWarning):
            raise SystemExit("A terminal is required to type the password; nothing was changed.") from None
    if not value:
        raise SystemExit("Empty password; nothing was changed.")
    return value


def _run_directory(args, paths, run_id):
    if args.project:
        return Path(paths.project) / "99-output-ib_nvl" / "bringup" / "xdr-upgrade-v2-logs" / run_id
    return ENTRY.parent / "xdr-upgrade-v2-logs" / run_id


def run(argv=None, *, out=sys.stderr, password_reader=getpass.getpass, ops_factory=None, sysfs_root=Path("/sys"),
        link_run=None, timings=None):
    """The CLI; keyword arguments exist for tests (simulated switches, short probe timings)."""
    args = parser().parse_args(argv)
    problems = _validate(args)
    if problems:
        for problem in problems:
            print("ERROR: " + problem, file=out)
        return EXIT_BAD_INPUT
    from ibsw_upgrade_contract import (load_global_text, normalize_upgrade, plan_input_paths, select_inventory_devices,
                                       snapshot_inventory)
    import fleet_distribution as dist
    import fleet_engine
    import fleet_link
    import fleet_ssh as ssh
    import ibsw_v2_device as ib

    selected = _selected(args)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ") + "_upgrade-v2_" + secrets.token_hex(16)
    paths = plan_input_paths(str(ENTRY), cwd=os.getcwd(), run_id=run_id, project=args.project,
                             csv_path=args.ib_csv, global_path=args.global_path)
    csv_text = Path(paths.csv_path).read_text(encoding="utf-8-sig")
    global_text = Path(paths.global_path).read_text(encoding="utf-8-sig")
    snapshot = select_inventory_devices(snapshot_inventory(csv_text, global_text), args.devices)
    document = load_global_text(global_text)
    policy = normalize_upgrade(document, selected=selected, method=args.method, package_dir=args.package_dir)
    devices = list(snapshot.devices)
    names = [device.hostname for device in devices]

    if args.method == "http":
        server = (document.get("common", {}).get("mgmt", {}).get("http", {}) or {}).get("address")
    else:
        server = args.mgmt_server
    kwargs = {} if link_run is None else {"run": link_run}
    decision = fleet_link.detect([device.address for device in devices], str(server), sysfs_root=sysfs_root,
                                 override=args.server_link, **kwargs)
    print(decision.line(), file=out)
    for warning in decision.warnings:
        print("[LINK] WARN " + warning, file=out)

    p2p = Path(args.p2p) if args.p2p else Path(paths.project or ENTRY.parent) / "p2p.xlsx"
    if p2p.is_file():
        groups, notes = dist.oob_groups(p2p, names)
    else:
        groups, notes = {name: dist.UNKNOWN_GROUP for name in names}, [f"no P2P file ({p2p}); every switch relays from any holder"]
    for note in notes:
        print("[GROUPS] WARN " + note, file=out)
    sizes = {}
    for name, group in groups.items():
        sizes[group] = sizes.get(group, 0) + 1
    print("[GROUPS] " + " · ".join(f"{group} {count}" for group, count in sorted(sizes.items())), file=out)

    private, public = _key_pair(args)
    if private is None:
        print("ERROR: no management key pair (~/.ssh/id_ed25519 or id_rsa with .pub, or --identity)", file=out)
        return EXIT_BAD_INPUT
    key, key_fingerprint = ssh.load_private_key(private, public)
    password = None
    if args.upgrade or args.password:
        password = _ask("Switch password: ", password_reader)
    scp_server = None
    if args.method == "scp":
        scp_password = _ask("Password for the ztp-server scp account: ", password_reader) if args.upgrade else None
        server_pins = ssh.HostPins.load(args.scp_known_hosts)
        keys = server_pins.known_hosts_text(args.mgmt_server, args.mgmt_port)
        if not keys:
            print("ERROR: --scp-known-hosts has no entry for the ztp-server; no trust on first use", file=out)
            return EXIT_BAD_INPUT
        scp_server = ib.ScpServer(args.mgmt_server, args.mgmt_user, args.mgmt_port, keys, scp_password)
    credentials = ssh.Credentials(args.user, key, key_fingerprint, password)
    pins = ssh.HostPins.load(args.known_hosts)
    run_dir = _run_directory(args, paths, run_id)
    evidence = fleet_engine.Evidence(run_dir)
    evidence.write("plan.json", dict(
        version=VERSION, run_id=run_id, argv=list(argv if argv is not None else sys.argv[1:]),
        mode="upgrade" if args.upgrade else "plan", selected=list(selected), method=args.method,
        inputs={"csv": paths.csv_path, "global": paths.global_path,
                "csv_sha256": hashlib.sha256(csv_text.encode()).hexdigest(),
                "global_sha256": hashlib.sha256(global_text.encode()).hexdigest()},
        devices=[device.__dict__ for device in devices],
        blocked_inputs=[dict(hostname=item.hostname, reasons=list(item.reasons)) for item in snapshot.blocked_devices],
        link=dict(line=decision.line(), speed_mbps=decision.speed_mbps, source=decision.source, mode=decision.mode,
                  warnings=list(decision.warnings), layers=[layer.__dict__ for layer in decision.layers]),
        groups=groups, key_fingerprint=key_fingerprint))
    options = fleet_engine.Options(
        run_id=run_id, selected=selected, upgrade=bool(args.upgrade),
        link=decision, groups=groups, skip_canary=args.skip_canary, check_workers=args.check_workers,
        upgrade_workers=args.upgrade_workers, in_flight=args.in_flight, probe_workers=args.probe_workers,
        relay_fanout=args.relay_fanout, relay_transfers=args.relay_transfers, method=args.method,
        progress_seconds=args.progress_seconds, **({"timings": timings} if timings is not None else {}))
    ops_arguments = dict(pins=pins, credentials=credentials, policy=policy, selected=selected,
                         run_id=options.run_id, switch_dir=args.local_dir, force_health=args.force,
                         management_line=Path(public).read_bytes().splitlines()[0] + b"\n",
                         method=args.method, scp_server=scp_server)
    ops = (ops_factory or ib.LiveOps)(**ops_arguments)
    engine = fleet_engine.Engine(devices, ib.IbFamily(policy), ops, options, evidence, out=out,
                                 blocked_inputs=snapshot.blocked_devices)
    interrupts = []

    def on_interrupt(_signum, _frame):
        interrupts.append(1)
        if len(interrupts) == 1:
            engine.request_stop()
        else:
            raise KeyboardInterrupt
    previous = signal.signal(signal.SIGINT, on_interrupt) if threading_main() else None
    try:
        report = engine.run(plan_only=not args.upgrade)
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
    print(fleet_engine.render_summary(report), file=out)
    print(f"evidence: {run_dir}", file=out)
    return fleet_engine.exit_code(report)


def threading_main():
    import threading
    return threading.current_thread() is threading.main_thread()


def main():
    if tuple(sys.argv[1:]) in (("--version",), ("--help",), ("-h",)):
        return run()
    guard = importlib.import_module("ib_bringup_runtime_guard")
    try:
        with guard._runtime_instance_guard():
            return run()
    except guard._InstanceGuardError as error:
        print(f"ERROR [{error.code}] {error}", file=sys.stderr)
        return EXIT_BUSY


if __name__ == "__main__":
    sys.exit(main())
