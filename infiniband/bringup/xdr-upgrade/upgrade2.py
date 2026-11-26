#!/usr/bin/env python3
"""IB switch upgrade v2: OS/BIOS/CPLD with the fleet engine (owner 2026-10-23).

Same inputs, credentials, canary rules, prechecks and verification as upgrade.py, with
a different engine: a main process with check, upgrade and probe workers, reboot probing
through two queues (ping, TCP/22, SSH boot_id, nvued, `nv show system version`), and OS
images distributed according to the ztp-server link (relay per OOB leaf below 10G,
staggered direct pulls at 10G and above). Every package is staged in /home/admin and
verified on the switch before installation. upgrade.py stays unchanged; read-only
inspection remains `upgrade.py --inspect-only`. A typed switch password is checked once,
with a password-only login that writes nothing, before any precheck; a refusal asks
again, three attempts in all (field 2026-10-24).

  upgrade2.py --project <dir>                  plan only: precheck, link, groups (no writes)
  upgrade2.py --project <dir> --upgrade -y     upgrade
  ... --push                                   the ztp-server pushes, switches forward (v3.1.6 U10)
  ... --pin-unknown-host-keys                  first registration of never-pinned host keys (v3.1.6 U7)
"""
from __future__ import annotations

import argparse
import copy
import csv
from datetime import datetime, timezone
import getpass
import hashlib
import importlib
from importlib import metadata
import json
import os
import stat
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
PASSWORD_ATTEMPTS = 3                       # like upgrade.py: re-asked after an explicit refusal, three in all
NOT_OFFERED = {"CONNECT_FAILED", "CONNECT_TIMEOUT", "HANDSHAKE_FAILED", "HOST_KEY_UNKNOWN", "HOST_KEY_MISMATCH"}
RUN_DIRECTORY_NAME = "xdr-upgrade-v2-logs"
_RUNTIME_VENV_PATHS = ("~/.venvs/http/ibsw-upgrade", "~/.venv-upgrade")
_RUNTIME_VENV_MARKER = "IBSW_UPGRADE_VENV_REEXEC"
from fleet_ssh import SSH_RUNTIME_PINS
_RUNTIME_DISTRIBUTIONS = (*SSH_RUNTIME_PINS, ("PyYAML", None))


def _runtime_problems(version):
    problems = []
    for name, expected in _RUNTIME_DISTRIBUTIONS:
        try:
            installed = version(name)
        except metadata.PackageNotFoundError:
            installed = None
        if installed is None or (expected is not None and installed != expected):
            problems.append(name)
    return problems


def _runtime_venv_candidates():
    return tuple(Path(os.path.expanduser(path)) for path in _RUNTIME_VENV_PATHS)


def _audited_runtime_venv(venv):
    """The v1 bounded ownership/mode/layout audit, using v2's own distribution list."""
    import grp
    import pwd
    uid = os.geteuid()
    account = pwd.getpwuid(uid)
    def safe(info):
        if info.st_uid not in (0, uid) or info.st_mode & stat.S_IWOTH:
            return False
        if info.st_mode & stat.S_IWGRP:
            try:
                group = grp.getgrgid(info.st_gid)
            except KeyError:
                return False
            return (info.st_gid == account.pw_gid and group.gr_name == account.pw_name
                    and all(member == account.pw_name for member in group.gr_mem))
        return True
    venv, home = Path(venv), Path(os.path.expanduser("~"))
    try:
        if not venv.is_absolute():
            return None, "not absolute"
        paths = [parent for parent in venv.parents if parent != home and parent.is_relative_to(home)]
        paths += [venv, venv / "bin", venv / "lib"]
        sites = sorted((venv / "lib").glob("python3.*/site-packages"))
        if len(sites) != 1:
            return None, "needs exactly one site-packages"
        paths += [sites[0].parent, sites[0]]
        for path in paths:
            info = os.lstat(path)
            if not stat.S_ISDIR(info.st_mode) or not safe(info):
                return None, "unsafe directory"
        config = os.lstat(venv / "pyvenv.cfg")
        python = venv / "bin/python3"
        executable = os.stat(python)
        if (not stat.S_ISREG(config.st_mode) or not safe(config)
                or not stat.S_ISREG(executable.st_mode) or not safe(executable)
                or not os.access(python, os.X_OK)):
            return None, "unsafe runtime files"
        def version(name):
            found = [item.version for item in metadata.distributions(name=name, path=[str(sites[0])])]
            if len(found) != 1:
                raise metadata.PackageNotFoundError(name)
            return found[0]
        if _runtime_problems(version):
            return None, "runtime distributions do not match"
    except (OSError, ValueError, UnicodeError):
        return None, "runtime unreadable"
    return str(python), "usable"


def _reexec_in_runtime_venv(argv=None):
    """Identity has already switched; exec preserves original args and inheritable FDs."""
    args = tuple(sys.argv[1:] if argv is None else argv)
    if any(arg in ("-h", "--help", "--version") for arg in args):
        return "NOT_NEEDED"
    switched = os.environ.pop(_RUNTIME_VENV_MARKER, None) is not None
    if not _runtime_problems(metadata.version):
        return "NOT_NEEDED"
    if not switched:
        for venv in _runtime_venv_candidates():
            python, _reason = _audited_runtime_venv(venv)
            if python is None:
                continue
            environment = dict(os.environ, **{_RUNTIME_VENV_MARKER: "1"})
            options = ["-B"] if sys.flags.dont_write_bytecode else []
            print(f"[RUNTIME] re-running once with fixed venv {venv}; arguments unchanged", file=sys.stderr)
            try:
                os.execve(python, [python, *options, sys.argv[0], *args], environment)
            except OSError:
                continue
    print("ERROR: pinned SSH runtime and PyYAML unavailable; use a matching fixed venv: "
          + ", ".join(_RUNTIME_VENV_PATHS) + "; nothing was installed automatically", file=sys.stderr)
    return "NO_CANDIDATE"


def _runtime_locked_files(locked_type, out):
    locked = []
    for name, _expected in _RUNTIME_DISTRIBUTIONS:
        distribution = metadata.distribution(name)
        files = distribution.files
        if files is None:
            print(f"[LOCK] WARN {name}: no RECORD; its files are not locked", file=out)
            continue
        for item in files:
            if "__pycache__" in item.parts:
                continue
            path = distribution.locate_file(item)
            try:
                locked.append(locked_type.read(name, path))
            except OSError:
                continue
    return locked


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
    inputs.add_argument("--inventory-checked", action="store_true", help=argparse.SUPPRESS)
    inputs.add_argument("--local-dir", default="/home/admin", help="package/step directory on the switch")
    auth = p.add_argument_group("credentials (the switch password is always typed, never an argument)")
    auth.add_argument("--known-hosts", default=str(Path.home() / ".ssh/known_hosts"),
                      help="known_hosts that pins the switch host keys (default: ~/.ssh/known_hosts)")
    auth.add_argument("--user", default="admin", help="switch account (default: admin)")
    auth.add_argument("--identity", help="management private key (with --management-public-key)")
    auth.add_argument("--management-public-key", help="management public key")
    auth.add_argument("--password", action="store_true", help="--plan: also ask for the switch password")
    auth.add_argument("--pin-unknown-host-keys", action="store_true",
                      help="add the host key of a switch that has no known_hosts entry at all, after its hostname and "
                           "eth0 MAC match the inventory (--known-hosts must be your ~/.ssh/known_hosts)")
    pull = p.add_argument_group("how packages reach the switches")
    pull.add_argument("--push", action="store_true",
                      help="the ztp-server pushes each package over SSH and the switches forward it between "
                           "themselves; no switch connects to the server (--method is then ignored)")
    pull.add_argument("--method", choices=("http", "scp"),
                      help="how a switch fetches its packages from the ztp-server (default: http)")
    pull.add_argument("--mgmt-server", help="scp: ztp-server address")
    pull.add_argument("--mgmt-user", help="scp: ztp-server account")
    pull.add_argument("--mgmt-port", type=int, default=22, help="scp: ztp-server SSH port (default: 22)")
    pull.add_argument("--scp-known-hosts", help="scp: known_hosts that pins the ztp-server host key")
    tune = p.add_argument_group("link and concurrency")
    tune.add_argument("--server-link", choices=("1G", "2G", "10G", "20G", "25G", "40G", "50G", "100G", "200G", "400G"),
                      help="override the detected ztp-server link speed")
    tune.add_argument("--in-flight", type=int, default=32, help="switches between dispatch and verification (1-64)")
    tune.add_argument("--check-workers", type=int, default=16,
                      help="parallel prechecks and post-upgrade verifications (default: 16)")
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


def _http_endpoints(document):
    """common.mgmt.http.address as one IPv4 or a list of IPv4 (owner 2026-10-24: Apache may listen on several
    addresses, one per ztp-server network). Each is validated like the project contract; duplicates removed."""
    from project_contract import validate_service_endpoint
    http = (((document.get("common") or {}).get("mgmt") or {}).get("http") or {}) if isinstance(document, dict) else {}
    raw = http.get("address") if isinstance(http, dict) else None
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        raise ValueError("common.mgmt.http.address is an empty list")
    endpoints = []
    for index, value in enumerate(values):
        field = f"common.mgmt.http.address[{index}]" if isinstance(raw, list) else "common.mgmt.http"
        endpoint = validate_service_endpoint(value, http.get("port", 80), field=field)
        if endpoint.host not in [item.host for item in endpoints]:
            endpoints.append(endpoint)
    return endpoints, isinstance(raw, list)


def _check_password(ops, devices, ssh):
    """One password-only login running `true` on the first selected switch that answers TCP/22 (field
    2026-10-24). Switches where the password could not be offered (no TCP/22, no SSH, host key not pinned
    or different) are passed over. Returns (hostname or None, "ACCEPTED" | "PASSWORD_REJECTED" | other code |
    "NO_SWITCH_ANSWERED")."""
    for device in devices:
        if not ops.tcp(device):
            continue
        try:
            ops.password_login(device)
        except ssh.SshError as error:
            if error.code in NOT_OFFERED:
                continue
            return device.hostname, error.code
        return device.hostname, "ACCEPTED"
    return None, "NO_SWITCH_ANSWERED"


def _run_directory(args, paths, run_id):
    return Path(paths.project) / "99-output-ib_nvl" / "bringup" / RUN_DIRECTORY_NAME / run_id


def run(argv=None, *, out=sys.stderr, password_reader=getpass.getpass, ops_factory=None, sysfs_root=Path("/sys"),
        link_run=None, timings=None, home=None, presented_connector=None):
    """The CLI; keyword arguments exist for tests (simulated switches, short probe timings, an owned home and a
    connect_presented stand-in for --pin-unknown-host-keys)."""
    import fleet_ssh as ssh
    try:
        return _run(argv, out=out, password_reader=password_reader, ops_factory=ops_factory,
                    sysfs_root=sysfs_root, link_run=link_run, timings=timings, home=home,
                    presented_connector=presented_connector)
    except OSError as error:
        print("ERROR: input file unreadable: " + str(error.filename or "input") + " ("
              + str(error.strerror or "read failed") + ")", file=out)
    except ssh.SshError as error:
        print("ERROR: " + error.code + "; management key or SSH runtime unavailable", file=out)
    except metadata.PackageNotFoundError:
        print(f"ERROR: SDK_UNAVAILABLE; required runtime distribution missing: {sys.prefix}", file=out)
    return EXIT_BAD_INPUT


def _pin_unknown_host_keys(args, devices, credentials, *, editor, run_id, connect, out):
    """v3.1.6 U7 (问题文件 §36.3; owner 11-20 P-06 (a)): before the run reads known_hosts, add the host key of
    each selected switch that has no entry at all (a pinned or @-marked address is never touched and never
    connected). The trust basis is the login: the presented key is written only after `hostname` and the eth0
    MAC read over that session match the inventory; --plan only lists it. Returns (rows for
    host-key-pins.json, {hostname: reason} for the summary)."""
    import fleet_ssh as ssh
    import ibsw_v2_device as ib
    import login_path
    pins = ssh.HostPins.load(args.known_hosts)
    rows, review = [], {}
    for device in devices:
        try:
            if pins.keys(device.address):
                continue
        except ssh.SshError:                    # a marker line: never an unknown key
            continue
        row = dict(hostname=device.hostname, address=device.address, fingerprint=None)
        try:
            session, (key_type, blob, fingerprint) = connect(device, credentials)
            row["fingerprint"] = fingerprint
            with session:
                identity = session.run("hostname; cat /sys/class/net/eth0/address")
                ib.check_identity({"identity": (identity.rc, identity.stdout, identity.stderr)}, device)
        except ssh.SshError as error:
            row.update(state="NOT_PINNED", reason="CONNECT_" + error.code)
        except ib.DeviceError as error:
            row.update(state="NOT_PINNED", reason=error.code)
            if error.code == "DEVICE_IDENTITY_MISMATCH":
                review[device.hostname] = error.code
        else:
            row.update(key_type=key_type, basis="hostname+MAC")
            if args.upgrade:                    # --upgrade --yes is the authorization
                record = login_path.pin_unknown_host_key(device.address, key_type, blob, fingerprint, editor,
                                                         before_write=lambda: None, hostname=device.hostname,
                                                         run_id=run_id)
                if fingerprint not in ssh.HostPins.load(args.known_hosts).fingerprints(device.address):
                    raise ValueError("pinned host key not read back")
                row.update(state="PINNED", backup=record.backup)
            else:
                row["state"] = "WOULD_PIN"
        verb = {"PINNED": "pinned", "WOULD_PIN": "would pin"}.get(row["state"], "not pinned")
        tail = "basis=hostname+MAC" if row["state"] != "NOT_PINNED" else row["reason"]
        print(f"[HOSTKEY] {verb} {device.hostname} {device.address} {row['fingerprint'] or '-'} {tail}", file=out)
        rows.append(row)
    return rows, review


def _run(argv=None, *, out=sys.stderr, password_reader=getpass.getpass, ops_factory=None, sysfs_root=Path("/sys"),
         link_run=None, timings=None, home=None, presented_connector=None):
    args = parser().parse_args(argv)
    method_ignored = args.push and args.method is not None     # U10: --push wins, said after the link line
    args.method = "push" if args.push else args.method or "http"
    problems = _validate(args)
    if problems:
        for problem in problems:
            print("ERROR: " + problem, file=out)
        return EXIT_BAD_INPUT
    editor = None
    if args.pin_unknown_host_keys:          # U7: only the operator's own file, checked before anything connects
        import pwd
        import login_path
        try:
            editor = login_path.LocalKnownHostsEditor(Path(args.known_hosts), home=Path(
                home if home is not None else pwd.getpwuid(os.getuid()).pw_dir))
        except ValueError:
            print(f"ERROR: --pin-unknown-host-keys needs --known-hosts to be your own ~/.ssh/known_hosts (not a "
                  f"link): {args.known_hosts}", file=out)
            return EXIT_BAD_INPUT
    from ibsw_upgrade_contract import (load_global_text, normalize_upgrade, plan_input_paths, select_inventory_devices,
                                       snapshot_inventory)
    import fleet_distribution as dist
    import fleet_engine
    import fleet_link
    import fleet_ssh as ssh
    import ibsw_v2_device as ib

    selected = _selected(args)
    from project_contract import ActiveProjectPointerError, active_project_dir, yaml
    try:
        project = Path(args.project).resolve() if args.project else active_project_dir(REPOSITORY)
    except ActiveProjectPointerError as error:
        print(f"ERROR: {error}", file=out)
        return EXIT_BAD_INPUT
    if project is None:
        print("ERROR: no active project; run setup or use --project", file=out)
        return EXIT_BAD_INPUT
    args.project = str(project)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ") + "_upgrade-v2_" + secrets.token_hex(16)
    csv_path = args.ib_csv or (str(project / "ib.csv") if (project / "ib.csv").exists() else None)
    try:
        paths = plan_input_paths(str(ENTRY), cwd=os.getcwd(), run_id=run_id, project=args.project,
                                 csv_path=csv_path, global_path=args.global_path)
    except ValueError as error:
        reason = ("explicit project input cannot silently use foreign source" if
                  str(error) == "explicit project input cannot silently use foreign source" else "invalid input path")
        print(f"ERROR: {reason}: {csv_path or project}; {args.global_path or project}", file=out)
        return EXIT_BAD_INPUT
    if not args.inventory_checked and (args.ib_csv or (project / "ib.csv").exists()):
        from tools.inventory_subset import compare
        master_csv = project / "02-devices_config.csv"
        try:
            mismatches = compare(paths.csv_path, master_csv)
        except (OSError, UnicodeError, csv.Error, IndexError):
            # M4's reader owns no CLI; malformed encoding/CSV rows are input
            # errors at this boundary, not device or engine exceptions.
            print(f"ERROR: cannot read or parse inventory comparison inputs: {paths.csv_path}; {master_csv}", file=out)
            return EXIT_BAD_INPUT
        for item in mismatches:
            print(f"INVENTORY MISMATCH: {item.hostname}; {item.column}; ib.csv={item.subset_value}; "
                  f"02={item.master_value}; {item.kind}", file=out)
        if mismatches:
            return EXIT_BAD_INPUT
    try:
        csv_text = Path(paths.csv_path).read_text(encoding="utf-8-sig")
        global_text = Path(paths.global_path).read_text(encoding="utf-8-sig")
        snapshot = select_inventory_devices(snapshot_inventory(csv_text, global_text), args.devices)
        document = load_global_text(global_text)
    except (ValueError, UnicodeError, yaml.YAMLError):
        print(f"ERROR: invalid project inputs: {paths.csv_path}; {paths.global_path}", file=out)
        return EXIT_BAD_INPUT
    endpoints, listed = [], False
    policy_document = document
    if args.method in ("http", "push"):     # push: the same server addresses decide the link
        try:
            endpoints, listed = _http_endpoints(document)
        except ValueError:
            print(f"ERROR: invalid HTTP service configuration: {paths.global_path}", file=out)
            return EXIT_BAD_INPUT
        if listed and args.method == "http":   # the v1 policy reader takes one address: build URLs with the first
            policy_document = copy.deepcopy(document)
            policy_document["common"]["mgmt"]["http"]["address"] = endpoints[0].host
    try:
        policy = normalize_upgrade(policy_document, selected=selected, method="local" if args.method == "push" else
                                   args.method, package_dir=args.package_dir)
    except ValueError:
        print(f"ERROR: invalid upgrade configuration: {paths.global_path}", file=out)
        return EXIT_BAD_INPUT
    devices = list(snapshot.devices)
    names = [device.hostname for device in devices]

    kwargs = {} if link_run is None else {"run": link_run}
    addresses = [device.address for device in devices]
    services, service_issues, origins = {}, {}, {}
    if args.method == "http":               # each switch: the HTTP address on its own network, or fail closed
        services = fleet_link.resolve_services(addresses, [endpoint.host for endpoint in endpoints], **kwargs)
        origin_of = {endpoint.host: endpoint.origin for endpoint in endpoints}
        for device in devices:
            service = services[device.address]
            if service.address:
                origins[device.hostname] = origin_of[service.address]
            else:
                service_issues[device.hostname] = (
                    f"{service.reason}: {device.hostname} egress {service.device or '-'}"
                    + (f" ({', '.join(service.candidates)})" if service.candidates else ""))
        decision = fleet_link.detect(addresses, [endpoint.host for endpoint in endpoints], sysfs_root=sysfs_root,
                                     override=args.server_link, services=services, **kwargs)
    elif args.method == "push":
        decision = fleet_link.detect(addresses, [endpoint.host for endpoint in endpoints], sysfs_root=sysfs_root,
                                     override=args.server_link, **kwargs)
    else:
        decision = fleet_link.detect(addresses, str(args.mgmt_server), sysfs_root=sysfs_root,
                                     override=args.server_link, **kwargs)
    print(decision.line(), file=out)
    if method_ignored:
        print("--method ignored with --push", file=out)
    for warning in decision.warnings:
        print("[LINK] WARN " + warning, file=out)
    if args.method == "http":
        uses = {}
        for device in devices:
            service = services[device.address]
            if service.address:
                key = (service.device, service.address)
                uses[key] = uses.get(key, 0) + 1
        listing = " · ".join(f"{egress} {address} {count} switch(es)"
                             for (egress, address), count in sorted(uses.items()))
        print("[HTTP] " + (listing or "no switch has an HTTP address on its network"), file=out)
        for hostname, reason in service_issues.items():
            print(f"[HTTP] WARN {reason}; this switch fails closed and nothing is written to it", file=out)

    p2p = Path(args.p2p) if args.p2p else Path(paths.project or ENTRY.parent) / "p2p.xlsx"
    if p2p.is_file():
        setup = dist._p2p_module()
        try:
            groups, notes = dist.oob_groups(p2p, names, module=setup)
        except (setup.SetupError, setup.ET.ParseError, csv.Error, setup.zipfile.BadZipFile):
            print(f"ERROR: invalid P2P input: {p2p}", file=out)
            return EXIT_BAD_INPUT
    elif args.p2p:
        print(f"ERROR: P2P input unreadable: {p2p}", file=out)
        return EXIT_BAD_INPUT
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
    locked_inputs = [fleet_engine.LockedFile.read("private key", private),
                     fleet_engine.LockedFile.read("management public key", public)]
    locked_inputs += _runtime_locked_files(fleet_engine.LockedFile, out)
    try:
        key, key_fingerprint = ssh.load_private_key(private, public)
    except ssh.SshError as error:
        print(f"ERROR: {error.code}; management key or SSH runtime unavailable: {private}; {public}", file=out)
        return EXIT_BAD_INPUT
    except (ValueError, UnicodeError):
        print(f"ERROR: KEY_INVALID; invalid management key pair: {private}; {public}", file=out)
        return EXIT_BAD_INPUT
    password = None
    if args.upgrade or args.password:
        password = _ask("Switch password: ", password_reader)
    scp_server = None
    if args.method == "scp":
        scp_password = _ask("Password for the ztp-server scp account: ", password_reader) if args.upgrade else None
        server_watch = fleet_engine.LockedFile.read("scp known hosts", args.scp_known_hosts)
        try:
            server_pins = ssh.HostPins.load(args.scp_known_hosts)
            keys = server_pins.known_hosts_text(args.mgmt_server, args.mgmt_port)
        except ValueError:
            print(f"ERROR: invalid scp known_hosts: {args.scp_known_hosts}", file=out)
            return EXIT_BAD_INPUT
        if not keys:
            print(f"ERROR: --scp-known-hosts has no entry for the ztp-server; no trust on first use: "
                  f"{args.scp_known_hosts}", file=out)
            return EXIT_BAD_INPUT
        scp_server = ib.ScpServer(args.mgmt_server, args.mgmt_user, args.mgmt_port, keys, scp_password)
    credentials = ssh.Credentials(args.user, key, key_fingerprint, password)
    pin_rows, pin_review = None, {}
    if editor is not None:                  # U7: before the snapshot below, so the run uses the new entries
        try:
            pin_rows, pin_review = _pin_unknown_host_keys(
                args, devices, credentials, editor=editor, run_id=run_id, out=out,
                connect=presented_connector or (lambda device, creds: ssh.connect_presented(device.address, creds,
                                                                                             method="any")))
        except ValueError:
            print(f"ERROR: invalid known_hosts: {args.known_hosts}", file=out)
            return EXIT_BAD_INPUT
    watched_inputs = [fleet_engine.LockedFile.read("known hosts", args.known_hosts)]
    if args.method == "scp":
        watched_inputs.append(server_watch)
    try:
        pins = ssh.HostPins.load(args.known_hosts)
    except ValueError:
        print(f"ERROR: invalid known_hosts: {args.known_hosts}", file=out)
        return EXIT_BAD_INPUT
    ops_arguments = dict(pins=pins, credentials=credentials, policy=policy, selected=selected,
                         run_id=run_id, switch_dir=args.local_dir, force_health=args.force,
                         management_line=Path(public).read_bytes().splitlines()[0] + b"\n",
                         method=args.method, scp_server=scp_server,
                         **({"http_origins": origins, "http_base": endpoints[0].origin}
                            if endpoints and args.method == "http" else {}))
    make_ops = ops_factory or ib.LiveOps
    ops = make_ops(**ops_arguments)
    password_check = None
    if password is not None:                # one check before the fan-out; v1 parity: three attempts
        for attempt in range(1, PASSWORD_ATTEMPTS + 1):
            host, verdict = _check_password(ops, devices, ssh)
            password_check = dict(host=host, result=verdict, attempts=attempt)
            if verdict != "PASSWORD_REJECTED":
                break
            if attempt == PASSWORD_ATTEMPTS:
                print(f"[AUTH] {host} rejected the switch password {attempt} times; nothing was changed.", file=out)
                return EXIT_BAD_INPUT
            print(f"[AUTH] {host} rejected the switch password before any write; nothing was changed. "
                  f"Attempt {attempt + 1}/{PASSWORD_ATTEMPTS}", file=out)
            credentials = ssh.Credentials(args.user, key, key_fingerprint, _ask("Switch password: ", password_reader))
            ops_arguments["credentials"] = credentials
            ops = make_ops(**ops_arguments)
        if verdict == "ACCEPTED":
            print(f"[AUTH] switch password accepted by {host} (password-only login, nothing written)", file=out)
        elif verdict == "NO_SWITCH_ANSWERED":
            print("[AUTH] no selected switch answered on TCP/22; the password was not checked "
                  "(the precheck reports the unreachable switches)", file=out)
        else:
            print(f"[AUTH] the password check on {host} was inconclusive ({verdict}); continuing, and a switch "
                  "that rejects the password holds the prechecks", file=out)
    run_dir = _run_directory(args, paths, run_id)
    evidence = fleet_engine.Evidence(run_dir)
    print(f"[RUN] evidence: {run_dir.resolve()}", file=out, flush=True)
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
        groups=groups, key_fingerprint=key_fingerprint, password_check=password_check,
        http=dict(configured=[endpoint.host for endpoint in endpoints], listed=listed,
                  switches={device.hostname: dict(address=services[device.address].address,
                                                  egress=services[device.address].device,
                                                  src=services[device.address].src,
                                                  reason=services[device.address].reason)
                            for device in devices} if services else {})))
    if pin_rows is not None:
        evidence.write("host-key-pins.json", pin_rows)
    options = fleet_engine.Options(
        run_id=run_id, selected=selected, upgrade=bool(args.upgrade),
        link=decision, groups=groups, skip_canary=args.skip_canary, check_workers=args.check_workers,
        upgrade_workers=args.upgrade_workers, in_flight=args.in_flight, probe_workers=args.probe_workers,
        relay_fanout=args.relay_fanout, relay_transfers=args.relay_transfers, method=args.method,
        progress_seconds=args.progress_seconds, password_given=password is not None,
        **({"timings": timings} if timings is not None else {}))
    engine = fleet_engine.Engine(devices, ib.IbFamily(policy, push=args.method == "push"), ops, options, evidence,
                                 out=out,
                                 blocked_inputs=snapshot.blocked_devices, service_issues=service_issues,
                                 locked_inputs=locked_inputs, watched_inputs=watched_inputs, review_inputs=pin_review,
            packages_ready=ops.bind_available_packages, routes_path=run_dir.parent / 'canary-routes.jsonl')
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
    print(fleet_engine.render_summary(report, management_key=str(public), user=args.user), file=out)
    unknown = sum(1 for row in report["devices"] if row["reason"] == "HOST_KEY_UNKNOWN")
    if unknown:                             # U7 (问题文件 :2366): the one line added to the summary
        print(f"{unknown} switch(es) HOST_KEY_UNKNOWN: --pin-unknown-host-keys pins them after the hostname and "
              "eth0 MAC check", file=out)
    print(f"evidence: {run_dir}", file=out)
    return fleet_engine.exit_code(report)


def threading_main():
    import threading
    return threading.current_thread() is threading.main_thread()


def main():
    import operator_identity
    argv = sys.argv[1:]
    # I-006 (v3.1.2 WP-10): before the runtime guard or any prompt, root re-runs as the operator (the owner of
    # the project directory); another account's run is refused.  No project (no --project, no pointer): unchanged.
    if not operator_identity.skips_identity(argv):
        project = parser().parse_args(argv).project
        if project is None:
            from project_pointer import ActiveProjectPointerError, active_project_dir
            try:
                project = active_project_dir(REPOSITORY)
            except ActiveProjectPointerError as error:
                print(f"ERROR: {error}", file=sys.stderr)
                return EXIT_BAD_INPUT
        if project is not None:
            identity = operator_identity.resolve_operator(project)
            if identity.refusal is not None:
                print("ERROR: " + identity.refusal, file=sys.stderr)
                return EXIT_BAD_INPUT
            if operator_identity.needs_reexec(identity):
                operator_identity.exec_as_operator(identity.operator, ENTRY, argv)
            print(identity.banner, file=sys.stderr)
    if _reexec_in_runtime_venv(argv) == "NO_CANDIDATE":
        return EXIT_BAD_INPUT
    if tuple(sys.argv[1:]) in (("--version",), ("--help",), ("-h",)):
        return run()
    guard = importlib.import_module("ib_bringup_runtime_guard")
    try:
        with guard._runtime_instance_guard():
            return run()
    except guard._InstanceGuardError as error:
        print(f"ERROR [{error.code}] {error}", file=sys.stderr)
        return EXIT_BUSY if error.code == "ALREADY_RUNNING" else EXIT_BAD_INPUT


if __name__ == "__main__":
    sys.exit(main())
