#!/usr/bin/env python3
"""Collect read-only information from switches with the items in the .sh file of the same name.

Install in tools/ next to its .sh file of the same name and link the .py (same name)
wherever operators run it.  Run through a link, it uses that directory:

  - the inventory CSV in the current directory (ib.csv / eth.csv / nvsw.csv by the family of
    the link directory, else 02-devices_config.csv);
  - results under <link dir>/99-output-info, a link to
    DAY0-Prepare/activate-project/99-output-info that is created on first use.

Selection: items are `group` or `group.item` (see --list); --commands "CMD" (repeatable) runs a
command line of your own on every selected device as an extra item (cmd.1, cmd.2, ...), with or
without items.  Devices default to the family's types; --type, --devices (hostname glob) or --all
choose others; --devices takes the same patterns as the other scripts (comma list of names,
`*`, digit ranges such as leaf[001-039], letter ranges such as pod[a-d]).

Login: keys first (BatchMode).  For every device type that had key failures the password is
asked once and those devices are retried; devices of one type share the password.

Each run writes, under 99-output-info/:
  info-<time>-<selection>/<host>.out   every selected item's output for that switch
  info-<time>-<selection>.csv          one row per switch and item (also printed at the end)
  info-<time>-<selection>.log          commands, timings and ssh errors

A helper script (owner 2026-11-11 rule, condition 1 narrowed 2026-11-21): nothing in the
repository calls or imports it, it imports only stdlib-only library modules under tools/,
--help/--list touch nothing, and nothing it writes is read by another script.
"""

import argparse
import csv
import getpass
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

# --devices uses the selector every other script uses (M4, R-003), imported rather than copied: one
# implementation, covered by its own tests.  Helpers may import stdlib-only library modules under
# tools/ (owner 2026-11-21, R-020 condition 1 narrowed); nothing in the repository imports this helper.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.hostname_ranges import SelectorError, parse_selector, select  # noqa: E402

FAMILIES = {
    "eth": {"dir": "ethernet", "csv": "eth.csv", "types": ("eth", "eth_spx", "spx", "air"),
            "user": "cumulus"},
    "ib": {"dir": "infiniband", "csv": "ib.csv", "types": ("ib",), "user": "admin"},
    "nvl": {"dir": "nvlink", "csv": "nvsw.csv", "types": ("nvl",), "user": "admin"},
}
TYPE_FAMILY = {t: f for f, spec in FAMILIES.items() for t in spec["types"]}
OTHER_USER = "root"                              # non-switch rows (server_ufm), as cron.sh logs in to UFM
OUTPUT_LINK = "99-output-info"
OUTPUT_TARGET = Path("DAY0-Prepare/activate-project/99-output-info")
COMMON_OPTIONS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=2"]
KEY_OPTIONS = ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
PASSWORD_OPTIONS = ["-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1",
                    "-o", "PreferredAuthentications=keyboard-interactive,password"]
AUTH_FAILURE = re.compile(r"permission denied|authentication failed|too many authentication", re.I)
NAME = re.compile(r"[A-Za-z0-9_-]+")
MAC_NA = frozenset({"", "na", "n/a", "none", "null", "tbd", "-"})


# ------------------------------------------------------------------ items file
def load_items(path):
    """[(group, group_desc, item, item_desc, meta, body)] from the .sh in file order."""
    groups, items, current, group = {}, [], None, None
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip()
        head = re.match(r"#@(group|item|family|pick|compare)\b\s*(.*)$", line)
        if head:
            kind, rest = head.groups()
            if kind in ("group", "item"):
                name, _, desc = rest.partition(" ")
                if not NAME.fullmatch(name):
                    raise SystemExit(f"ERROR: {path}:{number}: bad {kind} name {name!r}")
                if kind == "group":
                    group, current = name, None
                    groups[name] = desc.strip()
                else:
                    if group is None:
                        raise SystemExit(f"ERROR: {path}:{number}: #@item before any #@group")
                    if any(i["group"] == group and i["item"] == name for i in items):
                        raise SystemExit(f"ERROR: {path}:{number}: duplicate item {group}.{name}")
                    current = {"group": group, "item": name, "desc": desc.strip(), "family": None,
                               "pick": None, "compare": None, "body": []}
                    items.append(current)
                continue
            if current is None:
                raise SystemExit(f"ERROR: {path}:{number}: #@{kind} outside an item")
            if kind == "family":
                current["family"] = {f.strip() for f in rest.split(",") if f.strip()}
            elif kind == "pick":
                current["pick"] = re.compile(rest.strip(), re.M)
            else:
                words = rest.split()
                if len(words) != 2 or words[1] not in ("mac", "text"):
                    raise SystemExit(f"ERROR: {path}:{number}: #@compare <column> <mac|text>")
                current["compare"] = (words[0].lower(), words[1])
            continue
        if current is not None:
            current["body"].append(raw)
    for item in items:
        while item["body"] and not item["body"][-1].strip():
            item["body"].pop()
        if not any(line.strip() and not line.lstrip().startswith("#") for line in item["body"]):
            raise SystemExit(f"ERROR: {path}: item {item['group']}.{item['item']} has no commands")
    return groups, items


def select_items(groups, items, selection):
    chosen = []
    for token in (t.strip() for t in selection.split(",") if t.strip()):
        group, _, name = token.partition(".")
        picked = [i for i in items if i["group"] == group and (not name or i["item"] == name)]
        if not picked:
            raise SystemExit(f"ERROR: unknown item {token!r}; see --list")
        chosen += [i for i in picked if i not in chosen]
    return chosen


# ------------------------------------------------------------------ inventory
def entry_context():
    """(family or None, directory of the link that was run)."""
    entry = Path(os.path.abspath(sys.argv[0]))
    parts = entry.parent.parts
    for family, spec in FAMILIES.items():
        if spec["dir"] in parts:
            return family, entry.parent
    return None, entry.parent


def read_inventory(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise SystemExit(f"ERROR: {path} is empty")
    column = {}
    for index, name in enumerate(c.strip().lower() for c in rows[0]):
        column.setdefault(name, index)
    for required in ("hostname", "type"):
        if required not in column:
            raise SystemExit(f"ERROR: {path} has no '{required}' column")
    devices, seen = [], set()
    for row in rows[1:]:
        record = {name: (row[i].strip() if i < len(row) else "") for name, i in column.items()}
        host = record["hostname"]
        if not host or host.startswith("#") or host.casefold() in seen:
            continue
        seen.add(host.casefold())
        record["type"] = record["type"].lower()
        devices.append(record)
    return devices


def choose_devices(devices, args, family, selector):
    if args.all:
        chosen = devices
    else:
        types = ({t.strip().lower() for t in args.type.split(",") if t.strip()} if args.type
                 else set(FAMILIES[family]["types"]) if family else None)
        chosen = [d for d in devices if types is None or d["type"] in types]
    if selector is not None:
        picked = set(select(selector, [d["hostname"] for d in chosen]))
        chosen = [d for d in chosen if d["hostname"] in picked]
    return chosen


# ------------------------------------------------------------------ output place
def output_root(entry_dir):
    """<entry>/99-output-info, created on first use as a link to the active project's directory."""
    link = entry_dir / OUTPUT_LINK
    http_root = Path(__file__).resolve().parent.parent              # tools/ -> repository root
    target = http_root / OUTPUT_TARGET
    if not target.parent.exists():
        raise SystemExit(f"ERROR: {target.parent} does not exist (no active project?)")
    # Results live in the project: whoever owns it must create them, or a sudo run leaves root-owned
    # directories that the owner's later runs cannot write (and root has other SSH keys anyway).
    owner = target.parent.resolve().stat().st_uid
    if os.geteuid() != owner:
        raise SystemExit(f"ERROR: run as the owner of {target.parent} (uid {owner}), not uid {os.geteuid()}; "
                         "do not use sudo")
    if not link.exists() and not link.is_symlink():
        link.symlink_to(os.path.relpath(target, entry_dir))
    if link.is_symlink() and not link.exists():                     # new project: its directory is missing
        target.mkdir()
    if not link.is_dir():
        raise SystemExit(f"ERROR: {link} is not a usable directory")
    return link


# ------------------------------------------------------------------ remote run
def build_script(items, family, token):
    """One bash script: each applicable item between markers carrying its exit status."""
    parts = ["exec 2>&1", "export LC_ALL=C"]                 # same locale as sw-info.sh
    for item in items:
        key = f"{item['group']}.{item['item']}"
        if item["family"] and family not in item["family"]:
            parts.append(f"echo '{token} SKIP {key}'")
            continue
        parts += [f"echo '{token} BEGIN {key}'", "(", *item["body"], ")",
                  f"echo \"{token} END {key} $?\""]
    return "\n".join(parts) + "\n"


def split_output(text, token):
    sections, current, lines = {}, None, []
    for line in text.splitlines():
        if line.startswith(token + " "):
            word = line.split()
            if word[1] == "SKIP":
                sections[word[2]] = ("SKIP", "")
            elif word[1] == "BEGIN":
                current, lines = word[2], []
            elif word[1] == "END" and current == word[2]:
                sections[current] = (word[3] if len(word) > 3 else "?", "\n".join(lines))
                current = None
            continue
        if current is not None:
            lines.append(line)
    if current is not None:                      # cut off mid-item (timeout / disconnect)
        sections[current] = ("CUT", "\n".join(lines))
    return sections


def run_device(device, items, args, password, log):
    family = TYPE_FAMILY.get(device["type"])     # None for non-switch rows such as server_ufm
    target = device.get("eth0_ip") or device["hostname"]
    user = args.user or (FAMILIES[family]["user"] if family else OTHER_USER)
    token = "@@INFO-" + secrets.token_hex(6)
    script = build_script(items, family, token)
    command = [args.ssh, *COMMON_OPTIONS, *(PASSWORD_OPTIONS if password else KEY_OPTIONS),
               f"{user}@{target}", "bash -s"]
    environment, askpass_dir = None, None
    if password:
        askpass_dir = tempfile.mkdtemp(prefix="info-collect-")
        os.chmod(askpass_dir, stat.S_IRWXU)
        helper = Path(askpass_dir) / "askpass"
        helper.write_text('#!/bin/sh\nprintf "%s\\n" "$INFO_COLLECT_PASSWORD"\n', encoding="utf-8")
        os.chmod(helper, stat.S_IRWXU)
        environment = dict(os.environ, SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force",
                           DISPLAY=os.environ.get("DISPLAY", ":0"), INFO_COLLECT_PASSWORD=password)
    started = time.monotonic()
    try:
        done = subprocess.run(command, input=script, capture_output=True, text=True,
                              timeout=args.timeout, env=environment)
        rc, stdout, stderr = done.returncode, done.stdout, done.stderr
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        rc, stderr = "timeout", f"timeout after {args.timeout}s"
    finally:
        if askpass_dir:
            for child in Path(askpass_dir).iterdir():
                child.unlink()
            os.rmdir(askpass_dir)
    elapsed = time.monotonic() - started
    log(f"[{device['hostname']}] {user}@{target} {'password' if password else 'key'} rc={rc} {elapsed:.1f}s")
    for line in (stderr or "").strip().splitlines():
        log(f"[{device['hostname']}]   ssh: {line}")
    sections = split_output(stdout or "", token)
    auth_failed = rc == 255 and not sections and bool(AUTH_FAILURE.search(stderr or ""))
    return {"device": device, "target": target, "rc": rc, "sections": sections,
            "error": ((stderr or "").strip().splitlines() or [f"rc {rc}"])[-1] if not sections else "",
            "auth_failed": auth_failed, "password": bool(password)}


# ------------------------------------------------------------------ summary
def normalize_mac(value):
    text = (value or "").strip()
    if text.casefold() in MAC_NA:
        return ""
    digits = re.sub(r"[.:-]", "", text)
    if not re.fullmatch(r"[0-9A-Fa-f]{12}", digits):
        return None
    digits = digits.lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def pick_value(item, text):
    if item["pick"]:
        match = item["pick"].search(text)
        if not match:
            return ""
        return (match.group(1) if match.groups() else match.group(0)).strip()
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def summary_rows(result, items):
    device = result["device"]
    rows = []
    for item in items:
        key = f"{item['group']}.{item['item']}"
        row = {"hostname": device["hostname"], "type": device["type"], "target": result["target"],
               "item": key, "rc": "", "status": "", "value": "", "expected": "", "compare": "", "detail": ""}
        if key not in result["sections"]:
            row.update(status="FAILED", detail=result["error"] or "no output for this item")
        else:
            rc, text = result["sections"][key]
            if rc == "SKIP":
                row.update(status="SKIPPED", detail=f"not for type {device['type']}")
            else:
                row.update(rc=rc, status="OK" if rc == "0" else ("CUT" if rc == "CUT" else "RC_NONZERO"),
                           value=pick_value(item, text))
                if item["compare"]:
                    column, how = item["compare"]
                    expected = device.get(column, "")
                    row["expected"] = expected
                    if how == "mac":
                        want, got = normalize_mac(expected), normalize_mac(row["value"])
                        row["compare"] = ("CSV_EMPTY" if want == "" else "CSV_INVALID" if want is None
                                          else "MATCH" if want == got else "MISMATCH")
                    else:
                        row["compare"] = ("CSV_EMPTY" if not expected else
                                          "MATCH" if expected.strip() == row["value"] else "MISMATCH")
        rows.append(row)
    return rows


def write_host_file(path, result, items):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(f"# {result['device']['hostname']} ({result['target']}) "
                     f"login={'password' if result['password'] else 'key'} rc={result['rc']}\n")
        for item in items:
            key = f"{item['group']}.{item['item']}"
            rc, text = result["sections"].get(key, ("FAILED", result["error"]))
            handle.write(f"\n===== {key}  [{item['desc']}]  rc={rc} =====\n{text}\n")


# ------------------------------------------------------------------ main
def main():
    family, entry_dir = entry_context()
    items_file = Path(__file__).resolve().with_suffix(".sh")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__.split("\n\n", 1)[1])
    parser.add_argument("selection", nargs="?", help="comma-separated group or group.item (see --list)")
    parser.add_argument("--list", action="store_true", help="list groups and items, then exit")
    parser.add_argument("--commands", action="append", metavar="CMD",
                        help="run this command line on each device as item cmd.N (repeatable)")
    parser.add_argument("--csv", help="inventory CSV (default: the family CSV in the current directory)")
    parser.add_argument("--type", help="comma-separated CSV types (default: the family's types)")
    parser.add_argument("--devices", help="devices by name, * and [start-end] ranges, as in the other scripts")
    parser.add_argument("--all", action="store_true", help="every device in the CSV")
    parser.add_argument("--user", help="SSH user (default: cumulus for eth, admin for ib/nvl, root for other types)")
    parser.add_argument("--jobs", type=int, default=16, help="parallel logins (default: 16)")
    parser.add_argument("--timeout", type=int, default=120, help="seconds per device (default: 120)")
    parser.add_argument("--quiet", action="store_true", help="do not print the summary table")
    parser.add_argument("--items", default=str(items_file), help=argparse.SUPPRESS)
    parser.add_argument("--ssh", default="ssh", help=argparse.SUPPRESS)
    args = parser.parse_args()

    try:
        selector = parse_selector(args.devices) if args.devices is not None else None  # '' is an error, as in M4
    except SelectorError as exc:
        parser.error(str(exc))
    groups, items = load_items(Path(args.items))
    if args.list:
        for group, desc in groups.items():
            print(f"{group:12} {desc}")
            for item in (i for i in items if i["group"] == group):
                fam = ",".join(sorted(item["family"])) if item["family"] else "all"
                print(f"  {group + '.' + item['item']:24} [{fam:6}] {item['desc']}")
        return 0
    if not args.selection and not args.commands:
        parser.error("give a selection such as identity or version.ssd (see --list), or --commands")
    chosen = select_items(groups, items, args.selection) if args.selection else []
    for number, command in enumerate(args.commands or [], 1):
        if not command.strip():
            parser.error("--commands needs a non-empty command")
        chosen.append({"group": "cmd", "item": str(number), "desc": command, "family": None,
                       "pick": None, "compare": None, "body": [command]})
    selection = ",".join(filter(None, [args.selection, "cmd" if args.commands else ""]))

    csv_path = Path(args.csv) if args.csv else Path.cwd() / (FAMILIES[family]["csv"] if family else "02-devices_config.csv")
    if not csv_path.is_file() and not args.csv:
        csv_path = Path.cwd() / "02-devices_config.csv"
    if not csv_path.is_file():
        raise SystemExit(f"ERROR: inventory not found: {csv_path} (use --csv)")
    try:
        devices = choose_devices(read_inventory(csv_path), args, family, selector)
    except SelectorError as exc:
        parser.error(str(exc))
    if not devices:
        raise SystemExit(f"ERROR: no devices selected from {csv_path}")

    root = output_root(entry_dir)
    label = re.sub(r"[^A-Za-z0-9_.+-]", "_", selection.replace(",", "+"))[:60]
    stem = base = f"info-{datetime.now():%Y%m%d-%H%M%S}-{label}"
    number = 1
    while (root / stem).exists():                 # the same selection twice within one second
        number += 1
        stem = f"{base}-{number}"
    host_dir = root / stem
    host_dir.mkdir()
    log_lines = []

    def log(message):
        log_lines.append(f"{datetime.now():%H:%M:%S} {message}")

    log(f"items file {Path(args.items).resolve()}; selection {selection}; csv {csv_path}; "
        f"{len(devices)} device(s)")
    for item in chosen:
        log(f"item {item['group']}.{item['item']}: " + " | ".join(l for l in item["body"] if l.strip()))
    print(f"{len(devices)} device(s), {len(chosen)} item(s): {selection} → {host_dir}", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda d: run_device(d, chosen, args, None, log), devices))
    failed_types = sorted({r["device"]["type"] for r in results if r["auth_failed"]})
    for device_type in failed_types:
        retry = [i for i, r in enumerate(results) if r["auth_failed"] and r["device"]["type"] == device_type]
        password = getpass.getpass(f"Password for type {device_type} ({len(retry)} device(s) refused the key): ")
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            again = list(pool.map(lambda i: run_device(results[i]["device"], chosen, args, password, log), retry))
        for index, result in zip(retry, again):
            results[index] = result

    rows = []
    for result in results:
        write_host_file(host_dir / f"{result['device']['hostname']}.out", result, chosen)
        rows += summary_rows(result, chosen)
    fields = ["hostname", "type", "target", "item", "rc", "status", "value", "expected", "compare", "detail"]
    with open(root / f"{stem}.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    (root / f"{stem}.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    if not args.quiet:
        width = max(len(r["hostname"]) for r in rows)
        iwidth = max(len(r["item"]) for r in rows)
        for r in rows:
            extra = f"  {r['compare']}" if r["compare"] else ""
            print(f"{r['hostname']:<{width}}  {r['item']:<{iwidth}}  {r['status']:10}  {r['value']}{extra}"
                  + (f"  ({r['detail']})" if r["detail"] else ""))
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    print(f"results: {host_dir}/  summary: {root / (stem + '.csv')}  log: {root / (stem + '.log')}")
    return 0 if not any(r["status"] in ("FAILED", "CUT") for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
