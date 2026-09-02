#!/bin/bash
# Read-only MLNX-OS collection for an explicit, validated switch list.

set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SWITCHES_FILE="${BASE}/IB-switches-IP.log"
SHOW_OUTPUT="${BASE}/IB-SW-show.log"
ERROR_OUTPUT="${BASE}/error-show.log"
USERNAME="admin"
INSECURE_HOST_KEY=false

usage() {
    cat <<'EOF'
Usage: bash data-collect-IB.sh [OPTIONS]

Read-only collection of MLNX-OS state from a validated switch list.

Options:
  --switches FILE       One IPv4 address or DNS hostname per line
  --user USER           SSH user (default: admin)
  --output FILE         Collection output path
  --error-output FILE   Error log path
  --insecure-host-key   Disable host-key verification (explicit lab-only mode)
  -h, --help            Show this help and exit

Authentication uses an existing SSH key by default. To use a password, export
IB_SWITCH_PASSWORD; sshpass -e is used so the password is not placed in argv.
EOF
}

while (( $# )); do
    case "$1" in
        --switches) [[ $# -ge 2 ]] || { echo "--switches requires FILE" >&2; exit 2; }; SWITCHES_FILE=$2; shift 2 ;;
        --user) [[ $# -ge 2 ]] || { echo "--user requires USER" >&2; exit 2; }; USERNAME=$2; shift 2 ;;
        --output) [[ $# -ge 2 ]] || { echo "--output requires FILE" >&2; exit 2; }; SHOW_OUTPUT=$2; shift 2 ;;
        --error-output) [[ $# -ge 2 ]] || { echo "--error-output requires FILE" >&2; exit 2; }; ERROR_OUTPUT=$2; shift 2 ;;
        --insecure-host-key) INSECURE_HOST_KEY=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$USERNAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid SSH user" >&2; exit 2; }
[[ -f "$SWITCHES_FILE" && ! -L "$SWITCHES_FILE" ]] || {
    echo "Switch list is missing or not a regular non-symlink file: $SWITCHES_FILE" >&2
    exit 2
}

load_targets() {
    python3 - "$SWITCHES_FILE" <<'PY'
import ipaddress
import re
import sys

valid_hostname = re.compile(
    r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
seen = set()
bad = False
for number, raw in enumerate(open(sys.argv[1], encoding="utf-8-sig"), 1):
    value = raw.split("#", 1)[0].strip()
    if not value:
        continue
    try:
        normalized = str(ipaddress.ip_address(value))
    except ValueError:
        normalized = value.rstrip(".")
        if not valid_hostname.fullmatch(normalized):
            print(f"ERROR: {sys.argv[1]}:{number}: invalid switch target {value!r}", file=sys.stderr)
            bad = True
            continue
    if normalized not in seen:
        seen.add(normalized)
        print(normalized)
if bad or not seen:
    raise SystemExit(1)
PY
}

TARGET_TEXT=$(load_targets) || exit 2
TARGETS=()
while IFS= read -r target; do
    [[ -n "$target" ]] && TARGETS+=("$target")
done <<< "$TARGET_TEXT"

SSH_OPTIONS=(
    -o ConnectTimeout=10 -o ConnectionAttempts=2 -o LogLevel=ERROR
)
if $INSECURE_HOST_KEY; then
    SSH_OPTIONS+=( -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null )
else
    SSH_OPTIONS+=( -o StrictHostKeyChecking=accept-new )
fi
SSH_PREFIX=()
if [[ -n "${IB_SWITCH_PASSWORD:-}" ]]; then
    command -v sshpass >/dev/null 2>&1 || {
        echo "IB_SWITCH_PASSWORD is set but sshpass is not installed" >&2
        exit 2
    }
    export SSHPASS="$IB_SWITCH_PASSWORD"
    SSH_PREFIX=(sshpass -e)
    SSH_OPTIONS+=( -o PreferredAuthentications=publickey,keyboard-interactive,password )
else
    SSH_OPTIONS+=( -o BatchMode=yes -o PasswordAuthentication=no )
fi

umask 077
[[ ! -L "$SHOW_OUTPUT" && ! -L "$ERROR_OUTPUT" ]] || {
    echo "Refusing symlink output path" >&2
    exit 2
}
: > "$SHOW_OUTPUT"
: > "$ERROR_OUTPUT"
commands=(
    "show images" "show inventory" "show module" "show power"
    "show temperature" "show fan" "show version" "show cpld"
    "show interfaces ib status" "show running-config"
)
failed=0
for target in "${TARGETS[@]}"; do
    printf 'Collecting MLNX-OS info of switch %s ...\n' "$target" >> "$SHOW_OUTPUT"
    for command_text in "${commands[@]}"; do
        printf '# %s\n' "$command_text" >> "$SHOW_OUTPUT"
        if ! "${SSH_PREFIX[@]}" ssh "${SSH_OPTIONS[@]}" \
            "${USERNAME}@${target}" cli "enable" "$command_text" \
            >> "$SHOW_OUTPUT" 2>> "$ERROR_OUTPUT"
        then
            printf 'ERROR: %s: command failed: %s\n' "$target" "$command_text" \
                >> "$ERROR_OUTPUT"
            failed=1
        fi
    done
done
unset SSHPASS IB_SWITCH_PASSWORD
exit "$failed"
