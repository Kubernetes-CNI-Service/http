#!/bin/bash
# Guarded MLNX-OS image/CPLD upgrade for an explicit, validated switch list.

set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SWITCHES_FILE="${BASE}/IB-switches-IP.log"
IMAGE="${BASE}/image-X86_64-3.12.2002.img"
CPLD_TOOL="${BASE}/updateswitchcpld"
LOG_FILE="${BASE}/mlnxos-upgrade.log"
USERNAME="admin"
WAIT_SECONDS=360
DRY_RUN=false
CONFIRMED=false
INSECURE_HOST_KEY=false

usage() {
    cat <<'EOF'
Usage: bash OS-CPLD-upgrade.sh (--dry-run | --yes) [OPTIONS]

Options:
  --dry-run             Validate and print the plan; never contact a switch
  --yes                 Explicitly authorize image install, reload and CPLD update
  --switches FILE       One IPv4 address or DNS hostname per line
  --image FILE          MLNX-OS image file
  --cpld-tool FILE      Executable updateswitchcpld path
  --user USER           Switch user (default: admin)
  --wait SECONDS        Reboot wait before CPLD (default: 360)
  --log FILE            Operation log
  --insecure-host-key   Disable host-key verification (explicit lab-only mode)
  -h, --help            Show this help and exit

Real execution requires IB_SWITCH_PASSWORD in the environment. sshpass -e keeps
it out of SSH/SCP argv; the vendor CPLD tool still receives it through its
required -p option, so run this only on a trusted management host.
EOF
}

while (( $# )); do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --yes) CONFIRMED=true; shift ;;
        --switches) [[ $# -ge 2 ]] || { echo "--switches requires FILE" >&2; exit 2; }; SWITCHES_FILE=$2; shift 2 ;;
        --image) [[ $# -ge 2 ]] || { echo "--image requires FILE" >&2; exit 2; }; IMAGE=$2; shift 2 ;;
        --cpld-tool) [[ $# -ge 2 ]] || { echo "--cpld-tool requires FILE" >&2; exit 2; }; CPLD_TOOL=$2; shift 2 ;;
        --user) [[ $# -ge 2 ]] || { echo "--user requires USER" >&2; exit 2; }; USERNAME=$2; shift 2 ;;
        --wait) [[ $# -ge 2 ]] || { echo "--wait requires SECONDS" >&2; exit 2; }; WAIT_SECONDS=$2; shift 2 ;;
        --log) [[ $# -ge 2 ]] || { echo "--log requires FILE" >&2; exit 2; }; LOG_FILE=$2; shift 2 ;;
        --insecure-host-key) INSECURE_HOST_KEY=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if ! $DRY_RUN && ! $CONFIRMED; then
    echo "Refusing destructive upgrade without --yes; use --dry-run first" >&2
    exit 2
fi
[[ "$USERNAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid switch user" >&2; exit 2; }
[[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]] || { echo "Invalid --wait value" >&2; exit 2; }
[[ -f "$SWITCHES_FILE" && ! -L "$SWITCHES_FILE" ]] || {
    echo "Switch list is missing or not a regular non-symlink file: $SWITCHES_FILE" >&2
    exit 2
}
[[ -f "$IMAGE" && ! -L "$IMAGE" ]] || { echo "Image is missing or unsafe: $IMAGE" >&2; exit 2; }
IMAGE_NAME=$(basename "$IMAGE")
[[ "$IMAGE_NAME" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Unsafe image filename" >&2; exit 2; }
if ! $DRY_RUN; then
    [[ -x "$CPLD_TOOL" && ! -L "$CPLD_TOOL" ]] || {
        echo "CPLD tool is missing, non-executable or a symlink: $CPLD_TOOL" >&2
        exit 2
    }
    [[ -n "${IB_SWITCH_PASSWORD:-}" ]] || {
        echo "IB_SWITCH_PASSWORD must be exported for real execution" >&2
        exit 2
    }
    command -v sshpass >/dev/null 2>&1 || { echo "sshpass is required" >&2; exit 2; }
fi

load_targets() {
    python3 - "$SWITCHES_FILE" <<'PY'
import ipaddress
import re
import sys
valid_hostname = re.compile(r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")
seen = set(); bad = False
for number, raw in enumerate(open(sys.argv[1], encoding="utf-8-sig"), 1):
    value = raw.split("#", 1)[0].strip()
    if not value: continue
    try: normalized = str(ipaddress.ip_address(value))
    except ValueError:
        normalized = value.rstrip(".")
        if not valid_hostname.fullmatch(normalized):
            print(f"ERROR: {sys.argv[1]}:{number}: invalid target {value!r}", file=sys.stderr)
            bad = True; continue
    if normalized not in seen: seen.add(normalized); print(normalized)
if bad or not seen: raise SystemExit(1)
PY
}
TARGET_TEXT=$(load_targets) || exit 2
TARGETS=()
while IFS= read -r target; do
    [[ -n "$target" ]] && TARGETS+=("$target")
done <<< "$TARGET_TEXT"

if $DRY_RUN; then
    printf 'DRY RUN: image=%s cpld_tool=%s wait=%ss\n' "$IMAGE" "$CPLD_TOOL" "$WAIT_SECONDS"
    printf '  target=%s\n' "${TARGETS[@]}"
    exit 0
fi

SSH_OPTIONS=( -o ConnectTimeout=10 -o ConnectionAttempts=2 -o LogLevel=ERROR )
if $INSECURE_HOST_KEY; then
    SSH_OPTIONS+=( -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null )
else
    SSH_OPTIONS+=( -o StrictHostKeyChecking=accept-new )
fi
export SSHPASS="$IB_SWITCH_PASSWORD"
umask 077
[[ ! -L "$LOG_FILE" ]] || {
    echo "Refusing symlink log path: $LOG_FILE" >&2
    exit 2
}
: > "$LOG_FILE"
reloaded=()
failed=0
for target in "${TARGETS[@]}"; do
    printf 'Upgrading MLNX-OS on %s ...\n' "$target" | tee -a "$LOG_FILE"
    if ! sshpass -e scp "${SSH_OPTIONS[@]}" "$IMAGE" \
        "${USERNAME}@${target}:/var/opt/tms/images/${IMAGE_NAME}" >> "$LOG_FILE" 2>&1; then
        printf 'ERROR: %s image upload failed\n' "$target" >> "$LOG_FILE"; failed=1; continue
    fi
    if ! sshpass -e ssh "${SSH_OPTIONS[@]}" "${USERNAME}@${target}" cli \
        "enable" "configure terminal" "no cli default prefix-modes enable" \
        "image install ${IMAGE_NAME}" "image boot next" "configuration write" \
        "reload" >> "$LOG_FILE" 2>&1; then
        printf 'ERROR: %s image install/reload failed\n' "$target" >> "$LOG_FILE"; failed=1; continue
    fi
    reloaded+=("$target")
done

if (( ${#reloaded[@]} > 0 && WAIT_SECONDS > 0 )); then
    sleep "$WAIT_SECONDS"
fi
for target in "${reloaded[@]}"; do
    if ! printf 'y\n' | ip vrf exec default "$CPLD_TOOL" --managed \
        -t "$target" -u "$USERNAME" -p "$IB_SWITCH_PASSWORD" \
        --os mlnx-os --verbose --debug >> "$LOG_FILE" 2>&1; then
        printf 'ERROR: %s CPLD update failed\n' "$target" >> "$LOG_FILE"
        failed=1
    fi
done
unset SSHPASS IB_SWITCH_PASSWORD
exit "$failed"
