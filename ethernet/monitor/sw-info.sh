#!/bin/bash
# Unified switch info collector — auto-detects ETH (SN*) vs IB (Q*) via nv show platform.
# Output: ./monitor/<hostname>.info

BASEDIR=./monitor
HOSTNAME=$(hostname)
if [[ ! "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ ]]; then
    echo "unsafe local hostname; refusing info collection" >&2
    exit 1
fi
INFO_FILE="${BASEDIR}/${HOSTNAME}.info"
LOCK_DIR="${TMPDIR:-/tmp}/sw-info.lock"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    running_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if [[ "$running_pid" =~ ^[0-9]+$ ]] && kill -0 "$running_pid" 2>/dev/null; then
        echo "${HOSTNAME}: another sw-info.sh collection is still running (PID ${running_pid})" >&2
        exit 1
    fi
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    mkdir "$LOCK_DIR" 2>/dev/null || {
        echo "${HOSTNAME}: could not acquire info collection lock" >&2
        exit 1
    }
fi
printf '%s\n' "$$" > "$LOCK_DIR/pid"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sw-info.XXXXXX") || {
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    exit 1
}
OUT="${TMP_DIR}/${HOSTNAME}.info"

cleanup() {
    rm -f "$OUT" "$LOCK_DIR/pid"
    rmdir "$TMP_DIR" "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Detect switch type ────────────────────────────────────────────────────────
SYSTEM_TYPE=$(nv show platform 2>/dev/null \
    | awk '/system-type/ { print $NF; exit }')

case "${SYSTEM_TYPE}" in
    SN*)  SW_TYPE="ETH" ;;
    MSN*) SW_TYPE="ETH" ;;
    VX)   SW_TYPE="ETH" ;;
    Q*)   SW_TYPE="IB"  ;;
    MNV*|N*) SW_TYPE="NVLINK" ;;
    *)
        echo "${HOSTNAME}: unknown switch type '${SYSTEM_TYPE:-empty}', refusing to publish an info snapshot" >&2
        exit 1
        ;;
esac

# ── Command lists ─────────────────────────────────────────────────────────────
# Commands run on all switch types
COMMON_CMDS=(
    "nv show platform"
    "nv show platform inventory"
    "nv show platform firmware"
    "nv show platform environment temperature"
    "nv show platform transceiver detail"
    "nv show system image"
    "nv show system version"
    "nv show system health"
    "nv show interface"
    "nv config show"
    "timedatectl"
    "df -PT"
    "free -b"
    "top -bn2 -d 1"
    "uptime -p"
)

# ETH-only commands (Cumulus Linux / SN*)
ETH_CMDS=(
    "clagctl"
    "nv show evpn multihoming esi"
    "nv show vrf default router bgp neighbor"
)

# IB-only commands (NVOS / Q*)
IB_CMDS=(
   "nv show ib device"
)

# NV-only commands (NVOS / MNV*)
NV_CMDS=(
    "nv show nvlink device"
    "nv show nvlink port"
)

# ── Build final command list ──────────────────────────────────────────────────
CMD_LIST=("${COMMON_CMDS[@]}")
if [[ "$SW_TYPE" == "ETH" ]]; then
    CMD_LIST+=("${ETH_CMDS[@]}")
elif [[ "$SW_TYPE" == "IB" ]]; then
    CMD_LIST+=("${IB_CMDS[@]}")
elif [[ "$SW_TYPE" == "NVLINK" ]]; then
    CMD_LIST+=("${NV_CMDS[@]}")
fi

# ── Write header ──────────────────────────────────────────────────────────────
mkdir -p "$BASEDIR"
> "$OUT"
cat <<HEAD >> "$OUT"
====================================================
Device:       ${HOSTNAME}
Switch Type:  ${SW_TYPE} (${SYSTEM_TYPE:-unknown})
Collect Time: $(date '+%Y-%m-%d %H:%M:%S')
====================================================
HEAD

# ── Run commands ──────────────────────────────────────────────────────────────
for cmd in "${CMD_LIST[@]}"; do
    cat <<SEP >> "$OUT"

####################################################
# Execute Command: ${cmd}
####################################################
SEP
    # Commands are maintained by this script (not supplied by user input).
    # Execute them through a shell so arguments remain intact, while applying
    # the stable C locale outside the command string. Embedding ``LC_ALL=C``
    # in cmd and expanding ${cmd} makes bash treat it as an executable name.
    LC_ALL=C bash -c "${cmd}" >> "$OUT" 2>&1
done

cat <<FOOT >> "$OUT"

====================================================
# Collect complete
====================================================
FOOT

# Readers see the previous complete snapshot or the new complete snapshot;
# an interrupted command loop never leaves a partial *.info file behind.
mv "$OUT" "$INFO_FILE"
