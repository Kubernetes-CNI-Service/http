#!/bin/bash
# UFM appliance info collector. cron.sh copies it to the UFM and runs it there as root,
# exactly like sw-info.sh on a switch (infiniband/monitor/UFM-MONITOR.md).
# Read-only, except that it loads the MST driver (`mst start`) when its /dev/mst devices are missing, so
# the HCA temperatures can be read (owner 2026-10-23). Output: ./monitor/<hostname>.info, in the same
# sectioned layout as sw-info.sh.
#   ufm-info.sh        this node's Switch Status snapshot (run on every UFM)
#   ufm-info.sh --ha   the HA state, run only on the primary through the VIP (owner 2026-10-21):
#                      ./monitor/<hostname>.ha; it runs beside the node snapshot, with its own lock

MODE=node
case "${1:-}" in
    "") ;;
    --ha) MODE=ha ;;
    *) echo "usage: ufm-info.sh [--ha]" >&2; exit 2 ;;
esac

BASEDIR=./monitor
HOSTNAME=$(hostname)
if [[ ! "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ ]]; then
    echo "unsafe local hostname; refusing info collection" >&2
    exit 1
fi
if [[ "$MODE" == ha ]]; then
    INFO_FILE="${BASEDIR}/${HOSTNAME}.ha"
    LOCK_DIR="${TMPDIR:-/tmp}/ufm-info-ha.lock"
else
    INFO_FILE="${BASEDIR}/${HOSTNAME}.info"
    LOCK_DIR="${TMPDIR:-/tmp}/ufm-info.lock"
fi
IB_SYSFS="${UFM_INFO_IB_SYSFS:-/sys/class/infiniband}"

# A lock is stale only when its process is gone, or when it has had no pid for over a minute: right
# after mkdir the holder has not written its pid yet (owner 2026-10-22).
lock_age() {
    local modified
    modified=$(stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null) || modified=0
    echo $(( $(date +%s) - modified ))
}
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    running_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if { [[ "$running_pid" =~ ^[0-9]+$ ]] && kill -0 "$running_pid" 2>/dev/null; } \
        || { [[ -z "$running_pid" ]] && (( $(lock_age "$LOCK_DIR") < 60 )); }; then
        echo "${HOSTNAME}: another ufm-info.sh collection is still running (PID ${running_pid:-starting})" >&2
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

# The working copy lives next to the final file, so the closing mv is a rename on one
# filesystem; cron.sh only fetches *.info, never this hidden directory.
mkdir -p "$BASEDIR" || exit 1
TMP_DIR=$(mktemp -d "${BASEDIR}/.ufm-info.XXXXXX") || {
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    exit 1
}
OUT="${TMP_DIR}/${INFO_FILE##*/}"

cleanup() {
    rm -f "$OUT" "$LOCK_DIR/pid"
    rmdir "$TMP_DIR" "$LOCK_DIR" 2>/dev/null || true
    rmdir "$BASEDIR" 2>/dev/null || true   # only removed when empty: nothing was published
}
trap cleanup EXIT
trap 'exit 130' INT    # end here: an interrupted snapshot is never published
trap 'exit 143' TERM

# ── HCA temperature: one mget_temp per real mlx5 device ──────────────────────
# smi* are the management views of the same HCAs (same GUIDs); reading them
# again would only duplicate the temperature.
HCA_TEMP_CMDS=()
for device in "$IB_SYSFS"/mlx5_*; do
    [[ -e "$device" ]] || continue
    name=${device##*/}
    [[ "$name" =~ ^mlx5_[0-9]+$ ]] || continue
    HCA_TEMP_CMDS+=("mget_temp -d ${name}")
done
# mget_temp needs the MST devices (owner 2026-10-23): on the standby UFM `mst status -v` listed no
# /dev/mst device until `mst start` ran on that boot, and every mget_temp failed with "mopen: No such
# file or directory". When they are missing, `mst start` runs once, recorded in the snapshot, right
# before the temperatures.
MST_CMDS=()
if (( ${#HCA_TEMP_CMDS[@]} )) && command -v mst >/dev/null 2>&1 \
        && ! LC_ALL=C mst status -v 2>/dev/null | grep -q '/dev/mst/'; then
    MST_CMDS=("mst start")
fi

# ── Command list: the Switch Status columns (verified on a UFM, 2026-10-21) ──
CMD_LIST=(
    "hostname"
    "dmidecode -s system-serial-number"
    "dmidecode -s system-manufacturer"
    "dmidecode -s system-product-name"
    "dmidecode -s bios-version"
    "cat /etc/ufm-release"
    "cat /etc/os-release"
    "uname -r"
    "lsblk -d -o NAME,MODEL,SERIAL,REV,SIZE,TYPE"
    "ibstat"
    "${MST_CMDS[@]}"
    "${HCA_TEMP_CMDS[@]}"
    "ipmitool sdr type Temperature"
    "ipmitool sdr type 'Power Supply'"
    "ipmitool sdr type Fan"
    "top -bn2 -d 1"
    "df -PT"
    "free -b"
    "timedatectl"
    "ip -br link"
    "ip -br addr"
    "systemctl is-active ufm-enterprise"
    "systemctl list-units 'ufm*' --no-pager"
    "uptime -p"
)
SERVER_TYPE=UFM
if [[ "$MODE" == ha ]]; then
    # The primary sees both nodes: roles, resources, DRBD on both sides. ip -br link carries the
    # management MAC that cron.sh uses to tell which UFM answered the VIP.
    CMD_LIST=(
        "hostname"
        "ip -br link"
        "ufm_ha_cluster status"
        "ufm_enterprise_sanity.sh"
    )
    SERVER_TYPE=UFM-HA
fi

# A hung BMC or cluster query must not hold the whole snapshot.
LIMIT=()
if command -v timeout >/dev/null 2>&1; then
    LIMIT=(timeout 60)
fi

# ── Write header ──────────────────────────────────────────────────────────────
> "$OUT"
cat <<HEAD >> "$OUT"
====================================================
Device:       ${HOSTNAME}
Server Type:  ${SERVER_TYPE}
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
    LC_ALL=C "${LIMIT[@]}" bash -c "${cmd}" >> "$OUT" 2>&1
done

cat <<FOOT >> "$OUT"

====================================================
# Collect complete
====================================================
FOOT

# Readers see the previous complete snapshot or the new complete snapshot;
# an interrupted command loop never leaves a partial *.info file behind.
mv "$OUT" "$INFO_FILE"
