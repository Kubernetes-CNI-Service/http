#!/bin/bash
# UFM fabric collector: ibdiagnet (default) or iblinkinfo. cron.sh copies it to the UFM that holds the
# VIP and runs it there as root, alongside sw-link.sh on the switches (infiniband/monitor/UFM-MONITOR.md
# 4.3). The commands follow the owner's manual procedure (ufm-manual.log, 2026-10-22):
#   ibdiagnet  inside the "ufm" container with the fixed arguments, packed inside the container to
#              /opt/ufm/files (the master mounts the host directory of the same name there), then moved
#              on the host to /root/monitor/ibdiagnet/ (no docker cp)
#   iblinkinfo inside the container, stdout only, to /root/monitor/iblinkinfo/
# cron.sh switches to iblinkinfo only after ibdiagnet failed three times in a row (owner 2026-10-22).
#
# Usage: bash monitor/ufm-ibdiagnet.sh [<run-id>] [--iblinkinfo]
#   cron.sh passes the run-id it generated; run by hand without one, the script makes its own of
#   the same form and prints it (owner 2026-10-21: every script runs on its own).
# Output (relative to the working directory, /root on the UFM):
#   monitor/ibdiagnet/ibdiagnet2_<run-id>.{tgz,log,node,done}
#   monitor/iblinkinfo/iblinkinfo_<run-id>.{log,stderr,node,done}

usage() {
    echo "usage: ufm-ibdiagnet.sh [<YYYYMMDD-HHMM-prod|air-16hex run-id>] [--iblinkinfo]" >&2
    exit 2
}
RUN_ID=""
RUN_ID_GIVEN=0
KIND=ibdiagnet
for arg in "$@"; do
    if [[ "$arg" == "--iblinkinfo" ]]; then
        KIND=iblinkinfo
    elif (( RUN_ID_GIVEN )); then
        usage
    else
        RUN_ID=$arg
        RUN_ID_GIVEN=1
    fi
done
if (( ! RUN_ID_GIVEN )); then
    RUN_ID="$(date -u +%Y%m%d-%H%M)-prod-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
    echo "run-id: ${RUN_ID}"
fi
[[ "$RUN_ID" =~ ^[0-9]{8}-[0-9]{4}-(prod|air)-[0-9a-f]{16}$ ]] || usage

CONTAINER=ufm
IBDIAGNET_ARGV=(/opt/ufm/opensm/bin/ibdiagnet --sc --extended_speeds all -P all=1 --pm_per_lane
                --get_cable_info --cable_info_disconnected --get_phy_info --routing --sharp
                --phy_cable_disconnected --rail_validation)
IBLINKINFO=/opt/ufm/opensm/sbin/iblinkinfo
RUN_TIMEOUT=900                             # owner 2026-10-22: at most 15 minutes inside the container
IBLINKINFO_MAX_BYTES=$((64 * 1024 * 1024))  # owner 2026-10-22: iblinkinfo output has a size limit
# Inside the container (it has /usr/bin/timeout, owner 2026-10-22), so the timeout ends the tool
# itself and not only the docker client.
TIMEOUT_WRAPPER='if command -v timeout >/dev/null 2>&1; then exec timeout -k 30 '"${RUN_TIMEOUT}"' "$@"; else exec "$@"; fi'
CONTAINER_OUT=/var/tmp/ibdiagnet2          # ibdiagnet's own output directory inside the container
SHARED_FILES=/opt/ufm/files                # inside the container: the master mounts the host directory
HOST_FILES="${UFM_HOST_FILES:-/opt/ufm/files}"   # the same directory on the host (tests point it elsewhere)
KEEP=3                                      # runs kept on the UFM per kind (owner 2026-10-21)
if [[ "$KIND" == ibdiagnet ]]; then
    OUTDIR=./monitor/ibdiagnet
    PREFIX="ibdiagnet2_${RUN_ID}"
else
    OUTDIR=./monitor/iblinkinfo
    PREFIX="iblinkinfo_${RUN_ID}"
fi
LOCK_DIR="${TMPDIR:-/tmp}/ufm-ibdiagnet.lock"   # one fabric scan at a time, whichever kind

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
        echo "another ufm-ibdiagnet.sh collection is still running (PID ${running_pid:-starting})" >&2
        exit 1
    fi
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    mkdir "$LOCK_DIR" 2>/dev/null || { echo "could not acquire the ibdiagnet lock" >&2; exit 1; }
fi
printf '%s\n' "$$" > "$LOCK_DIR/pid"
trap 'rm -f "$LOCK_DIR/pid"; rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT
# Owner 2026-10-22: an interrupted run ends here; it never goes on to write a .done marker.
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$OUTDIR" || exit 1

# ── Keep the latest runs only (a run is every file with its run-id) ─────────────
ls -1t "$OUTDIR"/*_*.done 2>/dev/null | tail -n +"$KEEP" | while IFS= read -r done_file; do
    old=${done_file##*/}
    old=${old#*_}
    old=${old%.done}
    [[ "$old" =~ ^[0-9]{8}-[0-9]{4}-(prod|air)-[0-9a-f]{16}$ ]] || continue
    rm -f "$OUTDIR"/*_"$old".*
done

# ── Finish: the .done marker is what cron.sh waits for ──────────────────────────
finish() {
    local result="$1" artifact="$2" reason="$3" sum="" size=""
    if [[ -n "$artifact" ]]; then
        sum=$(sha256sum "$OUTDIR/$artifact" | awk '{print $1}')
        size=$(wc -c < "$OUTDIR/$artifact" | tr -d ' ')
    fi
    {
        printf 'result=%s\nkind=%s\nrun_id=%s\nartifact=%s\nsha256=%s\nsize=%s\n' \
            "$result" "$KIND" "$RUN_ID" "$artifact" "$sum" "$size"
        printf 'rc=%s\nhostname=%s\nreason=%s\n' "${RUN_RC:-}" "$(hostname)" "$reason"
    } > "$OUTDIR/${PREFIX}.done.part" && mv "$OUTDIR/${PREFIX}.done.part" "$OUTDIR/${PREFIX}.done"
}

timeout_reason() {
    (( RUN_RC == 124 || RUN_RC == 137 )) && printf '%s timed out after %ss; ' "$KIND" "$RUN_TIMEOUT"
}

# The node that really ran it: the VIP moves between the two UFMs.
{ hostname; ip -br link; } > "$OUTDIR/${PREFIX}.node" 2>&1

started=$(date +%s)
if [[ "$KIND" == iblinkinfo ]]; then
    # ── iblinkinfo: stdout only (warnings go to .stderr), capped ──────────────────
    artifact="${PREFIX}.log"
    docker exec "$CONTAINER" sh -c "$TIMEOUT_WRAPPER" sh "$IBLINKINFO" 2> "$OUTDIR/${PREFIX}.stderr" \
        | head -c $((IBLINKINFO_MAX_BYTES + 1)) > "$OUTDIR/${artifact}.part"
    RUN_RC=${PIPESTATUS[0]}
    size=$(wc -c < "$OUTDIR/${artifact}.part" | tr -d ' ')
    if (( size > IBLINKINFO_MAX_BYTES )); then
        rm -f "$OUTDIR/${artifact}.part"
        finish failed "" "iblinkinfo output exceeds ${IBLINKINFO_MAX_BYTES} bytes"
        exit 1
    fi
    if (( RUN_RC == 0 )) && grep -q '^Switch' "$OUTDIR/${artifact}.part"; then
        mv "$OUTDIR/${artifact}.part" "$OUTDIR/${artifact}"
        finish ok "$artifact" ""
        exit 0
    fi
    rm -f "$OUTDIR/${artifact}.part"
    finish failed "" "$(timeout_reason)iblinkinfo produced no switch lines (exit ${RUN_RC})"
    exit 1
fi

# ── ibdiagnet inside the container ───────────────────────────────────────────
docker exec "$CONTAINER" sh -c "$TIMEOUT_WRAPPER" sh "${IBDIAGNET_ARGV[@]}" > "$OUTDIR/${PREFIX}.log" 2>&1
RUN_RC=$?
# Owner 2026-10-22: success needs ibdiagnet2.net_dump, written by this run (a run that stops half way
# can leave the rest of the directory behind).
produced=$(docker exec "$CONTAINER" stat -c %Y "${CONTAINER_OUT}/ibdiagnet2.net_dump" 2>/dev/null)
if [[ ! "$produced" =~ ^[0-9]+$ ]] || (( produced < started )); then
    finish failed "" "$(timeout_reason)ibdiagnet produced no new ibdiagnet2.net_dump (exit ${RUN_RC})"
    exit 1
fi
# Packed inside the container to the shared /opt/ufm/files, then moved on the host: the move crosses
# file systems, so it lands as .part and is renamed once complete.
artifact="${PREFIX}.tgz"
if docker exec "$CONTAINER" sh -c "tar -zcf ${SHARED_FILES}/${artifact}.part -C ${CONTAINER_OUT%/*} ibdiagnet2 \
        && mv ${SHARED_FILES}/${artifact}.part ${SHARED_FILES}/${artifact}" \
    && mv "${HOST_FILES}/${artifact}" "$OUTDIR/${artifact}.part" \
    && tar -tzf "$OUTDIR/${artifact}.part" | grep -q '/ibdiagnet2\.net_dump$' \
    && mv "$OUTDIR/${artifact}.part" "$OUTDIR/${artifact}"; then
    finish ok "$artifact" ""
    exit 0
fi
rm -f "$OUTDIR/${artifact}.part" "${HOST_FILES}/${artifact}" "${HOST_FILES}/${artifact}.part"
finish failed "" "packing or moving the ibdiagnet output failed"
exit 1
