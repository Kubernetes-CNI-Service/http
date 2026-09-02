#!/bin/bash
# Unified switch link collector — auto-detects SPX (SN56**/SN*) vs IB (Q*).
# Output: ./monitor/<hostname>.link

BASEDIR=./monitor
HOSTNAME=$(hostname)
if [[ ! "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$ ]]; then
    echo "unsafe local hostname; refusing link collection" >&2
    exit 1
fi
FILE=$BASEDIR/${HOSTNAME}.link
LOCK_DIR="${TMPDIR:-/tmp}/sw-link.lock"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    running_pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if [[ "$running_pid" =~ ^[0-9]+$ ]] && kill -0 "$running_pid" 2>/dev/null; then
        echo "${HOSTNAME}: another sw-link.sh collection is still running (PID ${running_pid})" >&2
        exit 1
    fi
    rm -f "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
    mkdir "$LOCK_DIR" 2>/dev/null || {
        echo "${HOSTNAME}: could not acquire collection lock" >&2
        exit 1
    }
fi
printf '%s\n' "$$" > "$LOCK_DIR/pid"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sw-link.XXXXXX") || {
    rmdir "$LOCK_DIR" 2>/dev/null
    exit 1
}
a=$TMP_DIR/phy.log
b=$TMP_DIR/int.log
c=$TMP_DIR/qos.log
d=$TMP_DIR/state.log
OUT=$TMP_DIR/${HOSTNAME}.link

cleanup() {
    rm -f "$a" "$b" "$c" "$d" "$OUT"
    rm -f "$LOCK_DIR/pid"
    rmdir "$TMP_DIR" "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Detect switch type ────────────────────────────────────────────────────────
SYSTEM_TYPE=$(nv show platform 2>/dev/null \
    | awk '/system-type/ { print $NF; exit }')

case "${SYSTEM_TYPE}" in
    SN*)  SW_TYPE="SPX" ;;
    Q*)   SW_TYPE="IB"  ;;
    MNV*|N*) SW_TYPE="NVLINK" ;;
    *)
        echo "${HOSTNAME}: unknown switch type '${SYSTEM_TYPE:-empty}', refusing to publish a link snapshot" >&2
        exit 1
        ;;
esac

mkdir -p "$BASEDIR"

# ── SPX link collection (SN* switches) ───────────────────────────────────────
if [[ "$SW_TYPE" == "SPX" ]]; then

    echo "Hostname,Interface,Effective-BER,Effective-Error,Carrier-Transitions,Date,Time,ECN-Marked,PFC-Receive,PFC-Send,Oper-Status,Peer,Peer-Interface" > "$OUT"

    # nv show interface columns are:
    # Interface, Admin Status, Oper Status, Speed, MTU, Type, Remote Host,
    # Remote Port, Summary.  Use column 3 for the real link state; column 2 is
    # only the configured/admin state and may remain up while the link is down.
    nv show interface \
        | grep "^swp.*s[0-7]" \
        | awk -F "IPv4" '{print $1}' \
        | awk '{print $1,$3,$7,$8}' > "$d"

    for i in $(awk '{print $1}' "$d"); do
        nv show interface "$i" link phy health > "$a"
        nv show interface "$i"                 > "$b"
        nv show interface "$i" counter         > "$c"

        ber=$(awk '$1=="effective-ber" {print $2; exit}' "$a")
        error=$(awk '$1=="effective-error" {print $2; exit}' "$a")
        carrier=$(awk '$1=="carrier-transitions" {print $2; exit}' "$b")
        change_date=; change_time=
        read -r change_date change_time < <(
            awk '$1=="oper-status-last-change" {print $2, $3; exit}' "$b"
        )
        ecn=$(awk '/ECN Marked Packets/ {print $NF; exit}' "$c")
        pfc_receive=; pfc_send=
        read -r pfc_receive pfc_send < <(
            awk '/Pause Frames/ {print $3, $4; exit}' "$c"
        )
        oper=; peer=; peer_interface=
        read -r oper peer peer_interface < <(
            awk -v iface="$i" '$1==iface {print $2, $3, $4; exit}' "$d"
        )

        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$HOSTNAME" "$i" "$ber" "$error" "$carrier" \
            "$change_date" "$change_time" "$ecn" "$pfc_receive" "$pfc_send" \
            "$oper" "$peer" "$peer_interface" >> "$OUT"
    done

# ── IB link collection (Q* switches) ─────────────────────────────────────────
elif [[ "$SW_TYPE" == "IB" ]]; then

    echo "Hostname,Interface,Effective-BER,Effective-Error,Carrier-Down-Count,QP1-Drops-Receive,QP1-Drops-Transmit,State" > "$OUT"

    nv show interface \
        | grep "^sw.*p[1-2]" \
        | awk '{print $1,$2}' > "$d"

    for i in $(awk '{print $1}' "$d"); do
        nv show interface "$i" link phy health > "$a"
        nv show interface "$i" counter         > "$c"

        ber=$(awk '$1=="effective-ber" {print $2; exit}' "$a")
        error=$(awk '$1=="effective-error" {print $2; exit}' "$a")
        carrier=$(awk '$1=="carrier-down-count" {print $2; exit}' "$c")
        qp1_receive=; qp1_transmit=
        read -r qp1_receive qp1_transmit < <(
            awk '$1=="qp1-drops-Receive" {print $2, $3; exit}' "$c"
        )
        state=$(awk -v iface="$i" '$1==iface {print $2; exit}' "$d")

        printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
            "$HOSTNAME" "$i" "$ber" "$error" "$carrier" \
            "$qp1_receive" "$qp1_transmit" "$state" >> "$OUT"
    done

# ── NV link collection (MNV* switches) ───────────────────────────────────────
elif [[ "$SW_TYPE" == "NVLINK" ]]; then

    echo "Hostname,Interface,Effective-BER,Effective-Error,Link-Downed,QP1-Drops,State" > "$OUT"

    nv show interface \
        | grep "nvl" \
        | awk '{print $1,$2}' > "$d"

    if [[ ! -s "$d" ]]; then
        echo "${HOSTNAME}: NVLink platform has no parseable nvl interfaces" >&2
        exit 1
    fi

    for i in $(awk '{print $1}' "$d"); do
        nv show interface "$i" link phy-detail > "$a"
        nv show interface "$i" link counters   > "$c"

        ber=$(awk '$1=="effective-ber" {print $2; exit}' "$a")
        error=$(awk '$1=="effective-error" {print $2; exit}' "$a")
        link_downed=$(awk '$1=="link-downed" {print $2; exit}' "$c")
        qp1_drops=$(awk '$1=="qp1-drops" {print $2; exit}' "$c")
        state=$(awk -v iface="$i" '$1==iface {print $2; exit}' "$d")

        printf '%s,%s,%s,%s,%s,%s,%s\n' \
            "$HOSTNAME" "$i" "$ber" "$error" "$link_downed" \
            "$qp1_drops" "$state" >> "$OUT"
    done

fi

# Readers see either the previous complete snapshot or this complete snapshot,
# never a file that is still being assembled.
mv "$OUT" "$FILE"
