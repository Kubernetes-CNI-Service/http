#!/bin/bash
# Switch info collection: verify key-based SSH access → collect one device type selected by CSV filename.
#
# Host lists:
#   eth.csv   — type=eth|eth_spx|spx → ETH info; type=eth_spx|spx → SPX link
#   ib.csv    — parsed at startup; type=ib → IB list
#   nvsw.csv  — parsed at startup; type=nvl → NV list
#
# When no environment is specified, the script probes overlapping addresses
# and selects the currently reachable Production or AIR environment.


export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

usage() {
    cat <<'EOF'
Usage: bash cron.sh [--air | --prod | --type TYPE] [--wait-lock SECONDS] [-h|--help]

Collect switch information from the CSV linked in this monitor directory.

Options:
  --air        Collect AIR simulation Cumulus devices. Equivalent to
               --type air; this is the recommended shorthand.
  --prod       Collect Production Cumulus devices. Equivalent to
               --type prod.
  --type TYPE   Select an environment or CSV device type (case-insensitive).
                eth.csv:  auto, prod, air, ethernet, eth, eth_spx, or spx
                ib.csv:   ib
                nvsw.csv: nvl
                ethernet selects eth + eth_spx + spx. The other values are
                exact type matches; eth_spx and spx also collect SPX links.
                AIR and Production rows come from the same eth.csv and are
                selected by the type column.
                Without --type, auto-detect Production/AIR using the target's
                actual hostname and eth0 MAC; IP alone is not identity.
  --wait-lock SECONDS
                Wait up to SECONDS for an existing collector to finish.
                Default 0 keeps scheduled cron runs non-blocking.
  -h, --help    Show these instructions and exit.

Examples:
  bash cron.sh                 # auto-detect Production or AIR
  bash cron.sh --air           # AIR simulation Cumulus devices only
  bash cron.sh --prod          # Production Cumulus devices only
  bash cron.sh --type air      # compatibility spelling of --air
  bash cron.sh --type ethernet # all Ethernet switch types
  bash cron.sh --type eth      # ordinary ETH info only
  bash cron.sh --type eth_spx  # inband/OOB SPX: info + link
  bash cron.sh --type spx      # SPX-network SPX: info + link
  bash infiniband/monitor/cron.sh --type server_ufm   # UFM only (ib.csv type=server_ufm)
EOF
}

TYPE_FILTER=""
COLLECTION_ENV=""
LOCK_WAIT=0
WORKER_CONTEXT_FD=""
EMIT_TARGET_PLAN_FD=""
PREHELD_LOCK_FD=""
set_type_filter() {
    local value="$1" option="$2"
    if [[ -n "$TYPE_FILTER" && "$TYPE_FILTER" != "$value" ]]; then
        echo "ERROR: ${option} conflicts with selected type ${TYPE_FILTER}" >&2
        usage >&2
        exit 2
    fi
    TYPE_FILTER="$value"
}
while (( $# )); do
    case "$1" in
        --air)
            [[ -z "$TYPE_FILTER" || "$TYPE_FILTER" == "air" ]] || {
                echo "ERROR: --air conflicts with --type ${TYPE_FILTER}" >&2
                usage >&2
                exit 2
            }
            set_type_filter "air" "--air"
            shift
            ;;
        --prod)
            [[ -z "$TYPE_FILTER" || "$TYPE_FILTER" == "prod" ]] || {
                echo "ERROR: --prod conflicts with --type ${TYPE_FILTER}" >&2
                usage >&2
                exit 2
            }
            set_type_filter "prod" "--prod"
            shift
            ;;
        --type)
            [[ $# -ge 2 && -n "$2" ]] || { echo "ERROR: --type requires a value" >&2; usage >&2; exit 2; }
            value=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
            set_type_filter "$value" "--type $value"
            shift 2
            ;;
        --type=*)
            value=${1#*=}
            value=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')
            [[ -n "$value" ]] || { echo "ERROR: --type requires a value" >&2; usage >&2; exit 2; }
            set_type_filter "$value" "--type=$value"
            shift
            ;;
        --wait-lock)
            [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || { echo "ERROR: --wait-lock requires non-negative seconds" >&2; exit 2; }
            LOCK_WAIT="$2"
            shift 2
            ;;
        --wait-lock=*)
            value=${1#*=}
            [[ "$value" =~ ^[0-9]+$ ]] || { echo "ERROR: --wait-lock requires non-negative seconds" >&2; exit 2; }
            LOCK_WAIT="$value"
            shift
            ;;
        --worker-context-fd)
            [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 3 ]] || {
                echo "ERROR: --worker-context-fd requires an inherited descriptor" >&2
                exit 2
            }
            WORKER_CONTEXT_FD="$2"
            shift 2
            ;;
        --emit-target-plan-fd)
            [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 3 ]] || {
                echo "ERROR: --emit-target-plan-fd requires an inherited descriptor" >&2
                exit 2
            }
            EMIT_TARGET_PLAN_FD="$2"
            shift 2
            ;;
        --preheld-lock-fd)
            [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 3 ]] || {
                echo "ERROR: --preheld-lock-fd requires an inherited descriptor" >&2
                exit 2
            }
            PREHELD_LOCK_FD="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ── Config ────────────────────────────────────────────────────────────────────
BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ETH=$(mktemp)   # eth/eth_spx/spx (sw-info.sh)
SPX=$(mktemp)   # eth_spx/spx only (sw-link.sh)
IB=$(mktemp)    # populated from ib.csv: type=ib
NV=$(mktemp)    # populated from nvsw.csv: type=nvl
UFM=$(mktemp)   # populated from ib.csv: type=server_ufm (hostname|eth0_ip); never a switch target
INVENTORY_MACS=$(mktemp)  # hostname|eth0_mac from the inventory: the identity checked at key preparation
DYNAMIC_AIR_IDENTITIES=$(mktemp)  # runtime hostname|authoritative eth0 MAC|runtime source (AIR + unbound Production)
PLANNED_DEVICES=$(mktemp)  # immutable hostname set before per-device filtering
DEVICE_FAILURES=$(mktemp)  # hostname<TAB>operation<TAB>bounded reason
CONTEXT_FILE=""
UNQUALIFIED_CONTEXT_FILE=""
RESULT_FILE=""
INFO_ARCHIVE=""
IB_INFO_ARCHIVE=""      # this run's exact IB / NV info archives (INFO_ARCHIVE keeps the last one)
NV_INFO_ARCHIVE=""
LINK_ARCHIVE=""
LINK_CSV=""
V2_EMITTER=${BASE}/../../monitor/collection_v2_emitter.py
DYNAMIC_AIR_HELPER=${BASE}/../../ztp/dynamic_air_inventory.py
DHCP_RUNTIME_HELPER=${BASE}/../../ztp/dhcp_runtime_inventory.py
AIR_JSON_FILE=${BASE}/../../ztp/config/isc-dhcp-server/p2p-air.json
DHCP_LEASES_FILE=${DHCP_LEASES_FILE:-/var/lib/dhcp/dhcpd.leases}
# Optional test/non-standard deployment override.  When unset the runtime
# helper reads the normal syslog/daemon.log files and the DHCP service journal.
DHCP_RUNTIME_LOG_FILE=${DHCP_RUNTIME_LOG_FILE:-}
DYNAMIC_AIR_DISCOVERED=0
DYNAMIC_AIR_RESOLVED=0
DYNAMIC_AIR_UNRESOLVED=0
UNBOUND_PROD_DISCOVERED=0
UNBOUND_PROD_ADDED=0
UNBOUND_PROD_SKIPPED=0
LOCK_FILE="${BASE}/$(basename "${BASH_SOURCE[0]%.*}").lock"
ASKPASS_FILE=""
if [[ -n "$PREHELD_LOCK_FD" ]]; then
    if ! python3 - "$PREHELD_LOCK_FD" "$LOCK_FILE" <<'PY'
import fcntl, os, sys
descriptor = int(sys.argv[1])
opened = os.fstat(descriptor)
target = os.stat(sys.argv[2], follow_symlinks=False)
if (opened.st_dev, opened.st_ino) != (target.st_dev, target.st_ino):
    raise SystemExit("inherited collection lock is not the active lock file")
fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
PY
    then
        echo "[A4] ERROR: inherited collection lock is invalid" >&2
        exit 1
    fi
else
    exec 200>"$LOCK_FILE"
    if (( LOCK_WAIT > 0 )); then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 等待采集锁（最多 ${LOCK_WAIT}s）：$LOCK_FILE"
        lock_args=(-w "$LOCK_WAIT")
    else
        lock_args=(-n)
    fi
    if ! flock "${lock_args[@]}" 200; then
        # Owner 2026-10-22: an overlapping start is skipped; the log says the previous run still runs.
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 上一轮采集仍在运行（采集锁 $LOCK_FILE 被占用${LOCK_WAIT:+，已等待 ${LOCK_WAIT}s}），本轮跳过" >&2
        exit 1
    fi
fi
trap 'rm -f "$ETH" "$SPX" "$IB" "$NV" "$UFM" "$INVENTORY_MACS" ${UFM_CANDIDATES:+"$UFM_CANDIDATES"} "$DYNAMIC_AIR_IDENTITIES" "$PLANNED_DEVICES" "$DEVICE_FAILURES" ${CONTEXT_FILE:+"$CONTEXT_FILE"} ${UNQUALIFIED_CONTEXT_FILE:+"$UNQUALIFIED_CONTEXT_FILE"} ${RESULT_FILE:+"$RESULT_FILE"} ${ASKPASS_FILE:+"$ASKPASS_FILE"}' EXIT
if [[ -n "$WORKER_CONTEXT_FD" ]]; then
    CONTEXT_FILE=$(mktemp) || exit 1
    if ! cat <&"$WORKER_CONTEXT_FD" > "$CONTEXT_FILE"; then
        log "[A4] ERROR: failed to read anonymous worker context"
        exit 1
    fi
    # A missing dynamic resolver is not evidence of zero targets. Keep the
    # preheld lock, but run the normal legacy collector with live discovery;
    # never let this run publish an artifact-qualifying v2 sidecar.
    if python3 -c 'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); sys.exit(0 if value.get("v2_unavailable") == "resolver_unavailable" else 1)' "$CONTEXT_FILE"; then
        UNQUALIFIED_CONTEXT_FILE="$CONTEXT_FILE"
        CONTEXT_FILE=""
    fi
fi
SWSH=${BASE}/sw-info.sh          # unified info script for ETH and IB switches
SWLSH=${BASE}/sw-link.sh         # unified link script for SPX and IB switches
POST_COLLECT=${BASE}/post-collect.py  # exact-archive validation + HTML refresh
HTML_GENERATOR=${BASE}/../../monitor/generate-monitor-html.py
ETH_ARCHIVE=""

ETH_WAIT=120    # seconds to wait for sw-info.sh   to finish on ETH switches
SPX_WAIT=300    # seconds to wait for sw-link.sh   to finish on SPX switches
IB_WAIT=120     # seconds to wait for sw-info.sh   to finish on IB  switches
IBL_WAIT=180    # seconds to wait for sw-link.sh   to finish on IB  switches
NV_WAIT=120     # seconds to wait for sw-info.sh   to finish on NV  switches
NVL_WAIT=180    # seconds to wait for sw-link.sh   to finish on NV  switches
RETRIEVE_FIRST_WAIT=60  # owner 2026-10-21: after triggering, wait this long before the first check,
RETRIEVE_POLL=5         # then check every RETRIEVE_POLL seconds; the *_WAIT values above are the limits
# Owner 2026-10-22: every collected file on the ztp server is kept 3 days: today as it is, the two days
# before in one daily bundle each (CSVs stay unbundled for the page), older ones deleted.
RETAIN_DAYS=3   # number of days of data to retain (older files are deleted), need to >=2
CRON_LOG_MAX_BYTES=$((10 * 1024 * 1024))   # owner 2026-10-22: cronjob.log is compressed at 10 MB,
CRON_LOG_KEEP=7                             # keeping at most 7 compressed copies
MAX_PARALLEL=8  # conservative limit for NVOS sshd; avoids MaxStartups resets

# Ethernet switches (Cumulus Linux)
ETH_SSH_USER="cumulus"
ETH_REMOTE_DIR="/home/${ETH_SSH_USER}/monitor"

# InfiniBand switches (NVOS)
IB_SSH_USER="admin"
IB_REMOTE_DIR="/home/${IB_SSH_USER}/monitor"

# NVLink switches (NVOS)
NV_SSH_USER="admin"
NV_REMOTE_DIR="/home/${NV_SSH_USER}/monitor"

# UFM appliances (ib.csv type=server_ufm; infiniband/monitor/UFM-MONITOR.md). ufm-setup-upgrade has
# already installed the deployment key, so there is no key preparation, and a UFM never joins the
# switch result (PLANNED_DEVICES / DEVICE_FAILURES / collection_failed).
UFM_SSH_USER="root"
UFM_REMOTE_DIR="/root/monitor"
UFM_INFO_SH=${BASE}/ufm-info.sh
UFM_IBDIAG_SH=${BASE}/ufm-ibdiagnet.sh
UFM_WAIT=120    # at most this long for ufm-info.sh (counted from its start, alongside sw-info.sh)
# Owner 2026-10-22: ibdiagnet runs up to 15 minutes (6 on ufm01), so its result is first checked 5
# minutes after the start, then every 30 s, for at most 17 minutes (15 plus 2 for packing). The same
# limits apply to iblinkinfo. Page-driven collection never overlaps (the next cycle is scheduled after
# this one ends), so the long wait only stretches this cycle.
UFM_IBDIAG_FIRST_WAIT=300
UFM_IBDIAG_POLL=30
UFM_IBDIAG_WAIT=1020
# Owner 2026-10-22: ibdiagnet by default; after 3 consecutive failures iblinkinfo instead, trying
# ibdiagnet again every 6th run. The count lives on this server, beside the data (a failover would
# lose it on the UFM).
UFM_IBDIAG_FAIL_LIMIT=3
UFM_IBDIAG_RETRY_EVERY=6
UFM_PLANNED=0

# Shared public key deployed to all switch types.  It must come from the active
# project; embedding a former management server's key would silently authorize
# the wrong host after a project migration.
_collector_area=$(basename "$(dirname "$BASE")")
case "$_collector_area" in
    ethernet)   _inventory_name="eth.csv" ;;
    infiniband) _inventory_name="ib.csv" ;;
    nvlink)     _inventory_name="nvsw.csv" ;;
    *)
        echo "[ERROR] unsupported collector entrypoint area: ${_collector_area}" >&2
        exit 1
        ;;
esac
_inventory="${BASE}/${_inventory_name}"
ACTIVE_INVENTORY=$(readlink -f "$_inventory" 2>/dev/null || true)
ACTIVE_PROJECT_DIR=${ACTIVE_INVENTORY%/*}
MGMT_PUBKEY_FILE=${ACTIVE_PROJECT_DIR}/mgmt-server.pub
if [[ -z "$ACTIVE_INVENTORY" || ! -s "$MGMT_PUBKEY_FILE" ]]; then
    echo "[ERROR] active project mgmt-server.pub is missing or empty: ${MGMT_PUBKEY_FILE}" >&2
    exit 1
fi
if ! ssh-keygen -l -f "$MGMT_PUBKEY_FILE" >/dev/null 2>&1; then
    echo "[ERROR] invalid management public key: ${MGMT_PUBKEY_FILE}" >&2
    exit 1
fi
SSH_KEY=$(awk '
    NF >= 2 && ($1 ~ /^ssh-/ || $1 ~ /^ecdsa-/) { print $1 " " $2; exit }
' "$MGMT_PUBKEY_FILE")
if [[ -z "$SSH_KEY" ]]; then
    echo "[ERROR] no supported SSH public key in ${MGMT_PUBKEY_FILE}" >&2
    exit 1
fi
# Compression is enabled for SSH and SCP. BatchMode deliberately forbids password
# prompts because this script runs from cron and starts connections in parallel.
# At least one usable management-server private key must already be authorized on
# each switch; this script then idempotently installs SSH_KEY as an additional key.
SSH_OPTS="-C -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ConnectionAttempts=2 -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
# UFM sessions also detect a dead peer: during `ufm_ha_cluster failover` nobody may answer the VIP for a
# while, and without keepalives an scp would wait for TCP retransmits (owner 2026-10-22). Host keys are
# never pinned (UserKnownHostsFile=/dev/null), so the VIP changing hands does not stop a login.
UFM_ALIVE_OPTS="-o ServerAliveInterval=10 -o ServerAliveCountMax=3"
SSH_PASSWORD_OPTS="-C -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10 -o ConnectionAttempts=2 -o BatchMode=no -o NumberOfPasswordPrompts=1 -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=yes -o PreferredAuthentications=publickey,keyboard-interactive,password"

LOG=${BASE}/$(basename "${BASH_SOURCE[0]}")-$(date '+%Y%m%d-%H%M').log

# ── Helpers ───────────────────────────────────────────────────────────────────
# If stdout is already redirected (e.g. cron >> file), write only to stdout.
# If stdout is a terminal (interactive), tee to both terminal and $LOG.
log() {
    if [ -t 1 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    fi
}

# Create the executable OpenSSH askpass helper outside Docker's noexec /tmp.
# Container startup owns the fixed 0700 directory; this function only accepts
# an existing, canonical, caller-owned private directory before placing code in
# it. Native deployments retain their normal TMPDIR fallback.
create_ssh_askpass_helper() {
    local askpass_dir="${HTTP_ZTP_ASKPASS_TMPDIR:-}"
    local require_private_dir=0
    if [[ -n "$askpass_dir" ]]; then
        require_private_dir=1
    elif [[ "${HTTP_ZTP_RUNTIME_BACKEND:-}" == "supervisor" ]]; then
        askpass_dir="/run/http-ztp/askpass"
        require_private_dir=1
    else
        askpass_dir="${TMPDIR:-/tmp}"
    fi

    if (( require_private_dir )); then
        if ! python3 - "$askpass_dir" <<'PY'
import os
import stat
import sys

directory = sys.argv[1]
canonical = os.path.abspath(directory)
try:
    metadata = os.lstat(directory)
except OSError as exc:
    raise SystemExit(f"cannot inspect private askpass directory: {exc}")
if directory != canonical or os.path.realpath(directory) != canonical:
    raise SystemExit("private askpass directory must be an absolute canonical path")
if not stat.S_ISDIR(metadata.st_mode):
    raise SystemExit("private askpass path is not a directory")
if metadata.st_uid != os.geteuid():
    raise SystemExit("private askpass directory has the wrong owner")
if stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("private askpass directory mode must be 0700")
PY
        then
            log "[KEY] ERROR: unsafe executable SSH askpass directory: ${askpass_dir}"
            return 1
        fi
    fi

    ASKPASS_FILE=$(mktemp "${askpass_dir%/}/monitor-ssh-askpass.XXXXXX") || {
        log "[KEY] ERROR: could not create the temporary SSH askpass helper"
        return 1
    }
    if ! printf '%s\n' '#!/bin/sh' \
        'printf "%s\n" "$MONITOR_SSH_PASSWORD"' > "$ASKPASS_FILE" \
        || ! chmod 700 "$ASKPASS_FILE"
    then
        log "[KEY] ERROR: could not prepare the temporary SSH askpass helper"
        rm -f "$ASKPASS_FILE"
        ASKPASS_FILE=""
        return 1
    fi
    export SSH_ASKPASS="$ASKPASS_FILE" SSH_ASKPASS_REQUIRE=force
    export DISPLAY="${DISPLAY:-:0}"
}

detect_eth_environment() {
    local prod_csv="${BASE}/eth.csv" result=""
    [[ -f "$prod_csv" ]] || return 0
    case "$TYPE_FILTER" in
        air) COLLECTION_ENV="air"; return 0 ;;
        prod) TYPE_FILTER="ethernet"; COLLECTION_ENV="prod"; return 0 ;;
        eth|eth_spx|spx|ethernet) COLLECTION_ENV="prod"; return 0 ;;
        auto) TYPE_FILTER="" ;;
    esac
    result=$(python3 "${BASE}/../../ztp/environment_probe.py" \
        --inventory "$prod_csv" --user "$ETH_SSH_USER") || {
        log "[ENV] ERROR: cannot auto-detect reachable environment; verify key SSH or use --type prod/air"
        return 1
    }
    case "$result" in
        air) TYPE_FILTER="air"; COLLECTION_ENV="air" ;;
        prod) TYPE_FILTER="ethernet"; COLLECTION_ENV="prod" ;;
        *) log "[ENV] ERROR: invalid probe result: $result"; return 1 ;;
    esac
    log "[ENV] auto-detected reachable environment: $COLLECTION_ENV"
}

# hosts_file_has_entries <file>  — true if file exists and has ≥1 non-blank non-comment line
hosts_file_has_entries() {
    [[ -f "$1" ]] && grep -qvE '^\s*(#|$)' "$1"
}

hosts_file_entry_count() {
    grep -cvE '^\s*(#|$)' "$1" 2>/dev/null || true
}

# Remove Cumulus VX simulation nodes from the SPX link-collection list.
# VX implements enough NVUE for sw-info.sh, but it does not expose the
# hardware PHY/counter data consumed by sw-link.sh.  Keep an entry whenever
# platform detection itself fails so a transient SSH/NVUE error is reported by
# the normal collection path instead of silently dropping a real switch.
exclude_vx_from_spx() {
    local source_file="$1" user="$2" filtered_file entry name host system_type system_type_upper
    local kept=0 skipped=0 failed=0
    filtered_file=$(mktemp) || {
        log "[SPX] ERROR: could not create the VX-filtered host list"
        return 1
    }

    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
        IFS='|' read -r name host <<< "$entry"
        [[ -n "$name" ]] || name="$host"
        [[ -n "$host" ]] || host="$name"
        if ! valid_host_entry "$name" "$host"; then
            log "[SPX] ERROR: unsafe hostname/IP entry during platform check: ${name}|${host}"
            failed=1
            continue
        fi

        # This SSH call runs inside a ``while read`` loop.  Detach its stdin;
        # otherwise ssh consumes the remaining host-list rows and only the
        # first SPX candidate is inspected.
        if system_type=$(ssh -n $SSH_OPTS "${user}@${host}" \
            "nv show platform 2>/dev/null | awk '/system-type/ { print \$NF; exit }'"); then
            system_type=$(printf '%s' "$system_type" | tr -d '[:space:]')
        else
            system_type=""
        fi
        system_type_upper=$(printf '%s' "$system_type" | tr '[:lower:]' '[:upper:]')

        if [[ "$system_type_upper" == "VX" ]]; then
            log "[SPX][SKIP] ${name} (${host}): system-type=VX; sw-link.sh is not applicable"
            skipped=$((skipped + 1))
            continue
        fi
        if [[ -z "$system_type" ]]; then
            log "[SPX][WARN] ${name} (${host}): could not read system-type; keeping device in the sw-link.sh list"
        fi
        printf '%s|%s\n' "$name" "$host" >> "$filtered_file"
        kept=$((kept + 1))
    done < "$source_file"

    if (( failed )); then
        rm -f "$filtered_file"
        return 1
    fi
    mv "$filtered_file" "$source_file"
    log "[SPX] platform filter complete: eligible=${kept}, skipped VX=${skipped}"
}

valid_host_entry() {
    local name="$1" host="$2" octet
    local -a host_octets
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
    [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS='.' read -r -a host_octets <<< "$host"
    (( ${#host_octets[@]} == 4 )) || return 1
    for octet in "${host_octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
    done
}

# Append AIR-only Cumulus nodes whose current address is known from ISC DHCP.
# These nodes (for example simulated firewalls) intentionally have no matching
# Production row, so c1-generate_dhcp.py keeps them as dynamic known hosts and
# does not write them into the static project CSV.  An unresolved lease is an
# expected transient state: report it and leave the node out of this SSH run.
append_dynamic_air_hosts() {
    local inventory="$1" output_file error_file detail replacement_file
    local hostname ip mac _template address_source issue

    [[ "$TYPE_FILTER" == "air" ]] || return 0
    if [[ -n "${CONTEXT_FILE:-}" ]]; then
        output_file=$(mktemp) || return 1
        if ! python3 - "$CONTEXT_FILE" >"$output_file" <<'PY'
import json, sys
from pathlib import Path
context = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = context["air_dynamic_rows"]
if not isinstance(rows, list) or any(not isinstance(row, str) or "\n" in row
                                     or "\r" in row or "\x00" in row for row in rows):
    raise SystemExit("invalid frozen AIR runtime rows")
for row in rows:
    print(row)
PY
        then
            rm -f "$output_file"
            return 1
        fi
    else
    if [[ ! -f "$DYNAMIC_AIR_HELPER" ]]; then
        log "[AIR-DYNAMIC] WARN: helper not found: ${DYNAMIC_AIR_HELPER}; static AIR targets only"
        return 0
    fi
    if [[ ! -f "$AIR_JSON_FILE" ]]; then
        log "[AIR-DYNAMIC] WARN: AIR JSON not found: ${AIR_JSON_FILE}; static AIR targets only"
        return 0
    fi
    if [[ ! -f "$DHCP_LEASES_FILE" ]]; then
        log "[AIR-DYNAMIC] WARN: DHCP lease file not found: ${DHCP_LEASES_FILE}; dynamic AIR nodes will remain unresolved"
    fi

    output_file=$(mktemp) || {
        log "[AIR-DYNAMIC] WARN: could not create resolver output; static AIR targets only"
        return 0
    }
    error_file=$(mktemp) || {
        rm -f "$output_file"
        log "[AIR-DYNAMIC] WARN: could not create resolver error output; static AIR targets only"
        return 0
    }
    if ! python3 "$DYNAMIC_AIR_HELPER" \
        --inventory "$inventory" \
        --air-json "$AIR_JSON_FILE" \
        --leases "$DHCP_LEASES_FILE" \
        --include-static-transitions \
        --format pipe >"$output_file" 2>"$error_file"
    then
        detail=$(tr '\n' ' ' < "$error_file")
        log "[AIR-DYNAMIC] WARN: resolver failed; static AIR targets only${detail:+: ${detail}}"
        rm -f "$output_file" "$error_file"
        return 0
    fi
    rm -f "$error_file"
    fi

    while IFS='|' read -r hostname ip mac _template address_source issue; do
        [[ -n "$hostname" ]] || continue
        DYNAMIC_AIR_DISCOVERED=$((DYNAMIC_AIR_DISCOVERED + 1))
        if [[ -z "$ip" ]]; then
            DYNAMIC_AIR_UNRESOLVED=$((DYNAMIC_AIR_UNRESOLVED + 1))
            log "[AIR-DYNAMIC] WARN: ${hostname} (${mac:-MAC unknown}) has no active DHCP lease${issue:+; ${issue}}; skipping SSH this run"
            continue
        fi
        if ! valid_host_entry "$hostname" "$ip"; then
            DYNAMIC_AIR_UNRESOLVED=$((DYNAMIC_AIR_UNRESOLVED + 1))
            log "[AIR-DYNAMIC] WARN: unsafe resolved target ${hostname}|${ip}; skipping SSH this run"
            continue
        fi
        if awk -F'|' -v expected="$hostname" \
            'tolower($1) == tolower(expected) { found=1 } END { exit !found }' "$ETH"
        then
            if [[ "$address_source" == "dhcp-lease-transition" ]]; then
                replacement_file=$(mktemp) || {
                    log "[AIR-DYNAMIC] WARN: could not stage transition target for ${hostname}; keeping static target"
                    continue
                }
                awk -F'|' -v OFS='|' -v expected="$hostname" -v target="$ip" '
                    tolower($1) == tolower(expected) { print $1, target; next }
                    { print }
                ' "$ETH" > "$replacement_file"
                mv "$replacement_file" "$ETH"
                printf '%s|%s|%s\n' "$hostname" "$mac" "$address_source" \
                    >> "$DYNAMIC_AIR_IDENTITIES"
                DYNAMIC_AIR_RESOLVED=$((DYNAMIC_AIR_RESOLVED + 1))
                log "[AIR-DYNAMIC] transition ${hostname}: using old lease ${ip} for this SSH collection; canonical inventory remains unchanged"
                continue
            fi
            log "[AIR-DYNAMIC] WARN: ${hostname} already exists in the static AIR target list; ignoring runtime duplicate"
            continue
        fi
        printf '%s|%s\n' "$hostname" "$ip" >> "$ETH"
        printf '%s|%s|%s\n' "$hostname" "$mac" "${address_source:-dhcp-lease}" \
            >> "$DYNAMIC_AIR_IDENTITIES"
        DYNAMIC_AIR_RESOLVED=$((DYNAMIC_AIR_RESOLVED + 1))
        log "[AIR-DYNAMIC] added ${hostname} (${ip}, ${mac}, source=${address_source:-dhcp-lease})"
    done < "$output_file"
    rm -f "$output_file"

    if (( DYNAMIC_AIR_DISCOVERED > 0 )); then
        log "[AIR-DYNAMIC] discovered=${DYNAMIC_AIR_DISCOVERED}, resolved=${DYNAMIC_AIR_RESOLVED}, unresolved=${DYNAMIC_AIR_UNRESOLVED}"
    fi
    return 0
}

# Append Production Cumulus clients that have requested DHCP but have not yet
# been bound to a project hostname/MAC.  These targets are deliberately kept
# out of SPX collection and receive a deterministic transport identity derived
# only from their authoritative eth0 MAC.  The IP is a route to the device, not
# its identity; prepare_ssh_host_resilient verifies the remote eth0 MAC before
# allowing the default ``cumulus`` hostname.
append_unbound_prod_cumulus_hosts() {
    local inventory="$1" output_file error_file rows_file detail
    local runtime_name ip mac platform lease_state mac_plain suffix source
    local -a helper_args

    [[ "$COLLECTION_ENV" == "prod" ]] || return 0
    if [[ -n "${CONTEXT_FILE:-}" ]]; then
        rows_file=$(mktemp) || return 1
        if ! python3 - "$CONTEXT_FILE" >"$rows_file" <<'PY'
import json, sys
from pathlib import Path
context = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = context["prod_runtime_rows"]
if not isinstance(rows, list) or any(not isinstance(row, str) or "\n" in row
                                     or "\r" in row or "\x00" in row for row in rows):
    raise SystemExit("invalid frozen Production runtime rows")
for row in rows:
    print(row)
PY
        then
            rm -f "$rows_file"
            return 1
        fi
    else
    if [[ ! -f "$DHCP_RUNTIME_HELPER" ]]; then
        log "[PROD-UNBOUND] WARN: helper not found: ${DHCP_RUNTIME_HELPER}; planned Production targets only"
        return 0
    fi

    output_file=$(mktemp) || {
        log "[PROD-UNBOUND] WARN: could not create runtime inventory output"
        return 0
    }
    error_file=$(mktemp) || {
        rm -f "$output_file"
        log "[PROD-UNBOUND] WARN: could not create runtime inventory error output"
        return 0
    }
    rows_file=$(mktemp) || {
        rm -f "$output_file" "$error_file"
        log "[PROD-UNBOUND] WARN: could not create runtime inventory row output"
        return 0
    }

    helper_args=(--stdout --inventory "$inventory" --leases "$DHCP_LEASES_FILE")
    if [[ -n "$DHCP_RUNTIME_LOG_FILE" ]]; then
        helper_args+=(--dhcp-log "$DHCP_RUNTIME_LOG_FILE")
    else
        helper_args+=(--journal)
    fi
    if ! python3 "$DHCP_RUNTIME_HELPER" "${helper_args[@]}" \
        >"$output_file" 2>"$error_file"
    then
        detail=$(tr '\n' ' ' < "$error_file")
        log "[PROD-UNBOUND] WARN: runtime inventory failed; planned Production targets only${detail:+: ${detail}}"
        rm -f "$output_file" "$error_file" "$rows_file"
        return 0
    fi
    if ! python3 -c '
import json, sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
for item in payload.get("devices", []):
    values = [item.get("mac"), item.get("ip"), item.get("platform"), item.get("lease_state")]
    print("|".join("" if value is None else str(value) for value in values))
' "$output_file" >"$rows_file" 2>>"$error_file"
    then
        detail=$(tr '\n' ' ' < "$error_file")
        log "[PROD-UNBOUND] WARN: invalid runtime inventory JSON${detail:+: ${detail}}"
        rm -f "$output_file" "$error_file" "$rows_file"
        return 0
    fi
    rm -f "$output_file" "$error_file"
    fi

    while IFS='|' read -r mac ip platform lease_state; do
        [[ -n "$mac" ]] || continue
        UNBOUND_PROD_DISCOVERED=$((UNBOUND_PROD_DISCOVERED + 1))
        if [[ "$platform" != "cumulus" ]]; then
            UNBOUND_PROD_SKIPPED=$((UNBOUND_PROD_SKIPPED + 1))
            log "[PROD-UNBOUND] skip ${mac}: platform=${platform:-unknown}; Cumulus collector not applicable"
            continue
        fi
        if [[ "$lease_state" != "active" && "$lease_state" != "observed" ]]; then
            UNBOUND_PROD_SKIPPED=$((UNBOUND_PROD_SKIPPED + 1))
            log "[PROD-UNBOUND] skip ${mac}: lease_state=${lease_state:-unknown} is not active/observed"
            continue
        fi
        mac_plain=$(printf '%s' "$mac" | tr -cd '[:xdigit:]' | tr '[:upper:]' '[:lower:]')
        if [[ ! "$mac_plain" =~ ^[0-9a-f]{12}$ ]]; then
            UNBOUND_PROD_SKIPPED=$((UNBOUND_PROD_SKIPPED + 1))
            log "[PROD-UNBOUND] WARN: invalid authoritative eth0 MAC '${mac}'; skipping"
            continue
        fi
        suffix=$(printf '%s' "$mac_plain" | tr '[:lower:]' '[:upper:]')
        runtime_name="DISCOVERED-CUMULUS-${suffix}"
        if ! valid_host_entry "$runtime_name" "$ip"; then
            UNBOUND_PROD_SKIPPED=$((UNBOUND_PROD_SKIPPED + 1))
            log "[PROD-UNBOUND] WARN: unsafe or missing lease target ${runtime_name}|${ip}; skipping"
            continue
        fi
        if awk -F'|' -v expected_ip="$ip" -v expected_name="$runtime_name" '
            $2 == expected_ip || tolower($1) == tolower(expected_name) { found=1 }
            END { exit !found }
        ' "$ETH"
        then
            UNBOUND_PROD_SKIPPED=$((UNBOUND_PROD_SKIPPED + 1))
            log "[PROD-UNBOUND] WARN: duplicate runtime target ${runtime_name}|${ip}; skipping"
            continue
        fi
        source="dhcp-unbound-cumulus"
        printf '%s|%s\n' "$runtime_name" "$ip" >> "$ETH"
        printf '%s|%s|%s\n' "$runtime_name" "$mac" "$source" \
            >> "$DYNAMIC_AIR_IDENTITIES"
        UNBOUND_PROD_ADDED=$((UNBOUND_PROD_ADDED + 1))
        log "[PROD-UNBOUND] added ${runtime_name} (${ip}, ${mac}, lease=${lease_state})"
    done < "$rows_file"
    rm -f "$rows_file"

    if (( UNBOUND_PROD_DISCOVERED > 0 )); then
        log "[PROD-UNBOUND] discovered=${UNBOUND_PROD_DISCOVERED}, added=${UNBOUND_PROD_ADDED}, skipped=${UNBOUND_PROD_SKIPPED}"
    fi
    return 0
}

archive_collection_dir() {
    local dir="$1" label="$2" archive="${1}.tar.gz"
    # Owner 2026-10-22: written as .part and renamed, so a reader (the page, REQ7) never sees half an
    # archive; the retention cleanup leaves *.part alone.
    if ! tar -czf "${archive}.part" \
        -C "$(dirname "$dir")" "$(basename "$dir")"; then
        rm -f -- "${archive}.part"
        log "${label} ERROR: failed to create archive ${archive}"
        return 1
    fi
    # No clobber (codex review 2026-10-22): a second run in the same minute must not replace the
    # first one's archive; ln fails when the name exists.
    if [[ ! -s "${archive}.part" ]] || ! ln -- "${archive}.part" "$archive" 2>/dev/null; then
        rm -f -- "${archive}.part"
        log "${label} ERROR: archive is missing, empty or already exists (not replaced): ${archive}"
        return 1
    fi
    rm -f -- "${archive}.part"
    rm -r -- "$dir"
}

# Record one device-scoped problem without turning a surviving batch into a
# global collector failure. Inputs have already passed valid_host_entry().
record_device_failure() {
    local operation="$1" entry="$2" reason="$3" name host
    IFS='|' read -r name host <<< "$entry"
    [[ -n "$name" ]] || name="$host"
    reason=$(printf '%s' "$reason" | tr '\t\r\n' '   ')
    printf '%s\t%s\t%s\n' "$name" "$operation" "${reason:-operation failed}" \
        >> "$DEVICE_FAILURES"
}

record_planned_devices() {
    awk -F'|' '
        /^[[:space:]]*(#|$)/ { next }
        {
            key=tolower($1)
            if (key != "" && !seen[key]++) print $1
        }
    ' "$ETH" "$IB" "$NV" > "$PLANNED_DEVICES"
}

# Emit exactly one bounded machine result for the root worker. Device failures
# are deduplicated by hostname; one device can carry several failed operations.
emit_collection_result() {
    python3 - "$PLANNED_DEVICES" "$DEVICE_FAILURES" <<'PY'
import json
import sys

def truncate_utf8(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")

planned_path, failures_path = sys.argv[1:]
with open(planned_path, encoding="utf-8") as stream:
    planned = [line.strip() for line in stream if line.strip()]
planned_by_key = {name.casefold(): name for name in planned}
failures = {}
with open(failures_path, encoding="utf-8") as stream:
    for raw in stream:
        fields = raw.rstrip("\n").split("\t", 2)
        if len(fields) != 3:
            raise SystemExit("invalid device failure record")
        hostname, operation, reason = fields
        key = hostname.casefold()
        if key not in planned_by_key:
            raise SystemExit("failure references an unplanned device")
        item = failures.setdefault(key, {"operations": [], "reasons": []})
        if operation not in item["operations"]:
            item["operations"].append(operation)
        if reason not in item["reasons"]:
            item["reasons"].append(reason)
failed_devices = [
    {
        "hostname": planned_by_key[key],
        "operation": ",".join(sorted(value["operations"])),
        "reason": truncate_utf8("; ".join(value["reasons"]), 1024),
    }
    for key, value in sorted(failures.items())
]
failed_count = len(failed_devices)
succeeded = len(planned) - failed_count
state = "success" if not failed_count else ("partial" if succeeded else "failed")
payload = {
    "schema_version": 1,
    "task": "switch_collection",
    "state": state,
    "planned": len(planned),
    "succeeded": succeeded,
    "failed_count": failed_count,
    "failed_devices": failed_devices,
}
print("[HTTP_ZTP_TASK_RESULT] " + json.dumps(
    payload, ensure_ascii=False, separators=(",", ":"),
))
raise SystemExit(1 if state == "failed" else 0)
PY
}

# A collector/archive or evidence-publication failure is a terminal v1
# failure, never a fabricated v2 artifact assertion. The reason is fixed and
# contains no credentials or device transcript.
emit_failed_collection_result() {
    python3 - "$PLANNED_DEVICES" <<'A4_FAILED_PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    planned = [line.strip() for line in stream if line.strip()]
if len(planned) > 10000:
    raise SystemExit("too many planned devices")
payload = {
    "schema_version": 1, "task": "switch_collection", "state": "failed",
    "planned": len(planned), "succeeded": 0, "failed_count": len(planned),
    "failed_devices": [
        {"hostname": name, "operation": "collection",
         "reason": "collection or evidence publication failed"}
        for name in planned
    ],
}
print("[HTTP_ZTP_TASK_RESULT] " + json.dumps(
    payload, ensure_ascii=False, separators=(",", ":")))
A4_FAILED_PY
}

# run_parallel <hosts_file> <cmd_template> <operation>
# Runs cmd_template for every host in hosts_file, at most MAX_PARALLEL at a time.
# Host-list rows use "expected_hostname|ssh_target". __NAME__ is replaced with
# the CSV hostname and __HOST__ with the required eth0_ip address.
# Individual failures are removed from hosts_file and recorded for the final
# summary. Return 1 only for an unsafe row or an internal bookkeeping failure.
run_parallel() {
    local hosts_file="$1" cmd_tmpl="$2" operation="${3:-collection}"
    local pids=() unsafe=0 successful
    local entry name host command
    if [[ "$operation" != "collection" ]]; then
        echo "[PARALLEL][REJECT] unsupported failure operation: ${operation}" >&2
        return 1
    fi
    successful=$(mktemp) || return 1
    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
        IFS='|' read -r name host <<< "$entry"
        [[ -n "$name" ]] || name="$host"
        [[ -n "$host" ]] || host="$name"
        if ! valid_host_entry "$name" "$host"; then
            echo "[PARALLEL][REJECT] unsafe hostname/IP entry: ${name}|${host}" >&2
            unsafe=1
            continue
        fi
        command=${cmd_tmpl//__NAME__/$name}
        command=${command//__HOST__/$host}
        (
            if bash -c "$command" </dev/null; then
                printf '%s\n' "$entry" >> "$successful"
            else
                rc=$?
                echo "[PARALLEL][FAIL] ${name} (${host}, exit=${rc})" >&2
                record_device_failure "$operation" "$entry" "command exit=${rc}"
            fi
            exit 0
        ) &
        pids+=("$!")
        # 达到并发上限时，先等待本批全部结束再继续
        if (( ${#pids[@]} >= MAX_PARALLEL )); then
            for pid in "${pids[@]}"; do wait "$pid" || unsafe=1; done
            pids=()
        fi
    done < "$hosts_file"
    for pid in "${pids[@]}"; do wait "$pid" || unsafe=1; done
    if (( unsafe )); then
        rm -f "$successful"
        return 1
    fi
    mv "$successful" "$hosts_file"
    return 0
}

# ── Wait, then fetch each device's file as soon as it is complete ─────────────
# Owner 2026-10-21: wait RETRIEVE_FIRST_WAIT seconds after the trigger, then check every
# RETRIEVE_POLL seconds up to the phase limit and fetch each device's file as soon as it exists.
# The collectors rename a finished file into place on one filesystem, so a file that exists is
# complete; an .info must also end with its "# Collect complete" marker. A device that is not ready
# in time is dropped from the host list and recorded, exactly like run_parallel; the others are
# unaffected.
retrieve_when_ready() {
    local hosts_file="$1" user="$2" remote_dir="$3" ext="$4" dest="$5" limit="$6" label="$7"
    local started=$SECONDS pending ready round next entry name host first pid unsafe=0 checks=0 max_checks
    local pids=()
    pending=$(mktemp) || return 1
    ready=$(mktemp) || { rm -f "$pending"; return 1; }
    grep -vE '^[[:space:]]*(#|$)' "$hosts_file" > "$pending"
    first=$RETRIEVE_FIRST_WAIT
    (( first > limit )) && first=$limit
    max_checks=$(( (limit - first) / RETRIEVE_POLL + 1 ))
    log "${label} waiting ${first}s, then checking every ${RETRIEVE_POLL}s for *.${ext} (at most ${limit}s)"
    sleep "$first"
    while hosts_file_has_entries "$pending"; do
        checks=$((checks + 1))
        round=$(mktemp) || break
        pids=()
        while IFS= read -r entry; do
            IFS='|' read -r name host _rest <<< "$entry"
            [[ -n "$name" ]] || name="$host"
            [[ -n "$host" ]] || host="$name"
            if ! valid_host_entry "$name" "$host"; then
                echo "[PARALLEL][REJECT] unsafe hostname/IP entry: ${name}|${host}" >&2
                unsafe=1
                continue
            fi
            (
                # staged beside the destination under the device's own file name, then renamed in
                stage=$(mktemp -d "${dest}/.fetch.XXXXXX") || exit 0
                copy="${stage}/${name}.${ext}"
                if scp $SSH_OPTS "${user}@${host}:${remote_dir}/*.${ext}" "$copy" </dev/null >/dev/null 2>&1 \
                    && [[ -s "$copy" ]] \
                    && { [[ "$ext" != "info" ]] || grep -q '^# Collect complete$' "$copy"; } \
                    && mv "$copy" "${dest}/${name}.${ext}"; then
                    printf '%s\n' "$entry" >> "$round"
                fi
                rm -f "$copy"
                rmdir "$stage" 2>/dev/null
                exit 0
            ) &
            pids+=("$!")
            if (( ${#pids[@]} >= MAX_PARALLEL )); then
                for pid in "${pids[@]}"; do wait "$pid"; done
                pids=()
            fi
        done < "$pending"
        for pid in "${pids[@]}"; do wait "$pid"; done
        cat "$round" >> "$ready"
        next=$(mktemp) || { rm -f "$round"; break; }
        grep -vxF -f "$round" "$pending" > "$next"
        mv "$next" "$pending"
        rm -f "$round"
        hosts_file_has_entries "$pending" || break
        (( checks < max_checks && SECONDS - started < limit )) || break
        sleep "$RETRIEVE_POLL"
    done
    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        IFS='|' read -r name host _rest <<< "$entry"
        echo "[PARALLEL][FAIL] ${name} (${host}): no complete *.${ext} within ${limit}s" >&2
        record_device_failure "collection" "$entry" "no complete ${ext} file within ${limit}s"
    done < "$pending"
    # keep the host list in its original order
    next=$(mktemp) || { rm -f "$pending" "$ready"; return 1; }
    grep -vE '^[[:space:]]*(#|$)' "$hosts_file" | grep -xF -f "$ready" > "$next"
    mv "$next" "$hosts_file"
    rm -f "$pending" "$ready"
    (( unsafe == 0 ))
}

# load_inventory_macs <csv>: hostname|eth0_mac for every row that has a MAC (owner 2026-10-21:
# every device is checked by its management MAC at key preparation).
load_inventory_macs() {
    awk -F',' '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                gsub(/[[:space:]]/, "", $i)
                if (tolower($i) == "hostname") hc = i
                if (tolower($i) == "eth0_mac") mc = i
            }
            if (!hc || !mc) exit 0
            next
        }
        {
            h = $hc; m = tolower($mc)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", h)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", m)
            if (h != "" && h !~ /^#/ && m ~ /^([0-9a-f][0-9a-f]:){5}[0-9a-f][0-9a-f]$/) print h "|" m
        }
    ' "$1" > "$INVENTORY_MACS"
}

inventory_mac() {
    awk -F'|' -v expected="$1" 'tolower($1) == tolower(expected) { print $2; exit }' "${INVENTORY_MACS:-/dev/null}"
}

# parse_csv_hosts — find the *.csv in $BASE, select device types from its filename
# or a --type override, and populate only the corresponding temp file.
# eth.csv: eth|eth_spx|spx for info, eth_spx|spx for link; ib.csv: type==ib;
# nvsw.csv: type==nvl.
parse_csv_hosts() {
    local csv="" csv_name="" mode=""
    # Only these canonical entry names select a collector mode.
    for _name in eth.csv ib.csv nvsw.csv; do
        _f="${BASE}/${_name}"
        [[ -f "$_f" ]] && { csv="$_f"; break; }
    done
    if [[ -z "$csv" ]]; then
        log "[CSV] WARN: no *.csv found in ${BASE}, host lists will be empty"
        return 1
    fi

    csv_name=$(basename "$csv")
    case "$csv_name" in
        eth.csv)
            mode="eth"
            ;;
        ib.csv)
            mode="ib"
            ;;
        nvsw.csv)
            mode="nvl"
            ;;
        *)
            log "[CSV] ERROR: unsupported CSV filename '${csv_name}' (expected eth.csv, ib.csv, or nvsw.csv)"
            return 1
            ;;
    esac

    # A managed cycle reads the worker's immutable input copy, never a second
    # live CSV revision. Dynamic runtime additions remain visible to the
    # collector, but the v2 emitter rejects any unbound target-count delta.
    if [[ -n "${CONTEXT_FILE:-}" ]]; then
        local frozen_csv
        frozen_csv=$(python3 - "$CONTEXT_FILE" <<'A4_CSV_PY'
import hashlib
import json
from pathlib import Path
import sys
context = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
path = Path(context["artifacts"]["input_inventory"])
content = path.read_bytes()
if hashlib.sha256(content).hexdigest() != context["input_inventory_sha256"]:
    raise SystemExit("frozen input inventory digest mismatch")
if not path.is_file() or path.is_symlink():
    raise SystemExit("frozen input inventory is not a regular file")
print(path)
A4_CSV_PY
) || return 1
        csv="$frozen_csv"
    fi

    load_inventory_macs "$csv"

    if [[ -n "$TYPE_FILTER" ]]; then
        case "${mode}:${TYPE_FILTER}" in
            eth:ethernet|eth:eth|eth:eth_spx|eth:spx|eth:air|ib:ib|ib:server_ufm|nvl:nvl) ;;
            *)
                log "[CSV] ERROR: --type ${TYPE_FILTER} is incompatible with ${csv_name}"
                return 1
                ;;
        esac
    fi

    if awk -F',' '
        function ipnum(value, parts) {
            if (split(value, parts, ".") != 4) return -1
            return (((parts[1] * 256 + parts[2]) * 256 + parts[3]) * 256 + parts[4])
        }
        function same_network(left, right, prefix, block) {
            if (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 32) return 0
            block = 2 ^ (32 - prefix)
            return int(ipnum(left) / block) == int(ipnum(right) / block)
        }
        NR==1 {
            for (i=1; i<=NF; i++) {
                gsub(/[[:space:]]/, "", $i)
                saved_header[i] = $i
                if (tolower($i) == "hostname") hc = i
                if (tolower($i) == "type")     tc = i
                if (tolower($i) == "eth0_ip")  ic = i
                if (tolower($i) == "eth0_mac") mc = i
            }
            if (!hc || !tc || !ic) exit 2
            if (tolower($(ic + 1)) == "netmask") nc = ic + 1
            next
        }
        {
            h = $hc; t = $tc; target = $ic
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", h)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", target)
            t = tolower(t)
            if (h == "" || h ~ /^#/) next
            fallback = ""
            prefix = nc ? $nc : ""
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", prefix)
            if (mode == "eth" && t != "air" && target != "" && tolower(target) != "na") {
                for (i=1; i<=NF; i++) {
                    if (tolower(saved_header[i]) != "svi_ip") continue
                    svi = $i; svi_prefix = $(i + 1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", svi)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", svi_prefix)
                    if (svi != "" && tolower(svi) != "na" &&
                            same_network(target, svi, prefix) && svi != target) {
                        fallback = svi
                        break
                    }
                }
                if (fallback != "") fallback_by_ip[target] = fallback
            }
            row_count++
            row_hostname[row_count] = h
            row_type[row_count] = t
            row_target[row_count] = target
            row_fallback[row_count] = fallback
            mac = mc ? $mc : ""
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", mac)
            row_mac[row_count] = tolower(mac)
        }
        END {
            # Emit only after every row has been inspected.  AIR rows may
            # precede their Production counterpart in a hand-maintained CSV;
            # a streaming emitter made their same-subnet SVI fallback depend
            # on row order.
            for (row = 1; row <= row_count; row++) {
                h = row_hostname[row]
                t = row_type[row]
                target = row_target[row]
                fallback = row_fallback[row]
                if (mode == "eth" && t == "air" && fallback_by_ip[target] != "") {
                    fallback = fallback_by_ip[target]
                }
                # A UFM is collected by its own phase (ufm-info.sh), never as a switch.
                if (mode == "ib" && t == "server_ufm" && (filter == "" || filter == "server_ufm")) {
                    # Skipped, not fatal: a UFM row never stops the IB switches.
                    if (target == "" || tolower(target) == "na") {
                        print "missing eth0_ip for UFM, not collected: " h > "/dev/stderr"
                        continue
                    }
                    print h "|" target > ufm_file
                    continue
                }
                selected = filter == "ethernet" ? (t == "eth" || t == "eth_spx" || t == "spx") \
                        : filter != "" ? t == filter \
                        : (mode == "eth" && (t == "eth" || t == "eth_spx" || t == "spx")) \
                        || (mode == "ib"  && t == "ib") \
                        || (mode == "nvl" && t == "nvl")
                if (!selected) continue
                if (target == "" || tolower(target) == "na") {
                    print "missing eth0_ip for selected device: " h > "/dev/stderr"
                    bad = 1
                    continue
                }
                endpoint = h "|" target (fallback != "" ? "|" fallback : "")
                if (mode == "eth") {
                    if (t == "eth" || t == "eth_spx" || t == "spx" || t == "air") print endpoint > eth_file
                    if (t == "eth_spx" || t == "spx") print endpoint > spx_file
                } else if (mode == "ib" && t == "ib") {
                    print endpoint > ib_file
                } else if (mode == "nvl" && t == "nvl") {
                    print endpoint > nv_file
                }
            }
            if (bad) exit 3
        }
    ' mode="$mode" filter="$TYPE_FILTER" eth_file="$ETH" spx_file="$SPX" ib_file="$IB" nv_file="$NV" \
      ufm_file="${UFM:-/dev/null}" "$csv"
    then
        :
    else
        local awk_rc=$?
        case "$awk_rc" in
            2) log "[CSV] ERROR: ${csv_name} must contain hostname, type, and eth0_ip columns" ;;
            3) log "[CSV] ERROR: ${csv_name} has selected device(s) missing eth0_ip (see stderr for hostname)" ;;
            *) log "[CSV] ERROR: ${csv_name} CSV parsing failed (awk exit ${awk_rc})" ;;
        esac
        return 1
    fi

    if [[ "$mode" == "eth" && "$TYPE_FILTER" == "air" ]]; then
        append_dynamic_air_hosts "$csv"
    fi
    # Runtime unknowns belong to the whole Production scope.  Exact static
    # subtype requests (eth/eth_spx/spx) must not gain unrelated targets.
    if [[ "$mode" == "eth" && "$COLLECTION_ENV" == "prod" \
          && "$TYPE_FILTER" == "ethernet" ]]; then
        append_unbound_prod_cumulus_hosts "$csv"
    fi

    local selected_count=0 selected_types=""
    case "$mode" in
        eth)
            selected_types=${TYPE_FILTER:-ethernet}
            [[ "$selected_types" == "ethernet" ]] && selected_types="eth|eth_spx|spx"
            selected_count=$(wc -l < "$ETH" | tr -d ' ')
            log "[CSV] ${csv_name} selected type=${selected_types}; loaded ${selected_count} info host(s), $(wc -l < "$SPX" | tr -d ' ') SPX link host(s)"
            ;;
        ib)
            selected_types=${TYPE_FILTER:-ib}
            # UFMs selected from the same ib.csv are devices of this lane too (a --type server_ufm
            # run selects no switch), so they keep the empty-lane guard below from firing.
            selected_count=$(( $(wc -l < "$IB" | tr -d ' ') + $(wc -l < "${UFM:-/dev/null}" | tr -d ' ') ))
            log "[CSV] ${csv_name} selected type=${selected_types}; loaded $(wc -l < "$IB" | tr -d ' ') IB host(s), $(wc -l < "${UFM:-/dev/null}" | tr -d ' ') UFM(s)"
            ;;
        nvl)
            selected_types=${TYPE_FILTER:-nvl}
            selected_count=$(wc -l < "$NV" | tr -d ' ')
            log "[CSV] ${csv_name} selected type=${selected_types}; loaded ${selected_count} NVL host(s)"
            ;;
    esac

    # An empty lane is almost always a stale code/link or missing derived
    # inventory.  Treat it as an error so a manual run and the ZTP monitor
    # handoff cannot report a false success.  The one deliberate exception is
    # a dynamic AIR inventory whose known devices currently have no resolved
    # address and therefore cannot yet enter the host file.
    if [[ "$selected_count" -eq 0 ]]; then
        if [[ "$TYPE_FILTER" == "air" && "$DYNAMIC_AIR_DISCOVERED" -gt 0 ]]; then
            log "[AIR-DYNAMIC] WARN: no AIR target currently has a resolved address; SSH collection skipped without failing the round"
            return 0
        fi
        log "[CSV] ERROR: lane type ${selected_types} selected 0 devices from ${csv}; verify the active project inventory and rerun setup/load"
        return 1
    fi
}

# ── Phase 1: key-based SSH validation and shared-key deployment ───────────────
# Legacy all-or-nothing implementation kept as a compatibility reference;
# the active deploy_ssh_keys below performs per-host failure classification.
# deploy_ssh_keys_legacy <hosts_file> <label> <ssh_user> <remote_dir>
# Tries public-key authentication first. During an interactive run, failures
# trigger one shared hidden password prompt (up to three attempts) through
# OpenSSH SSH_ASKPASS. Cron runs cannot prompt and fail with a clear message.
# Idempotent — SSH_KEY is appended only when it is not already present.
deploy_ssh_keys_legacy() {
    local hosts_file="$1" label="$2" user="$3" remote_dir="$4"
    local prepare_template command attempt read_status password_success=0
    log "[KEY] ── ${label}: validating key login and deploying shared key ──"

    prepare_template="
        if ssh __SSH_OPTIONS__ ${user}@__HOST__ \
            'actual_raw=\$(hostname -s 2>/dev/null || hostname)
             actual=\$(printf \"%s\" \"\$actual_raw\" | tr \"[:upper:]\" \"[:lower:]\")
             expected=\$(printf \"%s\" \"__NAME__\" | tr \"[:upper:]\" \"[:lower:]\")
	             if [[ \"\$expected\" != \"\$actual\" ]]; then
	                 echo \"[KEY][HOSTNAME-MISMATCH][ERROR] __HOST__: CSV=__NAME__, switch=\$actual_raw; rejecting target\" >&2
	                 exit 42
	             fi
             mkdir -p ~/.ssh && chmod 700 ~/.ssh
             grep -qxF \"${SSH_KEY}\" ~/.ssh/authorized_keys 2>/dev/null \
                 || echo \"${SSH_KEY}\" >> ~/.ssh/authorized_keys
             chmod 600 ~/.ssh/authorized_keys
             mkdir -p ${remote_dir}' 2>&1; then
            echo \"[KEY][OK]   __NAME__ (__HOST__)\"
        else
            rc=\$?
            echo \"[KEY][FAIL] __NAME__ (__HOST__): SSH authentication or remote preparation failed\" >&2
            exit \$rc
        fi
    "
    command=${prepare_template/__SSH_OPTIONS__/$SSH_OPTS}
    if run_parallel "$hosts_file" "$command"; then
        log "[KEY] ── ${label}: done (public-key authentication) ──"
        return 0
    fi

    log "[KEY] WARN: one or more ${label} hosts failed passwordless login"
    if [[ ! -t 0 && ! -t 1 && ! -t 2 ]]; then
        log "[KEY] ERROR: no interactive terminal is available for a password prompt"
        return 1
    fi

    create_ssh_askpass_helper || return 1
    command=${prepare_template/__SSH_OPTIONS__/$SSH_PASSWORD_OPTS}

    for attempt in 1 2 3; do
        MONITOR_SSH_PASSWORD=""
        if [[ -t 0 ]]; then
            IFS= read -r -s -p "$(key_device_kind "$label") ${user} 密码 (attempt ${attempt}/3): " MONITOR_SSH_PASSWORD
            read_status=$?
            printf '\n'
        else
            IFS= read -r -s -p "$(key_device_kind "$label") ${user} 密码 (attempt ${attempt}/3): " MONITOR_SSH_PASSWORD </dev/tty
            read_status=$?
            printf '\n' >/dev/tty
        fi
        if (( read_status != 0 )); then
            log "[KEY] ERROR: could not read the switch password"
            break
        fi
        if [[ -z "$MONITOR_SSH_PASSWORD" ]]; then
            log "[KEY] WARN: empty password was not used"
            continue
        fi
        export MONITOR_SSH_PASSWORD
        if run_parallel "$hosts_file" "$command"; then
            password_success=1
            break
        fi
        log "[KEY] WARN: password-assisted SSH preparation attempt ${attempt} failed"
    done

    unset MONITOR_SSH_PASSWORD SSH_ASKPASS SSH_ASKPASS_REQUIRE
    rm -f "$ASKPASS_FILE"
    ASKPASS_FILE=""
    if (( ! password_success )); then
        log "[KEY] ERROR: ${label} SSH preparation failed after password retries"
        return 1
    fi
    log "[KEY] ── ${label}: done (password fallback installed shared key) ──"
}

# Classify one SSH preparation attempt. Return 10 only when credentials were
# rejected; every transport/connectivity/remote-command failure returns 11.
prepare_ssh_host_resilient() {
    local entry="$1" user="$2" remote_dir="$3" ssh_options="$4"
    local name host fallback candidate output rc remote_command auth_failed=0
    local identity_record expected_mac expected_mac_plain identity_source mac_probe
    local candidates=()
    PREPARED_ENTRY=""
    IFS='|' read -r name host fallback <<< "$entry"
    [[ -n "$name" ]] || name="$host"
    [[ -n "$host" ]] || host="$name"
    if ! valid_host_entry "$name" "$host"; then
        echo "[KEY][UNREACHABLE] ${name} (${host}): unsafe hostname/IP entry" >&2
        return 11
    fi
    if [[ -n "$fallback" ]] && ! valid_host_entry "$name" "$fallback"; then
        echo "[KEY][UNREACHABLE] ${name} (${fallback}): unsafe fallback IP entry" >&2
        return 11
    fi
    identity_record=$(awk -F'|' -v expected="$name" '
        tolower($1) == tolower(expected) { print $2 "|" $3; exit }
    ' "$DYNAMIC_AIR_IDENTITIES")
    IFS='|' read -r expected_mac identity_source <<< "$identity_record"
    if [[ -z "$identity_record" ]]; then
        # Owner 2026-10-21: every inventory device is identified by its management MAC when the CSV has one.
        expected_mac=$(inventory_mac "$name")
        [[ -n "$expected_mac" ]] && identity_source="inventory eth0_mac"
    fi
    expected_mac_plain=$(printf '%s' "$expected_mac" \
        | tr -cd '[:xdigit:]' | tr '[:upper:]' '[:lower:]')
    if [[ -n "$identity_record" && ! "$expected_mac_plain" =~ ^[0-9a-f]{12}$ ]]; then
        echo "[KEY][UNREACHABLE] ${name} (${host}): invalid authoritative runtime eth0 MAC" >&2
        return 11
    fi
    [[ "$expected_mac_plain" =~ ^[0-9a-f]{12}$ ]] || expected_mac_plain=""
    # A switch is checked on eth0; a UFM's management port has another name, so any interface counts.
    if [[ "${KEY_MAC_SCOPE:-eth0}" == "any" ]]; then
        mac_probe="remote_mac_raw=\$(cat /sys/class/net/*/address 2>/dev/null | tr '\n' ' ')
remote_macs=\" \$(printf '%s' \"\$remote_mac_raw\" | tr -d ':' | tr '[:upper:]' '[:lower:]') \"
case \"\$remote_macs\" in *' ${expected_mac_plain} '*) remote_mac='${expected_mac_plain}' ;; *) remote_mac='' ;; esac"
    else
        mac_probe="remote_mac_raw=\$(cat /sys/class/net/eth0/address 2>/dev/null || true)
remote_mac=\$(printf '%s' \"\$remote_mac_raw\" | tr -cd '[:xdigit:]' | tr '[:upper:]' '[:lower:]')"
    fi
    remote_command="actual_raw=\$(hostname -s 2>/dev/null || hostname)
actual=\$(printf '%s' \"\$actual_raw\" | tr '[:upper:]' '[:lower:]')
expected=\$(printf '%s' '${name}' | tr '[:upper:]' '[:lower:]')
expected_mac='${expected_mac_plain}'
${mac_probe}
if [[ -n \"\$expected_mac\" && \"\$remote_mac\" != \"\$expected_mac\" ]]; then
  echo '[KEY][ETH0-MAC-MISMATCH][ERROR] ${host}: expected=${expected_mac_plain}, switch='\"\$remote_mac_raw\"'; rejecting target' >&2
  exit 43
fi
if [[ \"\$expected\" != \"\$actual\" && -z \"\$expected_mac\" ]]; then
  echo '[KEY][HOSTNAME-MISMATCH][ERROR] ${host}: CSV=${name}, switch='\"\$actual_raw\"'; rejecting target' >&2
  exit 42
fi
if [[ \"\${expected%%.*}\" != \"\${actual%%.*}\" ]]; then
  echo '[KEY][MAC-VERIFIED-HOSTNAME-TRANSITION][WARN] ${host}: inventory=${name}, switch='\"\$actual_raw\"', eth0_mac='\"\$remote_mac_raw\"', source=${identity_source}' >&2
fi
mkdir -p ~/.ssh && chmod 700 ~/.ssh
grep -qxF '${SSH_KEY}' ~/.ssh/authorized_keys 2>/dev/null || echo '${SSH_KEY}' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
mkdir -p '${remote_dir}'"
    candidates+=("$host")
    [[ -n "$fallback" && "$fallback" != "$host" ]] && candidates+=("$fallback")
    for candidate in "${candidates[@]}"; do
        # This worker is spawned from a ``while read`` host-list loop. Detach
        # SSH stdin, otherwise OpenSSH may consume and skip a later row.
        output=$(ssh -n $ssh_options "${user}@${candidate}" "$remote_command" 2>&1)
        rc=$?
        [[ -n "$output" ]] && printf '%s\n' "$output"
        if (( rc == 0 )); then
            PREPARED_ENTRY="${name}|${candidate}"
            if [[ "$candidate" == "$host" ]]; then
                echo "[KEY][OK]   ${name} (${candidate})"
            else
                echo "[KEY][OK][FALLBACK] ${name} (${host} -> ${candidate})"
            fi
            return 0
        fi
        # A reachable address returning the wrong hostname must never be
        # bypassed by trying another endpoint: identity protection wins.
        if (( rc == 42 )) || [[ "$output" == *"[HOSTNAME-MISMATCH][ERROR]"* ]]; then
            echo "[KEY][UNREACHABLE] ${name} (${candidate}): hostname identity mismatch" >&2
            return 11
        fi
        if (( rc == 43 )) || [[ "$output" == *"[ETH0-MAC-MISMATCH][ERROR]"* ]]; then
            echo "[KEY][UNREACHABLE] ${name} (${candidate}): management MAC identity mismatch" >&2
            return 11
        fi
        if [[ "$output" == *"Permission denied"* \
           || "$output" == *"Authentication failed"* \
           || "$output" == *"Too many authentication failures"* ]]; then
            auth_failed=1
        fi
    done
    if (( auth_failed )); then
        echo "[KEY][AUTH-FAILED] ${name} (${host}${fallback:+ / ${fallback}}): authentication rejected" >&2
        return 10
    fi
    echo "[KEY][UNREACHABLE] ${name} (${host}${fallback:+ / ${fallback}}): SSH transport or remote preparation failed" >&2
    return 11
}

prepare_ssh_batch_resilient() {
    local input="$1" ready="$2" auth_failed="$3" unavailable="$4"
    local user="$5" remote_dir="$6" ssh_options="$7" entry pids=() pid
    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
        (
            prepare_ssh_host_resilient "$entry" "$user" "$remote_dir" "$ssh_options"
            case $? in
                0)  printf '%s\n' "$PREPARED_ENTRY" >> "$ready" ;;
                10) printf '%s\n' "$entry" >> "$auth_failed" ;;
                *)  printf '%s\n' "$entry" >> "$unavailable" ;;
            esac
        ) &
        pids+=("$!")
        if (( ${#pids[@]} >= MAX_PARALLEL )); then
            for pid in "${pids[@]}"; do wait "$pid" || true; done
            pids=()
        fi
    done < "$input"
    for pid in "${pids[@]}"; do wait "$pid" || true; done
}

retain_prepared_hosts() {
    local dependent="$1" prepared="$2" filtered entry name selected
    filtered=$(mktemp) || return 1
    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
        IFS='|' read -r name _rest <<< "$entry"
        selected=$(awk -F'|' -v expected="$name" '$1 == expected { print; exit }' "$prepared")
        [[ -n "$selected" ]] && printf '%s\n' "$selected" >> "$filtered"
    done < "$dependent"
    mv "$filtered" "$dependent"
}

key_device_kind() {
    case "$1" in
        ETH) printf 'Ethernet 交换机' ;;
        IB)  printf 'InfiniBand 交换机' ;;
        NV)  printf 'NVLink 交换机' ;;
        UFM) printf 'UFM 服务器' ;;
        *)   printf '%s' "$1" ;;
    esac
}

# Resilient replacement for deploy_ssh_keys. It prompts only for genuine
# authentication rejection, removes unavailable targets from this collection,
# and succeeds as long as at least one target remains reachable.
deploy_ssh_keys() {
    local hosts_file="$1" label="$2" user="$3" remote_dir="$4" extra_opts="${5:-}"
    local ready auth_failed unavailable next_auth attempt read_status
    local prepared_count unavailable_count
    log "[KEY] ── ${label}: validating key login and deploying shared key ──"
    ready=$(mktemp) || return 1
    auth_failed=$(mktemp) || { rm -f "$ready"; return 1; }
    unavailable=$(mktemp) || { rm -f "$ready" "$auth_failed"; return 1; }
    prepare_ssh_batch_resilient "$hosts_file" "$ready" "$auth_failed" "$unavailable" \
        "$user" "$remote_dir" "$SSH_OPTS${extra_opts:+ $extra_opts}"

    if hosts_file_has_entries "$auth_failed"; then
        log "[KEY] WARN: $(hosts_file_entry_count "$auth_failed") ${label} host(s) rejected public-key authentication"
    elif hosts_file_has_entries "$unavailable"; then
        log "[KEY] WARN: no authentication failures; password prompt skipped"
    fi

    if hosts_file_has_entries "$auth_failed" && [[ ! -t 0 && ! -t 1 && ! -t 2 ]]; then
        log "[KEY] WARN: no interactive terminal for password authentication; affected hosts marked unavailable"
        cat "$auth_failed" >> "$unavailable"
        : > "$auth_failed"
    fi

    if hosts_file_has_entries "$auth_failed"; then
        create_ssh_askpass_helper || {
            rm -f "$ready" "$auth_failed" "$unavailable"
            return 1
        }
    fi

    for attempt in 1 2 3; do
        hosts_file_has_entries "$auth_failed" || break
        MONITOR_SSH_PASSWORD=""
        if [[ -t 0 ]]; then
            IFS= read -r -s -p "$(key_device_kind "$label") ${user} 密码 (attempt ${attempt}/3): " MONITOR_SSH_PASSWORD
            read_status=$?
            printf '\n'
        else
            IFS= read -r -s -p "$(key_device_kind "$label") ${user} 密码 (attempt ${attempt}/3): " MONITOR_SSH_PASSWORD </dev/tty
            read_status=$?
            printf '\n' >/dev/tty
        fi
        if (( read_status != 0 )); then
            log "[KEY] WARN: could not read the switch password; remaining hosts marked unavailable"
            break
        fi
        if [[ -z "$MONITOR_SSH_PASSWORD" ]]; then
            log "[KEY] WARN: empty password was not used"
            continue
        fi
        export MONITOR_SSH_PASSWORD
        next_auth=$(mktemp) || break
        prepare_ssh_batch_resilient "$auth_failed" "$ready" "$next_auth" "$unavailable" \
            "$user" "$remote_dir" "$SSH_PASSWORD_OPTS${extra_opts:+ $extra_opts}"
        mv "$next_auth" "$auth_failed"
        if hosts_file_has_entries "$auth_failed"; then
            log "[KEY] WARN: password attempt ${attempt} still rejected for $(hosts_file_entry_count "$auth_failed") host(s)"
        fi
    done

    unset MONITOR_SSH_PASSWORD SSH_ASKPASS SSH_ASKPASS_REQUIRE
    [[ -n "$ASKPASS_FILE" ]] && rm -f "$ASKPASS_FILE"
    ASKPASS_FILE=""
    hosts_file_has_entries "$auth_failed" && cat "$auth_failed" >> "$unavailable"
    mv "$ready" "$hosts_file"
    prepared_count=$(hosts_file_entry_count "$hosts_file")
    unavailable_count=$(hosts_file_entry_count "$unavailable")
    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
        if [[ "${KEY_FAILURE_SINK:-result}" == "log" ]]; then
            log "[KEY] ERROR: ${label} ${entry%%|*}: SSH authentication or transport unavailable"
        else
            record_device_failure "ssh_prepare" "$entry" "SSH authentication or transport unavailable"
        fi
    done < "$unavailable"
    rm -f "$auth_failed" "$unavailable"
    if (( unavailable_count > 0 )); then
        log "[KEY] WARN: ${unavailable_count} ${label} host(s) unavailable; continuing with ${prepared_count} reachable host(s)"
    fi
    if (( prepared_count == 0 )); then
        log "[KEY] WARN: no reachable ${label} hosts remain; other device families continue"
        return 0
    fi
    log "[KEY] ── ${label}: done; prepared=${prepared_count}, unavailable=${unavailable_count} ──"
}

# ── ETH collection (SN* switches) ────────────────────────────────────────────
collect_eth_info() {
    local ts dir
    ts=$(date -u "+%Y%m%d-%H%M")
    # Archive provenance is explicit; downstream code never guesses from the
    # returned hostname or reused management address.
    ts="${ts}-${COLLECTION_ENV:-prod}"
    dir=${BASE}/eth-info/${ts}
    mkdir -p "$dir"
    log "[ETH] ── start ── ${ts}"

    log "[ETH] deploying sw-info.sh"
    if ! run_parallel "$ETH" \
        "scp $SSH_OPTS $SWSH ${ETH_SSH_USER}@__HOST__:${ETH_REMOTE_DIR}/ 2>&1" \
        "collection" \
    ; then log "[ETH] ERROR: one or more deploys failed; skipping this phase"; return 1; fi
    if ! hosts_file_has_entries "$ETH"; then
        log "[ETH] WARN: no device survived script deployment"; rm -r -- "$dir"; return 0
    fi

    log "[ETH] triggering remote collection"
    if ! run_parallel "$ETH" \
        "ssh $SSH_OPTS ${ETH_SSH_USER}@__HOST__ \
             'cd ${ETH_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.info
              test -s monitor/sw-info.sh || exit 1
              nohup bash monitor/sw-info.sh </dev/null >/dev/null 2>&1 &'" \
        "collection" \
    ; then log "[ETH] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi
    if ! hosts_file_has_entries "$ETH"; then
        log "[ETH] WARN: no device survived collection trigger"; rm -r -- "$dir"; return 0
    fi

    if ! retrieve_when_ready "$ETH" "${ETH_SSH_USER}" "${ETH_REMOTE_DIR}" info "$dir" "$ETH_WAIT" "[ETH]"; then
        log "[ETH] ERROR: unsafe host entry while retrieving *.info files"; return 1
    fi
    if ! hosts_file_has_entries "$ETH"; then
        log "[ETH] WARN: no device returned an info file"; rm -r -- "$dir"; return 0
    fi

    local count expected
    count=$(find "$dir" -name "*.info" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$ETH")
    log "[ETH] collected ${count} info file(s)"
    if (( count != expected )); then log "[ETH] ERROR: expected ${expected} unique info files, got ${count}"; return 1; fi

    printf '{\n  "schema_version": 1,\n  "environment": "%s",\n  "collector": "cron.sh",\n  "collected_at": "%s",\n  "device_count": %s\n}\n' \
        "${COLLECTION_ENV:-prod}" "$(date -Iseconds)" "$count" > "${dir}/collection.json"

    archive_collection_dir "$dir" "[ETH]" || return 1
    ETH_ARCHIVE="${dir}.tar.gz"
    INFO_ARCHIVE="$ETH_ARCHIVE"
    log "[ETH] done → ${dir}.tar.gz"
}

# ── SPX collection (SN56** switches) ─────────────────────────────────────────
collect_spx_link() {
    local ts dir
    ts=$(date -u "+%Y%m%d-%H%M")
    dir=${BASE}/spx-link/${ts}
    mkdir -p "$dir"
    log "[SPX] ── start ── ${ts}"

    log "[SPX] deploying sw-link.sh"
    if ! run_parallel "$SPX" \
        "scp $SSH_OPTS $SWLSH ${ETH_SSH_USER}@__HOST__:${ETH_REMOTE_DIR}/ 2>&1" \
        "collection" \
    ; then log "[SPX] ERROR: one or more deploys failed; skipping this phase"; return 1; fi
    if ! hosts_file_has_entries "$SPX"; then
        log "[SPX] WARN: no device survived script deployment"; rm -r -- "$dir"; return 0
    fi

    log "[SPX] triggering remote collection"
    if ! run_parallel "$SPX" \
        "ssh $SSH_OPTS ${ETH_SSH_USER}@__HOST__ \
             'cd ${ETH_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.link
              test -s monitor/sw-link.sh || exit 1
              nohup bash monitor/sw-link.sh </dev/null >/dev/null 2>&1 &'" \
        "collection" \
    ; then log "[SPX] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi
    if ! hosts_file_has_entries "$SPX"; then
        log "[SPX] WARN: no device survived collection trigger"; rm -r -- "$dir"; return 0
    fi

    if ! retrieve_when_ready "$SPX" "${ETH_SSH_USER}" "${ETH_REMOTE_DIR}" link "$dir" "$SPX_WAIT" "[SPX]"; then
        log "[SPX] ERROR: unsafe host entry while retrieving *.link files"; return 1
    fi
    if ! hosts_file_has_entries "$SPX"; then
        log "[SPX] WARN: no device returned a link file"; rm -r -- "$dir"; return 0
    fi

    local count expected csv
    count=$(find "$dir" -name "*.link" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$SPX")
    log "[SPX] collected ${count} link file(s)"
    if (( count != expected )); then log "[SPX] ERROR: expected ${expected} unique link files, got ${count}"; return 1; fi

    # Merge all .link files into one CSV; keep only the first header line
    csv="${dir}.csv"
    # Owner 2026-10-22: a reader (the page, REQ7) only ever sees a complete CSV: built as .part, renamed.
    cat "${dir}"/*.link 2>/dev/null > "${csv}.raw.part"
    awk 'NR==1 { h=$0; print; next } $0 != h { print }' "${csv}.raw.part" \
        > "${csv}.part" && ln "${csv}.part" "$csv" 2>/dev/null \
        || { rm -f "${csv}.raw.part" "${csv}.part"; log "ERROR: ${csv} already exists or could not be written (not replaced)"; return 1; }
    rm -f "${csv}.raw.part" "${csv}.part"

    archive_collection_dir "$dir" "[SPX]" || return 1
    LINK_ARCHIVE="${dir}.tar.gz"
    LINK_CSV="$csv"
    log "[SPX] done → ${dir}.tar.gz  |  CSV → ${csv}"
}

# ── IB collection (InfiniBand switches) ──────────────────────────────────────
collect_ib_info() {
    local ts dir
    ts=$(date -u "+%Y%m%d-%H%M")
    dir=${BASE}/ib-info/${ts}
    mkdir -p "$dir"
    log "[IB]  ── start ── ${ts}"

    log "[IB]  deploying sw-info.sh"
    if ! run_parallel "$IB" \
        "scp $SSH_OPTS $SWSH ${IB_SSH_USER}@__HOST__:${IB_REMOTE_DIR}/ 2>&1" \
        "collection" \
    ; then log "[IB]  ERROR: one or more deploys failed; skipping this phase"; return 1; fi
    if ! hosts_file_has_entries "$IB"; then
        log "[IB] WARN: no device survived script deployment"; rm -r -- "$dir"; return 0
    fi

    log "[IB]  triggering remote collection"
    if ! run_parallel "$IB" \
        "ssh $SSH_OPTS ${IB_SSH_USER}@__HOST__ \
             'cd ${IB_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.info
              test -s monitor/sw-info.sh || exit 1
              nohup bash monitor/sw-info.sh </dev/null >/dev/null 2>&1 &'" \
        "collection" \
    ; then log "[IB]  ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi
    if ! hosts_file_has_entries "$IB"; then
        log "[IB] WARN: no device survived collection trigger"; rm -r -- "$dir"; return 0
    fi

    if ! retrieve_when_ready "$IB" "${IB_SSH_USER}" "${IB_REMOTE_DIR}" info "$dir" "$IB_WAIT" "[IB]"; then
        log "[IB]  ERROR: unsafe host entry while retrieving *.info files"; return 1
    fi
    if ! hosts_file_has_entries "$IB"; then
        log "[IB] WARN: no device returned an info file"; rm -r -- "$dir"; return 0
    fi

    local count expected
    count=$(find "$dir" -name "*.info" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$IB")
    log "[IB]  collected ${count} info file(s)"
    if (( count != expected )); then log "[IB]  ERROR: expected ${expected} unique info files, got ${count}"; return 1; fi

    archive_collection_dir "$dir" "[IB]" || return 1
    INFO_ARCHIVE="${dir}.tar.gz"
    IB_INFO_ARCHIVE=$INFO_ARCHIVE
    log "[IB]  done → ${dir}.tar.gz"
}

# ── IB link collection (InfiniBand switches) ─────────────────────────────────
collect_ib_link() {
    local ts dir
    ts=$(date -u "+%Y%m%d-%H%M")
    dir=${BASE}/ib-link/${ts}
    mkdir -p "$dir"
    log "[IBL] ── start ── ${ts}"

    log "[IBL] deploying sw-link.sh"
    if ! run_parallel "$IB" \
        "scp $SSH_OPTS $SWLSH ${IB_SSH_USER}@__HOST__:${IB_REMOTE_DIR}/ 2>&1" \
        "collection" \
    ; then log "[IBL] ERROR: one or more deploys failed; skipping this phase"; return 1; fi
    if ! hosts_file_has_entries "$IB"; then
        log "[IBL] WARN: no device survived script deployment"; rm -r -- "$dir"; return 0
    fi

    log "[IBL] triggering remote collection"
    if ! run_parallel "$IB" \
        "ssh $SSH_OPTS ${IB_SSH_USER}@__HOST__ \
             'cd ${IB_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.link
              test -s monitor/sw-link.sh || exit 1
              nohup bash monitor/sw-link.sh </dev/null >/dev/null 2>&1 &'" \
        "collection" \
    ; then log "[IBL] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi
    if ! hosts_file_has_entries "$IB"; then
        log "[IBL] WARN: no device survived collection trigger"; rm -r -- "$dir"; return 0
    fi

    if ! retrieve_when_ready "$IB" "${IB_SSH_USER}" "${IB_REMOTE_DIR}" link "$dir" "$IBL_WAIT" "[IBL]"; then
        log "[IBL] ERROR: unsafe host entry while retrieving *.link files"; return 1
    fi
    if ! hosts_file_has_entries "$IB"; then
        log "[IBL] WARN: no device returned a link file"; rm -r -- "$dir"; return 0
    fi

    local count expected csv
    count=$(find "$dir" -name "*.link" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$IB")
    log "[IBL] collected ${count} link file(s)"
    if (( count != expected )); then log "[IBL] ERROR: expected ${expected} unique link files, got ${count}"; return 1; fi

    # Merge all .link files into one CSV; keep only the first header line
    csv="${dir}.csv"
    # Owner 2026-10-22: a reader (the page, REQ7) only ever sees a complete CSV: built as .part, renamed.
    cat "${dir}"/*.link 2>/dev/null > "${csv}.raw.part"
    awk 'NR==1 { h=$0; print; next } $0 != h { print }' "${csv}.raw.part" \
        > "${csv}.part" && ln "${csv}.part" "$csv" 2>/dev/null \
        || { rm -f "${csv}.raw.part" "${csv}.part"; log "ERROR: ${csv} already exists or could not be written (not replaced)"; return 1; }
    rm -f "${csv}.raw.part" "${csv}.part"

    archive_collection_dir "$dir" "[IBL]" || return 1
    LINK_ARCHIVE="${dir}.tar.gz"
    LINK_CSV="$csv"
    log "[IBL] done → ${dir}.tar.gz  |  CSV → ${csv}"
}

# ── NV info collection (NVLink switches) ─────────────────────────────────────
collect_nv_info() {
    local ts dir
    ts=$(date -u "+%Y%m%d-%H%M")
    dir=${BASE}/nvsw-info/${ts}
    mkdir -p "$dir"
    log "[NV]  ── start ── ${ts}"

    log "[NV]  deploying sw-info.sh"
    if ! run_parallel "$NV" \
        "scp $SSH_OPTS $SWSH ${NV_SSH_USER}@__HOST__:${NV_REMOTE_DIR}/ 2>&1" \
        "collection" \
    ; then log "[NV]  ERROR: one or more deploys failed; skipping this phase"; return 1; fi
    if ! hosts_file_has_entries "$NV"; then
        log "[NV] WARN: no device survived script deployment"; rm -r -- "$dir"; return 0
    fi

    log "[NV]  triggering remote collection"
    if ! run_parallel "$NV" \
        "ssh $SSH_OPTS ${NV_SSH_USER}@__HOST__ \
             'cd ${NV_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.info
              test -s monitor/sw-info.sh || exit 1
              nohup bash monitor/sw-info.sh </dev/null >/dev/null 2>&1 &'" \
        "collection" \
    ; then log "[NV]  ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi
    if ! hosts_file_has_entries "$NV"; then
        log "[NV] WARN: no device survived collection trigger"; rm -r -- "$dir"; return 0
    fi

    if ! retrieve_when_ready "$NV" "${NV_SSH_USER}" "${NV_REMOTE_DIR}" info "$dir" "$NV_WAIT" "[NV]"; then
        log "[NV]  ERROR: unsafe host entry while retrieving *.info files"; return 1
    fi
    if ! hosts_file_has_entries "$NV"; then
        log "[NV] WARN: no device returned an info file"; rm -r -- "$dir"; return 0
    fi

    local count expected
    count=$(find "$dir" -name "*.info" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$NV")
    log "[NV]  collected ${count} info file(s)"
    if (( count != expected )); then log "[NV]  ERROR: expected ${expected} unique info files, got ${count}"; return 1; fi

    archive_collection_dir "$dir" "[NV]" || return 1
    INFO_ARCHIVE="${dir}.tar.gz"
    NV_INFO_ARCHIVE=$INFO_ARCHIVE
    log "[NV]  done → ${dir}.tar.gz"
}

# ── NV link collection (NVLink switches) ─────────────────────────────────────
collect_nv_link() {
    local ts dir
    ts=$(date -u "+%Y%m%d-%H%M")
    dir=${BASE}/nvsw-link/${ts}
    mkdir -p "$dir"
    log "[NVL] ── start ── ${ts}"

    log "[NVL] deploying sw-link.sh"
    if ! run_parallel "$NV" \
        "scp $SSH_OPTS $SWLSH ${NV_SSH_USER}@__HOST__:${NV_REMOTE_DIR}/ 2>&1" \
        "collection" \
    ; then log "[NVL] ERROR: one or more deploys failed; skipping this phase"; return 1; fi
    if ! hosts_file_has_entries "$NV"; then
        log "[NVL] WARN: no device survived script deployment"; rm -r -- "$dir"; return 0
    fi

    log "[NVL] triggering remote collection"
    if ! run_parallel "$NV" \
        "ssh $SSH_OPTS ${NV_SSH_USER}@__HOST__ \
             'cd ${NV_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.link
              test -s monitor/sw-link.sh || exit 1
              nohup bash monitor/sw-link.sh </dev/null >/dev/null 2>&1 &'" \
        "collection" \
    ; then log "[NVL] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi
    if ! hosts_file_has_entries "$NV"; then
        log "[NVL] WARN: no device survived collection trigger"; rm -r -- "$dir"; return 0
    fi

    if ! retrieve_when_ready "$NV" "${NV_SSH_USER}" "${NV_REMOTE_DIR}" link "$dir" "$NVL_WAIT" "[NVL]"; then
        log "[NVL] ERROR: unsafe host entry while retrieving *.link files"; return 1
    fi
    if ! hosts_file_has_entries "$NV"; then
        log "[NVL] WARN: no device returned a link file"; rm -r -- "$dir"; return 0
    fi

    local count expected csv
    count=$(find "$dir" -name "*.link" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$NV")
    log "[NVL] collected ${count} link file(s)"
    if (( count != expected )); then log "[NVL] ERROR: expected ${expected} unique link files, got ${count}"; return 1; fi

    # Merge all .link files into one CSV; keep only the first header line
    csv="${dir}.csv"
    # Owner 2026-10-22: a reader (the page, REQ7) only ever sees a complete CSV: built as .part, renamed.
    cat "${dir}"/*.link 2>/dev/null > "${csv}.raw.part"
    awk 'NR==1 { h=$0; print; next } $0 != h { print }' "${csv}.raw.part" \
        > "${csv}.part" && ln "${csv}.part" "$csv" 2>/dev/null \
        || { rm -f "${csv}.raw.part" "${csv}.part"; log "ERROR: ${csv} already exists or could not be written (not replaced)"; return 1; }
    rm -f "${csv}.raw.part" "${csv}.part"

    archive_collection_dir "$dir" "[NVL]" || return 1
    LINK_ARCHIVE="${dir}.tar.gz"
    LINK_CSV="$csv"
    log "[NVL] done → ${dir}.tar.gz  |  CSV → ${csv}"
}

# ── UFM collection (ib.csv type=server_ufm) ───────────────────────────────────
# Same flow as the switch collectors and run alongside them (owner 2026-10-21): ufm-info.sh with
# sw-info.sh, ufm-ibdiagnet.sh with sw-link.sh. Each is started before the switch phase and fetched
# after it. Isolated from the switch result: a UFM problem is logged and returned to main, never
# written to PLANNED_DEVICES or DEVICE_FAILURES (infiniband/monitor/UFM-MONITOR.md).
UFM_INFO_DIR=""
UFM_INFO_ARCHIVE=""        # the exact ufm-info archive published in this run, for the switch status
UFM_INFO_STARTED=0
UFM_TRIGGERED=()
UFM_IBDIAG_RUN_ID=""
UFM_IBDIAG_VIP=""
UFM_IBDIAG_STARTED=0
UFM_IBDIAG_ARCHIVE=""      # the exact archive fetched in this run, for the IB closed loop
UFM_CANDIDATES=$(mktemp)   # every server_ufm row: the VIP holder may be one that failed key preparation

ufm_ssh() {
    local host="$1"; shift
    ssh $SSH_OPTS $UFM_ALIVE_OPTS "${UFM_SSH_USER}@${host}" "$@" </dev/null 2>&1
}

# The server_ufm row whose management MAC is in the text (`ip -br link` from the VIP holder): "name|host".
# Owner 2026-10-22: a failover moves the VIP at any moment, so the holder is named in the same session
# that starts the collector, and everything after that talks to the node by its own address.
ufm_vip_holder() {
    local text="$1" name host mac
    while IFS='|' read -r name host _rest; do
        mac=$(inventory_mac "$name")
        if [[ "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] && printf '%s' "$text" | grep -qiF -- "$mac"; then
            valid_host_entry "$name" "$host" || return 1
            printf '%s|%s\n' "$name" "$host"
            return 0
        fi
    done < "$UFM_CANDIDATES"
    return 1
}

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Drop one rejected file, and only inside the two UFM data directories of this collector.
ufm_discard() {
    local path="$1"
    case "$path" in
        "${BASE}/ufm-info/"?*|"${BASE}/ufm-ibdiagnet/"?*) ;;
        *) log "[UFM] WARN: refusing to remove ${path:-<empty>} outside the UFM data directories"; return 1 ;;
    esac
    [[ "$path" != *..* && -n "${BASE}" ]] || return 1
    [[ ! -e "$path" ]] || rm -f -- "$path"
}

ufm_info_start() {
    local ts name host mac out
    local failed=0
    UFM_TRIGGERED=()
    UFM_INFO_DIR=""
    if [[ ! -d "${BASE}/ufm-info" ]]; then
        log "[UFM] ERROR: ${BASE}/ufm-info 不存在：UFM 数据目录链接应由 setup 预先创建；本次不采集 UFM"
        return 1
    fi
    if [[ ! -s "$UFM_INFO_SH" ]]; then
        log "[UFM] ERROR: missing collector ${UFM_INFO_SH}"
        return 1
    fi
    ts=$(date -u "+%Y%m%d-%H%M")
    UFM_INFO_DIR=${BASE}/ufm-info/${ts}
    mkdir -p "$UFM_INFO_DIR" || return 1
    log "[UFM] ── info start ── ${ts}"
    while IFS='|' read -r name host _rest; do
        [[ -z "$name" || "$name" =~ ^[[:space:]]*# ]] && continue
        mac=$(inventory_mac "$name")
        if ! valid_host_entry "$name" "$host"; then
            log "[UFM][REJECT] unsafe hostname/IP entry: ${name}|${host}"
            failed=1; continue
        fi
        if [[ ! "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
            log "[UFM] ERROR: ${name} (${host}): ib.csv 没有有效的 eth0_mac，无法核对身份，跳过"
            failed=1; continue
        fi
        if ! out=$(ufm_ssh "$host" "mkdir -p ${UFM_REMOTE_DIR} && rm -f ${UFM_REMOTE_DIR}/*.info") \
            || ! out=$(scp $SSH_OPTS $UFM_ALIVE_OPTS "$UFM_INFO_SH" "${UFM_SSH_USER}@${host}:${UFM_REMOTE_DIR}/" </dev/null 2>&1) \
            || ! out=$(ufm_ssh "$host" "cd ${UFM_REMOTE_DIR%/*} || exit 1
                 test -s monitor/ufm-info.sh || exit 1
                 nohup bash monitor/ufm-info.sh </dev/null >/dev/null 2>&1 &"); then
            log "[UFM] ERROR: ${name} (${host}): 部署或启动 ufm-info.sh 失败: $(printf '%s' "$out" | tail -n 1)"
            failed=1; continue
        fi
        UFM_TRIGGERED+=("${name}|${host}|${mac}")
    done < "$UFM"
    ufm_ha_start || failed=1
    UFM_INFO_STARTED=$SECONDS
    return "$failed"
}

# HA state (owner 2026-10-21): read only on the primary, through the VIP, next to the node snapshots.
# The node collector may still be running from monitor/ufm-info.sh on that machine, so the VIP copy
# goes to monitor/ha/ and never overwrites it. No answer on the VIP means HA is not set up yet.
UFM_HA_VIP=""
UFM_HA_NODE=""
UFM_HA_HOST=""
ufm_ha_start() {
    local vip rc out holder
    UFM_HA_VIP=""
    UFM_HA_NODE=""
    UFM_HA_HOST=""
    vip=$(ufm_vip); rc=$?
    if (( rc == 2 )); then
        log "[UFM] ERROR: ${BASE}/01-global.yaml 不存在：global 链接应由 setup 预先创建；不采集 HA 状态"
        return 1
    fi
    if (( rc != 0 )) || [[ -z "$vip" ]]; then
        log "[UFM] SKIPPED: global 中没有 servers.ufm.vip，不采集 HA 状态"
        return 0
    fi
    if ! out=$(ufm_ssh "$vip" "true"); then
        if printf '%s' "$out" | grep -qiE 'timed out|no route|refused|unreachable'; then
            log "[UFM] SKIPPED: VIP ${vip} 无应答（HA 未就绪），不采集 HA 状态"
            return 0
        fi
        log "[UFM] ERROR: 登录 VIP ${vip} 失败: $(printf '%s' "$out" | tail -n 1)"
        return 1
    fi
    if ! out=$(ufm_ssh "$vip" "mkdir -p ${UFM_REMOTE_DIR}/ha && rm -f ${UFM_REMOTE_DIR}/*.ha") \
        || ! out=$(scp $SSH_OPTS $UFM_ALIVE_OPTS "$UFM_INFO_SH" "${UFM_SSH_USER}@${vip}:${UFM_REMOTE_DIR}/ha/" </dev/null 2>&1) \
        || ! out=$(ufm_ssh "$vip" "cd ${UFM_REMOTE_DIR%/*} || exit 1
             test -s monitor/ha/ufm-info.sh || exit 1
             nohup bash monitor/ha/ufm-info.sh --ha </dev/null >/dev/null 2>&1 &
             ip -br link"); then
        log "[UFM] ERROR: 在 VIP ${vip} 上部署或启动 ufm-info.sh --ha 失败: $(printf '%s' "$out" | tail -n 1)"
        return 1
    fi
    if ! holder=$(ufm_vip_holder "$out"); then
        log "[UFM] ERROR: VIP ${vip} 所在设备不是 ib.csv 中的 UFM（管理口 MAC 不符），HA 状态不收录"
        return 1
    fi
    UFM_HA_VIP=$vip
    UFM_HA_NODE=${holder%%|*}
    UFM_HA_HOST=${holder#*|}
    log "[UFM] HA state: started on ${UFM_HA_NODE} (VIP ${vip})；之后经 ${UFM_HA_HOST} 取回，VIP 中途切换不影响"
}

# The HA state is kept under the UFM whose management MAC it shows (the VIP moves between them),
# fetched within the same info phase limit.
ufm_ha_fetch() {
    local part mac node="$UFM_HA_NODE" host="$UFM_HA_HOST" out checks=0 max_checks
    [[ -n "$UFM_HA_VIP" ]] || return 0   # skipped or not started: already reported
    part="${UFM_INFO_DIR}/.vip.ha.part"
    max_checks=$(( (UFM_WAIT - RETRIEVE_FIRST_WAIT) / RETRIEVE_POLL + 1 ))
    # From the node that ran it, by its own address: after a failover the VIP answers from the other
    # UFM, which may still keep the state it wrote when it was the primary.
    until ufm_ssh "$host" "ls ${UFM_REMOTE_DIR}/*.ha" >/dev/null; do
        checks=$((checks + 1))
        if (( checks >= max_checks || SECONDS - UFM_INFO_STARTED >= UFM_WAIT )); then
            log "[UFM] ERROR: ${UFM_WAIT}s 内 ${node} (${host}) 上没有生成 HA 状态"
            return 1
        fi
        sleep "$RETRIEVE_POLL"
    done
    mac=$(inventory_mac "$node")
    if ! out=$(scp $SSH_OPTS $UFM_ALIVE_OPTS "${UFM_SSH_USER}@${host}:${UFM_REMOTE_DIR}/*.ha" "$part" </dev/null 2>&1) \
        || ! grep -q '^# Collect complete$' "$part"; then
        log "[UFM] ERROR: 从 ${node} (${host}) 取回 HA 状态失败或不完整: $(printf '%s' "$out" | tail -n 1)"
        ufm_discard "$part"; return 1
    fi
    if [[ ! "$node" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || ! grep -qiF -- "$mac" "$part"; then
        log "[UFM] ERROR: 从 ${host} 取回的 HA 状态里没有 ${node} 的管理口 MAC，不收录"
        ufm_discard "$part"; return 1
    fi
    mv -- "$part" "${UFM_INFO_DIR}/${node}.ha" || { ufm_discard "$part"; return 1; }
    log "[UFM] HA state from ${node} (VIP ${UFM_HA_VIP}) collected"
}

ufm_info_fetch() {
    local entry name host mac out count snapshot checks=0 max_checks
    local failed=0
    local -a pending=() still=()
    [[ -n "$UFM_INFO_DIR" && -d "$UFM_INFO_DIR" ]] || return 1
    pending=("${UFM_TRIGGERED[@]}")
    # Owner 2026-10-21: one minute after the start, then every RETRIEVE_POLL seconds.
    (( SECONDS - UFM_INFO_STARTED < RETRIEVE_FIRST_WAIT )) \
        && sleep $(( RETRIEVE_FIRST_WAIT - (SECONDS - UFM_INFO_STARTED) ))
    max_checks=$(( (UFM_WAIT - RETRIEVE_FIRST_WAIT) / RETRIEVE_POLL + 1 ))
    while (( ${#pending[@]} )); do
        checks=$((checks + 1))
        still=()
        for entry in "${pending[@]}"; do
            IFS='|' read -r name host mac <<< "$entry"
            snapshot="${UFM_INFO_DIR}/${name}.info"
            if ! ufm_ssh "$host" "ls ${UFM_REMOTE_DIR}/*.info" >/dev/null; then
                still+=("$entry"); continue
            fi
            if ! out=$(scp $SSH_OPTS $UFM_ALIVE_OPTS "${UFM_SSH_USER}@${host}:${UFM_REMOTE_DIR}/*.info" "$snapshot" \
                    </dev/null 2>&1); then
                log "[UFM] ERROR: ${name} (${host}): 取回 ufm-info 快照失败: $(printf '%s' "$out" | tail -n 1)"
                ufm_discard "$snapshot"; failed=1; continue
            fi
            # cron.sh does not pin host keys, so the snapshot itself must show the CSV management MAC.
            if ! grep -qiF -- "$mac" "$snapshot" || ! grep -q '^# Collect complete$' "$snapshot"; then
                log "[UFM] ERROR: ${name} (${host}): 快照中没有 ib.csv 的 eth0_mac ${mac} 或不完整：连到的可能不是这台 UFM，不收录"
                ufm_discard "$snapshot"; failed=1; continue
            fi
            log "[UFM] ${name} (${host}): snapshot collected"
        done
        pending=("${still[@]}")
        (( ${#pending[@]} )) || break
        (( checks < max_checks && SECONDS - UFM_INFO_STARTED < UFM_WAIT )) || break
        sleep "$RETRIEVE_POLL"
    done
    for entry in "${pending[@]}"; do
        IFS='|' read -r name host mac <<< "$entry"
        log "[UFM] ERROR: ${name} (${host}): ${UFM_WAIT}s 内没有生成 ufm-info 快照"
        failed=1
    done
    ufm_ha_fetch || failed=1

    count=$(find "$UFM_INFO_DIR" -name '*.info' 2>/dev/null | wc -l | tr -d '[:space:]')
    if (( count == 0 )); then
        for snapshot in "$UFM_INFO_DIR"/*.ha; do
            [[ -e "$snapshot" ]] && ufm_discard "$snapshot"
        done
        rmdir -- "$UFM_INFO_DIR" 2>/dev/null
        log "[UFM] ERROR: 没有取回任何 UFM 快照"
        return 1
    fi
    archive_collection_dir "$UFM_INFO_DIR" "[UFM]" || return 1
    UFM_COLLECTED=1
    UFM_INFO_ARCHIVE="${UFM_INFO_DIR}.tar.gz"
    log "[UFM] done → ${UFM_INFO_DIR}.tar.gz (${count} UFM)"
    return "$failed"
}

# The VIP from the project global (setup link); exit 2 when the link is missing.
ufm_vip() {
    local global="${BASE}/01-global.yaml"
    [[ -f "$global" ]] || return 2
    python3 - "$global" <<'UFM_VIP_PY'
import ipaddress
import sys

import yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
for item in data.get("servers") or []:
    ufm = item.get("ufm") if isinstance(item, dict) else None
    if isinstance(ufm, dict) and ufm.get("vip"):
        print(ipaddress.IPv4Address(str(ufm["vip"]).strip()))
        break
UFM_VIP_PY
}

UFM_IBDIAG_NODE=""
UFM_IBDIAG_HOST=""
UFM_IBDIAG_KIND=ibdiagnet
UFM_IBDIAG_OUTCOME=""      # skipped | pending | ok | failed: what this run adds to the failure count
UFM_IBDIAG_STATE=""
UFM_RUN_STATUS=""          # skipped | failed | ok: what the run record says (an error before the start counts)
UFM_RUN_REASON=""
UFM_IBDIAG_DONE_FILE=""    # the UFM's .done kept beside the data, also when it says failed
UFM_IB_ANALYSIS=not_run    # ok | failed | not_run: infiniband/monitor/post-collect.py

ufm_ibdiag_error() {
    UFM_RUN_STATUS=failed
    UFM_RUN_REASON=$1
    log "[UFM-IBDIAG] ERROR: $1"
}

ufm_ibdiag_skip() {
    UFM_RUN_STATUS=skipped
    UFM_RUN_REASON=$1
    log "[UFM-IBDIAG] SKIPPED: $1"
}

# The consecutive-failure count: "failures since_probe" (both 0 when there is no state yet).
ufm_ibdiag_state() {
    local failures since
    failures=$(sed -n 's/^failures=//p' "$UFM_IBDIAG_STATE" 2>/dev/null | head -n 1)
    since=$(sed -n 's/^since_probe=//p' "$UFM_IBDIAG_STATE" 2>/dev/null | head -n 1)
    [[ "$failures" =~ ^[0-9]+$ ]] || failures=0
    [[ "$since" =~ ^[0-9]+$ ]] || since=0
    printf '%s %s\n' "$failures" "$since"
}

# After this run: ibdiagnet success clears the count, failure adds one; an iblinkinfo run only
# advances the countdown to the next ibdiagnet try. A skipped run (no VIP answer) changes nothing.
ufm_ibdiag_record() {
    local failures since part
    # pending: started on the VIP holder but never fetched, a failure like any other
    [[ -n "$UFM_IBDIAG_STATE" && "$UFM_IBDIAG_OUTCOME" =~ ^(ok|failed|pending)$ ]] || return 0
    [[ "$UFM_IBDIAG_OUTCOME" == pending ]] && UFM_IBDIAG_OUTCOME=failed
    read -r failures since < <(ufm_ibdiag_state)
    if [[ "$UFM_IBDIAG_KIND" == iblinkinfo ]]; then
        since=$((since + 1))
    elif [[ "$UFM_IBDIAG_OUTCOME" == ok ]]; then
        (( failures >= UFM_IBDIAG_FAIL_LIMIT )) && log "[UFM-IBDIAG] ibdiagnet 恢复成功：失败计数清零，之后仍采集 ibdiagnet"
        failures=0; since=0
    else
        failures=$((failures + 1)); since=0
        if (( failures == UFM_IBDIAG_FAIL_LIMIT )); then
            log "[UFM-IBDIAG] WARNING: ibdiagnet 已连续失败 ${failures} 次：之后改采 iblinkinfo，每 ${UFM_IBDIAG_RETRY_EVERY} 轮再试一次 ibdiagnet"
        else
            log "[UFM-IBDIAG] ibdiagnet 连续失败 ${failures} 次（达到 ${UFM_IBDIAG_FAIL_LIMIT} 次后改采 iblinkinfo）"
        fi
    fi
    part="${UFM_IBDIAG_STATE}.part"
    printf 'failures=%s\nsince_probe=%s\nupdated=%s\n' "$failures" "$since" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        > "$part" && mv -f "$part" "$UFM_IBDIAG_STATE"
}

ufm_ibdiag_start() {
    local vip rc out nonce holder failures since kind_arg=""
    UFM_IBDIAG_RUN_ID=""
    UFM_IBDIAG_NODE=""
    UFM_IBDIAG_HOST=""
    UFM_IBDIAG_KIND=ibdiagnet
    UFM_IBDIAG_OUTCOME=skipped
    UFM_IBDIAG_STATE=""
    UFM_RUN_STATUS=skipped
    UFM_RUN_REASON="本轮没有启动 ibdiagnet/iblinkinfo"
    UFM_IBDIAG_DONE_FILE=""
    UFM_IB_ANALYSIS=not_run
    if [[ ! -d "${BASE}/ufm-ibdiagnet" ]]; then
        ufm_ibdiag_error "${BASE}/ufm-ibdiagnet 不存在：数据目录链接应由 setup 预先创建"
        return 1
    fi
    UFM_IBDIAG_STATE="${BASE}/ufm-ibdiagnet/.ibdiagnet-state"
    if [[ ! -s "$UFM_IBDIAG_SH" ]]; then
        ufm_ibdiag_error "missing collector ${UFM_IBDIAG_SH}"
        return 1
    fi
    vip=$(ufm_vip); rc=$?
    if (( rc == 2 )); then
        ufm_ibdiag_error "${BASE}/01-global.yaml 不存在：global 链接应由 setup 预先创建"
        return 1
    fi
    if (( rc != 0 )) || [[ -z "$vip" ]]; then
        ufm_ibdiag_skip "global 中没有 servers.ufm.vip"
        return 0
    fi
    # Only the UFM that holds the VIP runs ibdiagnet; no answer means HA is not set up yet.
    if ! out=$(ufm_ssh "$vip" "true"); then
        if printf '%s' "$out" | grep -qiE 'timed out|no route|refused|unreachable'; then
            ufm_ibdiag_skip "VIP ${vip} 无应答（HA 未就绪）"
            return 0
        fi
        ufm_ibdiag_error "登录 VIP ${vip} 失败: $(printf '%s' "$out" | tail -n 1)"
        return 1
    fi
    nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
    UFM_IBDIAG_RUN_ID="$(date -u "+%Y%m%d-%H%M")-${COLLECTION_ENV:-prod}-${nonce}"
    if [[ ! "$UFM_IBDIAG_RUN_ID" =~ ^[0-9]{8}-[0-9]{4}-(prod|air)-[0-9a-f]{16}$ ]]; then
        ufm_ibdiag_error "invalid run-id ${UFM_IBDIAG_RUN_ID}"
        UFM_IBDIAG_RUN_ID=""
        return 1
    fi
    read -r failures since < <(ufm_ibdiag_state)
    if (( failures >= UFM_IBDIAG_FAIL_LIMIT && since < UFM_IBDIAG_RETRY_EVERY - 1 )); then
        UFM_IBDIAG_KIND=iblinkinfo
        kind_arg=" --iblinkinfo"
        log "[UFM-IBDIAG] ibdiagnet 已连续失败 ${failures} 次：本轮采集 iblinkinfo（第 $((since + 1)) 轮；第 ${UFM_IBDIAG_RETRY_EVERY} 轮再试 ibdiagnet）"
    elif (( failures >= UFM_IBDIAG_FAIL_LIMIT )); then
        log "[UFM-IBDIAG] ibdiagnet 已连续失败 ${failures} 次：本轮再试一次 ibdiagnet"
    fi
    UFM_IBDIAG_OUTCOME=failed   # from here on any error counts against this kind
    if ! out=$(ufm_ssh "$vip" "mkdir -p ${UFM_REMOTE_DIR}") \
        || ! out=$(scp $SSH_OPTS $UFM_ALIVE_OPTS "$UFM_IBDIAG_SH" "${UFM_SSH_USER}@${vip}:${UFM_REMOTE_DIR}/" </dev/null 2>&1) \
        || ! out=$(ufm_ssh "$vip" "cd ${UFM_REMOTE_DIR%/*} || exit 1
             test -s monitor/ufm-ibdiagnet.sh || exit 1
             nohup bash monitor/ufm-ibdiagnet.sh ${UFM_IBDIAG_RUN_ID}${kind_arg} </dev/null >/dev/null 2>&1 &
             ip -br link"); then
        ufm_ibdiag_error "在 VIP ${vip} 上部署或启动 ufm-ibdiagnet.sh 失败: $(printf '%s' "$out" | tail -n 1)"
        UFM_IBDIAG_RUN_ID=""
        return 1
    fi
    if ! holder=$(ufm_vip_holder "$out"); then
        ufm_ibdiag_error "VIP ${vip} 所在设备不是 ib.csv 中的 UFM（管理口 MAC 不符），不收录"
        UFM_IBDIAG_RUN_ID=""
        return 1
    fi
    UFM_IBDIAG_VIP=$vip
    UFM_IBDIAG_NODE=${holder%%|*}
    UFM_IBDIAG_HOST=${holder#*|}
    UFM_IBDIAG_STARTED=$SECONDS
    UFM_IBDIAG_OUTCOME=pending
    log "[UFM-IBDIAG] ${UFM_IBDIAG_KIND} started on ${UFM_IBDIAG_NODE} (VIP ${vip}): run-id ${UFM_IBDIAG_RUN_ID}；之后经 ${UFM_IBDIAG_HOST} 取回"
}

ufm_ibdiag_fetch() {
    local remote done_text node_text result kind run_id artifact sum reason rc size mac node local_path out
    local host="$UFM_IBDIAG_HOST" checks=0 max_checks prefix expected suffix
    [[ -n "$UFM_IBDIAG_RUN_ID" ]] || return 0   # skipped or not started: already reported
    if [[ "$UFM_IBDIAG_KIND" == iblinkinfo ]]; then
        prefix=iblinkinfo; expected="iblinkinfo_${UFM_IBDIAG_RUN_ID}.log"; suffix=iblinkinfo.log
        remote="${UFM_REMOTE_DIR}/iblinkinfo/iblinkinfo_${UFM_IBDIAG_RUN_ID}"
    else
        prefix=ibdiagnet; expected="ibdiagnet2_${UFM_IBDIAG_RUN_ID}.tgz"; suffix=ibdiagnet2.tgz
        remote="${UFM_REMOTE_DIR}/ibdiagnet/ibdiagnet2_${UFM_IBDIAG_RUN_ID}"
    fi
    # Owner 2026-10-22: the first check 5 minutes after the start, then every 30 s, at most 17 minutes;
    # the .done marker is written last, after the output is complete.
    max_checks=$(( (UFM_IBDIAG_WAIT - UFM_IBDIAG_FIRST_WAIT) / UFM_IBDIAG_POLL + 1 ))
    (( SECONDS - UFM_IBDIAG_STARTED < UFM_IBDIAG_FIRST_WAIT )) \
        && sleep $(( UFM_IBDIAG_FIRST_WAIT - (SECONDS - UFM_IBDIAG_STARTED) ))
    # From the node that runs it, by its own address: a failover may move the VIP meanwhile.
    while ! done_text=$(ufm_ssh "$host" "cat ${remote}.done"); do
        checks=$((checks + 1))
        if (( checks >= max_checks || SECONDS - UFM_IBDIAG_STARTED >= UFM_IBDIAG_WAIT )); then
            ufm_ibdiag_error "${UFM_IBDIAG_WAIT}s 内 ${UFM_IBDIAG_KIND} 没有完成（run-id ${UFM_IBDIAG_RUN_ID}）"
            return 1
        fi
        sleep "$UFM_IBDIAG_POLL"
    done
    field() { printf '%s\n' "$done_text" | sed -n "s/^$1=//p" | head -n 1; }
    result=$(field result); kind=$(field kind); run_id=$(field run_id); artifact=$(field artifact)
    sum=$(field sha256); reason=$(field reason); rc=$(field rc); size=$(field size)
    node=${UFM_IBDIAG_NODE%%.*}
    # Codex review 2026-10-22: a failed run is recorded too, never mistaken for "no fault": the UFM's
    # own .done is kept beside the data whatever it says (named like the data it would have described).
    if [[ "$node" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ && "$run_id" == "$UFM_IBDIAG_RUN_ID" ]]; then
        UFM_IBDIAG_DONE_FILE="${BASE}/ufm-ibdiagnet/${UFM_IBDIAG_RUN_ID}_${node}_${suffix%.*}.done"
        printf '%s\n' "$done_text" > "${UFM_IBDIAG_DONE_FILE}.part" \
            && mv -f "${UFM_IBDIAG_DONE_FILE}.part" "$UFM_IBDIAG_DONE_FILE" || UFM_IBDIAG_DONE_FILE=""
    fi
    if [[ "$result" != "ok" ]]; then
        # the collector's reason already carries its exit code
        ufm_ibdiag_error "${reason:-${UFM_IBDIAG_KIND} 采集失败（exit ${rc:-?}）}（run-id ${UFM_IBDIAG_RUN_ID}）"
        return 1
    fi
    if [[ "$kind" != "$UFM_IBDIAG_KIND" || "$run_id" != "$UFM_IBDIAG_RUN_ID" || "$artifact" != "$expected" \
          || ! "$sum" =~ ^[0-9a-f]{64}$ ]]; then
        ufm_ibdiag_error "完成标记内容无效（run-id ${UFM_IBDIAG_RUN_ID}）"
        return 1
    fi
    # The run records the node it ran on; it must be the one named at the start.
    if ! node_text=$(ufm_ssh "$host" "cat ${remote}.node"); then
        ufm_ibdiag_error "读不到执行节点身份 ${remote}.node"
        return 1
    fi
    mac=$(inventory_mac "$UFM_IBDIAG_NODE")
    if [[ ! "$node" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] || ! printf '%s' "$node_text" | grep -qiF -- "$mac"; then
        ufm_ibdiag_error "${host} 上的执行记录不是 ${UFM_IBDIAG_NODE} 的（管理口 MAC 不符），不收录"
        return 1
    fi
    # Owner 2026-10-22: run-id (minute timestamp included) first, so the retention cleanup bundles it
    # per day; then the real node, not the VIP; the UFM's completion record is kept beside it.
    local_path="${BASE}/ufm-ibdiagnet/${UFM_IBDIAG_RUN_ID}_${node}_${suffix}"
    if ! out=$(scp $SSH_OPTS $UFM_ALIVE_OPTS "${UFM_SSH_USER}@${host}:${remote%/*}/${artifact}" \
            "${local_path}.part" </dev/null 2>&1); then
        ufm_ibdiag_error "取回 ${artifact} 失败: $(printf '%s' "$out" | tail -n 1)"
        ufm_discard "${local_path}.part"
        return 1
    fi
    if [[ "$(file_sha256 "${local_path}.part")" != "$sum" \
          || "$(wc -c < "${local_path}.part" | tr -d ' ')" != "$size" ]]; then
        ufm_ibdiag_error "${artifact} 的 sha256 或大小与完成标记不符"
        ufm_discard "${local_path}.part"
        return 1
    fi
    if [[ "$prefix" == ibdiagnet ]] && ! tar -tzf "${local_path}.part" 2>/dev/null | grep -q '/ibdiagnet2\.net_dump$'; then
        ufm_ibdiag_error "${artifact} 里没有 ibdiagnet2.net_dump"
        ufm_discard "${local_path}.part"
        return 1
    fi
    # No clobber: a file of that name is never replaced (ln fails when it exists).
    if ! ln -- "${local_path}.part" "$local_path" 2>/dev/null; then
        ufm_discard "${local_path}.part"
        ufm_ibdiag_error "${local_path##*/} 已存在，不覆盖"
        return 1
    fi
    rm -f -- "${local_path}.part"
    UFM_COLLECTED=1
    UFM_IBDIAG_ARCHIVE=$local_path
    UFM_IBDIAG_OUTCOME=ok
    UFM_RUN_STATUS=ok
    UFM_RUN_REASON=""
    log "[UFM-IBDIAG] done → ${local_path}（${UFM_IBDIAG_KIND}，执行节点 ${node}）"
}

# ── UFM run record (codex review 2026-10-22) ──────────────────────────────────
# One record per IB-lane run that has server_ufm rows: what this run did with ibdiagnet/iblinkinfo,
# bound to the worker cycle when there is one. It names this run's own files only, so an older report
# can never stand in for a run that produced none. Written last, as .part and then renamed.
ufm_run_record_write() {
    local dir="${BASE}/ufm-ibdiagnet" record_id record
    [[ -d "$dir" ]] || return 0
    record_id=${UFM_IBDIAG_RUN_ID:-$(date -u "+%Y%m%d-%H%M")-${COLLECTION_ENV:-prod}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
    record="${dir}/${record_id}.ufm-run.json"
    if ! python3 - "$record.part" "${CONTEXT_FILE:-}" "$UFM_RUN_STATUS" "$UFM_RUN_REASON" "$UFM_IBDIAG_RUN_ID" \
            "${UFM_IBDIAG_NODE%%.*}" "$UFM_IBDIAG_KIND" "$UFM_IBDIAG_DONE_FILE" "$UFM_IBDIAG_ARCHIVE" \
            "$UFM_IB_ANALYSIS" "${BASE}/99-output-p2p" "$UFM_IBDIAG_STATE" <<'UFM_RUN_RECORD_PY'
import datetime, hashlib, json, os, sys

(target, context_file, status, reason, run_id, node, kind, done_file, data_file, analysis, reports,
 state_file) = sys.argv[1:]


def identity(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        content = handle.read()
    return {"name": os.path.basename(path), "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


cycle = None
if context_file and os.path.isfile(context_file):
    with open(context_file, encoding="utf-8") as stream:
        cycle = json.load(stream).get("identity")
report = receipt = None
if analysis == "ok" and run_id and node:
    stem = f"{run_id}_{node}-{kind}-topology-validation"
    report = identity(os.path.join(reports, stem + ".xlsx"))
    receipt = identity(os.path.join(reports, stem + ".receipt.json"))
    if report is None or receipt is None:
        analysis = "failed"
failures = None
if state_file and os.path.isfile(state_file):
    for line in open(state_file, encoding="utf-8"):
        if line.startswith("failures="):
            failures = int(line.split("=", 1)[1]) if line.split("=", 1)[1].strip().isdigit() else None
record = {
    "schema": "ufm-ib-run-record-v1",
    "cycle": cycle,
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "outcome": status or "skipped",
    "reason": reason,
    "run_id": run_id or None,
    "node": node if run_id else None,
    "kind": kind if run_id else None,
    "done": identity(done_file),
    "input": identity(data_file) if status == "ok" else None,
    "analysis": analysis if status == "ok" else "not_run",
    "report": report,
    "receipt": receipt,
    "ibdiagnet_failures_in_a_row": failures,
}
with open(target, "w", encoding="utf-8") as stream:
    json.dump(record, stream, ensure_ascii=False, indent=2)
    stream.write("\n")
UFM_RUN_RECORD_PY
    then
        rm -f -- "${record}.part"
        log "[UFM-IBDIAG] ERROR: 写运行记录失败: ${record}"
        return 1
    fi
    mv -f -- "${record}.part" "$record" && log "[UFM-IBDIAG] 运行记录 → ${record}（${UFM_RUN_STATUS}）" \
        && UFM_RUN_RECORD_FILE=$record
}
UFM_RUN_RECORD_FILE=""   # this run's record; the v2 emitter binds it to the worker cycle (REQ7 R1)

# ── Logs (owner 2026-10-22): whoever writes a log rotates it, with the shared tools/log_rotation.py ──
# cron.sh rotates only the log it writes, its lane's cronjob.log (a setup link into
# 99-output-monitor/<lane>/; the copies sit beside the real file). The page generator and the
# switch-collection worker rotate their own logs.
LOG_ROTATION="${BASE}/../../tools/log_rotation.py"

rotate_log() {   # rotate_log <file or link>
    local link="$1" size message
    [[ -f "$link" ]] || return 0
    size=$(wc -c < "$link" | tr -d ' ')
    (( size >= CRON_LOG_MAX_BYTES )) || return 0
    if message=$(python3 "$LOG_ROTATION" --max-bytes "$CRON_LOG_MAX_BYTES" --keep "$CRON_LOG_KEEP" "$link" 2>&1); then
        [[ -n "$message" ]] && log "[LOG] $message"
    else
        log "[LOG] WARN: ${message:-${link##*/} 压缩失败，原文件保留}"
    fi
}

# ── Shared report directory (codex review 2026-10-22) ─────────────────────────
# 99-output-p2p is written by the post-collect of every lane (Ethernet and IB reports with their
# provenance and receipts; the analysers write a report under its final name) and cleaned by whichever
# lane finishes. Its lock file sits inside the real directory, so every lane and every caller uses the
# same lock whatever its TMPDIR: writers hold it shared from the analysis to the receipt, the cleanup
# takes it exclusive and skips the round while anyone is writing.
REPORT_LOCK_WAIT=600   # seconds a writer waits for a cleanup in progress (bundling takes seconds)

report_lock_file() {   # report_lock_file <99-output-p2p path>
    local real
    real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1") || return 1
    [[ -d "$real" ]] || return 1
    printf '%s/.report-writer.lock\n' "$real"
}

with_report_writer() {   # with_report_writer <99-output-p2p path> <command> [args...]
    local lock
    if ! lock=$(report_lock_file "$1"); then
        shift
        "$@"   # no such directory: the post-collect reports it
        return
    fi
    shift
    ( flock -s -w "$REPORT_LOCK_WAIT" 9 || {
          log "[CLN] ERROR: 99-output-p2p 的清理在 ${REPORT_LOCK_WAIT}s 内没有结束，本轮不写报告"; exit 1; }
      "$@" ) 9>>"$lock"
}

cleanup_shared_reports() {   # cleanup_shared_reports <99-output-p2p path>
    local lock
    [[ -d "$1" ]] || return 0
    lock=$(report_lock_file "$1") || return 0
    ( flock -n 9 || { log "[CLN] 99-output-p2p 正在写报告（或另一个 lane 正在清理），本轮跳过清理"; exit 0; }
      cleanup_data_dirs "$1" ) 9>>"$lock"
}

# ── Archiving of the data directories (owner 2026-10-22: one module, tools/collection_archive.py) ──
# cleanup_data_dirs <dir> [<dir> ...]: every file named YYYYMMDD-... follows one rule (RETAIN_DAYS):
# today's stay, the previous days are bundled per day into YYYYMMDD-daily.tar.gz with an index (CSVs
# stay loose for the page), older days are deleted; a file arriving after its day was bundled stays
# beside the bundle; failed collector batch directories past the window are removed; the newest file of
# each kind always stays loose (owner 2026-10-23). The module prints one line per action and they go to
# this run's log.
COLLECTION_ARCHIVE="${BASE}/../../tools/collection_archive.py"

cleanup_data_dirs() {
    local output line
    if ! output=$(python3 "$COLLECTION_ARCHIVE" --retain-days "$RETAIN_DAYS" "$@" 2>&1); then
        log "[CLN] WARN: ${COLLECTION_ARCHIVE##*/} 失败，本轮未整理: ${output##*$'\n'}"
        return 0
    fi
    while IFS= read -r line; do
        [[ -n "$line" ]] && log "$line"
    done <<< "$output"
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "========== cron start =========="

if ! detect_eth_environment; then
    log "[ENV] ERROR: environment selection failed, aborting"
    exit 1
fi

if [[ -n "$CONTEXT_FILE" && -z "$EMIT_TARGET_PLAN_FD" ]] && \
    python3 - "$CONTEXT_FILE" "$ETH" "$SPX" "$IB" "$NV" "$DYNAMIC_AIR_IDENTITIES" "$UFM" <<'A4_SNAPSHOT_PY'
import hashlib, ipaddress, json, re, sys
from pathlib import Path
context = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
plan = context.get("target_plan")
if plan is None:
    raise SystemExit(1)
content = (json.dumps(plan, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False) + "\n").encode()
if hashlib.sha256(content).hexdigest() != context.get("target_plan_sha256"):
    raise SystemExit("target plan digest mismatch")
# "ufm": the server_ufm rows of the infiniband slot (owner 2026-10-21); empty in the other slots.
if not isinstance(plan, dict) or set(plan) != {"eth", "spx", "ib", "nv", "dynamic_identities", "ufm"}:
    raise SystemExit("target plan shape mismatch")
for key, filename in zip(("eth", "spx", "ib", "nv", "dynamic_identities", "ufm"), sys.argv[2:]):
    rows = plan[key]
    if not isinstance(rows, list) or len(rows) > 10000:
        raise SystemExit("invalid target plan rows")
    for row in rows:
        if not isinstance(row, str) or any(c in row for c in "\r\n\x00"):
            raise SystemExit("invalid target plan row")
        pieces = row.split("|")
        if not pieces or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", pieces[0]):
            raise SystemExit("invalid target plan hostname")
        if key != "dynamic_identities":
            if len(pieces) not in (2, 3):
                raise SystemExit("invalid target plan endpoint")
            for endpoint in pieces[1:]:
                ipaddress.IPv4Address(endpoint)
    Path(filename).write_text("".join(row + "\n" for row in rows), encoding="utf-8")
A4_SNAPSHOT_PY
then
    log "[A4] loaded frozen target plan without re-reading target sources"
    # The identity table comes from the worker's immutable inventory copy, digest-checked.
    if frozen_csv=$(python3 - "$CONTEXT_FILE" <<'A4_MACS_PY'
import hashlib
import json
from pathlib import Path
import sys
context = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
path = Path(context["artifacts"]["input_inventory"])
if hashlib.sha256(path.read_bytes()).hexdigest() != context["input_inventory_sha256"]:
    raise SystemExit("frozen input inventory digest mismatch")
print(path)
A4_MACS_PY
    ); then
        load_inventory_macs "$frozen_csv"
    else
        log "[A4] WARN: frozen inventory unavailable for MAC identity; hostname identity is used"
    fi
else
    if [[ -n "$CONTEXT_FILE" && -z "$EMIT_TARGET_PLAN_FD" ]] && \
       python3 - "$CONTEXT_FILE" <<'A4_PLAN_PY'
import json, sys
from pathlib import Path
context = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
raise SystemExit(0 if "target_plan" in context else 1)
A4_PLAN_PY
    then
        log "[A4] ERROR: invalid frozen target plan"
        exit 1
    fi
    if ! parse_csv_hosts; then
        log "[CSV] ERROR: host parsing failed, aborting"
        exit 1
    fi
fi
if [[ -n "$EMIT_TARGET_PLAN_FD" ]]; then
    if ! python3 - "$ETH" "$SPX" "$IB" "$NV" "$DYNAMIC_AIR_IDENTITIES" "$UFM" \
            >&"$EMIT_TARGET_PLAN_FD" <<'A4_TARGET_PY'
import json, sys
from pathlib import Path
names = ("eth", "spx", "ib", "nv", "dynamic_identities", "ufm")
plan = {name: Path(path).read_text(encoding="utf-8").splitlines()
        for name, path in zip(names, sys.argv[1:])}
print(json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
A4_TARGET_PY
    then
        log "[A4] ERROR: target plan write failed"
        exit 1
    fi
    exit 0
fi
record_planned_devices

# UFM appliances (ib.csv type=server_ufm) run alongside the IB switches: ufm-info.sh with
# sw-info.sh, ufm-ibdiagnet.sh with sw-link.sh. Their problems never touch the switch result.
ufm_failed=0
ufm_active=0
UFM_COLLECTED=0
if hosts_file_has_entries "$UFM"; then
    if [[ ! -d "${BASE}/ufm-info" && ! -d "${BASE}/ufm-ibdiagnet" ]]; then
        log "[UFM] ERROR: ${BASE}/ufm-info 与 ufm-ibdiagnet 都不存在：数据目录链接应由 setup 预先创建；本次不连接任何 UFM"
        ufm_failed=1
    else
        ufm_active=1
        UFM_PLANNED=$(wc -l < "$UFM" | tr -d ' ')
        cp "$UFM" "$UFM_CANDIDATES"
    fi
fi

# Validate key login and prepare remote directories before starting any timed job.
# Abort on failure so the script does not wait for jobs that could not be deployed.
key_prepare_failed=0
if hosts_file_has_entries "$ETH"; then
    deploy_ssh_keys "$ETH" "ETH" "$ETH_SSH_USER" "$ETH_REMOTE_DIR" || key_prepare_failed=1
    retain_prepared_hosts "$SPX" "$ETH" || key_prepare_failed=1
fi
if hosts_file_has_entries "$IB"; then
    deploy_ssh_keys "$IB" "IB" "$IB_SSH_USER" "$IB_REMOTE_DIR" || key_prepare_failed=1
fi
if hosts_file_has_entries "$NV"; then
    deploy_ssh_keys "$NV" "NV" "$NV_SSH_USER" "$NV_REMOTE_DIR" || key_prepare_failed=1
fi
if (( key_prepare_failed )); then
    log "[KEY] ERROR: SSH preparation failed; aborting collection"
    exit 1
fi
# UFM: the same key preparation (key first, then a password on an interactive run, then the key is
# deployed) and the management-MAC identity check; its problems stay out of the switch result.
if (( ufm_active )); then
    KEY_MAC_SCOPE=any
    KEY_FAILURE_SINK=log
    deploy_ssh_keys "$UFM" "UFM" "$UFM_SSH_USER" "$UFM_REMOTE_DIR" "$UFM_ALIVE_OPTS" || ufm_failed=1
    KEY_MAC_SCOPE=eth0
    KEY_FAILURE_SINK=result
    if [[ "$(wc -l < "$UFM" | tr -d ' ')" -lt "$UFM_PLANNED" ]]; then
        ufm_failed=1
    fi
    hosts_file_has_entries "$UFM" || ufm_active=0
fi

# AIR Cumulus VX nodes still participate in ETH information collection, but
# must not run the hardware-only SPX link collector.
if hosts_file_has_entries "$SPX"; then
    if ! exclude_vx_from_spx "$SPX" "$ETH_SSH_USER"; then
        log "[SPX] ERROR: platform filtering failed; aborting collection"
        exit 1
    fi
fi


collection_failed=0

# SN* → ETH info collection
if hosts_file_has_entries "$ETH"; then collect_eth_info || collection_failed=1; fi
# SN56* → SPX link collection
if hosts_file_has_entries "$SPX"; then collect_spx_link || collection_failed=1; fi

# IB switches → IB info + IB link collection
(( ufm_active )) && { ufm_info_start || ufm_failed=1; }
if hosts_file_has_entries "$IB"; then collect_ib_info || collection_failed=1; fi
(( ufm_active )) && { ufm_info_fetch || ufm_failed=1; }
(( ufm_active )) && { ufm_ibdiag_start || ufm_failed=1; }
if hosts_file_has_entries "$IB"; then collect_ib_link || collection_failed=1; fi
(( ufm_active )) && { ufm_ibdiag_fetch || ufm_failed=1; }
(( ufm_active )) && ufm_ibdiag_record

# NV switches → NV info + NV link collection
if hosts_file_has_entries "$NV"; then collect_nv_info || collection_failed=1; fi
if hosts_file_has_entries "$NV"; then collect_nv_link || collection_failed=1; fi

# Close the Ethernet data path with the exact archive produced by this run.
# Never discover "latest" here: AIR and Production archives can coexist and
# another collector may publish a newer file while this process is running.
if [[ -n "$ETH_ARCHIVE" ]]; then
    if [[ ! -f "$POST_COLLECT" ]]; then
        log "[ETH-CLOSED-LOOP] ERROR: missing post-collection script: $POST_COLLECT"
        collection_failed=1
    else
        post_args=(--archive "$ETH_ARCHIVE" --environment "${COLLECTION_ENV:-prod}")
        activity_context=0
        if [[ -n "$CONTEXT_FILE" ]] && python3 - "$CONTEXT_FILE" <<'ACTIVITY_CONTEXT_PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    context = json.load(stream)
raise SystemExit(0 if "activity" in context else 1)
ACTIVITY_CONTEXT_PY
        then
            # Bash does not guarantee inherited high-numbered descriptors
            # survive the next exec. Duplicate the worker-owned regular FD
            # onto stdin for this one child; the analyzer inherits it again.
            post_args+=(--worker-context-fd 0)
            activity_context=1
        fi
        post_rc=0
        # its report goes into the shared 99-output-p2p (through the lldp tool's setup link)
        eth_reports="${BASE}/../../tools/lldp-analyze-tool/99-output-p2p"
        if (( activity_context )); then
            with_report_writer "$eth_reports" python3 "$POST_COLLECT" "${post_args[@]}" <&"$WORKER_CONTEXT_FD" \
                || post_rc=$?
        else
            with_report_writer "$eth_reports" python3 "$POST_COLLECT" "${post_args[@]}" || post_rc=$?
        fi
        if (( post_rc )); then
            log "[ETH-CLOSED-LOOP] ERROR: validation report or monitor.html refresh failed"
            collection_failed=1
        fi
    fi
elif [[ -n "$INFO_ARCHIVE$LINK_ARCHIVE" ]] || (( UFM_COLLECTED )); then
    # IB/NV switch info and link CSVs are already the monitor page's canonical
    # inputs.  They need no second analyzer, but a standalone cron run must
    # still publish the newly collected state into monitor.html.  Owner
    # 2026-10-21: many collectors run (eth/ib/nvl info and link, UFM), so any
    # data collected in this run is published even when another part failed.
    # IB closed loop (owner 2026-10-21, modelled on Ethernet): this run's exact
    # UFM ibdiagnet archive becomes the IB Link Validation report first.  A
    # failed analysis is a UFM warning; the page is refreshed regardless.
    if [[ -n "$UFM_IBDIAG_ARCHIVE" ]]; then
        UFM_IB_ANALYSIS=failed
        if [[ ! -f "$POST_COLLECT" ]]; then
            log "[IB-CLOSED-LOOP] ERROR: missing post-collection script: $POST_COLLECT"
            ufm_failed=1
        elif ! with_report_writer "${BASE}/99-output-p2p" python3 "$POST_COLLECT" --archive "$UFM_IBDIAG_ARCHIVE"; then
            log "[IB-CLOSED-LOOP] ERROR: IB validation report failed; monitor.html is refreshed without it"
            ufm_failed=1
        else
            UFM_IB_ANALYSIS=ok
        fi
    fi
    if [[ ! -f "$HTML_GENERATOR" ]]; then
        log "[MONITOR-HTML] ERROR: missing generator: $HTML_GENERATOR"
        collection_failed=1
    elif ! python3 "$HTML_GENERATOR" --type "${COLLECTION_ENV:-prod}"; then
        log "[MONITOR-HTML] ERROR: monitor.html refresh failed"
        collection_failed=1
    else
        log "[MONITOR-HTML] refreshed scope=${COLLECTION_ENV:-prod}"
    fi
fi

# Switch status (owner 2026-10-23): the production ETH/IB/NVL switches and UFM servers with a problem in
# this run (not collected, PSU/FAN, ASIC/PSU temperature, system health) are prepared as rows of the
# online Issue Tracker's ETH&IB Switch sheet, 99-output-monitor/<network>/issue-tracker/<type>-switch-status.json,
# until CableTracker can sync that sheet; nothing is sent. Each type gets this run's exact archive, or
# --no-archive, and the devices planned before any dropped out. Its result never changes this collection's.
SWITCH_STATUS=${BASE}/../../monitor/issue-tracker/switch-status.py
switch_status() {
    local kind=$1 archive=$2 planned=$3 rc=0 output line
    local source=(--no-archive)
    [[ -f "$SWITCH_STATUS" ]] || { log "[SWITCH-STATUS] WARNING: missing $SWITCH_STATUS"; return 0; }
    [[ -n "$archive" ]] && source=(--archive "$archive")
    output=$(python3 "$SWITCH_STATUS" --type "$kind" "${source[@]}" --planned "$planned" 2>&1) || rc=$?
    while IFS= read -r line; do
        [[ -n "$line" ]] && log "$line"
    done <<< "$output"
    (( rc == 0 )) || log "[SWITCH-STATUS] WARNING: ${kind} exited ${rc}"
    return 0
}
if [[ "${COLLECTION_ENV:-prod}" == prod ]]; then
    switch_status eth "$ETH_ARCHIVE" "$PLANNED_DEVICES"
    switch_status ib "$IB_INFO_ARCHIVE" "$PLANNED_DEVICES"
    switch_status nvl "$NV_INFO_ARCHIVE" "$PLANNED_DEVICES"
    # every UFM planned in this run, also when key preparation failed on all of them (ufm_active is then 0)
    [[ -s "$UFM_CANDIDATES" ]] && switch_status ufm "$UFM_INFO_ARCHIVE" "$UFM_CANDIDATES"
fi

# REQ7 (owner 2026-10-23): collection, analysis and display are followed by preparing this run's
# production link results for the online Issue Tracker and syncing them through the CableTracker
# engine. issue-tracker-sync.py itself checks the project's 01-global.yaml (common.mgmt.issue-tracker:
# status, spreadsheet_id, credentials) and does nothing when the sync is not enabled; an unchanged
# input is skipped in seconds. It keeps its own log (99-output-monitor/issue-tracker-sync.log) and
# its result never changes this collection's result.
ISSUE_TRACKER_SYNC=${BASE}/../../monitor/issue-tracker/issue-tracker-sync.py
issue_tracker_sync() {
    local domain=$1 engine_python=python3 rc=0
    [[ -f "$ISSUE_TRACKER_SYNC" ]] || { log "[ISSUE-TRACKER] WARNING: missing $ISSUE_TRACKER_SYNC"; return 0; }
    # The engine needs the Google/OpenAI client closure of infra/docker/requirements-issue-tracker-engine.txt.
    # Container: the image installs it into /opt/http-ztp/venv. activate.py is image-coupled, so every Docker
    # host must rebuild the image (deploy.sh build, with PyPI access) before it loads a release carrying it.
    # Native: ~/.venvs/http/cabletracker of the user who runs 11-load.py (its switch-collection worker runs
    # this script), created by that user with: python3 infra/deps.py install --target venv-cabletracker.
    # That venv is used only when nobody else can change it: every directory from $HOME/.venvs down to bin
    # and the resolved interpreter (and its directory) belong to this uid or root, are not group/other
    # writable and no directory is a symlink. Otherwise python3 is used, the reason is logged once per run,
    # and the engine fails at import (the WARNING below).
    if [[ -x /opt/http-ztp/venv/bin/python ]]; then
        engine_python=/opt/http-ztp/venv/bin/python
    elif [[ -n ${HOME:-} && -e $HOME/.venvs/http/cabletracker/bin/python ]]; then
        local venv_python=$HOME/.venvs/http/cabletracker/bin/python venv_reason="" venv_path resolved uid
        uid=$(id -u)
        resolved=$(readlink -f "$venv_python" 2>/dev/null) || resolved=""
        for venv_path in "$HOME/.venvs" "$HOME/.venvs/http" "$HOME/.venvs/http/cabletracker" \
                         "$HOME/.venvs/http/cabletracker/bin" "${resolved%/*}" "$resolved"; do
            if [[ -z $venv_path || -L $venv_path ]] || [[ -z $(find "$venv_path" -maxdepth 0 \
                    \( -user "$uid" -o -user 0 \) ! -perm -020 ! -perm -002 -print 2>/dev/null) ]]; then
                venv_reason="${venv_path:-the interpreter} is a symlink, not owned by uid $uid or root, or group/other writable"
                break
            fi
        done
        [[ -z $venv_reason && ! -x $resolved ]] && venv_reason="$resolved is not executable"
        if [[ -z $venv_reason ]]; then
            engine_python=$venv_python
        elif [[ -z ${ISSUE_TRACKER_VENV_NOTE:-} ]]; then
            ISSUE_TRACKER_VENV_NOTE=logged
            log "[ISSUE-TRACKER] WARNING: not using $venv_python ($venv_reason); the engine runs with python3"
        fi
    fi
    python3 "$ISSUE_TRACKER_SYNC" --only "$domain" --engine-python "$engine_python" >/dev/null 2>&1 || rc=$?
    case "$rc" in
        0) log "[ISSUE-TRACKER] ${domain}: done (see 99-output-monitor/issue-tracker-sync.log)" ;;
        75) log "[ISSUE-TRACKER] ${domain}: another sync is running; skipped" ;;
        *) log "[ISSUE-TRACKER] WARNING: ${domain} sync exited ${rc} (see 99-output-monitor/issue-tracker-sync.log)" ;;
    esac
    return 0
}
if [[ "${COLLECTION_ENV:-prod}" == prod ]]; then
    [[ -n "$ETH_ARCHIVE" ]] && issue_tracker_sync eth
    [[ -n "$UFM_IBDIAG_ARCHIVE" ]] && issue_tracker_sync ib
fi

(( ufm_active )) && { ufm_run_record_write || ufm_failed=1; }

cleanup_data_dirs \
    "${BASE}/eth-info"  \
    "${BASE}/spx-link"  \
    "${BASE}/ib-info"   \
    "${BASE}/ib-link"   \
    "${BASE}/nvsw-info" \
    "${BASE}/nvsw-link" \
    "${BASE}/ufm-info"  \
    "${BASE}/ufm-ibdiagnet"
rotate_log "${BASE}/cronjob.log"   # only the log cron.sh writes; the others rotate their own
# Owner 2026-10-22: the dated reports in 99-output-p2p follow the same retention; the CVT and the P2P
# outputs carry no date and are never touched.
MONITOR_DIR=${BASE}/../../monitor
cleanup_shared_reports "${MONITOR_DIR}/99-output-p2p"

if (( collection_failed )); then
    emit_failed_collection_result
    log "========== cron finish with errors =========="
    exit 1
fi
RESULT_FILE=$(mktemp) || exit 1
if emit_collection_result > "$RESULT_FILE"; then
    result_rc=0
else
    result_rc=$?
fi
if (( result_rc != 0 )); then
    cat "$RESULT_FILE"
    log "========== cron finish: every selected device failed =========="
    exit 1
fi
if [[ -n "$CONTEXT_FILE" ]]; then
    emitter_args=(
        --context-file "$CONTEXT_FILE"
        --legacy-result-file "$RESULT_FILE"
        --planned-file "$PLANNED_DEVICES"
    )
    [[ -z "$INFO_ARCHIVE" ]] || emitter_args+=(--info "$INFO_ARCHIVE")
    [[ -z "$LINK_ARCHIVE" ]] || emitter_args+=(--link "$LINK_ARCHIVE")
    [[ -z "$LINK_CSV" ]] || emitter_args+=(--csv "$LINK_CSV")
    # The emitter binds the UFM run only when it names this cycle and succeeded (UFM-MONITOR.md 15).
    [[ -z "$UFM_RUN_RECORD_FILE" ]] || emitter_args+=(--ufm-run-record "$UFM_RUN_RECORD_FILE")
    if [[ -n "$ETH_ARCHIVE" ]] && python3 - "$CONTEXT_FILE" <<'ACTIVITY_EMIT_PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    context = json.load(stream)
raise SystemExit(0 if "activity" in context else 1)
ACTIVITY_EMIT_PY
    then
        activity_file=$(python3 - "$CONTEXT_FILE" <<'ACTIVITY_PATH_PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["activity"]["sidecar_path"])
ACTIVITY_PATH_PY
        ) || exit 1
        emitter_args+=(--activity "$activity_file")
    fi
    # The v2 publisher has no SSH role. Give it a closed, credential-free
    # environment even when the collector is in an askpass fallback session.
    if ! env -i PATH="$PATH" LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 \
        python3 "$V2_EMITTER" "${emitter_args[@]}"; then
        emit_failed_collection_result
        log "========== cron finish: v2 evidence publication failed =========="
        exit 1
    fi
else
    cat "$RESULT_FILE"
fi
if [[ -s "$DEVICE_FAILURES" ]]; then
    log "========== cron finish with device warnings =========="
    exit 0
fi
if (( ufm_failed )); then
    log "========== cron finish with UFM warnings =========="
    exit 0
fi
log "========== cron finish =========="


### Crontab example
## crontab -e（脚本无需执行位，用 bash 直接调用）
#0 * * * *  bash /var/www/html/ethernet/monitor/cron.sh   >> /var/www/html/ethernet/monitor/cronjob.log 2>&1
#10 * * * * bash /var/www/html/infiniband/monitor/cron.sh >> /var/www/html/infiniband/monitor/cronjob.log 2>&1
#20 * * * * bash /var/www/html/nvlink/monitor/cron.sh     >> /var/www/html/nvlink/monitor/cronjob.log 2>&1
