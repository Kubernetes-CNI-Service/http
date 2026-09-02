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
EOF
}

TYPE_FILTER=""
COLLECTION_ENV=""
LOCK_WAIT=0
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
DYNAMIC_AIR_IDENTITIES=$(mktemp)  # runtime hostname|authoritative eth0 MAC|runtime source (AIR + unbound Production)
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
exec 200>"$LOCK_FILE"
if (( LOCK_WAIT > 0 )); then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 等待采集锁（最多 ${LOCK_WAIT}s）：$LOCK_FILE"
    lock_args=(-w "$LOCK_WAIT")
else
    lock_args=(-n)
fi
if ! flock "${lock_args[@]}" 200; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 采集锁等待超时或另一实例正在运行（$LOCK_FILE）" >&2
    exit 1
fi
trap 'rm -f "$ETH" "$SPX" "$IB" "$NV" "$DYNAMIC_AIR_IDENTITIES" ${ASKPASS_FILE:+"$ASKPASS_FILE"}' EXIT
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
RETAIN_DAYS=7   # number of days of data to retain (older files are deleted), need to >=2
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

# Shared public key deployed to all switch types.  It must come from the active
# project; embedding a former management server's key would silently authorize
# the wrong host after a project migration.
ACTIVE_INVENTORY=$(readlink -f "${BASE}/eth.csv" 2>/dev/null || true)
ACTIVE_PROJECT_DIR=${ACTIVE_INVENTORY%/*}
MGMT_PUBKEY_FILE=${MGMT_PUBKEY_FILE:-${ACTIVE_PROJECT_DIR}/mgmt-server.pub}
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
    if ! tar -czf "$archive" \
        -C "$(dirname "$dir")" "$(basename "$dir")"; then
        log "${label} ERROR: failed to create archive ${archive}"
        return 1
    fi
    if [[ ! -s "$archive" ]]; then
        log "${label} ERROR: archive is missing or empty: ${archive}"
        return 1
    fi
    rm -r -- "$dir"
}

# run_parallel <hosts_file> <cmd_template>
# Runs cmd_template for every host in hosts_file, at most MAX_PARALLEL at a time.
# Host-list rows use "expected_hostname|ssh_target". __NAME__ is replaced with
# the CSV hostname and __HOST__ with the required eth0_ip address.
# Returns 1 if any individual command failed, 0 if all succeeded.
run_parallel() {
    local hosts_file="$1" cmd_tmpl="$2"
    local pids=() failed=0
    local entry name host command
    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" =~ ^[[:space:]]*# ]] && continue
        IFS='|' read -r name host <<< "$entry"
        [[ -n "$name" ]] || name="$host"
        [[ -n "$host" ]] || host="$name"
        if ! valid_host_entry "$name" "$host"; then
            echo "[PARALLEL][REJECT] unsafe hostname/IP entry: ${name}|${host}" >&2
            failed=$((failed + 1))
            continue
        fi
        command=${cmd_tmpl//__NAME__/$name}
        command=${command//__HOST__/$host}
        (
            bash -c "$command" </dev/null
            rc=$?
            if (( rc != 0 )); then
                echo "[PARALLEL][FAIL] ${name} (${host}, exit=${rc})" >&2
            fi
            exit "$rc"
        ) &
        pids+=("$!")
        # 达到并发上限时，先等待本批全部结束再继续
        if (( ${#pids[@]} >= MAX_PARALLEL )); then
            for pid in "${pids[@]}"; do wait "$pid" || failed=$((failed + 1)); done
            pids=()
        fi
    done < "$hosts_file"
    for pid in "${pids[@]}"; do wait "$pid" || failed=$((failed + 1)); done
    return $((failed > 0 ? 1 : 0))
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

    if [[ -n "$TYPE_FILTER" ]]; then
        case "${mode}:${TYPE_FILTER}" in
            eth:ethernet|eth:eth|eth:eth_spx|eth:spx|eth:air|ib:ib|nvl:nvl) ;;
            *)
                log "[CSV] ERROR: --type ${TYPE_FILTER} is incompatible with ${csv_name}"
                return 1
                ;;
        esac
    fi

    if ! awk -F',' '
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
    ' mode="$mode" filter="$TYPE_FILTER" eth_file="$ETH" spx_file="$SPX" ib_file="$IB" nv_file="$NV" "$csv"
    then
        log "[CSV] ERROR: ${csv_name} must contain hostname, type, and eth0_ip columns"
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

    local selected_count=0
    case "$mode" in
        eth)
            selected_types=${TYPE_FILTER:-ethernet}
            [[ "$selected_types" == "ethernet" ]] && selected_types="eth|eth_spx|spx"
            selected_count=$(wc -l < "$ETH" | tr -d ' ')
            log "[CSV] ${csv_name} selected type=${selected_types}; loaded ${selected_count} info host(s), $(wc -l < "$SPX" | tr -d ' ') SPX link host(s)"
            ;;
        ib)
            selected_count=$(wc -l < "$IB" | tr -d ' ')
            log "[CSV] ${csv_name} selected type=${TYPE_FILTER:-ib}; loaded ${selected_count} IB host(s)"
            ;;
        nvl)
            selected_count=$(wc -l < "$NV" | tr -d ' ')
            log "[CSV] ${csv_name} selected type=${TYPE_FILTER:-nvl}; loaded ${selected_count} NVL host(s)"
            ;;
    esac

    # An explicit category request that selects no targets is almost always a
    # stale code/link or missing derived inventory.  Treat it as an error so a
    # manual run and the ZTP monitor handoff cannot report a false success.
    if [[ -n "$TYPE_FILTER" && "$selected_count" -eq 0 ]]; then
        if [[ "$TYPE_FILTER" == "air" && "$DYNAMIC_AIR_DISCOVERED" -gt 0 ]]; then
            log "[AIR-DYNAMIC] WARN: no AIR target currently has a resolved address; SSH collection skipped without failing the round"
            return 0
        fi
        log "[CSV] ERROR: --type ${TYPE_FILTER} selected 0 devices from ${csv}; verify the active project inventory and rerun setup/load"
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

    ASKPASS_FILE=$(mktemp "${TMPDIR:-/tmp}/monitor-ssh-askpass.XXXXXX") || {
        log "[KEY] ERROR: could not create the temporary SSH askpass helper"
        return 1
    }
    printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$MONITOR_SSH_PASSWORD"' > "$ASKPASS_FILE"
    chmod 700 "$ASKPASS_FILE"
    export SSH_ASKPASS="$ASKPASS_FILE" SSH_ASKPASS_REQUIRE=force
    export DISPLAY="${DISPLAY:-:0}"
    command=${prepare_template/__SSH_OPTIONS__/$SSH_PASSWORD_OPTS}

    for attempt in 1 2 3; do
        MONITOR_SSH_PASSWORD=""
        if [[ -t 0 ]]; then
            IFS= read -r -s -p "Switch password for ${user} (${label}, attempt ${attempt}/3): " MONITOR_SSH_PASSWORD
            read_status=$?
            printf '\n'
        else
            IFS= read -r -s -p "Switch password for ${user} (${label}, attempt ${attempt}/3): " MONITOR_SSH_PASSWORD </dev/tty
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
    local identity_record expected_mac expected_mac_plain identity_source
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
    expected_mac_plain=$(printf '%s' "$expected_mac" \
        | tr -cd '[:xdigit:]' | tr '[:upper:]' '[:lower:]')
    if [[ -n "$identity_record" && ! "$expected_mac_plain" =~ ^[0-9a-f]{12}$ ]]; then
        echo "[KEY][UNREACHABLE] ${name} (${host}): invalid authoritative runtime eth0 MAC" >&2
        return 11
    fi
    remote_command="actual_raw=\$(hostname -s 2>/dev/null || hostname)
actual=\$(printf '%s' \"\$actual_raw\" | tr '[:upper:]' '[:lower:]')
expected=\$(printf '%s' '${name}' | tr '[:upper:]' '[:lower:]')
expected_mac='${expected_mac_plain}'
remote_mac_raw=\$(cat /sys/class/net/eth0/address 2>/dev/null || true)
remote_mac=\$(printf '%s' \"\$remote_mac_raw\" | tr -cd '[:xdigit:]' | tr '[:upper:]' '[:lower:]')
if [[ -n \"\$expected_mac\" && \"\$remote_mac\" != \"\$expected_mac\" ]]; then
  echo '[KEY][ETH0-MAC-MISMATCH][ERROR] ${host}: expected=${expected_mac_plain}, switch='\"\$remote_mac_raw\"'; rejecting target' >&2
  exit 43
fi
if [[ \"\$expected\" != \"\$actual\" && -z \"\$expected_mac\" ]]; then
  echo '[KEY][HOSTNAME-MISMATCH][ERROR] ${host}: CSV=${name}, switch='\"\$actual_raw\"'; rejecting target' >&2
  exit 42
fi
if [[ \"\$expected\" != \"\$actual\" ]]; then
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
            echo "[KEY][UNREACHABLE] ${name} (${candidate}): eth0 MAC identity mismatch" >&2
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

# Resilient replacement for deploy_ssh_keys. It prompts only for genuine
# authentication rejection, removes unavailable targets from this collection,
# and succeeds as long as at least one target remains reachable.
deploy_ssh_keys() {
    local hosts_file="$1" label="$2" user="$3" remote_dir="$4"
    local ready auth_failed unavailable next_auth attempt read_status
    local prepared_count unavailable_count
    log "[KEY] ── ${label}: validating key login and deploying shared key ──"
    ready=$(mktemp) || return 1
    auth_failed=$(mktemp) || { rm -f "$ready"; return 1; }
    unavailable=$(mktemp) || { rm -f "$ready" "$auth_failed"; return 1; }
    prepare_ssh_batch_resilient "$hosts_file" "$ready" "$auth_failed" "$unavailable" \
        "$user" "$remote_dir" "$SSH_OPTS"

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
        ASKPASS_FILE=$(mktemp "${TMPDIR:-/tmp}/monitor-ssh-askpass.XXXXXX") || {
            rm -f "$ready" "$auth_failed" "$unavailable"
            return 1
        }
        printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$MONITOR_SSH_PASSWORD"' > "$ASKPASS_FILE"
        chmod 700 "$ASKPASS_FILE"
        export SSH_ASKPASS="$ASKPASS_FILE" SSH_ASKPASS_REQUIRE=force
        export DISPLAY="${DISPLAY:-:0}"
    fi

    for attempt in 1 2 3; do
        hosts_file_has_entries "$auth_failed" || break
        MONITOR_SSH_PASSWORD=""
        if [[ -t 0 ]]; then
            IFS= read -r -s -p "Switch password for ${user} (${label}, attempt ${attempt}/3): " MONITOR_SSH_PASSWORD
            read_status=$?
            printf '\n'
        else
            IFS= read -r -s -p "Switch password for ${user} (${label}, attempt ${attempt}/3): " MONITOR_SSH_PASSWORD </dev/tty
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
            "$user" "$remote_dir" "$SSH_PASSWORD_OPTS"
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
    rm -f "$auth_failed" "$unavailable"
    if (( unavailable_count > 0 )); then
        log "[KEY] WARN: ${unavailable_count} ${label} host(s) unavailable; continuing with ${prepared_count} reachable host(s)"
    fi
    if (( prepared_count == 0 )); then
        log "[KEY] ERROR: no reachable ${label} hosts remain"
        return 1
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
    ; then log "[ETH] ERROR: one or more deploys failed; skipping this phase"; return 1; fi

    log "[ETH] triggering remote collection"
    if ! run_parallel "$ETH" \
        "ssh $SSH_OPTS ${ETH_SSH_USER}@__HOST__ \
             'cd ${ETH_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.info
              test -s monitor/sw-info.sh || exit 1
              nohup bash monitor/sw-info.sh </dev/null >/dev/null 2>&1 &'" \
    ; then log "[ETH] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi

    log "[ETH] waiting ${ETH_WAIT}s for remote jobs"
    sleep "$ETH_WAIT"

    log "[ETH] retrieving *.info files"
    if ! run_parallel "$ETH" \
        "scp $SSH_OPTS ${ETH_SSH_USER}@__HOST__:${ETH_REMOTE_DIR}/*.info ${dir}/__NAME__.info 2>&1" \
    ; then log "[ETH] ERROR: some hosts returned no *.info files"; return 1; fi

    local count expected
    count=$(find "$dir" -name "*.info" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$ETH")
    log "[ETH] collected ${count} info file(s)"
    if (( count != expected )); then log "[ETH] ERROR: expected ${expected} unique info files, got ${count}"; return 1; fi

    printf '{\n  "schema_version": 1,\n  "environment": "%s",\n  "collector": "cron.sh",\n  "collected_at": "%s",\n  "device_count": %s\n}\n' \
        "${COLLECTION_ENV:-prod}" "$(date -Iseconds)" "$count" > "${dir}/collection.json"

    archive_collection_dir "$dir" "[ETH]" || return 1
    ETH_ARCHIVE="${dir}.tar.gz"
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
    ; then log "[SPX] ERROR: one or more deploys failed; skipping this phase"; return 1; fi

    log "[SPX] triggering remote collection"
    if ! run_parallel "$SPX" \
        "ssh $SSH_OPTS ${ETH_SSH_USER}@__HOST__ \
             'cd ${ETH_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.link
              test -s monitor/sw-link.sh || exit 1
              nohup bash monitor/sw-link.sh </dev/null >/dev/null 2>&1 &'" \
    ; then log "[SPX] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi

    log "[SPX] waiting ${SPX_WAIT}s for remote jobs"
    sleep "$SPX_WAIT"

    log "[SPX] retrieving *.link files"
    if ! run_parallel "$SPX" \
        "scp $SSH_OPTS ${ETH_SSH_USER}@__HOST__:${ETH_REMOTE_DIR}/*.link ${dir}/__NAME__.link 2>&1" \
    ; then log "[SPX] ERROR: some hosts returned no *.link files"; return 1; fi

    local count expected csv
    count=$(find "$dir" -name "*.link" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$SPX")
    log "[SPX] collected ${count} link file(s)"
    if (( count != expected )); then log "[SPX] ERROR: expected ${expected} unique link files, got ${count}"; return 1; fi

    # Merge all .link files into one CSV; keep only the first header line
    csv="${dir}.csv"
    cat "${dir}"/*.link 2>/dev/null > "$csv"
    awk 'NR==1 { h=$0; print; next } $0 != h { print }' "$csv" \
        > "${csv}.tmp" && mv "${csv}.tmp" "$csv"

    archive_collection_dir "$dir" "[SPX]" || return 1
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
    ; then log "[IB]  ERROR: one or more deploys failed; skipping this phase"; return 1; fi

    log "[IB]  triggering remote collection"
    if ! run_parallel "$IB" \
        "ssh $SSH_OPTS ${IB_SSH_USER}@__HOST__ \
             'cd ${IB_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.info
              test -s monitor/sw-info.sh || exit 1
              nohup bash monitor/sw-info.sh </dev/null >/dev/null 2>&1 &'" \
    ; then log "[IB]  ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi

    log "[IB]  waiting ${IB_WAIT}s for remote jobs"
    sleep "$IB_WAIT"

    log "[IB]  retrieving *.info files"
    if ! run_parallel "$IB" \
        "scp $SSH_OPTS ${IB_SSH_USER}@__HOST__:${IB_REMOTE_DIR}/*.info ${dir}/__NAME__.info 2>&1" \
    ; then log "[IB]  ERROR: some hosts returned no *.info files"; return 1; fi

    local count expected
    count=$(find "$dir" -name "*.info" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$IB")
    log "[IB]  collected ${count} info file(s)"
    if (( count != expected )); then log "[IB]  ERROR: expected ${expected} unique info files, got ${count}"; return 1; fi

    archive_collection_dir "$dir" "[IB]" || return 1
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
    ; then log "[IBL] ERROR: one or more deploys failed; skipping this phase"; return 1; fi

    log "[IBL] triggering remote collection"
    if ! run_parallel "$IB" \
        "ssh $SSH_OPTS ${IB_SSH_USER}@__HOST__ \
             'cd ${IB_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.link
              test -s monitor/sw-link.sh || exit 1
              nohup bash monitor/sw-link.sh </dev/null >/dev/null 2>&1 &'" \
    ; then log "[IBL] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi

    log "[IBL] waiting ${IBL_WAIT}s for remote jobs"
    sleep "$IBL_WAIT"

    log "[IBL] retrieving *.link files"
    if ! run_parallel "$IB" \
        "scp $SSH_OPTS ${IB_SSH_USER}@__HOST__:${IB_REMOTE_DIR}/*.link ${dir}/__NAME__.link 2>&1" \
    ; then log "[IBL] ERROR: some hosts returned no *.link files"; return 1; fi

    local count expected csv
    count=$(find "$dir" -name "*.link" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$IB")
    log "[IBL] collected ${count} link file(s)"
    if (( count != expected )); then log "[IBL] ERROR: expected ${expected} unique link files, got ${count}"; return 1; fi

    # Merge all .link files into one CSV; keep only the first header line
    csv="${dir}.csv"
    cat "${dir}"/*.link 2>/dev/null > "$csv"
    awk 'NR==1 { h=$0; print; next } $0 != h { print }' "$csv" \
        > "${csv}.tmp" && mv "${csv}.tmp" "$csv"

    archive_collection_dir "$dir" "[IBL]" || return 1
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
    ; then log "[NV]  ERROR: one or more deploys failed; skipping this phase"; return 1; fi

    log "[NV]  triggering remote collection"
    if ! run_parallel "$NV" \
        "ssh $SSH_OPTS ${NV_SSH_USER}@__HOST__ \
             'cd ${NV_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.info
              test -s monitor/sw-info.sh || exit 1
              nohup bash monitor/sw-info.sh </dev/null >/dev/null 2>&1 &'" \
    ; then log "[NV]  ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi

    log "[NV]  waiting ${NV_WAIT}s for remote jobs"
    sleep "$NV_WAIT"

    log "[NV]  retrieving *.info files"
    if ! run_parallel "$NV" \
        "scp $SSH_OPTS ${NV_SSH_USER}@__HOST__:${NV_REMOTE_DIR}/*.info ${dir}/__NAME__.info 2>&1" \
    ; then log "[NV]  ERROR: some hosts returned no *.info files"; return 1; fi

    local count expected
    count=$(find "$dir" -name "*.info" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$NV")
    log "[NV]  collected ${count} info file(s)"
    if (( count != expected )); then log "[NV]  ERROR: expected ${expected} unique info files, got ${count}"; return 1; fi

    archive_collection_dir "$dir" "[NV]" || return 1
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
    ; then log "[NVL] ERROR: one or more deploys failed; skipping this phase"; return 1; fi

    log "[NVL] triggering remote collection"
    if ! run_parallel "$NV" \
        "ssh $SSH_OPTS ${NV_SSH_USER}@__HOST__ \
             'cd ${NV_REMOTE_DIR%/*} || exit 1
              rm -f monitor/*.link
              test -s monitor/sw-link.sh || exit 1
              nohup bash monitor/sw-link.sh </dev/null >/dev/null 2>&1 &'" \
    ; then log "[NVL] ERROR: one or more triggers failed; skipping wait/retrieval"; return 1; fi

    log "[NVL] waiting ${NVL_WAIT}s for remote jobs"
    sleep "$NVL_WAIT"

    log "[NVL] retrieving *.link files"
    if ! run_parallel "$NV" \
        "scp $SSH_OPTS ${NV_SSH_USER}@__HOST__:${NV_REMOTE_DIR}/*.link ${dir}/__NAME__.link 2>&1" \
    ; then log "[NVL] ERROR: some hosts returned no *.link files"; return 1; fi

    local count expected csv
    count=$(find "$dir" -name "*.link" 2>/dev/null | wc -l | tr -d '[:space:]')
    expected=$(hosts_file_entry_count "$NV")
    log "[NVL] collected ${count} link file(s)"
    if (( count != expected )); then log "[NVL] ERROR: expected ${expected} unique link files, got ${count}"; return 1; fi

    # Merge all .link files into one CSV; keep only the first header line
    csv="${dir}.csv"
    cat "${dir}"/*.link 2>/dev/null > "$csv"
    awk 'NR==1 { h=$0; print; next } $0 != h { print }' "$csv" \
        > "${csv}.tmp" && mv "${csv}.tmp" "$csv"

    archive_collection_dir "$dir" "[NVL]" || return 1
    log "[NVL] done → ${dir}.tar.gz  |  CSV → ${csv}"
}

# ── Cleanup: retain last RETAIN_DAYS days, bundle prior-day files into daily archives ───
# cleanup_data_dirs <dir> [<dir> ...]
# Retention window is controlled by RETAIN_DAYS. For each directory:
#   - Files from today                        → keep as-is
#   - Files from past 1–(RETAIN_DAYS-1) days → bundle *.tar.gz per-day into
#                                               YYYYMMDD-daily.tar.gz, then delete originals;
#                                               *.csv files are kept as-is (not bundled)
#   - Files older than RETAIN_DAYS days       → delete all (tar.gz, csv, and
#                                               failed/interrupted batch dirs)
# Skips files already named *-daily.tar.gz (already bundled).
cleanup_data_dirs() {
    local today cutoff_ts dir date file date_ts bundle count_gz count_csv count_dirs dates
    local batch_dir batch_name
    today=$(date -u '+%Y%m%d')
    # cutoff: midnight RETAIN_DAYS days ago as seconds-since-epoch
    cutoff_ts=$(date -u -d "${RETAIN_DAYS} days ago" '+%s' 2>/dev/null \
             || date -u -v-${RETAIN_DAYS}d '+%s' 2>/dev/null)   # Linux / macOS fallback

    for dir in "$@"; do
        [[ -d "$dir" ]] || continue
        log "[CLN] ── ${dir} ──"

        count_gz=$(find "$dir" -maxdepth 1 -name '*.tar.gz' ! -name '*-daily.tar.gz' | wc -l)
        count_csv=$(find "$dir" -maxdepth 1 -name '*.csv' | wc -l)
        count_dirs=$(find "$dir" -mindepth 1 -maxdepth 1 -type d | wc -l)
        log "[CLN] found ${count_gz} tar.gz + ${count_csv} csv + ${count_dirs} batch dir(s)"

        # A successful collection is archived and its source directory is
        # removed immediately.  Directories that remain are failed or
        # interrupted batches.  Keep recent ones for troubleshooting, but
        # apply the same retention boundary as archives.  Only exact collector
        # batch names are eligible; symlinks and unrelated directories are
        # never traversed or removed.
        for batch_dir in "$dir"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*; do
            [[ -d "$batch_dir" && ! -L "$batch_dir" ]] || continue
            batch_name=${batch_dir##*/}
            if [[ ! "$batch_name" =~ ^([0-9]{8})-[0-9]{4}(-(air|prod))?$ ]]; then
                log "[CLN] WARN: unrelated directory retained: ${batch_name}"
                continue
            fi
            date=${BASH_REMATCH[1]}
            date_ts=$(date -u -d "${date}" '+%s' 2>/dev/null \
                   || date -u -j -f '%Y%m%d' "${date}" '+%s' 2>/dev/null \
                   || true)
            if [[ ! "$date_ts" =~ ^[0-9]+$ ]]; then
                log "[CLN] WARN: invalid batch date retained: ${batch_name}"
                continue
            fi
            if (( date_ts < cutoff_ts )); then
                if find "$batch_dir" -xdev -depth -delete; then
                    log "[CLN] deleted stale batch directory ${batch_name} (> ${RETAIN_DAYS} days old)"
                else
                    log "[CLN] WARN: could not delete stale batch directory ${batch_name}"
                fi
            fi
        done

        # Collect unique YYYYMMDD date prefixes present in the directory
        dates=""
        for file in "$dir"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9]*.{tar.gz,csv}; do
            [[ -f "$file" ]] || continue
            date="${file##*/}"       # basename
            date="${date:0:8}"       # first 8 chars = YYYYMMDD
            case " $dates " in
                *" $date "*) ;;
                *) dates="${dates}${dates:+ }${date}" ;;
            esac
        done

        for date in $dates; do
            date_ts=$(date -u -d "${date}" '+%s' 2>/dev/null \
                   || date -u -j -f '%Y%m%d' "${date}" '+%s' 2>/dev/null)

            # Older than RETAIN_DAYS days → delete
            if (( date_ts < cutoff_ts )); then
                find "$dir" -maxdepth 1 -type f \
                    \( -name "${date}-*.tar.gz" -o -name "${date}-*.csv" \) \
                    -delete
                log "[CLN] deleted files for ${date} (> ${RETAIN_DAYS} days old)"
                continue
            fi

            # Today → leave alone
            [[ "$date" == "$today" ]] && continue

            # Previous day within RETAIN_DAYS days → bundle into daily archive
            bundle="${dir}/${date}-daily.tar.gz"
            if [[ -e "$bundle" ]]; then
                log "[CLN] ${date}: daily bundle already exists, skipping"
                continue
            fi

            # Collect only *.tar.gz files for bundling (csv files are kept as-is)
            local files=()
            for file in "$dir"/${date}-*.tar.gz; do
                [[ -f "$file" ]] && files+=("$file")
            done
            (( ${#files[@]} == 0 )) && continue

            tar -czf "$bundle" -C "$dir" "${files[@]##*/}" \
                && rm -f "${files[@]}" \
                && log "[CLN] ${date}: bundled ${#files[@]} file(s) → $(basename "$bundle")" \
                || log "[CLN] ${date}: WARN bundle failed, originals kept"
        done
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "========== cron start =========="

if ! detect_eth_environment; then
    log "[ENV] ERROR: environment selection failed, aborting"
    exit 1
fi

if ! parse_csv_hosts; then
    log "[CSV] ERROR: host parsing failed, aborting"
    exit 1
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
if hosts_file_has_entries "$IB"; then collect_ib_info || collection_failed=1; fi
if hosts_file_has_entries "$IB"; then collect_ib_link || collection_failed=1; fi

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
    elif ! python3 "$POST_COLLECT" \
        --archive "$ETH_ARCHIVE" \
        --environment "${COLLECTION_ENV:-prod}"
    then
        log "[ETH-CLOSED-LOOP] ERROR: validation report or monitor.html refresh failed"
        collection_failed=1
    fi
elif (( collection_failed == 0 )) && \
    { hosts_file_has_entries "$IB" || hosts_file_has_entries "$NV"; }
then
    # IB/NV switch info and link CSVs are already the monitor page's canonical
    # inputs.  They need no second analyzer, but a standalone cron run must
    # still publish the newly collected state into monitor.html.
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

cleanup_data_dirs \
    "${BASE}/eth-info"  \
    "${BASE}/spx-link"  \
    "${BASE}/ib-info"   \
    "${BASE}/ib-link"   \
    "${BASE}/nvsw-info" \
    "${BASE}/nvsw-link"

if (( collection_failed )); then
    log "========== cron finish with errors =========="
    exit 1
fi
log "========== cron finish =========="


### Crontab example
## crontab -e（脚本无需执行位，用 bash 直接调用）
#0 * * * *  bash /var/www/html/ethernet/monitor/cron.sh   >> /var/www/html/ethernet/monitor/cronjob.log 2>&1
#10 * * * * bash /var/www/html/infiniband/monitor/cron.sh >> /var/www/html/infiniband/monitor/cronjob.log 2>&1
#20 * * * * bash /var/www/html/nvlink/monitor/cron.sh     >> /var/www/html/nvlink/monitor/cronjob.log 2>&1
