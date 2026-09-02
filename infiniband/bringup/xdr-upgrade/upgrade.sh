#!/bin/bash
# upgrade.sh — Unified IB Switch Firmware Upgrade Orchestrator
#
# Supports switch-initiated SCP (default), management-server push (local), and
# HTTP download while sharing one device, version, dry-run, and phase engine.
#
# OS upgrade supports multi-step paths (e.g. must pass through an intermediate
# version before reaching the final target). Each run advances one step;
# reboot the switch between runs to continue to the next step.
#
# Upgrade prompting rules:
#   • First switch needing an upgrade    → always prompt (unless -y)
#   • Subsequent switches (same baseline)→ auto-upgrade (no prompt)
#   • OS: subsequent with DIFFERENT OS   → prompt again
#   • Parallel subshells never prompt    → skip if baseline not confirmed
#
# Usage:
#   bash upgrade.sh -A                    # prompt for method; defaults to SCP
#   bash upgrade.sh --method scp --os
#   bash upgrade.sh --method local --bios
#   bash upgrade.sh --method http --dry-run
#
# After any real upgrade, the script waits VERIFY_WAIT seconds for switches to
# complete and then re-runs itself with --dry-run to confirm versions are at target.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BASE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# ─── Configuration ─────────────────────────────────────────────────────────────

METHOD=""
METHOD_SELECTION_TIMEOUT=10
METHOD_SELECTED_INTERACTIVELY=false

MGMT_SERVER=""                # SCP optional override; empty = detect through switch w
MGMT_SCP_ROOT="$BASE"          # SCP package directory on management server
MGMT_SCP_ROOT_EXPLICIT=false
DEFAULT_MGMT_SCP_USER=$(id -un 2>/dev/null || true)
LOCAL_SOURCE_ROOT="$BASE"      # local-push package directory on management server
SWITCH_LOCAL_DIR="/home/admin" # package directory on switches for local method
HTTP_SERVER=""               # HTTP optional override; empty = detect through switch w
HTTP_SCHEME=""               # compatibility selector; canonical transport is METHOD

SWITCH_USER="admin"
REMOTE_DIR="/home/admin/upgrade" # working dir on IB switches
PUBLIC_KEY_FILE=""
PUBLIC_KEY_FILE_EXPLICIT=false

SSH_CONNECT_TIMEOUT=10   # seconds; increase if switches are slow to accept connections

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=${SSH_CONNECT_TIMEOUT} -o BatchMode=no -o NumberOfPasswordPrompts=1"

# OS upgrade path — list in ascending version order (earliest → latest).
# A switch upgrades to the first entry whose version exceeds its current version.
# Add intermediate steps as needed for versions that cannot skip directly.
TARGET_OS_FILES=(
    "nvosv25-02-6077amd64.bin"
    "nvosv25-02-7002amd64.bin"
    "nvosv25-02-8008amd64.bin"
)

BIOS_UPGRADE_FROM_VERSION="0ACQF_06.01.006"
TARGET_BIOS_VERSION="0ACQF_06.01.009"
TARGET_BIOS_FILE="0ACQF.cab"
TARGET_CPLD_BURN_FILE="FUI000557_BURN_BM_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600_CPLD000368_REV0300_CPLD000389_REV0600_CPLD000368_REV0300_OPN.vme"
TARGET_CPLD_REFRESH_FILE="FUI000557_REFRESH_BM_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600_CPLD000368_REV0300_CPLD000389_REV0600_CPLD000368_REV0300_OPN.vme"

IBCSV="${BASE}/ib.csv"
IBLOG="${BASE}/ib.log"
OUTPUT_DIR="${BASE}/xdr-upgrade-logs"
SCRIPTS_DIR=""
LOG=""

DRY_RUN=false
VERIFY_ONLY=false
SCRIPTS_ONLY=false
RUN_OS=false
RUN_BIOS=false
RUN_CPLD=false
OS_FIRST=false
YES_ALL=false
IB_HOSTS=()
_IB_HOST_LABELS=""
_SEQUENTIAL_HOSTS=()
_ASKPASS_HELPER=""
_DEPLOY_TALLY=""
_DRY_RUN_NEEDS=""
_SCP_DISCOVERY_RESULTS=""
_PACKAGE_STATUS=""
_CPLD_STATUS_DETAIL=""
_SCP_REQUIRED_PACKAGES=()
SWITCH_PASSWORD_REQUIRED=true
PASSWORD_PROBE_HOST=""
PUBLIC_KEY_PROBE_DETAIL=""
PUBLIC_KEY_REACHABLE_HOST=""
PUBLIC_KEY_PROBE_TRANSPORT_FAILURES=0
PUBLIC_KEY_AUTH_FAILED_HOSTS=()
PUBLIC_KEY_SUCCESS_HOSTS=()
SKIPPED_SSH_HOSTS=()
SKIPPED_SSH_LABELS=()
SKIPPED_SSH_DETAILS=()
SKIPPED_SSH_REPORT_PRINTED=false
MGMT_SCP_USER="${MGMT_SCP_USER:-}"
MGMT_SCP_PASSWORD="${MGMT_SCP_PASSWORD:-}"
LOCAL_INTERFACE_IPS=""
DETECTED_MGMT_SERVER_IP=""
LOG_INDENT=""

# Default wait after OS/CPLD deployments. BIOS needs a longer reboot window.
# An explicit --phase-wait overrides both defaults. Set it to 0 to skip waits.
PHASE_WAIT=480
BIOS_PHASE_WAIT=600
PHASE_WAIT_EXPLICIT=false

# Maximum number of switches to upgrade in parallel (excluding the first sequential one).
# Keep the default below a typical sshd MaxStartups threshold; 0 explicitly
# requests unlimited concurrency.
PARALLEL_LIMIT=8

# Maximum random delay (seconds) before an OS package transfer.
# For local mode the delay happens on the management server immediately before
# it pushes a missing package; SCP/HTTPS mode applies it in the switch sub-script.
# 0 = no delay. Recommended: ~(total_switches / max_concurrent_downloads) * download_seconds
OS_DOWNLOAD_JITTER=120

# ─── Argument Parsing ──────────────────────────────────────────────────────────

# Retain the customer's exact invocation so a dry-run follow-up can remove
# only --dry-run instead of reconstructing every option from resolved defaults.
ORIGINAL_ARGS=("$@")

usage() {
    cat <<EOF
Usage: bash $(basename "${BASH_SOURCE[0]}") [OPTIONS]

Unified IB Switch Firmware Upgrade Orchestrator.
Supports SCP (default), direct HTTPS fetch, local push, and HTTP download/file fetch.

Options:
  -h, --help          Show this help message and exit
  --method METHOD     scp, http, local, or https (default: scp)
  -y, --yes           Answer yes to all prompts automatically
  -A, --all           Run all three phases: OS, BIOS, CPLD (default when no phase flag given)
  --os                Run OS upgrade phase
  --bios              Run BIOS upgrade phase
  --cpld              Run CPLD upgrade phase
  --os-first          Upgrade OS through every configured step before BIOS and CPLD
  --scripts-only      Generate upgrade sub-scripts only, do not connect to switches
  --dry-run           Check versions read-only, then offer a confirmed real run if upgrades are needed
  --verify-only       Read-only post-upgrade verification; never offers another upgrade
  --ib-csv FILE       Device CSV (default: ib.csv; selects type=ib eth0_ip values)
  --ib-log FILE       Legacy switch list used only when the CSV is absent (default: ib.log)
  --public-key FILE   Public key offered for optional installation on all selected switches
  --mgmt-server HOST  Explicit management-server address (default: auto-detect via switch w)
  --mgmt-user USER    Management-server SCP user (default: current id -un user)
  --scp-root DIR      Package directory (default: directory containing this script)
  --source-root DIR   Local-push package directory (default: script directory)
  --local-dir DIR     Local/HTTP switch package directory (default: /home/admin)
  --http-server HOST  HTTPS/HTTP server address (default: auto-detect via switch w)
  --http-scheme NAME  Compatibility selector for https or http; prefer --method
  --parallel-limit N  Maximum parallel devices (default: ${PARALLEL_LIMIT}; 0 means unlimited)
  --phase-wait SEC    Override every post-deployment wait (defaults: BIOS ${BIOS_PHASE_WAIT}, others ${PHASE_WAIT})

Phase flags (--os, --bios, --cpld) can be combined freely, e.g. "--bios --cpld" skips OS.

Upgrade prompting rules:
  First switch needing an upgrade     → always prompt (10s timeout, default yes)
  Subsequent switches (parallel run)  → auto-upgrade if baseline confirmed, else skip
  OS: subsequent with different OS    → also prompt (sequential, before going parallel)
BIOS and CPLD: single target version, auto-upgrade once first switch is confirmed.

Method selection:
  Enter/1/scp = switch pulls by SCP (default after ${METHOD_SELECTION_TIMEOUT}s)
  2/http      = switches download through HTTP, then NVUE fetches local files
  3/local     = local file fetch; pre-stage packages in the user's home directory
  4/https     = direct NVUE fetch; requires a valid CA certificate trusted by the switch

All local output is stored under ./xdr-upgrade-logs/.
Generated sub-scripts are stored under ./xdr-upgrade-logs/upgrade_scripts/<method>/.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)       usage; exit 0                          ;;
        --method)        [[ $# -ge 2 ]] || { echo "--method requires METHOD" >&2; exit 1; }; METHOD="$2"; shift ;;
        -y|--yes)        YES_ALL=true                           ;;
        -A|--all)        RUN_OS=true; RUN_BIOS=true; RUN_CPLD=true ;;
        --dry-run)       DRY_RUN=true                           ;;
        --verify-only)   DRY_RUN=true; VERIFY_ONLY=true         ;;
        --scripts-only)  SCRIPTS_ONLY=true                      ;;
        --os)            RUN_OS=true                            ;;
        --bios)          RUN_BIOS=true                          ;;
        --cpld)          RUN_CPLD=true                          ;;
        --os-first)      OS_FIRST=true; RUN_OS=true; RUN_BIOS=true; RUN_CPLD=true ;;
        --ib-csv)        [[ $# -ge 2 ]] || { echo "--ib-csv requires FILE" >&2; exit 1; }; IBCSV="$2"; shift ;;
        --ib-log)        [[ $# -ge 2 ]] || { echo "--ib-log requires FILE" >&2; exit 1; }; IBLOG="$2"; shift ;;
        --public-key)     [[ $# -ge 2 ]] || { echo "--public-key requires FILE" >&2; exit 1; }; PUBLIC_KEY_FILE="$2"; PUBLIC_KEY_FILE_EXPLICIT=true; shift ;;
        --mgmt-server)   [[ $# -ge 2 ]] || { echo "--mgmt-server requires HOST" >&2; exit 1; }; MGMT_SERVER="$2"; shift ;;
        --mgmt-user)     [[ $# -ge 2 ]] || { echo "--mgmt-user requires USER" >&2; exit 1; }; MGMT_SCP_USER="$2"; shift ;;
        --scp-root)      [[ $# -ge 2 ]] || { echo "--scp-root requires DIR" >&2; exit 1; }; MGMT_SCP_ROOT="$2"; MGMT_SCP_ROOT_EXPLICIT=true; shift ;;
        --source-root)   [[ $# -ge 2 ]] || { echo "--source-root requires DIR" >&2; exit 1; }; LOCAL_SOURCE_ROOT="$2"; shift ;;
        --local-dir)     [[ $# -ge 2 ]] || { echo "--local-dir requires DIR" >&2; exit 1; }; SWITCH_LOCAL_DIR="$2"; shift ;;
        --http-server)   [[ $# -ge 2 ]] || { echo "--http-server requires HOST" >&2; exit 1; }; HTTP_SERVER="$2"; shift ;;
        --http-scheme)   [[ $# -ge 2 ]] || { echo "--http-scheme requires NAME" >&2; exit 1; }; HTTP_SCHEME="$2"; shift ;;
        --parallel-limit) [[ $# -ge 2 ]] || { echo "--parallel-limit requires N" >&2; exit 1; }; PARALLEL_LIMIT="$2"; shift ;;
        --phase-wait)    [[ $# -ge 2 ]] || { echo "--phase-wait requires SEC" >&2; exit 1; }; PHASE_WAIT="$2"; PHASE_WAIT_EXPLICIT=true; shift ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1    ;;
    esac
    shift
done

select_method() {
    local choice=""
    if [[ -n "$METHOD" ]]; then
        case "$(printf '%s' "$METHOD" | tr '[:upper:]' '[:lower:]')" in
            1|scp)   METHOD="scp" ;;
            2|http)  METHOD="http" ;;
            3|local) METHOD="local" ;;
            4|https) METHOD="https" ;;
            *) echo "Invalid --method: ${METHOD}; expected scp, http, local, or https." >&2; exit 2 ;;
        esac
        return
    fi

    if [[ ! -t 0 ]]; then
        METHOD="scp"
        echo "No interactive TTY; defaulting package delivery method to scp."
        return
    fi

    printf '%s\n' \
        "Select package delivery method:" \
        "  1. scp    Switch pulls packages from management server [default]" \
        "  2. http   Switch downloads through HTTP, then uses local file fetch" \
        "  3. local  Uses local files [pre-stage packages in the user's home directory]" \
        "  4. https  Direct NVUE fetch [requires a valid CA certificate trusted by the switch]"
    printf "Choice [1/2/3/4] (default: scp in %ss): " "$METHOD_SELECTION_TIMEOUT"
    if ! IFS= read -r -t "$METHOD_SELECTION_TIMEOUT" choice; then
        printf '\n'
        choice=""
    fi
    [[ -n "$choice" ]] && METHOD_SELECTED_INTERACTIVELY=true
    case "$(printf '%s' "$choice" | tr '[:upper:]' '[:lower:]')" in
        ""|1|scp)   METHOD="scp" ;;
        2|http)  METHOD="http" ;;
        3|local) METHOD="local" ;;
        4|https) METHOD="https" ;;
        *) echo "Invalid method choice: ${choice}; expected 1/scp, 2/http, 3/local, or 4/https." >&2; exit 2 ;;
    esac
}

select_method
if [[ -n "$HTTP_SCHEME" ]]; then
    if [[ "$HTTP_SCHEME" != "http" && "$HTTP_SCHEME" != "https" ]]; then
        echo "Invalid --http-scheme: expected http or https." >&2
        exit 1
    fi
    case "$METHOD" in
        http|https) METHOD="$HTTP_SCHEME" ;;
        *) echo "--http-scheme can only be used with the HTTP/HTTPS delivery methods." >&2; exit 1 ;;
    esac
fi
SCRIPTS_DIR="${OUTPUT_DIR}/upgrade_scripts/${METHOD}"
LOG="${OUTPUT_DIR}/upgrade-${METHOD}-$(date '+%Y%m%d-%H%M').log"
if [[ -n "$MGMT_SERVER" && ! "$MGMT_SERVER" =~ ^[A-Za-z0-9._:-]+$ ]]; then
    echo "Invalid --mgmt-server value." >&2
    exit 1
fi
if [[ ! "$MGMT_SCP_ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    echo "Invalid --scp-root: must be a safe absolute path." >&2
    exit 1
fi
if [[ ! "$LOCAL_SOURCE_ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    echo "Invalid --source-root: must be a safe absolute path." >&2
    exit 1
fi
if [[ ! "$SWITCH_LOCAL_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    echo "Invalid --local-dir: must be a safe absolute path." >&2
    exit 1
fi
if [[ -n "$HTTP_SERVER" && ! "$HTTP_SERVER" =~ ^[A-Za-z0-9._:-]+$ ]]; then
    echo "Invalid --http-server value." >&2
    exit 1
fi
[[ "$PARALLEL_LIMIT" =~ ^[0-9]+$ ]] || { echo "Invalid --parallel-limit: expected a non-negative integer." >&2; exit 1; }
[[ "$PHASE_WAIT" =~ ^[0-9]+$ ]] || { echo "Invalid --phase-wait: expected a non-negative integer." >&2; exit 1; }
$PHASE_WAIT_EXPLICIT && BIOS_PHASE_WAIT="$PHASE_WAIT"
if ! mkdir -p "$OUTPUT_DIR"; then
    echo "Cannot create local output directory: ${OUTPUT_DIR}" >&2
    exit 1
fi

# If no phase flag was given, auto-select all in non-interactive modes;
# otherwise select_phases() will prompt the user before main() runs.
if ! $RUN_OS && ! $RUN_BIOS && ! $RUN_CPLD; then
    if $SCRIPTS_ONLY || $DRY_RUN || $YES_ALL; then
        RUN_OS=true; RUN_BIOS=true; RUN_CPLD=true
    fi
fi

# ─── Logging ───────────────────────────────────────────────────────────────────

emit_log_line() {
    local line="$1"
    if command -v flock >/dev/null 2>&1; then
        {
            flock -x 9
            printf '%s\n' "$line" >&9
            printf '%s\n' "$line"
        } 9>> "$LOG"
    else
        # One shell printf per destination avoids the multiple concurrent tee
        # processes that can split and visually interleave parallel log lines.
        printf '%s\n' "$line" >> "$LOG"
        printf '%s\n' "$line"
    fi
}

emit_log_spacing() {
    if command -v flock >/dev/null 2>&1; then
        {
            flock -x 9
            printf '\n\n' >&9
            printf '\n\n'
        } 9>> "$LOG"
    else
        printf '\n\n' >> "$LOG"
        printf '\n\n'
    fi
}

log() {
    local body="$*" ip hostname
    case "$body" in
        Generated:*/os_upgrade_*) $RUN_OS || return 0 ;;
        Generated:*/bios_upgrade_*) $RUN_BIOS || return 0 ;;
        Generated:*/cpld_upgrade_*) $RUN_CPLD || return 0 ;;
    esac
    if [[ -n "$_IB_HOST_LABELS" && "$body" == *"["* ]]; then
        while IFS=$'\t' read -r ip hostname; do
            [[ -n "$ip" && -n "$hostname" ]] || continue
            body="${body//\[$ip\]/[$hostname $ip]}"
        done <<< "$_IB_HOST_LABELS"
    fi
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ${LOG_INDENT}${body}"
    emit_log_line "$msg"
}

# Starts a top-level log section, then indents all following messages until the
# next section. Background device workers inherit the current indentation.
begin_log_section() {
    LOG_INDENT=""
    log "──────────────────────────────────────────────────────────"
    log "$1"
    log "──────────────────────────────────────────────────────────"
    LOG_INDENT="  "
}

# Round/result checkpoints align with phase headings. Two physical blank lines
# after each checkpoint visually separate the next round or phase.
log_phase_checkpoint() {
    local saved_indent="$LOG_INDENT"
    local rule="──────────────────────────────────────────────────────────"
    LOG_INDENT=""
    if [[ "$*" == Phase\ *\ result:* ]]; then
        log "──────────────────────────────────────────────────────────"
        log "$*"
        log "$rule"
    else
        log "$*"
    fi
    LOG_INDENT="$saved_indent"
    emit_log_spacing
}

die() { log "ERROR: $*"; exit 1; }

lower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }

# /dev/tty may exist and appear readable even when the current process has no
# controlling terminal (for example, cron or a CI runner). Test an actual open
# so prompts fail closed instead of printing kernel-level I/O errors.
tty_available() { { : </dev/tty; } 2>/dev/null; }

cleanup() {
    report_skipped_ssh_targets
    [[ -n "${_ASKPASS_HELPER:-}" ]] && rm -f -- "$_ASKPASS_HELPER"
    [[ -n "${_DEPLOY_TALLY:-}" ]] && rm -f -- "$_DEPLOY_TALLY"
    [[ -n "${_DRY_RUN_NEEDS:-}" ]] && rm -f -- "$_DRY_RUN_NEEDS"
    [[ -n "${_SCP_DISCOVERY_RESULTS:-}" ]] && rm -f -- "$_SCP_DISCOVERY_RESULTS"
    unset IB_SWITCH_PASSWORD MGMT_SCP_USER MGMT_SCP_PASSWORD IB_PUBLIC_KEY_PROMPT_DONE
}

prepare_mgmt_scp_auth() {
    local entered_user=""

    if [[ -z "$MGMT_SCP_USER" || -z "$MGMT_SCP_PASSWORD" ]]; then
        tty_available || die "Cannot prompt for management-server credentials: /dev/tty is unavailable."
    fi
    if [[ -z "$MGMT_SCP_USER" ]]; then
        if [[ -n "$DEFAULT_MGMT_SCP_USER" ]]; then
            printf "Management-server SCP username [%s]: " "$DEFAULT_MGMT_SCP_USER" > /dev/tty
        else
            printf "Management-server SCP username: " > /dev/tty
        fi
        IFS= read -r entered_user < /dev/tty
        MGMT_SCP_USER="${entered_user:-$DEFAULT_MGMT_SCP_USER}"
    fi
    [[ "$MGMT_SCP_USER" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "Management-server username is empty or contains unsafe characters."

    if [[ -z "$MGMT_SCP_PASSWORD" ]]; then
        printf "Management-server SCP password (attempt 1/3): " > /dev/tty
        IFS= read -r -s MGMT_SCP_PASSWORD < /dev/tty
        printf "\n" > /dev/tty
    fi
    [[ -n "$MGMT_SCP_PASSWORD" ]] || die "Management-server password cannot be empty."
    export MGMT_SCP_USER MGMT_SCP_PASSWORD
}

# Validates the management-server credentials from the first switch, matching
# the real SCP data path. A temporary credential-free helper is deployed to the
# switch; passwords travel only through encrypted SSH stdin and a short-lived
# switch-side askpass environment.
validate_mgmt_scp_authentication() {
    [[ "$METHOD" == "scp" ]] || return 0
    (( ${#_SCP_REQUIRED_PACKAGES[@]} > 0 )) || {
        log "Management-server SCP authentication is not required because no package needs to be transferred."
        return 0
    }
    (( ${#IB_HOSTS[@]} > 0 )) || die "No switch target is available for management-server authentication validation."

    local probe_host="${IB_HOSTS[0]}" mgmt_server_ip local_helper remote_helper
    local attempt=1 output="" rc=0 password="" detail=""
    detect_mgmt_server_ip "$probe_host" "$MGMT_SERVER" || \
        die "Cannot determine the management-server address for SCP authentication validation."
    mgmt_server_ip="$DETECTED_MGMT_SERVER_IP"

    local_helper=$(mktemp "${TMPDIR:-/tmp}/ib-mgmt-auth-check.XXXXXX") \
        || die "Failed to create the management-server authentication helper."
    remote_helper="${REMOTE_DIR}/.mgmt-auth-check.$$.sh"
    cat > "$local_helper" <<'EOF'
#!/bin/bash
set -u
IFS= read -r MGMT_SERVER_IP || exit 70
IFS= read -r MGMT_SCP_USER || exit 70
IFS= read -r MGMT_SCP_PASSWORD || exit 70
[[ -n "$MGMT_SERVER_IP" && -n "$MGMT_SCP_USER" && -n "$MGMT_SCP_PASSWORD" ]] || exit 70
export MGMT_SCP_PASSWORD
helper=$(mktemp /tmp/ib-mgmt-askpass.XXXXXX) || exit 70
cleanup() { rm -f -- "$helper"; }
trap cleanup EXIT
chmod 700 "$helper"
cat > "$helper" <<'ASKPASS'
#!/bin/sh
printf '%s\n' "$MGMT_SCP_PASSWORD"
ASKPASS
DISPLAY="${DISPLAY:-ib-mgmt-auth}" SSH_ASKPASS="$helper" SSH_ASKPASS_REQUIRE=force \
    ssh -C -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o NumberOfPasswordPrompts=1 \
        "${MGMT_SCP_USER}@${MGMT_SERVER_IP}" true
EOF
    chmod 700 "$local_helper"

    ssh_with_auth "${SWITCH_USER}@${probe_host}" "mkdir -p '${REMOTE_DIR}'" >/dev/null 2>&1 || {
        rm -f -- "$local_helper"
        die "Cannot create ${REMOTE_DIR} for management-server authentication validation."
    }
    scp_with_auth "$local_helper" "${SWITCH_USER}@${probe_host}:${remote_helper}" >/dev/null 2>&1 || {
        rm -f -- "$local_helper"
        die "Cannot deploy the management-server authentication helper to ${probe_host}."
    }
    rm -f -- "$local_helper"

    while (( attempt <= 3 )); do
        if output=$({
            printf '%s\n' "$mgmt_server_ip"
            printf '%s\n' "$MGMT_SCP_USER"
            printf '%s\n' "$MGMT_SCP_PASSWORD"
        } | ssh_with_auth_stdin "${SWITCH_USER}@${probe_host}" "bash '${remote_helper}'" 2>&1); then
            ssh_with_auth "${SWITCH_USER}@${probe_host}" "rm -f -- '${remote_helper}'" >/dev/null 2>&1 || true
            log "[${probe_host}] Management-server SCP authentication verified: ${MGMT_SCP_USER}@${mgmt_server_ip} (attempt ${attempt}/3)."
            return 0
        else
            rc=$?
        fi

        detail=$(printf '%s\n' "$output" | awk 'NF {line=$0} END {print line}')
        if [[ "$output" != *"Permission denied"* && "$output" != *"Authentication failed"* ]]; then
            ssh_with_auth "${SWITCH_USER}@${probe_host}" "rm -f -- '${remote_helper}'" >/dev/null 2>&1 || true
            [[ -n "$detail" ]] || detail="ssh exited with code ${rc}"
            log "[${probe_host}] ERROR: Management-server SSH connection failed before authentication could be verified: ${detail}"
            die "Cannot validate SCP access to ${MGMT_SCP_USER}@${mgmt_server_ip}; password retry was not attempted."
        fi

        log "[${probe_host}] ERROR: Management-server authentication failed for ${MGMT_SCP_USER}@${mgmt_server_ip} (attempt ${attempt}/3)."
        if (( attempt >= 3 )); then
            ssh_with_auth "${SWITCH_USER}@${probe_host}" "rm -f -- '${remote_helper}'" >/dev/null 2>&1 || true
            die "Management-server authentication failed after 3 attempts; exiting before upgrade phases."
        fi

        tty_available || {
            ssh_with_auth "${SWITCH_USER}@${probe_host}" "rm -f -- '${remote_helper}'" >/dev/null 2>&1 || true
            die "Cannot retry the management-server password: /dev/tty is unavailable."
        }
        printf "Management-server SCP password for %s@%s (attempt %d/3): " \
            "$MGMT_SCP_USER" "$mgmt_server_ip" "$(( attempt + 1 ))" > /dev/tty
        IFS= read -r -s password < /dev/tty
        printf "\n" > /dev/tty
        MGMT_SCP_PASSWORD="$password"
        export MGMT_SCP_PASSWORD
        attempt=$(( attempt + 1 ))
    done

    ssh_with_auth "${SWITCH_USER}@${probe_host}" "rm -f -- '${remote_helper}'" >/dev/null 2>&1 || true
    die "Management-server authentication failed after 3 attempts; exiting before upgrade phases."
}

# Prompts once and retains the password only in this process environment. A
# permission-restricted temporary askpass helper lets non-interactive ssh/scp
# reuse it for every switch without exposing it in arguments or log files.
prepare_ssh_auth() {
    local host probe_rc label
    local -a active_hosts=()

    PASSWORD_PROBE_HOST=""
    PUBLIC_KEY_REACHABLE_HOST=""
    PUBLIC_KEY_PROBE_TRANSPORT_FAILURES=0
    PUBLIC_KEY_AUTH_FAILED_HOSTS=()
    PUBLIC_KEY_SUCCESS_HOSTS=()
    SKIPPED_SSH_HOSTS=()
    SKIPPED_SSH_LABELS=()
    SKIPPED_SSH_DETAILS=()
    SKIPPED_SSH_REPORT_PRINTED=false
    for host in "${IB_HOSTS[@]}"; do
        public_key_login_available "$host"
        probe_rc=$?
        case "$probe_rc" in
            0)
                active_hosts+=("$host")
                [[ -n "$PUBLIC_KEY_REACHABLE_HOST" ]] || PUBLIC_KEY_REACHABLE_HOST="$host"
                PUBLIC_KEY_SUCCESS_HOSTS+=("$host")
                ;;
            1)
                active_hosts+=("$host")
                PUBLIC_KEY_AUTH_FAILED_HOSTS+=("$host")
                ;;
            *)
                PUBLIC_KEY_PROBE_TRANSPORT_FAILURES=$(( PUBLIC_KEY_PROBE_TRANSPORT_FAILURES + 1 ))
                label=$(hostname_label_for_ip "$host" || true)
                SKIPPED_SSH_HOSTS+=("$host")
                SKIPPED_SSH_LABELS+=("$label")
                SKIPPED_SSH_DETAILS+=("$PUBLIC_KEY_PROBE_DETAIL")
                log "[${host}] WARNING: Public-key SSH probe could not reach the device: ${PUBLIC_KEY_PROBE_DETAIL}; removing it from subsequent operations."
                ;;
        esac
    done
    IB_HOSTS=("${active_hosts[@]}")

    if (( ${#SKIPPED_SSH_HOSTS[@]} > 0 )); then
        log "Active switch targets after SSH probe: ${#IB_HOSTS[@]}; skipped as unreachable: ${#SKIPPED_SSH_HOSTS[@]}."
    fi

    if (( ${#PUBLIC_KEY_AUTH_FAILED_HOSTS[@]} == 0 )); then
        if [[ -z "$PUBLIC_KEY_REACHABLE_HOST" ]]; then
            die "No selected switch could be reached by SSH; password input was not requested."
        fi
        SWITCH_PASSWORD_REQUIRED=false
        _ASKPASS_HELPER=""
        if (( PUBLIC_KEY_PROBE_TRANSPORT_FAILURES == 0 )); then
            log "Passwordless SSH verified on all ${#IB_HOSTS[@]} selected switch(es); no switch password is required."
        else
            log "Passwordless SSH verified on all reachable switches; ${PUBLIC_KEY_PROBE_TRANSPORT_FAILURES} switch(es) could not be tested because of SSH connection errors. No switch password is required."
        fi
        return 0
    fi

    PASSWORD_PROBE_HOST="${PUBLIC_KEY_AUTH_FAILED_HOSTS[0]}"
    SWITCH_PASSWORD_REQUIRED=true
    log "Passwordless SSH authentication was rejected by ${#PUBLIC_KEY_AUTH_FAILED_HOSTS[@]} switch(es); a shared switch password is required."
    if [[ -z "${IB_SWITCH_PASSWORD:-}" ]]; then
        tty_available || die "Cannot prompt for the switch password: /dev/tty is unavailable."
        printf "  Switch password for %s (attempt 1/3, used for all devices): " "$SWITCH_USER" > /dev/tty
        IFS= read -r -s IB_SWITCH_PASSWORD < /dev/tty
        printf "\n" > /dev/tty
        [[ -n "$IB_SWITCH_PASSWORD" ]] || die "Switch password cannot be empty."
        export IB_SWITCH_PASSWORD
    fi

    _ASKPASS_HELPER=$(mktemp "${TMPDIR:-/tmp}/ib-upgrade-askpass.XXXXXX") \
        || die "Failed to create the temporary SSH askpass helper."
    chmod 700 "$_ASKPASS_HELPER"
    cat > "$_ASKPASS_HELPER" <<'EOF'
#!/bin/sh
printf '%s\n' "$IB_SWITCH_PASSWORD"
EOF
}

report_skipped_ssh_targets() {
    local count=${#SKIPPED_SSH_HOSTS[@]} index host label detail display
    (( count > 0 )) || return 0
    $SKIPPED_SSH_REPORT_PRINTED && return 0
    SKIPPED_SSH_REPORT_PRINTED=true

    begin_log_section "Skipped switches: SSH unavailable during Phase 0 (${count})"
    for (( index=0; index<count; index++ )); do
        host="${SKIPPED_SSH_HOSTS[$index]}"
        label="${SKIPPED_SSH_LABELS[$index]}"
        detail="${SKIPPED_SSH_DETAILS[$index]}"
        display="$host"
        [[ -n "$label" ]] && display="${label} ${host}"
        log "[${display}] skipped_from_all_subsequent_operations; reason=${detail}"
    done
}

# Verifies the shared switch credential against the first target that failed
# the public-key probe. Authentication failures allow up to three total
# password attempts. A transport failure moves to another authentication-
# rejected target because re-entering a password cannot fix connectivity.
validate_switch_authentication() {
    (( ${#IB_HOSTS[@]} > 0 )) || die "No switch target is available for authentication validation."
    local probe_host="${PASSWORD_PROBE_HOST:-${PUBLIC_KEY_REACHABLE_HOST:-${IB_HOSTS[0]}}}"
    local attempt=1 output="" rc=0 password="" detail="" candidate=""
    local authentication_rejected=false
    local -a password_candidates=("${PUBLIC_KEY_AUTH_FAILED_HOSTS[@]}" "${PUBLIC_KEY_SUCCESS_HOSTS[@]}")

    if ! $SWITCH_PASSWORD_REQUIRED; then
        return 0
    fi

    while (( attempt <= 3 )); do
        authentication_rejected=false
        for candidate in "${password_candidates[@]}"; do
            output=$(ssh_with_password_auth "${SWITCH_USER}@${candidate}" "true" 2>&1)
            rc=$?
            if (( rc == 0 )); then
                PASSWORD_PROBE_HOST="$candidate"
                log "[${candidate}] SSH password authentication verified for ${SWITCH_USER} (attempt ${attempt}/3)."
                return 0
            fi

            detail=$(printf '%s\n' "$output" | awk 'NF {line=$0} END {print line}')
            [[ -n "$detail" ]] || detail="ssh exited with code ${rc}"
            if ssh_output_is_authentication_rejection "$output"; then
                probe_host="$candidate"
                authentication_rejected=true
                break
            fi
            log "[${candidate}] WARNING: SSH connection failed before password authentication could be verified: ${detail}; trying another device."
        done

        $authentication_rejected || \
            die "Password authentication could not be tested: every previously reachable switch currently has an SSH connection error."

        log "[${probe_host}] ERROR: Switch authentication failed for ${SWITCH_USER} (attempt ${attempt}/3)."
        if (( attempt >= 3 )); then
            die "Switch authentication failed after 3 attempts; exiting before hostname and version checks."
        fi

        tty_available || die "Cannot retry the switch password: /dev/tty is unavailable."
        printf "  Switch password for %s (attempt %d/3, used for all devices): " \
            "$SWITCH_USER" "$(( attempt + 1 ))" > /dev/tty
        IFS= read -r -s password < /dev/tty
        printf "\n" > /dev/tty
        [[ -n "$password" ]] || {
            log "[${probe_host}] ERROR: Empty switch password was rejected (attempt $(( attempt + 1 ))/3)."
            IB_SWITCH_PASSWORD=""
            attempt=$(( attempt + 1 ))
            continue
        }
        IB_SWITCH_PASSWORD="$password"
        export IB_SWITCH_PASSWORD
        attempt=$(( attempt + 1 ))
    done

    die "Switch authentication failed after 3 attempts; exiting before hostname and version checks."
}

# NVOS emits this fixed SSH server banner once per connection. Suppress only
# that exact line and retain all authentication, transport, and remote errors.
filter_switch_ssh_banner() {
    local line normalized
    while IFS= read -r line || [[ -n "$line" ]]; do
        normalized="${line%$'\r'}"
        [[ "$normalized" == "NVOS switch" ]] || printf '%s\n' "$line" >&2
    done
}

# Probe without an askpass helper and explicitly disable every password path.
# Return 0 for successful public-key login, 1 only for an authentication
# rejection (password may help), and 2 for transport/SSH failures (password
# cannot help). PUBLIC_KEY_PROBE_DETAIL retains the final useful error line.
public_key_login_available() {
    local output rc normalized
    output=$(LC_ALL=C command ssh -C -n \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o PreferredAuthentications=publickey \
        $SSH_OPTS "${SWITCH_USER}@$1" true 2>&1)
    rc=$?
    if (( rc == 0 )); then
        PUBLIC_KEY_PROBE_DETAIL=""
        return 0
    fi

    normalized=$(printf '%s\n' "$output" \
        | awk '{sub(/\r$/, "")} $0 != "NVOS switch" && NF {line=$0} END {print line}')
    [[ -n "$normalized" ]] || normalized="ssh exited with code ${rc}"
    PUBLIC_KEY_PROBE_DETAIL="$normalized"

    ssh_output_is_authentication_rejection "$output" && return 1
    return 2
}

ssh_output_is_authentication_rejection() {
    case "$1" in
        *"Permission denied"*|*"Authentication failed"*|*"Too many authentication failures"*|*"No supported authentication methods available"*) return 0 ;;
        *) return 1 ;;
    esac
}

ssh_with_password_auth() {
    local rc
    LC_ALL=C DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS="$_ASKPASS_HELPER" \
        SSH_ASKPASS_REQUIRE=force command ssh -C -n \
        -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password,keyboard-interactive \
        $SSH_OPTS "$@" 2> >(filter_switch_ssh_banner)
    rc=$?
    return "$rc"
}

ssh_with_auth() {
    local rc
    if [[ -z "${_ASKPASS_HELPER:-}" ]]; then
        command ssh -C -n -o BatchMode=yes $SSH_OPTS "$@" \
            2> >(filter_switch_ssh_banner)
        rc=$?
        return "$rc"
    fi
    DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS="$_ASKPASS_HELPER" \
        SSH_ASKPASS_REQUIRE=force command ssh -C -n $SSH_OPTS "$@" \
        2> >(filter_switch_ssh_banner)
    rc=$?
    return "$rc"
}

scp_with_auth() {
    local rc
    if [[ -z "${_ASKPASS_HELPER:-}" ]]; then
        command scp -q -C -o BatchMode=yes $SSH_OPTS "$@" \
            2> >(filter_switch_ssh_banner)
        rc=$?
        return "$rc"
    fi
    DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS="$_ASKPASS_HELPER" \
        SSH_ASKPASS_REQUIRE=force command scp -q -C $SSH_OPTS "$@" \
        2> >(filter_switch_ssh_banner)
    rc=$?
    return "$rc"
}

# Same switch authentication as ssh_with_auth, but keeps stdin available for
# sending the management-server credentials through the encrypted SSH channel.
ssh_with_auth_stdin() {
    local rc
    if [[ -z "${_ASKPASS_HELPER:-}" ]]; then
        command ssh -C -o BatchMode=yes $SSH_OPTS "$@" \
            2> >(filter_switch_ssh_banner)
        rc=$?
        return "$rc"
    fi
    DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS="$_ASKPASS_HELPER" \
        SSH_ASKPASS_REQUIRE=force command ssh -C $SSH_OPTS "$@" \
        2> >(filter_switch_ssh_banner)
    rc=$?
    return "$rc"
}

# Deployment commands need a single combined stream so remote stderr receives
# the same timestamp/hostname formatting as stdout. Banner/noise filtering is
# performed by log_remote_output without altering the SSH exit status.
ssh_with_auth_stdin_combined() {
    local rc
    if [[ -z "${_ASKPASS_HELPER:-}" ]]; then
        command ssh -C -o BatchMode=yes $SSH_OPTS "$@" 2>&1
        rc=$?
        return "$rc"
    fi
    DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS="$_ASKPASS_HELPER" \
        SSH_ASKPASS_REQUIRE=force command ssh -C $SSH_OPTS "$@" 2>&1
    rc=$?
    return "$rc"
}

ssh_with_auth_tty() {
    local rc
    if [[ -z "${_ASKPASS_HELPER:-}" ]]; then
        command ssh -C -tt -o BatchMode=yes $SSH_OPTS "$@" \
            2> >(filter_switch_ssh_banner)
        rc=$?
        return "$rc"
    fi
    DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS="$_ASKPASS_HELPER" \
        SSH_ASKPASS_REQUIRE=force command ssh -C -tt $SSH_OPTS "$@" \
        2> >(filter_switch_ssh_banner)
    rc=$?
    return "$rc"
}

# Finds the public key offered for the optional switch installation. An
# explicit --public-key is authoritative; otherwise prefer the common modern
# key names in the invoking account's ~/.ssh directory.
resolve_public_key_file() {
    local candidate

    if $PUBLIC_KEY_FILE_EXPLICIT; then
        [[ -f "$PUBLIC_KEY_FILE" && -r "$PUBLIC_KEY_FILE" ]] || \
            die "Public key file is not a readable regular file: ${PUBLIC_KEY_FILE}"
        return 0
    fi

    for candidate in \
        "${HOME:-}/.ssh/id_ed25519.pub" \
        "${HOME:-}/.ssh/id_rsa.pub" \
        "${HOME:-}/.ssh/id_ecdsa.pub"; do
        [[ "$candidate" != "/.ssh/"* ]] || continue
        if [[ -f "$candidate" && -r "$candidate" ]]; then
            PUBLIC_KEY_FILE="$candidate"
            return 0
        fi
    done
    return 1
}

# Loads exactly one OpenSSH public key. Keeping the validated value in memory
# avoids logging it or interpolating it into a remote shell command.
load_public_key_value() {
    local line_count key_type key_blob

    line_count=$(awk 'NF && $1 !~ /^#/ {count++} END {print count + 0}' "$PUBLIC_KEY_FILE")
    (( line_count == 1 )) || return 1
    PUBLIC_KEY_VALUE=$(awk 'NF && $1 !~ /^#/ {sub(/\r$/, ""); print; exit}' "$PUBLIC_KEY_FILE")
    read -r key_type key_blob _ <<< "$PUBLIC_KEY_VALUE"
    case "$key_type" in
        ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
        *) return 1 ;;
    esac
    [[ "$key_blob" =~ ^[A-Za-z0-9+/]+={0,3}$ ]] || return 1
    command -v ssh-keygen >/dev/null 2>&1 || return 1
    ssh-keygen -lf "$PUBLIC_KEY_FILE" >/dev/null 2>&1 || return 1

    PUBLIC_KEY_IDENTITY_FILE=""
    if [[ "$PUBLIC_KEY_FILE" == *.pub && -r "${PUBLIC_KEY_FILE%.pub}" ]]; then
        PUBLIC_KEY_IDENTITY_FILE="${PUBLIC_KEY_FILE%.pub}"
    fi
    return 0
}

public_key_description() {
    local description=""
    if command -v ssh-keygen >/dev/null 2>&1; then
        description=$(ssh-keygen -lf "$PUBLIC_KEY_FILE" 2>/dev/null \
            | awk '{print $2 " " $4; exit}')
    fi
    [[ -n "$description" ]] || description=$(basename "$PUBLIC_KEY_FILE")
    printf '%s' "$description"
}

# Adds the key without replacing authorized_keys. The full-line comparison
# makes repeated runs idempotent and preserves every existing entry.
install_public_key_on_host() {
    local host="$1" output rc remote_command
    remote_command='IFS= read -r public_key || exit 70
[[ -n "$public_key" ]] || exit 70
umask 077
ssh_dir="$HOME/.ssh"
authorized_keys="$ssh_dir/authorized_keys"
mkdir -p -- "$ssh_dir" || exit 71
chmod 700 "$ssh_dir" || exit 72
touch "$authorized_keys" || exit 73
chmod 600 "$authorized_keys" || exit 74
if grep -Fqx -- "$public_key" "$authorized_keys"; then
    printf "present\n"
else
    printf "%s\n" "$public_key" >> "$authorized_keys" || exit 75
    printf "added\n"
fi'

    if output=$(printf '%s\n' "$PUBLIC_KEY_VALUE" \
        | ssh_with_auth_stdin "${SWITCH_USER}@${host}" "bash -c '$remote_command'" 2>&1); then
        PUBLIC_KEY_INSTALL_RESULT=$(printf '%s\n' "$output" | awk 'NF {line=$0} END {print line}')
        [[ "$PUBLIC_KEY_INSTALL_RESULT" == "added" || "$PUBLIC_KEY_INSTALL_RESULT" == "present" ]] || \
            PUBLIC_KEY_INSTALL_RESULT="installed"
        return 0
    else
        rc=$?
    fi
    PUBLIC_KEY_INSTALL_RESULT=$(printf '%s\n' "$output" | awk 'NF {line=$0} END {print line}')
    [[ -n "$PUBLIC_KEY_INSTALL_RESULT" ]] || PUBLIC_KEY_INSTALL_RESULT="ssh exited with code ${rc}"
    return "$rc"
}

# This check must never fall back to the password retained for the upgrade.
# Put BatchMode=yes before the shared options because OpenSSH uses the first
# value obtained for an option when the same option appears more than once.
verify_public_key_login() {
    local host="$1" rc
    local -a identity_options=()
    if [[ -n "${PUBLIC_KEY_IDENTITY_FILE:-}" ]]; then
        identity_options=(-o IdentitiesOnly=yes -i "$PUBLIC_KEY_IDENTITY_FILE")
    fi

    DISPLAY="${DISPLAY:-ib-upgrade}" SSH_ASKPASS_REQUIRE=never \
        command ssh -C -n \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o PreferredAuthentications=publickey \
        "${identity_options[@]}" $SSH_OPTS "${SWITCH_USER}@${host}" true \
        2> >(filter_switch_ssh_banner)
    rc=$?
    return "$rc"
}

# Offered once per top-level workflow, after the supplied switch password has
# been proven against a target lacking public-key access. It remains opt-in
# even with --yes, and is skipped when every target was already passwordless.
offer_public_key_installation() {
    local answer="" host description
    local added=0 present=0 failed=0

    $VERIFY_ONLY && return 0
    [[ "${IB_PUBLIC_KEY_PROMPT_DONE:-0}" == "1" ]] && return 0
    IB_PUBLIC_KEY_PROMPT_DONE=1
    export IB_PUBLIC_KEY_PROMPT_DONE

    if ! $SWITCH_PASSWORD_REQUIRED; then
        return 0
    fi

    if ! resolve_public_key_file; then
        log "Public-key installation not offered: no default public key was found (use --public-key FILE to select one)."
        return 0
    fi
    if ! load_public_key_value; then
        if $PUBLIC_KEY_FILE_EXPLICIT; then
            die "Public key file must contain exactly one supported OpenSSH public key: ${PUBLIC_KEY_FILE}"
        fi
        log "Public-key installation not offered: default key is not a supported single OpenSSH public key (${PUBLIC_KEY_FILE})."
        return 0
    fi
    tty_available || {
        log "Public-key installation not offered because no controlling TTY is available."
        return 0
    }

    description=$(public_key_description)
    printf '\n  Install public key %s on all %d selected switch(es)? [y/N] (default: no in 10s): ' \
        "$description" "${#IB_HOSTS[@]}" > /dev/tty
    if IFS= read -r -t 10 answer < /dev/tty; then
        answer=$(lower "$answer")
    else
        printf '\n' > /dev/tty
        answer=""
    fi
    if [[ "$answer" != "y" && "$answer" != "yes" ]]; then
        log "Public-key installation not requested."
        return 0
    fi

    log "Installing the selected public key on ${#IB_HOSTS[@]} switch(es)."
    for host in "${IB_HOSTS[@]}"; do
        if ! install_public_key_on_host "$host"; then
            log "[${host}] ERROR: Public-key installation failed: ${PUBLIC_KEY_INSTALL_RESULT}"
            failed=$(( failed + 1 ))
            continue
        fi
        if ! verify_public_key_login "$host"; then
            log "[${host}] ERROR: Key was ${PUBLIC_KEY_INSTALL_RESULT}, but passwordless SSH verification failed."
            failed=$(( failed + 1 ))
            continue
        fi
        if [[ "$PUBLIC_KEY_INSTALL_RESULT" == "present" ]]; then
            log "[${host}] Public key already present; passwordless SSH verified."
            present=$(( present + 1 ))
        else
            log "[${host}] Public key installed; passwordless SSH verified."
            added=$(( added + 1 ))
        fi
    done
    log "Public-key result: installed=${added}  already_present=${present}  failed=${failed}"
    return 0
}

# Collects management-server interface IPv4 addresses once. The switch-side w
# result must match one of these addresses before it is trusted as an SCP host.
discover_local_interface_ips() {
    local addresses=""
    if command -v ip >/dev/null 2>&1; then
        addresses=$(ip -o -4 addr show scope global 2>/dev/null \
            | awk '{sub(/\/.*/, "", $4); print $4}')
    fi
    if [[ -z "$addresses" ]] && command -v ifconfig >/dev/null 2>&1; then
        addresses=$(ifconfig 2>/dev/null \
            | awk '/^[[:space:]]*inet[[:space:]]/ {print $2}' \
            | awk '$1 !~ /^127\./')
    fi
    if [[ -z "$addresses" ]] && command -v hostname >/dev/null 2>&1; then
        addresses=$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '$1 ~ /^[0-9]+\./ && $1 !~ /^127\./')
    fi

    LOCAL_INTERFACE_IPS=$(printf '%s\n' "$addresses" | awk 'NF && !seen[$0]++')
    [[ -n "$LOCAL_INTERFACE_IPS" ]] \
        || die "Could not discover any management-server interface IPv4 address."
    log "Management-server interface IPs: $(echo "$LOCAL_INTERFACE_IPS" | tr '\n' ' ')"
}

# Sets DETECTED_MGMT_SERVER_IP to the source IP observed by this switch. A temporary
# TTY is allocated so the current probe session appears in w; matching on that
# TTY avoids confusing it with older sessions from the same user.
detect_mgmt_server_ip() {
    local host="$1" explicit_address="${2:-}" observed_ip

    if [[ -n "$explicit_address" ]]; then
        DETECTED_MGMT_SERVER_IP="$explicit_address"
        return 0
    fi

    # Defer local-interface discovery until a package transfer actually needs
    # an automatically detected server address. Runs with no pending upgrades
    # therefore avoid an unnecessary Phase 0 probe and its log output.
    [[ -n "$LOCAL_INTERFACE_IPS" ]] || discover_local_interface_ips

    observed_ip=$(ssh_with_auth_tty "${SWITCH_USER}@${host}" \
        "current_tty=\$(tty 2>/dev/null); current_tty=\${current_tty#/dev/}; (w -hi 2>/dev/null || w -h) | awk -v user='${SWITCH_USER}' -v tty=\"\$current_tty\" '\$1==user && \$2==tty {print \$3; exit}'" \
        2>/dev/null | tr -d '\r' \
        | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')

    if [[ -z "$observed_ip" ]]; then
        log "[${host}] ERROR: Could not identify the current ${SWITCH_USER} session source address from w."
        return 1
    fi
    if ! printf '%s\n' "$LOCAL_INTERFACE_IPS" | awk -v ip="$observed_ip" '$0==ip {found=1} END {exit !found}'; then
        log "[${host}] ERROR: w reported ${observed_ip}, but it is not a local management-server interface IP."
        return 1
    fi
    DETECTED_MGMT_SERVER_IP="$observed_ip"
    log "[${host}] Management-server address detected from w: ${DETECTED_MGMT_SERVER_IP}"
}

# ─── Version Extraction from Filenames ─────────────────────────────────────────

# nvosv25-02-7002amd64.bin → 25.02.7002
os_ver_from_file() {
    basename "$1" | grep -oE 'nvosv[0-9]+-[0-9]+-[0-9]+' \
        | sed 's/nvosv//; s/-/./g'
}

# FUI000557_BURN_BM_... → FUI000557
cpld_fui_from_file() {
    basename "$1" | grep -oE 'FUI[0-9]+' | head -1
}

# FUI..._CPLD000232_REV0900_CPLD000383_REV0800_...
# → newline-separated "CPLDID:REV" pairs, first occurrence per CPLD ID
cpld_pairs_from_file() {
    basename "$1" | grep -oE 'CPLD[0-9]+_REV[0-9]+' \
        | awk -F_ '!seen[$1]++ { print $1 ":" $2 }'
}

# ─── Version Comparison ────────────────────────────────────────────────────────

# BIOS uses an explicit supported transition, never a numeric comparison.
bios_version_state() {
    case "$1" in
        "$BIOS_UPGRADE_FROM_VERSION") printf 'upgrade\n' ;;
        "$TARGET_BIOS_VERSION")       printf 'target\n' ;;
        *)                            printf 'unsupported\n' ;;
    esac
}

# ver_lt A B → 0 (true) if A < B  (dot-separated integers, e.g. 25.02.6077)
ver_lt() {
    [[ -z "$1" || -z "$2" ]] && return 1
    local a="$1" b="$2"
    IFS='.' read -ra A <<< "$a"
    IFS='.' read -ra B <<< "$b"
    local i len
    len=$(( ${#A[@]} > ${#B[@]} ? ${#A[@]} : ${#B[@]} ))
    for (( i=0; i<len; i++ )); do
        local ai="${A[$i]:-0}" bi="${B[$i]:-0}"
        ai=$((10#$ai)); bi=$((10#$bi))
        (( ai < bi )) && return 0
        (( ai > bi )) && return 1
    done
    return 1  # equal → not less-than
}

# cpld_rev_num "REV0900" → "900"  (strips leading zeros to avoid octal errors)
cpld_rev_num() {
    local n
    n=$(echo "$1" | grep -oE '[0-9]+' | head -1 | sed 's/^0*//')
    echo "${n:-0}"
}

# ─── OS Upgrade Step Finder ────────────────────────────────────────────────────

# find_next_os_step <cur_ver>
# Prints path of first TARGET_OS_FILES entry with version > cur_ver.
# Prints nothing (returns 1) if cur_ver is already at or above all targets.
find_next_os_step() {
    local cur_ver="$1" os_file os_ver
    for os_file in "${TARGET_OS_FILES[@]}"; do
        os_ver=$(os_ver_from_file "$os_file")
        if ver_lt "$cur_ver" "$os_ver"; then
            echo "$os_file"
            return 0
        fi
    done
    return 1
}

validate_configuration() {
    (( ${#TARGET_OS_FILES[@]} > 0 )) || die "TARGET_OS_FILES cannot be empty."
    local file file_name version previous_version="" burn_fui refresh_fui
    local burn_pairs refresh_pairs seen_names=$'\n'

    for file in "${TARGET_OS_FILES[@]}" "$TARGET_BIOS_FILE" "$TARGET_CPLD_BURN_FILE" "$TARGET_CPLD_REFRESH_FILE"; do
        file_name=$(basename "$file")
        [[ "$file_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "Unsafe target package filename: ${file_name}"
        [[ "$seen_names" != *$'\n'"$file_name"$'\n'* ]] || die "Duplicate target package filename: ${file_name}"
        seen_names+="${file_name}"$'\n'
    done

    for file in "${TARGET_OS_FILES[@]}"; do
        version=$(os_ver_from_file "$file")
        [[ -n "$version" ]] || die "Cannot parse OS version from target filename: ${file}"
        if [[ -n "$previous_version" ]] && ! ver_lt "$previous_version" "$version"; then
            die "TARGET_OS_FILES must be strictly increasing: ${previous_version} is not lower than ${version}."
        fi
        previous_version="$version"
    done

    [[ "$TARGET_BIOS_FILE" == *.cab || "$TARGET_BIOS_FILE" == *.CAB ]] \
        || die "TARGET_BIOS_FILE must use a .cab filename."
    [[ "$BIOS_UPGRADE_FROM_VERSION" =~ ^[A-Za-z0-9]+_[0-9]+([.][0-9]+)+$ ]] \
        || die "Invalid BIOS_UPGRADE_FROM_VERSION: ${BIOS_UPGRADE_FROM_VERSION}"
    [[ "$TARGET_BIOS_VERSION" =~ ^[A-Za-z0-9]+_[0-9]+([.][0-9]+)+$ ]] \
        || die "Invalid TARGET_BIOS_VERSION: ${TARGET_BIOS_VERSION}"
    [[ "$BIOS_UPGRADE_FROM_VERSION" != "$TARGET_BIOS_VERSION" ]] \
        || die "BIOS source and target versions must be different."

    burn_fui=$(cpld_fui_from_file "$TARGET_CPLD_BURN_FILE")
    refresh_fui=$(cpld_fui_from_file "$TARGET_CPLD_REFRESH_FILE")
    [[ -n "$burn_fui" && "$burn_fui" == "$refresh_fui" ]] \
        || die "CPLD BURN and REFRESH files must contain the same FUI identifier."
    burn_pairs=$(cpld_pairs_from_file "$TARGET_CPLD_BURN_FILE" | sort)
    refresh_pairs=$(cpld_pairs_from_file "$TARGET_CPLD_REFRESH_FILE" | sort)
    [[ -n "$burn_pairs" && "$burn_pairs" == "$refresh_pairs" ]] \
        || die "CPLD BURN and REFRESH files must contain the same non-empty CPLD target set."

    [[ -z "$MGMT_SCP_USER" || "$MGMT_SCP_USER" =~ ^[A-Za-z0-9._-]+$ ]] \
        || die "Management-server username contains unsafe characters."
}

# ─── Sub-script Generation ─────────────────────────────────────────────────────

# Shared by SCP-mode generated scripts. NVUE's interactive wrapper ignores
# SSH_ASKPASS and requires a controlling terminal for the SCP password prompt.
# A small Python PTY relay supplies the already-validated password without
# embedding it in the URI/argv or echoing it to the generated-script log.
generated_scp_fetch_helper() {
    cat <<'SCP_FETCH_HELPER'
prepare_scp_fetch_auth() {
    [[ -n "${MGMT_SERVER_IP:-}" && -n "${MGMT_SCP_USER:-}" && -n "${MGMT_SCP_PASSWORD:-}" ]] || {
        log "[SCP] ERROR: Management-server address or credentials were not provided."
        return 1
    }
    command -v python3 >/dev/null 2>&1 || {
        log "[SCP] ERROR: python3 is required to answer the NVUE SCP password prompt safely."
        return 1
    }
}
run_nvue_scp_fetch() {
    prepare_scp_fetch_auth || return 1
    python3 - "$@" <<'PY'
import errno
import os
import pty
import signal
import sys

password = os.environ.get("MGMT_SCP_PASSWORD", "")
if not password:
    print("[SCP] ERROR: Management-server password is unavailable.", file=sys.stderr)
    raise SystemExit(70)

pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])

pending = b""
password_sent = False
repeated_prompt = False
while True:
    try:
        data = os.read(fd, 4096)
    except OSError as exc:
        if exc.errno == errno.EIO:
            break
        raise
    if not data:
        break
    pending += data
    while True:
        prompt_at = pending.lower().find(b"password:")
        if prompt_at >= 0:
            sys.stdout.buffer.write(pending[:prompt_at])
            sys.stdout.buffer.flush()
            pending = pending[prompt_at + len(b"password:"):]
            if password_sent:
                repeated_prompt = True
                os.kill(pid, signal.SIGTERM)
                break
            os.write(fd, password.encode() + b"\n")
            password_sent = True
            continue
        # Retain enough trailing bytes to detect a prompt split across reads.
        if len(pending) > len(b"password:") - 1:
            keep = len(b"password:") - 1
            sys.stdout.buffer.write(pending[:-keep])
            sys.stdout.buffer.flush()
            pending = pending[-keep:]
        break
    if repeated_prompt:
        break

if pending and not repeated_prompt:
    sys.stdout.buffer.write(pending)
    sys.stdout.buffer.flush()

_, status = os.waitpid(pid, 0)
try:
    os.close(fd)
except OSError:
    pass
if repeated_prompt:
    print("[SCP] ERROR: NVUE requested the management-server password more than once.", file=sys.stderr)
    raise SystemExit(77)
if os.WIFEXITED(status):
    raise SystemExit(os.WEXITSTATUS(status))
if os.WIFSIGNALED(status):
    raise SystemExit(128 + os.WTERMSIG(status))
raise SystemExit(1)
PY
}
SCP_FETCH_HELPER
}

generate_scripts_scp() {
    mkdir -p "$SCRIPTS_DIR"

    # ── OS upgrade scripts (one per entry in TARGET_OS_FILES) ─────────────
    local os_file os_ver os_script
    for os_file in "${TARGET_OS_FILES[@]}"; do
        os_ver=$(os_ver_from_file "$os_file")
        os_script="${SCRIPTS_DIR}/os_upgrade_${os_ver}.sh"
        cat > "$os_script" <<EOF
#!/bin/bash
# OS Upgrade Script — generated by upgrade_via_scp.sh
# Target OS: ${os_ver}
set -euo pipefail

SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1

JITTER=${OS_DOWNLOAD_JITTER}
LOCAL_FILE="$(basename "$os_file")"
$(generated_scp_fetch_helper)
SOURCE_URI="scp://\${MGMT_SCP_USER}@\${MGMT_SERVER_IP}${MGMT_SCP_ROOT}/${os_file}"

if [[ "\${SKIP_OS_JITTER:-0}" != "1" ]] && (( JITTER > 0 )); then
    _delay=\$(( RANDOM % JITTER ))
    log "[OS] Jitter delay \${_delay}s (max \${JITTER}s) before download ..."
    sleep "\$_delay"
fi

log "[OS] Fetching image directly through NVUE: \$SOURCE_URI"
run_nvue_scp_fetch nv action fetch system image "\$SOURCE_URI"
nv action install system image files "\$LOCAL_FILE" force

log "[OS] Done. Reboot required to activate OS ${os_ver}."
EOF
        chmod +x "$os_script"
        log "Generated: ${os_script}  (OS: ${os_ver})"
    done

    # ── BIOS upgrade script ────────────────────────────────────────────────
    local bios_ver bios_script
    bios_ver="$TARGET_BIOS_VERSION"
    bios_script="${SCRIPTS_DIR}/bios_upgrade_${bios_ver}.sh"
    cat > "$bios_script" <<EOF
#!/bin/bash
# BIOS Upgrade Script — generated by upgrade_via_scp.sh
# Target BIOS: ${bios_ver}
set -euo pipefail

SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
LOCAL_FILE="$(basename "$TARGET_BIOS_FILE")"
$(generated_scp_fetch_helper)
SOURCE_URI="scp://\${MGMT_SCP_USER}@\${MGMT_SERVER_IP}${MGMT_SCP_ROOT}/${TARGET_BIOS_FILE}"

log "[BIOS] Fetching firmware directly through NVUE: \$SOURCE_URI"
run_nvue_scp_fetch nv action fetch platform firmware BIOS "\$SOURCE_URI"
nv action install platform firmware BIOS files "\$LOCAL_FILE" force skip-version-check

log "[BIOS] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$bios_script"
    log "Generated: ${bios_script}  (BIOS: ${bios_ver})"

    # ── CPLD upgrade script ────────────────────────────────────────────────
    local cpld_fui cpld_script
    cpld_fui=$(cpld_fui_from_file "$TARGET_CPLD_BURN_FILE")
    cpld_script="${SCRIPTS_DIR}/cpld_upgrade_${cpld_fui}.sh"
    cat > "$cpld_script" <<EOF
#!/bin/bash
# CPLD Upgrade Script — generated by upgrade_via_scp.sh
# Firmware bundle: ${cpld_fui}
set -euo pipefail

SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
BURN_LOCAL="$(basename "$TARGET_CPLD_BURN_FILE")"
REFRESH_LOCAL="$(basename "$TARGET_CPLD_REFRESH_FILE")"
$(generated_scp_fetch_helper)
BURN_URI="scp://\${MGMT_SCP_USER}@\${MGMT_SERVER_IP}${MGMT_SCP_ROOT}/${TARGET_CPLD_BURN_FILE}"
REFRESH_URI="scp://\${MGMT_SCP_USER}@\${MGMT_SERVER_IP}${MGMT_SCP_ROOT}/${TARGET_CPLD_REFRESH_FILE}"

log "[CPLD] Fetching BURN firmware directly through NVUE: \$BURN_URI"
run_nvue_scp_fetch nv action fetch platform firmware CPLD1 "\$BURN_URI"
nv action install platform firmware CPLD1 files "\$BURN_LOCAL" skip-reboot

log "[CPLD] Fetching REFRESH firmware directly through NVUE: \$REFRESH_URI"
run_nvue_scp_fetch nv action fetch platform firmware CPLD1 "\$REFRESH_URI"
nv action install platform firmware CPLD1 files "\$REFRESH_LOCAL" force

log "[CPLD] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$cpld_script"
    log "Generated: ${cpld_script}  (CPLD bundle: ${cpld_fui})"
}

generate_scripts_local() {
    mkdir -p "$SCRIPTS_DIR"
    local os_file os_ver os_script os_basename
    for os_file in "${TARGET_OS_FILES[@]}"; do
        os_ver=$(os_ver_from_file "$os_file")
        os_basename=$(basename "$os_file")
        os_script="${SCRIPTS_DIR}/os_upgrade_${os_ver}.sh"
        cat > "$os_script" <<EOF
#!/bin/bash
# OS Upgrade Script — generated by upgrade.sh (local method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
LOCAL_FILE="${os_basename}"
LOCAL_PATH="${SWITCH_LOCAL_DIR}/${os_basename}"
[[ -s "\$LOCAL_PATH" ]] || { log "[OS] ERROR: Local package is missing or empty: \$LOCAL_PATH"; exit 1; }
log "[OS] Using switch-local package: \$LOCAL_PATH"
nv action fetch system image "file://\$LOCAL_PATH"
nv action install system image files "\$LOCAL_FILE" force
log "[OS] Done. Reboot required to activate OS ${os_ver}."
EOF
        chmod +x "$os_script"
        log "Generated: ${os_script}  (OS: ${os_ver})"
    done

    local bios_ver bios_script bios_basename
    bios_ver="$TARGET_BIOS_VERSION"
    bios_basename=$(basename "$TARGET_BIOS_FILE")
    bios_script="${SCRIPTS_DIR}/bios_upgrade_${bios_ver}.sh"
    cat > "$bios_script" <<EOF
#!/bin/bash
# BIOS Upgrade Script — generated by upgrade.sh (local method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
LOCAL_FILE="${bios_basename}"
LOCAL_PATH="${SWITCH_LOCAL_DIR}/${bios_basename}"
[[ -s "\$LOCAL_PATH" ]] || { log "[BIOS] ERROR: Local package is missing or empty: \$LOCAL_PATH"; exit 1; }
log "[BIOS] Using switch-local package: \$LOCAL_PATH"
nv action fetch platform firmware BIOS "file://\$LOCAL_PATH"
nv action install platform firmware BIOS files "\$LOCAL_FILE" force skip-version-check
log "[BIOS] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$bios_script"
    log "Generated: ${bios_script}  (BIOS: ${bios_ver})"

    local cpld_fui cpld_script burn_basename refresh_basename
    cpld_fui=$(cpld_fui_from_file "$TARGET_CPLD_BURN_FILE")
    burn_basename=$(basename "$TARGET_CPLD_BURN_FILE")
    refresh_basename=$(basename "$TARGET_CPLD_REFRESH_FILE")
    cpld_script="${SCRIPTS_DIR}/cpld_upgrade_${cpld_fui}.sh"
    cat > "$cpld_script" <<EOF
#!/bin/bash
# CPLD Upgrade Script — generated by upgrade.sh (local method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
BURN_LOCAL="${burn_basename}"
REFRESH_LOCAL="${refresh_basename}"
BURN_PATH="${SWITCH_LOCAL_DIR}/${burn_basename}"
REFRESH_PATH="${SWITCH_LOCAL_DIR}/${refresh_basename}"
[[ -s "\$BURN_PATH" ]] || { log "[CPLD] ERROR: Local BURN package is missing or empty: \$BURN_PATH"; exit 1; }
[[ -s "\$REFRESH_PATH" ]] || { log "[CPLD] ERROR: Local REFRESH package is missing or empty: \$REFRESH_PATH"; exit 1; }
nv action fetch platform firmware CPLD1 "file://\$BURN_PATH"
nv action install platform firmware CPLD1 files "\$BURN_LOCAL" skip-reboot
nv action fetch platform firmware CPLD1 "file://\$REFRESH_PATH"
nv action install platform firmware CPLD1 files "\$REFRESH_LOCAL" force
log "[CPLD] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$cpld_script"
    log "Generated: ${cpld_script}  (CPLD bundle: ${cpld_fui})"
}

http_path_for() {
    local file
    file=$(basename "$1")
    case "$file" in
        *.bin|*.BIN) printf '/image/%s\n' "$file" ;;
        *)           printf '/firmware/%s\n' "$file" ;;
    esac
}

generate_scripts_https() {
    mkdir -p "$SCRIPTS_DIR"
    local os_file os_ver os_script os_path os_basename
    for os_file in "${TARGET_OS_FILES[@]}"; do
        os_ver=$(os_ver_from_file "$os_file")
        os_path=$(http_path_for "$os_file")
        os_basename=$(basename "$os_file")
        os_script="${SCRIPTS_DIR}/os_upgrade_${os_ver}.sh"
        cat > "$os_script" <<EOF
#!/bin/bash
# OS Upgrade Script — generated by upgrade.sh (HTTPS method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
JITTER=${OS_DOWNLOAD_JITTER}
[[ -n "\${HTTP_SERVER_IP:-}" ]] || { log "[OS] ERROR: HTTPS server address was not provided."; exit 1; }
OS_URL="https://\${HTTP_SERVER_IP}${os_path}"
LOCAL_FILE="${os_basename}"
if [[ "\${SKIP_OS_JITTER:-0}" != "1" ]] && (( JITTER > 0 )); then _delay=\$(( RANDOM % JITTER )); log "[OS] Jitter delay \${_delay}s ..."; sleep "\$_delay"; fi
log "[OS] Fetching directly through NVUE: \$OS_URL"
nv action fetch system image "\$OS_URL"
nv action install system image files "\$LOCAL_FILE" force
log "[OS] Done. Reboot required to activate OS ${os_ver}."
EOF
        chmod +x "$os_script"
        log "Generated: ${os_script}  (OS: ${os_ver})"
    done

    local bios_ver bios_script bios_path bios_basename
    bios_ver="$TARGET_BIOS_VERSION"
    bios_path=$(http_path_for "$TARGET_BIOS_FILE")
    bios_basename=$(basename "$TARGET_BIOS_FILE")
    bios_script="${SCRIPTS_DIR}/bios_upgrade_${bios_ver}.sh"
    cat > "$bios_script" <<EOF
#!/bin/bash
# BIOS Upgrade Script — generated by upgrade.sh (HTTPS method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
[[ -n "\${HTTP_SERVER_IP:-}" ]] || { log "[BIOS] ERROR: HTTPS server address was not provided."; exit 1; }
BIOS_URL="https://\${HTTP_SERVER_IP}${bios_path}"
LOCAL_FILE="${bios_basename}"
log "[BIOS] Fetching directly through NVUE: \$BIOS_URL"
nv action fetch platform firmware BIOS "\$BIOS_URL"
nv action install platform firmware BIOS files "\$LOCAL_FILE" force skip-version-check
log "[BIOS] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$bios_script"
    log "Generated: ${bios_script}  (BIOS: ${bios_ver})"

    local cpld_fui cpld_script burn_path_url refresh_path_url burn_basename refresh_basename
    cpld_fui=$(cpld_fui_from_file "$TARGET_CPLD_BURN_FILE")
    burn_path_url=$(http_path_for "$TARGET_CPLD_BURN_FILE")
    refresh_path_url=$(http_path_for "$TARGET_CPLD_REFRESH_FILE")
    burn_basename=$(basename "$TARGET_CPLD_BURN_FILE")
    refresh_basename=$(basename "$TARGET_CPLD_REFRESH_FILE")
    cpld_script="${SCRIPTS_DIR}/cpld_upgrade_${cpld_fui}.sh"
    cat > "$cpld_script" <<EOF
#!/bin/bash
# CPLD Upgrade Script — generated by upgrade.sh (HTTPS method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
[[ -n "\${HTTP_SERVER_IP:-}" ]] || { log "[CPLD] ERROR: HTTPS server address was not provided."; exit 1; }
BURN_URL="https://\${HTTP_SERVER_IP}${burn_path_url}"
REFRESH_URL="https://\${HTTP_SERVER_IP}${refresh_path_url}"
BURN_LOCAL="${burn_basename}"
REFRESH_LOCAL="${refresh_basename}"
log "[CPLD] Fetching BURN directly through NVUE: \$BURN_URL"
nv action fetch platform firmware CPLD1 "\$BURN_URL"
nv action install platform firmware CPLD1 files "\$BURN_LOCAL" skip-reboot
log "[CPLD] Fetching REFRESH directly through NVUE: \$REFRESH_URL"
nv action fetch platform firmware CPLD1 "\$REFRESH_URL"
nv action install platform firmware CPLD1 files "\$REFRESH_LOCAL" force
log "[CPLD] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$cpld_script"
    log "Generated: ${cpld_script}  (CPLD bundle: ${cpld_fui})"
}

generated_http_download_helper() {
    cat <<'HTTP_DOWNLOAD_HELPER'
download_http_package() {
    local url="$1" destination="$2" tmp="${2}.part.$$"
    curl -fsSL --retry 3 --retry-delay 5 "$url" -o "$tmp" || {
        local rc=$?
        rm -f -- "$tmp"
        log "[HTTP] ERROR: Download failed: $url"
        return "$rc"
    }
    [[ -s "$tmp" ]] || {
        rm -f -- "$tmp"
        log "[HTTP] ERROR: Downloaded package is empty: $url"
        return 1
    }
    mv -f -- "$tmp" "$destination" || {
        local rc=$?
        rm -f -- "$tmp"
        log "[HTTP] ERROR: Cannot move the downloaded package to $destination"
        return "$rc"
    }
}
HTTP_DOWNLOAD_HELPER
}

generate_scripts_http() {
    mkdir -p "$SCRIPTS_DIR"
    local os_file os_ver os_script os_path os_basename
    for os_file in "${TARGET_OS_FILES[@]}"; do
        os_ver=$(os_ver_from_file "$os_file")
        os_path=$(http_path_for "$os_file")
        os_basename=$(basename "$os_file")
        os_script="${SCRIPTS_DIR}/os_upgrade_${os_ver}.sh"
        cat > "$os_script" <<EOF
#!/bin/bash
# OS Upgrade Script — generated by upgrade.sh (HTTP download method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
JITTER=${OS_DOWNLOAD_JITTER}
[[ -n "\${HTTP_SERVER_IP:-}" ]] || { log "[OS] ERROR: HTTP server address was not provided."; exit 1; }
OS_URL="http://\${HTTP_SERVER_IP}${os_path}"
LOCAL_FILE="${os_basename}"
LOCAL_PATH="${SWITCH_LOCAL_DIR}/${os_basename}"
$(generated_http_download_helper)
if [[ "\${SKIP_OS_JITTER:-0}" != "1" ]] && (( JITTER > 0 )); then _delay=\$(( RANDOM % JITTER )); log "[OS] Jitter delay \${_delay}s ..."; sleep "\$_delay"; fi
log "[OS] Downloading through HTTP: \$OS_URL → \$LOCAL_PATH"
download_http_package "\$OS_URL" "\$LOCAL_PATH"
nv action fetch system image "file://\$LOCAL_PATH"
nv action install system image files "\$LOCAL_FILE" force
log "[OS] Done. Reboot required to activate OS ${os_ver}."
EOF
        chmod +x "$os_script"
        log "Generated: ${os_script}  (OS: ${os_ver})"
    done

    local bios_ver bios_script bios_path bios_basename
    bios_ver="$TARGET_BIOS_VERSION"
    bios_path=$(http_path_for "$TARGET_BIOS_FILE")
    bios_basename=$(basename "$TARGET_BIOS_FILE")
    bios_script="${SCRIPTS_DIR}/bios_upgrade_${bios_ver}.sh"
    cat > "$bios_script" <<EOF
#!/bin/bash
# BIOS Upgrade Script — generated by upgrade.sh (HTTP download method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
[[ -n "\${HTTP_SERVER_IP:-}" ]] || { log "[BIOS] ERROR: HTTP server address was not provided."; exit 1; }
BIOS_URL="http://\${HTTP_SERVER_IP}${bios_path}"
LOCAL_FILE="${bios_basename}"
LOCAL_PATH="${SWITCH_LOCAL_DIR}/${bios_basename}"
$(generated_http_download_helper)
log "[BIOS] Downloading through HTTP: \$BIOS_URL → \$LOCAL_PATH"
download_http_package "\$BIOS_URL" "\$LOCAL_PATH"
nv action fetch platform firmware BIOS "file://\$LOCAL_PATH"
nv action install platform firmware BIOS files "\$LOCAL_FILE" force skip-version-check
log "[BIOS] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$bios_script"
    log "Generated: ${bios_script}  (BIOS: ${bios_ver})"

    local cpld_fui cpld_script burn_path_url refresh_path_url burn_basename refresh_basename
    cpld_fui=$(cpld_fui_from_file "$TARGET_CPLD_BURN_FILE")
    burn_path_url=$(http_path_for "$TARGET_CPLD_BURN_FILE")
    refresh_path_url=$(http_path_for "$TARGET_CPLD_REFRESH_FILE")
    burn_basename=$(basename "$TARGET_CPLD_BURN_FILE")
    refresh_basename=$(basename "$TARGET_CPLD_REFRESH_FILE")
    cpld_script="${SCRIPTS_DIR}/cpld_upgrade_${cpld_fui}.sh"
    cat > "$cpld_script" <<EOF
#!/bin/bash
# CPLD Upgrade Script — generated by upgrade.sh (HTTP download method)
set -euo pipefail
SCRIPT_LOG="\${BASH_SOURCE[0]}.log"
log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*"; }
exec > >(tee -a "\$SCRIPT_LOG") 2>&1
[[ -n "\${HTTP_SERVER_IP:-}" ]] || { log "[CPLD] ERROR: HTTP server address was not provided."; exit 1; }
BURN_URL="http://\${HTTP_SERVER_IP}${burn_path_url}"
REFRESH_URL="http://\${HTTP_SERVER_IP}${refresh_path_url}"
BURN_LOCAL="${burn_basename}"
REFRESH_LOCAL="${refresh_basename}"
BURN_PATH="${SWITCH_LOCAL_DIR}/${burn_basename}"
REFRESH_PATH="${SWITCH_LOCAL_DIR}/${refresh_basename}"
$(generated_http_download_helper)
log "[CPLD] Downloading BURN through HTTP: \$BURN_URL → \$BURN_PATH"
download_http_package "\$BURN_URL" "\$BURN_PATH"
nv action fetch platform firmware CPLD1 "file://\$BURN_PATH"
nv action install platform firmware CPLD1 files "\$BURN_LOCAL" skip-reboot
log "[CPLD] Downloading REFRESH through HTTP: \$REFRESH_URL → \$REFRESH_PATH"
download_http_package "\$REFRESH_URL" "\$REFRESH_PATH"
nv action fetch platform firmware CPLD1 "file://\$REFRESH_PATH"
nv action install platform firmware CPLD1 files "\$REFRESH_LOCAL" force
log "[CPLD] Install command completed; post-reboot verification will confirm activation."
EOF
    chmod +x "$cpld_script"
    log "Generated: ${cpld_script}  (CPLD bundle: ${cpld_fui})"
}

generate_scripts() {
    case "$METHOD" in
        scp)   generate_scripts_scp ;;
        local) generate_scripts_local ;;
        https) generate_scripts_https ;;
        http)  generate_scripts_http ;;
    esac
}

# ─── Switch Version Query (via SSH) ────────────────────────────────────────────

# get_os_ver <host>  → prints version string, empty on failure
get_os_ver() {
    ssh_with_auth "${SWITCH_USER}@${1}" \
        "nv show system version 2>/dev/null | awk '/product-release/ { print \$NF; exit }'"
}

# get_bios_ver <host>  → prints version string, empty on failure
get_bios_ver() {
    ssh_with_auth "${SWITCH_USER}@${1}" \
        "nv show platform firmware 2>/dev/null | awk '/^BIOS[[:space:]]/ { print \$2; exit }'"
}

# get_cpld_slots <host>  → lines of "SLOT:CPLDID_REVNNN", e.g. "CPLD1:CPLD000232_REV0900"
get_cpld_slots() {
    ssh_with_auth "${SWITCH_USER}@${1}" \
        "nv show platform firmware 2>/dev/null | awk '/^CPLD[0-9]/ { print \$1 \":\" \$2 }'"
}

# Collects every version needed for SCP package discovery through one SSH
# connection. This avoids three SSH handshakes per device before the phases.
get_package_inventory() {
    ssh_with_auth "${SWITCH_USER}@${1}" \
        "nv show system version 2>/dev/null | awk '/product-release/ { print \"OS\\t\" \$NF; exit }'; \
         nv show platform firmware 2>/dev/null | awk '/^BIOS[[:space:]]/ { print \"BIOS\\t\" \$2 } /^CPLD[0-9]/ { print \"CPLD\\t\" \$1 \":\" \$2 }'"
}

# Returns the switch-reported hostname. The final non-empty line is used so an
# SSH login banner printed before command output cannot become the hostname.
get_switch_hostname() {
    ssh_with_auth "${SWITCH_USER}@${1}" "hostname 2>/dev/null" \
        | awk 'NF { value=$0 } END { gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value }'
}

hostname_label_for_ip() {
    local wanted_ip="$1" ip hostname
    while IFS=$'\t' read -r ip hostname; do
        [[ "$ip" == "$wanted_ip" ]] && { printf '%s\n' "$hostname"; return 0; }
    done <<< "$_IB_HOST_LABELS"
    return 1
}

normalized_hostname() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[.]$//'
}

confirm_hostname_issues() {
    local count="$1" answer=""
    if $YES_ALL; then
        log "(auto-yes) Continuing despite ${count} hostname validation issue(s)."
        return 0
    fi
    tty_available || return 1
    printf '\n%d hostname validation issue(s) found. Continue? [y/N] (default: no in 10s): ' "$count" > /dev/tty
    if read -t 10 -r answer < /dev/tty; then
        answer=$(lower "$answer")
        [[ "$answer" == "y" || "$answer" == "yes" ]]
    else
        printf '\n' > /dev/tty
        return 1
    fi
}

validate_and_load_switch_hostnames() {
    local compare_csv="$1" host expected actual expected_norm actual_norm
    local new_labels="" issues=0

    log "Querying switch hostnames ..."
    for host in "${IB_HOSTS[@]}"; do
        expected=$(hostname_label_for_ip "$host" || true)
        actual=$(get_switch_hostname "$host")
        actual="${actual%$'\r'}"

        if [[ -z "$actual" || ! "$actual" =~ ^[A-Za-z0-9._-]+$ ]]; then
            log "[${host}] ERROR: Could not obtain a valid hostname from the switch; CSV hostname='${expected:-<empty>}'."
            (( issues++ ))
            [[ -n "$expected" ]] && new_labels+="${host}"$'\t'"${expected}"$'\n'
            continue
        fi

        new_labels+="${host}"$'\t'"${actual}"$'\n'
        if $compare_csv; then
            expected_norm=$(normalized_hostname "$expected")
            actual_norm=$(normalized_hostname "$actual")
            if [[ -z "$expected_norm" || "$expected_norm" != "$actual_norm" ]]; then
                log "[${host}] ERROR: Hostname mismatch: CSV='${expected:-<empty>}', switch='${actual}'."
                (( issues++ ))
            fi
        fi
    done

    # From this point onward, prefer the hostname reported by the switch. For
    # query failures retain a non-empty CSV label so the affected IP is readable.
    _IB_HOST_LABELS="$new_labels"
    if (( issues > 0 )); then
        confirm_hostname_issues "$issues" || die "Stopped because hostname validation was not confirmed."
        log "Continuing after user confirmation despite ${issues} hostname validation issue(s)."
    else
        log "Switch hostname validation passed: ${#IB_HOSTS[@]}/${#IB_HOSTS[@]} device(s)."
    fi
}

# Reads the CSV with RFC-compatible quoting, selects type=ib (case-insensitive),
# validates eth0_ip, removes duplicates, and prints IP<TAB>hostname per device.
read_ib_eth0_ips() {
    command -v python3 >/dev/null 2>&1 || {
        echo "ERROR: python3 is required to parse ${IBCSV}" >&2
        return 1
    }
    python3 - "$IBCSV" <<'PY'
import csv
import ipaddress
import sys

path = sys.argv[1]
try:
    handle = open(path, newline="", encoding="utf-8-sig")
except OSError as exc:
    print(f"ERROR: Cannot open device CSV {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)

with handle:
    reader = csv.reader(handle)
    try:
        header = next(reader)
    except StopIteration:
        print(f"ERROR: Device CSV is empty: {path}", file=sys.stderr)
        raise SystemExit(1)

    names = [name.strip().lower() for name in header]
    missing = [name for name in ("type", "eth0_ip") if name not in names]
    if missing:
        print(f"ERROR: Device CSV lacks required column(s): {', '.join(missing)}", file=sys.stderr)
        raise SystemExit(1)

    type_col = names.index("type")
    ip_col = names.index("eth0_ip")
    hostname_col = names.index("hostname") if "hostname" in names else None
    needed_col = max(type_col, ip_col)
    devices = []
    seen = set()
    invalid = False

    for line_no, row in enumerate(reader, start=2):
        if not row or all(not value.strip() for value in row):
            continue
        if len(row) <= needed_col:
            print(f"ERROR: {path}:{line_no}: incomplete CSV row", file=sys.stderr)
            invalid = True
            continue
        if row[type_col].strip().lower() != "ib":
            continue
        address = row[ip_col].strip()
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            print(f"ERROR: {path}:{line_no}: invalid eth0_ip for type=ib: {address!r}", file=sys.stderr)
            invalid = True
            continue
        if address not in seen:
            seen.add(address)
            hostname = row[hostname_col].strip() if hostname_col is not None and len(row) > hostname_col else ""
            # Keep log labels on one line and prevent bracket/tab delimiters
            # from changing the structured "[hostname IP]" log prefix.
            hostname = " ".join(hostname.split()).replace("[", "").replace("]", "").replace("\t", " ")
            if hostname.upper() == "NA":
                hostname = ""
            devices.append((address, hostname))

    if invalid:
        raise SystemExit(1)
    if not devices:
        print(f"ERROR: No type=ib devices with valid eth0_ip found in {path}", file=sys.stderr)
        raise SystemExit(1)
    for address, hostname in devices:
        print(f"{address}\t{hostname}")
PY
}

# Legacy ib.log reader: accepts one hostname/IP per line, blank lines and #
# comments, and removes duplicate targets while preserving file order.
read_ib_log_hosts() {
    local line host count=0 line_no=0 invalid=false
    local seen_hosts=$'\n'

    while IFS= read -r line || [[ -n "$line" ]]; do
        (( line_no++ ))
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        line="${line%%#*}"
        host="${line%%[[:space:]]*}"
        [[ -z "$host" ]] && continue
        if (( ${#host} > 253 )) || [[ ! "$host" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
            echo "ERROR: ${IBLOG}:${line_no}: unsafe switch hostname/IP: ${host}" >&2
            invalid=true
            continue
        fi
        [[ "$seen_hosts" == *$'\n'"$host"$'\n'* ]] && continue
        seen_hosts+="${host}"$'\n'
        echo "$host"
        (( count++ ))
    done < "$IBLOG"

    $invalid && return 1
    if (( count == 0 )); then
        echo "ERROR: No switch hostname/IP found in legacy list ${IBLOG}" >&2
        return 1
    fi
}

add_scp_required_package() {
    local package_name existing
    package_name=$(basename "$1")
    for existing in "${_SCP_REQUIRED_PACKAGES[@]}"; do
        [[ "$existing" == "$package_name" ]] && return 0
    done
    _SCP_REQUIRED_PACKAGES+=("$package_name")
}

collect_scp_required_packages_for_host() {
    local host="$1" inventory current next_file cpld_rc os_file os_ver slots
    inventory=$(get_package_inventory "$host") || inventory=""

    if $RUN_OS; then
        current=$(awk -F '\t' '$1 == "OS" { print $2; exit }' <<< "$inventory")
        if [[ -n "$current" ]]; then
            if $OS_FIRST; then
                for os_file in "${TARGET_OS_FILES[@]}"; do
                    os_ver=$(os_ver_from_file "$os_file")
                    if ver_lt "$current" "$os_ver"; then
                        printf '%s\n' "$(basename "$os_file")" >> "$_SCP_DISCOVERY_RESULTS"
                    fi
                done
            else
                next_file=$(find_next_os_step "$current") || next_file=""
                [[ -n "$next_file" ]] && printf '%s\n' "$(basename "$next_file")" >> "$_SCP_DISCOVERY_RESULTS"
            fi
        fi
    fi
    if $RUN_BIOS; then
        current=$(awk -F '\t' '$1 == "BIOS" { print $2; exit }' <<< "$inventory")
        if [[ "$(bios_version_state "$current")" == "upgrade" ]]; then
            printf '%s\n' "$(basename "$TARGET_BIOS_FILE")" >> "$_SCP_DISCOVERY_RESULTS"
        fi
    fi
    if $RUN_CPLD; then
        slots=$(awk -F '\t' '$1 == "CPLD" { print $2 }' <<< "$inventory")
        if cpld_upgrade_needed_from_slots "$host" "$slots"; then
            printf '%s\n' "$(basename "$TARGET_CPLD_BURN_FILE")" >> "$_SCP_DISCOVERY_RESULTS"
            printf '%s\n' "$(basename "$TARGET_CPLD_REFRESH_FILE")" >> "$_SCP_DISCOVERY_RESULTS"
        else
            cpld_rc=$?
            (( cpld_rc == 2 )) && log "[${host}] CPLD state unavailable during package discovery; no CPLD package assumed."
        fi
    fi
    return 0
}

collect_scp_required_packages() {
    _SCP_REQUIRED_PACKAGES=()
    [[ "$METHOD" == "scp" ]] || return 0

    local host pid package_name os_file discovered_packages discovery_parallelism="$PARALLEL_LIMIT"
    local -a pids=()
    (( PARALLEL_LIMIT == 0 )) && discovery_parallelism="unlimited"
    log "Discovering SCP packages required by current versions (one SSH query per device, up to ${discovery_parallelism} in parallel) ..."
    _SCP_DISCOVERY_RESULTS=$(mktemp) || die "Cannot create the SCP package-discovery result file."

    for host in "${IB_HOSTS[@]}"; do
        ( collect_scp_required_packages_for_host "$host" ) &
        pids+=($!)
        if (( PARALLEL_LIMIT > 0 && ${#pids[@]} >= PARALLEL_LIMIT )); then
            for pid in "${pids[@]}"; do wait "$pid" || true; done
            pids=()
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    discovered_packages=$'\n'"$(sort -u "$_SCP_DISCOVERY_RESULTS")"$'\n'
    # Parallel workers can finish in any order. Rebuild the final array in the
    # canonical component order so logs and missing-package reports are stable.
    for os_file in "${TARGET_OS_FILES[@]}"; do
        package_name=$(basename "$os_file")
        [[ "$discovered_packages" == *$'\n'"$package_name"$'\n'* ]] && add_scp_required_package "$package_name"
    done
    for package_name in \
        "$(basename "$TARGET_BIOS_FILE")" \
        "$(basename "$TARGET_CPLD_BURN_FILE")" \
        "$(basename "$TARGET_CPLD_REFRESH_FILE")"; do
        [[ "$discovered_packages" == *$'\n'"$package_name"$'\n'* ]] && add_scp_required_package "$package_name"
    done
    rm -f -- "$_SCP_DISCOVERY_RESULTS"
    _SCP_DISCOVERY_RESULTS=""

    if (( ${#_SCP_REQUIRED_PACKAGES[@]} == 0 )); then
        log "No SCP source package is required by the current device versions."
    else
        log "Required SCP source package(s): ${_SCP_REQUIRED_PACKAGES[*]}"
    fi
}

missing_required_scp_packages() {
    local root="$1" package_name missing=false
    for package_name in "${_SCP_REQUIRED_PACKAGES[@]}"; do
        if [[ ! -s "${root}/${package_name}" ]]; then
            printf '%s\n' "$package_name"
            missing=true
        fi
    done
    $missing && return 0 || return 1
}

ensure_scp_package_root() {
    [[ "$METHOD" == "scp" ]] || return 0
    (( ${#_SCP_REQUIRED_PACKAGES[@]} > 0 )) || return 0
    local missing answer
    missing=$(missing_required_scp_packages "$MGMT_SCP_ROOT") || return 0

    printf 'SCP package directory is missing package(s) required by current device versions: %s\n' "$MGMT_SCP_ROOT" >&2
    printf '%s\n' "$missing" | sed 's/^/  - /' >&2
    if $MGMT_SCP_ROOT_EXPLICIT; then
        die "The explicitly selected --scp-root is missing a required package."
    fi
    tty_available || die "Specify a complete package directory with --scp-root DIR."

    printf 'Specify the management-server package directory: ' > /dev/tty
    IFS= read -r answer < /dev/tty
    [[ -n "$answer" ]] || die "No package directory entered; use --scp-root DIR."
    [[ "$answer" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "Package directory must be a safe absolute path."
    MGMT_SCP_ROOT="$answer"
    missing=$(missing_required_scp_packages "$MGMT_SCP_ROOT") || {
        log "Using SCP package directory: ${MGMT_SCP_ROOT}"
        return 0
    }
    printf 'Selected directory is still missing required package(s):\n%s\n' \
        "$(printf '%s\n' "$missing" | sed 's/^/  - /')" >&2
    die "Specify a complete package directory with --scp-root DIR."
}

ensure_remote_package_local() {
    local host="$1" filename="$2" label="$3" mode="${4:-sequential}"
    local package_name package_path source_path delay
    package_name=$(basename "$filename")
    package_path="${SWITCH_LOCAL_DIR}/${package_name}"
    source_path="${LOCAL_SOURCE_ROOT}/${package_name}"

    if ssh_with_auth "${SWITCH_USER}@${host}" "test -s '${package_path}'" </dev/null 2>/dev/null; then
        log "[${host}] ${label} package already exists; reusing ${package_path}"
        return 0
    fi
    log "[${host}] ${label} package is missing or empty on switch: ${package_path}"
    [[ -s "$source_path" ]] || { log "[${host}] ERROR: Missing local source package: ${source_path}"; return 1; }

    # Remaining hosts are processed in parallel. Stagger only real OS package
    # transfers so simultaneous management-server pushes do not saturate its
    # NIC or storage. Reused switch-local files and BIOS/CPLD are not delayed.
    if [[ "$label" == OS\ * && "$mode" == "parallel" ]] && (( OS_DOWNLOAD_JITTER > 0 )); then
        delay=$(( RANDOM % OS_DOWNLOAD_JITTER ))
        log "[${host}] OS transfer jitter: waiting ${delay}s before pushing ${package_name}."
        sleep "$delay"
    fi

    log "[${host}] Copying ${source_path} → ${package_path}"
    ssh_with_auth "${SWITCH_USER}@${host}" "mkdir -p '${SWITCH_LOCAL_DIR}'" 2>/dev/null || return 1
    scp_with_auth "$source_path" "${SWITCH_USER}@${host}:${package_path}" </dev/null || return 1
    ssh_with_auth "${SWITCH_USER}@${host}" "test -s '${package_path}'" </dev/null 2>/dev/null
}

prepare_package_local() {
    local host="$1" filename="$2" label="$3" mode="${4:-sequential}"
    # Local packages land in /home/admin by default and NVUE fetches each file
    # directly from that path; no copy into /host/fw-images is required.
    ensure_remote_package_local "$host" "$filename" "$label" "$mode"
}

method_prepare_package() {
    local host="$1" filename="$2" label="$3" mode="${4:-sequential}" source
    _PACKAGE_STATUS=""
    case "$METHOD" in
        local)
            if $DRY_RUN; then
                source="${LOCAL_SOURCE_ROOT}/$(basename "$filename")"
                if ssh_with_auth "${SWITCH_USER}@${host}" "test -s '${SWITCH_LOCAL_DIR}/$(basename "$filename")'" </dev/null 2>/dev/null; then
                    _PACKAGE_STATUS="package=present"
                    return 0
                fi
                [[ -s "$source" ]] || { log "[${host}] ERROR: (dry-run) Missing source package: ${source}"; return 1; }
                _PACKAGE_STATUS="package=copy required"
                return 0
            fi
            prepare_package_local "$host" "$filename" "$label" "$mode"
            ;;
        scp)
            source="${MGMT_SCP_ROOT}/$(basename "$filename")"
            [[ -s "$source" ]] || { log "[${host}] ERROR: Required SCP source package disappeared or is empty: ${source}"; return 1; }
            $DRY_RUN && _PACKAGE_STATUS="source package=available"
            return 0
            ;;
        https|http)
            $DRY_RUN && _PACKAGE_STATUS="source=${METHOD^^}"
            return 0
            ;;
    esac
}

# Parallel dry-run callbacks append short records to this shared temporary file.
record_dry_run_need() {
    local host="$1" component="$2" current="$3" target="$4"
    $DRY_RUN || return 0
    printf '%s|%s|%s|%s\n' "$host" "$component" "$current" "$target" >> "$_DRY_RUN_NEEDS"
}

dry_run_need_count() {
    local component="$1"
    awk -F'|' -v wanted="$component" '$2==wanted {n++} END {print n+0}' "$_DRY_RUN_NEEDS"
}

report_verification_result() {
    local total_err="$1" need_count
    need_count=$(wc -l < "$_DRY_RUN_NEEDS" | tr -d ' ')
    if (( need_count > 0 && total_err > 0 )); then
        log "Verification FAILED: ${need_count} selected target(s) remain unmet; ${total_err} device check(s) failed."
        return 1
    fi
    if (( need_count > 0 )); then
        log "Verification FAILED: ${need_count} selected target(s) remain unmet."
        return 1
    fi
    if (( total_err > 0 )); then
        log "Verification FAILED: ${total_err} device check(s) failed."
        return 1
    fi
    log "Verification PASSED: all selected components reached their targets."
    return 0
}

print_dry_run_summary() {
    $DRY_RUN || return 0
    if $VERIFY_ONLY; then
        begin_log_section "Verification requirements"
    else
        begin_log_section "Dry-run upgrade requirements"
    fi

    if [[ ! -s "$_DRY_RUN_NEEDS" ]]; then
        if $VERIFY_ONLY; then
            log "All selected targets are satisfied."
        else
            log "No selected component requires an upgrade."
        fi
        return 0
    fi

    local os_need bios_need cpld_need host component current target
    local -a requirement_parts=()
    os_need=$(awk -F'|' '$2=="OS" {n++} END {print n+0}' "$_DRY_RUN_NEEDS")
    bios_need=$(awk -F'|' '$2=="BIOS" {n++} END {print n+0}' "$_DRY_RUN_NEEDS")
    cpld_need=$(awk -F'|' '$2=="CPLD" {n++} END {print n+0}' "$_DRY_RUN_NEEDS")
    $RUN_OS   && requirement_parts+=("OS=${os_need}")
    $RUN_BIOS && requirement_parts+=("BIOS=${bios_need}")
    $RUN_CPLD && requirement_parts+=("CPLD=${cpld_need}")
    if $VERIFY_ONLY; then
        log "Unmet targets: ${requirement_parts[*]}"
    else
        log "Components requiring upgrade: ${requirement_parts[*]}"
    fi

    while IFS='|' read -r host component current target; do
        log "  [${host}] ${component}: ${current} → ${target}"
    done < <(LC_ALL=C sort -t'.' -k1,1n -k2,2n -k3,3n -k4,4n "$_DRY_RUN_NEEDS")
}

# ─── Script Deployment ─────────────────────────────────────────────────────────

# deploy_and_run <host> <local_script_path> [sequential|parallel]
# SCPs script to REMOTE_DIR on switch, then executes it. Returns 1 on failure.
# On real (non-dry-run) success, writes a tally line to _DEPLOY_TALLY so the
# caller can count actual deployments across parallel subshells.
# Normalizes remote sub-script output before it enters the orchestrator log.
# The switch-local log retains its own timestamp; the outer log uses UFM time.
log_remote_output() {
    local host="$1" line="$2"
    # NVOS progress output may contain carriage returns and ANSI terminal
    # sequences. CR is split by the caller; remove remaining controls before
    # matching or printing so parallel workers cannot move the shared cursor.
    line=$(printf '%s\n' "$line" \
        | sed -E $'s/\033\\[[0-9;?]*[[:alpha:]~]//g' \
        | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177')
    case "$line" in
        ""|"NVOS switch"|"Action executing ..."|"Action succeeded") return 0 ;;
    esac
    line=$(printf '%s\n' "$line" \
        | sed -E 's/^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\][[:space:]]*//')
    [[ -n "$line" ]] && log "[${host}]   ${line}"
}

deploy_and_run() {
    local host="$1" script="$2" mode="${3:-sequential}"
    local remote="${REMOTE_DIR}/$(basename "$script")"
    local mgmt_server_ip="" http_server_ip="" skip_os_jitter=0
    [[ "$mode" == "sequential" ]] && skip_os_jitter=1

    if $DRY_RUN; then
        log "[${host}] ERROR: Safety guard blocked deploy_and_run during dry-run."
        return 97
    fi

    if [[ "$METHOD" == "scp" ]]; then
        detect_mgmt_server_ip "$host" "$MGMT_SERVER" || return 1
        mgmt_server_ip="$DETECTED_MGMT_SERVER_IP"
    elif [[ "$METHOD" == "https" || "$METHOD" == "http" ]]; then
        detect_mgmt_server_ip "$host" "$HTTP_SERVER" || return 1
        http_server_ip="$DETECTED_MGMT_SERVER_IP"
    fi

    log "[${host}] Deploying $(basename "$script") → ${remote}"
    local remote_dirs="'${REMOTE_DIR}'" required_dirs="${REMOTE_DIR}"
    if [[ "$METHOD" == "local" || "$METHOD" == "http" ]]; then
        remote_dirs+=" '${SWITCH_LOCAL_DIR}'"
        required_dirs+=" and ${SWITCH_LOCAL_DIR}"
    fi
    ssh_with_auth "${SWITCH_USER}@${host}" "mkdir -p ${remote_dirs}" 2>/dev/null \
        || { log "[${host}] ERROR: Cannot create required switch directories: ${required_dirs}"; return 1; }
    scp_with_auth "$script" "${SWITCH_USER}@${host}:${remote}" </dev/null \
        || { log "[${host}] ERROR: SCP failed for $(basename "$script")"; return 1; }

    local rc
    if [[ "$METHOD" == "scp" ]]; then
        log "[${host}] Executing ${remote}; switch will pull from ${mgmt_server_ip} by SCP"
        {
            printf '%s\n' "$mgmt_server_ip"
            printf '%s\n' "$MGMT_SCP_USER"
            printf '%s\n' "$MGMT_SCP_PASSWORD"
            printf '%s\n' "$skip_os_jitter"
        } | ssh_with_auth_stdin_combined "${SWITCH_USER}@${host}" \
            "IFS= read -r MGMT_SERVER_IP && IFS= read -r MGMT_SCP_USER && IFS= read -r MGMT_SCP_PASSWORD && IFS= read -r SKIP_OS_JITTER && export MGMT_SERVER_IP MGMT_SCP_USER MGMT_SCP_PASSWORD SKIP_OS_JITTER && bash '${remote}'" \
            | LC_ALL=C tr '\r' '\n' \
            | while IFS= read -r line; do log_remote_output "$host" "$line"; done
        rc="${PIPESTATUS[1]}"
    else
        log "[${host}] Executing ${remote} (${METHOD} method)"
        {
            printf '%s\n' "$skip_os_jitter"
            printf '%s\n' "$http_server_ip"
        } | ssh_with_auth_stdin_combined "${SWITCH_USER}@${host}" \
            "IFS= read -r SKIP_OS_JITTER && IFS= read -r HTTP_SERVER_IP && export SKIP_OS_JITTER HTTP_SERVER_IP && bash '${remote}'" \
            | LC_ALL=C tr '\r' '\n' \
            | while IFS= read -r line; do log_remote_output "$host" "$line"; done
        rc="${PIPESTATUS[1]}"
    fi
    (( rc == 0 )) || { log "[${host}] ERROR: Script exited with code ${rc}"; return 1; }

    # Record this deployment so the verification step can detect real upgrades
    echo 1 >> "$_DEPLOY_TALLY"
    return 0
}

# ─── Interactive Prompt ────────────────────────────────────────────────────────

# ask <question>
# Waits up to 10 seconds; empty input or timeout defaults to yes.
# Returns 0 (yes) or 1 (no). Skips prompt entirely when YES_ALL=true.
ask() {
    local question="$*" ip hostname
    if [[ -n "$_IB_HOST_LABELS" && "$question" == *"["* ]]; then
        while IFS=$'\t' read -r ip hostname; do
            [[ -n "$ip" && -n "$hostname" ]] || continue
            question="${question//\[$ip\]/[$hostname $ip]}"
        done <<< "$_IB_HOST_LABELS"
    fi
    if $YES_ALL; then
        log "(auto-yes) ${question}"
        return 0
    fi
    tty_available || { log "No TTY is available; declining interactive upgrade prompt."; return 1; }
    local ans
    printf "\n%s [Y/n] (auto-yes in 10s): " "$question" > /dev/tty
    if read -t 10 -r ans < /dev/tty; then
        # Treat empty input as yes
        local _a; _a=$(lower "$ans")
        [[ -z "$ans" || "$_a" == "y" || "$_a" == "yes" ]]
    else
        printf "\n" > /dev/tty
        log "No response in 10s, defaulting to yes."
        return 0
    fi
}

# ─── Phase Selection Prompt ────────────────────────────────────────────────────

# select_phases
# Called when no --os/--bios/--cpld/-A flag was given.
# Prompts user: Enter/y = all, n = exit, o = pick each phase individually.
# Modifies RUN_OS / RUN_BIOS / RUN_CPLD in the global scope.
select_phases() {
    local choice ans

    printf "\nNo upgrade phase specified. What would you like to do?\n"
    printf "  y = upgrade all  (OS + BIOS + CPLD)\n"
    printf "  n = exit without upgrading\n"
    printf "  o = select phases individually\n"
    printf "Choice [Y/n/o] (default: all): "
    read -r choice

    case "$(lower "$choice")" in
        ""|y|yes)
            RUN_OS=true; RUN_BIOS=true; RUN_CPLD=true
            log "Selected: all phases (OS + BIOS + CPLD)."
            ;;
        n|no)
            log "No phases selected. Exiting."
            exit 0
            ;;
        o)
            printf "\n"
            printf "  Upgrade OS?   [y/N]: "; read -r ans
            [[ "$(lower "$ans")" == y || "$(lower "$ans")" == yes ]] && RUN_OS=true
            printf "  Upgrade BIOS? [y/N]: "; read -r ans
            [[ "$(lower "$ans")" == y || "$(lower "$ans")" == yes ]] && RUN_BIOS=true
            printf "  Upgrade CPLD? [y/N]: "; read -r ans
            [[ "$(lower "$ans")" == y || "$(lower "$ans")" == yes ]] && RUN_CPLD=true
            if ! $RUN_OS && ! $RUN_BIOS && ! $RUN_CPLD; then
                log "No phases selected. Exiting."
                exit 0
            fi
            local selected=()
            $RUN_OS   && selected+=(OS)
            $RUN_BIOS && selected+=(BIOS)
            $RUN_CPLD && selected+=(CPLD)
            log "Selected phases: ${selected[*]}."
            ;;
        *)
            printf "Invalid choice '%s'. Exiting.\n" "$choice" >&2
            exit 1
            ;;
    esac
}

# ─── CPLD Comparison ───────────────────────────────────────────────────────────

# cpld_upgrade_needed <host>
# Compares each CPLD slot against TARGET_CPLD_PAIRS and collects outdated-slot
# details in _CPLD_STATUS_DETAIL for one atomic per-device result line.
# Returns 0 if any slot needs upgrade, 1 if all slots meet or exceed target,
# and 2 if get_cpld_slots returned no data (SSH/query failure).
cpld_upgrade_needed_from_slots() {
    local host="$1" slots="$2" needed=false found=false
    local slot fw cpld_id cur_rev tgt_rev cur_n tgt_n target_id
    local observed_ids=$'\n'
    _CPLD_STATUS_DETAIL=""

    while IFS=: read -r slot fw; do
        [[ -z "$slot" ]] && continue
        found=true
        cpld_id="${fw%%_*}"     # CPLD000232
        cur_rev="${fw#*_}"      # REV0900
        [[ "$observed_ids" == *$'\n'"$cpld_id"$'\n'* ]] || observed_ids+="${cpld_id}"$'\n'

        tgt_rev=$(echo "$TARGET_CPLD_PAIRS" \
            | awk -F: -v id="$cpld_id" '$1==id {print $2; exit}')
        [[ -z "$tgt_rev" ]] && continue

        cur_n=$(cpld_rev_num "$cur_rev")
        tgt_n=$(cpld_rev_num "$tgt_rev")
        if (( cur_n < tgt_n )); then
            [[ -n "$_CPLD_STATUS_DETAIL" ]] && _CPLD_STATUS_DETAIL+=", "
            _CPLD_STATUS_DETAIL+="${slot}(${cpld_id}) ${cur_rev}→${tgt_rev}"
            needed=true
        fi
    done <<< "$slots"

    if ! $found; then
        return 2
    fi
    while IFS=: read -r target_id tgt_rev; do
        [[ -n "$target_id" ]] || continue
        if [[ "$observed_ids" != *$'\n'"$target_id"$'\n'* ]]; then
            log "[${host}] ERROR: Target CPLD ${target_id} is missing from firmware query output."
            return 2
        fi
    done <<< "$TARGET_CPLD_PAIRS"
    $needed && return 0 || return 1
}

cpld_upgrade_needed() {
    local host="$1" slots
    slots=$(get_cpld_slots "$host")
    cpld_upgrade_needed_from_slots "$host" "$slots"
}

# ─── Host Iterator with First-Sequential / Rest-Parallel ───────────────────────

# each_host <callback>
# Calls callback(host, "sequential") for the first selected IB eth0_ip, waits
# for it, then calls callback(host, "parallel") & for all remaining addresses
# in parallel, waits for all to finish.
# Sets _PHASE_OK / _PHASE_ERR with success / failure counts.
_PHASE_OK=0
_PHASE_ERR=0

each_host() {
    local cb="$1" host first=true
    local pids=() pid
    _PHASE_OK=0; _PHASE_ERR=0

    if (( ${#_SEQUENTIAL_HOSTS[@]} > 0 )); then
        for host in "${_SEQUENTIAL_HOSTS[@]}"; do
            if "$cb" "$host" sequential; then (( _PHASE_OK++ )); else (( _PHASE_ERR++ )); fi
        done
        first=false
    fi

    for host in "${IB_HOSTS[@]}"; do
        if (( ${#_SEQUENTIAL_HOSTS[@]} > 0 )); then
            local is_representative=false representative
            for representative in "${_SEQUENTIAL_HOSTS[@]}"; do
                [[ "$host" == "$representative" ]] && { is_representative=true; break; }
            done
            $is_representative && continue
        fi
        if $first; then
            first=false
            if "$cb" "$host" sequential; then (( _PHASE_OK++ )); else (( _PHASE_ERR++ )); fi
        else
            # Use an explicit subshell. With `function &`, Bash can tail-exec an
            # external ssh/scp reached through nested functions and skip the
            # remainder of the callback while still returning success.
            ( "$cb" "$host" parallel ) &
            pids+=($!)
            # When parallel limit is reached, drain current batch before spawning more
            if (( PARALLEL_LIMIT > 0 && ${#pids[@]} >= PARALLEL_LIMIT )); then
                for pid in "${pids[@]}"; do
                    if wait "$pid"; then (( _PHASE_OK++ )); else (( _PHASE_ERR++ )); fi
                done
                pids=()
            fi
        fi
    done

    for pid in "${pids[@]}"; do
        if wait "$pid"; then (( _PHASE_OK++ )); else (( _PHASE_ERR++ )); fi
    done
}

prepare_os_representatives() {
    _SEQUENTIAL_HOSTS=()
    $DRY_RUN && return 0
    local host cur_os next_file
    local seen_baselines=$'\n'
    for host in "${IB_HOSTS[@]}"; do
        cur_os=$(get_os_ver "$host")
        [[ -n "$cur_os" ]] || continue
        next_file=$(find_next_os_step "$cur_os") || continue
        [[ -n "$next_file" ]] || continue
        if [[ "$seen_baselines" != *$'\n'"$cur_os"$'\n'* ]]; then
            seen_baselines+="${cur_os}"$'\n'
            _SEQUENTIAL_HOSTS+=("$host")
        fi
    done
}

prepare_bios_representative() {
    _SEQUENTIAL_HOSTS=()
    $DRY_RUN && return 0
    local host cur_bios
    for host in "${IB_HOSTS[@]}"; do
        cur_bios=$(get_bios_ver "$host")
        [[ -n "$cur_bios" ]] || continue
        if [[ "$(bios_version_state "$cur_bios")" == "upgrade" ]]; then
            _SEQUENTIAL_HOSTS+=("$host")
            return 0
        fi
    done
}

prepare_cpld_representative() {
    _SEQUENTIAL_HOSTS=()
    $DRY_RUN && return 0
    local host
    for host in "${IB_HOSTS[@]}"; do
        if cpld_upgrade_needed "$host"; then
            _SEQUENTIAL_HOSTS+=("$host")
            return 0
        fi
    done
}

# ─── Post-upgrade Verification ─────────────────────────────────────────────────

# countdown_sleep <seconds>
# Sleeps the given duration, logging progress every 60 seconds.
countdown_sleep() {
    local total="$1" elapsed=0 chunk=60
    while (( elapsed < total )); do
        local remaining=$(( total - elapsed ))
        log "Waiting for switches to complete upgrades... ${remaining}s remaining."
        local step=$(( remaining < chunk ? remaining : chunk ))
        sleep "$step"
        elapsed=$(( elapsed + step ))
    done
}

# verify_run
# Re-executes this script in non-interactive verification mode. The verification
# preserves the real run's explicit scope and fails if any target remains unmet.
verify_run() {
    local arg has_method=false has_phase=false suggested
    local -a opts=("${ORIGINAL_ARGS[@]}")
    for arg in "${ORIGINAL_ARGS[@]}"; do
        [[ "$arg" == "--method" ]] && has_method=true
        case "$arg" in
            -A|--all|--os|--bios|--cpld|--os-first) has_phase=true ;;
        esac
    done
    $has_method || opts+=(--method "$METHOD")
    if ! $has_phase; then
        $RUN_OS   && opts+=(--os)
        $RUN_BIOS && opts+=(--bios)
        $RUN_CPLD && opts+=(--cpld)
    fi
    opts+=(--verify-only)
    suggested=$(printf '%q ' bash "${BASH_SOURCE[0]}" "${opts[@]}")
    suggested="${suggested% }"
    log "══════════════════════════════════════════════════════════"
    log "Verification run: ${suggested}"
    log "══════════════════════════════════════════════════════════"
    bash "${BASH_SOURCE[0]}" "${opts[@]}"
}

offer_upgrade_after_dry_run() {
    local total_err="$1" answer="" need_count need_device_count followup_rc suggested arg
    local expect_value=false has_method=false has_phase=false
    local -a opts=()

    $DRY_RUN || return 0
    [[ -s "$_DRY_RUN_NEEDS" ]] || return 0
    if (( total_err > 0 )); then
        log "ERROR: Dry-run found upgrade requirements but also ${total_err} failure(s); real upgrade will not be offered."
        return 1
    fi

    # Preserve all customer-supplied arguments except the dry-run switch. Track
    # options that consume a value so a value literally named --dry-run remains
    # intact and is not mistaken for the control flag.
    for arg in "${ORIGINAL_ARGS[@]}"; do
        if $expect_value; then
            opts+=("$arg")
            expect_value=false
            continue
        fi
        case "$arg" in
            --dry-run) continue ;;
            --method)
                has_method=true
                expect_value=true
                opts+=("$arg")
                ;;
            --ib-csv|--ib-log|--public-key|--mgmt-server|--mgmt-user|--scp-root|--source-root|--local-dir|--http-server|--http-scheme|--parallel-limit|--phase-wait)
                expect_value=true
                opts+=("$arg")
                ;;
            -A|--all|--os|--bios|--cpld|--os-first)
                has_phase=true
                opts+=("$arg")
                ;;
            *) opts+=("$arg") ;;
        esac
    done

    # An interactive method choice belongs to the customer's run and should be
    # reproducible. A timeout/default choice is intentionally not injected.
    if ! $has_method && $METHOD_SELECTED_INTERACTIVELY; then
        opts+=(--method "$METHOD")
    fi

    # If the customer did not constrain phases, run only components that the
    # dry-run found necessary. Explicit phase selections remain untouched.
    if ! $has_phase; then
        grep -q '|OS|' "$_DRY_RUN_NEEDS" && opts+=(--os)
        grep -q '|BIOS|' "$_DRY_RUN_NEEDS" && opts+=(--bios)
        grep -q '|CPLD|' "$_DRY_RUN_NEEDS" && opts+=(--cpld)
    fi

    suggested=$(printf '%q ' bash "${BASH_SOURCE[0]}" "${opts[@]}")
    suggested="${suggested% }"
    need_count=$(wc -l < "$_DRY_RUN_NEEDS" | tr -d ' ')
    need_device_count=$(cut -d'|' -f1 "$_DRY_RUN_NEEDS" | LC_ALL=C sort -u | wc -l | tr -d ' ')
    log "Suggested real-upgrade command: ${suggested}"
    tty_available || {
        log "Dry-run found ${need_count} component upgrade requirement(s) across ${need_device_count} device(s), but no TTY is available for confirmation."
        return 0
    }
    printf '\nDry-run found %d component upgrade requirement(s) across %d device(s).\nSuggested command: %s\nStart the real upgrade for all listed requirements now? [y/N] (default: no in 30s): ' \
        "$need_count" "$need_device_count" "$suggested" > /dev/tty
    if read -t 30 -r answer < /dev/tty; then
        answer=$(lower "$answer")
    else
        printf '\n' > /dev/tty
        answer=""
    fi
    if [[ "$answer" != "y" && "$answer" != "yes" ]]; then
        log "Real upgrade not started after dry-run."
        return 0
    fi

    log "User confirmed dry-run plan; starting real upgrade: ${suggested}"
    bash "${BASH_SOURCE[0]}" "${opts[@]}"
    followup_rc=$?
    return "$followup_rc"
}

# ─── Main ──────────────────────────────────────────────────────────────────────

main() {
    validate_configuration
    log "═══════════════════════════════════════════════════════════"
    if $VERIFY_ONLY; then
        log "IB Switch Post-upgrade Verification  ($(date '+%Y-%m-%d %H:%M:%S'))"
    else
        log "IB Switch Firmware Upgrade  ($(date '+%Y-%m-%d %H:%M:%S'))"
    fi
    log "═══════════════════════════════════════════════════════════"
    LOG_INDENT="  "

    # Derive targets
    local target_os_final target_bios cpld_fui
    target_os_final=$(os_ver_from_file "${TARGET_OS_FILES[$(( ${#TARGET_OS_FILES[@]} - 1 ))]}")
    target_bios="$TARGET_BIOS_VERSION"
    TARGET_CPLD_PAIRS=$(cpld_pairs_from_file "$TARGET_CPLD_BURN_FILE")
    cpld_fui=$(cpld_fui_from_file "$TARGET_CPLD_BURN_FILE")

    if $RUN_OS; then
        log "OS upgrade path:  $(printf '%s  ' "${TARGET_OS_FILES[@]}" \
                                   | grep -oE 'nvosv[0-9]+-[0-9]+-[0-9]+' \
                                   | sed 's/nvosv//; s/-/./g' | tr '\n' ' ')"
        log "Target OS final:  ${target_os_final}"
    fi
    $RUN_BIOS && log "Target BIOS:      ${target_bios}  (upgrade only from ${BIOS_UPGRADE_FROM_VERSION} with ${TARGET_BIOS_FILE})"
    $RUN_CPLD && log "Target CPLD:      ${TARGET_CPLD_PAIRS//$'\n'/ }"
    if ! $VERIFY_ONLY; then
        log "Package method:    ${METHOD}"
        case "$METHOD" in
        scp)
            if [[ -n "$MGMT_SERVER" ]]; then
                log "SCP package source: ${MGMT_SERVER}:${MGMT_SCP_ROOT} (explicit address)"
            else
                log "SCP package source: <auto-detect from switch w>:${MGMT_SCP_ROOT}"
            fi
            ;;
        local) log "Local-push source: ${LOCAL_SOURCE_ROOT}; switch package directory: ${SWITCH_LOCAL_DIR}" ;;
        https)
            if [[ -n "$HTTP_SERVER" ]]; then
                log "HTTPS package source: https://${HTTP_SERVER} (explicit address; direct NVUE fetch)"
            else
                log "HTTPS package source: https://<auto-detect from switch w> (direct NVUE fetch)"
            fi
            ;;
        http)
            if [[ -n "$HTTP_SERVER" ]]; then
                log "HTTP package source: http://${HTTP_SERVER} (explicit address); switch package directory: ${SWITCH_LOCAL_DIR}"
            else
                log "HTTP package source: http://<auto-detect from switch w>; switch package directory: ${SWITCH_LOCAL_DIR}"
            fi
            ;;
        esac
    fi
    if $VERIFY_ONLY; then
        log "VERIFICATION MODE: read-only checks; unmet targets cause a non-zero exit and no upgrade is offered."
    elif $DRY_RUN; then
        log "DRY-RUN MODE: firmware/package checks are read-only; public-key installation occurs only after explicit confirmation."
    fi

    begin_log_section "Phase 0: Preparation"

    # Temp file to count actual deployments across parallel subshells
    _DEPLOY_TALLY=$(mktemp)
    _DRY_RUN_NEEDS=$(mktemp)
    trap cleanup EXIT

    if $SCRIPTS_ONLY; then
        generate_scripts
        log "Scripts generated. Exiting (--scripts-only)."
        exit 0
    fi

    local ib_host_output ib_source compare_csv=false
    if [[ -f "$IBCSV" ]]; then
        ib_host_output=$(read_ib_eth0_ips) \
            || die "Failed to load IB switch eth0_ip values from ${IBCSV}"
        ib_source="$IBCSV (type=ib, eth0_ip)"
        compare_csv=true
    elif [[ -f "$IBLOG" ]]; then
        log "Device CSV not found: ${IBCSV}; falling back to legacy list ${IBLOG}."
        ib_host_output=$(read_ib_log_hosts) \
            || die "Failed to load legacy IB switch list from ${IBLOG}"
        ib_source="$IBLOG (legacy fallback)"
    else
        die "Neither device CSV nor legacy IB list exists: ${IBCSV}, ${IBLOG}"
    fi
    IB_HOSTS=()
    _IB_HOST_LABELS=""
    local device_ip device_hostname
    while IFS=$'\t' read -r device_ip device_hostname; do
        [[ -n "$device_ip" ]] || continue
        IB_HOSTS+=("$device_ip")
        if [[ -n "$device_hostname" ]]; then
            _IB_HOST_LABELS+="${device_ip}"$'\t'"${device_hostname}"$'\n'
        fi
    done <<< "$ib_host_output"
    log "Loaded ${#IB_HOSTS[@]} IB switch target(s) from ${ib_source}."
    prepare_ssh_auth
    validate_switch_authentication
    offer_public_key_installation
    validate_and_load_switch_hostnames "$compare_csv"

    if [[ "$METHOD" == "scp" ]]; then
        collect_scp_required_packages
        ensure_scp_package_root
    fi

    # SCP source paths are embedded in generated scripts, so generate only
    # after current-version discovery and any source-directory selection.
    if ! $DRY_RUN; then
        generate_scripts
    fi

    if ! $DRY_RUN && [[ "$METHOD" == "scp" ]] && (( ${#_SCP_REQUIRED_PACKAGES[@]} > 0 )); then
        prepare_mgmt_scp_auth
        validate_mgmt_scp_authentication
    fi

    local os_ok=0 os_err=0
    local bios_ok=0 bios_err=0
    local cpld_ok=0 cpld_err=0
    local os_deployed=0 bios_deployed=0 cpld_deployed=0
    local tally_snap tally_now
    local os_first_ready=true

    # Phase 0 has no result checkpoint, so add the same visual separation used
    # by later phase transitions before whichever upgrade phase runs first.
    emit_log_spacing

    # ── Phase 1: OS Upgrade ────────────────────────────────────────────────
    if $RUN_OS; then
        if $DRY_RUN; then
            begin_log_section "Phase 1: OS Check  (final target: ${target_os_final})"
        else
            begin_log_section "Phase 1: OS Upgrade  (final target: ${target_os_final})"
        fi

        # OS_VER_CONFIRMED[cur_os]="yes" after user confirms upgrade from that version.
        # Set on sequential first-switch run; inherited as read-only by parallel subshells.
        local OS_VER_CONFIRMED=$'\n'
        local os_round=0 os_round_ok os_round_err os_round_deployed
        local os_max_rounds=${#TARGET_OS_FILES[@]}
        local os_pending host_os host

        # mode: "sequential" (first host, may prompt) | "parallel" (subshell, never prompts)
        _upgrade_os() {
            local host="$1" mode="${2:-sequential}"
            local cur_os next_file next_ver proceed

            cur_os=$(get_os_ver "$host")
            if [[ -z "$cur_os" ]]; then
                log "[${host}] ERROR: Could not get OS version. Skipping."
                return 1
            fi
            next_file=$(find_next_os_step "$cur_os")
            if [[ -z "$next_file" ]]; then
                if ver_lt "$target_os_final" "$cur_os"; then
                    log "[${host}] OS: ${cur_os} (newer than target ${target_os_final})"
                else
                    log "[${host}] OS: ${cur_os} (at target)"
                fi
                return 0
            fi
            next_ver=$(os_ver_from_file "$next_file")

            if $VERIFY_ONLY; then
                record_dry_run_need "$host" "OS" "$cur_os" "$next_ver"
                log "[${host}] OS: current=${cur_os}  target=${next_ver}  status=target not reached"
                return 0
            fi
            if $DRY_RUN; then
                record_dry_run_need "$host" "OS" "$cur_os" "$next_ver"
                method_prepare_package "$host" "$next_file" "OS ${next_ver}" "$mode" || return 1
                log "[${host}] OS: ${cur_os} → ${next_ver}; ${_PACKAGE_STATUS}; action=upgrade required"
                return 0
            fi

            proceed=false
            if [[ "$OS_VER_CONFIRMED" == *$'\n'"$cur_os"$'\n'* ]]; then
                log "[${host}] OS ${cur_os} baseline confirmed → upgrading automatically."
                proceed=true
            elif [[ "$mode" == "parallel" ]]; then
                # Parallel subshells never prompt; skip unconfirmed baselines.
                log "[${host}] OS ${cur_os} not confirmed yet. Skipping (run sequentially first)."
                return 0
            else
                # Sequential: prompt
                log "[${host}] OS upgrade needed: ${cur_os} → ${next_ver}"
                ask "[${host}] Upgrade OS (${cur_os} → ${next_ver})?" && proceed=true
            fi

            if $proceed; then
                method_prepare_package "$host" "$next_file" "OS ${next_ver}" "$mode" || return 1
                if deploy_and_run "$host" "${SCRIPTS_DIR}/os_upgrade_${next_ver}.sh" "$mode"; then
                    [[ "$mode" == "sequential" ]] && OS_VER_CONFIRMED+="${cur_os}"$'\n'
                    return 0
                fi
                return 1
            fi
            log "[${host}] OS upgrade skipped."
            return 0
        }

        while :; do
            (( os_round++ ))
            OS_VER_CONFIRMED=$'\n'
            $OS_FIRST && log "OS-first round ${os_round}: advancing each switch by one configured OS step."
            prepare_os_representatives
            tally_snap=$(wc -l < "$_DEPLOY_TALLY" | tr -d ' ')
            each_host _upgrade_os
            os_round_ok=$_PHASE_OK; os_round_err=$_PHASE_ERR
            tally_now=$(wc -l < "$_DEPLOY_TALLY" | tr -d ' ')
            os_round_deployed=$(( tally_now - tally_snap ))
            os_ok=$(( os_ok + os_round_ok ))
            os_err=$(( os_err + os_round_err ))
            os_deployed=$(( os_deployed + os_round_deployed ))
            if $OS_FIRST && ! $DRY_RUN; then
                log_phase_checkpoint "Phase 1 round ${os_round}: OS ok=${os_round_ok}  failed=${os_round_err}  upgraded=${os_round_deployed}"
            fi
            if (( os_round_deployed > 0 )) && ! $DRY_RUN && (( PHASE_WAIT > 0 )); then
                LOG_INDENT=""
                log "─────────────────────────────────────────────────────────"
                LOG_INDENT="  "
                log "${os_round_deployed} OS upgrade(s) deployed. Waiting ${PHASE_WAIT}s for switches to reboot."
                countdown_sleep "$PHASE_WAIT"
            fi

            $OS_FIRST || break
            $DRY_RUN && break
            if (( os_round_err > 0 )); then
                log "ERROR: OS-first stopped after round ${os_round} because OS processing failed on ${os_round_err} device(s)."
                os_first_ready=false
                break
            fi

            os_pending=false
            for host in "${IB_HOSTS[@]}"; do
                host_os=$(get_os_ver "$host")
                if [[ -z "$host_os" ]]; then
                    log "[${host}] ERROR: Could not verify OS after OS-first round ${os_round}."
                    os_err=$(( os_err + 1 ))
                    os_first_ready=false
                    os_pending=true
                    continue
                fi
                if ver_lt "$host_os" "$target_os_final"; then
                    log "[${host}] OS-first progress: ${host_os}; final target is ${target_os_final}."
                    os_pending=true
                fi
            done
            $os_first_ready || break
            $os_pending || {
                log "OS-first complete: all switches reached final OS target ${target_os_final}."
                break
            }
            if (( os_round >= os_max_rounds )); then
                log "ERROR: OS-first reached its safety limit of ${os_max_rounds} round(s), but switches remain below ${target_os_final}."
                os_err=$(( os_err + 1 ))
                os_first_ready=false
                break
            fi
            if (( os_round_deployed == 0 )); then
                log "ERROR: OS-first cannot continue because switches remain below target but no OS upgrade was deployed."
                os_err=$(( os_err + 1 ))
                os_first_ready=false
                break
            fi
        done

        if $VERIFY_ONLY; then
            log_phase_checkpoint "Phase 1 result: OS checked=${os_ok}  failed=${os_err}  unmet=$(dry_run_need_count OS)"
        elif $DRY_RUN; then
            log_phase_checkpoint "Phase 1 result: OS checked=${os_ok}  failed=${os_err}  requires_upgrade=$(dry_run_need_count OS)"
        else
            log_phase_checkpoint "Phase 1 result: OS ok=${os_ok}  failed=${os_err}  upgraded=${os_deployed}"
        fi
        if $OS_FIRST && ! $DRY_RUN && ! $os_first_ready; then
            log "ERROR: BIOS and CPLD phases are blocked until all switches reach OS ${target_os_final}."
        fi
    fi

    # ── Phase 2: BIOS Upgrade ──────────────────────────────────────────────
    if $RUN_BIOS && { ! $OS_FIRST || $DRY_RUN || $os_first_ready; }; then
        if $DRY_RUN; then
            begin_log_section "Phase 2: BIOS Check  (target: ${target_bios})"
        else
            begin_log_section "Phase 2: BIOS Upgrade  (target: ${target_bios})"
        fi

        # Set true after first switch confirms BIOS upgrade; inherited by parallel subshells.
        BIOS_CONFIRMED=false

        _upgrade_bios() {
            local host="$1" mode="${2:-sequential}"
            local cur_bios proceed

            cur_bios=$(get_bios_ver "$host")
            if [[ -z "$cur_bios" ]]; then
                log "[${host}] ERROR: Could not get BIOS version. Skipping."
                return 1
            fi
            case "$(bios_version_state "$cur_bios")" in
                target)
                    log "[${host}] BIOS: ${cur_bios} (at target; no upgrade required)"
                    return 0
                    ;;
                upgrade)
                    ;;
                unsupported)
                    log "[${host}] ERROR: Unsupported BIOS version ${cur_bios}; expected ${BIOS_UPGRADE_FROM_VERSION} for upgrade or ${TARGET_BIOS_VERSION} as the completed target. Skipping."
                    return 1
                    ;;
            esac

            if $VERIFY_ONLY; then
                record_dry_run_need "$host" "BIOS" "$cur_bios" "$target_bios"
                log "[${host}] BIOS: current=${cur_bios}  target=${target_bios}  status=target not reached"
                return 0
            fi
            if $DRY_RUN; then
                record_dry_run_need "$host" "BIOS" "$cur_bios" "$target_bios"
                method_prepare_package "$host" "$TARGET_BIOS_FILE" "BIOS ${target_bios}" "$mode" || return 1
                log "[${host}] BIOS: ${cur_bios} → ${target_bios}; ${_PACKAGE_STATUS}; action=upgrade required"
                return 0
            fi

            proceed=false
            if $BIOS_CONFIRMED; then
                log "[${host}] BIOS upgrade confirmed → upgrading automatically."
                proceed=true
            elif [[ "$mode" == "parallel" ]]; then
                log "[${host}] BIOS not confirmed yet. Skipping (run sequentially first)."
                return 0
            else
                log "[${host}] BIOS upgrade needed: ${cur_bios} → ${target_bios}"
                ask "[${host}] Upgrade BIOS (${cur_bios} → ${target_bios})?" && proceed=true
            fi

            if $proceed; then
                method_prepare_package "$host" "$TARGET_BIOS_FILE" "BIOS ${target_bios}" "$mode" || return 1
                if deploy_and_run "$host" "${SCRIPTS_DIR}/bios_upgrade_${target_bios}.sh" "$mode"; then
                    [[ "$mode" == "sequential" ]] && BIOS_CONFIRMED=true
                    return 0
                fi
                return 1
            fi
            log "[${host}] BIOS upgrade skipped."
            return 0
        }

        prepare_bios_representative
        tally_snap=$(wc -l < "$_DEPLOY_TALLY" | tr -d ' ')
        each_host _upgrade_bios
        bios_ok=$_PHASE_OK; bios_err=$_PHASE_ERR
        tally_now=$(wc -l < "$_DEPLOY_TALLY" | tr -d ' ')
        bios_deployed=$(( tally_now - tally_snap ))
        if $VERIFY_ONLY; then
            log_phase_checkpoint "Phase 2 result: BIOS checked=${bios_ok}  failed=${bios_err}  unmet=$(dry_run_need_count BIOS)"
        elif $DRY_RUN; then
            log_phase_checkpoint "Phase 2 result: BIOS checked=${bios_ok}  failed=${bios_err}  requires_upgrade=$(dry_run_need_count BIOS)"
        else
            log_phase_checkpoint "Phase 2 result: BIOS ok=${bios_ok}  failed=${bios_err}  upgraded=${bios_deployed}"
        fi
        if (( bios_deployed > 0 )) && ! $DRY_RUN && (( BIOS_PHASE_WAIT > 0 )); then
            LOG_INDENT=""
            log "──────────────────────────────────────────────────────────"
            LOG_INDENT="  "
            log "${bios_deployed} BIOS upgrade(s) deployed. Waiting ${BIOS_PHASE_WAIT}s for switches to reboot."
            countdown_sleep "$BIOS_PHASE_WAIT"
        fi
    fi

    # ── Phase 3: CPLD Upgrade ──────────────────────────────────────────────
    if $RUN_CPLD && { ! $OS_FIRST || $DRY_RUN || $os_first_ready; }; then
        if $DRY_RUN; then
            begin_log_section "Phase 3: CPLD Check  (bundle: ${cpld_fui})"
        else
            begin_log_section "Phase 3: CPLD Upgrade  (bundle: ${cpld_fui})"
        fi

        # Set true after first switch confirms CPLD upgrade; inherited by parallel subshells.
        CPLD_CONFIRMED=false

        _upgrade_cpld() {
            local host="$1" mode="${2:-sequential}"
            local proceed burn_package_status refresh_package_status

            local cpld_rc
            if cpld_upgrade_needed "$host"; then
                cpld_rc=0
            else
                cpld_rc=$?
            fi
            if (( cpld_rc == 2 )); then
                log "[${host}] ERROR: Could not get CPLD versions. Skipping."
                return 1
            fi
            if (( cpld_rc == 1 )); then
                log "[${host}] CPLD: all slots meet target"
                return 0
            fi

            if $VERIFY_ONLY; then
                record_dry_run_need "$host" "CPLD" "below-target" "$cpld_fui"
                log "[${host}] CPLD: ${_CPLD_STATUS_DETAIL}; target bundle=${cpld_fui}; status=target not reached"
                return 0
            fi
            if $DRY_RUN; then
                record_dry_run_need "$host" "CPLD" "below-target" "$cpld_fui"
                method_prepare_package "$host" "$TARGET_CPLD_BURN_FILE" "CPLD BURN" "$mode" || return 1
                burn_package_status="$_PACKAGE_STATUS"
                method_prepare_package "$host" "$TARGET_CPLD_REFRESH_FILE" "CPLD REFRESH" "$mode" || return 1
                refresh_package_status="$_PACKAGE_STATUS"
                log "[${host}] CPLD: ${_CPLD_STATUS_DETAIL}; bundle=${cpld_fui}; BURN ${burn_package_status}; REFRESH ${refresh_package_status}; action=upgrade required"
                return 0
            fi

            proceed=false
            if $CPLD_CONFIRMED; then
                log "[${host}] CPLD upgrade confirmed → upgrading automatically."
                proceed=true
            elif [[ "$mode" == "parallel" ]]; then
                log "[${host}] CPLD not confirmed yet. Skipping (run sequentially first)."
                return 0
            else
                log "[${host}] CPLD upgrade needed: ${_CPLD_STATUS_DETAIL}"
                ask "[${host}] Upgrade CPLD (bundle: ${cpld_fui})?" && proceed=true
            fi

            if $proceed; then
                method_prepare_package "$host" "$TARGET_CPLD_BURN_FILE" "CPLD BURN" "$mode" || return 1
                method_prepare_package "$host" "$TARGET_CPLD_REFRESH_FILE" "CPLD REFRESH" "$mode" || return 1
                if deploy_and_run "$host" "${SCRIPTS_DIR}/cpld_upgrade_${cpld_fui}.sh" "$mode"; then
                    [[ "$mode" == "sequential" ]] && CPLD_CONFIRMED=true
                    return 0
                fi
                return 1
            fi
            log "[${host}] CPLD upgrade skipped."
            return 0
        }

        prepare_cpld_representative
        tally_snap=$(wc -l < "$_DEPLOY_TALLY" | tr -d ' ')
        each_host _upgrade_cpld
        cpld_ok=$_PHASE_OK; cpld_err=$_PHASE_ERR
        tally_now=$(wc -l < "$_DEPLOY_TALLY" | tr -d ' ')
        cpld_deployed=$(( tally_now - tally_snap ))
        if $VERIFY_ONLY; then
            log_phase_checkpoint "Phase 3 result: CPLD checked=${cpld_ok}  failed=${cpld_err}  unmet=$(dry_run_need_count CPLD)"
        elif $DRY_RUN; then
            log_phase_checkpoint "Phase 3 result: CPLD checked=${cpld_ok}  failed=${cpld_err}  requires_upgrade=$(dry_run_need_count CPLD)"
        else
            log_phase_checkpoint "Phase 3 result: CPLD ok=${cpld_ok}  failed=${cpld_err}  upgraded=${cpld_deployed}"
        fi
        if (( cpld_deployed > 0 )) && ! $DRY_RUN && (( PHASE_WAIT > 0 )); then
            LOG_INDENT=""
            log "──────────────────────────────────────────────────────────"
            LOG_INDENT="  "
            log "${cpld_deployed} CPLD upgrade(s) deployed. Waiting ${PHASE_WAIT}s for switches to reboot."
            countdown_sleep "$PHASE_WAIT"
        fi
    fi

    # ── Summary ────────────────────────────────────────────────────────────
    local total_deployed=$(( os_deployed + bios_deployed + cpld_deployed ))
    local total_err=$(( os_err + bios_err + cpld_err ))
    LOG_INDENT=""
    log "═══════════════════════════════════════════════════════════"
    if $VERIFY_ONLY; then
        log "Verification assessment complete."
        LOG_INDENT="  "
        $RUN_OS   && log "OS:   checked=${os_ok}  failed=${os_err}  unmet=$(dry_run_need_count OS)"
        $RUN_BIOS && log "BIOS: checked=${bios_ok}  failed=${bios_err}  unmet=$(dry_run_need_count BIOS)"
        $RUN_CPLD && log "CPLD: checked=${cpld_ok}  failed=${cpld_err}  unmet=$(dry_run_need_count CPLD)"
    elif $DRY_RUN; then
        log "Dry-run assessment complete."
        LOG_INDENT="  "
        $RUN_OS   && log "OS:   checked=${os_ok}  failed=${os_err}  requires_upgrade=$(dry_run_need_count OS)"
        $RUN_BIOS && log "BIOS: checked=${bios_ok}  failed=${bios_err}  requires_upgrade=$(dry_run_need_count BIOS)"
        $RUN_CPLD && log "CPLD: checked=${cpld_ok}  failed=${cpld_err}  requires_upgrade=$(dry_run_need_count CPLD)"
    else
        if (( total_deployed > 0 )); then
            log "Upgrade deployment complete; verification pending."
        else
            log "Upgrade sweep complete."
        fi
        LOG_INDENT="  "
        $RUN_OS   && log "OS:   ok=${os_ok}  failed=${os_err}  upgraded=${os_deployed}"
        $RUN_BIOS && log "BIOS: ok=${bios_ok}  failed=${bios_err}  upgraded=${bios_deployed}"
        $RUN_CPLD && log "CPLD: ok=${cpld_ok}  failed=${cpld_err}  upgraded=${cpld_deployed}"
    fi
    print_dry_run_summary

    if $VERIFY_ONLY; then
        LOG_INDENT=""
        report_verification_result "$total_err" && exit 0 || exit 1
    elif $DRY_RUN; then
        local followup_rc
        offer_upgrade_after_dry_run "$total_err"
        followup_rc=$?
        (( followup_rc == 0 )) || exit "$followup_rc"
    fi

    # ── Phase 4: Verification ──────────────────────────────────────────────
    if (( total_deployed > 0 )) && ! $DRY_RUN; then
        local verification_rc
        begin_log_section "Phase 4: Verification"
        verify_run
        verification_rc=$?
        if (( verification_rc != 0 )); then
            LOG_INDENT=""
            log "Upgrade workflow FAILED: post-upgrade verification did not pass (exit ${verification_rc})."
            exit "$verification_rc"
        fi
    fi

    (( total_err > 0 )) && exit 1 || exit 0
}

# Prompt for phase selection if the user didn't specify any phase flag
if ! $RUN_OS && ! $RUN_BIOS && ! $RUN_CPLD; then
    select_phases
fi

main
