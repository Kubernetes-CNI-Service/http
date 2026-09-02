#!/bin/bash
#
#### Cumulus Linux ZTP FLAG
# CUMULUS-AUTOPROVISIONING

### NVOS ZTP FLAG
# No FLAG for NVOS

#
set -euo pipefail

#==================== 全局公共配置 ====================
ZTP_SERVER="http://127.0.0.1"
ZTP_URL_PREFIX="/ztp"
MANUAL_ZTP_OOB_URL="http://127.0.0.1/ztp/ztp-bootstrap_oob.sh"
MANUAL_ZTP_OOBOFOOB_URL="http://127.0.0.1/ztp/ztp-bootstrap_oobofoob.sh"
TARGET_CL_VER="0.0.0"
ZTP_UPGRADE_ENABLED="false"
PUBKEY_PATHS=(
    "${ZTP_URL_PREFIX}/config/publickey/laptop.pub"
    "${ZTP_URL_PREFIX}/config/publickey/mgmt-server.pub"
)

RUNTIME_WORK_ROOT="/run"
TMP_DIR=""
LOG_FILE_NAME="ztp-result.log"
APPLIED_STATE_DIR="/var/lib/nvidia-ztp"
PERSISTENT_LOG_DIR="${APPLIED_STATE_DIR}/logs"
PERSISTENT_LOG_POINTER="${PERSISTENT_LOG_DIR}/latest-log"
LOG_FILE_PATH=""
APPLIED_YAML_PATH="${APPLIED_STATE_DIR}/last-success.yaml"
APPLIED_RECEIPT_PATH="${APPLIED_STATE_DIR}/receipt.env"
APPLIED_FAILED_YAML_PATH="${APPLIED_STATE_DIR}/last-failed-dedicated.yaml"
APPLIED_CONFIG_HELPER="/usr/local/sbin/http-manual-ztp-applied-config"
APPLIED_CONFIG_SUDOERS="/etc/sudoers.d/http-manual-ztp-applied-config"
TIME_SYNC_HELPER="/usr/local/sbin/http-sync-management-time"
TIME_SYNC_SUDOERS="/etc/sudoers.d/http-sync-management-time"
# Keep the helper's complete protocol below the management reader's 8 MiB cap,
# including receipt/magic/delimiter overhead.
APPLIED_CONFIG_MAX_BYTES=$((8 * 1024 * 1024 - 8192))
ZTP_DHCP_STATE=""
ZTP_INTERFACE=""
ZTP_VRF=""
ZTP_ROUTE_DEV=""


# 设备型号
EthVX="VX*"
EthSW="SN*"
IBSW="Q*"
NVLSW="N*"
PROD_NAME=$(decode-syseeprom 2>/dev/null | grep '^Product Name' | awk '{print $NF}' || echo "unknown")
#==================== 全局公共配置 ====================


#==================== 公共函数定义 ====================
# 记录操作日志函数, 需要记录的日志内容作为参数,  例如: [ZTP] "This is a test log."
log() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "${LOG_FILE_PATH}"
}

# Allocate one private, root-owned workspace per invocation.  A fixed /tmp/ztp
# directory is unsafe because an unprivileged local user can pre-create it (or
# replace children with symlinks) before ZTP starts.
initialize_runtime_workspace() {
    local old_umask workspace
    if [[ -L "${RUNTIME_WORK_ROOT}" || ! -d "${RUNTIME_WORK_ROOT}" ]]; then
        echo "[ZTP] ERROR: Refusing unsafe ZTP runtime root" >&2
        return 1
    fi
    old_umask=$(umask)
    umask 077
    if ! workspace=$(mktemp -d "${RUNTIME_WORK_ROOT%/}/nvidia-ztp.XXXXXX"); then
        umask "${old_umask}"
        echo "[ZTP] ERROR: Could not create private ZTP runtime workspace" >&2
        return 1
    fi
    umask "${old_umask}"
    if [[ -L "${workspace}" || ! -d "${workspace}" ]] ||
       ! chown root:root "${workspace}" || ! chmod 0700 "${workspace}"; then
        rm -rf -- "${workspace}" 2>/dev/null || true
        echo "[ZTP] ERROR: ZTP runtime workspace is not a safe root directory" >&2
        return 1
    fi
    TMP_DIR="${workspace}"
}

cleanup_runtime_workspace() {
    local workspace parent base
    workspace="${TMP_DIR:-}"
    [[ -n "${workspace}" ]] || return 0
    parent=${workspace%/*}
    base=${workspace##*/}
    if [[ "${parent}" != "${RUNTIME_WORK_ROOT%/}" ||
          ! "${base}" =~ ^nvidia-ztp\.[A-Za-z0-9]+$ ||
          -L "${workspace}" || ! -d "${workspace}" ]]; then
        echo "[ZTP] ERROR: Refusing unsafe ZTP runtime workspace cleanup: ${workspace}" >&2
        return 1
    fi
    rm -rf -- "${workspace}"
    TMP_DIR=""
}

cleanup_runtime_workspace_on_exit() {
    local status=$?
    cleanup_runtime_workspace || true
    return "${status}"
}

# Create this invocation's log as a new root-owned regular file before the
# first message is emitted.  Do not reuse /tmp/ztp/ztp-result.log: that fixed
# path can be inherited, symlinked or truncated while ZTP is running, and an
# end-of-run copy then loses the only structured stage evidence.
initialize_persistent_log() {
    local old_umask timestamp pointer_tmp log_basename
    if [[ -L "${APPLIED_STATE_DIR}" ||
          ( -e "${APPLIED_STATE_DIR}" && ! -d "${APPLIED_STATE_DIR}" ) ||
          -L "${PERSISTENT_LOG_DIR}" ||
          ( -e "${PERSISTENT_LOG_DIR}" && ! -d "${PERSISTENT_LOG_DIR}" ) ]]; then
        echo "[ZTP] ERROR: Refusing unsafe persistent ZTP log directory" >&2
        return 1
    fi
    if ! mkdir -p -- "${PERSISTENT_LOG_DIR}" ||
       ! chown root:root "${APPLIED_STATE_DIR}" "${PERSISTENT_LOG_DIR}" ||
       ! chmod 0711 "${APPLIED_STATE_DIR}" ||
       ! chmod 0755 "${PERSISTENT_LOG_DIR}"; then
        echo "[ZTP] ERROR: Could not prepare persistent ZTP log directory" >&2
        return 1
    fi
    timestamp=$(date -u '+%Y%m%d_%H%M%S') || return 1
    old_umask=$(umask)
    umask 077
    if ! LOG_FILE_PATH=$(mktemp \
        "${PERSISTENT_LOG_DIR}/${LOG_FILE_NAME}_${timestamp}_$$.XXXXXX"); then
        umask "${old_umask}"
        echo "[ZTP] ERROR: Could not create persistent ZTP log" >&2
        return 1
    fi
    umask "${old_umask}"
    if [[ -L "${LOG_FILE_PATH}" || ! -f "${LOG_FILE_PATH}" ]] ||
       ! chown root:root "${LOG_FILE_PATH}" || ! chmod 0644 "${LOG_FILE_PATH}"; then
        rm -f -- "${LOG_FILE_PATH}" 2>/dev/null || true
        LOG_FILE_PATH=""
        echo "[ZTP] ERROR: Persistent ZTP log is not a safe regular file" >&2
        return 1
    fi
    if [[ -L "${PERSISTENT_LOG_POINTER}" ||
          ( -e "${PERSISTENT_LOG_POINTER}" && ! -f "${PERSISTENT_LOG_POINTER}" ) ]]; then
        rm -f -- "${LOG_FILE_PATH}" 2>/dev/null || true
        LOG_FILE_PATH=""
        echo "[ZTP] ERROR: Refusing unsafe persistent ZTP latest-log pointer" >&2
        return 1
    fi
    log_basename=${LOG_FILE_PATH##*/}
    if [[ ! "${log_basename}" =~ ^ztp-result\.log_[A-Za-z0-9._-]+$ ]]; then
        rm -f -- "${LOG_FILE_PATH}" 2>/dev/null || true
        LOG_FILE_PATH=""
        echo "[ZTP] ERROR: Persistent ZTP log basename is unsafe" >&2
        return 1
    fi
    old_umask=$(umask)
    umask 077
    if ! pointer_tmp=$(mktemp "${PERSISTENT_LOG_DIR}/.latest-log.XXXXXX"); then
        umask "${old_umask}"
        rm -f -- "${LOG_FILE_PATH}" 2>/dev/null || true
        LOG_FILE_PATH=""
        echo "[ZTP] ERROR: Could not create persistent ZTP latest-log pointer" >&2
        return 1
    fi
    umask "${old_umask}"
    if ! printf '%s\n' "${log_basename}" > "${pointer_tmp}" ||
       [[ -L "${pointer_tmp}" || ! -f "${pointer_tmp}" ]] ||
       ! chown root:root "${pointer_tmp}" || ! chmod 0644 "${pointer_tmp}" ||
       ! mv -f -- "${pointer_tmp}" "${PERSISTENT_LOG_POINTER}"; then
        rm -f -- "${pointer_tmp}" "${LOG_FILE_PATH}" 2>/dev/null || true
        LOG_FILE_PATH=""
        echo "[ZTP] ERROR: Could not publish persistent ZTP latest-log pointer" >&2
        return 1
    fi
}

# 在本次 DHCP ZTP 实际选择的 VRF 中执行网络命令。
ztp_net_exec() {
    if [[ -z "${ZTP_VRF}" ]]; then
        log "[ZTP] ERROR: ZTP network path has not been selected"
        return 1
    fi
    ip vrf exec "${ZTP_VRF}" "$@"
}

ztp_curl() {
    ztp_net_exec curl "$@"
}

# Establish one management-server-derived clock before version/config stages.
# This is intentionally independent of chrony/NTP reachability: the currently
# selected DHCP ZTP path is already known to reach the rendered HTTP server.
sync_management_clock_for_ztp() {
    local sync_url headers http_date server_epoch year before after offset rtc
    sync_url="${ZTP_SERVER}${ZTP_URL_PREFIX}/ztp-bootstrap_oob.sh"
    if ! headers=$(ztp_curl -fsS --connect-timeout 2 --max-time 8 --range 0-0 \
        -D - -o /dev/null "${sync_url}" 2>/dev/null); then
        log "[ZTP] ERROR: Cannot read management-server HTTP Date via selected ZTP path"
        return 1
    fi
    http_date=$(printf '%s\n' "${headers}" | sed -n \
        's/^[Dd]ate:[[:space:]]*//p' | tail -n 1 | tr -d '\r')
    if [[ -z "${http_date}" ]] ||
       ! server_epoch=$(date -u -d "${http_date}" '+%s' 2>/dev/null); then
        log "[ZTP] ERROR: Management-server returned no valid HTTP Date"
        return 1
    fi
    year=$(date -u -d "@${server_epoch}" '+%Y' 2>/dev/null || true)
    if [[ ! "${year}" =~ ^[0-9]+$ ]] || (( year < 2020 || year > 2100 )); then
        log "[ZTP] ERROR: Management-server HTTP Date is outside the accepted year range"
        return 1
    fi
    before=$(date -u '+%s')
    if ! date -u -s "@${server_epoch}" >/dev/null; then
        log "[ZTP] ERROR: Could not set system clock from management-server HTTP Date"
        return 1
    fi
    after=$(date -u '+%s')
    offset=$((after - server_epoch))
    rtc=unavailable
    if command -v hwclock >/dev/null 2>&1; then
        if hwclock --systohc --utc >/dev/null 2>&1; then
            rtc=updated
        else
            rtc=failed
        fi
    fi
    log "[ZTP] TIME_SYNC_V1 before=${before} server=${server_epoch} after=${after} offset=${offset} route=${ZTP_VRF} url=${sync_url} rtc=${rtc}"
    if [[ "${rtc}" == "failed" ]]; then
        log "[ZTP] WARN: System clock synchronized but RTC update failed"
    fi
}

# Install a no-argument, root-owned ZTP helper for the management GUI.  The
# cumulus user receives NOPASSWD permission for this exact helper only; neither
# an arbitrary command nor a caller-provided URL can cross the privilege
# boundary.  Factory reset uses the fixed non-privileged NVUE `force` action
# directly and does not need a sudo helper.
install_manual_ztp_helper() {
    local ztp_bin helper helper_tmp sudoers sudoers_tmp entry role url installed
    rm -f \
        /usr/local/sbin/http-manual-reset \
        /usr/local/sbin/http-manual-reset-oob \
        /usr/local/sbin/http-manual-reset-oobofoob
    ztp_bin=$(command -v ztp 2>/dev/null || true)
    if [[ -z "${ztp_bin}" ]]; then
        log "[ZTP] WARN: ztp command not found; manual GUI trigger helper not installed"
        return 0
    fi
    sudoers=/etc/sudoers.d/http-manual-ztp
    sudoers_tmp="${sudoers}.tmp.$$"
    : > "${sudoers_tmp}"
    installed=0
    for entry in \
        "oob|${MANUAL_ZTP_OOB_URL}" \
        "oobofoob|${MANUAL_ZTP_OOBOFOOB_URL}"
    do
        role=${entry%%|*}
        url=${entry#*|}
        helper="/usr/local/sbin/http-manual-ztp-${role}"
        if [[ -z "${url}" ]]; then
            rm -f "${helper}"
            continue
        fi
        helper_tmp="${helper}.tmp.$$"
        cat > "${helper_tmp}" <<EOF
#!/bin/sh
if [ "\$#" -ne 0 ]; then
    echo "$(basename "${helper}") accepts no arguments" >&2
    exit 2
fi
exec ${ztp_bin} -r '${url}'
EOF
        chown root:root "${helper_tmp}"
        chmod 0755 "${helper_tmp}"
        mv -f "${helper_tmp}" "${helper}"
        printf 'cumulus ALL=(root) NOPASSWD: %s\n' "${helper}" >> "${sudoers_tmp}"
        installed=$((installed + 1))
    done
    if [[ "${installed}" -eq 0 ]]; then
        rm -f "${sudoers_tmp}"
        log "[ZTP] WARN: no manual ZTP helper URL was rendered"
        return 0
    fi
    chown root:root "${sudoers_tmp}"
    chmod 0440 "${sudoers_tmp}"
    if ! command -v visudo >/dev/null 2>&1; then
        rm -f "${sudoers_tmp}"
        log "[ZTP] WARN: visudo not found; manual GUI trigger sudoers not installed"
        return 0
    fi
    if ! visudo -cf "${sudoers_tmp}" >/dev/null; then
        rm -f "${sudoers_tmp}"
        log "[ZTP] WARN: manual GUI trigger sudoers validation failed"
        return 0
    fi
    mv -f "${sudoers_tmp}" "${sudoers}"
    rm -f /usr/local/sbin/http-manual-ztp
    log "[ZTP] Restricted manual ZTP helpers installed for OOB and OOBofOOB; legacy reset helpers removed"
}

# Install one fixed, no-argument clock helper for the management GUI.  It can
# contact only the two ZTP endpoints rendered by load, accepts no caller URL or
# timestamp, validates the HTTP Date header, and then changes system time.  The
# GUI still re-measures the clock over a separate identity-verified SSH probe;
# a successful helper exit alone is not treated as synchronization evidence.
install_time_sync_helper() {
    local user_name="$1" helper_tmp sudoers_tmp
    case "${user_name}" in
        cumulus|admin) ;;
        *)
            log "[ZTP] WARN: Refusing to install time-sync helper for unexpected user ${user_name}"
            return 0
            ;;
    esac
    if [[ -L "${TIME_SYNC_HELPER}" || -L "${TIME_SYNC_SUDOERS}" ]]; then
        log "[ZTP] WARN: Refusing to replace symlinked time-sync helper or sudoers path"
        return 0
    fi
    if ! helper_tmp=$(mktemp "/usr/local/sbin/.http-sync-management-time.XXXXXX"); then
        log "[ZTP] WARN: Could not create time-sync helper temporary file"
        return 0
    fi
    if ! cat > "${helper_tmp}" <<EOF
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[ "\$#" -eq 0 ] || { echo "http-sync-management-time accepts no arguments" >&2; exit 2; }

fetch_date() {
    route=\$1
    url=\$2
    if [ "\${route}" = "direct" ]; then
        headers=\$(curl -fsS --connect-timeout 2 --max-time 8 --range 0-0 \\
            -D - -o /dev/null "\${url}" 2>/dev/null) || return 1
    else
        headers=\$(ip vrf exec "\${route}" curl -fsS --connect-timeout 2 --max-time 8 --range 0-0 \\
            -D - -o /dev/null "\${url}" 2>/dev/null) || return 1
    fi
    http_date=\$(printf '%s\n' "\${headers}" | sed -n \\
        's/^[Dd]ate:[[:space:]]*//p' | tail -n 1 | tr -d '\r')
    [ -n "\${http_date}" ] || return 1
    date -u -d "\${http_date}" '+%s' 2>/dev/null
}

list_routes() {
    printf '%s\n' direct
    ip vrf show 2>/dev/null | awk '
        \$1 == "Name" || \$1 ~ /^-+\$/ { next }
        NF >= 2 && \$2 ~ /^[0-9]+\$/ &&
        length(\$1) <= 15 && \$1 ~ /^[A-Za-z0-9_.-]+\$/ &&
        !seen[\$1]++ { print \$1 }
    '
}

server_epoch=
source_url=
source_route=
routes=\$(list_routes)
for route in \${routes}; do
    for url in '${MANUAL_ZTP_OOB_URL}' '${MANUAL_ZTP_OOBOFOOB_URL}'; do
        [ -n "\${url}" ] || continue
        if candidate=\$(fetch_date "\${route}" "\${url}"); then
            case "\${candidate}" in ''|*[!0-9]*) continue ;; esac
            year=\$(date -u -d "@\${candidate}" '+%Y' 2>/dev/null || true)
            case "\${year}" in ''|*[!0-9]*) continue ;; esac
            [ "\${year}" -ge 2020 ] && [ "\${year}" -le 2100 ] || continue
            server_epoch=\${candidate}
            source_url=\${url}
            source_route=\${route}
            break 2
        fi
    done
done
[ -n "\${server_epoch}" ] || {
    tried_routes=\$(printf '%s\n' "\${routes}" | tr '\n' ',' | sed 's/,$//')
    echo "no valid HTTP Date from rendered management-server ZTP endpoints; routes=\${tried_routes}" >&2
    exit 1
}

before=\$(date -u '+%s')
date -u -s "@\${server_epoch}" >/dev/null
after=\$(date -u '+%s')
offset=\$((after - server_epoch))
rtc=unavailable
if command -v hwclock >/dev/null 2>&1; then
    if hwclock --systohc --utc >/dev/null 2>&1; then
        rtc=updated
    else
        rtc=failed
        echo "system clock synchronized but RTC update failed" >&2
    fi
fi
printf 'TIME_SYNC_V1 before=%s server=%s after=%s offset=%s route=%s url=%s rtc=%s\n' \\
    "\${before}" "\${server_epoch}" "\${after}" "\${offset}" \\
    "\${source_route}" "\${source_url}" "\${rtc}"
EOF
    then
        rm -f "${helper_tmp}"
        log "[ZTP] WARN: Could not render time-sync helper"
        return 0
    fi
    chown root:root "${helper_tmp}"
    chmod 0755 "${helper_tmp}"
    mv -f "${helper_tmp}" "${TIME_SYNC_HELPER}"

    sudoers_tmp="${TIME_SYNC_SUDOERS}.tmp.$$"
    printf '%s ALL=(root) NOPASSWD: %s\n' "${user_name}" "${TIME_SYNC_HELPER}" > "${sudoers_tmp}"
    chown root:root "${sudoers_tmp}"
    chmod 0440 "${sudoers_tmp}"
    if ! command -v visudo >/dev/null 2>&1 || ! visudo -cf "${sudoers_tmp}" >/dev/null; then
        rm -f "${sudoers_tmp}" "${TIME_SYNC_HELPER}"
        log "[ZTP] WARN: time-sync sudoers validation failed"
        return 0
    fi
    mv -f "${sudoers_tmp}" "${TIME_SYNC_SUDOERS}"
    log "[ZTP] Restricted management-server time-sync helper installed for ${user_name}"
}

# Install one fixed, no-argument reader for the root-owned applied-config
# receipt.  The helper never accepts a caller-provided path and validates the
# receipt, ownership, modes, size and SHA-256 before returning any YAML.  A
# separate sudoers file keeps this read-only evidence boundary independent from
# the two helpers that trigger Cumulus ZTP.
install_applied_config_helper() {
    local user_name="$1"
    local helper_tmp sudoers_tmp

    case "${user_name}" in
        cumulus|admin) ;;
        *)
            log "[ZTP] WARN: Refusing to install applied-config helper for unexpected user ${user_name}"
            return 0
            ;;
    esac
    if [[ -L "${APPLIED_CONFIG_HELPER}" || -L "${APPLIED_CONFIG_SUDOERS}" ]]; then
        log "[ZTP] WARN: Refusing to replace symlinked applied-config helper or sudoers path"
        return 0
    fi
    if ! helper_tmp=$(mktemp "/usr/local/sbin/.http-manual-ztp-applied-config.XXXXXX"); then
        log "[ZTP] WARN: Could not create applied-config helper temporary file"
        return 0
    fi
    if ! cat > "${helper_tmp}" <<'EOF'
#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

STATE_DIR=/var/lib/nvidia-ztp
YAML_PATH=${STATE_DIR}/last-success.yaml
RECEIPT_PATH=${STATE_DIR}/receipt.env
FAILED_YAML_PATH=${STATE_DIR}/last-failed-dedicated.yaml
MAX_YAML_BYTES=8380416
MAX_RECEIPT_BYTES=4096

fail() {
    echo "ZTP applied-config evidence unavailable: $*" >&2
    exit 1
}

file_size() {
    local_size=$(wc -c < "$1" 2>/dev/null | tr -d '[:space:]') || return 1
    case "${local_size}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "${local_size}"
}

valid_hash() {
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
    esac
    return 0
}

check_root_file() {
    check_path="$1"
    [ ! -L "${check_path}" ] && [ -f "${check_path}" ] || fail "unsafe or missing ${check_path}"
    check_uid=$(stat -c '%u' "${check_path}" 2>/dev/null) || fail "cannot stat ${check_path}"
    check_mode=$(stat -c '%a' "${check_path}" 2>/dev/null) || fail "cannot stat ${check_path}"
    [ "${check_uid}" = "0" ] && [ "${check_mode}" = "600" ] || fail "unsafe owner or mode for ${check_path}"
}

[ "$#" -eq 0 ] || fail "helper accepts no arguments"
[ ! -L "${STATE_DIR}" ] && [ -d "${STATE_DIR}" ] || fail "unsafe or missing state directory"
state_uid=$(stat -c '%u' "${STATE_DIR}" 2>/dev/null) || fail "cannot stat state directory"
state_mode=$(stat -c '%a' "${STATE_DIR}" 2>/dev/null) || fail "cannot stat state directory"
[ "${state_uid}" = "0" ] && [ "${state_mode}" = "711" ] || fail "unsafe state directory owner or mode"
check_root_file "${RECEIPT_PATH}"
check_root_file "${YAML_PATH}"
receipt_size=$(file_size "${RECEIPT_PATH}") || fail "cannot size receipt"
[ "${receipt_size}" -gt 0 ] && [ "${receipt_size}" -le "${MAX_RECEIPT_BYTES}" ] || fail "receipt size out of range"
yaml_size=$(file_size "${YAML_PATH}") || fail "cannot size applied YAML"
[ "${yaml_size}" -gt 0 ] && [ "${yaml_size}" -le "${MAX_YAML_BYTES}" ] || fail "applied YAML size out of range"

schema=
status=
source_kind=
apply_mode=
raw_sha256=
source_name=
eth0_mac=
applied_at=
failed_raw_sha256=
seen_schema=
seen_status=
seen_source_kind=
seen_apply_mode=
seen_raw_sha256=
seen_source_name=
seen_eth0_mac=
seen_applied_at=
seen_failed_raw_sha256=
while IFS= read -r receipt_line || [ -n "${receipt_line}" ]; do
    case "${receipt_line}" in
        *=*) ;;
        *) fail "malformed receipt line" ;;
    esac
    receipt_key=${receipt_line%%=*}
    receipt_value=${receipt_line#*=}
    [ -n "${receipt_value}" ] || fail "empty receipt value for ${receipt_key}"
    case "${receipt_key}" in
        schema)
            [ -z "${seen_schema}" ] || fail "duplicate receipt key ${receipt_key}"
            schema=${receipt_value}; seen_schema=1 ;;
        status)
            [ -z "${seen_status}" ] || fail "duplicate receipt key ${receipt_key}"
            status=${receipt_value}; seen_status=1 ;;
        source_kind)
            [ -z "${seen_source_kind}" ] || fail "duplicate receipt key ${receipt_key}"
            source_kind=${receipt_value}; seen_source_kind=1 ;;
        apply_mode)
            [ -z "${seen_apply_mode}" ] || fail "duplicate receipt key ${receipt_key}"
            apply_mode=${receipt_value}; seen_apply_mode=1 ;;
        raw_sha256)
            [ -z "${seen_raw_sha256}" ] || fail "duplicate receipt key ${receipt_key}"
            raw_sha256=${receipt_value}; seen_raw_sha256=1 ;;
        source_name)
            [ -z "${seen_source_name}" ] || fail "duplicate receipt key ${receipt_key}"
            source_name=${receipt_value}; seen_source_name=1 ;;
        eth0_mac)
            [ -z "${seen_eth0_mac}" ] || fail "duplicate receipt key ${receipt_key}"
            eth0_mac=${receipt_value}; seen_eth0_mac=1 ;;
        applied_at)
            [ -z "${seen_applied_at}" ] || fail "duplicate receipt key ${receipt_key}"
            applied_at=${receipt_value}; seen_applied_at=1 ;;
        failed_raw_sha256)
            [ -z "${seen_failed_raw_sha256}" ] || fail "duplicate receipt key ${receipt_key}"
            failed_raw_sha256=${receipt_value}; seen_failed_raw_sha256=1 ;;
        *) fail "unknown receipt key ${receipt_key}" ;;
    esac
done < "${RECEIPT_PATH}"

[ "${schema}" = "1" ] || fail "unsupported receipt schema"
valid_hash "${raw_sha256}" || fail "invalid applied YAML hash"
case "${source_name}" in
    [A-Za-z0-9]*) ;;
    *) fail "unsafe source name" ;;
esac
case "${source_name}" in
    *[!A-Za-z0-9._-]*) fail "unsafe source name" ;;
esac
[ "${#source_name}" -le 255 ] || fail "unsafe source name"
case "${eth0_mac}" in
    [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
    *) fail "invalid eth0 MAC" ;;
esac
case "${applied_at}" in
    ''|*[!0-9TZ:+.-]*) fail "unsafe applied timestamp" ;;
esac
case "${status}|${source_kind}|${apply_mode}" in
    success\|dedicated\|replace|success\|dedicated\|patch|success\|default\|patch|success\|fallback\|patch) ;;
    success\|fallback_default\|patch)
        valid_hash "${failed_raw_sha256}" || fail "invalid failed dedicated hash"
        check_root_file "${FAILED_YAML_PATH}"
        failed_size=$(file_size "${FAILED_YAML_PATH}") || fail "cannot size failed dedicated YAML"
        [ "${failed_size}" -gt 0 ] && [ "${failed_size}" -le "${MAX_YAML_BYTES}" ] || fail "failed dedicated YAML size out of range"
        failed_actual=$(sha256sum "${FAILED_YAML_PATH}" 2>/dev/null) || fail "cannot hash failed dedicated YAML"
        failed_actual=${failed_actual%% *}
        [ "${failed_actual}" = "${failed_raw_sha256}" ] || fail "failed dedicated YAML hash mismatch"
        ;;
    *) fail "inconsistent receipt state" ;;
esac
if [ "${source_kind}" != "fallback_default" ] && [ -n "${seen_failed_raw_sha256}" ]; then
    fail "unexpected failed dedicated hash"
fi

actual_sha256=$(sha256sum "${YAML_PATH}" 2>/dev/null) || fail "cannot hash applied YAML"
actual_sha256=${actual_sha256%% *}
[ "${actual_sha256}" = "${raw_sha256}" ] || fail "applied YAML hash mismatch"

printf '%s\n' 'ZTP_APPLIED_CONFIG_V1'
cat "${RECEIPT_PATH}"
printf '%s\n' '---'
cat "${YAML_PATH}"
EOF
    then
        rm -f -- "${helper_tmp}" || true
        log "[ZTP] WARN: Could not render applied-config helper"
        return 0
    fi
    if ! chown root:root "${helper_tmp}" || ! chmod 0755 "${helper_tmp}" ||
       ! mv -f -- "${helper_tmp}" "${APPLIED_CONFIG_HELPER}"; then
        rm -f -- "${helper_tmp}" || true
        log "[ZTP] WARN: Could not install applied-config helper"
        return 0
    fi
    if ! command -v visudo >/dev/null 2>&1; then
        log "[ZTP] WARN: visudo not found; applied-config helper sudoers not installed"
        return 0
    fi
    if ! sudoers_tmp=$(mktemp "/etc/sudoers.d/.http-manual-ztp-applied-config.XXXXXX"); then
        log "[ZTP] WARN: Could not create applied-config sudoers temporary file"
        return 0
    fi
    if ! printf '%s ALL=(root) NOPASSWD: %s\n' \
        "${user_name}" "${APPLIED_CONFIG_HELPER}" > "${sudoers_tmp}" ||
       ! chown root:root "${sudoers_tmp}" || ! chmod 0440 "${sudoers_tmp}" ||
       ! visudo -cf "${sudoers_tmp}" >/dev/null 2>&1 ||
       ! mv -f -- "${sudoers_tmp}" "${APPLIED_CONFIG_SUDOERS}"; then
        rm -f -- "${sudoers_tmp}" || true
        log "[ZTP] WARN: Could not validate or install applied-config helper sudoers"
        return 0
    fi
    log "[ZTP] Restricted applied-config receipt helper installed for ${user_name}"
    return 0
}

# 从 Cumulus ZTP DHCP hook 的运行时状态中取得实际下载 bootstrap 的接口。
# /var/run 通常链接到 /run；兼容两种路径。文件缺失时保留旧平台/NVOS 的
# mgmt 优先行为，但文件存在且与当前服务器冲突时拒绝静默回退。
select_ztp_network_path() {
    local candidate iface url extra current master_path master_name route

    for candidate in /run/ztp.dhcp /var/run/ztp.dhcp; do
        if [[ -s "${candidate}" ]]; then
            ZTP_DHCP_STATE="${candidate}"
            break
        fi
    done

    if [[ -n "${ZTP_DHCP_STATE}" ]]; then
        # Cumulus 写入的 /run/ztp.dhcp 通常只有一行，而且文件末尾可能没有
        # newline。read 在这种情况下会返回非零，但变量中已经有完整内容，
        # 因此必须继续处理最后一行。
        while IFS='|' read -r iface url extra || [[ -n "${iface}${url}${extra}" ]]; do
            iface=${iface//[[:space:]]/}
            url=${url//[[:space:]]/}
            if [[ -n "${iface}" && ( "${url}" == "${ZTP_SERVER}" || "${url}" == "${ZTP_SERVER}/"* ) ]]; then
                ZTP_INTERFACE="${iface}"
                break
            fi
        done < "${ZTP_DHCP_STATE}"
        if [[ -z "${ZTP_INTERFACE}" ]]; then
            log "[ZTP] ERROR: ${ZTP_DHCP_STATE} has no path matching ${ZTP_SERVER}"
            return 1
        fi
        if [[ ! -d "/sys/class/net/${ZTP_INTERFACE}" ]]; then
            log "[ZTP] ERROR: ZTP DHCP selected interface does not exist: ${ZTP_INTERFACE}"
            return 1
        fi

        ZTP_VRF="default"
        current="${ZTP_INTERFACE}"
        while master_path=$(readlink -f "/sys/class/net/${current}/master" 2>/dev/null); do
            [[ -n "${master_path}" ]] || break
            master_name=${master_path##*/}
            if ip -d link show dev "${master_name}" 2>/dev/null | grep -qw vrf; then
                ZTP_VRF="${master_name}"
                break
            fi
            [[ "${master_name}" != "${current}" ]] || break
            current="${master_name}"
        done
        log "[ZTP] DHCP-selected path: state=${ZTP_DHCP_STATE}, interface=${ZTP_INTERFACE}, vrf=${ZTP_VRF}"
    else
        if [[ -d /sys/class/net/mgmt ]]; then
            ZTP_VRF="mgmt"
            [[ -d /sys/class/net/eth0 ]] && ZTP_INTERFACE="eth0"
        else
            ZTP_VRF="default"
        fi
        log "[ZTP] WARN: /run/ztp.dhcp not found; fallback vrf=${ZTP_VRF}, interface=${ZTP_INTERFACE:-auto}"
    fi

    if [[ "${ZTP_VRF}" == "default" ]]; then
        route=$(ip -4 route get "${ZTP_SERVER##*/}" 2>/dev/null | head -n 1 || true)
    else
        route=$(ip -4 route get "${ZTP_SERVER##*/}" vrf "${ZTP_VRF}" 2>/dev/null | head -n 1 || true)
    fi
    ZTP_ROUTE_DEV=$(awk '{for (i=1; i<=NF; i++) if ($i == "dev" && i < NF) {print $(i+1); exit}}' <<<"${route}")
    log "[ZTP] Selected route: vrf=${ZTP_VRF}, interface=${ZTP_INTERFACE:-auto}, route_dev=${ZTP_ROUTE_DEV:-unknown}, route=${route:-unavailable}"
}

# 将 apply 失败的设备专用配置保存到持久家目录，避免 ZTP 临时目录在退出后被清理。
persist_failed_config() {
    local source_file="$1"
    local user_home="$2"
    local user_name="$3"
    local failed_dir failed_name timestamp

    FAILED_CFG_PATH=""
    failed_dir="${user_home}/ztp-failed-configs"
    timestamp=$(date '+%Y%m%d_%H%M%S')
    failed_name="${source_file##*/}"
    failed_name="${failed_name%.yaml}_${timestamp}.yaml"

    if mkdir -p "${failed_dir}" &&
       cp -f "${source_file}" "${failed_dir}/${failed_name}" &&
       chmod 600 "${failed_dir}/${failed_name}" &&
       chown -R "${user_name}:${user_name}" "${failed_dir}"; then
        FAILED_CFG_PATH="${failed_dir}/${failed_name}"
    else
        log "[ZTP] WARN: Could not preserve failed MAC config from ${source_file}"
    fi
}

# Persist the exact YAML bytes that most recently completed both NVUE apply and
# save.  receipt.env is promoted last: if power is lost between the two renames,
# the fixed reader detects the old-receipt/new-YAML hash mismatch and fails
# closed.  Persistence is diagnostic evidence only, so every local I/O failure
# is downgraded to WARN and must not turn an already successful ZTP into failure.
persist_applied_receipt() {
    local source_file="$1"
    local receipt_status="$2"
    local source_kind="$3"
    local apply_mode="$4"
    local source_name="$5"
    local eth0_mac="$6"
    local failed_source="${7:-}"
    local source_size raw_sha256 copied_sha256 applied_at
    local failed_size failed_raw_sha256 failed_copied_sha256=""
    local yaml_tmp="" receipt_tmp="" failed_tmp=""

    cleanup_applied_receipt_temps() {
        [[ -z "${yaml_tmp}" ]] || rm -f -- "${yaml_tmp}" || true
        [[ -z "${receipt_tmp}" ]] || rm -f -- "${receipt_tmp}" || true
        [[ -z "${failed_tmp}" ]] || rm -f -- "${failed_tmp}" || true
    }

    case "${receipt_status}|${source_kind}|${apply_mode}" in
        success\|dedicated\|replace|success\|dedicated\|patch|success\|default\|patch|success\|fallback\|patch|success\|fallback_default\|patch) ;;
        *)
            log "[ZTP] WARN: Refusing unsafe applied-config receipt state"
            return 0
            ;;
    esac
    if [[ ! "${source_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$ ]]; then
        log "[ZTP] WARN: Refusing unsafe applied-config source name"
        return 0
    fi
    if ! eth0_mac=$(printf '%s' "${eth0_mac}" | tr '[:upper:]' '[:lower:]'); then
        log "[ZTP] WARN: Could not normalize applied-config eth0 MAC"
        return 0
    fi
    if [[ ! "${eth0_mac}" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
        log "[ZTP] WARN: Refusing applied-config receipt with invalid eth0 MAC"
        return 0
    fi
    if [[ -L "${source_file}" || ! -f "${source_file}" ]]; then
        log "[ZTP] WARN: Applied-config source is missing, non-regular or symlinked"
        return 0
    fi
    if ! source_size=$(wc -c < "${source_file}"); then
        log "[ZTP] WARN: Could not size applied-config source"
        return 0
    fi
    source_size=${source_size//[[:space:]]/}
    if [[ ! "${source_size}" =~ ^[0-9]+$ ]] || (( source_size < 1 || source_size > APPLIED_CONFIG_MAX_BYTES )); then
        log "[ZTP] WARN: Applied-config source size is outside the safe range"
        return 0
    fi
    if ! command -v sha256sum >/dev/null 2>&1 ||
       ! raw_sha256=$(sha256sum "${source_file}"); then
        log "[ZTP] WARN: Could not hash applied-config source"
        return 0
    fi
    raw_sha256=${raw_sha256%% *}
    if [[ ! "${raw_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
        log "[ZTP] WARN: Applied-config source returned an invalid SHA-256"
        return 0
    fi
    failed_raw_sha256=""
    if [[ "${source_kind}" == "fallback_default" ]]; then
        if [[ -L "${failed_source}" || ! -f "${failed_source}" ]]; then
            log "[ZTP] WARN: Failed dedicated source is missing, non-regular or symlinked"
            return 0
        fi
        if ! failed_size=$(wc -c < "${failed_source}"); then
            log "[ZTP] WARN: Could not size failed dedicated source"
            return 0
        fi
        failed_size=${failed_size//[[:space:]]/}
        if [[ ! "${failed_size}" =~ ^[0-9]+$ ]] || (( failed_size < 1 || failed_size > APPLIED_CONFIG_MAX_BYTES )); then
            log "[ZTP] WARN: Failed dedicated source size is outside the safe range"
            return 0
        fi
        if ! failed_raw_sha256=$(sha256sum "${failed_source}"); then
            log "[ZTP] WARN: Could not hash failed dedicated source"
            return 0
        fi
        failed_raw_sha256=${failed_raw_sha256%% *}
        if [[ ! "${failed_raw_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
            log "[ZTP] WARN: Failed dedicated source returned an invalid SHA-256"
            return 0
        fi
    elif [[ -n "${failed_source}" ]]; then
        log "[ZTP] WARN: Ignoring unexpected failed source for successful dedicated/default receipt"
        failed_source=""
    fi

    if [[ -L "${APPLIED_STATE_DIR}" || ( -e "${APPLIED_STATE_DIR}" && ! -d "${APPLIED_STATE_DIR}" ) ]]; then
        log "[ZTP] WARN: Refusing unsafe applied-config state directory"
        return 0
    fi
    if ! mkdir -p -- "${APPLIED_STATE_DIR}" ||
       ! chown root:root "${APPLIED_STATE_DIR}" || ! chmod 0711 "${APPLIED_STATE_DIR}"; then
        log "[ZTP] WARN: Could not prepare applied-config state directory"
        return 0
    fi
    if [[ -L "${APPLIED_YAML_PATH}" || -L "${APPLIED_RECEIPT_PATH}" ||
          ( "${source_kind}" == "fallback_default" && -L "${APPLIED_FAILED_YAML_PATH}" ) ]]; then
        log "[ZTP] WARN: Refusing symlinked applied-config state target"
        return 0
    fi
    if ! yaml_tmp=$(mktemp "${APPLIED_STATE_DIR}/.last-success.yaml.XXXXXX") ||
       ! receipt_tmp=$(mktemp "${APPLIED_STATE_DIR}/.receipt.env.XXXXXX"); then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not create applied-config temporary files"
        return 0
    fi
    if [[ "${source_kind}" == "fallback_default" ]] &&
       ! failed_tmp=$(mktemp "${APPLIED_STATE_DIR}/.last-failed-dedicated.yaml.XXXXXX"); then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not create failed dedicated temporary file"
        return 0
    fi
    if ! cp -- "${source_file}" "${yaml_tmp}" ||
       ! chown root:root "${yaml_tmp}" || ! chmod 0600 "${yaml_tmp}" ||
       ! copied_sha256=$(sha256sum "${yaml_tmp}"); then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not stage applied-config YAML"
        return 0
    fi
    copied_sha256=${copied_sha256%% *}
    if [[ "${copied_sha256}" != "${raw_sha256}" ]]; then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Applied-config source changed while it was being preserved"
        return 0
    fi
    if [[ -n "${failed_tmp}" ]]; then
        if ! cp -- "${failed_source}" "${failed_tmp}" ||
           ! chown root:root "${failed_tmp}" || ! chmod 0600 "${failed_tmp}" ||
           ! failed_copied_sha256=$(sha256sum "${failed_tmp}"); then
            cleanup_applied_receipt_temps
            log "[ZTP] WARN: Could not stage failed dedicated YAML"
            return 0
        fi
        failed_copied_sha256=${failed_copied_sha256%% *}
        if [[ "${failed_copied_sha256}" != "${failed_raw_sha256}" ]]; then
            cleanup_applied_receipt_temps
            log "[ZTP] WARN: Failed dedicated source changed while it was being preserved"
            return 0
        fi
    fi
    if ! applied_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ'); then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not timestamp applied-config receipt"
        return 0
    fi
    if [[ ! "${applied_at}" =~ ^[0-9TZ:+.-]+$ ]]; then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not generate a safe applied-config timestamp"
        return 0
    fi
    if ! {
        printf 'schema=1\n'
        printf 'status=%s\n' "${receipt_status}"
        printf 'source_kind=%s\n' "${source_kind}"
        printf 'apply_mode=%s\n' "${apply_mode}"
        printf 'raw_sha256=%s\n' "${raw_sha256}"
        printf 'source_name=%s\n' "${source_name}"
        printf 'eth0_mac=%s\n' "${eth0_mac}"
        printf 'applied_at=%s\n' "${applied_at}"
        if [[ -n "${failed_raw_sha256}" ]]; then
            printf 'failed_raw_sha256=%s\n' "${failed_raw_sha256}"
        fi
    } > "${receipt_tmp}" || ! chown root:root "${receipt_tmp}" || ! chmod 0600 "${receipt_tmp}"; then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not stage applied-config receipt"
        return 0
    fi

    # Promote data first and the receipt last.  The reader fails closed if an
    # interruption leaves a receipt/YAML pair with different hashes.
    if ! mv -f -- "${yaml_tmp}" "${APPLIED_YAML_PATH}"; then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not promote applied-config YAML"
        return 0
    fi
    yaml_tmp=""
    if [[ -n "${failed_tmp}" ]]; then
        if ! mv -f -- "${failed_tmp}" "${APPLIED_FAILED_YAML_PATH}"; then
            cleanup_applied_receipt_temps
            log "[ZTP] WARN: Could not promote failed dedicated YAML"
            return 0
        fi
        failed_tmp=""
    fi
    if ! mv -f -- "${receipt_tmp}" "${APPLIED_RECEIPT_PATH}"; then
        cleanup_applied_receipt_temps
        log "[ZTP] WARN: Could not promote applied-config receipt; reader will reject any mismatched prior receipt"
        return 0
    fi
    receipt_tmp=""
    log "[ZTP] Applied-config receipt saved: status=${receipt_status}, source=${source_name}, sha256=${raw_sha256}"
    return 0
}

# Cache one fallback config while the DHCP-selected path is still usable.
# Callers decide whether a missing candidate is fatal; this function never
# leaves a stale/partial cache that could be consumed after NVUE changes.
prefetch_config_candidate() {
    local source_url="$1"
    local cache_path="$2"
    local priority_label="$3"
    local cache_tmp="" cache_size

    if [[ -L "${cache_path}" ]]; then
        log "[ZTP] WARN: Refusing symlinked default-config cache (${priority_label}): ${source_url}"
        return 1
    fi
    rm -f -- "${cache_path}" || true
    if ! cache_tmp=$(mktemp "${TMP_DIR}/.default-config.XXXXXX"); then
        log "[ZTP] WARN: Could not create default-config cache (${priority_label}): ${source_url}"
        return 1
    fi
    if ! ztp_curl -sf "${source_url}" -o "${cache_tmp}" ||
       [[ -L "${cache_tmp}" || ! -f "${cache_tmp}" || ! -s "${cache_tmp}" ]]; then
        rm -f -- "${cache_tmp}" || true
        log "[ZTP] WARN: Default-config prefetch unavailable (${priority_label}): ${source_url}"
        return 1
    fi
    if ! cache_size=$(wc -c < "${cache_tmp}"); then
        rm -f -- "${cache_tmp}" || true
        log "[ZTP] WARN: Could not size default-config cache (${priority_label})"
        return 1
    fi
    cache_size=${cache_size//[[:space:]]/}
    if [[ ! "${cache_size}" =~ ^[0-9]+$ ]] ||
       (( cache_size < 1 || cache_size > APPLIED_CONFIG_MAX_BYTES )); then
        rm -f -- "${cache_tmp}" || true
        log "[ZTP] WARN: Default-config cache size is unsafe (${priority_label})"
        return 1
    fi
    if ! chmod 0600 "${cache_tmp}" || ! mv -f -- "${cache_tmp}" "${cache_path}"; then
        rm -f -- "${cache_tmp}" || true
        log "[ZTP] WARN: Could not promote default-config cache (${priority_label})"
        return 1
    fi
    log "[ZTP] Default config prefetched: priority=${priority_label}, url=${source_url}"
    return 0
}

# Download every configured public-key source while the DHCP-selected ZTP path
# is still intact.  A dedicated config may remove that transit path, so no
# network access is allowed in install_ssh_pubkeys() after NVUE apply/save.
prefetch_ssh_pubkeys() {
    local pub_path pub_url pub_tmp pub_cache
    local index=0
    local prefetched=0

    log "[ZTP] Start prefetching SSH public keys before any NVUE configuration change"
    for pub_path in "${PUBKEY_PATHS[@]}"; do
        index=$((index + 1))
        pub_url="${ZTP_SERVER}${pub_path}"
        pub_cache="${TMP_DIR}/pubkey.${index}.cache"
        if [[ -L "${pub_cache}" ]]; then
            log "[ZTP] WARN: Refusing symlinked public-key cache: ${pub_url}"
            continue
        fi
        rm -f -- "${pub_cache}" || true
        if ! pub_tmp=$(mktemp "${TMP_DIR}/.pubkey.${index}.XXXXXX"); then
            log "[ZTP] WARN: Could not create public-key cache for ${pub_url}"
            continue
        fi
        if ztp_curl -sf "${pub_url}" -o "${pub_tmp}" &&
           [[ ! -L "${pub_tmp}" && -f "${pub_tmp}" && -s "${pub_tmp}" ]] &&
           chmod 0600 "${pub_tmp}" && mv -f -- "${pub_tmp}" "${pub_cache}"; then
            prefetched=$((prefetched + 1))
            log "[ZTP] SSH public key prefetched: ${pub_url}"
        else
            rm -f -- "${pub_tmp}" || true
            log "[ZTP] WARN: SSH public key prefetch failed or returned empty content: ${pub_url}"
        fi
    done
    if (( prefetched == 0 )); then
        log "[ZTP] WARN: No non-empty SSH public key source was prefetched"
    else
        log "[ZTP] SSH public key prefetch complete: ${prefetched}/${#PUBKEY_PATHS[@]} source(s)"
    fi
    return 0
}

# Install only the local cache produced before NVUE changes.  This function is
# intentionally network-free: do not add ztp_curl/curl/ping/route operations.
install_ssh_pubkeys() {
    local pub_path pub_cache key key_type key_blob key_comment auth_tmp source_usable
    local installed=0
    local usable=0
    local index=0
    local ssh_dir auth_key user owner_group primary_group

    ssh_dir="$1"/.ssh
    auth_key="${ssh_dir}/authorized_keys"
    user="${1##*/}"
    if ! primary_group=$(id -gn "${user}" 2>/dev/null); then
        primary_group="${user}"
    fi
    owner_group="${user}:${primary_group}"

    log "[ZTP] Start installing prefetched SSH public keys to $1"
    if [[ -L "$1" || ! -d "$1" ]]; then
        log "[ZTP] WARN: Refusing unsafe SSH home directory: $1"
        log "[ZTP] ACCESS_NOT_READY: SSH home directory is unsafe"
        return 0
    fi
    if [[ -L "${ssh_dir}" || ( -e "${ssh_dir}" && ! -d "${ssh_dir}" ) ]]; then
        log "[ZTP] WARN: Refusing unsafe SSH directory: ${ssh_dir}"
        log "[ZTP] ACCESS_NOT_READY: SSH directory is unsafe"
        return 0
    fi
    if ! mkdir -p -- "${ssh_dir}" || ! chmod 0700 "${ssh_dir}"; then
        log "[ZTP] WARN: Could not prepare SSH directory: ${ssh_dir}"
        log "[ZTP] ACCESS_NOT_READY: SSH directory could not be prepared"
        return 0
    fi
    if [[ -L "${auth_key}" || ( -e "${auth_key}" && ! -f "${auth_key}" ) ]]; then
        log "[ZTP] WARN: Refusing unsafe authorized_keys: ${auth_key}"
        log "[ZTP] ACCESS_NOT_READY: authorized_keys is unsafe"
        return 0
    fi
    if [[ ! -e "${auth_key}" ]] && ! : > "${auth_key}"; then
        log "[ZTP] WARN: Could not create authorized_keys: ${auth_key}"
        log "[ZTP] ACCESS_NOT_READY: authorized_keys could not be created"
        return 0
    fi
    if ! auth_tmp=$(mktemp "${ssh_dir}/.authorized_keys.XXXXXX"); then
        log "[ZTP] WARN: Could not create authorized_keys staging file"
        log "[ZTP] ACCESS_NOT_READY: authorized_keys staging failed"
        return 0
    fi
    # Preserve comments/options/unknown lines verbatim while keeping only the
    # first occurrence of each OpenSSH key identity.  A comment is not part of
    # key identity, so ``type blob laptop`` and ``type blob mgmt`` are one key.
    if ! awk '
        function is_key_type(value) {
            return value ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/
        }
        {
            identity = ""
            for (field = 1; field < NF; field++) {
                if (is_key_type($field)) {
                    identity = $field SUBSEP $(field + 1)
                    break
                }
            }
            if (identity == "" || !seen[identity]++) print
        }
    ' "${auth_key}" > "${auth_tmp}"; then
        rm -f -- "${auth_tmp}" || true
        log "[ZTP] WARN: Could not stage existing authorized_keys"
        log "[ZTP] ACCESS_NOT_READY: authorized_keys staging failed"
        return 0
    fi
    for pub_path in "${PUBKEY_PATHS[@]}"; do
        index=$((index + 1))
        source_usable=0
        pub_cache="${TMP_DIR}/pubkey.${index}.cache"
        if [[ -L "${pub_cache}" || ! -f "${pub_cache}" || ! -s "${pub_cache}" ]]; then
            log "[ZTP] WARN: Prefetched public key unavailable; skipped: ${pub_path}"
            continue
        fi
        while IFS= read -r key || [[ -n "${key}" ]]; do
            [[ -z "${key}" || "${key}" == \#* ]] && continue
            read -r key_type key_blob key_comment <<< "${key}"
            case "${key_type}" in
                ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-*|sk-ssh-*|sk-ecdsa-*|ssh-*-cert-v01@openssh.com|ecdsa-*-cert-v01@openssh.com) ;;
                *)
                    log "[ZTP] WARN: Ignored malformed SSH public-key line from ${pub_path}"
                    continue
                    ;;
            esac
            if [[ ${#key_blob} -lt 8 || ! "${key_blob}" =~ ^[A-Za-z0-9+/]+={0,3}$ ]]; then
                log "[ZTP] WARN: Ignored malformed SSH public-key blob from ${pub_path}"
                continue
            fi
            source_usable=$((source_usable + 1))
            usable=$((usable + 1))
            if ! awk -v wanted_type="${key_type}" -v wanted_blob="${key_blob}" '
                {
                    for (field = 1; field < NF; field++) {
                        if ($field == wanted_type && $(field + 1) == wanted_blob) {
                            found = 1
                        }
                    }
                }
                END { exit(found ? 0 : 1) }
            ' "${auth_tmp}"; then
                printf '%s\n' "${key}" >> "${auth_tmp}"
            fi
        done < "${pub_cache}"
        if (( source_usable > 0 )); then
            installed=$((installed + 1))
            log "[ZTP] Prefetched SSH public key installed: ${pub_path}"
        else
            log "[ZTP] WARN: No valid SSH public key in prefetched source: ${pub_path}"
        fi
    done
    if [[ -L "${auth_key}" || ( -e "${auth_key}" && ! -f "${auth_key}" ) ]] ||
       ! chmod 0600 "${auth_tmp}" || ! chown "${owner_group}" "${auth_tmp}" ||
       ! mv -f -- "${auth_tmp}" "${auth_key}" ||
       ! chmod 0700 "${ssh_dir}" || ! chown "${owner_group}" "${ssh_dir}"; then
        rm -f -- "${auth_tmp}" || true
        log "[ZTP] WARN: Could not atomically publish authorized_keys"
        log "[ZTP] ACCESS_NOT_READY: authorized_keys publication failed"
        return 0
    fi
    if (( usable == 0 )); then
        log "[ZTP] WARN: No non-empty prefetched SSH public key was installed"
        log "[ZTP] ACCESS_NOT_READY: no prefetched SSH public key installed"
    else
        log "[ZTP] ACCESS_READY: ${installed} source(s), ${usable} valid SSH public key record(s) installed"
    fi
    return 0
}

# 检查网络可达性, 需提供IP地址作为参数，例如: 1.1.1.1
check_network() {
    local server_ip=${1}
    local -a interface_arg=()

    log "[ZTP] Checking network connectivity to ${server_ip} via vrf=${ZTP_VRF}, interface=${ZTP_INTERFACE:-auto}"

    if [[ -n "${ZTP_INTERFACE}" ]]; then
        interface_arg=(-I "${ZTP_INTERFACE}")
    fi
    if ztp_net_exec ping "${interface_arg[@]}" -c 3 -W 1 "${server_ip}" --no-vrf-switch >/dev/null 2>&1; then
        log "[ZTP] Network check passed: vrf=${ZTP_VRF}, interface=${ZTP_INTERFACE:-auto}"
        return 0
    else
        log "[ZTP] Network check failed: Cannot reach ${server_ip}"
        return 1
    fi
}
#==================== 公共函数定义 ====================



if ! initialize_runtime_workspace; then
    exit 1
fi
trap cleanup_runtime_workspace_on_exit EXIT

if ! initialize_persistent_log; then
    exit 1
fi
log "======================== ZTP START ========================"

if ! select_ztp_network_path; then
    log "[ZTP] ERROR: Cannot determine the DHCP-selected ZTP network path"
    log "======================== ZTP FINISH ========================"
    exit 1
fi

if ! check_network "${ZTP_SERVER##*/}"; then
    log "[ZTP] ERROR: Cannot reach ${ZTP_SERVER}"
    log "======================== ZTP FINISH ========================"
    exit 1
fi

if ! sync_management_clock_for_ztp; then
    log "[ZTP] ERROR: Refusing to continue with an unverified ZTP-stage clock"
    log "======================== ZTP FINISH ========================"
    exit 1
fi
log "[ZTP] Network check passed after management-server time sync: vrf=${ZTP_VRF}, interface=${ZTP_INTERFACE:-auto}"

# The initial DHCP-selected path is authoritative for all HTTP downloads that
# must survive a later dedicated config replacing transit interfaces/routes.
prefetch_ssh_pubkeys

# 根据设备型号不同执行不同的ztp流程
# Product-family variables intentionally contain shell globs
# (SN*/VX*/Q*/N*) across this complete if/elif command.
# shellcheck disable=SC2053
if [[ "${PROD_NAME}" == ${EthSW} || "${PROD_NAME}" == ${EthVX} ]]; then

    USER_NAME="cumulus"
    USER_HOME=/home/${USER_NAME}
    log "[ZTP] Detected Product Name: ${PROD_NAME}"

    # ========== 以太网交换机/VX 局部配置 ==========
    PHY_IMG_NAME="cumulus-linux-${TARGET_CL_VER}-mlx-amd64.bin"
    VX_IMG_NAME="cumulus-linux-${TARGET_CL_VER}-vx-amd64.bin"
    IMG_BASE_URL="${ZTP_SERVER}${ZTP_URL_PREFIX}/image/cumulus"
    PHY_IMG_URL="${IMG_BASE_URL}/${PHY_IMG_NAME}"
    VX_IMG_URL="${IMG_BASE_URL}/${VX_IMG_NAME}"

    CFG_BASE_URL="${ZTP_SERVER}${ZTP_URL_PREFIX}/config/cumulus"
    DEFAULT_VER_CFG="${CFG_BASE_URL}/default_${TARGET_CL_VER}.yaml"
    GLOBAL_BASE_CFG="${CFG_BASE_URL}/default.yaml"
    RELEASE_DEFAULT_VER_CFG="${CFG_BASE_URL}/latest_yaml/default_${TARGET_CL_VER}.yaml"
    RELEASE_GLOBAL_BASE_CFG="${CFG_BASE_URL}/latest_yaml/default.yaml"

    AR_FILE_NAME="ar_profile_custom.conf"
    AR_FILE_PATH="${CFG_BASE_URL}/${AR_FILE_NAME}"
    AR_FILE_LOCAL="/etc/cumulus/switchd.d/ar_profile_custom.conf"
    # ==============================================

    # shellcheck disable=SC2053
    if [[ "${PROD_NAME}" == ${EthVX} ]];then
        log "[ZTP] Cumulus VX Virtual Machine"
        USE_IMG_URL="${VX_IMG_URL}"
    else
        log "[ZTP] Physical Ethernet Switch:${PROD_NAME}"
        USE_IMG_URL="${PHY_IMG_URL}"
    fi

    IMG_VER=$(grep '^IMAGE_RELEASE=' /etc/image-release | awk -F'=' '{print $2}')
    RUN_VER=$(grep '^DISTRIB_RELEASE=' /etc/lsb-release | awk -F'=' '{print $2}')
    log "[ZTP] BaseImg:${IMG_VER}, RunningVer:${RUN_VER}, Target:${TARGET_CL_VER}"

    if [[ "${RUN_VER}" != "${TARGET_CL_VER}" && "${ZTP_UPGRADE_ENABLED}" == "true" ]];then
        log "[ZTP] Version mismatch, install image:${USE_IMG_URL}"
        ztp_net_exec onie-install -fa -i "${USE_IMG_URL}"
        log "[ZTP] Reboot into ONIE installation"
        reboot
    else
        if [[ "${RUN_VER}" != "${TARGET_CL_VER}" ]]; then
            log "[ZTP] Version mismatch, but image upgrade is disabled; continue provisioning current version"
        else
            log "[ZTP] Version matched, continue provisioning"
        fi
        log "[ZTP] Download config by eth0 MAC"
        ETH0_RAW_MAC=$(cat /sys/class/net/eth0/address)
        ETH0_MAC=$(echo "${ETH0_RAW_MAC}" | tr -d ':')
        MAC_CFG="${CFG_BASE_URL}/latest_yaml/${ETH0_MAC}.yaml"
        MAC_MODE="${CFG_BASE_URL}/latest_yaml/${ETH0_MAC}.mode"
        SPX_MARKER="${CFG_BASE_URL}/latest_yaml/${ETH0_MAC}.spx"
        MAC_LOCAL="${TMP_DIR}/${MAC_CFG##*/}"
        MAC_MODE_LOCAL="${TMP_DIR}/${MAC_MODE##*/}"

        RELEASE_VER_DEF_CACHE="${TMP_DIR}/default.release-version.yaml"
        RELEASE_GLOBAL_DEF_CACHE="${TMP_DIR}/default.release-global.yaml"
        LEGACY_VER_DEF_CACHE="${TMP_DIR}/default.legacy-version.yaml"
        LEGACY_GLOBAL_DEF_CACHE="${TMP_DIR}/default.legacy-global.yaml"
        DEDICATED_APPLY_FAILED="false"
        FAILED_DEDICATED_SOURCE=""


        ## 定义加载“版本部分默认配置”或者“全局部分默认配置”函数, 在“设备特定配置”不存在的情况下调用
        ## 其中“版本部分默认配置”是基于某个CL版本的部分默认配置，包含预设置密码，dns, timezone, ntp等，需用nv config patch
        ## “全局部分默认配置”是只有预设置密码的部分默认配置，需要用nv config patch
        load_default_cfg(){
            local selected_url selected_local receipt_source_kind failed_source
            if [[ ! -L "${RELEASE_VER_DEF_CACHE}" && -s "${RELEASE_VER_DEF_CACHE}" ]]; then
                selected_url="${RELEASE_DEFAULT_VER_CFG}"
                selected_local="${RELEASE_VER_DEF_CACHE}"
            elif [[ ! -L "${RELEASE_GLOBAL_DEF_CACHE}" && -s "${RELEASE_GLOBAL_DEF_CACHE}" ]]; then
                selected_url="${RELEASE_GLOBAL_BASE_CFG}"
                selected_local="${RELEASE_GLOBAL_DEF_CACHE}"
            elif [[ ! -L "${LEGACY_VER_DEF_CACHE}" && -s "${LEGACY_VER_DEF_CACHE}" ]]; then
                selected_url="${DEFAULT_VER_CFG}"
                selected_local="${LEGACY_VER_DEF_CACHE}"
            elif [[ ! -L "${LEGACY_GLOBAL_DEF_CACHE}" && -s "${LEGACY_GLOBAL_DEF_CACHE}" ]]; then
                selected_url="${GLOBAL_BASE_CFG}"
                selected_local="${LEGACY_GLOBAL_DEF_CACHE}"
            else
                log "[ZTP] ERROR: No prefetched Cumulus default config is available after dedicated config failure/miss"
                return 1
            fi
            log "[ZTP] Use prefetched default config:${selected_url}, action: patch"
            nv config patch "${selected_local}"
            nv config apply -y
            nv config save
            log "[ZTP] Default config:${selected_local} patch and save complete"
            receipt_source_kind="default"
            failed_source=""
            if [[ "${DEDICATED_APPLY_FAILED}" == "true" ]]; then
                receipt_source_kind="fallback_default"
                failed_source="${FAILED_DEDICATED_SOURCE}"
            fi
            persist_applied_receipt \
                "${selected_local}" "success" "${receipt_source_kind}" "patch" \
                "${selected_url##*/}" "${ETH0_RAW_MAC}" "${failed_source}"
        }

        CUMULUS_DEFAULT_PREFETCHED=0
        if prefetch_config_candidate "${RELEASE_DEFAULT_VER_CFG}" "${RELEASE_VER_DEF_CACHE}" "1-release-version"; then
            CUMULUS_DEFAULT_PREFETCHED=$((CUMULUS_DEFAULT_PREFETCHED + 1))
        fi
        if prefetch_config_candidate "${RELEASE_GLOBAL_BASE_CFG}" "${RELEASE_GLOBAL_DEF_CACHE}" "2-release-global"; then
            CUMULUS_DEFAULT_PREFETCHED=$((CUMULUS_DEFAULT_PREFETCHED + 1))
        fi
        if prefetch_config_candidate "${DEFAULT_VER_CFG}" "${LEGACY_VER_DEF_CACHE}" "3-legacy-version"; then
            CUMULUS_DEFAULT_PREFETCHED=$((CUMULUS_DEFAULT_PREFETCHED + 1))
        fi
        if prefetch_config_candidate "${GLOBAL_BASE_CFG}" "${LEGACY_GLOBAL_DEF_CACHE}" "4-legacy-global"; then
            CUMULUS_DEFAULT_PREFETCHED=$((CUMULUS_DEFAULT_PREFETCHED + 1))
        fi
        if (( CUMULUS_DEFAULT_PREFETCHED == 0 )); then
            log "[ZTP] WARN: No Cumulus default config candidate could be prefetched; dedicated config must apply successfully"
        else
            log "[ZTP] Cumulus default prefetch complete: ${CUMULUS_DEFAULT_PREFETCHED}/4 candidate(s), fixed priority 1..4"
        fi

        ## d-hostname2mac.py 为 CSV type=eth_spx/spx（含对应 AIR 节点）发布 MAC 标记。
        if ztp_curl -sf "${SPX_MARKER}" -o /dev/null; then
            log "[ZTP] SPX marker found for ${ETH0_RAW_MAC}; download AR custom config."
            if ztp_curl -sf  "${AR_FILE_PATH}" -o "${TMP_DIR}/${AR_FILE_NAME}"; then
                cp -f "${TMP_DIR}/${AR_FILE_NAME}" "${AR_FILE_LOCAL}"
                log "[ZTP] AR custom config copied to ${AR_FILE_LOCAL}"
            else
                log "[ZTP] WARN: SPX AR custom config is missing."
            fi
        else
            log "[ZTP] No SPX marker for ${ETH0_RAW_MAC}; skip AR custom config."
        fi

        ## 尝试加载“设备特定配置”，如果不存在或者加载失败，加载默认配置
        if ztp_curl -sf "${MAC_CFG}" -o "${MAC_LOCAL}";then
            APPLY_MODE="replace"
            PROFILE_NAME="full"
            if ztp_curl -sf "${MAC_MODE}" -o "${MAC_MODE_LOCAL}"; then
                APPLY_MODE=$(tr -d '[:space:]' < "${MAC_MODE_LOCAL}")
                case "${APPLY_MODE}" in
                    replace) PROFILE_NAME="full" ;;
                    patch) PROFILE_NAME="baseline" ;;
                    *)
                        log "[ZTP] ERROR: Invalid per-MAC apply mode '${APPLY_MODE}' from ${MAC_MODE}; use default cfg"
                        APPLY_MODE="invalid"
                        ;;
                esac
            else
                log "[ZTP] WARN: Per-MAC mode sidecar missing; use legacy action: replace"
            fi
            log "[ZTP] Load per-MAC config:${MAC_CFG}, profile=${PROFILE_NAME}, action=${APPLY_MODE}"
            if [[ "${APPLY_MODE}" == "invalid" ]] ||
               ! nv config "${APPLY_MODE}" "${MAC_LOCAL}" || ! nv config apply -y;then
                persist_failed_config "${MAC_LOCAL}" "${USER_HOME}" "${USER_NAME}"
                if [[ -n "${FAILED_CFG_PATH}" ]]; then
                    log "[ZTP] WARN: MAC config apply failed; config preserved at ${FAILED_CFG_PATH}; switch to default cfg"
                else
                    log "[ZTP] WARN: MAC config apply failed and could not be preserved; switch to default cfg"
                fi
                DEDICATED_APPLY_FAILED="true"
                FAILED_DEDICATED_SOURCE="${MAC_LOCAL}"
                nv config detach
                load_default_cfg
            else
                nv config save
                if [[ "${APPLY_MODE}" == "patch" ]]; then
                    log "[ZTP] Baseline identity config:${MAC_LOCAL} patch and save complete"
                    persist_applied_receipt \
                        "${MAC_LOCAL}" "success" "dedicated" "patch" \
                        "${MAC_CFG##*/}" "${ETH0_RAW_MAC}"
                else
                    log "[ZTP] Dedicated config:${MAC_LOCAL} apply and save complete"
                    persist_applied_receipt \
                        "${MAC_LOCAL}" "success" "dedicated" "replace" \
                        "${MAC_CFG##*/}" "${ETH0_RAW_MAC}"
                fi
            fi
        else
            log "[ZTP] MAC cfg not found, load default cfg"
            load_default_cfg
        fi


        install_ssh_pubkeys "${USER_HOME}"
        install_manual_ztp_helper
        install_applied_config_helper "${USER_NAME}"
        install_time_sync_helper "${USER_NAME}"

        log "[ZTP] Cumulus provision complete"
        log "======================== ZTP FINISH ========================"

        exit 0
    fi

elif [[ "${PROD_NAME}" == ${IBSW} || "${PROD_NAME}" == ${NVLSW} ]]; then
    USER_NAME="admin"
    USER_HOME=/home/${USER_NAME}
    log "[ZTP] Detected Product Name: ${PROD_NAME}"

    CFG_BASE_URL="${ZTP_SERVER}${ZTP_URL_PREFIX}/config/nvos"

    ETH0_RAW_MAC=$(cat /sys/class/net/eth0/address)
    ETH0_MAC=$(echo "${ETH0_RAW_MAC}" | tr -d ':')

    MAC_CFG="${CFG_BASE_URL}/latest_yaml/${ETH0_MAC}.yaml"
    MAC_LOCAL="${TMP_DIR}/${MAC_CFG##*/}"

    ## “全局部分默认配置”是只有预设置密码，dns, timezone, ntp等配置，需要用nv config patch
    GLOBAL_BASE_CFG="${CFG_BASE_URL}/default.yaml"
    GLOBAL_DEF_CACHE="${TMP_DIR}/default.nvos-global.yaml"

    load_nvos_default_cfg() {
        local receipt_source_kind="$1"
        local failed_source="${2:-}"
        if [[ -L "${GLOBAL_DEF_CACHE}" || ! -s "${GLOBAL_DEF_CACHE}" ]]; then
            log "[ZTP] ERROR: No prefetched NVOS default config is available after dedicated config failure/miss"
            return 1
        fi
        log "[ZTP] Use prefetched NVOS default config:${GLOBAL_BASE_CFG}, action: patch"
        nv config patch "${GLOBAL_DEF_CACHE}"
        nv set system ztp config-save enabled
        nv config apply -y
        nv config save
        log "[ZTP] Default config:${GLOBAL_DEF_CACHE} patch and save complete"
        persist_applied_receipt \
            "${GLOBAL_DEF_CACHE}" "success" "${receipt_source_kind}" "patch" \
            "${GLOBAL_BASE_CFG##*/}" "${ETH0_RAW_MAC}" "${failed_source}"
    }

    if ! prefetch_config_candidate "${GLOBAL_BASE_CFG}" "${GLOBAL_DEF_CACHE}" "1-nvos-global"; then
        log "[ZTP] WARN: NVOS default config could not be prefetched; dedicated config must apply successfully"
    fi

    ## 尝试加载“设备特定配置”，如果不存在或者加载失败，加载默认配置
    if ztp_curl -sf "${MAC_CFG}" -o "${MAC_LOCAL}";then
        log "[ZTP] Load per-MAC config:${MAC_CFG}"
        if ! nv config replace "${MAC_LOCAL}" || ! nv config apply -y;then
            persist_failed_config "${MAC_LOCAL}" "${USER_HOME}" "${USER_NAME}"
            if [[ -n "${FAILED_CFG_PATH}" ]]; then
                log "[ZTP] WARN: MAC config apply failed; config preserved at ${FAILED_CFG_PATH}; switch to default cfg"
            else
                log "[ZTP] WARN: MAC config apply failed and could not be preserved; switch to default cfg"
            fi
            nv config detach
            load_nvos_default_cfg "fallback_default" "${MAC_LOCAL}"
        else
            nv set system ztp config-save enabled
            nv config apply -y
            nv config save
            log "[ZTP] Dedicated config:${MAC_LOCAL} apply and save complete"
            persist_applied_receipt \
                "${MAC_LOCAL}" "success" "dedicated" "replace" \
                "${MAC_CFG##*/}" "${ETH0_RAW_MAC}"
        fi
    else
        log "[ZTP] MAC cfg not found, load default cfg"
        load_nvos_default_cfg "default"
    fi


    install_ssh_pubkeys "${USER_HOME}"
    install_applied_config_helper "${USER_NAME}"
    install_time_sync_helper "${USER_NAME}"

    log "[ZTP] NVOS provision complete"
    log "======================== ZTP FINISH ========================"

    exit 0
else
    USER_NAME="root"
    USER_HOME=/${USER_NAME}
    log "[ZTP] Detected Product Name: ${PROD_NAME}"

    install_ssh_pubkeys "${USER_HOME}"

    log "[ZTP] Unknown model:${PROD_NAME}, only install ssh public key and exit ZTP."
    log "======================== ZTP FINISH ========================"

    exit 0
fi

exit 0
