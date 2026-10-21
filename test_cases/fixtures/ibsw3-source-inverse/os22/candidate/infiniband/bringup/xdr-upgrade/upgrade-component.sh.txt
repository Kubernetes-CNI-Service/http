# Fixed IB NVOS component sections, composed by ibsw_upgrade_component.py.
# Not a standalone upgrade entry; no SSH/identity/activation permission here.
set -euo pipefail
: "${IBSW_RUN_ID:?bound plan required}"
: "${IBSW_METHOD:?bound transport required}"
: "${IBSW_PACKAGE_FILE:?bound package required}"
: "${IBSW_SWITCH_DIR:?bound switch directory required}"
: "${IBSW_LOCAL_PACKAGE:?bound local package required}"
: "${IBSW_BINDING_JSON:?bound node/run/step required}"

temporary=""
install_requested=false
ibsw_scp_context=""
ibsw_scp_context_read=false
IBSW_OS_DOWNLOAD_TIMEOUT=600
IBSW_FIRMWARE_DOWNLOAD_TIMEOUT=300
finish_step() {
    rc=$?
    unset ibsw_scp_context
    if [[ -n "$temporary" ]]; then
        rm -f -- "$temporary"
    fi
    # Neither a return code nor this marker proves the switch booted correctly.
    printf '%s\n' "IBSW_EXECUTION_RC=$rc IBSW_ACTIVATION_STATE=UNKNOWN"
    if $install_requested; then
        printf '%s\n' "IBSW_EXPECTED_EFFECT=$IBSW_EXPECTED_EFFECT"
    fi
    exit "$rc"
}
trap finish_step EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' "$IBSW_BINDING_JSON"
[[ -d "$IBSW_SWITCH_DIR" && ! -L "$IBSW_SWITCH_DIR" ]] || exit 65
read_scp_context() {
    $ibsw_scp_context_read && return
    local deadline=$((SECONDS+10)) remaining extra="" rc=0
    remaining=$((deadline-SECONDS))
    (( remaining > 0 )) || exit 65
    IFS= read -r -n 65537 -t "$remaining" ibsw_scp_context || exit 64
    [[ -n "$ibsw_scp_context" && ${#ibsw_scp_context} -le 65535 ]] || exit 64
    export -n ibsw_scp_context
    remaining=$((deadline-SECONDS))
    (( remaining > 0 )) || exit 65
    IFS= read -r -n 1 -t "$remaining" extra || rc=$?
    [[ "$rc" == 1 ]] || exit 65
    exec 0</dev/null
    ibsw_scp_context_read=true
}
prepare_package() {
    local IBSW_LOCAL_PACKAGE="$1" IBSW_PACKAGE_URL="$2" scp_source="${3:-}"
    printf '%s\n' 'IBSW_STAGE=PACKAGE_DOWNLOAD'
    [[ ! -L "$IBSW_LOCAL_PACKAGE" ]] || exit 65
    case "$IBSW_METHOD" in
    http)
        : "${IBSW_PACKAGE_URL:?project HTTP URL required}"
        temporary=$(mktemp "$IBSW_SWITCH_DIR/.ibsw-$IBSW_RUN_ID-XXXXXX")
        # Do not follow a redirect to an unapproved origin/protocol. Full-body
        # HTTP 200/nonempty is not a checksum or source-authenticity guarantee.
        local timeout=$IBSW_FIRMWARE_DOWNLOAD_TIMEOUT
        [[ "$IBSW_COMPONENT" != os ]] || timeout=$IBSW_OS_DOWNLOAD_TIMEOUT
        local attempt result rc started finished http_code bytes seconds speed line
        for attempt in 1 2 3 4; do
            started=$(date -u +%s)
            printf '%s\n' "IBSW_DOWNLOAD_ATTEMPT=$attempt"
            # Manual bounded retries preserve EVERY attempt's measurements;
            # never retry nv install, redirects, HTTP 404 or unknown failures.
            rc=0
            result=$(curl -q -fS --proto "=http" --connect-timeout 10 --max-time "$timeout" \
                -w '%{http_code}|%{size_download}|%{time_total}|%{speed_download}' \
                -o "$temporary" "$IBSW_PACKAGE_URL") || rc=$?
            finished=$(date -u +%s)
            IFS='|' read -r http_code bytes seconds speed <<< "$result"
            [[ "$http_code" =~ ^[0-9]{3}$ && "$bytes" =~ ^[0-9]+$ &&
                "$seconds" =~ ^[0-9]+([.][0-9]+)?$ && "$speed" =~ ^[0-9]+([.][0-9]+)?$ ]] || exit 66
            line="IBSW_DOWNLOAD_RESULT=$attempt|$started|$finished|$rc|$http_code|$bytes|$seconds|$speed"
            printf '%s\n' "$line"
            if [[ "$rc" == 0 && "$http_code" == 200 && -s "$temporary" ]]; then break; fi
            if [[ "$attempt" == 4 ]]; then
                [[ "$rc" != 0 ]] && exit "$rc" || exit 66
            fi
            case "$rc:$http_code" in
                5:*|6:*|7:*|18:*|28:*|52:*|56:*|22:408|22:429|22:500|22:502|22:503|22:504) sleep 5 ;;
                *) [[ "$rc" != 0 ]] && exit "$rc" || exit 66 ;;
            esac
        done
        [[ "$http_code" == "200" && -s "$temporary" ]] || exit 66
        if [[ "$IBSW_COMPONENT" == os ]]; then
            # OS reboot can erase /home/admin. Do not start installation until
            # the manager has durably committed these exact numeric records.
            printf '%s\n' 'IBSW_STAGE=WAIT_DOWNLOAD_RECORD'
            local ack_path="${BASH_SOURCE[0]%/*}/download-ack"
            local expected="IBSW_DOWNLOAD_ACK_V1|$IBSW_RUN_ID|$line" ack="" waited=0
            while :; do
                if [[ -f "$ack_path" && ! -L "$ack_path" ]]; then
                    IFS= read -r ack < "$ack_path" || exit 66
                    [[ "$ack" == "$expected" ]] || exit 66
                    break
                fi
                (( waited < 300 )) || exit 75
                sleep 1
                waited=$((waited+1))
            done
        fi
        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"
        temporary=""
        ;;
    scp)
        # SCP OS waits for its exact content-bound manager V2 ACK below.
        : "${scp_source:?bound source path required}"
        : "${IBSW_SCP_HELPER_B64:?fixed stdin-only helper required}"
        read_scp_context
        temporary=$(mktemp "$IBSW_SWITCH_DIR/.ibsw-$IBSW_RUN_ID-XXXXXX")
        local result rc=0 rest candidate content="" measurement=""
        result=$(builtin printf '%s\n' "$ibsw_scp_context" | /usr/bin/python3 -c \
            'import base64,sys;exec(base64.b64decode(sys.argv.pop(1)))' \
            "$IBSW_SCP_HELPER_B64" fetch "$scp_source" "$temporary" 2>/dev/null) || rc=$?
        if [[ "$rc" != 0 ]]; then
            printf '%s\n' 'IBSW_SCP_ERROR=TRANSFER_FAILED'
            exit "$rc"
        fi
        [[ -n "$result" && ${#result} -le 4096 ]] || exit 66
        rest="$result"
        while [[ -n "$rest" ]]; do
            if [[ "$rest" == *$'\n'* ]]; then
                candidate="${rest%%$'\n'*}"
                rest="${rest#*$'\n'}"
            else
                candidate="$rest"
                rest=""
            fi
            if [[ "$candidate" =~ ^IBSW_SCP_CONTENT_VERIFIED=1\|[0-9a-f]{64}\|[A-Za-z0-9_-]+\|[1-9][0-9]*\|[0-9a-f]{64}$ ]]; then
                [[ -z "$content" ]] || exit 66
                content="$candidate"
            elif [[ "$candidate" =~ ^IBSW_SCP_DOWNLOAD_RESULT=1\|[0-9]+\|[0-9]+\|0\|0\|[1-9][0-9]*\|[0-9]+([.][0-9]+)?\|[0-9]+([.][0-9]+)?$ ]]; then
                [[ -z "$measurement" ]] || exit 66
                measurement="$candidate"
            else
                exit 66 # No arbitrary helper stdout/stderr reflection.
            fi
        done
        [[ -n "$content" && -n "$measurement" && -s "$temporary" ]] || exit 66
        printf '%s\n' "$content" "$measurement"
        if [[ "$IBSW_COMPONENT" == os ]]; then
            # Public content DATA alone cannot release installation. The real
            # manager must finish its original reliable record before V2 ACK.
            printf '%s\n' 'IBSW_STAGE=WAIT_DOWNLOAD_RECORD'
            local content_digest
            content_digest=$(/usr/bin/python3 -c 'import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode("ascii")).hexdigest())' "$content") || exit 66
            local ack_path="${BASH_SOURCE[0]%/*}/download-ack"
            local expected="IBSW_SCP_DOWNLOAD_ACK_V2|$IBSW_RUN_ID|$content_digest|$measurement" ack="" waited=0
            while :; do
                if [[ -f "$ack_path" && ! -L "$ack_path" ]]; then
                    IFS= read -r ack < "$ack_path" || exit 66
                    [[ "$ack" == "$expected" ]] || exit 66
                    break
                fi
                (( waited < 300 )) || exit 75
                sleep 1
                waited=$((waited+1))
            done
        fi
        mv -- "$temporary" "$IBSW_LOCAL_PACKAGE"
        temporary=""
        ;;
    local) ;;
    *) exit 64 ;;
    esac
    [[ -f "$IBSW_LOCAL_PACKAGE" && -s "$IBSW_LOCAL_PACKAGE" && ! -L "$IBSW_LOCAL_PACKAGE" ]] || exit 66
    printf '%s\n' 'IBSW_STAGE=PACKAGE_READY'
}

# IBSW_BODY_OS
prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"
# NVOS IB published FILE fetch, then default-reboot install. The latter can
# disconnect SSH before any final marker returns; do not resend it on timeout.
printf '%s\n' 'IBSW_STAGE=IMAGE_FETCH'
nv action fetch system image "file://${IBSW_LOCAL_PACKAGE}"
install_requested=true
printf '%s\n' 'IBSW_STAGE=INSTALL_REQUESTED'
nv action install system image files "$IBSW_PACKAGE_FILE" force

# IBSW_BODY_BIOS
prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"
printf '%s\n' 'IBSW_STAGE=BIOS_FETCH'
nv action fetch platform firmware BIOS "file://${IBSW_LOCAL_PACKAGE}"
install_requested=true
printf '%s\n' 'IBSW_STAGE=INSTALL_REQUESTED'
nv action install platform firmware BIOS files "$IBSW_PACKAGE_FILE" force skip-version-check

# IBSW_BODY_CPLD
: "${IBSW_REFRESH_FILE:?bound REFRESH package required}"
: "${IBSW_REFRESH_LOCAL:?bound REFRESH path required}"
# Validate/prepare both files before any firmware write is attempted.
prepare_package "$IBSW_LOCAL_PACKAGE" "$IBSW_PACKAGE_URL" "${IBSW_SCP_PACKAGE_PATH:-}"
prepare_package "$IBSW_REFRESH_LOCAL" "$IBSW_REFRESH_URL" "${IBSW_SCP_REFRESH_PATH:-}"
nv action fetch platform firmware CPLD1 "file://${IBSW_LOCAL_PACKAGE}"
printf '%s\n' 'IBSW_COMPONENT_STAGE=BURN_REQUESTED'
printf '%s\n' 'IBSW_STAGE=CPLD_BURN'
nv action install platform firmware CPLD1 files "$IBSW_PACKAGE_FILE" force skip-reboot skip-version-check
nv action fetch platform firmware CPLD1 "file://${IBSW_REFRESH_LOCAL}"
install_requested=true
printf '%s\n' 'IBSW_COMPONENT_STAGE=REFRESH_REQUESTED'
printf '%s\n' 'IBSW_STAGE=CPLD_REFRESH'
nv action install platform firmware CPLD1 files "$IBSW_REFRESH_FILE" force skip-version-check
