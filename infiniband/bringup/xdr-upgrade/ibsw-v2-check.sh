# Generic read-only fact collector for the v2 IB switch upgrade (owner 2026-10-23).
# Not a standalone entry: tools/ibsw_v2_device.py sends it over SSH stdin
# (`bash -s -- <mode> ...`), so nothing is left on the switch. It never writes the
# switch and never decides anything; every item is printed as
#   IBSW_ITEM <name> <rc> <base64 stdout> <base64 stderr>
# and the manager judges. The whole body is one brace group, so bash has parsed all
# of it before any command can read stdin.
{
set -u
ROOT="${IBSW_SYSROOT:-}"
LIMIT=25

b64() { base64 -w0 2>/dev/null || base64; }

item() {
    # item NAME SECONDS COMMAND...: run with stdin closed and a time limit.
    local name="$1" seconds="$2" out err rc
    shift 2
    out=$(mktemp) && err=$(mktemp) || { printf 'IBSW_ITEM %s 125 - -\n' "$name"; return; }
    # Through a child bash so the exported helper functions below run under timeout too.
    timeout "$seconds" /bin/bash -c '"$@"' ibsw-item "$@" >"$out" 2>"$err" </dev/null
    rc=$?
    printf 'IBSW_ITEM %s %d %s %s\n' "$name" "$rc" "$(b64 <"$out")" "$(b64 <"$err")"
    rm -f -- "$out" "$err"
}

identity() { hostname && cat "$ROOT/sys/class/net/eth0/address"; }
boot_id() { cat "$ROOT/proc/sys/kernel/random/boot_id"; }
uptime_seconds() { cut -d' ' -f1 "$ROOT/proc/uptime"; }
now_seconds() { date +%s; }
account() { id -u && getent passwd "$(id -u)"; }
nvued() { systemctl show nvued.service --property=ActiveState --property=SubState --no-pager; }
capability() {
    local missing=""
    for program in /bin/bash /usr/bin/nohup /usr/bin/setsid /usr/bin/python3 /usr/bin/scp /usr/bin/ssh \
                   /usr/bin/curl /usr/bin/sha256sum /usr/bin/timeout; do
        [[ -x "$ROOT$program" ]] || missing="$missing $program"
    done
    [[ -z "$missing" ]] || { printf 'missing:%s\n' "$missing"; return 1; }
}
free_kib() { df -Pk "$1" | awk 'NR==2 {print $4}'; }

staged() {
    # staged DIR NAME...: size and sha256 of each regular file named NAME in DIR.
    local dir="$1" name path
    shift
    for name in "$@"; do
        path="$dir/$name"
        if [[ -f "$path" && ! -L "$path" ]]; then
            printf '%s %s %s\n' "$name" "$(stat -c %s -- "$path")" "$(sha256sum -- "$path" | cut -d' ' -f1)"
        else
            printf '%s - -\n' "$name"
        fi
    done
}

runs() {
    # Every upgrade step directory (v1 or v2) under DIR: name, boot_id at launch or -,
    # stdout mtime, process alive (1/0), post-install marker seen (1/0), exit code or -.
    local dir="$1" step stdout launch boot alive marker code
    for step in "$dir"/.ibsw-*/; do
        step="${step%/}"
        [[ -d "$step" && ! -L "$step" ]] || continue
        [[ -f "$step/runner.sh" || -f "$step/step.sh" ]] || continue
        stdout="$step/execution.stdout"
        boot=-
        launch="$step/launch.record"
        [[ -f "$launch" ]] && boot=$(cut -d' ' -f1 "$launch")
        alive=0
        if pgrep -f -- "$step/(runner|step)\.sh" >/dev/null 2>&1; then alive=1; fi
        marker=0
        if [[ -f "$stdout" ]] && grep -Eq '^(IBSW_STAGE=(INSTALL_REQUESTED|CPLD_BURN|CPLD_REFRESH)|IBSW_COMPONENT_STAGE=|IBSW_EXPECTED_EFFECT=)' "$stdout"; then
            marker=1
        fi
        code=-
        [[ -f "$step/owned-exit.record" ]] && code=$(tail -n 1 "$step/owned-exit.record")
        printf '%s %s %s %s %s %s\n' "${step##*/}" "$boot" "$( [[ -f "$stdout" ]] && stat -c %Y -- "$stdout" || echo -)" \
            "$alive" "$marker" "$code"
    done
}

step_state() {
    # step_state STEPDIR: the step's IBSW markers, exit record and launch record.
    local step="$1"
    [[ -d "$step" && ! -L "$step" ]] || { echo missing; return 1; }
    printf 'header '; head -n 1 "$step/execution.stdout" 2>/dev/null || echo
    printf 'launch '; cat "$step/launch.record" 2>/dev/null || echo -
    printf 'exit '; tr '\n' ' ' <"$step/owned-exit.record" 2>/dev/null; echo
    grep -E '^(IBSW_STAGE=|IBSW_COMPONENT_STAGE=|IBSW_EXECUTION_RC=|IBSW_EXPECTED_EFFECT=)' "$step/execution.stdout" 2>/dev/null | tail -n 50
}

export ROOT
export -f identity boot_id uptime_seconds now_seconds account nvued capability free_kib staged runs step_state

main() {
    local mode="${1:-}"
    shift || true
    printf 'IBSW_CHECK_BEGIN %s\n' "$mode"
    case "$mode" in
    precheck)
        local dir="$1"
        shift
        item identity "$LIMIT" identity
        item boot_id "$LIMIT" boot_id
        item uptime "$LIMIT" uptime_seconds
        item now "$LIMIT" now_seconds
        item account "$LIMIT" account
        item version "$LIMIT" nv show system version
        item firmware "$LIMIT" nv show platform firmware
        item health "$LIMIT" nv show system health
        item config_show "$LIMIT" nv config show -o commands
        item config_diff "$LIMIT" nv config diff -o commands
        item capability "$LIMIT" capability
        item free_kib "$LIMIT" free_kib "$dir"
        item runs "$LIMIT" runs "$dir"
        item staged 300 staged "$dir" "$@"
        ;;
    dispatch)
        # Same facts the installer depends on, right before launch (review 15.3/15.13).
        local dir="$1"
        shift
        item identity "$LIMIT" identity
        item boot_id "$LIMIT" boot_id
        item uptime "$LIMIT" uptime_seconds
        item now "$LIMIT" now_seconds
        item version "$LIMIT" nv show system version
        item firmware "$LIMIT" nv show platform firmware
        item health "$LIMIT" nv show system health
        item config_show "$LIMIT" nv config show -o commands
        item config_diff "$LIMIT" nv config diff -o commands
        item runs "$LIMIT" runs "$dir"
        item staged 120 staged "$dir" "$@"
        ;;
    status)
        item boot_id "$LIMIT" boot_id
        item step "$LIMIT" step_state "$1"
        ;;
    ladder)
        item boot_id "$LIMIT" boot_id
        item nvued "$LIMIT" nvued
        item version "$LIMIT" nv show system version
        ;;
    verify)
        item identity "$LIMIT" identity
        item boot_id "$LIMIT" boot_id
        item version "$LIMIT" nv show system version
        item firmware "$LIMIT" nv show platform firmware
        item health "$LIMIT" nv show system health
        item config_show "$LIMIT" nv config show -o commands
        item config_diff "$LIMIT" nv config diff -o commands
        ;;
    *)
        printf 'IBSW_CHECK_END unknown-mode\n'
        return 64
        ;;
    esac
    printf 'IBSW_CHECK_END ok\n'
}

main "$@" </dev/null
exit $?
}
