# Only the original direct child shell is observed, never an installer job.
set +e
set -u -o pipefail
umask 077
[[ -f "$IBSW_ORIGINAL_STEP" && ! -L "$IBSW_ORIGINAL_STEP" ]] || exit 65
[[ ! -e "$IBSW_EXIT_RECORD" && ! -L "$IBSW_EXIT_RECORD" ]] || exit 65
/bin/bash "$IBSW_ORIGINAL_STEP"
ibsw_child_rc=$?
set -o noclobber
printf 'IBSW_OWNED_EXIT_V1\n%s\n%s\n%s\n%s\n%s\n%d\n' "$IBSW_RUN_ID" "$IBSW_NODE" "$IBSW_COMPONENT" "$IBSW_STAGE" "$IBSW_SCRIPT_SHA256" "$ibsw_child_rc" > "$IBSW_EXIT_RECORD"
# Missing/partial write is UNKNOWN. No atomic/fsync/power-loss promise here.
exit "$ibsw_child_rc"
