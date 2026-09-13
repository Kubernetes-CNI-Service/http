#!/bin/bash

set -euo pipefail

non_interactive=false
teardown_confirmed=false
prompt_timeout=15

usage() {
  cat <<'EOF'
Usage: infra-teardown.sh [options]
  --non-interactive  Do not prompt; requires --yes
  --yes              Confirm the overall teardown operation
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) non_interactive=true ;;
    --yes) teardown_confirmed=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

source_dir=$(dirname -- "${BASH_SOURCE[0]}")
if [[ "$(basename -- "$source_dir")" == "current" ]]; then
  runtime_dir=$(cd -- "$source_dir/.." && pwd)
else
  runtime_dir=$(cd -- "$source_dir" && pwd)
fi
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: infra-teardown.sh must be run as root." >&2
  exit 1
fi
lock_file="/run/lock/http-infra.lock"
mkdir -p "$(dirname "$lock_file")"
exec 9>"$lock_file"
flock -x 9

log_dir="${runtime_dir}/logs"
mkdir -p "$log_dir"
log_file="${log_dir}/infra-teardown-$(date +%Y%m%d_%H%M%S)-$$.log"
exec 3>>"$log_file"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] infra-teardown.sh started" >&3

state_dir="/var/lib/http-infra"
state_file="${state_dir}/installed-packages"
managed_files_file="${state_dir}/managed-files"
timezone_state_file="${state_dir}/original-timezone"
timesyncd_unit_state_file="${state_dir}/original-timesyncd-unit-state"
run_info_file="${state_dir}/run-info"
public_status_file="${runtime_dir}/infra-status"
apt_lock_timeout=600
apache_public_boundary_conf="/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"
apache_listener_conf="/etc/apache2/conf-enabled/http-ztp-listeners.conf"
apache_ports_conf="/etc/apache2/ports.conf"
apache_default_site_state="${state_dir}/apache-default-site-enabled"
apache_public_boundary_sha256="616629333ac16e4bc0c076a499d98864959372b5a24bee3c0d4257c1aa9d15fb"
control_auth_helper="/usr/local/lib/http-ztp/control-auth.py"
control_auth_helper_sha256="5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
control_auth_file="/etc/http-ztp/control-users.htpasswd"
apache_boundary_snapshot=""

teardown_status=started
write_public_status() {
  local exit_code="$1" tmp remaining_packages=0
  if [[ -f "$state_file" ]]; then
    remaining_packages=$(awk 'NF { count++ } END { print count+0 }' "$state_file")
  fi
  tmp=$(mktemp "${runtime_dir}/.infra-status.XXXXXX")
  {
    printf 'schema_version=1\n'
    printf 'hostname=%s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf 'last_action=teardown\n'
    printf 'status=%s\n' "$teardown_status"
    printf 'exit_code=%s\n' "$exit_code"
    printf 'updated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'log_file=%s\n' "$log_file"
    printf 'recorded_packages=%s\n' "$remaining_packages"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$public_status_file"
}

on_teardown_exit() {
  local exit_code=$?
  trap - EXIT
  [[ -z "$apache_boundary_snapshot" ]] || rm -f -- "$apache_boundary_snapshot"
  if [[ $exit_code -ne 0 ]]; then teardown_status=failed; fi
  write_public_status "$exit_code" || true
  exit "$exit_code"
}
write_public_status 0
trap on_teardown_exit EXIT

installed_by_setup() {
  [[ -f "$state_file" ]] && awk -F '\t' -v pkg="$1" '$1 == pkg { found=1 } END { exit !found }' "$state_file"
}

forget_package() {
  local pkg="$1" tmp
  [[ -f "$state_file" ]] || return 0
  tmp=$(mktemp "${state_file}.tmp.XXXXXX")
  awk -F '\t' -v pkg="$pkg" '$1 != pkg' "$state_file" > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$state_file"
}

# ─── Helpers ──────────────────────────────────────────────────────────────────
info()    { echo "[INFO]  $*";  echo "[INFO]  $*"  >&3; }
warn()    { echo "[WARN]  $*";  echo "[WARN]  $*"  >&3; }
success() { echo "[OK]    $*";  echo "[OK]    $*"  >&3; }
error()   { echo "[ERROR] $*" >&2; echo "[ERROR] $*" >&3; }

logecho() { echo "$*"; echo "$*" >&3; }

systemd_is_operational() {
  command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]
}

protected_monitor_content_present() {
  local target
  for target in \
    /var/www/html/monitor/monitor.html \
    /usr/lib/cgi-bin/ztp-monitor-control \
    /usr/lib/cgi-bin/switch-collection-control \
    /usr/lib/cgi-bin/manual-ztp-control; do
    if [[ -e "$target" || -L "$target" ]]; then
      return 0
    fi
  done
  return 1
}

stop_apache_for_auth_failure() {
  if systemd_is_operational; then
    systemctl stop apache2 || true
  fi
}

monitor_authority_result_directory() {
  printf '%s\n' /run
}

terminate_monitor_authority_capture_holders() {
  local holder_file=$1 stdout_pipe=$2 stderr_pipe=$3
  local stdout_reader=$4 stderr_reader=$5 report_file=$6
  local pass descriptor holder_pid pass_file="${report_file}.pass"
  [[ -d /proc/self/fd ]] || return 0
  for pass in 1 2 3 4 5 6 7 8; do
    rm -f -- "$pass_file"
    for descriptor in /proc/[0-9]*/fd/[0-9]*; do
      [[ -e "$descriptor" ]] || continue
      if [[ "$descriptor" -ef "$holder_file" || \
            "$descriptor" -ef "$stdout_pipe" || \
            "$descriptor" -ef "$stderr_pipe" ]]; then
        holder_pid=${descriptor#/proc/}
        holder_pid=${holder_pid%%/*}
        case "$holder_pid" in
          ''|*[!0-9]*) continue ;;
        esac
        if [[ "$holder_pid" != "$stdout_reader" && \
              "$holder_pid" != "$stderr_reader" ]]; then
          : >"$report_file"
          : >"$pass_file"
          kill -KILL "$holder_pid" 2>/dev/null || true
        fi
      fi
    done
    [[ -e "$pass_file" ]] || break
  done
  rm -f -- "$pass_file"
  [[ ! -e "$report_file" ]]
}

capture_monitor_authority_decision() {
  local result_parent result_dir stdout_file stderr_file stdout_pipe stderr_pipe
  local holder_file residual_file cleanup_file
  local command_rc=125 token stdout_reader stderr_reader command_pid
  local command_uses_timeout=false
  monitor_authority_decision=""
  IFS= read -r result_parent < <(monitor_authority_result_directory) || return 1
  IFS= read -r result_dir < <(
    mktemp -d "${result_parent%/}/http-ztp-monitor-decision.XXXXXX"
  ) || return 1
  stdout_file="$result_dir/stdout"
  stderr_file="$result_dir/stderr"
  stdout_pipe="$result_dir/stdout.pipe"
  stderr_pipe="$result_dir/stderr.pipe"
  holder_file="$result_dir/holder"
  residual_file="$result_dir/residual-holder"
  cleanup_file="$result_dir/cleanup-holder"
  if ! mkfifo -- "$stdout_pipe" "$stderr_pipe"; then
    rm -rf -- "$result_dir"
    return 1
  fi
  : >"$holder_file"
  /usr/bin/timeout --signal=KILL 11 \
    head -c 4097 <"$stdout_pipe" >"$stdout_file" &
  stdout_reader=$!
  /usr/bin/timeout --signal=KILL 11 \
    head -c 4097 <"$stderr_pipe" >"$stderr_file" &
  stderr_reader=$!
  if command -v /usr/bin/timeout >/dev/null 2>&1; then
    command_uses_timeout=true
  fi
  (
    exec 8<"$holder_file"
    if [[ "$command_uses_timeout" == true ]]; then
      exec /usr/bin/timeout --signal=KILL 11 \
        "$@" >"$stdout_pipe" 2>"$stderr_pipe"
    else
      : >"$stdout_pipe"
      : >"$stderr_pipe"
      exit 124
    fi
  ) &
  command_pid=$!
  if wait "$command_pid" 2>/dev/null; then
    command_rc=0
  else
    command_rc=$?
  fi
  if [[ "$command_uses_timeout" == true ]] && \
      kill -KILL -- "-$command_pid" 2>/dev/null; then
    : >"$residual_file"
    command_rc=125
  fi
  if ! terminate_monitor_authority_capture_holders \
      "$holder_file" "$stdout_pipe" "$stderr_pipe" \
      "$stdout_reader" "$stderr_reader" "$residual_file"; then
    command_rc=125
  fi
  if ! wait "$stdout_reader" 2>/dev/null; then
    command_rc=125
  fi
  if ! wait "$stderr_reader" 2>/dev/null; then
    command_rc=125
  fi
  if ! terminate_monitor_authority_capture_holders \
      "$holder_file" "$stdout_pipe" "$stderr_pipe" 0 0 "$cleanup_file"; then
    command_rc=125
  fi
  if [[ "$command_rc" == 0 && ! -s "$stderr_file" ]]; then
    for token in \
      "attest-valid" \
      "recovery-in-progress" \
      "recovery-committed-cleanup-pending" \
      "restart-allowed:complete;reset-invalid-cache=false" \
      "restart-allowed:complete;reset-invalid-cache=true" \
      "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false" \
      "restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=true" \
      "restart-blocked:marker-retained;reset-invalid-cache=false" \
      "restart-blocked:marker-retained;reset-invalid-cache=true" \
      "restart-blocked:marker-authority-uncertain;reset-invalid-cache=false" \
      "restart-blocked:marker-authority-uncertain;reset-invalid-cache=true"
    do
      if cmp -s "$stdout_file" <(printf '%s' "$token"); then
        monitor_authority_decision=$token
        break
      fi
    done
  fi
  if ! rm -f -- "$stdout_file" "$stderr_file" "$stdout_pipe" "$stderr_pipe" \
      "$holder_file" "$residual_file" "$cleanup_file" ||
      ! rmdir -- "$result_dir"; then
    monitor_authority_decision=""
    return 1
  fi
  [[ -n "$monitor_authority_decision" ]]
}

preserve_apache_control_boundary() {
  local boundary_actual helper_actual content_state="absent"
  protected_monitor_content_present && content_state="present"
  if [[ ! -f "$apache_public_boundary_conf" || -L "$apache_public_boundary_conf" || \
        "$(stat -c '%h' "$apache_public_boundary_conf" 2>/dev/null || true)" != "1" ]]; then
    stop_apache_for_auth_failure
    error "Authenticated Apache boundary V2 is missing/unsafe while protected Monitor content is ${content_state}."
    error "Teardown stopped Apache; rerun current infra-setup.sh --mgmt --install-apache before retrying."
    return 1
  fi
  boundary_actual=$(sha256sum "$apache_public_boundary_conf" | awk '{print $1}')
  if [[ "$boundary_actual" != "$apache_public_boundary_sha256" ]]; then
    stop_apache_for_auth_failure
    error "Authenticated Apache boundary V2 hash mismatch; Apache remains stopped."
    return 1
  fi
  if [[ ! -f "$control_auth_helper" || -L "$control_auth_helper" || \
        "$(stat -c '%h' "$control_auth_helper" 2>/dev/null || true)" != "1" ]]; then
    stop_apache_for_auth_failure
    error "Native Monitor control auth helper is missing/unsafe; Apache remains stopped."
    return 1
  fi
  helper_actual=$(sha256sum "$control_auth_helper" | awk '{print $1}')
  if [[ "$helper_actual" != "$control_auth_helper_sha256" ]]; then
    stop_apache_for_auth_failure
    error "Native Monitor control auth helper hash mismatch; Apache remains stopped."
    return 1
  fi
  if ! capture_monitor_authority_decision \
      "$control_auth_helper" monitor-authority-attest-decision; then
    stop_apache_for_auth_failure
    error "Persistent Monitor cache authority is invalid; Apache remains stopped."
    return 1
  fi
  case "$monitor_authority_decision" in
    'attest-valid')
      ;;
    'recovery-in-progress')
      stop_apache_for_auth_failure
      error "classification=recovery-in-progress; Monitor authority recovery has not been committed; Apache remains stopped. Run exactly: sudo ./infra/infra-setup.sh --recover-monitor-authority"
      return 1
      ;;
    'recovery-committed-cleanup-pending')
      stop_apache_for_auth_failure
      error "classification=recovery-committed-cleanup-pending; previous Monitor authority recovery COMPLETED and the repaired authority itself is not in question; Apache remains stopped. Re-run exactly to reattest and finish marker cleanup: sudo ./infra/infra-setup.sh --recover-monitor-authority"
      return 1
      ;;
    *)
      stop_apache_for_auth_failure
      error "Persistent Monitor cache authority is invalid; Apache remains stopped."
      return 1
      ;;
  esac
  if ! "$control_auth_helper" validate; then
    stop_apache_for_auth_failure
    error "Persistent Monitor credential state is invalid at $control_auth_file; Apache remains stopped."
    return 1
  fi
  if [[ -z "$apache_boundary_snapshot" ]]; then
    apache_boundary_snapshot=$(mktemp /tmp/http-ztp-apache-boundary.XXXXXX)
    install -m 0600 -o root -g root -- \
      "$apache_public_boundary_conf" "$apache_boundary_snapshot"
  fi
  success "Preserving authenticated Apache boundary V2 and persistent Monitor credentials."
}

restore_preserved_apache_boundary() {
  local actual candidate
  if [[ -f "$apache_public_boundary_conf" && ! -L "$apache_public_boundary_conf" ]]; then
    actual=$(sha256sum "$apache_public_boundary_conf" | awk '{print $1}')
    if [[ "$actual" == "$apache_public_boundary_sha256" ]]; then
      return 0
    fi
    stop_apache_for_auth_failure
    error "Authenticated Apache boundary changed during teardown; Apache remains stopped."
    return 1
  fi
  if [[ -e "$apache_public_boundary_conf" || -L "$apache_public_boundary_conf" ]]; then
    stop_apache_for_auth_failure
    error "Authenticated Apache boundary target became a non-regular object; Apache remains stopped."
    return 1
  fi
  if [[ -L /etc/apache2 || -L /etc/apache2/conf-enabled ]]; then
    stop_apache_for_auth_failure
    error "Cannot safely restore authenticated Apache boundary through a symbolic-link directory."
    return 1
  fi
  install -d -m 0755 -o root -g root -- /etc/apache2/conf-enabled
  candidate=$(mktemp "${apache_public_boundary_conf}.tmp.XXXXXX")
  install -m 0644 -o root -g root -- "$apache_boundary_snapshot" "$candidate"
  actual=$(sha256sum "$candidate" | awk '{print $1}')
  if [[ "$actual" != "$apache_public_boundary_sha256" ]]; then
    rm -f -- "$candidate"
    stop_apache_for_auth_failure
    error "Preserved authenticated Apache boundary failed hash validation."
    return 1
  fi
  mv -f -- "$candidate" "$apache_public_boundary_conf"
  success "Restored the exact persistent authenticated Apache boundary V2."
}

apply_timezone() {
  local zone="$1"
  if [[ ! -f "/usr/share/zoneinfo/$zone" ]]; then
    error "Cannot restore unknown timezone: $zone"
    return 1
  fi
  if command -v timedatectl &>/dev/null && systemd_is_operational; then
    timedatectl set-timezone "$zone"
  else
    ln -snf "/usr/share/zoneinfo/$zone" /etc/localtime
    printf '%s\n' "$zone" > /etc/timezone
    warn "systemd/timedatectl is unavailable; timezone was restored through /etc/localtime and /etc/timezone."
  fi
}

print_section() {
  local title="$1"
  local row3
  printf -v row3 "║  %-50s║" "$title"
  logecho ""
  logecho "╔══════════════════════════════════════════════════════╗"
  logecho "$row3"
  logecho "╚══════════════════════════════════════════════════════╝"
}

apt_log() {
  info "Running: $*"
  "$@" >&3 2>&3
}

# Restore the earliest tool-owned backup (the state before first modification),
# or delete a tool-created file if explicitly requested and no backup exists.
# $1: file path   $2: "delete_if_no_backup" (optional) to remove new file when no backup found
restore_file() {
  local file="$1"
  local delete_if_no_backup="${2:-false}"

  local original_bak
  # Backup paths are tool-generated and cannot contain whitespace or newlines.
  # shellcheck disable=SC2012
  original_bak=$(ls -1tr "${file}".http-infra.bak.* 2>/dev/null | head -1 || true)

  if [[ -n "$original_bak" ]]; then
    cp -p "$original_bak" "$file"
    success "Restored: $file ← $original_bak"
    rm -f "${file}".http-infra.bak.*
    info "Removed backup(s) for $file"
  elif [[ "$delete_if_no_backup" == "delete_if_no_backup" && -f "$file" ]]; then
    rm -f "$file"
    warn "No backup found — deleted: $file"
  else
    warn "No backup found for $file, leaving untouched."
  fi
}

restore_managed_files() {
  local file action
  if [[ -s "$managed_files_file" ]]; then
    while IFS=$'\t' read -r file action; do
      [[ -z "$file" ]] && continue
      case "$file" in
        /etc/hosts|/etc/systemd/resolved.conf|/etc/systemd/timesyncd.conf|\
        /etc/lldpd.d/lldpcli.conf|/etc/apache2/conf-available/servername.conf|\
        /etc/apache2/ports.conf|\
        /etc/apache2/conf-enabled/http-ztp-listeners.conf|\
        /etc/apache2/conf-enabled/http-ztp-public-boundary.conf|\
        /etc/apache2/sites-enabled/000-default.conf) ;;
        *) error "Invalid managed file path in state: $file"; exit 1 ;;
      esac
      if [[ "$file" == "$apache_public_boundary_conf" ]]; then
        case "$action" in
          restore|delete) ;;
          *) error "Invalid managed file action for $file: $action"; exit 1 ;;
        esac
        success "Preserving authenticated Apache boundary V2: $file"
        continue
      fi
      case "$action" in
        restore) restore_file "$file" ;;
        delete) restore_file "$file" delete_if_no_backup ;;
        *) error "Invalid managed file action for $file: $action"; exit 1 ;;
      esac
    done < "$managed_files_file"
    rm -f "$managed_files_file"
    return 0
  fi

  # Backward compatibility for setup state written before managed-files existed.
  restore_file /etc/hosts
  restore_file /etc/systemd/resolved.conf
  restore_file /etc/systemd/timesyncd.conf
  restore_file /etc/lldpd.d/lldpcli.conf
  restore_file /etc/apache2/conf-available/servername.conf
  restore_file /etc/apache2/ports.conf
  restore_file /etc/apache2/conf-enabled/http-ztp-listeners.conf delete_if_no_backup
  success "Preserving authenticated Apache boundary V2: $apache_public_boundary_conf"
  restore_file /etc/apache2/sites-enabled/000-default.conf
  rm -f "$managed_files_file"
}

restore_apache_default_site_state() {
  local state
  [[ -f "$apache_default_site_state" && ! -L "$apache_default_site_state" ]] || return 0
  if ! IFS= read -r state < "$apache_default_site_state"; then
    error "Cannot read saved Apache default-site state."
    return 1
  fi
  case "$state" in
    enabled)
      if [[ ! -f /etc/apache2/sites-available/000-default.conf ||
            -L /etc/apache2/sites-available/000-default.conf ]]; then
        error "Cannot safely restore Apache default site."
        return 1
      fi
      a2ensite 000-default >&3 2>&3
      ;;
    disabled)
      a2dissite 000-default >&3 2>&3 || true
      ;;
    *)
      error "Invalid saved Apache default-site state: $state"
      return 1
      ;;
  esac
  rm -f -- "$apache_default_site_state"
}

# ─── Preflight ────────────────────────────────────────────────────────────────
if [[ -f "$run_info_file" ]]; then
  info "Loaded setup run information:"
  while IFS= read -r line; do logecho "  $line"; done < "$run_info_file"
fi

recorded_packages=()
packages_to_remove=()
missing_packages=()
if [[ -f "$state_file" ]]; then
  while IFS=$'\t' read -r pkg _version _installed_at; do
    [[ -z "$pkg" ]] && continue
    if [[ ! "$pkg" =~ ^[a-z0-9][a-z0-9+.-]*(:[a-z0-9]+)?$ ]]; then
      error "Invalid package name in state file: $pkg"
      exit 1
    fi
    recorded_packages+=("$pkg")
    if dpkg -s "$pkg" &>/dev/null; then
      packages_to_remove+=("$pkg")
    else
      missing_packages+=("$pkg")
    fi
  done < "$state_file"
fi

logecho ""
logecho "╔══════════════════════════════════════════════════════╗"
logecho "║                   INFRA TEARDOWN                    ║"
logecho "╚══════════════════════════════════════════════════════╝"
logecho ""
logecho "Packages recorded by infra-setup and currently installed:"
if [[ ${#packages_to_remove[@]} -gt 0 ]]; then
  for pkg in "${packages_to_remove[@]}"; do logecho "  [-] $pkg"; done
else
  logecho "  (none)"
fi
if [[ ${#missing_packages[@]} -gt 0 ]]; then
  logecho "Recorded packages already absent (state entries will be cleaned):"
  for pkg in "${missing_packages[@]}"; do logecho "  [!] $pkg"; done
fi
logecho "Configuration rollback: files recorded in managed-files plus timezone state."
warn "Only packages listed above from installed-packages will be uninstalled."
if [[ "$teardown_confirmed" != "true" ]]; then
  if [[ "$non_interactive" == "true" || ! -t 0 ]]; then
    error "Teardown confirmation required; rerun with --yes"
    exit 2
  fi
  confirm=""
  read -rp "Proceed with the rollback and listed package removals? [y/N] (default: cancel, auto-cancel in ${prompt_timeout}s) " \
    -t "$prompt_timeout" confirm || true
  logecho ""
  case "$confirm" in
    [yY][eE][sS]|[yY]) ;;
    *) teardown_status=aborted; info "Aborted."; exit 0 ;;
  esac
fi
logecho ""

# Refuse the transaction before its first package/configuration mutation unless
# the currently reachable Monitor surface is protected by the exact V2 policy
# and a valid persistent credential state.
preserve_apache_control_boundary

# ─── Step 1: Stop package-owned services before removal ───────────────────────
print_section "Step 1: Stop Managed Services"
if installed_by_setup lldpd && dpkg -s lldpd &>/dev/null; then
  systemd_is_operational && systemctl stop lldpd || true
fi
apache_will_be_removed=false
if installed_by_setup apache2 && dpkg -s apache2 &>/dev/null; then
  apache_will_be_removed=true
  systemd_is_operational && systemctl stop apache2 || true
fi
if installed_by_setup isc-dhcp-server && dpkg -s isc-dhcp-server &>/dev/null; then
  systemd_is_operational && systemctl stop isc-dhcp-server || true
fi

# Restore the original timezone while tzdata is still available.  A minimal
# image may have gained tzdata during setup and will remove it in Step 2.
if [[ -f "$timezone_state_file" ]]; then
  original_timezone=$(<"$timezone_state_file")
  if [[ -n "$original_timezone" ]]; then
    apply_timezone "$original_timezone"
    success "Timezone restored: $original_timezone"
  else
    warn "Original timezone state is empty; leaving current timezone unchanged."
  fi
  rm -f "$timezone_state_file"
fi

# ─── Step 2: Remove exactly the packages recorded by setup ───────────────────
print_section "Step 2: Remove Recorded Packages"
if [[ ${#packages_to_remove[@]} -gt 0 ]]; then
  apt_log apt-get -o "DPkg::Lock::Timeout=${apt_lock_timeout}" \
    remove --purge -y "${packages_to_remove[@]}"
  for pkg in "${packages_to_remove[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      error "$pkg is still installed after apt-get remove; keeping its state entry"
      exit 1
    else
      forget_package "$pkg"
      success "$pkg removed."
    fi
  done
else
  info "No recorded installed packages to remove."
fi

for pkg in "${missing_packages[@]}"; do
  forget_package "$pkg"
  info "Removed stale state entry: $pkg"
done

# ─── Step 3: Restore configuration after package purge ────────────────────────
print_section "Step 3: Restore Managed Configuration"
restore_preserved_apache_boundary
preserve_apache_control_boundary
restore_managed_files
restore_apache_default_site_state
rm -f -- "${apache_public_boundary_conf}".http-infra.bak.*

if systemd_is_operational; then
  if systemctl is-active --quiet systemd-resolved; then
    systemctl restart systemd-resolved
    success "systemd-resolved restarted."
  fi
fi
if [[ -f "$timesyncd_unit_state_file" ]]; then
  original_timesyncd_state=$(<"$timesyncd_unit_state_file")
  if [[ "$original_timesyncd_state" == "masked" ]] && systemd_is_operational; then
    systemctl disable --now systemd-timesyncd.service 2>/dev/null || true
    systemctl mask systemd-timesyncd.service
    success "systemd-timesyncd restored to its original masked state."
  else
    warn "Unknown saved systemd-timesyncd state: $original_timesyncd_state"
  fi
  rm -f "$timesyncd_unit_state_file"
fi
if systemd_is_operational; then
  if systemctl is-active --quiet systemd-timesyncd; then
    systemctl restart systemd-timesyncd
    success "systemd-timesyncd restarted."
  fi
fi
rmdir /etc/lldpd.d 2>/dev/null || true

if [[ "$apache_will_be_removed" != "true" ]] && dpkg -s apache2 &>/dev/null; then
  if systemd_is_operational; then
    preserve_apache_control_boundary
    if ! apache2ctl configtest >&3 2>&3; then
      systemctl stop apache2 || true
      error "Retained Apache configuration failed configtest; Apache remains stopped."
      exit 1
    fi
    if ! systemctl restart apache2; then
      systemctl stop apache2 || true
      error "Retained Apache failed to restart safely and remains stopped."
      exit 1
    fi
    success "Pre-existing apache2 retained with authenticated boundary V2."
  else
    warn "Pre-existing apache2 retained with boundary V2; systemd is not running, so restart was skipped."
  fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
print_section "SUMMARY"

logecho ""
logecho "── Recorded package removal status ─────────────────────"
if [[ ${#recorded_packages[@]} -eq 0 ]]; then
  logecho "  (no package entries were recorded)"
else
  for pkg in "${recorded_packages[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      warn "  [!] $pkg — still installed"
    else
      logecho "  [-] $pkg — absent"
    fi
  done
fi

logecho ""
logecho "── Config file status ──────────────────────────────────"
for f in \
  /etc/hosts \
  /etc/systemd/resolved.conf \
  /etc/systemd/timesyncd.conf \
  /etc/lldpd.d/lldpcli.conf \
  /etc/apache2/conf-available/servername.conf \
  /etc/apache2/conf-enabled/http-ztp-public-boundary.conf \
  /etc/apache2/sites-enabled/000-default.conf; do
  if [[ -f "$f" ]]; then
    logecho "  [*] $f (present)"
  else
    logecho "  [-] $f (removed)"
  fi
done

logecho ""
logecho "  Log file : $log_file"
logecho ""
success "infra-teardown.sh completed."
logecho ""

if [[ -f "$state_file" && ! -s "$state_file" && ! -e "$managed_files_file" ]]; then
  rm -f "$state_file"
  rm -f "$run_info_file"
  rmdir "$state_dir" 2>/dev/null || true
fi

teardown_status=completed
echo "[$(date '+%Y-%m-%d %H:%M:%S')] infra-teardown.sh finished" >&3
