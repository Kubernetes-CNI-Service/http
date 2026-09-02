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
        /etc/apache2/conf-enabled/http-ztp-public-boundary.conf|\
        /etc/apache2/sites-enabled/000-default.conf) ;;
        *) error "Invalid managed file path in state: $file"; exit 1 ;;
      esac
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
  restore_file /etc/apache2/conf-enabled/http-ztp-public-boundary.conf
  restore_file /etc/apache2/sites-enabled/000-default.conf
  rm -f "$managed_files_file"
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
restore_managed_files

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
    systemctl restart apache2 || true
    success "Pre-existing apache2 retained; managed configuration was restored."
  else
    warn "Pre-existing apache2 retained; systemd is not running, so restart was skipped."
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
