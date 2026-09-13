#!/bin/bash

set -euo pipefail

non_interactive=false
execution_policy="client"
force_apache=false
force_dhcp=false
force_doca=false
skip_doca=false
force_bluefield=false
force_power_cycle=false
mgmt_mode=false
offline_mode=false
defer_services=false
recover_monitor_authority=false
prompt_timeout=15
doca_prompt_timeout=10
explicit_policy=""

usage() {
  cat <<'EOF'
Usage: infra-setup.sh [options]
  --client                Use client policy (default): no Apache/DHCP, BF NIC yes, power cycle no
  --interactive           Prompt for optional software and BlueField actions
  --non-interactive       Never prompt; apply the selected policy and explicit action flags
  --all                   Confirm all optional software and BlueField actions
  --install-apache        Install/configure Apache without prompting
  --install-dhcp          Install ISC DHCP server without prompting
  --download-doca         Download/cache DOCA without installing doca-ofed when no NIC is detected
  --skip-doca             Skip all DOCA download, cache and installation actions
  --enable-bluefield-nic  Change detected BlueField DPU mode to NIC mode
  --power-cycle           Allow required BlueField power cycle after mode change
  --mgmt                  Cache downloaded DEBs in ../apps and publish a local APT repository
                          Without a Mellanox NIC, DOCA defaults to cache after 10s, without install
  --offline               With --mgmt, require a matching ../apps repository; never use Internet
  --defer-services        Install/configure Apache and DHCP but never start/restart them
                          Intended for transactional load; activation happens only after commit
  --recover-monitor-authority
                          Stop Apache and explicitly repair invalid Monitor cache content
  -h, --help              Show this help
EOF
}

select_policy() {
  local requested="$1"
  if [[ -n "$explicit_policy" && "$explicit_policy" != "$requested" ]]; then
    echo "ERROR: --client, --interactive and --all are mutually exclusive." >&2
    exit 2
  fi
  explicit_policy="$requested"
  execution_policy="$requested"
}

original_argument_count=$#
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) non_interactive=true ;;
    --client) select_policy client ;;
    --interactive) select_policy interactive ;;
    --all) select_policy all ;;
    --install-apache) force_apache=true ;;
    --install-dhcp) force_dhcp=true ;;
    --download-doca) force_doca=true ;;
    --skip-doca) skip_doca=true ;;
    --enable-bluefield-nic) force_bluefield=true ;;
    --power-cycle) force_power_cycle=true ;;
    --mgmt) mgmt_mode=true ;;
    --offline) offline_mode=true ;;
    --defer-services) defer_services=true ;;
    --recover-monitor-authority) recover_monitor_authority=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ "$recover_monitor_authority" == "true" && "$original_argument_count" != "1" ]]; then
  echo "ERROR: --recover-monitor-authority must be the only option." >&2
  exit 2
fi

if $force_doca && $skip_doca; then
  echo "ERROR: --download-doca and --skip-doca are mutually exclusive." >&2
  exit 2
fi
if [[ "$offline_mode" == "true" && "$mgmt_mode" != "true" ]]; then
  echo "ERROR: --offline is only valid together with --mgmt." >&2
  exit 2
fi
if [[ "$offline_mode" == "true" && "$force_doca" == "true" ]]; then
  echo "ERROR: --offline cannot be combined with --download-doca." >&2
  exit 2
fi
case "$execution_policy" in
  client)
    apache_mode="no"
    dhcp_mode="no"
    doca_mode="ask"
    bluefield_mode="yes"
    power_cycle_mode="no"
    ;;
  interactive)
    apache_mode="ask"
    dhcp_mode="ask"
    doca_mode="ask"
    bluefield_mode="ask"
    power_cycle_mode="ask"
    ;;
  all)
    apache_mode="yes"
    dhcp_mode="yes"
    doca_mode="yes"
    bluefield_mode="yes"
    power_cycle_mode="yes"
    ;;
esac
$force_apache && apache_mode="yes"
$force_dhcp && dhcp_mode="yes"
$force_doca && doca_mode="yes"
$skip_doca && doca_mode="no"
$force_bluefield && bluefield_mode="yes"
$force_power_cycle && power_cycle_mode="yes"

script_source="${BASH_SOURCE[0]:-}"
control_auth_source_sha256="5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
MONITOR_AUTHORITY_RECOVERY_WARNING='WARNING: explicit Monitor authority recovery reset invalid cache state; review the accepted www-data denial residual.'
control_auth_source=""
control_auth_helper="/usr/local/lib/http-ztp/control-auth.py"
if [[ ( "$mgmt_mode" == "true" || "$recover_monitor_authority" == "true" ) && \
      ( -z "$script_source" || ! -f "$script_source" ) ]]; then
  echo "ERROR: this operation requires executing infra-setup.sh from its governed file." >&2
  exit 2
fi
if [[ -z "$script_source" ]]; then
  # For `curl URL | sudo bash`, run from the target user's home directory so the
  # default becomes $HOME/http-infra and remains discoverable by check_infra.py.
  runtime_dir="${HTTP_INFRA_RUNTIME_DIR:-${PWD}/http-infra}"
else
  source_dir=$(dirname -- "$script_source")
  if [[ "$(basename -- "$source_dir")" == "current" ]]; then
    runtime_dir=$(cd -- "$source_dir/.." && pwd)
  else
    runtime_dir=$(cd -- "$source_dir" && pwd)
  fi
fi
apps_root=""
apps_dir=""
mgmt_http_root=""
if [[ "$mgmt_mode" == "true" || "$recover_monitor_authority" == "true" ]]; then
  mgmt_http_root=$(cd -P -- "$(dirname -- "$script_source")/.." && pwd)
  control_auth_source="${mgmt_http_root}/tools/control-auth.py"
fi
if [[ "$mgmt_mode" == "true" ]]; then
  apps_root="${mgmt_http_root}/apps"
  if [[ ! -f "$control_auth_source" || -L "$control_auth_source" || \
        ! -x "$control_auth_source" || \
        "$(stat -c '%h' "$control_auth_source" 2>/dev/null || true)" != "1" ]]; then
    echo "ERROR: --mgmt requires canonical sibling tools/control-auth.py: $control_auth_source" >&2
    exit 2
  fi
  control_auth_source_actual=$(sha256sum "$control_auth_source" | awk '{print $1}')
  if [[ "$control_auth_source_actual" != "$control_auth_source_sha256" ]]; then
    echo "ERROR: Control auth helper source hash mismatch: $control_auth_source" >&2
    exit 2
  fi
fi

systemd_is_operational() {
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
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

run_native_monitor_authority_routine() {
  local operation=${1:-} decision_command
  if [[ "$operation" != "monitor-authority-provision" && \
        "$operation" != "monitor-authority-attest" ]]; then
    echo "ERROR: invalid routine Monitor authority operation; service must remain stopped." >&2
    return 1
  fi
  decision_command="${operation}-decision"
  if ! capture_monitor_authority_decision \
      "$control_auth_helper" "$decision_command"; then
    echo "ERROR: routine Monitor cache authority validation failed; Apache must remain stopped." >&2
    return 1
  fi
  case "$monitor_authority_decision" in
    'attest-valid')
      return 0
      ;;
    'recovery-in-progress')
      echo "ERROR: classification=recovery-in-progress; Monitor authority recovery has not been committed; Apache must remain stopped. Run exactly: sudo ./infra/infra-setup.sh --recover-monitor-authority" >&2
      return 1
      ;;
    'recovery-committed-cleanup-pending')
      echo "ERROR: classification=recovery-committed-cleanup-pending; previous Monitor authority recovery COMPLETED and the repaired authority itself is not in question; Apache must remain stopped. Re-run exactly to reattest and finish marker cleanup: sudo ./infra/infra-setup.sh --recover-monitor-authority" >&2
      return 1
      ;;
    *)
      echo "ERROR: routine Monitor cache authority validation failed; Apache must remain stopped." >&2
      return 1
      ;;
  esac
}

recover_monitor_authority_action() {
  local apache_initial_state apache_stopped_state apache_started_state
  if ! systemd_is_operational; then
    echo "ERROR: systemd state is unavailable; Monitor authority was not repaired." >&2
    return 1
  fi
  if ! apache_initial_state=$(systemctl show --property=ActiveState --value apache2) ||
      [[ "$apache_initial_state" != "active" && \
         "$apache_initial_state" != "inactive" && \
         "$apache_initial_state" != "failed" ]]; then
    echo "ERROR: Apache state cannot be proven; Monitor authority was not repaired." >&2
    return 1
  fi
  if ! systemctl stop apache2; then
    echo "ERROR: Apache could not be stopped; Monitor authority was not repaired." >&2
    return 1
  fi
  if ! apache_stopped_state=$(systemctl show --property=ActiveState --value apache2) ||
      [[ "$apache_stopped_state" != "inactive" && \
         "$apache_stopped_state" != "failed" ]]; then
    echo "ERROR: Apache is not provably stopped; Monitor authority was not repaired." >&2
    return 1
  fi
  echo "[WARN] Apache stopped for explicit Monitor cache authority recovery." >&2
  echo "[WARN] Apache stopped for explicit Monitor cache authority recovery." >&3
  if [[ ! -f "$control_auth_source" || -L "$control_auth_source" || \
        ! -x "$control_auth_source" || \
        "$(stat -c '%h' "$control_auth_source" 2>/dev/null || true)" != "1" ]]; then
    echo "ERROR: recovery requires canonical sibling tools/control-auth.py; Apache remains stopped." >&2
    return 1
  fi
  control_auth_source_actual=$(sha256sum "$control_auth_source" | awk '{print $1}')
  if [[ "$control_auth_source_actual" != "$control_auth_source_sha256" ]]; then
    echo "ERROR: recovery helper source hash mismatch; Apache remains stopped." >&2
    return 1
  fi
  if [[ ! -f "$control_auth_helper" || -L "$control_auth_helper" || \
        ! -x "$control_auth_helper" || \
        "$(stat -c '%h' "$control_auth_helper" 2>/dev/null || true)" != "1" ]]; then
    echo "ERROR: installed recovery helper is missing or unsafe; Apache remains stopped." >&2
    return 1
  fi
  control_auth_installed_actual=$(sha256sum "$control_auth_helper" | awk '{print $1}')
  if [[ "$control_auth_installed_actual" != "$control_auth_source_sha256" ]]; then
    echo "ERROR: installed recovery helper hash mismatch; Apache remains stopped." >&2
    return 1
  fi
  if ! "$control_auth_helper" validate; then
    echo "ERROR: Monitor credentials are invalid; Apache remains stopped." >&2
    return 1
  fi
  if ! capture_monitor_authority_decision \
      "$control_auth_helper" monitor-authority-recover-decision; then
    echo "ERROR: explicit Monitor authority recovery returned an invalid structured result; Apache remains stopped." >&2
    return 1
  fi
  case "$monitor_authority_decision" in
    *';reset-invalid-cache=true')
      printf '%s\n' "$MONITOR_AUTHORITY_RECOVERY_WARNING" >&2
      printf '%s\n' "$MONITOR_AUTHORITY_RECOVERY_WARNING" >&3
      ;;
    *';reset-invalid-cache=false')
      ;;
    *)
      echo "ERROR: explicit Monitor authority recovery returned an invalid warning decision; Apache remains stopped." >&2
      return 1
      ;;
  esac
  case "$monitor_authority_decision" in
    'restart-allowed:complete;reset-invalid-cache=false'|\
    'restart-allowed:complete;reset-invalid-cache=true')
      ;;
    'restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false'|\
    'restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=true')
      echo "WARNING: previous Monitor authority recovery COMPLETED, but marker removal durability is unknown; a stale completed marker may reappear after crash." >&2
      ;;
    'restart-blocked:marker-retained;reset-invalid-cache=false'|\
    'restart-blocked:marker-retained;reset-invalid-cache=true')
      echo "ERROR: previous Monitor authority recovery COMPLETED and the repaired authority itself is not in question, but marker cleanup remains; Apache remains stopped. Re-run exactly: sudo ./infra/infra-setup.sh --recover-monitor-authority" >&2
      return 1
      ;;
    'restart-blocked:marker-authority-uncertain;reset-invalid-cache=false'|\
    'restart-blocked:marker-authority-uncertain;reset-invalid-cache=true')
      echo "ERROR: Monitor recovery marker authority is uncertain after semantic commit; Apache remains stopped. Re-run exactly: sudo ./infra/infra-setup.sh --recover-monitor-authority" >&2
      return 1
      ;;
    *)
      echo "ERROR: explicit Monitor authority recovery returned an invalid structured result; Apache remains stopped." >&2
      return 1
      ;;
  esac
  if ! run_native_monitor_authority_routine monitor-authority-attest; then
    echo "ERROR: recovered Monitor authority did not attest; Apache remains stopped." >&2
    return 1
  fi
  if [[ "$apache_initial_state" == "active" ]]; then
    if ! systemctl start apache2; then
      echo "ERROR: Apache could not be restored after recovery; it remains stopped." >&2
      return 1
    fi
    if ! apache_started_state=$(systemctl show --property=ActiveState --value apache2) ||
        [[ "$apache_started_state" != "active" ]]; then
      systemctl stop apache2 || true
      echo "ERROR: Apache restart could not be attested; it remains stopped." >&2
      return 1
    fi
  fi
  echo "[OK] explicit Monitor cache authority recovery completed." >&2
  echo "[OK] explicit Monitor cache authority recovery completed." >&3
}

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: infra-setup.sh must be run as root." >&2
  exit 1
fi
lock_file="/run/lock/http-infra.lock"
mkdir -p "$(dirname "$lock_file")"
exec 9>"$lock_file"
flock -x 9

log_dir="${runtime_dir}/logs"
mkdir -p "$log_dir"
log_file="${log_dir}/infra-setup-$(date +%Y%m%d_%H%M%S)-$$.log"
exec 3>>"$log_file"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] infra-setup.sh started" >&3

if [[ "$recover_monitor_authority" == "true" ]]; then
  if ! recover_monitor_authority_action; then
    exit 1
  fi
  exit 0
fi

# Detect the supported Ubuntu release and CPU architecture before choosing a
# repository.  Never mix packages from different Ubuntu releases/architectures.
if [[ ! -f /etc/os-release ]]; then
  echo "ERROR: Cannot determine OS. Aborting." >&2
  echo "ERROR: Cannot determine OS. Aborting." >&3
  exit 1
fi
# shellcheck source=/dev/null
source /etc/os-release
if [[ "$ID" != "ubuntu" || ! "$VERSION_ID" =~ ^(22\.04|24\.04)$ ]]; then
  echo "ERROR: This script requires Ubuntu 22.04 or 24.04. Detected: ${PRETTY_NAME:-unknown}" >&2
  echo "ERROR: Unsupported OS: ${PRETTY_NAME:-unknown}" >&3
  exit 1
fi
case "$(uname -m)" in
  x86_64)  arc="amd64" ;;
  aarch64) arc="arm64" ;;
  *)
    echo "ERROR: Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac
ubuntu_tag=${VERSION_ID//./}
repo_relative_path="ubuntu-${VERSION_ID}/${arc}"
if [[ "$mgmt_mode" == "true" ]]; then
  apps_dir="${apps_root}/${repo_relative_path}"
  mkdir -p "$apps_dir/partial"
  chmod 0755 "$apps_dir"
  if id _apt &>/dev/null; then
    chown _apt:root "$apps_dir/partial"
    chmod 0700 "$apps_dir/partial"
  else
    chmod 0755 "$apps_dir/partial"
  fi
fi

# ─── Configuration ────────────────────────────────────────────────────────────
http_server=http://127.0.0.1/apps
local_http_enabled=false
dns_servers=(208.67.220.220 8.8.8.8)
ntp_servers=(118.163.81.61 time.stdtime.gov.tw ntp.ubuntu.com)
time_zone=Etc/UTC
if [[ -n "$script_source" ]]; then
  runtime_config="$(dirname -- "$script_source")/infra-runtime.conf"
  if [[ -s "$runtime_config" ]]; then
    # Host-specific values are deliberately outside this synchronized script.
    # shellcheck source=/dev/null
    source "$runtime_config"
  fi
fi
http_server_base=${http_server%/}
http_server="${http_server_base}/${repo_relative_path}"
state_dir="/var/lib/http-infra"
state_file="${state_dir}/installed-packages"
managed_files_file="${state_dir}/managed-files"
timezone_state_file="${state_dir}/original-timezone"
timesyncd_unit_state_file="${state_dir}/original-timesyncd-unit-state"
run_info_file="${state_dir}/run-info"
public_status_file="${runtime_dir}/infra-status"
apache_public_boundary_conf="/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"
apache_listener_conf="/etc/apache2/conf-enabled/http-ztp-listeners.conf"
apache_ports_conf="/etc/apache2/ports.conf"
apache_default_site_state="${state_dir}/apache-default-site-enabled"

mkdir -p "$state_dir"
touch "$state_file"
chmod 0600 "$state_file"
touch "$managed_files_file"
chmod 0600 "$managed_files_file"
record_package_state() {
  local pkg="$1" state="$2"
  local version installed_at tmp
  if [[ "$state" == "installed" ]]; then
    if ! version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null); then
      error "Package installation could not be verified: $pkg"
      return 1
    fi
  else
    version="$state"
  fi
  installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  tmp=$(mktemp "${state_file}.tmp.XXXXXX")
  awk -F '\t' -v pkg="$pkg" '$1 != pkg' "$state_file" > "$tmp"
  printf '%s\t%s\t%s\n' "$pkg" "$version" "$installed_at" >> "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$state_file"
}

begin_package_install() { record_package_state "$1" pending; }
commit_package_install() { record_package_state "$1" installed; }

track_managed_file() {
  local file="$1" action tmp
  if awk -F '\t' -v file="$file" '$1 == file { found=1 } END { exit !found }' "$managed_files_file"; then
    return 0
  fi
  if [[ -f "$file" ]]; then
    backup_file "$file"
    action=restore
  else
    action=delete
  fi
  tmp=$(mktemp "${managed_files_file}.tmp.XXXXXX")
  cat "$managed_files_file" > "$tmp"
  printf '%s\t%s\n' "$file" "$action" >> "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$managed_files_file"
}

install_control_auth_helper() {
  local helper_dir candidate actual status_json
  helper_dir=$(dirname -- "$control_auth_helper")
  if [[ -L "$helper_dir" || ( -e "$helper_dir" && ! -d "$helper_dir" ) ]]; then
    error "Unsafe control auth helper directory: $helper_dir"
    return 1
  fi
  install -d -m 0755 -o root -g root -- "$helper_dir"
  if [[ -L "$helper_dir" ]]; then
    error "Control auth helper directory became a symbolic link: $helper_dir"
    return 1
  fi
  candidate=$(mktemp "${control_auth_helper}.tmp.XXXXXX")
  install -m 0755 -o root -g root -- "$control_auth_source" "$candidate"
  actual=$(sha256sum "$candidate" | awk '{print $1}')
  if [[ "$actual" != "$control_auth_source_sha256" ]]; then
    rm -f -- "$candidate"
    error "Installed control auth helper candidate hash mismatch."
    return 1
  fi
  mv -f -- "$candidate" "$control_auth_helper"
  actual=$(sha256sum "$control_auth_helper" | awk '{print $1}')
  if [[ "$actual" != "$control_auth_source_sha256" ]]; then
    error "Installed control auth helper hash mismatch."
    return 1
  fi

  # Create only a missing factory file, then validate the complete persistent
  # state before publishing any Apache policy which references it.
  run_native_monitor_authority_routine monitor-authority-provision
  run_native_monitor_authority_routine monitor-authority-attest
  "$control_auth_helper" ensure
  "$control_auth_helper" validate
  status_json=$("$control_auth_helper" status)
  info "Monitor control auth status: $status_json"
  success "Monitor control auth helper and credential state validated."
}

render_apache_publication_boundary() {
  cat <<'APACHE_PUBLIC_BOUNDARY_EOF'
# Managed by http/infra/infra-setup.sh.  Keep the marker and bytes stable:
# DAY0 load verifies this exact policy before Apache can be started.
# HTTP-ZTP-PUBLIC-BOUNDARY-V2

# Direct URLs remain usable, but Apache must not enumerate DocumentRoot.
<Directory "/var/www/html">
    Options -Indexes

    <FilesMatch "(?i)\.(?:py|pyc|pyo|cgi|log)$">
        Require all denied
    </FilesMatch>

    <FilesMatch "(?i)(?:manifest|current-release\.json|\.setup_manifest|\.ztp-prefix-publication\.json|\.deployment\.lock)">
        Require all denied
    </FilesMatch>

    <FilesMatch "(?i)(?:01-global\.yaml|02-devices_config\.csv|02-dhcp-subnet_config\.csv|dhcpd(?:_[^/]*)?\.(?:conf|hosts)|p2p-air\.json)">
        Require all denied
    </FilesMatch>
</Directory>

# The Monitor landing page is the browser authentication entry point.  The
# browser reuses this Basic-auth protection space for subsequent control calls,
# while Apache still authenticates every request server-side.
<Directory "/var/www/html/monitor">
    <Files "monitor.html">
        AuthType Basic
        AuthName "HTTP ZTP Monitor Control"
        AuthBasicProvider file
        AuthUserFile /etc/http-ztp/control-users.htpasswd
        Require user nvis cumulus
        Header always set Cache-Control "no-store"
    </Files>
</Directory>

# Bind both canonical and compatibility URLs to the same three exact CGI
# filesystem targets.  Anchors plus AcceptPathInfo Off reject suffix paths.
ScriptAliasMatch "^/monitor/control/ztp-monitor$" "/usr/lib/cgi-bin/ztp-monitor-control"
ScriptAliasMatch "^/monitor/control/switch-collection$" "/usr/lib/cgi-bin/switch-collection-control"
ScriptAliasMatch "^/monitor/control/manual-ztp$" "/usr/lib/cgi-bin/manual-ztp-control"

<Directory "/usr/lib/cgi-bin">
    <FilesMatch "^(?:ztp-monitor-control|switch-collection-control|manual-ztp-control)$">
        AuthType Basic
        AuthName "HTTP ZTP Monitor Control"
        AuthBasicProvider file
        AuthUserFile /etc/http-ztp/control-users.htpasswd
        Require user nvis cumulus
        SetEnv CONTROL_REQUIRE_AUTH 1
        AcceptPathInfo Off
    </FilesMatch>
</Directory>

# Authenticate the canonical and legacy URL spaces as well as their rejected
# PATH_INFO variants, so an invalid suffix can never bypass the challenge.
<LocationMatch "^/(?:monitor/control/(?:ztp-monitor|switch-collection|manual-ztp)|cgi-bin/(?:ztp-monitor-control|switch-collection-control|manual-ztp-control))(?:/.*)?$">
    AuthType Basic
    AuthName "HTTP ZTP Monitor Control"
    AuthBasicProvider file
    AuthUserFile /etc/http-ztp/control-users.htpasswd
    Require user nvis cumulus
    SetEnv CONTROL_REQUIRE_AUTH 1
    AcceptPathInfo Off
</LocationMatch>

# Protect the real filesystem targets even when another URL maps to them.
<DirectoryMatch "^/var/www/html/(?:DAY0-Prepare|monitor/status|ztp/(?:status|backup|optimize)|ztp/config/(?:isc-dhcp-server|cumulus/template|nvos/template))(?:/|$)">
    Require all denied
</DirectoryMatch>

# URL-space rules cover setup aliases and arbitrary ztp_url_prefix links.  A
# segment match is deliberate: infra does not know the selected prefix.
<LocationMatch "(?i)(?:^|/)(?:DAY0-Prepare|status|backup|optimize|monitor/ztp-status|config/(?:isc-dhcp-server|cumulus/template|nvos/template))(?:/|$)">
    Require all denied
</LocationMatch>

# Deny executable source and logs even if a future symlink publishes one
# outside the protected directory prefixes.
<LocationMatch "(?i)(?:^|/)[^/]*\.(?:py|pyc|pyo|cgi|log)(?:/|$)">
    Require all denied
</LocationMatch>

# Release manifests and host-local deployment state are never public assets.
<LocationMatch "(?i)(?:^|/)(?:[^/]*manifest[^/]*|current-release\.json|\.setup_manifest|\.ztp-prefix-publication\.json|\.deployment\.lock)(?:/|$)">
    Require all denied
</LocationMatch>

# Protect declarative inputs and DHCP runtime files wherever they are linked.
<LocationMatch "(?i)(?:^|/)(?:01-global\.yaml|02-devices_config\.csv|02-dhcp-subnet_config\.csv|dhcpd(?:_[^/]*)?\.(?:conf|hosts)|p2p-air\.json)(?:/|$)">
    Require all denied
</LocationMatch>
APACHE_PUBLIC_BOUNDARY_EOF
}

install_apache_publication_boundary() {
  local destination="$apache_public_boundary_conf"
  local candidate rollback existed=false

  track_managed_file "$destination"
  candidate=$(mktemp "${destination}.tmp.XXXXXX")
  rollback=$(mktemp "${destination}.rollback.XXXXXX")
  if [[ -f "$destination" ]]; then
    cp -p -- "$destination" "$rollback"
    existed=true
  fi

  render_apache_publication_boundary > "$candidate"
  chmod 0644 "$candidate"
  chown root:root "$candidate"
  mv -f -- "$candidate" "$destination"

  # Test the complete active Apache configuration before any service restart.
  # On failure, restore the state from immediately before this setup run; the
  # original pre-tool state remains separately recorded for teardown.
  if ! apache2ctl configtest >&3 2>&3; then
    if [[ "$existed" == "true" ]]; then
      cp -p -- "$rollback" "$destination"
    else
      rm -f -- "$destination"
    fi
    rm -f -- "$rollback"
    if systemd_is_operational; then
      systemctl stop apache2 || true
    fi
    error "Apache publication boundary failed configtest; previous configuration restored and Apache remains stopped."
    return 1
  fi
  rm -f -- "$rollback"
  success "Apache static publication boundary installed and configtest passed."
}

write_run_info() {
  local tmp script_hash
  tmp=$(mktemp "${run_info_file}.tmp.XXXXXX")
  if [[ -n "$script_source" && -f "$script_source" ]]; then
    script_hash=$(sha256sum "$script_source" | awk '{print $1}')
  else
    script_hash="unavailable:stdin"
  fi
  {
    printf 'schema_version=2\n'
    printf 'last_setup_started=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'status=started\n'
    printf 'script_sha256=%s\n' "$script_hash"
    printf 'http_server=%s\n' "$http_server"
    printf 'local_http_enabled=%s\n' "$local_http_enabled"
    printf 'mgmt_mode=%s\n' "$mgmt_mode"
  } > "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$run_info_file"
}

write_run_info

setup_status=started
deferred_policy_path="/usr/sbin/policy-rc.d"
deferred_policy_backup=""
deferred_policy_delegate=""
deferred_policy_temporary=""
deferred_policy_guard_installed=false

restore_deferred_service_policy() {
  [[ "$deferred_policy_guard_installed" == "true" ]] || return 0
  [[ -z "$deferred_policy_temporary" ]] || rm -f -- "$deferred_policy_temporary"
  rm -f -- "$deferred_policy_path"
  if [[ -n "$deferred_policy_backup" && \
        ( -e "$deferred_policy_backup" || -L "$deferred_policy_backup" ) ]]; then
    mv -- "$deferred_policy_backup" "$deferred_policy_path"
  fi
  deferred_policy_guard_installed=false
}

install_deferred_service_policy() {
  local temporary
  # Package postinst scripts must never start Apache/DHCP before their complete
  # configuration has passed validation.  In load mode the guard lasts until
  # infra returns to the caller; in standalone mode explicit systemctl actions
  # below are still allowed because policy-rc.d only controls package helpers.
  if [[ "$defer_services" != "true" && "$apache_mode" == "no" && \
        "$dhcp_mode" == "no" ]]; then
    return 0
  fi
  if [[ -e "$deferred_policy_path" || -L "$deferred_policy_path" ]]; then
    deferred_policy_backup=$(mktemp "${deferred_policy_path}.http-infra.backup.XXXXXX")
    rm -f -- "$deferred_policy_backup"
    if [[ -L "$deferred_policy_path" ]]; then
      deferred_policy_delegate=$(readlink -f -- "$deferred_policy_path" 2>/dev/null || true)
    fi
    mv -- "$deferred_policy_path" "$deferred_policy_backup"
    if [[ -z "$deferred_policy_delegate" ]]; then
      deferred_policy_delegate="$deferred_policy_backup"
    fi
  fi
  # Mark ownership before creating the replacement so EXIT cleanup restores an
  # existing policy even if a later write/chmod/rename is interrupted.
  deferred_policy_guard_installed=true
  temporary=$(mktemp "${deferred_policy_path}.http-infra.guard.XXXXXX")
  deferred_policy_temporary="$temporary"
  cat > "$temporary" <<EOF
#!/bin/sh
case "\${1:-}" in
  apache2|*/apache2|isc-dhcp-server|*/isc-dhcp-server) exit 101 ;;
esac
if [ -n "${deferred_policy_delegate}" ] && [ -x "${deferred_policy_delegate}" ]; then
  exec "${deferred_policy_delegate}" "\$@"
fi
exit 0
EOF
  chmod 0755 "$temporary"
  mv -f -- "$temporary" "$deferred_policy_path"
  deferred_policy_temporary=""
  if [[ "$defer_services" == "true" ]]; then
    echo "[INFO]  Transactional load mode: Apache/DHCP package auto-start is blocked until load commits."
    echo "[INFO]  Transactional load mode: Apache/DHCP package auto-start is blocked until load commits." >&3
  else
    echo "[INFO]  Apache/DHCP package auto-start is blocked until configuration validation succeeds."
    echo "[INFO]  Apache/DHCP package auto-start is blocked until configuration validation succeeds." >&3
  fi
}

write_public_status() {
  local exit_code="$1" tmp
  tmp=$(mktemp "${runtime_dir}/.infra-status.XXXXXX")
  {
    printf 'schema_version=1\n'
    printf 'hostname=%s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf 'last_action=setup\n'
    printf 'status=%s\n' "$setup_status"
    printf 'exit_code=%s\n' "$exit_code"
    printf 'updated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'http_server=%s\n' "$http_server"
    printf 'local_http_enabled=%s\n' "$local_http_enabled"
    printf 'mgmt_mode=%s\n' "$mgmt_mode"
    printf 'log_file=%s\n' "$log_file"
    printf 'recorded_packages=%s\n' "$(awk 'NF { count++ } END { print count+0 }' "$state_file" 2>/dev/null || echo 0)"
  } > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$public_status_file"
}

on_setup_exit() {
  local exit_code=$?
  trap - EXIT
  if ! restore_deferred_service_policy; then
    echo "ERROR: Failed to restore $deferred_policy_path" >&2
    echo "ERROR: Failed to restore $deferred_policy_path" >&3
    exit_code=1
  fi
  [[ -z "${apt_source_file:-}" ]] || rm -f "$apt_source_file"
  if [[ $exit_code -ne 0 ]]; then setup_status=failed; fi
  write_public_status "$exit_code" || true
  exit "$exit_code"
}
write_public_status 0
trap on_setup_exit EXIT
install_deferred_service_policy

mark_run_complete() {
  local tmp
  tmp=$(mktemp "${run_info_file}.tmp.XXXXXX")
  awk -F '=' '$1 != "status" && $1 != "last_setup_completed" && $1 != "local_http_enabled"' "$run_info_file" > "$tmp"
  {
    printf 'local_http_enabled=%s\n' "$local_http_enabled"
    printf 'status=completed\n'
    printf 'last_setup_completed=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$run_info_file"
}

doca_release="3.3.0-088000-26.01"
doca_package="doca-host_${doca_release}-ubuntu${ubuntu_tag}_${arc}.deb"
doca_package_version="${doca_release}-ubuntu${ubuntu_tag}"
doca_path="https://www.mellanox.com/downloads/DOCA/DOCA_v3.3.0/host/${doca_package}"

# Single source of truth for packages managed by this script.  Keep installation,
# mgmt caching and the final summary tied to these arrays.
base_packages=(wget lldpd tzdata)
common_packages=(ipmitool sshpass docker.io unzip nfs-common arping jq)
ztp_dependency_packages=(
  python3
  python3-yaml
  python3-jinja2
  python3-openpyxl
  python3-pandas
  python3-xlsxwriter
  openssh-client
  curl
)
optional_service_packages=(apache2 apache2-utils ssl-cert isc-dhcp-server)
apache_auth_modules=(
  auth_basic
  authn_file
  authn_core
  authz_user
  authz_core
  env
  alias
  cgid
  headers
)
mgmt_cache_packages=(
  "${base_packages[@]}"
  "${common_packages[@]}"
  "${ztp_dependency_packages[@]}"
  "${optional_service_packages[@]}"
)

# ─── Helpers ──────────────────────────────────────────────────────────────────
# Write to screen AND log directly via fd 3 (no pipes — avoids subshell fd issues)
info()    { echo "[INFO]  $*";  echo "[INFO]  $*"  >&3; }
warn()    { echo "[WARN]  $*";  echo "[WARN]  $*"  >&3; }
success() { echo "[OK]    $*";  echo "[OK]    $*"  >&3; }
error()   { echo "[ERROR] $*" >&2; echo "[ERROR] $*" >&3; }

confirm_action() {
  local mode="$1" prompt="$2" timeout="$3" default_answer="${4:-no}"
  local answer=""
  if [[ "$mode" == "yes" ]]; then
    return 0
  fi
  if [[ "$mode" == "no" ]]; then
    return 1
  fi
  if [[ "$non_interactive" == "true" || ! -t 0 ]]; then
    warn "$prompt — skipped (non-interactive mode)"
    return 1
  fi
  if [[ "$default_answer" == "yes" ]]; then
    read -rp "$prompt [Y/n] (default: perform, auto-perform in ${timeout}s) " -t "$timeout" answer || true
  else
    read -rp "$prompt [y/N] (default: skip, auto-skip in ${timeout}s) " -t "$timeout" answer || true
  fi
  logecho ""
  case "$answer" in
    [yY][eE][sS]|[yY]) return 0 ;;
    [nN][oO]|[nN]) return 1 ;;
    *)
      if [[ "$default_answer" == "yes" ]]; then return 0; else return 1; fi
      ;;
  esac
}

# logecho: plain echo to screen AND log
logecho() { echo "$*"; echo "$*" >&3; }

# print_section: box-style section header to screen AND log
print_section() {
  local title="$1"
  local row3
  printf -v row3 "║  %-50s║" "$title"
  logecho ""
  logecho "╔══════════════════════════════════════════════════════╗"
  logecho "$row3"
  logecho "╚══════════════════════════════════════════════════════╝"
}

# apt_log: keep complete command output in the log without flooding the terminal.
# APT commands run quietly with periodic heartbeats and a short completion
# summary. Non-APT commands retain their live streaming behavior.
apt_log() {
  local started_at=$SECONDS
  local command_status=0
  local tee_status=0
  local command_output=""
  local command_pid=""
  local summary=""
  local apt_action=""
  local elapsed=0
  local -a pipeline_status=()

  # apt_get() invokes APT through `env DEBIAN_FRONTEND=noninteractive
  # apt-get ...`.  Treat that wrapper exactly like a direct apt-get call;
  # otherwise the command falls through to the generic live-output path and
  # floods the terminal with dpkg unpack/configure messages.
  if [[ "${1##*/}" == "apt-get" ||
        ( "${1##*/}" == "env" && " $* " == *" apt-get "* ) ]]; then
    case " $* " in
      *" --download-only "*" install "*) apt_action="downloading packages into the offline cache" ;;
      *" install "*) apt_action="installing packages" ;;
      *" update "*) apt_action="refreshing package indexes" ;;
      *" remove "*|*" purge "*) apt_action="removing packages" ;;
      *) apt_action="processing packages" ;;
    esac
    info "APT: ${apt_action} (quiet mode; dpkg lock timeout ${apt_lock_timeout}s)."
    echo "[INFO]  Full APT command: $*" >&3
    command_output=$(mktemp /tmp/http-infra-apt-output.XXXXXX)
    set +e
    if command -v stdbuf >/dev/null 2>&1; then
      stdbuf -oL -eL "$@" >"$command_output" 2>&1 &
    else
      "$@" >"$command_output" 2>&1 &
    fi
    command_pid=$!
    while kill -0 "$command_pid" 2>/dev/null; do
      sleep 1
      elapsed=$((SECONDS - started_at))
      if (( elapsed > 0 && elapsed % 15 == 0 )); then
        info "APT still ${apt_action}; elapsed ${elapsed}s..."
      fi
    done
    wait "$command_pid"
    command_status=$?
    set -e
    cat "$command_output" >&3

    summary=$(grep -E \
      '^(Need to get|After this operation|Fetched |Download complete|[0-9]+ upgraded,|[0-9]+ packages? can be upgraded)' \
      "$command_output" | tail -n 6 || true)
    if [[ -n "$summary" ]]; then
      while IFS= read -r line; do
        info "APT: $line"
      done <<< "$summary"
    fi
    if (( command_status != 0 )); then
      error "APT failed after $((SECONDS - started_at))s (exit=${command_status}). Last output:"
      tail -n 30 "$command_output" >&2
      error "Full APT output is available in: $log_file"
      rm -f "$command_output"
      return "$command_status"
    fi
    rm -f "$command_output"
    success "APT completed in $((SECONDS - started_at))s: ${apt_action}."
    return 0
  fi

  info "Running: $*"
  info "Live command output follows."

  set +e
  if command -v stdbuf >/dev/null 2>&1; then
    stdbuf -oL -eL "$@" 2>&1 | tee -a "$log_file"
  else
    "$@" 2>&1 | tee -a "$log_file"
  fi
  pipeline_status=("${PIPESTATUS[@]}")
  set -e

  command_status=${pipeline_status[0]:-1}
  tee_status=${pipeline_status[1]:-0}
  if (( tee_status != 0 )); then
    warn "Unable to copy all live command output to log: $log_file"
  fi
  if (( command_status != 0 )); then
    error "Command failed after $((SECONDS - started_at))s (exit=${command_status}): $*"
    return "$command_status"
  fi
  success "Command completed in $((SECONDS - started_at))s."
}

apt_updated=false
local_apt_repo=false
apt_source_file=""
apt_lock_timeout=600

http_file_exists() {
  local url="$1"
  if command -v wget &>/dev/null; then
    wget -q --spider "$url" 2>/dev/null
  elif command -v curl &>/dev/null; then
    curl -fsSIL --max-time 5 "$url" &>/dev/null
  elif [[ -x /usr/lib/apt/apt-helper ]]; then
    local probe
    probe=$(mktemp /tmp/http-infra-http-probe.XXXXXX)
    /usr/lib/apt/apt-helper download-file "$url" "$probe" &>/dev/null
    local result=$?
    rm -f "$probe"
    return "$result"
  else
    return 1
  fi
}

configure_local_apt_repo() {
  if [[ "$mgmt_mode" == "true" && "$offline_mode" == "true" ]]; then
    if [[ ! -s "${apps_dir}/Packages.gz" ]]; then
      error "Offline management repository is missing: ${apps_dir}/Packages.gz"
      return 1
    fi
    repository_meta="${apps_dir}/repository.meta"
    if [[ ! -s "$repository_meta" ]] || \
       ! grep -Fxq 'os_id=ubuntu' "$repository_meta" || \
       ! grep -Fxq "os_version=${VERSION_ID}" "$repository_meta" || \
       ! grep -Fxq "architecture=${arc}" "$repository_meta"; then
      error "Offline repository metadata is missing or mismatched: $repository_meta"
      return 1
    fi
    apt_source_file=$(mktemp /tmp/http-infra-apt-source.XXXXXX)
    printf 'deb [trusted=yes] file:%s ./\n' "$apps_dir" > "$apt_source_file"
    local_apt_repo=true
    success "Offline management APT repository selected: ${apps_dir}/Packages.gz"
    return 0
  fi
  [[ "$mgmt_mode" == "false" && "$local_http_enabled" == "true" && -n "$http_server" ]] || return 0
  if http_file_exists "${http_server}/Packages.gz"; then
    apt_source_file=$(mktemp /tmp/http-infra-apt-source.XXXXXX)
    printf 'deb [trusted=yes] %s ./\n' "${http_server}/" > "$apt_source_file"
    local_apt_repo=true
    success "Local APT repository detected: ${http_server}/Packages.gz"
  else
    info "No local APT repository index found; package installation will use configured Internet repositories."
  fi
}

enable_embedded_doca_repo() {
  [[ "$local_apt_repo" == "true" ]] || return 0
  local doca_source=/etc/apt/sources.list.d/doca.list line
  if [[ ! -r "$doca_source" ]]; then
    error "doca-host did not create the expected APT source: $doca_source"
    return 1
  fi
  while IFS= read -r line; do
    [[ "$line" == deb\ *file:* ]] || continue
    if ! grep -Fxq -- "$line" "$apt_source_file"; then
      printf '%s\n' "$line" >> "$apt_source_file"
    fi
  done < "$doca_source"
  if ! grep -qE '^deb .*file:' "$apt_source_file"; then
    error "No binary DOCA file repository was found in $doca_source"
    return 1
  fi
  apt_updated=false
  success "Embedded DOCA repository enabled for this offline run."
}

apt_get() {
  if [[ "$mgmt_mode" == "true" && "$offline_mode" == "true" ]]; then
    apt_log env DEBIAN_FRONTEND=noninteractive apt-get \
      -o "DPkg::Lock::Timeout=${apt_lock_timeout}" \
      -o "Dir::Etc::sourcelist=${apt_source_file}" \
      -o "Dir::Etc::sourceparts=-" \
      -o "APT::Get::List-Cleanup=0" \
      -o "Dir::Cache::archives=${apps_dir}/" "$@"
  elif [[ "$mgmt_mode" == "true" ]]; then
    apt_log env DEBIAN_FRONTEND=noninteractive apt-get \
      -o "DPkg::Lock::Timeout=${apt_lock_timeout}" \
      -o "Dir::Cache::archives=${apps_dir}/" \
      -o "APT::Keep-Downloaded-Packages=true" \
      -o "Binary::apt-get::APT::Keep-Downloaded-Packages=true" "$@"
  elif [[ "$local_apt_repo" == "true" ]]; then
    apt_log env DEBIAN_FRONTEND=noninteractive apt-get \
      -o "DPkg::Lock::Timeout=${apt_lock_timeout}" \
      -o "Dir::Etc::sourcelist=${apt_source_file}" \
      -o "Dir::Etc::sourceparts=-" \
      -o "APT::Get::List-Cleanup=0" "$@"
  else
    apt_log env DEBIAN_FRONTEND=noninteractive apt-get \
      -o "DPkg::Lock::Timeout=${apt_lock_timeout}" "$@"
  fi
}

refresh_mgmt_repository() {
  [[ "$mgmt_mode" == "true" ]] || return 0
  (
    cd "$apps_dir"
    packages_tmp=$(mktemp .Packages.XXXXXX)
    for deb in ./*.deb; do
      [[ -f "$deb" ]] || continue
      dpkg-deb -f "$deb"
      printf 'Filename: ./%s\n' "${deb#./}"
      printf 'Size: %s\n' "$(stat -c %s "$deb")"
      printf 'MD5sum: %s\n' "$(md5sum "$deb" | awk '{print $1}')"
      printf 'SHA256: %s\n\n' "$(sha256sum "$deb" | awk '{print $1}')"
    done > "$packages_tmp"
    gzip -9c "$packages_tmp" > "${packages_tmp}.gz"
    mv -f "$packages_tmp" Packages
    mv -f "${packages_tmp}.gz" Packages.gz
    repository_meta_tmp=$(mktemp .repository.meta.XXXXXX)
    {
      printf 'schema_version=1\n'
      printf 'os_id=ubuntu\n'
      printf 'os_version=%s\n' "$VERSION_ID"
      printf 'architecture=%s\n' "$arc"
      printf 'generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$repository_meta_tmp"
    mv -f "$repository_meta_tmp" repository.meta
  ) >&3 2>&3
  chmod 0644 "$apps_dir"/*.deb "$apps_dir/Packages" "$apps_dir/Packages.gz" \
    "$apps_dir/repository.meta" 2>/dev/null || true
  rm -f "$apps_dir/lock"
  success "Local APT repository refreshed: $apps_dir/Packages.gz"
}

apt_update_once() {
  if [[ "$apt_updated" != "true" ]]; then
    info "Refreshing APT package indexes from the configured repositories..."
    apt_get update
    apt_updated=true
  fi
}

apt_install() {
  apt_get install -y "$@"
  refresh_mgmt_repository
}

cache_mgmt_package_closure() {
  [[ "$mgmt_mode" == "true" ]] || return 0
  local status_file
  status_file=$(mktemp /tmp/http-infra-empty-status.XXXXXX)
  : > "$status_file"
  info "Caching complete package closure for offline clients: $*"
  if ! apt_log apt-get \
    -o "DPkg::Lock::Timeout=${apt_lock_timeout}" \
    -o "Dir::State::status=${status_file}" \
    -o "Dir::Cache::archives=${apps_dir}/" \
    -o "APT::Keep-Downloaded-Packages=true" \
    -o "Binary::apt-get::APT::Keep-Downloaded-Packages=true" \
    --download-only install -y "$@"; then
    rm -f "$status_file"
    return 1
  fi
  rm -f "$status_file"
  refresh_mgmt_repository
}

ensure_doca_host_package() {
  local destination="$1" source_url part package_name package_version package_arch
  if [[ -f "$destination" ]]; then
    package_name=$(dpkg-deb -f "$destination" Package 2>/dev/null || true)
    package_version=$(dpkg-deb -f "$destination" Version 2>/dev/null || true)
    package_arch=$(dpkg-deb -f "$destination" Architecture 2>/dev/null || true)
    if [[ "$package_name" == "doca-host" && \
          "$package_version" == "$doca_package_version" && \
          "$package_arch" == "$arc" ]]; then
      success "Reusing verified DOCA host package: $destination"
      return 0
    fi
    warn "Existing DOCA host package is invalid or mismatched; replacing: $destination"
  fi

  if [[ "$offline_mode" == "true" ]]; then
    error "Offline mode requires a verified packaged DOCA host file: $destination"
    return 1
  fi

  if [[ "$local_http_enabled" == "true" && -n "$http_server" ]] && \
     http_file_exists "${http_server}/${doca_package}"; then
    source_url="${http_server}/${doca_package}"
  else
    source_url="$doca_path"
  fi
  part=$(mktemp "${destination}.part.XXXXXX")
  info "Downloading $doca_package from: $source_url"
  if ! apt_log wget -q "$source_url" -O "$part"; then
    rm -f "$part"
    error "Failed to download DOCA host package: $source_url"
    return 1
  fi
  package_name=$(dpkg-deb -f "$part" Package 2>/dev/null || true)
  package_version=$(dpkg-deb -f "$part" Version 2>/dev/null || true)
  package_arch=$(dpkg-deb -f "$part" Architecture 2>/dev/null || true)
  if [[ "$package_name" != "doca-host" || \
        "$package_version" != "$doca_package_version" || \
        "$package_arch" != "$arc" ]]; then
    rm -f "$part"
    error "Downloaded DOCA host package failed metadata validation"
    return 1
  fi
  chmod 0644 "$part"
  mv -f "$part" "$destination"
  success "DOCA host package downloaded and verified: $destination"
}

backup_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    local existing
    for existing in "${file}".http-infra.bak.*; do
      if [[ -f "$existing" ]]; then
        info "Original backup already exists: $existing"
        return
      fi
    done
    local backup
    backup="${file}.http-infra.bak.$(date +%Y%m%d_%H%M%S)"
    cp -p "$file" "$backup"
    info "Backed up: $file → $backup"
  fi
}

# ─── Preflight checks ─────────────────────────────────────────────────────────
print_section "Preflight Checks"

success "OS check passed: $PRETTY_NAME (${arc})"
info "APT repository scope: ${repo_relative_path}"

# sudo resolves the local kernel hostname before running a command.  Minimal
# AIR/cloud images sometimes set /etc/hostname without adding the same name to
# /etc/hosts, which produces `sudo: unable to resolve host ...` on every ZTP
# operation.  Keep this setup-owned and reversible through infra-teardown.sh.
local_hostname=$(hostname 2>/dev/null || true)
if [[ -n "$local_hostname" ]] && getent hosts "$local_hostname" &>/dev/null; then
  success "Local hostname resolves correctly: $local_hostname"
elif [[ -n "$local_hostname" ]]; then
  short_hostname=${local_hostname%%.*}
  track_managed_file /etc/hosts
  if [[ "$short_hostname" == "$local_hostname" ]]; then
    printf '127.0.1.1\t%s\n' "$local_hostname" >> /etc/hosts
  else
    printf '127.0.1.1\t%s %s\n' "$local_hostname" "$short_hostname" >> /etc/hosts
  fi
  if getent hosts "$local_hostname" &>/dev/null; then
    success "Added local hostname mapping to /etc/hosts: $local_hostname"
  else
    error "Local hostname still cannot be resolved after updating /etc/hosts: $local_hostname"
    exit 1
  fi
else
  warn "Kernel hostname is empty; skipping local hostname resolution check."
fi

if [[ "$mgmt_mode" == "true" ]]; then
  http_root_mode=$(stat -c '%a' "$mgmt_http_root" 2>/dev/null || true)
  if [[ "$http_root_mode" != "755" ]]; then
    warn "HTTP document root $mgmt_http_root has mode ${http_root_mode:-unknown}; setting 0755 for Apache traversal."
    chmod 0755 "$mgmt_http_root"
    success "HTTP document root permissions set to 0755."
  else
    success "HTTP document root permissions already allow Apache traversal."
  fi
fi

if [[ "$mgmt_mode" == "true" ]]; then
  if [[ "$offline_mode" == "true" ]]; then
    if [[ -s "${apps_dir}/Packages.gz" ]]; then
      success "Packaged offline APT repository found: ${apps_dir}/Packages.gz"
    else
      error "Packaged offline APT repository is missing: ${apps_dir}/Packages.gz"
      exit 1
    fi
  elif [[ -n "$http_server" ]] && http_file_exists "${http_server}/Packages.gz"; then
    success "Existing local APT repository is reachable: ${http_server}/Packages.gz"
  else
    info "Local APT repository is not published yet; management mode will build it from configured APT sources."
  fi
elif [[ "$local_http_enabled" == "true" ]]; then
  if http_file_exists "${http_server}/Packages.gz"; then
    success "Local APT repository is reachable: ${http_server}/Packages.gz"
  else
    warn "Local APT repository became unavailable; this run will use Internet downloads directly."
    local_http_enabled=false
  fi
else
  info "Local HTTP download is disabled; Internet sources will be used directly."
fi

configure_local_apt_repo
if [[ "$mgmt_mode" == "true" ]]; then
  info "Management cache mode enabled; package repository directory: $apps_dir"
  apt_update_once
  if [[ "$offline_mode" == "true" ]]; then
    success "Offline mode: reusing the packaged repository without Internet downloads."
  else
    cache_mgmt_package_closure "${mgmt_cache_packages[@]}"
  fi
fi

# ─── Step 1: DNS via systemd-resolved ─────────────────────────────────────────
systemd_unit_load_state() {
  if ! systemd_is_operational; then
    printf 'not-found\n'
    return 0
  fi
  systemctl show --property=LoadState --value "$1" 2>/dev/null || true
}

systemd_is_operational() {
  command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]
}

restart_systemd_service() {
  local unit="$1"
  if ! systemd_is_operational; then
    warn "systemd is not running; configuration for $unit was written but service restart was skipped."
    return 0
  fi
  systemctl restart "$unit"
}

current_timezone_name() {
  local value=""
  if command -v timedatectl &>/dev/null && systemd_is_operational; then
    value=$(timedatectl show -p Timezone --value 2>/dev/null || true)
  fi
  if [[ -z "$value" && -s /etc/timezone ]]; then
    value=$(head -n 1 /etc/timezone | xargs || true)
  fi
  if [[ -z "$value" && -L /etc/localtime ]]; then
    value=$(readlink -f /etc/localtime 2>/dev/null || true)
    value=${value#/usr/share/zoneinfo/}
  fi
  printf '%s\n' "$value"
}

apply_timezone() {
  local zone="$1"
  if [[ ! -f "/usr/share/zoneinfo/$zone" ]]; then
    error "Unknown timezone: $zone"
    return 1
  fi
  if command -v timedatectl &>/dev/null && systemd_is_operational; then
    timedatectl set-timezone "$zone"
  else
    ln -snf "/usr/share/zoneinfo/$zone" /etc/localtime
    printf '%s\n' "$zone" > /etc/timezone
    warn "systemd/timedatectl is unavailable; timezone was applied through /etc/localtime and /etc/timezone."
  fi
}

systemd_unit_is_missing() {
  local load_state
  load_state=$(systemd_unit_load_state "$1")
  [[ -z "$load_state" || "$load_state" == "not-found" ]]
}

print_section "Step 1: DNS Configuration"
if systemd_unit_is_missing systemd-resolved.service; then
  warn "systemd-resolved.service is not installed; skipping managed DNS configuration."
else
  desired_dns="${dns_servers[*]}"
  current_dns=$(grep -E '^\s*DNS\s*=' /etc/systemd/resolved.conf 2>/dev/null \
    | head -1 | sed 's/.*=//' | xargs || true)
  if [[ "$current_dns" == "$desired_dns" ]]; then
    success "DNS already matches desired configuration."
  else
    info "Setting DNS servers: $desired_dns"
    track_managed_file /etc/systemd/resolved.conf
    dns_line="DNS=${desired_dns}"
    if grep -qE '^\s*#?\s*DNS\s*=' /etc/systemd/resolved.conf; then
      sed -i "s|^\s*#\?\s*DNS\s*=.*|${dns_line}|" /etc/systemd/resolved.conf
    else
      echo "$dns_line" >> /etc/systemd/resolved.conf
    fi
    if ! systemctl restart systemd-resolved.service; then
      error "Unable to restart systemd-resolved.service."
      exit 1
    fi
    success "DNS configured and systemd-resolved restarted."
  fi
fi

# ─── Step 2: NTP via systemd-timesyncd ────────────────────────────────────────
print_section "Step 2: NTP Configuration"
timesyncd_unit_state=""
if systemd_is_operational; then
  timesyncd_unit_state=$(systemctl is-enabled systemd-timesyncd.service 2>/dev/null || true)
fi
if [[ "$timesyncd_unit_state" == "masked" ]]; then
  if [[ ! -f "$timesyncd_unit_state_file" ]]; then
    printf 'masked\n' > "$timesyncd_unit_state_file"
    chmod 0600 "$timesyncd_unit_state_file"
  fi
  warn "systemd-timesyncd.service is masked; temporarily unmasking it for managed NTP."
  if ! systemctl unmask systemd-timesyncd.service; then
    error "Unable to unmask systemd-timesyncd.service."
    exit 1
  fi
fi

if systemd_unit_is_missing systemd-timesyncd.service; then
  warn "systemd-timesyncd.service is not installed; skipping managed NTP configuration."
else
  desired_ntp="${ntp_servers[*]}"
  current_ntp=$(grep -E '^\s*NTP\s*=' /etc/systemd/timesyncd.conf 2>/dev/null \
    | head -1 | sed 's/.*=//' | xargs || true)
  if [[ "$current_ntp" == "$desired_ntp" ]]; then
    success "NTP already matches desired configuration."
  else
    info "Setting NTP servers: $desired_ntp"
    track_managed_file /etc/systemd/timesyncd.conf
    ntp_line="NTP=${desired_ntp}"
    if grep -qE '^\s*#?\s*NTP\s*=' /etc/systemd/timesyncd.conf; then
      sed -i "s|^\s*#\?\s*NTP\s*=.*|${ntp_line}|" /etc/systemd/timesyncd.conf
    else
      echo "$ntp_line" >> /etc/systemd/timesyncd.conf
    fi
    success "NTP configuration updated."
  fi

  if [[ "$timesyncd_unit_state" == "masked" ]]; then
    if ! systemctl enable --now systemd-timesyncd.service; then
      error "Unable to enable systemd-timesyncd.service after unmasking; check for another conflicting NTP daemon."
      exit 1
    fi
    success "systemd-timesyncd unmasked, enabled and started."
  else
    if ! systemctl restart systemd-timesyncd.service; then
      error "Unable to restart systemd-timesyncd.service (unit state: ${timesyncd_unit_state:-unknown})."
      exit 1
    fi
    success "systemd-timesyncd restarted."
  fi
fi

# ─── Step 3: Timezone and clock sync ──────────────────────────────────────────
print_section "Step 3: Timezone & Clock Sync"
if [[ ! -f "/usr/share/zoneinfo/$time_zone" ]]; then
  if dpkg -s tzdata &>/dev/null; then
    error "tzdata is installed but timezone data is missing: $time_zone"
    exit 1
  fi
  info "Timezone database is not installed; installing tzdata..."
  begin_package_install tzdata
  apt_update_once
  apt_install tzdata
  commit_package_install tzdata
fi
current_timezone=$(current_timezone_name)
if [[ "$current_timezone" == "$time_zone" ]]; then
  success "Timezone already matches desired configuration."
else
  if [[ ! -f "$timezone_state_file" ]]; then
    printf '%s\n' "$current_timezone" > "$timezone_state_file"
  fi
  info "Setting timezone to $time_zone..."
  apply_timezone "$time_zone"
  success "Timezone set."
fi

if command -v timedatectl &>/dev/null && systemd_is_operational; then
  info "Current timedatectl status:"
  while IFS= read -r line; do logecho "$line"; done < <(timedatectl status)
else
  info "Current timezone: $(current_timezone_name) (systemd unavailable)"
fi

# ─── Step 4: lldpd ────────────────────────────────────────────────────────────
print_section "Step 4: lldpd"
lldpcli_conf="/etc/lldpd.d/lldpcli.conf"

write_lldpcli_conf() {
  mkdir -p /etc/lldpd.d
  track_managed_file "$lldpcli_conf"
  cat > "$lldpcli_conf" << 'EOF'
configure system hostname .
configure lldp portidsubtype ifname
configure system interface pattern eth*,eno*,enp*,ens*,enP*
EOF
  success "lldpd configuration written: $lldpcli_conf"
}

expected_lldpcli_conf=$'configure system hostname .\nconfigure lldp portidsubtype ifname\nconfigure system interface pattern eth*,eno*,enp*,ens*,enP*'
if dpkg -s lldpd &>/dev/null; then
  success "lldpd is already installed."
  if [[ -f "$lldpcli_conf" ]] && [[ "$(cat "$lldpcli_conf")" == "$expected_lldpcli_conf" ]]; then
    success "$lldpcli_conf already matches desired configuration."
  else
    info "$lldpcli_conf differs from desired configuration, updating..."
    write_lldpcli_conf
    restart_systemd_service lldpd
    success "lldpd configuration applied."
  fi
else
  info "lldpd not found, installing..."
  begin_package_install lldpd
  apt_update_once
  apt_install lldpd
  commit_package_install lldpd
  write_lldpcli_conf
  restart_systemd_service lldpd
  success "lldpd installed and configuration applied."
fi

# ─── Step 5: Mellanox / DOCA-OFED ─────────────────────────────────────────────
print_section "Step 5: Mellanox NIC & DOCA-OFED"
has_mellanox=false
if lspci 2>/dev/null | grep -qi mellanox; then
  has_mellanox=true
fi

process_doca=$has_mellanox
if $skip_doca; then
  process_doca=false
  warn "DOCA handling explicitly skipped by --skip-doca."
elif ! $has_mellanox; then
  if [[ "$mgmt_mode" == "true" ]]; then
    if [[ "$offline_mode" == "true" ]]; then
      warn "No Mellanox NIC detected; offline mode will not attempt a DOCA download/cache."
      process_doca=false
    else
      doca_confirmation_mode="$doca_mode"
      if [[ "$doca_confirmation_mode" == "ask" && \
            ( "$non_interactive" == "true" || ! -t 0 ) ]]; then
        doca_confirmation_mode="yes"
        info "No interactive terminal; applying the default DOCA cache action."
      fi
      if confirm_action "$doca_confirmation_mode" \
        "No Mellanox NIC detected. Download and cache DOCA packages for offline clients?" \
        "$doca_prompt_timeout" yes; then
        process_doca=true
        info "DOCA download/cache enabled without a local Mellanox NIC."
      else
        warn "No Mellanox NIC detected; skipping DOCA download and cache."
      fi
    fi
  else
    warn "No Mellanox NIC detected, skipping DOCA-OFED installation."
  fi
fi

if ! $process_doca; then
  bluefield_mode_changed=false
  changed_mst_devices=()
else
  # wget is required by the DOCA path and is not guaranteed on minimal Ubuntu images.
  if ! command -v wget &>/dev/null; then
    info "DOCA cache/install requires wget; installing required download tool..."
    begin_package_install wget
    apt_update_once
    apt_install wget
    commit_package_install wget
    success "wget installed."
  fi

  doca_host_preexisting=false
  if [[ "$(dpkg-query -W -f='${db:Status-Status}' doca-host 2>/dev/null || true)" == "installed" ]]; then
    doca_host_preexisting=true
  fi
  if [[ "$mgmt_mode" == "true" ]]; then
    doca_tmp="${apps_dir}/${doca_package}"
  else
    doca_tmp="/tmp/${doca_package}"
  fi
  ensure_doca_host_package "$doca_tmp"
  if ! $doca_host_preexisting; then begin_package_install doca-host; fi
  if apt_get install -y "$doca_tmp"; then
    refresh_mgmt_repository
  else
    warn "doca-host installation command failed; checking package state before aborting"
  fi
  if [[ "$(dpkg-query -W -f='${db:Status-Status}' doca-host 2>/dev/null || true)" != "installed" ]]; then
    error "doca-host installation could not be verified."
    exit 1
  elif ! $doca_host_preexisting; then
    commit_package_install doca-host
  fi
  enable_embedded_doca_repo

  # The doca-host package registers its embedded repository.  Resolve the
  # complete doca-ofed closure even when mgmt already has OFED installed.
  if [[ "$mgmt_mode" == "true" ]]; then
    apt_updated=false
    apt_update_once
    if [[ "$offline_mode" == "true" ]]; then
      success "Offline mode: using the packaged DOCA closure without new downloads."
    else
      cache_mgmt_package_closure doca-ofed
    fi
  fi

  if ! $has_mellanox; then
    success "DOCA-OFED package closure cached for Mellanox-equipped offline clients; no local Mellanox NIC detected, so doca-ofed was not installed on this management host."
  elif dpkg -s doca-ofed &>/dev/null; then
    success "doca-ofed is already installed."
  else
    info "Mellanox NIC detected. Installing DOCA-OFED..."
    begin_package_install doca-ofed
    apt_update_once
    apt_install doca-ofed
    commit_package_install doca-ofed
    success "doca-ofed installed."
  fi
  if [[ "$mgmt_mode" != "true" ]]; then
    rm -f "$doca_tmp"
  fi

  # ── Bluefield mode check ──────────────────────────────────────────────────
  bluefield_mode_changed=false

  # Collect all BF3 PCI addresses (function 0 only)
  mapfile -t bf_pci_list < <(lspci 2>/dev/null \
    | grep -i "MT43244 BlueField" \
    | grep -E "[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.0" \
    | awk '{print $1}' || true)

  if [[ ${#bf_pci_list[@]} -eq 0 ]]; then
    info "No BlueField-3 device detected, skipping mode check."
  elif ! command -v mst &>/dev/null; then
    warn "mst tool not found, skipping Bluefield mode check."
  else
    info "Found ${#bf_pci_list[@]} BlueField-3 device(s): ${bf_pci_list[*]}"

    # Step 1: generate mst device files
    mst start &>/dev/null || true
    mst_status_output=$(mst status 2>/dev/null || true)

    for pci_addr in "${bf_pci_list[@]}"; do
      info "── Processing BF3 at PCI $pci_addr ──"

      # Step 2: find mst device by matching PCI address in mst status output
      mst_dev=$(echo "$mst_status_output" \
        | grep -C1 "$pci_addr" \
        | grep -oE '/dev/mst/mt[0-9a-zA-Z_]+' | head -1 || true)

      if [[ -z "$mst_dev" ]]; then
        warn "No mst device found for PCI $pci_addr, skipping."
        continue
      fi
      info "Using mst device: $mst_dev"

      # Step 3: read INTERNAL_CPU_OFFLOAD_ENGINE
      offload=$(mlxconfig -d "$mst_dev" q 2>/dev/null \
        | grep -i "INTERNAL_CPU_OFFLOAD_ENGINE" | awk '{print $NF}' || true)
      info "INTERNAL_CPU_OFFLOAD_ENGINE = ${offload:-unknown}"

      if [[ "${offload^^}" == "ENABLED(0)" ]]; then
        warn "BF3 [$pci_addr] is in DPU mode (INTERNAL_CPU_OFFLOAD_ENGINE=ENABLED(0))."
        if confirm_action "$bluefield_mode" "Change BF3 [$pci_addr] from DPU to NIC mode?" "$prompt_timeout" yes; then
          mlxconfig -d "$mst_dev" -y set INTERNAL_CPU_OFFLOAD_ENGINE=1 >&3 2>&3
          success "BF3 [$pci_addr] mode set to NIC (INTERNAL_CPU_OFFLOAD_ENGINE=DISABLED(1))."
          success "Power cycle required to take effect."
          bluefield_mode_changed=true
          changed_mst_devices+=("$mst_dev")
        else
          info "Skipping BF3 [$pci_addr] mode change."
        fi
      elif [[ "${offload^^}" == "DISABLED(1)" ]]; then
        success "BF3 [$pci_addr] is already in NIC mode (INTERNAL_CPU_OFFLOAD_ENGINE=DISABLED(1)), no change needed."
      else
        warn "BF3 [$pci_addr] mode undetermined (value: ${offload:-unknown}), skipping."
      fi
    done
  fi
fi

# ─── Step 6: Common tools ─────────────────────────────────────────────────────
print_section "Step 6: Common Tools"
packages_to_install=()
for pkg in "${common_packages[@]}"; do
  if ! dpkg -s "$pkg" &>/dev/null; then
    packages_to_install+=("$pkg")
  else
    success "$pkg is already installed."
  fi
done

if [[ ${#packages_to_install[@]} -gt 0 ]]; then
  info "Installing: ${packages_to_install[*]}"
  for pkg in "${packages_to_install[@]}"; do begin_package_install "$pkg"; done
  apt_update_once
  apt_install "${packages_to_install[@]}"
  for pkg in "${packages_to_install[@]}"; do
    commit_package_install "$pkg"
  done
  success "Packages installed: ${packages_to_install[*]}"
fi

# ─── Step 7: ZTP dependencies and optional services ─────────────────────────
print_section "Step 7: ZTP Dependencies & Optional Services"

if [[ "$mgmt_mode" == "true" ]]; then
  ztp_packages_to_install=()
  for pkg in "${ztp_dependency_packages[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
      ztp_packages_to_install+=("$pkg")
    else
      success "$pkg is already installed."
    fi
  done

  if [[ ${#ztp_packages_to_install[@]} -gt 0 ]]; then
    info "Installing ZTP dependencies: ${ztp_packages_to_install[*]}"
    for pkg in "${ztp_packages_to_install[@]}"; do begin_package_install "$pkg"; done
    apt_update_once
    apt_install "${ztp_packages_to_install[@]}"
    for pkg in "${ztp_packages_to_install[@]}"; do
      commit_package_install "$pkg"
    done
    success "ZTP dependencies installed: ${ztp_packages_to_install[*]}"
  else
    success "All ZTP dependencies are already installed."
  fi

else
  info "Client mode: ZTP generation and analysis dependencies are not required; skipping."
fi

if dpkg -s apache2 &>/dev/null; then
  success "apache2 is already installed."
  if confirm_action "$apache_mode" "Configure existing apache2?" "$prompt_timeout" no; then
    configure_apache2=true
  else
    configure_apache2=false
    info "Skipping apache2 configuration."
  fi
else
  if confirm_action "$apache_mode" "Install and configure apache2?" "$prompt_timeout" no; then
    configure_apache2=true
  else
    configure_apache2=false
    info "Skipping apache2 installation."
  fi
fi

if [[ "$configure_apache2" == "true" ]]; then
  if [[ "$mgmt_mode" != "true" ]]; then
    error "Authenticated Monitor Apache configuration requires --mgmt and its canonical control-auth helper."
    exit 1
  fi
  apache_packages_to_install=()
  for pkg in apache2 apache2-utils ssl-cert; do
    if ! dpkg -s "$pkg" &>/dev/null; then
      apache_packages_to_install+=("$pkg")
    fi
  done
  if [[ ${#apache_packages_to_install[@]} -gt 0 ]]; then
    for pkg in "${apache_packages_to_install[@]}"; do
      begin_package_install "$pkg"
    done
    apt_update_once
    apt_install "${apache_packages_to_install[@]}"
    for pkg in "${apache_packages_to_install[@]}"; do
      commit_package_install "$pkg"
    done
  fi

  for pkg in apache2 apache2-utils ssl-cert; do
    if ! dpkg -s "$pkg" &>/dev/null; then
      error "Required Apache package is unavailable after installation: $pkg"
      exit 1
    fi
  done

  info "Configuring apache2..."
  if systemd_is_operational && systemctl is-active --quiet apache2; then
    systemctl stop apache2
    warn "Stopped Apache before replacing its authenticated Monitor boundary."
  fi
  install_control_auth_helper
  track_managed_file /etc/apache2/conf-available/servername.conf
  server_name=$(hostname -f 2>/dev/null || hostname)
  echo "ServerName ${server_name}" > /etc/apache2/conf-available/servername.conf
  a2enconf servername >&3 2>&3
  for module in "${apache_auth_modules[@]}"; do
    a2enmod "$module" >&3 2>&3
  done

  # Native Apache has no authority until load publishes the current project's
  # exact service-IPv4 listeners.  Disable both distro wildcard sources first.
  track_managed_file /etc/apache2/ports.conf
  ports_candidate=$(mktemp "${apache_ports_conf}.tmp.XXXXXX")
  cat > "$ports_candidate" <<'EOF'
# Managed by http/infra/infra-setup.sh.
# DAY0-Prepare/11-load.py owns every exact service-IPv4 Listen directive.
EOF
  chmod 0644 "$ports_candidate"
  chown root:root "$ports_candidate"
  mv -f -- "$ports_candidate" "$apache_ports_conf"

  if [[ -L /etc/apache2/sites-enabled/000-default.conf ]]; then
    printf 'enabled\n' > "$apache_default_site_state"
  elif [[ ! -e /etc/apache2/sites-enabled/000-default.conf ]]; then
    printf 'disabled\n' > "$apache_default_site_state"
  else
    error "Unsafe non-symlink Apache default-site authority."
    exit 1
  fi
  chmod 0600 "$apache_default_site_state"
  a2dissite 000-default >&3 2>&3 || true

  if [[ -L "$apache_listener_conf" || ( -e "$apache_listener_conf" && ! -f "$apache_listener_conf" ) ]]; then
    error "Unsafe Apache exact-listener authority: $apache_listener_conf"
    exit 1
  fi
  track_managed_file "$apache_listener_conf"
  rm -f -- "$apache_listener_conf"

  install_apache_publication_boundary
  apache2ctl configtest >&3 2>&3

  success "apache2 wildcard listeners disabled; service activation deferred until load publishes exact listeners."
fi

if dpkg -s isc-dhcp-server &>/dev/null; then
  success "isc-dhcp-server is already installed."
  if confirm_action "$dhcp_mode" "Configure existing isc-dhcp-server (stop and disable service)?" "$prompt_timeout" no; then
    info "Stopping isc-dhcp-server (disabled by default)..."
    if systemd_is_operational; then
      systemctl stop isc-dhcp-server || true
      systemctl disable isc-dhcp-server || true
    else
      warn "systemd is not running; isc-dhcp-server stop/disable was skipped."
    fi
    success "isc-dhcp-server stopped and disabled."
  else
    info "Skipping isc-dhcp-server configuration."
  fi
else
  if confirm_action "$dhcp_mode" "Install isc-dhcp-server?" "$prompt_timeout" no; then
    info "Installing isc-dhcp-server..."
    begin_package_install isc-dhcp-server
    apt_update_once
    apt_install isc-dhcp-server
    commit_package_install isc-dhcp-server

    info "Stopping isc-dhcp-server (disabled by default)..."
    if systemd_is_operational; then
      systemctl stop isc-dhcp-server || true
      systemctl disable isc-dhcp-server || true
    else
      warn "systemd is not running; isc-dhcp-server stop/disable was skipped."
    fi
    success "isc-dhcp-server stopped and disabled."
  else
    info "Skipping isc-dhcp-server installation."
  fi
fi

if [[ "$mgmt_mode" == "true" ]]; then
  if [[ -n "$http_server" ]] && http_file_exists "${http_server}/Packages.gz"; then
    local_http_enabled=true
    success "Published APT repository verified: ${http_server}/Packages.gz"
  else
    local_http_enabled=false
    warn "APT files were generated in $apps_dir, but ${http_server:-<unset>}/Packages.gz is not reachable."
  fi
fi

logecho ""
success "infra-setup.sh completed successfully."

# ─── Summary ──────────────────────────────────────────────────────────────────
print_section "SUMMARY"

logecho ""
logecho "── Installed packages ──────────────────────────────────"
for pkg in "${mgmt_cache_packages[@]}" doca-host doca-ofed; do
  if dpkg -s "$pkg" &>/dev/null; then
    logecho "  [+] $pkg"
  fi
done

logecho ""
logecho "── Modified / created files ────────────────────────────"
for f in \
  /etc/systemd/resolved.conf \
  /etc/systemd/timesyncd.conf \
  /etc/lldpd.d/lldpcli.conf \
  /etc/apache2/conf-available/servername.conf \
  /etc/apache2/ports.conf \
  /etc/apache2/conf-enabled/http-ztp-listeners.conf \
  /etc/apache2/conf-enabled/http-ztp-public-boundary.conf \
  /etc/apache2/sites-enabled/000-default.conf; do
  if [[ -f "$f" ]]; then
    logecho "  [*] $f"
    for bak in "${f}".http-infra.bak.*; do
      [[ -f "$bak" ]] && logecho "       backup: $bak"
    done
  fi
done

logecho ""
logecho "── System settings ─────────────────────────────────────"
logecho "  Timezone : $(current_timezone_name)"
logecho "  DNS      : $(grep -E '^\s*DNS\s*=' /etc/systemd/resolved.conf 2>/dev/null | head -1 | sed 's/.*=//' | xargs || echo 'not set')"
logecho "  NTP      : $(grep -E '^\s*NTP\s*=' /etc/systemd/timesyncd.conf 2>/dev/null | head -1 | sed 's/.*=//' | xargs || echo 'not set')"
logecho "  Local APT: $local_http_enabled (${http_server:-not configured})"
logecho "  Log file : $log_file"
logecho ""

# ─── Bluefield power cycle reminder ───────────────────────────────────────────
if [[ "${bluefield_mode_changed:-false}" == "true" ]]; then
  logecho ""
  logecho "╔══════════════════════════════════════════════════════╗"
  logecho "║           ⚠  POWER CYCLE REQUIRED  ⚠               ║"
  logecho "╚══════════════════════════════════════════════════════╝"
  warn "Bluefield mode was changed to NIC. The change takes effect only after"
  warn "a full server power cycle (not just reboot)."
  logecho ""
  if confirm_action "$power_cycle_mode" "Perform power cycle now?" "$prompt_timeout" yes; then
    success "Power cycle command will be executed."
    info "To verify Bluefield mode after next boot:"
    logecho "  mst start && mst status"
    for mst_dev in "${changed_mst_devices[@]}"; do
      logecho "  mlxconfig -d $mst_dev q | grep INTERNAL_CPU_OFFLOAD_ENGINE"
    done
    logecho "  ENABLED(0) = DPU mode, DISABLED(1) = NIC mode"
    logecho ""
    ipmitool chassis power cycle
  else
    warn "Power cycle skipped. Run the following command manually when ready:"
    logecho ""
    logecho "  ipmitool chassis power cycle"
    logecho ""
    info "To verify Bluefield mode after next boot:"
    logecho "  mst start && mst status"
    for mst_dev in "${changed_mst_devices[@]}"; do
      logecho "  mlxconfig -d $mst_dev q | grep INTERNAL_CPU_OFFLOAD_ENGINE"
    done
    logecho "  ENABLED(0) = DPU mode, DISABLED(1) = NIC mode"
    logecho ""
  fi
fi

mark_run_complete
setup_status=completed
echo "[$(date '+%Y-%m-%d %H:%M:%S')] infra-setup.sh finished" >&3
