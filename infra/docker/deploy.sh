#!/usr/bin/env bash
# Build and operate the Ubuntu 24.04 host-network ZTP service container.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
runtime_env="$script_dir/infra-runtime.conf"
compose_file="$script_dir/compose.yaml"
image_name="http-ztp:ubuntu-24.04"
MONITOR_AUTHORITY_RECOVERY_WARNING='WARNING: explicit Monitor authority recovery reset invalid cache state; review the accepted www-data denial residual.'
container_name="http-ztp"
lock_wait="${HTTP_ZTP_LOCK_WAIT:-600}"
started_container_id=""
host_architecture=""
image_export_stage=""
image_export_parent=""
image_export_prefix=""
image_export_parent_dev=""
image_export_parent_ino=""
image_export_stage_dev=""
image_export_stage_ino=""

say() {
  printf '%s\n' "$*"
}

fail() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Usage: sudo ./infra/docker/deploy.sh ACTION

Actions:
  init [--project NAME --scope air|prod [OPTIONS]]
            Create the excluded infra-runtime.conf; without options, retain
            the neutral-template compatibility mode
  doctor    Validate Ubuntu, Docker, project mount, and host port ownership
  recover-monitor-authority
            Stop/remove the owned container, then explicitly repair invalid
            Monitor cache content; leaves the container stopped
  build     Build the Ubuntu 24.04 image (plain Docker CLI)
  image-export OUTPUT_DIR
            Build, verify, and export one project-independent image bundle
  build-export OUTPUT_DIR
            Compatibility alias for image-export
  deploy [--no-upgrade]
            Build, recreate inactive, run load, activate, and health-check
  deploy-preloaded IMAGE_ID [--no-upgrade]
            Verify an already-loaded immutable image, then deploy without build
  deploy-project-preloaded IMAGE_ID [--no-upgrade]
            Verify one bootstrap-installed project image for the configured
            project, then recreate, load, activate, and health-check it
  load      After no source write, run transactional 11-load in the running
            owned container and converge managed services under Supervisor
  reload-network
            Rebind an active generation after moving the same service IP to
            another interface; never regenerate project or DHCP artifacts
  rotate-auth USER
            Rotate exactly nvis or cumulus without exposing the password in
            argv, environment, or Docker logs; requires a human at the
            management-server terminal and cannot run unattended
  unload [--yes]
            Clear activation, then run transactional 13-unload --yes
  down [--yes]
            Clear activation and remove only the named container; keep data
  health    Run the active-runtime health contract
  status    Show Docker, Supervisor, dynamic plan, and activation state
  logs      Follow container stdout/stderr

Init OPTIONS:
  --project NAME                 Direct child of DAY0-Prepare (required)
  --scope air|prod               Deployment scope (required)
  --switch eth|ib|nvl|all        Defaults to eth for AIR and all for prod
  --mini                          AIR/Ethernet mini-device selection
  --monitor-interval SECONDS     5..86400; defaults to 30
  --dhcp-interface-allowlist NAMES
  --dhcp-relay-ingress NAMES     Comma/space-separated interface names
  --timezone IANA/NAME           Defaults to Asia/Shanghai

The host supports Ubuntu 22.04 and 24.04 on arm64 and amd64; the managed
container remains Ubuntu 24.04.  Listener count is always derived from project data plus current Linux
interfaces; this wrapper never modifies interface or Netplan configuration.

Docker Compose is optional.  If `docker compose` is unavailable, deploy uses
the equivalent plain `docker build`, `docker run`, and `docker exec` commands.
EOF
}

require_root() {
  [[ "$(id -u)" == "0" ]] || fail "run this wrapper with sudo/root"
}

host_preflight() {
  require_root
  [[ -r /etc/os-release ]] || fail "cannot read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04)
      host_os_version=$VERSION_ID
      ;;
    *)
      fail "this runtime requires Ubuntu 22.04 or 24.04"
      ;;
  esac
  command -v docker >/dev/null 2>&1 || fail "Docker CLI is not installed"
  command -v python3 >/dev/null 2>&1 || fail "Python 3 is not installed"
  command -v ss >/dev/null 2>&1 || fail \
    "ss is not installed; install the Ubuntu iproute2 package"
  python3 "$script_dir/hostlock.py" --validate-local-daemon ||
    fail "Docker must be the local rootful daemon on /var/run/docker.sock"
  case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
    arm64|aarch64)
      host_architecture=arm64
      say "[OK] Ubuntu $host_os_version arm64 host; Ubuntu 24.04 container"
      ;;
    amd64|x86_64)
      host_architecture=amd64
      say "[OK] Ubuntu $host_os_version amd64 host; Ubuntu 24.04 container"
      ;;
    *)
      fail "unsupported architecture; expected arm64 or amd64"
      ;;
  esac
}

normalize_interface_names() {
  local label=$1 raw=$2 value normalized=""
  raw=${raw//,/ }
  for value in $raw; do
    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$ ]] ||
      fail "unsafe $label entry: $value"
    case ",$normalized," in
      *",$value,"*) fail "duplicate $label entry: $value" ;;
    esac
    normalized="${normalized:+$normalized,}$value"
  done
  printf '%s' "$normalized"
}

init_mode="template"
init_project=""
init_scope=""
init_switch_scope=""
init_mini="disabled"
init_monitor_interval="30"
init_dhcp_interface_allowlist=""
init_dhcp_relay_ingress=""
init_timezone="Asia/Shanghai"

parse_init_options() {
  local option seen_options=":"
  init_mode="template"
  init_project=""
  init_scope=""
  init_switch_scope=""
  init_mini="disabled"
  init_monitor_interval="30"
  init_dhcp_interface_allowlist=""
  init_dhcp_relay_ingress=""
  init_timezone="Asia/Shanghai"
  [[ "$#" -gt 0 ]] || return 0
  init_mode="profile"
  while [[ "$#" -gt 0 ]]; do
    option=$1
    case "$seen_options" in
      *":$option:"*) fail "duplicate init option: $option" ;;
    esac
    seen_options="${seen_options}${option}:"
    case "$1" in
      --project|--scope|--switch|--monitor-interval|--dhcp-interface-allowlist|--dhcp-relay-ingress|--timezone)
        [[ "$#" -ge 2 && -n "$2" ]] || fail "$1 requires one value"
        case "$1" in
          --project) init_project=$2 ;;
          --scope) init_scope=$2 ;;
          --switch) init_switch_scope=$2 ;;
          --monitor-interval) init_monitor_interval=$2 ;;
          --dhcp-interface-allowlist) init_dhcp_interface_allowlist=$2 ;;
          --dhcp-relay-ingress) init_dhcp_relay_ingress=$2 ;;
          --timezone) init_timezone=$2 ;;
        esac
        shift 2
        ;;
      --mini)
        init_mini="enabled"
        shift
        ;;
      *)
        fail "unsupported init option: $1"
        ;;
    esac
  done
  [[ "$init_project" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "init --project must name one safe DAY0-Prepare directory"
  case "$init_scope" in
    air|prod) ;;
    "") fail "parameterized init requires --scope air or --scope prod" ;;
    *) fail "init --scope must be air or prod" ;;
  esac
  if [[ -z "$init_switch_scope" ]]; then
    if [[ "$init_scope" == "air" ]]; then
      init_switch_scope="eth"
    else
      init_switch_scope="all"
    fi
  fi
  case "$init_switch_scope" in
    all|eth|ib|nvl) ;;
    *) fail "init --switch must be all, eth, ib, or nvl" ;;
  esac
  if [[ "$init_scope" == "air" && "$init_switch_scope" != "eth" ]]; then
    fail "AIR init requires switch scope eth"
  fi
  if [[ "$init_mini" == "enabled" ]] &&
      [[ "$init_scope" != "air" || "$init_switch_scope" != "eth" ]]; then
    fail "init --mini requires AIR deployment and switch scope eth"
  fi
  [[ "$init_monitor_interval" =~ ^[0-9]+$ ]] ||
    fail "init monitor interval must be an integer"
  (( ${#init_monitor_interval} <= 5 )) ||
    fail "init monitor interval must be between 5 and 86400"
  init_monitor_interval=$((10#$init_monitor_interval))
  (( init_monitor_interval >= 5 && init_monitor_interval <= 86400 )) ||
    fail "init monitor interval must be between 5 and 86400"
  init_dhcp_interface_allowlist=$(normalize_interface_names \
    "DHCP interface allowlist" "$init_dhcp_interface_allowlist")
  init_dhcp_relay_ingress=$(normalize_interface_names \
    "DHCP relay ingress" "$init_dhcp_relay_ingress")
  [[ "$init_timezone" =~ ^[A-Za-z0-9][A-Za-z0-9_+.-]*(/[A-Za-z0-9][A-Za-z0-9_+.-]*)*$ ]] ||
    fail "init timezone must be one safe IANA timezone name"
  [[ -f "/usr/share/zoneinfo/$init_timezone" ]] ||
    fail "init timezone is not installed on this host: $init_timezone"
}

publish_runtime_env() {
  local temporary
  [[ ! -e "$runtime_env" && ! -L "$runtime_env" ]] ||
    fail "$runtime_env already exists; refusing to overwrite it"
  temporary=$(mktemp "$script_dir/.infra-runtime.conf.tmp.XXXXXX") ||
    fail "cannot create private runtime configuration staging file"
  chmod 0600 "$temporary" || {
    rm -f "$temporary"
    fail "cannot protect runtime configuration staging file"
  }
  if [[ "$init_mode" == "template" ]]; then
    if ! command cp "$script_dir/container.env.example" "$temporary"; then
      rm -f "$temporary"
      fail "cannot stage the neutral runtime configuration"
    fi
  else
    if ! printf '%s\n' \
        "HTTP_ZTP_PROJECT=$init_project" \
        "HTTP_ZTP_SCOPE=$init_scope" \
        "HTTP_ZTP_SWITCH_SCOPE=$init_switch_scope" \
        "HTTP_ZTP_MINI=$init_mini" \
        "HTTP_ZTP_MONITOR_INTERVAL=$init_monitor_interval" \
        "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=$init_dhcp_interface_allowlist" \
        "HTTP_ZTP_DHCP_RELAY_INGRESS=$init_dhcp_relay_ingress" \
        "HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass" \
        "TZ=$init_timezone" > "$temporary"; then
      rm -f "$temporary"
      fail "cannot stage the generated runtime configuration"
    fi
  fi
  chmod 0600 "$temporary" || {
    rm -f "$temporary"
    fail "cannot protect generated runtime configuration"
  }
  if ! ln "$temporary" "$runtime_env"; then
    rm -f "$temporary"
    fail "$runtime_env appeared concurrently; refusing to overwrite it"
  fi
  rm -f "$temporary"
  [[ -f "$runtime_env" && ! -L "$runtime_env" ]] ||
    fail "published runtime configuration is not a regular file"
}

initialize_runtime_env() {
  require_root
  [[ ! -e "$runtime_env" && ! -L "$runtime_env" ]] ||
    fail "$runtime_env already exists; refusing to overwrite it"
  if [[ "$init_mode" == "profile" ]]; then
    local project_path="$repo_root/DAY0-Prepare/$init_project"
    [[ -d "$project_path" && ! -L "$project_path" ]] ||
      fail "init project is absent or unsafe: $project_path"
    [[ -f "$project_path/02-dhcp-subnet_config.csv" &&
       ! -L "$project_path/02-dhcp-subnet_config.csv" ]] ||
      fail "init project is missing 02-dhcp-subnet_config.csv"
  fi
  publish_runtime_env
  if [[ "$init_mode" == "template" ]]; then
    say "[OK] created $runtime_env from the neutral template; edit it before deploy"
  else
    say "[OK] generated $runtime_env for project=$init_project scope=$init_scope switch=$init_switch_scope mini=$init_mini"
  fi
}

valid_env_key() {
  case "$1" in
    HTTP_ZTP_PROJECT|HTTP_ZTP_SCOPE|HTTP_ZTP_SWITCH_SCOPE|HTTP_ZTP_MINI|HTTP_ZTP_MONITOR_INTERVAL|HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST|HTTP_ZTP_DHCP_RELAY_INGRESS|HTTP_ZTP_ASKPASS_TMPDIR|TZ)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

stable_runtime_env_text() {
  local path=$1
  python3 - "$path" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    path_before = os.lstat(path)
    if stat.S_ISLNK(path_before.st_mode):
        raise OSError("runtime configuration NOFOLLOW policy rejects symlinks")
    descriptor = os.open(path, flags)
except OSError as exc:
    raise SystemExit(f"cannot open private runtime configuration: {exc}")
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit("private runtime configuration must be a regular file")
    if before.st_uid != os.geteuid():
        raise SystemExit("private runtime configuration must be owned by the current root user")
    if before.st_nlink != 1:
        raise SystemExit("private runtime configuration must be single-link")
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise SystemExit("private runtime configuration must have mode 0600")
    if before.st_size <= 0 or before.st_size > 64 * 1024:
        raise SystemExit("private runtime configuration size is unsafe")
    chunks = []
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            raise SystemExit("private runtime configuration was truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise SystemExit("private runtime configuration grew while being read")
    data = b"".join(chunks)
    if b"\0" in data:
        raise SystemExit("private runtime configuration contains NUL")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("private runtime configuration is not UTF-8") from exc
    after = os.fstat(descriptor)
    path_after = os.lstat(path)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if identity(before) != identity(after):
        raise SystemExit("private runtime configuration changed while being read")
    if (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino):
        raise SystemExit("private runtime configuration path changed while being read")
    sys.stdout.buffer.write(data)
finally:
    os.close(descriptor)
PY
}

load_runtime_env() {
  local runtime_text line key value lineno=0 seen=":"
  runtime_text=$(stable_runtime_env_text "$runtime_env") || fail \
    "unsafe or missing $runtime_env; run '$0 init --project NAME --scope air|prod [OPTIONS]'"
  for key in \
    HTTP_ZTP_PROJECT HTTP_ZTP_SCOPE HTTP_ZTP_SWITCH_SCOPE HTTP_ZTP_MINI \
    HTTP_ZTP_MONITOR_INTERVAL \
    HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST HTTP_ZTP_DHCP_RELAY_INGRESS \
    HTTP_ZTP_ASKPASS_TMPDIR TZ; do
    unset "$key"
  done
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    line=${line%$'\r'}
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || fail "$runtime_env:$lineno must be KEY=VALUE"
    key=${line%%=*}
    value=${line#*=}
    valid_env_key "$key" || fail "$runtime_env:$lineno unsupported key: $key"
    [[ "$key" =~ ^[A-Z0-9_]+$ ]] || fail "$runtime_env:$lineno unsafe key"
    case "$seen" in
      *":$key:"*) fail "$runtime_env:$lineno duplicate key: $key" ;;
    esac
    seen="${seen}${key}:"
    [[ "$value" =~ ^[A-Za-z0-9._:/,\ -]*$ ]] ||
      fail "$runtime_env:$lineno contains an unsafe value"
    export "${key}=${value}"
  done <<< "$runtime_text"
  [[ "${HTTP_ZTP_PROJECT:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "HTTP_ZTP_PROJECT must name one direct DAY0-Prepare project directory"
  [[ "${HTTP_ZTP_SCOPE:-}" == "air" || "${HTTP_ZTP_SCOPE:-}" == "prod" ]] ||
    fail "HTTP_ZTP_SCOPE must be air or prod"
  HTTP_ZTP_SWITCH_SCOPE=${HTTP_ZTP_SWITCH_SCOPE:-}
  if [[ -z "$HTTP_ZTP_SWITCH_SCOPE" ]]; then
    if [[ "$HTTP_ZTP_SCOPE" == "air" ]]; then
      HTTP_ZTP_SWITCH_SCOPE=eth
    else
      HTTP_ZTP_SWITCH_SCOPE=all
    fi
  fi
  case "$HTTP_ZTP_SWITCH_SCOPE" in
    all|eth|ib|nvl) ;;
    *) fail "HTTP_ZTP_SWITCH_SCOPE must be all, eth, ib, or nvl" ;;
  esac
  if [[ "$HTTP_ZTP_SCOPE" == "air" && "$HTTP_ZTP_SWITCH_SCOPE" != "eth" ]]; then
    fail "AIR deployment requires HTTP_ZTP_SWITCH_SCOPE=eth"
  fi
  HTTP_ZTP_MINI=${HTTP_ZTP_MINI:-disabled}
  case "$HTTP_ZTP_MINI" in
    enabled|disabled) ;;
    *) fail "HTTP_ZTP_MINI must be enabled or disabled" ;;
  esac
  if [[ "$HTTP_ZTP_MINI" == "enabled" ]] && \
      [[ "$HTTP_ZTP_SCOPE" != "air" || "$HTTP_ZTP_SWITCH_SCOPE" != "eth" ]]; then
    fail "HTTP_ZTP_MINI=enabled requires AIR deployment and switch scope eth"
  fi
  HTTP_ZTP_MONITOR_INTERVAL=${HTTP_ZTP_MONITOR_INTERVAL:-30}
  [[ "$HTTP_ZTP_MONITOR_INTERVAL" =~ ^[0-9]+$ ]] ||
    fail "HTTP_ZTP_MONITOR_INTERVAL must be an integer"
  (( ${#HTTP_ZTP_MONITOR_INTERVAL} <= 5 )) ||
    fail "HTTP_ZTP_MONITOR_INTERVAL must be between 5 and 86400"
  HTTP_ZTP_MONITOR_INTERVAL=$((10#$HTTP_ZTP_MONITOR_INTERVAL))
  (( HTTP_ZTP_MONITOR_INTERVAL >= 5 && HTTP_ZTP_MONITOR_INTERVAL <= 86400 )) ||
    fail "HTTP_ZTP_MONITOR_INTERVAL must be between 5 and 86400"
  HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=$(normalize_interface_names \
    "DHCP interface allowlist" "${HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST:-}")
  HTTP_ZTP_DHCP_RELAY_INGRESS=$(normalize_interface_names \
    "DHCP relay ingress" "${HTTP_ZTP_DHCP_RELAY_INGRESS:-}")
  HTTP_ZTP_ASKPASS_TMPDIR=${HTTP_ZTP_ASKPASS_TMPDIR:-/run/http-ztp/askpass}
  [[ "$HTTP_ZTP_ASKPASS_TMPDIR" == "/run/http-ztp/askpass" ]] ||
    fail "HTTP_ZTP_ASKPASS_TMPDIR must be /run/http-ztp/askpass"
  TZ=${TZ:-Asia/Shanghai}
  export HTTP_ZTP_PROJECT HTTP_ZTP_SCOPE HTTP_ZTP_SWITCH_SCOPE HTTP_ZTP_MINI
  export HTTP_ZTP_MONITOR_INTERVAL
  export HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST HTTP_ZTP_DHCP_RELAY_INGRESS
  export HTTP_ZTP_ASKPASS_TMPDIR TZ
  [[ -f "$repo_root/DAY0-Prepare/$HTTP_ZTP_PROJECT/02-dhcp-subnet_config.csv" ]] ||
    fail "project or 02-dhcp-subnet_config.csv is absent below $repo_root"
}

compose_available() {
  docker compose version >/dev/null 2>&1
}

safe_lock_run() {
  python3 "$script_dir/hostlock.py" --wait "$lock_wait" "$@"
}

validate_management_key_status() {
  local operation=$1 management_key_status=$2
  /usr/bin/python3 - "$operation" "$management_key_status" <<'PY'
import json
import re
import sys

operation, raw = sys.argv[1:]

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

try:
    value = json.loads(raw, object_pairs_hook=reject_duplicates)
except (TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(2)
if type(value) is not dict or set(value) != {"action", "fingerprint", "valid"}:
    raise SystemExit(2)
canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
if raw != canonical:
    raise SystemExit(2)
fingerprint = value["fingerprint"]
if fingerprint is not None and not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
    raise SystemExit(2)
if operation == "reconcile":
    if value["action"] not in {
        "copied-host-to-service",
        "copied-service-to-host",
        "generated-host-and-copied-service",
        "preserved-identical",
    } or value["valid"] is not True or fingerprint is None:
        raise SystemExit(2)
elif operation == "check":
    expected = {
        "generation-required": (False, False),
        "copy-host-to-service-required": (False, True),
        "copy-service-to-host-required": (False, True),
        "preserved-identical": (True, True),
    }.get(value["action"])
    if expected is None or type(value["valid"]) is not bool:
        raise SystemExit(2)
    if (value["valid"], fingerprint is not None) != expected:
        raise SystemExit(2)
else:
    raise SystemExit(2)
PY
}

prepare_management_ssh_key() {
  local management_key_status
  management_key_status=$(safe_lock_run -- /usr/bin/python3 -B "$script_dir/management_ssh_key.py" reconcile) ||
    fail "cannot reconcile the fixed Docker management SSH identity"
  (( ${#management_key_status} <= 512 )) ||
    fail "management SSH key helper output exceeded the fixed bound"
  validate_management_key_status reconcile "$management_key_status" ||
    fail "management SSH key helper returned invalid status"
  say "[OK] Docker management SSH identity is reconciled"
}

check_management_ssh_key() {
  local management_key_status
  management_key_status=$(safe_lock_run -- /usr/bin/python3 -B "$script_dir/management_ssh_key.py" check) ||
    fail "fixed Docker management SSH identity check failed"
  (( ${#management_key_status} <= 512 )) ||
    fail "management SSH key check output exceeded the fixed bound"
  validate_management_key_status check "$management_key_status" ||
    fail "management SSH key checker returned invalid status"
}

owned_container_id() {
  local require_running=${1:-false}
  local check_runtime=${2:-false}
  local allow_absent=${3:-false}
  local -a arguments
  arguments=(--inspect-owned-id)
  [[ "$require_running" == "true" ]] && arguments+=(--require-running)
  [[ "$allow_absent" == "true" ]] && arguments+=(--allow-absent)
  if [[ "$check_runtime" == "true" ]]; then
    arguments+=(
      --expect-env "HTTP_ZTP_PROJECT=$HTTP_ZTP_PROJECT"
      --expect-env "HTTP_ZTP_SCOPE=$HTTP_ZTP_SCOPE"
      --expect-env "HTTP_ZTP_SWITCH_SCOPE=$HTTP_ZTP_SWITCH_SCOPE"
      --expect-env "HTTP_ZTP_MINI=$HTTP_ZTP_MINI"
      --expect-env "HTTP_ZTP_MONITOR_INTERVAL=$HTTP_ZTP_MONITOR_INTERVAL"
      --expect-env "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=$HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST"
      --expect-env "HTTP_ZTP_DHCP_RELAY_INGRESS=$HTTP_ZTP_DHCP_RELAY_INGRESS"
      --expect-env "HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass"
      --expect-env "TZ=$TZ"
      --expect-env "HTTP_ZTP_RUNTIME_BACKEND=supervisor"
      --expect-env "HTTP_ZTP_ROOT=/var/www/html"
      --expect-env "HTTP_ZTP_STATE_ROOT=/var/lib/http-ztp"
      --expect-env "HTTP_ZTP_LOG_ROOT=/var/log/http-ztp"
      --expect-env "HTTP_ZTP_DHCP_CONFIG=/etc/dhcp/dhcpd.conf"
      --expect-env "HTTP_ZTP_DHCP_LEASES=/var/lib/dhcp/dhcpd.leases"
      --expect-env "HTTP_ZTP_APACHE_LISTENERS=/etc/apache2/conf-enabled/http-ztp-listeners.conf"
      --expect-env "PYTHONDONTWRITEBYTECODE=1"
    )
  fi
  safe_lock_run "${arguments[@]}"
}

container_id_running() {
  local container_id=$1
  [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" == "true" ]]
}

clear_activation_for_recreate() {
  local expected_owned_id=${1:-}
  local -a identity_argument=(--expect-owned-or-absent)
  if [[ -n "$expected_owned_id" ]]; then
    identity_argument=(--expected-owned-id "$expected_owned_id")
  fi
  # The image can intentionally be older than the newly synced mount here.
  # Use only the host helper: under one safe lock it verifies ownership labels
  # and bind identity, stops/removes by immutable ID, then clears activation.
  safe_lock_run --owned-action remove-clear "${identity_argument[@]}" ||
    fail "cannot safely stop/remove the owned container before rebuild"
}

prepare_bind_mounts() {
  install -d -m 0755 /var/www/html
  install -d -m 0700 \
    /var/lib/http-ztp-container \
    /var/lib/http-ztp-container/runtime
  install -d -m 0755 \
    /var/lib/http-ztp-container/dhcp-etc \
    /var/lib/http-ztp-container/dhcp-lib
  install -d -m 0750 \
    /var/lib/http-ztp-container/logs \
    /var/lib/http-ztp-container/apache-logs
}

prepare_control_auth() {
  local status
  status=$(safe_lock_run --prepare-control-auth) ||
    fail "cannot initialize or validate Monitor control credentials"
  case "$status" in
    '{"factory_records_active":false,"valid":true}') ;;
    '{"factory_records_active":true,"valid":true}')
      say "[WARN] factory Monitor control credentials are active; rotate both users immediately after first login"
      ;;
    *) fail "Monitor control credential helper returned invalid status" ;;
  esac
}

prepare_monitor_authority() {
  local status
  status=$(safe_lock_run --prepare-monitor-authority) ||
    fail "cannot provision or attest persistent Monitor cache authority"
  [[ "$status" == '{"valid":true}' ]] ||
    fail "Monitor cache authority helper returned invalid status"
}

attest_monitor_authority() {
  local status
  status=$(safe_lock_run --attest-monitor-authority) ||
    fail "persistent Monitor cache authority attestation failed"
  [[ "$status" == '{"valid":true}' ]] ||
    fail "Monitor cache authority attestor returned invalid status"
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

recover_monitor_authority_action() {
  if ! capture_monitor_authority_decision \
      python3 "$script_dir/hostlock.py" --wait "$lock_wait" \
      --recover-monitor-authority-decision; then
    fail "Monitor cache authority recovery returned an invalid structured result; container remains stopped"
    return $?
  fi
  case "$monitor_authority_decision" in
    *';reset-invalid-cache=true')
      printf '%s\n' "$MONITOR_AUTHORITY_RECOVERY_WARNING" >&2
      ;;
    *';reset-invalid-cache=false')
      ;;
    *)
      fail "Monitor cache authority recovery returned an invalid warning decision; container remains stopped"
      return $?
      ;;
  esac
  case "$monitor_authority_decision" in
    'restart-allowed:complete;reset-invalid-cache=false'|\
    'restart-allowed:complete;reset-invalid-cache=true')
      ;;
    'restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=false'|\
    'restart-allowed:marker-removal-durability-unknown;reset-invalid-cache=true')
      say "[WARN] previous Monitor authority recovery COMPLETED, but marker removal durability is unknown; a stale completed marker may reappear after crash"
      ;;
    'restart-blocked:marker-retained;reset-invalid-cache=false'|\
    'restart-blocked:marker-retained;reset-invalid-cache=true')
      fail "previous Monitor authority recovery COMPLETED and the repaired authority itself is not in question, but marker cleanup remains; container remains stopped. Re-run exactly: sudo ./infra/docker/deploy.sh recover-monitor-authority"
      return $?
      ;;
    'restart-blocked:marker-authority-uncertain;reset-invalid-cache=false'|\
    'restart-blocked:marker-authority-uncertain;reset-invalid-cache=true')
      fail "Monitor recovery marker authority is uncertain after semantic commit; container remains stopped. Re-run exactly: sudo ./infra/docker/deploy.sh recover-monitor-authority"
      return $?
      ;;
    *)
      fail "Monitor cache authority recovery returned an invalid structured result; container remains stopped"
      return $?
      ;;
  esac
  say "[OK] Monitor cache authority recovered; container remains stopped"
  say "[NEXT] sudo ./infra/docker/deploy.sh deploy"
}

build_image() {
  local iidfile=${1:-}
  # Snapshot the Docker build context under the same host-side lock used by
  # sync.  No host file descriptor is passed across docker exec.
  say "[INFO] building $image_name from locked repository $repo_root"
  if [[ -n "$iidfile" ]]; then
    safe_lock_run -- docker build --tag "$image_name" \
      --file "$script_dir/Dockerfile" --iidfile "$iidfile" "$repo_root"
  else
    safe_lock_run -- docker build --tag "$image_name" \
      --file "$script_dir/Dockerfile" "$repo_root"
  fi
}

stable_file_fingerprint() {
  local path=$1
  python3 - "$path" <<'PY'
import hashlib
import os
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    descriptor = os.open(path, flags)
except OSError as exc:
    raise SystemExit(f"cannot open frozen file {path}: {exc}")
try:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_size <= 0
    ):
        raise SystemExit(f"frozen file is not a nonempty owned single-link regular file: {path}")
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    after = os.fstat(descriptor)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns,
    )
    if identity(before) != identity(after) or total != before.st_size:
        raise SystemExit(f"frozen file changed while hashing: {path}")
    print(digest.hexdigest(), total)
finally:
    os.close(descriptor)
PY
}

stable_image_id_text() {
  local path=$1
  python3 - "$path" <<'PY'
import os
import re
import stat
import sys

path = sys.argv[1]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = -1
try:
    direct = os.lstat(path)
    descriptor = os.open(path, flags)
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(direct.st_mode)
        or (before.st_dev, before.st_ino) != (direct.st_dev, direct.st_ino)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size < 71
        or before.st_size > 72
    ):
        raise OSError("image iidfile is not one private owned regular file")
    payload = os.read(descriptor, 73)
    after = os.fstat(descriptor)
    current = os.lstat(path)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if (
        identity(before) != identity(after)
        or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        or len(payload) != before.st_size
    ):
        raise OSError("image iidfile changed while being read")
    value = payload.decode("ascii").rstrip("\n")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise OSError("image iidfile does not contain one immutable image ID")
    print(value)
except (OSError, UnicodeError) as exc:
    raise SystemExit(f"cannot read immutable image ID: {exc}")
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
}

safe_image_export_parent() {
  local path=$1
  python3 - "$path" <<'PY'
import os
from pathlib import Path
import stat
import sys

raw = sys.argv[1]
path = Path(raw)
if not path.is_absolute() or os.path.normpath(raw) != raw:
    raise SystemExit("image-export output parent must be one canonical absolute path")
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = -1
try:
    descriptor = os.open(path.anchor, flags)
except OSError as exc:
    raise SystemExit(f"image-export output parent is unreadable: {exc}")
try:
  for part in path.parts[1:]:
    try:
        direct = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
    except OSError as exc:
        raise SystemExit(f"image-export output parent is unreadable: {exc}")
    if stat.S_ISLNK(direct.st_mode):
        raise SystemExit("image-export output parent cannot contain a symlink")
    if not stat.S_ISDIR(direct.st_mode):
        raise SystemExit("image-export output parent must be an existing directory")
    try:
        opened = os.open(part, flags, dir_fd=descriptor)
    except OSError as exc:
        raise SystemExit(f"image-export output parent is unreadable: {exc}")
    metadata = os.fstat(opened)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != (direct.st_dev, direct.st_ino)
    ):
        os.close(opened)
        raise SystemExit("image-export output parent changed during validation")
    os.close(descriptor)
    descriptor = opened
  metadata = os.fstat(descriptor)
  if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
      raise SystemExit(
          "image-export output parent must be owned by the current root user and not group/world writable"
      )
  print(metadata.st_dev, metadata.st_ino)
finally:
    if descriptor >= 0:
        os.close(descriptor)
PY
}

verify_held_image_export_directory() {
  local descriptor=$1 expected_dev=$2 expected_ino=$3 expected_mode=$4 label=$5
  python3 - "$descriptor" "$expected_dev" "$expected_ino" "$expected_mode" "$label" <<'PY'
import os
import stat
import sys

descriptor = int(sys.argv[1])
expected = (int(sys.argv[2]), int(sys.argv[3]))
expected_mode = sys.argv[4]
label = sys.argv[5]
metadata = os.fstat(descriptor)
mode = stat.S_IMODE(metadata.st_mode)
mode_is_unsafe = (
    mode & 0o022 if expected_mode == "safe" else mode != int(expected_mode, 8)
)
if (
    not stat.S_ISDIR(metadata.st_mode)
    or (metadata.st_dev, metadata.st_ino) != expected
    or metadata.st_uid != os.geteuid()
    or mode_is_unsafe
):
    raise SystemExit(f"held image-export {label} identity is unsafe")
PY
}

ensure_image_export_output_absent() {
  local parent_descriptor=$1 output_name=$2
  python3 - "$parent_descriptor" "$output_name" <<'PY'
import os
import sys

descriptor = int(sys.argv[1])
name = sys.argv[2]
try:
    os.stat(name, dir_fd=descriptor, follow_symlinks=False)
except FileNotFoundError:
    raise SystemExit(0)
except OSError as exc:
    raise SystemExit(f"cannot inspect image-export output: {exc}")
raise SystemExit("image-export output already exists; refusing to overwrite it")
PY
}

create_private_image_export_stage() {
  local parent_descriptor=$1 prefix=$2
  python3 - "$parent_descriptor" "$prefix" <<'PY'
import os
import secrets
import stat
import sys

parent_descriptor = int(sys.argv[1])
prefix = sys.argv[2]
parent = os.fstat(parent_descriptor)
if (
    not stat.S_ISDIR(parent.st_mode)
    or parent.st_uid != os.geteuid()
    or stat.S_IMODE(parent.st_mode) & 0o022
):
    raise SystemExit("held image-export output parent identity is unsafe")
for _ in range(128):
    name = prefix + secrets.token_hex(8)
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
    except FileExistsError:
        continue
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        direct = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (direct.st_dev, direct.st_ino)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise OSError("new image-export staging directory identity is unsafe")
        os.fsync(parent_descriptor)
        print(name, opened.st_dev, opened.st_ino, flush=True)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        try:
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if stat.S_ISDIR(current.st_mode) and (
                current.st_dev, current.st_ino
            ) == (direct.st_dev, direct.st_ino):
                os.rmdir(name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
        except (NameError, OSError):
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raise SystemExit(0)
raise SystemExit("cannot allocate a unique private image-export staging directory")
PY
}

fsync_image_export_stage() {
  local stage_descriptor=$1
  shift
  python3 - "$stage_descriptor" "$@" <<'PY'
import hashlib
import json
import os
import stat
import sys

stage_descriptor = int(sys.argv[1])
names = sys.argv[2:]
if names != ["http-ztp-ubuntu-24.04.tar", "image-metadata.json", "SHA256SUMS"]:
    raise SystemExit("image-export staged file set is not canonical")

def identity(metadata):
    return {
        "st_ctime_ns": metadata.st_ctime_ns,
        "st_dev": metadata.st_dev,
        "st_gid": metadata.st_gid,
        "st_ino": metadata.st_ino,
        "st_mode": metadata.st_mode,
        "st_mtime_ns": metadata.st_mtime_ns,
        "st_nlink": metadata.st_nlink,
        "st_size": metadata.st_size,
        "st_uid": metadata.st_uid,
    }

records = []
for name in names:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=stage_descriptor)
    try:
        before = os.fstat(descriptor)
        direct = os.stat(name, dir_fd=stage_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (direct.st_dev, direct.st_ino)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
        ):
            raise OSError(f"image-export staged file identity is unsafe: {name}")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        direct_after = os.stat(name, dir_fd=stage_descriptor, follow_symlinks=False)
        if (
            identity(before) != identity(after)
            or (after.st_dev, after.st_ino) != (
                direct_after.st_dev, direct_after.st_ino
            )
            or total != before.st_size
        ):
            raise OSError(f"image-export staged file changed while sealing: {name}")
        os.fsync(descriptor)
        synced = os.fstat(descriptor)
        if identity(after) != identity(synced):
            raise OSError(f"image-export staged file changed while syncing: {name}")
        records.append({
            **identity(synced),
            "name": name,
            "sha256": digest.hexdigest(),
        })
    finally:
        os.close(descriptor)
os.fsync(stage_descriptor)
payload = json.dumps(records, separators=(",", ":"), sort_keys=True).encode("ascii")
print(payload.hex())
PY
}

publish_image_export_noreplace() {
  local stage=$1 output=$2 parent_descriptor=$3 stage_descriptor=$4
  local parent_dev=$5 parent_ino=$6 stage_dev=$7 stage_ino=$8
  local file_seal=${9}
  python3 - "$stage" "$output" "$parent_descriptor" "$stage_descriptor" \
    "$parent_dev" "$parent_ino" "$stage_dev" "$stage_ino" "$file_seal" <<'PY'
import ctypes
import errno
import hashlib
import json
import os
import stat
import sys

stage, output = sys.argv[1:3]
descriptor, stage_descriptor = map(int, sys.argv[3:5])
expected_parent = (int(sys.argv[5]), int(sys.argv[6]))
expected_stage = (int(sys.argv[7]), int(sys.argv[8]))
seal_text = sys.argv[9]
identity_keys = (
    "st_ctime_ns", "st_dev", "st_gid", "st_ino", "st_mode",
    "st_mtime_ns", "st_nlink", "st_size", "st_uid",
)
canonical_names = (
    "http-ztp-ubuntu-24.04.tar", "image-metadata.json", "SHA256SUMS",
)

def identity(metadata):
    return {key: getattr(metadata, key) for key in identity_keys}

def parse_seal():
    if not seal_text or len(seal_text) > 16384 or len(seal_text) % 2:
        raise OSError("image-export staged file seal has an invalid size")
    records = json.loads(bytes.fromhex(seal_text).decode("ascii"))
    if not isinstance(records, list) or len(records) != len(canonical_names):
        raise OSError("image-export staged file seal has an invalid record set")
    expected_keys = set(identity_keys) | {"name", "sha256"}
    by_name = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != expected_keys:
            raise OSError("image-export staged file seal has an invalid record")
        name = record["name"]
        digest = record["sha256"]
        if (
            name not in canonical_names
            or name in by_name
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or any(type(record[key]) is not int for key in identity_keys)
        ):
            raise OSError("image-export staged file seal has invalid values")
        by_name[name] = record
    if tuple(record["name"] for record in records) != canonical_names:
        raise OSError("image-export staged file seal order is not canonical")
    return by_name

def verify_files(expected_records):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for name in canonical_names:
        expected = expected_records[name]
        file_descriptor = os.open(name, flags, dir_fd=stage_descriptor)
        try:
            before = os.fstat(file_descriptor)
            direct = os.stat(
                name, dir_fd=stage_descriptor, follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or (before.st_dev, before.st_ino) != (
                    direct.st_dev, direct.st_ino
                )
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size <= 0
                or identity(before) != {
                    key: expected[key] for key in identity_keys
                }
            ):
                raise OSError(
                    f"image-export staged file identity changed: {name}"
                )
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(file_descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
            after = os.fstat(file_descriptor)
            current = os.stat(
                name, dir_fd=stage_descriptor, follow_symlinks=False,
            )
            if (
                identity(before) != identity(after)
                or (after.st_dev, after.st_ino) != (
                    current.st_dev, current.st_ino
                )
                or total != before.st_size
                or digest.hexdigest() != expected["sha256"]
            ):
                raise OSError(
                    f"image-export staged file content changed: {name}"
                )
            os.fsync(file_descriptor)
            if identity(after) != identity(os.fstat(file_descriptor)):
                raise OSError(
                    f"image-export staged file changed while syncing: {name}"
                )
        finally:
            os.close(file_descriptor)
    os.fsync(stage_descriptor)

def verify_published_entry():
    published = os.stat(output, dir_fd=descriptor, follow_symlinks=False)
    if (
        not stat.S_ISDIR(published.st_mode)
        or (published.st_dev, published.st_ino) != expected_stage
        or published.st_uid != os.geteuid()
        or stat.S_IMODE(published.st_mode) != 0o700
    ):
        raise OSError("published image-export directory identity changed")

try:
    expected_records = parse_seal()
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != expected_parent
        or opened.st_uid != os.geteuid()
        or stat.S_IMODE(opened.st_mode) & 0o022
    ):
        raise OSError("image-export output parent identity is unsafe")
    held_stage = os.fstat(stage_descriptor)
    staged = os.stat(stage, dir_fd=descriptor, follow_symlinks=False)
    if (
        not stat.S_ISDIR(held_stage.st_mode)
        or (held_stage.st_dev, held_stage.st_ino) != expected_stage
        or (staged.st_dev, staged.st_ino) != expected_stage
        or staged.st_uid != os.geteuid()
        or stat.S_IMODE(staged.st_mode) != 0o700
    ):
        raise OSError("image-export staging directory identity is unsafe")
    verify_files(expected_records)
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = (
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            descriptor, os.fsencode(stage), descriptor,
            os.fsencode(output), 1,
        )
    else:
        # The wrapper executes only on Linux, but the repository contract is
        # also tested on macOS.  Darwin exposes the same atomic no-replace
        # guarantee as renamex_np(RENAME_EXCL).
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise OSError(errno.ENOSYS, "atomic no-replace rename is unavailable")
        renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        renamex_np.restype = ctypes.c_int
        os.fchdir(descriptor)
        result = renamex_np(os.fsencode(stage), os.fsencode(output), 0x00000004)
    if result != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    verify_published_entry()
    verify_files(expected_records)
    verify_published_entry()
    os.fsync(descriptor)
except (OSError, TypeError, ValueError, UnicodeError) as exc:
    raise SystemExit(f"cannot atomically publish image-export without replacement: {exc}")
finally:
    pass
PY
}

remove_private_export_stage() {
  local candidate=$1 parent_descriptor=$2 prefix=$3 parent_dev=$4 parent_ino=$5
  local stage_dev=$6 stage_ino=$7
  python3 - "$candidate" "$parent_descriptor" "$prefix" \
    "$parent_dev" "$parent_ino" "$stage_dev" "$stage_ino" <<'PY'
import os
import stat
import sys

candidate = sys.argv[1]
parent_descriptor = int(sys.argv[2])
prefix = sys.argv[3]
expected_parent = (int(sys.argv[4]), int(sys.argv[5]))
expected_stage = (int(sys.argv[6]), int(sys.argv[7]))

parent = os.fstat(parent_descriptor)
if (
    not stat.S_ISDIR(parent.st_mode)
    or (parent.st_dev, parent.st_ino) != expected_parent
    or parent.st_uid != os.geteuid()
    or stat.S_IMODE(parent.st_mode) & 0o022
    or not candidate.startswith(prefix)
):
    raise SystemExit("refusing to clean an unsafe image-export staging identity")

def entry_identity(name):
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISDIR(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == expected_stage:
        return metadata
    return None

entry_name = candidate if entry_identity(candidate) is not None else None
if entry_name is None:
    for name in os.listdir(parent_descriptor):
        if entry_identity(name) is not None:
            entry_name = name
            break
if entry_name is None:
    raise SystemExit("original image-export staging directory is no longer below its held parent")

flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
stage_descriptor = os.open(entry_name, flags, dir_fd=parent_descriptor)
os.fchdir(parent_descriptor)

def empty_directory(descriptor):
    for name in os.listdir(descriptor):
        direct = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(direct.st_mode):
            # A generic image export never creates a nested directory.  Do
            # not recurse into a directory injected by another root process:
            # it could be a renamed external tree or a mount point.
            raise OSError("unexpected directory in private image-export staging")
        else:
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (direct.st_dev, direct.st_ino):
                raise OSError("image-export cleanup file changed identity")
            os.unlink(name, dir_fd=descriptor)

try:
    opened_stage = os.fstat(stage_descriptor)
    if (
        not stat.S_ISDIR(opened_stage.st_mode)
        or (opened_stage.st_dev, opened_stage.st_ino) != expected_stage
        or opened_stage.st_uid != os.geteuid()
    ):
        raise OSError("image-export cleanup stage changed identity")
    empty_directory(stage_descriptor)
    os.fsync(stage_descriptor)
finally:
    os.close(stage_descriptor)
current_stage = os.stat(entry_name, dir_fd=parent_descriptor, follow_symlinks=False)
if (current_stage.st_dev, current_stage.st_ino) != expected_stage:
    raise OSError("image-export cleanup stage changed before removal")
os.rmdir(entry_name, dir_fd=parent_descriptor)
os.fsync(parent_descriptor)
PY
}

cleanup_image_export_on_exit() {
  local status=${1:-$?}
  if [[ -n "$image_export_stage" ]]; then
    remove_private_export_stage \
      "$image_export_stage" 9 "$image_export_prefix" \
      "$image_export_parent_dev" "$image_export_parent_ino" \
      "$image_export_stage_dev" "$image_export_stage_ino" || true
  fi
  return "$status"
}

run_image_export() {
  local requested=$1 output_parent output_name output_dir stage repo_root_physical
  local current_parent_dev current_parent_ino
  local inspect_record image_id image_os image_architecture verified
  local manifest="$repo_root/infra/docker/deployment-source-manifest.json"
  local manifest_sha_before manifest_size_before manifest_sha_after manifest_size_after
  local archive archive_sha archive_size
  local metadata metadata_sha metadata_size sums iidfile stage_file_seal
  [[ "$requested" == /* ]] || fail "image-export OUTPUT_DIR must be an absolute path"
  output_parent=${requested%/*}
  output_name=${requested##*/}
  [[ -n "$output_parent" && "$output_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "image-export OUTPUT_DIR must end in one safe directory name"
  read -r image_export_parent_dev image_export_parent_ino < <(
    safe_image_export_parent "$output_parent"
  ) ||
    fail "image-export output parent is unsafe"
  output_dir="$output_parent/$output_name"
  repo_root_physical=$(CDPATH= cd -- "$repo_root" && pwd -P) ||
    fail "cannot resolve repository source tree"
  case "$output_dir" in
    "$repo_root_physical"|"$repo_root_physical"/*)
      fail "image-export output must be outside the repository source tree"
      ;;
  esac

  cd -- "$output_parent" || fail "cannot enter image-export output parent"
  exec 9< . || fail "cannot hold image-export output parent"
  verify_held_image_export_directory \
    9 "$image_export_parent_dev" "$image_export_parent_ino" safe parent ||
    fail "image-export output parent changed before it could be held"
  ensure_image_export_output_absent 9 "$output_name" ||
    fail "image-export output already exists; refusing to overwrite it"

  host_preflight
  read -r manifest_sha_before manifest_size_before < <(
    stable_file_fingerprint "$manifest"
  ) || fail "cannot freeze deployment source manifest before build"

  image_export_parent=$output_parent
  image_export_prefix=".$output_name.tmp."
  read -r stage image_export_stage_dev image_export_stage_ino < <(
    create_private_image_export_stage 9 "$image_export_prefix"
  ) ||
    fail "cannot create private image-export staging directory"
  image_export_stage=$stage
  trap 'image_export_status=$?; trap - EXIT; cleanup_image_export_on_exit "$image_export_status"; exit "$image_export_status"' EXIT
  cd -- "$stage" || fail "cannot enter private image-export staging directory"
  exec 8< . || fail "cannot hold private image-export staging directory"
  verify_held_image_export_directory \
    8 "$image_export_stage_dev" "$image_export_stage_ino" 0700 stage ||
    fail "image-export staging directory changed before it could be held"

  archive="http-ztp-ubuntu-24.04.tar"
  metadata="image-metadata.json"
  sums="SHA256SUMS"
  iidfile="image.iid"

  build_image "$iidfile" || fail "Docker image build failed"
  chmod 0600 "$iidfile" || fail "cannot protect Docker image iidfile"
  image_id=$(stable_image_id_text "$iidfile") ||
    fail "cannot freeze immutable image ID after build"
  inspect_record=$(docker image inspect --format \
    '{{.Id}}|{{.Os}}|{{.Architecture}}' "$image_id") ||
    fail "cannot inspect the newly built image"
  local inspected_image_id
  IFS='|' read -r inspected_image_id image_os image_architecture <<< "$inspect_record"
  [[ "$inspected_image_id" == "$image_id" ]] ||
    fail "newly built image did not return one immutable image ID"
  [[ "$image_os" == "linux" ]] || fail "newly built image is not Linux"
  [[ "$image_architecture" == "$host_architecture" ]] ||
    fail "newly built image architecture does not match this host"
  verified=$(verify_preloaded_image "$image_id")
  [[ "$verified" == "$image_id" ]] || fail "newly built image verification changed identity"

  if ! safe_lock_run -- docker save --output "$archive" "$image_id"; then
    fail "docker save failed; private staging will be removed"
  fi
  chmod 0600 "$archive" || fail "cannot protect exported image archive"
  read -r archive_sha archive_size < <(stable_file_fingerprint "$archive") ||
    fail "cannot freeze exported image archive"
  read -r manifest_sha_after manifest_size_after < <(
    stable_file_fingerprint "$manifest"
  ) || fail "cannot recheck deployment source manifest after export"
  [[ "$manifest_sha_after:$manifest_size_after" == "$manifest_sha_before:$manifest_size_before" ]] ||
    fail "deployment source manifest changed during image-export"
  verified=$(verify_preloaded_image "$image_id")
  [[ "$verified" == "$image_id" ]] || fail "exported image verification changed identity"
  rm -- "$iidfile" || fail "cannot remove private image iidfile before publication"

  python3 - "$metadata" "$image_id" "$image_os" "$image_architecture" \
    "${archive##*/}" "$archive_sha" "$archive_size" \
    "$manifest_sha_after" <<'PY'
import json
import os
import sys

(
    path, image_id, image_os, architecture, archive, archive_sha, archive_size,
    source_sha,
) = sys.argv[1:]
payload = {
    "architecture": architecture,
    "artifact_type": "http-ztp-generic-image",
    "image_id": image_id,
    "image_contract": "3",
    "image_flavor": "generic",
    "image_name": "http-ztp:ubuntu-24.04",
    "image_archive": archive,
    "image_archive_sha256": archive_sha,
    "image_archive_size": int(archive_size),
    "image_source_manifest_sha256": source_sha,
    "os": image_os,
    "schema_version": 1,
}
data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(path, flags, 0o600)
try:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short metadata write")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  chmod 0600 "$metadata" || fail "cannot protect image-export metadata"
  read -r metadata_sha metadata_size < <(stable_file_fingerprint "$metadata") ||
    fail "cannot freeze image-export metadata"
  (umask 077; printf '%s  %s\n%s  %s\n' \
    "$archive_sha" "${archive##*/}" \
    "$metadata_sha" "${metadata##*/}" > "$sums") ||
    fail "cannot write image-export checksums"
  chmod 0600 "$sums" || fail "cannot protect image-export checksums"
  stable_file_fingerprint "$sums" >/dev/null ||
    fail "cannot freeze image-export checksums"
  read -r current_parent_dev current_parent_ino < <(
    safe_image_export_parent "$output_parent"
  ) || fail "image-export output parent pathname changed before publication"
  [[ "$current_parent_dev:$current_parent_ino" == \
    "$image_export_parent_dev:$image_export_parent_ino" ]] ||
    fail "image-export output parent pathname changed before publication"
  stage_file_seal=$(fsync_image_export_stage 8 \
    "$archive" "$metadata" "$sums") ||
    fail "cannot durably freeze image-export staging files"
  publish_image_export_noreplace \
    "$stage" "$output_name" 9 8 \
    "$image_export_parent_dev" "$image_export_parent_ino" \
    "$image_export_stage_dev" "$image_export_stage_ino" \
    "$stage_file_seal" ||
    fail "cannot atomically publish the completed image-export bundle"
  current_parent_dev=""
  current_parent_ino=""
  if ! read -r current_parent_dev current_parent_ino < <(
    safe_image_export_parent "$output_parent"
  ) || [[ "$current_parent_dev:$current_parent_ino" != \
    "$image_export_parent_dev:$image_export_parent_ino" ]]; then
    if remove_private_export_stage \
      "$output_name" 9 "$output_name" \
      "$image_export_parent_dev" "$image_export_parent_ino" \
      "$image_export_stage_dev" "$image_export_stage_ino"; then
      image_export_stage=""
      fail "image-export output parent pathname changed after publication; detached output was rolled back"
    fi
    fail "image-export output parent pathname changed after publication; exact output rollback failed"
  fi
  image_export_stage=""
  trap - EXIT
  exec 8<&-
  exec 9<&-
  say "[OK] generic image bundle: $output_dir"
  say "[OK] IMAGE_ID=$image_id"
  say "[OK] archive SHA-256=$archive_sha bytes=$archive_size"
  say "[OK] metadata SHA-256=$metadata_sha bytes=$metadata_size"
  say "[OK] image build source manifest SHA-256=$manifest_sha_after bytes=$manifest_size_after"
  say "[INFO] this developer image is project-independent; users create and deploy upload releases separately"
  say "[NEXT] copy the image bundle; on the same-architecture Docker host run:"
  say "       cd /path/to/copied-bundle && sha256sum --check SHA256SUMS"
  say "       sudo docker load --input '${archive##*/}'"
  say "       sudo ./infra/docker/deploy.sh deploy-preloaded '$image_id'"
}

verify_preloaded_image() {
  local candidate=$1 expected_flavor=${2:-generic} expected_project=${3:-}
  local expected_upgrade_policy=${4:-} verified
  local -a flavor_args=(--expected-image-flavor "$expected_flavor")
  [[ "$candidate" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "deploy-preloaded requires one full lowercase sha256 immutable image ID"
  if [[ -n "$expected_project" ]]; then
    flavor_args+=(--expected-project "$expected_project")
  fi
  if [[ -n "$expected_upgrade_policy" ]]; then
    flavor_args+=(--expected-upgrade-policy "$expected_upgrade_policy")
  fi
  verified=$(python3 "$script_dir/hostlock.py" \
    --wait "$lock_wait" \
    --verify-preloaded-image "$candidate" \
    --expected-architecture "$host_architecture" \
    "${flavor_args[@]}") ||
    fail "preloaded image verification failed; no service was changed"
  [[ "$verified" == "$candidate" ]] ||
    fail "preloaded image verifier returned an unexpected identity"
  printf '%s' "$verified"
}

plain_docker_run() {
  local image_ref=${1:-$image_name}
  safe_lock_run --require-owned-or-absent -- docker run --detach \
    --name "$container_name" \
    --label com.nvidia.http-ztp.managed=true \
    --label com.nvidia.http-ztp.http-root=/var/www/html \
    --network host \
    --user 0:0 \
    --env "HTTP_ZTP_PROJECT=$HTTP_ZTP_PROJECT" \
    --env "HTTP_ZTP_SCOPE=$HTTP_ZTP_SCOPE" \
    --env "HTTP_ZTP_SWITCH_SCOPE=$HTTP_ZTP_SWITCH_SCOPE" \
    --env "HTTP_ZTP_MINI=$HTTP_ZTP_MINI" \
    --env "HTTP_ZTP_MONITOR_INTERVAL=$HTTP_ZTP_MONITOR_INTERVAL" \
    --env "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST=$HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST" \
    --env "HTTP_ZTP_DHCP_RELAY_INGRESS=$HTTP_ZTP_DHCP_RELAY_INGRESS" \
    --env HTTP_ZTP_ASKPASS_TMPDIR=/run/http-ztp/askpass \
    --env "TZ=$TZ" \
    --env HTTP_ZTP_RUNTIME_BACKEND=supervisor \
    --env HTTP_ZTP_ROOT=/var/www/html \
    --env HTTP_ZTP_STATE_ROOT=/var/lib/http-ztp \
    --env HTTP_ZTP_LOG_ROOT=/var/log/http-ztp \
    --env HTTP_ZTP_DHCP_CONFIG=/etc/dhcp/dhcpd.conf \
    --env HTTP_ZTP_DHCP_LEASES=/var/lib/dhcp/dhcpd.leases \
    --env HTTP_ZTP_APACHE_LISTENERS=/etc/apache2/conf-enabled/http-ztp-listeners.conf \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --mount type=bind,src=/var/www/html,dst=/var/www/html \
    --mount type=bind,src=/var/lib/http-ztp-container/runtime,dst=/var/lib/http-ztp \
    --mount type=bind,src=/var/lib/http-ztp-container/dhcp-etc,dst=/etc/dhcp \
    --mount type=bind,src=/var/lib/http-ztp-container/dhcp-lib,dst=/var/lib/dhcp \
    --mount type=bind,src=/var/lib/http-ztp-container/ssh,dst=/root/.ssh \
    --mount type=bind,src=/var/lib/http-ztp-container/logs,dst=/var/log/http-ztp \
    --mount type=bind,src=/var/lib/http-ztp-container/apache-logs,dst=/var/log/apache2 \
    --mount type=bind,src=/var/lib/http-ztp-container/control-auth,dst=/etc/http-ztp,readonly \
    --mount type=bind,src=/var/lib/http-ztp-container/monitor-auth,dst=/var/lib/http-ztp-monitor-auth \
    --tmpfs /run:rw,nosuid,nodev,exec,size=16m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=1g \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --cap-add KILL \
    --cap-add NET_BIND_SERVICE \
    --cap-add NET_RAW \
    --cap-add SETGID \
    --cap-add SETUID \
    --security-opt no-new-privileges:true \
    --restart unless-stopped \
    --stop-timeout 30 \
    --health-cmd /opt/http-ztp/healthcheck.py \
    --health-interval 30s \
    --health-timeout 15s \
    --health-start-period 30s \
    --health-retries 3 \
    "$image_ref" >/dev/null
}

start_inactive_container() {
  local readiness_mode=${1:-strict}
  local image_ref=${2:-$image_name}
  local launch_mode=${3:-auto}
  local cleanup_state=${4:-required}
  local auth_state=${5:-}
  local authority_state=${6:-}
  prepare_bind_mounts
  [[ "$auth_state" == "already-prepared" ]] ||
    fail "container recreate requires prior Monitor credential preparation"
  [[ "$authority_state" == "already-prepared" ]] ||
    fail "container recreate requires prior Monitor authority preparation"
  case "$cleanup_state" in
    required) clear_activation_for_recreate ;;
    already-cleared) ;;
    *) fail "unsupported container cleanup state: $cleanup_state" ;;
  esac
  case "$launch_mode" in
    auto)
      if compose_available; then
        say "[INFO] recreating with Docker Compose"
        safe_lock_run --require-owned-or-absent -- \
          docker compose --project-directory "$script_dir" \
          --file "$compose_file" up --detach --no-build --force-recreate
      else
        say "[INFO] Compose plugin not found; using plain Docker CLI"
        plain_docker_run "$image_ref"
      fi
      ;;
    plain)
      say "[INFO] using verified immutable image with plain Docker CLI"
      plain_docker_run "$image_ref"
      ;;
    *)
      fail "unsupported container launch mode: $launch_mode"
      ;;
  esac
  started_container_id=$(owned_container_id false true false)
  wait_control_plane "$readiness_mode" "$started_container_id"
}

wait_control_plane() {
  local mode=${1:-strict}
  local container_id=$2
  local attempt readiness_output readiness_code
  for attempt in $(seq 1 60); do
    if container_id_running "$container_id" && docker exec "$container_id" \
      supervisorctl status rsyslog >/dev/null 2>&1; then
      readiness_output=$(docker exec "$container_id" \
        /opt/http-ztp/hostctl.py ready 2>&1) && readiness_code=0 || readiness_code=$?
      if [[ "$readiness_code" == "0" ]]; then
        say "[OK] container control plane and runtime-resume are ready"
        return 0
      fi
      if [[ "$readiness_code" == "2" ]]; then
        printf '[ERROR] %s\n' "$readiness_output" >&2
        docker logs --tail 100 "$container_id" >&2 || true
        if [[ "$mode" == "recover" ]]; then
          say "[WARN] runtime-resume failed; continuing only to allow a locked recovery"
          return 0
        fi
        fail "container runtime-resume failed"
      fi
    fi
    sleep 1
  done
  docker logs --tail 100 "$container_id" >&2 || true
  fail "container control plane did not become ready"
}

assert_service_ports_free() {
  local conflict=false
  if ss -H -ltn 'sport = :80' | grep -q .; then
    printf '[ERROR] TCP 80 is already in use:\n' >&2
    ss -H -ltnp 'sport = :80' >&2 || true
    conflict=true
  fi
  if ss -H -lun 'sport = :67' | grep -q .; then
    printf '[ERROR] UDP 67 is already in use:\n' >&2
    ss -H -lunp 'sport = :67' >&2 || true
    conflict=true
  fi
  [[ "$conflict" == "false" ]] || fail \
    "stop the host Apache/DHCP daemon or other conflicting process, then retry"
}

run_load() {
  local container_id=$1
  shift
  wait_control_plane recover "$container_id"
  # hostctl owns the shared lock inside the container and passes that exact
  # descriptor to 11-load.  The host never holds an FD across docker exec.
  docker exec "$container_id" /opt/http-ztp/hostctl.py load "$@" ||
    fail "transactional container load failed"
  say "[OK] load, activation, and health verification completed"
}

run_reload_network() {
  local container_id=$1
  wait_control_plane recover "$container_id"
  docker exec "$container_id" /opt/http-ztp/hostctl.py reload-network ||
    fail "transactional container network reload failed"
  say "[OK] service-IP listener replan and managed-service restart completed"
}

run_unload() {
  local container_id=$1
  wait_control_plane recover "$container_id"
  if ! docker exec "$container_id" /opt/http-ztp/hostctl.py unload; then
    fail "13-unload failed; activation remains cleared"
  fi
  say "[OK] runtime unloaded; container control plane remains available"
}

show_destructive_plan() {
  local action_name=$1 container_id=$2
  say "[PLAN] action=$action_name"
  say "[PLAN] project=$HTTP_ZTP_PROJECT"
  say "[PLAN] scope=$HTTP_ZTP_SCOPE"
  say "[PLAN] container_id=$container_id"
  if [[ "$action_name" == "unload" ]]; then
    say "[DELETE] activation marker, managed Apache/DHCP/worker runtime, project publication links"
    say "[RETAIN] owned container, project inputs/outputs, status/log history, images, persistent bind data"
  elif [[ "$action_name" == "down" ]]; then
    say "[DELETE] owned container, activation marker"
    say "[RETAIN] project inputs/outputs, status/log history, images, persistent bind data"
  else
    fail "unsupported destructive action: $action_name"
  fi
}

confirm_destructive_action() {
  local action_name=$1 container_id=$2 assume_yes=$3 answer=""
  show_destructive_plan "$action_name" "$container_id"
  [[ "$assume_yes" == "true" ]] && return 0
  printf 'Type literal yes to continue [no]: '
  if ! IFS= read -r answer; then
    answer=""
  fi
  if [[ "$answer" != "yes" ]]; then
    say "[CANCEL] no Docker/runtime state changed"
    return 1
  fi
  return 0
}

show_status() {
  local container_id=$1
  docker ps --filter "id=$container_id"
  docker exec "$container_id" supervisorctl status || true
  docker exec "$container_id" /opt/http-ztp/activate.py status || true
  docker exec "$container_id" /opt/http-ztp/healthcheck.py || true
}

doctor() {
  local container_id
  host_preflight
  load_runtime_env
  check_management_ssh_key
  prepare_control_auth
  attest_monitor_authority
  container_id=$(owned_container_id false true true)
  if [[ -n "$container_id" ]] && container_id_running "$container_id"; then
    say "[INFO] $container_name ($container_id) is running; its host-network ports are expected"
  else
    assert_service_ports_free
  fi
  say "[OK] Docker deployment prerequisites are ready"
}

action=${1:-}
load_options=()
destructive_assume_yes=false
case "$action" in
  init)
    shift
    parse_init_options "$@"
    ;;
  image-export|build-export)
    [[ "$#" == "2" ]] ||
      fail "usage: sudo $0 $action /absolute/OUTPUT_DIR"
    ;;
  deploy)
    if [[ "$#" == "2" && "$2" == "--no-upgrade" ]]; then
      load_options=(--no-upgrade)
    elif [[ "$#" != "1" ]]; then
      fail "usage: sudo $0 deploy [--no-upgrade]"
    fi
    ;;
  deploy-preloaded|deploy-project-preloaded)
    if [[ "$#" == "3" && "$3" == "--no-upgrade" ]]; then
      load_options=(--no-upgrade)
    elif [[ "$#" != "2" ]]; then
      fail "usage: sudo $0 $action sha256:<64 lowercase hex> [--no-upgrade]"
    fi
    ;;
  rotate-auth)
    [[ "$#" == "2" ]] || fail "usage: sudo $0 rotate-auth nvis|cumulus"
    case "$2" in
      nvis|cumulus) ;;
      *) fail "rotate-auth user must be exactly nvis or cumulus" ;;
    esac
    ;;
  recover-monitor-authority)
    [[ "$#" == "1" ]] ||
      fail "usage: sudo $0 recover-monitor-authority"
    ;;
  unload|down)
    if [[ "$#" == "2" && "$2" == "--yes" ]]; then
      destructive_assume_yes=true
    elif [[ "$#" != "1" ]]; then
      fail "usage: sudo $0 $action [--yes]"
    fi
    ;;
  -h|--help|help|"")
    [[ "$#" -le 1 ]] || fail "help does not accept additional arguments"
    ;;
  *)
    [[ "$#" == "1" ]] || fail "action $action does not accept additional arguments"
    ;;
esac
case "$action" in
  init)
    initialize_runtime_env
    ;;
  doctor)
    doctor
    ;;
  build)
    host_preflight
    build_image
    ;;
  image-export|build-export)
    run_image_export "$2"
    ;;
  deploy)
    host_preflight
    load_runtime_env
    prepare_bind_mounts
    prepare_management_ssh_key
    clear_activation_for_recreate
    prepare_control_auth
    prepare_monitor_authority
    build_image
    start_inactive_container recover "$image_name" auto already-cleared already-prepared already-prepared
    assert_service_ports_free
    run_load "$started_container_id" "${load_options[@]}"
    ;;
  deploy-preloaded)
    host_preflight
    load_runtime_env
    prepare_bind_mounts
    prepare_management_ssh_key
    clear_activation_for_recreate
    prepare_control_auth
    prepare_monitor_authority
    preloaded_image_id=$(verify_preloaded_image "$2")
    say "[OK] verified preloaded image $preloaded_image_id against live source"
    start_inactive_container recover "$preloaded_image_id" plain already-cleared already-prepared already-prepared
    assert_service_ports_free
    run_load "$started_container_id" "${load_options[@]}"
    ;;
  deploy-project-preloaded)
    host_preflight
    load_runtime_env
    prepare_bind_mounts
    prepare_management_ssh_key
    clear_activation_for_recreate
    prepare_control_auth
    prepare_monitor_authority
    project_upgrade_policy=enabled
    if [[ "${#load_options[@]}" -ne 0 ]]; then
      project_upgrade_policy=disabled
    fi
    preloaded_image_id=$(verify_preloaded_image "$2" project "$HTTP_ZTP_PROJECT" "$project_upgrade_policy")
    say "[OK] verified project image $preloaded_image_id for $HTTP_ZTP_PROJECT against live source"
    start_inactive_container recover "$preloaded_image_id" plain already-cleared already-prepared already-prepared
    assert_service_ports_free
    run_load "$started_container_id" "${load_options[@]}"
    ;;
  load)
    host_preflight
    load_runtime_env
    prepare_management_ssh_key
    container_id=$(owned_container_id true true false)
    run_load "$container_id"
    ;;
  reload-network)
    host_preflight
    load_runtime_env
    container_id=$(owned_container_id true true false)
    run_reload_network "$container_id"
    ;;
  rotate-auth)
    host_preflight
    prepare_bind_mounts
    prepare_control_auth
    rotation_status=$(safe_lock_run --rotate-control-auth "$2") ||
      fail "Monitor control credential rotation failed"
    case "$rotation_status" in
      '{"factory_records_active":false,"valid":true}'|\
      '{"factory_records_active":true,"valid":true}') ;;
      *) fail "Monitor control credential rotation returned invalid status" ;;
    esac
    say "[OK] Monitor control credential rotated for $2"
    ;;
  recover-monitor-authority)
    host_preflight
    recover_monitor_authority_action
    ;;
  health)
    host_preflight
    load_runtime_env
    container_id=$(owned_container_id true true false)
    docker exec "$container_id" /opt/http-ztp/healthcheck.py --require-active
    ;;
  status)
    host_preflight
    load_runtime_env
    container_id=$(owned_container_id true true false)
    show_status "$container_id"
    ;;
  logs)
    host_preflight
    container_id=$(owned_container_id false false false)
    docker logs --follow --tail 200 "$container_id"
    ;;
  unload)
    host_preflight
    load_runtime_env
    container_id=$(owned_container_id true true false)
    confirm_destructive_action unload "$container_id" "$destructive_assume_yes" || exit 0
    run_unload "$container_id"
    ;;
  down)
    host_preflight
    load_runtime_env
    container_id=$(owned_container_id false true false)
    confirm_destructive_action down "$container_id" "$destructive_assume_yes" || exit 0
    clear_activation_for_recreate "$container_id"
    say "[OK] removed $container_name; persistent data was retained"
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    usage >&2
    fail "unknown action: $action"
    ;;
esac
