#!/usr/bin/env bash
# Private-root workflow supervisor.  The namespace PID-1 warden is the only
# process allowed to retain pre-isolation references and the only PASS sealer.

set -euo pipefail

readonly REFUSAL='[REFUSED] Monitor authority root-entrypoint runner requires the held host mount-namespace descriptor on FD 9.'
readonly COMMAND_ROOT=${COMMAND_ROOT:-/commands}
readonly EVIDENCE_ROOT=${EVIDENCE_ROOT:-/evidence}
readonly FIXTURE_ROOT=${FIXTURE_ROOT:-/fixture}
readonly EVENT_LOG="$EVIDENCE_ROOT/events.log"
readonly PHASE_LOG="$EVIDENCE_ROOT/phases.jsonl"
readonly OPERATION_LOG="$EVIDENCE_ROOT/operation-results.jsonl"
readonly INFRA_AUDIT_MAP="$EVIDENCE_ROOT/infra-audit-map.jsonl"
readonly OPERATION_CONTEXT="$FIXTURE_ROOT/current-operation"
readonly INFRA_AUDIT_SNAPSHOT=/tmp/http-ztp-monitor-infra-audit-before.json
readonly SOURCE_MANIFEST="$EVIDENCE_ROOT/source-manifest.json"
readonly TREE_ID_FILE="$EVIDENCE_ROOT/expected-tree-id"
readonly AUTHORITY=/var/lib/http-ztp-monitor-auth
readonly DOCKER_AUTHORITY=/var/lib/http-ztp-container/monitor-auth
readonly INSTALLED_HELPER=/usr/local/lib/http-ztp/control-auth.py
readonly REAL_CGI=/usr/lib/cgi-bin/ztp-monitor-control

RECORDED_OPERATION_NAME=""
RECORDED_OPERATION_RETURN_CODE=""
declare -a RECORDED_OPERATION_ARGV=()

export PATH="$COMMAND_ROOT"

refuse() {
  printf '%s\n' "$REFUSAL" >&2
  exit 64
}

fail() {
  printf '[FAIL] %s\n' "$1" >&2
  exit 1
}

[[ $# == 1 ]] || refuse
[[ "$1" == --execute-private-fixtures ]] || refuse

verify_supervisor_descriptor_set() {
  local path descriptor target
  for path in /proc/self/fd/*; do
    descriptor=${path##*/}
    case "$descriptor" in
      0|1|2) continue ;;
    esac
    if target=$(readlink -- "$path" 2>/dev/null); then
      fail "unexpected workflow-supervisor descriptor $descriptor ($target)"
    fi
  done
}

verify_fixture_mounts() {
  python3 -B - <<'PY'
from pathlib import Path

required = {"/", "/commands", "/dev", "/evidence", "/fixture", "/proc", "/run", "/source", "/tmp", "/var"}
records = []
for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
    left, right = line.split(" - ", 1)
    fields = left.split()
    target = fields[4].replace("\\040", " ")
    options = frozenset(fields[5].split(","))
    propagation = frozenset(item for item in fields[6:] if item.endswith(":") or item.startswith(("shared:", "master:")))
    fs_type = right.split()[0]
    records.append((target, options, propagation, fs_type))
targets = {item[0] for item in records}
if not required <= targets:
    raise SystemExit("private fixture mount set is incomplete")
root_records = [item for item in records if item[0] == "/"]
if len(root_records) != 1 or "ro" not in root_records[0][1] or "rw" in root_records[0][1]:
    raise SystemExit("private root mount is not read-only")
for target, options, propagation, fs_type in records:
    if propagation:
        raise SystemExit("non-private propagation is reachable")
    if target.startswith(("/sys/fs/cgroup", "/old-root", "/home", "/mnt", "/media")):
        raise SystemExit("forbidden host/control mount is reachable")
    writable = "rw" in options
    private_roots = ("/dev", "/evidence", "/fixture", "/proc", "/run", "/tmp", "/var")
    allowed_writable = (
        target == "/source/infra"
        or any(target == root or target.startswith(root + "/") for root in private_roots)
    )
    if writable and not allowed_writable:
        raise SystemExit("undeclared writable descendant mount is reachable")
    if fs_type in {"devtmpfs", "cgroup", "cgroup2", "debugfs", "tracefs"}:
        raise SystemExit("forbidden control/device filesystem is reachable")
PY
}

verify_private_root_readonly() {
  python3 -B - <<'PY'
import errno
import os

probe = "/etc/monitor-root-writable-probe"
try:
    descriptor = os.open(
        probe,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
except OSError as exc:
    if exc.errno != errno.EROFS:
        raise SystemExit(f"private root write probe failed ambiguously: errno={exc.errno}")
else:
    os.close(descriptor)
    raise SystemExit("private root unexpectedly accepted a write")
if os.path.lexists(probe):
    raise SystemExit("private root write probe left an artifact")
PY
}

verify_private_source_copy() {
  [[ "$PWD" == /source ]] || fail "workflow is not running from the private source view"
  [[ -r "$SOURCE_MANIFEST" && -r "$TREE_ID_FILE" ]] ||
    fail "immutable source evidence is absent"
  python3 -B - <<'PY'
import json
from pathlib import Path

tree_id = Path("/evidence/expected-tree-id").read_text(encoding="ascii")
manifest = json.loads(Path("/evidence/source-manifest.json").read_bytes())
if not tree_id.endswith("\n") or manifest.get("tree_id") != tree_id[:-1]:
    raise SystemExit("source manifest is not bound to the expected tree")
required = {
    "test_cases/run_monitor_authority_entrypoints.sh",
    "test_cases/monitor_authority_root_warden.py",
    "test_cases/monitor_authority_source_guard.py",
    "tools/control-auth.py",
    "infra/infra-setup.sh",
    "infra/infra-teardown.sh",
    "infra/docker/deploy.sh",
}
if not required <= {entry["path"] for entry in manifest["entries"]}:
    raise SystemExit("source manifest omits a required authority component")
PY
}

verify_stub_authority() {
  [[ "$PATH" == "$COMMAND_ROOT" ]] || fail "workflow PATH is not the finite command root"
  python3 -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat

root = Path("/commands")
manifest_path = Path("/evidence/command-manifest.json")
raw = manifest_path.read_bytes()
manifest = json.loads(raw)
if set(manifest) != {"entries", "leaf_names", "schema_version"} or manifest["schema_version"] != 1:
    raise SystemExit("command manifest grammar is invalid")
expected = {entry["name"] for entry in manifest["entries"]}
if manifest["leaf_names"] != sorted(expected) or len(manifest["leaf_names"]) != len(expected):
    raise SystemExit("command manifest leaf-name set is invalid")
actual = {entry.name for entry in os.scandir(root)}
if actual != expected:
    raise SystemExit("finite command leaf set changed")
for entry in manifest["entries"]:
    if set(entry) != {"mode", "name", "sha256", "type"}:
        raise SystemExit("command manifest entry grammar is invalid")
    path = root / entry["name"]
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or entry["mode"] != 0o555
            or entry["type"] not in {"service-stub", "utility"}
            or stat.S_IMODE(info.st_mode) != entry["mode"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]):
        raise SystemExit("finite command authority changed")
PY
  for forbidden in curl touch ssh wget nc; do
    if command -v "$forbidden" >/dev/null 2>&1; then
      fail "forbidden command is reachable"
    fi
  done
}

verify_network_and_pid_namespace() {
  [[ ${PPID:-0} == 1 ]] || fail "workflow supervisor is not the sole PID-1 child"
  python3 -B - <<'PY'
from pathlib import Path

routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
interfaces = {
    line.split(":", 1)[0].strip()
    for line in Path("/proc/net/dev").read_text(encoding="ascii").splitlines()[2:]
    if ":" in line
}
if routes or not interfaces <= {"lo"}:
    raise SystemExit("private network namespace exposes a route")
PY
}

record_phase() {
  local phase=$1
  python3 -B - "$phase" <<'PY'
import json
from pathlib import Path
import sys

required = (
    "supervisor-preconditions",
    "argv-collision-matrix",
    "bad-payload-cgi-503",
    "recovery-marker-routine-rejection",
    "native-stopped-writer-matrix",
    "native-lifecycle-cgi-200",
    "docker-writer-stop-remove",
    "recovery-decision-enum",
    "teardown-preservation",
    "postflight-attestation",
)
target = Path("/evidence/phases.jsonl")
existing = target.read_bytes().splitlines() if target.exists() else []
index = len(existing) + 1
phase = sys.argv[1]
if index > len(required) or phase != required[index - 1]:
    raise SystemExit("workflow phase is missing, duplicated, or out of order")
line = json.dumps({"index": index, "phase": phase}, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
with target.open("ab", buffering=0) as stream:
    stream.write(line)
    os_fsync = __import__("os").fsync
    os_fsync(stream.fileno())
PY
}

begin_operation() {
  local operation=$1
  printf '%s\n' "$operation" >"$OPERATION_CONTEXT"
  chmod 0600 "$OPERATION_CONTEXT"
}

snapshot_protected_paths() {
  local target=$1 stage=$2
  shift 2
  python3 -B - "$target" "$stage" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

target = Path(sys.argv[1])
stage = sys.argv[2]
roots = tuple(Path(value) for value in sys.argv[3:])
if not roots or any(not path.is_absolute() for path in roots):
    raise SystemExit("protected snapshot roots are not fixed absolute paths")

records = []
seen = set()

def identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode,
        metadata.st_uid, metadata.st_gid, metadata.st_nlink,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )

def walk(path):
    raw_path = str(path)
    if raw_path in seen:
        raise SystemExit("protected snapshot path is duplicated")
    seen.add(raw_path)
    named = path.lstat()
    base = {
        "ctime_ns": named.st_ctime_ns,
        "device": named.st_dev,
        "gid": named.st_gid,
        "inode": named.st_ino,
        "links": named.st_nlink,
        "mode": named.st_mode,
        "mtime_ns": named.st_mtime_ns,
        "path": raw_path,
        "size": named.st_size,
        "uid": named.st_uid,
    }
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    if stat.S_ISDIR(named.st_mode):
        descriptor = os.open(path, flags | os.O_DIRECTORY)
        try:
            held = os.fstat(descriptor)
            if identity(held) != identity(named):
                raise SystemExit("protected directory was rebound")
            base["type"] = "directory"
            records.append(base)
            for name in sorted(os.listdir(descriptor)):
                if not name or name in {".", ".."} or "/" in name:
                    raise SystemExit("protected snapshot name is unsafe")
                walk(path / name)
            if identity(os.fstat(descriptor)) != identity(named):
                raise SystemExit("protected directory changed while reading")
        finally:
            os.close(descriptor)
        return
    if (
        not stat.S_ISREG(named.st_mode)
        or named.st_nlink != 1
        or named.st_size > 1024 * 1024
    ):
        raise SystemExit("protected snapshot leaf is not single-link regular")
    descriptor = os.open(path, flags | os.O_NONBLOCK)
    try:
        held = os.fstat(descriptor)
        payload = b""
        while len(payload) <= 1024 * 1024:
            chunk = os.read(descriptor, min(65536, 1024 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        rebound = path.lstat()
    finally:
        os.close(descriptor)
    if (
        len(payload) != named.st_size
        or identity(held) != identity(named)
        or identity(rebound) != identity(named)
    ):
        raise SystemExit("protected snapshot leaf changed while reading")
    base["type"] = "file"
    base["sha256"] = hashlib.sha256(payload).hexdigest()
    records.append(base)

for root in roots:
    walk(root)
records.sort(key=lambda record: record["path"])
document = {"records": records}
if stage != "@single":
    document["stage"] = stage
payload = json.dumps(
    document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
).encode("ascii") + b"\n"
flags = os.O_WRONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
if target.exists():
    if stage == "@single":
        raise SystemExit("single protected snapshot already exists")
    flags |= os.O_APPEND
else:
    flags |= os.O_CREAT | os.O_EXCL
descriptor = os.open(target, flags, 0o600)
try:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SystemExit("protected snapshot evidence metadata is unsafe")
    if os.write(descriptor, payload) != len(payload):
        raise SystemExit("short protected snapshot evidence write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

write_invocation_evidence() {
  local target=$1 returncode=$2
  shift 2
  python3 -B - "$target" "$returncode" "$@" <<'PY'
import json
import os
from pathlib import Path
import sys

target = Path(sys.argv[1])
document = {"argv": sys.argv[3:], "returncode": int(sys.argv[2])}
payload = json.dumps(
    document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
).encode("ascii") + b"\n"
descriptor = os.open(
    target,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
try:
    if os.write(descriptor, payload) != len(payload):
        raise SystemExit("short invocation evidence write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

attest_with_evidence() {
  local prefix=$1 invocation=$2 rc
  local -a argv=(
    "$INSTALLED_HELPER" monitor-authority-attest-decision
  )
  set +e
  "${argv[@]}" >"$EVIDENCE_ROOT/$prefix.out" \
    2>"$EVIDENCE_ROOT/$prefix.err"
  rc=$?
  set -e
  write_invocation_evidence \
    "$invocation" "$rc" "${argv[@]}"
  [[ $rc == 0 ]] || fail "$prefix returned nonzero"
}

capture_infra_audit_before() {
  local operation=$1 command=$2 prefix
  case "$command" in
    ./infra/infra-setup.sh) prefix=infra-setup- ;;
    ./infra/infra-teardown.sh) prefix=infra-teardown- ;;
    *) return 0 ;;
  esac
  python3 -B - "$operation" "$prefix" <<'PY'
import json
import os
from pathlib import Path
import sys

target = Path("/tmp/http-ztp-monitor-infra-audit-before.json")
if target.exists():
    raise SystemExit("infra audit snapshot already exists")
logs = Path("/source/infra/logs")
names = sorted(path.name for path in logs.iterdir()) if logs.exists() else []
document = {
    "names": names,
    "operation": sys.argv[1],
    "prefix": sys.argv[2],
}
payload = json.dumps(
    document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
).encode("ascii") + b"\n"
descriptor = os.open(
    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600,
)
try:
    if os.write(descriptor, payload) != len(payload):
        raise SystemExit("short infra audit snapshot write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

capture_infra_audit_after() {
  local operation=$1 command=$2
  case "$command" in
    ./infra/infra-setup.sh|./infra/infra-teardown.sh) ;;
    *) return 0 ;;
  esac
  python3 -B - "$operation" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

snapshot_path = Path("/tmp/http-ztp-monitor-infra-audit-before.json")
snapshot_raw = snapshot_path.read_bytes()
snapshot = json.loads(snapshot_raw.decode("ascii"))
canonical_snapshot = json.dumps(
    snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
).encode("ascii") + b"\n"
if (
    snapshot_raw != canonical_snapshot
    or set(snapshot) != {"names", "operation", "prefix"}
    or snapshot["operation"] != sys.argv[1]
    or snapshot["prefix"] not in {"infra-setup-", "infra-teardown-"}
    or not isinstance(snapshot["names"], list)
    or not all(isinstance(name, str) for name in snapshot["names"])
):
    raise SystemExit("infra audit snapshot changed")
logs = Path("/source/infra/logs")
current = sorted(path.name for path in logs.iterdir())
before = set(snapshot["names"])
if not before <= set(current):
    raise SystemExit("infra audit log set lost an existing leaf")
added = sorted(set(current) - before)
pattern = re.compile(
    re.escape(snapshot["prefix"]) + r"[0-9]{8}_[0-9]{6}-[0-9]+\.log\Z"
)
if len(added) != 1 or pattern.fullmatch(added[0]) is None:
    raise SystemExit("entrypoint did not create one attributable infra log")
name = added[0]
path = logs / name
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_nlink != 1
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_size > 1024 * 1024
):
    raise SystemExit("attributed infra log metadata is unsafe")
payload = path.read_bytes()
if len(payload) != metadata.st_size:
    raise SystemExit("attributed infra log changed while reading")
warning = (
    b"WARNING: explicit Monitor authority recovery reset invalid cache state; "
    b"review the accepted www-data denial residual.\n"
)
if payload.count(warning) != payload.splitlines(keepends=True).count(warning):
    raise SystemExit("attributed infra warning is not an exact line")
record = {
    "log_name": name,
    "operation": sys.argv[1],
    "reset_warning_count": payload.count(warning),
    "sha256": hashlib.sha256(payload).hexdigest(),
    "size": len(payload),
}
encoded = json.dumps(
    record, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
).encode("ascii") + b"\n"
target = Path("/evidence/infra-audit-map.jsonl")
descriptor = os.open(
    target, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
    | getattr(os, "O_NOFOLLOW", 0),
)
try:
    if os.write(descriptor, encoded) != len(encoded):
        raise SystemExit("short infra audit map write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
snapshot_path.unlink()
PY
}

execute_recorded_operation() {
  local operation=$1 stdout_path=$2 stderr_path=$3
  shift 3
  begin_operation "$operation"
  capture_infra_audit_before "$operation" "$@"
  set +e
  if [[ "$stderr_path" == @stdout ]]; then
    "$@" >"$stdout_path" 2>&1
  else
    "$@" >"$stdout_path" 2>"$stderr_path"
  fi
  RECORDED_OPERATION_RETURN_CODE=$?
  set -e
  capture_infra_audit_after "$operation" "$@"
  RECORDED_OPERATION_NAME=$operation
  RECORDED_OPERATION_ARGV=("$@")
}

record_operation_result() {
  local operation=$1
  [[ "$RECORDED_OPERATION_NAME" == "$operation" ]] ||
    fail "operation-result is not bound to the immediately executed operation"
  python3 -B - "$operation" "$RECORDED_OPERATION_RETURN_CODE" \
    "${RECORDED_OPERATION_ARGV[@]}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

operation = sys.argv[1]
try:
    returncode = int(sys.argv[2])
except ValueError as exc:
    raise SystemExit("operation return code is not an integer") from exc
actual_argv = tuple(sys.argv[3:])

specs = []
for index in range(10):
    target = "status.lock" if index < 5 else "monitor-auth/factory-status.json"
    specs.append((
        f"bad-{index}", 1,
        (
            (f"authority-input@{target}", f"bad-payload-{index}.bin"),
            ("authority-tree-observations", f"authority-bad-{index}.jsonl"),
            ("health-combined", f"health-{index}.out"),
            ("cgi-stdout", f"cgi-bad-{index}.out"),
            ("cgi-stderr", f"cgi-bad-{index}.out.err"),
            ("cgi-invocation", f"cgi-bad-{index}.invocation.json"),
        ),
    ))
for phase in ("recovery-in-progress", "recovery-committed-cleanup-pending"):
    specs.append((
        f"marker-{phase}", 0,
        (
            ("authority-tree-observations", f"authority-marker-{phase}.jsonl"),
            ("classification-stdout", f"marker-{phase}.out"),
            ("classification-stderr", f"marker-{phase}.err"),
            ("recovery-stdout", f"marker-reset-{phase}.out"),
            ("recovery-stderr", f"marker-reset-{phase}.err"),
            ("post-attest-stdout", f"marker-after-{phase}.out"),
            ("post-attest-stderr", f"marker-after-{phase}.err"),
        ),
    ))
for mode in ("stop-fail", "show-fail", "stay-active"):
    specs.append((
        f"stop-{mode}", 1,
        (("authority-tree-observations", f"authority-stop-{mode}.jsonl"),
         ("recovery-stdout", f"stop-{mode}.out"),
         ("recovery-stderr", f"stop-{mode}.err")),
    ))
for index, state in enumerate(("active", "inactive", "failed")):
    specs.append((
        f"native-{state}", 0,
        (
            ("authority-tree-observations", f"authority-native-{state}.jsonl"),
            ("recovery-stdout", f"native-{state}.out"),
            ("recovery-stderr", f"native-{state}.err"),
            ("post-attest-stdout", f"native-attest-{state}.out"),
            ("post-attest-stderr", f"native-attest-{state}.err"),
            ("cgi-stdout", f"cgi-good-{index}.out"),
            ("cgi-stderr", f"cgi-good-{index}.out.err"),
            ("cgi-invocation", f"cgi-good-{index}.invocation.json"),
        ),
    ))
specs.extend((
    ("docker-writer", 0,
     (("container-authority-observations", "authority-docker-container.jsonl"),
      ("native-authority-observations", "authority-docker-native.jsonl"),
      ("recovery-stdout", "docker-recover.out"),
      ("recovery-stderr", "docker-recover.err"))),
    ("teardown", 0,
     (("pre-teardown-attest-stdout", "pre-teardown-attest.out"),
      ("pre-teardown-attest-stderr", "pre-teardown-attest.err"),
      ("pre-teardown-attest-invocation", "pre-teardown-attest.invocation.json"),
      ("authority-before", "teardown-before.json"),
      ("authority-after", "teardown-after.json"),
      ("teardown-stdout", "teardown.out"),
      ("teardown-stderr", "teardown.err"))),
))

target = Path("/evidence/operation-results.jsonl")
existing = target.read_bytes().splitlines() if target.exists() else []
index = len(existing) + 1
if index > len(specs):
    raise SystemExit("operation-result log has too many records")
expected_operation, expected_rc, artifact_specs = specs[index - 1]
if operation != expected_operation or returncode != expected_rc:
    raise SystemExit("operation-result invocation changed order or return code")
artifacts = []
for role, name in artifact_specs:
    payload = (Path("/evidence") / name).read_bytes()
    artifacts.append({
        "name": name,
        "role": role,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    })
record = {
    "argv": list(actual_argv),
    "artifacts": artifacts,
    "index": index,
    "operation": operation,
    "returncode": returncode,
}
encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC, 0o600)
try:
    if os.write(descriptor, encoded) != len(encoded):
        raise SystemExit("short operation-result write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

exercise_argv_collisions() {
  local state_before state_after
  begin_operation argv-collision-matrix
  state_before=$(sha256sum "$EVIDENCE_ROOT/service-state.json")
  local -a probes=(
    'docker|context show'
    'docker|context|show|'
    'systemctl|stop apache2'
    'systemctl|stop| apache2'
    'dpkg|-s|apache2|extra'
    'supervisord|-n -c /etc/supervisor/supervisord.conf'
    'supervisorctl|status|extra'
    'ss|-ltnp|'
    'apache2ctl|config|test'
  )
  local probe command packed rc stdout_file stderr_file
  for probe in "${probes[@]}"; do
    IFS='|' read -r command packed _extra _more <<<"$probe"
    stdout_file="$EVIDENCE_ROOT/collision.stdout"
    stderr_file="$EVIDENCE_ROOT/collision.stderr"
    set +e
    case "$probe" in
      'docker|context show') docker 'context show' >"$stdout_file" 2>"$stderr_file" ;;
      'docker|context|show|') docker context show '' >"$stdout_file" 2>"$stderr_file" ;;
      'systemctl|stop apache2') systemctl 'stop apache2' >"$stdout_file" 2>"$stderr_file" ;;
      'systemctl|stop| apache2') systemctl stop ' apache2' >"$stdout_file" 2>"$stderr_file" ;;
      'dpkg|-s|apache2|extra') dpkg -s apache2 extra >"$stdout_file" 2>"$stderr_file" ;;
      'supervisord|-n -c /etc/supervisor/supervisord.conf') supervisord '-n -c /etc/supervisor/supervisord.conf' >"$stdout_file" 2>"$stderr_file" ;;
      'supervisorctl|status|extra') supervisorctl status extra >"$stdout_file" 2>"$stderr_file" ;;
      'ss|-ltnp|') ss -ltnp '' >"$stdout_file" 2>"$stderr_file" ;;
      'apache2ctl|config|test') apache2ctl config test >"$stdout_file" 2>"$stderr_file" ;;
    esac
    rc=$?
    set -e
    [[ $rc == 99 ]] || fail "argv collision did not return 99"
    [[ ! -s "$stdout_file" ]] || fail "forbidden argv wrote stdout"
    cmp -s "$stderr_file" <(printf 'FORBIDDEN\n') || fail "forbidden argv diagnostic changed"
  done
  state_after=$(sha256sum "$EVIDENCE_ROOT/service-state.json")
  [[ "$state_before" == "$state_after" ]] || fail "forbidden argv mutated service state"
}

install_literal_bad_payload() {
  python3 -B - "$1" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import sys

index = int(sys.argv[1])
helper_digest = hashlib.sha256(Path("/usr/local/lib/http-ztp/control-auth.py").read_bytes()).hexdigest()
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
breaker = lambda schema, count, extra=False: canonical({
    "schema_version": schema, "contaminant_dev": 7,
    "contaminant_ino": 11, "failure_count": count,
    **({"extra": False} if extra else {}),
})
cache = lambda schema, digest, extra=False: canonical({
    "schema_version": schema, "factory_records_active": True,
    "helper_sha256": digest, **({"extra": False} if extra else {}),
})
lock = Path("/var/lib/http-ztp-monitor-auth/status.lock")
leaf = Path("/var/lib/http-ztp-monitor-auth/monitor-auth/factory-status.json")
payloads = (
    (lock, b'{"schema_version":1'), (lock, breaker(1, 1, True)),
    (lock, breaker(2, 1)), (lock, breaker(1, 0)), (lock, breaker(1, 4)),
    (leaf, b""), (leaf, b'{"schema_version":1'),
    (leaf, cache(1, helper_digest, True)), (leaf, cache(2, helper_digest)),
    (leaf, cache(1, "0" * 64)),
)
path, payload = payloads[index]
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(payload)
os.chown(path, 0 if path == lock else 33, 33)
path.chmod(0o660 if path == lock else 0o600)
evidence = Path(f"/evidence/bad-payload-{index}.bin")
evidence.write_bytes(payload)
evidence.chmod(0o600)
with evidence.open("rb") as stream:
    os.fsync(stream.fileno())
PY
}

reset_authority_fixture() {
  python3 -B - <<'PY'
from pathlib import Path
import shutil

root = Path("/var/lib/http-ztp-monitor-auth")
if root.exists():
    shutil.rmtree(root)
PY
  "$INSTALLED_HELPER" monitor-authority-provision
}

install_literal_docker_bad_payload() {
  python3 -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path

root = Path("/var/lib/http-ztp-container/monitor-auth")
lock = root / "status.lock"
cache = root / "monitor-auth/factory-status.json"
helper = Path("/usr/local/lib/http-ztp/control-auth.py")
valid_cache = (
    json.dumps({
        "factory_records_active": True,
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "schema_version": 1,
    }, sort_keys=True, separators=(",", ":")) + "\n"
).encode("ascii")
if cache.read_bytes() != valid_cache:
    raise SystemExit("Docker bad-payload fixture lacks its valid sibling cache")
lock.write_bytes(b'{"schema_version":1')
os.chown(lock, 0, 33)
lock.chmod(0o660)
PY
}

run_real_cgi() {
  local expected=$1 label=$2 output="$EVIDENCE_ROOT/cgi-$2.out" rc
  local invocation="$EVIDENCE_ROOT/cgi-$2.invocation.json"
  local -a cgi_argv=(
    setpriv --reuid=33 --regid=33 --clear-groups
    env -i CONTROL_REQUIRE_AUTH=1 AUTH_TYPE=Basic REMOTE_USER=nvis
    PATH_INFO= SCRIPT_NAME=/monitor/control/ztp-monitor REQUEST_METHOD=GET
    HOME=/root LANG=C.UTF-8 LC_ALL=C.UTF-8 PATH="$COMMAND_ROOT"
    PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
    "$REAL_CGI"
  )
  set +e
  "${cgi_argv[@]}" >"$output" 2>"$output.err"
  rc=$?
  set -e
  [[ $rc == 0 ]] || fail "real CGI process returned nonzero"
  python3 -B - "$invocation" "$rc" "${cgi_argv[@]}" <<'PY'
import json
import os
from pathlib import Path
import sys

target = Path(sys.argv[1])
returncode = int(sys.argv[2])
document = {"argv": sys.argv[3:], "returncode": returncode}
payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
descriptor = os.open(
    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600,
)
try:
    if os.write(descriptor, payload) != len(payload):
        raise SystemExit("short CGI invocation evidence write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  grep -Fq "Status: $expected" "$output" || fail "real CGI returned an unexpected status"
}

exercise_bad_payloads() {
  local index rc
  reset_authority_fixture
  for index in 0 1 2 3 4 5 6 7 8 9; do
    install_literal_bad_payload "$index"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-bad-$index.jsonl" pre-health "$AUTHORITY"
    execute_recorded_operation \
      "bad-$index" "$EVIDENCE_ROOT/health-$index.out" @stdout \
      python3 -B infra/docker/healthcheck.py
    rc=$RECORDED_OPERATION_RETURN_CODE
    [[ $rc == 1 ]] || fail "real health path did not reject malformed Monitor authority with rc=1"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-bad-$index.jsonl" post-health "$AUTHORITY"
    run_real_cgi '503 Service Unavailable' "bad-$index"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-bad-$index.jsonl" post-cgi "$AUTHORITY"
    record_operation_result "bad-$index"
    reset_authority_fixture
  done
}

exercise_recovery_marker_routine_rejection() {
  local phase rc marker="$AUTHORITY/monitor-auth/.factory-status.11111111111111111111111111111111.tmp"
  for phase in recovery-in-progress recovery-committed-cleanup-pending; do
    begin_operation "marker-$phase"
    printf 'normal\n' >"$FIXTURE_ROOT/systemctl-mode"
    printf 'active\n' >"$FIXTURE_ROOT/systemctl-state"
    printf '{"phase":"%s","schema_version":1}\n' "$phase" >"$marker"
    chown 33:33 "$marker"
    chmod 0600 "$marker"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-marker-$phase.jsonl" \
      pre-classification "$AUTHORITY"
    "$INSTALLED_HELPER" monitor-authority-attest-decision \
      >"$EVIDENCE_ROOT/marker-$phase.out" 2>"$EVIDENCE_ROOT/marker-$phase.err" ||
      fail "routine marker classification did not use the fixed success channel"
    [[ ! -s "$EVIDENCE_ROOT/marker-$phase.err" ]] ||
      fail "routine marker classification wrote stderr"
    cmp -s "$EVIDENCE_ROOT/marker-$phase.out" <(printf '%s' "$phase") ||
      fail "routine marker classification token changed"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-marker-$phase.jsonl" \
      post-classification "$AUTHORITY"
    execute_recorded_operation \
      "marker-$phase" "$EVIDENCE_ROOT/marker-reset-$phase.out" \
      "$EVIDENCE_ROOT/marker-reset-$phase.err" \
      ./infra/infra-setup.sh --recover-monitor-authority
    rc=$RECORDED_OPERATION_RETURN_CODE
    [[ $rc == 0 ]] || fail "explicit marker recovery failed"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-marker-$phase.jsonl" \
      post-recovery "$AUTHORITY"
    "$INSTALLED_HELPER" monitor-authority-attest-decision \
      >"$EVIDENCE_ROOT/marker-after-$phase.out" \
      2>"$EVIDENCE_ROOT/marker-after-$phase.err"
    cmp -s "$EVIDENCE_ROOT/marker-after-$phase.out" <(printf attest-valid) ||
      fail "marker recovery did not finish with read-only attest-valid"
    [[ ! -s "$EVIDENCE_ROOT/marker-after-$phase.err" ]] ||
      fail "marker post-recovery attest wrote stderr"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-marker-$phase.jsonl" \
      post-attest "$AUTHORITY"
    [[ $(<"$FIXTURE_ROOT/systemctl-state") == active ]] ||
      fail "marker recovery did not restore initially active Apache"
    record_operation_result "marker-$phase"
  done
}

exercise_native_matrix() {
  local initial before starts_after rc index=0
  for initial in active inactive failed; do
    install_literal_bad_payload 0
    printf '%s\n' "$initial" >"$FIXTURE_ROOT/systemctl-state"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-native-$initial.jsonl" \
      pre-recovery "$AUTHORITY"
    before=$(grep -c '^systemctl start apache2$' "$EVENT_LOG" || :)
    execute_recorded_operation \
      "native-$initial" "$EVIDENCE_ROOT/native-$initial.out" \
      "$EVIDENCE_ROOT/native-$initial.err" \
      ./infra/infra-setup.sh --recover-monitor-authority
    rc=$RECORDED_OPERATION_RETURN_CODE
    [[ $rc == 0 ]] || fail "Native explicit recovery failed"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-native-$initial.jsonl" \
      post-recovery "$AUTHORITY"
    starts_after=$(grep -c '^systemctl start apache2$' "$EVENT_LOG" || :)
    if [[ "$initial" == active ]]; then
      [[ $starts_after == $((before + 1)) ]] || fail "active Apache was not restored exactly once"
    else
      [[ $starts_after == "$before" ]] || fail "non-active Apache was started"
    fi
    "$INSTALLED_HELPER" monitor-authority-attest-decision \
      >"$EVIDENCE_ROOT/native-attest-$initial.out" \
      2>"$EVIDENCE_ROOT/native-attest-$initial.err"
    cmp -s "$EVIDENCE_ROOT/native-attest-$initial.out" <(printf attest-valid) ||
      fail "Native recovery did not finish with read-only attest-valid"
    [[ ! -s "$EVIDENCE_ROOT/native-attest-$initial.err" ]] ||
      fail "Native post-recovery attest wrote stderr"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-native-$initial.jsonl" \
      post-attest "$AUTHORITY"
    run_real_cgi '200 OK' "good-$index"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-native-$initial.jsonl" \
      post-cgi "$AUTHORITY"
    record_operation_result "native-$initial"
    index=$((index + 1))
  done
}

exercise_native_stop_failures() {
  local mode before after payload_before payload_after rc
  for mode in stop-fail show-fail stay-active; do
    install_literal_bad_payload 0
    printf '%s\n' "$mode" >"$FIXTURE_ROOT/systemctl-mode"
    printf 'active\n' >"$FIXTURE_ROOT/systemctl-state"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-stop-$mode.jsonl" \
      pre-recovery "$AUTHORITY"
    payload_before=$(sha256sum "$AUTHORITY/status.lock")
    before=$(grep -c '^systemctl start apache2$' "$EVENT_LOG" || :)
    execute_recorded_operation \
      "stop-$mode" "$EVIDENCE_ROOT/stop-$mode.out" \
      "$EVIDENCE_ROOT/stop-$mode.err" \
      ./infra/infra-setup.sh --recover-monitor-authority
    rc=$RECORDED_OPERATION_RETURN_CODE
    [[ $rc == 1 ]] || fail "Native stopped-writer proof did not reject $mode with rc=1"
    snapshot_protected_paths \
      "$EVIDENCE_ROOT/authority-stop-$mode.jsonl" \
      post-recovery "$AUTHORITY"
    payload_after=$(sha256sum "$AUTHORITY/status.lock")
    after=$(grep -c '^systemctl start apache2$' "$EVENT_LOG" || :)
    [[ "$payload_before" == "$payload_after" && "$before" == "$after" ]] ||
      fail "stopped-writer failure repaired or started Apache"
    record_operation_result "stop-$mode"
    printf 'normal\n' >"$FIXTURE_ROOT/systemctl-mode"
    reset_authority_fixture
  done
}

exercise_docker_writer_removal() {
  local rc
  install_literal_docker_bad_payload
  printf 'running\n' >"$FIXTURE_ROOT/docker-state"
  snapshot_protected_paths \
    "$EVIDENCE_ROOT/authority-docker-container.jsonl" \
    pre-recovery "$DOCKER_AUTHORITY"
  snapshot_protected_paths \
    "$EVIDENCE_ROOT/authority-docker-native.jsonl" \
    pre-recovery "$AUTHORITY"
  execute_recorded_operation \
    docker-writer "$EVIDENCE_ROOT/docker-recover.out" \
    "$EVIDENCE_ROOT/docker-recover.err" \
    ./infra/docker/deploy.sh recover-monitor-authority
  rc=$RECORDED_OPERATION_RETURN_CODE
  [[ $rc == 0 ]] || fail "Docker explicit recovery failed"
  snapshot_protected_paths \
    "$EVIDENCE_ROOT/authority-docker-container.jsonl" \
    post-recovery "$DOCKER_AUTHORITY"
  snapshot_protected_paths \
    "$EVIDENCE_ROOT/authority-docker-native.jsonl" \
    post-recovery "$AUTHORITY"
  [[ $(<"$FIXTURE_ROOT/docker-state") == absent ]] || fail "Docker writer remains"
  grep -Fq '[NEXT] sudo ./infra/docker/deploy.sh deploy' "$EVIDENCE_ROOT/docker-recover.out" ||
    fail "Docker recovery omitted the stopped next step"
  python3 -B - <<'PY'
from pathlib import Path

events = Path("/evidence/events.log").read_text(encoding="utf-8").splitlines()
names = ("docker-inspect-writer", "docker-stop-writer", "docker-reinspect-writer", "docker-remove-writer")
positions = [events.index(name) for name in names]
if positions != sorted(positions):
    raise SystemExit("Docker writer removal order changed")
if any(name in events for name in ("docker-create", "docker-start", "docker-build")):
    raise SystemExit("Docker recovery started a writer")
PY
  record_operation_result docker-writer
}

exercise_recovery_decision_enum() {
  python3 -B - <<'PY'
import runpy

module = runpy.run_path("tools/control-auth.py", run_name="monitor_decision_probe")
decide = module["monitor_authority_recovery_decision"]
reset_warning = module["MONITOR_AUTHORITY_RECOVERY_WARNING"] + "\n"
durability = module["MONITOR_AUTHORITY_CLEANUP_DURABILITY_WARNING"] + "\n"
matrix = (("complete", True), ("marker-removal-durability-unknown", True),
          ("marker-retained", False), ("marker-authority-uncertain", False))
observed = []
for cleanup, allowed in matrix:
    for reset in (False, True):
        diagnostics = reset_warning if reset else ""
        if cleanup == "marker-removal-durability-unknown":
            diagnostics += durability
        token = decide({"cleanup": cleanup, "recovery_committed": True,
                        "restart_allowed": allowed}, diagnostics)
        observed.append({
            "cleanup": cleanup,
            "diagnostics_sha256": __import__("hashlib").sha256(
                diagnostics.encode("utf-8")
            ).hexdigest(),
            "diagnostics_size": len(diagnostics.encode("utf-8")),
            "recovery_committed": True,
            "reset_invalid_cache": reset,
            "restart_allowed": allowed,
            "token": token,
        })
if {row["token"] for row in observed} != set(module["MONITOR_AUTHORITY_DECISION_TOKENS"]) - {
        "attest-valid", "recovery-in-progress", "recovery-committed-cleanup-pending"}:
    raise SystemExit("recovery decision enum is incomplete")
Path = __import__("pathlib").Path
Path("/evidence/recovery-decisions.json").write_text(
    __import__("json").dumps(
        observed, sort_keys=True, separators=(",", ":"),
    ) + "\n",
    encoding="ascii",
)
PY
}

exercise_teardown_preservation() {
  local rc
  attest_with_evidence pre-teardown-attest \
    "$EVIDENCE_ROOT/pre-teardown-attest.invocation.json"
  cmp -s "$EVIDENCE_ROOT/pre-teardown-attest.out" \
    <(printf attest-valid) || fail "Native authority is invalid before teardown"
  [[ ! -s "$EVIDENCE_ROOT/pre-teardown-attest.err" ]] ||
    fail "pre-teardown read-only attest wrote stderr"
  snapshot_protected_paths "$EVIDENCE_ROOT/teardown-before.json" @single \
    "$INSTALLED_HELPER" \
    /etc/apache2/conf-enabled/http-ztp-public-boundary.conf \
    "$AUTHORITY"
  execute_recorded_operation \
    teardown "$EVIDENCE_ROOT/teardown.out" "$EVIDENCE_ROOT/teardown.err" \
    ./infra/infra-teardown.sh --non-interactive --yes
  rc=$RECORDED_OPERATION_RETURN_CODE
  [[ $rc == 0 ]] || fail "real teardown entrypoint failed"
  snapshot_protected_paths "$EVIDENCE_ROOT/teardown-after.json" @single \
    "$INSTALLED_HELPER" \
    /etc/apache2/conf-enabled/http-ztp-public-boundary.conf \
    "$AUTHORITY"
  cmp -s "$EVIDENCE_ROOT/teardown-before.json" \
    "$EVIDENCE_ROOT/teardown-after.json" ||
    fail "teardown changed a protected authority byte or identity"
  record_operation_result teardown
}

run_real_workflow() {
  verify_supervisor_descriptor_set
  verify_fixture_mounts
  verify_private_root_readonly
  verify_private_source_copy
  verify_stub_authority
  verify_network_and_pid_namespace
  : >"$EVENT_LOG"
  : >"$PHASE_LOG"
  : >"$OPERATION_LOG"
  : >"$INFRA_AUDIT_MAP"
  [[ ! -e "$INFRA_AUDIT_SNAPSHOT" ]] ||
    fail "stale infra audit snapshot exists"
  record_phase supervisor-preconditions
  exercise_argv_collisions
  record_phase argv-collision-matrix
  exercise_bad_payloads
  record_phase bad-payload-cgi-503
  exercise_recovery_marker_routine_rejection
  record_phase recovery-marker-routine-rejection
  exercise_native_stop_failures
  record_phase native-stopped-writer-matrix
  exercise_native_matrix
  record_phase native-lifecycle-cgi-200
  exercise_docker_writer_removal
  record_phase docker-writer-stop-remove
  exercise_recovery_decision_enum
  record_phase recovery-decision-enum
  exercise_teardown_preservation
  record_phase teardown-preservation
  rm -f -- "$OPERATION_CONTEXT"
  snapshot_protected_paths \
    "$EVIDENCE_ROOT/authority-postflight.jsonl" pre-attest "$AUTHORITY"
  attest_with_evidence postflight-attest \
    "$EVIDENCE_ROOT/postflight-attest.invocation.json"
  cmp -s "$EVIDENCE_ROOT/postflight-attest.out" <(printf attest-valid) ||
    fail "final read-only postflight attest did not return attest-valid"
  [[ ! -s "$EVIDENCE_ROOT/postflight-attest.err" ]] ||
    fail "final read-only postflight attest wrote stderr"
  snapshot_protected_paths \
    "$EVIDENCE_ROOT/authority-postflight.jsonl" post-attest "$AUTHORITY"
  verify_fixture_mounts
  verify_private_root_readonly
  verify_private_source_copy
  verify_stub_authority
  verify_network_and_pid_namespace
  record_phase postflight-attestation
  printf 'root-entrypoint-workflow: EVIDENCE-COMPLETE\n'
}

# Bash may retain its script input on 255; the close-all supervisor contract
# requires that interpreter-private descriptor to be closed before validation.
exec 255<&- 2>/dev/null || :
run_real_workflow
