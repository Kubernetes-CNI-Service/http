#!/usr/bin/env python3
"""Create a bounded, redacted support bundle for the ZTP management stack.

The collector is deliberately read-only.  It never invokes load, monitor,
backup, DHCP release, ZTP, reset, apply/save, service start/stop, or a command
provided by the caller.  Optional switch access uses a fixed probe, BatchMode
SSH and inventory/report identity checks before any device evidence is saved.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Iterable, Optional

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - production load installs PyYAML
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
DAY0_ROOT = ROOT / "DAY0-Prepare"
HTTP_ROOT = ROOT
DEFAULT_OUTPUT_ROOT = Path("/var/tmp/ztp-diagnostics")
SCHEMA_VERSION = 1
MAX_COMMAND_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_ARCHIVES = 12
MAX_HOSTS = 32
COMMAND_TIMEOUT = 20
REMOTE_TIMEOUT = 45

SAFE_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:password|passwd|passphrase|hashed[_-]?password|secret|token|"
    r"credential|private[_-]?key|shared[_-]?key|preshared[_-]?key|psk|"
    r"auth(?:entication)?[_-]?(?:key|token|secret)|api[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
PASSWORD_HASH = re.compile(r"\$(?:1|2[abxy]?|5|6|y)\$[^\s\"']+")
PRIVATE_PEM = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"-----END [^-\r\n]*PRIVATE KEY-----",
    re.DOTALL,
)
AUTHORIZATION = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization)\s*:\s*)\S+.*$"
)
AUTHORIZATION_VALUE = re.compile(
    r"(?i)([\"']?(?:authorization|proxy-authorization)[\"']?\s*:\s*[\"']?)"
    r"(?:Basic|Bearer)\s+[^\s,;\]}\"']+"
)
SECRET_ASSIGNMENT = re.compile(
    r"(?im)^(?P<prefix>\s*(?:password|passwd|passphrase|hashed[-_ ]?password|"
    r"secret|token|credential|private[-_ ]?key|shared[-_ ]?key|"
    r"preshared[-_ ]?key|auth[-_ ]?key|api[-_ ]?key)\s*[:=]\s*).*$"
)
INLINE_SECRET_ASSIGNMENT = re.compile(
    r"(?i)([\"']?(?:password|passwd|passphrase|hashed[-_ ]?password|secret|"
    r"token|credential|private[-_ ]?key|shared[-_ ]?key|preshared[-_ ]?key|"
    r"auth[-_ ]?key|api[-_ ]?key)[\"']?\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\]}]+)"
)
SNMP_COMMUNITY_VALUE = re.compile(
    r"(?i)(\bsnmp(?:-server)?\s+community\s+)\S+"
)
URL_CREDENTIAL = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")
URL_QUERY = re.compile(r"(?i)(https?://[^\s?#]+)\?[^\s#]*?(?:#[^\s]*)?(?=\s|$)")
SSH_PUBLIC_LINE = re.compile(
    r"(?m)^\s*(?:ssh-(?:rsa|ed25519)|ecdsa-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$"
)
SSH_PUBLIC_VALUE = re.compile(
    r"(?i)\b(ssh-(?:rsa|ed25519)|ecdsa-[^\s]+)\s+"
    r"[A-Za-z0-9+/=]{20,}[^\r\n\"']*"
)
CONTROL_CHARS = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]"
)


class DiagnosticError(RuntimeError):
    pass


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_component(value: str) -> str:
    value = str(value or "")
    if SAFE_HOSTNAME.fullmatch(value):
        return value
    return "item-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def safe_relative(value: str) -> PurePosixPath:
    lexical_parts = str(value).split("/")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in lexical_parts)
    ):
        raise DiagnosticError(f"unsafe bundle member path: {value!r}")
    return relative


def sanitize_text(text: str) -> str:
    """Best-effort fallback for logs and command output (never raw configs)."""
    text = CONTROL_CHARS.sub("", text)
    text = PRIVATE_PEM.sub("<redacted:private-key>", text)
    text = AUTHORIZATION.sub(r"\1<redacted:authorization>", text)
    text = AUTHORIZATION_VALUE.sub(r"\1<redacted:authorization>", text)
    text = SECRET_ASSIGNMENT.sub(
        lambda match: match.group("prefix") + "<redacted:secret>", text
    )
    text = INLINE_SECRET_ASSIGNMENT.sub(r"\1<redacted:secret>", text)
    text = SNMP_COMMUNITY_VALUE.sub(r"\1<redacted:community>", text)
    text = URL_CREDENTIAL.sub(r"\1<redacted>@", text)
    text = URL_QUERY.sub(r"\1?<redacted:query>", text)
    text = PASSWORD_HASH.sub("<redacted:password-hash>", text)
    text = SSH_PUBLIC_LINE.sub("<redacted:ssh-public-key>", text)
    text = SSH_PUBLIC_VALUE.sub(r"\1 <redacted:ssh-public-key>", text)
    return text


def redact_scalar(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return sanitize_text(value)


def redact_object(value: Any, *, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        result = {}
        snmp_context = "snmp" in parent_key.casefold()
        for key, child in value.items():
            name = str(key)
            lowered = name.casefold().replace(" ", "-")
            sensitive = bool(SENSITIVE_KEY.search(lowered))
            # SNMP communities are credentials; BGP route communities are not.
            if lowered in {"community", "communities"} and snmp_context:
                sensitive = True
            if "snmp" in lowered and "communit" in lowered:
                sensitive = True
            if sensitive:
                result[key] = "<redacted:secret>"
            else:
                result[key] = redact_object(
                    child, parent_key=f"{parent_key}.{name}" if parent_key else name
                )
        return result
    if isinstance(value, list):
        return [redact_object(item, parent_key=parent_key) for item in value]
    return redact_scalar(value)


def structured_redaction(
    data: bytes, suffix: str, *, require_container: bool = False,
) -> tuple[Optional[bytes], str]:
    """Return redacted bytes or fail closed for an unparseable config."""
    text = data.decode("utf-8", errors="strict")
    suffix = suffix.casefold()
    try:
        if suffix == ".json":
            parsed = json.loads(text)
            rendered = json.dumps(
                redact_object(parsed), ensure_ascii=False, indent=2, sort_keys=True
            ) + "\n"
        elif suffix in {".yaml", ".yml"}:
            if yaml is None:
                raise ValueError("PyYAML is unavailable")
            parsed = yaml.safe_load(text)
            if require_container and not isinstance(parsed, (dict, list)):
                raise ValueError("expected a YAML mapping or list")
            rendered = yaml.safe_dump(
                redact_object(parsed), allow_unicode=True, sort_keys=False
            )
        elif suffix == ".csv":
            import io
            rows = list(csv.reader(io.StringIO(text)))
            if not rows:
                raise ValueError("empty CSV")
            header = rows[0]
            sensitive_columns = {
                index for index, name in enumerate(header)
                if SENSITIVE_KEY.search(str(name).casefold().replace(" ", "-"))
            }
            output = []
            for row_index, row in enumerate(rows):
                if row_index:
                    row = [
                        "<redacted:secret>"
                        if index in sensitive_columns
                        else sanitize_text(cell)
                        for index, cell in enumerate(row)
                    ]
                output.append(row)
            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerows(output)
            rendered = buffer.getvalue()
        else:
            raise ValueError(f"unsupported structured suffix: {suffix}")
    except (UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return None, str(exc)
    except Exception as exc:  # PyYAML parser exceptions vary by version
        return None, str(exc)
    # Every scalar has already been sanitized before serialization. Running
    # text regexes after json/yaml/csv rendering could consume structural
    # quotes or delimiters and produce an invalid redacted document.
    return rendered.encode("utf-8"), ""


def _preexec_no_core() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _kill_bounded_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return
    except ProcessLookupError:
        return
    except PermissionError:
        pass
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        pass


def run_bounded_command(
    argv: Iterable[str], *, timeout: int = COMMAND_TIMEOUT,
    max_bytes: int = MAX_COMMAND_BYTES,
) -> dict[str, Any]:
    """Run one fixed argv without a shell and cap time/output in memory."""
    arguments = [str(item) for item in argv]
    if not arguments:
        raise DiagnosticError("empty command")
    executable = shutil.which(arguments[0])
    if not executable:
        return {
            "argv": arguments, "returncode": 127, "duration_ms": 0,
            "timed_out": False, "truncated": False,
            "output": f"command not found: {arguments[0]}\n",
        }
    arguments[0] = executable
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
        "HOME": "/root" if os.geteuid() == 0 else str(Path.home()),
    }
    started = time.monotonic()
    process = subprocess.Popen(
        arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, shell=False, env=env,
        start_new_session=True, preexec_fn=_preexec_no_core,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    chunks: list[bytes] = []
    total = 0
    timed_out = False
    truncated = False
    deadline = started + max(1, timeout)
    while True:
        if time.monotonic() >= deadline and process.poll() is None:
            timed_out = True
            _kill_bounded_process(process)
        events = selector.select(0.1)
        for key, _mask in events:
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            remaining = max_bytes - total
            if remaining > 0:
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
            if len(chunk) > remaining or total >= max_bytes:
                truncated = True
                if process.poll() is None:
                    _kill_bounded_process(process)
        if process.poll() is not None and not selector.get_map():
            break
        if process.poll() is not None and not events:
            # Drain one final read after process exit.
            try:
                chunk = os.read(process.stdout.fileno(), 65536)
            except OSError:
                chunk = b""
            if chunk:
                remaining = max_bytes - total
                chunks.append(chunk[:max(remaining, 0)])
                total += min(len(chunk), max(remaining, 0))
                truncated = truncated or len(chunk) > remaining
            else:
                try:
                    selector.unregister(process.stdout)
                except (KeyError, ValueError):
                    pass
    selector.close()
    returncode = process.wait()
    process.stdout.close()
    return {
        "argv": arguments, "returncode": returncode,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "timed_out": timed_out, "truncated": truncated,
        "output": b"".join(chunks).decode("utf-8", errors="replace"),
    }


class BundleBuilder:
    def __init__(self, staging: Path, artifact_id: str):
        self.staging = staging
        self.artifact_id = artifact_id
        self.entries: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.total_bytes = 0
        self.staging.mkdir(parents=True, exist_ok=True)
        os.chmod(self.staging, 0o700)

    def warn(self, message: str) -> None:
        self.warnings.append(str(message))

    def write(self, relative: str, data: bytes, *, source: str,
              redacted: bool = True) -> None:
        member = safe_relative(relative)
        if len(data) > MAX_MEMBER_BYTES:
            self.warn(f"omitted oversized member {relative}: {len(data)} bytes")
            return
        if len(self.entries) >= MAX_MEMBERS:
            raise DiagnosticError("bundle member limit exceeded")
        if self.total_bytes + len(data) > MAX_TOTAL_BYTES:
            raise DiagnosticError("bundle uncompressed size limit exceeded")
        destination = self.staging.joinpath(*member.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(destination.parent, 0o700)
        descriptor = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.total_bytes += len(data)
        self.entries.append({
            "path": member.as_posix(), "source": source,
            "size": len(data), "sha256": sha256_bytes(data),
            "redacted": bool(redacted), "status": "collected",
        })

    def write_json(self, relative: str, value: Any, *, source: str) -> None:
        data = (
            json.dumps(redact_object(value), ensure_ascii=False, indent=2,
                       sort_keys=True) + "\n"
        ).encode("utf-8")
        self.write(relative, data, source=source, redacted=True)

    def omission(self, relative: str, *, source: str, reason: str,
                 size: int = 0, digest: str = "") -> None:
        self.write_json(relative + ".omitted.json", {
            "status": "omitted", "reason": reason,
            "source": source, "source_size": size,
            "source_sha256": digest,
        }, source=source)
        self.warn(f"{source}: {reason}")

    def capture_command(self, command_id: str, argv: Iterable[str],
                        *, timeout: int = COMMAND_TIMEOUT) -> dict[str, Any]:
        result = run_bounded_command(argv, timeout=timeout)
        metadata = {key: value for key, value in result.items() if key != "output"}
        metadata["command_id"] = command_id
        self.commands.append(metadata)
        header = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        body = header + "\n\n" + sanitize_text(result["output"])
        self.write(
            f"server/commands/{safe_component(command_id)}.txt",
            body.encode("utf-8"), source=f"command:{command_id}", redacted=True,
        )
        if result["returncode"] != 0 or result["timed_out"]:
            self.warn(
                f"command {command_id} rc={result['returncode']}"
                + (" timeout" if result["timed_out"] else "")
            )
        return result

    def finalize(self, metadata: dict[str, Any]) -> None:
        summary = [
            "# ZTP diagnostic support bundle", "",
            "Classification: INTERNAL / TOPOLOGY", "",
            "This bundle is read-only and redacted. It still contains device ",
            "hostnames, IP/MAC addresses, topology, versions and operational logs.",
            "Review it before sharing outside the support boundary.", "",
            f"Artifact: {self.artifact_id}",
            f"Project: {metadata.get('project', '')}",
            f"Scope: {metadata.get('scope', '')}",
            f"Partial: {'yes' if self.warnings else 'no'}", "",
            "Raw private keys, authorized_keys, known_hosts, environment, shell ",
            "history and unredacted manual/preflight evidence are never collected.",
        ]
        if self.warnings:
            summary.extend(["", "## Warnings", ""])
            summary.extend(f"- {sanitize_text(item)}" for item in self.warnings)
        self.write(
            "README.txt", ("\n".join(summary) + "\n").encode("utf-8"),
            source="collector", redacted=True,
        )
        manifest = {
            "schema": SCHEMA_VERSION, "artifact_id": self.artifact_id,
            **metadata, "partial": bool(self.warnings),
            "warnings": self.warnings, "commands": self.commands,
            "entries": list(self.entries),
            "limits": {
                "member_bytes": MAX_MEMBER_BYTES,
                "total_bytes": MAX_TOTAL_BYTES,
                "members": MAX_MEMBERS,
            },
        }
        self.write_json("manifest.json", manifest, source="collector")


def read_regular_file(
    path: Path, *, allowed_roots: Iterable[Path], max_bytes: int,
    tail: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    resolved = path.resolve(strict=True)
    roots = []
    for root in allowed_roots:
        try:
            roots.append(root.resolve(strict=True))
        except OSError:
            continue
    if not roots:
        raise DiagnosticError("no allowlisted source root is available")
    if not any(is_within(resolved, root) for root in roots):
        raise DiagnosticError(f"source escapes allowlisted roots: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(resolved, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise DiagnosticError(f"source is not a regular file: {path}")
        if info.st_nlink > 1:
            raise DiagnosticError(f"source is hard-linked: {path}")
        size = info.st_size
        truncated = size > max_bytes
        if truncated and not tail:
            raise DiagnosticError(f"source exceeds {max_bytes} bytes: {path}")
        if tail and truncated:
            os.lseek(descriptor, -max_bytes, os.SEEK_END)
        chunks = []
        remaining = min(size, max_bytes)
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            info.st_dev, info.st_ino, info.st_size
        ):
            raise DiagnosticError(f"source changed while reading: {path}")
        return data, {
            "resolved": str(resolved), "size": size,
            "mtime": dt.datetime.fromtimestamp(
                info.st_mtime, tz=dt.timezone.utc
            ).isoformat(timespec="seconds"),
            "truncated": truncated,
        }
    finally:
        os.close(descriptor)


def capture_file(
    builder: BundleBuilder, source: Path, relative: str, *,
    allowed_roots: Iterable[Path], structured: bool = False,
    tail: bool = False, max_bytes: int = MAX_MEMBER_BYTES,
) -> None:
    try:
        data, metadata = read_regular_file(
            source, allowed_roots=allowed_roots,
            max_bytes=max_bytes, tail=tail,
        )
    except (OSError, DiagnosticError) as exc:
        builder.warn(f"{source}: {exc}")
        return
    if structured:
        redacted, error = structured_redaction(data, source.suffix)
        if redacted is None:
            builder.omission(
                relative, source=str(source),
                reason="omitted_unparseable_sensitive_config: " + error,
                size=metadata["size"], digest=sha256_bytes(data),
            )
            return
        data = redacted
    else:
        data = sanitize_text(data.decode("utf-8", errors="replace")).encode("utf-8")
    if metadata["truncated"]:
        data = (
            f"[collector] source tail truncated from {metadata['size']} bytes\n"
        ).encode("utf-8") + data
    builder.write(relative, data, source=str(source), redacted=True)


def path_state(path: Path) -> dict[str, Any]:
    state_value: dict[str, Any] = {"path": str(path)}
    try:
        info = path.lstat()
    except OSError as exc:
        state_value.update({"exists": False, "error": str(exc)})
        return state_value
    state_value.update({
        "exists": True, "mode": oct(stat.S_IMODE(info.st_mode)),
        "uid": info.st_uid, "gid": info.st_gid,
        "size": info.st_size, "is_symlink": stat.S_ISLNK(info.st_mode),
    })
    if stat.S_ISLNK(info.st_mode):
        try:
            state_value["link_target"] = os.readlink(path)
            state_value["resolved"] = str(path.resolve(strict=True))
        except OSError as exc:
            state_value["resolve_error"] = str(exc)
    elif stat.S_ISREG(info.st_mode):
        try:
            state_value["sha256"] = sha256_file(path)
        except OSError as exc:
            state_value["hash_error"] = str(exc)
    return state_value


def resolve_project(value: str) -> Path:
    requested = Path(value)
    if not requested.is_absolute():
        if requested.parts and requested.parts[0] == "DAY0-Prepare":
            requested = ROOT / requested
        else:
            requested = DAY0_ROOT / requested
    try:
        project = requested.resolve(strict=True)
        day0 = DAY0_ROOT.resolve(strict=True)
    except OSError as exc:
        raise DiagnosticError(f"project does not exist: {requested}: {exc}") from exc
    if project.parent != day0 or not SAFE_PROJECT.fullmatch(project.name):
        raise DiagnosticError("project must be one direct safe child of DAY0-Prepare")
    if project.name == "template" or not project.is_dir():
        raise DiagnosticError("template/non-directory is not a diagnostic project")
    return project


def prepare_output_root(value: Optional[str]) -> Path:
    requested = Path(value) if value else DEFAULT_OUTPUT_ROOT
    if not requested.is_absolute():
        requested = Path.cwd() / requested
    # Resolve existing ancestors and reject DocumentRoot even before mkdir.
    resolved = requested.resolve(strict=False)
    http_root = HTTP_ROOT.resolve(strict=True)
    if is_within(resolved, http_root):
        raise DiagnosticError("diagnostic output must not be inside Apache DocumentRoot")
    if requested.exists() and requested.is_symlink():
        raise DiagnosticError("diagnostic output directory must not be a symlink")
    requested.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = requested.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise DiagnosticError("diagnostic output directory has unsafe owner/type")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise DiagnosticError("diagnostic output directory must be mode 0700")
    return resolved


def latest_snapshot(project: Path) -> Optional[Path]:
    latest = project / "99-output-ztp/latest"
    try:
        resolved = latest.resolve(strict=True)
        root = (project / "99-output-ztp").resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.parent == root and resolved.is_dir() else None


def load_latest_report(project: Path) -> tuple[Optional[Path], dict[str, Any]]:
    snapshot = latest_snapshot(project)
    if snapshot is None:
        return None, {}
    try:
        report = json.loads((snapshot / "report.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return snapshot, {}
    return snapshot, report if isinstance(report, dict) else {}


def runtime_active_project() -> Optional[Path]:
    """Return the project currently wired into the DHCP/ZTP runtime."""
    runtime_inventory = ROOT / "ztp/config/isc-dhcp-server/02-devices_config.csv"
    try:
        target = runtime_inventory.resolve(strict=True)
        day0 = DAY0_ROOT.resolve(strict=True)
    except OSError:
        return None
    project = target.parent
    if (
        target.name != "02-devices_config.csv"
        or project.parent != day0
        or not SAFE_PROJECT.fullmatch(project.name)
        or project.name == "template"
    ):
        return None
    return project


def device_in_scope(device: dict[str, Any], scope: str) -> bool:
    is_air = (
        str(device.get("type") or "").casefold() == "air"
        or str(device.get("environment") or "").casefold() == "air"
    )
    return scope == "all" or (scope == "air" and is_air) or (
        scope == "prod" and not is_air
    )


def select_devices(
    report: dict[str, Any], hostnames: list[str], scope: str,
) -> list[dict[str, Any]]:
    devices = [item for item in report.get("devices", []) if isinstance(item, dict)]
    selected = []
    for hostname in hostnames:
        if not SAFE_HOSTNAME.fullmatch(hostname):
            raise DiagnosticError(f"unsafe hostname: {hostname!r}")
        matches = [
            item for item in devices
            if str(item.get("hostname") or "") == hostname
            and device_in_scope(item, scope)
        ]
        if len(matches) != 1:
            raise DiagnosticError(
                f"hostname {hostname!r} is not unique in current {scope} report"
            )
        selected.append(matches[0])
    return selected


def collect_project_inputs(builder: BundleBuilder, project: Path) -> None:
    for name in ("01-global.yaml", "02-devices_config.csv", "02-dhcp-subnet_config.csv"):
        source = project / name
        capture_file(
            builder, source, f"project/inputs/{name}",
            allowed_roots=[project], structured=True,
        )
    for source in sorted((project / "99-output-p2p").glob("*-air.json"))[-2:]:
        capture_file(
            builder, source, f"project/inputs/p2p/{safe_component(source.name)}",
            allowed_roots=[project], structured=True,
        )
    capture_file(
        builder, project / "99-output-ztp/current-release.json",
        "project/release/current-release.json", allowed_roots=[project],
        structured=True,
    )


def collect_runtime_files(builder: BundleBuilder, project: Path) -> None:
    roots = [ROOT, project]
    runtime_files = {
        "ztp/config/isc-dhcp-server/dhcpd.conf": "server/dhcp/generated/dhcpd.conf",
        "ztp/config/isc-dhcp-server/dhcpd_eth.hosts": "server/dhcp/generated/dhcpd_eth.hosts",
        "ztp/config/isc-dhcp-server/dhcpd_ib.hosts": "server/dhcp/generated/dhcpd_ib.hosts",
        "ztp/config/isc-dhcp-server/dhcpd_nvl.hosts": "server/dhcp/generated/dhcpd_nvl.hosts",
        "ztp/config/isc-dhcp-server/dhcp-release-manifest.json": "server/dhcp/generated/dhcp-release-manifest.json",
        "ztp/config/isc-dhcp-server/p2p-air.json": "server/dhcp/generated/p2p-air.json",
        "ztp/ztp-bootstrap_oob.sh": "server/apache/runtime/ztp-bootstrap_oob.sh",
        "ztp/ztp-bootstrap_oobofoob.sh": "server/apache/runtime/ztp-bootstrap_oobofoob.sh",
        "ztp/ztp.json": "server/apache/runtime/ztp.json",
        "ztp/.setup_manifest.json": "server/apache/runtime/setup-manifest.json",
        ".ztp-prefix-publication.json": "server/apache/runtime/prefix-publication.json",
    }
    for source_text, relative in runtime_files.items():
        source = ROOT / source_text
        capture_file(
            builder, source, relative, allowed_roots=roots,
            structured=source.suffix in {".json", ".yaml", ".yml", ".csv"},
        )

    system_roots = [Path("/etc/dhcp"), Path("/etc/default")]
    for name in ("dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"):
        capture_file(
            builder, Path("/etc/dhcp") / name, f"server/dhcp/live/{name}",
            allowed_roots=system_roots,
        )
    capture_file(
        builder, Path("/etc/default/isc-dhcp-server"),
        "server/dhcp/live/isc-dhcp-server.default",
        allowed_roots=system_roots,
    )
    capture_file(
        builder, Path("/var/lib/dhcp/dhcpd.leases"),
        "server/dhcp/live/dhcpd.leases", allowed_roots=[Path("/var/lib/dhcp")],
        tail=True, max_bytes=8 * 1024 * 1024,
    )
    for source in sorted(Path("/etc/apache2/sites-enabled").glob("*.conf")):
        capture_file(
            builder, source, f"server/apache/sites/{safe_component(source.name)}",
            allowed_roots=[Path("/etc/apache2")],
        )
    for name in ("access.log", "error.log"):
        capture_file(
            builder, Path("/var/log/apache2") / name,
            f"server/apache/logs/{name}", allowed_roots=[Path("/var/log/apache2")],
            tail=True, max_bytes=8 * 1024 * 1024,
        )

    links = [
        ROOT / "ztp/status", ROOT / "ztp/config/isc-dhcp-server/01-global.yaml",
        ROOT / "ztp/config/isc-dhcp-server/02-devices_config.csv",
        ROOT / "ztp/config/isc-dhcp-server/02-subnet_config.csv",
        ROOT / "ztp/config/cumulus/latest_yaml",
        ROOT / "ztp/config/nvos/latest_yaml",
        project / "99-output-eth/latest", project / "99-output-ib_nvl/latest",
        project / "99-output-ztp/latest",
    ]
    builder.write_json(
        "project/release/path-state.json", [path_state(path) for path in links],
        source="collector:path-state",
    )
    release_links = (
        (
            "server/runtime-release/cumulus",
            ROOT / "ztp/config/cumulus/latest_yaml",
        ),
        (
            "server/runtime-release/nvos",
            ROOT / "ztp/config/nvos/latest_yaml",
        ),
        ("project/release/cumulus", project / "99-output-eth/latest"),
        ("project/release/nvos", project / "99-output-ib_nvl/latest"),
    )
    for relative_base, path in release_links:
        try:
            release = path.resolve(strict=True)
        except OSError as exc:
            builder.warn(f"{path}: {exc}")
            continue
        if not is_within(release, ROOT.resolve(strict=True)):
            builder.warn(f"{path}: release escapes DocumentRoot")
            continue
        for name in ("release-manifest.json", ".published-complete"):
            capture_file(
                builder, release / name,
                f"{relative_base}/{name}",
                allowed_roots=[ROOT, project], structured=name.endswith(".json"),
            )


def collect_selected_published_configs(
    builder: BundleBuilder, selected: list[dict[str, Any]], project: Path,
) -> None:
    for device in selected:
        hostname = str(device.get("hostname") or "")
        device_type = str(device.get("type") or "").casefold()
        platform = "nvos" if device_type in {"ib", "nvl"} else "cumulus"
        latest = project / (
            "99-output-ib_nvl/latest" if platform == "nvos"
            else "99-output-eth/latest"
        )
        try:
            release = latest.resolve(strict=True)
        except OSError as exc:
            builder.warn(f"{hostname}: {platform} latest unavailable: {exc}")
            continue
        if not (is_within(release, ROOT.resolve(strict=True)) and release.is_dir()):
            builder.warn(f"{hostname}: unsafe {platform} release path")
            continue
        base = f"devices/{safe_component(hostname)}/published"
        capture_file(
            builder, release / f"{hostname}.yaml", base + "/latest.yaml",
            allowed_roots=[ROOT, project], structured=True,
        )
        identities = device.get("identity_macs")
        mac_values = []
        if isinstance(identities, dict):
            mac_values.extend(normalize_mac(str(value)) for value in identities.values())
        mac_values.append(normalize_mac(str(device.get("mac") or device.get("mac_plain") or "")))
        states = [path_state(release / f"{mac}.yaml") for mac in dict.fromkeys(mac_values) if mac]
        builder.write_json(base + "/mac-link-state.json", states, source="collector:path-state")


def collect_selected_operation_metadata(
    builder: BundleBuilder, project: Path, hostnames: list[str],
) -> None:
    if not hostnames:
        return
    output_root = project / "99-output-ztp"
    for kind in ("manual-trigger", "manual-reset"):
        base = output_root / kind
        if not base.is_dir() or base.is_symlink():
            continue
        candidates = []
        for result_path in base.glob("*/*/result.json"):
            if result_path.is_symlink() or not result_path.is_file():
                continue
            try:
                value = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or str(value.get("hostname") or "") not in hostnames:
                continue
            candidates.append((result_path.stat().st_mtime, result_path.parent, value))
        for index, (_mtime, directory, result) in enumerate(
            sorted(candidates, reverse=True)[: max(3, len(hostnames))]
        ):
            hostname = str(result.get("hostname") or "")
            target = (
                f"devices/{safe_component(hostname)}/operations/"
                f"{safe_component(kind)}-{index}"
            )
            for name in ("result.json", "summary.json", "preflight.json"):
                capture_file(
                    builder, directory / name, f"{target}/{name}",
                    allowed_roots=[project], structured=True,
                )


def collect_monitor_state(
    builder: BundleBuilder, project: Path, snapshot: Optional[Path],
    selected: list[dict[str, Any]],
) -> None:
    if snapshot is not None:
        for name in ("report.json", "report.md", "devices.csv"):
            capture_file(
                builder, snapshot / name, f"monitor/ztp/latest/{name}",
                allowed_roots=[project], structured=Path(name).suffix in {".json", ".csv"},
            )
        for device in selected:
            hostname = str(device.get("hostname") or "")
            builder.write_json(
                f"monitor/ztp/devices/{safe_component(hostname)}/report-row.json",
                device, source="latest-report",
            )
            raw = snapshot / "raw/switches" / safe_component(hostname)
            if raw.is_dir() and not raw.is_symlink():
                for source in sorted(raw.iterdir()):
                    if source.is_file() and not source.is_symlink():
                        destination = (
                            f"monitor/ztp/devices/{safe_component(hostname)}/raw/"
                            f"{safe_component(source.name)}"
                        )
                        if source.name == "failed_yaml.log":
                            try:
                                data, meta = read_regular_file(
                                    source, allowed_roots=[project],
                                    max_bytes=4 * 1024 * 1024,
                                )
                            except (OSError, DiagnosticError) as exc:
                                builder.warn(f"{source}: {exc}")
                                continue
                            text = data.decode("utf-8", errors="replace")
                            body = "\n".join(
                                line for line in text.splitlines()
                                if not line.startswith("__FILE__=")
                            )
                            redacted, error = structured_redaction(
                                body.encode("utf-8"), ".yaml", require_container=True,
                            )
                            if redacted is None:
                                builder.omission(
                                    destination, source=str(source),
                                    reason="unparseable failed YAML: " + error,
                                    size=meta["size"], digest=sha256_bytes(data),
                                )
                            else:
                                builder.write(
                                    destination, redacted, source=str(source), redacted=True,
                                )
                        else:
                            capture_file(
                                builder, source, destination,
                                allowed_roots=[project], tail=True,
                                max_bytes=4 * 1024 * 1024,
                            )

    status_roots = (
        ("ztp-status", ROOT / "ztp/status"),
        ("monitor-status", ROOT / "monitor/status"),
    )
    builder.write_json(
        "monitor/runtime-workers/status-roots.json",
        [path_state(path) for _label, path in status_roots],
        source="collector:path-state",
    )
    for status_label, status_root in status_roots:
        try:
            resolved = status_root.resolve(strict=True)
        except OSError:
            continue
        if not (is_within(resolved, ROOT.resolve(strict=True)) and resolved.is_dir()):
            builder.warn(f"unsafe status root skipped: {status_root}")
            continue
        for source in sorted(resolved.iterdir()):
            name = source.name
            if not source.is_file() or source.is_symlink():
                continue
            if not (
                name.endswith((".json", ".pid", ".control"))
                or name in {
                    "ztp-monitor-background.log", "manual-ztp.log",
                    "switch-collection.log", "generate-monitor.log",
                }
            ):
                continue
            relative = (
                f"monitor/runtime-workers/{status_label}/"
                f"{safe_component(name)}"
            )
            if name == "manual-ztp.log":
                # Keep only diagnostic lines; the CLI can print a full config diff.
                try:
                    data, _meta = read_regular_file(
                        source, allowed_roots=[ROOT], max_bytes=2 * 1024 * 1024,
                        tail=True,
                    )
                except (OSError, DiagnosticError) as exc:
                    builder.warn(f"{source}: {exc}")
                    continue
                lines = []
                for line in data.decode("utf-8", errors="replace").splitlines():
                    if re.search(
                        r"(?:\bERROR\b|\bWARN\b|\bOK\b|failed|success|timeout|"
                        r"operation|trigger|hostname|SSH|DHCP|ZTP)", line, re.I,
                    ):
                        lines.append(line)
                builder.write(
                    relative, (sanitize_text("\n".join(lines)) + "\n").encode("utf-8"),
                    source=str(source), redacted=True,
                )
            else:
                capture_file(
                    builder, source, relative, allowed_roots=[ROOT],
                    structured=source.suffix == ".json", tail=True,
                    max_bytes=4 * 1024 * 1024,
                )
    for source in sorted((project / "99-output-monitor").glob("*/cronjob.log")):
        capture_file(
            builder, source,
            f"monitor/collections/{safe_component(source.parent.name)}-cronjob.log",
            allowed_roots=[project], tail=True, max_bytes=4 * 1024 * 1024,
        )


def _safe_tar_member(member: tarfile.TarInfo) -> bool:
    path = PurePosixPath(member.name)
    return (
        not path.is_absolute() and path.parts
        and all(part not in {"", ".", ".."} for part in path.parts)
        and member.isfile()
        and member.size <= MAX_MEMBER_BYTES
    )


def sanitize_switch_info(text: str) -> str:
    """Remove raw configuration sections while preserving operational state."""
    pieces = re.split(r"(?m)^(?=# Execute Command:)", text)
    kept = []
    for piece in pieces:
        header = piece.splitlines()[0] if piece.splitlines() else ""
        command = header.partition(":")[2].strip().casefold()
        if command and (
            "nv config show" in command
            or "/etc/nvue.d/" in command
            or "/etc/sonic/nvue.d/" in command
        ):
            kept.append(header + "\n[collector] raw configuration section omitted\n")
        else:
            kept.append(piece)
    return sanitize_text("".join(kept))


def collect_switch_archives(
    builder: BundleBuilder, project: Path, hostnames: list[str],
) -> None:
    root = project / "99-output-monitor"
    archives = sorted(
        (path for path in root.rglob("*.tar.gz") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:MAX_ARCHIVES] if root.is_dir() else []
    listing = []
    for index, archive_path in enumerate(archives):
        try:
            resolved = archive_path.resolve(strict=True)
            if not is_within(resolved, project.resolve(strict=True)):
                raise DiagnosticError("archive escapes project")
            archive_info = {
                "path": str(archive_path.relative_to(project)),
                "size": archive_path.stat().st_size,
                "mtime": dt.datetime.fromtimestamp(
                    archive_path.stat().st_mtime, tz=dt.timezone.utc,
                ).isoformat(timespec="seconds"),
                "sha256": sha256_file(archive_path), "members": [],
            }
            with tarfile.open(archive_path, "r:gz") as archive:
                for member in archive.getmembers():
                    archive_info["members"].append({
                        "name": member.name, "size": member.size,
                        "type": "file" if member.isfile() else "other",
                    })
                    basename = PurePosixPath(member.name).name
                    wanted = basename == "collection.json" or any(
                        basename == f"{hostname}.info" for hostname in hostnames
                    )
                    if not wanted or not _safe_tar_member(member):
                        continue
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    data = extracted.read(MAX_MEMBER_BYTES + 1)
                    if len(data) > MAX_MEMBER_BYTES:
                        builder.warn(f"oversized archive member: {archive_path}:{member.name}")
                        continue
                    if basename == "collection.json":
                        redacted, error = structured_redaction(data, ".json")
                        if redacted is None:
                            builder.omission(
                                f"monitor/collections/archive-{index}/collection.json",
                                source=f"{archive_path}:{member.name}",
                                reason="unparseable collection.json: " + error,
                                size=len(data), digest=sha256_bytes(data),
                            )
                            continue
                        data = redacted
                    else:
                        data = sanitize_switch_info(
                            data.decode("utf-8", errors="replace")
                        ).encode("utf-8")
                    builder.write(
                        f"monitor/collections/archive-{index}/{safe_component(basename)}",
                        data, source=f"{archive_path}:{member.name}", redacted=True,
                    )
            listing.append(archive_info)
        except (OSError, tarfile.TarError, DiagnosticError) as exc:
            builder.warn(f"cannot inspect {archive_path}: {exc}")
    builder.write_json(
        "monitor/collections/latest-archives.json", listing,
        source="collector:archive-index",
    )


REMOTE_PROBE = r'''
set +e
printf '__IDENTITY_BEGIN__\n'
hostname -s 2>/dev/null || true
cat /sys/class/net/eth0/address 2>/dev/null || true
cat /sys/class/net/eth1/address 2>/dev/null || true
printf '__IDENTITY_END__\n'
printf '__STATE_BEGIN__\n'
date -Is 2>/dev/null || date
date +%s 2>/dev/null || true
cat /proc/sys/kernel/random/boot_id 2>/dev/null || true
awk '/^btime / {print $2; exit}' /proc/stat 2>/dev/null || true
uptime
uname -a
timedatectl 2>/dev/null || true
nv show platform 2>&1 || true
nv show system version 2>&1 || true
nv show system health 2>&1 || true
ip -br address 2>&1 || true
ip -details link show 2>&1 || true
ip -4 route show table all 2>&1 || true
ip -6 route show table all 2>&1 || true
ip rule show 2>&1 || true
ip vrf show 2>&1 || true
ip neigh show 2>&1 || true
printf '%s\n' '-- /run/ztp.dhcp --'
cat /run/ztp.dhcp 2>/dev/null || cat /var/run/ztp.dhcp 2>/dev/null || true
printf '%s\n' '-- ztp status --'
sudo -n ztp -s 2>&1 || ztp -s 2>&1 || true
printf '%s\n' '-- helpers --'
stat -c '%U:%G %a %s %n' /usr/local/sbin/http-manual-ztp-* 2>/dev/null || true
printf '%s\n' '-- authorized_keys fingerprints --'
ssh-keygen -lf "$HOME/.ssh/authorized_keys" 2>/dev/null || true
printf '%s\n' '-- ifreload --'
sudo -n journalctl -u ifreload-nvue.service --no-pager -n 200 2>/dev/null || true
printf '%s\n' '-- EVPN/MLAG/BGP --'
clagctl 2>&1 || true
nv show evpn multihoming esi 2>&1 || true
nv show router bgp 2>&1 || true
printf '__STATE_END__\n'
printf '__ZTP_LOG_BEGIN__\n'
latest=""
log_dir=/var/lib/nvidia-ztp/logs
log_pointer="$log_dir/latest-log"
pointer_seen=false
pointer_error=""
if [ -e "$log_pointer" ] || [ -L "$log_pointer" ]; then
    pointer_seen=true
    pointer_meta=$(stat -c '%U:%a:%s' -- "$log_pointer" 2>/dev/null || true)
    pointer_size=${pointer_meta##*:}
    if [ -L "$log_pointer" ] || [ ! -f "$log_pointer" ] ||
       [ -z "$pointer_size" ] || [ "$pointer_size" -gt 256 ] 2>/dev/null ||
       [ "${pointer_meta%%:*}" != root ] ||
       [ "${pointer_meta#*:}" = "$pointer_meta" ] ||
       [ "${pointer_meta#*:}" != 644:"$pointer_size" ]; then
        pointer_error=invalid_pointer_metadata
    else
        log_name=$(cat -- "$log_pointer" 2>/dev/null || true)
        case "$log_name" in
            ztp-result.log_*)
                case "$log_name" in */*|*' '*|*'..'*) pointer_error=unsafe_pointer_name ;;
                esac
                ;;
            *) pointer_error=unsafe_pointer_name ;;
        esac
        if [ -z "$pointer_error" ] && [ "$(wc -l < "$log_pointer" 2>/dev/null)" -ne 1 ]; then
            pointer_error=invalid_pointer_lines
        fi
        candidate="$log_dir/$log_name"
        target_meta=$(stat -c '%U:%a' -- "$candidate" 2>/dev/null || true)
        if [ -z "$pointer_error" ] && [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
           [ "$target_meta" = root:644 ]; then
            latest="$candidate"
        elif [ -z "$pointer_error" ]; then
            pointer_error=invalid_pointer_target
        fi
    fi
fi
if [ -z "$latest" ] && [ "$pointer_seen" = false ]; then
    for candidate in $(ls -1t /var/lib/nvidia-ztp/logs/ztp-result.log_* 2>/dev/null); do
        if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then latest="$candidate"; break; fi
    done
fi
if [ -z "$latest" ] && [ "$pointer_seen" = false ]; then
    for candidate in $(ls -1t "$HOME"/ztp-result.log_* 2>/dev/null); do
        if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then latest="$candidate"; break; fi
    done
fi
if [ -n "$pointer_error" ]; then printf 'latest_log_pointer_error=%s\n' "$pointer_error"; fi
if [ -n "$latest" ]; then stat -c 'mtime_epoch=%Y size=%s file=%n' "$latest"; tail -n 1200 -- "$latest"; fi
printf '__ZTP_LOG_END__\n'
printf '__APPLIED_BEGIN__\n'
sudo -n -- /usr/local/sbin/http-manual-ztp-applied-config 2>&1 || true
printf '__APPLIED_END__\n'
printf '__NV_CONFIG_BEGIN__\n'
nv config show 2>&1 || true
printf '__NV_CONFIG_END__\n'
'''


def marker(text: str, name: str) -> str:
    match = re.search(
        rf"__{re.escape(name)}_BEGIN__\n(.*?)__{re.escape(name)}_END__",
        text, re.DOTALL,
    )
    return match.group(1).strip() if match else ""


def normalize_mac(value: str) -> str:
    parts = re.split(r"[:-]", str(value or "").strip())
    if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", part) for part in parts):
        return "".join(part.zfill(2) for part in parts).casefold()
    plain = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    return plain.casefold() if len(plain) == 12 else ""


def _device_identity(device: dict[str, Any], address: str) -> tuple[str, str]:
    candidate = device.get("candidate_identity")
    if isinstance(candidate, dict) and address in candidate:
        value = candidate[address]
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return str(value[0]), normalize_mac(str(value[1]))
    identities = device.get("identity_macs")
    if isinstance(identities, dict):
        eth0 = normalize_mac(str(identities.get("eth0") or ""))
        if eth0:
            return "eth0", eth0
    return "eth0", normalize_mac(str(device.get("mac") or device.get("mac_plain") or ""))


def _device_candidates(device: dict[str, Any]) -> list[str]:
    transit = {str(value) for value in device.get("ztp_transport_ips", [])}
    values = [device.get("ip")]
    probe = device.get("ip_probe")
    if isinstance(probe, dict):
        values.extend(probe.get("candidates") or [])
    values.extend(device.get("ssh_ips") or [])
    result = []
    for value in values:
        text = str(value or "").strip()
        try:
            normalized = str(ipaddress.ip_address(text))
        except ValueError:
            continue
        if normalized not in transit and normalized not in result:
            result.append(normalized)
    return result


def redact_authorized_key_fingerprints(text: str) -> str:
    lines = []
    for line in text.splitlines():
        match = re.match(r"^(\d+)\s+(SHA256:[A-Za-z0-9+/=]+).*(\([^()]+\))\s*$", line)
        if match:
            lines.append(f"{match.group(1)} {match.group(2)} {match.group(3)}")
    return "\n".join(lines)


def collect_applied_protocol(builder: BundleBuilder, hostname: str, text: str) -> None:
    base = f"devices/{safe_component(hostname)}/applied"
    if not text.startswith("ZTP_APPLIED_CONFIG_V1\n") or "\n---\n" not in text:
        builder.write(
            base + "/status.txt", sanitize_text(text).encode("utf-8"),
            source="remote:applied-helper", redacted=True,
        )
        return
    header, raw_yaml = text.split("\n---\n", 1)
    receipt = {}
    for line in header.splitlines()[1:]:
        if "=" in line:
            key, value = line.split("=", 1)
            receipt[key] = value
    builder.write_json(base + "/receipt.json", receipt, source="remote:applied-helper")
    redacted, error = structured_redaction(
        raw_yaml.encode("utf-8"), ".yaml", require_container=True,
    )
    if redacted is None:
        builder.omission(
            base + "/last-success.yaml", source="remote:applied-helper",
            reason="unparseable applied YAML: " + error,
            size=len(raw_yaml.encode("utf-8")),
            digest=sha256_bytes(raw_yaml.encode("utf-8")),
        )
    else:
        builder.write(
            base + "/last-success.yaml", redacted,
            source="remote:applied-helper", redacted=True,
        )


def collect_live_device(
    builder: BundleBuilder, device: dict[str, Any], *, identity: Optional[Path],
    known_hosts: Path,
) -> None:
    hostname = str(device.get("hostname") or "")
    if device.get("unbound_identity") or device.get("identity_pending"):
        builder.warn(f"{hostname}: unbound/identity-pending rows are server-evidence only")
        return
    candidates = _device_candidates(device)
    if not candidates:
        builder.warn(f"{hostname}: no canonical SSH candidate")
        return
    device_type = str(device.get("type") or "").casefold()
    user = "admin" if device_type in {"ib", "nvl"} else "cumulus"
    attempts = []
    for address in candidates:
        interface, expected_mac = _device_identity(device, address)
        if not expected_mac:
            builder.warn(f"{hostname}: no expected management MAC; live SSH refused")
            return
        argv = [
            "ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=0",
            "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        ]
        if identity is not None:
            argv += ["-i", str(identity)]
        argv += [f"{user}@{address}", "sh -c " + shlex.quote(REMOTE_PROBE)]
        result = run_bounded_command(argv, timeout=REMOTE_TIMEOUT)
        identity_text = marker(result["output"], "IDENTITY")
        identity_lines = identity_text.splitlines()
        remote_hostname = identity_lines[0].strip() if identity_lines else ""
        remote_macs = {
            "eth0": normalize_mac(identity_lines[1] if len(identity_lines) > 1 else ""),
            "eth1": normalize_mac(identity_lines[2] if len(identity_lines) > 2 else ""),
        }
        exact_host = remote_hostname.split(".", 1)[0].casefold() == hostname.split(".", 1)[0].casefold()
        exact_mac = remote_macs.get(interface) == expected_mac
        attempts.append({
            "address": address, "interface": interface,
            "returncode": result["returncode"], "timed_out": result["timed_out"],
            "remote_hostname": remote_hostname,
            "remote_macs": remote_macs,
            "hostname_match": exact_host, "mac_match": exact_mac,
        })
        if result["returncode"] != 0 or not exact_host or not exact_mac:
            continue
        base = f"devices/{safe_component(hostname)}"
        state_text = marker(result["output"], "STATE")
        fingerprints = redact_authorized_key_fingerprints(state_text)
        state_text = re.sub(
            r"(?ms)^-- authorized_keys fingerprints --.*?^-- ifreload --$",
            "-- authorized_keys fingerprints --\n" + fingerprints + "\n-- ifreload --",
            state_text,
        )
        builder.write(
            base + "/state.txt", sanitize_text(state_text).encode("utf-8"),
            source="remote:fixed-probe", redacted=True,
        )
        builder.write(
            base + "/ztp-result.log",
            sanitize_text(marker(result["output"], "ZTP_LOG")).encode("utf-8"),
            source="remote:fixed-probe", redacted=True,
        )
        collect_applied_protocol(builder, hostname, marker(result["output"], "APPLIED"))
        config_text = marker(result["output"], "NV_CONFIG")
        redacted, error = structured_redaction(
            config_text.encode("utf-8"), ".yaml", require_container=True,
        )
        if redacted is None:
            builder.omission(
                base + "/nv-config-show.yaml", source="remote:nv-config-show",
                reason="unparseable nv config show: " + error,
                size=len(config_text.encode("utf-8")),
                digest=sha256_bytes(config_text.encode("utf-8")),
            )
        else:
            builder.write(
                base + "/nv-config-show.yaml", redacted,
                source="remote:nv-config-show", redacted=True,
            )
        break
    builder.write_json(
        f"devices/{safe_component(hostname)}/connection-attempts.json",
        attempts, source="remote:identity-gate",
    )
    if not any(item["hostname_match"] and item["mac_match"] and item["returncode"] == 0 for item in attempts):
        builder.warn(f"{hostname}: no SSH candidate passed hostname+MAC identity gates")


def validate_ssh_inputs(identity: Optional[str], known_hosts: str) -> tuple[Optional[Path], Path]:
    identity_source = Path(identity) if identity else None
    known_hosts_source = Path(known_hosts)
    for label, source in (("identity", identity_source), ("known_hosts", known_hosts_source)):
        if source is None:
            continue
        if source.is_symlink():
            raise DiagnosticError(f"{label} must be a regular non-symlink file")
    identity_path = identity_source.resolve(strict=True) if identity_source else None
    known_hosts_path = known_hosts_source.resolve(strict=True)
    for label, path in (("identity", identity_path), ("known_hosts", known_hosts_path)):
        if path is not None and not path.is_file():
            raise DiagnosticError(f"{label} must be a regular non-symlink file")
    return identity_path, known_hosts_path


def collect_public_key_fingerprints(builder: BundleBuilder) -> None:
    for path in sorted((ROOT / "ztp/config/publickey").glob("*.pub")):
        if path.is_symlink() or not path.is_file():
            continue
        result = run_bounded_command(["ssh-keygen", "-lf", str(path)], timeout=5)
        cleaned = redact_authorized_key_fingerprints(result["output"])
        builder.write(
            f"server/keys/{safe_component(path.name)}.fingerprint.txt",
            (cleaned + "\n").encode("utf-8"),
            source="public-key-fingerprint", redacted=True,
        )


def collect_server_commands(
    builder: BundleBuilder, since_minutes: int, project: Path,
) -> None:
    since_epoch = int(time.time()) - since_minutes * 60
    commands = [
        ("date", ["date", "-Is"]),
        ("date_epoch", ["date", "+%s"]),
        ("uname", ["uname", "-a"]),
        ("uptime", ["uptime"]),
        ("timedatectl", ["timedatectl"]),
        ("os_release", ["cat", "/etc/os-release"]),
        ("ip_address", ["ip", "-details", "-json", "address", "show"]),
        ("ip_route_v4", ["ip", "-4", "route", "show", "table", "all"]),
        ("ip_route_v6", ["ip", "-6", "route", "show", "table", "all"]),
        ("ip_rule", ["ip", "rule", "show"]),
        ("ip_neigh", ["ip", "neigh", "show"]),
        ("listening_sockets", ["ss", "-lntup"]),
        ("filesystem", ["df", "-hT"]),
        ("worker_processes", [
            "pgrep", "-a", "-f",
            "12-ztp-monitor.py|manual-ztp-worker.py|switch-collection-worker.py",
        ]),
        ("apparmor", ["aa-status"]),
        ("python_version", ["python3", "--version"]),
        ("apache_version", ["apache2ctl", "-v"]),
        ("apache_vhosts", ["apache2ctl", "-S"]),
        ("apache_configtest", ["apache2ctl", "configtest"]),
        ("dhcp_configtest", ["dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"]),
        ("dhcp_runtime_inventory", [
            "python3", str(ROOT / "ztp/dhcp_runtime_inventory.py"),
            "--journal", "--journal-since", f"@{since_epoch}",
            "--leases", "/var/lib/dhcp/dhcpd.leases",
            "--inventory", str(project / "02-devices_config.csv"),
            "--include-known", "--stdout",
        ]),
        ("apache_active", ["systemctl", "is-active", "apache2"]),
        ("apache_enabled", ["systemctl", "is-enabled", "apache2"]),
        ("dhcp_active", ["systemctl", "is-active", "isc-dhcp-server"]),
        ("dhcp_enabled", ["systemctl", "is-enabled", "isc-dhcp-server"]),
        ("apache_status", ["systemctl", "status", "apache2", "--no-pager", "-l"]),
        ("dhcp_status", ["systemctl", "status", "isc-dhcp-server", "--no-pager", "-l"]),
        ("dhcp_journal", [
            "journalctl", "-u", "isc-dhcp-server", "--since", f"@{since_epoch}",
            "--no-pager", "-o", "short-iso-precise", "-n", "10000",
        ]),
        ("apache_journal", [
            "journalctl", "-u", "apache2", "--since", f"@{since_epoch}",
            "--no-pager", "-o", "short-iso-precise", "-n", "5000",
        ]),
    ]
    for command_id, argv in commands:
        builder.capture_command(command_id, argv)


def create_archive(staging: Path, destination: Path, top_level: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ztp-diagnostics.", suffix=".tar.gz", dir=str(destination.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            root_info = tarfile.TarInfo(top_level)
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o700
            root_info.uid = root_info.gid = 0
            root_info.uname = root_info.gname = "root"
            root_info.mtime = int(time.time())
            archive.addfile(root_info)
            for source in sorted(staging.rglob("*")):
                if source.is_dir():
                    continue
                if source.is_symlink() or not source.is_file():
                    raise DiagnosticError(f"unsafe staged member: {source}")
                relative = source.relative_to(staging).as_posix()
                safe_relative(relative)
                data = source.read_bytes()
                info = tarfile.TarInfo(f"{top_level}/{relative}")
                info.size = len(data)
                info.mode = 0o600
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = int(source.stat().st_mtime)
                import io
                archive.addfile(info, io.BytesIO(data))
        os.chmod(temporary, 0o600)
        with tarfile.open(temporary, "r:gz") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or not (member.isdir() or member.isfile())
                ):
                    raise DiagnosticError(f"unsafe final archive member: {member.name}")
        if destination.exists() or destination.is_symlink():
            raise DiagnosticError(f"refusing to overwrite output: {destination}")
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="收集 ZTP/DHCP/Apache/monitor 安全脱敏排错包（只读）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  sudo python3 tools/collect-ztp-diagnostics.py -p 2099-example-site --air\n"
            "  sudo python3 tools/collect-ztp-diagnostics.py -p 2099-example-site "
            "--air --host SITE01-OOB-Leaf02\n"
            "未指定 --host 时只收管理服务器证据；指定 host 才尝试只读 BatchMode SSH。"
        ),
    )
    parser.add_argument("-p", "--project", required=True, help="DAY0-Prepare 项目名或路径")
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--air", action="store_true", help="AIR 环境")
    scope_group.add_argument("--prod", action="store_true", help="Production 环境")
    scope_group.add_argument("--type", choices=("air", "prod"), dest="scope_type")
    parser.add_argument("--host", action="append", default=[], help="精确 hostname，可重复")
    parser.add_argument(
        "--server-only", action="store_true",
        help="即使指定 --host 也只抽取已有服务端证据，不进行 SSH",
    )
    parser.add_argument(
        "--since-minutes", type=int, default=1440,
        help="服务日志窗口，1..10080 分钟（默认 1440）",
    )
    parser.add_argument(
        "--output-dir", help="归档目录；默认 /var/tmp/ztp-diagnostics（必须在 DocumentRoot 外）",
    )
    parser.add_argument("--identity", help="可选 SSH 私钥路径；只读取，绝不打包")
    parser.add_argument(
        "--known-hosts", default="/root/.ssh/known_hosts",
        help="只读 known_hosts；不会接受或删除 host key",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.since_minutes <= 10080:
        parser.error("--since-minutes 必须在 1..10080")
    if len(args.host) > MAX_HOSTS:
        parser.error(f"--host 最多 {MAX_HOSTS} 台")
    if len(args.host) != len(set(args.host)):
        parser.error("--host 不得重复")
    args.scope = "air" if args.air else "prod" if args.prod else args.scope_type or "all"
    if args.host and args.scope == "all":
        parser.error("指定 --host 时必须明确 --air 或 --prod")
    return args


def main(argv: Optional[list[str]] = None) -> int:
    os.umask(0o077)
    try:
        args = parse_args(argv)
        project = resolve_project(args.project)
        output_root = prepare_output_root(args.output_dir)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        artifact_id = f"{stamp}-{project.name}-{args.scope}"
        destination = output_root / f"ztp-diagnostics-{artifact_id}.tar.gz"
        if destination.exists() or destination.is_symlink():
            raise DiagnosticError(f"output already exists: {destination}")
        with tempfile.TemporaryDirectory(prefix=".collect.", dir=output_root) as temporary:
            staging = Path(temporary) / artifact_id
            builder = BundleBuilder(staging, artifact_id)
            active_project = runtime_active_project()
            snapshot, report = load_latest_report(project)
            selected = select_devices(report, args.host, args.scope) if args.host else []
            collect_project_inputs(builder, project)
            collect_runtime_files(builder, project)
            collect_selected_published_configs(builder, selected, project)
            collect_selected_operation_metadata(builder, project, args.host)
            collect_server_commands(builder, args.since_minutes, project)
            collect_public_key_fingerprints(builder)
            collect_monitor_state(builder, project, snapshot, selected)
            collect_switch_archives(
                builder, project, [str(item.get("hostname") or "") for item in selected],
            )
            if selected and not args.server_only:
                if active_project != project:
                    active_text = str(active_project) if active_project else "unresolved"
                    builder.warn(
                        "live SSH collection is allowed only for the active runtime "
                        f"project; requested={project}, active={active_text}. "
                        "Device SSH was skipped; server/project evidence is retained."
                    )
                else:
                    try:
                        identity, known_hosts = validate_ssh_inputs(
                            args.identity, args.known_hosts
                        )
                    except (DiagnosticError, OSError) as exc:
                        builder.warn(
                            f"live SSH inputs are unavailable; device collection skipped: {exc}"
                        )
                    else:
                        for device in selected:
                            collect_live_device(
                                builder, device,
                                identity=identity, known_hosts=known_hosts,
                            )
            builder.finalize({
                "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                "collector_host": socket.gethostname(),
                "project": project.name, "project_path": str(project),
                "runtime_active_project": (
                    active_project.name if active_project is not None else None
                ),
                "runtime_active_project_path": (
                    str(active_project) if active_project is not None else None
                ),
                "scope": args.scope, "selected_hosts": args.host,
                "server_only": bool(args.server_only or not args.host),
                "since_minutes": args.since_minutes,
            })
            create_archive(staging, destination, artifact_id)
        digest = sha256_file(destination)
        print(f"[OK] 诊断包：{destination}")
        print(f"[OK] SHA256：{digest}")
        print(f"[INFO] 安全复制示例：scp root@<ztp-server>:{destination} .")
        return 2 if builder.warnings else 0
    except (DiagnosticError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
