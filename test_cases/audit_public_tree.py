#!/usr/bin/env python3
"""Fail closed when a Git publication candidate crosses the public boundary.

Only paths that Git would publish are inspected.  Before the first commit that
means index entries plus untracked, non-ignored files; in a clean checkout it
means tracked files.  Findings intentionally contain no matched credential
value, so this command is safe to run in CI logs.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import struct
import subprocess
import sys
from typing import Iterable, Sequence


MAX_BLOB_BYTES = 5 * 1024 * 1024

ZERO_BYTE_PLACEHOLDERS = frozenset(
    {
        "DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-amd64.bin",
        "DAY0-Prepare/template/cumulus-linux-5.16.4-mlx-vx.bin",
        "DAY0-Prepare/template/laptop.pub",
        "DAY0-Prepare/template/mgmt-server.pub",
        "DAY0-Prepare/template/nvosv25-02-7002amd64.bin",
        "DAY0-Prepare/template/nvosv25-02-8008amd64.bin",
        "DAY0-Prepare/template/p2p.xlsx",
    }
)

EMPTY_DIRECTORY_SENTINELS = frozenset(
    {
        "DAY0-Prepare/template/99-output-backup/.gitkeep",
        "DAY0-Prepare/template/99-output-dhcp/.gitkeep",
        "DAY0-Prepare/template/99-output-eth/.gitkeep",
        "DAY0-Prepare/template/99-output-ib_nvl/.gitkeep",
        "DAY0-Prepare/template/99-output-ib_nvl/bringup/ndr-upgrade-logs/.gitkeep",
        "DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-initial-setup-logs/.gitkeep",
        "DAY0-Prepare/template/99-output-ib_nvl/bringup/xdr-upgrade-logs/.gitkeep",
        "DAY0-Prepare/template/99-output-monitor/.gitkeep",
        "DAY0-Prepare/template/99-output-p2p/.gitkeep",
        "DAY0-Prepare/template/99-output-ztp/.gitkeep",
    }
)

EMPTY_DIRECTORY_SENTINEL_CONTENT = (
    b"# Retain this empty runtime-output skeleton in source checkouts.\n"
)

PUBLIC_DAY0_TEMPLATE_FILES = frozenset(
    {
        "DAY0-Prepare/template/.management-pubkeys",
        "DAY0-Prepare/template/01-global.yaml",
        "DAY0-Prepare/template/02-devices_config.csv",
        "DAY0-Prepare/template/02-dhcp-subnet_config.csv",
        "DAY0-Prepare/template/README.txt",
        "DAY0-Prepare/template/p2p/README.txt",
        *ZERO_BYTE_PLACEHOLDERS,
        *EMPTY_DIRECTORY_SENTINELS,
    }
)

PUBLIC_LOG_RULES = frozenset(
    {
        "ztp/config/cumulus/template/P2P/01-inventory.log",
        "ztp/config/cumulus/template/P2P/02-port-mapping.log",
        "ztp/config/cumulus/template/P2P/03-splitter.log",
        "ztp/config/nvos/template/P2P/01-inventory.log",
        "ztp/config/nvos/template/P2P/02-port-mapping.log",
        "ztp/config/nvos/template/P2P/03-splitter.log",
    }
)

FORBIDDEN_ROOTS = frozenset(
    {
        ".agents",
        ".codex",
        "download",
        "firmware",
        "image",
        "outputs",
        "package-imports",
    }
)

FORBIDDEN_EXACT_PATHS = frozenset(
    {
        "README.md",
        "USER_MANUAL.md",
        "DAY0-Prepare/README.md",
        "ethernet/eth.csv",
        "ethernet/p2p.xlsx",
        "infiniband/ib.csv",
        "infiniband/p2p.xlsx",
        "infra/01-global.yaml",
        "infra/02-devices_config.csv",
        "infra/README.md",
        "monitor/01-global.yaml",
        "monitor/02-devices_config.csv",
        "monitor/monitor.html",
        "monitor/README.md",
        "nvlink/nvsw.csv",
        "nvlink/p2p.xlsx",
        "tools/README.md",
        "tools/ibdiagnet-analyze-tool/README.md",
        "tools/lldp-analyze-tool/README.md",
        "ztp/README.md",
        "ztp/.setup_manifest",
        "ztp/config/cumulus/template/README.md",
        "ztp/config/cumulus/template/P2P/README.md",
        "ztp/config/isc-dhcp-server/README.md",
        "ztp/config/nvos/template/P2P/README.md",
        "ztp/optimize/issue-tracker/README.md",
        "ztp/status",
        "ztp/ztp-bootstrap_oob.sh",
        "ztp/ztp-bootstrap_oobofoob.sh",
        "ztp/ztp.json",
    }
)

FORBIDDEN_BASENAMES = frozenset(
    {
        ".deployment.lock",
        ".sync-code-in-progress",
        "current-release.json",
        "dhcp-release-manifest.json",
        "dhcpd.conf",
        "dhcpd_eth.hosts",
        "dhcpd_ib.hosts",
        "dhcpd_nvl.hosts",
        "p2p-air.json",
    }
)

FORBIDDEN_ARTIFACT_SUFFIXES = frozenset(
    {
        ".7z",
        ".bin",
        ".bz2",
        ".cab",
        ".deb",
        ".doc",
        ".docx",
        ".gz",
        ".img",
        ".jpeg",
        ".jpg",
        ".iso",
        ".jks",
        ".key",
        ".keystore",
        ".p12",
        ".pdf",
        ".pem",
        ".pfx",
        ".ppt",
        ".pptx",
        ".png",
        ".qcow",
        ".qcow2",
        ".rar",
        ".rpm",
        ".tar",
        ".tgz",
        ".vmdk",
        ".vme",
        ".webp",
        ".xls",
        ".xlsm",
        ".xlsx",
        ".xz",
        ".zip",
    }
)

CREDENTIAL_SUFFIXES = frozenset(
    {".key", ".keystore", ".p12", ".pem", ".pfx", ".pub"}
)

# A real redaction regression embeds this marker as input data.  The exception
# is deliberately bound to detector, path, exact line range and whole-block
# digest; moving it or changing either marker/payload makes the audit fail.
EXACT_TEST_FIXTURE_EXCEPTIONS = frozenset(
    {
        (
            "private-key",
            "test_cases/test_diagnostic_bundle.py",
            77,
            79,
            "439e9f9266d149ab9c58be0b9f2a08bcf4f28fc5a861b11b307d00ef1f191f83",
        )
    }
)

PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN[ \t]+(?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED)[ \t]+)?PRIVATE[ \t]+KEY-----"
)

PASSWORD_HASH_RES = (
    re.compile(rb"(?<![./A-Za-z0-9])\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}(?![./A-Za-z0-9])"),
    re.compile(rb"(?<![./A-Za-z0-9])\$5\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}(?![./A-Za-z0-9])"),
    re.compile(rb"(?<![./A-Za-z0-9])\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}(?![./A-Za-z0-9])"),
    re.compile(rb"(?<![./A-Za-z0-9])\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"),
    re.compile(rb"(?<![./A-Za-z0-9])\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{20,}(?![./A-Za-z0-9])"),
    re.compile(
        rb"(?<![./A-Za-z0-9])\$[156]\$rounds=[0-9]{4,9}\$"
        rb"[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}(?![./A-Za-z0-9])"
    ),
)

TOKEN_RES = (
    re.compile(rb"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82,255}(?![A-Za-z0-9_])"),
    re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])"),
    re.compile(rb"(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(rb"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])"),
    re.compile(rb"(?i)(?<![A-Za-z0-9])bearer[ \t]+[A-Za-z0-9._~+/-]{20,}(?![A-Za-z0-9._~+/-])"),
)

SSH_PUBLIC_KEY_RE = re.compile(
    rb"(?<![-A-Za-z0-9])"
    rb"(ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|"
    rb"sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com|"
    rb"ssh-(?:rsa|ed25519)-cert-v01@openssh\.com|"
    rb"ecdsa-sha2-nistp(?:256|384|521)-cert-v01@openssh\.com)"
    rb"[ \t]+([A-Za-z0-9+/]{24,}={0,3})(?=[ \t]|$)"
)

IPV4_RE = re.compile(
    rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)

PRIVATE_IPV4_TEMPLATE_RE = re.compile(
    rb"(?<![0-9])(?:"
    rb"10\.(?:[0-9]{1,3}|\{[^}\r\n]+\})\."
    rb"(?:[0-9]{1,3}|\{[^}\r\n]+\})\.(?:[0-9]{1,3}|\{[^}\r\n]+\})|"
    rb"192\.168\.(?:[0-9]{1,3}|\{[^}\r\n]+\})\."
    rb"(?:[0-9]{1,3}|\{[^}\r\n]+\})|"
    rb"172\.(?:1[6-9]|2[0-9]|3[01])\."
    rb"(?:[0-9]{1,3}|\{[^}\r\n]+\})\.(?:[0-9]{1,3}|\{[^}\r\n]+\})"
    rb")(?![0-9])"
)

MAC_RE = re.compile(
    rb"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])"
)

COMPACT_MAC_RE = re.compile(
    rb"(?i)(?<![0-9a-f])[0-9a-f]{12}(?![0-9a-f])"
)

CLEARTEXT_CREDENTIAL_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9_-])[\"']?"
    rb"(?:password|passwd|secret|api[_-]?key|access[_-]?token)[\"']?"
    rb"[ \t]*(?:=|:)[ \t]*([\"'])([^\"'\r\n]{6,})\1"
)

CLEARTEXT_UNQUOTED_CREDENTIAL_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9_-])"
    rb"(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
    rb"[ \t]*(?:=|:)[ \t]*"
    rb"([A-Za-z0-9][A-Za-z0-9_.!@#%+/-]{5,})(?=[ \t,}\]]|$)"
)

PATH_CREDENTIAL_RE = re.compile(
    rb"(?i)(?<![A-Za-z0-9_-])"
    rb"(?:password|passwd|secret|api[_-]?key|access[_-]?token)="
    rb"[^/\\]{6,}"
)

DOCUMENTATION_SUFFIXES = frozenset({".md", ".rst"})
SAFE_CREDENTIAL_LITERALS = frozenset(
    {
        b"******",
        b"example",
        b"placeholder",
        b"redacted",
        b"secret-value",
        b"sentinel",
    }
)

# These are deliberately narrow, path-bound protocol/test constants.  They do
# not permit arbitrary private identities elsewhere in the same file.
PRIVATE_IPV4_LITERAL_EXCEPTIONS = {
    "ztp/config/cumulus/template/90-c2-generate_configs.py": frozenset(
        {b"192.168.200.1"}
    ),
    "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py": frozenset(
        {b"192.168.200.{mgmt_base}"}
    ),
}

SYNTHETIC_MAC_LITERAL_EXCEPTIONS = {
    "ztp/optimize/feedback.py": frozenset({b"00:00:5e:00:01:06"}),
}


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    message: str
    line: int | None = None


@dataclass(frozen=True)
class IndexEntry:
    mode: str
    object_id: str


class AuditError(RuntimeError):
    """The audit could not establish a trustworthy candidate set."""


def git_candidates(root: Path) -> list[str]:
    command = [
        "git",
        "-C",
        os.fspath(root),
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
    ]
    try:
        process = subprocess.run(command, check=False, capture_output=True)
    except OSError as exc:
        raise AuditError("Git candidate discovery could not be started") from exc
    if process.returncode != 0:
        raise AuditError("Git candidate discovery failed")
    paths = [os.fsdecode(raw) for raw in process.stdout.split(b"\0") if raw]
    if len(paths) != len(set(paths)):
        raise AuditError("Git returned duplicate candidate paths")
    return sorted(paths)


def git_index_entries(root: Path) -> dict[str, IndexEntry]:
    command = ["git", "-C", os.fspath(root), "ls-files", "--stage", "-z", "--"]
    try:
        process = subprocess.run(command, check=False, capture_output=True)
    except OSError as exc:
        raise AuditError("Git index discovery could not be started") from exc
    if process.returncode != 0:
        raise AuditError("Git index discovery failed")
    entries: dict[str, IndexEntry] = {}
    for raw in process.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            metadata, encoded_path = raw.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ", 2)
            relative = os.fsdecode(encoded_path)
        except ValueError as exc:
            raise AuditError("Git returned an invalid index record") from exc
        if stage != b"0":
            raise AuditError("Git index contains unresolved merge entries")
        decoded_mode = mode.decode("ascii", "strict")
        decoded_id = object_id.decode("ascii", "strict")
        if not re.fullmatch(r"[0-9a-f]{40,64}", decoded_id):
            raise AuditError("Git returned an invalid object identifier")
        if relative in entries:
            raise AuditError("Git returned duplicate index entries")
        entries[relative] = IndexEntry(decoded_mode, decoded_id)
    return entries


def git_index_blob(root: Path, entry: IndexEntry) -> tuple[int, bytes | None]:
    size_process = subprocess.run(
        ["git", "-C", os.fspath(root), "cat-file", "-s", entry.object_id],
        check=False,
        capture_output=True,
        text=True,
    )
    if size_process.returncode != 0:
        raise AuditError("Git index object size could not be read")
    try:
        size = int(size_process.stdout.strip())
    except ValueError as exc:
        raise AuditError("Git returned an invalid index object size") from exc
    if size < 0:
        raise AuditError("Git returned a negative index object size")
    if size > MAX_BLOB_BYTES:
        return size, None
    blob_process = subprocess.run(
        ["git", "-C", os.fspath(root), "cat-file", "blob", entry.object_id],
        check=False,
        capture_output=True,
    )
    if blob_process.returncode != 0 or len(blob_process.stdout) != size:
        raise AuditError("Git index object could not be read exactly")
    return size, blob_process.stdout


def validate_relative_path(raw: str) -> PurePosixPath:
    if not raw or "\x00" in raw or "\\" in raw:
        raise AuditError("Git returned an unsafe candidate path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AuditError("Git returned a candidate path outside the repository")
    return path


def private_ipv4_matches(data: bytes) -> list[re.Match[bytes]]:
    matches: list[re.Match[bytes]] = []
    private_networks = (
        ipaddress.IPv4Network((0x0A000000, 8)),
        ipaddress.IPv4Network((0xAC100000, 12)),
        ipaddress.IPv4Network((0xC0A80000, 16)),
    )
    for match in IPV4_RE.finditer(data):
        try:
            address = ipaddress.IPv4Address(match.group(0).decode("ascii"))
        except ipaddress.AddressValueError:
            continue
        if any(address in network for network in private_networks):
            matches.append(match)
    return matches


def non_synthetic_mac_matches(data: bytes) -> list[re.Match[bytes]]:
    matches: list[re.Match[bytes]] = []
    for pattern in (MAC_RE, COMPACT_MAC_RE):
        for match in pattern.finditer(data):
            first_octet = int(match.group(0)[:2], 16)
            # Locally administered unicast addresses are synthetic fixtures.
            # Group addresses are protocol constants rather than identities.
            if not (first_octet & 0x02) and not (first_octet & 0x01):
                matches.append(match)
    return matches


def sensitive_path_finding(relative: str) -> Finding | None:
    encoded = os.fsencode(relative)
    basename = PurePosixPath(relative).name
    if (
        basename == ".env"
        or basename.startswith(".env.")
        or basename.startswith("id_rsa")
        or basename.startswith("id_ed25519")
        or private_ipv4_matches(encoded)
        or non_synthetic_mac_matches(encoded)
        or any(pattern.search(encoded) for pattern in PASSWORD_HASH_RES)
        or any(pattern.search(encoded) for pattern in TOKEN_RES)
        or PATH_CREDENTIAL_RE.search(encoded)
    ):
        return Finding(
            "sensitive-path",
            relative,
            "candidate path contains a private identity or credential marker",
        )
    return None


def field_path_finding(relative: str) -> Finding | None:
    path = PurePosixPath(relative)
    parts = path.parts
    if parts[0] in FORBIDDEN_ROOTS or parts[0].startswith(".codex_tmp"):
        return Finding("field-path", relative, "local/runtime root is not publishable")
    if parts[0] == "apps" and relative != "apps/README.md":
        return Finding("field-path", relative, "offline package content is not publishable")
    if parts[0] == "DAY0-Prepare" and len(parts) >= 3:
        if parts[1] != "template":
            return Finding("field-path", relative, "real DAY0 project directories are private")
        if relative not in PUBLIC_DAY0_TEMPLATE_FILES:
            return Finding("field-path", relative, "unexpected DAY0 template artifact")
    if relative in FORBIDDEN_EXACT_PATHS or path.name in FORBIDDEN_BASENAMES:
        return Finding("field-path", relative, "generated/runtime file is not publishable")
    if (
        len(parts) == 5
        and parts[:3] == ("ztp", "optimize", "issue-tracker")
        and parts[3].startswith("OPT-")
        and parts[4] == "README.md"
    ):
        return Finding("field-path", relative, "internal incident documentation is private")
    if any(part in {"collected", "dumps", "logs"} for part in parts):
        if relative not in EMPTY_DIRECTORY_SENTINELS:
            return Finding("field-path", relative, "runtime evidence directory is private")
    if any(part.startswith("99-output") for part in parts):
        if relative not in EMPTY_DIRECTORY_SENTINELS:
            return Finding("field-path", relative, "generated output is not publishable")
    if path.suffix.lower() == ".log" and relative not in PUBLIC_LOG_RULES:
        return Finding("field-path", relative, "runtime log is not publishable")
    return None


def valid_ssh_public_key(algorithm: bytes, encoded: bytes) -> bool:
    try:
        padding = b"=" * (-len(encoded) % 4)
        blob = base64.b64decode(encoded + padding, validate=True)
        if len(blob) < 8:
            return False
        (length,) = struct.unpack(">I", blob[:4])
        if length <= 0 or length > len(blob) - 4:
            return False
        return blob[4 : 4 + length] == algorithm
    except (ValueError, struct.error):
        return False


def exception_allowed(
    kind: str,
    relative: str,
    line_number: int,
    lines_with_endings: Sequence[bytes],
) -> bool:
    for detector, path, start, end, expected_digest in EXACT_TEST_FIXTURE_EXCEPTIONS:
        if (kind, relative, line_number) != (detector, path, start):
            continue
        block = b"".join(lines_with_endings[start - 1 : end])
        if hashlib.sha256(block).hexdigest() == expected_digest:
            return True
    return False


def scan_content(relative: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    lines_with_endings = data.splitlines(keepends=True)
    for line_number, raw_line in enumerate(lines_with_endings, 1):
        line = raw_line.rstrip(b"\r\n")
        if PRIVATE_KEY_RE.search(line):
            if not exception_allowed(
                "private-key", relative, line_number, lines_with_endings
            ):
                findings.append(
                    Finding("private-key", relative, "private-key material is not public", line_number)
                )
        if any(pattern.search(line) for pattern in PASSWORD_HASH_RES):
            findings.append(
                Finding("password-hash", relative, "reusable password hash is not public", line_number)
            )
        if any(pattern.search(line) for pattern in TOKEN_RES):
            findings.append(Finding("token", relative, "access token is not public", line_number))
        credential = CLEARTEXT_CREDENTIAL_RE.search(line)
        unquoted_credential = CLEARTEXT_UNQUOTED_CREDENTIAL_RE.search(line)
        if credential is not None or unquoted_credential is not None:
            value = (
                credential.group(2)
                if credential is not None
                else unquoted_credential.group(1)
            ).strip().lower()
            if (
                value not in SAFE_CREDENTIAL_LITERALS
                and b"{{" not in value
                and b"${" not in value
                and not value.startswith(b"$")
            ):
                findings.append(
                    Finding(
                        "cleartext-credential",
                        relative,
                        "literal credential value is not public",
                        line_number,
                    )
                )
        if (
            PurePosixPath(relative).suffix.lower() not in DOCUMENTATION_SUFFIXES
            and relative != "test_cases/audit_public_tree.py"
        ):
            private_matches = [
                match
                for match in private_ipv4_matches(line)
                if match.group(0)
                not in PRIVATE_IPV4_LITERAL_EXCEPTIONS.get(relative, frozenset())
            ]
            private_template_matches = [
                match
                for match in PRIVATE_IPV4_TEMPLATE_RE.finditer(line)
                if match.group(0)
                not in PRIVATE_IPV4_LITERAL_EXCEPTIONS.get(relative, frozenset())
            ]
            if private_matches or private_template_matches:
                findings.append(
                    Finding(
                        "private-ipv4",
                        relative,
                        "private IPv4 identity is not allowed in public source/test text",
                        line_number,
                    )
                )
            mac_matches = [
                match
                for match in non_synthetic_mac_matches(line)
                if match.group(0).lower()
                not in SYNTHETIC_MAC_LITERAL_EXCEPTIONS.get(relative, frozenset())
            ]
            if mac_matches:
                findings.append(
                    Finding(
                        "non-synthetic-mac",
                        relative,
                        "globally administered device MAC is not allowed in public source/test text",
                        line_number,
                    )
                )
        for match in SSH_PUBLIC_KEY_RE.finditer(line):
            if valid_ssh_public_key(match.group(1), match.group(2)):
                findings.append(
                    Finding("ssh-public-key", relative, "SSH public keys identify operators", line_number)
                )
                break
    return findings


def inspect_regular_data(relative: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    suffix = PurePosixPath(relative).suffix.lower()
    if suffix in CREDENTIAL_SUFFIXES:
        if relative not in ZERO_BYTE_PLACEHOLDERS or data:
            findings.append(Finding("credential-file", relative, "credential/key files are not public"))
            return findings
    if suffix in FORBIDDEN_ARTIFACT_SUFFIXES:
        if relative not in ZERO_BYTE_PLACEHOLDERS or data:
            findings.append(Finding("binary-artifact", relative, "binary/package artifact is not public"))
            return findings
    if relative in ZERO_BYTE_PLACEHOLDERS and data:
        findings.append(Finding("placeholder-content", relative, "canonical placeholder must remain empty"))
        return findings
    if relative in EMPTY_DIRECTORY_SENTINELS and data != EMPTY_DIRECTORY_SENTINEL_CONTENT:
        findings.append(Finding("placeholder-content", relative, "directory sentinel content changed"))
        return findings
    if b"\0" in data:
        findings.append(
            Finding("binary-content", relative, "unknown binary content is not publishable")
        )
        return findings
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        findings.append(
            Finding("binary-content", relative, "non-UTF-8 content is not publishable")
        )
        return findings
    if (
        relative == "DAY0-Prepare/template/.management-pubkeys"
        and data != b"mgmt-server.pub\n"
    ):
        findings.append(
            Finding(
                "placeholder-content",
                relative,
                "management key manifest changed from public placeholder",
            )
        )
        return findings
    findings.extend(scan_content(relative, data))
    return findings


def target_is_candidate(root: Path, resolved: Path, candidates: set[str]) -> bool:
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError:
        return False
    if resolved.is_dir():
        prefix = relative.rstrip("/") + "/"
        return any(candidate.startswith(prefix) for candidate in candidates)
    return relative in candidates


def index_symlink_target_is_candidate(
    relative: str, target: str, candidates: set[str]
) -> tuple[bool, str | None]:
    if not target or "\x00" in target or os.path.isabs(target):
        return False, "absolute-symlink"
    parent = PurePosixPath(relative).parent.as_posix()
    combined = posixpath.normpath(posixpath.join(parent, target))
    if combined == ".." or combined.startswith("../") or combined.startswith("/"):
        return False, "escaping-symlink"
    if combined in candidates:
        return True, None
    prefix = combined.rstrip("/") + "/"
    if any(candidate.startswith(prefix) for candidate in candidates):
        return True, None
    return False, "unpublished-symlink"


def inspect_index_candidate(
    root: Path,
    relative: str,
    entry: IndexEntry,
    candidates: set[str],
) -> list[Finding]:
    try:
        validate_relative_path(relative)
    except AuditError:
        return [Finding("unsafe-path", "<redacted>", "unsafe Git path")]
    size, data = git_index_blob(root, entry)
    if size > MAX_BLOB_BYTES:
        return [Finding("large-blob", relative, "indexed blob exceeds the 5 MiB public limit")]
    assert data is not None
    if entry.mode == "120000":
        target = os.fsdecode(data)
        valid, kind = index_symlink_target_is_candidate(relative, target, candidates)
        if valid:
            return []
        messages = {
            "absolute-symlink": "indexed absolute symlink is not portable",
            "escaping-symlink": "indexed symlink escapes repository",
            "unpublished-symlink": "indexed symlink target is excluded from Git publication",
        }
        assert kind is not None
        return [Finding(kind, relative, messages[kind])]
    if entry.mode not in {"100644", "100755"}:
        return [Finding("special-file", relative, "unsupported Git index mode")]
    return inspect_regular_data(relative, data)


def inspect_candidate(root: Path, relative: str, candidates: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        pure = validate_relative_path(relative)
    except AuditError:
        return [Finding("unsafe-path", "<redacted>", "unsafe Git path")]

    field = field_path_finding(relative)
    if field is not None:
        findings.append(field)
    sensitive_path = sensitive_path_finding(relative)
    if sensitive_path is not None:
        findings.append(sensitive_path)

    path = root.joinpath(*pure.parts)
    try:
        info = path.lstat()
    except OSError:
        findings.append(Finding("missing-candidate", relative, "Git candidate is absent"))
        return findings

    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            findings.append(Finding("broken-symlink", relative, "symlink target cannot be read"))
            return findings
        if os.path.isabs(target):
            findings.append(Finding("absolute-symlink", relative, "absolute symlink is not portable"))
            return findings
        lexical = Path(os.path.abspath(os.path.join(os.fspath(path.parent), target)))
        try:
            lexical.relative_to(root)
        except ValueError:
            findings.append(Finding("escaping-symlink", relative, "symlink escapes repository"))
            return findings
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            findings.append(Finding("broken-symlink", relative, "symlink target does not exist"))
            return findings
        try:
            resolved.relative_to(root)
        except ValueError:
            findings.append(Finding("escaping-symlink", relative, "symlink resolves outside repository"))
            return findings
        if not target_is_candidate(root, resolved, candidates):
            findings.append(
                Finding("unpublished-symlink", relative, "symlink target is excluded from Git publication")
            )
        return findings

    if not stat.S_ISREG(info.st_mode):
        findings.append(Finding("special-file", relative, "only regular files and symlinks are public"))
        return findings
    if info.st_nlink != 1:
        findings.append(Finding("hardlink", relative, "multiply-linked files are not publishable"))
    if info.st_size > MAX_BLOB_BYTES:
        findings.append(Finding("large-blob", relative, "blob exceeds the 5 MiB public limit"))
        return findings

    try:
        data = path.read_bytes()
    except OSError:
        findings.append(Finding("unreadable-file", relative, "candidate cannot be inspected"))
        return findings
    findings.extend(inspect_regular_data(relative, data))
    return findings


def redact_display_path(path: str) -> str:
    encoded = os.fsencode(path)
    for pattern in TOKEN_RES:
        encoded = pattern.sub(b"<redacted>", encoded)
    for pattern in PASSWORD_HASH_RES:
        encoded = pattern.sub(b"<redacted>", encoded)
    encoded = IPV4_RE.sub(b"<redacted-ipv4>", encoded)
    encoded = MAC_RE.sub(b"<redacted-mac>", encoded)
    encoded = COMPACT_MAC_RE.sub(b"<redacted-mac>", encoded)
    encoded = PATH_CREDENTIAL_RE.sub(b"<redacted-credential>", encoded)
    return json.dumps(os.fsdecode(encoded), ensure_ascii=True)


def audit(root: Path) -> tuple[list[str], list[Finding]]:
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise AuditError("repository root does not exist") from exc
    if not root.is_dir():
        raise AuditError("repository root is not a directory")
    candidates = git_candidates(root)
    index_entries = git_index_entries(root)
    candidate_set = set(candidates)
    findings: list[Finding] = []
    for relative in candidates:
        findings.extend(inspect_candidate(root, relative, candidate_set))
        entry = index_entries.get(relative)
        if entry is not None:
            findings.extend(inspect_index_candidate(root, relative, entry, candidate_set))
    return candidates, list(dict.fromkeys(findings))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit Git publication candidates for public-boundary violations."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Git worktree to audit (default: repository containing this script)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        candidates, findings = audit(args.root)
    except AuditError as exc:
        print(f"[ERROR] Public repository audit could not run: {exc}", file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            location = redact_display_path(finding.path)
            if finding.line is not None:
                location += f":{finding.line}"
            print(f"[ERROR] {location} [{finding.kind}]: {finding.message}", file=sys.stderr)
        print(
            f"[ERROR] Public repository audit rejected {len(findings)} finding(s); "
            "matched values were not printed.",
            file=sys.stderr,
        )
        return 1
    print(f"[OK] Public repository audit passed: {len(candidates)} Git candidate(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
