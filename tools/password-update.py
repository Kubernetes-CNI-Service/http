#!/usr/bin/env python3
"""Safely rotate Cumulus and NVOS password hashes in a project global YAML."""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterable

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from deployment_lock import DeploymentLockError, deployment_lock
from ztp_service_runtime import RuntimeContractError, stop_native_ztp_monitors


ROOT = Path(__file__).resolve().parents[1]
DAY0 = ROOT / "DAY0-Prepare"
GLOBAL_FILENAME = "01-global.yaml"
DEVICES_FILENAME = "02-devices_config.csv"
MAX_GLOBAL_SIZE = 4 * 1024 * 1024
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
SECTION_ORDER = ("eth", "ib", "nvl")
HASH_METHODS = {
    "eth": ("sha-512", "$6$", "SHA-512 crypt"),
    "ib": ("yescrypt", "$y$", "yescrypt"),
    "nvl": ("yescrypt", "$y$", "yescrypt"),
}
YAML_STRING_TAG = "tag:yaml.org,2002:str"
LIBXCRYPT_RANDOM_SIZE = 32
LIBXCRYPT_SALT_BUFFER_SIZE = 192
LIBXCRYPT_WORKSPACE_SIZE = 128 * 1024
HOMEBREW_LIBXCRYPT_CANDIDATES = (
    (
        Path("/opt/homebrew/opt/libxcrypt/lib/libcrypt.2.dylib"),
        Path("/opt/homebrew/Cellar/libxcrypt"),
    ),
    (
        Path("/usr/local/opt/libxcrypt/lib/libcrypt.2.dylib"),
        Path("/usr/local/Cellar/libxcrypt"),
    ),
)


class PasswordUpdateError(RuntimeError):
    """The requested password rotation is unsafe or cannot be completed."""


@dataclass(frozen=True)
class ScalarTarget:
    """One exact password scalar in the source YAML."""

    section: str
    field: str
    node: ScalarNode


@dataclass(frozen=True)
class FileSnapshot:
    """An immutable read of one validated regular file."""

    data: bytes
    metadata: os.stat_result
    sha256: str


@dataclass(frozen=True)
class UpdateResult:
    """Safe, non-secret evidence for one preview or committed update."""

    path: Path
    sections: tuple[str, ...]
    before_sha256: str
    after_sha256: str
    changed: bool
    dry_run: bool


def _mapping_items(node: Node, label: str) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        raise PasswordUpdateError(f"{label} 必须是 YAML mapping")
    result: dict[str, Node] = {}
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode) or key_node.tag != YAML_STRING_TAG:
            raise PasswordUpdateError(f"{label} 只能使用字符串 key")
        key = key_node.value
        if key in result:
            raise PasswordUpdateError(f"{label} 存在重复 key: {key}")
        result[key] = value_node
    return result


def _required_mapping_value(node: Node, key: str, label: str) -> Node:
    values = _mapping_items(node, label)
    if key not in values:
        raise PasswordUpdateError(f"{label} 缺少 {key}")
    return values[key]


def _selected_sections(sections: Iterable[str]) -> tuple[str, ...]:
    values = tuple(sections)
    if not values:
        raise PasswordUpdateError("至少需要选择一个平台")
    if len(values) != len(set(values)):
        raise PasswordUpdateError("平台选择不能重复")
    unknown = sorted(set(values) - set(SECTION_ORDER))
    if unknown:
        raise PasswordUpdateError(f"未知平台: {', '.join(unknown)}")
    return tuple(section for section in SECTION_ORDER if section in values)


def _switch_sections(root: Node) -> dict[str, Node]:
    switches_node = _required_mapping_value(root, "switches", "global YAML 顶层")
    if not isinstance(switches_node, SequenceNode):
        raise PasswordUpdateError("global YAML 的 switches 必须是 list")
    sections: dict[str, Node] = {}
    for index, item in enumerate(switches_node.value, 1):
        for key, value in _mapping_items(item, f"switches[{index}]").items():
            if key not in SECTION_ORDER:
                continue
            if key in sections:
                raise PasswordUpdateError(f"switches 中 {key} 平台定义重复")
            sections[key] = value
    return sections


def _node_reference_counts(root: Node) -> dict[int, int]:
    """Count YAML graph references so password aliases can be rejected."""
    counts: dict[int, int] = {}
    expanded: set[int] = set()

    def visit(node: Node) -> None:
        identity = id(node)
        counts[identity] = counts.get(identity, 0) + 1
        if identity in expanded:
            return
        expanded.add(identity)
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                visit(key_node)
                visit(value_node)
        elif isinstance(node, SequenceNode):
            for child in node.value:
                visit(child)

    visit(root)
    return counts


def _scalar(node: Node, label: str) -> ScalarNode:
    if not isinstance(node, ScalarNode) or node.tag != YAML_STRING_TAG:
        raise PasswordUpdateError(f"{label} 必须是 YAML 字符串标量")
    return node


def _nvos_target(section: str, section_node: Node) -> ScalarTarget:
    system = _required_mapping_value(section_node, "system", f"switches.{section}")
    system_values = _mapping_items(system, f"switches.{section}.system")

    security = system_values.get("security")
    if security is None:
        raise PasswordUpdateError(
            f"switches.{section}.system 缺少 security.password-hardening.state=disabled"
        )
    hardening = _required_mapping_value(
        security, "password-hardening", f"switches.{section}.system.security",
    )
    state = _scalar(
        _required_mapping_value(
            hardening, "state",
            f"switches.{section}.system.security.password-hardening",
        ),
        f"switches.{section}.system.security.password-hardening.state",
    )
    if state.value.strip().casefold() != "disabled":
        raise PasswordUpdateError(
            f"switches.{section}.system.security.password-hardening.state "
            "必须为 disabled，才能安全下发加密密码"
        )

    aaa = _required_mapping_value(system, "aaa", f"switches.{section}.system")
    users = _required_mapping_value(aaa, "user", f"switches.{section}.system.aaa")
    admin = _required_mapping_value(
        users, "admin", f"switches.{section}.system.aaa.user",
    )
    admin_values = _mapping_items(
        admin, f"switches.{section}.system.aaa.user.admin",
    )
    fields = [key for key in ("password", "hashed-password") if key in admin_values]
    if len(fields) != 1:
        raise PasswordUpdateError(
            f"switches.{section}.system.aaa.user.admin 必须且只能包含 "
            "password 或 hashed-password 其中一个"
        )
    field = fields[0]
    target = _scalar(
        admin_values[field],
        f"switches.{section}.system.aaa.user.admin.{field}",
    )
    return ScalarTarget(section=section, field=field, node=target)


def locate_password_targets(
    text: str, *, sections: Iterable[str],
) -> tuple[ScalarTarget, ...]:
    """Locate exact scalar spans without serializing or reformatting the YAML."""
    selected = _selected_sections(sections)
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise PasswordUpdateError(f"01-global.yaml YAML 语法错误: {exc}") from exc
    if root is None:
        raise PasswordUpdateError("01-global.yaml 不能为空")
    available = _switch_sections(root)
    missing = [section for section in selected if section not in available]
    if missing:
        raise PasswordUpdateError(
            f"01-global.yaml 缺少平台: {', '.join(missing)}"
        )

    reference_counts = _node_reference_counts(root)
    targets: list[ScalarTarget] = []
    for section in selected:
        section_node = available[section]
        if section == "eth":
            system = _required_mapping_value(
                section_node, "system", "switches.eth",
            )
            aaa = _required_mapping_value(system, "aaa", "switches.eth.system")
            users = _required_mapping_value(aaa, "user", "switches.eth.system.aaa")
            cumulus = _required_mapping_value(
                users, "cumulus", "switches.eth.system.aaa.user",
            )
            password = _scalar(
                _required_mapping_value(
                    cumulus, "hashed-password",
                    "switches.eth.system.aaa.user.cumulus",
                ),
                "switches.eth.system.aaa.user.cumulus.hashed-password",
            )
            targets.append(ScalarTarget(
                section="eth", field="hashed-password", node=password,
            ))
        else:
            targets.append(_nvos_target(section, section_node))

    if any(reference_counts.get(id(target.node), 0) != 1 for target in targets):
        raise PasswordUpdateError("密码字段不能使用 YAML anchor/alias 共享标量")
    spans = [
        (target.node.start_mark.index, target.node.end_mark.index)
        for target in targets
    ]
    if len(spans) != len(set(spans)):
        raise PasswordUpdateError("密码字段不能通过 YAML alias 共享同一个标量")
    return tuple(targets)


def _validate_hash(section: str, value: object) -> str:
    if not isinstance(value, str):
        raise PasswordUpdateError(f"{section} 密码哈希必须是字符串")
    method, prefix, label = HASH_METHODS[section]
    del method
    if (
        not value.startswith(prefix)
        or len(value) < len(prefix) + 8
        or len(value) > 512
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        or value.count("$") < 3
    ):
        raise PasswordUpdateError(f"{section} 不是合法的 {label} 输出")
    return value


def extract_password_hashes(
    text: str, *, sections: Iterable[str],
) -> dict[str, str]:
    """Return validated password hashes without exposing unrelated YAML data."""
    targets = locate_password_targets(text, sections=sections)
    return {
        target.section: _validate_hash(target.section, target.node.value)
        for target in targets
    }


def rewrite_global_passwords(
    text: str, hashes: dict[str, str], *, sections: Iterable[str],
) -> str:
    """Replace only selected credential scalar spans in a global YAML string."""
    selected = _selected_sections(sections)
    if set(hashes) != set(selected):
        raise PasswordUpdateError("密码哈希集合必须与选择的平台完全一致")
    validated = {
        section: _validate_hash(section, hashes[section])
        for section in selected
    }
    targets = locate_password_targets(text, sections=selected)
    rendered = text
    for target in sorted(
        targets, key=lambda item: item.node.start_mark.index, reverse=True,
    ):
        start = target.node.start_mark.index
        end = target.node.end_mark.index
        replacement = json.dumps(validated[target.section], ensure_ascii=True)
        rendered = rendered[:start] + replacement + rendered[end:]

    verified = locate_password_targets(rendered, sections=selected)
    for target in verified:
        if target.node.value != validated[target.section]:
            raise PasswordUpdateError(
                f"内部校验失败：{target.section} 密码哈希未被精确写入"
            )
    return rendered


def validate_plaintext_password(
    password: str, *, account_names: Iterable[str],
) -> None:
    """Enforce the shared Cumulus/NVOS password-hardening baseline."""
    if not isinstance(password, str):
        raise PasswordUpdateError("密码必须是字符串")
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise PasswordUpdateError(
            f"密码长度必须为 {MIN_PASSWORD_LENGTH} 到 "
            f"{MAX_PASSWORD_LENGTH} 个字符"
        )
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in password):
        raise PasswordUpdateError("密码只能包含不带空白的可打印 ASCII 字符")
    if not any(character.islower() for character in password):
        raise PasswordUpdateError("密码至少需要一个小写字母")
    if not any(character.isupper() for character in password):
        raise PasswordUpdateError("密码至少需要一个大写字母")
    if not any(character.isdigit() for character in password):
        raise PasswordUpdateError("密码至少需要一个数字")
    if not any(not character.isalnum() for character in password):
        raise PasswordUpdateError("密码至少需要一个特殊字符")
    lowered = password.casefold()
    for account in account_names:
        name = str(account).strip().casefold()
        if name and name in lowered:
            raise PasswordUpdateError(f"密码不能包含账户名 {account}")


def _mkpasswd_executable() -> str | None:
    """Resolve the preferred Ubuntu whois backend, if one is available."""
    return shutil.which("mkpasswd")


def _validate_libxcrypt_candidate(candidate: Path, cellar_root: Path) -> Path:
    """Accept only one immutable regular dylib below Homebrew's libxcrypt Cellar."""
    try:
        candidate_metadata = candidate.lstat()
    except OSError as exc:
        raise PasswordUpdateError(
            f"libxcrypt 路径不可读取：{candidate}"
        ) from exc
    if (
        not stat.S_ISREG(candidate_metadata.st_mode)
        or candidate_metadata.st_nlink != 1
    ):
        raise PasswordUpdateError(
            "Homebrew libxcrypt 必须是 single-link regular file，不能是 symlink"
        )
    try:
        resolved_cellar = cellar_root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_cellar)
        metadata = resolved.stat()
    except (OSError, ValueError) as exc:
        raise PasswordUpdateError(
            "Homebrew libxcrypt 必须解析到受信的 Cellar/libxcrypt 目录"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        raise PasswordUpdateError(
            "Homebrew libxcrypt 必须是非空 single-link regular file"
        )
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PasswordUpdateError(
            "Homebrew libxcrypt 权限不安全：不能允许 group/other writable"
        )
    return resolved


def _homebrew_libxcrypt_path() -> Path | None:
    """Resolve the fixed Homebrew libxcrypt dylib on macOS without env lookup."""
    if platform.system() != "Darwin":
        return None
    for candidate, cellar_root in HOMEBREW_LIBXCRYPT_CANDIDATES:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PasswordUpdateError(
                f"libxcrypt 路径不可读取：{candidate}"
            ) from exc
        return _validate_libxcrypt_candidate(candidate, cellar_root)
    return None


def _load_libxcrypt(path: Path):
    """Load only the already-validated dylib and bind reentrant crypt APIs."""
    try:
        library = ctypes.CDLL(
            str(path), mode=getattr(ctypes, "RTLD_LOCAL", 0), use_errno=True,
        )
        library.crypt_gensalt_rn.argtypes = (
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        )
        library.crypt_gensalt_rn.restype = ctypes.c_char_p
        library.crypt_rn.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        library.crypt_rn.restype = ctypes.c_char_p
    except (AttributeError, OSError) as exc:
        raise PasswordUpdateError(
            "Homebrew libxcrypt 缺少 crypt_gensalt_rn/crypt_rn 能力"
        ) from exc
    return library


def _validate_backend_hash(output: object, method: str, backend: str) -> str:
    methods = {
        "sha-512": ("$6$", "SHA-512 crypt"),
        "yescrypt": ("$y$", "yescrypt"),
    }
    prefix, label = methods[method]
    if (
        not isinstance(output, str)
        or not output.startswith(prefix)
        or "\n" in output
        or "\r" in output
        or len(output) < len(prefix) + 8
        or len(output) > 512
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in output)
        or output.count("$") < 3
    ):
        raise PasswordUpdateError(
            f"{backend} 返回了无效的 {label} 密码哈希"
        )
    return output


def _hash_password_mkpasswd(password: str, method: str, executable: str) -> str:
    """Hash via whois/mkpasswd while keeping the secret out of argv."""
    label = {
        "sha-512": "SHA-512 crypt",
        "yescrypt": "yescrypt",
    }[method]
    command = [
        executable,
        f"--method={method}",
        "--password-fd=0",
    ]
    environment = os.environ.copy()
    environment.pop("MKPASSWD_OPTIONS", None)
    try:
        completed = subprocess.run(
            command,
            input=password + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PasswordUpdateError(
            f"mkpasswd 无法生成 {label} 密码哈希"
        ) from exc
    if completed.returncode != 0:
        raise PasswordUpdateError(
            f"mkpasswd 不支持或无法生成 {label} 密码哈希；"
            "请确认安装的是 whois 包提供的 mkpasswd"
        )
    return _validate_backend_hash(completed.stdout.strip(), method, "mkpasswd")


def _hash_password_libxcrypt(password: str, method: str, path: Path) -> str:
    """Hash and verify via Homebrew libxcrypt reentrant APIs on macOS."""
    prefixes = {"sha-512": b"$6$", "yescrypt": b"$y$"}
    try:
        password_bytes = password.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PasswordUpdateError("密码必须是可打印 ASCII 字符") from exc
    if b"\x00" in password_bytes:
        raise PasswordUpdateError("密码不能包含 NUL 字符")

    library = _load_libxcrypt(path)
    password_buffer = ctypes.create_string_buffer(password_bytes)
    entropy_buffer = ctypes.create_string_buffer(
        secrets.token_bytes(LIBXCRYPT_RANDOM_SIZE), LIBXCRYPT_RANDOM_SIZE,
    )
    salt_buffer = ctypes.create_string_buffer(LIBXCRYPT_SALT_BUFFER_SIZE)
    hash_workspace = ctypes.create_string_buffer(LIBXCRYPT_WORKSPACE_SIZE)
    verify_workspace = ctypes.create_string_buffer(LIBXCRYPT_WORKSPACE_SIZE)
    try:
        setting = library.crypt_gensalt_rn(
            prefixes[method],
            0,
            entropy_buffer,
            LIBXCRYPT_RANDOM_SIZE,
            salt_buffer,
            LIBXCRYPT_SALT_BUFFER_SIZE,
        )
        if not setting:
            raise PasswordUpdateError(
                f"Homebrew libxcrypt 无法生成 {method} 随机盐"
            )
        generated = library.crypt_rn(
            password_buffer,
            setting,
            hash_workspace,
            LIBXCRYPT_WORKSPACE_SIZE,
        )
        if not generated:
            raise PasswordUpdateError(
                f"Homebrew libxcrypt 无法生成 {method} 密码哈希"
            )
        try:
            output = bytes(generated).decode("ascii")
        except (UnicodeDecodeError, TypeError) as exc:
            raise PasswordUpdateError(
                "Homebrew libxcrypt 返回了非 ASCII 密码哈希"
            ) from exc
        output = _validate_backend_hash(output, method, "Homebrew libxcrypt")

        verified = library.crypt_rn(
            password_buffer,
            output.encode("ascii"),
            verify_workspace,
            LIBXCRYPT_WORKSPACE_SIZE,
        )
        try:
            verified_output = bytes(verified).decode("ascii") if verified else ""
        except (UnicodeDecodeError, TypeError):
            verified_output = ""
        if not hmac.compare_digest(verified_output, output):
            raise PasswordUpdateError(
                "Homebrew libxcrypt 生成结果的反向校验失败"
            )
        return output
    finally:
        for buffer in (
            password_buffer,
            entropy_buffer,
            salt_buffer,
            hash_workspace,
            verify_workspace,
        ):
            ctypes.memset(buffer, 0, ctypes.sizeof(buffer))


def _missing_hash_backend_error() -> PasswordUpdateError:
    return PasswordUpdateError(
        "未找到可用密码哈希后端：Ubuntu 24.04 请安装 whois 包提供的 "
        "mkpasswd；macOS 请运行 brew install libxcrypt"
    )


def hash_password(password: str, method: str) -> str:
    """Hash with preferred mkpasswd or the fixed macOS Homebrew libxcrypt."""
    if method not in {"sha-512", "yescrypt"}:
        raise PasswordUpdateError(f"不支持的密码哈希算法: {method}")
    executable = _mkpasswd_executable()
    if executable:
        return _hash_password_mkpasswd(password, method, executable)
    library_path = _homebrew_libxcrypt_path()
    if library_path is None:
        raise _missing_hash_backend_error()
    return _hash_password_libxcrypt(password, method, library_path)


def validate_hash_backend(sections: Iterable[str]) -> str:
    """Prove all selected methods before reading an operator secret."""
    selected = _selected_sections(sections)
    executable = _mkpasswd_executable()
    library_path = None if executable else _homebrew_libxcrypt_path()
    if executable is None and library_path is None:
        raise _missing_hash_backend_error()
    methods = tuple(dict.fromkeys(HASH_METHODS[section][0] for section in selected))
    for method in methods:
        # This fixed public value is only a capability probe. It verifies the
        # backend without touching an operator password or printing any hash.
        hash_password("http-mkpasswd-capability-probe", method)
    return executable if executable is not None else str(library_path)


def _read_regular_snapshot(path: Path) -> FileSnapshot:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PasswordUpdateError(
            f"{path} 必须是存在的 regular file，不能是 symlink"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or metadata.st_nlink != 1
            or path_metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise PasswordUpdateError(
                f"{path} 必须是 single-link regular file，不能是 symlink"
            )
        if metadata.st_size > MAX_GLOBAL_SIZE:
            raise PasswordUpdateError(
                f"{path} 超过 {MAX_GLOBAL_SIZE} bytes，拒绝作为 global YAML"
            )
        chunks: list[bytes] = []
        remaining = MAX_GLOBAL_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > MAX_GLOBAL_SIZE:
            raise PasswordUpdateError(
                f"{path} 超过 {MAX_GLOBAL_SIZE} bytes，拒绝作为 global YAML"
            )
    finally:
        os.close(descriptor)
    return FileSnapshot(
        data=data,
        metadata=metadata,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _assert_unchanged(path: Path, expected: FileSnapshot) -> None:
    current = _read_regular_snapshot(path)
    if (
        (current.metadata.st_dev, current.metadata.st_ino)
        != (expected.metadata.st_dev, expected.metadata.st_ino)
        or current.sha256 != expected.sha256
        or current.data != expected.data
    ):
        raise PasswordUpdateError(
            "01-global.yaml 在生成密码哈希期间已被其他进程修改，拒绝覆盖"
        )


def _atomic_replace(path: Path, expected: FileSnapshot, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), stat.S_IMODE(expected.metadata.st_mode))
                if (
                    expected.metadata.st_uid != os.geteuid()
                    or expected.metadata.st_gid != os.getegid()
                ):
                    try:
                        os.fchown(
                            handle.fileno(),
                            expected.metadata.st_uid,
                            expected.metadata.st_gid,
                        )
                    except PermissionError as exc:
                        raise PasswordUpdateError(
                            "无法保留 01-global.yaml 的 owner/group，拒绝替换"
                        ) from exc
        except BaseException:
            if temporary.exists():
                temporary.unlink()
            raise

        _assert_unchanged(path, expected)
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def update_global_file(
    path: Path, hashes: dict[str, str], *, sections: Iterable[str], dry_run: bool,
) -> UpdateResult:
    """Preview or atomically update one validated global file."""
    path = Path(path)
    selected = _selected_sections(sections)
    snapshot = _read_regular_snapshot(path)
    try:
        source = snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PasswordUpdateError("01-global.yaml 必须是 UTF-8") from exc
    rendered = rewrite_global_passwords(source, hashes, sections=selected)
    output = rendered.encode("utf-8")
    after_sha256 = hashlib.sha256(output).hexdigest()
    if not dry_run:
        _atomic_replace(path, snapshot, output)
        committed = _read_regular_snapshot(path)
        if committed.sha256 != after_sha256 or committed.data != output:
            raise PasswordUpdateError("01-global.yaml 原子写入后的 SHA-256 校验失败")
    return UpdateResult(
        path=path,
        sections=selected,
        before_sha256=snapshot.sha256,
        after_sha256=after_sha256,
        changed=snapshot.data != output,
        dry_run=dry_run,
    )


def resolve_global_file(
    value: str, *, root: Path = ROOT, day0: Path = DAY0,
) -> Path:
    """Resolve a project name/path to a safe, regular 01-global.yaml."""
    root = Path(root).resolve(strict=True)
    day0 = Path(day0).resolve(strict=True)
    raw = Path(value).expanduser()
    if raw.is_absolute():
        candidate = raw
    else:
        direct = root / raw
        candidate = direct if direct.is_dir() else day0 / raw
    try:
        project = candidate.resolve(strict=True)
        project.relative_to(day0)
    except (OSError, ValueError) as exc:
        raise PasswordUpdateError(
            f"项目必须位于 {day0} (DAY0-Prepare) 下: {candidate}"
        ) from exc
    if project == day0 or project.name == "template" or not project.is_dir():
        raise PasswordUpdateError(f"不是可更新的 DAY0 项目目录: {project}")
    devices = project / DEVICES_FILENAME
    try:
        devices_metadata = devices.lstat()
    except OSError as exc:
        raise PasswordUpdateError(f"项目缺少 {DEVICES_FILENAME}: {project}") from exc
    if not stat.S_ISREG(devices_metadata.st_mode):
        raise PasswordUpdateError(f"{devices} 必须是 regular file")
    global_file = project / GLOBAL_FILENAME
    _read_regular_snapshot(global_file)
    return global_file


def _prompt_password(
    label: str, *, account_names: Iterable[str], reader=getpass.getpass,
) -> str:
    password = reader(f"{label} 新密码: ")
    validate_plaintext_password(password, account_names=account_names)
    confirmation = reader(f"再次输入 {label} 新密码: ")
    if not hmac.compare_digest(password, confirmation):
        raise PasswordUpdateError(f"两次输入的 {label} 密码不一致")
    return password


def _passwords_for_sections(
    sections: tuple[str, ...], *, same_password: bool,
    reader=getpass.getpass,
) -> dict[str, str]:
    if same_password:
        if len(sections) < 2:
            raise PasswordUpdateError("--same-password 只能用于同时选择多个系统")
        account_names = []
        if "eth" in sections:
            account_names.append("cumulus")
        if {"ib", "nvl"} & set(sections):
            account_names.append("admin")
        password = _prompt_password(
            "所选系统共用", account_names=account_names, reader=reader,
        )
        return {section: password for section in sections}

    labels = {
        "eth": "Cumulus (eth / SHA-512 crypt)",
        "ib": "NVOS IB (ib / yescrypt)",
        "nvl": "NVOS NVLink (nvl / yescrypt)",
    }
    accounts = {"eth": ("cumulus",), "ib": ("admin",), "nvl": ("admin",)}
    result: dict[str, str] = {}
    for section in sections:
        result[section] = _prompt_password(
            labels[section], account_names=accounts[section], reader=reader,
        )
    return result


def _hashes_for_sections(
    sections: tuple[str, ...], passwords: dict[str, str],
) -> dict[str, str]:
    # IB and NVLink intentionally receive independent salts even when they use
    # the same plaintext password.
    return {
        section: hash_password(passwords[section], HASH_METHODS[section][0])
        for section in sections
    }


def rotate_project_passwords(
    project: str | Path,
    *,
    platform: str = "all",
    same_password: bool = False,
    dry_run: bool = False,
    root: Path = ROOT,
    day0: Path = DAY0,
    lock_already_held: bool = False,
    reader=None,
) -> UpdateResult:
    """Prompt, hash, and update one project for the CLI or the load workflow."""
    global_file = resolve_global_file(str(project), root=root, day0=day0)
    sections = _sections_from_platform(platform)
    # Reject missing fields, duplicate keys, aliases, or incompatible NVOS
    # hardening before asking the operator to disclose any password.
    preflight = _read_regular_snapshot(global_file)
    try:
        preflight_text = preflight.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PasswordUpdateError("01-global.yaml 必须是 UTF-8") from exc
    locate_password_targets(preflight_text, sections=sections)
    validate_hash_backend(sections)
    password_reader = reader if reader is not None else getpass.getpass
    passwords = _passwords_for_sections(
        sections, same_password=same_password, reader=password_reader,
    )
    try:
        hashes = _hashes_for_sections(sections, passwords)
    finally:
        passwords.clear()
    try:
        if lock_already_held:
            return update_global_file(
                global_file, hashes, sections=sections, dry_run=dry_run,
            )
        with deployment_lock(root, dry_run=dry_run):
            if not dry_run:
                stop_native_ztp_monitors(Path(root))
            return update_global_file(
                global_file, hashes, sections=sections, dry_run=dry_run,
            )
    finally:
        hashes.clear()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "交互式生成 Cumulus SHA-512 crypt 与 NVOS yescrypt 密码哈希，"
            "并原子更新项目 01-global.yaml"
        ),
    )
    parser.add_argument(
        "project",
        help="DAY0-Prepare 下的项目名，或项目目录路径",
    )
    parser.add_argument(
        "--platform",
        choices=("all", "cumulus", "ib", "nvl", "nvos"),
        default="all",
        help=(
            "更新范围；默认 all，分别提示 Cumulus、NVOS IB、NVOS NVLink "
            "三套密码；nvos 同时选择 IB 和 NVLink"
        ),
    )
    parser.add_argument(
        "--same-password",
        action="store_true",
        help="为所选多个系统只提示一次，并使用同一个明文密码",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="完成输入、哈希与 YAML 校验，但不写文件",
    )
    return parser.parse_args(argv)


def _sections_from_platform(platform: str) -> tuple[str, ...]:
    selections = {
        "all": SECTION_ORDER,
        "cumulus": ("eth",),
        "ib": ("ib",),
        "nvl": ("nvl",),
        "nvos": ("ib", "nvl"),
    }
    try:
        return selections[platform]
    except KeyError as exc:
        raise PasswordUpdateError(f"未知平台: {platform}") from exc


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = rotate_project_passwords(
            args.project,
            platform=args.platform,
            same_password=args.same_password,
            dry_run=args.dry_run,
        )
    except (PasswordUpdateError, DeploymentLockError, RuntimeContractError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\n[ERROR] 密码更新已取消", file=sys.stderr)
        return 130

    algorithms = ", ".join(
        f"{section}={HASH_METHODS[section][2]}" for section in result.sections
    )
    prefix = "[DRY-RUN] 校验通过，未写入" if result.dry_run else "[OK] 已原子更新"
    print(f"{prefix}: {result.path}")
    print(f"[INFO] algorithms: {algorithms}")
    print(f"[INFO] before SHA-256: {result.before_sha256}")
    print(f"[INFO] after SHA-256:  {result.after_sha256}")
    if not result.dry_run:
        print("[NEXT] global 已变化；同步时必须显式选择 runtime，并按同一后端重新发布：")
        print(
            "[NEXT] Native/systemd：先用 sync-code.py --runtime native，同步成功后执行 "
            "DAY0-Prepare/11-load.py"
        )
        print(
            "[NEXT] Docker/Supervisor：先用 sync-code.py --runtime docker；source write 后"
            "执行 infra/docker/deploy.sh deploy，或对匹配 live 来源身份链的已验证镜像执行 "
            "deploy-preloaded <IMAGE_ID>；source write 后不得执行 load"
        )
        print(
            "[NEXT] 重新发布只会生成并提交新配置；既有设备仍需显式执行 "
            "manual ZTP/重新部署，密码变更才会下发"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
