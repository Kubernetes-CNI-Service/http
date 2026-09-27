"""Bounded, read-only Switch Status preview from one info archive.

This module intentionally does not grant collection-cycle authority, K-window
qualification, operation IDs, workbook eligibility, or a durable receipt. The
caller must later prove the exact selected hosts and archive role from one
governed worker completion; an arbitrary caller-supplied tuple is not enough.
"""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import tarfile


class SwitchInfoHoldError(ValueError):
    """The archive cannot be interpreted as complete Switch Status evidence."""


@dataclass(frozen=True)
class SwitchAbnormalValue:
    """Literal telemetry behind one abnormal key; never an issue decision."""

    hostname: str
    category: str
    component_or_sensor: str
    state: str
    current_c: float | None = None
    maximum_c: float | None = None
    critical_c: float | None = None

    @property
    def evidence_description(self) -> str:
        if self.current_c is None:
            return f"{self.component_or_sensor}: state={self.state}"
        return (f"{self.component_or_sensor}: state={self.state}; "
                f"current={self.current_c:g} C; max={self.maximum_c:g} C; "
                f"critical={self.critical_c:g} C")


@dataclass(frozen=True)
class SwitchInfoPreview:
    source_slot: str
    selected_hosts: tuple[str, ...]
    archive_sha256: str
    abnormal_keys: tuple[tuple[str, str, str], ...]
    abnormal_values: tuple[SwitchAbnormalValue, ...]
    not_applicable_by_host: tuple[tuple[str, tuple[str, ...]], ...] = ()
    qualified: bool = False


@dataclass(frozen=True)
class SwitchSourceRow:
    """One observed abnormality; a row source, not publication eligibility."""

    source_slot: str
    hostname: str
    category: str
    component_or_sensor: str
    archive_sha256: str
    value: SwitchAbnormalValue
    qualified: bool = False


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SECTION = re.compile(
    r"#{4,}\r?\n# Execute Command: ([^\r\n]+)\r?\n#{4,}\r?\n"
)
_ASIC = re.compile(r"\bASIC", re.IGNORECASE)
_PSU = re.compile(r"\bPSU(?:\d+)?(?:[-_/ ]|$)", re.IGNORECASE)
_DEFAULT_ARCHIVE_LIMIT = 8 * 1024 * 1024
_DEFAULT_MEMBER_LIMIT = 1024 * 1024
_MAX_EXPANDED_LIMIT = 64 * 1024 * 1024


def _positive_bound(value: int, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SwitchInfoHoldError(f"{name} must be a positive integer")
    return value


def _exact_archive_bytes(path: Path, *, expected_sha256: str,
                         expected_size_bytes: int, maximum: int) -> bytes:
    if not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256):
        raise SwitchInfoHoldError("archive digest is invalid")
    _positive_bound(expected_size_bytes, name="archive size")
    if expected_size_bytes > maximum:
        raise SwitchInfoHoldError("archive exceeds byte limit")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size_bytes:
                raise SwitchInfoHoldError("archive is not the bound regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise SwitchInfoHoldError("archive is unreadable") from exc
    if (len(raw) != expected_size_bytes or len(raw) > maximum
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise SwitchInfoHoldError("archive changed or disagrees with role digest")
    return raw


def _tar_members(raw: bytes, *, stamp: str, selected: tuple[str, ...],
                 max_member_bytes: int) -> dict[str, bytes]:
    # Exhaust gzip first so a truncated footer or CRC mismatch cannot become
    # a seemingly complete tar. Bound expanded bytes before tar parsing.
    limit = min(_MAX_EXPANDED_LIMIT,
                max_member_bytes * len(selected) + 1024 * 1024)
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
            expanded = gz.read(limit + 1)
        if len(expanded) > limit:
            raise SwitchInfoHoldError("expanded archive exceeds byte limit")
        with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as bundle:
            members = bundle.getmembers()
            if len(members) > len(selected) + 2:
                raise SwitchInfoHoldError("archive has unexpected members")
            content: dict[str, bytes] = {}
            seen: set[str] = set()
            directory_seen = False
            for member in members:
                name = member.name
                if name == stamp and member.isdir() and not directory_seen:
                    directory_seen = True
                    continue
                if name == stamp + "/" and member.isdir() and not directory_seen:
                    directory_seen = True
                    continue
                if not member.isfile() or not name.startswith(stamp + "/"):
                    raise SwitchInfoHoldError("archive has nonregular or foreign member")
                basename = name[len(stamp) + 1:]
                if (not basename or "/" in basename or basename in {".", ".."}
                        or basename.casefold() in seen):
                    raise SwitchInfoHoldError("archive member path is ambiguous")
                seen.add(basename.casefold())
                if basename != "collection.json" and not basename.endswith(".info"):
                    raise SwitchInfoHoldError("archive contains unrelated member")
                if member.size < 0 or member.size > max_member_bytes:
                    raise SwitchInfoHoldError("archive member exceeds byte limit")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise SwitchInfoHoldError("archive member is unreadable")
                body = stream.read(max_member_bytes + 1)
                if len(body) != member.size:
                    raise SwitchInfoHoldError("archive member is truncated")
                content[basename] = body
    except SwitchInfoHoldError:
        raise
    except (OSError, EOFError, UnicodeError, ValueError, tarfile.TarError) as exc:
        raise SwitchInfoHoldError("archive gzip or tar is incomplete") from exc
    required = {"collection.json"} | {host + ".info" for host in selected}
    if not directory_seen or set(content) != required:
        raise SwitchInfoHoldError("archive selected host set is incomplete or changed")
    return content


def _sections(text: str) -> dict[str, str]:
    parts = _SECTION.split(text)
    sections: dict[str, str] = {}
    for index in range(1, len(parts), 2):
        name = parts[index].strip()
        if name in sections:
            raise SwitchInfoHoldError("duplicate info command section")
        sections[name] = parts[index + 1]
    required = {
        "nv show platform inventory",
        "nv show platform environment temperature",
    }
    if not required.issubset(sections):
        raise SwitchInfoHoldError("Switch Status telemetry section is missing")
    return sections


def _inventory(host: str, text: str, *, nvl: bool = False) -> dict[tuple[str, str, str], SwitchAbnormalValue]:
    lines = text.splitlines()
    start = next((index for index, line in enumerate(lines)
                  if (re.search(r"\bComponent\b.*\bState\s+Type\b", line)
                      or line.split() == ["HW", "Version", "Model", "Serial",
                                          "State", "Type"])), None)
    if start is None:
        raise SwitchInfoHoldError("inventory header is missing")
    unnamed = lines[start].split() == ["HW", "Version", "Model", "Serial",
                                       "State", "Type"]
    if unnamed and (start + 1 >= len(lines)
                    or len(lines[start + 1].split()) != 6
                    or any(not re.fullmatch(r"-+", part)
                           for part in lines[start + 1].split())):
        raise SwitchInfoHoldError("unnamed inventory separator is invalid")
    seen: set[tuple[str, str]] = set()
    abnormal: dict[tuple[str, str, str], SwitchAbnormalValue] = {}
    types: set[str] = set()
    nvl_components: set[str] = set()
    for line in lines[start + 1:]:
        if not line.strip() or re.fullmatch(r"[-\s]+", line):
            continue
        fields = line.split()
        if len(fields) < 6 or (unnamed and len(fields) != 6):
            raise SwitchInfoHoldError("inventory row is malformed")
        component, state_value, kind = fields[0], fields[-2].casefold(), fields[-1].casefold()
        if nvl and kind in {"bmc", "switch"}:
            nvl_components.add(kind)
        if kind not in {"psu", "fan"}:
            continue
        if state_value not in {"ok", "fail"}:
            raise SwitchInfoHoldError("inventory component state is unknown")
        key = (kind, component.casefold())
        if key in seen:
            raise SwitchInfoHoldError("inventory component is duplicated")
        seen.add(key)
        types.add(kind)
        if state_value == "fail":
            abnormal[(host, kind, component)] = SwitchAbnormalValue(
                hostname=host, category=kind, component_or_sensor=component,
                state=state_value,
            )
    if nvl and types:
        raise SwitchInfoHoldError("NVLink PSU/FAN contradict not-applicable hardware")
    if nvl and nvl_components != {"bmc", "switch"}:
        raise SwitchInfoHoldError("NVLink inventory is incomplete")
    if not nvl and types != {"psu", "fan"}:
        raise SwitchInfoHoldError("PSU/FAN inventory is incomplete")
    return abnormal


def _number(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise SwitchInfoHoldError("temperature is not numeric") from exc
    if not math.isfinite(result) or abs(result) > 1_000_000:
        raise SwitchInfoHoldError("temperature is not finite or bounded")
    return result


def _temperature(host: str, text: str, *, nvl: bool = False) -> dict[tuple[str, str, str], SwitchAbnormalValue]:
    lines = text.splitlines()
    start = next((index for index, line in enumerate(lines)
                  if "Cur Temp" in line and "State" in line), None)
    if start is None:
        raise SwitchInfoHoldError("temperature header is missing")
    abnormal: dict[tuple[str, str, str], SwitchAbnormalValue] = {}
    seen: set[tuple[str, str]] = set()
    kinds: set[str] = set()
    for line in lines[start + 1:]:
        if not line.strip() or re.fullmatch(r"[-\s]+", line):
            continue
        fields = re.split(r"\s{2,}", line.strip())
        if len(fields) < 6:
            raise SwitchInfoHoldError("temperature row is malformed")
        name = fields[0]
        kind = "asic_temp" if _ASIC.search(name) else (
            "psu_temp" if _PSU.search(name) else None)
        if kind is None:
            continue
        current, critical, maximum = map(_number, fields[1:4])
        state_value = fields[5].casefold()
        if state_value not in {"ok", "normal", "alarm", "critical", "fail"}:
            raise SwitchInfoHoldError("temperature sensor state is unknown")
        if critical < maximum:
            raise SwitchInfoHoldError("temperature thresholds are inconsistent")
        key = (kind, name.casefold())
        if key in seen:
            raise SwitchInfoHoldError("temperature sensor is duplicated")
        seen.add(key)
        kinds.add(kind)
        if state_value not in {"ok", "normal"} or current >= maximum:
            abnormal[(host, kind, name)] = SwitchAbnormalValue(
                hostname=host, category=kind, component_or_sensor=name,
                state=state_value, current_c=current,
                maximum_c=maximum, critical_c=critical,
            )
    if nvl and kinds != {"asic_temp"}:
        raise SwitchInfoHoldError("NVLink ASIC or not-applicable temperature is invalid")
    if not nvl and kinds != {"asic_temp", "psu_temp"}:
        raise SwitchInfoHoldError("ASIC/PSU temperature telemetry is incomplete")
    return abnormal


def _host_info(host: str, body: bytes, *, source_slot: str) -> dict[tuple[str, str, str], SwitchAbnormalValue]:
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise SwitchInfoHoldError("info is not UTF-8") from exc
    device = re.search(r"(?m)^Device:\s*(\S+)\s*$", text)
    switch_type = re.search(r"(?m)^Switch Type:\s*(\w+)\b", text)
    expected_type = "NVLINK" if source_slot == "nvlink/prod" else "ETH"
    if (device is None or device.group(1) != host or switch_type is None
            or switch_type.group(1) != expected_type):
        raise SwitchInfoHoldError("info host or switch type disagrees with selection")
    sections = _sections(text)
    nvl = source_slot == "nvlink/prod"
    inventory = _inventory(host, sections["nv show platform inventory"], nvl=nvl)
    temperature = _temperature(
        host, sections["nv show platform environment temperature"], nvl=nvl,
    )
    if inventory.keys() & temperature.keys():
        raise SwitchInfoHoldError("abnormal telemetry key is ambiguous")
    return inventory | temperature


def read_switch_info_preview(
    archive_path: Path | str, *, expected_sha256: str,
    expected_size_bytes: int, source_slot: str,
    selected_hosts: tuple[str, ...],
    max_archive_bytes: int = _DEFAULT_ARCHIVE_LIMIT,
    max_member_bytes: int = _DEFAULT_MEMBER_LIMIT,
) -> SwitchInfoPreview:
    """Return a non-qualifying preview or HOLD on any incomplete evidence."""
    if source_slot not in {"ethernet/air", "ethernet/prod", "nvlink/prod"}:
        raise SwitchInfoHoldError("Switch preview source slot is unsupported")
    if (not isinstance(selected_hosts, tuple) or not selected_hosts
            or len(selected_hosts) > 256
            or any(not isinstance(host, str) or not _HOST.fullmatch(host)
                   for host in selected_hosts)
            or len({host.casefold() for host in selected_hosts}) != len(selected_hosts)):
        raise SwitchInfoHoldError("selected host set is invalid")
    archive_limit = _positive_bound(max_archive_bytes, name="archive byte limit")
    member_limit = _positive_bound(max_member_bytes, name="member byte limit")
    path = Path(archive_path)
    stamp = path.name.removesuffix(".tar.gz")
    expected_stamp = (r"[0-9]{8}-[0-9]{4}"
                      if source_slot == "nvlink/prod" else
                      r"[0-9]{8}-[0-9]{4}-" + source_slot.split("/", 1)[1])
    if (not path.name.endswith(".tar.gz")
            or not re.fullmatch(expected_stamp, stamp)):
        raise SwitchInfoHoldError("archive name is not the selected slot shape")
    raw = _exact_archive_bytes(path, expected_sha256=expected_sha256,
                               expected_size_bytes=expected_size_bytes,
                               maximum=archive_limit)
    content = _tar_members(raw, stamp=stamp, selected=selected_hosts,
                           max_member_bytes=member_limit)
    try:
        metadata = json.loads(content["collection.json"])
    except (ValueError, UnicodeError) as exc:
        raise SwitchInfoHoldError("collection metadata is malformed") from exc
    if (not isinstance(metadata, dict) or set(metadata) != {
        "schema_version", "environment", "collector", "collected_at", "device_count"
    } or metadata["schema_version"] != 1
            or metadata["environment"] != source_slot.split("/", 1)[1]
            or metadata["collector"] != "cron.sh"
            or not isinstance(metadata["collected_at"], str)
            or not metadata["collected_at"]
            or isinstance(metadata["device_count"], bool)
            or metadata["device_count"] != len(selected_hosts)):
        raise SwitchInfoHoldError("collection metadata disagrees with selection")
    abnormal: dict[tuple[str, str, str], SwitchAbnormalValue] = {}
    for host in selected_hosts:
        abnormal.update(_host_info(host, content[host + ".info"],
                                   source_slot=source_slot))
    return SwitchInfoPreview(
        source_slot=source_slot, selected_hosts=selected_hosts,
        archive_sha256=expected_sha256,
        abnormal_keys=tuple(sorted(abnormal)),
        abnormal_values=tuple(abnormal[key] for key in sorted(abnormal)),
        not_applicable_by_host=(
            tuple((host, ("fan", "psu")) for host in selected_hosts)
            if source_slot == "nvlink/prod" else ()
        ),
    )


def map_switch_source_rows(preview: SwitchInfoPreview) -> tuple[SwitchSourceRow, ...]:
    """Map bounded observations to typed inputs without granting eligibility."""
    if (type(preview) is not SwitchInfoPreview or preview.qualified is not False
            or preview.source_slot not in {"ethernet/air", "ethernet/prod", "nvlink/prod"}
            or not isinstance(preview.archive_sha256, str)
            or not _SHA.fullmatch(preview.archive_sha256)):
        raise SwitchInfoHoldError("source preview cannot grant row eligibility")
    if preview.source_slot == "nvlink/prod":
        if preview.not_applicable_by_host != tuple(
            (host, ("fan", "psu")) for host in preview.selected_hosts
        ):
            raise SwitchInfoHoldError("NVLink not-applicable state is incomplete")
    elif preview.not_applicable_by_host:
        raise SwitchInfoHoldError("non-NVLink source claimed not-applicable state")
    if (not isinstance(preview.selected_hosts, tuple)
            or len(preview.selected_hosts) > 256
            or any(not isinstance(host, str) or not _HOST.fullmatch(host)
                   for host in preview.selected_hosts)
            or len({host.casefold() for host in preview.selected_hosts})
            != len(preview.selected_hosts)):
        raise SwitchInfoHoldError("selected source hosts are invalid")
    selected = set(preview.selected_hosts)
    allowed_kinds = ({"asic_temp"} if preview.source_slot == "nvlink/prod"
                     else {"psu", "fan", "asic_temp", "psu_temp"})
    if (not isinstance(preview.abnormal_keys, tuple)
            or not isinstance(preview.abnormal_values, tuple)
            or len(preview.abnormal_keys) != len(preview.abnormal_values)
            or len(preview.abnormal_keys) > 256 * 1024):
        raise SwitchInfoHoldError("abnormal value witness is missing or unbounded")
    if (len(set(preview.abnormal_keys)) != len(preview.abnormal_keys)
            or any(host not in selected or kind not in allowed_kinds
                   or not isinstance(name, str) or not name or len(name) > 128
                   or not name.isprintable()
                   for host, kind, name in preview.abnormal_keys)):
        raise SwitchInfoHoldError("abnormality contradicts selected hardware")
    for key, value in zip(preview.abnormal_keys, preview.abnormal_values):
        if (type(value) is not SwitchAbnormalValue
                or (value.hostname, value.category, value.component_or_sensor) != key):
            raise SwitchInfoHoldError("abnormal value disagrees with source key")
        if value.category in {"psu", "fan"}:
            if (value.state != "fail" or value.current_c is not None
                    or value.maximum_c is not None or value.critical_c is not None):
                raise SwitchInfoHoldError("component abnormal value is invalid")
        else:
            values = (value.current_c, value.maximum_c, value.critical_c)
            if (value.state not in {"ok", "normal", "alarm", "critical", "fail"}
                    or any(type(number) is not float or not math.isfinite(number)
                           or abs(number) > 1_000_000 for number in values)
                    or value.critical_c < value.maximum_c
                    or (value.state in {"ok", "normal"}
                        and value.current_c < value.maximum_c)):
                raise SwitchInfoHoldError("temperature abnormal value is invalid")
    return tuple(SwitchSourceRow(
        source_slot=preview.source_slot, hostname=host, category=kind,
        component_or_sensor=name, archive_sha256=preview.archive_sha256,
        value=value,
    ) for (host, kind, name), value in zip(
        preview.abnormal_keys, preview.abnormal_values,
    ))
