#!/usr/bin/env python3
"""Create the per-project inputs consumed by feedback.py comparisons."""

from __future__ import annotations

import os
from pathlib import Path
import re
import tarfile


LINK_NAMES = {
    "air_backup": "monitor-air-latest",
    "generated": "generated-latest",
    "generated_backup": "monitor-prod-latest",
    "config_air_backup": "config-backup-air-latest",
    "config_prod_backup": "config-backup-prod-latest",
    "global_config": "01-global.yaml",
    "devices_config": "02-devices_config.csv",
    # feedback.py writes below this managed link so comparison artifacts live
    # with the selected DAY0 project instead of in the shared source tree.
    "comparison_output": "comparison",
}

# Older single-source feedback runs wrote the generated comparison CSV next to
# the managed ``generated-latest`` link.  Project/sample comparisons now keep
# every derived value below ``comparison/<scope>/``; these exact two filenames
# are therefore managed stale outputs, not user inputs.
LEGACY_ROOT_OUTPUT_NAMES = (
    "generated-latest.csv",
    "generated-latest-global.yaml",
)


def sample_directory(optimize_dir, project_dir):
    return Path(optimize_dir) / f"{Path(project_dir).name}-sample"


def comparison_output_directory(project_dir):
    """Return the project-owned directory for feedback comparison outputs."""
    return Path(project_dir).resolve() / "99-output-ztp" / "optimize"


def ensure_comparison_output_directory(project_dir, dry_run=False, report=print):
    """Create the project-owned output directory without following symlinks."""
    target = comparison_output_directory(project_dir)
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise FileExistsError(f"comparison 输出位置不是普通目录: {target}")
    if dry_run:
        if not target.is_dir():
            report(f"[DRY] mkdir {target}")
    else:
        target.mkdir(parents=True, exist_ok=True)
    return target


def prepare_comparison_output(sample, project_dir, dry_run=False, report=print):
    """Migrate a legacy real comparison directory, then prepare its link target.

    Older feedback.py releases created ``<project>-sample/comparison`` as a
    real directory.  When the project-owned target does not yet contain data,
    move that directory atomically into ``99-output-ztp/optimize`` so no
    reports are lost.  If both locations contain data, fail closed instead of
    choosing one copy or overwriting either side.
    """
    sample = Path(sample)
    legacy = sample / LINK_NAMES["comparison_output"]
    target = comparison_output_directory(project_dir)
    if legacy.is_symlink() or not legacy.exists():
        return ensure_comparison_output_directory(
            project_dir, dry_run=dry_run, report=report,
        )
    if not legacy.is_dir():
        raise FileExistsError(f"comparison 链接位置不是目录: {legacy}")
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise FileExistsError(f"comparison 输出位置不是普通目录: {target}")

    legacy_has_data = any(legacy.iterdir())
    target_has_data = target.is_dir() and any(target.iterdir())
    if legacy_has_data and target_has_data:
        raise FileExistsError(
            f"旧 comparison 与项目输出目录均含数据，拒绝自动合并: "
            f"{legacy} ; {target}"
        )
    if dry_run:
        action = "迁移" if legacy_has_data else "移除空旧目录"
        report(f"[DRY] {action}: {legacy} -> {target}")
        return target

    if legacy_has_data:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_dir():
            target.rmdir()
        os.replace(legacy, target)
        report(f"[MIGRATE] {legacy} -> {target}")
    else:
        legacy.rmdir()
        ensure_comparison_output_directory(project_dir, report=report)
        report(f"[CLEAN] 移除空旧 comparison 目录: {legacy}")
    return target


def _source_stem(path):
    name = Path(path).name
    return name[:-len(".tar.gz")] if name.casefold().endswith(".tar.gz") else name


def _timestamp_key(path):
    """Return a sortable timestamp from either a directory or archive name."""
    match = re.match(r"^(\d{8})[-_](\d{4})(\d{2})?", _source_stem(path))
    return "" if not match else f"{match.group(1)}{match.group(2)}{match.group(3) or '00'}"


def _is_air_source(path):
    stem = _source_stem(path).casefold()
    return stem.endswith(("-air", "_air", "-air-backup", "_air-backup"))


def is_air_comparison_source(path):
    """Return whether a sample comparison input belongs to AIR.

    Sample links use names such as ``monitor-air-latest`` while their targets
    use timestamp suffixes such as ``20260823-2125-air.tar.gz``. Check both
    forms so inventory selection works before and after symlink resolution.
    """
    source = Path(path)
    stem = _source_stem(source).casefold()
    if (_is_air_source(source) or "-air-" in stem or "_air_" in stem
            or stem.startswith("air-")):
        return True
    try:
        resolved = source.resolve()
    except OSError:
        return False
    return resolved != source.absolute() and _is_air_source(resolved)


def _is_tar_source(path):
    path = Path(path)
    return path.is_file() and path.name.casefold().endswith(".tar.gz")


def _latest_source(paths):
    candidates = [Path(path) for path in paths if _timestamp_key(path)]
    return max(candidates, key=lambda path: (_timestamp_key(path), path.name),
               default=None)


def _inside(path, root):
    """Return whether a resolved source remains below its project output root."""
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False


def _tar_details(path):
    """Return member basenames, YAML presence and backup log text."""
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            basenames = {Path(member.name).name for member in members}
            has_yaml = any(
                not Path(member.name).name.startswith("._")
                and Path(member.name).suffix.casefold() in {".yaml", ".yml"}
                for member in members
            )
            log_member = next(
                (member for member in members
                 if Path(member.name).name == "backup.log" and member.size <= 10 * 1024 * 1024),
                None,
            )
            log_text = ""
            if log_member is not None:
                stream = archive.extractfile(log_member)
                if stream is not None:
                    log_text = stream.read().decode("utf-8", errors="replace")
            return basenames, has_yaml, log_text
    except (OSError, tarfile.TarError):
        return set(), False, ""


def latest_monitor_backups(project_dir):
    """Return newest AIR/production monitor sources (folder or tar.gz)."""
    root = Path(project_dir) / "99-output-monitor" / "ethernet" / "eth-info"
    candidates = {"air": [], "production": []}
    if not root.is_dir():
        return {"air": None, "production": None}
    for path in root.iterdir():
        if path.is_symlink():
            continue
        if path.name.startswith((".", "._")) or "daily" in path.name.casefold():
            continue
        if path.is_dir():
            valid = any(
                item.is_file() and item.suffix.casefold() in {".info", ".yaml", ".yml"}
                for item in path.rglob("*")
            )
        else:
            valid = _is_tar_source(path) and path.stat().st_size > 0
        if valid and _timestamp_key(path):
            candidates["air" if _is_air_source(path) else "production"].append(path)
    return {kind: _latest_source(paths) for kind, paths in candidates.items()}


def latest_generated(project_dir):
    output = Path(project_dir) / "99-output-eth"
    latest = output / "latest"
    if latest.exists() and latest.is_symlink():
        resolved = latest.resolve()
        if _inside(resolved, output) and _valid_generated_source(resolved):
            return resolved
    candidates = []
    if output.is_dir():
        for path in output.iterdir():
            if path.is_symlink():
                continue
            if re.fullmatch(r"\d{8}_\d{6}_combine(?:\.tar\.gz)?",
                            path.name, re.IGNORECASE) and _valid_generated_source(path):
                candidates.append(path)
    return _latest_source(candidates)


def _valid_generated_source(path):
    path = Path(path)
    if path.is_dir():
        return ((path / ".published-complete").is_file()
                and _contains_config_yaml(path))
    if _is_tar_source(path):
        basenames, has_yaml, _log = _tar_details(path)
        return has_yaml and ".published-complete" in basenames
    return False


def _contains_config_yaml(directory):
    """Return whether a collected backup contains at least one real YAML."""
    return any(
        path.is_file() and not path.name.startswith("._")
        for pattern in ("*.yaml", "*.yml")
        for path in Path(directory).rglob(pattern)
    )


def latest_config_backups(project_dir):
    """Return newest completed AIR and production configuration sources.

    Current ``*-backup`` runs are considered complete only after yaml-collect
    has written its three reports and the finish marker.  Legacy timestamp
    directories did not have those reports, so they remain eligible when they
    contain at least one YAML file. Sources may be folders or ``.tar.gz``.
    A name ending in ``-air``/``_air`` (before ``.tar.gz``) is AIR; every
    other valid source is production.
    """
    output = Path(project_dir) / "99-output-backup"
    if not output.is_dir():
        return {"air": None, "production": None}

    candidates = {"air": [], "production": []}
    for path in output.iterdir():
        if path.is_symlink():
            continue
        if path.name.startswith((".", "._")) or not _timestamp_key(path):
            continue
        if path.is_dir():
            has_yaml = _contains_config_yaml(path)
            basenames = {item.name for item in path.iterdir() if item.is_file()}
            try:
                log_text = (path / "backup.log").read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                log_text = ""
        elif _is_tar_source(path):
            basenames, has_yaml, log_text = _tar_details(path)
        else:
            continue
        if not has_yaml:
            continue
        if "-backup" in _source_stem(path).casefold():
            required = ("backup.log", "devices_config.csv", "diff.log")
            if (not all(name in basenames for name in required)
                    or "##### Finish backup #######" not in log_text):
                continue
        kind = "air" if _is_air_source(path) else "production"
        candidates[kind].append(path)
    return {
        kind: _latest_source(paths)
        for kind, paths in candidates.items()
    }


def latest_config_backup(project_dir, air=False):
    """Compatibility helper returning one side of latest_config_backups()."""
    return latest_config_backups(project_dir)["air" if air else "production"]


def sample_link_targets(project_dir):
    """Return fixed link-name -> newest valid target (or None)."""
    project = Path(project_dir).resolve()
    monitor_backups = latest_monitor_backups(project)
    config_backups = latest_config_backups(project)
    return {
        LINK_NAMES["air_backup"]: monitor_backups["air"],
        LINK_NAMES["generated"]: latest_generated(project),
        LINK_NAMES["generated_backup"]: monitor_backups["production"],
        LINK_NAMES["config_air_backup"]: config_backups["air"],
        LINK_NAMES["config_prod_backup"]: config_backups["production"],
        LINK_NAMES["global_config"]: (
            project / "01-global.yaml"
            if (project / "01-global.yaml").is_file() else None
        ),
        LINK_NAMES["devices_config"]: (
            project / "02-devices_config.csv"
            if (project / "02-devices_config.csv").is_file() else None
        ),
        LINK_NAMES["comparison_output"]: comparison_output_directory(project),
    }


def _replace_relative_link(link, target):
    link = Path(link)
    target = Path(target).resolve()
    link.parent.mkdir(parents=True, exist_ok=True)
    relative = os.path.relpath(target, link.parent.resolve())
    if link.is_symlink() and os.readlink(link) == relative:
        return "skipped"
    if link.exists() and not link.is_symlink():
        raise FileExistsError(f"链接位置是实际文件或目录: {link}")
    temporary = link.parent / f".{link.name}.tmp.{os.getpid()}"
    try:
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()
        temporary.symlink_to(relative)
        os.replace(temporary, link)
    finally:
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()
    return "linked"


def cleanup_legacy_root_outputs(sample, dry_run=False, report=print):
    """Remove obsolete generated CSVs from the sample root, fail-safe.

    Only the two historical regular-file outputs are managed.  A symlink,
    directory, or other unexpected node is left untouched so this cleanup can
    never follow or remove an operator-owned path.
    """
    sample = Path(sample)
    for name in LEGACY_ROOT_OUTPUT_NAMES:
        path = sample / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            report(f"[WARN] 保留非普通 legacy optimize 路径: {path}")
            continue
        if not path.is_file():
            continue
        if dry_run:
            report(f"[DRY] 删除 sample 根目录重复输出: {path}")
        else:
            path.unlink()
            report(f"[CLEAN] 删除 sample 根目录重复输出: {path}")


def update_sample_links(optimize_dir, project_dir, dry_run=False, report=print):
    """Refresh all available sample links and return the sample directory."""
    sample = sample_directory(optimize_dir, project_dir)
    prepare_comparison_output(
        sample, project_dir, dry_run=dry_run, report=report,
    )
    targets = sample_link_targets(project_dir)
    if dry_run:
        report(f"[DRY] mkdir {sample}")
    else:
        sample.mkdir(parents=True, exist_ok=True)
        managed_names = set(LINK_NAMES.values())
        for old in sample.iterdir():
            if old.is_symlink() and old.name not in managed_names:
                old.unlink()
                report(f"[CLEAN] 删除旧 sample 链接: {old}")
    cleanup_legacy_root_outputs(sample, dry_run=dry_run, report=report)
    for name, target in targets.items():
        link = sample / name
        if target is None:
            report(f"[WARN] {name}: 当前项目没有可用目标")
            if not dry_run and link.is_symlink():
                link.unlink()
                report(f"[CLEAN] 删除失效 sample 链接: {link}")
            continue
        if dry_run:
            report(f"[DRY] {link} -> {target}")
            continue
        result = _replace_relative_link(link, target)
        report(f"[{'LINK' if result == 'linked' else 'SKIP'}] {link} -> {target}")
    return sample


def project_from_sample_path(path, day0_prepare):
    """Resolve <project>-sample in path ancestry back to DAY0-Prepare/project."""
    current = Path(path).expanduser().absolute()
    if current.is_file() or current.is_symlink():
        current = current.parent
    for directory in (current, *current.parents):
        if directory.name.endswith("-sample"):
            project = Path(day0_prepare) / directory.name[:-len("-sample")]
            if project.is_dir():
                return project.resolve()
    return None
