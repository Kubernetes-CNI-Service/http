#!/usr/bin/env python3
"""Create the per-project inputs consumed by feedback.py comparisons."""

from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import stat
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


def _directory_flags():
    return (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )


def _directory_identity(value):
    """Stable directory authority, excluding child-dependent metadata."""
    return (
        value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode),
        stat.S_IMODE(value.st_mode), value.st_uid, value.st_gid,
    )


def _node_version(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _node_identity(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_uid, value.st_gid,
    )


class HeldSampleMutationPlan:
    """Bind Feedback's managed roots before changing any sample/output name.

    The workspace deployment lock supplies exclusion between cooperating
    processes.  This object supplies pathname authority: every existing
    component below that workspace is opened without following symlinks and
    retained until the complete Feedback invocation returns.  Missing managed
    children are created only relative to an already-held parent descriptor.
    """

    def __init__(self, optimize_dir, project_dir, workspace_root):
        self.workspace_root = Path(workspace_root).expanduser().absolute()
        self.optimize_dir = Path(optimize_dir).expanduser().absolute()
        self.project_dir = Path(project_dir).expanduser().absolute()
        self.sample = sample_directory(self.optimize_dir, self.project_dir).absolute()
        self.output = self.project_dir / "99-output-ztp" / "optimize"
        self._fds = set()
        self._anchors = []
        self._missing = []
        self._source_versions = []
        self._applied = False
        self._closed = False
        self._sample_fd = None
        self._output_root_fd = None
        self._output_fd = None
        self._legacy_fd = None
        self._output_subdirs = {}
        try:
            self._bind_initial_tree()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _unsafe():
        raise ValueError("unsafe held sample/output mutation authority")

    @staticmethod
    def _safe_directory(value):
        return (
            stat.S_ISDIR(value.st_mode)
            and value.st_uid == os.geteuid()
            and not (stat.S_IMODE(value.st_mode) & 0o022)
        )

    def _remember_fd(self, descriptor):
        self._fds.add(descriptor)
        return descriptor

    def _open_root(self, path):
        descriptor = None
        try:
            named = os.lstat(path)
            descriptor = os.open(path, _directory_flags())
            held = os.fstat(descriptor)
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            self._unsafe()
        if (
            _directory_identity(named) != _directory_identity(held)
            or not self._safe_directory(held)
        ):
            os.close(descriptor)
            self._unsafe()
        self._remember_fd(descriptor)
        self._root_identity = _directory_identity(held)
        return descriptor

    def _open_child(self, parent_fd, name, *, required=True):
        try:
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if required:
                self._unsafe()
            self._missing.append((parent_fd, name))
            return None
        except OSError:
            self._unsafe()
        descriptor = None
        try:
            descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
            held = os.fstat(descriptor)
        except OSError:
            if descriptor is not None:
                os.close(descriptor)
            self._unsafe()
        if (
            _directory_identity(named) != _directory_identity(held)
            or not self._safe_directory(held)
            or held.st_dev != self._workspace_device
        ):
            os.close(descriptor)
            self._unsafe()
        self._remember_fd(descriptor)
        self._anchors.append(
            [parent_fd, name, descriptor, _directory_identity(held)],
        )
        return descriptor

    def _bind_chain(self, relative):
        descriptor = self._workspace_fd
        for component in relative.parts:
            descriptor = self._open_child(descriptor, component)
        return descriptor

    def _remove_missing(self, parent_fd, name):
        self._missing = [
            item for item in self._missing if item != (parent_fd, name)
        ]

    def _detach_anchor(self, descriptor, *, close):
        self._anchors = [
            item for item in self._anchors if item[2] != descriptor
        ]
        if close and descriptor in self._fds:
            os.close(descriptor)
            self._fds.remove(descriptor)

    def _anchor_existing_fd(self, parent_fd, name, descriptor):
        held = os.fstat(descriptor)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _directory_identity(held) != _directory_identity(named)
            or not self._safe_directory(held)
        ):
            self._unsafe()
        self._anchors.append(
            [parent_fd, name, descriptor, _directory_identity(held)],
        )

    def _bind_initial_tree(self):
        try:
            optimize_relative = self.optimize_dir.relative_to(self.workspace_root)
            project_relative = self.project_dir.relative_to(self.workspace_root)
        except ValueError:
            self._unsafe()
        if not optimize_relative.parts or not project_relative.parts:
            self._unsafe()

        self._workspace_fd = self._open_root(self.workspace_root)
        self._workspace_device = os.fstat(self._workspace_fd).st_dev
        self._optimize_fd = self._bind_chain(optimize_relative)
        self._project_fd = self._bind_chain(project_relative)

        if self.sample.parent != self.optimize_dir:
            self._unsafe()
        self._sample_fd = self._open_child(
            self._optimize_fd, self.sample.name, required=False,
        )
        self._output_root_fd = self._open_child(
            self._project_fd, "99-output-ztp", required=False,
        )
        if self._output_root_fd is not None:
            self._output_fd = self._open_child(
                self._output_root_fd, "optimize", required=False,
            )

        # All other source/output roots participating in link selection are
        # read-only, but binding their existing top-level components prevents
        # a same-name replacement from changing the mutation plan later.
        for name in ("99-output-eth", "99-output-monitor", "99-output-backup"):
            self._open_child(self._project_fd, name, required=False)

        self.retained_state = False
        if self._output_fd is not None:
            try:
                os.stat(
                    ".feedback-global-writeback-state.json",
                    dir_fd=self._output_fd, follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                self.retained_state = True

        self._legacy_has_data = False
        self._target_has_data = False
        if self._output_fd is not None:
            self._target_has_data = any(
                name != ".feedback-global-writeback-state.json"
                for name in os.listdir(self._output_fd)
            )
        self._unknown_symlinks = []
        self._legacy_regular_outputs = []
        self._legacy_unmanaged_outputs = []
        if self._sample_fd is not None:
            names = os.listdir(self._sample_fd)
            managed_names = set(LINK_NAMES.values())
            for name in names:
                node = os.stat(
                    name, dir_fd=self._sample_fd, follow_symlinks=False,
                )
                if name == LINK_NAMES["comparison_output"] and stat.S_ISDIR(
                        node.st_mode):
                    self._legacy_fd = self._open_child(self._sample_fd, name)
                    self._legacy_has_data = bool(os.listdir(self._legacy_fd))
                    continue
                if name in managed_names and not stat.S_ISLNK(node.st_mode):
                    self._unsafe()
                if name not in managed_names and stat.S_ISLNK(node.st_mode):
                    self._unknown_symlinks.append((name, _node_version(node)))
                if name in LEGACY_ROOT_OUTPUT_NAMES:
                    if stat.S_ISREG(node.st_mode):
                        self._legacy_regular_outputs.append(
                            (name, _node_version(node)),
                        )
                    elif not stat.S_ISLNK(node.st_mode):
                        self._legacy_unmanaged_outputs.append(name)
        if self._legacy_has_data and self._target_has_data:
            self._unsafe()

        self.targets = sample_link_targets(self.project_dir)
        self.targets[LINK_NAMES["comparison_output"]] = self.output
        for name, target in self.targets.items():
            if target is None or name == LINK_NAMES["comparison_output"]:
                continue
            target = Path(target).expanduser().absolute()
            try:
                target.relative_to(self.project_dir)
            except ValueError:
                self._unsafe()
            try:
                value = os.lstat(target)
            except OSError:
                self._unsafe()
            if stat.S_ISLNK(value.st_mode):
                self._unsafe()
            self.targets[name] = target
            self._source_versions.append((target, _node_version(value)))
        self._assert_stable()

    def _assert_stable(self):
        if self._closed:
            self._unsafe()
        try:
            root_named = os.lstat(self.workspace_root)
            root_held = os.fstat(self._workspace_fd)
        except OSError:
            self._unsafe()
        if (
            _directory_identity(root_named) != self._root_identity
            or _directory_identity(root_held) != self._root_identity
            or not self._safe_directory(root_held)
        ):
            self._unsafe()
        for parent_fd, name, descriptor, expected in self._anchors:
            try:
                named = os.stat(
                    name, dir_fd=parent_fd, follow_symlinks=False,
                )
                held = os.fstat(descriptor)
            except OSError:
                self._unsafe()
            if (
                _directory_identity(named) != expected
                or _directory_identity(held) != expected
                or not self._safe_directory(held)
            ):
                self._unsafe()
        for parent_fd, name in self._missing:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            self._unsafe()
        for path, expected in self._source_versions:
            try:
                current = os.lstat(path)
            except OSError:
                self._unsafe()
            if _node_version(current) != expected:
                self._unsafe()

    def _mkdir_child(self, parent_fd, name):
        self._assert_stable()
        try:
            os.mkdir(name, 0o755, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError:
            self._unsafe()
        self._remove_missing(parent_fd, name)
        descriptor = self._open_child(parent_fd, name)
        try:
            os.fsync(descriptor)
        except OSError:
            self._unsafe()
        return descriptor

    def _ensure_output(self, report):
        if self._output_root_fd is None:
            self._output_root_fd = self._mkdir_child(
                self._project_fd, "99-output-ztp",
            )

        if self._legacy_fd is not None:
            self._assert_stable()
            self._detach_anchor(self._legacy_fd, close=False)
            if self._legacy_has_data:
                if self._output_fd is not None:
                    self._detach_anchor(self._output_fd, close=True)
                    try:
                        os.rmdir("optimize", dir_fd=self._output_root_fd)
                    except OSError:
                        self._unsafe()
                else:
                    self._remove_missing(self._output_root_fd, "optimize")
                try:
                    os.replace(
                        LINK_NAMES["comparison_output"], "optimize",
                        src_dir_fd=self._sample_fd,
                        dst_dir_fd=self._output_root_fd,
                    )
                    os.fsync(self._sample_fd)
                    os.fsync(self._output_root_fd)
                except OSError:
                    self._unsafe()
                self._output_fd = self._legacy_fd
                self._anchor_existing_fd(
                    self._output_root_fd, "optimize", self._output_fd,
                )
                report(f"[MIGRATE] {self.sample / LINK_NAMES['comparison_output']} -> {self.output}")
            else:
                self._detach_anchor(self._legacy_fd, close=True)
                try:
                    os.rmdir(
                        LINK_NAMES["comparison_output"], dir_fd=self._sample_fd,
                    )
                    os.fsync(self._sample_fd)
                except OSError:
                    self._unsafe()
                if self._output_fd is None:
                    self._output_fd = self._mkdir_child(
                        self._output_root_fd, "optimize",
                    )
                report(f"[CLEAN] 移除空旧 comparison 目录: {self.sample / LINK_NAMES['comparison_output']}")
            self._legacy_fd = None
        elif self._output_fd is None:
            self._output_fd = self._mkdir_child(
                self._output_root_fd, "optimize",
            )

    @staticmethod
    def _identity_bound_unlink(parent_fd, name, expected):
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if _node_version(current) != expected:
            HeldSampleMutationPlan._unsafe()
        os.unlink(name, dir_fd=parent_fd)
        return True

    def _replace_link(self, name, target):
        relative = os.path.relpath(str(Path(target).absolute()), str(self.sample))
        try:
            existing = os.stat(
                name, dir_fd=self._sample_fd, follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISLNK(existing.st_mode):
                self._unsafe()
            try:
                if os.readlink(name, dir_fd=self._sample_fd) == relative:
                    confirmed = os.stat(
                        name, dir_fd=self._sample_fd,
                        follow_symlinks=False,
                    )
                    if _node_version(confirmed) != _node_version(existing):
                        self._unsafe()
                    return "skipped"
            except OSError:
                self._unsafe()
        temporary = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(16)}"
        temporary_identity = None
        try:
            os.symlink(relative, temporary, dir_fd=self._sample_fd)
            created = os.stat(
                temporary, dir_fd=self._sample_fd, follow_symlinks=False,
            )
            if (
                not stat.S_ISLNK(created.st_mode)
                or os.readlink(temporary, dir_fd=self._sample_fd) != relative
            ):
                self._unsafe()
            temporary_identity = _node_version(created)
            self._assert_stable()
            os.rename(
                temporary, name,
                src_dir_fd=self._sample_fd, dst_dir_fd=self._sample_fd,
            )
            temporary = None
            published = os.stat(
                name, dir_fd=self._sample_fd, follow_symlinks=False,
            )
            if (
                _node_identity(published) != temporary_identity[:6]
                or not stat.S_ISLNK(published.st_mode)
                or os.readlink(name, dir_fd=self._sample_fd) != relative
            ):
                self._unsafe()
            os.fsync(self._sample_fd)
            published_after = os.stat(
                name, dir_fd=self._sample_fd, follow_symlinks=False,
            )
            if (
                _node_identity(published_after) != temporary_identity[:6]
                or os.readlink(name, dir_fd=self._sample_fd) != relative
            ):
                self._unsafe()
        except OSError:
            self._unsafe()
        finally:
            if temporary is not None and temporary_identity is not None:
                try:
                    self._identity_bound_unlink(
                        self._sample_fd, temporary, temporary_identity,
                    )
                except (OSError, ValueError):
                    pass
        return "linked"

    def apply(self, *, dry_run=False, report=print):
        if dry_run or self._applied:
            self._unsafe()
        self._assert_stable()
        self._ensure_output(report)
        if self._sample_fd is None:
            self._sample_fd = self._mkdir_child(
                self._optimize_fd, self.sample.name,
            )

        for name, expected in self._unknown_symlinks:
            self._identity_bound_unlink(self._sample_fd, name, expected)
            report(f"[CLEAN] 删除旧 sample 链接: {self.sample / name}")
        for name, expected in self._legacy_regular_outputs:
            self._identity_bound_unlink(self._sample_fd, name, expected)
            report(f"[CLEAN] 删除 sample 根目录重复输出: {self.sample / name}")
        for name in self._legacy_unmanaged_outputs:
            report(f"[WARN] 保留非普通 legacy optimize 路径: {self.sample / name}")

        self.targets[LINK_NAMES["comparison_output"]] = self.output
        for name, target in self.targets.items():
            link = self.sample / name
            if target is None:
                report(f"[WARN] {name}: 当前项目没有可用目标")
                try:
                    existing = os.stat(
                        name, dir_fd=self._sample_fd, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                if not stat.S_ISLNK(existing.st_mode):
                    self._unsafe()
                self._identity_bound_unlink(
                    self._sample_fd, name, _node_version(existing),
                )
                report(f"[CLEAN] 删除失效 sample 链接: {link}")
                continue
            result = self._replace_link(name, target)
            report(f"[{'LINK' if result == 'linked' else 'SKIP'}] {link} -> {target}")
        self._assert_stable()
        self._applied = True
        return self.sample

    def duplicate_sample_fd(self):
        if not self._applied or self._sample_fd is None:
            self._unsafe()
        self._assert_stable()
        return os.dup(self._sample_fd)

    def assert_stable(self):
        """Reassert every held canonical directory/source before success."""
        self._assert_stable()

    def ensure_output_subdirectory(self, name):
        """Create a fixed comparison scope below the held output directory."""
        if not self._applied or name not in {"prod", "air"}:
            self._unsafe()
        self._assert_stable()
        descriptor = self._output_subdirs.get(name)
        if descriptor is None:
            descriptor = self._open_child(
                self._output_fd, name, required=False,
            )
            if descriptor is None:
                descriptor = self._mkdir_child(self._output_fd, name)
            self._output_subdirs[name] = descriptor
        self._assert_stable()
        return self.output / name

    def close(self):
        if self._closed:
            return
        self._closed = True
        for descriptor in tuple(self._fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds.clear()
        self._anchors.clear()


def plan_sample_mutations(optimize_dir, project_dir, workspace_root):
    """Return a read-only, held-fd mutation plan for Feedback's real CLI."""
    return HeldSampleMutationPlan(optimize_dir, project_dir, workspace_root)


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


def update_sample_links(
        optimize_dir, project_dir, dry_run=False, report=print,
        mutation_plan=None):
    """Refresh all available sample links and return the sample directory."""
    if mutation_plan is not None:
        if (
            Path(optimize_dir).expanduser().absolute()
            != mutation_plan.optimize_dir
            or Path(project_dir).expanduser().absolute()
            != mutation_plan.project_dir
        ):
            raise ValueError("unsafe held sample/output mutation authority")
        return mutation_plan.apply(dry_run=dry_run, report=report)
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
