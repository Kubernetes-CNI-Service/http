"""Held readonly regular input scope; no deployment/device execution authority.

Exact managed input admission is an explicit readonly API, not wired to a CLI.
This API pins real directory components and the first-opened leaf FDs;
it never adopts a closed snapshot DTO or reopens a replacement as authority.
Identity vocabulary and project restore eligibility reuse existing canonical
package/project facilities. Whole-schema planning never reads package files.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import threading

from _package_common import _package_project_identity, _source_identity
from project_contract import (
    SETUP_CORE_IDENTITY_LINKS, parse_setup_manifest_layout,
    require_project_eligible, runtime_link_specs,
)
from ibsw_upgrade_contract import InputPaths, snapshot_inventory


MAXIMUM_INPUT_BYTES = 4 * 1024 * 1024
_MANAGED_GLOBAL = "infiniband/bringup/xdr-upgrade/01-global.yaml"
_MANAGED_CSV = "infiniband/ib.csv"
_MANAGED_OUTPUT = "infiniband/bringup/xdr-upgrade/xdr-upgrade-logs"


def _object_key(metadata):
    # Cleanup owns the originally named object, not a numeric descriptor slot.
    # Size/timestamps may drift while the same original object still needs close.
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


class _CandidateDescriptor:
    def __init__(self, descriptor, named_preimage):
        self.descriptor = descriptor
        self.key = _object_key(named_preimage)
        self.attempted = False

    def conditional_close(self):
        if self.attempted:
            return None
        self.attempted = True
        try:
            if _object_key(os.fstat(self.descriptor)) != self.key:
                return ValueError("unknown reused descriptor slot; foreign object not closed")
            os.close(self.descriptor)
        except BaseException as error:
            return error
        return None


def _raise_cleanup_issues(issues):
    if not issues:
        return
    for error in issues:
        if not isinstance(error, Exception):
            raise error
    raise ValueError("HOLD: conditional cleanup has unresolved descriptor residue")


class _DirectoryLease:
    """Reference to a single original no-follow directory FD, never a dup()."""
    def __init__(self, pool, path, entry):
        self.pool, self.path, self.entry = pool, path, entry
        self.descriptor, self.identity = entry['owner'].descriptor, entry['identity']
        self.attempted = False

    def conditional_close(self):
        if self.attempted:
            return None
        self.attempted = True
        return self.pool.release(self.path, self.entry)


class _DirectoryPool:
    """Process-local live references only; final release closes the original FD.

    Sharing common prefixes avoids reopening every ancestor in every scope.
    A cached pathname is never authority: both its original FD and current
    no-follow name must still match before another lease can be acquired.
    """
    def __init__(self):
        self.lock = threading.RLock()
        self.entries = {}

    def acquire(self, path, parent, name, flags):
        with self.lock:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            identity = _package_project_identity(named)
            if not stat.S_ISDIR(named.st_mode):
                raise ValueError('real input directory required')
            entry = self.entries.get(path)
            if entry is not None:
                if (entry['identity'] != identity or
                        _package_project_identity(os.fstat(entry['owner'].descriptor)) != identity):
                    raise ValueError('original pooled directory FD/name identity changed')
                entry['references'] += 1
            else:
                descriptor = os.open(name, flags, dir_fd=parent)
                owner = _CandidateDescriptor(descriptor, named)
                try:
                    if _package_project_identity(os.fstat(descriptor)) != identity:
                        raise ValueError('directory changed during initial binding')
                except BaseException:
                    issue = owner.conditional_close()
                    if issue is not None:
                        _raise_cleanup_issues([issue])
                    raise
                entry = dict(owner=owner, identity=identity, references=1)
                self.entries[path] = entry
            return _DirectoryLease(self, path, entry)

    def release(self, path, entry):
        with self.lock:
            if self.entries.get(path) is not entry or entry['references'] < 1:
                return ValueError('unknown original directory lease; foreign FD not closed')
            entry['references'] -= 1
            if entry['references']:
                return None
            del self.entries[path]
            return entry['owner'].conditional_close()


_DIRECTORY_POOL = _DirectoryPool()


class _HeldDirectory:
    def __init__(self, path):
        self.path = Path(path)
        self.edges = []
        self.descriptors = []
        self._owners = []
        self.cleanup_issues = []
        if not self.path.is_absolute() or str(self.path) != os.path.normpath(str(self.path)):
            raise ValueError("canonical absolute input directory required")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            root = _DIRECTORY_POOL.acquire('/', None, '/', flags)
            root_fd = root.descriptor
            self._owners.append(root)
            self.descriptors.append(root_fd)
            self.root_identity = root.identity
            if _package_project_identity(os.fstat(root_fd)) != self.root_identity:
                raise ValueError("root FD changed before initial verification")
            parent = root_fd
            prefix = Path('/')
            for name in self.path.parts[1:]:
                prefix /= name
                owner = _DIRECTORY_POOL.acquire(str(prefix), parent, name, flags)
                opened = owner.descriptor
                self._owners.append(owner)
                self.descriptors.append(opened)
                identity = owner.identity
                self.edges.append((parent, name, opened, identity))
                parent = opened
            self.fd = parent
            self.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            if isinstance(original, (OSError, ValueError)):
                suffix = "; unknown cleanup residue remains HOLD" if self.cleanup_issues else ""
                raise ValueError("cannot bind regular input directory without symlink traversal" + suffix) from original
            raise

    def verify(self):
        if not self.descriptors:
            raise ValueError("input directory scope is closed")
        if _package_project_identity(os.fstat(self.descriptors[0])) != self.root_identity:
            raise ValueError("input root directory changed")
        for parent, name, opened, original in self.edges:
            if (_package_project_identity(os.fstat(opened)) != original or
                    _package_project_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != original):
                raise ValueError("input directory path/name identity changed")

    def close(self):
        for owner in reversed(self._owners):
            issue = owner.conditional_close()
            if issue is not None:
                self.cleanup_issues.append(issue)
        self.descriptors.clear()
        _raise_cleanup_issues(self.cleanup_issues)


class _HeldFile:
    def __init__(self, path, directory, *, allow_empty=False):
        if type(allow_empty) is not bool:
            raise ValueError("explicit boolean empty-file policy required")
        self.name = Path(path).name
        self.directory = directory
        self.fd = None
        self._owner = None
        self.cleanup_issues = []
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            directory.verify()
            named = os.stat(self.name, dir_fd=directory.fd, follow_symlinks=False)
            self.fd = os.open(self.name, flags, dir_fd=directory.fd)
            # Candidate cleanup key is registered from the named preimage
            # BEFORE the first fstat; a substituted first fstat is not adopted.
            self._owner = _CandidateDescriptor(self.fd, named)
            original = os.fstat(self.fd)
            self.identity = _source_identity(named)
            if (not stat.S_ISREG(original.st_mode) or self.identity != _source_identity(original)
                    or not (0 if allow_empty else 1) <= original.st_size <= MAXIMUM_INPUT_BYTES):
                raise ValueError("bounded regular input required")
            self.payload = self._read_original()
            self.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            if isinstance(original, (OSError, ValueError)):
                suffix = "; unknown cleanup residue remains HOLD" if self.cleanup_issues else ""
                raise ValueError("cannot bind regular input name, original FD and bytes" + suffix) from original
            raise

    def _read_original(self):
        size = self.identity[4]
        chunks = []
        offset = 0
        while offset < size:
            chunk = os.pread(self.fd, min(size - offset, 65536), offset)
            if not chunk:
                raise ValueError("input shrank while reading original FD")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(self.fd, 1, size):
            raise ValueError("input grew while reading original FD")
        return b"".join(chunks)

    def verify(self):
        if self.fd is None:
            raise ValueError("input file scope is closed")
        self.directory.verify()
        self.verify_identity()
        actual = self._read_original()
        after = _source_identity(os.fstat(self.fd))
        named_after = _source_identity(os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False))
        if actual != self.payload or after != self.identity or named_after != self.identity:
            raise ValueError("original input bytes/identity changed while verifying")
        self.directory.verify()

    def verify_identity(self):
        if self.fd is None:
            raise ValueError("input file scope is closed")
        opened = _source_identity(os.fstat(self.fd))
        named = _source_identity(os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False))
        if opened != self.identity or named != self.identity:
            raise ValueError("original input FD or filename identity changed")

    def close(self):
        if self.fd is not None:
            issue = self._owner.conditional_close() if self._owner else ValueError("unregistered input descriptor residue")
            if issue is not None:
                self.cleanup_issues.append(issue)
            self.fd = None
        _raise_cleanup_issues(self.cleanup_issues)


class _HeldAlias:
    """Hold a real parent and exact alias name/text; never open through it."""
    def __init__(self, path, directory, expected=None, *, allow_absolute=False):
        self.allow_absolute = allow_absolute
        self.name = Path(path).name
        self.directory = directory
        self.identity, self.target = self._observe()
        if expected is not None and self.target != expected:
            raise ValueError("managed input alias text does not match selected project")
        self.verify()

    def _observe(self):
        self.directory.verify()
        before = os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode) or before.st_nlink != 1:
            raise ValueError("managed input alias must be a single-link symlink")
        raw = os.readlink(self.name, dir_fd=self.directory.fd)
        after = os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)
        if _source_identity(before) != _source_identity(after):
            raise ValueError("managed input alias changed during three-read binding")
        if (os.path.isabs(raw) and not self.allow_absolute) or os.path.normpath(raw) != raw:
            raise ValueError("managed input alias must use exact relative canonical text")
        self.directory.verify()
        return _source_identity(after), raw

    def verify(self):
        if self._observe() != (self.identity, self.target):
            raise ValueError("original managed input alias identity/text changed")


class _EvidenceIdentity:
    """Original verified peer DATA identity, not a transferable success grant.

    The transaction reads/hash-checks a held regular file before constructing
    this guard. Keep its original directory FD/name and full source metadata
    (including ctime), but not a duplicate long-lived peer file FD. A replaced
    or edited name is refused; no later version is silently adopted.
    """
    def __init__(self, source):
        source.verify()
        self.directory, self.name, self.identity = source.directory, source.name, source.identity

    def verify(self):
        self.directory.verify()
        if _source_identity(os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)) != self.identity:
            raise ValueError('original peer evidence identity changed')


class BoundInputSession:
    """A live readonly scope. Returned inventory data is not execution permission."""
    def __init__(self, plan):
        self._initialize(plan)
        try:
            if plan.project:
                project = Path(plan.project)
                self._directories[str(project)] = _HeldDirectory(project)
                require_project_eligible(project)
            for path in (plan.csv_path, plan.global_path):
                selected = Path(path)
                if not selected.is_absolute():
                    raise ValueError("absolute source path required")
                if plan.project:
                    try:
                        selected.relative_to(Path(plan.project))
                    except ValueError:
                        raise ValueError("source does not belong to explicit bound project") from None
                self._files.append(_HeldFile(selected, self._directory(selected.parent)))
            self._finish_inventory()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise

    def _initialize(self, plan):
        self._directories = {}
        self._files = []
        self._metadata_files = []
        self._aliases = []
        self._managed_project = None
        self._standalone = False
        self._closed = False
        self._plan = plan
        if not isinstance(plan, InputPaths):
            raise ValueError("InputPaths plan required")
        if not all(hasattr(os, option) for option in ("O_NOFOLLOW", "O_DIRECTORY", "pread")):
            raise ValueError("safe no-follow input binding unavailable")

    def _directory(self, path):
        key = str(path)
        if key not in self._directories:
            self._directories[key] = _HeldDirectory(path)
        return self._directories[key]

    def _alias(self, path, expected=None):
        alias = _HeldAlias(path, self._directory(path.parent), expected)
        self._aliases.append(alias)
        return alias

    def _single_link_file(self, path, destination):
        source = _HeldFile(path, self._directory(path.parent))
        destination.append(source)
        if source.identity[3] != 1:
            raise ValueError("managed canonical input must be a single-link regular file")
        return source

    def _finish_inventory(self):
        self.verify()
        try:
            csv_text, global_text = (source.payload.decode("utf-8-sig") for source in self._files)
        except UnicodeError:
            raise ValueError("inputs must be UTF-8") from None
        self._inventory = snapshot_inventory(csv_text, global_text)
        self.verify()

    @classmethod
    def _from_managed_plan(cls, plan):
        scope = cls.__new__(cls)
        scope._initialize(plan)
        try:
            scope._bind_managed(plan)
            scope._finish_inventory()
            return scope
        except BaseException as original:
            try:
                scope.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            if isinstance(original, OSError):
                raise ValueError("cannot bind original managed input names and project authority") from original
            raise

    def _bind_managed(self, plan):
        global_alias = Path(plan.global_path)
        if (not global_alias.is_absolute()
                or global_alias.parts[-4:] != tuple(_MANAGED_GLOBAL.split("/"))):
            raise ValueError("explicit known managed global alias required; no active fallback")
        workspace = global_alias.parents[3]
        self._directory(workspace)
        alias = self._alias(global_alias)
        templates = dict(runtime_link_specs())
        global_source_alias, global_template = global_alias, _MANAGED_GLOBAL
        if alias.target == "../../01-global.yaml":
            # Historical bringup entry: pin BOTH original aliases, not resolve().
            global_source_alias = workspace / "infiniband/01-global.yaml"
            alias = self._alias(global_source_alias)
            global_template = "infiniband/01-global.yaml"
        prefix, suffix = templates[global_template].split("{project}")
        if not alias.target.startswith(prefix) or not alias.target.endswith(suffix):
            raise ValueError("managed global is not the exact direct project link")
        name = alias.target[len(prefix):-len(suffix)]
        if not name or "/" in name or name in (".", "..", "template"):
            raise ValueError("managed input must select one direct DAY0 project")
        project = workspace / "DAY0-Prepare" / name
        self._directory(project)
        self._managed_project = project
        if plan.project is not None and plan.project != str(project):
            raise ValueError("explicit project conflicts with original managed input owner")
        require_project_eligible(project)
        manifest = self._single_link_file(workspace / "ztp/.setup_manifest", self._metadata_files)
        try:
            owner, members = parse_setup_manifest_layout(manifest.payload.decode("utf-8"))
        except UnicodeError:
            raise ValueError("setup manifest must be UTF-8") from None
        if owner != str(project):
            raise ValueError("setup manifest and original selected alias disagree on project")
        if any(not Path(member).is_relative_to(workspace) for member in members):
            raise ValueError("setup manifest name escapes workspace")
        required = {str(workspace / "ztp" / item[0]) for item in SETUP_CORE_IDENTITY_LINKS}
        required.add(str(global_alias))
        required.add(str(global_source_alias))
        selected_csv = Path(plan.csv_path)
        if selected_csv == workspace / "infiniband/bringup/xdr-upgrade/ib.csv":
            self._alias(selected_csv, "../../ib.csv")
            selected_csv = workspace / _MANAGED_CSV
        if selected_csv == workspace / _MANAGED_CSV:
            self._alias(selected_csv, templates[_MANAGED_CSV].format(project=name))
            required.add(str(selected_csv))
        elif selected_csv != project / "02-devices_config.csv":
            raise ValueError("managed CSV must be same-project canonical input or known direct IB alias")
        if not required.issubset(members):
            raise ValueError("setup manifest lacks selected aliases or core identity anchors")
        for relative, target, _label, is_directory in SETUP_CORE_IDENTITY_LINKS:
            link = workspace / "ztp" / relative
            self._alias(link, os.path.relpath(project / target, link.parent))
            if is_directory:
                self._directory(project / target)
        self._single_link_file(project / "02-devices_config.csv", self._files)
        self._single_link_file(project / "01-global.yaml", self._files)
        self._single_link_file(project / "02-dhcp-subnet_config.csv", self._metadata_files)
        output_alias = workspace / _MANAGED_OUTPUT
        if Path(plan.output_path).is_relative_to(output_alias):
            parent = self._directory(output_alias.parent)
            try:
                output_stat = os.stat(output_alias.name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                return  # No output creation or writer permission in this scope.
            if stat.S_ISLNK(output_stat.st_mode):
                if str(output_alias) not in members:
                    raise ValueError("selected managed output lacks setup manifest identity")
                self._alias(output_alias, templates[_MANAGED_OUTPUT].format(project=name))
                self._directory(project / "99-output-ib_nvl/bringup/xdr-upgrade-logs")

    @classmethod
    def _from_standalone_plan(cls, plan):
        """Bind explicitly selected files/links, never consult active setup state."""
        scope = cls.__new__(cls)
        scope._initialize(plan)
        scope._standalone = True
        try:
            final_paths = []
            for original in (plan.csv_path, plan.global_path):
                selected, seen = Path(original), set()
                for _ in range(16):
                    if not selected.is_absolute() or str(selected) != os.path.normpath(str(selected)) or str(selected) in seen:
                        raise ValueError("standalone input link cycle or noncanonical source")
                    seen.add(str(selected))
                    parent = scope._directory(selected.parent)
                    named = os.stat(selected.name, dir_fd=parent.fd, follow_symlinks=False)
                    if not stat.S_ISLNK(named.st_mode):
                        scope._files.append(_HeldFile(selected, parent))
                        final_paths.append(selected)
                        break
                    alias = _HeldAlias(selected, parent, allow_absolute=True)
                    scope._aliases.append(alias)
                    selected = Path(os.path.normpath(os.path.join(str(selected.parent), alias.target)))
                else:
                    raise ValueError("standalone input link depth exceeded")
            # Direct project input identity is derived only from the two chosen
            # originals. No .setup_manifest, DHCP or active-project lookup.
            csv_source, global_source = final_paths
            project_sources = [path for path in final_paths if path.parent.parent.name == "DAY0-Prepare"]
            if project_sources:
                project = project_sources[0].parent
                if (csv_source != project / "02-devices_config.csv"
                        or global_source != project / "01-global.yaml"):
                    raise ValueError("standalone inputs select conflicting project sources")
                if plan.project is not None and str(project) != plan.project:
                    raise ValueError("standalone inputs conflict with explicit project")
                if any(source.identity[3] != 1 for source in scope._files):
                    raise ValueError("project canonical inputs must be single-link regular files")
                scope._managed_project = project
                logical = Path(plan.output_path).parent
                parent = scope._directory(logical.parent)
                try:
                    named = os.stat(logical.name, dir_fd=parent.fd, follow_symlinks=False)
                except FileNotFoundError:
                    named = None
                if named is not None and stat.S_ISLNK(named.st_mode):
                    alias = _HeldAlias(logical, parent, allow_absolute=True)
                    expected = project / "99-output-ib_nvl/bringup/xdr-upgrade-logs"
                    if os.path.normpath(os.path.join(str(logical.parent), alias.target)) != str(expected):
                        raise ValueError("standalone output link conflicts with selected project")
                    scope._aliases.append(alias)
            scope._finish_inventory()
            return scope
        except BaseException as original:
            try:
                scope.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise

    def _require_open(self):
        if self._closed:
            raise ValueError("input session is closed; verifier cannot be reused")

    def verify(self):
        self._require_open()
        try:
            for directory in self._directories.values():
                directory.verify()
            if self._plan.project and not self._standalone:
                require_project_eligible(Path(self._plan.project))
            if self._managed_project is not None and not self._standalone:
                require_project_eligible(self._managed_project)
            for alias in self._aliases:
                alias.verify()
            for source in self._metadata_files + self._files:
                source.verify()
            for alias in self._aliases:
                alias.verify()
            # Reading the second source cannot conceal mutation of the first
            # after its byte check, including the final alias metadata reads.
            # Recheck every original FD/name at scope end.
            for source in self._metadata_files + self._files:
                source.verify_identity()
            for directory in self._directories.values():
                directory.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            if isinstance(original, (OSError, ValueError)):
                raise ValueError("input scope changed or became ineligible") from original
            raise

    def inventory(self):
        self.verify()
        return self._inventory

    def close(self):
        if not self._closed:
            self._closed = True
            issues = []
            for source in reversed(self._metadata_files + self._files):
                try:
                    source.close()
                except BaseException as error:
                    issues.append(error)
            for directory in reversed(tuple(self._directories.values())):
                try:
                    directory.close()
                except BaseException as error:
                    issues.append(error)
            _raise_cleanup_issues(issues)

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, _type, original, _traceback):
        try:
            self.close()
        except BaseException as cleanup:
            if original is None or (isinstance(original, Exception) and not isinstance(cleanup, Exception)):
                raise
            # All provable ownership records have been attempted. Do not mask
            # the original operator interruption with a cleanup error.
        return False


def open_regular_inputs(plan: InputPaths) -> BoundInputSession:
    return BoundInputSession(plan)


def open_managed_inputs(plan: InputPaths) -> BoundInputSession:
    """Bind exact setup inputs live; inventory remains data, not device permission."""
    return BoundInputSession._from_managed_plan(plan)


def open_standalone_inputs(plan: InputPaths) -> BoundInputSession:
    """Explicit source binding without requiring a prior load/setup run."""
    return BoundInputSession._from_standalone_plan(plan)
