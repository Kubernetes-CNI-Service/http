#!/usr/bin/env python3
"""Real packaging workflow driven by the sanitized public project fixture."""

import argparse
from contextlib import contextmanager
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.public_project_fixture import (
    materialized_public_project,
)
from test_cases.test_public_project_fixture_contract import PACKAGING_METHODS
from test_cases.test_public_clean_clone_contract import (
    EXPECTED_PRIVATE_DOCUMENT_PATHS,
)


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_EXECUTABLE_PATH = os.confstr("CS_PATH") or "/usr/bin:/bin"
_SYSTEM_GIT = shutil.which("git", path=SYSTEM_EXECUTABLE_PATH)
if not _SYSTEM_GIT:
    raise RuntimeError("trusted system Git executable is unavailable")
GIT_BINARY = str(Path(_SYSTEM_GIT).resolve())
EXPECTED_PUBLIC_INPUTS = {
    "01-global.yaml.example": "01-global.yaml",
    "02-devices_config.csv.example": "02-devices_config.csv",
    "02-dhcp-subnet_config.csv.example": "02-dhcp-subnet_config.csv",
}
EXPECTED_PRIVATE_SITE_PROJECT = "2026-12-vb-gb300"
P0_DEFERRED_Q01_PATHS = (
    "docs/README.md",
    "docs/architecture/README.md",
    "docs/deployment/BUNDLE_WORKFLOWS.md",
    "docs/deployment/README.md",
    "docs/operations/README.md",
    "docs/reference/README.md",
    "docs/validation/README.md",
    "infra/docker/README.md",
)
P_PUBLISHED_Q01_SHA256 = {
    "docs/README.md": "e646ad967d9bd418451f152fd2c48f41fe3415dc7acea55e434ae610ff1b57fd",
    "docs/architecture/README.md": "153837bcd62f49edf8591ceec8b1b6ccefe9a3b5638a91bed6452ac87264a0e4",
    "docs/deployment/BUNDLE_WORKFLOWS.md": "adab10445e130f3335113c5b35072b81b5d7e10d28d3d1214ace45e120199a1b",
    "docs/deployment/README.md": "f1914024ab82546239f9424abaca44380f22d6c4331c76e3e6ede218333a036e",
    "docs/operations/README.md": "da1fb0570f8277d7304c1446ab49d7ae49dcf52a320c86b90babdf15e4a6dd05",
    "docs/reference/README.md": "717f023b3016420b61e8889493fd0e2ab9d0106388483025f8d66dee75c75039",
    "docs/validation/README.md": "2a2ee457e01074db1994363a2f8ed62029a9febb14d7c4ea92243b93ec61d98f",
    "infra/docker/README.md": "8355b6cf2bea57f072a689da6a4c3e4979cfd3da26c87f585a728c42972fb996",
}
P_V2_FORBIDDEN_PUBLIC_ROOTS = (
    "docs/v3/finished-project-lifecycle",
    "Finished-projects",
    "monitor/cabletracker-main",
    "v3-requirements.md",
)
P0_PUBLIC_OVERLAY = (
    "test_cases/public_project_fixture.py",
    "test_cases/test_public_clean_clone_contract.py",
    "test_cases/test_private_documentation_contract.py",
    "test_cases/test_public_clean_clone_workflow.py",
    "test_cases/test_public_project_fixture_contract.py",
    "test_cases/test_public_project_fixture_workflow.py",
    "test_cases/run_vm_validation.py",
    "test_cases/test_deployment_writer_lock.py",
    "test_cases/test_deploy_upload_archive.py",
    "test_cases/test_upload_package_contract.py",
    "examples/public-project/01-global.yaml.example",
    "examples/public-project/02-devices_config.csv.example",
    "examples/public-project/02-dhcp-subnet_config.csv.example",
    ".dockerignore",
    "requirements-container-top-level.lock",
    "user-manual.html",
    "infra/docker/Dockerfile",
    "infra/docker/Dockerfile.dockerignore",
    "infra/docker/compose.yaml",
    "infra/docker/activate.py",
    "infra/docker/entrypoint.py",
    "infra/docker/healthcheck.py",
    "infra/docker/hostctl.py",
    "infra/docker/hostlock.py",
    "infra/docker/management_ssh_key.py",
    "infra/docker/deploy.sh",
    "infra/docker/supervisord.conf",
    "infra/docker/apache-ztp.conf",
    "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/logrotate-http-ztp.conf",
    "infra/docker/container.env.example",
    "tools/_package_common.py",
    "tools/control-auth.py",
    "tools/deploy-upload-archive.py",
    "tools/deployment_prewrite_guard.py",
    "tools/deployment_lock.py",
    "tools/password-update.py",
    "tools/sync-code.py",
    "tools/tar-for-download.py",
    "tools/tar-for-upload.py",
    "tools/update-user-manual.py",
    "tools/ztp_service_runtime.py",
    "DAY0-Prepare/11-load.py",
    "DAY0-Prepare/12-ztp-monitor.py",
    "DAY0-Prepare/13-unload.py",
    "ztp/nvue_normalizer.py",
    "ztp/config/topology_rules.py",
    "ztp/optimize/feedback.py",
    "ztp/optimize/sample_links.py",
    "ztp/templates/ztp-bootstrap.sh",
    "ztp/templates/ztp.json",
)
EXACT_PACKAGING_TESTS = (
    "test_cases.test_deployment_writer_lock.SyncDeploymentLockTests."
    "test_sync_payload_covers_every_local_source_manifest_member",
    "test_cases.test_deployment_writer_lock.SyncDeploymentLockTests."
    "test_project_rsync_excludes_global_for_dedicated_merge",
    "test_cases.test_deploy_upload_archive.RelayArchiveInstallerTests."
    "test_real_packager_relay_copy_installer_and_embedded_guard_workflow",
    "test_cases.test_upload_package_contract.UploadPackageContractTests."
    "test_real_upload_archive_exactly_satisfies_packaged_source_manifest",
    "test_cases.test_upload_package_contract.UploadPackageContractTests."
    "test_relay_release_externalizes_project_switch_images",
)


def _public_candidate_paths():
    _raw, records = _index_snapshot(ROOT)
    private = set(EXPECTED_PRIVATE_DOCUMENT_PATHS)
    tracked = {Path(relative) for relative in records if relative not in private}
    return tuple(sorted(tracked | {Path(path) for path in P0_PUBLIC_OVERLAY}))


def _safe_repository_path(relative: str) -> bool:
    return bool(
        relative
        and "\0" not in relative
        and "\\" not in relative
        and not relative.startswith("/")
        and all(part not in {"", ".", ".."} for part in relative.split("/"))
    )


def _is_deferred_q01(relative: str) -> bool:
    if any(
        relative.startswith(published + "/")
        for published in P0_DEFERRED_Q01_PATHS
    ):
        return True
    return any(
        relative == forbidden or relative.startswith(forbidden + "/")
        for forbidden in P_V2_FORBIDDEN_PUBLIC_ROOTS
    )


def _canonical_git_environment():
    environment = os.environ.copy()
    for key in tuple(environment):
        if key == "PATH" or key.startswith(("GIT_", "LD_", "DYLD_")):
            environment.pop(key, None)
    environment.update({
        "PATH": SYSTEM_EXECUTABLE_PATH,
        "GIT_CONFIG": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    return environment


def _run_canonical_git(repository: Path, arguments):
    return subprocess.run(
        [GIT_BINARY, "--no-replace-objects", "-c",
         f"core.hooksPath={os.devnull}", "-C", str(repository), *arguments],
        env=_canonical_git_environment(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )


def _canonical_index_path(repository: Path):
    result = _run_canonical_git(repository, ["rev-parse", "--absolute-git-dir"])
    if result.returncode != 0:
        raise AssertionError(
            "canonical Git directory cannot be resolved: "
            + result.stderr.decode("utf-8", "replace")
        )
    try:
        raw = result.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise AssertionError("canonical Git directory is not UTF-8") from exc
    git_directory = Path(raw)
    if not git_directory.is_absolute() or not git_directory.is_dir():
        raise AssertionError("canonical Git directory is not an absolute directory")
    return git_directory / "index"


def _release_owned_index_lock(lock_path, descriptor, held, prior_error=None):
    failure = prior_error
    visible = None
    try:
        try:
            visible = lock_path.lstat()
        except BaseException as exc:
            failure = failure or exc
            try:
                visible = lock_path.lstat()
            except BaseException as retry_exc:
                failure = failure or retry_exc
        owned = bool(
            visible is not None
            and stat.S_ISREG(visible.st_mode)
            and visible.st_nlink == 1
            and (held.st_dev, held.st_ino)
            == (visible.st_dev, visible.st_ino)
        )
        if visible is not None and not owned:
            failure = failure or AssertionError(
                "canonical index lock identity changed"
            )
        if owned:
            try:
                lock_path.unlink()
            except BaseException as exc:
                failure = failure or exc
                try:
                    retry_visible = lock_path.lstat()
                except BaseException as retry_exc:
                    failure = failure or retry_exc
                else:
                    if (
                        stat.S_ISREG(retry_visible.st_mode)
                        and retry_visible.st_nlink == 1
                        and (held.st_dev, held.st_ino)
                        == (retry_visible.st_dev, retry_visible.st_ino)
                    ):
                        try:
                            lock_path.unlink()
                        except BaseException as retry_exc:
                            failure = failure or retry_exc
                    else:
                        failure = failure or AssertionError(
                            "canonical index lock identity changed"
                        )
    finally:
        os.close(descriptor)
    if failure is not None:
        raise AssertionError("canonical index lock teardown failed") from failure


@contextmanager
def _held_canonical_index(repository: Path):
    index_path = _canonical_index_path(repository)
    lock_path = index_path.with_name(index_path.name + ".lock")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise AssertionError(
            f"canonical index authority cannot be acquired: {lock_path}"
        ) from exc
    try:
        held = os.fstat(descriptor)
    except BaseException as exc:
        try:
            held = os.fstat(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        _release_owned_index_lock(lock_path, descriptor, held, prior_error=exc)
        raise AssertionError("unreachable index lock cleanup")
    try:
        yield
    finally:
        _release_owned_index_lock(lock_path, descriptor, held)


def _index_snapshot(repository: Path):
    result = _run_canonical_git(repository, ["ls-files", "--stage", "-z"])
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode("utf-8", "replace"))
    if result.stdout and not result.stdout.endswith(b"\0"):
        raise AssertionError("index stage records are not NUL terminated")
    records = {}
    for raw in result.stdout[:-1].split(b"\0") if result.stdout else ():
        try:
            metadata, raw_path = raw.split(b"\t", 1)
            raw_mode, raw_object_id, raw_stage = metadata.split(b" ", 2)
            mode = raw_mode.decode("ascii")
            object_id = raw_object_id.decode("ascii")
            stage = raw_stage.decode("ascii")
            relative = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise AssertionError("unsafe UTF-8 index stage record") from exc
        if mode not in {"100644", "100755", "120000"}:
            raise AssertionError(f"unsupported index mode {mode}: {relative}")
        if stage != "0":
            raise AssertionError(f"index entry is not stage-0: {relative}")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id):
            raise AssertionError(f"unsafe index object id: {relative}")
        if not _safe_repository_path(relative):
            raise AssertionError(f"unsafe index path: {relative!r}")
        if relative in records:
            raise AssertionError(f"duplicate/unmerged index path: {relative}")
        records[relative] = (mode, object_id)
    return result.stdout, records


def _index_blob(repository: Path, object_id: str) -> bytes:
    object_type = _run_canonical_git(repository, ["cat-file", "-t", object_id])
    if object_type.returncode != 0 or object_type.stdout != b"blob\n":
        detail = object_type.stderr.decode("utf-8", "replace").strip()
        raise AssertionError(
            f"indexed object type is not an exact blob: {object_id} {detail}"
        )
    result = _run_canonical_git(repository, ["cat-file", "blob", object_id])
    if result.returncode != 0:
        raise AssertionError(
            "indexed blob cannot be materialized: "
            + result.stderr.decode("utf-8", "replace")
        )
    return result.stdout


def _stat_identity(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def _directory_identity(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
        value.st_mtime_ns, value.st_ctime_ns,
    )


class _OverlayCapture(tuple):
    def __new__(cls, mode, payload, leaf_identity, parent_identities):
        value = super().__new__(cls, (mode, payload))
        value.leaf_identity = leaf_identity
        value.parent_identities = parent_identities
        return value


def _open_overlay_parent(repository: Path, relative: str):
    parts = relative.split("/")
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    descriptors = []
    try:
        descriptor = os.open(repository, flags)
        try:
            held = os.fstat(descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        descriptors.append((repository, descriptor, held))
        current = repository
        for part in parts[:-1]:
            descriptor = os.open(part, flags, dir_fd=descriptor)
            current = current / part
            try:
                held = os.fstat(descriptor)
            except BaseException:
                os.close(descriptor)
                raise
            if not stat.S_ISDIR(held.st_mode):
                raise AssertionError(
                    f"untracked public overlay parent is not a directory: {relative}"
                )
            descriptors.append((current, descriptor, held))
    except BaseException:
        for _path, opened, _held in reversed(descriptors):
            os.close(opened)
        raise
    return descriptors, parts[-1]


def _validate_overlay_parents(descriptors, relative: str):
    for path, descriptor, before in descriptors:
        held = os.fstat(descriptor)
        try:
            visible = path.lstat()
        except OSError as exc:
            raise AssertionError(
                f"untracked public overlay parent changed: {relative}"
            ) from exc
        if (
            not stat.S_ISDIR(visible.st_mode)
            or _directory_identity(before) != _directory_identity(held)
            or (held.st_dev, held.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            raise AssertionError(
                f"untracked public overlay parent changed: {relative}"
            )


def _capture_untracked_overlay_entry(repository: Path, relative: str):
    try:
        descriptors, leaf = _open_overlay_parent(repository, relative)
    except (AssertionError, OSError) as exc:
        raise AssertionError(
            f"unsafe/missing untracked public overlay parent: {relative}"
        ) from exc
    parent_descriptor = descriptors[-1][1]
    try:
        try:
            before = os.stat(
                leaf, dir_fd=parent_descriptor, follow_symlinks=False,
            )
        except OSError as exc:
            raise AssertionError(
                f"public candidate input is missing: {relative}"
            ) from exc
        if before.st_nlink != 1:
            raise AssertionError(
                f"untracked public overlay is not single-link: {relative}"
            )
        if stat.S_ISLNK(before.st_mode):
            try:
                target = os.readlink(leaf, dir_fd=parent_descriptor)
                after = os.stat(
                    leaf, dir_fd=parent_descriptor, follow_symlinks=False,
                )
            except OSError as exc:
                raise AssertionError(
                    f"untracked public overlay changed: {relative}"
                ) from exc
            _validate_overlay_parents(descriptors, relative)
            if _stat_identity(before) != _stat_identity(after):
                raise AssertionError(
                    f"untracked public overlay changed: {relative}"
                )
            try:
                payload = target.encode("utf-8")
            except UnicodeError as exc:
                raise AssertionError(
                    f"unsafe UTF-8 untracked symlink target: {relative}"
                ) from exc
            if "\0" in target:
                raise AssertionError(
                    f"NUL in untracked symlink target: {relative}"
                )
            return _OverlayCapture(
                "120000", payload, _stat_identity(before),
                tuple((path, _directory_identity(held))
                      for path, _descriptor, held in descriptors),
            )
        if not stat.S_ISREG(before.st_mode):
            raise AssertionError(
                f"P0 public overlay is not a regular file or symlink: {relative}"
            )
        flags = os.O_RDONLY
        for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
            flags |= getattr(os, name, 0)
        try:
            descriptor = os.open(leaf, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            raise AssertionError(
                f"unsafe untracked public overlay: {relative}"
            ) from exc
        try:
            held = os.fstat(descriptor)
            if (
                not stat.S_ISREG(held.st_mode)
                or held.st_nlink != 1
                or _stat_identity(held) != _stat_identity(before)
            ):
                raise AssertionError(
                    f"unsafe untracked public overlay: {relative}"
                )
            chunks = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            final_held = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            after = os.stat(
                leaf, dir_fd=parent_descriptor, follow_symlinks=False,
            )
        except OSError as exc:
            raise AssertionError(
                f"untracked public overlay changed: {relative}"
            ) from exc
        _validate_overlay_parents(descriptors, relative)
        if not (
            _stat_identity(before)
            == _stat_identity(held)
            == _stat_identity(final_held)
            == _stat_identity(after)
        ):
            raise AssertionError(
                f"untracked public overlay changed: {relative}"
            )
        mode = "100755" if before.st_mode & 0o111 else "100644"
        return _OverlayCapture(
            mode, b"".join(chunks), _stat_identity(before),
            tuple((path, _directory_identity(parent_held))
                  for path, _descriptor, parent_held in descriptors),
        )
    finally:
        for _path, descriptor, _held in reversed(descriptors):
            os.close(descriptor)


def _untracked_overlay_entry(repository: Path, relative: str):
    if not _safe_repository_path(relative):
        raise AssertionError(f"unsafe public overlay path: {relative!r}")
    return _capture_untracked_overlay_entry(repository, relative)


def _validate_materialized_path_trie(paths):
    selected = set(paths)
    for relative in sorted(selected):
        parts = relative.split("/")
        for length in range(1, len(parts)):
            ancestor = "/".join(parts[:length])
            if ancestor in selected:
                raise AssertionError(
                    "public candidate file/directory path conflict: "
                    f"{ancestor} -> {relative}"
                )


def _overlay_sources_match(repository: Path, captured):
    for relative, expected in captured.items():
        if not isinstance(expected, _OverlayCapture):
            return False
        try:
            descriptors, leaf = _open_overlay_parent(repository, relative)
        except (AssertionError, OSError):
            return False
        try:
            if len(descriptors) != len(expected.parent_identities):
                return False
            for (path, descriptor, _before), (expected_path, identity) in zip(
                descriptors, expected.parent_identities,
            ):
                if path != expected_path:
                    return False
                held = os.fstat(descriptor)
                try:
                    visible = path.lstat()
                except OSError:
                    return False
                if (
                    _directory_identity(held) != identity
                    or not stat.S_ISDIR(visible.st_mode)
                    or (held.st_dev, held.st_ino)
                    != (visible.st_dev, visible.st_ino)
                ):
                    return False
            try:
                after = os.stat(
                    leaf, dir_fd=descriptors[-1][1], follow_symlinks=False,
                )
            except OSError:
                return False
            if _stat_identity(after) != expected.leaf_identity:
                return False
            if expected[0] == "120000":
                try:
                    target = os.readlink(leaf, dir_fd=descriptors[-1][1])
                except (OSError, UnicodeError):
                    return False
                if target.encode("utf-8") != expected[1]:
                    return False
        finally:
            for _path, descriptor, _held in reversed(descriptors):
                os.close(descriptor)
    return True


def _restore_empty_destination(destination: Path, existed: bool):
    if destination.is_symlink() or destination.is_file():
        destination.unlink()
    elif destination.exists():
        shutil.rmtree(destination)
    if existed:
        destination.mkdir()


def _validate_public_overlay(repository_root: Path, overlay) -> None:
    for raw in overlay:
        relative = Path(raw)
        source = repository_root / relative
        if not source.exists() and not source.is_symlink():
            raise AssertionError(f"public candidate input is missing: {relative}")
        mode = source.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
            raise AssertionError(
                f"P0 public overlay is not a regular file or symlink: {relative}"
            )


def _copy_public_candidate(destination: Path) -> None:
    destination_state = None
    if not os.path.lexists(destination):
        destination_state = "absent"
    elif (
        not destination.is_symlink()
        and destination.is_dir()
        and not any(destination.iterdir())
    ):
        destination_state = "empty"
    try:
        preliminary_snapshot, _preliminary_records = _index_snapshot(ROOT)
        with _held_canonical_index(ROOT):
            _copy_public_candidate_held(destination, preliminary_snapshot)
    except BaseException:
        if destination_state is not None:
            _restore_empty_destination(
                destination, destination_state == "empty",
            )
        raise


def _copy_public_candidate_held(
    destination: Path, preliminary_snapshot: bytes,
) -> None:
    raw_snapshot, index_records = _index_snapshot(ROOT)
    if raw_snapshot != preliminary_snapshot:
        raise AssertionError("complete index snapshot changed before authority lock")
    forbidden = sorted(relative for relative in index_records if _is_deferred_q01(relative))
    if forbidden:
        raise AssertionError(
            "deferred Q01 public authority is present in index: "
            + ", ".join(forbidden)
        )
    private = set(EXPECTED_PRIVATE_DOCUMENT_PATHS)
    public_index_paths = {
        relative for relative in index_records if relative not in private
    }
    overlay_paths = tuple(P0_PUBLIC_OVERLAY)
    if len(overlay_paths) != len(set(overlay_paths)):
        raise AssertionError("duplicate public overlay path")
    for relative in overlay_paths:
        if not _safe_repository_path(relative) or _is_deferred_q01(relative):
            raise AssertionError(f"unsafe/deferred public overlay path: {relative}")
    _validate_materialized_path_trie(public_index_paths | set(overlay_paths))

    materialized = {
        relative: (mode, _index_blob(ROOT, object_id))
        for relative, (mode, object_id) in index_records.items()
        if relative not in private
    }
    captured_overlay = {}
    for relative in overlay_paths:
        if relative not in index_records:
            captured = _untracked_overlay_entry(ROOT, relative)
            captured_overlay[relative] = captured
            materialized[relative] = captured
    confirmed_snapshot, _confirmed_records = _index_snapshot(ROOT)
    if confirmed_snapshot != raw_snapshot:
        raise AssertionError("complete index snapshot changed during materialization")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination_existed = destination.exists() and not destination.is_symlink()
    if destination.is_symlink() or (
        destination.exists()
        and (not destination.is_dir() or any(destination.iterdir()))
    ):
        raise AssertionError("public candidate destination must be absent or empty")
    staging = Path(tempfile.mkdtemp(
        prefix=f".{destination.name}.materializing-", dir=destination.parent,
    ))
    publish_started = False
    try:
        for relative in sorted(materialized):
            mode, payload = materialized[relative]
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if mode == "120000":
                try:
                    link_target = payload.decode("utf-8")
                except UnicodeError as exc:
                    raise AssertionError(
                        f"unsafe UTF-8 indexed symlink target: {relative}"
                    ) from exc
                if "\0" in link_target:
                    raise AssertionError(f"NUL in indexed symlink target: {relative}")
                target.symlink_to(link_target)
            else:
                target.write_bytes(payload)
                target.chmod(0o755 if mode == "100755" else 0o644)
        publish_started = True
        os.replace(staging, destination)
        final_snapshot, _final_records = _index_snapshot(ROOT)
        if final_snapshot != raw_snapshot:
            raise AssertionError("index changed at public candidate publish boundary")
        if not _overlay_sources_match(ROOT, captured_overlay):
            raise AssertionError(
                "untracked public overlay changed at publish boundary"
            )
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        if publish_started:
            _restore_empty_destination(destination, destination_existed)
        raise


def _load_package_tool():
    path = ROOT / "tools/_package_common.py"
    tools = str(path.parent)
    if tools not in sys.path:
        sys.path.insert(0, tools)
    spec = importlib.util.spec_from_file_location("public_fixture_package_workflow", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PublicProjectFixtureWorkflowTests(unittest.TestCase):
    @staticmethod
    def _indexed_fixture(
        repository: Path, payload: bytes = b"indexed bytes\n",
        relative: str = "payload.txt",
    ):
        subprocess.run(
            ["git", "init", "--quiet"], cwd=repository,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        source = repository / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(payload)
        subprocess.run(
            ["git", "add", "--", relative], cwd=repository,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        return source

    @staticmethod
    def _copy_from(repository: Path, destination: Path, overlay=()):
        module = sys.modules[__name__]
        with mock.patch.object(module, "ROOT", repository), mock.patch.object(
            module, "P0_PUBLIC_OVERLAY", tuple(overlay),
        ):
            _copy_public_candidate(destination)

    @staticmethod
    def _assert_canonical_index_lock_released(repository: Path):
        index_path = _canonical_index_path(repository)
        lock = index_path.with_name(index_path.name + ".lock")
        if os.path.lexists(lock):
            raise AssertionError(f"canonical index lock leaked: {lock}")
        descriptor = os.open(
            lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        os.close(descriptor)
        lock.unlink()

    def test_public_candidate_materializes_validated_index_blob_not_worktree(self):
        for kind, expected_mode in (("regular", 0o644), ("executable", 0o755)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(
                prefix=f"http-public-index-{kind}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                relative = "nested/safe/payload.bin"
                source = self._indexed_fixture(repository, relative=relative)
                source.chmod(expected_mode)
                subprocess.run(
                    ["git", "add", "--", relative], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                source.write_bytes(b"unstaged worktree replacement\n")
                source.chmod(0o600)

                self._copy_from(repository, destination)

                copied = destination / relative
                self.assertEqual(b"indexed bytes\n", copied.read_bytes())
                self.assertEqual(expected_mode, stat.S_IMODE(copied.lstat().st_mode))

        with tempfile.TemporaryDirectory(prefix="http-public-index-symlink-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            relative = "nested/safe/payload.link"
            link = repository / relative
            link.parent.mkdir(parents=True)
            link.symlink_to("indexed-target")
            subprocess.run(
                ["git", "add", "--", relative], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            link.unlink()
            link.symlink_to("unstaged-target")

            self._copy_from(repository, destination)

            copied = destination / relative
            self.assertTrue(copied.is_symlink())
            self.assertEqual("indexed-target", os.readlink(copied))

    def test_public_candidate_index_snapshot_rejects_oid_mode_or_path_rebinding(self):
        for mutation in ("oid", "mode", "path"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix=f"http-public-index-{mutation}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                relative = "nested/safe/payload.bin"
                source = self._indexed_fixture(repository, relative=relative)
                real_run = subprocess.run
                changed = False

                def mutate_after_snapshot(*args, **kwargs):
                    nonlocal changed
                    result = real_run(*args, **kwargs)
                    command = args[0] if args else kwargs.get("args", ())
                    output = result.stdout
                    full_stage_snapshot = (
                        isinstance(output, bytes)
                        and output.endswith(b"\0")
                        and all(
                            re.fullmatch(
                                rb"(?:100644|100755|120000) [0-9a-f]+ 0\t[^\0]+",
                                record,
                            )
                            for record in output[:-1].split(b"\0")
                        )
                    )
                    if (
                        not changed
                        and "ls-files" in command
                        and full_stage_snapshot
                    ):
                        changed = True
                        if mutation == "oid":
                            source.write_bytes(b"different indexed object\n")
                            real_run(
                                ["git", "add", "--", relative], cwd=repository,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                            )
                        elif mutation == "mode":
                            source.chmod(0o755)
                            real_run(
                                ["git", "add", "--", relative], cwd=repository,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                            )
                        else:
                            real_run(
                                ["git", "rm", "--cached", "--quiet", "--", relative],
                                cwd=repository, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True,
                            )
                            replacement_relative = "nested/safe/replacement.bin"
                            replacement = repository / replacement_relative
                            replacement.write_bytes(b"replacement path\n")
                            real_run(
                                ["git", "add", "--", replacement_relative], cwd=repository,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                            )
                    return result

                module = sys.modules[__name__]
                with mock.patch.object(
                    subprocess, "run", side_effect=mutate_after_snapshot,
                ), mock.patch.object(module, "ROOT", repository), mock.patch.object(
                    module, "P0_PUBLIC_OVERLAY", (),
                ), self.assertRaisesRegex(AssertionError, "index|snapshot|changed"):
                    _copy_public_candidate(destination)
                self.assertTrue(changed, "hostile must run after full stage snapshot")
                self.assertEqual([], list(destination.iterdir()))

    def test_public_candidate_rejects_non_stage_zero_index_entry(self):
        for stage in (1, 2, 3):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(
                prefix=f"http-public-index-stage{stage}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                source = self._indexed_fixture(repository)
                object_id = subprocess.run(
                    ["git", "hash-object", "-w", "--", "payload.txt"], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
                ).stdout.strip()
                subprocess.run(
                    ["git", "update-index", "--force-remove", "--", "payload.txt"],
                    cwd=repository, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=True,
                )
                subprocess.run(
                    ["git", "update-index", "--index-info"], cwd=repository,
                    input=f"100644 {object_id} {stage}\tpayload.txt\n", text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                self.assertTrue(source.is_file())
                with self.assertRaisesRegex(AssertionError, "stage-0|unmerged|index"):
                    self._copy_from(repository, destination)
                self.assertEqual([], list(destination.iterdir()))

    def test_public_candidate_rejects_gitlink_index_entry_before_copy(self):
        with tempfile.TemporaryDirectory(prefix="http-public-index-gitlink-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            subprocess.run(
                ["git", "-c", "user.name=Fixture", "-c",
                 "user.email=fixture@example.invalid", "commit", "--quiet",
                 "-m", "fixture commit"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            commit_id = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo",
                 f"160000,{commit_id},vendor"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            (repository / "vendor").mkdir()
            with self.assertRaisesRegex(AssertionError, "160000|gitlink|index"):
                self._copy_from(repository, destination)
            self.assertEqual([], list(destination.iterdir()))

    def test_public_candidate_accepts_q01_exact8_and_rejects_deferred_v2(self):
        expected = tuple(P_PUBLISHED_Q01_SHA256)
        self.assertEqual(8, len(expected))
        s_tree = _run_canonical_git(
            ROOT, ["ls-tree", "-r", "--name-only", "991a64476cfe1de2a0ab45bca8b7b6d75d5e9149"],
        )
        self.assertEqual(0, s_tree.returncode, s_tree.stderr)
        self.assertEqual(
            set(), set(expected).intersection(s_tree.stdout.decode("utf-8").splitlines()),
        )
        rejected = tuple(f"{relative}/child.txt" for relative in expected) + tuple(
            candidate
            for root in P_V2_FORBIDDEN_PUBLIC_ROOTS
            for candidate in (root, root + "/future/child.txt")
        )
        for relative in rejected:
            with self.subTest(rejected=relative), tempfile.TemporaryDirectory(
                prefix="http-public-deferred-v2-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                subprocess.run(
                    ["git", "init", "--quiet"], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"deferred v2 reference\n")
                subprocess.run(
                    ["git", "add", "--", relative], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                with self.assertRaisesRegex(
                    AssertionError, "deferred|public|reference|v2",
                ):
                    self._copy_from(repository, destination)
                self.assertFalse(destination.exists())
        with tempfile.TemporaryDirectory(prefix="http-public-current-q01-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            expected_payloads = {}
            for relative in expected:
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = (ROOT / relative).read_bytes()
                self.assertEqual(
                    P_PUBLISHED_Q01_SHA256[relative],
                    hashlib.sha256(payload).hexdigest(),
                )
                path.write_bytes(payload)
                expected_payloads[relative] = payload
            subprocess.run(
                ["git", "add", "--", *expected], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            with mock.patch.object(sys.modules[__name__], "ROOT", repository):
                public_paths = set(_public_candidate_paths())
                self.assertEqual(
                    {Path(relative) for relative in expected},
                    {Path(relative) for relative in expected}.intersection(public_paths),
                )
                _raw, indexed = _index_snapshot(repository)
                for relative in expected:
                    mode, object_id = indexed[relative]
                    self.assertEqual("100644", mode)
                    self.assertEqual(
                        expected_payloads[relative],
                        _index_blob(repository, object_id),
                    )
            self._copy_from(repository, destination)

            self.assertEqual(
                set(expected),
                {
                    path.relative_to(destination).as_posix()
                    for path in destination.rglob("*") if path.is_file()
                },
            )
            for relative in expected:
                self.assertEqual(
                    expected_payloads[relative],
                    (destination / relative).read_bytes(),
                )

    def test_deferred_v2_prefix_siblings_remain_public_candidates(self):
        with tempfile.TemporaryDirectory(prefix="http-public-q01-sibling-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            siblings = (
                "docs/README.md.public-sibling",
                "docs/architecture/README.md.public-sibling",
                "docs/deployment/BUNDLE_WORKFLOWS.md.public-sibling",
                "docs/deployment/README.md.public-sibling",
                "docs/operations/README.md.public-sibling",
                "docs/reference/README.md.public-sibling",
                "docs/validation/README.md.public-sibling",
                "infra/docker/README.md.public-sibling",
                *(root + ".public-sibling" for root in P_V2_FORBIDDEN_PUBLIC_ROOTS),
            )
            for relative in siblings:
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"public sibling\n")
            subprocess.run(
                ["git", "add", "--", *siblings], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )

            self._copy_from(repository, destination)

            self.assertEqual(
                set(siblings),
                {
                    path.relative_to(destination).as_posix()
                    for path in destination.rglob("*") if path.is_file()
                },
            )

    def test_indexed_overlay_wins_while_untracked_overlay_uses_worktree(self):
        with tempfile.TemporaryDirectory(prefix="http-public-overlay-source-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            indexed = self._indexed_fixture(repository)
            indexed.write_bytes(b"unstaged indexed-overlay bytes\n")
            indexed_link = repository / "indexed-overlay.link"
            indexed_link.symlink_to("indexed-link-target")
            subprocess.run(
                ["git", "add", "--", "indexed-overlay.link"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            indexed_link.unlink()
            indexed_link.symlink_to("unstaged-link-target")
            untracked = repository / "overlay-only.txt"
            untracked.write_bytes(b"reviewed untracked overlay\n")
            untracked_link = repository / "overlay-only.link"
            untracked_link.symlink_to("reviewed-untracked-target")

            self._copy_from(
                repository, destination,
                (
                    "payload.txt", "indexed-overlay.link",
                    "overlay-only.txt", "overlay-only.link",
                ),
            )

            self.assertEqual(
                b"indexed bytes\n", (destination / "payload.txt").read_bytes(),
            )
            self.assertEqual(
                b"reviewed untracked overlay\n",
                (destination / "overlay-only.txt").read_bytes(),
            )
            self.assertEqual(
                "indexed-link-target",
                os.readlink(destination / "indexed-overlay.link"),
            )
            self.assertEqual(
                "reviewed-untracked-target",
                os.readlink(destination / "overlay-only.link"),
            )

    def test_public_candidate_parser_rejects_unsafe_index_records(self):
        hostile_specs = {
            "invalid-mode-100600": (b"100600", b"mode.py\0"),
            "invalid-utf8": (b"100644", b"bad-\xff.py\0"),
            "absolute": (b"100644", b"/absolute.py\0"),
            "dot": (b"100644", b".\0"),
            "dotdot": (b"100644", b"../escape.py\0"),
            "nested-dotdot": (b"100644", b"nested/../escape.py\0"),
            "nul-split": (b"100644", b"bad\0injected.py\0"),
        }
        for label, (mode, raw_path) in hostile_specs.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix=f"http-public-index-{label}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                subprocess.run(
                    ["git", "init", "--quiet"], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                object_id = subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"], cwd=repository,
                    input=b"real reachable fixture blob\n", stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=True,
                ).stdout.strip()
                raw_records = mode + b" " + object_id + b" 0\t" + raw_path
                real_run = subprocess.run

                def hostile_snapshot(*args, **kwargs):
                    command = args[0] if args else kwargs.get("args", ())
                    if "ls-files" in command:
                        return subprocess.CompletedProcess(
                            command, 0, stdout=raw_records, stderr=b"",
                        )
                    return real_run(*args, **kwargs)

                module = sys.modules[__name__]
                with mock.patch.object(
                    subprocess, "run", side_effect=hostile_snapshot,
                ), mock.patch.object(module, "ROOT", repository), mock.patch.object(
                    module, "P0_PUBLIC_OVERLAY", (),
                ), self.assertRaisesRegex(
                    (AssertionError, UnicodeError),
                    "UTF|utf|unsafe|path|NUL|index|record|mode",
                ):
                    _copy_public_candidate(destination)
                self.assertEqual([], list(destination.iterdir()))

    def test_empty_index_materializes_regular_and_symlink_untracked_overlay(self):
        with tempfile.TemporaryDirectory(prefix="http-public-empty-index-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            (repository / "only.txt").write_bytes(b"only untracked bytes\n")
            (repository / "only.link").symlink_to("only.txt")
            self._copy_from(
                repository, destination, ("only.txt", "only.link"),
            )
            self.assertEqual(
                b"only untracked bytes\n", (destination / "only.txt").read_bytes(),
            )
            self.assertEqual("only.txt", os.readlink(destination / "only.link"))

    def test_untracked_regular_open_uses_nonblocking_cloexec_nofollow_flags(self):
        with tempfile.TemporaryDirectory(prefix="http-public-open-flags-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            overlay = repository / "overlay.txt"
            overlay.write_bytes(b"untracked overlay\n")
            real_open = os.open
            opened = []

            def observed_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                raw_path = os.fspath(path)
                if Path(raw_path) == overlay or (
                    kwargs.get("dir_fd") is not None and raw_path == overlay.name
                ):
                    opened.append((descriptor, flags))
                return descriptor

            with mock.patch.object(os, "open", side_effect=observed_open):
                self._copy_from(repository, destination, ("overlay.txt",))
            self.assertEqual(1, len(opened))
            descriptor, flags = opened[0]
            self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
            required = 0
            for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC"):
                required |= getattr(os, name)
            self.assertEqual(required, flags & required)
            forbidden = os.O_WRONLY | os.O_RDWR
            for name in ("O_CREAT", "O_TRUNC", "O_APPEND", "O_EXCL"):
                forbidden |= getattr(os, name, 0)
            self.assertEqual(0, flags & forbidden)
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_untracked_overlay_rejects_symlink_parent_outside_repository(self):
        with tempfile.TemporaryDirectory(prefix="http-public-parent-link-") as directory:
            base = Path(directory)
            repository = base / "repository"
            outside = base / "outside"
            destination = base / "candidate"
            repository.mkdir()
            outside.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            (outside / "secret.txt").write_bytes(b"outside secret\n")
            (repository / "linked-parent").symlink_to(outside)
            with self.assertRaises((AssertionError, OSError)):
                self._copy_from(
                    repository, destination, ("linked-parent/secret.txt",),
                )
            self.assertEqual([], list(destination.iterdir()))
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_untracked_parent_swap_after_review_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="http-public-parent-race-") as directory:
            base = Path(directory)
            repository = base / "repository"
            outside = base / "outside"
            destination = base / "candidate"
            repository.mkdir()
            outside.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            parent = repository / "reviewed-parent"
            held_parent = repository / ".reviewed-parent.held"
            parent.mkdir()
            source = parent / "payload.txt"
            source.write_bytes(b"reviewed overlay\n")
            outside_source = outside / "payload.txt"
            outside_source.write_bytes(b"outside sentinel\n")
            real_open = os.open
            attacks = 0

            def swap_parent_before_leaf_open(path, flags, *args, **kwargs):
                nonlocal attacks
                raw_path = os.fspath(path)
                is_leaf = Path(raw_path) == source or (
                    kwargs.get("dir_fd") is not None
                    and raw_path == source.name
                )
                if is_leaf and attacks == 0:
                    attacks += 1
                    parent.rename(held_parent)
                    parent.symlink_to(outside, target_is_directory=True)
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=swap_parent_before_leaf_open,
            ), self.assertRaises((AssertionError, OSError)):
                self._copy_from(
                    repository, destination, ("reviewed-parent/payload.txt",),
                )
            self.assertEqual(1, attacks)
            self.assertEqual(b"outside sentinel\n", outside_source.read_bytes())
            self.assertEqual([], list(destination.iterdir()))
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_untracked_regular_rejects_leaf_swap_without_block_or_fd_leak(self):
        for replacement in ("fifo", "symlink", "regular"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory(
                prefix=f"http-public-leaf-{replacement}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                self._indexed_fixture(repository)
                overlay = repository / "overlay.txt"
                overlay.write_bytes(b"initial regular\n")
                real_open = os.open
                opened = []

                def swap_before_open(path, flags, *args, **kwargs):
                    raw_path = os.fspath(path)
                    is_leaf = Path(raw_path) == overlay or (
                        kwargs.get("dir_fd") is not None
                        and raw_path == overlay.name
                    )
                    if is_leaf:
                        overlay.unlink()
                        if replacement == "fifo":
                            os.mkfifo(overlay)
                        elif replacement == "symlink":
                            overlay.symlink_to("payload.txt")
                        else:
                            overlay.write_bytes(b"replacement file\n")
                        if replacement == "fifo" and not (
                            flags & getattr(os, "O_NONBLOCK")
                        ):
                            raise AssertionError("FIFO open lacks O_NONBLOCK")
                    descriptor = real_open(path, flags, *args, **kwargs)
                    if is_leaf:
                        opened.append(descriptor)
                    return descriptor

                with mock.patch.object(
                    os, "open", side_effect=swap_before_open,
                ), self.assertRaises((AssertionError, OSError)):
                    self._copy_from(repository, destination, ("overlay.txt",))
                for descriptor in opened:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                self.assertEqual([], list(destination.iterdir()))
                self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_untracked_regular_rejects_same_inode_overwrite_with_mtime_restore(self):
        with tempfile.TemporaryDirectory(prefix="http-public-overlay-rewrite-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            overlay = repository / "overlay.bin"
            original = b"reviewed-content"
            hostile = b"hostile-content!"
            self.assertEqual(len(original), len(hostile))
            overlay.write_bytes(original)
            initial = overlay.stat()
            real_open = os.open
            changed = False

            def overwrite_before_open(path, flags, *args, **kwargs):
                nonlocal changed
                raw_path = os.fspath(path)
                is_leaf = Path(raw_path) == overlay or (
                    kwargs.get("dir_fd") is not None
                    and raw_path == overlay.name
                )
                if is_leaf and not changed:
                    changed = True
                    with overlay.open("r+b", buffering=0) as stream:
                        stream.write(hostile)
                    os.utime(
                        overlay, ns=(initial.st_atime_ns, initial.st_mtime_ns),
                    )
                return real_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                os, "open", side_effect=overwrite_before_open,
            ), self.assertRaisesRegex(AssertionError, "changed|ctime|content|overlay"):
                self._copy_from(repository, destination, ("overlay.bin",))
            self.assertTrue(changed)
            self.assertEqual([], list(destination.iterdir()))
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_untracked_symlink_rejects_second_stat_aba_target_change(self):
        with tempfile.TemporaryDirectory(prefix="http-public-link-aba-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            link = repository / "overlay.link"
            link.symlink_to("reviewed-target")
            initial = link.lstat()
            held = repository / ".overlay.link.reviewed"
            real_readlink = os.readlink
            calls = 0

            def aba_readlink(path, *args, **kwargs):
                nonlocal calls
                raw_path = os.fspath(path)
                is_leaf = Path(raw_path) == link or (
                    kwargs.get("dir_fd") is not None and raw_path == link.name
                )
                if is_leaf:
                    calls += 1
                    link.rename(held)
                    link.symlink_to("hostile-target")
                    hostile = real_readlink(path, *args, **kwargs)
                    link.unlink()
                    held.rename(link)
                    return hostile
                return real_readlink(path, *args, **kwargs)

            with mock.patch.object(
                os, "readlink", side_effect=aba_readlink,
            ), self.assertRaisesRegex(AssertionError, "changed|symlink|overlay"):
                self._copy_from(repository, destination, ("overlay.link",))
            self.assertEqual(1, calls)
            restored = link.lstat()
            self.assertEqual((initial.st_dev, initial.st_ino),
                             (restored.st_dev, restored.st_ino))
            self.assertEqual("reviewed-target", os.readlink(link))
            self.assertEqual([], list(destination.iterdir()))
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_index_object_id_must_name_blob_not_annotated_tag_to_blob(self):
        with tempfile.TemporaryDirectory(prefix="http-public-tag-object-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            blob_id = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"], cwd=repository,
                input=b"tagged blob payload\n", stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=True,
            ).stdout.decode("ascii").strip()
            subprocess.run(
                ["git", "-c", "user.name=Fixture", "-c",
                 "user.email=fixture@example.invalid", "tag", "-a", "blob-tag",
                 "-m", "tag wrapping a blob", blob_id], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            tag_id = subprocess.run(
                ["git", "rev-parse", "refs/tags/blob-tag"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                check=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo",
                 f"100644,{tag_id},tagged.txt"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            with self.assertRaisesRegex(AssertionError, "object type|blob|tag"):
                self._copy_from(repository, destination)
            self.assertEqual([], list(destination.iterdir()))

    def test_index_change_at_atomic_publish_boundary_rolls_back_candidate(self):
        with tempfile.TemporaryDirectory(prefix="http-public-publish-race-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            source = self._indexed_fixture(repository)
            real_snapshot = _index_snapshot
            real_index_blob = _index_blob
            attack_attempts = 0
            changed = False
            materialized = False

            def observed_index_blob(candidate_repository, object_id):
                nonlocal materialized
                payload = real_index_blob(candidate_repository, object_id)
                materialized = True
                return payload

            def mutate_after_confirmation(candidate_repository):
                nonlocal attack_attempts, changed
                result = real_snapshot(candidate_repository)
                if materialized and attack_attempts == 0:
                    attack_attempts += 1
                    source.write_bytes(b"post-confirm index replacement\n")
                    update = subprocess.run(
                        ["git", "add", "--", "payload.txt"], cwd=repository,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                    )
                    changed = update.returncode == 0
                return result

            module = sys.modules[__name__]
            with mock.patch.object(
                module, "_index_snapshot", side_effect=mutate_after_confirmation,
            ), mock.patch.object(
                module, "_index_blob", side_effect=observed_index_blob,
            ):
                if changed:
                    self.fail("attack state must be established by the copy call")
                try:
                    self._copy_from(repository, destination)
                except AssertionError:
                    rejected = True
                else:
                    rejected = False
            self.assertEqual(1, attack_attempts)
            if changed:
                self.assertTrue(rejected, "a successful index mutation must reject")
                self.assertTrue(destination.is_dir())
                self.assertEqual([], list(destination.iterdir()))
            else:
                self.assertFalse(rejected, "an index lock may prevent the mutation")
                self.assertEqual(
                    b"indexed bytes\n", (destination / "payload.txt").read_bytes(),
                )
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_index_authority_is_held_through_final_publish_return(self):
        with tempfile.TemporaryDirectory(prefix="http-public-index-held-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            source = self._indexed_fixture(repository)
            source.write_bytes(b"late hostile index bytes\n")
            overlay = repository / "overlay.txt"
            overlay.write_bytes(b"stable untracked overlay\n")
            real_overlay_check = _overlay_sources_match
            attacks = 0
            attack_returncodes = []

            def mutate_after_final_validation(candidate_repository, captured):
                nonlocal attacks
                result = real_overlay_check(candidate_repository, captured)
                attacks += 1
                update = subprocess.run(
                    ["git", "add", "--", "payload.txt"], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                attack_returncodes.append(update.returncode)
                return result

            module = sys.modules[__name__]
            with mock.patch.object(
                module, "_overlay_sources_match",
                side_effect=mutate_after_final_validation,
            ):
                self._copy_from(repository, destination, ("overlay.txt",))
            self.assertEqual(1, attacks)
            self.assertEqual(1, len(attack_returncodes))
            self.assertNotEqual(
                0, attack_returncodes[0],
                "canonical index authority must remain held through return",
            )
            self.assertEqual(
                b"indexed bytes\n", (destination / "payload.txt").read_bytes(),
            )
            self.assertEqual(
                b"stable untracked overlay\n",
                (destination / "overlay.txt").read_bytes(),
            )
            self._assert_canonical_index_lock_released(repository)
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_overlay_parent_fstat_failure_closes_every_open_descriptor(self):
        for failure_point in ("root", "nested"):
            with self.subTest(failure_point=failure_point), tempfile.TemporaryDirectory(
                prefix=f"http-public-parent-fstat-{failure_point}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                self._indexed_fixture(repository)
                nested = repository / "nested"
                nested.mkdir()
                (nested / "overlay.txt").write_bytes(b"overlay bytes\n")
                real_open = os.open
                real_fstat = os.fstat
                opened = []
                target_descriptor = None
                attacks = 0

                def observed_open(path, flags, *args, **kwargs):
                    nonlocal target_descriptor
                    descriptor = real_open(path, flags, *args, **kwargs)
                    raw_path = os.fspath(path)
                    is_root = Path(raw_path) == repository
                    is_nested = (
                        kwargs.get("dir_fd") is not None and raw_path == "nested"
                    )
                    if is_root or is_nested:
                        opened.append(descriptor)
                    if (
                        (failure_point == "root" and is_root)
                        or (failure_point == "nested" and is_nested)
                    ):
                        target_descriptor = descriptor
                    return descriptor

                def fail_selected_fstat(descriptor):
                    nonlocal attacks
                    if descriptor == target_descriptor and attacks == 0:
                        attacks += 1
                        raise OSError("injected parent fstat failure")
                    return real_fstat(descriptor)

                with mock.patch.object(
                    os, "open", side_effect=observed_open,
                ), mock.patch.object(
                    os, "fstat", side_effect=fail_selected_fstat,
                ), self.assertRaises((AssertionError, OSError)):
                    self._copy_from(
                        repository, destination, ("nested/overlay.txt",),
                    )
                self.assertEqual(1, attacks)
                self.assertGreaterEqual(len(opened), 1)
                for descriptor in opened:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
                self._assert_canonical_index_lock_released(repository)
                self.assertEqual([], list(destination.iterdir()))
                self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_async_exception_after_atomic_replace_restores_original_destination(self):
        for original_state in ("absent", "empty"):
            with self.subTest(original_state=original_state), tempfile.TemporaryDirectory(
                prefix=f"http-public-replace-interrupt-{original_state}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                self._indexed_fixture(repository)
                if original_state == "empty":
                    destination.mkdir()
                real_replace = os.replace
                attacks = 0

                def interrupt_after_replace(source, target, *args, **kwargs):
                    nonlocal attacks
                    result = real_replace(source, target, *args, **kwargs)
                    if Path(target) == destination:
                        attacks += 1
                        raise KeyboardInterrupt("injected post-replace interrupt")
                    return result

                with mock.patch.object(
                    os, "replace", side_effect=interrupt_after_replace,
                ), self.assertRaises(KeyboardInterrupt):
                    self._copy_from(repository, destination)
                self.assertEqual(1, attacks)
                if original_state == "absent":
                    self.assertFalse(destination.exists())
                else:
                    self.assertTrue(destination.is_dir())
                    self.assertEqual([], list(destination.iterdir()))
                self._assert_canonical_index_lock_released(repository)
                self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_index_lock_first_fstat_failure_releases_fd_and_lock(self):
        with tempfile.TemporaryDirectory(prefix="http-public-lock-fstat-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            self._indexed_fixture(repository)
            index_path = _canonical_index_path(repository)
            lock = index_path.with_name(index_path.name + ".lock")
            real_open = os.open
            real_fstat = os.fstat
            lock_descriptor = None
            attacks = 0

            def observed_open(path, flags, *args, **kwargs):
                nonlocal lock_descriptor
                descriptor = real_open(path, flags, *args, **kwargs)
                if Path(os.fspath(path)) == lock:
                    lock_descriptor = descriptor
                return descriptor

            def fail_lock_fstat(descriptor):
                nonlocal attacks
                if descriptor == lock_descriptor and attacks == 0:
                    attacks += 1
                    raise OSError("injected index-lock fstat failure")
                return real_fstat(descriptor)

            with mock.patch.object(
                os, "open", side_effect=observed_open,
            ), mock.patch.object(
                os, "fstat", side_effect=fail_lock_fstat,
            ), self.assertRaises((AssertionError, OSError)):
                self._copy_from(repository, destination)
            self.assertEqual(1, attacks)
            self.assertIsNotNone(lock_descriptor)
            with self.assertRaises(OSError):
                os.fstat(lock_descriptor)
            self._assert_canonical_index_lock_released(repository)
            self.assertEqual([], list(destination.iterdir()))
            self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_permission_denied_lock_does_not_enter_readonly_fallback(self):
        for error_number in (errno.EACCES, errno.EPERM, errno.EROFS):
            for original_state in ("absent", "empty"):
                with self.subTest(
                    error_number=error_number, original_state=original_state,
                ), tempfile.TemporaryDirectory(
                    prefix=f"http-public-lock-denied-{error_number}-{original_state}-",
                ) as directory:
                    base = Path(directory)
                    repository = base / "repository"
                    destination = base / "candidate"
                    repository.mkdir()
                    if original_state == "empty":
                        destination.mkdir()
                    self._indexed_fixture(repository)
                    index_path = _canonical_index_path(repository)
                    lock_path = index_path.with_name(index_path.name + ".lock")
                    real_open = os.open
                    index_opens = 0

                    def deny_lock(path, flags, *args, **kwargs):
                        nonlocal index_opens
                        resolved = Path(os.fspath(path))
                        if resolved == lock_path:
                            raise OSError(error_number, "injected lock failure")
                        if resolved == index_path:
                            index_opens += 1
                        return real_open(path, flags, *args, **kwargs)

                    module = sys.modules[__name__]
                    with mock.patch.object(
                        os, "open", side_effect=deny_lock,
                    ), mock.patch.object(
                        module, "_copy_public_candidate_held",
                    ) as held_copy, self.assertRaisesRegex(
                        AssertionError, "index|authority|lock|acquired",
                    ):
                        self._copy_from(repository, destination)
                    self.assertEqual(0, index_opens)
                    held_copy.assert_not_called()
                    self.assertFalse(os.path.lexists(lock_path))
                    if original_state == "absent":
                        self.assertFalse(destination.exists())
                    else:
                        self.assertTrue(destination.is_dir())
                        self.assertEqual([], list(destination.iterdir()))
                    self.assertEqual(
                        [], list(base.glob(".candidate.materializing-*")),
                    )

    def test_writable_index_lock_teardown_failure_rolls_back_destination(self):
        for fault in (
            "identity-transient", "unlink-transient",
            "identity-unknown", "unlink-unknown",
        ):
            for original_state in ("absent", "empty"):
                with self.subTest(
                    fault=fault, original_state=original_state,
                ), tempfile.TemporaryDirectory(
                    prefix=f"http-public-lock-exit-{fault}-{original_state}-",
                ) as directory:
                    base = Path(directory)
                    repository = base / "repository"
                    destination = base / "candidate"
                    repository.mkdir()
                    self._indexed_fixture(repository)
                    if original_state == "empty":
                        destination.mkdir()
                    index_path = _canonical_index_path(repository)
                    lock_path = index_path.with_name(index_path.name + ".lock")
                    displaced = lock_path.with_name(index_path.name + ".owned-displaced")
                    unknown_payload = b"unknown competing lock\n"
                    unknown_identity = None
                    real_open = os.open
                    real_lstat = Path.lstat
                    real_unlink = Path.unlink
                    attacks = 0
                    events = []
                    lock_descriptor = None

                    def observed_open(path, flags, *args, **kwargs):
                        nonlocal lock_descriptor
                        descriptor = real_open(path, flags, *args, **kwargs)
                        if Path(os.fspath(path)) == lock_path:
                            lock_descriptor = descriptor
                        return descriptor

                    def install_unknown_lock():
                        nonlocal unknown_identity
                        os.replace(lock_path, displaced)
                        lock_path.write_bytes(unknown_payload)
                        unknown_identity = real_lstat(lock_path)

                    def fail_lock_lstat(path, *args, **kwargs):
                        nonlocal attacks
                        if path != lock_path:
                            return real_lstat(path, *args, **kwargs)
                        if fault.startswith("identity-") and attacks == 0:
                            attacks += 1
                            events.append("identity-fail")
                            if fault.endswith("-unknown"):
                                install_unknown_lock()
                            raise OSError("injected lock identity failure")
                        events.append("identity-recheck")
                        return real_lstat(path, *args, **kwargs)

                    def fail_lock_unlink(path, *args, **kwargs):
                        nonlocal attacks
                        if path != lock_path:
                            return real_unlink(path, *args, **kwargs)
                        if fault.startswith("unlink-") and attacks == 0:
                            attacks += 1
                            events.append("unlink-fail")
                            if fault.endswith("-unknown"):
                                install_unknown_lock()
                            raise OSError("injected lock unlink failure")
                        events.append("unlink-retry")
                        return real_unlink(path, *args, **kwargs)

                    with mock.patch.object(
                        os, "open", side_effect=observed_open,
                    ), mock.patch.object(
                        Path, "lstat", autospec=True, side_effect=fail_lock_lstat,
                    ), mock.patch.object(
                        Path, "unlink", autospec=True, side_effect=fail_lock_unlink,
                    ), self.assertRaises((AssertionError, OSError)):
                        self._copy_from(repository, destination)
                    self.assertEqual(1, attacks)
                    self.assertIsNotNone(lock_descriptor)
                    with self.assertRaises(OSError):
                        os.fstat(lock_descriptor)
                    if original_state == "absent":
                        self.assertFalse(destination.exists())
                    else:
                        self.assertTrue(destination.is_dir())
                        self.assertEqual([], list(destination.iterdir()))
                    if fault.endswith("-unknown"):
                        self.assertIsNotNone(unknown_identity)
                        visible = lock_path.lstat()
                        self.assertEqual(
                            (unknown_identity.st_dev, unknown_identity.st_ino),
                            (visible.st_dev, visible.st_ino),
                        )
                        self.assertEqual(unknown_payload, lock_path.read_bytes())
                        lock_path.unlink()
                        if os.path.lexists(displaced):
                            displaced.unlink()
                    else:
                        failure_event = (
                            "identity-fail" if fault.startswith("identity-")
                            else "unlink-fail"
                        )
                        retry_event = (
                            "identity-recheck" if fault.startswith("identity-")
                            else "unlink-retry"
                        )
                        self.assertLess(
                            events.index(failure_event), events.index(retry_event),
                        )
                        if fault.startswith("identity-"):
                            self.assertIn("unlink-retry", events)
                            self.assertLess(
                                events.index("identity-recheck"),
                                events.index("unlink-retry"),
                            )
                        else:
                            between = events[
                                events.index("unlink-fail") + 1:
                                events.index("unlink-retry")
                            ]
                            self.assertIn("identity-recheck", between)
                        self._assert_canonical_index_lock_released(repository)
                    self.assertEqual(
                        [], list(base.glob(".candidate.materializing-*")),
                    )

    def test_untracked_overlay_change_at_publish_boundary_rolls_back_candidate(self):
        for kind in ("regular", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(
                prefix=f"http-public-overlay-publish-{kind}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                self._indexed_fixture(repository)
                overlay = repository / "overlay"
                if kind == "regular":
                    overlay.write_bytes(b"reviewed overlay bytes\n")
                else:
                    overlay.symlink_to("reviewed-target")
                real_overlay_entry = _untracked_overlay_entry
                attacks = 0

                def mutate_after_capture(candidate_repository, relative):
                    nonlocal attacks
                    result = real_overlay_entry(candidate_repository, relative)
                    attacks += 1
                    if kind == "regular":
                        overlay.write_bytes(b"hostile overlay bytes\n")
                    else:
                        overlay.unlink()
                        overlay.symlink_to("hostile-target")
                    return result

                module = sys.modules[__name__]
                with mock.patch.object(
                    module, "_untracked_overlay_entry",
                    side_effect=mutate_after_capture,
                ), self.assertRaisesRegex(
                    AssertionError, "overlay|publish|changed",
                ):
                    self._copy_from(repository, destination, ("overlay",))
                self.assertEqual(1, attacks)
                self.assertTrue(destination.is_dir())
                self.assertEqual([], list(destination.iterdir()))
                self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_combined_index_overlay_trie_rejects_file_symlink_ancestor_conflicts(self):
        for indexed_shape in ("symlink-ancestor", "file-ancestor", "descendant"):
            with self.subTest(indexed_shape=indexed_shape), tempfile.TemporaryDirectory(
                prefix=f"http-public-trie-{indexed_shape}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                outside = base / "outside"
                destination = base / "candidate"
                repository.mkdir()
                outside.mkdir()
                destination.mkdir()
                subprocess.run(
                    ["git", "init", "--quiet"], cwd=repository,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                )
                sentinel = outside / "child.txt"
                sentinel.write_bytes(b"outside sentinel\n")
                if indexed_shape == "symlink-ancestor":
                    tree = repository / "tree"
                    tree.symlink_to(outside)
                    subprocess.run(
                        ["git", "add", "--", "tree"], cwd=repository,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                    )
                    overlay = "tree/child.txt"
                elif indexed_shape == "file-ancestor":
                    tree = repository / "tree"
                    tree.write_bytes(b"indexed ancestor\n")
                    subprocess.run(
                        ["git", "add", "--", "tree"], cwd=repository,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                    )
                    tree.unlink()
                    tree.mkdir()
                    (tree / "child.txt").write_bytes(b"overlay child\n")
                    overlay = "tree/child.txt"
                else:
                    child = repository / "tree/child.txt"
                    child.parent.mkdir()
                    child.write_bytes(b"indexed child\n")
                    subprocess.run(
                        ["git", "add", "--", "tree/child.txt"], cwd=repository,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                    )
                    shutil.rmtree(repository / "tree")
                    (repository / "tree").symlink_to(outside)
                    overlay = "tree"
                real_mkdtemp = tempfile.mkdtemp
                staging_directories = []

                def observed_mkdtemp(*args, **kwargs):
                    created = real_mkdtemp(*args, **kwargs)
                    staging_directories.append(created)
                    return created

                with mock.patch.object(
                    tempfile, "mkdtemp", side_effect=observed_mkdtemp,
                ), self.assertRaises((AssertionError, OSError)):
                    self._copy_from(repository, destination, (overlay,))
                self.assertEqual(
                    [], staging_directories,
                    "D/F conflicts must fail before creating a staging tree",
                )
                self.assertEqual(b"outside sentinel\n", sentinel.read_bytes())
                self.assertEqual([], list(destination.iterdir()))
                self.assertEqual([], list(base.glob(".candidate.materializing-*")))

    def test_git_control_environment_cannot_redirect_canonical_index(self):
        for control in ("GIT_INDEX_FILE", "GIT_DIR_AND_WORK_TREE"):
            with self.subTest(control=control), tempfile.TemporaryDirectory(
                prefix=f"http-public-git-env-{control.lower()}-",
            ) as directory:
                base = Path(directory)
                repository = base / "repository"
                destination = base / "candidate"
                repository.mkdir()
                destination.mkdir()
                source = self._indexed_fixture(repository)
                ambient_before = dict(os.environ)
                hostile_environment = {}
                if control == "GIT_INDEX_FILE":
                    alternate_index = base / "alternate.index"
                    shutil.copyfile(repository / ".git/index", alternate_index)
                    source.write_bytes(b"alternate index bytes\n")
                    environment = os.environ.copy()
                    environment["GIT_INDEX_FILE"] = str(alternate_index)
                    subprocess.run(
                        ["git", "add", "--", "payload.txt"], cwd=repository,
                        env=environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=True,
                    )
                    hostile_environment["GIT_INDEX_FILE"] = str(alternate_index)
                else:
                    alternate = base / "alternate-repository"
                    alternate.mkdir()
                    alternate_source = self._indexed_fixture(
                        alternate, payload=b"alternate repository bytes\n",
                    )
                    self.assertTrue(alternate_source.is_file())
                    hostile_environment.update({
                        "GIT_DIR": str(alternate / ".git"),
                        "GIT_WORK_TREE": str(alternate),
                    })
                source.write_bytes(b"worktree bytes ignored\n")
                with mock.patch.dict(
                    os.environ, hostile_environment, clear=False,
                ):
                    hostile_before = dict(os.environ)
                    self._copy_from(repository, destination)
                    self.assertEqual(hostile_before, dict(os.environ))
                self.assertEqual(
                    b"indexed bytes\n",
                    (destination / "payload.txt").read_bytes(),
                )
                self.assertEqual(ambient_before, dict(os.environ))

    def test_git_replace_ref_cannot_rebind_index_object_id(self):
        with tempfile.TemporaryDirectory(prefix="http-public-git-replace-") as directory:
            base = Path(directory)
            repository = base / "repository"
            destination = base / "candidate"
            repository.mkdir()
            destination.mkdir()
            subprocess.run(
                ["git", "init", "--quiet"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            reviewed = b"reviewed indexed bytes\n"
            replacement = b"replacement-ref bytes\n"
            reviewed_id = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"], cwd=repository,
                input=reviewed, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            ).stdout.decode("ascii").strip()
            replacement_id = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"], cwd=repository,
                input=replacement, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            ).stdout.decode("ascii").strip()
            subprocess.run(
                ["git", "update-index", "--add", "--cacheinfo",
                 f"100644,{reviewed_id},payload.txt"], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            subprocess.run(
                ["git", "replace", reviewed_id, replacement_id], cwd=repository,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            self._copy_from(repository, destination)
            self.assertEqual(reviewed, (destination / "payload.txt").read_bytes())

    def test_fixed_public_overlay_fails_closed_on_missing_or_special_inputs(self):
        with tempfile.TemporaryDirectory(prefix="http-public-overlay-") as directory:
            root = Path(directory)
            regular = root / "regular.txt"
            regular.write_text("public\n", encoding="utf-8")
            symlink = root / "link.txt"
            symlink.symlink_to(regular.name)
            _validate_public_overlay(root, ("regular.txt", "link.txt"))
            with self.assertRaisesRegex(AssertionError, "missing.txt"):
                _validate_public_overlay(root, ("missing.txt",))
            special = root / "directory"
            special.mkdir()
            with self.assertRaisesRegex(AssertionError, "directory"):
                _validate_public_overlay(root, ("directory",))

    def test_real_archive_uses_only_materialized_public_project_inputs(self):
        offenders = []
        for relative, methods in PACKAGING_METHODS.items():
            source = (ROOT / relative).read_text(encoding="utf-8")
            for method in methods:
                start = source.index(f"def {method}(")
                end = source.find("\n    def ", start + 5)
                body = source[start:end if end >= 0 else None]
                if (
                    "materialized_public_project" not in body
                    or EXPECTED_PRIVATE_SITE_PROJECT in body
                ):
                    offenders.append(f"{relative}::{method}")

        package = _load_package_tool()
        with materialized_public_project(ROOT) as project:
            with tempfile.TemporaryDirectory(prefix="public-package-output-") as directory:
                archive = Path(directory) / "public-project-upload.tar.gz"
                args = argparse.Namespace(
                    project=str(project), output=archive, force=False,
                    max_file_size_mib=50, include_images=False,
                    include_apps=False, apps_platform=None, apps_platforms=set(),
                    include_firmware=False, exclude_project_images=True,
                )
                package.create_package(
                    args, day0_all=False, artifact_kind="upload",
                )
                self.assertTrue(archive.is_file())
                prefix = f"./DAY0-Prepare/{project.name}/"
                with tarfile.open(archive, "r:gz") as bundle:
                    names = bundle.getnames()
                    project_names = [name for name in names if name.startswith(prefix)]
                    self.assertTrue(project_names)
                    self.assertFalse(any(
                        EXPECTED_PRIVATE_SITE_PROJECT in name for name in names
                    ))
                    for source_name, destination_name in EXPECTED_PUBLIC_INPUTS.items():
                        member = bundle.extractfile(prefix + destination_name)
                        self.assertIsNotNone(member, destination_name)
                        self.assertEqual(
                            (ROOT / "examples/public-project" / source_name).read_bytes(),
                            member.read(),
                        )
        self.assertEqual([], offenders)

    def test_exact_five_packaging_methods_pass_in_no_local_public_clone(self):
        self.assertEqual(5, len(EXACT_PACKAGING_TESTS))
        q01_documents = {Path(path) for path in P_PUBLISHED_Q01_SHA256}
        forbidden = {
            Path(path) for path in (
                "docs/v3/finished-project-lifecycle/ARCHITECTURE.md",
                "docs/v3/finished-project-lifecycle/OPEN_QUESTIONS.md",
                "docs/v3/finished-project-lifecycle/OVERVIEW.md",
                "docs/v3/finished-project-lifecycle/REQUIREMENTS.md",
                "docs/v3/finished-project-lifecycle/TEST_PLAN.md",
                "docs/v3/finished-project-lifecycle/USER_GUIDE.md",
                "docs/v3/finished-project-lifecycle/WORKFLOWS.md",
                "Finished-projects/README.txt",
                "v3-requirements.md",
                "monitor/cabletracker-main/README.md",
            )
        }
        with tempfile.TemporaryDirectory(prefix="http-public-h27-") as directory:
            base = Path(directory)
            authority = base / "authority"
            candidate = base / "candidate"
            checkout = base / "checkout"
            candidate.mkdir()
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", ROOT, authority],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            for relative in q01_documents:
                target = authority / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            subprocess.run(
                ["git", "add", "--", *(str(path) for path in q01_documents)],
                cwd=authority, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
            with mock.patch.object(sys.modules[__name__], "ROOT", authority):
                candidate_paths = set(_public_candidate_paths())
                self.assertEqual(
                    q01_documents, q01_documents.intersection(candidate_paths),
                )
                self.assertEqual(set(), forbidden.intersection(candidate_paths))
                self.assertFalse(any(
                    relative.as_posix() == root
                    or relative.as_posix().startswith(root + "/")
                    for relative in candidate_paths
                    for root in P_V2_FORBIDDEN_PUBLIC_ROOTS
                ))
                _copy_public_candidate(candidate)
            for relative in q01_documents:
                self.assertEqual(
                    (authority / relative).read_bytes(),
                    (candidate / relative).read_bytes(),
                )
            subprocess.run(
                ["git", "init", "--quiet"], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            subprocess.run(
                ["git", "add", "--all"], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            subprocess.run(
                ["git", "add", "-f", "--", *P0_PUBLIC_OVERLAY], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            rendered = subprocess.run(
                [sys.executable, "-B", "tools/update-user-manual.py"],
                cwd=candidate, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False, timeout=60,
            )
            self.assertEqual(0, rendered.returncode, rendered.stdout + rendered.stderr)
            subprocess.run(
                ["git", "add", "--", "user-manual.html"], cwd=candidate,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Public H27 Contract",
                    "-c", "user.email=public-h27@example.invalid",
                    "commit", "--quiet", "--no-verify", "-m", "public H27 candidate",
                ],
                cwd=candidate, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=True,
            )
            subprocess.run(
                ["git", "clone", "--quiet", "--no-local", candidate, checkout],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            )
            result = subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "-v", *EXACT_PACKAGING_TESTS],
                cwd=checkout, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, check=False, timeout=180,
            )
            combined = result.stdout + result.stderr
            self.assertEqual(0, result.returncode, combined)
            self.assertIn("Ran 5 tests", combined)
            self.assertNotIn(EXPECTED_PRIVATE_SITE_PROJECT, combined)


if __name__ == "__main__":
    unittest.main()
