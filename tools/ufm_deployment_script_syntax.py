#!/usr/bin/env python3
"""Fixed local syntax diagnostic; never script execution or device permission.

Only the checked readonly builder template is accepted by the public entry.
The private original-FD primitive can diagnose invalid syntax but cannot grant
generation, upload, SSH access, stage execution or deployment completion.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from tools import ufm_deployment_script_builder as _builder

_LIMIT = 10.0
_CAP = 524288
_OUTPUT_CAP = 65536
_STAGE = "phase1_readonly_preflight"

class SyntaxCheckHold(ValueError):
    def __init__(self, message, *, child_facts=None):
        super().__init__(message)
        self.child_facts = child_facts

@dataclass(frozen=True)
class StageSyntaxResult:
    state: str
    evidence_path: Path
    execution_permitted: bool = False
    completion: bool = False

def _close_owned_fd(fd, expected):
    actual = os.fstat(fd)
    if (actual.st_dev, actual.st_ino) != expected:
        raise SyntaxCheckHold("original descriptor cleanup identity UNKNOWN")
    os.close(fd)

class _OwnedFDs:
    def __init__(self):
        self.records = []
    def adopt(self, fd, *, fallback=None):
        record = {"fd": fd, "identity": fallback, "closed": False}
        self.records.append(record)  # register actual acquisition before metadata
        value = os.fstat(fd)
        record["identity"] = (value.st_dev, value.st_ino)
        return record, value
    def close_one(self, record):
        if not record["closed"]:
            if record["identity"] is None:
                raise SyntaxCheckHold("acquired descriptor cleanup identity UNKNOWN")
            _close_owned_fd(record["fd"], record["identity"])
            record["closed"] = True
    def close(self):
        first = None
        for record in reversed(self.records):
            try:
                self.close_one(record)
            except BaseException as error:
                first = first or error
        if first is not None:
            raise SyntaxCheckHold("owned descriptors cleanup UNKNOWN") from first

def _run_syntax_child(*, script_fd, cwd, deadline):
    """Borrow only the original script FD; own exactly one fixed bash child.

    Actual owned waitpid returns, not cached Popen.wait or EBADF, prove reaping.
    No new session, shell=True, environment credential, stdin script command,
    descendant probing, child hook or arbitrary executable is supported.
    """
    owner = _OwnedFDs()
    process = None
    selector = None
    ownership_unknown = False
    facts = {
        "pid": None, "argv": ["/bin/bash", "-n", "--", "/dev/fd/" + str(script_fd)],
        "pass_fds": [script_fd], "close_fds": True,
        "actual_waitpid_return": None, "kernel_reap_confirmed": False,
        "stdout_eof": False, "stderr_eof": False, "stdout_bytes": 0,
        "stderr_bytes": 0, "exit_code": None, "raw_pipe_cleanup_confirmed": False,
        "cleanup_unconfirmed": [], "selector_cleanup_confirmed": False,
        "execution_permitted": False, "completion": False,
    }
    digests = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    def reap():
        nonlocal ownership_unknown
        if facts["kernel_reap_confirmed"] or process is None:
            return
        try:
            pid, status = os.waitpid(process.pid, os.WNOHANG)
        except ChildProcessError:
            ownership_unknown = True
            raise SyntaxCheckHold("actual owned child reap UNKNOWN", child_facts=facts) from None
        if pid == process.pid:
            facts["actual_waitpid_return"] = pid
            facts["kernel_reap_confirmed"] = True
            facts["exit_code"] = os.waitstatus_to_exitcode(status)
            process.returncode = facts["exit_code"]
        elif pid != 0:
            ownership_unknown = True
            raise SyntaxCheckHold("unexpected owned waitpid result", child_facts=facts)
    reads = {}
    def drain_once(bound):
        remaining = bound - time.monotonic()
        if remaining <= 0:
            return
        if not reads:
            time.sleep(min(0.01, remaining))
            return
        try:
            ready = selector.select(min(0.01, remaining))
        except InterruptedError:
            return
        for key, _events in ready:
            fd = key.fd
            role = key.data
            try:
                raw = os.read(fd, 4096)
            except (BlockingIOError, InterruptedError):
                continue
            if not raw:
                facts[role + "_eof"] = True
                selector.unregister(fd)
                del reads[fd]
            else:
                facts[role + "_bytes"] += len(raw)
                digests[role].update(raw)
                if facts["stdout_bytes"] + facts["stderr_bytes"] > _OUTPUT_CAP:
                    raise SyntaxCheckHold("syntax output exceeded fixed bound", child_facts=facts)
    try:
        if (type(script_fd) is not int or type(deadline) not in (int, float)
                or not isinstance(cwd, Path) or not cwd.is_absolute()
                or ".." in cwd.parts or time.monotonic() >= deadline - 0.25):
            raise SyntaxCheckHold("syntax child input/deadline is invalid", child_facts=facts)
        writes = []
        for role in ("stdout", "stderr"):
            pair = os.pipe()
            # Both actual acquisitions are registered before a first stat fails.
            first = {"fd": pair[0], "identity": None, "closed": False}
            second = {"fd": pair[1], "identity": None, "closed": False}
            owner.records.extend((first, second))
            for item in (first, second):
                value = os.fstat(item["fd"])
                item["identity"] = (value.st_dev, value.st_ino)
            os.set_blocking(pair[0], False)
            reads[pair[0]] = role
            writes.append(second)
        selector = selectors.DefaultSelector()
        for fd, role in reads.items():
            selector.register(fd, selectors.EVENT_READ, role)
        process = subprocess.Popen(
            facts["argv"], stdin=subprocess.DEVNULL,
            stdout=writes[0]["fd"], stderr=writes[1]["fd"],
            cwd=os.fspath(cwd), env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            close_fds=True, pass_fds=(script_fd,), shell=False,
        )
        # Preserve actual self/PID immediately, before optional evidence fields.
        facts["pid"] = process.pid
        for record in writes:
            owner.close_one(record)
        work_deadline = deadline - 0.25
        while time.monotonic() < work_deadline:
            reap()
            if facts["kernel_reap_confirmed"] and not reads:
                break
            drain_once(work_deadline)
        if not (facts["kernel_reap_confirmed"] and not reads):
            raise SyntaxCheckHold("fixed syntax deadline/EOF remains HOLD", child_facts=facts)
        if facts["exit_code"] != 0:
            raise SyntaxCheckHold("fixed bash syntax rejected", child_facts=facts)
        return facts
    finally:
        primary = sys.exc_info()[1]
        cleanup = None
        if process is not None and not facts["kernel_reap_confirmed"]:
            # Only a child created here and not independently ECHILD-reaped may
            # be signalled. Never consult/probe another numeric PID.
            try:
                if not ownership_unknown:
                    os.kill(process.pid, signal.SIGKILL)
                    while time.monotonic() < deadline:
                        reap()
                        if facts["kernel_reap_confirmed"] and not reads:
                            break
                        drain_once(deadline)
                if not facts["kernel_reap_confirmed"]:
                    raise SyntaxCheckHold("actual owned child termination UNKNOWN")
            except BaseException as error:
                cleanup = error
                facts["cleanup_unconfirmed"].append("child_kernel_reap")
        if selector is not None:
            try:
                native = getattr(selector, "_selector", None)
                selector.close()
                native_closed = getattr(native, "closed", None)
                if (selector.get_map() is not None or
                        (native_closed is not None and native_closed is not True)):
                    raise SyntaxCheckHold("owned selector cleanup UNKNOWN")
                facts["selector_cleanup_confirmed"] = True
            except BaseException as error:
                cleanup = cleanup or error
                facts["cleanup_unconfirmed"].append("selector_close")
        try:
            owner.close()
        except BaseException as error:
            cleanup = cleanup or error
            facts["cleanup_unconfirmed"].append("original_pipe_close")
        facts["raw_pipe_cleanup_confirmed"] = all(record["closed"] for record in owner.records)
        for role, digest in digests.items():
            facts[role + "_sha256"] = digest.hexdigest()
        if cleanup is not None:
            hold = SyntaxCheckHold("syntax child cleanup UNKNOWN", child_facts=facts)
            hold.__cause__ = cleanup
            if primary is not None:
                if isinstance(primary, SyntaxCheckHold):
                    primary.child_facts = facts
                raise primary from hold
            raise hold from cleanup

def _read_held(directory, record):
    directory.verify()
    before = os.fstat(record["fd"])
    named = os.stat(record["name"], dir_fd=directory.fd, follow_symlinks=False)
    if (_builder._file_key(before) != record["key"]
            or _builder._file_key(named) != record["key"]):
        raise SyntaxCheckHold("original script/manifest named identity changed")
    parts = []
    offset = 0
    while True:
        raw = os.pread(record["fd"], min(65536, _CAP + 1 - offset), offset)
        if not raw:
            break
        parts.append(raw)
        offset += len(raw)
        if offset > _CAP:
            raise SyntaxCheckHold("original syntax artifact exceeds fixed cap")
    after = os.fstat(record["fd"])
    named_after = os.stat(record["name"], dir_fd=directory.fd, follow_symlinks=False)
    if not record["key"] == _builder._file_key(after) == _builder._file_key(named_after):
        raise SyntaxCheckHold("original artifact changed during readback")
    directory.verify()
    return b"".join(parts)

def _open_original(directory, owner, name):
    directory.verify()
    named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory.fd)
    record, actual = owner.adopt(fd, fallback=(named.st_dev, named.st_ino))
    record.update(name=name, key=_builder._file_key(actual))
    if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1
            or actual.st_uid != os.getuid() or stat.S_IMODE(actual.st_mode) != 0o600
            or actual.st_size > _CAP or record["key"] != _builder._file_key(named)):
        raise SyntaxCheckHold("syntax artifact original admission rejected")
    record["raw"] = _read_held(directory, record)
    return record

def _unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SyntaxCheckHold("duplicate manifest field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def _validate_held_stage(*, script_path, http, project, logs, directory,
                         project_chain, originals, deadline):
    """Private fixed consumer admission; no permission, DTO or caller command."""
    selection = http / "monitor/02-devices_config.csv"
    selection_key = (_builder._file_key(selection.lstat()), os.readlink(selection))
    paths = (project / "01-global.yaml", project / "02-devices_config.csv")
    captured = tuple(_builder._capture_source(path) for path in paths)
    declaration, interface, sources = _builder._project_declaration(project)
    if tuple(digest for _path, digest in sources) != tuple(item[2] for item in captured):
        raise SyntaxCheckHold("current declaration differs from original inputs")
    script = _open_original(directory, originals, "stage.sh")
    manifest = _open_original(directory, originals, "manifest.json")
    metadata = _unique_json(manifest["raw"])
    run_id = metadata.get("run_id")
    node_name = metadata.get("node")
    if (type(run_id) is not str or not _builder._RUN.fullmatch(run_id)
            or type(node_name) is not str):
        raise SyntaxCheckHold("generated node/run-id fields invalid")
    nodes = [node for node in declaration.members if node.hostname == node_name]
    if len(nodes) != 1:
        raise SyntaxCheckHold("generated node not a unique current member")
    node = nodes[0]
    project_key = hashlib.sha256(str(project).encode()).hexdigest()
    expected_path = logs / project_key / run_id / node.hostname / _STAGE / "stage.sh"
    expected_script = _builder._render_stage_probe(node.hostname, interface, run_id)
    expected = {
        "schema_version": 1, "state": "GENERATED_NOT_EXECUTED",
        "project_key": project_key, "project_root": str(project), "run_id": run_id,
        "node": node.hostname, "node_ipv4": node.address, "management_interface": interface,
        "stage": _STAGE, "login_user": "admin", "interpreter": "bash",
        "input_sha256": {path.name: item[2] for path, item in zip(paths, captured)},
        "script_sha256": hashlib.sha256(expected_script).hexdigest(),
        "script_bytes": len(expected_script), "syntax_check": "NOT_RUN",
        "sudo_check_scope": "sudo -n true only; not NOPASSWD or vendor command permission",
        "execution_permitted": False, "completion": False,
    }
    if (script_path != expected_path or script["raw"] != expected_script
            or metadata != expected or type(metadata["schema_version"]) is not int
            or type(metadata["script_bytes"]) is not int
            or metadata["execution_permitted"] is not False or metadata["completion"] is not False):
        raise SyntaxCheckHold("fixed template/manifest/current source binding differs")
    binding = dict(node=node.hostname, node_ipv4=node.address, run_id=run_id,
                   stage=_STAGE, input_sha256=expected["input_sha256"],
                   script_sha256=expected["script_sha256"])
    def verify():
        project_chain.verify()
        if (_builder.active_project_identity(http) != str(project)
                or (_builder._file_key(selection.lstat()), os.readlink(selection)) != selection_key
                or tuple(_builder._capture_source(path) for path in paths) != captured):
            raise SyntaxCheckHold("current original selected inputs changed")
        for record in (script, manifest):
            if _read_held(directory, record) != record["raw"]:
                raise SyntaxCheckHold("held script/manifest content changed")
        if time.monotonic() >= deadline:
            raise SyntaxCheckHold("fixed syntax total deadline expired")
    return script, manifest, metadata, binding, verify

def _validate_managed_held_stage(*, script_path, http, project, directory,
                                 project_chain, originals, managed_graph, deadline):
    """Actual managed01 originals only; no issued source/native permission.

    The factory owns every supplied holder. The original managed manifest is
    never rewritten into the historical outside-HTTP schema.
    """
    from tools import ufm_managed_output_binding as managed
    actual_project, output, inputs = managed._capture_layout(
        managed_graph, http, http/"infiniband/bringup/ufm/ufm-setup-logs")
    if actual_project != project or script_path.name != "01-readonly-preflight.sh":
        raise SyntaxCheckHold("managed source is not the selected project readonly01")
    project_chain.verify()
    script = _open_original(directory, originals, "01-readonly-preflight.sh")
    manifest = _open_original(directory, originals, "manifest.json")
    metadata = _unique_json(manifest["raw"])
    run_id, node_name = metadata.get("run_id"), metadata.get("node")
    if (type(run_id) is not str or not _builder._RUN.fullmatch(run_id)
            or type(node_name) is not str):
        raise SyntaxCheckHold("managed node/run-id fields invalid")
    declaration, interface, sources = _builder._project_declaration(project)
    if any(hashlib.sha256(inputs[path.name]).hexdigest() != digest for path, digest in sources):
        raise SyntaxCheckHold("managed declaration differs from held original inputs")
    nodes = [node for node in declaration.members if node.hostname == node_name]
    if len(nodes) != 1:
        raise SyntaxCheckHold("managed node is not one current CSV member")
    node = nodes[0]
    expected_path = output.path/run_id/node.hostname/"scripts/01-readonly-preflight.sh"
    if script_path != expected_path or directory.path != expected_path.parent:
        raise SyntaxCheckHold("managed script name/parent differs")
    for path in (output.path, output.path/run_id, output.path/run_id/node.hostname, expected_path.parent):
        managed_graph.directory(path, private=True)
    source_directory = managed_graph.directory(expected_path.parent, private=True)
    if _builder._dir_key(os.fstat(source_directory.fd)) != _builder._dir_key(os.fstat(directory.fd)):
        raise SyntaxCheckHold("managed original source directory differs")
    expected_script = _builder._render_stage_probe(node.hostname, interface, run_id)
    expected = {"schema_version":1, "state":"GENERATED_NOT_EXECUTED",
        "project_key":hashlib.sha256(str(project).encode()).hexdigest(), "project_root":str(project),
        "run_id":run_id, "node":node.hostname, "node_ipv4":node.address,
        "logical_step_id":_STAGE, "script_sha256":hashlib.sha256(expected_script).hexdigest(),
        "input_sha256":{name:hashlib.sha256(raw).hexdigest() for name, raw in inputs.items()},
        "syntax_check":"NOT_RUN", "execution_permitted":False, "completion":False}
    if (metadata != expected or type(metadata["schema_version"]) is not int
            or metadata["execution_permitted"] is not False or metadata["completion"] is not False
            or script["raw"] != expected_script):
        raise SyntaxCheckHold("managed manifest/template/original inputs differ")
    selection = http/"monitor/02-devices_config.csv"
    selection_key = (_builder._file_key(selection.lstat()), os.readlink(selection))
    paths = (project/"01-global.yaml", project/"02-devices_config.csv")
    source_records = tuple(next(record for record in managed_graph.files if record["name"] == path.name)
                           for path in paths)
    captured = tuple((record["raw"], record["key"], hashlib.sha256(record["raw"]).hexdigest())
                     for record in source_records)
    binding = dict(node=node.hostname, node_ipv4=node.address, run_id=run_id,
                   stage=_STAGE, management_interface=interface, input_sha256=expected["input_sha256"],
                   script_sha256=expected["script_sha256"])
    def verify():
        project_chain.verify();managed_graph.verify();directory.verify()
        if (_builder.active_project_identity(http) != str(project)
                or (_builder._file_key(selection.lstat()), os.readlink(selection)) != selection_key):
            raise SyntaxCheckHold("managed original selection changed")
        for path, original, record in zip(paths, captured, source_records):
            raw, key, _digest = original
            before = os.fstat(record["fd"])
            named = os.stat(path.name, dir_fd=project_chain.fd, follow_symlinks=False)
            actual = os.pread(record["fd"], managed._CAP+1, 0)
            after = os.fstat(record["fd"])
            if not key == _builder._file_key(before) == _builder._file_key(named) == _builder._file_key(after) or actual != raw:
                raise SyntaxCheckHold("managed original declaration FD/name/bytes changed")
        for record in (script, manifest):
            if _read_held(directory, record) != record["raw"]:
                raise SyntaxCheckHold("managed original script/manifest changed")
        if time.monotonic() >= deadline:
            raise SyntaxCheckHold("fixed syntax total deadline expired")
    verify()
    return script, manifest, metadata, binding, verify

def check_stage_script_syntax(*, script_path):
    """Fixed current-project readonly original artifact -> syntax-only evidence.

    Not an SSH permission, future execution grant, caller script approval or
    deployment state machine. The original builder manifest is never edited.
    """
    started = time.monotonic()
    deadline = started + _LIMIT
    directory = project_chain = None
    originals = _OwnedFDs()
    child = None
    evidence_path = None
    metadata = {}
    primary = None
    proof = {"schema_version": 1, "state": "FAILED_NOT_EXECUTED",
             "execution_permitted": False, "completion": False}
    try:
        if (not isinstance(script_path, Path) or not script_path.is_absolute()
                or ".." in script_path.parts or script_path.name != "stage.sh"
                or len(script_path.parents) < 5):
            raise SyntaxCheckHold("fixed generated script path is invalid")
        http = Path(_builder.HTTP_ROOT)
        project = Path(_builder.active_project_identity(http))
        if (not http.is_absolute() or http.resolve(strict=True) != http
                or project.parent != http / "DAY0-Prepare"
                or project.resolve(strict=True) != project):
            raise SyntaxCheckHold("current selected project identity is invalid")
        logs = script_path.parents[4]
        if (logs.name != "xdr-initial-setup-logs" or logs == http
                or http in logs.parents or logs == project or project in logs.parents):
            raise SyntaxCheckHold("syntax evidence may not use public/project log root")
        directory = _builder._Directories(script_path.parent, private=True)
        for record in directory.records[-5:]:
            value = os.fstat(record["fd"])
            if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o700:
                raise SyntaxCheckHold("generated private ancestor ownership/mode invalid")
        project_chain = _builder._Directories(project)
        script, manifest, metadata, binding, verify = _validate_held_stage(
            script_path=script_path, http=http, project=project, logs=logs,
            directory=directory, project_chain=project_chain,
            originals=originals, deadline=deadline)
        proof.update(binding)
        verify()
        child = _run_syntax_child(script_fd=script["fd"], cwd=directory.path, deadline=deadline)
        verify()
        proof["state"] = "CHECKED_NOT_EXECUTED"
        # Result is returned only after original resource/evidence cleanup.
    except BaseException as error:
        primary = error
        if not isinstance(error, Exception):
            raise
        if isinstance(error, SyntaxCheckHold):
            child = error.child_facts or child
            raise
        raise SyntaxCheckHold("fixed local syntax validation HOLD") from error
    finally:
        primary = sys.exc_info()[1]
        cleanup = None
        try:
            originals.close()
        except BaseException as error:
            cleanup = error
        if directory is not None:
            proof["child"] = child
            proof["state"] = "FAILED_NOT_EXECUTED" if primary is not None or cleanup is not None else proof["state"]
            proof["cause_type"] = type(primary or cleanup).__name__ if primary or cleanup else None
            proof["elapsed_seconds"] = time.monotonic() - started
            proof["resource_confirmation"] = "Only an API return after finally confirms success; this file alone grants nothing."
            name = "syntax-check-" + secrets.token_hex(16) + ".json"
            try:
                _builder._write_original(directory, name, _builder._canonical(proof))
                _builder._verify_original_artifacts(directory)
                evidence_path = directory.path / name
            except BaseException as error:
                cleanup = cleanup or error
        for owner in (project_chain, directory):
            if owner is not None:
                try:
                    owner.close()
                except BaseException as error:
                    cleanup = cleanup or error
        if time.monotonic() >= deadline:
            cleanup = cleanup or SyntaxCheckHold("fixed syntax total deadline expired")
        if cleanup is not None:
            hold = SyntaxCheckHold("syntax original resource/evidence cleanup UNKNOWN", child_facts=child)
            hold.__cause__ = cleanup
            if primary is not None:
                raise primary from hold
            raise hold from cleanup
    return StageSyntaxResult(proof["state"], evidence_path)
