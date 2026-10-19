#!/usr/bin/env python3
"""Generate one protected local read-only UFM stage probe, never execute it.

This is not complete stage1, deployment permission, an arbitrary shell builder,
remote upload or seven-step completion. Confirmed admin/bash/home/log intent
does not waive endpoint trust, backup, remote command approval or sudo policy.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from dataclasses import dataclass
HTTP_ROOT=Path(__file__).resolve().parents[1]
# The fixed generation CLI imports the same candidate modules under -I,
# rather than depending on a caller's cwd/PYTHONPATH or sibling installation.
for source_root in (HTTP_ROOT,HTTP_ROOT/"tools"):
    if str(source_root) not in sys.path:sys.path.insert(0,str(source_root))
from monitor.switch_collection_gate import active_project_identity
from tools.ufm_identity_binding import _project_declaration

_STAGE="phase1_readonly_preflight"
_DIR_FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
_CAP=524288
_HOST=re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
_INTERFACE=re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
_RUN=re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}")

class ScriptBuildHold(ValueError):
    """No execution is enabled; incomplete or unsafe generation remains HOLD."""

@dataclass(frozen=True)
class StageScriptArtifact:
    run_id: str
    script_path: Path
    manifest_path: Path

def _canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)+"\n").encode()

def _file_key(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

def _dir_key(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)

class _Directories:
    """Held no-follow original name/inode/mode/owner chain.

    Directory nlink counts are filesystem dependent (APFS also changes them
    for our file entries). They are not an immutable ancestor contract.
    Every generated regular file separately requires nlink1 and exact inode.
    """
    def __init__(self,path,*,private=False):
        if (not isinstance(path,Path) or not path.is_absolute() or ".." in path.parts
                or str(path)!=str(path.absolute())):
            raise ScriptBuildHold("local directory path is invalid")
        self.records=[];self.files=[];self.path=path;self.private=private
        try:
            named=os.stat("/",follow_symlinks=False)
            fd=os.open("/",_DIR_FLAGS)
            record={"fd":fd,"name":None,"key":_dir_key(named),"cleanup":None}
            self.records.append(record)
            record["cleanup"]=_dir_key(os.fstat(fd))
            for name in path.parts[1:]:
                parent=self.records[-1]["fd"]
                named=os.stat(name,dir_fd=parent,follow_symlinks=False)
                fd=os.open(name,_DIR_FLAGS,dir_fd=parent)
                record={"fd":fd,"name":name,"key":_dir_key(named),"cleanup":None}
                self.records.append(record)
                record["cleanup"]=_dir_key(os.fstat(fd))
            if private:
                value=os.fstat(self.fd)
                if value.st_uid!=os.getuid() or stat.S_IMODE(value.st_mode)!=0o700:
                    raise ScriptBuildHold("local private log root must be owned 0700")
            self.verify()
        except BaseException:
            primary=sys.exc_info()[1]
            try:self.close()
            except BaseException as cleanup:raise primary from cleanup
            raise
    @property
    def fd(self):return self.records[-1]["fd"]
    def verify(self):
        for index,record in enumerate(self.records):
            actual=os.fstat(record["fd"])
            if not stat.S_ISDIR(actual.st_mode) or _dir_key(actual)!=record["key"]:
                raise ScriptBuildHold("original directory identity changed")
            named=(os.stat("/",follow_symlinks=False) if index==0 else
                os.stat(record["name"],dir_fd=self.records[index-1]["fd"],follow_symlinks=False))
            if _dir_key(named)!=record["key"]:
                raise ScriptBuildHold("original directory named edge changed")
    def child(self,name,*,exclusive=False):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",name):
            raise ScriptBuildHold("generated directory component is unsafe")
        self.verify();created=False
        try:
            os.mkdir(name,0o700,dir_fd=self.fd);created=True
        except FileExistsError:
            if exclusive:raise ScriptBuildHold("unique run directory already exists") from None
        named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        fd=os.open(name,_DIR_FLAGS,dir_fd=self.fd)
        record={"fd":fd,"name":name,"key":_dir_key(named),"cleanup":None}
        self.records.append(record)
        value=os.fstat(fd)
        record["cleanup"]=_dir_key(value)
        if value.st_uid!=os.getuid() or stat.S_IMODE(value.st_mode)!=0o700:
            raise ScriptBuildHold("generated directory ownership/mode is invalid")
        self.path=self.path/name
        self.verify()
    def close(self):
        first=None
        for record in reversed(self.files):
            try:
                actual=os.fstat(record["fd"])
                if record["created"] is None or (actual.st_dev,actual.st_ino)!=(record["created"].st_dev,record["created"].st_ino):
                    raise ScriptBuildHold("generated descriptor cleanup identity UNKNOWN")
                os.close(record["fd"])
            except BaseException as error:first=first or error
        for record in reversed(self.records):
            try:
                actual=os.fstat(record["fd"])
                expected=record["cleanup"] or record["key"]
                if (actual.st_dev,actual.st_ino)!=expected[:2]:
                    raise ScriptBuildHold("directory cleanup identity UNKNOWN")
                os.close(record["fd"])
            except BaseException as error:first=first or error
        self.records.clear();self.files.clear()
        if first is not None:
            raise ScriptBuildHold("owned directory cleanup UNKNOWN") from first

def _capture_source(path):
    named=os.stat(path,follow_symlinks=False)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    primary=None;opened=None
    try:
        opened=os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_size>_CAP
                or _file_key(named)!=_file_key(opened)):
            raise ScriptBuildHold("input must be one bounded original regular file")
        parts=[];size=0
        while True:
            raw=os.read(fd,min(65536,_CAP+1-size))
            if not raw:break
            parts.append(raw);size+=len(raw)
            if size>_CAP:raise ScriptBuildHold("input source exceeds fixed cap")
        final=os.fstat(fd)
        after=os.stat(path,follow_symlinks=False)
        if _file_key(opened)!=_file_key(final) or _file_key(final)!=_file_key(after):
            raise ScriptBuildHold("input source changed during bounded capture")
        data=b"".join(parts)
        return data,_file_key(final),hashlib.sha256(data).hexdigest()
    finally:
        primary=sys.exc_info()[1]
        try:
            actual=os.fstat(fd)
            cleanup_origin=opened if opened is not None else named
            if (actual.st_dev,actual.st_ino)!=(cleanup_origin.st_dev,cleanup_origin.st_ino):
                raise ScriptBuildHold("input descriptor cleanup identity UNKNOWN")
            os.close(fd)
        except BaseException as cleanup:
            hold=ScriptBuildHold("input descriptor cleanup UNKNOWN");hold.__cause__=cleanup
            if primary is not None:raise primary from hold
            raise hold from cleanup

def _render_stage_probe(hostname,interface,run_id):
    if (type(hostname) is not str or not _HOST.fullmatch(hostname)
            or type(interface) is not str or not _INTERFACE.fullmatch(interface)
            or type(run_id) is not str or not _RUN.fullmatch(run_id)):
        raise ScriptBuildHold("fixed probe fields are unsafe")
    return ("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n"
        "# F01 phase1_readonly_preflight: GENERATED_NOT_EXECUTED; no deployment completion\n"
        "printf '%s\\n' 'F01_READ_ONLY_PREFLIGHT' 'run-id="+run_id+
        "' 'node="+hostname+"' 'phase=phase1_readonly_preflight'\n"
        "if ! sudo -n -- true; then\n"
        "  printf '%s\\n' 'F01_BLOCKED_SUDO_CHECK' >&2\n"
        "  exit 73\nfi\n"
        "hostname\nip -j link show dev "+interface+"\nip -j address show dev "+interface+"\n").encode()

def _readback_original(directory,record):
    """Four-stat, bounded actual bytes on the SAME original readable FD."""
    directory.verify()
    before_named=os.stat(record["name"],dir_fd=directory.fd,follow_symlinks=False)
    before=os.fstat(record["fd"]);created=record["created"]
    if (created is None or _dir_key(before)!=_dir_key(created) or before.st_nlink!=1
            or before.st_size!=len(record["expected"]) or _file_key(before)!=_file_key(before_named)
            or (record["key"] is not None and _file_key(before)!=record["key"])):
        raise ScriptBuildHold("generated original file identity changed")
    if os.lseek(record["fd"],0,os.SEEK_SET)!=0:
        raise ScriptBuildHold("original generated read offset is unknown")
    chunks=[];size=0
    while True:
        raw=os.read(record["fd"],min(65536,len(record["expected"])+1-size))
        if not raw:break
        chunks.append(raw);size+=len(raw)
        if size>len(record["expected"]):raise ScriptBuildHold("original generated content exceeds expected bound")
    after=os.fstat(record["fd"])
    after_named=os.stat(record["name"],dir_fd=directory.fd,follow_symlinks=False)
    actual=b"".join(chunks)
    if (not _file_key(before)==_file_key(after)==_file_key(after_named)
            or actual!=record["expected"]):
        raise ScriptBuildHold("original generated content verification failed")
    digest=hashlib.sha256(actual).hexdigest()
    if record["sha256"] is not None and digest!=record["sha256"]:
        raise ScriptBuildHold("original generated digest changed")
    directory.verify()
    return _file_key(after),digest

def _write_original(directory,name,data):
    if type(data) is not bytes or len(data)>_CAP:
        raise ScriptBuildHold("fixed generated content is invalid")
    directory.verify()
    fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
    record={"fd":fd,"name":name,"created":None,"expected":data,"key":None,"sha256":None}
    directory.files.append(record) # actual FD retained even on admission error
    created=os.fstat(fd);record["created"]=created
    if (not stat.S_ISREG(created.st_mode) or created.st_nlink!=1
            or created.st_uid!=os.getuid() or stat.S_IMODE(created.st_mode)!=0o600):
        raise ScriptBuildHold("generated file ownership/mode is invalid")
    view=memoryview(data)
    while view:
        written=os.write(fd,view)
        if written<=0:raise ScriptBuildHold("generated file write incomplete")
        view=view[written:]
    os.fsync(fd)
    record["key"],record["sha256"]=_readback_original(directory,record)
    return record

def _verify_original_artifacts(directory):
    for record in directory.files:
        if record["key"] is None or record["sha256"] is None:
            raise ScriptBuildHold("generated artifact was never confirmed")
        if _readback_original(directory,record)!=(record["key"],record["sha256"]):
            raise ScriptBuildHold("generated artifact changed before return")

def generate_stage_script(*,address,private_logs_root,stage=_STAGE):
    """Fixed active project -> unique local readonly probe and retained evidence.

    No passwords/private keys/caller commands/project override. Basename is not
    sufficient: the real no-follow private root must be outside the entire
    current HTTP tree and active project, independent of old bringup outputs.
    This API does not authorize execution even after successful generation.
    """
    if stage!=_STAGE:
        raise ScriptBuildHold("unknown vendor write-stage contract; generation is BLOCKED")
    logs=directory=project_chain=None;run_id=None
    try:
        http=Path(HTTP_ROOT)
        project=Path(active_project_identity(http))
        if (not http.is_absolute() or http.resolve(strict=True)!=http
                or project.parent!=http/"DAY0-Prepare" or project.resolve(strict=True)!=project):
            raise ScriptBuildHold("active project location is invalid")
        if (not isinstance(private_logs_root,Path) or not private_logs_root.is_absolute()
                or private_logs_root.name!="xdr-initial-setup-logs"
                or private_logs_root==http or http in private_logs_root.parents
                or private_logs_root==project or project in private_logs_root.parents):
            raise ScriptBuildHold("private logs may not use HTTP/project/bringup output")
        logs=_Directories(private_logs_root,private=True)
        project_chain=_Directories(project)
        selection=http/"monitor/02-devices_config.csv"
        selection_key=(_file_key(selection.lstat()),os.readlink(selection))
        paths=(project/"01-global.yaml",project/"02-devices_config.csv")
        captured=tuple(_capture_source(path) for path in paths)
        declaration,interface,sources=_project_declaration(project)
        if tuple(digest for _path,digest in sources)!=tuple(x[2] for x in captured):
            raise ScriptBuildHold("declaration does not match captured original input")
        selected=[node for node in declaration.members if node.address==address]
        if len(selected)!=1:raise ScriptBuildHold("probe target is not an exact complete-project member")
        node=selected[0]
        def verify_inputs():
            project_chain.verify()
            if (active_project_identity(http)!=str(project)
                    or (_file_key(selection.lstat()),os.readlink(selection))!=selection_key
                    or tuple(_capture_source(path) for path in paths)!=captured):
                raise ScriptBuildHold("original project selection/input changed")
        verify_inputs()
        run_id=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+secrets.token_hex(16)
        project_key=hashlib.sha256(str(project).encode()).hexdigest()
        logs.child(project_key)
        logs.child(run_id,exclusive=True)
        logs.child(node.hostname,exclusive=True)
        logs.child(stage,exclusive=True)
        directory=logs
        script=_render_stage_probe(node.hostname,interface,run_id)
        script_record=_write_original(directory,"stage.sh",script)
        verify_inputs()
        manifest={"schema_version":1,"state":"GENERATED_NOT_EXECUTED",
            "project_key":project_key,"project_root":str(project),"run_id":run_id,
            "node":node.hostname,"node_ipv4":node.address,"management_interface":interface,
            "stage":stage,"login_user":"admin","interpreter":"bash",
            "input_sha256":{path.name:item[2] for path,item in zip(paths,captured)},
            "script_sha256":script_record["sha256"],"script_bytes":len(script),
            "syntax_check":"NOT_RUN","sudo_check_scope":"sudo -n true only; not NOPASSWD or vendor command permission",
            "execution_permitted":False,"completion":False}
        _write_original(directory,"manifest.json",_canonical(manifest))
        verify_inputs();_verify_original_artifacts(directory);directory.verify();os.fsync(directory.fd)
        _verify_original_artifacts(directory);verify_inputs()
        return StageScriptArtifact(run_id,directory.path/"stage.sh",directory.path/"manifest.json")
    except BaseException as primary:
        if directory is not None:
            try:
                _write_original(directory,"failure.json",_canonical({"state":"FAILED_NOT_EXECUTED",
                    "run_id":run_id,"cause_type":type(primary).__name__,"execution_permitted":False,"completion":False}))
            except BaseException as secondary:
                hold=ScriptBuildHold("generation failed; failure evidence retention UNKNOWN");hold.__cause__=secondary
                raise primary from hold
        if isinstance(primary,ScriptBuildHold) or not isinstance(primary,Exception):raise
        raise ScriptBuildHold("local script generation remains HOLD") from None
    finally:
        primary=sys.exc_info()[1];cleanup=None
        for original in (project_chain,logs):
            if original is not None:
                try:original.close()
                except BaseException as error:cleanup=cleanup or error
        if cleanup is not None:
            hold=ScriptBuildHold("script generation owned cleanup UNKNOWN");hold.__cause__=cleanup
            if primary is not None:raise primary from hold
            raise hold from cleanup

def main(argv=None):
    parser=argparse.ArgumentParser(description="Generate only one fixed UFM read-only stage probe")
    parser.add_argument("--address",required=True)
    parser.add_argument("--private-logs-root",required=True,type=Path)
    parser.add_argument("--stage",default=_STAGE)
    args=parser.parse_args(argv)
    try:
        result=generate_stage_script(address=args.address,private_logs_root=args.private_logs_root,stage=args.stage)
    except ScriptBuildHold:
        print("UFM local stage generation HOLD; no device operation performed",file=sys.stderr)
        return 2
    print(json.dumps({"state":"GENERATED_NOT_EXECUTED","run_id":result.run_id,
        "script":str(result.script_path),"manifest":str(result.manifest_path),"execution_permitted":False},sort_keys=True))
    return 0
if __name__=="__main__":raise SystemExit(main())
