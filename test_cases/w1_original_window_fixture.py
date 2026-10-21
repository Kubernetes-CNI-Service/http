"""Finite owned local-file consistency fixture; no online permission or SDK."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest import mock
from test_cases import cold_completed_original_attach_fixture as base

PROGRAM=("import sys\n"
    "sys.path.insert(0,sys.argv[1])\n"
    "from test_cases.w1_original_window_fixture import child_entry\n"
    "raise SystemExit(child_entry(sys.argv[2],sys.argv[3]))\n")


def child_entry(data_root,manifest_path):
    from monitor import issue_tracker_publish_runtime as runtime
    from monitor import issue_tracker_whitelist_workbook as workbook
    from monitor import collection_ib_producer as producer
    from monitor import issue_tracker_credential_shape as credential
    from monitor import issue_tracker_online_target as target
    from monitor import issue_tracker_local_commit as local
    root=Path(data_root);manifest=Path(manifest_path)
    expected=json.loads(manifest.read_bytes())['graph']
    selected=root/'monitor/Issue_Tracker_Template_v1.xlsx'
    saved=manifest.parent/'original-template'
    project=root/'DAY0-Prepare/fabric-a';lock=project/'.tracker/LOCK'
    lock_parent=os.lstat(lock.parent);lock_identity=base.identity(os.lstat(lock))
    writer_code=local._writer_owner.__wrapped__.__code__
    a_method=runtime._hold_current_cable_cycle_source.__wrapped__
    consumer=workbook.read_whitelist_workbook
    parser=workbook._parse_xlsx_bytes;held_reader=workbook._read_held_bytes
    raw_method=runtime._CableOriginals.raw
    real_os=workbook.os;actual_read=os.read;actual_pread=os.pread
    if runtime.read_whitelist_workbook is not consumer:
        raise RuntimeError('actual W1 consumer alias prerequisite absent')
    facts=dict(observer_errors=[],healthy_complete=False,healthy_semantics=[],
        healthy_same_fd_semantics=False,healthy_slots_closed=False,healthy_local_revoked=False,
        audit_armed=False,arm_count=0,actual_a_frame=False,actual_pin_live=False,
        same_bytes_new_inode=False,same_mode=False,restored_original=False,
        foreign_open_count=0,foreign_read_count=0,fault_parser_completed=False,
        window_error_type=None,fault_originals_closed=False,fault_slots_closed=False,
        fault_local_revoked=False,fault_slot_count=0,lease_closed=False,
        profile_restored=False,network=0,nested_children=0,lock_rdwr_allowed=0)
    if sys.getprofile() is not None:raise RuntimeError('existing profile cannot be replaced')
    phase='healthy';mutating=False;armed=False
    pin=None;pin_key=None;pin_digest=None
    healthy_originals=None;healthy_token=None
    fault_originals=None;fault_token=None
    opened={};read_calls={};semantic_reads=[]

    def restore():
        nonlocal mutating,armed
        if armed:
            mutating=True
            try:
                os.replace(saved,selected)
                current=os.lstat(selected)
                facts['restored_original']=(current.st_dev,current.st_ino)==pin_key
            finally:mutating=False;armed=False

    def deny(event,args):
        if event.startswith('socket.'):
            facts['network']+=1;raise AssertionError('owned local fixture network forbidden')
        if event=='subprocess.Popen':
            facts['nested_children']+=1;raise AssertionError('owned local fixture nested child forbidden')
        if event in ('os.rename','os.remove','os.mkdir','os.rmdir','os.chmod','os.link','os.symlink','os.truncate','os.utime','os.chown'):
            if mutating and event=='os.rename' and len(args)>=2 and (Path(args[0]),Path(args[1])) in ((selected,saved),(saved,selected)):return
            if mutating and event=='os.chmod' and Path(args[0])==selected:return
            raise AssertionError('mutation outside two owned fixture paths forbidden')
        if event=='open' and len(args)>=3 and type(args[2]) is int:
            flags=args[2]
            if flags & os.O_ACCMODE==os.O_RDWR and not flags & (os.O_CREAT|os.O_TRUNC|os.O_APPEND|os.O_EXCL):
                caller=sys._getframe(1);root_fd=caller.f_locals.get('root_fd')
                if (caller.f_code is writer_code and caller.f_globals is local.__dict__
                        and args[0]=='LOCK' and type(root_fd) is int
                        and caller.f_locals.get('project')==project
                        and (os.fstat(root_fd).st_dev,os.fstat(root_fd).st_ino)==(lock_parent.st_dev,lock_parent.st_ino)
                        and base.identity(os.stat('LOCK',dir_fd=root_fd,follow_symlinks=False))==lock_identity
                        and base.identity(os.lstat(lock))==lock_identity):
                    facts['lock_rdwr_allowed']+=1;return
            if flags & (os.O_CREAT|os.O_TRUNC|os.O_APPEND|os.O_WRONLY|os.O_RDWR):
                if mutating and Path(args[0])==selected and flags & os.O_EXCL:return
                raise AssertionError('write-open outside owned fixture path forbidden')

    class WorkbookOS:
        def __getattr__(self,name):return getattr(real_os,name)
        def open(self,path,flags,*args,**kwargs):
            descriptor=real_os.open(path,flags,*args,**kwargs)
            if Path(path)==selected and armed:
                held=os.fstat(descriptor);key=(held.st_dev,held.st_ino);opened[descriptor]=key
                if key!=pin_key:facts['foreign_open_count']+=1
            return descriptor

    def current_consumer(frame):
        cursor=frame
        while cursor is not None:
            if (cursor.f_code is consumer.__code__ and cursor.f_globals is consumer.__globals__
                    and Path(cursor.f_locals.get('path',''))==selected):return cursor
            cursor=cursor.f_back
        return None

    def observe(frame,event,value):
        nonlocal phase,mutating,armed,pin,pin_key,pin_digest
        nonlocal healthy_originals,healthy_token,fault_originals,fault_token
        try:
            is_consumer=frame.f_code is consumer.__code__ and frame.f_globals is consumer.__globals__
            is_parser=frame.f_code is parser.__code__ and frame.f_globals is parser.__globals__
            is_held=frame.f_code is held_reader.__code__ and frame.f_globals is held_reader.__globals__
            is_raw=frame.f_code is raw_method.__code__ and frame.f_globals is raw_method.__globals__
            if not (is_consumer or is_parser or is_held or is_raw):return
            ancestor=current_consumer(frame)
            if ancestor is None:return
            if event in ('c_call','c_return'):
                if (armed and is_consumer and event=='c_call' and value is os.fstat):
                    descriptor=frame.f_locals.get('fd',frame.f_locals.get('descriptor'))
                    if type(descriptor) is int and descriptor not in opened:
                        held=os.fstat(descriptor);key=(held.st_dev,held.st_ino);opened[descriptor]=key
                        if key!=pin_key:facts['foreign_open_count']+=1
                primitive=(is_held and value is actual_read) or (is_raw and value is actual_pread)
                if primitive:
                    descriptor=frame.f_locals.get('fd',frame.f_locals.get('descriptor'))
                    if type(descriptor) is int:
                        tag=(id(frame),descriptor,phase)
                        if event=='c_call':read_calls[tag]=True
                        elif read_calls.get(tag):
                            held=os.fstat(descriptor);key=(held.st_dev,held.st_ino)
                            semantic_reads.append((phase,descriptor,key))
                            if phase=='fault' and armed and key!=pin_key:facts['foreign_read_count']+=1
            if is_parser and event=='return' and value is not None:
                raw=frame.f_locals.get('raw')
                if type(raw) is not bytes:raise RuntimeError('actual W1 semantic bytes prerequisite absent')
                if phase=='healthy':
                    facts['healthy_semantics'].append(dict(rules=list(value.rules),canonical_hex=value.canonical_bytes.hex(),whitelist_sha256=value.sha256,raw_matches_actual_pin=hashlib.sha256(raw).hexdigest()==pin_digest))
                    facts['healthy_same_fd_semantics']=(facts['healthy_same_fd_semantics'] or any(stage=='healthy' and descriptor==pin and key==pin_key for stage,descriptor,key in semantic_reads))
                elif armed:facts['fault_parser_completed']=True
            if not is_consumer:return
            if event=='call':
                # Its own later rename/restore ctime must not re-arm prerequisites.
                if phase=='fault' and facts['arm_count']!=0:return
                cursor=frame.f_back;a_frame=None
                while cursor is not None:
                    if cursor.f_code is a_method.__code__ and cursor.f_globals is a_method.__globals__:a_frame=cursor;break
                    cursor=cursor.f_back
                if a_frame is not None:
                    originals=a_frame.f_locals['originals'];token=a_frame.f_locals['token']
                    if phase=='healthy':healthy_originals,healthy_token=originals,token
                elif phase=='healthy' and healthy_originals is not None:originals=healthy_originals
                else:return
                record=originals.files.get((id(runtime.os),selected))
                if record is None:raise RuntimeError('W1 selected template not actually pinned')
                pin,parent,identity,pin_digest,view=record
                held=os.fstat(pin);pin_key=(held.st_dev,held.st_ino)
                live=base.identity(held)==tuple(str(item) for item in identity) and base.identity(os.lstat(selected))==base.identity(held)
                if not live:raise RuntimeError('W1 actual pin identity prerequisite absent')
                if phase=='healthy':return
                if a_frame is None:raise RuntimeError('W1 fault lacks actual root frame')
                facts['actual_a_frame']=True;facts['actual_pin_live']=live
                fault_originals,fault_token=originals,token
                raw=os.pread(pin,held.st_size+1,0)
                if len(raw)!=held.st_size or hashlib.sha256(raw).hexdigest()!=pin_digest:raise RuntimeError('W1 original byte prerequisite absent')
                facts['original_pin_key']=list(pin_key);facts['original_sha256']=pin_digest
                mutating=True
                try:
                    os.rename(selected,saved);armed=True
                    with selected.open('xb') as stream:stream.write(raw)
                    selected.chmod(held.st_mode & 0o7777)
                    changed=os.lstat(selected)
                    facts['replacement_key']=[changed.st_dev,changed.st_ino]
                    facts['same_bytes_new_inode']=((changed.st_dev,changed.st_ino)!=pin_key and selected.read_bytes()==raw)
                    facts['same_mode']=(changed.st_mode & 0o7777)==(held.st_mode & 0o7777)
                    facts['arm_count']+=1
                finally:mutating=False
            elif event=='return' and phase=='fault' and armed:restore()
        except BaseException as error:
            facts['observer_errors'].append(type(error).__name__)
            try:restore()
            except BaseException as cleanup:facts['observer_errors'].append(type(cleanup).__name__)

    sys.addaudithook(deny);facts['audit_armed']=True
    try:
        if base.graph(root)!=expected:raise RuntimeError('W1 cold original graph prerequisite mismatch')
        with ExitStack() as stack:
            for module in (producer,credential,target):stack.enter_context(mock.patch.object(module,'os',base.PrivateRootOS(root)))
            acquire=base.completed.GATE._hold_completed_source_read_lease
            Reader=base.completed.WORKER.CompletedCollectionCycleReader
            with acquire(str(project),status_dir=root/'monitor/status') as lease:
                lease_fd=lease._lock_fd;reader=Reader(lease=lease)
                before=base.graph(root);stack.enter_context(mock.patch.object(workbook,'os',WorkbookOS()))
                prior=sys.getprofile()
                try:
                    sys.setprofile(observe)
                    with runtime._hold_current_cable_cycle_source(reader,http_root=root) as healthy:
                        facts['healthy_outcome']=healthy.outcome;facts['healthy_target']=healthy.binding.spreadsheet_id
                        facts['healthy_keys']=sorted([list(row.activity_key) for row in (*healthy.changes.cabling,*healthy.changes.switch)])
                    facts['healthy_graph_unchanged']=base.graph(root)==before
                    facts['healthy_slots_closed']=(healthy_originals is not None and healthy_originals.closed and bool(healthy_originals.slots) and all(base.closed(fd) for view,fd,key in healthy_originals.slots))
                    facts['healthy_local_revoked']=healthy_token is not None and healthy_token not in local._ACTIVE
                    expected_keys=sorted([['eth_cabling','leaf-a','swp1','Mis-wiring'],['ib_cabling','leaf01','sw1p1','Mis-wiring'],['switch','leaf-a','fan','PSU1/FAN1'],['switch','nvsw01','asic_temp','ASIC1']])
                    semantic_ok=bool(facts['healthy_semantics']) and all(value==dict(rules=[],canonical_hex='5b5d0a',whitelist_sha256=hashlib.sha256(b'[]\n').hexdigest(),raw_matches_actual_pin=True) for value in facts['healthy_semantics'])
                    if (facts['observer_errors'] or not semantic_ok or not facts['healthy_graph_unchanged'] or not facts['healthy_slots_closed'] or not facts['healthy_local_revoked'] or facts['healthy_outcome']!='NO_SEND' or facts['healthy_target']!='synthetic_spreadsheet_id_0001' or facts['healthy_keys']!=expected_keys):raise RuntimeError('W1 healthy prerequisites absent; fault NOT_REACHED')
                    facts['healthy_complete']=True;phase='fault'
                    try:
                        with runtime._hold_current_cable_cycle_source(reader,http_root=root):pass
                    except BaseException as error:facts['window_error_type']=type(error).__name__
                    if fault_originals is not None:
                        facts['fault_originals_closed']=fault_originals.closed is True
                        facts['fault_slot_count']=len(fault_originals.slots)
                        facts['fault_slots_closed']=bool(fault_originals.slots) and all(base.closed(fd) for view,fd,key in fault_originals.slots)
                        facts['fault_local_revoked']=fault_token not in local._ACTIVE
                    lease.verify()
                finally:sys.setprofile(prior);facts['profile_restored']=sys.getprofile() is prior;restore()
            facts['lease_closed']=base.closed(lease_fd)
    except BaseException as error:facts['carrier_error_type']=type(error).__name__
    print('COLD_ORIGINAL_ATTACH_RESULT='+json.dumps(facts,sort_keys=True),flush=True)
    return 0


def run_workflow(test):
    result={}
    def after(case,committed,artifacts,parent,events):
        result['parent_closed']=parent._lock_fd==-1
        result['parent_events']=[row[0] for row in events]
        if not result['parent_closed'] or result['parent_events']!=['mark_success_return','exit_call','exit_return']:raise base.FixturePrerequisiteError('W1 actual parent exit prerequisite absent')
        with base.old.fixed_inputs(test,case):
            local=base.old.local_evidence(case,committed)
            control=Path(base.tempfile.mkdtemp(prefix='req7-w1-original-control-',dir=case.root.parent));control.chmod(0o700)
            print('W1_ORIGINAL_CONTROL_ROOT='+str(control),flush=True)
            manifest=control/'original-graph.json'
            with manifest.open('xb') as stream:stream.write(json.dumps(dict(graph=base.graph(case.root)),ensure_ascii=True,separators=(',',':')).encode('ascii'))
            manifest.chmod(0o600)
            with mock.patch.object(base,'CHILD_PROGRAM',PROGRAM):status,child,unused=base.launch(case.root,manifest)
            if status!=0:raise base.FixturePrerequisiteError('W1 cold child terminal facts unavailable')
            result.update(child);result['local_unchanged']=base.old.local_evidence(case,committed)==local
    base.completed.run_protected_after_parent_exit(test,after)
    return result
