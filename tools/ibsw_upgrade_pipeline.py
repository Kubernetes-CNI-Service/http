"""Bounded two-pool coordinator. No deployment/Git/history/file-lock gates.

Only the fixed native adapter below may produce actual completion evidence.
TCP readiness and queue messages are scheduling facts, never upgrade success.
"""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime,timezone
import errno
import heapq
import itertools
import os
import re
import resource
import secrets
import selectors
import socket
import sys
import threading
import time

from ibsw_upgrade_contract import SharedUpgradeHold

_NVUED_CHECK_SECONDS = 60.0
_NVUED_MAX_CHECKS = 5
_PROGRESS_HEARTBEAT_SECONDS = 30.0
_NVUED_COMMAND = 'systemctl show nvued.service --property=ActiveState --property=SubState --no-pager'
_RECHECK_SECONDS = 3.0
_now = time.monotonic
_idle = lambda seconds: threading.Event().wait(seconds)
_BOOT_COMMAND = "cat /proc/sys/kernel/random/boot_id"
_BOOT_RE = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_OS_DOWNLOAD_OBSERVATION_SECONDS=4*600+3*5+300


def worker_limits(count,cap=None):
    if type(count) is not int or count < 0:
        raise SharedUpgradeHold("invalid ready device count")
    upgrades = min(32, (count+1)//2)
    if cap is not None:
        if type(cap) is not int or not 1<=cap<=32:
            raise SharedUpgradeHold('parallel cap must be between 1 and 32')
        upgrades=min(upgrades,cap)
    return upgrades, min(8, (upgrades+3)//4)


def os_jitter_window(count):
    """Operator-approved heuristic, not measured bandwidth/admission control."""
    if type(count) is not int or not 0<=count<=32:
        raise SharedUpgradeHold('invalid simultaneous OS dispatch capacity')
    return 60*((count+7)//8)


def os_start_delay(count,*,canary,window=None):
    if canary: return 0
    window=os_jitter_window(count) if window is None else window
    if type(window) is not int or not 0<=window<=3600:
        raise SharedUpgradeHold('invalid OS jitter window')
    return secrets.randbelow(window) if window else 0


def _descriptor_budget(*, soft, occupied, requested, os_hops):
    """Half the finite soft limit is the process budget, NOT a worker count.

    Reserve room for journals/probes and conservative per-live-scope ownership:
    128 base + 64 per OS hop. Unused worker threads do not consume a reservation;
    one device retains its slot while rebooting and through every OS hop.
    """
    if (any(type(value) is not int for value in (soft, occupied, requested, os_hops))
            or soft <= 0 or occupied < 0 or not 1 <= requested <= 32 or os_hops < 1):
        raise SharedUpgradeHold('FD_BUDGET_INVALID: cannot determine bounded descriptor capacity')
    budget, reserve, per_job = soft // 2, 64, 128 + 64 * os_hops
    limit = min(requested, max(0, (budget - occupied - reserve) // per_job))
    if not limit:
        raise SharedUpgradeHold('FD_BUDGET_INSUFFICIENT: no complete device scope fits within '
            f'half the soft limit (soft={soft}, budget={budget}, occupied={occupied}, '
            f'reserve={reserve}, per-device={per_job}); no installer dispatched by this coordinator')
    return dict(soft_limit=soft, descriptor_budget=budget, baseline_descriptors=occupied,
        reserved_descriptors=reserve, per_in_flight=per_job,
        requested_in_flight=requested, in_flight_limit=limit)


def _open_descriptor_count():
    directory = '/proc/self/fd' if os.path.isdir('/proc/self/fd') else '/dev/fd'
    count = 0
    try:
        for name in os.listdir(directory):
            if name.isdigit():
                try:
                    os.fstat(int(name))
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
                else:
                    count += 1
    except OSError as error:
        raise SharedUpgradeHold('FD_BUDGET_UNAVAILABLE: cannot count local open descriptors') from error
    return count


def _soft_descriptor_limit():
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            soft = os.sysconf('SC_OPEN_MAX')
        if type(soft) is not int or soft <= 0:
            raise ValueError('finite positive capacity required')
        return soft
    except (OSError, ValueError) as error:
        raise SharedUpgradeHold('FD_BUDGET_UNAVAILABLE: cannot determine a finite local soft limit') from error


def check_preflight_descriptor_headroom():
    """Leave bounded room for the next sequential preflight and journal writes.

    With very large inventories, retained original backups alone may consume
    the budget. Stop before installation rather than silently raising ulimit,
    dropping original evidence, or trying to allocate at the OS hard boundary.
    """
    soft, occupied = _soft_descriptor_limit(), _open_descriptor_count()
    if occupied + 64 > soft // 2:
        raise SharedUpgradeHold('FD_BUDGET_INSUFFICIENT: preflight originals leave insufficient '
            f'headroom (soft={soft}, budget={soft//2}, occupied={occupied}); '
            'select a smaller --devices batch or explicitly increase the shell soft limit; '
            'no installer dispatched by this coordinator')


def preflight_slots(*, soft, occupied, pending, requested):
    """Additional startup tasks that fit, reserving 64 FD per pending scope.

    Current usage includes already-open worker FDs. Reserving pending scopes
    again is intentionally conservative and covers futures not yet opened.
    Completed evidence retained by the parent stays in occupied next round.
    """
    if (any(type(value) is not int for value in (soft,occupied,pending,requested))
            or soft <= 0 or occupied < 0 or not 1 <= requested <= 32
            or not 0 <= pending <= requested):
        raise SharedUpgradeHold('FD_BUDGET_INVALID: invalid startup descriptor capacity')
    return min(requested-pending, max(0,(soft//2-occupied-64-pending*64)//64))


def available_preflight_slots(pending, requested):
    return preflight_slots(soft=_soft_descriptor_limit(),occupied=_open_descriptor_count(),
                           pending=pending,requested=requested)


class WaitingQueue:
    def __init__(self):
        self.heap, self.current, self.serial = [], {}, itertools.count()

    def put(self, key, at, phase):
        serial=next(self.serial)
        self.current[key]=serial
        heapq.heappush(self.heap,(at,serial,key,phase))

    def _trim(self):
        while self.heap and self.current.get(self.heap[0][2]) != self.heap[0][1]:
            heapq.heappop(self.heap)

    def pop_due(self, now):
        self._trim()
        if not self.heap or self.heap[0][0] > now:
            return None
        _,serial,key,phase=heapq.heappop(self.heap)
        del self.current[key]
        return key,phase

    def next_at(self):
        self._trim()
        return self.heap[0][0] if self.heap else None

    def discard(self,key):
        self.current.pop(key,None)


class BootStability:
    """Track the live boot epoch; service readiness, not a timer, gates NVUE."""
    def __init__(self, before):
        self.before,self.epoch=before,None

    def observe(self, boot, now):
        if not _BOOT_RE.fullmatch(boot):
            raise SharedUpgradeHold("invalid fixed boot identity")
        if boot == self.before:
            return "WAIT_BOOT"
        self.epoch=boot
        return "READY"


def _nvued_running(raw):
    """Strict, machine-readable service DATA; never upgrade completion."""
    if (type(raw) is not tuple or len(raw)!=4 or type(raw[0]) is not bytes
            or type(raw[1]) is not bytes or raw[1] or type(raw[2]) is not int
            or raw[2]!=0 or raw[3] is not True):
        return False
    try:
        rows=raw[0].decode('ascii').splitlines()
    except UnicodeError:
        return False
    if len(rows)!=2 or any('=' not in row for row in rows):
        return False
    properties=dict(row.split('=',1) for row in rows)
    return properties=={'ActiveState':'active','SubState':'running'}


def _nvos_cli_ready(raw):
    """A successful parseable live version, not systemd readiness text."""
    if (type(raw) is not tuple or len(raw)!=4 or type(raw[0]) is not bytes
            or type(raw[1]) is not bytes or raw[1] or type(raw[2]) is not int
            or raw[2]!=0 or raw[3] is not True):
        return False
    from ibsw_upgrade_contract import record_readonly_query,parse_readonly_query_data
    try:
        record=record_readonly_query(('nv','show','system','version'),*raw[:3])
        return parse_readonly_query_data(record).state=='TEXT_DATA_PARSED'
    except (ValueError,UnicodeError):
        return False


class ParentTCPProbes:
    """Parent-owned nonblocking TCP only. Never authenticates or runs commands."""
    def __init__(self):
        self.selector=selectors.DefaultSelector()
        self.pending={}
        self.immediate=[]

    def request(self, job):
        connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            connection.setblocking(False)
            code=connection.connect_ex((job.address,22))
            if code == 0:
                connection.close()
                self.immediate.append((job,True))
            elif code in {errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY,errno.EINTR}:
                self.selector.register(connection,selectors.EVENT_WRITE,job)
                self.pending[id(job)]=(connection,job,min(job.deadline,_now()+10.0))
            else:
                connection.close()
                self.immediate.append((job,False))
        except BaseException:
            connection.close()
            raise

    def _remove(self,key):
        connection,job,_end=self.pending.pop(key)
        try:
            self.selector.unregister(connection)
        finally:
            connection.close()
        return job

    def poll(self):
        results,self.immediate=self.immediate,[]
        for item,_events in self.selector.select(0):
            job=item.data
            entry=self.pending.get(id(job))
            if entry is None:
                continue
            code=entry[0].getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
            results.append((self._remove(id(job)),code==0))
        for key,(_connection,_job,end) in list(self.pending.items()):
            if _now() >= end:
                results.append((self._remove(key),False))
        return results

    def close(self):
        errors=[]
        for key in list(self.pending):
            try: self._remove(key)
            except Exception as error: errors.append(error)
        self.selector.close()
        if errors: raise SharedUpgradeHold("TCP probe cleanup failed")


@dataclass
class Event:
    kind: str
    at: float = 0.0
    phase: str = ""
    row: object = None


class NativeStep:
    """Live same-process owner; not serializable or reconstructed from JSON."""
    def __init__(self,name,component,scope,stack,auth):
        self.name,self.component,self.scope,self.stack,self.auth=name,component,scope,stack,auth
        self.leaf_stack=ExitStack()
        self.leaf=self.dispatch=None
        self.deadline=float("inf")
        self.address=scope.devices[name].address
        self.phase="UPGRADE"
        self.wrote=False
        self.remote_may_be_active=False
        self.hops=0
        self.closed=False
        self.boot=None
        self.terminal=None
        self.started=None
        self.reported_epoch=None
        self.nvued_checks=0
        self.nvued_wait_until=None
        self.readiness_failure=None
        self.next_exit_probe=0.0

    def close(self):
        if self.closed: return
        self.closed=True
        try:
            self.leaf_stack.close()
        finally:
            self.stack.close()


class NativeAdapter:
    os_jitter_enabled=True
    def __init__(self,parent,parsed,password,driver,entry,cwd,directory,bus):
        self.parent,self.parsed,self.driver=parent,parsed,driver
        self.entry,self.cwd,self.directory,self.bus=entry,cwd,directory,bus
        self.auth=dict(known_hosts_path=parsed.known_hosts,identity_path=parsed.identity,
                       management_public_path=parsed.management_public_key,user=parsed.user)
        self.password=password
        self.timeline=[]
        self.component_flash_required={}
        self.canary_plans={}
        self.planned={(r["hostname"],r["component"]):r for r in getattr(parent,"_version_plan",[])}

    def verify(self):
        self.parent.verify()

    def descriptor_budget(self, requested):
        issues = getattr(self.parent, '_component_readiness_issues', [])
        if not issues and self.planned and all(row['action'] == 'AT_TARGET_NO_FLASH' for row in self.planned.values()):
            return None  # No live component scope will be started.
        soft = _soft_descriptor_limit()
        hops = max([1] + [len(row['path']) - 1 for row in self.planned.values()
            if row['component'] == 'os' and row['action'] == 'UPGRADE_REQUIRED'])
        return _descriptor_budget(soft=int(soft), occupied=_open_descriptor_count(),
            requested=requested, os_hops=hops)

    def no_change_observations(self,component,names):
        """Parent's original live preflight DATA, never completion or write permission.

        Keep no-flash observations outside execution queues. A later real write
        still independently checks identity, current OS and the component version.
        """
        self.verify()
        issues={(r['hostname'],r['component']) for r in
                getattr(self.parent,'_component_readiness_issues',[])}
        rows=[dict(hostname=name,component=component,state='PREFLIGHT_NO_CHANGE',
                     action='AT_TARGET_PREFLIGHT',verification_basis='PREFLIGHT_OBSERVATION_ONLY')
                for name in names if (name,component) not in issues and
                self.planned.get((name,component),{}).get('action')=='AT_TARGET_NO_FLASH']
        if component=='os' and self.parent.policy.ssd_version is not None:
            checks={r['hostname']:r for r in getattr(self.parent,'_startup_ssd_checks',[])}
            for row in rows:
                original=checks.get(row['hostname'])
                row['ssd_check']=({k:v for k,v in original.items() if k!='hostname'} if original else
                    dict(state='WARNING',status='UNAVAILABLE',expected_version=self.parent.policy.ssd_version,
                        observed_version=None,reason_code='SSD_PREFLIGHT_RESULT_MISSING',
                        verification_basis='PREFLIGHT_OS_AT_TARGET',informational_only=True))
        return rows

    def choose_canary(self,component,names):
        needed=[n for n in names if self.planned.get((n,component),{}).get("action")=="UPGRADE_REQUIRED"]
        return needed[0] if needed else None

    def choose_canaries(self,component,names):
        if component=='os':
            from ibsw_upgrade_schedule import select_os_canaries
            plan=select_os_canaries(self.parent.policy,
                [self.planned[(name,'os')] for name in names],names)
        else:
            name=self.choose_canary(component,names)
            plan=dict(canaries=[name] if name else [],routes=[])
        self.canary_plans[component]=plan
        return plan

    def record_canaries(self,component,names,routes):
        self.parent._record_native_component_canaries(component,names,routes)

    def requires_flash(self,component,names):
        return any(self.planned.get((n,component),{}).get("action")=="UPGRADE_REQUIRED" for n in names)

    def configure_component(self,component,needs_flash):
        self.component_flash_required[component]=needs_flash
        if not needs_flash and self.parent.parsed.canary_mode=='default':
            self.parent._record_native_component_no_canary(component)

    def remaining_upgrade_hops(self,name,component,completed_hops=0):
        """Queue weight from the original selected route, never write permission."""
        row=self.planned.get((name,component),{})
        if row.get('action')!='UPGRADE_REQUIRED': return 0
        if component!='os': return 1
        path=row.get('path')
        if (type(path) not in (list,tuple) or len(path)<2
                or type(completed_hops) is not int or not 0<=completed_hops<len(path)):
            raise SharedUpgradeHold('OS_DISPATCH_PRIORITY_ROUTE_INVALID')
        return len(path)-1-completed_hops

    def blocked(self,name,component,reason):
        self.parent._record_native_component_failure(component,name,"NOT_EXECUTED",reason)

    def begin(self,name,component,canary,stop):
        stack=ExitStack()
        if self.parent.parsed.method == 'scp':
            scope=stack.enter_context(self.parent.fork_native_component_scope(name,component))
        else:
            scope=stack.enter_context(self.driver.open_manual_run(
                self.entry,self.cwd,self.parsed.prepare_args,self.directory))
        scope._access_required=True
        if self.parent.policy.os_stages:
            # Live in-process context, never reconstruct a route from saved JSON.
            scope._os_route_owner=self.parent
            scope._frozen_os_routes=getattr(self.parent,'_frozen_os_routes',{})
            scope._os_source_baselines=getattr(self.parent,'_os_source_baselines',{})
        scope._pipeline_checks_only=not self.component_flash_required[component]
        scope._pipeline_stop_event=stop
        scope._progress_callback=lambda host,_component,stage:self.bus.emit(host,component,stage)
        scope._download_callback=self.bus.emit_download
        scope.enable_cooperative_status_snapshots()
        scope._native_schedule_started=True
        job=NativeStep(name,component,scope,stack,self.auth)
        job.covered_os_path=(tuple(self.planned[(name,'os')]['path'])
                             if component=='os' and self.component_flash_required[component] else None)
        job.canary_path=next((tuple(r['path']) for r in self.canary_plans.get(component,{}).get('routes',[])
                              if r['hostname']==name),None) if canary else None
        return self.next_step(job,stop)

    def next_step(self,job,stop):
        from ibsw_upgrade_observer import _COMPLETION_SECONDS
        from ibsw_upgrade_schedule import _native_failure_reason
        try:
            if stop.is_set():
                return job,self.abort(job,"shared stop before another original step")
            job.leaf_stack.close()
            job.leaf_stack=ExitStack()
            job.leaf=job.leaf_stack.enter_context(job.scope.open_readonly_query_inputs(job.name,**job.auth))
            job.leaf._cooperative_completion=True
            if job.covered_os_path is not None:
                job.leaf._covered_os_path=job.covered_os_path
            if job.canary_path is not None:
                job.leaf._expected_os_canary_path=job.canary_path[job.hops:]
            self.bus.emit(job.name,job.component,"CHECK_CURRENT_VERSION")
            job.dispatch=job.leaf.execute_component_once(job.component,password=self.password)
            job.deadline=_now()+_COMPLETION_SECONDS
            if job.component=='os' and job.dispatch.state!='NO_WRITE':
                job.deadline+=_OS_DOWNLOAD_OBSERVATION_SECONDS
            job.started=_now()
            job.reported_epoch=None
            job.nvued_checks=0
            job.nvued_wait_until=None
            job.readiness_failure=None
            job.next_exit_probe=0.0
            job.download_budget_settled=False
            job.hops+=1
            if job.hops > (len(job.scope.policy.os)+1 if job.component=="os" else 1):
                raise SharedUpgradeHold("bounded original component path exceeded")
            if job.dispatch.state=="NO_WRITE":
                job.phase="VERIFY"
            else:
                job.wrote=True
                job.remote_may_be_active=True
                boots=[r for r in job.dispatch.raw_records if r["command"]==_BOOT_COMMAND]
                import base64
                before=base64.b64decode(boots[0]["stdout_base64"],validate=True).decode().strip()
                job.boot=BootStability(before)
                job.phase="TCP"
            return job,Event("WAIT",_now(),job.phase)
        except SharedUpgradeHold:
            job.close()
            raise
        except Exception as error:
            if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS):
                job.close()
                raise
            job.scope._record_install_precheck_failure(job.name,error)
            return job,self.abort(job,_native_failure_reason(error))

    def _login_boot_once(self,job):
        from ibsw_upgrade_observer import _signed_session_single,_NativeObservationHold,_read_channel,_is_nvos_initializing
        leaf=job.leaf
        # Only boot, systemd and a readonly CLI availability probe until ready.
        with ExitStack() as stack:
            try:
                session=stack.enter_context(_signed_session_single(leaf,
                    _connection_deadline=job.deadline,_minimal=True))
            except _NativeObservationHold as error:
                if error.reason_code!="SSH_AUTHENTICATION_REJECTED": raise
                session=stack.enter_context(_signed_session_single(leaf,password=self.password,
                    _connection_deadline=job.deadline,_minimal=True))
            raw=_read_channel(leaf,session[0],_BOOT_COMMAND,job.deadline)
            if raw[1] or raw[2]!=0 or raw[3] is not True:
                raise _NativeObservationHold(reason_code="BOOT_ID_QUERY_FAILED")
            boot=raw[0].decode("ascii").strip()
            if not _BOOT_RE.fullmatch(boot):
                raise _NativeObservationHold(reason_code="BOOT_ID_QUERY_FAILED")
            if boot!=getattr(leaf,"_last_boot_probe",job.boot.before):
                from ibsw_upgrade_executor import _raw_record
                leaf._post_boot_records=getattr(leaf,"_post_boot_records",[])+[_raw_record(_BOOT_COMMAND,raw)]
                leaf._last_boot_probe=boot
            ready=False
            if boot==job.boot.before and _now()>=job.next_exit_probe:
                # Optional negative diagnostics only on the original boot.
                # No remote file is required after a new boot, or for success.
                from ibsw_upgrade_executor import _probe_component_exit_once
                job.next_exit_probe=_now()+30.0
                try:
                    owned=_probe_component_exit_once(leaf,job.dispatch,password=self.password,
                        deadline=min(job.deadline,_now()+25.0),_read_only=True,_transport=session[0])
                except _NativeObservationHold as error:
                    if error.reason_code in ('COMPONENT_DIRECTORY_MISSING','COMPONENT_FILE_MISSING','COMPONENT_SFTP_FAILED',
                            'READONLY_DEADLINE_EXCEEDED','READONLY_QUERY_TIMEOUT','READONLY_QUERY_INCOMPLETE'):
                        owned=False
                    else: raise
                if getattr(leaf,'_download_acknowledged',False) and not job.download_budget_settled:
                    from ibsw_upgrade_observer import _COMPLETION_SECONDS
                    # Installer/reboot observation has a separate finite budget
                    # once the download is safely recorded, not a 40-minute delay.
                    job.deadline=min(job.deadline,_now()+_COMPLETION_SECONDS)
                    job.download_budget_settled=True
                    self.record_time(job,'DOWNLOAD_RECORDED_INSTALL_RELEASED')
                if owned and owned['child_exit_code']!=0:
                    code=owned['child_exit_code']
                    phase=owned.get('preinstall_failure_phase')
                    if phase in ('PACKAGE_DOWNLOAD','WAIT_DOWNLOAD_RECORD'):
                        # Original child ended on the original boot; complete
                        # bound logs prove no install invocation in THIS hop.
                        # Keep the failed device quarantined, not an active slot.
                        job.remote_may_be_active=False
                    reason_code=({'PACKAGE_DOWNLOAD':'DOWNLOAD_FAILED_BEFORE_INSTALL',
                        'WAIT_DOWNLOAD_RECORD':'DOWNLOAD_RECORD_FAILED_BEFORE_INSTALL'}.get(
                            phase,'INSTALLER_EXIT_NONZERO_BEFORE_REBOOT'))
                    diagnostic=dict(child_exit_code=code,original_boot_unchanged=True)
                    if phase in ('PACKAGE_DOWNLOAD','WAIT_DOWNLOAD_RECORD'):
                        diagnostic.update(installation_started=False,preinstall_failure_phase=phase)
                    raise _NativeObservationHold(reason_code=reason_code,capture_raw={
                        'safe_diagnostic':diagnostic,
                        'component_owned_files':owned.get('diagnostic_files',{})})
            if boot!=job.boot.before:
                if job.nvued_checks>=_NVUED_MAX_CHECKS:
                    raise _NativeObservationHold(reason_code=job.readiness_failure or 'NVUE_READINESS_CHECK_LIMIT_EXCEEDED')
                self.bus.emit(job.name,job.component,'CHECK_NVUED')
                service=_read_channel(leaf,session[0],_NVUED_COMMAND,job.deadline)
                leaf.verify()
                job.nvued_checks+=1
                from ibsw_upgrade_executor import _raw_record
                records=[_raw_record(_BOOT_COMMAND,raw),_raw_record(_NVUED_COMMAND,service)]
                stage='WAIT_NVUED'
                failure=None
                job.readiness_failure='NVUED_NOT_RUNNING_AFTER_5_CHECKS'
                if _nvued_running(service):
                    self.bus.emit(job.name,job.component,'NVUED_RUNNING')
                    self.bus.emit(job.name,job.component,'CHECK_NVUE_CLI')
                    version=_read_channel(leaf,session[0],'nv show system version',job.deadline)
                    leaf.verify()
                    records.append(_raw_record('nv show system version',version))
                    if _nvos_cli_ready(version):
                        ready=True
                        stage='NVUE_READY'
                        job.readiness_failure=None
                    elif _is_nvos_initializing(version):
                        stage='WAIT_NVUE_CLI'
                        job.readiness_failure='NVOS_CLI_NOT_READY_AFTER_5_CHECKS'
                    else:
                        stage='NVUE_QUERY_FAILED'
                        failure=('OS_VERSION_PARSE_FAILED' if version[2]==0 and not version[1]
                                 and version[3] is True else 'OS_VERSION_QUERY_FAILED')
                job.scope._record_nvued_check(leaf,job.dispatch,job.nvued_checks,records)
                leaf._verification_nvued_epoch=boot if ready else None
                self.record_time(job,stage,
                    attempt=job.nvued_checks,max_attempts=_NVUED_MAX_CHECKS,
                    boot_id=boot,next_check_seconds=None if ready else _NVUED_CHECK_SECONDS)
                if failure:
                    raise _NativeObservationHold(reason_code=failure)
                if not ready:
                    self.bus.emit(job.name,job.component,stage)
            return boot,ready

    def record_time(self,job,phase,**details):
        self.timeline.append(dict(hostname=job.name,component=job.component,stage=job.dispatch.stage,
            phase=phase,utc=datetime.now(timezone.utc).isoformat(),since_dispatch_seconds=round(_now()-job.started,3),
            deadline_remaining_seconds=max(0,round(job.deadline-_now(),3)),**details))

    def advance(self,job):
        from ibsw_upgrade_observer import (_observe_component_completion_once,_NativeObservationHold,
                                           _CompletionDeferred,_CompletionBootChanged)
        from ibsw_upgrade_schedule import _native_failure_reason
        try:
            if _now() >= job.deadline:
                return self.abort(job,"COMPONENT_DEADLINE_EXCEEDED")
            if job.phase=="AUTH":
                if job.nvued_checks>=_NVUED_MAX_CHECKS:
                    return self.abort(job,job.readiness_failure or 'NVUE_READINESS_CHECK_LIMIT_EXCEEDED')
                boot,ready=self._login_boot_once(job)
                state=job.boot.observe(boot,_now())
                if state=="WAIT_BOOT":
                    observed=getattr(job.leaf,'_observed_component_stage',None)
                    waiting=observed if observed in ('PACKAGE_DOWNLOAD','WAIT_DOWNLOAD_RECORD','PACKAGE_READY',
                        'IMAGE_FETCH','BIOS_FETCH','CPLD_BURN') else 'WAIT_NEW_BOOT'
                    self.bus.emit(job.name,job.component,waiting)
                    return Event("WAIT",_now()+_RECHECK_SECONDS,"TCP")
                if not ready:
                    if job.nvued_checks>=_NVUED_MAX_CHECKS:
                        return self.abort(job,job.readiness_failure or 'NVUE_READINESS_CHECK_LIMIT_EXCEEDED')
                    job.nvued_wait_until=_now()+_NVUED_CHECK_SECONDS
                    return Event('WAIT',job.nvued_wait_until,'AUTH')
                job.nvued_wait_until=None
                self.bus.emit(job.name,job.component,'NVUE_READY')
                job.remote_may_be_active=False
                job.phase="VERIFY"
            if job.phase=="VERIFY":
                if job.dispatch.state=='DISPATCHED_UNKNOWN':
                    job.leaf._verification_boot_epoch=job.boot.epoch
                    self.bus.emit(job.name,job.component,'POST_REBOOT_VERIFICATION')
                self.record_time(job,"VERIFY_COLLECTION_STARTED")
                completion=_observe_component_completion_once(job.leaf,job.dispatch,password=self.password,
                    _deadline=job.deadline,_skip_exit_wait=True)
                if not job.scope._has_component_completion(job.dispatch,completion):
                    raise SharedUpgradeHold("original completion receipt missing")
                job.completion=completion
                if (completion.state=="VERIFIED" and job.component=="os"
                        and completion.target_version!=job.scope.policy.final_os):
                    return Event("NEXT")
                job.scope._record_native_component_status(job.component,job.name,completion)
                job.scope.verify()
                row=dict(hostname=job.name,component=job.component,
                         state="COMPLETE" if completion.state=="VERIFIED" else completion.state)
                row['health_overrides']=list(getattr(job.scope,'_health_overrides',[]))
                row['health_checks']=list(getattr(job.scope,'_health_checks',[]))
                row.update(health_postcheck_required=bool(job.wrote),health_postcheck_stage=job.dispatch.stage)
                row['health_verified']=bool(row['health_checks']) and all(
                    r['observed_state']=='PASS' for r in row['health_checks']) and completion.state=='VERIFIED'
                row.update(verification_basis='LIVE_POST_REBOOT' if job.dispatch.state=='DISPATCHED_UNKNOWN'
                           else 'NO_WRITE_LIVE',installer_exit_code=None)
                from ibsw_upgrade_contract import ssd_check_from_completion
                ssd_check=ssd_check_from_completion(job.scope.policy,job.dispatch,completion)
                if ssd_check is not None:
                    row['ssd_check']=ssd_check
                if completion.state=="VERIFIED":
                    row["action"]="UPGRADE_PERFORMED_AND_VERIFIED" if job.wrote else "ALREADY_AT_TARGET_VERIFIED"
                if completion.reason:
                    row.update(reason=completion.reason,log_directory=str(job.scope.run_directory/job.name/job.dispatch.stage))
                job.terminal=Event("FINISHED",row=row)
                return job.terminal
            raise SharedUpgradeHold("unknown cooperative phase")
        except _CompletionDeferred:
            return Event("WAIT",_now()+_RECHECK_SECONDS,"TCP")
        except _CompletionBootChanged as error:
            job.boot.observe(error.boot_id,_now())
            job.reported_epoch=None
            job.leaf._verification_nvued_epoch=None
            self.record_time(job,'BOOT_CHANGED_DURING_VERIFICATION',boot_id=error.boot_id)
            self.bus.emit(job.name,job.component,'CHECK_NVUED')
            return Event('WAIT',_now(),'AUTH')
        except _NativeObservationHold as error:
            if error.reason_code in {"SSH_CONNECT_FAILED","SSH_CONNECT_TIMEOUT","SSH_HANDSHAKE_FAILED","SSH_HANDSHAKE_TIMEOUT","SSH_AUTH_TRANSPORT_LOST","SSH_AUTH_TIMEOUT"}:
                self.bus.emit(job.name,job.component,"WAIT_REBOOT")
                return Event("WAIT",_now()+_RECHECK_SECONDS,"TCP")
            reason=_native_failure_reason(error)
            if error.reason_code in ('INSTALLER_EXIT_NONZERO_BEFORE_REBOOT','DOWNLOAD_FAILED_BEFORE_INSTALL',
                                     'DOWNLOAD_RECORD_FAILED_BEFORE_INSTALL'):
                reason+=' | installer-exit='+str(error.capture_raw['safe_diagnostic']['child_exit_code'])
            return self.abort(job,reason,error=error)
        except SharedUpgradeHold:
            raise
        except Exception as error:
            if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
            return self.abort(job,_native_failure_reason(error))

    def abort(self,job,reason,*,error=None):
        if job.terminal is not None:
            return job.terminal
        state="UNKNOWN" if job.wrote or job.scope.component_attempt_may_have_started(job.name,job.component) else "NOT_EXECUTED"
        safe=(error.capture_raw.get('safe_diagnostic',{}) if error is not None
              and type(getattr(error,'capture_raw',None)) is dict else {})
        if type(safe) is not dict: safe={}
        before_install=(getattr(error,'reason_code',None) in ('DOWNLOAD_FAILED_BEFORE_INSTALL',
            'DOWNLOAD_RECORD_FAILED_BEFORE_INSTALL') and safe.get('installation_started') is False
            and safe.get('original_boot_unchanged') is True and not job.remote_may_be_active)
        if before_install: state='FAIL'
        stage=getattr(job.leaf,'_last_progress_stage',None) or self.bus.latest.get((job.name,job.component))
        if stage:
            reason+=' | phase='+stage+(' | installer was not invoked in this hop; device isolated; no automatic retry' if before_install
                                     else ' | installer may have started; do not resend' if state=='UNKNOWN'
                                     else ' | installer was not dispatched')
        if error is not None and type(getattr(error,"capture_raw",None)) is dict and job.dispatch is not None:
            from ibsw_upgrade_observer import _record_component_probe_failure
            completion=_record_component_probe_failure(job.leaf,job.dispatch,error)
            job.scope._record_native_component_status(job.component,job.name,completion)
        else:
            job.scope._record_native_component_failure(job.component,job.name,state,reason)
        job.terminal=Event("FINISHED",row=dict(hostname=job.name,component=job.component,state=state,reason=reason,
                                        log_directory=str(job.scope.run_directory/job.name)))
        job.terminal.row.update(health_checks=list(getattr(job.scope,'_health_checks',[])),
            health_overrides=list(getattr(job.scope,'_health_overrides',[])),health_verified=False)
        job.terminal.row.update(health_postcheck_required=bool(job.wrote and not before_install),
            health_postcheck_stage=job.dispatch.stage if job.dispatch is not None else None)
        if type(safe.get('child_exit_code')) is int:
            job.terminal.row.update(installer_exit_code=safe['child_exit_code'],verification_basis='ORIGINAL_PREBOOT_EXIT')
        if before_install:
            job.terminal.row.update(installation_started=False,failure_phase=safe['preinstall_failure_phase'])
        return job.terminal

    def validate_result(self,job,event):
        job.scope.verify()
        if event.row["state"]=="COMPLETE":
            completion=getattr(job,"completion",None)
            if completion is None or completion.state!="VERIFIED" or not job.scope._has_component_completion(job.dispatch,completion):
                raise SharedUpgradeHold("coordinator requires original live verified completion")


def run_pipeline(names,components,adapter,*,skip_canary=False,progress=None,probe_factory=ParentTCPProbes):
    """Fixed internal orchestration; callback seam exists only for local tests."""
    from ibsw_upgrade_schedule import component_order
    names=tuple(names)
    if tuple(components)!=component_order(components) or len(set(n.casefold() for n in names))!=len(names):
        raise SharedUpgradeHold("invalid original cooperative selection")
    options=getattr(adapter,'parsed',None)
    upgrades,verifiers=worker_limits(len(names),getattr(options,'parallel_limit',None))
    resource_budget=(adapter.descriptor_budget(upgrades)
                     if names and hasattr(adapter,'descriptor_budget') else None)
    in_flight_limit=resource_budget['in_flight_limit'] if resource_budget else upgrades
    stop=threading.Event()
    quarantined,unresolved=set(),set()
    matrix={name:{} for name in names}
    phases=[]
    writers=readers=None
    with ExitStack() as worker_stack:
        for component in components:
            if stop.is_set(): break
            if progress: progress.start_phase()
            observations=adapter.no_change_observations(component,names) if hasattr(adapter,'no_change_observations') else []
            no_change={r['hostname'] for r in observations}
            if (len(no_change)!=len(observations) or any(n not in names for n in no_change)):
                raise SharedUpgradeHold('invalid original preflight no-change selection')
            for name in no_change: matrix[name][component]='PREFLIGHT_NO_CHANGE'
            candidates=[n for n in names if n not in quarantined and n not in no_change]
            needs_flash=bool(candidates) and adapter.requires_flash(component,candidates)
            if hasattr(adapter,'configure_component'): adapter.configure_component(component,needs_flash)
            if skip_canary or not needs_flash:
                plan=dict(canaries=[],routes=[])
            elif hasattr(adapter,'choose_canaries'):
                plan=adapter.choose_canaries(component,candidates)
            else:  # Private callback seam for isolated coordinator tests only.
                chosen=adapter.choose_canary(component,candidates)
                plan=dict(canaries=[chosen] if chosen else [],routes=[])
            canaries=tuple(plan['canaries'])
            if (len(set(canaries))!=len(canaries) or any(n not in candidates for n in canaries)
                    or (needs_flash and not skip_canary and not canaries)):
                raise SharedUpgradeHold('required original canary coverage missing')
            canary=canaries[0] if canaries else None  # Legacy first-canary attribution, not the whole set.
            if canaries and hasattr(adapter,'record_canaries'):
                adapter.record_canaries(component,canaries,plan['routes'])
            if canaries:
                sys.stderr.write(f'[{component.upper()} CANARY PLAN] required={len(canaries)}\n')
                for name in canaries:
                    route=next((r for r in plan['routes'] if r['hostname']==name),None)
                    sys.stderr.write('  - '+name+(' | '+' -> '.join(route['path']) if route else '')+'\n')
                    if route:
                        sys.stderr.write(f"    Covers ({len(route['covers'])}):\n")
                        for covered in route['covers']: sys.stderr.write('      - '+covered+'\n')
            if candidates and not needs_flash:
                sys.stderr.write(f"[{component.upper()}] No upgrades planned; no upgrade canary required. "
                                 "Check each device independently; no upgrade-path validation is claimed.\n")
            released=not canaries
            passed_canaries=set()
            failed_canary=False
            original_order={name:index for index,name in enumerate(names)}
            def dispatch_key(name,completed_hops=0):
                remaining=(adapter.remaining_upgrade_hops(name,component,completed_hops)
                    if component=='os' and hasattr(adapter,'remaining_upgrade_hops') else 0)
                if type(remaining) is not int or remaining<0:
                    raise SharedUpgradeHold('OS_DISPATCH_PRIORITY_ROUTE_INVALID')
                return -remaining,original_order[name]
            todo=list(canaries)+sorted((n for n in candidates if n not in canaries),key=dispatch_key)
            phase=dict(component=component,canary=canary,targets=[],blocked_by_canary=[],
                       no_change=observations,
                       canaries=list(canaries),canary_routes=plan['routes'],
                       dispatch_policy='LONGEST_REMAINING_OS_PATH_FIRST' if component=='os' else 'ORIGINAL_ORDER',
                       canary_requirement='NOT_REQUIRED' if not needs_flash else
                       'EXPLICITLY_SKIPPED' if skip_canary else 'REQUIRED')
            phases.append(phase)
            if component=='os' and candidates:
                sys.stderr.write('[OS DISPATCH] longest remaining OS path first; ties use original device order; '
                    'only ready tasks compete; canary gates, stagger and in-flight limits are unchanged\n')
            if observations:
                sys.stderr.write(f'[{component.upper()}] No-change: {len(observations)}; preflight observation only; excluded from upgrade queue\n')
            if candidates and writers is None:
                sys.stderr.write(f"Scheduler: ready-ib={len(names)} upgrade-workers={upgrades} verification-workers={verifiers} "
                    f"in-flight-limit={in_flight_limit} rule=U:min(32,ceil(N/2)),V:min(8,ceil(U/4))\n")
                sys.stderr.write('[COUNTS] dispatch/verification counts below are worker tasks, not confirmed running installer processes.\n')
                if resource_budget:
                    sys.stderr.write('[RESOURCE] nofile-soft='+str(resource_budget['soft_limit'])+
                        ' fd-budget='+str(resource_budget['descriptor_budget'])+
                        ' baseline='+str(resource_budget['baseline_descriptors'])+
                        ' reserve='+str(resource_budget['reserved_descriptors'])+
                        ' per-in-flight='+str(resource_budget['per_in_flight'])+
                        f' effective-in-flight={in_flight_limit}/{upgrades}; no ulimit changes\n')
                writers=worker_stack.enter_context(ThreadPoolExecutor(max_workers=max(1,upgrades),thread_name_prefix='ib-upgrade'))
                readers=worker_stack.enter_context(ThreadPoolExecutor(max_workers=max(1,verifiers),thread_name_prefix='ib-verify'))
            jobs,pending={},{}
            delayed_starts={}
            jitter_events=[]
            simultaneous_os=min(upgrades,in_flight_limit,len(candidates)) if component=='os' else 0
            jitter_enabled=component=='os' and getattr(adapter,'os_jitter_enabled',False)
            jitter_override=getattr(options,'os_download_jitter',None)
            window=(os_jitter_window(simultaneous_os) if jitter_override is None else jitter_override) if jitter_enabled else 0
            phase['os_download_jitter']=(dict(capacity=simultaneous_os,window_seconds=window,
                formula='60*ceil(N/8)',basis='eligible OS dispatch capacity, not an observed live-download count',
                canaries_delayed=False,events=jitter_events) if component=='os' else None)
            phase['os_downloads']=[]
            if jitter_enabled and candidates:
                sys.stderr.write(f'[OS DOWNLOAD STAGGER] capacity={simultaneous_os} window=0..{max(0,window-1)}s '
                    'rule=60*ceil(N/8); canaries exempt; no separate download concurrency cap\n')
            q=WaitingQueue()
            probes=probe_factory()
            last_progress=_now()
            def block(name,state,reason):
                adapter.verify()
                adapter.blocked(name,component,reason)
                row=dict(hostname=name,component=component,state=state,reason=reason)
                phase["targets"].append(row); matrix[name][component]=state
            for name in names:
                if name in quarantined and name not in no_change:
                    block(name,"BLOCKED_PREVIOUS_FAILURE","Earlier device failure requires manual review; no later writes")
            def accept(job,event):
                nonlocal released,failed_canary
                row=event.row
                if (type(row) is not dict or row.get("hostname")!=job.name or row.get("component")!=component
                        or row.get("state") not in {"COMPLETE","FAIL","FAILED","UNKNOWN","NOT_EXECUTED"}):
                    raise SharedUpgradeHold("foreign cooperative completion")
                adapter.verify()
                if hasattr(adapter,"validate_result"): adapter.validate_result(job,event)
                phase["targets"].append(row); matrix[job.name][component]=row["state"]
                phase['os_downloads'].extend(getattr(job.scope,'_download_measurements',[])
                    if hasattr(job,'scope') else [])
                if row["state"]!="COMPLETE":
                    quarantined.add(job.name)
                    if job.remote_may_be_active: unresolved.add(job.name)
                if job.name in canaries:
                    if row['state']=='COMPLETE' and row.get('action')=='UPGRADE_PERFORMED_AND_VERIFIED':
                        passed_canaries.add(job.name)
                    else:
                        failed_canary=True
                    released=not failed_canary and len(passed_canaries)==len(canaries)
                    if released:
                        sys.stderr.write(f'[{component.upper()} CANARY COVERAGE] VERIFIED: all {len(canaries)} '
                                         'required canary routes passed; releasing ordinary devices\n')
                sys.stderr.write(f"[DONE {component.upper()}] {job.name}: {row['state']}\n")
                if row.get('ssd_check'):
                    check=row['ssd_check']
                    sys.stderr.write(f"[SSD][{job.name}] {check['state']} / {check['status']}: "
                        f"observed={check['observed_version'] or 'UNAVAILABLE'} "
                        f"target={check['expected_version']} (informational only; non-blocking)\n")
                if row.get("reason"):
                    sys.stderr.write("  Reason: "+row["reason"]+"\n")
                q.discard(job.name); jobs.pop(job.name,None)
                job.close()
            try:
                while todo or jobs or pending or delayed_starts:
                    adapter.verify()
                    for future in [f for f in pending if f.done()]:
                        kind,name=pending.pop(future)
                        value=future.result()
                        if kind=="UPGRADE":
                            job,event=value; jobs[name]=job
                        else:
                            job=jobs[name]; event=value
                        if event.kind=="FINISHED": accept(job,event)
                        elif event.kind=="NEXT":
                            delay=os_start_delay(simultaneous_os,canary=name in canaries,window=window) if jitter_enabled else 0
                            jitter_events.append(dict(hostname=name,after_hop=job.hops,delay_seconds=delay))
                            if delay and progress: progress.emit(name,component,'WAIT_OS_DOWNLOAD_STAGGER')
                            q.put(name,_now()+delay,"UPGRADE")
                        elif event.kind=="WAIT":
                            job.phase=event.phase
                            q.put(name,min(event.at,job.deadline),event.phase)
                        else: raise SharedUpgradeHold("unknown cooperative event")
                    if failed_canary:
                        phase["blocked_by_canary"]=list(todo)+list(delayed_starts)
                        for name in list(todo)+list(delayed_starts):
                            block(name,"BLOCKED_CANARY","Required component canary coverage failed, is unknown or did not exercise the planned route; no peer dispatch")
                        todo=[]
                        delayed_starts.clear()
                    busy_w=sum(kind=="UPGRADE" for kind,_ in pending.values())
                    new_starts=sum(kind=="UPGRADE" and name not in jobs for kind,name in pending.values())
                    ready_starts=[]
                    while todo and busy_w+len(ready_starts)<upgrades and len(jobs)+new_starts+len(unresolved)+len(delayed_starts)<in_flight_limit:
                        if not released and (todo[0] not in canaries or jobs or pending or ready_starts): break
                        name=todo.pop(0)
                        if name in canaries:
                            sys.stderr.write(f"[CANARY {component.upper()}] {name}\n")
                        delay=os_start_delay(simultaneous_os,canary=name in canaries,window=window) if jitter_enabled else 0
                        if jitter_enabled: jitter_events.append(dict(hostname=name,after_hop=0,delay_seconds=delay))
                        if delay:
                            delayed_starts[name]=_now()+delay
                            sys.stderr.write(f'[OS STAGGER] {name}: wait={delay}s window={window}s\n')
                            if progress: progress.emit(name,component,'WAIT_OS_DOWNLOAD_STAGGER')
                            continue
                        ready_starts.append(name); new_starts+=1
                    dispatches=[(name,None) for name in ready_starts]
                    dispatches.extend((name,None) for name,at in delayed_starts.items() if at<=_now())
                    for job,ready in probes.poll():
                        if job.name not in jobs: continue
                        q.put(job.name,_now() if ready else _now()+_RECHECK_SECONDS,"AUTH" if ready else "TCP")
                    busy_v=sum(kind=="VERIFY" for kind,_ in pending.values())
                    held=[]
                    while True:
                        due=q.pop_due(_now())
                        if due is None: break
                        name,step=due; job=jobs[name]
                        if _now()>=job.deadline:
                            accept(job,adapter.abort(job,"COMPONENT_DEADLINE_EXCEEDED"))
                        elif step=="TCP":
                            probes.request(job)
                            job.phase="TCP_IN_PROGRESS"
                        elif step=="UPGRADE":
                            dispatches.append((name,job))
                        else:
                            if busy_v>=verifiers: held.append((name,step)); continue
                            job.phase=step
                            pending[readers.submit(adapter.advance,job)]=("VERIFY",name); busy_v+=1
                    # Initial tasks and verified next hops share the same ready
                    # queue. A waiting reboot/jitter never reserves a writer.
                    for name,job in sorted(dispatches,key=lambda item:dispatch_key(
                            item[0],item[1].hops if item[1] is not None else 0)):
                        if busy_w>=upgrades:
                            if job is not None: held.append((name,'UPGRADE'))
                            elif name in ready_starts:
                                todo.append(name)
                                todo.sort(key=lambda n:(n not in canaries,dispatch_key(n)))
                            continue
                        if job is None:
                            delayed_starts.pop(name,None)
                            pending[writers.submit(adapter.begin,name,component,name in canaries,stop)]=('UPGRADE',name)
                        else:
                            pending[writers.submit(adapter.next_step,job,stop)]=('UPGRADE',name)
                        busy_w+=1
                    for name,step in held: q.put(name,_now(),step)
                    new_starts=sum(kind=='UPGRADE' and name not in jobs for kind,name in pending.values())
                    if todo and not jobs and not pending and len(unresolved)>=in_flight_limit:
                        for name in todo:
                            block(name,"NOT_EXECUTED","Unresolved remote installers retain the in-flight capacity; manual review required")
                        todo=[]
                    nvued_names={j.name for j in jobs.values() if j.phase=='AUTH'
                                 and getattr(j,'nvued_wait_until',None) and _now()<j.nvued_wait_until}
                    if progress: progress.drain((set(jobs)|{n for _,n in pending.values()})-nvued_names)
                    if _now()-last_progress>=_PROGRESS_HEARTBEAT_SECONDS:
                        sys.stderr.write(f"[PROGRESS {component.upper()}] dispatch-tasks={busy_w} verify-tasks={busy_v} "
                                         f"in-flight={len(jobs)+new_starts+len(unresolved)}/{in_flight_limit} waiting-nvued={len(nvued_names)} "
                                         f"unresolved={len(unresolved)} queued={len(todo)} staggering={len(delayed_starts)} "
                                         f"settled={len(phase['targets'])}/{len(names)-len(no_change)} (includes failures)\n")
                        for name in sorted(nvued_names):
                            remaining=max(0,int(jobs[name].nvued_wait_until-_now()+0.999))
                            wait_stage='WAIT_NVUE_CLI' if jobs[name].readiness_failure=='NVOS_CLI_NOT_READY_AFTER_5_CHECKS' else 'WAIT_NVUED'
                            sys.stderr.write(f"[{component.upper()}][{name}] {wait_stage} "
                                f"checks={jobs[name].nvued_checks}/5 next-check={remaining}s\n")
                        last_progress=_now()
                    if pending:
                        wait(tuple(pending),timeout=0.25,return_when=FIRST_COMPLETED)
                    elif jobs:
                        at=q.next_at()
                        _idle(min(0.25 if probes.pending else 10.0,max(0.001,(at-_now()) if at is not None else 0.25)))
                    elif delayed_starts:
                        _idle(min(1.0,max(0.001,min(delayed_starts.values())-_now())))
            except BaseException:
                stop.set()
                # A child already dispatching is not cancelled/replayed. Retain
                # its context before closing; original requests remain private.
                for future,(kind,name) in list(pending.items()):
                    try:
                        value=future.result()
                        if kind=="UPGRADE":
                            job,_event=value; jobs[name]=job
                    except BaseException:
                        pass
                raise
            finally:
                original=sys.exc_info()[1]
                cleanup=[]
                try: probes.close()
                except BaseException as error: cleanup.append(error)
                for job in list(jobs.values()):
                    try:
                        adapter.abort(job,"coordinator stopped; original request retained for manual review")
                    except BaseException as error: cleanup.append(error)
                    finally:
                        try: job.close()
                        except BaseException as error: cleanup.append(error)
                if cleanup and original is None:
                    raise SharedUpgradeHold("coordinator cleanup incomplete; original outcomes retained") from cleanup[0]
    if writers is None:
        sys.stderr.write('[UPGRADE] No installation tasks; preflight/SSD observations only; no upgrade or verification workers started\n')
    def outcome(name):
        states=matrix[name].values()
        for value in ("UNKNOWN","FAILED","FAIL","NOT_EXECUTED","BLOCKED_CANARY","BLOCKED_PREVIOUS_FAILURE"):
            if value in states: return value
        if len(matrix[name])!=len(components): return 'NOT_EXECUTED'
        return 'NO_CHANGE' if all(s=='PREFLIGHT_NO_CHANGE' for s in states) else 'COMPLETE'
    success=bool(names) and all(outcome(n) in ('COMPLETE','NO_CHANGE') for n in names)
    return dict(state="COMPLETE" if success else "INCOMPLETE",workers=upgrades if writers is not None else 0,
                verification_workers=verifiers if readers is not None else 0,
                in_flight_limit=in_flight_limit if writers is not None else 0,resource_budget=resource_budget,
                unresolved_in_flight=sorted(unresolved),components=phases,
                os_downloads=[row for phase in phases for row in phase['os_downloads']],
                verification_timeline=list(getattr(adapter,"timeline",[])),
                targets=[dict(hostname=n,state=outcome(n)) for n in names])
