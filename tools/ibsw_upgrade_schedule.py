"""Component ordering, status lists and one-device verified upgrade execution.

The manual coordinator uses live identity, configuration and version evidence;
no load/Git/file-lock gate is involved. The separate callback-only schedule
simulator at the end is for tests and cannot establish a real device outcome.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from ibsw_upgrade_contract import UpgradePolicy


COMPONENT_REGISTRY = ("os", "bios", "cpld")
COMPONENT_ORDER = ("os", "bios", "cpld")


def select_os_canaries(policy, version_rows, names):
    """Minimum complete-route suffix cover DATA, never dispatch permission.

    All actual paths end at one final OS. A shorter route is covered only if
    its entire ordered sequence of (source, target, package) hops is a suffix
    of one selected route. One representative of each distinct maximal route
    is necessary and sufficient; this is not a heuristic numeric interval or
    a union of unrelated partially exercised routes. No external IO.
    """
    from ibsw_upgrade_contract import SharedUpgradeHold, select_os_path
    try:
        names = tuple(names)
        if (not isinstance(policy, UpgradePolicy) or not policy.os
                or any(type(n) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', n) for n in names)
                or len({n.casefold() for n in names}) != len(names)):
            raise ValueError('original distinct OS targets required')
        records = {}
        for row in version_rows:
            if type(row) is not dict or row.get('component') != 'os':
                raise ValueError('OS route rows required')
            name = row.get('hostname')
            if name not in names or name in records:
                raise ValueError('duplicate or foreign OS route')
            records[name] = row
        if set(records) != set(names):
            raise ValueError('missing OS route')
        by_version = {p.version: p for p in policy.os}
        routes, details = {}, {}
        for name in names:
            row = records[name]
            path = row.get('path')
            if (type(path) not in (tuple, list) or not path or path[0] != row.get('current')
                    or path[-1] != policy.final_os or row.get('target') != policy.final_os
                    or any(type(v) is not str or v not in by_version for v in path)):
                raise ValueError('unknown or inconsistent actual OS path')
            packages = tuple(by_version[v] for v in path[1:])
            actual = select_os_path(policy, path[0], available=frozenset(p.path for p in packages))
            if (tuple(actual) != packages or row.get('action') !=
                    ('UPGRADE_REQUIRED' if packages else 'AT_TARGET_NO_FLASH')):
                raise ValueError('unapproved or incomplete OS route')
            for key, expected in (('files', [p.file for p in packages]),
                                  ('package_paths', [p.path for p in packages])):
                if key in row and row[key] != expected:
                    raise ValueError('OS package selection differs from route')
            if packages:
                routes[name] = tuple((source, p.version, p.file, p.path, p.url)
                                     for source, p in zip(path, packages))
                details[name] = dict(hostname=name, path=list(path), files=[p.file for p in packages])
        selected = []
        order = {name: i for i, name in enumerate(names)}
        for name in sorted(routes, key=lambda n: (-len(routes[n]), order[n])):
            if not any(routes[c][-len(routes[name]):] == routes[name] for c in selected):
                selected.append(name)
        return dict(canaries=selected, routes=[dict(details[name], covers=[n for n in names
                    if n in routes and routes[name][-len(routes[n]):] == routes[n]]) for name in selected])
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise SharedUpgradeHold('OS_CANARY_ROUTE_PLAN_INVALID') from error


def component_order(selected, order=COMPONENT_ORDER):
    """Fixed DATA ordering, not dispatch or OS-final permission. No imports."""
    if (not isinstance(selected, (tuple, list)) or not selected
            or len(set(selected)) != len(selected) or set(selected) - set(COMPONENT_REGISTRY)
            or not isinstance(order, (tuple, list)) or len(order) != 3
            or set(order) != set(COMPONENT_REGISTRY) or order[0] != "os"):
        raise ValueError("unique selected components and exact fixed-registry permutation required")
    return tuple(component for component in order if component in selected)


def component_status_document(component, run_id, plan_sha256, input_sha256, targets, canary):
    """Initial local DATA list only; no native completion/current facts."""
    component_order((component,))
    return {"schema_version": 1, "component": component, "run_id": run_id,
        "plan_sha256": plan_sha256, "input_sha256": input_sha256,
        "canary": canary, "revision": 0, "execution_state": "NOT_EXECUTED",
        "attestation_state": "DATA_ONLY_UNATTESTED",
        "targets": [{"node": node, "state": "NOT_EXECUTED", "manual_required": False,
                     "reason": None, "evidence": []} for node in targets]}


def validate_component_status_document(document, initial):
    """Exact source-bound DATA; callers cannot persist a PASS permission."""
    mutable = {"revision", "targets"}
    if (not isinstance(document, dict) or set(document) != set(initial)
            or any(document[key] != initial[key] for key in set(initial) - mutable)
            or type(document["revision"]) is not int or not 0 <= document["revision"] <= 2147483647
            or not isinstance(document["targets"], list) or len(document["targets"]) != len(initial["targets"])):
        raise ValueError("component status does not match original plan/targets")
    for actual, declared in zip(document["targets"], initial["targets"]):
        if (not isinstance(actual, dict) or set(actual) != set(declared)
                or actual["node"] != declared["node"] or actual["state"] not in {"NOT_EXECUTED", "FAIL", "UNKNOWN"}
                or type(actual["manual_required"]) is not bool
                or actual["manual_required"] != (actual["state"] != "NOT_EXECUTED")
                or (actual["state"] == "NOT_EXECUTED" and (actual["reason"] is not None or actual["evidence"]))
                or (actual["state"] != "NOT_EXECUTED" and (not isinstance(actual["reason"], str)
                    or not actual["reason"] or len(actual["reason"]) > 512))
                or not isinstance(actual["evidence"], list)):
            raise ValueError("unknown component-list DATA state; no caller PASS")
        seen = set()
        for reference in actual["evidence"]:
            if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
                    or not isinstance(reference["path"], str) or reference["path"] in seen
                    or reference["path"].split("/")[0] != actual["node"]["hostname"]
                    or len(reference["path"].split("/")) != 3
                    or reference["path"].split("/")[-1] not in {"step-binding.json", "request.json", "os-dispatch.json"}
                    or (reference["path"].split("/")[1] != document["component"]
                        if document["component"] != "os" else not re.fullmatch(r"os-[0-9]{4}", reference["path"].split("/")[1]))
                    or not isinstance(reference["sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])):
                raise ValueError("unknown original component evidence reference")
            seen.add(reference["path"])
    return document


def declared_step_key(policy, component, package_index=0):
    """Private artifact ordering only; not version, OS-final or dispatch approval."""
    if not isinstance(policy, UpgradePolicy) or type(package_index) is not int:
        raise ValueError("declared policy and integer candidate index required")
    if component == "os" and 0 <= package_index < len(policy.os):
        return f"os-{package_index:04d}"
    if package_index == 0 and ((component == "bios" and policy.bios is not None)
                              or (component == "cpld" and policy.cpld_burn is not None
                                  and policy.cpld_refresh is not None)):
        return component
    raise ValueError("selected declared component candidate required")


def native_component_status_document(component, run_id, plan_sha256, input_sha256, targets, canary,
                                     *, canaries=None, canary_routes=None):
    document = component_status_document(component, run_id, plan_sha256, input_sha256, targets, canary)
    document.update(schema_version=2, execution_state="OBSERVATION_FACTS_ONLY")
    if canaries is not None or canary_routes is not None:
        document.update(schema_version=3, canaries=list(canaries or ()), canary_routes=list(canary_routes or ()))
    return document


def validate_native_component_status_document(document, initial):
    """Persisted observations are facts, never cold-start dispatch authority."""
    if type(document) is not dict or type(initial) is not dict:
        raise ValueError('native component documents must be mappings')
    mutable = {"revision", "targets", "canary"}
    if initial.get('schema_version') == 3:
        mutable.update(('canaries', 'canary_routes'))
        names = [r['node']['hostname'] for r in initial['targets']]
        canaries = document.get('canaries')
        routes = document.get('canary_routes')
        if (type(canaries) is not list or any(type(n) is not str or n not in names for n in canaries)
                or len(set(canaries)) != len(canaries) or document.get('canary') != (canaries[0] if canaries else None)
                or type(routes) is not list or (routes and (document.get('component') != 'os'
                    or len(routes) != len(canaries)))):
            raise ValueError('invalid native canary set or coverage')
        for name, route in zip(canaries, routes):
            if (type(route) is not dict or set(route) != {'hostname','path','files','covers'}
                    or route['hostname'] != name or type(route['path']) is not list or len(route['path']) < 2
                    or any(type(v) is not str or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', v) for v in route['path'])
                    or type(route['files']) is not list or len(route['files'])+1 != len(route['path'])
                    or any(type(f) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*',f) for f in route['files'])
                    or type(route['covers']) is not list or name not in route['covers']
                    or any(type(n) is not str or n not in names for n in route['covers'])
                    or len(set(route['covers'])) != len(route['covers'])):
                raise ValueError('invalid native canary route attribution')
    if (type(document) is not dict or set(document) != set(initial)
            or any(document[k] != initial[k] for k in set(initial) - mutable)
            or (document["canary"] is not None if initial["canary"] is None else
                document["canary"] is not None and
                document["canary"] not in [row["node"]["hostname"] for row in initial["targets"]])
            or type(document["revision"]) is not int or not 0 <= document["revision"] <= 2147483647
            or type(document["targets"]) is not list or len(document["targets"]) != len(initial["targets"])):
        raise ValueError("native component facts differ from original sources")
    for row, original in zip(document["targets"], initial["targets"]):
        if (type(row) is not dict or set(row) != set(original) or row["node"] != original["node"]
                or row["state"] not in {"NOT_EXECUTED", "VERIFIED", "FAIL", "UNKNOWN"}
                or type(row["manual_required"]) is not bool
                or row["manual_required"] != (row["state"] in {"FAIL", "UNKNOWN"})
                or type(row["evidence"]) is not list
                or (row["state"] == "NOT_EXECUTED" and (row["evidence"] or (row["reason"] is not None and
                    (type(row["reason"]) is not str or not 0 < len(row["reason"]) <= 512))))
                or (row["state"] == "VERIFIED" and (row["reason"] is not None or not row["evidence"]))
                or (row["state"] in {"FAIL", "UNKNOWN"} and
                    (type(row["reason"]) is not str or not 0 < len(row["reason"]) <= 512))):
            raise ValueError("unknown native observation state")
        seen = set()
        for ref in row["evidence"]:
            parts = ref.get("path", "").split("/") if type(ref) is dict else []
            if (type(ref) is not dict or set(ref) != {"path", "sha256"} or len(parts) != 3
                    or parts[0] != row["node"]["hostname"] or ref["path"] in seen
                    or parts[2] not in {"step-binding.json", "request.json", "component-dispatch.json", "component-completion.json"}
                    or (not re.fullmatch(r"os-[0-9]{4}", parts[1]) if document["component"] == "os"
                        else parts[1] != document["component"])
                    or type(ref["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", ref["sha256"])):
                raise ValueError("unknown original native completion reference")
            seen.add(ref["path"])
        if row["state"] == "VERIFIED" and not any(r["path"].endswith("/component-completion.json") for r in row["evidence"]):
            raise ValueError("verified observation requires original completion evidence")
    return document


def _native_failure_reason(error):
    """Safe code/source only; never echo SDK text, credentials or config values."""
    from pathlib import Path
    modules = {"ibsw_upgrade_driver.py", "ibsw_upgrade_executor.py", "ibsw_upgrade_observer.py",
               "ibsw_upgrade_schedule.py", "ibsw_upgrade_contract.py", "ibsw_upgrade_inputs.py",
               "ibsw_upgrade_pipeline.py", "ibsw_upgrade_access.py"}
    code = getattr(error, "reason_code", "")
    if type(code) is not str or re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", code) is None:
        code = type(error).__name__
    source = None
    trace = error.__traceback__
    while trace is not None:
        module = Path(trace.tb_frame.f_code.co_filename).name
        if module in modules:
            source = f"{module}:{trace.tb_lineno} ({trace.tb_frame.f_code.co_name})"
        trace = trace.tb_next
    reason=code + (" at " + source if source else "")
    capture=getattr(error,'capture_raw',None)
    safe=capture.get('safe_diagnostic') if type(capture) is dict else None
    if type(safe) is dict and safe.get('command') in {
            'id -u','test -x /bin/bash && test -x /usr/bin/nohup','nv config show -o commands',
            'nv config diff -o commands','nv show system version','nv show system health','nv show platform firmware'}:
        reason+=' | query='+safe['command']
        budget=safe.get('budget_seconds')
        if type(budget) in (int,float) and 0<budget<=120:
            reason+=' | query-budget='+format(budget,'g')+'s'
        for field in ('returncode','stream_complete','elapsed_seconds','stdout_bytes','stderr_bytes'):
            value=safe.get(field)
            if value is None or type(value) in (int,bool): reason+=' '+field+'='+str(value)
            elif type(value) is float and 0<=value<1e9: reason+=' '+field+'='+str(round(value,3))
    if type(safe) is dict:
        name=safe.get('file')
        if type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,180}',name): reason+=' | file='+name
        if safe.get('operation') in ('open','lstat','stat','read','close','rename'):
            reason+=' | operation='+safe['operation']
        if type(safe.get('errno')) is int and 0<safe['errno']<4096:
            reason+=' | errno='+str(safe['errno'])
    from ibsw_upgrade_access import AccessHold
    if isinstance(error,AccessHold):
        diagnostic=error.diagnostic
        reason+=' | access-check='+diagnostic['check_code']+' access-phase='+diagnostic['phase']
        for name in ('role','mode','owner_uid','expected_uid','operation','native_errno'):
            if name in diagnostic: reason+=' '+name+'='+str(diagnostic[name])
    return reason


def run_upgrade_component(scope, node, component, *, known_hosts_path, identity_path,
                          management_public_path, user, password, stop_event=None):
    """One node/component using the original native executor and completion gate.

    The fixed coordinator owns component-canary release. No readiness DTO,
    saved status or caller boolean can replace actual execution/readback facts.
    """
    from ibsw_upgrade_contract import ComponentDispatchResult, ComponentCompletionResult, SharedUpgradeHold
    from ibsw_upgrade_observer import _observe_component_completion_once
    scope.verify()
    if ((not getattr(scope, "manual_execution", False) and not scope.parsed.exclusive_config_window) or not scope._native_schedule_started
            or node not in scope.devices or component not in scope.parsed.selected):
        raise SharedUpgradeHold("original initialized component/window/target required")
    attempted, dispatched = False, False
    try:
        for _ in range(len(scope.policy.os) + 1 if component == "os" else 1):
            if stop_event is not None and stop_event.is_set():
                if attempted:
                    scope.verify()
                    scope._record_native_component_failure(component, node, "UNKNOWN", "shared stop before final component target")
                return {"hostname": node, "component": component, "state": "UNKNOWN" if attempted else "NOT_EXECUTED"}
            with scope.open_readonly_query_inputs(node, known_hosts_path=known_hosts_path,
                    identity_path=identity_path, management_public_path=management_public_path, user=user) as leaf:
                dispatch = leaf.execute_component_once(component, password=password)
                attempted = True
                if type(dispatch) is not ComponentDispatchResult or dispatch.hostname != node or dispatch.component != component:
                    raise SharedUpgradeHold("fixed backend returned foreign component facts")
                dispatched |= dispatch.state == "DISPATCHED_UNKNOWN"
                # Once dispatched, always collect its outcome; never cancel,
                # resend or assume success because another worker has stopped.
                completion = _observe_component_completion_once(leaf, dispatch, password=password)
                if (type(completion) is not ComponentCompletionResult or completion.hostname != node
                        or completion.component != component or not scope._has_component_completion(dispatch, completion)):
                    raise SharedUpgradeHold("completion lacks original live native receipt")
            if completion.state != "VERIFIED" or component != "os" or completion.target_version == scope.policy.final_os:
                break
        else:
            raise SharedUpgradeHold("bounded original OS chain did not reach final target")
        scope._record_native_component_status(component, node, completion)
        scope.verify()
        row = {"hostname": node, "component": component,
               "state": "COMPLETE" if completion.state == "VERIFIED" else completion.state}
        if completion.state == "VERIFIED":
            row["action"] = "UPGRADE_PERFORMED_AND_VERIFIED" if dispatched else "ALREADY_AT_TARGET_VERIFIED"
        if completion.reason is not None:
            row["reason"] = completion.reason
            row["log_directory"] = str(scope.run_directory / node / dispatch.stage)
        return row
    except SharedUpgradeHold:
        if stop_event is not None:
            stop_event.set()
        raise
    except Exception as error:
        try:
            scope.verify()
            state = ("NOT_EXECUTED" if getattr(scope, "manual_execution", False) and not attempted
                     and not scope.component_attempt_may_have_started(node, component) else "UNKNOWN")
            reason = _native_failure_reason(error)
            scope._record_native_component_failure(component, node, state, reason)
        except Exception as shared:
            if stop_event is not None:
                stop_event.set()
            raise SharedUpgradeHold("shared source/record failure stops the batch") from shared
        return {"hostname": node, "component": component, "state": state, "reason": reason,
                "log_directory": str(scope.run_directory / node)}


def run_upgrade(scope, *, known_hosts_path, identity_path, management_public_path, user, password):
    """Fixed actual backend/completion only. Saved lists cannot release canaries."""
    from ibsw_upgrade_contract import ComponentDispatchResult, ComponentCompletionResult, SharedUpgradeHold
    from ibsw_upgrade_observer import _observe_component_completion_once
    selected = component_order(scope.parsed.selected)
    if not scope.parsed.exclusive_config_window:
        raise SharedUpgradeHold("explicit exclusive configuration maintenance window required")
    if scope._native_schedule_started:
        raise SharedUpgradeHold("same run cannot be dispatched twice; retained outcomes require review")
    scope.verify()
    scope.initialize_native_component_status_data()
    scope._native_schedule_started = True
    nodes = tuple(scope.devices)
    states, completed, quarantined = dict.fromkeys(nodes, "NOT_EXECUTED"), {n: set() for n in nodes}, set()
    skip = scope.parsed.canary_mode == "skip"
    for component in selected:
        eligible = tuple(node for node in nodes if node not in quarantined)
        if not eligible:
            continue
        # A failure never rotates this component's canary. The next distinct
        # component independently chooses its first still-eligible node.
        canary = None if skip else eligible[0]
        if canary is not None:
            scope._record_native_component_canary(component, canary)
        released = skip
        for node in nodes:
            if node in quarantined or (node != canary and not released):
                continue
            try:
                # Each OS package obtains and closes its own one-shot leaf;
                # the fixed backend freshly selects the next actual stage.
                for _ in range(len(scope.policy.os) + 1 if component == "os" else 1):
                    with scope.open_readonly_query_inputs(node, known_hosts_path=known_hosts_path,
                            identity_path=identity_path, management_public_path=management_public_path, user=user) as leaf:
                        dispatch = leaf.execute_component_once(component, password=password)
                        if type(dispatch) is not ComponentDispatchResult or dispatch.hostname != node or dispatch.component != component:
                            raise SharedUpgradeHold("fixed backend returned foreign component facts")
                        completion = _observe_component_completion_once(leaf, dispatch, password=password)
                        if (type(completion) is not ComponentCompletionResult or completion.hostname != node
                                or completion.component != component or not scope._has_component_completion(dispatch, completion)):
                            raise SharedUpgradeHold("fixed completion was not committed as an original held fact")
                    if completion.state != "VERIFIED" or component != "os" or completion.target_version == scope.policy.final_os:
                        break
                else:
                    raise SharedUpgradeHold("bounded original OS declaration chain did not reach its final target")
                scope._record_native_component_status(component, node, completion)
                if completion.state == "VERIFIED":
                    completed[node].add(component)
                    states[node] = "COMPLETE" if set(selected) <= completed[node] else "VERIFIED"
                    if node == canary:
                        released = True
                else:
                    states[node] = completion.state
                    quarantined.add(node)
            except SharedUpgradeHold:
                raise
            except Exception as error:
                # Check original shared sources before classifying a node error.
                try:
                    scope.verify()
                    scope._record_native_component_failure(component, node, "UNKNOWN", type(error).__name__)
                except Exception as shared:
                    raise SharedUpgradeHold("shared source/record failure stops the entire batch") from shared
                states[node] = "UNKNOWN"
                quarantined.add(node)
    return ScheduleResult("COMPLETE" if all(v == "COMPLETE" for v in states.values()) else
                          "PARTIAL" if any(completed.values()) else "HOLD", tuple(states.items()), skip)


@dataclass(frozen=True)
class Node:
    name: str
    identity_trusted: bool = False


@dataclass(frozen=True)
class StageResult:
    ok: bool
    os_final_verified: bool = False


@dataclass(frozen=True)
class ScheduleResult:
    state: str
    nodes: tuple[tuple[str, str], ...]
    skipped_canary: bool


class SharedScheduleHold(RuntimeError):
    """Explicit common-safety stop in the isolated simulator, not attribution API.

    Real shared-source/package/record failures must be derived by the fixed
    native driver itself. This exception and callbacks never issue permission.
    """


def run_schedule(nodes, execute, *, selected, skip_canary=False, canary=None, order=COMPONENT_ORDER):
    """Component-canary local precedence only; no file/PASS/native admission."""
    nodes = tuple(nodes)
    selected = component_order(selected, order)
    if not nodes or len({node.name for node in nodes}) != len(nodes):
        raise ValueError("nonempty unique node names required")
    if not selected or len(set(selected)) != len(selected) or set(selected) - {"os", "bios", "cpld"}:
        raise ValueError("explicit unique supported components required")
    if type(skip_canary) is not bool:
        raise ValueError("skip_canary must be boolean")
    if canary is not None and canary not in {node.name for node in nodes}:
        raise ValueError("canary must belong to selected nodes")
    states = {node.name: "NOT_STARTED" for node in nodes}
    def result(state):
        return ScheduleResult(state, tuple(states.items()), skip_canary)
    quarantined, backed_up, verified_os = set(), set(), set()
    completed = {node.name: set() for node in nodes}
    for node in nodes:
        if node.identity_trusted is not True:
            quarantined.add(node.name)
            states[node.name] = "HOLD"
    shared_hold = False
    def stage(node, name):
        nonlocal shared_hold
        states[node.name] = "IN_PROGRESS"
        try:
            observed = execute(node, name)
        except SharedScheduleHold:
            states[node.name] = "UNKNOWN"
            quarantined.add(node.name)
            shared_hold = True
            return False
        except Exception:
            states[node.name] = "UNKNOWN"
            quarantined.add(node.name)
            return False
        if not isinstance(observed, StageResult) or type(observed.ok) is not bool or type(observed.os_final_verified) is not bool:
            states[node.name] = "UNKNOWN"
            quarantined.add(node.name)
            return False
        if not observed.ok or (name == "os_final" and not observed.os_final_verified):
            states[node.name] = "HOLD"
            quarantined.add(node.name)
            return False
        states[node.name] = name.upper() + "_VERIFIED"
        return True
    def checks(node):
        for name in ("config", "health", "evidence"):
            if not stage(node, name):
                return False
        return True

    def component(node, selected_component):
        if node.name in quarantined:
            return False
        if node.name not in backed_up:
            if not stage(node, "backup"):
                return False
            backed_up.add(node.name)
        # FW-only checks its own OS-final precondition; it does not select an
        # OS write or read another component list. These callbacks remain a
        # simulator seam, not actual postactivation current/health facts.
        if node.name not in verified_os:
            if not stage(node, "os_final") or not checks(node):
                return False
            verified_os.add(node.name)
            if "os" in selected:
                completed[node.name].add("os")
            states[node.name] = "OS_VERIFIED"
        if selected_component != "os":
            if not stage(node, selected_component) or not checks(node):
                return False
            completed[node.name].add(selected_component)
            states[node.name] = selected_component.upper() + "_VERIFIED"
        return True

    chosen = None if skip_canary else next(node for node in nodes if node.name == (canary or nodes[0].name))
    for selected_component in selected:
        if chosen is not None:
            # A failed canary cannot release an unverified later component.
            # Its already-complete OS acceptance remains independently useful.
            if selected_component == "os" and chosen.name in verified_os:
                accepted = True
            else:
                accepted = component(chosen, selected_component)
            if shared_hold:
                return result("HOLD")
            if not accepted:
                continue
        for node in nodes:
            if chosen is not None and node == chosen:
                continue
            component(node, selected_component)
            if shared_hold:
                return result("HOLD")
    for node in nodes:
        if set(selected).issubset(completed[node.name]):
            states[node.name] = "COMPLETE"
    if all(state == "COMPLETE" for state in states.values()):
        return result("COMPLETE")
    return result("PARTIAL" if any(completed.values()) else "HOLD")
