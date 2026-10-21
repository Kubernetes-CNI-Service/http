"""One fresh-read sync attempt. External IO belongs only to the backend.

No SDK, credentials, worker, timer, retry, enrollment or completion permit is
installed here. A successful method return is not durable remote completion.
"""

from dataclasses import dataclass

from monitor.issue_tracker_cable_merge import plan_current_online


@dataclass(frozen=True)
class CableCycleResult:
    state: str
    phase: str
    business_effect: str
    history_effect: str


def sync_current_once(changes, backend):
    """Always read afresh; retain local work and never retry within this call.

    Ordinary failures carry fixed diagnostics only. In particular a business
    transport exception can follow a remote effect, and means UNKNOWN, not
    zero writes. Interruptions/BaseException propagate without a retry.
    """
    phase = 'read'
    business_effect = 'NOT_ATTEMPTED'
    history_effect = 'NOT_ATTEMPTED'
    try:
        current = backend.read_current()
        phase = 'merge'
        plan = plan_current_online(changes, current)
        if not plan.actions:
            return CableCycleResult('NO_CHANGE', 'complete',
                                    business_effect, history_effect)
        phase = 'business'
        business_effect = 'UNKNOWN'
        backend.write_business(plan.requests_json)
        business_effect = 'API_RETURNED'
        phase = 'history'
        history_effect = 'UNKNOWN'
        backend.append_history(plan.history_rows)
        history_effect = 'API_RETURNED'
    except Exception:
        return CableCycleResult('FAILED', phase, business_effect, history_effect)
    return CableCycleResult('API_RETURNED', 'complete',
                            business_effect, history_effect)
