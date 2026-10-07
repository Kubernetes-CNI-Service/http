"""Read-only, ETH-only per-key source continuity from protected prod cycles.

This is not the three-panel status producer, Whitelist decision, C5 qualified
set, local publication, or an online permit. The pure reducer accepts typed
fixtures; only the I/O entrypoint reopens worker/emitter-owned source bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from monitor.issue_tracker_activity_source import EthLinkObservation
from monitor.issue_tracker_cycle_source import CycleEvidence, read_completed_cycle_evidence
from monitor.issue_tracker_k_chain import (
    KChainState, assess_k_window, assess_per_key_window,
)
from monitor.issue_tracker_local_commit import _owner
from monitor.issue_tracker_state_owner import current_k
from monitor.issue_tracker_switch_runtime import (
    ProdEthActivityCycleSource, read_prod_eth_activity_cycle_source,
    validate_prod_eth_activity_cycle_source,
)
from monitor.issue_tracker_topology_derivation import TopologyDerivationWitness


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MISWIRED = frozenset(("WRONG_PEER", "SW_LLDP_PRESENT", "NO_LLDP"))
_MISSING = frozenset(("DOWN", "MISSING_DEVICE", "MISSING_INTERFACE"))


class PerKeySourceHold(ValueError):
    """Protected source evidence cannot support even a local progress claim."""


@dataclass(frozen=True)
class EthPerKeySourceStatus:
    state: str
    reason: str
    observed: int
    required: int
    key: tuple[str, str, str, str]
    cycle_ids: tuple[str, ...]
    completion_sha256: tuple[str, ...]
    activity_sha256: tuple[str, ...]
    k_event_sha256: str
    qualified: bool = False


def _key_for_link(link):
    if type(link) is not EthLinkObservation:
        raise PerKeySourceHold("ETH activity has an invalid link type")
    if link.status in _MISWIRED:
        issue_type = "Mis-wiring"
    elif link.status in _MISSING:
        issue_type = "Link Down"
    elif link.status in ("CONFIRMED_BOTH_SIDE", "CONFIRMED_SW_SIDE"):
        return None
    else:
        raise PerKeySourceHold("ETH activity status is unknown")
    parts = (link.device_a, link.interface_a, link.device_b, link.interface_b)
    if any(type(part) is not str or not part or "\x00" in part for part in parts):
        raise PerKeySourceHold("ETH activity endpoint is invalid")
    return ("eth_cabling", link.device_a, link.interface_a, issue_type)


def reduce_eth_per_key_sources(cycles, sources, settings, key):
    """Count active normalized keys, not repeated measurements; never grant trust."""
    try:
        if (type(settings) is not KChainState
                or type(settings.k) is not int or settings.k < 1
                or type(cycles) is not tuple
                or not cycles or type(sources) is not tuple
                or len(sources) != len(cycles) or type(key) is not tuple
                or len(key) != 4 or key[0] != "eth_cabling"
                or key[3] not in ("Mis-wiring", "Link Down")
                or any(type(part) is not str or not part or chr(0) in part
                       for part in key)):
            raise PerKeySourceHold("ETH per-key source shape is invalid")
        assess_k_window(cycles, settings)
        if len(cycles) > settings.k:
            raise PerKeySourceHold("ETH per-key reducer needs one K suffix")
        topology = None
        activity_hashes = set()
        expected_by_key = {}
        rows_by_cycle = {}
        for cycle, source in zip(cycles, sources):
            if (type(cycle) is not CycleEvidence
                    or type(source) is not ProdEthActivityCycleSource
                    or source.qualified is not False or cycle.qualifying is not True
                    or source.cycle_id != cycle.cycle_id
                    or source.sequence != cycle.sequence
                    or source.completion_sha256 != cycle.completion_sha256
                    or type(source.activity_sha256) is not str
                    or _SHA.fullmatch(source.activity_sha256) is None
                    or source.activity_sha256 in activity_hashes
                    or type(source.derivation) is not TopologyDerivationWitness
                    or source.derivation.qualified is not False
                    or type(source.links) is not tuple):
                raise PerKeySourceHold("ETH source is missing, replayed, or rebound")
            current_topology = source.derivation.source_sha256
            if (not isinstance(current_topology, dict) or "topology" not in current_topology
                    or any(type(role) is not str or not role
                           or type(digest) is not str or _SHA.fullmatch(digest) is None
                           for role, digest in current_topology.items())):
                raise PerKeySourceHold("ETH P2P derivation identity is invalid")
            # O-4 compares the independently verified expected P2P authority,
            # not release ID or every incidental derivation-input digest.
            # Physical-edge changes are unsafe even if someone reuses a digest.
            frozen_topology = (current_topology["topology"], source.derivation.edges)
            if topology is not None and frozen_topology != topology:
                raise PerKeySourceHold("ETH P2P derivation changed within K")
            topology = frozen_topology
            activity_hashes.add(source.activity_sha256)
            rows = {}
            for link in source.links:
                item_key = _key_for_link(link)
                if item_key is None:
                    continue
                if item_key in rows:
                    raise PerKeySourceHold("ETH source has duplicate activity key")
                expected = (link.device_a, link.interface_a,
                            link.device_b, link.interface_b)
                if (item_key in expected_by_key
                        and expected_by_key[item_key] != expected):
                    raise PerKeySourceHold("ETH expected peer changed within topology")
                expected_by_key[item_key] = expected
                rows[item_key] = link
            rows_by_cycle[cycle.cycle_id] = rows
        # Changed peer/status measurements with the same normalized active
        # key retain continuity. The latest source remains independently bound;
        # no older measurement is promoted as the latest business value.
        observed = {
            cycle.cycle_id: frozenset(rows_by_cycle[cycle.cycle_id])
            for cycle in cycles
        }
        window = assess_per_key_window(cycles, observed, settings, key)
        return EthPerKeySourceStatus(
            state=("source_window_complete" if window.status == "qualified"
                   else "pending"),
            reason=window.reason, observed=window.observed,
            required=window.required, key=key,
            cycle_ids=tuple(cycle.cycle_id for cycle in cycles),
            completion_sha256=tuple(cycle.completion_sha256 for cycle in cycles),
            activity_sha256=tuple(source.activity_sha256 for source in sources),
            k_event_sha256=settings.event_sha256,
        )
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, PerKeySourceHold):
            raise
        raise PerKeySourceHold("ETH per-key source evidence is unsafe") from exc


def read_prod_eth_per_key_source(store, *, http_root, settings, key, writer_token):
    """Reopen each protected ETH role under a held project writer lock."""
    try:
        root = Path(http_root).resolve(strict=True)
        owner = _owner(writer_token)
        project = Path(store.project_identity)
        if (store.scope != "prod" or project != owner.project
                or owner.publication != project / "99-output-monitor"
                or Path(store.root_status_dir) != root / "monitor/status"
                or current_k(writer_token) != settings):
            raise PerKeySourceHold("ETH per-key worker/K owner differs")
        cycles = read_completed_cycle_evidence(store)
        if not cycles:
            raise PerKeySourceHold("ETH per-key cycle source is absent")
        tail = cycles[-settings.k:]
        sources = tuple(read_prod_eth_activity_cycle_source(
            store, http_root=root, sequence=cycle.sequence,
        ) for cycle in tail)
        result = reduce_eth_per_key_sources(tail, sources, settings, key)
        if (current_k(writer_token) != settings
                or read_completed_cycle_evidence(store) != cycles
                or any(validate_prod_eth_activity_cycle_source(
                    source, store, http_root=root,
                ) != source for source in sources)):
            raise PerKeySourceHold("ETH per-key source changed before readback")
        return result
    except (OSError, TypeError, KeyError, AttributeError, RuntimeError,
            ValueError) as exc:
        if isinstance(exc, PerKeySourceHold):
            raise
        raise PerKeySourceHold("ETH per-key protected source is unsafe") from exc
