"""Group anomalous flows into incidents, so an operator reads one line per
thing that happened rather than one line per packet-flow.

The volume problem this exists for: at the deployed 4.97% false-positive
rate, a network carrying 100,000 flows a day produces about 9,100 alerts a
day, roughly half of them false. That is nineteen people reading alerts
full time, and the documented failure mode of intrusion detection is not
missing an attack -- it is an operator who stopped reading. Meanwhile the
sensor itself sustains 8,796 flows/second, so the bottleneck is a human,
not the model, and the only lever that moves a human's number by an order
of magnitude is not showing them the same event a hundred times.

A port scan is one decision to make and hundreds of flows. A DDoS is one
decision and thousands. Grouping those back together is the difference.

The three patterns are deliberately the same three the engineered features
describe (see source/preprocessing/online.py) -- fan-out, port sweep, and
fan-in -- because those are the shapes a single flow cannot show and a
group can:

    scan    one source reaching many destinations or many ports
    flood   many sources converging on one destination
    repeat  the same source, destination and port, over and over

Anything that fits none of them stays its own incident. That is a real
answer, not a fallback: a lone anomalous flow to one host on one port is
exactly the case an operator should look at individually.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

# A source touching three destinations could be a laptop opening tabs; the
# shape only becomes a scan when it keeps going. Three is low enough to
# catch a slow scan and high enough that ordinary fan-out does not trip it.
DEFAULT_MIN_DISTINCT = 3
# Flows more than this far apart are different incidents even for the same
# key. Five minutes is longer than any single burst and shorter than the
# gap between two deliberate attempts.
DEFAULT_GAP_SECONDS = 300
DEFAULT_MIN_REPEATS = 5

PATTERN_SCAN = "scan"
PATTERN_FLOOD = "flood"
PATTERN_REPEAT = "repeat"
PATTERN_SINGLE = "single"


@dataclass
class Incident:
    """One thing that happened, however many flows it took."""

    pattern: str
    key: str
    flow_ids: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    distinct_src_ips: int = 0
    distinct_dst_ips: int = 0
    distinct_dst_ports: int = 0
    max_error_ratio: float = 0.0
    worst_flow_id: str | None = None

    @property
    def n_flows(self) -> int:
        return len(self.flow_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "key": self.key,
            "n_flows": self.n_flows,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "distinct_src_ips": self.distinct_src_ips,
            "distinct_dst_ips": self.distinct_dst_ips,
            "distinct_dst_ports": self.distinct_dst_ports,
            "max_error_ratio": round(self.max_error_ratio, 4),
            "worst_flow_id": self.worst_flow_id,
            "flow_ids": self.flow_ids,
        }


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _error_ratio(flow: dict[str, Any]) -> float:
    threshold = flow.get("threshold_used") or 0.0
    error = flow.get("reconstruction_error") or 0.0
    return float(error / threshold) if threshold else 0.0


def _sessionise(flows: Sequence[dict[str, Any]], gap_seconds: int) -> list[list[dict[str, Any]]]:
    """Split one key's flows wherever they stop being continuous.

    Without this, a host scanned at 09:00 and again at 17:00 would read as
    one incident spanning eight hours, and an operator would have no way to
    see that it happened twice.
    """
    ordered = sorted(flows, key=lambda f: (_parse_time(f.get("timestamp")) or datetime.min))
    sessions: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    previous: datetime | None = None
    for flow in ordered:
        stamp = _parse_time(flow.get("timestamp"))
        if current and previous and stamp and stamp - previous > timedelta(seconds=gap_seconds):
            sessions.append(current)
            current = []
        current.append(flow)
        previous = stamp or previous
    if current:
        sessions.append(current)
    return sessions


def _build(pattern: str, key: str, flows: Sequence[dict[str, Any]]) -> Incident:
    stamps = [t for t in (_parse_time(f.get("timestamp")) for f in flows) if t]
    worst = max(flows, key=_error_ratio)
    return Incident(
        pattern=pattern,
        key=key,
        flow_ids=[f["flow_id"] for f in flows],
        first_seen=min(stamps) if stamps else None,
        last_seen=max(stamps) if stamps else None,
        distinct_src_ips=len({f.get("src_ip") for f in flows}),
        distinct_dst_ips=len({f.get("dst_ip") for f in flows}),
        distinct_dst_ports=len({f.get("dst_port") for f in flows}),
        max_error_ratio=_error_ratio(worst),
        worst_flow_id=worst["flow_id"],
    )


def _candidates(flows: Sequence[dict[str, Any]], min_distinct: int, min_repeats: int,
                gap_seconds: int) -> list[Incident]:
    """Every grouping that could be made, before deciding which to keep."""
    by_src: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    by_dst: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    by_tuple: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        by_src[flow.get("src_ip")].append(flow)
        by_dst[flow.get("dst_ip")].append(flow)
        by_tuple[(flow.get("src_ip"), flow.get("dst_ip"), flow.get("dst_port"))].append(flow)

    found: list[Incident] = []
    for src, group in by_src.items():
        for session in _sessionise(group, gap_seconds):
            incident = _build(PATTERN_SCAN, str(src), session)
            if max(incident.distinct_dst_ips, incident.distinct_dst_ports) >= min_distinct:
                found.append(incident)
    for dst, group in by_dst.items():
        for session in _sessionise(group, gap_seconds):
            incident = _build(PATTERN_FLOOD, str(dst), session)
            if incident.distinct_src_ips >= min_distinct:
                found.append(incident)
    for key, group in by_tuple.items():
        for session in _sessionise(group, gap_seconds):
            if len(session) >= min_repeats:
                src, dst, port = key
                found.append(_build(PATTERN_REPEAT, f"{src} -> {dst}:{port}", session))
    return found


def group_incidents(
    flows: Iterable[dict[str, Any]],
    min_distinct: int = DEFAULT_MIN_DISTINCT,
    min_repeats: int = DEFAULT_MIN_REPEATS,
    gap_seconds: int = DEFAULT_GAP_SECONDS,
) -> list[Incident]:
    """Anomalous flows in, incidents out, every flow in exactly one.

    A flow can fit several shapes at once -- a DDoS participant is both a
    source reaching a destination and one of many sources reaching it -- so
    the groupings compete and the largest wins, ties broken by the strongest
    flow in the group and then by key so the output does not depend on dict
    ordering. Claiming greedily by size is what makes a thousand-flow flood
    read as one incident instead of a thousand sources with two flows each.
    """
    flows = [f for f in flows if f.get("flow_id")]
    if not flows:
        return []

    candidates = _candidates(flows, min_distinct, min_repeats, gap_seconds)
    candidates.sort(key=lambda i: (-i.n_flows, -i.max_error_ratio, i.pattern, i.key))

    claimed: set[str] = set()
    incidents: list[Incident] = []
    by_id = {f["flow_id"]: f for f in flows}
    for candidate in candidates:
        remaining = [fid for fid in candidate.flow_ids if fid not in claimed]
        # A group that has lost most of its members to a stronger group is no
        # longer the shape it was detected as; re-check rather than emit a
        # "scan" that is now two flows.
        if len(remaining) < 2:
            continue
        rebuilt = _build(candidate.pattern, candidate.key, [by_id[fid] for fid in remaining])
        if candidate.pattern == PATTERN_SCAN and max(
                rebuilt.distinct_dst_ips, rebuilt.distinct_dst_ports) < min_distinct:
            continue
        if candidate.pattern == PATTERN_FLOOD and rebuilt.distinct_src_ips < min_distinct:
            continue
        if candidate.pattern == PATTERN_REPEAT and rebuilt.n_flows < min_repeats:
            continue
        claimed.update(remaining)
        incidents.append(rebuilt)

    for flow in flows:
        if flow["flow_id"] not in claimed:
            incidents.append(_build(PATTERN_SINGLE, str(flow.get("src_ip")), [flow]))

    # Worst first: an operator working top-down should meet the most
    # anomalous thing first, not the largest.
    incidents.sort(key=lambda i: (-i.max_error_ratio, -i.n_flows))
    return incidents


def summarise(incidents: Sequence[Incident], n_flows: int) -> dict[str, Any]:
    by_pattern: dict[str, int] = defaultdict(int)
    for incident in incidents:
        by_pattern[incident.pattern] += 1
    return {
        "n_flows": n_flows,
        "n_incidents": len(incidents),
        "reduction": round(1 - len(incidents) / n_flows, 4) if n_flows else 0.0,
        "by_pattern": dict(by_pattern),
    }
