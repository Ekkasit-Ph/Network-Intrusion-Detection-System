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

The groupings are the same shapes the engineered features describe (see
source/preprocessing/online.py), because those are what a single flow
cannot show and a group can:

    fan_out    one source reaching many destinations or many ports
    fan_in     many sources converging on one destination
    repeated   the same source, destination and port, over and over
    isolated   fits none of the above

`isolated` is a real answer, not a fallback: a lone anomalous flow to one
host on one port is exactly the case an operator should look at on its own.

These names describe the shape and nothing more, deliberately. Earlier they
were `scan`, `flood` and `repeat`, which read as attack types -- and the
detector has no notion of attack type, it emits one reconstruction error
per flow and no class. Checked against the dataset's own labels, the names
were not merely unproven but wrong: incidents shaped like `fan_in` were 71%
`scanning` flows and almost no `ddos`, while every `ddos` flow in the
sample landed in a `fan_out` group. A badge reading FLOOD over scanning
traffic is worse than no badge, because an operator would act on it.

What the shape does support is triage: "this host touched 300 destinations"
is a fact about the flows, true whether the cause is a port scan, a
vulnerability sweep run by the security team, or a monitoring agent
polling. Which of those it is remains a human judgement, and the panel
should not pretend otherwise.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

import numpy as np

# An absolute floor, not the test. Three is the smallest count where "many"
# is meaningful at all; whether a given three is worth reporting is decided
# by _outlier_floor below, against the rest of the window.
DEFAULT_MIN_DISTINCT = 3
# How far above the typical key a count must sit to be called a pattern.
# Robust z (median + k x scaled MAD), so one enormous scan does not raise
# the bar for everything else the way a mean and standard deviation would.
#
# 4.0 from measurement, not taste. Over 25 windows of 400 structureless
# flows, and against three planted patterns:
#
#     z    false groups/window    finds a 20-flow sweep
#    3.0          0.80                  25/25
#    4.0          0.28                  25/25
#    5.0          0.04                   9/25
#
# 5.0 nearly clears the false groups and loses the small sweep two times in
# three, which is the wrong trade for a detector: a spurious row costs a
# glance, a missed one costs the thing this system is for. 4.0 is the knee
# -- most of the reduction, none of the sensitivity.
DEFAULT_OUTLIER_Z = 4.0
# Flows more than this far apart are different incidents even for the same
# key. Five minutes is longer than any single burst and shorter than the
# gap between two deliberate attempts.
DEFAULT_GAP_SECONDS = 300
DEFAULT_MIN_REPEATS = 5

PATTERN_FAN_OUT = "fan_out"
PATTERN_FAN_IN = "fan_in"
PATTERN_REPEATED = "repeated"
PATTERN_ISOLATED = "isolated"


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


def _outlier_floor(counts: Sequence[int], z: float, hard_floor: int) -> float:
    """The count a key has to beat to be a pattern rather than arithmetic.

    Spread flows over a fixed set of hosts and every host ends up contacted
    by many sources, with no attacker anywhere: 500 flows across 30
    destinations gives each about seventeen, from about seventeen different
    sources. A fixed `>= 3 distinct` test calls all thirty of those a
    fan-in. Measured on uniformly random flows with no structure at all,
    that test grouped 100% of them and left nothing isolated -- it reported
    the pigeonhole principle as a detection.

    So the bar comes from the window itself: median plus z scaled MADs.
    Median and MAD rather than mean and standard deviation because one real
    scan of 100,000 flows would drag a mean up far enough to hide
    everything else behind it.

    The reference is only those keys that already clear `hard_floor`. A
    scan does not just add one big key, it adds a destination per host it
    touched, each with a single source -- 250 of them in the test that
    caught this. Counting those in dragged the median to 1, which dropped
    the bar to the hard floor and let every piece of background noise
    through as a fan-in. The population to compare against is keys that
    could plausibly be a pattern, not every key that exists.

    With too few such keys to say anything about spread, the hard floor
    stands alone rather than a bar inferred from three numbers.
    """
    plausible = [c for c in counts if c >= hard_floor]
    if len(plausible) < 5:
        return float(hard_floor)
    values = np.asarray(plausible, dtype=float)
    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    # 1.4826 puts MAD on a standard-deviation scale for normal data, so `z`
    # means what a reader expects it to mean.
    return max(float(hard_floor), median + z * 1.4826 * mad)


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
                gap_seconds: int, outlier_z: float) -> list[Incident]:
    """Every grouping that clears the window's own bar, before deciding
    which to keep."""
    by_src: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    by_dst: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    by_tuple: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        by_src[flow.get("src_ip")].append(flow)
        by_dst[flow.get("dst_ip")].append(flow)
        by_tuple[(flow.get("src_ip"), flow.get("dst_ip"), flow.get("dst_port"))].append(flow)

    # Sessions first, then the bar, so a host active in two bursts is judged
    # on each burst rather than on the day's total.
    out_sessions = [(src, sess) for src, g in by_src.items()
                    for sess in _sessionise(g, gap_seconds)]
    in_sessions = [(dst, sess) for dst, g in by_dst.items()
                   for sess in _sessionise(g, gap_seconds)]

    def reach_out(session: Sequence[dict[str, Any]]) -> int:
        return max(len({f.get("dst_ip") for f in session}),
                   len({f.get("dst_port") for f in session}))

    out_floor = _outlier_floor([reach_out(s) for _, s in out_sessions], outlier_z, min_distinct)
    in_floor = _outlier_floor([len({f.get("src_ip") for f in s}) for _, s in in_sessions],
                              outlier_z, min_distinct)

    found: list[Incident] = []
    for src, session in out_sessions:
        if reach_out(session) >= out_floor:
            found.append(_build(PATTERN_FAN_OUT, str(src), session))
    for dst, session in in_sessions:
        if len({f.get("src_ip") for f in session}) >= in_floor:
            found.append(_build(PATTERN_FAN_IN, str(dst), session))
    for key, group in by_tuple.items():
        for session in _sessionise(group, gap_seconds):
            if len(session) >= min_repeats:
                src, dst, port = key
                found.append(_build(PATTERN_REPEATED, f"{src} -> {dst}:{port}", session))
    return found, out_floor, in_floor


def group_incidents(
    flows: Iterable[dict[str, Any]],
    min_distinct: int = DEFAULT_MIN_DISTINCT,
    min_repeats: int = DEFAULT_MIN_REPEATS,
    gap_seconds: int = DEFAULT_GAP_SECONDS,
    outlier_z: float = DEFAULT_OUTLIER_Z,
) -> list[Incident]:
    """Anomalous flows in, incidents out, every flow in exactly one.

    A flow can fit several shapes at once -- a host in a botnet is both a
    source reaching a destination and one of many sources reaching it -- so
    the groupings compete and the largest wins, ties broken by the strongest
    flow in the group and then by key so the output does not depend on dict
    ordering. Claiming greedily by size is what turns a thousand-flow burst
    into one incident instead of a thousand sources with two flows each.

    The cost of largest-wins is that a host doing two things at once is
    reported as the larger one. Measured on the dataset, `fan_out` groups
    absorbed every `ddos` flow in the sample, because the same hosts that
    generate that traffic also reach many destinations. An operator reading
    an incident is reading the dominant shape, not an inventory.
    """
    flows = [f for f in flows if f.get("flow_id")]
    if not flows:
        return []

    candidates, out_floor, in_floor = _candidates(
        flows, min_distinct, min_repeats, gap_seconds, outlier_z)
    candidates.sort(key=lambda i: (-i.n_flows, -i.max_error_ratio, i.pattern, i.key))

    claimed: set[str] = set()
    incidents: list[Incident] = []
    by_id = {f["flow_id"]: f for f in flows}
    for candidate in candidates:
        remaining = [fid for fid in candidate.flow_ids if fid not in claimed]
        # A group that has lost most of its members to a stronger group is no
        # longer the shape it was detected as; re-check rather than emit a
        # fan-out group that is now two flows.
        if len(remaining) < 2:
            continue
        rebuilt = _build(candidate.pattern, candidate.key, [by_id[fid] for fid in remaining])
        # Re-checked against the same bar, not the bare floor: a group that
        # lost most of its members to a stronger one is no longer the
        # outlier it was measured as.
        if candidate.pattern == PATTERN_FAN_OUT and max(
                rebuilt.distinct_dst_ips, rebuilt.distinct_dst_ports) < out_floor:
            continue
        if candidate.pattern == PATTERN_FAN_IN and rebuilt.distinct_src_ips < in_floor:
            continue
        if candidate.pattern == PATTERN_REPEATED and rebuilt.n_flows < min_repeats:
            continue
        claimed.update(remaining)
        incidents.append(rebuilt)

    for flow in flows:
        if flow["flow_id"] not in claimed:
            incidents.append(_build(PATTERN_ISOLATED, str(flow.get("src_ip")), [flow]))

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
