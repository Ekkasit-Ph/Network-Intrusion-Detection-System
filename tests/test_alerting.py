"""Tests for alert aggregation (source/alerting/aggregate.py).

The pattern names describe shape only -- fan_out, fan_in, repeated,
isolated -- and these tests assert the shapes, never an attack type. The
detector emits a reconstruction error per flow and no class, so there is
no attack type here to assert.

The module's job is a volume claim -- one incident per thing that happened
rather than one per flow -- so the tests are mostly about the shapes it is
supposed to recognise, and about the two ways an aggregator quietly goes
wrong: losing flows, or double-counting them.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from source.alerting.aggregate import (
    PATTERN_FAN_IN,
    PATTERN_REPEATED,
    PATTERN_FAN_OUT,
    PATTERN_ISOLATED,
    group_incidents,
    summarise,
)

BASE = datetime(2026, 9, 20, 12, 0, 0)


def flow(fid, src="10.0.1.5", dst="10.0.2.11", port=80, offset=0, error=0.004):
    return {
        "flow_id": fid,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "src_port": 40000 + offset,
        "protocol": "TCP",
        "timestamp": (BASE + timedelta(seconds=offset)).isoformat(),
        "reconstruction_error": error,
        "threshold_used": 0.002,
    }


def test_port_sweep_becomes_one_incident():
    flows = [flow(f"f{i}", port=20 + i, offset=i) for i in range(40)]
    incidents = group_incidents(flows)
    assert len(incidents) == 1
    assert incidents[0].pattern == PATTERN_FAN_OUT
    assert incidents[0].n_flows == 40
    assert incidents[0].distinct_dst_ports == 40


def test_fan_out_across_hosts_becomes_one_incident():
    flows = [flow(f"f{i}", dst=f"10.0.2.{i}", offset=i) for i in range(25)]
    incidents = group_incidents(flows)
    assert len(incidents) == 1
    assert incidents[0].pattern == PATTERN_FAN_OUT
    assert incidents[0].distinct_dst_ips == 25


def test_many_sources_one_target_becomes_one_incident():
    flows = [flow(f"f{i}", src=f"10.0.3.{i}", offset=i) for i in range(60)]
    incidents = group_incidents(flows)
    assert len(incidents) == 1
    assert incidents[0].pattern == PATTERN_FAN_IN
    assert incidents[0].distinct_src_ips == 60


def test_repeated_attempts_on_one_port_become_one_incident():
    flows = [flow(f"f{i}", offset=i) for i in range(12)]
    incidents = group_incidents(flows)
    assert len(incidents) == 1
    assert incidents[0].pattern == PATTERN_REPEATED


def test_an_isolated_flow_stays_its_own_incident():
    """Not a fallback -- one anomalous flow to one host on one port is
    exactly what an operator should see on its own."""
    incidents = group_incidents([flow("only")])
    assert len(incidents) == 1
    assert incidents[0].pattern == PATTERN_ISOLATED
    assert incidents[0].n_flows == 1


def test_every_flow_lands_in_exactly_one_incident():
    """The two ways an aggregator silently lies: dropping flows, so an
    attack vanishes from the console, and claiming one twice, so the counts
    stop adding up."""
    flows = (
        [flow(f"scan{i}", src="10.0.1.5", dst=f"10.0.2.{i}", offset=i) for i in range(20)]
        + [flow(f"flood{i}", src=f"10.0.4.{i}", dst="10.0.2.99", offset=100 + i) for i in range(30)]
        + [flow("lonely", src="10.0.9.9", dst="10.0.9.1", port=7, offset=300)]
    )
    incidents = group_incidents(flows)

    seen = [fid for incident in incidents for fid in incident.flow_ids]
    assert sorted(seen) == sorted(f["flow_id"] for f in flows)
    assert len(seen) == len(set(seen))
    assert sum(i.n_flows for i in incidents) == len(flows)


def test_the_same_source_twice_in_a_day_is_two_incidents():
    """Sessionisation. Without it, a host scanned at noon and again hours
    later reads as one long incident and the operator cannot see it
    happened twice."""
    morning = [flow(f"a{i}", dst=f"10.0.2.{i}", offset=i) for i in range(10)]
    evening = [flow(f"b{i}", dst=f"10.0.2.{i}", offset=20_000 + i) for i in range(10)]
    incidents = group_incidents(morning + evening)
    assert len(incidents) == 2
    assert all(i.pattern == PATTERN_FAN_OUT for i in incidents)


def test_a_group_stripped_by_a_stronger_one_is_not_emitted_as_its_old_shape():
    """A flood claims its flows first; what is left of each source must not
    still be reported as a scan built from three destinations it no longer
    has."""
    flood = [flow(f"d{i}", src=f"10.0.4.{i}", dst="10.0.2.99", offset=i) for i in range(40)]
    incidents = group_incidents(flood)
    assert [i.pattern for i in incidents] == [PATTERN_FAN_IN]


def test_worst_flow_is_surfaced_for_triage():
    flows = [flow(f"f{i}", port=20 + i, offset=i, error=0.004) for i in range(10)]
    flows[7]["reconstruction_error"] = 0.5
    incidents = group_incidents(flows)
    assert incidents[0].worst_flow_id == "f7"
    assert incidents[0].max_error_ratio == pytest.approx(250.0)


def test_incidents_are_ordered_worst_first():
    quiet = [flow(f"q{i}", src="10.0.1.1", dst=f"10.0.5.{i}", offset=i, error=0.0021)
             for i in range(20)]
    loud = [flow(f"l{i}", src="10.0.1.2", dst=f"10.0.6.{i}", offset=i, error=0.09)
            for i in range(5)]
    incidents = group_incidents(quiet + loud)
    assert incidents[0].max_error_ratio > incidents[1].max_error_ratio


def test_summary_reports_the_reduction():
    flows = [flow(f"f{i}", port=20 + i, offset=i) for i in range(50)]
    incidents = group_incidents(flows)
    summary = summarise(incidents, len(flows))
    assert summary["n_flows"] == 50
    assert summary["n_incidents"] == 1
    assert summary["reduction"] == pytest.approx(0.98)


def test_empty_input_is_not_an_error():
    assert group_incidents([]) == []
    assert summarise([], 0)["reduction"] == 0.0


def test_grouping_does_not_depend_on_input_order():
    flows = (
        [flow(f"s{i}", src="10.0.1.5", dst=f"10.0.2.{i}", offset=i) for i in range(15)]
        + [flow(f"t{i}", src=f"10.0.7.{i}", dst="10.0.2.50", offset=50 + i) for i in range(15)]
    )
    forward = group_incidents(flows)
    backward = group_incidents(list(reversed(flows)))
    assert [(i.pattern, i.key, i.n_flows) for i in forward] == \
           [(i.pattern, i.key, i.n_flows) for i in backward]
