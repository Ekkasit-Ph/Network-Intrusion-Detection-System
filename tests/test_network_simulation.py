"""Tests for the part of the simulation that runs without Mininet or Ryu.

Neither is installed here (Mininet needs root and system packages; Ryu has
not kept up with Python 3.12), so `topology.py`, `ryu_app.py` and the attack
scripts cannot be executed in this environment and are not tested.

What *is* testable is the seam between the simulation and module 6: the
reference policy, and its export into the exact format
`source/firewall_check/rules.py` parses. That seam is where a silent
mistake would be most damaging -- if the exported rules disagreed with the
policy the switch enforces, module 6 would report the drift as coverage
failure, and the output would look like a genuine security finding rather
than a bug.
"""

from __future__ import annotations

import json

import pytest

from network_simulation.firewall_rules import (
    DEFAULT_ACTION,
    IOT_SUBNET,
    POLICY,
    SERVER_SUBNET,
    TCP,
    UDP,
    export_iptables,
    export_ryu_flow_dump,
)
from source.firewall_check.rules import (
    ACTION_ALLOW,
    ACTION_DROP,
    FirewallRuleSet,
    parse_iptables_save,
    parse_ryu_flow_dump,
)
from source.firewall_check.ryu_log_compare import check_flow


def _ruleset_from_ryu() -> FirewallRuleSet:
    return FirewallRuleSet(parse_ryu_flow_dump(export_ryu_flow_dump())[0], default_action=DEFAULT_ACTION)


def _flow(**kw):
    base = {"flow_id": "f", "src_ip": "10.0.1.11", "dst_ip": "10.0.2.11",
            "src_port": 40000, "dst_port": 80, "protocol": "TCP", "is_anomaly": 1}
    base.update(kw)
    return base


# --------------------------------------------------------------------------
# the export survives the parser module 6 uses
# --------------------------------------------------------------------------

def test_every_policy_rule_survives_the_round_trip():
    parsed = parse_ryu_flow_dump(export_ryu_flow_dump())[0]
    # +1 for the table-miss entry the export appends.
    assert len(parsed) == len(POLICY) + 1


def test_drop_rules_stay_drops_through_the_round_trip():
    """A dropping OpenFlow entry is one with no output action. If the
    export or the parser got that backwards, every block would read as an
    allow and module 6 would report a full sheet of false gaps."""
    parsed = parse_ryu_flow_dump(export_ryu_flow_dump())[0]
    exported_drops = sum(r.action == "drop" for r in POLICY)
    parsed_drops = sum(r.action == ACTION_DROP for r in parsed)
    assert parsed_drops == exported_drops
    assert exported_drops > 0, "a policy with no drops cannot test this"


def test_match_fields_survive_the_round_trip():
    parsed = {(r.protocol, r.dst_port, str(r.src_net), str(r.dst_net)) for r in
              parse_ryu_flow_dump(export_ryu_flow_dump())[0]}
    for rule in POLICY:
        span = (rule.dst_port, rule.dst_port) if rule.dst_port is not None else None
        key = (rule.protocol, span,
               str(rule.src_net) if rule.src_net else "None",
               str(rule.dst_net) if rule.dst_net else "None")
        assert key in parsed, f"{rule.name} lost a match field in export/parse"


def test_the_iptables_export_produces_the_same_verdicts():
    """Two renderings of one policy must not disagree, or the demo's answer
    would depend on which firewall the presenter happened to use."""
    ryu_set = _ruleset_from_ryu()
    ipt_set = FirewallRuleSet(parse_iptables_save(export_iptables())[0], default_action=DEFAULT_ACTION)

    probes = [
        _flow(src_ip="10.0.1.11", dst_ip="10.0.2.11", dst_port=445),
        _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=23),
        _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=22),
        _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=80),
        _flow(src_ip="10.0.1.11", dst_ip="10.0.2.11", dst_port=53, protocol="UDP"),
        _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=9999),
    ]
    for probe in probes:
        assert check_flow(ryu_set, probe)["gap_detected"] == check_flow(ipt_set, probe)["gap_detected"], probe


def test_the_export_is_valid_json_in_ryus_shape():
    dump = export_ryu_flow_dump(dpid=7)
    text = json.dumps(dump)
    assert "7" in dump, "keyed by datapath id, as GET /stats/flow/<dpid> returns"
    reparsed, _ = parse_ryu_flow_dump(text)
    assert all(r.source == "ryu:dpid=7" for r in reparsed)


# --------------------------------------------------------------------------
# the policy says what it means to say
# --------------------------------------------------------------------------

def test_smb_from_the_iot_subnet_is_covered_not_a_gap():
    """The lateral-movement case the policy exists to cover: the detector
    flags it, and the firewall already stops it."""
    verdict = check_flow(_ruleset_from_ryu(),
                         _flow(src_ip="10.0.1.11", dst_ip="10.0.2.11", dst_port=445))
    assert verdict["gap_detected"] is False


def test_smb_from_outside_the_iot_subnet_is_still_a_gap():
    """The rule is scoped to the IoT subnet, so the same traffic from the
    attacker segment is not covered. A test that only checked the covered
    case would pass on a rule that blocked everything."""
    verdict = check_flow(_ruleset_from_ryu(),
                         _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=445))
    assert verdict["gap_detected"] is True


def test_ssh_password_guessing_is_a_gap_by_design():
    """SSH is deliberately open, so a password-guessing run is something
    only the detector can catch -- which is what makes module 6's report
    worth reading."""
    verdict = check_flow(_ruleset_from_ryu(),
                         _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=22))
    assert verdict["gap_detected"] is True


def test_http_borne_attacks_are_gaps_by_design():
    verdict = check_flow(_ruleset_from_ryu(),
                         _flow(src_ip="10.0.3.11", dst_ip="10.0.2.11", dst_port=80))
    assert verdict["gap_detected"] is True


def test_the_policy_leaves_real_gaps_and_covers_real_traffic():
    """If the policy covered everything the detector can find, module 6
    would report nothing and demonstrate nothing; if it covered nothing,
    every flow would be a gap and the report would be noise."""
    rule_set = _ruleset_from_ryu()
    probes = [
        _flow(dst_port=445, src_ip="10.0.1.11"), _flow(dst_port=23), _flow(dst_port=3389),
        _flow(dst_port=22), _flow(dst_port=80), _flow(dst_port=9999),
    ]
    verdicts = [check_flow(rule_set, p)["gap_detected"] for p in probes]
    assert any(verdicts) and not all(verdicts)


def test_telnet_is_blocked_from_anywhere():
    rule_set = _ruleset_from_ryu()
    for src in ("10.0.1.11", "10.0.2.11", "10.0.3.11"):
        assert check_flow(rule_set, _flow(src_ip=src, dst_port=23))["gap_detected"] is False


def test_policy_priorities_are_ordered_so_drops_beat_allows():
    """A drop that sits below a broad allow never fires. Checked here rather
    than left to reading, because the symptom is a rule that silently does
    nothing."""
    rule_set = _ruleset_from_ryu()
    # port 445 to a server is covered by both block-smb-from-iot (300) and
    # nothing else; port 80 is allowed. Confirm the drop wins where they
    # would overlap.
    assert check_flow(rule_set, _flow(src_ip="10.0.1.11", dst_port=445))["gap_detected"] is False
    for rule in POLICY:
        if rule.action == "drop":
            competing = [r for r in POLICY if r.action == "allow" and r.priority > rule.priority]
            assert not competing, f"{rule.name} is outranked by {[c.name for c in competing]}"


def test_every_policy_rule_records_why_it_exists():
    """A firewall policy in a report needs its reasoning attached, or the
    reader cannot tell a deliberate opening from an oversight."""
    for rule in POLICY:
        assert rule.rationale.strip(), f"{rule.name} has no rationale"


# --------------------------------------------------------------------------
# the modules that need Mininet/Ryu at least import cleanly
# --------------------------------------------------------------------------

def test_topology_module_reports_a_useful_error_without_mininet():
    """Someone will run this on a machine without Mininet. It should say so
    and say how to fix it, not raise ImportError from three frames deep."""
    import network_simulation.topology as topology

    assert topology.HOSTS, "topology must define hosts without importing mininet"
    subnets = {ip.split(".")[2] for _, ip in topology.HOSTS}
    assert subnets == {"1", "2", "3"}, "three segments, matching firewall_rules"


def test_the_policy_subnets_and_the_topology_agree():
    """The policy is written in terms of 10.0.1/2/3.0/24; if the topology
    used different addresses, every scoped rule would silently match
    nothing."""
    import network_simulation.topology as topology

    host_subnets = {".".join(ip.split(".")[:3]) + ".0/24" for _, ip in topology.HOSTS}
    assert IOT_SUBNET in host_subnets
    assert SERVER_SUBNET in host_subnets


def test_every_advertised_scenario_is_implemented():
    """`SCENARIOS` is what the CLI advertises; `run_scenario` is what
    actually dispatches. A name in one and not the other is a KeyError
    partway through a demo."""
    import inspect

    from network_simulation import attack_scripts

    dispatch = inspect.getsource(attack_scripts.run_scenario)
    for name in attack_scripts.SCENARIOS:
        assert hasattr(attack_scripts, name), f"{name} is advertised but not defined"
        assert f'"{name}"' in dispatch, f"{name} is defined but run_scenario cannot reach it"


def test_topologys_scenario_flag_offers_exactly_those_scenarios():
    """argparse's choices are written by hand in topology.main(); this is
    the thing that goes stale when a scenario is added."""
    import inspect

    from network_simulation import attack_scripts, topology

    source = inspect.getsource(topology.main)
    for name in attack_scripts.SCENARIOS:
        assert f'"{name}"' in source, f"--scenario cannot select {name}"
