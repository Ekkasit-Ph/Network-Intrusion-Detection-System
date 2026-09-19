"""Tests for module 6 (firewall coverage verification).

Two things here are worth more care than the parsing:

1. **Which way a verdict points.** "gap" means the detector flagged
   something the firewall would have allowed. An inverted verdict reads
   perfectly well in the dashboard and says the opposite of the truth.
2. **Not knowing.** A flow whose record lacks an address or protocol has
   *undetermined* coverage. Recording that as "covered" hides a real gap;
   recording it as a gap invents one. Both are worse than a NULL.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from source.firewall_check.rules import (
    ACTION_ALLOW,
    ACTION_DROP,
    FirewallRule,
    FirewallRuleSet,
    load_rules,
    parse_iptables_save,
    parse_ryu_flow_dump,
)
from source.firewall_check.ryu_log_compare import check_flow, run
from web.backend import database
from web.database.initialize_database import initialize_database

TCP, UDP, ICMP = 6, 17, 1


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------

def test_an_absent_field_is_a_wildcard():
    rule = FirewallRule(action=ACTION_DROP)
    assert rule.matches("1.2.3.4", "5.6.7.8", TCP, 1234, 80)
    assert rule.matches("9.9.9.9", "8.8.8.8", UDP, 53, 53)


def test_fields_that_are_set_must_all_agree():
    rule = FirewallRule(action=ACTION_DROP, protocol=TCP, dst_port=445)
    assert rule.matches("10.0.0.1", "10.0.0.2", TCP, 5000, 445)
    assert not rule.matches("10.0.0.1", "10.0.0.2", UDP, 5000, 445)   # wrong protocol
    assert not rule.matches("10.0.0.1", "10.0.0.2", TCP, 5000, 80)    # wrong port


def test_addresses_match_by_prefix():
    rules, _ = parse_iptables_save("-A INPUT -s 10.0.0.0/24 -j DROP")
    rule = rules[0]
    assert rule.matches("10.0.0.7", "1.1.1.1", TCP, 1, 2)
    assert not rule.matches("10.0.1.7", "1.1.1.1", TCP, 1, 2)


def test_highest_priority_rule_wins():
    rule_set = FirewallRuleSet([
        FirewallRule(action=ACTION_ALLOW, priority=1),
        FirewallRule(action=ACTION_DROP, priority=100, dst_port=445),
    ])
    action, rule = rule_set.action_for("10.0.0.1", "10.0.0.2", TCP, 5000, 445)
    assert action == ACTION_DROP
    assert rule.priority == 100

    action, _ = rule_set.action_for("10.0.0.1", "10.0.0.2", TCP, 5000, 80)
    assert action == ACTION_ALLOW


def test_unmatched_traffic_takes_the_default_action():
    rules = [FirewallRule(action=ACTION_DROP, dst_port=445, priority=10)]
    assert FirewallRuleSet(rules, default_action=ACTION_ALLOW).action_for(
        "1.1.1.1", "2.2.2.2", TCP, 1, 80)[0] == ACTION_ALLOW
    assert FirewallRuleSet(rules, default_action=ACTION_DROP).action_for(
        "1.1.1.1", "2.2.2.2", TCP, 1, 80)[0] == ACTION_DROP


def test_a_malformed_address_is_not_counted_as_covered():
    """Failing to parse an address must not be read as "the rule applies"
    -- that would report protection that does not exist."""
    rule = FirewallRule(action=ACTION_DROP, src_net=None, dst_net=None)
    assert rule.matches("not-an-ip", "10.0.0.1", TCP, 1, 2)  # no constraint, still matches
    constrained = parse_iptables_save("-A INPUT -d 10.0.0.0/8 -j DROP")[0][0]
    assert not constrained.matches("1.1.1.1", "not-an-ip", TCP, 1, 2)


# --------------------------------------------------------------------------
# parsing Ryu
# --------------------------------------------------------------------------

RYU_DUMP = json.dumps({
    "1": [
        {"priority": 100, "match": {"ipv4_dst": "10.0.0.5", "ip_proto": 6, "tcp_dst": 445},
         "actions": []},
        {"priority": 50, "match": {"ipv4_src": "10.0.0.0/24"},
         "actions": [{"type": "OUTPUT", "port": 2}]},
        {"priority": 0, "match": {}, "actions": [{"type": "OUTPUT", "port": "CONTROLLER"}]},
    ]
})


def test_ryu_entry_without_an_output_action_is_a_drop():
    """OpenFlow has no DROP action -- an empty action list is the drop, and
    reading it as "allow" would turn every block into a gap."""
    rules = parse_ryu_flow_dump(RYU_DUMP)[0]
    blocking = [r for r in rules if r.action == ACTION_DROP]
    assert len(blocking) == 1
    assert blocking[0].dst_port == (445, 445)
    assert blocking[0].priority == 100


def test_ryu_output_action_is_an_allow():
    rules = parse_ryu_flow_dump(RYU_DUMP)[0]
    assert sum(r.action == ACTION_ALLOW for r in rules) == 2


def test_ryu_instructions_form_is_understood():
    """OpenFlow 1.3 nests actions inside instructions; missing that would
    silently read every rule as a drop."""
    payload = {"1": [{"priority": 10, "match": {},
                      "instructions": [{"type": "APPLY_ACTIONS",
                                        "actions": [{"type": "OUTPUT", "port": 1}]}]}]}
    assert parse_ryu_flow_dump(payload)[0][0].action == ACTION_ALLOW


def test_legacy_openflow_field_names_are_accepted():
    """nw_src/tp_dst are the pre-1.2 spellings. Treating them as absent
    would wildcard a field that was set, making the rule look broader than
    it is -- and so under-report gaps."""
    payload = {"1": [{"priority": 5, "match": {"nw_src": "192.168.1.0/24", "nw_proto": 6,
                                               "tp_dst": 22}, "actions": []}]}
    rule = parse_ryu_flow_dump(payload)[0][0]
    assert rule.src_net is not None and rule.protocol == TCP and rule.dst_port == (22, 22)


# --------------------------------------------------------------------------
# parsing iptables
# --------------------------------------------------------------------------

IPTABLES = """
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport 445 -j DROP
-A INPUT -s 10.0.0.0/8 -j LOG --log-prefix "seen "
-A FORWARD -p udp --dport 53 -j ACCEPT
-A OUTPUT -j DROP
COMMIT
"""


def test_iptables_targets_are_mapped_and_non_verdict_targets_skipped():
    rules = parse_iptables_save(IPTABLES)[0]
    assert [r.action for r in rules] == [ACTION_ALLOW, ACTION_DROP, ACTION_ALLOW]
    # LOG decides nothing, and OUTPUT is not a chain we evaluate.
    assert all(r.dst_port != 999 for r in rules)


def test_iptables_file_order_is_preserved_as_priority():
    """iptables is first-match-wins; encoding order as descending priority
    is what lets one matcher serve both formats."""
    rules, _ = parse_iptables_save("-A INPUT -p tcp --dport 80 -j ACCEPT\n"
                                   "-A INPUT -p tcp --dport 80 -j DROP\n")
    rule_set = FirewallRuleSet(rules)
    action, _ = rule_set.action_for("1.1.1.1", "2.2.2.2", TCP, 5000, 80)
    assert action == ACTION_ALLOW, "the earlier rule must win, as iptables would"


def test_load_rules_detects_the_format(tmp_path):
    ryu = tmp_path / "flows.json"
    ryu.write_text(RYU_DUMP)
    assert len(load_rules(str(ryu))[0]) == 3

    ipt = tmp_path / "rules.txt"
    ipt.write_text(IPTABLES)
    assert len(load_rules(str(ipt))[0]) == 3


# --------------------------------------------------------------------------
# the verdict
# --------------------------------------------------------------------------

def _flow(**kw):
    base = {"flow_id": "f1", "src_ip": "192.168.1.50", "dst_ip": "10.0.0.5",
            "src_port": 40000, "dst_port": 445, "protocol": "TCP", "is_anomaly": 1}
    base.update(kw)
    return base


def test_a_flow_the_firewall_would_allow_is_a_gap():
    rule_set = FirewallRuleSet([], default_action=ACTION_ALLOW)
    verdict = check_flow(rule_set, _flow())
    assert verdict["gap_detected"] is True
    assert verdict["firewall_rule_matched"] is False


def test_a_flow_the_firewall_would_drop_is_not_a_gap():
    rule_set = FirewallRuleSet(parse_ryu_flow_dump(RYU_DUMP)[0])
    verdict = check_flow(rule_set, _flow())
    assert verdict["gap_detected"] is False
    assert verdict["firewall_rule_matched"] is True
    assert "drop" in verdict["firewall_action_logged"]


def test_protocol_names_from_the_flows_table_are_resolved():
    """`flows.protocol` stores a display name for the dashboard; rules match
    on the number. A failed conversion would make every rule with a protocol
    constraint miss."""
    rule_set = FirewallRuleSet(parse_ryu_flow_dump(RYU_DUMP)[0])
    assert check_flow(rule_set, _flow(protocol="TCP"))["gap_detected"] is False
    assert check_flow(rule_set, _flow(protocol=6))["gap_detected"] is False
    assert check_flow(rule_set, _flow(protocol="proto-6"))["gap_detected"] is False


def test_an_incomplete_flow_record_is_undetermined_not_covered():
    rule_set = FirewallRuleSet(parse_ryu_flow_dump(RYU_DUMP)[0])
    for missing in ({"src_ip": None}, {"dst_ip": None}, {"protocol": "N/A"}):
        verdict = check_flow(rule_set, _flow(**missing))
        assert verdict["gap_detected"] is None, missing
        assert verdict["firewall_rule_matched"] is None, missing
        assert "unknown" in verdict["firewall_action_logged"]


def test_default_deny_flips_the_verdict():
    """Whether unmatched traffic is a gap depends entirely on the switch's
    table-miss behaviour, which is why it is a required decision and not a
    silent default."""
    flow = _flow(dst_port=9999)  # nothing in RYU_DUMP matches this
    rules = parse_ryu_flow_dump(RYU_DUMP)[0]
    # The dump's catch-all sends to CONTROLLER, which is an OUTPUT: allow.
    permissive = [r for r in rules if r.priority > 0]
    assert check_flow(FirewallRuleSet(permissive, ACTION_ALLOW), flow)["gap_detected"] is True
    assert check_flow(FirewallRuleSet(permissive, ACTION_DROP), flow)["gap_detected"] is False


# --------------------------------------------------------------------------
# end to end, against the real database
# --------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    path = tmp_path / "nids.db"
    initialize_database(path)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with database.get_connection(path) as conn:
        for i, (dst_port, anomalous) in enumerate([(445, True), (80, True), (443, False)]):
            database.insert_flow(
                conn, flow_id=f"f{i}", timestamp=(now + timedelta(seconds=i)).isoformat(),
                src_ip="192.168.1.50", dst_ip="10.0.0.5", src_port=40000 + i,
                dst_port=dst_port, protocol="TCP", reconstruction_error=0.9,
                threshold_used=0.5, is_anomaly=anomalous, features={},
            )
    return path


def test_run_records_one_row_per_anomalous_flow(tmp_path, db):
    rules = tmp_path / "flows.json"
    rules.write_text(RYU_DUMP)

    summary = run(rules, db, default_action=ACTION_ALLOW)

    # Only the two anomalies are checked; port 445 is blocked, port 80 is not.
    assert summary["checked"] == 2
    assert summary["gaps"] == 1
    assert summary["covered"] == 1

    with database.get_connection(db) as conn:
        gaps = database.get_firewall_gaps(conn)
    assert [g["flow_id"] for g in gaps] == ["f1"]


def test_run_never_touches_the_flows_table(tmp_path, db):
    """Module 6 is read-only with respect to detections, and must not be
    able to become a blocking control by accident."""
    rules = tmp_path / "flows.json"
    rules.write_text(RYU_DUMP)

    with database.get_connection(db) as conn:
        before = [dict(r) for r in conn.execute("SELECT * FROM flows ORDER BY flow_id")]
    run(rules, db)
    with database.get_connection(db) as conn:
        after = [dict(r) for r in conn.execute("SELECT * FROM flows ORDER BY flow_id")]
    assert before == after


def test_an_empty_rule_file_reports_everything_as_a_gap_and_says_so(tmp_path, db, caplog):
    """An unparsed rule file produces a full sheet of gaps, which looks like
    a dramatic finding rather than a mistake -- so it has to be called out."""
    rules = tmp_path / "flows.json"
    rules.write_text("{}")

    with caplog.at_level("WARNING"):
        summary = run(rules, db)
    assert summary["gaps"] == 2
    assert any("No rules parsed" in r.message for r in caplog.records)


# --------------------------------------------------------------------------
# fail closed: a condition we cannot express must never widen a rule
#
# This is the one direction of error that is genuinely dangerous here. A
# rule stripped of a condition it actually carries matches MORE traffic
# than the real one, so module 6 reports flows as *covered* that the
# firewall in fact permits -- hiding a real gap, silently, in output that
# reads like reassurance. Dropping the rule instead can only over-report
# gaps, and an over-reported gap gets investigated.
# --------------------------------------------------------------------------

def test_multiport_expands_instead_of_becoming_any_port():
    """`-m multiport --dports 80,443` read as "any TCP port" would turn a
    two-port block into a block on everything -- and everything TCP would
    then read as covered."""
    rules, skipped = parse_iptables_save("-A INPUT -p tcp -m multiport --dports 80,443 -j DROP")
    assert not skipped
    assert {r.dst_port for r in rules} == {(80, 80), (443, 443)}
    assert all(r.dst_port is not None for r in rules), "a portless rule would match all TCP"


def test_port_ranges_are_kept_as_ranges():
    rules, skipped = parse_iptables_save("-A INPUT -p tcp --dport 8000:8100 -j DROP")
    assert not skipped
    rule = rules[0]
    assert rule.matches("1.1.1.1", "2.2.2.2", TCP, 1, 8050)
    assert not rule.matches("1.1.1.1", "2.2.2.2", TCP, 1, 8101)


def test_open_ended_port_ranges():
    lo, = parse_iptables_save("-A INPUT -p tcp --dport 1024: -j DROP")[0]
    assert lo.matches("1.1.1.1", "2.2.2.2", TCP, 1, 65535)
    assert not lo.matches("1.1.1.1", "2.2.2.2", TCP, 1, 1023)
    hi, = parse_iptables_save("-A INPUT -p tcp --dport :1023 -j DROP")[0]
    assert hi.matches("1.1.1.1", "2.2.2.2", TCP, 1, 80)
    assert not hi.matches("1.1.1.1", "2.2.2.2", TCP, 1, 1024)


@pytest.mark.parametrize("line,why", [
    ("-A INPUT -p tcp ! --dport 22 -j DROP", "negation inverts, not widens"),
    ("-A INPUT -s 2001:db8::/32 -j DROP", "IPv6 address"),
    ("-A INPUT -s example.com -j DROP", "hostname, not an address"),
    ("-A INPUT -m state --state ESTABLISHED -j ACCEPT", "connection state a flow record lacks"),
    ("-A INPUT -i eth0 -p tcp --dport 80 -j DROP", "interface a flow record lacks"),
    ("-A INPUT -m conntrack --ctstate NEW -j DROP", "conntrack module"),
])
def test_unrepresentable_iptables_rules_are_skipped_with_a_reason(line, why):
    rules, skipped = parse_iptables_save(line)
    assert rules == [], f"{why}: rule was kept, and is now broader than reality"
    assert len(skipped) == 1 and skipped[0], "a skip must carry an explanation"


@pytest.mark.parametrize("match", [
    {"ipv6_src": "2001:db8::/32"},
    {"in_port": 3},
    {"vlan_vid": 100},
    {"ipv4_src": "10.0.0.999/24"},
])
def test_unrepresentable_ryu_matches_are_skipped(match):
    rules, skipped = parse_ryu_flow_dump({"1": [{"priority": 1, "match": match, "actions": []}]})
    assert rules == []
    assert len(skipped) == 1


def test_eth_type_is_ignorable_not_unrepresentable():
    """Every IPv4 rule carries eth_type=0x0800; treating it as unknown
    would skip the entire policy."""
    rules, skipped = parse_ryu_flow_dump(
        {"1": [{"priority": 1, "match": {"eth_type": 2048, "ip_proto": 6, "tcp_dst": 80},
                "actions": []}]})
    assert not skipped and len(rules) == 1


def test_nothing_in_a_realistic_ruleset_raises():
    """Before this, a plain `--dport 80:443` crashed the whole run."""
    realistic = """
    -A INPUT -i lo -j ACCEPT
    -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    -A INPUT -p tcp --dport 22 -j ACCEPT
    -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
    -A INPUT -p tcp --dport 1024:65535 -j DROP
    -A INPUT -s 2001:db8::/32 -j DROP
    -A FORWARD -p udp --dport 53 -j ACCEPT
    -A INPUT -j DROP
    """
    rules, skipped = parse_iptables_save(realistic)
    assert rules, "everything was skipped; the parser understands nothing"
    assert skipped, "fixture should include rules that cannot be represented"


def test_skipped_rules_are_reported_to_the_operator(tmp_path, db, caplog):
    """Skipping is safe but not free: it inflates the gap list, so the
    reader has to be told the picture is incomplete."""
    rules = tmp_path / "rules.txt"
    rules.write_text("-A INPUT -i eth0 -p tcp --dport 445 -j DROP\n"
                     "-A INPUT -p tcp --dport 445 -j DROP\n")

    with caplog.at_level("WARNING"):
        summary = run(rules, db, fmt="iptables")

    assert summary["rules_skipped"] == 1
    assert summary["rules_loaded"] == 1
    assert any("EXCLUDED" in r.message for r in caplog.records)
    assert any("-i eth0" in r.getMessage() for r in caplog.records)
