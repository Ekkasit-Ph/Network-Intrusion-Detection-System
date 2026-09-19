"""Module 6: does the firewall already cover what the detector flagged?

    python -m source.firewall_check.ryu_log_compare --rules flows.json
    python -m source.firewall_check.ryu_log_compare --rules iptables.rules --format iptables

For each anomalous flow in the DB, this asks the rule set what would have
happened to that flow, and records the answer in `firewall_checks`. A
**gap** is a flow the detector called anomalous that the firewall would
have let through: the detector saw something the perimeter did not.

**This never changes a firewall rule.** PROJECT.md forbids auto-blocking,
for a concrete reason rather than a stylistic one: the detector's own
measured false-positive rate is about 5%, so wiring it to a blocking action
would drop roughly one in twenty legitimate flows -- a self-inflicted
denial of service, caused by the tool meant to prevent one. This module
reads rules and writes rows. Nothing here opens a socket to a controller.

Two things to get right, both of which change every verdict:

**Default action.** A flow no rule matches is allowed or denied depending
on whether the switch has a table-miss drop entry. `--default-action` makes
that explicit; assuming it silently would invert the gap count on a
default-deny network.

**Direction.** The rules are evaluated against the flow as the exporter
recorded it (src -> dst). A stateful firewall permitting the reply of an
allowed connection is not modelled -- this is post-hoc coverage reporting
on flow records, not a packet-path simulation, and saying so is better than
implying a fidelity it doesn't have.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

from source.firewall_check.rules import (
    ACTION_ALLOW,
    ACTION_DROP,
    FirewallRuleSet,
    load_rules,
)
from web.backend import database

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17, "ICMP": 1, "IGMP": 2, "ICMPv6": 58}


def _protocol_number(value: Any) -> int | None:
    """`flows.protocol` holds a display name ("TCP"), because that column
    exists for the dashboard. Rules match on the number."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.upper() in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NUMBERS[text.upper()]
    if text.lower().startswith("proto-"):
        text = text.split("-", 1)[1]
    try:
        return int(float(text))
    except ValueError:
        return None


def check_flow(rule_set: FirewallRuleSet, flow: dict[str, Any]) -> dict[str, Any]:
    """What the firewall would do with `flow`, and whether that leaves a gap."""
    protocol = _protocol_number(flow.get("protocol"))
    src_ip, dst_ip = flow.get("src_ip"), flow.get("dst_ip")

    if protocol is None or not src_ip or not dst_ip:
        # Rather than guessing, record that coverage is unknown: NULL in
        # all three columns, which the schema allows precisely for this.
        # Counting an unknown as "covered" would hide a real gap; counting
        # it as a gap would invent one.
        return {
            "firewall_rule_matched": None,
            "firewall_action_logged": "unknown: flow record lacks addresses or protocol",
            "gap_detected": None,
        }

    action, rule = rule_set.action_for(
        src_ip, dst_ip, protocol,
        int(flow.get("src_port") or 0), int(flow.get("dst_port") or 0),
    )
    return {
        "firewall_rule_matched": rule is not None,
        "firewall_action_logged": rule.describe() if rule else f"no rule matched (default {action})",
        "gap_detected": action == ACTION_ALLOW,
    }


def run(
    rules_path: Path,
    db_path: Path,
    fmt: str = "auto",
    default_action: str = ACTION_ALLOW,
    limit: int = 1000,
    anomalies_only: bool = True,
) -> dict[str, int]:
    rules, skipped = load_rules(str(rules_path), fmt=fmt)
    rule_set = FirewallRuleSet(rules, default_action=default_action)
    log.info("Loaded %d rule(s) from %s (default action for unmatched traffic: %s)",
             len(rule_set), rules_path, default_action)
    if not rules:
        log.warning("No rules parsed -- every flow will be reported as a gap. "
                    "Check --format and the file's contents before believing the output.")
    if skipped:
        # Loud on purpose. A skipped rule can only cause gaps to be
        # over-reported, never under-reported (see UnrepresentableRule),
        # but the reader still has to know the picture is incomplete --
        # otherwise a gap list padded by unparsed rules reads as a finding.
        log.warning("%d rule(s) could not be evaluated and were EXCLUDED. Flows they cover "
                    "will be reported as gaps even though the firewall may handle them:",
                    len(skipped))
        for reason in skipped[:20]:
            log.warning("    %s", reason)
        if len(skipped) > 20:
            log.warning("    ... and %d more", len(skipped) - 20)

    summary = {"checked": 0, "gaps": 0, "covered": 0, "unknown": 0,
               "rules_loaded": len(rule_set), "rules_skipped": len(skipped)}
    with database.get_connection(db_path) as conn:
        flows = database.get_recent_flows(conn, limit=limit)
        for flow in flows:
            if anomalies_only and not flow.get("is_anomaly"):
                continue
            verdict = check_flow(rule_set, flow)
            database.insert_firewall_check(
                conn,
                flow_id=flow["flow_id"],
                firewall_rule_matched=verdict["firewall_rule_matched"],
                firewall_action_logged=verdict["firewall_action_logged"],
                gap_detected=verdict["gap_detected"],
            )
            summary["checked"] += 1
            if verdict["gap_detected"] is None:
                summary["unknown"] += 1
            elif verdict["gap_detected"]:
                summary["gaps"] += 1
                log.info("GAP  %s  %s:%s -> %s:%s %s  (%s)",
                         flow["flow_id"], flow["src_ip"], flow["src_port"],
                         flow["dst_ip"], flow["dst_port"], flow["protocol"],
                         verdict["firewall_action_logged"])
            else:
                summary["covered"] += 1

    log.info("Checked %d anomalous flow(s): %d gap(s), %d already covered, %d undetermined.",
             summary["checked"], summary["gaps"], summary["covered"], summary["unknown"])
    log.info("No firewall rule was changed. See GET /firewall-gaps on the dashboard.")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules", type=Path, required=True,
                        help="Ryu flow dump (GET /stats/flow/<dpid>) or iptables-save output")
    parser.add_argument("--format", choices=["auto", "ryu", "iptables"], default="auto")
    parser.add_argument("--db-path", type=Path, default=database.DEFAULT_DB_PATH)
    parser.add_argument("--default-action", choices=[ACTION_ALLOW, ACTION_DROP], default=ACTION_ALLOW,
                        help="What happens to traffic no rule matches. 'drop' if the switch has a "
                             "table-miss drop entry; getting this wrong inverts every verdict")
    parser.add_argument("--limit", type=int, default=1000, help="How many recent flows to consider")
    parser.add_argument("--all-flows", action="store_true",
                        help="Also check flows the detector did NOT flag (normally only anomalies "
                             "are checked, since a gap is defined relative to a detection)")
    args = parser.parse_args()

    run(args.rules, args.db_path, fmt=args.format, default_action=args.default_action,
        limit=args.limit, anomalies_only=not args.all_flows)


if __name__ == "__main__":
    main()
