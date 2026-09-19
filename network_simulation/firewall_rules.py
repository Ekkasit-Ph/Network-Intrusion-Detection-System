"""The reference firewall policy, defined once.

Module 6 compares detections against the rules that were actually in force.
That comparison is only meaningful if the rules it reads are the same ones
the switch is enforcing -- if `ryu_app.py` installed one policy and a
hand-written JSON file described another, every "gap" would be an artifact
of the two drifting apart, and it would look exactly like a real finding.

So the policy lives here, in one list, and everything else is derived:

    ryu_app.py                  installs these as OpenFlow entries
    export_ryu_flow_dump()      renders them in the shape Ryu's
                                GET /stats/flow/<dpid> returns, which is
                                what source/firewall_check/rules.py parses
    export_iptables()           the same policy for a plain-Linux host

The export path is testable without Mininet or Ryu installed, which matters
because neither runs in this project's environment (Mininet needs root and
system packages; Ryu has not kept up with Python 3.12). See the README.

The policy itself is deliberately incomplete. A firewall that blocked
everything the detector can find would make module 6 report nothing and
prove nothing; a realistic perimeter covers the obvious services and misses
the rest, which is the situation module 6 exists to surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

TCP, UDP, ICMP = 6, 17, 1

# The simulated network. Keep in step with topology.py.
IOT_SUBNET = "10.0.1.0/24"      # sensors/cameras -- talk to the server, nothing else
SERVER_SUBNET = "10.0.2.0/24"   # the services worth attacking
ATTACKER_SUBNET = "10.0.3.0/24"


@dataclass(frozen=True)
class PolicyRule:
    """One reference rule. `None` means "any", matching OpenFlow's
    wildcard. Higher priority wins."""

    name: str
    action: str            # "drop" | "allow"
    priority: int
    protocol: int | None = None
    src_net: str | None = None
    dst_net: str | None = None
    dst_port: int | None = None
    rationale: str = ""


# Ordered by priority for readability; the exporters do not depend on order.
POLICY: list[PolicyRule] = [
    PolicyRule(
        name="block-smb-from-iot", action="drop", priority=300,
        protocol=TCP, src_net=IOT_SUBNET, dst_port=445,
        rationale="No IoT sensor has a reason to speak SMB. This is the rule "
                  "that makes a lateral-movement scan show up as *covered* "
                  "rather than a gap.",
    ),
    PolicyRule(
        name="block-telnet", action="drop", priority=300, protocol=TCP, dst_port=23,
        rationale="Telnet is the classic IoT botnet vector and has no legitimate use here.",
    ),
    PolicyRule(
        name="block-rdp", action="drop", priority=300, protocol=TCP, dst_port=3389,
        rationale="No Windows hosts in the topology; anything reaching for RDP is hostile.",
    ),
    PolicyRule(
        name="allow-web-to-servers", action="allow", priority=200,
        protocol=TCP, dst_net=SERVER_SUBNET, dst_port=80,
        rationale="The service under test. Deliberately left open, so an HTTP-borne "
                  "attack (injection, XSS) is a gap the detector has to catch on its own.",
    ),
    PolicyRule(
        name="allow-https-to-servers", action="allow", priority=200,
        protocol=TCP, dst_net=SERVER_SUBNET, dst_port=443,
        rationale="As above.",
    ),
    PolicyRule(
        name="allow-dns", action="allow", priority=200, protocol=UDP, dst_port=53,
        rationale="Every host needs resolution. Also why DNS-borne attacks are "
                  "invisible to the perimeter and left entirely to the model.",
    ),
    PolicyRule(
        name="allow-ssh-to-servers", action="allow", priority=150,
        protocol=TCP, dst_net=SERVER_SUBNET, dst_port=22,
        rationale="Administration. Open on purpose: a password-guessing run against "
                  "it is a gap, which is the point of the exercise.",
    ),
    PolicyRule(
        name="allow-icmp", action="allow", priority=100, protocol=ICMP,
        rationale="Ping is left on so that scanning shows up as a detector finding "
                  "rather than being silently dropped at the switch.",
    ),
]

# The table-miss entry. "allow" here makes the simulated network default-open,
# which is the common (and more interesting) case: gaps are then genuine
# coverage holes rather than an artifact of a deny-all policy. Module 6 takes
# this as `--default-action`, and getting it wrong inverts every verdict.
DEFAULT_ACTION = "allow"


def _match_dict(rule: PolicyRule) -> dict[str, Any]:
    match: dict[str, Any] = {}
    if rule.protocol is not None:
        match["eth_type"] = 0x0800  # IPv4; OpenFlow requires it before ip_proto
        match["ip_proto"] = rule.protocol
    if rule.src_net:
        match["ipv4_src"] = rule.src_net
    if rule.dst_net:
        match["ipv4_dst"] = rule.dst_net
    if rule.dst_port is not None:
        match["tcp_dst" if rule.protocol == TCP else "udp_dst"] = rule.dst_port
    return match


def export_ryu_flow_dump(dpid: int = 1, out_port: int = 2) -> dict[str, list[dict[str, Any]]]:
    """The policy in the shape `GET /stats/flow/<dpid>` returns.

    A dropping entry carries an empty action list -- OpenFlow has no DROP
    action, so "no output" *is* the drop, and that is what
    `source/firewall_check/rules.py` reads.
    """
    entries = []
    for rule in POLICY:
        entries.append({
            "priority": rule.priority,
            "match": _match_dict(rule),
            "actions": [] if rule.action == "drop" else [{"type": "OUTPUT", "port": out_port}],
            "cookie": 0,
            "table_id": 0,
        })
    entries.append({
        "priority": 0,
        "match": {},
        "actions": [] if DEFAULT_ACTION == "drop" else [{"type": "OUTPUT", "port": "CONTROLLER"}],
        "cookie": 0,
        "table_id": 0,
    })
    return {str(dpid): entries}


def export_iptables() -> str:
    """The same policy as `iptables-save` output, for running the demo on a
    plain host instead of an SDN switch."""
    lines = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    for rule in sorted(POLICY, key=lambda r: -r.priority):
        parts = ["-A FORWARD"]
        if rule.protocol is not None:
            parts += ["-p", {TCP: "tcp", UDP: "udp", ICMP: "icmp"}[rule.protocol]]
        if rule.src_net:
            parts += ["-s", rule.src_net]
        if rule.dst_net:
            parts += ["-d", rule.dst_net]
        if rule.dst_port is not None:
            parts += ["--dport", str(rule.dst_port)]
        parts += ["-j", "DROP" if rule.action == "drop" else "ACCEPT"]
        lines.append(" ".join(parts))
    lines.append(f"-A FORWARD -j {'DROP' if DEFAULT_ACTION == 'drop' else 'ACCEPT'}")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Write the reference policy in the format module 6 reads.")
    parser.add_argument("--format", choices=["ryu", "iptables"], default="ryu")
    parser.add_argument("--output", default="-", help="File to write, or - for stdout")
    args = parser.parse_args()

    text = (json.dumps(export_ryu_flow_dump(), indent=2) if args.format == "ryu"
            else export_iptables())
    if args.output == "-":
        print(text)
    else:
        with open(args.output, "w") as handle:
            handle.write(text)


if __name__ == "__main__":
    main()
