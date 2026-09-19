"""Firewall rules, as module 6 needs to reason about them.

One representation, two parsers. Ryu is what PROJECT.md specifies, and its
`ofctl_rest` API already serves the switch's flow table as JSON, so that is
the primary source. iptables is supported too because the demo host's own
firewall is the other thing a reviewer will reasonably ask about.

The matching rules encoded here are OpenFlow's, not iptables':

  * an absent match field is a wildcard -- it matches anything
  * the highest-priority matching entry wins, and ties break toward the
    first one listed, matching how Ryu reports them

That difference matters. iptables is first-match-wins with no priorities,
so `parse_iptables_save` assigns descending priorities in file order,
letting one matcher serve both.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

# OpenFlow instruction sets with no output action drop the packet; that is
# how a Ryu firewall app expresses "block" (there is no explicit DROP
# action in OpenFlow).
ACTION_DROP = "drop"
ACTION_ALLOW = "allow"

_PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "igmp": 2, "ipv6-icmp": 58}


@dataclass(frozen=True)
class FirewallRule:
    """One rule. `None` in any match field means "any" -- the OpenFlow
    wildcard, and also what an iptables rule that omits `-s`/`--dport`
    means."""

    action: str
    priority: int = 0
    src_net: ipaddress.IPv4Network | None = None
    dst_net: ipaddress.IPv4Network | None = None
    protocol: int | None = None
    # Ports are half-open ranges (lo, hi) inclusive, so `--dport 80:443`
    # and `--dport 80` are the same shape. A bare int is accepted and
    # normalized in __post_init__.
    src_port: tuple[int, int] | int | None = None
    dst_port: tuple[int, int] | int | None = None
    source: str = ""  # where this rule came from, for the dashboard

    def __post_init__(self) -> None:
        for field in ("src_port", "dst_port"):
            value = getattr(self, field)
            if isinstance(value, int):
                object.__setattr__(self, field, (value, value))

    @staticmethod
    def _port_in(span: tuple[int, int] | None, port: int) -> bool:
        return span is None or span[0] <= port <= span[1]

    def matches(self, src_ip: str, dst_ip: str, protocol: int,
                src_port: int, dst_port: int) -> bool:
        if self.protocol is not None and self.protocol != protocol:
            return False
        if not self._port_in(self.src_port, src_port):
            return False
        if not self._port_in(self.dst_port, dst_port):
            return False
        for net, addr in ((self.src_net, src_ip), (self.dst_net, dst_ip)):
            if net is None:
                continue
            try:
                if ipaddress.IPv4Address(addr) not in net:
                    return False
            except (ipaddress.AddressValueError, ValueError):
                # A malformed or non-IPv4 address cannot be shown to be
                # covered, so it is treated as not covered rather than
                # silently counted as protected.
                return False
        return True

    def describe(self) -> str:
        parts = [self.action]
        if self.protocol is not None:
            parts.append({6: "tcp", 17: "udp", 1: "icmp"}.get(self.protocol, f"proto{self.protocol}"))
        if self.src_net is not None:
            parts.append(f"src={self.src_net}")
        if self.dst_net is not None:
            parts.append(f"dst={self.dst_net}")
        for label, span in (("sport", self.src_port), ("dport", self.dst_port)):
            if span is not None:
                parts.append(f"{label}={span[0]}" if span[0] == span[1] else f"{label}={span[0]}-{span[1]}")
        parts.append(f"prio={self.priority}")
        return " ".join(parts)


class UnrepresentableRule(ValueError):
    """A rule carrying a condition this model cannot express.

    Such a rule is **dropped, never widened**. Silently ignoring the
    condition -- an interface constraint, a connection-state match, an IPv6
    address, a negation -- would leave a rule that matches strictly more
    traffic than the real one, and a too-broad rule makes module 6 report
    traffic as *covered* that the firewall actually permits. That hides a
    real gap, which is the one error this tool must not make. Dropping the
    rule errs the other way: it can only over-report gaps, and an
    over-reported gap gets investigated.
    """


class FirewallRuleSet:
    """The rules in force, queried by flow."""

    def __init__(self, rules: Iterable[FirewallRule], default_action: str = ACTION_ALLOW) -> None:
        # Sorted once, descending by priority; ties keep their original
        # order, which `sorted` guarantees by being stable.
        self.rules = sorted(rules, key=lambda r: -r.priority)
        # What happens to a flow no rule matches. A switch with a
        # table-miss entry that drops is "default deny"; without one,
        # unmatched traffic is forwarded. Getting this backwards would
        # invert every gap verdict, so it is explicit rather than assumed.
        self.default_action = default_action

    def __len__(self) -> int:
        return len(self.rules)

    def match(self, src_ip: str, dst_ip: str, protocol: int,
              src_port: int, dst_port: int) -> FirewallRule | None:
        for rule in self.rules:
            if rule.matches(src_ip, dst_ip, protocol, src_port, dst_port):
                return rule
        return None

    def action_for(self, src_ip: str, dst_ip: str, protocol: int,
                   src_port: int, dst_port: int) -> tuple[str, FirewallRule | None]:
        rule = self.match(src_ip, dst_ip, protocol, src_port, dst_port)
        return (rule.action if rule else self.default_action), rule


# --------------------------------------------------------------------------
# Ryu
# --------------------------------------------------------------------------

# ofctl_rest reports IPv4 addresses either bare ("10.0.0.1") or already as
# a prefix ("10.0.0.0/24"), and older builds use a netmask pair.
def _to_network(value: Any) -> ipaddress.IPv4Network | None:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (list, tuple)) and len(value) == 2:
            return ipaddress.IPv4Network(f"{value[0]}/{value[1]}", strict=False)
        return ipaddress.IPv4Network(str(value), strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        # An IPv6 address, a hostname, or a malformed prefix. Dropping the
        # constraint would turn "block this subnet" into "block everything",
        # so the rule goes instead.
        raise UnrepresentableRule(f"address constraint {value!r} is not IPv4: {exc}") from exc


def _to_port_span(value: Any) -> tuple[int, int] | None:
    """`80`, `"80"`, or a range `"80:443"` / `"80-443"`."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    for sep in (":", "-"):
        if sep in text:
            lo, hi = text.split(sep, 1)
            # An open-ended range: `:1024` is 0-1024, `1024:` is 1024-65535.
            return (int(lo) if lo else 0, int(hi) if hi else 65535)
    return (int(text), int(text))


def _first(match: dict[str, Any], *keys: str) -> Any:
    """OpenFlow renamed several match fields between versions (nw_src ->
    ipv4_src, tp_dst -> tcp_dst/udp_dst). Accept every spelling rather than
    silently wildcarding a field that was actually set -- which would
    report a rule as broader than it is, and so under-report gaps."""
    for key in keys:
        if match.get(key) not in (None, ""):
            return match[key]
    return None


# Match fields this model understands, plus the ones it can safely ignore
# because they cannot make a rule narrower in terms of the IPv4 5-tuple.
_RYU_UNDERSTOOD = {
    "ipv4_src", "nw_src", "ipv4_dst", "nw_dst", "ip_proto", "nw_proto",
    "tcp_src", "udp_src", "tp_src", "tcp_dst", "udp_dst", "tp_dst",
}
_RYU_IGNORABLE = {
    "eth_type",   # 0x0800 is implied by every IPv4 field above
    "eth_src", "eth_dst",  # L2, orthogonal to the 5-tuple in this topology
}


def parse_ryu_flow_dump(payload: str | dict[str, Any]) -> tuple[list[FirewallRule], list[str]]:
    """Rules from Ryu's `GET /stats/flow/<dpid>` response.

    That endpoint returns `{"<dpid>": [ {priority, match, actions|instructions}, ... ]}`.
    An entry with no output action drops -- OpenFlow has no DROP action, an
    empty action list *is* the drop.

    Returns `(rules, skipped)`. An entry matching on something this model
    cannot express -- `in_port`, a VLAN tag, an IPv6 address -- is skipped
    rather than having that condition dropped, because a rule stripped of a
    condition matches more traffic than the real one and would report
    coverage that does not exist. See `UnrepresentableRule`.
    """
    data = json.loads(payload) if isinstance(payload, str) else payload
    rules: list[FirewallRule] = []
    skipped: list[str] = []

    for dpid, entries in data.items():
        for entry in entries:
            match = entry.get("match", {}) or {}
            try:
                unknown = set(match) - _RYU_UNDERSTOOD - _RYU_IGNORABLE
                if unknown:
                    raise UnrepresentableRule(
                        f"match field(s) {sorted(unknown)} cannot be evaluated against a flow record")

                actions = entry.get("actions")
                if actions is None:
                    actions = [a for instruction in entry.get("instructions", [])
                               for a in instruction.get("actions", [])]
                has_output = any(
                    (a.get("type", "").upper() == "OUTPUT") if isinstance(a, dict)
                    else str(a).upper().startswith("OUTPUT")
                    for a in actions
                )
                protocol = _first(match, "ip_proto", "nw_proto")
                rules.append(FirewallRule(
                    action=ACTION_ALLOW if has_output else ACTION_DROP,
                    priority=int(entry.get("priority", 0)),
                    src_net=_to_network(_first(match, "ipv4_src", "nw_src")),
                    dst_net=_to_network(_first(match, "ipv4_dst", "nw_dst")),
                    protocol=int(protocol) if protocol is not None else None,
                    src_port=_to_port_span(_first(match, "tcp_src", "udp_src", "tp_src")),
                    dst_port=_to_port_span(_first(match, "tcp_dst", "udp_dst", "tp_dst")),
                    source=f"ryu:dpid={dpid}",
                ))
            except (UnrepresentableRule, ValueError, TypeError) as exc:
                skipped.append(f"dpid={dpid} priority={entry.get('priority')}: {exc}")
    return rules, skipped


# --------------------------------------------------------------------------
# iptables
# --------------------------------------------------------------------------

_IPTABLES_RULE = re.compile(r"^-A\s+(?P<chain>\S+)\s+(?P<rest>.*)$")


# Flags whose meaning this model implements.
_IPTABLES_UNDERSTOOD = {"-s", "-d", "-p", "--dport", "--sport", "--dports", "--sports", "-j", "-m"}
# `-m` modules we can handle. Anything else -- state, conntrack, limit,
# recent, string -- makes the rule conditional on something a flow record
# does not carry.
_IPTABLES_MATCH_MODULES = {"multiport", "tcp", "udp", "icmp"}


def parse_iptables_save(text: str) -> tuple[list[FirewallRule], list[str]]:
    """Rules from `iptables-save` output (INPUT/FORWARD chains).

    iptables is first-match-wins with no priority field, so file order is
    encoded as descending priority -- that makes `FirewallRuleSet`'s
    highest-priority-wins search produce iptables' semantics unchanged.

    Returns `(rules, skipped)`. A rule using a condition this model cannot
    express -- a negation, an interface, `-m state` -- is skipped rather
    than having that condition silently dropped; see `UnrepresentableRule`
    for why widening is the dangerous direction.

    `-m multiport --dports 80,443` expands into one rule per port, since
    reading it as "any port" would turn a two-port block into a block on
    everything.
    """
    rules: list[FirewallRule] = []
    skipped: list[str] = []
    order = 1_000_000

    for line in text.splitlines():
        line = line.strip()
        m = _IPTABLES_RULE.match(line)
        if not m or m.group("chain") not in ("INPUT", "FORWARD"):
            continue
        tokens = m.group("rest").split()

        try:
            fields, modules = _iptables_fields(tokens)

            target = fields.get("-j", "").upper()
            if target in ("DROP", "REJECT"):
                action = ACTION_DROP
            elif target == "ACCEPT":
                action = ACTION_ALLOW
            else:
                # LOG, RETURN, a user chain: these do not decide the
                # packet's fate, so there is no verdict to record.
                continue

            unknown_modules = modules - _IPTABLES_MATCH_MODULES
            if unknown_modules:
                raise UnrepresentableRule(
                    f"-m {'/'.join(sorted(unknown_modules))} depends on state a flow record lacks")

            protocol = fields.get("-p")
            if protocol and protocol.lower() not in _PROTOCOL_NUMBERS:
                raise UnrepresentableRule(f"unknown protocol {protocol!r}")

            base = {
                "action": action,
                "src_net": _to_network(fields.get("-s")),
                "dst_net": _to_network(fields.get("-d")),
                "protocol": _PROTOCOL_NUMBERS.get(protocol.lower()) if protocol else None,
                "source": "iptables",
            }
            src_spans = _port_list(fields.get("--sport") or fields.get("--sports"))
            dst_spans = _port_list(fields.get("--dport") or fields.get("--dports"))
            for src_span in src_spans:
                for dst_span in dst_spans:
                    rules.append(FirewallRule(priority=order, src_port=src_span,
                                              dst_port=dst_span, **base))
            order -= 1
        except (UnrepresentableRule, ValueError, TypeError) as exc:
            skipped.append(f"{line}: {exc}")
            order -= 1

    return rules, skipped


def _iptables_fields(tokens: list[str]) -> tuple[dict[str, str], set[str]]:
    """Flag -> value, plus the set of `-m` modules used. Raises if the rule
    uses a flag this model does not implement."""
    fields: dict[str, str] = {}
    modules: set[str] = set()
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "!":
            # Negation. "block everything except X" is not expressible
            # here, and dropping the `!` would inverts the rule's meaning
            # entirely rather than merely widening it.
            raise UnrepresentableRule("negated match (!)")
        if not token.startswith("-"):
            i += 1
            continue
        if token not in _IPTABLES_UNDERSTOOD:
            raise UnrepresentableRule(f"flag {token} is not implemented")
        if i + 1 >= len(tokens):
            raise UnrepresentableRule(f"flag {token} has no value")
        value = tokens[i + 1]
        if value == "!":
            raise UnrepresentableRule(f"negated match after {token}")
        if token == "-m":
            modules.add(value.lower())
        else:
            fields[token] = value
        i += 2
    return fields, modules


def _port_list(value: str | None) -> list[tuple[int, int] | None]:
    """`None` -> [None] (no constraint); `"80,443"` -> two spans;
    `"80:443"` -> one span."""
    if not value:
        return [None]
    return [_to_port_span(part) for part in value.split(",")]


def load_rules(path: str, fmt: str = "auto") -> tuple[list[FirewallRule], list[str]]:
    """Read a rule file, guessing the format from its contents unless told.
    Returns `(rules, skipped)`."""
    with open(path) as handle:
        text = handle.read()
    if fmt == "auto":
        fmt = "ryu" if text.lstrip().startswith("{") else "iptables"
    if fmt == "ryu":
        return parse_ryu_flow_dump(text)
    if fmt == "iptables":
        return parse_iptables_save(text)
    raise ValueError(f"unknown firewall rule format: {fmt!r}")
