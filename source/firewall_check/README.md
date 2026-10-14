# firewall_check — module 6

Compares the firewall's rules against the detector's findings and records
the flows the firewall would have let through.

```
source/firewall_check/
├── rules.py               # FirewallRule / FirewallRuleSet + Ryu and iptables parsers
└── ryu_log_compare.py     # walks the flows table, writes verdicts to firewall_checks
```

```bash
python -m source.firewall_check.ryu_log_compare --rules flows.json --default-action allow
python -m source.firewall_check.ryu_log_compare --rules iptables.rules --format iptables
```

A **gap** is a flow the detector called anomalous that the firewall would
have permitted: the detector saw something the perimeter did not.

## This never changes a firewall rule

PROJECT.md forbids auto-blocking, for a concrete reason rather than a
stylistic one. The detector's measured false-positive rate is about 5%, so
wiring it to a blocking action would drop roughly one legitimate flow in
twenty — a denial of service inflicted by the tool meant to prevent one.
This module reads rules and writes rows; nothing here opens a socket to a
controller, and `tests/test_firewall_check.py` (on the `development` branch)
asserts the `flows` table is byte-identical before and after a run.

## Two things that decide every verdict

**Default action.** A flow no rule matches is allowed or denied depending
on whether the switch has a table-miss drop entry. `--default-action` makes
that a required decision; assuming it would invert the gap count on a
default-deny network.

**Empty action list means drop.** OpenFlow has no DROP action — a flow
entry with no output *is* the block. Reading it as "allow" would turn every
successfully-blocked attack into a reported gap, which looks like a
dramatic finding rather than a parsing error.

## Not knowing is recorded as not knowing

A flow record missing an address or protocol has *undetermined* coverage,
and gets `NULL` in all three columns rather than a guess. Counting it as
covered would hide a real gap; counting it as a gap would invent one.

## Matching semantics

One matcher serves both formats. OpenFlow's rules are the ones encoded: an
absent match field is a wildcard, and the highest-priority entry wins.
iptables is first-match-wins with no priorities, so `parse_iptables_save`
assigns descending priorities in file order, which reproduces its semantics
exactly. Targets that decide nothing (`LOG`, `RETURN`, a jump to a user
chain) are skipped rather than guessed at.

`ryu_log_compare` evaluates rules against the flow as the exporter recorded
it (src → dst). A stateful firewall permitting the reply of an allowed
connection is **not** modelled: this is post-hoc coverage reporting over
flow records, not a packet-path simulation.

## Verified end to end

Against a synthetic capture using the simulation's addressing, with the
policy from
[`network_simulation/firewall_rules.py`](../../network_simulation/firewall_rules.py):

```
Checked 33 anomalous flow(s): 18 gap(s), 15 already covered, 0 undetermined.

  COVERED : port 445 x15    SMB scan from the IoT subnet — the policy blocks it
  GAP     : port 22  x15    SSH password guessing — SSH is deliberately open
            port 80  x3     HTTP — payload attacks the perimeter cannot see
```

That is the demonstration this module exists for: the same detector output
splits into "the firewall already had this" and "only the detector caught
this".

**One caveat on that run.** All 33 flows were flagged anomalous, including
the three benign HTTP ones. That is the synthetic pcap, not the detector —
hand-built packets with one-second inter-packet gaps do not resemble the
training distribution. Fed real nProbe rows instead, the same online path
produces a 2.00% false-positive rate. The gap/covered split above depends
only on the firewall policy and the flow's 5-tuple, so it is unaffected;
the flag rate is not a performance measurement and should not be read as
one.
