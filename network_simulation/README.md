# network_simulation

Mininet topology + Ryu controller app, providing the live traffic and the
reference firewall policy that modules 1 and 6 consume.

```
network_simulation/
├── firewall_rules.py    # the reference policy, and its export to what module 6 reads
├── topology.py           # Mininet: three segments behind one OpenFlow switch
├── ryu_app.py            # Ryu app installing that policy
└── attack_scripts/       # scan / ddos / password traffic generators
```

## What runs here, and what does not

**Not run in this environment.** Mininet needs root and system packages;
Ryu has not kept up with Python 3.12. `topology.py`, `ryu_app.py` and the
attack scripts have therefore not been executed as part of this work. They
are written so an integrated run is reproducible on a machine that has
both, and both files fail with an explanatory message rather than a bare
`ImportError` when the dependency is missing.

**Verified here:** the seam between the simulation and module 6 — the
policy, and its export into the exact JSON `source/firewall_check` parses.
That is deliberately where the effort went, because a mismatch there is the
failure that would look most like a real result: if the exported rules
disagreed with the ones the switch enforces, module 6 would report the
drift as coverage failure and the output would read as a security finding.
[`tests/test_network_simulation.py`](../tests/test_network_simulation.py)
pins the round-trip, and checks the Ryu and iptables renderings of the same
policy return identical verdicts.

## The policy is defined once

`firewall_rules.POLICY` is the single source. `ryu_app.py` installs it;
`export_ryu_flow_dump()` renders it as `GET /stats/flow/<dpid>` would.
Nothing is transcribed by hand between the two.

```bash
python -m network_simulation.firewall_rules --format ryu --output flows.json
python -m network_simulation.firewall_rules --format iptables --output rules.txt
```

It is **deliberately incomplete**. A perimeter that blocked everything the
detector can find would make module 6 report nothing and prove nothing:

| rule | effect on the demo |
|---|---|
| block SMB from the IoT subnet | lateral movement is **covered** — the firewall already stops it |
| block telnet, RDP | covered |
| allow HTTP/HTTPS to servers | injection and XSS are **gaps** — payload attacks the perimeter cannot see |
| allow SSH to servers | password guessing is a **gap** |
| allow DNS | DNS-borne attacks are a gap, and see the L7_PROTO caveat in [`../source/extraction/README.md`](../source/extraction/README.md) |

`DEFAULT_ACTION` sets what happens to traffic no rule matches, and module 6
takes it as `--default-action`. Getting it wrong inverts every verdict, so
it is stated in both places rather than assumed in either.

## Topology

```
10.0.1.0/24   iot1..iot4   sensors -- benign background traffic
10.0.2.0/24   srv1, srv2   http/ssh -- the things worth attacking
10.0.3.0/24   atk1         where the attack scripts run
```

One switch, not a multi-hop network. The detector consumes flow records, so
the only property the topology must have is that every inter-segment flow
crosses one observable point; depth would look better without changing a
single feature the model sees.

## Running the integrated demo

```bash
# 1. controller, with the REST API so its flow table can be read back
ryu-manager ryu.app.ofctl_rest network_simulation/ryu_app.py

# 2. topology + an attack scenario
sudo python3 network_simulation/topology.py --scenario scan

# 3. capture and score (module 1 -> 2 -> 3 -> 5)
sudo python -m web.backend.live_capture --source s1-eth1

# 4. what the firewall already covered (module 6)
curl -s http://localhost:8080/stats/flow/1 > flows.json
python -m source.firewall_check.ryu_log_compare --rules flows.json --default-action allow
```

Steps 3 and 4 have been exercised end to end against a synthetic pcap in
place of steps 1–2; see [`../source/firewall_check/README.md`](../source/firewall_check/README.md)
for that run's output and its limitations.

## Attack scenarios

`scan` (fan-out: one source, many destinations), `ddos` (fan-in: many
sources, one destination) and `password` (many short identical flows to one
service) reproduce **flow-level** signatures, not exploits — the model reads
NetFlow records, so what has to be reproduced is the shape of the traffic.

`injection` and `xss` are deliberately absent. At flow level they are
ordinary HTTP requests; the model's own per-class results say so (`xss` is
its weakest class at 74%). Generating them would add traffic nothing
downstream can distinguish from browsing.

Every scenario runs benign background traffic alongside the attack, so a run
can show a false-positive rate — the number this project is most
constrained by.
