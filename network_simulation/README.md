# network_simulation

On this branch (`main`) this package holds just the piece the running system
depends on:

```
network_simulation/
└── firewall_rules.py    # the reference firewall policy, and its export to
                          # the exact JSON that module 6 (firewall_check) parses
```

`firewall_rules.py` is pure-stdlib and runs anywhere. It is the **seam**
between the firewall and module 6: a mismatch between the exported rules and
the ones the switch enforces is exactly the failure that would read as a false
security finding, so the policy and its round-trip export live with the app.

## The full simulation lives on the `development` branch

The Mininet topology, the Ryu controller app, the GNS3 real-OS lab, the
traffic/attack generators and the demo capture scripts are **development and
integration-testing tools**, not part of what a user installs. They are kept
on the `development` branch together with the test suite and the benchmark
scripts:

```bash
git checkout development    # topology.py, ryu_app.py, demo/, gns3/, tests/, ...
```

The write-ups of those runs (Mininet VM setup, the integration run, the live
demo and its findings) are on that branch under `documentation/guides/`.
