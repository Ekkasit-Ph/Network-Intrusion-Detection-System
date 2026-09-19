"""Mininet topology for the integrated demo.

    sudo python3 network_simulation/topology.py            # interactive CLI
    sudo python3 network_simulation/topology.py --scenario scan

Three segments behind one OpenFlow switch, which is where the sensor taps:

    10.0.1.0/24   iot1..iot4     sensors/cameras -- benign background traffic
    10.0.2.0/24   srv1, srv2     http/ssh/dns -- the things worth attacking
    10.0.3.0/24   atk1           where the attack scripts run

One switch, not a realistic multi-hop network, and that is deliberate: the
detector consumes *flow records*, so the only thing the topology has to get
right is that every flow between segments crosses one observable point.
Adding depth would make the picture prettier without changing a single
feature the model sees.

Requires Mininet and root, neither of which this project's environment has
(see the README). The code is here so the integrated run is reproducible on
a machine that does; it has not been executed as part of this work, and
that is stated rather than implied.
"""

from __future__ import annotations

import argparse
import sys

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653

HOSTS = [
    ("iot1", "10.0.1.11/24"), ("iot2", "10.0.1.12/24"),
    ("iot3", "10.0.1.13/24"), ("iot4", "10.0.1.14/24"),
    ("srv1", "10.0.2.11/24"), ("srv2", "10.0.2.12/24"),
    ("atk1", "10.0.3.11/24"),
]


def build():
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.link import TCLink

    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    switch = net.addSwitch("s1", protocols="OpenFlow13")

    for name, ip in HOSTS:
        host = net.addHost(name, ip=ip)
        # A little delay and a finite bandwidth so flow durations and byte
        # rates aren't all zero -- with an idealised link every flow
        # completes in the same instant and several features degenerate.
        net.addLink(host, switch, bw=100, delay="2ms")

    # All three subnets sit on one switch, so hosts need routes to each
    # other's networks; Mininet only configures the host's own /24.
    return net


def _configure_routes(net) -> None:
    for name, _ in HOSTS:
        host = net.get(name)
        for subnet in ("10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"):
            host.cmd(f"ip route replace {subnet} dev {host.defaultIntf()}")


def start_services(net) -> None:
    """Enough of a service to answer, so flows have two directions. A
    one-sided flow exercises a different and much smaller part of the
    feature set -- MIN_IP_PKT_LEN alone changes meaning (see
    source/extraction/README.md)."""
    for name in ("srv1", "srv2"):
        host = net.get(name)
        host.cmd("python3 -m http.server 80 &> /dev/null &")
        host.cmd("python3 -m http.server 8080 &> /dev/null &")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["none", "scan", "ddos", "password"], default="none",
                        help="Run one attack scenario non-interactively, then exit")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    try:
        from mininet.cli import CLI
        from mininet.log import setLogLevel
    except ImportError:
        sys.exit(
            "Mininet is not installed. It needs system packages and root:\n"
            "    sudo apt install mininet openvswitch-switch\n"
            "See network_simulation/README.md."
        )

    setLogLevel("info")
    net = build()
    net.start()
    _configure_routes(net)
    start_services(net)

    if args.scenario == "none":
        CLI(net)
    else:
        from network_simulation.attack_scripts import run_scenario
        run_scenario(net, args.scenario, duration=args.duration)

    net.stop()


if __name__ == "__main__":
    main()
