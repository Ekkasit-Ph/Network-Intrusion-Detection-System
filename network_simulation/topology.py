"""Mininet topology for the integrated demo.

    sudo python3 network_simulation/topology.py            # interactive CLI
    sudo python3 network_simulation/topology.py --scenario scan

Three segments behind one OpenFlow switch, plus the sensor on a fourth:

    10.0.1.0/24   iot1..iot6     sensors/cameras -- benign background traffic
    10.0.2.0/24   srv1, srv2     http/ssh -- the things worth attacking
                  dns1           the network's DNS resolver (real UDP/53)
    10.0.3.0/24   atk1           where the attack scripts run
    10.0.4.0/24   nids1          the sensor, fed by a SPAN port

The sensor hangs off a mirror rather than sitting inline. PROJECT.md's
first constraint is that this system never blocks traffic, so that a false
positive cannot become an outage; a mirror makes that structural instead of
a promise the code keeps, because nothing on a SPAN port can reach the
forwarding path.

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
    ("iot5", "10.0.1.15/24"), ("iot6", "10.0.1.16/24"),
    ("srv1", "10.0.2.11/24"), ("srv2", "10.0.2.12/24"),
    ("dns1", "10.0.2.13/24"),
    ("atk1", "10.0.3.11/24"),
]

# Real networks are a mix of devices with different default TTLs -- Linux
# hosts leave the stack at 64, Windows at 128, and a lot of embedded/IoT gear
# at 255. With one TTL everywhere, MIN_TTL/MAX_TTL degenerate to a constant
# and the model never learns they carry information (see the integration-run
# notes on MIN_TTL being flat). Assigning a realistic spread per host is a
# per-net-namespace sysctl, so each Mininet host can hold its own value.
HOST_TTLS = {
    "iot1": 255, "iot2": 255, "iot3": 64, "iot4": 128,
    "iot5": 255, "iot6": 64, "srv1": 64, "srv2": 64,
    "dns1": 64, "atk1": 64,
}

# The sensor gets a segment of its own so its address never appears in the
# traffic it is metering. A monitoring host that also answers pings would
# put its own flows into the capture it is supposed to be observing.
SENSOR = ("nids1", "10.0.4.11/24")
SUBNETS = ("10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24")
MIRROR_NAME = "nids-span"


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

    # The sensor, last so its switch port is the highest-numbered one and
    # `mirror_to_sensor` can find it without guessing. No bandwidth limit
    # on this link: it carries a copy of every other link at once, and
    # capping it at one link's rate would drop mirrored packets under load
    # and make the sensor under-report exactly when traffic matters most.
    net.addLink(net.addHost(SENSOR[0], ip=SENSOR[1]), switch, delay="0ms")

    # Every subnet sits on one switch, so hosts need routes to each other's
    # networks; Mininet only configures the host's own /24.
    return net


def _configure_routes(net) -> None:
    for name, _ in [*HOSTS, SENSOR]:
        host = net.get(name)
        for subnet in SUBNETS:
            host.cmd(f"ip route replace {subnet} dev {host.defaultIntf()}")


def set_realistic_ttls(net) -> None:
    """Give hosts a realistic spread of default TTLs (see HOST_TTLS). Each
    Mininet host is its own net namespace, so net.ipv4.ip_default_ttl is
    independent per host."""
    for name, ttl in HOST_TTLS.items():
        try:
            net.get(name).cmd(f"sysctl -w net.ipv4.ip_default_ttl={ttl} >/dev/null 2>&1")
        except KeyError:
            pass  # host not in this topology variant


def mirror_to_sensor(net) -> str:
    """Copy every packet crossing the switch to the sensor's port.

    A SPAN port, not an inline tap, and the distinction is the whole
    argument. PROJECT.md's first constraint is that module 6 never blocks
    traffic, to keep a false positive from becoming a self-inflicted
    outage. Hanging the sensor off a mirror makes that physical rather than
    a promise the code keeps: nothing it does can reach the forwarding
    path, because it is not on it.

    `select-all=true` copies both directions of every port. The sensor's
    own port is excluded implicitly -- it has no traffic of its own to
    mirror -- but its subnet is separate anyway so anything it did emit
    would be obvious in the capture rather than silently mixed in.
    """
    switch = net.get("s1")
    sensor_port = switch.intfNames()[-1]  # the last link added; see build()

    switch.cmd(f"ovs-vsctl -- --id=@p get Port {sensor_port}"
               f" -- --id=@m create Mirror name={MIRROR_NAME}"
               f" select-all=true output-port=@p"
               f" -- set Bridge {switch.name} mirrors=@m")

    # The sensor's interface has to be up and promiscuous or the kernel
    # drops frames addressed to other hosts before any capture sees them --
    # which is every frame on a mirror.
    sensor = net.get(SENSOR[0])
    sensor.cmd(f"ip link set {sensor.defaultIntf()} promisc on")
    return sensor_port


def clear_mirror(net) -> None:
    """A mirror outlives `net.stop()` if the bridge does, and a stale one
    keeps copying into a port that no longer exists."""
    switch = net.get("s1")
    switch.cmd(f"ovs-vsctl -- clear Bridge {switch.name} mirrors")
    switch.cmd(f"ovs-vsctl -- --if-exists destroy Mirror {MIRROR_NAME}")


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
    parser.add_argument("--no-mirror", dest="mirror", action="store_false",
                        help="Skip the SPAN port. Without it the sensor host exists but "
                             "sees only its own traffic, which is nothing.")
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

    if args.mirror:
        port = mirror_to_sensor(net)
        print(f"*** Mirroring all switch traffic to {SENSOR[0]} via {port}")
        print(f"*** Meter it with:  {SENSOR[0]} python3 -m web.backend.live_capture "
              f"--source {net.get(SENSOR[0]).defaultIntf()}")

    if args.scenario == "none":
        CLI(net)
    else:
        from network_simulation.attack_scripts import run_scenario
        run_scenario(net, args.scenario, duration=args.duration)

    if args.mirror:
        clear_mirror(net)
    net.stop()


if __name__ == "__main__":
    main()
