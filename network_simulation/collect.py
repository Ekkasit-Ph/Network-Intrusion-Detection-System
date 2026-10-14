"""Record a labelled NetFlow CSV from the Mininet topology.

Why this exists: `mininet-integration-run.md` showed that a model trained
on NF-ToN-IoT-v2 scores this network backwards (AUROC 0.000) because its
idea of "normal" is a dataset full of scans. The documented fix is to
train on the target network's own benign traffic -- which needs a
labelled capture of that traffic, in the same raw-CSV shape the
preprocessing pipeline already reads. That is what this produces.

Labelling is by address, not by timing, so it cannot drift:

    10.0.3.11 (atk1) -> 10.0.2.11   port scan        Attack="scanning"
    10.0.3.11 (atk1) -> 10.0.2.12   connection flood Attack="dos"
    everything else                                  Attack="Benign"

Giving each attack its own target is what makes that rule exact. The
identifier columns are dropped in preprocessing (IDENTIFIER_COLS), so
labelling by address leaks nothing into the features.

Usage (inside the VM, as root -- live capture needs CAP_NET_RAW):

    sudo PYTHONPATH=$HOME/nids python3 network_simulation/collect.py \
        --output /tmp/mininet-traffic.csv --rounds 40
"""
from __future__ import annotations

import argparse
import csv
import random
import subprocess
import sys
import time
from pathlib import Path

from network_simulation.topology import (
    SENSOR,
    build,
    clear_mirror,
    mirror_to_sensor,
    start_services,
    _configure_routes,
)

REPO = Path(__file__).resolve().parent.parent

CLIENTS = ("iot1", "iot2", "iot3", "iot4")
SERVERS = ("10.0.2.11", "10.0.2.12")
SCAN_TARGET = "10.0.2.11"
FLOOD_TARGET = "10.0.2.12"
ATTACKER_IP = "10.0.3.11"

# Different sizes so IN_BYTES/OUT_BYTES and the packet-size histogram
# features vary. A benign class where every flow carries an identical byte
# count teaches the autoencoder a constant, and then anything at all looks
# anomalous.
PAGES = ("README.md", "requirements.txt", "docker-compose.yml", "Dockerfile",
         "documentation/", "source/", "web/", "")


def _spread(net, commands: dict[str, str]) -> None:
    """Run one command per host, all at once, and wait for them.

    Concurrently, because flows that overlap in time are what give the
    behavioral window features something to count. `popen`, not `cmd`:
    `cmd` waits for completion, so a loop over it would serialise every
    host and the network would never have more than one flow in flight.
    """
    running = [net.get(h).popen(c, shell=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
               for h, c in commands.items()]
    for proc in running:
        proc.wait()


def benign_round(net, rnd: int, rng: random.Random) -> None:
    commands = {}
    for i, host in enumerate(CLIENTS):
        target = SERVERS[(rnd + i) % 2]
        port = rng.choice((80, 8080))
        page = rng.choice(PAGES)
        size = rng.choice((56, 256, 512, 1200))
        count = rng.choice((2, 3, 5))
        commands[host] = (
            f"curl -s -m 3 -o /dev/null http://{target}:{port}/{page} ; "
            f"ping -c {count} -i 0.2 -s {size} -W 1 {target} >/dev/null 2>&1"
        )
    # Servers talk to each other too, so "benign" is not synonymous with
    # "originates in the IoT subnet".
    if rnd % 3 == 0:
        commands["srv1"] = f"curl -s -m 3 -o /dev/null http://10.0.2.12:{rng.choice((80, 8080))}/"
    _spread(net, commands)

    # iperf every few rounds only -- it is much slower than curl, and bulk
    # transfers are a minority of real traffic anyway.
    if rnd % 4 == 3:
        udp_rate = rng.choice(("100k", "400k", "1m"))
        _spread(net, {
            "iot1": f"iperf -c {SERVERS[0]} -t {rng.choice((1, 2))} -y c",
            "iot3": f"iperf -c {SERVERS[1]} -u -b {udp_rate} -t 2 -y c",
        })


def attack_burst(net, rng: random.Random) -> None:
    """Two shapes, two targets, so the address-based labels stay exact."""
    atk = net.get("atk1")

    # Scanning: a TCP connect scan. -sT not -sS, because a SYN scan needs
    # raw sockets and leaves half-open connections that nfstream meters
    # differently from a completed handshake -- -sT is what an unprivileged
    # attacker on a compromised host actually has.
    lo = rng.choice((20, 100, 1000))
    atk.cmd(f"nmap -sT -n -Pn --
