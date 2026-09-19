"""Attack traffic generators for the Mininet demo.

Each scenario produces traffic whose *flow-level* signature matches one of
the ToN-IoT attack classes the model was trained on. That qualifier
matters: the model reads NetFlow records, not payloads, so what has to be
reproduced is the shape of the flows -- how many, to how many destinations,
how short, how one-sided -- and not the exploit itself. A scan is a scan to
this detector whether or not anything is actually vulnerable at the far end.

Which is also why two of the trained classes are absent here. `injection`
and `xss` are payload attacks; at flow level they are ordinary HTTP
requests, and the model's own per-class detection rates say as much
(`xss` is its weakest class). Generating them would add traffic that
nothing downstream can distinguish from browsing, so the scenarios cover
the classes where a flow-level signature actually exists.

Requires Mininet (and hping3 inside the namespace for the flood scenarios).
Not run in this project's environment -- see ../README.md.
"""

from __future__ import annotations

import logging
import time

log = logging.getLogger(__name__)

SCENARIOS = ("scan", "ddos", "password")


def _has(host, tool: str) -> bool:
    return bool(host.cmd(f"command -v {tool}").strip())


def scan(net, duration: int = 60) -> None:
    """Port/host scanning: one source, many destinations, tiny one-sided
    flows. This is the fan-out signature
    `source/preprocessing/engineer_features.py` was written for -- a single
    scan flow looks like an ordinary short connection, and only the count of
    distinct destinations in the source's recent history separates them."""
    attacker = net.get("atk1")
    if _has(attacker, "nmap"):
        attacker.cmd(f"timeout {duration} nmap -sS -T4 -p 1-1024 10.0.1.0/24 10.0.2.0/24 &> /dev/null")
    else:
        log.warning("nmap not found; falling back to a hping3 sweep")
        for host in range(11, 15):
            attacker.cmd(f"timeout {duration // 4} hping3 -S -p ++1 --faster 10.0.1.{host} &> /dev/null")


def ddos(net, duration: int = 60) -> None:
    """Many sources converging on one destination -- the fan-in signature.
    Every IoT host floods srv1 at once, which is what makes this different
    from one host being busy."""
    target = net.get("srv1").IP()
    for name in ("iot1", "iot2", "iot3", "iot4"):
        host = net.get(name)
        if _has(host, "hping3"):
            host.cmd(f"timeout {duration} hping3 --flood -S -p 80 {target} &> /dev/null &")
        else:
            # ab/curl loops are a poor flood but still produce many short
            # flows from many sources, which is the feature that matters.
            host.cmd(f"timeout {duration} sh -c 'while :; do curl -s -m 1 http://{target}/ >/dev/null; done' &")
    time.sleep(duration + 2)


def password(net, duration: int = 60) -> None:
    """Repeated short connections to one service from one source: many
    flows, near-identical byte counts, all failing the same way."""
    attacker = net.get("atk1")
    target = net.get("srv1").IP()
    if _has(attacker, "hydra"):
        attacker.cmd(f"timeout {duration} hydra -l root -P /usr/share/wordlists/rockyou.txt "
                     f"ssh://{target} &> /dev/null")
    else:
        attacker.cmd(
            f"timeout {duration} sh -c 'for i in $(seq 1 500); do "
            f"nc -w 1 {target} 22 < /dev/null >/dev/null 2>&1; done'"
        )


def benign_background(net, duration: int = 60) -> None:
    """Ordinary traffic, so a run contains something the detector should
    *not* flag. A demo with attacks only cannot show a false-positive rate,
    which is the number this project is most constrained by."""
    for name in ("iot1", "iot2", "iot3"):
        host = net.get(name)
        host.cmd(
            f"timeout {duration} sh -c 'while :; do "
            f"curl -s -m 2 http://10.0.2.11/ >/dev/null; sleep 2; done' &"
        )


def run_scenario(net, scenario: str, duration: int = 60) -> None:
    benign_background(net, duration)
    log.info("Running scenario %r for %ds (benign background is also running)", scenario, duration)
    {"scan": scan, "ddos": ddos, "password": password}[scenario](net, duration)
    log.info("Scenario finished.")
