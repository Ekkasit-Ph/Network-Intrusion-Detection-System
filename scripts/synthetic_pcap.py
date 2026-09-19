"""Generate a valid pcap for benchmarking the flow-extraction stage.

Module 1's throughput can only be measured against real packets, and this
project has no capture of its own (see documentation/roadmap.md -- a real
one comes out of the Mininet run). Rather than leave the stage unmeasured,
this writes Ethernet/IPv4/{TCP,UDP} frames by hand: complete TCP sessions
(SYN, SYN-ACK, ACK, request, response, FIN x2) and DNS query/response
pairs, which is enough for nDPI to classify them as HTTP and DNS and for
every timing-relevant code path in the metering to run.

    python -m scripts.synthetic_pcap out.pcap --n-flows 2000

What it is not: a substitute for real traffic when judging *accuracy*. The
payloads are filler and the inter-packet timing is uniform. It measures how
fast the pipeline moves packets, nothing about how well it detects.
"""
from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path

FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
_ETH_IPV4 = b"\x08\x00"
_MAC_A, _MAC_B = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(src: str, dst: str, proto: int, payload_len: int, ident: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident & 0xFFFF, 0x4000, 64, proto, 0,
        bytes(int(o) for o in src.split(".")), bytes(int(o) for o in dst.split(".")),
    )
    return header[:10] + struct.pack("!H", _checksum(header)) + header[12:]


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int,
         window: int = 29200, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, window, 0, 0) + payload


def _udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


class PcapWriter:
    """Classic libpcap format, microsecond resolution, Ethernet link type."""

    def __init__(self, path: Path) -> None:
        self._fh = path.open("wb")
        self._fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self._clock = 1_700_000_000.0

    def write(self, frame: bytes, gap_seconds: float = 0.0008) -> None:
        self._clock += gap_seconds
        secs = int(self._clock)
        usecs = int(round((self._clock - secs) * 1_000_000))
        self._fh.write(struct.pack("!IIII", secs, usecs, len(frame), len(frame)) + frame)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _frame(src: str, dst: str, proto: int, segment: bytes, ident: int) -> bytes:
    return _MAC_B + _MAC_A + _ETH_IPV4 + _ipv4(src, dst, proto, len(segment), ident) + segment


def write_tcp_session(pcap: PcapWriter, src: str, dst: str, sport: int, dport: int,
                      body_len: int, ident: int, rng: random.Random) -> None:
    """A full conversation, not a bare SYN. A one-sided flow exercises a
    much smaller part of the feature set and would make the benchmark look
    faster than the real thing (see source/extraction/README.md)."""
    body = bytes(rng.getrandbits(8) for _ in range(min(body_len, 1400)))
    ack_after = 5001 + len(body)
    for src_ip, dst_ip, segment in (
        (src, dst, _tcp(sport, dport, 1000, 0, SYN)),
        (dst, src, _tcp(dport, sport, 5000, 1001, SYN | ACK)),
        (src, dst, _tcp(sport, dport, 1001, 5001, ACK)),
        (src, dst, _tcp(sport, dport, 1001, 5001, PSH | ACK, payload=b"GET / HTTP/1.1\r\nHost: bench\r\n\r\n")),
        (dst, src, _tcp(dport, sport, 5001, 1029, PSH | ACK, payload=b"HTTP/1.1 200 OK\r\n\r\n" + body)),
        (src, dst, _tcp(sport, dport, 1029, ack_after, ACK)),
        (src, dst, _tcp(sport, dport, 1029, ack_after, FIN | ACK)),
        (dst, src, _tcp(dport, sport, ack_after, 1030, FIN | ACK)),
    ):
        pcap.write(_frame(src_ip, dst_ip, 6, segment, ident))


def write_dns_exchange(pcap: PcapWriter, src: str, resolver: str, sport: int, ident: int) -> None:
    name = b"\x03www\x07example\x03com\x00"
    query = struct.pack("!HHHHHH", ident & 0xFFFF, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    answer = (struct.pack("!HHHHHH", ident & 0xFFFF, 0x8180, 1, 1, 0, 0) + name
              + struct.pack("!HH", 1, 1) + b"\xc0\x0c"
              + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34]))
    pcap.write(_frame(src, resolver, 17, _udp(sport, 53, query), ident))
    pcap.write(_frame(resolver, src, 17, _udp(53, sport, answer), ident))


def build(path: Path, n_flows: int, seed: int = 0, dns_every: int = 9) -> Path:
    """`dns_every=9` puts UDP/DNS at ~11% of flows, close to the 8.9% of
    benign traffic that is UDP in the training split."""
    rng = random.Random(seed)
    with PcapWriter(path) as pcap:
        for i in range(n_flows):
            src = f"10.0.{rng.randint(1, 3)}.{rng.randint(10, 60)}"
            if i % dns_every == 0:
                write_dns_exchange(pcap, src, "10.0.2.11", rng.randint(1024, 65000), i)
            else:
                write_tcp_session(pcap, src, f"10.0.2.{rng.randint(11, 12)}",
                                  rng.randint(1024, 65000), rng.choice([80, 443, 8080, 22]),
                                  rng.randint(40, 1400), i, rng)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("output", type=Path)
    parser.add_argument("--n-flows", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    out = build(args.output, args.n_flows, args.seed)
    print(f"{out}: {args.n_flows} flows, {out.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
