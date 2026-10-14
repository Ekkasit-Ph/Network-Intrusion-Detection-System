#!/usr/bin/env python3
"""Minimal UDP DNS responder for the Mininet demo.

Why hand-rolled: the VM has no dnsmasq, and the point is only to produce
*real DNS-protocol flows* (UDP/53, with the query/response the nfstream/nDPI
metering classifies as DNS) so the model's "normal" includes the protocol it
was weakest on in the dataset. It answers every A query with a rotating
10.0.2.x address and ignores everything else -- correctness of the record is
irrelevant to a flow-level detector, presence of the protocol is not.

Run inside the dns1 namespace:  python3 dns_server.py [--port 53]
"""
import argparse
import socket
import struct


def build_response(query: bytes) -> bytes | None:
    if len(query) < 12:
        return None
    tid = query[:2]
    # flags: response, recursion available; qdcount=1, ancount=1
    header = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    # question section starts at byte 12; copy it verbatim up to and incl. the
    # QTYPE/QCLASS (walk the labels to their terminating zero, then +4 bytes)
    i = 12
    while i < len(query) and query[i] != 0:
        i += query[i] + 1
    qend = i + 1 + 4  # zero byte + QTYPE(2) + QCLASS(2)
    if qend > len(query):
        return None
    question = query[12:qend]
    # answer: name pointer to 0x0c, type A, class IN, ttl 60, rdlen 4, IP
    answer = (b"\xc0\x0c" + b"\x00\x01" + b"\x00\x01" +
              struct.pack(">I", 60) + b"\x00\x04" +
              bytes([10, 0, 2, (query[13] % 6) + 20]))
    return header + question + answer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    while True:
        try:
            data, addr = sock.recvfrom(512)
        except OSError:
            break
        resp = build_response(data)
        if resp:
            sock.sendto(resp, addr)


if __name__ == "__main__":
    main()
