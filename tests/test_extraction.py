"""Tests for module 1 (NFStream-based flow extraction).

Two layers, deliberately:

1. The header parsers are tested directly against hand-built bytes, so a
   wrong offset fails with an obvious message instead of surfacing as a
   slightly-off feature value much later.
2. The whole extractor runs over a synthetic pcap whose every header value
   was chosen by this file, so each of the 19 plugin-computed fields can be
   asserted against a number we know rather than one we eyeballed.

Why this matters more than usual: these fields feed a model trained on
nProbe's output. A parser that is merely *plausible* -- right shape, wrong
value -- produces train/serve skew that no amount of downstream testing
would catch, because every stage after this one would be working correctly
on a wrong number.
"""

from __future__ import annotations

import socket
import struct

import numpy as np

import pytest

from source.common.constants import NETFLOW_FEATURES
from source.extraction.nfplugin import (
    parse_dns,
    parse_ftp_return_code,
    parse_icmp_type_code,
    parse_tcp_seq_and_paylen,
    parse_tcp_window,
    parse_ttl,
)

pytest.importorskip("nfstream", reason="module 1 needs nfstream installed")


# --------------------------------------------------------------------------
# packet construction helpers -- every value here is chosen, not incidental
# --------------------------------------------------------------------------

def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s", (4 << 4) | 5, 0, 20 + len(payload), 0, 0, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, window: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(ip_packet: bytes) -> bytes:
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip_packet


def write_pcap(path, packets) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def dns_query(query_id: int, qtype: int) -> bytes:
    return (struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00" + struct.pack("!HH", qtype, 1))


def dns_response(query_id: int, qtype: int, answer_ttl: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, answer_ttl, 4) + b"\x5d\xb8\xd8\x22"
    return header + question + answer


# --------------------------------------------------------------------------
# 1. header parsers, in isolation
# --------------------------------------------------------------------------

def test_parse_ttl_reads_the_right_offset():
    assert parse_ttl(ipv4("10.0.0.1", "10.0.0.2", 6, b"", ttl=64)) == 64
    assert parse_ttl(ipv4("10.0.0.1", "10.0.0.2", 6, b"", ttl=255)) == 255
    assert parse_ttl(b"\x45\x00") is None  # truncated header, not a guess


def test_parse_tcp_window():
    pkt = ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 0, 0, 0x02, window=64240), 64)
    assert parse_tcp_window(pkt) == 64240


def test_parse_tcp_seq_and_payload_length():
    pkt = ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, seq=99, ack=0, flags=0x18, window=100, payload=b"Z" * 250), 64)
    assert parse_tcp_seq_and_paylen(pkt) == (99, 250)


def test_pure_ack_has_zero_payload_length():
    pkt = ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, seq=5, ack=5, flags=0x10, window=100), 64)
    assert parse_tcp_seq_and_paylen(pkt) == (5, 0)


def test_parse_icmp_type_and_code():
    pkt = ipv4("10.0.0.1", "10.0.0.2", 1, struct.pack("!BBHHH", 3, 1, 0, 0, 0), 64)
    assert parse_icmp_type_code(pkt) == (3, 1)  # destination unreachable / host unreachable


def test_parse_dns_query_and_response():
    qid, qtype, ttl = parse_dns(dns_query(0xBEEF, qtype=28))  # AAAA
    assert (qid, qtype, ttl) == (0xBEEF, 28, 0)  # a query carries no answer TTL

    qid, qtype, ttl = parse_dns(dns_response(0xBEEF, qtype=1, answer_ttl=3600))
    assert (qid, qtype, ttl) == (0xBEEF, 1, 3600)


def test_parse_dns_rejects_a_runt_packet():
    assert parse_dns(b"\x00\x01") is None


def test_parse_ftp_return_code():
    assert parse_ftp_return_code(b"220 Service ready\r\n") == 220
    assert parse_ftp_return_code(b"530 Not logged in\r\n") == 530
    assert parse_ftp_return_code(b"USER anonymous\r\n") is None  # a command, not a reply


# --------------------------------------------------------------------------
# 2. the whole extractor, over a pcap with known contents
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def flows(tmp_path_factory):
    """One TCP flow (with a deliberate retransmission and asymmetric
    flags/TTL/window), one DNS exchange, one ICMP echo."""
    path = tmp_path_factory.mktemp("pcap") / "known.pcap"
    packets = [
        # --- TCP: client TTL 64 / window 65535, server TTL 128 / window 8192 ---
        eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 1, 0, 0x02, 65535), 64)),            # SYN
        eth(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(80, 50000, 1, 2, 0x12, 8192), 128)),            # SYN-ACK
        eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 2, 2, 0x10, 65535), 64)),            # ACK
        eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 2, 2, 0x18, 65535, b"X" * 300), 64)),  # PSH 300B
        eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 2, 2, 0x18, 65535, b"X" * 300), 64)),  # retransmit
        eth(ipv4("10.0.0.2", "10.0.0.1", 6, tcp(80, 50000, 2, 302, 0x18, 8192, b"Y" * 1000), 128)),  # 1000B
        eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(50000, 80, 302, 1002, 0x11, 65535), 64)),       # FIN-ACK
        # --- DNS query + response, answer TTL 3600 ---
        eth(ipv4("10.0.0.1", "10.0.0.3", 17, udp(40000, 53, dns_query(0x1234, 1)), 64)),
        eth(ipv4("10.0.0.3", "10.0.0.1", 17, udp(53, 40000, dns_response(0x1234, 1, 3600)), 57)),
        # --- ICMP echo request (type 8, code 0) ---
        eth(ipv4("10.0.0.1", "10.0.0.4", 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1), 64)),
    ]
    write_pcap(path, packets)

    from source.extraction.sensor import extract
    rows = list(extract(str(path)))
    return {(r["PROTOCOL"], r["L4_DST_PORT"]): r for r in rows}


def test_every_row_matches_the_training_schema_exactly(flows):
    for row in flows.values():
        assert list(row.keys()) == NETFLOW_FEATURES


def test_tcp_flow_ttl_min_and_max_span_both_directions(flows):
    tcp_flow = flows[(6, 80)]
    assert tcp_flow["MIN_TTL"] == 64   # client
    assert tcp_flow["MAX_TTL"] == 128  # server


def test_tcp_windows_are_recorded_per_direction(flows):
    tcp_flow = flows[(6, 80)]
    assert tcp_flow["TCP_WIN_MAX_IN"] == 65535
    assert tcp_flow["TCP_WIN_MAX_OUT"] == 8192


def test_client_and_server_flag_bitmasks_differ_correctly(flows):
    tcp_flow = flows[(6, 80)]
    # client sent SYN, ACK, PSH, FIN -> 0x02|0x10|0x08|0x01 = 0x1B
    assert tcp_flow["CLIENT_TCP_FLAGS"] == 0x1B
    # server sent only SYN-ACK and PSH-ACK -> 0x02|0x10|0x08 = 0x1A (no FIN)
    assert tcp_flow["SERVER_TCP_FLAGS"] == 0x1A
    # the bidirectional mask is the union
    assert tcp_flow["TCP_FLAGS"] == 0x1B


def test_retransmission_is_counted_once_with_its_payload_size(flows):
    tcp_flow = flows[(6, 80)]
    assert tcp_flow["RETRANSMITTED_IN_PKTS"] == 1
    assert tcp_flow["RETRANSMITTED_IN_BYTES"] == 300
    assert tcp_flow["RETRANSMITTED_OUT_PKTS"] == 0  # server never repeated itself


def test_packet_size_histogram_covers_every_packet(flows):
    tcp_flow = flows[(6, 80)]
    buckets = [
        tcp_flow["NUM_PKTS_UP_TO_128_BYTES"],
        tcp_flow["NUM_PKTS_128_TO_256_BYTES"],
        tcp_flow["NUM_PKTS_256_TO_512_BYTES"],
        tcp_flow["NUM_PKTS_512_TO_1024_BYTES"],
        tcp_flow["NUM_PKTS_1024_TO_1514_BYTES"],
    ]
    total_packets = tcp_flow["IN_PKTS"] + tcp_flow["OUT_PKTS"]
    assert sum(buckets) == total_packets, f"buckets {buckets} lose packets (total {total_packets})"
    # 4 header-only packets (40B IP) land in the smallest bucket,
    # the two 340B packets in 256-512, and the 1040B one in 1024-1514
    assert buckets[0] == 4
    assert buckets[2] == 2
    assert buckets[4] == 1


def test_dns_fields_come_from_the_actual_query_and_answer(flows):
    dns_flow = flows[(17, 53)]
    assert dns_flow["DNS_QUERY_ID"] == 0x1234
    assert dns_flow["DNS_QUERY_TYPE"] == 1
    assert dns_flow["DNS_TTL_ANSWER"] == 3600  # picked up from the response, not the query


def test_icmp_type_uses_nprobe_type_times_256_plus_code(flows):
    icmp_flow = flows[(1, 0)]
    assert icmp_flow["ICMP_IPV4_TYPE"] == 8       # echo request
    assert icmp_flow["ICMP_TYPE"] == 8 * 256 + 0


def test_byte_and_packet_counts_match_the_capture(flows):
    tcp_flow = flows[(6, 80)]
    assert tcp_flow["IN_PKTS"] == 5   # SYN, ACK, PSH, retransmit, FIN
    assert tcp_flow["OUT_PKTS"] == 2  # SYN-ACK, PSH


# --------------------------------------------------------------------------
# 3. byte accounting -- the layer these are counted at
#
# nProbe wrote the training columns at the IP layer, and the data says so:
# SHORTEST_FLOW_PKT bottoms out at 40 there (a bare TCP header) and never
# at 54/60, where ethernet framing would floor it. NFStream's default
# counts whole ethernet frames, so every byte column came out 14 bytes per
# packet too large -- and nothing above noticed, because the only existing
# byte-ish assertion was on the size histogram, which the plugin computes
# from `packet.ip_size` and therefore already had right.
# --------------------------------------------------------------------------

def test_byte_counters_are_ip_layer_not_ethernet_frames(flows):
    tcp_flow = flows[(6, 80)]
    # IP sizes: SYN 40, ACK 40, PSH 340, retransmit 340, FIN 40
    assert tcp_flow["IN_BYTES"] == 800
    # SYN-ACK 40, PSH 1040
    assert tcp_flow["OUT_BYTES"] == 1080

    dns_flow = flows[(17, 53)]
    assert dns_flow["IN_BYTES"] == 57   # 20 IP + 8 UDP + 29 query
    assert dns_flow["OUT_BYTES"] == 73  # 20 IP + 8 UDP + 45 response


def test_packet_length_extremes_are_ip_layer(flows):
    tcp_flow = flows[(6, 80)]
    assert tcp_flow["SHORTEST_FLOW_PKT"] == 40    # 54 would mean ethernet
    assert tcp_flow["LONGEST_FLOW_PKT"] == 1040   # 1054 would mean ethernet
    assert tcp_flow["MAX_IP_PKT_LEN"] == 1040


def test_min_ip_pkt_len_is_zero_on_one_directional_flows(flows):
    """nProbe reports MIN_IP_PKT_LEN as 0 whenever OUT_PKTS is 0, and as
    SHORTEST_FLOW_PKT otherwise. Measured over 3M training rows: equal on
    every row with OUT_PKTS > 0, zero on all 2,278,969 rows with
    OUT_PKTS == 0 (one exception), and never once greater than
    SHORTEST_FLOW_PKT -- which is what rules out a reverse-direction
    minimum. 76% of training rows carry that 0, so reporting the true
    length here would disagree with the model on most of its traffic."""
    icmp_flow = flows[(1, 0)]   # single packet, nothing came back
    assert icmp_flow["OUT_PKTS"] == 0
    assert icmp_flow["MIN_IP_PKT_LEN"] == 0
    assert icmp_flow["MAX_IP_PKT_LEN"] == 28  # MAX is never blanked

    tcp_flow = flows[(6, 80)]   # bidirectional: the real minimum shows
    assert tcp_flow["OUT_PKTS"] > 0
    assert tcp_flow["MIN_IP_PKT_LEN"] == tcp_flow["SHORTEST_FLOW_PKT"] == 40


def test_rate_columns_follow_nprobes_convention_not_their_names(flows):
    """`*_SECOND_BYTES` and `*_AVG_THROUGHPUT` are not rates in this
    dataset. Measured over 3M training rows: SECOND_BYTES equals the byte
    total on 99.85% of them (99.95% on the DST side) and AVG_THROUGHPUT
    equals byte total x 8000 on 99.58% (99.87%). Dividing by duration --
    which is what the names suggest and what this code used to do -- matches
    0.00% of rows, because FLOW_DURATION_MILLISECONDS is 0 on 98.4% of
    flows. Four features, essentially every flow."""
    tcp_flow = flows[(6, 80)]
    assert tcp_flow["FLOW_DURATION_MILLISECONDS"] > 0, (
        "fixture must have a non-zero duration, or this cannot tell the "
        "two conventions apart"
    )
    assert tcp_flow["SRC_TO_DST_SECOND_BYTES"] == 800     # == IN_BYTES
    assert tcp_flow["DST_TO_SRC_SECOND_BYTES"] == 1080    # == OUT_BYTES
    assert tcp_flow["SRC_TO_DST_AVG_THROUGHPUT"] == 800 * 8000
    assert tcp_flow["DST_TO_SRC_AVG_THROUGHPUT"] == 1080 * 8000


def test_a_zero_duration_flow_produces_finite_values_matching_nprobe(flows):
    """A single-packet flow has zero duration. Dividing by it is what
    produced the +/-inf values clean.py has to repair in the raw CSV -- but
    the fix is not to emit 0 either, which is what this code used to do.
    nProbe reports the byte total, so a one-packet flow's SECOND_BYTES is
    the size of that packet."""
    icmp_flow = flows[(1, 0)]
    assert icmp_flow["FLOW_DURATION_MILLISECONDS"] == 0
    assert icmp_flow["IN_BYTES"] == 28
    assert icmp_flow["SRC_TO_DST_SECOND_BYTES"] == 28
    assert icmp_flow["SRC_TO_DST_AVG_THROUGHPUT"] == 28 * 8000
    assert np.isfinite(icmp_flow["SRC_TO_DST_AVG_THROUGHPUT"])
    # Nothing came back, so the DST side is genuinely zero.
    assert icmp_flow["DST_TO_SRC_SECOND_BYTES"] == 0.0


def test_non_tcp_flows_report_zero_for_tcp_only_fields(flows):
    dns_flow = flows[(17, 53)]
    assert dns_flow["TCP_WIN_MAX_IN"] == 0
    assert dns_flow["TCP_FLAGS"] == 0
    assert dns_flow["RETRANSMITTED_IN_PKTS"] == 0


# --------------------------------------------------------------------------
# 4. two protocol shapes the single fixture above can't express, each of
#    which used to produce a wrong value that looked entirely plausible
# --------------------------------------------------------------------------

def test_a_ping_reply_does_not_erase_the_request(tmp_path):
    """Echo reply is type 0 code 0, which encodes to the same 0 that means
    "this flow carried no ICMP". Last-packet-wins therefore made an
    ordinary answered ping indistinguishable from a flow with no ICMP in
    it at all -- and from a scan whose pings went unanswered, which is a
    distinction an intrusion detector exists to draw."""
    path = tmp_path / "ping.pcap"
    write_pcap(path, [
        eth(ipv4("10.0.0.1", "10.0.0.4", 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1), 64)),
        eth(ipv4("10.0.0.4", "10.0.0.1", 1, struct.pack("!BBHHH", 0, 0, 0, 1, 1), 64)),
    ])
    from source.extraction.sensor import extract
    row = list(extract(str(path)))[0]

    assert row["OUT_PKTS"] == 1, "fixture must actually contain the reply"
    assert row["ICMP_IPV4_TYPE"] == 8            # the request, not the reply
    assert row["ICMP_TYPE"] == 8 * 256 + 0
    assert row["ICMP_TYPE"] != 0                 # the bug's signature


def test_dns_over_tcp_skips_its_two_byte_length_prefix(tmp_path):
    """DNS over TCP frames each message with a 2-byte length (RFC 1035
    s4.2.2). Parsing it as a UDP message shifts every offset by two and
    reads the length itself as the query id -- which is a number, in the
    right column, in a plausible range."""
    message = dns_query(0xBEEF, qtype=252)  # AXFR: a zone transfer, TCP-only
    framed = struct.pack("!H", len(message)) + message

    path = tmp_path / "dns_tcp.pcap"
    write_pcap(path, [
        eth(ipv4("10.0.0.1", "10.0.0.3", 6,
                 tcp(50001, 53, 1, 0, 0x18, 65535, framed), 64)),
    ])
    from source.extraction.sensor import extract
    row = list(extract(str(path)))[0]

    assert row["DNS_QUERY_ID"] == 0xBEEF
    assert row["DNS_QUERY_TYPE"] == 252
    assert row["DNS_QUERY_ID"] != len(message)  # what the unstripped parse returned


def test_length_prefix_is_only_stripped_when_it_actually_fits():
    """A TCP segment that continues an earlier message has no prefix, and
    guessing one off the front would silently eat two real bytes."""
    from source.extraction.nfplugin import strip_tcp_dns_length_prefix

    message = dns_query(0x1234, qtype=1)
    framed = struct.pack("!H", len(message)) + message
    assert strip_tcp_dns_length_prefix(framed) == message

    # Declares far more than follows -> not a length prefix, leave it be.
    bogus = struct.pack("!H", 9999) + b"\x00" * 10
    assert strip_tcp_dns_length_prefix(bogus) == bogus
    assert strip_tcp_dns_length_prefix(b"\x00") == b"\x00"


def test_udp_dns_is_not_treated_as_framed(flows):
    """The same stripping applied to UDP would corrupt every ordinary DNS
    lookup, so the branch has to key off the transport protocol."""
    dns_flow = flows[(17, 53)]
    assert dns_flow["DNS_QUERY_ID"] == 0x1234
    assert dns_flow["DNS_QUERY_TYPE"] == 1


# --------------------------------------------------------------------------
# 5. invariants that hold on 3M rows of the real training data, so they must
#    hold on anything we emit too -- a cheap net for the whole mapping
# --------------------------------------------------------------------------

def test_extracted_rows_satisfy_the_training_datas_invariants(flows):
    for key, r in flows.items():
        where = f"flow {key}"
        assert r["DURATION_IN"] <= r["FLOW_DURATION_MILLISECONDS"], where
        assert r["DURATION_OUT"] <= r["FLOW_DURATION_MILLISECONDS"], where
        assert r["SHORTEST_FLOW_PKT"] <= r["LONGEST_FLOW_PKT"], where
        assert r["MIN_TTL"] <= r["MAX_TTL"], where
        assert r["RETRANSMITTED_IN_PKTS"] <= r["IN_PKTS"], where
        assert r["RETRANSMITTED_OUT_PKTS"] <= r["OUT_PKTS"], where
        assert r["MIN_IP_PKT_LEN"] <= r["MAX_IP_PKT_LEN"], where
        # Bytes must be at least 20 per packet (a bare IP header); anything
        # less means the counter isn't measuring whole IP packets.
        if r["IN_PKTS"]:
            assert r["IN_BYTES"] >= 20 * r["IN_PKTS"], where
        if r["OUT_PKTS"]:
            assert r["OUT_BYTES"] >= 20 * r["OUT_PKTS"], where


def test_oversized_packets_are_left_out_of_the_histogram(tmp_path):
    """The five buckets stop at 1514 and nProbe drops anything larger
    rather than folding it into the top bucket -- verified on the 13 rows
    in 3M with LONGEST_FLOW_PKT > 1514, where the buckets always sum short
    of the packet count. Folding them in instead would inflate
    NUM_PKTS_1024_TO_1514_BYTES against what the model was trained on."""
    path = tmp_path / "jumbo.pcap"
    write_pcap(path, [
        eth(ipv4("10.0.0.1", "10.0.0.2", 6,
                 tcp(50000, 8080, 1, 0, 0x18, 65535, b"J" * 2000), 64)),
    ])
    from source.extraction.sensor import extract
    row = list(extract(str(path)))[0]

    buckets = [row["NUM_PKTS_UP_TO_128_BYTES"], row["NUM_PKTS_128_TO_256_BYTES"],
               row["NUM_PKTS_256_TO_512_BYTES"], row["NUM_PKTS_512_TO_1024_BYTES"],
               row["NUM_PKTS_1024_TO_1514_BYTES"]]
    assert row["LONGEST_FLOW_PKT"] == 2040  # 20 IP + 20 TCP + 2000
    assert sum(buckets) == 0, f"jumbo packet was bucketed as {buckets}"
