"""Custom NFStream plugin computing the NF-ToN-IoT-v2 fields NFStream
doesn't expose natively (module 1).

Of the 43 fields in the training schema, NFStream's `NFlow` gives 16
directly and 7 more are arithmetic on those. The remaining 19 need
per-packet header access:

    MIN_TTL, MAX_TTL                     IP header
    TCP_WIN_MAX_IN, TCP_WIN_MAX_OUT      TCP header
    NUM_PKTS_*_BYTES  (5 buckets)        per-packet size histogram
    RETRANSMITTED_{IN,OUT}_{BYTES,PKTS}  TCP sequence tracking
    ICMP_TYPE, ICMP_IPV4_TYPE            ICMP header
    DNS_QUERY_ID, DNS_QUERY_TYPE, DNS_TTL_ANSWER   DNS payload
    FTP_COMMAND_RET_CODE                 FTP response line

NFStream's per-packet object has no `.ttl` or `.window` attribute, but it
does carry `.ip_packet` -- the raw IP bytes -- so this plugin parses the
headers itself. Everything here is offset arithmetic on those bytes; there
is no dependency on a packet-parsing library.

**Why matching the training schema matters so much here**: the model was
fit on nProbe's interpretation of these fields. Any field this plugin
computes differently is train/serve skew -- the model would be scoring a
quantity that doesn't mean what it meant during training. Where nProbe's
exact semantics are ambiguous, the choice made is written down in the
relevant method's comment rather than left implicit, so the assumption can
be checked against a labelled capture later.

Directional convention: NFStream calls the first-seen direction src2dst.
NetFlow's IN_* is src->dst and OUT_* is dst->src, so `packet.direction == 0`
maps to IN and `1` to OUT.
"""

from __future__ import annotations

import struct

from nfstream import NFPlugin

# TCP flag bits, for reassembling nProbe's cumulative TCP_FLAGS byte.
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

_DIR_IN, _DIR_OUT = 0, 1


def _ip_header_len(ip: bytes) -> int:
    """IHL is the low nibble of byte 0, counted in 32-bit words."""
    return (ip[0] & 0x0F) * 4


def parse_ttl(ip: bytes) -> int | None:
    """TTL lives at a fixed offset in the IPv4 header."""
    return ip[8] if len(ip) >= 9 else None


def parse_tcp_window(ip: bytes) -> int | None:
    """TCP receive window: bytes 14-15 of the TCP header."""
    off = _ip_header_len(ip)
    return struct.unpack("!H", ip[off + 14 : off + 16])[0] if len(ip) >= off + 16 else None


def parse_tcp_seq_and_paylen(ip: bytes) -> tuple[int, int] | None:
    """(sequence number, TCP payload length) -- the pair a retransmission
    repeats. Payload length is derived, not carried in the header: IP total
    length minus both header lengths."""
    off = _ip_header_len(ip)
    if len(ip) < off + 20:
        return None
    seq = struct.unpack("!I", ip[off + 4 : off + 8])[0]
    data_off = (ip[off + 12] >> 4) * 4
    total_len = struct.unpack("!H", ip[2:4])[0]
    return seq, max(0, total_len - off - data_off)


def parse_icmp_type_code(ip: bytes) -> tuple[int, int] | None:
    off = _ip_header_len(ip)
    return (ip[off], ip[off + 1]) if len(ip) >= off + 2 else None


def _skip_dns_name(buf: bytes, pos: int) -> int:
    """Walk a DNS name to its end, handling both label sequences and the
    0xC0 compression pointer (which terminates the name in two bytes)."""
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # pointer: 2 bytes, name ends here
            return pos + 2
        pos += length + 1
    return pos


def parse_dns(payload: bytes) -> tuple[int, int, int] | None:
    """(query id, query type, answer TTL) from a DNS message.

    Answer TTL is 0 when the message carries no answer record -- which is
    every query, so most flows legitimately report 0 here rather than a
    missing value. That matches the training data, where DNS_TTL_ANSWER is
    0 for the majority of rows.
    """
    if len(payload) < 12:
        return None
    query_id, _flags, qdcount, ancount = struct.unpack("!HHHH", payload[:8])
    pos = 12
    query_type = 0
    for _ in range(min(qdcount, 4)):  # cap: malformed counts shouldn't spin
        pos = _skip_dns_name(payload, pos)
        if pos + 4 > len(payload):
            return query_id, 0, 0
        query_type = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 4

    answer_ttl = 0
    if ancount:
        pos = _skip_dns_name(payload, pos)
        if pos + 10 <= len(payload):
            answer_ttl = struct.unpack("!I", payload[pos + 4 : pos + 8])[0]
    return query_id, query_type, answer_ttl


def strip_tcp_dns_length_prefix(payload: bytes) -> bytes:
    """DNS over TCP frames every message with a 2-byte big-endian length
    (RFC 1035 s4.2.2); DNS over UDP does not. Parsing a TCP message as if
    it were a UDP one shifts every offset by two and reads the length
    itself as the query id.

    The prefix is only stripped when the length it declares actually
    matches what follows, so a segment that is a continuation rather than
    the start of a message is left alone instead of losing two real bytes.
    """
    if len(payload) < 2:
        return payload
    declared = struct.unpack("!H", payload[:2])[0]
    rest = payload[2:]
    # `>=` rather than `==`: a segment may carry several pipelined messages,
    # and we only ever read the first.
    return rest if declared and len(rest) >= declared else payload


def parse_ftp_return_code(payload: bytes) -> int | None:
    """FTP replies start with a 3-digit status code ("220 ready"). Commands
    sent by the client have no code, so those yield None."""
    if len(payload) < 3 or not payload[:3].isdigit():
        return None
    return int(payload[:3])


class NetFlowV2Fields(NFPlugin):
    """Accumulates the 19 packet-level fields onto `flow.udps`."""

    def on_init(self, packet, flow):
        flow.udps.min_ttl = 255
        flow.udps.max_ttl = 0
        flow.udps.tcp_win_max_in = 0
        flow.udps.tcp_win_max_out = 0
        flow.udps.num_pkts_up_to_128 = 0
        flow.udps.num_pkts_128_to_256 = 0
        flow.udps.num_pkts_256_to_512 = 0
        flow.udps.num_pkts_512_to_1024 = 0
        flow.udps.num_pkts_1024_to_1514 = 0
        flow.udps.retrans_in_bytes = 0
        flow.udps.retrans_in_pkts = 0
        flow.udps.retrans_out_bytes = 0
        flow.udps.retrans_out_pkts = 0
        flow.udps.icmp_type = 0
        flow.udps.icmp_ipv4_type = 0
        flow.udps.dns_query_id = 0
        flow.udps.dns_query_type = 0
        flow.udps.dns_ttl_answer = 0
        flow.udps.ftp_command_ret_code = 0
        # Sequence numbers already seen, per direction, for retransmission
        # detection. Bounded below so a long-lived flow can't grow this
        # without limit.
        flow.udps._seen_seqs = ({}, {})
        # "Have we recorded an ICMP header yet" -- can't be inferred from
        # icmp_type, since a legitimate type 0 code 0 encodes to the same
        # 0 the field is initialized to.
        flow.udps._icmp_seen = False
        self._observe(packet, flow)

    def on_update(self, packet, flow):
        self._observe(packet, flow)

    def on_expire(self, flow):
        # A flow whose packets carried no readable TTL would otherwise
        # expire reporting the 255 sentinel as though it were measured.
        if flow.udps.min_ttl == 255 and flow.udps.max_ttl == 0:
            flow.udps.min_ttl = 0
        # Internal bookkeeping, not output fields.
        del flow.udps._seen_seqs
        del flow.udps._icmp_seen

    # ------------------------------------------------------------------
    def _observe(self, packet, flow):
        ip = bytes(packet.ip_packet) if packet.ip_packet else b""
        if len(ip) < 20 or packet.ip_version != 4:
            return

        ttl = parse_ttl(ip)
        if ttl is not None:
            flow.udps.min_ttl = min(flow.udps.min_ttl, ttl)
            flow.udps.max_ttl = max(flow.udps.max_ttl, ttl)

        self._count_size_bucket(packet, flow)

        if packet.protocol == 6:
            self._observe_tcp(packet, flow, ip)
        elif packet.protocol == 1:
            self._observe_icmp(flow, ip)

        self._observe_payload(packet, flow, ip)

    def _count_size_bucket(self, packet, flow):
        """Buckets are on the IP packet length -- NetFlow counts what was on
        the wire at layer 3, not the ethernet frame or the payload."""
        size = packet.ip_size
        if size <= 128:
            flow.udps.num_pkts_up_to_128 += 1
        elif size <= 256:
            flow.udps.num_pkts_128_to_256 += 1
        elif size <= 512:
            flow.udps.num_pkts_256_to_512 += 1
        elif size <= 1024:
            flow.udps.num_pkts_512_to_1024 += 1
        elif size <= 1514:
            flow.udps.num_pkts_1024_to_1514 += 1
        # Anything above 1514 is jumbo/reassembled and has no bucket in the
        # schema, so it is deliberately counted nowhere.

    def _observe_tcp(self, packet, flow, ip: bytes):
        window = parse_tcp_window(ip)
        if window is not None:
            if packet.direction == _DIR_IN:
                flow.udps.tcp_win_max_in = max(flow.udps.tcp_win_max_in, window)
            else:
                flow.udps.tcp_win_max_out = max(flow.udps.tcp_win_max_out, window)

        parsed = parse_tcp_seq_and_paylen(ip)
        if parsed is None:
            return
        seq, paylen = parsed
        if paylen == 0:
            return  # pure ACKs repeat sequence numbers by design; not retransmissions

        seen = flow.udps._seen_seqs[packet.direction]
        if seen.get(seq) == paylen:
            if packet.direction == _DIR_IN:
                flow.udps.retrans_in_pkts += 1
                flow.udps.retrans_in_bytes += paylen
            else:
                flow.udps.retrans_out_pkts += 1
                flow.udps.retrans_out_bytes += paylen
        elif len(seen) < 4096:  # cap memory on long flows
            seen[seq] = paylen

    def _observe_icmp(self, flow, ip: bytes):
        parsed = parse_icmp_type_code(ip)
        if parsed is None:
            return
        icmp_type, icmp_code = parsed
        # First ICMP packet wins, matching how DNS query id is handled
        # below. Last-packet-wins is actively harmful here: an echo reply
        # is type 0 code 0, so a perfectly ordinary ping would overwrite
        # the request and report 0 -- the exact value `on_init` uses to
        # mean "this flow carried no ICMP at all". The two states have to
        # stay distinguishable. Taking the first packet also reports the
        # request rather than the reply, which is what the training data
        # is dominated by: echo request (type 8) appears 2,293 times there
        # against 42 for echo reply (type 0).
        if flow.udps._icmp_seen:
            return
        flow.udps._icmp_seen = True
        # nProbe packs type and code into one number as type*256 + code;
        # ICMP_IPV4_TYPE carries the bare type.
        flow.udps.icmp_type = icmp_type * 256 + icmp_code
        flow.udps.icmp_ipv4_type = icmp_type

    def _observe_payload(self, packet, flow, ip: bytes):
        if packet.payload_size <= 0:
            return
        payload = ip[len(ip) - packet.payload_size :]

        if packet.src_port == 53 or packet.dst_port == 53:
            message = strip_tcp_dns_length_prefix(payload) if packet.protocol == 6 else payload
            parsed = parse_dns(message)
            if parsed:
                query_id, query_type, answer_ttl = parsed
                # First query wins for id/type; an answer's TTL overwrites
                # the default 0 whenever one actually appears in the flow.
                if not flow.udps.dns_query_id:
                    flow.udps.dns_query_id = query_id
                    flow.udps.dns_query_type = query_type
                if answer_ttl:
                    flow.udps.dns_ttl_answer = answer_ttl

        elif packet.src_port == 21 or packet.dst_port == 21:
            code = parse_ftp_return_code(payload)
            if code is not None:
                flow.udps.ftp_command_ret_code = code
