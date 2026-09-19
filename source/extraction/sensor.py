"""Live/offline flow extraction into the NF-ToN-IoT-v2 43-field schema
(module 1).

    python -m source.extraction.sensor --source eth0            # live capture
    python -m source.extraction.sensor --source capture.pcap    # replay a file
    python -m source.extraction.sensor --source eth0 --output flows.csv

Live capture needs packet-capture privileges (root, or
`setcap cap_net_raw,cap_net_admin=eip` on the python binary). Reading a
pcap file needs nothing special, which is also how the tests exercise this.

The output column order is `NETFLOW_FEATURES` verbatim, so a captured CSV
drops straight into `source/preprocessing/pipeline.py` alongside the
training data -- that shared constant is the only thing keeping extraction
and training from silently disagreeing about what column means what.

Wired to detection by `web/backend/live_capture.py`, which feeds these rows
through `source/preprocessing/online.py` (rolling behavioural features, the
saved encoders and scaler) and then the frozen model. This module stays
transform-free on purpose: it produces raw NetFlow values, exactly as the
training CSV holds them, and every derived quantity happens downstream where
it can be compared against the batch pipeline.
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
from pathlib import Path
from typing import Any, Iterator

from source.common.constants import NETFLOW_FEATURES
from source.extraction import l7_proto
from source.extraction.nfplugin import ACK, CWR, ECE, FIN, PSH, RST, SYN, URG, NetFlowV2Fields

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def _flags_byte(syn: int, ack: int, fin: int, rst: int, psh: int, urg: int, ece: int, cwr: int) -> int:
    """nProbe's TCP_FLAGS is the OR of every flag seen over the flow's
    lifetime. NFStream reports per-flag packet *counts* instead, so a
    non-zero count means that bit was set at some point."""
    value = 0
    for count, bit in ((syn, SYN), (ack, ACK), (fin, FIN), (rst, RST),
                       (psh, PSH), (urg, URG), (ece, ECE), (cwr, CWR)):
        if count:
            value |= bit
    return value


# The two *_SECOND_BYTES and two *_AVG_THROUGHPUT columns are not rates in
# this dataset, despite their names, and computing them as rates is skew on
# four features across essentially every flow.
#
# What nProbe actually wrote, measured over 3M training rows:
#
#     SRC_TO_DST_SECOND_BYTES   == IN_BYTES         99.85%   (DST side 99.95%)
#     SRC_TO_DST_AVG_THROUGHPUT == IN_BYTES * 8000  99.58%   (DST side 99.87%)
#
# No division by duration is involved. Dividing matches 0.00% of rows.
# The reason is visible in the data: FLOW_DURATION_MILLISECONDS is 0 on
# 98.4% of flows, so the exporter's per-second figure collapses onto the
# byte total, and 8000 is the bits-per-second conversion that goes with a
# per-millisecond denominator. The rows that fit neither formula carry
# durations around 4,294,935 ms -- a 32-bit counter wrap -- and are the
# same corrupt readings clean.py caps.
#
# So these four columns carry almost nothing beyond IN_BYTES/OUT_BYTES in
# this dataset. That is a property of the data, not a choice made here;
# what is chosen is to reproduce it, because the model was fitted on it.
THROUGHPUT_BITS_PER_BYTE = 8000


def flow_to_row(flow: Any) -> dict[str, Any]:
    """Map one NFStream flow (with NetFlowV2Fields attached) onto the 43
    training columns."""
    u = flow.udps
    duration_ms = flow.bidirectional_duration_ms

    row = {
        "IPV4_SRC_ADDR": flow.src_ip,
        "IPV4_DST_ADDR": flow.dst_ip,
        "L4_SRC_PORT": flow.src_port,
        "L4_DST_PORT": flow.dst_port,
        "PROTOCOL": flow.protocol,
        # NFStream reports the protocol by name; the training schema stores
        # nProbe's numeric master.app encoding. l7_proto rebuilds that
        # mapping from the loaded nDPI library -- see its docstring.
        "L7_PROTO": l7_proto.encode(flow.application_name),
        "IN_BYTES": flow.src2dst_bytes,
        "OUT_BYTES": flow.dst2src_bytes,
        "IN_PKTS": flow.src2dst_packets,
        "OUT_PKTS": flow.dst2src_packets,
        "FLOW_DURATION_MILLISECONDS": duration_ms,
        "TCP_FLAGS": _flags_byte(
            flow.bidirectional_syn_packets, flow.bidirectional_ack_packets,
            flow.bidirectional_fin_packets, flow.bidirectional_rst_packets,
            flow.bidirectional_psh_packets, flow.bidirectional_urg_packets,
            flow.bidirectional_ece_packets, flow.bidirectional_cwr_packets),
        "CLIENT_TCP_FLAGS": _flags_byte(
            flow.src2dst_syn_packets, flow.src2dst_ack_packets,
            flow.src2dst_fin_packets, flow.src2dst_rst_packets,
            flow.src2dst_psh_packets, flow.src2dst_urg_packets,
            flow.src2dst_ece_packets, flow.src2dst_cwr_packets),
        "SERVER_TCP_FLAGS": _flags_byte(
            flow.dst2src_syn_packets, flow.dst2src_ack_packets,
            flow.dst2src_fin_packets, flow.dst2src_rst_packets,
            flow.dst2src_psh_packets, flow.dst2src_urg_packets,
            flow.dst2src_ece_packets, flow.dst2src_cwr_packets),
        "DURATION_IN": flow.src2dst_duration_ms,
        "DURATION_OUT": flow.dst2src_duration_ms,
        "MIN_TTL": u.min_ttl,
        "MAX_TTL": u.max_ttl,
        "LONGEST_FLOW_PKT": flow.bidirectional_max_ps,
        "SHORTEST_FLOW_PKT": flow.bidirectional_min_ps,
        # MIN_IP_PKT_LEN tracks SHORTEST_FLOW_PKT except on one-directional
        # flows, where nProbe reports 0. That is not a guess: across 3M
        # training rows the two columns are equal whenever OUT_PKTS > 0,
        # MIN_IP_PKT_LEN is 0 for all 2,278,969 rows with OUT_PKTS == 0
        # (1 row excepted), and it is never once greater than
        # SHORTEST_FLOW_PKT -- which rules out it being a reverse-direction
        # minimum. 76% of training rows carry the 0, so emitting the real
        # length here would disagree with the model's idea of this feature
        # on most of the traffic it sees. MAX_IP_PKT_LEN has no such
        # behaviour: it equals LONGEST_FLOW_PKT on 100% of rows and is
        # never 0.
        "MIN_IP_PKT_LEN": flow.bidirectional_min_ps if flow.dst2src_packets else 0,
        "MAX_IP_PKT_LEN": flow.bidirectional_max_ps,
        # Not rates -- see THROUGHPUT_BITS_PER_BYTE above for the measurement.
        "SRC_TO_DST_SECOND_BYTES": float(flow.src2dst_bytes),
        "DST_TO_SRC_SECOND_BYTES": float(flow.dst2src_bytes),
        "RETRANSMITTED_IN_BYTES": u.retrans_in_bytes,
        "RETRANSMITTED_IN_PKTS": u.retrans_in_pkts,
        "RETRANSMITTED_OUT_BYTES": u.retrans_out_bytes,
        "RETRANSMITTED_OUT_PKTS": u.retrans_out_pkts,
        "SRC_TO_DST_AVG_THROUGHPUT": float(flow.src2dst_bytes * THROUGHPUT_BITS_PER_BYTE),
        "DST_TO_SRC_AVG_THROUGHPUT": float(flow.dst2src_bytes * THROUGHPUT_BITS_PER_BYTE),
        "NUM_PKTS_UP_TO_128_BYTES": u.num_pkts_up_to_128,
        "NUM_PKTS_128_TO_256_BYTES": u.num_pkts_128_to_256,
        "NUM_PKTS_256_TO_512_BYTES": u.num_pkts_256_to_512,
        "NUM_PKTS_512_TO_1024_BYTES": u.num_pkts_512_to_1024,
        "NUM_PKTS_1024_TO_1514_BYTES": u.num_pkts_1024_to_1514,
        "TCP_WIN_MAX_IN": u.tcp_win_max_in,
        "TCP_WIN_MAX_OUT": u.tcp_win_max_out,
        "ICMP_TYPE": u.icmp_type,
        "ICMP_IPV4_TYPE": u.icmp_ipv4_type,
        "DNS_QUERY_ID": u.dns_query_id,
        "DNS_QUERY_TYPE": u.dns_query_type,
        "DNS_TTL_ANSWER": u.dns_ttl_answer,
        "FTP_COMMAND_RET_CODE": u.ftp_command_ret_code,
    }

    missing = [c for c in NETFLOW_FEATURES if c not in row]
    extra = [c for c in row if c not in NETFLOW_FEATURES]
    if missing or extra:
        raise RuntimeError(
            f"extracted row does not match the training schema "
            f"(missing={missing}, unexpected={extra}) -- fix before scoring, "
            f"a mismatched column set means the model sees the wrong feature "
            f"in the wrong position"
        )
    return row


# NFStream's byte counters and packet-size extremes follow `accounting_mode`;
# 0 (its default) measures the whole ethernet frame, 1 measures the IP
# packet. nProbe wrote the training data at the IP layer, which the data
# itself confirms: SHORTEST_FLOW_PKT bottoms out at 40 there (a bare TCP
# header) and never at 54/60, which is where ethernet framing would floor
# it. Leaving this at the default inflated IN_BYTES/OUT_BYTES and all four
# packet-length columns by 14 bytes per packet, and that error propagated
# into both *_SECOND_BYTES and both *_AVG_THROUGHPUT columns as well.
ACCOUNTING_MODE_IP_LAYER = 1


def extract(source: str, idle_timeout: int = 15, active_timeout: int = 120,
            snapshot_length: int = 1536) -> Iterator[dict[str, Any]]:
    """Yield one schema-shaped dict per completed flow from `source`
    (an interface name for live capture, or a pcap path)."""
    from nfstream import NFStreamer  # imported here so --help works without nfstream

    streamer = NFStreamer(
        source=source,
        udps=NetFlowV2Fields(),
        statistical_analysis=True,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        snapshot_length=snapshot_length,
        accounting_mode=ACCOUNTING_MODE_IP_LAYER,
    )

    # nfstream pins *this* process to a 2-CPU slice of whatever mask it was
    # given (nfstream/utils.py::set_affinity, called from streamer.py) and
    # never puts it back. Its meters run in their own processes, so the only
    # thing that narrowing reaches is everything downstream of this
    # generator -- scaling, scoring, SHAP -- which silently loses CPUs it
    # was never meant to give up.
    #
    # Measured on an 8-CPU host: batched scoring drops ~25% straight away,
    # and if anything later rebuilds torch's thread pool against the
    # narrowed mask (torch.set_num_threads with the default 4 threads on 2
    # CPUs) throughput collapses from 2.7M flow/s to 10.7k, a 250x cliff
    # that reads as a hung process rather than a slow one.
    #
    # Restoring the mask that was in force on entry is not the same as
    # grabbing more CPUs: taskset, cgroup and container limits all still
    # apply, because they are what that mask already encodes.
    try:
        original_affinity = os.sched_getaffinity(0)
    except AttributeError:  # not Linux; nfstream does not narrow anything there
        original_affinity = None

    def _restore() -> None:
        if original_affinity and os.sched_getaffinity(0) != original_affinity:
            try:
                os.sched_setaffinity(0, original_affinity)
            except OSError:  # a supervisor may legitimately refuse; not fatal
                log.debug("could not restore CPU affinity to %s", sorted(original_affinity))

    try:
        for flow in streamer:
            row = flow_to_row(flow)
            _restore()
            yield row
    finally:
        _restore()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, help="Interface name (live) or path to a .pcap file")
    parser.add_argument("--output", type=Path, default=None, help="Write CSV here; omit to print a summary only")
    parser.add_argument("--limit", type=int, default=None, help="Stop after N flows (useful on a live interface)")
    parser.add_argument("--idle-timeout", type=int, default=15)
    parser.add_argument("--active-timeout", type=int, default=120)
    args = parser.parse_args()

    writer = None
    handle = None
    if args.output:
        handle = args.output.open("w", newline="")
        writer = csv.DictWriter(handle, fieldnames=NETFLOW_FEATURES)
        writer.writeheader()

    count = 0
    try:
        for row in extract(args.source, args.idle_timeout, args.active_timeout):
            count += 1
            if writer:
                writer.writerow(row)
            else:
                log.info("%s:%s -> %s:%s proto=%s pkts_in=%s pkts_out=%s ttl=%s-%s",
                         row["IPV4_SRC_ADDR"], row["L4_SRC_PORT"], row["IPV4_DST_ADDR"],
                         row["L4_DST_PORT"], row["PROTOCOL"], row["IN_PKTS"], row["OUT_PKTS"],
                         row["MIN_TTL"], row["MAX_TTL"])
            if args.limit and count >= args.limit:
                break
    except KeyboardInterrupt:
        log.info("Stopped by user.")
    except PermissionError:
        log.error("Live capture needs packet-capture privileges. Run as root, or grant them once:\n"
                  "    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))")
        sys.exit(1)
    finally:
        if handle:
            handle.close()

    log.info("Extracted %d flow(s)%s", count, f" -> {args.output}" if args.output else "")


if __name__ == "__main__":
    main()
