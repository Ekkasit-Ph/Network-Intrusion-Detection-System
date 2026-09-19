"""Tests for the nDPI name -> L7_PROTO number mapping.

What these can prove: the mapping reproduces nDPI's own protocol ids and
nProbe's master.app encoding, so a name NFStream reports turns into the
number the training data uses for that protocol.

What they deliberately do NOT claim: that live extraction will assign the
*same* id nProbe assigned to comparable traffic. That depends on dissection
conditions in the original capture which can't be reproduced here -- see
`source/extraction/README.md` for the concrete UDP/53 case where the
training data disagrees with what this nDPI build reports.
"""

from __future__ import annotations

import pytest

pytest.importorskip("nfstream", reason="the mapping is built from the installed nDPI library")

from source.extraction import l7_proto  # noqa: E402


# Values decoded from the training CSV: for each, the dominant destination
# port confirms which protocol the id belongs to.
KNOWN_IDS = [
    ("HTTP", 7.0, "port 80"),
    ("TLS", 91.0, "port 443"),
    ("DNS", 5.0, "port 53/udp"),
    ("FTP_CONTROL", 1.0, "port 21"),
    ("SSH", 92.0, "port 22"),
    ("TELNET", 77.0, "port 23"),
    ("MAIL_IMAP", 4.0, "port 143"),
    ("MAIL_POP", 2.0, "port 110"),
    ("VNC", 89.0, "port 5900"),
    ("NETBIOS", 10.0, "port 139"),
]


@pytest.mark.parametrize("name,expected,why", KNOWN_IDS)
def test_known_protocol_ids_match_the_training_data(name, expected, why):
    assert l7_proto.encode(name) == expected, f"{name} ({why})"


def test_mapping_table_was_actually_built():
    """A silently empty table would make every flow Unknown and look like
    'the model just doesn't rely on L7_PROTO much'."""
    assert len(l7_proto.NAME_TO_ID) > 100


def test_master_dot_app_encoding_matches_the_training_values():
    """nProbe writes the two ids either side of a decimal point. These
    exact values appear in the training CSV, which is what pins down the
    encoding as digit-concatenation rather than a fraction."""
    assert l7_proto.encode("HTTP.AMAZON") == 7.178   # 7.177999973297119 in float32
    assert l7_proto.encode("VNC.HTTP") == 89.7       # 89.69999694824219; port 5800 is VNC-over-HTTP


def test_names_are_case_insensitive():
    assert l7_proto.encode("http") == l7_proto.encode("HTTP") == 7.0


def test_network_layer_protocols_resolve_without_their_ip_prefix():
    """nDPI declares these as NDPI_PROTOCOL_IP_* but reports them without
    the prefix, so both spellings have to resolve."""
    assert l7_proto.encode("ICMP") == l7_proto.encode("IP_ICMP")
    assert l7_proto.encode("ICMP") > 0


def test_unknown_and_missing_names_fall_back_to_zero():
    # 0.0 is nDPI's own UNKNOWN id and the most common value in training
    # data, so this is a value the model has seen -- not a novel one.
    assert l7_proto.encode("NOT_A_REAL_PROTOCOL") == 0.0
    assert l7_proto.encode(None) == 0.0
    assert l7_proto.encode("") == 0.0


def test_unresolvable_sub_protocol_degrades_to_the_master():
    """Better to report HTTP than to report nothing because the app half
    of the name wasn't recognised."""
    assert l7_proto.encode("HTTP.SOMETHING_UNKNOWN") == 7.0


def test_category_constants_do_not_pollute_the_table():
    """nDPI's category enums share the NDPI_PROTOCOL_ prefix but are not
    protocols; letting them in would shadow real names with wrong ids."""
    assert "CATEGORY_WEB" not in l7_proto.NAME_TO_ID
    assert "QOE_CATEGORY_MAX" not in l7_proto.NAME_TO_ID


def test_coverage_report_separates_resolved_from_unresolved():
    report = l7_proto.coverage_report(["HTTP", "DNS", "NOPE", "TLS"])
    assert report["total"] == 4
    assert report["resolved"] == 3
    assert report["unresolved_names"] == ["NOPE"]


def test_sensor_emits_a_real_id_not_a_placeholder(tmp_path):
    """End-to-end: the extractor must put the mapped number in the column,
    which is the whole point of this module existing."""
    from tests.test_extraction import dns_query, eth, ipv4, udp, write_pcap

    path = tmp_path / "dns.pcap"
    write_pcap(path, [
        eth(ipv4("10.0.0.1", "10.0.0.3", 17, udp(40000, 53, dns_query(0x1234, 1)), 64)),
        eth(ipv4("10.0.0.3", "10.0.0.1", 17, udp(53, 40000, dns_query(0x1234, 1)), 57)),
    ])

    from source.extraction.sensor import extract
    rows = list(extract(str(path)))

    assert rows, "no flow extracted"
    assert rows[0]["L7_PROTO"] == 5.0  # DNS, not the old hardcoded 0.0
