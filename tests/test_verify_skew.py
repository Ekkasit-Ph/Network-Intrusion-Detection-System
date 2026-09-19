"""Tests for the skew measurement itself.

`verify_skew.py` reports how much a extraction bug costs in recall and FPR.
Those numbers are only worth anything if the machinery producing them is
exact -- a lossy decode/encode would turn the whole thing into a
measurement of the codec's own error, and it would look like a plausible
result rather than a broken one. So the round-trip and the injected
inflation are both pinned here.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("sklearn")
from sklearn.preprocessing import StandardScaler  # noqa: E402

from source.extraction.verify_skew import (  # noqa: E402
    ETHERNET_HEADER_BYTES,
    _apply_ethernet_framing_bug,
    _Codec,
    assert_codec_round_trips,
)

COLUMNS = [
    "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
    "SHORTEST_FLOW_PKT", "LONGEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
]


@pytest.fixture
def scaled():
    """A frame in the same shape the model consumes: raw NetFlow values
    put through log1p and then a StandardScaler, exactly as
    `source/preprocessing/pipeline.py` does it."""
    rng = np.random.default_rng(0)
    n = 500
    in_pkts = rng.integers(1, 40, n).astype(float)
    out_pkts = rng.integers(0, 30, n).astype(float)      # zeros: one-directional flows
    raw = pd.DataFrame({
        "IN_BYTES": in_pkts * rng.integers(40, 1400, n),
        "OUT_BYTES": out_pkts * rng.integers(40, 1400, n),
        "IN_PKTS": in_pkts,
        "OUT_PKTS": out_pkts,
        "SHORTEST_FLOW_PKT": rng.integers(28, 100, n).astype(float),
        "LONGEST_FLOW_PKT": rng.integers(100, 1500, n).astype(float),
        "SRC_TO_DST_SECOND_BYTES": rng.uniform(0, 1e5, n),
        "DST_TO_SRC_SECOND_BYTES": rng.uniform(0, 1e5, n),
    })
    raw["MIN_IP_PKT_LEN"] = np.where(out_pkts > 0, raw["SHORTEST_FLOW_PKT"], 0.0)
    raw["MAX_IP_PKT_LEN"] = raw["LONGEST_FLOW_PKT"]
    raw["SRC_TO_DST_AVG_THROUGHPUT"] = raw["SRC_TO_DST_SECOND_BYTES"] * 8
    raw["DST_TO_SRC_AVG_THROUGHPUT"] = raw["DST_TO_SRC_SECOND_BYTES"] * 8
    raw = raw[COLUMNS]

    logged = np.log1p(raw)
    scaler = StandardScaler().fit(logged)
    df = pd.DataFrame(scaler.transform(logged), columns=COLUMNS).astype(np.float32)
    return df, _Codec(COLUMNS, scaler), raw


def test_decode_recovers_the_original_netflow_values(scaled):
    df, codec, raw = scaled
    for col in COLUMNS:
        assert codec.decode(df, col) == pytest.approx(raw[col].to_numpy(), rel=1e-5, abs=1e-4), col


def test_round_trip_is_an_identity(scaled):
    df, codec, _ = scaled
    drift = assert_codec_round_trips(df, codec, tuple(COLUMNS))
    assert drift < 1e-5


def test_round_trip_guard_rejects_a_lossy_codec(scaled):
    """The guard has to actually fire -- an assertion that can never fail
    protects nothing."""
    df, codec, _ = scaled

    class Lossy(_Codec):
        def decode(self, frame, col):
            return super().decode(frame, col) * 1.05  # 5% off

    with pytest.raises(RuntimeError, match="not an identity"):
        assert_codec_round_trips(df, Lossy(COLUMNS, codec._scaler), tuple(COLUMNS))


def test_injected_bug_adds_exactly_one_ethernet_header_per_packet(scaled):
    df, codec, raw = scaled
    bugged = _apply_ethernet_framing_bug(df, codec)

    for byte_col, pkt_col in (("IN_BYTES", "IN_PKTS"), ("OUT_BYTES", "OUT_PKTS")):
        delta = codec.decode(bugged, byte_col) - codec.decode(df, byte_col)
        expected = ETHERNET_HEADER_BYTES * raw[pkt_col].to_numpy()
        assert delta == pytest.approx(expected, rel=1e-4, abs=1e-2), byte_col

    for col in ("SHORTEST_FLOW_PKT", "LONGEST_FLOW_PKT", "MAX_IP_PKT_LEN"):
        delta = codec.decode(bugged, col) - codec.decode(df, col)
        assert delta == pytest.approx(ETHERNET_HEADER_BYTES, rel=1e-4, abs=1e-2), col


def test_injected_bug_reproduces_the_one_directional_min_length_error(scaled):
    """The old code reported a real minimum on one-directional flows where
    nProbe writes 0, so the simulated column must be non-zero there too --
    otherwise the measurement understates what the bug cost."""
    df, codec, raw = scaled
    bugged = _apply_ethernet_framing_bug(df, codec)

    one_way = raw["OUT_PKTS"].to_numpy() == 0
    assert one_way.any(), "fixture must contain one-directional flows"
    assert (codec.decode(df, "MIN_IP_PKT_LEN")[one_way] < 1e-6).all(), "fixture is not set up right"
    assert (codec.decode(bugged, "MIN_IP_PKT_LEN")[one_way] > 1).all()


def test_rates_are_inflated_proportionally_not_by_a_flat_offset(scaled):
    """Byte rates are IN_BYTES over a duration the bug doesn't touch, so
    they scale by the same ratio the byte total did."""
    df, codec, _ = scaled
    bugged = _apply_ethernet_framing_bug(df, codec)

    bytes_ratio = codec.decode(bugged, "IN_BYTES") / np.maximum(codec.decode(df, "IN_BYTES"), 1e-9)
    rate_ratio = (codec.decode(bugged, "SRC_TO_DST_SECOND_BYTES")
                  / np.maximum(codec.decode(df, "SRC_TO_DST_SECOND_BYTES"), 1e-9))
    positive = codec.decode(df, "SRC_TO_DST_SECOND_BYTES") > 1
    assert rate_ratio[positive] == pytest.approx(bytes_ratio[positive], rel=1e-3)


def test_columns_outside_the_bug_are_left_alone(scaled):
    """A simulation that also perturbs unrelated features would overstate
    the damage."""
    df, codec, _ = scaled
    bugged = _apply_ethernet_framing_bug(df, codec)
    for col in ("IN_PKTS", "OUT_PKTS"):
        assert (bugged[col].to_numpy() == df[col].to_numpy()).all(), col
